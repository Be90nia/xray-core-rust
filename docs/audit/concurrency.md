# 高并发正确性审计报告（concurrency.md）

- 审计范围：竞态（check-then-act / 非原子读改写 / DashMap-Mutex 混用）、死锁（锁序 / 持锁跨 await / 双通道互等）、waker-poll 语义（裸 Pending 残留）、select! 取消安全、spawn_blocking 占用 worker、原子序。
- 重点 crate：xray-core（inbound/outbound/wiring/grpc_server）、xray-proxy-vless/encryption、xray-app-dispatcher（default/udp_session）、xray-mux（client/worker/session/writer）、xray-transport-quic 系（quic/hysteria-quinn/tuic-pool/kcp）、xray-buf（pipe/copy/timeout/splice）、xray-app-reverse、xray-app-observatory、xray-app-dns、validators。
- 方法：全量 grep 六类模式 → 逐点读上下文 → 与 Go 基准（D:/Project/Xray-core）对照锁/共享状态语义。

## 统计

| 严重度 | 数量 |
|---|---|
| P0 | 0 |
| P1 | 3 |
| P2 | 4 |

---

## 发现清单

### [P1] mux XUDP 管理器条目状态永不流转：clone 语义破坏 Go 共享指针语义，同 GlobalID 后续 New 帧被静默丢弃 + 管理器条目永久泄漏
- 位置：`crates/xray-mux/src/worker.rs:276-286,318`；关联 `crates/xray-mux/src/session.rs:322-331`（set_xudp 存的是 clone）、`crates/xray-mux/src/session.rs:717-746`（XUDPManager::get 返回 clone、cleanup 只清 Expiring）
- 证据（worker.rs）：
```rust
let existing = xmgr.get(&global_id).await;            // 返回 Option<XUDP> —— 值克隆
let mut xudp = match existing {
    None => { let x = XUDP::new(global_id); xmgr.register(x.clone()).await; x }  // 注册的是 Initializing
    Some(mut ex) => {
        if ex.status == XudpStatus::Initializing {
            warn!("XUDP conflict {:?}", global_id);
            return Ok(());                            // 静默丢帧（含内联 data）
        }
        ex.status = XudpStatus::Initializing;         // 只改了本地克隆
        ex
    }
};
...
xudp.status = XudpStatus::Active;                     // 仍是本地克隆，管理器条目永远停留在 Initializing
```
  Go 基准（common/mux/server.go xudp 路径）中 `XUDPManager.Get/Register` 返回/保存 `*XUDP` 指针，握手收尾 `xudp.Status = Active`、Session 关闭置 `Expiring` 都直接落在共享条目上；并发重复 New 命中 Initializing 才判 conflict，完成后同 GlobalID 走复用路径。
- 影响：(1) 首个 New 注册后管理器条目永远处于 Initializing，此后任何携带同 GlobalID 的 New 帧（Go 语义=同目标 UDP 流复用）都进 conflict 分支被丢弃，内联数据一并丢失——不是并发窗口才触发，顺序流量必现；(2) 管理器条目永远到不了 Expiring，`start_cleanup`/`cleanup` 的 60s 过期清理永不生效，条目按 GlobalID 无上限累积（内存泄漏）；(3) 并发首包双 None → 双 register 后写覆盖、双 dispatch，产生两条并行 UDP 出站流。
- 修复建议：`XUDPManager::get` 改为返回共享句柄（`Arc<tokio::sync::Mutex<XUDP>>`），或在 manager 内提供 `try_begin_init(&global_id)`/`update_status(&global_id, status)` 把 conflict 判定与状态转移放进同一写锁；`handle_xudp_new` 收尾与 `Session::close` 一律经 manager 更新状态。

### [P1] VLESS ENC Handler 级共享 ClientInstance 的 tokio Mutex 跨整段网络握手 await：所有连接拨号串行化，服务端黑洞时拨号路径永久挂死
- 位置：`crates/xray-proxy-vless/src/dispatcher.rs:157-161,178-187`
- 证据：
```rust
let enc_client: Option<Arc<tokio::sync::Mutex<crate::encryption::ClientInstance>>> = ...  // Handler 级共享（注释自述对齐 Go outbound.go:94）
...
if let Some(client) = enc_client {
    let mut client = client.lock().await;
    let enc_conn = client
        .handshake(conn)              // 全网络往返：写 client_hello + 读 server 响应，内部无任何 timeout
        .await
```
  Go 基准 `proxy/vless/encryption/client.go:188-194` 只在写缓存字段时加锁：`i.RWLock.Lock(); i.Expire=...; i.PfsKey=...; i.Ticket=...; i.RWLock.Unlock()`——锁粒度是字段更新，不是整段握手；握手网络 IO 在锁外。
- 影响：(1) 同一 outbound 的所有并发连接建立被这把锁完全串行（每次握手含完整网络 RTT）；(2) `ClientInstance::handshake`（`encryption/mod.rs:321` 起）内部对 conn 的 read/write 无超时包装，dispatcher 调用点也无 timeout——服务端 TCP accept 后黑洞（不回响应）时握手读永远 Pending，锁被永久持有，此后该 outbound 的全部新连接在建链阶段即挂死（症状为整站断连且无报错）。
- 修复建议：对齐 Go 锁粒度——去掉粗粒度外层锁（`pfs_key_cache/ticket_cache/expire_cache` 内部已是 RwLock，读侧天然并发安全），只在握手结束写缓存时短暂加锁；过渡方案在调用点以 `tokio::time::timeout(budget, async { let mut g = client.lock().await; g.handshake(conn).await })` 包住 lock+handshake 全程。

### [P1] burst healthping `do_check` 在 parking_lot Mutex 临界区内同步执行 tags×rounds 次网络探测：锁被持有可达数十至数百秒，且整体跑在 tokio worker 线程上
- 位置：`crates/xray-app-observatory/src/burst/burst_observer.rs:220-247`（锁范围）、`:166-192`（scheduler spawn 循环内联调用）
- 证据：
```rust
let mut g = self.rtts.lock();                 // parking_lot::Mutex
for tag in tags {
    let entry = g.entry(tag.clone())...
    for _ in 0..rounds {                      // rounds = sampling_count
        if self.cancel_pending.load(...) != entry_cancel { return; }
        let result = executor.probe(tag);     // 同步阻塞：HttpProbeExecutor 每次探测内部起独立线程+runtime 并 join（observer.rs:911-933），timeout 默认 5s
        ...
    }
}
```
  scheduler 侧 `tokio::spawn` 的循环在 `ticker.tick()` 分支直接调 `observer.do_check(&tags, ...)`（183 行），阻塞探测在 async worker 线程上内联执行。
- 影响：(1) `rtts` 锁被持有 tags×rounds×探测耗时——10 tag × sampling 4 × 5s 超时 = 200s 量级；期间任何 `latest_rtt()`/`cleanup()` 调用者在调用线程上阻塞（parking_lot 无 async 意识），observatory 接入 router leastload 后即拖死数据路径 worker；(2) 探测整段占用一个 tokio worker 线程，小 runtime（2-4 worker）下每轮探测该 worker 完全不可调度。Go 基准中探测在独立 goroutine，Results 锁只在读写样本时短暂持有。
- 修复建议：`do_check` 先在锁外完成全部探测（收集 `Vec<(tag, rtt)>`），再短暂加锁批量 `entry.put`；scheduler 循环把 `do_check` 挪进 `spawn_blocking`（或复用 observer.rs 中现成的 `probe_tags` scoped-thread 并行路径）。

### [P2] observatory `start()` 后台探测循环在 async task 内串行内联同步阻塞探测，逐 tag 占死 worker 线程
- 位置：`crates/xray-app-observatory/src/observer.rs:117-129`（循环内 `executor.probe(tag)`）、`:911-933`（`HttpProbeExecutor::probe` 起线程 + join 阻塞）
- 证据：
```rust
for tag in &tags {
    let result = executor.probe(tag);         // 同步契约：内部 std::thread::scope spawn + join，最长 timeout_ms(默认 5000)
    any_alive |= result.alive;
    status.update_with_probe_result(tag, &result, now);
}
```
- 影响：与 P1#3 同类的 worker 占用问题（非 burst 路径）：N 个 tag 串行，最坏 N×5s 内一个 worker 线程不可用；本 crate 已备好并行版 `probe_tags`（scoped threads）却未被 start 循环使用。
- 修复建议：start 循环改调 `spawn_blocking` 包裹的 `probe_all/probe_tags`，或对每 tag `tokio::task::spawn_blocking` + `join_all`。

### [P2] mux `IncrementalWorkerPicker::pick_internal` 放锁后再建 worker：并发 dispatch 空池穿透，重复创建 carrier 连接（Go 持锁跨 Create）
- 位置：`crates/xray-mux/src/client.rs:151-176`
- 证据：
```rust
let mut workers = self.workers.lock().await;
if let Some(idx) = Self::find_available(&workers) { ... }
workers.retain(|w| !w.is_closed());
drop(workers);                                 // 放锁
let worker = self.factory.create().await;      // 网络拨号在锁外
let mut workers = self.workers.lock().await;
workers.push(worker.clone());
```
  Go 基准 `common/mux/client.go:88-106`：`pickInternal` 以 `p.access.Lock(); defer p.access.Unlock()` 包住全程，`p.Factory.Create()` 在锁内——空池时仅创建一个 worker。
- 影响：并发 N 路 dispatch 在空池时各自 create → N 条 mux carrier 连接同时建立，仅最后 insert 的进入池，其余 worker 脱管但仍被各自调用方使用——突破 mux maxConnection 语义（每 worker=一条服务器连接），浪费服务器侧配额；另 `cleanup_started` 标志只写不读（周期清理任务未实现，171-173 行注释自述），closed worker 仅靠后续 pick 内 retain 兜底回收。
- 修复建议：tokio Mutex 不宜跨 create 持有，则用 in-flight 标志 + `Notify`/`watch` 扇出拨号结果实现 single-flight，或 `Arc<Semaphore>(1)` 串行化 create 段，保证空池创建路径互斥。

### [P2] reverse `RuntimeBridge`/`RuntimePortal::close()` 只翻 running 标志，已 spawn 的 monitor/cleanup 循环从不读取该标志：close 不停任务，重启后双循环并存
- 位置：`crates/xray-app-reverse/src/bridge.rs:260-286`（Bridge start/close）、`:341-367`（Portal start/close）
- 证据：
```rust
fn start(&self) -> Result<(), ReverseError> {
    if self.running.swap(true, Ordering::AcqRel) { return Ok(()); }
    ...
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(BRIDGE_MONITOR_INTERVAL).await;
            if Self::monitor_step(...).await.is_err() { break; }   // 循环退出条件只有 step 报错，不看 running
        }
    });
    ...
}
fn close(&self) -> Result<(), ReverseError> {
    self.running.store(false, Ordering::Release);   // 无人消费
    Ok(())
}
```
  Go 基准 `app/reverse/bridge.go` 的 `Bridge.Close` = `monitorTask.Close()`，monitor goroutine 随 Close 终止。
- 影响：close 后 monitor 继续按周期创建 BridgeWorker 并 dispatch carrier（后台任务泄漏、资源持续消耗）；close→start 再次调用时 `running.swap(true)` 成功又 spawn 第二个 monitor——两个 monitor 并发执行 `monitor_step`（workers Vec 的 retain/snapshot/push 交错，worker 重复创建）。Portal 的 30s picker.cleanup 循环同款问题（危害较小）。
- 修复建议：循环内 select `running` 的 watch channel（或 CancellationToken），close 时置位；或 close 持有 JoinHandle 并 abort。

### [P2] tuic `QuinnConnectionPool::get_or_connect` 读-放锁-再拨号无 single-flight：并发同 key 穿透重复 QUIC 握手，仅最后一个入池
- 位置：`crates/xray-proxy-tuic/src/pool.rs:121-150`
- 证据：
```rust
{
    let pool = self.inner.lock().await;
    if let Some(entry) = pool.get(&key) {
        if entry.is_alive().await { return Ok(entry.clone()); }
    }
}                                                  // 锁已放
let conn = connector().await?;                     // 完整 QUIC 握手在锁外，无去重
let mut pool = self.inner.lock().await;
pool.insert(key, pooled.clone());                  // 后写覆盖先写
```
- 影响：突发并发首包（如网页打开触发多条 h3 流）时对同一目标发起 N 次 QUIC 握手：服务器侧连接数瞬时放大，N-1 条连接成为孤儿（不入池、随各自调用方用完即弃）；与池化初衷（全局复用）相悖。无数据损坏，属明确改进项。
- 修复建议：加 in-flight map（`HashMap<PoolKey, Arc<Notify>>` 或广播首次拨号结果），后到者等待首次拨号结果复用同一连接。

---

## 已核查无问题项（避免复查浪费）

- **waker/poll 语义（维度③）**：历史裸 Pending 根治点全部保持——`CommonConn::poll_write`（common_conn.rs:239-317）与 `VisionConn::poll_write`（vision_conn.rs:252-340）部分写后 continue、Ok(0)→WriteZero、仅内层真 Pending 才上传；`XorConn`（xor_conn.rs）的"接受即缓冲 + poll_write/poll_read/poll_flush 三路清写"有注释论证且 CTR 状态不可回退前提成立；`TrojanUdpFramedConn`、`FragmentConnection`、`KcpConn`（read_state/write_state 缓存 future + tokio Notify permit 语义正确）、`SsRelayReader`、commander 转发层均符合 AsyncRead/Write 契约。
- **xray-buf pipe**：`CountingNotify`（count 累积 + Notify permit）与 Go signal.Notifier 等价性成立，无双读者丢唤醒；`wait_close` 先注册 notified 再复查的竞态防护正确；writer Wait 分支取消安全（mb 仅在锁内原子并入或整体释放）。
- **select! 取消安全（维度④）**：`handle_udp_associate`/`ss_udp_client_relay`/ss2022 udp（recv_from/recv_packet/rx.recv 均取消安全，accum 帧解析在无 await 段完成）；`handle_session_output` 持 input 锁读期间 select done 防"close 等锁、读等唤醒"互等（worker.rs:355-365 注释与实现一致）；xray-buf TimeoutReader/TimeoutWriter 分支语义与 Go task 竞速一致。
- **dns 单飞（cached.rs:96-131）**：insert/remove 与 subscribe 均在同锁窗口内完成，leader 崩溃后残留条目自愈（waiter 收 Err 回退直查），无丢广播窗口；dot/tcp nameserver 连接复用锁跨 connect 但全部路径有 timeout 包裹，不会无限串行。
- **validators（trojan DashMap / vless RwLock 双 map）**：add/del 跨两 map 非原子但窗口无害（auth 侧每 map 各自一致），与 Go sync.Map 双表结构一致。
- **原子序（维度⑥）**：stats/counter SeqCst 正确；geodata scheduler cancel 用 Acquire/Release 配对正确；observatory `cancel_pending: AtomicPtr` 仅做代际比较不解引用，AcqRel/Acquire 合法；proxyman last_activity/inactive 用 Relaxed 仅统计用途可接受。
- **spawn_blocking（维度⑤）**：kcp 收包循环、buf::splice、metrics accept 用法正确（阻塞体均在 blocking 池）。
- **锁序**：`Session::close` 持 xudp 锁跨 `manager.inner.write()` 当前无反向序（SessionManager 所有方法均在锁外调用 session 方法，close/close_if_no_session_and_idle 已显式收集-放锁-再关）；dns cache_controller 双 RwLock 单向嵌套，无环。
