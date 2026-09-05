# 内存优化 + 泄漏审计报告（memory.md）

- 审计人：MemAudit（性能/内存维度）
- 日期：2026-09-06
- 基线：master（v54 后工作区），Rust 移植 Go Xray-core v26.7.28
- 范围：①内存泄漏模式（Arc 环/task 泄漏/通道泄漏）②缓冲与会话表只增不减 ③大对象按值/Clone 滥用 ④池化现状 ⑤零拷贝/mmap 接线现状
- 方法：先查 git 历史（负优化预审，见附录 A），再按 `spawn(/Arc</clone()/HashMap/unbounded_channel/BytesMut` 热区扫描 + 逐点读上下文确认；只读代码，未改任何文件

## 统计

| 严重度 | 数量 |
|---|---|
| P0 | 0 |
| P1 | 4 |
| P2 | 6 |

---

## 一、内存泄漏模式

### [P1] reverse BridgeWorker ↔ ServerWorker 强引用环，worker 退役后整组对象永久驻留 | crates/xray-app-reverse/src/worker.rs:355-356

**证据**：

```rust
// worker.rs:353-356（BridgeWorker::new）
*me.self_ref.write() = Some(Arc::downgrade(&me));          // self_ref 用了 Weak ✓

let server = Arc::new(ServerWorker::new(me.clone()));       // ServerWorker.dispatcher 持 Arc<BridgeWorker>（强）
*me.worker.write() = Some(Arc::clone(&server));             // BridgeWorker.worker 持 Arc<ServerWorker>（强）
```

`xray-mux/src/worker.rs:111-115` 证实 `ServerWorker { dispatcher: Arc<dyn Dispatcher>, session_manager, xudp_manager, ... }`，即 `me.clone()` 以强引用存入 ServerWorker。全文件检索无任何 `*me.worker.write() = None`（grep 仅命中初始化处 356 行），close 路径（`timer_server.close()` / 帧循环结束）只置 closed 标志，不拆环。

**影响**：monitor 循环按 `is_active()` 把退役 worker 从 `workers` Vec 摘除（bridge.rs:231 retain）、timer 闭包与帧循环任务结束后释放各自 Arc——此后**唯一持有者就是这个环**：BridgeWorker + ServerWorker + SessionManager + XUDPManager + 其 dispatcher 字段 `Arc<dyn LinkDispatch>`（生产实现指向 DefaultDispatcher/Ohm/Router 链）全部永久驻留。每个退役 worker 恒定泄漏一组对象；长期运行的 reverse 代理下无上限缓慢增长。注意 353 行作者已在 `self_ref` 上用了 `Arc::downgrade`，唯独漏了 `worker` 这条边。

**修复建议**：close 时拆环——timer 回调或帧循环收尾处（二者都持有 `Arc<ServerWorker>`，无法直接拿到 `me`）改为经 `BridgeWorker` 的 weak 自引用 upgrade 后 `*me.worker.write() = None`；或 `worker` 字段直接存 `Weak<ServerWorker>`（timer/帧循环已是外部强持有方，生命周期自足）。

### [P1] reverse monitor 循环无视 close()，关闭后仍持续创建 BridgeWorker；重启叠加双 monitor | crates/xray-app-reverse/src/bridge.rs:268-286

**证据**：

```rust
// bridge.rs:268-278（start）
tokio::spawn(async move {
    loop {
        tokio::time::sleep(BRIDGE_MONITOR_INTERVAL).await;
        if Self::monitor_step(&dispatcher, &domain, &tag, &workers).await.is_err() {
            break;                       // 唯一出口；monitor_step 实际恒 Ok（new 失败已被 at_warning 吞掉）
        }
    }
});
// bridge.rs:282-286（close）
self.running.store(false, Ordering::Release);   // running 从未被上面的循环读取
```

`RuntimePortal::start` 的 picker 清理循环（bridge.rs:355-360）同款：`loop { sleep; picker.cleanup(); }` 无任何停止条件。

**影响**：`close()` 后 monitor 任务永不退出，且每 30s（BRIDGE_MONITOR_INTERVAL）继续 `BridgeWorker::new` 向已关闭的 bridge 拨号建连（泄漏 #1 的环使每个 worker 退役后仍驻留）；close→start 一次即叠加第二个 monitor，双重创建 worker。任务与连接双泄漏。

**修复建议**：monitor 循环每轮 `if !running.load() { break; }`（sleep 分支改 `select!` 竞争 running watch 亦可）；Portal 清理循环同改。Go 原型是 `monitorTask.Close()` 信号停表，此处等价补齐。

### [P1] ss2022 UDP `server_sessions` 会话表只插不删，无过期淘汰 | crates/xray-core/src/inbound.rs:1102,1124-1134

**证据**：

```rust
// serve_ss2022_udp
let mut server_sessions: HashMap<u64, Arc<ServerUdpSession2022>> = HashMap::new();  // :1102
...
// :1113 只清了 relay sender 表
sessions.retain(|_, tx| !tx.is_closed());
...
// :1124-1134 只 insert，全函数无 server_sessions.retain/remove
if !server_sessions.contains_key(&sid) {
    match ServerUdpSession2022::new(kind, hdr.aead_psk.to_vec(), sid) { ... server_sessions.insert(sid, Arc::new(s)); }
}
```

**影响**：每个新客户端 sessionId 建一个 `ServerUdpSession2022`（内含 AEAD cipher 实例 + PSK 拷贝 + nonce 计数器），永不回收。移动端客户端每次重启换 session_id、扫描器随机 sid 皆累积。同文件的 relay task 有 60s 空闲淘汰（:1220 `_ = &mut idle => break`）、sender 表有 retain，唯独密码学会话表漏了——恰是任务书要求对照 vless SessionStore 60s 清理模式查的同类缺失。Go `udpNat` entry 整体过期。

**修复建议**：relay 空闲退出是既有信号——`sessions.retain` 时同步 `server_sessions.retain(|sid, _| sessions.contains_key(sid))` 即可（sid 同键空间）；或给每 session 记 last_seen 后按 60s/包触发 retain。

### [P1] DNS 缓存清理任务从未接线，缓存表只写不清理 | crates/xray-app-dns/src/cache_controller.rs:240-253 + crates/xray-app-dns/src/nameserver/cached.rs:135-155

**证据**：

```rust
// cache_controller.rs:239-240（实现完整，对齐 Go cacheCleanup 300s）
/// 对应 Go `cacheCleanup.Start()`。
pub fn start_cleanup_task(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
```

全 crates 检索 `start_cleanup_task|run_cleanup` 仅命中定义处与测试——**生产无任何调用方**。而写入端每查询都落表（cached.rs:142/144/152/154 `cache.upsert` / `upsert_negative`），`find_records`（cache_controller.rs:109-111）只 get；TTL 过期仅让下次同域名查询回源（cached.rs:79-85 落 fetch），**过期条目永远留在 `ips: RwLock<HashMap<String, Arc<Record>>>` 里**。

**影响**：唯一 FQDN 数无上限增长（域名串 + IpRecord/负缓存条目各数百字节），长期运行代理解析百万级域名 → 数十至数百 MB 只增不减。Go `app/dns` 有 `task.Periodic` 每 300s `collectExpiredKeys + writeAndShrink`，实现已逐行对齐移植却漏接线——属"模式已备、接线缺失"而非"无模式"。

**修复建议**：在 DnsService 启动（server.rs 构造/start）处对每个启缓存 nameserver 调 `start_cleanup_task()` 并保留 JoinHandle 随 service 关闭 abort。

### 通道/task 泄漏排查结论（无新增发现）

- SOCKS UDP relay：控制连接 EOF 后 `relay.abort()`（xray-core/src/inbound.rs:132）✓；mux inbound keepalive/idle 句柄 abort（inbound.rs:203-204）✓
- legacy SS UDP / TUIC UDP：60s idle 淘汰 + 收包顺带 `retain(|_, tx| !tx.is_closed())`（inbound.rs:993、tuic server.rs:426）✓
- splithttp SessionMap 30s reaper + UploadQueue `max_packets` 上限（upload_queue.rs:193）✓；observatory/burst 用 watch cancel ✓；wireguard ShutGuard Drop 发停机（driver.rs:523-526）✓；mux session 持 parent Weak（session.rs:520）✓
- vmess AuthIDDecoder 已是 LRU(120)（commit 2164aab，无回归）✓
- Arc 环专项：`Arc::downgrade/Weak` 清单逐点核对，唯一漏网即上述 reverse worker 环

### [P2] xicmp 每连接 unbounded_channel + 裸 socket 后台收包任务 | crates/xray-transport/src/finalmask/xicmp.rs:285,319

**证据**：

```rust
let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();   // :285（new_client），:319（new_server）同
tokio::spawn(async move { loop { ...raw_for_task.recv().await ... tx.send(pkt).is_err() => return; } });
```

**影响**：应用层 `recv_from` 停滞期间（对端 ping 洪水）unbounded 队列无上限积压；连接 drop 后需**下一个包到达**才触发 `tx.send` Err 使任务退出。当前生产 `IcmpRawSocket` 实现仍是占位（接受项，不展开），但通道模式先落地了——真实 raw socket 接入即带此风险，属"给未来埋的雷"。

**修复建议**：换 `mpsc::channel(N)`（如 64）+ `send(pkt).await`，天然背压；或保留 unbounded 但入队前 `if rx 强端已关` 短路（收包循环持 `Weak` 判活）。

---

## 二、缓冲区 / 会话表只增不减

（P1 两条见上：ss2022 server_sessions、DNS 缓存表。）

### [P2] xray-buf 全局分片池归还无上限、峰值工作集永不收缩 | crates/xray-buf/src/alloc.rs:135-160

**证据**：

```rust
// release()：TLS 层有 TLS_MAX_PER_TIER=8 上限 ✓，全局分片层：
// 2. 尝试全局分片（无上限，但 Mutex 保护）   ← :153 自注释
let mut shard = SHARDS[shard_idx].lock();
shard.tiers[tier].push(buf);                    // :156 无任何容量判断
```

**影响**：池只记峰值不还债——一次并发 bulk 突刺（如 1 万并发连接 × 8KB 层 = 80MB）后这些 BytesMut 永久滞留在 SHARDS/各 worker TLS 缓存，RSS 高水位不再回落。Go 原型 `sync.Pool` 依赖 GC 周期清空，语义不同。当前生产调用方（bridge.rs:114、inbound.rs:490、buffer.rs:36）基本只用 8KB 层，量级可控，但随 128KB 层启用（大 payload 场景）会放大。

**修复建议**：`release` 时 `if shard.tiers[tier].len() >= PER_SHARD_CAP { return; }`（如 64/分片/层，8 分片 × 4 层上限 ~21MB 封顶）；一行判断即可。

---

## 三、大对象按值传递 / Clone 滥用（热路径）

### [P2] CommonConn 每 TLS record 双堆分配 + 三次拷贝 + drain 前移 | crates/xray-proxy-vless/src/encryption/common_conn.rs:192-205

**证据**：

```rust
// 完整 record：解密
let data: Vec<u8> = this.raw_buf[TLS_RECORD_HEADER_LEN..total].to_vec();  // 拷贝① + 分配①（≤16KB）
let mut plaintext = Vec::with_capacity(data.len()...);                     // 分配②
peer_aead.open(&mut plaintext, None, &data, &header)?;                     // 拷贝②（密文→明文）
this.raw_buf.drain(..total);                                               // 拷贝③：O(剩余) memmove 前移
this.decrypted = plaintext;                                                // 随后 put_slice 进 ReadBuf（拷贝④）
```

**影响**：这是全部 Vision/ENC 流量的每-record 路径（16KB record 满速下载时每秒千次级），每次 2 个堆分配 + 4 次缓冲拷贝。语义正确无泄漏，属吞吐/分配churn 硬伤。

**修复建议**：`raw_buf` 换 `BytesMut`：`split_to(total)` O(1) 摘段替代 `drain` memmove；密文段用 AEAD `open_in_place`（strip 5B 头后原位解密）消掉 to_vec 与 plaintext 双分配；`decrypted` 直接引用 split 段（`Bytes` 廉价切片）消 ReadBuf 拷贝。改后同段逻辑用既有 `common_conn` 测试 + interop_enc.py 回归。

### [P2] XorConn 每写一次两次全量分配 | crates/xray-proxy-vless/src/encryption/xor_conn.rs:268-290

**证据**：

```rust
// ponytail: 每写一次一次分配；XOR 型 wrapper 必须先变换后写，无零分配写法。
let mut enc = buf.to_vec();                        // :269
this.xor_write(&mut enc);
...
Poll::Pending => { this.write_pending = Some((enc[sent..].to_vec(), 0)); ... }  // :290 再拷一次
```

**影响**：xor_mode 开启的连接每 write 1-2 次分配（部分写入 Pending 时 2 次）。`ponytail:` 注释已自认天花板；在 ENC 复合流上叠加 CommonConn 的分配构成 churn 叠加。

**修复建议**：conn 内持久化 `pending: Vec<u8>` 复用（`clear()+extend_from_slice`），Pending 分支改 `pending.truncate`/`copy_within`，免第二份分配。v54 xor_conn 刚按 Go 同构重写并有逐字节 fixture 单测，动它需过 `xor_conn_go_fixture.txt` 回归（见附录 A）。

### 其余核查结论

- bridge 泵已零拷贝化：`write_all_mb` 逐 Buffer 写 MultiBuffer 替代 `mb.to_vec()`（xray-transport/src/bridge.rs:146-161）✓
- vmess body_chunk 每块 `vec![0u8; sb]`/ciphertext 分配与 Go 每块分配等价（encoding/body_chunk.rs:300/421），nonce derive `.to_vec()` 为固定 12B（mod.rs:115）——Go 对齐，不计
- `DispatcherContext`/`AccessLogEntry` 等 Clone 均为小对象、每连接一次量级，不计

---

## 四、池化现状（xray-buf）

- 两级池已实装且已接线：TLS 每层 ≤8 + 8 分片 Mutex，bridge 泵/inbound relay/Buffer::new 全部走池，`Buffer::Drop` 自动回池（buffer.rs:438-446）✓
- 已知缺口即上文 alloc.rs 归还无上限一条（P2）
- 超过 128KB 直配不进池、`resize` 涨容量后按实际容量归层——语义正确
- 未池化点：`serve_ss*_udp`/`serve_dokodemo_udp` 每循环 65535B 栈数组（非堆）✓；`spawn_ss_pump` 每连接 `vec![0u8; 8*1024]`（inbound.rs:765）为每连接一次分配，量级可接受，不计

## 五、零拷贝 / mmap 现状

### [P2] 内核级 splice 实现存在但零调用方；且现有形态若接线会引入单方向饿死 | crates/xray-buf/src/splice.rs:20-62

**证据**：全 crates 检索 `splice_copy_bidirectional` 仅命中定义/导出（splice.rs:46/66/83），无调用点。实现自身两处硬伤：

```rust
// :56-57 两方向【串行】：a2b 完整跑到 EOF 后才开始 b2a
let a2b = splice_one_way(a_fd, b_fd, ...)?;
let b2a = splice_one_way(b_fd, a_fd, ...)?;
// :34/:39 EAGAIN → std::thread::sleep(1ms) 忙等（spawn_blocking 线程上空转 1000 次/秒/方向）
Err(nix::errno::Errno::EAGAIN) => std::thread::sleep(BACKOFF),
```

**影响**：当前为死代码（无运行时开销）。但若有人按签名接进 dispatcher 桥：全双工长连接（SSH/WS）a→b 未 EOF 时 b→a 永不启动 = 流量卡死；且空闲连接常态烧 1 个 blocking 线程 + 每秒 2000 次唤醒。splice 的 git 史（两次 revert，见附录 A）是协议层回归，与本条无冲突，但说明该路径动一次回归成本高。

**修复建议**：接线前必须先改两方向为 `spawn_blocking` 双任务并发（等价 Go 两 goroutine）+ 用 `AsyncFd` 事件驱动或 `poll` 机制替换 1ms 轮询；在此之前保留死代码应加 `#[allow(dead_code)]` 注明现状或直接删（要时再写）。

### 接线现状澄清（无缺陷，供 PM 排期参考）

- **协议级"splice"（Vision raw 直通）已接线**：`dup_tcp_stream` 克隆链穿透全 TLS 栈（vless encoding/client.rs:230 → reality/btls/utls 各 `raw_tcp_clone` → TcpConnection），server 侧 accept 层预 dup（vless inbound/server.rs:123）+ VisionConn `raw_fallback` 直读直写（vision_conn.rs:188/293）——这是生产在跑的零加密开销路径 ✓
- bridge 下行泵池化读缓冲 + 半关闭 watch 限窗（bridge.rs:185-187/234-274）✓
- mmap：全库无 mmap 用法；geodata 走 WeakCacheMap 共享（合理，规则文件不大），无需引入

---

## 附录 A：负优化预审（git 历史 + beads 线索）

- `git log --grep="perf|优化|cache|pool|revert|泄漏|leak"` 命中：2164aab（vmess HashSet→LRU 内存泄漏修复）、8c23cf7（UdpRelay 60s 空闲淘汰）、3734eaf（WeakCacheMap）、d0cc542/11bd9db（splice 触发器两次 revert，根因=btls BAD_DECRYPT 协议回归，非内存问题）
- 与本次建议的冲突核查：①DNS 清理接线、ss2022 retain、reverse 拆环均为**缺失功能的补齐**，无历史回退记录；②CommonConn 拷贝优化不触碰 v50 修复的 poll_write 裸 Pending 语义（只动 read 侧缓冲管理）；③XorConn 建议仅复用分配缓冲，不改 v54 定稿的 XOR 时序（有 `xor_conn_go_fixture.txt` 逐字节回归兜底）；④splice 若接线，其两方向串行缺陷与历史 revert 根因不同源，但回归成本共识不变——故列为"接线前必须重构"而非"建议接线"。
- 未发现"同一模块反复优化"热点；beads 侧性能关键词无失败/回退任务记录（`bd list --search` 经 BD_IGNORE_SCHEMA_SKEW 读取）。

## 附录 B：审计中确认健康、无需处理的既有模式（防误报对照）

| 模式 | 位置 |
|---|---|
| SessionStore 60s 后台清理 | vless ENC（v46 实装） |
| SS UDP 每 client 60s idle + retain | xray-core/src/inbound.rs:993,1038-1076 |
| TUIC UDP assoc retain + dissociate 清 frags | xray-proxy-tuic/src/server.rs:426,473-477 |
| FakeDNS LRU(32768/65535) | xray-core/src/register.rs:654-668 |
| splithttp SessionMap 30s reaper + UploadQueue 上限 | xray-transport-splithttp/src/hub/session.rs:107-108, upload_queue.rs:81 |
| mux session 弱父引用 | xray-mux/src/session.rs:520 |
| vmess AuthIDDecoder LRU(120) | xray-proxy-vmess（2164aab） |
| salt 重放池 4096 惰性 retain | xray-proxy-ss/src/ss2022/replay.rs:40-42 |
