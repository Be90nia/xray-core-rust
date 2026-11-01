# Verify-C1：C1–C4 独立复核（机制 + 修法可行性）

- 仓库 `D:/Project/Xray-core-rust`，分支 `feature/fix-inbound-parity`，HEAD `5fe98b90`
- 被测二进制 `target/release/xray.exe`（`version` → `git_rev=5fe98b907c7b550d4a70202abb475e26ee89013d`，26.10.11，与 HEAD 一致）
- 口径：生产主路 = 默认 `xray.exe run -c`（`xray_conf::Config::build()` → `xray_core::start_full`）
- 只读复核，零产品代码改动；脚本落在 `round2/scripts/`，原始输出见 `round2/tmp/`

---

## 0 结论摘要

| # | 裁决 | 一句话 |
|---|---|---|
| **C1** | **CONFIRMED（机制修正）** | 「对端不读 ⇒ policy 失效」成立，且我独立复现了**两个方向**。但根因措辞需修正：**读侧 deadline 确实存在且会准时触发**（实测 2.01s）；坏的是「判定无法执行」——被堵在 `send`/`write` 的四腿永远轮不到看判定，`join!` 又等四腿全归。上传向是**无界泄漏**（与 connIdle 取值无关）。 |
| **C1 修法** | **可行，且不触碰坑约束 ⑫ 的实质** | 最小形态 = **一条 `watch` 中止闸 + 6 个既有 await 点变可中断 + 既有的读超时分支顺手关闸**；四腿结构 / mpsc 容量 / vectored / readv 读腿 / splice 分支**一个都不动**。落点见 §3。 |
| **C2** | **CONFIRMED（E2）** | 锁跨写为真且两 loop 会互等；但**断言里的路径是错的**（不存在的 `crates/xray-app-dns/src/outbound.rs`）——真实位置 `crates/xray-core/src/outbound.rs:1836/1933`。 |
| **C3** | **CONFIRMED（E2）** | 锁跨拨号 + 锁跨写，且 `read_loop` 的判死清槽（`:202/:208`）被同一把锁挡住 ⇒ 死连接永不重拨。字面位置全对。 |
| **C4** | **ADJUSTED（一半反证，一半更严重）** | ①「重复 tag 报 `inbound registry full`」**不可能发生**：udf `BoundedRegistry::insert` 对重复键**静默覆盖并返回 Ok**（`memgov.rs`），该文案只在真达 1024 上限时出现 ⇒ **REJECTED**；真正的缺陷更严重 = **并发同 tag 会静默覆盖 slot、丢掉前一个 cancel 令牌 → 孤儿监听器**。②「Ok 而实际已停」**CONFIRMED（E2，代码可证）**：`build_inbound` 全程不查 `is_cancelled()`，绑定后 `start_inbound` 无条件 `Ok(Some(handle))`。我的外部 E1 无法判定该窗口（见 §5.3），另抓到一处 E1 实证：同 tag 并发 add 的状态码不一致（1/12 把 `existing tag found` 包成 `Internal: unable to listen socket: ...`）。 |

**给 PM 的一句话**：C1 是 blocker 没错，但**别按原修法建议做**（「写臂包 timeout」在默认 300s connIdle + 半窗 1s 的两段语义下修不干净），按 §3 的中止闸形态修。

---

## 1 C1 独立 E1 复现（不沿用上一轮脚本）

脚本：`round2/scripts/verifyC1_leak_instrument.py`（主）、`round2/scripts/verifyC1_s3_states.py`（状态机细观测）。
测量仪器**与上一轮不同**：上一轮用客户端侧 socket 枚举；我用 **xray 进程句柄数（`psutil.Process.num_handles`）+ 按 PID 的连接表 + 0.5s 粒度的 TCP 状态机轮询**，形状也不同（多连接并发、客户端**保持连接但静默**）。

公共配置：`policy.levels["0"].connIdle = uplinkOnly = downlinkOnly = 2`（秒），`inbounds=[socks 127.0.0.1:21280]`，`outbounds=[freedom]`。

### 1.1 S2 对照组：无写阻塞时 connIdle **工作正常**（关键分离变量）

```
== S2 CONTROL-IDLE：目标 accept 后既不读也不写，客户端静默
  client saw_eof=True after 2.01s (expect ~2.0s)
```

**读法**：没有任何在途写时，`up_reader`/`down_reader` 的 `timeout(conn_idle, read)` 于 2.01s 触发 → 四腿退出 → `join!` 返回 → 连接拆掉。
⇒ **「超时机制不触发」这个说法不准确；准确说法是「触发后无法执行」**。这一条把故障变量精确隔离到「写/入队被堵」。

### 1.2 S1 上传向停读（目标永不 read，客户端写满窗口后**保持连接**）

```
[0..5] filled ≈ 10.9-13.3 MB (blocked)        # 6 条连接，全部把 outbound 窗口写死
holding 6 stalled senders for 8s
  [S1-during-stall] handles=203 est_to_blackhole=6 est_to_flood=0
  clients seeing EOF while stalled: 6/6
  after closing all stalled senders (+3x connIdle):
  [S1-after-close] handles=203 est_to_blackhole=6 est_to_flood=0     <<< 不回落
基线 handles=166
```

**读法**：
- `clients seeing EOF 6/6` ⇒ 下行侧按时死了（`down_reader` 的 connIdle 触发 → `down_writer` 退出 → `shutdown_flush` 关了客户端写半部）。**这再次证明读超时是好的**。
- `est_to_blackhole` 从头到尾 **= 6**：客户端全部 `close()` 后再等 3×connIdle，xray 侧到黑洞目标的 6 条 socket **仍全部 ESTABLISHED**，句柄 **Δ+37 不复位**。
- 机制：`up_writer` 卡在 `write_all_mb`（`bridge.rs:452`），`up_rx` 满 → `up_reader` 卡在 `up_tx.send`（`:436`）→ **既不在读也不在任何 deadline 之下** ⇒ 连客户端 close 都读不到（它没在读！）⇒ **无界泄漏，与 connIdle 取值无关**。
- 前提（诚实标注）：这里的「无界」前提是**对端存活但不读**（写永不报错，= 断言描述的场景）。对端进程真的死掉时，`write_all` 会报错而自愈；故这是「活着但僵住的对端」造成的无界占用。

### 1.3 S3 下载向停读（客户端停读，目标狂写）——状态机逐拍

```
client pre-read 1048576B, now stops reading (t=0)
  t=+ 0.5s handles=174 ['21281->0:LISTEN', '21281->6617:ESTABLISHED', '6618->22082:ESTABLISHED']
  t=+ 1.5s ... 同上
  t=+ 2.0s handles=175 ['21281->0:LISTEN', '21281->6617:ESTABLISHED', '6618->22082:FIN_WAIT2']   <<< connIdle 到点
  t=+ 2.5s .. t=+ 8.0s 完全不变（FIN_WAIT2 + 客户端侧 ESTABLISHED 钉住 6 秒以上）
--- client resumes reading
resumed: extra=67166208B eof=False            # 同一条连接又收了 67MB —— 从未被拆
after client close +3s: handles=172 ['21281->0:LISTEN']
```

**读法（这是最干净的一条证据）**：
1. `t≈+2.0s` 时 outbound socket 转 **FIN_WAIT2** ⇒ `up_reader` 的 connIdle 触发、`up_writer` 退出、`s_write.shutdown()`（`:459`）已发出 FIN。**计时器精确工作。**
2. 但 `down_writer`（`:509`）卡在 `writer.write_multi_buffer`、`down_reader`（`:490`）卡在 `down_tx.send` ⇒ `join!`（`:547`）永不返回 ⇒ **入站连接整整 12s 保持 ESTABLISHED（connIdle=2s）**，客户端恢复读取后又在这条「早该被拆」的连接上收了 67MB。
3. 对向不对称性：这条泄漏**只要客户端 socket 真的死掉**（写入报错）就会自愈（`handles` 回落 172）；**客户端活着但不读**则永久钉住。上一轮 E1① 与本条同源，我换仪器/换 payload/换粒度独立得到同一结论。

### 1.4 复跑命令

```
python reports/audit-2026-10-31-perf-mem-wiring/round2/scripts/verifyC1_leak_instrument.py --n 6 --dump
python reports/audit-2026-10-31-perf-mem-wiring/round2/scripts/verifyC1_s3_states.py
```

---

## 2 C1 机制精化（原断言需要修正的两处）

1. **「写臂无 deadline」→ 应改为「判定无法执行」**。读臂有 deadline（`:415/:424/:471/:480`），并且会触发（S2 2.01s、S3 t=2.0s 都有实锤）。缺的是**投递面**：被堵在 `send`/`write` 的腿不再被 poll，既不读、也不看窗口、也不看自己的 deadline；`join!`（`:547`）要求四腿全归，于是「一条腿的判定」永远无法传导成「连接关闭」。
2. **严重度分层**（实测差异，原报告未区分）：
   - 上传向（写 outbound 堵）：**无界泄漏**——不看 connIdle，客户端断开也不释放（S1：Δ37 句柄、6 条 ESTABLISHED 不回落）。
   - 下载向（写 client 堵）：**有界但很长**——`connIdle` 到点后连接仍存活，直到客户端 socket 真死才自愈（S3：12s 存活 + 恢复后 67MB 续传）。
   - 每泄漏一条：**1 条入站 socket + 1 条出站 socket + 4 个 task + 至多 2×64 条 MultiBuffer**（`PIPE_BUF_CAP=64`，`:388`（两条 channel 在 `:390/:392`）；readv 读腿下单条可含多 Buffer，故「≤512KiB」是下限估算而非上限）。
3. **致命组合的准确表述**：`join!` + 不可取消的 `send`/`write`。单独任一项都不致命（`select!` 版桥 `:122-125` 就靠「任一腿结束即 drop 另一腿」规避了这个问题——代价是丢掉 VMess 那种「请求向 EOF 后响应向续传」的语义）。

---

## 3 C1 修法可行性（**本次复核的主交付**）

### 3.1 是否必须改泵结构？

**不必。** 有两类可选修法，且**不需要**动四腿结构、不需要改 mpsc 容量、不需要改 vectored/readv/frozen 读腿、不需要碰 splice 分支。

| 方案 | 形态 | 能否修净 | 结论 |
|---|---|---|---|
| **A. 只给写臂包 `timeout`** | `timeout(w, write_all_mb(..))` ×2 | ❌ | ① 默认 `connIdle=300s`（`xray-features/src/policy.rs:24`），S3 那类停顿要 300s 才拆；② 写腿**不知道当前窗口**（半窗在读者腿里算），要让它知道就得复制 up_done/down_done 状态机 = **双份账本**（CLAUDE.md §3.5.6 明令禁止）；③ 在飞 `timeout` 无法在窗口从 300s 缩到 1s 时「重新武装」（`write_multi_buffer(mb)` 吃所有权，丢弃即丢批）。 |
| **B. 中止闸（推荐）** | 1 条 `watch::channel(false)` + 被堵腿的 await 变可中断；**关闭决定仍由既有读超时做**（单一账本），闸只负责**投递** | ✅ | 与 Go 同构：`signal.CancelAfterInactivity` 关 ctx → `task.Run` 早退 → `common.Interrupt(link)` 打断阻塞写。 |

### 3.2 最小修法形态（file:line 级落点）

只改 `crates/xray-transport/src/bridge.rs` 两个生产函数 + 一个 Linux 变体，**不新增文件/依赖/抽象**：

```
(a) :396 附近（两个 mpsc 之后）新增一条闸，与既有 up_done/down_done 同族：
    let (abort_tx, abort_rx) = tokio::sync::watch::channel(false);
    // 每腿克隆 abort_rx / abort_tx；模块级加一个小 helper（放在 :310 p7lm_trace 旁）：
    /// 连接中止闸：已关时立即 Ready，不重复注册 waker。
    async fn wait_abort(rx: &mut watch::Receiver<bool>) { let _ = rx.wait_for(|v| *v).await; }
    // tokio 1.53（Cargo.toml:102）⇒ wait_for 可用（自 1.28 起存在；探针离线解析到 1.54.1，语义一致）

(b) up_reader 读臂 :415/:424 —— 两处 `Err(_) => break` 改为 `Err(_) => { let _ = abort_tx.send(true); break }`
                                  （connIdle 到点 / 半窗到点 = Go 语义「连接已被判死」，必须广播）

(c) up_reader send 臂 :436 —— 改为
    tokio::select! { _ = wait_abort(&mut abort_rx) => break, r = up_tx.send(mb) => if r.is_err() { break } }

(d) up_writer 写臂 :452 —— 改为
    tokio::select! { _ = wait_abort(&mut abort_rx) => break, r = write_all_mb(&mut s_write, &mb) => if r.is_err() { break } }
    收尾 :459 `s_write.shutdown()` 目前**无界**（:527 的 shutdown_flush 才有 3s）→ 用同款 `timeout(3s, ..)` 兜住

(e) down_reader :471/:480 同 (b)；:490 send 同 (c)
(f) down_writer :509 写臂同 (d)
(g) :547 `join!` **保持原样** —— 四腿现在都能被唤醒了
(h) `bridge_link_with_link`（代理链，`default.rs:2025`）同款：读臂 :719/:764 关闸、写臂 :738/:783 可中断、:798 `join!` 不动
(i) `bridge_link_with_stream_downlink_splice`（Linux，`default.rs:1917`）：上行写臂 :638 同款；下行是内核 splice，不动
```

**为什么它同时满足三种语义**（关键：闸只搬运既有的判定，不新造判定）：

- `connIdle`：由读者腿既有的 `timeout(conn_idle, read)` 判定（`Err(_)` → 关闸）。被堵的写腿/send 腿立刻退出 ⇒ 判定终于能执行。
- `downlinkOnly`：`up_reader` 结束（**含正常 EOF**）后在 `:443` 发 `Some(downlink_only)`，`down_reader` 的 `window` 分支（`:480`）在窗口内无数据 → 关闸。**正常 EOF 不关闸**，VMess「请求向 EOF 后响应向续传」语义不变（`:444` 与 `:497` 的路径未改）。
- `uplinkOnly`：对称（`:497` → `up_reader` 的 `:424`）。
- 写错误**仍然只关本向**（:452/:509 的 `is_err()` 分支不关闸），保留 `50074b2` 教训（瞬时写错不得 shutdown 对向）。

**已知残留（必须在报告里写明，别假装全修）**：**双向同时停读**（出站写堵 + 客户端写堵，两条读者腿都卡在 `send`）时没有任何腿处于读超时之下 ⇒ 仍无判定可搬运。要覆盖它只能给 `send` 臂也加窗口计时（比 Go 的**共享活动计时器**更严：Go 会用「另一方向的进展」重置计时，逐腿计时不会），或引入 `Arc<AtomicU64>` 共享活动刻度（= 第二套记账面，需 PM 裁决）。**这两条我建议作为 C1 的 follow-up 而不是本次 blocker 修复范围**——因为原报告的两条 E1（上传停读 / 下载停读）都不属于这个形态，修 S1 就能全绿。

### 3.2.1 形态已用探针**编译并实测**（不是纸面设计）

探针 `round2/tmp/probe-abort/`（独立 `[workspace]`，只依赖 tokio 的
`rt-multi-thread/macros/sync/time`），实现上述 `wait_abort` 三件事并实测：

```
A) already-closed -> ready in 9.2µs            # 闸已关时零成本直通，不重复注册 waker
B) stuck op interrupted after 204.3502ms       # 能打断一个「永不完成」的 future（=卡在 write_all 的写腿）
C) idle wait returned after 5.009462s          # 5s 空闲等待
   wall=5.41s  last_cpu_sample=0.000s          # <<< CPU 0.000s ⇒ 不 busy-loop
```

判读：`watch` 闸满足「成本 = 每批一次 poll，阻塞期间零 CPU」这条 ⑫ 的前提条件；
且 `watch::Receiver/Sender` 都可 clone，四腿各自持有即可，无需共享 `Mutex`。
（实现注意：`select!` 默认**随机**轮询各分支，故中止臂与数据臂同时就绪时顺序不定——
中止臂是终结分支，谁先谁后都只会多搬一个批次，不影响正确性；写腿被中止时丢弃在飞批次属收尾态。）
复跑：`cd round2/tmp/probe-abort && CARGO_TARGET_DIR=<独立目录> cargo run --release --offline`

### 3.3 是否触碰坑约束 ⑫

**判定：不触碰其实质；但必须带性能门合入。**

- ⑫ 原文（`docs/architecture/xray-frame-强约束插件模型-2026-10-23.md:129`）：「数据面热路径零改动（**buf/copy/splice/poll 语义**）」，立此约束的历史是 vision splice gate 双 revert + bridge 三轮战役 + 154-167 MB/s 锚。它禁的是**改零拷贝/批大小/背压结构**，不是「循环体一个字符都不许动」——后者会让任何数据面缺陷永不可修。
- 本修法：不引入逐字节/逐 Buffer await、不改批边界、不改 coalescing、不动 `write_all_mb` 的 vectored 分支、不动 `readv`/`frozen`/`tls_readbuf` 读腿选择、不动 mpsc 容量与帧格式、不动 splice 分支。**唯一的热路径成本 = 每批多一次 `watch` poll**（与既有的每轮 `timeout()` + 2 个 channel 操作同量级，实测需用 loopback 锚证明）。
- 因此：⑫ 要求的那道性能门必须跑（§6 G6），且**不得**在没有该门的情况下合入。

### 3.4 备选与权衡

- 想要更强的「一关即停、无需级联」语义 → 用 `tokio_util::sync::CancellationToken`（`cancelled()` 可 clone、自带 `run_until_cancelled`）。成本：`crates/xray-transport/Cargo.toml` 加 `tokio-util = { workspace = true, features = ["rt"] }`（**包已在 lockfile 内**，非新增外部依赖）。等价功能，写法更惯用；`watch` 版零 Cargo 改动、且本文件已有两条 watch，故我更倾向 `watch`。
- **不要**引入「泵外 supervisor 定时扫活动时间戳」：那是第二套超时账本，违反 CLAUDE.md §3.5.6「禁止双份账本」，且必须复制 up_done/down_done 状态机。

---

## 4 C2 / C3 判读（E2）

### 4.1 C2 —— DNS-over-TCP 出站写锁

- **位置修正**：真实位置 `crates/xray-core/src/outbound.rs:1836`（response_loop）、`:1933`（`write_client_frame`，request_loop 的 Respond/Hijack/上游内联都走它）、`:1920`（收尾 `writer.lock().await.shutdown()`）。断言里的 `crates/xray-app-dns/src/outbound.rs` **不存在**（该 crate 无 `outbound.rs`）。
- **真能发生吗：能。** 机制闭环：`response_loop` 持 `writer` 锁卡在 `write_multi_buffer`（客户端零窗口）→ `request_loop` 下一次写先卡在 `writer.lock()` → 两条 loop 的 `timeout(timeout, read)` **都不再被 poll** → 末尾 `tokio::select!{ request_loop, response_loop }`（`:1916-1919`）永不到场。与 C1 同族（写臂无 deadline + 锁跨 await），但**互等对象是同一把 std 锁**，比 C1 更死。
- 未做 E1：需要构造「dns 出站 + TCP 上游 + 客户端停读」三件套；本轮只做静态闭环（E2）。

### 4.2 C3 —— wireguard UDP `send` 持锁跨拨号/写

- **位置全对**：`crates/xray-proxy-wireguard/src/driver.rs:144`（取锁）、`:146`（持锁 `connect()`）、`:152`（持锁 `write_all`）、`:202/:208`（`read_loop` 持锁清槽 = 判死路径）。
- **真能发生吗：能，且有两个独立后果。**
  1. **永不重拨**：隧道半死时 `write_all` 不返回（缓冲区满才报错，死链路只会静默堆积），`guard` 不放 → `read_loop` 想 `*writer = None`（`:208`）先卡在同一把锁 → 「读侧判死」与「写侧判死」互相阻塞 = 双份账本互锁。
  2. **拨号期吞吐悬崖**：首包 `connect().await`（真拨号，可能数百 ms）期间整把锁被独占 → 该 destination 的所有 UDP 帧串行排队（不只是故障态，正常冷启动也是）。
- 修法同族：锁内不 await（取出 `Option<WriteHalf>` → 锁外写 → 出错回锁置 None）+ 写有界。三处形态与 C1 一致，可在本 crate 内独立修。

---

## 5 C4 判读

### 5.1 「重复 tag 报 inbound registry full」——**REJECTED**

代码事实：`InboundRuntime.slots` 是 `skeleton_infra::memgov::BoundedRegistry`（`inbound.rs:23`，cap=1024，`Eviction::Reject`，`inbound.rs:3119-3122`），而 `BoundedRegistry::insert`（`crates/udf-frame/skeleton-infra/src/memgov.rs`）：

```rust
pub fn insert(&mut self, k: K, v: V) -> Result<(), BoundError> {
    if let Some(slot) = self.map.get_mut(&k) { *slot = v; return Ok(()); }   // 重复键 = 静默覆盖
    if self.map.len() >= self.max { ... Eviction::Reject => return Err(BoundError{..}) }
```

⇒ `start_inbound` 的 `.map_err(|e| io::Error::other(format!("inbound registry full: {e}")))?`（`inbound.rs:3147-3155`）**对重复 tag 永远不可能命中**（只在 ≥1024 个入站时）。断言此条**不成立**。

### 5.2 同一处的真实缺陷：并发同 tag ⇒ **静默覆盖 slot ⇒ 孤儿监听器**（E2）

`contains()`（读锁，`:3141`）与 `insert`（写锁，`:3147-3155`）之间可被抢占时：
1. A、B 都通过 `contains`；A `insert(tag→slotA)`；B `insert(tag→slotB)` **覆盖** slotA，**slotA 的 `cancel` 令牌被 drop 而从未 `cancel()`**。
2. 两者都去 bind 同一端口 → 一个 `EADDRINUSE` → 其 Err 分支 `self.slots.write().remove(ib.tag.as_str())`（`:3160`）**把胜者的那条 slot 也摘掉**。
3. 结果：**一个正在监听的 listener 既不在注册表里（`remove-inbound` 报 HandlerNotFound）、也永远不会被 cancel** ⇒ 孤儿监听 + 端口被占。
这比「文案误报」严重得多，且**不需要任何微妙时序**——只需要两个 add 落在同一个窗口。

### 5.3 「add 返回 Ok 而实际已停」——**CONFIRMED（E2，代码可证）**

`spawn_one_inbound`（`inbound.rs:4159-4211`）→ `build_inbound`（`inbound.rs:4213+`）**全程不查 `shutdown_token.is_cancelled()`**：先 bind，再把 token 交给 `spawn_inbound_serve`；`:3319` 的 `select!{ serve, shutdown_token.cancelled() }` 在令牌已关时**立即就绪** → serve 立刻退出、listener 立刻 drop；而 `start_inbound` **无条件** `Ok(Some(handle))`（`:3157`）。所以「insert 后被 remove 取消 ⇒ 仍返回 Ok」是**结构性的**，不依赖任何 µs 级竞态。

**我的外部 E1 尝试（结论：不可判定，据实报）**：`round2/scripts/verifyC4_grpc_race.py --rounds 24 --conc 4`

```
t0..t23: add_rc=0 listening=False registered=False listening_after_remove=False -> FALSE_OK_STOPPED
  → 假成功 24/24
```

**这个 24/24 不能当证据**：我的 remover 是持续循环的，绝大多数轮次是「add 完整成功 → 随后被 remove 正常摘除」，我的 `listening` 采样又在 add 返回后 50ms 才做 ⇒ 无法区分「窗口内取消」与「完成后摘除」。**该窗口（bind + spawn，亚毫秒）在进程外不可定时命中**；判定性实验必须在进程内做（§6 G4）。我把它如实降级为 E2。

### 5.4 意外抓到的 C4 侧 E1：同 tag 并发 add 的**状态码不一致**（1/12）

```
rc=1 code:'Some entity that we attempted to create already exists' message:"existing tag found: dup"   ×9
rc=0 added inbound: dup                                                                                 ×2
rc=1 code:'Internal error'                message:"unable to listen socket: existing tag found: dup"    ×1  <<<
```

读法：9 条来自 gRPC 层的前置检查 `ProxymanError::ExistingTag`（`functions.rs:612-614`，AlreadyExists）；那 **1 条**证明**两道 `contains` 都被冲过**——`start_inbound` 自己的 `contains`（`inbound.rs:3141`）输了，返回 `io::Error("existing tag found")`，被 `.map_err(... ListenSocketFailed ...)`（`functions.rs:619`）包成 **Internal / "unable to listen socket"**。
⇒ ①「双重 contains 检查」的 TOCTOU 是**真的、可复现的**；② 同一失败面产出**两种状态码与两种文案**，排障会误判为绑定失败。

---

## 6 验证门（每条修好需要什么测试）

| 门 | 内容 | 判据 |
|---|---|---|
| **G1** | 本报告两个脚本复跑 | S1：全部客户端关闭 + 3×connIdle 后 `est_to_blackhole==0`、句柄回基线 ±6；S3：停读 ≤ `connIdle+1s` 内连接被拆（客户端读侧 EOF、`handles` 回落）；**S2 仍 ≈2s（不许回归）** |
| **G2** | `bridge.rs` 新增 in-crate 单测 | `bridge_link_with_stream_full` + 一个「永不读」的 `AsyncWrite` 半部 + `connection_idle=100ms` ⇒ 整个 future 在 ≤300ms 内 `Ok`/`Err` 返回（当前实现会挂到测试超时）；对称地测下行（`link.writer` 用不读的 sink） |
| **G3** | 半窗语义单测 | `connection_idle=10s, downlink_only=100ms`：客户端半关闭后桥在 ≤~300ms 返回 ⇒ 证明中止闸**没有**破坏 downlinkOnly/uplinkOnly；反向断言：单纯 `up_w.shutdown()`（正常 EOF）时下行的持续传输**不被提前杀**（保 VMess 语义，复用现有 `bridge_link_with_stream_full_default` 用例） |
| **G4** | C4 进程内并发测试（E1 判定性） | `tokio::join!(rt.start_inbound(&ib), async { rt.remove_inbound(tag) })` 反复 N 次：断言「`Ok` ⇒ `contains(tag)`」恒成立；同 tag 并发 add ⇒ **恒**返回 `ExistingTag`（统一状态码）；并断言「端口监听集合 ⊆ 注册表 tag 集合」（抓孤儿监听） |
| **G5** | 端到端 | `run_full32` 32/32；Go↔Rust 双向互通 12/12（停读修复不得改变 wire 行为）；mux carrier（vless+ws+mux）会话复用仍通过 |
| **G6** | ⑫ 性能门（**必须**） | `python tools/loopback_alloc_bench.py --tag c1-abort --runs 3`：双向吞吐 ≥154 MB/s 且波动 <5%，alloc/MB 不增长（新增路径零分配） |
| **G7** | 浸泡 | 64 条「对端不读」连接 × 双向 30s，结束后句柄与 ESTABLISHED 数回落（防改成累积泄漏） |
| **G8** | Linux 专面（本轮不可达） | splice 变体（`bridge_link_with_stream_downlink_splice`）在 Linux CI 跑 G1/G2 同款；`TPROXY`/`tun`/`wg` 数据面未覆盖 |
| **G9** | C2 | DNS-over-TCP 停读：两 loop 须在 `connIdle` 内退出（新单测：`DuplexStream` + 不读的 fake TCP 上游 + 断言 future 有界完成）；且 `writer` 锁不得跨写（可选：`try_lock` 断言） |
| **G10** | C3 | `DialedUdp::send` 对手不读 ⇒ 有界返回；第二次 `send` 触发重拨（`connect` 计数 == 2）；拨号在飞时 `read_loop` 能拿到锁清槽（不互锁） |

---

## 7 「只修 C1、不修 C2/C3」的残留风险（单列）

1. **DNS 面（C2）**：DNS 出站是「每次查询/每客户端一条链接」的高频路径，且**没有连接级 policy 兜底**（`dispatch_dns_link` 的 `timeout` 只包读）。任意客户端连上后停读即可让该会话的 **2 socket + 2 task + 上游 `write_slot`** 永久钉死；反复触发 = 纯资源耗尽面（不需要异常流量，只需慢客户端）。C1 的闸在 `bridge.rs`，**完全覆盖不到** `outbound.rs` 的这把锁。
2. **wireguard 面（C3）**：UDP 泵无 connIdle 语义，死连接的后果是**静默黑洞**而非报错——上层看到的是「UDP 全丢、无错误」，排障成本极高；且首包拨号期整把锁独占 ⇒ 冷启动期该 dest 的 UDP 吞吐塌陷。C1 修不到（不同 crate/不同机制）。
3. **同族未列站点**：所有 UDP 泵（freedom `udp.rs` 的 `pump_request/pump_response`、socks `udp.rs`、ss `pump_ss_udp`、tuic、hysteria）都是「读有 deadline / 写裸写」的同一形状，本轮未逐站核（C1 的修法可复用，但不在本条 blocker 范围）。
4. **C1 自身的残留**（若只按 §3.2 的 S1 修）：**双向同时停读**仍无判定可搬运（见 §3.2 末）；建议随 follow-up 用共享活动刻度或 `send` 臂加窗解决，并明确该取舍是「比 Go 更严」还是「引入第二账本」。
5. **C4 与 C1 无关**：孤儿监听 + 假成功是 API 面缺陷，C1 修完照样存在；且 `BoundedRegistry::insert` 的「重复键覆盖」是 udf 语义，若在 udf 侧改成 fail-closed 会影响其他消费者（须走 §3.5.2 提炼回路），主仓侧更稳的做法是**insert 前在同一把写锁内再查一次**。

---

## 8 未覆盖范围（据实声明）

- **Linux 专有面**：splice 快路径、TPROXY、tun/wireguard 数据面在 Windows 不可达 → 未实测；C1 修法在本机只对「池化泵」验证过。
- **mux 写路径**（`xray-mux` 的 XUDP/SharedWriter）未做停读压测，只静态看过会话泵；可能有同类写臂。
- **C2 未升级 E1**（缺 dns-outbound + TCP 上游 + 停读客户端三件套编排）。
- **C4a「Ok 而实际已停」未获外部 E1**（原因见 §5.3，非"没测"）；**C4b 的「孤儿监听」也未 E1**（同一窗口问题）。
- 未审性能/内存计量（非目标）。
- 附带观察（不在本轮发现清单，仅记录以便 PM 归口）：`commander: inbound added/removed via gRPC` 这两条 `tracing::info!` **在 `loglevel=info` 下没有出现在 stdout**（`add`/`remove` 均 rc=0；同期启动期 INFO 与 30s 后的 DEBUG 都正常打印）。我因此无法用日志时间戳做 C4a 的判别器；这条**静默可观测性缺口**建议另立一条（不属 C1–C4）。

## 9 环境说明

- 我的端口段：socks 21280/21281、黑洞/洪泛 22080-22082、gRPC api 18090/18091、C4 动态入站 24000+/18100/18200。
- 期间 `AdversarialInput` 执行过一次 `Stop-Process -Name xray -Force`；我的实例全部经 `subprocess.Popen` 持有并在 `finally` 按 PID 清理，**本轮所有轮次均正常完成**（C4 两轮、S3 两次、C1 主脚本一次皆无中断），未观察到被误杀影响。
- 无产品代码改动；`git status` 中新增文件仅为本报告与 `round2/scripts/` 下 3 个探针脚本。

---

## 10 裁决表（9 列）

| 编号 | 原断言 | 裁决 | 复现/反证命令与输出 | 是否触碰热路径红线 | 最小修法 | 验证门 | 风险 | Go 对照 |
|---|---|---|---|---|---|---|---|---|
| **C1** | 写臂无 deadline + `bridge.rs:547 join!` 四腿 ⇒ 对端不读时 connIdle/uplinkOnly/downlinkOnly 全失效 | **CONFIRMED（机制修正）**：读 deadline **存在且准时**（S2 2.01s / S3 t=2.0s），失效点是**判定不可执行**；上传向**无界**（Δ37 句柄、6 条 ESTABLISHED 不回落，客户端已全关），下载向**12s 存活 + 恢复续传 67MB** | `python round2/scripts/verifyC1_leak_instrument.py --n 6 --dump`；`python round2/scripts/verifyC1_s3_states.py`（输出见 §1） | **不触碰实质**：四腿结构/mpsc 容量/vectored/readv/frozen/splice 全不动，仅既有 await 点加 select 臂（每批 +1 次 watch poll）→ **必须带 G6 性能门** | `bridge.rs:396` 加 `watch::channel(false)` 中止闸；`:415/:424/:471/:480` 超时分支关闸；`:436/:452/:490/:509` 改 `select!{wait_abort, op}`；`:459 s_write.shutdown()` 加 3s 界；`bridge_link_with_link` 同款（`:719/:764/:738/:783`）；splice 变体 `:638` 同款 | **G1 G2 G3 G5 G6 G7**（+G8 Linux） | 双向同时停读仍未覆盖（§3.2 末）；中止时丢弃在飞批次（收尾态，可接受）；`send` 臂加窗版比 Go 共享计时器更严 | `common/task/task.go:51`（`case <-ctx.Done(): return`）+ `common.Interrupt(link)`（`proxy/freedom/freedom.go:233-234`）+ `CancelAfterInactivity`（写阻塞=无进展=计时触发） |
| **C2** | DNS-over-TCP writer 锁跨 `write_multi_buffer().await` → 客户端不读时两 loop 互等同一锁 | **CONFIRMED（E2）**；**路径错误已纠正**：`crates/xray-app-dns/src/outbound.rs` 不存在，真实 `crates/xray-core/src/outbound.rs:1836/1933`（+`:1920` 收尾亦无界） | 静态闭环（§4.1）：`writer.lock().await.write_multi_buffer(..)` 持锁跨写 → request_loop 先卡锁 → 两 loop 的 `timeout(read)` 都不再被 poll → `:1916-1919 select!` 永不到场 | 同族（该函数非桥热路径，独立函数） | 写客户端也走同一取消令牌/有界化；或锁内只出队、锁外写 | **G9** + G5 | 高频路径且**无 policy 兜底**（仅读有 timeout）→ 慢客户端即可钉死 2 socket+2 task+上游 slot | `proxy/dns/dns.go:226` CancelAfterInactivity → task.Run 早退 |
| **C3** | wireguard UDP `send` 持锁跨拨号与 `write_all` → 死连接继续写、永不重拨 | **CONFIRMED（E2）**；位置全对（`:144/:146/:152` + 判死路径 `:202/:208`） | 静态闭环（§4.2）：`read_loop` 的 `*writer = None` 需同一把锁 ⇒ 与卡在写的 `send` 互锁；另发现「拨号期独占锁 ⇒ 该 dest UDP 串行」 | 同族（非 bridge 热路径） | 锁内不 await：取出 `Option<WriteHalf>` → 锁外写 → 出错回锁置 None；写加 deadline | **G10** + G5 | UDP 泵无 connIdle ⇒ 死连接表现为**静默黑洞**（不报错）；冷启动吞吐悬崖 | `proxy/wireguard/client.go:230` CancelAfterInactivity；`bind.go` 读队列与写无共享可变槽 |
| **C4** | `start_inbound`/`remove_inbound` 竞态可返回 Ok 而实际已停；重复 tag 报 `inbound registry full` | **ADJUSTED**：①「registry full 误报」**REJECTED**（`BoundedRegistry::insert` 对重复键静默覆盖并 `Ok`，该文案只在 ≥1024 时出现）；②同处真缺陷 = **静默覆盖 slot ⇒ 丢前一个 cancel 令牌 ⇒ 孤儿监听器**（更严重）；③「Ok 而实际已停」**CONFIRMED（E2，`build_inbound` 不查 `is_cancelled`，`start_inbound` 无条件 Ok）**；④E1 另证：同 tag 并发 add 出现**两种状态码**（AlreadyExists ×9 vs Internal "unable to listen socket" ×1） | `python round2/scripts/verifyC4_grpc_race.py --rounds 24 --conc 4`（E1，§5.4 输出）；`start_inbound`/`remove_inbound`/`BoundedRegistry::insert` 逐行核对（§5.1–5.3） | 不涉及 | insert 与 spawn 在同一把写锁内完成（或 insert 前写锁内复查 + 状态位 Starting/Listening），并在取消时返回 Err；同 tag 错误统一为 `ExistingTag`；`insert` 重复键改为 fail-closed（主仓侧先查，不改 udf 语义除非走提炼回路） | **G4**（进程内并发，判定性）+ G5 | 孤儿监听端口永久占用且不可摘除 → 后续同端口 add 恒 EADDRINUSE；API 假成功误导运维 | `app/proxyman/inbound/inbound.go:39/73` Add/Remove 全程 `m.access.Lock()`；重复 tag 报 `existing tag found`；Remove 在锁内同步 Close |

---

## 附：本轮产出

- `round2/scripts/verifyC1_leak_instrument.py`（C1 主 E1，句柄+连接表仪器）
- `round2/scripts/verifyC1_s3_states.py`（C1 下载向状态机逐拍观测）
- `round2/scripts/verifyC4_grpc_race.py`（C4 gRPC 并发探针）
- `round2/tmp/probe-abort/`（§3.2.1 中止闸形态探针，独立 workspace）
- `round2/tmp/log-verifyc1-instrument.txt`、`log-verifyc1-s3states.txt`、`log-verifyc4-api*.txt`、`cfg-verifyc{1,4}-*.json`
- 构建目录 `target-VerifyC1` 已按约定删除
