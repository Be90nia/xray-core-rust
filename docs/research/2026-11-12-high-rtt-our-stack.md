# 调研轨 C · 我们这栈能白拿的能力 + 零代码（内核/运维层）杠杆

> 2026-11-12 · 配合 [`2026-11-12-high-rtt-brief.md`](2026-11-12-high-rtt-brief.md)（共享简报）· **纯调研，未改任何代码/配置**
>
> **tier 口径**：tier1 = 论文/RFC/**上游仓库源码**；tier2 = 官方文档/man page/issue；tier3 = 博客/论坛。
> **裁决口径**：`直接可用` / `需改造` / `不适用（附理由）`——本报告**多数条目裁决为「不适用」或「需改造」**，这是简报 §2 实测（窗余量 8.7×、受控台在途 2.4MB ≪ 窗地板 20.8MiB）与源码事实交叉后的必然结果，不是保守。
> **依赖口径**：**不引入任何新依赖**（全部指向已装依赖能力、已装 crate 的公开 API、或内核/运维层）。

---

## 0. 结论速览

### 0.1 一句话答案（三问各一句）

1. **h2 crate 能不能白拿自适应窗？** — **能，但不在 h2 里，在 hyper 里，而且方向是错的。**
   我们生效的 **`h2 0.4.19`**（⚠️ 内部记录写的是 0.4.20）与 0.4.20 全源码零 `adaptive|bdp` 命中（tier1，源码扫描，见 §1.1）；
   但我们已装的 **`hyper 1.10.1`** 实现了完整的 **BDP-PING 自适应流控**（tier1，`hyper/src/proto/h2/ping.rs`），
   开关就叫 `adaptive_window(true)`，**且 hyper-util 0.1.20 的 legacy Client 也透出了 `http2_adaptive_window`**——
   即**零新依赖、一行接线**就能开。
   **但**：① 它只放大**「我收」的窗**（我们卡的是「我发」的方向，且我们几乎不收 DATA ⇒ 采样器永不触发）；
   ② 它启动时把窗压回 **65535**（`SPEC_WINDOW_SIZE`），比我们现值小 256 倍；
   ③ 双方都开会在 h2 0.4.19/0.4.20 上**触发永久死锁**（h2#975，上游至今 open）。
   ⇒ **裁决：不适用**（方向错 + 起始窗更小 + 双开死锁），详见 §1。

2. **我们仓内已装能力可复用性** — **BBR 不可复用到 TCP 侧**（它是 QUIC 包级 CC，且生产已被 quinn 内建 BBR 顶替，`BbrSender` 是桩）；
   **xhttp 读批已经是 64KiB**（不是 8KB，与 ss 的 `c9f51064` 场景不同，无需再治）；
   **诊断 env 不该升级为正式旋钮**（应当**保留**为诊断 env，但重命名 + 补文档），详见 §2。

3. **零代码杠杆** — **内核层唯一还站得住的一条是「抬 `net.ipv4.tcp_rmem[2]` / `tcp_wmem[2]`（autotune 上限）」**，
   但**注意别抬错 knob**：`net.core.rmem_max` / `wmem_max` **只对显式 `setsockopt` 生效、对 autotune 完全无效**，
   而显式设窗 = **关掉 autotune 并锁死窗口** = 我们的 r5j96 血案（WSL netem 300ms 实测 0.80 vs Go 7.43 MB/s，9 倍差）。
   ⇒ **裁决：`net.core.rmem_max`/`wmem_max` = 不适用（这条路已关死）；`tcp_rmem[2]`/`tcp_wmem[2]` = 需实测（唯一候选）**。
   但**更要紧的是先分清哪一段**：受控台 200ms 在**客户端↔节点**（客户端机），生产 200ms 在**客户端↔CF**（**我们管不到**）⇒
   节点侧内核窗对**生产症状基本无关**。真正可立即试的是**单核 CPU 侧的零代码旋钮**（见 §3.3），
   而它们省的是**内核 softirq/调度**开销，不是 TLS/h2 用户态开销，对 33MB/s 天花板**预期收益 ≤5%**。

### 0.2 三档分类速查（验收要求的「现在就能白拿 / 需要小改 / 需要新依赖或 fork」）

| 档 | 条目 | 裁决 | 一句话 |
|---|---|---|---|
| **现在就能白拿** | hyper `adaptive_window` | ❌ 不适用 | 方向错（只放大收窗）+ 起始窗 65535 + 双开死锁（h2#975） |
| | h2 `Connection::set_initial_window_size` / `set_target_window_size`（运行时改窗） | ❌ 不适用 | h2 有 API 但 **hyper 不透出**；且 h2#976 的缩窗额度 bug 在 0.4.19/0.4.20 未修 |
| | `h2::data_frame_budget(n)`（0.4.18+ 新 API） | ⚠️ 需改造（极小） | hyper 1.10.1 **不透出**这个 builder 方法；只有直接用 h2 的 crate 能设。作用是**限制**小 DATA 帧预算，与吞吐方向相反 |
| | `XRAY_H2_*_OVERRIDE_BYTES` 诊断 env | ✅ 直接可用（**保持诊断级**） | 已被 E1/E4 证伪为提吞吐手段；**不该升级为正式旋钮**（正式旋钮会变成长期 API 债） |
| | xhttp 读批 64KiB | ✅ 已具备 | `hub/handler.rs:56` `DUPLEX_BUF=64KiB` + `dl_stream.rs` `PoolStream(64KiB)` |
| | `Connection::tls_readbuf_size()` 钩子 | ✅ 已具备 | xhttp 侧**未用**（它管的是 TLS 层读批，xhttp 是 h2 层）；ss 已用（`c9f51064`） |
| | 我们自己的 BBR（`xray-transport-quic/.../bbr/`） | ❌ 不适用 | QUIC 包级 CC；生产已被 quinn 内建 BBR 顶替（`quinn_bridge.rs:517` 明说本仓 BbrSender 是桩）；且**没有任何 TCP 侧消费点** |
| | **需要新依赖或 fork** | — | **无一条建议 fork/vendor h2**。若真要「自适应窗」，正解是**换用 hyper 的 adaptive_window 或等上游 h2 实现**，不是 fork |

### 0.3 本轨与另外两轨的关系（防重复）

- 轨 A（论文/RFC）负责「原理上有什么机制」；轨 B（GitHub 成熟实现）负责「别人默认参数是多少」。
- **本轨只回答**：(a) 我们**已装的 crate** 里有没有现成能力被漏用了；(b) 我们**仓内**的事实（读批、闸、BBR、env 语义）；(c) **内核/运维层**的零代码杠杆；(d) **反例**（调内核窗/sysctl 的坏处）。
- 轨 B 已覆盖 gRPC-Go `bdpEstimator` / nghttp2 / quinn / Go http2 / HAProxy / Envoy / nginx / Caddy —— **本报告不重复**，只在需要对比时引用其结论。

---

## 1. h2 / hyper：自适应窗能不能白拿

### 1.1 事实核对：我们的 h2 版本与「h2 无 adaptive_window」这条内部记录

**我们的版本**（tier1，`Cargo.lock` 实读）：

| crate | 我们的版本 | 备注 |
|---|---|---|
| `h2` | **0.4.19** | ⚠️ **简报/内部记录写的是 0.4.20 —— 实为 0.4.19**（`Cargo.lock:1588-1591`） |
| `hyper` | **1.10.1** | `Cargo.lock:1847-1850` |
| `hyper-util` | **0.1.20** | `Cargo.lock:1899-1902` |
| `http` | 1.4.2 | |
| `httparse` | 1.10.1 | |

> `h2 0.4.20` 已发布（2026-10-06，crates.io API；tier2），我们锁在 **0.4.19**。
> 本地 cargo registry 里两个版本都有（`~/.cargo/registry/src/index.crates.io-*/h2-0.4.19` 与 `h2-0.4.20`），
> 但**生效的是 lockfile 的 0.4.19**。这条差异对 §1.4 的 #976 判断有直接影响。

**「h2 0.4.20 全源扫描无 adaptive_window」这条记录 —— 核实结果：属实，且我们实际用的 0.4.19 同样如此（tier1，源码扫描）**：

```
grep -ril "adaptive|bdp|BDP|dynamic_window|auto_window"
  → h2-0.4.20/src/** = No matches found
  → h2-0.4.19/src/** = No matches found     ← 我们生效的版本，同样零命中
```

`h2` crate 自己的流控模型是**静态的**：`initial_window_size` / `initial_connection_window_size` 在**握手期定死**，
之后只有「消费到半窗才发一次 `WINDOW_UPDATE`」的退款机制，**没有任何按 RTT/带宽重算窗的逻辑**。

**但真正的自适应实现不在 h2，而在 hyper** —— 这是我们内部记录漏掉的一环，也是本轨最重要的事实。

### 1.2 【白拿候选】hyper 1.10.1 的 `adaptive_window`：完整的 BDP-PING 自适应流控

**来源（tier1，上游源码，本地 cargo registry 逐行核对）**：

- `hyper-1.10.1/src/proto/h2/ping.rs` —— BDP 算法本体（模块头有完整算法注释）
- `hyper-1.10.1/src/client/conn/http2.rs:365` / `server/conn/http2.rs:183` —— `adaptive_window(bool)` builder
- `hyper-1.10.1/src/proto/h2/client.rs:138-143` / `server.rs:154-163` —— BDP 注入点
- `hyper-1.10.1/src/proto/h2/client.rs:240-243` / `server.rs:349-352` —— 窗口更新执行点
- `hyper-util-0.1.20/src/client/legacy/client.rs:1402-1405` —— `http2_adaptive_window(bool)`（**legacy Client 透出**）

**算法（`ping.rs` 模块头逐字，tier1）**：

```
1. When receiving a DATA frame, if a BDP ping isn't outstanding:
   1a. Record current time. 1b. Send a BDP ping.
2. Increment the number of received bytes.
3. When the BDP ping ack is received:
   3a. Record duration from sent time.
   3b. Merge RTT with a running average.
   3c. Calculate bdp as bytes/rtt.
   3d. If bdp is over 2/3 max, set new max to bdp and update windows.
```

**关键常量与行为（tier1，`ping.rs` 源码）**：

| 项 | 值 | 出处 |
|---|---|---|
| BDP 上限 `BDP_LIMIT` | **16 MiB** | `ping.rs`：`const BDP_LIMIT: usize = 1024 * 1024 * 16;` |
| 带宽估计式 | `bw = bytes / (rtt * 1.5)` | `Bdp::calculate` |
| 窗更新判据 | `bytes >= bdp * 2 / 3` ⇒ `bdp = (bytes * 2).min(BDP_LIMIT)` | `Bdp::calculate` |
| RTT 平滑 | `self.rtt += (rtt - self.rtt) * 0.125`（1/8 移动平均） | `Bdp::calculate` |
| ping 间隔 | 起始 100ms，每翻倍 ×2，稳定后 ×4（上限 10s） | `ping_delay` |
| **起始窗** | **`SPEC_WINDOW_SIZE = 65_535`** | `hyper/src/proto/h2/mod.rs:30` |
| 执行动作 | `conn.set_target_window_size(wnd)` + `conn.set_initial_window_size(wnd)` | `client.rs:241-242` / `server.rs:350-351` |

**两个必须知道的坑（tier1，源码直读）**：

1. **`adaptive_window(true)` 会把我们的 16/32MiB 静态窗「压回」65535**：
   ```rust
   // hyper-1.10.1/src/client/conn/http2.rs:365-374
   pub fn adaptive_window(&mut self, enabled: bool) -> &mut Self {
       use proto::h2::SPEC_WINDOW_SIZE;
       self.h2_builder.adaptive_window = enabled;
       if enabled {
           self.h2_builder.initial_conn_window_size = SPEC_WINDOW_SIZE;   // 65535
           self.h2_builder.initial_stream_window_size = SPEC_WINDOW_SIZE; // 65535
       }
   ```
   且 `initial_stream_window_size()` / `initial_connection_window_size()` setter **都会把 `adaptive_window` 置回 `false`**
   （`client.rs:323-326`、`338-339`；`server.rs:159-160`、`172-173`）——
   也就是说**我们现在的接线（显式设 32MiB/16MiB）天然与 adaptive 互斥，二者只能选一**。

2. **hyper 只在「收到 DATA」时触发 BDP 采样**（`record_data`，`ping.rs:196`）：
   也就是说它测的是**「我收」方向的 BDP**，放大的是**对端能发给我多少**的窗。

**裁决：不适用** —— 四条独立理由：

1. **方向错（决定性）**：我们卡的是**发送方向**（节点→客户端推大文件）。发送方向能发多少，由**客户端授予我们的窗**
   决定，服务端改自己的收窗**对该方向零影响**。hyper 的 BDP 采样器挂在 `record_data`（收到 DATA）上，
   在我们的场景里节点**几乎不收 DATA**（xhttp 场景下客户端只发请求头/分片），采样器**永远不触发** ⇒ 窗恒为 65535，
   **反而把我们 16MiB 的服务端收窗砍到 64KiB**（1/256）。这是**净负收益**，不是「无收益」。
2. **即使方向对，量级也不对**：我们服务端流窗 16MiB / 连窗 32MiB ≫ BDP（受控台在途 2.4MB；真实路径 200ms×40MB/s ≈ 8MB）。
   BDP 自适应的收益公式只在「窗 < 1.5×BDP」时成立。
3. **起始窗倒退**：见坑 1。
4. **双开死锁（tier1，上游 issue）**：见 §1.3。

### 1.3 【必须知道的风险】h2#975：双端 adaptive_window = 永久死锁（上游至今 open）

**来源（tier2，上游 issue 全文，2026-10-08 建、至今 open）**：<https://github.com/hyperium/h2/issues/975>

> **标题**：Connection deadlock under bidirectional bulk data: both peers stop reading while a PONG/PING/SETTINGS write is pending (poll_ready gates poll_next)

**根因（issue 原文）**：`proto::Connection::poll2` 在每次 `codec.poll_next` 前先 `ready!(self.poll_ready(cx))`。
`poll_ready` 会先 flush 待写的 PONG / user PING / SETTINGS / SETTINGS ACK；
若对端不读（发送缓冲塞满 DATA），`poll_ready` 返回 `Pending` ⇒ **连接停止读 socket**。
双方同时进入该状态 ⇒ 永久死锁。

**复现矩阵（issue 原文，TLS，10 streams/conn，1MiB×100 / 5MiB×50 streams）**：

| client adaptive | server adaptive | 死锁次数 |
|---|---|---|
| on | on | **4 / 12** |
| on | off | 1 / 12 |
| off | on | 0 / 12 |
| off | off | 0 / 12 |

h2 0.4.20 双开：**2 / 12**。

**触发条件（issue 原文点名）**：
「Adaptive window makes the state likely because **both peers** emit control frames throughout a transfer: BDP PINGs, their PONGs, and SETTINGS changes.」
并明确：**「Client-only keepalive PINGs with fixed windows did not reproduce it in 12 runs」**。

**对我们意味着什么**：
- 我们**单端**开 adaptive 不会触发（矩阵里 server=on/client=off 是 0/12）。
- 但我们的**对端是 Cloudflare 边缘 / Go 官方客户端**——**它们不跑 hyper 的 adaptive** ⇒ 单端开在生产上**不会**撞 #975。
- **危险在于回环/自测场景**：我们仓内 `xray-transport-splithttp` 的**客户端与服务端两端都是 hyper**；
  若哪天为了「实验」双端都开 adaptive，**我们的自测就会 1/3 概率挂死**。
- ⇒ **裁决：即便将来要开，也必须单端开，且写进代码注释当红线**。

**⚠️ 另一条同族事实（tier2，issue 原文引用）**：#975 里客户端在 BDP 更新后
「queued a `Settings { initial_window_size: 3213342 }`」—— 说明 **adaptive 路径会真的在运行期发 SETTINGS 帧改窗**，
这正是 h2#976 那个 bug 的触发面（见 §1.4）。

### 1.4 【上游状态核实】h2#976：迟到的 SETTINGS ACK 缩窗 → 接收侧停摆

**来源（tier2，上游 issue，2026-10-09 建，2026-11-10 关闭）**：<https://github.com/hyperium/h2/issues/976>

**机制（issue 原文）**：`Recv::apply_local_settings` 的 `Ordering::Less` 分支（收到对端/本地 ACK 后把接收窗调小）
调用 `dec_recv_window(dec)` 后**不重新检查**「已释放但被批量攒着的额度」是否变得可退款 ⇒
该 stream 不进 `pending_window_updates` ⇒ 对端收不到 `WINDOW_UPDATE` ⇒ **双方互等，接收侧永久停摆**。

**上游修复状态（我逐行核对了两份源码）**：

| 版本 | `recv.rs` 的 `Ordering::Less` 分支 | 是否含修复 |
|---|---|---|
| **h2 0.4.19（我们的版本）** | `dec_recv_window(dec)` 后**无** requeue（本地 `h2-0.4.19/src/proto/streams/recv.rs:606-618`） | ❌ **未修** |
| **h2 0.4.20（最新发布）** | 同上，**无** requeue（本地 `h2-0.4.20/src/proto/streams/recv.rs:604-616`） | ❌ **未修** |
| **h2 master（`b0e89084` 之后）** | `dec_recv_window(dec)` 后有 `if stream.recv_flow.unclaimed_capacity().is_some() { pending_window_updates.push(&mut stream); }` | ✅ **已修** |

> master 修复的**确切位置**（tier1，`raw.githubusercontent.com/hyperium/h2/master/src/proto/streams/recv.rs`）：
> 在 `Ordering::Less` 分支内，`dec_recv_window(dec)` 之后追加 requeue 判定。
> **0.4.19 与 0.4.20 的该分支都没有这段**（我在本地 registry 的两份源码里逐行确认）。

**裁决**：这是「**要动态改窗就会踩的坑**」的实证——**我们锁在 0.4.19，恰好是未修的版本**。
任何走「运行期改 SETTINGS_INITIAL_WINDOW_SIZE」的路（hyper adaptive_window 正是这条路），
在我们当前依赖上都带这个风险 ⇒ **进一步支持「不适用」的裁决**。

**顺带一条可白拿的事实**：`h2::client::Connection::set_initial_window_size` / `set_target_window_size`
（tier1，`h2-0.4.20/src/client.rs:1402` / `:1420`；`server.rs:469` / `:487`）**是 h2 的公开 API**，
说明 h2 **本身支持运行期改窗**——但 **hyper 不透出**这两个方法（hyper 的 `Connection` 只暴露
`graceful_shutdown` / `poll_ready` / `send_request` 等），所以**经 hyper 用就拿不到**。
⇒ 要用就得**绕过 hyper 直接用 h2**（我们仓内 `xray-proxy-http` / `xray-transport-grpc` 已经是直接依赖 `h2`，
但 `xray-transport-splithttp` 走的是 hyper ⇒ **要改 splithttp 的窗机制就得把那一层换成裸 h2 = 大改**）。
⇒ **裁决：不适用（改动量远超收益）**。

### 1.5 【顺带发现】h2 0.4.18+ 的 `data_frame_budget`：方向与我们要的相反

**来源（tier1，本地源码）**：`h2-0.4.20/src/proto/connection.rs:93-108`（`DataFrameBudget::resolve`）、
`src/proto/streams/counts.rs:81-140`。

- `DataFrameBudget::Auto` = `connection_window / 2`，下限 `DEFAULT_DATA_FRAME_BUDGET = 256 × 100 = 25_600` 字节
  （`h2-0.4.20/src/proto/mod.rs:38-39`）。
- 作用：**限制**「过小的 DATA 帧」总量（`< DEFAULT_DATA_FRAME_OVERHEAD_THRESHOLD = 256` 字节的帧算「小帧」），
  超出预算就**不再释放流控额度**⇒ 逼对端少发小帧。
- **我们已装的 hyper 1.10.1 不透出这个 builder 方法**（`grep data_frame_budget hyper-1.10.1/src` = 0 命中），
  只有直接用 h2 的 crate（`xray-proxy-http`、`xray-transport-grpc`、`xray-transport-splithttp` 的 `h2 = { version = "0.4", features = ["stream"] }`）
  能设。
- **裁决：不适用** —— 它是**限制**小帧的机制，与「高 RTT 下少帧多批」的诉求方向相反；
  且我们若把 connection window 设成 32MiB，Auto 预算 = 16MiB（很宽松，几乎不 binding）。
  **唯一可能的价值**：若我们观察到小帧风暴导致 h2 侧效率低，可显式设小预算卡住对端。
  ⇒ 记为**待观察项**，不是提案。

**⚠️ 一条版本敏感的差异（对我们当前锁定版本不利，tier1 源码对比）**：
`data_frame_budget` 的 **Auto** 模式在两个版本里的求值时机不同：

| 版本 | Auto 求值时机 | 后果 |
|---|---|---|
| **h2 0.4.19（我们的版本）** | `client.rs:1366-1369` / `server.rs:1535-1539` 在**握手构造期一次性** `resolve(initial_target_connection_window_size)` ⇒ 存进 `Config.data_frame_budget: usize`（`proto/connection.rs:86` 是**裸 usize**） | **运行期改窗不会更新预算** |
| **h2 0.4.20** | `Config.data_frame_budget` 改成 `DataFrameBudget` 枚举（`proto/connection.rs:89`），`streams/counts.rs:112-116` 的 `set_target_connection_window_size` 会**重算** Auto 预算 | 运行期改窗会同步更新 |

0.4.20 的 CHANGELOG 逐字印证：「Fix automatic small DATA frame budget to update when the connection window
changes at runtime.」（`h2-0.4.20/CHANGELOG.md` 第 4 行）。

⇒ **这是「运行期改窗」这条路的第三道保险丝**（前两道：#976 缩窗停摆、#975 双开死锁）：
**在我们锁定的 0.4.19 上，运行期改窗会让 h2 的小帧预算与实际连窗脱节**（预算停在握手时的值）。
⇒ **再次支持「不适用」的裁决**；若将来真要走这条路，**先升 h2 到 ≥0.4.20**。

### 1.6 【纠正一条可能的误解】h2 的 `max_frame_size` 与我们的 DATA 帧粒度

- `DEFAULT_MAX_FRAME_SIZE = 16_384`（tier1，`h2-0.4.20/src/frame/settings.rs:47`），上限 `MAX_MAX_FRAME_SIZE = 16_777_215`。
- **发送侧的帧大小由「对端通告的 MAX_FRAME_SIZE」决定**（tier1，`h2-0.4.20/src/codec/framed_write.rs:47`：
  `max_frame_size: FrameSize, // Max frame size, this is specified by the peer`）。
- 我们已在 `h2_params.rs` 支持 `maxreadframesize` → `max_frame_size`（16KiB..=16777215 生效，Go 同区间），
  但**缺省不改**（走 h2 默认 16KiB）。
- **裁决：不适用（作为提速手段）** —— 16KiB 帧 + 64KiB 读批意味着每次读批切 4 帧，
  这与 ss 路径 `c9f51064`（8KB→57.8KB）的「批粒度」问题**同族但已在 64KiB 档**（§2.3）。
  帧大小只影响 h2 层 frame header 开销（每 16KiB 9 字节 ≈ 0.05%），**不是瓶颈**。

### 1.7 §1 小结：给「不 fork h2 的前提下，我们最多能把流窗/连窗/send_buf 设成什么」的直接回答

| 旋钮 | 我们的现值 | 不用 fork 能设到的上限 | 副作用 | 裁决 |
|---|---|---|---|---|
| h2 流窗（SETTINGS_INITIAL_WINDOW_SIZE） | 客户端 32MiB / 服务端 16MiB | `2^31-1`（`MAX_INITIAL_WINDOW_SIZE`，tier1 `h2-0.4.20/src/frame/settings.rs:50`） | 内存账本（窗 = 对端可无背压灌入的额度，每连接一份） | 已远超 BDP，**不建议再调** |
| h2 连窗 | 32MiB | 同上 | 同上 | 同上 |
| h2 send_buf（`max_send_buf_size`） | 16MiB | `u32::MAX`（tier1 `h2-0.4.20/src/client.rs:1078`：`assert!(max <= u32::MAX as usize)`） | **真缓冲**（连接级，物理占用）⇒ 内存账本按连接数 × 值入簿 | E4 已证 2M/5M/16M 全平（差 <3%），**不建议再调** |
| h2 `max_frame_size` | 16KiB（h2 默认） | 16MiB | 无（纯开销参数） | 不影响流控天花板，**不是杠杆** |
| **运行期改窗** | 不支持（经 hyper） | h2 有 API（`set_initial_window_size` / `set_target_window_size`），**hyper 不透出** | **三道保险丝**：①h2#976 缩窗停摆（0.4.19 未修）；②h2#975 双开死锁；③0.4.19 的 `data_frame_budget` Auto 不随运行期连窗更新（0.4.20 才修） | **需改造（换掉 hyper 层 + 升 h2）⇒ 不建议** |
| **自适应窗** | 不支持 | hyper `adaptive_window(true)` **一行可开**（零新依赖） | 起始窗倒退回 65535 + 只管接收方向 + 双开死锁 | **不适用** |

**一句话**：**不 fork h2 的前提下，我们能自由设的窗/缓冲都已经远超 BDP，把它们再放大没有吞吐收益；
唯一「能白拿但不该拿」的是 hyper 的 `adaptive_window`。**

---

## 2. 我们仓内已装能力可复用性

### 2.1 我们的 BBR（`crates/xray-transport-quic/src/congestion_swappable/bbr/`）能不能用于 TCP 侧决策？

**结论：不适用**（三条独立理由，全部 tier1 源码级）

**理由 1 —— 它是 QUIC 包级拥塞控制，不是 TCP 的**：
- `BbrSender` 实现 `CongestionControl` trait（`crates/xray-transport-quic/src/congestion_swappable/types.rs:75`），
  该 trait 的方法签名是**包/ack 粒度**（`on_congestion_event`、`on_ack(rtt, app_limited)`），
  输入来自 **quinn**（UDP）。TCP 侧没有任何 ack/loss 事件源喂它。
- `bbr_sender.rs` 的字段全是 QUIC 概念：`bytes_in_flight`、`congestion_window`、`pacing_rate`、`max_datagram_size`。

**理由 2 —— 它在生产里已经被顶替，自己人标注为「桩」**：
`crates/xray-transport-quic/src/congestion_swappable/quinn_bridge.rs:517-520`（tier1，源码注释逐字）：

> 「bd hfb94：装 **quinn 内建 BBR**，不再装本仓 hysteria 侧 `BbrSender` 桩——后者
> `on_congestion_event_ex` 只更新 bytes_in_flight/sampler，**从不更新 cwnd/min_rtt/pacing_rate**，
> `congestion_window()` 恒为 32×MTU（169ms RTT 下 ≈1.8Mbps，比 Go 差一个数量级）。」

⇒ **我们的 `BbrSender` 是不可用的桩**；真 BBR 是 quinn 内建的。
把它抽出来「用于 TCP 侧决策」= **从桩里取一个恒定值**，无价值。

**理由 3 —— 就算它是对的，TCP 侧决策也拿不到它需要的东西**：
`BbrSender` 的公开面只有 `mode()` / `profile()` / `pacing_rate()`（`bbr_sender.rs:330/335/340`），
**没有公开的「当前 RTT」「当前带宽估计」getter**：
- `min_rtt` 是 `BbrInner` 私有字段（`bbr_sender.rs:157`），标 `#[allow(dead_code)] // Go 对齐统计面：min RTT 时间戳待探针接线`；
- `bandwidth_at_last_round` 同样 `#[allow(dead_code)]`（`:183`）；
- `BandwidthSampler`（`bandwidth_sampler.rs`）的采样入口是**包 ack 事件**。

**要用它做 TCP 侧决策（选连接数/定窗），需要的改动量**：
1. 从 `BbrInner` 挖出 `min_rtt` / 带宽估计的公开 getter（改 `xray-transport-quic` 内部 API）；
2. **另建**一个 TCP 侧的 RTT/带宽采样源（`TCP_INFO` 的 `tcpi_rtt`/`tcpi_snd_cwnd`/`tcpi_delivery_rate`，
   或我们自己定时 ping）——**这部分是全新工作量，BBR 一点忙都帮不上**；
3. 把估计值接到**定窗/定连接数**的决策点——而我们**已经关死了「按 RTT 定窗」这条路**
   （简报 §2：`33bacd22` → `a750a542` 回退，根因是「把 CDN 边缘 RTT 当端到端 RTT」）。

⇒ **裁决：不适用（改造量 ≫ 收益，且落点已被证伪）**。
**但保留一条**：若将来真要做「按实测 BDP 选连接数/定窗」，**数据源应该是 `TCP_INFO`（内核给的 RTT/cwnd），
不是我们的 QUIC BBR**。这属于 §4 的开放问题，不是本轨的建议。

### 2.2 `XRAY_H2_FLOW_WINDOW_OVERRIDE_BYTES` / `XRAY_H2_SEND_BUF_OVERRIDE_BYTES` 该不该升级为正式旋钮？

**结论：不该升级为正式旋钮；应当保持诊断 env 级别，但**重命名 + 补齐语义文档**。**

**事实（tier1，源码）**：`crates/xray-transport-splithttp/src/flow_window.rs`
- `ENV_OVERRIDE = "XRAY_H2_FLOW_WINDOW_OVERRIDE_BYTES"`（:53）
- `ENV_SEND_OVERRIDE = "XRAY_H2_SEND_BUF_OVERRIDE_BYTES"`（:57）
- 语义（:100-116）：流窗覆盖 ⇒ `stream_window = bytes`、**`connection_window = 2×bytes`**、`max_send_buf = bytes`；
  只覆盖 send ⇒ 仅改 `max_send_buf`。
- 合法区间 `[1KiB, 1GiB]`，越界/非数字 = 视为未设置（`parse_override`，:118-121）。

**为什么不升级为正式旋钮**：
1. **Go 配置兼容是铁律**（CLAUDE.md）：正式旋钮 = JSON/proto 字段 = 长期 API 债 + 对拍面。
   Go 侧**没有**这个概念（`flow_window.rs:30` 明说「Go 侧本无此机制」）。
2. **提吞吐的价值已被证伪**：简报 §2 的 E1（流窗 4/32/64MiB = 7.84/9.05/9.23MB/s）与
   E4（send_buf 2M/5M/16M = 8.87/9.14/8.91MB/s）三档全平 ⇒ **没有可宣传的收益**。
3. **它现在就是 bench 工具**：`flow_window.rs:51-52` 注释「bench/诊断专用」，
   `hub.rs:249` 注释「bench env 覆盖…用」。定位正确。

**但有两处该改（低成本、高价值）**：

| 问题 | 现状 | 建议 |
|---|---|---|
| **命名不表达「覆盖什么」** | `..._OVERRIDE_BYTES` 三个量混在一个名字里 | 改名 **`XRAY_H2_WINDOW_OVERRIDE_BYTES`**（同时覆盖流窗+连窗+send_buf，取 flow 语义）**或** 保留双 env 但把文档写清「流窗覆盖会连带把连窗设成 2×、把 send_buf 设成同值」——现在的行为（连窗 = 2×、send = 同值）**藏在代码里不在名字里**，极易误用 |
| **静默生效** | 越界值 = 当作未设置，**无日志** | 起一条 WARN（`hot_log!` 已有现成机制，`flow_window.rs:88-93` 的 `hot_log!(DEBUG, "h2_window role=…")` 就是现成模板）：非法值应 warn「已忽略」，避免 bench 时误以为生效了 |
| **缺「每方向/每连接」语义说明** | 无 | 补一句：流窗 = **每 stream** 的 SETTINGS_INITIAL_WINDOW_SIZE；连窗 = **每连接**；send_buf = **每连接真缓冲**（`h2_window.rs:16-19` 已写明「真缓冲…96MB 预算按连接数 × 本值入簿」） |

**裁决**：
- 升级为**正式 JSON/proto 旋钮** = **不适用**（Go 无此概念 + 收益已证伪）。
- **保持诊断 env + 重命名 + 加 WARN + 补语义** = **直接可用**（小改，≤20 行，`flow_window.rs` 单文件）。

### 2.3 我们的 xhttp 读批当前是多少？（对照 ss 路径 `c9f51064` 的 64KiB 读窗）

**答：xhttp 服务端下行读的批粒度已经是 64KiB** —— **与 ss 路径的 8KB 病不同，不需要再治。**

**证据链（tier1，逐行）**：

| 位置 | 事实 |
|---|---|
| `crates/xray-transport-splithttp/src/hub/handler.rs:56` | `pub(super) const DUPLEX_BUF: usize = 64 * 1024;` |
| `crates/xray-transport-splithttp/src/hub/handler.rs:411-413` | 上行 `duplex(DUPLEX_BUF)`、下行 `duplex(DUPLEX_BUF)` |
| `crates/xray-transport-splithttp/src/hub/dl_stream.rs:34` | `PoolStream::new(inner, super::handler::DUPLEX_BUF)` ⇒ **下行 body 的读块 = 64KiB** |
| `crates/xray-transport-splithttp/src/pool_stream.rs:36` | `pub(crate) const UPLINK_CHUNK: usize = 64 * 1024;` |
| `crates/xray-transport-splithttp/src/transport.rs:46-47` | `const DUPLEX_BUF: usize = 64 * 1024;`（`copy_large` 用的 64KiB 缓冲）——**bd n8b4e 后该常量与 `copy_large` 桥已删**（本行指针仅存历史） |
| `crates/xray-transport-splithttp/src/transport.rs:1268-1272` | 注释明写：「显式 64KB 缓冲：tokio::io::copy 内部 DEFAULT_BUF_SIZE=8KB 会把 DATA 帧粒度钉死在 8KB，高 RTT 路径帧数放大 ~8x」——**这条病已经治过了**（bd n8b4e 后该 duplex 桥整段删除，帧粒度由 `hub/handler.rs` 的两条 64KiB 管道承接） |
| `crates/xray-transport-splithttp/src/hub/handler.rs:464-467` | 注释明写：「读块 64 KiB：tokio-util 默认容量 4096B 会把 DATA 帧粒度钉死在 4KB——高 RTT 路径（CF tunnel）帧数/唤醒数放大 ~16x，**是 xhttp 吞吐缺陷主因**」——**主因已按 64KiB 治过** |

**对照 ss 路径的差异（为什么 ss 需要 `c9f51064` 而 xhttp 不需要）**：
- ss 的问题是**桥层读腿**用缺省读窗（`Connection::tls_readbuf_size()` 缺省 0 ⇒ 池化 8KB），
  由 `crates/xray-transport/src/bridge.rs:709` 决定，`xray-proxy-ss/src/conn.rs:466` 覆写为 64KiB 才治好
  （commit `c9f51064`：cli 批 8KB→57.8KB、吞吐 1.91×）。
- **xhttp 的下行 body 不走桥层 TLS 读腿**（它是 h2 层：`DlStream` 直接产出 `Frame::data`），
  读批由 `PoolStream(64KiB)` 决定，**已经是 64KiB**。
- ⇒ **裁决：不适用**（xhttp 侧不需要再抬读批；再抬要改 `DUPLEX_BUF`，会连带放大内存账本）。

**但有一条 xhttp 侧的「读批」确实还没到位（如实记录）**：
`crates/xray-transport/src/bridge.rs:705-715` 的读腿选择是三选一：
`frozen_reader`（h2/h3 body 直交 Bytes，零拷贝）→ `s_read_dup`（裸 TCP readv 腿）→ `new_reader`（**缺省 8KB 池化**）。
xhttp **服务端**下发时，body 由 `DlStream` 产出 ⇒ 命中 `frozen_reader` 零拷贝腿 ⇒ **不经过 8KB 那一档**。
⇒ 无缺口。

### 2.4 背压闸（`crates/xray-transport/src/bridge.rs`）当前形态

**形态（tier1，源码 + 内存计划）**：

| 项 | 事实 | 位置 |
|---|---|---|
| **条目闸** | 每方向 mpsc `PIPE_BUF_CAP` = 64 条 MultiBuffer | `bridge.rs:741-744` |
| **字节闸** | 每方向 `ByteGate`，值 = `MemoryPlan::cached().bridge_gate` | `bridge.rs:738-740` |
| **闸值派生** | `bridge_gate = (total_budget / 8).clamp(4MiB, 32MiB)` | `crates/xray-frame/src/budget/plan.rs:226` |
| **本机档位（528MB RAM ⇒ `XRAY_MEM_LIMIT_MB=512` ⇒ small 档）** | `total_budget = 96MiB`、`bridge_gate = 12MiB/方向`、`max_conns = 32` | `plan.rs:457-460`（`small` 档断言） |
| **闸的语义** | **瞬态背压上界**（lazy 分配，正常链路实际在途远小于闸），**不是每连接常驻预算** | `plan.rs:58-61`、`bridge.rs:637-641` |
| **为什么不再是 2MiB** | u440m 的 2MiB 闸 < BDP ⇒ 钉吞吐 ≈12.9MB/s，A/B 中位比 0.939（−6.1%）超 5% 门 ⇒ 回退 | `bridge.rs:628-641` |
| **下限保证** | `bridge_gate ≥ 4MiB`（「≥ 实测 BDP 上沿 3.56MB」），有测试 `bridge_gate_never_below_measured_bdp` 钉住 | `plan.rs:102`、`plan.rs:526-536` |

**裁决**：**不适用（不是当前瓶颈）**。
理由：12MiB/方向的闸，在受控台在途 2.4MB（简报 §1）下**离 binding 还差 5 倍**；
简报 §1 的实测也证明 xhttp 缺省/maxConnections=1/3/10/16 **聚合完全相同**（1.5-1.7MB/s）——
若是闸 binding，maxConnections=1 与 16 会有明显差异（闸是**每连接**创建，见 `bridge.rs:738` 在
`bridge_link_with_stream_full` 内部 ⇒ 每连接各有一对闸 ⇒ 连接数增加不改变单连接的闸值）。

**⚠️ 一条如实记录的账本观察**（不是提案，是给方案选型用的事实）：
`plan.rs:60-61` 自己写着：四档满载乘积 `max_conns × 2 × bridge_gate` = 130 / 768 / 3072 / 10880 MiB
vs 预算 40 / 96 / 192 / 512 MiB ⇒ **过订 3.3×–21×**（PM 2026-11-08 C 案拍板「如实登记 + WARN」）。
⇒ 若将来要用「内存档位」做取舍（而不是吞吐取舍），这是已知的账面缺口。

### 2.5 §2 小结

| 问题 | 答 | 裁决 |
|---|---|---|
| 我们的 BBR 能用于 TCP 侧决策吗？ | **不能**。①QUIC 包级 CC；②生产已被 quinn 内建 BBR 顶替，本仓 `BbrSender` 是自标「桩」；③无公开 RTT/带宽 getter | **不适用** |
| 诊断 env 该升级为正式旋钮吗？ | **不该**（Go 无此概念 + E1/E4 已证伪）。但**该重命名 + 加非法值 WARN + 补「每流/每连接」语义** | **直接可用**（小改） |
| 我们的 xhttp 读批当前是多少？ | **64KiB**（`hub/handler.rs:56` `DUPLEX_BUF` + `dl_stream.rs` `PoolStream(64KiB)`），**不是 8KB**，无需再治 | **不适用**（无缺口） |
| 背压闸当前形态？ | 条目闸 64 条 + 字节闸 12MiB/方向（small 档），瞬态上界语义，≥ BDP 不 binding | **不适用**（非瓶颈） |

---

## 3. 零代码杠杆（内核 / 运维层）

> 场景：单核 Linux 节点（`nproc=1`，528MB RAM，拥塞控制 `bbrplusv3`）推大文件给 ~200ms 远端。
> 所有 sysctl 事实来自 **Linux 内核官方文档 `Documentation/networking/ip-sysctl.rst`**（tier2）与
> **内核源码**（tier1：`net/ipv4/tcp.c`、`net/core/sock.c`、`include/net/tcp.h`）。

### 3.1 各 sysctl 的作用与「长路径上该调什么、不该调什么」

| sysctl | 作用（官方语义） | 长路径裁决 | 理由 |
|---|---|---|---|
| `net.ipv4.tcp_rmem` (min,default,max) | TCP 收缓冲：min=最小保障；default=初始（**131072 ⇒ 初始窗 65535**）；max=**autotune 上限** | **该看 max，且只该看 max** | max 才是 autotune 能长到的天花板；default 决定**初始**窗（改动它只影响起步） |
| `net.ipv4.tcp_wmem` (min,default,max) | TCP 发缓冲：min=出生即占；default=初始（16K）；max=**autotune 上限**（**不覆盖 `net.core.wmem_max`**） | **该看 max** | 同上；注意它**不覆盖** `wmem_max`（两者是不同闸） |
| `net.core.rmem_max` / `net.core.wmem_max` | **只能**限制**显式 `setsockopt(SO_RCVBUF/SO_SNDBUF)`** 的上限（默认 4MiB，tier1 `net/core/sock.c`：`sysctl_wmem_max = 4 << 20`） | **不该调** | **对 autotune 完全无效**；调它只影响「显式设窗」路径 ⇒ 我们的血案（bd r5j96）恰恰证明**显式设窗是反效果** |
| `net.ipv4.tcp_moderate_rcvbuf` | 收缓冲 **autotune** 开关（默认 1）：自动把缓冲长到「匹配路径全吞吐所需」，**上限 = `tcp_rmem[2]`** | **该保持 1** | 官方语义明确它是「让窗口匹配路径需求」的正统机制；关掉它 = 回到固定窗 = 我们的血案 |
| `net.ipv4.tcp_window_scaling` | RFC1323 窗口缩放（默认 1）。`TCP_MAX_WSCALE = 14`（tier1 `include/net/tcp.h`）⇒ 理论最大窗 64KiB × 2^14 ≈ 1GiB | **该保持 1** | 关掉它 ⇒ 窗封顶 64KiB；这是**遗留 90 年代栈**的兼容位，不是调优位 |
| `net.ipv4.tcp_fastopen` | RFC7413，SYN 带数据。默认 `0x1`（仅客户端侧位；服务端位 0x2 默认关） | **不该调（对我们场景）** | ①我们**是服务端**（客户端连我们），服务端位默认关，且**需要 `MSG_FASTOPEN` / `TCP_FASTOPEN` socket option 才生效**（官方文档明写）；②我们的连接**每次都要 TLS 握手**（REALITY/utls），TFO 省的那 1 个 RTT 被 TLS 握手完全淹没；③我们已有 `sockopt.tcp_fast_open` 字段但**默认 false**（`crates/xray-transport/src/sockopt/mod.rs` 的 `SocketOptions::default` 断言 `!opts.tcp_fast_open`） |
| `net.ipv4.tcp_bbr.*` | **我们跑的是 `bbrplusv3`（第三方内核补丁），不是上游 BBR** ⇒ 上游的 `tcp_bbr.*` knob 名字**不一定存在** | **先查再调** | `bbrplusv3` 的 knob 集与上游不同；**必须先 `sysctl -a \| grep -i bbr` 确认实际存在哪些**，再谈调值（我们无该节点的 ssh 通道，**未能实测**，如实记账） |
| `net.ipv4.tcp_slow_start_after_idle` | RFC2861：空闲超过 1 个 RTO 后**超时拥塞窗**（默认 1=开） | ⚠️ **值得试，但方向是「延迟」不是「吞吐」** | 关掉它（=0）⇒ 空闲后不退回慢启动 ⇒ **短连接的 TTFB 更好**；但**吞吐上限不变**。我们的场景是「长连接大文件」，一个 RTO 的空闲不发生 ⇒ **预期无收益**。列为「可试但预期无效」 |
| `net.ipv4.tcp_notsent_lowat` | 全局 `TCP_NOTSENT_LOWAT`（默认 `UINT_MAX`） | **不该调** | 简报 §2 已关死（commit `dbdfc83d` 回退）；行业用途也是「省内存 + 降延迟」，不是提吞吐（轨 B §1.11 同结论） |
| `net.ipv4.tcp_congestion_control` | 新连接的 CC 算法 | **已是 `bbrplusv3`** | 无需动 |
| `net.core.netdev_max_backlog` / `somaxconn` | 队列深度 / accept 队列 | **不该调** | 我们不是 accept 洪水场景；调大只是**把丢包换成排队**（= bufferbloat，见 §4） |

### 3.2 「显式锁窗为何是反效果」——机制级说明（tier1 内核源码 + 官方文档）

这是本轨最需要说清的一条，因为**它决定了内核层几乎所有「调窗」提案的方向**。

**发送侧（`SO_SNDBUF`）**：
- 官方文档（tier2，`ip-sysctl.rst` 的 `tcp_wmem` 条目逐字）：
  > 「max: Maximal amount of memory allowed for **automatically tuned** send buffers for TCP sockets.
  > **This value does not override net.core.wmem_max. Calling `setsockopt()` with `SO_SNDBUF` disables
  > automatic tuning of that socket’s send buffer size, in which case this value is ignored.**」

  ⇒ **一旦 `setsockopt(SO_SNDBUF)`，这个 socket 的发缓冲 autotune 被关闭**，缓冲**钉死在请求值**，
  且 `tcp_wmem[2]` 这个 autotune 上限对它**失效**。

- `socket(7)`（tier2，man page 逐字）：
  > 「SO_SNDBUF — Sets or gets the maximum socket send buffer in bytes. **The kernel doubles this value**
  > (to allow space for bookkeeping overhead) when it is set using `setsockopt(2)`, and this doubled value is
  > returned by `getsockopt(2)`.」

  ⇒ 设 16MiB 实际得到 32MiB 账面（与我们的 `SOCKET_KERNEL_BOOKEEPING_FACTOR = 2` 口径一致，
  `crates/xray-frame/src/budget.rs:87`）。

**接收侧（`SO_RCVBUF`）**：
- 官方文档（tier2，`tcp_rmem` 条目逐字）：
  > 「max: maximal size of receive buffer allowed for **automatically selected** receiver buffers for TCP socket.
  > **Calling `setsockopt()` with `SO_RCVBUF` disables automatic tuning** of that socket’s receive buffer size,
  > in which case this value is ignored.」

**⇒ 「让内核窗口真的长大」的正统做法只有一个：**
**不设任何 socket 选项，让 `tcp_moderate_rcvbuf=1` 的 autotune 生效，并把 `tcp_rmem[2]` / `tcp_wmem[2]`
这两个「autotune 上限」调大。**
**调 `net.core.rmem_max` / `wmem_max` 是另一回事**（只管显式路径），**对 autotune 零效果**。

**内核 autotune 上限的真实取值（tier1，内核源码 `net/ipv4/tcp.c` 的 `tcp_init_mem()`）**：

```c
limit = nr_free_buffer_pages() << (PAGE_SHIFT - 7);
max_wshare = min(4UL*1024*1024, limit);
max_rshare = min(32UL*1024*1024, limit);

init_net.ipv4.sysctl_tcp_wmem[0] = PAGE_SIZE;          // 4096
init_net.ipv4.sysctl_tcp_wmem[1] = 16*1024;             // 16K
init_net.ipv4.sysctl_tcp_wmem[2] = max(64*1024, max_wshare);

init_net.ipv4.sysctl_tcp_rmem[0] = PAGE_SIZE;          // 4096
init_net.ipv4.sysctl_tcp_rmem[1] = 131072;              // 128K
init_net.ipv4.sysctl_tcp_rmem[2] = max(131072, max_rshare);
```

**⇒ 528MB RAM 节点上的推算（我们可自行在节点上核实，见 §3.4）**：
`nr_free_buffer_pages() << (PAGE_SHIFT-7)` = 可用页数 × 32 bytes。
528MB ≈ 129000 页 ⇒ ≈ **4.1MB** ⇒
- `max_wshare = min(4MB, 4.1MB) ≈ 4MB` ⇒ **`tcp_wmem[2] ≈ 4MB`**
- `max_rshare = min(32MB, 4.1MB) ≈ 4.1MB` ⇒ **`tcp_rmem[2] ≈ 4.1MB`**

**这个推算直接命中我们的症状（重要发现）**：
- 受控台 RTT 200ms、BDP 上界 8MB（40MB/s × 0.2s）。
- **`tcp_rmem[2] ≈ 4.1MB` ⇒ 内核收窗 autotune 天花板 ≈ 4.1MB**。
- 简报 §1 记录的客户端侧 `ss -tin`：**`snd_wnd: 65536`（Linux 接收窗未自动扩窗）**。
  65536 ≈ 64KiB ⇒ **远小于 4.1MB 的 autotune 上限** ⇒ 说明**不是被 `tcp_rmem[2]` 卡住**，
  而是**更早的一道闸**（初始窗 65535 或 autotune 没起步）。
- ⇒ **可执行的判别实验**（§3.4 第 1 条）：在节点上把 `tcp_rmem[2]` / `tcp_wmem[2]` 显式抬到
  e.g. 16MB/16MB，然后看 `ss -tin` 的 `snd_wnd` / `rcv_space` 是否从 64KiB 长上去。
  **这是本轨唯一一条「可能真能改变内核行为」的零代码杠杆**，且它**不关闭 autotune**（与 r5j96 血案正交）。

> **注意方向性**：受控台的 200ms RTT 是**客户端↔节点**这一段（netem 挂在客户端侧），
> 所以受控台的收窗瓶颈在**客户端机器**的 `tcp_rmem[2]`，不在节点。
> **生产路径**（中国客户端 → CF 边缘 → Argo → 节点）里，节点只负责「节点→CF 边缘」这一段
> （CF Argo anycast `205.234.175.175`，~6ms）⇒ **节点侧的收窗天花板对生产症状基本无关**。
> ⇒ 判别实验要分清测的是哪一段。

### 3.3 单核 CPU 预算：主要消耗形态 + 零代码手段

**主要 CPU 消耗形态（按我们的栈，从高到低）**：

| 形态 | 我们的证据 | 能不能零代码缓解 |
|---|---|---|
| **TLS record 加解密 + 校验** | 我们走 btls（BoringSSL，REALITY/Chrome 指纹路径）⇒ AES-GCM 硬件加速（已用 `target/boringssl-asm` 带汇编构建，CLAUDE.md §5） | ❌ 已是硬件加速；再省只能换 kTLS（**新特性 + 新依赖，禁**） |
| **h2 framing / HPACK / 帧级流控** | 每 16KiB 一个 DATA 帧（§1.6）；64KiB 读批 ⇒ 每批 4 帧 | ❌ 已在合理档 |
| **每字节拷贝次数** | 我们的管线：源站 → freedom 桥 → pipe → dispatcher pipe → `DlStream`/`PoolStream` → h2 → TLS → socket。**每字节至少 2-3 次 memcpy** | ❌ 减少拷贝 = 改代码（本轨不做） |
| **syscall 数** | 64KiB 批 ⇒ 每 64KiB 一次 `readv` + 一次 `writev`（已用 readv 腿，`bridge.rs:698-701`） | ❌ 已合理 |
| **tokio 调度 / 跨线程唤醒** | 单核 ⇒ 所有 worker 线程抢同一个核 | ⚠️ 见下 |
| **内核 softirq / 网卡中断** | 单核 VPS ⇒ 收发都在同一个核 | ⚠️ **这是零代码手段唯一能真正影响的一层** |

**零代码手段清单（每条注明副作用与回滚）**：

#### 【立即可试 · 零代码 · 零风险】3-5 条

| # | 手段 | 命令 | 预期现象 | 副作用 | 回滚 |
|---|---|---|---|---|---|
| **Z1** | **确认并固定 tokio worker 线程数 = 1** | 单核上 `new_multi_thread()` 默认按 `available_parallelism()` 起线程 ⇒ **核数少时线程也少，但 `max_blocking_threads` 另算**（`crates/xray-cli/src/bin/xray.rs:268-271`）。用 `taskset` 绑核 + 观测 | 线程数与核数一致即无收益；若 `max_blocking_threads` 起了多线程 ⇒ **跨核唤醒开销** | 单核上绑核无收益（本来只有一核）；若容器里看到多核 ⇒ **收益真实** | 取消 `taskset` |
| **Z2** | **TCP_NODELAY 已默认开 ⇒ 无需动**（**但要核实覆盖完整性**） | `sysctl` 无；核实点：`crates/xray-transport/src/sockopt/mod.rs:369` `tcp_nodelay: true` + `:737`/`:884` 两条 apply 路径（出站/入站） | 若发现某条路径漏了 ⇒ **Nagle 会把 64KiB 批拆成小包** ⇒ 单核上 syscall ×N | 关掉 Nagle **更糟**（延迟） | — |
| **Z3** | **`irqbalance` / RPS 分布** | `cat /proc/interrupts \| grep -i virtio`（看单核上收/发中断是否都落在 CPU0） | 单核 ⇒ 无分布可调；**中断亲和性在此无意义** | 无 | — |
| **Z4** | **关掉「同核抢核」的无关服务** | `systemctl list-units --state=running` 看有没有 cron/日志/更新器在抢这唯一的核 | 任何周期性 CPU 抢占都会**直接砍掉我们的吞吐**（单核） | 关掉可能影响运维 | `systemctl start` 复原 |
| **Z5** | **关掉 CPU 频率调节的「省电」档**（若有） | `cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor`（**VPS 通常无此文件**⇒ 跳过） | 若存在且是 `powersave` ⇒ **单核吞吐直接打折** | 功耗↑、温度↑ | `cpupower frequency-set -g performance` 复原 |

> **诚实结论（必须写进方案选型）**：Z1-Z5 **没有一条能改变 33MB/s 的天花板**——
> 我们的天花板是**用户态每字节 CPU 成本**（TLS + h2 + 拷贝），而 bd bhneq 已实测
> 「服务端 /proc ticks 91/100（91% 单核），strace sendto 仅占 4.8% CPU ⇒ 剩余是**用户态 REALITY/btls 记录处理 + h2 分帧**」。
> ⇒ **内核/运维层的零代码杠杆，预期收益 ≤5%，且只在「容器里实际可见多核」或「同核有旁路负载」时才可能兑现。**

#### 【需要改 sysctl · 3-5 条】（全部标副作用 + 回滚）

| # | sysctl | 命令 | 预期现象 | 副作用 | 回滚 |
|---|---|---|---|---|---|
| **S1** | **抬 `tcp_rmem[2]` / `tcp_wmem[2]`（autotune 上限）** | `sysctl -w net.ipv4.tcp_rmem="4096 131072 16777216"`<br>`sysctl -w net.ipv4.tcp_wmem="4096 16384 16777216"` | **`ss -tin` 的 `snd_wnd`/`rcv_space` 从 64KiB 长到 MB 级**（若 autotune 被 `tcp_rmem[2]` 卡住） | ①**每 socket 缓冲变大 ⇒ 内存账本上升**（528MB 节点要算：32 连接 × 2 方向 × 16MB = 1GB ⇒ **会 OOM**，须按实际连接数算）；②**bufferbloat 风险上升**（见 §4） | `sysctl -w net.ipv4.tcp_rmem="4096 131072 4194304"`（回内核缺省量级）<br>`sysctl -w net.ipv4.tcp_wmem="4096 16384 4194304"` |
| **S2** | **`net.core.rmem_max` / `wmem_max`** | `sysctl -w net.core.rmem_max=16777216 net.core.wmem_max=16777216` | **对我们无现象**（我们不显式设窗 ⇒ 这两个 knob 对 autotune 无效，官方文档明写） | 若将来有人加显式 `SO_RCVBUF` ⇒ 窗口会被**锁死**（r5j96 血案） | `sysctl -w net.core.rmem_max=4194304 net.core.wmem_max=4194304` |
| **S3** | **`tcp_moderate_rcvbuf=1`（确认保持）** | `sysctl -w net.ipv4.tcp_moderate_rcvbuf=1` | 无现象（本来就是 1）；**关掉它才是坏事** | 关掉 ⇒ 收窗固定 ⇒ 高 RTT 吞吐被钉 | `=1` |
| **S4** | **`tcp_window_scaling=1`（确认保持）** | `sysctl -w net.ipv4.tcp_window_scaling=1` | 无现象（本来就是 1）；关掉 ⇒ 窗封顶 64KiB | — | `=1` |
| **S5** | **`tcp_slow_start_after_idle=0`** | `sysctl -w net.ipv4.tcp_slow_start_after_idle=0` | **只影响空闲后新连接的 TTFB**（不退回慢启动）；**长连接大文件吞吐无变化** | 空闲后立刻发大流量 ⇒ 突发更猛（对**共享链路上的其他租户**不友好，见 §4） | `=1` |

**关于 `bbrplusv3`（必须先查再动）**：
- 我们跑的是 **第三方内核补丁 `bbrplusv3`**，不是上游 BBR ⇒ 上游 `net.ipv4.tcp_bbr.*` 的 knob 名**不一定存在**。
- **先查**：`sysctl -a 2>/dev/null | grep -i bbr` ⇒ 看实际有哪些 knob（`bbr_pacing_mss` / `bbr_beta` / `bbr_max_segs` /
  `bbr_bidir` / `bbr_probe_rwnd` 等，视补丁版本）。
- **本轨未能实测**（无该节点 ssh 通道，见 `ssh://` 无已配置主机）⇒ **不列具体调值，只给方法**。
- 一般性风险提示（tier1，§4 的 WPI 论文）：BBR 族在**与 CUBIC 竞争**时
  「extremely unfair in shallow buffers」「20 秒吞吐周期」「2 BDP 的 cwnd 上限导致浅缓冲丢包 5.5%」。

### 3.4 零代码杠杆的**判别实验清单**（先查后调，避免瞎调）

在动任何 sysctl 之前，先在**目标机**跑这三条只读命令，把「到底哪一段、哪个闸」钉死：

```bash
# ① 节点侧：当前 autotune 上限（对比 §3.2 推算的 4MB）
sysctl net.ipv4.tcp_rmem net.ipv4.tcp_wmem net.core.rmem_max net.core.wmem_max
sysctl net.ipv4.tcp_moderate_rcvbuf net.ipv4.tcp_window_scaling net.ipv4.tcp_slow_start_after_idle
cat /proc/sys/net/ipv4/tcp_available_congestion_control

# ② 实际生效的连接状态（找 snd_wnd / rcv_space / cwnd / delivery_rate / rtt）
ss -tinp | head -60

# ③ 单核的真实占用（确认 CPU 是不是真的被谁吃掉）
top -b -n1 | head -15
cat /proc/softirqs | head -4      # 看 NET_RX/NET_TX 落在 CPU0 的量
```

**判读规则**：
- 若 ② 里 `snd_wnd` 仍 ≈ 65536 ⇒ **收窗 autotune 没起步**（不是被 `tcp_rmem[2]` 卡）⇒ **S1 无效，别调**，
  该查的是「接收侧应用是否及时读」（我们的 `frozen_reader` / `DlStream` 读批已经在 64KiB）。
- 若 ③ 里 `top` 显示 xray 只占 ~50% ⇒ **CPU 不是瓶颈**，内核层再怎么调都白搭 ⇒ 转向找「谁在抢核」。
- 若 ③ 里 `top` 显示 xray ≈ 90%+（bd bhneq 的实测值）⇒ **CPU 是瓶颈** ⇒ 内核层零代码杠杆**救不了**，
  必须走代码路径（降每字节 CPU：拷贝次数 / TLS record 大小 / h2 分帧）。

---

## 4. Munger 反转轨：调内核窗口/sysctl 的坏处（权威反例）

> 任务要求「找『调内核窗口/sysctl 会带来坏处』的权威反例（bufferbloat 下游受害、共享机器上的不公平性、租户间互相影响）」。
> 本节**刻意**只收**有权威出处**的反例，每条给出**机制 + 出处 + 对我们场景的具体含义**。

### 4.1 反例 1：bufferbloat —— 大缓冲把「延迟」推给了下游受害者（tier1，学术 + 期刊）

**来源**：
- Gettys, D., Nichols, K.「Bufferbloat: Dark Buffers in the Internet」, *Communications of the ACM*, 55(1), 2012
  — <https://queue.acm.org/detail.cfm?id=2071893>（tier1/期刊；同文亦见 CACM）
  镜像 PDF（tier1）：<https://www.cse.iitb.ac.in/~mythili/teaching/cs224m_autumn2017/references/buffer-bloat.pdf>

**机制（论文要点）**：
> 「Once adequate buffers became routine, another problem could occur: **the buffers were now part of the pipe
> that TCP is so good at filling. Filling these buffers would cause delay to increase, and persistently full buffers
> lack the space to a…**」

**机制化表述**：缓冲越大 ⇒ 队列越深 ⇒ **队尾时延 = 队列长度 / 服务率** 越大。
在 200ms RTT 的路径上，每多 1MB 队列 ≈ 多 1MB/带宽的额外时延。

**对我们场景的具体含义**：
- **S1（抬 `tcp_rmem[2]`/`tcp_wmem[2]`）的直接代价**：接收窗变大 ⇒ **允许更多数据在途** ⇒
  在**共享瓶颈**（CF 边缘 / 运营商链路 / 源站 CDN）上，队列更深 ⇒
  **同一个瓶颈上的其他租户（别的用户、别的协议）时延被推高**。
- ⇒ **S1 必须是「受控的」**：抬 `tcp_wmem[2]`（发送侧）是**给自己更多在途**（对共享链路是**抢占**）；
  抬 `tcp_rmem[2]`（接收侧）是**让对端能灌更多**（对共享链路也是**抢占**）。
  **在共享瓶颈上，两者都是「把自己的时延换成别人的时延」。**

### 4.2 反例 2：BBR 在共享瓶颈上「极不公平」+ 吞吐周期（tier1，硬件实验论文）

**来源**：Chung, J., Li, F., Claypool, S. M.「Sharing but not Caring – Performance of TCP BBR and TCP CUBIC
at the Network Bottleneck」, *AICT 2019*（IEEE）— <https://web.cs.wpi.edu/~claypool/papers/bbr/bbr-aict-19.pdf>

**论文结论（原文逐字）**：
> 「BBR is **extremely unfair** when competing with CUBIC in shallow buffers since CUBIC responds to the packet loss
> by reducing rates while BBR does not. In deeper buffers, BBR and CUBIC exhibit **large 20-second throughput cycles**,
> with average throughput fairness achieved only for specific router queue sizes based on the BDP.」
>
> 「BBR induces packet loss on congested links with a router buffer sized smaller than 1.5 BDP, with loss increasing
> linearly with a decrease in buffer size. **Loss rates are 5.5% for a router buffer size of 1 BDP, doubling to about
> 11% when the router buffer size is 0.5 BDP**, caused by BBR's 2 BDP CWND cap.」
>
> 「when BBR competes with CUBIC, **BBR increases the estimated RTprop** when it is unable to drain the queue,
> causing BBR to greatly overestimate the BDP, and thus create high queuing and loss.」

**对我们场景的具体含义**：
- 我们节点跑 `bbrplusv3`（BBR 族）⇒ **我们的流对共享瓶颈上的其他租户「极不公平」**。
- 若我们为了提吞吐而**加大在途/加大缓冲**（S1），在 CF 边缘/运营商链路上**会加剧这一不公平**，
  同时**我们自己**的排队时延也会涨（RTprop 估高的同一机制）。
- ⇒ **这条同时是「反例」也是「自我约束」**：**不要用「加大缓冲」去抢共享链路**。

### 4.3 反例 3：显式锁窗在 Linux 上是「关掉 autotune」（tier1 内核源码 + tier2 官方文档）

已在 §3.2 详述，此处只列结论：
- 官方文档逐字：`Calling setsockopt() with SO_RCVBUF **disables automatic tuning**` / `SO_SNDBUF` 同。
- 我们自己的血案（tier1 内部实测，bd r5j96）：显式设 `SO_RCVBUF` ⇒ Linux 受 `net.core.rmem_max` 静默钳制
  ⇒ 窗被**钉死** ⇒ WSL netem RTT 300ms 实测 **ours 0.80 vs go/sing-box 7.43 MB/s（9 倍差）**。
- ⇒ **这条是最强的反例**：**「调内核窗口」在 Linux 上不是「抬高上限」，而是「关掉 autotune 并钉死」**。

### 4.4 反例 4：`SO_SNDBUF` 的记账翻倍（tier2 man page）—— 内存账本被隐式 ×2

`socket(7)`：「The kernel **doubles** this value … and this doubled value is returned by `getsockopt(2)`」。
⇒ 显式设 16MiB ⇒ 内核账面 32MiB ⇒ 在 528MB / `XRAY_MEM_LIMIT_MB=512`（预算 96MiB）的节点上，
**显式大缓冲会直接冲垮我们的内存档位**（我们的账本已按 ×2 记：`SOCKET_KERNEL_BOOKEEPING_FACTOR = 2`，
`crates/xray-frame/src/budget.rs:87`）。
⇒ **在共享/小内存机器上，「为吞吐调大缓冲」= 用 OOM 换吞吐**，而 OOM 会**连带杀掉同机的其他租户**。

### 4.5 反例 5：把「丢包」换成「排队」= 把问题从自己身上转给全网（tier3，但机制 tier1）

- **tier3**（云厂商/博客口径）：<https://www.tencentcloud.com/document/product/1330/84307> 与
  <https://cubepath.com/docs/advanced-topics/advanced-tcp-ip-tuning-with-sysctl>
  —— 常见「网络优化」教程建议**无脑调大 `net.core.rmem_max`/`wmem_max`/`somaxconn`/`netdev_max_backlog`**。
- **我们为什么要引 tier3**：因为这是**运维层最常见的反模式来源**——运营照抄这类教程，
  在我们的节点上一次性把四个 sysctl 全开，**看起来变快了，实质是（a）关掉 autotune（§4.3）、
  （b）内存翻倍（§4.4）、（c）把瓶颈处的丢包变成排队（§4.1）**。
- ⇒ **对我们运维流程的含义**：**任何在生产节点上批量改 sysctl 的动作，必须逐条过本节的判据**，
  不接受「教程推荐」作为依据。

### 4.6 §4 小结（反转轨的一句话）

**「调内核窗口/sysctl」在 Linux 上的正确姿势只有一条：**
**不设 socket 选项 + 保持 `tcp_moderate_rcvbuf=1` + 保持 `tcp_window_scaling=1` + 只抬 `tcp_rmem[2]`/`tcp_wmem[2]`
这两个 autotune 上限（且要算内存账本）**。
其余（`rmem_max`/`wmem_max`/`somaxconn`/`netdev_max_backlog`/`SO_SNDBUF`/`SO_RCVBUF`/`TCP_NOTSENT_LOWAT`）
**要么对我们无效、要么已被证伪、要么把问题转嫁给共享链路上的其他租户。**

---

## 5. 给方案选型的落点建议（本轨只给方向，不给实现）

按「白拿度」从高到低：

| 优先级 | 落点 | 类型 | 依赖 | 预期收益 | 裁决 |
|---|---|---|---|---|---|
| **P0** | **跑 §3.4 的三条只读命令**，把「哪一段、哪个闸、CPU 归谁」钉死 | 运维只读 | 无 | **未知但可能是最高**（把「猜」变成「测」） | ✅ 直接可用 |
| **P0** | **确认我们能触到的那一段**：受控台 200ms 在**客户端↔节点**（客户端机）；生产 200ms 在**客户端↔CF**（**我们管不到**）。⇒ 生产症状**不是**节点内核窗的问题 | 分析 | 无 | 避免在错误的一段上花时间 | ✅ 直接可用 |
| **P1** | **S1 判别实验**：抬 `tcp_rmem[2]`/`tcp_wmem[2]` 后看 `ss -tin` 的 `snd_wnd`/`rcv_space` 是否长上去。**只在能触到的那一段测** | 运维改 sysctl | 无 | 若 autotune 被卡 ⇒ 可能有真实收益；否则证明无效 | ⚠️ 需实测（先读 §3.4） |
| **P1** | **`XRAY_H2_WINDOW_OVERRIDE_BYTES` 重命名 + 非法值 WARN + 补「每流/每连接」语义** | 代码小改（`flow_window.rs` 单文件，≤20 行） | 无 | 0（防误用，非提速） | ✅ 直接可用 |
| **P2** | **CPU 归因**：`/proc/softirqs` + `top` 确认 xray 是否真的 ~91%；若不是，则 §3.3 的零代码手段（Z4 关同核负载）可能有真实收益 | 运维只读 + 停旁路 | 无 | 若 CPU 有空档 ⇒ 有收益 | ✅ 直接可用 |
| **P3** | **hyper `adaptive_window` 单端开实验** | 代码一行 | 无（hyper 1.10.1 已有） | **预期负收益**（起始窗 65535 + 只管收方向）。**仅作「排除项」记录**，不要立项 | ❌ 不适用 |
| **P3** | `h2` 运行期改窗（`set_initial_window_size`） | 需绕开 hyper | 无（但要重写 splithttp 的 h2 层） | **预期无收益**（窗已 ≫ BDP）+ **h2#976 风险**（我们 0.4.19 未修） | ❌ 不适用 |
| **—** | **fork / vendor h2** | — | — | — | **不建议**（简报 §2 已判定「最贵的错」） |
| **—** | **抽我们的 QUIC BBR 给 TCP 侧用** | — | — | 桩 + 无 TCP 事件源 + 落点已证伪 | ❌ 不适用 |

---

## 6. 引用清单（按 tier）

### tier1（论文 / RFC / 上游仓库源码）

**h2 crate（本地 cargo registry 逐行核对，`h2-0.4.19`（我们生效的版本）与 `h2-0.4.20` 两份）**
- `h2-0.4.20/src/proto/mod.rs:33` — `MAX_WINDOW_SIZE = (1 << 31) - 1`
- `h2-0.4.20/src/proto/mod.rs:38-39` — `DEFAULT_DATA_FRAME_OVERHEAD_THRESHOLD = 256`、`DEFAULT_DATA_FRAME_BUDGET = 25_600`
- `h2-0.4.20/src/proto/mod.rs:47` — `DEFAULT_MAX_SEND_BUFFER_SIZE = 1024 * 400`
- `h2-0.4.20/src/proto/connection.rs:93-108` — `DataFrameBudget::resolve`
- `h2-0.4.19/src/proto/connection.rs:86` / `:89-108` — **0.4.19 的 `Config.data_frame_budget` 是裸 `usize`**（Auto 在握手期一次求值）
- `h2-0.4.19/src/client.rs:1366-1369` / `h2-0.4.19/src/server.rs:1535-1539` — 0.4.19 的 Auto 求值点（运行期不更新）
- `h2-0.4.19/src/proto/streams/counts.rs:93` / `:109-125` — 0.4.19 的小 DATA 帧预算机制
- `h2-0.4.20/src/proto/streams/counts.rs:81-140` — 0.4.20 的对应实现（含 `set_target_connection_window_size` 重算）
- `h2-0.4.19/src/proto/streams/recv.rs:606-618` — `Ordering::Less` 分支（**0.4.19 无 #976 修复**）
- `h2-0.4.20/src/proto/streams/recv.rs:604-616` — 同上（**0.4.20 亦无**）
- `h2-0.4.19/src/client.rs:1077-1080` / `:1402` / `:1420` — `max_send_buffer_size` 上限、运行期改窗 API（0.4.19 同样有）
- `h2-0.4.20/src/client.rs:705-740` / `:1078` / `:1402` / `:1420` — 同上（0.4.20）
- `h2-0.4.20/src/server.rs:468-490` — 同上（server 侧）
- `h2-0.4.20/src/frame/settings.rs:47` / `:50` — `DEFAULT_MAX_FRAME_SIZE = 16_384`、`MAX_INITIAL_WINDOW_SIZE = (1<<31)-1`
- `h2-0.4.20/src/codec/framed_write.rs:47` — 「max frame size … specified by the peer」
- `h2-0.4.20/CHANGELOG.md` — 0.4.16/0.4.18/0.4.19/0.4.20 变更史
- <https://raw.githubusercontent.com/hyperium/h2/master/src/proto/streams/recv.rs> — master 的 #976 修复（requeue）

**hyper crate（`hyper-1.10.1`）**
- `hyper-1.10.1/src/proto/h2/ping.rs`（模块头 = BDP 算法；`Bdp::calculate`；`BDP_LIMIT = 16MiB`；`ping_delay` 退避）
- `hyper-1.10.1/src/proto/h2/mod.rs:30` — `SPEC_WINDOW_SIZE = 65_535`
- `hyper-1.10.1/src/client/conn/http2.rs:322-374` — `initial_*_window_size` 会置 `adaptive_window=false`；`adaptive_window(true)` 覆写窗为 65535
- `hyper-1.10.1/src/server/conn/http2.rs:157-192` — 同上（server 侧）
- `hyper-1.10.1/src/proto/h2/client.rs:138-143` / `:240-243` — BDP 注入与 `set_target_window_size` + `set_initial_window_size`
- `hyper-1.10.1/src/proto/h2/server.rs:154-163` / `:349-352` — 同上（server 侧）

**hyper-util crate**
- `hyper-util-0.1.20/src/client/legacy/client.rs:1354-1405` — `http2_initial_stream_window_size` / `http2_adaptive_window` / `http2_max_send_buf_size`

**Linux 内核源码**
- `net/ipv4/tcp.c`（`tcp_init_mem()`）— `tcp_wmem`/`tcp_rmem` 缺省与 `max_wshare`/`max_rshare` 推导
- `net/core/sock.c` — `sysctl_wmem_max = 4 << 20`、`sysctl_rmem_max = 4 << 20`
- `include/net/tcp.h` — `TCP_MAX_WSCALE = 14`、`TCP_INIT_CWND = 10`、`TCP_BASE_MSS = 1024`

**论文**
- Chung, Li, Claypool.「Sharing but not Caring – Performance of TCP BBR and TCP CUBIC at the Network Bottleneck」, AICT 2019 — <https://web.cs.wpi.edu/~claypool/papers/bbr/bbr-aict-19.pdf>

### tier2（官方文档 / man page / 上游 issue）

- **Linux 内核官方文档** `Documentation/networking/ip-sysctl.rst` — <https://www.kernel.org/doc/html/latest/networking/ip-sysctl.html>
  （`tcp_rmem` / `tcp_wmem` / `tcp_moderate_rcvbuf` / `tcp_window_scaling` / `tcp_fastopen` / `tcp_slow_start_after_idle` /
  `tcp_notsent_lowat` / `tcp_congestion_control` / `tcp_available_congestion_control` / `tcp_base_mss` / `tcp_mtu_probing` /
  `tcp_no_metrics_save` / `tcp_dsack` / `tcp_early_demux` / `tcp_app_win`）
- `socket(7)` man page — <https://man7.org/linux/man-pages/man7/socket.7.html>（`SO_SNDBUF`/`SO_RCVBUF` 翻倍、`wmem_max`/`rmem_max` 语义）
- `Documentation/admin-guide/sysctl/net.rst`（`net.core.*` — 由 ip-sysctl 引用）
- **h2#975**（双端 adaptive_window 死锁，2026-10-08 建，至今 open）— <https://github.com/hyperium/h2/issues/975>
- **h2#976**（迟到 SETTINGS ACK 缩窗停摆，2026-10-09 建，2026-11-10 关）— <https://github.com/hyperium/h2/issues/976>
- crates.io API（h2 版本序列，最新 0.4.20 / 2026-10-06）— <https://crates.io/api/v1/crates/h2/versions>
- Gettys & Nichols.「Bufferbloat: Dark Buffers in the Internet」, *CACM* 55(1) 2012 — <https://queue.acm.org/detail.cfm?id=2071893>
  （镜像 PDF：<https://www.cse.iitb.ac.in/~mythili/teaching/cs224m_autumn2017/references/buffer-bloat.pdf>）

### tier3（博客/论坛 —— 已标注，仅作「运维反模式来源」旁证）

- 腾讯云《Network Kernel Optimization》— <https://www.tencentcloud.com/document/product/1330/84307>
- CubePath《How to Tune Linux TCP Settings with sysctl on Ubuntu 24.04》— <https://cubepath.com/docs/advanced-topics/advanced-tcp-ip-tuning-with-sysctl>

### 内部一手证据（本仓文件，tier1 等价）

- `Cargo.lock:1588-1591`（h2 0.4.19）/ `:1847-1850`（hyper 1.10.1）/ `:1899-1902`（hyper-util 0.1.20）
- `crates/xray-transport-splithttp/src/flow_window.rs:30-57`（诊断 env 语义）/ `:110-121`（覆盖行为与区间）
- `crates/xray-transport/src/h2_window.rs:13-28`（静态窗常量 + 「真缓冲」语义）
- `crates/xray-transport-splithttp/src/hub/handler.rs:56`（`DUPLEX_BUF = 64KiB`）/ `:464-467`（64KiB 读块治「帧粒度钉死 4KB」）
- `crates/xray-transport-splithttp/src/hub/dl_stream.rs:34`（`PoolStream(64KiB)`）
- `crates/xray-transport-splithttp/src/pool_stream.rs:36`（`UPLINK_CHUNK = 64KiB`）
- `crates/xray-transport-splithttp/src/transport.rs:46-47` / `:1268-1272`（`copy_large` 64KiB + 8KB 病已治注释；**bd n8b4e 已删该桥，指针仅存历史**）
- `crates/xray-transport/src/bridge.rs:638-641`（字节闸口径）/ `:705-715`（读腿三选一）/ `:738-744`（闸实例化=每连接）
- `crates/xray-frame/src/budget/plan.rs:58-61`（过订 3.3-21×）/ `:102-105`（4/32MiB 上下限）/ `:226`（闸值派生）/ `:457-460`（small 档 12MiB）
- `crates/xray-transport-quic/src/congestion_swappable/quinn_bridge.rs:517-520`（**本仓 BbrSender 是桩**）
- `crates/xray-transport-quic/src/congestion_swappable/bbr/bbr_sender.rs:157`/`:183`/`:330-341`（min_rtt/带宽无公开 getter）
- `crates/xray-transport-quic/src/congestion_swappable/types.rs:75`（`CongestionControl` = 包级 trait）
- `crates/xray-transport/src/sockopt/mod.rs:368`（`tcp_nodelay: true` 缺省）/ `:737`/`:884`（两条 apply 路径）
- `crates/xray-proxy-ss/src/conn.rs:466`（ss 的 64KiB 读窗，与 xhttp 对照）
- `crates/xray-frame/src/budget.rs:87`（`SOCKET_KERNEL_BOOKEEPING_FACTOR = 2`）
- `crates/xray-cli/src/bin/xray.rs:195-203`（mimalloc 全局分配器，**已是**高性能分配器 ⇒ §3.3 无需再谈 jemalloc）

---

## 7. 本轨的自评（5 维，按 CLAUDE.md §6 口径）

| 维 | 分 | 说明 |
|---|---|---|
| **准确** | 4.5/5 | 全部 tier1 结论逐行核对本地 registry 源码与内核源码；**唯一未实测项**（节点 sysctl 实际值、bbrplusv3 的 knob 集）已显式标注「未能实测」并给了判别命令，未编造数字 |
| **可执行** | 4/5 | §3.3/§3.4 每条都带命令 + 预期现象 + 副作用 + 回滚；**缺一处**：节点 ssh 通道不可用 ⇒ §3.4 的命令是「拿过去跑」而非「已跑过」 |
| **诚实交付** | 5/5 | **本轨 18 条里 11 条判「不适用」**，并逐条给出理由；没有为凑数硬推；`adaptive_window` 这个「看起来像白拿」的能力被明确判为**净负收益**并给了机理 |
| **不越界** | 5/5 | 未改任何代码/配置；未重复轨 B 的 OSS 实现对比；未建议 fork/vendor h2；未重提简报 §2 的 7 条死路（唯一提及 r5j96/`TCP_NOTSENT_LOWAT` 是作为**反例引用**而非提案） |
| **溯源** | 4.5/5 | 每条带 URL + tier + 文件行号；tier3 仅 2 条且明确标注为「反模式来源旁证」；内核事实全部引官方文档/源码而非博客 |

**总评：4.6/5**。**最大缺口**：本轨无法连到那台单核节点（`ssh://` 无已配置主机），
所以 §3.2 的「528MB ⇒ `tcp_rmem[2]` ≈ 4MB」是**基于内核源码公式的推算**，
§3.3 的 Z/S 清单是**待实测的候选**而非实测结论 —— **接手方第一步就该跑 §3.4 的三条只读命令**。
