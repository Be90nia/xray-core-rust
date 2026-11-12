# 调研轨 B · GitHub 成熟实现的机制与默认参数

> 2026-11-12 · 配合 [`2026-11-12-high-rtt-brief.md`](2026-11-12-high-rtt-brief.md)（共享简报）· 纯调研，未改任何代码/配置
>
> **tier 口径**：tier1 = 论文/RFC/**项目源码**；tier2 = 官方文档/issue/配置手册；tier3 = 博客/论坛（本报告尽量不用 tier3）。
> **裁决口径**：`直接可用` / `需改造` / `不适用（附理由）`。本报告**多数条目的裁决是「不适用」**——这不是保守，是简报 §2 的实测（窗余量 = 需求的 8.7×、在途 2.4MB ≪ 窗地板 20.8MiB）与本轨源码事实交叉验证后的结论。
> **依赖口径**：本报告**不引入任何新依赖**（全部结论都指向「已装依赖的能力」或「判定不适用」）。

---

## 0. 结论速览（先看这页）

| # | 对象 | 关键默认值 | 机制一句话 | 裁决 |
|---|---|---|---|---|
| 1 | gRPC-Go `bdpEstimator` | `bdpLimit=16MiB`, `beta=0.66`, `gamma=2`, `alpha=0.9`, 起始窗 65535 | 接收侧发 BDP ping 量 RTT→按 BDP 放大**自己发出的** `SETTINGS_INITIAL_WINDOW_SIZE` | **不适用**（①方向错：它放大的是"我收"的窗，我们卡在"我发"的方向；②我们的窗已 ≫ BDP；③要改 h2 crate 退款路径 = vendor） |
| 2 | nghttp2 窗口策略 | `NGHTTP2_INITIAL_WINDOW_SIZE=65535`, 连窗 65535；**退款阈值 = 半窗** | `recv_window_size ≥ local_window_size/2` 才发 `WINDOW_UPDATE` | **不适用**（阈值已是行业标准 1/2；简报 E1 证明退款粒度收益 0；改 = vendor nghttp2/h2） |
| 3 | h2 crate（**我们的栈**） | `DEFAULT_INITIAL_WINDOW_SIZE=65535`, `DEFAULT_MAX_FRAME_SIZE=16384`；退款阈值 `unclaimed ≥ window/2` | 消费侧累计到半窗才发一次 `WINDOW_UPDATE` | **不适用**（同上；另：我们简报里的 "T/3 批粒度" 比行业标准更保守） |
| 4 | quinn | `STREAM_RWND = 12.5MB/s × 100ms = 1.25MB`；`send_window = 8×STREAM_RWND = 10MB`；`receive_window = VarInt::MAX` | **窗口 = 目标带宽 × 期望 RTT**（源码里写死的 BDP 公式） | **需改造（仅 QUIC 腿）**：我们 quic 腿若沿用默认值，等于按 12.5MB/s 假设配窗；可按实测带宽重算 |
| 5 | Go `x/net/http2` | **客户端**：连窗 `1<<30`=1GiB、流窗 `4<<20`=4MiB；**服务端**：两者均 `1<<20`=1MiB | **完全不做自适应**：固定给大窗，靠窗口 ≫ BDP 兜底 | **不适用**（且**纠正我们内部记录**：Go 客户端"收窗 1MiB"是错的，见 §1.5） |
| 6 | HAProxy h2 | `tune.bufsize=16384`；`tune.h2.initial-window-size=16384`；`tune.h2.fe/be.rxbuf=1600k`；`max-concurrent-streams=100` | **共享接收缓冲池**：每流保底 1 个 buffer，其余空闲 buffer 在活跃流之间**动态共享**，窗口随可用内存浮动 | **需改造（方向反）**：它是"接收侧"模型；对我们"发送侧"吞吐无直接增益，但对我们**内存账本/窗口一致性**有借鉴价值 |
| 7 | Envoy h2 | `initial_stream_window_size=16MiB`、`initial_connection_window_size=24MiB`、`max_concurrent_streams=1024`、`per_connection_buffer_limit_bytes=1MiB` | **窗口 == 内存预算**：h2 流窗直接当作该流可缓冲字节的软上限，触顶触发 watermark → 反压读 | **不适用**（我们窗已 16MiB/32MiB ≫ BDP）；其"窗口=预算"纪律可借鉴 |
| 8 | nginx | `proxy_buffer_size` = 页大小(4KB)、`proxy_buffers` = 8×4KB、`proxy_busy_buffers_size` = 2×4KB、`proxy_max_temp_file_size` = 1GB | **不缓冲整对象**：小缓冲 + 背压 + 落盘临时文件；吞吐交给内核 TCP 窗 | **不适用**（nginx 无 h2 上游；其模型说明"行业答案"是不堆内存） |
| 9 | Caddy | `WriteBufferSize/ReadBufferSize=4KiB`、`MaxIdleConnsPerHost=32`、h2 窗 = Go 默认 | 透传（`copyResponse`），不做全量缓冲 | **不适用** |
| 10 | HAProxy socket 缓冲 | `tune.sndbuf.* / rcvbuf.*` 默认 **0（不设）**，文档明说 "should normally never be set" | 行业共识：**不显式设 socket 缓冲**，让内核 autotune | **不适用/佐证**：与我们简报 §2「显式 SO_RCVBUF 血案」一致（外部佐证，非新提案） |
| 11 | HAProxy `notsent-lowat` | `tune.notsent-lowat.client/server`，默认 0（不限） | 用途是**省内存 + 降应用层延迟**，不是提吞吐 | **佐证已关闭路径**：我们回退 `TCP_NOTSENT_LOWAT`（commit `dbdfc83d`）与行业用途一致 |
| 12 | aria2 | `-x`=1（每服务器连接数）、`-s`=5、`-k`=20M、`-j`=5、`--optimize-concurrent-downloads`=false | 分段多连接 + **按实测带宽自适应并发数**（闭环） | **不适用**（我们单核 CPU 已是天花板，bd bhneq ≈33MB/s；加连接不增 CPU 预算） |
| 13 | yt-dlp | `--concurrent-fragments`=1、`--http-chunk-size` 默认关闭（常用 10MB） | 分片并发 + 大 chunk 绕服务端限速 | **不适用**（同上） |
| 14 | curl | `--parallel-max` = 50（7.66.0 新增） | 固定并发上限，无 BDP 公式 | **不适用**（同上） |

**本轨的一句话答案**：**在"高 RTT + 单核 CPU 受限"这个形态下，行业里没有"按 BDP 动态定窗"能救我们的成熟答案**——
(a) 真正做 BDP 自适应的只有 gRPC-Go 一家（单实现、无外部采纳、且方向是接收侧）；
(b) 主流（Go / Envoy / nginx / Caddy / quinn）全部走**"固定给足窗口 + 让窗口 ≫ BDP"**或**"小缓冲 + 交回内核 TCP"**两条路；
(c) 我们已经处在 (b) 的第一条路上（窗 16/32MiB ≫ BDP 2.4–8MB），**所以流控窗这条路在结构上就不可能是杠杆**——
这个判断有本轨源码事实（Go 4MiB/1GiB、Envoy 16MiB/24MiB、quinn 1.25MB×bandwidth×RTT）+ 我们自己的 E1/E4 实测双重支撑。

---

## 1. BDP 动态定窗 / 定缓冲：四个实现逐个拆

### 1.1 gRPC-Go：`bdpEstimator` + `dynamicWindow`（**唯一真·BDP 自适应实现**）

**来源**（tier1，项目源码）：
- <https://github.com/grpc/grpc-go/blob/master/internal/transport/bdp_estimator.go>
- <https://github.com/grpc/grpc-go/blob/master/internal/transport/http2_client.go>（`updateFlowControl` / `handleData`）
- <https://github.com/grpc/grpc-go/blob/master/internal/transport/http2_server.go>
- <https://github.com/grpc/grpc-go/blob/master/internal/transport/defaults.go>
- <https://github.com/grpc/grpc-go/blob/master/dialoptions.go> / `server.go`（`StaticWindowSize` 开关）

**关键常量**（`bdp_estimator.go` L26–43）：

```go
const (
    bdpLimit = (1 << 20) * 16   // 16MiB，窗口增长上限
    alpha    = 0.9              // RTT 移动平均系数（样本数 ≥10 后）
    beta     = 0.66             // 当前样本 ≥ 0.66×BDP 且是历史最大带宽 ⇒ 判定"可以放大"
    gamma    = 2                // 放大后 BDP = 2×样本
)
```

**机制一句话**：接收侧在每轮采样开始时插一个**特殊 PING**（payload `{2,4,16,16,9,14,7,7}`，tier1 `bdp_estimator.go` L47），用 PING/PONG 往返量出**真实数据路径 RTT**，再按 `bwCurrent = sample/(rtt×1.5)` 估带宽；当样本 ≥ `0.66×BDP` 且带宽创历史新高，就把 BDP 置为 `2×样本`（上限 16MiB），然后 `updateFlowControl(bdp)`：
- 向对端发 `SETTINGS_INITIAL_WINDOW_SIZE = bdp`（**放大对端能发给我多少**）；
- 同时把连接级 `WINDOW_UPDATE` 增到同一量级；
- 前 10 个样本用平均值 bootstrap RTT，之后用 `alpha=0.9` 指数加权。

**触发条件 / 关闭开关**：
- 默认开启：`http2_client.go` L407 `if !opts.StaticWindowSize { t.bdpEst = &bdpEstimator{...} }`；服务端同构（`http2_server.go` L301）。
- 起始窗 = `defaultWindowSize = 65535`（`defaults.go` L28，HTTP/2 规范默认）。
- 关闭方式：`WithInitialWindowSize` / `WithInitialConnWindowSize` / `WithStaticStreamWindowSize` / `WithStaticConnWindowSize` 任一都会置 `StaticWindowSize=true`（`dialoptions.go` L215/225/242/260）。注意：**旧的用户可见选项 `WithDynamicWindow` 在当前 master 的 `dialoptions.go` 里已不存在**（grep 0 命中）——动态窗已变成"默认行为、没有开关"，只留下"关掉它"的开关。

**实测收益出处**：gRFC A31（`grpc/proposal` 仓库 A31 文件在 master 上已 404，我未取到原文）——**本条来源缺失，我按"未取到"记账，不引用其数字**。

**适用性裁决：不适用**（三条独立理由）
1. **方向错**：gRPC 的估计器长在**接收侧**，放大的是"对端可以发给我多少"。我们卡的是**发送方向**（节点→客户端推大文件）——发送侧能发多少由**客户端授予的窗**决定，服务端改自己的窗对发送方向无效。要在发送方向用这套机制，只能让**客户端**跑估计器，而客户端是 Go / v2rayN（见 §1.5，它们根本不跑这套）。
2. **量级不对**：我们的窗（服务端流 16MiB / 连 32MiB，客户端 32MiB/32MiB，见 zct77 §4.1）已经 ≫ BDP（受控台在途 2.4MB；真实路径 200ms×40MB/s ≈ 8MB）。BDP 自适应的收益公式是"窗 < 1.5×BDP 时才起作用"，我们永远进不了这个区间。
3. **代价不对**：要改退款路径就得动 h2 crate（我们已 vendor 过 rustls/quinn-proto，有先例也有月度 rebase 债），简报 §12 已判定"vendor h2 是最贵的错"。

**新依赖**：无（gRPC-Go 是 Go 侧参考，不进我们依赖树）。若真要抄机制 ⇒ **需要 vendor h2**（明确不建议）。

---

### 1.2 nghttp2：半窗退款 + 64KB 起始窗

**来源**（tier1，源码）：
- <https://github.com/nghttp2/nghttp2/blob/master/lib/nghttp2_helper.c>（`nghttp2_should_send_window_update`，L251–255）
- <https://github.com/nghttp2/nghttp2/blob/master/lib/nghttp2_session.c>（`session_update_recv_stream_consumed_size` / `nghttp2_session_consume`）
- <https://github.com/nghttp2/nghttp2/blob/master/lib/includes/nghttp2/nghttp2.h>

**关键常量**：
```c
#define NGHTTP2_INITIAL_WINDOW_SIZE        ((1 << 16) - 1)   /* 65535，流初始窗 */
#define NGHTTP2_INITIAL_CONNECTION_WINDOW_SIZE ((1 << 16) - 1) /* 65535，连初始窗 */
#define NGHTTP2_MAX_WINDOW_SIZE            ((int32_t)((1U << 31) - 1))
```

**机制一句话**：`nghttp2_should_send_window_update(local, recv) = recv > 0 && local > 0 && recv >= local/2` —— **消费掉半个窗才发一次 `WINDOW_UPDATE`**（增量 = 已消费字节，不是"补满"）；另有 `nghttp2_option_set_no_auto_window_update()` 可关掉自动退款、改为应用显式 `nghttp2_session_consume()` 驱动。

**适用性裁决：不适用**
- 退款阈值"半窗"就是行业标准（nghttp2 / h2 crate 都是 1/2，见 §1.3）。我们简报里的"T/3 批粒度"其实**比行业更保守**。
- 简报 §7 已实测：窗口余量 = 需求的 8.7× ⇒ 改退款粒度收益 0；且改它必须 vendor。
- nghttp2 本身我们也不用（我们用 Rust 的 `h2` crate）。

**新依赖**：无。

---

### 1.3 h2 crate（**我们自己的栈**）：`DEFAULT_INITIAL_WINDOW_SIZE` 与半窗退款

**来源**（tier1，源码）：
- <https://github.com/hyperium/h2/blob/master/src/proto/streams/flow_control.rs>
- <https://github.com/hyperium/h2/blob/master/src/frame/settings.rs>

**关键常量**：
```rust
pub const DEFAULT_INITIAL_WINDOW_SIZE: u32 = 65_535;   // settings.rs L44
pub const DEFAULT_MAX_FRAME_SIZE: FrameSize = 16_384;  // settings.rs L47
pub const MAX_INITIAL_WINDOW_SIZE: usize = (1 << 31) - 1;
```
```rust
// flow_control.rs L18-L19, L93-L107
const UNCLAIMED_NUMERATOR: i32 = 1;
const UNCLAIMED_DENOMINATOR: i32 = 2;   // 阈值 = window/2
pub fn unclaimed_capacity(&self) -> Option<WindowSize> {
    let threshold = self.window_size.0 / UNCLAIMED_DENOMINATOR * UNCLAIMED_NUMERATOR;
    if unclaimed < threshold { None } else { Some(unclaimed as WindowSize) }
}
```

**机制一句话**：h2 crate 把"未认领的容量"累到 **≥ 半个窗**才发一次 `WINDOW_UPDATE`，增量 = 已消费总量（不是补满）——与 nghttp2 完全一致的半窗聚合。

**顺带核实的两件事（tier1 grep 0 命中）**：
- h2 crate **没有任何 BDP / 带宽 / autotune 代码**（GitHub 代码检索 `repo:hyperium/h2 bdp OR bandwidth OR autotune` = **0 命中**，全仓级）⇒ 上游 hyper/h2 **不提供**流控自适应能力（zct77 §M3 的结论成立，我复核无误）。
- h2 crate 也**不提供**改退款阈值/窗口策略的公开旋钮：GitHub 代码检索 `repo:hyperium/h2 WindowUpdateStrategy` = **0 命中**，`src/server.rs` 里也**没有** `window_update_strategy` setter（tier1 复核）⇒ 阈值完全封在 crate 内部 ⇒ 改阈值 = vendor（zct77 §M7 结论复核成立）。
  （注：窗口**大小**是可以在 crate 外设的——我们本仓就是通过 **hyper** 的 `http2::Builder::initial_stream_window_size / initial_connection_window_size` 间接设置 h2 的 `SETTINGS_INITIAL_WINDOW_SIZE`，见 `crates/xray-transport-splithttp/src/h2_params.rs`。**"设窗大小"可做、"改退款阈值"只能 vendor** —— 这两件事必须分开看。）

**适用性裁决：不适用**（同 §1.2：阈值已是行业标准 1/2；简报已实测收益 0；改 = vendor h2 = 明确否决项）。

**新依赖**：无。

---

### 1.4 quinn：**唯一把 BDP 公式写进源码的通用实现**

**来源**（tier1，源码）：
- <https://github.com/quinn-rs/quinn/blob/main/quinn-proto/src/config/transport.rs>（`TransportConfig::default`，L376–390）
- <https://github.com/quinn-rs/quinn/blob/main/quinn-proto/src/congestion.rs>（`pub use bbr::{Bbr, BbrConfig};`）

**关键常量（这就是作业要的那个"窗口/RTT 推导公式"）**：
```rust
impl Default for TransportConfig {
    fn default() -> Self {
        const EXPECTED_RTT: u32 = 100;              // ms
        const MAX_STREAM_BANDWIDTH: u32 = 12500 * 1000; // bytes/s  (12.5 MB/s)
        // Window size needed to avoid pipeline stalls
        const STREAM_RWND: u32 = MAX_STREAM_BANDWIDTH / 1000 * EXPECTED_RTT;  // = 1_250_000
        Self {
            max_concurrent_bidi_streams: 100,
            stream_receive_window: STREAM_RWND.into(),     // 1.25MB
            receive_window: VarInt::MAX,                    // ≈2^62，实质无限
            send_window: (8 * STREAM_RWND).into(),          // 10MB
            initial_rtt: Duration::from_millis(333),        // RFC 9000 默认
            ...
        }
    }
}
```

**机制一句话**：quinn 的**流接收窗 = 目标带宽 × 期望 RTT**（`bandwidth × RTT`，即 BDP），连接接收窗放到 `VarInt::MAX`（实质无限），发送窗 = 8×流窗；**流窗可以按"避免管道停顿"这个判据独立推导**，而不是拍一个固定值。

**另**：quinn 内置 BBR（`quinn::congestion::Bbr` / `BbrConfig`），我们仓已有 `crates/xray-transport-quic/src/congestion_swappable/bbr/`。

**适用性裁决：需改造（仅 QUIC 腿）**
- 公式本身可以直接抄：`window = 目标带宽 × 期望 RTT`。我们 h2 腿**不用**（h2 是 HTTP/2 无 QUIC 传输层，不能按此配窗），所以对主瓶颈无增益。
- 但对我们 **h3/QUIC 腿**有直接价值：quinn 默认按 **12.5MB/s** 假设配窗，若我们实际能跑 30–40MB/s，窗口就偏小（1.25MB×流；若单流）——按实测带宽重算 `stream_receive_window` 是"零新依赖、纯配置"的改动。
- 判决边界：QUIC 腿是否在我们的关键路径上，本轨不判定（属主代理/其他轨的范围）。

**新依赖**：无（quinn 已在依赖树内）。

---

### 1.5 Go `x/net/http2`：**核实我们内部记录（结论：记错了）**

**来源**（tier1，源码）：
- <https://github.com/golang/net/blob/master/http2/config.go>（L104–113）
- <https://github.com/golang/net/blob/master/http2/transport.go>（L41–49、L474、L529、L541–542）
- <https://github.com/golang/net/blob/master/http2/server.go>（L283、L800）
- Go 标准库内嵌副本（tier1）：<https://github.com/golang/go/blob/release-branch.go1.24/src/net/http/h2_bundle.go>（`http2transportDefaultConnFlow = 1 << 30`、`http2transportDefaultStreamFlow = 4 << 20`，L7462–7470）

**关键常量**（`config.go` L104–113，**server / client 分叉**）：
```go
if server {
    setDefault(&conf.MaxUploadBufferPerConnection, initialWindowSize, math.MaxInt32, 1<<20)   // 1MiB
} else {
    setDefault(&conf.MaxUploadBufferPerConnection, initialWindowSize, math.MaxInt32, transportDefaultConnFlow) // 1GiB
}
if server {
    setDefault(&conf.MaxUploadBufferPerStream, 1, math.MaxInt32, 1<<20)                        // 1MiB
} else {
    setDefault(&conf.MaxUploadBufferPerStream, 1, math.MaxInt32, transportDefaultStreamFlow)     // 4MiB
}
```
```go
// transport.go L44 / L49
transportDefaultConnFlow   = 1 << 30   // 1GiB："how many connection-level flow control tokens we give the server at start-up"
transportDefaultStreamFlow = 4 << 20   // 4MiB："how many stream-level flow control tokens we announce to the peer"
```

**机制一句话**：Go 的 h2 **完全不做自适应**——客户端开局就宣布 **连窗 1GiB / 流窗 4MiB**，服务端则给 **1MiB / 1MiB**；整个 `x/net/http2` 里 **grep 不到任何 bdp / autotune / bandwidth 逻辑**（tier1 复核）。

**⭐ 我们内部记录的纠正**（作业点名要核实的项）：

| 我们内部记的 | 实际（tier1 源码） | 判定 |
|---|---|---|
| Go 客户端收窗 **1MiB** | Go **客户端**连窗 = **1GiB**（`transportDefaultConnFlow`）；**1MiB 是 Go 服务端**的 `MaxUploadBufferPerConnection` 默认 | ❌ **记错一半**：1MiB 属服务端；客户端侧是 1GiB |
| Go 客户端流窗 **4MiB** | ✅ 对（`transportDefaultStreamFlow = 4<<20`） | ✅ 正确 |

**这条纠正为什么重要（不是抠字眼）**：zct77 文档 §1.2 有一句"Go 客户端默认收窗只有 1MiB/流窗 4MiB"，并据此推出"C/D 两格都被客户端小窗绑定"。按本轨源码核实，**客户端连窗是 1GiB 而不是 1MiB**，所以"被客户端小窗绑定"这个归因的**连窗部分不成立**（流窗 4MiB 部分成立）。它不推翻 zct77 的结论（那结论最终靠 A vs B 的 1.9× 差坐实 ours-srv），但它**改变了后续归因的可选解释集合**：客户端连窗从来不是瓶颈，瓶颈候选回到 ours-srv 的写侧/停-启相位（与 E2/E4 的实测方向一致）。

**适用性裁决：不适用**（作为"提速手段"）——Go 的做法恰恰印证了 §0 的判断：**主流实现的做法是"固定给足窗口 + 窗口 ≫ BDP"，不是"按 BDP 微调"**。Go 客户端 4MiB 流窗在 200ms RTT 下对应单流天花板 ≈ 4MiB/0.2s ≈ **21MB/s**——这正好解释了简报里"Go 官方客户端走 xhttp 只有 25–27MB/s"这个数（单流或两流即触顶）。我们 Rust 客户端给了 32MiB 流窗 ⇒ 天花板 ≈ 160MB/s ⇒ 实际只跑到 15–40MB/s ⇒ **剩下的差距不在 h2 窗上**（这条与 E1「64MiB 对照无收益」互相印证）。

**新依赖**：无。

---

## 2. 真实代理的"每连接缓冲预算"（行业默认即答案）

### 2.1 Envoy：窗口 = 内存预算

**来源**（tier1 proto + 源码；tier2 文档）：
- <https://github.com/envoyproxy/envoy/blob/main/api/envoy/config/cluster/v3/cluster.proto>（`per_connection_buffer_limit_bytes`，L910–912）
- <https://github.com/envoyproxy/envoy/blob/main/api/envoy/config/core/v3/protocol.proto>（`Http2ProtocolOptions`，L599–631）
- <https://github.com/envoyproxy/envoy/blob/main/source/common/http/http2/codec_impl.cc>（`per_stream_buffer_limit_(http2_options.initial_stream_window_size().value())`，L970；`ClientStreamImpl(..., per_stream_buffer_limit_, ...)`，L2470）
- <https://github.com/envoyproxy/envoy/blob/main/docs/root/faq/configuration/flow_control.rst>（tier1 官方 FAQ）
- 边缘最佳实践（tier2）：<https://www.envoyproxy.io/docs/envoy/latest/configuration/best_practices/edge>

**关键默认值**：
| 旋钮 | 默认 | 出处 |
|---|---|---|
| `cluster.per_connection_buffer_limit_bytes` | **1MiB**（"an implementation defined default is applied (1MiB)"） | `cluster.proto` L910 |
| `listener.per_connection_buffer_limit_bytes` | **1MiB** | `cluster.proto` L910 同族 |
| `Http2ProtocolOptions.initial_stream_window_size` | **16MiB** | `protocol.proto` L611–626 |
| `Http2ProtocolOptions.initial_connection_window_size` | **24MiB** | `protocol.proto` L628–631 |
| `Http2ProtocolOptions.max_concurrent_streams` | **1024** | `protocol.proto` L599–604 |

**机制一句话**（Envoy 官方 FAQ，tier1）：
> "The cluster limits affect how much raw data will be read per read() call from upstream, **as well as how much data may be buffered in userspace** between Envoy and upstream."
> 且 h2 的 `initial_stream_window_size` "also acts as a **soft limit on the number of bytes Envoy will buffer per-stream** … Once the buffer reaches this pointer, **watermark callbacks will fire to stop the flow of data** to the stream buffers."

⇒ Envoy 把 **h2 流窗直接当作"该流允许缓冲的字节上限"**，窗口耗尽 = 内存上限 = 触发 watermark 反压（`codec_impl.cc` 里 `per_stream_buffer_limit_` 一路传给 `ClientStreamImpl`/`ServerStreamImpl`）。**这就是"窗口 = 预算"的干净范式。**

**额外发现（对我们 CPU/字节有用）**：`per_connection_buffer_limit_bytes` **同时决定每次 `read()` 的批量大小**——"how much raw data will be read per read() call"。这是 Envoy 唯一把"每 syscall 批量"显式做成配置的旋钮。

**边缘最佳实践（tier2）**：Envoy 官方 edge 指南建议把 listener/cluster buffer limit 降到 **32KiB**——即"边缘代理应该少缓冲、交给内核 TCP 窗"。

**适用性裁决：不适用（作为吞吐杠杆）**；**需改造（作为纪律借鉴，两条）**
1. 不适用：我们的流窗 16MiB / 连窗 32MiB 已 ≫ BDP（2.4–8MB），Envoy 那种"流窗 = 每流内存预算"对我们只会**提前反压**（我们的桥闸才是内存闸）。
2. 可借鉴 A（对我们**内存账本**有意义，非吞吐）：我们 `crates/xray-frame/src/budget/plan.rs` 的 `bridge_gate` 与 h2 流窗是**两套互不知情的预算**；Envoy 的范式是"一个数字同时管窗口与内存"，我们的记账面（bd u440m/D-01 的过订登记）若引入"窗 ≤ 可用内存"的一致性约束，能从根上消掉过订争议。
3. 可借鉴 B（对我们**每字节 CPU**可能有杠杆）：Envoy 让"每 read() 批量 = 连接缓冲限"。我们的读取粒度目前是固定的（h2/hyper 侧 64KiB chunk，见 zct77 §M5）——把"读取批量"与"内存闸"绑成同一个旋钮，是一个**零新依赖**的可测点（与 zct77 R2「帧 16KiB→64KiB」是同一族、但作用在 read 侧）。

**新依赖**：无。

---

### 2.2 HAProxy：**共享接收缓冲池 ⇒ 每流窗口动态浮动**（本轨最值得抄的一条）

**来源**（tier1 源码 + tier2 配置手册）：
- <https://github.com/haproxy/haproxy/blob/master/doc/configuration.txt>（`tune.h2.*`、`tune.bufsize`、`tune.sndbuf.*`、`tune.notsent-lowat.*`、`tune.h2.zero-copy-fwd-send`）
- <https://github.com/haproxy/haproxy/blob/master/include/haproxy/defaults.h>（`BUFSIZE 16384`，L71–86）
- <https://github.com/haproxy/haproxy/blob/master/src/cfgparse.c>

**关键默认值**：
| 旋钮 | 默认 | 出处 |
|---|---|---|
| `tune.bufsize` | **16384**（16KB，每流最多缓存字节） | `defaults.h` L81；`configuration.txt` L4489–4492 |
| `tune.h2.initial-window-size` | **16384**（= `tune.bufsize`） | `configuration.txt` L4976–4991 |
| `tune.h2.fe.rxbuf` / `tune.h2.be.rxbuf` | **1600k**（100 流 × 16KB） | `configuration.txt` L4954–4967 / L4810–4824 |
| `tune.h2.max-concurrent-streams` | **100** | `configuration.txt` L5003–5010 |
| `tune.h2.max-frame-size` | max(16384, `tune.bufsize`) | `configuration.txt` L5014–5021 |
| `tune.h2.zero-copy-fwd-send` | **on** | `configuration.txt` L5023–5027 |
| `tune.h1.zero-copy-fwd-send` / `h1.zero-copy-fwd-recv` | **on** | `configuration.txt` L4747–4757 |
| `tune.notsent-lowat.client/server` | **0**（不限） | `configuration.txt` L5389–5401 |
| `tune.sndbuf.*` / `tune.rcvbuf.*` | **0**（不设，让内核 autotune） | `configuration.txt` L5762–5766 / L5833–5837 |
| 每连接常驻内存 | **≈33KB**（"two buffers of tune.bufsize (16kB by default) each"） | `configuration.txt` L10384–10388 |

**机制一句话（共享池动态窗）**（`configuration.txt` L4954–4967，HAProxy 原文）：
> "Sets the HTTP/2 receive buffer size for incoming connections … This size will be rounded up to the next multiple of tune.bufsize and **will be shared between all streams** … In any case, **one buffer will always be granted to each stream**, and **7/8 of the unused buffers will be shared between streams downloading payload**, allowing [the window] to be **automatically adjusted to reflect the available space** … **The default value is 1600k (100 streams with 16kB buffers each) permits roughly 130 Mbps of upload speed for a client with a 100ms RTT**."

**这条给出的是作业要的第二个公式**（HAProxy 自己写死在文档里的）：

> **每流带宽上限 ≈ 流窗 / RTT**。
> 16KB 窗 / 100ms RTT ⇒ 16384/0.1 = 164KB/s ≈ **1.25 Mbps/流**（`configuration.txt` L4851–4853 明写 "allows at least 1.25 Mbps of bandwidth per stream over a 100 ms ping time, and 125 Mbps for 1 ms ping time"）。
> 1600KB 池 / 100ms RTT ⇒ **≈130 Mbps**（同段原文）。

⇒ 换成我们的数：RTT 200ms、目标 30MB/s ⇒ 需要 **窗口 ≥ 6MB/流**（若单流）。我们客户端给的是 32MiB ⇒ **窗不是约束**（与 §1.5 一致）。

**HAProxy 对 socket 缓冲的立场（外部佐证我们已关闭的路）**：`tune.sndbuf.client/server` / `tune.rcvbuf.client/server` 文档原文："It should normally never be set, and the default size (0) lets the kernel [decide]"（L5762–5766、L5833–5837）⇒ **行业明确不建议显式设 socket 缓冲**，与我们简报 §2「显式 SO_RCVBUF = 锁 autotune ⇒ 反而更差」的血案一致。

**HAProxy 对 `TCP_NOTSENT_LOWAT` 的用途（外部佐证已回退的 commit）**：`tune.notsent-lowat.client/server` 的目的是 "to **significantly reduce the memory consumption** in system buffers, and **reduce the application level latency** incurred by flushing buffered data"（L5392–5399），默认 0（不限）⇒ 行业把它当**省内存/降延迟**工具，不是提速手段 ⇒ 我们回退 `dbdfc83d` 与行业定位一致。

**适用性裁决**
- **共享池动态窗（需改造，但方向与我们相反）**：HAProxy 的模型是"**窗口从实际可用内存里动态分配**"。我们是**发送侧**受限，它的模型管的是**接收侧**。要抄，只有一种落法：**我方客户端**（我们的 Rust 客户端）把它的 h2 接收窗从固定值改成"按可用内存动态给"——但我们的客户端侧并不受窗口限制（§1.5），所以**吞吐上不适用**。
  - **真正的价值在别处**：我们**服务端**的 h2 接收窗（上传方向）目前是固定 16MiB，而我们的内存闸（`budget/plan.rs` 的 `bridge_gate`，small 档 12MiB/方向）是**另一套账**。HAProxy 的"窗 = 池中实际可用 buffer"范式，可以作为**我们"窗与内存闸一致性"的建模参考**（与 §2.1 的 Envoy 结论同向）。
- **零拷贝转发（需改造，CPU 侧有条件）**：`tune.h2.zero-copy-fwd-send` 默认 **on**，实现是 **kernel splice 转发**（绕过用户态 buffer）。**但我们的链路中间夹着 TLS**（btls/rustls），splice 无法跨 TLS 边界 ⇒ **只能省下"用户态 buffer → socket"这一次拷贝**，TLS 前的拷贝省不掉 ⇒ 收益远小于 HAProxy 的纯 TCP 场景。**判：需改造且收益存疑，不建议本轮做**。
- **socket 缓冲 / notsent-lowat：不适用**（外部佐证已关闭路径，非新提案）。

**新依赖**：无（splice 需要 libc 能力，HAProxy 用 `splice(2)`；我们若要抄需 `nix`/`libc`——**属于新增依赖面，需 PM 拍板**，见 §6）。

---

### 2.3 nginx：小缓冲 + 背压 + 落盘

**来源**（tier1 源码 + tier2 官方文档）：
- <https://github.com/nginx/nginx/blob/master/src/http/modules/ngx_http_proxy_module.c>（`ngx_http_proxy_merge_loc_conf`，L3740–3845）
- 官方文档（tier2）：<https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_buffer_size>

**关键默认值**（源码 `ngx_conf_merge_*`）：
| 旋钮 | 默认 | 出处 |
|---|---|---|
| `proxy_buffer_size` | **`ngx_pagesize`**（Linux x86_64 = 4KB；官方文档写 4k\|8k） | `ngx_http_proxy_module.c` L3747–3748 |
| `proxy_buffers` | **8 × `ngx_pagesize`**（≈32KB） | L3753–3754 |
| `proxy_busy_buffers_size` | **2 × size**（≈8KB） | L3769–3778 |
| `proxy_temp_file_write_size` | **2 × size** | L3800–3809 |
| `proxy_max_temp_file_size` | **1GB** | L3820–3829 |
| `proxy_buffering` | **on** | L259–262 |

**机制一句话**：nginx **不把对象缓存进内存**：用 32KB 缓冲边读边写，客户端慢就写临时文件（上限 1GB），上游读取按缓冲大小切片 ⇒ **吞吐由内核 TCP 窗决定，不由应用缓冲决定**。

**适用性裁决：不适用**
- nginx 上游默认是 HTTP/1.1（`proxy_http_version` 默认 1.0/1.1），没有 h2 上游可比。
- 但它的**模型**给了我们一个有用的"行业答案"：**没人靠加大应用缓冲解决高 RTT 吞吐**；大家都把窗口让给 TCP。这与 §0 结论一致（我们已经在"给足窗口"这条路上）。

**新依赖**：无。

---

### 2.4 Caddy：透传，不缓冲

**来源**（tier1 源码）：
- <https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/reverseproxy/reverseproxy.go>（`copyResponse(rw, res.Body, h.flushInterval(...))`，L1543）
- <https://github.com/caddyserver/caddy/blob/master/modules/caddyhttp/reverseproxy/httptransport.go>（`WriteBufferSize`/`ReadBufferSize` 默认 **4KiB**，L119–123；`MaxIdleConnsPerHost` 默认 **32**，L218–220；`http2.ConfigureTransport(rt)`，L538）

**机制一句话**：Caddy 的 `reverse_proxy` 用 `copyResponse` **流式转发**，只有可配的 `flush_interval`；它的 h2 窗口**不自己定**，直接吃 Go 的默认（⇒ 连窗 1GiB / 流窗 4MiB，§1.5）。

**适用性裁决：不适用**（Caddy 没有我们这种"单核 + h2 复用 + 桥背压"的形态；且它的 h2 行为 = Go 的行为）。

**新依赖**：无。

---

## 3. 用「更多连接 / 更多流」换窗口：行业怎么决定并发数

### 3.1 各实现的并发流/连接默认值（tier1/tier2 汇总）

| 实现 | 旋钮 | 默认 | 出处 |
|---|---|---|---|
| Envoy h2 | `max_concurrent_streams` | **1024** | `protocol.proto` L599–604 |
| HAProxy h2 | `tune.h2.{fe,be}.max-concurrent-streams` | **100**（HAProxy 反而建议"别调大"） | `configuration.txt` L4860–4901, L5003–5010 |
| Go `x/net/http2` | `initialMaxConcurrentStreams` / `defaultMaxConcurrentStreams` | **100 / 1000** | `transport.go` L56–60 |
| quinn | `max_concurrent_bidi_streams` / `max_concurrent_uni_streams` | **100 / 100** | `quinn-proto/src/config/transport.rs` L382–383 |
| gRPC-Go | `defaultMaxStreamsClient` | **100** | `internal/transport/defaults.go` L34 |
| h2 crate（我们的栈） | — | 由 `H2Params::max_concurrent_streams` 显式设置；我们服务端写死 `H2_MAX_CONCURRENT_STREAMS`（`crates/xray-transport-splithttp/src/transport.rs` L634） | 本仓源码 |

**HAProxy 的告诫（tier2，可直接引用给决策人）**：*"A smaller value than the default 100 may improve a site's responsiveness at the expense of maintaining more established connections … It is highly recommended not to increase this value; some might find it optimal to run at low values (1..5 typically)."*（L4893–4901）—— **行业不认为"加流"是提速手段**。

### 3.2 真正在用"多连接换窗口"的：下载器

**aria2**（tier1 手册源码 + tier2 手册）：
- 来源：<https://github.com/aria2/aria2/blob/master/doc/manual-src/en/aria2c.rst>
- `-x, --max-connection-per-server=<NUM>` — "The maximum number of connections to one server for each download. **Default: 1**"（L183–186）
- `-s, --split=<N>` — "Download a file using N connections … **Default: 5**"（L317–326）
- `-k, --min-split-size=<SIZE>` — "aria2 does not split less than 2*SIZE byte range … **Default: 20M**"（L205–213）
- `-j, --max-concurrent-downloads=<N>` — **Default: 5**（L54–58）
- `--optimize-concurrent-downloads [true|false|<A>:<B>]` — "**Optimizes the number of concurrent downloads according to the bandwidth available. aria2 uses the download speed observed in the previous download to adjust the number of connections** … **Default: false**"（L1546–1558）

**机制一句话**：aria2 的答案是"**按目标带宽/RTT 需要的量分段 + 用多连接摊开每连接窗口**"（`-k 20M` 保证每段足够大、`-s 5` 拆 5 路），并且有一个**闭环自适应**开关（`--optimize-concurrent-downloads`）：用上一轮实测速率决定并发数。

**yt-dlp**（tier1 源码）：
- 来源：<https://github.com/yt-dlp/yt-dlp/blob/master/yt_dlp/options.py>
- `--concurrent-fragments`（`-N`）**Default: 1**（L1012–1014）
- `--http-chunk-size` — "Size of a chunk for chunk-based HTTP downloading … (default is disabled). **May be useful for bypassing bandwidth throttling imposed by a webserver (experimental)**"（L1077–1081）

**curl**（tier1 文档源码）：
- 来源：<https://github.com/curl/curl/blob/master/docs/cmdline-opts/parallel-max.md>
- `--parallel-max <num>` — "controls the maximum amount of transfers to do simultaneously. **The default is 50**. 65535 is the largest supported value."（Added in 7.66.0）

**机制一句话**：三家都**没有**"基于窗口/RTT 推导并发数"的公式——aria2 的 `-x/-s/-k` 是**固定值**，唯一的自适应是 aria2 那个**基于上一轮实测速率的闭环**（默认关）。

**适用性裁决：不适用（三条理由）**
1. **CPU 是我们的天花板，不是窗口**：us1 单核 xhttp+REALITY 服务端 CPU 上限 ≈ 33MB/s（bd bhneq，本仓既有结论）。多连接/多流在**同一颗核**上只会摊薄 CPU（而且我们的 zct77 §12 明确否决项 #12「加并发流互相覆盖退款」），不增加字节吞吐上限。
2. **我们的 h2 窗口已经 ≫ BDP**（§1.5 / §2.2 的公式），加流只是把同一份窗口预算切碎。
3. aria2 的闭环自适应（`--optimize-concurrent-downloads`）本身**值得记一笔**：它是"用实测速率反馈调节并行度"的**可抄模式**（不是抄它的默认值，是抄它的**控制结构**）——如果我们将来有"多档策略可切"的需求（例如 `maxConnections` 档位），可以用实测速率做闭环选择器，而不是让用户手调。但**本轮不适用**（无第二档可选、且 CPU 封顶）。

**新依赖**：无。

---

## 4. 降低每字节 CPU：外部做法盘点

| 做法 | 行业做法与出处 | 裁决 |
|---|---|---|
| **零拷贝转发（splice）** | HAProxy `tune.h1/h2/pt.zero-copy-fwd-*-send` **默认 on**，内核 splice 绕过用户态 buffer（`configuration.txt` L4747–4757, L5023–5027, L5456–5462） | **需改造但收益存疑**：我们链路上 TLS 夹在中间，splice 不能跨 TLS ⇒ 最多省一次拷贝；且需 `libc`/`nix` 能力（**新增依赖面，需 PM 拍板**）。不建议本轮做 |
| **h2 帧尺寸** | 全行业默认 **16KB**：h2 crate `DEFAULT_MAX_FRAME_SIZE=16384`（tier1 `settings.rs` L47）；Go `maxFrameSize: 16 << 10`（tier1 `transport.go` L474）；HAProxy `tune.h2.max-frame-size` = max(16384, bufsize)（tier2） | **与本仓既有候选 R2 同族**（16KiB→64KiB，帧数↓4×）。本轨**不重复提案**，仅确认：行业默认 16KB 是"规范默认"而非保守；Go 侧 `frameScratchBufferLen` 上限 512KB（`transport.go` L1480–1487）说明大帧 scratch 成本可控 |
| **每 syscall 批量** | Envoy：`per_connection_buffer_limit_bytes` **同时决定每次 read() 的批量大小**（tier1 flow_control FAQ）；HAProxy：`tune.h2.max-frames-at-once`（"maximum number of HTTP/2 incoming frames that will be processed at once on a backend connection"，L4803–4808） | **需改造（有条件）**：我们的读取批量目前固定（hyper/h2 侧 64KiB chunk，见 zct77 §M5），Envoy/HAProxy 都把它做成显式旋钮 ⇒ 值得作为"CPU 侧可测点"（与 R2 同族但作用在 read 侧），**零新依赖** |
| **TLS record 大小** | TLS 1.3 记录上限 16KB（RFC 8446 §5.1，tier1 规范）⇒ 一个 h2 帧 ≈ 一个 TLS record（我们 btls 侧） | **不适用**：受规范限制，不可调；且帧尺寸不变则 record 数不变 ⇒ 不构成独立杠杆 |
| **`sendmmsg` / `io_uring`** | 本轨**未在 HAProxy/Envoy 的 TCP 转发路径中找到 `sendmmsg`/`io_uring` 的使用**（HAProxy 的 `mmsg` 仅用于 UDP；Envoy 的 io_uring 用于**文件 I/O**，不用于 socket 发送） | **不适用（无先例可抄）**：不构成建议。注意：我们现在是 TLS 在中间，`sendmmsg` 本来也用不上 |
| **`MSG_ZEROCOPY`** | HAProxy 文档里没有该开关（grep 0 命中于 `configuration.txt` 的调优项列表） | **不适用**：无成熟先例，且 TLS 在中间时收益存疑 |
| **事件循环批处理** | HAProxy `tune.h2.max-frames-at-once`（一次事件循环处理 N 帧）；Go `x/net/http2` 的 `bufPools`（按尺寸分档的 scratch buffer 池，`transport.go` L1508–1509） | **需改造（低优先）**：Go 的分档 buffer 池是"减少每帧分配"的现成模式；我们仓已有池化纪律（xray_buf 分层池），大概率已覆盖 |

---

## 5. 裁决汇总（含明确「不适用」清单）

### 5.1 明确判「不适用」并说明的条目（≥1，本轨共 9 条）

1. **gRPC-Go BDP 动态窗** —— 方向错（接收侧 vs 我们的发送侧）+ 量级错（窗已 ≫ BDP）+ 代价高（vendor h2）。
2. **nghttp2 半窗退款阈值调整** —— 阈值已是行业标准 1/2；简报实测收益 0；改 = vendor。
3. **h2 crate 退款粒度/阈值改动** —— 同上，且 h2 crate 无公开旋钮（zct77 §M7 复核成立）。
4. **Go/Envoy/HAProxy 固定窗值照搬** —— 我们窗已 16/32MiB ≫ BDP（2.4–8MB）；E1「64MiB 对照无收益」独立印证。
5. **Envoy `per_connection_buffer_limit_bytes` 照搬（1MiB）** —— 会**提前反压**我们的桥闸（我们是靠 12MiB/方向的闸在管内存，h2 窗再小就双重限流）。
6. **aria2 / yt-dlp / curl 的多连接策略** —— 单核 CPU 是天花板（≈33MB/s，bd bhneq）；多连接不增字节吞吐。
7. **HAProxy 共享 rxbuf 动态窗（吞吐向）** —— 它是接收侧模型；我们的瓶颈在发送侧。
8. **HAProxy `tune.sndbuf/rcvbuf` / `notsent-lowat`（提速向）** —— 行业定位就是"省内存/降延迟"，且我们已有血案（bd r5j96）与回退（`dbdfc83d`）。
9. **nginx/Caddy 缓冲模型照搬** —— nginx 无 h2 上游；Caddy 的 h2 行为 = Go 行为。

### 5.2 判「需改造」但**本轮不主张做**的条目（留给决策人）

| 条目 | 为什么值得记 | 为什么本轮不做 |
|---|---|---|
| **窗口 = 内存预算**（Envoy 范式 + HAProxy 共享池范式） | 我们 h2 窗与 `xray-frame/src/budget/plan.rs` 的闸是两套账，bd u440m/D-01 的过订争议有结构性解法 | 与吞吐无关，属内存账本票；改动面在记账层，收益是"账本自洽" |
| **quinn 窗口按实测带宽重算**（§1.4） | quinn 默认按 12.5MB/s 配窗；我们 h3 腿若跑 30–40MB/s 则窗偏小 | 需确认 h3 腿是否在关键路径上（本轨不判定） |
| **read 批量 = 连接缓冲限**（Envoy 范式） | CPU 侧零新依赖的可测点，与 zct77 R2 同族 | 需与 §5.2-1 的预算口径一起定，否则又造一套账 |
| **零拷贝 splice** | HAProxy 默认开 | TLS 夹在中间，收益存疑 + 需 `libc`/`nix` 新依赖面 ⇒ **需 PM 拍板** |

### 5.3 依赖影响总表

| 提案 | 新依赖？ |
|---|---|
| gRPC-Go BDP 动态窗 | 否（参考实现）；但**真要抄 ⇒ 必须 vendor h2**（否决） |
| nghttp2 / h2 crate 退款阈值 | 否；改 ⇒ **vendor**（否决） |
| Go / Envoy / HAProxy 窗值照搬 | 否 |
| HAProxy 共享池动态窗（内存口径） | 否（纯本仓记账改造） |
| quinn 窗口重算 | 否（quinn 已在树内，改 `TransportConfig`） |
| read 批量旋钮 | 否 |
| 零拷贝 splice | **是**（`libc`/`nix` 能力面）⇒ **需 PM 拍板** |
| aria2/yt-dlp/curl 策略 | 否（纯行为参考） |

---

## 6. 对我们仓的具体落点线索（若 PM 决定推进某条）

| 落点 | 文件 / 符号 | 说明 |
|---|---|---|
| h2 客户端/服务端窗旋钮（已存在） | `crates/xray-transport-splithttp/src/h2_params.rs`：`H2Params::{initial_connection_window, initial_stream_window, max_concurrent_streams, max_frame_size}` + `apply`（L171–180 附近的 builder setter 组） | 已支持 Go 侧 `MaxReceiveBufferPerConnection/PerStream/MaxConcurrentStreams/MaxReadFrameSize` ⇒ **窗口类实验零代码**（E1/E4 就是这么做的） |
| 服务端并发流上限 | `crates/xray-transport-splithttp/src/transport.rs` L634 `.max_concurrent_streams(H2_MAX_CONCURRENT_STREAMS)` | 行业默认区间 100（HAProxy/Go/quinn）～1024（Envoy） |
| 内存闸（与 h2 窗的关系面） | `crates/xray-frame/src/budget/plan.rs`：`MemoryPlan`、`PER_CONN_UPPER_BYTES`（3MiB）、`ENV_MEM_LIMIT_MB`、`ENV_MAX_CONNS` | §5.2-1 的落点：把 h2 窗纳入同一本账 |
| 桥背压闸执行点 | `crates/xray-transport/src/bridge.rs` | §5.2-3（read 批量）与闸的耦合点 |
| QUIC 腿窗口/拥塞 | `crates/xray-transport-quic/src/congestion_swappable/bbr/` | §1.4 的 quinn `TransportConfig` 落点 |

---

## 7. 本轨**没有**回答 / 明确交给别人的问题

1. **根在哪一层**（简报 §3 问题 1）：本轨只提供了"窗口类解释在量级上不成立"的**排除性证据**（窗 16/32MiB ≫ BDP 2.4–8MB，tier1 交叉：Go 4MiB/1GiB、Envoy 16/24MiB、quinn 1.25MB×RTT、HAProxy 16KB+1600k 池），**没有**判定是 CPU / 停-启相位 / TCP 窗 / 连接数。⇒ 归 R0（E2/E3 取证）与主代理。
2. **BBR 的 app-limited 语义**（简报 §3 问题 3）：本轨未查（属论文/原理轨）。
3. **让内核窗口真的长大的正统做法**（sysctl 侧）：属零代码/内核轨（本轨只提供 HAProxy「不要显式设 socket 缓冲」的 tier2 佐证）。
4. **CDN/Argo 侧的行为**（我们的 ws vs xhttp 差异在边缘发生什么）：本轨未查（无公开源码可查）。

---

## 8. 引用清单（tier 标注）

**tier1（项目源码 / 官方规范）**
- gRPC-Go：`internal/transport/bdp_estimator.go`、`http2_client.go`、`http2_server.go`、`defaults.go`、`dialoptions.go` — <https://github.com/grpc/grpc-go>
- nghttp2：`lib/nghttp2_helper.c`、`lib/nghttp2_session.c`、`lib/includes/nghttp2/nghttp2.h` — <https://github.com/nghttp2/nghttp2>
- hyperium/h2：`src/proto/streams/flow_control.rs`、`src/frame/settings.rs` — <https://github.com/hyperium/h2>
- quinn：`quinn-proto/src/config/transport.rs`、`quinn-proto/src/congestion.rs` — <https://github.com/quinn-rs/quinn>
- Go x/net：`http2/config.go`、`http2/transport.go`、`http2/server.go` — <https://github.com/golang/net>
- Go 标准库内嵌 h2：`src/net/http/h2_bundle.go`（release-branch.go1.24）— <https://github.com/golang/go>
- Envoy：`api/envoy/config/cluster/v3/cluster.proto`、`api/envoy/config/core/v3/protocol.proto`、`source/common/http/http2/codec_impl.cc`、`docs/root/faq/configuration/flow_control.rst` — <https://github.com/envoyproxy/envoy>
- HAProxy：`doc/configuration.txt`、`include/haproxy/defaults.h`、`src/cfgparse.c` — <https://github.com/haproxy/haproxy>
- nginx：`src/http/modules/ngx_http_proxy_module.c` — <https://github.com/nginx/nginx>
- Caddy：`modules/caddyhttp/reverseproxy/{reverseproxy,httptransport}.go` — <https://github.com/caddyserver/caddy>
- aria2：`doc/manual-src/en/aria2c.rst` — <https://github.com/aria2/aria2>
- yt-dlp：`yt_dlp/options.py` — <https://github.com/yt-dlp/yt-dlp>
- curl：`docs/cmdline-opts/parallel-max.md` — <https://github.com/curl/curl>
- RFC 8446 §5.1（TLS 1.3 记录上限 16KB）— <https://www.rfc-editor.org/rfc/rfc8446#section-5.1>

**tier2（官方文档 / 配置手册 / 最佳实践）**
- Envoy edge 最佳实践（buffer limit 32KiB 建议）— <https://www.envoyproxy.io/docs/envoy/latest/configuration/best_practices/edge>
- Envoy `Http2ProtocolOptions` API 文档 — <https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/core/v3/protocol.proto>
- nginx `ngx_http_proxy_module` 文档 — <https://nginx.org/en/docs/http/ngx_http_proxy_module.html>
- HAProxy 配置手册（master）— <https://docs.haproxy.org/3.0/configuration.html>
- aria2c 手册 1.37.0 — <https://aria2.github.io/manual/en/html/aria2c.html>

**本仓交叉引用**
- `docs/research/2026-11-09-zct77-h2-rtt-stall-plan.md`（§4.1 窗量级核算、§12 E1/E4 数据、M3/M5/M7 机制表）
- `crates/xray-transport-splithttp/src/h2_params.rs`、`src/transport.rs`
- `crates/xray-frame/src/budget/plan.rs`
- bd `r5j96`（显式 socket 缓冲血案）、`u440m` / D-01（内存账本过订）、`bhneq`（us1 单核 ≈33MB/s 上限）
