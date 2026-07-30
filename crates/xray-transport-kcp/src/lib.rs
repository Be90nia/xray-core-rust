//! `xray-transport-kcp` — mKCP 传输协议（Go `transport/internet/kcp`）。
//!
//! # 当前实现范围
//!
//! 业务核心 1:1 翻译自 Go `transport/internet/kcp/`，所有逻辑独立可测：
//!
//! - **Segment 协议**（[`segment`]）：`DataSegment` / `AckSegment` / `CmdOnlySegment`
//!   的二进制 serialize/parse，与 xray Go 端字节级兼容。
//! - **State 状态机**（[`state`]）：6 态 `Active / ReadyToClose / PeerClosed /
//!   Terminating / PeerTerminated / Terminated` + `Is(...)` 谓词。
//! - **RoundTripInfo**（[`round_trip`]）：RFC 6298 RTT 估算（SRTT + RTTVAR + RTO）。
//! - **Config**（[`config`]）：包裹 prost 生成的 `Config`，提供 `GetSendingInFlightSize`
//!   等派生计算 + 默认配置。
//! - **SendingWorker / SendingWindow**（[`sending`]）：发送窗口、ACK 处理、丢包调整。
//! - **ReceivingWorker / ReceivingWindow / AckList**（[`receiving`]）：接收窗口、
//!   ACK 列表合并刷新。
//! - **Connection**（[`connection`]）：核心连接对象，编排 workers + state + RTT。
//! - **Output**（[`output`]）：`SegmentWriter` trait + `SimpleSegmentWriter`（buffered）
//!   + `RetryableWriter`（5 次 100ms 间隔重试）。
//! - **IO**（[`io`]）：`PacketReader` trait + `KCPPacketReader`。
//!
//! # IO 边界（trait + stub）
//!
//! 以下依赖外部资源，留 trait + 默认 stub 实现，等上层接入：
//!
//! - **Dialer**（[`dialer`]）：`KcpDialerFactory` trait。Go `DialKCP` 依赖
//!   `internet.DialSystem`（实际 UDP 连接）+ `tls.Client`（TLS 包装）+
//!   `UdpmaskManager`（UDP masking）。当前仅定义 trait + 编排框架（构造 Connection
//!   + spawn 输入循环 + 可选 TLS 套壳），实际 UDP/TLS/Udpmask 留待上层注入。
//! - **Listener**（[`listener`]）：`KcpListenerFactory` trait。Go `Listener` 依赖
//!   `udp.Hub`（UDP 包接收循环）+ `tls.Server` + `internet.ConnHandler`。当前仅
//!   定义 trait + 编排框架（sessions map + OnReceive + Remove），实际 UDP socket
//!   bind + 接收循环留待上层注入。
//!
//! # 不引入 `kcp-tokio` 等通用 KCP crate
//!
//! xray mKCP 是 **skywind3000 KCP 协议的 xtaci Go 端口的 xray 定制版**：
//!
//! - 自定义 Segment 二进制格式（DataSegment: 18B overhead + payload；
//!   AckSegment: 17B + N×4B；CmdOnlySegment: 16B 固定）
//! - 自定义 6 态 State 状态机（标准 KCP 只有 3 态）
//! - 自定义 RoundTripInfo（RFC 6298，含 minRtt 钳制 + maxRto 10000）
//! - 自定义 Updater（基于 signal.Notifier 的 wakeup 机制，非 tick-only）
//!
//! 通用 KCP crate（`kcp`、`kcp-tokio`、`tokio-kcp`）使用标准 KCP 协议格式，
//! 与 xray Go 端**字节级不兼容**——若用现成 crate 等于放弃与 xray Go 互通。
//! 因此 1:1 翻译 Go 源码，与 `docs/translation-conventions.md` §0「源码 1:1
//! 映射」原则一致。

pub mod config;
pub mod connection;
pub mod dialer;
pub mod error;
pub mod io;
pub mod listener;
pub mod output;
pub mod receiving;
pub mod round_trip;
pub mod segment;
pub mod sending;
pub mod state;
pub mod updater;
pub mod udp_hub;
pub mod register;

/// 协议名（对应 Go `ProtocolName = "mkcp"`）。
pub const PROTOCOL_NAME: &str = "mkcp";

pub use config::{Config, ConfigExt, default_config};
pub use connection::{Connection, ConnectionCloser, ConnMetadata, NoopCloser};
pub use dialer::{KcpDialerFactory, PacketInput, fetch_input, init_global_conv, next_conv};
pub use error::{KcpError, Result};
pub use io::{KCPPacketReader, PacketReader};
pub use listener::{ConnHandler, ConnectionId, Listener, ListenerWriter, UdpHub};
pub use output::{RetryableWriter, SegmentWriter, SimpleSegmentWriter, UnderlyingWriter};
pub use round_trip::RoundTripInfo;
pub use segment::{
    AckSegment, CmdOnlySegment, Command, DataSegment, DATA_SEGMENT_OVERHEAD, Segment,
    SegmentKind, SegmentOption, read_segment,
};
pub use state::{State, STATE_ACTIVE};
pub use updater::{NoopUpdater, TokioUpdater, Updater};
pub use udp_hub::{StdPacketInput, StdUdpHub};

pub use register::register_listener;
