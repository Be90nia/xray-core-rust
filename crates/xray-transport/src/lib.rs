#![deny(warnings)]
// 治理红线（bd 75rv ②）：任何 rustc warning 即构建失败；豁免一律显式 allow + 理由
#![cfg_attr(test, allow(clippy::disallowed_macros, clippy::print_stdout, clippy::print_stderr))] // 测试目标统一豁免（print 宏断言便利），生产禁令不受影响
#![warn(clippy::print_stdout, clippy::print_stderr)]
// 库代码禁直写控制台（诊断走 tracing）；豁免面见各文件 allow 与 clippy.toml 注释
//! # xray-transport
//!
//! 传输层 IO 边界抽象。提供 `Link` / `Connection` / `Listener` / `Dialer` 核心
//! trait 及参考 TCP 实现，供下游 crate （Phase 4+ dispatcher/dns/router 等）
//! 引用类型边界。
//!
//! ## 本 crate 范围（ponytail 最小骨架）
//! - `link::Link` — inbound→outbound 字节流桥，组装 `Reader` + `Writer`
//! - `connection::Connection` trait + `TcpConnection` 参考实现
//! - `listener::Listener` trait + `TcpListenerConn` 参考实现
//! - `dialer::Dialer` trait（仅声明，无实现）
//! - `stat::CounterConnection` 字节计数包装器

//! ## 未实现（留 stub）
//! `sockopt` / `tcp` / `udp` / `headers` / `finalmask` / `pipe` / `config` /
//! `filelocker` / `browser_dialer` / `tagged` / `memory_settings`
//! 这些模块依赖 Phase 4+ 未就绪的 `outbound.Manager` / `session.Outbound` /
//! `policy.BufferPolicyFromContext` / 平台特定 syscall，留待具体传输实现 crate 处理。
//!
//! 参考：Go 版本位于 `E:\Projcet\Xray-core\transport\`。

// async-trait 展开对 trait 脱糖方法加 #[must_use]（其 expand.rs:69），clippy 1.99 起
// 将 Pin<Box<dyn Future>> 判为已 must_use → double_must_use 误报；宏行为非本 crate 可控。
#![allow(clippy::double_must_use)]

/// T3.2a 日志统一入口：域规范 target = `xray_frame::transport`（热路径豁免清单见
/// reports/framework-audit-2026-10-24/T3.2a-log-transport-cli.md）。
pub(crate) static LOG: std::sync::LazyLock<xray_frame::logging::LogFacade> =
    std::sync::LazyLock::new(|| xray_frame::logging::LogFacade::new("transport", vec![]));

/// 面 4 热路径日志门面（能力收敛方案 §2 面 4）：栈缓冲零分配，先过滤后格式化
/// ——级别未命中时零格式化零堆分配。显式级别判定（订阅者兴趣），禁 env 存在性
/// 开关（P7LM 教训：env 存在即生效的假开关）。
pub(crate) static HOT_LOG: xray_frame::logging::HotLog =
    xray_frame::logging::HotLog::with_target("xray_frame::transport");

/// 热路径日志宏：DEBUG 走 [`xray_frame::logging::HotLog::debug_fmt`]（内部栈
/// 缓冲）；其余级别经 [`xray_frame::logging::HotBuf`] 栈缓冲发射。字段以
/// key=value 拼入 message（与 LOG 慢路径既有风格一致）。
macro_rules! hot_log {
    (DEBUG, $($arg:tt)*) => {
        crate::HOT_LOG.debug_fmt(format_args!($($arg)*))
    };
    ($level:expr, $($arg:tt)*) => {
        if crate::HOT_LOG.enabled($level) {
            let mut buf = xray_frame::logging::HotBuf::<256>::new();
            buf.write_fmt(format_args!($($arg)*));
            crate::HOT_LOG.log($level, &buf);
        }
    };
}
pub(crate) use hot_log;

pub mod accept_policy;
pub mod bridge;
pub mod cnc;
pub mod connection;
pub mod dialer;
pub mod dns_skip;
pub mod fallback;
pub mod link;
pub mod listener;
pub mod listener_registry;
pub mod retry;
pub mod splice;
pub mod stat;
pub mod system_dialer;
pub mod system_listener;

// 以下模块依赖 Phase 4+ 才会出现的 features（dns/outbound/policy 等），当前为 stub。
#[cfg(feature = "browser-dialer")]
pub mod browser_dialer;
pub mod config;
pub mod filelocker;
pub mod finalmask;
pub mod happy_eyeballs;
pub mod headers;
pub mod memory_settings;
pub mod pipe;
pub mod proxy_protocol;
pub mod record_framer;
pub mod sockopt;
pub mod tagged;
pub mod tcp;
pub mod udp;
// 顶层 re-export。
pub use bridge::{bridge_connections, bridge_connections_with_splice, copy_one_way};
pub use proxy_protocol::{build_proxy_header, read_proxy_protocol};
/// Re-exported so proxy crates can inspect negotiated TLS parameters (e.g.
/// `ServerConnection::protocol_version` for VLESS XRV outer-TLS1.3 gating)
/// without a direct `rustls` dependency.
pub use rustls;
/// TLS acceptor for inbound connections.
/// Re-exported so proxy crates don't need a direct `tokio-rustls` dependency.
pub use tokio_rustls::TlsAcceptor;
