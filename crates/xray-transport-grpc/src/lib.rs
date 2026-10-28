#![deny(warnings)]
// 治理红线（bd 75rv ②）：任何 rustc warning 即构建失败；豁免一律显式 allow + 理由
#![cfg_attr(
    test,
    allow(
        clippy::disallowed_macros,
        clippy::disallowed_methods,
        clippy::print_stdout,
        clippy::print_stderr
    )
)]
// 测试目标统一豁免（print 宏断言便利 + 测试计时夹具裸时钟不得改语义），生产禁令不受影响
#![warn(clippy::print_stdout, clippy::print_stderr)]
// 库代码禁直写控制台（诊断走 tracing）；豁免面见各文件 allow 与 clippy.toml 注释
//! # xray-transport-grpc
//!
//! gRPC 传输协议——基于 HTTP/2 + protobuf framing 的双向 stream。
//! 对应 Go `transport/internet/grpc/`。
//!
//! ## 协议本质
//!
//! gRPC 走 HTTP/2 多路复用 stream，每个 TCP 连接可承载多个 gRPC stream，
//! Xray 利用此特性实现 multi_mode（每连接多 stream 提升吞吐）。底层
//! 用 google.golang.org/grpc 标准库的 Tun/TunMulti 服务，把 net.Conn 适配为
//! gRPC 双向 stream。
//!
//! ## 切片边界（P5-4 切片1）
//!
//! 切片1 已交付配置层：[`config::Config`] 8 字段 + `service_name`/
//! `tun_stream_name`/`tun_multi_stream_name` 解析 + prost proto 双向转换。
//!
//! ## 切片2（dcs）
//!
//! 实现协议核心层（不引入 tonic/h2 重依赖）：
//! - [`encoding`] — gRPC wire framing + [`encoding::Hunk`] proto 手动编解码 +
//!   [`encoding::HunkStream`] trait 抽象（由调用方注入 h2/hyper 传输）+
//!   [`encoding::HunkReaderWriter`] 适配 [`xray_buf::io::Reader`]/[`xray_buf::io::Writer`]
//! - [`client`] — [`client::GrpcClient`] 把已建立的 HunkStream 包成 `transport::Link`
//! - [`server`] — [`server::GrpcServer`] 处理 inbound HunkStream + 路由匹配
//!
//! 实际 HTTP/2 + TLS 拨号/监听留 follow-up（依赖 tonic/h2 决策，由
//! `k9t reality-s2` 等 TLS 切片解锁后统一接入）。
/// T3.2a 日志统一入口：域规范 target = `xray_frame::transport::grpc`（热路径豁免清单见
/// reports/framework-audit-2026-10-24/T3.2a-log-transport-cli.md）。
pub(crate) static LOG: std::sync::LazyLock<xray_frame::logging::LogFacade> =
    std::sync::LazyLock::new(|| xray_frame::logging::LogFacade::new("transport::grpc", vec![]));

pub mod client;
pub mod config;
pub mod encoding;
pub mod error;
pub mod server;
pub mod transport;

#[cfg(feature = "register")]
pub mod register;

// 顶层 re-export。
pub use config::Config;
pub use encoding::CompressionEncoding;
pub use error::{GrpcError, Result};
#[cfg(all(feature = "register", not(unix)))]
pub use register::{register_dialer, register_listener};
#[cfg(all(feature = "register", unix))]
pub use register::{register_dialer, register_listener, register_unix_listener};
