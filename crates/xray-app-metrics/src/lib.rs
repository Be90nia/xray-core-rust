#![deny(warnings)]
// 治理红线（bd 75rv ②）：任何 rustc warning 即构建失败；豁免一律显式 allow + 理由
#![cfg_attr(
    test,
    allow(
        clippy::disallowed_methods,
        clippy::disallowed_macros,
        clippy::print_stdout,
        clippy::print_stderr
    )
)]
// 测试目标统一豁免（print 宏断言 + 测试内裸 spawn 自管 runtime，bd g3cr
// 家规扩展；生产禁令不受影响）
#![warn(clippy::print_stdout, clippy::print_stderr)]
// 库代码禁直写控制台（诊断走 tracing）；豁免面见各文件 allow 与 clippy.toml 注释
//! xray-app-metrics crate。
//!
//! 对应 Go `app/metrics/`：暴露 metrics HTTP 流量路由的 outbound handler + listener，
//! 以及把 stats / observatory 数据导出为 HTTP 接口的注入 trait。
//!
//! ## IO 边界
//!
//! 以下行为通过 trait 注入实现，本 crate 不绑定具体 HTTP/gRPC/RPC 栈：
//! - TCP 监听 + http.Serve：[`MetricsHttpServer`] trait
//! - expvar.Publish("stats") / expvar.Publish("observatory")：通过 [`StatsCollector`] /
//!   [`ObservationCollector`] 暴露快照数据
//! - outbound.Manager.AddHandler/RemoveHandler：[`OutboundRegistrar`] trait
//! - transport.Link → Conn 的转换：上层负责构造 `BoxedConn` 投递到 `Outbound::dispatch`
//!
//! ## 配套 proto
//!
//! `xray.app.metrics.Config { string tag = 1; string listen = 2; }`
//! 在 Rust 端由 [`MetricsConfig`] 承载，`from_proto` / `to_proto` 提供 prost 互转。

pub mod config;
pub mod debug;
pub mod error;
pub mod feature;
pub mod metrics;
pub mod outbound;

pub use config::MetricsConfig;
pub use error::{MetricsError, at_error, at_warning};
pub use feature::MetricsFeature;
pub use metrics::{
    MetricsHandler, MetricsHttpServer, NoopHttpServer, ObservationCollector, ObservationEntry,
    ObservationSnapshot, OutboundRegistrar, RecordingOutboundRegistrar, StatsCollector,
    StatsSnapshot, TokioHttpServer, TrafficCount, aggregate_counters, format_prometheus,
    parse_counter_name,
};
