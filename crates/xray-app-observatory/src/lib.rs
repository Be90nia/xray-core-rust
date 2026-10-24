#![deny(warnings)]
// 治理红线（bd 75rv ②）：任何 rustc warning 即构建失败；豁免一律显式 allow + 理由
#![cfg_attr(test, allow(clippy::disallowed_methods, clippy::disallowed_macros, clippy::print_stdout, clippy::print_stderr))] // 测试目标统一豁免（print 宏断言 + 测试内裸 spawn 自管 runtime，bd g3cr 家规扩展；生产禁令不受影响）
#![warn(clippy::print_stdout, clippy::print_stderr)]
// 库代码禁直写控制台（诊断走 tracing）；豁免面见各文件 allow 与 clippy.toml 注释
//! xray-app-observatory crate.
//!
//! 对应 Go `app/observatory/`：outbound 健康探测 + 状态快照 + 命令服务。
//!
//! ## IO 边界
//!
//! - HTTP probe + dispatcher dial：[`observer::ProbeExecutor`] trait
//! - outbound.Manager.Select：[`observer::OutboundSelector`] trait
//! - gRPC server：[`command::ObservatoryServiceRegistrar`] trait
//!
//! ## 核心业务
//!
//! - [`status::StatusStore`]：状态集合的更新 + 清理算法（纯逻辑）
//! - [`error_collector::ErrorCollector`]：错误累积
//! - [`burst::HealthPingRtts`]：环形缓冲 + statistics（avg/deviation/min/max）
//! - [`burst::HealthPingSettings`]：默认值校验
//! - [`observer::Observer`]：探测编排

pub mod burst;
pub mod burst_feature;
pub mod command;
pub mod config;
pub mod error;
pub mod error_collector;
pub mod feature;
pub mod observer;
pub mod status;
pub use burst::{
    burst_observer::BurstObserver,
    healthping_settings::{
        DEFAULT_DESTINATION, DEFAULT_HTTP_METHOD, DEFAULT_INTERVAL_NANOS, DEFAULT_SAMPLING_COUNT,
        DEFAULT_TIMEOUT_NANOS, HealthPingConfig, HealthPingSettings, MIN_INTERVAL_NANOS,
    },
    healthping_stats::{HealthPingRtts, HealthPingStats, PingRtt},
};
pub use burst_feature::BurstObservatoryFeature;
pub use command::{
    DefaultObservatoryService, NoopObservatoryServiceRegistrar, ObservationProvider,
    ObservatoryService, ObservatoryServiceDescriptor, ObservatoryServiceRegistrar,
};
pub use config::{
    DEAD_DELAY_MS, DEFAULT_PROBE_INTERVAL_MS, DEFAULT_PROBE_URL, HealthPingMeasurement,
    ObservationResult, ObservatoryConfig, OutboundStatus, ProbeResult,
};
pub use error::{ObservatoryError, at_error, at_warning};
pub use error_collector::ErrorCollector;
pub use feature::ObservatoryFeature;
pub use observer::{
    FixedProbeExecutor, HttpProbeExecutor, NoopOutboundSelector, Observer, OutboundSelector,
    ProbeExecutor, RealOutboundProbeExecutor, RealOutboundSelector, now_unix_secs,
};
