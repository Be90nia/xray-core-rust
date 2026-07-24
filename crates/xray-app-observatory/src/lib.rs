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
pub mod command;
pub mod config;
pub mod error;
pub mod error_collector;
pub mod observer;
pub mod status;

pub use burst::{
    healthping_settings::{HealthPingConfig, HealthPingSettings},
    healthping_stats::{HealthPingRtts, HealthPingStats, PingRtt},
    is_valid_rtt, RTT_FAILED, RTT_UNQUALIFIED, RTT_UNTESTED,
};
pub use command::{
    DefaultObservatoryService, NoopObservatoryServiceRegistrar, ObservationProvider,
    ObservatoryService, ObservatoryServiceDescriptor, ObservatoryServiceRegistrar,
};
pub use config::{
    DEAD_DELAY_MS, DEFAULT_PROBE_INTERVAL_MS, DEFAULT_PROBE_URL, HealthPingMeasurement,
    ObservationResult, ObservatoryConfig, OutboundStatus, ProbeResult,
};
pub use error::{at_error, at_warning, ObservatoryError};
pub use error_collector::ErrorCollector;
pub use observer::{
    FixedProbeExecutor, HttpProbeExecutor, NoopOutboundSelector, Observer,
    OutboundSelector, ProbeExecutor, RealOutboundSelector, now_unix_secs,
};
pub use status::StatusStore;
