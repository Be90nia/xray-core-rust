//! xray-app-reverse crate.
//!
//! 对应 Go `app/reverse/`：portal/bridge 双向反向代理。
//!
//! ## IO 边界
//!
//! - mux/pipe/signal.ActivityTimer：尚未翻译，bridge worker 与 portal worker
//!   的实际数据流通过 trait stub 保留（[`bridge::Bridge`] / [`bridge::Portal`]）
//! - dispatcher / outbound.Manager：上层注入 factory + [`outbound::OutboundRegistrar`]
//!
//! ## 核心业务
//!
//! - [`config::Control`] + [`config::ControlState`]：proto 数据结构 + fill_in_random
//! - [`picker::StaticMuxPicker`]：最少连接选择算法（纯逻辑）
//! - [`worker::portal_heartbeat_decision`]：portal worker heartbeat drain/send 决策（纯逻辑）
//! - [`worker::bridge_worker_is_active`]：bridge worker 活跃状态判断（纯逻辑）
//! - [`reverse::Reverse`]：编排 bridges/portals 的 init/start/close

pub mod bridge;
pub mod config;
pub mod error;
pub mod outbound;
pub mod picker;
pub mod reverse;
pub mod worker;
pub mod relay;
pub use relay::{serve_portal, MuxStream, YamuxBridge};

pub use bridge::{
    is_domain, is_internal_domain, pick_portal_worker, should_create_bridge_worker,
    validate_bridge_config, validate_portal_config, Bridge, BridgeFactory, Portal,
    PortalFactory, SharedBridge, SharedPortal,
};
pub use config::{
    BridgeConfig, Control, ControlState, INTERNAL_DOMAIN, PortalConfig, ReverseConfig,
};
pub use error::{at_error, at_warning, ReverseError};
pub use outbound::{
    OutboundRegistrar, ReverseOutboundHandler, StubOutboundHandler, StubOutboundRegistrar,
};
pub use picker::{PickerWorker, StaticMuxPicker, WorkerSnapshot};
pub use reverse::Reverse;
pub use worker::{
    bridge_worker_is_active, portal_heartbeat_decision, DRAIN_THRESHOLD,
    HeartbeatDecision, HEARTBEAT_COUNTER_MOD, PortalWorkerState,
};
