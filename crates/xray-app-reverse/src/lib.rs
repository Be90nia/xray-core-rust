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
// 测试目标统一豁免（print 宏断言便利，bd g3cr 家规扩展）；spawn 走 xray_common::testing
// （L3 闸不豁免），生产禁令不受影响
#![warn(clippy::print_stdout, clippy::print_stderr)]
// 库代码禁直写控制台（诊断走 tracing）；豁免面见各文件 allow 与 clippy.toml 注释
//! xray-app-reverse crate.
//!
//! 对应 Go `app/reverse/`：portal/bridge 双向反向代理。
//!
//! ## 结构
//!
//! - [`config::Control`] + [`config::ControlState`]：proto 数据结构 + fill_in_random
//! - [`picker::StaticMuxPicker`]：最少连接选择算法
//! - [`worker::portal_heartbeat_decision`] / [`worker::bridge_worker_is_active`]：纯决策
//! - [`worker::PortalWorker`] / [`worker::BridgeWorker`]：IO 实体 （pipe 16KiB + mux
//!   ClientWorker/ServerWorker + InactivityTimer + Control proto）
//! - [`bridge::RuntimeBridge`] / [`bridge::RuntimePortal`]：monitor/outbound 编排
//! - [`outbound::PortalOutbound`]：注册进 outbound manager 的 portal 出站 handler
//! - [`reverse::ReverseFeature`]：`xray_features::Feature` 适配（编排 + 特性注册）
//! - [`timer::InactivityTimer`]：Go `signal.CancelAfterInactivity` 等价 （含 `SetTimeout`
//!   语义；xray_common 版无 set_timeout/terminate 回调）

// async-trait 展开对 trait 脱糖方法加 #[must_use]（其 expand.rs:69），clippy 1.99 起
// 将 Pin<Box<dyn Future>> 判为已 must_use → double_must_use 误报；宏行为非本 crate 可控。
#![allow(clippy::double_must_use)]

pub mod bridge;
pub mod config;
pub mod error;
pub mod outbound;
pub mod picker;
pub mod relay;
pub mod reverse;
pub mod timer;
pub mod worker;
pub use bridge::{
    BRIDGE_MONITOR_INTERVAL, Bridge, BridgeFactory, DefaultDispatcherAdapter, LinkDispatch,
    PICKER_CLEANUP_INTERVAL, Portal, PortalFactory, RuntimeBridge, RuntimePortal, SharedBridge,
    SharedPortal, is_domain, is_internal_domain, pick_portal_worker, should_create_bridge_worker,
    validate_bridge_config, validate_portal_config,
};
pub use config::{
    BridgeConfig, Control, ControlState, INTERNAL_DOMAIN, PortalConfig, ReverseConfig,
};
pub use error::{ReverseError, at_error, at_warning};
pub use outbound::{OutboundRegistrar, PortalOutbound, SimpleOhmRegistrar, StubOutboundRegistrar};
pub use picker::{PickerWorker, StaticMuxPicker, WorkerSnapshot};
pub use relay::{MuxStream, YamuxBridge, serve_portal};
pub use reverse::{
    Reverse, ReverseDeps, ReverseFeature, RuntimeBridgeFactory, RuntimePortalFactory,
};
pub use timer::InactivityTimer;
pub use worker::{
    BRIDGE_DRAIN_WINDOW, BRIDGE_IDLE_TIMEOUT, BridgeWorker, DRAIN_THRESHOLD, HEARTBEAT_COUNTER_MOD,
    HeartbeatDecision, PORTAL_HEARTBEAT_INTERVAL, PORTAL_IDLE_TIMEOUT, PortalWorker,
    PortalWorkerState, bridge_worker_is_active, internal_control_destination,
    portal_heartbeat_decision,
};
