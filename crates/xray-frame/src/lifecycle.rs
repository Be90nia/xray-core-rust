//! 生命周期编排的**薄转发层**：唯一实现在 [`crate::state_loop`]。
//!
//! 本文件不再持有第二份账本 / 第二份顺序逻辑——`bring_up` 只把调用方的
//! `impl Fn` ctx 工厂包成状态环的 [`CtxFactory`] 再直转，`Phase` /
//! `StartedPlugins` 原样 re-export。既有 `use xray_frame::lifecycle::bring_up`
//! 的调用方零改动。
//!
//! 编排语义（逐插件 init→start 交替、失败逆序回滚、stop 闭包按逆启动序注册进
//! [`ShutdownCoordinator`]、panic 装甲）全在 `state_loop` 侧：本层零语义。

use std::sync::Arc;

use skeleton_infra::shutdown::ShutdownCoordinator;

pub use crate::state_loop::{Phase, StartedPlugins};
use crate::{
    context::PluginContext, error::PluginError, plugin::Plugin, registry::PluginRegistry,
    state_loop::CtxFactory,
};

/// 启动编排（薄转发）：`impl Fn` 工厂 → 状态环的 [`CtxFactory`] 视图。
pub fn bring_up(
    registry: &PluginRegistry,
    ctx_factory: impl Fn(&Arc<dyn Plugin>) -> Result<PluginContext, PluginError> + Send + Sync + 'static,
    coordinator: Arc<ShutdownCoordinator>,
) -> Result<StartedPlugins, PluginError> {
    let factory: CtxFactory = Arc::new(ctx_factory);
    crate::state_loop::bring_up(registry, factory, coordinator)
}
