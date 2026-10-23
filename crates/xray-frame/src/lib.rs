//! # xray-frame
//!
//! Xray-core-rust 装配框架层（P0 起步占位）：从 udf-frame 父基座**继承派生**——
//! A 类件直接用（契约词汇/池化/FxScope/logx），B 类继承管理面派生特化面，
//! C 类自有件（plugin/accept/deadline/…）随 P0/P1 落地。
//!
//! 继承派生规划：`docs/architecture/udf-frame继承派生规划-2026-10-23.md`；
//! 实施计划：`docs/architecture/xray-frame-impl-plan-2026-10-19.md`（P0-P4）。
//!
//! 本文件承载**接线冒烟**（udf 依赖面可解析、继承面编译期可见）与 P0 骨架
//! 模块挂载。P0-1..P0-8 均已落（plugin/error/context/logging/registry/lifecycle
//! 及 assembly 装配组合根：register→build(ctx)→bring_up→shutdown 三段式 +
//! P0-8 装配门：deps 拓扑校验、per-plugin ctx 路由、停机超时接线）；
//! P1 通用件已起步：P1-1 pool（缓冲池接缝 + xray-buf 外侧适配 + PoolBase
//! 管理面白拿，分配路径零改动）；P1-4 deadline（超时唯一入口即件 + 握手/
//! 空闲限时配置面）；P1-5 observe（观测字段模板 conn_id/stage/peer/dest
//! 四元组 + Stage 枚举 + 统一落点 emit 挂 P0-7 LogFacade）；P1-6 reload
//! （配置热更回滚语义件 Stage/ReloadTx/swap_all/ConfigReloadListener）。

/// 契约层词汇直呼（继承面 A 类：`use skeleton::`——包名 udf-skeleton 的 lib 名）。
pub use skeleton::EffectId;

// P0 骨架七件（2026-10-23 派单）：L1 契约（plugin）+ L5 统一错误（error）+
// L2 能力句柄（context）+ 装配日志唯一入口（logging）+ 插件注册表（registry）+
// 生命周期三相编排（lifecycle）+ 装配组合根（assembly）。
pub mod assembly;
// P3-2 per-plugin 配置段路由（坑约束 7）：PluginConfig::section 无实例段路由 +
// build_plugins_from_config 配置驱动选择性 build。
pub mod config;
// L4 契约测试夹具（P1-7 A 块）：assert_plugin_contract! 宏 + #[doc(hidden)]
// 最小辅助面；宏经 #[macro_export] 挂根。
pub mod context;
pub mod contract_assert;
// P1 即件：超时唯一入口（坑约束 2）+ 握手/空闲限时（P1-4）。
pub mod deadline;
// P3-1 S1 旁路查表面（dispatcher 中央 match 臂退役的查表骨架，契约 §P3-1）。
pub mod dispatch;
pub mod error;
pub mod lifecycle;
pub mod logging;
// P1 观测字段模板（坑约束 3/10/11 的字段面，P1-5）。
pub mod observe;
pub mod plugin;
pub mod pool;
pub mod registry;
// P1-6 配置热更回滚语义件（Stage/ReloadTx/swap_all + ConfigReloadListener）。
// 本件 Stage 与 observe::Stage 同名不同型：观测枚举挂根，本件的走 reload:: 路径。
pub mod reload;

pub use assembly::{Framework, FrameworkBuilder, FrameworkOptions};
pub use config::{PluginConfig, build_plugins_from_config};
pub use context::{PluginContext, derive_fingerprint};
pub use deadline::{DEFAULT_LIMIT, HandshakeDeadline, IdleDeadline, with_deadline};
pub use dispatch::{HandlerCapability, Lookup, lookup};
pub use error::{LifecyclePhase, PluginError};
pub use lifecycle::{Phase, StartedPlugins, bring_up};
pub use logging::{LogFacade, init_from_env};
pub use observe::{ObserveFields, ObserveSink, Stage, emit};
pub use plugin::{ClauseId, Lifecycle, Plugin, PluginContract, PluginDep};
pub use pool::{BufferPool, ManagedBufferPool, PoolError, PooledBuffer, XrayBufPool};
pub use registry::PluginRegistry;
// reload::Stage 不挂根（与 observe::Stage 撞名），走 xray_frame::reload::Stage。
pub use reload::{
    ConfigChange, ConfigReloadListener, ConfigSource, ReloadError, ReloadTx, Swap, clean, swap_all,
    swap_one,
};

#[cfg(test)]
mod wiring_smoke_tests {
    /// A 类直用①：契约层效果句柄可构造（零依赖词汇继承可见）。
    #[test]
    fn udf_contract_vocabulary_inherited() {
        let id = super::EffectId(42);
        assert_eq!(id.0, 42);
    }

    /// A 类直用②：池化契约（skeleton::pool::PoolManaged，零依赖）+ udf 随附
    /// 实现（skeleton_infra::pool::ThreadPool，pool feature 默认开）——
    /// xray-frame 侧池化派生（BufferPool 接缝）落在此继承面上。
    #[test]
    fn udf_pool_contract_and_impl_inherited() {
        fn assert_pool_managed<T: skeleton::pool::PoolManaged>() {}
        assert_pool_managed::<skeleton_infra::pool::ThreadPool>();
    }

    /// A 类直用③：FxScope 托管口（tokio feature）类型可见——插件异步任务
    /// 唯一托管口的继承面。
    #[test]
    fn udf_fxscope_type_inherited() {
        let _scope = skeleton_infra::fx::FxScope::new();
    }

    /// A 类直用④：logx 门面绑定层（log feature）可达——"log 嵌入流程"的
    /// 继承面（装配层日志唯一入口）。不真初始化全局订阅者（单例污染其他
    /// 测试）；用绑定层错误类型证明 feature 编进依赖树。
    #[test]
    fn udf_logx_facade_inherited() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<skeleton_infra::logx::LogInitError>();
    }
}
