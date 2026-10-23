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
//! 模块挂载。P0-1/2/3/7 已落（plugin/error/context/logging/registry）；
//! lifecycle 编排、assembly、shutdown 随 P0-4/5/8 派单填充。

/// 契约层词汇直呼（继承面 A 类：`use skeleton::`——包名 udf-skeleton 的 lib 名）。
pub use skeleton::EffectId;

// P0 骨架五件（2026-10-23 派单）：L1 契约（plugin）+ L5 统一错误（error）+
// L2 能力句柄（context）+ 装配日志唯一入口（logging）+ 插件注册表（registry）。
pub mod context;
pub mod error;
pub mod logging;
pub mod plugin;
pub mod registry;

pub use context::{PluginContext, derive_fingerprint};
pub use error::{LifecyclePhase, PluginError};
pub use logging::{LogFacade, init_from_env};
pub use plugin::{ClauseId, Lifecycle, Plugin, PluginContract, PluginDep};
pub use registry::PluginRegistry;

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
