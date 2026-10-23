//! # xray-frame
//!
//! Xray-core-rust 装配框架层（P0 起步占位）：从 udf-frame 父基座**继承派生**——
//! A 类件直接用（契约词汇/池化/FxScope/logx），B 类继承管理面派生特化面，
//! C 类自有件（plugin/accept/deadline/…）随 P0/P1 落地。
//!
//! 继承派生规划：`docs/architecture/udf-frame继承派生规划-2026-10-23.md`；
//! 实施计划：`docs/architecture/xray-frame-impl-plan-2026-10-19.md`（P0-P4）。
//!
//! 本文件当前只承载**接线冒烟**：证明 udf 依赖面在本仓可解析、继承面编译期
//! 可见。P0 骨架（Plugin trait + Registry + Context + error）随后续派单填充。

/// 契约层词汇直呼（继承面 A 类：`use skeleton::`——包名 udf-skeleton 的 lib 名）。
pub use skeleton::EffectId;

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
