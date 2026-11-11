//! # xray-frame
//!
//! Xray-core-rust 装配框架层（P0 起步占位）：从 udf-frame 父基座**继承派生**——
//! A 类件直接用（契约词汇/池化/FxScope/logx），B 类继承管理面派生特化面，
//! C 类自有件（plugin/accept/deadline/…）随 P0/P1 落地。
//!
//! 继承派生纪律：见 `CLAUDE.md` §3.5（三层定位 + 造件查重 + 派生回路）；
//! 框架规范源：`docs/architecture/xray-frame-强约束插件模型-2026-10-23.md`。
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

// 生产时钟站点逐点 allow + 理由登记（台账见 reports/audit-2026-10-31/dod-fix-D3-D8-docs.md）；
// 单元测试编译单元统一豁免（惯例同 xray-buf/xray-proxy-* lib.rs）；集成测试（tests/）
// 为独立编译单元、cfg_attr(test) 不覆盖，各文件顶显式豁免。
#![cfg_attr(test, allow(clippy::disallowed_methods))]

/// 契约层词汇直呼（继承面 A 类：`use skeleton::`——包名 udf-skeleton 的 lib 名）。
pub use skeleton::EffectId;

// L2 第⑦柄：插件审计事件流（nn8os 2a，底座 udf memgov::BoundedRegistry 有界环）。
pub mod audit;
// P0 骨架七件（2026-10-23 派单）：L1 契约（plugin）+ L5 统一错误（error）+
// L2 能力句柄（context）+ 装配日志唯一入口（logging）+ 插件注册表（registry）+
// 生命周期三相编排（lifecycle）+ 装配组合根（assembly）。
pub mod assembly;
// 进程级能力入口（面 2 · 能力收敛方案 §2 面 2）：ctx 结构性不可达站点的
// 唯一受管入口（CompatCaps + 一次性 install + 兜底 = 迁移前行为）。
pub mod compat;
// P3-2 per-plugin 配置段路由（坑约束 7）：PluginConfig::section 无实例段路由 +
// build_plugins_from_config 配置驱动选择性 build。
pub mod config;
// L4 契约测试夹具（P1-7 A 块）：assert_plugin_contract! 宏 + #[doc(hidden)]
// 最小辅助面；宏经 #[macro_export] 挂根。
pub mod context;
pub mod contract_assert;
// P1 即件：超时唯一入口（坑约束 2）+ 握手/空闲限时（P1-4）+ 预算面
// （面 3：Budget/BudgetDeadline 双源预算句柄，保 tokio 虚拟推进语义）。
pub mod deadline;
// 装配面内存预算登记簿（ADR-B · audit ARCH-07 拆分裁决）：纯常量簿上浮本件；
// 预算门 check_startup_budget（吃 xray_conf::BuiltConfig）留 xray-core
// （xray-conf 已依赖 xray-frame，门上浮即反向成环）。
pub mod budget;
// P3-1 S1 旁路查表面（dispatcher 中央 match 臂退役的查表骨架，契约 §P3-1）。
pub mod dispatch;
pub mod error;
// 派生件 3（bd 9u35o）：热替换快照持有件——`arc-swap` 之上组合包装「无锁读 + 原子整体换
// `Arc`」，供 geoip 注册表（bd hdgz9）与 TLS 证书热重载（bd 5ctu1）共用；udf 无等价件。
pub mod hot_slot;
// smoltcp 用户态 IP 栈机制件（masque B3 净移动，PM 2026-11-11 裁定：移动 +
// re-export，实施计划 §4.2/§5 B3）：IP 包 ↔ TCP/UDP socket 桥，自
// xray-proxy-wireguard/netstack 原样搬入（PacketStack = 原 WgNetStack 仅改名）；
// wireguard 侧与未来 masque 经 re-export 消费（xray-proxy-tun 的同源副本本票未
// 收编，另立 bd 票）。
pub mod ipstack;
pub mod lifecycle;
pub mod logging;
// 网络 socket 机制件（bd vqvn1 NEW-02）：Windows ICMP-unreachable 上报关闭的唯一
// 实现（xray-transport 与 xray-proxy-dns 都转调本件，udf 因方向性不收）。
pub mod net;
// P1 观测字段模板（坑约束 3/10/11 的字段面，P1-5）。
pub mod observe;
pub mod plugin;
pub mod pool;
pub mod registry;
// P1-6 配置热更回滚语义件（Stage/ReloadTx/swap_all + ConfigReloadListener）。
// 本件 Stage 与 observe::Stage 同名不同型：观测枚举挂根，本件的走 reload:: 路径。
pub mod reload;
// 红线受控入口（面 5 · 能力收敛方案 §2 面 5）：红线站点穷举登记 +
// 受控执行入口（spawn_unchecked / event）+ 台账（CI 门核对调用集合）。
pub mod redline;
// 两级 scope 模型（面 6 · 能力收敛方案 §2 面 6）：arm scope → connection
// scope（表达 mux link 的跨连接生命周期）+ 组件自有账本（ADR-0004
// `ComponentScope`：持有者契约唯一落点）。
pub mod scope;
// 派生件 1（bd h4bl5）：serveStale 缓存——udf `std_ext::cache::SyncTtlCache` 之上
// 组合包装「过期保留读 + 同 key 刷新 single-flight」。
pub mod cache;
// 装配状态环（唯一路径）：Reducer/EffectBuf/compose/journal 三族的生产消费点。
pub mod state_loop;
// 派生件 2（bd h4bl5）：UUIDv4 凭据 id 值面——udf `std_ext::id::RandomId`
// 之上组合包装「位面归一化 + 严格 v4 解析」。
pub mod uuid;

pub use assembly::{Framework, FrameworkBuilder, FrameworkOptions};
pub use audit::{AuditHandle, AuditRecord, DEFAULT_AUDIT_RING_CAP};
pub use compat::{CompatAlreadyInstalled, CompatCaps, CompatGuard};
pub use config::{
    ConfigLayerError, MergePolicy, PluginConfig, TagArraySpec, UnmatchedPolicy, XrayConfigLayers,
    build_plugins_from_config, xray_policy,
};
pub use context::{PluginContext, derive_fingerprint};
pub use deadline::{
    Budget, BudgetDeadline, BudgetSource, DEFAULT_LIMIT, HandshakeDeadline, IdleDeadline,
    with_deadline,
};
pub use dispatch::{HandlerCapability, Lookup, lookup};
pub use error::{LifecyclePhase, PluginError};
pub use hot_slot::HotSlot;
pub use lifecycle::{Phase, StartedPlugins, bring_up};
pub use logging::{HotBuf, HotLog, LogFacade, init_from_env};
pub use observe::{ObserveFields, ObserveSink, Stage, emit};
pub use plugin::{ClauseId, Lifecycle, Plugin, PluginContract, PluginDep};
pub use pool::{
    BufferPool, ManagedBufferPool, PoolError, PooledBuffer, SharedPoolRegistry, XrayBufPool,
};
pub use redline::{RedlineSite, SITES};
pub use registry::PluginRegistry;
// reload::Stage 不挂根（与 observe::Stage 撞名），走 xray_frame::reload::Stage。
pub use reload::{
    ConfigChange, ConfigReloadListener, ConfigSource, ReloadError, ReloadTx, Swap, clean, swap_all,
    swap_one,
};
pub use scope::{ArmScope, ArmScopeRegistry, ComponentScope, ConnScope};

#[cfg(test)]
mod wiring_smoke_tests {
    /// A 类直用①：契约层效果句柄可构造（零依赖词汇继承可见）。
    #[test]
    fn udf_contract_vocabulary_inherited() {
        let id = super::EffectId::new(42);
        assert_eq!(id.get(), 42);
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
