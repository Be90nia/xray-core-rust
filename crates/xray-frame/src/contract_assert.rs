//! L4 契约测试夹具（模型 §2.2 L4 行）：宏
//! [`assert_plugin_contract`](crate::assert_plugin_contract)
//! （`#[macro_export]` 挂根）。
//!
//! 每协议 crate 的集成测试必须调用本宏（缺 = CI 红，规范源 §2.2 L4）。
//! 逐条断言：
//! ① 必选方法集可调——name 非空且稳定（两次调用一致）、version 非空、
//!    deps/contract 可调；
//! ② `clauses` 与 `not_applicable` 不得重叠、N/A 理由非空（P1-7 拍板 P2.2：
//!    允许声明 N/A 但必须有理由字段）；
//! ③ `extra` 键值非空；
//! ④ lifecycle 三相可调且不 panic（`Err` 同样视为失败上抛）。
//!
//! 宏体走 `#[doc(hidden)]` 辅助面（[`assert_contract_for`] /
//! [`contract_test_context`]）——从外部 crate 的集成测试可直接调用，最小暴露。
//! 注意：④ 在非 async 上下文调用 lifecycle；start 内需要 spawn 托管任务的
//! 插件应在 tokio runtime 内调用本宏。

use std::sync::Arc;

use skeleton::{clock::SystemClock, config::StdEnv};
use skeleton_infra::fx::FxScope;

use crate::{
    context::{PluginContext, derive_fingerprint},
    logging::LogFacade,
    plugin::{Plugin, PluginContract},
};

/// 宏辅助：构造 lifecycle 三相调用可用的最小 [`PluginContext`]（空配置根——
/// 三相本体契约上不消费段数据；段路由/配置解析走 build 期，不在此覆盖）。
#[doc(hidden)]
pub fn contract_test_context(plugin_name: &'static str) -> PluginContext {
    PluginContext::new(
        plugin_name,
        Arc::new(FxScope::new()),
        Arc::new(SystemClock),
        derive_fingerprint(None),
        Arc::new(StdEnv),
        serde_json::json!({}),
        LogFacade::new(plugin_name, vec![]),
    )
}

/// 宏辅助：对插件实例执行契约断言（条款面 + lifecycle 三相）。
/// 断言失败 = panic，消息带 `[contract:<类型>]` 前缀可定位。
#[doc(hidden)]
pub fn assert_contract_for<P: Plugin>(plugin: &P, type_name: &str) {
    // ① 必选方法集可调；name 非空且稳定；version 非空。
    let name = plugin.name();
    assert!(!name.is_empty(), "[contract:{type_name}] name() 为空");
    assert_eq!(plugin.name(), name, "[contract:{type_name}] name() 不稳定（两次调用不同）");
    assert!(!plugin.version().is_empty(), "[contract:{type_name}] version() 为空");
    let _ = plugin.deps();
    let contract: &PluginContract = plugin.contract();

    // ② clauses 与 not_applicable 不得重叠；N/A 理由非空。
    for (clause, reason) in contract.not_applicable {
        assert!(
            !reason.trim().is_empty(),
            "[contract:{type_name}] 条款 {clause:?} 声明 N/A 但理由为空"
        );
        assert!(
            !contract.clauses.contains(clause),
            "[contract:{type_name}] 条款 {clause:?} 同时出现在 clauses 与 not_applicable"
        );
    }

    // ③ extra 键值非空。
    for (key, desc) in contract.extra {
        assert!(
            !key.is_empty() && !desc.is_empty(),
            "[contract:{type_name}] extra 条款键或值为空: ({key:?}, {desc:?})"
        );
    }

    // ④ lifecycle 三相可调且不 panic（Err 升级为 panic，fail-visible）。
    let lifecycle = plugin.lifecycle();
    let ctx = contract_test_context(name);
    lifecycle
        .init(&ctx)
        .unwrap_or_else(|e| panic!("[contract:{type_name}] lifecycle init 失败: {e}"));
    lifecycle
        .start(&ctx)
        .unwrap_or_else(|e| panic!("[contract:{type_name}] lifecycle start 失败: {e}"));
    lifecycle.stop().unwrap_or_else(|e| panic!("[contract:{type_name}] lifecycle stop 失败: {e}"));
}

/// L4 契约测试夹具：对插件类型执行全量契约断言（①-④，见
/// [`crate::contract_assert`] 模块文档）。
///
/// 插件类型须实现 `Default`（夹具自行构造实例）。
///
/// ```ignore
/// // 每协议 crate 的 tests/plugin_contract.rs：
/// use xray_proxy_blackhole::BlackholePlugin;
/// use xray_frame::assert_plugin_contract;
///
/// #[test]
/// fn plugin_contract_holds() {
///     assert_plugin_contract!(BlackholePlugin);
/// }
/// ```
#[macro_export]
macro_rules! assert_plugin_contract {
    ($plugin:ty) => {{
        let plugin = <$plugin as ::std::default::Default>::default();
        $crate::contract_assert::assert_contract_for(&plugin, ::std::any::type_name::<$plugin>());
    }};
}
