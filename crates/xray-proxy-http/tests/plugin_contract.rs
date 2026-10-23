//! P2 批次 B 验收：L4 契约夹具（通用 8 条适用 + 3 条 N/A + HTTP-H2W 协议专属）
//! + 装配链 register → build → bring_up → shutdown（`is_clean()`）。
//!
//! （注册不进 xray-frame——xray-frame 禁依赖协议 crate，拍板 P2.1；同
//! blackhole P1-7 / socks P2-A 的做法，注册写在协议 crate 自己的装配链里。）

use std::sync::Arc;

use serde_json::json;
use xray_features::inbound::InboundHandler;
use xray_frame::{
    ClauseId, Plugin, PluginDep, PluginError,
    assembly::{Framework, FrameworkOptions},
    assert_plugin_contract,
};
use xray_proxy_http::{HttpPlugin, ServerConfig};

fn framework_options() -> FrameworkOptions {
    FrameworkOptions { registry_cap: 8, id_fingerprint: Some(1), shutdown_timeout: None }
}

/// 段形态：inbounds[] 按 protocol 路由（坑约束 7；http 生产形态是入站，
/// 段路由的 inbounds[] 半边在此被真实覆盖）。
fn http_section_config(settings: serde_json::Value) -> serde_json::Value {
    json!({ "inbounds": [
        { "protocol": "http", "tag": "http-in", "settings": settings }
    ] })
}

#[test]
fn contract_macro_holds_for_http() {
    assert_plugin_contract!(HttpPlugin);
}

/// 契约面内容断言：差异表 §2.2 第 6 行——8 条适用、2/4/11 走 N/A（理由非空）、
/// HTTP-H2W 协议专属（h2 窗钉不得改回默认 400KB）。
#[test]
fn contract_surface_declares_subset_na_and_extra() {
    let plugin = HttpPlugin::default();
    let contract = plugin.contract();

    assert_eq!(plugin.name(), "http");
    assert_eq!(plugin.version(), "0.1.0");
    let deps: &[PluginDep] = plugin.deps();
    assert!(deps.is_empty(), "http 无依赖插件");

    let expected: &[ClauseId] = &[
        ClauseId::ConnIdPresent,
        ClauseId::SpawnManaged,
        ClauseId::StopRegistered,
        ClauseId::ConfigSectionOnly,
        ClauseId::ErrorClassifiedNoPanicEscape,
        ClauseId::BoundedResources,
        ClauseId::LogDiscipline,
        ClauseId::HotPathFreeze,
    ];
    assert_eq!(contract.clauses.len(), expected.len(), "http 适用 8 条（差异表 §2.2 第 6 行）");
    for clause in expected {
        assert!(contract.clauses.contains(clause), "缺条款 {clause:?}");
    }

    let na: &[ClauseId] =
        &[ClauseId::HandshakeDeadline, ClauseId::PoolDiscipline, ClauseId::SecretMasking];
    assert_eq!(contract.not_applicable.len(), na.len(), "http 声明 3 条 N/A");
    for clause in na {
        let reason = contract
            .not_applicable
            .iter()
            .find(|(id, _)| id == clause)
            .map(|(_, reason)| *reason)
            .unwrap_or_else(|| panic!("缺 N/A 声明 {clause:?}"));
        assert!(!reason.trim().is_empty(), "N/A {clause:?} 理由不得为空");
        assert!(!contract.clauses.contains(clause), "{clause:?} 不得同时出现在 clauses");
    }

    assert_eq!(
        contract.extra,
        &[("HTTP-H2W", "h2 客户端流窗 16MB + 服务端 send_buf 16MB 不得改回默认 400KB")],
        "协议专属条款 HTTP-H2W"
    );
}

/// 完整装配链：段路由解析 → bring_up 三相 → 停机报告干净；
/// build 产物逐字段核对（users/allowTransparent/userLevel）。
#[tokio::test]
async fn http_assembles_bring_up_and_shuts_down_clean() {
    let plugin = Arc::new(HttpPlugin::default());
    let mut framework = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(http_section_config(json!({
            "users": [{ "user": "alice", "pass": "p1" }],
            "allowTransparent": true,
            "userLevel": 2
        })))
        .register(Arc::clone(&plugin) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect("build phase");
    assert!(!framework.is_running(), "build 成功但未 bring_up，不得误报运行态");

    framework.bring_up().expect("bring_up: init/start 三相");
    assert!(framework.is_running());

    let report = framework.shutdown().await;
    assert!(report.is_clean(), "健康链停机报告必须干净");

    let expected = ServerConfig {
        accounts: [("alice".to_string(), "p1".to_string())].into_iter().collect(),
        allow_transparent: true,
        user_level: 2,
    };
    assert_eq!(plugin.built_config().expect("built"), &expected);
}

/// L5 装配门负向：缺段 fail-fast（坑约束 7 装配半边），
/// build 失败 → 无 Framework 产出（无半启动态）。
#[tokio::test]
async fn missing_section_fails_fast_at_build() {
    let err = Framework::builder(framework_options())
        .expect("registry cap")
        .register(Arc::new(HttpPlugin::default()) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect_err("config 根无 http 段必须 fail-fast");
    assert!(matches!(err, PluginError::Config(_)), "实际: {err}");
}

/// 入站 handler 由插件产出（tag 注入 + 认证配置从段注入；bind/handshake
/// 行为属既有 InboundHandler 实测——tests/http_proxy_e2e.rs）。
#[tokio::test]
async fn inbound_handler_produced_by_plugin() {
    let plugin = Arc::new(HttpPlugin::default());
    let framework = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(http_section_config(json!({
            "users": [{ "user": "u", "pass": "p" }]
        })))
        .register(Arc::clone(&plugin) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect("build");

    let inbound = plugin.inbound_handler("http-in").expect("inbound handler");
    assert_eq!(inbound.tag(), "http-in");
    assert!(plugin.built_config().expect("built").requires_auth(), "认证配置随插件注入");

    framework.shutdown().await;
}
