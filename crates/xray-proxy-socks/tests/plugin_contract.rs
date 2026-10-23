//! P2 批次 A 首族验收：L4 契约夹具（12 条全适用 + SOCKS-B1）+ 装配链
//! register → build → bring_up → shutdown（`is_clean()`）。
//!
//! （注册不进 xray-frame——xray-frame 禁依赖协议 crate，拍板 P2.1；同
//! blackhole P1-7 的做法，注册写在协议 crate 自己的装配链里。）

use std::sync::Arc;

use serde_json::json;
use xray_features::inbound::InboundHandler;
use xray_frame::{
    ClauseId, Plugin, PluginDep, PluginError,
    assembly::{Framework, FrameworkOptions},
    assert_plugin_contract,
};
use xray_proxy_socks::{AuthType, ServerConfig, SocksPlugin};

fn framework_options() -> FrameworkOptions {
    FrameworkOptions { registry_cap: 8, id_fingerprint: Some(1), shutdown_timeout: None }
}

/// 段形态：inbounds[] 按 protocol 路由（坑约束 7；socks 生产形态是入站，
/// 段路由的 inbounds[] 回落半边在此被真实覆盖）。
fn socks_section_config(settings: serde_json::Value) -> serde_json::Value {
    json!({ "inbounds": [
        { "protocol": "socks", "tag": "socks-in", "settings": settings }
    ] })
}

#[test]
fn contract_macro_holds_for_socks() {
    assert_plugin_contract!(SocksPlugin);
}

/// 契约面内容断言：12 条通用条款全适用（无 N/A）、SOCKS-B1 协议专属。
#[test]
fn contract_surface_declares_all_applicable_and_extra() {
    let plugin = SocksPlugin::default();
    let contract = plugin.contract();

    assert_eq!(plugin.name(), "socks");
    assert_eq!(plugin.version(), "0.1.0");
    let deps: &[PluginDep] = plugin.deps();
    assert!(deps.is_empty(), "socks 无依赖插件");

    assert_eq!(contract.clauses.len(), 12, "socks 12 条全适用（差异表 §2.2 第 5 行）");
    let expected: &[ClauseId] = &[
        ClauseId::AuthErrorClassified,
        ClauseId::HandshakeDeadline,
        ClauseId::ConnIdPresent,
        ClauseId::PoolDiscipline,
        ClauseId::SpawnManaged,
        ClauseId::StopRegistered,
        ClauseId::ConfigSectionOnly,
        ClauseId::ErrorClassifiedNoPanicEscape,
        ClauseId::BoundedResources,
        ClauseId::LogDiscipline,
        ClauseId::SecretMasking,
        ClauseId::HotPathFreeze,
    ];
    for clause in expected {
        assert!(contract.clauses.contains(clause), "缺条款 {clause:?}");
    }
    assert!(contract.not_applicable.is_empty(), "全适用 → 不允许 N/A 声明");

    assert_eq!(
        contract.extra,
        &[("SOCKS-B1", "SOCKS5 地址/端口长度字段必须显式边界检查，禁饱和截断")],
        "协议专属条款 SOCKS-B1"
    );
}

/// 完整装配链：段路由解析 → bring_up 三相 → 停机报告干净；
/// build 产物逐字段核对（auth/accounts/udp/userLevel）。
#[tokio::test]
async fn socks_assembles_bring_up_and_shuts_down_clean() {
    let plugin = Arc::new(SocksPlugin::default());
    let mut framework = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(socks_section_config(json!({
            "auth": "password",
            "accounts": [{ "user": "alice", "pass": "p1" }],
            "udp": true,
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
        auth_type: AuthType::Password,
        accounts: [("alice".to_string(), "p1".to_string())].into_iter().collect(),
        udp_enabled: true,
        user_level: 2,
        ..ServerConfig::default()
    };
    assert_eq!(plugin.built_config().expect("built"), &expected);
}

/// L5 装配门负向：缺段 fail-fast（坑约束 7 装配半边），
/// build 失败 → 无 Framework 产出（无半启动态）。
#[tokio::test]
async fn missing_section_fails_fast_at_build() {
    let err = Framework::builder(framework_options())
        .expect("registry cap")
        .register(Arc::new(SocksPlugin::default()) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect_err("config 根无 socks 段必须 fail-fast");
    assert!(matches!(err, PluginError::Config(_)), "实际: {err}");
}

/// 入站 handler 由插件产出（tag 注入 + 认证配置从段注入；bind/handshake
/// 行为属既有 InboundHandler 实测——tests/e2e_proxy.rs）。
#[tokio::test]
async fn inbound_handler_produced_by_plugin() {
    let plugin = Arc::new(SocksPlugin::default());
    let framework = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(socks_section_config(json!({
            "auth": "password",
            "accounts": [{ "user": "u", "pass": "p" }]
        })))
        .register(Arc::clone(&plugin) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect("build");

    let inbound = plugin.inbound_handler("socks-in").expect("inbound handler");
    assert_eq!(inbound.tag(), "socks-in");
    assert!(plugin.built_config().expect("built").requires_auth(), "认证配置随插件注入");

    framework.shutdown().await;
}
