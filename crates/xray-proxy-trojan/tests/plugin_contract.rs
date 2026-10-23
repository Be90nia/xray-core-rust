//! P2 批次 B 验收：L4 契约夹具（12 条全适用 + TRJ-1）+ 装配链
//! register → build → bring_up → shutdown（`is_clean()`）。
//!
//! （注册不进 xray-frame——xray-frame 禁依赖协议 crate，拍板 P2.1；同
//! blackhole P1-7 / socks P2-A 的做法，注册写在协议 crate 自己的装配链里。）

use std::sync::Arc;

use serde_json::json;
use xray_frame::{
    ClauseId, Plugin, PluginDep, PluginError,
    assembly::{Framework, FrameworkOptions},
    assert_plugin_contract,
};
use xray_proxy_trojan::TrojanPlugin;

fn framework_options() -> FrameworkOptions {
    FrameworkOptions { registry_cap: 8, id_fingerprint: Some(1), shutdown_timeout: None }
}

/// 段形态：inbounds[] 按 protocol 路由（坑约束 7；trojan 生产形态是入站，
/// 段路由的 inbounds[] 回落半边在此被真实覆盖）。
fn trojan_section_config(settings: serde_json::Value) -> serde_json::Value {
    json!({ "inbounds": [
        { "protocol": "trojan", "tag": "trojan-in", "settings": settings }
    ] })
}

#[test]
fn contract_macro_holds_for_trojan() {
    assert_plugin_contract!(TrojanPlugin);
}

/// 契约面内容断言：12 条通用条款全适用（无 N/A）、TRJ-1 协议专属。
#[test]
fn contract_surface_declares_all_applicable_and_extra() {
    let plugin = TrojanPlugin::default();
    let contract = plugin.contract();

    assert_eq!(plugin.name(), "trojan");
    assert_eq!(plugin.version(), "0.1.0");
    let deps: &[PluginDep] = plugin.deps();
    assert!(deps.is_empty(), "trojan 无依赖插件");

    assert_eq!(contract.clauses.len(), 12, "trojan 12 条全适用（差异表 §2.2 第 3 行）");
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
        &[("TRJ-1", "u16/u8 边界必须显式检查禁饱和截断")],
        "协议专属条款 TRJ-1"
    );
}

/// 完整装配链：段路由解析 → bring_up 三相 → 停机报告干净；
/// build 产物逐字段核对（clients 入 Validator + fallback dest 推导）。
#[tokio::test]
async fn trojan_assembles_bring_up_and_shuts_down_clean() {
    let plugin = Arc::new(TrojanPlugin::default());
    let mut framework = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(trojan_section_config(json!({
            "clients": [{ "password": "test-pass-12345", "email": "alice" }],
            "fallbacks": [{ "dest": 8080, "xver": 1 }]
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

    let validator = plugin.built_validator().expect("built");
    assert_eq!(validator.get_count(), 1, "clients 灌入 Validator");
    assert!(validator.get_by_email("alice").is_some());

    let fb = plugin.built_fallbacks().expect("built").as_ref().expect("fallbacks 在场");
    let matched = fb.decide("", "", "").expect("通配 fallback 命中");
    assert_eq!(matched.dest, "localhost:8080", "数字 dest 同规生产 → localhost:N");
    assert_eq!(matched.r#type, "tcp", "host:port 形态推导 tcp");
    assert_eq!(matched.xver, 1);
}

/// L5 装配门负向：缺段 fail-fast（坑约束 7 装配半边），
/// build 失败 → 无 Framework 产出（无半启动态）。
#[tokio::test]
async fn missing_section_fails_fast_at_build() {
    let err = Framework::builder(framework_options())
        .expect("registry cap")
        .register(Arc::new(TrojanPlugin::default()) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect_err("config 根无 trojan 段必须 fail-fast");
    assert!(matches!(err, PluginError::Config(_)), "实际: {err}");
}

/// L5 装配门负向：fallback `dest` 缺失 → build `Err`（同规生产 Go
/// trojan.go:196-198 硬错，拒启）。
#[tokio::test]
async fn fallback_dest_missing_fails_fast_at_build() {
    let err = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(trojan_section_config(json!({
            "clients": [{ "password": "test-pass-12345" }],
            "fallbacks": [{ "name": "sni" }]
        })))
        .register(Arc::new(TrojanPlugin::default()) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect_err("fallback dest 缺失必须 fail-fast");
    assert!(
        err.to_string().contains(r#"please fill in a valid value for every "dest""#),
        "实际: {err}"
    );
}

/// 入站 handler 由插件产出（tag 注入 + 用户/fallback 配置从段注入；bind/
/// handshake 行为属既有 InboundHandler 实测——server.rs 零 diff，wire 不变）。
#[tokio::test]
async fn inbound_handler_produced_by_plugin() {
    let plugin = Arc::new(TrojanPlugin::default());
    let framework = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(trojan_section_config(json!({
            "clients": [{ "password": "test-pass-12345" }],
            "fallbacks": [{ "dest": 80 }]
        })))
        .register(Arc::clone(&plugin) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect("build");

    let inbound = plugin.inbound_handler("trojan-in").expect("inbound handler");
    assert_eq!(inbound.tag(), "trojan-in");
    assert_eq!(plugin.built_validator().expect("built").get_key_count(), 1, "用户配置随插件注入");

    framework.shutdown().await;
}

/// build 前调用观察面 → `Err`（fail-visible，不 panic）。
#[test]
fn observface_before_build_fails_visible() {
    let plugin = TrojanPlugin::default();
    assert!(plugin.built_validator().is_err());
    assert!(plugin.built_fallbacks().is_err());
    assert!(plugin.inbound_handler("trojan-in").is_err());
}
