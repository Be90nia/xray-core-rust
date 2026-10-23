//! P2 批次 D 验收：L4 契约夹具（12 条全适用 + HY-QUINN）+ 装配链
//! register → build → bring_up → shutdown（`is_clean()`）+ L5 缺段/歧义负向。
//!
//! （注册不进 xray-frame——xray-frame 禁依赖协议 crate，拍板 P2.1；同
//! blackhole P1-7 / trojan P2-B 的做法，注册写在协议 crate 自己的装配链里。）

use std::sync::Arc;

use serde_json::json;
use xray_frame::{
    ClauseId, Plugin, PluginDep, PluginError,
    assembly::{Framework, FrameworkOptions},
    assert_plugin_contract,
};
use xray_proxy_hysteria::HysteriaPlugin;

fn framework_options() -> FrameworkOptions {
    FrameworkOptions { registry_cap: 8, id_fingerprint: Some(1), shutdown_timeout: None }
}

/// 入站段形态：inbounds[] 按 protocol 路由（坑约束 7；覆盖段路由的 inbounds
/// 回落半边——`section()` 先查 outbounds[] 再回落 inbounds[]）。
fn hysteria_inbound_section(settings: serde_json::Value) -> serde_json::Value {
    json!({ "inbounds": [
        { "protocol": "hysteria", "tag": "hysteria-in", "settings": settings }
    ] })
}

/// 出站段形态：outbounds[] 优先路由半边。
fn hysteria_outbound_section(settings: serde_json::Value) -> serde_json::Value {
    json!({ "outbounds": [
        { "protocol": "hysteria", "tag": "hysteria-out", "settings": settings }
    ] })
}

#[test]
fn contract_macro_holds_for_hysteria() {
    assert_plugin_contract!(HysteriaPlugin);
}

/// 契约面内容断言：12 条通用条款全适用（无 N/A）、HY-QUINN 协议专属。
#[test]
fn contract_surface_declares_all_applicable_and_extra() {
    let plugin = HysteriaPlugin::default();
    let contract = plugin.contract();

    assert_eq!(plugin.name(), "hysteria");
    assert_eq!(plugin.version(), "0.1.0");
    let deps: &[PluginDep] = plugin.deps();
    assert!(deps.is_empty(), "hysteria 无依赖插件");

    assert_eq!(contract.clauses.len(), 12, "hysteria 12 条全适用（差异表 §2.2 第 11 行）");
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
        &[("HY-QUINN", "quinn Connection 句柄禁跨线程裸转移；插件生命周期内持句柄必须登记停机")],
        "协议专属条款 HY-QUINN"
    );
}

/// 完整装配链（入站面）：段路由解析 → bring_up 三相 → 停机报告干净；
/// build 产物逐字段核对（users 灌入 + 可选键回落默认）。
#[tokio::test]
async fn hysteria_inbound_assembles_bring_up_and_shuts_down_clean() {
    let plugin = Arc::new(HysteriaPlugin::default());
    let mut framework = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(hysteria_inbound_section(json!({
            "bind": "127.0.0.1:9443",
            "serverName": "hys.example.com",
            "users": [{ "email": "alice", "auth": "tok-123" }],
            "udpIdleTimeout": 30
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

    let config = plugin.built_inbound().expect("built inbound");
    assert_eq!(config.bind_addr, "127.0.0.1:9443");
    assert_eq!(config.server_name, "hys.example.com");
    assert_eq!(config.users.len(), 1);
    assert_eq!(config.users[0].email, "alice");
    assert_eq!(config.users[0].auth, "tok-123");
    assert_eq!(config.udp_idle_timeout_secs, 30);
    assert_eq!(config.masq_type, "", "masquerade 缺省 = NotFound 语义空串");
    assert!(plugin.built_outbound().is_err(), "入站段 → 出站观察面 fail-visible");
}

/// 出站面：outbounds[] 优先路由 + 配置解析核对 + 装配链干净。
#[tokio::test]
async fn hysteria_outbound_assembles_and_parses_config() {
    let plugin = Arc::new(HysteriaPlugin::default());
    let mut framework = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(hysteria_outbound_section(json!({
            "address": "us1.example.com:443",
            "auth": "tok-456"
        })))
        .register(Arc::clone(&plugin) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect("build phase");
    framework.bring_up().expect("bring_up: init/start 三相");
    let report = framework.shutdown().await;
    assert!(report.is_clean(), "健康链停机报告必须干净");

    let config = plugin.built_outbound().expect("built outbound");
    assert_eq!(config.server_addr, "us1.example.com:443");
    assert_eq!(config.server_name, "us1.example.com", "SNI 默认 = address host 部分");
    assert_eq!(config.auth, "tok-456");
    assert_eq!(config.alpn, vec!["hysteria".to_string(), "h3".to_string()]);
    assert!(plugin.built_inbound().is_err(), "出站段 → 入站观察面 fail-visible");
}

/// L5 装配门负向：缺段 fail-fast（坑约束 7 装配半边），
/// build 失败 → 无 Framework 产出（无半启动态）。
#[tokio::test]
async fn missing_section_fails_fast_at_build() {
    let err = Framework::builder(framework_options())
        .expect("registry cap")
        .register(Arc::new(HysteriaPlugin::default()) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect_err("config 根无 hysteria 段必须 fail-fast");
    assert!(matches!(err, PluginError::Config(_)), "实际: {err}");
}

/// L5 装配门负向：settings 面歧义（users 与 address 并存）/ 全缺 → build `Err`
/// （fail-visible，禁静默择一）。
#[tokio::test]
async fn ambiguous_and_empty_settings_fail_fast_at_build() {
    for settings in [
        json!({}),                                               // 全缺
        json!({ "users": [{ "auth": "t" }], "address": "h:1" }), // 并存歧义
    ] {
        let err = Framework::builder(framework_options())
            .expect("registry cap")
            .with_config(hysteria_inbound_section(settings))
            .register(Arc::new(HysteriaPlugin::default()) as Arc<dyn Plugin>)
            .expect("register")
            .build()
            .expect_err("settings 面歧义/全缺必须 fail-fast");
        assert!(err.to_string().contains("hysteria settings"), "实际: {err}");
    }
}
