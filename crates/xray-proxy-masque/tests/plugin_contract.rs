//! MASQUE 插件契约测试（L4 夹具 + L5 装配负向；B4.3 验收 1）。

use std::sync::Arc;

use serde_json::json;
use xray_frame::{
    Framework, FrameworkOptions, assert_plugin_contract,
    plugin::{ClauseId, Plugin, PluginDep},
};
use xray_proxy_masque::plugin::MasquePlugin;

/// 段路由配置（outbounds[] 内 `protocol == "masque"` 元素；PluginContext::section
/// 同规）。
fn masque_section(settings: serde_json::Value) -> serde_json::Value {
    json!({ "outbounds": [ { "protocol": "masque", "tag": "masque-ob", "settings": settings } ] })
}

fn framework_options() -> FrameworkOptions {
    FrameworkOptions { registry_cap: 8, id_fingerprint: Some(1), shutdown_timeout: None }
}

/// L4：宏夹具（条款/extra/N-A 结构合法性，含可穷举校验）。
#[test]
fn contract_macro_holds_for_masque() {
    assert_plugin_contract!(MasquePlugin);
}

/// 契约面内容断言：12 条通用条款全适用（无 N/A）+ 3 条 masque 协议专属
/// （规划 §4.4：TLS-REQUIRED / ADDR-POOL / H2-ONLY）。
#[test]
fn contract_surface_declares_all_applicable_and_extra() {
    let plugin = MasquePlugin::new();
    let contract = plugin.contract();

    assert_eq!(plugin.name(), "masque");
    assert_eq!(plugin.version(), "0.1.0");
    let deps: &[PluginDep] = plugin.deps();
    assert!(deps.is_empty(), "masque 无依赖插件");

    assert_eq!(contract.clauses.len(), 12, "masque 12 条全适用");
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

    assert_eq!(contract.extra.len(), 3, "协议专属条款三条（规划 §4.4）");
    let extra_names: Vec<&str> = contract.extra.iter().map(|(n, _)| *n).collect();
    assert!(extra_names.contains(&"MASQUE-TLS-REQUIRED"));
    assert!(extra_names.contains(&"MASQUE-ADDR-POOL"));
    assert!(extra_names.contains(&"MASQUE-H2-ONLY"));
    for (_, reason) in contract.extra {
        assert!(!reason.is_empty(), "extra 条款理由非空");
    }
}

/// L5 装配负向（验收 1）：缺 address / 缺 users / 空 users → build Err
/// （无半启动态）。
#[tokio::test]
async fn missing_address_fails_fast_at_build() {
    let err = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(masque_section(json!({ "users": [{ "pass": "p" }] })))
        .register(Arc::new(MasquePlugin::new()) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect_err("缺 address 必须 build Err");
    assert!(err.to_string().contains("address"), "错误须指名 address：{err}");
}

#[tokio::test]
async fn missing_users_fails_fast_at_build() {
    let err = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(masque_section(json!({ "address": ["10.0.0.1/24"] })))
        .register(Arc::new(MasquePlugin::new()) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect_err("缺 users 必须 build Err");
    assert!(err.to_string().contains("users"), "错误须指名 users：{err}");
}

#[tokio::test]
async fn empty_users_fails_fast_at_build() {
    let err = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(masque_section(json!({
            "users": [],
            "address": ["10.0.0.1/24"]
        })))
        .register(Arc::new(MasquePlugin::new()) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect_err("空 users 必须 build Err（任务书验收 1；Go 不拒——本仓 fail-visible）");
    assert!(err.to_string().contains("users"), "错误须指名 users：{err}");
}

/// L5 装配正向：合法服务端面（users + 每族一前缀 + mtu 缺省）build 通过。
#[tokio::test]
async fn valid_server_section_builds() {
    let _framework = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(masque_section(json!({
            "users": [{ "pass": "p", "email": "a@b", "level": 1 }],
            "address": ["10.0.0.1/24", "fd00::1/120"],
            "mtu": 1500
        })))
        .register(Arc::new(MasquePlugin::new()) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect("合法段必须 build 通过");
}

/// 客户端 settings 解析负向（同规 outbound 装配器消费面）：缺 address/port。
#[test]
fn client_settings_negative() {
    let e = xray_proxy_masque::client::parse_client_settings(&json!({}))
        .expect_err("缺 address 必须拒");
    assert!(e.contains("address"), "got: {e}");
    let e = xray_proxy_masque::client::parse_client_settings(&json!({ "address": "127.0.0.1" }))
        .expect_err("缺 port 必须拒");
    assert!(e.contains("port"), "got: {e}");
}
