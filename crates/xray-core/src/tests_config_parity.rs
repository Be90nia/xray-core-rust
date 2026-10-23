//! P3-2 对拍测试（契约任务书 P3-2）：同一份配置 JSON，旧 core 解析面 vs
//! xray-frame 插件 build 管线，产物**逐字段相等**（三族产物同型 + PartialEq →
//! 全量 `assert_eq!`；freedom 的 fragment/noises 两键 core 面 parse-then-drop、
//! 插件面接全——已知差异单列断言钉住，不混进全量对拍）。
//!
//! 本模块 `#[cfg(test)]`，零生产语义；旧 parse 函数原文未动（「本单不删旧
//! 解析面」红线）。

use std::sync::Arc;

use serde_json::{Value, json};
use xray_frame::{Plugin, build_plugins_from_config};
use xray_proxy_blackhole::{BlackholePlugin, ResponseConfig};
use xray_proxy_freedom::FreedomPlugin;
use xray_proxy_socks::SocksPlugin;

/// 构造只含一个协议条目的配置根（settings 内嵌形态）。
fn root_with(protocol: &str, settings: Value) -> Value {
    json!({"outbounds": [{"protocol": protocol, "settings": settings}]})
}

// ── socks：core `parse_socks_server_config` ↔ SocksPlugin::build ──

#[test]
fn socks_parity_password_auth_full_fields() {
    let settings = json!({
        "auth": "password",
        "accounts": [{"user": "u", "pass": "p"}],
        "udp": true,
        "userLevel": 2,
        "ip": "127.0.0.1",
    });
    let core = crate::inbound::parse_socks_server_config(&serde_json::to_vec(&settings).unwrap())
        .expect("core parse");
    let plugin = Arc::new(SocksPlugin::default());
    let built = build_plugins_from_config(
        &root_with("socks", settings),
        &[Arc::clone(&plugin) as Arc<dyn Plugin>],
    )
    .expect("plugin build");
    assert_eq!(built, ["socks"]);
    assert_eq!(plugin.built_config().expect("built"), &core);
}

#[test]
fn socks_parity_defaults_when_settings_empty() {
    // 空 settings：两侧都走全默认（NoAuth/无账户/无 UDP/level 0/无地址）。
    let core = crate::inbound::parse_socks_server_config(b"{}").expect("core parse");
    let plugin = Arc::new(SocksPlugin::default());
    let built = build_plugins_from_config(
        &root_with("socks", json!({})),
        &[Arc::clone(&plugin) as Arc<dyn Plugin>],
    )
    .expect("plugin build");
    assert_eq!(built, ["socks"]);
    assert_eq!(plugin.built_config().expect("built"), &core);
    assert_eq!(core.auth_type, xray_proxy_socks::AuthType::NoAuth);
}

#[test]
fn socks_parity_inbounds_layout_users_alias() {
    // inbounds[] 布局 + users 别名（Go socks.go accounts 在场覆盖 users；两键
    // 都缺席时 users 兜底路径）。
    let settings = json!({"users": [{"user": "a", "pass": "1"}], "udp": false});
    let core = crate::inbound::parse_socks_server_config(&serde_json::to_vec(&settings).unwrap())
        .expect("core parse");
    let plugin = Arc::new(SocksPlugin::default());
    let root = json!({"inbounds": [{"protocol": "socks", "settings": settings}]});
    let built = build_plugins_from_config(&root, &[Arc::clone(&plugin) as Arc<dyn Plugin>])
        .expect("plugin build");
    assert_eq!(built, ["socks"]);
    assert_eq!(plugin.built_config().expect("built"), &core);
    assert!(core.accounts.contains_key("a"));
}

// ── freedom：core `parse_freedom_config` ↔ FreedomPlugin::build ──

#[test]
fn freedom_parity_strategy_override_and_final_rules() {
    let settings = json!({
        "domainStrategy": "UseIP",
        "destinationOverride": {"server": {"address": "1.2.3.4", "port": 443}},
        "userLevel": 1,
        "proxyProtocol": 2,
        "finalRules": [{"action": "allow"}],
    });
    let core = crate::outbound::parse_freedom_config(&serde_json::to_vec(&settings).unwrap())
        .expect("core parse");
    let plugin = Arc::new(FreedomPlugin::default());
    let built = build_plugins_from_config(
        &root_with("freedom", settings),
        &[Arc::clone(&plugin) as Arc<dyn Plugin>],
    )
    .expect("plugin build");
    assert_eq!(built, ["freedom"]);
    // 同型全量对拍（无 fragment/noises 输入 → 两键两侧均 Default）。
    assert_eq!(plugin.built_config().expect("built"), &core);
}

#[test]
fn freedom_parity_target_strategy_priority() {
    // targetStrategy 非空优先于 domainStrategy（Go freedom.go:62-64）。
    let settings = json!({"targetStrategy": "ForceIPv4", "domainStrategy": "UseIP"});
    let core = crate::outbound::parse_freedom_config(&serde_json::to_vec(&settings).unwrap())
        .expect("core parse");
    let plugin = Arc::new(FreedomPlugin::default());
    let built = build_plugins_from_config(
        &root_with("freedom", settings),
        &[Arc::clone(&plugin) as Arc<dyn Plugin>],
    )
    .expect("plugin build");
    assert_eq!(built, ["freedom"]);
    assert_eq!(plugin.built_config().expect("built"), &core);
    assert_eq!(core.domain_strategy, xray_proxy_freedom::DomainStrategy::ForceIPv4 as i32);
}

#[test]
fn freedom_known_divergence_fragment_noises() {
    // 已知差异（有意，插件注释明示「收敛属 P3 入口收口」）：fragment/noises
    // 两键 core 面 parse-then-drop（产物字段 Default），插件面接全。共有字段
    // 仍逐项相等；差异字段两侧各钉各的值 = 差异证据。
    let settings = json!({
        "domainStrategy": "AsIs",
        "fragment": {"lengthMin": 10, "lengthMax": 20},
        "noises": [{"packet": "rand", "delayMin": 1, "delayMax": 2}],
    });
    let core = crate::outbound::parse_freedom_config(&serde_json::to_vec(&settings).unwrap())
        .expect("core parse");
    let plugin = Arc::new(FreedomPlugin::default());
    let built = build_plugins_from_config(
        &root_with("freedom", settings),
        &[Arc::clone(&plugin) as Arc<dyn Plugin>],
    )
    .expect("plugin build");
    assert_eq!(built, ["freedom"]);
    let plugin_cfg = plugin.built_config().expect("built");
    // 共有字段相等。
    assert_eq!(plugin_cfg.domain_strategy, core.domain_strategy);
    assert_eq!(plugin_cfg.destination_override, core.destination_override);
    assert_eq!(plugin_cfg.user_level, core.user_level);
    assert_eq!(plugin_cfg.proxy_protocol, core.proxy_protocol);
    assert_eq!(plugin_cfg.final_rules, core.final_rules);
    // 差异字段：core drop（Default），plugin 接全。
    assert_eq!(core.fragment, None);
    assert!(core.noises.is_empty());
    let fragment = plugin_cfg.fragment.clone().expect("plugin parsed fragment");
    assert_eq!((fragment.length_min, fragment.length_max), (10, 20));
    assert_eq!(plugin_cfg.noises.len(), 1);
}

// ── blackhole：core `parse_blackhole_response` ↔ BlackholePlugin::build ──

#[test]
fn blackhole_parity_http_response() {
    let settings = json!({"response": {"type": "http"}});
    let core = crate::outbound::parse_blackhole_response(&serde_json::to_vec(&settings).unwrap())
        .expect("core parse");
    let plugin = Arc::new(BlackholePlugin::default());
    let built = build_plugins_from_config(
        &root_with("blackhole", settings),
        &[Arc::clone(&plugin) as Arc<dyn Plugin>],
    )
    .expect("plugin build");
    assert_eq!(built, ["blackhole"]);
    assert_eq!(plugin.built_response().expect("built"), &core);
    assert_eq!(core, ResponseConfig::Http403);
}

#[test]
fn blackhole_parity_custom_response_base64() {
    let settings = json!({"response": {"type": "custom", "customResponseData": "aGVsbG8="}});
    let core = crate::outbound::parse_blackhole_response(&serde_json::to_vec(&settings).unwrap())
        .expect("core parse");
    let plugin = Arc::new(BlackholePlugin::default());
    let built = build_plugins_from_config(
        &root_with("blackhole", settings),
        &[Arc::clone(&plugin) as Arc<dyn Plugin>],
    )
    .expect("plugin build");
    assert_eq!(built, ["blackhole"]);
    assert_eq!(plugin.built_response().expect("built"), &core);
    assert_eq!(core, ResponseConfig::Custom(b"hello".to_vec()));
}

#[test]
fn blackhole_parity_missing_response_is_none() {
    let settings = json!({});
    let core = crate::outbound::parse_blackhole_response(&serde_json::to_vec(&settings).unwrap())
        .expect("core parse");
    let plugin = Arc::new(BlackholePlugin::default());
    let built = build_plugins_from_config(
        &root_with("blackhole", settings),
        &[Arc::clone(&plugin) as Arc<dyn Plugin>],
    )
    .expect("plugin build");
    assert_eq!(built, ["blackhole"]);
    assert_eq!(plugin.built_response().expect("built"), &core);
    assert_eq!(core, ResponseConfig::None);
}

// ── 缺段 fail-fast（对拍反面）：注册链插件被要求 build 但配置无段 → Err ──

#[test]
fn missing_section_fails_fast_not_global_fallback() {
    // 直接段路由面：PluginConfig::section 缺段 → Err(Missing)，不回落全局键。
    let root = json!({"outbounds": [{"protocol": "freedom"}], "socks": {"auth": "password"}});
    let err = xray_frame::PluginConfig::section("socks", &root).unwrap_err();
    assert!(
        err.to_string().contains("protocol=socks"),
        "fail-fast error carries routing key: {err}"
    );

    // 配置驱动装配面：无条目 = 不 build（合法态）；有条目但插件 build 内
    // `ctx.section()?` 找不到段才 Err——经 FrameworkBuilder 全管线断言见
    // xray-frame tests/config_routing.rs。
    let built = build_plugins_from_config(
        &json!({}),
        &[Arc::new(SocksPlugin::default()) as Arc<dyn Plugin>],
    )
    .expect("no entry, no build");
    assert!(built.is_empty());
}
