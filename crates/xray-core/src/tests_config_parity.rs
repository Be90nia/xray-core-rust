//! P3-2 对拍测试（契约任务书 P3-2）：同一份配置 JSON，旧 core 解析面 vs
//! xray-frame 插件 build 管线，产物**逐字段相等**（产物同型 + PartialEq 的族
//! 全量 `assert_eq!`；freedom 的 fragment/noises 两键 core 面 parse-then-drop、
//! 插件面接全——已知差异单列断言钉住，不混进全量对拍）。
//!
//! T5.1 扩面（2026-10-24）：3 族 → 16 族全覆盖（缺口：ss/dokodemo/tuic 无对拍
//! 能力，单列不伪造通过；已知差异 3 处以 freedom fragment/noises 同款「钉子」
//! 测试记录：vless 出站 level/email 生产面丢、hysteria 出站 server_addr 插件面
//! 缺 port 拼接、wireguard 入站 port 键位置 settings 级 vs 段级）。
//!
//! 本模块 `#[cfg(test)]`，零生产语义；旧 parse 函数原文未动（「本单不删旧
//! 解析面」红线）。

use std::sync::Arc;

use serde_json::{Value, json};
use xray_frame::{Plugin, build_plugins_from_config};
use xray_proxy_anytls::AnytlsPlugin;
use xray_proxy_blackhole::{BlackholePlugin, ResponseConfig};
use xray_proxy_dns::DnsPlugin;
use xray_proxy_freedom::FreedomPlugin;
use xray_proxy_hysteria::HysteriaPlugin;
use xray_proxy_http::HttpPlugin;
use xray_proxy_loopback::LoopbackPlugin;
use xray_proxy_socks::SocksPlugin;
use xray_proxy_trojan::TrojanPlugin;
use xray_proxy_tun::TunPlugin;
use xray_proxy_vless::VlessPlugin;
use xray_proxy_vmess::{Validator as VmessValidatorTrait, VmessPlugin};
use xray_proxy_wireguard::WireguardPlugin;

/// 构造只含一个协议条目的配置根（settings 内嵌形态）。
fn root_with(protocol: &str, settings: Value) -> Value {
    json!({"outbounds": [{"protocol": protocol, "settings": settings}]})
}

/// 构造只含一个协议条目的入站配置根（inbounds 段形态；`section()` 路由
/// outbounds 优先、回落 inbounds——出站族样本勿与本 helper 混用）。
fn root_inbound_with(protocol: &str, settings: Value) -> Value {
    json!({"inbounds": [{"protocol": protocol, "settings": settings}]})
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

// ═══════════════════════════════════════════════════════════════════════════
// T5.1 扩面：3 族 → 16 族全覆盖（2026-10-24）。
//
// 口径沿用上节：同一份 settings JSON，生产解析面 vs 插件 build 产物。
// 产物同型且 PartialEq 的族全量 `assert_eq!`；其余逐字段断言（FallbackPolicy
// 无 PartialEq → decide 行为探针；vmess/vless validator 无按 email 查询 API →
// count + behavior_seed（用户 id 集合敏感））。
//
// **缺口清单（不伪造通过，P3 入口收口时回补）**：
// - `ss`：xray-proxy-ss 无 Plugin 实现（框架侧缺），无从对拍。
// - `dokodemo`：入站生产面 `DokodemoInboundSettings` 私有 struct+私有字段，
//   字段级对比不可达；出站面插件无观察面（插件只有入站 Config）。
// - `tuic`：生产面 `TuicInboundSettings` 私有 struct+私有字段，插件
//   `TuicInboundConfig` 字段无法与生产对拍。
// ═══════════════════════════════════════════════════════════════════════════

// ── vless：出站字段级（core `parse_vless_config` ↔ VlessPlugin built_outbound）──

#[test]
fn vless_parity_outbound_vnext_fields() {
    let settings = json!({
        "vnext": [{
            "address": "server.example.com",
            "port": 443,
            "users": [{
                "id": "b831381d-6324-4d53-ad4f-8cda48b30811",
                "flow": "xtls-rprx-vision",
                "level": 1,
                "email": "cli@x",
            }],
        }],
    });
    let core = crate::outbound::parse_vless_config(&serde_json::to_vec(&settings).unwrap())
        .expect("core parse");
    let plugin = Arc::new(VlessPlugin::default());
    let built = build_plugins_from_config(
        &root_with("vless", settings),
        &[Arc::clone(&plugin) as Arc<dyn Plugin>],
    )
    .expect("plugin build");
    assert_eq!(built, ["vless"]);
    let p = plugin.built_outbound().expect("built");
    assert_eq!(p.user_uuid, core.user_uuid);
    assert_eq!(p.server_address, core.server_address);
    assert_eq!(p.server_port, core.server_port);
    assert_eq!(p.flow, core.flow);
    assert_eq!(p.encryption, core.encryption);
    assert_eq!(p.testseed, core.testseed);
    assert_eq!(p.testpre, core.testpre);
    assert!(p.stream_settings.is_none() && core.stream_settings.is_none());
    // level/email 两侧不比：生产 `parse_vless_config` 读但未接进 config
    // （`#[allow(unused_variables)]` 存量清零批次），见下方 known-divergence 钉子。
}

/// 已知差异钉子（freedom fragment/noises 同款）：vless 出站 `level`/`email`
/// 生产面读但丢（core 恒 0/空串）、插件面接全。P3 入口收口时收敛任一侧后此
/// 测试即红，提醒更新主对拍。
#[test]
fn vless_known_divergence_outbound_level_email_core_drops() {
    let settings = json!({
        "vnext": [{
            "address": "server.example.com",
            "port": 443,
            "users": [{
                "id": "b831381d-6324-4d53-ad4f-8cda48b30811",
                "level": 1,
                "email": "cli@x",
            }],
        }],
    });
    let core = crate::outbound::parse_vless_config(&serde_json::to_vec(&settings).unwrap())
        .expect("core parse");
    let plugin = Arc::new(VlessPlugin::default());
    build_plugins_from_config(
        &root_with("vless", settings),
        &[Arc::clone(&plugin) as Arc<dyn Plugin>],
    )
    .expect("plugin build");
    assert_eq!(
        (core.level, core.email.as_str()),
        (0, ""),
        "生产面现状：level/email 读但丢（收口后本断言翻红）"
    );
    let p = plugin.built_outbound().expect("built");
    assert_eq!((p.level, p.email.as_str()), (1, "cli@x"), "插件面接全");
}

// ── vmess：入站 validator（core `build_vmess_validator` ↔ VmessPlugin）──

#[test]
fn vmess_parity_inbound_validator_users() {
    let settings = json!({
        "clients": [
            {"id": "b831381d-6324-4d53-ad4f-8cda48b30811", "email": "alice@x", "level": 2},
            {"id": "66ad4540-b58c-4ad2-9926-ea63445a9b57", "email": "bob@x"},
        ],
        "default": {"level": 5},
    });
    let core = crate::inbound::build_vmess_validator(&serde_json::to_vec(&settings).unwrap())
        .expect("core validator");
    let plugin = Arc::new(VmessPlugin::default());
    let built = build_plugins_from_config(
        &root_inbound_with("vmess", settings),
        &[Arc::clone(&plugin) as Arc<dyn Plugin>],
    )
    .expect("plugin build");
    assert_eq!(built, ["vmess"]);
    let p = plugin.built_validator().expect("built");
    assert_eq!(core.count(), p.count(), "用户数一致");
    // behavior_seed 由全部用户 id HMAC 派生——id 集合任一差异即翻转。
    assert_eq!(core.behavior_seed(), p.behavior_seed(), "用户 id 集合一致");
}

// ── trojan：入站用户表 + fallback 决策树（core build_trojan_* ↔ TrojanPlugin）──

#[test]
fn trojan_parity_inbound_validator_and_fallbacks() {
    let settings = json!({
        "clients": [
            {"password": "secret1", "email": "alice@x", "level": 1},
            {"password": "secret2", "email": "bob@x"},
        ],
        "fallbacks": [
            {"dest": 8080},
            {"sni": "tls.example.com", "dest": "internal:9000", "path": "/ws"},
        ],
    });
    let data = serde_json::to_vec(&settings).unwrap();
    let core_users = crate::inbound::build_trojan_users(&data).expect("core users");
    let core_fbs = crate::inbound::build_trojan_fallbacks(&data).expect("core fallbacks");
    let plugin = Arc::new(TrojanPlugin::default());
    let built = build_plugins_from_config(
        &root_inbound_with("trojan", settings),
        &[Arc::clone(&plugin) as Arc<dyn Plugin>],
    )
    .expect("plugin build");
    assert_eq!(built, ["trojan"]);
    let pv = plugin.built_validator().expect("built validator");
    assert_eq!(pv.get_count(), core_users.len(), "用户数一致");
    // core 表 key = hex(sha224(password))；逐 key 对拍运行时用户（PartialEq）。
    for (key_hash, user) in &core_users {
        let pu = pv.get(key_hash).unwrap_or_else(|| panic!("plugin missing {key_hash}"));
        assert_eq!(&pu, user, "user fields diverge");
    }
    // FallbackPolicy 无 PartialEq → decide 行为探针（SNI/ALPN/path 三层）。
    use xray_proxy_trojan::fallback::FallbackPolicy;
    let pf = plugin.built_fallbacks().expect("built fallbacks");
    let probe = |p: Option<&std::sync::Arc<FallbackPolicy>>, sni: &str, alpn: &str, path: &str| {
        p.and_then(|f| f.decide(sni, alpn, path)).cloned()
    };
    for (sni, alpn, path) in
        [("", "", ""), ("tls.example.com", "", "/ws"), ("other.com", "h2", "/x")]
    {
        assert_eq!(
            probe(pf.as_ref(), sni, alpn, path),
            probe(core_fbs.as_ref(), sni, alpn, path),
            "fallback decide({sni},{alpn},{path}) diverges"
        );
    }
}

// ── http：入站全量 eq（core `parse_http_config` ↔ HttpPlugin built_config）──

#[test]
fn http_parity_inbound_users_alias_transparent_level() {
    let settings = json!({
        "users": [{"user": "alice", "pass": "p1"}],
        "allowTransparent": true,
        "userLevel": 3,
    });
    let core =
        crate::inbound::parse_http_config(&serde_json::to_vec(&settings).unwrap()).expect("core");
    let plugin = Arc::new(HttpPlugin::default());
    let built = build_plugins_from_config(
        &root_inbound_with("http", settings),
        &[Arc::clone(&plugin) as Arc<dyn Plugin>],
    )
    .expect("plugin build");
    assert_eq!(built, ["http"]);
    assert_eq!(plugin.built_config().expect("built"), &core);
}

// ── dns：出站全量 eq（core `build_dns_outbound_config` ↔ DnsPlugin built_config）──

#[test]
fn dns_parity_outbound_rule_and_rewrite() {
    let settings = json!({
        "userLevel": 2,
        "rules": [{"action": "return", "domain": ["example.com"]}],
        "rewriteAddress": "8.8.8.8",
        "rewritePort": 53,
    });
    let core = crate::outbound::build_dns_outbound_config(&serde_json::to_vec(&settings).unwrap())
        .expect("core parse");
    let plugin = Arc::new(DnsPlugin::default());
    let built = build_plugins_from_config(
        &root_with("dns", settings),
        &[Arc::clone(&plugin) as Arc<dyn Plugin>],
    )
    .expect("plugin build");
    assert_eq!(built, ["dns"]);
    assert_eq!(plugin.built_config().expect("built"), &core);
}

// ── hysteria：出站字段级（core `parse_hysteria_config` 元组 ↔ built_outbound）──

#[test]
fn hysteria_parity_outbound_flat_fields() {
    let settings = json!({
        "address": "example.com",
        "port": 39622,
        "version": 2,
        "auth": "tok",
        "serverName": "sni.example.com",
    });
    let core = crate::outbound::parse_hysteria_config(&serde_json::to_vec(&settings).unwrap())
        .expect("core parse");
    let plugin = Arc::new(HysteriaPlugin::default());
    let built = build_plugins_from_config(
        &root_with("hysteria", settings),
        &[Arc::clone(&plugin) as Arc<dyn Plugin>],
    )
    .expect("plugin build");
    assert_eq!(built, ["hysteria"]);
    let p = plugin.built_outbound().expect("built");
    assert_eq!(p.auth, core.1, "auth");
    assert_eq!(p.server_name, core.2, "server_name/sni");
    // server_addr 不比：插件面存 address 原样（缺 `:{port}` 拼接），见下方钉子。
}

/// 已知差异钉子：hysteria 出站 `server_addr` 生产面拼 `address:port`、插件面存
/// address 原样（缺端口）。P3 出站接线（拨号面）前必须收敛插件侧，否则拨号
/// 目标错端口；收敛后本测试翻红，提醒更新主对拍。
#[test]
fn hysteria_known_divergence_outbound_server_addr_port() {
    let settings = json!({
        "address": "example.com",
        "port": 39622,
        "version": 2,
        "auth": "tok",
        "serverName": "sni.example.com",
    });
    let core = crate::outbound::parse_hysteria_config(&serde_json::to_vec(&settings).unwrap())
        .expect("core parse");
    let plugin = Arc::new(HysteriaPlugin::default());
    build_plugins_from_config(
        &root_with("hysteria", settings),
        &[Arc::clone(&plugin) as Arc<dyn Plugin>],
    )
    .expect("plugin build");
    assert_eq!(core.0, "example.com:39622", "生产面：address:port 拼接");
    let p = plugin.built_outbound().expect("built");
    assert_eq!(p.server_addr, "example.com", "插件面现状：address 原样（收口后翻红）");
}

// ── anytls：出站字段级（core `parse_anytls_config` ↔ built_password）──

#[test]
fn anytls_parity_outbound_password_and_server() {
    let settings = json!({
        "server": "1.2.3.4",
        "server_port": 443,
        "password": "pw1",
        "sni": "sni.example.com",
    });
    let core = crate::outbound::parse_anytls_config(&serde_json::to_vec(&settings).unwrap())
        .expect("core parse");
    let plugin = Arc::new(AnytlsPlugin::default());
    let built = build_plugins_from_config(
        &root_with("anytls", settings),
        &[Arc::clone(&plugin) as Arc<dyn Plugin>],
    )
    .expect("plugin build");
    assert_eq!(built, ["anytls"]);
    // 插件面只观察 password（anytls 出站其余字段属 core 解析面，见插件 crate doc）。
    assert_eq!(plugin.built_password().expect("built"), Some("pw1"));
    assert_eq!(core.password, "pw1");
    assert_eq!(core.server_addr, "1.2.3.4:443");
    assert_eq!(core.sni, "sni.example.com");
}

// ── wireguard：入站全量 eq（core `parse_wireguard_inbound_config` ↔ built_config）──

#[test]
fn wireguard_parity_inbound_device_fields() {
    let settings = json!({
        "secretKey": "aa".repeat(32),
        "port": 51821,
    });
    let (core_device, _) =
        crate::inbound::parse_wireguard_inbound_config(&serde_json::to_vec(&settings).unwrap())
            .expect("core parse");
    let plugin = Arc::new(WireguardPlugin::default());
    let built = build_plugins_from_config(
        &root_inbound_with("wireguard", settings),
        &[Arc::clone(&plugin) as Arc<dyn Plugin>],
    )
    .expect("plugin build");
    assert_eq!(built, ["wireguard"]);
    let p = plugin.built_config().expect("built");
    assert_eq!(p.device, core_device, "device 全量相等（PartialEq derive）");
    // listen_port 不比：键位置两侧不同（生产读 settings 内 `port`、插件读段级
    // `port`），同一份 settings 内样本必然两侧不一致，见下方钉子。
}

/// 已知差异钉子：wireguard 入站 `port` 键位置——生产
/// `parse_wireguard_inbound_config` 读 settings 内 `port`（Go 对齐），插件
/// `parse_wireguard_section` 读段级（条目顶层）`port`。settings 内同值两侧必
/// 一侧缺省。P3 入口收口收敛位置后本测试翻红，提醒更新主对拍。
#[test]
fn wireguard_known_divergence_port_key_location() {
    let settings = json!({ "secretKey": "aa".repeat(32), "port": 51821 });
    let (_, core_port) =
        crate::inbound::parse_wireguard_inbound_config(&serde_json::to_vec(&settings).unwrap())
            .expect("core parse");
    assert_eq!(core_port, 51821, "生产面：settings 内 port 生效");
    let plugin = Arc::new(WireguardPlugin::default());
    build_plugins_from_config(
        &root_inbound_with("wireguard", settings),
        &[Arc::clone(&plugin) as Arc<dyn Plugin>],
    )
    .expect("plugin build");
    let p = plugin.built_config().expect("built");
    assert_eq!(p.listen_port, 51820, "插件面现状：settings 内 port 被忽略（收口后翻红）");
}

// ── loopback：出站 tag（core `outbound::parse_loopback_config` ↔ built_inbound_tag）──

#[test]
fn loopback_parity_outbound_inbound_tag() {
    let settings = json!({"inboundTag": "in-main"});
    let (core_tag, sniffing) =
        crate::outbound::parse_loopback_config(&serde_json::to_vec(&settings).unwrap())
            .expect("core parse");
    assert!(!sniffing.enabled, "无 sniffing → 缺省不嗅探（两侧同规）");
    let plugin = Arc::new(LoopbackPlugin::default());
    let built = build_plugins_from_config(
        &root_with("loopback", settings),
        &[Arc::clone(&plugin) as Arc<dyn Plugin>],
    )
    .expect("plugin build");
    assert_eq!(built, ["loopback"]);
    assert_eq!(plugin.built_inbound_tag().expect("built"), core_tag);
}

// ── tun：入站 StackOptions 字段级（core `parse_tun_inbound_config` ↔ built_config）──

#[test]
fn tun_parity_inbound_stack_options_fields() {
    let settings = json!({
        "name": "utun7",
        "mtu": 1400,
        "desc": "d1",
        "gateway": ["10.0.0.1/24"],
        "dns": ["1.1.1.1"],
        "userLevel": 2,
        "autoSystemRoutingTable": ["t0"],
    });
    let core =
        crate::inbound::parse_tun_inbound_config(&serde_json::to_vec(&settings).unwrap())
            .expect("core parse");
    let plugin = Arc::new(TunPlugin::default());
    let built = build_plugins_from_config(
        &root_inbound_with("tun", settings),
        &[Arc::clone(&plugin) as Arc<dyn Plugin>],
    )
    .expect("plugin build");
    assert_eq!(built, ["tun"]);
    let p = plugin.built_config().expect("built");
    assert_eq!(p.name, core.name);
    assert_eq!(p.mtu, core.mtu);
    assert_eq!(p.desc, core.desc);
    assert_eq!(p.gateway, core.gateway);
    assert_eq!(p.dns, core.dns);
    assert_eq!(p.user_level, core.user_level);
    assert_eq!(p.idle_timeout, core.idle_timeout);
    assert_eq!(p.auto_system_routing_table, core.auto_system_routing_table);
    assert_eq!(p.auto_outbounds_interface, core.auto_outbounds_interface);
    assert!(p.tun.is_some() && core.tun.is_some(), "占位设备注入两侧一致");
}
