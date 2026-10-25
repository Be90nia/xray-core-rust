//! P3-2 对拍测试（契约任务书 P3-2）：同一份配置 JSON，旧 core 解析面 vs
//! xray-frame 插件 build 管线，产物**逐字段相等**（产物同型 + PartialEq 的族
//! 全量 `assert_eq!`；freedom 的 fragment/noises 两键 core 面 parse-then-drop、
//! 插件面接全——已知差异单列断言钉住，不混进全量对拍）。
//!
//! T5.1 扩面（2026-10-24）：3 族 → 16 族全覆盖。已知差异 2 处「钉子」已收口为
//! 一致断言：vless 出站 level/email 生产面接线、wireguard 入站 port 键位收敛
//! settings 级（本日 B5 前置）。hysteria 出站 server_addr 插件面缺 port 拼接
//! 一处已收口——插件面按 Go `infra/conf/hysteria.go:13-17` 合成 host:port，与
//! 生产面逐字相等（见 `hysteria_parity_outbound_server_addr_port`）。
//!
//! bd hw6w 收口（2026-10-25）：`ss` 从「缺口登记」转为**真对拍**——P2 补课后
//! `xray-proxy-ss` 已有 `impl Plugin`（`SsPlugin`，产物观察面 `face()`），入站
//! 五形态（legacy 单/多用户 → ss2022 单/多/中继）core 解析面 vs 插件解析面逐
//! 字段 + 逐行为比，见 `ss_parity_*`。`ss` 出站面**刻意不对拍**：生产装配
//! （`arm_builders/outbound.rs:287`）与插件出站分支调同一个
//! `xray_proxy_ss::parse_ss_config`，同函数自比无信息量。
//!
//! 16/16 族的可观测出口 = `parity_roster_covers_all_16_families`（名称清单 +
//! 总数断言）；CI 宽门已含本模块——`cargo test --workspace`
//! （`.github/workflows/ci.yml:160`）跑 lib 测试目标，无需单列 workflow。
//!
//! 新登记已知差异 1 处（**只报告不修**，见
//! `reports/wsl-2026-10-25/parity-16.md`）：ss2022 中继 `destinations[]` 旧形的
//! `server` 为 IP 字面量时，core 面硬写 `Address::Domain`、插件面走
//! `parse_address_str` → `Address::IPv4`，见
//! `ss_known_divergence_relay_destinations_address_typing`。
//!
//! 本模块 `#[cfg(test)]`，零生产语义；旧 parse 函数原文未动（「本单不删旧
//! 解析面」红线）。

use std::sync::Arc;

use serde_json::{Value, json};
use tokio::io::AsyncWriteExt;
use xray_common::net::address::Address;
use xray_frame::{Plugin, build_plugins_from_config};
use xray_proxy_anytls::AnytlsPlugin;
use xray_proxy_blackhole::{BlackholePlugin, ResponseConfig};
use xray_proxy_dns::DnsPlugin;
use xray_proxy_dokodemo::{DokodemoPlugin, Network as DokodemoNetwork, PredefinedAddress};
use xray_proxy_freedom::FreedomPlugin;
use xray_proxy_http::HttpPlugin;
use xray_proxy_hysteria::HysteriaPlugin;
use xray_proxy_loopback::LoopbackPlugin;
use xray_proxy_socks::SocksPlugin;
use xray_proxy_ss::{
    CipherKind2022, RelayInbound, SsFace, SsInbound, SsPlugin, psk_from_base64,
    ss2022::{
        derive_psk,
        key::{derive_identity_subkey, ecb_block, psk_identity},
    },
};
use xray_proxy_trojan::TrojanPlugin;
use xray_proxy_tuic::TuicPlugin;
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
// **缺口清单（不伪造通过）**：
// - ~~`ss`~~（bd hw6w 收口，2026-10-25）：P2 补课后 `xray-proxy-ss` 已有 `impl Plugin`（产物观察面
//   `face()`），入站五形态真对拍见 `ss_parity_*`；
//   出站面两侧同函数（`parse_ss_config`）刻意不对拍。
// - ~~`dokodemo`/`tuic`~~（已收口，本日 B5 前置）：生产面 struct+解析 fn 放宽
//   `pub(crate)`（先例注释同 `parse_wireguard_inbound_config`），对拍见
//   `dokodemo_parity_inbound_full_fields` / `tuic_parity_inbound_full_fields`。
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
    assert_eq!(p.level, core.level);
    assert_eq!(p.email, core.email);
}

/// vless 出站 `level`/`email` 对拍（原 known-divergence 钉子，已收口）：生产
/// `parse_vless_config` 接线 `with_level`/`with_email`（Go
/// `infra/conf/vless.go:247-249` outbound user 语义），与插件面逐字段相等。
#[test]
fn vless_parity_outbound_level_email() {
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
    assert_eq!((core.level, core.email.as_str()), (1, "cli@x"), "生产面接线（非 0/空串缺省）");
    let p = plugin.built_outbound().expect("built");
    assert_eq!((p.level, p.email.as_str()), (core.level, core.email.as_str()), "两侧一致");
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
    // server_addr（address:port 拼接）见下方 `hysteria_parity_outbound_server_addr_port`。
}

/// hysteria 出站 `server_addr` 对拍：插件面与生产面**逐字相等**。
///
/// Go `infra/conf/hysteria.go:13-17`：`address`=host、`port`=独立字段，拨号
/// 目标由二者合成 `host:port`（Go `protocol.NewServerSpecFromPB` →
/// `TCPDestination(address, port)`）；生产面 `parse_hysteria_config` 与插件面
/// `parse_outbound_config` 同形。插件面若只存 host 原样，B5 切组合根后拨号
/// 会打错端口。
#[test]
fn hysteria_parity_outbound_server_addr_port() {
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
    assert_eq!(p.server_addr, core.0, "插件面：address:port 拼接（与生产面一致）");
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
    let (core_device, core_port) =
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
    assert_eq!(p.listen_port, core_port, "settings 级 port 两侧一致");
}

/// wireguard 入站 `port` 对拍（原 known-divergence 钉子，已收口）：生产
/// `parse_wireguard_inbound_config` 与插件 `parse_wireguard_section` 均读
/// settings 级 `port`（键位收敛，缺省同 51820）。
#[test]
fn wireguard_parity_inbound_port_settings_level() {
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
    assert_eq!(p.listen_port, 51821, "插件面：settings 级 port 生效（与生产同键位）");
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
    let core = crate::inbound::parse_tun_inbound_config(&serde_json::to_vec(&settings).unwrap())
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

// ── ss：入站五形态（core `parse_ss_inbound_config` ↔ SsPlugin build `face()`）──
//
// 出站面不在对拍范围：生产装配 `arm_builders/outbound.rs:287` 与插件
// `plugin.rs` 出站分支调的是**同一个** `xray_proxy_ss::parse_ss_config`，同函数
// 自比无信息量（面判别本身由 `xray-proxy-ss/tests/plugin_contract.rs` 覆盖）。
// 入站面才是两套独立解析实现（`core/inbound.rs` vs `ss/plugin.rs`）。

/// 16 字节 PSK 的 base64（ss2022 aes-128-gcm 的 key 长度）。
fn b64_psk(byte: u8) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode([byte; 16])
}

/// 建 ss 插件（inbounds 段形态）并返回句柄：`face()` 借用插件内 OnceLock，
/// 句柄须在测试作用域内存活。
fn build_ss_plugin(settings: &Value) -> Arc<SsPlugin> {
    let plugin = Arc::new(SsPlugin::default());
    let built = build_plugins_from_config(
        &root_inbound_with("shadowsocks", settings.clone()),
        &[Arc::clone(&plugin) as Arc<dyn Plugin>],
    )
    .expect("plugin build");
    assert_eq!(built, ["shadowsocks"]);
    plugin
}

/// legacy 用户表逐字段比（`Validator::get_all` 是唯一公开用户观察面）。
/// 凭据走 bool 断言，失败面不打印密码/key。
fn assert_legacy_users_eq(core: &SsInbound, plugin: &SsInbound) {
    let (c, p) = (core.validator().get_all(), plugin.validator().get_all());
    assert_eq!(c.len(), p.len(), "用户数");
    for (i, (cu, pu)) in c.iter().zip(p.iter()).enumerate() {
        assert_eq!(cu.email, pu.email, "user {i} email");
        assert_eq!(cu.level, pu.level, "user {i} level");
        assert_eq!(cu.account.cipher_type, pu.account.cipher_type, "user {i} cipher");
        assert_eq!(cu.account.iv_check, pu.account.iv_check, "user {i} iv_check");
        assert!(cu.account.password == pu.account.password, "user {i} password");
        assert!(cu.account.key == pu.account.key, "user {i} key");
    }
}

/// relay destination 观察面：`RelayInbound` 只公开 `destinations_count()`，
/// address/port 仅能经 `handle_conn_relay` 的 identity 匹配返回面看到——送
/// `[salt][EIH]` 后取回 (地址, 端口)。
async fn relay_target(
    relay: &RelayInbound,
    kind: CipherKind2022,
    server_psk_b64: &str,
    dest_key_b64: &str,
) -> (Address, u16) {
    let server_psk = derive_psk(&psk_from_base64(server_psk_b64).expect("server psk"), kind)
        .expect("derive server psk");
    let dest_key = psk_from_base64(dest_key_b64).expect("dest psk");
    let salt = vec![0x5Au8; kind.key_size()];
    let subkey = derive_identity_subkey(&server_psk, &salt, kind);
    let eih = ecb_block(kind, &subkey, &psk_identity(&dest_key), true).expect("eih");
    let mut wire = salt;
    wire.extend_from_slice(&eih);
    let (mut client, server) = tokio::io::duplex(64);
    client.write_all(&wire).await.expect("write relay wire");
    drop(client);
    let (addr, port, _, _) = relay.handle_conn_relay(server).await.expect("relay identity match");
    (addr, port)
}

#[test]
fn ss_parity_legacy_single_user() {
    // 扁平 password + method：两侧都产 Legacy 单用户，email 同缺省 `u@ss.local`。
    let settings = json!({"method": "aes-256-gcm", "password": "pw-single"});
    let core = crate::inbound::parse_ss_inbound_config(&serde_json::to_vec(&settings).unwrap())
        .expect("core parse");
    let plugin = build_ss_plugin(&settings);
    let crate::inbound::SsInboundMode::Legacy(core_in) = core else {
        panic!("core 面应为 Legacy");
    };
    let SsFace::LegacyInbound(plugin_in) = plugin.face().expect("built") else {
        panic!("plugin 面应为 LegacyInbound");
    };
    assert_legacy_users_eq(&core_in, plugin_in);
    assert_eq!(core_in.validator().get_all()[0].email, "u@ss.local");
}

#[test]
fn ss_parity_legacy_multi_users_and_clients_alias() {
    // 逐用户 method（第二项缺 method → 两侧同缺省 aes-128-gcm）；`users` 主键、
    // `clients` 旧名回退（Go shadowsocks.go:46-47）。
    let users = json!([
        {"method": "aes-256-gcm", "password": "pw1", "email": "a@x"},
        {"password": "pw2", "email": "b@x"},
    ]);
    for key in ["users", "clients"] {
        let mut settings = json!({"method": "aes-128-gcm"});
        settings[key] = users.clone();
        let core = crate::inbound::parse_ss_inbound_config(&serde_json::to_vec(&settings).unwrap())
            .expect("core parse");
        let plugin = build_ss_plugin(&settings);
        let crate::inbound::SsInboundMode::Legacy(core_in) = core else {
            panic!("core 面应为 Legacy（{key}）");
        };
        let SsFace::LegacyInbound(plugin_in) = plugin.face().expect("built") else {
            panic!("plugin 面应为 LegacyInbound（{key}）");
        };
        assert_legacy_users_eq(&core_in, plugin_in);
        assert_eq!(plugin_in.validator().count(), 2, "{key} 用户数");
    }
}

#[test]
fn ss_parity_ss2022_single_user() {
    let settings = json!({"method": "2022-blake3-aes-128-gcm", "password": b64_psk(0x11)});
    let core = crate::inbound::parse_ss_inbound_config(&serde_json::to_vec(&settings).unwrap())
        .expect("core parse");
    let plugin = build_ss_plugin(&settings);
    let crate::inbound::SsInboundMode::Ss2022(core_in) = core else {
        panic!("core 面应为 Ss2022");
    };
    let SsFace::Ss2022(plugin_in) = plugin.face().expect("built") else {
        panic!("plugin 面应为 Ss2022");
    };
    assert_eq!(plugin_in.kind(), core_in.kind());
    assert!(plugin_in.psk() == core_in.psk(), "server PSK");
}

#[test]
fn ss_parity_ss2022_multi_users() {
    let (server, user_a, user_b) = (b64_psk(0x11), b64_psk(0x22), b64_psk(0x33));
    let settings = json!({
        "method": "2022-blake3-aes-128-gcm",
        "password": server,
        "users": [
            {"password": user_a, "email": "a@y", "level": 2},
            {"password": user_b, "email": "b@y", "level": 0},
        ],
    });
    let core = crate::inbound::parse_ss_inbound_config(&serde_json::to_vec(&settings).unwrap())
        .expect("core parse");
    let plugin = build_ss_plugin(&settings);
    let crate::inbound::SsInboundMode::Ss2022Multi(core_in) = core else {
        panic!("core 面应为 Ss2022Multi");
    };
    let SsFace::Ss2022Multi(plugin_in) = plugin.face().expect("built") else {
        panic!("plugin 面应为 Ss2022Multi");
    };
    assert_eq!(plugin_in.kind(), core_in.kind());
    assert!(plugin_in.server_psk() == core_in.server_psk(), "server PSK");
    assert_eq!(plugin_in.users_count(), 2);
    assert_eq!(plugin_in.users_count(), core_in.users_count());
    // udp_user_table = (psk identity, psk) 有序表（配置序）：覆盖两用户 PSK 与
    // identity 预计算；bool 比较（失败面不打印 PSK）。
    assert!(plugin_in.udp_user_table() == core_in.udp_user_table(), "identity/PSK 表");
}

/// ss2022 中继（Go 形 `users[].address`）：两侧同判 relay，destination 的
/// address/port 经行为探针逐字相等（两侧都走 `parse_address_str`）。
#[tokio::test]
async fn ss_parity_ss2022_relay_go_form() {
    let (server, dest_key) = (b64_psk(0x11), b64_psk(0x22));
    let settings = json!({
        "method": "2022-blake3-aes-128-gcm",
        "password": server.clone(),
        "users": [{
            "password": dest_key.clone(),
            "email": "relay@y",
            "level": 3,
            "address": "10.0.0.7",
            "port": 8388,
        }],
    });
    let core = crate::inbound::parse_ss_inbound_config(&serde_json::to_vec(&settings).unwrap())
        .expect("core parse");
    let plugin = build_ss_plugin(&settings);
    let crate::inbound::SsInboundMode::Ss2022Relay(core_relay) = core else {
        panic!("core 面应为 Ss2022Relay");
    };
    let SsFace::Ss2022Relay(plugin_relay) = plugin.face().expect("built") else {
        panic!("plugin 面应为 Ss2022Relay");
    };
    assert_eq!(core_relay.destinations_count(), 1);
    assert_eq!(plugin_relay.destinations_count(), core_relay.destinations_count());
    let kind = CipherKind2022::Aes128Gcm;
    let core_target = relay_target(&core_relay, kind, &server, &dest_key).await;
    assert_eq!(relay_target(plugin_relay, kind, &server, &dest_key).await, core_target);
    let ip: std::net::Ipv4Addr = "10.0.0.7".parse().expect("ipv4");
    assert_eq!(core_target, (Address::IPv4(ip), 8388));
}

/// 新登记已知差异（**只报告不修**，见 `reports/wsl-2026-10-25/parity-16.md`）：
/// ss2022 中继 `destinations[]` **旧形**的 `server` 为 IP 字面量时——core 解析面
/// 硬写 `Address::Domain`（`xray-core/src/inbound.rs` destinations 分支），插件面
/// 走 `parse_address_str` → `Address::IPv4`。域名形态两侧一致（`users[].address`
/// 的 Go 形分支见 `ss_parity_ss2022_relay_go_form`）。功能上等价（Domain(IP) 仍
/// 解析到同一 IP），但按 domain 匹配的路由规则可能分叉。
#[tokio::test]
async fn ss_known_divergence_relay_destinations_address_typing() {
    let (server, dest_key) = (b64_psk(0x11), b64_psk(0x22));
    let settings = json!({
        "method": "2022-blake3-aes-128-gcm",
        "password": server.clone(),
        "destinations": [{
            "password": dest_key.clone(),
            "email": "d@y",
            "server": "10.0.0.7",
            "server_port": 8388,
        }],
    });
    let core = crate::inbound::parse_ss_inbound_config(&serde_json::to_vec(&settings).unwrap())
        .expect("core parse");
    let plugin = build_ss_plugin(&settings);
    let crate::inbound::SsInboundMode::Ss2022Relay(core_relay) = core else {
        panic!("core 面应为 Ss2022Relay");
    };
    let SsFace::Ss2022Relay(plugin_relay) = plugin.face().expect("built") else {
        panic!("plugin 面应为 Ss2022Relay");
    };
    let kind = CipherKind2022::Aes128Gcm;
    let core_target = relay_target(&core_relay, kind, &server, &dest_key).await;
    let plugin_target = relay_target(plugin_relay, kind, &server, &dest_key).await;
    let ip: std::net::Ipv4Addr = "10.0.0.7".parse().expect("ipv4");
    assert_eq!(core_target, (Address::Domain("10.0.0.7".into()), 8388), "core 面域名包装");
    assert_eq!(plugin_target, (Address::IPv4(ip), 8388), "插件面解析成 IPv4");
}

#[test]
fn ss_parity_errors_fail_fast() {
    // 三处硬错两侧同判（禁静默回落）：未知 cipher / 缺 password / ss2022 缺 server PSK。
    for settings in [
        json!({"method": "no-such-cipher", "password": "pw"}),
        json!({"method": "aes-128-gcm"}),
        json!({"method": "2022-blake3-aes-128-gcm"}),
    ] {
        let core = crate::inbound::parse_ss_inbound_config(&serde_json::to_vec(&settings).unwrap());
        assert!(core.is_err(), "core 面应硬错: {settings}");
        let plugin = Arc::new(SsPlugin::default());
        let built = build_plugins_from_config(
            &root_inbound_with("shadowsocks", settings.clone()),
            &[Arc::clone(&plugin) as Arc<dyn Plugin>],
        );
        assert!(built.is_err(), "插件面应硬错: {settings}");
    }
}

// ── dokodemo：入站全字段（core `parse_dokodemo_settings` ↔ DokodemoPlugin built_config）──

/// 字段模型差异的语义映射：core 面 `allow_tcp`/`allow_udp` 双 bool ↔ 插件面
/// `allowed_networks`（`allows_network` 探针）；core 面 `dest` ↔ 插件面
/// `rewrite_address`+`rewrite_port`；`port_map`/`follow_redirect` 同型直比。
#[test]
fn dokodemo_parity_inbound_full_fields() {
    let settings = json!({
        "address": "1.2.3.4",
        "port": 8080,
        "network": "tcp,udp",
        "portMap": { "80": "192.168.99.1:9090" },
    });
    let core = crate::inbound::parse_dokodemo_settings(&serde_json::to_vec(&settings).unwrap())
        .expect("core parse");
    let plugin = Arc::new(DokodemoPlugin::default());
    let built = build_plugins_from_config(
        &root_inbound_with("dokodemo-door", settings),
        &[Arc::clone(&plugin) as Arc<dyn Plugin>],
    )
    .expect("plugin build");
    assert_eq!(built, ["dokodemo-door"]);
    let p = plugin.built_config().expect("built");
    // 网络面（core 双 bool ↔ 插件 allowed_networks）。
    assert!(core.allow_tcp && core.allow_udp, "样本 tcp,udp → 两侧双放行");
    assert!(p.allows_network(DokodemoNetwork::Tcp), "插件 TCP 放行");
    assert!(p.allows_network(DokodemoNetwork::Udp), "插件 UDP 放行");
    // 预定义目标（core dest ↔ 插件 rewrite_address + rewrite_port）。
    let dest = core.dest.expect("address 在场 → dest Some");
    let Some(PredefinedAddress::Ip(ip)) = p.predefined_address() else {
        panic!("rewrite_address 应解析为 IP");
    };
    assert_eq!(
        dest.address(),
        &xray_common::net::address::Address::from_ipv4_bytes([1, 2, 3, 4]),
        "core dest.address ↔ 插件 rewrite_address"
    );
    assert_eq!(ip, std::net::Ipv4Addr::new(1, 2, 3, 4));
    assert_eq!(
        dest.port().value(),
        u16::try_from(p.rewrite_port).expect("rewrite_port u16"),
        "core dest.port ↔ 插件 rewrite_port"
    );
    assert_eq!(core.follow_redirect, p.follow_redirect);
    assert_eq!(core.port_map, p.port_map);
}

// ── tuic：入站全字段（core `parse_tuic_inbound_settings` ↔ TuicPlugin built_config）──

/// bind_addr 两侧来源不同（core 面由装配层传 listener 地址串；插件面从段级
/// `listen`+`port` 合成），样本对齐成同一 SocketAddr 后逐字段比。sockopt 不比
/// （core 面由装配层 streamSettings 注入，解析面样本无此输入）。
#[test]
fn tuic_parity_inbound_full_fields() {
    let settings = json!({
        "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
        "password": "pw1",
        "serverName": "relay.example.com",
        "congestion_control": "hysteria_bbr",
        "brutal_up_bps": 0,
    });
    let config = json!({ "inbounds": [{
        "protocol": "tuic",
        "listen": "127.0.0.1",
        "port": 8443,
        "settings": settings,
    }] });
    let core = crate::inbound::parse_tuic_inbound_settings(
        &serde_json::to_vec(&settings).unwrap(),
        "127.0.0.1:8443",
    )
    .expect("core parse");
    let plugin = Arc::new(TuicPlugin::default());
    let built = build_plugins_from_config(&config, &[Arc::clone(&plugin) as Arc<dyn Plugin>])
        .expect("plugin build");
    assert_eq!(built, ["tuic"]);
    let p = plugin.built_config().expect("built");
    assert_eq!(core.bind_addr, p.listen);
    assert_eq!(core.server_name, p.server_name);
    assert_eq!(core.uuid, p.uuid);
    assert_eq!(core.password, p.password);
    assert_eq!(core.cert_der, p.cert_der, "无 certificate → 两侧 None（自签延迟到 start）");
    assert_eq!(core.key_der, p.key_der);
    assert_eq!(core.congestion_control, p.congestion_control);
    assert_eq!(core.brutal_up_bps, p.brutal_up_bps);
}

// ═══════════════════════════════════════════════════════════════════════════
// 16 族覆盖出口（bd hw6w）：名称清单 + 总数断言。
//
// 表内每条 = 「族 → 该族的对拍用例名」；用例名即 cargo test 输出里的可 grep
// 面。本表与实现同步由两条断言保证：族数 16、用例名总数与模块内对拍用例数
// 一致（新增/删除用例而不更新本表 → 红）。
// ═══════════════════════════════════════════════════════════════════════════

const PARITY_FAMILIES: [(&str, &[&str]); 16] = [
    (
        "socks",
        &[
            "socks_parity_password_auth_full_fields",
            "socks_parity_defaults_when_settings_empty",
            "socks_parity_inbounds_layout_users_alias",
        ],
    ),
    (
        "freedom",
        &[
            "freedom_parity_strategy_override_and_final_rules",
            "freedom_parity_target_strategy_priority",
            "freedom_known_divergence_fragment_noises",
        ],
    ),
    (
        "blackhole",
        &[
            "blackhole_parity_http_response",
            "blackhole_parity_custom_response_base64",
            "blackhole_parity_missing_response_is_none",
        ],
    ),
    ("vless", &["vless_parity_outbound_vnext_fields", "vless_parity_outbound_level_email"]),
    ("vmess", &["vmess_parity_inbound_validator_users"]),
    ("trojan", &["trojan_parity_inbound_validator_and_fallbacks"]),
    ("http", &["http_parity_inbound_users_alias_transparent_level"]),
    ("dns", &["dns_parity_outbound_rule_and_rewrite"]),
    (
        "hysteria",
        &["hysteria_parity_outbound_flat_fields", "hysteria_parity_outbound_server_addr_port"],
    ),
    ("anytls", &["anytls_parity_outbound_password_and_server"]),
    (
        "wireguard",
        &["wireguard_parity_inbound_device_fields", "wireguard_parity_inbound_port_settings_level"],
    ),
    ("loopback", &["loopback_parity_outbound_inbound_tag"]),
    ("tun", &["tun_parity_inbound_stack_options_fields"]),
    (
        "ss",
        &[
            "ss_parity_legacy_single_user",
            "ss_parity_legacy_multi_users_and_clients_alias",
            "ss_parity_ss2022_single_user",
            "ss_parity_ss2022_multi_users",
            "ss_parity_ss2022_relay_go_form",
            "ss_known_divergence_relay_destinations_address_typing",
            "ss_parity_errors_fail_fast",
        ],
    ),
    ("dokodemo", &["dokodemo_parity_inbound_full_fields"]),
    ("tuic", &["tuic_parity_inbound_full_fields"]),
];

#[test]
fn parity_roster_covers_all_16_families() {
    assert_eq!(PARITY_FAMILIES.len(), 16, "16 族全覆盖");
    let mut families = std::collections::BTreeSet::new();
    let mut cases = Vec::new();
    for (family, tests) in PARITY_FAMILIES {
        assert!(families.insert(family), "{family} 重复登记");
        assert!(!tests.is_empty(), "{family} 缺对拍用例");
        cases.extend_from_slice(tests);
    }
    let unique: std::collections::BTreeSet<_> = cases.iter().copied().collect();
    assert_eq!(unique.len(), cases.len(), "用例名重复登记");
    // 族内用例总数（本表外的 2 个 #[test]：缺段 fail-fast 反向控制 + 本表自身）。
    assert_eq!(unique.len(), 31, "16 族对拍用例总数");
}
