//! T4.2 phase 4：构造表是唯一构造路径的测试。
//!
//! - outbound：17 个协议逐个经生产入口 `build_protocol_handler`（表分派）构建成功， 断言 handler
//!   tag 回显 / proxy_chain 回显 / mux 注册副作用。
//! - inbound：17 协议（含 hysteria2 双键别名）断言表映射到对应适配器（fn 指针等同）； loopback（无
//!   bind 副作用）追加 e2e 对照。
//! - 表未命中：显式可见失败（outbound `Unsupported` / inbound warn+skip），不静默构造。
//!
//! **无法对照项（显式清单）**：
//! 1. inbound 16 个需真实 bind/spawn 的协议——e2e 对照需各占真实端口，不纳入；其 等价性由「fn
//!    指针等同 + 入口与表值消费同一 InboundCtx 前置换算 + phase 1 构造 函数唯一」结构保证。
//! 2. outbound dial_fn 闭包内的拨号目标/网络——`Arc<dyn DispatchHandler>` 表面无 Any
//!    下转口，不可观测；以上述可观测代理属性替代。
//! 3. outbound `tun`（linux/android/freebsd 门控）——Windows 测试主机只能覆盖拒绝臂，
//!    不纳入可构造协议集。
//! 4. dispatch 期行为——非构造侧范畴。

use std::{collections::HashMap, sync::Arc};

use serde_json::json;
use tokio_util::sync::CancellationToken;
use xray_app_dispatcher::default::SimpleOhm;
use xray_conf::{BuiltEntry, BuiltInbound, BuiltOutbound};

use super::InboundCtx;
use crate::{
    arm_registry::{lookup_inbound_builder, lookup_outbound_builder},
    inbound::spawn_one_inbound,
    outbound::{BuildError, build_protocol_handler, register_outbounds},
};

/// 17 个出站协议 + 2 个 Go 老式别名（`direct`/`block`）的最小可构造 settings
/// （与 tests_config_parity 同源形态）。
/// 元组第三项 = streamSettings（hysteria 构造期硬错要求 security=tls，
/// 其余协议 None 即可）。
fn outbound_cases() -> Vec<(&'static str, serde_json::Value, Option<serde_json::Value>)> {
    let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
    vec![
        ("freedom", json!({}), None),
        (
            "vless",
            json!({"vnext":[{"address":"1.2.3.4","port":443,"users":[{"id":uuid,"encryption":"none"}]}]}),
            None,
        ),
        ("trojan", json!({"servers":[{"address":"1.2.3.4","port":443,"password":"pw"}]}), None),
        ("blackhole", json!({}), None),
        ("socks", json!({"servers":[{"address":"1.2.3.4","port":1080}]}), None),
        ("mux", json!({"concurrency": 8}), None),
        ("vmess", json!({"vnext":[{"address":"1.2.3.4","port":443,"users":[{"id":uuid}]}]}), None),
        (
            "shadowsocks",
            json!({"servers":[{"address":"1.2.3.4","port":8388,"method":"aes-128-gcm","password":"pw"}]}),
            None,
        ),
        (
            "hysteria",
            json!({"address":"1.2.3.4","port":443,"auth":"pw"}),
            Some(json!({"security": "tls"})),
        ),
        ("anytls", json!({"server":"1.2.3.4","server_port":443,"password":"pw"}), None),
        (
            "tuic",
            json!({"servers":[{"address":"1.2.3.4","port":443,"uuid":uuid,"password":"pw"}]}),
            None,
        ),
        ("wireguard", json!({"secretKey": "aa".repeat(32), "peers": []}), None),
        ("dns", json!({"servers":["8.8.8.8:53"]}), None),
        ("loopback", json!({"inboundTag": "in-main"}), None),
        ("http", json!({"servers":[{"address":"1.2.3.4","port":8080}]}), None),
        ("naive", json!({"server":"1.2.3.4","port":443,"username":"u","password":"p"}), None),
        ("dokodemo", json!({"address":"1.2.3.4","port":443}), None),
        // Go 老式别名（infra/conf/xray.go:42-46：`direct`→FreedomConfig、
        // `block`→BlackholeConfig）——生产注册表 + 构造表两级都要命中（bd pjg6n）。
        ("direct", json!({}), None),
        ("block", json!({}), None),
    ]
}

fn ob_of(
    protocol: &str,
    settings: &serde_json::Value,
    stream: Option<&serde_json::Value>,
) -> BuiltOutbound {
    BuiltOutbound {
        entry: BuiltEntry {
            kind: protocol.to_string(),
            data: serde_json::to_vec(settings).expect("settings serialize"),
        },
        tag: "t-arm-lookup".to_string(),
        send_through: None,
        stream_settings_json: stream.cloned(),
        proxy_settings_json: None,
        mux_json: None,
        target_strategy: None,
    }
}

/// 表是唯一构造路径（旧 match 已删）：17 协议逐个经生产入口
/// `build_protocol_handler` 构建成功，断言 handler tag 回显出站 tag / 无 proxy_chain
/// 配置时回显 None / mux 注册副作用恰好一次。
/// `#[tokio::test]`：anytls 构造期需 tokio runtime 上下文（anytls 0.3.5
/// client.rs:49 reactor 要求）。
#[tokio::test]
async fn arm_lookup_outbound_entry_builds_every_protocol() {
    let empty_rules: HashMap<String, xray_proxy_freedom::DefaultRuleType> = HashMap::new();
    for (protocol, settings, stream) in outbound_cases() {
        let ob = ob_of(protocol, &settings, stream.as_ref());
        let mut bridges = Vec::new();
        let (handler, _bridge_ref, proxy_chain) =
            build_protocol_handler(&ob, None, &mut bridges, None, &empty_rules, None)
                .unwrap_or_else(|e| panic!("{protocol}: table build failed: {e:?}"));
        assert_eq!(
            handler.tag(),
            ob.tag.as_str(),
            "{protocol}: handler tag must echo outbound tag"
        );
        assert!(
            proxy_chain.is_none(),
            "{protocol}: proxy_chain must stay None without proxySettings"
        );
        assert_eq!(
            bridges.len(),
            usize::from(protocol == "mux"),
            "{protocol}: mux registration side effect"
        );
    }
}

/// inbound 表完备性 + fn 指针等同：20 协议（含 hysteria 双键别名 + dokodemo 双键 +
/// Go 老式 `tunnel` 别名 + tun）的表值必须指向对应适配器函数；UDS 形态槽必须恰好
/// 登记 5 个裸流 + 4 个 transport 协议（原手写白名单/inline match 的替代真源）。
#[test]
fn arm_lookup_inbound_table_is_complete() {
    use super::{InboundBuilder, inbound as entries};

    let cases: &[(&str, InboundBuilder)] = &[
        ("socks", entries::socks_entry),
        ("mixed", entries::mixed_entry),
        ("vless", entries::vless_entry),
        ("trojan", entries::trojan_entry),
        ("vmess", entries::vmess_entry),
        ("http", entries::http_entry),
        ("dokodemo", entries::dokodemo_entry),
        // Go 注册名（同臂别名键）：配置按 Go 文档写 `dokodemo-door` 必须命中。
        ("dokodemo-door", entries::dokodemo_entry),
        // Go 老式别名（infra/conf/xray.go:29）：`tunnel` → DokodemoConfig。
        ("tunnel", entries::dokodemo_entry),
        ("shadowsocks", entries::shadowsocks_entry),
        ("hysteria", entries::hysteria_entry),
        ("hysteria2", entries::hysteria_entry),
        ("anytls", entries::anytls_entry),
        ("tuic", entries::tuic_entry),
        ("naive", entries::naive_entry),
        ("wireguard", entries::wireguard_entry),
        ("dns", entries::dns_entry),
        ("loopback", entries::loopback_entry),
        ("blackhole", entries::blackhole_entry),
        ("freedom", entries::freedom_entry),
        ("tun", entries::tun_entry),
    ];
    for (protocol, expected) in cases {
        let got = lookup_inbound_builder(protocol)
            .unwrap_or_else(|| panic!("{protocol}: missing from inbound table"));
        assert_eq!(
            got.stream as usize, *expected as usize,
            "{protocol}: table must map to the expected adapter"
        );
    }
    // UDS 形态槽（bd 7y07s）：裸流 5 协议 / transport 4 协议——原
    // `UDS_SUPPORTED_PROTOCOLS` 白名单与两处 inline match 的真源。
    let uds_streams: Vec<&str> = ["socks", "vless", "vmess", "trojan", "shadowsocks"]
        .into_iter()
        .filter(|p| lookup_inbound_builder(p).expect("key").uds_stream.is_some())
        .collect();
    assert_eq!(uds_streams, ["socks", "vless", "vmess", "trojan", "shadowsocks"]);
    let uds_transports: Vec<&str> = ["vless", "vmess", "trojan", "shadowsocks"]
        .into_iter()
        .filter(|p| lookup_inbound_builder(p).expect("key").uds_transport.is_some())
        .collect();
    assert_eq!(uds_transports, ["vless", "vmess", "trojan", "shadowsocks"]);
    // 其余协议无 UDS 形态（UDS 入口据此显式 Unsupported，不静默回落 TCP）。
    for protocol in
        ["mixed", "http", "dokodemo", "dokodemo-door", "anytls", "tuic", "hysteria", "dns"]
    {
        let ctor = lookup_inbound_builder(protocol).expect("key");
        assert!(
            ctor.uds_stream.is_none() && ctor.uds_transport.is_none(),
            "{protocol}: 不应有 UDS 形态"
        );
    }
    // tun 自管监听面：不消费 listen 地址（入口不解析 port/addr，平台门控在表值内）。
    assert!(!lookup_inbound_builder("tun").expect("tun").needs_listen_addr);
    // 未知协议无键 → 入口显式 warn+skip（见 arm_lookup_missing_key_fails_visible）。
    assert!(lookup_inbound_builder("no-such-protocol").is_none());
}

/// loopback inbound（无 bind 副作用的唯一臂）：生产入口 `spawn_one_inbound`
/// （含前置逻辑 + 表分派）与直接调用表值两路 e2e 对照，均须 `Ok(None)`。
#[tokio::test]
async fn arm_lookup_inbound_loopback_entry_matches_table_value() {
    let ib = BuiltInbound {
        entry: BuiltEntry {
            kind: "loopback".to_string(),
            data: serde_json::to_vec(&json!({"inboundTag": "in-main"})).expect("settings"),
        },
        tag: "t-arm-lookup-in".to_string(),
        // port 必须在场以越过「inbound has no port」早退；loopback 臂自身不 bind。
        port: Some(1),
        listen: Some("127.0.0.1".to_string()),
        stream_settings_json: None,
        sniffing_json: None,
    };
    let token = CancellationToken::new();
    let r1 = spawn_one_inbound(&ib, Arc::new(SimpleOhm::new()), None, token.clone(), None)
        .await
        .expect("entry spawn");
    assert!(r1.is_none(), "loopback entry path must be Ok(None)");
    let entry = lookup_inbound_builder("loopback").expect("loopback missing from inbound table");
    let settings = xray_transport::dialer::StreamSettings::from_json(None);
    let r2 = (entry.stream)(InboundCtx {
        ib: &ib,
        ohm: Arc::new(SimpleOhm::new()),
        policy: None,
        shutdown_token: token,
        addr: "127.0.0.1:1",
        settings: &settings,
        api: None,
        plugin_ctx: xray_frame::PluginContext::for_plugin("loopback"),
    })
    .await
    .expect("table path spawn");
    assert!(r2.is_none(), "loopback table path must be Ok(None)");
}

/// 表未命中必须显式可见（表是唯一构造路径，无 match 可回落）：未注册协议得
/// outbound `Err(Unsupported(协议名))` / inbound `Err(InvalidInput, "unknown
/// inbound protocol: …")`（bd vdl95 fail-visible：Go「unknown protocol」硬错，
/// 旧行为 warn+skip 会让节点静默消失、端口无监听而管理员无感），绝不静默构造
/// handler。
#[tokio::test]
async fn arm_lookup_missing_key_fails_visible() {
    const UNKNOWN: &str = "no-such-protocol";
    assert!(lookup_outbound_builder(UNKNOWN).is_none(), "unknown key must be absent");
    assert!(lookup_inbound_builder(UNKNOWN).is_none(), "unknown key must be absent");

    let empty_rules: HashMap<String, xray_proxy_freedom::DefaultRuleType> = HashMap::new();
    let mut bridges = Vec::new();
    let ob = ob_of(UNKNOWN, &json!({}), None);
    match build_protocol_handler(&ob, None, &mut bridges, None, &empty_rules, None) {
        Err(BuildError::Unsupported(kind)) => assert_eq!(kind, UNKNOWN),
        Err(other) => panic!("{UNKNOWN}: expected Unsupported, got {other:?}"),
        Ok(_) => panic!("{UNKNOWN}: table miss must not construct a handler"),
    }
    assert!(bridges.is_empty(), "{UNKNOWN}: table miss must not register mux bridges");

    let ib = BuiltInbound {
        entry: BuiltEntry { kind: UNKNOWN.to_string(), data: b"{}".to_vec() },
        tag: "t-arm-lookup-miss".to_string(),
        port: Some(1),
        listen: Some("127.0.0.1".to_string()),
        stream_settings_json: None,
        sniffing_json: None,
    };
    let spawned =
        spawn_one_inbound(&ib, Arc::new(SimpleOhm::new()), None, CancellationToken::new(), None)
            .await;
    match spawned {
        Err(e) => {
            assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput, "got: {e}");
            assert!(
                e.to_string().contains(&format!("unknown inbound protocol: {UNKNOWN}")),
                "error must name the protocol: {e}"
            );
        },
        Ok(spawned) => panic!(
            "{UNKNOWN}: inbound table miss must fail-visible (bd vdl95), got Ok({spawned:?})"
        ),
    }
}

// ============ bd pjg6n / bd 16uis 回归 ============

fn built_from_json(json: serde_json::Value) -> xray_conf::BuiltConfig {
    xray_conf::Config::from_json_str(&json.to_string())
        .expect("config json parses")
        .build()
        .expect("config builds")
}

/// bd pjg6n：Go 老式 outbound 别名 `direct`→freedom、`block`→blackhole 必须走完
/// **生产注册表**（`register_outbounds`，o91s4 的整配置拒启面）——否则 Go 合法
/// 配置在装配期未命中即拒启。
#[tokio::test]
async fn go_legacy_outbound_aliases_assemble_via_register_outbounds() {
    let built = built_from_json(json!({
        "outbounds": [
            {"tag": "direct", "protocol": "direct"},
            {"tag": "blocked", "protocol": "block"}
        ]
    }));
    let ohm = SimpleOhm::new();
    register_outbounds(&built, &ohm, None, None, None)
        .expect("`direct`/`block` are legal Go protocols, must assemble not reject");
    let tags = ohm.list_tags();
    assert!(tags.iter().any(|t| t == "direct"), "direct alias must register: {tags:?}");
    assert!(tags.iter().any(|t| t == "blocked"), "block alias must register: {tags:?}");
}

/// bd 16uis（a）：端口越界必须报错，不得 `as u16` 静默回绕（70000 → 4464）。
#[test]
fn inbound_port_out_of_range_is_error_not_wraparound() {
    for (what, result) in [
        (
            "dokodemo",
            crate::inbound::parse_dokodemo_settings(br#"{"address":"1.2.3.4","port":70000}"#)
                .map(|_| ()),
        ),
        (
            "freedom",
            crate::inbound::parse_freedom_inbound_dest(br#"{"address":"1.2.3.4","port":70000}"#)
                .map(|_| ()),
        ),
    ] {
        let err = result.expect_err("port 70000 must be rejected, not wrapped to 4464");
        assert!(err.to_string().contains("70000"), "{what}: error must name the value: {err}");
    }
    // 边界值合法（65535 不报错）。
    crate::inbound::parse_dokodemo_settings(br#"{"address":"1.2.3.4","port":65535}"#)
        .expect("65535 is a valid port");
}

/// bd 16uis（c）：mux `via` 指向不存在的出站必须拒启，不得回落 default
/// （default 若是 freedom 则用户以为在走代理、实际明文直连）。
#[tokio::test]
async fn mux_via_unknown_tag_rejects_config() {
    let built = built_from_json(json!({
        "outbounds": [
            {"tag": "muxed", "protocol": "mux", "settings": {"concurrency": 4, "via": "ghost"}},
            {"tag": "direct", "protocol": "freedom"}
        ]
    }));
    let err = register_outbounds(&built, &SimpleOhm::new(), None, None, None)
        .expect_err("mux via `ghost` must reject the config (bd 16uis)");
    assert!(err.to_string().contains("ghost"), "error must name the via tag: {err}");

    // 正向对照：via 指向在场出站正常装配。
    let built = built_from_json(json!({
        "outbounds": [
            {"tag": "muxed", "protocol": "mux", "settings": {"concurrency": 4, "via": "direct"}},
            {"tag": "direct", "protocol": "freedom"}
        ]
    }));
    register_outbounds(&built, &SimpleOhm::new(), None, None, None)
        .expect("mux via pointing at a registered outbound must assemble");
}

/// bd 16uis（b）：blackhole outbound 坏 settings JSON 必须报错（旧实现静默
/// `ResponseConfig::None`，用户以为配了 HTTP 403 回包）。
#[test]
fn blackhole_outbound_response_bad_json_is_error() {
    let err = crate::outbound::parse_blackhole_response(b"{not json")
        .expect_err("bad JSON must not silently degrade to ResponseConfig::None");
    assert!(err.contains("blackhole outbound settings JSON"), "got: {err}");
    // 缺省 settings（空字节）仍是 None，不是错——Go `{}` 同义。
    assert_eq!(
        crate::outbound::parse_blackhole_response(b"").expect("empty settings is legal"),
        xray_proxy_blackhole::ResponseConfig::None
    );
}

/// bd 16uis（d）：app kind 无 factory 必须拒启（旧实现 warn+skip，app 静默不生效）。
#[test]
fn app_kind_without_factory_is_fatal() {
    let built = xray_conf::BuiltConfig {
        apps: vec![BuiltEntry { kind: "no-such-app-kind".to_string(), data: b"{}".to_vec() }],
        ..xray_conf::BuiltConfig::default()
    };
    match crate::instance::Instance::new_from_built(&built) {
        Err(xray_features::FeatureError::NotFound { name }) => {
            assert_eq!(name, "no-such-app-kind");
        },
        Err(other) => panic!("expected NotFound, got {other:?}"),
        Ok(_) => panic!("unknown app kind must reject the instance, not warn+skip"),
    }
}
