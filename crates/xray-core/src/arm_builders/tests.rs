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

use super::{InboundCtx, lookup_inbound_builder, lookup_outbound_builder};
use crate::{
    inbound::spawn_one_inbound,
    outbound::{BuildError, build_protocol_handler},
};

/// 17 个出站协议的最小可构造 settings（与 tests_config_parity 同源形态）。
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

/// inbound 表完备性 + fn 指针等同：17 协议（含 hysteria 双键别名）的表值必须
/// 指向对应适配器函数；tun（入口内联处理，不经表分派）与未知协议无键。
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
    ];
    for (protocol, expected) in cases {
        let got = lookup_inbound_builder(protocol)
            .unwrap_or_else(|| panic!("{protocol}: missing from inbound table"));
        assert_eq!(
            got as usize, *expected as usize,
            "{protocol}: table must map to the expected adapter"
        );
    }
    // tun inbound 在 spawn_one_inbound 内联处理（持有 TUN 设备的专用构造 / 平台
    // 拒绝），不经表分派——表内刻意无键。
    assert!(lookup_inbound_builder("tun").is_none());
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
    let r2 = entry(InboundCtx {
        ib: &ib,
        ohm: Arc::new(SimpleOhm::new()),
        policy: None,
        shutdown_token: token,
        addr: "127.0.0.1:1",
        settings: &settings,
        api: None,
    })
    .await
    .expect("table path spawn");
    assert!(r2.is_none(), "loopback table path must be Ok(None)");
}

/// 表未命中必须显式可见（表是唯一构造路径，无 match 可回落）：未注册协议得
/// outbound `Err(Unsupported(协议名))` / inbound `Ok(None)`（warn 后跳过），绝不
/// 静默构造 handler。
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
            .await
            .expect("unsupported inbound must skip, not error");
    assert!(spawned.is_none(), "{UNKNOWN}: inbound miss must skip without spawning");
}
