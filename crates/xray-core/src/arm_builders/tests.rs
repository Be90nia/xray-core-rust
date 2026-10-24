//! T4.2 phase 2：构造侧查表 vs match 两路等价性测试。
//!
//! - outbound：17 个协议逐个以同一 `BuiltOutbound` 走 `match_protocol_handler` （真 match
//!   本体，不经 feature 门）与查表适配器，断言 tag / bridge_ref 在场 性 / proxy_chain 回显 / mux
//!   注册副作用一致。
//! - inbound：17 协议（含 hysteria2 双键别名）断言表映射到与 match 臂同一适配器 函数（fn
//!   指针等同）；loopback（无 bind 副作用）追加 e2e 两路对照。
//!
//! **无法比较项（显式清单）**：
//! 1. inbound 16 个需真实 bind/spawn 的协议——e2e 对照需双路径各占真实端口， 不纳入；其等价性由「fn
//!    指针等同 + 两路消费同一 InboundCtx 前置换算 + phase 1 构造函数唯一」结构保证。
//! 2. outbound dial_fn 闭包内的拨号目标/网络——`Arc<dyn DispatchHandler>` 表面 无 Any
//!    下转口，不可观测；以上述四项可观测代理属性替代。
//! 3. outbound `tun`（linux/android/freebsd 门控）——本表与 match 臂两侧对称 缺席，Windows
//!    测试主机不可构造。
//! 4. dispatch 期行为——phase 3+ 范畴。

use std::{collections::HashMap, sync::Arc};

use serde_json::json;
use tokio_util::sync::CancellationToken;
use xray_app_dispatcher::default::SimpleOhm;
use xray_conf::{BuiltEntry, BuiltInbound, BuiltOutbound};

use super::{InboundCtx, OutboundCtx, lookup_inbound_builder, lookup_outbound_builder};
use crate::{inbound::spawn_one_inbound, outbound::match_protocol_handler};

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

/// 表查 vs match（真 match 本体，两 feature 态下均为同一函数）：17 协议逐个
/// 断言构建成功 + tag / bridge_ref 在场性 / proxy_chain 回显 / mux 副作用一致。
/// `#[tokio::test]`：anytls 构造期需 tokio runtime 上下文（anytls 0.3.5
/// client.rs:49 reactor 要求；match 侧同要求，两侧一致）。
#[tokio::test]
async fn arm_lookup_outbound_table_matches_match_path() {
    let empty_rules: HashMap<String, xray_proxy_freedom::DefaultRuleType> = HashMap::new();
    for (protocol, settings, stream) in outbound_cases() {
        let ob = ob_of(protocol, &settings, stream.as_ref());
        let mut bridges_match = Vec::new();
        let (h1, b1, c1) = match_protocol_handler(
            &ob,
            None,
            &mut bridges_match,
            None,
            &empty_rules,
            None,
            None,
            None,
            None,
        )
        .unwrap_or_else(|e| panic!("{protocol}: match path build failed: {e:?}"));
        let entry = lookup_outbound_builder(protocol)
            .unwrap_or_else(|| panic!("{protocol}: missing from outbound table"));
        let mut bridges_table = Vec::new();
        let (h2, b2, c2) = entry(OutboundCtx {
            ob: &ob,
            loopback_sink: None,
            mux_bridges: &mut bridges_table,
            dns: None,
            inbound_default_rules: &empty_rules,
            policy_manager: None,
            proxy_chain_tag: None,
            target_strategy: None,
            send_through: None,
        })
        .unwrap_or_else(|e| panic!("{protocol}: table path build failed: {e:?}"));
        assert_eq!(h1.tag(), h2.tag(), "{protocol}: handler tag diverges");
        assert_eq!(b1.is_some(), b2.is_some(), "{protocol}: bridge_ref presence diverges");
        assert_eq!(c1, c2, "{protocol}: proxy_chain echo diverges");
        assert_eq!(
            bridges_match.len(),
            bridges_table.len(),
            "{protocol}: mux registration side effect diverges"
        );
    }
}

/// inbound 表完备性 + fn 指针等同：17 协议（含 hysteria 双键别名）的表值必须
/// 是 match 臂通往的同一适配器函数；tun（match 前早退）与未知协议对称无键。
#[test]
fn arm_lookup_inbound_table_covers_match_arms() {
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
            "{protocol}: table must map to the same adapter the match arm reaches"
        );
    }
    // tun 在 match 前早退（tun 不经构造分派），表内对称无键。
    assert!(lookup_inbound_builder("tun").is_none());
    // 未知协议无键 → 切换点回落 match wildcard warn（语义与 match other 臂一致）。
    assert!(lookup_inbound_builder("no-such-protocol").is_none());
}

/// loopback inbound（无 bind 副作用的唯一臂）：spawn_one_inbound（含前置逻辑 +
/// match 本体）与查表适配器两路 e2e 对照，均须 `Ok(None)`。
#[tokio::test]
async fn arm_lookup_inbound_loopback_table_matches_match_path() {
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
        .expect("match path spawn");
    assert!(r1.is_none(), "loopback match path must be Ok(None)");
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
