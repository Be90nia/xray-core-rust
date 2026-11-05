//! bd zg6eg P0-1：xdns 配置方言对齐 Go v26.10.17（`infra/conf/transport_finalmask.go:815-911`）。
//!
//! 走**生产入口** [`xray_transport::finalmask::build_udpmask_manager_from_json`]
//! （dialer 装配链的真实调用点），锁住三件事：
//!
//! 1. Go 形态 `XDNS{domains[{names}], resolvers[{addrs[], worker, tlsConfig, quicConfig}],
//!    extraPoll}` 能被读入（此前强制 `type`+`settings` 键，Go 写的配置整段读不进）；
//! 2. Rust 旧方言（`type`/`settings`）硬错指路——它 Go 侧是未知键（静默忽略 → xdns
//!    实际失效），禁再产；
//! 3. `https`（DOH）Go 支持但本栈未实现 → 配置期点名报错，不静默降级成 udp。
//!
//! 字段级断言（type/addr/worker/tls/quic 逐项）在 `src/finalmask/xdns/mod.rs` 单测。

use xray_transport::finalmask::build_udpmask_manager_from_json;

fn udpmask(settings: serde_json::Value) -> serde_json::Value {
    serde_json::json!({ "udp": [{ "type": "xdns", "settings": settings }] })
}

/// Go 形态：多 addrs + worker + tlsConfig + quicConfig + domains(names) + extraPoll。
#[test]
fn go_shaped_xdns_config_loads() {
    let json = udpmask(serde_json::json!({
        "domains": [{ "names": ["t.example.com"], "lenLimit": 200, "labelLimit": 50, "types": [16] }],
        "resolvers": [{
            "addrs": ["8.8.8.8", "tcp://94.140.14.14:5353", "udp://[2001:4860:4860::8888]:53"],
            "worker": 8,
            "tlsConfig": { "serverName": "dns.google", "alpn": ["h2"] },
            "quicConfig": { "congestion": "bbr", "maxIdleTimeout": 30 }
        }],
        "extraPoll": 3
    }));
    build_udpmask_manager_from_json(Some(&json)).expect("Go 形态 xdns 配置必须可读入");
}

/// 缺省形态：只给 addrs（worker 缺省 32、端口缺省 53）；domains 不给 types
/// （运行期按侧取缺省）同样是合法 Go 配置。
#[test]
fn go_shaped_xdns_config_minimal_loads() {
    let json = udpmask(serde_json::json!({
        "domains": [{ "names": ["t.example.com"] }],
        "resolvers": [{ "addrs": ["8.8.8.8"] }]
    }));
    build_udpmask_manager_from_json(Some(&json)).expect("缺省形态必须可读入");
}

/// Rust 旧方言（`type` + `settings.addr`）不是 Go 键 → 硬错并指路 `addrs`。
#[test]
fn legacy_rust_dialect_rejected() {
    let json = udpmask(serde_json::json!({
        "domains": [{ "names": ["t.example.com"], "types": [16] }],
        "resolvers": [{ "type": "udp", "settings": { "addr": "8.8.8.8:53" } }]
    }));
    let Err(e) = build_udpmask_manager_from_json(Some(&json)) else {
        panic!("旧方言必须硬错");
    };
    assert!(e.to_string().contains("addrs"), "错误须指路 addrs：{e}");
}

/// https(DOH)：Go 支持、本栈未实现 → 配置期点名（禁静默改成 udp）。
#[test]
fn doh_resolver_rejected_loudly() {
    let json = udpmask(serde_json::json!({
        "resolvers": [{ "addrs": ["https://dns.google/dns-query"], "worker": 8,
                        "tlsConfig": { "serverName": "dns.google" } }]
    }));
    let Err(e) = build_udpmask_manager_from_json(Some(&json)) else {
        panic!("DOH 必须硬错");
    };
    assert!(e.to_string().contains("DOH"), "错误须点明 DOH：{e}");
}

/// 未知 scheme（Go `:903-904` → "invalid protocol"）同样配置期硬错。
#[test]
fn unknown_scheme_rejected() {
    let json = udpmask(serde_json::json!({ "resolvers": [{ "addrs": ["quic://8.8.8.8:53"] }] }));
    let Err(e) = build_udpmask_manager_from_json(Some(&json)) else {
        panic!("未知 scheme 必须硬错");
    };
    assert!(e.to_string().contains("invalid protocol"), "错误须为 Go 文案：{e}");
}
