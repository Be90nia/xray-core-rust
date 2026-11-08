//! 集成测试：trojan `flow` 三路语义一致 —— Go `infra/conf/trojan.go:73-75`（客户端
//! servers 逐项）与 `:134-136`（服务端 clients 逐用户）都 `PrintRemovedFeatureError`
//! ⇒ **整配置加载失败**。
//!
//! 链路证明（与 `invalid_inline_cert_startup.rs` 同型）：
//! - 入站 `start_full` → `spawn_inbounds`（`?`）→ `spawn_one_inbound`（`?`）→
//!   `build_trojan_inbound` → `build_trojan_users` Err；
//! - 出站 `start_full` → `register_outbounds` 任一条目 Err → 整配置拒启。
//!
//! 对照组：同一配置去掉 `flow` 后必须正常启动（证明报错来自 flow 而非无关缺口）。

use xray_conf::Config;
use xray_core::start_full;

fn inbound_config_json(settings: serde_json::Value) -> String {
    serde_json::json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "trojan-in",
            "listen": "127.0.0.1",
            "port": 12829,
            "protocol": "trojan",
            "settings": settings
        }],
        "outbounds": [{"protocol": "freedom", "tag": "direct"}]
    })
    .to_string()
}

fn outbound_config_json(server: serde_json::Value) -> String {
    serde_json::json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": 0,
            "protocol": "socks",
            "settings": {}
        }],
        "outbounds": [{"protocol": "trojan", "tag": "proxy", "settings": {"servers": [server]}}]
    })
    .to_string()
}

/// 启动应失败且错误含 Go 文案 `Flow for Trojan`。
async fn expect_flow_rejection(json: &str) {
    let cfg = Config::from_json_str(json).expect("config json parses");
    let built = cfg.build().expect("config builds");
    let err = match start_full(&built).await {
        Err(e) => e,
        Ok(_) => panic!("trojan flow must fail startup"),
    };
    let msg = err.to_string();
    assert!(
        msg.contains("Flow for Trojan"),
        "error should surface the removed feature, got: {msg}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trojan_inbound_flow_fails_startup() {
    expect_flow_rejection(&inbound_config_json(serde_json::json!({
        "clients": [{"password": "test-pass-12345", "flow": "xtls-rprx-vision"}]
    })))
    .await;

    // 对照组：去掉 flow → 同一链路正常启动。
    let control = Config::from_json_str(&inbound_config_json(serde_json::json!({
        "clients": [{"password": "test-pass-12345"}]
    })))
    .expect("config json parses");
    let built = control.build().expect("config builds");
    let (_instance, _ohm, _handles) =
        start_full(&built).await.expect("trojan inbound without flow must start");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trojan_outbound_flow_fails_startup() {
    expect_flow_rejection(&outbound_config_json(serde_json::json!({
        "address": "127.0.0.1",
        "port": 443,
        "password": "test-pass-12345",
        "flow": "xtls-rprx-vision"
    })))
    .await;
}
