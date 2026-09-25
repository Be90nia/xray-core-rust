//! 集成测试：含非法 `certificates[]` 的完整 inbound 配置 → 启动报错（而非静默自签）。
//!
//! 对齐 9587026（certificate.rs Err 语义）与 Go `infra/conf/transport_security.go:250`
//! （`TLSCertConfig.CertStr []string` 反序列化类型不匹配 = 配置加载期 error）。
//! 断言完整启动链路把错误传到顶层：
//! `start_full` → `spawn_inbounds`（`?`）→ `spawn_one_inbound`（`?`）→
//! `build_tls_acceptor` → `build_server_config` → `entry_certs_and_key` Err。
//!
//! 对照组证明「报错」来自证书校验而非无关缺口：证书缺省（无 `certificates`）
//! 时同一链路正常启动（走自签回退），即非法内联不再静默落入该回退。

use xray_conf::Config;
use xray_core::start_full;

fn config_json(tls_settings: serde_json::Value) -> String {
    serde_json::json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "trojan-in",
            "listen": "127.0.0.1",
            "port": 0,
            "protocol": "trojan",
            "settings": {"clients": [{"password": "test-pass-12345"}]},
            "streamSettings": {
                "security": "tls",
                "tlsSettings": tls_settings
            }
        }],
        "outbounds": [{"protocol": "freedom", "tag": "direct"}]
    })
    .to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_inline_certificates_fail_startup_instead_of_silent_self_signed() {
    // ===== 1. 非法内联（数字数组）：完整配置启动必须报错 =====
    let invalid = Config::from_json_str(&config_json(serde_json::json!({
        "certificates": [{ "certificate": [1, 2, 3], "key": ["not-a-key"] }]
    })))
    .expect("config json parses");
    let built = invalid.build().expect("config builds");
    let err = match start_full(&built).await {
        Err(e) => e,
        Ok(_) => panic!("invalid inline certificates[] must fail startup"),
    };
    let msg = err.to_string();
    assert!(
        msg.contains("certificate"),
        "error should surface the certificate failure, got: {msg}"
    );

    // ===== 2. 对照：证书缺省 → 同一链路走自签回退正常启动 =====
    let fallback =
        Config::from_json_str(&config_json(serde_json::json!({}))).expect("config json parses");
    let built = fallback.build().expect("config builds");
    let (_instance, _ohm, _handles) =
        start_full(&built).await.expect("absent certificates falls back to self-signed and starts");
}
