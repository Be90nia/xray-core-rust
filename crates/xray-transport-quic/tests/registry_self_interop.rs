//! QUIC 传输 Rust↔Rust 自洽互通（0270p）：**生产注册表路径**端到端。
//!
//! 与 `src/transport.rs` 内的 echo_roundtrip 单测不同，这里两端都走**生产入口**：
//! - 服务端：`register_listener()` 注册 → `listener_registry::listen_tcp`（装配层实际
//!   调用的查找入口）→ `transport::listen`；
//! - 客户端：`register_dialer()` 注册 → `dialer::dial`（`removed_feature_warnings` 与
//!   `protocol_settings_key("quic") → quicSettings` 解析都在这条生产路径上）。
//!
//! 断言 ≥256KiB 确定性载荷字节级往返（> 票面要求的 64KB），且带非缺省 `quicSettings`
//! （`congestion: "bbr"`）——解析失败 dial 即报错，成功即证明 quicSettings 消费链完整。

// 测试编译单元统一豁免（数据面分配纪律见 crate clippy.toml）
#![allow(clippy::disallowed_methods)]
#![allow(clippy::unwrap_used)] // 测试断言便利豁免；生产禁令不受影响

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use xray_common::net::{address::Address, destination::Destination, port::Port};
use xray_transport::{
    dialer::{StreamSettings, dial},
    listener_registry::listen_tcp,
    sockopt::SocketOptions,
};

fn ensure_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// 服务端 StreamSettings：`network=quic` + 自签证书 + 非缺省 quicSettings。
fn quic_server_settings(cert: String, key: String) -> StreamSettings {
    StreamSettings::from_json(Some(&serde_json::json!({
        "network": "quic",
        "security": "tls",
        "tlsSettings": { "certificates": [{ "certificate": cert, "key": key }] },
        "quicSettings": { "congestion": "bbr", "keepAlive": 10 }
    })))
}

/// 客户端 StreamSettings：`network=quic` + allowInsecure（自签对端）。
fn quic_client_settings() -> StreamSettings {
    StreamSettings::from_json(Some(&serde_json::json!({
        "network": "quic",
        "security": "tls",
        "tlsSettings": { "serverName": "127.0.0.1", "allowInsecure": true },
        "quicSettings": { "congestion": "bbr" }
    })))
}

/// 生产注册表路径 Rust↔Rust：listen_tcp（registry 查找）↔ dial（registry 查找），
/// 256KiB 确定性载荷字节级回显。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn registry_path_quic_self_interop_roundtrip() {
    ensure_crypto_provider();
    xray_transport_quic::register::register_dialer().expect("register quic dialer");
    xray_transport_quic::register::register_listener().expect("register quic listener");

    let (cert, key) =
        xray_tls::certificate::generate_self_signed_cert(&["127.0.0.1"]).expect("self-signed cert");
    let server_settings = quic_server_settings(cert, key);
    let probe_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    // UDP 探针取空闲端口（QUIC 是 UDP；TCP probe 只用来占号防竞争，随即释放）。
    let port = probe_listener.local_addr().unwrap().port();
    drop(probe_listener);
    let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    // echo handler：读到什么写回什么（与 src/transport.rs 单测同语义）。
    let handler: xray_transport::listener_registry::ConnHandler = std::sync::Arc::new(|conn| {
        tokio::spawn(async move {
            let mut conn = conn;
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                match conn.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if conn.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    },
                }
            }
        });
    });
    let listener = listen_tcp(addr, server_settings, SocketOptions::default(), handler)
        .await
        .expect("registry listen_tcp for network=quic");
    let bound = listener.local_addr().expect("local addr");
    let dest = Destination::tcp("127.0.0.1".parse::<Address>().unwrap(), Port::new(bound.port()));

    // 客户端：生产 dial 入口（removed-feature 警告在此路径发出——允许但不断言日志）。
    let mut conn = dial(&dest, &quic_client_settings(), &SocketOptions::default())
        .await
        .expect("registry dial for network=quic");

    // 256KiB 确定性载荷（> 票面 64KB 要求；跨多个 QUIC stream 帧）。
    let payload: Vec<u8> = (0..(256 * 1024)).map(|i| (i * 7 % 251) as u8).collect();
    conn.write_all(&payload).await.expect("upload write");
    conn.shutdown().await.expect("upload half close");

    // read_exact（非 read_to_end）：echo handler 读到 EOF 即退出、不 shutdown 写向，
    // 与 src/transport.rs 回环单测同语义——按定长读满即可。
    let mut echoed = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(30), conn.read_exact(&mut echoed))
        .await
        .expect("echo roundtrip within 30s")
        .expect("read echo");
    assert_eq!(echoed, payload, "256KiB 回显必须字节级一致");
}
