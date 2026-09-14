//! REALITY 生产路径 TLS 冒烟门（bd m1t5）。
//!
//! 发行 CI（build-linux-release.yml）在发行 feature 闭包下跑本测试：
//! 走 pub API 完成 `server_tls`（内部 `build_server_config` 构建 rustls
//! `ServerConfig`）+ `u_client` watfaq-rustls fallback 的完整 REALITY
//! 握手，断言双端 Verified/握手成功。
//!
//! rustls 双 CryptoProvider feature unification 时裸 `builder()` 会
//! panic（bd rknm）——生产构建点已各自前置 `install_default`，本测试
//! **不**手动安装 provider，让生产路径自我兜底：前置被删且 unification
//! 回到双 provider 时，此处即 panic 暴露回归。
//!
//! 刻意选 watfaq fallback 指纹（`randomizednoalpn`，btls 不支持）：
//! 纯 rustls 路径，不依赖 btls 平台材料，跨平台 CI 稳定（btls 指纹
//! 路径在 CI 有 transcript mismatch 的既有 ignore 前科）。

use std::time::Duration;

use tokio::io::duplex;
use x25519_dalek::{PublicKey, StaticSecret};
use xray_proto::transport::internet::reality::Config as ProtoConfig;
use xray_reality::client::{u_client, UConnState};
use xray_reality::server::{RealityServerOutcome, server_tls};
use xray_reality::RealityConfig;

#[tokio::test]
async fn reality_server_tls_with_u_client_handshake_succeeds() {
    let server_priv = [0x11u8; 32];
    let short_id = [0xaa; 8];

    // server X25519 公钥（client RealityConfig.public_key）
    let server_pub = PublicKey::from(&StaticSecret::from(server_priv));

    let proto = ProtoConfig {
        fingerprint: "randomizednoalpn".into(),
        public_key: server_pub.as_bytes().to_vec(),
        server_name: "example.com".into(),
        short_id: short_id.to_vec(),
        ..Default::default()
    };
    let state = UConnState::new(RealityConfig::from_proto(&proto).unwrap()).unwrap();

    // 双向管道（足够大 buffer 避免 TCP 反压）+ Connection 适配（btls 路径要求）
    let (client_side, server_side) = duplex(65536);
    let client_conn = xray_transport::connection::DuplexConnection::new(client_side);

    // server_tls：verify ClientHello → build_server_config → rustls 握手
    let server_task = tokio::spawn(async move {
        server_tls(server_side, &server_priv, &[short_id], 43200, &[], &[], &[]).await
    });

    let client_result =
        tokio::time::timeout(Duration::from_secs(10), u_client(client_conn, state)).await;
    let server_result = server_task.await.unwrap();

    match (client_result, server_result) {
        (Ok(Ok(_tls_stream)), Ok(RealityServerOutcome::Verified(_))) => {}
        (Ok(Ok(_)), _) => panic!("server unexpected outcome"),
        (Ok(Err(e)), _) => panic!("client u_client failed: {e:?}"),
        (Err(_timeout), _) => panic!("client u_client timeout"),
    }
}
