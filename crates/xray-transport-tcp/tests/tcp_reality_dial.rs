//! 集成测试：tcp + reality 出站拨号端到端。
//!
//! 验证 `dial_with_settings("tcp", security:reality)` 正确走 REALITY 握手路径
//!（而非标准 TLS fallback）。用 `xray_reality::server::server_tls` 做服务端对握。

use std::net::Ipv4Addr;

use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use xray_common::net::address::Address;
use xray_common::net::destination::Destination;
use xray_common::net::port::Port;
use xray_reality::server::{RealityServerOutcome, server_tls};
use xray_transport::dialer::{StreamSettings, dial_with_settings};
use xray_transport::sockopt::SocketOptions;

/// tcp + reality 出站：dial 应完成 REALITY TLS 握手（session_id/auth_key/cert HMAC）并能 echo。
#[tokio::test]
async fn tcp_plus_reality_handshake_e2e() {
    // 1. 服务端 X25519 静态密钥对（确定性，测试用）
    let server_secret = x25519_dalek::StaticSecret::from([0x99u8; 32]);
    let server_public = x25519_dalek::PublicKey::from(&server_secret);
    let server_private_key = server_secret.to_bytes();
    let server_public_bytes = server_public.to_bytes();

    // 2. short_id（client 与 server 必须匹配）
    let short_id: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

    // 3. REALITY echo server：accept → server_tls 验证 → echo
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let allowed_short_ids = vec![short_id];
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let outcome = server_tls(tcp, &server_private_key, &allowed_short_ids, 43200)
            .await
            .expect("server_tls should not IO-error");
        match outcome {
            RealityServerOutcome::Verified(mut tls) => {
                let mut buf = [0u8; 64];
                loop {
                    match tls.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            let _ = tls.write_all(&buf[..n]).await;
                        }
                    }
                }
            }
            RealityServerOutcome::Invalid { .. } => {
                panic!("REALITY server verification failed (client hello rejected)");
            }
        }
    });

    // 4. 注册 tcp dialer（含 reality 包装）
    let _ = xray_transport_tcp::register::register_dialer();

    // 5. client dial tcp+reality
    let mut settings = StreamSettings::tcp();
    settings.security = "reality".to_string();
    settings.security_json = Some(serde_json::json!({
        "serverName": "reality.local",
        "publicKey": base64::engine::general_purpose::STANDARD.encode(server_public_bytes),
        "shortId": hex::encode(short_id),
        "fingerprint": "chrome"
    }));
    let dest = Destination::tcp(
        Address::IPv4(Ipv4Addr::LOCALHOST),
        Port::new(addr.port()),
    );
    let mut conn = dial_with_settings("tcp", &dest, &SocketOptions::default(), &settings)
        .await
        .expect("tcp+reality dial 应成功（REALITY 握手）");

    // 6. echo 回环
    conn.write_all(b"hello-over-reality").await.unwrap();
    let mut got = [0u8; 64];
    let n = conn.read(&mut got).await.expect("reality echo read 应成功");
    assert_eq!(&got[..n], b"hello-over-reality");
}
