//! REALITY 互通测试: REALITY client → Go xray-core server → 目标
//!
//! 验证 Rust REALITY 客户端能连真实 Go 服务端。
//! REALITY TLS 握手 (session_id 注入) + VLESS header (flow=xtls-rprx-vision) + VisionConn padding。
//!
//! 运行:
//! ```sh
//! cargo test -p xray-reality --test vps_interop -- --ignored --nocapture
//! ```

use base64::Engine;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{Duration, timeout},
};
use xray_common::{net::address::Address, uuid::UUID};
use xray_proto::xray::proxy::vless::encoding::Addons;
use xray_proxy_vless::encoding::{VlessCommand, client::encode_request_header};
use xray_reality::{
    RealityConfig,
    client::{UConnState, u_client},
};
use xray_transport::connection::TcpConnection;

const VLESS_VERSION: u8 = 0;

/// REALITY + VLESS Vision client → VPS Go 服务端 → HTTP GET www.google.com
///
/// 完整流程：TCP → REALITY TLS 握手 (watfaq-rustls with_reality) → VLESS header
/// (flow=xtls-rprx-vision) → VisionConn padding + HTTP GET → 读响应。
#[tokio::test]
#[ignore]
async fn vless_reality_vision_vps_interop() {
    use xray_proxy_vless::encryption::vision_conn::VisionConn;

    let host = "sg.yzswgroup.top";
    let port: u16 = 39231;
    let uuid_str = "a0832f31-62c1-4197-ac85-2634e38ab700";
    let sni = "www.mozilla.org"; // REALITY 伪装域名
    let pbk_b64url = "fmgkhSuC9GpezIl_aWG1nqCkA0qyQIDIPPCQxg65pVs";
    let sid_hex = "363396b6";

    // base64url decode public_key (32 bytes X25519)
    let public_key =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(pbk_b64url).expect("decode pbk");
    assert_eq!(public_key.len(), 32, "X25519 public key must be 32 bytes");

    // hex decode + pad short_id to 8 bytes (Go ShortId is [8]byte)
    let sid_bytes = hex::decode(sid_hex).expect("decode sid");
    let mut short_id = vec![0u8; 8];
    short_id[..sid_bytes.len()].copy_from_slice(&sid_bytes);

    let uuid = UUID::parse(uuid_str).expect("parse UUID");

    // 1. 构造 REALITY UConnState
    let config = RealityConfig {
        fingerprint: "chrome".into(),
        server_name: sni.into(),
        public_key,
        short_id,
        ..Default::default()
    };
    let state = UConnState::new(config).expect("UConnState");

    // 2. TCP connect
    let addr = format!("{host}:{port}");
    eprintln!("[1/5] TCP connect → {addr}");
    let tcp = TcpStream::connect(&addr).await.expect("TCP connect");
    tcp.set_nodelay(true).ok();
    let conn = TcpConnection::new(tcp);

    // 3. REALITY TLS handshake (watfaq-rustls with_reality)
    eprintln!("[2/5] REALITY handshake (SNI={sni})");
    let mut tls = u_client(conn, state).await.expect("REALITY handshake");
    eprintln!("  REALITY handshake OK");

    // 4. VLESS header (flow=xtls-rprx-vision, target=www.google.com:80)
    eprintln!("[3/5] VLESS header (flow=xtls-rprx-vision, target=www.google.com:80)");
    let target_addr = Address::Domain("www.google.com".to_string());
    let addons = Addons { flow: "xtls-rprx-vision".to_string(), ..Default::default() };
    encode_request_header(
        &mut tls,
        VLESS_VERSION,
        &uuid,
        VlessCommand::Tcp,
        Some(&target_addr),
        Some(80),
        &addons,
    )
    .await
    .expect("encode VLESS header");
    tls.flush().await.expect("flush VLESS header");

    // 5. VisionConn 包装 tls，发 HTTP GET（自动 Vision padding，首块带 uuid）
    eprintln!("[4/5] Vision padding + HTTP GET");
    let uuid_bytes = uuid.as_bytes().to_vec();
    // v50 起 VisionConn 的 AsyncRead/AsyncWrite 带 InnerRawClone bound；经
    // Box<dyn Connection> 适配（RealityTlsStream 已实现 Connection）。
    let mut vision = VisionConn::new(
        Box::new(tls) as Box<dyn xray_transport::connection::Connection>,
        uuid_bytes,
    );
    let http_req = b"GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n";
    vision.write_all(http_req).await.expect("write HTTP via Vision");
    vision.flush().await.expect("flush Vision");

    // 6. 读 response（VisionConn 自动 unpadding；若服务端 raw 则 passthrough）
    eprintln!("[5/5] Read response (10s timeout)...");
    let mut buf = vec![0u8; 4096];
    let result = timeout(Duration::from_secs(10), vision.read(&mut buf)).await;

    match result {
        Ok(Ok(n)) => {
            if n == 0 {
                panic!("EOF: server closed after REALITY handshake — padding may be rejected");
            }
            let preview = String::from_utf8_lossy(&buf[..n]);
            eprintln!("Received {n} bytes");
            eprintln!("First bytes: {:02x?}", &buf[..n.min(32)]);
            eprintln!("Preview: {}", &preview[..preview.len().min(500)]);
            assert!(
                preview.contains("HTTP/"),
                "REALITY+VLESS+Vision interop: non-HTTP response (Vision unpadding may need adjustment)"
            );
            eprintln!("✅ REALITY+VLESS+Vision VPS interop PASS!");
        },
        Ok(Err(e)) => panic!("Read error: {e}"),
        Err(_) => panic!("Timeout 10s: REALITY handshake or Vision padding rejected"),
    }
}
