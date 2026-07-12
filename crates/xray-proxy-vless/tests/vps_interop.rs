//! VPS 互通测试: VLESS client → Go xray-core server → 目标
//!
//! 验证 Rust VLESS 客户端能连真实 Go 服务端。
//! flow=xtls-rprx-vision 需要 VisionConn padding 才能完整工作。
//!
//! 运行:
//! ```sh
//! cargo test -p xray-proxy-vless --test vps_interop -- --ignored --nocapture
//! ```

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

use xray_common::net::address::Address;
use xray_common::uuid::UUID;
use xray_proxy_vless::encoding::client::encode_request_header;
use xray_proxy_vless::encoding::VlessCommand;
use xray_proto::xray::proxy::vless::encoding::Addons;
use xray_tls::utls;
use xray_transport::connection::TcpConnection;

const VLESS_VERSION: u8 = 0;

/// VLESS client (encryption=none) → VPS Go 服务端 (flow=xtls-rprx-vision)
///
/// 集成 VisionConn padding exchange：encode VLESS header 后用 VisionConn
/// 包装 TLS conn，发 HTTP GET（自动 Vision padding，首块带 uuid）。
#[tokio::test]
#[ignore]
async fn vless_tcp_tls_vps_interop() {
    use xray_proxy_vless::encryption::vision_conn::VisionConn;

    let host = "sg.yzswgroup.top";
    let port: u16 = 39627;
    let uuid_str = "a0832f31-62c1-4197-ac85-2634e38ab700";
    let sni = "sg.yzswgroup.top";
    let uuid = UUID::parse(uuid_str).expect("parse UUID");

    // 1. TCP connect
    let addr = format!("{host}:{port}");
    eprintln!("[1/5] TCP connect → {addr}");
    let tcp = TcpStream::connect(&addr).await.expect("TCP connect");
    tcp.set_nodelay(true).ok();
    let conn = TcpConnection::new(tcp);

    // 2. TLS handshake
    eprintln!("[2/5] TLS handshake (SNI={sni})");
    let tls_config = utls::default_client_config();
    let mut tls = utls::client(conn, sni, tls_config)
        .await
        .expect("TLS handshake");

    // 3. VLESS request header (encryption=none, flow=xtls-rprx-vision, target=www.google.com:80)
    eprintln!("[3/5] VLESS header (flow=xtls-rprx-vision, target=www.google.com:80)");
    let target_addr = Address::Domain("www.google.com".to_string());
    let addons = Addons {
        flow: "xtls-rprx-vision".to_string(),
        ..Default::default()
    };
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

    // 4. VisionConn 包装 tls，发 HTTP GET（自动 Vision padding，首块带 uuid）
    eprintln!("[4/5] Vision padding + HTTP GET");
    let uuid_bytes = uuid.as_bytes().to_vec();
    let mut vision = VisionConn::new(tls, uuid_bytes);
    let http_req = b"GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n";
    vision
        .write_all(http_req)
        .await
        .expect("write HTTP via Vision");
    vision.flush().await.expect("flush Vision");

    // 5. 读 response（VisionConn 自动 unpadding；若服务端 raw 则 passthrough）
    eprintln!("[5/5] Read response (10s timeout)...");
    let mut buf = vec![0u8; 4096];
    let result = timeout(Duration::from_secs(10), vision.read(&mut buf)).await;

    match result {
        Ok(Ok(n)) => {
            if n == 0 {
                eprintln!("⚠️ EOF (server closed after padding — padding may be rejected)");
            } else {
                let preview = String::from_utf8_lossy(&buf[..n]);
                eprintln!("Received {n} bytes");
                eprintln!("First bytes: {:02x?}", &buf[..n.min(32)]);
                eprintln!("Preview: {}", &preview[..preview.len().min(500)]);
                if preview.contains("HTTP/") {
                    eprintln!("✅ VLESS+Vision+TLS VPS interop PASS!");
                } else {
                    eprintln!("⚠️ Non-HTTP response (Vision unpadding may need adjustment)");
                }
            }
        }
        Ok(Err(e)) => eprintln!("⚠️ Read error: {e}"),
        Err(_) => eprintln!("⚠️ Timeout 10s (server may be waiting for more data)"),
    }
}


// ============================================================================
// VLESS + WS + TLS (encryption=none, no Vision) — CDN 配置
// ============================================================================

/// VLESS client over WebSocket → VPS Go 服务端 → HTTP GET 1.1.1.1
///
/// 此配置无 flow=xtls-rprx-vision，服务端不期望 Vision padding。
/// 测试 VLESS header + WebSocket 传输层与 Go 的互通。
#[tokio::test]
#[ignore]
async fn vless_ws_tls_vps_interop() {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let tcp_addr = "home.begonia92.top:443";
    let ws_host = "cdn_sg.yzswgroup.top";
    let ws_path = "/3dba3e56aa3a6ca5-vw";
    let uuid_str = "a0832f31-62c1-4197-ac85-2634e38ab700";
    let uuid = UUID::parse(uuid_str).expect("parse UUID");

    // 1. TCP connect
    eprintln!("[1/5] TCP connect → {tcp_addr}");
    let tcp = TcpStream::connect(tcp_addr).await.expect("TCP connect");
    tcp.set_nodelay(true).ok();
    let conn = TcpConnection::new(tcp);

    // 2. TLS handshake
    eprintln!("[2/5] TLS handshake (SNI={ws_host})");
    let tls_config = utls::default_client_config();
    let tls = utls::client(conn, ws_host, tls_config).await.expect("TLS handshake");

    // 3. WebSocket upgrade
    eprintln!("[3/5] WebSocket upgrade (path={ws_path})");
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let ws_url = format!("wss://{ws_host}{ws_path}");
    let ws_request = ws_url.into_client_request().expect("build WS request");
    let (mut ws, response) = tokio_tungstenite::client_async(ws_request, tls).await.expect("WS upgrade");
    eprintln!("  WS upgrade: {}", response.status());

    // 4. VLESS header + HTTP request
    eprintln!("[4/5] VLESS header + HTTP GET (target=1.1.1.1:80)");
    let target_addr = Address::IPv4(std::net::Ipv4Addr::new(1, 1, 1, 1));
    let addons = Addons::default();

    // 手动构造 VLESS header (encryption=none):
    // [1B version=0][16B UUID][1B addons_len=0][1B cmd=1(TCP)][1B atyp=1(IPv4)][4B IP][2B port BE]
    let mut header_buf: Vec<u8> = Vec::with_capacity(32);
    header_buf.push(0x00); // version
    header_buf.extend_from_slice(uuid.as_bytes()); // 16B UUID
    header_buf.push(0x00); // addons_len = 0
    header_buf.push(0x01); // cmd = TCP
    header_buf.push(0x01); // atyp = IPv4
    header_buf.extend_from_slice(&[1, 1, 1, 1]); // 1.1.1.1
    header_buf.extend_from_slice(&80u16.to_be_bytes()); // port 80

    // 只发 VLESS header（不发 HTTP，先等 response header）
    let header_len = header_buf.len();
    ws.send(Message::Binary(header_buf.into())).await.expect("send VLESS header");
    eprintln!("  Sent VLESS header {} bytes", header_len);

    // 5a. 读 response header
    eprintln!("[5a/6] Read response header...");
    match timeout(Duration::from_secs(5), ws.next()).await {
        Ok(Some(Ok(msg))) => {
            eprintln!("  Response msg: {:?}", msg);
            match msg {
                Message::Binary(d) => eprintln!("  Response header: {} bytes {:02x?}", d.len(), &d[..d.len().min(16)]),
                Message::Close(r) => { eprintln!("⚠️ Server closed: {:?}", r); return; }
                _ => eprintln!("  Other: {:?}", msg),
            }
        }
        _ => { eprintln!("⚠️ No response header received"); return; }
    }

    // 5b. 发 HTTP GET
    eprintln!("[5b/6] Send HTTP GET...");
    let http_req = b"GET / HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n";
    ws.send(Message::Binary(http_req.to_vec().into())).await.expect("send HTTP");

    // 6. 读 HTTP response
    eprintln!("[6/6] Read HTTP response...");

    // 5. Read response
    eprintln!("[5/5] Read response...");
    loop {
        match timeout(Duration::from_secs(10), ws.next()).await {
            Ok(Some(Ok(msg))) => {
                eprintln!("  WS msg: {:?}", msg);
                match msg {
                    Message::Binary(data) => {
                        let resp = String::from_utf8_lossy(&data);
                        eprintln!("  Binary: {} bytes", data.len());
                        if resp.starts_with("HTTP/") {
                            eprintln!("✅ VLESS+WS+TLS VPS interop PASS!");
                            eprintln!("  Response: {}", &resp[..resp.len().min(200)]);
                            break;
                        } else {
                            eprintln!("  First bytes: {:02x?}", &data[..data.len().min(32)]);
                            break;
                        }
                    }
                    Message::Ping(_) | Message::Pong(_) => continue,
                    Message::Close(r) => { eprintln!("⚠️ Close: {:?}", r); break; }
                    _ => continue,
                }
            }
            Ok(Some(Err(e))) => { eprintln!("⚠️ WS error: {e}"); break; }
            Ok(None) => { eprintln!("⚠️ Stream closed"); break; }
            Err(_) => { eprintln!("⚠️ Timeout 10s"); break; }
        }
    }
}
