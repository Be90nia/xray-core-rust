//! VPS 互通测试: Trojan client → Go xray-core server → 目标网站
//!
//! 验证 Rust Trojan 客户端能连真实 Go 服务端。
//! 测试流程: TCP → TLS → Trojan header → HTTP GET → 读响应
//!
//! 运行:
//! ```sh
//! cargo test -p xray-proxy-trojan --test vps_interop -- --ignored --nocapture
//! ```
//! 或自定义参数:
//! ```sh
//! VPS_HOST=xxx VPS_PORT=xxx VPS_PASS=xxx cargo test -p xray-proxy-trojan --test vps_interop -- --ignored --nocapture
//! ```

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use xray_proxy_trojan::hex_sha224;
use xray_tls::utls;
use xray_transport::connection::TcpConnection;

/// Trojan 客户端 → VPS Go 服务端 → 1.1.1.1 HTTP。
///
/// 默认参数从用户 VPS 配置提取，可通过环境变量覆盖。
#[tokio::test]
#[ignore]
async fn trojan_tcp_tls_vps_interop() {
    let host = std::env::var("VPS_HOST").unwrap_or_else(|_| "sg.yzswgroup.top".into());
    let port: u16 =
        std::env::var("VPS_PORT").unwrap_or_else(|_| "39237".into()).parse().expect("valid port");
    let password =
        std::env::var("VPS_PASS").unwrap_or_else(|_| "a0832f31-62c1-4197-ac85-2634e38ab700".into());
    let sni = std::env::var("VPS_SNI").unwrap_or_else(|_| "sg.yzswgroup.top".into());

    let addr = format!("{host}:{port}");
    eprintln!("[1/5] TCP connect → {addr}");
    let tcp = TcpStream::connect(&addr).await.expect("TCP connect failed");
    tcp.set_nodelay(true).ok();
    let conn = TcpConnection::new(tcp);

    eprintln!("[2/5] TLS handshake (SNI={sni})");
    let tls_config = utls::default_client_config();
    let mut tls = utls::client(conn, &sni, tls_config).await.expect("TLS handshake failed");

    eprintln!("[3/5] Trojan header (target=1.1.1.1:80)");
    let key_hex = hex_sha224(&password);
    let mut header = Vec::with_capacity(64);
    header.extend_from_slice(&key_hex); // 56 bytes hex
    header.extend_from_slice(b"\r\n"); // CRLF
    header.push(0x01); // CMD = TCP
    header.push(0x01); // ATYP = IPv4
    header.extend_from_slice(&[1, 1, 1, 1]); // 1.1.1.1
    header.extend_from_slice(&80u16.to_be_bytes()); // port 80
    header.extend_from_slice(b"\r\n"); // CRLF
    tls.write_all(&header).await.expect("send trojan header");

    eprintln!("[4/5] HTTP GET through tunnel");
    tls.write_all(b"GET / HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n")
        .await
        .expect("send HTTP");

    eprintln!("[5/5] Read response");
    let mut buf = vec![0u8; 4096];
    let n = tls.read(&mut buf).await.expect("read response");
    assert!(n > 0, "empty response");
    let response = String::from_utf8_lossy(&buf[..n]);
    eprintln!("Response ({n} bytes):\n{}", &response[..response.len().min(300)]);
    assert!(
        response.starts_with("HTTP/"),
        "expected HTTP response, got: {}",
        &response[..response.len().min(100)]
    );
    eprintln!("✅ Trojan VPS interop PASS");
}

/// Trojan 客户端 → VPS → DNS 查询 (TCP DNS to 1.1.1.1:53)。
///
/// 验证 Trojan 隧道可以转发非 HTTP 流量。
#[tokio::test]
#[ignore]
async fn trojan_vps_dns_through_tunnel() {
    let host = std::env::var("VPS_HOST").unwrap_or_else(|_| "sg.yzswgroup.top".into());
    let port: u16 =
        std::env::var("VPS_PORT").unwrap_or_else(|_| "39237".into()).parse().expect("valid port");
    let password =
        std::env::var("VPS_PASS").unwrap_or_else(|_| "a0832f31-62c1-4197-ac85-2634e38ab700".into());
    let sni = std::env::var("VPS_SNI").unwrap_or_else(|_| "sg.yzswgroup.top".into());

    let addr = format!("{host}:{port}");
    let tcp = TcpStream::connect(&addr).await.expect("TCP connect");
    let conn = TcpConnection::new(tcp);
    let tls_config = utls::default_client_config();
    let mut tls = utls::client(conn, &sni, tls_config).await.expect("TLS handshake");

    // Trojan header → target = 1.1.1.1:53 (DNS over TCP)
    let key_hex = hex_sha224(&password);
    let mut header = Vec::with_capacity(64);
    header.extend_from_slice(&key_hex);
    header.extend_from_slice(b"\r\n");
    header.push(0x01); // TCP
    header.push(0x01); // IPv4
    header.extend_from_slice(&[1, 1, 1, 1]); // 1.1.1.1
    header.extend_from_slice(&53u16.to_be_bytes()); // port 53
    header.extend_from_slice(b"\r\n");
    tls.write_all(&header).await.expect("send trojan header");

    // 构造 DNS 查询: example.com A record
    // DNS over TCP: 2B length prefix + DNS message
    let dns_query: Vec<u8> = vec![
        0xAB, 0xCD, // ID
        0x01, 0x00, // flags: standard query, recursion desired
        0x00, 0x01, // questions: 1
        0x00, 0x00, // answers: 0
        0x00, 0x00, // authority: 0
        0x00, 0x00, // additional: 0
        // QNAME: example.com
        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, // root label
        0x00, 0x01, // QTYPE: A
        0x00, 0x01, // QCLASS: IN
    ];
    let len = dns_query.len() as u16;
    tls.write_all(&len.to_be_bytes()).await.expect("send DNS length");
    tls.write_all(&dns_query).await.expect("send DNS query");

    // 读 DNS 响应
    let mut len_buf = [0u8; 2];
    tls.read_exact(&mut len_buf).await.expect("read DNS length");
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    assert!(resp_len > 0, "empty DNS response");

    let mut dns_resp = vec![0u8; resp_len];
    tls.read_exact(&mut dns_resp).await.expect("read DNS response");

    // DNS 响应应包含 answer 记录
    let answer_count = u16::from_be_bytes([dns_resp[6], dns_resp[7]]);
    assert!(answer_count > 0, "expected at least 1 DNS answer, got {answer_count}");
    eprintln!("✅ DNS through Trojan tunnel: {answer_count} answers received");
}

// ============================================================================
// Trojan + WS + TLS — CDN 配置
// ============================================================================

/// Trojan client over WebSocket → VPS Go 服务端 → HTTP GET 1.1.1.1
///
/// 配置: home.begonia92.top:2096 / WS path=/3dba3e56aa3a6ca5-tw / SNI=cdn_sg.yzswgroup.top
#[tokio::test]
#[ignore]
async fn trojan_ws_tls_vps_interop() {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let tcp_addr = "home.begonia92.top:2096";
    let ws_host = "cdn_sg.yzswgroup.top";
    let ws_path = "/3dba3e56aa3a6ca5-tw";
    let password = "a0832f31-62c1-4197-ac85-2634e38ab700";

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
    let (mut ws, response) =
        tokio_tungstenite::client_async(ws_request, tls).await.expect("WS upgrade");
    eprintln!("  WS upgrade: {}", response.status());

    // 4. Trojan header + HTTP request
    eprintln!("[4/5] Trojan header + HTTP GET (target=1.1.1.1:80)");
    let key_hex = hex_sha224(password);
    let mut payload = Vec::with_capacity(80);
    payload.extend_from_slice(&key_hex); // 56 bytes hex
    payload.extend_from_slice(b"\r\n");
    payload.push(0x01); // CMD = TCP
    payload.push(0x01); // ATYP = IPv4
    payload.extend_from_slice(&[1, 1, 1, 1]); // 1.1.1.1
    payload.extend_from_slice(&80u16.to_be_bytes()); // port 80
    payload.extend_from_slice(b"\r\n");
    // Append HTTP GET
    payload.extend_from_slice(b"GET / HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n");

    let plen = payload.len();
    ws.send(Message::Binary(payload.into())).await.expect("send Trojan+HTTP");
    eprintln!("  Sent Trojan header + HTTP {} bytes", plen);

    // 5. Read response
    eprintln!("[5/5] Read response...");
    loop {
        match tokio::time::timeout(std::time::Duration::from_secs(10), ws.next()).await {
            Ok(Some(Ok(msg))) => {
                eprintln!("  WS msg: {:?}", msg);
                match msg {
                    Message::Binary(data) => {
                        let resp = String::from_utf8_lossy(&data);
                        eprintln!("  Binary: {} bytes", data.len());
                        if resp.starts_with("HTTP/") {
                            eprintln!("✅ Trojan+WS+TLS VPS interop PASS!");
                            eprintln!("  Response: {}", &resp[..resp.len().min(200)]);
                            break;
                        }
                        eprintln!("  First bytes: {:02x?}", &data[..data.len().min(32)]);
                        // 继续读直到 HTTP response
                    },
                    Message::Ping(_) | Message::Pong(_) => continue,
                    Message::Close(r) => {
                        eprintln!("⚠️ Server closed: {:?}", r);
                        break;
                    },
                    _ => continue,
                }
            },
            Ok(Some(Err(e))) => {
                eprintln!("⚠️ WS error: {e}");
                break;
            },
            Ok(None) => {
                eprintln!("⚠️ Stream closed");
                break;
            },
            Err(_) => {
                eprintln!("⚠️ Timeout 10s");
                break;
            },
        }
    }
}
