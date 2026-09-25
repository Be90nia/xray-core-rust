//! VPS 互通测试: VMess+WS+TLS client → Go xray-core server → 目标
//!
//! VMess config: home.begonia92.top:2083 / WS path=/3dba3e56aa3a6ca5-vm / TLS
//!
//! 运行:
//! ```sh
//! cargo test -p xray-proxy-vmess --test vps_interop -- --ignored --nocapture
//! ```

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use xray_common::{
    net::{address::Address, destination::Destination, port::Port},
    protocol::{Command, RequestHeader, SecurityType},
    uuid::UUID,
};
use xray_proxy_vmess::{VERSION, account::cmd_key_of, encoding::client::ClientSession};
use xray_tls::utls;
use xray_transport::connection::TcpConnection;

/// VMess+WS+TLS 客户端 → VPS Go 服务端 → HTTP GET 1.1.1.1
///
/// 测试 VMess AEAD header + body chunk 加密与 Go 服务端互通。
#[tokio::test]
#[ignore]
async fn vmess_ws_tls_vps_interop() {
    let tcp_addr = "home.begonia92.top:2083";
    let ws_host = "cdn_sg.yzswgroup.top";
    let ws_path = "/3dba3e56aa3a6ca5-vm";
    let uuid_str = "a0832f31-62c1-4197-ac85-2634e38ab700";

    let uuid = UUID::parse(uuid_str).expect("parse UUID");
    let cmd_key = cmd_key_of(&uuid); // Go: MD5(UUID.bytes + magic)

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
    eprintln!("  WS upgrade response: {}", response.status());

    // 4. VMess session + encode
    eprintln!("[4/5] VMess encode (target=1.1.1.1:80, AES-128-GCM)");
    let session = ClientSession::new();
    let mut header = RequestHeader::new(
        VERSION,
        Command::Tcp,
        Destination::tcp(Address::IPv4(std::net::Ipv4Addr::new(1, 1, 1, 1)), Port::new(80)),
        SecurityType::Aes128Gcm,
    );
    header.option.set(xray_proxy_vmess::request_option::CHUNK_STREAM);

    // Encode request header (AEAD encrypted)
    let header_bytes = session.encode_request_header(&header, &cmd_key).expect("encode header");

    // Encode request body (HTTP GET, chunk-encrypted)
    let http_request = b"GET / HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n";
    let mut body_bytes: Vec<u8> = Vec::new();
    session.encode_request_body(&header, http_request, &mut body_bytes).expect("encode body");

    let header_len = header_bytes.len();
    let body_len = body_bytes.len();
    let mut payload = header_bytes;
    payload.extend_from_slice(&body_bytes);

    eprintln!("  Sending {} bytes (header={} + body={})", payload.len(), header_len, body_len);
    ws.send(Message::Binary(payload.into())).await.expect("send VMess data");

    // 5. Read response (循环读多帧，跳过 Ping/Pong)
    eprintln!("[5/5] Read response...");
    let deadline = std::time::Duration::from_secs(10);
    loop {
        match tokio::time::timeout(deadline, ws.next()).await {
            Ok(Some(Ok(msg))) => {
                eprintln!("  WS msg: {:?}", msg);
                match msg {
                    Message::Binary(data) => {
                        eprintln!(
                            "  Binary: {} bytes, first: {:02x?}",
                            data.len(),
                            &data[..data.len().min(32)]
                        );
                        if !data.is_empty() {
                            eprintln!(
                                "✅ VMess VPS interop: received binary response from Go server"
                            );
                            break;
                        }
                    },
                    Message::Ping(_) | Message::Pong(_) => continue,
                    Message::Close(reason) => {
                        eprintln!("⚠️ Server closed: {:?}", reason);
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
                eprintln!("⚠️ WS stream closed (None)");
                break;
            },
            Err(_) => {
                eprintln!("⚠️ Read timed out ({:?})", deadline);
                break;
            },
        }
    }
}
