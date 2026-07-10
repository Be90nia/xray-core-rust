//! E2E: HTTP CONNECT proxy → dial_system → bridge_connections → echo target
//!
//! 验证 HTTP 代理完整链路：客户端通过 HTTP CONNECT 代理连接 echo 服务器。

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use xray_proxy_http::config::ServerConfig;
use xray_proxy_http::server::http_server_handshake;
use xray_transport::bridge::bridge_connections;
use xray_transport::connection::TcpConnection;
use xray_transport::sockopt::SocketOptions;
use xray_transport::system_dialer::dial_system;

/// HTTP CONNECT 代理 → freedom → echo 端到端验证。
#[tokio::test]
async fn http_connect_proxy_to_echo_target_e2e() {
    // ===== 1. echo 目标服务器 =====
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (sock, _) = echo_listener.accept().await.unwrap();
        let (mut rd, mut wr) = tokio::io::split(sock);
        tokio::io::copy(&mut rd, &mut wr).await.unwrap();
    });

    // ===== 2. HTTP proxy =====
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let echo_ip = echo_addr.ip();
    let echo_port = echo_addr.port();
    tokio::spawn(async move {
        let (mut client_stream, _) = proxy_listener.accept().await.unwrap();
        let config = ServerConfig::default();
        let (dest, method) = http_server_handshake(&mut client_stream, &config)
            .await
            .expect("handshake");
        assert_eq!(method, "CONNECT");
        let target_conn = dial_system(&dest, &SocketOptions::default())
            .await
            .expect("dial target");
        let client_conn: Box<dyn xray_transport::connection::Connection> =
            Box::new(TcpConnection::new(client_stream));
        let _ = bridge_connections(client_conn, target_conn).await;
    });

    // ===== 3. 客户端: HTTP CONNECT =====
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let connect_req = format!(
        "CONNECT {echo_ip}:{echo_port} HTTP/1.1\r\nHost: {echo_ip}:{echo_port}\r\n\r\n",
    );
    client.write_all(connect_req.as_bytes()).await.unwrap();

    // 读 200 响应
    let mut buf = vec![0u8; 1024];
    let n = client.read(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "expected 200, got: {response}"
    );

    // 通过隧道发数据，收 echo
    let payload = b"hello http e2e!";
    client.write_all(payload).await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed[..], payload, "echo should match sent data");
}
