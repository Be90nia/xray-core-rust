//! E2E: HTTP CONNECT proxy → dial_system → bridge_connections → echo target
//!
//! 验证 HTTP 代理完整链路：客户端通过 HTTP CONNECT 代理连接 echo 服务器。

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use xray_proxy_http::{config::ServerConfig, server::http_server_handshake};
use xray_transport::{
    bridge::bridge_connections, connection::TcpConnection, sockopt::SocketOptions,
    system_dialer::dial_system,
};

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
        let hs = http_server_handshake(&mut client_stream, &config).await.expect("handshake");
        assert_eq!(hs.method, "CONNECT");
        let target_conn =
            dial_system(&hs.dest, &SocketOptions::default()).await.expect("dial target");
        let client_conn: Box<dyn xray_transport::connection::Connection> =
            Box::new(TcpConnection::new(client_stream));
        let _ = bridge_connections(client_conn, target_conn).await;
    });

    // ===== 3. 客户端: HTTP CONNECT =====
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let connect_req =
        format!("CONNECT {echo_ip}:{echo_port} HTTP/1.1\r\nHost: {echo_ip}:{echo_port}\r\n\r\n",);
    client.write_all(connect_req.as_bytes()).await.unwrap();

    // 读 200 响应
    let mut buf = vec![0u8; 1024];
    let n = client.read(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.starts_with("HTTP/1.1 200"), "expected 200, got: {response}");

    // 通过隧道发数据，收 echo
    let payload = b"hello http e2e!";
    client.write_all(payload).await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed[..], payload, "echo should match sent data");
}

/// Plain HTTP 代理（GET）端到端验证。
///
/// 测试核心流程：handshake 解析绝对 URL → extract_request_path +
/// build_forwarded_request 重建请求 → 拨号目标 → 转发响应。
#[tokio::test]
async fn http_plain_proxy_get_forwarded_e2e() {
    use std::time::Duration;

    use xray_proxy_http::server::{build_forwarded_request, extract_request_path};

    // ===== 1. HTTP 目标服务器（返回固定响应） =====
    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target_listener.local_addr().unwrap();
    let target_port = target_addr.port();
    tokio::spawn(async move {
        let (mut sock, _) = target_listener.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        let _ = sock.read(&mut buf).await.unwrap();
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nhello world";
        sock.write_all(resp).await.unwrap();
    });

    // ===== 2. HTTP proxy（模拟 handle_plain_http 核心逻辑） =====
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut client_stream, _) = proxy_listener.accept().await.unwrap();
        let config = ServerConfig::default();
        let hs = http_server_handshake(&mut client_stream, &config).await.expect("handshake");
        assert_eq!(hs.method, "GET");

        // 重建转发请求（绝对 URL → 相对 path，移除 hop-by-hop）
        let path = extract_request_path(&hs.target);
        let req_bytes = build_forwarded_request(&hs.method, &path, &hs.headers);
        assert!(String::from_utf8_lossy(&req_bytes).contains("GET /test HTTP/1.1"));

        // 拨号目标 + 写请求 + 读响应 → 转发客户端
        let mut target =
            dial_system(&hs.dest, &SocketOptions::default()).await.expect("dial target");
        target.write_all(&req_bytes).await.unwrap();
        // bridge 剩余 body + 响应
        let _ = tokio::io::copy(&mut target, &mut client_stream).await;
    });

    // ===== 3. 客户端: GET via proxy（绝对 URL） =====
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let get_req = format!(
        "GET http://127.0.0.1:{target_port}/test HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\nProxy-Connection: keep-alive\r\n\r\n",
    );
    client.write_all(get_req.as_bytes()).await.unwrap();

    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(3), client.read(&mut buf))
        .await
        .expect("timeout")
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.starts_with("HTTP/1.1 200"), "expected 200, got: {response}");
    assert!(response.contains("hello world"), "expected body, got: {response}");
}
