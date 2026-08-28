//! 集成测试：tcp + http header 伪装出站拨号。
//!
//! 验证 `dial_with_settings("tcp", transport_json: {header: {type: http}})`
//! 真把 HTTP 伪装 header 注入连接（Go `tcp/dialer.go:104-115` 装配），
//! 并正确吞掉对端 response header。

use std::net::Ipv4Addr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use xray_common::net::address::Address;
use xray_common::net::destination::Destination;
use xray_common::net::port::Port;
use xray_transport::dialer::{StreamSettings, dial_with_settings};
use xray_transport::sockopt::SocketOptions;

/// TCP + http header 出站：dial 后首写应带 "GET / HTTP/1.1" + Chrome UA
/// request header；对端 response header 应被吞掉，payload 透传。
#[tokio::test]
async fn tcp_http_header_dial_injects_request_header() {
    // 伪装目标：裸 TCP server，读到 header 终结符或 EOF 为止，回传原始字节。
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut raw = Vec::new();
        let mut chunk = [0u8; 256];
        loop {
            match sock.read(&mut chunk).await.unwrap() {
                0 => break, // EOF：client 已关写方向（裸 payload 无 header 场景）。
                n => raw.extend_from_slice(&chunk[..n]),
            }
            if find_ending(&raw).is_some() {
                break;
            }
        }
        (sock, raw)
    });

    // 注册 tcp dialer（含 security + header 包装）。
    let _ = xray_transport_tcp::register::register_dialer();

    let mut settings = StreamSettings::tcp();
    settings.transport_json = Some(serde_json::json!({
        "header": {"type": "http"}
    }));
    let dest = Destination::tcp(Address::IPv4(Ipv4Addr::LOCALHOST), Port::new(addr.port()));
    let mut conn = dial_with_settings("tcp", &dest, &SocketOptions::default(), &settings)
        .await
        .expect("tcp+header dial 应成功");

    conn.write_all(b"payload-after-header").await.unwrap();
    conn.shutdown().await.unwrap(); // 关写方向，让 server 端 EOF 可达。

    let (mut sock, raw) = server.await.unwrap();
    let pos = find_ending(&raw).expect("应收到带 ENDING 的 request header");
    let header = String::from_utf8_lossy(&raw[..pos]).to_string();
    let payload = &raw[pos + 4..];

    assert!(
        header.starts_with("GET / HTTP/1.1\r\n"),
        "request 首行应为 GET / HTTP/1.1，实际 {header:?}"
    );
    assert!(
        header.contains("User-Agent: Mozilla/5.0"),
        "应含默认 Chrome UA，实际 {header:?}"
    );
    assert_eq!(payload, b"payload-after-header");

    // 回 response header + payload：client 应吞 header 拿到 payload（读方向仍开）。
    sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: x\r\n\r\nreply-body")
        .await
        .unwrap();
    let mut buf = [0u8; 10];
    conn.read_exact(&mut buf).await.expect("client read");
    assert_eq!(&buf[..], b"reply-body");
}

fn find_ending(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}
