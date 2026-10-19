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

/// bd 04n8 验收：chunked POST 请求体完整到达目标（transfer-encoding 头保留 +
/// body 帧透传）；普通 Content-Length POST 不回退。
#[tokio::test]
async fn http_plain_proxy_chunked_and_content_length_post_e2e() {
    use std::time::Duration;

    use xray_proxy_http::server::{build_forwarded_request, extract_request_path};

    // 目标服务器：accept 两次，解析每个请求的头+body，回报 channel 供断言
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target_listener.local_addr().unwrap();
    tokio::spawn(async move {
        for _ in 0..2 {
            let (mut sock, _) = target_listener.accept().await.unwrap();
            let (head, body) = read_http_request(&mut sock).await;
            let _ = sock
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await;
            let _ = tx.send((head, body));
        }
    });

    for (name, req_head_tpl, req_body, expect_body) in [
        (
            "chunked",
            "POST http://{host}/upload HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\n\r\n",
            &b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"[..],
            &b"hello world"[..],
        ),
        (
            "content-length",
            "POST http://{host}/submit HTTP/1.1\r\nHost: {host}\r\nContent-Length: 11\r\n\r\n",
            &b"hello world"[..],
            &b"hello world"[..],
        ),
    ] {
        // 代理：模拟 handle_plain_http 核心逻辑（handshake → 重建请求 → dial → 双向 bridge）
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut client_stream, _) = proxy_listener.accept().await.unwrap();
            let config = ServerConfig::default();
            let hs = http_server_handshake(&mut client_stream, &config).await.expect("handshake");
            let path = extract_request_path(&hs.target);
            let req_bytes = build_forwarded_request(&hs.method, &path, &hs.headers);
            let mut target =
                dial_system(&hs.dest, &SocketOptions::default()).await.expect("dial target");
            target.write_all(&req_bytes).await.unwrap();
            let (mut cs_rd, mut cs_wr) = tokio::io::split(client_stream);
            let (mut tg_rd, mut tg_wr) = tokio::io::split(target);
            let up = tokio::io::copy(&mut cs_rd, &mut tg_wr);
            let down = tokio::io::copy(&mut tg_rd, &mut cs_wr);
            let _ = tokio::join!(up, down);
        });

        let host = format!("127.0.0.1:{}", target_addr.port());
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client.write_all(req_head_tpl.replace("{host}", &host).as_bytes()).await.unwrap();
        client.write_all(req_body).await.unwrap();
        client.shutdown().await.unwrap(); // 半关：body 发完，读半部保留等响应

        let mut resp = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut resp))
            .await
            .expect("response timeout")
            .unwrap();
        assert!(
            String::from_utf8_lossy(&resp).starts_with("HTTP/1.1 200"),
            "{name}: got: {}",
            String::from_utf8_lossy(&resp)
        );

        let (tgt_head, tgt_body) = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("target report")
            .expect("target reported a request");
        assert_eq!(
            tgt_head.contains("transfer-encoding: chunked"),
            name == "chunked",
            "{name}: head = {tgt_head}"
        );
        assert_eq!(tgt_body, expect_body, "{name}: target must receive full body");
    }
}

/// 读完整 HTTP 请求（head + body）。body 按 content-length 或 chunked 终止帧判定，
/// 不依赖 EOF。返回 (小写 head 文本, 解码后 body)。
async fn read_http_request(sock: &mut TcpStream) -> (String, Vec<u8>) {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 2048];
    let head_end = loop {
        let n = sock.read(&mut tmp).await.unwrap();
        assert!(n > 0, "target EOF before request head complete");
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_subsequence(&buf, b"\r\n\r\n") {
            break pos;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_lowercase();
    let mut body = buf[head_end + 4..].to_vec();
    if let Some(cl) = head.lines().find_map(|l| l.strip_prefix("content-length:")) {
        let want: usize = cl.trim().parse().unwrap();
        while body.len() < want {
            let n = sock.read(&mut tmp).await.unwrap();
            assert!(n > 0, "target EOF before content-length body complete");
            body.extend_from_slice(&tmp[..n]);
        }
        body.truncate(want);
    } else if head.contains("transfer-encoding: chunked") {
        while find_subsequence(&body, b"0\r\n\r\n").is_none() {
            let n = sock.read(&mut tmp).await.unwrap();
            assert!(n > 0, "target EOF before chunked terminator");
            body.extend_from_slice(&tmp[..n]);
        }
        body = decode_chunked(&body);
    } else {
        panic!("target got neither content-length nor chunked head: {head}");
    }
    (head, body)
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// RFC 7230 chunked 解码（测试用：逐块 size 行 + 数据 + CRLF，size 0 终止）。
fn decode_chunked(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    loop {
        let nl = raw[pos..].iter().position(|&b| b == b'\n').expect("chunk size line");
        let line_end = pos + nl + 1;
        let size =
            usize::from_str_radix(std::str::from_utf8(&raw[pos..line_end]).unwrap().trim(), 16)
                .unwrap();
        if size == 0 {
            break;
        }
        out.extend_from_slice(&raw[line_end..line_end + size]);
        pos = line_end + size + 2; // 跳过数据后的 \r\n
    }
    out
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
