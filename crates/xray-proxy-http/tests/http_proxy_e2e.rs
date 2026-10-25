//! E2E: HTTP CONNECT proxy → dial_system → bridge_connections → echo target
//!
//! 验证 HTTP 代理完整链路：客户端通过 HTTP CONNECT 代理连接 echo 服务器。

#![cfg_attr(test, allow(clippy::disallowed_macros))] // 测试脚手架：直印进度；spawn 走 xray_common::testing（L3 闸不豁免）
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
    xray_common::testing::spawn("http-echo-target", async move {
        let (sock, _) = echo_listener.accept().await.unwrap();
        let (mut rd, mut wr) = tokio::io::split(sock);
        tokio::io::copy(&mut rd, &mut wr).await.unwrap();
    });

    // ===== 2. HTTP proxy =====
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let echo_ip = echo_addr.ip();
    let echo_port = echo_addr.port();
    xray_common::testing::spawn("http-proxy-connect", async move {
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
    xray_common::testing::spawn("http-target-post", async move {
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
        xray_common::testing::spawn("http-proxy-post", async move {
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
    xray_common::testing::spawn("http-target-get", async move {
        let (mut sock, _) = target_listener.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        let _ = sock.read(&mut buf).await.unwrap();
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nhello world";
        sock.write_all(resp).await.unwrap();
    });

    // ===== 2. HTTP proxy（模拟 handle_plain_http 核心逻辑） =====
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    xray_common::testing::spawn("http-proxy-get", async move {
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

// ===== plain HTTP 转发五场景（票 poys 验收）：真实 HttpServer serve 路径 =====

use std::{net::SocketAddr, time::Duration};

use xray_features::inbound::InboundHandler;
use xray_proxy_http::server::HttpServer;

/// 起真实 HttpServer（走 handle_connection → handshake → plain 转发的 serve 路径）。
async fn spawn_http_proxy(config: ServerConfig) -> SocketAddr {
    let proxy = HttpServer::new("http-plain-e2e", config);
    proxy.start().await.expect("start http proxy");
    let port = proxy.bound_port().await;
    assert!(port > 0, "proxy did not bind");
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// 读完整 HTTP 响应（head + content-length body；无 CL 头则读当前已到字节）。
async fn read_http_response(sock: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 2048];
    let head_end = loop {
        let n = tokio::time::timeout(Duration::from_secs(5), sock.read(&mut tmp))
            .await
            .expect("response timeout")
            .unwrap();
        assert!(n > 0, "EOF before response head complete");
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_subsequence(&buf, b"\r\n\r\n") {
            break pos;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_lowercase();
    if let Some(cl) = head.lines().find_map(|l| l.strip_prefix("content-length:")) {
        let want: usize = cl.trim().parse().unwrap();
        while buf.len() < head_end + 4 + want {
            let n = tokio::time::timeout(Duration::from_secs(5), sock.read(&mut tmp))
                .await
                .expect("body timeout")
                .unwrap();
            assert!(n > 0, "EOF before response body complete");
            buf.extend_from_slice(&tmp[..n]);
        }
    }
    String::from_utf8_lossy(&buf).to_string()
}

/// 读到 EOF（连接被代理关闭）。返回 EOF 前收到的剩余字节。
async fn read_to_eof(sock: &mut TcpStream) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 2048];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(5), sock.read(&mut tmp))
            .await
            .expect("eof timeout (connection not closed by proxy)")
            .unwrap();
        if n == 0 {
            return buf;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

/// 场景 A：同一连接 2 个 plain HTTP 请求且带 `Proxy-Connection: keep-alive`
/// → 两个都 200（抓包证明同一四元组，见 tmp/ 捕获报告）。
#[tokio::test]
async fn plain_http_keep_alive_two_requests_same_connection_e2e() {
    // 后端：每请求一条新 upstream 连接（对齐 Go Dispatch 每请求新 link），
    // 各回 Content-Length 响应
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    xray_common::testing::spawn("http-target-keepalive", async move {
        for _ in 0..2 {
            let (mut sock, _) = target.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let n = sock.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            assert!(req.starts_with("GET /"), "upstream got: {req}");
            assert!(
                req.contains("connection: close"),
                "forwarded request must carry Connection: close: {req}"
            );
            sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await.unwrap();
            // 半关 + 排空：立即 drop 带未读数据的 socket 在 Windows 上发 RST，
            // 会截断 proxy 侧读向（RST 丢弃接收缓冲）
            let _ = sock.shutdown().await;
            let mut sink = [0u8; 512];
            while sock.read(&mut sink).await.unwrap_or(0) > 0 {}
        }
    });

    let proxy_addr = spawn_http_proxy(ServerConfig::default()).await;

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let req_tpl = format!(
        "GET http://127.0.0.1:{}/{{}} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nProxy-Connection: keep-alive\r\n\r\n",
        target_addr.port(),
        target_addr.port(),
    );
    // 第 1 个请求
    client.write_all(req_tpl.replace("{}", "a").as_bytes()).await.unwrap();
    let resp1 = read_http_response(&mut client).await;
    assert!(resp1.starts_with("HTTP/1.1 200"), "resp1: {resp1}");
    assert!(resp1.contains("ok"), "resp1 body: {resp1}");
    assert!(
        resp1.to_lowercase().contains("proxy-connection: keep-alive"),
        "resp1 must keep alive: {resp1}"
    );
    assert!(
        resp1.to_lowercase().contains("keep-alive: timeout=60"),
        "resp1 must carry Keep-Alive header: {resp1}"
    );
    // 第 2 个请求（同一 TCP 连接）
    client.write_all(req_tpl.replace("{}", "b").as_bytes()).await.unwrap();
    let resp2 = read_http_response(&mut client).await;
    assert!(resp2.starts_with("HTTP/1.1 200"), "resp2: {resp2}");
    assert!(resp2.contains("ok"), "resp2 body: {resp2}");
}

/// 场景 B：不带 `Proxy-Connection: keep-alive` → 第一个响应后代理关连接
/// （抓包：一条 FIN，见 tmp/ 捕获报告）。
#[tokio::test]
async fn plain_http_without_keep_alive_closes_after_response_e2e() {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    xray_common::testing::spawn("http-target-no-keepalive", async move {
        let (mut sock, _) = target.accept().await.unwrap();
        let mut buf = [0u8; 4096];
        let _ = sock.read(&mut buf).await.unwrap();
        sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await.unwrap();
        // 半关 + 排空（立即 drop 带未读数据 → Windows RST 截断 proxy 读向）
        let _ = sock.shutdown().await;
        let mut sink = [0u8; 512];
        while sock.read(&mut sink).await.unwrap_or(0) > 0 {}
    });

    let proxy_addr = spawn_http_proxy(ServerConfig::default()).await;

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let req = format!(
        "GET http://127.0.0.1:{}/only HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        target_addr.port(),
        target_addr.port(),
    );
    client.write_all(req.as_bytes()).await.unwrap();
    let resp = read_http_response(&mut client).await;
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    // 对齐 Go：responseDone 只看 ContentLength，响应头写 keep-alive 三头；
    // 但 Process 层 keepAlive=false → 不循环 → 关连接
    assert!(resp.to_lowercase().contains("proxy-connection: keep-alive"), "{resp}");
    let trailing = read_to_eof(&mut client).await;
    assert!(trailing.is_empty(), "unexpected trailing bytes: {trailing:?}");
}

/// 场景 C：上游响应无 Content-Length（chunked）→ 不循环，响应后关连接；
/// chunk 帧原样透传。
#[tokio::test]
async fn plain_http_chunked_response_no_loop_close_e2e() {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    xray_common::testing::spawn("http-target-chunked", async move {
        let (mut sock, _) = target.accept().await.unwrap();
        let mut buf = [0u8; 4096];
        let _ = sock.read(&mut buf).await.unwrap();
        sock.write_all(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
              5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
        )
        .await
        .unwrap();
        // 半关 + 排空（立即 drop 带未读数据 → Windows RST 截断 proxy 读向，
        // chunk 透传会中断在第一帧）
        let _ = sock.shutdown().await;
        let mut sink = [0u8; 512];
        while sock.read(&mut sink).await.unwrap_or(0) > 0 {}
    });

    let proxy_addr = spawn_http_proxy(ServerConfig::default()).await;

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let req = format!(
        "GET http://127.0.0.1:{}/chunk HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nProxy-Connection: keep-alive\r\n\r\n",
        target_addr.port(),
        target_addr.port(),
    );
    client.write_all(req.as_bytes()).await.unwrap();
    // 即使客户端请求 keep-alive，无 Content-Length 也不循环
    let mut resp = read_http_response(&mut client).await;
    resp.push_str(&String::from_utf8_lossy(&read_to_eof(&mut client).await));
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    assert!(resp.to_lowercase().contains("transfer-encoding: chunked"), "{resp}");
    assert!(resp.to_lowercase().contains("connection: close"), "{resp}");
    assert!(resp.to_lowercase().contains("proxy-connection: close"), "{resp}");
    assert!(resp.contains("5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"), "chunk frames: {resp}");
}

/// 场景 D：allow_transparent=false 且 origin-form（无 host）→ 400 + 两个 close 头。
#[tokio::test]
async fn plain_http_origin_form_rejected_400_when_not_transparent_e2e() {
    let proxy_addr = spawn_http_proxy(ServerConfig::default()).await; // allow_transparent=false

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client.write_all(b"GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n").await.unwrap();
    let resp = read_http_response(&mut client).await;
    assert!(resp.starts_with("HTTP/1.1 400"), "{resp}");
    let lower = resp.to_lowercase();
    assert!(lower.contains("proxy-connection: close"), "{resp}");
    assert!(lower.contains("connection: close"), "{resp}");
    let trailing = read_to_eof(&mut client).await;
    assert!(trailing.is_empty(), "connection must close: {trailing:?}");
}

/// 场景 E：上游读响应失败（accept 后立即断开）→ 503 + 双 close 头 + 关连接。
#[tokio::test]
async fn plain_http_upstream_failure_returns_503_e2e() {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    xray_common::testing::spawn("http-target-drops-conn", async move {
        let (sock, _) = target.accept().await.unwrap();
        drop(sock); // 不回响应直接断
    });

    let proxy_addr = spawn_http_proxy(ServerConfig::default()).await;

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let req = format!(
        "GET http://127.0.0.1:{}/down HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        target_addr.port(),
        target_addr.port(),
    );
    client.write_all(req.as_bytes()).await.unwrap();
    let resp = read_http_response(&mut client).await;
    assert!(resp.starts_with("HTTP/1.1 503"), "{resp}");
    let lower = resp.to_lowercase();
    assert!(lower.contains("connection: close"), "{resp}");
    assert!(lower.contains("proxy-connection: close"), "{resp}");
    let trailing = read_to_eof(&mut client).await;
    assert!(trailing.is_empty(), "connection must close: {trailing:?}");
}
