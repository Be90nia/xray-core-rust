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
    // Go 26.10.17 二进制实测（`D:/tmp/probe_chunked.py` 同场景）：chunked 上游
    // （Transfer-Encoding、无 Content-Length）时 Go 的 `handlePlainHTTP` 只置
    // `response.Close = true`（server.go:276-279），由 transferWriter 写
    // `Connection: close`；`Proxy-Connection` **只在 400/503 错误路径**成对下发
    // （server.go:218-219 / :294-295）。原断言要求该头属非 Go 行为，已按实测改判。
    assert!(!resp.to_lowercase().contains("proxy-connection"), "{resp}");
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

// ===== 请求解析对拍 Go v26.9.9（bd afgov，`reports/audit-2026-10-29/parity-s2-parser.md`）=====
//
// 用例编号与报告 §1 一一对应；判据同报告：状态行 + body + 是否被断链。

/// 一次性源站：accept 一条连接 → 读一次 → 回固定 `200` + body `ok`。
async fn spawn_ok_origin(name: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    xray_common::testing::spawn(name, async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 4096];
        let _ = sock.read(&mut buf).await.unwrap();
        sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await.unwrap();
        // 半关 + 排空：立即 drop 带未读数据的 socket 在 Windows 上发 RST，
        // 会截断 proxy 侧读向（见既有场景注释）
        let _ = sock.shutdown().await;
        let mut sink = [0u8; 512];
        while sock.read(&mut sink).await.unwrap_or(0) > 0 {}
    });
    addr
}

/// 发一段字节给代理，断言「零响应字节 + 连接被关闭」——Go `http.ReadRequest`
/// 失败后 `Process` 直接断链、不回响应（H03/H09/H10/H19/H20 的 Go 侧实测形态）。
///
/// 目标用**活源站**：修复前这些畸形请求会被宽松接受并正常转发回 200，断言才有判别力
/// （拿不可达端口会因 dial 失败静默断链而假绿）。
async fn assert_rejected_without_response(build: impl Fn(u16) -> Vec<u8>) {
    let origin = spawn_ok_origin("http-origin-reject").await;
    let proxy_addr = spawn_http_proxy(ServerConfig::default()).await;
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client.write_all(&build(origin.port())).await.unwrap();
    let received = read_to_eof(&mut client).await;
    assert!(
        received.is_empty(),
        "malformed request must be rejected with no response, got {:?}",
        String::from_utf8_lossy(&received)
    );
}

/// H15（D-6）：裸 LF 换行必须像 Go 一样立即解析并 200——**绝不得**静默挂到 60s
/// 握手限时（客户端会以为代理已死）。
#[tokio::test]
async fn http_bare_lf_request_accepted_e2e() {
    let origin = spawn_ok_origin("http-origin-bare-lf").await;
    let proxy_addr = spawn_http_proxy(ServerConfig::default()).await;
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let req = format!(
        "GET http://127.0.0.1:{p}/cl HTTP/1.1\nHost: 127.0.0.1:{p}\nConnection: close\n\n",
        p = origin.port()
    );
    client.write_all(req.as_bytes()).await.unwrap();
    let resp = tokio::time::timeout(Duration::from_secs(2), read_http_response(&mut client))
        .await
        .expect("bare-LF request must not hang (Go answers immediately)");
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    assert!(resp.ends_with("ok"), "{resp}");
}

/// H30（D-8）：绝对 URI 的 userinfo 归 `URL.User`，host 只取 authority 的 host 段
/// （Go `net/url` `parseAuthority`：`LastIndex("@")` 之后才是 host）。
#[tokio::test]
async fn http_absolute_uri_with_userinfo_routes_to_host_e2e() {
    let origin = spawn_ok_origin("http-origin-userinfo").await;
    let proxy_addr = spawn_http_proxy(ServerConfig::default()).await;
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let req = format!(
        "GET http://user:pass@127.0.0.1:{p}/cl HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\n\
         Connection: close\r\n\r\n",
        p = origin.port()
    );
    client.write_all(req.as_bytes()).await.unwrap();
    let resp = read_http_response(&mut client).await;
    assert!(resp.starts_with("HTTP/1.1 200"), "userinfo must not leak into host: {resp}");
}

/// H19/H20（D-7）：畸形 header 行（无冒号 / 空头名）不得静默丢弃——拒绝并断链。
#[tokio::test]
async fn http_header_line_without_colon_rejected_e2e() {
    assert_rejected_without_response(|p| {
        format!(
            "GET http://127.0.0.1:{p}/cl HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\nBadHeader\r\n\
             Connection: close\r\n\r\n"
        )
        .into_bytes()
    })
    .await;
}

/// H20：空头名（`: v`）——Go `canonicalMIMEHeaderKey` 对空名返回 ok=false。
#[tokio::test]
async fn http_empty_header_name_rejected_e2e() {
    assert_rejected_without_response(|p| {
        format!(
            "GET http://127.0.0.1:{p}/cl HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\n: v\r\n\
             Connection: close\r\n\r\n"
        )
        .into_bytes()
    })
    .await;
}

/// H03/H04/H05/H13（D-1）：请求行严格单空格三切分——双空格/尾空格/URI 内空格
/// 全部落到版本段而失败（Go `parseRequestLine` + `ParseHTTPVersion`）。
#[tokio::test]
async fn http_request_line_double_space_rejected_e2e() {
    assert_rejected_without_response(|p| {
        format!(
            "GET  http://127.0.0.1:{p}/cl HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\n\
             Connection: close\r\n\r\n"
        )
        .into_bytes()
    })
    .await;
}

/// H13：URI 内含空格（第三段以 `b HTTP/1.1` 起头）→ 版本非法。
#[tokio::test]
async fn http_request_line_space_in_uri_rejected_e2e() {
    assert_rejected_without_response(|p| {
        format!(
            "GET http://127.0.0.1:{p}/a b HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\n\
             Connection: close\r\n\r\n"
        )
        .into_bytes()
    })
    .await;
}

/// H09/H10（D-5）：URI 含控制字符 / NUL —— Go `net/url` `stringContainsCTLByte` 拒绝。
#[tokio::test]
async fn http_control_char_in_uri_rejected_e2e() {
    assert_rejected_without_response(|p| {
        format!(
            "GET http://127.0.0.1:{p}/a\x01b HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\n\
             Connection: close\r\n\r\n"
        )
        .into_bytes()
    })
    .await;
    assert_rejected_without_response(|p| {
        format!(
            "GET http://127.0.0.1:{p}/a\x00b HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\n\
             Connection: close\r\n\r\n"
        )
        .into_bytes()
    })
    .await;
}

/// H06（D-3）：URI 里的非法 UTF-8 单字节（latin-1 `é`）Go 照收（net/url 允许 ≥0x80
/// 原始字节）——不得因解码失败断链。
#[tokio::test]
async fn http_non_utf8_uri_accepted_e2e() {
    let origin = spawn_ok_origin("http-origin-non-utf8").await;
    let proxy_addr = spawn_http_proxy(ServerConfig::default()).await;
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let mut req = format!("GET http://127.0.0.1:{}/x", origin.port()).into_bytes();
    req.extend_from_slice(b"\xe9");
    req.extend_from_slice(
        format!(" HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n", origin.port())
            .as_bytes(),
    );
    client.write_all(&req).await.unwrap();
    let resp = read_http_response(&mut client).await;
    assert!(resp.starts_with("HTTP/1.1 200"), "non-UTF-8 URI must not断链: {resp}");
}

/// H17/H08（D-2）：16KB 级请求行/header 行 Go 照收（`http.ReadRequest` 手工调用不套
/// `MaxHeaderBytes`）——不得按 16KB 断链。
#[tokio::test]
async fn http_16k_header_line_accepted_e2e() {
    let origin = spawn_ok_origin("http-origin-16k-header").await;
    let proxy_addr = spawn_http_proxy(ServerConfig::default()).await;
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let big = "a".repeat(16 * 1024);
    let req = format!(
        "GET http://127.0.0.1:{p}/cl HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\nX-Big: {big}\r\n\
         Connection: close\r\n\r\n",
        p = origin.port()
    );
    client.write_all(req.as_bytes()).await.unwrap();
    let resp = read_http_response(&mut client).await;
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
}

/// H18（D-2）：200 个 header 行 Go 照收（无行数上限）——不得按 128 行断链。
#[tokio::test]
async fn http_200_header_lines_accepted_e2e() {
    let origin = spawn_ok_origin("http-origin-200-headers").await;
    let proxy_addr = spawn_http_proxy(ServerConfig::default()).await;
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let mut req = format!(
        "GET http://127.0.0.1:{p}/cl HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\n",
        p = origin.port()
    );
    for i in 0..200 {
        req.push_str(&format!("X-Pad-{i}: v\r\n"));
    }
    req.push_str("Connection: close\r\n\r\n");
    client.write_all(req.as_bytes()).await.unwrap();
    let resp = read_http_response(&mut client).await;
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
}

// ===== 字节保真（bd t3lzr）：非 UTF-8 头值/URI 原样转发，Go v26.9.9 对拍 =====

/// 抓取型源站：accept 一条连接 → 读完整请求（head + content-length body）→ 回 200
/// → 回报 (head 原始字节, body 原始字节)。head 不含结尾空行。
async fn spawn_capturing_origin(
    name: &'static str,
) -> (SocketAddr, tokio::sync::mpsc::UnboundedReceiver<(Vec<u8>, Vec<u8>)>) {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    xray_common::testing::spawn(name, async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = Vec::new();
        let mut tmp = [0u8; 2048];
        let head_end = loop {
            let n = sock.read(&mut tmp).await.unwrap();
            assert!(n > 0, "origin EOF before head complete");
            buf.extend_from_slice(&tmp[..n]);
            if let Some(pos) = find_subsequence(&buf, b"\r\n\r\n") {
                break pos;
            }
        };
        let head = buf[..head_end].to_vec();
        let mut body = buf[head_end + 4..].to_vec();
        let want = head
            .split(|&b| b == b'\n')
            .find_map(|line| {
                let line = line.strip_suffix(b"\r").unwrap_or(line);
                let idx = line.iter().position(|&b| b == b':')?;
                let (k, v) = (&line[..idx], &line[idx + 1..]);
                if !k.eq_ignore_ascii_case(b"content-length") {
                    return None;
                }
                std::str::from_utf8(v).ok()?.trim().parse::<usize>().ok()
            })
            .unwrap_or(0);
        while body.len() < want {
            let n = sock.read(&mut tmp).await.unwrap();
            assert!(n > 0, "origin EOF before body complete");
            body.extend_from_slice(&tmp[..n]);
        }
        body.truncate(want);
        let _ = tx.send((head, body));
        sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await.unwrap();
        // 半关 + 排空：立即 drop 带未读数据的 socket 在 Windows 上发 RST（见既有注释）
        let _ = sock.shutdown().await;
        let mut sink = [0u8; 512];
        while sock.read(&mut sink).await.unwrap_or(0) > 0 {}
    });
    (addr, rx)
}

/// 一条 plain HTTP 请求经真实 `HttpServer` serve 路径转发，返回上游收到的原始字节。
async fn forward_and_capture(
    name: &'static str,
    build: impl FnOnce(u16) -> Vec<u8>,
) -> (Vec<u8>, Vec<u8>) {
    let (origin, mut rx) = spawn_capturing_origin(name).await;
    let proxy_addr = spawn_http_proxy(ServerConfig::default()).await;
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client.write_all(&build(origin.port())).await.unwrap();
    client.shutdown().await.unwrap();
    let resp = read_to_eof(&mut client).await;
    assert!(
        resp.starts_with(b"HTTP/1.1 200"),
        "proxy response must be 200, got {:?}",
        String::from_utf8_lossy(&resp)
    );
    tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("origin report timeout")
        .expect("origin reported a request")
}

/// T1（bd t3lzr）：非 UTF-8 头值按原字节到达上游（Go `X-Bin: e9ff`，修复前退化成
/// `efbfbdefbfbd` 两个 U+FFFD）。
#[tokio::test]
async fn http_plain_forward_preserves_non_utf8_header_value_e2e() {
    let (head, _body) = forward_and_capture("http-origin-bin-headerval", |port| {
        let mut req =
            format!("GET http://127.0.0.1:{port}/t1 HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-Bin: ")
                .into_bytes();
        req.extend_from_slice(b"\xe9\xff");
        req.extend_from_slice(b"\r\nConnection: close\r\n\r\n");
        req
    })
    .await;
    assert!(
        find_subsequence(&head, b"x-bin: \xe9\xff").is_some(),
        "非 UTF-8 头值必须原样到达上游，实际 head = {:?}",
        String::from_utf8_lossy(&head)
    );
    assert!(
        find_subsequence(&head, b"\xef\xbf\xbd").is_none(),
        "不得出现 U+FFFD 替换字节: {:?}",
        String::from_utf8_lossy(&head)
    );
}

/// T2（bd t3lzr）：请求行里的非 ASCII 字节按 Go `url.URL.EscapedPath` 转义
/// （`/t2/\xe9` → `/t2/%E9`），不是 U+FFFD。
#[tokio::test]
async fn http_plain_forward_percent_encodes_non_ascii_uri_e2e() {
    let (head, _body) = forward_and_capture("http-origin-nonascii-uri", |port| {
        let mut req = format!("GET http://127.0.0.1:{port}/t2/").into_bytes();
        req.extend_from_slice(b"\xe9");
        req.extend_from_slice(
            format!(" HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n").as_bytes(),
        );
        req
    })
    .await;
    assert!(
        find_subsequence(&head, b"GET /t2/%E9 HTTP/1.1\r\n").is_some(),
        "非 ASCII 路径字节须转义为 %E9，实际 head = {:?}",
        String::from_utf8_lossy(&head)
    );
}

/// T4（bd t3lzr 防回归）：合法 UTF-8 头值原样到达上游（`中` = e4b8ad）。
#[tokio::test]
async fn http_plain_forward_keeps_utf8_header_value_e2e() {
    let (head, _body) = forward_and_capture("http-origin-utf8-headerval", |port| {
        let mut req = format!(
            "GET http://127.0.0.1:{port}/t4 HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-Utf8: "
        )
        .into_bytes();
        req.extend_from_slice(b"\xe4\xb8\xad");
        req.extend_from_slice(b"\r\nConnection: close\r\n\r\n");
        req
    })
    .await;
    assert!(
        find_subsequence(&head, b"x-utf8: \xe4\xb8\xad").is_some(),
        "UTF-8 头值必须不变，实际 head = {:?}",
        String::from_utf8_lossy(&head)
    );
}

/// T3（bd t3lzr 防回归）：非 UTF-8 请求体逐字节到达上游（body 路径本已正确，锁死）。
#[tokio::test]
async fn http_plain_forward_preserves_non_utf8_body_e2e() {
    let (_head, body) = forward_and_capture("http-origin-bin-body", |port| {
        let mut req = format!(
            "POST http://127.0.0.1:{port}/t3 HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\
             Content-Length: 4\r\nConnection: close\r\n\r\n"
        )
        .into_bytes();
        req.extend_from_slice(b"\xe9\xff\x80\x01");
        req
    })
    .await;
    assert_eq!(body, b"\xe9\xff\x80\x01", "body 必须逐字节到达上游");
}
