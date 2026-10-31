//! G4 线上取证：splithttp 服务端配额（票 3zbwx / 2xgln / dct2d）。
//!
//! 三个测试都打真实 listener（`listen_splithttp`），不是 mock：
//! - packet-up `Content-Length` 超限 → 413 且不读 body（dct2d 的 wire 侧证据）
//! - 会话表满 → 429（3zbwx）
//! - h2 SETTINGS 声明 250 并发流，第 251 条被 RST_STREAM(REFUSED_STREAM)（2xgln）

// 测试编译单元统一豁免（数据面分配纪律见 crate clippy.toml）
#![allow(clippy::disallowed_methods)]
#![allow(clippy::unwrap_used)] // 测试断言便利豁免（allow-unwrap-in-tests 对 tests/ 目录失效，clippy#13981）

use std::{io, sync::Arc, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use xray_transport::{
    dialer::StreamSettings, listener_registry::ConnHandler, sockopt::SocketOptions,
};
use xray_transport_splithttp::transport::listen_splithttp;

/// 缺省 x_padding 范围 [100, 1000] 内的合法值（100 也保证 :path 值 < 127 字节，
/// 让手写 HPACK 免去 varint 编码）。
const PAD: &str = "x_padding=";

fn padding_query() -> String {
    format!("{PAD}{}", "X".repeat(100))
}

async fn start_listener() -> (Box<dyn xray_transport::listener_registry::TransportListener>, u16) {
    let settings = StreamSettings {
        protocol: "splithttp".to_string(),
        transport_json: Some(serde_json::json!({"path": "/xhttp"})),
        ..StreamSettings::tcp()
    };
    let handler: ConnHandler = Arc::new(|_conn| {});
    let listener = listen_splithttp(
        "127.0.0.1:0".parse().unwrap(),
        &settings,
        &SocketOptions::default(),
        handler,
    )
    .await
    .expect("listen");
    let addr = listener.local_addr().expect("local_addr");
    (listener, addr.port())
}

/// 读到响应头结束，返回状态码。
async fn read_status(stream: &mut TcpStream) -> u16 {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        stream.read_exact(&mut byte).await.expect("读响应头");
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        assert!(buf.len() < 8192, "响应头过长: {buf:?}");
    }
    let head = String::from_utf8_lossy(&buf);
    let line = head.lines().next().expect("状态行");
    line.split_whitespace().nth(1).expect("状态码").parse().expect("状态码数字")
}

/// dct2d wire 侧：`Content-Length` 超限，客户端一个 body 字节都没发，服务端即回 413。
#[tokio::test]
async fn packet_up_oversize_content_length_is_413_without_body() {
    let (listener, port) = start_listener().await;
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.expect("connect");
    let req = format!(
        "POST /xhttp/sess-big/0?{} HTTP/1.1\r\nHost: h\r\nContent-Length: 2000000000\r\n\r\n",
        padding_query()
    );
    s.write_all(req.as_bytes()).await.expect("写请求头");
    let status = tokio::time::timeout(Duration::from_secs(5), read_status(&mut s))
        .await
        .expect("413 必须在 5s 内返回（超时=服务端还在等 body）");
    assert_eq!(status, 413, "超限 Content-Length 必须 413");
    listener.close().expect("close");
}

/// 3zbwx：真实 listener 上网关与会话表门都生效——超长 id 400、表满 429。
#[tokio::test]
async fn session_gate_rejects_malformed_id_and_full_table() {
    let (listener, port) = start_listener().await;

    // 1) 超长 id（> 128）→ 400
    let long_id = "a".repeat(200);
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.expect("connect");
    let req = format!(
        "POST /xhttp/{long_id}/0?{} HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\n",
        padding_query()
    );
    s.write_all(req.as_bytes()).await.expect("写请求");
    assert_eq!(read_status(&mut s).await, 400, "超长 session id 必须 400");
    drop(s);

    // 2) 灌满会话表（DEFAULT_MAX_SESSIONS = 1024）：1024 个不同 id 全部 200， 第 1025 个必须 429。
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.expect("connect");
    for i in 0..1024u32 {
        let req = format!(
            "POST /xhttp/fill{i}/0?{} HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\n",
            padding_query()
        );
        s.write_all(req.as_bytes()).await.expect("写请求");
        let status = tokio::time::timeout(Duration::from_secs(5), read_status(&mut s))
            .await
            .expect("填表请求必须及时响应");
        assert_eq!(status, 200, "第 {i} 个会话应成功");
    }
    let req = format!(
        "POST /xhttp/overflow/0?{} HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\n",
        padding_query()
    );
    s.write_all(req.as_bytes()).await.expect("写请求");
    let status = tokio::time::timeout(Duration::from_secs(5), read_status(&mut s))
        .await
        .expect("越限请求必须及时响应");
    assert_eq!(status, 429, "会话表满后新 id 必须 429（fail-visible）");

    listener.close().expect("close");
}

// ===== 2xgln：h2 并发流上限（raw h2 客户端，忽略 SETTINGS 才能越限）=====

const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// 客户端 SETTINGS（空负载，让服务端不必等 ACK）。
const EMPTY_SETTINGS: [u8; 9] = [0, 0, 0, 0x04, 0x00, 0, 0, 0, 0];
/// SETTINGS ACK。
const SETTINGS_ACK: [u8; 9] = [0, 0, 0, 0x04, 0x01, 0, 0, 0, 0];

struct Frame {
    kind: u8,
    sid: u32,
    payload: Vec<u8>,
}

async fn read_frame(s: &mut TcpStream) -> io::Result<Frame> {
    let mut hdr = [0u8; 9];
    s.read_exact(&mut hdr).await?;
    let len = ((hdr[0] as usize) << 16) | ((hdr[1] as usize) << 8) | hdr[2] as usize;
    let sid = u32::from_be_bytes([hdr[5] & 0x7f, hdr[6], hdr[7], hdr[8]]);
    let mut payload = vec![0u8; len];
    s.read_exact(&mut payload).await?;
    Ok(Frame { kind: hdr[3], sid, payload })
}

/// 最小 HPACK：全字面量、无索引、不更新动态表（不依赖对端表状态）。
///
/// 编码要点（RFC 7541 §6.2.2 "Literal Header Field without Indexing — New Name"）：
/// - 首字节 = pattern `0000` + 4 位索引 0（新名字，无索引引用）→ 恒 `0x00`
/// - 名字 = 7 位前缀字符串字面量（H=0，≤127 时单字节长度）
/// - 值 = 7 位前缀字符串字面量（H=0，≤127 时单字节长度）
fn push_literal(block: &mut Vec<u8>, name: &str, value: &str) {
    assert!(name.len() < 127 && value.len() < 127, "测试只编短头字段（免 varint）");
    block.push(0x00);
    block.push(name.len() as u8);
    block.extend_from_slice(name.as_bytes());
    block.push(value.len() as u8);
    block.extend_from_slice(value.as_bytes());
}

fn headers_frame(stream_id: u32, path: &str, end_stream: bool) -> Vec<u8> {
    let mut block = Vec::new();
    for (name, value) in
        [(":method", "POST"), (":scheme", "http"), (":path", path), (":authority", "h")]
    {
        push_literal(&mut block, name, value);
    }
    let len = block.len();
    let mut f = vec![0u8; 9];
    f[0] = (len >> 16) as u8;
    f[1] = (len >> 8) as u8;
    f[2] = len as u8;
    f[3] = 0x01; // HEADERS
    f[4] = if end_stream { 0x05 } else { 0x04 }; // END_HEADERS (+ END_STREAM)
    f[5..9].copy_from_slice(&stream_id.to_be_bytes());
    f.extend_from_slice(&block);
    f
}

/// 2xgln 对照：raw 客户端打单流必须被正常服务（否则越限测试的失败无法归因）。
#[tokio::test]
async fn single_raw_h2_request_is_accepted() {
    let (listener, port) = start_listener().await;
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.expect("connect");
    s.write_all(H2_PREFACE).await.expect("preface");
    s.write_all(&EMPTY_SETTINGS).await.expect("client settings");
    let settings = tokio::time::timeout(Duration::from_secs(5), read_frame(&mut s))
        .await
        .expect("服务端 SETTINGS")
        .expect("读 SETTINGS");
    assert_eq!(settings.kind, 0x04);
    s.write_all(&SETTINGS_ACK).await.expect("ack");

    let path = format!("/xhttp/s1/0?{}", padding_query());
    s.write_all(&headers_frame(1, &path, true)).await.expect("写 HEADERS");

    // 收到响应 HEADERS 即证明 raw 客户端编解码合法。
    let f = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let f = read_frame(&mut s).await.expect("读帧");
            if f.kind == 0x01 || f.kind == 0x07 {
                return f;
            }
        }
    })
    .await
    .expect("响应必须在 5s 内到达");
    assert_eq!(f.kind, 0x01, "非 GOAWAY：单流必须被正常服务");
    assert_eq!(f.sid, 1);
    listener.close().expect("close");
}

/// 2xgln：服务端 SETTINGS 声明 MAX_CONCURRENT_STREAMS=250，第 251 条 HEADERS 被
/// RST_STREAM(REFUSED_STREAM)。
#[tokio::test]
async fn h2_rejects_streams_past_max_concurrent() {
    let (listener, port) = start_listener().await;
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.expect("connect");
    s.write_all(H2_PREFACE).await.expect("preface");
    s.write_all(&EMPTY_SETTINGS).await.expect("client settings");

    // 服务端 SETTINGS：确认 MAX_CONCURRENT_STREAMS（id=3）已下发。
    let settings = tokio::time::timeout(Duration::from_secs(5), read_frame(&mut s))
        .await
        .expect("服务端 SETTINGS 必须在 5s 内到达")
        .expect("读 SETTINGS");
    assert_eq!(settings.kind, 0x04, "首帧必须是 SETTINGS");
    let mut max_concurrent = None;
    for chunk in settings.payload.chunks_exact(6) {
        let id = u16::from_be_bytes([chunk[0], chunk[1]]);
        if id == 3 {
            max_concurrent = Some(u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]));
        }
    }
    assert_eq!(max_concurrent, Some(250), "SETTINGS_MAX_CONCURRENT_STREAMS 必须为 250");
    s.write_all(&SETTINGS_ACK).await.expect("ack");

    // 越限：连开 251 条流（客户端故意忽略 SETTINGS）。
    let path = format!("/xhttp/s0/0?{}", padding_query());
    for i in 0..251u32 {
        s.write_all(&headers_frame(2 * i + 1, &path, false)).await.expect("写 HEADERS");
    }

    // 找 RST_STREAM(REFUSED_STREAM)：错误码在 payload 前 4 字节。
    let outcome = tokio::time::timeout(Duration::from_secs(15), async {
        let mut seen: Vec<String> = Vec::new();
        loop {
            match read_frame(&mut s).await {
                Ok(f) => {
                    seen.push(format!("kind={} sid={} len={}", f.kind, f.sid, f.payload.len()));
                    if f.kind == 0x03 && f.payload.len() >= 4 {
                        let code = u32::from_be_bytes([
                            f.payload[0],
                            f.payload[1],
                            f.payload[2],
                            f.payload[3],
                        ]);
                        return Ok::<_, String>((f.sid, code));
                    }
                    if f.kind == 0x07 {
                        let last = u32::from_be_bytes([
                            f.payload[0] & 0x7f,
                            f.payload[1],
                            f.payload[2],
                            f.payload[3],
                        ]);
                        let code = u32::from_be_bytes([
                            f.payload[4],
                            f.payload[5],
                            f.payload[6],
                            f.payload[7],
                        ]);
                        return Err(format!(
                            "服务端 GOAWAY last_stream={last} code={code}；此前帧: {seen:?}"
                        ));
                    }
                },
                Err(e) => return Err(format!("读帧失败 {e}；此前帧: {seen:?}")),
            }
        }
    })
    .await
    .expect("RST_STREAM 必须在 15s 内到达");
    let refused = outcome.expect("越限必须被拒而非断连");

    assert_eq!(refused.1, 7, "越限流必须 RST_STREAM(REFUSED_STREAM=7)，实际 {refused:?}");
    assert_eq!(refused.0, 501, "被拒的必须是第 251 条流（id=501）");
    listener.close().expect("close");
}
