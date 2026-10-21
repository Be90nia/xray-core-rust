//! Gap-matrix e2e（Go scenarios 对照缺口补齐）：G-04 / G-10 / G-14 / G-15 / G-16。
//!
//! 全部走 `xray_core::functions::start_full` 全实例路径（BuiltConfig → start_full →
//! 真实 inbound/outbound 装配 → 回环客户端验证），对照 Go testing/scenarios：
//!
//! - **G-10** `http_test.go TestHttpBasicAuth/TestSocksWithHttpRequest`： HTTP outbound 带 users →
//!   假代理断言 `Proxy-Authorization: Basic`； HTTP inbound 带 accounts → 缺/错凭据
//!   407、正确凭据放行。
//! - **G-14** `transport_test.go TestHTTPConnectionHeader`：vmess inbound 侧 TCP+HTTP 伪装头
//!   e2e（客户端经 `HeaderConn::client` 真实伪装包装）。
//! - **G-15** `feature_test.go TestDialerProxy`：outbound 底层拨号经另一 outbound
//!   （`sockopt.dialerProxy` → SOCKS5 recorder → trojan 服务器）整链 e2e。
//! - **G-16** `feature_test.go TestForward`：freedom `destinationOverride` 改投 指定服务器整链
//!   e2e（客户端 CONNECT TEST-NET-3 不可路由地址）。
//! - **G-04** `socks_test.go TestSocksBridageUDP`：SOCKS5 UDP ASSOCIATE 全链 e2e （socks inbound
//!   UDP relay → dispatcher → socks outbound ASSOCIATE → 外部 SOCKS5 UDP 服务器），判别器 =
//!   服务器记录 CMD 必须 3（不得 TCP 降级）。
//!
//! 仅回环流量；SOCKS5/HTTP 假服务器以原始字节手写（测试自包含，不加依赖）。

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::timeout,
};
use xray_common::{
    net::{address::Address, destination::Destination, port::Port},
    protocol::{Command, RequestHeader, SecurityType},
    uuid::UUID,
};
use xray_conf::{BuiltConfig, BuiltEntry, BuiltInbound, BuiltOutbound};
use xray_core::functions::start_full;
use xray_proxy_vmess::{
    account::cmd_key_of,
    encoding::{VERSION as VMESS_VERSION, client::ClientSession as VmessClientSession},
};
use xray_transport::{
    connection::{Connection, TcpConnection},
    headers::conn::{auth_from_json, wrap_client},
};

/// TCP 测试载荷。
const PAYLOAD: &[u8] = b"hello gap-matrix e2e!";

/// UDP（G-04）测试载荷。
const UDP_PAYLOAD: &[u8] = b"socks-udp-full-chain-g04";

/// VMess 测试 UUID（与其他集成测试同值，便于排障；各测试独立进程无冲突）。
const VMESS_UUID_STR: &str = "66ad4540-b58c-4ad2-9926-ea63445a9b57";

/// 客户端整体交换超时（防不可路由地址/降级路径挂死拖垮套件）。
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);

/// 监听就绪等待（对齐 e2e_test.rs LISTENER_READY_DELAY）。
const LISTENER_READY_DELAY: Duration = Duration::from_millis(100);

// ============================================================
// 通用测试基建
// ============================================================

/// 挑空闲端口（bind(:0) → drop）。
async fn pick_free_port() -> u16 {
    let probe = TcpListener::bind("127.0.0.1:0").await.expect("probe bind");
    let port = probe.local_addr().expect("probe addr").port();
    drop(probe);
    port
}

/// 多连接 TCP echo 服务器（accept 循环，逐连接回写）。
async fn spawn_tcp_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("echo bind");
    let addr = listener.local_addr().expect("echo addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else { break };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        },
                    }
                }
            });
        }
    });
    addr
}

/// freedom outbound（显式 finalRules allow：loopback 逃生门，对齐 e2e_test.rs）。
fn freedom_allow_all(tag: &str) -> BuiltOutbound {
    BuiltOutbound {
        entry: BuiltEntry {
            kind: "freedom".into(),
            data: br#"{"finalRules":[{"action":"allow","network":"tcp,udp","ip":["127.0.0.0/8","::1/128"]}]}"#
                .to_vec(),
        },
        tag: tag.into(),
        send_through: None,
        stream_settings_json: None,
        proxy_settings_json: None,
        mux_json: None,
        target_strategy: None,
    }
}

/// SOCKS5 no-auth inbound。
fn socks_inbound(tag: &str, port: u16, data: &'static [u8]) -> BuiltInbound {
    BuiltInbound {
        entry: BuiltEntry { kind: "socks".into(), data: data.to_vec() },
        tag: tag.into(),
        port: Some(port),
        listen: Some("127.0.0.1".into()),
        stream_settings_json: None,
        sniffing_json: None,
    }
}

/// 启动 xray 实例并等监听就绪。
async fn start_xray(built: &BuiltConfig) {
    let (_instance, _ohm, _handles) = start_full(built).await.expect("start_full");
    tokio::time::sleep(LISTENER_READY_DELAY).await;
}

/// SOCKS5 CONNECT 客户端：no-auth 握手 → CONNECT 目标 → 写载荷 → 读回显。
/// 返回读到的回显字节（调用方与载荷比对）。
async fn socks5_connect_roundtrip(
    proxy: SocketAddr,
    target: SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let ip = match target.ip() {
        std::net::IpAddr::V4(v) => v.octets(),
        other => return Err(format!("target not ipv4: {other}")),
    };
    let mut c = TcpStream::connect(proxy).await.map_err(|e| e.to_string())?;
    c.write_all(&[0x05, 0x01, 0x00]).await.map_err(|e| e.to_string())?;
    let mut resp = [0u8; 2];
    c.read_exact(&mut resp).await.map_err(|e| e.to_string())?;
    if resp != [0x05, 0x00] {
        return Err(format!("socks5 method reply unexpected: {resp:?}"));
    }
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&ip);
    req.extend_from_slice(&target.port().to_be_bytes());
    c.write_all(&req).await.map_err(|e| e.to_string())?;
    let mut connect_resp = [0u8; 10];
    c.read_exact(&mut connect_resp).await.map_err(|e| e.to_string())?;
    if connect_resp[1] != 0x00 {
        return Err(format!("socks5 CONNECT failed: code {}", connect_resp[1]));
    }
    c.write_all(payload).await.map_err(|e| e.to_string())?;
    let mut got = vec![0u8; payload.len()];
    c.read_exact(&mut got).await.map_err(|e| e.to_string())?;
    Ok(got)
}

// ============================================================
// 假服务器（原始字节手写，自包含）
// ============================================================

/// 记录型 SOCKS5 TCP 服务器：no-auth → 记录 (CMD, 目标) → CONNECT 则回成功并
/// copy_bidirectional 到目标（G-15 recorder）。
async fn spawn_socks5_tcp_recorder() -> (u16, Arc<Mutex<Vec<(u8, SocketAddr)>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("recorder bind");
    let port = listener.local_addr().expect("recorder addr").port();
    let records: Arc<Mutex<Vec<(u8, SocketAddr)>>> = Arc::new(Mutex::new(Vec::new()));
    let rec = Arc::clone(&records);
    tokio::spawn(async move {
        loop {
            let Ok((mut ctrl, _)) = listener.accept().await else { break };
            let rec = Arc::clone(&rec);
            tokio::spawn(async move {
                socks5_noauth_reply(&mut ctrl).await?;
                let (cmd, dst) = socks5_read_request(&mut ctrl).await?;
                rec.lock().expect("recorder lock").push((cmd, dst));
                if cmd != 0x01 {
                    let _ = ctrl.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
                    return Err("only CONNECT forwarded".to_string());
                }
                let _ = ctrl.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0]).await;
                let Ok(mut target) = TcpStream::connect(dst).await else {
                    return Err(format!("recorder target dial failed: {dst}"));
                };
                let _ = tokio::io::copy_bidirectional(&mut ctrl, &mut target).await;
                Ok(())
            });
        }
    });
    (port, records)
}

/// SOCKS5 UDP 回显服务器：no-auth → 记录 CMD → ASSOCIATE 则绑 relay 并原样回显
/// 收到的首个 UDP 帧（帧内 DST 原样回写）。返回 (端口, CMD 记录)（G-04 判别器）。
async fn spawn_socks5_udp_echo() -> (u16, Arc<Mutex<Vec<u8>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("udp echo bind");
    let port = listener.local_addr().expect("udp echo addr").port();
    let cmds: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let out = Arc::clone(&cmds);
    tokio::spawn(async move {
        let Ok((mut ctrl, _)) = listener.accept().await else { return };
        if socks5_noauth_reply(&mut ctrl).await.is_err() {
            return;
        }
        let Ok((cmd, _dst)) = socks5_read_request(&mut ctrl).await else { return };
        out.lock().expect("cmd lock").push(cmd);
        if cmd != 0x03 {
            let _ = ctrl.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
            return;
        }
        let Ok(relay) = UdpSocket::bind("127.0.0.1:0").await else { return };
        let rport = relay.local_addr().expect("relay addr").port();
        if ctrl.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1]).await.is_err() {
            return;
        }
        if ctrl.write_all(&rport.to_be_bytes()).await.is_err() {
            return;
        }
        // 回显一帧后保活 ctrl（SOCKS UDP 语义：ctrl 断则关联终结）
        let mut buf = vec![0u8; 65535];
        if let Ok((n, peer)) = relay.recv_from(&mut buf).await {
            let _ = relay.send_to(&buf[..n], peer).await;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    });
    (port, cmds)
}

/// HTTP CONNECT 假代理：记录完整请求头 → 回 200 → 与 CONNECT 目标对接
/// （G-10 outbound 判别器：断言 `Proxy-Authorization: Basic`）。
async fn spawn_http_connect_proxy() -> (u16, Arc<Mutex<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("http proxy bind");
    let port = listener.local_addr().expect("http proxy addr").port();
    let recorded: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
    let rec = Arc::clone(&recorded);
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else { break };
            let rec = Arc::clone(&rec);
            tokio::spawn(async move {
                // 读到空行为止（请求头）
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                loop {
                    if sock.read_exact(&mut byte).await.is_err() {
                        return;
                    }
                    head.push(byte[0]);
                    if head.ends_with(b"\r\n\r\n") {
                        break;
                    }
                    if head.len() > 16 * 1024 {
                        return;
                    }
                }
                let head_str = String::from_utf8_lossy(&head).to_string();
                *rec.lock().expect("recorded lock") = head_str.clone();
                let Some(target) = head_str
                    .lines()
                    .next()
                    .and_then(|l| l.strip_prefix("CONNECT "))
                    .and_then(|rest| rest.split_whitespace().next())
                else {
                    let _ = sock.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
                    return;
                };
                let Ok(mut target_sock) = TcpStream::connect(target).await else {
                    let _ = sock.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                    return;
                };
                let _ = sock.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await;
                let _ = tokio::io::copy_bidirectional(&mut sock, &mut target_sock).await;
            });
        }
    });
    (port, recorded)
}

/// SOCKS5 方法协商（no-auth）：读 greeting → 回 `[05 00]`。
async fn socks5_noauth_reply<S>(stream: &mut S) -> Result<(), String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut hdr = [0u8; 2];
    stream.read_exact(&mut hdr).await.map_err(|e| e.to_string())?;
    let mut methods = vec![0u8; usize::from(hdr[1])];
    stream.read_exact(&mut methods).await.map_err(|e| e.to_string())?;
    stream.write_all(&[0x05, 0x00]).await.map_err(|e| e.to_string())
}

/// 读 SOCKS5 请求头：返回 (CMD, 解析后的目标)。只支持 ATYP=IPv4（测试目标恒 IPv4）。
async fn socks5_read_request<S>(stream: &mut S) -> Result<(u8, SocketAddr), String>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await.map_err(|e| e.to_string())?;
    let (cmd, atyp) = (head[1], head[3]);
    match atyp {
        0x01 => {
            let mut o = [0u8; 6];
            stream.read_exact(&mut o).await.map_err(|e| e.to_string())?;
            let addr =
                SocketAddr::from(([o[0], o[1], o[2], o[3]], u16::from_be_bytes([o[4], o[5]])));
            Ok((cmd, addr))
        },
        0x03 => {
            let mut l = [0u8; 1];
            stream.read_exact(&mut l).await.map_err(|e| e.to_string())?;
            let mut rest = vec![0u8; usize::from(l[0]) + 2];
            stream.read_exact(&mut rest).await.map_err(|e| e.to_string())?;
            let port = u16::from_be_bytes([rest[rest.len() - 2], rest[rest.len() - 1]]);
            let host = String::from_utf8_lossy(&rest[..rest.len() - 2]).to_string();
            let addr = tokio::net::lookup_host((host.as_str(), port))
                .await
                .map_err(|e| format!("resolve {host}: {e}"))?
                .next()
                .ok_or_else(|| format!("resolve {host}: no addr"))?;
            Ok((cmd, addr))
        },
        other => Err(format!("unsupported ATYP {other}")),
    }
}

/// SOCKS5 UDP 帧编码：RSV RSV FRAG=0 ATYP=IPv4 ADDR PORT PAYLOAD。
fn socks_udp_frame(ip: [u8; 4], port: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = vec![0u8, 0, 0, 0x01];
    f.extend_from_slice(&ip);
    f.extend_from_slice(&port.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// 解析 SOCKS5 UDP 帧的 (IP, PORT, PAYLOAD)。
fn parse_socks_udp_frame(f: &[u8]) -> Option<([u8; 4], u16, &[u8])> {
    if f.len() < 10 || f[3] != 0x01 {
        return None;
    }
    let ip = [f[4], f[5], f[6], f[7]];
    let port = u16::from_be_bytes([f[8], f[9]]);
    Some((ip, port, &f[10..]))
}

// ============================================================
// G-10 HTTP Basic Auth
// ============================================================

/// G-10（Go TestSocksWithHttpRequest + TestHttpBasicAuth outbound 腿）：带 users 的
/// HTTP outbound → 假代理必须看到 `Proxy-Authorization: Basic <b64(user:pass)>`，
/// 且载荷经 CONNECT 隧道完整回环。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g10_http_outbound_sends_proxy_authorization_basic() {
    let echo = spawn_tcp_echo().await;
    let (proxy_port, recorded) = spawn_http_connect_proxy().await;
    let socks_port = pick_free_port().await;

    let mut built = BuiltConfig::default();
    built.inbounds.push(socks_inbound("socks-in", socks_port, br#"{"auth":"noauth"}"#));
    built.outbounds.push(BuiltOutbound {
        entry: BuiltEntry {
            kind: "http".into(),
            data: json!({
                "servers": [{
                    "address": "127.0.0.1",
                    "port": proxy_port,
                    "users": [{"user": "a", "pass": "b"}]
                }]
            })
            .to_string()
            .into_bytes(),
        },
        tag: "http-out".into(),
        send_through: None,
        stream_settings_json: None,
        proxy_settings_json: None,
        mux_json: None,
        target_strategy: None,
    });
    start_xray(&built).await;

    let proxy_addr: SocketAddr = format!("127.0.0.1:{socks_port}").parse().expect("addr");
    let got = timeout(EXCHANGE_TIMEOUT, socks5_connect_roundtrip(proxy_addr, echo, PAYLOAD))
        .await
        .expect("exchange timeout")
        .expect("socks5 roundtrip");
    assert_eq!(got, PAYLOAD, "payload must round-trip via CONNECT tunnel");

    let req = recorded.lock().expect("recorded lock").clone();
    let expected_line = format!("CONNECT 127.0.0.1:{} HTTP/1.1\r\n", echo.port());
    assert!(req.starts_with(&expected_line), "request line must CONNECT to echo; got {req:?}");
    let expected_auth = format!("Proxy-Authorization: Basic {}\r\n", B64.encode("a:b"));
    assert!(req.contains(&expected_auth), "missing Proxy-Authorization Basic header; got {req:?}");
}

/// G-10（Go TestHttpBasicAuth inbound 腿）：带 accounts 的 HTTP inbound——
/// 无凭据 → 407；错误凭据 → 407；正确凭据 → 200 + 隧道回环。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g10_http_inbound_rejects_missing_or_wrong_credentials_with_407() {
    let echo = spawn_tcp_echo().await;
    let http_port = pick_free_port().await;

    let mut built = BuiltConfig::default();
    built.inbounds.push(BuiltInbound {
        entry: BuiltEntry {
            kind: "http".into(),
            data: json!({"accounts": [{"user": "a", "pass": "b"}]}).to_string().into_bytes(),
        },
        tag: "http-in".into(),
        port: Some(http_port),
        listen: Some("127.0.0.1".into()),
        stream_settings_json: None,
        sniffing_json: None,
    });
    built.outbounds.push(freedom_allow_all("direct"));
    start_xray(&built).await;

    let http_addr: SocketAddr = format!("127.0.0.1:{http_port}").parse().expect("addr");

    let read_response = async |auth: Option<&str>| -> String {
        let mut c = TcpStream::connect(http_addr).await.expect("connect http inbound");
        let mut req = format!("CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1\r\n", echo.port());
        if let Some(a) = auth {
            req.push_str(&format!("Proxy-Authorization: Basic {a}\r\n"));
        }
        req.push_str("\r\n");
        c.write_all(req.as_bytes()).await.expect("write request");
        let mut buf = vec![0u8; 1024];
        let n = timeout(EXCHANGE_TIMEOUT, c.read(&mut buf))
            .await
            .expect("response timeout")
            .expect("read response");
        String::from_utf8_lossy(&buf[..n]).to_string()
    };

    // 无凭据 → 407
    let resp = read_response(None).await;
    assert!(resp.contains("407"), "no-auth must 407; got {resp:?}");

    // 错误凭据 → 407
    let resp = read_response(Some(&B64.encode("a:wrong"))).await;
    assert!(resp.contains("407"), "wrong password must 407; got {resp:?}");

    // 正确凭据 → 200 + 隧道
    let mut c = TcpStream::connect(http_addr).await.expect("connect http inbound");
    let req = format!(
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1\r\nProxy-Authorization: Basic {}\r\n\r\n",
        echo.port(),
        B64.encode("a:b")
    );
    c.write_all(req.as_bytes()).await.expect("write request");
    let mut buf = vec![0u8; 1024];
    let n = timeout(EXCHANGE_TIMEOUT, c.read(&mut buf))
        .await
        .expect("response timeout")
        .expect("read response");
    let resp = String::from_utf8_lossy(&buf[..n]).to_string();
    assert!(resp.contains("200"), "valid credentials must pass; got {resp:?}");
    c.write_all(PAYLOAD).await.expect("write payload");
    let mut got = vec![0u8; PAYLOAD.len()];
    c.read_exact(&mut got).await.expect("read echo");
    assert_eq!(&got, &PAYLOAD, "payload must round-trip after auth");
}

// ============================================================
// G-14 TCP+HTTP 伪装头（入站侧）
// ============================================================

/// G-14（Go TestHTTPConnectionHeader）：vmess inbound + tcpSettings.header.type=http，
/// 客户端经 `HeaderConn::client` 真实伪装包装（先发伪装 GET，读侧消费伪装响应），
/// vmess 会话全链回环。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g14_vmess_inbound_accepts_http_header_camouflaged_stream() {
    let echo = spawn_tcp_echo().await;
    let vmess_port = pick_free_port().await;
    let uuid = UUID::parse(VMESS_UUID_STR).expect("uuid");

    let mut built = BuiltConfig::default();
    built.inbounds.push(BuiltInbound {
        entry: BuiltEntry {
            kind: "vmess".into(),
            data: json!({"clients": [{"id": VMESS_UUID_STR, "email": "g14@local", "level": 0}]})
                .to_string()
                .into_bytes(),
        },
        tag: "vmess-in".into(),
        port: Some(vmess_port),
        listen: Some("127.0.0.1".into()),
        stream_settings_json: Some(json!({
            "network": "tcp",
            "tcpSettings": {"header": {"type": "http"}}
        })),
        sniffing_json: None,
    });
    built.outbounds.push(freedom_allow_all("direct"));
    start_xray(&built).await;

    // 客户端：裸 TCP → Connection → HTTP 伪装包装（客户端首写注入伪装 GET）→ vmess 会话
    let tcp =
        TcpStream::connect(format!("127.0.0.1:{vmess_port}")).await.expect("connect vmess inbound");
    let auth = auth_from_json(Some(&json!({"header": {"type": "http"}})))
        .expect("auth json")
        .expect("http header auth");
    let conn: Box<dyn Connection> = Box::new(TcpConnection::new(tcp));
    let mut wrapped = wrap_client(conn, &auth);

    let session = VmessClientSession::new();
    let dest =
        Destination::tcp(Address::ipv4(std::net::Ipv4Addr::LOCALHOST), Port::new(echo.port()));
    let header = RequestHeader::new(VMESS_VERSION, Command::Tcp, dest, SecurityType::Aes128Gcm);
    let cmd_key = cmd_key_of(&uuid);
    let sealed = session.encode_request_header(&header, &cmd_key).expect("encode vmess header");
    wrapped.write_all(&sealed).await.expect("write camouflaged request");

    timeout(EXCHANGE_TIMEOUT, session.decode_response_header_async(&mut wrapped))
        .await
        .expect("vmess response header timeout")
        .expect("decode vmess response header");
    session
        .encode_request_body_async(&header, PAYLOAD, &mut wrapped)
        .await
        .expect("encode vmess body");
    let response =
        timeout(EXCHANGE_TIMEOUT, session.decode_response_body_async(&header, &mut wrapped))
            .await
            .expect("vmess body timeout")
            .expect("decode vmess body");
    assert_eq!(response, PAYLOAD, "payload must round-trip through camouflaged inbound");
}

// ============================================================
// G-16 freedom DestinationOverride
// ============================================================

/// G-16（Go TestForward）：freedom destinationOverride 强制改投指定服务器——
/// 客户端 CONNECT TEST-NET-3（203.0.113.1:1，不可路由），改写生效则载荷经
/// echo 完整回环；改写失效则拨号 203.0.113.1 超时失败。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g16_freedom_destination_override_rewrites_socks_target() {
    let echo = spawn_tcp_echo().await;
    let socks_port = pick_free_port().await;

    let mut built = BuiltConfig::default();
    built.inbounds.push(socks_inbound("socks-in", socks_port, br#"{"auth":"noauth"}"#));
    built.outbounds.push(BuiltOutbound {
        entry: BuiltEntry {
            kind: "freedom".into(),
            data: json!({
                "destinationOverride": {"server": {"address": "127.0.0.1", "port": echo.port()}},
                "finalRules": [{"action": "allow"}]
            })
            .to_string()
            .into_bytes(),
        },
        tag: "direct".into(),
        send_through: None,
        stream_settings_json: None,
        proxy_settings_json: None,
        mux_json: None,
        target_strategy: None,
    });
    start_xray(&built).await;

    let unroutable: SocketAddr = "203.0.113.1:1".parse().expect("test-net-3 addr");
    let proxy_addr: SocketAddr = format!("127.0.0.1:{socks_port}").parse().expect("addr");
    let got = timeout(EXCHANGE_TIMEOUT, socks5_connect_roundtrip(proxy_addr, unroutable, PAYLOAD))
        .await
        .expect("exchange timeout (override failed to rewrite target?)")
        .expect("socks5 roundtrip");
    assert_eq!(got, PAYLOAD, "payload must round-trip to overridden echo target");
}

// ============================================================
// G-15 代理链 dialer proxy
// ============================================================

/// G-15（Go TestDialerProxy）：实例 B 的 trojan outbound 底层拨号经
/// `sockopt.dialerProxy = socks-out` → SOCKS5 recorder → 实例 A 的 trojan inbound
/// → freedom → echo。判别器：recorder 记录到的 CONNECT 目标必须是 trojan 服务器
/// （dial 走了链），且载荷全链回环。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g15_dialer_proxy_chains_trojan_outbound_dial_via_socks_outbound() {
    let echo = spawn_tcp_echo().await;
    let (recorder_port, recorded) = spawn_socks5_tcp_recorder().await;

    // 实例 A：trojan 服务器（trojan inbound + freedom → echo）
    let trojan_port = pick_free_port().await;
    let mut server = BuiltConfig::default();
    server.inbounds.push(BuiltInbound {
        entry: BuiltEntry {
            kind: "trojan".into(),
            data: json!({"clients": [{"password": "chain-pass-1", "email": "g15@server"}]})
                .to_string()
                .into_bytes(),
        },
        tag: "trojan-in".into(),
        port: Some(trojan_port),
        listen: Some("127.0.0.1".into()),
        stream_settings_json: None,
        sniffing_json: None,
    });
    server.outbounds.push(freedom_allow_all("direct"));
    start_xray(&server).await;

    // 实例 B：socks inbound → trojan outbound（dialerProxy=socks-out）→ socks outbound
    let socks_port = pick_free_port().await;
    let mut client = BuiltConfig::default();
    client.inbounds.push(socks_inbound("socks-in", socks_port, br#"{"auth":"noauth"}"#));
    client.outbounds.push(BuiltOutbound {
        entry: BuiltEntry {
            kind: "trojan".into(),
            data: json!({
                "servers": [{
                    "address": "127.0.0.1",
                    "port": trojan_port,
                    "password": "chain-pass-1"
                }]
            })
            .to_string()
            .into_bytes(),
        },
        tag: "chain-out".into(),
        send_through: None,
        stream_settings_json: Some(json!({"sockopt": {"dialerProxy": "socks-out"}})),
        proxy_settings_json: None,
        mux_json: None,
        target_strategy: None,
    });
    client.outbounds.push(BuiltOutbound {
        entry: BuiltEntry {
            kind: "socks".into(),
            data: json!({"servers": [{"address": "127.0.0.1", "port": recorder_port}]})
                .to_string()
                .into_bytes(),
        },
        tag: "socks-out".into(),
        send_through: None,
        stream_settings_json: None,
        proxy_settings_json: None,
        mux_json: None,
        target_strategy: None,
    });
    start_xray(&client).await;

    let proxy_addr: SocketAddr = format!("127.0.0.1:{socks_port}").parse().expect("addr");
    let got = timeout(EXCHANGE_TIMEOUT, socks5_connect_roundtrip(proxy_addr, echo, PAYLOAD))
        .await
        .expect("exchange timeout")
        .expect("socks5 roundtrip");
    assert_eq!(got, PAYLOAD, "payload must round-trip through the dialer-proxy chain");

    let recs = recorded.lock().expect("recorder lock").clone();
    assert!(
        recs.iter().any(|(cmd, addr)| *cmd == 0x01
            && addr.port() == trojan_port
            && addr.ip().is_loopback()),
        "recorder must see CONNECT to trojan server (:{trojan_port}); got {recs:?}"
    );
}

// ============================================================
// G-04 SOCKS5 UDP ASSOCIATE 全链
// ============================================================

/// G-04（Go TestSocksBridageUDP 提升到集成层）：SOCKS5 客户端 → 实例 socks inbound
/// （UDP ASSOCIATE relay）→ dispatcher → socks outbound（ASSOCIATE 到外部 SOCKS5
/// UDP 服务器）→ UDP 回显。判别器：外部服务器记录 CMD 必须 3（ASSOCIATE），
/// 载荷经全链回环——任何一侧 TCP 降级都会使断言失败。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g04_socks_udp_associate_full_chain_inbound_to_outbound() {
    let (fake_socks_port, served_cmds) = spawn_socks5_udp_echo().await;
    let socks_port = pick_free_port().await;

    let mut built = BuiltConfig::default();
    built.inbounds.push(socks_inbound("socks-in", socks_port, br#"{"auth":"noauth","udp":true}"#));
    built.outbounds.push(BuiltOutbound {
        entry: BuiltEntry {
            kind: "socks".into(),
            data: json!({"servers": [{"address": "127.0.0.1", "port": fake_socks_port}]})
                .to_string()
                .into_bytes(),
        },
        tag: "socks-out".into(),
        send_through: None,
        stream_settings_json: None,
        proxy_settings_json: None,
        mux_json: None,
        target_strategy: None,
    });
    start_xray(&built).await;

    // 1. TCP 控制连接 + no-auth 握手
    let mut ctrl =
        TcpStream::connect(format!("127.0.0.1:{socks_port}")).await.expect("connect socks control");
    ctrl.write_all(&[0x05, 0x01, 0x00]).await.expect("greeting");
    let mut method = [0u8; 2];
    ctrl.read_exact(&mut method).await.expect("method reply");
    assert_eq!(method, [0x05, 0x00], "no-auth must be selected");

    // 2. UDP ASSOCIATE（DST = 0.0.0.0:0）
    ctrl.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await.expect("associate");
    let mut assoc = [0u8; 10];
    ctrl.read_exact(&mut assoc).await.expect("associate reply");
    assert_eq!(assoc[1], 0x00, "ASSOCIATE must succeed, reply {assoc:?}");
    assert_eq!(assoc[3], 0x01, "BND.ADDR must be IPv4");
    let relay_port = u16::from_be_bytes([assoc[8], assoc[9]]);
    assert!(relay_port > 0, "relay port must be assigned");

    // 3. UDP 帧经全链（inbound relay → outbound ASSOCIATE → 外部 UDP 回显）
    let udp = UdpSocket::bind("127.0.0.1:0").await.expect("client udp bind");
    let frame = socks_udp_frame([10, 9, 8, 7], 5353, UDP_PAYLOAD);
    udp.send_to(&frame, ("127.0.0.1", relay_port)).await.expect("send to relay");

    let mut buf = vec![0u8; 65535];
    let (n, _src) = timeout(EXCHANGE_TIMEOUT, udp.recv_from(&mut buf))
        .await
        .expect("udp echo timeout (downgrade or associate failure)")
        .expect("recv echo");
    let (_dst_ip, dst_port, payload) =
        parse_socks_udp_frame(&buf[..n]).expect("reply must be a SOCKS5 UDP frame");
    assert_eq!(payload, UDP_PAYLOAD, "payload must round-trip via UDP relay");
    assert_eq!(
        (_dst_ip, dst_port),
        ([10, 9, 8, 7], 5353),
        "frame DST must echo the request target"
    );

    // 4. 判别器：外部服务器只见 UDP ASSOCIATE（3），不得 TCP CONNECT 降级（1）
    assert_eq!(
        *served_cmds.lock().expect("cmd lock"),
        vec![0x03],
        "external socks server must see CMD=3 (UDP ASSOCIATE), not TCP downgrade"
    );

    // 控制连接断开 → relay 终结（SOCKS UDP 语义）
    drop(udp);
    drop(ctrl);
}
