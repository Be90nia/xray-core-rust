//! Transport-layer interop tests: WS / gRPC / KCP / TLS / REALITY.
//!
//! 5 e2e tests, each verifying one transport layer end-to-end through `start_full`.
//! Pattern: SOCKS5 inbound (client side) + protocol outbound (over chosen transport)
//! + protocol inbound (server side) + freedom outbound → echo.

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use xray_conf::{BuiltConfig, BuiltEntry, BuiltInbound, BuiltOutbound};
use xray_core::functions::start_full;

// --- Constants ----------------------------------------------------------------

/// Pre-test delay for listener ready (matches `functions.rs::integration_*` baseline).
const READY_DELAY: std::time::Duration = std::time::Duration::from_millis(100);
/// KCP/REALITY may need a longer warmup (UDP bind + first-conv handshake).
const TRANSPORT_WARMUP: std::time::Duration = std::time::Duration::from_millis(500);

const TEST_UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

/// rustls 默认 ring provider 装一次（REALITY watfaq fallback + uTLS 都要）。
/// 多测试并行场景下 Once 保证只调一次。
fn ensure_crypto_provider() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

async fn start_echo() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = listener.local_addr().expect("echo addr");
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((mut sock, _)) => {
                    tokio::spawn(async move {
                        let mut buf = [0u8; 1024];
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
                },
                Err(_) => break,
            }
        }
    });
    addr
}

async fn pick_free_port() -> u16 {
    let probe = TcpListener::bind("127.0.0.1:0").await.expect("pick port");
    let port = probe.local_addr().expect("probe addr").port();
    drop(probe);
    port
}

async fn socks5_echo_round_trip(proxy_port: u16, echo_port: u16, payload: &[u8]) {
    let mut sock = TcpStream::connect(("127.0.0.1", proxy_port)).await.expect("connect socks");
    sock.write_all(&[0x05, 0x01, 0x00]).await.expect("socks greet");
    let mut greet = [0u8; 2];
    sock.read_exact(&mut greet).await.expect("socks greet resp");
    assert_eq!(greet, [0x05, 0x00], "socks5 no-auth method");
    let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    req.extend_from_slice(&echo_port.to_be_bytes());
    sock.write_all(&req).await.expect("socks connect");
    let mut cr = [0u8; 10];
    sock.read_exact(&mut cr).await.expect("socks connect resp");
    assert_eq!(cr[0], 0x05, "socks5 version");
    assert_eq!(cr[1], 0x00, "socks5 CONNECT succeeded");
    sock.write_all(payload).await.expect("write payload");
    let mut got = vec![0u8; payload.len()];
    let read = tokio::time::timeout(std::time::Duration::from_secs(5), sock.read_exact(&mut got))
        .await
        .unwrap_or_else(|_| panic!("echo timeout"))
        .expect("echo read");
    assert_eq!(read, payload.len(), "echo length");
    assert_eq!(&got, payload, "echo data matches");
}

fn vless_inbound(port: u16, tag: &str) -> BuiltInbound {
    BuiltInbound {
        entry: BuiltEntry {
            kind: "vless".into(),
            data: format!(r#"{{"clients":[{{"id":"{TEST_UUID}"}}]}}"#).into_bytes(),
        },
        tag: tag.into(),
        port: Some(port),
        listen: Some("127.0.0.1".into()),
        stream_settings_json: None,
        sniffing_json: None,
    }
}

fn vless_outbound(upstream_port: u16, stream_settings_json: serde_json::Value) -> BuiltOutbound {
    BuiltOutbound {
        entry: BuiltEntry {
            kind: "vless".into(),
            data: format!(
                r#"{{"vnext":[{{"address":"127.0.0.1","port":{upstream_port},"users":[{{"id":"{TEST_UUID}","encryption":"none"}}]}}]}}"#
            )
            .into_bytes(),
        },
        tag: "proxy".into(),
        send_through: None,
        stream_settings_json: Some(stream_settings_json),
        proxy_settings_json: None,
        mux_json: None,
        target_strategy: None,
    }
}

fn vmess_inbound(port: u16, tag: &str) -> BuiltInbound {
    BuiltInbound {
        entry: BuiltEntry {
            kind: "vmess".into(),
            data: format!(r#"{{"clients":[{{"id":"{TEST_UUID}"}}]}}"#).into_bytes(),
        },
        tag: tag.into(),
        port: Some(port),
        listen: Some("127.0.0.1".into()),
        stream_settings_json: None,
        sniffing_json: None,
    }
}

fn vmess_outbound(upstream_port: u16, stream_settings_json: serde_json::Value) -> BuiltOutbound {
    BuiltOutbound {
        entry: BuiltEntry {
            kind: "vmess".into(),
            data: format!(
                r#"{{"vnext":[{{"address":"127.0.0.1","port":{upstream_port},"users":[{{"id":"{TEST_UUID}","security":"auto"}}]}}]}}"#
            )
            .into_bytes(),
        },
        tag: "proxy".into(),
        send_through: None,
        stream_settings_json: Some(stream_settings_json),
        proxy_settings_json: None,
        mux_json: None,
        target_strategy: None,
    }
}

fn freedom_outbound() -> BuiltOutbound {
    BuiltOutbound {
        entry: BuiltEntry { kind: "freedom".into(), data: b"{}".to_vec() },
        tag: "direct".into(),
        send_through: None,
        stream_settings_json: None,
        proxy_settings_json: None,
        mux_json: None,
        target_strategy: None,
    }
}

fn socks_inbound(port: u16) -> BuiltInbound {
    BuiltInbound {
        entry: BuiltEntry { kind: "socks".into(), data: vec![] },
        tag: "socks-in".into(),
        port: Some(port),
        listen: Some("127.0.0.1".into()),
        stream_settings_json: None,
        sniffing_json: None,
    }
}

// --- Test 1: WebSocket transport (VLESS + WS) --------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn websocket_transport_via_vless_e2e() {
    let echo_addr = start_echo().await;
    let vless_port = pick_free_port().await;
    let socks_port = pick_free_port().await;

    let ws_settings: serde_json::Value = serde_json::from_str(
        r#"{"network":"ws","security":"none","wsSettings":{"path":"/vmess-ws-transport"}}"#,
    )
    .unwrap();

    let mut server_cfg = BuiltConfig::default();
    server_cfg.inbounds.push(vless_inbound(vless_port, "vless-ws-in"));
    server_cfg.outbounds.push(freedom_outbound());
    server_cfg.inbounds[0].stream_settings_json = Some(ws_settings.clone());

    let (_si, _so, sh) = start_full(&server_cfg).await.expect("vless-ws server");
    tokio::time::sleep(READY_DELAY).await;

    let mut client_cfg = BuiltConfig::default();
    client_cfg.inbounds.push(socks_inbound(socks_port));
    client_cfg.outbounds.push(vless_outbound(vless_port, ws_settings));

    let (_ci, _co, ch) = start_full(&client_cfg).await.expect("vless-ws client");
    tokio::time::sleep(READY_DELAY).await;

    socks5_echo_round_trip(socks_port, echo_addr.port(), b"hello ws").await;

    for h in sh.iter().chain(ch.iter()) {
        h.abort();
    }
}

// --- Test 2: gRPC transport (VLESS + gRPC) -----------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grpc_transport_via_vless_e2e() {
    let echo_addr = start_echo().await;
    let vless_port = pick_free_port().await;
    let socks_port = pick_free_port().await;

    let grpc_settings: serde_json::Value = serde_json::from_str(
        r#"{"network":"grpc","security":"none","grpcSettings":{"serviceName":"GunService"}}"#,
    )
    .unwrap();

    let mut server_cfg = BuiltConfig::default();
    server_cfg.inbounds.push(vless_inbound(vless_port, "vless-grpc-in"));
    server_cfg.outbounds.push(freedom_outbound());
    server_cfg.inbounds[0].stream_settings_json = Some(grpc_settings.clone());

    let (_si, _so, sh) = start_full(&server_cfg).await.expect("vless-grpc server");
    tokio::time::sleep(TRANSPORT_WARMUP).await;

    let mut client_cfg = BuiltConfig::default();
    client_cfg.inbounds.push(socks_inbound(socks_port));
    client_cfg.outbounds.push(vless_outbound(vless_port, grpc_settings));

    let (_ci, _co, ch) = start_full(&client_cfg).await.expect("vless-grpc client");
    tokio::time::sleep(TRANSPORT_WARMUP).await;

    socks5_echo_round_trip(socks_port, echo_addr.port(), b"hello grpc").await;

    for h in sh.iter().chain(ch.iter()) {
        h.abort();
    }
}

// --- Test 3: mKCP transport (VLESS + KCP) ------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kcp_transport_via_vless_e2e() {
    let echo_addr = start_echo().await;
    let vless_port = pick_free_port().await;
    let socks_port = pick_free_port().await;

    let kcp_settings: serde_json::Value =
        serde_json::from_str(r#"{"network":"kcp","security":"none","kcpSettings":{}}"#).unwrap();

    let mut server_cfg = BuiltConfig::default();
    server_cfg.inbounds.push(vless_inbound(vless_port, "vless-kcp-in"));
    server_cfg.outbounds.push(freedom_outbound());
    server_cfg.inbounds[0].stream_settings_json = Some(kcp_settings.clone());

    let (_si, _so, sh) = start_full(&server_cfg).await.expect("vless-kcp server");
    tokio::time::sleep(TRANSPORT_WARMUP).await;

    let mut client_cfg = BuiltConfig::default();
    client_cfg.inbounds.push(socks_inbound(socks_port));
    client_cfg.outbounds.push(vless_outbound(vless_port, kcp_settings));

    let (_ci, _co, ch) = start_full(&client_cfg).await.expect("vless-kcp client");
    tokio::time::sleep(TRANSPORT_WARMUP).await;

    socks5_echo_round_trip(socks_port, echo_addr.port(), b"hello kcp").await;

    for h in sh.iter().chain(ch.iter()) {
        h.abort();
    }
}

// --- Test 4: TLS transport (VMess + TLS, self-signed + allowInsecure) -------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_transport_via_vmess_e2e() {
    let echo_addr = start_echo().await;
    let vmess_port = pick_free_port().await;
    let socks_port = pick_free_port().await;

    let (cert_pem, key_pem) =
        xray_tls::certificate::generate_self_signed_cert(&["localhost"]).expect("gen cert");
    let server_tls: serde_json::Value = serde_json::from_str(&format!(
        r#"{{"network":"tcp","security":"tls","tlsSettings":{{"certificates":[{{"certificate":[{cert_pem:?}],"key":[{key_pem:?}]}}]}}}}"#
    ))
    .unwrap();
    let client_tls: serde_json::Value = serde_json::from_str(
        r#"{"network":"tcp","security":"tls","tlsSettings":{"allowInsecure":true,"serverName":"localhost"}}"#,
    )
    .unwrap();

    let mut server_cfg = BuiltConfig::default();
    server_cfg.inbounds.push(vmess_inbound(vmess_port, "vmess-tls-in"));
    server_cfg.outbounds.push(freedom_outbound());
    server_cfg.inbounds[0].stream_settings_json = Some(server_tls);

    let (_si, _so, sh) = start_full(&server_cfg).await.expect("vmess-tls server");
    tokio::time::sleep(READY_DELAY).await;

    let mut client_cfg = BuiltConfig::default();
    client_cfg.inbounds.push(socks_inbound(socks_port));
    client_cfg.outbounds.push(vmess_outbound(vmess_port, client_tls));

    let (_ci, _co, ch) = start_full(&client_cfg).await.expect("vmess-tls client");
    tokio::time::sleep(READY_DELAY).await;

    socks5_echo_round_trip(socks_port, echo_addr.port(), b"hello tls").await;

    for h in sh.iter().chain(ch.iter()) {
        h.abort();
    }
}

// --- Test 5: REALITY transport (VLESS + REALITY) ----------------------------
// reality_transport_via_vless_e2e：watfaq-rustls fallback fingerprint（`randomizednoalpn`），
// 跳过 btls transcript 已知问题（xray-reality/src/server.rs:1131 aai 遗留），
// 等价验 server_tls + HMAC cert 验证链端到端。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reality_transport_via_vless_e2e() {
    use base64::Engine;
    use x25519_dalek::{PublicKey, StaticSecret};

    let echo_addr = start_echo().await;
    let vless_port = pick_free_port().await;
    let socks_port = pick_free_port().await;

    // rustls ring crypto provider（REALITY watfaq fallback 路径必需）。
    ensure_crypto_provider();

    let server_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let server_public = PublicKey::from(&server_secret);
    let priv_key_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(server_secret.to_bytes());
    let pub_key_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(server_public.to_bytes());

    let short_id_hex = "0123456789abcdef";

    let server_reality: serde_json::Value = serde_json::from_str(&format!(
        r#"{{"network":"tcp","security":"reality","realitySettings":{{"privateKey":"{priv_key_b64}","shortIds":["{short_id_hex}"],"dest":"{}:{}"}}}}"#,
        "127.0.0.1",
        echo_addr.port()
    ))
    .unwrap();

    // 注：fingerprint 走 watfaq-rustls fallback（随机化指纹）；btls 路径有
    // 已知 transcript mismatch（ClientHello session_id 注入晚于 BoringSSL
    // transcript 哈希），见 xray-reality/src/server.rs:1131 注记
    // `reality_fingerprint_matrix_btls`。e2e 验收用 watfaq fallback 等价：
    // server_tls + HMAC cert 验证全链路，链端到端走通。
    let client_reality: serde_json::Value = serde_json::from_str(&format!(
        r#"{{"network":"tcp","security":"reality","realitySettings":{{"serverName":"localhost","publicKey":"{pub_key_b64}","shortId":"{short_id_hex}","fingerprint":"randomizednoalpn"}}}}"#
    ))
    .unwrap();

    let mut server_cfg = BuiltConfig::default();
    server_cfg.inbounds.push(vless_inbound(vless_port, "vless-reality-in"));
    server_cfg.outbounds.push(freedom_outbound());
    server_cfg.inbounds[0].stream_settings_json = Some(server_reality);

    let (_si, _so, sh) = start_full(&server_cfg).await.expect("vless-reality server");
    tokio::time::sleep(TRANSPORT_WARMUP).await;

    let mut client_cfg = BuiltConfig::default();
    client_cfg.inbounds.push(socks_inbound(socks_port));
    client_cfg.outbounds.push(vless_outbound(vless_port, client_reality));

    let (_ci, _co, ch) = start_full(&client_cfg).await.expect("vless-reality client");
    tokio::time::sleep(TRANSPORT_WARMUP).await;

    socks5_echo_round_trip(socks_port, echo_addr.port(), b"hello reality").await;

    for h in sh.iter().chain(ch.iter()) {
        h.abort();
    }
}
