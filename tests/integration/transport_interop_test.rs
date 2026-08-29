//! Transport-layer interop tests: WS / gRPC / KCP / TLS / REALITY.
//!
//! 5 e2e tests, each verifying one transport layer end-to-end through `start_full`.
//! Pattern: SOCKS5 inbound (client side) + protocol outbound (e.g. VMess/VLESS over
//! chosen transport) + protocol inbound (server side) + freedom outbound → echo.
//!
//! All tests require full xray-core runtime (libclang/nasm/btls). Marked `#[ignore]`
//! because tests/ folder is not the primary CI path; run with
//! `cargo test --test integration_transport_interop -- --ignored`.
//!
//! Pre-existing coverage (functions.rs `mod tests`):
//! - vless+websocket, vless+tls, trojan+tls, vmess+tls
//! Missing transport-layer e2e coverage at the test crate level:
//! - WS over VMess (new: protocol+transport combo not exercised)
//! - gRPC (new transport)
//! - KCP (new transport, UDP)
//! - TLS (new: ss_client or vmess+TLS with explicit pinning)
//! - REALITY (new: VLESS+REALITY with x25519 keypair)

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use xray_conf::{BuiltConfig, BuiltEntry, BuiltInbound, BuiltOutbound};
use xray_core::functions::start_full;

// --- Constants ----------------------------------------------------------------

const READY_DELAY: std::time::Duration = std::time::Duration::from_millis(100);
const TEST_UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

// --- Helpers ------------------------------------------------------------------

/// Start a loopback echo server (writes back whatever it reads until EOF/error).
async fn start_echo() -> (TcpListener, std::net::SocketAddr) {
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
                                }
                            }
                        }
                    });
                }
                Err(_) => break,
            }
        }
    });
    (listener, addr)
}

/// Bind a TCP listener and immediately drop it, returning the probe port.
/// Best-effort free-port allocation (port may be racy under contention).
async fn pick_free_port() -> u16 {
    let probe = TcpListener::bind("127.0.0.1:0").await.expect("pick port");
    let port = probe.local_addr().expect("probe addr").port();
    drop(probe);
    port
}

/// Drive SOCKS5 CONNECT through `proxy_port` to `echo_port` and verify payload
/// round-trips intact. Asserts on every step so failure root-causes the layer.
async fn socks5_echo_round_trip(proxy_port: u16, echo_port: u16, payload: &[u8]) {
    let mut sock = TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .expect("connect socks");

    // SOCKS5 greeting: no auth
    sock.write_all(&[0x05, 0x01, 0x00]).await.expect("socks greet");
    let mut greet = [0u8; 2];
    sock.read_exact(&mut greet).await.expect("socks greet resp");
    assert_eq!(greet, [0x05, 0x00], "socks5 no-auth method");

    // SOCKS5 CONNECT to 127.0.0.1:echo_port (ATYP=1, IPv4)
    let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    req.extend_from_slice(&echo_port.to_be_bytes());
    sock.write_all(&req).await.expect("socks connect");

    let mut cr = [0u8; 10];
    sock.read_exact(&mut cr).await.expect("socks connect resp");
    assert_eq!(cr[0], 0x05, "socks5 version");
    assert_eq!(cr[1], 0x00, "socks5 CONNECT succeeded (transport layer wired end-to-end)");

    sock.write_all(payload).await.expect("write payload");
    let mut got = vec![0u8; payload.len()];
    let read = tokio::time::timeout(std::time::Duration::from_secs(5), sock.read_exact(&mut got))
        .await
        .unwrap_or_else(|_| panic!("echo timeout: transport may be unwired for this pair"))
        .expect("echo read");
    assert_eq!(read, payload.len(), "echo length");
    assert_eq!(&got, payload, "echo data matches payload (proxy chain intact)");
}

/// Build a "VMess server inbound" BuiltEntry: 1 user, no stream security (clean).
fn vmess_inbound(port: u16, tag: &str) -> BuiltInbound {
    BuiltInbound {
        entry: BuiltEntry {
            kind: "vmess".into(),
            data: format!(r#"{{"clients":[{{"id":"{TEST_UUID}"}}]}}"#)
                .into_bytes(),
        },
        tag: tag.into(),
        port: Some(port),
        listen: Some("127.0.0.1".into()),
        stream_settings_json: None,
        sniffing_json: None,
    }
}

/// Build a "VMess client outbound" BuiltEntry pointing at `upstream_port`.
fn vmess_outbound(upstream_port: u16, stream_settings: Option<serde_json::Value>) -> BuiltOutbound {
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
        stream_settings_json: stream_settings,
        proxy_settings_json: None,
        mux_json: None,
        target_strategy: None,
    }
}

/// Freedom outbound (default route to echo server).
fn freedom_outbound() -> BuiltOutbound {
    BuiltOutbound {
        entry: BuiltEntry {
            kind: "freedom".into(),
            data: b"{}".to_vec(),
        },
        tag: "direct".into(),
        send_through: None,
        stream_settings_json: None,
        proxy_settings_json: None,
        mux_json: None,
        target_strategy: None,
    }
}

/// SOCKS5 inbound on `port` (client-side proxy entry).
fn socks_inbound(port: u16) -> BuiltInbound {
    BuiltInbound {
        entry: BuiltEntry {
            kind: "socks".into(),
            data: vec![],
        },
        tag: "socks-in".into(),
        port: Some(port),
        listen: Some("127.0.0.1".into()),
        stream_settings_json: None,
        sniffing_json: None,
    }
}

// --- Test 1: WebSocket transport (VMess + WS) --------------------------------
//
// SOCKS5 → VMess/WS /vless → Freedom → echo.
// Validates the WebSocket transport registration + dialer/listener pairing
// to a non-default path (different from the pre-existing VLESS+/vless test in
// functions.rs::integration_vless_over_websocket_to_echo).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires full xray-core runtime (libclang/nasm/btls)"]
async fn websocket_transport_via_vmess_e2e() {
    let (_echo_l, echo_addr) = start_echo().await;
    let vmess_port = pick_free_port().await;
    let socks_port = pick_free_port().await;

    let ws_settings: serde_json::Value = serde_json::from_str(
        r#"{"network":"ws","security":"none","wsSettings":{"path":"/vmess-ws-transport"}}"#,
    )
    .unwrap();

    let mut server_cfg = BuiltConfig::default();
    server_cfg.inbounds.push(vmess_inbound(vmess_port, "vmess-ws-in"));
    server_cfg.outbounds.push(freedom_outbound());

    let mut server = server_cfg.clone();
    server.inbounds[0].stream_settings_json = Some(ws_settings.clone());

    let (_si, _so, sh) = start_full(&server).await.expect("vmess-ws server");
    tokio::time::sleep(READY_DELAY).await;

    let mut client_cfg = BuiltConfig::default();
    client_cfg.inbounds.push(socks_inbound(socks_port));
    client_cfg.outbounds.push(vmess_outbound(vmess_port, Some(ws_settings)));

    let (_ci, _co, ch) = start_full(&client_cfg).await.expect("vmess-ws client");
    tokio::time::sleep(READY_DELAY).await;

    socks5_echo_round_trip(socks_port, echo_addr.port(), b"hello ws-transport").await;

    for h in sh.iter().chain(ch.iter()) {
        h.abort();
    }
}

// --- Test 2: gRPC transport (VMess + gRPC) -----------------------------------
//
// SOCKS5 → VMess/gRPC GunService → Freedom → echo.
// Validates the gRPC transport dialer/listener (h2 + gRPC wire framing) plus
// serviceName routing on both sides. Listener uses xray-transport-grpc (h2 raw).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires full xray-core runtime (libclang/nasm/btls)"]
async fn grpc_transport_via_vmess_e2e() {
    let (_echo_l, echo_addr) = start_echo().await;
    let vmess_port = pick_free_port().await;
    let socks_port = pick_free_port().await;

    let grpc_settings: serde_json::Value = serde_json::from_str(
        r#"{"network":"grpc","security":"none","grpcSettings":{"serviceName":"GunService"}}"#,
    )
    .unwrap();

    let mut server_cfg = BuiltConfig::default();
    server_cfg.inbounds.push(vmess_inbound(vmess_port, "vmess-grpc-in"));
    server_cfg.outbounds.push(freedom_outbound());

    let mut server = server_cfg.clone();
    server.inbounds[0].stream_settings_json = Some(grpc_settings.clone());

    let (_si, _so, sh) = start_full(&server).await.expect("vmess-grpc server");
    tokio::time::sleep(READY_DELAY).await;

    let mut client_cfg = BuiltConfig::default();
    client_cfg.inbounds.push(socks_inbound(socks_port));
    client_cfg.outbounds.push(vmess_outbound(vmess_port, Some(grpc_settings)));

    let (_ci, _co, ch) = start_full(&client_cfg).await.expect("vmess-grpc client");
    tokio::time::sleep(READY_DELAY).await;

    socks5_echo_round_trip(socks_port, echo_addr.port(), b"hello grpc-transport").await;

    for h in sh.iter().chain(ch.iter()) {
        h.abort();
    }
}

// --- Test 3: mKCP transport (VMess + KCP) ------------------------------------
//
// SOCKS5 → VMess/KCP (UDP) → Freedom → echo.
// Validates the KCP transport — UDP-based, requires its own listener/dialer
// registration. Default KCP settings (empty kcpSettings) exercised to keep
// the test focused on transport wiring rather than tuning.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires full xray-core runtime (libclang/nasm/btls)"]
async fn kcp_transport_via_vmess_e2e() {
    let (_echo_l, echo_addr) = start_echo().await;
    let vmess_port = pick_free_port().await;
    let socks_port = pick_free_port().await;

    let kcp_settings: serde_json::Value = serde_json::from_str(
        r#"{"network":"kcp","security":"none","kcpSettings":{}}"#,
    )
    .unwrap();

    let mut server_cfg = BuiltConfig::default();
    server_cfg.inbounds.push(vmess_inbound(vmess_port, "vmess-kcp-in"));
    server_cfg.outbounds.push(freedom_outbound());

    let mut server = server_cfg.clone();
    server.inbounds[0].stream_settings_json = Some(kcp_settings.clone());

    let (_si, _so, sh) = start_full(&server).await.expect("vmess-kcp server");
    // KCP needs slightly more time for UDP socket bind + first conv handshake.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let mut client_cfg = BuiltConfig::default();
    client_cfg.inbounds.push(socks_inbound(socks_port));
    client_cfg.outbounds.push(vmess_outbound(vmess_port, Some(kcp_settings)));

    let (_ci, _co, ch) = start_full(&client_cfg).await.expect("vmess-kcp client");
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    socks5_echo_round_trip(socks_port, echo_addr.port(), b"hello kcp-transport").await;

    for h in sh.iter().chain(ch.iter()) {
        h.abort();
    }
}

// --- Test 4: TLS transport (VMess + TLS with cert-pinning allowInsecure) -----
//
// SOCKS5 → VMess/TLS (allowInsecure, self-signed) → Freedom → echo.
// Validates the TLS transport is wired through both inbound (xray-tls
// server_config) and outbound (xray-tls client_config with allowInsecure).
// Differs from existing VMess+TLS in functions.rs by pairing with a *new*
// client config (vmess+ws-style streamSettings layout not previously exercised
// at integration level).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires full xray-core runtime (libclang/nasm/btls)"]
async fn tls_transport_via_vmess_e2e() {
    let (_echo_l, echo_addr) = start_echo().await;
    let vmess_port = pick_free_port().await;
    let socks_port = pick_free_port().await;

    let (cert_pem, key_pem) = xray_tls::certificate::generate_self_signed_cert(&["localhost"])
        .expect("generate self-signed cert");
    let server_tls: serde_json::Value = serde_json::from_str(&format!(
        r#"{{"network":"tcp","security":"tls","tlsSettings":{{"certificates":[{{"certificate":[{:?],"key":[{:?}]}}]}}}}"#,
        cert_pem, key_pem
    ))
    .unwrap();
    let client_tls: serde_json::Value = serde_json::from_str(
        r#"{"network":"tcp","security":"tls","tlsSettings":{"allowInsecure":true,"serverName":"localhost"}}"#,
    )
    .unwrap();

    let mut server_cfg = BuiltConfig::default();
    server_cfg.inbounds.push(vmess_inbound(vmess_port, "vmess-tls-in"));
    server_cfg.outbounds.push(freedom_outbound());

    let mut server = server_cfg.clone();
    server.inbounds[0].stream_settings_json = Some(server_tls);

    let (_si, _so, sh) = start_full(&server).await.expect("vmess-tls server");
    tokio::time::sleep(READY_DELAY).await;

    let mut client_cfg = BuiltConfig::default();
    client_cfg.inbounds.push(socks_inbound(socks_port));
    client_cfg.outbounds.push(vmess_outbound(vmess_port, Some(client_tls)));

    let (_ci, _co, ch) = start_full(&client_cfg).await.expect("vmess-tls client");
    tokio::time::sleep(READY_DELAY).await;

    socks5_echo_round_trip(socks_port, echo_addr.port(), b"hello tls-transport").await;

    for h in sh.iter().chain(ch.iter()) {
        h.abort();
    }
}

// --- Test 5: REALITY transport (VLESS + REALITY with x25519 keypair) --------
//
// VLESS + REALITY inbound (privateKey=server_secret) + Freedom outbound +
// SOCKS5 → VLESS+REALITY outbound (publicKey=server_pub) → Freedom → echo.
// Validates REALITY end-to-end: TLS handshake with auth_key derivation +
// session_id injection + server-side validation + downstream VLESS protocol.
// Uses an ephemeral x25519 keypair so no external Go xray binary needed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires full xray-core runtime (libclang/nasm/btls)"]
async fn reality_transport_via_vless_e2e() {
    use base64::Engine;
    use x25519_dalek::{PublicKey, StaticSecret};

    let (_echo_l, echo_addr) = start_echo().await;
    let vless_port = pick_free_port().await;
    let socks_port = pick_free_port().await;

    // Ephemeral server keypair
    let server_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let server_public = PublicKey::from(&server_secret);
    let server_priv_bytes = server_secret.to_bytes();
    let server_pub_bytes = server_public.to_bytes();

    let priv_key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(server_priv_bytes);
    let pub_key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(server_pub_bytes);

    // shortId in hex; Rust parses as 8-byte padded hex
    let short_id_hex = "0123456789abcdef";

    let server_reality: serde_json::Value = serde_json::json!({
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
            "privateKey": priv_key_b64,
            "shortIds": [short_id_hex],
            "dest": format!("{}:{}", "127.0.0.1", echo_addr.port())
        }
    });

    let client_reality: serde_json::Value = serde_json::json!({
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
            "serverName": "localhost",
            "publicKey": pub_key_b64,
            "shortId": short_id_hex,
            "fingerprint": "chrome"
        }
    });

    // Server side: VLESS+REALITY inbound + Freedom outbound
    let mut server_cfg = BuiltConfig::default();
    server_cfg.inbounds.push(BuiltInbound {
        entry: BuiltEntry {
            kind: "vless".into(),
            data: format!(r#"{{"clients":[{{"id":"{TEST_UUID}"}]}}"#).into_bytes(),
        },
        tag: "vless-reality-in".into(),
        port: Some(vless_port),
        listen: Some("127.0.0.1".into()),
        stream_settings_json: Some(server_reality),
        sniffing_json: None,
    });
    server_cfg.outbounds.push(freedom_outbound());
    let (_si, _so, sh) = start_full(&server_cfg).await.expect("vless-reality server");
    tokio::time::sleep(READY_DELAY).await;

    // Client side: SOCKS5 + VLESS+REALITY outbound
    let mut client_cfg = BuiltConfig::default();
    client_cfg.inbounds.push(socks_inbound(socks_port));
    client_cfg.outbounds.push(BuiltOutbound {
        entry: BuiltEntry {
            kind: "vless".into(),
            data: format!(
                r#"{{"vnext":[{{"address":"127.0.0.1","port":{vless_port},"users":[{{"id":"{TEST_UUID}","encryption":"none","flow":""}}]}}]}}"#
            )
            .into_bytes(),
        },
        tag: "proxy".into(),
        send_through: None,
        stream_settings_json: Some(client_reality),
        proxy_settings_json: None,
        mux_json: None,
        target_strategy: None,
    });
    let (_ci, _co, ch) = start_full(&client_cfg).await.expect("vless-reality client");
    tokio::time::sleep(READY_DELAY).await;

    socks5_echo_round_trip(
        socks_port,
        echo_addr.port(),
        b"hello reality-transport",
    )
    .await;

    for h in sh.iter().chain(ch.iter()) {
        h.abort();
    }
}
