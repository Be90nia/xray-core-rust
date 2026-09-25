//! gRPC multi-mode end-to-end tests (jghj: 8yn).
//!
//! 4 variants verified through full xray-core `start_full` path:
//!   1. gRPC + single mode (no TLS) — basic GunService/Tun
//!   2. gRPC + TLS (self-signed + allowInsecure)
//!   3. gRPC + multiMode (TunMulti path)
//!   4. gRPC + custom path ("/A/B/Tun" serviceName)
//!
//! Pattern: SOCKS5 inbound + VLESS outbound (over chosen gRPC settings) →
//! VLESS inbound (server side) + freedom outbound → echo.
//!
//! All tests `#[ignore]` — run with `cargo test --test integration_grpc_multimode -- --ignored`.

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use xray_conf::{BuiltConfig, BuiltEntry, BuiltInbound, BuiltOutbound};
use xray_core::functions::start_full;

const TRANSPORT_WARMUP: std::time::Duration = std::time::Duration::from_millis(500);
const TEST_UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

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

async fn run_grpc_e2e(grpc_settings: serde_json::Value, payload: &[u8]) {
    let echo_addr = start_echo().await;
    let vless_port = pick_free_port().await;
    let socks_port = pick_free_port().await;

    let mut server_cfg = BuiltConfig::default();
    server_cfg.inbounds.push(vless_inbound(vless_port, "vless-grpc-mm-in"));
    server_cfg.outbounds.push(freedom_outbound());
    server_cfg.inbounds[0].stream_settings_json = Some(grpc_settings.clone());

    let (_si, _so, sh) = start_full(&server_cfg).await.expect("vless-grpc server");
    tokio::time::sleep(TRANSPORT_WARMUP).await;

    let mut client_cfg = BuiltConfig::default();
    client_cfg.inbounds.push(socks_inbound(socks_port));
    client_cfg.outbounds.push(vless_outbound(vless_port, grpc_settings));

    let (_ci, _co, ch) = start_full(&client_cfg).await.expect("vless-grpc client");
    tokio::time::sleep(TRANSPORT_WARMUP).await;

    socks5_echo_round_trip(socks_port, echo_addr.port(), payload).await;

    for h in sh.iter().chain(ch.iter()) {
        h.abort();
    }
}

// --- 变体 1: gRPC single mode (no TLS) — 路径 /<service>/Tun ---
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grpc_single_mode_via_vless_e2e() {
    let grpc_settings: serde_json::Value = serde_json::from_str(
        r#"{"network":"grpc","security":"none","grpcSettings":{"serviceName":"GunService"}}"#,
    )
    .unwrap();
    run_grpc_e2e(grpc_settings, b"hello grpc single").await;
}

// --- 变体 2: gRPC + TLS (allowInsecure, self-signed server) ---
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grpc_tls_via_vless_e2e() {
    let grpc_settings: serde_json::Value = serde_json::from_str(
        r#"{
            "network":"grpc",
            "security":"tls",
            "tlsSettings":{"serverName":"localhost","allowInsecure":true,"alpn":["h2"]},
            "grpcSettings":{"serviceName":"GunService"}
        }"#,
    )
    .unwrap();
    run_grpc_e2e(grpc_settings, b"hello grpc tls").await;
}

// --- 变体 3: gRPC multiMode=true — 路径 /<service>/TunMulti ---
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grpc_multi_mode_via_vless_e2e() {
    let grpc_settings: serde_json::Value = serde_json::from_str(
        r#"{"network":"grpc","security":"none","grpcSettings":{"serviceName":"GunService","multiMode":true}}"#,
    )
    .unwrap();
    run_grpc_e2e(grpc_settings, b"hello grpc multimode").await;
}

// --- 变体 4: gRPC custom path — serviceName="/A/B/Tun" 路径 /A/B/Tun ---
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grpc_custom_path_via_vless_e2e() {
    let grpc_settings: serde_json::Value = serde_json::from_str(
        r#"{"network":"grpc","security":"none","grpcSettings":{"serviceName":"/A/B/Tun"}}"#,
    )
    .unwrap();
    run_grpc_e2e(grpc_settings, b"hello grpc custom").await;
}
