//! VLESS Go<->Rust interop tests.
//!
// Test scenarios:
// 1. Go VLESS server -> Rust VLESS client (wire-level protocol compat)
// 2. Rust VLESS server -> Go VLESS client (via Go xray SOCKS5 inbound)
//
// All tests are #[ignore] by default: run with `cargo test -- --ignored`.
// Requires Go xray-core binary at XRAY_GO_BIN or default path.

mod interop_helpers;

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use interop_helpers::*;
use xray_app_dispatcher::default::{DialBridge, SimpleOhm};
use xray_app_dispatcher::DispatchHandler;
use xray_common::net::address::Address;
use xray_common::protocol::ID;
use xray_common::uuid::UUID;
use xray_proxy_freedom::make_freedom_dial_fn;
use xray_proxy_vless::account::MemoryAccount as VlessAccount;
use xray_proxy_vless::encoding::client::{decode_response_header, encode_request_header};
use xray_proxy_vless::encoding::{empty_addons, VlessCommand, VERSION};
use xray_proxy_vless::validator::{MemoryUser as VlessUser, MemoryValidator, Validator as VlessValidatorTrait};
use xray_proxy_vless::serve_vless;

// Fixed UUID for interop tests.
const SAMPLE_UUID: &str = "a3482e88-686a-4a58-8126-99c9214826d7";

// Test payload.
const PAYLOAD: &[u8] = b"hello vless interop test!";

// -- Helper: construct Rust VLESS server --

fn make_vless_ohm() -> Arc<SimpleOhm> {
    let ohm = Arc::new(SimpleOhm::new());
    let dial_fn = make_freedom_dial_fn();
    let bridge = Arc::new(DialBridge::new("freedom", dial_fn)) as Arc<dyn DispatchHandler>;
    ohm.set_default(bridge);
    ohm
}

fn make_vless_validator() -> (Arc<MemoryValidator>, UUID) {
    let uuid = UUID::parse(SAMPLE_UUID).expect("uuid parse");
    let account = VlessAccount {
        id: ID::new(uuid.clone()),
        flow: String::new(),
        encryption: "none".to_string(),
        xor_mode: 0,
        seconds: 0,
        padding: String::new(),
        reverse: None,
        testpre: 0,
        testseed: Vec::new(),
    };
    let user = VlessUser::new("interop@example.com", 0, account);
    let v = MemoryValidator::new();
    v.add(user).expect("add user");
    (Arc::new(v), uuid)
}

// -- Test 1: Go VLESS server -> Rust VLESS client (wire-level compat) --

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires XRAY_GO_BIN (Go xray-core binary); run with --ignored"]
async fn go_vless_server_rust_client() {
    // Start HTTP echo server as target
    let echo_port = spawn_http_echo_server()
        .await
        .expect("start http echo server");

    // Configure Go xray: VLESS inbound + freedom outbound
    let vless_port: u16 = 20021;
    let config = XrayConfig {
        inbounds: vec![vless_server_inbound(vless_port, SAMPLE_UUID)],
        outbounds: vec![freedom_outbound()],
    };
    let config_path = write_config_to_temp(&config, "go-vless-server")
        .expect("write config");

    let mut go_proc = start_go_xray(&config_path)
        .await
        .expect("start Go xray");
    wait_for_port(vless_port, 5000)
        .await
        .expect("Go VLESS port ready");

    // Rust VLESS client: connect to Go server, send data
    let result = rust_vless_client_connect(vless_port, echo_port).await;

    // Cleanup
    let _ = go_proc.kill().await;
    let _ = std::fs::remove_file(&config_path);

    result.expect("VLESS interop: Go server -> Rust client");
}

/// Rust VLESS client connects to Go VLESS server, sends HTTP request.
async fn rust_vless_client_connect(
    server_port: u16,
    echo_port: u16,
) -> std::io::Result<()> {
    let uuid = UUID::parse(SAMPLE_UUID).ok_or_else(|| std::io::Error::other("invalid UUID"))?;

    let mut client = tokio::net::TcpStream::connect(format!("127.0.0.1:{server_port}")).await?;

    // Encode VLESS request header
    let addons = empty_addons();
    encode_request_header(
        &mut client,
        VERSION,
        &uuid,
        VlessCommand::Tcp,
        Some(&Address::ipv4(std::net::Ipv4Addr::LOCALHOST)),
        Some(echo_port),
        &addons,
    )
    .await
    .map_err(|e| std::io::Error::other(e.to_string()))?;

    // NOTE: Go xray buffers the response header with `SetFlushNext` — it is
    // only flushed with the FIRST upstream data chunk (proxy/vless/inbound/
    // inbound.go:618-623 + common/buf/writer.go:211-216). The real Go client
    // runs request-send and response-read concurrently (outbound.go task.Run),
    // so a sequential "wait for response header before sending payload" dead-
    // locks: server waits for upstream data, echo waits for our HTTP request.
    // Send the payload FIRST, then read header+body from the stream (the
    // header is guaranteed to precede body bytes on the wire).

    // Send HTTP request
    let http_req = format!(
        "GET /interop HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        echo_port
    );
    client.write_all(http_req.as_bytes()).await?;

    // Now the upstream echo will respond; Go flushes the buffered response
    // header with the first upstream chunk, so read it here.
    let _resp_addons = decode_response_header(&mut client, VERSION)
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    // Read response body
    let mut buf = vec![0u8; 4096];
    let mut total = Vec::new();
    loop {
        match client.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => total.extend_from_slice(&buf[..n]),
            Err(e) => {
                if e.kind() == std::io::ErrorKind::ConnectionReset {
                    break;
                }
                return Err(e);
            }
        }
    }

    let resp_str = String::from_utf8_lossy(&total);
    assert!(
        resp_str.contains("200 OK") || resp_str.contains("ok"),
        "Expected HTTP 200 response, got: {}",
        &resp_str[..resp_str.len().min(200)]
    );

    Ok(())
}

// -- Test 2: Rust VLESS server -> Go VLESS client (via Go xray SOCKS5 proxy) --

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires XRAY_GO_BIN (Go xray-core binary); run with --ignored"]
async fn rust_vless_server_go_client() {
    // Start HTTP echo server as target
    let echo_port = spawn_http_echo_server()
        .await
        .expect("start http echo server");

    // Start Rust VLESS server
    let ohm = make_vless_ohm();
    let (validator, _uuid) = make_vless_validator();
    let vless_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let rust_vless_port = vless_listener.local_addr().expect("local addr").port();
    let ohm_clone = Arc::clone(&ohm);
    let validator_clone = Arc::clone(&validator);
    tokio::spawn(async move {
        let _ = serve_vless(vless_listener, ohm_clone, validator_clone, None, None, None).await;
    });

    // Configure Go xray: SOCKS5 inbound -> VLESS outbound -> Rust server
    let socks_port: u16 = 20031;
    let config = XrayConfig {
        inbounds: vec![socks5_inbound(socks_port)],
        outbounds: vec![vless_outbound(rust_vless_port, SAMPLE_UUID)],
    };
    let config_path = write_config_to_temp(&config, "go-vless-client")
        .expect("write config");

    let mut go_proc = start_go_xray(&config_path)
        .await
        .expect("start Go xray");
    wait_for_port(socks_port, 5000)
        .await
        .expect("Go SOCKS5 port ready");

    // Send HTTP request through Go SOCKS5 -> Go VLESS -> Rust VLESS -> freedom -> echo
    let proxy_addr = format!("127.0.0.1:{socks_port}")
        .parse()
        .expect("parse addr");
    let result = http_get_via_socks5(
        proxy_addr,
        "127.0.0.1",
        echo_port,
        "/interop",
    )
    .await;

    // Cleanup
    let _ = go_proc.kill().await;
    let _ = std::fs::remove_file(&config_path);

    let resp = result.expect("VLESS interop: Rust server -> Go client");
    assert!(
        resp.contains("200 OK") || resp.contains("ok"),
        "Expected HTTP 200 in response, got: {}",
        &resp[..resp.len().min(200)]
    );
}
