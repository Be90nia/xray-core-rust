//! VMess Go<->Rust interop tests.
//!
// Test scenarios:
// 1. Go VMess server -> Rust VMess client (wire-level protocol compat)
// 2. Rust VMess server -> Go VMess client (via Go xray SOCKS5 inbound)
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
use xray_common::net::destination::Destination;
use xray_common::net::port::Port;
use xray_common::protocol::{Command, RequestHeader, SecurityType};
use xray_common::uuid::UUID;
use xray_proxy_freedom::make_freedom_dial_fn;
use xray_proxy_vmess::account::MemoryAccount;
use xray_proxy_vmess::encoding::client::ClientSession;
use xray_proxy_vmess::encoding::VERSION;
use xray_proxy_vmess::validator::{MemoryUser, TimedUserValidator, Validator as VmessValidatorTrait};
use xray_proxy_vmess::serve_vmess;

// Fixed UUID for interop tests.
const SAMPLE_UUID: &str = "66ad4540-b58c-4ad2-9926-ea63445a9b57";

// Test payload.
const PAYLOAD: &[u8] = b"hello vmess interop test!";

// -- Helper: construct Rust VMess server (validator + serve_vmess + freedom) --

fn make_vmess_ohm() -> Arc<SimpleOhm> {
    let ohm = Arc::new(SimpleOhm::new());
    let dial_fn = make_freedom_dial_fn();
    let bridge = Arc::new(DialBridge::new("freedom", dial_fn)) as Arc<dyn DispatchHandler>;
    ohm.set_default(bridge);
    ohm
}

fn make_vmess_validator() -> (Arc<TimedUserValidator>, [u8; 16]) {
    let uuid = UUID::parse(SAMPLE_UUID).expect("uuid parse");
    let account = MemoryAccount::new(uuid);
    let cmd_key = account.cmd_key();
    let user = MemoryUser::new("interop@example.com", account);
    let v = TimedUserValidator::new();
    v.add(user).expect("add user");
    (Arc::new(v), cmd_key)
}

// -- Test 1: Go VMess server -> Rust VMess client (wire-level compat) --
// Rust client connects directly to Go VMess server, sends data, verifies echo.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Go xray-core binary; run with --ignored"]
async fn go_vmess_server_rust_client_aes128gcm() {
    run_go_server_rust_client(SecurityType::Aes128Gcm).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Go xray-core binary; run with --ignored"]
async fn go_vmess_server_rust_client_chacha20poly1305() {
    run_go_server_rust_client(SecurityType::Chacha20Poly1305).await;
}

async fn run_go_server_rust_client(security: SecurityType) {
    // Start HTTP echo server as the target
    let echo_port = spawn_http_echo_server()
        .await
        .expect("start http echo server");

    // Configure Go xray: VMess inbound + freedom outbound
    let vmess_port: u16 = 20001;
    let config = XrayConfig {
        inbounds: vec![vmess_server_inbound(vmess_port, SAMPLE_UUID)],
        outbounds: vec![freedom_outbound()],
    };
    let config_path = write_config_to_temp(&config, "go-vmess-server")
        .expect("write config");

    let mut go_proc = start_go_xray(&config_path)
        .await
        .expect("start Go xray");
    wait_for_port(vmess_port, 5000)
        .await
        .expect("Go VMess port ready");

    // Rust VMess client: connect to Go server, send request
    let result = rust_vmess_client_connect(vmess_port, security, echo_port).await;

    // Cleanup
    let _ = go_proc.kill().await;
    let _ = std::fs::remove_file(&config_path);

    result.expect("VMess interop: Go server -> Rust client");
}

/// Rust VMess client connects to Go VMess server, sends data, verifies echo.
async fn rust_vmess_client_connect(
    server_port: u16,
    security: SecurityType,
    echo_port: u16,
) -> std::io::Result<()> {
    let uuid = UUID::parse(SAMPLE_UUID).ok_or_else(|| std::io::Error::other("invalid UUID"))?;
    let account = MemoryAccount::new(uuid);
    let cmd_key = account.cmd_key();

    let mut client = tokio::net::TcpStream::connect(format!("127.0.0.1:{server_port}")).await?;

    let client_session = ClientSession::new();
    let dest = Destination::tcp(
        Address::ipv4(std::net::Ipv4Addr::LOCALHOST),
        Port::new(echo_port),
    );
    let header = RequestHeader::new(VERSION, Command::Tcp, dest, security);

    let sealed_header = client_session
        .encode_request_header(&header, &cmd_key)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    client.write_all(&sealed_header).await?;

    // Read response header
    let _resp = client_session
        .decode_response_header_async(&mut client)
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    // Send request body (HTTP GET to echo server)
    let http_req = format!(
        "GET /interop HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        echo_port
    );
    client_session
        .encode_request_body_async(&header, http_req.as_bytes(), &mut client)
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    // Read response
    let response = client_session
        .decode_response_body_async(&header, &mut client)
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    // Verify we got an HTTP response
    let resp_str = String::from_utf8_lossy(&response);
    assert!(
        resp_str.contains("200 OK") || resp_str.contains("ok"),
        "Expected HTTP 200 response, got: {}",
        &resp_str[..resp_str.len().min(200)]
    );

    Ok(())
}

// -- Test 2: Rust VMess server -> Go VMess client (via Go xray SOCKS5 proxy) --
// Go xray acts as: SOCKS5 inbound -> VMess outbound -> Rust VMess server -> freedom -> echo

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Go xray-core binary; run with --ignored"]
async fn rust_vmess_server_go_client_aes128gcm() {
    run_rust_server_go_client(SecurityType::Aes128Gcm).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Go xray-core binary; run with --ignored"]
async fn rust_vmess_server_go_client_chacha20poly1305() {
    run_rust_server_go_client(SecurityType::Chacha20Poly1305).await;
}

async fn run_rust_server_go_client(security: SecurityType) {
    // Start HTTP echo server as target
    let echo_port = spawn_http_echo_server()
        .await
        .expect("start http echo server");

    // Start Rust VMess server
    let ohm = make_vmess_ohm();
    let (validator, _cmd_key) = make_vmess_validator();
    let vmess_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let rust_vmess_port = vmess_listener.local_addr().expect("local addr").port();
    let ohm_clone = Arc::clone(&ohm);
    let validator_clone = Arc::clone(&validator);
    tokio::spawn(async move {
        let _ = serve_vmess(vmess_listener, ohm_clone, validator_clone, None).await;
    });

    // Configure Go xray: SOCKS5 inbound -> VMess outbound -> Rust server
    let socks_port: u16 = 20011;
    let go_security = match security {
        SecurityType::Aes128Gcm => "aes-128-gcm",
        SecurityType::Chacha20Poly1305 => "chacha20-poly1305",
        SecurityType::None => "none",
        SecurityType::Auto => "auto",
        _ => "auto",
    };
    let config = XrayConfig {
        inbounds: vec![socks5_inbound(socks_port)],
        outbounds: vec![Outbound {
            protocol: "vmess".into(),
            settings: Some(serde_json::json!({
                "vnext": [{
                    "address": "127.0.0.1",
                    "port": rust_vmess_port,
                    "users": [{
                        "id": SAMPLE_UUID,
                        "alterId": 0,
                        "security": go_security
                    }]
                }]
            })),
            stream_settings: None,
            tag: Some("vmess-out".into()),
        }],
    };
    let config_path = write_config_to_temp(&config, "go-vmess-client")
        .expect("write config");

    let mut go_proc = start_go_xray(&config_path)
        .await
        .expect("start Go xray");
    wait_for_port(socks_port, 5000)
        .await
        .expect("Go SOCKS5 port ready");

    // Send HTTP request through Go SOCKS5 -> Go VMess -> Rust VMess -> freedom -> echo
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

    let resp = result.expect("VMess interop: Rust server -> Go client");
    assert!(
        resp.contains("200 OK") || resp.contains("ok"),
        "Expected HTTP 200 in response, got: {}",
        &resp[..resp.len().min(200)]
    );
}
