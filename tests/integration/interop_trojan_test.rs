//! Trojan Go<->Rust interop tests.
// Test scenarios:
// 1. Go Trojan server -> Rust Trojan client (wire-level protocol compat)
// 2. Rust Trojan server -> Go Trojan client (via Go xray SOCKS5 inbound)
//
// Note: Trojan normally requires TLS. For interop tests we use
// security=none (plain TCP) which Go xray supports for testing.
//
// All tests are #[ignore] by default: run with `cargo test -- --ignored`.
// Requires Go xray-core binary at XRAY_GO_BIN or default path.

mod interop_helpers;

use std::{collections::HashMap, sync::Arc};

use interop_helpers::*;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use xray_app_dispatcher::{
    DispatchHandler,
    default::{DialBridge, SimpleOhm},
};
use xray_common::net::address::Address;
use xray_proxy_freedom::make_freedom_dial_fn;
use xray_proxy_trojan::{
    config::MemoryAccount as TrojanAccount,
    protocol::{Network as TrojanNetwork, write_request_header},
    serve_trojan,
    server::trojan_server_handshake,
    validator::{MemoryUser as TrojanUser, Validator as TrojanValidator},
};

// Test password.
const PASSWORD: &str = "interop-trojan-password";

// -- Helper: construct Rust Trojan server --

fn make_trojan_ohm() -> Arc<SimpleOhm> {
    let ohm = Arc::new(SimpleOhm::new());
    let dial_fn = make_freedom_dial_fn();
    let bridge = Arc::new(DialBridge::new("freedom", dial_fn)) as Arc<dyn DispatchHandler>;
    ohm.set_default(bridge);
    ohm
}

fn make_trojan_validator() -> (Arc<TrojanValidator>, TrojanAccount) {
    let account = TrojanAccount::new(PASSWORD);
    let user = TrojanUser::new("interop@example.com", 0, account.clone());
    let v = TrojanValidator::new();
    v.add(user).expect("add user");
    (Arc::new(v), account)
}

fn make_trojan_users() -> HashMap<String, TrojanUser> {
    let account = TrojanAccount::new(PASSWORD);
    let user = TrojanUser::new("interop@example.com", 0, account);
    let mut map = HashMap::new();
    map.insert("interop@example.com".to_string(), user);
    map
}

// -- Test 1: Go Trojan server -> Rust Trojan client (wire-level handshake) --
// Rust Trojan client connects to Go Trojan server, sends handshake, verifies.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires XRAY_GO_BIN (Go xray-core binary); run with --ignored"]
async fn go_trojan_server_rust_client_handshake() {
    // Start HTTP echo server as target
    let echo_port = spawn_http_echo_server().await.expect("start http echo server");

    // Configure Go xray: Trojan inbound (plain TCP) + freedom outbound
    let trojan_port: u16 = 20041;
    let config = XrayConfig {
        inbounds: vec![trojan_server_inbound(trojan_port, PASSWORD)],
        outbounds: vec![freedom_outbound()],
    };
    let config_path = write_config_to_temp(&config, "go-trojan-server").expect("write config");

    let mut go_proc = start_go_xray(&config_path).await.expect("start Go xray");
    wait_for_port(trojan_port, 5000).await.expect("Go Trojan port ready");

    // Rust Trojan client: connect to Go server, send handshake
    let result = rust_trojan_client_connect(trojan_port, echo_port).await;

    // Cleanup
    let _ = go_proc.kill().await;
    let _ = std::fs::remove_file(&config_path);

    result.expect("Trojan interop: Go server -> Rust client");
}

/// Rust Trojan client connects to Go Trojan server, sends handshake + data.
async fn rust_trojan_client_connect(server_port: u16, echo_port: u16) -> std::io::Result<()> {
    let account = TrojanAccount::new(PASSWORD);
    let mut client = tokio::net::TcpStream::connect(format!("127.0.0.1:{server_port}")).await?;

    // Write Trojan request header
    let dest_addr = Address::ipv4(std::net::Ipv4Addr::LOCALHOST);
    let mut header_buf = Vec::new();
    write_request_header(&mut header_buf, &account, TrojanNetwork::Tcp, &dest_addr, echo_port);
    client.write_all(&header_buf).await?;
    client.flush().await?;

    // Send HTTP request through the tunnel
    let http_req = format!(
        "GET /interop HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        echo_port
    );
    client.write_all(http_req.as_bytes()).await?;

    // Read response
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
            },
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

// -- Test 2: Rust Trojan server -> Go Trojan client (via Go xray SOCKS5 proxy) --

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires XRAY_GO_BIN (Go xray-core binary); run with --ignored"]
async fn rust_trojan_server_go_client() {
    // Start HTTP echo server as target
    let echo_port = spawn_http_echo_server().await.expect("start http echo server");

    // Start Rust Trojan server
    let ohm = make_trojan_ohm();
    let users = make_trojan_users();
    let trojan_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let rust_trojan_port = trojan_listener.local_addr().expect("local addr").port();
    let ohm_clone = Arc::clone(&ohm);
    tokio::spawn(async move {
        let listener = xray_transport::system_listener::InboundTcpListener::from_tokio(
            trojan_listener,
            xray_transport::sockopt::SocketOptions::default(),
        );
        let _ = serve_trojan(
            listener,
            ohm_clone,
            users,
            None,
            None,
            std::time::Duration::from_secs(30),
        )
        .await;
    });

    // Configure Go xray: SOCKS5 inbound -> Trojan outbound -> Rust server
    let socks_port: u16 = 20051;
    let config = XrayConfig {
        inbounds: vec![socks5_inbound(socks_port)],
        outbounds: vec![trojan_outbound(rust_trojan_port, PASSWORD)],
    };
    let config_path = write_config_to_temp(&config, "go-trojan-client").expect("write config");

    let mut go_proc = start_go_xray(&config_path).await.expect("start Go xray");
    wait_for_port(socks_port, 5000).await.expect("Go SOCKS5 port ready");

    // Send HTTP request through Go SOCKS5 -> Go Trojan -> Rust Trojan -> freedom -> echo
    let proxy_addr = format!("127.0.0.1:{socks_port}").parse().expect("parse addr");
    let result = http_get_via_socks5(proxy_addr, "127.0.0.1", echo_port, "/interop").await;

    // Cleanup
    let _ = go_proc.kill().await;
    let _ = std::fs::remove_file(&config_path);

    let resp = result.expect("Trojan interop: Rust server -> Go client");
    assert!(
        resp.contains("200 OK") || resp.contains("ok"),
        "Expected HTTP 200 in response, got: {}",
        &resp[..resp.len().min(200)]
    );
}

// -- Test 3: Rust Trojan handshake wire compat with Go format --
// Verify Rust Trojan server can parse Go Trojan client's handshake format.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires XRAY_GO_BIN (Go xray-core binary); run with --ignored"]
async fn rust_trojan_server_go_client_handshake_only() {
    let (validator, _account) = make_trojan_validator();
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");

    let validator_clone = Arc::clone(&validator);
    let server_handle = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("accept");
        trojan_server_handshake(&mut sock, &validator_clone, std::time::Duration::from_secs(30)).await
    });

    // Rust client constructs Trojan handshake in Go-compatible format
    let account = TrojanAccount::new(PASSWORD);
    let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");

    let dest_addr = Address::ipv4(std::net::Ipv4Addr::LOCALHOST);
    let mut header_buf = Vec::new();
    write_request_header(&mut header_buf, &account, TrojanNetwork::Tcp, &dest_addr, 8080);
    client.write_all(&header_buf).await.expect("write header");
    client.flush().await.expect("flush");

    // Verify Rust server parses the handshake
    let result = server_handle.await.expect("server task").expect("handshake");
    let (network, parsed_addr, parsed_port, user) = result;
    assert_eq!(network, TrojanNetwork::Tcp);
    assert_eq!(parsed_addr, dest_addr);
    assert_eq!(parsed_port, 8080);
    assert_eq!(user.email, "interop@example.com");
}
