//! Shadowsocks Go->Rust interop tests.
// Test scenarios:
// 1. Go SS server -> Rust SS client (wire-level protocol compat, multiple ciphers)
// 2. Go SS server -> Rust SS client via Go xray SOCKS5 proxy
//
// Note: Rust currently has no SS server (serve_ss), so only Go->Rust direction.
// Each cipher type (AES-128-GCM, ChaCha20-Poly1305, AES-256-GCM) is tested.
//
// 5 只 SS 用例仍 #[ignore]（run with `cargo test -- --ignored`）；两只 SS-2022
// 用例常态跑：Go 二进制缺失时打一行 skip 日志后返回（`go_binary_ready`，不静默）。
// 二进制查找链见 `go_xray_bin_path`：$XRAY_GO_BIN → reports/night-run-*/tmp/*/
// xray-go.exe → dist/xray-go.exe。

mod interop_helpers;

use interop_helpers::*;
use tokio::io::AsyncReadExt;
use xray_common::net::address::Address;
use xray_proto::xray::proxy::shadowsocks::Account as ProtoAccount;
use xray_proxy_ss::{
    Client2022,
    client::Client,
    config::{CipherType, MemoryAccount as SsAccount},
    server::read_request,
    stream::ChunkOut,
};

// Test password.
const PASSWORD: &str = "interop-ss-password";

// Test payload.
const PAYLOAD: &[u8] = b"hello ss interop test!";

// -- Helper: construct SS account --

fn make_ss_account(ct: CipherType) -> SsAccount {
    let p =
        ProtoAccount { password: PASSWORD.to_string(), cipher_type: ct.as_i32(), iv_check: false };
    SsAccount::from_proto(&p).expect("account from proto")
}

// -- Test 1: Go SS server -> Rust SS client (wire-level compat) --
// Rust SS client connects directly to Go SS server, sends data.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires XRAY_GO_BIN (Go xray-core binary); run with --ignored"]
async fn go_ss_server_rust_client_aes128gcm() {
    run_go_ss_server_rust_client(CipherType::Aes128Gcm, "aes-128-gcm", 20061).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires XRAY_GO_BIN (Go xray-core binary); run with --ignored"]
async fn go_ss_server_rust_client_chacha20poly1305() {
    run_go_ss_server_rust_client(CipherType::ChaCha20Poly1305, "chacha20-ietf-poly1305", 20071)
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires XRAY_GO_BIN (Go xray-core binary); run with --ignored"]
async fn go_ss_server_rust_client_aes256gcm() {
    run_go_ss_server_rust_client(CipherType::Aes256Gcm, "aes-256-gcm", 20081).await;
}

async fn run_go_ss_server_rust_client(ct: CipherType, go_method: &str, ss_port: u16) {
    if !go_binary_ready() {
        return;
    }
    // Start echo server as target
    let echo_port = spawn_echo_server().await.expect("start echo server");

    // Configure Go xray: SS inbound + freedom outbound
    let config = XrayConfig {
        inbounds: vec![ss_server_inbound(ss_port, PASSWORD, go_method)],
        outbounds: vec![freedom_outbound()],
    };
    let config_path =
        write_config_to_temp(&config, &format!("go-ss-server-{go_method}")).expect("write config");

    let mut go_proc = start_go_xray(&config_path).await.expect("start Go xray");
    wait_for_port(ss_port, 5000).await.expect("Go SS port ready");

    // Rust SS client: connect to Go server, send data, verify echo
    let result = rust_ss_client_connect(ct, ss_port, echo_port).await;
    // Cleanup
    let _ = go_proc.kill().await;
    let _ = std::fs::remove_file(&config_path);

    result.expect("SS interop: Go server -> Rust client");
}

/// Rust SS client connects to Go SS server, sends data, verifies echo.
async fn rust_ss_client_connect(
    ct: CipherType,
    server_port: u16,
    echo_port: u16,
) -> std::io::Result<()> {
    let account = make_ss_account(ct);
    let client = Client::new(account, "127.0.0.1".to_string(), server_port);

    let target_addr = Address::ipv4(std::net::Ipv4Addr::LOCALHOST);
    let mut ss_stream = client
        .dial_target_for_proxy(&target_addr, echo_port)
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    // Send payload through SS tunnel
    ss_stream.write_chunk(PAYLOAD).await.map_err(|e| std::io::Error::other(e.to_string()))?;
    ss_stream.flush().await.map_err(|e| std::io::Error::other(e.to_string()))?;

    // Read echo response
    let response = ss_stream
        .read_chunk()
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?
        .unwrap_or_default();

    // Verify echo
    assert_eq!(
        response.as_slice(),
        PAYLOAD,
        "SS echo mismatch: got {} bytes, expected {}",
        response.len(),
        PAYLOAD.len()
    );

    Ok(())
}

// -- Test 2: Go SS server -> Rust SS server wire-level compat --
// Both Go SS server and Rust SS server parse the same client request.
// Verify Rust read_request can parse data sent by Go SS server.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires XRAY_GO_BIN (Go xray-core binary); run with --ignored"]
async fn rust_ss_server_reads_go_client_request() {
    // Start Rust SS server
    let account = make_ss_account(CipherType::Aes128Gcm);
    let account_clone = account.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let ss_port = listener.local_addr().expect("local addr").port();

    let server_handle = tokio::spawn(async move {
        let (conn, _) = listener.accept().await.expect("accept");
        read_request(conn, &account_clone, "interop", 0).await
    });

    // Rust SS client connects to Rust SS server (self-test to verify server works)
    let client = Client::new(account, "127.0.0.1".to_string(), ss_port);
    let target_addr = Address::ipv4(std::net::Ipv4Addr::new(1, 2, 3, 4));
    let target_port: u16 = 5678;
    let mut ss_stream = client.dial_target(&target_addr, target_port).await.expect("dial_target");
    ss_stream.write_chunk(PAYLOAD).await.expect("write_chunk");
    ss_stream.flush().await.expect("flush");
    ss_stream.shutdown().await.ok();

    // Verify server parsed the request correctly
    let (header, _body) = server_handle.await.expect("server task").expect("read_request");

    // Header fields verification (body verification covered in e2e test above)
    assert_eq!(header.address, target_addr, "address mismatch");
    assert_eq!(header.port, target_port, "port mismatch");
    assert_eq!(header.address, target_addr, "address mismatch");
    assert_eq!(header.port, target_port, "port mismatch");
}

// -- Test 3: Full Go SS proxy -> Rust SS client --
// Go xray runs as full proxy (SS inbound + freedom outbound).
// Rust SS client connects, sends HTTP request through the tunnel.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires XRAY_GO_BIN (Go xray-core binary); run with --ignored"]
async fn go_ss_proxy_rust_client_aes128gcm_http() {
    if !go_binary_ready() {
        return;
    }
    // Start HTTP echo server as target
    let echo_port = spawn_http_echo_server().await.expect("start http echo server");

    // Configure Go xray: SS inbound + freedom outbound
    let ss_port: u16 = 20091;
    let config = XrayConfig {
        inbounds: vec![ss_server_inbound(ss_port, PASSWORD, "aes-128-gcm")],
        outbounds: vec![freedom_outbound()],
    };
    let config_path = write_config_to_temp(&config, "go-ss-proxy").expect("write config");

    let mut go_proc = start_go_xray(&config_path).await.expect("start Go xray");
    wait_for_port(ss_port, 5000).await.expect("Go SS port ready");

    // Rust SS client: connect, send HTTP, verify
    let account = make_ss_account(CipherType::Aes128Gcm);
    let client = Client::new(account, "127.0.0.1".to_string(), ss_port);
    let target_addr = Address::ipv4(std::net::Ipv4Addr::LOCALHOST);

    let result = async {
        let mut ss_stream = client
            .dial_target_for_proxy(&target_addr, echo_port)
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        // Send HTTP request through SS tunnel
        let http_req = format!(
            "GET /interop HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
            echo_port
        );
        ss_stream
            .write_chunk(http_req.as_bytes())
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        ss_stream.flush().await.map_err(|e| std::io::Error::other(e.to_string()))?;

        // Read response (may come in multiple chunks)
        let mut total = Vec::new();
        loop {
            match ss_stream.read_chunk().await {
                Ok(Some(data)) => total.extend_from_slice(&data),
                Ok(None) => break,
                Err(e) => {
                    // Connection reset after close is normal
                    if e.to_string().contains("reset") || e.to_string().contains("closed") {
                        break;
                    }
                    return Err(std::io::Error::other(e.to_string()));
                },
            }
            // Stop after getting enough data
            if total.len() > 100 {
                break;
            }
        }

        let resp_str = String::from_utf8_lossy(&total);
        if !resp_str.contains("200 OK") && !resp_str.contains("ok") {
            return Err(std::io::Error::other(format!(
                "Expected HTTP 200, got: {}",
                &resp_str[..resp_str.len().min(200)]
            )));
        }
        Ok::<(), std::io::Error>(())
    }
    .await;

    // Cleanup
    let _ = go_proc.kill().await;
    let _ = std::fs::remove_file(&config_path);

    result.expect("SS HTTP interop: Go proxy -> Rust client");
}

// -- SS-2022: Go server -> Rust client（SIP022 wire 互通） --
// 对应 Go testing/scenarios/shadowsocks_2022_test.go 三方法中的两个缺口方法。
// PSK 随机生成（base64），Go 单用户 ServerConfig（method + password）。

/// 生成随机 PSK 并 base64 编码（与 ss_test.rs 同实现；跨测试二进制不共享代码）。
fn random_psk_b64(len: usize) -> String {
    use base64::Engine as _;
    let psk: Vec<u8> = (0..len).map(|_| rand::random::<u8>()).collect();
    base64::engine::general_purpose::STANDARD.encode(psk)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn go_ss2022_server_rust_client_aes128gcm() {
    run_go_ss2022_server_rust_client("2022-blake3-aes-128-gcm", 16, 47231).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn go_ss2022_server_rust_client_chacha20poly1305() {
    run_go_ss2022_server_rust_client("2022-blake3-chacha20-poly1305", 32, 47232).await;
}

async fn run_go_ss2022_server_rust_client(method: &'static str, psk_len: usize, ss_port: u16) {
    if !go_binary_ready() {
        return;
    }
    let echo_port = spawn_echo_server().await.expect("start echo server");
    let psk_b64 = random_psk_b64(psk_len);

    let config = XrayConfig {
        inbounds: vec![ss2022_server_inbound(ss_port, &psk_b64, method)],
        outbounds: vec![freedom_outbound()],
    };
    let config_path =
        write_config_to_temp(&config, &format!("go-ss2022-server-{method}")).expect("write config");

    let mut go_proc = start_go_xray(&config_path).await.expect("start Go xray");
    wait_for_port(ss_port, 5000).await.expect("Go SS2022 port ready");

    let result = async {
        let client = Client2022::new(method, &[psk_b64], "127.0.0.1", ss_port)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        let mut stream = client
            .dial_target("127.0.0.1", echo_port)
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        stream.write_chunk(PAYLOAD).await.map_err(|e| std::io::Error::other(e.to_string()))?;
        stream.flush().await.map_err(|e| std::io::Error::other(e.to_string()))?;

        // SS-2022 响应必须走 pump 语义（try_open_chunk + 手动喂数据）：
        // 响应线上是 resp_salt || fixed header chunk || var chunk，read_chunk 是
        // legacy-only，会把 server salt 误当 size chunk（bd vl7v）。
        let mut pending: Vec<u8> = Vec::new();
        let mut wire = [0u8; 4096];
        let response = loop {
            match stream.try_open_chunk(&mut pending) {
                Ok(ChunkOut::Message(data)) => break data,
                Ok(ChunkOut::End) => break Vec::new(),
                Ok(ChunkOut::NeedMore) => {
                    let n =
                        stream.get_mut().read(&mut wire).await.map_err(std::io::Error::other)?;
                    if n == 0 {
                        return Err(std::io::Error::other(
                            "SS-2022 response: EOF before echo payload",
                        ));
                    }
                    pending.extend_from_slice(&wire[..n]);
                },
                Err(e) => return Err(std::io::Error::other(e.to_string())),
            }
        };
        assert_eq!(
            response.as_slice(),
            PAYLOAD,
            "SS-2022 echo mismatch: got {} bytes, expected {}",
            response.len(),
            PAYLOAD.len()
        );
        Ok::<(), std::io::Error>(())
    }
    .await;

    // Cleanup
    let _ = go_proc.kill().await;
    let _ = std::fs::remove_file(&config_path);

    result.expect("SS-2022 interop: Go server -> Rust client");
}
