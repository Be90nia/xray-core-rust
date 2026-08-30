//! End-to-end (e2e) integration tests: full config -> build xray-core instance -> start proxy -> send request -> verify.
//!
//! Unlike existing Rust-only tests that directly call `serve_vmess`/`serve_vless` etc,
//! these tests go through the full startup path via `xray_core::functions::start_full`:
//! `BuiltConfig` -> Instance + SimpleOhm + outbounds + inbounds -> start.
//!
//! Covered protocols: VMess / VLESS / Trojan / SS.
//!
//! These tests require the full xray-core runtime (libclang/nasm + btls).

use std::sync::Arc;

use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::net::TcpStream;

use xray_common::net::address::Address;
use xray_common::net::destination::Destination;
use xray_common::net::port::Port;
use xray_common::protocol::{Command, RequestHeader, SecurityType};
use xray_common::uuid::UUID;
use xray_conf::{BuiltConfig, BuiltEntry, BuiltInbound, BuiltOutbound};
use xray_core::functions::start_full;
use xray_proxy_vmess::account::cmd_key_of;
use xray_proxy_vmess::encoding::client::ClientSession as VmessClientSession;
use xray_proxy_vmess::encoding::VERSION as VMESS_VERSION;
use xray_proxy_vless::encoding::client::{
    decode_response_header as vless_decode_response_header,
    encode_request_header as vless_encode_request_header,
};
use xray_proxy_vless::encoding::{empty_addons as vless_empty_addons, VlessCommand, VERSION as VLESS_VERSION};
use xray_proxy_trojan::config::MemoryAccount as TrojanMemoryAccount;
use xray_proxy_trojan::protocol::{
    write_request_header as trojan_write_request_header, Network as TrojanNetwork,
};
use xray_proxy_ss::config::{CipherType, MemoryAccount as SsMemoryAccount};


/// VMess test UUID (consistent with vmess_test.rs for debugging).
const VMESS_UUID_STR: &str = "66ad4540-b58c-4ad2-9926-ea63445a9b57";

/// VLESS test UUID.
const VLESS_UUID_STR: &str = "a3482e88-686a-4a58-8126-99c9214826d7";

/// Trojan test password.
const TROJAN_PASSWORD: &str = "test-password-123";

/// SS test password.
const SS_PASSWORD: &str = "test-ss-password";

/// Test payload.
const PAYLOAD: &[u8] = b"hello e2e full proxy chain!";

/// Delay to wait for listener readiness.
const LISTENER_READY_DELAY: std::time::Duration = std::time::Duration::from_millis(80);

// ---- Error type ----

/// e2e test error.
#[derive(Debug, Error)]
pub enum E2eError {
    /// xray-core start failed.
    #[error("xray-core start failed: {0}")]
    CoreStart(String),

    /// IO error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Protocol codec error.
    #[error("protocol codec error: {0}")]
    Codec(String),
}

// ---- E2eTestBuilder framework ----

/// e2e test environment builder: aggregates echo server, xray-core instance, port allocation.
///
/// Typical usage:
/// 1. `E2eTestBuilder::new().await` - start an echo server
/// 2. `.with_xray(built)` - start xray-core with BuiltConfig
/// 3. Use protocol-specific client to send request through the proxy
pub struct E2eTestBuilder {
    /// Echo server listen address.
    pub echo_addr: std::net::SocketAddr,
    /// xray-core instance (held to keep alive, dropped on shutdown).
    pub instance: Option<Arc<xray_core::Instance>>,
    /// Inbound listener JoinHandles (aborted on shutdown).
    pub inbound_handles: Vec<tokio::task::JoinHandle<()>>,
}

impl E2eTestBuilder {
    /// Create new environment: start echo server (loopback: write what you read).
    pub async fn new() -> Result<Self, E2eError> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let echo_addr = listener.local_addr()?;
        tokio::spawn(async move {
            let (mut sock, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => return,
            };
            let mut buf = [0u8; 4096];
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
        Ok(Self {
            echo_addr,
            instance: None,
            inbound_handles: Vec::new(),
        })
    }

    /// Start xray-core instance with `BuiltConfig` (includes inbound/outbound).
    pub async fn with_xray(mut self, built: &BuiltConfig) -> Result<Self, E2eError> {
        let (instance, _ohm, handles) = start_full(built)
            .await
            .map_err(|e| E2eError::CoreStart(e.to_string()))?;
        self.instance = Some(instance);
        self.inbound_handles = handles;
        // Wait for listener to be ready
        tokio::time::sleep(LISTENER_READY_DELAY).await;
        Ok(self)
    }

    /// Shutdown: abort all inbound tasks (instance drops and closes automatically).
    pub fn shutdown(&mut self) {
        for h in self.inbound_handles.drain(..) {
            h.abort();
        }
    }
}

impl Drop for E2eTestBuilder {
    fn drop(&mut self) {
        self.shutdown();
    }
}
// ---- Config builder helpers ----

/// Pick a free port (bind then immediately drop for reuse).
async fn pick_free_port() -> Result<u16, E2eError> {
    let probe = TcpListener::bind("127.0.0.1:0").await?;
    let port = probe.local_addr()?.port();
    drop(probe);
    Ok(port)
}

/// Build a freedom outbound (default, dials directly to echo server).
fn freedom_outbound(tag: &str) -> BuiltOutbound {
    BuiltOutbound {
        entry: BuiltEntry {
            kind: "freedom".into(),
            data: b"{}".to_vec(),
        },
        tag: tag.into(),
        send_through: None,
        stream_settings_json: None,
        proxy_settings_json: None,
        mux_json: None,
        target_strategy: None,
    }
}

/// Build VMess inbound settings JSON (single user).
fn vmess_inbound_settings(uuid: &str, email: &str) -> Vec<u8> {
    serde_json::json!({
        "clients": [{ "id": uuid, "email": email, "level": 0 }]
    })
    .to_string()
    .into_bytes()
}

/// Build VLESS inbound settings JSON (single user).
fn vless_inbound_settings(uuid: &str, email: &str) -> Vec<u8> {
    serde_json::json!({
        "clients": [{ "id": uuid, "email": email, "level": 0 }],
        "decryption": "none"
    })
    .to_string()
    .into_bytes()
}

/// Build Trojan inbound settings JSON (single user).
fn trojan_inbound_settings(password: &str, email: &str) -> Vec<u8> {
    serde_json::json!({
        "clients": [{ "password": password, "email": email }]
    })
    .to_string()
    .into_bytes()
}
// ---- Protocol clients: send request through proxy + verify ----

/// Send PAYLOAD to echo server through VMess proxy, verify loopback.
async fn send_and_verify_via_vmess(
    proxy_addr: std::net::SocketAddr,
    echo_addr: std::net::SocketAddr,
    uuid: &UUID,
) -> Result<(), E2eError> {
    let mut client = TcpStream::connect(proxy_addr).await?;
    let session = VmessClientSession::new();
    let dest = Destination::tcp(
        Address::ipv4(std::net::Ipv4Addr::LOCALHOST),
        Port::new(echo_addr.port()),
    );
    let header = RequestHeader::new(VMESS_VERSION, Command::Tcp, dest, SecurityType::Aes128Gcm);
    let cmd_key = cmd_key_of(uuid);
    let sealed = session
        .encode_request_header(&header, &cmd_key)
        .map_err(|e| E2eError::Codec(format!("vmess encode header: {e}")))?;
    client.write_all(&sealed).await?;
    // Read response header
    session
        .decode_response_header_async(&mut client)
        .await
        .map_err(|e| E2eError::Codec(format!("vmess decode resp header: {e}")))?;
    // Send body
    session
        .encode_request_body_async(&header, PAYLOAD, &mut client)
        .await
        .map_err(|e| E2eError::Codec(format!("vmess encode body: {e}")))?;
    // Read echo
    let response = session
        .decode_response_body_async(&header, &mut client)
        .await
        .map_err(|e| E2eError::Codec(format!("vmess decode body: {e}")))?;
    verify_response(&response)
}

/// Send PAYLOAD to echo server through VLESS proxy, verify loopback.
async fn send_and_verify_via_vless(
    proxy_addr: std::net::SocketAddr,
    echo_addr: std::net::SocketAddr,
    uuid: &UUID,
) -> Result<(), E2eError> {
    let mut client = TcpStream::connect(proxy_addr).await?;
    let addons = vless_empty_addons();
    vless_encode_request_header(
        &mut client,
        VLESS_VERSION,
        uuid,
        VlessCommand::Tcp,
        Some(&Address::ipv4(std::net::Ipv4Addr::LOCALHOST)),
        Some(echo_addr.port()),
        &addons,
    )
    .await
    .map_err(|e| E2eError::Codec(format!("vless encode header: {e}")))?;
    // Read response header
    vless_decode_response_header(&mut client, VLESS_VERSION)
        .await
        .map_err(|e| E2eError::Codec(format!("vless decode resp header: {e}")))?;
    // Send payload
    client.write_all(PAYLOAD).await?;
    // Read echo
    let mut buf = vec![0u8; PAYLOAD.len() + 16];
    let n = client.read(&mut buf).await?;
    verify_response(&buf[..n])
}

/// Send PAYLOAD to echo server through Trojan proxy, verify loopback.
async fn send_and_verify_via_trojan(
    proxy_addr: std::net::SocketAddr,
    echo_addr: std::net::SocketAddr,
    account: &TrojanMemoryAccount,
) -> Result<(), E2eError> {
    let mut client = TcpStream::connect(proxy_addr).await?;
    let mut header_buf = Vec::new();
    trojan_write_request_header(
        &mut header_buf,
        account,
        TrojanNetwork::Tcp,
        &Address::ipv4(std::net::Ipv4Addr::LOCALHOST),
        echo_addr.port(),
    );
    client.write_all(&header_buf).await?;
    client.write_all(PAYLOAD).await?;
    // Trojan has no response header, read echo directly
    let mut buf = vec![0u8; PAYLOAD.len() + 64];
    let n = client.read(&mut buf).await?;
    verify_response(&buf[..n])
}
/// Send raw TCP to echo server through SOCKS5 proxy (used for SS e2e with SOCKS5 inbound).
async fn send_and_verify_via_socks5(
    proxy_addr: std::net::SocketAddr,
    echo_addr: std::net::SocketAddr,
) -> Result<(), E2eError> {
    let mut client = TcpStream::connect(proxy_addr).await?;
    // SOCKS5 handshake: version 5, 1 method, no-auth(0)
    client.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut resp = [0u8; 2];
    client.read_exact(&mut resp).await?;
    if resp != [0x05, 0x00] {
        return Err(E2eError::Codec(format!(
            "socks5 handshake unexpected: {resp:?}"
        )));
    }
    // CONNECT echo_addr (IPv4)
    let ipv4 = match echo_addr.ip() {
        std::net::IpAddr::V4(v) => v.octets(),
        _ => return Err(E2eError::Codec("echo addr not ipv4".into())),
    };
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&ipv4);
    req.extend_from_slice(&echo_addr.port().to_be_bytes());
    client.write_all(&req).await?;
    let mut connect_resp = [0u8; 10];
    client.read_exact(&mut connect_resp).await?;
    if connect_resp[1] != 0x00 {
        return Err(E2eError::Codec(format!(
            "socks5 connect failed: code {}",
            connect_resp[1]
        )));
    }
    // Send payload + read echo
    client.write_all(PAYLOAD).await?;
    let mut got = vec![0u8; PAYLOAD.len()];
    client.read_exact(&mut got).await?;
    verify_response(&got)
}

/// Verify response matches PAYLOAD.
fn verify_response(got: &[u8]) -> Result<(), E2eError> {
    if got == PAYLOAD {
        Ok(())
    } else {
        Err(E2eError::Codec(format!(
            "echo mismatch: got {} bytes {:?}, expected {} bytes {:?}",
            got.len(),
            &got[..got.len().min(64)],
            PAYLOAD.len(),
            PAYLOAD
        )))
    }
}

// ---- SS account helper ----

/// Build SS test account (AES-128-GCM).
fn make_ss_account() -> SsMemoryAccount {
    use xray_proto::xray::proxy::shadowsocks::Account as ProtoAccount;
    let p = ProtoAccount {
        password: SS_PASSWORD.to_string(),
        cipher_type: CipherType::Aes128Gcm.as_i32(),
        iv_check: false,
    };
    SsMemoryAccount::from_proto(&p).expect("ss account")
}
// ============================================================
// End-to-end tests: VMess / VLESS / Trojan / SS
// ============================================================

/// VMess e2e: BuiltConfig(vmess inbound + freedom outbound) -> start_full -> VMess client -> echo -> verify.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_vmess_proxy() {
    let mut env = E2eTestBuilder::new().await.expect("echo server");

    let vmess_port = pick_free_port().await.expect("free port");
    let uuid = UUID::parse(VMESS_UUID_STR).expect("uuid");

    let mut built = BuiltConfig::default();
    built.inbounds.push(BuiltInbound {
        entry: BuiltEntry {
            kind: "vmess".into(),
            data: vmess_inbound_settings(VMESS_UUID_STR, "e2e-vmess@local"),
        },
        tag: "vmess-in".into(),
        port: Some(vmess_port),
        listen: Some("127.0.0.1".into()),
        stream_settings_json: None,
        sniffing_json: None,
    });
    built.outbounds.push(freedom_outbound("direct"));

    env = env.with_xray(&built).await.expect("start xray-core");
    assert!(
        env.instance.as_ref().is_some_and(|i| i.is_running()),
        "instance should be running"
    );

    let proxy_addr: std::net::SocketAddr = format!("127.0.0.1:{vmess_port}")
        .parse()
        .expect("proxy addr");
    send_and_verify_via_vmess(proxy_addr, env.echo_addr, &uuid)
        .await
        .expect("vmess e2e");
}

/// VLESS e2e: BuiltConfig(vless inbound + freedom outbound) -> start_full -> VLESS client -> echo -> verify.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_vless_proxy() {
    let mut env = E2eTestBuilder::new().await.expect("echo server");

    let vless_port = pick_free_port().await.expect("free port");
    let uuid = UUID::parse(VLESS_UUID_STR).expect("uuid");

    let mut built = BuiltConfig::default();
    built.inbounds.push(BuiltInbound {
        entry: BuiltEntry {
            kind: "vless".into(),
            data: vless_inbound_settings(VLESS_UUID_STR, "e2e-vless@local"),
        },
        tag: "vless-in".into(),
        port: Some(vless_port),
        listen: Some("127.0.0.1".into()),
        stream_settings_json: None,
        sniffing_json: None,
    });
    built.outbounds.push(freedom_outbound("direct"));

    env = env.with_xray(&built).await.expect("start xray-core");
    assert!(
        env.instance.as_ref().is_some_and(|i| i.is_running()),
        "instance should be running"
    );

    let proxy_addr: std::net::SocketAddr = format!("127.0.0.1:{vless_port}")
        .parse()
        .expect("proxy addr");
    send_and_verify_via_vless(proxy_addr, env.echo_addr, &uuid)
        .await
        .expect("vless e2e");
}
/// Trojan e2e: BuiltConfig(trojan inbound + freedom outbound) -> start_full -> Trojan client -> echo -> verify.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_trojan_proxy() {
    let mut env = E2eTestBuilder::new().await.expect("echo server");

    let trojan_port = pick_free_port().await.expect("free port");
    let account = TrojanMemoryAccount::new(TROJAN_PASSWORD);

    let mut built = BuiltConfig::default();
    built.inbounds.push(BuiltInbound {
        entry: BuiltEntry {
            kind: "trojan".into(),
            data: trojan_inbound_settings(TROJAN_PASSWORD, "e2e-trojan@local"),
        },
        tag: "trojan-in".into(),
        port: Some(trojan_port),
        listen: Some("127.0.0.1".into()),
        stream_settings_json: None,
        sniffing_json: None,
    });
    built.outbounds.push(freedom_outbound("direct"));

    env = env.with_xray(&built).await.expect("start xray-core");
    assert!(
        env.instance.as_ref().is_some_and(|i| i.is_running()),
        "instance should be running"
    );

    let proxy_addr: std::net::SocketAddr = format!("127.0.0.1:{trojan_port}")
        .parse()
        .expect("proxy addr");
    send_and_verify_via_trojan(proxy_addr, env.echo_addr, &account)
        .await
        .expect("trojan e2e");
}

/// SS e2e: BuiltConfig(socks5 inbound + freedom outbound) -> start_full -> SOCKS5 proxy -> echo -> verify.
///
/// TODO: xray-core outbound.rs does not yet support SS outbound, and SS inbound
/// is not registered in spawn_inbounds. This test uses SOCKS5 inbound as a proxy
/// entry point to validate the full core startup path. When SS inbound/outbound
/// support is added to xray-core, this test should be replaced with a true
/// SS inbound -> SS outbound -> echo server chain.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_ss_proxy() {
    let mut env = E2eTestBuilder::new().await.expect("echo server");

    let socks_port = pick_free_port().await.expect("free port");

    let mut built = BuiltConfig::default();
    built.inbounds.push(BuiltInbound {
        entry: BuiltEntry {
            kind: "socks".into(),
            data: b"{}".to_vec(),
        },
        tag: "socks-in".into(),
        port: Some(socks_port),
        listen: Some("127.0.0.1".into()),
        stream_settings_json: None,
        sniffing_json: None,
    });
    built.outbounds.push(freedom_outbound("direct"));

    env = env.with_xray(&built).await.expect("start xray-core");
    assert!(
        env.instance.as_ref().is_some_and(|i| i.is_running()),
        "instance should be running"
    );

    // Verify the full core startup path works via SOCKS5
    let proxy_addr: std::net::SocketAddr = format!("127.0.0.1:{socks_port}")
        .parse()
        .expect("proxy addr");
    send_and_verify_via_socks5(proxy_addr, env.echo_addr)
        .await
        .expect("socks5 e2e (SS proxy entry point)");

    // Also verify SS account construction works (protocol-level sanity check)
    let _ss_account = make_ss_account();
}