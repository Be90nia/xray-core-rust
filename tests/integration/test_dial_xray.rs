//! DialXray 集成测试（bd sk8r P3）。
//!
//! 对应 Go `testing/scenarios/feature_test.go::TestDialXray`：
//! 起一个 VMess inbound + freedom outbound 的 server 实例，再起一个 VMess
//! outbound + dispatcher 配置的 client 实例，通过 `core.Dial(ctx, client, dest)`
//! 拨号走 client → server → echo。
//!
//! **任务非目标约束**：P3 任务明确禁止「test DialXray 真实外部拨号」（真实
//! dial = server 与 client 双方 Xray 进程跨 VMess 协议握手 + dispatcher
//! outbound 拨号 — 涉及完整会话/计数器链路、跨实例 SimpleOhm 隔离等多项已
//! 知未对齐实现）。本测试改为**两端配置启动 smoke test**：
//!
//! 1. server: VMess inbound + freedom outbound → `start_full` → `is_running()`
//! 2. client: dispatcher + VMess outbound → `start_full` → `is_running()`
//! 3. server 端 dispatcher `get_default_handler()` 可用
//! 4. client 端 dispatcher 至少有一个 outbound handler（tag = "proxy-via-vmess"）
//!
//! 仅证明 core 启动路径可装配两端配置 + dispatcher 注册成功，不做真实
//! 跨实例 VMess 拨号（Go 端 `core.Dial` 等价物在 Rust 暴露为 dispatcher
//! `get_default_handler().dispatch(...)`，但跨实例 SimpleOhm 共享 / 计数器
//! 链路 / 反压等留 P4+）。
//!
//! **依赖 libclang/nasm**（xray-tls → btls-sys），标记 `#[ignore]`，与
//! `e2e_vmess_proxy` 同模式。运行：`cargo test -p xray-integration-tests
//! --test integration_dial_xray -- --ignored`。
//!
//! 拓扑：
//!   client Xray (dispatcher + vmess outbound) -- vmess protocol -->
//!   server Xray (vmess inbound + freedom outbound) --> echo server

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use xray_app_dispatcher::OutboundHandlerManager;
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

const VMESS_UUID_STR: &str = "dial-xray-test-9c8e4a2b-6f1d-4e0b-a5d8-7c9e2f3b8a01";

async fn pick_free_port() -> u16 {
    let probe = TcpListener::bind("127.0.0.1:0").await.expect("pick port");
    let port = probe.local_addr().expect("port").port();
    drop(probe);
    port
}

async fn spawn_echo_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("echo bind");
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    port
}

fn vmess_inbound_settings(uuid: &str, email: &str) -> Vec<u8> {
    serde_json::json!({
        "clients": [{ "id": uuid, "email": email, "level": 0 }]
    })
    .to_string()
    .into_bytes()
}

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

/// VMess outbound 指向 server 端 `server_addr:server_port`，使用 AEAD + AES-128-GCM。
fn vmess_outbound(server_addr: &str, server_port: u16, uuid: &str) -> BuiltOutbound {
    let v: serde_json::Value = serde_json::json!({
        "vnext": [{
            "address": server_addr,
            "port": server_port,
            "users": [{
                "id": uuid,
                "alterId": 0,
                "security": "aes-128-gcm"
            }]
        }]
    });
    BuiltOutbound {
        entry: BuiltEntry {
            kind: "vmess".into(),
            data: serde_json::to_vec(&v).unwrap(),
        },
        tag: "proxy-via-vmess".into(),
        send_through: None,
        stream_settings_json: None,
        proxy_settings_json: None,
        mux_json: None,
        target_strategy: None,
    }
}

async fn wait_ready(port: u16) {
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("vmess inbound at 127.0.0.1:{port} did not become ready in 1s");
}

/// 两端 VMess 配置启动 smoke test（不做真实跨实例拨号 — P3 非目标）。
///
/// 断言：
/// 1. server 端 `is_running()` = true；server SimpleOhm 含 "direct" outbound
/// 2. client 端 `is_running()` = true；client SimpleOhm 含 "proxy-via-vmess"
/// 3. server 端 SimpleOhm `get_default_handler()` 可用
/// 4. VMess protocol roundtrip via direct outbound (intra-instance dispatch)
///    走 dispatcher + freedom default outbound — 验证 dispatcher→default outbound 链。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires full xray-core runtime (libclang/nasm); see task sk8r non-goals"]
async fn dial_xray_two_instance_smoke() {
    let _ = UUID::parse(VMESS_UUID_STR).expect("uuid parse");

    // ---- Server: VMess inbound + freedom outbound ----
    let echo_port = spawn_echo_server().await;
    let server_port = pick_free_port().await;

    let server_built = BuiltConfig {
        inbounds: vec![BuiltInbound {
            entry: BuiltEntry {
                kind: "vmess".into(),
                data: vmess_inbound_settings(VMESS_UUID_STR, "dial-xray@server"),
            },
            tag: "vmess-in".into(),
            port: Some(server_port),
            listen: Some("127.0.0.1".into()),
            stream_settings_json: None,
            sniffing_json: None,
        }],
        outbounds: vec![freedom_outbound("direct")],
        apps: vec![],
    };
    let (server_instance, server_ohm, server_handles) = start_full(&server_built)
        .await
        .expect("start_full server");
    assert!(
        server_instance.is_running(),
        "server instance must be running"
    );
    assert!(
        server_ohm.get_handler("direct").is_some(),
        "server SimpleOhm must register `direct` freedom outbound"
    );
    assert!(
        server_ohm.get_default_handler().is_some(),
        "server SimpleOhm must expose a default handler"
    );

    wait_ready(server_port).await;

    // ---- Client: dispatcher + VMess outbound (no inbound needed) ----
    let client_built = BuiltConfig {
        inbounds: vec![],
        outbounds: vec![vmess_outbound("127.0.0.1", server_port, VMESS_UUID_STR)],
        apps: vec![],
    };
    let (client_instance, client_ohm, client_handles) = start_full(&client_built)
        .await
        .expect("start_full client");
    assert!(
        client_instance.is_running(),
        "client instance must be running"
    );
    assert!(
        client_ohm.get_handler("proxy-via-vmess").is_some(),
        "client SimpleOhm must register VMess outbound"
    );

    // ---- Intra-instance VMess round-trip via server's VMess inbound ----
    // 验证 server 端 dispatcher→default outbound 链 OK（dokodemo 不参与，
    // 直接 VMess client → server inbound → freedom → echo）。
    use tokio::net::TcpStream;
    let mut client = TcpStream::connect(("127.0.0.1", server_port))
        .await
        .expect("connect server vmess inbound");
    let session = VmessClientSession::new();
    let dest = Destination::tcp(
        Address::ipv4(std::net::Ipv4Addr::LOCALHOST),
        Port::new(echo_port),
    );
    let uuid = UUID::parse(VMESS_UUID_STR).expect("uuid");
    let header =
        RequestHeader::new(VMESS_VERSION, Command::Tcp, dest, SecurityType::Aes128Gcm);
    let cmd_key = cmd_key_of(&uuid);
    let sealed = session
        .encode_request_header(&header, &cmd_key)
        .expect("vmess encode header");
    client.write_all(&sealed).await.expect("write vmess header");
    session
        .decode_response_header_async(&mut client)
        .await
        .expect("vmess decode resp header");

    // 写 PAYLOAD + 读 echo
    let payload = b"hello dial_xray smoke test!";
    client.write_all(payload).await.expect("write payload");

    let mut buf = vec![0u8; payload.len()];
    let mut got = 0;
    let read_fut = async {
        while got < buf.len() {
            let n = client.read(&mut buf[got..]).await.expect("read");
            if n == 0 {
                break;
            }
            got += n;
        }
        got
    };
    let n = tokio::time::timeout(Duration::from_secs(5), read_fut)
        .await
        .expect("echo roundtrip must complete in 5s");
    assert_eq!(n, payload.len(), "echo length mismatch");
    assert_eq!(&buf[..n], payload, "echo payload mismatch");

    // cleanup
    for h in server_handles {
        h.abort();
    }
    for h in client_handles {
        h.abort();
    }
}
