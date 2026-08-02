//! VMess 协议 Rust-only 端到端集成测试。
//!
//! 验证 VMess 完整代理链路（inbound → freedom outbound → echo server）
//! 在不同加密方式下的正确性。不依赖 Go 二进制。
//!
//! 测试模式：
//! 1. 启动 echo server（回环）
//! 2. 启动 VMess inbound（serve_vmess + freedom outbound）
//! 3. VMess client 连接 → encode header/body → decode response → 验证 echo 回环

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use xray_app_dispatcher::default::{DialBridge, SimpleOhm};
use xray_app_dispatcher::DispatchHandler;
use xray_common::net::address::Address;
use xray_common::net::destination::Destination;
use xray_common::net::port::Port;
use xray_common::protocol::{Command, RequestHeader, SecurityType};
use xray_common::uuid::UUID;
use xray_proxy_freedom::make_freedom_dial_fn;
use xray_proxy_vmess::account::{cmd_key_of, MemoryAccount};
use xray_proxy_vmess::encoding::client::ClientSession;
use xray_proxy_vmess::encoding::VERSION;
use xray_proxy_vmess::validator::{MemoryUser, TimedUserValidator, Validator};
use xray_proxy_vmess::serve_vmess;

/// 固定 UUID（避免反重放状态污染）。
const SAMPLE_UUID_STR: &str = "66ad4540-b58c-4ad2-9926-ea63445a9b57";

/// 测试负载。
const PAYLOAD: &[u8] = b"hello vmess integration test!";

/// 构造含已注册用户的 validator + cmd_key。
fn make_validator() -> (Arc<TimedUserValidator>, [u8; 16]) {
    let uuid = UUID::parse(SAMPLE_UUID_STR).expect("uuid");
    let account = MemoryAccount::new(uuid);
    let cmd_key = account.cmd_key();
    let user = MemoryUser::new("alice@example.com", account);
    let v = TimedUserValidator::new();
    v.add(user).expect("add user");
    (Arc::new(v), cmd_key)
}

/// 构造 SimpleOhm + freedom 默认出站。
fn make_ohm() -> Arc<SimpleOhm> {
    let ohm = Arc::new(SimpleOhm::new());
    let dial_fn = make_freedom_dial_fn();
    let bridge = Arc::new(DialBridge::new("freedom", dial_fn)) as Arc<dyn DispatchHandler>;
    ohm.set_default(bridge);
    ohm
}

/// 启动 echo server，返回监听端口。
async fn spawn_echo_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
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
    port
}

/// VMess 端到端测试核心：client → serve_vmess → freedom → echo。
async fn run_vmess_e2e(security: SecurityType) {
    // 1. echo server
    let echo_port = spawn_echo_server().await;

    // 2. dispatcher: freedom outbound → SimpleOhm default
    let ohm = make_ohm();

    // 3. validator + serve_vmess（监听随机端口）
    let (validator, cmd_key) = make_validator();
    let vmess_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let vmess_addr = vmess_listener.local_addr().unwrap();
    let ohm_clone = Arc::clone(&ohm);
    let validator_clone = Arc::clone(&validator);
    tokio::spawn(async move {
        let _ = serve_vmess(vmess_listener, ohm_clone, validator_clone, None).await;
    });

    // 4. VMess client：connect → encode header → decode response header → echo round-trip
    let mut client = tokio::net::TcpStream::connect(vmess_addr)
        .await
        .unwrap();
    let client_session = ClientSession::new();
    let dest = Destination::tcp(
        Address::ipv4(std::net::Ipv4Addr::LOCALHOST),
        Port::new(echo_port),
    );
    let header = RequestHeader::new(VERSION, Command::Tcp, dest, security);

    let sealed_header = client_session
        .encode_request_header(&header, &cmd_key)
        .expect("encode header");
    client.write_all(&sealed_header).await.unwrap();

    // 读响应头（客户端收到后才能开始 body 流）
    let _resp = client_session
        .decode_response_header_async(&mut client)
        .await
        .expect("decode response header");

    // 发请求 body
    client_session
        .encode_request_body_async(&header, PAYLOAD, &mut client)
        .await
        .expect("encode request body");

    // 读响应 body，验证 echo 回环
    let response = client_session
        .decode_response_body_async(&header, &mut client)
        .await
        .expect("decode response body");
    assert_eq!(
        response, PAYLOAD,
        "echo 回环失败 ({security:?}): 收到 {response:?}, 期望 {PAYLOAD:?}"
    );
}

/// AES-128-GCM 加密端到端测试。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vmess_e2e_aes128gcm() {
    run_vmess_e2e(SecurityType::Aes128Gcm).await;
}

/// ChaCha20-Poly1305 加密端到端测试。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vmess_e2e_chacha20poly1305() {
    run_vmess_e2e(SecurityType::Chacha20Poly1305).await;
}

/// 无效用户认证测试：validator 中不存在的 UUID，server 应关闭连接。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vmess_rejects_unknown_user() {
    let ohm = make_ohm();
    let validator = Arc::new(TimedUserValidator::new()); // 空 validator
    let vmess_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let vmess_addr = vmess_listener.local_addr().unwrap();
    let ohm_clone = Arc::clone(&ohm);
    let validator_clone = Arc::clone(&validator);
    tokio::spawn(async move {
        let _ = serve_vmess(vmess_listener, ohm_clone, validator_clone, None).await;
    });

    // client 用未注册的随机 UUID
    let unknown_uuid = UUID::new();
    let cmd_key = cmd_key_of(&unknown_uuid);
    let mut client = tokio::net::TcpStream::connect(vmess_addr)
        .await
        .unwrap();

    let client_session = ClientSession::new();
    let dest = Destination::tcp(
        Address::ipv4(std::net::Ipv4Addr::LOCALHOST),
        Port::new(80),
    );
    let header = RequestHeader::new(VERSION, Command::Tcp, dest, SecurityType::Aes128Gcm);
    let sealed_header = client_session
        .encode_request_header(&header, &cmd_key)
        .expect("encode header");
    client.write_all(&sealed_header).await.unwrap();

    // server 因 UserNotFound 关闭 → client 读响应得到 EOF 或 reset
    let mut buf = [0u8; 16];
    let result = client.read(&mut buf).await;
    match result {
        Ok(0) => {}
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionAborted => {}
        other => panic!("期望 EOF 或连接重置，得到 {other:?}"),
    }
}

/// 大负载测试：发送较大数据块验证 chunk 分片正确性。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vmess_e2e_aes128gcm_large_payload() {
    // 构造 16 KiB 负载（跨多个 VMess chunk）
    let large_payload: Vec<u8> = (0..16384).map(|i| (i % 256) as u8).collect();

    let echo_port = spawn_echo_server().await;
    let ohm = make_ohm();
    let (validator, cmd_key) = make_validator();
    let vmess_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let vmess_addr = vmess_listener.local_addr().unwrap();
    let ohm_clone = Arc::clone(&ohm);
    let validator_clone = Arc::clone(&validator);
    tokio::spawn(async move {
        let _ = serve_vmess(vmess_listener, ohm_clone, validator_clone, None).await;
    });

    let mut client = tokio::net::TcpStream::connect(vmess_addr)
        .await
        .unwrap();
    let client_session = ClientSession::new();
    let dest = Destination::tcp(
        Address::ipv4(std::net::Ipv4Addr::LOCALHOST),
        Port::new(echo_port),
    );
    let header = RequestHeader::new(VERSION, Command::Tcp, dest, SecurityType::Aes128Gcm);

    let sealed_header = client_session
        .encode_request_header(&header, &cmd_key)
        .expect("encode header");
    client.write_all(&sealed_header).await.unwrap();

    let _resp = client_session
        .decode_response_header_async(&mut client)
        .await
        .expect("decode response header");

    client_session
        .encode_request_body_async(&header, &large_payload, &mut client)
        .await
        .expect("encode request body");

    let response = client_session
        .decode_response_body_async(&header, &mut client)
        .await
        .expect("decode response body");
    assert_eq!(
        response, large_payload,
        "大负载 echo 回环失败: 收到 {} 字节, 期望 {} 字节",
        response.len(),
        large_payload.len()
    );
}
