//! VLESS 协议 Rust-only 端到端集成测试。
//!
//! 验证 VLESS 完整代理链路（inbound → freedom outbound → echo server）。
//!
//! 测试模式：
//! 1. 启动 echo server（回环）
//! 2. 启动 VLESS inbound（serve_vless + freedom outbound）
//! 3. VLESS client 连接 → encode header → decode response → 验证 echo 回环

use std::sync::Arc;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use xray_app_dispatcher::{
    DispatchHandler,
    default::{DialBridge, SimpleOhm},
};
use xray_common::{net::address::Address, protocol::ID, uuid::UUID};
use xray_proxy_freedom::make_freedom_dial_fn;
use xray_proxy_vless::{
    account::MemoryAccount,
    encoding::{
        VERSION, VlessCommand,
        client::{decode_response_header, encode_request_header},
        empty_addons,
    },
    serve_vless,
    validator::{MemoryUser, MemoryValidator, Validator},
};

/// 固定 UUID。
const SAMPLE_UUID_STR: &str = "a3482e88-686a-4a58-8126-99c9214826d7";

/// 测试负载。
const PAYLOAD: &[u8] = b"hello vless integration test!";

/// 构造含已注册用户的 validator。
fn make_validator() -> (Arc<MemoryValidator>, UUID) {
    let uuid = UUID::parse(SAMPLE_UUID_STR).expect("uuid");
    let account = MemoryAccount {
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
    let user = MemoryUser::new("alice@example.com", 0, account);
    let v = MemoryValidator::new();
    v.add(user).expect("add user");
    (Arc::new(v), uuid)
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
                },
            }
        }
    });
    port
}

/// VLESS 端到端测试核心：client → serve_vless → freedom → echo。
async fn run_vless_e2e() {
    // 1. echo server
    let echo_port = spawn_echo_server().await;

    // 2. dispatcher: freedom outbound → SimpleOhm default
    let ohm = make_ohm();

    // 3. validator + serve_vless（监听随机端口）
    let (validator, uuid) = make_validator();
    let vless_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let vless_addr = vless_listener.local_addr().unwrap();
    let ohm_clone = Arc::clone(&ohm);
    let validator_clone = Arc::clone(&validator);
    tokio::spawn(async move {
        let listener = xray_transport::system_listener::InboundTcpListener::from_tokio(
            vless_listener,
            xray_transport::sockopt::SocketOptions::default(),
        );
        let _ = serve_vless(listener, ohm_clone, validator_clone, None, None, None).await;
    });

    // 4. VLESS client：connect → encode header → decode response → echo round-trip
    let mut client = tokio::net::TcpStream::connect(vless_addr).await.unwrap();

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
    .expect("encode header");

    // 读响应头
    let _resp_addons =
        decode_response_header(&mut client, VERSION).await.expect("decode response header");

    // 发 payload
    client.write_all(PAYLOAD).await.unwrap();

    // 读 echo 回环
    let mut buf = vec![0u8; PAYLOAD.len() + 16];
    let n = client.read(&mut buf).await.expect("read response");
    assert_eq!(&buf[..n], PAYLOAD, "echo 回环失败: 收到 {:?}, 期望 {:?}", &buf[..n], PAYLOAD);
}

/// VLESS TCP 端到端测试。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vless_e2e_tcp() {
    run_vless_e2e().await;
}

/// 无效用户认证测试：validator 中不存在的 UUID，server 应关闭连接。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vless_rejects_unknown_user() {
    let ohm = make_ohm();
    let validator = Arc::new(MemoryValidator::new()); // 空 validator
    let vless_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let vless_addr = vless_listener.local_addr().unwrap();
    let ohm_clone = Arc::clone(&ohm);
    let validator_clone = Arc::clone(&validator);
    tokio::spawn(async move {
        let listener = xray_transport::system_listener::InboundTcpListener::from_tokio(
            vless_listener,
            xray_transport::sockopt::SocketOptions::default(),
        );
        let _ = serve_vless(listener, ohm_clone, validator_clone, None, None, None).await;
    });

    // client 用未注册的随机 UUID
    let unknown_uuid = UUID::new();
    let mut client = tokio::net::TcpStream::connect(vless_addr).await.unwrap();

    let addons = empty_addons();
    encode_request_header(
        &mut client,
        VERSION,
        &unknown_uuid,
        VlessCommand::Tcp,
        Some(&Address::ipv4(std::net::Ipv4Addr::LOCALHOST)),
        Some(80),
        &addons,
    )
    .await
    .expect("encode header");

    // server 因用户不存在关闭连接 → client 读响应得到 EOF 或 reset
    let mut buf = [0u8; 16];
    let result = client.read(&mut buf).await;
    match result {
        Ok(0) => {},
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {},
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionAborted => {},
        other => panic!("期望 EOF 或连接重置，得到 {other:?}"),
    }
}
