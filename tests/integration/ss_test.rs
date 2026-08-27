//! Shadowsocks 协议 Rust-only 端到端集成测试。
//!
//! 验证 SS client → server 的完整链路：
//! client 写 IV + 加密首帧(addr+port) + 加密 body →
//! server read_request 解析 → read_chunk 读 body → 验证数据一致。

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use xray_common::net::address::Address;
use xray_proxy_ss::client::Client;
use xray_proxy_ss::config::{CipherType, MemoryAccount};
use xray_proxy_ss::protocol::write_address_port_ss;
use xray_proxy_ss::server::read_request;
use xray_proxy_ss::validator::{MemoryUser, Validator};
use xray_proto::xray::proxy::shadowsocks::Account as ProtoAccount;

/// 测试密码。
const PASSWORD: &str = "test-ss-password";

/// 测试负载。
const PAYLOAD: &[u8] = b"hello ss integration test!";

/// 用 CipherType 构造 account。
fn make_account(ct: CipherType) -> MemoryAccount {
    let p = ProtoAccount {
        password: PASSWORD.to_string(),
        cipher_type: ct.as_i32(),
        iv_check: false,
    };
    MemoryAccount::from_proto(&p).expect("account")
}

/// SS 端到端测试核心：client dial_target → server read_request → 验证 addr + body。
async fn run_ss_e2e(ct: CipherType) {
    let account = make_account(ct);

    // server 监听
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_port = listener.local_addr().unwrap().port();

    // server task：accept → read_request → read body
    let account_clone = account.clone();
    let server_handle = tokio::spawn(async move {
        let (conn, _) = listener.accept().await.unwrap();
        let (header, mut ss_stream) = read_request(conn, &account_clone, "alice", 0)
            .await
            .expect("read_request");

        // 读 body chunk
        let body = ss_stream.read_chunk().await.expect("read_chunk").expect("chunk data");
        (header, body)
    });

    // client：dial_target → write body
    let client = Client::new(account, "127.0.0.1".to_string(), server_port);
    let target_addr = Address::ipv4(std::net::Ipv4Addr::new(1, 2, 3, 4));
    let target_port: u16 = 5678;
    let mut ss_stream = client
        .dial_target(&target_addr, target_port)
        .await
        .expect("dial_target");

    ss_stream
        .write_chunk(PAYLOAD)
        .await
        .expect("write_chunk");
    ss_stream.flush().await.expect("flush");

    // 关闭写端
    ss_stream.shutdown().await.ok();

    // 等待 server 完成
    let (header, body) = server_handle.await.expect("server task");

    // 验证请求头
    assert_eq!(header.address, target_addr, "地址不匹配");
    assert_eq!(header.port, target_port, "端口不匹配");

    // 验证 body
    assert_eq!(body.as_slice(), PAYLOAD, "body 不匹配");
}

/// AES-128-GCM 端到端测试。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ss_e2e_aes128gcm() {
    run_ss_e2e(CipherType::Aes128Gcm).await;
}

/// ChaCha20-Poly1305 端到端测试。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ss_e2e_chacha20poly1305() {
    run_ss_e2e(CipherType::ChaCha20Poly1305).await;
}

/// AES-256-GCM 端到端测试。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ss_e2e_aes256gcm() {
    run_ss_e2e(CipherType::Aes256Gcm).await;
}

/// 地址格式验证：IPv4/IPv6/Domain 三种地址类型 roundtrip。
#[test]
fn ss_address_format_roundtrip() {
    // IPv4
    let mut buf = Vec::new();
    let addr = Address::ipv4(std::net::Ipv4Addr::new(192, 168, 1, 1));
    write_address_port_ss(&mut buf, &addr, 443);
    let (parsed_addr, parsed_port, consumed) =
        xray_proxy_ss::protocol::read_address_port_ss(&buf).expect("parse ipv4");
    assert_eq!(parsed_addr, addr);
    assert_eq!(parsed_port, 443);
    assert_eq!(consumed, buf.len());

    // Domain
    let mut buf = Vec::new();
    let addr = Address::Domain("example.com".to_string());
    write_address_port_ss(&mut buf, &addr, 8080);
    let (parsed_addr, parsed_port, consumed) =
        xray_proxy_ss::protocol::read_address_port_ss(&buf).expect("parse domain");
    assert_eq!(parsed_addr, addr);
    assert_eq!(parsed_port, 8080);
    assert_eq!(consumed, buf.len());

    // IPv6
    let mut buf = Vec::new();
    let addr = Address::ipv6(std::net::Ipv6Addr::LOCALHOST);
    write_address_port_ss(&mut buf, &addr, 9090);
    let (parsed_addr, parsed_port, consumed) =
        xray_proxy_ss::protocol::read_address_port_ss(&buf).expect("parse ipv6");
    assert_eq!(parsed_addr, addr);
    assert_eq!(parsed_port, 9090);
    assert_eq!(consumed, buf.len());
}
