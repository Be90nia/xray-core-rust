//! Trojan 协议 Rust-only 端到端集成测试。
//!
//! 验证 Trojan 服务端握手（trojan_server_handshake）正确解析请求头。
//! Trojan 的 server 端只做握手验证，不做数据转发（切片2 限制），
//! 因此测试验证：client 构造请求头 → server 解析 → 验证字段一致。

use std::sync::Arc;

use tokio::{io::AsyncWriteExt as _, net::TcpListener};
use xray_common::net::address::Address;
use xray_proxy_trojan::{
    config::MemoryAccount,
    protocol::{CRLF, write_request_header},
    server::trojan_server_handshake,
    validator::{MemoryUser, Validator},
};

/// 测试密码。
const PASSWORD: &str = "test-password-123";

/// 构造含已注册用户的 validator。
fn make_validator() -> (Arc<Validator>, MemoryAccount) {
    let account = MemoryAccount::new(PASSWORD);
    let user = MemoryUser::new("alice@example.com", 0, account.clone());
    let v = Validator::new();
    v.add(user).expect("add user");
    (Arc::new(v), account)
}

/// Trojan 握手测试：client 构造请求头 → server 解析 → 验证字段。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trojan_handshake_succeeds() {
    let (validator, account) = make_validator();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // server task：accept → trojan_server_handshake
    let validator_clone = Arc::clone(&validator);
    let server_handle = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        trojan_server_handshake(&mut sock, &validator_clone, std::time::Duration::from_secs(30))
            .await
    });

    // client task：connect → write_request_header
    let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();

    let dest_addr = Address::ipv4(std::net::Ipv4Addr::LOCALHOST);
    let dest_port: u16 = 8080;

    let mut header_buf = Vec::new();
    let _unused = write_request_header(
        &mut header_buf,
        &account,
        xray_proxy_trojan::protocol::Network::Tcp,
        &dest_addr,
        dest_port,
    );

    client.write_all(&header_buf).await.unwrap();
    client.flush().await.unwrap();

    // 等待 server 完成
    let result = server_handle.await.expect("server task").expect("handshake");
    let (network, parsed_addr, parsed_port, user) = result;

    // 验证解析结果
    assert_eq!(network, xray_proxy_trojan::protocol::Network::Tcp);
    assert_eq!(parsed_addr, dest_addr);
    assert_eq!(parsed_port, dest_port);
    assert_eq!(user.email, "alice@example.com");
}

/// 无效用户测试：validator 中不存在的密码 hash，server 应拒绝。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trojan_rejects_unknown_user() {
    let validator = Arc::new(Validator::new()); // 空 validator
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let validator_clone = Arc::clone(&validator);
    let server_handle = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        trojan_server_handshake(&mut sock, &validator_clone, std::time::Duration::from_secs(30))
            .await
    });

    // client 用未注册的密码
    let fake_account = MemoryAccount::new("wrong-password");
    let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();

    let dest_addr = Address::ipv4(std::net::Ipv4Addr::LOCALHOST);
    let mut header_buf = Vec::new();
    let _unused = write_request_header(
        &mut header_buf,
        &fake_account,
        xray_proxy_trojan::protocol::Network::Tcp,
        &dest_addr,
        80,
    );

    client.write_all(&header_buf).await.unwrap();
    client.flush().await.unwrap();

    // server 应返回错误
    let result = server_handle.await.expect("server task");
    assert!(result.is_err(), "期望握手失败，但成功了");
}

/// CRLF 格式验证：Trojan 协议要求 hex key 后紧跟 CRLF。
#[test]
fn trojan_protocol_crlf_format() {
    // 验证 CRLF 常量正确
    assert_eq!(CRLF, [b'\r', b'\n']);

    // 验证 MemoryAccount key 长度 = 56 字节（SHA224 hex 编码）
    let account = MemoryAccount::new("test");
    assert_eq!(account.key.len(), 56, "SHA224 hex 编码应为 56 字节");
}
