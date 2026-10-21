//! Shadowsocks 协议 Rust-only 端到端集成测试。
//!
//! 验证 SS client → server 的完整链路：
//! client 写 IV + 加密首帧(addr+port) + 加密 body →
//! server read_request 解析 → read_chunk 读 body → 验证数据一致。

use tokio::net::TcpListener;
use xray_common::net::address::Address;
use xray_proto::xray::proxy::shadowsocks::Account as ProtoAccount;
use xray_proxy_ss::{
    client::Client,
    config::{CipherType, MemoryAccount},
    protocol::write_address_port_ss,
    server::read_request,
};

/// 测试密码。
const PASSWORD: &str = "test-ss-password";

/// 测试负载。
const PAYLOAD: &[u8] = b"hello ss integration test!";

/// 用 CipherType 构造 account。
fn make_account(ct: CipherType) -> MemoryAccount {
    let p =
        ProtoAccount { password: PASSWORD.to_string(), cipher_type: ct.as_i32(), iv_check: false };
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
        let (header, mut ss_stream) =
            read_request(conn, &account_clone, "alice", 0).await.expect("read_request");

        // 读 body chunk
        let body = ss_stream.read_chunk().await.expect("read_chunk").expect("chunk data");
        (header, body)
    });

    // client：dial_target → write body
    let client = Client::new(account, "127.0.0.1".to_string(), server_port);
    let target_addr = Address::ipv4(std::net::Ipv4Addr::new(1, 2, 3, 4));
    let target_port: u16 = 5678;
    let mut ss_stream = client.dial_target(&target_addr, target_port).await.expect("dial_target");

    ss_stream.write_chunk(PAYLOAD).await.expect("write_chunk");
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

// ============================================================================
// SS-2022（SIP022）TCP e2e
// 对应 Go `testing/scenarios/shadowsocks_2022_test.go`：
// ss2022Methods = {2022-blake3-aes-128-gcm, 2022-blake3-aes-256-gcm,
// 2022-blake3-chacha20-poly1305} × testShadowsocks2022Tcp。
// aes-256-gcm 已有 crate 级 e2e（ss2022/client.rs::tcp_roundtrip），
// 此处补齐 aes-128-gcm 与 chacha20-poly1305 两方法。
// ============================================================================

use std::sync::Arc;

use base64::Engine as _;
use tokio::net::UdpSocket;
use xray_proxy_ss::{
    Client2022, Ss2022Inbound, Validator,
    protocol::{decode_udp_packet, encode_udp_packet},
    validator::MemoryUser,
};

/// 生成 SS-2022 随机 PSK 并 base64 编码（对应 Go 测试 `rand.Read(password)` +
/// `base64.StdEncoding.EncodeToString`；PSK 长度 = cipher key 长度）。
fn random_psk_b64(len: usize) -> String {
    let psk: Vec<u8> = (0..len).map(|_| rand::random::<u8>()).collect();
    base64::engine::general_purpose::STANDARD.encode(psk)
}

/// SS-2022 TCP 端到端核心：Client2022.dial_target → Ss2022Inbound.handle_conn
/// → 验证目标 addr/port/用户 + body 一致。
async fn run_ss2022_tcp_e2e(method: &'static str, psk_len: usize) {
    let psk_b64 = random_psk_b64(psk_len);
    let inbound = Arc::new(Ss2022Inbound::new(method, &psk_b64, "alice").expect("inbound"));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_port = listener.local_addr().unwrap().port();

    // server task：accept → 解析 header → 读 body chunk
    let server_handle = tokio::spawn(async move {
        let (conn, _) = listener.accept().await.unwrap();
        let mut result = inbound.handle_conn(conn).await.expect("handle_conn");
        let body = result.stream.read_chunk().await.expect("read_chunk").expect("chunk data");
        (result.address, result.port, result.user_email, body)
    });

    // client：拨号到目标（ATYP=domain），写 body 后关闭
    let client = Client2022::new(method, &[psk_b64], "127.0.0.1", server_port).expect("client");
    let mut stream = client.dial_target("1.2.3.4", 5678).await.expect("dial_target");
    stream.write_chunk(PAYLOAD).await.expect("write_chunk");
    stream.flush().await.expect("flush");
    stream.shutdown().await.ok();

    let (address, port, email, body) = server_handle.await.expect("server task");
    // dial_target 以 ATYP=3（domain）编码目标："1.2.3.4" 作为域名上线路径
    assert_eq!(address, Address::Domain("1.2.3.4".to_string()), "地址不匹配");
    assert_eq!(port, 5678, "端口不匹配");
    assert_eq!(email, "alice", "用户不匹配");
    assert_eq!(body.as_slice(), PAYLOAD, "body 不匹配");
}

/// SS-2022 `2022-blake3-aes-128-gcm` TCP 端到端（16B PSK，Go shadowsocks_2022_test.go:44 子用例）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ss2022_e2e_tcp_aes128gcm() {
    run_ss2022_tcp_e2e("2022-blake3-aes-128-gcm", 16).await;
}

/// SS-2022 `2022-blake3-chacha20-poly1305` TCP 端到端（32B PSK，Go shadowsocks_2022_test.go:56
/// 子用例）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ss2022_e2e_tcp_chacha20poly1305() {
    run_ss2022_tcp_e2e("2022-blake3-chacha20-poly1305", 32).await;
}

// ============================================================================
// SS UDP e2e（非 2022）
// 对应 Go `testing/scenarios/shadowsocks_test.go`：
// TestShadowsocksAES128GCMUDP（:200）/ TestShadowsocksAES256GCMUDP（:294）。
// wire 对称：请求与回包同格式（IV + AEAD(addr+port+payload)），
// client/server 各自用 EncodeUDPPacket / DecodeUDPPacket 处理两个方向。
// ============================================================================

/// UDP 回包负载（模拟 relay 目标返回的数据）。
const UDP_RESPONSE: &[u8] = b"ss udp echo response";

/// SS UDP 端到端核心：client encode → 真实 UDP socket → server decode →
/// encode 回包 → client decode，验证目标 addr/port 与双向 payload。
async fn run_ss_udp_e2e(ct: CipherType) {
    let account = make_account(ct);

    // server 侧 validator：注册同一 account（AEAD zero-nonce Open 匹配用户）
    let server_validator = Validator::new();
    server_validator.add(MemoryUser::new("bob", account.clone())).expect("add user");
    let client_account = account.clone();

    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server.local_addr().unwrap();
    let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // server task：收包 → 解码 → 以目标地址为回包头编码响应（relay 语义）
    let server_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        let (n, from) = server.recv_from(&mut buf).await.expect("server recv");
        let (header, payload) =
            decode_udp_packet(&server_validator, &buf[..n]).expect("server decode");
        let resp = encode_udp_packet(&account, &header.address, header.port, UDP_RESPONSE)
            .expect("server encode");
        server.send_to(&resp, from).await.expect("server send");
        (header.address, header.port, payload)
    });

    // client：编码请求包 → 发送 → 收回包 → 解码
    let target_addr = Address::ipv4(std::net::Ipv4Addr::new(8, 8, 8, 8));
    let target_port: u16 = 53;
    let packet = encode_udp_packet(&client_account, &target_addr, target_port, PAYLOAD)
        .expect("client encode");
    client_sock.send_to(&packet, server_addr).await.expect("client send");

    // client 侧解码同 wire 格式的回包（对称 AEAD，SS UDP 请求/响应同构）
    let client_validator = Validator::new();
    client_validator.add(MemoryUser::new("alice", client_account.clone())).expect("add user");
    let mut rbuf = vec![0u8; 65535];
    let (n, _) =
        tokio::time::timeout(std::time::Duration::from_secs(10), client_sock.recv_from(&mut rbuf))
            .await
            .expect("recv timeout")
            .expect("client recv");
    let (resp_header, resp_payload) =
        decode_udp_packet(&client_validator, &rbuf[..n]).expect("client decode");

    // server 侧视角：目标地址/端口/payload 与编码一致
    let (seen_addr, seen_port, seen_payload) = server_task.await.expect("server task");
    assert_eq!(seen_addr, target_addr, "server 解码目标地址不匹配");
    assert_eq!(seen_port, target_port, "server 解码目标端口不匹配");
    assert_eq!(seen_payload.as_slice(), PAYLOAD, "server 解码 payload 不匹配");

    // client 侧视角：回包头 = 目标地址，payload = relay 响应
    assert_eq!(resp_header.address, target_addr, "回包地址应为目标地址");
    assert_eq!(resp_header.port, target_port, "回包端口应为目标端口");
    assert_eq!(resp_payload, UDP_RESPONSE, "回包 payload 不匹配");
}

/// SS `aes-128-gcm` UDP 端到端（Go shadowsocks_test.go:200 AES128GCMUDP 对应）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ss_e2e_udp_aes128gcm() {
    run_ss_udp_e2e(CipherType::Aes128Gcm).await;
}

/// SS `aes-256-gcm` UDP 端到端（Go shadowsocks_test.go:294 AES256GCMUDP 对应）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ss_e2e_udp_aes256gcm() {
    run_ss_udp_e2e(CipherType::Aes256Gcm).await;
}
