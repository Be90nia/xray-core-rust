//! E2E: Shadowsocks proxy → echo target
//!
//! 验证 SS 协议完整链路（AES-128-GCM AEAD chunk 流）：
//! 客户端 Client::dial_target（写 IV + 首帧 addr+port）→
//! 服务端 server::read_request（读 IV + 解密首帧 → SSStream）→
//! SSStream.read_chunk 解密 body → 转发到 echo → 读 echo 回响 → SSStream.write_chunk 加密发回 →
//! 客户端 SSStream.read_chunk 验证 echo 回环。
//!
//! 不依赖 xray_transport（SS crate 未引入），用裸 TcpStream 直接拨号到 echo，
//! 等价于 freedom outbound 对 IP 目标的行为。

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use xray_common::net::address::Address;
use xray_proto::xray::proxy::shadowsocks::Account as ProtoAccount;
use xray_proxy_ss::{
    client::Client,
    config::{CipherType, MemoryAccount},
    server::read_request,
};

/// 构造 SS 账户（AES-128-GCM cipher + 派生 key）。
fn make_account(ct: CipherType, password: &str) -> MemoryAccount {
    let p =
        ProtoAccount { password: password.to_string(), cipher_type: ct.as_i32(), iv_check: false };
    MemoryAccount::from_proto(&p).expect("account")
}

/// SS → echo 端到端验证（AES-128-GCM AEAD chunk）。
///
/// 流程：
/// 1. echo server（独立 task）：tokio::io::copy 双工回环
/// 2. proxy server（独立 task）：
///    - read_request 读 IV + 解密首帧 → 得到 SSStream + RequestHeader（addr+port）
///    - SSStream.read_chunk 解密 body 明文
///    - 裸 TcpStream::connect 拨号到 echo（等价于 freedom outbound 对 IP 目标）
///    - 明文转发到 echo，读回 echo 响应
///    - SSStream.write_chunk 加密发回客户端
/// 3. SS 客户端：Client::dial_target（写 IV + 首帧 addr+port）→ write_chunk(payload) → read_chunk
///    验证回环
#[tokio::test]
async fn ss_proxy_to_echo_target_e2e() {
    // ===== 1. echo 目标服务器 =====
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let echo_addr = echo_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (sock, _) = echo_listener.accept().await.expect("echo accept");
        let (mut rd, mut wr) = tokio::io::split(sock);
        let _ = tokio::io::copy(&mut rd, &mut wr).await;
    });

    // ===== 2. 账户配置 =====
    let account = make_account(CipherType::Aes128Gcm, "ss-e2e-password");

    // ===== 3. SS proxy server =====
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let server_account = account.clone();
    let server_handle = tokio::spawn(async move {
        let (conn, _) = proxy_listener.accept().await.expect("proxy accept");

        // 读 IV + 解密首帧（addr+port）→ 返回 SSStream（继续 read_chunk 读 body）
        let (header, mut ss_stream) =
            read_request(conn, &server_account, "u@x.com", 0).await.expect("read_request");

        // 读 body chunk（已解密的明文 payload）
        let body = ss_stream.read_chunk().await.expect("read body chunk").expect("non-empty body");

        // 拨号到 echo（裸 TcpStream，等价 freedom outbound 对 IP 目标）
        let target_socket_addr = match &header.address {
            Address::IPv4(v4) => std::net::SocketAddr::new(std::net::IpAddr::V4(*v4), header.port),
            Address::IPv6(v6) => std::net::SocketAddr::new(std::net::IpAddr::V6(*v6), header.port),
            other => panic!("expected IP echo target, got {other:?}"),
        };
        let mut echo_conn = TcpStream::connect(target_socket_addr).await.expect("connect echo");

        // 明文转发到 echo
        echo_conn.write_all(&body).await.expect("forward to echo");
        echo_conn.flush().await.expect("flush to echo");

        // 读回 echo 响应（长度 = body 长度）
        let mut echoed = vec![0u8; body.len()];
        echo_conn.read_exact(&mut echoed).await.expect("read echo back");

        // 加密写回客户端（一个 chunk）
        ss_stream.write_chunk(&echoed).await.expect("write response chunk");
        ss_stream.flush().await.expect("flush response");

        // 显式 drop 让客户端读到 EOF
        drop(ss_stream);
        drop(echo_conn);
        echoed
    });

    // ===== 4. SS 客户端 =====
    let client = Client::new(account, "127.0.0.1".to_string(), proxy_addr.port());

    let echo_v4 = match echo_addr.ip() {
        std::net::IpAddr::V4(v4) => v4,
        _ => panic!("expected IPv4 echo addr"),
    };

    // dial_target 完成：TCP connect + 写 IV + 写首帧（addr+port）
    let mut stream =
        client.dial_target(&Address::IPv4(echo_v4), echo_addr.port()).await.expect("dial_target");

    // 写 body chunk
    let payload = b"hello ss e2e!";
    stream.write_chunk(payload).await.expect("write body chunk");
    stream.flush().await.expect("flush body");

    // 读 echo 回响 chunk
    let resp = stream.read_chunk().await.expect("read response chunk").expect("non-empty response");

    assert_eq!(&resp[..], payload, "echo should match sent data through ss→echo");

    // 等待 server task 收尾，确保无 panic
    let server_echoed = server_handle.await.expect("server task join");
    assert_eq!(&server_echoed[..], payload, "server side echo should match");
}
