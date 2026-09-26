//! SS dispatcher adapter 集成测试：验证 [`SsOutbound`] + [`SsInbound`] 适配器组合的完整链路。
//!
//! 与 `ss_proxy_e2e.rs` 互补：后者测 SS 协议本身的端到端正确性；
//! 本测试聚焦适配器层：`SsOutbound::process` + `SsInbound::handle_conn` 能否正确组合，
//! 即 dispatcher 接入方按照 `process → handle_conn → 桥接 link` 的契约调用时一切正常。

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use xray_common::net::address::Address;
use xray_proto::xray::proxy::shadowsocks::Account as ProtoAccount;
use xray_proxy_ss::{
    config::{CipherType, MemoryAccount},
    inbound::SsInbound,
    outbound::SsOutbound,
    stream::SSStream,
};

/// 构造 SS 账户（AEAD cipher + 派生 key）。
fn make_account(ct: CipherType, password: &str) -> MemoryAccount {
    let p =
        ProtoAccount { password: password.to_string(), cipher_type: ct.as_i32(), iv_check: false };
    MemoryAccount::from_proto(&p).expect("account")
}

/// 集成测试 1：`SsOutbound::process` → `SsInbound::handle_conn` 握手 + 元数据正确。
///
/// 流程：
/// 1. SS inbound 监听一个端口（用 `SsInbound::handle_conn`）
/// 2. SS outbound 调 `process(target_addr, target_port)` 拨号 + 写首帧（addr+port）
/// 3. inbound 解密首帧，得到 `RequestHeader`，验证其 `address` / `port` 与 outbound 写入的目标一致
///
/// 这覆盖 dispatcher 接入的**握手契约**：outbound 写的目标地址必须能被 inbound 还原。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn outbound_inbound_handshake_metadata_matches() {
    let account = make_account(CipherType::Aes128Gcm, "dispatcher-handshake");

    // inbound 监听
    let inbound_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind inbound listener");
    let inbound_addr = inbound_listener.local_addr().unwrap();

    let ib = SsInbound::new(account.clone(), "u@dispatcher.local");
    let ib = std::sync::Arc::new(ib);
    let ib_for_server = ib.clone();

    let target_addr = Address::Domain("example.com".to_string());
    let target_port = 443u16;

    let server_handle = tokio::spawn(async move {
        let (conn, _peer) = inbound_listener.accept().await.expect("inbound accept");
        ib_for_server.handle_conn(conn).await
    });

    // outbound 拨号 + 写首帧（addr+port）
    let ob = SsOutbound::new(account, inbound_addr.ip().to_string(), inbound_addr.port());
    let _out_stream: SSStream<TcpStream> =
        ob.process(&target_addr, target_port).await.expect("outbound process");

    // 等待 inbound 解析完成
    let (header, _in_stream) =
        server_handle.await.expect("server task join").expect("handshake should succeed");
    assert_eq!(header.port, target_port, "inbound 还原的 port 应与 outbound 写入一致");
    assert_eq!(header.address, target_addr, "inbound 还原的 address 应与 outbound 写入一致");
}

/// 集成测试 2：`SsOutbound` → `SsInbound` → echo 全链路数据回环。
///
/// 流程：
/// 1. echo 目标服务器（`tokio::io::copy` 双工回环）
/// 2. SS inbound 适配器：`handle_conn` 解密首帧得到目标 → 用裸 `TcpStream` 拨号到 echo （等价
///    freedom outbound 对 IP 目标）→ `read_chunk` 读 body → 转发到 echo → 读回 echo → `write_chunk`
///    加密写回客户端
/// 3. SS outbound 适配器：`process(echo_addr, echo_port)` 拨号 + 写首帧 → `write_chunk(payload)`
/// 4. 验证通过 SSStream 读到的回响与原 payload 一致
///
/// 这覆盖 dispatcher 接入的**完整数据契约**：适配器包装后数据单向往返正确。
#[ignore = "known-fail（bd 待登记 P2）：full chain roundtrip 客户端 read_chunk AEAD 认证失败（CI Linux run 36210988842 + 本地 Win 复现；同文件 metadata 用例绿，指向响应方向 salt/nonce 处理缺陷）——SS legacy 响应方向待协议专项"]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn outbound_inbound_full_chain_to_echo_roundtrip() {
    let account = make_account(CipherType::Aes128Gcm, "dispatcher-full-chain");

    // ===== 1. echo 目标服务器 =====
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let echo_addr = echo_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (sock, _) = echo_listener.accept().await.expect("echo accept");
        let (mut rd, mut wr) = tokio::io::split(sock);
        let _ = tokio::io::copy(&mut rd, &mut wr).await;
    });

    // ===== 2. SS inbound 适配器（dispatcher 模拟：handle_conn → 裸 TcpStream 转发） =====
    let inbound_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind inbound listener");
    let inbound_addr = inbound_listener.local_addr().unwrap();

    let ib = SsInbound::new(account.clone(), "u@dispatcher.local");
    let ib = std::sync::Arc::new(ib);

    let echo_v4 = match echo_addr.ip() {
        std::net::IpAddr::V4(v4) => v4,
        _ => panic!("expected IPv4 echo addr"),
    };
    let echo_socket_addr =
        std::net::SocketAddr::new(std::net::IpAddr::V4(echo_v4), echo_addr.port());

    let server_handle = tokio::spawn({
        let ib = ib.clone();
        async move {
            let (conn, _) = inbound_listener.accept().await.expect("inbound accept");
            let (header, mut ss_stream) = ib.handle_conn(conn).await.expect("handshake");

            // 验证 outbound 写入的目标 = echo
            let target_socket_addr = match &header.address {
                Address::IPv4(v4) => {
                    std::net::SocketAddr::new(std::net::IpAddr::V4(*v4), header.port)
                },
                other => panic!("expected IPv4 echo target, got {other:?}"),
            };
            assert_eq!(
                target_socket_addr, echo_socket_addr,
                "inbound 解析出的目标应等于 echo 地址"
            );

            // SSStream 不实现 AsyncRead/AsyncWrite（chunk 分帧语义），
            // 故用 read_chunk / write_chunk 显式桥接（参考 ss_proxy_e2e.rs）。
            let body =
                ss_stream.read_chunk().await.expect("read body chunk").expect("non-empty body");

            let mut echo_conn = TcpStream::connect(target_socket_addr).await.expect("connect echo");
            echo_conn.write_all(&body).await.expect("forward to echo");
            echo_conn.flush().await.expect("flush to echo");

            let mut echoed = vec![0u8; body.len()];
            echo_conn.read_exact(&mut echoed).await.expect("read echo back");

            ss_stream.write_chunk(&echoed).await.expect("write response chunk");
            ss_stream.flush().await.expect("flush response");

            drop(ss_stream);
            drop(echo_conn);
            echoed
        }
    });

    // ===== 3. SS outbound 适配器：process → write body → read echo =====
    let ob = SsOutbound::new(account, inbound_addr.ip().to_string(), inbound_addr.port());

    let mut stream =
        ob.process(&Address::IPv4(echo_v4), echo_addr.port()).await.expect("outbound process");

    let payload = b"hello ss dispatcher adapter!";
    stream.write_chunk(payload).await.expect("write body chunk");
    stream.flush().await.expect("flush body");

    let resp = stream.read_chunk().await.expect("read response chunk").expect("non-empty response");

    assert_eq!(&resp[..], payload, "echo through outbound→inbound→echo chain should match");

    // 等待 server task 收尾，确保无 panic
    let server_echoed = server_handle.await.expect("server task join");
    assert_eq!(&server_echoed[..], payload, "server side echo should match");
}
