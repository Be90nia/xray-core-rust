//! E2E: VMess proxy → freedom outbound（dial_system）→ echo target
//!
//! 验证 VMess 协议完整链路（AES-128-GCM security + Plain size parser）：
//! 客户端 encode_request_header + encode_request_body →
//! 服务端 decode_request_header_async + encode_response_header_async + decode_request_body_async →
//! dial_system 到 echo → encode_response_body_async →
//! 客户端 decode_response_header_async + decode_response_body_async 验证 echo 回环。
//!
//! 与 `body_roundtrip.rs` 的区别：body_roundtrip 用 `Vec<u8>` 模拟双工；
//! 本测试用真实 TcpStream，并经 freedom outbound（dial_system）转发到独立 echo server。
//!
//! 实现注记：VMess 编解码内部使用 `Box<dyn AeadCipher>`（非 Send），
//! 不能跨 `tokio::spawn` 边界；server/client 在同一 task 内用 `tokio::join!` 并发。

use std::sync::Arc;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use xray_common::{
    bitmask::Bitmask,
    net::{address::Address, destination::Destination, network::Network, port::Port},
    protocol::{Command, RequestHeader, ResponseCommand, ResponseHeader, SecurityType},
    uuid::UUID,
};
use xray_proxy_vmess::{
    account::{MemoryAccount, cmd_key_of},
    encoding::{
        client::ClientSession,
        server::{ServerSession, SessionHistory},
    },
    validator::{MemoryUser, TimedUserValidator, Validator},
};
use xray_transport::{sockopt::SocketOptions, system_dialer::dial_system};

/// 固定 UUID（与 body_roundtrip.rs 一致），避免每次运行随机化导致反重放状态污染。
fn sample_uuid() -> UUID {
    UUID::parse("66ad4540-b58c-4ad2-9926-ea63445a9b57").expect("uuid")
}

/// VMess → freedom → echo 端到端验证（AES-128-GCM body）。
///
/// 流程：
/// 1. echo server（独立 task）：tokio::io::copy 双工回环
/// 2. server 逻辑（同 task，与 client 并发 via tokio::join!）：
///    - decode_request_header_async 拿到目标地址
///    - encode_response_header_async 发响应头
///    - dial_system 经 freedom outbound 连到 echo
///    - decode_request_body_async 解密 body 明文
///    - 明文转发到 echo，读回 echo 响应
///    - encode_response_body_async 加密发回客户端
/// 3. VMess 客户端：encode_request_header（sync→Vec<u8>）+ encode_request_body（sync→Vec<u8>）→
///    一次性写入 TcpStream；decode_response_*_async 验证回环
#[tokio::test]
async fn vmess_proxy_to_echo_target_e2e() {
    // ===== 1. echo 目标服务器 =====
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let echo_addr = echo_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (sock, _) = echo_listener.accept().await.expect("echo accept");
        let (mut rd, mut wr) = tokio::io::split(sock);
        // 简单回环：读到什么写回什么
        let _ = tokio::io::copy(&mut rd, &mut wr).await;
    });

    // ===== 2. UUID + validator =====
    let uuid = sample_uuid();
    // cmd_key 必须在 uuid 移交给 MemoryAccount 前计算（两者都需 uuid）
    let cmd_key = cmd_key_of(&uuid);
    let validator = TimedUserValidator::new();
    let account = MemoryAccount::new(uuid);
    validator.add(MemoryUser::new("alice@example.com", account)).expect("add user");

    // ===== 3. proxy listener =====
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let validator_arc = Arc::new(validator);
    let history_arc = Arc::new(SessionHistory::new());
    let validator_for_server = Arc::clone(&validator_arc);
    let history_for_server = Arc::clone(&history_arc);

    // 共享：server 解密 body 后写入这里，client 侧断言用
    let payload_sent: &'static [u8] = b"hello vmess e2e!";
    let expected_echo: Vec<u8> = payload_sent.to_vec();

    // ===== 4. server 与 client 并发（同 task，tokio::join! 不要求 Send） =====
    let server_future = async {
        let (mut client_stream, _) = proxy_listener.accept().await.expect("proxy accept");

        let mut server = ServerSession::new(&validator_for_server, &history_for_server);

        // 解码 VMess 请求头（含 AuthID + AEAD 解密 + 反重放）
        let (req_header, _user) = server
            .decode_request_header_async(&mut client_stream)
            .await
            .expect("decode request header");

        // 发送 VMess 响应头（客户端必须收到才能开始 body 流）
        let resp_header = ResponseHeader {
            command: Command::Tcp,
            option: Bitmask::new(0),
            response_command: ResponseCommand::None,
        };
        server
            .encode_response_header_async(&resp_header, &mut client_stream)
            .await
            .expect("encode response header");

        // 经 freedom outbound（dial_system）拨号到目标
        let addr = req_header.destination.address().clone();
        let port = req_header.destination.port().value();
        let dest = Destination::new(addr, Port::new(port), Network::TCP);
        let mut target =
            dial_system(&dest, &SocketOptions::default()).await.expect("dial echo target");

        // 解密请求 body（含 terminator chunk，返回纯明文 payload）
        let plain_body = server
            .decode_request_body_async(&req_header, &mut client_stream)
            .await
            .expect("decode request body");

        // 明文转发到 echo
        target.write_all(&plain_body).await.expect("forward to echo");
        // 读回 echo 响应
        let mut echoed = vec![0u8; plain_body.len()];
        target.read_exact(&mut echoed).await.expect("read echo back");

        // 加密发回客户端
        server
            .encode_response_body_async(&req_header, &echoed, &mut client_stream)
            .await
            .expect("encode response body");
        client_stream.flush().await.expect("flush client");

        // 显式 drop 关闭写端，让客户端读到 EOF
        drop(client_stream);
        drop(target);
        echoed
    };

    let client_future = async {
        let mut client = TcpStream::connect(proxy_addr).await.expect("connect proxy");
        let client_session = ClientSession::new();

        let echo_v4 = match echo_addr.ip() {
            std::net::IpAddr::V4(v4) => v4,
            _ => panic!("expected IPv4 echo addr"),
        };

        let request_header = RequestHeader::new(
            xray_proxy_vmess::encoding::VERSION,
            Command::Tcp,
            Destination::new(Address::IPv4(echo_v4), Port::new(echo_addr.port()), Network::TCP),
            SecurityType::Aes128Gcm,
        );

        // encode_request_header（sync）→ Vec<u8> → 写入 TcpStream
        let sealed_header = client_session
            .encode_request_header(&request_header, &cmd_key)
            .expect("encode request header");
        client.write_all(&sealed_header).await.expect("write header");

        // encode_request_body（sync）→ Vec<u8>（含 payload chunk + terminator chunk）→ 写入
        let mut body_buf: Vec<u8> = Vec::new();
        client_session
            .encode_request_body(&request_header, payload_sent, &mut body_buf)
            .expect("encode request body");
        client.write_all(&body_buf).await.expect("write body");
        client.flush().await.expect("flush body");

        // 解码响应头（占位，校验完整性）
        let _resp_header = client_session
            .decode_response_header_async(&mut client)
            .await
            .expect("decode response header");

        // 解码响应 body，验证 echo 回环
        client_session
            .decode_response_body_async(&request_header, &mut client)
            .await
            .expect("decode response body")
    };

    // 并发跑 server 和 client（current-thread runtime + join! 不需要 Send）
    let (server_echoed, client_resp) = tokio::join!(server_future, client_future);

    assert_eq!(
        &client_resp[..],
        &expected_echo[..],
        "client: echo should match sent data through vmess→freedom→echo"
    );
    assert_eq!(&server_echoed[..], &expected_echo[..], "server: echoed payload should match sent");
}

/// 5iy：生产路径多 chunk nonce 状态机验证。
///
/// make_vmess_dial_fn（VmessConn pump_up/pump_down，nonce 跨 chunk 持久）→
/// serve_vmess（pump_request_body/pump_response_body，同状态机）→ freedom → echo。
/// 20KB 强制 ≥3 chunk 双向；若任何一侧 nonce 重置，AEAD open 必失败/数据错乱。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vmess_multichunk_production_roundtrip_e2e() {
    use xray_app_dispatcher::default::{DialBridge, SimpleOhm};
    use xray_proxy_vmess::{
        dispatcher::{VmessOutboundConfig, make_vmess_dial_fn},
        inbound::server::serve_vmess,
    };

    // echo server
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let echo_port = echo_listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = echo_listener.accept().await else { break };
            tokio::spawn(async move {
                let (mut rd, mut wr) = tokio::io::split(sock);
                let _ = tokio::io::copy(&mut rd, &mut wr).await;
            });
        }
    });

    // serve_vmess + freedom ohm
    let ohm = Arc::new(SimpleOhm::new());
    let bridge = Arc::new(DialBridge::new("freedom", xray_proxy_freedom::make_freedom_dial_fn()))
        as Arc<dyn xray_app_dispatcher::DispatchHandler>;
    ohm.set_default(bridge);

    let uuid = sample_uuid();
    let validator = Arc::new(TimedUserValidator::new());
    validator
        .add(MemoryUser::new("alice@example.com", MemoryAccount::new(uuid)))
        .expect("add user");
    let vmess_listener = xray_transport::system_listener::InboundTcpListener::bind(
        "127.0.0.1:0",
        SocketOptions::default(),
    )
    .await
    .expect("bind vmess");
    let vmess_addr = vmess_listener.local_addr().unwrap();
    let ohm2 = Arc::clone(&ohm);
    let validator2 = Arc::clone(&validator);
    tokio::spawn(async move {
        // sm80④：测试装配传短握手超时（与 serve_vmess 其他测试用例一致）。
        let _ =
            serve_vmess(vmess_listener, ohm2, validator2, None, std::time::Duration::from_secs(10))
                .await;
    });

    // 生产 outbound：make_vmess_dial_fn → VmessConn
    let cfg = Arc::new(VmessOutboundConfig::new(
        sample_uuid(),
        Address::from_ipv4_bytes([127, 0, 0, 1]),
        Port::new(vmess_addr.port()),
    ));
    let dial = make_vmess_dial_fn(cfg);
    let dest = Destination::new(
        Address::from_ipv4_bytes([127, 0, 0, 1]),
        Port::new(echo_port),
        Network::TCP,
    );
    let mut conn = dial(&dest).await.expect("vmess dial");

    // 20KB 分 3 次写（2×8192 + 3616）：多 chunk up + 多 chunk down
    let payload: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
    for part in payload.chunks(8192) {
        conn.write_all(part).await.expect("write part");
    }
    // 读回全部 echo
    let mut received = Vec::new();
    let mut rbuf = [0u8; 8192];
    while received.len() < payload.len() {
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), conn.read(&mut rbuf))
            .await
            .expect("read timeout")
            .expect("read");
        if n == 0 {
            break;
        }
        received.extend_from_slice(&rbuf[..n]);
    }
    assert_eq!(received.len(), payload.len(), "echo size mismatch");
    assert_eq!(received, payload, "multi-chunk nonce continuity broken");
}
