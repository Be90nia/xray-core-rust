//! VMess 客户端 ↔ 服务端完整 roundtrip E2E 测试。
//!
//! 流程：
//! 1. 客户端 encode_request_header + encode_request_body → 字节流
//! 2. 服务端 decode_request_header + decode_request_body → 验证字段一致
//! 3. 服务端 encode_response_header + encode_response_body → 字节流
//! 4. 客户端 decode_response_header + decode_response_body → 验证 payload 一致
//!
//! 不接真实 TCP（ponytail: TCP IO 留 follow-up），用 `Vec<u8>` 双工模拟。

use xray_common::bitmask::Bitmask;
use xray_common::net::address::Address;
use xray_common::net::destination::Destination;
use xray_common::net::port::Port;
use xray_common::protocol::{Command, RequestHeader, ResponseHeader, SecurityType};
use xray_common::uuid::UUID;

use xray_proxy_vmess::account::MemoryAccount;
use xray_proxy_vmess::encoding::client::ClientSession;
use xray_proxy_vmess::encoding::server::{ServerSession, SessionHistory};
use xray_proxy_vmess::validator::{MemoryUser, TimedUserValidator, Validator};

fn sample_uuid() -> UUID {
    UUID::parse("66ad4540-b58c-4ad2-9926-ea63445a9b57").expect("uuid")
}

fn sample_destination() -> Destination {
    Destination::tcp(Address::ipv4(std::net::Ipv4Addr::new(1, 2, 3, 4)), Port::new(8080))
}

fn sample_request_header() -> RequestHeader {
    RequestHeader::new(
        xray_proxy_vmess::encoding::VERSION,
        Command::Tcp,
        sample_destination(),
        SecurityType::Aes128Gcm,
    )
}

fn make_validator_with_user() -> TimedUserValidator {
    let v = TimedUserValidator::new();
    let account = MemoryAccount::new(sample_uuid());
    let user = MemoryUser::new("alice@example.com", account);
    v.add(user).expect("add");
    v
}

#[test]
fn full_roundtrip_request_response_cycle() {
    let validator = make_validator_with_user();
    let history = SessionHistory::new();

    // ===== 客户端：encode_request_header + encode_request_body =====
    let client = ClientSession::new();
    let cmd_key = xray_proxy_vmess::account::cmd_key_of(&sample_uuid());

    let request_header = sample_request_header();
    let request_payload = b"hello vmess server, this is client request body payload";

    let mut client_to_server: Vec<u8> = Vec::new();
    let sealed_header = client
        .encode_request_header(&request_header, &cmd_key)
        .expect("encode_request_header");
    client_to_server.extend_from_slice(&sealed_header);
    client
        .encode_request_body(&request_header, request_payload, &mut client_to_server)
        .expect("encode_request_body");

    // ===== 服务端：decode_request_header + decode_request_body =====
    let mut server = ServerSession::new(&validator, &history);
    let mut reader = &client_to_server[..];

    let (decoded_req_header, matched_user) = server
        .decode_request_header(&mut reader)
        .expect("decode_request_header");
    assert_eq!(decoded_req_header.command, Command::Tcp);
    assert_eq!(decoded_req_header.security, SecurityType::Aes128Gcm);
    assert_eq!(matched_user.email, "alice@example.com");
    // server 的 request_body_key/iv 应已从 header 填充，与 client 一致
    assert_eq!(server.request_body_key, client.request_body_key);
    assert_eq!(server.request_body_iv, client.request_body_iv);
    assert_eq!(server.response_header, client.response_header);

    let decoded_req_body = server
        .decode_request_body(&decoded_req_header, &mut reader)
        .expect("decode_request_body");
    assert_eq!(decoded_req_body, request_payload);

    // ===== 服务端：encode_response_header + encode_response_body =====
    let response_header = ResponseHeader {
        command: Command::Tcp,
        option: Bitmask::new(0),
    };
    let response_payload = b"hello client, this is server response body payload";

    let mut server_to_client: Vec<u8> = Vec::new();
    server
        .encode_response_header(&response_header, &mut server_to_client)
        .expect("encode_response_header");
    server
        .encode_response_body(&decoded_req_header, response_payload, &mut server_to_client)
        .expect("encode_response_body");

    // ===== 客户端：decode_response_header + decode_response_body =====
    let mut client_reader = &server_to_client[..];
    let decoded_resp_header = client
        .decode_response_header(&mut client_reader)
        .expect("decode_response_header");
    assert_eq!(decoded_resp_header.option.bits(), 0);

    let decoded_resp_body = client
        .decode_response_body(&request_header, &mut client_reader)
        .expect("decode_response_body");
    assert_eq!(decoded_resp_body, response_payload);
}

#[test]
fn full_roundtrip_large_body_multi_chunk() {
    let validator = make_validator_with_user();
    let history = SessionHistory::new();

    let client = ClientSession::new();
    let cmd_key = xray_proxy_vmess::account::cmd_key_of(&sample_uuid());
    let request_header = sample_request_header();

    // 大 payload：触发多 chunk（payload_chunk_size ≈ 8110）
    let request_payload: Vec<u8> = (0..50_000).map(|i| (i % 251) as u8).collect();

    let mut client_to_server: Vec<u8> = Vec::new();
    let sealed_header = client
        .encode_request_header(&request_header, &cmd_key)
        .expect("encode_request_header");
    client_to_server.extend_from_slice(&sealed_header);
    client
        .encode_request_body(&request_header, &request_payload, &mut client_to_server)
        .expect("encode_request_body");

    let mut server = ServerSession::new(&validator, &history);
    let mut reader = &client_to_server[..];

    let (decoded_req_header, _user) = server
        .decode_request_header(&mut reader)
        .expect("decode_request_header");
    let decoded_req_body = server
        .decode_request_body(&decoded_req_header, &mut reader)
        .expect("decode_request_body");
    assert_eq!(decoded_req_body.len(), request_payload.len());
    assert_eq!(decoded_req_body, request_payload);
}

#[test]
fn full_roundtrip_empty_body() {
    let validator = make_validator_with_user();
    let history = SessionHistory::new();

    let client = ClientSession::new();
    let cmd_key = xray_proxy_vmess::account::cmd_key_of(&sample_uuid());
    let request_header = sample_request_header();

    let mut client_to_server: Vec<u8> = Vec::new();
    let sealed_header = client
        .encode_request_header(&request_header, &cmd_key)
        .expect("encode_request_header");
    client_to_server.extend_from_slice(&sealed_header);
    // 空 body（只写终止 chunk）
    client
        .encode_request_body(&request_header, b"", &mut client_to_server)
        .expect("encode_request_body");

    let mut server = ServerSession::new(&validator, &history);
    let mut reader = &client_to_server[..];

    let (decoded_req_header, _) = server
        .decode_request_header(&mut reader)
        .expect("decode_request_header");
    let decoded_req_body = server
        .decode_request_body(&decoded_req_header, &mut reader)
        .expect("decode_request_body");
    assert!(decoded_req_body.is_empty());
}

#[test]
fn replay_same_request_header_fails() {
    let validator = make_validator_with_user();
    let history = SessionHistory::new();

    let client = ClientSession::new();
    let cmd_key = xray_proxy_vmess::account::cmd_key_of(&sample_uuid());
    let request_header = sample_request_header();

    let sealed = client
        .encode_request_header(&request_header, &cmd_key)
        .expect("encode_request_header");

    // 第一次 decode 成功
    let mut server1 = ServerSession::new(&validator, &history);
    let mut reader1 = &sealed[..];
    server1
        .decode_request_header(&mut reader1)
        .expect("first decode ok");

    // 第二次重放应失败（SessionHistory 反重放）
    let mut server2 = ServerSession::new(&validator, &history);
    let mut reader2 = &sealed[..];
    let err = server2
        .decode_request_header(&mut reader2)
        .unwrap_err();
    assert!(
        matches!(err, xray_proxy_vmess::error::VmessError::Replay | xray_proxy_vmess::error::VmessError::DuplicateSession),
        "expected replay error, got {err:?}"
    );
}

#[test]
fn decode_request_body_wrong_key_fails() {
    let validator = make_validator_with_user();
    let history = SessionHistory::new();

    let client = ClientSession::new();
    let cmd_key = xray_proxy_vmess::account::cmd_key_of(&sample_uuid());
    let request_header = sample_request_header();

    let mut client_to_server: Vec<u8> = Vec::new();
    let sealed_header = client
        .encode_request_header(&request_header, &cmd_key)
        .expect("encode_request_header");
    client_to_server.extend_from_slice(&sealed_header);
    client
        .encode_request_body(&request_header, b"secret payload", &mut client_to_server)
        .expect("encode_request_body");

    let mut server = ServerSession::new(&validator, &history);
    let mut reader = &client_to_server[..];

    let (decoded_req_header, _) = server
        .decode_request_header(&mut reader)
        .expect("decode_request_header");

    // 故意篡改 server 的 body key
    server.request_body_key = [0xFFu8; 16];

    let err = server
        .decode_request_body(&decoded_req_header, &mut reader)
        .unwrap_err();
    assert!(
        matches!(err, xray_proxy_vmess::error::VmessError::Io(_)),
        "expected IO error (auth failed), got {err:?}"
    );
}

#[test]
fn full_roundtrip_chacha20poly1305() {
    // 验证 ChaCha20-Poly1305 security 完整 client↔server round-trip
    // （不同于默认 Aes128Gcm，ChaCha20 用 generate_chacha20poly1305_key 派生 32B key）
    let validator = make_validator_with_user();
    let history = SessionHistory::new();

    let client = ClientSession::new();
    let cmd_key = xray_proxy_vmess::account::cmd_key_of(&sample_uuid());

    let request_header = RequestHeader::new(
        xray_proxy_vmess::encoding::VERSION,
        Command::Tcp,
        sample_destination(),
        SecurityType::Chacha20Poly1305,
    );
    let request_payload = b"chacha20poly1305 security round-trip payload";

    let mut client_to_server: Vec<u8> = Vec::new();
    let sealed_header = client
        .encode_request_header(&request_header, &cmd_key)
        .expect("encode_request_header");
    client_to_server.extend_from_slice(&sealed_header);
    client
        .encode_request_body(&request_header, request_payload, &mut client_to_server)
        .expect("encode_request_body");

    let mut server = ServerSession::new(&validator, &history);
    let mut reader = &client_to_server[..];

    let (decoded_req_header, _user) = server
        .decode_request_header(&mut reader)
        .expect("decode_request_header");
    assert_eq!(decoded_req_header.security, SecurityType::Chacha20Poly1305);

    let decoded_req_body = server
        .decode_request_body(&decoded_req_header, &mut reader)
        .expect("decode_request_body");
    assert_eq!(decoded_req_body, request_payload);

    // 响应同样走 ChaCha20
    let response_header = ResponseHeader {
        command: Command::Tcp,
        option: Bitmask::new(0),
    };
    let response_payload = b"chacha20 server response";
    let mut server_to_client: Vec<u8> = Vec::new();
    server
        .encode_response_header(&response_header, &mut server_to_client)
        .expect("encode_response_header");
    server
        .encode_response_body(&decoded_req_header, response_payload, &mut server_to_client)
        .expect("encode_response_body");

    let mut client_reader = &server_to_client[..];
    let _ = client
        .decode_response_header(&mut client_reader)
        .expect("decode_response_header");
    let decoded_resp_body = client
        .decode_response_body(&request_header, &mut client_reader)
        .expect("decode_response_body");
    assert_eq!(decoded_resp_body, response_payload);
}

#[test]
fn full_roundtrip_chunk_masking() {
    // 验证 ChunkMasking option（ShakeSizeParser）完整 client↔server round-trip
    let validator = make_validator_with_user();
    let history = SessionHistory::new();

    let client = ClientSession::new();
    let cmd_key = xray_proxy_vmess::account::cmd_key_of(&sample_uuid());

    let mut request_header = sample_request_header();
    request_header
        .option
        .set(xray_proxy_vmess::request_option::CHUNK_MASKING);
    let request_payload = b"chunk masking enabled shake size parser payload";

    let mut client_to_server: Vec<u8> = Vec::new();
    let sealed_header = client
        .encode_request_header(&request_header, &cmd_key)
        .expect("encode_request_header");
    client_to_server.extend_from_slice(&sealed_header);
    client
        .encode_request_body(&request_header, request_payload, &mut client_to_server)
        .expect("encode_request_body");

    let mut server = ServerSession::new(&validator, &history);
    let mut reader = &client_to_server[..];

    let (decoded_req_header, _user) = server
        .decode_request_header(&mut reader)
        .expect("decode_request_header");
    assert!(decoded_req_header
        .option
        .has(xray_proxy_vmess::request_option::CHUNK_MASKING));
    let decoded_req_body = server
        .decode_request_body(&decoded_req_header, &mut reader)
        .expect("decode_request_body");
    assert_eq!(decoded_req_body, request_payload);

    // 响应同样走 ChunkMasking（encode_response_body 检查 request.option）
    let response_header = ResponseHeader {
        command: Command::Tcp,
        option: Bitmask::new(0),
    };
    let response_payload = b"chunk masking server response";
    let mut server_to_client: Vec<u8> = Vec::new();
    server
        .encode_response_header(&response_header, &mut server_to_client)
        .expect("encode_response_header");
    server
        .encode_response_body(&decoded_req_header, response_payload, &mut server_to_client)
        .expect("encode_response_body");

    let mut client_reader = &server_to_client[..];
    let _ = client
        .decode_response_header(&mut client_reader)
        .expect("decode_response_header");
    let decoded_resp_body = client
        .decode_response_body(&request_header, &mut client_reader)
        .expect("decode_response_body");
    assert_eq!(decoded_resp_body, response_payload);
}
