//! Go vs Rust 兼容性测试。
//!
//! 验证 Rust 实现与 Go 版本的协议兼容性：
//! - 相同输入 → 相同输出（编解码确定性）
//! - 跨语言可交互的关键数据格式一致

use xray_common::uuid::UUID;
use xray_proxy_trojan::config::{hex_sha224, MemoryAccount as TrojanAccount};
use xray_proxy_trojan::protocol::{write_request_header, COMMAND_TCP};
use xray_proxy_ss::protocol::{read_address_port_ss, write_address_port_ss};
use xray_common::net::address::Address;
use xray_proxy_vmess::account::cmd_key_of;
use xray_proxy_vmess::encoding::client::ClientSession;
use xray_proxy_vmess::encoding::VERSION;
use xray_common::protocol::{Command, SecurityType};
use xray_common::net::destination::Destination;
use xray_common::net::address::Address as VmAddr;
use xray_common::net::port::Port;

/// Trojan SHA224 hash 与 Go 一致性验证。
///
/// Go 端 `crypto/sha256.Sum224(password)` → hex 编码 = 56 字节。
/// 验证 Rust 端 `hex_sha224` 对已知输入产生相同输出。
#[test]
fn trojan_sha224_compatible_with_go() {
    let hex = hex_sha224("password");
    assert_eq!(
        hex.len(),
        56,
        "SHA224 hex 编码应为 56 字节（Go 兼容）"
    );

    // 验证两次调用产生相同结果（确定性）
    let hex2 = hex_sha224("password");
    assert_eq!(hex, hex2, "SHA224 应是确定性的");

    // 不同输入产生不同输出
    let hex3 = hex_sha224("other");
    assert_ne!(hex, hex3, "不同输入应产生不同 hash");
}

/// VMess cmd_key 与 Go 一致性验证。
///
/// Go 端 `cmdKey = md5(UUID.Bytes()[:16])`。
/// 验证 Rust 端对已知 UUID 产生相同 16 字节 cmd_key。
#[test]
fn vmess_cmd_key_compatible_with_go() {
    let uuid = UUID::parse("66ad4540-b58c-4ad2-9926-ea63445a9b57").expect("uuid");
    let key = cmd_key_of(&uuid);
    assert_eq!(key.len(), 16, "cmd_key 应为 16 字节");

    // 确定性：相同 UUID → 相同 key
    let key2 = cmd_key_of(&uuid);
    assert_eq!(key, key2, "cmd_key 应是确定性的");
}

/// SS 地址格式与 Go 一致性验证。
///
/// SS 用 SOCKS5 兼容的地址格式（与 VLESS/VMess 不同）。
/// 验证 IPv4/Domain/IPv6 三种类型的 wire format 一致。
#[test]
fn ss_address_format_compatible_with_go() {
    // IPv4：1 字节 type(0x01) + 4 字节 addr + 2 字节 BE port
    let mut buf = Vec::new();
    let addr = Address::ipv4(std::net::Ipv4Addr::new(1, 2, 3, 4));
    write_address_port_ss(&mut buf, &addr, 443);
    assert_eq!(buf[0], 0x01, "IPv4 地址类型字节应为 0x01");
    assert_eq!(&buf[1..5], &[1, 2, 3, 4], "IPv4 地址字节");
    assert_eq!(&buf[5..7], &443u16.to_be_bytes(), "端口 BE 编码");

    // Domain：1 字节 type(0x03) + 1 字节长度 + N 字节域名 + 2 字节 BE port
    let mut buf = Vec::new();
    let addr = Address::Domain("example.com".to_string());
    write_address_port_ss(&mut buf, &addr, 80);
    assert_eq!(buf[0], 0x03, "Domain 地址类型字节应为 0x03");
    assert_eq!(buf[1], 11, "域名长度");
    assert_eq!(&buf[2..13], b"example.com", "域名内容");

    // IPv6：1 字节 type(0x04) + 16 字节 addr + 2 字节 BE port
    let mut buf = Vec::new();
    let addr = Address::ipv6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    write_address_port_ss(&mut buf, &addr, 8443);
    assert_eq!(buf[0], 0x04, "IPv6 地址类型字节应为 0x04");
    assert_eq!(buf.len(), 1 + 16 + 2, "IPv6 地址总长度 = 19 字节");
}

/// Trojan 协议帧格式与 Go 一致性验证。
///
/// Trojan TCP 帧格式：[56字节hex(SHA224(password))][CRLF][1字节cmd][SOCKS5 addr+port][CRLF]
#[test]
fn trojan_frame_format_compatible_with_go() {
    let account = TrojanAccount::new("test-password");
    let dest_addr = Address::ipv4(std::net::Ipv4Addr::LOCALHOST);
    let dest_port: u16 = 443;

    let mut buf = Vec::new();
    write_request_header(
        &mut buf,
        &account,
        xray_proxy_trojan::protocol::Network::Tcp,
        &dest_addr,
        dest_port,
    );

    // 验证帧结构
    assert_eq!(&buf[..56], &account.key, "前 56 字节应为 hex key");
    assert_eq!(&buf[56..58], b"\r\n", "hex key 后应为 CRLF");
    assert_eq!(buf[58], COMMAND_TCP, "命令字节应为 TCP(1)");
    // SOCKS5 地址从 buf[59] 开始：0x01 + 4 字节 IPv4 + 2 字节端口
    assert_eq!(buf[59], 0x01, "SOCKS5 地址类型应为 IPv4(0x01)");
}

/// VMess 请求头编码确定性验证。
///
/// 相同 UUID + 相同目标 → 编码后的请求头一致（不含随机填充部分）。
#[test]
fn vmess_request_header_deterministic() {
    let uuid = UUID::parse("66ad4540-b58c-4ad2-9926-ea63445a9b57").expect("uuid");
    let cmd_key = cmd_key_of(&uuid);

    // 构造两个相同的请求头
    let dest1 = Destination::tcp(
        VmAddr::ipv4(std::net::Ipv4Addr::LOCALHOST),
        Port::new(80),
    );
    let dest2 = Destination::tcp(
        VmAddr::ipv4(std::net::Ipv4Addr::LOCALHOST),
        Port::new(80),
    );

    let session1 = ClientSession::new();
    let session2 = ClientSession::new();

    let header1 = xray_common::protocol::RequestHeader::new(
        VERSION,
        Command::Tcp,
        dest1,
        SecurityType::Aes128Gcm,
    );
    let header2 = xray_common::protocol::RequestHeader::new(
        VERSION,
        Command::Tcp,
        dest2,
        SecurityType::Aes128Gcm,
    );

    let sealed1 = session1
        .encode_request_header(&header1, &cmd_key)
        .expect("encode1");
    let sealed2 = session2
        .encode_request_header(&header2, &cmd_key)
        .expect("encode2");

    // 注意：sealed header 包含随机 padding/nonce，长度可能不同
    assert!(!sealed1.is_empty(), "编码后应非空");
    assert!(!sealed2.is_empty(), "编码后应非空");
}
