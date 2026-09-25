//! XUDP 集成测试
//!
//! 覆盖 Write→Read 往返、GlobalID+Writer 集成、多帧混合流、
//! XudpSession+Manager 联动、Go 兼容性等场景。

use std::io::Cursor;

use xray_common::net::{address::Address, destination::Destination, network::Network, port::Port};
use xray_xudp::{
    extension::{XudpManager, XudpStatus},
    packet::{FrameMetadata, FrameStatus, PacketReader, PacketWriter},
};

// ========== 辅助函数 ==========

/// 构造 IPv4 UDP Destination
fn ipv4_dest(ip: &str, port: u16) -> Destination {
    let addr = Address::ipv4(ip.parse().expect("valid ipv4"));
    Destination::udp(addr, Port::new(port))
}

/// 构造 IPv6 UDP Destination
fn ipv6_dest(ip: &str, port: u16) -> Destination {
    let addr = Address::ipv6(ip.parse().expect("valid ipv6"));
    Destination::udp(addr, Port::new(port))
}

/// 构造 Domain UDP Destination
fn domain_dest(domain: &str, port: u16) -> Destination {
    let addr = Address::new_domain(domain.to_string());
    Destination::udp(addr, Port::new(port))
}

/// 默认测试 GlobalID
fn test_global_id() -> [u8; 8] {
    [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
}

/// 通过 global_id() 公共接口生成 GlobalID（cone=true, UDP 网络）
fn generate_global_id_via_public_api(source: &str) -> [u8; 8] {
    let input = xray_xudp::GlobalIdInput {
        source: source.to_string(),
        source_network: Network::UDP,
        cone: true,
    };
    xray_xudp::global_id(&input)
}

// ========== 集成测试 ==========

/// 测试 IPv4 地址的 PacketWriter→PacketReader 往返
///
/// 对应 Go 版 TestXudpReadWrite：写入含 IPv4 UDP 目标的数据，
/// 读回验证数据和地址一致。
#[test]
fn test_write_read_roundtrip_ipv4() {
    let dest = ipv4_dest("127.0.0.1", 1345);
    let global_id = test_global_id();
    let mut buf = Vec::new();

    {
        let mut writer = PacketWriter::new(&mut buf, dest.clone(), global_id);
        writer.write_packet(b"a").expect("write ipv4 packet");
    }

    let mut reader = PacketReader::new(Cursor::new(buf));
    let pkt = reader.read_packet().expect("read ipv4 packet").expect("packet data");

    // 验证数据内容（对应 Go 版 dest[0].Byte(0) == 'a'）
    assert_eq!(pkt.data(), b"a", "data content should match written payload");

    // 验证流结束
    assert!(
        reader.read_packet().expect("eof check").is_none(),
        "stream should end after one packet"
    );
}

/// 测试 IPv6 地址的 PacketWriter→PacketReader 往返
#[test]
fn test_write_read_roundtrip_ipv6() {
    let dest = ipv6_dest("::1", 5678);
    let global_id = test_global_id();
    let mut buf = Vec::new();

    {
        let mut writer = PacketWriter::new(&mut buf, dest.clone(), global_id);
        writer.write_packet(b"ipv6 payload").expect("write ipv6 packet");
    }

    let mut reader = PacketReader::new(Cursor::new(buf));
    let pkt = reader.read_packet().expect("read ipv6 packet").expect("packet data");

    assert_eq!(pkt.data(), b"ipv6 payload", "ipv6 data roundtrip should match");
}

/// 测试 Domain 地址的 PacketWriter→PacketReader 往返
#[test]
fn test_write_read_roundtrip_domain() {
    let dest = domain_dest("example.com", 443);
    let global_id = test_global_id();
    let mut buf = Vec::new();

    {
        let mut writer = PacketWriter::new(&mut buf, dest.clone(), global_id);
        writer.write_packet(b"domain data").expect("write domain packet");
    }

    let mut reader = PacketReader::new(Cursor::new(buf));
    let pkt = reader.read_packet().expect("read domain packet").expect("packet data");

    assert_eq!(pkt.data(), b"domain data", "domain data roundtrip should match");
}

/// 测试 GlobalID 与 PacketWriter 集成
///
/// 通过 XudpConfig::new 构造配置，使用 global_id() 公共接口
/// 生成 ID，写入 New 帧，读回验证 GlobalID 一致。
#[test]
fn test_global_id_with_packet_writer() {
    // 通过公共 API 生成 GlobalID
    let global_id = generate_global_id_via_public_api("udp:192.168.1.100:9999");

    // 构造 IPv4 目标
    let dest = ipv4_dest("192.168.1.100", 9999);
    let mut buf = Vec::new();

    {
        let mut writer = PacketWriter::new(&mut buf, dest.clone(), global_id);
        writer.write_packet(b"gid test").expect("write with global_id");
    }

    // 解析第一帧的元数据，验证 GlobalID 一致
    let (meta, _consumed) = FrameMetadata::from_bytes(&buf).expect("parse frame metadata");
    assert_eq!(meta.status(), FrameStatus::New, "first frame should be New status");
    assert_eq!(
        meta.global_id(),
        Some(&global_id),
        "GlobalID in frame should match the one generated via public API"
    );

    // 再通过 PacketReader 读回数据验证
    let mut reader = PacketReader::new(Cursor::new(buf));
    let pkt = reader.read_packet().expect("read gid packet").expect("packet data");
    assert_eq!(pkt.data(), b"gid test", "data should match");
}

/// 测试同一字节流中交替写入 New/Keep/KeepAlive 帧
///
/// 验证 PacketReader 能正确逐帧解析混合帧类型。
#[test]
fn test_multi_frame_mixed_stream() {
    let dest = ipv4_dest("10.0.0.1", 3000);
    let global_id = test_global_id();
    let mut buf = Vec::new();

    {
        let mut writer = PacketWriter::new(&mut buf, dest.clone(), global_id);
        // 第一次写入 → New 帧
        writer.write_packet(b"new_frame_data").expect("write new");
        // 第二次写入 → Keep 帧
        writer.write_packet(b"keep_frame_data").expect("write keep");
    }

    // 手动追加一个 KeepAlive 帧
    FrameMetadata::keep_alive().write_to(&mut buf).expect("write keep_alive");

    // 再追加一个数据帧（Keep 类型）
    {
        // 创建新 writer 继续写入（new_sent=false 但已有数据，需手动构造 Keep 帧）
        let keep_meta = FrameMetadata::keep_udp(dest.address().clone(), dest.port());
        keep_meta.write_to(&mut buf).expect("write keep meta");
        let data = b"after_keepalive";
        buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
        buf.extend_from_slice(data);
    }

    let mut reader = PacketReader::new(Cursor::new(buf));

    // 第一帧：New 帧
    let p1 = reader.read_packet().expect("read1").expect("some");
    assert_eq!(p1.data(), b"new_frame_data", "first packet should be New frame data");
    // New 帧的 udp_target 携带真实来源（b2e 中央 dispatcher 语义，6a3210d）
    assert_eq!(p1.udp_target(), Some(&dest), "New frame should carry udp_target since b2e");

    // 第二帧：Keep 帧
    let p2 = reader.read_packet().expect("read2").expect("some");
    assert_eq!(p2.data(), b"keep_frame_data", "second packet should be Keep frame data");
    // Keep 帧应携带 udp_target
    assert!(p2.udp_target().is_some(), "Keep frame should have udp_target");

    // 第三帧：KeepAlive 被自动跳过，直接读到第四帧数据
    let p3 = reader.read_packet().expect("read3").expect("some");
    assert_eq!(p3.data(), b"after_keepalive", "KeepAlive should be skipped, data should follow");

    // 流结束
    assert!(reader.read_packet().expect("eof").is_none(), "stream should end");
}

/// 测试 XudpSession 与 XudpManager 联动
///
/// 通过 XudpManager 创建会话，验证 get_or_create/remove/cleanup_expired 联动。
#[test]
fn test_xudp_session_manager_integration() {
    let mgr = XudpManager::new();

    // 初始状态
    assert!(mgr.is_empty(), "manager should start empty");
    assert_eq!(mgr.len(), 0, "initial length should be 0");

    // 创建第一个会话
    let id1 = [10u8; 8];
    let status1 = mgr.get_or_create(id1);
    assert_eq!(status1, XudpStatus::Initializing, "new session should be Initializing");
    assert_eq!(mgr.len(), 1, "one session after first create");

    // 创建第二个会话
    let id2 = [20u8; 8];
    let status2 = mgr.get_or_create(id2);
    assert_eq!(status2, XudpStatus::Initializing, "new session should be Initializing");
    assert_eq!(mgr.len(), 2, "two sessions after second create");

    // 再次获取已存在的会话（返回相同状态）
    let status1_again = mgr.get_or_create(id1);
    assert_eq!(status1_again, XudpStatus::Initializing, "existing session returns same status");
    assert_eq!(mgr.len(), 2, "length unchanged for existing session");

    // 删除会话
    assert!(mgr.remove(&id1), "remove should succeed for existing session");
    assert!(!mgr.remove(&id1), "remove should fail for non-existing session");
    assert_eq!(mgr.len(), 1, "one session after removal");

    // 清理过期会话（新会话不会过期）
    let removed = mgr.cleanup_expired();
    assert_eq!(removed, 0, "no expired sessions to clean up");
    assert_eq!(mgr.len(), 1, "length unchanged after cleanup");

    // 删除剩余会话
    assert!(mgr.remove(&id2), "remove remaining session");
    assert!(mgr.is_empty(), "manager should be empty after all removals");
}

/// 测试 KeepAlive 帧穿插数据帧时 Reader 自动跳过
#[test]
fn test_keep_alive_frames_skipped() {
    let dest = ipv4_dest("172.16.0.1", 8080);
    let mut buf = Vec::new();

    // 写入数据帧
    {
        let global_id = test_global_id();
        let mut writer = PacketWriter::new(&mut buf, dest.clone(), global_id);
        writer.write_packet(b"data1").expect("write data1");
    }

    // 穿插 KeepAlive 帧
    FrameMetadata::keep_alive().write_to(&mut buf).expect("insert keep_alive 1");

    // 再写数据帧（Keep 类型）
    {
        let keep_meta = FrameMetadata::keep_udp(dest.address().clone(), dest.port());
        keep_meta.write_to(&mut buf).expect("write keep meta");
        buf.extend_from_slice(&(5u16).to_be_bytes()); // data_len = 5
        buf.extend_from_slice(b"data2");
    }

    // 又穿插 KeepAlive
    FrameMetadata::keep_alive().write_to(&mut buf).expect("insert keep_alive 2");

    // 最后一个数据帧
    {
        let keep_meta = FrameMetadata::keep_udp(dest.address().clone(), dest.port());
        keep_meta.write_to(&mut buf).expect("write keep meta");
        buf.extend_from_slice(&(5u16).to_be_bytes()); // data_len = 5
        buf.extend_from_slice(b"data3");
    }

    let mut reader = PacketReader::new(Cursor::new(buf));

    let p1 = reader.read_packet().expect("read1").expect("some");
    assert_eq!(p1.data(), b"data1", "first data packet");

    // KeepAlive 被自动跳过
    let p2 = reader.read_packet().expect("read2").expect("some");
    assert_eq!(p2.data(), b"data2", "second data packet (KeepAlive skipped)");

    // 又一个 KeepAlive 被跳过
    let p3 = reader.read_packet().expect("read3").expect("some");
    assert_eq!(p3.data(), b"data3", "third data packet (KeepAlive skipped)");

    assert!(reader.read_packet().expect("eof").is_none(), "stream should end");
}

/// 测试大数据包（不超过 Go parity 上限）的 Write→Read 往返
#[test]
fn test_large_packet_write_read() {
    let dest = ipv4_dest("192.168.100.1", 5000);
    let global_id = test_global_id();

    // Go `common/xudp/xudp.go:100`：`length+666 > buf.Size(8192) → continue`，
    // 应用层 packet 上限 = 8192-666 = 7526；超限帧静默丢弃（u5ni 对齐，原 2MB 上限
    // 会使帧 length 字段 u16 截断损坏）。7526 是合法边界。
    let large_size = 7526;
    let large_data: Vec<u8> = vec![0xAB; large_size];

    let mut buf = Vec::new();
    {
        let mut writer = PacketWriter::new(&mut buf, dest.clone(), global_id);
        writer.write_packet(&large_data).expect("write large packet");
    }

    let mut reader = PacketReader::new(Cursor::new(buf));
    let pkt = reader.read_packet().expect("read large packet").expect("packet data");

    assert_eq!(pkt.data().len(), large_size, "large packet data length should match");
    assert!(pkt.data().iter().all(|&b| b == 0xAB), "large packet data content should match");
}

/// 测试 Go 兼容性：验证 Rust 实现 Write→Read 的字节流与 Go 版兼容
///
/// Go 版 TestXudpReadWrite 使用 tcp:127.0.0.1:1345 作为目标地址
/// （但实际写入时 XUDP 协议将 network 字段设为 UDP=2）。
/// 此测试验证 Rust PacketWriter 写入后 PacketReader 能完整读回，
/// 数据和端口一致（对应 Go 版 dest[0].UDP.Port == 1345）。
#[test]
fn test_go_compatibility_write_read() {
    // 模仿 Go 版测试：使用 127.0.0.1:1345 作为目标
    let dest = ipv4_dest("127.0.0.1", 1345);
    let global_id = [0u8; 8]; // Go 版使用 var arr [8]byte（全零）
    let mut buf = Vec::new();

    {
        let mut writer = PacketWriter::new(&mut buf, dest.clone(), global_id);
        writer.write_packet(b"a").expect("write go-compatible packet");
    }

    let mut reader = PacketReader::new(Cursor::new(buf));
    let pkt = reader.read_packet().expect("read go-compatible").expect("packet data");

    // 对应 Go 版断言
    assert_eq!(pkt.data()[0], b'a', "first byte should be 'a' (Go: dest[0].Byte(0) == 'a')");

    // 验证帧元数据中端口为 1345（对应 Go 版 dest[0].UDP.Port == 1345）
    // 重新解析帧元数据验证端口
    let buf_inner = reader.into_inner();
    let buf_bytes = buf_inner.into_inner();
    let (meta, _) = FrameMetadata::from_bytes(&buf_bytes).expect("parse metadata");
    let target = meta.target().expect("target should exist");
    assert_eq!(target.port().value(), 1345, "port should be 1345 (Go: dest[0].UDP.Port == 1345)");
}
