//! B1 胶囊 golden 测试：按 Go `transport/internet/masque/connectip/capsule.go`
//! （v26.11.9 @ 676eaf66）构造形态逐字节对拍。
//!
//! golden 字节均由 Go `append` 逻辑手推并逐字节给出（varint 为 RFC 9000 §16 形式）；
//! 每个 case 运行时打印 期望/实际 hex 对照段（`--nocapture` 可见）。
//!
//! DATAGRAM 帧形态来自 `conn.go:667-677`（h2 承载恒带 `contextIDZero=[0x00]` 前缀）；
//! 读侧丢弃语义来自 `conn.go:467-471,513-520`。

use xray_transport_masque::capsule::{
    self, AddressRequestEntry, AssignedAddress, CAPSULE_ADDRESS_ASSIGN, CAPSULE_ADDRESS_REQUEST,
    CAPSULE_ROUTE_ADVERTISEMENT, Capsule, IpPrefix, IpRoute,
};

/// bytes → hex（字节间空格，golden 对照可读）。
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ")
}

/// golden 断言：encode 后逐字节比对并打印对照段。
fn golden(case: &str, actual: &[u8], expected_hex: &str) {
    println!("[{case}]\n  expected: {expected_hex}\n  actual:   {}", hex(actual));
    assert_eq!(hex(actual), expected_hex, "{case} golden mismatch");
}

fn prefix(v4: [u8; 4], len: u8) -> IpPrefix {
    IpPrefix { addr: std::net::IpAddr::from(v4), prefix_len: len }
}

fn prefix6(v6: [u8; 16], len: u8) -> IpPrefix {
    IpPrefix { addr: std::net::IpAddr::from(v6), prefix_len: len }
}

#[test]
fn golden_datagram_carries_context_id_zero_prefix() {
    // Go conn.go:667-677：payload = contextIDZero(00) + packet；
    // 帧 = varint(0) + varint(1+4) + payload。packet = 45 00 00 1C（IPv4 头首 4 字节形态）。
    let frame = capsule::encode_capsule(&Capsule::Datagram(vec![0x45, 0x00, 0x00, 0x1C]))
        .expect("datagram encode should succeed");
    golden("DATAGRAM(4B packet)", &frame, "00 05 00 45 00 00 1C");

    // 读侧：contextID 前缀剥除，还原裸包。
    let decoded = capsule::decode_capsule(0, &frame[2..])
        .expect("datagram decode should succeed")
        .expect("contextID=0 datagram must be delivered");
    assert_eq!(decoded, Capsule::Datagram(vec![0x45, 0x00, 0x00, 0x1C]));
}

#[test]
fn golden_address_assign_v4_single_entry() {
    // Go capsule.go:48-56：条目 = varint(reqID) + 04 + addr(4B) + prefixLen。
    // reqID=1 → 01；192.0.2.1/32 → 04 C0 00 02 01 20；totalLen=7 → 07。
    let capsule = Capsule::AddressAssign(vec![AssignedAddress {
        request_id: 1,
        prefix: prefix([192, 0, 2, 1], 32),
    }]);
    let frame = capsule::encode_capsule(&capsule).expect("assign encode should succeed");
    golden("ADDRESS_ASSIGN(v4 /32)", &frame, "01 07 01 04 C0 00 02 01 20");

    let decoded = capsule::decode_capsule(CAPSULE_ADDRESS_ASSIGN, &frame[2..])
        .expect("assign decode should succeed")
        .expect("assign capsule must be delivered");
    assert_eq!(decoded, capsule);
}

#[test]
fn golden_address_assign_v6_multi_byte_varint_request_id() {
    // reqID=300 → varint 两字节 41 2C（0x40 前缀 + 0x012C）；
    // 2001:0db8::/32 → 06 + 20 01 0D B8 + 11×00 + prefixLen 32=0x20；totalLen=20 → 14。
    let capsule = Capsule::AddressAssign(vec![AssignedAddress {
        request_id: 300,
        prefix: prefix6([0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 32),
    }]);
    let frame = capsule::encode_capsule(&capsule).expect("assign encode should succeed");
    golden(
        "ADDRESS_ASSIGN(v6 reqID=300)",
        &frame,
        "01 14 41 2C 06 20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 00 20",
    );

    let decoded = capsule::decode_capsule(CAPSULE_ADDRESS_ASSIGN, &frame[2..])
        .expect("assign decode should succeed")
        .expect("assign capsule must be delivered");
    assert_eq!(decoded, capsule);
}

#[test]
fn golden_address_request_matches_go_client_form() {
    // Go dialer.go:277-296 客户端请求形态：{reqID, 0.0.0.0/0}。
    // reqID=1 → 01；0.0.0.0/0 → 04 00 00 00 00 00；totalLen=7 → 07。
    let capsule = Capsule::AddressRequest(vec![AddressRequestEntry {
        request_id: 1,
        prefix: prefix([0, 0, 0, 0], 0),
    }]);
    let frame = capsule::encode_capsule(&capsule).expect("request encode should succeed");
    golden("ADDRESS_REQUEST(0.0.0.0/0)", &frame, "02 07 01 04 00 00 00 00 00");

    let decoded = capsule::decode_capsule(CAPSULE_ADDRESS_REQUEST, &frame[2..])
        .expect("request decode should succeed")
        .expect("request capsule must be delivered");
    assert_eq!(decoded, capsule);
}

#[test]
fn golden_route_advertisement_v4_single_entry() {
    // Go capsule.go:262-277：条目 = 版本字节 + start(4B) + end(4B) + proto。
    // 192.0.2.0-192.0.2.255 proto=17(0x11)；totalLen=10 → 0A。
    let capsule = Capsule::RouteAdvertisement(vec![IpRoute {
        start_ip: std::net::IpAddr::from([192, 0, 2, 0]),
        end_ip: std::net::IpAddr::from([192, 0, 2, 255]),
        ip_protocol: 17,
    }]);
    let frame = capsule::encode_capsule(&capsule).expect("route encode should succeed");
    golden("ROUTE_ADVERTISEMENT(v4 single)", &frame, "03 0A 04 C0 00 02 00 C0 00 02 FF 11");

    let decoded = capsule::decode_capsule(CAPSULE_ROUTE_ADVERTISEMENT, &frame[2..])
        .expect("route decode should succeed")
        .expect("route capsule must be delivered");
    assert_eq!(decoded, capsule);
}

#[test]
fn golden_route_advertisement_two_ordered_entries() {
    // 相邻条目：同版本同协议严格升序不重叠（Go checkRouteOrder）。
    // 条目 = 版本字节 + start(4B) + end(4B) + proto = 10B；两条 totalLen=20 → 14。
    let capsule = Capsule::RouteAdvertisement(vec![
        IpRoute {
            start_ip: std::net::IpAddr::from([192, 0, 2, 0]),
            end_ip: std::net::IpAddr::from([192, 0, 2, 127]),
            ip_protocol: 6,
        },
        IpRoute {
            start_ip: std::net::IpAddr::from([192, 0, 2, 128]),
            end_ip: std::net::IpAddr::from([192, 0, 2, 255]),
            ip_protocol: 6,
        },
    ]);
    let frame = capsule::encode_capsule(&capsule).expect("route encode should succeed");
    golden(
        "ROUTE_ADVERTISEMENT(v4 two ordered)",
        &frame,
        "03 14 04 C0 00 02 00 C0 00 02 7F 06 04 C0 00 02 80 C0 00 02 FF 06",
    );
}

#[test]
fn unknown_capsule_type_round_trips_as_unknown() {
    // Go conn_test.go:385 TestSkipUnknownCapsule：未知类型跳过不报错；
    // 编解码面保留 Unknown{ty, payload}，丢弃决定权在会话层。
    let decoded = capsule::decode_capsule(42, &[0xDE, 0xAD])
        .expect("unknown type decode should not error")
        .expect("unknown capsule must be delivered as Unknown");
    assert_eq!(decoded, Capsule::Unknown { ty: 42, payload: vec![0xDE, 0xAD] });
    assert!(capsule::encode_capsule(&decoded).is_err(), "unknown capsule is not encodable");
}

#[test]
fn datagram_non_zero_context_id_is_dropped_not_errored() {
    // Go conn.go:513-520：contextID 非 0 丢弃（非错误）；varint 畸形同丢弃。
    let dropped = capsule::decode_capsule(0, &[0x01, 0x45, 0x00])
        .expect("non-zero contextID decode should not error");
    assert_eq!(dropped, None, "contextID=1 datagram must be dropped");
    let malformed = capsule::decode_capsule(0, &[]).expect("empty payload should not error");
    assert_eq!(malformed, None, "empty DATAGRAM payload must be dropped");
}

#[test]
fn datagram_oversize_is_dropped_on_decode_and_mtu_on_encode() {
    // Go conn.go:468：payload > 1 + 65535 整颗丢弃；写侧超限归 MTU 分类。
    let oversize = vec![0u8; 1 + capsule::MAX_CAPSULE_PAYLOAD + 1];
    let dropped = capsule::decode_capsule(0, &oversize).expect("oversize decode should not error");
    assert_eq!(dropped, None, "oversize datagram must be dropped");

    let err =
        capsule::encode_capsule(&Capsule::Datagram(vec![0u8; capsule::MAX_CAPSULE_PAYLOAD + 1]))
            .expect_err("oversize encode must be an MTU error");
    assert!(
        err.to_string().contains("capsule packet size"),
        "encode oversize should classify as Mtu, got {err}"
    );

    // 边界内 65535B 包：帧 = varint(0) + varint(65536=80 01 00 00) + 00 + packet。
    let frame =
        capsule::encode_capsule(&Capsule::Datagram(vec![0u8; capsule::MAX_CAPSULE_PAYLOAD]))
            .expect("boundary datagram encode should succeed");
    assert_eq!(
        &frame[..5],
        &[0x00, 0x80, 0x01, 0x00, 0x00],
        "type varint(0) + length varint(65536) must be 00 80 01 00 00"
    );
    assert_eq!(frame.len(), 1 + 4 + 1 + capsule::MAX_CAPSULE_PAYLOAD);
}

#[test]
fn address_request_validation_gaps() {
    // Go capsule.go:93-95：ADDRESS_REQUEST 空载荷 → Err。
    let err = capsule::decode_capsule(CAPSULE_ADDRESS_REQUEST, &[])
        .expect_err("empty ADDRESS_REQUEST must be rejected");
    assert!(err.to_string().contains("no addresses"), "got {err}");

    // Go capsule.go:103-105：reqID=0 → Err。
    let err = capsule::decode_capsule(CAPSULE_ADDRESS_REQUEST, &[0x00, 0x04, 0, 0, 0, 0, 0x20])
        .expect_err("zero request ID must be rejected");
    assert!(err.to_string().contains("zero request ID"), "got {err}");

    // ADDRESS_ASSIGN 允许空载荷（0 条目）——Go parseAddressAssignCapsule 空循环合法。
    let empty = capsule::decode_capsule(CAPSULE_ADDRESS_ASSIGN, &[])
        .expect("empty ADDRESS_ASSIGN should not error")
        .expect("empty assign must be delivered");
    assert_eq!(empty, Capsule::AddressAssign(vec![]));
}

#[test]
fn prefix_validation_gaps() {
    // Go parseAddress：版本非法 / 前缀长超位长 / 掩码外低位非零 均 Err。
    let bad_version =
        capsule::decode_capsule(CAPSULE_ADDRESS_ASSIGN, &[0x01, 0x05, 0, 0, 0, 0, 0x20]);
    assert!(bad_version.is_err(), "IP version 5 must be rejected");

    let too_long = capsule::decode_capsule(CAPSULE_ADDRESS_ASSIGN, &[0x01, 0x04, 192, 0, 2, 1, 33]);
    assert!(
        too_long.unwrap_err().to_string().contains("exceeds IP address length"),
        "prefix /33 must be rejected"
    );

    // 192.0.2.1/24：掩码外低位（第 4 字节 = 1）非零 → Err。
    let unmasked = capsule::decode_capsule(CAPSULE_ADDRESS_ASSIGN, &[0x01, 0x04, 192, 0, 2, 1, 24]);
    assert!(
        unmasked.unwrap_err().to_string().contains("lower bits not covered by prefix length"),
        "unmasked prefix must be rejected"
    );
}

#[test]
fn route_order_validation_gaps() {
    // Go checkRouteOrder：v6 先于 v4 = 次序降 → Err。
    let v6_then_v4 = capsule::decode_capsule(
        CAPSULE_ROUTE_ADVERTISEMENT,
        &[
            0x06, 0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20, 0x01, 0x0D,
            0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0x06, 0x04, 192, 0, 2, 0, 192, 0, 2, 255,
            17,
        ],
    );
    assert!(
        v6_then_v4.unwrap_err().to_string().contains("not ordered"),
        "v6-before-v4 must be rejected"
    );

    // 同版本同协议区间重叠（prev.end >= cur.start）→ Err。
    let overlapping = capsule::decode_capsule(
        CAPSULE_ROUTE_ADVERTISEMENT,
        &[0x04, 192, 0, 2, 0, 192, 0, 2, 128, 6, 0x04, 192, 0, 2, 128, 192, 0, 2, 255, 6],
    );
    assert!(
        overlapping.unwrap_err().to_string().contains("overlap or are not in ascending order"),
        "overlapping ranges must be rejected"
    );

    // 同版本不同协议升序 → 合法（Go cmp.Or 位长同、协议升 → -1 → 通过）。
    let mixed_proto = capsule::decode_capsule(
        CAPSULE_ROUTE_ADVERTISEMENT,
        &[0x04, 192, 0, 2, 0, 192, 0, 2, 255, 6, 0x04, 198, 51, 100, 0, 198, 51, 100, 255, 17],
    );
    assert!(mixed_proto.is_ok(), "same-version different-proto ascending routes must be accepted");

    // 区间内 start > end → Err（Go parseIPAddressRange）。
    let inverted = capsule::decode_capsule(
        CAPSULE_ROUTE_ADVERTISEMENT,
        &[0x04, 192, 0, 2, 255, 192, 0, 2, 0, 6],
    );
    assert!(
        inverted.unwrap_err().to_string().contains("greater than end"),
        "inverted range must be rejected"
    );
}

#[test]
fn entry_limit_8192_is_enforced() {
    // Go capsule.go:27-30：单胶囊 8192 条目上限；编解码两侧同判。
    let mut entries = Vec::with_capacity(8193);
    for i in 0..8193u64 {
        // reqID 取模避免 varint 变长干扰：本测试只考条目数上限。
        entries.push(AddressRequestEntry {
            request_id: (i % 200) + 1,
            prefix: prefix([10, 0, 0, 0], 8),
        });
    }
    let err = capsule::encode_capsule(&Capsule::AddressRequest(entries))
        .expect_err("8193 entries must be rejected on encode");
    assert!(err.to_string().contains("too many entries"), "got {err}");

    // 解码侧：手工构造 8193 条目（每条 7 字节；reqID ≤ 63 保证单字节 varint）。
    let mut payload = Vec::with_capacity(8193 * 7);
    for i in 0..8193u64 {
        payload.extend_from_slice(&[(i % 63) as u8 + 1, 0x04, 10, 0, 0, 0, 8]);
    }
    let err = capsule::decode_capsule(CAPSULE_ADDRESS_ASSIGN, &payload)
        .expect_err("8193 entries must be rejected on decode");
    assert!(err.to_string().contains("too many entries"), "got {err}");
}

#[test]
fn encode_decode_roundtrip_all_known_types() {
    let cases = vec![
        Capsule::Datagram(vec![0x60, 0x00, 0x00, 0x00, 0x00, 0x00]),
        Capsule::AddressAssign(vec![
            AssignedAddress { request_id: 1, prefix: prefix([192, 0, 2, 1], 32) },
            AssignedAddress {
                request_id: 16384,
                prefix: prefix6([0x20, 1, 0xD, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 128),
            },
        ]),
        Capsule::AddressRequest(vec![
            AddressRequestEntry { request_id: 1, prefix: prefix([0, 0, 0, 0], 0) },
            AddressRequestEntry { request_id: 2, prefix: prefix6([0; 16], 0) },
        ]),
        Capsule::RouteAdvertisement(vec![IpRoute {
            start_ip: std::net::IpAddr::from([0, 0, 0, 0]),
            end_ip: std::net::IpAddr::from([255, 255, 255, 255]),
            ip_protocol: 0,
        }]),
    ];
    for c in &cases {
        let frame = capsule::encode_capsule(c).expect("known capsule must encode");
        let ty = {
            // 帧头 varint 类型值：长度 1 字节（类型值 0-3）。
            frame[0] as u64
        };
        let decoded = capsule::decode_capsule(ty, &frame[2..])
            .expect("golden frame must decode")
            .expect("golden capsule must be delivered");
        assert_eq!(&decoded, c, "roundtrip mismatch for {c:?}");
    }
}
