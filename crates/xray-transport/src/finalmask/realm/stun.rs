//! # STUN 客户端 + NAT 端口预测（对应 Go `transport/internet/finalmask/realm/stun.go`）
//!
//! 自实现 RFC5389 STUN Binding Request/Response 的最小子集——仅支持
//! Binding Request 构造、Binding Success Response 解析、XOR-MAPPED-ADDRESS /
//! MAPPED-ADDRESS 属性提取。避免引入 `stun` / `stun-rs` 外部依赖。
//!
//! 同时复刻 Go 的 NAT 端口预测算法（symmetric NAT 候选扩展）。

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::time::Duration;

use rand::RngCore;

/// 默认 STUN 解析超时（对应 Go `defaultSTUNTimeout`）。
pub const DEFAULT_STUN_TIMEOUT: Duration = Duration::from_secs(4);
/// 默认 punch 完成超时（对应 Go `defaultPunchTimeout`）。
pub const DEFAULT_PUNCH_TIMEOUT: Duration = Duration::from_secs(10);
/// 默认 punch 重发间隔（对应 Go `defaultPunchInterval`）。
pub const DEFAULT_PUNCH_INTERVAL: Duration = Duration::from_millis(100);

/// symmetric NAT 端口预测：相邻两观察端口允许的最大间隔。
const SYMMETRIC_NAT_PORT_GAP: u16 = 4;
/// symmetric NAT 端口预测：在最大观察端口之上额外预测的端口数。
const SYMMETRIC_NAT_EXTRA_PORTS: u16 = 4;
/// symmetric NAT 端口预测：每主机最多生成的候选端口数。
const SYMMETRIC_NAT_MAX_PORTS_PER_HOST: usize = 32;

/// RFC5389 magic cookie。
const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;
/// Binding Request 类型。
const STUN_BINDING_REQUEST: u16 = 0x0001;
/// Binding Success Response 类型。
const STUN_BINDING_SUCCESS: u16 = 0x0101;
/// MAPPED-ADDRESS 属性类型（明文）。
const STUN_ATTR_MAPPED_ADDRESS: u16 = 0x0001;
/// XOR-MAPPED-ADDRESS 属性类型（RFC5389）。
const STUN_ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
/// STUN message header 长度。
pub const STUN_HEADER_LEN: usize = 20;
/// Transaction ID 字节长度。
pub const STUN_TRANSACTION_ID_SIZE: usize = 12;

/// STUN transaction ID（12 字节）。
pub type TransactionId = [u8; STUN_TRANSACTION_ID_SIZE];

/// 构造 STUN Binding Request（对应 Go `stun.Build(stun.TransactionID, stun.BindingRequest)`）。
///
/// 返回完整 wire 包与生成的 transaction ID（用于响应匹配）。
#[must_use]
pub fn build_binding_request() -> (Vec<u8>, TransactionId) {
    let mut tx_id = [0u8; STUN_TRANSACTION_ID_SIZE];
    rand::rng().fill_bytes(&mut tx_id);
    let mut packet = Vec::with_capacity(STUN_HEADER_LEN);
    packet.extend_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes()); // length = 0（无属性）
    packet.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    packet.extend_from_slice(&tx_id);
    (packet, tx_id)
}

/// 判断是否为 STUN 消息（对应 Go `stun.IsMessage`）。
#[must_use]
pub fn is_stun_message(packet: &[u8]) -> bool {
    if packet.len() < STUN_HEADER_LEN {
        return false;
    }
    // STUN 类型字段高 2 位必须为 0（区分 RTP 等协议）
    if (packet[0] & 0xC0) != 0 {
        return false;
    }
    let cookie = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);
    cookie == STUN_MAGIC_COOKIE
}

/// 解析 STUN Binding Response（对应 Go `parseSTUNBindingResponse`）。
///
/// 返回 `(transaction_id, mapped_addr)`，优先 XOR-MAPPED-ADDRESS，其次 MAPPED-ADDRESS。
pub fn parse_stun_binding_response(
    packet: &[u8],
) -> io::Result<(TransactionId, SocketAddr)> {
    if packet.len() < STUN_HEADER_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "STUN packet too short",
        ));
    }
    let msg_type = u16::from_be_bytes([packet[0], packet[1]]);
    if msg_type != STUN_BINDING_SUCCESS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a STUN binding success response",
        ));
    }
    let cookie = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);
    if cookie != STUN_MAGIC_COOKIE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bad STUN magic cookie",
        ));
    }
    let mut tx_id = [0u8; STUN_TRANSACTION_ID_SIZE];
    tx_id.copy_from_slice(&packet[8..STUN_HEADER_LEN]);
    let body_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if packet.len() < STUN_HEADER_LEN + body_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "STUN body length exceeds packet",
        ));
    }
    let body = &packet[STUN_HEADER_LEN..STUN_HEADER_LEN + body_len];
    if let Some(addr) = find_attr(body, STUN_ATTR_XOR_MAPPED_ADDRESS, Some(&tx_id))? {
        return Ok((tx_id, addr));
    }
    if let Some(addr) = find_attr(body, STUN_ATTR_MAPPED_ADDRESS, None)? {
        return Ok((tx_id, addr));
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "STUN mapped address not found",
    ))
}

/// 在属性 body 中查找指定类型并解码地址。
fn find_attr(
    body: &[u8],
    target: u16,
    tx_id: Option<&TransactionId>,
) -> io::Result<Option<SocketAddr>> {
    let mut i = 0;
    while i + 4 <= body.len() {
        let attr_type = u16::from_be_bytes([body[i], body[i + 1]]);
        let attr_len = u16::from_be_bytes([body[i + 2], body[i + 3]]) as usize;
        let val_start = i + 4;
        let val_end = val_start + attr_len;
        if val_end > body.len() {
            break;
        }
        if attr_type == target {
            let val = &body[val_start..val_end];
            let addr = if attr_type == STUN_ATTR_XOR_MAPPED_ADDRESS {
                decode_xor_mapped_address(val, tx_id.ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "missing transaction id")
                })?)?
            } else {
                decode_mapped_address(val)?
            };
            return Ok(Some(addr));
        }
        // 4 字节对齐填充
        i = val_end + ((4 - (attr_len % 4)) % 4);
    }
    Ok(None)
}

/// 解析 MAPPED-ADDRESS（明文，对应 RFC5389 旧版 NAT 友好客户端）。
fn decode_mapped_address(val: &[u8]) -> io::Result<SocketAddr> {
    if val.len() < 4 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad mapped address"));
    }
    let family = val[1];
    let port = u16::from_be_bytes([val[2], val[3]]);
    let ip_bytes = &val[4..];
    let ip = match family {
        0x01 => {
            if ip_bytes.len() < 4 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "bad ipv4"));
            }
            let mut octets = [0u8; 4];
            octets.copy_from_slice(&ip_bytes[..4]);
            IpAddr::V4(Ipv4Addr::from(octets))
        }
        0x02 => {
            if ip_bytes.len() < 16 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "bad ipv6"));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&ip_bytes[..16]);
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "bad address family")),
    };
    Ok(SocketAddr::new(ip, port))
}

/// 解析 XOR-MAPPED-ADDRESS（RFC5389）。
///
/// - port XOR 高 16 位 cookie
/// - IPv4 XOR 整个 cookie（4 字节）
/// - IPv6 XOR cookie(4) + transaction_id(12) = 16 字节
fn decode_xor_mapped_address(
    val: &[u8],
    tx_id: &TransactionId,
) -> io::Result<SocketAddr> {
    if val.len() < 4 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad xor mapped address"));
    }
    let family = val[1];
    let cookie_hi = ((STUN_MAGIC_COOKIE >> 16) & 0xFFFF) as u16;
    let port = u16::from_be_bytes([val[2], val[3]]) ^ cookie_hi;
    let ip_bytes = &val[4..];
    let ip = match family {
        0x01 => {
            if ip_bytes.len() < 4 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "bad ipv4"));
            }
            let key = STUN_MAGIC_COOKIE.to_be_bytes();
            let mut octets = [0u8; 4];
            for (i, b) in ip_bytes[..4].iter().enumerate() {
                octets[i] = b ^ key[i];
            }
            IpAddr::V4(Ipv4Addr::from(octets))
        }
        0x02 => {
            if ip_bytes.len() < 16 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "bad ipv6"));
            }
            let mut key = [0u8; 16];
            key[..4].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
            key[4..].copy_from_slice(tx_id);
            let mut octets = [0u8; 16];
            for (i, b) in ip_bytes[..16].iter().enumerate() {
                octets[i] = b ^ key[i];
            }
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "bad address family")),
    };
    Ok(SocketAddr::new(ip, port))
}

/// DNS 解析 STUN 服务器列表（对应 Go `resolveSTUNServers`）。
///
/// 按 `local` 过滤地址族：`Some(IpAddr::V4(_))` 仅返回 IPv4；`None` 接受所有。
/// 失败的条目静默跳过（与 Go 行为一致）。
pub fn resolve_stun_servers(local: Option<IpAddr>, servers: &[String]) -> Vec<SocketAddr> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(servers.len());
    for server in servers {
        let resolved: Vec<SocketAddr> = match server.to_socket_addrs() {
            Ok(it) => it.collect(),
            Err(_) => continue,
        };
        for addr in resolved {
            if let Some(ip) = local {
                let family_ok = match ip {
                    IpAddr::V4(_) => addr.is_ipv4(),
                    IpAddr::V6(_) => addr.is_ipv6(),
                };
                if !family_ok {
                    continue;
                }
            }
            if seen.insert(addr.to_string()) {
                out.push(addr);
            }
        }
    }
    out
}

/// 计算候选 peer 地址（对应 Go `candidatePunchAddrs`）。
///
/// 返回 `(candidates, seen_set)`。`locals` 决定可用的地址族（v4/v6）。
#[must_use]
pub fn candidate_punch_addrs(
    locals: &[SocketAddr],
    peers: &[SocketAddr],
) -> (Vec<SocketAddr>, std::collections::HashSet<SocketAddr>) {
    let mut allow_v4 = false;
    let mut allow_v6 = false;
    for local in locals {
        if local.is_ipv4() {
            allow_v4 = true;
        } else {
            allow_v6 = true;
        }
        if allow_v4 && allow_v6 {
            break;
        }
    }
    let mut seen = std::collections::HashSet::with_capacity(peers.len());
    let mut candidates = Vec::with_capacity(peers.len());
    for peer in peers {
        if seen.contains(peer) {
            continue;
        }
        let allow = if peer.is_ipv4() { allow_v4 } else { allow_v6 };
        if allow {
            seen.insert(*peer);
            candidates.push(*peer);
        }
    }
    (candidates, seen)
}

/// 扩展 symmetric NAT 候选端口（对应 Go `expandSymmetricNATCandidates`）。
///
/// 对每个 v4 主机：若观察到的端口组在 `SYMMETRIC_NAT_PORT_GAP` 范围内，
/// 额外预测 `[min..=max+SYMMETRIC_NAT_EXTRA_PORTS]` 内的端口（最多
/// `SYMMETRIC_NAT_MAX_PORTS_PER_HOST` 个新候选），最后整体按字符串排序。
pub fn expand_symmetric_nat_candidates(
    mut candidates: Vec<SocketAddr>,
    seen: &mut std::collections::HashSet<SocketAddr>,
) -> Vec<SocketAddr> {
    let mut ports_by_ip: HashMap<IpAddr, Vec<u16>> = HashMap::new();
    for addr in &candidates {
        if addr.is_ipv4() {
            ports_by_ip.entry(addr.ip()).or_default().push(addr.port());
        }
    }
    for (ip, ports) in &mut ports_by_ip {
        let uniq = unique_sorted_ports(std::mem::take(ports));
        *ports = uniq.clone();
        if !predictable_port_group(&uniq) {
            continue;
        }
        let start = u32::from(uniq[0]);
        let mut end = u32::from(uniq[uniq.len() - 1]) + u32::from(SYMMETRIC_NAT_EXTRA_PORTS);
        if end > 65535 {
            end = 65535;
        }
        let mut added = 0usize;
        let mut port = start;
        while port <= end && added < SYMMETRIC_NAT_MAX_PORTS_PER_HOST {
            let candidate = SocketAddr::new(*ip, port as u16);
            if seen.insert(candidate) {
                candidates.push(candidate);
                added += 1;
            }
            port += 1;
        }
    }
    candidates.sort_by_key(|a| a.to_string());
    candidates
}

/// 排序去重端口列表（对应 Go `uniqueSortedPorts`）。
#[must_use]
pub fn unique_sorted_ports(mut ports: Vec<u16>) -> Vec<u16> {
    ports.sort_unstable();
    ports.dedup();
    ports
}

/// 判断端口组是否在 symmetric NAT 可预测范围内（对应 Go `predictablePortGroup`）。
#[must_use]
pub fn predictable_port_group(ports: &[u16]) -> bool {
    if ports.len() < 2 {
        return false;
    }
    for i in 1..ports.len() {
        // 已排序，ports[i] >= ports[i-1]，减法安全
        if ports[i] - ports[i - 1] > SYMMETRIC_NAT_PORT_GAP {
            return false;
        }
    }
    true
}

/// `SocketAddr` 列表 → 字符串列表（对应 Go `addrPortStrings`）。
#[must_use]
pub fn addr_port_strings(addrs: &[SocketAddr]) -> Vec<String> {
    addrs.iter().map(std::string::ToString::to_string).collect()
}

/// 字符串列表 → `SocketAddr` 列表（对应 Go `parseAddrPorts`）。
pub fn parse_addr_ports(addrs: &[String]) -> io::Result<Vec<SocketAddr>> {
    addrs
        .iter()
        .map(|s| {
            s.parse::<SocketAddr>().map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData, e.to_string())
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_xor_mapped_v4(addr: Ipv4Addr, port: u16, tx_id: &TransactionId) -> Vec<u8> {
        let cookie_hi = ((STUN_MAGIC_COOKIE >> 16) & 0xFFFF) as u16;
        let xored_port = port ^ cookie_hi;
        let raw_ip = u32::from(addr);
        let xored_ip = raw_ip ^ STUN_MAGIC_COOKIE;
        let mut attr = Vec::with_capacity(8);
        attr.push(0); // reserved
        attr.push(0x01); // family IPv4
        attr.extend_from_slice(&xored_port.to_be_bytes());
        attr.extend_from_slice(&xored_ip.to_be_bytes());
        // wrap in full packet
        let mut packet = Vec::with_capacity(STUN_HEADER_LEN + 4 + attr.len());
        packet.extend_from_slice(&STUN_BINDING_SUCCESS.to_be_bytes());
        packet.extend_from_slice(&(4u16 + attr.len() as u16).to_be_bytes());
        packet.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        packet.extend_from_slice(tx_id);
        // attr header
        packet.extend_from_slice(&STUN_ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        packet.extend_from_slice(&(attr.len() as u16).to_be_bytes());
        packet.extend_from_slice(&attr);
        packet
    }

    #[test]
    fn stun_parses_xor_mapped_ipv4() {
        let tx_id = [7u8; STUN_TRANSACTION_ID_SIZE];
        let packet = build_xor_mapped_v4(Ipv4Addr::new(1, 2, 3, 4), 5678, &tx_id);
        let (parsed_tx, parsed_addr) =
            parse_stun_binding_response(&packet).expect("parse xor-mapped");
        assert_eq!(parsed_tx, tx_id);
        assert_eq!(parsed_addr.port(), 5678);
        assert_eq!(parsed_addr.ip(), IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
    }

    #[test]
    fn stun_rejects_non_success_response() {
        let mut packet = vec![0u8; STUN_HEADER_LEN];
        // Binding Error Response = 0x0111
        packet[0..2].copy_from_slice(&0x0111u16.to_be_bytes());
        packet[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        let err = parse_stun_binding_response(&packet).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn stun_rejects_bad_cookie() {
        let mut packet = vec![0u8; STUN_HEADER_LEN];
        packet[0..2].copy_from_slice(&STUN_BINDING_SUCCESS.to_be_bytes());
        packet[4..8].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
        let err = parse_stun_binding_response(&packet).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn stun_is_message_detects_magic() {
        let (req, _id) = build_binding_request();
        assert!(is_stun_message(&req));
        assert!(!is_stun_message(&[0u8; 10]));
        // 错误 cookie
        let mut bad = req.clone();
        bad[4..8].copy_from_slice(&0u32.to_be_bytes());
        assert!(!is_stun_message(&bad));
    }

    #[test]
    fn predictable_port_group_logic() {
        assert!(!predictable_port_group(&[100]));
        assert!(predictable_port_group(&[100, 101, 102, 105]));
        assert!(!predictable_port_group(&[100, 110]));
    }

    #[test]
    fn unique_sorted_ports_dedup() {
        assert_eq!(unique_sorted_ports(vec![3, 1, 2, 1, 3]), vec![1, 2, 3]);
        assert_eq!(unique_sorted_ports(Vec::<u16>::new()), Vec::<u16>::new());
    }

    #[test]
    fn candidate_filter_by_family() {
        let locals: Vec<SocketAddr> = vec!["127.0.0.1:1000".parse().unwrap()];
        let peers: Vec<SocketAddr> = vec![
            "1.1.1.1:5000".parse().unwrap(),
            "[::1]:5000".parse().unwrap(),
        ];
        let (cands, _seen) = candidate_punch_addrs(&locals, &peers);
        assert_eq!(cands.len(), 1);
        assert!(cands[0].is_ipv4());
    }

    #[test]
    fn candidate_dedup_peers() {
        let locals: Vec<SocketAddr> = vec!["127.0.0.1:1000".parse().unwrap()];
        let peers: Vec<SocketAddr> = vec![
            "1.1.1.1:5000".parse().unwrap(),
            "1.1.1.1:5000".parse().unwrap(),
        ];
        let (cands, _seen) = candidate_punch_addrs(&locals, &peers);
        assert_eq!(cands.len(), 1);
    }

    #[test]
    fn expand_symmetric_nat_adds_predictable_ports() {
        // 两观察端口 30000, 30002 — gap=2 ≤ 4，predictable
        let initial: Vec<SocketAddr> = vec![
            "1.2.3.4:30000".parse().unwrap(),
            "1.2.3.4:30002".parse().unwrap(),
        ];
        let (_, mut seen) = candidate_punch_addrs(&[], &initial);
        seen.clear();
        seen.insert(initial[0]);
        seen.insert(initial[1]);
        let expanded = expand_symmetric_nat_candidates(initial.clone(), &mut seen);
        assert!(expanded.len() > initial.len());
        let ports: Vec<u16> = expanded.iter().map(SocketAddr::port).collect();
        assert!(ports.contains(&30001));
        assert!(ports.contains(&30006));
    }

    #[test]
    fn expand_unpredictable_unchanged() {
        // gap = 100 > 4，不应扩展
        let initial: Vec<SocketAddr> = vec![
            "1.2.3.4:30000".parse().unwrap(),
            "1.2.3.4:30100".parse().unwrap(),
        ];
        let (_, mut seen) = candidate_punch_addrs(&[], &initial);
        seen.clear();
        seen.insert(initial[0]);
        seen.insert(initial[1]);
        let expanded = expand_symmetric_nat_candidates(initial.clone(), &mut seen);
        assert_eq!(expanded.len(), initial.len());
    }

    #[test]
    fn addr_port_strings_roundtrip() {
        let addrs: Vec<SocketAddr> = vec![
            "1.2.3.4:5678".parse().unwrap(),
            "[::1]:9999".parse().unwrap(),
        ];
        let strings = addr_port_strings(&addrs);
        let parsed = parse_addr_ports(&strings).unwrap();
        assert_eq!(parsed, addrs);
    }
}
