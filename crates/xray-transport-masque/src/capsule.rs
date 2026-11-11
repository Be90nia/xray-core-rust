//! CONNECT-IP 胶囊编解码（RFC 9297 HTTP Datagram 帧格式 + RFC 9484 地址/路由胶囊）。
//!
//! 语义唯一源：Go `transport/internet/masque/connectip/capsule.go`（v26.11.9 @ 676eaf66）；
//! DATAGRAM 的 contextID 前缀语义见 `connectip/conn.go:467-471,512-521,667-677` 与
//! `connectip/proxy.go:18`（`contextIDZero = [0x00]`，h2 承载恒带前缀）。
//!
//! udf 不适用判定（CLAUDE.md §3.5.3/§3.5.5）：RFC wire 语义属协议方向件，单消费方
//! 无提炼候选。varint 用上浮件 [`xray_transport::wire::varint`]（规划 §5 B1.1）。

use std::{
    io::{Cursor, Read as _},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use xray_transport::wire::varint::{read_varint, varint_len, write_varint};

use crate::error::{MasqueError, Result};

/// 胶囊类型：DATAGRAM（Go `capsule.go:22`）。
pub const CAPSULE_DATAGRAM: u64 = 0;
/// 胶囊类型：ADDRESS_ASSIGN（Go `capsule.go:23`）。
pub const CAPSULE_ADDRESS_ASSIGN: u64 = 1;
/// 胶囊类型：ADDRESS_REQUEST（Go `capsule.go:24`）。
pub const CAPSULE_ADDRESS_REQUEST: u64 = 2;
/// 胶囊类型：ROUTE_ADVERTISEMENT（Go `capsule.go:25`）。
pub const CAPSULE_ROUTE_ADVERTISEMENT: u64 = 3;

/// 单胶囊 DATAGRAM 包上限（Go `conn.go:63` `maxCapsulePacketSize = 1<<16-1`；
/// h2 写侧超限走 ICMP packet-too-big 回灌，见 B2 `connect.rs`）。
pub const MAX_CAPSULE_PAYLOAD: usize = (1 << 16) - 1;
/// 单胶囊地址/路由条目上限（Go `capsule.go:27-30`，地址与路由同值 8192）。
pub const MAX_ENTRIES_PER_CAPSULE: usize = 8192;

/// 已分配地址（ADDRESS_ASSIGN 条目；Go `AssignedAddress`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssignedAddress {
    /// 对应 ADDRESS_REQUEST 的请求 ID。
    pub request_id: u64,
    /// 分配前缀。
    pub prefix: IpPrefix,
}

impl AssignedAddress {
    /// 拒绝判定（Go `capsule.go:42-44`）：前缀恰为 `0.0.0.0/32` 或 `::/128`。
    /// 服务端以此形态回应不可满足的请求（Go `address.go:17-19`）。
    pub fn is_rejected(&self) -> bool {
        self.prefix == IpPrefix { addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED), prefix_len: 32 }
            || self.prefix == IpPrefix { addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED), prefix_len: 128 }
    }
}

/// 地址请求条目（ADDRESS_REQUEST；Go `addressRequestCapsule` 的
/// `RequestIDs[i]`+`Prefixes[i]` 平行切片，此处合并为条目）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressRequestEntry {
    /// 请求 ID（对端要求的回执键；恒非 0，Go `capsule.go:103-105`）。
    pub request_id: u64,
    /// 请求前缀。
    pub prefix: IpPrefix,
}

/// IP 前缀（Go `netip.Prefix`：addr 的主机位必须全 0，见 [`decode_prefix_entry`]）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpPrefix {
    /// 前缀地址。
    pub addr: IpAddr,
    /// 前缀长度（≤ 32/128）。
    pub prefix_len: u8,
}

/// IP 地址区间路由（ROUTE_ADVERTISEMENT 条目；Go `IPRoute`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpRoute {
    /// 区间起点（含）。
    pub start_ip: IpAddr,
    /// 区间终点（含）。
    pub end_ip: IpAddr,
    /// IP 协议号（0 = 全部）。
    pub ip_protocol: u8,
}

/// CONNECT-IP 胶囊（规划 §4.3 形态）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Capsule {
    /// IP 包（contextID=0 前缀已剥除，裸包）。
    Datagram(Vec<u8>),
    /// 服务端地址分配。
    AddressAssign(Vec<AssignedAddress>),
    /// 客户端地址请求。
    AddressRequest(Vec<AddressRequestEntry>),
    /// 路由通告。
    RouteAdvertisement(Vec<IpRoute>),
    /// 未知类型原样保留——读侧"跳过不报错"（Go `conn_test.go:385`
    /// `TestSkipUnknownCapsule`），丢弃决定权在会话层（B2 `connect.rs`）。
    Unknown {
        /// 原始胶囊类型值。
        ty: u64,
        /// 原始载荷。
        payload: Vec<u8>,
    },
}

/// 编码完整胶囊帧：`varint(type) varint(length) payload`（RFC 9297 §11.3）。
///
/// 与 Go `capsule.go` 各 `append` 同构：DATAGRAM 载荷 = `contextIDZero(0x00)` + 包
/// （Go `conn.go:667-677`）；地址/路由载荷 = 条目拼接，`length` = 条目总长。
pub fn encode_capsule(c: &Capsule) -> Result<Vec<u8>> {
    let mut payload = Vec::new();
    let ty = match c {
        Capsule::Datagram(packet) => {
            if packet.len() > MAX_CAPSULE_PAYLOAD {
                return Err(MasqueError::Mtu);
            }
            payload.push(0x00); // contextIDZero（Go proxy.go:18）
            payload.extend_from_slice(packet);
            CAPSULE_DATAGRAM
        },
        Capsule::AddressAssign(entries) => {
            encode_prefix_entries(&mut payload, entries.iter().map(|e| (e.request_id, &e.prefix)))?;
            CAPSULE_ADDRESS_ASSIGN
        },
        Capsule::AddressRequest(entries) => {
            encode_prefix_entries(&mut payload, entries.iter().map(|e| (e.request_id, &e.prefix)))?;
            CAPSULE_ADDRESS_REQUEST
        },
        Capsule::RouteAdvertisement(routes) => {
            if routes.len() > MAX_ENTRIES_PER_CAPSULE {
                return Err(too_many_entries("ROUTE_ADVERTISEMENT"));
            }
            for r in routes {
                payload.push(ip_version_byte(r.start_ip)?);
                payload.extend_from_slice(&ip_octets(r.start_ip));
                payload.extend_from_slice(&ip_octets(r.end_ip));
                payload.push(r.ip_protocol);
            }
            CAPSULE_ROUTE_ADVERTISEMENT
        },
        // Go 读侧对未知胶囊只跳过不回写；本仓也无转发未知胶囊的路径。
        Capsule::Unknown { ty, .. } => {
            return Err(MasqueError::Protocol(format!(
                "masque: unknown capsule type {ty} is not encodable"
            )));
        },
    };

    let mut frame =
        Vec::with_capacity(varint_len(ty) + varint_len(payload.len() as u64) + payload.len());
    frame.extend(varint_bytes(ty));
    frame.extend(varint_bytes(payload.len() as u64));
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// WARP（Cloudflare）变体的 DATAGRAM 帧：载荷 = 裸 IP 包，**无 contextID 前缀**
/// （Go `conn.go:667-671` 的 `bare` 分支）。
pub fn encode_bare_datagram(packet: &[u8]) -> Result<Vec<u8>> {
    if packet.len() > MAX_CAPSULE_PAYLOAD {
        return Err(MasqueError::Mtu);
    }
    let mut frame = Vec::with_capacity(
        varint_len(CAPSULE_DATAGRAM) + varint_len(packet.len() as u64) + packet.len(),
    );
    frame.extend(varint_bytes(CAPSULE_DATAGRAM));
    frame.extend(varint_bytes(packet.len() as u64));
    frame.extend_from_slice(packet);
    Ok(frame)
}

/// 解码一颗胶囊：`ty` + 裸载荷 → [`Capsule`]。
///
/// 返回 `Ok(None)` = 按丢语义跳过（Go `conn.go:467-471,513-520`）：DATAGRAM 载荷超
/// 上限 / contextID 非 0 / varint 畸形——均非错误（Go 侧丢弃并记 debug 日志）。
pub fn decode_capsule(ty: u64, payload: &[u8]) -> Result<Option<Capsule>> {
    match ty {
        CAPSULE_DATAGRAM => {
            // Go conn.go:468：超 `len(contextIDZero)+maxCapsulePacketSize` 整颗丢弃。
            if payload.len() > 1 + MAX_CAPSULE_PAYLOAD {
                return Ok(None);
            }
            let mut cur = Cursor::new(payload);
            // Go conn.go:513-517：varint 畸形（含空载荷）按丢弃处理。
            let Ok(context_id) = read_varint(&mut cur) else {
                return Ok(None);
            };
            if context_id != 0 {
                // Go conn.go:518-520：非 0 contextID 不属于本会话，丢弃。
                return Ok(None);
            }
            let packet = &payload[cur.position() as usize..];
            Ok(Some(Capsule::Datagram(packet.to_vec())))
        },
        CAPSULE_ADDRESS_ASSIGN => {
            let entries = decode_prefix_entries(payload, false)?
                .into_iter()
                .map(|e| AssignedAddress { request_id: e.request_id, prefix: e.prefix })
                .collect();
            Ok(Some(Capsule::AddressAssign(entries)))
        },
        CAPSULE_ADDRESS_REQUEST => {
            let entries = decode_prefix_entries(payload, true)?;
            Ok(Some(Capsule::AddressRequest(entries)))
        },
        CAPSULE_ROUTE_ADVERTISEMENT => {
            let routes = decode_routes(payload)?;
            Ok(Some(Capsule::RouteAdvertisement(routes)))
        },
        _ => Ok(Some(Capsule::Unknown { ty, payload: payload.to_vec() })),
    }
}

/// WARP 变体的解帧入口：bare 模式下 DATAGRAM 载荷即裸 IP 包（无 contextID 前缀），
/// 但首字节为 0 时仍按标准 varint 形态解析（Go `conn.go:512-521` 的 `bare` 分支）。
pub fn decode_capsule_bare(ty: u64, payload: &[u8]) -> Result<Option<Capsule>> {
    if ty == CAPSULE_DATAGRAM && !payload.is_empty() && payload[0] != 0 {
        return Ok(
            (payload.len() <= MAX_CAPSULE_PAYLOAD).then(|| Capsule::Datagram(payload.to_vec()))
        );
    }
    decode_capsule(ty, payload)
}

// ===== 地址/路由条目编解码（Go capsule.go:48-56,76-83,145-152,262-277） =====

fn encode_prefix_entries<'a>(
    payload: &mut Vec<u8>,
    entries: impl Iterator<Item = (u64, &'a IpPrefix)>,
) -> Result<()> {
    let entries: Vec<(u64, &IpPrefix)> = entries.collect();
    if entries.len() > MAX_ENTRIES_PER_CAPSULE {
        return Err(too_many_entries("ADDRESS"));
    }
    for (request_id, prefix) in entries {
        payload.extend(varint_bytes(request_id));
        payload.push(ip_version_byte(prefix.addr)?);
        payload.extend_from_slice(&ip_octets(prefix.addr));
        payload.push(prefix.prefix_len);
    }
    Ok(())
}

/// 解析 {varint reqID, 版本字节, 地址字节, 前缀长字节} 条目序列
/// （Go `parseAddress`，capsule.go:135-177）。
///
/// `require_request`：ADDRESS_REQUEST 额外要求非空载荷 + reqID ≠ 0
/// （Go `capsule.go:93-95,103-105`）；ADDRESS_ASSIGN 允许空载荷（0 条目）。
fn decode_prefix_entries(
    payload: &[u8],
    require_request: bool,
) -> Result<Vec<AddressRequestEntry>> {
    if require_request && payload.is_empty() {
        return Err(MasqueError::Protocol(
            "masque: ADDRESS_REQUEST capsule contains no addresses".into(),
        ));
    }
    let mut cur = Cursor::new(payload);
    let mut entries = Vec::new();
    while (cur.position() as usize) < payload.len() {
        if entries.len() >= MAX_ENTRIES_PER_CAPSULE {
            return Err(too_many_entries("ADDRESS"));
        }
        let request_id = read_varint(&mut cur)
            .map_err(|e| MasqueError::Protocol(format!("masque: truncated capsule entry: {e}")))?;
        if require_request && request_id == 0 {
            return Err(MasqueError::Protocol(
                "masque: ADDRESS_REQUEST capsule contains a zero request ID".into(),
            ));
        }
        let prefix = decode_prefix_entry(&mut cur)?;
        entries.push(AddressRequestEntry { request_id, prefix });
    }
    Ok(entries)
}

/// 单条地址前缀解析（Go `parseAddress`，capsule.go:135-177）：
/// 版本字节 → 地址字节 → 前缀长字节；前缀长不得超位长，且被前缀覆盖外的低位必须全 0。
fn decode_prefix_entry(cur: &mut Cursor<&[u8]>) -> Result<IpPrefix> {
    let mut version = [0u8; 1];
    cur.read_exact(&mut version)
        .map_err(|e| MasqueError::Protocol(format!("masque: truncated capsule entry: {e}")))?;
    let (expect_len, bit_len) = match version[0] {
        4 => (4usize, 32u8),
        6 => (16usize, 128u8),
        v => {
            return Err(MasqueError::Protocol(format!("masque: invalid IP version: {v}")));
        },
    };
    let mut octets = vec![0u8; expect_len];
    cur.read_exact(&mut octets)
        .map_err(|e| MasqueError::Protocol(format!("masque: truncated capsule entry: {e}")))?;
    let mut prefix_len = [0u8; 1];
    cur.read_exact(&mut prefix_len)
        .map_err(|e| MasqueError::Protocol(format!("masque: truncated capsule entry: {e}")))?;
    let addr = if expect_len == 4 {
        IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]))
    } else {
        let mut b = [0u8; 16];
        b.copy_from_slice(&octets);
        IpAddr::V6(Ipv6Addr::from(b))
    };
    let prefix_len = prefix_len[0];
    if prefix_len > bit_len {
        return Err(MasqueError::Protocol(format!(
            "masque: prefix length {prefix_len} exceeds IP address length ({bit_len})"
        )));
    }
    if !is_masked(&addr, prefix_len) {
        return Err(MasqueError::Protocol(
            "masque: lower bits not covered by prefix length are not all zero".into(),
        ));
    }
    Ok(IpPrefix { addr, prefix_len })
}

/// 被前缀覆盖外的低位是否全 0（Go `prefix != prefix.Masked()` 等价判定）。
pub(crate) fn is_masked(addr: &IpAddr, prefix_len: u8) -> bool {
    let octets: [u8; 16] = match addr {
        // v4 补零对齐到 16 字节：prefix_len ≤ 32 ⇒ 只会索引 0..=4，补零段不影响判定。
        IpAddr::V4(a) => {
            let mut padded = [0u8; 16];
            padded[..4].copy_from_slice(&a.octets());
            padded
        },
        IpAddr::V6(a) => a.octets(),
    };
    let full = (prefix_len / 8) as usize;
    if octets[full..].iter().any(|&b| b != 0) {
        return false;
    }
    let rem = prefix_len % 8;
    rem == 0 || octets[full] & (0xFFu8 >> rem) == 0
}

// ===== ROUTE_ADVERTISEMENT（Go capsule.go:145-152,155-184,262-277） =====

fn decode_routes(payload: &[u8]) -> Result<Vec<IpRoute>> {
    let mut cur = Cursor::new(payload);
    let mut routes = Vec::new();
    while (cur.position() as usize) < payload.len() {
        if routes.len() >= MAX_ENTRIES_PER_CAPSULE {
            return Err(too_many_entries("ROUTE_ADVERTISEMENT"));
        }
        let mut buf = [0u8; 1];
        cur.read_exact(&mut buf)
            .map_err(|e| MasqueError::Protocol(format!("masque: truncated capsule entry: {e}")))?;
        let width = match buf[0] {
            4 => 4usize,
            6 => 16usize,
            v => {
                return Err(MasqueError::Protocol(format!("masque: invalid IP version: {v}")));
            },
        };
        let mut start = vec![0u8; width];
        let mut end = vec![0u8; width];
        cur.read_exact(&mut start)
            .map_err(|e| MasqueError::Protocol(format!("masque: truncated capsule entry: {e}")))?;
        cur.read_exact(&mut end)
            .map_err(|e| MasqueError::Protocol(format!("masque: truncated capsule entry: {e}")))?;
        cur.read_exact(&mut buf)
            .map_err(|e| MasqueError::Protocol(format!("masque: truncated capsule entry: {e}")))?;
        let start_ip = ip_from_octets(&start);
        let end_ip = ip_from_octets(&end);
        // Go parseIPAddressRange（capsule.go:284-287）：区间内 start ≤ end。
        if start_ip > end_ip {
            return Err(MasqueError::Protocol("masque: start IP is greater than end IP".into()));
        }
        let route = IpRoute { start_ip, end_ip, ip_protocol: buf[0] };
        // Go parseRouteAdvertisementCapsule（capsule.go:200-208）：相邻条目有序不重叠。
        if let Some(prev) = routes.last() {
            check_route_order(prev, &route)?;
        }
        routes.push(route);
    }
    Ok(routes)
}

/// 相邻路由条目次序校验（Go `checkRouteOrder`，capsule.go:211-229）：
/// 按 (位长, IP 协议号) 升序；位长与协议都相同时区间必须严格升序不重叠。
fn check_route_order(a: &IpRoute, b: &IpRoute) -> Result<()> {
    let mismatch = MasqueError::Protocol(format!(
        "masque: routes are not ordered by IP version and IP protocol: {}-{} precedes {}-{}",
        a.start_ip, a.end_ip, b.start_ip, b.end_ip
    ));
    let overlap = MasqueError::Protocol(format!(
        "masque: IP address ranges {}-{} and {}-{} overlap or are not in ascending order",
        a.start_ip, a.end_ip, b.start_ip, b.end_ip
    ));
    match ip_bit_len(a.start_ip)
        .cmp(&ip_bit_len(b.start_ip))
        .then(a.ip_protocol.cmp(&b.ip_protocol))
    {
        std::cmp::Ordering::Greater => Err(mismatch),
        std::cmp::Ordering::Equal if a.end_ip >= b.start_ip => Err(overlap),
        _ => Ok(()),
    }
}

// ===== 小工具 =====

fn too_many_entries(kind: &str) -> MasqueError {
    MasqueError::Protocol(format!(
        "masque: {kind} capsule contains too many entries (maximum {MAX_ENTRIES_PER_CAPSULE})"
    ))
}

fn ip_version_byte(addr: IpAddr) -> Result<u8> {
    match addr {
        IpAddr::V4(_) => Ok(4),
        IpAddr::V6(_) => Ok(6),
    }
}

fn ip_octets(addr: IpAddr) -> Vec<u8> {
    match addr {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    }
}

fn ip_from_octets(bytes: &[u8]) -> IpAddr {
    if bytes.len() == 4 {
        IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
    } else {
        let mut b = [0u8; 16];
        b.copy_from_slice(bytes);
        IpAddr::V6(Ipv6Addr::from(b))
    }
}

pub(crate) fn ip_bit_len(addr: IpAddr) -> u8 {
    match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

/// varint → bytes（`write_varint` 需要预分配缓冲，不增长 Vec）。
fn varint_bytes(v: u64) -> Vec<u8> {
    let mut b = [0u8; 8];
    let n = write_varint(&mut b, v);
    b[..n].to_vec()
}
