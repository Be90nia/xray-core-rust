//! 隧道内 DNS 解析（Go `proxy/wireguard/netstack.go LookupContextHost` 经
//! `wireguard.Net.Dial` 的域名语义；Go `proxy/masque/client.go newTunnel`
//! 的 `remoteDNS` 面对应）。
//!
//! 查询形态：栈内 UDP socket → DNS 查询 IP 包（A/AAAA 各一）→ 栈路由进隧道
//! → 应答经隧道回栈 → socket recv。TTL 取各记录最小值（Go c7e56b0 语义）。
//!
//! 与 wireguard `dispatcher.rs` 的同构函数为**同语义重写**（其侧 `pub(crate)`
//! 跨 crate 不可见；公共提炼归 xray-frame/dispatcher 需 PM 裁决——见 crate
//! 文档）。RFC 1035 wire 编码为公共面候选。

use std::{net::IpAddr, sync::Arc, time::Duration};

use tokio::sync::Mutex as AsyncMutex;
use xray_frame::ipstack::PacketStack;

use crate::{LOG, relay};

/// 单 server 查询超时。
const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(3);

/// 构造 DNS 查询（RFC 1035）：单 question，RD=1。
fn dns_build_query(name: &str, want_a: bool, req_id: u16) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(12 + name.len() + 6);
    out.extend_from_slice(&req_id.to_be_bytes());
    // flags: RD=1 (0x0100)；QDCOUNT=1。
    out.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    // QNAME：标签序列。
    for label in name.split('.') {
        if label.is_empty() {
            return Err(format!("empty DNS label in {name:?}"));
        }
        let bytes = label.as_bytes();
        if bytes.len() > 63 {
            return Err(format!("DNS label too long in {name:?}"));
        }
        out.push(bytes.len() as u8);
        out.extend_from_slice(bytes);
    }
    out.push(0); // 根标签终结。
    // QTYPE：A=1 / AAAA=28；QCLASS=IN。
    let qtype: u16 = if want_a { 1 } else { 28 };
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&[0x00, 0x01]);
    Ok(out)
}

/// 解析 DNS 响应：提取全部 A/AAAA 记录 + 记录最小 TTL（Go `LookupContextHost`
/// `ttl := uint32(300)` 起步逐记录 min 语义）。`req_id` 不匹配报错；rcode!=0
/// 或无答案返回空。
fn dns_parse_ips(payload: &[u8], req_id: u16) -> Result<(Vec<IpAddr>, u32), String> {
    if payload.len() < 12 {
        return Err("DNS response too short".into());
    }
    if u16::from_be_bytes([payload[0], payload[1]]) != req_id {
        return Err("DNS response ID mismatch".into());
    }
    let rcode = payload[3] & 0x0f;
    if rcode != 0 {
        return Ok((Vec::new(), 0));
    }
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    let ancount = u16::from_be_bytes([payload[6], payload[7]]);
    let mut pos = 12usize;
    for _ in 0..qdcount {
        dns_skip_name(payload, &mut pos)?;
        pos += 4; // QTYPE + QCLASS。
    }
    let mut ips = Vec::new();
    let mut min_ttl = u32::MAX;
    for _ in 0..ancount {
        dns_skip_name(payload, &mut pos)?;
        if pos + 10 > payload.len() {
            return Err("DNS answer truncated".into());
        }
        let rtype = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let ttl = u32::from_be_bytes([
            payload[pos + 4],
            payload[pos + 5],
            payload[pos + 6],
            payload[pos + 7],
        ]);
        let rdlength = u16::from_be_bytes([payload[pos + 8], payload[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlength > payload.len() {
            return Err("DNS rdata truncated".into());
        }
        let rdata = &payload[pos..pos + rdlength];
        pos += rdlength;
        match (rtype, rdlength) {
            (1, 4) => {
                ips.push(IpAddr::V4(std::net::Ipv4Addr::new(
                    rdata[0], rdata[1], rdata[2], rdata[3],
                )));
                min_ttl = min_ttl.min(ttl);
            },
            (28, 16) => {
                let mut o = [0u8; 16];
                o.copy_from_slice(rdata);
                ips.push(IpAddr::V6(std::net::Ipv6Addr::from(o)));
                min_ttl = min_ttl.min(ttl);
            },
            _ => {},
        }
    }
    let ttl = if min_ttl == u32::MAX { 300 } else { min_ttl };
    Ok((ips, ttl))
}

/// 跳过 name 字段（标签序列或 `0xC0` 压缩指针，RFC 1035 §4.1.4）。
fn dns_skip_name(payload: &[u8], pos: &mut usize) -> Result<(), String> {
    loop {
        let Some(&len) = payload.get(*pos) else {
            return Err("DNS name truncated".into());
        };
        if len & 0xC0 == 0xC0 {
            // 压缩指针：2 字节。
            *pos += 2;
            return Ok(());
        }
        *pos += 1;
        if len == 0 {
            return Ok(());
        }
        *pos += len as usize;
    }
}

/// 隧道内域名解析（Go `client.go:351-360 resolveRemote` → `tnet.LookupHost`）。
/// 接口地址族约束查询类型（v4-only 栈只发 A）；双栈 A/AAAA 各查后按族过滤。
/// 返回（可用 IP 列表，记录最小 TTL 秒）。取舍：不走本地 DnsService、TC 截断
/// 不重试 TCP（公共 DNS A/AAAA 极少超 MTU）。
pub(crate) async fn resolve_domain_in_tunnel(
    stack: &Arc<AsyncMutex<PacketStack>>,
    domain: &str,
    has_v4: bool,
    has_v6: bool,
    servers: &[IpAddr],
) -> Result<(Vec<IpAddr>, u32), String> {
    let mut ips = Vec::new();
    let mut min_ttl = u32::MAX;
    let want_a = has_v4;
    let want_aaaa = has_v6;
    for server in servers {
        for want in [want_a, want_aaaa].into_iter().filter(|w| *w) {
            let req_id = {
                use std::{
                    collections::hash_map::RandomState,
                    hash::{BuildHasher, Hasher},
                };
                RandomState::new().build_hasher().finish() as u16 | 1
            };
            let query = dns_build_query(domain, want, req_id)?;
            match dns_query_via_stack(stack, server, &query, req_id).await {
                Ok((mut got, ttl)) => {
                    ips.append(&mut got);
                    if ttl > 0 {
                        min_ttl = min_ttl.min(ttl);
                    }
                },
                Err(e) => LOG.debug(format!("masque dns: query {domain} via {server} failed: {e}")),
            }
        }
        if !ips.is_empty() {
            break; // Go dice/first-hit：首个有答案的 server 收敛。
        }
    }
    ips.retain(|ip| match ip {
        IpAddr::V4(_) => has_v4,
        IpAddr::V6(_) => has_v6,
    });
    ips.dedup();
    let ttl = if min_ttl == u32::MAX { 300 } else { min_ttl };
    Ok((ips, ttl))
}

/// 经栈发单条 DNS 查询并等应答（栈内 UDP socket 临时端口 → 栈路由进隧道）。
async fn dns_query_via_stack(
    stack: &Arc<AsyncMutex<PacketStack>>,
    server: &IpAddr,
    query: &[u8],
    req_id: u16,
) -> Result<(Vec<IpAddr>, u32), String> {
    let server_addr = match server {
        IpAddr::V4(v4) => smoltcp::wire::IpAddress::Ipv4(
            #[allow(clippy::incompatible_msrv)] // 工作区实际工具链新于 MSRV=1.85，该 API 受控使用
            smoltcp::wire::Ipv4Address::from(v4.octets()),
        ),
        IpAddr::V6(v6) => smoltcp::wire::IpAddress::Ipv6(
            #[allow(clippy::incompatible_msrv)] // 工作区实际工具链新于 MSRV=1.85，该 API 受控使用
            smoltcp::wire::Ipv6Address::from(v6.octets()),
        ),
    };
    let server_ep = smoltcp::wire::IpEndpoint::new(server_addr, 53);
    let handle = {
        let mut s = stack.lock().await;
        let h = s.add_udp_socket();
        let bound = s.with_udp_socket(h, relay::bind_ephemeral);
        let sent = bound && s.with_udp_socket(h, |sock| sock.send_slice(query, server_ep).is_ok());
        s.poll(smoltcp::time::Instant::now());
        if !sent {
            s.remove_socket(h);
            return Err("dns query socket send failed".into());
        }
        h
    };
    let deadline = xray_frame::compat::clock().now_instant() + DNS_QUERY_TIMEOUT;
    loop {
        let received = {
            let mut s = stack.lock().await;
            s.poll(smoltcp::time::Instant::now());
            s.with_udp_socket(handle, |sock| {
                let mut scratch = vec![0u8; 4096];
                sock.recv_slice(&mut scratch)
                    .ok()
                    .map(|(n, meta)| (scratch[..n].to_vec(), meta.endpoint))
            })
        };
        if let Some((payload, ep)) = received {
            if ep == server_ep {
                let mut s = stack.lock().await;
                s.remove_socket(handle);
                return dns_parse_ips(&payload, req_id);
            }
        }
        if xray_frame::compat::clock().now_instant() >= deadline {
            let mut s = stack.lock().await;
            s.remove_socket(handle);
            return Err("dns query timeout".into());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
