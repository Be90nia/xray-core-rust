//! MASQUE 客户端出站（Go `proxy/masque/client.go` 直译形态 + wireguard
//! dispatcher 桥形态，规划 B4.3）。
//!
//! 流程（DialFn 闭包）：拨 CONNECT-IP 隧道（`xray-transport-masque::dialer::dial`，
//! finalmask→TLS→h2→establish）→ 隧道栈（[`PacketStack`]，地址 = 会话分配结果）。
//! 双泵：下行 `recv_packet → ingest_rx`，上行轮询 `drain_tx → send_packet`。
//! 目标拨号：TCP = 栈内 connect + [`StackTcpRelay`]；UDP = 栈内 socket +
//! XUDP 帧约定（dispatcher UDP link 语义）；域名 = 隧道内 DNS（remoteDNS）。
//!
//! `shortcut:`（规划 R15/非目标 5）：每 outbound 连接一条隧道（Go 用 xmux
//! 池化握手；本批不接池——握手成本 A/B 证据成立时另批移动 `splithttp::mux`）。

use std::{future::Future, io, net::IpAddr, sync::Arc};

use rand::Rng as _;
use skeleton_infra::fx::Spawned;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use xray_app_dispatcher::default::DialFn;
use xray_common::net::{address::Address, destination::Destination, network::Network, port::Port};
use xray_frame::{context::PluginContext, ipstack::PacketStack};
use xray_transport::{connection::Connection, dialer::StreamSettings, sockopt::SocketOptions};
use xray_transport_masque::{config::Config as MasqueConfig, connect::MIN_PACKET_SIZE};
use xray_xudp::packet::PacketWriter;

use crate::{LOG, dns, relay};

/// 客户端 settings（Go `infra/conf/masque.go MasqueClientConfig` 同规）。
#[derive(Debug, Clone)]
pub struct MasqueClientSettings {
    /// MASQUE 服务器地址（拨号目标；Go `address`）。
    pub address: Address,
    /// 服务器端口（Go `port`；0 = 未设置 → `Err`）。
    pub port: u16,
    /// 隧道内 DNS 服务器（Go `remoteDNS`；空 = Go 缺省四址）。
    pub remote_dns: Vec<IpAddr>,
}

/// Go `client.go:113-115` 缺省 remoteDNS。
const DEFAULT_REMOTE_DNS: [IpAddr; 4] = [
    IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
    IpAddr::V4(std::net::Ipv4Addr::new(1, 0, 0, 1)),
    IpAddr::V6(std::net::Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
    IpAddr::V6(std::net::Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1001)),
];

/// outbound settings JSON → [`MasqueClientSettings`]（装配负向：缺 address /
/// port → `Err`；Go `Build()` 同款文案）。
pub fn parse_client_settings(v: &serde_json::Value) -> Result<MasqueClientSettings, String> {
    let address_text = v.get("address").and_then(|a| a.as_str()).ok_or("\"address\" is not set")?;
    let address: Address =
        address_text.parse().map_err(|e| format!("invalid address {address_text:?}: {e}"))?;
    let port_raw = v.get("port").and_then(|p| p.as_u64()).unwrap_or(0);
    if port_raw == 0 {
        return Err("\"port\" is not set".into());
    }
    let port = u16::try_from(port_raw).map_err(|_| "\"port\" overflow".to_string())?;
    let mut remote_dns = Vec::new();
    if let Some(list) = v.get("remoteDNS").and_then(|r| r.as_array()) {
        for s in list {
            let text = s.as_str().ok_or("remoteDNS entries must be strings")?;
            let ip: IpAddr =
                text.parse().map_err(|e| format!("invalid remote DNS server {text:?}: {e}"))?;
            remote_dns.push(ip);
        }
    }
    Ok(MasqueClientSettings { address, port, remote_dns })
}

/// DNS 缓存条目：(解析结果 IP 列表, TTL 秒, 写入时刻)。
type DnsCacheEntry = (Vec<IpAddr>, u32, std::time::Instant);

/// 域名解析 TTL 缓存（Go `Handler.cache` 形态；容量宽松兜底——挤出 = 下次
/// miss 重查，语义无害）。时间源 = compat clock。
struct DnsCache {
    entries: std::sync::Mutex<std::collections::HashMap<String, DnsCacheEntry>>,
}

const DNS_CACHE_CAP: usize = 1024;

impl DnsCache {
    fn new() -> Self {
        Self { entries: std::sync::Mutex::new(std::collections::HashMap::new()) }
    }

    fn get(&self, domain: &str) -> Option<Vec<IpAddr>> {
        let mut map = self.entries.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let (ips, ttl, at) = map.get(domain)?;
        let elapsed =
            xray_frame::compat::clock().now_system().duration_since(std::time::UNIX_EPOCH).ok()?;
        let _ = elapsed;
        // TTL 判定走 compat instant 面（SystemClock 单调）。
        if xray_frame::compat::clock().now_instant()
            >= *at + std::time::Duration::from_secs(u64::from(*ttl))
        {
            map.remove(domain);
            return None;
        }
        Some(ips.clone())
    }

    fn put(&self, domain: &str, ips: Vec<IpAddr>, ttl: u32) {
        let mut map = self.entries.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if map.len() >= DNS_CACHE_CAP {
            map.clear(); // 容量兜底：整表清（TTL 缓存挤出无语义损失）。
        }
        map.insert(domain.to_owned(), (ips, ttl, xray_frame::compat::clock().now_instant()));
    }
}

/// 隧道生命周期守卫：Connection drop → 泵 abort（下行泵任务持有会话本体，
/// abort 即 future drop → 会话 Drop 中止写泵 + 半关闭，fd 滞留防线与 grpc
/// driver 教训同源）。
struct TunnelGuard {
    pumps: Vec<Spawned<()>>,
}

impl Drop for TunnelGuard {
    fn drop(&mut self) {
        for p in self.pumps.drain(..) {
            p.abort();
        }
    }
}

/// 隧道连接（duplex 两半 + 守卫；读 = relay→client 半，写 = client→relay 半——
/// wireguard `WireguardConnection::new(read, write)` 同形态，两个 duplex 各
/// 单向桥接）。
struct TunnelConn {
    read_half: tokio::io::DuplexStream,
    write_half: tokio::io::DuplexStream,
    _guard: Arc<std::sync::Mutex<TunnelGuard>>,
}

impl tokio::io::AsyncRead for TunnelConn {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let half = &mut self.as_mut().read_half;
        std::pin::pin!(half).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for TunnelConn {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let half = &mut self.as_mut().write_half;
        std::pin::pin!(half).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let half = &mut self.as_mut().write_half;
        std::pin::pin!(half).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let half = &mut self.as_mut().write_half;
        std::pin::pin!(half).poll_shutdown(cx)
    }
}

impl Connection for TunnelConn {
    fn remote_addr(&self) -> io::Result<Option<std::net::SocketAddr>> {
        Ok(None)
    }

    fn local_addr(&self) -> io::Result<Option<std::net::SocketAddr>> {
        Ok(None)
    }
}

type DialResult = std::result::Result<Box<dyn Connection>, String>;

/// 构造 DialBridge 用的 DialFn（wireguard `make_wireguard_dial_fn` 同构形态）。
///
/// 每次调用建一条新隧道 + 新栈（R15 shortcut）；域名目标经隧道内 DNS
/// （remoteDNS，Go `LookupContextHost` 语义）。
#[must_use]
pub fn make_masque_dial_fn(
    client: MasqueClientSettings,
    transport_settings: StreamSettings,
    sockopt: SocketOptions,
    ctx: Arc<PluginContext>,
) -> DialFn {
    let masque_cfg = |ts: &StreamSettings| -> Result<MasqueConfig, String> {
        MasqueConfig::from_json(ts.transport_json.as_ref()).map_err(|e| e.to_string())
    };
    let remote_dns = if client.remote_dns.is_empty() {
        DEFAULT_REMOTE_DNS.to_vec()
    } else {
        client.remote_dns.clone()
    };
    let server_dest =
        Destination::new(client.address.clone(), Port::new(client.port), Network::TCP);
    let dns_cache = Arc::new(DnsCache::new());

    Arc::new(move |dest: &Destination| {
        let dest = dest.clone();
        let ts = transport_settings.clone();
        let so = sockopt.clone();
        let cfg = match masque_cfg(&ts) {
            Ok(c) => c,
            Err(e) => {
                return Box::pin(async move { Err(e) })
                    as std::pin::Pin<Box<dyn Future<Output = DialResult> + Send>>;
            },
        };
        let ctx = Arc::clone(&ctx);
        let dns_cache = Arc::clone(&dns_cache);
        let remote_dns = remote_dns.clone();
        let server_dest = server_dest.clone();
        Box::pin(async move {
            // 1. 拨隧道（transport 层 finalmask/TLS/h2/establish 全链）。
            let mut session = xray_transport_masque::dialer::dial(&server_dest, &so, &ts, &cfg)
                .await
                .map_err(|e| format!("masque tunnel dial: {e}"))?;
            let local = session.local_addrs().to_vec();
            if local.is_empty() {
                session.close();
                return Err("masque tunnel: no local address assigned".into());
            }
            // 2. 隧道栈 + 双泵（下行泵独占会话本体；abort = drop → fd 回收）。
            let cidrs: Vec<smoltcp::wire::IpCidr> = local.iter().map(|a| ip_to_cidr(*a)).collect();
            let stack =
                Arc::new(tokio::sync::Mutex::new(PacketStack::new(&cidrs, MIN_PACKET_SIZE)));
            let up_writer = session.writer().ok();
            let down_stack = Arc::clone(&stack);
            let down_pump = ctx
                .spawn(async move {
                    loop {
                        match session.recv_packet().await {
                            Ok(pkt) => {
                                let mut s = down_stack.lock().await;
                                s.ingest_rx(pkt);
                                s.poll(smoltcp::time::Instant::now());
                            },
                            Err(_) => return,
                        }
                    }
                })
                .map_err(|_| "masque: scope closed".to_string())?;
            // 上行泵：栈出站包 → 会话（写面 SessionWriter 共享句柄）。
            let up_stack = Arc::clone(&stack);
            let up_pump = ctx
                .spawn(async move {
                    let mut writer = up_writer;
                    let mut timer = tokio::time::interval(std::time::Duration::from_millis(5));
                    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                    timer.tick().await;
                    loop {
                        timer.tick().await;
                        let Some(writer) = writer.as_mut() else { return };
                        let mut s = up_stack.lock().await;
                        s.poll(smoltcp::time::Instant::now());
                        for pkt in s.drain_tx() {
                            match writer.send_packet(&pkt).await {
                                Ok(Some(icmp)) => {
                                    s.ingest_rx(icmp);
                                },
                                Ok(None) => {},
                                Err(_) => return,
                            }
                        }
                        drop(s);
                    }
                })
                .map_err(|_| "masque: scope closed".to_string())?;
            let pumps = vec![down_pump, up_pump];
            let guard = Arc::new(std::sync::Mutex::new(TunnelGuard { pumps }));

            // 3. 域名目标 → 隧道内 DNS（remoteDNS 按族过滤；Go LookupContextHost）。
            let dest = match dest.address() {
                Address::Domain(domain) => {
                    let has_v4 = local.iter().any(|a| a.is_ipv4());
                    let has_v6 = local.iter().any(|a| a.is_ipv6());
                    let ips = match dns_cache.get(domain) {
                        Some(ips) => ips,
                        None => {
                            let (ips, ttl) = dns::resolve_domain_in_tunnel(
                                &stack,
                                domain,
                                has_v4,
                                has_v6,
                                &remote_dns,
                            )
                            .await?;
                            if ips.is_empty() {
                                return Err(format!(
                                    "masque: DNS lookup for {domain} returned no usable address"
                                ));
                            }
                            dns_cache.put(domain, ips.clone(), ttl);
                            ips
                        },
                    };
                    let ip = ips[thread_rng_choice(ips.len())];
                    let addr = match ip {
                        IpAddr::V4(v4) => Address::IPv4(v4),
                        IpAddr::V6(v6) => Address::IPv6(v6),
                    };
                    // Destination 无 with_address——重建（wireguard 同款形态）。
                    Destination::new(addr, dest.port(), dest.network())
                },
                _ => dest,
            };

            // 4. 栈内目标拨号。
            match dest.network() {
                Network::TCP => {
                    let ip = match dest.address() {
                        Address::IPv4(v4) => smoltcp::wire::IpAddress::Ipv4(
                            #[allow(clippy::incompatible_msrv)]
                            // 工作区实际工具链新于 MSRV=1.85，该 API 受控使用
                            smoltcp::wire::Ipv4Address::from(v4.octets()),
                        ),
                        Address::IPv6(v6) => smoltcp::wire::IpAddress::Ipv6(
                            #[allow(clippy::incompatible_msrv)]
                            // 工作区实际工具链新于 MSRV=1.85，该 API 受控使用
                            smoltcp::wire::Ipv6Address::from(v6.octets()),
                        ),
                        Address::Domain(_) => {
                            return Err("masque: domain target unresolved".into());
                        },
                    };
                    let handle = {
                        let mut s = stack.lock().await;
                        let h = s.add_tcp_socket();
                        s.tcp_connect(h, ip, dest.port().value())
                            .map_err(|e| format!("smoltcp tcp_connect: {e}"))?;
                        h
                    };
                    let connected = relay::wait_tcp_connected(&stack, handle).await;
                    if !connected {
                        let mut s = stack.lock().await;
                        s.remove_socket(handle);
                        return Err("masque outbound: tcp connect timeout or failed".into());
                    }
                    let (client_to_relay, relay_from_client) = tokio::io::duplex(relay::DUPLEX_BUF);
                    let (relay_to_client, client_from_relay) = tokio::io::duplex(relay::DUPLEX_BUF);
                    let relay_task = relay::StackTcpRelay {
                        from_client: relay_from_client,
                        to_client: relay_to_client,
                        stack: Arc::clone(&stack),
                        handle,
                    };
                    ctx.spawn(async move { relay_task.run().await })
                        .map_err(|_| "masque: scope closed".to_string())?;
                    Ok(Box::new(TunnelConn {
                        read_half: client_from_relay,
                        write_half: client_to_relay,
                        _guard: Arc::clone(&guard),
                    }) as Box<dyn Connection>)
                },
                Network::UDP => {
                    // XUDP 帧约定（dispatcher UDP link 语义；wireguard UdpRelay 同构）。
                    let handle = {
                        let mut s = stack.lock().await;
                        let h = s.add_udp_socket();
                        s.with_udp_socket(h, relay::bind_ephemeral);
                        h
                    };
                    let (client_to_relay, mut relay_from_client) =
                        tokio::io::duplex(relay::DUPLEX_BUF);
                    let (mut relay_to_client, client_from_relay) =
                        tokio::io::duplex(relay::DUPLEX_BUF);
                    let stack_for_relay = Arc::clone(&stack);
                    let default_dest = dest.clone();
                    ctx.spawn(async move {
                        let mut acc = Vec::new();
                        let mut scratch = vec![0u8; 65535];
                        loop {
                            tokio::select! {
                                read = relay_from_client.read(&mut scratch) => {
                                    match read {
                                        Ok(0) | Err(_) => return,
                                        Ok(n) => {
                                            pump_client_to_udp(
                                                &stack_for_relay, handle,
                                                &scratch[..n], &default_dest,
                                                &mut acc,
                                            ).await;
                                        },
                                    }
                                },
                                _ = tokio::time::sleep(std::time::Duration::from_millis(5)) => {
                                    if let Some(out) = pump_udp_to_client(
                                        &stack_for_relay, handle, &default_dest,
                                        &mut scratch,
                                    ).await {
                                        if relay_to_client.write_all(&out).await.is_err() {
                                            return;
                                        }
                                    }
                                },
                            }
                        }
                    })
                    .map_err(|_| "masque: scope closed".to_string())?;
                    Ok(Box::new(TunnelConn {
                        read_half: client_from_relay,
                        write_half: client_to_relay,
                        _guard: Arc::clone(&guard),
                    }) as Box<dyn Connection>)
                },
                Network::Unix => Err("masque outbound does not support Unix socket".into()),
            }
        }) as std::pin::Pin<Box<dyn Future<Output = DialResult> + Send>>
    })
}

// ===== 局部工具面 =====

/// `ips` 随机取一（Go `dice.Roll` 语义）。
fn thread_rng_choice(len: usize) -> usize {
    #[allow(deprecated)] // 存量清零批次
    rand::thread_rng().gen_range(0..len.max(1))
}

/// `ip` → smoltcp IpCidr（/32 / /128）。
fn ip_to_cidr(addr: IpAddr) -> smoltcp::wire::IpCidr {
    let (address, len) = match addr {
        IpAddr::V4(v) => (
            smoltcp::wire::IpAddress::Ipv4(
                #[allow(clippy::incompatible_msrv)]
                // 工作区实际工具链新于 MSRV=1.85，该 API 受控使用
                smoltcp::wire::Ipv4Address::from(v.octets()),
            ),
            32,
        ),
        IpAddr::V6(v) => (
            smoltcp::wire::IpAddress::Ipv6(
                #[allow(clippy::incompatible_msrv)]
                // 工作区实际工具链新于 MSRV=1.85，该 API 受控使用
                smoltcp::wire::Ipv6Address::from(v.octets()),
            ),
            128,
        ),
    };
    smoltcp::wire::IpCidr::new(address, len)
}

/// 上行：duplex 字节 → XUDP 帧 → 栈内 UDP socket（wireguard
/// `pump_client_to_udp` 同构；`acc` 跨调用保持未消费半帧，坏帧丢弃重同步）。
async fn pump_client_to_udp(
    stack: &Arc<tokio::sync::Mutex<PacketStack>>,
    handle: smoltcp::iface::SocketHandle,
    bytes: &[u8],
    default_dest: &Destination,
    acc: &mut Vec<u8>,
) {
    use xray_xudp::packet::PacketReader;
    if bytes.is_empty() {
        return;
    }
    acc.extend_from_slice(bytes);
    loop {
        let frame = {
            let mut cursor = std::io::Cursor::new(&acc[..]);
            let mut reader = PacketReader::new(&mut cursor);
            match reader.read_packet() {
                Ok(Some(pkt)) => Some((cursor.position() as usize, pkt)),
                Ok(None) => None, // 半帧，等更多字节。
                Err(_) => {
                    // 坏帧：丢弃已累积字节重同步。
                    acc.clear();
                    None
                },
            }
        };
        let Some((consumed, pkt)) = frame else { break };
        let (payload, target) = pkt.into_parts();
        let dest = target.as_ref().unwrap_or(default_dest);
        match relay::destination_to_endpoint(dest) {
            Some(endpoint) => {
                let mut s = stack.lock().await;
                s.poll(smoltcp::time::Instant::now());
                s.with_udp_socket(handle, |sock| {
                    let _ = sock.send_slice(&payload, endpoint);
                });
                s.poll(smoltcp::time::Instant::now());
            },
            None => {
                // 域名 target 无法进 smoltcp（仅 IP；Go dispatchMessage per-frame
                // resolveFunc 本形态无 resolve 面）——可观测丢弃。
                LOG.warn(format!(
                    "masque outbound: dropping XUDP frame with domain target dest={dest}"
                ));
            },
        }
        acc.drain(..consumed);
    }
}

/// 下行：栈内 UDP socket → XUDP 帧字节（帧 target = 回包源；wireguard
/// `pump_udp_to_client` 同构）。返回 None = 无数据。
async fn pump_udp_to_client(
    stack: &Arc<tokio::sync::Mutex<PacketStack>>,
    handle: smoltcp::iface::SocketHandle,
    default_dest: &Destination,
    scratch: &mut [u8],
) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    {
        let mut s = stack.lock().await;
        s.poll(smoltcp::time::Instant::now());
        let received = s.with_udp_socket(handle, |sock| {
            sock.recv_slice(scratch).ok().map(|(n, meta)| (n, meta.endpoint))
        });
        if let Some((n, remote)) = received {
            let target =
                relay::endpoint_to_destination(&remote).unwrap_or_else(|| default_dest.clone());
            let mut writer = PacketWriter::new(Vec::new(), default_dest.clone(), [0u8; 8]);
            let _ = writer.write_packet_with_udp_target(&scratch[..n], &target);
            out.extend_from_slice(&writer.into_inner());
        } else {
            return None;
        }
    }
    (!out.is_empty()).then_some(out)
}
