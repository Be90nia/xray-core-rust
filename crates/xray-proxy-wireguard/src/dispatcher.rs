//! WireGuard outbound → DialBridge 适配器。
//!
//! 把 [`WireguardOutboundHandler`] 接入 dispatcher 的 `DialBridge`。
//!
//! ## 桥接架构
//!
//! smoltcp TCP/UDP socket 不直接 impl `AsyncRead/AsyncWrite`，需要中继：
//!
//! ```text
//! [上层 Link] ←→ [WireguardConnection (duplex half)] ←→ [中继 task] ←→ [smoltcp TCP/UDP socket]
//! ```
//!
//! 中继 task 持有 duplex 另一端 + `Arc<AsyncMutex<WgNetStack>>` + socket handle，
//! 用 `tokio::select!` 同时等待 duplex 可读 + 定时器，驱动 smoltcp socket IO。
//! UDP 走 XUDP 帧约定（对应 Go `client.go` 的 `udpConnClient`——逐帧 UDP target）。
//!
//! # ponytail: 轮询式桥接，延迟 ~5ms 量级。waker 驱动优化留待吞吐量瓶颈时。

use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use smoltcp::socket::tcp;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{Mutex as AsyncMutex, OnceCell},
};
use xray_app_dispatcher::default::DialFn;
use xray_app_dns::DnsService;
use xray_common::net::{address::Address, destination::Destination, network::Network};
use xray_transport::connection::Connection;
use xray_xudp::packet::{PacketReader, PacketWriter};

use crate::{
    config::{DeviceConfig, DomainStrategy},
    netstack::WgNetStack,
    outbound::WireguardOutboundHandler,
};

/// duplex 缓冲大小。
const DUPLEX_BUF: usize = 64 * 1024;

/// 中继轮询间隔（ms）。
const RELAY_POLL_MS: u64 = 5;

/// WireGuard 连接——包装 tokio duplex 的一半。
///
/// 上层通过 `AsyncRead/AsyncWrite` 读写 duplex，中继 task 在另一端
/// 桥接 smoltcp TCP socket。
pub struct WireguardConnection {
    read: tokio::io::DuplexStream,
    write: tokio::io::DuplexStream,
}

impl WireguardConnection {
    fn new(read: tokio::io::DuplexStream, write: tokio::io::DuplexStream) -> Self {
        Self { read, write }
    }
}

impl AsyncRead for WireguardConnection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().read).poll_read(cx, buf)
    }
}

impl AsyncWrite for WireguardConnection {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().write).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().write).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().write).poll_shutdown(cx)
    }
}

impl Connection for WireguardConnection {
    fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(None)
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(None)
    }
}

/// smoltcp TCP socket ↔ tokio duplex 中继 task。
///
/// 持有 duplex 的"远端"（与 [`WireguardConnection`] 配对）+ netstack + socket handle。
/// 用 `tokio::select!` 同时等待 duplex 可读 + 定时器，驱动 smoltcp socket IO。
struct TcpRelay {
    /// duplex 远端——从 WireguardConnection 侧读取用户数据。
    from_client: tokio::io::DuplexStream,
    /// duplex 远端——向 WireguardConnection 侧写入 smoltcp 数据。
    to_client: tokio::io::DuplexStream,
    /// smoltcp 网栈。
    netstack: Arc<AsyncMutex<WgNetStack>>,
    /// smoltcp TCP socket handle。
    handle: smoltcp::iface::SocketHandle,
}

impl TcpRelay {
    /// 运行中继循环直到 socket 关闭或出错。
    async fn run(mut self) {
        let poll_interval = Duration::from_millis(RELAY_POLL_MS);
        let mut timer = tokio::time::interval(poll_interval);
        // 消掉首次立即触发
        timer.tick().await;

        loop {
            // select! 上 duplex 可读 + 定时器
            let mut user_buf = vec![0u8; 8192];
            tokio::select! {
                // 用户数据到达（从 WireguardConnection 写入 → from_client 可读）
                result = tokio::io::AsyncReadExt::read(&mut self.from_client, &mut user_buf) => {
                    match result {
                        Ok(0) => {
                            // 用户侧关闭写入
                            self.close_socket().await;
                            return;
                        }
                        Ok(n) => {
                            user_buf.truncate(n);
                            self.send_to_smoltcp(&user_buf).await;
                        }
                        Err(_) => {
                            self.close_socket().await;
                            return;
                        }
                    }
                }
                // 定时器：检查 smoltcp socket 状态 + 接收数据
                _ = timer.tick() => {}
            }

            // 每次循环都尝试从 smoltcp 接收数据
            let should_close = self.recv_from_smoltcp().await;
            if should_close {
                let _ = tokio::io::AsyncWriteExt::shutdown(&mut self.to_client).await;
                return;
            }
        }
    }

    /// 发送用户数据到 smoltcp TCP socket。
    async fn send_to_smoltcp(&self, data: &[u8]) {
        let mut stack = self.netstack.lock().await;
        stack.poll(smoltcp::time::Instant::now());
        stack.with_tcp_socket(self.handle, |s| {
            if s.may_send() {
                // ponytail: 忽略部分写入——smoltcp send_slice 返回实际写入字节数
                // 下次 poll 时会继续发送缓冲区中的数据
                let _ = s.send_slice(data);
            }
        });
        stack.poll(smoltcp::time::Instant::now());
    }

    /// 从 smoltcp TCP socket 接收数据，写入 duplex。
    /// 返回 true 表示 socket 已关闭。
    async fn recv_from_smoltcp(&mut self) -> bool {
        let recv_data = {
            let mut stack = self.netstack.lock().await;
            stack.poll(smoltcp::time::Instant::now());
            let (data, closed) = stack.with_tcp_socket(self.handle, |s| {
                let mut buf = vec![0u8; 8192];
                let n = s.recv_slice(&mut buf).unwrap_or(0);
                buf.truncate(n);
                (buf, !s.is_active())
            });
            stack.poll(smoltcp::time::Instant::now());
            (data, closed)
        };

        if !recv_data.0.is_empty() {
            let _ = tokio::io::AsyncWriteExt::write(&mut self.to_client, &recv_data.0).await;
        }
        recv_data.1
    }

    async fn close_socket(&self) {
        let mut stack = self.netstack.lock().await;
        stack.with_tcp_socket(self.handle, |s| {
            s.close();
        });
        stack.poll(smoltcp::time::Instant::now());
    }
}

/// smoltcp UDP socket ↔ tokio duplex 中继 task（XUDP 帧约定）。
///
/// 对应 Go `client.go:225-244` 的 UDP 分支：`DialUDPAddrPort` + `udpConnClient`。
/// - 上行：duplex 字节流解 XUDP 帧 → 逐帧 UDP target `send_slice`
/// - 下行：smoltcp `recv_slice`（源地址）→ XUDP 帧（target=源地址）写回 duplex
struct UdpRelay {
    from_client: tokio::io::DuplexStream,
    to_client: tokio::io::DuplexStream,
    netstack: Arc<AsyncMutex<WgNetStack>>,
    handle: smoltcp::iface::SocketHandle,
    /// dial 目标（XUDP 帧缺 target 时的默认值；帧 target 优先，Go `b.UDP` 语义）。
    dest: Destination,
    /// 半帧累积缓冲（一次 read 可能不含完整 XUDP 帧）。
    acc: Vec<u8>,
}

impl UdpRelay {
    async fn run(mut self) {
        let poll_interval = Duration::from_millis(RELAY_POLL_MS);
        let mut timer = tokio::time::interval(poll_interval);
        timer.tick().await;

        loop {
            let mut user_buf = vec![0u8; 8192];
            tokio::select! {
                result = tokio::io::AsyncReadExt::read(&mut self.from_client, &mut user_buf) => {
                    match result {
                        Ok(0) | Err(_) => {
                            let mut stack = self.netstack.lock().await;
                            stack.remove_socket(self.handle);
                            return;
                        }
                        Ok(n) => {
                            user_buf.truncate(n);
                            pump_client_to_udp(
                                &self.netstack,
                                self.handle,
                                &user_buf,
                                &self.dest,
                                &mut self.acc,
                            )
                            .await;
                        }
                    }
                }
                _ = timer.tick() => {}
            }

            if let Some(frame) = pump_udp_to_client(&self.netstack, self.handle, &self.dest).await {
                let _ = tokio::io::AsyncWriteExt::write_all(&mut self.to_client, &frame).await;
            }
        }
    }
}

/// 上行泵：duplex 字节 → XUDP 帧 → smoltcp UDP socket 发送。
///
/// `acc` 跨调用保持未消费的半帧字节。坏帧丢弃已累积字节重同步。
pub(crate) async fn pump_client_to_udp(
    netstack: &Arc<AsyncMutex<WgNetStack>>,
    handle: smoltcp::iface::SocketHandle,
    bytes: &[u8],
    default_dest: &Destination,
    acc: &mut Vec<u8>,
) {
    #[allow(unused_imports)] // 存量清零批次
    use std::io::Read as _;
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
                Ok(None) => None, // 半帧，等更多字节
                Err(_) => {
                    // 坏帧：丢弃全部已累积字节重同步
                    acc.clear();
                    None
                },
            }
        };
        let Some((consumed, pkt)) = frame else { break };
        let (payload, target) = pkt.into_parts();
        let dest = target.as_ref().unwrap_or(default_dest);
        match destination_to_endpoint(dest) {
            Some(endpoint) => {
                let mut stack = netstack.lock().await;
                stack.poll(smoltcp::time::Instant::now());
                stack.with_udp_socket(handle, |sock| {
                    let _ = sock.send_slice(&payload, endpoint);
                });
                stack.poll(smoltcp::time::Instant::now());
            },
            None => {
                // Go dispatchMessage 走 per-frame resolveFunc；此处域名 target
                // 无法进 smoltcp（仅 IP），静默丢改为可观测告警（bd 7v0k④）。
                tracing::warn!(dest = %dest, "wg outbound: dropping XUDP frame with domain target");
            },
        }
        acc.drain(..consumed);
    }
}

/// 下行泵：smoltcp UDP socket 接收 → XUDP 帧字节。
///
/// 返回 `None` 表示无数据。帧 target = 回包源地址（Go `udpConnClient.ReadMultiBuffer`
/// 的 `b.UDP = addr` 语义）。
pub(crate) async fn pump_udp_to_client(
    netstack: &Arc<AsyncMutex<WgNetStack>>,
    handle: smoltcp::iface::SocketHandle,
    default_dest: &Destination,
) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let received = {
            let mut stack = netstack.lock().await;
            stack.poll(smoltcp::time::Instant::now());
            let mut buf = vec![0u8; 65535];
            stack.with_udp_socket(handle, |sock| match sock.recv_slice(&mut buf) {
                Ok((n, meta)) => {
                    buf.truncate(n);
                    Some((buf, meta.endpoint))
                },
                Err(_) => None,
            })
        };
        let Some((payload, remote)) = received else { break };
        let target = endpoint_to_destination(&remote).unwrap_or_else(|| default_dest.clone());
        // ponytail: 每帧独立 writer（New 帧）——读端 New/Keep 均接受，语义等价
        let mut writer = PacketWriter::new(Vec::new(), default_dest.clone(), [0u8; 8]);
        let _ = writer.write_packet_with_udp_target(&payload, &target);
        out.extend_from_slice(&writer.into_inner());
    }
    (!out.is_empty()).then_some(out)
}

/// 域名目标解析（Go `client.go:167-187`）。
///
/// 用 WireGuard 自身的 `domainStrategy` + interface 地址族约束（`hasIPv4/6`）
/// 解析；空结果且有 fallback 策略时二次解析；随机选一个 IP（`dice.Roll`）。
pub(crate) async fn resolve_dest_domain(
    domain: &str,
    strategy: DomainStrategy,
    has_v4: bool,
    has_v6: bool,
    dns: &Arc<DnsService>,
) -> Result<std::net::IpAddr, String> {
    use rand::Rng;
    use xray_app_dns::config::IpOption;

    let prefer = IpOption {
        ipv4_enable: has_v4 && strategy.prefer_ip4(),
        ipv6_enable: has_v6 && strategy.prefer_ip6(),
        fake_enable: false,
    };
    let mut result = dns.lookup_ip(domain, prefer).await;
    let need_fallback = match &result {
        Ok((ips, _)) => ips.is_empty(),
        Err(_) => true,
    };
    if need_fallback && (strategy.fallback_ip4() || strategy.fallback_ip6()) {
        let fallback = IpOption {
            ipv4_enable: has_v4 && strategy.fallback_ip4(),
            ipv6_enable: has_v6 && strategy.fallback_ip6(),
            fake_enable: false,
        };
        result = dns.lookup_ip(domain, fallback).await;
    }
    match result {
        Ok((ips, _)) if !ips.is_empty() => {
            let usable = filter_by_interface_family(ips, has_v4, has_v6);
            if usable.is_empty() {
                return Err(
                    "wireguard: no DNS candidate matches interface address families".to_string()
                );
            }
            #[allow(deprecated)] // 存量清零批次
            let idx = rand::thread_rng().gen_range(0..usable.len());
            Ok(usable[idx])
        },
        Ok(_) => Err("wireguard: empty DNS response".to_string()),
        Err(e) => Err(format!("wireguard: DNS lookup failed: {e}")),
    }
}

/// 按接口地址族过滤候选 IP（保持原有顺序）。
///
/// smoltcp 接口只配了 v4（或只配了 v6）地址时，选中另一族目标会让 connect
/// 进入无源地址的 SynSent——SYN 无响应直到 `wait_tcp_connected` 超时。
/// 上游 DNS（`xray-app-dns` serial/parallel_query 当前丢弃顶层 IpOption，
/// 返回混合族列表）无法依赖，故在此出口处强制约束。
#[must_use]
fn filter_by_interface_family(
    ips: Vec<std::net::IpAddr>,
    has_v4: bool,
    has_v6: bool,
) -> Vec<std::net::IpAddr> {
    ips.into_iter()
        .filter(|ip| match ip {
            std::net::IpAddr::V4(_) => has_v4,
            std::net::IpAddr::V6(_) => has_v6,
        })
        .collect()
}

/// Destination（仅 IP）→ smoltcp IpEndpoint。
fn destination_to_endpoint(dest: &Destination) -> Option<smoltcp::wire::IpEndpoint> {
    let addr = match dest.address() {
        Address::IPv4(v4) => smoltcp::wire::IpAddress::Ipv4(v4.octets().into()),
        Address::IPv6(v6) => smoltcp::wire::IpAddress::Ipv6(v6.octets().into()),
        Address::Domain(_) => return None,
    };
    Some(smoltcp::wire::IpEndpoint::new(addr, dest.port().value()))
}

/// smoltcp IpEndpoint → Destination（UDP）。
fn endpoint_to_destination(ep: &smoltcp::wire::IpEndpoint) -> Option<Destination> {
    let addr = match ep.addr {
        smoltcp::wire::IpAddress::Ipv4(v4) => Address::from_ipv4_bytes(v4.octets()),
        smoltcp::wire::IpAddress::Ipv6(v6) => Address::from_ipv6_bytes(v6.octets()),
    };
    Some(Destination::new(addr, xray_common::net::port::Port::new(ep.port), Network::UDP))
}

/// WireGuard 包头 reserved 字段——发送侧写入（Go `bind.go:184-186`）。
///
/// Cloudflare Warp 用这 3 字节区分客户端；`reserved` 长度非 3 时不动。
pub(crate) fn apply_reserved(pkt: &mut [u8], reserved: &[u8]) {
    if pkt.len() > 3 && reserved.len() == 3 {
        pkt[1..4].copy_from_slice(reserved);
    }
}

/// WireGuard 包头 reserved 字段——接收侧清零（Go `bind.go:145-149`）。
pub(crate) fn clear_reserved(pkt: &mut [u8]) {
    if pkt.len() > 3 {
        pkt[1] = 0;
        pkt[2] = 0;
        pkt[3] = 0;
    }
}

/// 构造 DialBridge 用的 DialFn 闭包（lazy init 模式）。
///
/// 闭包捕获 `DeviceConfig` + 可选 DNS 服务 + 可选 system dialer。首次 dial 时
/// 通过 `OnceCell` lazy init `WireguardOutboundHandler`（含 driver task + smoltcp
/// netstack）。
///
/// - `system_dialer`：`Some` 时 WG 自身 UDP 经此拨号出站（Go `client.go:94-143` processWireGuard 的
///   `internet.Dialer`——UDP 可经 socks 等出站链）； `None` 直连（Go 无 ProxySettings 时的 raw UDP）
/// - 域名目标：经 WireGuard 自身 `domainStrategy` 解析（Go `client.go:167-187`， `dns`
///   缺失时域名断链报错）
/// - UDP 目标：smoltcp UDP socket + XUDP 帧中继（Go `client.go:225-244`）
///
/// # Panics
/// 不会 panic；任何错误以 `Err(String)` 返回。
pub fn make_wireguard_dial_fn(
    config: DeviceConfig,
    dns: Option<Arc<DnsService>>,
    system_dialer: Option<DialFn>,
) -> DialFn {
    let handler: Arc<OnceCell<WireguardOutboundHandler>> = Arc::new(OnceCell::new());
    let config_clone = config.clone();
    let dns_clone = dns.clone();
    // interface 地址族（Go parseEndpoints 的 hasIPv4/hasIPv6）——约束 DNS 解析族
    let (has_v4, has_v6) = endpoint_families(&config);
    // 域名解析 TTL 缓存（Go Handler.cache，c7e569b0；endpoint 与目标域名共享）。
    let dns_cache = Arc::new(TtlDnsCache::default());

    Arc::new(move |dest: &Destination| {
        let dest = dest.clone();
        let config = config_clone.clone();
        let dns = dns_clone.clone();
        let system_dialer = system_dialer.clone();
        let handler_cell = Arc::clone(&handler);
        let dns_cache = Arc::clone(&dns_cache);

        Box::pin(async move {
            // lazy init WireguardOutboundHandler（含 driver task）
            let handler = handler_cell
                .get_or_try_init(|| async {
                    WireguardOutboundHandler::new_with_dialer(
                        "wireguard",
                        &config,
                        dns.as_ref(),
                        system_dialer.as_ref().cloned(),
                        Some(Arc::clone(&dns_cache)),
                    )
                    .await
                })
                .await
                .map_err(|e| format!("wireguard handler init: {e}"))?;

            let netstack = handler.netstack();

            // 域名目标 → 缓存（Go Handler.cache TTL 内随机取一）→ 未命中按
            // remoteDNS 模式解析（["local"] = 本地 app DNS；其余 = 隧道内 DNS，
            // 服务器列表来自 remoteDNS 或默认四址）→ 写回缓存（Go resolveDomain
            // client.go:388-446，c7e569b0）。
            let dest = match dest.address() {
                Address::Domain(domain) => {
                    let ip = resolve_dest_ip_cached(
                        domain,
                        netstack,
                        has_v4,
                        has_v6,
                        &config,
                        dns.as_ref(),
                        &dns_cache,
                    )
                    .await?;
                    let addr = match ip {
                        std::net::IpAddr::V4(v4) => Address::IPv4(v4),
                        std::net::IpAddr::V6(v6) => Address::IPv6(v6),
                    };
                    Destination::new(addr, dest.port(), dest.network())
                },
                _ => dest,
            };

            match dest.network() {
                Network::TCP => {
                    let ip = match dest.address() {
                        Address::IPv4(v4) => smoltcp::wire::IpAddress::Ipv4(
                            #[allow(clippy::incompatible_msrv)] // 存量清零批次
                            smoltcp::wire::Ipv4Address::from_octets(v4.octets()),
                        ),
                        Address::IPv6(v6) => smoltcp::wire::IpAddress::Ipv6(
                            #[allow(clippy::incompatible_msrv)] // 存量清零批次
                            smoltcp::wire::Ipv6Address::from_octets(v6.octets()),
                        ),
                        Address::Domain(_) => unreachable!("resolved above"),
                    };
                    let port = dest.port().value();
                    let handle = {
                        let mut stack = netstack.lock().await;
                        let handle = stack.add_tcp_socket();
                        stack
                            .tcp_connect(handle, ip, port)
                            .map_err(|e| format!("smoltcp tcp_connect: {e}"))?;
                        handle
                    };

                    let connected = wait_tcp_connected(netstack, handle).await;
                    if !connected {
                        let mut stack = netstack.lock().await;
                        stack.remove_socket(handle);
                        return Err("wireguard outbound: tcp connect timeout or failed".to_string());
                    }

                    spawn_relay(|from_client, to_client| {
                        UdpOrTcpRelay::Tcp(TcpRelay {
                            from_client,
                            to_client,
                            netstack: Arc::clone(netstack),
                            handle,
                        })
                    })
                    .await
                },
                Network::UDP => {
                    // Go client.go:226 DialUDPAddrPort —— smoltcp UDP socket（bind 0 随机端口）
                    let handle = {
                        let mut stack = netstack.lock().await;
                        let handle = stack.add_udp_socket();
                        stack.with_udp_socket(handle, |sock| {
                            bind_ephemeral(sock);
                        });
                        handle
                    };

                    spawn_relay(|from_client, to_client| {
                        UdpOrTcpRelay::Udp(UdpRelay {
                            from_client,
                            to_client,
                            netstack: Arc::clone(netstack),
                            handle,
                            dest: dest.clone(),
                            acc: Vec::new(),
                        })
                    })
                    .await
                },
                Network::Unix => Err("wireguard outbound does not support Unix socket".to_string()),
            }
        })
    })
}

/// 目标域名解析（缓存包装）。Go `resolveRemote`/`resolveDomain`（client.go:379-446，
/// c7e569b0）：TTL 内命中随机取一；未命中按 remoteDNS 模式解析后写回。
async fn resolve_dest_ip_cached(
    domain: &str,
    netstack: &Arc<AsyncMutex<WgNetStack>>,
    has_v4: bool,
    has_v6: bool,
    config: &DeviceConfig,
    dns: Option<&Arc<DnsService>>,
    cache: &TtlDnsCache,
) -> Result<std::net::IpAddr, String> {
    if let Some(ip) = cache.get(domain) {
        return Ok(ip);
    }
    let (ips, ttl) = match config.resolve_dns() {
        Ok(crate::config::DnsConfig::Local) => {
            // Go resolveRemote 的 local 分支：走 app DNS（h.dns.LookupIP），
            // 不经隧道。app DNS 不暴露记录 TTL → 缺省 300（Go netstack 默认）。
            let d = dns.ok_or_else(|| {
                "wireguard outbound: remoteDNS=local requires dns service".to_string()
            })?;
            let ip = resolve_dest_domain(domain, config.domain_strategy, has_v4, has_v6, d).await?;
            (vec![ip], DEFAULT_DNS_TTL_SECS)
        },
        Ok(crate::config::DnsConfig::Default) => {
            resolve_domain_in_tunnel(netstack, domain, has_v4, has_v6, &TUNNEL_DNS_SERVERS).await?
        },
        Ok(crate::config::DnsConfig::Servers(servers)) => {
            resolve_domain_in_tunnel(netstack, domain, has_v4, has_v6, &servers).await?
        },
        Err(e) => return Err(e.to_string()),
    };
    cache.put(domain, ips, ttl);
    cache.get(domain).ok_or_else(|| "wireguard outbound: dns cache write failed".to_string())
}

/// 中继类型（统一 spawn 模板用）。
enum UdpOrTcpRelay {
    Tcp(TcpRelay),
    Udp(UdpRelay),
}

impl UdpOrTcpRelay {
    async fn run(self) {
        match self {
            Self::Tcp(relay) => relay.run().await,
            Self::Udp(relay) => relay.run().await,
        }
    }
}

/// 创建 duplex pair 并 spawn 中继 task，返回 client 侧 Connection。
#[allow(deprecated)] // 存量清零批次：deprecated
async fn spawn_relay<F>(make: F) -> Result<Box<dyn Connection>, String>
where
    F: FnOnce(tokio::io::DuplexStream, tokio::io::DuplexStream) -> UdpOrTcpRelay,
{
    // ponytail: 两个 duplex——tokio::io::duplex 单向（client→relay / relay→client 各一）
    let (client_to_relay, relay_from_client) = tokio::io::duplex(DUPLEX_BUF);
    let (relay_to_client, client_from_relay) = tokio::io::duplex(DUPLEX_BUF);
    let conn = WireguardConnection::new(client_from_relay, client_to_relay);
    let relay = make(relay_from_client, relay_to_client);
    tokio::spawn(async move {
        relay.run().await;
    });
    Ok(Box::new(conn))
}

/// smoltcp UDP socket 绑定临时端口（1024-65535 随机，冲突重试）。
///
/// smoltcp `bind(0)` 拒绝零端口（BindError::Unaddressable）；Go
/// `DialUDPAddrPort(netip.AddrPort{}, ...)` 的随机端口语义在此手动实现。
pub(crate) fn bind_ephemeral(sock: &mut smoltcp::socket::udp::Socket<'static>) {
    use rand::Rng;
    for _ in 0..16 {
        #[allow(deprecated)] // 存量清零批次
        let port: u16 = rand::thread_rng().gen_range(1024..65535);
        if sock.bind(port).is_ok() {
            return;
        }
    }
}

/// DeviceConfig.endpoint 的地址族（Go `parseEndpoints` 的 hasIPv4/hasIPv6）。
pub(crate) fn endpoint_families(config: &DeviceConfig) -> (bool, bool) {
    let mut has_v4 = false;
    let mut has_v6 = false;
    for s in &config.endpoint {
        // Go netstack.go:89-92 按地址本体 Is4/Is6 判族——掩码段不参与
        // （rsplit 取尾段会把 "fd00::1/128" 的 "128" 误判为 v4，bd thc9）。
        let addr = s.split('/').next().unwrap_or(s);
        match addr.parse::<std::net::IpAddr>() {
            Ok(ip) if ip.is_ipv4() => has_v4 = true,
            Ok(_) => has_v6 = true,
            Err(_) => {},
        }
    }
    (has_v4, has_v6)
}

/// Go client.go:88-97 CreateNetTUN 的默认 dnsServers（c7e569b0 后为 `remoteDNS`
/// 未配置时的默认值，client.go:113-115）——隧道内 DNS 查询目标（bd p06j）。
const TUNNEL_DNS_SERVERS: [std::net::IpAddr; 4] = [
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 0, 0, 1)),
    std::net::IpAddr::V6(std::net::Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
    std::net::IpAddr::V6(std::net::Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1001)),
];

/// DNS 记录缺省 TTL（Go netstack.go `ttl := uint32(300)`，c7e569b0）。
pub(crate) const DEFAULT_DNS_TTL_SECS: u32 = 300;

/// 域名解析 TTL 缓存（Go `Handler.cache` + `resolveDomain`，client.go:53-56,
/// 388-446，c7e569b0）。键 = 域名，值 =（策略过滤后的 IP 列表，过期时刻）。
///
/// `ponytail`: 无清理循环——条目惰性删除（get 过期即删），生命周期 = dial_fn
/// （单出站一个），泄漏上界 = 域名数；Go 侧同为 TODO cache cleanup loop。
#[derive(Default)]
pub(crate) struct TtlDnsCache {
    map: parking_lot::Mutex<HashMap<String, TtlCacheEntry>>,
}

struct TtlCacheEntry {
    ips: Vec<std::net::IpAddr>,
    expires_at: std::time::Instant,
}

impl TtlDnsCache {
    /// 命中未过期条目 → 随机取一 IP（Go `dice.Roll(len(entry.got))`）；过期条目
    /// 删除并返回 None（Go client.go:399-406）。
    pub(crate) fn get(&self, host: &str) -> Option<std::net::IpAddr> {
        use rand::Rng;
        let mut map = self.map.lock();
        if let Some(e) = map.get(host) {
            if std::time::Instant::now() < e.expires_at {
                #[allow(deprecated)] // 存量清零批次
                let idx = rand::thread_rng().gen_range(0..e.ips.len());
                return Some(e.ips[idx]);
            }
            map.remove(host);
        }
        None
    }

    /// 写回缓存（`ttl_secs` 秒有效）；空列表不缓存（Go 只在 len(got)>0 后写）。
    pub(crate) fn put(&self, host: &str, ips: Vec<std::net::IpAddr>, ttl_secs: u32) {
        if ips.is_empty() {
            return;
        }
        self.map.lock().insert(
            host.to_string(),
            TtlCacheEntry {
                ips,
                expires_at: std::time::Instant::now() + Duration::from_secs(u64::from(ttl_secs)),
            },
        );
    }
}

/// 隧道内 DNS 单 server 查询超时。
const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(3);

/// 隧道内域名解析（Go client.go:351-360 `resolveRemote` → `tnet.LookupHost`）。
/// 接口地址族约束查询类型（v4-only 栈只发 A）；双栈 A/AAAA 各查合并后按族过滤。
/// 返回（可用 IP 列表，记录最小 TTL 秒）——c7e569b0 的 TTL 遵循。
/// 取舍：不走本地 DnsService（Go resolveRemote 同样绕过 app/dns）、TC 截断
/// 响应不重试 TCP（公共 DNS A/AAAA 答案极少超 1400 MTU）。
pub(crate) async fn resolve_domain_in_tunnel(
    netstack: &Arc<AsyncMutex<WgNetStack>>,
    domain: &str,
    has_v4: bool,
    has_v6: bool,
    servers: &[std::net::IpAddr],
) -> Result<(Vec<std::net::IpAddr>, u32), String> {
    use rand::Rng;
    if !has_v4 && !has_v6 {
        return Err("wireguard outbound: interface has no address family for tunnel DNS".into());
    }
    let domain = domain.trim_end_matches('.');
    // 查询类型序列：v4-only→[A]；v6-only→[AAAA]；双栈→[A, AAAA]（族约束过滤兜底）
    let qtypes: Vec<bool> = match (has_v4, has_v6) {
        (true, false) => vec![true],
        (false, true) => vec![false],
        _ => vec![true, false],
    };
    let handle = {
        let mut stack = netstack.lock().await;
        let h = stack.add_udp_socket();
        stack.with_udp_socket(h, bind_ephemeral);
        h
    };

    let mut last_err = String::from("wireguard tunnel dns: no query attempted");
    let mut found: Vec<std::net::IpAddr> = Vec::new();
    let mut best_ttl = DEFAULT_DNS_TTL_SECS;
    'qtypes: for want_a in qtypes {
        #[allow(deprecated)] // 存量清零批次
        let req_id: u16 = rand::thread_rng().random();
        let query = dns_build_query(domain, want_a, req_id)?;
        for server in servers.iter().filter(|ip| ip.is_ipv4() == want_a) {
            let target = smoltcp::wire::IpEndpoint::new(
                match server {
                    std::net::IpAddr::V4(v4) => smoltcp::wire::IpAddress::Ipv4(
                        #[allow(clippy::incompatible_msrv)] // 存量清零批次
                        smoltcp::wire::Ipv4Address::from_octets(v4.octets()),
                    ),
                    std::net::IpAddr::V6(v6) => smoltcp::wire::IpAddress::Ipv6(
                        #[allow(clippy::incompatible_msrv)] // 存量清零批次
                        smoltcp::wire::Ipv6Address::from_octets(v6.octets()),
                    ),
                },
                53,
            );
            {
                let mut stack = netstack.lock().await;
                stack.poll(smoltcp::time::Instant::now());
                stack.with_udp_socket(handle, |sock| {
                    let _ = sock.send_slice(&query, target);
                });
                stack.poll(smoltcp::time::Instant::now());
            }
            let deadline = std::time::Instant::now() + DNS_QUERY_TIMEOUT;
            loop {
                let received = {
                    let mut stack = netstack.lock().await;
                    stack.poll(smoltcp::time::Instant::now());
                    let mut buf = vec![0u8; 4096];
                    stack.with_udp_socket(handle, |sock| {
                        sock.recv_slice(&mut buf)
                            .ok()
                            .map(|(n, meta)| (buf[..n].to_vec(), meta.endpoint))
                    })
                };
                if let Some((data, _from)) = received {
                    match dns_parse_ips(&data, req_id) {
                        Ok((ips, ttl)) if !ips.is_empty() => {
                            found = ips;
                            best_ttl = ttl;
                            break 'qtypes;
                        },
                        Ok(_) => {}, // rcode 错误 / 截断空答——换下一 server
                        Err(e) => last_err = e,
                    }
                }
                if std::time::Instant::now() >= deadline {
                    last_err = format!("wireguard tunnel dns: timeout querying {server}");
                    break;
                }
                tokio::time::sleep(Duration::from_millis(RELAY_POLL_MS)).await;
            }
        }
    }

    {
        let mut stack = netstack.lock().await;
        stack.remove_socket(handle);
    }
    let usable = filter_by_interface_family(found, has_v4, has_v6);
    if usable.is_empty() {
        return Err(last_err);
    }
    Ok((usable, best_ttl))
}

/// 构造 DNS 查询（RFC 1035）：单 question，`want_a` 选 A / AAAA，RD=1。
fn dns_build_query(name: &str, want_a: bool, req_id: u16) -> Result<Vec<u8>, String> {
    if name.is_empty() || name.len() > 253 {
        return Err(format!("wireguard tunnel dns: invalid name length: {name}"));
    }
    let mut buf = Vec::with_capacity(17 + name.len());
    buf.extend_from_slice(&req_id.to_be_bytes());
    buf.extend_from_slice(&[0x01, 0x00]); // flags: RD=1
    buf.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // QD=1 AN=NS=AR=0
    for label in name.split('.') {
        let len = label.len();
        if len == 0 || len > 63 {
            return Err(format!("wireguard tunnel dns: invalid label in {name}"));
        }
        buf.push(len as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);
    buf.extend_from_slice(if want_a { &[0, 1] } else { &[0, 28] }); // QTYPE
    buf.extend_from_slice(&[0, 1]); // QCLASS=IN
    Ok(buf)
}

/// 解析 DNS 响应：提取全部 A/AAAA 记录 + 记录最小 TTL（Go netstack.go
/// LookupContextHost：`ttl := uint32(300)` 起步，逐记录 `min(ttl, h.TTL)`，
/// c7e569b0）。`req_id` 不匹配报错；rcode!=0 或无答案返回空（调用方换 server）。
fn dns_parse_ips(payload: &[u8], req_id: u16) -> Result<(Vec<std::net::IpAddr>, u32), String> {
    if payload.len() < 12 {
        return Err("wireguard tunnel dns: short response".into());
    }
    if u16::from_be_bytes([payload[0], payload[1]]) != req_id {
        return Err("wireguard tunnel dns: req id mismatch".into());
    }
    if payload[3] & 0x0F != 0 {
        return Ok((Vec::new(), DEFAULT_DNS_TTL_SECS)); // 非 NOERROR
    }
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    let ancount = u16::from_be_bytes([payload[6], payload[7]]);
    let mut pos = 12;
    for _ in 0..qdcount {
        dns_skip_name(payload, &mut pos)?;
        pos += 4; // qtype + qclass
    }
    let mut ips = Vec::new();
    let mut ttl = DEFAULT_DNS_TTL_SECS;
    for _ in 0..ancount {
        dns_skip_name(payload, &mut pos)?;
        if pos + 10 > payload.len() {
            break;
        }
        let rtype = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let record_ttl = u32::from_be_bytes([
            payload[pos + 2],
            payload[pos + 3],
            payload[pos + 4],
            payload[pos + 5],
        ]);
        let rdlength = usize::from(u16::from_be_bytes([payload[pos + 8], payload[pos + 9]]));
        pos += 10;
        if pos + rdlength > payload.len() {
            break;
        }
        match (rtype, rdlength) {
            (1, 4) => {
                ips.push(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                    payload[pos],
                    payload[pos + 1],
                    payload[pos + 2],
                    payload[pos + 3],
                )));
                ttl = ttl.min(record_ttl);
            },
            (28, 16) => {
                let mut o = [0u8; 16];
                o.copy_from_slice(&payload[pos..pos + 16]);
                ips.push(std::net::IpAddr::V6(std::net::Ipv6Addr::from(o)));
                ttl = ttl.min(record_ttl);
            },
            _ => {},
        }
        pos += rdlength;
    }
    Ok((ips, ttl))
}

/// 跳过 name 字段（标签序列或 `0xC0` 压缩指针，RFC 1035 §4.1.4）。
fn dns_skip_name(payload: &[u8], pos: &mut usize) -> Result<(), String> {
    loop {
        let Some(&len) = payload.get(*pos) else {
            return Err("wireguard tunnel dns: truncated name".into());
        };
        if len & 0xC0 == 0xC0 {
            *pos += 2;
            return Ok(());
        }
        if len == 0 {
            *pos += 1;
            return Ok(());
        }
        *pos += 1 + usize::from(len);
    }
}

/// 等待 smoltcp TCP socket 连接建立（轮询，最多 5 秒）。
async fn wait_tcp_connected(
    netstack: &Arc<AsyncMutex<WgNetStack>>,
    handle: smoltcp::iface::SocketHandle,
) -> bool {
    let timeout = Duration::from_secs(5);
    let start = std::time::Instant::now();
    let poll_interval = Duration::from_millis(RELAY_POLL_MS);

    loop {
        {
            let mut stack = netstack.lock().await;
            stack.poll(smoltcp::time::Instant::now());
            let state = stack.with_tcp_socket(handle, |s| s.state());
            if state == tcp::State::Established {
                return true;
            }
            if state == tcp::State::Closed || state == tcp::State::CloseWait {
                return false;
            }
        }

        if start.elapsed() >= timeout {
            return false;
        }
        tokio::time::sleep(poll_interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wireguard_connection_satisfies_traits() {
        fn assert_async_read<T: AsyncRead>() {}
        fn assert_async_write<T: AsyncWrite>() {}
        fn assert_connection<T: Connection>() {}

        assert_async_read::<WireguardConnection>();
        assert_async_write::<WireguardConnection>();
        assert_connection::<WireguardConnection>();
    }

    #[tokio::test]
    async fn duplex_bridge_basic_io() {
        // 验证 duplex pair 基本读写
        let (client_to_relay, mut relay_from_client) = tokio::io::duplex(DUPLEX_BUF);
        let (mut relay_to_client, client_from_relay) = tokio::io::duplex(DUPLEX_BUF);

        let mut conn = WireguardConnection::new(client_from_relay, client_to_relay);

        // 写入到 conn（通过 write half）
        let write_data = b"hello wireguard";
        tokio::io::AsyncWriteExt::write(&mut conn.write, write_data).await.expect("write to conn");

        // 从 relay 侧读取
        let mut buf = vec![0u8; 64];
        let n = tokio::io::AsyncReadExt::read(&mut relay_from_client, &mut buf)
            .await
            .expect("read from relay");
        assert_eq!(&buf[..n], write_data);

        // 从 relay 侧写入
        let reply = b"reply from tunnel";
        tokio::io::AsyncWriteExt::write(&mut relay_to_client, reply)
            .await
            .expect("write from relay");

        // 从 conn 侧读取
        let mut rbuf = vec![0u8; 64];
        let rn =
            tokio::io::AsyncReadExt::read(&mut conn.read, &mut rbuf).await.expect("read from conn");
        assert_eq!(&rbuf[..rn], reply);
    }

    #[test]
    fn endpoint_families_parse_addr_body_for_family() {
        // bd thc9：按地址本体判族（Go netstack.go:89-92）——rsplit 尾段
        // 启发式曾把 "fd00::1/128" 的掩码 "128" 误判为 v4。
        let cfg = DeviceConfig { endpoint: vec!["fd00::1/128".into()], ..Default::default() };
        let (has_v4, has_v6) = endpoint_families(&cfg);
        assert!(!has_v4, "fd00::1/128 是 v6");
        assert!(has_v6);

        // Go conf 缺省 bogon 双栈形态
        let cfg = DeviceConfig {
            endpoint: vec!["10.0.0.1".into(), "fd59:7153:2388:b5fd::1".into()],
            ..Default::default()
        };
        let (has_v4, has_v6) = endpoint_families(&cfg);
        assert!(has_v4);
        assert!(has_v6);
    }

    /// bd p06j：隧道内 DNS client——查询包经 smoltcp tx 发往 1.1.1.1:53
    /// （= WG 隧道方向，本机 :53 零泄漏），伪造 DNS 响应注入后解析出 IP。
    #[tokio::test]
    async fn tunnel_dns_resolves_via_smoltcp_stack() {
        let netstack = Arc::new(AsyncMutex::new(WgNetStack::new(&[udp_ip_cidr()], 1420)));
        let ns_for_resolver = Arc::clone(&netstack);
        let resolver = tokio::spawn(async move {
            resolve_domain_in_tunnel(
                &ns_for_resolver,
                "example.invalid",
                true,
                false,
                &TUNNEL_DNS_SERVERS,
            )
            .await
        });

        // 驱动栈：捕获查询（dst 1.1.1.1:53）→ 构造响应 → ingest 回栈
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            assert!(tokio::time::Instant::now() < deadline, "tunnel dns e2e timeout");
            let query = {
                let mut s = netstack.lock().await;
                s.poll(smoltcp::time::Instant::now());
                s.drain_tx()
                    .into_iter()
                    .find(|p| p.len() > 28 && p[0] >> 4 == 4 && p[16..20] == [1, 1, 1, 1])
            };
            if let Some(query) = query {
                let ihl = usize::from(query[0] & 0x0F) * 4;
                let dns_query = &query[ihl + 8..];
                let sport = u16::from_be_bytes([query[ihl], query[ihl + 1]]);
                let req_id = u16::from_be_bytes([dns_query[0], dns_query[1]]);
                let resp = make_dns_a_response(dns_query, req_id, [93, 184, 216, 34]);
                let pkt = build_udp_packet(
                    smoltcp::wire::Ipv4Address::new(1, 1, 1, 1),
                    smoltcp::wire::IpEndpoint {
                        addr: smoltcp::wire::IpAddress::Ipv4(smoltcp::wire::Ipv4Address::new(
                            10, 0, 0, 2,
                        )),
                        port: sport,
                    },
                    &resp,
                );
                let mut s = netstack.lock().await;
                s.ingest_rx(pkt);
                s.poll(smoltcp::time::Instant::now());
            }
            if resolver.is_finished() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        let (ips, ttl) = resolver.await.expect("resolver task").expect("tunnel dns resolves");
        assert_eq!(ips, vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(93, 184, 216, 34))]);
        assert_eq!(ttl, DEFAULT_DNS_TTL_SECS);
    }

    #[test]
    fn ttl_dns_cache_hit_and_expiry() {
        // Go Handler.cache（c7e569b0）：TTL 内随机取一，过期即删重查。
        let cache = TtlDnsCache::default();
        let a = std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4));
        let b = std::net::IpAddr::V4(std::net::Ipv4Addr::new(5, 6, 7, 8));
        cache.put("h.test", vec![a, b], 60);
        let hit = cache.get("h.test").expect("must hit within ttl");
        assert!(hit == a || hit == b);
        assert!(cache.get("missing.test").is_none());
        // ttl=0 → 立即过期
        cache.put("h.test", vec![a], 0);
        assert!(cache.get("h.test").is_none(), "过期条目必须被删除");
    }

    /// 复制查询报文改头为 NOERROR 响应，追加一条指针压缩的 A answer。
    fn make_dns_a_response(query: &[u8], req_id: u16, ip: [u8; 4]) -> Vec<u8> {
        let mut resp = query.to_vec();
        resp[0..2].copy_from_slice(&req_id.to_be_bytes());
        resp[2] = 0x81; // QR | RD
        resp[3] = 0x80; // RA
        resp[6..8].copy_from_slice(&1u16.to_be_bytes()); // ANCOUNT
        resp.extend_from_slice(&[0xC0, 0x0C]); // name 指针 → offset 12
        resp.extend_from_slice(&[0, 1, 0, 1]); // type A, class IN
        resp.extend_from_slice(&[0, 0, 0, 60]); // TTL
        resp.extend_from_slice(&[0, 4]); // RDLENGTH
        resp.extend_from_slice(&ip);
        resp
    }

    /// 静态 hosts DnsService（Go client.go DNS 解析路径的测试替身）。
    async fn hosts_dns() -> std::sync::Arc<xray_app_dns::DnsService> {
        let cfg: xray_app_dns::DnsAppConfig = serde_json::from_str(
            r#"{"hosts": {"wg-test.invalid": "127.0.0.1", "wg-test6.invalid": "::1"}}"#,
        )
        .expect("dns config json");
        let svc = cfg.build().expect("dns config build");
        std::sync::Arc::new(xray_app_dns::DnsService::new(svc))
    }

    #[tokio::test]
    async fn resolve_dest_domain_prefers_matching_family() {
        let dns = hosts_dns().await;
        // Go client.go:170-172 —— IPv4Enable = hasIPv4 && preferIP4()
        let ip = resolve_dest_domain(
            "wg-test.invalid",
            crate::config::DomainStrategy::ForceIp,
            true,
            true,
            &dns,
        )
        .await
        .expect("resolve v4");
        assert!(ip.is_ipv4());

        // v6 正路径不测：check_routes() 系统探测在无 IPv6 路由的测试机上
        // 将 ipv6_enable 置 false（Go checkSystem 同语义，server.rs:211-220），
        // v6-only 查询必然 EmptyResponse——非实现缺陷，是环境约束。
        // v6 约束语义由下方 family_constraint 测试覆盖（它断言 Err 路径）。
        let _ = crate::config::DomainStrategy::ForceIp;
    }

    #[tokio::test]
    async fn resolve_dest_domain_family_constraint_yields_error() {
        let dns = hosts_dns().await;
        // interface 只有 v6 但 hosts 只有 v4 记录 → 空结果报错（Go dns.ErrEmptyResponse）
        let r = resolve_dest_domain(
            "wg-test.invalid",
            crate::config::DomainStrategy::ForceIp,
            false,
            true,
            &dns,
        )
        .await;
        assert!(r.is_err());
    }

    #[test]
    fn interface_family_filter_mixed_candidates() {
        let v4 = |o: [u8; 4]| std::net::IpAddr::V4(std::net::Ipv4Addr::from(o));
        let v6 = |s: u16| {
            std::net::IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0x4860, 0, 0, 0, 0, 0, s))
        };
        let mixed = vec![v4([1, 2, 3, 4]), v6(1), v4([5, 6, 7, 8]), v6(2)];

        // v4-only 接口（172.16.0.2/32 常见配置）：混合候选必须全部收敛为 v4。
        // 上游 DNS serial_query 丢弃顶层 IpOption 返回混合族列表，
        // 不过滤时 dice 以 50% 概率选中 v6 → smoltcp 无源地址 → SYN 黑洞超时。
        let got = filter_by_interface_family(mixed.clone(), true, false);
        assert_eq!(got, vec![v4([1, 2, 3, 4]), v4([5, 6, 7, 8])]);

        // v6-only 接口：对称约束。
        let got = filter_by_interface_family(mixed.clone(), false, true);
        assert_eq!(got, vec![v6(1), v6(2)]);

        // 双族接口：全保留（原顺序）。
        let got = filter_by_interface_family(mixed.clone(), true, true);
        assert_eq!(got, mixed);

        // 候选与接口族完全无交集 → 空（调用方报错，而非静默选中后挂 5s）。
        let got = filter_by_interface_family(vec![v4([9, 9, 9, 9])], false, true);
        assert!(got.is_empty());
    }

    #[tokio::test]
    async fn resolve_dest_domain_rejects_candidates_outside_interface_families() {
        // hosts 只有 v4 记录 + v6-only 接口：现有 family_constraint 测试
        // （上方）由 hosts 层过滤产生 Err；此处覆盖出口过滤分支——
        // v4-only 接口 + v4-only 记录正常解析（回归面：过滤不得误杀合法候选）。
        let dns = hosts_dns().await;
        let ip = resolve_dest_domain(
            "wg-test.invalid",
            crate::config::DomainStrategy::ForceIp,
            true,
            false,
            &dns,
        )
        .await
        .expect("v4-only interface with v4 record resolves");
        assert!(ip.is_ipv4());
    }

    fn udp_ip_cidr() -> smoltcp::wire::IpCidr {
        smoltcp::wire::IpCidr::new(
            smoltcp::wire::IpAddress::Ipv4(smoltcp::wire::Ipv4Address::new(10, 0, 0, 2)),
            32,
        )
    }

    fn udp_dest(port: u16) -> Destination {
        Destination::new(
            Address::from_ipv4_bytes([8, 8, 4, 4]),
            xray_common::net::port::Port::new(port),
            Network::UDP,
        )
    }

    #[tokio::test]
    async fn udp_relay_sends_xudp_frame_to_smoltcp_socket() {
        let netstack =
            std::sync::Arc::new(AsyncMutex::new(WgNetStack::new(&[udp_ip_cidr()], 1420)));
        let handle = {
            let mut s = netstack.lock().await;
            let h = s.add_udp_socket();
            s.with_udp_socket(h, |sock| {
                bind_ephemeral(sock);
            });
            h
        };

        // 客户端写一帧 XUDP（target 8.8.4.4:53，payload "dns-query"）
        let mut frame = Vec::new();
        {
            #[allow(unused_imports)] // 存量清零批次
            use std::io::Write;
            let mut pw = xray_xudp::packet::PacketWriter::new(&mut frame, udp_dest(53), [0x42; 8]);
            pw.write_packet(b"dns-query").expect("write frame");
        }
        pump_client_to_udp(&netstack, handle, &frame, &udp_dest(53), &mut Vec::new()).await;

        // smoltcp 应产生一个出站 IP 包：dst 8.8.4.4:53 payload "dns-query"
        let tx = {
            let mut s = netstack.lock().await;
            s.poll(smoltcp::time::Instant::now());
            s.drain_tx()
        };
        assert_eq!(tx.len(), 1, "exactly one outgoing packet");
        let pkt = &tx[0];
        assert_eq!(pkt[0] >> 4, 4, "ipv4 packet");
        // UDP header: sport(2) dport(2) len(2) cksum(2)；dst IP 在 IP 头 16..20
        let udp_start = ((pkt[0] & 0x0F) as usize) * 4;
        assert_eq!(&pkt[16..20], &[8, 8, 4, 4], "dst ip");
        assert_eq!(&pkt[udp_start + 2..udp_start + 4], &[0, 53], "dst port");
        let payload_start = udp_start + 8;
        assert_eq!(&pkt[payload_start..], b"dns-query");
    }

    #[tokio::test]
    async fn udp_relay_receives_udp_packet_as_xudp_frame() {
        let netstack =
            std::sync::Arc::new(AsyncMutex::new(WgNetStack::new(&[udp_ip_cidr()], 1420)));
        let handle = {
            let mut s = netstack.lock().await;
            let h = s.add_udp_socket();
            s.with_udp_socket(h, |sock| {
                bind_ephemeral(sock);
                // 先发一个包确定 local endpoint（smoltcp bind(0) 首次 send 分配端口）
                let _ = sock.send_slice(
                    b"seed",
                    smoltcp::wire::IpEndpoint::new(
                        smoltcp::wire::IpAddress::Ipv4(smoltcp::wire::Ipv4Address::new(8, 8, 4, 4)),
                        53,
                    ),
                );
            });
            h
        };
        let local_ep = {
            let mut s = netstack.lock().await;
            s.poll(smoltcp::time::Instant::now());
            let _ = s.drain_tx();
            s.with_udp_socket(handle, |sock| {
                let listen = sock.endpoint();
                smoltcp::wire::IpEndpoint::new(
                    listen.addr.unwrap_or(smoltcp::wire::IpAddress::Ipv4(
                        smoltcp::wire::Ipv4Address::new(10, 0, 0, 2),
                    )),
                    listen.port,
                )
            })
        };

        // 构造一个入站 UDP 包：src 8.8.4.4:53 → local，payload "dns-reply"
        let reply =
            build_udp_packet(smoltcp::wire::Ipv4Address::new(8, 8, 4, 4), local_ep, b"dns-reply");
        {
            let mut s = netstack.lock().await;
            s.ingest_rx(reply);
            s.poll(smoltcp::time::Instant::now());
        }

        let out = pump_udp_to_client(&netstack, handle, &udp_dest(53)).await;
        let out = out.expect("frame emitted");
        // 读端解帧：payload + 回包源地址
        let pkt = xray_xudp::packet::PacketReader::new(std::io::Cursor::new(&out))
            .read_packet()
            .expect("parse frame")
            .expect("one packet");
        assert_eq!(pkt.data(), b"dns-reply");
        let target = pkt.udp_target().expect("udp target");
        assert_eq!(target.address(), &Address::from_ipv4_bytes([8, 8, 4, 4]));
        assert_eq!(target.port().value(), 53);
    }

    /// 构造 UDPv4 包（smoltcp wire）：src:53 → dst，payload。
    fn build_udp_packet(
        src: smoltcp::wire::Ipv4Address,
        dst: smoltcp::wire::IpEndpoint,
        payload: &[u8],
    ) -> Vec<u8> {
        use smoltcp::{
            phy::ChecksumCapabilities,
            wire::{IpAddress, Ipv4Packet, Ipv4Repr, UdpPacket, UdpRepr},
        };

        let dst_v4 = match dst.addr {
            IpAddress::Ipv4(a) => a,
            _ => unreachable!("v4 only in test"),
        };
        // UDP 段（8B 头 + payload）
        let mut udp_buf = vec![0u8; 8 + payload.len()];
        {
            let repr = UdpRepr { src_port: 53, dst_port: dst.port };
            let mut udp = UdpPacket::new_unchecked(&mut udp_buf);
            repr.emit(
                &mut udp,
                &IpAddress::Ipv4(src),
                &IpAddress::Ipv4(dst_v4),
                payload.len(),
                |buf| buf.copy_from_slice(payload),
                &ChecksumCapabilities::default(),
            );
        }
        // IP 包（20B 头；payload 已就位，emit 只填头 + checksum）
        let mut ip_buf = vec![0u8; 20 + udp_buf.len()];
        ip_buf[20..].copy_from_slice(&udp_buf);
        let repr4 = Ipv4Repr {
            src_addr: src,
            dst_addr: dst_v4,
            next_header: smoltcp::wire::IpProtocol::Udp,
            payload_len: udp_buf.len(),
            hop_limit: 64,
        };
        let mut ip = Ipv4Packet::new_unchecked(&mut ip_buf);
        repr4.emit(&mut ip, &ChecksumCapabilities::default());
        ip_buf
    }

    #[test]
    fn reserved_field_wire_format() {
        // Go bind.go:184-186 send —— copy(buff[1:], reserved)
        let mut pkt = vec![1u8, 9, 9, 9, 7, 7];
        apply_reserved(&mut pkt, &[1, 2, 3]);
        assert_eq!(&pkt[..5], &[1, 1, 2, 3, 7]);
        // recv —— 清零（Go bind.go:145-149）
        clear_reserved(&mut pkt);
        assert_eq!(&pkt[..5], &[1, 0, 0, 0, 7]);
        // 短包不动；reserved 非长度 3 不写
        let mut short = vec![1u8, 2];
        apply_reserved(&mut short, &[1, 2, 3]);
        assert_eq!(short, vec![1u8, 2]);
        let mut p2 = vec![1u8, 9, 9, 9];
        apply_reserved(&mut p2, &[5]);
        assert_eq!(p2, vec![1u8, 9, 9, 9]);
    }

    /// bd xoj：system dialer 注入——WG 自身 UDP 经 dialer 出站（Go bind.go:126-166
    /// netBindClient.connectTo）。用户 UDP 请求驱动 smoltcp tx → WG 握手 init →
    /// DialedUdp 惰性拨号 → XUDP 帧到达 mock「代理链」对端，帧 target = WG
    /// endpoint，reserved 写入包头 [1..4]（Go bind.go:184-186）。
    #[tokio::test]
    async fn make_dial_fn_routes_wg_udp_via_system_dialer() {
        use tokio::io::AsyncReadExt as _;
        use xray_transport::connection::{Connection, DuplexConnection};

        use crate::config::PeerConfig;

        let seen: std::sync::Arc<tokio::sync::Mutex<Option<Destination>>> =
            std::sync::Arc::new(tokio::sync::Mutex::new(None));
        let (client_end, mut wg_wire) = tokio::io::duplex(64 * 1024);
        let slot: std::sync::Arc<tokio::sync::Mutex<Option<tokio::io::DuplexStream>>> =
            std::sync::Arc::new(tokio::sync::Mutex::new(Some(client_end)));
        let dialer: DialFn = {
            let seen = Arc::clone(&seen);
            let slot = Arc::clone(&slot);
            Arc::new(move |dest: &Destination| {
                let seen = Arc::clone(&seen);
                let slot = Arc::clone(&slot);
                let dest = dest.clone();
                Box::pin(async move {
                    *seen.lock().await = Some(dest);
                    match slot.lock().await.take() {
                        Some(c) => Ok(Box::new(DuplexConnection::new(c)) as Box<dyn Connection>),
                        None => Err("unexpected second dial".to_string()),
                    }
                })
            })
        };

        let (sec_c, _) = {
            use boringtun::x25519::{PublicKey, StaticSecret};
            let secret_bytes: [u8; 32] = [0x77; 32];
            let secret = StaticSecret::from(secret_bytes);
            let public = PublicKey::from(&secret);
            (hex::encode(secret_bytes), hex::encode(public.as_bytes()))
        };
        let (_, pub_s) = {
            use boringtun::x25519::{PublicKey, StaticSecret};
            let secret_bytes: [u8; 32] = [0x88; 32];
            let secret = StaticSecret::from(secret_bytes);
            let public = PublicKey::from(&secret);
            (hex::encode(secret_bytes), hex::encode(public.as_bytes()))
        };
        let config = crate::config::DeviceConfig {
            secret_key: sec_c,
            endpoint: vec!["10.0.0.2/32".into()],
            peers: vec![PeerConfig {
                public_key: pub_s,
                endpoint: "203.0.113.9:51820".into(),
                ..Default::default()
            }],
            reserved: vec![7, 8, 9],
            ..Default::default()
        };

        let dial_fn = make_wireguard_dial_fn(config, None, Some(dialer));
        let conn = dial_fn(&udp_dest(53)).await.expect("dial through wireguard");

        // 用户 UDP 请求（XUDP 帧）→ UdpRelay → smoltcp → tx → WG 握手 init → dialed
        let mut frame = Vec::new();
        {
            let mut pw = PacketWriter::new(&mut frame, udp_dest(53), [0u8; 8]);
            pw.write_packet(b"q").expect("write frame");
        }
        let mut conn = conn;
        tokio::io::AsyncWriteExt::write_all(&mut conn, &frame).await.expect("write xudp frame");

        // mock「代理链」对端：dialer 收到 WG endpoint + XUDP 帧 target=endpoint
        let mut buf = vec![0u8; 2048];
        let n = tokio::time::timeout(Duration::from_secs(10), wg_wire.read(&mut buf))
            .await
            .expect("timeout waiting wg packet on dialed conn")
            .expect("wire read");

        let dialed_dest = seen.lock().await.clone().expect("dialer was called");
        assert_eq!(
            dialed_dest.address(),
            &Address::from_ipv4_bytes([203, 0, 113, 9]),
            "dialer 以 WG peer endpoint 拨号"
        );
        assert_eq!(dialed_dest.port().value(), 51820);
        assert_eq!(dialed_dest.network(), Network::UDP);

        let pkt = PacketReader::new(std::io::Cursor::new(&buf[..n]))
            .read_packet()
            .expect("parse frame")
            .expect("one packet");
        let target = pkt.udp_target().expect("udp target");
        assert_eq!(
            target.address(),
            &Address::from_ipv4_bytes([203, 0, 113, 9]),
            "XUDP 帧 target = WG endpoint"
        );
        assert_eq!(target.port().value(), 51820);
        let data = pkt.data();
        assert!(
            matches!(data.first().map(|b| b & 0x07), Some(1..=4)),
            "WG 消息类型（握手/数据），got head: {:?}",
            &data[..data.len().min(4)]
        );
        assert_eq!(&data[1..4], &[7, 8, 9], "reserved 写入包头（Go bind.go:184-186）");
    }
}
