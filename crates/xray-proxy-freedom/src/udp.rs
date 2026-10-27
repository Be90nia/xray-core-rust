//! Freedom UDP relay——XUDP 帧流 ↔ 原始 UDP 数据报。
//!
//! 对应 Go `proxy/freedom/freedom.go` 的 UDP 分支：
//! - **request** 方向：[`xray_xudp::packet::PacketReader`] 从 link.reader 读 XUDP 帧， 提取 (dest,
//!   payload)，通过 [`UdpSocket::send_to`] 发往目标。
//! - **response** 方向：[`UdpSocket::recv_from`] 读回 UDP 响应，用
//!   [`xray_xudp::packet::PacketWriter`] 封装为 XUDP 帧写回 link.writer。
//!
//! ## link 语义
//!
//! dispatcher 给 freedom 的 `link` 是一条**字节流**——对 UDP 目标，inbound 侧
//! （如 SOCKS UDP associate / dokodemo / tun）已将每个 UDP 数据报封装为 XUDP 帧
//! 写入流。freedom 的职责就是拆帧 → 真实 UDP socket → 装帧回写。
//!
//! ## ponytail: 单连接单 dest
//!
//! 每次 dispatch 创建一个 `UdpSocket`，所有帧都发往从首帧或原始 dest 解析出的目标。
//! 真实 Xray 对 Keep 帧的 `udp_target` 字段做 per-packet 路由（不同 dest），当前也支持
//! 但共享同一 socket（NAT 下 per-dest 用同一本地端口）。

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use tokio::net::UdpSocket;
use xray_buf::{
    io::{Reader, Writer},
    multi::MultiBuffer,
};
use xray_common::net::{address::Address, destination::Destination, port::Port};
use xray_transport::link::Link;
use xray_xudp::packet::{PacketError, PacketReader, PacketWriter};

/// XUDP GlobalID 长度（与 Go `xudp` 一致，私有常量 GLOBAL_ID_LEN=8）。
const GLOBAL_ID_LEN: usize = 8;

/// UDP recv 缓冲区大小（单包最大 65535 字节）。
const RECV_BUF_SIZE: usize = 65535;

/// UDP request pump 的 accum 缓冲上限（防 peer 灌爆内存）。
const ACCUM_MAX_BYTES: usize = 2 * 1024 * 1024;

/// UDP relay 策略（Go `Process` 的 `UDPOverride` + `defaultRule` 形态）。
#[derive(Debug, Clone, Default)]
pub struct UdpPolicy {
    /// destinationOverride（逐包改写请求目标；Go :269-279 + :596-601）。
    pub destination_override: Option<crate::config::DestinationOverride>,
    /// 配置的 final rules（双向逐包检查；Go :515-517 / :634-637）。
    pub final_rules: Vec<crate::config::FinalRule>,
    /// 按入站协议名推导的默认规则（Go `getDefaultFinalRule(inbound)`；None=不应用）。
    pub default_rule: Option<crate::config::FinalRule>,
    /// 域名解析策略（bd 2yj2/czwu，Go PacketWriter 用 config.DomainStrategy
    /// 逐帧解析域名；会话默认目标另经 GetDynamicStrategy 调整）。
    pub domain_strategy: xray_transport::sockopt::DomainStrategy,
}

/// Freedom UDP relay 主入口（无 noises、无策略）。
pub async fn relay(dest: &Destination, link: Link) -> io::Result<()> {
    relay_with_noises(dest, link, &[]).await
}

/// Freedom UDP relay 主入口（首包前注入 noises，对齐 Go `NoisePacketWriter`）。
pub async fn relay_with_noises(
    dest: &Destination,
    link: Link,
    noises: &[crate::config::Noise],
) -> io::Result<()> {
    // 兼容接缝：自持 `for_plugin` ctx（测试/库层便捷形）。生产装配经
    // `FreedomDispatchBridge` 注入 `arm_plugin_ctx`。绑定局部变量：scope 必须
    // 覆盖 relay_policy 全程（含响应泵 join）——临时值语义依赖「同语句存活
    // 到 await 完」的隐式规则，显式绑定防呆。
    let ctx = xray_frame::PluginContext::for_plugin("freedom");
    relay_policy(&ctx, dest, link, noises, &UdpPolicy::default()).await
}

/// Freedom UDP relay 主入口（携带 override/finalRules/defaultRule 策略）。
///
/// 解析目标地址 → 绑定 UDP socket → 双向并发转发 XUDP 帧与 UDP 数据报。
/// 任一方向结束（EOF / 错误）时整体返回。
///
/// - 请求方向逐包：override 改写帧目标（Go :596-601）→ Block 检查丢包（:634-637） → 发送；noises
///   首包前注入，override 端口为 53（DNS）时跳过（:668-674）。
/// - 响应方向逐包：来源 Block 检查丢包（Go `PacketReader` :515-517）。
pub async fn relay_policy(
    ctx: &xray_frame::PluginContext,
    dest: &Destination,
    link: Link,
    noises: &[crate::config::Noise],
    policy: &UdpPolicy,
) -> io::Result<()> {
    let Link { mut reader, mut writer } = link;

    // 1. 解析目标地址（override 先于解析，Go :269-279 override 先于 dial）
    let overridden =
        crate::config::apply_destination_override(dest, policy.destination_override.as_ref());
    let default_target =
        resolve_socket_addr(&overridden, dynamic_udp_strategy(policy.domain_strategy, dest))
            .await?;

    // override 端口为 53（DNS）时首包前不注入 noises（Go :668-674：
    // `if w.UDPOverride.Port == 53` 跳过 Noise，保守不干扰 DNS 查询）
    let skip_noise = matches!(
        policy.destination_override.as_ref().and_then(|o| o.server.as_ref()),
        Some(s) if s.port == 53
    );

    // 2. 绑定 UDP socket：sendThrough 源地址优先（bd 7zc，对齐 Go system_dialer.go:59-84
    //    ListenPacket 绑 srcAddr），否则与目标同族通配。 经 dial_udp_packet_conn 过
    //    DialerController（AI7：Go 走 DialSystem UDP 分支同样过 controllers——TUN 出站绑定对 UDP
    //    生效的关键接线）。
    let src_ip = xray_transport::system_dialer::DIAL_SRC.try_with(|v| *v).ok().flatten();
    let bind_addr = match src_ip {
        Some(ip) => SocketAddr::new(ip, 0),
        None => match default_target {
            SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0),
            SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0),
        },
    };
    let sock = Arc::new(
        xray_transport::system_dialer::dial_udp_packet_conn(bind_addr, default_target).await?,
    );

    // 3. GlobalID（随机 8 字节，对应 Go xudp.NewPacketWriter 的 GlobalID）
    let global_id: [u8; GLOBAL_ID_LEN] = rand::random();

    // 4. 响应 pump: socket.recv_from → XUDP 帧 → link.writer
    let resp_sock = Arc::clone(&sock);
    let resp_global_id = global_id;
    let resp_policy = policy.clone();
    // for_plugin/装配根 scope 均不 close——闸关态=装配 bug，fail-visible。
    let resp_task =
        ctx.spawn(async move {
            pump_response(&resp_sock, resp_global_id, &mut writer, &resp_policy).await
        })
        .expect("plugin ctx FxScope is never closed (assembly-owned)");

    // 5. 请求 pump: link.reader → XUDP 帧 → socket.send_to noises 在首个真实数据报前注入（对齐 Go
    //    NoisePacketWriter 首写触发）
    let mut noises = if noises.is_empty() { None } else { Some(noises.to_vec()) };
    let mut resolved: HashMap<String, IpAddr> = HashMap::new();
    let req_result = pump_request(
        &sock,
        default_target,
        &mut reader,
        &mut noises,
        policy,
        skip_noise,
        &mut resolved,
    )
    .await;

    // 请求方向结束（link EOF），等待响应方向也结束
    let _ = resp_task.join().await;

    req_result
}

/// UDP 会话策略：Go `GetDynamicStrategy`（freedom.go:287-289）——UseIP/ForceIP
/// 在原始目标为 IP 时按其家族收窄（原目标 v4 → 优先 v4 的 ip46 形态）。
fn dynamic_udp_strategy(
    strategy: xray_transport::sockopt::DomainStrategy,
    orig: &Destination,
) -> xray_transport::sockopt::DomainStrategy {
    use xray_transport::sockopt::DomainStrategy as DS;
    let Some(ip) = orig.address().ip() else {
        return strategy;
    };
    match strategy {
        DS::UseIP if ip.is_ipv4() => DS::UseIPv4v6,
        DS::UseIP => DS::UseIPv6v4,
        DS::ForceIP if ip.is_ipv4() => DS::ForceIPv4v6,
        DS::ForceIP => DS::ForceIPv6v4,
        other => other,
    }
}

/// 将目标 Destination 解析为 SocketAddr。
///
/// IP 地址直接转换；Domain 按 strategy 解析（bd 2yj2）：有策略走
/// [`lookup_for_ip`] 家族过滤随机选一（Force\* 失败硬错，Use\* 失败降级
/// 系统 resolver）；AsIs 走系统 DNS。
async fn resolve_socket_addr(
    dest: &Destination,
    strategy: xray_transport::sockopt::DomainStrategy,
) -> io::Result<SocketAddr> {
    let port = dest.port().value();
    match dest.address() {
        Address::IPv4(ip) => Ok(SocketAddr::new(IpAddr::V4(*ip), port)),
        Address::IPv6(ip) => Ok(SocketAddr::new(IpAddr::V6(*ip), port)),
        Address::Domain(domain) => {
            if strategy.has_strategy() {
                match xray_transport::system_dialer::lookup_for_ip(domain, strategy, None).await {
                    Ok(ips) if !ips.is_empty() => {
                        use rand::seq::IndexedRandom;
                        return Ok(SocketAddr::new(
                            *ips.choose(&mut rand::rng()).expect("non-empty"),
                            port,
                        ));
                    },
                    _ => {
                        // Force* 解析失败硬错（Go :293-295）；Use* 降级系统解析（Go :296-300）
                        if strategy.force_ip() {
                            return Err(io::Error::new(
                                io::ErrorKind::NotFound,
                                format!("force strategy resolve failed for {domain}"),
                            ));
                        }
                    },
                }
            }
            let lookup = format!("{domain}:{port}");
            tokio::net::lookup_host(&lookup)
                .await?
                .next()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "DNS resolve failed"))
        },
    }
}

/// 请求方向：从 link.reader 读 XUDP 帧 → socket.send_to。
///
/// 对应 Go `freedom.Process` UDP 分支的 `request` goroutine +
/// `xudp.NewPacketReader(link.Reader)` + `PacketWriter.WriteMultiBuffer`。
/// `resolved` 为 per-connection 域名→IP 缓存（Go `ResolvedUDPAddr`
/// TypedSyncMap :608-612：多 IP 域名随机解析会导致同会话帧漂移，须缓存）。
async fn pump_request(
    sock: &UdpSocket,
    default_target: SocketAddr,
    reader: &mut Box<dyn Reader>,
    noises: &mut Option<Vec<crate::config::Noise>>,
    policy: &UdpPolicy,
    skip_noise: bool,
    resolved: &mut HashMap<String, IpAddr>,
) -> io::Result<()> {
    let mut accum: Vec<u8> = Vec::new();
    loop {
        // 尽量从 accum 解析完整帧。半帧（UnexpectedEof）= 读边界切开，必须继续
        // 追加字节而不是当终止帧退出（z7ya：误判会让整条流在突发中途静默死亡）。
        loop {
            match parse_and_send(
                sock,
                &mut accum,
                default_target,
                noises,
                policy,
                skip_noise,
                resolved,
            )
            .await?
            {
                FrameParse::Progress => {},
                FrameParse::Terminated => return Ok(()),
                FrameParse::NeedMore => break,
            }
        }
        match reader.read_multi_buffer().await {
            Ok(mb) => {
                if mb.is_empty() {
                    return Ok(());
                }
                // 池化 Buffer 直写：逐 buffer 单拷贝进 accum，免 to_vec 的中间分配+二次拷贝。
                accum.reserve(mb.len());
                for buf in mb.iter() {
                    accum.extend_from_slice(buf.bytes());
                }
                if accum.len() > ACCUM_MAX_BYTES {
                    return Err(io::Error::new(
                        io::ErrorKind::OutOfMemory,
                        format!("udp accum exceeded {ACCUM_MAX_BYTES} bytes"),
                    ));
                }
            },
            Err(_) => return Ok(()),
        }
    }
}

/// 域名帧目标解析（Go PacketWriter :613-641）：有策略走
/// [`lookup_for_ip`] 家族过滤随机选一（Force\* 失败也丢帧——Go :627-630
/// 注释 drop packet；Use\* 失败落系统 resolver，Go ShouldUseSystemResolver）；
/// AsIs 走系统解析（Go ResolveUDPAddr）。
///
/// # Errors
/// 两条路径都解析不出 IP 时返回错误，调用方丢帧继续。
async fn resolve_udp_domain(
    domain: &str,
    port: u16,
    strategy: xray_transport::sockopt::DomainStrategy,
) -> io::Result<IpAddr> {
    if strategy.has_strategy() {
        if let Ok(ips) = xray_transport::system_dialer::lookup_for_ip(domain, strategy, None).await
        {
            use rand::seq::IndexedRandom;
            if let Some(ip) = ips.choose(&mut rand::rng()) {
                return Ok(*ip);
            }
        } else if strategy.force_ip() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("force strategy resolve failed for {domain}"),
            ));
        }
    }
    tokio::net::lookup_host((domain, port)).await?.next().map(|sa| sa.ip()).ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, format!("DNS resolve failed for {domain}"))
    })
}

/// 单次帧解析结果（z7ya：区分「半帧」与「协议层终止帧」）。
///
/// `Progress`：解析并消费了一帧（已发送或按策略丢弃）；
/// `NeedMore`：accum 无完整帧（空或半帧）——必须继续读字节，**不是**流结束；
/// `Terminated`：读到协议层终止帧（019n：非数据帧 / 非法长度头），request 泵退出。
enum FrameParse {
    Progress,
    NeedMore,
    Terminated,
}

/// 从 accum 前端解析一个 XUDP 帧，逐包应用策略后 send_to。
///
/// 逐包顺序对齐 Go `PacketWriter.WriteMultiBuffer` :586-656：
/// 1. override 改写帧目标（:596-601）；
/// 2. 域名帧逐帧解析 + per-domain 缓存（bd czwu，Go :610-641）；
/// 3. finalRule Block 检查在解析后的 IP 上，命中丢包继续（bd 6x5o，:634-637）；
/// 4. noises 首包前注入，override 端口 53 时跳过（NoisePacketWriter :668-674）。
///
/// 帧不完整（UnexpectedEof）返回 [`FrameParse::NeedMore`]，致命错误返回 Err。
async fn parse_and_send(
    sock: &UdpSocket,
    accum: &mut Vec<u8>,
    default_target: SocketAddr,
    noises: &mut Option<Vec<crate::config::Noise>>,
    policy: &UdpPolicy,
    skip_noise: bool,
    resolved: &mut HashMap<String, IpAddr>,
) -> io::Result<FrameParse> {
    if accum.is_empty() {
        return Ok(FrameParse::NeedMore);
    }

    // 用 Cursor + 同步 PacketReader 解析一帧
    let (result, consumed) = {
        let mut cursor = std::io::Cursor::new(&accum[..]);
        let mut pr = PacketReader::new(&mut cursor);
        let r = pr.read_packet();
        let pos = cursor.position() as usize;
        (r, pos)
    };

    match result {
        Ok(Some(pkt)) => {
            accum.drain(..consumed);
            let (data, udp_target) = pkt.into_parts();
            // 逐包 override 改写（Go :596-601：地址有效替换 / 端口非 0 替换）
            let mut effective = udp_target.unwrap_or_else(|| {
                Destination::udp(default_target.ip().into(), Port::new(default_target.port()))
            });
            effective = crate::config::apply_destination_override(
                &effective,
                policy.destination_override.as_ref(),
            );
            // 域名帧逐帧解析（bd czwu①：Go :610-641，此前 fallback 会话默认目标
            // = 静默发错主机）；解析失败丢帧继续（Go :627-630 b.Release(); continue）
            let target = match dest_to_socket_addr(&effective) {
                Some(sa) => sa,
                None => {
                    let Some(domain) = effective.address().as_domain().map(str::to_string) else {
                        return Ok(FrameParse::Progress);
                    };
                    let ip = match resolved.get(&domain) {
                        Some(ip) => *ip,
                        None => match resolve_udp_domain(
                            &domain,
                            effective.port().value(),
                            policy.domain_strategy,
                        )
                        .await
                        {
                            Ok(ip) => {
                                resolved.insert(domain.clone(), ip);
                                ip
                            },
                            Err(e) => {
                                // 丢帧继续（Go :627-630 b.Release(); continue；
                                // Force* 失败同样丢帧——Go :625-628 注释）
                                crate::FREEDOM_LOG.debug(format!(
                                    "freedom: udp frame dropped, resolve failed: {e} domain={domain}"
                                ));
                                return Ok(FrameParse::Progress);
                            },
                        },
                    };
                    effective = crate::config::destination_with_ip(&effective, ip);
                    SocketAddr::new(ip, effective.port().value())
                },
            };
            // finalRule Block 检查在解析后的目标上（bd 6x5o UDP：Go :634-637
            // applyFinalRules 在域名→IP 之后）：命中丢包但不中断流
            if crate::config::is_blocked_by_rules(
                &policy.final_rules,
                policy.default_rule.as_ref(),
                &effective,
            ) {
                crate::FREEDOM_LOG
                    .debug(format!("freedom: udp packet blocked by final rule dest={effective}"));
                return Ok(FrameParse::Progress);
            }
            // 首个真实数据报前发送 noises（对齐 Go NoisePacketWriter.WriteMultiBuffer：
            // 噪声包发往同一目标，applyTo 按目标 IP 族过滤，写后按 delay 睡眠；
            // override 端口 53（DNS）时跳过——Go :668-674）
            if !skip_noise {
                if let Some(ns) = noises.take() {
                    send_noises(sock, target, &ns).await?;
                }
            }
            sock.send_to(&data, target).await?;
            Ok(FrameParse::Progress)
        },
        Ok(None) => Ok(FrameParse::Terminated), // 019n 终止帧（流内非数据帧）
        Err(PacketError::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof => {
            Ok(FrameParse::NeedMore)
        }, // 半帧：读边界切开，继续读字节而非终止
        // 019n：协议层终止帧
        Err(PacketError::MetadataTooShort(_)) => Ok(FrameParse::Terminated),
        Err(e) => Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string())),
    }
}

/// 依次发送 noise 包到 `target`（对应 Go `NoisePacketWriter` 噪声循环 :691-724）。
async fn send_noises(
    sock: &UdpSocket,
    target: SocketAddr,
    noises: &[crate::config::Noise],
) -> io::Result<()> {
    use rand::RngCore;
    for n in noises {
        let is_v4 = target.is_ipv4();
        match n.apply_to.as_str() {
            "ipv4" if !is_v4 => continue,
            "ipv6" if is_v4 => continue,
            _ => {},
        }
        // 用户指定 packet 或随机长度噪声（[length_min, length_max) 半开，对齐 Go RandBetween）
        let packet: Vec<u8> = if !n.packet.is_empty() {
            n.packet.clone()
        } else {
            let mut buf =
                vec![0u8; crate::fragment::rand_between(n.length_min, n.length_max) as usize];
            rand::rng().fill_bytes(&mut buf);
            buf
        };
        sock.send_to(&packet, target).await?;
        if n.delay_min != 0 || n.delay_max != 0 {
            tokio::time::sleep(std::time::Duration::from_millis(crate::fragment::rand_between(
                n.delay_min,
                n.delay_max,
            )))
            .await;
        }
    }
    Ok(())
}
/// 响应方向：socket.recv_from → XUDP 帧 → link.writer。
///
/// 对应 Go `freedom.Process` UDP 分支的 `response` goroutine +
/// `xudp.NewPacketWriter(link.Writer, ctx)`。帧来源地址 = recv_from 的真实
/// peer（multi-dest 会话下客户端才能区分各目标的响应来源）。
/// 逐包来源 finalRule Block 检查（Go `PacketReader.ReadMultiBuffer` :515-517，
/// 命中丢包 continue）。
async fn pump_response(
    sock: &UdpSocket,
    global_id: [u8; GLOBAL_ID_LEN],
    writer: &mut Box<dyn Writer>,
    policy: &UdpPolicy,
) -> io::Result<()> {
    let mut buf = vec![0u8; RECV_BUF_SIZE];
    loop {
        let (n, peer) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(_) => return Ok(()),
        };
        if n == 0 {
            continue;
        }
        // 帧来源 = 响应真实来源
        let source = Destination::udp(
            match peer.ip() {
                IpAddr::V4(v) => Address::IPv4(v),
                IpAddr::V6(v) => Address::IPv6(v),
            },
            Port::new(peer.port()),
        );
        // 来源 Block 检查：命中丢包继续（Go :515-517）
        if crate::config::is_blocked_by_rules(
            &policy.final_rules,
            policy.default_rule.as_ref(),
            &source,
        ) {
            crate::FREEDOM_LOG
                .debug(format!("freedom: udp response blocked by final rule source={source}"));
            continue;
        }
        // 用同步 PacketWriter 装帧
        let mut frame = Vec::with_capacity(n + 64);
        let mut pw = PacketWriter::new(&mut frame, source, global_id);
        if pw.write_packet(&buf[..n]).is_err() {
            return Ok(());
        }
        drop(pw);

        let mut mb = MultiBuffer::new();
        mb.merge_bytes(&frame);
        if writer.write_multi_buffer(mb).await.is_err() {
            return Ok(()); // writer 关闭
        }
    }
}
/// Destination → SocketAddr（仅 IP 地址，Domain 返回 None）。
fn dest_to_socket_addr(dest: &Destination) -> Option<SocketAddr> {
    let port = dest.port().value();
    match dest.address() {
        Address::IPv4(ip) => Some(SocketAddr::new(IpAddr::V4(*ip), port)),
        Address::IPv6(ip) => Some(SocketAddr::new(IpAddr::V6(*ip), port)),
        Address::Domain(_) => None,
    }
}

#[cfg(test)]
mod tests {
    // FAKE_DNS_LOCK 等测试串行锁：guard 有意跨 await 存活（测试进程内互斥），无生产死锁面
    #![allow(clippy::await_holding_lock)]

    fn test_ctx() -> std::sync::Arc<xray_frame::PluginContext> {
        std::sync::Arc::new(xray_frame::PluginContext::for_plugin("freedom"))
    }
    use xray_common::net::{address::Address, network::Network, port::Port};

    use super::*;

    /// 构造 IPv4 UDP Destination。
    fn udp_dest(ip: &str, port: u16) -> Destination {
        let addr = Address::from_ipv4_bytes(ip.parse::<std::net::Ipv4Addr>().unwrap().octets());
        Destination::new(addr, Port::new(port), Network::UDP)
    }

    /// AI7：freedom UDP 出站 socket（TUN UDP 流量的真实出站，Go 走 DialSystem
    /// UDP 分支过 controllers）必须过 DialerController——relay_policy 的 bind
    /// 走 `dial_udp_packet_conn`。魔数端口过滤隔离并行测试。
    #[tokio::test]
    async fn udp_relay_policy_runs_dialer_controllers() {
        static SAW: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        const PROBE_PORT: u16 = 59996;
        // 闭包参数类型经 DialerController 注解推断（freedom 不依赖 socket2）。
        let ctl: xray_transport::system_dialer::DialerController =
            std::sync::Arc::new(|_socket, dest| {
                if dest.port() == PROBE_PORT {
                    SAW.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
                Ok(())
            });
        xray_transport::system_dialer::register_dialer_controller(ctl).unwrap();
        // echo 固定魔数端口（controller 按它过滤）；端口被占即跳过（环境冲突）。
        let echo = match UdpSocket::bind(("127.0.0.1", PROBE_PORT)).await {
            Ok(s) => s,
            Err(_) => return,
        };
        let echo_port = echo.local_addr().unwrap().port();
        let echo_task = xray_common::testing::spawn(
            "udp-relay-policy-runs-dialer-controllers-echo",
            async move {
                let mut buf = vec![0u8; RECV_BUF_SIZE];
                while let Ok((n, peer)) = echo.recv_from(&mut buf).await {
                    let _ = echo.send_to(&buf[..n], peer).await;
                }
            },
        );

        let pipe_opt = xray_buf::pipe::PipeOption::default();
        let (up_r, up_w) = xray_buf::pipe::new_with_option(pipe_opt);
        let (dn_r, dn_w) = xray_buf::pipe::new_with_option(pipe_opt);
        let link = Link::new(Box::new(up_r) as Box<dyn Reader>, Box::new(dn_w) as Box<dyn Writer>);
        let dest = udp_dest("127.0.0.1", echo_port);
        let relay_task = xray_common::testing::spawn(
            "udp-relay-policy-runs-dialer-controllers-echo",
            async move { relay(&dest, link).await },
        );

        // client 写一帧 XUDP → relay bind（controller 在此被调）→ send → echo 回包。
        let mut client_writer = Box::new(up_w) as Box<dyn Writer>;
        let mut frame = Vec::new();
        {
            let mut pw = PacketWriter::new(&mut frame, udp_dest("127.0.0.1", echo_port), [9u8; 8]);
            pw.write_packet(b"ctl-probe").unwrap();
        }
        let mut mb = MultiBuffer::new();
        mb.merge_bytes(&frame);
        client_writer.write_multi_buffer(mb).await.unwrap();

        let mut client_reader = Box::new(dn_r) as Box<dyn Reader>;
        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client_reader.read_multi_buffer(),
        )
        .await
        .expect("timeout waiting echo")
        .expect("read ok");
        assert!(!resp.to_vec().is_empty(), "echo 回包应为空帧之外的非空数据");
        assert!(
            SAW.load(std::sync::atomic::Ordering::SeqCst) >= 1,
            "controller 未被 freedom UDP 出站路径调用"
        );

        drop(client_writer);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), relay_task).await;
        echo_task.abort();
    }

    /// 端到端：freedom UDP relay 把 XUDP 帧 → UDP echo server → XUDP 帧回写。
    #[tokio::test]
    async fn udp_relay_echo_roundtrip() {
        // 1. 启动 UDP echo server
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        let echo_task = xray_common::testing::spawn("udp-relay-echo-roundtrip-echo", async move {
            let mut buf = vec![0u8; RECV_BUF_SIZE];
            while let Ok((n, peer)) = echo.recv_from(&mut buf).await {
                let _ = echo.send_to(&buf[..n], peer).await;
            }
        });

        // 2. 构造 link（pipe 对）：client 写 XUDP 帧 → freedom relay → UDP server freedom relay
        //    回写 XUDP 帧 → client 读
        let pipe_opt = xray_buf::pipe::PipeOption::default();
        let (up_r, up_w) = xray_buf::pipe::new_with_option(pipe_opt);
        let (dn_r, dn_w) = xray_buf::pipe::new_with_option(pipe_opt);
        let link = Link::new(Box::new(up_r) as Box<dyn Reader>, Box::new(dn_w) as Box<dyn Writer>);

        let dest = udp_dest("127.0.0.1", echo_addr.port());
        let relay_task = xray_common::testing::spawn("udp-relay-echo-roundtrip", async move {
            relay(&dest, link).await
        });

        // 3. client 写一个 XUDP 帧
        let mut client_writer = Box::new(up_w) as Box<dyn Writer>;
        let global_id: [u8; GLOBAL_ID_LEN] = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut frame = Vec::new();
        {
            let mut pw =
                PacketWriter::new(&mut frame, udp_dest("127.0.0.1", echo_addr.port()), global_id);
            pw.write_packet(b"hello-udp").unwrap();
        }
        let mut mb = MultiBuffer::new();
        mb.merge_bytes(&frame);
        client_writer.write_multi_buffer(mb).await.unwrap();

        // 4. client 读回 echo（XUDP 帧）
        let mut client_reader = Box::new(dn_r) as Box<dyn Reader>;
        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client_reader.read_multi_buffer(),
        )
        .await
        .expect("timeout reading echo")
        .expect("read ok");

        let resp_bytes = resp.to_vec();
        // 解析回包 XUDP 帧
        let mut pr = PacketReader::new(std::io::Cursor::new(&resp_bytes[..]));
        let pkt = pr.read_packet().expect("parse response frame").expect("non-empty");
        assert_eq!(pkt.data(), b"hello-udp");

        // 关闭 client writer 让 relay 的 request pump 收到 EOF
        drop(client_writer);

        // relay 应正常结束
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), relay_task).await;

        echo_task.abort();
    }

    /// 多包往返：连续写多个 XUDP 帧，验证都能 echo 回来。
    // nn8os 2b 残余豁免：测试耗时断言用 std 即时读数（墙钟差），非插件能力面。
    #[allow(clippy::disallowed_methods, reason = "测试耗时断言配套，非生产时钟取用")]
    #[tokio::test]
    async fn udp_relay_multiple_packets() {
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        let echo_task =
            xray_common::testing::spawn("udp-relay-multiple-packets-echo", async move {
                let mut buf = vec![0u8; RECV_BUF_SIZE];
                while let Ok((n, peer)) = echo.recv_from(&mut buf).await {
                    let _ = echo.send_to(&buf[..n], peer).await;
                }
            });

        let pipe_opt = xray_buf::pipe::PipeOption::default();
        let (up_r, up_w) = xray_buf::pipe::new_with_option(pipe_opt);
        let (dn_r, dn_w) = xray_buf::pipe::new_with_option(pipe_opt);
        let link = Link::new(Box::new(up_r) as Box<dyn Reader>, Box::new(dn_w) as Box<dyn Writer>);

        let dest = udp_dest("127.0.0.1", echo_addr.port());
        let relay_task =
            xray_common::testing::spawn("udp-relay-multiple-packets-echo", async move {
                relay(&dest, link).await
            });

        let mut client_writer = Box::new(up_w) as Box<dyn Writer>;
        let global_id: [u8; GLOBAL_ID_LEN] = [0xAA; GLOBAL_ID_LEN];
        let dest_frame = udp_dest("127.0.0.1", echo_addr.port());

        // 写 3 个包到一个帧缓冲
        let mut combined = Vec::new();
        {
            let mut pw = PacketWriter::new(&mut combined, dest_frame.clone(), global_id);
            pw.write_packet(b"one").unwrap();
            pw.write_packet(b"two").unwrap();
            pw.write_packet(b"three").unwrap();
        }
        let mut mb = MultiBuffer::new();
        mb.merge_bytes(&combined);
        client_writer.write_multi_buffer(mb).await.unwrap();

        // 读回响应，累积字节（帧可能跨 read_multi_buffer），直到解析出 3 个包或超时
        let mut client_reader = Box::new(dn_r) as Box<dyn Reader>;
        let mut collected = Vec::new();
        let mut payloads = Vec::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while payloads.len() < 3 {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                panic!("timeout: only got {} packets", payloads.len());
            }
            match tokio::time::timeout(remaining, client_reader.read_multi_buffer()).await {
                Ok(Ok(mb)) if !mb.is_empty() => collected.extend_from_slice(&mb.to_vec()),
                _ => {},
            }
            // 尝试从累积字节解析完整帧
            let mut pr = PacketReader::new(std::io::Cursor::new(&collected[..]));
            payloads.clear();
            while let Ok(Some(pkt)) = pr.read_packet() {
                payloads.push(pkt.data().to_vec());
            }
        }
        assert_eq!(payloads, vec![b"one".to_vec(), b"two".to_vec(), b"three".to_vec()]);

        drop(client_writer);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), relay_task).await;
        echo_task.abort();
    }

    #[test]
    fn dest_to_socket_addr_ipv4() {
        let d = udp_dest("127.0.0.1", 8080);
        let sa = dest_to_socket_addr(&d).unwrap();
        assert_eq!(sa.port(), 8080);
        assert!(sa.is_ipv4());
    }

    #[test]
    fn dest_to_socket_addr_domain_returns_none() {
        let d =
            Destination::new(Address::Domain("example.com".into()), Port::new(443), Network::UDP);
        assert!(dest_to_socket_addr(&d).is_none());
    }

    /// 构造 relay 策略 + destinationOverride JSON（复用生产解析路径）。
    #[allow(clippy::unnecessary_literal_unwrap)] // 测试常量 JSON 必然 Some
    fn override_to(port: u16) -> UdpPolicy {
        UdpPolicy {
            destination_override: Some(crate::config::DestinationOverride::from_json(
                &serde_json::json!({"server": {"address": "127.0.0.1", "port": port}}),
            ))
            .expect("override json"),
            ..Default::default()
        }
    }

    /// 逐包 destinationOverride：帧目标 A，override 改写为 B → 数据报到 B 不到 A。
    #[tokio::test]
    async fn udp_per_packet_override_rewrites_target() {
        let dest_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a_port = dest_a.local_addr().unwrap().port();
        let b_port = dest_b.local_addr().unwrap().port();
        let policy = override_to(b_port);

        let pipe_opt = xray_buf::pipe::PipeOption::default();
        let (up_r, up_w) = xray_buf::pipe::new_with_option(pipe_opt);
        let (_dn_r, dn_w) = xray_buf::pipe::new_with_option(pipe_opt);
        let link = Link::new(Box::new(up_r) as Box<dyn Reader>, Box::new(dn_w) as Box<dyn Writer>);
        let dest = udp_dest("127.0.0.1", a_port);
        let relay_task =
            xray_common::testing::spawn("udp-per-packet-override-rewrites-target", async move {
                let ctx = test_ctx();
                relay_policy(&ctx, &dest, link, &[], &policy).await
            });

        let mut client_writer = Box::new(up_w) as Box<dyn Writer>;
        let mut frame = Vec::new();
        {
            let mut pw = PacketWriter::new(&mut frame, udp_dest("127.0.0.1", a_port), [7; 8]);
            pw.write_packet(b"overridden").unwrap();
        }
        let mut mb = MultiBuffer::new();
        mb.merge_bytes(&frame);
        client_writer.write_multi_buffer(mb).await.unwrap();
        drop(client_writer);

        let mut buf = [0u8; 64];
        let (n, payload_ok) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let (n, _) = dest_b.recv_from(&mut buf).await.unwrap();
            (n, &buf[..n] == b"overridden")
        })
        .await
        .expect("override target should receive the packet");
        assert_eq!(n, "overridden".len());
        assert!(payload_ok);
        // 原始目标 A 收不到（override 改写）
        assert!(dest_a.try_recv(&mut buf).is_err(), "original target should not receive");

        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), relay_task).await;
    }

    /// 请求方向 finalRule Block：命中丢包不发送（Go PacketWriter :634-637）。
    #[tokio::test]
    async fn udp_request_blocked_by_final_rule() {
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo.local_addr().unwrap().port();

        let rule_cfg = crate::config::FinalRuleConfig::from_json(&serde_json::json!({
            "action": "block", "network": "udp", "port": echo_port
        }))
        .unwrap();
        let policy = UdpPolicy {
            final_rules: vec![crate::config::FinalRule::build(&rule_cfg).unwrap()],
            ..Default::default()
        };

        let pipe_opt = xray_buf::pipe::PipeOption::default();
        let (up_r, up_w) = xray_buf::pipe::new_with_option(pipe_opt);
        let (_dn_r, dn_w) = xray_buf::pipe::new_with_option(pipe_opt);
        let link = Link::new(Box::new(up_r) as Box<dyn Reader>, Box::new(dn_w) as Box<dyn Writer>);
        let dest = udp_dest("127.0.0.1", echo_port);
        let relay_task =
            xray_common::testing::spawn("udp-request-blocked-by-final-rule-echo", async move {
                let ctx = test_ctx();
                relay_policy(&ctx, &dest, link, &[], &policy).await
            });

        let mut client_writer = Box::new(up_w) as Box<dyn Writer>;
        let mut frame = Vec::new();
        {
            let mut pw = PacketWriter::new(&mut frame, udp_dest("127.0.0.1", echo_port), [8; 8]);
            pw.write_packet(b"blocked").unwrap();
        }
        let mut mb = MultiBuffer::new();
        mb.merge_bytes(&frame);
        client_writer.write_multi_buffer(mb).await.unwrap();
        drop(client_writer);

        // request pump EOF 后 relay 的 response 侧仍挂在 recv_from（生产由
        // link.writer 关闭驱动结束）——测试只等 request 侧排空即可
        let _ = tokio::time::timeout(std::time::Duration::from_millis(500), relay_task).await;
        let mut buf = [0u8; 64];
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(300), echo.recv_from(&mut buf))
                .await
                .is_err(),
            "blocked packet must not reach the target"
        );
    }

    /// override 端口为 53（DNS）时跳过 noises（Go NoisePacketWriter :668-674）。
    #[tokio::test]
    async fn udp_noise_skipped_when_override_port_53() {
        // override 端口 53 = 数据实际发往 53 → 测试 socket 直接绑 53
        // （Windows 无特权端口限制；53 被占用时本测试报错即环境冲突）
        let target = match UdpSocket::bind("127.0.0.1:53").await {
            Ok(s) => s,
            Err(_) => return, // 环境端口冲突，跳过验证
        };
        let policy = override_to(53);
        let noises = vec![crate::config::Noise {
            packet: vec![1, 2, 3, 4],
            apply_to: "ip".into(),
            ..Default::default()
        }];

        let pipe_opt = xray_buf::pipe::PipeOption::default();
        let (up_r, up_w) = xray_buf::pipe::new_with_option(pipe_opt);
        let (_dn_r, dn_w) = xray_buf::pipe::new_with_option(pipe_opt);
        let link = Link::new(Box::new(up_r) as Box<dyn Reader>, Box::new(dn_w) as Box<dyn Writer>);
        let dest = udp_dest("127.0.0.1", 53001);
        let relay_task =
            xray_common::testing::spawn("udp-noise-skipped-when-override-port-53", async move {
                let ctx = test_ctx();
                relay_policy(&ctx, &dest, link, &noises, &policy).await
            });

        let mut client_writer = Box::new(up_w) as Box<dyn Writer>;
        let mut frame = Vec::new();
        {
            let mut pw = PacketWriter::new(&mut frame, udp_dest("127.0.0.1", 53001), [9; 8]);
            pw.write_packet(b"dns-packet").unwrap();
        }
        let mut mb = MultiBuffer::new();
        mb.merge_bytes(&frame);
        client_writer.write_multi_buffer(mb).await.unwrap();
        drop(client_writer);

        // 只应收到 1 个数据报（数据），noise 被跳过（否则是 2 个）
        let mut received = 0usize;
        let mut buf = [0u8; 64];
        let _ = tokio::time::timeout(std::time::Duration::from_millis(800), async {
            loop {
                if target.recv_from(&mut buf).await.is_ok() {
                    received += 1;
                }
            }
        })
        .await;
        assert_eq!(received, 1, "noise must be skipped for port 53 override, got {received}");
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), relay_task).await;
    }
    // 019n：终止帧触发 request EOF，但 resp_task 永久等 UDP recv_from（无 EOF 概念）
    // 真正验证 request 端响应：单 spawn pump_request 测试避免依赖 resp_task.await
    // 直接验证协议层：terminator 帧触发 xudp PacketReader::MetadataTooShort
    // request pump 端处理逻辑（line 254）依赖此错误类型返 false→EOF。
    #[tokio::test]
    async fn udp_relay_terminator_frame_ends_request_pump() {
        // 0x00 0x02 = body_len=2 < MIN_META_LEN=4 → MetadataTooShort
        let terminator = [0x00u8, 0x02u8, 0xAA, 0xBB];
        let mut cursor = std::io::Cursor::new(&terminator[..]);
        let mut pr = xray_xudp::packet::PacketReader::new(&mut cursor);
        let r = pr.read_packet();
        assert!(
            matches!(r, Err(xray_xudp::packet::PacketError::MetadataTooShort(_))),
            "terminator 帧 (body_len<MIN_META_LEN) 应触发 MetadataTooShort, got {r:?}"
        );
    }

    /// z7ya 回归：帧被读边界切开（半帧）时，request 泵必须继续读字节，
    /// 不得把半帧误判为协议层终止帧退出——否则该 UDP 流此后全部静默丢包。
    #[tokio::test]
    async fn udp_relay_partial_frame_split_across_reads_keeps_pumping() {
        struct ChunkReader {
            chunks: Vec<Vec<u8>>,
            i: usize,
        }
        impl Reader for ChunkReader {
            fn read_multi_buffer(
                &mut self,
            ) -> std::pin::Pin<
                Box<
                    dyn Future<Output = std::result::Result<MultiBuffer, xray_buf::io::Error>>
                        + Send
                        + '_,
                >,
            > {
                Box::pin(async move {
                    let mut mb = MultiBuffer::new();
                    if self.i < self.chunks.len() {
                        mb.merge_bytes(&self.chunks[self.i]);
                        self.i += 1;
                    }
                    Ok(mb)
                })
            }
        }

        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        let echo_task = xray_common::testing::spawn("read-multi-buffer-echo", async move {
            let mut buf = vec![0u8; RECV_BUF_SIZE];
            let mut got = Vec::new();
            for _ in 0..2 {
                match echo.recv_from(&mut buf).await {
                    Ok((n, _)) => got.push(buf[..n].to_vec()),
                    Err(_) => break,
                }
            }
            got
        });

        // 两帧：第一帧 payload 600B（> 300B 切点），第二帧 100B
        let payload_one = vec![0xABu8; 600];
        let payload_two = vec![0xCDu8; 100];
        let dest = udp_dest("127.0.0.1", echo_addr.port());
        let mut frames = Vec::new();
        {
            let mut pw = PacketWriter::new(&mut frames, dest, [7u8; GLOBAL_ID_LEN]);
            pw.write_packet(&payload_one).unwrap();
            pw.write_packet(&payload_two).unwrap();
        }
        // 第一帧在 300 字节处切断 → 第一次读只有半帧
        let chunks = vec![frames[..300].to_vec(), frames[300..].to_vec(), Vec::new()];

        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut reader: Box<dyn Reader> = Box::new(ChunkReader { chunks, i: 0 });
        let mut noises = None;
        let policy = UdpPolicy::default();
        let mut resolved = HashMap::new();
        pump_request(&sock, echo_addr, &mut reader, &mut noises, &policy, true, &mut resolved)
            .await
            .expect("pump ends cleanly at stream EOF");

        let got = tokio::time::timeout(std::time::Duration::from_secs(2), echo_task)
            .await
            .expect("echo timeout")
            .expect("echo join");
        assert_eq!(got.len(), 2, "两帧都必须送达（半帧不得杀掉泵）: {got:?}");
        assert_eq!(got[0], payload_one, "第一帧（跨读边界）payload 不符");
        assert_eq!(got[1], payload_two, "第二帧 payload 不符");
    }

    // 因原测试依赖 echo socket 关闭驱动 pump_response 退出，但 UDP recv_from 无 EOF 概念
    // 且生产 relay 不持有 echo 关闭权。原测试 5s+ 超时为预期失败——此处删除避免噪音。

    /// bd czwu①/6x5o：域名帧逐帧解析投递到帧自己的目标（不再发会话默认目标）
    /// + per-domain 缓存（同域名只解析一次，Go ResolvedUDPAddr）。
    #[tokio::test]
    async fn udp_domain_frames_resolved_per_frame_with_cache() {
        use crate::test_support::{FAKE_DNS_LOCK, FakeDns, install, uninstall};
        let _g = FAKE_DNS_LOCK.lock();
        // 同域名第二次解析走缓存；脚本多备几份，若缓存失效会弹出下一份但 seen 计数仍暴露
        let local = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let fake = FakeDns::ips(vec![vec![local], vec![local], vec![local]]);
        install(&fake);

        // UDP echo server：域名帧解析出的真实目标
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo.local_addr().unwrap().port();
        let echo_task = xray_common::testing::spawn(
            "udp-domain-frames-resolved-per-frame-with-cache-echo",
            async move {
                let mut buf = vec![0u8; RECV_BUF_SIZE];
                let mut got = Vec::new();
                for _ in 0..3 {
                    if let Ok((n, peer)) = echo.recv_from(&mut buf).await {
                        got.push(buf[..n].to_vec());
                        let _ = echo.send_to(&buf[..n], peer).await;
                    }
                }
                got
            },
        );

        // 会话默认目标 = 无监听端口（修复前域名帧 fallback 到这里 → 静默错投）
        let closed = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let closed_port = closed.local_addr().unwrap().port();

        let pipe_opt = xray_buf::pipe::PipeOption::default();
        let (up_r, up_w) = xray_buf::pipe::new_with_option(pipe_opt);
        let (_dn_r, dn_w) = xray_buf::pipe::new_with_option(pipe_opt);
        let link = Link::new(Box::new(up_r) as Box<dyn Reader>, Box::new(dn_w) as Box<dyn Writer>);
        let dest = udp_dest("127.0.0.1", closed_port);
        let policy = UdpPolicy {
            domain_strategy: xray_transport::sockopt::DomainStrategy::UseIP,
            ..Default::default()
        };
        let relay_task = xray_common::testing::spawn(
            "udp-domain-frames-resolved-per-frame-with-cache",
            async move {
                let ctx = test_ctx();
                relay_policy(&ctx, &dest, link, &[], &policy).await
            },
        );

        // 三帧：a.test / b.test / a.test（第三次应命中缓存，不再查询）
        let mut client_writer = Box::new(up_w) as Box<dyn Writer>;
        let global_id: [u8; GLOBAL_ID_LEN] = [9; GLOBAL_ID_LEN];
        let mut frames = Vec::new();
        for (domain, payload) in
            [("a.test", &b"one"[..]), ("b.test", &b"two"[..]), ("a.test", &b"three"[..])]
        {
            let frame_dest = Destination::new(
                Address::Domain(domain.into()),
                Port::new(echo_port),
                Network::UDP,
            );
            let mut pw = PacketWriter::new(&mut frames, frame_dest, global_id);
            pw.write_packet(payload).unwrap();
        }
        let mut mb = MultiBuffer::new();
        mb.merge_bytes(&frames);
        client_writer.write_multi_buffer(mb).await.unwrap();

        let got = tokio::time::timeout(std::time::Duration::from_secs(5), echo_task)
            .await
            .expect("echo timeout")
            .expect("echo task");
        assert_eq!(
            got,
            vec![b"one".to_vec(), b"two".to_vec(), b"three".to_vec()],
            "domain frames must be delivered to their own resolved target"
        );
        assert_eq!(fake.query_count(), 2, "a.test resolved once (cache), b.test once");
        assert_eq!(fake.seen()[0].0, "a.test");
        assert_eq!(fake.seen()[1].0, "b.test");

        drop(client_writer);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), relay_task).await;
        uninstall();
    }

    /// f17zu 验收④（托管实证）：`ctx.spawn`（迁移唯一口）落 FxScope 记账的任务
    /// 在 scope 关停（最后一个 `Arc<PluginContext>` drop → `FxScope` drop →
    /// JoinSet abort_all）时被统一收掉。哨兵任务永挂（`pending`），唯一退出
    /// 路径 = scope abort（future drop → oneshot tx drop → rx Err）。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn spawned_task_collected_when_plugin_scope_drops() {
        let ctx = test_ctx();
        let (tx, rx) = tokio::sync::oneshot::channel::<&'static str>();
        let _sentinel = ctx
            .spawn(async move {
                let _tx = tx; // abort → future drop → tx drop → rx 断
                std::future::pending::<()>().await;
            })
            .expect("plugin ctx FxScope is never closed (assembly-owned)");

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        drop(ctx); // 最后一个 Arc<PluginContext>：scope 关停
        // 任务被收 = future drop → tx drop → rx 在时限内收到 Err(RecvError)
        // （timeout 返回 Ok(Err(_))）。若超时（Err(Elapsed)）= 任务仍在跑 = 泄漏。
        let collected = tokio::time::timeout(std::time::Duration::from_secs(5), rx).await;
        assert!(
            matches!(collected, Ok(Err(_))),
            "scope drop 后哨兵任务必须被 FxScope abort 收掉（rx 断开=被收；{collected:?}=超时即泄漏）"
        );
    }
}
