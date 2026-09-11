//! Freedom outbound → DialBridge 适配器（阶段 1 切片 1e）。
//!
//! Freedom 是直连代理——直接拨号到目标，无中间服务器。所以 DialFn 闭包不需要
//! 捕获任何 client 配置，直接调 [`dial_system`] 返回 [`Connection`]。
//!
//! `dial_system` 已返回 `Box<dyn Connection>`，无需 wrapper。
//!
//! [`DialBridge`]: xray_app_dispatcher::default::DialBridge
//! [`DialFn`]: xray_app_dispatcher::default::DialFn
//! [`Connection`]: xray_transport::connection::Connection

use std::collections::HashMap;
use std::net::SocketAddr;

use xray_app_dispatcher::default::DialFn;
use xray_common::net::destination::Destination;
use xray_transport::connection::Connection;
use xray_transport::sockopt::SocketOptions;
use xray_transport::system_dialer::dial_system;

use crate::config::Config;

/// 构造 Freedom 的 DialFn 闭包（默认配置）。
///
/// 等价 [`make_dial_fn_with_config`] 传入 `Config::default()`。保留无参签名以兼容既有调用方。
#[must_use]
pub fn make_dial_fn() -> DialFn {
    make_dial_fn_with_config(Config::default())
}

/// dial 路径消费：SocketOptions、`fragment`（TCP 分片包装，对齐 Go :410-418）、
/// `destinationOverride`（拨号前改写目标，对齐 Go :269-279；UDP 逐包改写见
/// [`crate::udp`]）、`proxyProtocol`（拨号后写 PROXY protocol 头，对齐 Go :367-376）。
/// domainStrategy 注入 sockopt（dial_system 预解析 + ForceIP 硬错，bd 2yj2，
/// 对齐 Go :282-296 LookupForIP）。dial 经 `retry.ExponentialBackoff(5,100)`
/// 等价重试吸收瞬时失败（bd czwu，Go :281）。noises 由
/// [`FreedomDispatchBridge::with_noises`] 接入 UDP 路径。finalRules 的 Block
/// 检查在 [`FreedomDispatchBridge`]（需要 link 做黑洞，dial_fn 无 link）。
///
/// # Panics
///
/// 不会 panic；错误以 `Err(String)` 返回。
pub fn make_dial_fn_with_config(config: Config) -> DialFn {
    let fragment = config.fragment;
    let destination_override = config.destination_override;
    let proxy_protocol = config.proxy_protocol;
    // freedom DomainStrategy 与 transport sockopt 的 proto i32 值域一致
    // （Go 两者同源自 config.proto，转换后写入 SocketConfig.DomainStrategy 进拨号层）
    let domain_strategy =
        xray_transport::sockopt::DomainStrategy::from_i32(config.domain_strategy);
    Arc::new(move |dest: &Destination| {
        let dest = dest.clone();
        let fragment = fragment.clone();
        let destination_override = destination_override.clone();
        Box::pin(async move {
            // destinationOverride 改写（Go :269-279；isValidAddress 排除 AnyIP）
            let dial_dest =
                crate::config::apply_destination_override(&dest, destination_override.as_ref());
            let sockopt = SocketOptions {
                domain_strategy,
                ..SocketOptions::default()
            };
            // Go :281 retry.ExponentialBackoff(5, 100)：dial 瞬时失败指数退避重试
            let conn: Box<dyn Connection> =
                xray_transport::retry::exponential_backoff(5, 100, || {
                    dial_system(&dial_dest, &sockopt)
                })
                .await
                .map_err(|e| format!("freedom dial: {e}"))?;
            // PROXY protocol 头（Go :367-376）：拨号后、任何业务数据前写
            let conn = write_proxy_protocol_header(conn, proxy_protocol).await?;
            // fragment 配置存在时 dial 后包 writer（对齐 Go :410-418）
            let conn: Box<dyn Connection> = match fragment {
                Some(f) => Box::new(crate::fragment::FragmentConnection::new(conn, f)),
                None => conn,
            };
            Ok(conn)
        })
    })
}

tokio::task_local! {
    /// PROXY protocol 头的源地址（入站客户端源，对应 Go `session.Inbound.Source`）。
    /// 由 [`FreedomDispatchBridge::dispatch_with_access`] 从 `AccessContext.from`
    /// 注入；纯 DialFn 调用方无此值 → warn + 跳过（Go `inbound == nil` 场景）。
    static PROXY_PROTO_SRC: Option<SocketAddr>;
}

/// `proxyProtocol` ∈ {1,2} 时在连接上写 PROXY protocol 头（Go :367-376）。
///
/// 源地址来自 [`PROXY_PROTO_SRC`] task-local；无源信息（无入站上下文）→
/// warn + 跳过，不为改 DialFn 签名。
async fn write_proxy_protocol_header(
    mut conn: Box<dyn Connection>,
    version: u32,
) -> Result<Box<dyn Connection>, String> {
    if version != 1 && version != 2 {
        return Ok(conn);
    }
    let src = PROXY_PROTO_SRC.try_with(|v| *v).ok().flatten();
    let dst = conn.remote_addr().ok().flatten();
    let (Some(src), Some(dst)) = (src, dst) else {
        tracing::warn!(
            version,
            "freedom: proxyProtocol enabled but session has no source info, skipping header"
        );
        return Ok(conn);
    };
    let header = xray_transport::build_proxy_header(version as u8, src, dst);
    if header.is_empty() {
        tracing::warn!(version, "freedom: invalid PROXY protocol version, skipping header");
        return Ok(conn);
    }
    use tokio::io::AsyncWriteExt;
    conn.as_mut()
        .write_all(&header)
        .await
        .map_err(|e| format!("freedom: PROXY protocol write failed: {e}"))?;
    Ok(conn)
}

use std::sync::Arc;

use xray_app_dispatcher::DispatchHandler;
use xray_app_dispatcher::default::{DialBridge, PinFuture};

use xray_common::net::network::Network;
use xray_transport::link::Link;

/// Freedom dispatch handler——在 TCP DialBridge 之上增加 UDP relay。
///
/// 对应 Go `proxy/freedom/freedom.go::Handler`：TCP 走 `dial_system` 流桥接
/// （委托内部 [`DialBridge`]，fragment/destinationOverride/proxyProtocol 配置经
/// [`make_dial_fn_with_config`] 消费）；UDP 走 [`crate::udp::relay_policy`]
/// （XUDP 帧 ↔ 原始数据报，noises 首包前注入 + 逐包 override/Block 检查，
/// 对齐 Go `PacketWriter`/`NoisePacketWriter`）。
///
/// finalRules：TCP dial 前 Block 检查 → 黑洞（Go :335-366）；UDP 请求/响应
/// 双向逐包检查（Go :515-517 / :634-637）。默认规则按入站协议名推导
/// （Go `getDefaultFinalRule(inbound.Name)` :154-169）——入站 tag → 协议名
/// 映射由 xray-core 装配时经 [`Self::with_inbound_default_rules`] 注入，
/// 无映射（入站未注册/无 access 上下文）= 无默认规则（对应 Go `inbound == nil`）。
///
/// **代理链**：仅 TCP 支持代理链（通过内部 DialBridge）；UDP 直连目标，
/// 不支持代理链（与 Go freedom 一致——freedom 是直连出口）。
pub struct FreedomDispatchBridge {
    tag: String,
    tcp: Arc<DialBridge>,
    noises: Vec<crate::config::Noise>,
    /// sendThrough 源地址规格（bd 7zc）。UDP 分支拨号前解析并设 DIAL_SRC
    /// （TCP 分支的源 bind 由 outbound 侧 dial_fn 包装层处理）。
    send_through: Option<xray_transport::system_dialer::SendThroughSpec>,
    /// destinationOverride（TCP Block 检查 + UDP 逐包改写；拨号改写在 dial_fn 内）。
    destination_override: Option<crate::config::DestinationOverride>,
    /// 预构建的 final rules（`FinalRule::build` 失败的项跳过，与 Handler 口径一致）。
    final_rules: Vec<crate::config::FinalRule>,
    /// 入站 tag → 默认规则类型（xray-core 装配注入）。
    inbound_rules: Arc<HashMap<String, crate::config::DefaultRuleType>>,
    /// domainStrategy（proto i32， freedom Config 平行值域）。TCP dispatch 域名
    /// 先解析后匹配 finalRule（bd 6x5o）+ UDP 逐帧域名解析（bd czwu）共用。
    domain_strategy: i32,
}

impl FreedomDispatchBridge {
    /// 从已构造的 TCP [`DialBridge`] 包装。保留 `dial_bridge` 的 Arc 以便代理链 Phase 2 注入。
    #[must_use]
    pub fn from_bridge(dial_bridge: Arc<DialBridge>) -> Self {
        let tag = dial_bridge.tag().to_string();
        Self {
            tag,
            tcp: dial_bridge,
            noises: Vec::new(),
            send_through: None,
            destination_override: None,
            final_rules: Vec::new(),
            inbound_rules: Arc::new(HashMap::new()),
            domain_strategy: 0,
        }
    }

    /// 设置 UDP 路径首包前注入的 noises（对齐 Go `NoisePacketWriter` 写入时机）。
    #[must_use]
    pub fn with_noises(mut self, noises: Vec<crate::config::Noise>) -> Self {
        self.noises = noises;
        self
    }

    /// 设置 sendThrough 源地址（对齐 Go SenderConfig.Via 的 UDP 分支：
    /// system_dialer.go:59-84 ListenPacket 绑源地址）。
    #[must_use]
    pub fn with_send_through(
        mut self,
        spec: xray_transport::system_dialer::SendThroughSpec,
    ) -> Self {
        self.send_through = Some(spec);
        self
    }

    /// 设置 destinationOverride（TCP dial 改写在 dial_fn；此处供 Block 检查
    /// 与 UDP 逐包改写——Go :269-279 override 先于 finalRule 匹配）。
    #[must_use]
    pub fn with_destination_override(
        mut self,
        ov: Option<crate::config::DestinationOverride>,
    ) -> Self {
        self.destination_override = ov;
        self
    }

    /// 设置预构建的 final rules（TCP dial 前 + UDP 双向逐包 Block 检查）。
    #[must_use]
    pub fn with_final_rules(mut self, rules: Vec<crate::config::FinalRule>) -> Self {
        self.final_rules = rules;
        self
    }

    /// 设置入站 tag → 默认规则类型映射（对应 Go `getDefaultFinalRule(inbound)`，
    /// 由 xray-core 装配时从 inbound (tag, protocol) 清单构建）。
    #[must_use]
    pub fn with_inbound_default_rules(
        mut self,
        rules: HashMap<String, crate::config::DefaultRuleType>,
    ) -> Self {
        self.inbound_rules = Arc::new(rules);
        self
    }

    /// 设置 domainStrategy（freedom Config proto i32；Go freedom.go:282-296）。
    #[must_use]
    pub fn with_domain_strategy(mut self, strategy: i32) -> Self {
        self.domain_strategy = strategy;
        self
    }

}
impl std::fmt::Debug for FreedomDispatchBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FreedomDispatchBridge")
            .field("tag", &self.tag)
            .field("final_rules", &self.final_rules.len())
            .field("has_override", &self.destination_override.is_some())
            .finish_non_exhaustive()
    }
}

impl FreedomDispatchBridge {
    /// 组装 UDP relay 策略（Go `Process` 的 UDPOverride + defaultRule 形态）。
    fn udp_policy(
        &self,
        default_rule: Option<crate::config::FinalRule>,
    ) -> crate::udp::UdpPolicy {
        crate::udp::UdpPolicy {
            destination_override: self.destination_override.clone(),
            final_rules: self.final_rules.clone(),
            default_rule,
            domain_strategy: xray_transport::sockopt::DomainStrategy::from_i32(
                self.domain_strategy,
            ),
        }
    }
}

impl DispatchHandler for FreedomDispatchBridge {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn dispatch(&self, dest: &Destination, link: Link) -> PinFuture<()> {
        // 无 access 上下文：无默认规则（Go `getDefaultFinalRule(nil)` 返回 nil）、
        // 无 PROXY protocol 源（warn + 跳过）。
        self.dispatch_with_access(dest, link, xray_app_dispatcher::AccessContext::default())
    }

    fn dispatch_with_access(
        &self,
        dest: &Destination,
        link: Link,
        access: xray_app_dispatcher::AccessContext,
    ) -> PinFuture<()> {
        // 默认规则：入站 tag → 协议名映射推导（Go getDefaultFinalRule(inbound.Name)）
        let default_rule = self
            .inbound_rules
            .get(access.inbound_tag.as_str())
            .copied()
            .map(crate::config::FinalRule::build_default_rule);

        if dest.network() == Network::UDP {
            let tag = self.tag.clone();
            let dest = dest.clone();
            let send_through = self.send_through.clone();
            let noises = self.noises.clone();
            let policy = self.udp_policy(default_rule);
            Box::pin(async move {
                // bd 7zc：sendThrough → DIAL_SRC scope → relay bind 源地址
                // （对应 Go DialSystem UDP 分支 src 传递）。
                let result = match send_through.as_ref().and_then(|s| s.resolve()) {
                    Some(ip) => {
                        xray_transport::system_dialer::DIAL_SRC
                            .scope(Some(ip), crate::udp::relay_policy(&dest, link, &noises, &policy))
                            .await
                    }
                    None => crate::udp::relay_policy(&dest, link, &noises, &policy).await,
                };
                if let Err(e) = result {
                    tracing::warn!(tag = %tag, "freedom udp relay ended: {e}");
                }
            })
        } else {
            // TCP：域名先解析、finalRule Block 检查在解析后的目标上匹配
            // （bd 6x5o，Go :282-339：HasStrategy→LookupForIP / asis+hasRules→
            // 系统解析，dialDest 替换为 IP 后 matchFinalRule → Block 黑洞不拨号）。
            let tag = self.tag.clone();
            let final_rules = self.final_rules.clone();
            let mut check_dest =
                crate::config::apply_destination_override(dest, self.destination_override.as_ref());
            let domain_strategy =
                xray_transport::sockopt::DomainStrategy::from_i32(self.domain_strategy);
            let src = access.from.parse::<SocketAddr>().ok();
            let tcp = Arc::clone(&self.tcp);
            Box::pin(async move {
                if let Some(domain) = check_dest.address().as_domain().map(str::to_string) {
                    let should_resolve = crate::config::should_resolve_domain_before_final_rules(
                        &check_dest,
                        &final_rules,
                        default_rule.as_ref(),
                    );
                    if should_resolve || domain_strategy.has_strategy() {
                        match crate::config::resolve_domain_for_rules(
                            &domain,
                            check_dest.port().value(),
                            domain_strategy,
                        )
                        .await
                        {
                            Ok(ip) => {
                                check_dest = crate::config::destination_with_ip(&check_dest, ip);
                            }
                            Err(e) => {
                                // Go :293-295：Lookup 失败 + ForceIP/shouldResolve → 断链；
                                // 否则降级保留域名（dial 层系统解析，Go :296-300 吞错继续）
                                if domain_strategy.force_ip() || should_resolve {
                                    tracing::warn!(
                                        tag = %tag,
                                        domain = %domain,
                                        "freedom: domain resolve failed, aborting: {e}"
                                    );
                                    link.writer.shutdown();
                                    return;
                                }
                            }
                        }
                    }
                }
                let blocked = crate::config::match_final_rules(
                    &final_rules,
                    default_rule.as_ref(),
                    &check_dest,
                )
                .filter(|r| r.action == crate::config::RuleAction::Block);
                if let Some(rule) = blocked {
                    crate::config::blackhole_link(link, &tag, &rule).await;
                    return;
                }
                // PROXY protocol 源注入 task-local：DialFn 闭包在本 future 轮询期间执行
                // （DialBridge::dispatch 不另起 task），scope 覆盖 dial + 头写入。
                PROXY_PROTO_SRC.scope(src, tcp.dispatch(&check_dest, link)).await;
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use xray_app_dispatcher::default::{DefaultDispatcher, DialBridge, SimpleOhm, SniffingRequest};
    use xray_buf::io::{Reader, Writer};
    use xray_buf::multi::MultiBuffer;
    use xray_common::net::address::Address;
    use xray_common::net::network::Network;
    use xray_common::net::port::Port;

    #[tokio::test]
    async fn dispatcher_e2e_freedom_to_echo() {
        // echo server
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if sock.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });

        // dispatcher + DialBridge(freedom)
        let ohm = SimpleOhm::new();
        ohm.set_default(Arc::new(DialBridge::new("freedom-out", make_dial_fn())));
        let mut dispatcher = DefaultDispatcher::new();
        dispatcher.ohm = Some(Arc::new(ohm));

        let dest = Destination::new(
            Address::from_ipv4_bytes([127, 0, 0, 1]),
            Port::new(echo_addr.port()),
            Network::TCP,
        );
        let inbound = dispatcher
            .dispatch(&dest, &SniffingRequest::default(), None, None)
            .expect("dispatch returns inbound Link");

        let mut w = inbound.writer;
        let mut r = inbound.reader;

        let payload = b"hello freedom via dispatcher";
        let mut mb = MultiBuffer::new();
        mb.merge_bytes(payload);
        w.write_multi_buffer(mb).await.unwrap();

        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            r.read_multi_buffer(),
        )
        .await
        .expect("timeout")
        .unwrap();

        assert_eq!(resp.to_vec(), payload);
        w.shutdown();
    }

    /// bd g35 验收 3：UDP dest 经 DefaultDispatcher → FreedomDispatchBridge →
    /// freedom udp relay（XUDP 帧 ↔ UDP 数据报）直发语义回归（b2e）。
    #[tokio::test]
    async fn dispatcher_e2e_freedom_udp_direct() {
        use tokio::net::UdpSocket;
        use xray_xudp::packet::{PacketReader, PacketWriter};

        // 1. UDP echo server
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                match echo.recv_from(&mut buf).await {
                    Ok((n, peer)) => {
                        let _ = echo.send_to(&buf[..n], peer).await;
                    }
                    Err(_) => break,
                }
            }
        });

        // 2. dispatcher + FreedomDispatchBridge（TCP DialBridge + UDP relay）
        let tcp_bridge = Arc::new(DialBridge::new("freedom-out", make_dial_fn()));
        let ohm = SimpleOhm::new();
        ohm.set_default(Arc::new(FreedomDispatchBridge::from_bridge(tcp_bridge)));
        let mut dispatcher = DefaultDispatcher::new();
        dispatcher.ohm = Some(Arc::new(ohm));

        // 3. dispatch UDP dest → inbound Link
        let dest = Destination::new(
            Address::from_ipv4_bytes([127, 0, 0, 1]),
            Port::new(echo_addr.port()),
            Network::UDP,
        );
        let inbound = dispatcher
            .dispatch(&dest, &SniffingRequest::default(), None, None)
            .expect("dispatch returns inbound Link");
        let mut w = inbound.writer;
        let mut r = inbound.reader;

        // 4. 写 XUDP New 帧 → freedom 拆帧 send_to → echo → 回帧
        let mut frame = Vec::new();
        {
            let mut pw = PacketWriter::new(&mut frame, dest.clone(), [0x22; 8]);
            pw.write_packet(b"udp-direct").unwrap();
        }
        let mut mb = MultiBuffer::new();
        mb.merge_bytes(&frame);
        w.write_multi_buffer(mb).await.unwrap();

        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            r.read_multi_buffer(),
        )
        .await
        .expect("timeout reading udp echo");

        // 读错误（EOF）也算失败——必须拿到回帧
        let resp = resp.expect("read ok");
        let resp_bytes = resp.to_vec();
        let mut pr = PacketReader::new(std::io::Cursor::new(&resp_bytes[..]));
        let pkt = pr.read_packet().unwrap().expect("echo frame");
        assert_eq!(pkt.data(), b"udp-direct");
        w.shutdown();
        echo_task.abort();
    }

    /// bd 7zc：sendThrough → freedom UDP relay 以指定源 IP bind（对齐 Go
    /// system_dialer.go:59-84 UDP ListenPacket 绑 srcAddr）。echo server 记录
    /// recv_from 的 peer，断言源 IP 为 127.0.0.2（loopback /8 内非默认源）。
    #[tokio::test]
    async fn dispatcher_e2e_freedom_udp_send_through_binds_source() {
        use std::net::IpAddr;
        use tokio::net::UdpSocket;
        use xray_transport::system_dialer::SendThroughSpec;
        use xray_xudp::packet::PacketWriter;

        // 1. UDP echo server：记录首个 peer 源 IP
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        let peer_ip = Arc::new(parking_lot::Mutex::new(None::<IpAddr>));
        let recorder = Arc::clone(&peer_ip);
        let echo_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                match echo.recv_from(&mut buf).await {
                    Ok((n, peer)) => {
                        if recorder.lock().is_none() {
                            *recorder.lock() = Some(peer.ip());
                        }
                        let _ = echo.send_to(&buf[..n], peer).await;
                    }
                    Err(_) => break,
                }
            }
        });

        // 2. FreedomDispatchBridge + sendThrough=127.0.0.2
        let tcp_bridge = Arc::new(DialBridge::new("freedom-via", make_dial_fn()));
        let bridge = FreedomDispatchBridge::from_bridge(tcp_bridge)
            .with_send_through(SendThroughSpec::Fixed("127.0.0.2".parse().unwrap()));
        let ohm = SimpleOhm::new();
        ohm.set_default(Arc::new(bridge));
        let mut dispatcher = DefaultDispatcher::new();
        dispatcher.ohm = Some(Arc::new(ohm));

        // 3. dispatch UDP dest → 写 XUDP 帧 → relay 以 127.0.0.2 bind 后 send_to
        let dest = Destination::new(
            Address::from_ipv4_bytes([127, 0, 0, 1]),
            Port::new(echo_addr.port()),
            Network::UDP,
        );
        let inbound = dispatcher
            .dispatch(&dest, &SniffingRequest::default(), None, None)
            .expect("dispatch returns inbound Link");
        let mut w = inbound.writer;

        let mut frame = Vec::new();
        {
            let mut pw = PacketWriter::new(&mut frame, dest.clone(), [0x33; 8]);
            pw.write_packet(b"via-127.0.0.2").unwrap();
        }
        let mut mb = MultiBuffer::new();
        mb.merge_bytes(&frame);
        w.write_multi_buffer(mb).await.unwrap();

        // 等 echo 记录 peer（轮询 3s）
        let expected: IpAddr = "127.0.0.2".parse().unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while peer_ip.lock().is_none() && std::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(*peer_ip.lock(), Some(expected), "UDP 源 IP 应为 sendThrough 指定的 127.0.0.2");
        echo_task.abort();
    }

    /// bd v2q：fragment 配置经 make_dial_fn_with_config → DialBridge TCP 路径端到端。
    /// tlshello 模式：客户端发一条 TLS record，服务端字节级解析应看到多条重组
    /// record（分片发生在 wire 上，与 TCP 分段无关），payload 重组 == 原文，
    /// 且回程（读路径透传）不受分片影响。
    #[tokio::test]
    async fn dispatcher_tcp_fragment_tlshello_e2e() {
        use crate::config::Fragment;

        // echo server：全量回显并保留收到的原始字节
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut all = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        all.extend_from_slice(&buf[..n]);
                        if sock.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
            all
        });

        let config = Config {
            fragment: Some(Fragment {
                packets_from: 0,
                packets_to: 1,
                length_min: 4,
                length_max: 4,
                interval_min: 0,
                interval_max: 0,
                max_split_min: 0,
                max_split_max: 0,
            }),
            ..Config::default()
        };
        let ohm = SimpleOhm::new();
        ohm.set_default(Arc::new(DialBridge::new(
            "freedom-frag",
            make_dial_fn_with_config(config),
        )));
        let mut dispatcher = DefaultDispatcher::new();
        dispatcher.ohm = Some(Arc::new(ohm));

        let dest = Destination::new(
            Address::from_ipv4_bytes([127, 0, 0, 1]),
            Port::new(addr.port()),
            Network::TCP,
        );
        let inbound = dispatcher
            .dispatch(&dest, &SniffingRequest::default(), None, None)
            .expect("dispatch returns inbound Link");
        let mut w = inbound.writer;
        let mut r = inbound.reader;

        // 一条完整 TLS handshake record：type=22 + version 3,1 + len=12 + payload
        let payload: Vec<u8> = (0..12u8).collect();
        let mut record = vec![22u8, 3, 1, 0, payload.len() as u8];
        record.extend_from_slice(&payload);
        let mut mb = MultiBuffer::new();
        mb.merge_bytes(&record);
        w.write_multi_buffer(mb).await.unwrap();

        // 回程透传：echo 回来的字节 == 服务端收到的字节
        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            r.read_multi_buffer(),
        )
        .await
        .expect("timeout")
        .expect("read ok");

        w.shutdown();
        let received = server.await.unwrap();
        assert_eq!(resp.to_vec(), received, "down path transparent to fragmentation");

        // 字节级解析：单条 record 被重组为多条小 record
        let mut records = Vec::new();
        let mut i = 0;
        while i + 5 <= received.len() {
            let l = ((received[i + 3] as usize) << 8) | received[i + 4] as usize;
            assert!(i + 5 + l <= received.len(), "truncated record at {i}");
            records.push((received[i], received[i + 5..i + 5 + l].to_vec()));
            i += 5 + l;
        }
        assert_eq!(i, received.len(), "no trailing garbage");
        assert!(records.len() >= 3, "fragmented on the wire: {} records", records.len());
        assert!(records.iter().all(|(t, _)| *t == 22), "record type preserved");
        let data: Vec<u8> = records.iter().flat_map(|(_, p)| p.clone()).collect();
        assert_eq!(data, payload, "reassembled handshake == original");
    }
    /// TCP finalRule Block：命中黑洞不拨号（对端连接计数为 0）。
    #[tokio::test]
    async fn tcp_block_rule_blackholes_without_dialing() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = listener.local_addr().unwrap();
        let conns = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let conns_srv = Arc::clone(&conns);
        tokio::spawn(async move {
            while let Ok((_, _)) = listener.accept().await {
                conns_srv.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        });

        let rule_cfg = crate::config::FinalRuleConfig::from_json(&serde_json::json!({
            "action": "block", "ip": ["127.0.0.0/8"], "blockDelay": {"from": 0, "to": 0}
        }))
        .unwrap();
        let bridge = FreedomDispatchBridge::from_bridge(Arc::new(DialBridge::new(
            "freedom-out",
            make_dial_fn(),
        )))
        .with_final_rules(vec![crate::config::FinalRule::build(&rule_cfg).unwrap()]);

        let dest = Destination::new(
            Address::from_ipv4_bytes([127, 0, 0, 1]),
            Port::new(echo_addr.port()),
            Network::TCP,
        );
        let pipe_opt = xray_buf::pipe::PipeOption::default();
        let (up_r, up_w) = xray_buf::pipe::new_with_option(pipe_opt);
        let (dn_r, dn_w) = xray_buf::pipe::new_with_option(pipe_opt);
        let link = xray_transport::link::Link::new(
            Box::new(up_r) as Box<dyn Reader>,
            Box::new(dn_w) as Box<dyn Writer>,
        );
        let task = tokio::spawn(async move { bridge.dispatch(&dest, link).await });

        // 客户端写数据后关闭 → blackhole drain 读到 EOF 提前返回
        let mut w = Box::new(up_w) as Box<dyn Writer>;
        let mut mb = MultiBuffer::new();
        mb.merge_bytes(b"probe");
        w.write_multi_buffer(mb).await.unwrap();
        drop(w);
        tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .expect("blackhole should return after drain EOF")
            .ok()
            .expect("dispatch ok");
        assert_eq!(
            conns.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "blocked target must never be dialed"
        );
        let _ = dn_r;
    }

    /// 入站 tag → 协议名默认规则：vless 入站 → BlockPrivate（127.0.0.0/8 被阻）；
    /// 未注册 tag（socks）→ 无默认规则正常拨号。
    #[tokio::test]
    async fn inbound_default_rule_map_derives_block_private() {
        // echo server（记录连接数）
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = vec![0u8; 4096];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        });

        let make_bridge = || {
            FreedomDispatchBridge::from_bridge(Arc::new(DialBridge::new(
                "freedom-out",
                make_dial_fn(),
            )))
            .with_inbound_default_rules(std::collections::HashMap::from([(
                "vless-in".to_string(),
                crate::config::DefaultRuleType::BlockPrivate,
            )]))
        };
        let dest = Destination::new(
            Address::from_ipv4_bytes([127, 0, 0, 1]),
            Port::new(echo_addr.port()),
            Network::TCP,
        );
        let pipe_opt = xray_buf::pipe::PipeOption::default();
        let new_link = || {
            let (up_r, up_w) = xray_buf::pipe::new_with_option(pipe_opt);
            let (dn_r, dn_w) = xray_buf::pipe::new_with_option(pipe_opt);
            (
                xray_transport::link::Link::new(
                    Box::new(up_r) as Box<dyn Reader>,
                    Box::new(dn_w) as Box<dyn Writer>,
                ),
                up_w,
                dn_r,
            )
        };

        // 阶段 1：vless-in → BlockPrivate（127.0.0.0/8）→ 黑洞，写后关 up 触发 drain EOF
        {
            let (link, mut up_w, _dn_r) = new_link();
            let access = xray_app_dispatcher::AccessContext {
                inbound_tag: "vless-in".into(),
                ..Default::default()
            };
            let bridge = make_bridge();
            let task = tokio::spawn(bridge.dispatch_with_access(&dest, link, access));
            let mut mb = MultiBuffer::new();
            mb.merge_bytes(b"probe");
            up_w.write_multi_buffer(mb).await.unwrap();
            up_w.shutdown(); // xray-buf pipe 无 Drop 关闭——显式 shutdown 才有 EOF
            tokio::time::timeout(std::time::Duration::from_secs(5), task)
                .await
                .expect("blackhole drain should end")
                .ok()
                .expect("dispatch ok");
        }

        // 阶段 2：socks-in（不在映射 → 无默认规则）→ 正常拨号 echo
        {
            let (link, mut up_w, mut dn_r) = new_link();
            let access = xray_app_dispatcher::AccessContext {
                inbound_tag: "socks-in".into(),
                ..Default::default()
            };
            let bridge = make_bridge();
            let task = tokio::spawn(bridge.dispatch_with_access(&dest, link, access));
            let mut mb = MultiBuffer::new();
            mb.merge_bytes(b"echo-me");
            up_w.write_multi_buffer(mb).await.unwrap();
            let resp = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                dn_r.read_multi_buffer(),
            )
            .await
            .expect("timeout")
            .expect("read ok");
            assert_eq!(resp.to_vec(), b"echo-me");
            up_w.shutdown();
            task.abort();
        }
    }

    /// proxyProtocol=1 + access.from → 拨号后首字节为 PROXY v1 头（Go :367-376）。
    #[tokio::test]
    async fn proxy_protocol_header_written_when_source_available() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 256];
            let n = sock.read(&mut buf).await.unwrap();
            let text = String::from_utf8_lossy(&buf[..n]).to_string();
            assert!(
                text.starts_with("PROXY "),
                "first bytes must be PROXY header, got: {text:?}"
            );
            // 头之后回显剩余负载
            if let Some(idx) = text.find("\r\n") {
                let rest = &buf[idx + 2..n];
                if !rest.is_empty() {
                    use tokio::io::AsyncWriteExt;
                    let _ = sock.write_all(rest).await;
                }
            }
        });

        // proxyProtocol=1 进 dial_fn（生产 parse_freedom_config 路径等价）
        let config = Config {
            proxy_protocol: 1,
            ..Default::default()
        };
        let bridge = FreedomDispatchBridge::from_bridge(Arc::new(DialBridge::new(
            "freedom-out",
            make_dial_fn_with_config(config),
        )));

        let dest = Destination::new(
            Address::from_ipv4_bytes([127, 0, 0, 1]),
            Port::new(echo_addr.port()),
            Network::TCP,
        );
        let pipe_opt = xray_buf::pipe::PipeOption::default();
        let (up_r, up_w) = xray_buf::pipe::new_with_option(pipe_opt);
        let (dn_r, dn_w) = xray_buf::pipe::new_with_option(pipe_opt);
        let link = xray_transport::link::Link::new(
            Box::new(up_r) as Box<dyn Reader>,
            Box::new(dn_w) as Box<dyn Writer>,
        );
        let access = xray_app_dispatcher::AccessContext {
            from: "198.51.100.7:4444".into(),
            ..Default::default()
        };
        let task = tokio::spawn(bridge.dispatch_with_access(&dest, link, access));

        let mut w = Box::new(up_w) as Box<dyn Writer>;
        let mut mb = MultiBuffer::new();
        mb.merge_bytes(b"payload-after-header");
        w.write_multi_buffer(mb).await.unwrap();

        let mut r = Box::new(dn_r) as Box<dyn Reader>;
        let resp = tokio::time::timeout(std::time::Duration::from_secs(5), r.read_multi_buffer())
            .await
            .expect("timeout waiting echo")
            .expect("read ok");
        assert_eq!(resp.to_vec(), b"payload-after-header");
        w.shutdown();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), task).await;
    }

    /// bd 2yj2：domainStrategy=UseIPv4 注入 sockopt → dial_system 经
    /// LookupForIP 预解析，双栈应答下仅查询 IPv4（Go freedom.go:282-296）。
    #[tokio::test]
    async fn dial_fn_useipv4_resolves_only_ipv4() {
        use crate::test_support::{install, uninstall, FakeDns, FAKE_DNS_LOCK};
        let _g = FAKE_DNS_LOCK.lock();
        let fake = FakeDns::ips(vec![vec![
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        ]]);
        install(&fake);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 256];
            let _ = sock.read(&mut buf).await;
        });

        let config = Config {
            domain_strategy: crate::config::DomainStrategy::UseIPv4 as i32,
            ..Default::default()
        };
        let dial = make_dial_fn_with_config(config);
        let dest = Destination::new(
            Address::Domain("dualstack.test".into()),
            Port::new(echo_addr.port()),
            Network::TCP,
        );
        let conn = dial(&dest).await.expect("dial via strategy-resolved IP");
        drop(conn);

        assert_eq!(
            fake.seen(),
            vec![("dualstack.test".to_string(), true, false)],
            "UseIPv4 must query with ipv4_enable=true, ipv6_enable=false"
        );
        uninstall();
    }

    /// bd 6x5o：域名先解析为 IP 再匹配 finalRule——解析到 10.0.0.0/8 的域名
    /// 被 Block 规则黑洞（不拨号），对齐 Go shouldResolveDomainBeforeFinalRules。
    #[tokio::test]
    async fn domain_resolving_to_private_ip_blocked() {
        use crate::test_support::{install, uninstall, FakeDns, FAKE_DNS_LOCK};
        use std::sync::atomic::{AtomicUsize, Ordering};
        let _g = FAKE_DNS_LOCK.lock();
        let fake = FakeDns::ips(vec![vec![std::net::IpAddr::V4(
            "10.0.0.1".parse().unwrap(),
        )]]);
        install(&fake);

        let listener = std::sync::Arc::new(TcpListener::bind("127.0.0.1:0").await.unwrap());
        let echo_port = listener.local_addr().unwrap().port();
        let conn_count = std::sync::Arc::new(AtomicUsize::new(0));
        let accept_task = {
            let (listener, count) = (listener, std::sync::Arc::clone(&conn_count));
            tokio::spawn(async move {
                loop {
                    if listener.accept().await.is_ok() {
                        count.fetch_add(1, Ordering::SeqCst);
                    }
                }
            })
        };

        // 生产解析路径：block + 10.0.0.0/8 + blockDelay 0s（黑洞即刻放行 EOF）
        let rule = crate::config::FinalRuleConfig::from_json(&serde_json::json!({
            "action": "block",
            "ip": ["10.0.0.0/8"],
            "blockDelay": {"from": 0, "to": 0},
        }))
        .unwrap();
        let config = Config {
            domain_strategy: crate::config::DomainStrategy::UseIPv4 as i32,
            final_rules: vec![rule.clone()],
            ..Default::default()
        };
        // 生产装配口径（outbound.rs freedom 分支）：bridge 侧 finalRules（Block
        // 检查）与 domainStrategy 经 builder 注入；dial_fn 侧 config 消费 sockopt。
        let built_rule = crate::config::FinalRule::build(&rule).unwrap();
        let bridge = FreedomDispatchBridge::from_bridge(Arc::new(DialBridge::new(
            "direct",
            make_dial_fn_with_config(config),
        )))
        .with_domain_strategy(crate::config::DomainStrategy::UseIPv4 as i32)
        .with_final_rules(vec![built_rule]);
        let pipe_opt = xray_buf::pipe::PipeOption::default();
        let (up_r, up_w) = xray_buf::pipe::new_with_option(pipe_opt);
        let (dn_r, dn_w) = xray_buf::pipe::new_with_option(pipe_opt);
        let link = xray_transport::link::Link::new(
            Box::new(up_r) as Box<dyn Reader>,
            Box::new(dn_w) as Box<dyn Writer>,
        );
        let dest = Destination::new(
            Address::Domain("intranet.test".into()),
            Port::new(echo_port),
            Network::TCP,
        );
        let task = tokio::spawn(bridge.dispatch_with_access(
            &dest,
            link,
            xray_app_dispatcher::AccessContext::default(),
        ));

        // 上行写一点数据后关闭 → 黑洞 drain 见 EOF → 即刻关下行
        // （xray-buf pipe 无 Drop 关闭——显式 shutdown 才有 EOF）
        let mut w = Box::new(up_w) as Box<dyn Writer>;
        let mut mb = MultiBuffer::new();
        mb.merge_bytes(b"payload");
        w.write_multi_buffer(mb).await.unwrap();
        w.shutdown();
        let mut r = Box::new(dn_r) as Box<dyn Reader>;
        let closed = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            // EOF 语义与 blackhole drain 一致：Err 或 Ok(空) 都视为对端关闭
            loop {
                match r.read_multi_buffer().await {
                    Ok(mb) if !mb.is_empty() => continue,
                    _ => break,
                }
            }
        })
        .await;
        assert!(closed.is_ok(), "blackholed connection must close downstream");
        assert_eq!(conn_count.load(Ordering::SeqCst), 0, "blocked target must not be dialed");
        accept_task.abort();
        let _ = task.await;
        uninstall();
    }

    /// bd czwu②：dial 失败走 retry.ExponentialBackoff(5,100)——对已关闭端口
    /// 连续 5 次尝试（线性退避 0+100+200+300ms），总耗时 ≥500ms 而非立即失败。
    #[tokio::test]
    async fn dial_fn_retries_transient_failures() {
        let dial = make_dial_fn();
        let dest = Destination::new(
            Address::from_ipv4_bytes([127, 0, 0, 1]),
            Port::new(1), // 本机回环端口 1 无监听 → ECONNREFUSED
            Network::TCP,
        );
        let start = std::time::Instant::now();
        let result = dial(&dest).await;
        let elapsed = start.elapsed();
        assert!(result.is_err(), "closed port must fail eventually");
        assert!(
            elapsed >= std::time::Duration::from_millis(500),
            "expected retry backoff >=500ms, got {elapsed:?}"
        );
        // dial_system 单次连接尝试自身可耗 ~2s（Happy Eyeballs/连接选项），5 次上界放宽
        assert!(elapsed < std::time::Duration::from_secs(30), "{elapsed:?}");
    }
}
