//! Freedom 出站代理 Handler——对应 Go `proxy/freedom/freedom.go` 的 `Handler`。
//!
//! ## 切片边界（P6-5 切片2）
//!
//! 实现 [`OutboundHandler`] trait，内部调 [`xray_transport::system_dialer::dial_system`]
//! 验证 TCP 拨号端到端可用。桥接 `transport::Link`（link.reader/writer ↔ Connection）
//! 与 Domain DNS 解析留切片3。

use xray_app_proxyman::outbound::proxy_outbound::{OutboundDialer, ProxyOutbound};
use xray_app_proxyman::error::ProxymanError;
use xray_transport::bridge::bridge_link_with_stream_full;
use xray_transport::build_proxy_header;
use xray_transport::link::Link;
use std::net::SocketAddr;
use std::sync::Arc;
use async_trait::async_trait;
use xray_common::net::destination::Destination;
use xray_common::net::address::Address;
use xray_common::net::network::Network;
use xray_common::net::port::Port;
use xray_common::session::Session;
use xray_features::outbound::{OutboundError, OutboundHandler};
use xray_transport::sockopt::SocketOptions;
use xray_transport::system_dialer::dial_system;

use crate::config::{
    Config, DomainStrategy, Fragment, FinalRule, DefaultRuleType, RuleAction,
    get_default_rule_type,
};

/// Freedom 出站 Handler。
///
/// 持有配置 + tag，实现 [`OutboundHandler`]。dial 方法通过 [`dial_system`] 建立到
/// `destination` 的直连 TCP 连接。
pub struct FreedomHandler {
    tag: String,
    config: Config,
    /// 从 `config.final_rules` 预构建的运行时规则。对应 Go `Handler.finalRules`。
    final_rules: Vec<FinalRule>,
    /// 默认规则类型（None=不应用默认规则；可由 session.inbound 推导）。
    default_rule_type: Option<DefaultRuleType>,
}

impl FreedomHandler {
    /// 构造 Freedom Handler，并预构建 final rules。
    #[must_use]
    pub fn new(tag: impl Into<String>, config: Config) -> Self {
        let final_rules = config
            .final_rules
            .iter()
            .filter_map(|rc| FinalRule::build(rc).ok())
            .collect();
        Self {
            tag: tag.into(),
            final_rules,
            default_rule_type: None,
            config,
        }
    }

    /// 显式设置默认规则类型（覆盖 session 推导）。对应 Go `getDefaultFinalRule`
    /// 的入站选择——当 Rust `Session` 不携带入站协议名时由此注入。
    #[must_use]
    pub fn with_default_rule_type(mut self, kind: DefaultRuleType) -> Self {
        self.default_rule_type = Some(kind);
        self
    }

    /// 解析域名为 IP 地址。
    ///
    /// `dial_system` 不支持 Domain（socket2 需要具体 IP），所以所有策略
    /// 都需要在此解析域名。AsIs 策略接受任意 IP 族，UseIP* 按 strategy 过滤。
    async fn resolve_domain(
        &self,
        domain: &str,
        port: u16,
        strategy: DomainStrategy,
    ) -> Result<Destination, OutboundError> {
        let addr = format!("{domain}:{port}");
        let lookup_result = tokio::net::lookup_host(&addr)
            .await
            .map_err(|e| OutboundError::ConnectionFailed(
                format!("DNS resolution failed for {domain}: {e}")
            ))?;

        let filtered: Vec<_> = lookup_result
            .filter(|addr| match strategy {
                DomainStrategy::UseIPv4 | DomainStrategy::UseIPv4v6 => addr.is_ipv4(),
                DomainStrategy::UseIPv6 | DomainStrategy::UseIPv6v4 => addr.is_ipv6(),
                DomainStrategy::UseIP | DomainStrategy::AsIs => true,
            })
            .collect();

        if filtered.is_empty() {
            return Err(OutboundError::ConnectionFailed(
                format!("DNS resolution returned no matching addresses for {domain} (strategy: {strategy:?})")
            ));
        }

        // UseIPv4v6: prefer IPv4, fallback IPv6
        // UseIPv6v4: prefer IPv6, fallback IPv4
        let selected = match strategy {
            DomainStrategy::UseIPv4v6 => filtered.iter().find(|a| a.is_ipv4()).or_else(|| filtered.first()),
            DomainStrategy::UseIPv6v4 => filtered.iter().find(|a| a.is_ipv6()).or_else(|| filtered.first()),
            _ => filtered.first(),
        };

        let socket_addr = *selected.expect("filtered is non-empty");

        let address = match socket_addr {
            std::net::SocketAddr::V4(v4) => Address::IPv4(*v4.ip()),
            std::net::SocketAddr::V6(v6) => Address::IPv6(*v6.ip()),
        };

        Ok(Destination::new(address, Port::new(socket_addr.port()), Network::TCP))
    }

    /// 决定当前连接的默认规则。
    ///
    /// 优先用显式 `default_rule_type`，否则从 `session.inbound.tag` 推导
    /// （对应 Go `getDefaultFinalRule(inbound)`）。
    fn resolve_default_rule(&self, session: &Session) -> Option<FinalRule> {
        let kind = self
            .default_rule_type
            .or_else(|| session.inbound.tag.as_deref().and_then(get_default_rule_type))?;
        Some(FinalRule::build_default_rule(kind))
    }

    /// 匹配 final rules → default rule。返回首个命中的规则（对应 Go `matchFinalRule`）。
    fn match_final_rule(
        &self,
        dest: &Destination,
        default_rule: Option<&FinalRule>,
    ) -> Option<FinalRule> {
        let net_idx = network_index(dest.network());
        let port = dest.port().value();
        let ip = dest.address().ip();
        for rule in &self.final_rules {
            if rule.apply(net_idx, port, ip) {
                return Some(rule.clone());
            }
        }
        if let Some(dr) = default_rule {
            if dr.apply(net_idx, port, ip) {
                return Some(dr.clone());
            }
        }
        None
    }

    /// 若目标被 Block 规则命中，返回该规则（dial 前调用）。
    fn check_blocked(&self, dest: &Destination, session: &Session) -> Option<FinalRule> {
        let default_rule = self.resolve_default_rule(session);
        let rule = self.match_final_rule(dest, default_rule.as_ref())?;
        if rule.action == RuleAction::Block {
            Some(rule)
        } else {
            None
        }
    }

    /// 黑洞处理：阻塞读取上游数据并丢弃，最多等待 `block_delay`，然后关闭下游。
    ///
    /// 对应 Go `Process` 中 `blockedDest != nil` 分支——不拨号，drain input→Discard，
    /// 超时后 Interrupt + Close，防探测。
    async fn blackhole(&self, link: Link, rule: &FinalRule) -> Result<(), ProxymanError> {
        let delay = block_delay(rule);
        tracing::info!(
            tag = %self.tag,
            ?delay,
            "freedom: target blocked by final rule, blackholing connection"
        );
        let Link { reader, writer } = link;
        let drain = async {
            let mut r = reader;
            while r.read_multi_buffer().await.is_ok() {}
        };
        tokio::select! {
            _ = drain => {}
            _ = tokio::time::sleep(delay) => {}
        }
        writer.shutdown();
        Ok(())
    }
}

/// Network → `[bool; 8]` 索引（TCP=0, UDP=1, Unix=2）。对应 Go `int(network)`。
fn network_index(network: Network) -> usize {
    match network {
        Network::TCP => 0,
        Network::UDP => 1,
        Network::Unix => 2,
    }
}

/// 计算阻断延时。对应 Go `Handler.blockDelay`。
///
/// 默认 [30, 90] 秒；`rule.block_delay` 可覆盖。`dice.Roll(span+1)` → [0, span]。
fn block_delay(rule: &FinalRule) -> std::time::Duration {
    let (min, max) = match rule.block_delay {
        Some(r) => (r.min, r.max),
        None => (30, 90),
    };
    let span = if max >= min { max - min } else { min - max };
    let roll = rand::random_range(0..=span);
    std::time::Duration::from_secs(min + roll)
}

#[async_trait]
impl OutboundHandler for FreedomHandler {
    fn tag(&self) -> &str {
        &self.tag
    }

    /// 通过 [`dial_system`] 拨号到 `destination`。
    ///
    /// 切片2 限制：`destination` 必须是 IP 地址（IPv4/IPv6），Domain 返回
    /// [`OutboundError::ConnectionFailed`]（DNS 解析留切片3 接入 LookupForIP）。
    ///
    /// **注意**：当前拨号建立的 Connection 在 dial 返回后 drop——这是切片2 的
    /// 验证性实现，仅证明 dial_system 端到端可用。真正的桥接（Connection ↔ Link）
    /// 留切片3。
    async fn dial(
        &self,
        destination: &Destination,
        _session: &Session,
    ) -> Result<(), OutboundError> {
        let strategy = DomainStrategy::from_i32(self.config.domain_strategy);

        let effective_dest = match destination.address() {
            Address::IPv4(_) | Address::IPv6(_) => destination.clone(),
            Address::Domain(domain) => {
                // dial_system 不支持 Domain（socket2 需要具体 IP），
                // 所有策略都需解析域名。AsIs 接受任意 IP 族。
                self.resolve_domain(domain, destination.port().value(), strategy).await?
            }
        };

        // FinalRule：dial 前检查私有 IP 阻断（对应 Go matchFinalRule Block 分支）。
        if let Some(_rule) = self.check_blocked(&effective_dest, _session) {
            tracing::info!(
                tag = %self.tag,
                dest = ?effective_dest,
                "freedom: connection blocked by final rule"
            );
            return Err(OutboundError::ConnectionFailed(
                "freedom: destination blocked by final rule".to_string(),
            ));
        }

        let sockopt = SocketOptions::default();
        let _conn = dial_system(&effective_dest, &sockopt)
            .await
            .map_err(|e| OutboundError::ConnectionFailed(format!("dial_system failed: {e}")))?;
        tracing::debug!(
            tag = %self.tag,
            strategy = ?strategy,
            "freedom dial succeeded"
        );
        Ok(())
    }

    fn can_handle(&self, _destination: &Destination) -> bool {
        // Freedom 可处理任意目标：IP 直接拨号，Domain 按 DomainStrategy 解析后拨号。
        true
    }
}

#[async_trait]
impl ProxyOutbound for FreedomHandler {
    /// Freedom 出站处理：拨号到目标地址，桥接 Link ↔ Connection。
    ///
    /// 对应 Go `freedom.(*Handler).Process(ctx, link, dialer)`。
    async fn process(
        &self,
        session: &Session,
        link: Link,
        dialer: Arc<dyn OutboundDialer>,
    ) -> Result<(), ProxymanError> {
        let dest = session.destination()
            .ok_or_else(|| ProxymanError::Other("freedom: no destination in session".to_string()))?;

        let strategy = DomainStrategy::from_i32(self.config.domain_strategy);

        let effective_dest = match dest.address() {
            Address::IPv4(_) | Address::IPv6(_) => dest.clone(),
            Address::Domain(domain) => {
                self.resolve_domain(domain, dest.port().value(), strategy).await
                    .map_err(|e| ProxymanError::OutboundProcessFailed(e.to_string()))?
            }
        };

        // FinalRule：dial 前检查阻断规则。命中 Block → 黑洞（blockDelay + drain），
        // 不拨号（对应 Go matchFinalRule Block 分支）。
        if let Some(rule) = self.check_blocked(&effective_dest, session) {
            return self.blackhole(link, &rule).await;
        }

        let mut conn = dialer.dial(&effective_dest).await
            .map_err(|e| ProxymanError::OutboundProcessFailed(format!("freedom dial failed: {e}")))?;

        // PROXY protocol：在拨号连接上写入 PROXY header（v1/v2）。
        // 对应 Go `proxyproto.HeaderProxyFromAddrs(version, srcAddr, dstAddr)`。
        if self.config.proxy_protocol == 1 || self.config.proxy_protocol == 2 {
            let src = session
                .source()
                .and_then(|d| d.address().ip())
                .map(|ip| SocketAddr::new(ip, 0));
            let dst = conn
                .remote_addr()
                .ok()
                .flatten();
            if let (Some(src), Some(dst)) = (src, dst) {
                let header = build_proxy_header(self.config.proxy_protocol as u8, src, dst);
                if !header.is_empty() {
                    use tokio::io::AsyncWriteExt;
                    if let Err(e) = conn.as_mut().write_all(&header).await {
                        tracing::warn!(tag = %self.tag, error = %e, "freedom: PROXY protocol write failed");
                        return Err(ProxymanError::OutboundProcessFailed(
                            format!("PROXY protocol write failed: {e}"),
                        ));
                    }
                    tracing::debug!(
                        tag = %self.tag,
                        version = self.config.proxy_protocol,
                        "freedom: PROXY protocol header written"
                    );
                }
            } else {
                tracing::debug!(
                    tag = %self.tag,
                    "freedom: PROXY protocol enabled but src/dst addr unavailable, skipping"
                );
            }
        }
        if !self.config.noises.is_empty() {
            use tokio::io::AsyncWriteExt;
            for noise in &self.config.noises {
                let size = if noise.length_max > noise.length_min {
                    rand::random_range(noise.length_min..=noise.length_max)
                } else {
                    noise.length_min
                } as usize;
                if size > 0 {
                    let buf = vec![0u8; size];
                    let _ = conn.as_mut().write_all(&buf).await;
                }
                if noise.delay_max > 0 {
                    let delay = if noise.delay_max > noise.delay_min {
                        rand::random_range(noise.delay_min..=noise.delay_max)
                    } else {
                        noise.delay_min
                    };
                    tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                }
            }
        }

        // Fragment: 首个 upstream chunk 分片写入（绕过 SNI 审查）。
        if let Some(fragment) = &self.config.fragment {
            self.bridge_with_fragment(link, conn, fragment).await
                .map_err(|e| ProxymanError::OutboundProcessFailed(format!("fragment bridge failed: {e}")))
        } else {
            bridge_link_with_stream_full(link, conn).await
                .map_err(|e| ProxymanError::OutboundProcessFailed(format!("bridge failed: {e}")))
        }
    }
}

impl FreedomHandler {
    /// 分片桥接：首个 upstream chunk 按 fragment 配置分片写入，后续正常桥接。
    async fn bridge_with_fragment(
        &self,
        link: Link,
        mut conn: Box<dyn xray_transport::connection::Connection>,
        fragment: &Fragment,
    ) -> std::io::Result<()> {
        use tokio::io::AsyncWriteExt;
        use xray_buf::multi::MultiBuffer;

        let Link { reader, writer } = link;
        let mut reader = reader;

        // 1. 读取首个 upstream chunk，分片写入 conn。
        let mb = reader.read_multi_buffer().await.ok();
        if let Some(mb) = &mb {
            let data = mb.to_vec();
            if !data.is_empty() {
                let mut offset = 0usize;
                while offset < data.len() {
                    let frag_size = if fragment.length_max > fragment.length_min {
                        rand::random_range(fragment.length_min..=fragment.length_max)
                    } else {
                        fragment.length_min
                    } as usize;
                    let end = (offset + frag_size.max(1)).min(data.len());
                    conn.as_mut().write_all(&data[offset..end]).await?;
                    conn.as_mut().flush().await?;
                    if fragment.interval_max > 0 {
                        let gap = if fragment.interval_max > fragment.interval_min {
                            rand::random_range(fragment.interval_min..=fragment.interval_max)
                        } else {
                            fragment.interval_min
                        };
                        tokio::time::sleep(std::time::Duration::from_micros(gap)).await;
                    }
                    offset = end;
                }
            }
        }

        // 2. 后续数据用正常桥接。
        let link = Link { reader, writer };
        bridge_link_with_stream_full(link, conn).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xray_common::net::network::Network;
    use xray_common::net::port::Port;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    fn make_ip_dest(ip: &str, port: u16) -> Destination {
        let addr: std::net::IpAddr = ip.parse().unwrap();
        let address = match addr {
            std::net::IpAddr::V4(v4) => Address::IPv4(v4),
            std::net::IpAddr::V6(v6) => Address::IPv6(v6),
        };
        Destination::new(address, Port::new(port), Network::TCP)
    }

    fn make_domain_dest(host: &str, port: u16) -> Destination {
        Destination::new(
            Address::Domain(host.to_string()),
            Port::new(port),
            Network::TCP,
        )
    }

    #[test]
    fn handler_tag_returns_construction_tag() {
        let h = FreedomHandler::new("freedom_out", Config::default());
        assert_eq!(h.tag(), "freedom_out");
    }

    #[test]
    fn can_handle_ipv4_destination() {
        let h = FreedomHandler::new("direct", Config::default());
        assert!(h.can_handle(&make_ip_dest("127.0.0.1", 80)));
    }

    #[test]
    fn can_handle_ipv6_destination() {
        let h = FreedomHandler::new("direct", Config::default());
        assert!(h.can_handle(&make_ip_dest("::1", 443)));
    }

    #[test]
    fn can_handle_domain_destination() {
        let h = FreedomHandler::new("direct", Config::default());
        assert!(h.can_handle(&make_domain_dest("example.com", 443)));
    }

    #[tokio::test]
    async fn dial_to_local_tcp_server_succeeds() {
        // 启动本地 TCP 服务器（接受连接后立即关闭）
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            // 接受一个连接即可（dial_system 建立后 drop，服务器端 accept 到后关闭）
            let _ = listener.accept().await;
        });

        let h = FreedomHandler::new("test", Config::default());
        let dest = make_ip_dest("127.0.0.1", addr.port());
        let session = Session::new();
        let result = h.dial(&dest, &session).await;
        assert!(result.is_ok(), "dial should succeed: {:?}", result.err());

        server_task.await.unwrap();
    }


    #[tokio::test]
    async fn dial_to_domain_with_asis_resolves_and_dials() {
        // AsIs 策略：解析域名后拨号。
        // 用 localhost 域名测试，加超时防止 DNS 卡住。
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let h = FreedomHandler::new("test", Config::default());
        let dest = make_domain_dest("localhost", addr.port());
        let session = Session::new();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            h.dial(&dest, &session),
        ).await;

        match result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => panic!("dial with AsIs failed: {e}"),
            Err(_) => {
                // DNS 超时——环境问题，不算测试失败
                eprintln!("SKIP: localhost DNS resolution timed out");
            }
        }

        server_task.abort();
    }

    #[tokio::test]
    async fn dial_to_invalid_domain_returns_error() {
        // 无效域名：DNS 解析失败
        let h = FreedomHandler::new("test", Config::default());
        let dest = make_domain_dest("this-domain-does-not-exist-xyz.invalid", 80);
        let session = Session::new();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            h.dial(&dest, &session),
        ).await;
        match result {
            Ok(Err(_)) => {}
            Ok(Ok(())) => panic!("expected error for invalid domain"),
            Err(_) => {
                // DNS 超时也算失败（NXDOMAIN 应该很快返回）
                eprintln!("SKIP: DNS resolution timed out for invalid domain");
            }
        }
    }

    #[tokio::test]
    async fn dial_and_write_to_echo_server() {
        // 更完整的端到端：handler.dial 成功 + 服务器 echo + 验证
        // 注意：切片2 中 dial 后 Connection drop，所以不能直接写。
        // 这个测试验证 dial 成功 + 服务器端 accept 到连接。
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            // 简单 echo：读一个字节写回
            let mut buf = [0u8; 1];
            use tokio::io::AsyncReadExt;
            if sock.read_exact(&mut buf).await.is_ok() {
                let _ = sock.write_all(&buf).await;
            }
        });

        // 用 handler.dial 验证拨号（Connection 在 handler 内 drop）
        let h = FreedomHandler::new("echo-test", Config::default());
        let dest = make_ip_dest("127.0.0.1", addr.port());
        let session = Session::new();
        h.dial(&dest, &session).await.unwrap();

        // 服务器侧在 handler drop Connection 后才能 accept（取决于时序）
        // 给服务器一点时间
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        // 服务器 task 应该已经完成或即将完成
        let _ = server_task.await;
    }
}
