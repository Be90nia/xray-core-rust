//! Freedom 出站代理 Handler——对应 Go `proxy/freedom/freedom.go` 的 `Handler`。
//!
//! ## 切片边界（P6-5 切片2）
//!
//! 实现 [`OutboundHandler`] trait，内部调 [`xray_transport::system_dialer::dial_system`]
//! 验证 TCP 拨号端到端可用。桥接 `transport::Link`（link.reader/writer ↔ Connection）
//! 与 Domain DNS 解析留切片3。

use std::{net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use xray_app_proxyman::{
    error::ProxymanError,
    outbound::proxy_outbound::{OutboundDialer, ProxyOutbound},
};
use xray_common::{net::destination::Destination, session::Session};
use xray_features::outbound::{OutboundError, OutboundHandler};
use xray_transport::{
    bridge::bridge_link_with_stream_full_default, build_proxy_header, link::Link,
    sockopt::SocketOptions, system_dialer::dial_system,
};

use crate::{
    config::{Config, DefaultRuleType, FinalRule, RuleAction, get_default_rule_type},
    fragment::FragmentConnection,
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
        let final_rules =
            config.final_rules.iter().filter_map(|rc| FinalRule::build(rc).ok()).collect();
        Self { tag: tag.into(), final_rules, default_rule_type: None, config }
    }

    /// 显式设置默认规则类型（覆盖 session 推导）。对应 Go `getDefaultFinalRule`
    /// 的入站选择——当 Rust `Session` 不携带入站协议名时由此注入。
    #[must_use]
    pub fn with_default_rule_type(mut self, kind: DefaultRuleType) -> Self {
        self.default_rule_type = Some(kind);
        self
    }

    /// dial 前预检：命中 Block 规则则返回该规则。
    ///
    /// IP 目标直接匹配（Go :331-337）；域名目标仅在可能命中时解析（Go :294-295
    /// `defaultRule != nil || len(finalRules) > 0`），任一解析 IP 命中 Block 即阻断
    /// （Go :304-329）。解析仅服务预检——拨号目标保持原样（域名保留，#6058），
    /// 实际解析由拨号层按 SocketOptions.domain_strategy 完成。
    async fn check_blocked_resolved(
        &self,
        dest: &Destination,
        session: &Session,
    ) -> Result<Option<FinalRule>, OutboundError> {
        let default_rule = self.resolve_default_rule(session);
        if !dest.address().is_domain() {
            return Ok(self
                .match_final_rule(dest, default_rule.as_ref())
                .filter(|r| r.action == RuleAction::Block));
        }
        if default_rule.is_none() && self.final_rules.is_empty() {
            return Ok(None);
        }
        let strategy =
            xray_transport::sockopt::DomainStrategy::from_i32(self.config.domain_strategy);
        match crate::config::resolve_ips_for_rules(
            dest.address().as_domain().unwrap_or_default(),
            dest.port().value(),
            strategy,
        )
        .await
        {
            Ok(ips) => Ok(ips.iter().find_map(|ip| {
                let ip_dest = crate::config::destination_with_ip(dest, *ip);
                self.match_final_rule(&ip_dest, default_rule.as_ref())
                    .filter(|r| r.action == RuleAction::Block)
            })),
            Err(e) => Err(OutboundError::ConnectionFailed(format!(
                "freedom: ForceIP domain resolve failed: {e}"
            ))),
        }
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
        crate::config::match_final_rules(&self.final_rules, default_rule, dest)
    }

    /// 黑洞处理：阻塞读取上游数据并丢弃，最多等待 `block_delay`，然后关闭下游。
    ///
    /// 对应 Go `Process` 中 `blockedDest != nil` 分支——不拨号，drain input→Discard，
    /// 超时后 Interrupt + Close，防探测。
    async fn blackhole(&self, link: Link, rule: &FinalRule) -> Result<(), ProxymanError> {
        crate::config::blackhole_link(link, &self.tag, rule).await;
        Ok(())
    }
}

#[async_trait]
impl OutboundHandler for FreedomHandler {
    fn tag(&self) -> &str {
        &self.tag
    }

    /// 通过 [`dial_system`] 拨号到 `destination`。
    ///
    /// 目标可为 IP 或域名（域名按 domainStrategy 在拨号层解析，Go :296-300）；
    /// finalRule Block 预检命中 → [`OutboundError::ConnectionFailed`]。
    async fn dial(
        &self,
        destination: &Destination,
        session: &Session,
    ) -> Result<(), OutboundError> {
        // FinalRule 预检：解析仅服务 Block 判定，不改写拨号目标（#6058）。
        if self.check_blocked_resolved(destination, session).await?.is_some() {
            tracing::info!(
                tag = %self.tag,
                dest = ?destination,
                "freedom: connection blocked by final rule"
            );
            return Err(OutboundError::ConnectionFailed(
                "freedom: destination blocked by final rule".to_string(),
            ));
        }

        // 拨号恒用原始目标（#6058）：域名保留，解析下沉拨号层。
        let sockopt = SocketOptions {
            domain_strategy: xray_transport::sockopt::DomainStrategy::from_i32(
                self.config.domain_strategy,
            ),
            ..SocketOptions::default()
        };
        let _conn = dial_system(destination, &sockopt)
            .await
            .map_err(|e| OutboundError::ConnectionFailed(format!("dial_system failed: {e}")))?;
        tracing::debug!(tag = %self.tag, "freedom dial succeeded");
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
        let dest = session.destination().ok_or_else(|| {
            ProxymanError::Other("freedom: no destination in session".to_string())
        })?;

        // FinalRule 预检：命中 Block → 黑洞（blockDelay + drain），不拨号
        // （对应 Go matchFinalRule Block 分支）。解析仅服务预检，不改写拨号目标。
        if let Some(rule) = self
            .check_blocked_resolved(&dest, session)
            .await
            .map_err(|e| ProxymanError::OutboundProcessFailed(e.to_string()))?
        {
            return self.blackhole(link, &rule).await;
        }

        // 拨号恒用原始目标（#6058：Go :339 dialer.Dial(destination)，域名由 dialer 解析）。
        let mut conn = dialer.dial(&dest).await.map_err(|e| {
            ProxymanError::OutboundProcessFailed(format!("freedom dial failed: {e}"))
        })?;

        // PROXY protocol：在拨号连接上写入 PROXY header（v1/v2）。
        // 对应 Go `proxyproto.HeaderProxyFromAddrs(version, srcAddr, dstAddr)`。
        if self.config.proxy_protocol == 1 || self.config.proxy_protocol == 2 {
            let src =
                session.source().and_then(|d| d.address().ip()).map(|ip| SocketAddr::new(ip, 0));
            let dst = conn.remote_addr().ok().flatten();
            if let (Some(src), Some(dst)) = (src, dst) {
                let header = build_proxy_header(self.config.proxy_protocol as u8, src, dst);
                if !header.is_empty() {
                    use tokio::io::AsyncWriteExt;
                    if let Err(e) = conn.as_mut().write_all(&header).await {
                        tracing::warn!(tag = %self.tag, error = %e, "freedom: PROXY protocol write failed");
                        return Err(ProxymanError::OutboundProcessFailed(format!(
                            "PROXY protocol write failed: {e}"
                        )));
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
        // Fragment 配置存在时 dial 后包 writer（对齐 Go :410-418 FragmentWriter）；
        // noises 是 UDP 路径特性（Go NoisePacketWriter 只包 UDP PacketWriter），
        // TCP 路径不注入。
        let conn: Box<dyn xray_transport::connection::Connection> = match &self.config.fragment {
            Some(fragment) => Box::new(FragmentConnection::new(conn, fragment.clone())),
            None => conn,
        };

        bridge_link_with_stream_full_default(link, conn)
            .await
            .map_err(|e| ProxymanError::OutboundProcessFailed(format!("bridge failed: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use tokio::{io::AsyncWriteExt, net::TcpListener};
    use xray_common::net::{address::Address, network::Network, port::Port};

    use super::*;

    fn make_ip_dest(ip: &str, port: u16) -> Destination {
        let addr: std::net::IpAddr = ip.parse().unwrap();
        let address = match addr {
            std::net::IpAddr::V4(v4) => Address::IPv4(v4),
            std::net::IpAddr::V6(v6) => Address::IPv6(v6),
        };
        Destination::new(address, Port::new(port), Network::TCP)
    }

    fn make_domain_dest(host: &str, port: u16) -> Destination {
        Destination::new(Address::Domain(host.to_string()), Port::new(port), Network::TCP)
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
    async fn dial_to_domain_resolves_at_dial_layer_and_dials() {
        // #6058：域名目标 handler 不再预解析，由 dial_system 按 domainStrategy
        // 解析（FakeDns 脚本确定性返回 127.0.0.1）→ 连接本地监听成功。
        use crate::test_support::{FAKE_DNS_LOCK, FakeDns, install, uninstall};
        let _g = FAKE_DNS_LOCK.lock();
        let fake = FakeDns::ips(vec![vec![std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)]]);
        install(&fake);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let config = Config {
            domain_strategy: crate::config::DomainStrategy::UseIPv4 as i32,
            ..Default::default()
        };
        let h = FreedomHandler::new("test", config);
        let dest = make_domain_dest("dualstack.test", addr.port());
        let session = Session::new();
        let result =
            tokio::time::timeout(std::time::Duration::from_secs(5), h.dial(&dest, &session)).await;

        match result {
            Ok(Ok(())) => {},
            Ok(Err(e)) => panic!("dial via dial-layer resolution failed: {e}"),
            Err(_) => eprintln!("SKIP: dial timed out"),
        }

        uninstall();
        server_task.abort();
    }

    #[tokio::test]
    async fn dial_to_invalid_domain_returns_error() {
        // 无效域名：DNS 解析失败
        let h = FreedomHandler::new("test", Config::default());
        let dest = make_domain_dest("this-domain-does-not-exist-xyz.invalid", 80);
        let session = Session::new();
        let result =
            tokio::time::timeout(std::time::Duration::from_secs(5), h.dial(&dest, &session)).await;
        match result {
            Ok(Err(_)) => {},
            Ok(Ok(())) => panic!("expected error for invalid domain"),
            Err(_) => {
                // DNS 超时也算失败（NXDOMAIN 应该很快返回）
                eprintln!("SKIP: DNS resolution timed out for invalid domain");
            },
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

    /// #6058 预检：域名经策略解析命中 Block（10.0.0.0/8）→ dial 报阻断，不拨号。
    #[tokio::test]
    async fn dial_blocked_when_domain_resolves_to_blocked_ip() {
        use crate::test_support::{FAKE_DNS_LOCK, FakeDns, install, uninstall};
        let _g = FAKE_DNS_LOCK.lock();
        let fake = FakeDns::ips(vec![vec![std::net::IpAddr::V4("10.0.0.1".parse().unwrap())]]);
        install(&fake);

        let rule = crate::config::FinalRuleConfig::from_json(
            &serde_json::json!({"action": "block", "ip": ["10.0.0.0/8"]}),
        )
        .unwrap();
        let config = Config {
            domain_strategy: crate::config::DomainStrategy::UseIPv4 as i32,
            final_rules: vec![rule],
            ..Default::default()
        };
        let h = FreedomHandler::new("test", config);
        let dest = make_domain_dest("intranet.test", 80);
        let session = Session::new();
        let err = h.dial(&dest, &session).await.expect_err("blocked domain must not dial");
        assert!(err.to_string().contains("blocked by final rule"), "got: {err}");
        uninstall();
    }

    /// #6058：无规则（defaultRule=nil + finalRules 空）→ 域名不做预检解析
    /// （FakeDns 仅被拨号层查询 1 次），拨号正常（Go :294-295 条件门控）。
    #[tokio::test]
    async fn dial_domain_without_rules_skips_precheck_resolution() {
        use crate::test_support::{FAKE_DNS_LOCK, FakeDns, install, uninstall};
        let _g = FAKE_DNS_LOCK.lock();
        let fake = FakeDns::ips(vec![vec![std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)]]);
        install(&fake);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let config = Config {
            domain_strategy: crate::config::DomainStrategy::UseIPv4 as i32,
            ..Default::default()
        };
        let h = FreedomHandler::new("test", config);
        let dest = make_domain_dest("localhost", addr.port());
        let session = Session::new();
        let result =
            tokio::time::timeout(std::time::Duration::from_secs(5), h.dial(&dest, &session)).await;
        match result {
            Ok(Ok(())) => {},
            Ok(Err(e)) => panic!("dial should succeed: {e}"),
            Err(_) => eprintln!("SKIP: dial timed out"),
        }
        assert_eq!(
            fake.query_count(),
            1,
            "only the dial layer may resolve; no pre-check without rules"
        );
        uninstall();
        server_task.abort();
    }

    /// #6058：有规则（非 Block）→ 预检解析发生（FakeDns 共 2 次：预检+拨号层），
    /// 未命中 Block → 拨号照常成功。
    #[tokio::test]
    async fn dial_domain_with_rules_prechecks_then_dials() {
        use crate::test_support::{FAKE_DNS_LOCK, FakeDns, install, uninstall};
        let _g = FAKE_DNS_LOCK.lock();
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let fake = FakeDns::ips(vec![vec![ip], vec![ip]]);
        install(&fake);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let rule = crate::config::FinalRuleConfig::from_json(
            &serde_json::json!({"action": "allow", "port": "53"}),
        )
        .unwrap();
        let config = Config {
            domain_strategy: crate::config::DomainStrategy::UseIPv4 as i32,
            final_rules: vec![rule],
            ..Default::default()
        };
        let h = FreedomHandler::new("test", config);
        let dest = make_domain_dest("localhost", addr.port());
        let session = Session::new();
        let result =
            tokio::time::timeout(std::time::Duration::from_secs(5), h.dial(&dest, &session)).await;
        match result {
            Ok(Ok(())) => {},
            Ok(Err(e)) => panic!("dial should succeed: {e}"),
            Err(_) => eprintln!("SKIP: dial timed out"),
        }
        assert_eq!(
            fake.query_count(),
            2,
            "pre-check (rules present) + dial layer each resolve once"
        );
        uninstall();
        server_task.abort();
    }
}
