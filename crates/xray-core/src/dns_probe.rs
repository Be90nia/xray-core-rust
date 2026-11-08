//! TUN 系统 DNS 接管防环路探针的生产接线（bd ji765c）。
//!
//! `xray-proxy-tun::dns_verify` 只承载判定语义，环境事实经 [`DnsRoutingProbe`]
//! 注入；探针缺位 ⇒ Linux `autoSystemDnsToGateway` fail-closed 拒启（功能死键，
//! bd yq6gv-c）。本模块用装配期已有的 router / 配置 / 出站表三处句柄实现该 trait，
//! 并由 [`install`] 在装配期注册。
//!
//! 平台门控与 `xray-proxy-tun` 的 target 条件依赖一致（见 `lib.rs` 模块声明）。

use std::{collections::HashSet, net::IpAddr, sync::Arc};

use xray_app_dispatcher::default::{
    DispatcherContext, OutboundHandlerManager, RoutingRouter, SimpleOhm,
};
use xray_common::net::{network::Network, port::Port};
use xray_proxy_tun::dns_verify::{
    DnsCapability, DnsRoutingProbe, PROBE_SOURCE_PORT, RouteProbe, SystemResolverUse,
};

/// 探测目标端口：系统 DNS 查询落 TUN 时恒为 `:53`（Go `tun_system_dns.go:62`）。
const DNS_PORT: u16 = 53;

/// 生产探针：`verifyDNSRouting` 三段 core feature 访问的装配期句柄面。
pub(crate) struct CoreDnsRoutingProbe {
    /// routers 表（无 routing app 时 `None` = Go `router feature unavailable`）。
    router: Option<Arc<dyn RoutingRouter>>,
    /// 出站表（判 tag 是否存在）。
    ohm: Arc<SimpleOhm>,
    /// DNS 型出站 tag 集 = 配置 `protocol: "dns"` 的出站。
    ///
    /// Go 用 `ProxySettings` 类型断言；Rust 侧 `DispatchHandler` 无 downcast 面
    /// （`Send + Sync + Debug`，无 `Any`），故按协议名判定——两者信息源同一。
    dns_outbound_tags: HashSet<String>,
    /// 装配期判定的系统解析器风险（与运行期状态无关，故提前算好）。
    resolver_risk: Option<SystemResolverUse>,
}

impl CoreDnsRoutingProbe {
    /// 从装配期产物构造：`built` = 配置真相，`router`/`ohm` = 装配句柄。
    pub(crate) fn from_assembly(
        built: &xray_conf::BuiltConfig,
        router: Option<Arc<dyn RoutingRouter>>,
        ohm: Arc<SimpleOhm>,
    ) -> Self {
        Self {
            router,
            ohm,
            dns_outbound_tags: built
                .outbounds
                .iter()
                .filter(|ob| ob.entry.kind == "dns")
                .map(|ob| ob.tag.clone())
                .collect(),
            resolver_risk: system_resolver_risk(built),
        }
    }
}

impl DnsRoutingProbe for CoreDnsRoutingProbe {
    fn system_resolver_use(&self) -> Option<SystemResolverUse> {
        self.resolver_risk
    }

    fn route_for_dns(&self, inbound_tag: &str, source: IpAddr, address: IpAddr) -> RouteProbe {
        let Some(router) = self.router.as_ref() else {
            return RouteProbe::RouterUnavailable;
        };
        // 形如 Go `session.Inbound{Name:"tun", Tag: inboundTag}` + UDP 源临时端口 →
        // `address:53`；无嗅探协议（Go 探针会话不填 protocol）。
        let ctx = DispatcherContext {
            target_ips: vec![address],
            target_port: Port::new(DNS_PORT),
            source_ips: vec![source],
            source_port: Port::new(PROBE_SOURCE_PORT),
            network: Network::UDP,
            inbound_tag: inbound_tag.to_owned(),
            ..DispatcherContext::new()
        };
        match router.pick_route(&ctx) {
            Ok(route) if !route.outbound_tag.is_empty() => RouteProbe::Routed(route.outbound_tag),
            // 「无规则命中」与路由失败在 Go 侧同为拒（tun_system_dns.go:70-80）。
            _ => RouteProbe::NoRoute,
        }
    }

    fn outbound_dns(&self, tag: &str) -> DnsCapability {
        if self.ohm.get_handler(tag).is_none() {
            return DnsCapability::Missing;
        }
        if self.dns_outbound_tags.contains(tag) {
            DnsCapability::DnsCapable
        } else {
            DnsCapability::NotDns
        }
    }
}

/// 装配期注册生产探针（进程级，后注册覆盖——同 `sysroute` 出站绑定 controller 惯例）。
///
/// 无 router 也照注册：探针自身回答 `RouterUnavailable`，接管侧仍 fail-closed 拒启
/// 且错误可读（比「未注册」更能定位配置缺什么）。
pub(crate) fn install(
    built: &xray_conf::BuiltConfig,
    router: Option<Arc<dyn RoutingRouter>>,
    ohm: Arc<SimpleOhm>,
) {
    let probe = CoreDnsRoutingProbe::from_assembly(built, router, ohm);
    tracing::info!(
        router = probe.router.is_some(),
        dns_outbounds = probe.dns_outbound_tags.len(),
        system_resolver_risk = ?probe.resolver_risk,
        "tun system DNS probe registered"
    );
    xray_proxy_tun::register_dns_probe(Arc::new(probe));
}

/// 解析环路前置判定（Go `MayUseSystemResolver` + `dns` feature 两态，
/// tun_system_dns.go:44-56）。
///
/// 无 `dns` app ⇒ core 装的兜底 client 本身就是系统解析器；有 `dns` app 但
/// nameserver 为空或含 `localhost` ⇒ 仍有查询落回系统解析器（nameserver 按域名
/// 选择，一个即中）。解析不出配置同样按风险处理——宁可不接管，不静默放行。
fn system_resolver_risk(built: &xray_conf::BuiltConfig) -> Option<SystemResolverUse> {
    let Some(app) = built.apps.iter().find(|a| a.kind == "dns") else {
        return Some(SystemResolverUse::DnsFeature);
    };
    let Ok(cfg) = serde_json::from_slice::<xray_app_dns::DnsAppConfig>(&app.data) else {
        return Some(SystemResolverUse::ConfiguredServer);
    };
    let risky = cfg.servers.is_empty()
        || cfg
            .servers
            .iter()
            .any(|s| s.address.trim().to_ascii_lowercase().starts_with("localhost"));
    risky.then_some(SystemResolverUse::ConfiguredServer)
}

#[cfg(test)]
mod tests {
    use xray_app_dispatcher::{
        DispatchHandler, DispatcherError,
        default::{PinFuture, Route, RoutingContext as DispRoutingContext},
    };
    use xray_common::net::destination::Destination;
    use xray_conf::{BuiltEntry, BuiltOutbound};
    use xray_proxy_tun::verify_dns_routing;
    use xray_transport::link::Link;

    use super::*;

    /// 网关 `10.0.0.1/30` 的接管地址（Go `systemDNSAddrs` 推导结果）。
    const TAKEOVER_SOURCE: &str = "10.0.0.1";
    const TAKEOVER_ADDRESS: &str = "10.0.0.2";

    /// 固定出站 tag 的替身 router。
    #[derive(Debug)]
    struct FixedRouter(&'static str);

    impl RoutingRouter for FixedRouter {
        fn pick_route(&self, _ctx: &dyn DispRoutingContext) -> Result<Route, DispatcherError> {
            Ok(Route::new(self.0))
        }
    }

    /// 只提供 tag 的替身出站（探针只用 `get_handler` 判存在性）。
    #[derive(Debug)]
    struct TagOnlyHandler(&'static str);

    impl DispatchHandler for TagOnlyHandler {
        fn tag(&self) -> &str {
            self.0
        }

        fn dispatch(&self, _dest: &Destination, _link: Link) -> PinFuture<()> {
            Box::pin(async {})
        }
    }

    fn dns_app(servers_json: &str) -> xray_conf::BuiltConfig {
        xray_conf::BuiltConfig {
            apps: vec![BuiltEntry { kind: "dns".into(), data: servers_json.as_bytes().to_vec() }],
            ..Default::default()
        }
    }

    fn outbound(tag: &str, kind: &str) -> BuiltOutbound {
        BuiltOutbound {
            entry: BuiltEntry { kind: kind.into(), data: b"{}".to_vec() },
            tag: tag.into(),
            send_through: None,
            stream_settings_json: None,
            proxy_settings_json: None,
            mux_json: None,
            target_strategy: None,
        }
    }

    fn ohm_with(tags: &[&'static str]) -> Arc<SimpleOhm> {
        let ohm = Arc::new(SimpleOhm::new());
        for tag in tags {
            ohm.add(tag, Arc::new(TagOnlyHandler(tag)));
        }
        ohm
    }

    /// 路由命中 `dns-out`，`dns-out` 是配置里的 dns 型出站 ⇒ 验证通过。
    #[test]
    fn routed_to_dns_outbound_passes() {
        let mut built = dns_app(r#"{"servers":["8.8.8.8"]}"#);
        built.outbounds = vec![outbound("dns-out", "dns")];
        let probe = CoreDnsRoutingProbe::from_assembly(
            &built,
            Some(Arc::new(FixedRouter("dns-out"))),
            ohm_with(&["dns-out"]),
        );
        verify_dns_routing(&probe, "tun-in", TAKEOVER_SOURCE, TAKEOVER_ADDRESS)
            .expect("dns-capable route must pass");
    }

    /// 路由命中非 dns 型出站（freedom 等）⇒ 拒（查询无人应答）。
    #[test]
    fn routed_to_non_dns_outbound_refuses() {
        let mut built = dns_app(r#"{"servers":["8.8.8.8"]}"#);
        built.outbounds = vec![outbound("direct", "freedom")];
        let probe = CoreDnsRoutingProbe::from_assembly(
            &built,
            Some(Arc::new(FixedRouter("direct"))),
            ohm_with(&["direct"]),
        );
        let err = verify_dns_routing(&probe, "tun-in", TAKEOVER_SOURCE, TAKEOVER_ADDRESS)
            .expect_err("non-dns outbound must be refused");
        assert!(err.to_string().contains("outbound direct does not handle DNS"), "{err}");
    }

    /// 路由命中未注册的 tag ⇒ 拒（Go `outbound X does not exist`）。
    #[test]
    fn missing_outbound_refuses() {
        let built = dns_app(r#"{"servers":["8.8.8.8"]}"#);
        let probe = CoreDnsRoutingProbe::from_assembly(
            &built,
            Some(Arc::new(FixedRouter("ghost"))),
            ohm_with(&["dns-out"]),
        );
        let err = verify_dns_routing(&probe, "tun-in", TAKEOVER_SOURCE, TAKEOVER_ADDRESS)
            .expect_err("missing outbound must be refused");
        assert!(err.to_string().contains("outbound ghost does not exist"), "{err}");
    }

    /// 无 routing app ⇒ 拒（Go `router feature unavailable`）。
    #[test]
    fn no_router_refuses() {
        let built = dns_app(r#"{"servers":["8.8.8.8"]}"#);
        let probe = CoreDnsRoutingProbe::from_assembly(&built, None, ohm_with(&["dns-out"]));
        let err = verify_dns_routing(&probe, "tun-in", TAKEOVER_SOURCE, TAKEOVER_ADDRESS)
            .expect_err("missing router must be refused");
        assert!(err.to_string().contains("router feature unavailable"), "{err}");
    }

    /// `localhost` nameserver（独立上游并存也中）⇒ 拒。
    #[test]
    fn localhost_nameserver_refuses() {
        let built = dns_app(r#"{"servers":["8.8.8.8","localhost"]}"#);
        let probe = CoreDnsRoutingProbe::from_assembly(
            &built,
            Some(Arc::new(FixedRouter("dns-out"))),
            ohm_with(&["dns-out"]),
        );
        let err = verify_dns_routing(&probe, "tun-in", TAKEOVER_SOURCE, TAKEOVER_ADDRESS)
            .expect_err("localhost nameserver must be refused");
        assert!(err.to_string().contains("may resolve through the system resolver"), "{err}");
    }

    /// 无 `dns` app ⇒ 兜底 client 即系统解析器 ⇒ 拒。
    #[test]
    fn no_dns_app_refuses() {
        let probe = CoreDnsRoutingProbe::from_assembly(
            &xray_conf::BuiltConfig::default(),
            Some(Arc::new(FixedRouter("dns-out"))),
            ohm_with(&["dns-out"]),
        );
        let err = verify_dns_routing(&probe, "tun-in", TAKEOVER_SOURCE, TAKEOVER_ADDRESS)
            .expect_err("system resolver dns feature must be refused");
        assert!(err.to_string().contains("DNS feature is the system resolver"), "{err}");
    }
}
