//! TUN 系统 DNS 接管的防环路验证——Go `proxy/tun/tun_system_dns.go:29-96`
//! `verifyDNSRouting` 的移植（bd uwt1）。
//!
//! ## 语义（照抄 Go，勿自行发挥）
//!
//! 系统解析器被指向 TUN 内地址后，任何一条「解析仍可能落回系统解析器」的路径都会
//! 成环：系统 resolver → TUN → Xray → 系统 resolver。因此系统 DNS 接管只允许在
//! **验证通过**后进行：一条发往接管地址 `:53` 的 UDP 查询必须被路由到 DNS 型出站。
//! 拒绝条件与检查顺序逐条对齐 Go：
//!
//! 1. 接管地址解析失败 / 源地址解析失败或与接管地址族不一致 → 拒；
//! 2. DNS 应用仍可能走系统解析器（无 dns 应用段 = 系统解析器兜底；或配置了 `localhost`
//!    nameserver——nameserver 按域名选择，配了独立上游也挡不住）→ 拒；
//! 3. 路由探测失败（无 router / 无路由命中）→ 拒；
//! 4. 命中的出站不存在 / 不是 DNS 型出站 → 拒。
//!
//! ## 与 Go 的结构差异
//!
//! Go 用包级 `var verifyDNSRouting = func(...)` 可覆盖变量 + build tag
//! `(linux && !android) || freebsd`；Rust 把「判定语义」（本模块，平台无关、全平台
//! 编译，注入 [`DnsRoutingProbe`] 替身即可离线单测）与「环境探针」分离：探针由
//! core 接线方经 [`register_dns_probe`] 进程级注册（同 [`crate::sysroute`] 出站绑定
//! controller 惯例，后注册覆盖）。探针缺位 = 无法证明安全 → Linux 接管 fail-closed
//! 拒启，绝不静默放行。Windows 无「接管进 TUN」语义（Go build tag 不含 windows；
//! DNS 写适配器自身指向真实上游，环路防护在 dial 点 `dns_skip`）——由
//! [`crate::sysroute`] 显式记日志跳过，不静默。

use std::{net::IpAddr, sync::Arc};

use parking_lot::RwLock;

use crate::error::TunError;

/// 路由探测使用的代表客户端源端口。真实查询来自不可预知的临时端口，只有「按源
/// 端口匹配」的路由规则才受此值影响（Go `probeSourcePort`，tun_system_dns.go:22-25）。
pub const PROBE_SOURCE_PORT: u16 = 49152;

/// DNS 应用仍可能落回系统解析器的两种形态（Go 的两类拒绝消息判别，
/// tun_system_dns.go:47-56）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemResolverUse {
    /// DNS feature 本体就是系统解析器（Go `localdns.Client`——无 dns 应用段时
    /// core 安装的兜底客户端）。
    DnsFeature,
    /// dns 应用配置存在可走系统解析器的 nameserver（Go `appdns.DNS.MayUseSystemResolver`：
    /// 无任何 nameserver，或有 `localhost` nameserver——nameserver 按域名选择，
    /// 一个即中，独立上游并存也拒）。
    ConfiguredServer,
}

/// 路由探测结果（Go `router.PickRoute` 的三种结局）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteProbe {
    /// router feature 不可用。
    RouterUnavailable,
    /// 无路由命中（Go "no route for address:53"）。
    NoRoute,
    /// 命中出站 tag。
    Routed(String),
}

/// 出站 DNS 能力核查结果（Go `ohm.GetHandler` + `ProxySettings` 类型断言的结局）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsCapability {
    /// outbound manager 不可用。
    ManagerUnavailable,
    /// tag 不存在（Go "outbound X does not exist"）。
    Missing,
    /// 存在但不处理 DNS（Go "outbound X does not handle DNS"）。
    NotDns,
    /// DNS 型出站。
    DnsCapable,
}

/// 环境事实探针——Go `verifyDNSRouting` 函数体内三段 core feature 访问的注入面。
///
/// 生产实现由 core 接线（持 router / dns 应用 / outbound manager 句柄）注册；
/// 测试注入假实现离线驱动判定语义。探测目标固定为 UDP `address:53`，源端口用
/// [`PROBE_SOURCE_PORT`]。
pub trait DnsRoutingProbe: Send + Sync {
    /// DNS 应用是否仍可能走系统解析器（`None` = 已证不可能）。
    fn system_resolver_use(&self) -> Option<SystemResolverUse>;

    /// UDP 源（临时端口）→ `address:53` 的路由探测。`inbound_tag` 供按入站 tag
    /// 匹配的路由规则使用（Go `session.Inbound{Name: "tun", Tag: inboundTag}`）。
    fn route_for_dns(&self, inbound_tag: &str, source: IpAddr, address: IpAddr) -> RouteProbe;

    /// 出站 tag 是否存在且为 DNS 型出站。
    fn outbound_dns(&self, tag: &str) -> DnsCapability;
}

static DNS_PROBE: RwLock<Option<Arc<dyn DnsRoutingProbe>>> = RwLock::new(None);

/// 注册生产探针（进程级，后注册覆盖——换配置重启语义对齐 sysroute 出站绑定状态）。
pub fn register_dns_probe(probe: Arc<dyn DnsRoutingProbe>) {
    *DNS_PROBE.write() = Some(probe);
}

/// 当前注册的探针（接线方未注册 = `None`）。
pub(crate) fn dns_probe() -> Option<Arc<dyn DnsRoutingProbe>> {
    DNS_PROBE.read().clone()
}

/// 验证「系统 DNS 指向 `address`」不会形成解析环路——Go `verifyDNSRouting`
/// （tun_system_dns.go:34-96）的判定语义，检查顺序与错误文案逐条对齐。
///
/// 通过 = 解析路径不可能落回系统解析器，且一条发往 `address:53` 的 UDP 查询会被
/// 路由到 DNS 型出站；否则返回带明确原因的错误，调用方拒启（Go「宁可无 TUN」：
/// 接管失败时系统 DNS 保持指向 OS，宿主解析不受影响）。
///
/// # Errors
/// 任一拒绝条件命中：地址非法 / 源地址非法或族不一致 / 解析可能回系统解析器 /
/// 路由不可用或无路由 / 出站管理器不可用或出站不是 DNS 型。
pub fn verify_dns_routing(
    probe: &dyn DnsRoutingProbe,
    inbound_tag: &str,
    source: &str,
    address: &str,
) -> Result<(), TunError> {
    let addr: IpAddr = address
        .parse()
        .map_err(|_| TunError::InvalidConfig(format!("invalid DNS address {address}")))?;
    let src: IpAddr = source
        .parse()
        .map_err(|_| TunError::InvalidConfig(format!("invalid source address {source}")))?;
    if src.is_ipv4() != addr.is_ipv4() {
        return Err(TunError::InvalidConfig(format!("invalid source address {source}")));
    }

    // 任何可能仍落回系统解析器的路径都必须拒绝（Go tun_system_dns.go:44-56）。
    if let Some(risk) = probe.system_resolver_use() {
        return Err(TunError::InvalidConfig(match risk {
            SystemResolverUse::DnsFeature => {
                "DNS feature is the system resolver, takeover would loop".to_string()
            },
            SystemResolverUse::ConfiguredServer => {
                "DNS configuration may resolve through the system resolver, takeover would loop"
                    .to_string()
            },
        }));
    }

    let tag = match probe.route_for_dns(inbound_tag, src, addr) {
        RouteProbe::RouterUnavailable => {
            return Err(TunError::InvalidConfig("router feature unavailable".into()));
        },
        RouteProbe::NoRoute => {
            return Err(TunError::InvalidConfig(format!("no route for {address}:53")));
        },
        RouteProbe::Routed(tag) => tag,
    };

    match probe.outbound_dns(&tag) {
        DnsCapability::ManagerUnavailable => {
            Err(TunError::InvalidConfig("outbound manager unavailable".into()))
        },
        DnsCapability::Missing => {
            Err(TunError::InvalidConfig(format!("outbound {tag} does not exist")))
        },
        DnsCapability::NotDns => {
            Err(TunError::InvalidConfig(format!("outbound {tag} does not handle DNS")))
        },
        DnsCapability::DnsCapable => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 假探针：固定三段环境事实。
    struct FakeProbe {
        resolver: Option<SystemResolverUse>,
        route: RouteProbe,
        cap: DnsCapability,
    }

    impl DnsRoutingProbe for FakeProbe {
        fn system_resolver_use(&self) -> Option<SystemResolverUse> {
            self.resolver
        }

        fn route_for_dns(&self, _tag: &str, _source: IpAddr, _address: IpAddr) -> RouteProbe {
            self.route.clone()
        }

        fn outbound_dns(&self, _tag: &str) -> DnsCapability {
            self.cap.clone()
        }
    }

    /// 「DNS 指向自身子树」标准形：gateway `10.0.0.1/30` 的后继 `10.0.0.2`
    /// （接管地址，属 TUN 自身子树）——Go `systemDNSAddrs` 的推导结果。
    const TAKEOVER_SOURCE: &str = "10.0.0.1";
    const TAKEOVER_ADDRESS: &str = "10.0.0.2";

    /// 安全配置：解析不可能回系统解析器 + :53 命中 DNS 型出站。
    fn safe_probe() -> FakeProbe {
        FakeProbe {
            resolver: None,
            route: RouteProbe::Routed("dns-out".into()),
            cap: DnsCapability::DnsCapable,
        }
    }

    fn err_of(probe: &FakeProbe) -> String {
        verify_dns_routing(probe, "tun-in", TAKEOVER_SOURCE, TAKEOVER_ADDRESS)
            .expect_err("must refuse")
            .to_string()
    }

    #[test]
    fn safe_config_passes() {
        verify_dns_routing(&safe_probe(), "tun-in", TAKEOVER_SOURCE, TAKEOVER_ADDRESS)
            .expect("safe config must pass");
    }

    #[test]
    fn dns_feature_is_system_resolver_refuses() {
        let p = FakeProbe { resolver: Some(SystemResolverUse::DnsFeature), ..safe_probe() };
        assert!(err_of(&p).contains("DNS feature is the system resolver, takeover would loop"));
    }

    #[test]
    fn localhost_nameserver_refuses_even_with_independent_upstreams() {
        // Go：nameserver 按域名选择，一个 localhost 即中——独立上游并存也拒。
        let p = FakeProbe { resolver: Some(SystemResolverUse::ConfiguredServer), ..safe_probe() };
        assert!(err_of(&p).contains(
            "DNS configuration may resolve through the system resolver, takeover would loop"
        ));
    }

    #[test]
    fn no_route_to_dns_refuses_with_clear_error() {
        let p = FakeProbe { route: RouteProbe::NoRoute, ..safe_probe() };
        assert_eq!(err_of(&p), "invalid tun config: no route for 10.0.0.2:53");
    }

    #[test]
    fn routed_to_non_dns_outbound_refuses() {
        // 路由命中但出站不处理 DNS（如 freedom/direct）→ 查询无人应答 → 拒。
        let p = FakeProbe {
            route: RouteProbe::Routed("direct".into()),
            cap: DnsCapability::NotDns,
            ..safe_probe()
        };
        assert!(err_of(&p).contains("outbound direct does not handle DNS"));
    }

    #[test]
    fn routed_to_missing_outbound_refuses() {
        let p = FakeProbe {
            route: RouteProbe::Routed("ghost".into()),
            cap: DnsCapability::Missing,
            ..safe_probe()
        };
        assert!(err_of(&p).contains("outbound ghost does not exist"));
    }

    #[test]
    fn router_unavailable_refuses() {
        let p = FakeProbe { route: RouteProbe::RouterUnavailable, ..safe_probe() };
        assert!(err_of(&p).contains("router feature unavailable"));
    }

    #[test]
    fn manager_unavailable_refuses() {
        let p = FakeProbe { cap: DnsCapability::ManagerUnavailable, ..safe_probe() };
        assert!(err_of(&p).contains("outbound manager unavailable"));
    }

    #[test]
    fn invalid_dns_address_refuses() {
        let p = safe_probe();
        let err = verify_dns_routing(&p, "tun-in", TAKEOVER_SOURCE, "not-an-ip")
            .expect_err("must refuse")
            .to_string();
        assert!(err.contains("invalid DNS address not-an-ip"));
    }

    #[test]
    fn source_address_family_mismatch_refuses() {
        // Go：src.Is4() != ip.Is4() → "invalid source address"（v4 源配 v6 指向）。
        let p = safe_probe();
        let err = verify_dns_routing(&p, "tun-in", "10.0.0.1", "fd00::2")
            .expect_err("must refuse")
            .to_string();
        assert!(err.contains("invalid source address 10.0.0.1"));
    }
}
