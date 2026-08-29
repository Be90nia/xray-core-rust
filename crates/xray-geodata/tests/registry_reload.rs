//! Geodata registry Reload 集成测试。
//!
//! 对应 Go `common/geodata/IPReg.Reload()` + `DomainReg.Reload()`。

use std::net::IpAddr;
use std::sync::Arc;

use xray_geodata::matcher::domain::{DomainMatcher, DomainRule, DomainType};
use xray_geodata::matcher::ip::IPMatcher;
use xray_geodata::pb::{Cidr, CidrRule, IpRule};

fn ip_rule(cidr_ip: &[u8], prefix: u32) -> IpRule {
    IpRule {
        value: Some(xray_geodata::pb::ip_rule::Value::Custom(CidrRule {
            cidr: Some(Cidr::new(cidr_ip.to_vec(), prefix)),
            reverse_match: false,
        })),
    }
}

#[test]
fn ip_registry_add_returns_dynamic_matcher() {
    let reg = xray_geodata::matcher::ip::IpRegistry::new();
    let dyn_matcher = reg.add_rules(&[ip_rule(&[10, 0, 0, 0], 8)]).unwrap();
    assert!(dyn_matcher.match_ip("10.0.0.1".parse::<IpAddr>().unwrap()));
    assert!(!dyn_matcher.match_ip("192.168.1.1".parse::<IpAddr>().unwrap()));
}

#[test]
fn ip_registry_reload_swaps_matchers_atomically() {
    let reg = xray_geodata::matcher::ip::IpRegistry::new();
    let dyn_matcher: Arc<xray_geodata::matcher::ip::DynamicIPMatcher> =
        reg.add_rules(&[ip_rule(&[10, 0, 0, 0], 8)]).unwrap();

    assert!(dyn_matcher.match_ip("10.1.2.3".parse::<IpAddr>().unwrap()));
    assert!(!dyn_matcher.match_ip("192.168.0.1".parse::<IpAddr>().unwrap()));

    // Reload: 用 192.168.0.0/16 替换
    reg.reload_with(&[ip_rule(&[192, 168, 0, 0], 16)]).unwrap();

    assert!(!dyn_matcher.match_ip("10.1.2.3".parse::<IpAddr>().unwrap()));
    assert!(dyn_matcher.match_ip("192.168.1.1".parse::<IpAddr>().unwrap()));
}

#[test]
fn ip_registry_reload_preserves_reverse_state() {
    let reg = xray_geodata::matcher::ip::IpRegistry::new();
    let arc = reg
        .add_rules(&[ip_rule(&[10, 0, 0, 0], 8)])
        .unwrap();

    arc.set_reverse(true);
    assert!(!arc.match_ip("10.1.2.3".parse::<IpAddr>().unwrap()));
    assert!(arc.match_ip("192.168.0.1".parse::<IpAddr>().unwrap()));

    reg.reload_with(&[ip_rule(&[192, 168, 0, 0], 16)]).unwrap();

    // reverse 状态保留
    assert!(arc.match_ip("10.1.2.3".parse::<IpAddr>().unwrap()));
    assert!(!arc.match_ip("192.168.1.1".parse::<IpAddr>().unwrap()));
}

#[test]
fn domain_registry_reload_swaps_matchers_atomically() {
    let reg = xray_geodata::matcher::domain::DomainRegistry::new(Box::new(
        xray_geodata::matcher::domain::MphDomainMatcherFactory::new(),
    ));

    let dyn_matcher: Arc<xray_geodata::matcher::domain::DynamicDomainMatcher> = reg
        .add_rules(vec![DomainRule::new(DomainType::Full, "example.com", 1)])
        .unwrap();

    assert!(dyn_matcher.match_any("example.com"));
    assert!(!dyn_matcher.match_any("other.com"));

    reg.reload_with(vec![DomainRule::new(DomainType::Full, "test.org", 2)])
        .unwrap();

    assert!(!dyn_matcher.match_any("example.com"));
    assert!(dyn_matcher.match_any("test.org"));
}