//! Geodata registry Reload 集成测试（bd hdgz9：世代热换**按各自 rules** 重建）。
//!
//! 对应 Go `common/geodata/IPReg.Reload()` + `DomainReg.Reload()`。

use std::{
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use xray_geodata::{
    matcher::{
        domain::{DomainMatcher, DomainRegistry},
        ip::{DynamicIPMatcher, IPMatcher, IpRegistry},
    },
    pb::{
        Cidr, CidrRule, Domain, DomainRule as PbDomainRule, GeoIp, GeoIpList, GeoIpRule, GeoSite,
        GeoSiteList, GeoSiteRule, IpRule, domain_rule::Value as DomainRuleValue,
        ip_rule::Value as IpRuleValue,
    },
};

fn cidr(ip: [u8; 4], prefix: u32) -> Cidr {
    Cidr::new(ip.to_vec(), prefix)
}

fn ip_rule(cidr_ip: [u8; 4], prefix: u32) -> IpRule {
    IpRule {
        value: Some(IpRuleValue::Custom(CidrRule {
            cidr: Some(cidr(cidr_ip, prefix)),
            reverse_match: false,
        })),
    }
}

fn geoip_rule(code: &str) -> IpRule {
    IpRule {
        value: Some(IpRuleValue::Geoip(GeoIpRule {
            file: "geoip.dat".to_string(),
            code: code.to_string(),
            reverse_match: false,
        })),
    }
}

/// 合成 `geoip.dat`（`GeoIPList` 顶层 repeated 编码，与真实资产同形）。
fn write_geoip_dat(dir: &Path, entries: &[(&str, Vec<Cidr>)]) {
    use prost::Message;

    let mut list = GeoIpList::new();
    for (code, cidrs) in entries {
        let mut geo = GeoIp::new(code);
        geo.cidr = cidrs.clone();
        list = list.with_entry(geo);
    }
    std::fs::write(dir.join("geoip.dat"), list.encode_to_vec()).unwrap();
}

fn tmp_dir(label: &str) -> PathBuf {
    let mut dir = std::env::temp_dir();
    dir.push(format!("xray_geodata_registry_{label}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[test]
fn ip_registry_build_returns_dynamic_matcher() {
    let reg = IpRegistry::new();
    let dyn_matcher = reg.build_ip_matcher(&[ip_rule([10, 0, 0, 0], 8)]).unwrap();
    assert!(dyn_matcher.match_ip(ip("10.0.0.1")));
    assert!(!dyn_matcher.match_ip(ip("192.168.1.1")));
}

/// 真 reload 出口门：**每个 matcher 用自己的 rules** 从新资产重建。
///
/// 旧实现（`reload_with`：同一份新规则覆盖所有 matcher）会让 CN / US 两个
/// matcher 变成同一份规则 ⇒ 交叉断言必红（Go `IPRegistry.Reload` 无此行为）。
#[test]
fn ip_registry_reload_uses_each_matchers_own_rules() {
    let dir = tmp_dir("own_rules");
    write_geoip_dat(
        &dir,
        &[("CN", vec![cidr([10, 0, 0, 0], 8)]), ("US", vec![cidr([192, 168, 0, 0], 16)])],
    );
    let reg = IpRegistry::with_datadir(dir.clone());
    let cn: Arc<DynamicIPMatcher> = reg.build_ip_matcher(&[geoip_rule("CN")]).unwrap();
    let us: Arc<DynamicIPMatcher> = reg.build_ip_matcher(&[geoip_rule("US")]).unwrap();
    assert!(cn.match_ip(ip("10.1.2.3")));
    assert!(us.match_ip(ip("192.168.1.1")));

    // 换资产（cron 热更 = 落盘 + reload）：CN → 172.16/12，US → 8.8.8.0/24
    write_geoip_dat(
        &dir,
        &[("CN", vec![cidr([172, 16, 0, 0], 12)]), ("US", vec![cidr([8, 8, 8, 0], 24)])],
    );
    reg.reload().unwrap();

    assert!(cn.match_ip(ip("172.16.0.1")), "CN matcher 必须看到新 CN 数据");
    assert!(!cn.match_ip(ip("10.1.2.3")), "旧 CN 数据必须消失");
    assert!(us.match_ip(ip("8.8.8.8")), "US matcher 必须看到新 US 数据");
    assert!(!us.match_ip(ip("192.168.1.1")), "旧 US 数据必须消失");
    // 交叉断言：「同一份新规则覆盖」的旧实现到这里必红。
    assert!(!cn.match_ip(ip("8.8.8.8")), "CN matcher 不得套用 US 规则");
    assert!(!us.match_ip(ip("172.16.0.1")), "US matcher 不得套用 CN 规则");
}

/// 热换失败不半切：任一条重建失败 ⇒ 整体 Err，旧世代快照原样保留。
#[test]
fn ip_registry_reload_error_keeps_previous_generation() {
    let dir = tmp_dir("reload_err");
    write_geoip_dat(&dir, &[("CN", vec![cidr([10, 0, 0, 0], 8)])]);
    let reg = IpRegistry::with_datadir(dir.clone());
    let cn = reg.build_ip_matcher(&[geoip_rule("CN")]).unwrap();
    assert!(cn.match_ip(ip("10.1.2.3")));

    std::fs::remove_file(dir.join("geoip.dat")).unwrap();
    assert!(reg.reload().is_err(), "资产缺失 ⇒ 整体 Err");
    assert!(cn.match_ip(ip("10.1.2.3")), "旧世代原样保留（不半切）");
}

#[test]
fn ip_registry_reload_preserves_reverse_state() {
    let reg = IpRegistry::new();
    let arc = reg.build_ip_matcher(&[ip_rule([10, 0, 0, 0], 8)]).unwrap();

    arc.set_reverse(true).unwrap();
    assert!(!arc.match_ip(ip("10.1.2.3")));
    assert!(arc.match_ip(ip("192.168.0.1")));

    reg.reload().unwrap();

    // reverse 状态保留
    assert!(!arc.match_ip(ip("10.1.2.3")), "reload 后 reverse 语义保留");
    assert!(arc.match_ip(ip("192.168.0.1")));
}

/// 合成 `geosite.dat`（`GeoSiteList` 顶层 repeated 编码，与真实资产同形）。
fn write_geosite_dat(dir: &Path, entries: &[(&str, Vec<Domain>)]) {
    use prost::Message;

    let list = GeoSiteList {
        entry: entries
            .iter()
            .map(|(code, domains)| GeoSite { code: (*code).to_string(), domain: domains.clone() })
            .collect(),
    };
    std::fs::write(dir.join("geosite.dat"), list.encode_to_vec()).unwrap();
}

fn geosite_rule(code: &str) -> PbDomainRule {
    PbDomainRule {
        value: Some(DomainRuleValue::Geosite(GeoSiteRule {
            file: "geosite.dat".to_string(),
            code: code.to_string(),
            attrs: String::new(),
        })),
    }
}

#[test]
fn domain_registry_build_returns_dynamic_matcher() {
    let reg = DomainRegistry::new();
    let matcher = reg
        .build_domain_matcher(&[PbDomainRule {
            value: Some(DomainRuleValue::Custom(Domain::full("example.com"))),
        }])
        .unwrap();
    assert!(matcher.match_any("example.com"));
    assert!(!matcher.match_any("other.com"));
}

/// 域名侧真 reload：**每个 matcher 用自己的 pb 规则**从新资产重建。
///
/// 旧实现（`reload_with`：同一份新规则覆盖所有 matcher）会让 CN / US 两个
/// matcher 变成同一份规则 ⇒ 交叉断言必红（Go `DomainRegistry.Reload` 无此行为）。
#[test]
fn domain_registry_reload_uses_each_matchers_own_rules() {
    let dir = tmp_dir("domain_own_rules");
    write_geosite_dat(
        &dir,
        &[("CN", vec![Domain::full("cn.example")]), ("US", vec![Domain::full("us.example")])],
    );
    let reg = DomainRegistry::with_datadir(dir.clone());
    let cn = reg.build_domain_matcher(&[geosite_rule("CN")]).unwrap();
    let us = reg.build_domain_matcher(&[geosite_rule("US")]).unwrap();
    assert!(cn.match_any("cn.example"));
    assert!(us.match_any("us.example"));

    // 换资产（cron 热更 = 落盘 + reload）
    write_geosite_dat(
        &dir,
        &[("CN", vec![Domain::full("cn2.example")]), ("US", vec![Domain::full("us2.example")])],
    );
    reg.reload().unwrap();

    assert!(cn.match_any("cn2.example"), "CN matcher 必须看到新 CN 数据");
    assert!(!cn.match_any("cn.example"), "旧 CN 数据必须消失");
    assert!(us.match_any("us2.example"), "US matcher 必须看到新 US 数据");
    assert!(!us.match_any("us.example"), "旧 US 数据必须消失");
    // 交叉断言：「同一份新规则覆盖」的旧实现到这里必红。
    assert!(!cn.match_any("us2.example"), "CN matcher 不得套用 US 规则");
    assert!(!us.match_any("cn2.example"), "US matcher 不得套用 CN 规则");
}

/// 热换失败不半切：任一条重建失败 ⇒ 整体 Err，旧世代快照原样保留。
#[test]
fn domain_registry_reload_error_keeps_previous_generation() {
    let dir = tmp_dir("domain_reload_err");
    write_geosite_dat(&dir, &[("CN", vec![Domain::full("cn.example")])]);
    let reg = DomainRegistry::with_datadir(dir.clone());
    let cn = reg.build_domain_matcher(&[geosite_rule("CN")]).unwrap();
    assert!(cn.match_any("cn.example"));

    std::fs::remove_file(dir.join("geosite.dat")).unwrap();
    assert!(reg.reload().is_err(), "资产缺失 ⇒ 整体 Err");
    assert!(cn.match_any("cn.example"), "旧世代原样保留（不半切）");
}
