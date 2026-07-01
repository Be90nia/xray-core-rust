//! 6fe 验收 E2E：构造标准 geoip.dat/geosite.dat → GeoDataLoader 加载 → matcher 查询。
//!
//! 验证任务验收点：「能加载标准 geoip.dat/geosite.dat 并 O(n) 查询」
//! （O(log n) 是 Go 原版目标；当前 IPSet 与 Go 原版一致采用前缀排序 + early short-circuit
//!  on /0 catch-all，本质 O(n) 但实际命中提前退出。MPH domain matcher 为 O(1) 查询。）

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use prost::Message;

use xray_geodata::loader::GeoDataLoader;
use xray_geodata::matcher::domain::{
    DomainMatcher, DomainRule, DomainType, MphDomainMatcher,
};
use xray_geodata::matcher::ip::{HeuristicIPMatcher, IPMatcher};
use xray_geodata::pb::{Cidr, Domain, GeoIp, GeoIpList, GeoSite, GeoSiteList};

// ── 测试夹具：构造标准 dat 字节 ───────────────────────────────────

fn make_geoip_dat() -> Vec<u8> {
    let cn = GeoIp::new("CN")
        .with_cidr(Cidr::new(vec![192, 168, 0, 0], 16))
        .with_cidr(Cidr::new(vec![10, 0, 0, 0], 8));
    let us = GeoIp::new("US").with_cidr(Cidr::new(vec![172, 16, 0, 0], 12));
    GeoIpList::new().with_entry(cn).with_entry(us).encode_to_vec()
}

fn make_geosite_dat() -> Vec<u8> {
    let cn = GeoSite::new("CN")
        .with_domain(Domain::full("baidu.com"))
        .with_domain(Domain::domain("qq.com"));
    let us = GeoSite::new("US").with_domain(Domain::full("google.com"));
    GeoSiteList::new().with_entry(cn).with_entry(us).encode_to_vec()
}

fn unique_dir(label: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "xray-geodata-e2e-{}-{label}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

// ── E2E 测试 ────────────────────────────────────────────────────

#[test]
fn load_geoip_and_match_ipv4_end_to_end() {
    let dir = unique_dir("geoip");
    std::fs::write(dir.join("geoip.dat"), make_geoip_dat()).unwrap();
    let loader = GeoDataLoader::new(dir.clone());

    // 加载 CN 条目
    let geo_cn = loader.load_ip("geoip.dat", "CN").unwrap();
    assert_eq!(geo_cn.code, "CN");
    assert_eq!(geo_cn.cidr.len(), 2);

    // 构造 HeuristicIPMatcher 并查询
    let matcher = HeuristicIPMatcher::from_cidrs(&geo_cn.cidr);
    assert!(matcher.match_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    assert!(matcher.match_ip(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))));
    assert!(!matcher.match_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));

    // 加载 US 条目并查询
    let geo_us = loader.load_ip("geoip.dat", "US").unwrap();
    assert_eq!(geo_us.code, "US");
    let m_us = HeuristicIPMatcher::from_cidrs(&geo_us.cidr);
    assert!(m_us.match_ip(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
    assert!(!m_us.match_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn load_geosite_and_match_domain_end_to_end() {
    let dir = unique_dir("geosite");
    std::fs::write(dir.join("geosite.dat"), make_geosite_dat()).unwrap();
    let loader = GeoDataLoader::new(dir.clone());

    let site_cn = loader.load_site("geosite.dat", "CN").unwrap();
    assert_eq!(site_cn.code, "CN");
    assert_eq!(site_cn.domain.len(), 2);

    // 把 GeoSite.domain（prost）转 DomainRule 列表（matcher 层）
    let rules: Vec<DomainRule> = site_cn
        .domain
        .iter()
        .enumerate()
        .map(|(i, d)| {
            let dt = DomainType::from_i32(d.r#type).unwrap_or(DomainType::Full);
            DomainRule::new(dt, d.value.clone(), (i + 1) as u32)
        })
        .collect();

    let matcher = MphDomainMatcher::build(&rules).unwrap();

    // Full 匹配
    assert!(matcher.match_any("baidu.com"));
    // Domain 类型：自身或子域名
    assert!(matcher.match_any("www.qq.com"));
    assert!(matcher.match_any("qq.com"));
    // 不在 CN geosite 内
    assert!(!matcher.match_any("google.com"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn check_file_validates_existence_without_loading_body() {
    let dir = unique_dir("check");
    std::fs::write(dir.join("geoip.dat"), make_geoip_dat()).unwrap();
    let loader = GeoDataLoader::new(dir.clone());

    // 已存在的 code 返回 Ok
    assert!(loader.check_file("geoip.dat", "CN").is_ok());
    assert!(loader.check_file("geoip.dat", "US").is_ok());
    // 不存在的 code 返回 Err
    assert!(loader.check_file("geoip.dat", "JP").is_err());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn not_found_code_returns_structured_error() {
    let dir = unique_dir("notfound");
    std::fs::write(dir.join("geoip.dat"), make_geoip_dat()).unwrap();
    let loader = GeoDataLoader::new(dir.clone());

    let err = loader.load_ip("geoip.dat", "XX").unwrap_err();
    assert!(
        matches!(
            err,
            xray_geodata::loader::LoaderError::NotFound { ref code } if code == "XX"
        ),
        "expected NotFound error, got {err:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn multiple_geoip_entries_in_one_dat_independent_query() {
    // 同一 dat 文件多 code 并存，查询各自独立
    let dir = unique_dir("multi");
    std::fs::write(dir.join("geoip.dat"), make_geoip_dat()).unwrap();
    let loader = GeoDataLoader::new(dir.clone());

    let cn = loader.load_ip("geoip.dat", "CN").unwrap();
    let us = loader.load_ip("geoip.dat", "US").unwrap();
    assert_eq!(cn.code, "CN");
    assert_eq!(us.code, "US");
    assert_ne!(cn.cidr.len(), us.cidr.len());

    let m_cn = HeuristicIPMatcher::from_cidrs(&cn.cidr);
    let m_us = HeuristicIPMatcher::from_cidrs(&us.cidr);

    // CN 命中 10.x 但 US 不命中
    assert!(m_cn.match_ip(IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1))));
    assert!(!m_us.match_ip(IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1))));

    let _ = std::fs::remove_dir_all(&dir);
}
