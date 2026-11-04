//! Go 形状的 `geosite.dat`（手写 protobuf `Domain.Type` = 0/1/2/3）→ `GeoDataLoader`
//! 加载 → `from_proto_type` 换成 matcher 类型 → 匹配行为回归。
//!
//! 夹具直接写 pb 编号（不用 `Domain::full()` 等构造器，避免夹具与实现同源），
//! 对应 `protos/common/geodata/geodat.proto` 的 `Substr=0/Regex=1/Domain=2/Full=3`。

// 集成测试夹具不在 `#[test]` 函数体内，根 clippy.toml 的 allow-unwrap-in-tests 覆盖不到。
#![allow(clippy::unwrap_used, reason = "集成测试夹具不在 #[test] 函数体内")]

use std::{path::PathBuf, time::Duration};

use prost::Message;
use xray_geodata::{
    loader::GeoDataLoader,
    matcher::domain::{DomainMatcher, DomainRule, DomainType, MphDomainMatcher, from_proto_type},
    pb::{Domain, GeoSite, GeoSiteList},
};

/// 各条规则的 pb 类型、值与规则ID（ID = 1..4，按下标分配）。
const RULES: [(i32, &str); 4] = [
    (0, "marker"),      // Substr
    (1, r"^x\.test$"),  // Regex
    (2, "example.com"), // Domain
    (3, "example.com"), // Full
];

fn make_geosite_dat() -> Vec<u8> {
    let mut site = GeoSite::new("CN");
    for (pb_type, value) in RULES {
        let d = Domain { r#type: pb_type, value: value.to_string(), ..Domain::default() };
        site.domain.push(d);
    }
    GeoSiteList::new().with_entry(site).encode_to_vec()
}

fn unique_dir(label: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_nanos();
    p.push(format!("xray-geodata-dtnum-{}-{label}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// 加载 → 转 matcher 规则 → 构建匹配器。返回 `(matcher, dir)`，调用方负责删 dir。
fn load_matcher(label: &str) -> (MphDomainMatcher, PathBuf) {
    let dir = unique_dir(label);
    std::fs::write(dir.join("geosite.dat"), make_geosite_dat()).unwrap();
    let site = GeoDataLoader::new(dir.clone()).load_site("geosite.dat", "CN").unwrap();

    let rules: Vec<DomainRule> = site
        .domain
        .iter()
        .enumerate()
        .map(|(i, d)| {
            let dt = from_proto_type(d.r#type)
                .unwrap_or_else(|| panic!("unknown pb domain type {} on {:?}", d.r#type, d.value));
            DomainRule::new(dt, d.value.clone(), (i + 1) as u32)
        })
        .collect();
    (MphDomainMatcher::build(&rules).unwrap(), dir)
}

#[test]
fn go_shaped_geosite_rules_match_per_their_pb_type() {
    let (matcher, dir) = load_matcher("match");
    // 规则ID：1=Substr "marker"、2=Regex "^x\.test$"、3=Domain "example.com"、4=Full "example.com"
    let hits = |input: &str, id: u32| matcher.match_domain(input).contains(&id);

    // Substr：子串命中
    assert!(hits("a.marker.b", 1), "Substr 应命中 a.marker.b");
    assert!(!hits("nomatch", 1));

    // Regex：锚定整串
    assert!(hits("x.test", 2), "Regex 应命中 x.test");
    assert!(!hits("ax.test", 2), "Regex ^x\\.test$ 不应命中 ax.test");

    // Domain：自身与子域名
    assert!(hits("example.com", 3));
    assert!(hits("sub.example.com", 3));

    // Full：精确全匹配，子域名不命中
    assert!(hits("example.com", 4));
    assert!(!hits("sub.example.com", 4), "Full 不应命中子域名");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn proto_numbers_map_to_distinct_matcher_types() {
    // 四类各自正确、互不错位（错位即两类断言同时炸）
    assert_eq!(from_proto_type(0), Some(DomainType::Substr));
    assert_eq!(from_proto_type(1), Some(DomainType::Regex));
    assert_eq!(from_proto_type(2), Some(DomainType::Domain));
    assert_eq!(from_proto_type(3), Some(DomainType::Full));
}

#[test]
fn domain_constructor_encodes_proto_numbering_after_roundtrip() {
    // 构造器产 pb 编号：编码 → 解码后 r#type 仍是 3（pb Full），且能换回 matcher Full
    let bytes = Domain::full("example.com").encode_to_vec();
    let decoded = Domain::decode(bytes.as_slice()).unwrap();
    assert_eq!(decoded.r#type, 3, "Domain::full 必须写 pb Full=3");
    assert_eq!(from_proto_type(decoded.r#type), Some(DomainType::Full));
}
