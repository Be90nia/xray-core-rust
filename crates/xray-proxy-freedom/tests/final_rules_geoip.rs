//! 端到端（bd djiou / epic twqps S3）：`finalRules` 的 `geoip:` 规则经**生产构造入口**
//! 真正生效——`FinalRuleConfig::from_json`（解析期查资产）+ `FinalRule::build`（构造期
//! 走全局 `IP_REG`，资产目录 = `get_asset_dir()` → `XRAY_LOCATION_ASSET`）+
//! `IP_REG.reload()` 热更。走的是配置装载到 dial 之间的同一段代码，不打桩。
//!
//! 单测试文件 = 独占进程 ⇒ 可安全写 env（`EnvFlag` 每次现读 env；`IP_REG` 在首次
//! 使用时捕获资产目录，故必须先设 env 再碰 `IP_REG`）。

use prost::Message as _;
use xray_geodata::{
    matcher::ip::IP_REG,
    pb::{Cidr, GeoIp, GeoIpList},
};
use xray_proxy_freedom::{FinalRule, FinalRuleConfig};

/// 最小 `geoip.dat`（`GeoIpList` 的 prost 编码，与真实资产同形）：
/// 单条 `PRIVATE` 条目，内容由 `cidrs` 决定。
fn write_geoip_dat(dir: &std::path::Path, cidrs: &[(Vec<u8>, u32)]) {
    let mut entry = GeoIp::new("PRIVATE");
    entry.cidr = cidrs.iter().map(|(ip, prefix)| Cidr::new(ip.clone(), *prefix)).collect();
    let list = GeoIpList::new().with_entry(entry);
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join(xray_geodata::rule_parser::DEFAULT_GEOIP_DAT), list.encode_to_vec())
        .unwrap();
}

fn asset_dir(label: &str) -> std::path::PathBuf {
    let mut dir = std::env::temp_dir();
    dir.push(format!("xray_freedom_e2e_{label}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn geoip_private_config() -> serde_json::Value {
    serde_json::json!({"action": "block", "ip": ["geoip:private"]})
}

#[test]
fn final_rules_geoip_private_work_through_production_entry() {
    let dir = asset_dir("geoip");
    write_geoip_dat(&dir, &[(vec![127, 0, 0, 0], 8), (vec![10, 0, 0, 0], 8)]);
    // SAFETY: 本测试二进制只有本用例，且写入发生在任何线程读该变量之前。
    unsafe { std::env::set_var("XRAY_LOCATION_ASSET", &dir) };

    let cfg = FinalRuleConfig::from_json(&geoip_private_config())
        .expect("`geoip:` 规则按生产资产目录解析");
    let rule = FinalRule::build(&cfg).expect("全局 IP_REG 构造 matcher");
    assert!(rule.apply(1, 80, Some("127.0.0.1".parse().unwrap())), "资产内地址命中规则");
    assert!(rule.apply(1, 80, Some("10.1.2.3".parse().unwrap())), "资产内地址命中规则");
    assert!(!rule.apply(1, 80, Some("8.8.8.8".parse().unwrap())), "资产外地址不命中");

    // 热更：资产换代 → `IP_REG.reload()` 按各 matcher 自己的 rules 重建，
    // 已交给调用方的 matcher 句柄必须跟着换（Go `DynamicIPMatcher` 同）。
    write_geoip_dat(&dir, &[(vec![8, 8, 8, 0], 24)]);
    IP_REG.reload().expect("reload 成功");
    assert!(rule.apply(1, 80, Some("8.8.8.8".parse().unwrap())), "热更后新资产命中");
    assert!(!rule.apply(1, 80, Some("10.1.2.3".parse().unwrap())), "热更后旧资产不再命中");

    // 资产缺失 ⇒ 解析期拒启（可诊断，不静默退化成"匹配所有 / 全放行"）。
    let empty = asset_dir("no_asset");
    // SAFETY: 同上，本测试二进制独占用例。
    unsafe { std::env::set_var("XRAY_LOCATION_ASSET", &empty) };
    let e = FinalRuleConfig::from_json(&geoip_private_config()).expect_err("资产缺失必须拒启");
    assert!(e.to_string().contains("geoip:private"), "错误须点名规则: {e}");
    assert!(e.to_string().contains("asset dir"), "错误须可定位资产目录: {e}");
}
