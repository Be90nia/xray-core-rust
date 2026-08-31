//! 明文出站校验（d7fa2076 vless/trojan 私网外禁明文）。
//!
//! 对应 Go `infra/conf/xray.go:234-263` 的 `requiresTransportSecurity` +
//! `validateOutboundTransportSecurity`：Build 阶段硬校验 vless `encryption=none`
//! 与 trojan 无 stream TLS 的出站目标非私网 IP/域名时直接报错（Go
//! `common/errors.PrintRemovedFeatureError` 等价的 hard error）。
//!
//! # 私网判定
//!
//! Go 端走 geodata 私网匹配器；Rust 端用 [`xray_geodata::matcher::ip::IPSet`]
//! 内置 RFC1918 + link-local + loopback + ULA + IPv6 link-local +
//! `localhost`/`.local`/`.internal`/`.lan`/`.localdomain`/`.home`/`.corp`/`.lan`
//! 等常用私网域名。覆盖范围与 Go geodata `private`/`cn-priv` 列表不完全等价，
//! 但符合 Batch16-M 任务范围内「用 crates/xray-geodata 已有 API + RFC1918 +
//! link-local + loopback 默认集」的明确边界。
//!
//! ponytail: 默认私网集是「够用」而非「穷举」——若需严格对齐 Go geodata 全量数据，
//! 后续可挂 xray-geodata 的 geoip-loader 加载 `geoip-private.dat`。当前任务不需要。

use std::net::IpAddr;
use std::sync::LazyLock;

use xray_common::net::address::Address;
use xray_geodata::matcher::ip::IPSet;
use xray_geodata::pb::Cidr;

use crate::error::ConfError;

/// 默认私网 IP 集（IPv4 + IPv6，懒初始化）。
///
/// 覆盖：
/// - IPv4: RFC1918 10/8 + 172.16/12 + 192.168/16；loopback 127/8；link-local 169.254/16
/// - IPv6: loopback ::1/128；ULA fc00::/7；link-local fe80::/10；unspecified ::
/// - IPv4-mapped IPv6 形式（::ffff:10.0.0.0/104 等）暂不展开，靠裸 IP 走 IPv4 路径
static PRIVATE_IP_SET: LazyLock<IPSet> = LazyLock::new(|| {
    let cidrs: &[(Vec<u8>, u32)] = &[
        // RFC1918
        (vec![10, 0, 0, 0], 8),
        (vec![172, 16, 0, 0], 12),
        (vec![192, 168, 0, 0], 16),
        // loopback
        (vec![127, 0, 0, 0], 8),
        // link-local
        (vec![169, 254, 0, 0], 16),
        // 0.0.0.0（unspecified）
        (vec![0, 0, 0, 0], 8),
        // 100.64/10 carrier-grade NAT（RFC6598）
        (vec![100, 64, 0, 0], 10),
        // IPv6 loopback ::1/128
        (
            vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            128,
        ),
        // IPv6 unspecified ::/128
        (
            vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            128,
        ),
        // IPv6 ULA fc00::/7
        (vec![0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 7),
        // IPv6 link-local fe80::/10
        (vec![0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 10),
        // IPv4-mapped IPv6 (::ffff:0:0/96)
        (
            vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0],
            96,
        ),
    ];
    let cidrs: Vec<Cidr> = cidrs
        .iter()
        .map(|(ip, p)| Cidr {
            ip: ip.clone(),
            prefix: *p,
        })
        .collect();
    IPSet::from_cidrs(&cidrs)
});

/// 默认私网域名前缀（mDNS / 链路本地 / RFC6762）。
///
/// 命中规则：完整域等于其中任一，或以 `.` + 其中任一结尾。
const PRIVATE_DOMAIN_SUFFIXES: &[&str] = &[
    "localhost",
    "local",
    "internal",
    "intranet",
    "lan",
    "home",
    "corp",
    "localdomain",
];

/// 是否需要传输层加密（`true` = 需要 TLS/reality 等加密；`false` = 允许明文）。
///
/// 对应 Go `infra/conf/xray.go:234-243` `requiresTransportSecurity`：
/// - `address == nil` → 不需要（无目标不算明文出站）
/// - IP 类地址且命中私网 → 不需要（私网内可明文）
/// - 域名命中私网后缀 → 不需要
#[must_use]
pub fn requires_transport_security(address: Option<&Address>) -> bool {
    let Some(addr) = address else {
        return false;
    };
    match addr {
        Address::IPv4(v4) => {
            let ip = IpAddr::V4(*v4);
            !PRIVATE_IP_SET.contains(ip)
        }
        Address::IPv6(v6) => {
            let ip = IpAddr::V6(*v6);
            !PRIVATE_IP_SET.contains(ip)
        }
        Address::Domain(d) => {
            let normalized = d.trim_end_matches('.').to_ascii_lowercase();
            !PRIVATE_DOMAIN_SUFFIXES
                .iter()
                .any(|suf| normalized == *suf || normalized.ends_with(&format!(".{suf}")))
        }
    }
}

/// 校验单个出站：vless encryption=none 或 trojan 无 TLS 且目标非私网时报错。
///
/// 对应 Go `infra/conf/xray.go:245-266` `validateOutboundTransportSecurity`：
/// - `streamSettings.security != ""` → 已配 TLS/reality 等，OK
/// - vless `encryption` 非空且 != "none" → OK
/// - vless encryption empty / "none" 且目标需 TLS → 报 vless 明文禁令
/// - trojan 无 stream security 且目标需 TLS → 报 trojan 明文禁令
///
/// # 参数
/// - `protocol`: 出站协议名（小写，如 `"vless"` / `"trojan"`）
/// - `settings`: 出站 settings JSON（bytes）—— 含 vless `encryption` 或 trojan 配置
/// - `stream_settings`: 出站 `streamSettings` JSON —— `security` 字段（`"tls"` / `"reality"` / `""`）
///
/// # 错误
/// - [`ConfError::Build`]：明文出站禁令触发。
pub fn validate_outbound_transport_security(
    protocol: &str,
    settings: &[u8],
    stream_settings: Option<&serde_json::Value>,
) -> Result<(), ConfError> {
    // 1. stream_settings.security 非空 → 已有 TLS 等加密，跳过
    if let Some(ss) = stream_settings {
        if let Some(sec) = ss.get("security").and_then(|v| v.as_str()) {
            if !sec.is_empty() {
                return Ok(());
            }
        }
    }

    // 2. 解析 settings JSON（若无则视为空对象）
    let settings_val: serde_json::Value = if settings.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(settings).map_err(|e| ConfError::Build {
            what: "outbound.settings",
            message: e.to_string(),
        })?
    };

    // 3. 按协议分派
    match protocol {
        "vless" => {
            let encryption = settings_val
                .get("encryption")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !encryption.is_empty() && encryption != "none" {
                return Ok(());
            }
            let address = extract_vless_address(&settings_val);
            if requires_transport_security(address.as_ref()) {
                return Err(ConfError::Build {
                    what: "outbound.vless",
                    message:
                        "vless without TLS or other encryption is prohibited unless \
the server address is a private IP or domain"
                            .to_string(),
                });
            }
        }
        "trojan" => {
            let address = extract_trojan_address(&settings_val);
            if requires_transport_security(address.as_ref()) {
                return Err(ConfError::Build {
                    what: "outbound.trojan",
                    message:
                        "trojan without TLS is prohibited unless the server address is \
a private IP or domain"
                            .to_string(),
                });
            }
        }
        _ => {
            // 其他协议（vmess / ss / socks / freedom / ...）不在本任务校验范围。
        }
    }

    Ok(())
}

/// 从 vless settings JSON 提取目标 address。
///
/// 顺序：顶层 `address` → `vnext[0].address` → None。
fn extract_vless_address(settings: &serde_json::Value) -> Option<Address> {
    if let Some(v) = settings.get("address") {
        if let Some(addr) = parse_address_value(v) {
            return Some(addr);
        }
    }
    if let Some(vnext) = settings.get("vnext").and_then(|v| v.as_array()) {
        if let Some(first) = vnext.first() {
            if let Some(addr) = parse_address_value(first.get("address")?) {
                return Some(addr);
            }
        }
    }
    None
}
/// 顺序：顶层 `address` → `servers[0].address` → None。
fn extract_trojan_address(settings: &serde_json::Value) -> Option<Address> {
    if let Some(v) = settings.get("address") {
        if let Some(addr) = parse_address_value(v) {
            return Some(addr);
        }
    }
    if let Some(servers) = settings.get("servers").and_then(|v| v.as_array()) {
        if let Some(first) = servers.first() {
            if let Some(addr) = parse_address_value(first.get("address")?) {
                return Some(addr);
            }
        }
    }
    None
}

/// 把 `serde_json::Value` 解析为 `Address`。支持字符串（"1.2.3.4" / "example.com"）。
fn parse_address_value(v: &serde_json::Value) -> Option<Address> {
    let s = v.as_str()?;
    s.parse::<Address>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_ip_v4_rfc1918_not_required() {
        let addrs = [
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.0.1",
            "127.0.0.1",
            "169.254.1.1",
        ];
        for s in addrs {
            let a: Address = s.parse().unwrap();
            assert!(
                !requires_transport_security(Some(&a)),
                "私网 IPv4 {s} 应允许明文"
            );
        }
    }

    #[test]
    fn public_ip_v4_required() {
        let addrs = ["8.8.8.8", "1.1.1.1", "93.184.216.34"];
        for s in addrs {
            let a: Address = s.parse().unwrap();
            assert!(
                requires_transport_security(Some(&a)),
                "公网 IPv4 {s} 应要求 TLS"
            );
        }
    }

    #[test]
    fn private_ip_v6_not_required() {
        let addrs = ["::1", "fe80::1", "fc00::1", "fd00::1"];
        for s in addrs {
            let a: Address = s.parse().unwrap();
            assert!(
                !requires_transport_security(Some(&a)),
                "私网 IPv6 {s} 应允许明文"
            );
        }
    }

    #[test]
    fn public_ip_v6_required() {
        let a: Address = "2606:4700:4700::1111".parse().unwrap();
        assert!(requires_transport_security(Some(&a)));
    }

    #[test]
    fn private_domain_not_required() {
        let addrs = ["localhost", "router.local", "nas.home", "host.internal"];
        for s in addrs {
            let a: Address = s.parse().unwrap();
            assert!(
                !requires_transport_security(Some(&a)),
                "私网域名 {s} 应允许明文"
            );
        }
    }

    #[test]
    fn public_domain_required() {
        let a: Address = "example.com".parse().unwrap();
        assert!(requires_transport_security(Some(&a)));
    }

    #[test]
    fn nil_address_not_required() {
        assert!(!requires_transport_security(None));
    }

    #[test]
    fn vless_encryption_none_private_address_ok() {
        let settings = serde_json::json!({
            "vnext": [{"address": "127.0.0.1", "port": 443, "users": [{"id": "u", "encryption": "none"}]}]
        });
        let bytes = serde_json::to_vec(&settings).unwrap();
        assert!(validate_outbound_transport_security("vless", &bytes, None).is_ok());
    }

    #[test]
    fn vless_encryption_none_public_address_rejects() {
        let settings = serde_json::json!({
            "vnext": [{"address": "example.com", "port": 443, "users": [{"id": "u", "encryption": "none"}]}]
        });
        let bytes = serde_json::to_vec(&settings).unwrap();
        let err = validate_outbound_transport_security("vless", &bytes, None).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("vless without TLS"),
            "错误信息应包含明文禁令: {msg}"
        );
    }

    #[test]
    fn vless_encryption_aes_gcm_public_address_ok() {
        // Go vless.go L253:outbound 顶层 `encryption` 字段(v26.7.x VLESS encryption 机制,
        // L301 account.Encryption = c.Encryption 灌进 users);嵌套 users[].encryption 不参与本校验。
        let settings = serde_json::json!({
            "encryption": "aes-128-gcm",
            "vnext": [{"address": "example.com", "port": 443, "users": [{"id": "u", "encryption": "none"}]}]
        });
        let bytes = serde_json::to_vec(&settings).unwrap();
        assert!(validate_outbound_transport_security("vless", &bytes, None).is_ok());
    }

    #[test]
    fn vless_with_stream_security_ok() {
        let settings = serde_json::json!({
            "vnext": [{"address": "example.com", "port": 443, "users": [{"id": "u", "encryption": "none"}]}]
        });
        let bytes = serde_json::to_vec(&settings).unwrap();
        let stream = serde_json::json!({"security": "tls"});
        assert!(validate_outbound_transport_security("vless", &bytes, Some(&stream)).is_ok());
    }

    #[test]
    fn trojan_no_tls_public_rejects() {
        let settings = serde_json::json!({
            "servers": [{"address": "example.com", "port": 443, "password": "x"}]
        });
        let bytes = serde_json::to_vec(&settings).unwrap();
        let err = validate_outbound_transport_security("trojan", &bytes, None).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("trojan without TLS"),
            "错误信息应包含 trojan 明文禁令: {msg}"
        );
    }

    #[test]
    fn trojan_no_tls_private_ok() {
        let settings = serde_json::json!({
            "servers": [{"address": "192.168.1.10", "port": 443, "password": "x"}]
        });
        let bytes = serde_json::to_vec(&settings).unwrap();
        assert!(validate_outbound_transport_security("trojan", &bytes, None).is_ok());
    }

    #[test]
    fn trojan_with_tls_public_ok() {
        let settings = serde_json::json!({
            "servers": [{"address": "example.com", "port": 443, "password": "x"}]
        });
        let bytes = serde_json::to_vec(&settings).unwrap();
        let stream = serde_json::json!({"security": "reality"});
        assert!(validate_outbound_transport_security("trojan", &bytes, Some(&stream)).is_ok());
    }

    #[test]
    fn other_protocols_unaffected() {
        let settings = serde_json::json!({"vnext": [{"address": "example.com", "port": 443}]});
        let bytes = serde_json::to_vec(&settings).unwrap();
        for p in ["vmess", "shadowsocks", "freedom", "socks", "http"] {
            assert!(
                validate_outbound_transport_security(p, &bytes, None).is_ok(),
                "协议 {p} 不在本任务校验范围"
            );
        }
    }

    #[test]
    fn vless_top_level_address_overrides_vnext() {
        let settings = serde_json::json!({
            "address": "127.0.0.1",
            "port": 443,
            "vnext": [{"address": "example.com", "port": 443, "users": [{"id": "u"}]}]
        });
        let bytes = serde_json::to_vec(&settings).unwrap();
        assert!(validate_outbound_transport_security("vless", &bytes, None).is_ok());
    }

    #[test]
    fn trojan_top_level_address_overrides_servers() {
        let settings = serde_json::json!({
            "address": "127.0.0.1",
            "port": 443,
            "servers": [{"address": "example.com", "port": 443, "password": "x"}]
        });
        let bytes = serde_json::to_vec(&settings).unwrap();
        assert!(validate_outbound_transport_security("trojan", &bytes, None).is_ok());
    }

    #[test]
    fn empty_settings_vless_allowed() {
        // Go 基准 xray.go:237-239:address == nil → requiresTransportSecurity=false → 允许。
        let bytes = b"{}";
        assert!(validate_outbound_transport_security("vless", bytes, None).is_ok());
    }

    #[test]
    fn empty_settings_trojan_allowed() {
        let bytes = b"{}";
        assert!(validate_outbound_transport_security("trojan", bytes, None).is_ok());
    }

    #[test]
    fn invalid_settings_json_propagates() {
        let bytes = b"not json";
        let err = validate_outbound_transport_security("vless", bytes, None).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("outbound.settings"),
            "settings JSON 解析失败应通过 Build 错误传播: {msg}"
        );
    }
}
