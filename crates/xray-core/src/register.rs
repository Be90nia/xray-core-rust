//! Feature 注册中心 —— 将 kind 字符串映射到 FeatureFactory。
//!
//! Go 用 `init()` 自注册（每个协议/应用在 init 中调用 `common.RegisterConfig`）。
//! Rust 没有 init，需要程序入口显式调用 [`register_all_features`]。
//!
//! 当前阶段：各 `xray-app-*` crate 尚未实现 `Feature` trait，因此注册 stub factory
//! （返回 `FeatureError::StartFailed` 提示 "not yet implemented"）。
//! 待各 crate 切片完成后，替换为真实 factory。

use std::sync::Arc;

use xray_features::{Feature, FeatureError, FeatureFactory, registry};

/// 注册所有已知 kind 的 FeatureFactory（stub 版本）。
///
/// 必须在 `Instance::new_from_built` 之前调用，否则所有 kind 查找返回 `NotFound`。
///
/// # 注册的 kind 列表
///
/// App: log, routing, dns, policy, api, metrics, stats, fakeDns,
///      observatory, burstObservatory, version, geodata
///
/// Proxy inbound: socks, http, shadowsocks, vmess, vless, trojan,
///                dokodemo, blackhole, dns, hysteria2, tuic, wireguard, anytls, tun, loopback
///
/// Proxy outbound: freedom, blackhole, dns, socks, http, shadowsocks,
///                 vmess, vless, trojan, hysteria2, tuic, wireguard, loopback
pub fn register_all_features() {
    // --- App kinds ---
    for &kind in APP_KINDS {
        registry::register_feature(kind, stub_factory(kind));
    }

    // --- Proxy inbound kinds ---
    for &kind in PROXY_INBOUND_KINDS {
        registry::register_feature(kind, stub_factory(kind));
    }

    // --- Proxy outbound kinds ---
    for &kind in PROXY_OUTBOUND_KINDS {
        registry::register_feature(kind, stub_factory(kind));
    }
}

/// App kind 列表（与 `xray-conf/src/built.rs` push_app! 宏的 kind 一致）。
const APP_KINDS: &[&str] = &[
    "log",
    "routing",
    "dns",
    "policy",
    "api",
    "metrics",
    "stats",
    "fakeDns",
    "observatory",
    "burstObservatory",
    "version",
    "geodata",
];

/// 代理入站 kind 列表（与 `xray-conf` 解析的 protocol 值一致）。
const PROXY_INBOUND_KINDS: &[&str] = &[
    "socks",
    "http",
    "shadowsocks",
    "vmess",
    "vless",
    "trojan",
    "dokodemo",
    "blackhole",
    "dns",
    "hysteria2",
    "tuic",
    "wireguard",
    "anytls",
    "tun",
    "loopback",
];

/// 代理出站 kind 列表。
const PROXY_OUTBOUND_KINDS: &[&str] = &[
    "freedom",
    "blackhole",
    "dns",
    "socks",
    "http",
    "shadowsocks",
    "vmess",
    "vless",
    "trojan",
    "hysteria2",
    "tuic",
    "wireguard",
    "loopback",
];

/// 创建 stub factory：返回 `StartFailed` 错误提示 "not yet implemented"。
fn stub_factory(kind: &'static str) -> FeatureFactory {
    Arc::new(move |_data: &[u8]| {
        Err(FeatureError::StartFailed {
            name: kind,
            message: format!("{kind}: not yet implemented (stub factory registered)"),
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_all_features_makes_all_kinds_findable() {
        register_all_features();

        for &kind in APP_KINDS.iter().chain(PROXY_INBOUND_KINDS).chain(PROXY_OUTBOUND_KINDS) {
            // stub factory 应能被找到（不再返回 NotFound）
            let result = registry::create_feature(kind, b"{}");
            assert!(
                !matches!(result, Err(FeatureError::NotFound { .. })),
                "kind={kind} should be registered, got NotFound"
            );
            // stub factory 返回 StartFailed
            if let Err(FeatureError::StartFailed { name, .. }) = result {
                assert_eq!(name, kind);
            }
        }
    }

    #[test]
    fn all_kinds_are_unique() {
        let mut all: Vec<&str> = Vec::new();
        all.extend(APP_KINDS);
        all.extend(PROXY_INBOUND_KINDS);
        all.extend(PROXY_OUTBOUND_KINDS);
        let mut sorted = all.clone();
        sorted.sort();
        sorted.dedup();
        // "dns", "blackhole", "loopback" 出现在多个列表中是正常的（不同上下文）
        // 只检查同一个列表内无重复
        for list in &[APP_KINDS, PROXY_INBOUND_KINDS, PROXY_OUTBOUND_KINDS] {
            let mut seen = std::collections::HashSet::new();
            for &k in *list {
                assert!(seen.insert(k), "duplicate kind in same list: {k}");
            }
        }
    }
}
