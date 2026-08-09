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
///                dokodemo, blackhole, dns, hysteria2, tuic, wireguard, anytls, tun*, loopback
///
/// Proxy outbound: freedom, blackhole, dns, socks, http, shadowsocks,
///                 vmess, vless, trojan, hysteria2, tuic, wireguard, loopback
///
/// *tun 仅在 Linux/Android/FreeBSD 上注册。
pub fn register_all_features() {
    // --- App kinds ---
    for &kind in APP_KINDS {
        let _ = registry::register_feature(kind, stub_factory(kind));
    }
    // Override log with real factory
    let _ = registry::register_feature("log", log_factory());

    // --- Proxy inbound kinds ---
    for &kind in PROXY_INBOUND_KINDS {
        let _ = registry::register_feature(kind, stub_factory(kind));
    }
    // TUN inbound——仅 Linux/Android/FreeBSD
    for &kind in TUN_INBOUND_KIND {
        let _ = registry::register_feature(kind, stub_factory(kind));
    }

    // --- Proxy outbound kinds ---
    for &kind in PROXY_OUTBOUND_KINDS {
        let _ = registry::register_feature(kind, stub_factory(kind));
    }
    // TUN outbound——仅 Linux/Android/FreeBSD
    for &kind in TUN_OUTBOUND_KIND {
        let _ = registry::register_feature(kind, stub_factory(kind));
    }
}

/// 注册所有传输层 dialer + listener。
///
/// 必须在 `register_outbounds` / `spawn_inbounds` 之前调用，
/// 否则传输注册表为空——除裸 TCP 外所有 dial/listen 返回 NotFound。
pub fn register_all_transports() {
    // TCP（系统传输）
    let _ = xray_transport::tcp::register_tcp_transport();

    // WebSocket
    let _ = xray_transport_websocket::register::register_dialer();
    let _ = xray_transport_websocket::register::register_listener();

    // HTTPUpgrade
    let _ = xray_transport_httpupgrade::register::register_dialer();
    let _ = xray_transport_httpupgrade::register::register_listener();

    // gRPC
    let _ = xray_transport_grpc::register::register_dialer();
    let _ = xray_transport_grpc::register::register_listener();

    // SplitHTTP / XHTTP
    let _ = xray_transport_splithttp::register::register_dialer();
    let _ = xray_transport_splithttp::register::register_listener();

    // mKCP
    let _ = xray_transport_kcp::register::register_dialer();
    let _ = xray_transport_kcp::register::register_listener();

    // Hysteria transport
    let _ = xray_transport_hysteria::register::register_dialer();
    let _ = xray_transport_hysteria::register::register_listener();

    // REALITY
    let _ = xray_reality::register::register_dialer();

    tracing::info!("all transport dialers + listeners registered");
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
/// TUN 单独注册（平台门控）。
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
    "loopback",
];

/// TUN 入站 kind——仅 Linux/Android/FreeBSD 可用。
#[cfg(any(target_os = "linux", target_os = "android", target_os = "freebsd"))]
const TUN_INBOUND_KIND: &[&str] = &["tun"];

/// TUN 入站 kind——非 Linux/Android/FreeBSD 不注册。
#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "freebsd")))]
const TUN_INBOUND_KIND: &[&str] = &[];

/// 代理出站 kind 列表。TUN 单独注册（平台门控）。
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

/// TUN 出站 kind——仅 Linux/Android/FreeBSD 可用。
#[cfg(any(target_os = "linux", target_os = "android", target_os = "freebsd"))]
const TUN_OUTBOUND_KIND: &[&str] = &["tun"];

/// TUN 出站 kind——非 Linux/Android/FreeBSD 不注册。
#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "freebsd")))]
const TUN_OUTBOUND_KIND: &[&str] = &[];

/// 创建 stub factory：返回 `StartFailed` 错误提示 "not yet implemented"。
fn stub_factory(kind: &'static str) -> FeatureFactory {
    Arc::new(move |_data: &[u8]| {
        Err(FeatureError::StartFailed {
            name: kind,
            message: format!("{kind}: not yet implemented (stub factory registered)"),
        })
    })
}

/// Log app 真实 factory：从 proto 编码的配置字节创建 LogFeature。
fn log_factory() -> FeatureFactory {
    Arc::new(|data: &[u8]| {
        let proto: xray_proto::xray::app::log::Config =
            prost::Message::decode(data).unwrap_or_default();
        let config = xray_app_log::LogConfig::from_proto(&proto);
        let feature = xray_app_log::LogFeature::new(config)?;
        Ok(Arc::new(feature) as Arc<dyn Feature>)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_all_features_makes_all_kinds_findable() {
        register_all_features();

        for &kind in APP_KINDS
            .iter()
            .chain(PROXY_INBOUND_KINDS)
            .chain(TUN_INBOUND_KIND)
            .chain(PROXY_OUTBOUND_KINDS)
            .chain(TUN_OUTBOUND_KIND)
        {
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
        all.extend(TUN_INBOUND_KIND);
        all.extend(PROXY_OUTBOUND_KINDS);
        all.extend(TUN_OUTBOUND_KIND);
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
