//! 顶层配置类型：`Config` / `InboundDetourConfig` / `OutboundDetourConfig` /
//! `SniffingConfig` / `MuxConfig`。
//!
//! 对应 Go `infra/conf/xray.go`。切片 1 的策略：各 app（log/routing/dns/policy...）
//! 的具体配置类型尚未实现，先用 [`serde_json::Value`] 占位 —— 这样能完整解析任意
//! Xray 配置文件而不依赖未实现的子 crate。后续各 app crate 完成后，逐步把 `Value`
//! 替换为强类型字段。

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::common::{Address, PortList, StringList};

// =========================================================================
// Config —— 顶层配置
// =========================================================================

/// 顶层 Xray 配置，对应 Go `infra/conf.Config`。
///
/// 所有字段均可选（`#[serde(default)]`）；未知字段默认忽略以兼容前向兼容。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// 日志配置。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log: Option<crate::app_config::LogConfig>,

    /// 路由配置（占位，待 `xray-app-router` 强类型化）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routing: Option<Value>,

    /// DNS 配置（占位，待 `xray-app-dns` 强类型化）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<Value>,

    /// 策略配置。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<crate::app_config::PolicyConfig>,

    /// API 配置。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api: Option<crate::app_config::ApiConfig>,

    /// Metrics 配置。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics: Option<crate::app_config::MetricsConfig>,

    /// 统计配置。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats: Option<crate::app_config::StatsConfig>,

    /// 顶层反向代理配置（Go v26 已移除该 feature）。保留字段以便
    /// `build()` 给出与 Go 对齐的 removed 错误而非静默吞掉。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reverse: Option<Value>,

    /// FakeDNS 配置。JSON tag 是 camelCase `fakeDns`。
    #[serde(rename = "fakeDns", skip_serializing_if = "Option::is_none")]
    pub fake_dns: Option<crate::app_config::FakeDnsConfig>,

    /// 观测器配置。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observatory: Option<crate::app_config::ObservatoryConfig>,

    /// 突发观测器配置。JSON tag 是 camelCase `burstObservatory`。
    #[serde(rename = "burstObservatory", skip_serializing_if = "Option::is_none")]
    pub burst_observatory: Option<crate::app_config::BurstObservatoryConfig>,

    /// 版本声明配置。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<crate::app_config::VersionConfig>,

    /// Geodata 配置。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geodata: Option<crate::app_config::GeodataConfig>,

    /// 旧式全局 transport 配置（Go 中已废弃，Build 时报错指引迁移到 streamSettings）。
    /// 保留字段以便给出精确错误而非静默吞掉。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<HashMap<String, Value>>,

    /// 环境变量注入配置，对应 Go `EnvConfig`（xray.go:383）。
    /// Build 时逐 key 注入进程环境（xray.go:532-536），供 `env:VAR` 值展开使用。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<HashMap<String, String>>,

    /// 入站配置列表。JSON tag 为 `"inbounds"`。
    #[serde(rename = "inbounds")]
    pub inbound_configs: Vec<InboundDetourConfig>,

    /// 出站配置列表。JSON tag 为 `"outbounds"`。
    #[serde(rename = "outbounds")]
    pub outbound_configs: Vec<OutboundDetourConfig>,
}

impl Config {
    /// 从 JSON 字符串解析（strict 模式，无注释容忍）。
    pub fn from_json_str(s: &str) -> Result<Self, crate::error::ConfError> {
        crate::json::decode_json_strict(s.as_bytes())
    }

    /// 入站数量。
    pub fn inbound_count(&self) -> usize {
        self.inbound_configs.len()
    }

    /// 出站数量。
    pub fn outbound_count(&self) -> usize {
        self.outbound_configs.len()
    }

    /// 按 tag 查找入站。
    pub fn find_inbound(&self, tag: &str) -> Option<&InboundDetourConfig> {
        self.inbound_configs.iter().find(|i| i.tag == tag)
    }

    /// 按 tag 查找出站。
    pub fn find_outbound(&self, tag: &str) -> Option<&OutboundDetourConfig> {
        self.outbound_configs.iter().find(|o| o.tag == tag)
    }

    /// 是否使用了已废弃的全局 transport 字段（Build 时用于触发迁移错误）。
    pub fn uses_deprecated_transport(&self) -> bool {
        self.transport.as_ref().map(|m| !m.is_empty()).unwrap_or(false)
    }
}

// =========================================================================
// InboundDetourConfig —— 入站配置
// =========================================================================

/// 入站配置，对应 Go `infra/conf.InboundDetourConfig`。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct InboundDetourConfig {
    /// 协议名：vless / vmess / trojan / shadowsocks / socks / http / freedom / ...
    pub protocol: String,

    /// 监听端口列表（支持 `80` / `"80,443"` / `"1000-2000"` 等多种格式）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<PortList>,

    /// 监听地址（IP / Domain / Unix socket 路径）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen: Option<Address>,

    /// 协议特定 settings（占位，由各 `xray-proxy-*` crate 定义强类型）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settings: Option<Value>,

    /// 入站 tag，路由匹配用。
    pub tag: String,

    /// 流设置（TLS/WS/gRPC/Reality 等传输层配置）。占位。
    #[serde(rename = "streamSettings", skip_serializing_if = "Option::is_none")]
    pub stream_settings: Option<Value>,

    /// 流量嗅探配置。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sniffing: Option<SniffingConfig>,
}

// =========================================================================
// OutboundDetourConfig —— 出站配置
// =========================================================================

/// 出站配置，对应 Go `infra/conf.OutboundDetourConfig`。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OutboundDetourConfig {
    /// 协议名。
    pub protocol: String,

    /// 发送绑定的本端 IP（Go 是 *string，可选）。
    #[serde(rename = "sendThrough", skip_serializing_if = "Option::is_none")]
    pub send_through: Option<String>,

    /// 出站 tag，路由匹配与链式代理用。
    pub tag: String,

    /// 协议特定 settings（占位）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settings: Option<Value>,

    /// 流设置。占位。
    #[serde(rename = "streamSettings", skip_serializing_if = "Option::is_none")]
    pub stream_settings: Option<Value>,

    /// 链式代理（通过另一出站转发）。占位。
    #[serde(rename = "proxySettings", skip_serializing_if = "Option::is_none")]
    pub proxy_settings: Option<Value>,

    /// Mux 多路复用设置。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mux: Option<MuxConfig>,

    /// 出站选择策略（Go 中字段 `TargetStrategy`，JSON tag `targetStrategy`）。
    #[serde(rename = "targetStrategy", skip_serializing_if = "Option::is_none")]
    pub target_strategy: Option<String>,
}

// =========================================================================
// SniffingConfig —— 流量嗅探
// =========================================================================

/// 流量嗅探配置，对应 Go `infra/conf.SniffingConfig`。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SniffingConfig {
    /// 是否启用嗅探。
    pub enabled: bool,

    /// 命中时覆盖目标协议：`["http", "tls", "quic", "fakedns"]`。
    #[serde(rename = "destOverride")]
    pub dest_override: StringList,

    /// 排除的域名（不嗅探）。
    #[serde(rename = "domainsExcluded")]
    pub domains_excluded: StringList,

    /// 排除的 IP（不嗅探）。
    #[serde(rename = "ipsExcluded")]
    pub ips_excluded: StringList,

    /// 仅填充 metadata，不覆盖目标。
    #[serde(rename = "metadataOnly")]
    pub metadata_only: bool,

    /// 仅路由用，不修改目标地址。
    #[serde(rename = "routeOnly")]
    pub route_only: bool,
}

// =========================================================================
// MuxConfig —— 多路复用
// =========================================================================

/// Mux 多路复用配置，对应 Go `infra/conf.MuxConfig`。
///
/// Go 的 Build 会把空的 `XudpProxyUDP443` 改成 `"reject"`，并校验枚举值。
/// 切片 1 仅保留原值，校验留给后续 Build 阶段。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MuxConfig {
    /// 是否启用 Mux。
    pub enabled: bool,

    /// 并发连接数（< 0 表示完全禁用 mux）。
    pub concurrency: i16,

    /// XUDP 并发数。
    #[serde(rename = "xudpConcurrency")]
    pub xudp_concurrency: i16,

    /// XUDP 代理 UDP 443 端口的策略：`"reject"` / `"allow"` / `"skip"`。
    /// 空串等价 `"reject"`（由 Build 阶段处理）。
    #[serde(rename = "xudpProxyUDP443")]
    pub xudp_proxy_udp_443: String,
}

// =========================================================================
// 测试
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL_CONFIG: &str = r#"{
        "inbounds": [
            {
                "protocol": "vless",
                "port": 443,
                "listen": "0.0.0.0",
                "settings": { "clients": [] },
                "tag": "vless-in",
                "streamSettings": { "network": "tcp" },
                "sniffing": {
                    "enabled": true,
                    "destOverride": ["http", "tls"]
                }
            }
        ],
        "outbounds": [
            {
                "protocol": "freedom",
                "tag": "direct"
            },
            {
                "protocol": "vless",
                "tag": "proxy",
                "settings": { "vnext": [] },
                "mux": { "enabled": true, "concurrency": 8 }
            }
        ],
        "routing": { "rules": [] },
        "log": { "loglevel": "warning" }
    }"#;

    #[test]
    fn parse_minimal_config() {
        let cfg = Config::from_json_str(MINIMAL_CONFIG).expect("minimal config should parse");
        assert_eq!(cfg.inbound_count(), 1);
        assert_eq!(cfg.outbound_count(), 2);
        assert!(cfg.log.is_some());
        assert!(cfg.routing.is_some());
        assert!(cfg.dns.is_none());
    }

    #[test]
    fn inbound_fields_populated() {
        let cfg = Config::from_json_str(MINIMAL_CONFIG).unwrap();
        let inbound = cfg.find_inbound("vless-in").expect("inbound exists");
        assert_eq!(inbound.protocol, "vless");
        assert_eq!(inbound.port.as_ref().unwrap().0, vec![crate::common::PortRange::single(443)]);
        assert_eq!(inbound.listen.as_ref().unwrap().as_str(), "0.0.0.0");
        assert!(inbound.settings.is_some());
        assert!(inbound.stream_settings.is_some());
        let sniffing = inbound.sniffing.as_ref().unwrap();
        assert!(sniffing.enabled);
        assert_eq!(sniffing.dest_override.0, vec!["http".to_string(), "tls".to_string()]);
    }

    #[test]
    fn outbound_mux_parsed() {
        let cfg = Config::from_json_str(MINIMAL_CONFIG).unwrap();
        let proxy = cfg.find_outbound("proxy").unwrap();
        assert_eq!(proxy.protocol, "vless");
        let mux = proxy.mux.as_ref().unwrap();
        assert!(mux.enabled);
        assert_eq!(mux.concurrency, 8);
    }

    #[test]
    fn empty_config_uses_defaults() {
        let cfg: Config = serde_json::from_str("{}").unwrap();
        assert!(cfg.inbound_configs.is_empty());
        assert!(cfg.outbound_configs.is_empty());
        assert!(cfg.log.is_none());
    }

    #[test]
    fn camel_case_tags_match() {
        // fakeDns / burstObservatory 是 camelCase JSON tag，必须正确映射。
        let json = r#"{
            "fakeDns": { "pools": [] },
            "burstObservatory": { "subjectSelector": ["p1"] }
        }"#;
        let cfg: Config = serde_json::from_str(json).unwrap();
        assert!(cfg.fake_dns.is_some());
        assert!(cfg.burst_observatory.is_some());
    }

    #[test]
    fn deprecated_transport_detected() {
        let json = r#"{ "transport": { "http": { "path": "/x" } } }"#;
        let cfg: Config = serde_json::from_str(json).unwrap();
        assert!(cfg.uses_deprecated_transport());
    }

    #[test]
    fn unknown_fields_ignored() {
        // 前向兼容：未知字段不应导致解析失败。
        let json = r#"{ "futureField": 42, "inbounds": [] }"#;
        let cfg: Config = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.inbound_count(), 0);
    }

    #[test]
    fn find_inbound_and_outbound_by_tag() {
        let cfg = Config::from_json_str(MINIMAL_CONFIG).unwrap();
        assert!(cfg.find_inbound("vless-in").is_some());
        assert!(cfg.find_inbound("nonexistent").is_none());
        assert!(cfg.find_outbound("direct").is_some());
        assert!(cfg.find_outbound("proxy").is_some());
    }

    #[test]
    fn config_serializes_without_panic() {
        // PortList Serialize 已对齐 Go dump 形式（数字/逗号区间串），与
        // Deserialize 对称（round-trip 见 serial::tests）。此处验证整份
        // Config serialize 不 panic 且保留关键字段。
        let cfg = Config::from_json_str(MINIMAL_CONFIG).unwrap();
        let serialized = serde_json::to_string(&cfg).expect("serialize must succeed");
        assert!(!serialized.is_empty());
        assert!(serialized.contains("vless"));
        assert!(serialized.contains("freedom"));
    }
    #[test]
    fn env_parses_from_json() {
        // Go EnvConfig = map[string]string（xray.go:383），顶层 json tag "env"（:396）。
        let cfg = Config::from_json_str(r#"{ "env": { "XRAY_ENV_A": "1", "XRAY_ENV_B": "x y" } }"#)
            .unwrap();
        let env = cfg.env.expect("env must parse");
        assert_eq!(env.get("XRAY_ENV_A").map(String::as_str), Some("1"));
        assert_eq!(env.get("XRAY_ENV_B").map(String::as_str), Some("x y"));

        // 缺省：None。
        let cfg: Config = serde_json::from_str("{}").unwrap();
        assert!(cfg.env.is_none());
    }
}
