//! App 配置类型安全化：将 `serde_json::Value` 占位替换为强类型 struct。
//!
//! 对应 Go `infra/conf` 各 app 子包。

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// =========================================================================
// Log
// =========================================================================

/// 日志配置，对应 Go `infra/conf.LogConfig`。
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct LogConfig {
    /// 日志级别：`debug` / `info` / `warning` / `error` / `none`。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loglevel: Option<String>,
    /// Access log 文件路径，空字符串表示不记录。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access: Option<String>,
    /// Error log 文件路径。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// =========================================================================
// Policy
// =========================================================================

/// 单个级别的策略限制。
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PolicyLevel {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handshake: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conn_idle: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uplink: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub downlink: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub buffer_size: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats_user_uplink: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats_user_downlink: Option<bool>,
}

/// 系统级策略。
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PolicySystem {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats_inbound_uplink: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats_inbound_downlink: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats_outbound_uplink: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats_outbound_downlink: Option<bool>,
}

/// 策略配置，对应 Go `infra/conf.PolicyConfig`。
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PolicyConfig {
    /// 级别 → 策略。key 是数字字符串（`"0"`..`"9"`）。
    #[serde(default)]
    pub levels: HashMap<String, PolicyLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<PolicySystem>,
}

// =========================================================================
// Observatory
// =========================================================================

/// 观测器配置，对应 Go `infra/conf.ObservatoryConfig`。
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ObservatoryConfig {
    /// 被探测的 outbound tag（可选，默认首个）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_outbound: Option<String>,
    /// 探测 URL。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub probe_url: Option<String>,
    /// 探测间隔（Go duration 字符串，如 `"1m"`）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub probe_interval: Option<String>,
    /// 探测超时。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub probe_timeout: Option<String>,
}

/// 突发观测器配置。
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct BurstObservatoryConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_outbound: Option<String>,
    /// ping 探测配置。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ping_config: Option<Value>,
}

// =========================================================================
// Metrics / Stats / Version / Geodata / API
// =========================================================================

/// Metrics 配置。
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct MetricsConfig {
    /// Prometheus 监听地址（如 `"127.0.0.1:9100"`）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen: Option<String>,
    /// 是否在 metrics 中包含 tag 标签。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
}

/// Stats 配置（空 — 存在即启用）。
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct StatsConfig {}

/// 版本声明。
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct VersionConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// Geodata 加载配置。
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct GeodataConfig {
    /// 国家代码匹配器（`regex` / `domain` / `ip`）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// 数据目录。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dir: Option<String>,
}

/// API 配置。
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ApiConfig {
    /// API handler tag。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    /// gRPC 监听地址（如 `"127.0.0.1:8080"` / `":8080"`）。
    ///
    /// 对应 Go proto `xray.app.commander.Config.Listen`。为空时走 outbound 模式
    ///（通过 OutboundHandler 接收 API 连接，需 transport 全链路）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen: Option<String>,
    /// 启用的 API 服务列表。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub services: Option<Vec<String>>,
}

// =========================================================================
// FakeDNS
// =========================================================================

/// FakeDNS 配置。
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct FakeDnsConfig {
    /// IP 池（CIDR，如 `"198.18.0.0/15"`）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_pool: Option<String>,
    /// 池大小。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pool_size: Option<u32>,
}

// 保持 serde_json::Value 作为 re-export，供 BurstObservatoryConfig::ping_config 等使用
pub use serde_json::Value;
