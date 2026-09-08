//! App 配置类型安全化：将 `serde_json::Value` 占位替换为强类型 struct。
//!
//! 对应 Go `infra/conf` 各 app 子包。

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// =========================================================================
// Log
// =========================================================================

/// 日志配置，对应 Go `infra/conf.LogConfig`（json 字段：loglevel/access/error/
/// dnsLog/maskAddress；`format` 为 Rust 扩展——Go v26.6.1 无此字段）。
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct LogConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loglevel: Option<String>,
    /// Access log：文件路径，`"none"` 关闭，空（未配置）= console。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access: Option<String>,
    /// Error log：文件路径，`"none"` 关闭，空（未配置）= console。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// DNS 查询日志开关（Go json `dnsLog`）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_log: Option<bool>,
    /// 日志 IP 掩码：`"half"` / `"quarter"` / `"full"` 等（Go json `maskAddress`）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mask_address: Option<String>,
    /// 输出格式：`"json"` / `"console"`（Rust 扩展）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
}

// =========================================================================
// Policy
// =========================================================================

/// 单个级别的策略限制。
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct PolicyLevel {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handshake: Option<u32>,
    /// Go json `connIdle`（Rust 方言 `conn_idle` 别名保留）。
    #[serde(skip_serializing_if = "Option::is_none", alias = "conn_idle")]
    pub conn_idle: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uplink: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub downlink: Option<u32>,
    /// Per-connection 缓冲，KB 单位；负值（如 -1）= 无限制。
    /// Go 语义见 infra/conf/policy.go:42-50（×1024 转字节，负值 → proto -1）。
    #[serde(alias = "buffer_size")]
    pub buffer_size: Option<i32>,
    /// Go json `statsUserUplink`（Rust 方言 `stats_user_uplink` 别名保留）。
    #[serde(skip_serializing_if = "Option::is_none", alias = "stats_user_uplink")]
    pub stats_user_uplink: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none", alias = "stats_user_downlink")]
    pub stats_user_downlink: Option<bool>,
    /// 是否启用 per-user 在线 IP 追踪。对应 Go json `statsUserOnline`。
    #[serde(skip_serializing_if = "Option::is_none", alias = "stats_user_online")]
    pub stats_user_online: Option<bool>,
}

/// 系统级策略。
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct PolicySystem {
    #[serde(skip_serializing_if = "Option::is_none", alias = "stats_inbound_uplink")]
    pub stats_inbound_uplink: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none", alias = "stats_inbound_downlink")]
    pub stats_inbound_downlink: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none", alias = "stats_outbound_uplink")]
    pub stats_outbound_uplink: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none", alias = "stats_outbound_downlink")]
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
#[serde(default, rename_all = "camelCase")]
pub struct ObservatoryConfig {
    /// 被探测的 outbound tag（可选，默认首个）。
    /// Go json `subjectSelector` 是 tag 列表（语义不同，见 register.rs 消费）；此处为 Rust 单值方言。
    #[serde(skip_serializing_if = "Option::is_none", alias = "subject_outbound")]
    pub subject_outbound: Option<String>,
    /// 探测 URL。Go json 键为 `probeURL`（大写 URL）。
    #[serde(
        rename = "probeURL",
        alias = "probe_url",
        alias = "probeUrl",
        skip_serializing_if = "Option::is_none"
    )]
    pub probe_url: Option<String>,
    /// 探测间隔（Go duration 字符串，如 `"1m"`）。
    #[serde(skip_serializing_if = "Option::is_none", alias = "probe_interval")]
    pub probe_interval: Option<String>,
}

/// 突发观测器配置。
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct BurstObservatoryConfig {
    #[serde(skip_serializing_if = "Option::is_none", alias = "subject_outbound")]
    pub subject_outbound: Option<String>,
    /// ping 探测配置。
    #[serde(skip_serializing_if = "Option::is_none", alias = "ping_config")]
    pub ping_config: Option<Value>,
}

// =========================================================================
// Metrics / Stats / Version / Geodata / API
// =========================================================================

/// Metrics 配置。
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
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

/// 版本声明（对应 Go `infra/conf/version.go:10-13` `VersionConfig`）。
///
/// Go 字段：
/// ```text
/// type VersionConfig struct {
///     MinVersion string `json:"min"`
///     MaxVersion string `json:"max"`
/// }
/// ```
///
/// Rust 端当前为死字段（仅 `Config.version: Option<VersionConfig>` 一处定义，
/// xray-app-version 已实现但 Instance 装配未注册）——保留形状对齐 Go，等
/// 后续 batch 接入 `xray_app_version::Version::new` 即可生效（`coreVersion`
/// 取自 `core.Version_x/y/z`，`min/max` 为运行期约束）。
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct VersionConfig {
    /// 最低支持的核心版本（含），Go `MinVersion`。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min: Option<String>,
    /// 最高支持的核心版本（含），Go `MaxVersion`。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max: Option<String>,
}

/// Geodata 加载配置。对应 Go `infra/conf.GeodataConfig`（geodata.go:42-46）。
///
/// Go 字段：
/// ```text
/// type GeodataConfig struct {
///     Cron     *string               `json:"cron"`
///     Outbound string                `json:"outbound"`
///     Assets   []*GeodataAssetConfig `json:"assets"`
/// }
/// ```
///
/// Rust 端 `assets` 序列化为对象数组（url/file），由装配层送入
/// `xray_app_geodata::instance::GeodataConfig`（register.rs:691-703）。
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct GeodataConfig {
    /// 定时表达式（标准 cron 5 段格式；非空时按表达式自动 reload）。
    /// 对应 Go `Cron *string`（geodata.go:43）；Rust 端为可空字符串，
    /// 空 / 缺省 = 仅手动 reload，调度器不启动。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cron: Option<String>,
    /// 用于下载 assets 的 outbound tag。对应 Go `Outbound string`（geodata.go:44）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outbound: Option<String>,
    /// 待加载/定时更新的资源列表。对应 Go `Assets []*GeodataAssetConfig`。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assets: Option<Vec<GeodataAssetConfig>>,
}

/// 单个 geodata 资源。对应 Go `infra/conf.GeodataAssetConfig`（geodata.go:13-16）。
#[derive(Debug, Default, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(default, rename_all = "camelCase")]
pub struct GeodataAssetConfig {
    /// 下载 URL（http/https）。对应 Go `URL string`。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// 本地文件名（`asset_dir` 下）。对应 Go `File string`。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
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
#[serde(default, rename_all = "camelCase")]
pub struct FakeDnsConfig {
    /// IP 池（CIDR，如 `"198.18.0.0/15"`）。Go json `ipPool`（Rust 方言 `ip_pool` 别名保留）。
    #[serde(skip_serializing_if = "Option::is_none", alias = "ip_pool")]
    pub ip_pool: Option<String>,
    /// 池大小。Go json `poolSize`（Rust 方言 `pool_size` 别名保留）。
    #[serde(skip_serializing_if = "Option::is_none", alias = "pool_size")]
    pub pool_size: Option<u32>,
}

// 保持 serde_json::Value 作为 re-export，供 BurstObservatoryConfig::ping_config 等使用
pub use serde_json::Value;

#[cfg(test)]
mod tests {
    use super::*;

    /// Go 标准 camelCase 键生效（policy levels/system）。
    #[test]
    fn policy_go_camel_case_keys() {
        let c: PolicyConfig = serde_json::from_value(serde_json::json!({
            "levels": {"0": {
                "handshake": 4, "connIdle": 300, "bufferSize": 512,
                "statsUserUplink": true, "statsUserDownlink": true, "statsUserOnline": true
            }},
            "system": {"statsInboundUplink": true, "statsOutboundDownlink": true}
        }))
        .unwrap();
        let l = &c.levels["0"];
        assert_eq!(l.handshake, Some(4));
        assert_eq!(l.conn_idle, Some(300));
        assert_eq!(l.buffer_size, Some(512));
        assert_eq!(l.stats_user_uplink, Some(true));
        assert_eq!(l.stats_user_online, Some(true));
        let sys = c.system.as_ref().unwrap();
        assert_eq!(sys.stats_inbound_uplink, Some(true));
        assert_eq!(sys.stats_outbound_downlink, Some(true));
    }

    /// 旧 Rust snake_case 方言键仍可解析（alias 双读）。
    #[test]
    fn policy_legacy_snake_keys_still_parse() {
        let c: PolicyConfig = serde_json::from_value(serde_json::json!({
            "levels": {"0": {"conn_idle": 300, "buffer_size": 512, "stats_user_online": true}},
            "system": {"stats_inbound_uplink": true}
        }))
        .unwrap();
        let l = &c.levels["0"];
        assert_eq!(l.conn_idle, Some(300));
        assert_eq!(l.buffer_size, Some(512));
        assert_eq!(l.stats_user_online, Some(true));
        assert_eq!(c.system.unwrap().stats_inbound_uplink, Some(true));
    }

    /// observatory：Go 键 `probeURL`（大写 URL）+ 旧键 `probe_url` 双读；
    /// 序列化输出 Go 键。
    #[test]
    fn observatory_probe_url_dual_read_and_go_serialization() {
        let go: ObservatoryConfig =
            serde_json::from_value(serde_json::json!({"probeURL": "https://x/204", "probeInterval": "1m"}))
                .unwrap();
        assert_eq!(go.probe_url.as_deref(), Some("https://x/204"));
        assert_eq!(go.probe_interval.as_deref(), Some("1m"));
        let legacy: ObservatoryConfig =
            serde_json::from_value(serde_json::json!({"probe_url": "https://y/204"})).unwrap();
        assert_eq!(legacy.probe_url.as_deref(), Some("https://y/204"));
        let serde_camel: ObservatoryConfig =
            serde_json::from_value(serde_json::json!({"probeUrl": "https://z/204"})).unwrap();
        assert_eq!(serde_camel.probe_url.as_deref(), Some("https://z/204"));
        // probe_timeout 已删（Go ObservatoryConfig 无此字段）：未知字段被忽略
        let with_dead: ObservatoryConfig =
            serde_json::from_value(serde_json::json!({"probeTimeout": "5s"})).unwrap();
        assert_eq!(with_dead.probe_url, None);
        // 序列化主键 = Go 标准
        let out = serde_json::to_value(&go).unwrap();
        assert!(out.get("probeURL").is_some());
    }

    /// burstObservatory：subjectOutbound + pingConfig（camelCase 主键 + snake 别名）。
    #[test]
    fn burst_observatory_camel_and_snake() {
        let go: BurstObservatoryConfig = serde_json::from_value(serde_json::json!({
            "subjectOutbound": "p1", "pingConfig": {"destination": "https://x"}
        }))
        .unwrap();
        assert_eq!(go.subject_outbound.as_deref(), Some("p1"));
        assert!(go.ping_config.is_some());
        let legacy: BurstObservatoryConfig = serde_json::from_value(serde_json::json!({
            "subject_outbound": "p1", "ping_config": {"destination": "https://x"}
        }))
        .unwrap();
        assert_eq!(legacy.subject_outbound.as_deref(), Some("p1"));
    }

    /// fakeDns：Go 键 ipPool/poolSize 生效 + 旧键兼容 + 序列化输出 Go 键。
    #[test]
    fn fakedns_go_keys_and_legacy_alias() {
        let go: FakeDnsConfig = serde_json::from_value(serde_json::json!({
            "ipPool": "198.18.0.0/15", "poolSize": 65535
        }))
        .unwrap();
        assert_eq!(go.ip_pool.as_deref(), Some("198.18.0.0/15"));
        assert_eq!(go.pool_size, Some(65535));
        let legacy: FakeDnsConfig = serde_json::from_value(serde_json::json!({
            "ip_pool": "198.18.0.0/15", "pool_size": 12345
        }))
        .unwrap();
        assert_eq!(legacy.ip_pool.as_deref(), Some("198.18.0.0/15"));
        assert_eq!(legacy.pool_size, Some(12345));
        let out = serde_json::to_value(&go).unwrap();
        assert_eq!(out["ipPool"], "198.18.0.0/15");
        assert_eq!(out["poolSize"], 65535);
    }

    /// version: Go 键 min/max（infra/conf/version.go:10-13）+ 序列化输出 Go 键。
    #[test]
    fn version_config_min_max_shape() {
        // Go 形态 {"min": "...", "max": "..."} 双读正确。
        let c: VersionConfig =
            serde_json::from_value(serde_json::json!({"min": "1.8.0", "max": "26.9.9"}))
                .unwrap();
        assert_eq!(c.min.as_deref(), Some("1.8.0"));
        assert_eq!(c.max.as_deref(), Some("26.9.9"));
        // 只给 min / 只给 max 都应通过。
        let only_min: VersionConfig =
            serde_json::from_value(serde_json::json!({"min": "1.8.0"})).unwrap();
        assert_eq!(only_min.min.as_deref(), Some("1.8.0"));
        assert!(only_min.max.is_none());
        let only_max: VersionConfig =
            serde_json::from_value(serde_json::json!({"max": "26.9.9"})).unwrap();
        assert!(only_max.min.is_none());
        assert_eq!(only_max.max.as_deref(), Some("26.9.9"));
        // 序列化输出 Go 主键（min/max），无 alias 泄漏。
        let out = serde_json::to_value(&c).unwrap();
        assert_eq!(out["min"], "1.8.0");
        assert_eq!(out["max"], "26.9.9");
    }

    /// geodata: Go 键 cron / outbound / assets（infra/conf/geodata.go:42-46）
    /// + 序列化输出 Go 键 + 旧 Rust 字段（code/dir）不再识别。
    #[test]
    fn geodata_go_cron_outbound_assets_shape() {
        let c: GeodataConfig = serde_json::from_value(serde_json::json!({
            "cron": "0 */6 * * *",
            "outbound": "direct",
            "assets": [
                {"url": "https://github.com/.../geoip.dat", "file": "geoip.dat"},
                {"url": "https://github.com/.../geosite.dat", "file": "geosite.dat"}
            ]
        }))
        .unwrap();
        assert_eq!(c.cron.as_deref(), Some("0 */6 * * *"));
        assert_eq!(c.outbound.as_deref(), Some("direct"));
        let assets = c.assets.as_ref().expect("assets");
        assert_eq!(assets.len(), 2);
        assert_eq!(assets[0].url.as_deref(), Some("https://github.com/.../geoip.dat"));
        assert_eq!(assets[0].file.as_deref(), Some("geoip.dat"));
        assert_eq!(assets[1].file.as_deref(), Some("geosite.dat"));
        // 序列化输出 Go 键。
        let out = serde_json::to_value(&c).unwrap();
        assert_eq!(out["cron"], "0 */6 * * *");
        assert_eq!(out["outbound"], "direct");
        assert_eq!(out["assets"][0]["url"], "https://github.com/.../geoip.dat");
        assert_eq!(out["assets"][0]["file"], "geoip.dat");
    }

    /// geodata: 缺省 = None（仅手动 reload，调度器不启动）。
    #[test]
    fn geodata_default_is_all_none() {
        let c: GeodataConfig = serde_json::from_value(serde_json::json!({})).unwrap();
        assert!(c.cron.is_none());
        assert!(c.outbound.is_none());
        assert!(c.assets.is_none());
    }
}
