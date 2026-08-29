//! HealthPingSettings + HealthPingConfig + 默认值校验。
//!
//! 对应 Go `app/observatory/burst/healthping.go` 的 `HealthPingSettings` + `NewHealthPing`。

use crate::error::ObservatoryError;
use serde::{Deserialize, Serialize};
use xray_proto::xray::core::app::observatory::burst::HealthPingConfig as ProtoHealthPingConfig;

/// HealthPingConfig，对应 proto `HealthPingConfig`。
/// JSON 字段命名采用 camelCase 对齐 Go proto（`samplingCount` / `httpMethod`）。
/// 缺失字段用 `Default::default()`（空字符串 / 0）——proto 默认零值语义。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct HealthPingConfig {
    pub destination: String,
    pub connectivity: String,
    pub interval: i64,
    pub sampling_count: i32,
    pub timeout: i64,
    pub http_method: String,
}

impl HealthPingConfig {
    pub fn from_proto(p: &ProtoHealthPingConfig) -> Self {
        Self {
            destination: p.destination.clone(),
            connectivity: p.connectivity.clone(),
            interval: p.interval,
            sampling_count: p.sampling_count,
            timeout: p.timeout,
            http_method: p.http_method.clone(),
        }
    }

    pub fn to_proto(&self) -> ProtoHealthPingConfig {
        let mut out = ProtoHealthPingConfig::default();
        out.destination = self.destination.clone();
        out.connectivity = self.connectivity.clone();
        out.interval = self.interval;
        out.sampling_count = self.sampling_count;
        out.timeout = self.timeout;
        out.http_method = self.http_method.clone();
        out
    }
}

/// HealthPingSettings：从 proto 配置归一化的运行时设置。
///
/// 时间字段以纳秒为单位（与 Go time.Duration 兼容），便于跨语言一致。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthPingSettings {
    pub destination: String,
    pub connectivity: String,
    pub interval: i64,
    pub sampling_count: i32,
    pub timeout: i64,
    pub http_method: String,
}

/// 默认 destination（Chromium connectivity check 204 endpoint）。
pub const DEFAULT_DESTINATION: &str = "https://connectivitycheck.gstatic.com/generate_204";

/// 默认 interval（1 分钟，纳秒）。
pub const DEFAULT_INTERVAL_NANOS: i64 = 60_000_000_000;

/// 最小允许 interval（10 秒，纳秒）。
pub const MIN_INTERVAL_NANOS: i64 = 10_000_000_000;

/// 默认 sampling count。
pub const DEFAULT_SAMPLING_COUNT: i32 = 10;

/// 默认 timeout（5 秒，纳秒）。
pub const DEFAULT_TIMEOUT_NANOS: i64 = 5_000_000_000;

/// 默认 HTTP method。
pub const DEFAULT_HTTP_METHOD: &str = "HEAD";

impl Default for HealthPingSettings {
    fn default() -> Self {
        Self {
            destination: DEFAULT_DESTINATION.into(),
            connectivity: String::new(),
            interval: DEFAULT_INTERVAL_NANOS,
            sampling_count: DEFAULT_SAMPLING_COUNT,
            timeout: DEFAULT_TIMEOUT_NANOS,
            http_method: DEFAULT_HTTP_METHOD.into(),
        }
    }
}

impl HealthPingSettings {
    /// 从 proto HealthPingConfig 构造，应用默认值与最小约束。
    ///
    /// 对应 Go `NewHealthPing` 的 settings 归一化逻辑：
    /// - destination 空 → DEFAULT_DESTINATION
    /// - interval 0 → DEFAULT_INTERVAL_NANOS；< MIN → MIN
    /// - sampling_count <= 0 → DEFAULT_SAMPLING_COUNT
    /// - timeout <= 0 → DEFAULT_TIMEOUT_NANOS
    /// - http_method 空 → "HEAD"；非空 → trim
    pub fn from_config(config: Option<&HealthPingConfig>) -> Self {
        let mut s = Self::default();
        if let Some(c) = config {
            // destination
            let dest = c.destination.trim();
            if !dest.is_empty() {
                s.destination = dest.to_string();
            }
            // connectivity
            s.connectivity = c.connectivity.trim().to_string();
            // interval
            if c.interval != 0 {
                if c.interval < MIN_INTERVAL_NANOS {
                    s.interval = MIN_INTERVAL_NANOS;
                } else {
                    s.interval = c.interval;
                }
            }
            // sampling count
            if c.sampling_count > 0 {
                s.sampling_count = c.sampling_count;
            }
            // timeout
            if c.timeout > 0 {
                s.timeout = c.timeout;
            }
            // http method
            let m = c.http_method.trim();
            if !m.is_empty() {
                s.http_method = m.to_string();
            }
        }
        s
    }

    /// 校验配置自洽性。
    pub fn validate(&self) -> Result<(), ObservatoryError> {
        if self.sampling_count <= 0 {
            return Err(ObservatoryError::InvalidConfig(format!(
                "sampling_count must be > 0, got {}",
                self.sampling_count
            )));
        }
        if self.interval <= 0 {
            return Err(ObservatoryError::InvalidConfig(format!(
                "interval must be > 0, got {}",
                self.interval
            )));
        }
        if self.timeout <= 0 {
            return Err(ObservatoryError::InvalidConfig(format!(
                "timeout must be > 0, got {}",
                self.timeout
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_settings_have_defaults() {
        let s = HealthPingSettings::default();
        assert_eq!(s.destination, DEFAULT_DESTINATION);
        assert_eq!(s.interval, DEFAULT_INTERVAL_NANOS);
        assert_eq!(s.sampling_count, DEFAULT_SAMPLING_COUNT);
        assert_eq!(s.timeout, DEFAULT_TIMEOUT_NANOS);
        assert_eq!(s.http_method, DEFAULT_HTTP_METHOD);
        assert!(s.connectivity.is_empty());
    }

    #[test]
    fn from_config_none_uses_defaults() {
        let s = HealthPingSettings::from_config(None);
        let d = HealthPingSettings::default();
        assert_eq!(s, d);
    }

    #[test]
    fn from_config_empty_uses_defaults() {
        let c = HealthPingConfig::default();
        let s = HealthPingSettings::from_config(Some(&c));
        let d = HealthPingSettings::default();
        assert_eq!(s, d);
    }

    #[test]
    fn from_config_overrides_destination() {
        let mut c = HealthPingConfig::default();
        c.destination = "  https://custom.test  ".into();
        let s = HealthPingSettings::from_config(Some(&c));
        assert_eq!(s.destination, "https://custom.test");
    }

    #[test]
    fn from_config_empty_destination_keeps_default() {
        let mut c = HealthPingConfig::default();
        c.destination = "   ".into();
        let s = HealthPingSettings::from_config(Some(&c));
        assert_eq!(s.destination, DEFAULT_DESTINATION);
    }

    #[test]
    fn from_config_interval_zero_uses_default() {
        let mut c = HealthPingConfig::default();
        c.interval = 0;
        let s = HealthPingSettings::from_config(Some(&c));
        assert_eq!(s.interval, DEFAULT_INTERVAL_NANOS);
    }

    #[test]
    fn from_config_interval_below_min_clamped() {
        let mut c = HealthPingConfig::default();
        c.interval = 1_000; // 1us, way below MIN
        let s = HealthPingSettings::from_config(Some(&c));
        assert_eq!(s.interval, MIN_INTERVAL_NANOS);
    }

    #[test]
    fn from_config_interval_valid_kept() {
        let mut c = HealthPingConfig::default();
        c.interval = 120_000_000_000; // 2 min
        let s = HealthPingSettings::from_config(Some(&c));
        assert_eq!(s.interval, 120_000_000_000);
    }

    #[test]
    fn from_config_sampling_zero_uses_default() {
        let mut c = HealthPingConfig::default();
        c.sampling_count = 0;
        let s = HealthPingSettings::from_config(Some(&c));
        assert_eq!(s.sampling_count, DEFAULT_SAMPLING_COUNT);
    }

    #[test]
    fn from_config_sampling_valid_kept() {
        let mut c = HealthPingConfig::default();
        c.sampling_count = 20;
        let s = HealthPingSettings::from_config(Some(&c));
        assert_eq!(s.sampling_count, 20);
    }

    #[test]
    fn from_config_timeout_zero_uses_default() {
        let mut c = HealthPingConfig::default();
        c.timeout = 0;
        let s = HealthPingSettings::from_config(Some(&c));
        assert_eq!(s.timeout, DEFAULT_TIMEOUT_NANOS);
    }

    #[test]
    fn from_config_timeout_valid_kept() {
        let mut c = HealthPingConfig::default();
        c.timeout = 10_000_000_000; // 10s
        let s = HealthPingSettings::from_config(Some(&c));
        assert_eq!(s.timeout, 10_000_000_000);
    }

    #[test]
    fn from_config_http_method_empty_uses_default() {
        let mut c = HealthPingConfig::default();
        c.http_method = "".into();
        let s = HealthPingSettings::from_config(Some(&c));
        assert_eq!(s.http_method, "HEAD");
    }

    #[test]
    fn from_config_http_method_trimmed() {
        let mut c = HealthPingConfig::default();
        c.http_method = "  GET  ".into();
        let s = HealthPingSettings::from_config(Some(&c));
        assert_eq!(s.http_method, "GET");
    }

    #[test]
    fn from_config_connectivity_trimmed() {
        let mut c = HealthPingConfig::default();
        c.connectivity = "  https://c.test  ".into();
        let s = HealthPingSettings::from_config(Some(&c));
        assert_eq!(s.connectivity, "https://c.test");
    }

    #[test]
    fn validate_passes_for_default() {
        let s = HealthPingSettings::default();
        assert!(s.validate().is_ok());
    }

    #[test]
    fn validate_fails_for_zero_sampling() {
        let mut s = HealthPingSettings::default();
        s.sampling_count = 0;
        assert!(s.validate().is_err());
    }

    #[test]
    fn validate_fails_for_negative_sampling() {
        let mut s = HealthPingSettings::default();
        s.sampling_count = -1;
        assert!(s.validate().is_err());
    }

    #[test]
    fn validate_fails_for_zero_interval() {
        let mut s = HealthPingSettings::default();
        s.interval = 0;
        assert!(s.validate().is_err());
    }

    #[test]
    fn validate_fails_for_zero_timeout() {
        let mut s = HealthPingSettings::default();
        s.timeout = 0;
        assert!(s.validate().is_err());
    }

    #[test]
    fn config_proto_roundtrip() {
        let c = HealthPingConfig {
            destination: "d".into(),
            connectivity: "c".into(),
            interval: 60_000_000_000,
            sampling_count: 10,
            timeout: 5_000_000_000,
            http_method: "GET".into(),
        };
        let p = c.to_proto();
        assert_eq!(HealthPingConfig::from_proto(&p), c);
    }
}
