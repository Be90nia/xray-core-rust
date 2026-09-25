//! xray-app-observatory 配置 + 数据结构。
//!
//! 对应 proto `xray.core.app.observatory.{ObservationResult, OutboundStatus, ProbeResult, Config}`
//! + `xray.core.app.observatory.burst.HealthPingMeasurementResult`。

use xray_proto::xray::core::app::observatory::{
    Config as ProtoConfig, HealthPingMeasurementResult as ProtoHealthPing,
    ObservationResult as ProtoObservationResult, OutboundStatus as ProtoOutboundStatus,
    ProbeResult as ProtoProbeResult,
};

/// 健康测量统计（对应 proto HealthPingMeasurementResult）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HealthPingMeasurement {
    pub all: i64,
    pub fail: i64,
    pub deviation: i64,
    pub average: i64,
    pub max: i64,
    pub min: i64,
}

impl HealthPingMeasurement {
    pub fn from_proto(p: &ProtoHealthPing) -> Self {
        Self {
            all: p.all,
            fail: p.fail,
            deviation: p.deviation,
            average: p.average,
            max: p.max,
            min: p.min,
        }
    }

    pub fn to_proto(&self) -> ProtoHealthPing {
        let mut out = ProtoHealthPing::default();
        out.all = self.all;
        out.fail = self.fail;
        out.deviation = self.deviation;
        out.average = self.average;
        out.max = self.max;
        out.min = self.min;
        out
    }
}

/// OutboundStatus：单个 outbound 的观测状态（对应 proto）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OutboundStatus {
    pub alive: bool,
    pub delay: i64,
    pub last_error_reason: String,
    pub outbound_tag: String,
    pub last_seen_time: i64,
    pub last_try_time: i64,
    pub health_ping: Option<HealthPingMeasurement>,
}

impl OutboundStatus {
    pub fn from_proto(p: &ProtoOutboundStatus) -> Self {
        Self {
            alive: p.alive,
            delay: p.delay,
            last_error_reason: p.last_error_reason.clone(),
            outbound_tag: p.outbound_tag.clone(),
            last_seen_time: p.last_seen_time,
            last_try_time: p.last_try_time,
            health_ping: if p.health_ping.is_some() {
                Some(HealthPingMeasurement::from_proto(p.health_ping.as_ref().unwrap()))
            } else {
                None
            },
        }
    }

    pub fn to_proto(&self) -> ProtoOutboundStatus {
        let mut out = ProtoOutboundStatus::default();
        out.alive = self.alive;
        out.delay = self.delay;
        out.last_error_reason = self.last_error_reason.clone();
        out.outbound_tag = self.outbound_tag.clone();
        out.last_seen_time = self.last_seen_time;
        out.last_try_time = self.last_try_time;
        if let Some(hp) = &self.health_ping {
            out.health_ping = Some(hp.to_proto());
        }
        out
    }
}

/// ObservationResult：所有 outbound 状态的集合。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObservationResult {
    pub status: Vec<OutboundStatus>,
}

impl ObservationResult {
    pub fn from_proto(p: &ProtoObservationResult) -> Self {
        Self { status: p.status.iter().map(OutboundStatus::from_proto).collect() }
    }

    pub fn to_proto(&self) -> ProtoObservationResult {
        let mut out = ProtoObservationResult::default();
        out.status = self.status.iter().map(|s| s.to_proto()).collect();
        out
    }
}

/// ProbeResult：单次探测的结果。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProbeResult {
    pub alive: bool,
    pub delay: i64,
    pub last_error_reason: String,
}

impl ProbeResult {
    pub fn from_proto(p: &ProtoProbeResult) -> Self {
        Self { alive: p.alive, delay: p.delay, last_error_reason: p.last_error_reason.clone() }
    }

    pub fn to_proto(&self) -> ProtoProbeResult {
        let mut out = ProtoProbeResult::default();
        out.alive = self.alive;
        out.delay = self.delay;
        out.last_error_reason = self.last_error_reason.clone();
        out
    }
}

/// 默认 probe URL（Google 204 endpoint）。
pub const DEFAULT_PROBE_URL: &str = "https://www.google.com/generate_204";

/// 默认 probe interval（10 秒，单位 ms）。
pub const DEFAULT_PROBE_INTERVAL_MS: i64 = 10_000;

/// 探测失败时的占位 delay（与 Go 版 magic number 一致）。
pub const DEAD_DELAY_MS: i64 = 99_999_999;

/// Observer 配置。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservatoryConfig {
    pub subject_selector: Vec<String>,
    pub probe_url: String,
    pub probe_interval: i64,
    pub enable_concurrency: bool,
}

impl Default for ObservatoryConfig {
    fn default() -> Self {
        Self {
            subject_selector: Vec::new(),
            probe_url: String::new(),
            probe_interval: 0,
            enable_concurrency: false,
        }
    }
}

impl ObservatoryConfig {
    pub fn from_proto(p: &ProtoConfig) -> Self {
        Self {
            subject_selector: p.subject_selector.clone(),
            probe_url: p.probe_url.clone(),
            probe_interval: p.probe_interval,
            enable_concurrency: p.enable_concurrency,
        }
    }

    pub fn to_proto(&self) -> ProtoConfig {
        let mut out = ProtoConfig::default();
        out.subject_selector = self.subject_selector.clone();
        out.probe_url = self.probe_url.clone();
        out.probe_interval = self.probe_interval;
        out.enable_concurrency = self.enable_concurrency;
        out
    }

    /// 解析后的 probe URL（空则用默认）。
    pub fn effective_probe_url(&self) -> &str {
        if self.probe_url.is_empty() { DEFAULT_PROBE_URL } else { &self.probe_url }
    }

    /// 解析后的 probe interval（0 则用默认）。
    pub fn effective_probe_interval_ms(&self) -> i64 {
        if self.probe_interval == 0 { DEFAULT_PROBE_INTERVAL_MS } else { self.probe_interval }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_ping_default_zero() {
        let h = HealthPingMeasurement::default();
        assert_eq!(h.all, 0);
        assert_eq!(h.fail, 0);
    }

    #[test]
    fn health_ping_proto_roundtrip() {
        let h = HealthPingMeasurement {
            all: 10,
            fail: 2,
            deviation: 50,
            average: 100,
            max: 200,
            min: 50,
        };
        let p = h.to_proto();
        assert_eq!(HealthPingMeasurement::from_proto(&p), h);
    }

    #[test]
    fn outbound_status_default() {
        let s = OutboundStatus::default();
        assert!(!s.alive);
        assert_eq!(s.delay, 0);
        assert!(s.outbound_tag.is_empty());
        assert!(s.health_ping.is_none());
    }

    #[test]
    fn outbound_status_proto_roundtrip_no_health() {
        let s = OutboundStatus {
            alive: true,
            delay: 50,
            last_error_reason: "none".into(),
            outbound_tag: "out".into(),
            last_seen_time: 1000,
            last_try_time: 999,
            health_ping: None,
        };
        let p = s.to_proto();
        assert_eq!(OutboundStatus::from_proto(&p), s);
    }

    #[test]
    fn outbound_status_proto_roundtrip_with_health() {
        let mut s = OutboundStatus::default();
        s.outbound_tag = "out".into();
        s.health_ping = Some(HealthPingMeasurement {
            all: 5,
            fail: 1,
            deviation: 10,
            average: 50,
            max: 80,
            min: 30,
        });
        let p = s.to_proto();
        assert_eq!(OutboundStatus::from_proto(&p), s);
    }

    #[test]
    fn observation_result_proto_roundtrip() {
        let r = ObservationResult {
            status: vec![
                OutboundStatus {
                    outbound_tag: "a".into(),
                    alive: true,
                    delay: 10,
                    ..Default::default()
                },
                OutboundStatus {
                    outbound_tag: "b".into(),
                    alive: false,
                    delay: 99_999_999,
                    last_error_reason: "timeout".into(),
                    ..Default::default()
                },
            ],
        };
        let p = r.to_proto();
        assert_eq!(ObservationResult::from_proto(&p), r);
    }

    #[test]
    fn probe_result_proto_roundtrip() {
        let r = ProbeResult { alive: true, delay: 50, last_error_reason: String::new() };
        let p = r.to_proto();
        assert_eq!(ProbeResult::from_proto(&p), r);
    }

    #[test]
    fn config_default_is_empty() {
        let c = ObservatoryConfig::default();
        assert!(c.subject_selector.is_empty());
        assert!(c.probe_url.is_empty());
        assert_eq!(c.probe_interval, 0);
        assert!(!c.enable_concurrency);
    }

    #[test]
    fn config_proto_roundtrip() {
        let c = ObservatoryConfig {
            subject_selector: vec!["a".into(), "b".into()],
            probe_url: "https://x.test/204".into(),
            probe_interval: 5000,
            enable_concurrency: true,
        };
        let p = c.to_proto();
        assert_eq!(ObservatoryConfig::from_proto(&p), c);
    }

    #[test]
    fn config_effective_probe_url_default_when_empty() {
        let c = ObservatoryConfig::default();
        assert_eq!(c.effective_probe_url(), DEFAULT_PROBE_URL);
    }

    #[test]
    fn config_effective_probe_url_custom() {
        let c = ObservatoryConfig { probe_url: "https://custom.test".into(), ..Default::default() };
        assert_eq!(c.effective_probe_url(), "https://custom.test");
    }

    #[test]
    fn config_effective_probe_interval_default_when_zero() {
        let c = ObservatoryConfig::default();
        assert_eq!(c.effective_probe_interval_ms(), DEFAULT_PROBE_INTERVAL_MS);
    }

    #[test]
    fn config_effective_probe_interval_custom() {
        let c = ObservatoryConfig { probe_interval: 30_000, ..Default::default() };
        assert_eq!(c.effective_probe_interval_ms(), 30_000);
    }

    #[test]
    fn dead_delay_constant() {
        assert_eq!(DEAD_DELAY_MS, 99_999_999);
    }
}
