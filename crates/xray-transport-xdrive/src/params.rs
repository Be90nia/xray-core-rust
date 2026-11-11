//! 参数缺省/上限/按后端覆盖。对应 Go `transport/internet/xdrive/params.go`。
//!
//! [`Params::for_storage`] 只在 storage 是 [`SlotStore`](crate::storage::SlotStore)
//! 时套 Drive 槽路径缺省（concurrency 64 / flush 10ms / maxPoll 200ms），且只覆盖
//! 配置留 0 的字段——WAL 后端（local/template/s3）的 concurrency 与 flush 语义
//! 不同，套用会放大请求风暴（规划 §7 R5）。B1 仅 `local`（恒非 slot）。

use std::time::Duration;

use crate::{config::Config, storage::Storage};

const DEFAULT_SEGMENT_BYTES: usize = 512 * 1024;
const DEFAULT_FLUSH_INTERVAL: Duration = Duration::from_millis(20);
const DEFAULT_MIN_POLL_INTERVAL: Duration = Duration::from_millis(50);
const DEFAULT_MAX_POLL_INTERVAL: Duration = Duration::from_millis(500);
const DEFAULT_EAGER_WINDOW: Duration = Duration::from_millis(2000);
const DEFAULT_HOLE_TIMEOUT: Duration = Duration::from_millis(30_000);
const DEFAULT_SESSION_TTL: Duration = Duration::from_millis(5 * 60 * 1000);
const DEFAULT_CONCURRENCY: usize = 8;

const MAX_SEGMENT_BYTES: usize = 16 * 1024 * 1024;
const MAX_CONCURRENCY: usize = 256;

/// WAL 读写节拍参数（Go `params` struct）。
#[derive(Debug, Clone, Copy)]
pub struct Params {
    pub segment_bytes: usize,
    pub flush_interval: Duration,
    pub min_poll_interval: Duration,
    pub max_poll_interval: Duration,
    pub eager_window: Duration,
    pub hole_timeout: Duration,
    pub session_ttl: Duration,
    pub concurrency: usize,
}

fn millis(value: u32, fallback: Duration) -> Duration {
    if value == 0 { fallback } else { Duration::from_millis(u64::from(value)) }
}

fn seconds(value: u32, fallback: Duration) -> Duration {
    if value == 0 { fallback } else { Duration::from_secs(u64::from(value)) }
}

fn capped(value: u32, fallback: usize, limit: usize) -> usize {
    if value == 0 { fallback } else { usize::try_from(value).unwrap_or(limit).min(limit) }
}

impl Params {
    /// Go `paramsFromConfig`：逐字段缺省/封顶，maxPoll 抬到 min 下限。
    #[must_use]
    pub fn from_config(c: &Config) -> Self {
        let mut p = Params {
            segment_bytes: capped(c.segment_bytes, DEFAULT_SEGMENT_BYTES, MAX_SEGMENT_BYTES),
            flush_interval: millis(c.flush_interval_ms, DEFAULT_FLUSH_INTERVAL),
            min_poll_interval: millis(c.poll_interval_ms, DEFAULT_MIN_POLL_INTERVAL),
            max_poll_interval: millis(c.max_poll_interval_ms, DEFAULT_MAX_POLL_INTERVAL),
            eager_window: millis(c.eager_window_ms, DEFAULT_EAGER_WINDOW),
            hole_timeout: millis(c.hole_timeout_ms, DEFAULT_HOLE_TIMEOUT),
            session_ttl: seconds(c.session_ttl_seconds, DEFAULT_SESSION_TTL),
            concurrency: capped(c.concurrency, DEFAULT_CONCURRENCY, MAX_CONCURRENCY),
        };
        if p.max_poll_interval < p.min_poll_interval {
            p.max_poll_interval = p.min_poll_interval;
        }
        p
    }

    /// Go `paramsForStorage`：仅 slot 后端覆盖 Drive 槽路径缺省（只动配置留 0 的
    /// 字段）。判定严格按 trait（[`Storage::as_slot_store`]）——B1 起单测钉死
    /// local 不触发覆盖。
    #[must_use]
    pub fn for_storage(c: &Config, storage: &dyn Storage) -> Self {
        if storage.as_slot_store().is_some() {
            let mut cc = c.clone();
            if cc.concurrency == 0 {
                cc.concurrency = 64;
            }
            if cc.flush_interval_ms == 0 {
                cc.flush_interval_ms = 10;
            }
            if cc.max_poll_interval_ms == 0 {
                cc.max_poll_interval_ms = 200;
            }
            return Self::from_config(&cc);
        }
        Self::from_config(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::LocalStorage;

    fn config(service: &str) -> Config {
        Config {
            service: service.to_string(),
            remote_folder: "/tmp/xdrive-params-test".to_string(),
            ..Config::default()
        }
    }

    #[test]
    fn defaults_match_go() {
        let p = Params::from_config(&config("local"));
        assert_eq!(p.segment_bytes, 512 * 1024);
        assert_eq!(p.flush_interval, Duration::from_millis(20));
        assert_eq!(p.min_poll_interval, Duration::from_millis(50));
        assert_eq!(p.max_poll_interval, Duration::from_millis(500));
        assert_eq!(p.eager_window, Duration::from_millis(2000));
        assert_eq!(p.hole_timeout, Duration::from_millis(30_000));
        assert_eq!(p.session_ttl, Duration::from_millis(5 * 60 * 1000));
        assert_eq!(p.concurrency, 8);
    }

    #[test]
    fn caps_and_clamp_match_go() {
        let mut c = config("local");
        c.segment_bytes = u32::MAX; // > 16 MiB → 封顶
        c.concurrency = u32::MAX; // > 256 → 封顶
        // maxPoll 留 0 → 缺省 500ms；500 > min(200) 不触发抬升（Go 同款）。
        c.poll_interval_ms = 200;
        let p = Params::from_config(&c);
        assert_eq!(p.segment_bytes, 16 * 1024 * 1024);
        assert_eq!(p.concurrency, 256);
        assert_eq!(p.min_poll_interval, Duration::from_millis(200));
        assert_eq!(p.max_poll_interval, Duration::from_millis(500));

        // min > max（poll=700 > 缺省 max=500）→ max 抬到 min。
        let mut c2 = config("local");
        c2.poll_interval_ms = 700;
        let p2 = Params::from_config(&c2);
        assert_eq!(p2.max_poll_interval, Duration::from_millis(700));
    }

    #[test]
    fn local_storage_never_gets_slot_overrides() {
        let dir = std::env::temp_dir().join(format!("xdrive-params-{}", std::process::id()));
        let storage = LocalStorage::new(&dir.join("r").to_string_lossy()).unwrap();
        let c = config("local");
        let p = Params::for_storage(&c, &storage);
        assert_eq!(p.concurrency, 8);
        assert_eq!(p.flush_interval, Duration::from_millis(20));
        assert_eq!(p.max_poll_interval, Duration::from_millis(500));
        let _ = std::fs::remove_dir_all(dir);
    }
}
