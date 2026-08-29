//! BurstObserver：对应 Go `app/observatory/burst/burstobserver.go` 的 Observer。
//!
//! 实装 `BurstObservatory.Check`（Go `features/extension/observatory.go:16-19`
//! 接口 → `burstobserver.go:34-36` 委托 → `healthping.go:148-155` 实现）：
//! 按需对指定 tag 立即执行一轮 health check，而不是等下一个调度 tick。
//! Go 调用点：`proxy/vless/inbound/inbound.go:664-666`（新 worker 注册后
//! `go burstObs.Check([]string{r.Tag()})` 立即探测）。

use std::collections::HashMap;

use parking_lot::Mutex;

use super::{HealthPingRtts, HealthPingSettings, RTT_FAILED};
use crate::observer::ProbeExecutor;

/// 当前 Unix 时间（纳秒），与 healthping_stats 时间单位一致。
fn now_unix_nanos() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

/// Burst 观察者：按需 Check + per-tag RTT 样本表。
///
/// 对应 Go `burst.Observer` 持有的 `HealthPing.Results`（tag → RTT 环形缓冲）。
pub struct BurstObserver {
    rtts: Mutex<HashMap<String, HealthPingRtts>>,
    capacity: usize,
    validity_nanos: i64,
}

impl BurstObserver {
    /// 从 HealthPingSettings 构造。
    ///
    /// 容量 = `sampling_count`；有效期对应 Go `healthping.go:246`：
    /// `validity = interval * SamplingCount * 2`（采样在时间线上随机分布，
    /// 极端情况下早期检查偏左、晚期偏右，故取 2 倍采样周期）。
    pub fn new(settings: &HealthPingSettings) -> Self {
        let capacity = settings.sampling_count.max(1) as usize;
        let validity_nanos = settings.interval * settings.sampling_count.max(1) as i64 * 2;
        Self {
            rtts: Mutex::new(HashMap::new()),
            capacity,
            validity_nanos,
        }
    }

    /// 对应 Go `Observer.Check(tag []string)`：对给定 tag 立即执行一轮探测。
    ///
    /// Go 语义（healthping.go:148-155）：
    /// - tags 为空 → no-op；
    /// - 否则 `doCheck(ctx, tags, 0, 1)`——每个 tag 探测一轮，RTT 记入样本表。
    pub fn check(&self, tags: &[String], executor: &dyn ProbeExecutor) -> HashMap<String, i64> {
        let mut out = HashMap::new();
        if tags.is_empty() {
            return out; // Go healthping.go:149-151：空 tags no-op
        }
        let now = now_unix_nanos();
        let mut g = self.rtts.lock();
        for tag in tags {
            let result = executor.probe(tag);
            let rtt = if result.alive { result.delay } else { RTT_FAILED };
            let entry = g
                .entry(tag.clone())
                .or_insert_with(|| HealthPingRtts::new(self.capacity, self.validity_nanos));
            entry.put(rtt, now);
            out.insert(tag.clone(), rtt);
        }
        out
    }

    /// 查某 tag 最新 RTT 样本：
    /// - 无样本（从未 check 过）→ `None`；
    /// - 有样本 → 最新写入值（可能是 `RTT_FAILED` 哨兵，用
    ///   [`super::is_valid_rtt`] 判断有效性）。
    pub fn latest_rtt(&self, tag: &str) -> Option<i64> {
        self.rtts.lock().get(tag)?.latest()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProbeResult;
    use crate::observer::FixedProbeExecutor;

    fn observer() -> BurstObserver {
        BurstObserver::new(&HealthPingSettings::default())
    }

    fn alive(delay: i64) -> ProbeResult {
        ProbeResult {
            alive: true,
            delay,
            last_error_reason: String::new(),
        }
    }

    fn dead(reason: &str) -> ProbeResult {
        ProbeResult {
            alive: false,
            delay: 0,
            last_error_reason: reason.into(),
        }
    }

    #[test]
    fn check_empty_tags_is_noop_and_no_sample() {
        // 无样本：从未 check 过的 tag → None
        let obs = observer();
        assert!(obs.latest_rtt("never-checked").is_none());

        // Go healthping.go:149-151：空 tags 直接返回，不探测
        let executor = FixedProbeExecutor::new().with_result("a", alive(10));
        let out = obs.check(&[], &executor);
        assert!(out.is_empty());
        assert!(obs.latest_rtt("a").is_none());
    }

    #[test]
    fn check_records_rtt_sample() {
        // 有样本：alive probe 的 delay 记入样本表
        let obs = observer();
        let executor = FixedProbeExecutor::new().with_result("out-a", alive(50));
        let out = obs.check(&["out-a".to_string()], &executor);
        assert_eq!(out.get("out-a"), Some(&50));
        assert_eq!(obs.latest_rtt("out-a"), Some(50));
    }

    #[test]
    fn check_failed_probe_records_sentinel() {
        // 超出有效域：probe 失败 → RTT_FAILED 哨兵（is_valid_rtt 为 false）
        let obs = observer();
        let executor = FixedProbeExecutor::new().with_result("out-dead", dead("timeout"));
        let out = obs.check(&["out-dead".to_string()], &executor);
        assert_eq!(out.get("out-dead"), Some(&RTT_FAILED));
        assert_eq!(obs.latest_rtt("out-dead"), Some(RTT_FAILED));
        assert!(!super::super::is_valid_rtt(obs.latest_rtt("out-dead").unwrap()));
    }

    #[test]
    fn latest_reflects_most_recent_sample() {
        // 多轮 check：latest 是最近一次写入的值（环形覆盖语义）
        let obs = observer();
        let first = FixedProbeExecutor::new().with_result("t", alive(30));
        obs.check(&["t".to_string()], &first);
        let second = FixedProbeExecutor::new().with_result("t", alive(70));
        obs.check(&["t".to_string()], &second);
        assert_eq!(obs.latest_rtt("t"), Some(70));
    }

    #[test]
    fn new_derives_capacity_from_settings() {
        // Go healthping.go:246：validity = interval * SamplingCount * 2；
        // 容量 = sampling_count。逐个写入样本，latest 始终是最新值。
        let mut s = HealthPingSettings::default();
        s.interval = 10_000_000_000; // 10s
        s.sampling_count = 5;
        let obs = BurstObserver::new(&s);
        for expected in 1..=5i64 {
            let e = FixedProbeExecutor::new().with_result("t", alive(expected));
            obs.check(&["t".to_string()], &e);
            assert_eq!(obs.latest_rtt("t"), Some(expected));
        }
    }
}
