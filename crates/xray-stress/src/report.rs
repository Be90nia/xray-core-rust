//! 结束汇总：延迟分位、RSS 线性回归、泄漏/吞吐衰减判定、summary.md 渲染。
//!
//! 全部纯函数，单元测试锚定行为。

use std::{sync::Arc, time::Duration};

/// 每场景累计计数（原子，由场景 worker 更新、采样器快照）。
#[derive(Debug, Default, Clone)]
pub struct ScenarioStats {
    pub name: String,
    pub conn_ok: u64,
    pub conn_fail: u64,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    /// roundtrip 延迟样本（ms），环形缓冲，容量 = [`LATENCY_CAP`]。
    pub latencies_ms: Vec<f64>,
    /// 环形缓冲写指针（下一写入位）。
    pub lat_next: usize,
    /// 环形缓冲已填充数（≤ cap 后恒为 cap）。
    pub lat_filled: usize,
}

pub const LATENCY_CAP: usize = 4096;

/// 场景计数共享句柄：worker 写、采样器快照。
#[derive(Clone)]
pub struct StatsHandle(Arc<parking_lot::Mutex<ScenarioStats>>);

impl StatsHandle {
    pub fn new(name: &str) -> Self {
        Self(Arc::new(parking_lot::Mutex::new(ScenarioStats::new(name))))
    }

    /// 记录一次成功 roundtrip（tx/rx 字节 + 延迟 ms）。
    pub fn record_ok(&self, bytes_tx: u64, bytes_rx: u64, latency_ms: f64) {
        let mut s = self.0.lock();
        s.conn_ok += 1;
        s.bytes_tx += bytes_tx;
        s.bytes_rx += bytes_rx;
        s.record_latency(latency_ms);
    }

    pub fn record_fail(&self) {
        self.0.lock().conn_fail += 1;
    }

    pub fn name(&self) -> String {
        self.0.lock().name.clone()
    }

    pub fn snapshot(&self) -> ScenarioStats {
        self.0.lock().clone()
    }
}

impl ScenarioStats {
    pub fn new(name: &str) -> Self {
        Self { name: name.to_string(), ..Default::default() }
    }

    /// 记录一个延迟样本（环形覆盖最旧）。
    pub fn record_latency(&mut self, ms: f64) {
        if self.latencies_ms.len() < LATENCY_CAP {
            self.latencies_ms.push(ms);
        } else {
            self.latencies_ms[self.lat_next] = ms;
        }
        self.lat_next = (self.lat_next + 1) % LATENCY_CAP;
        self.lat_filled = (self.lat_filled + 1).min(LATENCY_CAP);
    }

    /// 分位（0.0-1.0）；无样本返回 None。
    pub fn percentile(&self, q: f64) -> Option<f64> {
        percentile_of(&self.latencies_ms[..self.lat_filled], q)
    }
}

/// 对样本升序排序后取分位（最近邻插值）。
pub fn percentile_of(samples_ms: &[f64], q: f64) -> Option<f64> {
    if samples_ms.is_empty() {
        return None;
    }
    let mut sorted = samples_ms.to_vec();
    sorted.sort_by(|a, b| a.total_cmp(b));
    let q = q.clamp(0.0, 1.0);
    let idx = ((sorted.len() - 1) as f64 * q).round() as usize;
    Some(sorted[idx])
}

/// (t_seconds, rss_mb) 样本的最小二乘拟合斜率（MB/h）。
pub fn rss_slope_mb_per_h(samples: &[(f64, f64)]) -> Option<f64> {
    let n = samples.len();
    if n < 2 {
        return None;
    }
    let (mut st, mut stt, mut sr, mut str_) = (0.0, 0.0, 0.0, 0.0);
    for &(t, rss) in samples {
        st += t;
        stt += t * t;
        sr += rss;
        str_ += t * rss;
    }
    let denom = n as f64 * stt - st * st;
    if denom == 0.0 {
        return None;
    }
    Some((n as f64 * str_ - st * sr) / denom * 3600.0)
}

/// 泄漏判定输入。
pub struct LeakVerdict {
    pub slope_mb_per_h: f64,
    /// 斜率相对基线的百分比（%/h）。
    pub slope_pct_per_h: f64,
    pub baseline_mb: f64,
    pub peak_mb: f64,
    pub first_mb: f64,
    pub last_mb: f64,
    /// true = RSS 线性增长超过阈值，SUSPECT。
    pub suspect: bool,
}

/// RSS 泄漏判定：基线 = 前 10% 样本均值，斜率百分比 > `threshold_pct_per_h` → SUSPECT。
pub fn judge_leak(samples: &[(f64, f64)], threshold_pct_per_h: f64) -> Option<LeakVerdict> {
    let slope_mb_per_h = rss_slope_mb_per_h(samples)?;
    let n = samples.len();
    let baseline_n = (n / 10).max(1);
    let baseline_mb: f64 =
        samples[..baseline_n].iter().map(|s| s.1).sum::<f64>() / baseline_n as f64;
    let first_mb = samples[0].1;
    let last_mb = samples[n - 1].1;
    let peak_mb = samples.iter().map(|s| s.1).fold(f64::MIN, f64::max);
    let slope_pct_per_h =
        if baseline_mb > 0.0 { slope_mb_per_h / baseline_mb * 100.0 } else { f64::INFINITY };
    Some(LeakVerdict {
        slope_mb_per_h,
        slope_pct_per_h,
        baseline_mb,
        peak_mb,
        first_mb,
        last_mb,
        suspect: slope_pct_per_h > threshold_pct_per_h,
    })
}

/// 吞吐衰减判定：前 25% 时窗均值 vs 后 25% 时窗均值。
/// 返回 (首段均值, 尾段均值, 衰减比率 0.0-1.0+)。
pub fn throughput_decay(samples: &[(f64, f64)]) -> Option<(f64, f64, f64)> {
    if samples.is_empty() {
        return None;
    }
    let n = samples.len();
    let q = (n / 4).max(1);
    let head: f64 = samples[..q].iter().map(|s| s.1).sum::<f64>() / q as f64;
    let tail: f64 = samples[n - q..].iter().map(|s| s.1).sum::<f64>() / q as f64;
    let ratio = if head > 0.0 { tail / head } else { 1.0 };
    Some((head, tail, ratio))
}

/// 渲染 summary.md 全文。
pub fn render_summary(
    run_id: &str,
    duration: Duration,
    leak: Option<&LeakVerdict>,
    leak_threshold_pct: f64,
    scenarios: &[ScenarioStats],
    throughput: &[(f64, f64)],
    throughput_label: &str,
) -> String {
    let mut md = String::with_capacity(4096);
    md.push_str(&format!("# xray-stress summary — run `{run_id}`\n\n"));
    md.push_str(&format!("- duration: {}s\n- finished: {}\n\n", duration.as_secs(), unix_now()));

    // 内存判定
    md.push_str("## 内存（进程 RSS）\n\n");
    match leak {
        Some(v) => {
            md.push_str(&format!(
                "- baseline (first 10%): {:.1} MB\n- first / last / peak: {:.1} / {:.1} / {:.1} MB\n- linear slope: {:.2} MB/h ({:.2} %/h of baseline)\n- leak threshold: {:.1} %/h\n- verdict: **{}**\n\n",
                v.baseline_mb,
                v.first_mb,
                v.last_mb,
                v.peak_mb,
                v.slope_mb_per_h,
                v.slope_pct_per_h,
                leak_threshold_pct,
                if v.suspect { "SUSPECT — RSS 线性增长超阈值" } else { "OK — 未检出线性泄漏" }
            ));
        },
        None => md.push_str("- 无 RSS 样本（采样器未运行或样本不足 2 个）\n\n"),
    }

    // 吞吐衰减
    md.push_str(&format!("## 吞吐（{throughput_label}）\n\n"));
    match throughput_decay(throughput) {
        Some((head, tail, ratio)) => {
            let verdict = if ratio < 0.8 { "DEGRADED" } else { "OK" };
            md.push_str(&format!(
                "- first-25% window avg: {head:.0} B/s\n- last-25% window avg: {tail:.0} B/s\n- tail/head ratio: {ratio:.3}\n- verdict: **{verdict}**\n\n"
            ));
        },
        None => md.push_str("- 无吞吐样本\n\n"),
    }

    // 场景表
    md.push_str("## 场景计数\n\n");
    md.push_str(
        "| scenario | conn_ok | conn_fail | tx_bytes | rx_bytes | p50_ms | p95_ms | p99_ms |\n",
    );
    md.push_str("|---|---|---|---|---|---|---|---|\n");
    for s in scenarios {
        let (p50, p95, p99) = (s.percentile(0.50), s.percentile(0.95), s.percentile(0.99));
        let fmt = |v: Option<f64>| v.map_or("-".into(), |x| format!("{x:.1}"));
        md.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} |\n",
            s.name,
            s.conn_ok,
            s.conn_fail,
            s.bytes_tx,
            s.bytes_rx,
            fmt(p50),
            fmt(p95),
            fmt(p99)
        ));
    }
    md.push_str("\n错误计数表：上表 conn_fail 列即每场景失败连接数。\n");
    md
}

/// 时间戳（Unix 秒；不引 chrono，summary 只需可排序的完成时刻）。
fn unix_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("unix={secs}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx(a: f64, b: f64, eps: f64) -> bool {
        (a - b).abs() < eps
    }

    #[test]
    fn percentile_empty_is_none() {
        assert!(percentile_of(&[], 0.5).is_none());
    }

    #[test]
    fn percentile_single_sample() {
        assert!(approx(percentile_of(&[3.0], 0.99).unwrap(), 3.0, 1e-9));
    }

    #[test]
    fn percentile_unsorted_input_sorted_internally() {
        let s = vec![5.0, 1.0, 3.0];
        assert!(approx(percentile_of(&s, 0.5).unwrap(), 3.0, 1e-9));
        assert!(approx(percentile_of(&s, 0.0).unwrap(), 1.0, 1e-9));
        assert!(approx(percentile_of(&s, 1.0).unwrap(), 5.0, 1e-9));
    }

    #[test]
    fn latency_ring_overwrites_oldest() {
        let mut st = ScenarioStats::new("s1");
        for i in 0..(LATENCY_CAP + 10) {
            st.record_latency(i as f64);
        }
        // 最旧的 0..10 已被覆盖，环形内最早样本 = 10
        let p0 = st.percentile(0.0).unwrap();
        assert!(approx(p0, 10.0, 1e-9), "p0={p0}");
    }

    #[test]
    fn rss_slope_flat_is_zero() {
        let s: Vec<(f64, f64)> = (0..10).map(|i| (i as f64 * 60.0, 100.0)).collect();
        let slope = rss_slope_mb_per_h(&s).unwrap();
        assert!(approx(slope, 0.0, 1e-9));
    }

    #[test]
    fn rss_slope_one_mb_per_minute_is_sixty_per_h() {
        // 每 60s 涨 1MB → 60 MB/h
        let s: Vec<(f64, f64)> = (0..10).map(|i| (i as f64 * 60.0, 100.0 + i as f64)).collect();
        let slope = rss_slope_mb_per_h(&s).unwrap();
        assert!(approx(slope, 60.0, 0.5), "slope={slope}");
    }

    #[test]
    fn leak_suspect_above_threshold() {
        // 基线 100MB，每小时涨 10MB = 10%/h > 5%/h → SUSPECT
        let s: Vec<(f64, f64)> =
            (0..10).map(|i| (i as f64 * 3600.0, 100.0 + i as f64 * 10.0)).collect();
        let v = judge_leak(&s, 5.0).unwrap();
        assert!(v.suspect, "slope_pct={}", v.slope_pct_per_h);
        assert!(approx(v.peak_mb, 190.0, 1e-9));
        assert!(approx(v.baseline_mb, 100.0, 1.0));
    }

    #[test]
    fn leak_clean_below_threshold() {
        // 稳态 100MB，斜率 0 → 非 SUSPECT
        let s: Vec<(f64, f64)> =
            (0..10).map(|i| (i as f64 * 3600.0, 100.0 + (i % 2) as f64)).collect();
        let v = judge_leak(&s, 5.0).unwrap();
        assert!(!v.suspect);
    }

    #[test]
    fn leak_empty_is_none() {
        assert!(judge_leak(&[], 5.0).is_none());
    }

    #[test]
    fn throughput_decay_detects_half_rate() {
        // 前 400s 吞吐 1000，后 400s 吞吐 500
        let mut s: Vec<(f64, f64)> = (0..40).map(|i| (i as f64 * 10.0, 1000.0)).collect();
        s.extend((40..80).map(|i| (i as f64 * 10.0, 500.0)));
        let (head, tail, ratio) = throughput_decay(&s).unwrap();
        assert!(approx(head, 1000.0, 1.0));
        assert!(approx(tail, 500.0, 1.0));
        assert!(approx(ratio, 0.5, 0.01));
    }

    #[test]
    fn throughput_decay_steady_is_one() {
        let s: Vec<(f64, f64)> = (0..40).map(|i| (i as f64 * 10.0, 800.0)).collect();
        let (_, _, ratio) = throughput_decay(&s).unwrap();
        assert!(approx(ratio, 1.0, 0.01));
    }

    #[test]
    fn summary_contains_verdict_lines() {
        let mut s1 = ScenarioStats::new("s1-short");
        s1.conn_ok = 10;
        s1.conn_fail = 1;
        s1.record_latency(5.0);
        s1.record_latency(50.0);
        let leak_samples: Vec<(f64, f64)> =
            (0..10).map(|i| (i as f64 * 3600.0, 100.0 + i as f64)).collect();
        let leak = judge_leak(&leak_samples, 5.0);
        let tp: Vec<(f64, f64)> = (0..10).map(|i| (i as f64 * 60.0, 1000.0)).collect();
        let md = render_summary(
            "run-test",
            Duration::from_secs(600),
            leak.as_ref(),
            5.0,
            &[s1],
            &tp,
            "aggregate",
        );
        assert!(md.contains("run-test"));
        assert!(md.contains("SUSPECT") || md.contains("OK"));
        assert!(md.contains("s1-short"));
        assert!(md.contains("conn_ok"));
    }
}
