//! 采样器：进程 RSS / fd / tokio RuntimeMetrics / 每场景吞吐与延迟分位。
//!
//! CSV 追加（崩了可续，`run_id` 列区分 run），checkpoint 默认每 6h 覆盖写
//! `summary-latest.md`（中间态 summary，崩了也有近时快照可看）。

use std::io::Write as _;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::runtime::Handle;
use xray_common::runtime_guard::RuntimeMetricsSnapshot;

use crate::report::{render_summary, StatsHandle};

/// 一条场景快照行（含全局进程行共用的公共列）。
struct SampleRow {
    ts: u64,
    scenario: String,
    conn_ok: u64,
    conn_fail: u64,
    tx_bps: f64,
    rx_bps: f64,
    p50_ms: Option<f64>,
    p95_ms: Option<f64>,
    p99_ms: Option<f64>,
    // 仅 __proc__ 行填充
    rss_mb: f64,
    fd_count: Option<usize>,
    alive_tasks: usize,
    worker_park: u64,
    busy_s: f64,
}

pub const CSV_HEADER: &str = "ts,scenario,conn_ok,conn_fail,tx_bps,rx_bps,p50_ms,p95_ms,p99_ms,rss_mb,fd_count,alive_tasks,worker_park,busy_s";

pub struct Sampler {
    pub run_id: String,
    out_dir: std::path::PathBuf,
    csv: std::fs::File,
    stats: Vec<StatsHandle>,
    prev_bytes: Vec<(String, u64)>,
    /// (t_sec, aggregate bytes/s) 供 summary 吞吐衰减判定。
    pub samples_throughput: Vec<(f64, f64)>,
    /// (t_sec, rss_mb) 供 summary 泄漏判定。
    pub samples_rss: Vec<(f64, f64)>,
    last_checkpoint: Instant,
    checkpoint_every: Duration,
}

impl Sampler {
    pub fn new(
        run_id: &str,
        out_dir: &Path,
        stats: Vec<StatsHandle>,
        checkpoint_every: Duration,
    ) -> std::io::Result<Self> {
        std::fs::create_dir_all(out_dir)?;
        let csv_path = out_dir.join("metrics.csv");
        let fresh = !csv_path.exists();
        let mut csv = std::fs::OpenOptions::new().create(true).append(true).open(&csv_path)?;
        if fresh {
            writeln!(csv, "{CSV_HEADER}")?;
        }
        Ok(Self {
            run_id: run_id.to_string(),
            out_dir: out_dir.to_path_buf(),
            csv,
            stats,
            prev_bytes: Vec::new(),
            samples_throughput: Vec::new(),
            samples_rss: Vec::new(),
            last_checkpoint: Instant::now(),
            checkpoint_every,
        })
    }

    /// 采样一次并追加 CSV。`elapsed` 为本次 run 已进行秒数。
    pub fn sample_once(&mut self, elapsed: f64, interval: Duration) -> std::io::Result<()> {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let (rss_mb, fd_count) = sample_process();
        let rt = RuntimeMetricsSnapshot::capture(&Handle::current());
        self.samples_rss.push((elapsed, rss_mb));

        let mut rows = Vec::with_capacity(self.stats.len() + 1);
        let mut agg_bytes = 0u64;
        for h in &self.stats {
            let snap = h.snapshot();
            let prev = self
                .prev_bytes
                .iter()
                .find(|(n, _)| *n == snap.name)
                .map(|(_, b)| *b);
            let window = interval.as_secs_f64().max(1e-6);
            let total = snap.bytes_tx + snap.bytes_rx;
            let bps = prev.map_or(0.0, |p| (total.saturating_sub(p)) as f64 / window);
            self.prev_bytes.retain(|(n, _)| *n != snap.name);
            self.prev_bytes.push((snap.name.clone(), total));
            agg_bytes += total;
            rows.push(SampleRow {
                ts,
                scenario: snap.name.clone(),
                conn_ok: snap.conn_ok,
                conn_fail: snap.conn_fail,
                tx_bps: bps / 2.0,
                rx_bps: bps / 2.0,
                p50_ms: snap.percentile(0.50),
                p95_ms: snap.percentile(0.95),
                p99_ms: snap.percentile(0.99),
                rss_mb: 0.0,
                fd_count: None,
                alive_tasks: 0,
                worker_park: 0,
                busy_s: 0.0,
            });
        }
        self.samples_throughput.push((elapsed, agg_bytes as f64 / interval.as_secs_f64().max(1e-6)));
        rows.push(SampleRow {
            ts,
            scenario: "__proc__".into(),
            conn_ok: 0,
            conn_fail: 0,
            tx_bps: 0.0,
            rx_bps: 0.0,
            p50_ms: None,
            p95_ms: None,
            p99_ms: None,
            rss_mb,
            fd_count,
            alive_tasks: rt.alive_tasks,
            worker_park: rt.worker_park_count,
            busy_s: rt.worker_busy_duration.as_secs_f64(),
        });
        for r in &rows {
            self.write_row(r)?;
        }
        Ok(())
    }

    fn write_row(&mut self, r: &SampleRow) -> std::io::Result<()> {
        let fmt = |v: Option<f64>| v.map_or("-".into(), |x| format!("{x:.1}"));
        writeln!(
            self.csv,
            "{},{},{},{},{:.0},{:.0},{},{},{},{:.1},{},{},{},{:.3}",
            r.ts,
            r.scenario,
            r.conn_ok,
            r.conn_fail,
            r.tx_bps,
            r.rx_bps,
            fmt(r.p50_ms),
            fmt(r.p95_ms),
            fmt(r.p99_ms),
            r.rss_mb,
            r.fd_count.map_or("-".into(), |v| v.to_string()),
            r.alive_tasks,
            r.worker_park,
            r.busy_s,
        )
    }

    /// checkpoint 到点时覆盖写中间态 summary。
    pub fn maybe_checkpoint(
        &mut self,
        duration: Duration,
        leak_threshold_pct: f64,
        throughput_label: &str,
    ) -> std::io::Result<bool> {
        if self.last_checkpoint.elapsed() < self.checkpoint_every {
            return Ok(false);
        }
        self.last_checkpoint = Instant::now();
        let snapshots: Vec<_> = self.stats.iter().map(|h| h.snapshot()).collect();
        let leak = crate::report::judge_leak(&self.samples_rss, leak_threshold_pct);
        let md = render_summary(
            &format!("{}-checkpoint", self.run_id),
            duration,
            leak.as_ref(),
            leak_threshold_pct,
            &snapshots,
            &self.samples_throughput,
            throughput_label,
        );
        let path = self.out_dir.join("summary-latest.md");
        std::fs::write(path, md)?;
        Ok(true)
    }

    /// 终态 summary.md。
    pub fn write_final_summary(
        &self,
        duration: Duration,
        leak_threshold_pct: f64,
        throughput_label: &str,
    ) -> std::io::Result<std::path::PathBuf> {
        let snapshots: Vec<_> = self.stats.iter().map(|h| h.snapshot()).collect();
        let leak = crate::report::judge_leak(&self.samples_rss, leak_threshold_pct);
        let md = render_summary(
            &self.run_id,
            duration,
            leak.as_ref(),
            leak_threshold_pct,
            &snapshots,
            &self.samples_throughput,
            throughput_label,
        );
        let path = self.out_dir.join("summary.md");
        std::fs::write(&path, md)?;
        Ok(path)
    }
}

/// (rss_mb, fd_count)。sysinfo 0.39：memory() = bytes；fd_count() macOS 返回 None。
fn sample_process() -> (f64, Option<usize>) {
    let pid = sysinfo::get_current_pid().unwrap_or_else(|_| sysinfo::Pid::from_u32(0));
    let mut sys = sysinfo::System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[pid]), true);
    match sys.process(pid) {
        Some(p) => (p.memory() as f64 / 1024.0 / 1024.0, p.open_files()),
        None => (0.0, None),
    }
}
