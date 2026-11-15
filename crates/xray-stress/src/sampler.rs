//! 采样器：进程 RSS / fd / tokio RuntimeMetrics / 每场景吞吐与延迟分位。
//!
//! CSV 追加（崩了可续，`run_id` 列区分 run），checkpoint 按 [`checkpoint_interval`]
//! 覆盖写 `summary-latest.md`（中间态 summary，崩了也有近时快照可看）。
//!
//! 吞吐列与 `samples_throughput` 一律是**窗口增量**（累计快照做差 / 采样间隔）：
//! 直接用累计值会随 t² 单调暴涨，让衰减判定恒报 OK（审计 F-3）。

use std::{
    io::Write as _,
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use tokio::runtime::Handle;
use xray_common::runtime_guard::RuntimeMetricsSnapshot;

use crate::report::{StatsHandle, render_summary};

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
    /// 每场景上一次的累计 (tx, rx) 字节快照，用于求窗口增量。
    prev_bytes: Vec<(String, (u64, u64))>,
    /// (t_sec, 窗口聚合 B/s) 供 summary 吞吐衰减判定；drain 段不入。
    pub samples_throughput: Vec<(f64, f64)>,
    /// (t_sec, rss_mb) 供 summary 泄漏判定。
    pub samples_rss: Vec<(f64, f64)>,
    last_checkpoint: Instant,
    checkpoint_every: Duration,
}

impl Sampler {
    // 字段初始化在尾表达式位不可挂语句属性（E0658），allow 上移 fn 级。
    #[allow(
        clippy::disallowed_methods,
        reason = "压测 checkpoint 锚点取时；Clock 端口注入待 bd 39hko"
    )]
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
    /// `drain=true` 时行标签写 `__drain__`（负载已停、基础设施保留的观察窗），
    /// 且不入 `samples_rss`——负载期泄漏判定不得被 drain 回落稀释。
    #[allow(
        clippy::disallowed_methods,
        reason = "CSV 行时间戳是落盘产物的真实墙钟（跨机对账用；mock 钟会破时间线）；本 crate 是独立 bin，无 ctx.clock() 注入面亦未接 compat::clock → 待压测工具接 Clock 端口后迁"
    )]
    pub fn sample_once(
        &mut self,
        elapsed: f64,
        interval: Duration,
        drain: bool,
    ) -> std::io::Result<()> {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let (rss_mb, fd_count) = sample_process();
        let rt = RuntimeMetricsSnapshot::capture(&Handle::current());
        if !drain {
            self.samples_rss.push((elapsed, rss_mb));
        }

        let mut rows = Vec::with_capacity(self.stats.len() + 1);
        let mut agg_bps = 0.0;
        // 首个采样窗没有前值，窗口增量恒 0——不是测量值，不进吞吐序列。
        let has_baseline = !self.prev_bytes.is_empty();
        let window = interval.as_secs_f64().max(1e-6);
        for h in &self.stats {
            let snap = h.snapshot();
            let cur = (snap.bytes_tx, snap.bytes_rx);
            let prev = self.prev_bytes.iter().find(|(n, _)| *n == snap.name).map(|(_, v)| *v);
            // 窗口增量：累计快照做差才是本窗口真实收发。用累计值除采样间隔会随
            // t² 单调暴涨（审计 F-3）⇒ 吞吐衰减判定永不触发。
            let (tx_bps, rx_bps) = prev.map_or((0.0, 0.0), |(ptx, prx)| {
                (
                    cur.0.saturating_sub(ptx) as f64 / window,
                    cur.1.saturating_sub(prx) as f64 / window,
                )
            });
            self.prev_bytes.retain(|(n, _)| *n != snap.name);
            self.prev_bytes.push((snap.name.clone(), cur));
            agg_bps += tx_bps + rx_bps;
            rows.push(SampleRow {
                ts,
                scenario: snap.name.clone(),
                conn_ok: snap.conn_ok,
                conn_fail: snap.conn_fail,
                tx_bps,
                rx_bps,
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
        // drain 段负载已停，吞吐归零会拉塌衰减判定的尾段均值 → 该序列不含 drain 采样。
        if !drain && has_baseline {
            self.samples_throughput.push((elapsed, agg_bps));
        }
        rows.push(SampleRow {
            ts,
            scenario: if drain { "__drain__".into() } else { "__proc__".into() },
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
    // 赋值表达式语句位挂属性在本工具链 E0658（无 stmt_expr_attributes），故挂 fn 位。
    #[allow(
        clippy::disallowed_methods,
        reason = "压测 checkpoint 锚点取时；Clock 端口注入待 bd 39hko"
    )]
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

/// checkpoint 周期 = `max(15min, duration/10)`：保证单 run 内必然触发。
/// 审计 F-28：原固定 6h > 单 run 5h ⇒ `summary-latest.md` 永不落盘。
pub fn checkpoint_interval(duration: Duration) -> Duration {
    (duration / 10).max(Duration::from_secs(900))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{StatsHandle, throughput_decay};

    /// 用真实采样器跑 `windows` 个 1s 窗口：每窗前向 stats 灌 `per_window(i)` 字节。
    /// 返回 (samples_throughput, metrics.csv 全文)。
    fn run_windows(
        per_window: impl Fn(usize) -> (u64, u64),
        windows: usize,
    ) -> (Vec<(f64, f64)>, String) {
        static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("xray-stress-sampler-{}-{seq}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let h = StatsHandle::new("s1-short");
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let samples = rt.block_on(async {
            let mut s =
                Sampler::new("run-test", &dir, vec![h.clone()], Duration::from_secs(900)).unwrap();
            for i in 0..windows {
                let (tx, rx) = per_window(i);
                h.record_ok(tx, rx, 1.0);
                s.sample_once(i as f64, Duration::from_secs(1), false).unwrap();
            }
            s.samples_throughput
        });
        let csv = std::fs::read_to_string(dir.join("metrics.csv")).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        (samples, csv)
    }

    #[test]
    fn throughput_is_window_increment_not_cumulative() {
        let (samples, csv) = run_windows(|_| (2000, 1000), 6);
        // 首窗无前值被剔除，其余每窗恒 3000 B/s（累计口径会给 3000/6000/9000…）
        assert_eq!(samples.len(), 5);
        for (t, bps) in &samples {
            assert!((bps - 3000.0).abs() < 1e-6, "t={t} bps={bps} 仍随窗口累加");
        }
        // tx/rx 分列真实收发（旧实现两列各 bps/2 = 1500/1500）
        let row = csv.lines().filter(|l| l.contains("s1-short")).nth(1).unwrap();
        let cols: Vec<&str> = row.split(',').collect();
        assert_eq!((cols[4], cols[5]), ("2000", "1000"), "tx/rx 必须分列真实收发");
    }

    #[test]
    fn throughput_collapse_is_degraded_and_steady_is_ok() {
        let steady = run_windows(|_| (5000, 5000), 40).0;
        let (_, _, ratio) = throughput_decay(&steady).unwrap();
        assert!(ratio >= 0.8, "稳态 run 应判 OK: ratio={ratio}");

        // 后 20 窗吞吐降到 1/10（10× 崩塌）
        let collapsed = run_windows(|i| if i < 20 { (5000, 5000) } else { (500, 500) }, 40).0;
        let (head, tail, ratio) = throughput_decay(&collapsed).unwrap();
        assert!(ratio < 0.8, "10× 崩塌必须判 DEGRADED: ratio={ratio} head={head} tail={tail}");
    }

    #[test]
    fn checkpoint_interval_always_fires_within_run() {
        // 5h run：6h 固定周期永不触发（F-28），新公式落 30min
        assert_eq!(checkpoint_interval(Duration::from_secs(18_000)), Duration::from_secs(1_800));
        // 短跑：下限 15min，20s 短跑不写 checkpoint
        assert_eq!(checkpoint_interval(Duration::from_secs(20)), Duration::from_secs(900));
        assert_eq!(checkpoint_interval(Duration::from_secs(600)), Duration::from_secs(900));
    }

    #[test]
    fn checkpoint_writes_summary_latest_when_due() {
        static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir()
            .join(format!("xray-stress-checkpoint-{}-{seq}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        rt.block_on(async {
            let h = StatsHandle::new("s1-short");
            let mut s = Sampler::new("run-cp", &dir, vec![h], Duration::from_millis(0)).unwrap();
            assert!(s.maybe_checkpoint(Duration::from_secs(600), 5.0, "test").unwrap());
            assert!(dir.join("summary-latest.md").exists(), "checkpoint 必须落盘");
        });
        let _ = std::fs::remove_dir_all(&dir);
    }
}
