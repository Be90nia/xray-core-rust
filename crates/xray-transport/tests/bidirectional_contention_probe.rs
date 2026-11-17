//! 方向饥饿探针（issue #22 疑问 2）——**只测量，不改产品代码**。
//!
//! 测什么：两个方向在**同一个进程级 in-flight 预算**上同时申请许可时，是否出现
//! 「某方向长期零进展、另一方向独占」的不公平等待形态。
//!
//! 机制定位（静态事实，file:line 见报告）：
//! - `crates/xray-transport/src/bridge.rs:874-875`：每连接两个**独立** `ByteGate` （`up_gate` /
//!   `down_gate`）⇒ per-conn 闸**不**跨方向争用；
//! - 两个闸的 `global` 字段都指向**同一个** `inflight::global()` ⇒
//!   方向只在**进程级预算层**汇合争用——本探针即测该层。
//!
//! 纪律：
//! - 用**独立预算实例**（`InflightBudget::new` ⇒ `autotune=false`，容量不漂、 不碰进程单例
//!   `global()`、不污染其他测试）；
//! - 每轮给出「预算饱和」证据（`peak/total`、`backpressure_waits` 增量）， 否则测的是「没竞争」；
//! - 每场景 ≥3 轮，单轮不作结论。

#![allow(
    clippy::disallowed_methods,
    reason = "测试夹具需真实测量等待时长（Instant::now）与并发起跑（tokio::spawn）；非产品面，不改语义"
)]

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use xray_frame::budget::inflight::InflightBudget;

const MIB: usize = 1024 * 1024;

/// 一次等待判定阈值：快路径 `acquire` 是**同步返回**（一次 CAS，无挂起点 ⇒ µs 级）；
/// 慢路径必然跨过一次挂起 + 唤醒 ⇒ ≥ 亚毫秒。阈值取 500µs 区分二者。
const WAIT_THRESHOLD: Duration = Duration::from_micros(500);

/// 单次申请的挂死上限（超时即记「零进展停滞」，防 CI 无限挂）。
const STALL_LIMIT: Duration = Duration::from_secs(2);

/// 单方向累计读数。
#[derive(Debug, Default, Clone, Copy)]
struct DirStats {
    /// 窗口内最终拿到许可的次数（进展计数）。
    permits: u64,
    /// 判定为「等了」的申请次数（elapsed ≥ 阈值）。
    waits: u64,
    /// 累计等待时长（ns）。
    wait_total_ns: u64,
    /// 单次最长等待（ns）。
    wait_max_ns: u64,
    /// 首次拿到许可的延迟（ns）——启动期的独占形态。
    first_grant_ns: u64,
    /// 相邻两次拿到许可之间的最大间隔（ns）——**零进展窗口**的直接量度。
    gap_max_ns: u64,
    /// 申请挂死（超时）次数——硬性零进展证据。
    stalls: u64,
}

/// 一个方向的任务：在 `deadline` 前反复申请 → 持有 `hold` → 归还。
async fn run_direction(
    budget: Arc<InflightBudget>,
    chunk: usize,
    hold: Duration,
    deadline: Instant,
) -> DirStats {
    let mut st = DirStats::default();
    let mut last_grant: Option<Instant> = None;
    let t_start = Instant::now();
    while Instant::now() < deadline {
        let t0 = Instant::now();
        let Ok(permit) = tokio::time::timeout(STALL_LIMIT, budget.acquire(chunk)).await else {
            st.stalls += 1;
            break;
        };
        let t1 = Instant::now();
        let elapsed = t1.duration_since(t0);
        if elapsed >= WAIT_THRESHOLD {
            st.waits += 1;
            st.wait_total_ns += elapsed.as_nanos() as u64;
            st.wait_max_ns = st.wait_max_ns.max(elapsed.as_nanos() as u64);
        }
        if last_grant.is_none() {
            st.first_grant_ns = t1.duration_since(t_start).as_nanos() as u64;
        }
        if let Some(prev) = last_grant {
            st.gap_max_ns = st.gap_max_ns.max(t1.duration_since(prev).as_nanos() as u64);
        }
        last_grant = Some(t1);
        st.permits += 1;
        tokio::time::sleep(hold).await;
        drop(permit);
    }
    st
}

/// 一轮：一个独立预算实例 + 两个方向并发。
async fn one_round(
    total: usize,
    chunk_up: usize,
    chunk_down: usize,
    hold: Duration,
    window: Duration,
) -> (DirStats, DirStats, u64, usize) {
    let budget = InflightBudget::new(total);
    let waits0 = budget.backpressure_waits();
    let deadline = Instant::now() + window;
    let (up, down) = tokio::join!(
        run_direction(Arc::clone(&budget), chunk_up, hold, deadline),
        run_direction(Arc::clone(&budget), chunk_down, hold, deadline),
    );
    let waits_delta = budget.backpressure_waits() - waits0;
    (up, down, waits_delta, budget.peak())
}

/// 打印一行汇总（`--nocapture` 下贴进报告）。
fn report(
    tag: &str,
    round: usize,
    up: DirStats,
    down: DirStats,
    waits_delta: u64,
    peak: usize,
    total: usize,
) {
    println!(
        "{tag} r{round} | up: permits={} waits={} wait_total={:.1}ms wait_max={:.1}ms first_grant={:.1}ms gap_max={:.1}ms stalls={} \
         | down: permits={} waits={} wait_total={:.1}ms wait_max={:.1}ms first_grant={:.1}ms gap_max={:.1}ms stalls={} \
         | 饱和证据: peak_used={peak}B/{total}B backpressure_waits_delta={waits_delta}",
        up.permits,
        up.waits,
        up.wait_total_ns as f64 / 1e6,
        up.wait_max_ns as f64 / 1e6,
        up.first_grant_ns as f64 / 1e6,
        up.gap_max_ns as f64 / 1e6,
        up.stalls,
        down.permits,
        down.waits,
        down.wait_total_ns as f64 / 1e6,
        down.wait_max_ns as f64 / 1e6,
        down.first_grant_ns as f64 / 1e6,
        down.gap_max_ns as f64 / 1e6,
        down.stalls,
    );
}

/// 场景 A：**紧预算**（总量 = 1 块，块 = 1 块）——两方向只能轮流占同一份额，最尖锐的争用面。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scenario_tight_single_slot() {
    let (total, chunk) = (MIB, MIB);
    for round in 1..=3 {
        let (up, down, waits_delta, peak) =
            one_round(total, chunk, chunk, Duration::from_millis(1), Duration::from_millis(600))
                .await;
        report("A/tight", round, up, down, waits_delta, peak, total);
        assert!(peak >= total, "预算必须被打满，否则测的不是争用");
        assert!(waits_delta > 0, "必须出现真实等待（背压计数增量）");
        assert!(up.permits > 0 && down.permits > 0, "两方向都必须有进展");
        assert_eq!(up.stalls, 0);
        assert_eq!(down.stalls, 0);
    }
}

/// 场景 B：**两槽**（总量 = 2 块，块 = 1 块）——两方向各占一块，恰好不排队（边界对照）。
///
/// 期望形态是**零等待**：任一方向处于 `acquire` 的瞬间自己不持许可，对端至多持
/// 1 块 ⇒ `cur + 1 ≤ total` 恒成立，快路径必中，全局背压计数必须零增量。
/// 该断言若红 = 预算判定/归还路径有 bug（而非竞争形态），属确定性失败信号。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scenario_two_slots() {
    let (total, chunk) = (2 * MIB, MIB);
    for round in 1..=3 {
        let (up, down, waits_delta, peak) =
            one_round(total, chunk, chunk, Duration::from_millis(1), Duration::from_millis(600))
                .await;
        report("B/two-slots", round, up, down, waits_delta, peak, total);
        assert_eq!(
            waits_delta, 0,
            "两槽装得下两方向各一块 ⇒ 零排队（waits 增量必须为 0；>0 = 预算判定/归还 bug）"
        );
        assert!(up.permits > 0 && down.permits > 0, "两方向都必须有进展");
        assert_eq!(up.stalls, 0);
        assert_eq!(down.stalls, 0);
    }
}

/// 场景 C：**零等待对照**（总量 = 16 块）——预算不 binding，验证「测的确实是竞争面」。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scenario_no_contention_control() {
    let (total, chunk) = (16 * MIB, MIB);
    for round in 1..=3 {
        let (up, down, waits_delta, peak) =
            one_round(total, chunk, chunk, Duration::from_millis(1), Duration::from_millis(600))
                .await;
        report("C/control", round, up, down, waits_delta, peak, total);
        assert_eq!(up.waits, 0, "预算不 binding 时不得有等待（否则本用例失效）");
        assert_eq!(down.waits, 0);
    }
}

/// 场景 D：**持有期归零**（紧预算 + 立即归还）——最大化「唤醒后被后来者抢走」的窗口，
/// 即 `try_take` 无 FIFO 时的 barging 面。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scenario_tight_zero_hold() {
    let (total, chunk) = (MIB, MIB);
    for round in 1..=3 {
        let (up, down, waits_delta, peak) =
            one_round(total, chunk, chunk, Duration::ZERO, Duration::from_millis(600)).await;
        report("D/tight-zero-hold", round, up, down, waits_delta, peak, total);
        assert!(waits_delta > 0, "必须出现真实等待（背压计数增量）");
        assert!(up.permits > 0 && down.permits > 0, "两方向都必须有进展");
        assert_eq!(up.stalls, 0);
        assert_eq!(down.stalls, 0);
    }
}

/// 场景 E：**单块超预算**（总量 = 1 块，块 = 4 块）——`try_take` 的 `cur == 0` 放行分支
/// 与「账非空即阻塞」分支交界处（软上界语义），方向争用形态的极端面。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scenario_oversize_block() {
    let (total, chunk) = (MIB, 4 * MIB);
    for round in 1..=3 {
        let (up, down, waits_delta, peak) =
            one_round(total, chunk, chunk, Duration::from_millis(1), Duration::from_millis(600))
                .await;
        report("E/oversize", round, up, down, waits_delta, peak, total);
        assert!(waits_delta > 0, "必须出现真实等待（背压计数增量）");
        assert!(up.permits > 0 && down.permits > 0, "两方向都必须有进展");
        assert_eq!(up.stalls, 0);
        assert_eq!(down.stalls, 0);
    }
}

/// 场景 F：**不对称需求**——上方向每轮拿 2 块、下方向每轮拿 1 块，观察小预算下
/// 「重需求方向是否把轻需求方向挤到零进展」。这是 issue 里「某方向独占」形态的直译。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scenario_asymmetric_demand() {
    let (total, chunk_up, chunk_down) = (4 * MIB, 2 * MIB, MIB);
    for round in 1..=3 {
        let (up, down, waits_delta, peak) = one_round(
            total,
            chunk_up,
            chunk_down,
            Duration::from_millis(1),
            Duration::from_millis(600),
        )
        .await;
        report("F/asym", round, up, down, waits_delta, peak, total);
        assert!(up.permits > 0 && down.permits > 0, "两方向都必须有进展");
        assert_eq!(up.stalls, 0);
        assert_eq!(down.stalls, 0);
    }
}

/// 场景 G（**决定性对照**）：**两方向代码完全对称** + Barrier 同时起跑。
///
/// 目的：把「方向不公平」与「先手/唤醒后被后来者 CAS 抢走（无 FIFO barging）」区分开。
/// 两方向跑的是**同一份代码** ⇒ 方向标签不可能成为原因。观测量：
/// 「先拿到第一个许可的方向」是否就是最终独占方。
/// - 若「先手方赢」占比 ≈ 100% ⇒ 独占由**获取顺序**决定（无 FIFO 的 barging），
///   上行/下行谁先拿到首块取决于时序 ⇒ **方向饥饿是时序派生的，不是方向语义**；
/// - 若胜负与先手无关 ⇒ 才可能是方向语义本身的不公平。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scenario_symmetric_swap_order() {
    let (total, chunk) = (MIB, MIB);
    let (first_mover_wins, first_mover_loses, ties, up_wins, down_wins) =
        symmetric_race(total, chunk, Duration::from_millis(1), 12).await;
    println!(
        "G/symmetric | 对称代码 + Barrier 同时起跑 12 轮：先拿到首块方最终独占={first_mover_wins} 轮 \
         先手方反而落后={first_mover_loses} 轮 平局={ties} 轮 | 独占方为 up 的轮数={up_wins} 为 down 的轮数={down_wins} \
         （独占 = 该方向许可数 ≥ 10 倍对手）"
    );
    assert!(first_mover_wins + first_mover_loses + ties == 12, "轮次计数必须完整");
    assert!(up_wins + down_wins + ties == 12, "独占方计数必须完整");
    assert!(first_mover_wins > first_mover_loses, "独占须与获取顺序强相关（否则另有原因）");
}

/// 场景 H：**生产同比例**（总量 = 4 MiB，块 = 512 KiB ⇒ 8 个槽）——块小于总预算时
/// 是否仍出现独占（对照「单槽极端」与「多槽常态」）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scenario_production_ratio() {
    let (total, chunk) = (4 * MIB, 512 * 1024);
    for round in 1..=3 {
        let (up, down, waits_delta, peak) =
            one_round(total, chunk, chunk, Duration::from_millis(1), Duration::from_millis(600))
                .await;
        report("H/prod-ratio", round, up, down, waits_delta, peak, total);
        assert!(up.permits > 0 && down.permits > 0, "两方向都必须有进展");
        assert_eq!(up.stalls, 0);
        assert_eq!(down.stalls, 0);
    }
}

/// 对称竞速：两方向跑同一份代码、Barrier 同时起跑。
/// 返回 (先手方独占轮, 先手方落后轮, 平局轮, 独占方=up 的轮, 独占方=down 的轮)。
async fn symmetric_race(
    total: usize,
    chunk: usize,
    hold: Duration,
    rounds: usize,
) -> (usize, usize, usize, usize, usize) {
    let mut first_wins = 0usize;
    let mut first_loses = 0usize;
    let mut ties = 0usize;
    let mut up_wins = 0usize;
    let mut down_wins = 0usize;
    for _ in 0..rounds {
        let budget = InflightBudget::new(total);
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let deadline = Instant::now() + Duration::from_millis(300);
        let up_task = {
            let budget = Arc::clone(&budget);
            let barrier = Arc::clone(&barrier);
            tokio::spawn(async move {
                barrier.wait().await;
                run_direction(budget, chunk, hold, deadline).await
            })
        };
        let down_task = {
            let budget = Arc::clone(&budget);
            let barrier = Arc::clone(&barrier);
            tokio::spawn(async move {
                barrier.wait().await;
                run_direction(budget, chunk, hold, deadline).await
            })
        };
        let up = up_task.await.expect("方向任务不得 panic（panic 即探针失效）");
        let down = down_task.await.expect("方向任务不得 panic（panic 即探针失效）");
        // 谁先拿到首块（first_grant 小者 = 先手方）。
        let up_first = up.first_grant_ns <= down.first_grant_ns;
        let (hi, lo) = if up.permits >= down.permits {
            (up.permits, down.permits)
        } else {
            (down.permits, up.permits)
        };
        let exclusive = lo == 0 || hi >= lo * 10;
        if exclusive {
            if up.permits > down.permits {
                up_wins += 1;
            } else {
                down_wins += 1;
            }
            if (up_first && up.permits > down.permits) || (!up_first && down.permits > up.permits) {
                first_wins += 1;
            } else {
                first_loses += 1;
            }
        } else {
            ties += 1;
        }
    }
    (first_wins, first_loses, ties, up_wins, down_wins)
}
