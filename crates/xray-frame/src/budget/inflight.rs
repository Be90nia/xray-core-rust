//! 进程级 in-flight 字节预算（跨连接聚合闸）——`plan.rs` 记的「全局共享配额终态」。
//!
//! ## 为什么需要它
//!
//! 桥的每连接、每方向字节闸（`xray_transport::bridge::ByteGate`）只封**单连接**：
//! N 条连接可同时各占 `2 × bridge_gate`，合计 `max_conns × 2 × gate` 与整机预算是
//! 3.3×–21× 过订（bd zbsbc 实测）。旧处置是「如实登记进 caps 栏 + WARN」，
//! 因为**收紧连接数**会直接砍并发（四档只剩 4/4/4/8 条 = 功能回退，PM 打回）。
//!
//! 本件是那条上界的替代答案：跨连接合计由**一个进程级预算**兜住，容量取
//! `inflight_budget_bytes`（`max(总预算/2, min(并发×闸×2, 可用/4))`），因此
//! - 并发数**不降**（预算按字节记账，不按连接数截断）；
//! - 合计在途 ≤ 预算（构造上自洽：许可未归还前不会被超发）；
//! - 预算耗尽时**等待（背压）而非拒绝**——对齐 Go：上游没有连接总数硬限制， 它靠动态缓冲 +
//!   GC/背压，我们靠「取不到许可就等」。
//!
//! ## 语义
//!
//! - `InflightBudget::acquire`：取 `bytes` 字节许可，账上装得下才返回（未耗尽时 只多一次原子读 +
//!   一次 CAS，无锁无等待）；装不下才进慢路径——先记睡眠者计数、再 `enable()`
//!   注册等待者并重试一次，仍装不下才挂上等释放，**不自旋**。
//! - `release` 只在有睡眠者时广播（`sleepers == 0` 时零锁返回）：稳态绝大多数
//!   归还都没有等待者，旧形态无条件 `notify_waiters()` 等于每批一次进程级互斥。
//! - 单块 > 预算时**直通**（`used == 0` 即放行）：预算是软上界，堵死 = 连接挂死 （同 `ByteGate`
//!   的既有口径）。
//! - 释放走 `InflightPermit` 的 `Drop` ⇒ 错误/中止路径天然归还，无泄漏。
//! - 广播唤醒（`notify_waiters`）而非 `notify_one`：被唤醒的等待者可能装不下
//!   （大块优先），点对点唤醒会让其余等待者漏唤醒。公平性由 CAS 竞争提供：
//!   先到先得，无饥饿保证但无忙旋。
//! - **背压计数**（`InflightBudget::backpressure_waits`）与**峰值**（`InflightBudget::peak`）：
//!   运维区别「闸在承载过载」与「网络故障」的判据（bd uaoby R-3）。
//! - **实况重探测**（`InflightBudget::resample`）：启动档位是单点 `MemAvailable`
//!   快照（开机时别人占着内存就永久落小档，bd uaoby R-4）。慢路径在触顶时每 4096
//!   次背压至多重算一次容量（幅度 < 1/8 视为噪声不动），实况变差收紧、变好放宽。容量恒由实况派生 ⇒
//!   物理装不下时仍是背压，不是拒绝。**只有合计这一把杠杆
//!   跟随实况**：单连接闸（`bridge_gate`）与连接软上限仍是启动快照——它们不是内存
//!   上界（前者只是单连接上界，后者触顶只 WARN），物理上界由本预算独立兜住。
//!
//! 归属（CLAUDE.md §3.5.5）：预算容量绑 Xray 内存档位（`MemoryPlan`）⇒ Xray 语义
//! ⇒ 派生层 `xray-frame`。记账机制本身零 Xray 语义，将来随 `MemoryPlan` 一起上浮。

use std::sync::{
    Arc, LazyLock,
    atomic::{AtomicU64, AtomicUsize, Ordering},
};

use tokio::sync::Notify;

/// 进程级在途字节预算（单例见 [`global`]；测试可 [`InflightBudget::new`] 造独立实例）。
#[derive(Debug)]
pub struct InflightBudget {
    /// 容量（字节）。运行期可被重采样改写（[`Self::resample`]），故非 `const`。
    total: AtomicUsize,
    used: AtomicUsize,
    peak: AtomicUsize,
    /// 正挂在 [`Notify`] 上等的任务数（慢路径计数门）。
    sleepers: AtomicUsize,
    /// 慢路径进入次数（= 曾经等过预算的块数）。运维判据：单调增说明闸在承载过载，
    /// 而不是网络慢（bd uaoby R-3 的「闸在工作 vs 故障」分辨面）。
    backpressure_waits: AtomicU64,
    /// 实际生效过的重采样次数（容量真的变了才 +1）。
    resamples: AtomicU64,
    /// 是否允许按实况可用内存自调容量。只有进程单例开（[`global`]）——测试造的
    /// 独立实例容量由用例钉死，不得被本机实况改写。
    autotune: bool,
    notify: Notify,
}

/// 在途字节许可（drop 即归还）。跨 `.await` 持有安全：与 [`InflightBudget`] 之间
/// 是 `Arc` 关系，无借用。
#[derive(Debug)]
#[must_use = "许可随 drop 归还；立即丢弃 = 没记账"]
pub struct InflightPermit {
    budget: Arc<InflightBudget>,
    bytes: usize,
}

impl Drop for InflightPermit {
    fn drop(&mut self) {
        self.budget.release(self.bytes);
    }
}

impl InflightPermit {
    /// 把记账责任交出去（`(预算句柄, 字节数)`），本许可随之失效（不再 drop 归还）。
    ///
    /// 唯一消费者 = **组合许可**：`xray_transport::bridge` 的 `GatePermit` 要把本预算
    /// 与 per-conn 方向闸合成一张许可（一块数据一份），归还要与另一个原子计数在同
    /// 一处完成；拿句柄后由它调 [`InflightBudget::release`]。
    #[must_use = "拿到的句柄必须用于归还，否则账本永久占用"]
    pub fn into_parts(self) -> (Arc<InflightBudget>, usize) {
        let parts = (Arc::clone(&self.budget), self.bytes);
        std::mem::forget(self);
        parts
    }
}

impl InflightBudget {
    /// 建独立预算（`total` 夹到 ≥ 1：0 = 永不放行，等于把数据面锁死）。
    ///
    /// **不自调容量**：容量由调用方钉死（测试/显式注入）。要按实况内存自调的是进程
    /// 单例，见 [`global`]。
    #[must_use]
    pub fn new(total: usize) -> Arc<Self> {
        Self::with_autotune(total, false)
    }

    fn with_autotune(total: usize, autotune: bool) -> Arc<Self> {
        Arc::new(Self {
            total: AtomicUsize::new(total.max(1)),
            used: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            sleepers: AtomicUsize::new(0),
            backpressure_waits: AtomicU64::new(0),
            resamples: AtomicU64::new(0),
            autotune,
            notify: Notify::new(),
        })
    }

    /// 预算容量（字节）。运行期可能被重采样改写（[`Self::resample`]）。
    #[must_use]
    pub fn total(&self) -> usize {
        self.total.load(Ordering::Acquire)
    }

    /// 当前在途（字节）。
    #[must_use]
    pub fn used(&self) -> usize {
        self.used.load(Ordering::Acquire)
    }

    /// 历史峰值（字节）——运维/压测判据：常态远低于 `total` 才说明预算不 binding。
    #[must_use]
    pub fn peak(&self) -> usize {
        self.peak.load(Ordering::Acquire)
    }

    /// 曾因预算装不下而等待的块数累计（背压次数，单调增）。
    #[must_use]
    pub fn backpressure_waits(&self) -> u64 {
        self.backpressure_waits.load(Ordering::Relaxed)
    }

    /// 容量被重采样改写的次数（单调增；长期为 0 = 实况内存稳定或从未触顶）。
    #[must_use]
    pub fn resamples(&self) -> u64 {
        self.resamples.load(Ordering::Relaxed)
    }

    /// 取 `bytes` 字节在途许可；预算装不下就等（背压），**不拒绝**。
    ///
    /// 中止语义：调用方用 `tokio::select!` 包住本 future 时，未取到许可即被丢弃
    /// ⇒ 账上零变化（计数只在取到后加）。
    pub async fn acquire(self: &Arc<Self>, bytes: usize) -> InflightPermit {
        // 快路径：账上装得下就零锁返回——`Notify` 的入链/出链/广播全不进。旧形态
        // 每批都先 `enable()` 注册等待者，稳态热路径上白付三次进程级互斥
        //（tokio `Notify` 的 waiters 链表锁）。
        if self.try_take(bytes) {
            return InflightPermit { budget: Arc::clone(self), bytes };
        }
        let waits = self.backpressure_waits.fetch_add(1, Ordering::Relaxed) + 1;
        // 已经在等了 ⇒ 此刻付一次 `/proc/meminfo` 的代价是划算的（bd uaoby R-4：
        // 启动快照的档位不会自己回头）。按次数限量 + 滞回，稳态零代价。
        self.resample_periodically(waits);
        loop {
            // 慢路径：先记睡眠者、再登记等待者，然后**立刻重试一次**。不丢唤醒靠的
            // 是后两步与 `release` 的配合：`release` 先减账、再查睡眠者计数，所以
            // 要么它的广播看见本任务（本任务已被登记），要么本任务这次重试看得见
            // 那次减账——不存在「广播已发、账已减、本任务却没重试就睡下」的窗口。
            let _sleeper = SleeperGuard::new(&self.sleepers);
            let mut notified = std::pin::pin!(self.notify.notified());
            let _ = notified.as_mut().enable();
            // 登记与上一轮判定之间可能有归还落地：立刻重试一次，避免白睡一轮。
            if self.try_take(bytes) {
                return InflightPermit { budget: Arc::clone(self), bytes };
            }
            notified.await;
        }
    }

    /// 尝试占账（`fetch_update` 保证「判定 + 自增」不可分割，不会超发）。
    fn try_take(&self, bytes: usize) -> bool {
        let Ok(prev) = self.used.fetch_update(Ordering::AcqRel, Ordering::Acquire, |cur| {
            // 单块超预算永不阻塞（预算软上界，堵死 = 连接挂死）：只在本来空账
            // 或装得下时放行。并发下两个大块可能同时通过判定而少量超账——软上界。
            (cur == 0 || cur.saturating_add(bytes) <= self.total())
                .then(|| cur.saturating_add(bytes))
        }) else {
            return false;
        };
        // 成功的 CAS 返回值 = 占账前的读数，故 `prev + bytes` 就是本次占账后的
        // 真实 `used`（峰值只可能在占账后出现）——省掉一次 `used.load`。
        self.peak.fetch_max(prev.saturating_add(bytes), Ordering::AcqRel);
        true
    }

    /// 显式重探测：按**实况**可用内存重算容量（bd uaoby R-4）。
    ///
    /// 返回 `(旧容量, 新容量)`；无实质变化时 `None`。进程单例还会在背压慢路径上
    /// 限量自动调它（`resample_periodically`），本方法留给周期任务/运维 API
    /// 显式触发。
    pub fn resample(&self) -> Option<(usize, usize)> {
        self.apply_available(crate::budget::plan::live_available())
    }

    /// 慢路径自动重采样：**首次**背压就探一次（启动快照落小档要立刻纠正，不等累积），
    /// 之后每累计 [`RESAMPLE_EVERY_WAITS`] 次才再探。
    ///
    /// 按**背压次数**而非时间节流：不用裸时钟（坑约束 3：`Instant::now` 被 clippy 禁用，
    /// 要注入 `Clock`），且成本天然跟负载挂钩——探测成本 ∝ 过载量，稳态与全停时都是
    /// 零探测（全停时不再有新块进来，计数不涨）。
    fn resample_periodically(&self, waits: u64) {
        if self.autotune && (waits == 1 || waits.is_multiple_of(RESAMPLE_EVERY_WAITS)) {
            let _ = self.resample();
        }
    }

    /// 重采样的纯函数面（实况值由调用方给，单测不碰平台探测）：按 `available` 重算
    /// 容量并落账，返回 `(旧, 新)`；与现容量差异 < 1/8 视为噪声不动（滞回）。
    fn apply_available(&self, available: u64) -> Option<(usize, usize)> {
        // 我们自己的在途页也记在「不可用」里：把它加回来，避免自激——自身压力不得
        // 反过来压低自己的上限（否则越堵越紧，吞吐自噬；预算是软上界，物理装不下
        // 时本来就靠背压兜）。
        let live = available.saturating_add(self.used() as u64);
        let target = crate::budget::plan::inflight_budget_for_live(live).max(1);
        let old = self.total();
        if !materially_differs(old, target) {
            return None;
        }
        self.total.store(target, Ordering::Release);
        self.resamples.fetch_add(1, Ordering::Relaxed);
        // 扩容 ⇒ 等待者应立即前进；缩容 ⇒ 也让它们按新容量重判一次（被唤醒后装不下
        // 就继续等，不丢唤醒）。
        self.notify.notify_waiters();
        // fail-visible：档位/容量自己漂了必须留痕（调用点已按背压次数限量）。
        // 收紧是 OOM 防线的动作，必须 warn；放宽是快照纠正，info 即可。
        if target < old {
            tracing::warn!(
                target: "xray_frame::budget",
                old,
                new = target,
                live_available = live,
                "进程级 in-flight 预算按实况内存**收紧**（实况可用少了；超出走背压不拒连）"
            );
        } else {
            tracing::info!(
                target: "xray_frame::budget",
                old,
                new = target,
                live_available = live,
                "进程级 in-flight 预算按实况内存**放宽**（启动快照落小档已被实况纠正）"
            );
        }
        Some((old, target))
    }

    /// 归还 `bytes` 字节（`InflightPermit::drop` 的实现路径）。
    ///
    /// 公开的唯一理由：**组合许可**——`xray_transport::bridge` 的 `GatePermit` 把本
    /// 预算与它的 per-conn 方向闸合成一张许可（一块数据一份），drop 时直接调本方法
    /// 归还全局那一半。裸调本方法而不曾 [`Self::acquire`] 会把账本算少（`fetch_sub`
    /// 下溢），除组合许可外不要用。
    pub fn release(&self, bytes: usize) {
        self.used.fetch_sub(bytes, Ordering::AcqRel);
        // 无睡眠者就零锁返回：`notify_waiters` 恒进等待者链表锁（tokio 无空表短路），
        // 而稳态绝大多数 release 都没有等待者。有睡眠者时仍**广播**（不能换
        // `notify_one`：被唤醒者可能装不下大块，点对点会让其余等待者漏唤醒）。
        // 查计数必须在减账**之后**：反了会让刚入列的等待者错过本次广播——它重试时
        // 读到的还是没减的账 ⇒ 永久挂住。
        if self.sleepers.load(Ordering::SeqCst) > 0 {
            self.notify.notify_waiters();
        }
    }
}

/// 睡眠者计数守卫：进入等待前 +1，离开（取到而返回 / 被唤醒 / future 被 `select!`
/// 丢弃）时 −1。少减一次会让计数永久 > 0 ⇒ `release` 恒广播（计数门静默失效）。
struct SleeperGuard<'a>(&'a AtomicUsize);

impl<'a> SleeperGuard<'a> {
    fn new(counter: &'a AtomicUsize) -> Self {
        counter.fetch_add(1, Ordering::SeqCst);
        Self(counter)
    }
}

impl Drop for SleeperGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// 慢路径自动重采样的间隔（背压次数）：每累计这么多次「装不下」才探一次实况可用
/// 内存。一次 `/proc/meminfo` 读约 10µs，而 4096 次背压对应 ≥ 数 GB 的传输量 ⇒
/// 探测成本可忽略；反过来过载越狠探得越勤，稳态零探测。
const RESAMPLE_EVERY_WAITS: u64 = 4096;

/// 容量变更是否**实质**（差 > 1/8）：`MemAvailable` 常态抖动几 % 不该让预算反复缩涨。
fn materially_differs(a: usize, b: usize) -> bool {
    let (hi, lo) = if a >= b { (a, b) } else { (b, a) };
    hi - lo > hi / 8
}

/// 进程级预算单例（首次访问时按档位派生容量；**慢路径按实况内存自调**）。
pub fn global() -> &'static Arc<InflightBudget> {
    static GLOBAL: LazyLock<Arc<InflightBudget>> =
        LazyLock::new(|| InflightBudget::with_autotune(default_total(), true));
    &GLOBAL
}

/// 缺省容量 = [`MemoryPlan::inflight_budget_bytes`](crate::budget::plan::MemoryPlan::inflight_budget_bytes)
/// （唯一事实源：`max(total_budget/2, min(max_conns × bridge_gate × 2, available/4))`）。
///
/// 2026-11-15 生产回归后修正：旧口径「恒取 total_budget/2」在 small 档只有 48MiB，
/// 10 条 60MB/s@200ms 连接需 ~120MB ⇒ 每条分 ~4.8MB，吞吐按比例砍半且全协议同抖。
/// 新容量按「并发 × 单方向闸」与「物理可用 1/4」双上界派生，多连接测速不再 binding；
/// 超并发时仍背压（物理内存装不下就是装不下）。
#[must_use]
pub fn default_total() -> usize {
    crate::budget::plan::MemoryPlan::cached().inflight_budget_bytes()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    const MIB: usize = 1024 * 1024;

    /// 装满后必须**等**（不是拒绝、不是自旋放行）；归还后立即放行。
    #[tokio::test]
    async fn acquire_waits_when_full_then_proceeds_on_release() {
        let budget = InflightBudget::new(4 * MIB);
        let held = budget.acquire(4 * MIB).await;
        assert_eq!(budget.used(), 4 * MIB);

        let blocked = tokio::spawn({
            let budget = Arc::clone(&budget);
            async move { budget.acquire(1).await }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!blocked.is_finished(), "预算耗尽时必须等待（背压），不得放行/拒绝");
        assert_eq!(budget.used(), 4 * MIB, "等待期间账上零变化");

        drop(held);
        let permit = tokio::time::timeout(Duration::from_secs(1), blocked)
            .await
            .expect("归还后必须放行")
            .expect("join");
        assert_eq!(budget.used(), 1);
        drop(permit);
        assert_eq!(budget.used(), 0);
        assert_eq!(budget.peak(), 4 * MIB);
    }

    /// 聚合上界：N 个并发任务各取许可，任一时刻在途合计 ≤ 预算（构造自洽）。
    #[tokio::test]
    async fn aggregate_inflight_never_exceeds_total() {
        let budget = InflightBudget::new(8 * MIB);
        let max_seen = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let budget = Arc::clone(&budget);
            let max_seen = Arc::clone(&max_seen);
            tasks.push(tokio::spawn(async move {
                for _ in 0..4 {
                    let permit = budget.acquire(3 * MIB).await;
                    max_seen.fetch_max(budget.used(), Ordering::AcqRel);
                    tokio::time::sleep(Duration::from_millis(1)).await;
                    drop(permit);
                }
            }));
        }
        for t in tasks {
            t.await.expect("join");
        }
        assert!(
            max_seen.load(Ordering::Acquire) <= 8 * MIB,
            "在途合计 {} 超预算（8MiB）",
            max_seen.load(Ordering::Acquire)
        );
        assert_eq!(budget.used(), 0, "全部归还后账本必须归零（无泄漏）");
    }

    /// 单块 > 预算直通（软上界）：否则「一块比预算还大」即连接挂死。
    #[tokio::test]
    async fn single_oversize_block_passes_when_empty() {
        let budget = InflightBudget::new(1024);
        let permit = tokio::time::timeout(Duration::from_secs(1), budget.acquire(4096))
            .await
            .expect("超预算单块必须放行");
        drop(permit);
        assert_eq!(budget.used(), 0);
    }

    /// 被丢弃的 acquire future 不得留下账目（中止路径零泄漏）。
    #[tokio::test]
    async fn aborted_acquire_leaves_no_charge() {
        let budget = InflightBudget::new(2 * MIB);
        let held = budget.acquire(2 * MIB).await;
        let pending = budget.acquire(MIB);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), pending).await.is_err(),
            "满载时必须等"
        );
        assert_eq!(budget.used(), 2 * MIB);
        drop(held);
        assert_eq!(budget.used(), 0);
    }

    /// 睡眠者计数只减不欠账：快路径不记、等待中记、唤醒/中止后销账。计数漏减会让
    /// `release` 恒广播（计数门静默失效，热路径优化白做）。
    #[tokio::test]
    async fn sleeper_count_settles_to_zero() {
        let budget = InflightBudget::new(MIB);
        let held = budget.acquire(MIB).await;
        assert_eq!(budget.sleepers.load(Ordering::SeqCst), 0, "快路径不得记睡眠者");

        let waiter = tokio::spawn({
            let budget = Arc::clone(&budget);
            async move { budget.acquire(1).await }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(budget.sleepers.load(Ordering::SeqCst), 1, "等预算时必须登记睡眠者");
        drop(held);
        let permit = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("归还后必须放行")
            .expect("join");
        assert_eq!(budget.sleepers.load(Ordering::SeqCst), 0, "唤醒后必须销账");

        // 中止路径：等待中 future 被丢弃（调用方 select! 超时）也必须销账。
        assert!(
            tokio::time::timeout(Duration::from_millis(50), budget.acquire(2 * MIB)).await.is_err(),
            "账非空且装不下 ⇒ 必须等"
        );
        assert_eq!(budget.sleepers.load(Ordering::SeqCst), 0, "中止的等待者不得留账");
        drop(permit);
        assert_eq!(budget.used(), 0);
    }

    /// 背压计数：**只有真的等过的块**才 +1（快路径零记），且可被外部读到
    /// （bd uaoby R-3「闸在工作」的可观测面）。
    #[tokio::test]
    async fn backpressure_waits_count_only_blocked_blocks() {
        let budget = InflightBudget::new(MIB);
        let held = budget.acquire(MIB).await;
        assert_eq!(budget.backpressure_waits(), 0, "快路径不得计背压");

        let waiter = tokio::spawn({
            let budget = Arc::clone(&budget);
            async move { budget.acquire(1).await }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(budget.backpressure_waits(), 1, "等待中的块必须计入背压");
        assert_eq!(budget.used(), MIB, "等待期间账上零变化");

        drop(held);
        let permit = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("归还后必须放行")
            .expect("join");
        assert_eq!(budget.backpressure_waits(), 1, "放行不得重复计数");
        drop(permit);
        assert_eq!(budget.used(), 0);
    }

    /// 实况重探测：容量按当下可用内存重算（收紧/放宽都跟随），差异 < 1/8 不动
    /// （滞回），`used` 加回去避免自身压力自激（bd uaoby R-4）。
    #[tokio::test]
    async fn resample_retunes_capacity_from_live_available() {
        let budget = InflightBudget::new(200 * MIB);
        // 实况 256MiB（tiny 档）：容量按该实况重算（tiny 档 = 40MiB 预算 / 闸 20MiB
        // / 可用 1/4 ⇒ 64MiB），必须比现容量 200MiB 小。
        let tiny_available = 256 * MIB;
        let expected = crate::budget::plan::inflight_budget_for_live(tiny_available as u64);
        let (old, new) =
            budget.apply_available(tiny_available as u64).expect("实况远小于现容量 ⇒ 必须收紧");
        assert_eq!(old, 200 * MIB);
        assert_eq!(new, expected, "容量必须按实况档位公式重算");
        assert_eq!(budget.total(), expected);
        assert_eq!(budget.resamples(), 1);

        // 同一实况再探一次：无实质变化 ⇒ 不动（不反复记 resamples）。
        assert!(budget.apply_available(tiny_available as u64).is_none(), "无变化不得改写容量");
        assert_eq!(budget.resamples(), 1);

        // 实况变好 ⇒ 放宽（启动快照落小档可被纠正）。
        let big_available = 8 * 1024 * MIB;
        let widened = budget.apply_available(big_available as u64).expect("实况变好必须放宽");
        assert!(widened.1 > widened.0, "放宽后容量必须变大：{widened:?}");
        assert_eq!(budget.total(), widened.1);

        // 滞回：与现容量差 < 1/8 视为噪声。
        let noise = (budget.total() as u64) / 100; // 1%
        assert!(
            budget.apply_available(big_available as u64 + noise).is_none(),
            "1% 抖动必须被滞回吞掉（不得反复缩涨）"
        );
        assert_eq!(budget.backpressure_waits(), 0, "重采样不得被算作背压");
    }

    /// 重采样不得把在途账丢回「装不下」的死锁：被唤醒的等待者在扩容后必须能前进。
    #[tokio::test]
    async fn resample_wakes_waiters_when_capacity_grows() {
        let budget = InflightBudget::new(MIB);
        let held = budget.acquire(MIB).await;
        let waiter = tokio::spawn({
            let budget = Arc::clone(&budget);
            async move { budget.acquire(2 * MIB).await }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!waiter.is_finished(), "2MiB 装不进 1MiB 预算 ⇒ 必须等");

        // 实况充裕 ⇒ 放宽到装得下 2MiB（+ 已占 1MiB）。
        budget.apply_available(8 * 1024 * MIB as u64).expect("必须放宽");
        let permit = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("扩容后等待者必须被唤醒并前进")
            .expect("join");
        drop(permit);
        drop(held);
        assert_eq!(budget.used(), 0);
    }

    /// 独立实例不得自调容量（用例钉死的容量是本机实况无关的契约）。
    #[tokio::test]
    async fn injected_budget_does_not_autotune() {
        let budget = InflightBudget::new(MIB);
        let held = budget.acquire(MIB).await;
        let waiter = tokio::spawn({
            let budget = Arc::clone(&budget);
            async move { budget.acquire(1).await }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(budget.total(), MIB, "独立实例容量不得被实况改写");
        assert_eq!(budget.resamples(), 0);
        drop(held);
        let _permit = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("归还后必须放行")
            .expect("join");
        assert_eq!(budget.total(), MIB);
    }

    /// 任一等待者漏唤醒即永久挂住 ⇒ 超时红（删掉 `release` 的广播即整批挂死，已验）。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_contention_never_loses_wakeup() {
        const UNIT: usize = 64 * 1024;
        let budget = InflightBudget::new(2 * UNIT);
        let mut tasks = Vec::new();
        for _ in 0..16 {
            let budget = Arc::clone(&budget);
            tasks.push(tokio::spawn(async move {
                for _ in 0..100 {
                    let permit = tokio::time::timeout(Duration::from_secs(5), budget.acquire(UNIT))
                        .await
                        .expect("丢唤醒 = 永远拿不到许可（超时即红）");
                    tokio::task::yield_now().await;
                    drop(permit);
                }
            }));
        }
        for t in tasks {
            t.await.expect("join");
        }
        assert_eq!(budget.used(), 0, "全部归还后账本必须归零（无泄漏）");
        assert_eq!(budget.sleepers.load(Ordering::SeqCst), 0, "争用结束后不得留睡眠者");
        assert!(budget.peak() <= 2 * UNIT, "峰值 {} 超预算", budget.peak());
    }
}
