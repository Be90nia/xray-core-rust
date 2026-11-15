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
//!
//! 归属（CLAUDE.md §3.5.5）：预算容量绑 Xray 内存档位（`MemoryPlan`）⇒ Xray 语义
//! ⇒ 派生层 `xray-frame`。记账机制本身零 Xray 语义，将来随 `MemoryPlan` 一起上浮。

use std::sync::{
    Arc, LazyLock,
    atomic::{AtomicUsize, Ordering},
};

use tokio::sync::Notify;

/// 进程级在途字节预算（单例见 [`global`]；测试可 [`InflightBudget::new`] 造独立实例）。
#[derive(Debug)]
pub struct InflightBudget {
    total: usize,
    used: AtomicUsize,
    peak: AtomicUsize,
    /// 正挂在 [`Notify`] 上等的任务数（慢路径计数门）。
    sleepers: AtomicUsize,
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
    #[must_use]
    pub fn new(total: usize) -> Arc<Self> {
        Arc::new(Self {
            total: total.max(1),
            used: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            sleepers: AtomicUsize::new(0),
            notify: Notify::new(),
        })
    }

    /// 预算容量（字节）。
    #[must_use]
    pub fn total(&self) -> usize {
        self.total
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

    /// 取 `bytes` 字节在途许可；预算装不下就等（背压），**不拒绝**。
    ///
    /// 中止语义：调用方用 `tokio::select!` 包住本 future 时，未取到许可即被丢弃
    /// ⇒ 账上零变化（计数只在取到后加）。
    pub async fn acquire(self: &Arc<Self>, bytes: usize) -> InflightPermit {
        loop {
            let mut notified = std::pin::pin!(self.notify.notified());
            let _ = notified.as_mut().enable();
            if self.try_take(bytes) {
                return InflightPermit { budget: Arc::clone(self), bytes };
            }
            notified.await;
        }
    }

    /// 尝试占账（`fetch_update` 保证「判定 + 自增」不可分割，不会超发）。
    fn try_take(&self, bytes: usize) -> bool {
        let taken = self
            .used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |cur| {
                (cur == 0 || cur.saturating_add(bytes) <= self.total)
                    .then(|| cur.saturating_add(bytes))
            })
            .is_ok();
        if taken {
            self.peak.fetch_max(self.used.load(Ordering::Acquire), Ordering::AcqRel);
        }
        taken
    }

    /// 归还 `bytes` 字节（`InflightPermit::drop` 的实现路径）。
    ///
    /// 公开的唯一理由：**组合许可**——`xray_transport::bridge` 的 `GatePermit` 把本
    /// 预算与它的 per-conn 方向闸合成一张许可（一块数据一份），drop 时直接调本方法
    /// 归还全局那一半。裸调本方法而不曾 [`Self::acquire`] 会把账本算少（`fetch_sub`
    /// 下溢），除组合许可外不要用。
    pub fn release(&self, bytes: usize) {
        self.used.fetch_sub(bytes, Ordering::AcqRel);
        self.notify.notify_waiters();
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

/// 进程级预算单例（首次访问时按档位派生容量）。
pub fn global() -> &'static Arc<InflightBudget> {
    static GLOBAL: LazyLock<Arc<InflightBudget>> =
        LazyLock::new(|| InflightBudget::new(default_total()));
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

    /// 并发争用下**不得丢唤醒**：16 任务 × 100 轮抢 2 份额度，每次 acquire 带超时兜底。
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
