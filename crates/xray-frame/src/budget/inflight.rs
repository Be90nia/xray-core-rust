//! 进程级 in-flight 字节预算（跨连接聚合闸）——`plan.rs` 记的「全局共享配额终态」。
//!
//! ## 为什么需要它
//!
//! 桥的每连接、每方向字节闸（`xray_transport::bridge::ByteGate`）只封**单连接**：
//! N 条连接可同时各占 `2 × bridge_gate`，合计 `max_conns × 2 × gate` 与整机预算是
//! 3.3×–21× 过订（bd zbsbc 实测）。旧处置是「如实登记进 caps 栏 + WARN」，
//! 因为**收紧连接数**会直接砍并发（四档只剩 4/4/4/8 条 = 功能回退，PM 打回）。
//!
//! 本件是那条上界的替代答案：跨连接合计由**一个进程级预算**兜住，容量取档位总预算
//! 的一半（[`default_total`]），因此
//! - 并发数**不降**（预算按字节记账，不按连接数截断）；
//! - 合计在途 ≤ 预算（构造上自洽：许可未归还前不会被超发）；
//! - 预算耗尽时**等待（背压）而非拒绝**——对齐 Go：上游没有连接总数硬限制， 它靠动态缓冲 +
//!   GC/背压，我们靠「取不到许可就等」。
//!
//! ## 语义
//!
//! - [`InflightBudget::acquire`]：取 `bytes` 字节许可，账上装得下才返回（未耗尽时 只多一次原子读 +
//!   一次 CAS，无锁无等待）；装不下就挂在 [`tokio::sync::Notify`] 上等释放，**不自旋**。
//! - 单块 > 预算时**直通**（`used == 0` 即放行）：预算是软上界，堵死 = 连接挂死 （同 `ByteGate`
//!   的既有口径）。
//! - 释放走 [`InflightPermit`] 的 `Drop` ⇒ 错误/中止路径天然归还，无泄漏。
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
            // 先登记等待者再判定：`Notify` 的 `notified()` 首次 poll 才注册，
            // 「判定失败 → 对端 release+notify_waiters → 本任务 await」之间会漏
            // 唤醒 ⇒ 永久挂住。`enable()` 提前注册即消除该竞态。
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
                // 单块超预算永不阻塞（预算软上界，堵死 = 连接挂死）：只在本来空账
                // 或装得下时放行。并发下两个大块可能同时通过判定而少量超账——软上界。
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
        // 广播：唤醒者里只有一个能装上（其余重试再等），点对点会漏唤醒其余等待者。
        self.notify.notify_waiters();
    }
}

/// 进程级预算单例（首次访问时按档位派生容量）。
pub fn global() -> &'static Arc<InflightBudget> {
    static GLOBAL: LazyLock<Arc<InflightBudget>> =
        LazyLock::new(|| InflightBudget::new(default_total()));
    &GLOBAL
}

/// 缺省容量 = 档位总预算的一半（字节）。
///
/// 为什么不取满 `total_budget`：整机预算还要装固定面（池/缓存/握手在飞）与瞬态面
/// （xdns frag / QUIC 窗 / TUIC 信箱），数据面在途只该占自己那一半。四档得
/// 20 / 48 / 96 / `min(available/8, 256)` MiB，最小的 tiny 档（20MiB）仍是实测 BDP
/// 上沿 3.56MB 的 5.6×——预算在正常链路上不 binding（不砍吞吐），只在「写端持续
/// 灌、读端不读」的堆积形态下生效。
#[must_use]
pub fn default_total() -> usize {
    (crate::budget::plan::MemoryPlan::cached().total_budget / 2).max(1)
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
}
