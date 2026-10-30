//! 插件审计事件流（L2 能力面第⑦柄；模型 §4 表：`ctx.audit()`，禁等价写法 =
//! 裸 tracing 事件）。
//!
//! 底座 = udf [`skeleton_infra::memgov::BoundedRegistry`]（`EvictOldest` 有界
//! 环）：审计域只借容量纪律，不引 journal 域的 `AuditEvent`（那是
//! skeleton-infra journal dispatch 生命周域专用，SyncStore 内部件）。
//!
//! 环语义对齐 udf 自家审计域的纪律（skeleton-infra/src/audit.rs）：**空洞 =
//! 有界环溢出丢最旧的显式证据**——[`AuditHandle::evicted_count`] 单调记录被逐
//! 出数，禁静默重写历史（对账键：`seq` 在订阅窗内连续，缺口即溢出证据）。
//!
//! 留 xray-frame（ADR-1 默认答案：派生层）。举证：udf 侧无可复用等价件——
//! skeleton-infra/src/audit.rs 的 `AuditEvent{seq, kind}` 是 store/journal 生命
//! 周域的 dispatch 记账节点，与本处 `AuditRecord{seq, plugin, message}` 形状、
//! 用途都不同。

use std::sync::{
    Mutex, MutexGuard,
    atomic::{AtomicU64, Ordering},
};

use skeleton_infra::memgov::{BoundError, BoundedRegistry, Eviction};

/// 缺省审计环容量。每插件实例一份（装配根共享面），1024 条足够事后取证窗口；
/// 超容走 `EvictOldest` + 显式溢出计数，不阻塞发射方。
pub const DEFAULT_AUDIT_RING_CAP: usize = 1024;

/// Mutex 取锁：中毒 = 持锁方已 panic——fail-fast 传播（udf runtime::lock 同纪律）。
fn lock_audit<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().expect("audit ring lock poisoned: prior panic while holding the lock")
}

/// 一条插件审计事件（事后取证值面）。
///
/// `seq` 进程内单调（同一 [`AuditHandle`] 内连续）；`plugin` = 发射插件名；
/// `message` 为渲染后的单行文本（发射方负责不含密钥——掩码纪律归 [`crate::logging::LogFacade`]
/// 面）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    /// 单调序号（Handle 内连续；空洞 = 溢出显式证据）。
    pub seq: u64,
    /// 发射方插件名。
    pub plugin: &'static str,
    /// 渲染后的单行审计文本。
    pub message: String,
}

/// 插件审计事件流句柄（L2 `ctx.audit()` 实体）。
///
/// 共享形态：装配根建一份，`Arc` 注入各插件 [`crate::context::PluginContext`]，
/// 全插件事件落同一环（`plugin` 字段标注归属）。发射 O(log n)（BTreeMap 插入），
/// 无分配路径外的锁竞争面（单 Mutex 串行——审计非热路径）。
pub struct AuditHandle {
    ring: Mutex<BoundedRegistry<u64, AuditRecord>>,
    capacity: usize,
    next_seq: AtomicU64,
    evicted: AtomicU64,
}

impl std::fmt::Debug for AuditHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditHandle")
            .field("capacity", &self.capacity)
            .field("len", &self.len())
            .field("evicted", &self.evicted_count())
            .finish_non_exhaustive()
    }
}

impl AuditHandle {
    /// 构造审计环。`capacity == 0` → panic（`BoundedRegistry` 同款 fail-fast：
    /// 恒满注册表必是 bug）。
    pub fn new(capacity: usize) -> Self {
        Self {
            ring: Mutex::new(BoundedRegistry::new(capacity, Eviction::EvictOldest)),
            capacity,
            next_seq: AtomicU64::new(0),
            evicted: AtomicU64::new(0),
        }
    }

    /// 记一条审计事件，返回其 `seq`。
    ///
    /// 环满 → 逐出最旧（`EvictOldest`）+ [`Self::evicted_count`] 自增——发射
    /// 永不失败、永不阻塞（fail-visible 靠溢出计数，不靠拒收）。
    pub fn record(&self, plugin: &'static str, message: impl std::fmt::Display) -> u64 {
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        let mut ring = lock_audit(&self.ring);
        // 逐出判定必须取**插入前**环态：EvictOldest 下只有「插入前已满」的
        // 插入才逐出；把环从 n-1 填满到 n 的那一插不逐出任何元素（填满 ≠
        // 逐出——bd 打回 2026-10-26：误把满位信号记在插入后，首填多计 1）。
        // seq 连续单调 → 插入键恒为最大键，「插入前已满 ⇒ 必逐出最小键（最旧）」精确。
        let evicted_now = ring.len() == self.capacity;
        // BoundError 仅 Reject 策略产生；EvictOldest 环满自逐，insert 恒 Ok。
        let _: Result<(), BoundError> =
            ring.insert(seq, AuditRecord { seq, plugin, message: message.to_string() });
        if evicted_now {
            self.evicted.fetch_add(1, Ordering::Relaxed);
        }
        seq
    }

    /// 取走环内全部事件（升序；随取随清——PoolBase::take_audit_events 同形，
    /// 非热路径批量读侧）。
    pub fn take_events(&self) -> Vec<AuditRecord> {
        let mut ring = lock_audit(&self.ring);
        let mut out = Vec::with_capacity(ring.len());
        // BoundedRegistry 升序确定序：反复摘最小键。let-else 使迭代器暂存
        // 语句级消亡（while-let 暂存活整个循环体，与 remove 的 &mut 冲突）。
        loop {
            let Some(min_key) = ring.iter().next().map(|(k, _)| *k) else { break };
            // remove 返回 Option；刚 iter 到的键必在（同锁内无并发摘除）。
            if let Some(rec) = ring.remove(&min_key) {
                out.push(rec);
            }
        }
        out
    }

    /// 当前环内事件数。
    pub fn len(&self) -> usize {
        lock_audit(&self.ring).len()
    }

    /// 环空判定。
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// 容量上界（构造时定，不变）。
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// 累计被逐出数（空洞显式证据；单调不减）。
    pub fn evicted_count(&self) -> u64 {
        self.evicted.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_take_roundtrip_is_ascending() {
        let h = AuditHandle::new(8);
        h.record("socks", "evt-a");
        h.record("blackhole", "evt-b");
        assert_eq!(h.len(), 2);
        let events = h.take_events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].seq, 0);
        assert_eq!(events[0].plugin, "socks");
        assert_eq!(events[1].seq, 1);
        assert!(h.is_empty(), "take 随取随清");
        // seq 不回退：drain 后继续单调
        assert_eq!(h.record("dokodemo", "evt-c"), 2);
    }

    #[test]
    fn ring_eviction_is_explicit_not_silent() {
        let h = AuditHandle::new(2);
        h.record("p", "one");
        h.record("p", "two");
        assert_eq!(h.evicted_count(), 0, "未满零逐出");
        h.record("p", "three");
        assert_eq!(h.evicted_count(), 1, "满位插入 = 恰好逐出一条，显式计数");
        let events = h.take_events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].message, "two", "最旧（one）被逐出");
        assert_eq!(events[1].message, "three");
        // drain 后重填：从空到满的每一插都不逐出（原回归形态——首填多计）。
        h.record("p", "four");
        h.record("p", "five");
        assert_eq!(h.evicted_count(), 1, "drain 后重填至满位，零逐出");
        h.record("p", "six");
        assert_eq!(h.evicted_count(), 2, "重填后的满位插入恢复逐出计数");
        let events = h.take_events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].message, "five");
        assert_eq!(events[1].message, "six");
    }

    #[test]
    fn display_message_renders_at_record_time() {
        let h = AuditHandle::new(4);
        h.record("p", format_args!("coded {}/{}", 1, 2));
        assert_eq!(h.take_events()[0].message, "coded 1/2");
    }
}
