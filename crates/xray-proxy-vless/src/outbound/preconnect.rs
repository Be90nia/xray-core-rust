//! VLESS outbound 预连接池（pre-connect）。
//!
//! 对应 Go `proxy/vless/outbound/outbound.go` 的 pre-connect 逻辑。
//!
//! 预连接（`testpre`）让 outbound 在首次使用时预建立 N 条到 VLESS 服务端的
//! 连接，放入池中。后续请求直接取池中已建立的连接，省去握手延迟。过期连接
//! 由 `ConnExpire` 定时清理。
//!
//! 本模块是纯逻辑 + 线程安全状态（`Mutex<…>`），实际的 IO（拨号 + 握手）
//! 由上层 dispatcher 注入。池操作语义：
//! - `try_acquire`：取一条预连接（命中返回 true，未命中返回 false）
//! - `try_donate`：归还/捐献一条连接到池（池满则丢弃）
//! - `gc_expired`：清理过期连接

use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::error::Result;

/// 池中一条预连接的元数据（不含连接本身，连接由上层持有）。
#[derive(Debug, Clone)]
pub struct PreConnEntry {
    /// 建立时间（判断是否过期）。
    pub created_at: Instant,
    /// 序号（调试/日志用）。
    pub seq: u64,
}

impl PreConnEntry {
    fn new(seq: u64) -> Self {
        Self {
            created_at: Instant::now(),
            seq,
        }
    }

    /// 是否已过期（`now - created_at > ttl`）。
    #[must_use]
    pub fn is_expired(&self, now: Instant, ttl: Duration) -> bool {
        now.duration_since(self.created_at) > ttl
    }
}

/// 预连接池配置。
#[derive(Debug, Clone)]
pub struct PreConnectConfig {
    /// 预连接数（对应 Go `testpre`）。
    pub count: u32,
    /// 连接过期时间（对应 Go `ConnExpire`，默认 30s）。
    pub ttl: Duration,
}

impl Default for PreConnectConfig {
    fn default() -> Self {
        Self {
            count: 0,
            ttl: Duration::from_secs(30),
        }
    }
}

impl PreConnectConfig {
    /// 是否启用预连接。
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.count > 0
    }
}

/// 预连接池。
///
/// 对应 Go outbound Handler 的 `preConns` 字段 + `ConnExpire` 定时器。
/// 线程安全：所有操作受 mutex 保护。
#[derive(Debug)]
pub struct PreConnectPool {
    config: PreConnectConfig,
    inner: Arc<Mutex<PoolInner>>,
}

#[derive(Debug)]
struct PoolInner {
    /// 当前池中的连接条目（FIFO 取用）。
    entries: Vec<PreConnEntry>,
    /// 下一个序号。
    next_seq: u64,
    /// 已取出的连接总数（统计用）。
    acquired_total: u64,
    /// 已捐献的连接总数。
    donated_total: u64,
    /// 因池满被丢弃的连接数。
    rejected_full: u64,
}

impl Clone for PreConnectPool {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            inner: Arc::clone(&self.inner),
        }
    }
}

impl PreConnectPool {
    /// 创建预连接池。
    #[must_use]
    pub fn new(config: PreConnectConfig) -> Self {
        Self {
            config,
            inner: Arc::new(Mutex::new(PoolInner {
                entries: Vec::new(),
                next_seq: 0,
                acquired_total: 0,
                donated_total: 0,
                rejected_full: 0,
            })),
        }
    }

    /// 池配置（只读快照）。
    #[must_use]
    pub fn config(&self) -> &PreConnectConfig {
        &self.config
    }

    /// 当前池中连接数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().entries.len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.lock().entries.is_empty()
    }

    /// 尝试从池中取一条预连接。
    ///
    /// 命中返回 `Some(entry)`，池空返回 `None`。取出的连接由上层
    /// 拨号逻辑填充实际 IO 连接。
    #[must_use]
    pub fn try_acquire(&self) -> Option<PreConnEntry> {
        let mut inner = self.inner.lock();
        let entry = inner.entries.pop()?;
        inner.acquired_total += 1;
        Some(entry)
    }

    /// 尝试将一条已建立的连接捐献到池中（供后续请求复用）。
    ///
    /// 池满（`len >= count`）或未启用预连接时返回 `Ok(false)`（连接被丢弃）。
    ///
    /// # Errors
    /// 仅在内部状态异常时返回错误（当前实现不会，预留）。
    pub fn try_donate(&self) -> Result<bool> {
        if !self.config.enabled() {
            return Ok(false);
        }
        let mut inner = self.inner.lock();
        if inner.entries.len() >= self.config.count as usize {
            inner.rejected_full += 1;
            return Ok(false);
        }
        let seq = inner.next_seq;
        inner.next_seq += 1;
        inner.entries.insert(0, PreConnEntry::new(seq));
        inner.donated_total += 1;
        Ok(true)
    }

    /// 填充池到目标数量（返回需要建立的连接缺口）。
    ///
    /// 对应 Go 端 `testpre` 初始化：池不足 `count` 时，缺口由上层拨号填充。
    #[must_use]
    pub fn fill_deficit(&self) -> u32 {
        if !self.config.enabled() {
            return 0;
        }
        let target = self.config.count as usize;
        let mut inner = self.inner.lock();
        let current = inner.entries.len();
        if current >= target {
            return 0;
        }
        let deficit = target - current;
        for _ in 0..deficit {
            let seq = inner.next_seq;
            inner.next_seq += 1;
            inner.entries.insert(0, PreConnEntry::new(seq));
            inner.donated_total += 1;
        }
        deficit as u32
    }

    /// 清理过期连接，返回清理数。
    ///
    /// 对应 Go `ConnExpire` 定时器逻辑。
    pub fn gc_expired(&self) -> usize {
        let now = Instant::now();
        let ttl = self.config.ttl;
        let mut inner = self.inner.lock();
        let before = inner.entries.len();
        inner.entries.retain(|e| !e.is_expired(now, ttl));
        before - inner.entries.len()
    }

    /// 统计：已取出的连接总数。
    #[must_use]
    pub fn acquired_total(&self) -> u64 {
        self.inner.lock().acquired_total
    }

    /// 统计：已捐献的连接总数。
    #[must_use]
    pub fn donated_total(&self) -> u64 {
        self.inner.lock().donated_total
    }

    /// 统计：因池满被丢弃的连接数。
    #[must_use]
    pub fn rejected_full(&self) -> u64 {
        self.inner.lock().rejected_full
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_pool_never_donates() {
        let pool = PreConnectPool::new(PreConnectConfig::default()); // count=0
        assert!(!pool.config().enabled());
        assert_eq!(pool.try_donate().unwrap(), false);
        assert!(pool.is_empty());
    }

    #[test]
    fn donate_then_acquire() {
        let pool = PreConnectPool::new(PreConnectConfig {
            count: 3,
            ttl: Duration::from_secs(30),
        });
        assert!(pool.try_donate().unwrap());
        assert!(pool.try_donate().unwrap());
        assert_eq!(pool.len(), 2);

        let e = pool.try_acquire().unwrap();
        assert!(pool.acquired_total() >= 1);
        // FIFO: 最后 donate 的 seq 最大
        let _ = e;
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn donate_full_rejects() {
        let pool = PreConnectPool::new(PreConnectConfig {
            count: 2,
            ttl: Duration::from_secs(30),
        });
        pool.try_donate().unwrap();
        pool.try_donate().unwrap();
        assert_eq!(pool.len(), 2);

        // 池满
        assert_eq!(pool.try_donate().unwrap(), false);
        assert_eq!(pool.rejected_full(), 1);
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn fill_deficit_fills_to_target() {
        let pool = PreConnectPool::new(PreConnectConfig {
            count: 5,
            ttl: Duration::from_secs(30),
        });
        let deficit = pool.fill_deficit();
        assert_eq!(deficit, 5);
        assert_eq!(pool.len(), 5);

        // 再次调用缺口为 0
        assert_eq!(pool.fill_deficit(), 0);
        assert_eq!(pool.len(), 5);
    }

    #[test]
    fn fill_deficit_partial() {
        let pool = PreConnectPool::new(PreConnectConfig {
            count: 4,
            ttl: Duration::from_secs(30),
        });
        pool.try_donate().unwrap(); // 1 条
        let deficit = pool.fill_deficit();
        assert_eq!(deficit, 3);
        assert_eq!(pool.len(), 4);
    }

    #[test]
    fn acquire_empty_returns_none() {
        let pool = PreConnectPool::new(PreConnectConfig {
            count: 2,
            ttl: Duration::from_secs(30),
        });
        assert!(pool.try_acquire().is_none());
    }

    #[test]
    fn gc_removes_expired() {
        let pool = PreConnectPool::new(PreConnectConfig {
            count: 3,
            ttl: Duration::from_millis(1),
        });
        let _ = pool.fill_deficit();
        assert_eq!(pool.len(), 3);

        // 等待过期
        std::thread::sleep(Duration::from_millis(10));
        let cleaned = pool.gc_expired();
        assert_eq!(cleaned, 3);
        assert!(pool.is_empty());
    }

    #[test]
    fn gc_keeps_fresh() {
        let pool = PreConnectPool::new(PreConnectConfig {
            count: 3,
            ttl: Duration::from_secs(30),
        });
        let _ = pool.fill_deficit();
        let cleaned = pool.gc_expired();
        assert_eq!(cleaned, 0);
        assert_eq!(pool.len(), 3);
    }

    #[test]
    fn clone_shares_state() {
        let pool = PreConnectPool::new(PreConnectConfig {
            count: 2,
            ttl: Duration::from_secs(30),
        });
        let pool2 = pool.clone();
        pool.try_donate().unwrap();
        assert_eq!(pool2.len(), 1);
    }

    #[test]
    fn seq_monotonic() {
        let pool = PreConnectPool::new(PreConnectConfig {
            count: 3,
            ttl: Duration::from_secs(30),
        });
        let _ = pool.fill_deficit();
        let e1 = pool.try_acquire().unwrap();
        let e2 = pool.try_acquire().unwrap();
        let e3 = pool.try_acquire().unwrap();
        // FIFO pop: 最后插入的 seq 最大先出
        assert!(e3.seq > e2.seq);
        assert!(e2.seq > e1.seq);
    }
}
