//! SS-2022 TCP salt 重放过滤器。
//!
//! 对齐 sing-shadowsocks `common/replay.SimpleFilter`（Go ss2022 Service 内嵌
//! `replay.NewSimple(60s)`）：解密请求前以明文 salt 查重，TTL 内同 salt 视为
//! 重放攻击拒绝（check 即注册——即使后续解密失败 salt 也已入池）。
//!
//! 与 sing 的差异：过期项按池大小阈值惰性清理（sing 按 lastClean 轮询），
//! 对外语义一致：TTL 内同 salt 必拒。

use std::collections::HashMap;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

/// 明文 salt 重放过滤器（线程共享，inbound handler 持有）。
pub struct SaltReplayFilter {
    ttl: Duration,
    /// (上次全量清理时刻, salt 池)——sing `lastClean` 与 pool 同锁
    /// （check 是 `&self`，可变状态必须在锁内）。
    state: Mutex<(Instant, HashMap<Box<[u8]>, Instant>)>,
}

/// 生产 salt 重放窗口（对齐 sing `replay.NewSimple(60 * time.Second)`）。
pub const REPLAY_WINDOW: Duration = Duration::from_secs(60);

impl SaltReplayFilter {
    /// 创建过滤器（生产用 `Duration::from_secs(60)`，对齐 sing）。
    #[must_use]
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            state: Mutex::new((Instant::now(), HashMap::new())),
        }
    }

    /// 检查 salt 是否为新值。`true` = 新（已注册），`false` = TTL 内重放。
    #[must_use]
    pub fn check(&self, salt: &[u8]) -> bool {
        let now = Instant::now();
        let (last_clean, pool) = &mut *self.state.lock();
        // sing SimpleFilter：清理周期（> TTL）到了才全表 retain 并重置
        // lastClean；周期内的 check 只查表（池内存上限 = TTL × QPS，Go 同构）。
        if now.duration_since(*last_clean) > self.ttl {
            pool.retain(|_, t| now.duration_since(*t) < self.ttl);
            *last_clean = now;
        }
        let replayed = matches!(pool.get(salt), Some(t) if now.duration_since(*t) < self.ttl);
        if !replayed {
            pool.insert(salt.into(), now);
        }
        !replayed
    }

    /// 当前池大小（测试用）。
    #[must_use]
    pub fn len(&self) -> usize {
        self.state.lock().1.len()
    }

    /// 池是否为空（测试用）。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.state.lock().1.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_salt_rejected_within_ttl() {
        let f = SaltReplayFilter::new(Duration::from_secs(60));
        assert!(f.check(b"salt-salt-salt-salt"));
        assert!(!f.check(b"salt-salt-salt-salt"), "same salt within TTL must be replay");
        assert!(f.check(b"another-salt-aaaaaaaaaaaa"), "different salt must pass");
        assert_eq!(f.len(), 2);
    }

    #[test]
    fn expired_salt_reusable() {
        let f = SaltReplayFilter::new(Duration::from_millis(30));
        assert!(f.check(b"short-lived-salt-xx"));
        std::thread::sleep(Duration::from_millis(50));
        assert!(f.check(b"short-lived-salt-xx"), "salt past TTL is reusable");
    }
    #[test]
    fn pool_capped_by_lazy_cleanup() {
        let f = SaltReplayFilter::new(Duration::from_millis(30));
        for i in 0..4100u32 {
            f.check(&i.to_be_bytes());
        }
        assert_eq!(f.len(), 4100, "live entries are kept");
        std::thread::sleep(Duration::from_millis(50));
        assert!(f.check(b"trigger-cleanup"), "4101st insert triggers retain");
        assert_eq!(f.len(), 1, "expired entries swept by lazy cleanup");
    }
}
