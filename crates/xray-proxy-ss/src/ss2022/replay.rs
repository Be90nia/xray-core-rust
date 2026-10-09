//! SS-2022 TCP salt 重放过滤器。
//!
//! 对齐 Go `common/antireplay/mapfilter.go`（v26.9.30 终态，`ReplayFilter[T]`
//! 双池轮换）：poolA 当前窗 / poolB 上一窗，每过 interval 轮换（B=A, A=新表）。
//! Check：两池任一命中即重放；未命中写入 poolA。条目实际存活 1~2 × interval。
//!
//! 调用时序对齐 Go `InitServerStream`：请求头解密+解析成功后才 Check
//! （check 即注册）——解密失败的未知 salt 不入池，防未认证 salt 毒化
//! （攻击者无法用垃圾包预占合法 salt 致其被拒）。

use std::{collections::HashMap, time::Duration};

use parking_lot::Mutex;

/// 明文 salt 重放过滤器（线程共享，inbound handler 持有）。
pub struct SaltReplayFilter {
    interval: Duration,
    /// (上次轮换时刻, poolA, poolB)——Go `lastClean`/`poolA`/`poolB` 同锁
    /// （check 是 `&self`，可变状态必须在锁内）。
    state: Mutex<ReplayState>,
}

/// Go `ReplayFilter` 锁内状态（lastClean + 双池）。
struct ReplayState {
    last_clean: std::time::Instant,
    pool_a: HashMap<Box<[u8]>, ()>,
    pool_b: HashMap<Box<[u8]>, ()>,
}

/// 生产 salt 重放窗口（对齐 Go `antireplay.NewMapFilter[[32]byte](60)`）。
pub const REPLAY_WINDOW: Duration = Duration::from_secs(60);

impl SaltReplayFilter {
    /// 创建过滤器（生产用 [`REPLAY_WINDOW`]，对齐 Go 60s）。
    #[must_use]
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            state: Mutex::new(ReplayState {
                last_clean: std::time::Instant::now(),
                pool_a: HashMap::new(),
                pool_b: HashMap::new(),
            }),
        }
    }

    /// 检查 salt 是否为新值。`true` = 新（已注册），`false` = 窗口内重放。
    #[must_use]
    pub fn check(&self, salt: &[u8]) -> bool {
        let now = std::time::Instant::now();
        let st = &mut *self.state.lock();
        // Go MapFilter：到期轮换（B=A，A=新表）——条目存活 1~2 × interval
        if now.duration_since(st.last_clean) >= self.interval {
            st.pool_b = std::mem::take(&mut st.pool_a);
            st.last_clean = now;
        }
        let replayed = st.pool_a.contains_key(salt) || st.pool_b.contains_key(salt);
        if !replayed {
            st.pool_a.insert(salt.into(), ());
        }
        !replayed
    }

    /// 当前两池条目总数（测试用）。
    #[must_use]
    pub fn len(&self) -> usize {
        let st = &*self.state.lock();
        st.pool_a.len() + st.pool_b.len()
    }

    /// 两池是否为空（测试用）。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_salt_rejected_within_window() {
        let f = SaltReplayFilter::new(Duration::from_secs(60));
        assert!(f.check(b"salt-salt-salt-salt"));
        assert!(!f.check(b"salt-salt-salt-salt"), "same salt within window must be replay");
        assert!(f.check(b"another-salt-aaaaaaaaaaaa"), "different salt must pass");
        assert_eq!(f.len(), 2, "重放 check 不重复入池，仅 2 个唯一条目");
    }

    /// 双池轮换：条目在 [1×interval, 2×interval) 仍在 poolB（拒绝），
    /// 两次轮换后才可复用（Go ReplayFilter 语义）。
    #[test]
    fn salt_survives_two_rotations() {
        let f = SaltReplayFilter::new(Duration::from_millis(30));
        assert!(f.check(b"rotating-salt-aaaa"));
        // <1×interval：poolA 命中
        std::thread::sleep(Duration::from_millis(15));
        assert!(!f.check(b"rotating-salt-aaaa"), "within first window rejected");
        // ≥1×interval：轮换进 poolB，仍拒绝
        std::thread::sleep(Duration::from_millis(25));
        assert!(!f.check(b"rotating-salt-aaaa"), "in poolB after rotation rejected");
        // ≥2×interval：第二次轮换后两池皆无，可复用
        std::thread::sleep(Duration::from_millis(35));
        assert!(f.check(b"rotating-salt-aaaa"), "dropped after second rotation");
    }

    #[test]
    fn expired_entries_swept_by_rotation() {
        let f = SaltReplayFilter::new(Duration::from_millis(30));
        for i in 0..100u32 {
            let _ = f.check(&i.to_be_bytes());
        }
        assert_eq!(f.len(), 100, "live entries kept in poolA");
        std::thread::sleep(Duration::from_millis(40));
        assert!(f.check(b"trigger-rotation-aaaa"), "rotation check passes");
        assert_eq!(f.len(), 101, "旧 100 条移 poolB 未删 + 新 1 条入 poolA");
        std::thread::sleep(Duration::from_millis(35));
        assert!(f.check(b"second-rotation-aaaa"), "second rotation");
        assert_eq!(f.len(), 2, "两次轮换后两池仅剩两条新 salt");
    }
}
