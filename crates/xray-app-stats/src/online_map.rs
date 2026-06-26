//! OnlineMap 实现。
//!
//! 对应 Go `app/stats/online_map.go`：
//! - `OnlineMap struct { entries map[string]ipEntry; access sync.Mutex; count atomic.Int64 }`
//! - `AddIP(ip)` 跳过 localhost，refcount++ / 新建
//! - `RemoveIP(ip)` refcount--，归零删除
//! - `Count() int` / `ForEach(func(string, int64) bool)`
//!
//! 关键点：
//! 1. **跳过 localhost**：`127.0.0.1` 与 `[::1]` 不计入（Go 同款常量）
//! 2. **引用计数**：多次 AddIP 同一 IP 累加，多次 RemoveIP 递减
//! 3. **lastSeen Unix 秒**：每次 AddIP 更新；ForEach 回调返回 false 停止
//! 4. **死锁警告**：ForEach 在锁内回调，禁止回调内调用 AddIP / RemoveIP

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use xray_features::stats::OnlineMap as OnlineMapTrait;

/// IPv4 localhost 字面量。对应 Go `localhostIPv4 = "127.0.0.1"`。
const LOCALHOST_IPV4: &str = "127.0.0.1";
/// IPv6 localhost 字面量。对应 Go `localhostIPv6 = "[::1]"`。
const LOCALHOST_IPV6: &str = "[::1]";

/// 单个 IP 的引用计数 + 最后见时间戳。
#[derive(Debug, Clone, Copy)]
struct IpEntry {
    ref_count: i32,
    last_seen: i64,
}

/// 在线 IP 映射实现。
///
/// 对应 Go `app/stats.OnlineMap`。线程安全。
#[derive(Debug)]
pub struct OnlineMap {
    entries: Mutex<HashMap<String, IpEntry>>,
    count: AtomicI64,
}

impl OnlineMap {
    /// 新建空映射。对应 Go `NewOnlineMap()`。
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            count: AtomicI64::new(0),
        }
    }

    /// 当前 Unix 秒时间戳（与 Go `time.Now().Unix()` 等价）。
    fn now_unix() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
            .unwrap_or(0)
    }

    /// 是否为 localhost（跳过项）。
    fn is_localhost(ip: &str) -> bool {
        ip == LOCALHOST_IPV4 || ip == LOCALHOST_IPV6
    }
}

impl Default for OnlineMap {
    fn default() -> Self {
        Self::new()
    }
}

impl OnlineMapTrait for OnlineMap {
    fn count(&self) -> usize {
        usize::try_from(self.count.load(Ordering::SeqCst)).unwrap_or(0)
    }

    fn add_ip(&self, ip: &str) {
        if Self::is_localhost(ip) {
            return;
        }
        let now = Self::now_unix();
        let mut entries = self.entries.lock();
        match entries.get_mut(ip) {
            Some(e) => {
                e.ref_count = e.ref_count.saturating_add(1);
                e.last_seen = now;
            }
            None => {
                entries.insert(
                    ip.to_string(),
                    IpEntry {
                        ref_count: 1,
                        last_seen: now,
                    },
                );
                self.count.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    fn remove_ip(&self, ip: &str) {
        let mut entries = self.entries.lock();
        let Some(e) = entries.get_mut(ip) else {
            return;
        };
        e.ref_count -= 1;
        if e.ref_count <= 0 {
            entries.remove(ip);
            self.count.fetch_sub(1, Ordering::SeqCst);
        }
    }

    fn for_each(&self, f: &mut dyn FnMut(&str, i64) -> bool) {
        let entries = self.entries.lock();
        for (ip, e) in entries.iter() {
            if !f(ip.as_str(), e.last_seen) {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_starts_empty() {
        let m = OnlineMap::new();
        assert_eq!(m.count(), 0);
    }

    #[test]
    fn default_starts_empty() {
        let m = OnlineMap::default();
        assert_eq!(m.count(), 0);
    }

    #[test]
    fn add_increments_count() {
        let m = OnlineMap::new();
        m.add_ip("10.0.0.1");
        m.add_ip("10.0.0.2");
        m.add_ip("10.0.0.3");
        assert_eq!(m.count(), 3);
    }

    #[test]
    fn add_same_ip_increments_refcount() {
        let m = OnlineMap::new();
        m.add_ip("10.0.0.1");
        m.add_ip("10.0.0.1");
        m.add_ip("10.0.0.1");
        // refcount = 3 但 IP 数仍为 1
        assert_eq!(m.count(), 1);
    }

    #[test]
    fn remove_decrements_refcount() {
        let m = OnlineMap::new();
        m.add_ip("10.0.0.1");
        m.add_ip("10.0.0.1");
        m.remove_ip("10.0.0.1");
        // refcount = 1，IP 仍存在
        assert_eq!(m.count(), 1);
    }

    #[test]
    fn remove_to_zero_deletes_entry() {
        let m = OnlineMap::new();
        m.add_ip("10.0.0.1");
        m.remove_ip("10.0.0.1");
        assert_eq!(m.count(), 0);
    }

    #[test]
    fn remove_unknown_ip_silent() {
        let m = OnlineMap::new();
        m.remove_ip("10.0.0.99"); // 不存在
        assert_eq!(m.count(), 0);
    }

    #[test]
    fn over_remove_clamps_to_zero() {
        // ref_count 用 i32，多次 remove 不会变负影响 count
        let m = OnlineMap::new();
        m.add_ip("10.0.0.1");
        m.remove_ip("10.0.0.1");
        m.remove_ip("10.0.0.1"); // 再次 remove 不存在，静默
        assert_eq!(m.count(), 0);
    }

    #[test]
    fn skips_ipv4_localhost() {
        let m = OnlineMap::new();
        m.add_ip("127.0.0.1");
        assert_eq!(m.count(), 0);
    }

    #[test]
    fn skips_ipv6_localhost() {
        let m = OnlineMap::new();
        m.add_ip("[::1]");
        assert_eq!(m.count(), 0);
    }

    #[test]
    fn skips_both_localhosts_with_others() {
        let m = OnlineMap::new();
        m.add_ip("127.0.0.1");
        m.add_ip("[::1]");
        m.add_ip("10.0.0.5");
        assert_eq!(m.count(), 1);
    }

    #[test]
    fn for_each_visits_all() {
        let m = OnlineMap::new();
        m.add_ip("10.0.0.1");
        m.add_ip("10.0.0.2");
        m.add_ip("10.0.0.3");
        let mut ips = Vec::new();
        m.for_each(&mut |ip, _| {
            ips.push(ip.to_string());
            true
        });
        ips.sort();
        assert_eq!(ips, vec!["10.0.0.1", "10.0.0.2", "10.0.0.3"]);
    }

    #[test]
    fn for_each_stops_on_false() {
        let m = OnlineMap::new();
        for i in 1..=5 {
            m.add_ip(&format!("10.0.0.{i}"));
        }
        let mut visited = 0;
        m.for_each(&mut |_, _| {
            visited += 1;
            false // 第一次就停
        });
        assert_eq!(visited, 1);
    }

    #[test]
    fn for_each_returns_last_seen() {
        let m = OnlineMap::new();
        m.add_ip("10.0.0.1");
        std::thread::sleep(std::time::Duration::from_millis(1100));
        m.add_ip("10.0.0.1"); // 更新 lastSeen
        let now = OnlineMap::now_unix();
        let mut got = 0;
        m.for_each(&mut |_, ts| {
            assert!(ts <= now, "last_seen must be <= now");
            assert!(ts >= now - 5, "last_seen must be recent, got {ts}");
            got += 1;
            true
        });
        assert_eq!(got, 1);
    }

    #[test]
    fn for_each_empty_no_invocation() {
        let m = OnlineMap::new();
        let mut called = 0;
        m.for_each(&mut |_, _| {
            called += 1;
            true
        });
        assert_eq!(called, 0);
    }

    #[test]
    fn implements_features_trait() {
        let m: std::sync::Arc<dyn OnlineMapTrait> = std::sync::Arc::new(OnlineMap::new());
        m.add_ip("10.0.0.1");
        m.add_ip("10.0.0.2");
        assert_eq!(m.count(), 2);
        m.remove_ip("10.0.0.1");
        assert_eq!(m.count(), 1);
    }

    #[test]
    fn concurrent_add_remove_safe() {
        use std::sync::Arc;
        use std::thread;
        let m = Arc::new(OnlineMap::new());
        let mut handles = Vec::new();
        for i in 0..8 {
            let m2 = Arc::clone(&m);
            handles.push(thread::spawn(move || {
                for j in 0..100 {
                    let ip = format!("10.{i}.{j}.1");
                    m2.add_ip(&ip);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(m.count(), 800);
    }
}
