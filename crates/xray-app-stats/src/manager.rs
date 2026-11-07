//! Manager 实现。
//!
//! 对应 Go `app/stats/stats.go::Manager`：
//! - 三个 `map[string]*X` 注册表 → `RwLock<HashMap<String, Arc<dyn X>>>`
//! - `Start` / `Close` 控制 channels 生命周期 + online_maps 清空
//! - `RegisterX` 重名返回 [`ManagerError::AlreadyRegistered`]
//! - `VisitX` / `GetX` 在读锁内回调

use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use parking_lot::RwLock;
use xray_features::stats::{Channel, Counter, Manager as ManagerTrait, ManagerError, OnlineMap};

use crate::{
    channel::{ChannelConfig, StatsChannel},
    counter::Counter as StatsCounter,
    online_map::OnlineMap as StatsOnlineMap,
};

/// 统计管理器实现。对应 Go `app/stats.Manager`。
pub struct Manager {
    counters: RwLock<HashMap<String, Arc<dyn Counter>>>,
    online_maps: RwLock<HashMap<String, Arc<dyn OnlineMap>>>,
    channels: RwLock<HashMap<String, Arc<dyn Channel>>>,
    running: AtomicBool,
    /// 每类注册表条目上界（`None` = 无上限，对齐 Go）。
    ///
    /// Go `app/stats` 的 `RegisterCounter`/`RegisterOnlineMap`/`RegisterChannel`
    /// **只在重名时报错，没有条目上界**。本仓此前硬编码 1024（三类各一份），而
    /// counter 池按 inbound/outbound/user 三方按用户数线性增长 ⇒ 约 512 用户即
    /// 触顶，之后所有新计数器被拒且调用方 `.ok()` 吞错 ⇒ 计数**永久静默停在 0**
    /// （bd 441no）。缺省改回 Go 语义（无上限）；需要封顶的装配方经
    /// [`Manager::with_registry_limit`] 显式给出，触顶走
    /// [`ManagerError::CapacityExceeded`] + warn 一次（fail-visible，不再静默）。
    registry_limit: Option<usize>,
    /// 触顶 warn 只打一次（判据：首次拒绝由 `swap` 抢到）。
    capacity_warned: AtomicBool,
}

impl Manager {
    /// 新建空 Manager。对应 Go `NewManager(ctx, config) (*Manager, error)`。
    ///
    /// Go 中 `ctx` 未使用，`config` 也是空（proto 只有 `Config{}`），均省略。
    /// 条目上界缺省**无上限**（Go 语义，见 `registry_limit` 字段的说明）。
    #[must_use]
    pub fn new() -> Self {
        Self::with_registry_limit(None)
    }

    /// 指定每类注册表条目上界（`None` = 无上限 = Go 语义）。
    #[must_use]
    pub fn with_registry_limit(registry_limit: Option<usize>) -> Self {
        Self {
            counters: RwLock::new(HashMap::new()),
            online_maps: RwLock::new(HashMap::new()),
            channels: RwLock::new(HashMap::new()),
            running: AtomicBool::new(false),
            registry_limit,
            capacity_warned: AtomicBool::new(false),
        }
    }

    /// 新建时为运行态（测试用）。Go 中 Start() 后 running=true。
    #[must_use]
    pub fn new_running() -> Self {
        let m = Self::new();
        m.running.store(true, Ordering::SeqCst);
        m
    }

    /// 触顶判定：已达上界 ⇒ warn 一次 + `CapacityExceeded`（绝不静默拒绝）。
    fn check_capacity(&self, len: usize, kind: &'static str) -> Result<(), ManagerError> {
        let Some(limit) = self.registry_limit else {
            return Ok(());
        };
        if len < limit {
            return Ok(());
        }
        if !self.capacity_warned.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                "stats {kind} registry reached its configured limit ({limit}): further entries \
                 are rejected and their counters will stay absent — raise the limit or unset it"
            );
        }
        Err(ManagerError::CapacityExceeded { kind, limit })
    }
}

impl Default for Manager {
    fn default() -> Self {
        Self::new()
    }
}

impl ManagerTrait for Manager {
    // --- Counter ---

    fn register_counter(&self, name: &str) -> Result<Arc<dyn Counter>, ManagerError> {
        let mut counters = self.counters.write();
        if counters.contains_key(name) {
            return Err(ManagerError::AlreadyRegistered {
                kind: "Counter",
                name: name.to_string(),
            });
        }
        self.check_capacity(counters.len(), "Counter")?;
        tracing::debug!("create new counter {name}");
        let c: Arc<dyn Counter> = Arc::new(StatsCounter::new());
        counters.insert(name.to_string(), Arc::clone(&c));
        Ok(c)
    }

    fn unregister_counter(&self, name: &str) {
        let mut counters = self.counters.write();
        if counters.remove(name).is_some() {
            tracing::debug!("remove counter {name}");
        }
    }

    fn get_counter(&self, name: &str) -> Option<Arc<dyn Counter>> {
        let counters = self.counters.read();
        counters.get(name).map(Arc::clone)
    }

    fn visit_counters(&self, f: &mut dyn FnMut(&str, &dyn Counter) -> bool) {
        let counters = self.counters.read();
        for (name, c) in counters.iter() {
            if !f(name.as_str(), c.as_ref()) {
                break;
            }
        }
    }

    // --- OnlineMap ---

    fn register_online_map(&self, name: &str) -> Result<Arc<dyn OnlineMap>, ManagerError> {
        let mut maps = self.online_maps.write();
        if maps.contains_key(name) {
            return Err(ManagerError::AlreadyRegistered {
                kind: "OnlineMap",
                name: name.to_string(),
            });
        }
        self.check_capacity(maps.len(), "OnlineMap")?;
        tracing::debug!("create new OnlineMap {name}");
        let om: Arc<dyn OnlineMap> = Arc::new(StatsOnlineMap::new());
        maps.insert(name.to_string(), Arc::clone(&om));
        Ok(om)
    }

    fn unregister_online_map(&self, name: &str) {
        let mut maps = self.online_maps.write();
        if maps.remove(name).is_some() {
            tracing::debug!("remove OnlineMap {name}");
        }
    }

    fn get_online_map(&self, name: &str) -> Option<Arc<dyn OnlineMap>> {
        let maps = self.online_maps.read();
        maps.get(name).map(Arc::clone)
    }

    fn visit_online_maps(&self, f: &mut dyn FnMut(&str, &dyn OnlineMap) -> bool) {
        let maps = self.online_maps.read();
        for (name, om) in maps.iter() {
            if !f(name.as_str(), om.as_ref()) {
                break;
            }
        }
    }

    // --- Channel ---

    fn register_channel(&self, name: &str) -> Result<Arc<dyn Channel>, ManagerError> {
        let mut channels = self.channels.write();
        if channels.contains_key(name) {
            return Err(ManagerError::AlreadyRegistered {
                kind: "Channel",
                name: name.to_string(),
            });
        }
        self.check_capacity(channels.len(), "Channel")?;
        tracing::debug!("create new channel {name}");
        let c: Arc<dyn Channel> = Arc::new(StatsChannel::new(ChannelConfig::default()));
        if self.running.load(Ordering::SeqCst) {
            c.start().map_err(|e| ManagerError::ChannelStart(e.to_string()))?;
        }
        channels.insert(name.to_string(), Arc::clone(&c));
        Ok(c)
    }

    fn unregister_channel(&self, name: &str) {
        let mut channels = self.channels.write();
        if let Some(c) = channels.remove(name) {
            tracing::debug!("remove channel {name}");
            let _ = c.close();
        }
    }

    fn get_channel(&self, name: &str) -> Option<Arc<dyn Channel>> {
        let channels = self.channels.read();
        channels.get(name).map(Arc::clone)
    }

    // --- Aggregate ---

    fn get_all_online_users(&self) -> Vec<String> {
        let maps = self.online_maps.read();
        maps.iter()
            .filter_map(|(name, om)| if om.count() > 0 { Some(name.clone()) } else { None })
            .collect()
    }
}

/// Manager 生命周期扩展方法。对应 Go `Manager.Start` / `Manager.Close`。
///
/// 注意：features::stats::Manager trait 不包含 Start/Close（Go 也不在 interface 中
/// 隐含，而是通过 features.Feature 嵌入）。Rust 端独立暴露方法。
impl Manager {
    /// 启动 Manager。对应 Go `Manager.Start() error`。
    ///
    /// 标记 running=true，并 start 所有已注册的 channels。
    pub fn start(&self) -> Result<(), ManagerError> {
        self.running.store(true, Ordering::SeqCst);
        let channels = self.channels.read();
        for c in channels.values() {
            // Channel::start 失败：Go `Channel.Start()` 返回 error（不是「未实现」）。
            c.start().map_err(|e| ManagerError::ChannelStart(e.to_string()))?;
        }
        Ok(())
    }

    /// 关闭 Manager。对应 Go `Manager.Close() error`。
    ///
    /// 标记 running=false，关闭所有 channels，清空 online_maps。
    pub fn close(&self) -> Result<(), ManagerError> {
        self.running.store(false, Ordering::SeqCst);
        // 清空 online_maps（Go 行为）
        let mut maps = self.online_maps.write();
        for name in maps.keys() {
            tracing::debug!("remove OnlineMap {name}");
        }
        maps.clear();
        // 关闭所有 channels（Go 行为：delete + close）
        let mut channels = self.channels.write();
        let drain: Vec<Arc<dyn Channel>> = channels.drain().map(|(_, v)| v).collect();
        drop(channels); // 释放写锁后调用 close 避免死锁
        for c in drain {
            let _ = c.close();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Counter ---

    #[test]
    fn register_counter_returns_new() {
        let m = Manager::new();
        let c = m.register_counter("uplink").unwrap();
        assert_eq!(c.value(), 0);
    }

    #[test]
    fn register_counter_duplicate_errors() {
        let m = Manager::new();
        m.register_counter("x").unwrap();
        match m.register_counter("x") {
            Err(ManagerError::AlreadyRegistered { kind, name }) => {
                assert_eq!(kind, "Counter");
                assert_eq!(name, "x");
            },
            Err(e) => panic!("expected AlreadyRegistered, got {e:?}"),
            Ok(_) => panic!("expected Err"),
        }
    }

    /// bd 441no：缺省无条目上界（Go 语义）——旧实现硬编码 1024，多用户节点过线
    /// 之后新计数器被静默拒绝。这里越过旧阈值证明不再有天花板。
    #[test]
    fn default_registry_has_no_capacity_ceiling() {
        let m = Manager::new();
        for i in 0..1100 {
            m.register_counter(&format!("user>>>u{i}>>>traffic>>>uplink")).expect("no ceiling");
        }
        assert!(m.get_counter("user>>>u1099>>>traffic>>>uplink").is_some());
    }

    /// 显式封顶时触顶必须 fail-visible：返回 `CapacityExceeded`（不是「已注册」），
    /// 且不落库（后续 get 仍 None）。
    #[test]
    fn explicit_registry_limit_rejects_visibly() {
        let m = Manager::with_registry_limit(Some(2));
        m.register_counter("a").unwrap();
        m.register_counter("b").unwrap();
        match m.register_counter("c") {
            Err(ManagerError::CapacityExceeded { kind, limit }) => {
                assert_eq!(kind, "Counter");
                assert_eq!(limit, 2);
            },
            Err(e) => panic!("expected CapacityExceeded, got {e:?}"),
            Ok(_) => panic!("expected Err"),
        }
        assert!(m.get_counter("c").is_none(), "触顶条目不得落库");
        // 上界按注册表各算：online map 不受 counter 计数影响。
        m.register_online_map("u").expect("separate registry");
    }

    #[test]
    fn get_counter_returns_none_for_missing() {
        let m = Manager::new();
        assert!(m.get_counter("missing").is_none());
    }

    #[test]
    fn get_counter_returns_registered() {
        let m = Manager::new();
        let c = m.register_counter("y").unwrap();
        c.add(10);
        let fetched = m.get_counter("y").expect("found");
        assert_eq!(fetched.value(), 10);
        // 同一个实例
        assert!(Arc::ptr_eq(&c, &fetched));
    }

    #[test]
    fn unregister_counter_silent_for_missing() {
        let m = Manager::new();
        m.unregister_counter("nope"); // 不 panic
    }

    #[test]
    fn unregister_counter_removes() {
        let m = Manager::new();
        m.register_counter("temp").unwrap();
        m.unregister_counter("temp");
        assert!(m.get_counter("temp").is_none());
    }

    #[test]
    fn visit_counters_visits_all() {
        let m = Manager::new();
        m.register_counter("a").unwrap();
        m.register_counter("b").unwrap();
        m.register_counter("c").unwrap();
        let mut names = Vec::new();
        m.visit_counters(&mut |name, _| {
            names.push(name.to_string());
            true
        });
        names.sort();
        assert_eq!(names, vec!["a", "b", "c"]);
    }

    #[test]
    fn visit_counters_stops_on_false() {
        let m = Manager::new();
        for i in 0..5 {
            m.register_counter(&format!("c{i}")).unwrap();
        }
        let mut visited = 0;
        m.visit_counters(&mut |_, _| {
            visited += 1;
            false
        });
        assert_eq!(visited, 1);
    }

    #[test]
    fn visit_counters_provides_reference() {
        let m = Manager::new();
        let c = m.register_counter("v").unwrap();
        c.add(42);
        m.visit_counters(&mut |name, counter| {
            assert_eq!(name, "v");
            assert_eq!(counter.value(), 42);
            false
        });
    }

    // --- OnlineMap ---

    #[test]
    fn register_online_map_returns_new() {
        let m = Manager::new();
        let om = m.register_online_map("user>>>alice").unwrap();
        assert_eq!(om.count(), 0);
    }

    #[test]
    fn register_online_map_duplicate_errors() {
        let m = Manager::new();
        m.register_online_map("u").unwrap();
        match m.register_online_map("u") {
            Err(ManagerError::AlreadyRegistered { kind, .. }) => {
                assert_eq!(kind, "OnlineMap");
            },
            Err(e) => panic!("expected AlreadyRegistered, got {e:?}"),
            Ok(_) => panic!("expected Err"),
        }
    }

    #[test]
    fn get_online_map_missing_returns_none() {
        let m = Manager::new();
        assert!(m.get_online_map("x").is_none());
    }

    #[test]
    fn unregister_online_map_removes() {
        let m = Manager::new();
        m.register_online_map("t").unwrap();
        m.unregister_online_map("t");
        assert!(m.get_online_map("t").is_none());
    }

    #[test]
    fn get_all_online_users_filters_zero_counts() {
        let m = Manager::new();
        let om1 = m.register_online_map("user>>>a").unwrap();
        let _om2 = m.register_online_map("user>>>b").unwrap();
        om1.add_ip("10.0.0.1");

        let mut users = m.get_all_online_users();
        users.sort();
        assert_eq!(users, vec!["user>>>a"]);
    }

    #[test]
    fn get_all_online_users_empty_when_all_zero() {
        let m = Manager::new();
        m.register_online_map("user>>>a").unwrap();
        m.register_online_map("user>>>b").unwrap();
        assert!(m.get_all_online_users().is_empty());
    }

    // --- Channel ---

    #[test]
    fn register_channel_returns_new() {
        let m = Manager::new();
        let c = m.register_channel("ch").unwrap();
        assert!(!c.running());
    }

    #[test]
    fn register_channel_duplicate_errors() {
        let m = Manager::new();
        m.register_channel("c").unwrap();
        match m.register_channel("c") {
            Err(ManagerError::AlreadyRegistered { kind, .. }) => {
                assert_eq!(kind, "Channel");
            },
            Err(e) => panic!("expected AlreadyRegistered, got {e:?}"),
            Ok(_) => panic!("expected Err"),
        }
    }

    #[test]
    fn register_channel_auto_start_if_running() {
        let m = Manager::new_running();
        let c = m.register_channel("auto").unwrap();
        assert!(c.running(), "channel must be auto-started when manager running");
    }

    #[test]
    fn register_channel_not_started_if_not_running() {
        let m = Manager::new();
        let c = m.register_channel("manual").unwrap();
        assert!(!c.running());
    }

    #[test]
    fn unregister_channel_closes() {
        let m = Manager::new();
        let c = m.register_channel("c").unwrap();
        c.start().unwrap();
        m.unregister_channel("c");
        assert!(!c.running());
        assert!(m.get_channel("c").is_none());
    }

    #[test]
    fn get_channel_missing_returns_none() {
        let m = Manager::new();
        assert!(m.get_channel("none").is_none());
    }

    // --- Start / Close ---

    #[test]
    fn start_starts_all_channels() {
        let m = Manager::new();
        let c1 = m.register_channel("a").unwrap();
        let c2 = m.register_channel("b").unwrap();
        assert!(!c1.running());
        assert!(!c2.running());

        m.start().unwrap();
        assert!(c1.running());
        assert!(c2.running());
    }

    #[test]
    fn close_clears_channels_and_online_maps() {
        let m = Manager::new();
        let c = m.register_channel("x").unwrap();
        m.register_online_map("u").unwrap();
        c.start().unwrap();

        m.close().unwrap();
        assert!(!c.running(), "channel must be closed");
        assert!(m.get_channel("x").is_none(), "channel must be removed");
        assert!(m.get_online_map("u").is_none(), "online_maps must be cleared");
    }

    #[test]
    fn close_does_not_clear_counters() {
        // Go Close() 不清 counters（仅 channels 和 online_maps）
        let m = Manager::new();
        m.register_counter("keep").unwrap();
        m.close().unwrap();
        assert!(m.get_counter("keep").is_some());
    }

    // --- Default / trait ---

    #[test]
    fn default_is_not_running() {
        let _m = Manager::default();
    }

    #[test]
    fn implements_features_manager_trait() {
        let m: Arc<dyn ManagerTrait> = Arc::new(Manager::new());
        let c = m.register_counter("t").unwrap();
        c.add(5);
        assert_eq!(m.get_counter("t").map(|c| c.value()), Some(5));
        let mut sum = 0_i64;
        m.visit_counters(&mut |_, c| {
            sum += c.value();
            true
        });
        assert_eq!(sum, 5);
    }
}
