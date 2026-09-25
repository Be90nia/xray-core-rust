//! 弱引用缓存（`WeakCacheMap`）。
//!
//! 对应 Go `common/utils/weak_cache.go`（Go 1.24 `weak.Pointer` 标准库）。
//! 用途：保存昂贵的共享对象（IPSet / DomainMatcher），最后一次外部 `Arc`
//! 释放后自动清理条目，无需后台 goroutine。
//!
//! # API
//!
//! - [`WeakCacheMap::new`]            —— 构造空缓存。
//! - [`WeakCacheMap::store`]          —— 插入 `(K, Arc<V>)`，返回 `Weak<V>` 给调用者持有。
//! - [`WeakCacheMap::load`]           —— 取 `Weak<V>`；值已被回收则返回 `None`。
//! - [`WeakCacheMap::get_or_insert_with`] —— 缓存命中直接 clone `Arc`；否则调 init 闭包构造。
//! - [`WeakCacheMap::len`]            —— 内部表长度（含已失效条目，未清理）。
//! - [`WeakCacheMap::cleanup_expired`] —— 显式清理已失效条目（Go 无对应 API；可选用）。
//!
//! ponytail: 全局 `Mutex` 串行化所有操作；热点路径单写多读，
//! 高并发下 `RwLock` 更优，但 IP/域名缓存命中多在路由热路径——
//! 一旦 cache 命中，每次路由查表只一次 lock，开销可忽略。升级路径：
//! 用 `arc_swap` 或 dashmap shards。

use std::{
    collections::HashMap,
    hash::Hash,
    sync::{Arc, Mutex, Weak},
};

/// 弱引用缓存。
///
/// `V` 必须 `Send + Sync + 'static`（弱引用跨线程安全）。
#[derive(Debug)]
pub struct WeakCacheMap<K, V>
where
    K: Eq + Hash + Send + 'static,
    V: Send + Sync + 'static,
{
    inner: Mutex<HashMap<K, Weak<V>>>,
}

impl<K, V> Default for WeakCacheMap<K, V>
where
    K: Eq + Hash + Send + 'static,
    V: Send + Sync + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<K, V> WeakCacheMap<K, V>
where
    K: Eq + Hash + Send + 'static,
    V: Send + Sync + 'static,
{
    /// 构造空缓存。
    #[must_use]
    pub fn new() -> Self {
        Self { inner: Mutex::new(HashMap::new()) }
    }

    /// 取 `Weak<V>`：值已被回收（外部 `Arc` 全部释放）则返回 `None`，
    /// 同时清理对应 slot。
    #[must_use]
    pub fn load(&self, key: &K) -> Option<Weak<V>> {
        let mut guard = self.inner.lock().expect("WeakCacheMap poisoned");
        let weak = guard.get(key)?.clone();
        if weak.strong_count() == 0 {
            guard.remove(key);
            return None;
        }
        Some(weak)
    }

    /// 存储 `(K, Arc<V>)`，返回 `Weak<V>` 给调用者持有。
    ///
    /// 调用者必须持有 `Arc<V>`（否则弱引用立即失效）。
    pub fn store(&self, key: K, value: Arc<V>) -> Weak<V> {
        let weak = Arc::downgrade(&value);
        let mut guard = self.inner.lock().expect("WeakCacheMap poisoned");
        guard.insert(key, weak.clone());
        weak
    }

    /// 缓存命中 → 升级到 `Arc<V>` 克隆返回；未命中 → 调 `init` 闭包构造并存入缓存。
    ///
    /// 等价于 Go `factory.GetOrCreateFrom*` + `utils.WeakCacheMap` 的组合用法。
    pub fn get_or_insert_with<F>(&self, key: K, init: F) -> Arc<V>
    where
        F: FnOnce() -> Arc<V>,
    {
        // 快速路径：命中 + 升级成功
        if let Some(weak) = self.load(&key) {
            if let Some(arc) = weak.upgrade() {
                return arc;
            }
        }
        // 慢速路径：构造 + 插入
        let arc = init();
        self.store(key, arc.clone());
        arc
    }

    /// 内部表条目数（含已失效弱引用），仅供监控/调试。
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().expect("WeakCacheMap poisoned").len()
    }

    /// 是否空表（条目数为 0）。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// 显式清理已失效弱引用条目。
    ///
    /// 不需要周期性调用（Go 端 `runtime.AddCleanup` 自动清理）。
    /// 测试或调试场景可显式触发。
    pub fn cleanup_expired(&self) -> usize {
        let mut guard = self.inner.lock().expect("WeakCacheMap poisoned");
        let before = guard.len();
        guard.retain(|_, w| w.strong_count() > 0);
        before - guard.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_and_load_returns_weak_upgrade() {
        let cache: WeakCacheMap<String, i32> = WeakCacheMap::new();
        let arc = Arc::new(42);
        let weak = cache.store("k".to_string(), arc.clone());
        assert_eq!(weak.upgrade().unwrap().as_ref(), &42);
        assert_eq!(cache.load(&"k".to_string()).unwrap().upgrade().unwrap().as_ref(), &42);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn load_after_drop_returns_none_and_cleans_slot() {
        let cache: WeakCacheMap<String, i32> = WeakCacheMap::new();
        {
            let _arc = Arc::new(7);
            cache.store("k".to_string(), _arc);
        } // Arc 释放 → 弱引用失效
        assert!(cache.load(&"k".to_string()).is_none());
        assert_eq!(cache.len(), 0, "load 应在回收时清理 slot");
    }

    #[test]
    fn get_or_insert_with_miss_then_hit() {
        let cache: WeakCacheMap<String, Vec<u8>> = WeakCacheMap::new();
        let counter = Arc::new(std::sync::Mutex::new(0_u32));
        let c2 = Arc::clone(&counter);
        let arc = cache.get_or_insert_with("k".to_string(), || {
            *c2.lock().unwrap() += 1;
            Arc::new(vec![1, 2, 3])
        });
        assert_eq!(*arc, vec![1, 2, 3]);
        assert_eq!(*counter.lock().unwrap(), 1);

        // 命中路径：不重复 init
        let c2 = Arc::clone(&counter);
        let arc2 = cache.get_or_insert_with("k".to_string(), || {
            *c2.lock().unwrap() += 1;
            Arc::new(vec![9])
        });
        assert_eq!(*arc2, vec![1, 2, 3]);
        assert_eq!(*counter.lock().unwrap(), 1);
    }

    #[test]
    fn cleanup_expired_drops_dead_entries() {
        let cache: WeakCacheMap<String, i32> = WeakCacheMap::new();
        // 关键语义：cache 内只持 Weak，调用方必须保留 Arc 才能让 cache 命中。
        let live_arc = Arc::new(1);
        cache.store("live".to_string(), Arc::clone(&live_arc));
        let dead_arc = Arc::new(2);
        cache.store("dead".to_string(), Arc::clone(&dead_arc));
        // 此刻 cache 内 live/dead 都可升级（外部 Arc 还活着）
        assert!(cache.load(&"live".to_string()).unwrap().upgrade().is_some());
        assert!(cache.load(&"dead".to_string()).unwrap().upgrade().is_some());
        // 释放 dead → cache 内 dead slot 的 Weak 强引用归零
        drop(dead_arc);
        // load("dead") 应返回 None 并清理 slot
        assert!(cache.load(&"dead".to_string()).is_none());
        assert_eq!(cache.len(), 1, "load 应在 dead 回收时清理 slot");
        // live 仍可升级
        assert!(cache.load(&"live".to_string()).unwrap().upgrade().is_some());
        // explicit cleanup_expired 幂等
        assert_eq!(cache.cleanup_expired(), 0);
        // 释放 live → load 已清理 slot
        drop(live_arc);
        assert!(cache.load(&"live".to_string()).is_none());
        // load 已清理所有 dead slot，cleanup_expired 幂等
        assert_eq!(cache.cleanup_expired(), 0, "所有 slot 已清");
        assert!(cache.is_empty());
    }
}
