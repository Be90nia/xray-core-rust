//! 缓存工具
//!
//! 对应 Go 版本 `common/cache` 包，提供 LRU 缓存实现。

use std::{collections::HashMap, hash::Hash};

/// LRU（最近最少使用）缓存，支持可配置容量。
///
/// 对应 Go 版本 `cache.Lru`，当插入超过容量时，
/// 自动淘汰最久未访问的条目。
pub struct LruCache<K: Hash + Eq + Clone, V: Clone> {
    capacity: usize,
    entries: HashMap<K, V>,
    order: Vec<K>,
}

impl<K: Hash + Eq + Clone, V: Clone> LruCache<K, V> {
    /// 创建新的 LRU 缓存，指定最大容量。
    ///
    /// 容量为 0 表示不缓存任何条目。
    pub fn new(capacity: usize) -> Self {
        Self { capacity, entries: HashMap::new(), order: Vec::new() }
    }

    /// 获取缓存中的值。
    ///
    /// 如果存在，将该键移到最近访问位置（LRU 更新）。
    /// 返回值的引用，如果键不存在则返回 `None`。
    pub fn get(&mut self, key: &K) -> Option<&V> {
        if self.entries.contains_key(key) {
            // 将键移到 order 末尾（最近访问）
            self.order.retain(|k| k != key);
            self.order.push(key.clone());
            self.entries.get(key)
        } else {
            None
        }
    }

    /// 插入键值对，返回旧值（如果键已存在）。
    ///
    /// 如果插入后超过容量，淘汰最久未访问的条目。
    /// 容量为 0 时直接返回 `None`，不存储任何条目。
    pub fn put(&mut self, key: K, value: V) -> Option<V> {
        // 容量为 0 时不缓存
        if self.capacity == 0 {
            return None;
        }

        // 如果键已存在，先从 order 中移除
        if self.entries.contains_key(&key) {
            self.order.retain(|k| k != &key);
        }

        self.order.push(key.clone());
        let old = self.entries.insert(key, value);

        // 淘汰超出容量的条目
        while self.entries.len() > self.capacity {
            if let Some(oldest) = self.order.first().cloned() {
                self.order.remove(0);
                self.entries.remove(&oldest);
            } else {
                break;
            }
        }

        old
    }

    /// 移除指定键，返回其值。
    pub fn remove(&mut self, key: &K) -> Option<V> {
        self.order.retain(|k| k != key);
        self.entries.remove(key)
    }

    /// 返回缓存中的条目数。
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 检查缓存是否为空。
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 返回缓存容量。
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// 清空缓存。
    pub fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
    }

    /// 检查是否包含指定键。
    pub fn contains(&self, key: &K) -> bool {
        self.entries.contains_key(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lru_new() {
        let cache: LruCache<i32, String> = LruCache::new(3);
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.capacity(), 3);
    }

    #[test]
    fn test_lru_put_get() {
        let mut cache = LruCache::new(3);
        cache.put(1, "one".to_string());
        cache.put(2, "two".to_string());

        assert_eq!(cache.get(&1), Some(&"one".to_string()));
        assert_eq!(cache.get(&2), Some(&"two".to_string()));
        assert_eq!(cache.get(&3), None);
    }

    #[test]
    fn test_lru_put_returns_old() {
        let mut cache = LruCache::new(3);
        cache.put(1, "one".to_string());
        let old = cache.put(1, "uno".to_string());
        assert_eq!(old, Some("one".to_string()));
        assert_eq!(cache.get(&1), Some(&"uno".to_string()));
    }

    #[test]
    fn test_lru_eviction() {
        let mut cache = LruCache::new(2);
        cache.put(1, "one".to_string());
        cache.put(2, "two".to_string());
        cache.put(3, "three".to_string()); // 应淘汰 key=1

        assert_eq!(cache.get(&1), None);
        assert_eq!(cache.get(&2), Some(&"two".to_string()));
        assert_eq!(cache.get(&3), Some(&"three".to_string()));
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn test_lru_get_updates_order() {
        let mut cache = LruCache::new(2);
        cache.put(1, "one".to_string());
        cache.put(2, "two".to_string());

        // 访问 key=1，使其成为最近访问
        cache.get(&1);

        // 插入新条目，应淘汰 key=2（最久未访问）
        cache.put(3, "three".to_string());

        assert_eq!(cache.get(&1), Some(&"one".to_string()));
        assert_eq!(cache.get(&2), None);
        assert_eq!(cache.get(&3), Some(&"three".to_string()));
    }

    #[test]
    fn test_lru_remove() {
        let mut cache = LruCache::new(3);
        cache.put(1, "one".to_string());
        cache.put(2, "two".to_string());

        let removed = cache.remove(&1);
        assert_eq!(removed, Some("one".to_string()));
        assert_eq!(cache.get(&1), None);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_lru_remove_nonexistent() {
        let mut cache: LruCache<i32, String> = LruCache::new(3);
        assert_eq!(cache.remove(&99), None);
    }

    #[test]
    fn test_lru_clear() {
        let mut cache = LruCache::new(3);
        cache.put(1, "one".to_string());
        cache.put(2, "two".to_string());
        cache.clear();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_lru_contains() {
        let mut cache = LruCache::new(3);
        cache.put(1, "one".to_string());
        assert!(cache.contains(&1));
        assert!(!cache.contains(&2));
    }

    #[test]
    fn test_lru_zero_capacity() {
        let mut cache: LruCache<i32, String> = LruCache::new(0);
        cache.put(1, "one".to_string());
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.get(&1), None);
    }

    #[test]
    fn test_lru_string_keys() {
        let mut cache = LruCache::new(2);
        cache.put("a".to_string(), 1);
        cache.put("b".to_string(), 2);
        cache.put("c".to_string(), 3);

        assert_eq!(cache.get(&"a".to_string()), None);
        assert_eq!(cache.get(&"b".to_string()), Some(&2));
        assert_eq!(cache.get(&"c".to_string()), Some(&3));
    }

    #[test]
    fn test_lru_put_same_key_no_eviction() {
        let mut cache = LruCache::new(2);
        cache.put(1, "one".to_string());
        cache.put(2, "two".to_string());
        cache.put(1, "uno".to_string()); // 更新已有键，不应淘汰

        assert_eq!(cache.len(), 2);
        assert_eq!(cache.get(&1), Some(&"uno".to_string()));
        assert_eq!(cache.get(&2), Some(&"two".to_string()));
    }
}
