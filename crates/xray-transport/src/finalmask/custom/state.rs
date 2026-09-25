//! # Per-addr TTL 状态存储（对应 Go `finalmask/header/custom/state.go`）
//!
//! TCP/UDP 用于跨连接复用 vars（按 local|remote 或 addr 作 key），TTL 默认 5 秒。

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use parking_lot::Mutex;

/// 状态条目：vars + 过期时间。
struct StateEntry {
    vars: HashMap<String, Vec<u8>>,
    expires_at: Instant,
}

/// Per-key TTL 存储。
pub struct StateStore {
    ttl: Duration,
    entries: Mutex<HashMap<String, StateEntry>>,
}

impl StateStore {
    pub fn new(ttl: Duration) -> Self {
        Self { ttl, entries: Mutex::new(HashMap::new()) }
    }

    /// 读取 key 的 vars 副本；过期则清理并返回 None。
    pub fn get(&self, key: &str) -> Option<HashMap<String, Vec<u8>>> {
        let mut entries = self.entries.lock();
        let expired = matches!(entries.get(key), Some(e) if Instant::now() > e.expires_at);
        if expired {
            entries.remove(key);
            return None;
        }
        entries.get(key).map(|e| clone_vars(&e.vars))
    }

    /// 写入 key 的 vars（深拷贝，TTL = now + ttl）。
    pub fn set(&self, key: &str, vars: &HashMap<String, Vec<u8>>) {
        let mut entries = self.entries.lock();
        entries.insert(
            key.to_string(),
            StateEntry { vars: clone_vars(vars), expires_at: Instant::now() + self.ttl },
        );
    }
}

/// 深拷贝 vars 映射（对应 Go `cloneVars`）。
pub(crate) fn clone_vars(vars: &HashMap<String, Vec<u8>>) -> HashMap<String, Vec<u8>> {
    vars.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[test]
    fn set_then_get_returns_clone() {
        let store = StateStore::new(Duration::from_secs(5));
        let mut vars = HashMap::new();
        vars.insert("k".into(), b"v".to_vec());
        store.set("key1", &vars);

        let got = store.get("key1").expect("entry should exist");
        assert_eq!(got.get("k").map(|v| v.as_slice()), Some(b"v" as &[u8]));

        // 改变副本不影响存储
        vars.insert("k".into(), b"modified".to_vec());
        let got2 = store.get("key1").expect("entry should still exist");
        assert_eq!(got2.get("k").map(|v| v.as_slice()), Some(b"v" as &[u8]));
    }

    #[test]
    fn expired_entry_returns_none() {
        let store = StateStore::new(Duration::from_millis(10));
        let vars = HashMap::new();
        store.set("key", &vars);
        assert!(store.get("key").is_some());

        // 等过期
        std::thread::sleep(Duration::from_millis(20));
        assert!(store.get("key").is_none());
        // 第二次 get 不应 panic（已清理）
        assert!(store.get("key").is_none());
    }

    #[test]
    fn missing_key_returns_none() {
        let store = StateStore::new(Duration::from_secs(5));
        assert!(store.get("nonexistent").is_none());
    }
}
