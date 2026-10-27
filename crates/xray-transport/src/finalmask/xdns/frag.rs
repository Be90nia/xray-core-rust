//! # 分片重组管理（对应 Go `xdns/frag.go`，v26.9.30）
//!
//! 服务端把客户端发来的多片 query payload 按 (clientID, fragID) 重组；
//! TTL 8s，单 entry ≤ 4096B，单 client 未重组总量 ≤ 16KB，条目上限 4096。

use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};

use tokio::sync::Mutex;

pub(crate) type ClientID = [u8; 8];

const FRAG_TTL: Duration = Duration::from_secs(8);
const FRAG_SIZE: usize = 4096;
const FRAG_CLIENT_ID_SIZE: usize = 16384;
const FRAG_COUNT: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct FragKey {
    pub(crate) client_id: ClientID,
    pub(crate) frag_id: u8,
}

impl FragKey {
    pub(crate) fn new(client_id: ClientID, frag_id: u8) -> Self {
        Self { client_id, frag_id }
    }
}

struct FragEntry {
    data: Vec<Option<Vec<u8>>>,
    size: usize,
    filled: usize,
    total: u8,
    deadline: Instant,
}

struct Inner {
    m: HashMap<FragKey, FragEntry>,
    sizem: HashMap<ClientID, usize>,
    closed: bool,
}

/// 分片重组器（对应 Go `FragManager`）。
pub(crate) struct FragManager {
    inner: Mutex<Inner>,
}

impl FragManager {
    pub(crate) fn new() -> Self {
        Self {
            inner: Mutex::new(Inner { m: HashMap::new(), sizem: HashMap::new(), closed: false }),
        }
    }

    /// TTL 清扫：移除过期 entry（供服务端维护循环周期调用，对应 Go `gc`）。
    pub(crate) async fn sweep_expired(&self) {
        let mut g = self.inner.lock().await;
        if g.closed {
            return;
        }
        let now = xray_frame::compat::clock().now_instant();
        let expired: Vec<FragKey> =
            g.m.iter().filter(|(_, e)| now > e.deadline).map(|(k, _)| k.clone()).collect();
        for k in expired {
            Self::remove_entry(&mut g, &k);
        }
    }

    pub(crate) async fn close(&self) {
        let mut g = self.inner.lock().await;
        g.closed = true;
        g.m.clear();
        g.sizem.clear();
    }

    fn remove_entry(g: &mut Inner, k: &FragKey) -> Option<FragEntry> {
        let e = g.m.remove(k)?;
        let s = g.sizem.entry(k.client_id).or_default();
        *s = s.saturating_sub(e.size);
        if *s == 0 {
            g.sizem.remove(&k.client_id);
        }
        Some(e)
    }

    /// 淘汰 deadline 最早的 entry（对应 Go `tryRemove`）。
    fn try_remove(g: &mut Inner) {
        if g.m.len() < FRAG_COUNT {
            return;
        }
        let mut keys: VecDeque<FragKey> = g.m.keys().cloned().collect();
        let Some(first) = keys.pop_front() else { return };
        let mut worst = first.clone();
        let mut worst_dl = g.m[&first].deadline;
        for k in keys {
            let dl = g.m[&k].deadline;
            if dl < worst_dl {
                worst = k;
                worst_dl = dl;
            }
        }
        Self::remove_entry(g, &worst);
    }

    /// 投递一片；集齐返回重组 payload，否则返回空，对齐 Go `Feed`。
    pub(crate) async fn feed(
        &self,
        key: FragKey,
        frag_idx: u8,
        frag_n: u8,
        data: &[u8],
    ) -> Vec<u8> {
        let mut g = self.inner.lock().await;
        if g.closed || frag_n < 2 {
            return Vec::new();
        }

        let now = xray_frame::compat::clock().now_instant();
        let expired = g.m.get(&key).is_some_and(|e| now > e.deadline);
        let missing = !g.m.contains_key(&key);
        if missing || expired {
            if missing {
                Self::try_remove(&mut g);
            } else {
                Self::remove_entry(&mut g, &key);
            }
            g.m.insert(
                key.clone(),
                FragEntry {
                    data: vec![None; frag_n as usize],
                    size: 0,
                    filled: 0,
                    total: frag_n,
                    deadline: now + FRAG_TTL,
                },
            );
        }

        // 只读校验（独立作用域，避免与后续可变借用交叠）
        let reject = {
            let e = match g.m.get(&key) {
                Some(e) => e,
                None => return Vec::new(),
            };
            let over_client_budget = e.filled < e.total as usize - 1
                && g.sizem.get(&key.client_id).copied().unwrap_or(0) + data.len()
                    > FRAG_CLIENT_ID_SIZE;
            frag_n != e.total
                || frag_idx >= e.total
                || e.data[frag_idx as usize].is_some()
                || e.size + data.len() > FRAG_SIZE
                || over_client_budget
        };
        if reject {
            return Vec::new();
        }

        // 落片；集齐则拼接并移除（Go removeEntey 同步扣 sizem）
        let mut out: Option<(Vec<u8>, usize)> = None;
        {
            let e = g.m.get_mut(&key).expect("entry exists");
            e.data[frag_idx as usize] = Some(data.to_vec());
            e.size += data.len();
            e.filled += 1;
            e.deadline = now + FRAG_TTL;
            if e.filled == e.total as usize {
                let mut acc = Vec::with_capacity(e.size);
                for part in std::mem::take(&mut e.data) {
                    acc.extend_from_slice(&part.expect("filled == total"));
                }
                out = Some((acc, e.size));
            }
        }
        *g.sizem.entry(key.client_id).or_default() += data.len();
        if let Some((acc, total)) = out {
            g.m.remove(&key);
            let empty = match g.sizem.get_mut(&key.client_id) {
                Some(s) => {
                    *s = s.saturating_sub(total);
                    *s == 0
                },
                None => false,
            };
            if empty {
                g.sizem.remove(&key.client_id);
            }
            return acc;
        }
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn feed_assembles_in_order() {
        let m = FragManager::new();
        let key = FragKey { client_id: [1; 8], frag_id: 7 };
        assert!(m.feed(key.clone(), 0, 3, b"he").await.is_empty());
        assert!(m.feed(key.clone(), 2, 3, b"o").await.is_empty());
        assert!(m.feed(key.clone(), 9, 3, b"x").await.is_empty()); // idx 越界
        let out = m.feed(key.clone(), 1, 3, b"ll").await;
        assert_eq!(out, b"hello");
        // 重组后 entry 移除，同 key 可再起新组
        assert!(m.feed(key.clone(), 0, 3, b"a").await.is_empty());
    }

    #[tokio::test]
    async fn feed_rejects_short_frag_n() {
        let m = FragManager::new();
        let key = FragKey { client_id: [1; 8], frag_id: 1 };
        let out = m.feed(key, 0, 1, b"x").await;
        assert!(out.is_empty());
    }

    #[tokio::test]
    async fn feed_rejects_duplicate_fragment() {
        let m = FragManager::new();
        let key = FragKey { client_id: [2; 8], frag_id: 2 };
        assert!(m.feed(key.clone(), 0, 2, b"a").await.is_empty());
        assert!(m.feed(key.clone(), 0, 2, b"b").await.is_empty());
        let out = m.feed(key, 1, 2, b"c").await;
        assert_eq!(out, b"ac");
    }

    #[tokio::test]
    async fn feed_enforces_total_mismatch() {
        let m = FragManager::new();
        let key = FragKey { client_id: [3; 8], frag_id: 3 };
        assert!(m.feed(key.clone(), 0, 2, b"a").await.is_empty());
        // entry 未过期但 fragN 变化 → 拒收（对齐 Go `fragN != entry.total`）
        assert!(m.feed(key, 0, 3, b"b").await.is_empty());
    }

    #[tokio::test]
    async fn close_stops_feeding() {
        let m = FragManager::new();
        m.close().await;
        let key = FragKey { client_id: [4; 8], frag_id: 4 };
        assert!(m.feed(key, 0, 2, b"x").await.is_empty());
    }
}
