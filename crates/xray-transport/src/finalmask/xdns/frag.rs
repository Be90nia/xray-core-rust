//! # 分片重组管理（对应 Go `xdns/frag.go`，v26.9.30）
//!
//! 服务端把客户端发来的多片 query payload 按 (clientID, fragID) 重组；
//! TTL 8s，单 entry ≤ 4096B，单 client 未重组总量 ≤ 16KB，条目上限 4096。

use std::{
    collections::{BTreeSet, HashMap},
    time::{Duration, Instant},
};

use tokio::sync::Mutex;

pub(crate) type ClientID = [u8; 8];

const FRAG_TTL: Duration = Duration::from_secs(8);
/// 单 entry 载荷上限（字节）。对应 Go `frag.go` 同界。**pub 是为了登记簿
/// 交叉断言**（`xray-core::memory_budget` 的 frag 账面必须与本常量同步，
/// bd wpa3o-b——同 `sockopt::QUIC_UDP_MIN_BUFFER` 先例）。
pub const FRAG_SIZE: usize = 4096;
/// 单 client 未重组总量上限（字节）。对应 Go 同界。pub 理由同上（wpa3o-b）。
pub const FRAG_CLIENT_ID_SIZE: usize = 16384;
/// 全表 entry 条数上限。对应 Go 同界。pub 理由同上（wpa3o-b）。
pub const FRAG_COUNT: usize = 4096;

/// 本容器**最坏堆占用**（字节）——登记簿账面的实现侧算式（bd wpa3o-b）。
///
/// - payload：`FRAG_COUNT × FRAG_SIZE`（每 entry 载荷 ≤ 4KiB，feed 侧拒绝超限）
/// - 片槽数组：每 entry `vec![None; frag_n]`，`frag_n` 为 u8 ⇒ ≤ 255 槽 ×
///   `size_of::<Option<Vec<u8>>>()`（niche 优化 = 24B，64 位平台恒定）
/// - entry 结构 + m 表桶 + by_deadline/sizem 索引面 ⇒ 取整上沿 1MiB（登记簿面
///   用取整值，禁猜实现细节）
///
/// entry 结构按 `ENTRY_STRUCT_BOOKED`（64B 上沿，见下）计（**平台无关**：Windows 上
/// `Instant` 携带 QPC 频率 = 16B ⇒ FragEntry = 64B；Linux/macOS Instant = 8B
/// ⇒ 56B。账面字面量不得随平台漂移 ⇒ 统一按大值登记）。
///
/// 合计 = 4096 × (4096 + 6120 + 64) + 1,048,576 = **43,155,456**（≈41.2MiB）。
/// 交叉断言住 `xray-core::memory_budget` tests（改任一上限即红，账面随重算）。
pub const WORST_CASE_BYTES: usize = FRAG_COUNT
    * (FRAG_SIZE
        + (u8::MAX as usize) * std::mem::size_of::<Option<Vec<u8>>>()
        + ENTRY_STRUCT_BOOKED)
    + 1_048_576;

/// FragEntry 单结构的**平台无关账面上沿**（字节）：Windows 64B（`Instant` 16B =
/// QPC 频率 + 计数，rust#103182 起）、Linux/macOS 56B ⇒ 统一按 64B 登记；
/// 布局增长超过本值的测试锚见 `worst_case_layout_and_value_anchor`（即红须重算账面）。
const ENTRY_STRUCT_BOOKED: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
    /// p7qln：deadline 序索引（`(deadline, key)`），淘汰/清扫走队首 O(log n)，
    /// 替代 Go `tryRemove`/`gc` 的全表线性扫描。与 `m` 的键集恒同步（不变量，
    /// 见 `deadline_index_stays_consistent` 测试）。
    by_deadline: BTreeSet<(Instant, FragKey)>,
    closed: bool,
}

/// 分片重组器（对应 Go `FragManager`）。
pub(crate) struct FragManager {
    inner: Mutex<Inner>,
}

impl FragManager {
    pub(crate) fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                m: HashMap::new(),
                sizem: HashMap::new(),
                by_deadline: BTreeSet::new(),
                closed: false,
            }),
        }
    }

    /// TTL 清扫：移除过期 entry（供服务端维护循环周期调用，对应 Go `gc`）。
    pub(crate) async fn sweep_expired(&self) {
        let mut g = self.inner.lock().await;
        if g.closed {
            return;
        }
        let now = xray_frame::compat::clock().now_instant();
        // p7qln：deadline 序索引队首即最老，只弹真正过期的（O(k log n)；
        // 原实现全表扫 O(n)）。
        while let Some(front) = g.by_deadline.iter().next().map(|(dl, k)| (*dl, k.clone())) {
            if front.0 >= now {
                break;
            }
            Self::remove_entry(&mut g, &front.1);
        }
    }

    pub(crate) async fn close(&self) {
        let mut g = self.inner.lock().await;
        g.closed = true;
        g.m.clear();
        g.sizem.clear();
        g.by_deadline.clear();
    }

    fn remove_entry(g: &mut Inner, k: &FragKey) -> Option<FragEntry> {
        let e = g.m.remove(k)?;
        g.by_deadline.remove(&(e.deadline, k.clone()));
        let s = g.sizem.entry(k.client_id).or_default();
        *s = s.saturating_sub(e.size);
        if *s == 0 {
            g.sizem.remove(&k.client_id);
        }
        Some(e)
    }

    /// 淘汰 deadline 最早的 entry（对应 Go `tryRemove`）。
    ///
    /// p7qln：原实现把全表 key 克隆进 VecDeque 再线性扫最老 deadline（表满时
    /// 每个新 entry O(4096) 扫描 + 4096 次 key 分配）；索引队首即最老，O(log n)。
    fn try_remove(g: &mut Inner) {
        if g.m.len() < FRAG_COUNT {
            return;
        }
        let first = g.by_deadline.iter().next().map(|(_, k)| k.clone());
        if let Some(k) = first {
            Self::remove_entry(g, &k);
        }
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
            g.by_deadline.insert((now + FRAG_TTL, key.clone()));
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

        // 落片；集齐则拼接并移除（remove_entry 同步扣 sizem + deadline 索引）
        let mut out: Option<Vec<u8>> = None;
        // (旧 deadline, 新 deadline)：借 `e`（经 Deref 是对 `*g` 整体借用）期间不能
        // 同时摸 `g.by_deadline`，索引刷新挪到块外做。
        let mut refresh: Option<(Instant, Instant)> = None;
        {
            let e = g.m.get_mut(&key).expect("entry exists");
            e.data[frag_idx as usize] = Some(data.to_vec());
            e.size += data.len();
            e.filled += 1;
            if e.filled == e.total as usize {
                let mut acc = Vec::with_capacity(e.size);
                for part in std::mem::take(&mut e.data) {
                    acc.extend_from_slice(&part.expect("filled == total"));
                }
                out = Some(acc);
            } else {
                // deadline 刷新（索引同步在块外，见 refresh）；完成路径不刷新：
                // entry 即刻移除，索引由 remove_entry 清理。
                let old = e.deadline;
                e.deadline = now + FRAG_TTL;
                refresh = Some((old, e.deadline));
            }
        }
        if let Some((old, new)) = refresh {
            g.by_deadline.remove(&(old, key.clone()));
            g.by_deadline.insert((new, key.clone()));
        }
        *g.sizem.entry(key.client_id).or_default() += data.len();
        if let Some(acc) = out {
            Self::remove_entry(&mut g, &key);
            return acc;
        }
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// bd wpa3o-b：账面算式的布局假设 + 数值锚。改 FragEntry 布局或任一上限
    /// 即红——登记簿（`xray-frame::budget::XDNS_FRAG_WORST_CASE_BYTES`）须随重算
    /// （交叉断言本体住 `xray-core::memory_budget`，它同时可见两侧）。
    #[test]
    fn worst_case_layout_and_value_anchor() {
        assert_eq!(std::mem::size_of::<Option<Vec<u8>>>(), 24, "niche 优化假设");
        assert!(
            std::mem::size_of::<FragEntry>() <= ENTRY_STRUCT_BOOKED,
            "FragEntry 布局增长超账面上沿 {}B（实测 {}B）：登记簿须重算（bd wpa3o-b）",
            ENTRY_STRUCT_BOOKED,
            std::mem::size_of::<FragEntry>()
        );
        assert_eq!(WORST_CASE_BYTES, 43_155_456, "4096×(4096+255×24+64)+1MiB 上沿");
    }

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

    /// p7qln 结构断言：deadline 序索引与条目集合恒同步（建/刷/完成/清扫各路径）。
    /// 若哪条路径漏同步（如完成路径直连 `m.remove`），本测试必红。
    #[tokio::test]
    async fn deadline_index_stays_consistent() {
        let m = FragManager::new();
        let key = FragKey { client_id: [9; 8], frag_id: 1 };
        assert!(m.feed(key.clone(), 0, 3, b"a").await.is_empty());
        assert!(m.feed(key.clone(), 1, 3, b"b").await.is_empty());
        // 完成 → remove_entry 必须同步索引
        let out = m.feed(key, 2, 3, b"c").await;
        assert_eq!(out, b"abc");
        {
            let g = m.inner.lock().await;
            assert!(g.m.is_empty(), "完成即移除");
            assert!(g.by_deadline.is_empty(), "完成路径必须同步索引");
        }
        // 未完成 entry：跨 sweep（未到期）保留，索引一致
        let key2 = FragKey { client_id: [9; 8], frag_id: 2 };
        assert!(m.feed(key2, 0, 2, b"x").await.is_empty());
        m.sweep_expired().await;
        let g = m.inner.lock().await;
        assert_eq!(g.m.len(), 1);
        assert_eq!(g.by_deadline.len(), g.m.len(), "索引与条目集合必须恒等");
    }

    /// p7qln：满表（FRAG_COUNT）再进新 key ⇒ 淘汰 deadline 最早者（对齐 Go
    /// `tryRemove` 语义），条目数守恒、幸存者完好。新实现走索引队首 O(log n)。
    #[tokio::test]
    async fn eviction_at_capacity_picks_oldest() {
        let m = FragManager::new();
        let first = FragKey { client_id: [0; 8], frag_id: 0 };
        assert!(m.feed(first.clone(), 0, 2, b"a").await.is_empty());
        // 留出可分辨的 deadline 差（Instant 粒度不保证逐次递增）
        tokio::time::sleep(Duration::from_millis(5)).await;
        for i in 1..FRAG_COUNT as u64 {
            let k = FragKey { client_id: i.to_be_bytes(), frag_id: 0 };
            assert!(m.feed(k, 0, 2, b"a").await.is_empty());
        }
        {
            let g = m.inner.lock().await;
            assert_eq!(g.m.len(), FRAG_COUNT, "表满");
            assert_eq!(g.by_deadline.len(), FRAG_COUNT, "索引同步");
        }
        // 新 key 进满表 ⇒ 淘汰最老（first）
        let extra = FragKey { client_id: u64::MAX.to_be_bytes(), frag_id: 0 };
        assert!(m.feed(extra, 0, 2, b"a").await.is_empty());
        {
            let g = m.inner.lock().await;
            assert_eq!(g.m.len(), FRAG_COUNT, "满表淘汰后条目数守恒");
            assert!(!g.m.contains_key(&first), "最早 deadline 必须被淘汰");
            assert_eq!(g.by_deadline.len(), g.m.len(), "索引一致性");
        }
        // 幸存者完好：补 idx1 重组成功
        let survivor = FragKey { client_id: (FRAG_COUNT as u64 - 1).to_be_bytes(), frag_id: 0 };
        let out = m.feed(survivor, 1, 2, b"b").await;
        assert_eq!(out, b"ab");
    }
}
