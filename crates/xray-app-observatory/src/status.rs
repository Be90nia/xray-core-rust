//! StatusStore：管理 Vec````<OutboundStatus>```` + update/clearRemoved/findLocation。
//!
//! 对应 Go `Observer.status` + `statusLock` + `updateStatusForResult` +
//! `clearRemovedOutbounds` + `findStatusLocationLockHolderOnly`。

use parking_lot::Mutex;

use crate::config::{DEAD_DELAY_MS, OutboundStatus, ProbeResult};

/// 状态表硬上界（有界背板）：正常配置的 outbound tag 数远小于此值；触达即淘汰
/// 最久未探测项——已配置 tag 每轮刷新 last_try_time 不会落入淘汰候选，查询
/// 语义与无界版一致（防 tag 流失面失控的防御性上界）。
const MAX_STATUSES: usize = 1024;
/// StatusStore：线程安全的 outbound 状态集合。
pub struct StatusStore {
    inner: Mutex<Vec<OutboundStatus>>,
}

impl StatusStore {
    pub fn new() -> Self {
        Self { inner: Mutex::new(Vec::new()) }
    }

    /// 当前快照（clone 所有 status）。
    pub fn snapshot(&self) -> Vec<OutboundStatus> {
        self.inner.lock().clone()
    }

    /// 当前 status 数量。
    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.lock().is_empty()
    }

    /// 查找指定 outbound tag 在 status 列表中的索引（不存在返回 -1... 即 None）。
    ///
    /// 对应 Go `findStatusLocationLockHolderOnly`。
    pub fn find_location(&self, outbound_tag: &str) -> Option<usize> {
        self.inner.lock().iter().position(|s| s.outbound_tag == outbound_tag)
    }

    /// 用 ProbeResult 更新指定 outbound 的 status。
    ///
    /// 对应 Go `updateStatusForResult`：
    /// - 若 outbound 已存在 → 更新现有
    /// - 否则 → 创建新 entry 追加（触顶时先淘汰最久未探测项，上界 MAX_STATUSES）
    /// - alive → 更新 delay + last_seen_time
    /// - !alive → delay = DEAD_DELAY_MS + last_error_reason
    pub fn update_with_probe_result(
        &self,
        outbound_tag: &str,
        result: &ProbeResult,
        now_unix_secs: i64,
    ) {
        let mut g = self.inner.lock();

        // 查找或插入
        let idx = g.iter().position(|s| s.outbound_tag == outbound_tag);
        let idx = match idx {
            Some(i) => i,
            None => {
                // 有界背板：满时逐 last_try_time 最小（最久未探测）项，并列取
                // 下标最小（最早入表）确定序。已存在 tag 的更新路径永不触发淘汰。
                if g.len() >= MAX_STATUSES {
                    let stale_idx =
                        g.iter().enumerate().min_by_key(|(_, s)| s.last_try_time).map(|(i, _)| i);
                    if let Some(i) = stale_idx {
                        g.remove(i);
                    }
                }
                g.push(OutboundStatus::default());
                g.len() - 1
            },
        };

        let status = &mut g[idx];
        status.last_try_time = now_unix_secs;
        status.outbound_tag = outbound_tag.to_string();
        status.alive = result.alive;
        if result.alive {
            status.delay = result.delay;
            status.last_seen_time = now_unix_secs;
            status.last_error_reason.clear();
        } else {
            status.last_error_reason = result.last_error_reason.clone();
            status.delay = DEAD_DELAY_MS;
        }
    }

    /// 移除 status 中 outbound_tag 不在 `keep` 列表中的项。
    ///
    /// 对应 Go `clearRemovedOutbounds`。
    pub fn clear_removed(&self, keep: &[String]) {
        let mut g = self.inner.lock();
        g.retain(|s| keep.iter().any(|k| k == &s.outbound_tag));
    }
}

impl Default for StatusStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result_alive(delay: i64) -> ProbeResult {
        ProbeResult { alive: true, delay, last_error_reason: String::new() }
    }

    fn result_dead(reason: &str) -> ProbeResult {
        ProbeResult { alive: false, delay: 0, last_error_reason: reason.into() }
    }

    #[test]
    fn new_store_is_empty() {
        let s = StatusStore::new();
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn update_inserts_new_status_for_alive() {
        let s = StatusStore::new();
        s.update_with_probe_result("out1", &result_alive(50), 1000);
        assert_eq!(s.len(), 1);

        let snap = s.snapshot();
        assert_eq!(snap[0].outbound_tag, "out1");
        assert!(snap[0].alive);
        assert_eq!(snap[0].delay, 50);
        assert_eq!(snap[0].last_seen_time, 1000);
        assert_eq!(snap[0].last_try_time, 1000);
        assert!(snap[0].last_error_reason.is_empty());
    }

    #[test]
    fn update_inserts_new_status_for_dead() {
        let s = StatusStore::new();
        s.update_with_probe_result("out1", &result_dead("timeout"), 1000);
        let snap = s.snapshot();
        assert!(!snap[0].alive);
        assert_eq!(snap[0].delay, DEAD_DELAY_MS);
        assert_eq!(snap[0].last_error_reason, "timeout");
        // dead 不更新 last_seen_time
        assert_eq!(snap[0].last_seen_time, 0);
    }

    #[test]
    fn update_modifies_existing_status() {
        let s = StatusStore::new();
        s.update_with_probe_result("out1", &result_alive(50), 1000);
        s.update_with_probe_result("out1", &result_alive(30), 2000);
        assert_eq!(s.len(), 1);
        let snap = s.snapshot();
        assert_eq!(snap[0].delay, 30);
        assert_eq!(snap[0].last_seen_time, 2000);
    }

    #[test]
    fn update_alive_then_dead_transitions() {
        let s = StatusStore::new();
        s.update_with_probe_result("out1", &result_alive(50), 1000);
        s.update_with_probe_result("out1", &result_dead("refused"), 2000);
        let snap = s.snapshot();
        assert!(!snap[0].alive);
        assert_eq!(snap[0].delay, DEAD_DELAY_MS);
        assert_eq!(snap[0].last_error_reason, "refused");
        // last_seen_time 不变（dead 不更新）
        assert_eq!(snap[0].last_seen_time, 1000);
    }

    #[test]
    fn update_dead_then_alive_transitions() {
        let s = StatusStore::new();
        s.update_with_probe_result("out1", &result_dead("refused"), 1000);
        s.update_with_probe_result("out1", &result_alive(40), 2000);
        let snap = s.snapshot();
        assert!(snap[0].alive);
        assert_eq!(snap[0].delay, 40);
        assert_eq!(snap[0].last_seen_time, 2000);
        assert!(snap[0].last_error_reason.is_empty());
    }

    #[test]
    fn find_location_existing() {
        let s = StatusStore::new();
        s.update_with_probe_result("a", &result_alive(1), 0);
        s.update_with_probe_result("b", &result_alive(2), 0);
        s.update_with_probe_result("c", &result_alive(3), 0);
        assert_eq!(s.find_location("b"), Some(1));
        assert_eq!(s.find_location("a"), Some(0));
        assert_eq!(s.find_location("c"), Some(2));
    }

    #[test]
    fn find_location_missing() {
        let s = StatusStore::new();
        s.update_with_probe_result("a", &result_alive(1), 0);
        assert!(s.find_location("missing").is_none());
    }

    #[test]
    fn find_location_empty_store() {
        let s = StatusStore::new();
        assert!(s.find_location("any").is_none());
    }

    #[test]
    fn clear_removed_removes_unlisted() {
        let s = StatusStore::new();
        s.update_with_probe_result("a", &result_alive(1), 0);
        s.update_with_probe_result("b", &result_alive(2), 0);
        s.update_with_probe_result("c", &result_alive(3), 0);
        s.clear_removed(&["a".into(), "c".into()]);
        let snap = s.snapshot();
        assert_eq!(snap.len(), 2);
        assert!(snap.iter().any(|s| s.outbound_tag == "a"));
        assert!(snap.iter().any(|s| s.outbound_tag == "c"));
        assert!(!snap.iter().any(|s| s.outbound_tag == "b"));
    }

    #[test]
    fn clear_removed_empty_keep_removes_all() {
        let s = StatusStore::new();
        s.update_with_probe_result("a", &result_alive(1), 0);
        s.clear_removed(&[]);
        assert!(s.is_empty());
    }

    #[test]
    fn clear_removed_empty_store_is_noop() {
        let s = StatusStore::new();
        s.clear_removed(&["a".into()]);
        assert!(s.is_empty());
    }

    #[test]
    fn snapshot_returns_clone() {
        let s = StatusStore::new();
        s.update_with_probe_result("a", &result_alive(1), 0);
        let snap1 = s.snapshot();
        let snap2 = s.snapshot();
        assert_eq!(snap1, snap2);
    }

    #[test]
    fn snapshot_is_independent_of_store() {
        let s = StatusStore::new();
        s.update_with_probe_result("a", &result_alive(1), 0);
        let mut snap = s.snapshot();
        snap[0].delay = 999;
        // 原始 store 不变
        assert_eq!(s.snapshot()[0].delay, 1);
    }
    #[test]
    fn status_store_caps_at_max_and_evicts_stalest() {
        // 有界背板：触顶后长度钉在上界；淘汰走「最久未探测」（last_try_time
        // 最小），刚刷新的 tag 永不被逐——已配置 tag 每轮刷新 last_try_time，
        // 正常配置（tag 数远小于上界）行为与无界版完全一致。
        let s = StatusStore::new();
        for i in 0..1024 {
            s.update_with_probe_result(&format!("tag{i}"), &result_alive(50), 1_000);
        }
        assert_eq!(s.len(), 1024);

        // tag0 刷新为最新，再溢入新 tag → 被逐的必须是未刷新的 tag1。
        s.update_with_probe_result("tag0", &result_alive(60), 2_000);
        s.update_with_probe_result("overflow", &result_alive(50), 2_000);
        assert_eq!(s.len(), 1024, "触顶后长度不再增长");
        assert!(s.find_location("tag0").is_some(), "刚刷新的 tag 不被逐");
        assert!(s.find_location("overflow").is_some(), "新 tag 仍可入表");
        assert!(s.find_location("tag1").is_none(), "最久未探测项被逐");
    }

    #[test]
    fn default_is_empty() {
        let s = StatusStore::default();
        assert!(s.is_empty());
    }
}
