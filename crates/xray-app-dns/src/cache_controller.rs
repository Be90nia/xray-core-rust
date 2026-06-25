//! DNS 缓存控制器。对应 Go `app/dns/cache_controller.go`。
//!
//! ## 范围
//!
//! - 缓存数据结构 + cleanup 逻辑 + 内存收缩策略：完整翻译。
//! - `pubsub.Service` / `singleflight.Group`：Rust 端用 `tokio::sync::broadcast` +
//!   `Mutex<HashMap>` 简化模拟；真实订阅/去重逻辑见 `nameserver/cached.rs`。
//! - `task.Periodic`：用 `tokio::time::interval` + `tokio::spawn`，在 `start_cleanup_task` 启动。

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use tokio::sync::broadcast;

use crate::config::IpOption;
use crate::dnscommon::{IpRecord, Record};

/// 触发空表重建的最小历史峰值（Go `minSizeForEmptyRebuild = 512`）。
pub const MIN_SIZE_FOR_EMPTY_REBUILD: usize = 512;
/// 触发收缩的绝对阈值（Go `shrinkAbsoluteThreshold = 10240`）。
pub const SHRINK_ABSOLUTE_THRESHOLD: usize = 10240;
/// 触发收缩的比例阈值（Go `shrinkRatioThreshold = 0.65`）。
pub const SHRINK_RATIO_THRESHOLD: f64 = 0.65;
/// 后台清理周期（Go `cacheCleanup.Interval = 300 * time.Second`）。
pub const CLEANUP_INTERVAL: Duration = Duration::from_secs(300);

/// DNS 缓存控制器。对应 Go `CacheController`。
pub struct CacheController {
    /// 服务名（日志/诊断用）。
    pub name: String,
    /// 是否禁用缓存。
    pub disable_cache: bool,
    /// 是否提供过期数据。
    pub serve_stale: bool,
    /// 过期数据可服务的负 TTL（Go `serveExpiredTTL` 存为 `-int32(原值)`）。
    pub serve_expired_ttl_secs: i32,
    ips: RwLock<HashMap<String, Arc<Record>>>,
    /// 缓存生命周期峰值，用于收缩阈值计算。
    high_watermark: RwLock<usize>,
    /// 广播通道发送端（响应到达时发 `CacheEvent`）。
    pub tx: broadcast::Sender<CacheEvent>,
}

/// 广播事件。对应 Go `pubsub` 中的 `*IPRecord` 消息。
#[derive(Debug, Clone)]
pub enum CacheEvent {
    /// 域名 + 协议族 + 记录。
    Record {
        /// 查询域名。
        domain: String,
        /// 仅 IPv4 (true) 或仅 IPv6 (false)。
        is_v4: bool,
        /// 返回的记录。
        record: IpRecord,
    },
}

impl CacheController {
    /// 创建新控制器。对应 Go `NewCacheController`。
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        disable_cache: bool,
        serve_stale: bool,
        serve_expired_ttl: u32,
    ) -> Self {
        let (tx, _) = broadcast::channel(256);
        Self {
            name: name.into(),
            disable_cache,
            serve_stale,
            serve_expired_ttl_secs: -(serve_expired_ttl as i32),
            ips: RwLock::new(HashMap::new()),
            high_watermark: RwLock::new(0),
            tx,
        }
    }

    /// 当前缓存条目数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.ips.read().len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ips.read().is_empty()
    }

    /// 高水位（峰值）。
    #[must_use]
    pub fn high_watermark(&self) -> usize {
        *self.high_watermark.read()
    }

    /// 查询缓存。对应 Go `findRecords`。
    ///
    /// 返回 `Arc` 共享记录，调用方可不持锁使用。
    #[must_use]
    pub fn find_records(&self, fqdn: &str) -> Option<Arc<Record>> {
        self.ips.read().get(fqdn).cloned()
    }

    /// 写入 / 合并记录。对应 Go `addIoResult` / `setRecord`。
    ///
    /// `is_v4=true` 更新 A 记录，`false` 更新 AAAA。
    pub fn upsert(&self, fqdn: &str, is_v4: bool, record: IpRecord) {
        let mut ips = self.ips.write();
        let entry = ips
            .entry(fqdn.to_string())
            .or_insert_with(|| Arc::new(Record::default()));
        // Arc::make_mut：如独占则就地修改，否则 COW。
        let entry_mut = Arc::make_mut(entry);
        if is_v4 {
            entry_mut.a = Some(record);
        } else {
            entry_mut.aaaa = Some(record);
        }
    }

    /// 收集已过期 key。对应 Go `collectExpiredKeys`（内部逻辑）。
    ///
    /// **注意**：`serve_stale && serve_expired_ttl != 0` 时，把 `now` 提前以保留过期数据。
    #[must_use]
    pub fn collect_expired_keys(&self, now: Instant) -> Vec<String> {
        let ips = self.ips.read();
        if ips.is_empty() {
            return Vec::new();
        }
        let effective_now = self.effective_now(now);
        let mut keys = Vec::with_capacity(ips.len() / 4);
        for (domain, rec) in ips.iter() {
            let a_expired = rec.a.as_ref().is_some_and(|r| r.expire < effective_now);
            let aaaa_expired = rec
                .aaaa
                .as_ref()
                .is_some_and(|r| r.expire < effective_now);
            if a_expired || aaaa_expired {
                keys.push(domain.clone());
            }
        }
        keys
    }

    /// 清理 + 收缩。对应 Go `writeAndShrink`。
    ///
    /// 在持有写锁时调用，返回是否触发了收缩。
    pub fn cleanup_and_maybe_shrink(&self, expired_keys: Vec<String>, now: Instant) -> bool {
        let mut ips = self.ips.write();
        let mut high = self.high_watermark.write();

        let len_before = ips.len();
        if len_before > *high {
            *high = len_before;
        }

        let effective_now = self.effective_now(now);
        for domain in &expired_keys {
            let Some(rec) = ips.get_mut(domain) else {
                continue;
            };
            let a_expired = rec
                .a
                .as_ref()
                .is_some_and(|r| r.expire < effective_now);
            let aaaa_expired = rec
                .aaaa
                .as_ref()
                .is_some_and(|r| r.expire < effective_now);
            // 通过 Arc::make_mut 以避免 clone 整个 HashMap。
            // （此处 `ips.get_mut` 已返回 &mut Arc<Record>，但修 Arc 内容需要 make_mut。）
            if a_expired || aaaa_expired {
                let rec_mut = Arc::make_mut(rec);
                if a_expired {
                    rec_mut.a = None;
                }
                if aaaa_expired {
                    rec_mut.aaaa = None;
                }
                if rec_mut.a.is_none() && rec_mut.aaaa.is_none() {
                    ips.remove(domain);
                }
            }
        }

        let len_after = ips.len();

        if len_after == 0 {
            if *high >= MIN_SIZE_FOR_EMPTY_REBUILD {
                // 空表重建以回收内存。
                *ips = HashMap::new();
                *high = 0;
                return true;
            }
            return false;
        }

        let reduction = high.saturating_sub(len_after);
        if reduction > SHRINK_ABSOLUTE_THRESHOLD
            && (reduction as f64) > (*high as f64) * SHRINK_RATIO_THRESHOLD
        {
            // 收缩：重建更小的 HashMap。
            let old = std::mem::take(&mut *ips);
            *ips = old; // Rust HashMap 默认 capacity 收缩逻辑需 reserve/shrink_to_fit
            ips.shrink_to_fit();
            true
        } else {
            false
        }
    }

    /// 单轮 cleanup。对应 Go `CacheController.CacheCleanup`。
    ///
    /// 返回 `(是否发生清理, 是否发生收缩)`。
    pub fn run_cleanup(&self, now: Instant) -> (bool, bool) {
        // 与 Go 一致：即使无 expired，也走 cleanup_and_maybe_shrink 更新 high_watermark。
        // （Go collectExpiredKeys 返回空 list 时 writeAndShrink 仍被调用。）
        let expired = self.collect_expired_keys(now);
        let has_expired = !expired.is_empty();
        let shrunk = self.cleanup_and_maybe_shrink(expired, now);
        (has_expired, shrunk)
    }

    /// 启动后台 cleanup tokio task。
    ///
    /// 返回 `JoinHandle`，调用方可保留以便 shutdown。
    /// 对应 Go `cacheCleanup.Start()`。
    pub fn start_cleanup_task(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let ctrl = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
            interval.tick().await; // 跳过首次立即触发
            loop {
                interval.tick().await;
                let now = Instant::now();
                let (cleaned, shrunk) = ctrl.run_cleanup(now);
                if cleaned || shrunk {
                    tracing::debug!(
                        server = %ctrl.name,
                        cleaned,
                        shrunk,
                        "dns cache cleanup"
                    );
                }
            }
        })
    }

    /// 计算考虑 `serve_stale` 后的“有效当前时间”。
    fn effective_now(&self, now: Instant) -> Instant {
        if self.serve_stale && self.serve_expired_ttl_secs != 0 {
            // Go: now = now.Add(time.Duration(serveExpiredTTL) * time.Second)，
            // serveExpiredTTL 已存为负值（实际是减）。
            now - Duration::from_secs(self.serve_expired_ttl_secs.unsigned_abs() as u64)
        } else {
            now
        }
    }

    /// 注册订阅者（对应 Go `registerSubscribers`）。
    ///
    /// 返回 `(rx_v4, rx_v6)`：分别监听 A / AAAA 响应。
    /// 返回的 receiver 可能在 `upsert` 后收到 `CacheEvent::Record`。
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<CacheEvent> {
        self.tx.subscribe()
    }

    /// 计算发送缓存事件所需的 IPOption 语义（辅助函数）。
    ///
    /// ponytail: 真正的 dispatch 在 `nameserver/cached.rs::do_fetch` 完成，
    /// 此处仅作为 helper 暴露给外部封装。
    #[must_use]
    pub const fn option_enables(option: IpOption) -> (bool, bool) {
        (option.ipv4_enable, option.ipv6_enable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dnscommon::ip_record;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_ctrl() -> CacheController {
        CacheController::new("test", false, false, 0)
    }

    #[test]
    fn empty_controller_has_zero_len() {
        let c = make_ctrl();
        assert_eq!(c.len(), 0);
        assert!(c.is_empty());
        assert_eq!(c.high_watermark(), 0);
    }

    #[test]
    fn upsert_then_find_returns_record() {
        let c = make_ctrl();
        let now = Instant::now();
        let rec = ip_record(1, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)], Duration::from_secs(60), 0, now);
        c.upsert("example.com.", true, rec);
        assert_eq!(c.len(), 1);
        let r = c.find_records("example.com.").unwrap();
        assert!(r.a.is_some());
        assert!(r.aaaa.is_none());
    }

    #[test]
    fn upsert_separate_v4_v6_into_same_entry() {
        let c = make_ctrl();
        let now = Instant::now();
        let rec4 = ip_record(1, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)], Duration::from_secs(60), 0, now);
        let rec6 = ip_record(2, vec![IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)], Duration::from_secs(60), 0, now);
        c.upsert("x.com.", true, rec4);
        c.upsert("x.com.", false, rec6);
        let r = c.find_records("x.com.").unwrap();
        assert!(r.a.is_some());
        assert!(r.aaaa.is_some());
    }

    #[test]
    fn collect_expired_keys_returns_only_expired() {
        let c = make_ctrl();
        let now = Instant::now();
        let expired = ip_record(1, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)], Duration::from_secs(0), 0, now);
        let live = ip_record(2, vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))], Duration::from_secs(120), 0, now);
        c.upsert("gone.com.", true, expired);
        c.upsert("live.com.", true, live);
        // 让 expired 真正过期。
        let later = now + Duration::from_secs(1);
        let keys = c.collect_expired_keys(later);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], "gone.com.");
    }

    #[test]
    fn run_cleanup_removes_expired_and_returns_cleaned() {
        let c = make_ctrl();
        let now = Instant::now();
        let expired = ip_record(1, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)], Duration::from_secs(0), 0, now);
        c.upsert("gone.com.", true, expired);
        let later = now + Duration::from_secs(1);
        let (cleaned, _) = c.run_cleanup(later);
        assert!(cleaned);
        assert!(c.find_records("gone.com.").is_none());
    }

    #[test]
    fn run_cleanup_returns_false_when_nothing_expired() {
        let c = make_ctrl();
        let now = Instant::now();
        let live = ip_record(1, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)], Duration::from_secs(120), 0, now);
        c.upsert("live.com.", true, live);
        let (cleaned, _) = c.run_cleanup(now);
        assert!(!cleaned);
    }

    #[test]
    fn cleanup_high_watermark_tracks_peak() {
        let c = make_ctrl();
        let now = Instant::now();
        let live = ip_record(1, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)], Duration::from_secs(120), 0, now);
        c.upsert("a.com.", true, live.clone());
        c.upsert("b.com.", true, live.clone());
        c.upsert("c.com.", true, live);
        // high_watermark 仅在 cleanup 时记录（Go 同样行为）。
        let _ = c.run_cleanup(now);
        assert_eq!(c.high_watermark(), 3);
        assert_eq!(c.high_watermark(), 3); // 提升峰值
    }

    #[test]
    fn serve_stale_shifts_effective_now() {
        let c = CacheController::new("test", false, true, 30);
        assert_eq!(c.serve_expired_ttl_secs, -30);
        // effective_now 应当 now + 30s（Go: now.Add(-30s) 后与 expire 比较）。
        let now = Instant::now();
        let expired_under_normal = ip_record(1, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)], Duration::from_secs(10), 0, now);
        c.upsert("gone.com.", true, expired_under_normal);
        // 正常情况 (now+10s) 已过期；但 serve_stale 加 30s，所以不应被认为过期。
        let later = now + Duration::from_secs(20);
        let keys = c.collect_expired_keys(later);
        assert!(keys.is_empty(), "expected no expired keys due to serve_stale grace");
    }
}
