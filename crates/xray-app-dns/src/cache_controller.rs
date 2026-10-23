//! DNS 缓存控制器。对应 Go `app/dns/cache_controller.go`。
//!
//! ## 范围
//!
//! - 缓存数据结构 + cleanup 逻辑 + 内存收缩策略：完整翻译。
//! - `pubsub.Service` / `singleflight.Group`：Rust 端用 `tokio::sync::broadcast` + `Mutex<HashMap>`
//!   简化模拟；真实订阅/去重逻辑见 `nameserver/cached.rs`。
//! - `task.Periodic`：用 `tokio::time::interval`，经 `start_managed` 在**启动期** 注册进实例
//!   `FxScope` 托管（P1-11：配置期零 spawn，坑约束 5）。

use std::{
    collections::HashMap,
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};

use parking_lot::RwLock;
use skeleton::clock::{Clock, SystemClock};
use skeleton_infra::fx::FxScope;
use tokio::sync::broadcast;

use crate::{
    config::IpOption,
    dnscommon::{IpRecord, Record},
};

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
    /// 负缓存 TTL（秒）。0 = 禁用。Go cache 无显式字段——当前 NXDOMAIN 按
    /// 响应 TTL 走正缓存 upsert（`fetch` 只写真实响应），本字段暂无行为
    /// 消费方，保留 config 透传面（jsonconf `negativeTtlSecs`）。
    pub negative_ttl_secs: u32,
    ips: RwLock<HashMap<String, Arc<Record>>>,
    /// 缓存生命周期峰值，用于收缩阈值计算。
    high_watermark: RwLock<usize>,
    /// 广播通道发送端（响应到达时发 `CacheEvent`）。
    pub tx: broadcast::Sender<CacheEvent>,
    pub single_flight: tokio::sync::Mutex<
        HashMap<(String, bool, bool), broadcast::Sender<crate::nameserver::cached::QueryOutcome>>,
    >,
    /// 时间源契约（P1-12）：TTL/stale 判定与清理节奏统一走 `skeleton::clock::Clock`。
    /// 生产 `SystemClock`；测试注入 `MockClock` 得确定性时间线（零真等）。
    clock: Arc<dyn Clock>,
    /// 实例托管 scope（P1-11）：启动期经 `start_managed` 注单（配置期为空 =
    /// 零 spawn）；serveStale pull（`nameserver/cached.rs`）与 DoH h2 conn 驱动
    /// （`nameserver/doh.rs`）经 `fx_scope` 取用同一 scope。
    fx: OnceLock<Arc<FxScope>>,
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
    ///
    /// 时间源默认 [`SystemClock`]；测试注入 [`skeleton::clock::MockClock`]
    /// 走 [`Self::with_clock`]（P1-12：TTL/stale 判定可确定性测试）。
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        disable_cache: bool,
        serve_stale: bool,
        serve_expired_ttl: u32,
        negative_ttl_secs: u32,
    ) -> Self {
        Self::with_clock(
            name,
            disable_cache,
            serve_stale,
            serve_expired_ttl,
            negative_ttl_secs,
            Arc::new(SystemClock),
        )
    }

    /// 创建新控制器（可注入时间源）。对应 Go `NewCacheController` + 时钟注入口。
    ///
    /// P1-12：TTL/stale/清理节奏统一走 [`Clock`] 契约——生产 [`SystemClock`]
    /// 直通真实时间；测试注入 `MockClock` 后过期路径零真等（`advance` 显式
    /// 推进，时间线逐纳秒可断言）。
    #[must_use]
    pub fn with_clock(
        name: impl Into<String>,
        disable_cache: bool,
        serve_stale: bool,
        serve_expired_ttl: u32,
        negative_ttl_secs: u32,
        clock: Arc<dyn Clock>,
    ) -> Self {
        let (tx, _) = broadcast::channel(256);
        Self {
            name: name.into(),
            disable_cache,
            serve_stale,
            serve_expired_ttl_secs: -(serve_expired_ttl as i32),
            negative_ttl_secs,
            ips: RwLock::new(HashMap::new()),
            high_watermark: RwLock::new(0),
            tx,
            single_flight: tokio::sync::Mutex::new(HashMap::new()),
            clock,
            fx: OnceLock::new(),
        }
    }

    /// 缓存时间源（P1-12）：`query_ip`/`fetch` 的 TTL 判定与后台清理共用
    /// 同一时钟，保证过期判定单源一致。
    #[must_use]
    pub(crate) fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
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
        if self.disable_cache {
            return;
        }
        let mut ips = self.ips.write();
        let entry = ips.entry(fqdn.to_string()).or_insert_with(|| Arc::new(Record::default()));
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
            let aaaa_expired = rec.aaaa.as_ref().is_some_and(|r| r.expire < effective_now);
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
            let a_expired = rec.a.as_ref().is_some_and(|r| r.expire < effective_now);
            let aaaa_expired = rec.aaaa.as_ref().is_some_and(|r| r.expire < effective_now);
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

    /// 实例托管 scope（P1-11 注单后可见）：serveStale pull（`cached.rs::pull`）
    /// 与 DoH h2 conn 驱动（`doh.rs::query_once`）的 spawn 口。
    #[must_use]
    pub(crate) fn fx_scope(&self) -> Option<&Arc<FxScope>> {
        self.fx.get()
    }

    /// 注单实例 scope（仅附着，不 spawn）。测试直连路径用；生产经
    /// [`Self::start_managed`]。首注单为准（重复 start 不换 scope，与读侧一致）。
    pub(crate) fn attach_scope(&self, fx: &Arc<FxScope>) {
        let _ = self.fx.set(Arc::clone(fx));
    }

    /// 启动期注册：注单实例 [`FxScope`] + spawn 后台 cleanup 托管任务。
    /// 对应 Go `cacheCleanup.Start()`。
    ///
    /// P1-11：**配置期不得调用**（配置期无 runtime 托管面 = 生命周期错位）——
    /// 生产唯一调用点 = 实例 start（`DnsService` 的 `Feature::start`，经
    /// `Server::start_managed_tasks` 逐 NS 下发）。
    ///
    /// - 无 tokio runtime（同步上下文/纯结构测试）→ 跳过 spawn 留 debug 痕
    ///   （后台任务本就无处运行，同旧 `Handle::try_current` None 语义）。
    /// - scope 已关（停机中）→ 拒新 spawn 留 warn 痕，不 panic（坑约束 5： spawn
    ///   失败按错误归类上报）。
    ///
    /// 任务归 scope 生命周期集托管：停机 `FxScope::shutdown` abort 兜底，
    /// `expect_idle` 在途归零可断言。清理时间取 [`Clock::now_instant`]
    /// （P1-12：与 TTL/stale 判定同一时钟源，单钟语义不变）。
    pub fn start_managed(self: &Arc<Self>, fx: &Arc<FxScope>, interval: Duration) {
        self.attach_scope(fx);
        if tokio::runtime::Handle::try_current().is_err() {
            tracing::debug!(server = %self.name, "dns cleanup task skipped: no tokio runtime");
            return;
        }
        let ctrl = Arc::clone(self);
        let spawned = fx.spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await; // 跳过首次立即触发
            loop {
                ticker.tick().await;
                let now = ctrl.clock.now_instant();
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
        });
        if spawned.is_err() {
            tracing::warn!(server = %self.name, "dns cleanup task not started: fx scope closed");
        }
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
    use std::net::{IpAddr, Ipv4Addr};

    use skeleton::clock::MockClock;

    use super::*;
    use crate::dnscommon::ip_record;

    fn make_ctrl() -> CacheController {
        CacheController::new("test", false, false, 0, 0)
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
        let now = c.clock().now_instant();
        let rec =
            ip_record(1, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)], Duration::from_secs(60), 0, now);
        c.upsert("example.com.", true, rec);
        assert_eq!(c.len(), 1);
        let r = c.find_records("example.com.").unwrap();
        assert!(r.a.is_some());
        assert!(r.aaaa.is_none());
    }

    #[test]
    fn upsert_separate_v4_v6_into_same_entry() {
        let c = make_ctrl();
        let now = c.clock().now_instant();
        let rec4 =
            ip_record(1, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)], Duration::from_secs(60), 0, now);
        let rec6 = ip_record(
            2,
            vec![IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)],
            Duration::from_secs(60),
            0,
            now,
        );
        c.upsert("x.com.", true, rec4);
        c.upsert("x.com.", false, rec6);
        let r = c.find_records("x.com.").unwrap();
        assert!(r.a.is_some());
        assert!(r.aaaa.is_some());
    }

    #[test]
    fn collect_expired_keys_returns_only_expired() {
        let c = make_ctrl();
        let now = c.clock().now_instant();
        let expired =
            ip_record(1, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)], Duration::from_secs(0), 0, now);
        let live = ip_record(
            2,
            vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))],
            Duration::from_secs(120),
            0,
            now,
        );
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
        let now = c.clock().now_instant();
        let expired =
            ip_record(1, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)], Duration::from_secs(0), 0, now);
        c.upsert("gone.com.", true, expired);
        let later = now + Duration::from_secs(1);
        let (cleaned, _) = c.run_cleanup(later);
        assert!(cleaned);
        assert!(c.find_records("gone.com.").is_none());
    }

    #[test]
    fn run_cleanup_returns_false_when_nothing_expired() {
        let c = make_ctrl();
        let now = c.clock().now_instant();
        let live =
            ip_record(1, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)], Duration::from_secs(120), 0, now);
        c.upsert("live.com.", true, live);
        let (cleaned, _) = c.run_cleanup(now);
        assert!(!cleaned);
    }

    #[test]
    fn cleanup_high_watermark_tracks_peak() {
        let c = make_ctrl();
        let now = c.clock().now_instant();
        let live =
            ip_record(1, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)], Duration::from_secs(120), 0, now);
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
        let c = CacheController::new("test", false, true, 30, 0);
        assert_eq!(c.serve_expired_ttl_secs, -30);
        // effective_now 应当 now + 30s（Go: now.Add(-30s) 后与 expire 比较）。
        let now = c.clock().now_instant();
        let expired_under_normal =
            ip_record(1, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)], Duration::from_secs(10), 0, now);
        c.upsert("gone.com.", true, expired_under_normal);
        // 正常情况 (now+10s) 已过期；但 serve_stale 加 30s，所以不应被认为过期。
        let later = now + Duration::from_secs(20);
        let keys = c.collect_expired_keys(later);
        assert!(keys.is_empty(), "expected no expired keys due to serve_stale grace");
    }

    /// 对应 Go `cache_controller.go:255-258`：`disableCache=true` 时
    /// upsert 后立即返回，不写 `ips`，`find_records` 也无。
    /// 对齐「discover-after-write」语义。
    #[test]
    fn upsert_no_op_when_disable_cache() {
        let c = CacheController::new("test", true, false, 0, 0);
        let now = c.clock().now_instant();
        let rec =
            ip_record(1, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)], Duration::from_secs(60), 0, now);
        c.upsert("example.com.", true, rec);
        assert_eq!(c.len(), 0, "disable_cache upsert must be no-op");
        assert!(c.find_records("example.com.").is_none());
    }

    /// 生产接线验证：start_managed 周期执行 run_cleanup（FxScope 托管）。
    ///
    /// P1-12 确定性化（零真等）：时钟注入 [`MockClock`]（判定时间线显式
    /// `advance` 推进）+ tokio `start_paused`（调度时间线虚拟推进）——
    /// 原实现真等 200ms 等 ticker。
    #[tokio::test(start_paused = true)]
    async fn cleanup_task_removes_expired_entries() {
        let clock = Arc::new(MockClock::new());
        let c = Arc::new(CacheController::with_clock("test", false, false, 0, 0, clock.clone()));
        let now = clock.now_instant();
        let expired =
            ip_record(1, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)], Duration::from_secs(0), 0, now);
        c.upsert("gone.com.", true, expired);
        let live = ip_record(
            2,
            vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))],
            Duration::from_secs(120),
            0,
            now,
        );
        c.upsert("live.com.", true, live);

        let fx = Arc::new(skeleton_infra::fx::FxScope::new());
        c.start_managed(&fx, Duration::from_millis(20));
        assert_eq!(fx.in_flight(), 1, "start_managed must host the cleanup task");
        // MockClock 冻结时 expire==now 不判过期（严格 <）；推过过期点后，
        // 下一个 cleanup tick（20ms 虚拟时刻）即清理。
        clock.advance(Duration::from_secs(1));
        tokio::time::sleep(Duration::from_millis(200)).await;

        assert!(
            c.find_records("gone.com.").is_none(),
            "expired entry must be removed by cleanup task"
        );
        assert!(c.find_records("live.com.").is_some(), "live entry must survive");

        // P1-11：任务归 scope 生命周期集托管——排空后在途归零。
        fx.shutdown().await;
        skeleton_infra::fx::expect_idle(&fx);
    }

    /// P1-11 验收①：scope 已关（停机中）再 start_managed——spawn 拒新
    /// （warn 留痕），不得 panic、不得新增在途任务。
    #[test]
    fn start_managed_after_close_is_rejected_without_panic() {
        let c = Arc::new(CacheController::new("test", false, false, 0, 0));
        let fx = Arc::new(skeleton_infra::fx::FxScope::new());
        fx.close();
        c.start_managed(&fx, CLEANUP_INTERVAL);
        assert!(fx.is_closed());
        assert_eq!(fx.in_flight(), 0, "closed scope must not gain new tasks");
        // 无 runtime 同步上下文：仅附着、不 spawn（旧 Handle::try_current None 语义）。
        let fx_open = Arc::new(skeleton_infra::fx::FxScope::new());
        c.start_managed(&fx_open, CLEANUP_INTERVAL);
        assert_eq!(fx_open.in_flight(), 0, "sync context must not spawn");
        // 首注单为准：第二次 start_managed 不换 scope（仍指最早注单的 fx）。
        assert_eq!(c.fx_scope().map(|s| Arc::ptr_eq(s, &fx)), Some(true));
    }
    /// ① MockClock 推过期秒 → 缓存立即过期（零真等）。
    ///
    /// 同时钉死严格 `<` 边界：expire == effective_now 不判过期（Go
    /// `expire.Before(now)` 同款），推满 TTL 整 60s 仍存活，再推 1s 才清。
    #[test]
    fn mock_clock_advance_expires_entry_without_real_wait() {
        let clock = Arc::new(MockClock::new());
        let c = CacheController::with_clock("test", false, false, 0, 0, clock.clone());
        let now = clock.now_instant();
        c.upsert(
            "a.com.",
            true,
            ip_record(1, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)], Duration::from_secs(60), 0, now),
        );

        // 虚拟时间冻结：同刻不清。
        let (cleaned, _) = c.run_cleanup(clock.now_instant());
        assert!(!cleaned);
        assert!(c.find_records("a.com.").is_some());

        // 恰满 TTL（expire == now）：严格 < 不判过期。
        clock.advance(Duration::from_secs(60));
        let (cleaned, _) = c.run_cleanup(clock.now_instant());
        assert!(!cleaned, "expire == effective_now 不得判过期（Go Before 语义）");

        // 推过 TTL 1s → 立即过期。
        clock.advance(Duration::from_secs(1));
        let (cleaned, _) = c.run_cleanup(clock.now_instant());
        assert!(cleaned);
        assert!(c.find_records("a.com.").is_none());
    }

    /// ② stale 宽限边界：宽限内仍可服务（不清理），恰在边界保留，超出即弃。
    #[test]
    fn stale_grace_boundary_within_served_beyond_discarded() {
        // serve_stale = true + 宽限 30s（Go serveExpiredTTL=30）。
        let clock = Arc::new(MockClock::new());
        let c = CacheController::with_clock("test", false, true, 30, 0, clock.clone());
        let now = clock.now_instant();
        // TTL 10s：真实过期点 = t0 + 10s。
        c.upsert(
            "g.com.",
            true,
            ip_record(1, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)], Duration::from_secs(10), 0, now),
        );

        // 过期后 10s（宽限内）：effective_now = now - 30s < expire → 保留可服务。
        clock.advance(Duration::from_secs(20));
        assert!(c.collect_expired_keys(clock.now_instant()).is_empty(), "宽限内不得清理");
        assert!(c.find_records("g.com.").is_some(), "宽限内记录仍可服务");

        // 恰在宽限边界（expire == effective_now）：严格 < 保留。
        clock.advance(Duration::from_secs(20));
        assert!(
            c.collect_expired_keys(clock.now_instant()).is_empty(),
            "宽限边界（expire == effective_now）不得判过期"
        );

        // 超出宽限 1s：即弃。
        clock.advance(Duration::from_secs(1));
        assert_eq!(c.collect_expired_keys(clock.now_instant()), vec!["g.com.".to_string()]);
        let (cleaned, _) = c.run_cleanup(clock.now_instant());
        assert!(cleaned);
        assert!(c.find_records("g.com.").is_none());
    }

    /// ③ 双族 TTL 各自独立生效：A 先过独立 TTL 只清 A 槽，AAAA 存活；条目
    /// 随 AAAA 过期才整条消失（缓存键与每 NS 一缓存前提不受影响）。
    #[test]
    fn dual_family_ttl_independent() {
        let clock = Arc::new(MockClock::new());
        let c = CacheController::with_clock("test", false, false, 0, 0, clock.clone());
        let now = clock.now_instant();
        c.upsert(
            "d.com.",
            true,
            ip_record(1, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)], Duration::from_secs(10), 0, now),
        );
        c.upsert(
            "d.com.",
            false,
            ip_record(
                2,
                vec![IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)],
                Duration::from_secs(120),
                0,
                now,
            ),
        );

        // t0+20s：A（TTL 10s）已过期，AAAA（TTL 120s）存活。
        clock.advance(Duration::from_secs(20));
        let (cleaned, _) = c.run_cleanup(clock.now_instant());
        assert!(cleaned);
        let r = c.find_records("d.com.").expect("AAAA 存活则条目不得整条删除");
        assert!(r.a.is_none(), "A 槽按自身 TTL 清空");
        assert!(r.aaaa.is_some(), "AAAA 按自身 TTL 存活");

        // t0+121s：AAAA 也过期 → 两槽空 → 整条移除。
        clock.advance(Duration::from_secs(101));
        let (cleaned, _) = c.run_cleanup(clock.now_instant());
        assert!(cleaned);
        assert!(c.find_records("d.com.").is_none());
    }
}
