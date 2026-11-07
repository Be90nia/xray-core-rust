//! DNS 缓存控制器。对应 Go `app/dns/cache_controller.go`。
//!
//! ## 范围
//!
//! - 缓存数据结构 + cleanup 逻辑 + 内存收缩策略：完整翻译。**答案表底座 = udf
//!   `std_ext::cache::SyncTtlCache`**（audit ARCH-04：`&self` 共享 + 短临界 Mutex + LRU 淘汰序 +
//!   逐条 TTL；本仓 9utc3 的自造 FIFO 淘汰队列已删—— Go 同源无淘汰界，LRU 是 Rust
//!   侧防洪泛策略的升级，非对拍差异）。
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
use std_ext::cache::SyncTtlCache;
use tokio::sync::broadcast;
// 派生件 1（bd h4bl5）：serveStale 的窗口口径 + 同 fqdn 单飞刷新许可。
// DNS 答案本体仍留 `ips`（Go 对拍面：per-family 过期 + cleanup/shrink + pubsub
// 广播），换掉的只是本仓原先自实现的「过期可服务窗口 + 后台刷新去重」。
// UNBOUNDED_RETENTION（audit ARCH-04）：无上限宽限窗的条目物理保留下限同源。
use xray_frame::cache::{RefreshGate, RefreshPermit, UNBOUNDED_RETENTION, stale_window};

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
/// 缓存键数上界（9utc3，Go 同源无此界——Rust 侧防洪泛加界）。键数达界后再插
/// 新键时淘汰：**基件先清物理过期键**（与 cleanup 同一 expire + serveStale
/// 宽限口径），仍满再逐 **LRU 尾**（audit ARCH-04 起淘汰序由 udf
/// `SyncTtlCache` 给出；旧自造 FIFO 队列已删）。
/// 16384 键 ≈ 4-5 MiB（票面：10 万键 ≈ 20-30 MiB），远高于常规解析工作集。
pub const MAX_CACHE_ENTRIES: usize = 16384;

/// 条目物理保留 TTL 下限（基件 `ttl == 0` fail-fast panic）：已过期条目入表
/// （负缓存回填/测试确定性）也给 1s 缓冲，过期判定仍由 per-family cleanup 口径
/// 负责，物理面只兜底。
const MIN_ENTRY_TTL: Duration = Duration::from_secs(1);

/// cleanup 扫表的分批回插批大小（bd m6pkl N3）。
///
/// 基件无键迭代面 ⇒ 清理只能 `pop_lru` 出栈再回插；批内立即回插让读路径任何
/// 时刻最多看到这一批（LRU 尾 = 最冷键）不在表中，而不是整张表出栈到底。
const CLEANUP_CHUNK: usize = 256;

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
    /// 负答案缓存 TTL（秒）。0 = 不覆写（跟响应自带 TTL，Go 行为）。
    /// Go cache 无此字段（Rust 扩展，jsonconf `negativeTtlSecs`）；
    /// 大于 0 时 `nameserver::cached::fetch` 用它覆写负答案（rcode 非 NO_ERROR
    /// 或 A/AAAA 空表）的过期时刻（bd 2bmns G-5）。
    pub negative_ttl_secs: u32,
    /// 答案表（audit ARCH-04：底座 = udf `SyncTtlCache`——`&self` 共享 + 内部
    /// Mutex 短临界 + get 自带 touch（LRU recency）+ 满插先清过期再逐 LRU 尾 +
    /// 惰性过期）。条目物理保留 TTL = 家族最晚过期时刻 + serveStale 宽限
    /// （见 [`Self::entry_retention`]），过期语义本体仍按 per-family 判定
    /// （Go 对拍面：cleanup/shrink/pubsub 不变）。
    ips: SyncTtlCache<String, Arc<Record>>,
    /// 复合写闸：`upsert` 的 get→改→insert 与 cleanup 的槽清写在基件「单操作
    /// 原子」之上补复合原子性——v4/v6 同键合并不被另一族 upsert 交错覆盖
    /// （旧 `ips.write()` 全局写锁的等价替代；读路径不经本闸，锁争用面更小）。
    write_gate: parking_lot::Mutex<()>,
    /// 缓存生命周期峰值，用于收缩阈值计算。
    high_watermark: RwLock<usize>,
    /// 广播通道发送端（响应到达时发 `CacheEvent`）。
    pub tx: broadcast::Sender<CacheEvent>,
    pub single_flight: SfMap,
    /// 时间源契约（P1-12）：TTL/stale 判定与清理节奏统一走 `skeleton::clock::Clock`。
    /// 生产 `SystemClock`；测试注入 `MockClock` 得确定性时间线（零真等）。
    clock: Arc<dyn Clock>,
    /// 实例托管 scope（P1-11）：启动期经 `start_managed` 注单（配置期为空 =
    /// 零 spawn）；serveStale pull（`nameserver/cached.rs`）与 DoH h2 conn 驱动
    /// （`nameserver/doh.rs`）经 `fx_scope` 取用同一 scope。
    fx: OnceLock<Arc<FxScope>>,
    /// serveStale 宽限窗（派生件 1 口径：`None` = 无上限；`Some(ZERO)` = 不服务
    /// 过期值）。构造时由 `serve_stale`/`serve_expired_ttl` 折算，此后不变。
    stale_window: Option<Duration>,
    /// serveStale 后台刷新闸（派生件 1）：同 fqdn 同时至多一个 pull 在飞。
    stale_gate: RefreshGate<String>,
}

/// singleflight 表：`Mutex` 换 `parking_lot` 短临界（guard 非 Send，锁内零 await），
/// key 用 `Arc<str>` 让领导者路径的 key 复制退化为引用计数。
pub type SfMap = parking_lot::Mutex<
    HashMap<(Arc<str>, bool, bool), broadcast::Sender<crate::nameserver::cached::QueryOutcome>>,
>;

/// singleflight 表条目软上界（bd 3pj18 / PM-08）。
///
/// 条目生命周期由领导者 `SfLeaderGuard` 兜底移除，「在飞并发 fqdn 数」本就有界；
/// 但守卫未执行到的异常面（线程 panic 之外的自定义 abort 路径、未来改动引入的
/// 泄漏）会让表无界增长。达界后**不再登记新领导者**（退化为直连查询，牺牲去重
/// 换有界内存），已有条目照常服务与移除，故正常负载不会撞界。
pub const SF_MAX_ENTRIES: usize = 4096;

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

/// `serveExpiredTTL`（秒）→ 宽限窗：0 = 不设上限（Go 语义：`serveExpiredTTL == 0`
/// 表示过期后无限期可服务）。
fn nonzero_grace(secs: u32) -> Option<Duration> {
    (secs != 0).then(|| Duration::from_secs(u64::from(secs)))
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
            ips: SyncTtlCache::new(Arc::clone(&clock), MAX_CACHE_ENTRIES),
            write_gate: parking_lot::Mutex::new(()),
            high_watermark: RwLock::new(0),
            tx,
            single_flight: parking_lot::Mutex::new(HashMap::new()),
            clock,
            fx: OnceLock::new(),
            // Go `serveExpiredTTL == 0` ⇒ 不设上限；`serveStale == false` ⇒ 零宽限。
            stale_window: stale_window(serve_stale, nonzero_grace(serve_expired_ttl)),
            stale_gate: RefreshGate::new(),
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
        self.ips.len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ips.is_empty()
    }

    /// 高水位（峰值）。
    #[must_use]
    pub fn high_watermark(&self) -> usize {
        *self.high_watermark.read()
    }

    /// 查询缓存。对应 Go `findRecords`。
    ///
    /// 返回 `Arc` 共享记录，调用方可不持锁使用。基件 `get` 自带 touch（命中刷
    /// 新 LRU recency——audit ARCH-04：淘汰序升级为 LRU 的记账面，读路径零写锁
    /// 升级）；条目超物理保留（家族过期 + 宽限窗尽）按惰性过期返回 `None`
    /// （与 cleanup 的 effective_now 口径对齐：宽限尽即消费侧本就拒绝服务）。
    #[must_use]
    pub fn find_records(&self, fqdn: &str) -> Option<Arc<Record>> {
        // shortcut: SyncTtlCache 无 Borrow<str> 查表面，每次 `&str` 查一次小分配；
        // DNS 每查询一次、远小于上游往返，热起来再给 udf 提 Borrow 口。
        self.ips.get(&fqdn.to_string())
    }

    /// 条目物理保留 TTL：家族最晚过期时刻 + serveStale 宽限窗（宽限内条目必须
    /// 物理存活，否则 serveStale 无旧值可服务；判定边界与 cleanup 的
    /// `effective_now = now - 宽限` 精确互补）；无上限窗口 ⇒ 至少
    /// [`UNBOUNDED_RETENTION`]（对齐 `xray_frame::cache` 口径，至容量淘汰）。
    /// 全家族已过期（物理即逝）给 [`MIN_ENTRY_TTL`] 下限兜底（基件 `ttl == 0`
    /// fail-fast panic）；过期语义本体由 per-family cleanup 口径负责。
    fn entry_retention(rec: &Record, window: Option<Duration>, now: Instant) -> Duration {
        let max_expire = rec
            .a
            .as_ref()
            .map(|r| r.expire)
            .into_iter()
            .chain(rec.aaaa.as_ref().map(|r| r.expire))
            .max();
        let Some(max_expire) = max_expire else {
            return MIN_ENTRY_TTL;
        };
        match window {
            Some(w) => max_expire
                .checked_add(w)
                .and_then(|end| end.checked_duration_since(now))
                .unwrap_or(MIN_ENTRY_TTL)
                .max(MIN_ENTRY_TTL),
            None => max_expire.saturating_duration_since(now).max(UNBOUNDED_RETENTION),
        }
    }

    /// 写入 / 合并记录。对应 Go `addIoResult` / `setRecord`。
    ///
    /// `is_v4=true` 更新 A 记录，`false` 更新 AAAA。9utc3 键数硬上界由基件
    /// 内生：新键达 [`MAX_CACHE_ENTRIES`] 满插时**先清物理过期键**、仍满逐
    /// **LRU 尾**（淘汰序 = udf 件给出，audit ARCH-04）。
    pub fn upsert(&self, fqdn: &str, is_v4: bool, record: IpRecord) {
        if self.disable_cache {
            return;
        }
        let _gate = self.write_gate.lock();
        let key = fqdn.to_string();
        let mut entry = self.ips.get(&key).unwrap_or_else(|| Arc::new(Record::default()));
        // Arc::make_mut：如独占则就地修改，否则 COW（读侧 Arc 不受影响）。
        let entry_mut = Arc::make_mut(&mut entry);
        if is_v4 {
            entry_mut.a = Some(record);
        } else {
            entry_mut.aaaa = Some(record);
        }
        let ttl = Self::entry_retention(entry_mut, self.stale_window, self.clock.now_instant());
        self.ips.insert(key, entry, ttl);
    }

    /// 收集已过期 key。对应 Go `collectExpiredKeys`（内部逻辑）。
    ///
    /// **注意**：`serve_stale && serve_expired_ttl != 0` 时，把 `now` 提前以保留过期数据。
    #[must_use]
    pub fn collect_expired_keys(&self, now: Instant) -> Vec<String> {
        let len = self.ips.len();
        if len == 0 {
            return Vec::new();
        }
        let _gate = self.write_gate.lock();
        let effective_now = self.effective_now(now);
        // 扫描面：基件 `SyncTtlCache` 无键迭代 API（迭代面只在单线程 `TtlCache`
        // ——udf 基件面缺口，提炼候选见 impl 报告）。以 `pop_lru` 出栈 +
        // **正序**回插实现一次 O(n) 扫描：pop 序 = recency 序（旧→新），正序回插
        // 使 LRU 序与扫描前逐位一致；回插时重算物理保留（家族最晚过期 + 宽限）。
        // 两条代价控制（bd m6pkl N3）：
        // ① 键按值消费——回插移动取回的 `String`，只有过期条目付一次拷贝
        //    （旧形态 `key.clone()` 每条一次：16k 键 = 16k 次 String 分配/周期）；
        // ② 分批回插——旧形态把整表出栈到底才回插，读路径在窗口内看到空表
        //    （miss → 上游重查）。批内立即回插把窗口压到 ≤ [`CLEANUP_CHUNK`] 个
        //    **最冷**键（LRU 尾，本来最不可能被查）。
        let mut keys = Vec::with_capacity(len / 4);
        let mut chunk: Vec<(String, Arc<Record>)> = Vec::with_capacity(CLEANUP_CHUNK.min(len));
        // 扫描面 = 起始条数：回插的新条目不计入（否则 pop 与回插互相追逐死循环）。
        let mut remaining = len;
        while remaining > 0 {
            for _ in 0..CLEANUP_CHUNK.min(remaining) {
                let Some(entry) = self.ips.pop_lru() else { break };
                chunk.push(entry);
            }
            if chunk.is_empty() {
                break;
            }
            remaining -= chunk.len();
            for (key, rec) in chunk.drain(..) {
                let ttl = Self::entry_retention(&rec, self.stale_window, now);
                let a_expired = rec.a.as_ref().is_some_and(|r| r.expire < effective_now);
                let aaaa_expired = rec.aaaa.as_ref().is_some_and(|r| r.expire < effective_now);
                if a_expired || aaaa_expired {
                    keys.push(key.clone());
                }
                self.ips.insert(key, rec, ttl);
            }
        }
        keys
    }

    /// 清理 + 收缩。对应 Go `writeAndShrink`。
    ///
    /// 经复合写闸（读路径不受阻）调用，返回是否触发了收缩。
    pub fn cleanup_and_maybe_shrink(&self, expired_keys: Vec<String>, now: Instant) -> bool {
        let _gate = self.write_gate.lock();
        let mut high = self.high_watermark.write();

        let len_before = self.ips.len();
        if len_before > *high {
            *high = len_before;
        }

        let effective_now = self.effective_now(now);
        for domain in &expired_keys {
            // peek（不 touch、惰性过期）：物理已逝条目此处即回收并跳过。
            let Some(rec) = self.ips.peek(domain) else {
                continue;
            };
            let a_expired = rec.a.as_ref().is_some_and(|r| r.expire < effective_now);
            let aaaa_expired = rec.aaaa.as_ref().is_some_and(|r| r.expire < effective_now);
            if !(a_expired || aaaa_expired) {
                continue;
            }
            let mut rec = rec;
            // 通过 Arc::make_mut 以避免 clone 整个表（读侧 Arc 不受影响）。
            let rec_mut = Arc::make_mut(&mut rec);
            if a_expired {
                rec_mut.a = None;
            }
            if aaaa_expired {
                rec_mut.aaaa = None;
            }
            if rec_mut.a.is_none() && rec_mut.aaaa.is_none() {
                let _ = self.ips.remove(domain);
            } else {
                // 存活家族续命：物理保留重算（家族最晚过期 + 宽限）。
                let ttl =
                    Self::entry_retention(rec_mut, self.stale_window, self.clock.now_instant());
                self.ips.insert(domain.clone(), rec, ttl);
            }
        }

        let len_after = self.ips.len();

        if len_after == 0 {
            if *high >= MIN_SIZE_FOR_EMPTY_REBUILD {
                // 空表重建以回收内存（基件 arena 随逐条 remove 已回落；pop 兜底排空）。
                while self.ips.pop_lru().is_some() {}
                *high = 0;
                return true;
            }
            return false;
        }

        let reduction = high.saturating_sub(len_after);
        if reduction > SHRINK_ABSOLUTE_THRESHOLD
            && (reduction as f64) > (*high as f64) * SHRINK_RATIO_THRESHOLD
        {
            // 收缩判定保持 Go 对拍布尔语义；HashMap 重建面已随底座更换消失
            // （基件 arena 自管理容量）。
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
        let spawned = fx.spawn_tracked(async move {
            let mut ticker = tokio::time::interval(interval);
            // Go time.Ticker 丢 tick 不补发（Burst 是 tokio 默认）
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
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

    /// serveStale 判定（派生件 1 单源）：`ttl` 为 `merge_records` 给出的剩余
    /// TTL（秒，> 0 未过期、<= 0 已过期秒数的相反数）。
    ///
    /// 等价于 Go `nameserver_cached.go:35` 的
    /// `serveExpiredTTL == 0 || serveExpiredTTL < ttl`（`serveExpiredTTL` 存负值）：
    /// 宽限窗 `None` = 不设上限；`Some(d)` ⇒ 超时 `d` 内仍可服务。
    #[must_use]
    pub fn stale_servable(&self, ttl: i32) -> bool {
        if ttl > 0 {
            return false;
        }
        match self.stale_window {
            None => true,
            Some(window) => Duration::from_secs(ttl.unsigned_abs() as u64) < window,
        }
    }

    /// 取得该 fqdn 的后台刷新许可：已有 pull 在飞 ⇒ `None`（本次直接用旧值）。
    ///
    /// 许可随 [`RefreshPermit`] drop 释放，故调用方必须把它移交给刷新任务。
    #[must_use]
    pub fn begin_stale_refresh(&self, fqdn: &str) -> Option<RefreshPermit> {
        // shortcut: 每次过期读一次 String 分配（非法热路径，过期答案本就要打上游）；热起来再换
        // Arc<str> 键。
        self.stale_gate.try_begin(&fqdn.to_string())
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

    /// bd m6pkl N3：跨多批（[`CLEANUP_CHUNK`]）扫表。每条键恰好扫一次（回插的
    /// 新条目不得被再扫）、过期集合完整且无重复、存活条目一条不丢。
    #[test]
    fn collect_expired_keys_across_chunks_scans_each_entry_once() {
        let c = make_ctrl();
        let now = c.clock().now_instant();
        let n = CLEANUP_CHUNK * 3 + 7;
        for i in 0..n {
            // 偶数键短 TTL（过期），奇数键长 TTL（存活）
            let ttl = if i % 2 == 0 { 0 } else { 120 };
            let rec = ip_record(
                1,
                vec![IpAddr::V4(Ipv4Addr::new(10, 0, (i / 256) as u8, (i % 256) as u8))],
                Duration::from_secs(ttl),
                0,
                now,
            );
            c.upsert(&format!("k{i}.com."), true, rec);
        }
        assert_eq!(c.len(), n);

        let later = now + Duration::from_secs(1);
        let keys = c.collect_expired_keys(later);
        // 偶数键（0,2,…）短 TTL ⇒ 过期条数 = ⌈n/2⌉
        assert_eq!(keys.len(), n.div_ceil(2), "过期集合必须恰好是偶数键（无遗漏）");
        let unique: std::collections::HashSet<&String> = keys.iter().collect();
        assert_eq!(unique.len(), keys.len(), "同一键不得重复收集");

        assert_eq!(c.len(), n, "扫描（出栈 + 回插）不得丢条目");
        // collect 只「报告」过期键；物理删除发生在 cleanup_and_maybe_shrink。
        for i in (1..n).step_by(2) {
            assert!(c.find_records(&format!("k{i}.com.")).is_some(), "存活条目不得丢");
        }
        let (cleaned, _) = c.run_cleanup(later);
        assert!(cleaned, "有过期键时必须报告已清理");
        for i in 0..n {
            let fqdn = format!("k{i}.com.");
            let found = c.find_records(&fqdn).is_some();
            assert_eq!(found, i % 2 == 1, "{fqdn}：清理后过期必须消失、存活必须仍在");
        }
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
        let _ = fx.shutdown().await; // 报告含 panic 载荷：测试收尾显式让渡
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

    /// 9utc3 ①：键数硬上界——插满 MAX+1 后长度钉在 MAX，最旧插入键被逐，
    /// 最新键存活（全新鲜、零读路径 ⇒ LRU 尾 == 最旧插入键，与旧 FIFO 同判）。
    #[test]
    fn upsert_is_bounded_at_max_cache_entries() {
        let c = make_ctrl();
        let now = c.clock().now_instant();
        let live_ttl = Duration::from_secs(3600);
        for i in 0..=MAX_CACHE_ENTRIES {
            let rec = ip_record(
                1,
                vec![IpAddr::V4(Ipv4Addr::new(10, 0, (i / 256) as u8, (i % 256) as u8))],
                live_ttl,
                0,
                now,
            );
            c.upsert(&format!("d{i}.example.com."), true, rec);
        }
        assert_eq!(c.len(), MAX_CACHE_ENTRIES, "键数必须钉在上界");
        assert!(c.find_records("d0.example.com.").is_none(), "最旧插入键必须被逐");
        assert!(
            c.find_records(&format!("d{MAX_CACHE_ENTRIES}.example.com.")).is_some(),
            "最新键必须存活"
        );
    }

    /// 9utc3 ②：淘汰过期优先——短 TTL 键过期后，超界插入先清它而非最旧
    /// 存活键（基件满插「先清物理过期、仍满逐 LRU 尾」）。
    #[test]
    fn evict_prefers_expired_over_oldest_live() {
        let clock = Arc::new(MockClock::new());
        let c = CacheController::with_clock("test", false, false, 0, 0, clock.clone());
        let now = clock.now_instant();
        let short =
            ip_record(1, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)], Duration::from_secs(1), 0, now);
        c.upsert("short.example.com.", true, short);
        for i in 1..MAX_CACHE_ENTRIES {
            let rec = ip_record(
                1,
                vec![IpAddr::V4(Ipv4Addr::new(10, 0, (i / 256) as u8, (i % 256) as u8))],
                Duration::from_secs(3600),
                0,
                now,
            );
            c.upsert(&format!("live{i}.example.com."), true, rec);
        }
        assert_eq!(c.len(), MAX_CACHE_ENTRIES);
        // short（TTL 1s）已过期，live*（TTL 3600s）全部新鲜。
        clock.advance(Duration::from_secs(2));
        let fresh = ip_record(
            1,
            vec![IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1))],
            Duration::from_secs(60),
            0,
            clock.now_instant(),
        );
        c.upsert("fresh.example.com.", true, fresh);
        assert_eq!(c.len(), MAX_CACHE_ENTRIES);
        assert!(c.find_records("short.example.com.").is_none(), "过期键必须先被逐");
        assert!(c.find_records("fresh.example.com.").is_some(), "触发淘汰的新键必须存活");
        assert!(c.find_records("live1.example.com.").is_some(), "存在过期键时最旧存活键不得被逐");
    }

    /// 9utc3 ③：cleanup 删除后上界依旧——多轮「插满超界 → cleanup 清光」
    /// 后键数界不破（淘汰序队列已删，基件 LRU 面自带同步）。
    #[test]
    fn bound_survives_cleanup_cycles() {
        let clock = Arc::new(MockClock::new());
        let c = CacheController::with_clock("test", false, false, 0, 0, clock.clone());
        for round in 0..3u32 {
            let now = clock.now_instant();
            for i in 0..=MAX_CACHE_ENTRIES {
                let rec = ip_record(
                    1,
                    vec![IpAddr::V4(Ipv4Addr::new(
                        10,
                        round as u8,
                        (i / 256) as u8,
                        (i % 256) as u8,
                    ))],
                    Duration::from_secs(60),
                    0,
                    now,
                );
                c.upsert(&format!("r{round}d{i}.example.com."), true, rec);
            }
            assert_eq!(c.len(), MAX_CACHE_ENTRIES, "round {round}: 键数必须钉在上界");
            // TTL 60s，推进 120s 全表过期 → cleanup 清光。
            clock.advance(Duration::from_secs(120));
            let (cleaned, _) = c.run_cleanup(clock.now_instant());
            assert!(cleaned, "round {round}: 必须发生清理");
            assert_eq!(c.len(), 0, "round {round}: 清理后必须为空");
        }
    }

    /// ARCH-04 行为级①（淘汰序 = LRU，非旧 FIFO）：命中 d0 使其晋升 MRU 后，
    /// 超界插入逐 LRU 尾 d1——d0 因被读过而存活，d1（从未读）被逐。旧 FIFO
    /// 下这里被逐的是 d0，本测试即淘汰序变更的行为钉。
    #[test]
    fn lru_eviction_respects_recency_of_hits() {
        let c = make_ctrl();
        let now = c.clock().now_instant();
        let live_ttl = Duration::from_secs(3600);
        for i in 0..MAX_CACHE_ENTRIES {
            let rec = ip_record(
                1,
                vec![IpAddr::V4(Ipv4Addr::new(10, 0, (i / 256) as u8, (i % 256) as u8))],
                live_ttl,
                0,
                now,
            );
            c.upsert(&format!("d{i}.example.com."), true, rec);
        }
        // 读 d0：基件 get 触碰 → d0 晋升 MRU；LRU 尾变为 d1。
        assert!(c.find_records("d0.example.com.").is_some());
        let fresh = ip_record(1, vec![IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1))], live_ttl, 0, now);
        c.upsert("fresh.example.com.", true, fresh);
        assert_eq!(c.len(), MAX_CACHE_ENTRIES, "满插逐尾后键数仍钉在上界");
        assert!(
            c.find_records("d0.example.com.").is_some(),
            "被命中过的键必须因 recency 晋升而存活（LRU ≠ FIFO 的行为面）"
        );
        assert!(c.find_records("d1.example.com.").is_none(), "从未被读的最旧键必须是 LRU 尾被逐者");
        assert!(c.find_records("fresh.example.com.").is_some(), "触发淘汰的新键必须存活");
    }

    /// ARCH-04 行为级②（物理保留 = 过期 + serveStale 宽限）：宽限内条目必须
    /// 可读（serveStale 有旧值可服务），宽限尽后读取按惰性过期判 miss——
    /// 与 cleanup 的 effective_now 口径互补（消费侧在宽限尽时本就拒绝服务）。
    #[test]
    fn physical_retention_matches_serve_stale_grace() {
        let clock = Arc::new(MockClock::new());
        // serve_stale = true + 宽限 30s；记录 TTL 10s。
        let c = CacheController::with_clock("test", false, true, 30, 0, clock.clone());
        let now = clock.now_instant();
        c.upsert(
            "g.com.",
            true,
            ip_record(1, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)], Duration::from_secs(10), 0, now),
        );
        // 过期点 t0+10s，宽限至 t0+40s：+20s 宽限内仍可读。
        clock.advance(Duration::from_secs(20));
        assert!(c.find_records("g.com.").is_some(), "宽限内条目必须物理存活");
        // +41s（超宽限 1s）：读取惰性过期 → miss；无 cleanup 参与也成立。
        clock.advance(Duration::from_secs(21));
        assert!(c.find_records("g.com.").is_none(), "宽限尽后读取必须按惰性过期判 miss");
        assert_eq!(c.len(), 0, "惰性回收后条目数归零");
    }

    /// ARCH-04 行为级③（无上限宽限 ⇒ 物理保留至少一年，至容量淘汰）：
    /// serve_stale + serveExpiredTTL=0（Go 语义：过期无限期可服务）下条目
    /// 不随 TTL 消失。
    #[test]
    fn unbounded_stale_window_retains_entry_physically() {
        let clock = Arc::new(MockClock::new());
        let c = CacheController::with_clock("test", false, true, 0, 0, clock.clone());
        let now = clock.now_instant();
        c.upsert(
            "g.com.",
            true,
            ip_record(1, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)], Duration::from_secs(10), 0, now),
        );
        clock.advance(Duration::from_secs(100_000));
        assert!(
            c.find_records("g.com.").is_some(),
            "无上限宽限窗下条目必须物理保留（至少一年，至容量淘汰）"
        );
    }

    /// ARCH-04 行为级④（同键 v4/v6 复合合并原子性）：先 v4 后 v6 两次 upsert
    /// 合并为单条目双族齐备；键数界上 A-only 客户端与 AAAA-only 客户端并发
    /// 各自更新本族槽位时由复合写闸串行化（行为断言取顺序等价形态）。
    #[test]
    fn dual_family_upsert_merges_into_one_entry_under_write_gate() {
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
        let r = c.find_records("x.com.").expect("合并后条目必须存在");
        assert!(r.a.is_some(), "v4 槽位不得被 v6 upsert 覆盖丢失");
        assert!(r.aaaa.is_some(), "v6 槽位不得被 v4 upsert 覆盖丢失");
        assert_eq!(c.len(), 1, "同键两族必须合并为单条目");
    }
}
