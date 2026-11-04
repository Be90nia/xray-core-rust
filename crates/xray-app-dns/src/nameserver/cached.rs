//! 缓存层：CachedNameserver trait + queryIP/fetch/doFetch/merge 调度。
//!
//! 对应 Go `app/dns/nameserver_cached.go`。
//!
//! ## 范围
//!
//! - 缓存命中检测 + 调度逻辑：完整翻译。
//! - `pubsub` / `singleflight`：用 `tokio::sync::broadcast` 与简化的 per-key `Mutex<HashMap>`
//!   模拟，业务语义保留（避免重复查询、等待首个响应）。
//!
//! CachedNameserver 是内部 trait，调用方用具体类型或泛型 `T:`，故用 `async fn` 而非
//! 手写 boxed future（与上层 `Server` trait 风格不同）。

use std::{
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::sync::broadcast;
use xray_frame::cache::RefreshPermit;

use crate::{
    cache_controller::{CacheController, SfMap},
    config::IpOption,
    dnscommon::{IpRecord, merge_records},
    error::DnsError,
};

/// singleflight 等待者相对领导者的兜底余量：等待上限 = 本 NS 的 `query_timeout`
/// + 本余量（见 [`sf_wait_timeout`]）。
///
/// 领导者自身查询在 `query_timeout` 必定收场（各 NS 的整条查询绝对 deadline），
/// 等待者必须**晚一步**收场才能共享到领导者的结论。固定值与缺省 `query_timeout`
/// 相等（改前 4s == UDP/TCP/DoT/DoQ 缺省 4000ms）⇒ 等待者在领导者刚失败的同刻
/// 超时并自起一轮上游查询，必然重复（bd 26v9t）。
const SF_WAIT_MARGIN: Duration = Duration::from_secs(1);

/// singleflight 等待者的等待上限：领导者查询超时 + [`SF_WAIT_MARGIN`]。
fn sf_wait_timeout<S: CachedNameserver + ?Sized>(server: &S) -> Duration {
    server.query_timeout() + SF_WAIT_MARGIN
}

/// 后台 pull 的兜底超时。对应 Go `pull` 的 `context.WithTimeout(..., 8s)`。
const PULL_TIMEOUT: Duration = Duration::from_secs(8);

/// 按 key 移除 singleflight 条目；`same_channel` 校验防止误删后来领导者的新条目。
fn remove_sf_entry(sf: &SfMap, key: &(Arc<str>, bool, bool), tx: &broadcast::Sender<QueryOutcome>) {
    if let Some(mut sf) = sf.try_lock() {
        if sf.get(key).is_some_and(|t| t.same_channel(tx)) {
            sf.remove(key);
        }
    }
}

/// 领导者守卫：fetch 正常返回、出错返回或被上层 abort（如 parallel_query 的
/// `abort_all`）时，Drop 保证把本条 singleflight 条目从 map 移除——
/// 条目泄漏会让后续同 key 查询永远走「等待者」路径。
struct SfLeaderGuard<'a> {
    sf: &'a SfMap,
    key: (Arc<str>, bool, bool),
    tx: broadcast::Sender<QueryOutcome>,
}

impl Drop for SfLeaderGuard<'_> {
    fn drop(&mut self) {
        // Drop 不能 await；try_lock 失败时条目由等待者的 remove_sf_entry 兜底清除。
        remove_sf_entry(self.sf, &self.key, &self.tx);
    }
}

/// singleflight 临界区结果：等待者拿接收端，领导者拿条目 sender。
enum SfSlot {
    Waiter(broadcast::Receiver<QueryOutcome>),
    Leader(broadcast::Sender<QueryOutcome>),
}

/// 缓存型 nameserver 接口。对应 Go `CachedNameserver` interface。
pub trait CachedNameserver: Send + Sync {
    /// 取共享缓存控制器。
    fn cache_controller(&self) -> &CacheController;

    /// 本 NS 单次查询的超时（整条查询的绝对预算，与 `send_query` 内一致）。
    ///
    /// singleflight 等待者的兜底超时按它派生（[`sf_wait_timeout`]）。各 NS 覆写
    /// 为自身配置值；缺省 4s = UDP/TCP/DoT/DoQ 的缺省 `timeout_ms`。
    fn query_timeout(&self) -> Duration {
        Duration::from_secs(4)
    }

    /// 发起底层 DNS 查询（UDP/TCP/DoH/...）。返回 `(rec_v4, rec_v6, err)`。
    ///
    /// 成功后调用方应通过 `cache_controller().tx` 广播结果。
    fn send_query(
        &self,
        fqdn: &str,
        option: IpOption,
    ) -> impl std::future::Future<Output = QueryOutcome> + Send;
}

/// 单轮查询的统一返回。
#[derive(Debug, Default)]
pub struct QueryOutcome {
    /// IPv4 记录（可能为 None 表示无响应）。
    pub rec_v4: Option<IpRecord>,
    /// IPv6 记录。
    pub rec_v6: Option<IpRecord>,
    /// 累积错误（已收集多个）。
    pub errors: Vec<DnsError>,
}

/// singleflight 仅 clone rec_v4/rec_v6，errors 不复制（诊断用途）。
impl Clone for QueryOutcome {
    fn clone(&self) -> Self {
        Self { rec_v4: self.rec_v4.clone(), rec_v6: self.rec_v6.clone(), errors: Vec::new() }
    }
}

/// 缓存入口查询。对应 Go `queryIP(ctx, s, domain, option)`。
///
/// 1. 若缓存启用且命中：返回 `(ips, ttl, Ok)`；过期且 `serveStale` 时走 stale 优化路径（Go
///    nameserver_cached.go:31-41：秒回旧 IP + `go pull` 续期）。
/// 2. 否则调用 `fetch`（singleflight + pubsub）执行实际查询。
/// 3. 持有 `Arc<S>`（`'static`）：stale 路径需把服务器共享给后台 `pull` 任务 （Go 的 interface
///    值天然可共享；Rust 须显式 Arc）。
pub async fn query_ip<S: CachedNameserver + 'static>(
    server: Arc<S>,
    domain: &str,
    option: IpOption,
) -> Result<(Vec<IpAddr>, u32), DnsError> {
    use crate::dnscommon::fqdn;
    let fqdn_str = fqdn(domain);
    let fqdn_owned = fqdn_str.as_str();
    let cache = server.cache_controller();

    if !cache.disable_cache {
        if let Some(rec) = cache.find_records(fqdn_owned) {
            let now = cache.clock().now_instant();
            let (ips, ttl, err) = merge_records(option, rec.a.as_ref(), rec.aaaa.as_ref(), now);
            // Go nameserver_cached.go:27-32：err 非 RecordNotFound 且 ttl>0
            // 即 cache HIT——含负缓存（rcode/空答案）在 TTL 内直接返回，不打
            // 上游（修复前落 fetch，负缓存每次完整上游 RTT，bd wmdn①）。
            if !matches!(err, Some(DnsError::RecordNotFound)) {
                if ttl > 0 {
                    // Go nameserver_cached.go:32：cache HIT 也记一条 dns log（elapsed 0）。
                    record_dns_log(
                        &cache.name,
                        fqdn_owned,
                        &ips,
                        0,
                        xray_app_log::DnsStatus::CacheHit,
                        err.as_ref(),
                    );
                    return match err {
                        None => Ok((ips, ttl as u32)),
                        Some(e) => Err(e),
                    };
                }
                // 过期可服务：Go merge 对过期记录返回 `(ips, ttl<=0, nil)`——
                // serveStale 时秒回旧 IP 并后台刷新。闸门与去重都走派生件 1
                // （`xray_frame::cache`）：窗口口径单源 + 同 fqdn 只起一个 pull。
                if cache.stale_servable(ttl) {
                    if let Some((sips, _)) = stale_result(&rec, option, now) {
                        // Go nameserver_cached.go:37：过期秒回也记一条（Optimiste）。
                        record_dns_log(
                            &cache.name,
                            fqdn_owned,
                            &sips,
                            0,
                            xray_app_log::DnsStatus::CacheOptimiste,
                            None,
                        );
                        // 许可先取（此后 `cache` 借用结束，`server` 才能移进 pull）。
                        let permit = cache.begin_stale_refresh(fqdn_owned);
                        pull(server, fqdn_owned.to_string(), option, permit);
                        return Ok((sips, 1));
                    }
                }
            }
        }
    }

    fetch(server.as_ref(), fqdn_owned, option).await
}

/// serveStale 可服务的过期结果。对应 Go `merge` 的 `ttl<=0 且 err==nil` 情形：
/// option 内每个启用的地址家族都必须有「rcode==NO_ERROR 且 ips 非空」的记录，
/// 返回 `(合并 ips, 最小剩余 ttl)`（ttl 相对真实当前时间，可 <= 0）。
fn stale_result(
    rec: &crate::dnscommon::Record,
    option: IpOption,
    now: Instant,
) -> Option<(Vec<IpAddr>, i32)> {
    use crate::dnscommon::rcode;
    let mut all_ips = Vec::new();
    let mut ttl = i32::MAX;
    for (enabled, r) in
        [(option.ipv4_enable, rec.a.as_ref()), (option.ipv6_enable, rec.aaaa.as_ref())]
    {
        // 家族未启用 → 跳过；启用但无记录 → 不允许 stale（Go nil → errRecordNotFound）。
        if !enabled {
            continue;
        }
        let r = r?;
        if r.rcode != rcode::NO_ERROR || r.ips.is_empty() {
            return None;
        }
        ttl = ttl.min(raw_ttl_seconds(r.expire, now));
        all_ips.extend(r.ips.iter().copied());
    }
    if all_ips.is_empty() {
        return None;
    }
    Some((all_ips, ttl))
}

/// 真实剩余 TTL（秒，向上取整，过期时为负）。`ttl_seconds` 对过期钳 0，
/// 而 Go `serveExpiredTTL < ttl` 闸门（nameserver_cached.go:35）需要负值语义。
fn raw_ttl_seconds(expire: Instant, now: Instant) -> i32 {
    match expire.checked_duration_since(now) {
        Some(d) => d.as_secs_f64().ceil() as i32,
        None => {
            let overdue = now - expire;
            -(overdue.as_secs_f64().ceil() as i32)
        },
    }
}

/// 实际查询 + 缓存写入。对应 Go `fetch` + `doFetch`。
///
/// singleflight 去重：同 key 并发查询合并为一次 `send_query`，等待者共享
/// 领导者结果（领导者条目由 `SfLeaderGuard` 保证移除）；pubsub 订阅仍由
/// `CacheEvent` 广播承担。
pub async fn fetch<S: CachedNameserver>(
    server: &S,
    fqdn: &str,
    option: IpOption,
) -> Result<(Vec<IpAddr>, u32), DnsError> {
    let cache = server.cache_controller();
    let started = cache.clock().now_instant();
    // Arc<str> 让 leader 路径的 key 复制退化为引用计数（String clone 是全量拷贝）。
    let sf_key = (Arc::from(fqdn), option.ipv4_enable, option.ipv6_enable);

    // singleflight：同步临界区内定身份——已有条目则订阅为等待者，否则注册条目
    // 成为领导者。parking_lot guard 非 Send：锁内零 await，guard 不越过任何
    // await 点。领导者条目由 SfLeaderGuard 在 Drop 时移除——正常完成、错误、
    // 被上层 abort（如 parallel_query 的 abort_all）都保证不泄漏。
    // 等待上限按领导者 NS 的查询超时派生（改前固定 4s = 缺省查询超时 ⇒ 必然重复）。
    let sf_wait = sf_wait_timeout(server);
    let mut outcome = {
        let slot = {
            let mut sf = cache.single_flight.lock();
            match sf.get(&sf_key).cloned() {
                Some(tx) => {
                    let rx = tx.subscribe();
                    // 丢弃自己的 sender 克隆：channel 关闭只取决于 map 内（领导者
                    // 侧）的 sender——领导者被 abort 时 guard Drop 移除它，等待者
                    // 的 recv 才能立即得到 Closed 而非空等。
                    drop(tx);
                    SfSlot::Waiter(rx)
                },
                None => {
                    let (tx, _) = broadcast::channel(1);
                    sf.insert(sf_key.clone(), tx.clone());
                    SfSlot::Leader(tx)
                },
            }
        };
        match slot {
            SfSlot::Waiter(mut rx) => {
                // 等待者兜底超时：领导者异常挂起时不被无限拖住。
                // 条目统一由领导者侧 guard 移除（等待者不清理，避免误删超时
                // 期间新领导者的条目；Go singleflight 同为领导者单点删除）。
                match tokio::time::timeout(sf_wait, rx.recv()).await {
                    Ok(Ok(o)) => o,
                    _ => server.send_query(fqdn, option).await,
                }
            },
            SfSlot::Leader(tx) => {
                let _guard =
                    SfLeaderGuard { sf: &cache.single_flight, key: sf_key, tx: tx.clone() };

                let outcome = server.send_query(fqdn, option).await;

                // 广播给等待者（条目移除由 guard Drop 完成）。
                let _ = tx.send(outcome.clone());
                outcome
            },
        }
    };
    let now = cache.clock().now_instant();

    // bd 2bmns G-5：`negativeTtlSecs`（Rust 扩展，Go 无此 JSON 字段）覆写**负答案**
    // 的缓存 TTL。负答案 = rcode 非 NO_ERROR（NXDOMAIN/SERVFAIL…）或 A/AAAA 空表；
    // 0/未配 = 不覆写，跟响应自带 TTL（Go 行为）。此前该字段只存不用。
    let negative_ttl = cache.negative_ttl_secs;
    if negative_ttl > 0 {
        for rec in [outcome.rec_v4.as_mut(), outcome.rec_v6.as_mut()].into_iter().flatten() {
            if rec.rcode == crate::dnscommon::rcode::NO_ERROR && !rec.ips.is_empty() {
                continue;
            }
            rec.expire = now + Duration::from_secs(u64::from(negative_ttl));
        }
    }

    // 缓存结果。仅写入上游真实响应（含 NXDOMAIN 的 rcode=3 记录，TTL 取响应
    // TTL）；上游超时/失败（rec=None）不写任何缓存——Go 从不缓存失败，修复前
    // upsert_negative 把失败伪造成 rcode=3 负缓存（bd rofg②）。
    if let Some(rec) = outcome.rec_v4.clone() {
        let _ = cache.tx.send(crate::cache_controller::CacheEvent::Record {
            domain: fqdn.to_string(),
            is_v4: true,
            record: rec.clone(),
        });
        cache.upsert(fqdn, true, rec);
    }
    if let Some(rec) = outcome.rec_v6.clone() {
        let _ = cache.tx.send(crate::cache_controller::CacheEvent::Record {
            domain: fqdn.to_string(),
            is_v4: false,
            record: rec.clone(),
        });
        cache.upsert(fqdn, false, rec);
    }

    let (ips, ttl, err) =
        merge_records(option, outcome.rec_v4.as_ref(), outcome.rec_v6.as_ref(), now);
    let elapsed_ms = now.duration_since(started).as_millis() as u64;
    if let Some(e) = err {
        // bd d881②：merge 只见 rec（None 一律合成 RecordNotFound，Go
        // getIPs(nil) 同款）——真实上游错误（超时/连接失败）在 outcome.errors，
        // 这里透传原始错误；RecordNotFound 只留给真正的「查无此记录」（负缓存
        // rcode 路径）。聚合形态与 merge_records 一致：同类取首条，异类合并。
        let mut errs = outcome.errors;
        let merged = match errs.len() {
            0 => e,
            1 => errs.swap_remove(0),
            _ if errs
                .iter()
                .skip(1)
                .all(|x| std::mem::discriminant(x) == std::mem::discriminant(&errs[0])) =>
            {
                errs.swap_remove(0)
            },
            _ => DnsError::SystemResolve(
                errs.iter().map(|x| x.to_string()).collect::<Vec<_>>().join("; "),
            ),
        };
        // Go nameserver_cached.go:126：查询收场统一记一条（含错误）。
        record_dns_log(
            &cache.name,
            fqdn,
            &ips,
            elapsed_ms,
            xray_app_log::DnsStatus::Queried,
            Some(&merged),
        );
        return Err(merged);
    }

    let r_ttl: u32 = if ttl > 0 { ttl as u32 } else { 1 };
    // Go nameserver_cached.go:126：`log.Record(&log.DNSLog{... Status: DNSQueried, Elapsed:
    // ...})`。
    record_dns_log(&cache.name, fqdn, &ips, elapsed_ms, xray_app_log::DnsStatus::Queried, None);
    Ok((ips, r_ttl))
}

/// 记一条 DNS 查询日志（Go `log.Record(&log.DNSLog{})`，common/log/dns.go:9-16）。
///
/// 进程级出口（`LogFeature::start` 装、`close` 卸），未装配时 API 自身留痕后静默。
/// `query` 取 Go 同款的 `"<qtype> <fqdn>"` 形态不在此处判定（本层不知 qtype），
/// 只填 domain —— 与 Go `DNSLog.Domain` 一致，读者侧靠 result/status 区分。
fn record_dns_log(
    server: &str,
    domain: &str,
    ips: &[IpAddr],
    elapsed_ms: u64,
    status: xray_app_log::DnsStatus,
    error: Option<&DnsError>,
) {
    xray_app_log::record_dns(xray_app_log::DnsLog {
        query: String::new(),
        domain: domain.to_string(),
        result: ips.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "),
        server: server.to_string(),
        elapsed_ms,
        status,
        error: error.map(ToString::to_string),
    });
}

/// 后台拉取（serveStale 路径）。对应 Go `pull`（nameserver_cached.go:45-49）：
/// 8s 兜底超时；并发去重**由派生件 1 的刷新许可前置承担**（`permit == None` =
/// 同 fqdn 已有 pull 在飞，本次不重复起任务；旧实现是把 N 个任务都起起来再靠
/// `fetch` 的 singleflight 合并）。
///
/// P1-11：spawn 走实例 `FxScope` 托管（坑约束 5）——scope 未注单（实例未
/// start 的直连/测试路径）跳过留 debug 痕；已关（停机中）拒新留 warn 痕。
/// 均不裸 spawn、不 panic。许可随任务结束（drop）释放；任一早退路径同样释放，
/// 不会把 fqdn 永久卡在「在飞」。
pub fn pull<S: CachedNameserver + 'static>(
    server: Arc<S>,
    fqdn: String,
    option: IpOption,
    permit: Option<RefreshPermit>,
) {
    let Some(permit) = permit else {
        tracing::debug!(
            target: "xray.dns",
            fqdn = %fqdn,
            "dns serveStale pull skipped: same-fqdn refresh already in flight"
        );
        return;
    };
    let cache = server.cache_controller();
    let fx = cache.fx_scope().cloned();
    let server_name = cache.name.clone();
    let spawned = fx.map(|fx| {
        let task_fqdn = fqdn.clone();
        // 每次刷新 spawn 前先收割（bd 86i4h 阶段2）：条目不随累计刷新数增长。
        xray_frame::compat::spawn_reaping(
            &fx,
            &xray_frame::compat::log(),
            "dns serveStale refresh",
            async move {
                // 许可生命周期 = 本次刷新任务：任务结束（超时/完成）即释放。
                let _permit = permit;
                let _ =
                    tokio::time::timeout(PULL_TIMEOUT, fetch(server.as_ref(), &task_fqdn, option))
                        .await;
            },
        )
    });
    match spawned {
        Some(Ok(_)) => {},
        Some(Err(_)) => {
            tracing::warn!(
                target: "xray.dns",
                server = %server_name,
                fqdn = %fqdn,
                "dns serveStale pull dropped: fx scope closed"
            );
        },
        None => {
            tracing::debug!(
                target: "xray.dns",
                server = %server_name,
                fqdn = %fqdn,
                "dns serveStale pull skipped: fx scope not attached (instance not started)"
            );
        },
    }
}

/// 订阅缓存广播通道的便捷封装。对应 Go `registerSubscribers`。
///
/// 调用方通常这样使用：
/// ```ignore
/// let mut rx = subscribe(cache);
/// loop {
///     match rx.recv().await {
///         Ok(event) => { /* handle */ }
///         Err(broadcast::error::RecvError::Lagged(n)) => continue,
///         Err(broadcast::error::RecvError::Closed) => break,
///     }
/// }
/// ```
pub fn subscribe(
    cache: &CacheController,
) -> broadcast::Receiver<crate::cache_controller::CacheEvent> {
    cache.subscribe()
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::disallowed_methods,
        reason = "713x6：测试计时不得改语义（契约）——测试取时/等待窗口保持原语义，时钟禁令只约束生产路径"
    )]
    use std::{net::Ipv4Addr, time::Duration};

    use super::*;
    use crate::dnscommon::ip_record;

    struct StubServer {
        cache: Arc<CacheController>,
        rec_v4: Option<IpRecord>,
        rec_v6: Option<IpRecord>,
    }

    impl CachedNameserver for StubServer {
        fn cache_controller(&self) -> &CacheController {
            &self.cache
        }

        async fn send_query(&self, _fqdn: &str, _option: IpOption) -> QueryOutcome {
            QueryOutcome {
                rec_v4: self.rec_v4.clone(),
                rec_v6: self.rec_v6.clone(),
                errors: Vec::new(),
            }
        }
    }

    fn v4_record(ttl_secs: u64) -> IpRecord {
        ip_record(
            1,
            vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))],
            Duration::from_secs(ttl_secs),
            0,
            Instant::now(),
        )
    }
    fn v4_only_option() -> IpOption {
        IpOption { ipv4_enable: true, ipv6_enable: false, fake_enable: false }
    }

    #[tokio::test]
    async fn query_ip_falls_through_to_send_query_on_cache_miss() {
        let cache = Arc::new(CacheController::new("test", false, false, 0, 0));
        let server = StubServer { cache, rec_v4: Some(v4_record(60)), rec_v6: None };
        let (ips, ttl) = query_ip(Arc::new(server), "example.com", v4_only_option()).await.unwrap();
        assert_eq!(ips.len(), 1);
        assert_eq!(ttl, 60);
    }

    #[tokio::test]
    async fn query_ip_returns_cached_when_enabled_and_fresh() {
        let cache = Arc::new(CacheController::new("test", false, false, 0, 0));
        // 预填缓存。
        cache.upsert("example.com.", true, v4_record(60));

        // 即使 send_query 会 panic，query_ip 也应走缓存命中。
        let server = StubServer {
            cache,
            rec_v4: None, // 不会被调用
            rec_v6: None,
        };
        let (ips, ttl) = query_ip(Arc::new(server), "example.com", v4_only_option()).await.unwrap();
        assert_eq!(ips.len(), 1);
        assert!(ttl > 0);
    }

    #[tokio::test]
    async fn query_ip_skips_cache_when_disabled() {
        let cache = Arc::new(CacheController::new("test", true, false, 0, 0));
        cache.upsert("example.com.", true, v4_record(60));

        let server = StubServer { cache, rec_v4: Some(v4_record(60)), rec_v6: None };
        let (ips, _ttl) =
            query_ip(Arc::new(server), "example.com", v4_only_option()).await.unwrap();
        assert_eq!(ips.len(), 1); // 来自 send_query 而非缓存
    }

    /// 过期但曾成功的记录 + serveStale → 秒回 `(ips, 1)` 且后台 pull 真实刷新缓存。
    #[tokio::test]
    async fn query_ip_serves_stale_and_background_pull_refreshes() {
        struct CountingServer {
            cache: Arc<CacheController>,
            calls: std::sync::atomic::AtomicUsize,
        }
        impl CachedNameserver for CountingServer {
            fn cache_controller(&self) -> &CacheController {
                &self.cache
            }

            async fn send_query(&self, _fqdn: &str, _option: IpOption) -> QueryOutcome {
                self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                // 留出并发窗口，让重复 pull 进入 singleflight 等待者路径。
                tokio::time::sleep(Duration::from_millis(30)).await;
                QueryOutcome { rec_v4: Some(v4_record(60)), rec_v6: None, errors: Vec::new() }
            }
        }

        // serve_stale = true。
        let cache = Arc::new(CacheController::new("test", false, true, 0, 0));
        // P1-11：pull 经实例 scope 托管 spawn——测试注单等价实例 start。
        cache.attach_scope(&Arc::new(skeleton_infra::fx::FxScope::new()));
        // 预置已过期记录（expire = now - 30s）。
        let expired = ip_record(
            1,
            vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))],
            Duration::from_secs(0),
            0,
            Instant::now() - Duration::from_secs(30),
        );
        cache.upsert("example.com.", true, expired);

        let server = Arc::new(CountingServer {
            cache: cache.clone(),
            calls: std::sync::atomic::AtomicUsize::new(0),
        });

        // 两个并发查询同时命中过期记录：都秒回旧 IP，pull 去重只打一次上游。
        let (r1, r2) = tokio::join!(
            query_ip(server.clone(), "example.com", v4_only_option()),
            query_ip(server.clone(), "example.com", v4_only_option()),
        );
        let (ips1, ttl1) = r1.unwrap();
        let (_, ttl2) = r2.unwrap();
        assert_eq!(ips1, vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))], "must serve stale ips");
        assert_eq!((ttl1, ttl2), (1, 1), "stale answer carries ttl=1");

        // 后台 pull 被调用：等缓存被刷新为新鲜记录（fetch → upsert）。
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match cache.find_records("example.com.") {
                Some(rec) if !rec.a.as_ref().is_some_and(|r| r.is_expired(Instant::now())) => break,
                _ if Instant::now() >= deadline => panic!("background pull must refresh the cache"),
                _ => tokio::time::sleep(Duration::from_millis(5)).await,
            }
        }
        assert_eq!(
            server.calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "concurrent pulls must dedupe to one upstream query"
        );
    }

    /// serveExpiredTTL 闸门：记录过期时长超出宽限 → 不服务 stale，落到 fetch。
    #[tokio::test]
    async fn query_ip_stale_gated_by_serve_expired_ttl() {
        let cache = Arc::new(CacheController::new("test", false, true, 60, 0));
        // 过期 120s（超出 60s 宽限）。
        let expired = ip_record(
            1,
            vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))],
            Duration::from_secs(0),
            0,
            Instant::now() - Duration::from_secs(120),
        );
        cache.upsert("example.com.", true, expired);

        let server = StubServer { cache, rec_v4: Some(v4_record(60)), rec_v6: None };
        // Go: serveExpiredTTL(-60) < ttl(-120) 不成立 → 不走 stale，fetch 返回 1.2.3.4。
        let (ips, _ttl) =
            query_ip(Arc::new(server), "example.com", v4_only_option()).await.unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]);
    }

    /// bd wmdn① 回归：负缓存（rcode=3 空答案）TTL 内命中——query_ip 直接
    /// 返回 RCodeError，**不打上游**。修复前 merge 错误落 `_ => {}` 进 fetch，
    /// 负缓存每次完整上游 RTT（Go nameserver_cached.go:27-32 TTL 内零查询）。
    #[tokio::test]
    async fn negative_cache_hit_within_ttl_skips_upstream() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        use crate::dnscommon::rcode;

        struct CountingServer {
            cache: Arc<CacheController>,
            calls: AtomicUsize,
        }
        impl CachedNameserver for CountingServer {
            fn cache_controller(&self) -> &CacheController {
                &self.cache
            }

            async fn send_query(&self, _fqdn: &str, _option: IpOption) -> QueryOutcome {
                self.calls.fetch_add(1, Ordering::SeqCst);
                QueryOutcome { rec_v4: Some(v4_record(60)), rec_v6: None, errors: Vec::new() }
            }
        }

        let cache = Arc::new(CacheController::new("test", false, false, 0, 0));
        // 预填负缓存：rcode=3、空 IP、TTL 60s。
        let neg = ip_record(1, vec![], Duration::from_secs(60), rcode::NX_DOMAIN, Instant::now());
        cache.upsert("neg.example.com.", true, neg);

        let server = Arc::new(CountingServer { cache: cache.clone(), calls: AtomicUsize::new(0) });
        let err = query_ip(server.clone(), "neg.example.com", v4_only_option()).await.unwrap_err();
        assert!(matches!(err, DnsError::RCodeError(3)), "应直接返回负缓存 rcode 错误");
        assert_eq!(server.calls.load(Ordering::SeqCst), 0, "TTL 内负缓存命中不得打上游");
    }

    /// bd 2bmns G-5：`negativeTtlSecs` 真的生效——负答案（NXDOMAIN / 空表）的
    /// 缓存 TTL 被它覆写，不再是响应自带 TTL。此前该字段只存不用。
    ///
    /// 反向断言：删掉 `fetch` 里的 negative TTL 覆写块，TTL 断言立刻变红
    /// （剩 ~3600s 而不是 ~30s）。
    #[tokio::test]
    async fn negative_ttl_secs_overrides_negative_answer_ttl() {
        use crate::dnscommon::rcode;

        let cache = Arc::new(CacheController::new("test", false, false, 0, 30));
        let neg = ip_record(1, vec![], Duration::from_secs(3600), rcode::NX_DOMAIN, Instant::now());
        let server = StubServer { cache: cache.clone(), rec_v4: Some(neg), rec_v6: None };

        let err = query_ip(Arc::new(server), "neg.example.com", v4_only_option())
            .await
            .expect_err("NXDOMAIN 必须作为错误上抛");
        assert!(matches!(err, DnsError::RCodeError(3)), "unexpected: {err}");

        let rec = cache.find_records("neg.example.com.").expect("负答案必须入缓存");
        let ttl = rec.a.as_ref().expect("v4 record").ttl_seconds(cache.clock().now_instant());
        assert!((29..=30).contains(&ttl), "negativeTtlSecs=30 必须覆写缓存 TTL，实际 {ttl}");
    }

    /// 0 = 不覆写（跟响应自带 TTL，Go 行为）——默认值不得砍断正常负缓存。
    #[tokio::test]
    async fn negative_ttl_zero_keeps_response_ttl() {
        use crate::dnscommon::rcode;

        let cache = Arc::new(CacheController::new("test", false, false, 0, 0));
        let neg = ip_record(1, vec![], Duration::from_secs(3600), rcode::NX_DOMAIN, Instant::now());
        let server = StubServer { cache: cache.clone(), rec_v4: Some(neg), rec_v6: None };

        let err = query_ip(Arc::new(server), "zero.example.com", v4_only_option())
            .await
            .expect_err("NXDOMAIN 必须作为错误上抛");
        assert!(matches!(err, DnsError::RCodeError(3)), "unexpected: {err}");

        let rec = cache.find_records("zero.example.com.").expect("负答案必须入缓存");
        let ttl = rec.a.as_ref().expect("v4 record").ttl_seconds(cache.clock().now_instant());
        assert!(ttl > 3000, "0 = 不覆写，应保留响应 TTL，实际 {ttl}");
    }

    /// bd rofg② 回归：上游失败（rec=None + errors 非空）不写 rcode=3 负缓存
    /// （Go 从不缓存失败）。修复前 fetch 的 `else if` 兜底把失败伪造成负缓存。
    #[tokio::test]
    async fn upstream_failure_not_cached_as_negative() {
        struct FailServer {
            cache: Arc<CacheController>,
        }
        impl CachedNameserver for FailServer {
            fn cache_controller(&self) -> &CacheController {
                &self.cache
            }

            async fn send_query(&self, _fqdn: &str, _option: IpOption) -> QueryOutcome {
                QueryOutcome {
                    rec_v4: None,
                    rec_v6: None,
                    errors: vec![DnsError::SystemResolve("upstream timeout".into())],
                }
            }
        }

        let cache = Arc::new(CacheController::new("test", false, false, 0, 0));
        let server = FailServer { cache: cache.clone() };
        let err = fetch(&server, "fail.example.com.", v4_only_option()).await.unwrap_err();
        // bd d881②：单家族 + rec=None + errors=[原始错误] → 透传原始错误，
        // 不得吞成 RecordNotFound（超时/网络失败必须对调用方可辨）。
        assert!(
            matches!(&err, DnsError::SystemResolve(s) if s == "upstream timeout"),
            "上游原始错误应透传，got: {err:?}"
        );
        assert!(cache.is_empty(), "上游失败不得写任何缓存");
    }

    /// bd d881②：双家族都失败时原始错误透传——同类取首条，异类聚合成
    /// SystemResolve（与 merge_records 聚合形态一致）。
    #[tokio::test]
    async fn upstream_errors_passthrough_dual_family() {
        struct DualFailServer {
            cache: Arc<CacheController>,
        }
        impl CachedNameserver for DualFailServer {
            fn cache_controller(&self) -> &CacheController {
                &self.cache
            }

            async fn send_query(&self, _fqdn: &str, _option: IpOption) -> QueryOutcome {
                QueryOutcome {
                    rec_v4: None,
                    rec_v6: None,
                    errors: vec![
                        DnsError::WireFormat("v4 timeout".into()),
                        DnsError::EmptyResponse,
                    ],
                }
            }
        }

        let cache = Arc::new(CacheController::new("test", false, false, 0, 0));
        let server = DualFailServer { cache };
        let err = fetch(
            &server,
            "dual.example.com.",
            IpOption { ipv4_enable: true, ipv6_enable: true, fake_enable: false },
        )
        .await
        .unwrap_err();
        match err {
            DnsError::SystemResolve(s) => {
                assert!(
                    s.contains("v4 timeout") && s.contains("empty response"),
                    "异类错误应聚合，got: {s}"
                );
            },
            other => panic!("expected aggregated SystemResolve, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fetch_broadcasts_event_to_cache_subscribers() {
        let cache = Arc::new(CacheController::new("test", false, false, 0, 0));
        let mut rx = cache.subscribe();
        let server = StubServer { cache: cache.clone(), rec_v4: Some(v4_record(60)), rec_v6: None };
        let (ips, _) = fetch(&server, "example.com.", v4_only_option()).await.unwrap();
        assert_eq!(ips.len(), 1);

        let event = rx.recv().await.unwrap();
        match event {
            crate::cache_controller::CacheEvent::Record { domain, is_v4, .. } => {
                assert_eq!(domain, "example.com.");
                assert!(is_v4);
            },
        }
    }

    /// P1-11 验收①/②：serveStale pull 托管化边界——未注单跳过（不 panic
    /// 不 spawn）、已关闭拒新（warn 留痕，in_flight 不增）、开放 scope 任务
    /// 入集且排空后 expect_idle 过。
    #[tokio::test]
    async fn pull_requires_attached_open_scope() {
        // 未注单：跳过。
        let cache = Arc::new(CacheController::new("probe", false, true, 30, 0));
        let server = Arc::new(HangServer {
            cache: cache.clone(),
            hang: std::sync::atomic::AtomicBool::new(true),
        });
        pull(
            server,
            "stale.com.".to_string(),
            v4_only_option(),
            cache.begin_stale_refresh("stale.com."),
        );
        assert!(cache.fx_scope().is_none(), "unattached scope must stay unattached");

        // 已关闭：拒新，in_flight 不增。
        let fx = Arc::new(skeleton_infra::fx::FxScope::new());
        cache.attach_scope(&fx);
        fx.close();
        let server = Arc::new(HangServer {
            cache: cache.clone(),
            hang: std::sync::atomic::AtomicBool::new(true),
        });
        pull(
            server,
            "stale.com.".to_string(),
            v4_only_option(),
            cache.begin_stale_refresh("stale.com."),
        );
        assert_eq!(fx.in_flight(), 0, "closed scope must not gain new tasks");

        // 开放 scope：pull 任务入集；排空后在途归零。
        let cache2 = Arc::new(CacheController::new("probe2", false, true, 30, 0));
        let fx_open = Arc::new(skeleton_infra::fx::FxScope::new());
        cache2.attach_scope(&fx_open);
        // 许可先取（cache2 随后被移进 server）。
        let permit = cache2.begin_stale_refresh("stale.com.");
        let server2 =
            Arc::new(HangServer { cache: cache2, hang: std::sync::atomic::AtomicBool::new(true) });
        pull(server2, "stale.com.".to_string(), v4_only_option(), permit);
        assert_eq!(fx_open.in_flight(), 1, "open scope must host the pull task");
        let _ = fx_open.shutdown().await; // 测试收尾：让渡 panic 报告
        skeleton_infra::fx::expect_idle(&fx_open);
    }

    /// 可控挂起的 Server：`hang=true` 时 send_query 循环等待，false 时返回成功。
    struct HangServer {
        cache: Arc<CacheController>,
        hang: std::sync::atomic::AtomicBool,
    }

    impl CachedNameserver for HangServer {
        fn cache_controller(&self) -> &CacheController {
            &self.cache
        }

        async fn send_query(&self, _fqdn: &str, _option: IpOption) -> QueryOutcome {
            while self.hang.load(std::sync::atomic::Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            QueryOutcome { rec_v4: Some(v4_record(60)), rec_v6: None, errors: Vec::new() }
        }
    }

    #[tokio::test]
    async fn singleflight_leader_abort_does_not_leak_and_key_recovers() {
        let cache = Arc::new(CacheController::new("test", false, false, 0, 0));
        let server = Arc::new(HangServer { cache, hang: std::sync::atomic::AtomicBool::new(true) });

        // 领导者：进入 fetch 后停在挂起的 send_query 上。
        let leader =
            xray_common::testing::spawn("singleflight-leader-abort-does-not-leak-and-key-reco", {
                let server = server.clone();
                async move { fetch(&*server, "a.com.", v4_only_option()).await }
            });
        // 等领导者注册条目。
        loop {
            if server.cache.single_flight.lock().len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        // 等待者：进入等待者路径（recv 广播）。
        let waiter =
            xray_common::testing::spawn("singleflight-leader-abort-does-not-leak-and-key-reco", {
                let server = server.clone();
                async move { fetch(&*server, "a.com.", v4_only_option()).await }
            });
        tokio::time::sleep(Duration::from_millis(20)).await;

        // 解除挂起并中止领导者：guard Drop 必须移除条目，等待者收到
        // channel 关闭后回退直查成功。
        server.hang.store(false, std::sync::atomic::Ordering::SeqCst);
        leader.abort();
        let (ips, _) = tokio::time::timeout(Duration::from_secs(2), waiter)
            .await
            .expect("waiter must not hang after leader abort")
            .unwrap()
            .unwrap();
        assert_eq!(ips.len(), 1);

        // 同 key 再查：可恢复（条目已被清，新查询正常成为领导者）。
        let (ips, _) = fetch(&*server, "a.com.", v4_only_option()).await.unwrap();
        assert_eq!(ips.len(), 1);
        assert!(
            server.cache.single_flight.lock().is_empty(),
            "singleflight entry must be cleaned up"
        );
    }

    #[tokio::test]
    async fn singleflight_deduplicates_concurrent_same_key_queries() {
        struct CountingServer {
            cache: Arc<CacheController>,
            calls: std::sync::atomic::AtomicUsize,
        }
        impl CachedNameserver for CountingServer {
            fn cache_controller(&self) -> &CacheController {
                &self.cache
            }

            async fn send_query(&self, _fqdn: &str, _option: IpOption) -> QueryOutcome {
                self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                // 留出并发窗口让第二个请求进入等待者路径。
                tokio::time::sleep(Duration::from_millis(20)).await;
                QueryOutcome { rec_v4: Some(v4_record(60)), rec_v6: None, errors: Vec::new() }
            }
        }

        let cache = Arc::new(CacheController::new("test", false, false, 0, 0));
        let server =
            Arc::new(CountingServer { cache, calls: std::sync::atomic::AtomicUsize::new(0) });
        let f1 = xray_common::testing::spawn("send-query", {
            let server = server.clone();
            async move { fetch(&*server, "dup.com.", v4_only_option()).await }
        });
        let f2 = xray_common::testing::spawn("send-query", {
            let server = server.clone();
            async move { fetch(&*server, "dup.com.", v4_only_option()).await }
        });
        let (r1, r2) = tokio::join!(f1, f2);
        assert!(r1.unwrap().is_ok());
        assert!(r2.unwrap().is_ok());
        assert_eq!(
            server.calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "same-key concurrent queries must hit send_query once"
        );
        assert!(server.cache.single_flight.lock().is_empty());
    }

    /// serveStale 刷新失败：上游失败不写缓存（不覆盖旧值），过期记录保留，
    /// 后续查询继续乐观返回旧值——Go 无 backoff timer，重试由后续查询驱动
    /// （每次乐观命中 spawn 一次 pull，singleflight 防并发重复）。
    #[tokio::test]
    async fn stale_refresh_failure_keeps_old_value() {
        struct FailServer {
            cache: Arc<CacheController>,
            calls: std::sync::atomic::AtomicUsize,
        }
        impl CachedNameserver for FailServer {
            fn cache_controller(&self) -> &CacheController {
                &self.cache
            }

            async fn send_query(&self, _fqdn: &str, _option: IpOption) -> QueryOutcome {
                self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                QueryOutcome {
                    rec_v4: None,
                    rec_v6: None,
                    errors: vec![DnsError::SystemResolve("upstream down".into())],
                }
            }
        }

        let cache = Arc::new(CacheController::new("test", false, true, 0, 0));
        // P1-11：pull 经实例 scope 托管 spawn——测试注单等价实例 start。
        cache.attach_scope(&Arc::new(skeleton_infra::fx::FxScope::new()));
        let expired = ip_record(
            1,
            vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))],
            Duration::from_secs(0),
            0,
            Instant::now() - Duration::from_secs(30),
        );
        cache.upsert("example.com.", true, expired);

        let server = Arc::new(FailServer {
            cache: cache.clone(),
            calls: std::sync::atomic::AtomicUsize::new(0),
        });

        // 第一次：秒回旧 IP（后台 pull 会失败，不影响本次返回）。
        let (ips, ttl) = query_ip(server.clone(), "example.com", v4_only_option()).await.unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))], "秒回旧 IP");
        assert_eq!(ttl, 1);

        // 等 pull 失败落地（fetch 完成且不写缓存）。
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            server.calls.load(std::sync::atomic::Ordering::SeqCst) >= 1,
            "后台 pull 必须真实打过上游"
        );

        // 旧记录未被清除/覆盖；第二次查询依旧乐观返回旧值（查询驱动重试）。
        let rec = cache.find_records("example.com.").expect("刷新失败必须保留旧记录");
        assert_eq!(
            rec.a.as_ref().unwrap().ips,
            vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))],
            "失败结果不得覆盖旧值"
        );
        let (ips, ttl) = query_ip(server.clone(), "example.com", v4_only_option()).await.unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))]);
        assert_eq!(ttl, 1);
    }

    /// serveStale 关闭（Go 缺省）：过期条目不返回旧值，落 fetch 阻塞刷新。
    #[tokio::test]
    async fn stale_disabled_falls_through_to_fetch() {
        let cache = Arc::new(CacheController::new("test", false, false, 0, 0));
        let expired = ip_record(
            1,
            vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))],
            Duration::from_secs(0),
            0,
            Instant::now() - Duration::from_secs(30),
        );
        cache.upsert("example.com.", true, expired);

        let server = StubServer { cache, rec_v4: Some(v4_record(60)), rec_v6: None };
        let (ips, ttl) = query_ip(Arc::new(server), "example.com", v4_only_option()).await.unwrap();
        assert_eq!(
            ips,
            vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))],
            "serveStale 关闭时不得返回过期旧值"
        );
        assert_eq!(ttl, 60, "应返回 fetch 新值的 TTL");
    }

    /// bd 26v9t：等待上限 = 本 NS 的 `query_timeout` + 1s（改前固定 4s，恰等于
    /// UDP/TCP/DoT/DoQ 缺省 4000ms ⇒ 领导者刚失败的同刻等待者超时并自起一轮
    /// 上游查询，必然重复）。五种 NS 各自按自身配置值派生。
    #[test]
    fn sf_wait_timeout_derives_from_ns_query_timeout() {
        use xray_common::net::{address::Address, destination::Destination, port::Port};

        use crate::nameserver::{
            doh::DohNameServer, dot::DotNameServer, quic::DoqNameServer, tcp::TcpNameServer,
            udp::UdpNameServer,
        };

        let dest = Destination::tcp(Address::from(Ipv4Addr::LOCALHOST), Port::new(53));
        let udp_dest = Destination::udp(Address::from(Ipv4Addr::LOCALHOST), Port::new(53));
        let resolver: Arc<dyn crate::dial::HostResolver> =
            Arc::new(crate::dial::SystemHostResolver);
        let tls = xray_tls::utls::default_client_config();
        let cache = |tag: &str| Arc::new(CacheController::new(tag, true, false, 0, 0));
        let default_qt = Duration::from_millis(4000);

        let udp =
            UdpNameServer::new(udp_dest, cache("t"), Vec::new(), default_qt, Arc::clone(&resolver));
        let tcp = TcpNameServer::new(
            dest.clone(),
            cache("t"),
            Vec::new(),
            default_qt,
            Arc::clone(&resolver),
        );
        let dot = DotNameServer::new(
            dest.clone(),
            "localhost".to_string(),
            Arc::clone(&tls),
            cache("t"),
            Vec::new(),
            default_qt,
        );
        let doq = DoqNameServer::new(
            "127.0.0.1:853".parse().expect("addr"),
            "localhost".to_string(),
            Arc::clone(&tls),
            cache("t"),
            Vec::new(),
            default_qt,
        );
        // DoH 缺省 5000ms ⇒ 派生 6s。
        let doh = DohNameServer::new(
            dest,
            "localhost".to_string(),
            tls,
            cache("t"),
            Vec::new(),
            Duration::from_millis(5000),
            true,
        );

        assert_eq!(sf_wait_timeout(&udp), Duration::from_secs(5));
        assert_eq!(sf_wait_timeout(&tcp), Duration::from_secs(5));
        assert_eq!(sf_wait_timeout(&dot), Duration::from_secs(5));
        assert_eq!(sf_wait_timeout(&doq), Duration::from_secs(5));
        assert_eq!(sf_wait_timeout(&doh), Duration::from_secs(6));
    }

    /// bd 26v9t：领导者跑得比等待上限更久时，等待者在上限处自查询——上限跟
    /// `query_timeout` 走（100ms + 1s），不再被固定 4s 拖住。
    #[tokio::test]
    async fn sf_waiter_gives_up_at_derived_timeout() {
        struct SlowServer {
            cache: Arc<CacheController>,
            calls: std::sync::atomic::AtomicUsize,
        }
        impl CachedNameserver for SlowServer {
            fn cache_controller(&self) -> &CacheController {
                &self.cache
            }

            fn query_timeout(&self) -> Duration {
                Duration::from_millis(100)
            }

            async fn send_query(&self, _fqdn: &str, _option: IpOption) -> QueryOutcome {
                self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                // 比派生上限（100ms + 1s）更久 ⇒ 等待者必在上限处自查询。
                tokio::time::sleep(Duration::from_millis(1300)).await;
                QueryOutcome { rec_v4: Some(v4_record(60)), rec_v6: None, errors: Vec::new() }
            }
        }

        let server = Arc::new(SlowServer {
            cache: Arc::new(CacheController::new("sf-derived", true, false, 0, 0)),
            calls: std::sync::atomic::AtomicUsize::new(0),
        });

        // 领导者先起步（占住 singleflight 条目）。
        let leader = xray_common::testing::spawn("sf-derived-leader", {
            let server = Arc::clone(&server);
            async move { fetch(&*server, "slow.com.", v4_only_option()).await }
        });
        loop {
            if !server.cache.single_flight.lock().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        let started = Instant::now();
        let waiter = fetch(&*server, "slow.com.", v4_only_option()).await;
        let elapsed = started.elapsed();
        assert!(waiter.is_ok());
        assert!(
            elapsed >= Duration::from_millis(1100),
            "等待者至少要等满派生上限（100ms + 1s），实测 {elapsed:?}"
        );
        // 派生上限 1.1s + 自查询 1.3s ≈ 2.4s；改前固定 4s ⇒ 5.3s。
        assert!(
            elapsed < Duration::from_millis(3200),
            "等待上限应跟 query_timeout 走（约 1.1s）而非固定 4s，实测 {elapsed:?}"
        );
        assert_eq!(
            server.calls.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "领导者 1 次 + 等待者自查询 1 次"
        );
        let _ = leader.await;
    }
}
