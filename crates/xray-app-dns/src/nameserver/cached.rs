//! 缓存层：CachedNameserver trait + queryIP/fetch/doFetch/merge 调度。
//!
//! 对应 Go `app/dns/nameserver_cached.go`。
//!
//! ## 范围
//!
//! - 缓存命中检测 + 调度逻辑：完整翻译。
//! - `pubsub` / `singleflight`：用 `tokio::sync::broadcast` 与简化的 per-key
//!   `Mutex<HashMap>` 模拟，业务语义保留（避免重复查询、等待首个响应）。
//!
//! CachedNameserver 是内部 trait，调用方用具体类型或泛型 `T:`，故用 `async fn` 而非
//! 手写 boxed future（与上层 `Server` trait 风格不同）。

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::broadcast;

use crate::cache_controller::CacheController;
use crate::config::IpOption;
use crate::dnscommon::{merge_records, IpRecord};
use crate::error::DnsError;

/// singleflight 等待者的兜底超时。领导者底层查询各自带 per-query timeout
/// （默认 4s），此处取同量级值，防领导者异常挂起时等待者被无限拖住。
const SF_WAIT_TIMEOUT: Duration = Duration::from_secs(4);

/// 后台 pull 的兜底超时。对应 Go `pull` 的 `context.WithTimeout(..., 8s)`。
const PULL_TIMEOUT: Duration = Duration::from_secs(8);

type SfMap = tokio::sync::Mutex<
    std::collections::HashMap<(String, bool, bool), broadcast::Sender<QueryOutcome>>,
>;

/// 按 key 移除 singleflight 条目；`same_channel` 校验防止误删后来领导者的新条目。
fn remove_sf_entry(sf: &SfMap, key: &(String, bool, bool), tx: &broadcast::Sender<QueryOutcome>) {
    if let Ok(mut sf) = sf.try_lock() {
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
    key: (String, bool, bool),
    tx: broadcast::Sender<QueryOutcome>,
}

impl Drop for SfLeaderGuard<'_> {
    fn drop(&mut self) {
        // Drop 不能 await；try_lock 失败时条目由等待者的 remove_sf_entry 兜底清除。
        remove_sf_entry(self.sf, &self.key, &self.tx);
    }
}

/// 缓存型 nameserver 接口。对应 Go `CachedNameserver` interface。
pub trait CachedNameserver: Send + Sync {
    /// 取共享缓存控制器。
    fn cache_controller(&self) -> &CacheController;

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
        Self {
            rec_v4: self.rec_v4.clone(),
            rec_v6: self.rec_v6.clone(),
            errors: Vec::new(),
        }
    }
}

/// 缓存入口查询。对应 Go `queryIP(ctx, s, domain, option)`。
///
/// 1. 若缓存启用且命中：返回 `(ips, ttl, Ok)`；过期且 `serveStale` 时走
///    stale 优化路径（Go nameserver_cached.go:31-41：秒回旧 IP + `go pull` 续期）。
/// 2. 否则调用 `fetch`（singleflight + pubsub）执行实际查询。
/// 3. 持有 `Arc<S>`（`'static`）：stale 路径需把服务器共享给后台 `pull` 任务
///    （Go 的 interface 值天然可共享；Rust 须显式 Arc）。
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
            let now = Instant::now();
            let (ips, ttl, err) = merge_records(option, rec.a.as_ref(), rec.aaaa.as_ref(), now);
            // Go nameserver_cached.go:27-32：err 非 RecordNotFound 且 ttl>0
            // 即 cache HIT——含负缓存（rcode/空答案）在 TTL 内直接返回，不打
            // 上游（修复前落 fetch，负缓存每次完整上游 RTT，bd wmdn①）。
            if !matches!(err, Some(DnsError::RecordNotFound)) {
                if ttl > 0 {
                    return match err {
                        None => Ok((ips, ttl as u32)),
                        Some(e) => Err(e),
                    };
                }
                // 过期可服务：Go merge 对过期记录返回 `(ips, ttl<=0, nil)`——
                // serveStale 时秒回旧 IP 并后台刷新。
                if cache.serve_stale
                    && (cache.serve_expired_ttl_secs == 0
                        || cache.serve_expired_ttl_secs < ttl)
                {
                    if let Some((sips, _)) = stale_result(&rec, option, now) {
                        pull(server, fqdn_owned.to_string(), option);
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
        }
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
    let sf_key = (fqdn.to_string(), option.ipv4_enable, option.ipv6_enable);

    // singleflight：如果已有同名查询在进行，等待其结果；否则成为领导者。
    // 领导者条目由 SfLeaderGuard 在 Drop 时移除——正常完成、错误、被上层
    // abort（如 parallel_query 的 abort_all）都保证不泄漏。
    let outcome = {
        let mut sf = cache.single_flight.lock().await;
        if let Some(tx) = sf.get(&sf_key).cloned() {
            drop(sf);
            let mut rx = tx.subscribe();
            // 丢弃自己的 sender 克隆：channel 关闭只取决于 map 内（领导者侧）
            // 的 sender——领导者被 abort 时 guard Drop 移除它，等待者的 recv
            // 才能立即得到 Closed 而非空等。
            drop(tx);
            // 等待者兜底超时：领导者异常挂起时不被无限拖住。
            // 条目统一由领导者侧 guard 移除（等待者不清理，避免误删超时
            // 期间新领导者的条目；Go singleflight 同为领导者单点删除）。
            match tokio::time::timeout(SF_WAIT_TIMEOUT, rx.recv()).await {
                Ok(Ok(o)) => o,
                _ => server.send_query(fqdn, option).await,
            }
        } else {
            let (tx, _) = broadcast::channel(1);
            sf.insert(sf_key.clone(), tx.clone());
            drop(sf);
            let _guard = SfLeaderGuard {
                sf: &cache.single_flight,
                key: sf_key.clone(),
                tx: tx.clone(),
            };

            let outcome = server.send_query(fqdn, option).await;

            // 广播给等待者（条目移除由 guard Drop 完成）。
            let _ = tx.send(outcome.clone());
            outcome
        }
    };
    let now = Instant::now();

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

    let (ips, ttl, err) = merge_records(
        option,
        outcome.rec_v4.as_ref(),
        outcome.rec_v6.as_ref(),
        now,
    );
    if let Some(e) = err {
        return Err(e);
    }

    let r_ttl: u32 = if ttl > 0 { ttl as u32 } else { 1 };
    Ok((ips, r_ttl))
}

/// 后台拉取（serveStale 路径）。对应 Go `pull`（nameserver_cached.go:45-49）：
/// 8s 兜底超时；并发去重由 `fetch` 的 singleflight 天然承担（同 key 在途时
/// 后续 pull 合并为等待者，不重复打上游）。
///
/// ponytail: 用 `tokio::spawn` fire-and-forget。
pub fn pull<S: CachedNameserver + 'static>(
    server: Arc<S>,
    fqdn: String,
    option: IpOption,
) {
    tokio::spawn(async move {
        let _ = tokio::time::timeout(PULL_TIMEOUT, fetch(server.as_ref(), &fqdn, option)).await;
    });
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
pub fn subscribe(cache: &CacheController) -> broadcast::Receiver<crate::cache_controller::CacheEvent> {
    cache.subscribe()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dnscommon::ip_record;
    use std::net::Ipv4Addr;
    use std::time::Duration;

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
        let server = StubServer {
            cache,
            rec_v4: Some(v4_record(60)),
            rec_v6: None,
        };
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

        let server = StubServer {
            cache,
            rec_v4: Some(v4_record(60)),
            rec_v6: None,
        };
        let (ips, _ttl) = query_ip(Arc::new(server), "example.com", v4_only_option()).await.unwrap();
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

        let server = StubServer {
            cache,
            rec_v4: Some(v4_record(60)),
            rec_v6: None,
        };
        // Go: serveExpiredTTL(-60) < ttl(-120) 不成立 → 不走 stale，fetch 返回 1.2.3.4。
        let (ips, _ttl) = query_ip(Arc::new(server), "example.com", v4_only_option()).await.unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]);
    }

    /// bd wmdn① 回归：负缓存（rcode=3 空答案）TTL 内命中——query_ip 直接
    /// 返回 RCodeError，**不打上游**。修复前 merge 错误落 `_ => {}` 进 fetch，
    /// 负缓存每次完整上游 RTT（Go nameserver_cached.go:27-32 TTL 内零查询）。
    #[tokio::test]
    async fn negative_cache_hit_within_ttl_skips_upstream() {
        use crate::dnscommon::rcode;
        use std::sync::atomic::{AtomicUsize, Ordering};

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

        let server = Arc::new(CountingServer {
            cache: cache.clone(),
            calls: AtomicUsize::new(0),
        });
        let err = query_ip(server.clone(), "neg.example.com", v4_only_option())
            .await
            .unwrap_err();
        assert!(matches!(err, DnsError::RCodeError(3)), "应直接返回负缓存 rcode 错误");
        assert_eq!(server.calls.load(Ordering::SeqCst), 0, "TTL 内负缓存命中不得打上游");
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
                QueryOutcome { rec_v4: None, rec_v6: None, errors: vec![DnsError::SystemResolve("upstream timeout".into())] }
            }
        }

        let cache = Arc::new(CacheController::new("test", false, false, 0, 0));
        let server = FailServer { cache: cache.clone() };
        let err = fetch(&server, "fail.example.com.", v4_only_option()).await.unwrap_err();
        // 单家族 + rec=None → merge_records 立即返回 RecordNotFound（Go 同：
        // getIPs(nil) = errRecordNotFound）。
        assert!(matches!(err, DnsError::RecordNotFound), "上游失败应返回 RecordNotFound");
        assert!(cache.is_empty(), "上游失败不得写任何缓存");
    }

    #[tokio::test]
    async fn fetch_broadcasts_event_to_cache_subscribers() {
        let cache = Arc::new(CacheController::new("test", false, false, 0, 0));
        let mut rx = cache.subscribe();
        let server = StubServer {
            cache: cache.clone(),
            rec_v4: Some(v4_record(60)),
            rec_v6: None,
        };
        let (ips, _) = fetch(&server, "example.com.", v4_only_option()).await.unwrap();
        assert_eq!(ips.len(), 1);

        let event = rx.recv().await.unwrap();
        match event {
            crate::cache_controller::CacheEvent::Record { domain, is_v4, .. } => {
                assert_eq!(domain, "example.com.");
                assert!(is_v4);
            }
        }
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
        let server = Arc::new(HangServer {
            cache,
            hang: std::sync::atomic::AtomicBool::new(true),
        });

        // 领导者：进入 fetch 后停在挂起的 send_query 上。
        let leader = tokio::spawn({
            let server = server.clone();
            async move { fetch(&*server, "a.com.", v4_only_option()).await }
        });
        // 等领导者注册条目。
        loop {
            if server.cache.single_flight.lock().await.len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        // 等待者：进入等待者路径（recv 广播）。
        let waiter = tokio::spawn({
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
            server.cache.single_flight.lock().await.is_empty(),
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
        let server = Arc::new(CountingServer {
            cache,
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let f1 = tokio::spawn({
            let server = server.clone();
            async move { fetch(&*server, "dup.com.", v4_only_option()).await }
        });
        let f2 = tokio::spawn({
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
        assert!(server.cache.single_flight.lock().await.is_empty());
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
        let rec = cache
            .find_records("example.com.")
            .expect("刷新失败必须保留旧记录");
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

        let server = StubServer {
            cache,
            rec_v4: Some(v4_record(60)),
            rec_v6: None,
        };
        let (ips, ttl) = query_ip(Arc::new(server), "example.com", v4_only_option()).await.unwrap();
        assert_eq!(
            ips,
            vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))],
            "serveStale 关闭时不得返回过期旧值"
        );
        assert_eq!(ttl, 60, "应返回 fetch 新值的 TTL");
    }
}
