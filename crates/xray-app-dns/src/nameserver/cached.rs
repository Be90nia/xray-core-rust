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
/// 1. 若缓存启用且命中：返回 `(ips, ttl, Ok)` 或 stale 优化路径。
/// 2. 否则调用 `fetch`（singleflight + pubsub）执行实际查询。
pub async fn query_ip<S: CachedNameserver>(
    server: &S,
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
            match merge_records(option, rec.a.as_ref(), rec.aaaa.as_ref(), now) {
                Ok((ips, ttl)) if ttl > 0 => {
                    return Ok((ips, ttl as u32));
                }
                // 过期 / 错误：落到下方 fetch。
                _ => {}
            }
        }
    }

    fetch(server, fqdn_owned, option).await
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

    // 缓存结果。
    if let Some(rec) = outcome.rec_v4.clone() {
        let _ = cache.tx.send(crate::cache_controller::CacheEvent::Record {
            domain: fqdn.to_string(),
            is_v4: true,
            record: rec.clone(),
        });
        cache.upsert(fqdn, true, rec);
    } else if option.ipv4_enable {
        cache.upsert_negative(fqdn, true, now);
    }
    if let Some(rec) = outcome.rec_v6.clone() {
        let _ = cache.tx.send(crate::cache_controller::CacheEvent::Record {
            domain: fqdn.to_string(),
            is_v4: false,
            record: rec.clone(),
        });
        cache.upsert(fqdn, false, rec);
    } else if option.ipv6_enable {
        cache.upsert_negative(fqdn, false, now);
    }

    let (ips, ttl) = merge_records(
        option,
        outcome.rec_v4.as_ref(),
        outcome.rec_v6.as_ref(),
        now,
    )?;

    let r_ttl: u32 = if ttl > 0 { ttl as u32 } else { 1 };
    Ok((ips, r_ttl))
}

/// 后台拉取（serveStale 路径）。对应 Go `pull`。
///
/// ponytail: 用 `tokio::spawn` fire-and-forget。
pub fn pull<S: CachedNameserver + 'static>(
    server: Arc<S>,
    fqdn: String,
    option: IpOption,
) {
    tokio::spawn(async move {
        let _ = fetch(server.as_ref(), &fqdn, option).await;
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
        let (ips, ttl) = query_ip(&server, "example.com", v4_only_option()).await.unwrap();
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
        let (ips, ttl) = query_ip(&server, "example.com", v4_only_option()).await.unwrap();
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
        let (ips, _ttl) = query_ip(&server, "example.com", v4_only_option()).await.unwrap();
        assert_eq!(ips.len(), 1); // 来自 send_query 而非缓存
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
}
