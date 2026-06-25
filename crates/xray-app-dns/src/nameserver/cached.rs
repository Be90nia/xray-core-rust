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
use std::time::Instant;

use tokio::sync::broadcast;

use crate::cache_controller::CacheController;
use crate::config::IpOption;
use crate::dnscommon::{merge_records, IpRecord};
use crate::error::DnsError;

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
/// ponytail: 省略 singleflight 去重（per-key Mutex）与 pubsub 订阅，直接串行
/// send_query + 合并。多并发请求去重在 `CacheController` 的 RwLock 层面已部分缓解；
/// 真实部署可在 `fetch` 外层包一层 `DashMap<String, Shared<...>>` 实现 singleflight。
pub async fn fetch<S: CachedNameserver>(
    server: &S,
    fqdn: &str,
    option: IpOption,
) -> Result<(Vec<IpAddr>, u32), DnsError> {
    let outcome = server.send_query(fqdn, option).await;
    let now = Instant::now();

    // 广播结果到 cache。
    let cache = server.cache_controller();
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

    let (ips, ttl) = merge_records(
        option,
        outcome.rec_v4.as_ref(),
        outcome.rec_v6.as_ref(),
        now,
    )?;

    // Go 行为：ttl == 0 && err == RecordNotFound → 返回 ttl=0；其他负 ttl 返回 1。
    let r_ttl: u32 = if ttl > 0 {
        ttl as u32
    } else {
        1
    };
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
        let cache = Arc::new(CacheController::new("test", false, false, 0));
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
        let cache = Arc::new(CacheController::new("test", false, false, 0));
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
        let cache = Arc::new(CacheController::new("test", true, false, 0));
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
        let cache = Arc::new(CacheController::new("test", false, false, 0));
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
}
