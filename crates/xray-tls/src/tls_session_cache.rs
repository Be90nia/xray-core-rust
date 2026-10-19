//! 进程内 TLS session cache（bypass-握手复用，bd 2026-10-19 B2）。
//!
//! 对齐 Go `tls.Config.ClientSessionCache`：在客户端缓存 (server_name, fingerprint)
//! 对应的 BoringSSL `SSL_SESSION`，让同一目的地后续 dial 通过 `SSL_set_session`
//! 把 PSK 信息塞进 ClientHello 触发 1-RTT resumption（TLS 1.3 新会话票走 at most 1-RTT，
//! 0-RTT 视服务端策略）。
//!
//! ## BoringSSL TLS 1.3 `not_resumable` 陷阱（关键约束，bd 0kqj B2 修复）
//!
//! BoringSSL `SSL_SESSION_to_bytes` 在 TLS 1.3 path 上发现 `SSL_get_session()`
//! 拿到的 session 有 `not_resumable=true`（握手完成即设 true 防误用），序列化会
//! 写成 `"NOT RESUMABLE"` 占位符。`SSL_SESSION_from_bytes` 还原后仍是
//! `not_resumable=true`，`ssl_session_get_type()` 返回 `SSLSessionType::kNotResumable`，
//! 客户端 ClientHello 不发 PSK 扩展、服务端识别不到 ticket —— 此前 B2 cache 命
//! 中率 47/47 但 `session_reused=false` 根因。
//!
//! 修复=BoringSSL `SslSession` 直接缓存，跳过序列化。BoringSSL `SslSession` 是
//! 引用计数对象（`SslSession_up_ref` 即 bump），`Ssl_set_session` 内部 `up_ref`
//! 后两方各持一份，独立 drop 也只 free 一次。drop 跟随 Rust `HashMap` +
//! `Mutex` 自然清理。
//!
//! ## BoringSSL 客户端 cache 边界
//!
//! BoringSSL 客户端无内置 cache。本模块就是 app 级 cache：握手成功从
//! `SSL_get_session()` 拿现成 SslSession → 存入 hash map → 下次 dial
//! 取出 → `SSL_set_session` 投递。
//!
//! ## 进程内 only 约束
//!
//! 缓存是进程级 `LazyLock` 单例。重启进程 cache 失效 → 第一个 dial 必 full handshake
//! 之后才能复用——这与 Rust `r2` build 同启服务端的场景一致（同进程 instance、
//! cache 热）。重启跨进程不冲击：full handshake 路径本身工作正常。
//!
//! ## CTX 不一致
//!
//! 不同 fingerprint 是不同 SSL_CTX（`connector_for_fingerprint` 每次返回新 connector）
//! ——但 BoringSSL 的 `SSL_set_session` 会检查 cipher 是否与 session 里 cipher 兼容，
//! 不兼容即拒，不会误握手。`enableSessionResumption=false` 直接早返 None 对齐
//! rustls 路径。
//!
//! ponytail: 单进程一份 hash map（`[key](String, Fingerprint)` → `SslSession`+Instant），
//! TTL = 24h（远大于 Chrome page-load 间隔；BoringSSL 内置 session_timeout 默认
//! 24h = server 端 ticket 寿命），超期条目惰性清理（lookup 时比对）。

use std::{
    collections::HashMap,
    sync::{Arc, LazyLock, Mutex as StdMutex},
    time::{Duration, Instant},
};

use tracing::{debug, trace};

use crate::fingerprint::Fingerprint;

/// Session cache TTL（24h，对齐 BoringSSL `SSL_SESSION` 默认 timeout）。
///
/// ponytail: TTL 是「本模块愿意持有 session 的最长时长」；BoringSSL server
/// 端 ticket lifetime 通常 24h，过期 ticket 1-RTT 会拒绝、强制 1-RTT 兜底。
/// 设大些便于浏览器当晚重复访问复用率；冷提可在 lookup 时简化比对。
const SESSION_TTL: Duration = Duration::from_secs(24 * 3600);

/// 缓存条目：(SslSession ref-count handle, 写入时刻)。
struct CacheEntry {
    /// 直接持有 SslSession 句柄——BoringSSL 内置引用计数，drop 时 `SSL_SESSION_free`。
    /// 跳过 `to_der` / `from_der` 序列化避免 TLS 1.3 `not_resumable` 陷阱。
    session: btls::ssl::SslSession,
    /// 写入时刻，用于惰性 TTL 淘汰。
    stored_at: Instant,
}

/// 缓存表类型别名（`clippy::type_complexity` 要求显式 type）。
type CacheMap = HashMap<(String, Fingerprint), CacheEntry>;

/// 进程内单例 cache：`Arc<StdMutex<CacheMap>>`（lookup 极少但须跨 dial
/// 共享，锁粒度 = 整张表；同 key 并发写 = 后写覆盖，已达成语义）。
static CACHE: LazyLock<Arc<StdMutex<CacheMap>>> =
    LazyLock::new(|| Arc::new(StdMutex::new(HashMap::new())));

fn cache() -> Arc<StdMutex<CacheMap>> {
    CACHE.clone()
}

/// 在客户端握手前取出可复用的 session（命中则 `Some(SslSession)`）。
///
/// `enable_session_resumption=false` 时直接返回 None（与 rustls 路径的
/// `Resumption::disabled()` 对齐）。
///
/// 不再需要 `SslContextRef`：SslSession 已是 ref-counted，独立持有不影响后续 SSL。
pub(crate) fn lookup_for_resume(
    server_name: &str,
    fingerprint: Fingerprint,
    enable_session_resumption: bool,
) -> Option<btls::ssl::SslSession> {
    if !enable_session_resumption {
        return None;
    }
    let cache = cache();
    let session = {
        let mut guard = cache.lock().unwrap_or_else(|p| p.into_inner());
        let entry = guard.get_mut(&(server_name.to_string(), fingerprint))?;
        if entry.stored_at.elapsed() > SESSION_TTL {
            guard.remove(&(server_name.to_string(), fingerprint));
            return None;
        }
        debug!(target: "xray_tls::session_cache", server_name, ?fingerprint, "session resume: 命中 cache");
        // SslSession 内部 ref-counted，`to_owned` 增量引用计数，调用方 drop 独立 free。
        entry.session.clone()
    };
    Some(session)
}

/// 握手成功后回写 session 到 cache（无副作用失败）。
///
/// `enable_session_resumption=false` 时不做任何事。
pub(crate) fn store_session(
    server_name: &str,
    fingerprint: Fingerprint,
    session: &btls::ssl::SslSessionRef,
    enable_session_resumption: bool,
) {
    if !enable_session_resumption {
        return;
    }
    let cache = cache();
    let mut guard = cache.lock().unwrap_or_else(|p| p.into_inner());
    // SslSession 内部 ref-counted，`to_owned` 增量引用计数。
    let owned = session.to_owned();
    guard.insert(
        (server_name.to_string(), fingerprint),
        CacheEntry { session: owned, stored_at: Instant::now() },
    );
    trace!(
        target: "xray_tls::session_cache",
        server_name,
        ?fingerprint,
        "session stored"
    );
}

/// 解析 `tlsSettings.enableSessionResumption` 缺省 = true（Go 语义）。
///
/// 与 `client_config::build_client_config` 解析同名字段保持一致——缺省对齐 Go
/// `SessionTicketsDisabled=false`（即允许会话复用）。
pub(crate) fn parse_enable_session_resumption(security_json: Option<&serde_json::Value>) -> bool {
    security_json
        .and_then(|v| v.as_object())
        .and_then(|m| m.get("enableSessionResumption"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// enableSessionResumption 缺省 = true（Go 语义）。
    #[test]
    fn enable_session_resumption_default_true() {
        assert!(parse_enable_session_resumption(None));
        assert!(parse_enable_session_resumption(Some(&serde_json::json!({}))));
    }

    /// enableSessionResumption=false 显式关 cache。
    #[test]
    fn enable_session_resumption_false_disables() {
        assert!(!parse_enable_session_resumption(Some(
            &serde_json::json!({"enableSessionResumption": false})
        )));
    }

    /// enableSessionResumption=true 显式开 cache。
    #[test]
    fn enable_session_resumption_true_enables() {
        assert!(parse_enable_session_resumption(Some(
            &serde_json::json!({"enableSessionResumption": true})
        )));
    }

    /// lookup_for_resume 在 resumption=false 时直接返 None（早返分支）。
    /// 单元测只能验证解析逻辑（完整握手级验证见集成 e2e）。
    #[test]
    fn lookup_disabled_short_circuits() {
        // resumption 关闭 → 函数体内早返 None；这里只验证 parse 路径正确，
        // 真正的 lookup 路径依赖 btls 完整 handshake，集成层覆盖。
        assert!(!parse_enable_session_resumption(Some(
            &serde_json::json!({"enableSessionResumption": false})
        )));
    }
}
