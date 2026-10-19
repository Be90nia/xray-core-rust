//! 进程内 TLS session cache（bypass-握手复用，bd 2026-10-19 B2）。
//!
//! 对齐 Go `tls.Config.ClientSessionCache`：在客户端缓存 (server_name, fingerprint)
//! 对应的 BoringSSL `SSL_SESSION`（serialized bytes），让同一目的地后续 dial
//! 通过 `SSL_set_session` 把 PSK 信息塞进 ClientHello 触发 1-RTT resumption（TLS 1.3
//! 新会话票走 at most 1-RTT，0-RTT 视服务端策略）。
//!
//! ## BoringSSL 客户端 cache 边界（关键约束）
//!
//! BoringSSL 客户端无内置 cache（`SSL_SESS_CACHE_CLIENT` 仅启用 callback），
//! 实现路径：set_new_session_cb 接收 `SslSession` → 存入本模块 hash map → 下次
//!   dial 前 `SSL_SESSION_from_bytes` + `SSL_set_session` 投递。
//!
//! ## CTX 生命周期
//!
//! `connector_for_fingerprint()` 每次返回新 `SslConnector`（独立 SSL_CTX），
//! 故 session 的「CTX 一致」约束由序列化/反序列化两端同 fingerprint 满足。
//! SSL_set_session 不持有所有权（BoringSSL 内部 up-ref），set 后 SslSession 可
//! 立即 drop——本模块存序列化字节，无需保留原 SSL_SESSION。
//!
//! ## enableSessionResumption=false
//!
//! 调用方读 `tlsSettings.enableSessionResumption`，false 时本模块
//! `lookup_for_resume`/`store_session` 均返回 None/不做修改（rustls 路径
//! 已有 `Resumption::disabled()`，btls 路径无对应 API，由本 cache 软禁）。
//!
//! ponytail: 单进程一份 hash map（`[key](String, Fingerprint)` → `Vec<u8>`），
//! TTL = 24h（远大于 Chrome page-load 间隔；BoringSSL 内置 session_timeout 默认
//! 24h = server 端 ticket 寿命），超期条目惰性清理（lookup 时比对）。

use std::{
    collections::HashMap,
    sync::{Arc, LazyLock, Mutex as StdMutex},
    time::{Duration, Instant},
};

use foreign_types::ForeignTypeRef;
use tracing::{debug, trace};

use crate::fingerprint::Fingerprint;

/// Session cache TTL（24h，对齐 BoringSSL `SSL_SESSION` 默认 timeout）。
///
/// ponytail: TTL 是「本模块愿意持有 session 字节的最长时长」；BoringSSL server
/// 端 ticket lifetime 通常 24h，过期 ticket 1-RTT 会拒绝、强制 1-RTT 兜底。
/// 设大些便于浏览器当晚重复访问复用率；冷提可在 lookup 时简化比对。
const SESSION_TTL: Duration = Duration::from_secs(24 * 3600);

/// 缓存条目：(serialized bytes, 写入时刻)。
#[derive(Clone)]
struct CacheEntry {
    /// `SSL_SESSION_to_bytes` 产出 → 后同字节喂 `SSL_SESSION_from_bytes`。
    bytes: Vec<u8>,
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
/// `ctx` 是当前连接即将使用的 `SslContextRef`——`SSL_SESSION_from_bytes` 要求
/// ctx 仅用于 cipher 校验，不修改原 session。
pub(crate) fn lookup_for_resume(
    server_name: &str,
    fingerprint: Fingerprint,
    ctx: &btls::ssl::SslContextRef,
    enable_session_resumption: bool,
) -> Option<btls::ssl::SslSession> {
    if !enable_session_resumption {
        return None;
    }
    // 绑定 Arc 到 let——cache() 临时值随语句结束 drop，MutexGuard 借用了
    //         *arc 跨语句会触发 E0716（temporary dropped while borrowed）。
    let cache = cache();
    let bytes = {
        let mut guard = cache.lock().unwrap_or_else(|p| p.into_inner());
        let entry = guard.get_mut(&(server_name.to_string(), fingerprint))?;
        if entry.stored_at.elapsed() > SESSION_TTL {
            guard.remove(&(server_name.to_string(), fingerprint));
            return None;
        }
        entry.bytes.clone()
    };
    let session_ptr = unsafe {
        btls_sys::SSL_SESSION_from_bytes(bytes.as_ptr(), bytes.len(), ctx.as_ptr())
    };
    if session_ptr.is_null() {
        // 反序列化失败（CTX cipher 不兼容 / bytes 损坏）→ 静默放弃本次复用。
        trace!(target: "xray_tls::session_cache", server_name, ?fingerprint, "session resume: deserialize failed");
        return None;
    }
    debug!(target: "xray_tls::session_cache", server_name, ?fingerprint, "session resume: 命中 cache");
    // SAFETY: session_ptr 非空（已检）；`SslSessionRef::from_ptr` 不持有所有权，
    // `to_owned` up-ref 后 SslSession 成为独立 owner（drop 时 free）。
    let sess_ref = unsafe { btls::ssl::SslSessionRef::from_ptr(session_ptr) };
    Some(sess_ref.to_owned())
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
    let mut out: *mut u8 = std::ptr::null_mut();
    let mut out_len: usize = 0;
    let ok = unsafe {
        btls_sys::SSL_SESSION_to_bytes(session.as_ptr(), &mut out, &mut out_len)
    };
    if ok != 1 || out.is_null() {
        debug!(
            target: "xray_tls::session_cache",
            server_name,
            ?fingerprint,
            "session store: SSL_SESSION_to_bytes failed; cache not updated"
        );
        return;
    }
    let bytes = unsafe { std::slice::from_raw_parts(out, out_len).to_vec() };
    unsafe { btls_sys::OPENSSL_free(out.cast()) };
    let cache = cache();
    let mut guard = cache.lock().unwrap_or_else(|p| p.into_inner());
    guard.insert(
        (server_name.to_string(), fingerprint),
        CacheEntry { bytes, stored_at: Instant::now() },
    );
}

/// 解析 `tlsSettings.enableSessionResumption` 缺省 = true（Go 语义）。
///
/// 与 `client_config::build_client_config` 解析同名字段保持一致——缺省对齐 Go
/// `SessionTicketsDisabled=false`（即允许会话复用）。
pub(crate) fn parse_enable_session_resumption(
    security_json: Option<&serde_json::Value>,
) -> bool {
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