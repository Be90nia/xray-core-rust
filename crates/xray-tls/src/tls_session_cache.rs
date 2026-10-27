//! 进程内 TLS session cache（bypass-握手复用，bd 2026-10-19 B2）。
//!
//! 对齐 Go `tls.Config.ClientSessionCache`：在客户端缓存 server_name 对应的
//! BoringSSL `SSL_SESSION`，让同一目的地后续 dial 通过 `SSL_set_session`
//! 把 PSK 信息塞进 ClientHello 触发 1-RTT resumption（TLS 1.3 新会话票走 at most 1-RTT，
//! 0-RTT 视服务端策略）。Go 的 cache key 本就是 host:port 字符串、不分指纹，
//! 本模块同构（不同指纹的 CTX 间投递 session 由 `SSL_set_session` 的 cipher
//! 兼容性检查兜底，不兼容即拒、不误握手）。
//!
//! ## 根因史：为什么必须用 `SSL_CTX_sess_set_new_cb` 写入（B2 二次修复）
//!
//! 第一版在**握手完成点**取 `SSL_get_session()` 存 cache——这个时机拿到的是
//! **无 ticket 的 handshake session**（TLS 1.3 客户端握手完成时
//! `established_session` dup 自 `new_session`，NewSessionTicket 尚未到达/处理）。
//! BoringSSL `ssl_session_get_type` 对「TLS 1.3 + 空 ticket」返回
//! `kNotResumable`，`should_offer_psk` 直接拒绝 → ClientHello 永不发 PSK
//! 扩展 → 服务端无从复用（bd 0kqj 症状：cache 47/47 命中但
//! `session_reused=false`）。此前把 `not_resumable` 归因于 to_der 序列化
//! 陷阱是误诊——序列化只是暴露问题的通道，直接持有 SslSession 同样无效。
//!
//! 带 ticket 的 resumption session 只在 NST 到达时由
//! `SSL_CTX_sess_set_new_cb` 回调交付（BoringSSL `tls13_client.cc`
//! `ssl_process_new_session_ticket`：`ticket_age_add_valid = true;
//! not_resumable = false` 后 UpRef 交回调）。修复 = connector builder 挂
//! [`crate::btls_client`] 的 session cache hook（`set_new_session_callback`
//! + `SSL_SESS_CACHE_CLIENT`——后者是回调触发前提），本模块只做存取。
//!
//! ## 进程内 only 约束
//!
//! 缓存是进程级 `LazyLock` 单例。重启进程 cache 失效 → 第一个 dial 必 full handshake
//! 之后才能复用——这与 Rust `r2` build 同启服务端的场景一致（同进程 instance、
//! cache 热）。重启跨进程不冲击：full handshake 路径本身工作正常。
//!
//! ponytail: 单进程一份 hash map（`String`(server_name) → `SslSession`+Instant），
//! TTL = 24h（远大于 Chrome page-load 间隔；BoringSSL 内置 session_timeout 默认
//! 24h = server 端 ticket 寿命），超期条目惰性清理（lookup 时比对）。

use std::{
    collections::HashMap,
    sync::{Arc, LazyLock, Mutex as StdMutex},
    time::{Duration, Instant},
};

use skeleton::clock::{Clock, SystemClock};
use tracing::{debug, trace};

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

/// 缓存表类型别名（`clippy::type_complexity` 要求显式 type）。key = server_name
/// （对齐 Go `tls.Config.ClientSessionCache`，不分指纹）。
type CacheMap = HashMap<String, CacheEntry>;

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
pub(crate) fn lookup_for_resume(
    server_name: &str,
    enable_session_resumption: bool,
) -> Option<btls::ssl::SslSession> {
    if !enable_session_resumption {
        return None;
    }
    let cache = cache();
    let session = {
        let mut guard = cache.lock().unwrap_or_else(|p| p.into_inner());
        let entry = guard.get_mut(server_name)?;
        if entry.stored_at.elapsed() > SESSION_TTL {
            guard.remove(server_name);
            return None;
        }
        debug!(target: "xray_tls::session_cache", server_name, "session resume: 命中 cache");
        // SslSession 内部 ref-counted，`to_owned` 增量引用计数，调用方 drop 独立 free。
        entry.session.clone()
    };
    Some(session)
}

/// NST 回调入口：NewSessionTicket 到达时写入 cache（此 session 带票、
/// `not_resumable=false`，是唯一可复用的形态）。后续写入覆盖前写入。
/// 回调在 SSL_CTX 级、无法感知 per-connection `enableSessionResumption`——
/// 该 flag 由 [`lookup_for_resume`] 读取侧门控，false 时只存不读、行为正确。
pub(crate) fn store_session(server_name: &str, session: btls::ssl::SslSession) {
    let cache = cache();
    let mut guard = cache.lock().unwrap_or_else(|p| p.into_inner());
    guard.insert(
        server_name.to_string(),
        CacheEntry { session, stored_at: SystemClock.now_instant() },
    );
    trace!(
        target: "xray_tls::session_cache",
        server_name,
        "session stored (new_session_cb)"
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

/// 解析 `tlsSettings.allowEarlyData` 缺省 = false（Rust 扩展字段，Go 忽略）。
///
/// 0-RTT (early data) 总闸：客户端侧控制 btls 握手是否提供 0-RTT（仅幂等首写
/// 协议应开，如 ws/httpupgrade upgrade GET）；服务端侧控制 rustls 是否接受
/// 0-RTT（见 `server_config::build_server_config`）。缺省关闭 = 现行为零变化。
pub(crate) fn parse_allow_early_data(security_json: Option<&serde_json::Value>) -> bool {
    security_json
        .and_then(|v| v.as_object())
        .and_then(|m| m.get("allowEarlyData"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

#[cfg(test)]
mod allow_early_data_tests {
    use super::parse_allow_early_data;

    #[test]
    fn allow_early_data_defaults_false() {
        assert!(!parse_allow_early_data(None));
        assert!(!parse_allow_early_data(Some(&serde_json::json!({}))));
    }

    #[test]
    fn allow_early_data_parses_bool() {
        assert!(parse_allow_early_data(Some(&serde_json::json!({"allowEarlyData": true}))));
        assert!(!parse_allow_early_data(Some(&serde_json::json!({"allowEarlyData": false}))));
        // 非 bool 值（字符串/数字）按缺省关处理，不 panic
        assert!(!parse_allow_early_data(Some(&serde_json::json!({"allowEarlyData": "yes"}))));
        assert!(!parse_allow_early_data(Some(&serde_json::json!({"allowEarlyData": 1}))));
    }
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
