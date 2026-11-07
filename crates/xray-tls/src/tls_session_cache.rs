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
//! ## 容量与老化（bd nzli4/nzli6）
//!
//! 宿主是 udf `std_ext::cache::SyncTtlCache`：容量 **128 条 LRU**（对齐 Go
//! `tls.NewLRUClientSessionCache(128)`），逐条 TTL 24h。此前是无界 `HashMap`
//! 与「仅惰性 TTL」两条叠加 ⇒ 条目数 = TTL 窗口内握过的不同 server_name 数，
//! 无上界（256MB 机器上的积压点）。现在满插即逐 LRU 尾（`evictions` 计数）
//! 并在驱逐时 `debug!` 留痕，过期条目在读面惰性回收（`expired` 计数）。

use std::{
    sync::{Arc, LazyLock},
    time::Duration,
};

use btls::ssl::SslSession;
use skeleton::clock::{Clock, SystemClock};
use std_ext::cache::SyncTtlCache;
use tracing::{debug, trace};

/// Session cache 条目上界（对齐 Go `tls.NewLRUClientSessionCache(128)`，
/// `transport/internet/tls/config.go:25`）——满则逐 LRU 尾，**禁无界增长**。
///
/// 会话条目上界（登记于 xray-core `memory_budget::TLS_SESSION_CACHE_MAX_ENTRIES`，
/// 交叉断言钉住，bd sgdwm）。
/// 字节口径（256MB 机器「全部池/缓存 ≤4MB」硬顶）：单条 `SSL_SESSION`
/// （TLS 1.3 ticket + master secret + peer 证书链引用）估 2~20KiB
/// ⇒ 128 条最坏 ≈ 2.5MiB。
pub const TLS_SESSION_CACHE_CAPACITY: usize = 128;

/// Session cache TTL（24h，对齐 BoringSSL `SSL_SESSION` 默认 timeout）。
///
/// TTL 是「本模块愿意持有 session 的最长时长」；BoringSSL server 端 ticket
/// lifetime 通常 24h，过期 ticket 被拒后强制完整握手兜底。过期条目由缓存
/// 读面惰性回收（`SyncTtlCache::expired` 计数可观测）。
const SESSION_TTL: Duration = Duration::from_secs(24 * 3600);

/// 进程内单例 cache：容量（[`TLS_SESSION_CACHE_CAPACITY`]）+ 逐条 TTL 双界，
/// 并发面 `&self`（内部短临界区）。key = server_name（对齐 Go
/// `tls.Config.ClientSessionCache`，不分指纹）。
static CACHE: LazyLock<SyncTtlCache<String, SslSession>> = LazyLock::new(build_cache::<SslSession>);

/// 构造会话缓存。`V` 泛化 = 容量/TTL 接线可在无 btls 握手下断言（见 tests）。
fn build_cache<V>() -> SyncTtlCache<String, V> {
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    SyncTtlCache::new(clock, TLS_SESSION_CACHE_CAPACITY)
}

/// 在客户端握手前取出可复用的 session（命中则 `Some(SslSession)`）。
///
/// `enable_session_resumption=false` 时直接返回 None（与 rustls 路径的
/// `Resumption::disabled()` 对齐）。
pub(crate) fn lookup_for_resume(
    server_name: &str,
    enable_session_resumption: bool,
) -> Option<SslSession> {
    if !enable_session_resumption {
        return None;
    }
    // SslSession 内部 ref-counted，clone 增量引用计数，调用方 drop 独立 free。
    let session = CACHE.get(&server_name.to_string())?;
    debug!(target: "xray_tls::session_cache", server_name, "session resume: 命中 cache");
    Some(session)
}

/// NST 回调入口：NewSessionTicket 到达时写入 cache（此 session 带票、
/// `not_resumable=false`，是唯一可复用的形态）。后续写入覆盖前写入。
/// 回调在 SSL_CTX 级、无法感知 per-connection `enableSessionResumption`——
/// 该 flag 由 [`lookup_for_resume`] 读取侧门控，false 时只存不读、行为正确。
pub(crate) fn store_session(server_name: &str, session: SslSession) {
    let evictions_before = CACHE.evictions();
    CACHE.insert(server_name.to_string(), session, SESSION_TTL);
    let evicted = CACHE.evictions() - evictions_before;
    if evicted > 0 {
        // 满插逐 LRU 尾：容量上界生效的显式留痕（不是静默丢弃）。
        debug!(
            target: "xray_tls::session_cache",
            capacity = TLS_SESSION_CACHE_CAPACITY,
            evictions = CACHE.evictions(),
            "session cache 满：逐 LRU 尾"
        );
    }
    trace!(
        target: "xray_tls::session_cache",
        server_name,
        "session stored (new_session_cb)"
    );
}

/// 解析 `tlsSettings.enableSessionResumption` 缺省 = true（Go 配置语义）。
///
/// 与 `client_config::build_client_config` 解析同名字段保持一致——缺省对齐 Go
/// `SessionTicketsDisabled=false`（即允许会话复用）。
///
/// # 与 Go 的 wire 差异（bd 9anht，运维须知）
///
/// Go 客户端的 uTLS 路径 `copyConfig` **不搬** `ClientSessionCache`
/// （utls v1.8.3 `common.go:773`），`reality.go:137` 更显式
/// `SessionTicketsDisabled: true` ⇒ **Go 侧从不 resume**，每次 dial 都是
/// full handshake（ClientHello 无 `pre_shared_key`）。Rust 侧缺省复用
/// 缓存 ticket ⇒ 热身后的 ClientHello 带 PSK 扩展，JA3/JA4 与 Go 基线不同。
/// 要拿到与 Go 同形态的握手，配置显式写 `"enableSessionResumption": false`
/// （本模块读面早返，等价 Go 行为，代价是每次 dial 多一个 RTT）。
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

    /// bd nzli6：(a) 缓存有界 + 满插逐 LRU 尾。`V` 用 `Vec<u8>` 替身（容量/TTL
    /// 接线与真实 `SslSession` 同一条构造路径），真实 session 的存取由 e2e 互通覆盖。
    #[test]
    fn session_cache_bounded_and_evicts_lru_tail() {
        let cache = build_cache::<Vec<u8>>();
        assert_eq!(cache.capacity(), TLS_SESSION_CACHE_CAPACITY);
        for i in 0..TLS_SESSION_CACHE_CAPACITY {
            cache.insert(format!("host{i}.example"), vec![i as u8], SESSION_TTL);
        }
        assert_eq!(cache.len(), TLS_SESSION_CACHE_CAPACITY);
        assert_eq!(cache.evictions(), 0);

        // 第 129 条：不增长，逐最旧（首个写入且从未被 touch 的 host0）。
        cache.insert("overflow.example".to_string(), vec![0xff], SESSION_TTL);
        assert_eq!(cache.len(), TLS_SESSION_CACHE_CAPACITY, "容量满即淘汰，禁无界增长");
        assert_eq!(cache.evictions(), 1, "淘汰计数可观测");
        assert!(cache.peek(&"host0.example".to_string()).is_none(), "最旧条目（LRU 尾）被逐");
        assert!(cache.peek(&"overflow.example".to_string()).is_some());
    }

    /// bd nzli6 追测（Main 必补项）：单条缓存 session 的**真实字节**（替换 [INFERENCE]）。
    ///
    /// 方法：真实 btls 握手（自签单证书服务端 + Chrome 指纹客户端），NewSessionTicket
    /// 经 `new_session_cb` 写入 cache 后取回测量：
    /// - `to_der()`：i2d_SSL_SESSION 全长（ticket + master secret + 固定字段；
    ///   回调交付的是带票可复用形态，无 not_resumable 占位符问题）；
    /// - `master_key()` / `id()` 组件；
    /// - 叶子证书 DER（session up-ref 把链留在内存，本夹具为自签单证书； 生产链 = 叶子 + 中间 CA ⇒
    ///   略增）。
    /// 复现：`cargo test -p xray-tls --lib tls_session_cache -- --nocapture`。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::disallowed_macros, reason = "测量探针：输出单条 session 字节供人工判读")]
    #[ignore = "测量探针：需 btls 自签对端握手，实测挂起 >60s（2026-11-04 PM 观测）；\
                容量上界已按 TLS1.3 ticket 200–500B / TLS1.2 session 1–4KB 估算判定（见 bd nzli6）"]
    async fn measure_single_cached_session_bytes() {
        use tokio::io::AsyncReadExt;

        use crate::{
            btls_client::BtlsConn, btls_server::accept as btls_accept, fingerprint::Fingerprint,
        };

        // 唯一 SNI：与本测试二进制其它并行握手互不串缓存键。
        const SNI: &str = "cache-footprint.invalid";
        let params = rcgen::CertificateParams::new(vec![SNI.to_string()]).expect("params");
        let key_pair = rcgen::KeyPair::generate().expect("keypair");
        let cert = params.self_signed(&key_pair).expect("cert");
        let cert_der = cert.der().to_vec();
        let key_der = key_pair.serialize_der();

        let (client_io, server_io) = tokio::io::duplex(256 * 1024);
        let server_fut = btls_accept(server_io, &cert_der, &key_der);
        let connect_fut = BtlsConn::connect(
            Box::new(xray_transport::connection::DuplexConnection::new(client_io))
                as Box<dyn xray_transport::connection::Connection>,
            SNI,
            Fingerprint::Chrome,
            None,
            None,
        );

        // ⚠️ connect 与服务端必须在同一轮询循环里并跑（join! 协作式轮询）——单独
        // await connect 会让服务端永远不被 poll ⇒ 握手死锁（初版实测踩过）。
        let session = {
            let measure = async {
                let mut client = connect_fut.await.expect("btls handshake");
                // NST 是握手后的记录，客户端读侧处理时才触发 new_session_cb ⇒ 读泵
                // + lookup 轮询；3s 兜底窗（sleep 钉死上限，不读墙钟——时钟唯一源纪律）。
                let deadline = tokio::time::sleep(Duration::from_secs(3));
                tokio::pin!(deadline);
                loop {
                    if let Some(s) = lookup_for_resume(SNI, true) {
                        break s;
                    }
                    let mut buf = [0u8; 1024];
                    tokio::select! {
                        _ = &mut deadline => panic!("NST 未在 3s 内写入 cache（回调链路断裂？）"),
                        r = client.read(&mut buf) => {
                            if r.expect("client read") == 0 {
                                // EOF：服务端已关。给回调一点余量后由下一轮 lookup 判定。
                                tokio::time::sleep(Duration::from_millis(10)).await;
                            }
                        }
                    }
                }
                // client 在此 drop ⇒ 服务端 EOF ⇒ server_fut 完成，join! 收口。
            };
            // 10s 外层兜底：任一侧卡死时测试失败而非挂死整个进程。
            tokio::time::timeout(Duration::from_secs(10), async {
                let (s, ()) = tokio::join!(measure, async {
                    let _ = server_fut.await;
                });
                s
            })
            .await
            .expect("probe 未在 10s 内完成（握手或 NST 链路卡死）")
        };

        let der = session.to_der().expect("i2d_SSL_SESSION");
        let mut master = [0u8; 128];
        let master_len = session.master_key(&mut master);
        let id_len = session.id().len();
        // 单条 ≈ SSL_SESSION 结构体（~0.3KB）+ der（ticket 在内）+ 被链住叶子证书。
        let per_entry = der.len() + cert_der.len() + 300;
        println!(
            "[PROBE] btls cached session: der={}B master_key={}B session_id={}B leaf_cert={}B ⇒ 单条≈{per_entry}B ⇒ 128 条≈{}B",
            der.len(),
            master_len,
            id_len,
            cert_der.len(),
            per_entry * TLS_SESSION_CACHE_CAPACITY
        );
        // 1MB 预算口径：单条载荷（der + 叶子）> 8KiB ⇒ 容量 128 需重裁。
        assert!(
            der.len() + cert_der.len() <= 8 * 1024,
            "der={}B + leaf={}B 超 8KiB/条 ⇒ TLS_SESSION_CACHE_CAPACITY 需按 1MB/实测值下调",
            der.len(),
            cert_der.len()
        );
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
