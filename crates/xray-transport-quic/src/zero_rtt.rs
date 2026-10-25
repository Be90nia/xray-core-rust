//! QUIC 0-RTT 会话恢复（bd fgzb / B7）——Go `splithttp/dialer.go:243` `tr.DialEarly` 对位。
//!
//! Go quic-go `Transport.DialEarly` 在客户端具备会话票时以 0-RTT 发出 early data，
//! 无票时等同普通拨号。Rust 侧对应机制分两半，都在本模块：
//!
//! 1. **会话票存储**（[`session_store`] / [`enable_client_session_resumption`]）： rustls 0.23
//!    `ClientConfig` 每实例自带独立票缓存，连接间不复用 → 0-RTT 永不 命中。挂进程级共享缓存后，同一
//!    server 第二连起具备 TLS 1.3 PSK 票。该函数 同时设 `enable_early_data = true`（本仓 vendor
//!    rustls 默认 false，不设则 恢复会话不发 early_data 扩展，quinn `has_0rtt()` 恒 false）。
//! 2. **0-RTT 拨号**（[`start_0rtt`]）：quinn `Connecting::into_0rtt`——无票返回
//!    `Err(connecting)`（原样还回继续普通握手）；有票返回 `(Connection, ZeroRttAccepted)`，early
//!    data 立即可发。
//!
//! # 降级保证（任务红线：不得因 0-RTT 失败而断连）
//!
//! - **无票**（首连 / 票过期）：`into_0rtt` 失败 → [`ZeroRttDial::FullHandshake`]， 调用方对还回的
//!   `Connecting` 普通 `await`，即 Go 无票 DialEarly 的行为。
//! - **被拒**（server 票密钥轮换 / server 禁 0-RTT）：server 以 1-RTT 完成握手， quinn 把已缓冲的
//!   early data 自动转 1-RTT 重发，[`quinn::ZeroRttAccepted`] 解析
//!   `false`——连接照常建立，数据不丢（quinn 官方 seamless fallback 语义）。
//!
//! # 重放风险（安全门槛，bd fgzb 明示）
//!
//! TLS 1.3 0-RTT 数据**无防重放保证**（协议设计如此）。xhttp transport 层无法判断
//! 请求幂等性（packet-up 是 POST 代理数据流），故由环境变量开关控制（见 splithttp
//! `h3_client`）：默认开启（对齐 Go DialEarly），`XRAY_H3_ZERO_RTT=0|false|off|no`
//! 禁用。重放后果：代理请求包重复投递（server 端 session seq 冲突报错），无资金 /
//! 副作用语义；若上游把本机制用于非幂等 API，必须先关开关。

use std::{
    collections::HashMap,
    sync::{Arc, LazyLock, Mutex},
};

use rustls::client::{ClientSessionMemoryCache, ClientSessionStore, Resumption};

/// 进程级共享 TLS 1.3 会话票缓存。
///
/// rustls 内部按 server name 索引，跨 `ClientConfig` 实例共享——同一 server 第二连
/// 起才有票可恢复。容量 256 servers（rustls 默认量级，实际上限 256×4 tickets/server）。
static SESSION_CACHE: LazyLock<Arc<ClientSessionMemoryCache>> =
    LazyLock::new(|| Arc::new(ClientSessionMemoryCache::new(256)));

/// 共享会话票存储（供诊断/测试判等两个 config 是否共享同一缓存）。
pub fn session_store() -> Arc<dyn ClientSessionStore> {
    SESSION_CACHE.clone()
}

/// 给客户端 rustls 配置挂共享会话票缓存并启用 0-RTT early data（0-RTT 两个前置
/// 条件，一体设置）。
///
/// ① 票缓存：rustls 默认每 `ClientConfig` 独立缓存，连接间不复用 → 0-RTT 永不
/// 命中；② `enable_early_data`：本仓 vendor rustls（watfaq patch）该字段默认
/// false——不设 true 则恢复会话不发 early_data 扩展、不产出 early secrets，
/// quinn `has_0rtt()` 恒 false。
///
/// 必须在 `QuicClientConfig::try_from` 之前调用（quinn 包装后 config 冻结）。
pub fn enable_client_session_resumption(tls: &mut rustls::ClientConfig) {
    tls.resumption = Resumption::store(session_store());
    tls.enable_early_data = true;
}

/// 缓存上限：超过后不再缓存新配置（新配置连接退化为普通 1-RTT，无正确性影响）。
const SHARED_CONFIG_CAP: usize = 64;

/// 进程级 H3 客户端 TLS 配置复用缓存（`domain` → 改造后的共享 `Arc<ClientConfig>`）。
static SHARED_CONFIGS: LazyLock<Mutex<HashMap<String, Arc<rustls::ClientConfig>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// 返回可跨连接复用的客户端配置（0-RTT 前置）。
///
/// `domain` 是**配置域标识**（调用方保证「同 domain 必是同一份 TLS 语义」——
/// splithttp H3 传 server_name：一个 server_name 在进程配置里只有一份
/// tlsSettings，且运行期配置不可变）。同一 domain 跨连接复用同一个
/// `Arc<rustls::ClientConfig>`——这是 rustls 会话恢复能命中的前提：票与**创建
/// 它的 verifier 实例身份**绑定（`Weak::ptr_eq`，`ServerData::compatible_config`），
/// 每次拨号新建 `ClientConfig` 则票的兼容性检查必失败。语义漂移（同 domain 换
/// 验证策略）在本机制下会复用旧策略——xray 客户端配置进程内不可变，不成立；
/// 若上游引入热重载，必须同步失效本缓存。
///
/// 首次见到某 domain 时改造入参（挂共享票缓存 + enable_early_data）并入缓存；
/// 缓存满（`SHARED_CONFIG_CAP`）时返回新建 Arc，该连接退化为普通 1-RTT。
pub fn shared_client_config(
    domain: &str,
    mut tls: rustls::ClientConfig,
) -> Arc<rustls::ClientConfig> {
    if let Ok(mut map) = SHARED_CONFIGS.lock() {
        if let Some(shared) = map.get(domain) {
            return shared.clone();
        }
        enable_client_session_resumption(&mut tls);
        let arc = Arc::new(tls);
        if map.len() < SHARED_CONFIG_CAP {
            map.insert(domain.to_string(), arc.clone());
        }
        return arc;
    }
    // 锁中毒：退化为无复用（本连接无 0-RTT，不断连）。
    enable_client_session_resumption(&mut tls);
    Arc::new(tls)
}

/// [`start_0rtt`] 的两种结果。
pub enum ZeroRttDial {
    /// 0-RTT 尝试已启动：连接立即可用（early data 可发）。
    /// [`quinn::ZeroRttAccepted`] 解析 `true` = server 接受；`false` = 被拒
    /// （quinn 已自动降级 1-RTT）。该 future 不 poll 也不影响连接工作。
    EarlyData(quinn::Connection, quinn::ZeroRttAccepted),
    /// 无票 / 不可 0-RTT——原 `Connecting` 原样还回，普通 `await` 即 1-RTT 握手。
    FullHandshake(quinn::Connecting),
}

/// 0-RTT 拨号入口（Go `tr.DialEarly` 对位）。
///
/// 无 early secrets（无票 / cipher 不匹配）时 [`quinn::Connecting::into_0rtt`]
/// 返回 `Err(self)`，此处折叠为 [`ZeroRttDial::FullHandshake`]。
pub fn start_0rtt(connecting: quinn::Connecting) -> ZeroRttDial {
    match connecting.into_0rtt() {
        Ok((conn, accepted)) => ZeroRttDial::EarlyData(conn, accepted),
        Err(connecting) => ZeroRttDial::FullHandshake(connecting),
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use super::{ZeroRttDial, session_store, start_0rtt};

    fn ensure_provider() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    /// 服务端 endpoint：xray_tls 自签证书 + stateful resumption + 0-RTT 配额。
    ///
    /// vendored rustls 只对 **stateful** resumption 允许 0-RTT（tls13.rs：
    /// `early_data with stateless resumption is not allowed`）。xray-tls
    /// `build_server_config` 默认装真 Ticketer（stateless 加密票，0-RTT 恒拒），
    /// 必须 `allowEarlyData=true` 让它保持 stateful（NeverProducesTickets +
    /// ServerSessionMemoryCache）。其配额写死 64KB，但 rustls client 对 QUIC 校验
    /// 票内配额只能 0 或 u32::MAX（`InvalidMaxEarlyDataSize`）——返回后覆盖为
    /// u32::MAX（vendored quinn-proto `QuicServerConfig` 同款值）。
    fn server_endpoint() -> quinn::Endpoint {
        let mut tls = xray_tls::server_config::build_server_config(
            "tls",
            Some(&serde_json::json!({ "allowEarlyData": true })),
        )
        .expect("server config")
        .expect("tls server config");
        Arc::get_mut(&mut tls)
            .expect("freshly built server config has no shared refs")
            .max_early_data_size = u32::MAX;
        let quic = quinn::crypto::rustls::QuicServerConfig::try_from((*tls).clone())
            .expect("QuicServerConfig");
        let cfg = quinn::ServerConfig::with_crypto(Arc::new(quic));
        quinn::Endpoint::server(cfg, "127.0.0.1:0".parse().unwrap()).expect("server bind")
    }

    /// 客户端 endpoint：allowInsecure（自签证书免验）+ 共享会话票缓存。
    ///
    /// `sni` 同时是 rustls ServerName 与 [`shared_client_config`] 的配置域标识——
    /// 每个测试用唯一 SNI，隔离进程级票缓存槽位与配置缓存条目（测试并行跑）。
    fn client_endpoint(sni: &str) -> quinn::Endpoint {
        let tls_arc = xray_tls::client_config::build_client_config(
            "tls",
            Some(&serde_json::json!({ "allowInsecure": true })),
            sni,
        )
        .expect("client config")
        .expect("tls client config");
        // 走共享缓存（票与 verifier 实例身份绑定——每次新建 ClientConfig 则
        // 第二连的票兼容性检查必失败，0-RTT 永不命中）。
        let tls = super::shared_client_config(
            sni,
            Arc::try_unwrap(tls_arc).unwrap_or_else(|a| (*a).clone()),
        );
        let quic =
            quinn::crypto::rustls::QuicClientConfig::try_from(tls).expect("QuicClientConfig");
        let mut cfg = quinn::ClientConfig::new(Arc::new(quic));
        // 1s idle timeout：泄漏连接快速回收，不让测试进程挂着 QUIC 状态。
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(quinn::IdleTimeout::from(quinn::VarInt::from_u32(1_000))));
        cfg.transport_config(Arc::new(transport));
        let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).expect("client bind");
        ep.set_default_client_config(cfg);
        ep
    }

    /// echo 回显 server：每连接循环 accept_bi，读到什么写回什么。
    fn spawn_echo_server(endpoint: quinn::Endpoint) {
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                tokio::spawn(async move {
                    let Ok(conn) = incoming.await else { return };
                    while let Ok((mut tx, mut rx)) = conn.accept_bi().await {
                        tokio::spawn(async move {
                            let mut buf = vec![0u8; 16 * 1024];
                            loop {
                                match rx.read(&mut buf).await {
                                    Ok(Some(n)) if n > 0 => {
                                        if tx.write_all(&buf[..n]).await.is_err() {
                                            break;
                                        }
                                    },
                                    _ => break,
                                }
                            }
                            let _ = tx.finish();
                        });
                    }
                });
            }
        });
    }

    /// 在既有连接上开 bi 流做一轮 echo，校验字节完整。
    async fn roundtrip_on(conn: &quinn::Connection, payload: &[u8]) {
        let (mut tx, mut rx) = conn.open_bi().await.expect("open_bi");
        tx.write_all(payload).await.expect("write");
        tx.finish().expect("finish");
        let mut echoed = vec![0u8; payload.len()];
        rx.read_exact(&mut echoed).await.expect("read echo");
        assert_eq!(echoed, payload);
    }

    /// 新连接 + echo 一轮（1-RTT 常规路径）。
    async fn roundtrip(
        ep: &quinn::Endpoint,
        addr: std::net::SocketAddr,
        sni: &str,
        payload: &[u8],
    ) {
        let conn = ep.connect(addr, sni).expect("connect").await.expect("handshake");
        roundtrip_on(&conn, payload).await;
    }

    /// 会话恢复命中 0-RTT：第二连 `ZeroRttAccepted == true`，且该连接数据完整收发。
    #[tokio::test]
    async fn resumed_session_hits_zero_rtt() {
        ensure_provider();
        let server = server_endpoint();
        let addr = server.local_addr().unwrap();
        spawn_echo_server(server);
        let ep = client_endpoint("zt-hits.test");

        // 连 1：无票 → start_0rtt 必落 FullHandshake（Go 无票 DialEarly 行为）。
        let connecting = ep.connect(addr, "zt-hits.test").unwrap();
        let conn1 = match start_0rtt(connecting) {
            ZeroRttDial::FullHandshake(connecting) => connecting.await.unwrap(),
            ZeroRttDial::EarlyData(..) => panic!("first connection must not have a ticket"),
        };
        roundtrip_on(&conn1, b"first").await;

        // NewSessionTicket 在握手后异步送达，等它落共享缓存（loopback <10ms，200ms 兜底；
        // 仍未到则逐次重试，票到达即成功——此处只等事件，不放宽断言）。
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mut tries = 0;
        let (conn2, accepted) = loop {
            tries += 1;
            match start_0rtt(ep.connect(addr, "zt-hits.test").unwrap()) {
                ZeroRttDial::EarlyData(conn, accepted) => break (conn, accepted),
                ZeroRttDial::FullHandshake(_) => {
                    assert!(tries < 20, "session ticket never became available for 0-RTT");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                },
            }
        };

        // quinn 权威观察点：只有 server 真收下 0-RTT 才解析 true。
        let hit = tokio::time::timeout(Duration::from_secs(5), accepted)
            .await
            .expect("0-RTT verdict within 5s");
        assert!(hit, "second connection must hit 0-RTT against ticket-issuing server");

        // 0-RTT 连接照常收发（early data 或降级后都不断连）。
        roundtrip_on(&conn2, b"second").await;
        ep.close(0u32.into(), b"test done");
    }

    /// 0-RTT 被拒降级：server 换实例（新随机票密钥）解不开旧票 → `ZeroRttAccepted
    /// == false`，quinn 自动把缓冲 early data 转 1-RTT，连接与数据照常（任务红线：
    /// 0-RTT 失败不得断连）。
    #[tokio::test]
    async fn rejected_zero_rtt_falls_back_to_1rtt() {
        ensure_provider();
        // server A：发票（连 1）。
        let server_a = server_endpoint();
        let addr_a = server_a.local_addr().unwrap();
        spawn_echo_server(server_a);
        let ep = client_endpoint("zt-rej.test");
        roundtrip(&ep, addr_a, "zt-rej.test", b"first").await;
        tokio::time::sleep(Duration::from_millis(200)).await;

        // server B：新实例 = 新 Ticketer 随机密钥，A 发的票在 B 处必解不开。
        let server_b = server_endpoint();
        let addr_b = server_b.local_addr().unwrap();
        spawn_echo_server(server_b);

        // 有票 → into_0rtt 成功；B 拒绝 → false。
        let (conn, accepted) = match start_0rtt(ep.connect(addr_b, "zt-rej.test").unwrap()) {
            ZeroRttDial::EarlyData(conn, accepted) => (conn, accepted),
            ZeroRttDial::FullHandshake(_) => {
                panic!("stale ticket must allow a 0-RTT attempt")
            },
        };
        let hit = tokio::time::timeout(Duration::from_secs(5), accepted)
            .await
            .expect("0-RTT verdict within 5s");
        assert!(!hit, "rotated ticket key must reject 0-RTT");

        // 降级后数据照常收发 = 降级成功。
        roundtrip_on(&conn, b"fallback").await;
        ep.close(0u32.into(), b"test done");
    }

    /// 共享缓存判等：两次 enable 落到同一 store（跨 ClientConfig 复用的前提）。
    #[test]
    fn session_store_is_process_wide() {
        let a = session_store();
        let b = session_store();
        assert!(Arc::ptr_eq(&a, &b), "session store must be a process-wide singleton");
    }
}
