//! Quinn 连接池 — 复用 QUIC 连接、自动重连、多路复用。
//!
//! 核心设计：
//! - 连接池 key = (server_addr, server_name, alpn) — 同一目标同一 TLS 参数共用连接
//! - 每个 [`PooledConnection`] 包装 [`quinn::Connection`] + 引用计数 + 状态标记
//! - 连接断开时自动重建（指数退避，最大 5 次）
//! - 多 stream 复用：一个 QUIC 连接上开多个 bi/uni stream
//! - UDP native 模式：通过 [`quinn::Connection::send_datagram`] / [`recv_datagram`] 传输
//!
//! ## 线程安全
//!
//! 池表用 `parking_lot::RwLock`（临界区零 await，bd 4zjf）；per-key 拨号锁用
//! [`tokio::sync::Mutex`]（single-flight，跨 await 持有）。
//!
//! ## 生命周期
//!
//! - 池内连接：强引用计数归零时从池中移除
//! - 池本身：[`Arc`] 持有，drop 时关闭所有连接

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{Mutex, RwLock};
use tokio::time::sleep;

use crate::error::{Result, TuicError};

/// 拨号超时兜底（对齐 dispatcher 拨号 30s；connector 自带超时时无感）。
const DIAL_TIMEOUT: Duration = Duration::from_secs(30);

/// 连接池 key — 同一目标同一 TLS 参数共用连接。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PoolKey {
    /// 服务端地址。
    pub server_addr: SocketAddr,
    /// SNI / server name。
    pub server_name: String,
    /// ALPN 协议列表（排序后拼接，用于 key）。
    pub alpn_tag: String,
}

impl PoolKey {
    /// 从参数构造 key。
    pub fn new(server_addr: SocketAddr, server_name: &str, alpn: &[Vec<u8>]) -> Self {
        let mut alpn_parts: Vec<String> = alpn
            .iter()
            .map(|p| String::from_utf8_lossy(p).into_owned())
            .collect();
        alpn_parts.sort_unstable();
        Self {
            server_addr,
            server_name: server_name.to_string(),
            alpn_tag: alpn_parts.join(","),
        }
    }
}

/// 池内连接项 — 包装 quinn 连接 + 元数据。
///
/// 字段公开以便 [`TuicClient`] 直接访问底层连接。
#[derive(Clone)]
pub struct PooledConnection {
    /// 底层 quinn 连接。
    pub conn: quinn::Connection,
    /// 创建时间（用于老化判断）。
    pub created_at: Instant,
    /// 连接是否已关闭（外部标记，不依赖 quinn 内部状态）。
    pub is_closed: Arc<RwLock<bool>>,
}










impl PooledConnection {
    /// 检查连接是否仍活跃。
    pub async fn is_alive(&self) -> bool {
        !*self.is_closed.read().await && self.conn.close_reason().is_none()
    }

    /// 标记连接已关闭。
    pub async fn mark_closed(&self) {
        let mut closed = self.is_closed.write().await;
        *closed = true;
    }
}

/// Quinn 连接池 — 全局复用 QUIC 连接。
///
/// 用法：
/// ```ignore
/// let pool = QuinnConnectionPool::new();
/// let key = PoolKey::new(addr, "example.com", &[b"h3".to_vec(), b"tuic".to_vec()]);
/// let pooled = pool.get_or_connect(key, || async { /* 新建连接 */ }).await?;
/// let (send, recv) = pooled.conn.open_bi().await?;
/// ```
#[derive(Clone)]
pub struct QuinnConnectionPool {
    /// 池表：parking_lot 读写锁，临界区零 await（bd 4zjf：alive 检查的
    /// await 必须在锁外，防 pool-wide stall）。
    inner: Arc<parking_lot::RwLock<HashMap<PoolKey, PooledConnection>>>,
    /// per-key 拨号锁（single-flight）：同 key 并发 get_or_connect 只有一个
    /// leader 真正拨号，其余在锁上排队，拿到锁后 double-check 池直接复用，
    /// 消除 N-1 条孤儿连接（票 5poj）。
    dial_locks: Arc<Mutex<HashMap<PoolKey, Arc<Mutex<()>>>>>,
}

impl QuinnConnectionPool {
    /// 创建空连接池。
    pub fn new() -> Self {
        Self {
            inner: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            dial_locks: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// 获取或创建连接。
    ///
    /// 流程：
    /// 1. 先读锁查池中是否已有活跃连接
    /// 2. 无则调用 `connector` 新建连接（写锁插入）
    /// 3. 返回 [`PooledConnection`]
    ///
    /// `connector` 签名：`async fn() -> Result<quinn::Connection>`
    pub async fn get_or_connect<F, Fut>(
        &self,
        key: PoolKey,
        connector: F,
    ) -> Result<PooledConnection>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<quinn::Connection>>,
    {
        self.get_or_connect_dial_timeout(key, connector, DIAL_TIMEOUT)
            .await
    }

    /// [`Self::get_or_connect`] 带可配置拨号超时（测试用小超时）。
    ///
    /// single-flight 语义：同 key 并发请求串行进入拨号临界区，非首个
    /// 到达者在临界区内 double-check 池命中已拨好的连接直接复用。
    pub(crate) async fn get_or_connect_dial_timeout<F, Fut>(
        &self,
        key: PoolKey,
        connector: F,
        dial_timeout: std::time::Duration,
    ) -> Result<PooledConnection>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<quinn::Connection>>,
    {
        // 快速路径：池中已有活跃连接。读锁内只 clone，is_alive 的 await 在
        // 锁外——bd 4zjf：alive 检查不得持池锁跨 await（pool-wide stall）。
        let cached = {
            let pool = self.inner.read();
            pool.get(&key).cloned()
        };
        if let Some(entry) = cached {
            if entry.is_alive().await {
                return Ok(entry);
            }
        }

        // 取/建 per-key 拨号锁（锁获取顺序恒为 dial_locks → key lock → inner）。
        let key_lock = {
            let mut locks = self.dial_locks.lock().await;
            locks.entry(key.clone()).or_default().clone()
        };
        let _guard = key_lock.lock().await;

        // double-check：leader 拨号期间同 key 连接可能已入池（锁外 await，同上）
        let cached = {
            let pool = self.inner.read();
            pool.get(&key).cloned()
        };
        if let Some(entry) = cached {
            if entry.is_alive().await {
                return Ok(entry);
            }
        }

        // 慢速路径：新建连接（兜底超时——connector 本身无时限时防无限挂起）
        let conn = tokio::time::timeout(dial_timeout, connector())
            .await
            .map_err(|_| {
                TuicError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "tuic pool dial timeout",
                ))
            })??;
        let pooled = PooledConnection {
            conn,
            created_at: Instant::now(),
            is_closed: Arc::new(RwLock::new(false)),
        };

        self.inner.write().insert(key, pooled.clone());
        Ok(pooled)
    }

    /// 移除指定 key 的连接（通常由重连逻辑调用）。
    pub fn remove(&self, key: &PoolKey) {
        self.inner.write().remove(key);
    }

    /// 关闭池中所有连接并清空。
    pub fn clear(&self) {
        for (_, entry) in self.inner.write().drain() {
            entry.conn.close(0u32.into(), b"pool cleared");
        }
    }

    /// 获取池中连接数（调试用）。
    pub fn len(&self) -> usize {
        self.inner.read().len()
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

}

impl Default for QuinnConnectionPool {
    fn default() -> Self {
        Self::new()
    }
}

/// 自动重连包装 — 连接断开时指数退避重建。
///
/// 最大重试 5 次，初始间隔 1s，倍增上限 30s。
pub struct ReconnectingConnection {
    pool: QuinnConnectionPool,
    key: PoolKey,
    max_retries: usize,
    base_delay: Duration,
    max_delay: Duration,
}

impl ReconnectingConnection {
    /// 构造重连包装。
    pub fn new(pool: QuinnConnectionPool, key: PoolKey) -> Self {
        Self {
            pool,
            key,
            max_retries: 5,
            base_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(30),
        }
    }

    /// 获取活跃连接，失败时自动重连。
    ///
    /// `connector` 每次重试都会调用。
    pub async fn get_or_reconnect<F, Fut>(
        &self,
        connector: F,
    ) -> Result<PooledConnection>
    where
        F: Fn() -> Fut + Clone,
        Fut: Future<Output = Result<quinn::Connection>>,
    {
        let mut last_err = None;
        for attempt in 0..=self.max_retries {
            match self
                .pool
                .get_or_connect(self.key.clone(), connector.clone())
                .await
            {
                Ok(pooled) => {
                    if pooled.is_alive().await {
                        return Ok(pooled);
                    }
                    // 池中连接已死，移除后重试
                    self.pool.remove(&self.key);
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }

            if attempt < self.max_retries {
                let delay = self
                    .base_delay
                    .mul_f64(2f64.powi(attempt as i32))
                    .min(self.max_delay);
                sleep(delay).await;
            }
        }

        Err(last_err.unwrap_or_else(|| {
            TuicError::Io(std::io::Error::other(
                "reconnect exhausted: all attempts failed",
            ))
        }))
    }
}

/// 多路复用 stream 管理 — 一个 QUIC 连接上维护多个 bi-stream。
///
/// ponytail: 不维护复杂 stream 池，quinn 内部已做流控；
/// 这里只提供便捷方法：open_bi / open_uni / send_datagram / recv_datagram。
#[derive(Clone)]
pub struct MultiplexedConnection {
    /// 内部池连接（公开以便 [`TuicClient`] 访问）。
    pub pooled: PooledConnection,
}








impl MultiplexedConnection {
    /// 从 [`PooledConnection`] 构造。
    pub fn new(pooled: PooledConnection) -> Self {
        Self { pooled }
    }

    /// 打开 bidirectional stream。
    pub async fn open_bi(&self) -> Result<(quinn::SendStream, quinn::RecvStream)> {
        self.pooled
            .conn
            .open_bi()
            .await
            .map_err(TuicError::Quinn)
    }

    /// 打开 unidirectional stream。
    pub async fn open_uni(&self) -> Result<quinn::SendStream> {
        self.pooled
            .conn
            .open_uni()
            .await
            .map_err(TuicError::Quinn)
    }

    /// 发送 QUIC DATAGRAM（native UDP 模式）。
    pub fn send_datagram(&self, data: bytes::Bytes) -> Result<()> {
        self.pooled
            .conn
            .send_datagram(data)
            .map_err(TuicError::QuinnSendDatagram)
    }







    /// 接收 QUIC DATAGRAM（native UDP 模式）。
    pub async fn recv_datagram(&self) -> Result<bytes::Bytes> {
        self.pooled
            .conn
            .read_datagram()
            .await
            .map_err(TuicError::Quinn)
    }








    /// 关闭连接。
    pub fn close(&self, error_code: quinn::VarInt, reason: &[u8]) {
        self.pooled.conn.close(error_code, reason);
    }

    /// 检查连接是否活跃。
    pub async fn is_alive(&self) -> bool {
        self.pooled.is_alive().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn pool_key_hashable() {
        let key1 = PoolKey::new(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 443)),
            "example.com",
            &[b"h3".to_vec()],
        );
        let key2 = PoolKey::new(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 443)),
            "example.com",
            &[b"h3".to_vec()],
        );
        let key3 = PoolKey::new(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 443)),
            "example.com",
            &[b"tuic".to_vec()],
        );
        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    #[test]
    fn pool_key_alpn_order_independent() {
        let key1 = PoolKey::new(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 443)),
            "example.com",
            &[b"h3".to_vec(), b"tuic".to_vec()],
        );
        let key2 = PoolKey::new(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 443)),
            "example.com",
            &[b"tuic".to_vec(), b"h3".to_vec()],
        );
        assert_eq!(key1, key2);
    }

    #[test]
    fn pool_new_is_empty() {
        let pool = QuinnConnectionPool::new();
        assert!(pool.is_empty());
        assert_eq!(pool.len(), 0);
    }
    /// bd 4zjf：快速路径 is_alive().await 阻塞期间，池内元操作不得被
    /// inner 锁饿死（lock-across-await → pool-wide stall）。
    #[tokio::test]
    async fn concurrent_get_or_connect_does_not_stall_on_alive_check() {
        use crate::client::TuicClient;
        use crate::server::TuicMockServer;

        fn make_pool_client_config(cert_der: &[u8]) -> std::sync::Arc<rustls::ClientConfig> {
            let mut roots = rustls::RootCertStore::empty();
            roots.add(cert_der.to_vec().into()).expect("add cert");
            Arc::new(
                rustls::ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            )
        }

        let uuid = uuid::Uuid::new_v4();
        let (server, cert_der) = TuicMockServer::bind(
            "127.0.0.1:0".parse().expect("parse addr"),
            "localhost",
            uuid,
            "pw".to_string(),
        )
        .await
        .expect("mock server bind");
        let server_addr = server.local_addr();
        let _server_task = tokio::spawn(async move {
            let _ = server.run().await;
        });

        // 入池：key 与 TuicClient::connect_with 一致（测试 config 无 ALPN → tag 空）
        let pool = QuinnConnectionPool::new();
        let _client = TuicClient::connect(
            server_addr,
            "localhost",
            uuid,
            "pw",
            make_pool_client_config(&cert_der),
            pool.clone(),
        )
        .await
        .expect("connect");
        let key = PoolKey::new(server_addr, "localhost", &[]);

        // 取池内连接的 is_closed 锁句柄（Arc 同源）。
        let pooled = pool
            .get_or_connect(key.clone(), || async {
                Err(TuicError::Io(std::io::Error::other(
                    "fast path expected: connector must not run",
                )))
            })
            .await
            .expect("fast path hit");

        // W：持写锁冻结 is_alive() 的读获取。
        let w_lock = pooled.is_closed.clone();
        let (frozen_tx, frozen_rx) = tokio::sync::oneshot::channel::<()>();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let _w = w_lock.write().await;
            let _ = frozen_tx.send(());
            let _ = release_rx.await;
        });
        frozen_rx.await.expect("W froze is_closed");

        // A：快速路径 is_alive().await 阻塞在 is_closed 读锁上。
        let pool_a = pool.clone();
        let key_a = key.clone();
        let task_a = tokio::spawn(async move {
            pool_a
                .get_or_connect(key_a, || async {
                    Err(TuicError::Io(std::io::Error::other(
                        "fast path expected: connector must not run",
                    )))
                })
                .await
        });
        tokio::time::sleep(Duration::from_millis(200)).await;

        // B：池元操作（len）在 A 的 alive 检查阻塞期间必须可用——修复后
        // len 同步且池锁临界区零 await，in-flight await 不可能再卡住它。
        assert_eq!(
            pool.len(),
            1,
            "pool metadata must stay available while an alive-check is in flight (bd 4zjf)"
        );

        release_tx.send(()).expect("release W");
        let r = tokio::time::timeout(Duration::from_secs(5), task_a)
            .await
            .expect("A must finish after release")
            .expect("join A")
            .expect("fast path returns alive entry");
        assert_eq!(pool.len(), 1);
    }
}
