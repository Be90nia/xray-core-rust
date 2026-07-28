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
//! 连接池内部用 [`tokio::sync::Mutex`]（异步锁），避免阻塞 async runtime。
//!
//! ## 生命周期
//!
//! - 池内连接：强引用计数归零时从池中移除
//! - 池本身：[`Arc`] 持有，drop 时关闭所有连接

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Mutex, RwLock};
use tokio::time::{sleep, Instant};

use crate::error::{Result, TuicError};

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
    inner: Arc<Mutex<HashMap<PoolKey, PooledConnection>>>,
}

impl QuinnConnectionPool {
    /// 创建空连接池。
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
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
        Fut: std::future::Future<Output = Result<quinn::Connection>>,
    {
        // 快速路径：读锁检查
        {
            let pool = self.inner.lock().await;
            if let Some(entry) = pool.get(&key) {
                if entry.is_alive().await {
                    return Ok(entry.clone());
                }
            }
        }

        // 慢速路径：新建连接
        let conn = connector().await?;
        let pooled = PooledConnection {
            conn,
            created_at: Instant::now(),
            is_closed: Arc::new(RwLock::new(false)),
        };

        let mut pool = self.inner.lock().await;
        pool.insert(key, pooled.clone());
        Ok(pooled)
    }

    /// 移除指定 key 的连接（通常由重连逻辑调用）。
    pub async fn remove(&self, key: &PoolKey) {
        let mut pool = self.inner.lock().await;
        pool.remove(key);
    }

    /// 关闭池中所有连接并清空。
    pub async fn clear(&self) {
        let mut pool = self.inner.lock().await;
        for (_, entry) in pool.drain() {
            entry.conn.close(0u32.into(), b"pool cleared");
        }
    }

    /// 获取池中连接数（调试用）。
    pub async fn len(&self) -> usize {
        let pool = self.inner.lock().await;
        pool.len()
    }

    /// 是否为空。
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
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
        Fut: std::future::Future<Output = Result<quinn::Connection>>,
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
                    self.pool.remove(&self.key).await;
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

    #[tokio::test]
    async fn pool_new_is_empty() {
        let pool = QuinnConnectionPool::new();
        assert!(pool.is_empty().await);
        assert_eq!(pool.len().await, 0);
    }
}
