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
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::Mutex;
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
    ///
    /// AtomicBool（wfx8-2）：is_alive/mark_closed 同步化，消除 tokio 异步
    /// 锁面——4zjf 类「alive 检查持锁跨 await」的结构性宿主随之消失。
    pub is_closed: Arc<AtomicBool>,
}

impl PooledConnection {
    /// 检查连接是否仍活跃。
    pub fn is_alive(&self) -> bool {
        !self.is_closed.load(Ordering::Acquire) && self.conn.close_reason().is_none()
    }

    /// 标记连接已关闭。
    pub fn mark_closed(&self) {
        self.is_closed.store(true, Ordering::Release);
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
        // 快速路径：池中已有活跃连接。读锁内只 clone，alive 检查在锁外——
        // bd 4zjf：池锁临界区零 await（is_closed 已是 AtomicBool，检查无 await）。
        let cached = {
            let pool = self.inner.read();
            pool.get(&key).cloned()
        };
        if let Some(entry) = cached {
            if entry.is_alive() {
                return Ok(entry);
            }
        }

        // 取/建 per-key 拨号锁（锁获取顺序恒为 dial_locks → key lock → inner）。
        let key_lock = {
            let mut locks = self.dial_locks.lock().await;
            locks.entry(key.clone()).or_default().clone()
        };
        let _guard = key_lock.lock().await;

        // double-check：leader 拨号期间同 key 连接可能已入池（锁外，同上）
        let cached = {
            let pool = self.inner.read();
            pool.get(&key).cloned()
        };
        if let Some(entry) = cached {
            if entry.is_alive() {
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
            is_closed: Arc::new(AtomicBool::new(false)),
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
                    if pooled.is_alive() {
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
    pub fn is_alive(&self) -> bool {
        self.pooled.is_alive()
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

    // bd 4zjf 回归测试 concurrent_get_or_connect_does_not_stall_on_alive_check
    // 已随 wfx8-2 删除：其前提是 is_closed 为 tokio RwLock（冻结写锁即可卡死
    // alive 检查）。is_closed 改 AtomicBool 后 alive 检查无锁无 await，该
    // stall 场景结构性不存在，测试不再守卫任何可失败路径。
}
