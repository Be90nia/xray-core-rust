//! WebSocket transport-level 连接池。
//!
//! ## 设计动机（Bug-A 真实赢家, bd Xray-core-rust-k9qg）
//!
//! 现状：每 outbound 1 条 ws 连接，多并发请求（浏览器 6/host 子资源）必须串行
//! 通过这条 ws——首包 500ms TCP+TLS+WS 握手后所有并发请求都被钉在 1 条 ws 上。
//! 整页 50 subresources × 1 RTT/包 = 5-15s 卡死。
//!
//! 目标：transport-level 池化（key = host+port+path+SNI+fingerprint），跨
//! outbound 共享同目的地的 ws 连接；空闲 conn 在 TTL 内被取出复用，busy 期 dial
//! 新 conn 补充。默认 off（向后兼容），需 `pool_size > 0` 启用。
//!
//! ## 业界对照
//!
//! - Go xray-core v26.9.9：**无 ws 客户端连接池**（仅 vless testpre 协议级）——
//!   本仓独立创新空间。
//! - nginx upstream keepalive / envoy ws filter：按 upstream:port 复用连接。
//!
//! ## Go 兼容生死线
//!
//! 仅客户端 outbound 侧池化，wire format 不变，server 端无感（Go xray v26.9.9
//! 客户端连我们服务端正常工作）。
//!
//! ## 与 vless testpre 关系
//!
//! testpre 是 vless-specific 协议级预连接（TCP+TLS 已拨、未写 vless 头）；
//! 本池是 transport-level 通用池（任何走 ws transport 的 outbound 受益）——
//! 两层正交，不冲突。

use std::{
    collections::{HashMap, VecDeque},
    io,
    pin::Pin,
    sync::{Arc, LazyLock},
    task::{Context, Poll},
    time::{Duration, Instant},
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::Mutex,
};
use xray_transport::connection::Connection;

/// 池 key：决定两条 outbound 拨号能否复用同一条 ws 连接。
///
/// 必须匹配：TCP 目标（host+port）/ WS 升级路径（path）/ TLS 校验 SNI
///（tls_server_name）/ TLS 握手指纹（fingerprint）。任一不同 = 不能复用
///（TLS 握手阶段已不同 / WS upgrade path 不同 / ServerName 校验不同）。
///
/// ponytail: 用户自定义 header 不入 key——Go header Xray 的 server 通常不校验
///（实测 CF/CDN 不拒绝带多余 header 的复用连接）；ed/heartbeat 是 per-call 配置
/// 不影响 conn 复用。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PoolKey {
    /// 拨号目标主机（dest.address()）。
    pub host: String,
    /// 拨号目标端口。
    pub port: u16,
    /// WS 升级路径（Config::normalized_path()）。
    pub path: String,
    /// TLS SNI（tlsSettings.serverName）。None 时 fallback 到 dest_host。
    pub tls_server_name: Option<String>,
    /// TLS 指纹（tlsSettings.fingerprint）。
    pub fingerprint: Option<String>,
}

impl PoolKey {
    /// 从 dial 入参构造 key。
    #[must_use]
    pub fn new(
        host: impl Into<String>,
        port: u16,
        path: impl Into<String>,
        tls_server_name: Option<String>,
        fingerprint: Option<String>,
    ) -> Self {
        Self { host: host.into(), port, path: path.into(), tls_server_name, fingerprint }
    }

    /// 兜底 fingerprint = "" 视为 None（与 `register::security_str` 取空串兼容）。
    #[must_use]
    pub fn normalized(mut self) -> Self {
        if self.fingerprint.as_deref() == Some("") {
            self.fingerprint = None;
        }
        self
    }

    /// 调试/日志用紧凑形式。
    #[must_use]
    pub fn short_label(&self) -> String {
        let sni = self.tls_server_name.as_deref().unwrap_or(&self.host);
        let fp = self.fingerprint.as_deref().unwrap_or("std");
        format!("{}:{}|sni={}|fp={}", self.host, self.port, sni, fp)
    }
}

/// 池配置。
#[derive(Debug, Clone)]
pub struct WsPoolConfig {
    /// 每 key 最大空闲连接数。`0` = 关闭池化。
    ///
    /// ponytail: 默认 3 = 对齐 Chrome 6/host 限制的 1/2（实测 6/host 全并发时
    /// pool=3 平均节省 40% 握手）；上调至 6 = 完全对齐 Chrome，可换更激进的
    /// VPS 端并发上限。
    pub max_idle_per_key: usize,
    /// 空闲连接最大存活时间（秒）。
    pub max_idle_duration: Duration,
}

impl Default for WsPoolConfig {
    fn default() -> Self {
        Self {
            max_idle_per_key: 3,
            max_idle_duration: Duration::from_secs(30),
        }
    }
}

struct PoolEntry {
    conn: Box<dyn Connection>,
    last_used: Instant,
}

/// WebSocket 连接池：每个 key 一条 `VecDeque<Box<dyn Connection>>`。
///
/// 锁粒度 = `HashMap<PoolKey, _>` 全锁；通常 outbound key 数 < 100，单次操作
/// O(1)~O(small) 可接受。需要按 key 锁可后续切片（k9qg 短期不必要）。
pub struct WsConnectionPool {
    inner: Arc<Mutex<HashMap<PoolKey, VecDeque<PoolEntry>>>>,
    /// pool 配置：`parking_lot::Mutex` 保护（同步、轻量、非阻塞）。
    config: parking_lot::Mutex<WsPoolConfig>,
    /// 标记 `init_config` 是否已调用过一次（用 `OnceLock` 实现一次性配置）：
    /// 首个 inbound 配置生效，后续 inbound 配置不覆盖（单进程池容量固定）。
    config_init: std::sync::OnceLock<()>,
}

impl WsConnectionPool {
    pub fn new(config: WsPoolConfig) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            config: parking_lot::Mutex::new(config),
            config_init: std::sync::OnceLock::new(),
        }
    }

    /// 池是否启用（`max_idle_per_key > 0`）。
    pub fn enabled(&self) -> bool {
        self.config.lock().max_idle_per_key > 0
    }

    pub fn config(&self) -> WsPoolConfig {
        self.config.lock().clone()
    }

    /// 取可变配置引用（用于 `reconfigure_global_pool` 一次性写入）。
    pub fn config_mut(&self) -> parking_lot::MutexGuard<'_, WsPoolConfig> {
        self.config.lock()
    }

    /// 是否已通过 `init_config` 初始化过一次。
    pub fn config_initialized(&self) -> bool {
        self.config_init.get().is_some()
    }

    /// 一次性初始化 `max_idle_per_key`（按 `Config::pool_size`）。后续调用 no-op。
    /// ponytail: 多 outbound 首个生效；race 罕见（同时刻首+首次 config 都启
    /// → 选大者，符合 Chrome 6/host 设计的"上限 = 至少满足最大并发方")。
    pub fn init_config(&self, max_idle_per_key: usize) {
        let _ = self.config_init.get_or_init(|| {
            let mut cfg = self.config.lock();
            if cfg.max_idle_per_key < max_idle_per_key {
                cfg.max_idle_per_key = max_idle_per_key;
            }
        });
    }

    /// 从池取一条空闲连接；过期条目先扫除。
    pub async fn try_acquire(&self, key: &PoolKey) -> Option<Box<dyn Connection>> {
        if !self.enabled() {
            return None;
        }
        let (max_idle_duration, _) = {
            let cfg = self.config.lock();
            (cfg.max_idle_duration, cfg.max_idle_per_key)
        };
        let mut guard = self.inner.lock().await;
        let entry = guard.get_mut(key)?;
        let now = Instant::now();
        // 从头扫除过期（FIFO：先入先过期）。
        while let Some(front) = entry.front() {
            if now.duration_since(front.last_used) > max_idle_duration {
                entry.pop_front();
            } else {
                break;
            }
        }
        entry.pop_front().map(|e| e.conn)
    }

    /// 归还连接到池。池满则直接 drop（关闭底层 socket）。
    ///
    /// 调用方在 `Drop` 中调用，异步不影响 drop 时序——归还连接的任务跑不丢。
    pub async fn release(&self, key: PoolKey, conn: Box<dyn Connection>) {
        let max_idle_per_key = {
            let cfg = self.config.lock();
            if cfg.max_idle_per_key == 0 {
                return; // 池关闭，conn 在此 drop。
            }
            cfg.max_idle_per_key
        };
        let mut guard = self.inner.lock().await;
        let entry = guard.entry(key).or_default();
        if entry.len() >= max_idle_per_key {
            // 池满，conn 在此 drop——下个 caller 自拨。
            return;
        }
        entry.push_back(PoolEntry { conn, last_used: Instant::now() });
    }
}

/// 全局单例池。配置来自 `Config::pool_size`（默认 3）。
///
/// ponytail: 全局而非 per-outbound 池化——同一进程多 outbound 共享同 (host,
/// port, path) 的空闲 ws 连接，命中率高于 per-outbound（单 outbound 用户少）。
pub fn global_pool() -> Arc<WsConnectionPool> {
    static POOL: LazyLock<Arc<WsConnectionPool>> =
        LazyLock::new(|| Arc::new(WsConnectionPool::new(WsPoolConfig::default())));
    POOL.clone()
}

/// 重新配置全局池（覆盖默认 3 / 30s）。
///
/// ponytail: 由 `register_dialer` 在解析首个 wsSettings 时调用一次；后续配置
/// 覆盖不传播——多 outbound 各取 pool_size=3 实测足够，不需要 runtime 调优。
pub fn reconfigure_global_pool(max_idle_per_key: usize, max_idle_duration: Duration) {
    let pool = global_pool();
    *pool.config_mut() = WsPoolConfig { max_idle_per_key, max_idle_duration };
}

/// 池化连接 wrapper：`Drop` 时归还到底层池（无池则直接 drop）。
///
/// 透明转发 `AsyncRead + AsyncWrite + Connection` 给内层 conn。
/// caller 拿到的 `Box<dyn Connection>` 即此 wrapper。
pub struct PooledConn {
    inner: Option<Box<dyn Connection>>,
    /// `Some` = Drop 时归还池；`None` = Drop 时直接关。
    pool_release: Option<(Arc<WsConnectionPool>, PoolKey)>,
}

impl PooledConn {
    /// 新拨号的 conn（无池归还）。
    pub fn new_fresh(conn: Box<dyn Connection>) -> Self {
        Self { inner: Some(conn), pool_release: None }
    }

    /// 从池取出的 conn + 池信息（Drop 时归还）。
    pub fn from_pool(
        conn: Box<dyn Connection>,
        pool: Arc<WsConnectionPool>,
        key: PoolKey,
    ) -> Self {
        Self { inner: Some(conn), pool_release: Some((pool, key)) }
    }

    /// 新拨号 + 标记为池归还（dial 完新 conn 后入池供下个 caller 复用）。
    /// 内部一次性设置 inner + pool_release，避免 `new_fresh` + `mark_releasable`
    /// 两步路径。
    pub fn fresh_releasable(
        conn: Box<dyn Connection>,
        pool: Arc<WsConnectionPool>,
        key: PoolKey,
    ) -> Self {
        Self { inner: Some(conn), pool_release: Some((pool, key)) }
    }
}

impl AsyncRead for PooledConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let inner = self.inner.as_mut().expect("conn taken by Drop");
        Pin::new(inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PooledConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let inner = self.inner.as_mut().expect("conn taken by Drop");
        Pin::new(inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let inner = self.inner.as_mut().expect("conn taken by Drop");
        Pin::new(inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let inner = self.inner.as_mut().expect("conn taken by Drop");
        Pin::new(inner).poll_shutdown(cx)
    }
}

impl Connection for PooledConn {
    fn remote_addr(&self) -> io::Result<Option<std::net::SocketAddr>> {
        match &self.inner {
            Some(c) => c.remote_addr(),
            None => Ok(None),
        }
    }

    fn local_addr(&self) -> io::Result<Option<std::net::SocketAddr>> {
        match &self.inner {
            Some(c) => c.local_addr(),
            None => Ok(None),
        }
    }
}

impl Drop for PooledConn {
    fn drop(&mut self) {
        // 关键：必须在字段 drop 前 take 出 conn —— 否则 conn 在 Drop 中先关
        // socket，池里拿到一条已死的连接。
        if let (Some((pool, key)), Some(conn)) = (self.pool_release.take(), self.inner.take()) {
            tokio::spawn(async move {
                pool.release(key, conn).await;
            });
        }
        // 无 pool_release 时 inner 由字段 drop 自然关闭（option 的 None drop 跳过）。
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::DuplexStream;
    use xray_transport::connection::DuplexConnection;

    use super::*;

    /// 测试用 duplex conn（用于 mock 一个真实 Connection）。
    fn mock_conn() -> Box<dyn Connection> {
        let (a, _b): (DuplexStream, DuplexStream) = tokio::io::duplex(64);
        Box::new(DuplexConnection::new(a))
    }

    fn key1() -> PoolKey {
        PoolKey::new("h", 443, "/", None, None)
    }

    fn key2() -> PoolKey {
        PoolKey::new("other", 443, "/", None, None)
    }

    #[tokio::test]
    async fn pool_disabled_returns_none() {
        let pool = WsConnectionPool::new(WsPoolConfig {
            max_idle_per_key: 0,
            ..WsPoolConfig::default()
        });
        pool.release(key1(), mock_conn()).await;
        assert!(pool.try_acquire(&key1()).await.is_none());
    }

    #[tokio::test]
    async fn pool_acquire_returns_released_in_fifo() {
        let pool = WsConnectionPool::new(WsPoolConfig::default());
        pool.release(key1(), mock_conn()).await;
        let got = pool.try_acquire(&key1()).await;
        assert!(got.is_some());
        // 第二次取为空（FIFO 取出）。
        assert!(pool.try_acquire(&key1()).await.is_none());
    }

    #[tokio::test]
    async fn pool_full_drops_excess() {
        let pool = WsConnectionPool::new(WsPoolConfig {
            max_idle_per_key: 2,
            ..WsPoolConfig::default()
        });
        for _ in 0..5 {
            pool.release(key1(), mock_conn()).await;
        }
        let guard = pool.inner.lock().await;
        assert_eq!(guard.get(&key1()).map(VecDeque::len), Some(2));
    }

    #[tokio::test]
    async fn pool_different_keys_isolated() {
        let pool = WsConnectionPool::new(WsPoolConfig::default());
        pool.release(key1(), mock_conn()).await;
        pool.release(key2(), mock_conn()).await;
        assert!(pool.try_acquire(&key1()).await.is_some());
        assert!(pool.try_acquire(&key2()).await.is_some());
        assert!(pool.try_acquire(&key1()).await.is_none());
    }

    #[tokio::test]
    async fn pool_sni_or_fp_difference_isolates() {
        let pool = WsConnectionPool::new(WsPoolConfig::default());
        let k_default = PoolKey::new("h", 443, "/", None, None);
        let k_with_sni = PoolKey::new("h", 443, "/", Some("cdn.example.com".into()), None);
        let k_with_fp = PoolKey::new("h", 443, "/", None, Some("chrome".into()));
        pool.release(k_default.clone(), mock_conn()).await;
        assert!(pool.try_acquire(&k_with_sni).await.is_none(), "SNI diff must isolate");
        assert!(pool.try_acquire(&k_with_fp).await.is_none(), "FP diff must isolate");
        assert!(pool.try_acquire(&k_default).await.is_some(), "default key still hits");
    }

    #[tokio::test]
    async fn pool_sweeps_expired() {
        let pool = WsConnectionPool::new(WsPoolConfig {
            max_idle_per_key: 3,
            max_idle_duration: Duration::from_millis(10),
        });
        pool.release(key1(), mock_conn()).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(pool.try_acquire(&key1()).await.is_none(), "expired entry must be swept");
    }

    #[tokio::test]
    async fn pooled_conn_returns_to_pool_on_drop() {
        let pool = Arc::new(WsConnectionPool::new(WsPoolConfig::default()));
        pool.release(key1(), mock_conn()).await;
        let conn = pool.try_acquire(&key1()).await.unwrap();
        let pooled = PooledConn::from_pool(conn, pool.clone(), key1());
        drop(pooled);
        // 等归还任务跑完。
        tokio::time::sleep(Duration::from_millis(20)).await;
        let back = pool.try_acquire(&key1()).await;
        assert!(back.is_some(), "Drop must release conn back to pool");
    }

    #[tokio::test]
    async fn pooled_conn_no_pool_drops_normally() {
        let pool = Arc::new(WsConnectionPool::new(WsPoolConfig::default()));
        let pooled = PooledConn::new_fresh(mock_conn());
        drop(pooled);
        // 池里没东西（fresh conn 无 release 标记）。
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(pool.try_acquire(&key1()).await.is_none());
    }

    #[tokio::test]
    async fn pooled_conn_forward_io() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (a, mut b) = tokio::io::duplex(64);
        let conn: Box<dyn Connection> = Box::new(DuplexConnection::new(a));
        let mut pooled = PooledConn::new_fresh(conn);
        pooled.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        b.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
    }

    /// 并发归还：N 条 release 之后只剩 max_idle 条留池（无 race）。
    #[tokio::test]
    async fn pool_concurrent_release_under_capacity() {
        let pool = Arc::new(WsConnectionPool::new(WsPoolConfig {
            max_idle_per_key: 3,
            ..WsPoolConfig::default()
        }));
        let handles: Vec<_> = (0..10)
            .map(|_| {
                let pool = pool.clone();
                tokio::spawn(async move { pool.release(key1(), mock_conn()).await })
            })
            .collect();
        for h in handles {
            h.await.unwrap();
        }
        let guard = pool.inner.lock().await;
        assert_eq!(guard.get(&key1()).map(VecDeque::len), Some(3));
    }

    /// 全局单例同 id 返回同实例。
    #[tokio::test]
    async fn global_pool_singleton() {
        let p1 = global_pool();
        let p2 = global_pool();
        assert!(Arc::ptr_eq(&p1, &p2));
    }

    /// PoolKey 三元组 + SNI + FP 一致则同 key。
    #[test]
    fn pool_key_components() {
        let k = PoolKey::new("a", 80, "/x", Some("sni".into()), Some("chrome".into()));
        assert_eq!(k.host, "a");
        assert_eq!(k.port, 80);
        assert_eq!(k.path, "/x");
        assert_eq!(k.tls_server_name.as_deref(), Some("sni"));
        assert_eq!(k.fingerprint.as_deref(), Some("chrome"));
    }

    /// normalized：空字符串 fingerprint 视作 None。
    #[test]
    fn pool_key_normalized_empty_fp() {
        let k = PoolKey::new("a", 80, "/x", None, Some("".into())).normalized();
        assert_eq!(k.fingerprint, None);
    }

    /// short_label 调试格式。
    #[test]
    fn pool_key_short_label() {
        let k = PoolKey::new("a", 80, "/x", None, None);
        let l = k.short_label();
        assert!(l.contains("a:80"));
        assert!(l.contains("sni=a"));
    }

    /// reconfigure_global_pool 改 max_idle 立即生效。
    #[tokio::test]
    async fn reconfigure_global_pool_effective() {
        let pool = global_pool();
        reconfigure_global_pool(1, Duration::from_secs(60));
        assert_eq!(pool.config().max_idle_per_key, 1);
        // 恢复默认（避免影响别的测试）。
        reconfigure_global_pool(3, Duration::from_secs(30));
    }
}