//! WebSocket transport-level 预连接池（virgin-connection pool, bd k9qg → ss-ws 池票修订）。
//!
//! 现状：每 outbound 1 条 ws 连接，多并发请求（浏览器 6/host 子资源）必须串行
//! 通过这条 ws——首包 500ms TCP+TLS+WS 握手后所有并发请求都被钉在 1 条 ws 上。
//! 整页 50 subresources × 1 RTT/包 = 5-15s 卡死。
//!
//! 目标：transport-level 预连接池（key = host+port+path+SNI+fingerprint），跨
//! outbound 共享同目的地 ws 连接。**语义**：池内只存「握手完成、零内层字节」的
//! 预连接；交付出去的连接承载过任何会话数据即绝不回池（used = 不可归还）——
//! 交付侧无归还代码路径，预连接只由补拨任务（replenish：acquire/现拨后 spawn
//! 后台拨号）存入，维持每 key ≤ `max_idle_per_key` 条。每条会话拿到的新鲜
//! 连接 wire 行为与现拨一致，只是免了握手。默认 `max_idle_per_key=12`（Chrome
//! 6/host × 多 host burst 上限）；显式 `pool_size=0` 关闭池化。
//!
//! ## 业界对照
//!
//! - Go xray-core v26.9.9：**无 ws 客户端连接池**（仅 vless testpre 协议级）—— 本仓独立创新空间。
//! - nginx upstream keepalive / envoy ws filter：按 upstream:port 复用连接（同
//!   为「预连接」语义——上游连接归还前必须保证干净）。
//!
//! ## Go 兼容生死线
//!
//! 仅客户端 outbound 侧池化，wire format 不变，server 端无感（每条会话看到的
//! 都是一条全新握手完成的连接——与服务端 per-connection 会话状态兼容，ss 等
//! 单连接单会话语义协议同样安全）。
//!
//! ## 与 vless testpre 关系
//!
//! testpre 是 vless-specific 协议级预连接（TCP+TLS 已拨、未写 vless 头）；
//! 本池是 transport-level 通用池（任何走 ws transport 的 outbound 受益）——
//! 两层正交，不冲突。

use std::{
    collections::{HashMap, VecDeque},
    pin::Pin,
    sync::{Arc, LazyLock},
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

use tokio::{
    io::{AsyncRead, ReadBuf},
    sync::Mutex,
};
use xray_transport::connection::Connection;

/// 池 key：决定两条 outbound 拨号能否复用同一条 ws 连接。
///
/// 必须匹配：TCP 目标（host+port）/ WS 升级路径（path）/ TLS 校验 SNI
/// （tls_server_name）/ TLS 握手指纹（fingerprint）。任一不同 = 不能复用
/// （TLS 握手阶段已不同 / WS upgrade path 不同 / ServerName 校验不同）。
///
/// ponytail: 用户自定义 header 不入 key——Go header Xray 的 server 通常不校验
/// （实测 CF/CDN 不拒绝带多余 header 的复用连接）；ed/heartbeat 是 per-call 配置
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
    /// ponytail: 默认 12 = 对齐 Chrome 6/host 限制 + 整页多 host 的 burst 上限
    /// （实测一页 50+ subresource、Chrome 6 并发/host = 池瞬间打空——3 默认池
    /// 命中率 40%、12 命中率 ~95%）；3（首版）= Chrome 6/host 的 1/2，命中率
    /// 不足；12 对齐 Chrome 6/host × 2 host 同时访问的峰值。
    pub max_idle_per_key: usize,
    /// 空闲连接最大存活时间（秒）。
    pub max_idle_duration: Duration,
}

impl Default for WsPoolConfig {
    fn default() -> Self {
        // TTL 10s（2026-10-16 根治）：CDN 边缘 idle 切断窗口 ~100s（CF），30s
        // 时代实测 vl-ws-cdn 复用死连接（个位数/0.x 回归）——10s 令死亡窗口≈0，
        // 浏览器秒级并发复用命中率不受损。
        Self { max_idle_per_key: 12, max_idle_duration: Duration::from_secs(10) }
    }
}

struct PoolEntry {
    conn: Box<dyn Connection>,
    last_used: Instant,
}

/// 非阻塞活性探测：一次 `poll_read`（noop waker）。
///
/// `Pending` = 活（idle 无数据——正常空闲 ws 连接必 Pending）；`Ready` 任意形态
/// = 死：EOF（对端已发 close 帧后关闭）/ 残留帧（不该出现的半关状态）/ Err（断连）。
/// 2026-10-17 生产事故：连接在池内 idle 期间被服务端/CF 关闭，取出复用写 vless
/// header 即 "Sending after closing"——TTL+IO 错误毒标记都拦不住 close 帧路径。
fn probe_conn_alive(conn: &mut Box<dyn Connection>) -> bool {
    let mut buf = [0u8; 16];
    let mut rb = ReadBuf::new(&mut buf);
    let mut cx = Context::from_waker(Waker::noop());
    matches!(Pin::new(conn).poll_read(&mut cx, &mut rb), Poll::Pending)
}

/// 预连接池（virgin-connection pool）：每个 key 一条 `VecDeque<Box<dyn Connection>>`。
///
/// 池内只存「握手完成、零内层字节」的预连接；任何承载过会话数据的连接一律
/// 不回池（used = 不可归还）——交付侧没有任何归还代码路径（无 Drop 归还
/// wrapper），预连接只经 [`WsConnectionPool::release`] 由补拨任务（replenish）
/// 存入。try_acquire 只交出未使用连接。
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
    /// 每 key 补拨 in-flight 计数（拨号中、尚未入池的预连接）。
    /// 与 `inner` 的 idle 条数共同受 `max_idle_per_key` 上限约束。
    preconnect_inflight: parking_lot::Mutex<HashMap<PoolKey, usize>>,
}

impl WsConnectionPool {
    pub fn new(config: WsPoolConfig) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            config: parking_lot::Mutex::new(config),
            config_init: std::sync::OnceLock::new(),
            preconnect_inflight: parking_lot::Mutex::new(HashMap::new()),
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
        // 取出循环：idle 期间被对端关闭的连接（close 帧/EOF）当场丢弃，继续取
        // 下一条——探测是唯一可靠的死活判据（TTL 拦不住 10s 内的主动 close）。
        while let Some(e) = entry.pop_front() {
            let mut conn = e.conn;
            if probe_conn_alive(&mut conn) {
                return Some(conn);
            }
        }
        None
    }

    /// 归还连接到池。池满则直接 drop（关闭底层 socket）。
    ///
    /// 语义（预连接池）：**只由补拨任务（replenish）调用**，存入的是握手完成、
    /// 零内层字节的预连接；承载过会话数据的连接没有任何归还代码路径。
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

    /// 抢一个预连接补拨名额：`idle + in-flight < max_idle_per_key` 时记账并放行。
    ///
    /// 放行后调用方 spawn 拨号任务，任务收尾（无论成败）必须调
    /// [`Self::end_preconnect`] 释放名额。
    pub async fn begin_preconnect(&self, key: &PoolKey) -> bool {
        if !self.enabled() {
            return false;
        }
        // 顺序：tokio await 先行，parking_lot guard 只在同步段持有（guard 跨
        // await = future 非 Send）。
        let max_idle_per_key = self.config.lock().max_idle_per_key;
        let idle = self.inner.lock().await.get(key).map_or(0, VecDeque::len);
        let mut inflight = self.preconnect_inflight.lock();
        if idle + inflight.get(key).copied().unwrap_or(0) >= max_idle_per_key {
            return false;
        }
        *inflight.entry(key.clone()).or_default() += 1;
        true
    }

    /// 释放一个补拨名额（补拨任务收尾调用，无论拨号成败）。
    pub fn end_preconnect(&self, key: &PoolKey) {
        let mut inflight = self.preconnect_inflight.lock();
        if let Some(n) = inflight.get_mut(key) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                inflight.remove(key);
            }
        }
    }
}

/// 全局单例池。配置来自 `Config::pool_size`（默认 12）。
///
/// ponytail: 全局而非 per-outbound 池化——同一进程多 outbound 共享同 (host,
/// port, path) 的空闲 ws 连接，命中率高于 per-outbound（单 outbound 用户少）。
pub fn global_pool() -> Arc<WsConnectionPool> {
    static POOL: LazyLock<Arc<WsConnectionPool>> =
        LazyLock::new(|| Arc::new(WsConnectionPool::new(WsPoolConfig::default())));
    POOL.clone()
}

/// 重新配置全局池（覆盖默认 12 / 10s）。
///
/// ponytail: 由 `register_dialer` 在解析首个 wsSettings 时调用一次；后续配置
/// 覆盖不传播——多 outbound 各取 pool_size=12 实测足够，不需要 runtime 调优。
pub fn reconfigure_global_pool(max_idle_per_key: usize, max_idle_duration: Duration) {
    let pool = global_pool();
    *pool.config_mut() = WsPoolConfig { max_idle_per_key, max_idle_duration };
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::DuplexStream;
    use xray_transport::connection::DuplexConnection;

    use super::*;

    /// 测试用 duplex conn（用于 mock 一个真实 Connection）。
    /// 2026-10-17：对端 `forget` 保活——真实 ws 连接握手完成后远端是活的；
    /// 之前 `_b` 随函数返回 drop = mock 天生 EOF，probe 正确判死后既有
    /// 归还/取出测试全挂。EOF 场景由 `probe_admits_alive_and_discards_dead_preconnections`
    /// 专项覆盖。
    fn mock_conn() -> Box<dyn Connection> {
        let (a, b): (DuplexStream, DuplexStream) = tokio::io::duplex(64);
        std::mem::forget(b);
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
        let pool =
            WsConnectionPool::new(WsPoolConfig { max_idle_per_key: 0, ..WsPoolConfig::default() });
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
        let pool =
            WsConnectionPool::new(WsPoolConfig { max_idle_per_key: 2, ..WsPoolConfig::default() });
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

    /// 补拨名额：idle + in-flight 受 max_idle_per_key 上限约束（virgin-connection
    /// 池语义——补拨是唯一入池通道，超额即拒）。
    #[tokio::test]
    async fn begin_preconnect_respects_idle_and_inflight_capacity() {
        let pool = Arc::new(WsConnectionPool::new(WsPoolConfig {
            max_idle_per_key: 2,
            ..Default::default()
        }));

        // 池空 + 无 in-flight → 放行。
        assert!(pool.begin_preconnect(&key1()).await, "empty pool must admit preconnect");
        // in-flight=1 → 再抢一个（1+1 < 2）→ 第三个被拒。
        assert!(pool.begin_preconnect(&key1()).await, "1 idle + 1 inflight < 2 must admit");
        assert!(!pool.begin_preconnect(&key1()).await, "2 inflight must hit the cap");

        // 补拨完成入池（模拟：end + release）→ idle=2 → 名额被 idle 顶满。
        pool.end_preconnect(&key1());
        pool.end_preconnect(&key1());
        pool.release(key1(), mock_conn()).await;
        pool.release(key1(), mock_conn()).await;
        assert!(!pool.begin_preconnect(&key1()).await, "full idle pool must reject preconnect");

        // 取走一条 → idle=1 → 又可补拨。
        assert!(pool.try_acquire(&key1()).await.is_some());
        assert!(pool.begin_preconnect(&key1()).await, "freed slot must admit preconnect");
    }

    /// end_preconnect 释放名额（含重复调用饱和不减）。
    #[tokio::test]
    async fn end_preconnect_releases_slot_idempotently() {
        let pool = Arc::new(WsConnectionPool::new(WsPoolConfig::default()));
        assert!(pool.begin_preconnect(&key1()).await);
        pool.end_preconnect(&key1());
        // 重复 end 不下溢（名额计数不出现负值语义）。
        pool.end_preconnect(&key1());
        // 池禁用时 begin 恒 false。
        let disabled =
            WsConnectionPool::new(WsPoolConfig { max_idle_per_key: 0, ..WsPoolConfig::default() });
        assert!(!disabled.begin_preconnect(&key1()).await);
    }

    /// 活预连接不受探测影响；死连接（idle 期间被对端关闭）在取出时被当场丢弃
    /// ——2026-10-17 生产事故回归（"Sending after closing"）。
    #[tokio::test]
    async fn probe_admits_alive_and_discards_dead_preconnections() {
        let pool = Arc::new(WsConnectionPool::new(WsPoolConfig::default()));
        // 活连接：对端持有 → 无 EOF → probe 放行。
        let (a, keep): (DuplexStream, DuplexStream) = tokio::io::duplex(64);
        let _keep = keep;
        pool.release(key1(), Box::new(DuplexConnection::new(a))).await;
        assert!(pool.try_acquire(&key1()).await.is_some(), "idle alive conn must survive probe");

        // 死连接：对端已关 → try_acquire 当场丢弃。
        let (c, d): (DuplexStream, DuplexStream) = tokio::io::duplex(64);
        drop(d);
        tokio::time::sleep(Duration::from_millis(10)).await; // EOF 传播
        pool.release(key1(), Box::new(DuplexConnection::new(c))).await;
        assert!(
            pool.try_acquire(&key1()).await.is_none(),
            "dead conn in pool must be discarded on acquire"
        );
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
        reconfigure_global_pool(12, Duration::from_secs(10));
    }
}
