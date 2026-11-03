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
//! 连接 wire 行为与现拨一致，只是免了握手。**缺省开池**（`Config::default()`
//! 的 `pool_size: 12` 经 `init_config` 传入；`WsPoolConfig::default()` 自身仍是
//! `max_idle_per_key=0`）。bd s8eio 复议：缺省 0 关池实测经 CF 的 ws 节点慢 33%；
//! 显式 `wsSettings.poolSize: 0` 关池（严格对齐 Go 无池）。启用后每 key ≤ `max_idle_per_key`
//! 条（Chrome 6/host × 多 host burst 上限 = 12 的调参值仍作为文档化建议保留）。
//!
//! ## 业界对照
//!
//! - Go xray-core v26.10.17：**无 ws 客户端连接池**（`websocket/dialer.go` 每次 Dial 现拨；全仓仅
//!   `common/bytespool` 内存池与 fakedns LRU，与本机制无关）。 故本池默认关 = 基准行为；开启属 Rust
//!   独有优化（服务端可见连接数会随池深上升）。
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
    /// finalmask TCP 伪装（bd dppv）：mask 在 dial 内层（TLS/WS 握手前）套上，
    /// 入池连接已含 mask——masked/unmasked 出站指向同一 dest 时不得互取池货。
    pub mask: bool,
}

impl PoolKey {
    /// 从 dial 入参构造 key（无 finalmask）。
    #[must_use]
    pub fn new(
        host: impl Into<String>,
        port: u16,
        path: impl Into<String>,
        tls_server_name: Option<String>,
        fingerprint: Option<String>,
    ) -> Self {
        Self {
            host: host.into(),
            port,
            path: path.into(),
            tls_server_name,
            fingerprint,
            mask: false,
        }
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
    /// 本类型 `default()` 为 0，但上层 `Config::default()` 用 12 经
    /// `init_config` 传入 → **实际缺省开池**（bd s8eio 复议）。显式
    /// `wsSettings.poolSize: 0` 关池（严格对齐 Go 无池；预连接是只握手不传数据
    /// 的额外服务端连接）。调参参考：Chrome 6/host × 多 host burst（实测一页
    /// 50+ subresource）下 12 命中率 ~95%（3 → ~40%）。
    pub max_idle_per_key: usize,
    /// 空闲连接最大存活时间（秒）。
    pub max_idle_duration: Duration,
}

impl Default for WsPoolConfig {
    fn default() -> Self {
        // TTL 10s（2026-10-16 根治）：CDN 边缘 idle 切断窗口 ~100s（CF），30s
        // 时代实测 vl-ws-cdn 复用死连接（个位数/0.x 回归）——10s 令死亡窗口≈0，
        // 浏览器秒级并发复用命中率不受损。
        //
        // bd s8eio：默认关池（0 = 不预连接，对齐 Go 无池）。
        Self { max_idle_per_key: 0, max_idle_duration: Duration::from_secs(10) }
    }
}

struct PoolEntry {
    conn: Box<dyn Connection>,
    last_used: Instant,
}

/// 池内统计快照（诊断面）。
///
/// `keys` 含**空 key**——空 key 是泄漏信号（条目被摘光后 key 未随之摘除）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolStats {
    /// 当前 key 数。
    pub keys: usize,
    /// 当前空闲连接条目数。
    pub entries: usize,
}

/// 扫除周期 = TTL/4，钳在 `[100ms, 30s]`。
///
/// TTL 极小也要能及时回收（否则测试/短 TTL 场景回收滞后一个 TTL）；TTL 极大时
/// 无需频繁扫（扫本身是 O(key 数) 的锁内遍历）。
fn sweep_interval(max_idle_duration: Duration) -> Duration {
    (max_idle_duration / 4).clamp(Duration::from_millis(100), Duration::from_secs(30))
}

/// 扫除过期条目并摘除**空 key**（FIFO：先入先过期）。返回被摘除的条目数。
///
/// 与 `try_acquire` 的惰性扫除同一判据（`now - last_used > max_idle_duration`）——
/// 后台任务只是把「按 key 惰性扫」扩成「周期全量扫」，不改变复用窗口。
fn sweep_expired(
    map: &mut HashMap<PoolKey, VecDeque<PoolEntry>>,
    max_idle_duration: Duration,
    now: Instant,
) -> usize {
    let mut removed = 0usize;
    map.retain(|_, entry| {
        while let Some(front) = entry.front() {
            if now.duration_since(front.last_used) > max_idle_duration {
                entry.pop_front();
                removed += 1;
            } else {
                break;
            }
        }
        // 空 key 一并摘除（修前：条目被扫光后 key 永久留在表里）。
        !entry.is_empty()
    });
    removed
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
    ///
    /// `Arc` 化：后台扫除任务要读 TTL（TTL 可被 `reconfigure_global_pool` 改），
    /// 用 `Weak` 持配置句柄——池 drop 后任务自动退出，不延长池寿命。
    config: Arc<parking_lot::Mutex<WsPoolConfig>>,
    /// 标记 `init_config` 是否已调用过一次（用 `OnceLock` 实现一次性配置）：
    /// 首个 inbound 配置生效，后续 inbound 配置不覆盖（单进程池容量固定）。
    config_init: std::sync::OnceLock<()>,
    /// 每 key 补拨 in-flight 计数（拨号中、尚未入池的预连接）。
    /// 与 `inner` 的 idle 条数共同受 `max_idle_per_key` 上限约束。
    preconnect_inflight: parking_lot::Mutex<HashMap<PoolKey, usize>>,
    /// 后台扫除任务只启动一次（`OnceLock` 幂等闸）。
    sweeper_started: std::sync::OnceLock<()>,
}

impl WsConnectionPool {
    pub fn new(config: WsPoolConfig) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            config: Arc::new(parking_lot::Mutex::new(config)),
            config_init: std::sync::OnceLock::new(),
            preconnect_inflight: parking_lot::Mutex::new(HashMap::new()),
            sweeper_started: std::sync::OnceLock::new(),
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

    /// 池内统计快照（诊断面）。
    ///
    /// key 数含**空 key**——空 key 是泄漏信号（条目被摘光后 key 未随之摘除）。
    pub async fn stats(&self) -> PoolStats {
        let guard = self.inner.lock().await;
        PoolStats { keys: guard.len(), entries: guard.values().map(VecDeque::len).sum() }
    }

    /// 启动后台扫除任务（幂等：整进程每池一次）。
    ///
    /// 修前只有 `try_acquire(同一 key)` 会扫过期条目（bd il9lh MW-4）——**长期不再
    /// 访问的 key，其空闲条目与 key 本身永不释放**（每 key 至多 `max_idle_per_key`
    /// 条 socket 常驻）。本任务给出真正的回收路径：周期性扫**全部** key，摘除
    /// 过期条目并连带摘除空 key。
    ///
    /// 持 `Weak`（inner + config）：池 drop 后 `upgrade` 失败 → 任务自行退出，
    /// 不延长池寿命、不留孤儿任务。
    fn ensure_sweeper(&self) {
        self.sweeper_started.get_or_init(|| {
            let Ok(handle) = tokio::runtime::Handle::try_current() else {
                // 无 runtime 上下文（同步调用方）：不启任务，惰性扫除路径仍在。
                return;
            };
            let inner = Arc::downgrade(&self.inner);
            let config = Arc::downgrade(&self.config);
            handle.spawn(async move {
                loop {
                    let interval = {
                        let Some(cfg) = config.upgrade() else { return };
                        let ttl = cfg.lock().max_idle_duration;
                        sweep_interval(ttl)
                    };
                    tokio::time::sleep(interval).await;
                    let (Some(inner), Some(cfg)) = (inner.upgrade(), config.upgrade()) else {
                        return;
                    };
                    let ttl = cfg.lock().max_idle_duration;
                    let mut map = inner.lock().await;
                    #[allow(
                        clippy::disallowed_methods,
                        reason = "连接池 idle 过期扫描墙钟取时；Clock 端口注入待 bd 39hko"
                    )]
                    let now = Instant::now();
                    sweep_expired(&mut map, ttl, now);
                }
            });
        });
    }

    /// 是否已通过 `init_config` 初始化过一次。
    pub fn config_initialized(&self) -> bool {
        self.config_init.get().is_some()
    }

    /// 一次性初始化 `max_idle_per_key`（按 `Config::pool_size`）。后续调用 no-op。
    pub fn init_config(&self, max_idle_per_key: usize) {
        // ponytail: 一次性（首个 wsSettings 生效）——多 outbound 的不同 poolSize
        // 不合并、不重配；要按 outbound 独立容量需把池从全局改成 per-outbound
        // 句柄（届时 `config_init` 一并删）。
        let _ = self.config_init.get_or_init(|| {
            self.config.lock().max_idle_per_key = max_idle_per_key;
        });
    }

    /// 从池取一条空闲连接；过期条目先扫除。
    pub async fn try_acquire(&self, key: &PoolKey) -> Option<Box<dyn Connection>> {
        if !self.enabled() {
            return None;
        }
        self.ensure_sweeper();
        let (max_idle_duration, _) = {
            let cfg = self.config.lock();
            (cfg.max_idle_duration, cfg.max_idle_per_key)
        };
        let mut guard = self.inner.lock().await;
        #[allow(
            clippy::disallowed_methods,
            reason = "连接池 idle 过期扫描墙钟取时；Clock 端口注入待 bd 39hko"
        )]
        let now = Instant::now();
        // 从头扫除过期（FIFO：先入先过期）。
        {
            let entry = guard.get_mut(key)?;
            while let Some(front) = entry.front() {
                if now.duration_since(front.last_used) > max_idle_duration {
                    entry.pop_front();
                } else {
                    break;
                }
            }
        }
        // 条目被扫光 → key 变空 → 一并摘除（修前：空 key 永久留在表里）。
        if guard.get(key).is_some_and(VecDeque::is_empty) {
            guard.remove(key);
            return None;
        }
        // 取出循环：idle 期间被对端关闭的连接（close 帧/EOF）当场丢弃，继续取
        // 下一条——探测是唯一可靠的死活判据（TTL 拦不住 10s 内的主动 close）。
        loop {
            let popped = {
                let Some(entry) = guard.get_mut(key) else { break };
                entry.pop_front()
            };
            let Some(e) = popped else { break };
            let mut conn = e.conn;
            if probe_conn_alive(&mut conn) {
                // 取走了最后一条 → key 变空 → 一并摘除（空 key 不留）。
                if guard.get(key).is_some_and(VecDeque::is_empty) {
                    guard.remove(key);
                }
                return Some(conn);
            }
        }
        // 取空后 key 变空 → 摘除。
        if guard.get(key).is_some_and(VecDeque::is_empty) {
            guard.remove(key);
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
        self.ensure_sweeper();
        let mut guard = self.inner.lock().await;
        #[allow(
            clippy::disallowed_methods,
            reason = "连接池 entry last_used 锚点；Clock 端口注入待 bd 39hko"
        )]
        let last_used = Instant::now();
        // 容量判定先于建条目：池满时**不建空 key**（修前 `entry().or_default()`
        // 先建 key 再判满，多出永不回收的空条目）。
        {
            let Some(entry) = guard.get_mut(&key) else {
                let mut fresh = VecDeque::new();
                fresh.push_back(PoolEntry { conn, last_used });
                guard.insert(key, fresh);
                return;
            };
            if entry.len() >= max_idle_per_key {
                // 池满，conn 在此 drop——下个 caller 自拨。
                return;
            }
            entry.push_back(PoolEntry { conn, last_used });
        }
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

/// 全局单例池。初始配置 = [`WsPoolConfig::default`]（**关池**，bd s8eio）；
/// 首个 `poolSize>0` 的 wsSettings 经 [`WsConnectionPool::init_config`] 打开。
///
/// ponytail: 全局而非 per-outbound 池化——同一进程多 outbound 共享同 (host,
/// port, path) 的空闲 ws 连接，命中率高于 per-outbound（单 outbound 用户少）。
pub fn global_pool() -> Arc<WsConnectionPool> {
    static POOL: LazyLock<Arc<WsConnectionPool>> =
        LazyLock::new(|| Arc::new(WsConnectionPool::new(WsPoolConfig::default())));
    POOL.clone()
}

/// 重新配置全局池（测试/显式开关用；`max_idle_per_key=0` 即关池）。
///
/// ponytail: 生产拨号路径不走本函数（走 `init_config` 一次性生效）；此处的
/// 覆盖会绕开一次性闸门，仅测试与运维手动开关使用。
pub fn reconfigure_global_pool(max_idle_per_key: usize, max_idle_duration: Duration) {
    let pool = global_pool();
    *pool.config_mut() = WsPoolConfig { max_idle_per_key, max_idle_duration };
}

#[cfg(test)]
mod tests {
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    use tokio::io::{AsyncReadExt, DuplexStream};
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

    /// 机制测试用的启用态配置：12 条上限（**默认已关池**，bd s8eio——池测试必须
    /// 显式开启才测得到补拨/取还语义）。
    fn pool_cfg_12() -> WsPoolConfig {
        WsPoolConfig { max_idle_per_key: 12, ..WsPoolConfig::default() }
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
        let pool = WsConnectionPool::new(pool_cfg_12());
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
        let pool = WsConnectionPool::new(pool_cfg_12());
        pool.release(key1(), mock_conn()).await;
        pool.release(key2(), mock_conn()).await;
        assert!(pool.try_acquire(&key1()).await.is_some());
        assert!(pool.try_acquire(&key2()).await.is_some());
        assert!(pool.try_acquire(&key1()).await.is_none());
    }

    #[tokio::test]
    async fn pool_sni_or_fp_difference_isolates() {
        let pool = WsConnectionPool::new(pool_cfg_12());
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

    /// bd il9lh MW-4：**不访问任何 key** 时 idle 条目也必须被回收——修前唯一的回收
    /// 路径是 `try_acquire(同一 key)`，长期不用的 key 的空闲连接与 key 永不释放。
    ///
    /// 断言两件事：① 池内条目/键归零；② **socket 级**——条目被 drop ⇒ 对端读到
    /// EOF（连接真被关闭，不是只删了计数）。
    #[tokio::test]
    async fn idle_entries_reclaimed_without_any_access() {
        let pool = WsConnectionPool::new(WsPoolConfig {
            max_idle_per_key: 3,
            max_idle_duration: Duration::from_millis(200),
        });
        let (a, mut peer_a) = tokio::io::duplex(64);
        let (b, mut peer_b) = tokio::io::duplex(64);
        pool.release(key1(), Box::new(DuplexConnection::new(a))).await;
        pool.release(key2(), Box::new(DuplexConnection::new(b))).await;
        assert_eq!(pool.stats().await.entries, 2, "two idle entries must be pooled");

        // 全程不调用 try_acquire：只等 TTL + 扫除周期。
        tokio::time::sleep(Duration::from_millis(600)).await;

        let stats = pool.stats().await;
        assert_eq!(stats.entries, 0, "idle entries must be reclaimed without access");
        assert_eq!(stats.keys, 0, "emptied keys must be removed too");

        let mut buf = [0u8; 1];
        assert_eq!(peer_a.read(&mut buf).await.unwrap_or(0), 0, "peer must see EOF");
        assert_eq!(peer_b.read(&mut buf).await.unwrap_or(0), 0, "peer must see EOF");
    }

    /// 空 key 不摘（修前）：条目被取光后 key 仍留在表里（每访问过的 key 累积一条
    /// 空条目，永不回收）。
    #[tokio::test]
    async fn key_removed_when_last_entry_taken() {
        let pool = WsConnectionPool::new(pool_cfg_12());
        pool.release(key1(), mock_conn()).await;
        assert_eq!(pool.stats().await.keys, 1);
        assert!(pool.try_acquire(&key1()).await.is_some());
        assert_eq!(pool.stats().await.keys, 0, "emptied key must be removed from the map");
    }

    /// 复用率不下降（后台扫除不得误伤未过期的条目）：TTL 内的 release→acquire
    /// 循环必须 100% 命中。
    #[tokio::test]
    async fn reuse_within_ttl_keeps_hit_rate() {
        let pool = WsConnectionPool::new(WsPoolConfig {
            max_idle_per_key: 4,
            max_idle_duration: Duration::from_millis(500),
        });
        let mut hits = 0usize;
        for _ in 0..20 {
            pool.release(key1(), mock_conn()).await;
            if pool.try_acquire(&key1()).await.is_some() {
                hits += 1;
            }
        }
        assert_eq!(hits, 20, "reuse within TTL must stay 100%");
    }

    /// 扫除任务已跑过（周期 250ms）但条目未过 TTL（1s）→ 条目必须存活（不得把
    /// 回收做成「更激进」而拉低复用率）。
    #[tokio::test]
    async fn sweeper_keeps_entries_within_ttl() {
        let pool = WsConnectionPool::new(WsPoolConfig {
            max_idle_per_key: 2,
            max_idle_duration: Duration::from_secs(1),
        });
        pool.release(key1(), mock_conn()).await;
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(pool.stats().await.entries, 1, "entry within TTL must survive the sweeper");
        assert!(pool.try_acquire(&key1()).await.is_some(), "entry must still be reusable");
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
        let pool = Arc::new(WsConnectionPool::new(pool_cfg_12()));
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
        let pool = Arc::new(WsConnectionPool::new(pool_cfg_12()));
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
        #[allow(clippy::disallowed_methods, reason = "测试：并发 release 任务")]
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

    /// 并发取池 miss 计数 = dial_ws 冷拨次数：register.rs 取池未命中即走
    /// `dial_with_params` 现拨（TCP+TLS+ws 握手），命中即交付——1:1 映射。
    async fn concurrent_take_misses(pool: Arc<WsConnectionPool>, key: PoolKey, n: usize) -> usize {
        let hits = Arc::new(AtomicUsize::new(0));
        #[allow(clippy::disallowed_methods, reason = "测试：并发 take 任务")]
        let handles: Vec<_> = (0..n)
            .map(|_| {
                let (pool, hits, key) = (pool.clone(), hits.clone(), key.clone());
                tokio::spawn(async move {
                    if pool.try_acquire(&key).await.is_some() {
                        hits.fetch_add(1, Ordering::SeqCst);
                    }
                })
            })
            .collect();
        for h in handles {
            h.await.unwrap();
        }
        n - hits.load(Ordering::SeqCst)
    }

    async fn prefill(pool: &WsConnectionPool, key: &PoolKey, n: usize) {
        for _ in 0..n {
            pool.release(key.clone(), mock_conn()).await;
        }
    }

    /// 修前形态快照（bd lmjw 根因链）：容量 3（k9qg 首版默认）撑不住页面
    /// burst——12 并发取同 key 有 9 路冷拨（9 次 TCP+TLS+ws 握手），即
    /// 「页面十几资源 → 池空 → 回退冷拨号」。若有人把默认容量改回 3 本测试即红。
    #[tokio::test]
    async fn burst_12_capacity_3_stock_cold_dials_nine() {
        let pool = Arc::new(WsConnectionPool::new(WsPoolConfig {
            max_idle_per_key: 3,
            ..WsPoolConfig::default()
        }));
        prefill(&pool, &key1(), 3).await;
        assert_eq!(concurrent_take_misses(pool, key1(), 12).await, 9);
    }

    /// 修后形态（bd lmjw B1，容量 12）：整页 burst（Chrome 6/host，整页 ≤12）
    /// 全部命中库存，0 冷拨。
    #[tokio::test]
    async fn burst_12_full_stock_never_cold_dials() {
        let pool = Arc::new(WsConnectionPool::new(pool_cfg_12()));
        prefill(&pool, &key1(), 12).await;
        assert_eq!(concurrent_take_misses(pool, key1(), 12).await, 0);
    }

    /// 票面验收（bd lmjw）：单页 15 连接场景握手 ≤3——12 库存吸收后仅 ≤3 路现拨。
    #[tokio::test]
    async fn burst_15_handshakes_within_ticket_budget() {
        let pool = Arc::new(WsConnectionPool::new(pool_cfg_12()));
        prefill(&pool, &key1(), 12).await;
        let misses = concurrent_take_misses(pool, key1(), 15).await;
        assert!(misses <= 3, "15-conn page must cold-dial ≤3, got {misses}");
    }

    /// 池空行为不回归：冷启动（首用/TTL 过期后）池空，12 并发全冷拨是物理必然
    /// （库存不存在则无从命中）；随后补拨按 spawn_replenish 的 begin→end→release
    /// 序补满库存，下一波 12 并发全命中——冷拨回退路径本身不受容量策略影响。
    #[tokio::test]
    async fn empty_pool_cold_start_then_replenish_refills_next_wave() {
        let pool = Arc::new(WsConnectionPool::new(pool_cfg_12()));
        assert_eq!(concurrent_take_misses(pool.clone(), key1(), 12).await, 12);
        for _ in 0..12 {
            assert!(pool.begin_preconnect(&key1()).await);
            pool.end_preconnect(&key1());
            pool.release(key1(), mock_conn()).await;
        }
        assert_eq!(concurrent_take_misses(pool, key1(), 12).await, 0);
    }

    /// 并发补拨闸门：16 路补拨并发抢名额，放行总数恒 = 容量（idle+inflight
    /// ≤ max_idle_per_key 不变量在并发下不被击穿），入池恰好 12 条不超额。
    #[tokio::test]
    async fn concurrent_replenish_gate_admits_exactly_capacity() {
        let pool = Arc::new(WsConnectionPool::new(pool_cfg_12()));
        let admitted = Arc::new(AtomicUsize::new(0));
        #[allow(clippy::disallowed_methods, reason = "测试：并发 replenish 任务")]
        let handles: Vec<_> = (0..16)
            .map(|_| {
                let (pool, admitted) = (pool.clone(), admitted.clone());
                tokio::spawn(async move {
                    if pool.begin_preconnect(&key1()).await {
                        admitted.fetch_add(1, Ordering::SeqCst);
                        pool.end_preconnect(&key1());
                        pool.release(key1(), mock_conn()).await;
                    }
                })
            })
            .collect();
        for h in handles {
            h.await.unwrap();
        }
        assert_eq!(admitted.load(Ordering::SeqCst), 12);
        let guard = pool.inner.lock().await;
        assert_eq!(guard.get(&key1()).map(VecDeque::len), Some(12));
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
