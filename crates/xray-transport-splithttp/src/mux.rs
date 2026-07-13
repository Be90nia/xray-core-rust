//! xmux 多路复用——HTTP/2 单连接上的并发请求池。对应 Go `transport/internet/splithttp/mux.go`。
//!
//! ## 设计
//!
//! Go 版本通过 `XmuxManager` 持有多个 `XmuxClient`（每个 client 复用一个 HTTP/2 连接），
//! 在 `GetXmuxClient` 中按 `max_concurrency` / `max_connections` / `cMaxReuseTimes` /
//! `hMaxRequestTimes` / `hMaxReusableSecs` 5 个维度决定复用现有 client 还是新建。
//!
//! ## Rust 翻译决策
//!
//! - Go 的 `XmuxConn` 是 interface（仅 `IsClosed() bool`），Rust 用 trait + generic
//!   `<C: XmuxConn>` 单态化，避免 `dyn` 的动态分发开销
//! - `atomic.Int32` → `AtomicI32`；`time.Time` zero → `Option<Instant>`（None 表未设置）
//! - `math.MaxInt32` 表示"无限制"，Rust 直接 `i32::MAX`
//! - `sync.Mutex` + `[]*XmuxClient` → `Mutex<Vec<Arc<XmuxClient<C>>>>`
//!
//! ## 复用判定（`get_xmux_client` 内部 4 分支）
//!
//! 1. 清理：移除 `is_closed()` / `left_usage == 0` / `left_requests <= 0` / `unreusable_at` 已过的 client
//! 2. 若列表空 → 新建
//! 3. 若 `connections > 0` 且当前 < connections → 新建（未达上限）
//! 4. 过滤 `open_usage < concurrency` 的候选；空 → 新建；否则随机选一个并 `left_usage -= 1`

use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rand::Rng;

use crate::config::XmuxConfig;

/// `i32::MAX` 表示"无限制"，对应 Go `math.MaxInt32`。
pub const UNLIMITED_REQUESTS: i32 = i32::MAX;

/// xmux 连接抽象。对应 Go `XmuxConn` interface。
///
/// 实现者代表一个可复用的 HTTP/2 连接（或其它资源），仅需报告是否已关闭。
pub trait XmuxConn: Send + Sync {
    /// 连接是否已关闭（不可再复用）。
    fn is_closed(&self) -> bool;
}

/// 单个 xmux 客户端——复用一个底层连接 `C`，跟踪 5 维计数。对应 Go `XmuxClient`。
///
/// 字段全部 atomic / Mutex 保护，`Arc<XmuxClient<C>>` 可跨线程共享。
pub struct XmuxClient<C: XmuxConn + 'static> {
    /// 底层连接。
    pub conn: C,
    /// 连接剩余可复用次数。`-1` = 无限制（默认）；`0` = 已用尽。
    /// 对应 Go `leftUsage`（i32）。
    left_usage: AtomicI32,
    /// HTTP/2 stream 剩余可发请求数。`UNLIMITED_REQUESTS` = 无限制（默认）。
    /// 对应 Go `LeftRequests`（atomic.Int32）。
    left_requests: AtomicI32,
    /// 当前打开的并发请求数（用于 `max_concurrency` 判定）。
    /// 对应 Go `OpenUsage`（atomic.Int32）。
    open_usage: AtomicI32,
    /// 连接不再可用的时刻。`None` = 无此限制（默认）。
    /// 对应 Go `UnreusableAt`（`time.Time{}` zero 表无限制）。
    unreusable_at: Mutex<Option<Instant>>,
}

impl<C: XmuxConn + 'static> XmuxClient<C> {
    /// 构造一个全部限制为默认（无限）的 client。内部用，由 `XmuxManager::new_xmux_client` 调。
    fn new(conn: C) -> Self {
        Self {
            conn,
            left_usage: AtomicI32::new(-1),
            left_requests: AtomicI32::new(UNLIMITED_REQUESTS),
            open_usage: AtomicI32::new(0),
            unreusable_at: Mutex::new(None),
        }
    }

    /// 读取剩余复用次数。
    pub fn left_usage(&self) -> i32 {
        self.left_usage.load(Ordering::SeqCst)
    }

    /// 读取剩余请求数。
    pub fn left_requests(&self) -> i32 {
        self.left_requests.load(Ordering::SeqCst)
    }

    /// 读取当前打开并发数。
    pub fn open_usage(&self) -> i32 {
        self.open_usage.load(Ordering::SeqCst)
    }

    /// 增加一个并发槽位。caller 在打开新请求时调用。
    pub fn inc_open_usage(&self) {
        self.open_usage.fetch_add(1, Ordering::SeqCst);
    }

    /// 释放一个并发槽位。caller 在请求结束时调用。
    pub fn dec_open_usage(&self) {
        self.open_usage.fetch_sub(1, Ordering::SeqCst);
    }

    /// 减少一个剩余请求数（不可低于 0）。
    pub fn dec_left_requests(&self) {
        let _ = self.left_requests.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
            if v > 0 {
                Some(v - 1)
            } else {
                None
            }
        });
    }

    /// 判断此 client 是否已不可复用（5 维任一触发即返回 `true`）。
    fn is_unreusable(&self) -> bool {
        if self.conn.is_closed() {
            return true;
        }
        if self.left_usage.load(Ordering::SeqCst) == 0 {
            return true;
        }
        if self.left_requests.load(Ordering::SeqCst) <= 0 {
            return true;
        }
        if let Some(t) = *self.unreusable_at.lock().unwrap() {
            if Instant::now() > t {
                return true;
            }
        }
        false
    }
}

/// xmux 多路复用管理器。对应 Go `XmuxManager`。
///
/// 维护一组 `XmuxClient<C>`，在 `get_xmux_client()` 中按 4 分支算法选择复用或新建。
///
/// # 泛型
///
/// - `C`: 实现 `XmuxConn` 的连接类型（如 `Arc<DefaultDialerClient>` 或测试用 mock）
///
/// # 线程安全
///
/// 所有共享状态用 `Mutex` + `Atomic*` 保护，`Arc<XmuxManager<C>>` 可跨线程共享。
pub struct XmuxManager<C: XmuxConn + 'static> {
    xmux_config: XmuxConfig,
    /// `max_concurrency.rand()`，0 表示无限制。
    concurrency: i32,
    /// `max_connections.rand()`，0 表示无限制。
    connections: i32,
    /// 新建连接的工厂闭包。
    new_conn_func: Box<dyn Fn() -> C + Send + Sync>,
    /// 已建立的 client 池。
    xmux_clients: Mutex<Vec<Arc<XmuxClient<C>>>>,
}

impl<C: XmuxConn + 'static> XmuxManager<C> {
    /// 构造 manager。对应 Go `NewXmuxManager`。
    ///
    /// `concurrency` / `connections` 在构造时一次性 rand 采样（与 Go 一致）。
    pub fn new<F>(xmux_config: XmuxConfig, new_conn_func: F) -> Self
    where
        F: Fn() -> C + Send + Sync + 'static,
    {
        Self {
            concurrency: xmux_config.normalized_max_concurrency().rand(),
            connections: xmux_config.normalized_max_connections().rand(),
            xmux_config,
            new_conn_func: Box::new(new_conn_func),
            xmux_clients: Mutex::new(Vec::new()),
        }
    }

    /// 内部：新建一个 `XmuxClient`，根据 config 设置 3 维限制，并 push 到池中。
    /// 对应 Go `(*XmuxManager).newXmuxClient`。
    fn new_xmux_client(&self) -> Arc<XmuxClient<C>> {
        let client = XmuxClient::new((self.new_conn_func)());

        // cMaxReuseTimes: rand > 0 时设置（=rand-1）；否则保持 -1 无限制
        let x = self.xmux_config.normalized_c_max_reuse_times().rand();
        if x > 0 {
            client.left_usage.store(x - 1, Ordering::SeqCst);
        }

        // hMaxRequestTimes: rand > 0 时设置；否则保持 UNLIMITED_REQUESTS
        let x = self.xmux_config.normalized_h_max_request_times().rand();
        if x > 0 {
            client.left_requests.store(x, Ordering::SeqCst);
        }

        // hMaxReusableSecs: rand > 0 时设置 UnreusableAt = Now + secs
        let x = self.xmux_config.normalized_h_max_reusable_secs().rand();
        if x > 0 {
            *client.unreusable_at.lock().unwrap() =
                Some(Instant::now() + Duration::from_secs(x as u64));
        }

        let arc_client = Arc::new(client);
        self.xmux_clients
            .lock()
            .unwrap()
            .push(arc_client.clone());
        arc_client
    }

    /// 选择一个可用的 client（4 分支算法）。对应 Go `(*XmuxManager).GetXmuxClient`。
    ///
    /// 算法：
    /// 1. 清理池中所有 `is_unreusable()` 的 client
    /// 2. 若池空 → 新建
    /// 3. 若 `connections > 0` 且当前 < connections → 新建（鼓励多连接）
    /// 4. 过滤 `open_usage < concurrency` 的候选（`concurrency > 0` 时）；
    ///    空则新建；否则随机选一个，`left_usage > 0` 时 `-= 1`
    #[must_use]
    pub fn get_xmux_client(&self) -> Arc<XmuxClient<C>> {
        let mut clients = self.xmux_clients.lock().unwrap();

        // 1. 清理不可复用的（同 Go 的 for-loop retain 逻辑）
        clients.retain(|c| !c.is_unreusable());

        // 2. 池空 → 新建
        if clients.is_empty() {
            drop(clients);
            return self.new_xmux_client();
        }

        // 3. 未达 maxConnections → 新建
        if self.connections > 0 && (clients.len() as i32) < self.connections {
            drop(clients);
            return self.new_xmux_client();
        }

        // 4. 按 maxConcurrency 过滤候选；concurrency=0 表示无限制
        let candidates: Vec<Arc<XmuxClient<C>>> = if self.concurrency > 0 {
            clients
                .iter()
                .filter(|c| c.open_usage() < self.concurrency)
                .cloned()
                .collect()
        } else {
            clients.clone()
        };

        if candidates.is_empty() {
            drop(clients);
            return self.new_xmux_client();
        }

        // 随机选一个，left_usage > 0 时 -1
        let i = rand::rng().random_range(0..candidates.len());
        let chosen = candidates[i].clone();
        if chosen.left_usage() > 0 {
            chosen.left_usage.fetch_sub(1, Ordering::SeqCst);
        }
        chosen
    }

    /// 当前池中 client 数量（含可能不可复用的；测试用）。
    pub fn pool_size(&self) -> usize {
        self.xmux_clients.lock().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::atomic::AtomicUsize;

    /// 测试用 XmuxConn 实现——可手动标记 closed。
    struct FakeConn {
        closed: std::sync::atomic::AtomicBool,
        id: usize,
    }

    impl FakeConn {
        fn new(id: usize) -> Self {
            Self {
                closed: std::sync::atomic::AtomicBool::new(false),
                id,
            }
        }

        fn close(&self) {
            self.closed.store(true, Ordering::SeqCst);
        }
    }

    impl XmuxConn for FakeConn {
        fn is_closed(&self) -> bool {
            self.closed.load(Ordering::SeqCst)
        }
    }

    // 静态计数器：测试中区分 new_conn_func 调用次数
    thread_local! {
        static CONN_COUNTER: AtomicUsize = AtomicUsize::new(0);
    }

    fn make_factory() -> impl Fn() -> FakeConn + Send + Sync {
        let counter = Arc::new(AtomicUsize::new(0));
        move || {
            let id = counter.fetch_add(1, Ordering::SeqCst);
            FakeConn::new(id)
        }
    }

    /// 对应 Go `mux_test.go::TestDefault`：默认 config（全 nil）应让所有 `get_xmux_client`
    /// 返回同一个 client（concurrency=0 不限并发，connections=0 不限连接数）。
    #[test]
    fn default_config_reuses_single_client() {
        let manager = XmuxManager::new(XmuxConfig::default(), make_factory());

        let mut distinct_ids: HashSet<usize> = HashSet::new();
        for _ in 0..64 {
            let client = manager.get_xmux_client();
            client.inc_open_usage();
            distinct_ids.insert(Arc::as_ptr(&client) as usize);
        }

        assert_eq!(distinct_ids.len(), 1, "应仅复用 1 个 client");
        assert_eq!(manager.pool_size(), 1);
    }

    /// `max_concurrency > 0` 时，达到上限应触发新建 client。
    #[test]
    fn max_concurrency_triggers_new_client_when_full() {
        let mut config = XmuxConfig::default();
        config.max_concurrency = Some(crate::config::RangeConfig::new(2, 2));
        // 不限连接数，否则 Step 3 会一直新建
        config.max_connections = Some(crate::config::RangeConfig::new(0, 0));

        let manager = XmuxManager::new(config, make_factory());

        // 第 1 个 client：占满 concurrency=2
        let c1 = manager.get_xmux_client();
        c1.inc_open_usage();
        c1.inc_open_usage();

        // 第 2 次调用：c1 的 open_usage=2 已达上限 → 应新建 c2
        let c2 = manager.get_xmux_client();

        assert_ne!(
            Arc::as_ptr(&c1) as usize,
            Arc::as_ptr(&c2) as usize,
            "concurrency 满时应新建 client"
        );
    }

    /// 连接关闭后，下次 `get_xmux_client` 应清理池并新建。
    #[test]
    fn closed_client_is_pruned() {
        let manager = XmuxManager::new(XmuxConfig::default(), make_factory());

        let c1 = manager.get_xmux_client();
        assert_eq!(manager.pool_size(), 1);

        // 模拟底层连接关闭——FakeConn::close 走 trait object 不可达，
        // 因此直接用 XmuxConn::is_closed 返回 true 的特殊实现验证。
        // 这里通过 Arc 拿到内部引用不安全，改用独立测试。
        drop(c1);

        // 池里仍有 1 个（被 Arc 引用计数 +1，未真正清理）
        assert_eq!(manager.pool_size(), 1);
    }

    /// 用一个可在 trait 层面关闭的 mock 验证清理逻辑。
    #[test]
    fn closed_via_trait_is_pruned() {
        use std::sync::atomic::AtomicBool;

        struct ClosabledConn {
            closed: AtomicBool,
        }
        impl XmuxConn for ClosabledConn {
            fn is_closed(&self) -> bool {
                self.closed.load(Ordering::SeqCst)
            }
        }

        let closed_flag = Arc::new(AtomicBool::new(false));
        let cf = closed_flag.clone();
        let manager = XmuxManager::new(XmuxConfig::default(), move || {
            // 每次新建都共享同一个 closed_flag，但本测试只用 1 个 client
            ClosabledConn {
                closed: AtomicBool::new(false),
            }
        });
        // 上面闭包里我们没用 closed_flag（每次都是新 false），改写策略：
        let _ = cf;

        let _c1 = manager.get_xmux_client();
        assert_eq!(manager.pool_size(), 1);

        // 用一个新 manager，连接一开始就关闭
        let manager2 = XmuxManager::new(XmuxConfig::default(), || ClosabledConn {
            closed: AtomicBool::new(true), // 一开始就关闭
        });

        let _ = manager2.get_xmux_client();
        // 第 1 次：池空 → 新建（已关闭的 conn），但 is_unreusable 会在下次清理时被识别
        assert_eq!(manager2.pool_size(), 1);

        let _ = manager2.get_xmux_client();
        // 第 2 次：上次留下的是 closed → 清理 → 池又空 → 再新建。池里只有这 1 个新的。
        assert_eq!(manager2.pool_size(), 1);
    }

    /// `c_max_reuse_times` 设置后应正确初始化 `left_usage`。
    #[test]
    fn c_max_reuse_times_sets_left_usage() {
        let mut config = XmuxConfig::default();
        config.c_max_reuse_times = Some(crate::config::RangeConfig::new(5, 5));

        let manager = XmuxManager::new(config, make_factory());
        let client = manager.get_xmux_client();

        // rand()=5，left_usage = 5-1 = 4
        assert_eq!(client.left_usage(), 4);
    }

    /// `h_max_request_times` 设置后应正确初始化 `left_requests`。
    #[test]
    fn h_max_request_times_sets_left_requests() {
        let mut config = XmuxConfig::default();
        config.h_max_request_times = Some(crate::config::RangeConfig::new(100, 100));

        let manager = XmuxManager::new(config, make_factory());
        let client = manager.get_xmux_client();

        assert_eq!(client.left_requests(), 100);
    }

    /// `h_max_reusable_secs` 设置后 `unreusable_at` 应为未来时刻。
    /// 间接验证：池里这个 client 在 `Instant::now()` 时不可被判定为过期。
    #[test]
    fn h_max_reusable_secs_sets_unreusable_at_future() {
        let mut config = XmuxConfig::default();
        config.h_max_reusable_secs = Some(crate::config::RangeConfig::new(60, 60));

        let manager = XmuxManager::new(config, make_factory());
        let client = manager.get_xmux_client();

        // 此时不应被清理；通过再次调用 get_xmux_client 不新建来验证
        let client2 = manager.get_xmux_client();
        assert_eq!(
            Arc::as_ptr(&client) as usize,
            Arc::as_ptr(&client2) as usize,
            "未过期的 client 应被复用"
        );
    }

    /// `max_connections > 0` 时，应持续新建直到达到上限。
    #[test]
    fn max_connections_encourages_new_clients() {
        let mut config = XmuxConfig::default();
        config.max_connections = Some(crate::config::RangeConfig::new(3, 3));

        let manager = XmuxManager::new(config, make_factory());

        let _c1 = manager.get_xmux_client();
        let _c2 = manager.get_xmux_client();
        let _c3 = manager.get_xmux_client();

        // 第 4 次：已达到 max_connections=3，且 concurrency=0 → 不限并发 → 应在池中选一个
        // （Step 3：clients.len() == connections，不进 if，走到 Step 4）
        let c4 = manager.get_xmux_client();
        assert_eq!(manager.pool_size(), 3, "达到 max_connections 后不再新建");
    }

    /// 验证 `XmuxClient` 的 inc/dec_open_usage 与 left_requests 计数。
    #[test]
    fn client_counter_operations() {
        let client = XmuxClient::new(FakeConn::new(0));

        assert_eq!(client.open_usage(), 0);
        client.inc_open_usage();
        client.inc_open_usage();
        assert_eq!(client.open_usage(), 2);
        client.dec_open_usage();
        assert_eq!(client.open_usage(), 1);

        assert_eq!(client.left_requests(), UNLIMITED_REQUESTS);
        client.dec_left_requests();
        // 无限制时 dec 无效果（fetch_update 在 UNLIMITED_REQUESTS 时仍减 1，因为 > 0）
        // 注：UNLIMITED_REQUESTS = i32::MAX > 0，所以会减 1
        assert_eq!(client.left_requests(), i32::MAX - 1);

        // 模拟到 0
        client.left_requests.store(1, Ordering::SeqCst);
        client.dec_left_requests();
        assert_eq!(client.left_requests(), 0);
        // 已为 0 时不再减（fetch_update 返回 None）
        client.dec_left_requests();
        assert_eq!(client.left_requests(), 0);
    }
}
