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
//! - Go 的 `XmuxConn` 是 interface（仅 `IsClosed() bool`），Rust 用 trait + generic `<C: XmuxConn>`
//!   单态化，避免 `dyn` 的动态分发开销
//! - `atomic.Int32` → `AtomicI32`；`time.Time` zero → `Option<Instant>`（None 表未设置）
//! - `math.MaxInt32` 表示"无限制"，Rust 直接 `i32::MAX`
//! - `sync.Mutex` + `[]*XmuxClient` → `Mutex<Vec<Arc<XmuxClient<C>>>>`
//!
//! ## 复用判定（`get_xmux_client` 内部按模式分派）
//!
//! 1. 清理：移除 `is_closed()` / `left_usage == 0` / `left_requests <= 0` / `unreusable_at` 已过的
//!    client
//! 2. 若列表空 → 新建
//! 3. **显式 `maxConnections=N`**（Go 语义）：未达 N 前每次新建，达 N 后随机复用
//! 4. **`maxConcurrency=M`**（Go 语义 + **我们的缺省预设 M=1**）：候选 = 占用 < M 的 client；
//!    候选空 → 按需新建（受池上限约束）；达池上限 → 复用最闲的（不得新建越界）
//! 5. **两旋钮皆 0**（Go nil 语义）：单 client 复用，不增长
//!
//! ## 我们的缺省拓扑（bd m2mmm）
//!
//! Go 的缺省是 `maxConnections=3`（3 条连接复用）；我们的缺省改为
//! `maxConcurrency=1` = **每个并发请求独占一条连接**，池按并发需求增长，
//! 池上限 = 整机内存份额派生 ∩ `XRAY_MAX_CONNS` 显式上限
//! （`xray_frame::budget::plan::xmux_pool_cap`——唯一事实源）。
//! Go 配置面（键名/取值区间/互斥硬错/RangeConfig）逐项不变——只有「用户什么都没写」
//! 时的缺省不同。

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicI32, Ordering},
    },
    time::{Duration, Instant},
};

use parking_lot::Mutex;
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

    /// 安装「建连失败」回调（**池层注入**）：底层报告本次**建连型**请求失败
    /// （非 200 / 传输错误）时调用 ⇒ 池层归还本次取用预约 + 把该 client 标记为
    /// 不可复用（下次取用即剪枝）。
    ///
    /// 缺省实现 = 无操作（非池化连接 / 不参与取用预约的连接类型）。
    fn set_dial_failure_hook(&self, _hook: Arc<dyn Fn() + Send + Sync>) {}
}

/// 单 client 的取用预约上界（条）——**幽灵预约兜底闸**（bd m2mmm 评审 B2）。
///
/// 正常路径下预约数 = 该 client 上的在途请求数（我们的缺省 M=1 ⇒ 1；Go
/// `maxConnections` 模式下单连接可承载数千并发）⇒ 上界取 4096：既容得下合法的
/// Go 模式高并发，又能在**释放路径漏掉**时（预约只增不减）很快触顶 ⇒ 标记
/// 不可复用 + 剪枝 + WARN（不静默）。
pub const MAX_RESERVED_PER_CLIENT: i32 = 4096;

/// client 的共享账本——取用预约计数 + 「不可复用」标记。
///
/// 抽成独立结构，是为了让**建连失败回调**（装在底层连接上）与 client 本体共享
/// 同一份账本：回调归还预约、标记不可复用时，client 侧立即可见（无需回池锁）。
#[derive(Debug, Default)]
struct ClientLedger {
    /// **已分配**（manager 交出本 client）但尚未结束的取用数。
    ///
    /// 与 `open_usage`（Go `Running`，**连接建立后**才 +1）不同：本计数覆盖
    /// 「已选中 → 连接关闭」整个窗口（含握手期）⇒ 并发取用不会在握手窗口里
    /// 误判「空闲」而挤进同一条连接（缺省「每请求一连接」语义的前提）。
    ///
    /// 配对：manager 取用时 +1（[`XmuxManager::get_xmux_client`]）；成功建连后
    /// 由连接关闭释放（[`XmuxClient::dec_open_usage`]，dialer 的 `set_on_close`
    /// 回调）；**建连失败**由回调归还（[`XmuxClient::dec_reserved`]）。
    reserved: AtomicI32,
    /// 不可复用标记（建连失败 / 预约越界 ⇒ 置位 ⇒ 下次取用即剪枝）。
    unusable: AtomicBool,
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
    /// 取用预约账本（与建连失败回调共享，见 [`ClientLedger`]）。
    ledger: Arc<ClientLedger>,
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
            ledger: Arc::new(ClientLedger::default()),
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
    ///
    /// 同时释放 manager 的**取用预约**（`ClientLedger::reserved`）——与
    /// [`XmuxManager::get_xmux_client`] 的取用 +1 配对（dialer 的
    /// `set_on_close` 回调是成功建连后的释放点；**建连失败**由
    /// [`Self::dec_reserved`] 归还）。
    pub fn dec_open_usage(&self) {
        self.open_usage.fetch_sub(1, Ordering::SeqCst);
        self.dec_reserved();
    }

    /// 归还一个取用预约（**建连失败**路径用；不会降到负数）。
    ///
    /// 建连失败时 dialer 不会安装 `set_on_close` ⇒ 预约原本无处释放 ⇒ 幽灵预约
    /// 永久滞留 ⇒ 该 client 永远「占用中」被剪枝、池被僵尸占满（bd m2mmm 评审 B2）。
    pub fn dec_reserved(&self) {
        // fetch_update 在 1.99 改名 try_update，但工作区 MSRV=1.85，保持旧名 + 局部豁免。
        #[allow(deprecated)] // fetch_update 1.99 改名 try_update，MSRV=1.85 保持旧名
        let _ = self
            .ledger
            .reserved
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| Some(v.saturating_sub(1)));
    }

    /// 当前取用预约数（已交出未结算的取用数）——可观测面（池内幽灵预约自检）。
    pub fn reserved(&self) -> i32 {
        self.ledger.reserved.load(Ordering::SeqCst)
    }

    /// 记一次「已分配」（manager 交出本 client 时 +1）。
    ///
    /// 上界 = [`MAX_RESERVED_PER_CLIENT`]：越界即视为**释放路径漏了** ⇒ 标记
    /// 不可复用（剪枝）+ WARN（不静默）。
    fn reserve(&self) {
        // fetch_update 在 1.99 改名 try_update，但工作区 MSRV=1.85，保持旧名 + 局部豁免。
        #[allow(deprecated)] // fetch_update 1.99 改名 try_update，MSRV=1.85 保持旧名
        let prev = self
            .ledger
            .reserved
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                Some((v + 1).min(MAX_RESERVED_PER_CLIENT))
            })
            .unwrap_or(MAX_RESERVED_PER_CLIENT);
        if prev >= MAX_RESERVED_PER_CLIENT {
            self.ledger.unusable.store(true, Ordering::SeqCst);
            crate::hot_log!(
                tracing::Level::WARN,
                "xmux reservation overflow: reserved={prev} >= {MAX_RESERVED_PER_CLIENT} => client marked unusable"
            );
        }
    }

    /// 当前占用（并发请求数）——`max_concurrency` 判定的度量。
    ///
    /// 取 `open_usage`（Go `Running`，连接建立后计数）与 `reserved`（已分配未结束）
    /// 的**较大者**：前者是 Go 语义，后者覆盖握手窗口 ⇒ 并发取用不会挤进同一条
    /// 连接，缺省「每请求一连接」语义才成立。
    pub fn effective_load(&self) -> i32 {
        self.open_usage.load(Ordering::SeqCst).max(self.ledger.reserved.load(Ordering::SeqCst))
    }

    /// 减少一个剩余请求数（不可低于 0）。
    // fetch_update 在 1.99 改名 try_update，但工作区 MSRV=1.85，保持旧名 + 局部豁免。
    #[allow(deprecated)] // fetch_update 1.99 改名 try_update，MSRV=1.85 保持旧名
    pub fn dec_left_requests(&self) {
        let _ = self.left_requests.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
            if v > 0 { Some(v - 1) } else { None }
        });
    }

    /// 判断此 client 是否已不可复用（5 维任一触发即返回 `true`）。
    fn is_unreusable(&self) -> bool {
        if self.conn.is_closed() {
            return true;
        }
        // 建连失败 / 预约越界 ⇒ 标记不可复用（剪枝，避免幽灵预约占住池位）。
        if self.ledger.unusable.load(Ordering::SeqCst) {
            return true;
        }
        if self.left_usage.load(Ordering::SeqCst) == 0 {
            return true;
        }
        if self.left_requests.load(Ordering::SeqCst) <= 0 {
            return true;
        }
        if let Some(t) = *self.unreusable_at.lock() {
            #[allow(
                clippy::disallowed_methods,
                reason = "数据面热路径豁免（坑约束⑫）+ ctx 不可达：splithttp 传输层无 Clock 注入面；xmux client 不可复用判定锚点（Go xmux time.Time 墙钟语义），FxScope/Clock 迁移收口见 bd 39hko"
            )]
            if Instant::now() > t {
                return true;
            }
        }
        false
    }
}

/// 池容量上限提供者：返回当前允许的池内 client 数上限（条）。
///
/// `None` = 缺省「整机内存份额派生 ∩ 显式上限」（[`xray_frame::budget::plan::xmux_pool_cap`]）。
/// 注入面（测试替身 / 将来接别的信号）——生产用 [`XmuxManager::new`]（缺省派生）。
pub type CapacityProvider = Option<Arc<dyn Fn() -> usize + Send + Sync>>;

/// xmux 多路复用管理器。对应 Go `XmuxManager`。
///
/// 维护一组 `XmuxClient<C>`，在 `get_xmux_client()` 中按**三种模式**选择复用或新建：
///
/// | 模式 | 触发条件 | 池拓扑 |
/// |---|---|---|
/// | `maxConnections`（Go 语义） | 显式 `maxConnections=N` | 硬上限 N；未达上限前每次新建，达上限后随机复用（每 client 并发不限）|
/// | `maxConcurrency`（Go 语义 + **我们的缺省预设**） | `maxConcurrency=M`（含我们缺省 `M=1`） | 每 client 承载 ≤ M；全忙则按需新建（受池上限约束），达上限复用最闲的 |
/// | 缺省 nil（Go 语义） | 两旋钮皆 0/未设 | 单 client 复用，不增长 |
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
    /// 池容量上限提供者（`None` = 缺省整机内存份额派生）。
    capacity: CapacityProvider,
    /// 新建连接的工厂闭包。
    new_conn_func: Box<dyn Fn() -> C + Send + Sync>,
    /// 已建立的 client 池。
    xmux_clients: Mutex<Vec<Arc<XmuxClient<C>>>>,
    /// 创建锁——串行化「判定 + 建 client + 入池」三步。
    ///
    /// Go 侧靠 `dialer.go:54-55` 的 `globalDialerAccess` **持锁**调 `GetXmuxClient`
    /// ⇒ 并发拨号串行、池内最多 `maxConnections` 条。本仓 `parking_lot::Mutex`
    /// **非重入**（`new_xmux_client` 内部另加池锁 ⇒ 不能持池锁建连），故用**独立**
    /// 创建锁把三步收进同一临界区。锁序固定：`create_lock` → `xmux_clients`（无环）。
    create_lock: Mutex<()>,
}

impl<C: XmuxConn + 'static> XmuxManager<C> {
    /// 构造 manager。对应 Go `NewXmuxManager`。
    ///
    /// `concurrency` / `connections` 在构造时一次性 rand 采样（与 Go 一致）。
    /// 池容量上限走**缺省整机内存份额派生**（[`CapacityProvider`] 的 `None` 分支）。
    pub fn new<F>(xmux_config: XmuxConfig, new_conn_func: F) -> Self
    where
        F: Fn() -> C + Send + Sync + 'static,
    {
        Self::new_with_capacity(xmux_config, new_conn_func, None)
    }

    /// 构造 manager 并**注入池容量上限提供者**（测试替身 / 将来接别的信号）。
    ///
    /// `capacity = None` ⇒ 缺省整机内存份额派生（见 `default_pool_cap`）。
    pub fn new_with_capacity<F>(
        xmux_config: XmuxConfig,
        new_conn_func: F,
        capacity: CapacityProvider,
    ) -> Self
    where
        F: Fn() -> C + Send + Sync + 'static,
    {
        Self {
            concurrency: xmux_config.normalized_max_concurrency().rand(),
            connections: xmux_config.normalized_max_connections().rand(),
            xmux_config,
            capacity,
            new_conn_func: Box::new(new_conn_func),
            xmux_clients: Mutex::new(Vec::new()),
            create_lock: Mutex::new(()),
        }
    }

    /// 池内 client 数上限（条）。
    ///
    /// - **显式 `maxConnections`**（Go 语义硬上限，用户值优先，动态信号不得改写）
    /// - 否则 = 容量提供者的动态值（缺省 = 整机内存份额派生 ∩ `XRAY_MAX_CONNS` 显式上限）
    ///
    /// **不得被单 client 并发上限 `M` 抬高**（bd m2mmm 评审 S5）：`M` 只约束「单
    /// client 承载 ≤ M」，把它当池下限会让显式 `maxConcurrency=1000` 在 512MiB 盒
    /// 上把池开到 1000 条（规划占用 ~3GiB）⇒ 突破「我们最多占整机一份」（契约 3）
    /// 与用户硬约束「不得把 VPS 内存吃光」。
    ///
    /// 取舍（写进契约）：`M > 份额上限` 时，池按份额上限封顶 ⇒ 需求超过
    /// 「份额上限 × M」时走「复用最闲 client」兜底（单 client 可能承载超过 M）——
    /// 该超载面属 bd m2mmm 评审 S1（可观测超载 vs 拒绝），**不在本票范围**。
    fn pool_cap(&self) -> usize {
        if self.connections > 0 {
            return self.connections as usize;
        }
        let dynamic = match &self.capacity {
            Some(provider) => provider(),
            None => default_pool_cap(),
        };
        dynamic.max(1)
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
        // 赋值表达式语句位挂属性在本工具链 E0658（无 stmt_expr_attributes），allow 上移 if 语句位。
        #[allow(
            clippy::disallowed_methods,
            reason = "数据面热路径豁免（坑约束⑫）+ ctx 不可达：splithttp 传输层无 Clock 注入面；xmux client UnreusableAt = Now + secs 锚点（Go xmux time.Time 墙钟语义），FxScope/Clock 迁移收口见 bd 39hko"
        )]
        if x > 0 {
            *client.unreusable_at.lock() = Some(Instant::now() + Duration::from_secs(x as u64));
        }

        let arc_client = Arc::new(client);
        // 建连失败回调（bd m2mmm 评审 B2）：底层报告本次**建连型**请求失败
        // （非 200 / 传输错误）⇒ 归还本次取用预约 + 标记该 client 不可复用
        // （下次取用即剪枝 ⇒ 池内不留幽灵预约、不静默退化成复用）。
        let ledger = Arc::clone(&arc_client.ledger);
        arc_client.conn.set_dial_failure_hook(Arc::new(move || {
            ledger.unusable.store(true, Ordering::SeqCst);
            // fetch_update 在 1.99 改名 try_update，但工作区 MSRV=1.85，保持旧名 + 局部豁免。
            #[allow(deprecated)] // fetch_update 1.99 改名 try_update，MSRV=1.85 保持旧名
            let _ = ledger
                .reserved
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| Some(v.saturating_sub(1)));
            crate::hot_log!(
                tracing::Level::WARN,
                "xmux dial failed: reservation released, client marked unusable"
            );
        }));
        self.xmux_clients.lock().push(arc_client.clone());
        // 新建的 client 立即被本次取用占用 ⇒ 记预约（与 `take` 同一记账面）。
        arc_client.reserve();
        arc_client
    }

    /// 选择一个可用的 client。对应 Go `(*XmuxManager).GetXmuxClient`。
    ///
    /// 算法（按模式分派，Go 语义逐项保留）：
    /// 1. 清理池中所有 `is_unreusable()` 的 client
    /// 2. 若池空 → 新建
    /// 3. **显式 `maxConnections=N`**：未达 N 前每次新建（Go「鼓励多连接」）， 达 N 后随机复用（每
    ///    client 并发不限）
    /// 4. **`maxConcurrency=M`**（含我们缺省预设 `M=1`）：候选 = 占用 < M 的 client； 候选空 →
    ///    **按需新建**（受池上限约束）；达池上限 → 复用**最闲**的 client （**不得**新建越界）
    /// 5. **两旋钮皆 0**（Go nil 语义）：单 client 复用，不增长
    ///
    /// 取用即**预约**（`XmuxClient::reserve`）：预约覆盖「已选中 → 连接关闭」整个
    /// 窗口（含握手期）⇒ 并发取用不会在握手窗口误判空闲而挤进同一条连接，
    /// 缺省「每请求一连接」语义成立。
    ///
    /// **原子性**：判定、建 client、入池三步在同一临界区完成（`Self::create_lock`）
    /// ⇒ 并发突发下池内 client 数恒 ≤ `maxConnections`（Go `dialer.go:54-55` 持
    /// `globalDialerAccess` 调 `GetXmuxClient` 的等价语义）。
    #[must_use]
    pub fn get_xmux_client(&self) -> Arc<XmuxClient<C>> {
        // 串行化「判定 + 建 client + 入池」。Go 侧持全局锁调 `GetXmuxClient`；
        // 本仓若把判定（池空/未达上限）与建 client 分离（先释放池锁再建），并发突发
        // 会各自看到「池空」⇒ 各建一条 client ⇒ `maxConnections` 旋钮在并发下失效。
        let _create = self.create_lock.lock();

        let mut clients = self.xmux_clients.lock();

        // 1. 清理不可复用的（同 Go 的 for-loop retain 逻辑）
        clients.retain(|c| !c.is_unreusable());

        // 2. 池空 → 新建
        if clients.is_empty() {
            drop(clients);
            return self.new_xmux_client();
        }

        // 3. 显式 maxConnections：Go 语义（未达上限每次新建；达上限随机复用）。
        if self.connections > 0 {
            if clients.len() < self.connections as usize {
                drop(clients);
                return self.new_xmux_client();
            }
            let chosen = Self::take_random(&clients);
            return chosen;
        }

        // 4. maxConcurrency 模式（我们缺省预设 maxConcurrency=1 落此）。
        if self.concurrency > 0 {
            let candidates: Vec<Arc<XmuxClient<C>>> =
                clients.iter().filter(|c| c.effective_load() < self.concurrency).cloned().collect();
            if candidates.is_empty() {
                // 需求 > 现有承载 ⇒ 按需新建（**池上限内**才新建）。
                if clients.len() < self.pool_cap() {
                    drop(clients);
                    return self.new_xmux_client();
                }
                // 达池上限 ⇒ 复用最闲的 client（**不得**新建越界）。
                return Self::take_least_busy(&clients);
            }
            return Self::take_random(&candidates);
        }

        // 5. Go nil 语义（两旋钮皆 0）：单 client 复用，不增长。
        Self::take_random(&clients)
    }

    /// 取用池中随机一个 client（Go Step 6：复用时扣 `leftUsage` + 记预约）。
    fn take_random(clients: &[Arc<XmuxClient<C>>]) -> Arc<XmuxClient<C>> {
        let i = rand::rng().random_range(0..clients.len());
        Self::take(clients[i].clone())
    }

    /// 取用池中**最闲**的 client（池已达上限时的兜底：不得新建越界）。
    fn take_least_busy(clients: &[Arc<XmuxClient<C>>]) -> Arc<XmuxClient<C>> {
        let idx = clients
            .iter()
            .enumerate()
            .min_by_key(|(_, c)| c.effective_load())
            .map_or(0, |(i, _)| i);
        Self::take(clients[idx].clone())
    }

    /// 完成取用记账：`left_usage > 0` 时 -1（Go 语义）+ 记预约（`reserve`）。
    fn take(client: Arc<XmuxClient<C>>) -> Arc<XmuxClient<C>> {
        if client.left_usage() > 0 {
            client.left_usage.fetch_sub(1, Ordering::SeqCst);
        }
        client.reserve();
        client
    }

    /// 当前池中 client 数量（含可能不可复用的；测试用）。
    pub fn pool_size(&self) -> usize {
        self.xmux_clients.lock().len()
    }
}

/// 缺省池容量上限：整机内存份额派生 ∩ `XRAY_MAX_CONNS` 显式上限
/// （`xray_frame::budget::plan::xmux_pool_cap`——**唯一事实源**，S3）。
///
/// 口径（bd m2mmm，用户硬约束 2026-11-12）：
/// - 档位 = 内存档位（tiny/small/medium/large），档位上限按**设计表** 13/32/64/170
/// - 我们那一份 = 档位设计预算占整机设计尺寸的份额（15.6% ~ 25%）
/// - 每连接规划占用 ≈3MiB ⇒ 派生连接数 = 实况可用 × 份额 ÷ 每连接占用
/// - 生效上限 = min(档位上限, 派生值)；别人吃掉内存 ⇒ 我们的上限同比例下降
/// - `XRAY_MAX_CONNS`（显式连接数上限）只**收紧**（取 min），不得突破份额上限
///
/// **只在池「想增长」时才问**（[`XmuxManager::pool_cap`] 只在新建分支调用），
/// 且结果 TTL 缓存 5s ⇒ 探测不落在拨号热路径。
fn default_pool_cap() -> usize {
    const TTL: Duration = Duration::from_secs(5);
    static CACHE: LazyLock<Mutex<Option<(Instant, usize)>>> = LazyLock::new(|| Mutex::new(None));

    let mut guard = CACHE.lock();
    #[allow(
        clippy::disallowed_methods,
        reason = "ctx 不可达：splithttp 传输层无 Clock 注入面；缺省池上限的 TTL 缓存锚点（运行期按实况内存缩放，缓存只为免探测风暴），FxScope/Clock 迁移收口见 bd 39hko"
    )]
    let now = Instant::now();
    if let Some((at, cap)) = *guard {
        if now.saturating_duration_since(at) < TTL {
            return cap;
        }
    }
    let cap = xray_frame::budget::plan::xmux_pool_cap(xray_frame::budget::plan::live_available());
    *guard = Some((now, cap));
    cap
}

// ===== 切片 v7w9: 进程全局 XmuxManager 池 =====

use parking_lot::Mutex as PMutex;
use skeleton_infra::memgov::{BoundedRegistry, Eviction};

/// 进程级 keyed 容量上界（条目数 = 不同（目标+配置）的 manager 数）。
///
/// 依据：每 outbound 目标+配置内容一个 manager（Go `globalDialerMap` 同构），进程级
/// outbound 数量级 ≤ 数百，1024 触顶即异常配置。策略 = [`Eviction::Reject`]
/// （fail-closed **不淘汰**）：`EvictOldest` 是 BTreeMap 字典序首键淘汰（非「最旧
/// 使用」），会挤掉在表 key、破坏其复用；`Reject` 触顶时新 manager 照常返回调用方
/// （一次性、不入缓存），既有条目与复用不受影响——对齐「OnlineMap fail-closed,
/// no eviction」铁律。证伪钉死：
/// `tests::evict_oldest_would_break_reuse_hence_reject`。
const MANAGER_POOL_MAX_KEYS: usize = 1024;

/// 进程级 `XmuxManager` 缓存——按 string key 缓存 `Arc<XmuxManager<C>>`。
///
/// 对应 Go `transport/internet/splithttp/dialer.go:46-79` 的 `globalDialerMap`
/// （按 dialerConf{dest, streamSettings} 复用）。Rust 端用 `String` 作为通用 key。
///
/// **注册表宿主 = udf [`BoundedRegistry`]（2026-11-02 复核交付⑦）**：本件是 keyed
/// **注册表**、不是借还池——值是长期共享句柄（多请求并发持有同一 `Arc`、条目永不
/// 归还，内部持活 HTTP/2 连接与后台连接生命周期），「独占借用 → 归还」的池语义
/// （`ObjectPool`/`PoolManaged`）不适用（§3.5.4：注册表禁整面 impl `PoolManaged`）。
/// 容量与淘汰语义见 `MANAGER_POOL_MAX_KEYS`。
pub struct ManagerPool<C: XmuxConn + 'static> {
    map: PMutex<BoundedRegistry<String, Arc<XmuxManager<C>>>>,
}
impl<C: XmuxConn + 'static> ManagerPool<C> {
    pub fn new() -> Self {
        Self { map: PMutex::new(BoundedRegistry::new(MANAGER_POOL_MAX_KEYS, Eviction::Reject)) }
    }

    /// 指定容量/策略构造（测试注入小上限与淘汰策略用；生产走 [`Self::new`]）。
    #[cfg(test)]
    fn with(max_keys: usize, evict: Eviction) -> Self {
        Self { map: PMutex::new(BoundedRegistry::new(max_keys, evict)) }
    }

    /// 获取或创建并缓存 manager（同 key 复用同一 `Arc`，Go `globalDialerMap` 语义）。
    ///
    /// 表满（`Reject`）＝ fail-closed：`mk()` 新建的 manager **照常返回**调用方但
    /// 不入缓存（该次一次性使用），既有条目与复用不受影响。
    pub fn get_or<F>(&self, key: &str, mk: F) -> Arc<XmuxManager<C>>
    where
        F: FnOnce() -> Arc<XmuxManager<C>>,
    {
        let mut g = self.map.lock();
        if let Some(m) = g.get(key) {
            return m.clone();
        }
        let m = mk();
        // 满即不入表（一次性）；同 key 走覆盖路径永不触淘汰（上方 get 未命中才到这）。
        let _ = g.insert(key.to_string(), m.clone());
        m
    }

    /// 测试用：当前池条目数。
    pub fn len(&self) -> usize {
        self.map.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.lock().is_empty()
    }
}

impl<C: XmuxConn + 'static> Default for ManagerPool<C> {
    fn default() -> Self {
        Self::new()
    }
}

// ===== 接线：真实客户端的 xmux 适配 + 进程级 manager 池（bd s42cg） =====

use std::sync::LazyLock;

use crate::{client::DefaultDialerClient, h3_client::H3Conn};

/// h2（hyper）客户端作为 xmux 连接单元（Go `XmuxConn` = `DialerClient`）。
///
/// `is_closed` = 客户端自身的 closed 标志（连接级错误后置位 ⇒ 该条目被池清理）。
impl XmuxConn for Arc<DefaultDialerClient> {
    fn is_closed(&self) -> bool {
        (**self).is_closed()
    }

    fn set_dial_failure_hook(&self, hook: Arc<dyn Fn() + Send + Sync>) {
        (**self).set_dial_failure_hook(hook);
    }
}

/// h3（QUIC）客户端作为 xmux 连接单元。
impl XmuxConn for Arc<H3Conn> {
    fn is_closed(&self) -> bool {
        (**self).is_closed()
    }
}

/// h2 侧进程级 manager 池（对应 Go `globalDialerMap`）。
///
/// key = [`xmux_manager_key`]（目标 + 影响客户端构造的配置内容）。
pub static H2_MANAGERS: LazyLock<ManagerPool<Arc<DefaultDialerClient>>> =
    LazyLock::new(ManagerPool::new);

/// h3 侧进程级 manager 池（对应 Go `globalDialerMap` 的 h3 分支）。
///
/// 池单元 = [`crate::h3_client::LazyH3Conn`]（**惰性**建连的 QUIC/H3 连接）——
/// Go 的 h3 xmux 单元是 `http3.Transport`（只造 transport，握手推迟到首次请求）✓。
pub static H3_MANAGERS: LazyLock<ManagerPool<crate::h3_client::LazyH3Conn>> =
    LazyLock::new(ManagerPool::new);

/// 把一个已建好的连接包装成 xmux 池单元（默认 xmux 配置 ⇒ 无限复用）。
///
/// 供**直连/测试**路径使用（生产路径走 manager 池）：拨号函数现在收
/// `Arc<XmuxClient<C>>`（连接 + 五维计数一体，对齐 Go `*XmuxClient`）。
#[must_use]
pub fn wrap_xmux_client<C: XmuxConn + Clone + 'static>(conn: C) -> Arc<XmuxClient<C>> {
    XmuxManager::new(XmuxConfig::default(), move || conn.clone()).get_xmux_client()
}

/// xmux manager 的池 key（目标 + 影响客户端构造的配置）。
///
/// Go 的 key 是 `dialerConf{dest, *MemoryStreamConfig}`——**指针身份**（每个 outbound
/// 一个 `MemoryStreamConfig` ⇒ 每 outbound 一个 manager）。Rust 侧拨号入口拿到的是
/// **克隆**的 `StreamSettings`（`register.rs:33`），无稳定身份 ⇒ 用**内容** key
/// （目标 + 安全层 + 协议层 JSON）。
///
/// 差异登记：两个**配置内容完全相同**的 outbound 在 Rust 侧会共用一个 manager（Go 侧
/// 不会）。影响面可控——传输层在路由层之下（路由在拨号前已定），共享的只是同目标
/// 的底层连接；不同 dest / 不同 security / 不同协议配置必然分池。
#[must_use]
pub fn xmux_manager_key(
    dest: &xray_common::net::destination::Destination,
    parts: &[&str],
) -> String {
    let mut key = dest.address().to_string();
    key.push(':');
    key.push_str(&dest.port().value().to_string());
    for p in parts {
        key.push('|');
        key.push_str(p);
    }
    key
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, sync::atomic::AtomicUsize};

    use super::*;

    /// 测试用 XmuxConn 实现——可手动标记 closed，并可触发「建连失败」回调。
    struct FakeConn {
        closed: std::sync::atomic::AtomicBool,
        #[allow(dead_code)] // 测试 fake 保 trait 完整实现
        id: usize,
        /// 池层注入的「建连失败」回调（bd m2mmm 评审 B2）。
        dial_failure: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    }

    impl FakeConn {
        fn new(id: usize) -> Self {
            Self {
                closed: std::sync::atomic::AtomicBool::new(false),
                id,
                dial_failure: Mutex::new(None),
            }
        }

        #[allow(dead_code)] // 测试 fake 的显式关闭入口（配合 closed 断言）
        fn close(&self) {
            self.closed.store(true, Ordering::SeqCst);
        }

        /// 模拟「本次建连失败」（非 200 / 传输错误）——触发池层注入的回调。
        fn trigger_dial_failure(&self) {
            let hook = self.dial_failure.lock().clone();
            if let Some(hook) = hook {
                hook();
            }
        }
    }

    impl XmuxConn for FakeConn {
        fn is_closed(&self) -> bool {
            self.closed.load(Ordering::SeqCst)
        }

        fn set_dial_failure_hook(&self, hook: Arc<dyn Fn() + Send + Sync>) {
            *self.dial_failure.lock() = Some(hook);
        }
    }

    // 静态计数器：测试中区分 new_conn_func 调用次数
    thread_local! {
        static CONN_COUNTER: AtomicUsize = const { AtomicUsize::new(0) };
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
            ClosabledConn { closed: AtomicBool::new(false) }
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

    /// 五维判定逐条（Go `mux.go:89-146` 规格）：
    ///
    /// - `maxConnections = N`：前 N 次取用各建一个 client，第 N+1 次**复用**（不新建）。
    /// - `cMaxReuseTimes = N`：client 的 `leftUsage = N-1` ⇒ 复用 N-1 次后被淘汰。
    /// - `hMaxRequestTimes = N`：`LeftRequests = N` ⇒ 扣满 N 次后被淘汰。
    /// - `hMaxReusableSecs = N`：`UnreusableAt = now + N s` ⇒ 到点后被淘汰。
    /// - `maxConcurrency = N`：`Running < N` 才算候选（见上方既有用例）。
    #[test]
    fn max_connections_grows_then_reuses() {
        let mut config = XmuxConfig::default();
        config.max_connections = Some(crate::config::RangeConfig::new(2, 2));
        let manager = XmuxManager::new(config, make_factory());

        let c1 = manager.get_xmux_client();
        let c2 = manager.get_xmux_client();
        assert_eq!(manager.pool_size(), 2, "未达 maxConnections 前每次新建");
        assert_ne!(Arc::as_ptr(&c1) as usize, Arc::as_ptr(&c2) as usize);

        // 第 3 次：已达上限 ⇒ 复用池中某个（不再新建）。
        let c3 = manager.get_xmux_client();
        assert_eq!(manager.pool_size(), 2, "达 maxConnections 后不得再新建");
        assert!(
            [Arc::as_ptr(&c1) as usize, Arc::as_ptr(&c2) as usize]
                .contains(&(Arc::as_ptr(&c3) as usize)),
            "达上限后必须复用已有 client"
        );
    }

    /// 并发突发取用（Barrier 齐放，模拟并发拨号）：N 个线程同时 `get_xmux_client`。
    fn concurrent_burst(
        manager: &Arc<XmuxManager<FakeConn>>,
        n: usize,
    ) -> Vec<Arc<XmuxClient<FakeConn>>> {
        let barrier = Arc::new(std::sync::Barrier::new(n));
        let handles: Vec<_> = (0..n)
            .map(|_| {
                let m = manager.clone();
                let b = barrier.clone();
                std::thread::spawn(move || {
                    b.wait();
                    m.get_xmux_client()
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().expect("burst thread panicked")).collect()
    }

    /// 并发突发下池不得突破 `maxConnections`（Go `dialer.go:54-55` 持锁语义）。
    ///
    /// 回归锚：修复前 `get_xmux_client` 的「判定（池空/未达上限）→ 释放池锁 → 建
    /// client（内部另加锁 push）」是 check-then-act ⇒ 并发 N 次取用各建一条 client。
    #[test]
    fn concurrent_burst_respects_max_connections() {
        let mut config = XmuxConfig::default();
        config.max_connections = Some(crate::config::RangeConfig::new(3, 3));
        let created = Arc::new(AtomicUsize::new(0));
        let counter = created.clone();
        let manager = Arc::new(XmuxManager::new(config, move || {
            counter.fetch_add(1, Ordering::SeqCst);
            FakeConn::new(0)
        }));

        let clients = concurrent_burst(&manager, 10);

        assert!(
            manager.pool_size() <= 3,
            "maxConnections=3 ⇒ 池内 client 数恒 ≤ 3，实测 {}",
            manager.pool_size()
        );
        assert!(
            created.load(Ordering::SeqCst) <= 3,
            "底层连接只应建 ≤ 3 条，实测 {}",
            created.load(Ordering::SeqCst)
        );
        let distinct: HashSet<usize> = clients.iter().map(|c| Arc::as_ptr(c) as usize).collect();
        assert!(distinct.len() <= 3, "10 次并发取用最多命中 3 个 client，实测 {}", distinct.len());
    }

    /// `maxConnections=1` + 并发 10 次 ⇒ 只开 1 条底层连接，10 次全部复用同一 client。
    #[test]
    fn concurrent_burst_with_max_connections_one_opens_single_client() {
        let mut config = XmuxConfig::default();
        config.max_connections = Some(crate::config::RangeConfig::new(1, 1));
        let created = Arc::new(AtomicUsize::new(0));
        let counter = created.clone();
        let manager = Arc::new(XmuxManager::new(config, move || {
            counter.fetch_add(1, Ordering::SeqCst);
            FakeConn::new(0)
        }));

        let clients = concurrent_burst(&manager, 10);

        assert_eq!(manager.pool_size(), 1, "maxConnections=1 ⇒ 池内只允许 1 个 client");
        assert_eq!(created.load(Ordering::SeqCst), 1, "只应建 1 条底层连接");
        let first = Arc::as_ptr(&clients[0]) as usize;
        assert!(
            clients.iter().all(|c| Arc::as_ptr(c) as usize == first),
            "10 次并发取用必须复用同一 client"
        );
    }

    /// `cMaxReuseTimes = 2`：client 建好后 `leftUsage = 1` ⇒ 复用 1 次后（leftUsage=0）
    /// 下次取用时被淘汰并新建（Go `leftUsage == 0` 淘汰条件）。
    #[test]
    fn c_max_reuse_times_evicts_after_exhaustion() {
        let mut config = XmuxConfig::default();
        config.c_max_reuse_times = Some(crate::config::RangeConfig::new(2, 2));
        let manager = XmuxManager::new(config, make_factory());

        let c1 = manager.get_xmux_client();
        assert_eq!(c1.left_usage(), 1, "Go: leftUsage = cMaxReuseTimes - 1");
        let c2 = manager.get_xmux_client();
        assert_eq!(Arc::as_ptr(&c1) as usize, Arc::as_ptr(&c2) as usize, "应复用同一 client");
        assert_eq!(c1.left_usage(), 0, "复用一次后 leftUsage 归零");
        // 下一次：leftUsage == 0 ⇒ 淘汰 + 新建。
        let c3 = manager.get_xmux_client();
        assert_ne!(Arc::as_ptr(&c1) as usize, Arc::as_ptr(&c3) as usize, "leftUsage 耗尽后须新建");
    }

    /// `hMaxRequestTimes = 2`：`LeftRequests = 2`，扣满后淘汰（Go 条件
    /// `LeftRequests.Load() <= 0`）。
    #[test]
    fn h_max_request_times_evicts_after_requests_exhausted() {
        let mut config = XmuxConfig::default();
        config.h_max_request_times = Some(crate::config::RangeConfig::new(2, 2));
        let manager = XmuxManager::new(config, make_factory());

        let c1 = manager.get_xmux_client();
        assert_eq!(c1.left_requests(), 2);
        c1.dec_left_requests();
        assert_eq!(c1.left_requests(), 1);
        c1.dec_left_requests();
        assert_eq!(c1.left_requests(), 0);
        // 扣满 ⇒ 下次取用时淘汰 + 新建。
        let c2 = manager.get_xmux_client();
        assert_ne!(Arc::as_ptr(&c1) as usize, Arc::as_ptr(&c2) as usize, "请求数耗尽后须新建");
    }

    /// `hMaxReusableSecs = 1`：`UnreusableAt = now + 1s`，到点后淘汰（Go 条件
    /// `now.After(UnreusableAt)`）。
    #[tokio::test]
    async fn h_max_reusable_secs_evicts_after_expiry() {
        let mut config = XmuxConfig::default();
        config.h_max_reusable_secs = Some(crate::config::RangeConfig::new(1, 1));
        let manager = XmuxManager::new(config, make_factory());

        let c1 = manager.get_xmux_client();
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        let c2 = manager.get_xmux_client();
        assert_ne!(
            Arc::as_ptr(&c1) as usize,
            Arc::as_ptr(&c2) as usize,
            "超过 hMaxReusableSecs 后须淘汰旧 client"
        );
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
        #[allow(unused_variables)] // 存量清零批次
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

    /// 预约越界钳制 + 剪枝（bd m2mmm 评审 B2 验收：`MAX_RESERVED_PER_CLIENT` 触顶路径必须有测试）。
    ///
    /// 连打 `reserve()` 超过 [`MAX_RESERVED_PER_CLIENT`] ⇒ `reserved` 钳在上限、
    /// `unusable` 置位 ⇒ `is_unreusable()` 返回 true（下次取用即剪枝，WARN 已发）。
    #[test]
    fn reservation_overflow_clamps_and_marks_unusable() {
        let client = XmuxClient::new(FakeConn::new(0));
        // 上限 + 1 次：最后一次触发越界分支（prev >= MAX ⇒ unusable 置位）。
        for _ in 0..=MAX_RESERVED_PER_CLIENT {
            client.reserve();
        }
        assert_eq!(
            client.reserved(),
            MAX_RESERVED_PER_CLIENT,
            "预约必须钳在 MAX_RESERVED_PER_CLIENT"
        );
        assert!(client.is_unreusable(), "预约越界 ⇒ 标记不可复用（剪枝，释放路径漏了必须可见）");
    }

    /// `ManagerPool<FakeConn>::get_or`：同 key 返回同一 manager。
    /// 对应 Go `globalDialerMap` 的语义（dialer.go:46-79）。
    #[test]
    fn manager_pool_returns_same_manager_for_same_key() {
        let pool: ManagerPool<FakeConn> = ManagerPool::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let cc = counter.clone();
        let mk = move || {
            let n = cc.fetch_add(1, Ordering::SeqCst);
            Arc::new(XmuxManager::new(XmuxConfig::default(), move || FakeConn::new(n)))
        };

        let m1 = pool.get_or("host:port:cfg", mk);
        let same_ref: Arc<XmuxManager<FakeConn>> = pool.get_or("host:port:cfg", || {
            panic!("factory must not be called for existing key");
        });
        let _ = same_ref;
        // 内部 Arc 一致
        assert!(Arc::ptr_eq(&m1, &same_ref));

        // 不同 key 新建
        let m2 = pool.get_or("other:port:cfg", || {
            Arc::new(XmuxManager::new(XmuxConfig::default(), || FakeConn::new(999)))
        });
        assert!(!Arc::ptr_eq(&m1, &m2));
        assert_eq!(pool.len(), 2);
    }

    fn mock_manager(id: usize) -> Arc<XmuxManager<FakeConn>> {
        Arc::new(XmuxManager::new(XmuxConfig::default(), move || FakeConn::new(id)))
    }

    /// 复用率实测（迁移前后同口径）：同 key 连续取多次恒同一 `Arc`、factory 恰
    /// 跑一次；不同 key 各自入表。守护 `get_or` 复用语义不因注册表换宿主
    /// （HashMap → BoundedRegistry）被稀释。
    #[test]
    fn manager_pool_reuse_rate_is_preserved_across_registry_swap() {
        let pool: ManagerPool<FakeConn> = ManagerPool::new();
        let first = pool.get_or("k", || mock_manager(0));
        for _ in 0..8 {
            let again = pool.get_or("k", || panic!("factory must run exactly once"));
            assert!(Arc::ptr_eq(&first, &again), "same key must reuse one manager");
        }
        for i in 0..8usize {
            let _ = pool.get_or(&format!("k{i}"), || mock_manager(i));
        }
        assert_eq!(pool.len(), 9, "9 distinct keys => 9 entries");
    }

    /// 反向自检：容量上界真实生效（max=1）——第二个 key 的 manager 照常返回但
    /// 不入表（`Reject`，fail-closed 不淘汰），且首个 key 的复用不受溢出影响。
    /// 若上界失效（无界直插），len 断言红。
    #[test]
    fn manager_pool_rejects_overflow_and_keeps_existing_reuse() {
        let pool: ManagerPool<FakeConn> = ManagerPool::with(1, Eviction::Reject);
        let m1 = pool.get_or("a", || mock_manager(1));
        let m2 = pool.get_or("b", || mock_manager(2));
        assert!(!Arc::ptr_eq(&m1, &m2), "distinct keys get distinct managers");
        assert_eq!(pool.len(), 1, "overflow entry must not enter the registry");
        let m1_again = pool.get_or("a", || panic!("existing key must be reused"));
        assert!(Arc::ptr_eq(&m1, &m1_again), "Reject must not break existing reuse");
    }

    /// 反证钉死（生产选 `Reject` 的依据）：`EvictOldest` 按 BTreeMap 字典序首键
    /// 淘汰（`"a" < "b"` ⇒ key "a" 被挤出），同 key 复用随之破坏——日后若有人把
    /// 生产策略改成淘汰，本断言翻红即拦截。
    #[test]
    fn evict_oldest_would_break_reuse_hence_reject() {
        let pool: ManagerPool<FakeConn> = ManagerPool::with(1, Eviction::EvictOldest);
        let m1 = pool.get_or("a", || mock_manager(0));
        let _m2 = pool.get_or("b", || mock_manager(1));
        let m1_again = pool.get_or("a", || mock_manager(2));
        assert!(
            !Arc::ptr_eq(&m1, &m1_again),
            "EvictOldest evicts the lexicographically first key ('a'<'b') and breaks reuse; \
             production must stay on Eviction::Reject"
        );
    }

    // ===== 缺省连接拓扑（bd m2mmm）=====

    /// 注入固定容量上限的 provider（测试替身）。
    fn fixed_capacity(cap: usize) -> CapacityProvider {
        Some(Arc::new(move || cap))
    }

    /// **我们的缺省**（`config::default_xmux_config()` = `maxConcurrency {1,1}`）
    /// ⇒ 每个并发请求独占一条连接：并发 N 次取用 ⇒ 池内 N 个 client。
    ///
    /// 回归锚：缺省曾是 Go 的 `maxConnections {3,3}`（固定 3 条复用）⇒ 高 RTT 腿
    /// 吞吐被连接数封顶（每连接 ≈ snd_wnd/RTT）。
    #[test]
    fn default_preset_gives_one_connection_per_concurrent_request() {
        let manager = Arc::new(XmuxManager::new_with_capacity(
            crate::config::default_xmux_config(),
            make_factory(),
            fixed_capacity(100),
        ));

        let clients = concurrent_burst(&manager, 10);

        let distinct: HashSet<usize> = clients.iter().map(|c| Arc::as_ptr(c) as usize).collect();
        assert_eq!(distinct.len(), 10, "缺省 ⇒ 每个并发请求独占一条连接");
        assert_eq!(manager.pool_size(), 10, "池按并发需求增长");
    }

    /// 缺省语义在**串行**取用下仍复用同一条连接（池不无谓增长）。
    #[test]
    fn default_preset_reuses_idle_connection_sequentially() {
        let manager = XmuxManager::new_with_capacity(
            crate::config::default_xmux_config(),
            make_factory(),
            fixed_capacity(100),
        );

        let mut first = None;
        for _ in 0..5 {
            let c = manager.get_xmux_client();
            // 模拟请求结束（dialer 的 set_on_close 回调路径）⇒ 释放占用。
            c.inc_open_usage();
            c.dec_open_usage();
            let ptr = Arc::as_ptr(&c) as usize;
            match first {
                None => first = Some(ptr),
                Some(p) => assert_eq!(p, ptr, "空闲 client 应被复用（缺省不无谓增长）"),
            }
        }
        assert_eq!(manager.pool_size(), 1, "串行取用只应开 1 条连接");
    }

    /// 显式 `maxConnections=K` ⇒ 池硬上限 K（**动态 provider 不得改写**用户值）。
    #[test]
    fn explicit_max_connections_is_hard_cap() {
        let mut config = XmuxConfig::default();
        config.max_connections = Some(crate::config::RangeConfig::new(2, 2));
        let manager = Arc::new(XmuxManager::new_with_capacity(
            config,
            make_factory(),
            fixed_capacity(1000), // provider 给很大 ⇒ 仍须 ≤ 2
        ));

        let clients = concurrent_burst(&manager, 10);

        assert_eq!(manager.pool_size(), 2, "显式 maxConnections=2 ⇒ 池恒 ≤ 2");
        let distinct: HashSet<usize> = clients.iter().map(|c| Arc::as_ptr(c) as usize).collect();
        assert!(distinct.len() <= 2, "10 次并发取用最多命中 2 个 client，实测 {}", distinct.len());
    }

    /// 显式 `maxConcurrency=M` ⇒ 单 client 承载 ≤ M；第 M+1 个并发需求 ⇒ 新 client。
    #[test]
    fn explicit_max_concurrency_bounds_per_client() {
        let mut config = XmuxConfig::default();
        config.max_concurrency = Some(crate::config::RangeConfig::new(2, 2));
        let manager = XmuxManager::new_with_capacity(config, make_factory(), fixed_capacity(100));

        let c1 = manager.get_xmux_client();
        let c2 = manager.get_xmux_client();
        assert_eq!(
            Arc::as_ptr(&c1) as usize,
            Arc::as_ptr(&c2) as usize,
            "占用 1 < M=2 ⇒ 同一 client 承载第二个请求"
        );
        let c3 = manager.get_xmux_client();
        assert_ne!(
            Arc::as_ptr(&c1) as usize,
            Arc::as_ptr(&c3) as usize,
            "占用达 M=2 ⇒ 新建 client（单 client 不得超 M）"
        );
        assert_eq!(manager.pool_size(), 2);
    }

    /// 动态容量上限（provider）约束池增长：给 1 ⇒ 池内 ≤ 1；给 100 ⇒ 可长到 100。
    #[test]
    fn provider_cap_bounds_pool_growth() {
        let manager = Arc::new(XmuxManager::new_with_capacity(
            crate::config::default_xmux_config(),
            make_factory(),
            fixed_capacity(1),
        ));
        let clients = concurrent_burst(&manager, 10);
        assert_eq!(manager.pool_size(), 1, "provider=1 ⇒ 池内 ≤ 1（不得新建越界）");
        let distinct: HashSet<usize> = clients.iter().map(|c| Arc::as_ptr(c) as usize).collect();
        assert_eq!(distinct.len(), 1, "达上限后复用同一 client");

        let manager = Arc::new(XmuxManager::new_with_capacity(
            crate::config::default_xmux_config(),
            make_factory(),
            fixed_capacity(100),
        ));
        let clients = concurrent_burst(&manager, 10);
        let distinct: HashSet<usize> = clients.iter().map(|c| Arc::as_ptr(c) as usize).collect();
        assert_eq!(distinct.len(), 10, "provider=100 ⇒ 池可增长到 100（10 并发 ⇒ 10 条）");
    }

    /// 池上限 = **内存份额派生值**，**不得**被单 client 并发上限 `M` 抬高
    /// （bd m2mmm 评审 S5：显式 `maxConcurrency=1000` 在 512MiB 盒上把池开到
    /// 1000 条 ⇒ 规划占用 ~3GiB ⇒ 突破「我们最多占整机一份」）。
    ///
    /// 评审前该用例固化的是**相反**行为（池上限 1 被 M=4 抬到 4）——那正是 S5
    /// 指出的越界行为，故按新契约重写（改动理由已报 PM）。
    #[test]
    fn pool_cap_is_memory_derived_and_not_raised_by_per_client_limit() {
        let mut config = XmuxConfig::default();
        config.max_concurrency = Some(crate::config::RangeConfig::new(4, 4));
        // provider=1 模拟「内存份额派生出的池上限 = 1」。
        let manager = XmuxManager::new_with_capacity(config, make_factory(), fixed_capacity(1));

        // 前 4 次取用都落在同一 client（占用 1..4 ≤ M=4）。
        let mut clients = Vec::new();
        for _ in 0..4 {
            clients.push(manager.get_xmux_client());
        }
        let first = Arc::as_ptr(&clients[0]) as usize;
        assert!(
            clients.iter().all(|c| Arc::as_ptr(c) as usize == first),
            "占用 < M ⇒ 同一 client 承载"
        );
        // 第 5 个并发需求 ⇒ 池上限（1）已满 ⇒ **不得**因 M=4 而开第 2 条连接。
        let c5 = manager.get_xmux_client();
        assert_eq!(
            first,
            Arc::as_ptr(&c5) as usize,
            "池上限 = 内存派生值 ⇒ M 不得抬高池（不得突破内存份额）"
        );
        assert_eq!(manager.pool_size(), 1, "池内 client 数不得超过内存派生上限");
    }

    /// 显式 `maxConcurrency=1000` @512MiB（份额上限 32）⇒ 池上限仍 ≤ 32 条。
    #[test]
    fn explicit_max_concurrency_cannot_raise_pool_over_memory_share() {
        let mut config = XmuxConfig::default();
        config.max_concurrency = Some(crate::config::RangeConfig::new(1000, 1000));
        // provider=32 = 512MiB 档的内存份额派生上限（small 档）。
        let manager = XmuxManager::new_with_capacity(config, make_factory(), fixed_capacity(32));

        assert!(
            manager.pool_cap() <= 32,
            "显式 M=1000 不得把池上限抬过内存份额上限（32），实得 {}",
            manager.pool_cap()
        );
    }

    /// 池增长到**内存份额上限**即停（M=4 不得把池抬到 4 条）。
    #[test]
    fn pool_growth_stops_at_memory_share_not_at_per_client_limit() {
        let mut config = XmuxConfig::default();
        config.max_concurrency = Some(crate::config::RangeConfig::new(4, 4));
        // provider=2 = 内存份额派生出的池上限。
        let manager =
            Arc::new(XmuxManager::new_with_capacity(config, make_factory(), fixed_capacity(2)));

        let clients = concurrent_burst(&manager, 10);

        assert_eq!(clients.len(), 10);
        assert_eq!(manager.pool_size(), 2, "池必须停在内存份额上限（2），不得被 M=4 抬到 4");
    }

    /// **B2**：建连失败（非 200 / 传输错误）⇒ 预约必须**归还**、client 必须**可剪枝**，
    /// 且下一次取用仍能拿到**新** client（不得静默退化成复用）。
    ///
    /// 反证锚：失败路径不释放预约 ⇒ 该 client 永远「占用中」⇒ 池被僵尸占满 ⇒
    /// `take_least_busy` 静默破坏「每请求一条连接」。
    #[test]
    fn dial_failure_releases_reservation_and_prunes_client() {
        let manager = Arc::new(XmuxManager::new_with_capacity(
            crate::config::default_xmux_config(),
            make_factory(),
            fixed_capacity(100),
        ));

        let c1 = manager.get_xmux_client();
        assert_eq!(c1.reserved(), 1, "取用即记预约");
        assert_eq!(manager.pool_size(), 1);

        // 模拟非 200 失败 ⇒ 池层回调：归还预约 + 标记不可复用。
        c1.conn.trigger_dial_failure();

        assert_eq!(c1.reserved(), 0, "失败路径必须归还取用预约（不得留幽灵预约）");
        assert!(c1.is_unreusable(), "失败 client 必须可被剪枝");

        // 下一次取用 ⇒ 失败 client 被剪掉 ⇒ 拿到**新** client。
        let c2 = manager.get_xmux_client();
        assert_ne!(
            Arc::as_ptr(&c1) as usize,
            Arc::as_ptr(&c2) as usize,
            "失败后必须换新 client（不得静默复用失败连接）"
        );
        assert_eq!(manager.pool_size(), 1, "失败 client 必须从池中剪掉");
        assert_eq!(c2.reserved(), 1, "新 client 记自己的预约");
    }

    /// **B2**：失败必须**有 WARN 日志**（可观测，不静默）。
    #[test]
    fn dial_failure_logs_warn() {
        let capture = WarnCapture::default();
        let manager = Arc::new(XmuxManager::new_with_capacity(
            crate::config::default_xmux_config(),
            make_factory(),
            fixed_capacity(100),
        ));
        let c1 = manager.get_xmux_client();

        {
            let _guard = tracing::subscriber::set_default(capture.clone());
            c1.conn.trigger_dial_failure();
        }

        let warnings = capture.messages();
        assert!(
            warnings.iter().any(|m| m.contains("xmux dial failed")),
            "建连失败必须留 WARN 痕迹，实际捕获：{warnings:?}"
        );
    }

    /// 极简 warn 捕获 subscriber（模式取自 xray-app-dns `WarnCapture`）：断言
    /// 真实 tracing 事件发出（非 mock）。
    #[derive(Clone, Default)]
    struct WarnCapture(Arc<parking_lot::Mutex<Vec<String>>>);

    impl tracing::Subscriber for WarnCapture {
        fn enabled(&self, meta: &tracing::Metadata<'_>) -> bool {
            meta.level() <= &tracing::Level::WARN
        }

        fn new_span(&self, _attrs: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _span: &tracing::span::Id, _id: &tracing::span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            struct Fmt(String);
            impl tracing::field::Visit for Fmt {
                fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                    self.0.push_str(&format!("{}={value} ", field.name()));
                }

                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    self.0.push_str(&format!("{}={value:?} ", field.name()));
                }
            }
            let mut v = Fmt(String::new());
            event.record(&mut v);
            self.0.lock().push(v.0);
        }

        fn enter(&self, _span: &tracing::span::Id) {}

        fn exit(&self, _span: &tracing::span::Id) {}
    }

    impl WarnCapture {
        fn messages(&self) -> Vec<String> {
            self.0.lock().clone()
        }
    }
}
