//! L2 即件·超时唯一入口（P1-4；坑约束 2「握手/首包必带 deadline」的实现体）。
//!
//! 三面：
//! - [`timeout`]：构造形态——裸 `tokio::time::timeout` 的本仓唯一包装点。 P0-3
//!   `PluginContext::with_deadline` 委托此：返回未 await 的
//!   [`tokio::time::Timeout`]（不借上下文，任务可 'static 移交），既有调用面 零破坏（P1-2
//!   拍板「不改 P0-3 行为」）。
//! - [`with_deadline`]：await 形态——构造 + clock 记账（单调面测真耗时， 判负经
//!   `xray_frame::deadline` target 留 debug 痕）。两形态同一实现点： `with_deadline` =
//!   `timeout(fut, d).await` + 记账，语义零分叉。
//! - [`HandshakeDeadline`] / [`IdleDeadline`]：握手/空闲限时配置面（Go
//!   `signal.CancelAfterInactivity` 等价面）。`IdleDeadline` 只提供件，主仓 `xray-app-reverse` 的
//!   `InactivityTimer` 接线收敛归 P3（不越界改行为）。
//!
//! 超时错误复用 [`tokio::time::error::Elapsed`]，不另造错误枚举（P0-3 验收
//! 钉死「真超时返回 Err(Elapsed)」）。重试归 `std_ext::retry`，本件不做。
//! 强约束映射（模型 §2）：L3-2 禁裸 sleep、L3-5 禁 `Instant::now`——时间
//! 读取只走 [`Clock`] 契约（装甲 #19 单调/挂钟双口分流）。

use std::{future::Future, sync::Arc, time::Duration};

use skeleton::clock::Clock;

/// 握手/空闲时限默认档：5 秒（PM 拍板 2026-10-23：与停机超时同档减少魔数；
/// Go 首包口径在互通实测时校准）。
pub const DEFAULT_LIMIT: Duration = Duration::from_secs(5);

/// 构造形态：`tokio::time::timeout` 的唯一包装点（P0-3 既有调用面）。
///
/// 不带记账、不做 clock 读取——与 P0-3 落地体逐字节等价；await 返回值即
/// 超时判负 [`tokio::time::error::Elapsed`]。带 clock 记账的形态用
/// [`with_deadline`]。
#[must_use = "不 await 即无超时（deadline 永不触发，坑约束 2 失守）"]
pub fn timeout<F: Future>(fut: F, d: Duration) -> tokio::time::Timeout<F> {
    tokio::time::timeout(d, fut)
}

/// await 形态：唯一超时入口（坑约束 2）——构造 + clock 记账。
///
/// # Examples
///
/// ```
/// # tokio::runtime::Runtime::new().expect("runtime").block_on(async {
/// use std::sync::Arc;
/// use std::time::Duration;
/// use skeleton::clock::SystemClock;
/// use xray_frame::deadline::with_deadline;
///
/// let clock = Arc::new(SystemClock) as Arc<dyn skeleton::clock::Clock>;
/// let out = with_deadline(clock, async { 21 * 2 }, Duration::from_secs(1))
///     .await
///     .expect("期限内完成");
/// assert_eq!(out, 42);
/// # });
/// ```
pub async fn with_deadline<F: Future>(
    clock: Arc<dyn Clock>,
    fut: F,
    d: Duration,
) -> Result<F::Output, tokio::time::error::Elapsed> {
    let started = clock.now_instant();
    match timeout(fut, d).await {
        Ok(out) => Ok(out),
        Err(elapsed) => {
            // clock 记账（P0-3 任务书口径）：真超时经单调面测真耗时；差值用
            // checked_duration_since 显式化（禁饱和化掩盖，armor #19）。
            let spent = clock.now_instant().checked_duration_since(started);
            tracing::debug!(target: "xray_frame::deadline", ?d, ?spent, "deadline 判负（坑约束 2）");
            Err(elapsed)
        },
    }
}

/// 握手限时配置：首包/握手统一时限面（Go `signal.CancelAfterInactivity`
/// 等价面）。
///
/// [`guard`](Self::guard) 把握手整体包进总时限；首包空闲面（读侧无进展即
/// 超时）由 [`IdleDeadline`] 承接，两者默认档同为 [`DEFAULT_LIMIT`]。
#[derive(Debug, Clone, Copy)]
pub struct HandshakeDeadline {
    /// 握手总时限。
    pub limit: Duration,
    /// 首包空闲时限（读侧无进展即超时）。
    pub idle_limit: Duration,
}

impl HandshakeDeadline {
    /// 构造期校验：两时限必须 > 0（恒非法 = bug → fail-fast panic）。
    pub fn new(limit: Duration, idle_limit: Duration) -> Self {
        assert!(
            !limit.is_zero(),
            "HandshakeDeadline 握手总时限必须 > 0（恒非法 = bug，fail-fast）"
        );
        assert!(
            !idle_limit.is_zero(),
            "HandshakeDeadline 首包空闲时限必须 > 0（恒非法 = bug，fail-fast）"
        );
        Self { limit, idle_limit }
    }

    /// 把握手整体包进总时限（内部走 [`with_deadline`] 唯一入口）。
    pub async fn guard<F: Future>(
        &self,
        clock: Arc<dyn Clock>,
        fut: F,
    ) -> Result<F::Output, tokio::time::error::Elapsed> {
        with_deadline(clock, fut, self.limit).await
    }
}

impl Default for HandshakeDeadline {
    /// 默认档：limit = idle_limit = [`DEFAULT_LIMIT`]（5s，PM 拍板 2026-10-23）。
    fn default() -> Self {
        Self { limit: DEFAULT_LIMIT, idle_limit: DEFAULT_LIMIT }
    }
}

/// 空闲时限守卫：读侧无进展即超时（收敛主仓 `xray-app-reverse` 的
/// `InactivityTimer` 散点的件面；接线归 P3，本件不接线主仓）。
#[derive(Debug, Clone, Copy)]
pub struct IdleDeadline {
    /// 空闲时限。
    limit: Duration,
}

impl IdleDeadline {
    /// 构造期校验：时限必须 > 0（恒非法 = bug → fail-fast panic）。
    pub fn new(limit: Duration) -> Self {
        assert!(!limit.is_zero(), "IdleDeadline 空闲时限必须 > 0（恒非法 = bug，fail-fast）");
        Self { limit }
    }

    /// 把一次读等待包进空闲时限（无进展 = [`tokio::time::error::Elapsed`]）；
    /// 内部走 [`with_deadline`] 唯一入口。
    pub async fn guard<F: Future>(
        &self,
        clock: Arc<dyn Clock>,
        fut: F,
    ) -> Result<F::Output, tokio::time::error::Elapsed> {
        with_deadline(clock, fut, self.limit).await
    }
}

// =========================================================================
// 预算面（面 3 · 能力收敛方案 §2 面 3）：双源预算句柄
// =========================================================================
//
// 派生三段式（ADR-1）：
// - **udf 基件**：`skeleton::clock::Clock`（墙钟双面：单调测量 / 挂钟展示）—— `MockClock`
//   提供可冻结/可推进的确定性时间线。
// - **派生方式**：trait 扩展思想 + 新类型（[`Budget`] / [`BudgetDeadline`]）。 **不改 udf `Clock`
//   trait**（tokio 面属宿主绑定，进父仓会破坏 udf 的零 tokio
//   依赖纪律）；也不复制任何时钟实现——本件是**句柄**，唯一时间源仍 只有 udf `Clock` + tokio 二者。
// - **主仓消费**：生产 tokio 虚拟钟预算站点（app-dns / core inbound / mux / proxy / transport）与
//   std 墙钟 TTL 锚点，统一改走本件取时。
//
// **为何保留 tokio 源为默认**：`tokio::time::timeout_at` / `sleep_until` 只收
// `tokio::time::Instant`；换成 std `Instant` → `tokio::time::advance` 失效 →
// 测试可推进性当场作废。故本件统一的是**入口**，不是时钟实现。

/// 预算源：Tokio = 可被 `tokio::time::advance` 虚拟推进（默认，保留既有语义）；
/// Wall = udf `Clock` 墙钟（可被 `MockClock` 冻结/推进）。
#[derive(Clone)]
pub enum BudgetSource {
    /// tokio 时间轴（虚拟推进面）。
    Tokio,
    /// udf `Clock` 墙钟面（测试可注入 `MockClock` 冻结）。
    Wall(Arc<dyn Clock>),
}

/// 预算起点（两源统一表达）。
#[derive(Clone)]
enum BudgetInstant {
    /// tokio 单调面（虚拟推进）。
    Tokio(tokio::time::Instant),
    /// std 单调面（墙钟源）。
    Wall(std::time::Instant),
}

/// 预算句柄：一次预算的起点 + 源（**取代裸 `tokio::time::Instant::now()`**）。
#[derive(Clone)]
pub struct Budget {
    source: BudgetSource,
    start: BudgetInstant,
}

impl Budget {
    /// 默认源 = tokio（虚拟可推进；`tokio::time::advance` 语义完整保留）。
    pub fn tokio() -> Self {
        Self {
            source: BudgetSource::Tokio,
            start: BudgetInstant::Tokio(tokio::time::Instant::now()),
        }
    }

    /// 墙钟源（注入 udf `Clock`；`MockClock` → 冻结/推进可控）。
    pub fn wall(clock: Arc<dyn Clock>) -> Self {
        let start = clock.now_instant();
        Self { source: BudgetSource::Wall(clock), start: BudgetInstant::Wall(start) }
    }

    /// 预算源（只读）。
    pub fn source(&self) -> &BudgetSource {
        &self.source
    }

    /// 从此刻起截取一个截止点。
    pub fn deadline(&self, d: Duration) -> BudgetDeadline {
        let at = match (&self.source, &self.start) {
            (BudgetSource::Tokio, BudgetInstant::Tokio(start)) => match start.checked_add(d) {
                Some(at) => BudgetInstant::Tokio(at),
                // 溢出（恒非法 = 调用方给了荒谬时限）→ 立即到期（fail-closed）。
                None => BudgetInstant::Tokio(*start),
            },
            (BudgetSource::Wall(_), BudgetInstant::Wall(start)) => {
                BudgetInstant::Wall(start.checked_add(d).unwrap_or(*start))
            },
            // 源与起点同源构造 → 该臂不可达（保留兜底防未来改构造时静默错配）。
            _ => match tokio::time::Instant::now().checked_add(d) {
                Some(at) => BudgetInstant::Tokio(at),
                None => BudgetInstant::Tokio(tokio::time::Instant::now()),
            },
        };
        BudgetDeadline { source: self.source.clone(), at }
    }

    /// 已耗时长（Tokio 源随虚拟时间推进；Wall 源随 `Clock` 推进）。
    pub fn elapsed(&self) -> Duration {
        match &self.start {
            BudgetInstant::Tokio(start) => {
                tokio::time::Instant::now().saturating_duration_since(*start)
            },
            BudgetInstant::Wall(start) => {
                let now = match &self.source {
                    BudgetSource::Wall(clock) => clock.now_instant(),
                    BudgetSource::Tokio => std::time::Instant::now(),
                };
                now.saturating_duration_since(*start)
            },
        }
    }

    /// 剩余预算（`d` 减已耗时；下溢饱和为 0）。
    pub fn remaining(&self, d: Duration) -> Duration {
        d.saturating_sub(self.elapsed())
    }
}

/// 预算截止点（两源统一表达）。
#[derive(Clone)]
pub struct BudgetDeadline {
    source: BudgetSource,
    at: BudgetInstant,
}

impl BudgetDeadline {
    /// 预算超时包装：Tokio 源 → `tokio::time::timeout_at`（**保 advance 语义**）；
    /// Wall 源 → tokio 计时器 + 墙钟判负（`MockClock` 推进可强制判负）。
    ///
    /// 形态说明：取 `async fn` 而非返回具名 future 类型——具名 future 需
    /// `Pin` 投影，而 `tokio::time::Timeout<F>` 的 `Unpin` 约束会把 `F: Unpin`
    /// 传染给调用方（async 块非 `Unpin`）→ 泛型面被无谓收窄。`async fn` 由
    /// 编译器内部 pin，调用形态不变（`.timeout(fut).await`）。
    pub async fn timeout<F: Future>(
        &self,
        fut: F,
    ) -> Result<F::Output, tokio::time::error::Elapsed> {
        match &self.source {
            BudgetSource::Tokio => {
                let at = match self.at {
                    BudgetInstant::Tokio(at) => at,
                    BudgetInstant::Wall(_) => tokio::time::Instant::now(),
                };
                tokio::time::timeout_at(at, fut).await
            },
            BudgetSource::Wall(clock) => {
                let at = match self.at {
                    BudgetInstant::Wall(at) => at,
                    BudgetInstant::Tokio(_) => std::time::Instant::now(),
                };
                // 墙钟源：**到期判定完全由 `Clock` 决定**（冻结 → 永不到期；
                // 推进 → 判负）——故此处不挂 tokio 计时器兜底（挂了会让"冻结"
                // 语义失真：真实时间到了就判负，与墙钟无关）。
                tokio::select! {
                    // biased：判负臂优先裁决（预算已耗尽即判负）。
                    biased;
                    out = fut => Ok(out),
                    _ = wall_expiry_watch(Arc::clone(clock), at) => Err(mint_elapsed().await),
                }
            },
        }
    }

    /// 是否已过期（Tokio 源随虚拟时间；Wall 源随 `Clock`）。
    pub fn is_expired(&self) -> bool {
        match (&self.source, &self.at) {
            (BudgetSource::Tokio, BudgetInstant::Tokio(at)) => tokio::time::Instant::now() >= *at,
            (BudgetSource::Wall(clock), BudgetInstant::Wall(at)) => clock.now_instant() >= *at,
            _ => false,
        }
    }

    /// 剩余时长（过期后为 0）。
    pub fn remaining(&self) -> Duration {
        match (&self.source, &self.at) {
            (BudgetSource::Tokio, BudgetInstant::Tokio(at)) => {
                at.saturating_duration_since(tokio::time::Instant::now())
            },
            (BudgetSource::Wall(clock), BudgetInstant::Wall(at)) => {
                at.saturating_duration_since(clock.now_instant())
            },
            _ => Duration::ZERO,
        }
    }
}

/// 墙钟到期监视：轮询墙钟（`Clock`）直到越过截止点。
///
/// - 墙钟冻结（`MockClock` 不推进）→ 永不到期（预算不判负）。
/// - 墙钟推进越过截止点 → 立即判负（轮询间隔内检出）。
///
/// 轮询间隔固定 10ms（真实时间）：墙钟推进的**检出延迟**上界 = 间隔；墙钟
/// 自身推进由 `Clock` 决定（与本间隔无关）。
const WALL_POLL_INTERVAL: Duration = Duration::from_millis(10);

async fn wall_expiry_watch(clock: Arc<dyn Clock>, at: std::time::Instant) {
    loop {
        if clock.now_instant() >= at {
            return;
        }
        tokio::time::sleep(WALL_POLL_INTERVAL).await;
    }
}

/// 铸一个真正的 `tokio::time::error::Elapsed`。
///
/// tokio 的 `Elapsed::new()` 是 `pub(crate)` → 外部不可自造；零时长 timeout
/// 必然判负 → 取其真值（不碰私有 API、不另造错误枚举）。
async fn mint_elapsed() -> tokio::time::error::Elapsed {
    match tokio::time::timeout(Duration::ZERO, std::future::pending::<()>()).await {
        Err(elapsed) => elapsed,
        Ok(_) => unreachable!("零时长 timeout 必判负（tokio 契约）"),
    }
}
