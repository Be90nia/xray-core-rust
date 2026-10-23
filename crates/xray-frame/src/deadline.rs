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
