//! 两级 scope 模型（面 6 · 能力收敛方案 §2 面 6）：arm scope（inbound 级）
//! → connection scope（每连接）。
//!
//! 派生三段式（ADR-1）：
//! - **udf 基件**：`skeleton_infra::fx::FxScope`（spawn 唯一托管口：生命周期集 + accepting 闸 +
//!   in_flight 计数）、`skeleton_infra::fx::{CancelSource, CancelToken,
//!   cancel_pair}`（取消对）、`CancelToken::run_until_cancelled` （取消 = None 形状）。
//! - **派生方式**：**组合包装**（子 scope = 新 `FxScope` + 外接取消源；父闸关 →
//!   级联取消子）。**不动父仓**——udf 的 `cancel_pair` / `run_until_cancelled` 已是足够扩展点。
//! - **主仓消费**：`crates/xray-core/src/inbound.rs`（mux link ×4 / SS 泵 ×1 / 监控壳 ×2 / vision
//!   ×2 / tun ×1）。
//!
//! **为何两级能表达 mux link 的跨连接生命周期**：mux carrier 的任务寿命 =
//! "直到 carrier 连接关闭"，与触发它的那个 inbound 连接不同寿命，但与 **arm
//! scope**（inbound 级）同寿命。旧判定"迁 = scope 归属改挂非宿主连接，语义不等
//! 价"成立的原因是**只有一层 scope**（挂 arm scope 会让 carrier 随 inbound 一起
//! 死，或挂连接 scope 会随连接死）。两级模型下：carrier 任务归 **arm scope**，
//! 每连接任务归 **connection scope**（连接断 → 该连接任务结束，不影响 sibling
//! 连接）。
//!
//! **父闸信号的实现事实**（udf `FxScope` 语义边界，非本件选择）：`FxScope::close()`
//! 只关 accepting 闸（拒新 spawn、放行在途），**不发取消信号**；且
//! `FxScope::with_source` 会消费外部 `CancelSource` → 外部无从触发其取消面。
//! 故父 → 子级联以**闸位轮询**（[`PARENT_POLL_INTERVAL`]）实现：父闸关 → 子
//! scope 取消 → 子任务结束。

use std::{future::Future, sync::Arc, time::Duration};

use skeleton_infra::fx::{CancelSource, CancelToken, FxScope, ScopeClosed, Spawned, cancel_pair};

/// 父闸监视间隔（父 close → 子级联取消的检测粒度）。
const PARENT_POLL_INTERVAL: Duration = Duration::from_millis(20);

/// 连接级子 scope（生命周期 = 父 scope 存活期 ∧ 自身显式关闭）。
pub struct ConnScope {
    /// 本 scope 的托管任务（udf `FxScope`）。
    fx: Arc<FxScope>,
    /// 本 scope 的取消源（`close` / 父闸关 → cancel；共享给监视任务）。
    source: Arc<CancelSource>,
    /// 本 scope 的观察令牌（任务内携带判停）。
    token: CancelToken,
}

impl ConnScope {
    /// 独立连接 scope（无父；`close` 即终点）。
    pub fn new() -> Self {
        let (source, token) = cancel_pair();
        Self { fx: Arc::new(FxScope::new()), source: Arc::new(source), token }
    }

    /// 从父 scope 派生（父闸关 → 本 scope 级联取消 → 本 scope 任务结束）。
    pub fn child_of(parent: &Arc<FxScope>) -> Self {
        let scope = Self::new();
        let parent = Arc::clone(parent);
        let source = Arc::clone(&scope.source);
        let token = scope.token.clone();
        // 父闸监视任务：父 `close()`（accepting 闸关）→ 级联取消本 scope。
        // 任务归本 scope 托管 → 本 scope 关闭时监视任务自身了结（不泄漏
        // in_flight 计数）。
        scope
            .fx
            .spawn(async move {
                loop {
                    tokio::select! {
                        // biased：取消优先裁决（scope 已关 → 监视任务立即了结）。
                        biased;
                        _ = token.cancelled() => return,
                        _ = tokio::time::sleep(PARENT_POLL_INTERVAL) => {
                            if parent.is_closed() {
                                source.cancel();
                                return;
                            }
                        }
                    }
                }
            })
            .expect("新建 scope 的 accepting 闸必开（构造期不可能已关）");
        scope
    }

    /// 托管任务（等价 `ctx.spawn`，但归属本连接 scope）。
    ///
    /// 返回的句柄 join 后得 `Option<T>`：`None` = 任务被 scope 取消（父闸关 /
    /// 本 scope 关闭）而非正常完成——取消语义必须与"完成"可区分（禁静默把
    /// 取消当成功）。
    pub fn spawn<T>(
        &self,
        fut: impl Future<Output = T> + Send + 'static,
    ) -> Result<Spawned<Option<T>>, ScopeClosed>
    where
        T: Send + 'static,
    {
        let token = self.token.clone();
        self.fx.spawn(async move { token.run_until_cancelled(fut).await })
    }

    /// 取消令牌观察面（任务内携带判停）。
    pub fn token(&self) -> CancelToken {
        self.token.clone()
    }

    /// 显式关闭本 scope（连接结束）：取消 + 关闸（拒新 spawn）。
    pub fn close(&self) {
        self.source.cancel();
        self.fx.close();
    }

    /// 停机（取消 + abort 在途任务 + 等净）。
    pub async fn shutdown(&self) {
        self.source.cancel();
        self.fx.shutdown().await;
    }

    /// 在途任务数（泄漏断言锚）。
    pub fn in_flight(&self) -> usize {
        self.fx.in_flight()
    }

    /// accepting 闸读侧（true = 可 spawn）。
    pub fn is_closed(&self) -> bool {
        self.fx.is_closed()
    }
}

impl Default for ConnScope {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ConnScope {
    /// 析构 = 关闭（取消 + 关闸）：scope 主人走了 → 其任务不得继续跑
    /// （否则 in_flight 永归零不了 = 泄漏）。
    fn drop(&mut self) {
        self.source.cancel();
        self.fx.close();
    }
}
