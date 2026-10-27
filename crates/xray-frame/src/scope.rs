//! 两级 scope 模型（面 6 · 能力收敛方案 §2 面 6）：arm scope（inbound 级）
//! → connection scope（每连接）。
//!
//! 派生三段式（ADR-1）：
//! - **udf 基件**：`skeleton_infra::fx::FxScope`（spawn 唯一托管口：生命周期集 + accepting 闸 +
//!   in_flight 计数）、`skeleton_infra::fx::{CancelSource, CancelToken,
//!   cancel_pair}`（取消对）、`CancelToken::run_until_cancelled` （取消 = None 形状）。
//! - **派生方式**：**组合包装**（arm 级 = 新 `FxScope` + 外接关闭广播 [`ArmScope`]；子 scope = 新
//!   `FxScope` + 外接取消源；父关 → 级联取消子）。 **不动父仓**——udf 的 `cancel_pair` /
//!   `run_until_cancelled` 已是足够扩展点。
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
//! **父闸信号的实现事实**（udf `FxScope` 语义边界）：`FxScope::close()` 只关
//! accepting 闸（拒新 spawn、放行在途），**不发取消信号、零通知**；且
//! `FxScope::with_source` 会消费外部 `CancelSource` → 外部无从触发其取消面。
//! 故父 → 子级联以 xray-frame 侧自建的关闭广播承担：arm 级 scope 一律经
//! [`ArmScope`] 持有（`close` = 关闸 + `watch` 广播同一同步段落账），子 scope
//! 经 [`ConnScope::child_of`] 订阅信号**事件驱动**级联取消——替代旧 20ms 闸位
//! 轮询（每连接 ≈50 次/秒空转唤醒，bd mzput），稳态零唤醒。

use std::{future::Future, sync::Arc, time::Duration};

use skeleton_infra::fx::{
    CancelSource, CancelToken, FxScope, ScopeClosed, Spawned, TaskError, cancel_pair,
};
use tokio::sync::watch;

/// arm 级父 scope（关闭信号中枢）：内嵌 udf `FxScope`（托管语义零变化）+
/// `watch` 关闭广播。**父级关闭事件必须经 [`ArmScope::close`]**——裸
/// `FxScope::close()` 无通知，绕过本件的关闸不会级联到 conn scope。
pub struct ArmScope {
    /// 内嵌托管 scope（spawn/闸/排空语义 = udf 原样）。
    fx: Arc<FxScope>,
    /// 关闭广播（true = 已关）。`send_replace` 对零订阅者无害；每接收端独立
    /// 版本账 → 关闭前后订阅都读得到终值（无丢失唤醒）。
    closed: watch::Sender<bool>,
}

impl ArmScope {
    /// 新建 arm scope（内部自建 udf `FxScope`；返回 `Arc` 便于跨任务共享）。
    pub fn new() -> Arc<Self> {
        let (closed, _) = watch::channel(false);
        Arc::new(Self { fx: Arc::new(FxScope::new()), closed })
    }

    /// 内嵌托管 scope（token / in_flight / `expect_idle` 等观察与 builder 面）。
    pub fn fx(&self) -> &Arc<FxScope> {
        &self.fx
    }

    /// 托管任务（等价 `self.fx().spawn`）。
    ///
    /// `#[inline(always)]`：薄透传不落真实栈帧——debug 构建不内联，本仓 xray-core
    /// inbound 深轮询链的测试线程栈余量已薄（mzput 实证：一层透传帧即可击穿
    /// 2MB 默认档），透传面必须栈中性；`always` 钉死决策防未来重编译翻转。
    #[inline(always)]
    pub fn spawn<T>(
        &self,
        fut: impl Future<Output = T> + Send + 'static,
    ) -> Result<Spawned<T>, ScopeClosed>
    where
        T: Send + 'static,
    {
        self.fx.spawn(fut)
    }

    /// accepting 闸读侧（true = 已关）。
    pub fn is_closed(&self) -> bool {
        self.fx.is_closed()
    }

    /// 停机排空（超时档；udf `FxScope::shutdown_timeout` 透传，内部自行关闸）。
    ///
    /// bd a9xgp：入口先广播关闭信号（同 [`Self::close`] 的父闸账）——排空形态的
    /// 停机与 close 形态**同必级联**到 conn scope（子 scope 监视任务 observe 广播
    /// → 取消），调用方不再需要「先 close 再 shutdown_timeout」的两步纪律。
    /// 幂等：重复广播仅多一次无害唤醒。
    pub async fn shutdown_timeout(&self, d: Duration) -> Result<(), TaskError> {
        self.closed.send_replace(true);
        self.fx.shutdown_timeout(d).await
    }

    /// 关闭：关 accepting 闸 + 广播关闭信号（同一同步段落账，子 scope 观察
    /// 到广播时闸必已关）。幂等：闸 CAS 幂等；watch 重复写同值仅多一次无害
    /// 唤醒，接收端读终值即知已关。广播不触碰本 scope 自身取消令牌（udf
    /// close 契约「close 只关闸不取消」保持）。
    pub fn close(&self) {
        self.fx.close();
        self.closed.send_replace(true);
    }
}

/// 连接级子 scope（生命周期 = 父 scope 存活期 ∧ 自身显式关闭）。
pub struct ConnScope {
    /// 本 scope 的托管任务（udf `FxScope`）。
    fx: Arc<FxScope>,
    /// 本 scope 的取消源（`close` / 父关 → cancel；共享给监视任务）。
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

    /// 从父 scope 派生（父 [`ArmScope::close`] → 本 scope 级联取消 → 本 scope
    /// 任务结束）。
    pub fn child_of(parent: &Arc<ArmScope>) -> Self {
        let scope = Self::new();
        // 订阅先行（无丢失唤醒的关键序）：watch 每接收端独立版本账——订阅即得
        // 当前值；此后的 send 必使本接收端版本落后，`changed()` 立即就绪。
        let mut closed = parent.closed.subscribe();
        // 父已关（注册前关闭窗口）：同步取消 + 关闸，不 spawn 监视任务——
        // 观察零延迟、与父关闭时刻的先后无关。
        if *closed.borrow_and_update() {
            scope.source.cancel();
            scope.fx.close();
            return scope;
        }
        // 生命周期锚：监视任务持父 Arc（旧闸位轮询持 `Arc<FxScope>` 同款）→
        // 子任务存活期间父 scope 不 drop，父内嵌 `FxScope` 寿命语义不变。
        let parent = Arc::clone(parent);
        let source = Arc::clone(&scope.source);
        let token = scope.token.clone();
        // 父关闭监视任务：挂起在 `changed()`（事件驱动，无定时器、无轮询）→
        // 父关 → 级联取消本 scope。任务归本 scope 托管 → 本 scope 先关时监视
        // 任务自身了结（不泄漏 in_flight 计数）。
        scope
            .fx
            .spawn(async move {
                let _parent = parent;
                tokio::select! {
                    // biased：取消优先裁决（本 scope 先关 → 监视任务立即了结）。
                    biased;
                    _ = token.cancelled() => return,
                    _ = wait_closed(&mut closed) => {}
                }
                source.cancel();
            })
            .expect("新建 scope 的 accepting 闸必开（构造期不可能已关）");
        scope
    }

    /// 托管任务（等价 `ctx.spawn`，但归属本连接 scope）。
    ///
    /// 返回的句柄 join 后得 `Option<T>`：`None` = 任务被 scope 取消（父关 /
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

/// 父关闭等待（watch 终值读法，无丢失唤醒论证）：
/// `borrow_and_update` 把「已读版本」推进到当前值；此后首次 `send` 使接收端
/// 版本落后 → `changed()` 就绪（翻转发生在 borrow 与 changed 的首次 poll 之间
/// 也一样——watch 以版本号判定，不依赖等待起点）。循环处理「读时 false、
/// changed 醒来仍是 false」的重复写伪唤醒，直至读到 true。
/// 发送端全亡（父中枢先于本任务 drop）按已关兜底取消（fail-closed）。
async fn wait_closed(closed: &mut watch::Receiver<bool>) {
    loop {
        if *closed.borrow_and_update() {
            return;
        }
        if closed.changed().await.is_err() {
            return;
        }
    }
}

/// arm scope 登记表（宿主停机编排面，bd a9xgp）：装配期按装配序登记每个 arm
/// 的 [`ArmScope`] 句柄，宿主 `close` 在 token cancel 后经
/// [`ArmScopeRegistry::close_all_reverse`] **逆序显式 close**——广播父闸 →
/// `ConnScope` 级联取消在途连接。裸 token cancel（不经宿主 close）形态由各 arm
/// 的停机监视任务兜底（消费方自建），本表只承载宿主编排面。
///
/// 登记泄漏口径：条目仅在 `close_all_reverse` 出清；宿主未 close 即退出 = 随表
/// drop（arm scope 及其任务随之结束，语义等同既有 Arc 归零 Drop 兜底）。
pub struct ArmScopeRegistry {
    /// 登记序 = 装配序；(tag, scope)。close 幂等，重复登记/重复关闭均无害。
    entries: std::sync::Mutex<Vec<(String, Arc<ArmScope>)>>,
}

impl ArmScopeRegistry {
    /// 空表（宿主实例构造期建一份，`Arc` 注入装配链）。
    pub fn new() -> Self {
        Self { entries: std::sync::Mutex::new(Vec::new()) }
    }

    /// 登记一个 arm scope（装配序追加；同 scope 重复登记仅多一条幂等条目）。
    pub fn register(&self, tag: impl Into<String>, scope: Arc<ArmScope>) {
        // 毒锁容忍（装配/停机期不得因别处 panic 拒绝登记或拒关停）：
        // 同 arm_builders intern 表先例，poison = 数据仍自洽（纯 Vec）直接取用。
        self.entries.lock().unwrap_or_else(|e| e.into_inner()).push((tag.into(), scope));
    }

    /// 逆序（后装配先关）显式 close 全部并清空登记，返回关闭条数（日志锚）。
    /// close 幂等：已被停机监视任务先关的 arm 在此重复 close 无害。
    pub fn close_all_reverse(&self) -> usize {
        let mut guard = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let taken = std::mem::take(&mut *guard);
        drop(guard);
        let count = taken.len();
        for (tag, scope) in taken.into_iter().rev() {
            scope.close();
            tracing::debug!(tag = %tag, "arm scope closed (reverse registration order)");
        }
        count
    }

    /// 当前登记数（诊断面；`close_all_reverse` 后为 0）。
    pub fn registered(&self) -> usize {
        self.entries.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

impl Default for ArmScopeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ArmScopeRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArmScopeRegistry").field("registered", &self.registered()).finish()
    }
}
