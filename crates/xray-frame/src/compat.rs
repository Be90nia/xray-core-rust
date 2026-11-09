//! 进程级能力入口（面 2 · 能力收敛方案 §2 面 2）：ctx 结构性不可达站点的
//! 唯一受管入口。
//!
//! 派生三段式（ADR-1 宪法条款）：
//! - **udf 基件**（零 Xray 语义）：`skeleton::clock::{Clock, SystemClock}`（墙钟
//!   面）、`skeleton_infra::fx::{FxScope, Spawned, ScopeClosed}`（任务托管面）、
//!   `skeleton_infra::logx`（日志分发面，经本仓 [`crate::logging::LogFacade`] 薄壳 消费）。
//! - **派生方式**：**组合包装**（三件组合成一份进程级能力快照）+ 新类型 [`CompatCaps`]。不复制 udf
//!   任何机制，只组合。
//! - **主仓消费**：拿不到实例级 ctx 的站点（纯函数 / 进程级 `LazyLock` 锚 / C ABI 回调边界 / legacy
//!   spawn 区）改调本模块的只读访问器。
//!
//! 语义纪律：
//! - **一次性安装**：重复 [`install`] → fail-visible（[`CompatAlreadyInstalled`]）， 禁静默覆盖。
//! - **兜底 = 迁移前行为**：未安装时 [`caps`] 返回 `SystemClock` + 自持 scope + 默认日志门面（≡
//!   迁移前的裸 `SystemTime::now` / 裸 spawn），站点行为不变。
//! - **测试隔离**：全局单槽禁被并行测试改写 → 测试走**显式注入**（把 [`CompatCaps`] 直接传参）或
//!   [`install_scoped`] 作用域守卫（守卫持有期间独占 全局锁 → 并发测试被串行化；drop 即还原）。
//! - **禁 thread_local 覆盖**：tokio 任务跨线程迁移，thread-local 不跟随 task → 语义错（ADR-2
//!   已否决该备选）。

use std::{
    fmt,
    future::Future,
    sync::{
        Arc, LazyLock, Mutex, MutexGuard, PoisonError, RwLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use skeleton::clock::{Clock, SystemClock};
use skeleton_infra::fx::{FxScope, ScopeClosed, ShutdownReport, Spawned, TaskError};

use crate::logging::LogFacade;

/// 进程级能力快照（不可变；clone = Arc 计数，非 Vec 克隆）。
#[derive(Clone)]
pub struct CompatCaps {
    /// 墙钟面（`Clock` 双口：单调测量 / 挂钟展示）。
    clock: Arc<dyn Clock>,
    /// 任务托管面（裸 spawn 的唯一替代口）。
    fx: Arc<FxScope>,
    /// 日志面（target/掩码表由构造期钉死）。
    log: LogFacade,
}

impl CompatCaps {
    /// 组合构造：三件能力源由装配根分别持有（异质源，非内聚数据结构）。
    pub fn new(clock: Arc<dyn Clock>, fx: Arc<FxScope>, log: LogFacade) -> Self {
        Self { clock, fx, log }
    }

    /// 兜底能力集（≡ 迁移前行为）：系统钟 + 自持 scope + 默认日志门面。
    ///
    /// 未 [`install`] 的站点读到这份 = 与迁移前逐字等价（系统挂钟、裸 spawn
    /// 语义、日志 target `xray_frame::compat`）。
    pub fn fallback() -> Self {
        Self::new(
            Arc::new(SystemClock),
            Arc::new(FxScope::new()),
            LogFacade::new("compat", Vec::new()),
        )
    }

    /// 时钟能力句柄。
    pub fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }

    /// 任务托管能力句柄。
    pub fn fx(&self) -> &Arc<FxScope> {
        &self.fx
    }

    /// 日志能力句柄。
    pub fn log(&self) -> &LogFacade {
        &self.log
    }
}

/// 重复安装（fail-visible）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompatAlreadyInstalled;

impl fmt::Display for CompatAlreadyInstalled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("compat caps already installed (process-level slot is one-shot)")
    }
}

impl std::error::Error for CompatAlreadyInstalled {}

/// 永久槽：装配根一次性安装（[`install`]）。
static PERMANENT: RwLock<Option<Arc<CompatCaps>>> = RwLock::new(None);
/// 临时槽：作用域安装（[`install_scoped`]）——优先于永久槽（测试隔离用）。
static SCOPED: RwLock<Option<Arc<CompatCaps>>> = RwLock::new(None);
/// 作用域安装的全局互斥：守卫持有期间并发作用域安装被串行化。
static SCOPED_LOCK: Mutex<()> = Mutex::new(());
/// 兜底能力集（进程级单例；`SystemClock` + 自持 scope + 默认日志门面）。
static FALLBACK: LazyLock<Arc<CompatCaps>> = LazyLock::new(|| Arc::new(CompatCaps::fallback()));

/// 装配期一次安装（重复 → fail-visible，禁静默覆盖）。
///
/// 生产调用点 = 装配根（启动早期）；站点首次触发懒加载锚必在其后。
pub fn install(caps: CompatCaps) -> Result<(), CompatAlreadyInstalled> {
    let mut slot = PERMANENT.write().unwrap_or_else(PoisonError::into_inner);
    if slot.is_some() {
        return Err(CompatAlreadyInstalled);
    }
    *slot = Some(Arc::new(caps));
    Ok(())
}

/// 作用域守卫：安装 → drop 还原（测试隔离专用）。
///
/// 持有期间独占全局互斥锁 → 并发作用域安装被串行化（故只用于确需改写进程级
/// 能力的少数测试）。生产路径禁用（走 [`install`] 一次性安装）。
pub struct CompatGuard {
    /// 还原点（进入前的临时槽内容）。
    prev: Option<Arc<CompatCaps>>,
    /// 全局互斥（drop 即释放 → 串行化窗口关闭）。
    _lock: MutexGuard<'static, ()>,
}

impl Drop for CompatGuard {
    fn drop(&mut self) {
        let mut slot = SCOPED.write().unwrap_or_else(PoisonError::into_inner);
        *slot = self.prev.take();
    }
}

/// 作用域安装（测试隔离用）：装入临时槽，守卫 drop 即还原。
///
/// 临时槽优先于永久槽 → 作用域安装期间 [`caps`] 读到临时那份。
///
/// **守卫窗口内 spawn 的归宿**：期间经 [`spawn`] 起的任务落在**临时** caps 的
/// scope 上——守卫 drop 后该 scope 若已无他引，`JoinSet` drop = abort 在途任务
/// （[`Spawned::join`] 回 `Cancelled`）。故并发用例经进程级访问器 spawn 时，须
/// 自持守卫到 join 完成（见 `tests/compat_caps.rs::process_scope_spawn_is_managed`）。
pub fn install_scoped(caps: CompatCaps) -> CompatGuard {
    let lock = SCOPED_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    let prev = {
        let mut slot = SCOPED.write().unwrap_or_else(PoisonError::into_inner);
        slot.replace(Arc::new(caps))
    };
    CompatGuard { prev, _lock: lock }
}

/// 只读访问：作用域槽 → 永久槽 → 兜底（迁移前行为）。
pub fn caps() -> Arc<CompatCaps> {
    if let Some(c) = SCOPED.read().unwrap_or_else(PoisonError::into_inner).as_ref() {
        return Arc::clone(c);
    }
    if let Some(c) = PERMANENT.read().unwrap_or_else(PoisonError::into_inner).as_ref() {
        return Arc::clone(c);
    }
    Arc::clone(&FALLBACK)
}

/// 兜底能力集单例（= 未安装时 [`caps`] 读到的那份）。
pub fn fallback_caps() -> Arc<CompatCaps> {
    Arc::clone(&FALLBACK)
}

/// 永久槽当前的能力集（未安装 = `None`）。
///
/// 只读观测面：装配根启动自检（G7：装没装、装的是哪份）经此确认；站点读能力
/// 仍走 [`caps`]（含作用域槽优先级）。
pub fn installed_caps() -> Option<Arc<CompatCaps>> {
    PERMANENT.read().unwrap_or_else(PoisonError::into_inner).clone()
}

/// 便捷访问器：进程级时钟（Arc 计数 +1，非克隆实现体）。
pub fn clock() -> Arc<dyn Clock> {
    Arc::clone(caps().clock())
}

/// 便捷访问器：进程级任务托管 scope。
pub fn spawn_scope() -> Arc<FxScope> {
    Arc::clone(caps().fx())
}

/// 便捷访问器：进程级日志门面（clone = Arc 计数 + 空分发缓存）。
pub fn log() -> LogFacade {
    caps().log().clone()
}

/// 进程级 [`spawn`] 的收割节流计数（bd s3tig）：udf `JoinSet` 条目只在
/// `try_reap`/`join_next` 出集，无收割装配点的 scope 条目按累计 spawn 数永久
/// 滞留。与 [`REAP_EVERY`] 配套摊薄，口径同 [`ManagedScope::spawn`]；tick 进程级
/// 共享——生产常驻 scope 仅一份（fallback → permanent 装配期一次性换轨），每
/// scope 条目上界不破；`install_scoped` 测试窗口短暂多份并存且窗口内 spawn 数
/// 有限（上游修法不涉本仓，udf issue#13 缺口一）。
static SPAWN_REAP_TICK: AtomicUsize = AtomicUsize::new(0);

/// 便捷访问器：进程级托管 spawn（禁裸 spawn 的唯一替代口）。
///
/// 收割装配（bd s3tig）：走 [`spawn_reaping_ticked`] + `SPAWN_REAP_TICK`——每
/// [`REAP_EVERY`] 次 spawn 摊一次收割，已完成条目出集不再随累计任务数滞留
/// （上界 = [`REAP_EVERY`] - 1 + 在途数），条目内 panic 载荷经 `caps` 日志面上报。
/// 任务生命周期与拒发语义不变：句柄 abort 面 / 归属 scope drop=abort 同前，scope
/// 关闭仍回 `Err(ScopeClosed)`（新增仅一条拒发 warn，口径同 [`ManagedScope`]）。
#[inline(always)]
pub fn spawn<T>(fut: impl Future<Output = T> + Send + 'static) -> Result<Spawned<T>, ScopeClosed>
where
    T: Send + 'static,
{
    let caps = caps();
    spawn_reaping_ticked(caps.fx(), caps.log(), "compat::spawn", Some(&SPAWN_REAP_TICK), fut)
}

/// 增量收割：把已完成条目清出 udf `JoinSet`，其中 panic 载荷落 `log`（abort
/// 条目 = 预期消亡，不计）。返回收割到的条目数（诊断/断言面）。
///
/// 收割语义 = udf `FxScope::try_reap`（非阻塞，不动在途任务、不改 `in_flight`）；
/// 本件只负责**上报形态**与**装配点**——无此装配点的 scope 条目按累计 spawn
/// 数永久滞留（udf issue#13 缺口一）。
pub fn reap_into(scope: &FxScope, log: &LogFacade, label: &str) -> usize {
    let reaped = scope.try_reap();
    let count = reaped.len();
    for outcome in reaped {
        if let TaskError::Panicked(msg) = outcome {
            log.error(format!("{label}: background task panicked: {msg}"));
        }
    }
    count
}

/// 收割节流间隔（O29）：长生命周期 scope 每 N 次 spawn 摊一次 `try_reap`。
///
/// `try_reap` 与 `spawn_tracked` 取的是**同一把** scope 锁 → 逐次收割 = 每 spawn
/// 两次加锁（每连接 2 次 spawn ⇒ 4 次全局锁）。摊薄后每连接 2 次，代价有界：
/// 已完成条目在每个 scope 内最多滞留 `REAP_EVERY - 1` 条（与 spawn 总次数无关）。
/// **停机排空不受影响**：`shutdown_timeout` 自走 join 循环收 JoinSet，panic 清单
/// 进 `ShutdownReport`（不经本路径，不丢）。
pub const REAP_EVERY: usize = 32;

/// 托管 spawn 的收割版（bd 86i4h 阶段1）：**先收割已完成条目、再入集新任务**
/// ——条目数跟随在途任务数而非累计任务数（长跑服务端「每连接一个任务」形态的
/// 内存只涨不降即由此消失）。拒发（`ScopeClosed`）与 panic 上报口径同
/// [`ManagedScope::spawn`]，调用方无需各自处理。
///
/// 逐次收割（无节流）；长生命周期 scope 用 [`spawn_reaping_ticked`] 摊薄。
/// spawn 速率 ≥ panic 速率时滞留窗口恒有界；空闲期 panic 由停机排空兜底上报
/// （udf `ShutdownReport::panicked`，不丢）。
///
/// `#[inline(always)]`：本件是每条连接的热路径透传口，薄帧不得成为栈开销
/// （xray-core inbound 深轮询链栈余量薄，mzput 实证）。
#[inline(always)]
pub fn spawn_reaping<T>(
    scope: &FxScope,
    log: &LogFacade,
    label: &str,
    fut: impl Future<Output = T> + Send + 'static,
) -> Result<Spawned<T>, ScopeClosed>
where
    T: Send + 'static,
{
    spawn_reaping_ticked(scope, log, label, None, fut)
}

/// 同 [`spawn_reaping`]，`tick` 由**该 scope 自持**（每 scope 一个计数）：`None`
/// = 逐次收割，`Some` = 每 [`REAP_EVERY`] 次收割一次。节流只改「何时收割」，不改
/// 收割语义与 JoinSet 归属（条目有界，panic 上报延迟 ≤ `REAP_EVERY` 次 spawn）。
#[inline(always)]
pub fn spawn_reaping_ticked<T>(
    scope: &FxScope,
    log: &LogFacade,
    label: &str,
    tick: Option<&AtomicUsize>,
    fut: impl Future<Output = T> + Send + 'static,
) -> Result<Spawned<T>, ScopeClosed>
where
    T: Send + 'static,
{
    if tick.is_none_or(|t| t.fetch_add(1, Ordering::Relaxed) % REAP_EVERY == 0) {
        reap_into(scope, log, label);
    }
    let spawned = scope.spawn_tracked(fut);
    if spawned.is_err() {
        log.warn(format!("{label}: spawn rejected (scope closed)"));
    }
    spawned
}

/// 托管任务面（bd 4a1zy）：组合包装 udf [`FxScope`]，四口 = `spawn` / `close` /
/// `in_flight` / `shutdown_timeout`。
///
/// 派生方式 = **组合包装**（不复制 udf 任何托管机制）。相对裸 `FxScope` 只加一条
/// Xray 语义：**拒发与停机未收净必须留日志**——udf 的两个静默面
/// （`spawn_tracked` 回 `Err(ScopeClosed)`、`shutdown_timeout` 回 `Err(TimedOut)`）
/// 在本件里落 `LogFacade` 报告，调用方不必各自处理（禁静默放弃）。
///
/// 生命周期：`ManagedScope` 的 Drop 不等不报，随内嵌 `Arc<FxScope>` 最后一份引用
/// 归零时 JoinSet Drop=abort 在途任务（udf 语义）。要"停机收口"必须显式调
/// [`Self::shutdown_timeout`]——它走 udf 三段（close 闸 → abort 在途 → 等净），
/// **不是**等任务自然跑完（口径同迁移前自持 `JoinSet` 的 drop=abort）。
///
/// 已知上界（迁移前自持账本的差异，已由上游补齐）：`FxScope` 在 udf `51c2428b`
/// （issue#13）后提供增量收割口 `try_reap`，本件每次 spawn 先收割（每
/// [`REAP_EVERY`] 次摊一次，O29）——已完成条目出集不再随 spawn 总数累积（滞留
/// 上限 `REAP_EVERY - 1` 条），其中的 panic 载荷随之经本件落日志；停机排空
/// （`shutdown_timeout`）返回 udf [`ShutdownReport`]，panic 清单与
/// 未完成数一并在本件上报（udf 侧此前丢弃 join 结果、静默丢条目的缺口已修）。
#[derive(Clone)]
pub struct ManagedScope {
    /// 日志域标识（拼进每条报告；`Arc<str>` 便于克隆进 'static future）。
    label: Arc<str>,
    scope: Arc<FxScope>,
    log: LogFacade,
    /// 收割节流计数（O29）：随 scope 共享（clone 同一份），每 [`REAP_EVERY`] 次
    /// spawn 摊一次 `try_reap`。
    tick: Arc<AtomicUsize>,
}

impl ManagedScope {
    /// 自有 scope + 域 `compat` 门面（target `xray_frame::compat`）。
    pub fn new(label: impl Into<Arc<str>>) -> Self {
        Self {
            label: label.into(),
            scope: Arc::new(FxScope::new()),
            log: LogFacade::new("compat", Vec::new()),
            tick: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// 托管 spawn：scope 已关（拒发）时记 warn 并回 `Err`。
    ///
    /// 走 [`spawn_reaping_ticked`]（udf `try_reap` + 入集，收割按本 scope 的 `tick`
    /// 摊薄）：已完成条目出集，其中的 panic 载荷落日志。udf `task_body` 自带
    /// `catch_unwind`（panic 归一成 `TaskError::Panicked` 双投 oneshot + 集合条目），
    /// 故本件**不再包任务体**：上报口径 = `background task panicked: {payload}`
    /// （同迁移前 `harvest`）。
    pub fn spawn<F>(&self, fut: F) -> Result<Spawned<()>, ScopeClosed>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        spawn_reaping_ticked(&self.scope, &self.log, &self.label, Some(&self.tick), fut)
    }

    /// 增量收割已完成条目（udf `try_reap`）并上报 panic；返回收割条数。
    ///
    /// [`Self::spawn`] 每次调用前已自动收割；本体供**无 spawn 的空闲期**显式
    /// 触发（调用方自定节拍），确保滞留窗口有界。
    pub fn reap(&self) -> usize {
        reap_into(&self.scope, &self.log, &self.label)
    }

    /// 暴露底层 [`FxScope`] 句柄：供「拿不到 PluginContext 但持有 ManagedScope」
    /// 的宿主把托管任务喂给统一托管口（如 `crate::pool::spawn_idle_pruner`）；
    /// 本门面语义（spawn 排程 / reap / 停机报告）不变（bd jovl4 接线授权）。
    #[must_use]
    pub fn fx_scope(&self) -> &FxScope {
        &self.scope
    }

    /// 关 accepting 闸（拒新 spawn，放行在途——udf `FxScope::close` 语义）。
    pub fn close(&self) {
        self.scope.close();
    }

    /// 在途任务数（排空断言锚）。
    pub fn in_flight(&self) -> usize {
        self.scope.in_flight()
    }

    /// 停机收口（udf 三段：close 闸 → abort 在途 → 等净，带超时）：任务是
    /// **被取消**而非被等完成（abortable 段零残留）；不可让渡的在途段会让等净
    /// 超时 → 报告 `timed_out > 0` + 一条 error。成功 = 一条 info 报告
    /// （`drained N`）；排空中收割到的任务 panic 逐条 error 上报（udf `issue#13`
    /// 前这条路径会静默丢弃 join 结果）。返回 udf `ShutdownReport` 供调用方断言。
    pub async fn shutdown_timeout(&self, timeout: Duration) -> ShutdownReport {
        let pending = self.scope.in_flight();
        let report = self.scope.shutdown_timeout(timeout).await;
        for msg in &report.panicked {
            self.log.error(format!("{}: background task panicked: {msg}", self.label));
        }
        if report.timed_out > 0 {
            self.log.error(format!(
                "{}: shutdown incomplete ({pending} task(s) in flight, {} unfinished at deadline)",
                self.label, report.timed_out
            ));
        } else {
            self.log.info(format!("{}: drained {pending} background task(s)", self.label));
        }
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_clock_is_system_clock() {
        let caps = CompatCaps::fallback();
        let now = caps.clock().now_system();
        let real = std::time::SystemTime::now();
        let delta = now.duration_since(real).or_else(|_| real.duration_since(now));
        assert!(
            delta.map(|d| d < std::time::Duration::from_secs(1)).unwrap_or(false),
            "兜底时钟 = 系统钟（now_system ≈ 真实挂钟）"
        );
    }

    #[test]
    fn scoped_install_shadows_and_is_dropped() {
        let marker = CompatCaps::fallback();
        {
            let _guard = install_scoped(marker.clone());
            // 比**内层能力句柄**（`install_scoped` 整体搬移结构 → 内层 Arc 同一
            // 份分配；外层 `Arc<CompatCaps>` 是新分配，比外层无意义）。
            assert!(Arc::ptr_eq(caps().clock(), marker.clock()), "作用域安装优先于永久/兜底");
        }
        // 与并发永久安装无关的判据：作用域那份**不再可见**（还原到永久槽或兜底）。
        assert!(!Arc::ptr_eq(caps().clock(), marker.clock()), "守卫 drop → 作用域那份不再可见");
    }

    #[test]
    fn duplicate_install_is_fail_visible() {
        install(CompatCaps::fallback()).expect("首次安装成功");
        let second = install(CompatCaps::fallback());
        assert!(matches!(second, Err(CompatAlreadyInstalled)), "重复安装 → fail-visible");
    }

    /// bd 4a1zy 验收①：停机 = udf 三段（close 闸 → abort 在途 → 等净）。口径
    /// 对齐迁移前自持 `JoinSet`（drop = abort 全组）：**不等**在途连接跑完，
    /// 只保证零残留 + 闸关拒发。连接级优雅终止由 inbound arm scope 先取消。
    #[tokio::test]
    async fn managed_scope_shutdown_aborts_and_zeroes_in_flight() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let scope = ManagedScope::new("test-drain");
        let done = Arc::new(AtomicBool::new(false));
        let task_done = Arc::clone(&done);
        scope
            .spawn(async move {
                tokio::time::sleep(Duration::from_millis(20)).await;
                task_done.store(true, Ordering::SeqCst);
            })
            .expect("scope 新建即 accepting");
        assert_eq!(scope.in_flight(), 1, "spawn 后在途数必须可见");

        let report = scope.shutdown_timeout(Duration::from_secs(5)).await;
        assert_eq!(report.timed_out, 0, "可 abort 的在途任务应能等净");
        assert!(report.panicked.is_empty(), "无 panic 任务不应有 panic 清单");
        assert!(!done.load(Ordering::SeqCst), "停机走 abort：不得等 20ms 任务跑完");
        assert_eq!(scope.in_flight(), 0, "等净后 in_flight 归零");

        // 排空后闸已关：拒发必须回 Err 且留日志（不静默吞）。
        assert!(scope.spawn(async {}).is_err(), "停机后拒发新任务");
    }

    /// bd 4a1zy 验收②：任务永不完成（poll 不让渡 → abort 落不了地）时停机
    /// **超时可见**：`Err(TimedOut)` + 一条带域标识的 error 报告，且剩余任务
    /// 最终收尾（零残留）。
    ///
    /// 捕获为何走专用线程 + `block_on`：`set_default` 是线程局部门面，测试任务
    /// 在多线程 runtime 上跨 worker 迁移会逃出捕获窗；`Runtime::block_on` 的
    /// future 恒在调用线程 poll，故捕获必定命中（不入全局槽 → 测试隔离）。
    #[test]
    fn managed_scope_shutdown_timeout_is_reported() {
        let captured = Arc::new(Mutex::new(Vec::<String>::new()));
        let sink = Arc::clone(&captured);
        std::thread::spawn(move || {
            let _guard = tracing::subscriber::set_default(Capture(sink));
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("runtime");
            rt.block_on(async move {
                use std::sync::atomic::{AtomicBool, Ordering};

                let scope = ManagedScope::new("test-timeout");
                let started = Arc::new(AtomicBool::new(false));
                let hold = Arc::new(AtomicBool::new(true));
                let (task_started, task_hold) = (Arc::clone(&started), Arc::clone(&hold));
                scope
                    .spawn(async move {
                        task_started.store(true, Ordering::SeqCst);
                        // 不可让渡的 poll：abort 只在任务回到 Pending 后生效 →
                        // drain 必然真超时（确定性构造，不靠固定 spin 余量）。
                        while task_hold.load(Ordering::Relaxed) {
                            std::hint::spin_loop();
                        }
                    })
                    .expect("spawn accepted");
                while !started.load(Ordering::SeqCst) {
                    tokio::task::yield_now().await;
                }

                let report = scope.shutdown_timeout(Duration::from_millis(50)).await;
                assert!(report.timed_out > 0, "不可让渡的在途任务必须计入停机超时");

                // 放行 → 剩余任务收尾（超时退回 = abort 兜底，禁留活口）。
                hold.store(false, Ordering::Relaxed);
                for _ in 0..200 {
                    if scope.in_flight() == 0 {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                assert_eq!(scope.in_flight(), 0, "超时后剩余任务必须收尾");
            });
        })
        .join()
        .expect("测试线程");

        let lines = captured.lock().unwrap_or_else(PoisonError::into_inner).join("\n");
        assert!(lines.contains("shutdown incomplete"), "停机超时必须上报（禁静默）: {lines:?}");
        assert!(lines.contains("test-timeout"), "报告必须带域标识: {lines:?}");
    }

    /// bd 4a1zy 裁决①（udf issue#13 后口径）：被托管任务 panic 必须可观测——
    /// 两条上报路径都验：①**运行期**（下次 `spawn` 前 `try_reap` 收割 → error 带
    /// 载荷 + 域标识）；②**停机期**（`ShutdownReport::panicked` 不再被丢弃）。
    /// 且 panic 不逃逸（`in_flight` 归零、进程不因任务 panic 拉倒）。
    #[test]
    fn managed_scope_reports_task_panic() {
        let captured = Arc::new(Mutex::new(Vec::<String>::new()));
        let sink = Arc::clone(&captured);
        std::thread::spawn(move || {
            let _guard = tracing::subscriber::set_default(Capture(sink));
            // 捕获窗为何走专用线程 + `block_on`：`set_default` 是线程局部门面，
            // 任务在多线程 runtime 上跨 worker 迁移会逃出捕获窗；`block_on` 的
            // future 恒在调用线程 poll，故捕获必命中（不入全局槽 → 测试隔离）。
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            rt.block_on(async move {
                // ① 运行期路径：panic 任务终局后，下一次 spawn 触发收割即上报。
                let scope = ManagedScope::new("test-panic");
                let panicked =
                    scope.spawn(async { panic!("managed-scope boom") }).expect("spawn accepted");
                for _ in 0..200 {
                    if panicked.is_finished() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                assert!(panicked.is_finished(), "panic 任务必须终局（udf task_body 归一）");
                // 收割按 REAP_EVERY 摊薄（O29）→ 触发面要够一整轮才轮到收割。
                for _ in 0..REAP_EVERY {
                    scope.spawn(async {}).expect("spawn 照常受理（panic 不传染 scope）");
                }
                for _ in 0..200 {
                    if scope.in_flight() == 0 {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                assert_eq!(scope.in_flight(), 0, "panic 任务必须正常收尾（零残留）");

                // ② 停机期路径：排空中收割的 panic 进报告（issue#13 前是静默丢弃）。
                // 任务须**先被 poll 到 panic** 再停机——否则 abort 抢先，任务根本没跑过，
                // 报告里当然没有载荷（那不是缺口，是没发生）。
                let scope = ManagedScope::new("test-panic-drain");
                let drain_task =
                    scope.spawn(async { panic!("drain boom") }).expect("spawn accepted");
                for _ in 0..200 {
                    if drain_task.is_finished() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                assert!(drain_task.is_finished(), "panic 任务必须先跑完再验停机路径");
                let report = scope.shutdown_timeout(Duration::from_secs(5)).await;
                assert!(
                    report.panicked.iter().any(|m| m.contains("drain boom")),
                    "停机报告必须带 panic 载荷: {:?}",
                    report.panicked
                );
            });
        })
        .join()
        .expect("测试线程");

        let lines = captured.lock().unwrap_or_else(PoisonError::into_inner).join("\n");
        assert!(lines.contains("background task panicked"), "运行期 panic 必须上报: {lines:?}");
        assert!(lines.contains("managed-scope boom"), "panic 载荷必须带上: {lines:?}");
        assert!(lines.contains("test-panic"), "报告必须带域标识: {lines:?}");
        assert!(lines.contains("drain boom"), "停机期 panic 必须上报: {lines:?}");
    }

    /// bd 86i4h 阶段1 验收：`spawn_reaping` 的收割分类——`Panicked` 载荷上报
    /// （error+域标识）、`Cancelled`（abort=预期消亡）不上报、`Ok` 条目静默出集；
    /// 二次收割为空（条目真的清出，不是计数漂移）。拒发（闸关）走 warn 上报。
    #[test]
    fn spawn_reaping_classifies_panic_cancelled_ok_and_rejects() {
        let captured = Arc::new(Mutex::new(Vec::<String>::new()));
        let sink = Arc::clone(&captured);
        std::thread::spawn(move || {
            // set_default（线程局部门面）+ block_on：future 恒在调用线程 poll，
            // 捕获必定命中（多线程 runtime 上任务跨 worker 迁移会逃出捕获窗）。
            let _guard = tracing::subscriber::set_default(Capture(sink));
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            rt.block_on(async move {
                let scope = FxScope::new();
                let log = LogFacade::new("test-reap", Vec::new());

                // ① panic（句柄即弃 → 载荷只在集合面）
                drop(
                    spawn_reaping(&scope, &log, "reap-test", async { panic!("reap-boom") })
                        .expect("spawn accepted"),
                );
                // ② 正常完成（Ok 条目）
                drop(spawn_reaping(&scope, &log, "reap-test", async {}).expect("spawn accepted"));
                // ③ abort（Cancelled 条目）
                let doomed = spawn_reaping(&scope, &log, "reap-test", async {
                    std::future::pending::<()>().await
                })
                .expect("spawn accepted");
                doomed.abort();

                for _ in 0..200 {
                    if scope.in_flight() == 0 {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
                assert_eq!(scope.in_flight(), 0, "三类任务都必须终局（panic 不逃逸）");

                let reaped = reap_into(&scope, &log, "reap-test");
                assert_eq!(
                    reaped, 2,
                    "try_reap 只回错误结局（Panicked + Cancelled）；Ok 条目静默出集: {reaped}"
                );
                assert_eq!(reap_into(&scope, &log, "reap-test"), 0, "二次收割空（幂等）");

                // 拒发可见：闸关后 spawn 回 Err 且留 warn（禁静默放弃）。
                scope.close();
                assert!(
                    spawn_reaping(&scope, &log, "reap-test", async {}).is_err(),
                    "闸关后必须拒发"
                );
            });
        })
        .join()
        .expect("测试线程");

        let lines = captured.lock().unwrap_or_else(PoisonError::into_inner).join("\n");
        assert!(lines.contains("background task panicked"), "panic 必须上报: {lines:?}");
        assert!(lines.contains("reap-boom"), "panic 载荷必须带上: {lines:?}");
        assert!(lines.contains("reap-test"), "报告必须带域标识: {lines:?}");
        assert!(lines.contains("spawn rejected"), "拒发必须上报: {lines:?}");
        assert_eq!(
            lines.matches("background task panicked").count(),
            1,
            "Cancelled（abort）不得计入 panic 上报: {lines:?}"
        );
    }

    /// bd s3tig 验收：`spawn_reaping_ticked` 的节流两态——非触发位**不**收割
    /// （完成条目滞留 = 进程级 `compat::spawn` 修复前的泄漏形态，且上报面静默），
    /// 连续 [`REAP_EVERY`] 次调用必含一个触发位（`prev % REAP_EVERY == 0`）→
    /// 滞留条目清出集合并上报。判别器 = `try_reap()` 错误结局（Panicked 条目真在
    /// 集合里才数得出）+ Capture 日志；tick 为本地值，无全局态，全确定性。
    #[test]
    fn spawn_reaping_ticked_holds_between_and_reaps_on_threshold() {
        let captured = Arc::new(Mutex::new(Vec::<String>::new()));
        let sink = Arc::clone(&captured);
        std::thread::spawn(move || {
            let _guard = tracing::subscriber::set_default(Capture(sink));
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            rt.block_on(async move {
                let scope = FxScope::new();
                let log = LogFacade::new("ticked-test", Vec::new());
                let tick = AtomicUsize::new(1); // 1..=REAP_EVERY-1 = 非触发位

                // ① 非触发位：完成条目滞留集合，载荷不上报（静默滞留形态）。
                let boom = spawn_reaping_ticked(&scope, &log, "ticked", Some(&tick), async {
                    panic!("park-boom")
                })
                .expect("spawn accepted");
                while !boom.is_finished() {
                    tokio::task::yield_now().await;
                }
                drop(boom); // 载荷只在集合面
                let held = scope.try_reap();
                assert_eq!(held.len(), 1, "非触发位不得收割（节流语义）: {held:?}");
                assert!(
                    matches!(&held[0], TaskError::Panicked(m) if m.contains("park-boom")),
                    "滞留条目必须带 panic 载荷: {held:?}"
                );

                // ② 触发位：本 spawn（prev=2）不触发；下面 REAP_EVERY 次连发
                // （prev=3..）在 prev % REAP_EVERY == 0 处必触发一次 → 清出并上报。
                let boom2 = spawn_reaping_ticked(&scope, &log, "ticked", Some(&tick), async {
                    panic!("threshold-boom")
                })
                .expect("spawn accepted");
                while !boom2.is_finished() {
                    tokio::task::yield_now().await;
                }
                drop(boom2);
                for _ in 0..REAP_EVERY {
                    spawn_reaping_ticked(&scope, &log, "ticked", Some(&tick), async {})
                        .expect("spawn accepted");
                }
                assert!(scope.try_reap().is_empty(), "触发位 spawn 必须收割（滞留条目清出集合）");
            });
        })
        .join()
        .expect("测试线程");

        let lines = captured.lock().unwrap_or_else(PoisonError::into_inner).join("\n");
        assert!(
            !lines.contains("park-boom"),
            "非触发位条目未清出 → 不得上报（静默滞留形态）: {lines:?}"
        );
        assert!(lines.contains("background task panicked"), "触发位收割必须上报 panic: {lines:?}");
        assert!(lines.contains("threshold-boom"), "panic 载荷必须带上: {lines:?}");
        assert!(lines.contains("ticked"), "报告必须带域标识: {lines:?}");
    }

    /// 接线验收（bd 86i4h 阶段1）：`ArmScope::spawn` / `ConnScope::spawn` 内部
    /// 已走 `spawn_reaping`——panic 载荷在**下一次 spawn** 被清出集合并上报，
    /// 不再滞留到停机（长跑服务端「每连接一任务」的内存只涨不降）。
    ///
    /// 判别器：`ArmScope::fx().try_reap()` 只剩 0 条 = 前一次的 panic 条目已被
    /// spawn 内置收割吃掉（未接线时它仍在集合里，返回 1 条）。
    #[test]
    fn scope_spawn_reaps_and_reports_panic() {
        let captured = Arc::new(Mutex::new(Vec::<String>::new()));
        let sink = Arc::clone(&captured);
        std::thread::spawn(move || {
            let _guard = tracing::subscriber::set_default(Capture(sink));
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            rt.block_on(async move {
                let arm = crate::scope::ArmScope::new();
                let doomed = arm.spawn(async { panic!("arm-boom") }).expect("spawn accepted");
                while !doomed.is_finished() {
                    tokio::task::yield_now().await;
                }
                drop(doomed); // 句柄丢弃：载荷只在集合面
                // 收割按 REAP_EVERY 摊薄（O29）→ 触发面要够一整轮才轮到收割。
                for _ in 0..REAP_EVERY {
                    let _ = arm.spawn(async {}).expect("spawn accepted");
                }
                assert_eq!(
                    arm.fx().try_reap().len(),
                    0,
                    "ArmScope::spawn 必须内置收割（panic 条目不得滞留）"
                );

                let conn = crate::scope::ConnScope::new();
                let doomed = conn.spawn(async { panic!("conn-boom") }).expect("spawn accepted");
                while !doomed.is_finished() {
                    tokio::task::yield_now().await;
                }
                drop(doomed);
                let probe = conn.spawn(async {}).expect("spawn accepted");
                while !probe.is_finished() {
                    tokio::task::yield_now().await;
                }

                for _ in 0..200 {
                    if conn.in_flight() == 0 {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
                assert_eq!(conn.in_flight(), 0, "任务必须终局（panic 不逃逸）");
            });
        })
        .join()
        .expect("测试线程");

        let lines = captured.lock().unwrap_or_else(PoisonError::into_inner).join("\n");
        assert!(lines.contains("arm-boom"), "ArmScope 收割必须上报 panic: {lines:?}");
        assert!(lines.contains("conn-boom"), "ConnScope 收割必须上报 panic: {lines:?}");
    }

    /// 事件捕获订阅器：只把日志文本收进 `Vec`（线程局部安装，不抢全局槽）。
    struct Capture(Arc<Mutex<Vec<String>>>);

    impl tracing::Subscriber for Capture {
        fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            struct Text(String);
            impl tracing::field::Visit for Text {
                fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                    self.0.push_str(&format!("{}={value} ", field.name()));
                }

                fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
                    self.0.push_str(&format!("{}={value:?} ", field.name()));
                }
            }
            let mut text = Text(String::new());
            event.record(&mut text);
            self.0.lock().unwrap_or_else(PoisonError::into_inner).push(text.0);
        }

        fn enter(&self, _span: &tracing::span::Id) {}

        fn exit(&self, _span: &tracing::span::Id) {}
    }
}
