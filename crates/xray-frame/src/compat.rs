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
};

use skeleton::clock::{Clock, SystemClock};
use skeleton_infra::fx::{FxScope, ScopeClosed, Spawned, TaskError};

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
/// 滞留。与 [`REAP_EVERY`] 配套摊薄，口径同 [`crate::scope::ComponentScope::spawn`]；tick 进程级
/// 共享——生产常驻 scope 仅一份（fallback → permanent 装配期一次性换轨），每
/// scope 条目上界不破；`install_scoped` 测试窗口短暂多份并存且窗口内 spawn 数
/// 有限（上游修法不涉本仓，udf issue#13 缺口一）。
static SPAWN_REAP_TICK: AtomicUsize = AtomicUsize::new(0);

/// 便捷访问器：进程级托管 spawn（禁裸 spawn 的唯一替代口）。
///
/// 收割装配（bd s3tig）：走 [`spawn_reaping_ticked`] + `SPAWN_REAP_TICK`——每
/// [`REAP_EVERY`] 次 spawn 摊一次收割，已完成条目出集不再随累计任务数滞留
/// （上界 = [`REAP_EVERY`] - 1 + 在途数），条目内 panic 载荷经 `caps` 日志面上报。
/// 任务生命周期与拒发语义不变：句柄 abort 面 / 归属 scope drop=abort 同前（udf `JoinSet` 语义，实现事实），scope
/// 关闭仍回 `Err(ScopeClosed)`（新增仅一条拒发 warn，口径同 [`crate::scope::ComponentScope`]）。
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
/// [`crate::scope::ComponentScope::spawn`]，调用方无需各自处理。
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
