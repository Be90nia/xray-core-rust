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
    sync::{Arc, LazyLock, Mutex, MutexGuard, PoisonError, RwLock},
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

/// 便捷访问器：进程级托管 spawn（禁裸 spawn 的唯一替代口）。
pub fn spawn<T>(fut: impl Future<Output = T> + Send + 'static) -> Result<Spawned<T>, ScopeClosed>
where
    T: Send + 'static,
{
    spawn_scope().spawn_tracked(fut)
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
/// （issue#13）后提供增量收割口 `try_reap`，本件**每次 spawn 前先收割**——已完成
/// 条目即时出集（长跑进程不再按 spawn 总数累积），其中的 panic 载荷随之经本件落
/// 日志；停机排空（`shutdown_timeout`）返回 udf [`ShutdownReport`]，panic 清单与
/// 未完成数一并在本件上报（udf 侧此前丢弃 join 结果、静默丢条目的缺口已修）。
#[derive(Clone)]
pub struct ManagedScope {
    /// 日志域标识（拼进每条报告；`Arc<str>` 便于克隆进 'static future）。
    label: Arc<str>,
    scope: Arc<FxScope>,
    log: LogFacade,
}

impl ManagedScope {
    /// 自有 scope + 域 `compat` 门面（target `xray_frame::compat`）。
    pub fn new(label: impl Into<Arc<str>>) -> Self {
        Self {
            label: label.into(),
            scope: Arc::new(FxScope::new()),
            log: LogFacade::new("compat", Vec::new()),
        }
    }

    /// 托管 spawn：scope 已关（拒发）时记 warn 并回 `Err`。
    ///
    /// 每次 spawn 前先 `reap`（udf `try_reap`）——已完成条目即时出集，其中
    /// 的 panic 载荷当场落日志。udf `task_body` 自带 `catch_unwind`（panic 归一成
    /// `TaskError::Panicked` 双投 oneshot + 集合条目），故本件**不再包任务体**：
    /// 上报口径 = `background task panicked: {payload}`（同迁移前 `harvest`）。
    pub fn spawn<F>(&self, fut: F) -> Result<Spawned<()>, ScopeClosed>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.reap();
        let spawned = self.scope.spawn_tracked(fut);
        if spawned.is_err() {
            self.log.warn(format!("{}: spawn rejected (scope closed)", self.label));
        }
        spawned
    }

    /// 增量收割已完成条目（udf `try_reap`）：panic 载荷落 error，abort 条目是预期
    /// 消亡（`Cancelled`）不计；不动在途任务、不改 `in_flight`。
    ///
    /// 由 [`Self::spawn`] 每次调用前触发：spawn 速率 ≥ panic 速率时滞留窗口恒有界；
    /// 空闲期的 panic 由停机排空兜底上报（不会丢）。
    fn reap(&self) {
        for outcome in self.scope.try_reap() {
            if let TaskError::Panicked(msg) = outcome {
                self.log.error(format!("{}: background task panicked: {msg}", self.label));
            }
        }
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
                scope.spawn(async {}).expect("spawn 照常受理（panic 不传染 scope）");
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
