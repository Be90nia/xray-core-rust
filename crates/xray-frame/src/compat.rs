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
    any::Any,
    fmt,
    future::Future,
    pin::Pin,
    sync::{Arc, LazyLock, Mutex, MutexGuard, PoisonError, RwLock},
    task::{Context, Poll},
    time::Duration,
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
/// 已知上界（udf 缺口，非本件引入）：udf `FxScope` 无增量收割口，已完成任务的
/// `JoinSet` 条目滞留到 `shutdown*` 才释放 → 长跑进程按 spawn 总数累积（每条约
/// 一个 `JoinHandle` 字节）。迁移前的自持账本靠"每次 spawn 前 try_join_next"
/// 压掉该窗口；恢复同等有界性需 udf 补 reap API（提炼候选，见 bd 4a1zy 备注）。
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
    /// 任务体经 [`CatchPanic`] 包装：panic 不再逃逸进 `FxScope` 生命周期集，
    /// 而是记一条 error 后**正常结束**（`in_flight` 照常归零，不留 panic 条目）。
    /// 运行期与停机 abort 窗口内被 poll 到的 panic 都在上报面内（语义对齐迁移前
    /// `harvest` 的 `background task panicked: {payload}`，bd 4a1zy 裁决①）。
    pub fn spawn<F>(&self, fut: F) -> Result<Spawned<()>, ScopeClosed>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let guarded = CatchPanic { fut, label: Arc::clone(&self.label), log: self.log.clone() };
        let spawned = self.scope.spawn_tracked(guarded);
        if spawned.is_err() {
            self.log.warn(format!("{}: spawn rejected (scope closed)", self.label));
        }
        spawned
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
    /// 超时 → `Err(TimedOut)` + 一条 error 报告。成功 = 一条 info 报告
    /// （`drained N`），保证停机事件在日志里可见。
    pub async fn shutdown_timeout(&self, timeout: Duration) -> Result<(), TaskError> {
        let pending = self.scope.in_flight();
        let outcome = self.scope.shutdown_timeout(timeout).await;
        match &outcome {
            Ok(()) => {
                self.log.info(format!("{}: drained {pending} background task(s)", self.label))
            },
            Err(e) => self.log.error(format!(
                "{}: shutdown incomplete ({pending} task(s) still in flight): {e}",
                self.label
            )),
        }
        outcome
    }
}

/// panic 捕获包装（`ManagedScope::spawn` 内部件）：包住任务体的 poll 端，
/// panic → 一条 error 报告 + 任务**正常结束**。
///
/// 为什么包 poll 端而不是用 `futures::FutureExt::catch_unwind`：`futures` 不在
/// 本 crate 依赖树，按裁决不为捕获功能新增依赖；`std::panic::catch_unwind` 是
/// 同步口，只能包住一次 `poll` 调用，故落地为最小 Future 适配。
/// `AssertUnwindSafe`：被包的是**别人的**任务体，跨 unwind 的借用残留由我们
/// 兜底（payload 只做 downcast，不碰内部状态），与 udf `task_body` 同口径。
struct CatchPanic<F> {
    fut: F,
    /// 域标识（panic 报告前缀；先克隆出来再 poll，避免借用横跨 catch_unwind）。
    label: Arc<str>,
    log: LogFacade,
}

impl<F: Future<Output = ()>> Future for CatchPanic<F> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let report = (Arc::clone(&self.label), self.log.clone());
        // SAFETY: 结构性 pin 投影——`fut` 是唯一被 pin 的字段，投影后不再移动。
        let fut = unsafe { self.map_unchecked_mut(|s| &mut s.fut) };
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| fut.poll(cx))) {
            Ok(poll) => poll,
            Err(payload) => {
                let (label, log) = report;
                log.error(format!("{label}: background task panicked: {}", panic_message(payload)));
                // 正常结束：对 FxScope 是"任务完成"→ in_flight 照常归零，零 panic 条目。
                Poll::Ready(())
            },
        }
    }
}

/// panic 载荷 → 文案（`&str` / `String` 下转，其余哨兵；口径同 udf
/// `TaskError::Panicked` / 迁移前 `harvest`）。
fn panic_message(payload: Box<dyn Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_owned()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "<non-string panic payload>".to_owned()
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

        scope.shutdown_timeout(Duration::from_secs(5)).await.expect("可 abort 的在途任务应能等净");
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

                let err = scope
                    .shutdown_timeout(Duration::from_millis(50))
                    .await
                    .expect_err("不可让渡的在途任务必须触发停机超时");
                assert_eq!(err, TaskError::TimedOut);

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

    /// bd 4a1zy 裁决①：被托管任务 panic 必须可观测（error 报告带载荷 + 域标识）
    /// 且不逃逸——wrapper 正常结束 ⇒ `in_flight` 归零、进程不因任务 panic 拉倒。
    #[test]
    fn managed_scope_reports_task_panic() {
        let captured = Arc::new(Mutex::new(Vec::<String>::new()));
        let sink = Arc::clone(&captured);
        std::thread::spawn(move || {
            let _guard = tracing::subscriber::set_default(Capture(sink));
            // current_thread：wrapper 的 emit 发生在**被 poll 的线程**，单线程
            // runtime 上就是本线程 → 线程局部门面捕获必命中（多线程会跨 worker
            // 逃出捕获窗；本用例任务体首 poll 即 panic-捕获-结束，无需并发 worker）。
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            rt.block_on(async move {
                let scope = ManagedScope::new("test-panic");
                scope.spawn(async { panic!("managed-scope boom") }).expect("spawn accepted");
                // wrapper 正常收尾 → in_flight 归零（panic 不留条目）；有界轮询。
                for _ in 0..200 {
                    if scope.in_flight() == 0 {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                assert_eq!(scope.in_flight(), 0, "panic 任务必须正常收尾（零残留）");
            });
        })
        .join()
        .expect("测试线程");

        let lines = captured.lock().unwrap_or_else(PoisonError::into_inner).join("\n");
        assert!(lines.contains("background task panicked"), "panic 必须上报: {lines:?}");
        assert!(lines.contains("managed-scope boom"), "panic 载荷必须带上: {lines:?}");
        assert!(lines.contains("test-panic"), "报告必须带域标识: {lines:?}");
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
