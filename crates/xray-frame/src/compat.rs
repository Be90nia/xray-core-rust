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
    sync::{Arc, LazyLock, Mutex, MutexGuard, PoisonError, RwLock},
};

use skeleton::clock::{Clock, SystemClock};
use skeleton_infra::fx::{FxScope, ScopeClosed, Spawned};

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
}
