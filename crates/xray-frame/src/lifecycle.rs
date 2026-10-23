//! P0-4 生命周期三相状态机：init→start 按 deps 拓扑序编排 + 失败逆序回滚 +
//! 停机闭包编入 [`ShutdownCoordinator`](skeleton_infra::shutdown::ShutdownCoordinator)
//! 次序（模型 §2.2 L5 启动期相位硬校验；坑约束 #6 stop 必经编排器、#8 panic 不逃逸）。
//!
//! 编排语义（契约任务书 P0-4，PM 拍板 v0.1 全同步）：
//! - **逐插件 init→start 交替**（非全体 init 后全体 start）：第 k 插件 init 成功 即刻 start，观察序
//!   C,B,A。
//! - **回滚**：任一步失败 → 已 `start` 成功者逆序 `stop`（init 成功但 start 未 成功者不 stop——start
//!   是「已启动」判据）；回滚中单插件 stop 失败/panic 记录后继续，不阻断后续回滚。
//! - **注册**：全部 start 成功后按**启动序逆序**注册 stop 闭包（ShutdownCoordinator 注册序串行执行
//!   → 停机执行序 = 逆启动序）。注册被拒（`Duplicate`/`Closed`） → 整链回滚 + fail-visible 上抛。
//! - **panic 装甲**：init/start/stop 各包 `catch_unwind`，payload 提取转
//!   [`PluginError::Lifecycle`]（坑约束 #8）；tear_down 路径的 stop 由 coordinator
//!   编排面自带装甲捕获记 `Failed`。
//!
//! 停机闭包的 Framework 层生产接线（超时档位、FxScope 排空）归 P0-8；本件
//! 只对**传入的** coordinator 落注册与 tear_down 语义。

use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::Arc,
};

use skeleton_infra::shutdown::{RegisterError, ShutdownCoordinator, ShutdownReport};

use crate::{
    context::PluginContext,
    error::{LifecyclePhase, PluginError},
    logging::LogFacade,
    plugin::Plugin,
    registry::PluginRegistry,
};

/// 插件生命周期相位（单向迁移：Pending→Init→Started→Stopped；非法迁移 =
/// 装配期 bug，账本推进时断言拦截）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Pending,
    Init,
    Started,
    Stopped,
}

/// 一次装配的启动产物（逆序回滚与停机编排的账本）。
pub struct StartedPlugins {
    /// 启动序（=拓扑序）；停机注册按此向量逆序压入。
    plugins: Vec<(Arc<dyn Plugin>, Phase)>,
    coordinator: Arc<ShutdownCoordinator>,
}

/// 手写（`Arc<dyn Plugin>` 不可 derive）：打印插件名+相位，`Result` 错误路径
/// 可诊断（fail-visible 的可读半边）。
impl std::fmt::Debug for StartedPlugins {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StartedPlugins")
            .field(
                "plugins",
                &self.plugins.iter().map(|(p, phase)| (p.name(), phase)).collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

impl StartedPlugins {
    /// 停机编排收口：coordinator 按**注册序**（=逆启动序）串行执行全部 stop
    /// 闭包，返回全量报告（`is_clean()` 全 `Stopped` 才真）。
    pub fn tear_down(self) -> ShutdownReport {
        self.coordinator.shutdown()
    }

    /// 启动序账本观察面（相位应全 [`Phase::Started`]，tear_down 消费 self）。
    pub fn phases(&self) -> &[(Arc<dyn Plugin>, Phase)] {
        &self.plugins
    }
}

/// 启动编排：按 `registry.start_order()` 逐插件 init→start；任一步失败 →
/// 已启动者逆序 stop → `Err(PluginError::Lifecycle)`（ctx 构建失败原样上抛）。
pub fn bring_up(
    registry: &PluginRegistry,
    ctx_factory: impl Fn(&Arc<dyn Plugin>) -> Result<PluginContext, PluginError>,
    coordinator: Arc<ShutdownCoordinator>,
) -> Result<StartedPlugins, PluginError> {
    let order = registry.start_order()?;
    // 域 = infra 域（logging.rs 约定）；回滚路径的 stop 残障唯一留痕口。
    let log = LogFacade::new("assembly", vec![]);
    let mut ledger: Vec<(Arc<dyn Plugin>, Phase)> = Vec::with_capacity(order.len());

    for plugin in order {
        // ctx 构建在 init 之前，不属于任何相：失败原样上抛 + 回滚已启动。
        let ctx = match ctx_factory(&plugin) {
            Ok(ctx) => ctx,
            Err(source) => {
                rollback(&mut ledger, &log);
                return Err(source);
            },
        };
        let mut phase = Phase::Pending;
        if let Err(source) = guarded(&plugin, LifecyclePhase::Init, &ctx, |l, c| l.init(c)) {
            rollback(&mut ledger, &log);
            return Err(source);
        }
        advance(&mut phase, Phase::Init, plugin.name());
        if let Err(source) = guarded(&plugin, LifecyclePhase::Start, &ctx, |l, c| l.start(c)) {
            rollback(&mut ledger, &log);
            return Err(source);
        }
        advance(&mut phase, Phase::Started, plugin.name());
        ledger.push((plugin, phase));
    }

    // 全部启动成功 → 按启动序逆序注册（注册序 = coordinator 执行序 → 停机 =
    // 逆启动序）。注册被拒 = 整链失败：回滚已启动者再上抛。
    for index in (0..ledger.len()).rev() {
        let plugin = Arc::clone(&ledger[index].0);
        let closer = {
            let plugin = Arc::clone(&plugin);
            move || {
                // stop Err 升级为 panic：coordinator 装甲捕获记 `Failed`，
                // is_clean()==false——fail-visible，不静默吞 Err。
                if let Err(source) = plugin.lifecycle().stop() {
                    panic!("plugin {} stop failed: {source}", plugin.name());
                }
            }
        };
        if let Err(source) = coordinator.register(plugin.name(), closer) {
            rollback(&mut ledger, &log);
            return Err(register_failure(plugin.name(), source));
        }
    }

    Ok(StartedPlugins { plugins: ledger, coordinator })
}

/// init/start 统一装甲：`Err` 透传包 `Lifecycle`（source 链保原错误），panic
/// 提取 payload 转 `Lifecycle`——两路都标炸点插件与相。
fn guarded(
    plugin: &Arc<dyn Plugin>,
    phase: LifecyclePhase,
    ctx: &PluginContext,
    call: impl FnOnce(&dyn crate::plugin::Lifecycle, &PluginContext) -> Result<(), PluginError>,
) -> Result<(), PluginError> {
    let lifecycle = plugin.lifecycle();
    match catch_unwind(AssertUnwindSafe(|| call(lifecycle, ctx))) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(source)) => Err(PluginError::Lifecycle {
            plugin: plugin.name().to_string(),
            phase,
            source: Box::new(source),
        }),
        Err(payload) => Err(PluginError::Lifecycle {
            plugin: plugin.name().to_string(),
            phase,
            source: panic_payload_message(payload).into(),
        }),
    }
}

/// 回滚路径单插件 stop 装甲：失败/panic 记录后继续（不阻断后续插件回滚）。
fn rollback_stop(plugin: &Arc<dyn Plugin>, log: &LogFacade) {
    let name = plugin.name();
    match catch_unwind(AssertUnwindSafe(|| plugin.lifecycle().stop())) {
        Ok(Ok(())) => {},
        Ok(Err(source)) => {
            log.error(format!("assembly rollback: plugin {name} stop failed: {source}"))
        },
        Err(payload) => log.error(format!(
            "assembly rollback: plugin {name} stop panicked: {}",
            panic_payload_message(payload)
        )),
    }
}

/// 逆序回滚已 `start` 成功者；账本推进 `Stopped`（非法迁移由 advance 拦）。
fn rollback(ledger: &mut [(Arc<dyn Plugin>, Phase)], log: &LogFacade) {
    for (plugin, phase) in ledger.iter_mut().rev() {
        if *phase != Phase::Started {
            continue;
        }
        rollback_stop(plugin, log);
        advance(phase, Phase::Stopped, plugin.name());
    }
}

/// 账本单向迁移校验：非法迁移 = 装配期 bug（编排器内部不变量，用户输入不可
/// 触发），assert 携带插件名与迁移对，便于定位。
fn advance(phase: &mut Phase, to: Phase, plugin: &str) {
    let legal = matches!(
        (&*phase, to),
        (Phase::Pending, Phase::Init)
            | (Phase::Init, Phase::Started)
            | (Phase::Started, Phase::Stopped)
    );
    assert!(
        legal,
        "lifecycle ledger illegal transition for plugin {plugin}: {phase:?} -> {to:?} (assembly bug)"
    );
    *phase = to;
}

/// panic payload 提取：String/&str 原文；其他类型占位描述（payload 无稳定
/// 下行通道，兜底不失真为空串）。
fn panic_payload_message(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else {
        "non-string panic payload".to_string()
    }
}

/// 注册被拒转统一错误：`Duplicate` 语义同源映射；`Closed` 无专属变体走 `Other`
/// （source 链保原文）。
fn register_failure(plugin: &str, source: RegisterError) -> PluginError {
    match source {
        RegisterError::Duplicate(name) => PluginError::Duplicate { name },
        other => PluginError::Other(
            format!("plugin {plugin} stop registration rejected: {other}").into(),
        ),
    }
}
