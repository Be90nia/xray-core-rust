//! 状态环解释器（`EffectRuntime` 实现）：真插件调用 + 失败回滚 + 协调器停机。
//!
//! 职责边界（reducer 只描述副作用，本模块只执行副作用）：
//!
//! - `BringUp { name }` → 该插件的 init → start（逐插件交替，失败即中断余下）。
//! - `FinishStart` → 全部带起成功后，把 stop 闭包按**逆启动序**登记进协调器 （登记被拒 →
//!   回滚已启动者 + fail-visible 错误）。
//! - `BeginStop` → 协调器按登记序执行 stop 闭包（= 逆启动序），产出停机报告。
//!
//! 解释器把结果写入共享槽位（[`StartOutcome`] / 失败槽 / 报告槽），由驱动层
//! （[`crate::state_loop::AssemblyLoop`]）读取后派发结果动作——回灌走驱动层，
//! 同栈回灌深度恒为 0。

use std::sync::{Arc, Mutex};

use skeleton::{Effect, EffectRuntime};
use skeleton_infra::shutdown::{RegisterError, ShutdownCoordinator, ShutdownReport};

use super::{AssemblyAction, AssemblyOp, CtxFactory, Plan};
use crate::{
    error::{LifecyclePhase, PluginError},
    logging::LogFacade,
    plugin::Plugin,
};

/// 启动批次结果（解释器 → 驱动层）。
#[derive(Debug, Clone, Default)]
pub(super) struct StartOutcome {
    /// init 成功者（依赖序）。
    pub(super) init_ok: Vec<String>,
    /// init+start 均成功者（依赖序）。
    pub(super) started: Vec<String>,
    /// 首个失败者与原因。
    pub(super) failed: Option<(String, String)>,
}

/// 状态环解释器（`EffectRuntime` 实现）。
pub(super) struct LoopFx {
    /// 依赖序计划（名 → 插件句柄）。
    plan: Arc<Plan>,
    /// ctx 工厂（逐插件取 ctx）。
    ctx_factory: CtxFactory,
    /// 停机协调器（stop 闭包登记 + 执行）。
    coordinator: Arc<ShutdownCoordinator>,
    /// 失败槽（原始 `PluginError`；保 source 链）。
    failure: Arc<Mutex<Option<PluginError>>>,
    /// 启动批次结果槽。
    outcome: Arc<Mutex<Option<StartOutcome>>>,
    /// 停机报告槽。
    report: Arc<Mutex<Option<ShutdownReport>>>,
    /// 本批已 init 成功者（依赖序）。
    init_ok: Vec<String>,
    /// 本批已 start 成功者（依赖序）。
    started: Vec<String>,
    /// 本批首个失败（中断余下）。
    failed: Option<(String, String)>,
}

impl LoopFx {
    pub(super) fn new(
        plan: Arc<Plan>,
        ctx_factory: CtxFactory,
        coordinator: Arc<ShutdownCoordinator>,
        failure: Arc<Mutex<Option<PluginError>>>,
        outcome: Arc<Mutex<Option<StartOutcome>>>,
        report: Arc<Mutex<Option<ShutdownReport>>>,
    ) -> Self {
        Self {
            plan,
            ctx_factory,
            coordinator,
            failure,
            outcome,
            report,
            init_ok: Vec::new(),
            started: Vec::new(),
            failed: None,
        }
    }

    /// 带起一个插件（init → start）。
    fn bring_up(&mut self, name: &str) {
        if self.failed.is_some() {
            // 前序失败 → 余下插件不带起（失败即中断）。
            return;
        }
        let Some(plugin) = self.plan.plugin(name).cloned() else {
            self.fail(name, PluginError::Other(format!("plugin {name} missing from plan").into()));
            return;
        };
        let ctx = match (self.ctx_factory)(&plugin) {
            Ok(ctx) => ctx,
            Err(err) => {
                self.fail(name, err);
                return;
            },
        };
        if let Err(err) =
            guarded(&plugin, LifecyclePhase::Init, &ctx, |lifecycle, ctx| lifecycle.init(ctx))
        {
            self.fail(name, err);
            return;
        }
        if let Err(err) =
            guarded(&plugin, LifecyclePhase::Start, &ctx, |lifecycle, ctx| lifecycle.start(ctx))
        {
            self.fail(name, err);
            return;
        }
        self.init_ok.push(name.to_string());
        self.started.push(name.to_string());
    }

    /// 批次收尾：全部带起成功后登记 stop 闭包（逆启动序）；登记被拒 → 回滚 + 报错。
    fn finish_start(&mut self) {
        if self.failed.is_none() {
            for name in self.started.iter().rev() {
                let Some(plugin) = self.plan.plugin(name).cloned() else {
                    continue;
                };
                let plugin_name = plugin.name();
                let closer = {
                    let plugin = Arc::clone(&plugin);
                    move || {
                        // stop Err 升级为 panic：协调器装甲捕获记 `Failed`，
                        // is_clean()==false——fail-visible，不静默吞 Err。
                        if let Err(source) = plugin.lifecycle().stop() {
                            panic!("plugin {plugin_name} stop failed: {source}");
                        }
                    }
                };
                if let Err(source) = self.coordinator.register(plugin_name, closer) {
                    let err = register_failure(plugin_name, source);
                    self.fail(plugin_name, err);
                    return;
                }
            }
        }
        let outcome = StartOutcome {
            init_ok: std::mem::take(&mut self.init_ok),
            started: std::mem::take(&mut self.started),
            failed: self.failed.take(),
        };
        *lock(&self.outcome) = Some(outcome);
    }

    /// 失败：记失败 + 回滚已启动者（逆启动序）。
    fn fail(&mut self, name: &str, err: PluginError) {
        if self.failed.is_some() {
            return;
        }
        self.failed = Some((name.to_string(), err.to_string()));
        *lock(&self.failure) = Some(err);
        self.rollback();
    }

    /// 回滚已 start 成功者（逆启动序；失败仅留痕，不阻断回滚余下）。
    fn rollback(&mut self) {
        let log = LogFacade::new("assembly", vec![]);
        for name in self.started.iter().rev() {
            let Some(plugin) = self.plan.plugin(name).cloned() else {
                continue;
            };
            rollback_stop(&plugin, &log);
        }
    }

    /// 停机：协调器按登记序（= 逆启动序）执行 stop 闭包。
    fn stop_all(&mut self) {
        let report = self.coordinator.shutdown();
        *lock(&self.report) = Some(report);
    }
}

impl EffectRuntime<AssemblyAction, AssemblyOp> for LoopFx {
    fn run(
        &mut self,
        effect: Effect<AssemblyAction, AssemblyOp>,
        _back: &skeleton::ActionSender<AssemblyAction>,
    ) {
        match effect {
            Effect::Run { op: AssemblyOp::BringUp { name }, .. } => self.bring_up(&name),
            Effect::Run { op: AssemblyOp::FinishStart, .. } => self.finish_start(),
            Effect::Run { op: AssemblyOp::BeginStop, .. } => self.stop_all(),
            Effect::Cancel { .. } => {},
            // `Effect` 是 non_exhaustive：未知变体在此忽略（今日无其它变体）。
            _ => {},
        }
    }
}

/// init / start 统一装甲：`Err` 透传包 `Lifecycle`（source 链保原错误），panic 提取
/// payload 转 `Lifecycle`——两路都标炸点插件与相（坑约束 #8：panic 不逃逸）。
fn guarded(
    plugin: &Arc<dyn Plugin>,
    phase: LifecyclePhase,
    ctx: &crate::context::PluginContext,
    call: impl FnOnce(
        &dyn crate::plugin::Lifecycle,
        &crate::context::PluginContext,
    ) -> Result<(), PluginError>,
) -> Result<(), PluginError> {
    let lifecycle = plugin.lifecycle();
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| call(lifecycle, ctx))) {
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

/// 回滚路径单插件 stop 装甲：失败 / panic 记录后继续（不阻断回滚余下）。
fn rollback_stop(plugin: &Arc<dyn Plugin>, log: &LogFacade) {
    let name = plugin.name();
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| plugin.lifecycle().stop())) {
        Ok(Ok(())) => {},
        Ok(Err(source)) => {
            log.error(format!("assembly rollback: plugin {name} stop failed: {source}"));
        },
        Err(payload) => log.error(format!(
            "assembly rollback: plugin {name} stop panicked: {}",
            panic_payload_message(payload)
        )),
    }
}

/// 注册被拒转统一错误：`Duplicate` 同源映射；`Closed` 无专属变体走 `Other`
/// （source 链保原文）。
fn register_failure(plugin: &str, source: RegisterError) -> PluginError {
    match source {
        RegisterError::Duplicate(name) => PluginError::Duplicate { name },
        other => PluginError::Other(
            format!("plugin {plugin} stop registration rejected: {other}").into(),
        ),
    }
}

/// panic payload 提取：String / &str 原文；其他类型占位描述（payload 无稳定
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

/// 取锁：毒锁恢复继续（持锁点 panic 状态未变异不株连）。
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}
