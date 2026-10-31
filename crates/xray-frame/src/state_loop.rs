//! 装配层状态环（udf `runtime` / `compose` / `journal` 三族的生产消费点）。
//!
//! # 唯一路径
//!
//! 装配生命周期（注册 → 依赖序启动 → 运行 → 停机）只此一份实现：本模块的 reducer
//! 持相位机与账本，解释器（`fx`）持真插件调用；`crate::assembly::Framework` 的
//! `bring_up` / `shutdown` 经本模块驱动。旧 `lifecycle::bring_up` 已删（无第二份账本
//! / 第二份顺序逻辑）。
//!
//! # 三族接线
//!
//! | udf 基件 | 本层派生 | 消费点 |
//! |---|---|---|
//! | `skeleton::Reducer` + `skeleton::EffectBuf` | `LifecycleReducer`（相位迁移 + 效果派发）、`AuditReducer`（轨迹派生） | [`AssemblyLoop`] 的 store 排空环 |
//! | `skeleton_infra::runtime::SyncStore` | 同步排空至 idle 的状态环载体 | `Framework::bring_up` / `shutdown` |
//! | `skeleton_infra::compose::combine` | `AssemblyRoot`（父状态 = 生命周期分片 + 审计分片） | 同上（两分片同动作流） |
//! | `skeleton::JournalPort` + `skeleton_infra::journal::JsonlJournal` | 审计轨迹落盘（**用户显式配置才写**） | `FrameworkBuilder::with_journal` |
//!
//! # 状态词表（xray 语义只落本层；udf 侧零 xray 概念）
//!
//! - 装配相位 [`AssemblyPhase`]：`Empty → Registered → Starting → Running → Stopping →
//!   Stopped`（启动失败 → `Failed`）。
//! - 插件相位 [`Phase`]：`Pending → Init → Started → Stopped`。
//! - 动作 [`LifecycleAction`]：注册 / 启动 / 启动结果 / 停机 / 停机结果。
//! - 效果 [`AssemblyOp`]：`BringUp { name }`（逐插件带起）、`FinishStart`（批次收尾：登记 stop
//!   闭包）、`BeginStop`（协调器停机）。
//! - 轨迹 [`TrailEntry`]：落盘单位（serde 派生，JSON 对象）。
//!
//! # 顺序来源
//!
//! 依赖序**单一来源** = [`PluginRegistry::start_order`]（Kahn 拓扑排序）；缺依赖 / 成环
//! 在该处即 `Err`（`PluginError::MissingDep` / `CyclicDep`）——启动前 fail-visible。
//! 本模块不复制第二份排序实现。
//!
//! # 深度纪律
//!
//! 效果派发与结果回灌都**只在驱动层**发生：reducer 只产出效果（`EffectBuf`），解释器
//! 只执行效果并把结果写入共享槽位，驱动层再把结果作为一次外部派发落账本 + 迁移相位。
//! 回灌链深度恒为 0（无同栈回灌），不随插件数增长（udf 回灌预算 64 的纪律）。

use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use skeleton::{Effect, EffectBuf, EffectId, Fragment, JournalPort, Reducer, Store};
use skeleton_infra::{
    combine,
    journal::JournalError,
    runtime::SyncStore,
    shutdown::{ComponentOutcome, OutcomeKind, ShutdownCoordinator, ShutdownReport},
};

use crate::{
    context::PluginContext, error::PluginError, logging::LogFacade, plugin::Plugin,
    registry::PluginRegistry,
};

mod fx;

/// 装配相位（状态环顶层相位）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AssemblyPhase {
    /// 未注册任何插件。
    #[default]
    Empty,
    /// 已注册、待启动。
    Registered,
    /// 启动中（逐插件 init → start）。
    Starting,
    /// 全部插件已启动。
    Running,
    /// 停机中。
    Stopping,
    /// 全部插件已停机。
    Stopped,
    /// 启动失败（已启动者已回滚）。
    Failed,
}

/// 插件相位（单插件在装配生命周期中的位置）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// 已注册未启动。
    Pending,
    /// init 成功、start 未完成。
    Init,
    /// 已启动。
    Started,
    /// 已停机。
    Stopped,
}

/// 生命周期动作（纯数据；父动作的组成部分）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleAction {
    /// 注册一个插件（注册序）。
    Register {
        /// 插件名。
        name: String,
    },
    /// 请求启动（按依赖序）。
    Start,
    /// 启动结果（解释器产出；驱动层回灌）。
    StartOutcome {
        /// init 成功者（依赖序）。
        init_ok: Vec<String>,
        /// init+start 均成功者（依赖序）。
        started: Vec<String>,
        /// 首个失败者与原因（失败即中断余下）。
        failed: Option<(String, String)>,
    },
    /// 请求停机（逆启动序）。
    Stop,
    /// 停机结果（解释器产出；驱动层回灌）。
    StopOutcome {
        /// 已停机插件名（协调器报告序 = 逆启动序）。
        stopped: Vec<String>,
    },
}

/// 状态环父动作（compose 的路由面）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssemblyAction {
    /// 路由到两个子分片（生命周期 + 审计同流）。
    Lifecycle(LifecycleAction),
}

/// 效果（副作用描述；reducer 只描述，解释器执行）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssemblyOp {
    /// 带起一个插件（init → start；按派发序执行，失败即中断余下）。
    BringUp {
        /// 插件名（依赖序）。
        name: String,
    },
    /// 批次收尾（全部带起成功后登记 stop 闭包，逆启动序）。
    FinishStart,
    /// 停机（协调器执行已登记的 stop 闭包，序 = 逆启动序）。
    BeginStop,
}

/// 审计轨迹条目（journal 落盘单位；JSON 对象）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrailEntry {
    /// 轨迹序号（单调递增）。
    pub seq: u64,
    /// 轨迹种类。
    pub kind: AuditKind,
    /// 关联插件名（无关联时缺省）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin: Option<String>,
    /// 补充说明（失败原因等；无则缺省）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// 审计轨迹种类。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditKind {
    /// 插件注册。
    Register,
    /// 启动请求。
    Start,
    /// 插件启动成功。
    PluginStarted,
    /// 插件启动失败。
    PluginFailed,
    /// 停机请求。
    Stop,
    /// 插件停机完成。
    PluginStopped,
}

/// 轨迹条目派生（驱动层预落盘与审计分片记账共用同一映射，单一来源）。
///
/// 口径：账本记的是**尝试**（含被拒的非法转移），相位记的是**实况**——两者分面，
/// 不互相覆盖。
fn entries_for(action: &LifecycleAction, base: u64) -> Vec<TrailEntry> {
    let mut out: Vec<TrailEntry> = Vec::new();
    let mut push = |kind: AuditKind, plugin: Option<String>, detail: Option<String>| {
        out.push(TrailEntry { seq: base + out.len() as u64, kind, plugin, detail });
    };
    match action {
        LifecycleAction::Register { name } => {
            push(AuditKind::Register, Some(name.clone()), None);
        },
        LifecycleAction::Start => {
            push(AuditKind::Start, None, None);
        },
        LifecycleAction::StartOutcome { started, failed, .. } => {
            for name in started {
                push(AuditKind::PluginStarted, Some(name.clone()), None);
            }
            if let Some((name, reason)) = failed {
                push(AuditKind::PluginFailed, Some(name.clone()), Some(reason.clone()));
            }
        },
        LifecycleAction::Stop => {
            push(AuditKind::Stop, None, None);
        },
        LifecycleAction::StopOutcome { stopped } => {
            for name in stopped {
                push(AuditKind::PluginStopped, Some(name.clone()), None);
            }
        },
    }
    out
}

/// 生命周期分片（compose 子片 A；装配相位 + 插件账本）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LifecycleSlice {
    /// 装配相位。
    pub phase: AssemblyPhase,
    /// 插件账本（注册序）。
    pub plugins: Vec<PluginEntry>,
    /// 依赖序计划名（[`Plan`] 的名序；可查面）。
    pub plan: Vec<String>,
    /// 已启动序（依赖序）。
    pub started: Vec<String>,
    /// 已停机序（协调器报告序 = 逆启动序）。
    pub stopped: Vec<String>,
    /// 失败说明（启动失败时）。
    pub failure: Option<String>,
    /// 最近一次被拒的非法转移说明（fail-visible 面）。
    pub rejected: Option<String>,
    /// 非法转移计数（单调；驱动层据此判「本次被拒」）。
    pub rejections: u64,
    /// 效果 id 计数器（udf 纪律：store 内 id 全局唯一，reducer 侧自持单调计数）。
    pub next_effect_id: u64,
}

/// 插件账本条目。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginEntry {
    /// 插件名。
    pub name: String,
    /// 插件相位。
    pub phase: Phase,
}

/// 审计分片（compose 子片 B；轨迹账本；journal 的快照面）。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditSlice {
    /// 轨迹条目（插入序 = 发生序）。
    pub entries: Vec<TrailEntry>,
}

/// 状态环根状态（compose 组合面：两个分片）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AssemblyState {
    /// 生命周期分片。
    pub lifecycle: LifecycleSlice,
    /// 审计分片。
    pub audit: AuditSlice,
}

/// 依赖序计划（**单一顺序源** = [`PluginRegistry::start_order`]）。
///
/// 缺依赖 / 成环在计划产出处即 `Err`（`PluginError::MissingDep` / `CyclicDep`）——
/// 启动前 fail-visible，零生命周期调用。
#[derive(Clone)]
pub struct Plan {
    plugins: Vec<Arc<dyn Plugin>>,
}

impl Plan {
    /// 依注册表的依赖序建计划（缺依赖 / 成环 → `Err`，启动前 fail-visible）。
    pub fn from_registry(registry: &PluginRegistry) -> Result<Self, PluginError> {
        Ok(Self { plugins: registry.start_order()? })
    }

    /// 依赖序插件名。
    pub fn names(&self) -> Vec<String> {
        self.plugins.iter().map(|p| p.name().to_string()).collect()
    }

    /// 计划规模。
    pub fn len(&self) -> usize {
        self.plugins.len()
    }

    /// 计划为空。
    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }

    /// 依名取插件句柄。
    pub fn plugin(&self, name: &str) -> Option<&Arc<dyn Plugin>> {
        self.plugins.iter().find(|p| p.name() == name)
    }
}

impl std::fmt::Debug for Plan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Plan").field("names", &self.names()).finish_non_exhaustive()
    }
}

/// ctx 工厂（逐插件取 ctx；失败即装配期 fail-visible）。
///
/// ctx 在解释器内**就地创建即用即弃**（不进账本、不跨线程）——故工厂只要求
/// `Send + Sync`（闭包体可共享），返回的 `PluginContext` 无需 `Send`。
pub type CtxFactory =
    Arc<dyn Fn(&Arc<dyn Plugin>) -> Result<PluginContext, PluginError> + Send + Sync + 'static>;

/// 审计账本句柄（`JournalPort` 的装配层形态；`None` = 不写盘）。
pub type AssemblyJournal =
    Box<dyn JournalPort<TrailEntry, State = AuditSlice, Err = JournalError> + Send>;

/// 生命周期分片 reducer（纯函数：相位迁移 + 效果派发；禁 IO）。
struct LifecycleReducer {
    /// 依赖序计划（效果派发序）。
    plan: Arc<Plan>,
}

impl LifecycleReducer {
    /// 相位门：不在允许集内 → 记拒（相位不变）并返回 false。
    fn gate(next: &mut LifecycleSlice, allowed: &[AssemblyPhase], what: &str) -> bool {
        let phase = next.phase;
        if allowed.contains(&phase) {
            return true;
        }
        Self::reject(next, format!("{what} while phase {phase:?}"));
        false
    }

    /// 非法转移（记痕 + 计数；相位不变）。
    fn reject(next: &mut LifecycleSlice, reason: String) {
        next.rejected = Some(reason);
        next.rejections += 1;
    }
}

impl Reducer for LifecycleReducer {
    type Action = LifecycleAction;
    type Op = AssemblyOp;
    type State = LifecycleSlice;

    fn initial(&self) -> LifecycleSlice {
        LifecycleSlice { plan: self.plan.names(), ..LifecycleSlice::default() }
    }

    fn reduce(
        &self,
        state: &LifecycleSlice,
        action: LifecycleAction,
        out: &mut EffectBuf<LifecycleAction, AssemblyOp>,
    ) -> LifecycleSlice {
        let mut next = state.clone();
        match action {
            LifecycleAction::Register { name } => {
                if !Self::gate(
                    &mut next,
                    &[AssemblyPhase::Empty, AssemblyPhase::Registered],
                    "register",
                ) {
                    return next;
                }
                next.phase = AssemblyPhase::Registered;
                next.plugins.push(PluginEntry { name, phase: Phase::Pending });
            },
            LifecycleAction::Start => {
                if !Self::gate(&mut next, &[AssemblyPhase::Registered], "start") {
                    return next;
                }
                next.phase = AssemblyPhase::Starting;
                for name in self.plan.names() {
                    let id = EffectId::new(next.next_effect_id);
                    next.next_effect_id += 1;
                    out.push(Effect::Run { id, op: AssemblyOp::BringUp { name } });
                }
                let id = EffectId::new(next.next_effect_id);
                next.next_effect_id += 1;
                out.push(Effect::Run { id, op: AssemblyOp::FinishStart });
            },
            LifecycleAction::StartOutcome { init_ok, started, failed } => {
                if !Self::gate(&mut next, &[AssemblyPhase::Starting], "start outcome") {
                    return next;
                }
                for name in &init_ok {
                    if let Some(entry) = next.plugins.iter_mut().find(|p| &p.name == name) {
                        entry.phase = Phase::Init;
                    }
                }
                for name in &started {
                    if let Some(entry) = next.plugins.iter_mut().find(|p| &p.name == name) {
                        entry.phase = Phase::Started;
                    }
                }
                next.started = started;
                next.phase =
                    if failed.is_some() { AssemblyPhase::Failed } else { AssemblyPhase::Running };
                if let Some((_, reason)) = failed {
                    next.failure = Some(reason);
                }
            },
            LifecycleAction::Stop => {
                if !Self::gate(&mut next, &[AssemblyPhase::Running], "stop") {
                    return next;
                }
                next.phase = AssemblyPhase::Stopping;
                let id = EffectId::new(next.next_effect_id);
                next.next_effect_id += 1;
                out.push(Effect::Run { id, op: AssemblyOp::BeginStop });
            },
            LifecycleAction::StopOutcome { stopped } => {
                if !Self::gate(&mut next, &[AssemblyPhase::Stopping], "stop outcome") {
                    return next;
                }
                for name in &stopped {
                    if let Some(entry) = next.plugins.iter_mut().find(|p| &p.name == name) {
                        entry.phase = Phase::Stopped;
                    }
                }
                next.stopped = stopped;
                next.phase = AssemblyPhase::Stopped;
            },
        }
        next
    }
}

/// 审计分片 reducer（纯函数：动作 → 轨迹条目）。
struct AuditReducer;

impl Reducer for AuditReducer {
    type Action = LifecycleAction;
    type Op = AssemblyOp;
    type State = AuditSlice;

    fn initial(&self) -> AuditSlice {
        AuditSlice::default()
    }

    fn reduce(
        &self,
        state: &AuditSlice,
        action: LifecycleAction,
        _out: &mut EffectBuf<LifecycleAction, AssemblyOp>,
    ) -> AuditSlice {
        let mut next = state.clone();
        next.entries.extend(entries_for(&action, state.entries.len() as u64));
        next
    }
}

/// 状态环根 reducer（compose 组合面：父状态 = 生命周期分片 + 审计分片）。
///
/// 两个子片吃**同一条**动作流：生命周期分片算相位与账本，审计分片派生轨迹——combine 的
/// 父子分片形态（`get` / `set` 镜头 + 动作路由），零 dyn 零装箱（分片自身）。
struct AssemblyRoot {
    lifecycle: Box<
        dyn Fragment<State = AssemblyState, Action = AssemblyAction, Op = AssemblyOp> + Send + Sync,
    >,
    audit: Box<
        dyn Fragment<State = AssemblyState, Action = AssemblyAction, Op = AssemblyOp> + Send + Sync,
    >,
    /// 生命周期分片初值（含依赖序计划名；父状态显式构造子切片初值——combine 纪律）。
    lifecycle_initial: LifecycleSlice,
}

impl AssemblyRoot {
    fn new(plan: Arc<Plan>) -> Self {
        // 生命周期分片：唯一派效果的子片 → lift 显式转发 Run / Cancel（Emit 由
        // combine 核心代上浮）。
        let lifecycle = combine!(
            LifecycleReducer { plan: Arc::clone(&plan) },
            AssemblyState.lifecycle,
            wrap: AssemblyAction::Lifecycle,
            unwrap: |action: &AssemblyAction| match action {
                AssemblyAction::Lifecycle(inner) => Some(inner.clone()),
            },
            lift: |effect: Effect<LifecycleAction, AssemblyOp>,
                   out: &mut EffectBuf<AssemblyAction, AssemblyOp>| {
                match effect {
                    Effect::Run { id, op } => out.push(Effect::Run { id, op }),
                    Effect::Cancel { id } => out.push(Effect::Cancel { id }),
                    // `Effect` 是 non_exhaustive：未知变体在此丢弃（今日无其它变体）。
                    _ => {},
                }
            },
        );
        // 审计分片：只记账不派效果 → 无 lift（子片不产效果，无可上提）。
        let audit = combine!(
            AuditReducer,
            AssemblyState.audit,
            wrap: AssemblyAction::Lifecycle,
            unwrap: |action: &AssemblyAction| match action {
                AssemblyAction::Lifecycle(inner) => Some(inner.clone()),
            },
        );
        Self {
            lifecycle: Box::new(lifecycle),
            audit: Box::new(audit),
            lifecycle_initial: LifecycleSlice { plan: plan.names(), ..LifecycleSlice::default() },
        }
    }
}

impl Reducer for AssemblyRoot {
    type Action = AssemblyAction;
    type Op = AssemblyOp;
    type State = AssemblyState;

    fn initial(&self) -> AssemblyState {
        AssemblyState { lifecycle: self.lifecycle_initial.clone(), audit: AuditSlice::default() }
    }

    fn reduce(
        &self,
        state: &AssemblyState,
        action: AssemblyAction,
        out: &mut EffectBuf<AssemblyAction, AssemblyOp>,
    ) -> AssemblyState {
        let after_lifecycle = self.lifecycle.reduce(state, action.clone(), out);
        self.audit.reduce(&after_lifecycle, action, out)
    }
}

/// 装配状态环（装配生命周期的**唯一路径**）。
///
/// - 载体 = `skeleton_infra::runtime::SyncStore`（同步排空至 idle）。
/// - 根 reducer = `AssemblyRoot`（combine 两分片）。
/// - 解释器 = `fx::LoopFx`（真插件调用 + 失败回滚 + 协调器停机）。
pub struct AssemblyLoop {
    store: SyncStore<AssemblyState, AssemblyAction, AssemblyOp>,
    journal: Mutex<Option<AssemblyJournal>>,
    /// 解释器产出的失败（原始 `PluginError`，保 source 链）。
    failure: Arc<Mutex<Option<PluginError>>>,
    /// 解释器产出的启动批次结果。
    outcome: Arc<Mutex<Option<fx::StartOutcome>>>,
    /// 解释器产出的停机报告。
    report: Arc<Mutex<Option<ShutdownReport>>>,
}

impl AssemblyLoop {
    /// 装配状态环。
    ///
    /// `plan` = 依赖序计划（[`Plan::from_registry`]，缺依赖 / 成环在产出处即 `Err`）；
    /// `ctx_factory` = 逐插件 ctx 工厂；`journal` = 审计账本（`None` = 不写盘）。
    pub fn new(
        plan: Plan,
        ctx_factory: CtxFactory,
        coordinator: Arc<ShutdownCoordinator>,
        journal: Option<AssemblyJournal>,
    ) -> Self {
        let plan = Arc::new(plan);
        let failure = Arc::new(Mutex::new(None));
        let outcome = Arc::new(Mutex::new(None));
        let report = Arc::new(Mutex::new(None));
        let reducer = AssemblyRoot::new(Arc::clone(&plan));
        let fx = fx::LoopFx::new(
            Arc::clone(&plan),
            ctx_factory,
            Arc::clone(&coordinator),
            Arc::clone(&failure),
            Arc::clone(&outcome),
            Arc::clone(&report),
        );
        Self {
            store: SyncStore::new(reducer, fx),
            journal: Mutex::new(journal),
            failure,
            outcome,
            report,
        }
    }

    /// 派发一个生命周期动作（**先落盘后 apply**）。
    ///
    /// - 落盘半边：轨迹条目先入账本（`Err` → **不 apply**，内存态不领先持久前缀）。
    /// - apply 半边：进 store 排空环（同步至 idle：效果已执行）。
    /// - 非法转移 → `Err`（相位不变；状态面记 `rejected` + 计数）。
    pub fn dispatch(&self, action: LifecycleAction) -> Result<(), PluginError> {
        let before = self.store.snapshot();
        let entries = entries_for(&action, before.audit.entries.len() as u64);
        {
            let mut guard = lock(&self.journal);
            if let Some(journal) = guard.as_mut() {
                for entry in &entries {
                    journal.append(entry).map_err(|err| PluginError::Other(Box::new(err)))?;
                }
            }
        }
        self.store.dispatch(AssemblyAction::Lifecycle(action));
        let after = self.store.snapshot();
        if after.lifecycle.rejections > before.lifecycle.rejections {
            let reason = after.lifecycle.rejected.clone().unwrap_or_default();
            return Err(PluginError::Other(reason.into()));
        }
        Ok(())
    }

    /// 启动一批（注册 → 依赖序带起 → 结果回灌）。
    ///
    /// 结果回灌走驱动层（解释器只写共享槽位）：回灌链深度恒为 0。
    pub fn start(&self, names: &[&'static str]) -> Result<(), PluginError> {
        for name in names {
            self.dispatch(LifecycleAction::Register { name: (*name).to_string() })?;
        }
        self.dispatch(LifecycleAction::Start)?;
        if self.phase() != AssemblyPhase::Starting {
            return Err(PluginError::Other(
                format!("start rejected while phase {:?}", self.phase()).into(),
            ));
        }
        let outcome = lock(&self.outcome).take().unwrap_or_default();
        let failed = outcome.failed.clone();
        self.dispatch(LifecycleAction::StartOutcome {
            init_ok: outcome.init_ok,
            started: outcome.started,
            failed,
        })?;
        if let Some(err) = lock(&self.failure).take() {
            return Err(err);
        }
        Ok(())
    }

    /// 停机（协调器按逆启动序执行 stop 闭包）。
    pub fn stop(&self) -> ShutdownReport {
        if self.phase() != AssemblyPhase::Running {
            return ShutdownReport::default();
        }
        if let Err(err) = self.dispatch(LifecycleAction::Stop) {
            // 停机未被受理（相位拒 / 账本写盘失败）：插件没收到停机信号，
            // 必须外泄为**不干净**报告，不能报成「干净的空报告」。
            return unclean("assembly_stop", err);
        }
        let report = lock(&self.report).take().unwrap_or_default();
        let stopped: Vec<String> = report.per_component.iter().map(|c| c.name.clone()).collect();
        if let Err(err) = self.dispatch(LifecycleAction::StopOutcome { stopped }) {
            LogFacade::new("assembly", vec![])
                .error(format!("assembly stop outcome rejected: {err}"));
        }
        report
    }

    /// 账本冲刷（快照行；udf `persist_snapshot` 内部 flush + sync_all → 持久点）。
    pub fn persist_journal(&self) -> Result<(), PluginError> {
        let slice = self.store.snapshot().audit.clone();
        let mut guard = lock(&self.journal);
        if let Some(journal) = guard.as_mut() {
            journal.persist_snapshot(&slice).map_err(|err| PluginError::Other(Box::new(err)))?;
        }
        Ok(())
    }

    /// 装配相位（观察面）。
    pub fn phase(&self) -> AssemblyPhase {
        self.store.snapshot().lifecycle.phase
    }

    /// 根状态快照（生命周期分片 + 审计分片）。
    pub fn state(&self) -> Arc<AssemblyState> {
        self.store.snapshot()
    }

    /// 审计轨迹（插入序 = 发生序）。
    pub fn trail(&self) -> Vec<TrailEntry> {
        self.store.snapshot().audit.entries.clone()
    }

    /// 插件账本（注册序 + 相位）。
    pub fn plugins(&self) -> Vec<(String, Phase)> {
        self.store.snapshot().lifecycle.plugins.iter().map(|p| (p.name.clone(), p.phase)).collect()
    }
}

/// 启动产物（已启动链的句柄；停机入口 [`StartedPlugins::tear_down`]）。
pub struct StartedPlugins {
    loop_: AssemblyLoop,
}

/// 手写（`AssemblyLoop` 持 store/journal，不可 derive）：打印插件账本 + 相位，
/// 测试断言与错误路径可诊断（fail-visible 的可读半边）。
impl std::fmt::Debug for StartedPlugins {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StartedPlugins")
            .field("phase", &self.loop_.phase())
            .field("plugins", &self.loop_.plugins())
            .finish_non_exhaustive()
    }
}

impl StartedPlugins {
    /// 插件账本（注册序 + 相位；已启动者相位 = `Started`）。
    pub fn phases(&self) -> Vec<(String, Phase)> {
        self.loop_.plugins()
    }

    /// 审计轨迹（插入序 = 发生序）。
    pub fn trail(&self) -> Vec<TrailEntry> {
        self.loop_.trail()
    }

    /// 停机（协调器按逆启动序执行 stop 闭包；消费本句柄）。
    ///
    /// 账本快照失败（写盘/序列化）以 `journal_snapshot` 行并入报告——`is_clean()`
    /// 因此覆盖持久化面，不静默丢。
    pub fn tear_down(self) -> ShutdownReport {
        let mut report = self.loop_.stop();
        if let Err(err) = self.loop_.persist_journal() {
            LogFacade::new("assembly", vec![]).error(format!("journal snapshot failed: {err}"));
            report.per_component.push(ComponentOutcome {
                name: "journal_snapshot".into(),
                kind: OutcomeKind::Failed { reason: err.to_string() },
            });
        }
        report
    }
}

/// 未受理动作的不干净报告（`is_clean()==false` 外泄真因；原因经 error 日志留痕）。
fn unclean(name: &str, err: PluginError) -> ShutdownReport {
    LogFacade::new("assembly", vec![]).error(format!("{name}: {err}"));
    let mut report = ShutdownReport::default();
    report.per_component.push(ComponentOutcome {
        name: name.into(),
        kind: OutcomeKind::Failed { reason: err.to_string() },
    });
    report
}

/// 装配并带起（**唯一路径**；旧 `lifecycle::bring_up` 的替代面）。
///
/// 依赖序计划来自 [`Plan::from_registry`]（缺依赖 / 成环 → `Err`，启动前
/// fail-visible，零生命周期调用）。`ctx_factory` 逐插件取 ctx（装配期失败 →
/// 已启动者回滚 + `Err`）。
pub fn bring_up(
    registry: &PluginRegistry,
    ctx_factory: CtxFactory,
    coordinator: Arc<ShutdownCoordinator>,
) -> Result<StartedPlugins, PluginError> {
    bring_up_with_journal(registry, ctx_factory, coordinator, None)
}

/// 装配并带起（带审计账本；`None` = 不写盘）。
pub fn bring_up_with_journal(
    registry: &PluginRegistry,
    ctx_factory: CtxFactory,
    coordinator: Arc<ShutdownCoordinator>,
    journal: Option<AssemblyJournal>,
) -> Result<StartedPlugins, PluginError> {
    let plan = Plan::from_registry(registry)?;
    let names: Vec<&'static str> = registry.iter().map(|p| p.name()).collect();
    let loop_ = AssemblyLoop::new(plan, ctx_factory, coordinator, journal);
    loop_.start(&names)?;
    Ok(StartedPlugins { loop_ })
}

/// 取锁：毒锁恢复继续（持锁点 panic 状态未变异不株连；与本仓其它模块同款）。
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use skeleton::{clock::SystemClock, config::MockEnv};
    // udf testing 族替身（D5 消费点，2026-10-31）：reducer 契约逐条断言面。
    use skeleton_infra::testing::{ExpectedEffect, Script, ScriptedRuntime, TestStore};

    use super::*;
    use crate::{
        error::LifecyclePhase,
        logging::LogFacade,
        plugin::{Lifecycle, PluginContract, PluginDep},
        scope::ArmScope,
    };

    static NO_DEPS: &[PluginDep] = &[];
    static DEP_B: &[PluginDep] = &[PluginDep { name: "B" }];
    static DEP_A: &[PluginDep] = &[PluginDep { name: "A" }];

    /// 事件观察器（插件名 + 事件）。
    #[derive(Clone, Default)]
    struct Probe(Arc<Mutex<Vec<String>>>);

    impl Probe {
        fn record(&self, event: &str) {
            lock(&self.0).push(event.to_string());
        }

        fn events(&self) -> Vec<String> {
            lock(&self.0).clone()
        }
    }

    /// 生命周期行为体（init / start / stop 记事件；start 可注失败）。
    struct Body {
        name: &'static str,
        probe: Probe,
        fail_start: bool,
    }

    impl Lifecycle for Body {
        fn init(&self, _ctx: &PluginContext) -> Result<(), PluginError> {
            self.probe.record(&format!("{}:init", self.name));
            Ok(())
        }

        fn start(&self, _ctx: &PluginContext) -> Result<(), PluginError> {
            self.probe.record(&format!("{}:start", self.name));
            if self.fail_start {
                return Err(PluginError::Other(format!("{} start refused", self.name).into()));
            }
            Ok(())
        }

        fn stop(&self) -> Result<(), PluginError> {
            self.probe.record(&format!("{}:stop", self.name));
            Ok(())
        }
    }

    struct FakePlugin {
        name: &'static str,
        deps: &'static [PluginDep],
        body: Body,
    }

    impl Plugin for FakePlugin {
        fn name(&self) -> &'static str {
            self.name
        }

        fn version(&self) -> &'static str {
            "0.0.0"
        }

        fn deps(&self) -> &'static [PluginDep] {
            self.deps
        }

        fn contract(&self) -> &PluginContract {
            static CONTRACT: PluginContract =
                PluginContract { clauses: &[], extra: &[], not_applicable: &[] };
            &CONTRACT
        }

        fn lifecycle(&self) -> &dyn Lifecycle {
            &self.body
        }

        fn build(&self, _ctx: &mut PluginContext) -> Result<(), PluginError> {
            Ok(())
        }
    }

    fn fake(name: &'static str, deps: &'static [PluginDep], probe: &Probe) -> Arc<dyn Plugin> {
        Arc::new(FakePlugin {
            name,
            deps,
            body: Body { name, probe: probe.clone(), fail_start: false },
        })
    }

    fn ctx_of(name: &'static str) -> PluginContext {
        PluginContext::new(
            name,
            ArmScope::new(),
            Arc::new(SystemClock),
            crate::context::derive_fingerprint(Some("127.0.0.1:10808")),
            Arc::new(MockEnv::new()),
            serde_json::json!({}),
            LogFacade::new(name, vec![]),
            Arc::new(crate::audit::AuditHandle::new(crate::audit::DEFAULT_AUDIT_RING_CAP)),
        )
    }

    fn ctx_factory() -> CtxFactory {
        Arc::new(|plugin: &Arc<dyn Plugin>| Ok(ctx_of(plugin.name())))
    }

    fn registry_of(plugins: Vec<Arc<dyn Plugin>>) -> PluginRegistry {
        let mut registry = PluginRegistry::new(16).expect("cap 16");
        for plugin in plugins {
            registry.register(plugin).expect("unique name");
        }
        registry
    }

    /// 用例①：注册序 ≠ 依赖序 → 启动序仍按依赖（顺序源 = 注册表拓扑序）。
    #[test]
    fn start_order_follows_dependencies_not_registration_order() {
        let probe = Probe::default();
        // 注册序 A(deps B), B —— 依赖序应为 B, A。
        let registry = registry_of(vec![fake("A", DEP_B, &probe), fake("B", NO_DEPS, &probe)]);
        let started = bring_up(&registry, ctx_factory(), Arc::new(ShutdownCoordinator::new()))
            .expect("bring up ok");
        assert_eq!(
            probe.events(),
            ["B:init", "B:start", "A:init", "A:start"],
            "init/start 按依赖序交替"
        );
        assert!(
            started.phases().iter().all(|(_, phase)| *phase == Phase::Started),
            "全部插件账本相位 = Started：{:?}",
            started.phases()
        );
    }

    /// 用例②：缺依赖 → 计划产出处即 `Err`（启动前 fail-visible，零生命周期调用）。
    #[test]
    fn missing_dependency_fails_before_any_lifecycle_call() {
        let probe = Probe::default();
        static DEP_MISSING: &[PluginDep] = &[PluginDep { name: "MISSING" }];
        let registry = registry_of(vec![fake("A", DEP_MISSING, &probe)]);
        let err = bring_up(&registry, ctx_factory(), Arc::new(ShutdownCoordinator::new()))
            .expect_err("缺依赖必须启动前报错");
        assert!(matches!(err, PluginError::MissingDep { .. }), "{err:?}");
        assert!(probe.events().is_empty(), "零生命周期调用");
    }

    /// 用例③：成环 → 计划产出处即 `Err`（启动前 fail-visible，零生命周期调用）。
    #[test]
    fn cyclic_dependency_fails_before_any_lifecycle_call() {
        let probe = Probe::default();
        let registry = registry_of(vec![fake("A", DEP_B, &probe), fake("B", DEP_A, &probe)]);
        let err = bring_up(&registry, ctx_factory(), Arc::new(ShutdownCoordinator::new()))
            .expect_err("成环必须启动前报错");
        assert!(matches!(err, PluginError::CyclicDep { .. }), "{err:?}");
        assert!(probe.events().is_empty(), "零生命周期调用");
    }

    /// 用例④：正常注册 → running → 停机（逆启动序 stop）。
    #[test]
    fn registration_running_shutdown_phases_transition() {
        let probe = Probe::default();
        let registry = registry_of(vec![fake("A", NO_DEPS, &probe), fake("B", NO_DEPS, &probe)]);
        let started = bring_up(&registry, ctx_factory(), Arc::new(ShutdownCoordinator::new()))
            .expect("bring up ok");
        let report = started.tear_down();
        assert!(report.is_clean(), "健康链报告干净：{report:?}");
        assert_eq!(probe.events()[4..], ["B:stop", "A:stop"], "停机序 = 逆启动序");
    }

    /// 用例⑤：非法转移被拒（重复启动 → `Err`，相位不变）。
    #[test]
    fn illegal_transitions_are_rejected() {
        let probe = Probe::default();
        let registry = registry_of(vec![fake("A", NO_DEPS, &probe)]);
        let plan = Plan::from_registry(&registry).expect("plan");
        let names: Vec<&'static str> = registry.iter().map(|p| p.name()).collect();
        let loop_ =
            AssemblyLoop::new(plan, ctx_factory(), Arc::new(ShutdownCoordinator::new()), None);
        loop_.start(&names).expect("start ok");
        let err = loop_.dispatch(LifecycleAction::Start).expect_err("重复启动必须被拒");
        assert!(err.to_string().contains("start while phase"), "{err}");
        assert_eq!(loop_.phase(), AssemblyPhase::Running, "被拒转移不改相位");
        let err = loop_
            .dispatch(LifecycleAction::Register { name: "B".into() })
            .expect_err("运行中注册必须被拒");
        assert!(err.to_string().contains("register while phase"), "{err}");
    }

    /// 用例⑥：启动失败 → `Err`（source 链保原始错误）+ 已启动者回滚。
    #[test]
    fn start_failure_rolls_back_started_plugins() {
        let probe = Probe::default();
        let failing = Arc::new(FakePlugin {
            name: "B",
            deps: NO_DEPS,
            body: Body { name: "B", probe: probe.clone(), fail_start: true },
        }) as Arc<dyn Plugin>;
        let registry = registry_of(vec![fake("A", NO_DEPS, &probe), failing]);
        let err = bring_up(&registry, ctx_factory(), Arc::new(ShutdownCoordinator::new()))
            .expect_err("start 失败必须整链失败");
        let PluginError::Lifecycle { plugin, phase, source } = &err else {
            panic!("start 失败必须收敛 Lifecycle，实际 {err:?}");
        };
        assert_eq!(plugin, "B");
        assert_eq!(*phase, LifecyclePhase::Start);
        assert!(source.to_string().contains("B start refused"), "source 链保原始错误");
        assert_eq!(
            probe.events(),
            ["A:init", "A:start", "B:init", "B:start", "A:stop"],
            "回滚只及已 start 成功者"
        );
    }

    /// 用例⑦：journal 开启 → 写出可查的启动 / 停机轨迹（顺序稳定）。
    #[test]
    fn journal_records_ordered_start_and_stop_trail() {
        let probe = Probe::default();
        let registry = registry_of(vec![fake("A", NO_DEPS, &probe), fake("B", NO_DEPS, &probe)]);
        let path = std::env::temp_dir()
            .join(format!("xray-frame-state-loop-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let journal =
            skeleton_infra::journal::JsonlJournal::<TrailEntry, AuditSlice>::create(&path)
                .expect("建账本");
        let started = bring_up_with_journal(
            &registry,
            ctx_factory(),
            Arc::new(ShutdownCoordinator::new()),
            Some(Box::new(journal)),
        )
        .expect("bring up ok");
        let report = started.tear_down();
        assert!(report.is_clean(), "健康链报告干净：{report:?}");

        let text = std::fs::read_to_string(&path).expect("读账本");
        let kinds: Vec<String> = text
            .lines()
            .filter(|line| line.contains("\"t\":\"a\""))
            .map(|line| {
                let value: serde_json::Value = serde_json::from_str(line).expect("行是 JSON");
                value["kind"].as_str().expect("kind 字段").to_string()
            })
            .collect();
        assert_eq!(
            kinds,
            [
                "register",
                "register",
                "start",
                "plugin_started",
                "plugin_started",
                "stop",
                "plugin_stopped",
                "plugin_stopped",
            ],
            "轨迹顺序稳定：{text}"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// 用例⑧：未配置账本 → 零写盘（内存轨迹仍记账）。
    #[test]
    fn no_journal_configured_writes_nothing() {
        let probe = Probe::default();
        let registry = registry_of(vec![fake("A", NO_DEPS, &probe)]);
        let started = bring_up(&registry, ctx_factory(), Arc::new(ShutdownCoordinator::new()))
            .expect("bring up ok");
        assert_eq!(started.trail().len(), 3, "内存轨迹仍记账");
    }

    /// 用例⑨：失败原因进轨迹（可查）。
    #[test]
    fn failure_reason_reaches_the_trail() {
        let probe = Probe::default();
        let failing = Arc::new(FakePlugin {
            name: "B",
            deps: NO_DEPS,
            body: Body { name: "B", probe: probe.clone(), fail_start: true },
        }) as Arc<dyn Plugin>;
        let registry = registry_of(vec![failing]);
        let path = std::env::temp_dir()
            .join(format!("xray-frame-state-loop-fail-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let journal =
            skeleton_infra::journal::JsonlJournal::<TrailEntry, AuditSlice>::create(&path)
                .expect("建账本");
        let result = bring_up_with_journal(
            &registry,
            ctx_factory(),
            Arc::new(ShutdownCoordinator::new()),
            Some(Box::new(journal)),
        );
        assert!(result.is_err(), "启动失败必须报错");
        let text = std::fs::read_to_string(&path).expect("读账本");
        assert!(text.contains("plugin_failed"), "失败条目进账本：{text}");
        let _ = std::fs::remove_file(&path);
    }

    /// 用例⑩：停机在未运行相位 → 空报告（合法干净，零生命周期调用）。
    #[test]
    fn stop_before_running_returns_empty_report() {
        let probe = Probe::default();
        let registry = registry_of(vec![fake("A", NO_DEPS, &probe)]);
        let plan = Plan::from_registry(&registry).expect("plan");
        let loop_ =
            AssemblyLoop::new(plan, ctx_factory(), Arc::new(ShutdownCoordinator::new()), None);
        let report = loop_.stop();
        assert!(report.is_clean(), "未启动链 = 空报告");
        assert!(probe.events().is_empty(), "零生命周期调用");
    }

    /// 用例⑪：审计分片快照可序列化（journal 快照面）。
    #[test]
    fn audit_slice_is_serializable() {
        let slice = AuditSlice {
            entries: vec![TrailEntry {
                seq: 0,
                kind: AuditKind::Start,
                plugin: None,
                detail: None,
            }],
        };
        let text = serde_json::to_string(&slice).expect("序列化");
        let back: AuditSlice = serde_json::from_str(&text).expect("反序列化");
        assert_eq!(back, slice);
    }

    /// 用例⑫：轨迹序号单调（落盘与内存同序）。
    #[test]
    fn trail_sequence_is_monotonic() {
        let probe = Probe::default();
        let registry = registry_of(vec![fake("A", NO_DEPS, &probe)]);
        let started = bring_up(&registry, ctx_factory(), Arc::new(ShutdownCoordinator::new()))
            .expect("bring up ok");
        let seqs: Vec<u64> = started.trail().iter().map(|e| e.seq).collect();
        assert_eq!(seqs, [0, 1, 2], "序号单调递增：{seqs:?}");
    }

    /// 用例⑬：账本异常必须外泄为**不干净**报告（不得报成干净的空报告）。
    ///
    /// 三个面：① `append` 失败 → 动作不 apply（内存态不领先持久前缀）；
    /// ② 启动成功后的 `Stop` 落盘失败 → 报告带 `assembly_stop` Failed 行；
    /// ③ 停机快照失败 → 报告带 `journal_snapshot` Failed 行。
    struct BrokenJournal {
        /// 第几次 append 起开始失败（0 = 首次即失败）。
        fail_append_at: usize,
        /// 快照写入是否失败。
        fail_snapshot: bool,
        appends: usize,
    }

    impl JournalPort<TrailEntry> for BrokenJournal {
        type Err = JournalError;
        type State = AuditSlice;

        fn append(&mut self, _action: &TrailEntry) -> Result<(), JournalError> {
            self.appends += 1;
            if self.appends > self.fail_append_at {
                return Err(JournalError::VersionMismatch { found: 0, expected: 1 });
            }
            Ok(())
        }

        fn persist_snapshot(&mut self, _state: &AuditSlice) -> Result<(), JournalError> {
            if self.fail_snapshot {
                return Err(JournalError::VersionMismatch { found: 0, expected: 1 });
            }
            Ok(())
        }

        fn restore(&self) -> Result<skeleton::Restore<TrailEntry, AuditSlice>, JournalError> {
            Ok(skeleton::Restore::Empty)
        }
    }

    /// 单插件链（账本按给定替身装配）。
    fn one_plugin_loop(probe: &Probe, journal: BrokenJournal) -> AssemblyLoop {
        let registry = registry_of(vec![fake("A", NO_DEPS, probe)]);
        AssemblyLoop::new(
            Plan::from_registry(&registry).expect("plan"),
            ctx_factory(),
            Arc::new(ShutdownCoordinator::new()),
            Some(Box::new(journal)),
        )
    }

    #[test]
    fn journal_write_failure_is_never_silently_clean() {
        // ① 首条落盘即失败 → 启动失败 + 零状态推进。
        let probe = Probe::default();
        let loop_ = one_plugin_loop(
            &probe,
            BrokenJournal { fail_append_at: 0, fail_snapshot: false, appends: 0 },
        );
        let err = loop_.start(&["A"]).expect_err("账本写盘失败必须启动即失败");
        assert!(err.to_string().contains("version mismatch"), "{err}");
        assert_eq!(loop_.phase(), AssemblyPhase::Empty, "不 apply 即零状态推进");
        assert!(probe.events().is_empty(), "零生命周期调用");

        // ② 启动 ok（3 条落盘），停机落盘失败 → 不干净报告 + 相位不动。
        let probe = Probe::default();
        let loop_ = one_plugin_loop(
            &probe,
            BrokenJournal { fail_append_at: 3, fail_snapshot: false, appends: 0 },
        );
        loop_.start(&["A"]).expect("start ok");
        assert_eq!(loop_.phase(), AssemblyPhase::Running);
        let report = loop_.stop();
        assert!(!report.is_clean(), "停机未被受理必须不干净：{report:?}");
        assert_eq!(report.per_component[0].name, "assembly_stop");
        assert_eq!(loop_.phase(), AssemblyPhase::Running, "停机未被受理 → 相位不动");
    }

    /// 用例⑭：停机快照失败并入报告（`is_clean()` 覆盖持久化面）。
    #[test]
    fn journal_snapshot_failure_taints_report() {
        let probe = Probe::default();
        let started = crate::state_loop::bring_up_with_journal(
            &registry_of(vec![fake("A", NO_DEPS, &probe)]),
            ctx_factory(),
            Arc::new(ShutdownCoordinator::new()),
            Some(Box::new(BrokenJournal {
                fail_append_at: usize::MAX,
                fail_snapshot: true,
                appends: 0,
            })),
        )
        .expect("bring up ok");
        let report = started.tear_down();
        assert!(!report.is_clean(), "快照失败必须不干净：{report:?}");
        assert!(
            report.per_component.iter().any(|c| c.name == "journal_snapshot"),
            "快照失败行必须在报告里：{report:?}"
        );
    }

    // =========================================================================
    // udf testing 族替身消费点（D5，2026-10-31）：状态环 reducer 契约的逐动作/
    // 逐效果断言面，脱离 LoopFx 解释器独立成立。TestStore=效果回收断言
    // （CollectRuntime 只回收不解释）；ScriptedRuntime=脚本化回灌，确定性复现
    // 驱动协议「效果出 → 解释器回灌 → 相位迁移」。替身来自 udf 基件（§3.5.2
    // 白拿），语义不复制。
    // =========================================================================

    /// 用例⑮：TestStore 钉启动效果契约——依赖序 `BringUp × N` + `FinishStart`
    /// 收尾、效果 id 从 0 单调；效果未解释前相位停在 Starting。
    #[test]
    fn test_store_pins_start_effect_contract() {
        let probe = Probe::default();
        let registry = registry_of(vec![fake("A", NO_DEPS, &probe), fake("B", DEP_A, &probe)]);
        let plan = Arc::new(Plan::from_registry(&registry).expect("plan"));
        let mut store = TestStore::new(AssemblyRoot::new(plan));

        store.dispatch(AssemblyAction::Lifecycle(LifecycleAction::Register { name: "A".into() }));
        store.dispatch(AssemblyAction::Lifecycle(LifecycleAction::Register { name: "B".into() }));
        assert_eq!(store.state().lifecycle.phase, AssemblyPhase::Registered);

        store.dispatch(AssemblyAction::Lifecycle(LifecycleAction::Start));
        // 逐条效果断言：依赖序 + id 单调（ExpectedEffect 全比对）。
        store.receive(ExpectedEffect::Run {
            id: Some(EffectId::new(0)),
            op: AssemblyOp::BringUp { name: "A".into() },
        });
        store.receive(ExpectedEffect::Run {
            id: Some(EffectId::new(1)),
            op: AssemblyOp::BringUp { name: "B".into() },
        });
        store.receive(ExpectedEffect::Run {
            id: Some(EffectId::new(2)),
            op: AssemblyOp::FinishStart,
        });
        // CollectRuntime 只回收不解释 → 相位停在 Starting（执行是解释器职责）。
        assert_eq!(store.state().lifecycle.phase, AssemblyPhase::Starting);
    }

    /// 用例⑯：TestStore 钉结果回灌 + 停机效果 + 审计轨迹派生——驱动层回灌
    /// （`AssemblyLoop::start` 所派的同款结果动作）后相位 Running；`Stop` 恰发
    /// 一条 `BeginStop`（id 跨动作连续）；审计分片对同动作流逐条记账。
    #[test]
    fn test_store_pins_outcome_stop_and_audit_trail() {
        let probe = Probe::default();
        let registry = registry_of(vec![fake("A", NO_DEPS, &probe), fake("B", DEP_A, &probe)]);
        let plan = Arc::new(Plan::from_registry(&registry).expect("plan"));
        let mut store = TestStore::new(AssemblyRoot::new(plan));

        for name in ["A", "B"] {
            store.dispatch(AssemblyAction::Lifecycle(LifecycleAction::Register {
                name: name.into(),
            }));
        }
        store.dispatch(AssemblyAction::Lifecycle(LifecycleAction::Start));
        for (id, op) in [
            (0, AssemblyOp::BringUp { name: "A".into() }),
            (1, AssemblyOp::BringUp { name: "B".into() }),
            (2, AssemblyOp::FinishStart),
        ] {
            store.receive(ExpectedEffect::Run { id: Some(EffectId::new(id)), op });
        }
        store.dispatch(AssemblyAction::Lifecycle(LifecycleAction::StartOutcome {
            init_ok: vec!["A".into(), "B".into()],
            started: vec!["A".into(), "B".into()],
            failed: None,
        }));
        assert_eq!(store.state().lifecycle.phase, AssemblyPhase::Running);
        assert_eq!(store.state().lifecycle.started, ["A", "B"]);
        assert_eq!(
            store.state().lifecycle.plugins,
            [
                PluginEntry { name: "A".into(), phase: Phase::Started },
                PluginEntry { name: "B".into(), phase: Phase::Started },
            ]
        );

        store.dispatch(AssemblyAction::Lifecycle(LifecycleAction::Stop));
        store
            .receive(ExpectedEffect::Run { id: Some(EffectId::new(3)), op: AssemblyOp::BeginStop });
        assert_eq!(store.state().lifecycle.phase, AssemblyPhase::Stopping);
        store.dispatch(AssemblyAction::Lifecycle(LifecycleAction::StopOutcome {
            stopped: vec!["B".into(), "A".into()],
        }));
        assert_eq!(store.state().lifecycle.phase, AssemblyPhase::Stopped);

        // 审计分片轨迹（kind+plugin 序完全确定；seq 单调由分片内 base+len 保证）。
        let trail: Vec<_> =
            store.state().audit.entries.iter().map(|e| (e.kind, e.plugin.clone())).collect();
        assert_eq!(
            trail,
            [
                (AuditKind::Register, Some("A".to_string())),
                (AuditKind::Register, Some("B".to_string())),
                (AuditKind::Start, None),
                (AuditKind::PluginStarted, Some("A".to_string())),
                (AuditKind::PluginStarted, Some("B".to_string())),
                (AuditKind::Stop, None),
                (AuditKind::PluginStopped, Some("B".to_string())),
                (AuditKind::PluginStopped, Some("A".to_string())),
            ]
        );
    }

    /// 用例⑰：TestStore 钉相位门负例——非法转移记痕 + 计数、相位不变、零效果
    /// （拒绝路径不泄效果：后续合法 Start 的效果序若混入泄效果即在此破）。
    #[test]
    fn test_store_pins_phase_gate_rejections() {
        let probe = Probe::default();
        let registry = registry_of(vec![fake("A", NO_DEPS, &probe)]);
        let plan = Arc::new(Plan::from_registry(&registry).expect("plan"));
        let mut store = TestStore::new(AssemblyRoot::new(plan));

        // Empty 相位：Start / Stop 均拒（计数单调、相位不变）。
        store.dispatch(AssemblyAction::Lifecycle(LifecycleAction::Start));
        assert_eq!(store.state().lifecycle.phase, AssemblyPhase::Empty);
        assert_eq!(store.state().lifecycle.rejections, 1);
        assert!(store.state().lifecycle.rejected.as_deref().expect("reason").contains("start"));
        store.dispatch(AssemblyAction::Lifecycle(LifecycleAction::Stop));
        assert_eq!(store.state().lifecycle.rejections, 2);

        // Registered 相位：StartOutcome 拒（仅 Starting 受理）。
        store.dispatch(AssemblyAction::Lifecycle(LifecycleAction::Register { name: "A".into() }));
        store.dispatch(AssemblyAction::Lifecycle(LifecycleAction::StartOutcome {
            init_ok: vec!["A".into()],
            started: vec!["A".into()],
            failed: None,
        }));
        assert_eq!(store.state().lifecycle.phase, AssemblyPhase::Registered);
        assert_eq!(store.state().lifecycle.rejections, 3);
        assert!(store.state().lifecycle.rejected.as_deref().expect("reason").contains("outcome"));

        // 拒绝路径零效果：合法 Start 只出 BringUp + FinishStart 两条（id 从 0 起）。
        store.dispatch(AssemblyAction::Lifecycle(LifecycleAction::Start));
        store.receive(ExpectedEffect::Run {
            id: Some(EffectId::new(0)),
            op: AssemblyOp::BringUp { name: "A".into() },
        });
        store.receive(ExpectedEffect::Run {
            id: Some(EffectId::new(1)),
            op: AssemblyOp::FinishStart,
        });
    }

    /// 用例⑱：ScriptedRuntime 脚本化回灌——效果出（Start 契约）→ 脚本回灌驱动层
    /// 同款结果动作 → 相位 Running + 账本/审计推进。驱动协议的确定性复现，
    /// 零真实插件（真解释路径由 LoopFx 全环用例覆盖）。
    #[tokio::test]
    async fn scripted_runtime_pins_outcome_feedback_round_trip() {
        let probe = Probe::default();
        let registry = registry_of(vec![fake("A", NO_DEPS, &probe), fake("B", DEP_A, &probe)]);
        let plan = Arc::new(Plan::from_registry(&registry).expect("plan"));
        let scope = Arc::new(skeleton_infra::fx::FxScope::new());
        let mut scripted = ScriptedRuntime::<AssemblyAction, AssemblyOp>::new(Arc::clone(&scope));
        scripted.feed([Script::Emit(AssemblyAction::Lifecycle(LifecycleAction::StartOutcome {
            init_ok: vec!["A".into(), "B".into()],
            started: vec!["A".into(), "B".into()],
            failed: None,
        }))]);
        let store = SyncStore::new(AssemblyRoot::new(plan), scripted);

        store.dispatch(AssemblyAction::Lifecycle(LifecycleAction::Register { name: "A".into() }));
        store.dispatch(AssemblyAction::Lifecycle(LifecycleAction::Register { name: "B".into() }));
        store.dispatch(AssemblyAction::Lifecycle(LifecycleAction::Start));
        // 脚本任务在 FxScope 内回灌；在飞清零即回灌链折叠完毕。
        while scope.in_flight() > 0 {
            tokio::task::yield_now().await;
        }
        let state = store.snapshot();
        assert_eq!(state.lifecycle.phase, AssemblyPhase::Running, "脚本回灌推进相位");
        assert_eq!(state.lifecycle.started, ["A", "B"]);
        assert!(state.audit.entries.iter().any(|e| e.kind == AuditKind::PluginStarted));
        // 收尾净空（fx::expect_idle 同款锚）。
        let _ = scope.shutdown().await;
    }
}
