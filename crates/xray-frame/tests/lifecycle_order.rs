//! P0-4 验收：生命周期三相编排语义（任务书指定 4 用例 + 注册被拒防御路径）。
//!
//! ①三插件 A(deps B)/B(deps C)/C：init+start 观察序 = C,B,A（逐插件交替）
//! ②B.start 失败 → C 已 stop、A 未 start、`Err(Lifecycle{phase:Start})`
//! ③tear_down 后 `is_clean()==true` 且 stop 执行序 = A,B,C（逆启动序）
//! ④init panic → `Lifecycle{phase:Init}` 且无资源泄漏（已启动者全回滚）

use std::sync::{Arc, Mutex};

use skeleton::{clock::SystemClock, config::MockEnv};
use skeleton_infra::shutdown::ShutdownCoordinator;
use xray_frame::{
    PluginContext, PluginError, PluginRegistry,
    context::derive_fingerprint,
    error::LifecyclePhase,
    lifecycle::{Phase, bring_up},
    logging::LogFacade,
    plugin::{Lifecycle, Plugin, PluginContract, PluginDep},
};

const FIXED_ADDR: &str = "127.0.0.1:10808";

static NO_DEPS: &[PluginDep] = &[];
static DEP_C: &[PluginDep] = &[PluginDep { name: "C" }];
static DEP_B: &[PluginDep] = &[PluginDep { name: "B" }];

/// 事件观察器：`(插件名, 事件)` 序列（init/start/stop 各记一条）。
#[derive(Clone)]
struct Probe(Arc<Mutex<Vec<String>>>);

impl Probe {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(Vec::new())))
    }

    fn record(&self, event: String) {
        self.0.lock().expect("probe poisoned").push(event);
    }

    fn events(&self) -> Vec<String> {
        self.0.lock().expect("probe poisoned").clone()
    }
}

/// 生命周期行为体（init/start/stop 的可编排故障注入点）。
struct LifecycleBody {
    name: &'static str,
    probe: Probe,
    fail_start: bool,
    panic_init: bool,
}

impl Lifecycle for LifecycleBody {
    fn init(&self, _ctx: &PluginContext) -> Result<(), PluginError> {
        self.probe.record(format!("{}:init", self.name));
        if self.panic_init {
            panic!("boom in {} init", self.name);
        }
        Ok(())
    }

    fn start(&self, _ctx: &PluginContext) -> Result<(), PluginError> {
        self.probe.record(format!("{}:start", self.name));
        if self.fail_start {
            return Err(PluginError::Handler(format!("{} start refused", self.name)));
        }
        Ok(())
    }

    fn stop(&self) -> Result<(), PluginError> {
        self.probe.record(format!("{}:stop", self.name));
        Ok(())
    }
}

struct FakePlugin {
    name: &'static str,
    deps: &'static [PluginDep],
    contract: PluginContract,
    body: LifecycleBody,
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
        &self.contract
    }

    fn lifecycle(&self) -> &dyn Lifecycle {
        &self.body
    }

    fn build(&self, _ctx: &mut PluginContext) -> Result<(), PluginError> {
        Ok(())
    }
}

fn fake(name: &'static str, deps: &'static [PluginDep], probe: &Probe) -> FakePlugin {
    FakePlugin {
        name,
        deps,
        contract: PluginContract { clauses: &[], extra: &[], not_applicable: &[] },
        body: LifecycleBody { name, probe: probe.clone(), fail_start: false, panic_init: false },
    }
}

fn with_fail_start(mut plugin: FakePlugin) -> FakePlugin {
    plugin.body.fail_start = true;
    plugin
}

fn with_panic_init(mut plugin: FakePlugin) -> FakePlugin {
    plugin.body.panic_init = true;
    plugin
}

/// 注册表装配（容量 8 足容纳全部测例插件）。
fn registry_of(plugins: Vec<FakePlugin>) -> PluginRegistry {
    let mut registry = PluginRegistry::new(8).expect("registry capacity");
    for plugin in plugins {
        registry.register(Arc::new(plugin)).expect("unique names");
    }
    registry
}

/// ctx 工厂（照抄 context.rs 测试配方：FxScope + SystemClock + MockEnv）。
fn ctx_factory() -> impl Fn(&Arc<dyn Plugin>) -> Result<PluginContext, PluginError> {
    |plugin: &Arc<dyn Plugin>| {
        Ok(PluginContext::new(
            plugin.name(),
            Arc::new(skeleton_infra::fx::FxScope::new()),
            Arc::new(SystemClock),
            derive_fingerprint(Some(FIXED_ADDR)),
            Arc::new(MockEnv::new()),
            serde_json::json!({}),
            LogFacade::new(plugin.name(), vec![]),
            Arc::new(xray_frame::AuditHandle::new(xray_frame::DEFAULT_AUDIT_RING_CAP)),
        ))
    }
}

/// 用例①：拓扑序启动，观察序 = C,B,A（逐插件 init→start 交替）。
#[test]
fn bring_up_starts_in_dependency_order() {
    let probe = Probe::new();
    // 注册序 A,B,C ≠ 启动序（证明排序来自 deps 而非注册序）。
    let registry = registry_of(vec![
        fake("A", DEP_B, &probe),
        fake("B", DEP_C, &probe),
        fake("C", NO_DEPS, &probe),
    ]);

    let started = bring_up(&registry, ctx_factory(), Arc::new(ShutdownCoordinator::new()))
        .expect("bring_up succeeds");

    assert_eq!(
        probe.events(),
        vec!["C:init", "C:start", "B:init", "B:start", "A:init", "A:start"],
        "init/start 必须逐插件交替且按拓扑序"
    );
    assert_eq!(started.phases().len(), 3);
    assert!(
        started.phases().iter().all(|(_, phase)| *phase == Phase::Started),
        "全部插件账本相位 = Started"
    );

    let report = started.tear_down();
    assert!(report.is_clean(), "健康链 tear_down 报告必须干净");
}

/// 用例②：B.start 失败 → C 已 stop、A 未 start、`Err(Lifecycle{phase:Start})`。
#[test]
fn start_failure_rolls_back_started_plugins() {
    let probe = Probe::new();
    let registry = registry_of(vec![
        fake("A", DEP_B, &probe),
        with_fail_start(fake("B", DEP_C, &probe)),
        fake("C", NO_DEPS, &probe),
    ]);

    let error = bring_up(&registry, ctx_factory(), Arc::new(ShutdownCoordinator::new()))
        .expect_err("start 失败必须整链失败");

    let PluginError::Lifecycle { plugin, phase, source } = error else {
        panic!("start 失败必须收敛 PluginError::Lifecycle，实际 {error:?}");
    };
    assert_eq!(plugin, "B");
    assert_eq!(phase, LifecyclePhase::Start);
    assert!(source.to_string().contains("B start refused"), "source 链保原始错误");

    // A 未 init（逐插件交替下 B 炸即中断）；C start 成功 → 回滚 stop。
    assert_eq!(
        probe.events(),
        vec!["C:init", "C:start", "B:init", "B:start", "C:stop"],
        "回滚只及已 start 成功者；init 成功但 start 失败的 B 不 stop"
    );
}

/// 用例③：tear_down 后 is_clean()==true 且 stop 执行序 = A,B,C（逆启动序）。
#[test]
fn tear_down_stops_in_reverse_start_order_and_reports_clean() {
    let probe = Probe::new();
    let registry = registry_of(vec![
        fake("A", DEP_B, &probe),
        fake("B", DEP_C, &probe),
        fake("C", NO_DEPS, &probe),
    ]);
    let coordinator = Arc::new(ShutdownCoordinator::new());

    let started =
        bring_up(&registry, ctx_factory(), Arc::clone(&coordinator)).expect("bring_up succeeds");
    let report = started.tear_down();

    assert!(report.is_clean(), "全部组件必须干净停机：{report:?}");
    assert_eq!(probe.events()[6..], ["A:stop", "B:stop", "C:stop"], "stop 执行序 = 逆启动序");
    assert_eq!(
        report.per_component.iter().map(|o| o.name.as_str()).collect::<Vec<_>>(),
        vec!["A", "B", "C"],
        "报告行序 = 注册序 = 逆启动序"
    );
}

/// 用例④：init panic → `Lifecycle{phase:Init}`，payload 进 source，无资源泄漏。
#[test]
fn init_panic_becomes_lifecycle_error_without_leak() {
    let probe = Probe::new();
    let registry = registry_of(vec![
        fake("A", DEP_B, &probe),
        with_panic_init(fake("B", DEP_C, &probe)),
        fake("C", NO_DEPS, &probe),
    ]);

    let error = bring_up(&registry, ctx_factory(), Arc::new(ShutdownCoordinator::new()))
        .expect_err("init panic 必须整链失败");

    let PluginError::Lifecycle { plugin, phase, source } = error else {
        panic!("init panic 必须收敛 PluginError::Lifecycle，实际 {error:?}");
    };
    assert_eq!(plugin, "B");
    assert_eq!(phase, LifecyclePhase::Init);
    assert!(source.to_string().contains("boom in B init"), "panic payload 提取进 source");

    // C 已启动 → 已 stop（无泄漏）；A 未动。
    assert_eq!(
        probe.events(),
        vec!["C:init", "C:start", "B:init", "C:stop"],
        "init panic 不逃逸编排线程，已启动者全部回滚"
    );
}

/// 防御路径：coordinator 注册窗已关 → 整链回滚 + fail-visible（`Other`）。
#[test]
fn register_closed_fails_visible_after_full_rollback() {
    let probe = Probe::new();
    let registry = registry_of(vec![
        fake("A", DEP_B, &probe),
        fake("B", DEP_C, &probe),
        fake("C", NO_DEPS, &probe),
    ]);
    let coordinator = Arc::new(ShutdownCoordinator::new());
    coordinator.shutdown(); // 关注册窗（无组件报告 = 合法）

    let error = bring_up(&registry, ctx_factory(), coordinator).expect_err("注册被拒必须整链失败");

    assert!(matches!(error, PluginError::Other(_)), "RegisterError::Closed 走 Other：{error:?}");
    assert_eq!(
        probe.events(),
        vec![
            "C:init", "C:start", "B:init", "B:start", "A:init", "A:start", "A:stop", "B:stop",
            "C:stop",
        ],
        "注册失败 = 整链失败：全部已启动者逆序回滚"
    );
}
