//! P0-8 验收：停机接线（ShutdownCoordinator × Framework 生产链）。
//!
//! ①三插件端到端：stop 执行序 = 逆启动序（`Framework::shutdown` 全链观察序断言）
//! ②某插件 stop 闭包 panic → 该组件 `OutcomeKind::Failed`、其余 `Stopped`、
//!   `is_clean()==false`，编排不中断（后续组件照常执行）
//! ③`with_default_timeout(50ms)` 下慢闭包 → `OutcomeKind::TimedOut` 且编排
//!   不挂死
//! ④重名防线双层：整链侧（P0-2 注册表拒 → `builder.register` Err）+
//!   coordinator 侧重名形状（`RegisterError::Duplicate`，bring_up 映射的输入；
//!   udf 既有测例 `skeleton-infra/tests/shutdown.rs::duplicate_name_is_rejected`）
//! ⑤`FrameworkOptions.shutdown_timeout` 真透传 `with_default_timeout`
//!   （透传断裂 → 默认 5s 档吞掉 50ms 档，慢闭包记 Stopped，本测例必红）

use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use skeleton::{clock::SystemClock, config::MockEnv};
use skeleton_infra::shutdown::{
    ComponentOutcome, OutcomeKind, RegisterError, ShutdownCoordinator, ShutdownReport,
};
use xray_frame::{
    Framework, FrameworkOptions, PluginContext, PluginError, PluginRegistry,
    context::derive_fingerprint,
    lifecycle::bring_up,
    logging::LogFacade,
    plugin::{Lifecycle, Plugin, PluginContract, PluginDep},
};

const FIXED_ADDR: &str = "127.0.0.1:10808";

static NO_DEPS: &[PluginDep] = &[];
static DEP_C: &[PluginDep] = &[PluginDep { name: "C" }];
static DEP_B: &[PluginDep] = &[PluginDep { name: "B" }];

/// 事件观察器：`(插件名, 事件)` 序列（与 lifecycle_order.rs 同款）。
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

/// 生命周期行为体：stop 可注入 panic / 慢闭包（P0-8 观测面注入点）。
struct LifecycleBody {
    name: &'static str,
    probe: Probe,
    panic_stop: bool,
    slow_stop: Option<Duration>,
}

impl Lifecycle for LifecycleBody {
    fn init(&self, _ctx: &PluginContext) -> Result<(), PluginError> {
        self.probe.record(format!("{}:init", self.name));
        Ok(())
    }

    fn start(&self, _ctx: &PluginContext) -> Result<(), PluginError> {
        self.probe.record(format!("{}:start", self.name));
        Ok(())
    }

    fn stop(&self) -> Result<(), PluginError> {
        self.probe.record(format!("{}:stop", self.name));
        if let Some(d) = self.slow_stop {
            std::thread::sleep(d);
        }
        if self.panic_stop {
            panic!("boom in {} stop", self.name);
        }
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
        body: LifecycleBody { name, probe: probe.clone(), panic_stop: false, slow_stop: None },
    }
}

fn with_panic_stop(mut plugin: FakePlugin) -> FakePlugin {
    plugin.body.panic_stop = true;
    plugin
}

fn with_slow_stop(mut plugin: FakePlugin, d: Duration) -> FakePlugin {
    plugin.body.slow_stop = Some(d);
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

/// ctx 工厂（照抄 lifecycle_order.rs 配方：FxScope + SystemClock + MockEnv）。
fn ctx_factory() -> impl Fn(&Arc<dyn Plugin>) -> Result<PluginContext, PluginError> {
    |plugin: &Arc<dyn Plugin>| {
        Ok(PluginContext::new(
            plugin.name(),
            xray_frame::scope::ArmScope::new(),
            Arc::new(SystemClock),
            derive_fingerprint(Some(FIXED_ADDR)),
            Arc::new(MockEnv::new()),
            serde_json::json!({}),
            LogFacade::new(plugin.name(), vec![]),
            Arc::new(xray_frame::AuditHandle::new(xray_frame::DEFAULT_AUDIT_RING_CAP)),
        ))
    }
}

/// 装配选项（与 assembly_e2e.rs 同款）。
fn opts(cap: usize, timeout: Option<Duration>) -> FrameworkOptions {
    FrameworkOptions { registry_cap: cap, id_fingerprint: None, shutdown_timeout: timeout }
}

/// 报告行取用：按名查（名字随行——报告自足）。
fn outcome<'a>(report: &'a ShutdownReport, name: &str) -> &'a ComponentOutcome {
    report
        .per_component
        .iter()
        .find(|o| o.name == name)
        .unwrap_or_else(|| panic!("component {name} missing from report: {report:?}"))
}

/// 用例①：Framework 全链（P0-8 生产接线）——三插件 stop 执行序 = 逆启动序。
#[tokio::test]
async fn framework_shutdown_stops_plugins_in_reverse_start_order() {
    let probe = Probe::new();
    // 注册序 A,B,C；deps 链 → 启动序 C,B,A → 停机注册序（逆启动序）A,B,C。
    let mut fw = Framework::builder(opts(8, None))
        .expect("cap 8")
        .register(Arc::new(fake("A", DEP_B, &probe)))
        .expect("unique A")
        .register(Arc::new(fake("B", DEP_C, &probe)))
        .expect("unique B")
        .register(Arc::new(fake("C", NO_DEPS, &probe)))
        .expect("unique C")
        .build()
        .expect("build ok");
    fw.bring_up().expect("bring_up ok");

    let report = fw.shutdown().await;

    assert!(report.is_clean(), "健康链报告必须干净：{report:?}");
    assert_eq!(
        &probe.events()[6..],
        ["A:stop", "B:stop", "C:stop"],
        "stop 观察序 = 逆启动序（启动序 C,B,A）"
    );
    assert_eq!(
        report.per_component.iter().map(|o| o.name.as_str()).collect::<Vec<_>>(),
        vec!["A", "B", "C"],
        "报告行序 = coordinator 注册序 = 逆启动序"
    );
}

/// 用例②：stop 闭包 panic → 该组件 `Failed`（载荷留痕）、其余 `Stopped`、
/// `is_clean()==false`、编排不中断。
#[test]
fn stop_panic_marks_failed_others_stopped_and_report_not_clean() {
    let probe = Probe::new();
    let registry = registry_of(vec![
        fake("A", NO_DEPS, &probe),
        with_panic_stop(fake("B", NO_DEPS, &probe)),
        fake("C", NO_DEPS, &probe),
    ]);
    let started = bring_up(&registry, ctx_factory(), Arc::new(ShutdownCoordinator::new()))
        .expect("bring_up ok");

    let report = started.tear_down();

    assert!(!report.is_clean(), "panic 必须 fail-visible：{report:?}");
    let b = outcome(&report, "B");
    assert!(
        matches!(&b.kind, OutcomeKind::Failed { reason } if reason.contains("boom in B stop")),
        "panic 组件记 Failed 且载荷留痕：{b:?}"
    );
    for name in ["A", "C"] {
        assert_eq!(outcome(&report, name).kind, OutcomeKind::Stopped, "{name} 照常 Stopped");
    }
    assert_eq!(
        &probe.events()[6..],
        ["C:stop", "B:stop", "A:stop"],
        "编排不中断：panic 之后的组件闭包照常执行"
    );
}

/// 用例③：默认档 50ms 下慢闭包 → `TimedOut` 且编排不挂死、其余组件照常。
#[test]
fn slow_stop_times_out_without_hanging_orchestration() {
    let probe = Probe::new();
    let registry = registry_of(vec![
        with_slow_stop(fake("SLOW", NO_DEPS, &probe), Duration::from_millis(500)),
        fake("QUICK", NO_DEPS, &probe),
    ]);
    let coordinator =
        Arc::new(ShutdownCoordinator::new().with_default_timeout(Duration::from_millis(50)));
    let started = bring_up(&registry, ctx_factory(), coordinator).expect("bring_up ok");

    let begin = Instant::now();
    let report = started.tear_down();

    assert!(begin.elapsed() < Duration::from_secs(2), "编排被慢闭包拖死");
    assert_eq!(outcome(&report, "SLOW").kind, OutcomeKind::TimedOut, "{report:?}");
    assert_eq!(
        outcome(&report, "QUICK").kind,
        OutcomeKind::Stopped,
        "慢组件超时后其余组件照常执行"
    );
    assert!(!report.is_clean());
}

/// 用例④（防线第一层·整链侧）：重名插件 → `builder.register` Err（P0-2 注册表
/// 重名不覆盖），装配在最早点 fail-visible。
#[test]
fn duplicate_plugin_name_fails_visible_at_builder() {
    let probe = Probe::new();
    let builder = Framework::builder(opts(8, None))
        .expect("cap 8")
        .register(Arc::new(fake("DUP", NO_DEPS, &probe)))
        .expect("first registration ok");

    let err = match builder.register(Arc::new(fake("DUP", NO_DEPS, &probe))) {
        Err(err) => err,
        Ok(_) => panic!("重名必须 fail-visible"),
    };

    assert!(matches!(&err, PluginError::Duplicate { name } if name.as_str() == "DUP"), "{err:?}");
    assert!(probe.events().is_empty(), "装配被拒 → 零生命周期调用");
}

/// 用例④（防线第二层·coordinator 侧）：重名 → `RegisterError::Duplicate`——
/// bring_up 注册被拒时经 `register_failure` 映射 `PluginError::Duplicate` 整链
/// 失败；生产链上该层被第一层前置挡死（注册表已拒重名 → coordinator 收到的
/// 名字必唯一），故直构复核映射输入形状。udf 侧既有测例：
/// `skeleton-infra/tests/shutdown.rs::duplicate_name_is_rejected`。
#[test]
fn coordinator_duplicate_register_error_shape() {
    let coordinator = ShutdownCoordinator::new();
    coordinator.register("DUP", || {}).expect("首次注册成功");
    assert_eq!(
        coordinator.register("DUP", || {}),
        Err(RegisterError::Duplicate("DUP".to_string()))
    );
}

/// 用例⑤（接缝实证）：`FrameworkOptions.shutdown_timeout` 真透传
/// `with_default_timeout`——50ms 档下慢闭包在 `Framework::shutdown` 报告记
/// `TimedOut`；若透传断裂（恒 5s 默认档），500ms 闭包会记 `Stopped`，本测例红。
#[tokio::test]
async fn framework_options_shutdown_timeout_flows_to_coordinator_default() {
    let probe = Probe::new();
    let mut fw = Framework::builder(opts(8, Some(Duration::from_millis(50))))
        .expect("cap 8")
        .register(Arc::new(with_slow_stop(
            fake("SLOW", NO_DEPS, &probe),
            Duration::from_millis(500),
        )))
        .expect("unique SLOW")
        .build()
        .expect("build ok");
    fw.bring_up().expect("bring_up ok");

    let begin = Instant::now();
    let report = fw.shutdown().await;

    assert!(begin.elapsed() < Duration::from_secs(2), "编排被慢闭包拖死");
    assert_eq!(
        outcome(&report, "SLOW").kind,
        OutcomeKind::TimedOut,
        "options 超时档必须生效为 coordinator 默认档：{report:?}"
    );
}
