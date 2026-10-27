//! P0-5 验收：装配组合根端到端（任务书指定 3 用例 + 缺依赖/成环防御路径）。
//!
//! ①两插件端到端：register→build→start 序正确，shutdown 后 `expect_idle` 通过
//! ②shutdown 报告 `is_clean()`
//! ③build 阶段失败 → 整链 Err 无半启动态（`is_running()==false`、无残任务）
//! ④装配期缺依赖/成环 → 直接 Err，零生命周期调用

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use skeleton_infra::fx::expect_idle;
use xray_frame::{
    Framework, FrameworkBuilder, FrameworkOptions, PluginContext, PluginError,
    error::LifecyclePhase,
    plugin::{Lifecycle, Plugin, PluginContract, PluginDep},
};

static NO_DEPS: &[PluginDep] = &[];
static DEP_A: &[PluginDep] = &[PluginDep { name: "A" }];
static DEP_B: &[PluginDep] = &[PluginDep { name: "B" }];

/// 事件观察器：插件名+事件序列（build/init/start/stop 各记一条）。
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

/// 生命周期行为体：init/start/stop 可注入故障；start 可 spawn 托管任务
/// （`std::future::pending` 永挂——shutdown 第③段 abort + 排空后 expect_idle
/// 才可能通过，真泄漏此处必红）。
struct LifecycleBody {
    name: &'static str,
    probe: Probe,
    fail_start: bool,
    spawn_in_start: bool,
}

impl Lifecycle for LifecycleBody {
    fn init(&self, _ctx: &PluginContext) -> Result<(), PluginError> {
        self.probe.record(format!("{}:init", self.name));
        Ok(())
    }

    fn start(&self, ctx: &PluginContext) -> Result<(), PluginError> {
        self.probe.record(format!("{}:start", self.name));
        if self.fail_start {
            return Err(PluginError::Handler(format!("{} start refused", self.name)));
        }
        if self.spawn_in_start {
            ctx.spawn(std::future::pending::<()>()).expect("scope accepting");
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
    probe: Probe,
    fail_build: bool,
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
        static EMPTY: PluginContract =
            PluginContract { clauses: &[], extra: &[], not_applicable: &[] };
        &EMPTY
    }

    fn lifecycle(&self) -> &dyn Lifecycle {
        &self.body
    }

    fn build(&self, _ctx: &mut PluginContext) -> Result<(), PluginError> {
        self.probe.record(format!("{}:build", self.name));
        if self.fail_build {
            return Err(PluginError::Handler(format!("{} build refused", self.name)));
        }
        Ok(())
    }
}

fn fake(name: &'static str, deps: &'static [PluginDep], probe: &Probe) -> FakePlugin {
    FakePlugin {
        name,
        deps,
        probe: probe.clone(),
        fail_build: false,
        body: LifecycleBody {
            name,
            probe: probe.clone(),
            fail_start: false,
            spawn_in_start: false,
        },
    }
}

fn with_fail_build(mut plugin: FakePlugin) -> FakePlugin {
    plugin.fail_build = true;
    plugin
}

fn with_fail_start(mut plugin: FakePlugin) -> FakePlugin {
    plugin.body.fail_start = true;
    plugin
}

fn with_spawn_in_start(mut plugin: FakePlugin) -> FakePlugin {
    plugin.body.spawn_in_start = true;
    plugin
}

/// 装配选项（fingerprint=None 走装配根派生默认路径）。
fn opts(cap: usize, timeout: Option<Duration>) -> FrameworkOptions {
    FrameworkOptions { registry_cap: cap, id_fingerprint: None, shutdown_timeout: timeout }
}

/// 用例①：两插件端到端——build 拓扑序、init/start 拓扑序逐插件交替（注册序
/// B,A ≠ 启动序，证排序来自 deps）、stop 逆启动序；shutdown 后托管任务收净
/// （expect_idle 真泄漏必红）。
#[tokio::test]
async fn two_plugins_end_to_end_register_build_start_shutdown() {
    let probe = Probe::new();
    let builder = Framework::builder(opts(8, None)).expect("cap 8 registry");
    // 注册序 B(deps A) 在前、A 在后：启动序必须仍为 A,B。
    let builder = builder.register(Arc::new(with_spawn_in_start(fake("B", DEP_A, &probe))));
    let builder = builder.and_then(|b| b.register(Arc::new(fake("A", NO_DEPS, &probe))));
    let mut fw = builder.and_then(FrameworkBuilder::build).expect("build phase");
    assert!(!fw.is_running(), "build 成功但未 bring_up，不得误报运行态");

    fw.bring_up().expect("bring_up succeeds");
    assert!(fw.is_running());
    assert_eq!(
        probe.events(),
        vec![
            "A:build", "B:build", // build 拓扑序
            "A:init", "A:start", "B:init", "B:start", // init/start 拓扑序逐插件交替
        ],
        "装配链观察序必须 build→init→start 且按 deps 拓扑序"
    );

    // scope 提前取（shutdown 消费所有权），停机后做泄漏断言。
    let fx = Arc::clone(fw.scope());
    let report = fw.shutdown().await;
    assert!(report.is_clean(), "健康链停机报告必须干净");
    assert_eq!(
        probe.events(),
        vec![
            "A:build", "B:build", "A:init", "A:start", "B:init", "B:start", "B:stop",
            "A:stop", // stop 逆启动序
        ],
        "停机序必须 = 逆启动序"
    );
    expect_idle(fx.fx());
}

/// 用例②：shutdown 报告 is_clean()——已启动链全 Stopped；未启动链 = 空报告
/// （合法干净）。
#[tokio::test]
async fn shutdown_report_is_clean() {
    let probe = Probe::new();
    let builder = Framework::builder(opts(4, None)).expect("cap 4 registry");
    let mut fw = builder
        .register(Arc::new(fake("A", NO_DEPS, &probe)))
        .and_then(|b| b.register(Arc::new(fake("B", NO_DEPS, &probe))))
        .and_then(FrameworkBuilder::build)
        .expect("build phase");
    fw.bring_up().expect("bring_up succeeds");
    let report = fw.shutdown().await;
    assert!(report.is_clean());
    assert_eq!(report.per_component.len(), 2, "两个插件各一条停机报告行");

    // 未启动链（只 register→build）shutdown = 空报告，同样 is_clean。
    let probe2 = Probe::new();
    let fw2 = Framework::builder(opts(4, None))
        .expect("cap 4 registry")
        .register(Arc::new(fake("A", NO_DEPS, &probe2)))
        .and_then(FrameworkBuilder::build)
        .expect("build phase");
    let report2 = fw2.shutdown().await;
    assert!(report2.is_clean());
    assert!(report2.per_component.is_empty(), "未启动链无停机组件行");
}

/// 用例③：build 阶段失败 → 整链 Err 无半启动态。
/// 子路径 1：`build(ctx)` 失败 → `builder.build()` Err，零 init/start。
/// 子路径 2：init/start 阶段失败 → Framework 可观察：`is_running()==false` +
/// 已启动者逆序回滚；shutdown 第③段排空后无残任务（expect_idle）。
#[tokio::test]
async fn build_phase_failure_fails_visible_without_half_start() {
    // 子路径 1：B.build 拒绝 → 整链 Err；探针证明止于 build 相。
    let probe = Probe::new();
    let builder = Framework::builder(opts(8, None)).expect("cap 8 registry");
    let err = builder
        .register(Arc::new(fake("A", NO_DEPS, &probe)))
        .and_then(|b| b.register(Arc::new(with_fail_build(fake("B", DEP_A, &probe)))))
        .and_then(FrameworkBuilder::build)
        .expect_err("B build refused must fail the chain");
    assert!(
        matches!(&err, PluginError::Handler(m) if m.contains("B build refused")),
        "build 失败原样上抛: {err}"
    );
    assert_eq!(
        probe.events(),
        vec!["A:build", "B:build"],
        "build 失败止于 build 相，零 init/start（无半启动态）"
    );

    // 子路径 2：B.start 失败 → 回滚已启动的 A；is_running 保持 false。
    let probe = Probe::new();
    let builder =
        Framework::builder(opts(8, Some(Duration::from_secs(1)))).expect("cap 8 registry");
    let mut fw = builder
        .register(Arc::new(with_spawn_in_start(fake("A", NO_DEPS, &probe))))
        .and_then(|b| b.register(Arc::new(with_fail_start(fake("B", DEP_A, &probe)))))
        .and_then(FrameworkBuilder::build)
        .expect("build phase succeeds");
    let err = fw.bring_up().expect_err("B start refused");
    assert!(
        matches!(&err, PluginError::Lifecycle { plugin, phase: LifecyclePhase::Start, .. }
            if plugin == "B"),
        "start 失败标炸点插件与相: {err}"
    );
    assert!(!fw.is_running(), "无半启动态：账本保持未启动");
    assert_eq!(
        probe.events(),
        vec!["A:build", "B:build", "A:init", "A:start", "B:init", "B:start", "A:stop",],
        "已启动者 A 逆序回滚 stop；B init 成功未 start 故不 stop"
    );
    // A 在 start 期 spawn 的托管任务仍在途（回滚 stop 闭包同步快收不等排空
    // ——三段式第②段语义）；shutdown 第③段排空收净后 expect_idle 才可能过。
    let fx = Arc::clone(fw.scope());
    let report = fw.shutdown().await;
    assert!(report.is_clean(), "失败链 coordinator 无注册闭包，报告空且干净");
    expect_idle(fx.fx());
}

/// 用例④：装配期缺依赖 / 成环 → `build()` 即 Err（start_order 装配期校验），
/// 零生命周期调用，不产生半启动。
#[test]
fn missing_dep_fails_at_build_without_half_start() {
    let probe = Probe::new();
    let err = Framework::builder(opts(4, None))
        .expect("cap 4 registry")
        .register(Arc::new(fake("B", DEP_A, &probe))) // deps "A" 未注册
        .and_then(FrameworkBuilder::build)
        .expect_err("missing dep must fail at build");
    assert!(
        matches!(&err, PluginError::MissingDep { plugin, dep } if plugin == "B" && dep == "A"),
        "缺依赖标声明方与缺名: {err}"
    );
    assert!(probe.events().is_empty(), "装配期错误零生命周期调用");
}

#[test]
fn cyclic_dep_fails_at_build_without_half_start() {
    let probe = Probe::new();
    let err = Framework::builder(opts(4, None))
        .expect("cap 4 registry")
        .register(Arc::new(fake("A", DEP_B, &probe)))
        .and_then(|b| b.register(Arc::new(fake("B", DEP_A, &probe))))
        .and_then(FrameworkBuilder::build)
        .expect_err("cycle must fail at build");
    match &err {
        PluginError::CyclicDep { cycle } => {
            assert!(
                cycle.contains(&"A".to_string()) && cycle.contains(&"B".to_string()),
                "环残留集含 A/B: {cycle:?}"
            );
        },
        other => panic!("expected CyclicDep, got: {other}"),
    }
    assert!(probe.events().is_empty(), "装配期错误零生命周期调用");
}
