//! P0-2 PluginRegistry 集成验收（契约任务书 P0-2 六条用例 + 硬约束钉死）：
//! ①deps 反序 ②缺依赖 ③成环 ④重名 ⑤容量（含 new(0)）⑥无依赖稳定注册序。
//! 不启动任何生命周期钩子（P0-4 非目标隔离）。

use std::{
    sync::{Arc, mpsc},
    thread,
    time::Duration,
};

use xray_frame::{
    PluginError, PluginRegistry,
    context::PluginContext,
    plugin::{Lifecycle, Plugin, PluginContract, PluginDep},
};

struct StubLifecycle;

impl Lifecycle for StubLifecycle {
    fn init(&self, _ctx: &PluginContext) -> Result<(), PluginError> {
        Ok(())
    }

    fn start(&self, _ctx: &PluginContext) -> Result<(), PluginError> {
        Ok(())
    }

    fn stop(&self) -> Result<(), PluginError> {
        Ok(())
    }
}

/// 最小桩件：名字 + 依赖声明可配，其余 L1 方法给空实现（registry 只消费
/// name/deps，契约/lifecycle/build 不被触碰）。
struct Stub {
    name: &'static str,
    deps: &'static [PluginDep],
}

impl Plugin for Stub {
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
        const EMPTY: PluginContract =
            PluginContract { clauses: &[], extra: &[], not_applicable: &[] };
        &EMPTY
    }

    fn lifecycle(&self) -> &dyn Lifecycle {
        &StubLifecycle
    }

    fn build(&self, _ctx: &mut PluginContext) -> Result<(), PluginError> {
        Ok(())
    }
}

fn stub(name: &'static str, deps: &'static [PluginDep]) -> Arc<dyn Plugin> {
    Arc::new(Stub { name, deps })
}

fn names(plugins: &[Arc<dyn Plugin>]) -> Vec<&'static str> {
    plugins.iter().map(|p| p.name()).collect()
}

/// ①A deps B：注册序 [A,B] → 启动序 [B,A]（注册序≠启动序）。
#[test]
fn start_order_reverses_single_dep() {
    let mut reg = PluginRegistry::new(8).expect("cap ok");
    reg.register(stub("a", &[PluginDep { name: "b" }])).expect("first");
    reg.register(stub("b", &[])).expect("second");
    let order = reg.start_order().expect("acyclic");
    assert_eq!(names(&order), ["b", "a"]);
}

/// ②缺依赖：声明方 a 缺 b → MissingDep{plugin:"a", dep:"b"}（装配期 fail-visible）。
#[test]
fn missing_dep_fails_at_assembly() {
    let mut reg = PluginRegistry::new(8).expect("cap ok");
    reg.register(stub("a", &[PluginDep { name: "b" }])).expect("first");
    match reg.start_order() {
        Err(PluginError::MissingDep { plugin, dep }) => {
            assert_eq!((plugin.as_str(), dep.as_str()), ("a", "b"));
        },
        Err(other) => panic!("expected MissingDep, got {other:?}"),
        Ok(_) => panic!("expected MissingDep, got Ok"),
    }
}

/// ③A↔B 成环：CyclicDep 且 cycle 同时含 "a"/"b"（Kahn 残留集自洽链）。
#[test]
fn two_node_cycle_reports_both_names() {
    let mut reg = PluginRegistry::new(8).expect("cap ok");
    reg.register(stub("a", &[PluginDep { name: "b" }])).expect("first");
    reg.register(stub("b", &[PluginDep { name: "a" }])).expect("second");
    match reg.start_order() {
        Err(PluginError::CyclicDep { cycle }) => {
            assert!(cycle.iter().any(|n| n == "a"), "cycle={cycle:?}");
            assert!(cycle.iter().any(|n| n == "b"), "cycle={cycle:?}");
        },
        Err(other) => panic!("expected CyclicDep, got {other:?}"),
        Ok(_) => panic!("expected CyclicDep, got Ok"),
    }
}

/// ③b 成环必须**有限时间**返回 `CyclicDep`：`start_order` 的轮数上界保证「成环
/// 分支被去掉」的变异体以断言失败退出，而不是在 `find` 恒 None 下无限循环
/// （挂死型红不可观测）。工作线程 + 超时把「挂死」和「panic」都变成可断言的失败。
#[test]
fn two_node_cycle_returns_within_bounded_time() {
    let mut reg = PluginRegistry::new(8).expect("cap ok");
    reg.register(stub("a", &[PluginDep { name: "b" }])).expect("first");
    reg.register(stub("b", &[PluginDep { name: "a" }])).expect("second");
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(matches!(reg.start_order(), Err(PluginError::CyclicDep { .. })));
    });
    let reported_cycle = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("成环必须在有限时间内返回（挂死或 panic 均算失败）");
    assert!(reported_cycle, "成环 → CyclicDep");
}

/// ④重名不覆盖：第二个同名 → Duplicate，注册表不扩容不覆盖。
#[test]
fn duplicate_name_rejected() {
    let mut reg = PluginRegistry::new(8).expect("cap ok");
    reg.register(stub("a", &[])).expect("first");
    match reg.register(stub("a", &[])) {
        Err(PluginError::Duplicate { name }) => assert_eq!(name, "a"),
        other => panic!("expected Duplicate, got {other:?}"),
    }
    assert_eq!(reg.len(), 1, "重名拒后不得覆盖");
}

/// ⑤容量 fail-closed：new(0) 即 Err(Full{cap:0})；new(1) 第二个注册 → Full。
#[test]
fn capacity_is_fail_closed() {
    assert!(matches!(PluginRegistry::new(0), Err(PluginError::Full { cap: 0 })));
    let mut reg = PluginRegistry::new(1).expect("cap 1 ok");
    reg.register(stub("a", &[])).expect("first");
    assert!(matches!(reg.register(stub("b", &[])), Err(PluginError::Full { cap: 1 })));
    assert_eq!(reg.len(), 1);
}

/// ⑥无依赖多插件：启动序 = 注册序（名字取反字典序 c,a,b 钉死「按注册序」，
/// 若实现按名字排序则断言必红）。
#[test]
fn independent_plugins_keep_registration_order() {
    let mut reg = PluginRegistry::new(8).expect("cap ok");
    reg.register(stub("c", &[])).expect("first");
    reg.register(stub("a", &[])).expect("second");
    reg.register(stub("b", &[])).expect("third");
    let order = reg.start_order().expect("acyclic");
    assert_eq!(names(&order), ["c", "a", "b"]);
    // 同层稳定序：start_order 重算两次结果一致（PM 拍板：每次重算不缓存）。
    let again = reg.start_order().expect("acyclic");
    assert_eq!(names(&order), names(&again));
}
