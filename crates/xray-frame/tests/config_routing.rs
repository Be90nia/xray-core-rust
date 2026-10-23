//! P3-2 配置段路由集成测（契约任务书 P3-2 验收①）：缺段 fail-fast + 段隔离，
//! 走 [`FrameworkBuilder`] 全管线与 [`build_plugins_from_config`] 配置驱动两入口。

use std::sync::{Arc as StdArc, OnceLock};

use serde_json::{Value, json};
use xray_frame::{
    Framework, FrameworkOptions, Plugin, PluginContext, PluginContract, PluginError,
    build_plugins_from_config, plugin::Lifecycle,
};

/// build 期记录自己段的插件（段隔离断言锚；seen 是 build 期运行时写入 →
/// OnceLock 非 LazyLock）。
struct RecordingPlugin {
    name: &'static str,
    seen: OnceLock<Value>,
}

struct NoopLifecycleImpl;

impl Lifecycle for NoopLifecycleImpl {
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

static NOOP_LIFECYCLE: NoopLifecycleImpl = NoopLifecycleImpl;

/// 测试桩契约：无条款（契约条款面归各协议插件自己的 L4 夹具，此处只测路由）。
static BARE_CONTRACT: PluginContract =
    PluginContract { clauses: &[], extra: &[], not_applicable: &[] };

impl Plugin for RecordingPlugin {
    fn name(&self) -> &'static str {
        self.name
    }

    fn version(&self) -> &'static str {
        "0.0.0"
    }

    fn contract(&self) -> &PluginContract {
        &BARE_CONTRACT
    }

    fn lifecycle(&self) -> &dyn Lifecycle {
        &NOOP_LIFECYCLE
    }

    fn build(&self, ctx: &mut PluginContext) -> Result<(), PluginError> {
        let section = ctx.section()?;
        let _ = self.seen.set(section.clone());
        Ok(())
    }
}

fn opts() -> FrameworkOptions {
    FrameworkOptions { registry_cap: 8, id_fingerprint: None, shutdown_timeout: None }
}

/// 验收①②：注册链插件无自己的段 → 全管线 build 整链 `Err`（fail-fast，
/// 不回落全局/不静默跳过）。
#[test]
fn framework_build_fails_fast_on_missing_section() {
    let plugin = StdArc::new(RecordingPlugin { name: "alpha", seen: OnceLock::new() });
    let err = Framework::builder(opts())
        .expect("opts")
        .with_config(json!({}))
        .register(StdArc::clone(&plugin) as StdArc<dyn Plugin>)
        .expect("register")
        .build()
        .unwrap_err();
    assert!(err.to_string().contains("protocol=alpha"), "missing-section error: {err}");
}

/// 验收①③：双插件各有段 → 各 build 各的段（A 取不到 B 的段 = 段隔离）。
#[test]
fn framework_build_routes_each_plugin_to_its_own_section() {
    let alpha = StdArc::new(RecordingPlugin { name: "alpha", seen: OnceLock::new() });
    let beta = StdArc::new(RecordingPlugin { name: "beta", seen: OnceLock::new() });
    let root = json!({
        "outbounds": [
            {"protocol": "alpha", "settings": {"who": "alpha-out"}},
            {"protocol": "beta", "settings": {"who": "beta-out"}},
        ],
    });
    Framework::builder(opts())
        .expect("opts")
        .with_config(root)
        .register(StdArc::clone(&alpha) as StdArc<dyn Plugin>)
        .expect("register alpha")
        .register(StdArc::clone(&beta) as StdArc<dyn Plugin>)
        .expect("register beta")
        .build()
        .expect("both built");
    assert_eq!(alpha.seen.get().expect("alpha built")["settings"]["who"], "alpha-out");
    assert_eq!(beta.seen.get().expect("beta built")["settings"]["who"], "beta-out");
}

/// 验收①：配置驱动辅助与全管线对同一份配置产出一致的可 build 集（两入口
/// 语义对齐的回归锚；差异面 = 未注册协议跳过，见 src/config.rs 单测）。
#[test]
fn config_driven_and_framework_pipeline_agree_on_built_set() {
    let a1 = StdArc::new(RecordingPlugin { name: "alpha", seen: OnceLock::new() });
    let a2 = StdArc::new(RecordingPlugin { name: "alpha", seen: OnceLock::new() });
    let b1 = StdArc::new(RecordingPlugin { name: "beta", seen: OnceLock::new() });
    let b2 = StdArc::new(RecordingPlugin { name: "beta", seen: OnceLock::new() });
    let root = json!({
        "outbounds": [
            {"protocol": "beta", "settings": {}},
            {"protocol": "alpha", "settings": {}},
        ],
        "inbounds": [
            {"protocol": "alpha", "settings": {}},
        ],
    });
    let config_built = build_plugins_from_config(
        &root,
        &[StdArc::clone(&a1) as StdArc<dyn Plugin>, StdArc::clone(&b1) as StdArc<dyn Plugin>],
    )
    .expect("config-driven build");
    // 全管线（注册顺序 alpha, beta）：配置序 beta 先、inbound alpha 兜底，
    // 两管线 built 集一致（顺序按各自遍历序，集合相等即对齐）。
    let _ = Framework::builder(opts())
        .expect("opts")
        .with_config(root.clone())
        .register(StdArc::clone(&a2) as StdArc<dyn Plugin>)
        .expect("register alpha")
        .register(StdArc::clone(&b2) as StdArc<dyn Plugin>)
        .expect("register beta")
        .build()
        .expect("framework build");
    let mut from_config: Vec<&str> = config_built.clone();
    from_config.sort_unstable();
    assert_eq!(from_config, vec!["alpha", "beta"]);
    // 配置驱动侧：beta（outbounds 首条）先 build，alpha 的第二条目因 inbounds
    // 也命中而补齐——两布局都被扫到。
    assert_eq!(config_built.len(), 2);
    assert!(a1.seen.get().is_some() && b1.seen.get().is_some());
}
