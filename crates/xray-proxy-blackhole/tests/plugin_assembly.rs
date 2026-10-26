//! P1-7 C 块验收：xray-frame 装配链真装 blackhole 插件
//! register → build → bring_up → shutdown，断言 `is_clean()`。
//!
//! （不进 xray-frame——xray-frame 禁依赖协议 crate，拍板 P2.1。）

use std::sync::Arc;

use serde_json::json;
use xray_frame::{
    Plugin, PluginError,
    assembly::{Framework, FrameworkOptions},
};
use xray_proxy_blackhole::{BlackholePlugin, ResponseConfig};

fn framework_options() -> FrameworkOptions {
    FrameworkOptions { registry_cap: 8, id_fingerprint: Some(1), shutdown_timeout: None }
}

fn config_root() -> serde_json::Value {
    json!({ "outbounds": [
        { "protocol": "blackhole", "tag": "bh-out", "settings": { "response": { "type": "http" } } }
    ] })
}

/// 完整装配链：build 期段路由解析 → bring_up 三相 → 停机报告干净。
#[tokio::test]
async fn blackhole_assembles_bring_up_and_shuts_down_clean() {
    let plugin = Arc::new(BlackholePlugin::default());
    let mut framework = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(config_root())
        .register(Arc::clone(&plugin) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect("build phase");
    assert!(!framework.is_running(), "build 成功但未 bring_up，不得误报运行态");

    framework.bring_up().expect("bring_up: init/start 三相");
    assert!(framework.is_running());

    let report = framework.shutdown().await;
    let stopped: Vec<&str> = report.per_component.iter().map(|o| o.name.as_str()).collect();
    assert_eq!(stopped, ["blackhole"], "stop 闭包必须按插件名注册进 ShutdownCoordinator");
    assert!(report.is_clean(), "健康链必须全 Stopped: {report:?}");

    // 停机后插件 build 产物仍在（OnceLock 值语义独立于装配链生命周期）。
    assert_eq!(plugin.built_response().expect("built"), &ResponseConfig::Http403);
}

/// build 期缺段 fail-visible 后整链无半启动态（`is_running()==false`）。
#[tokio::test]
async fn build_failure_leaves_no_half_started_chain() {
    let err = Framework::builder(framework_options())
        .expect("registry cap")
        .register(Arc::new(BlackholePlugin::default()) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect_err("缺段 build 失败");
    assert!(matches!(err, PluginError::Config(_)), "实际: {err}");
    // build 失败 → 无 Framework 产出（fail-visible 无半启动态的编译期形态：
    // builder 已消费，观察面即本 assert 本身）。
}
