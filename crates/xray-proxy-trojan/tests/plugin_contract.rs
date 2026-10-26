//! P2 批次 B 验收：L4 契约夹具（12 条全适用 + TRJ-1）+ 装配链
//! register → build → bring_up → shutdown（`is_clean()`）。
//!
//! （注册不进 xray-frame——xray-frame 禁依赖协议 crate，拍板 P2.1；同
//! blackhole P1-7 / socks P2-A 的做法，注册写在协议 crate 自己的装配链里。）

use std::sync::Arc;

use serde_json::json;
use xray_frame::{
    ClauseId, Plugin, PluginDep, PluginError,
    assembly::{Framework, FrameworkOptions},
    assert_plugin_contract,
};
use xray_proxy_trojan::TrojanPlugin;

fn framework_options() -> FrameworkOptions {
    FrameworkOptions { registry_cap: 8, id_fingerprint: Some(1), shutdown_timeout: None }
}

/// 段形态：inbounds[] 按 protocol 路由（坑约束 7；trojan 生产形态是入站，
/// 段路由的 inbounds[] 回落半边在此被真实覆盖）。
fn trojan_section_config(settings: serde_json::Value) -> serde_json::Value {
    json!({ "inbounds": [
        { "protocol": "trojan", "tag": "trojan-in", "settings": settings }
    ] })
}

#[test]
fn contract_macro_holds_for_trojan() {
    assert_plugin_contract!(TrojanPlugin);
}

/// 契约面内容断言：12 条通用条款全适用（无 N/A）、TRJ-1 协议专属。
#[test]
fn contract_surface_declares_all_applicable_and_extra() {
    let plugin = TrojanPlugin::default();
    let contract = plugin.contract();

    assert_eq!(plugin.name(), "trojan");
    assert_eq!(plugin.version(), "0.1.0");
    let deps: &[PluginDep] = plugin.deps();
    assert!(deps.is_empty(), "trojan 无依赖插件");

    assert_eq!(contract.clauses.len(), 12, "trojan 12 条全适用（差异表 §2.2 第 3 行）");
    let expected: &[ClauseId] = &[
        ClauseId::AuthErrorClassified,
        ClauseId::HandshakeDeadline,
        ClauseId::ConnIdPresent,
        ClauseId::PoolDiscipline,
        ClauseId::SpawnManaged,
        ClauseId::StopRegistered,
        ClauseId::ConfigSectionOnly,
        ClauseId::ErrorClassifiedNoPanicEscape,
        ClauseId::BoundedResources,
        ClauseId::LogDiscipline,
        ClauseId::SecretMasking,
        ClauseId::HotPathFreeze,
    ];
    for clause in expected {
        assert!(contract.clauses.contains(clause), "缺条款 {clause:?}");
    }
    assert!(contract.not_applicable.is_empty(), "全适用 → 不允许 N/A 声明");

    assert_eq!(
        contract.extra,
        &[("TRJ-1", "u16/u8 边界必须显式检查禁饱和截断")],
        "协议专属条款 TRJ-1"
    );
}

/// 完整装配链：段路由解析 → bring_up 三相 → 停机报告干净；
/// build 产物逐字段核对（clients 入 Validator + fallback dest 推导）。
#[tokio::test]
async fn trojan_assembles_bring_up_and_shuts_down_clean() {
    let plugin = Arc::new(TrojanPlugin::default());
    let mut framework = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(trojan_section_config(json!({
            "clients": [{ "password": "test-pass-12345", "email": "alice" }],
            "fallbacks": [{ "dest": 8080, "xver": 1 }]
        })))
        .register(Arc::clone(&plugin) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect("build phase");
    assert!(!framework.is_running(), "build 成功但未 bring_up，不得误报运行态");

    framework.bring_up().expect("bring_up: init/start 三相");
    assert!(framework.is_running());

    let report = framework.shutdown().await;
    assert!(report.is_clean(), "健康链停机报告必须干净");

    let validator = plugin.built_validator().expect("built");
    assert_eq!(validator.get_count(), 1, "clients 灌入 Validator");
    assert!(validator.get_by_email("alice").is_some());

    let fb = plugin.built_fallbacks().expect("built").as_ref().expect("fallbacks 在场");
    let matched = fb.decide("", "", "").expect("通配 fallback 命中");
    assert_eq!(matched.dest, "localhost:8080", "数字 dest 同规生产 → localhost:N");
    assert_eq!(matched.r#type, "tcp", "host:port 形态推导 tcp");
    assert_eq!(matched.xver, 1);
}

/// L5 装配门负向：缺段 fail-fast（坑约束 7 装配半边），
/// build 失败 → 无 Framework 产出（无半启动态）。
#[tokio::test]
async fn missing_section_fails_fast_at_build() {
    let err = Framework::builder(framework_options())
        .expect("registry cap")
        .register(Arc::new(TrojanPlugin::default()) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect_err("config 根无 trojan 段必须 fail-fast");
    assert!(matches!(err, PluginError::Config(_)), "实际: {err}");
}

/// L5 装配门负向：fallback `dest` 缺失 → build `Err`（同规生产 Go
/// trojan.go:196-198 硬错，拒启）。
#[tokio::test]
async fn fallback_dest_missing_fails_fast_at_build() {
    let err = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(trojan_section_config(json!({
            "clients": [{ "password": "test-pass-12345" }],
            "fallbacks": [{ "name": "sni" }]
        })))
        .register(Arc::new(TrojanPlugin::default()) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect_err("fallback dest 缺失必须 fail-fast");
    assert!(
        err.to_string().contains(r#"please fill in a valid value for every "dest""#),
        "实际: {err}"
    );
}

/// 入站 handler 由插件产出（tag 注入 + 用户/fallback 配置从段注入；bind/
/// handshake 行为属既有 InboundHandler 实测——server.rs 零 diff，wire 不变）。
#[tokio::test]
async fn inbound_handler_produced_by_plugin() {
    let plugin = Arc::new(TrojanPlugin::default());
    let framework = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(trojan_section_config(json!({
            "clients": [{ "password": "test-pass-12345" }],
            "fallbacks": [{ "dest": 80 }]
        })))
        .register(Arc::clone(&plugin) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect("build");

    let inbound = plugin.inbound_handler("trojan-in").expect("inbound handler");
    assert_eq!(inbound.tag(), "trojan-in");
    assert_eq!(plugin.built_validator().expect("built").get_key_count(), 1, "用户配置随插件注入");

    framework.shutdown().await;
}

/// build 前调用观察面 → `Err`（fail-visible，不 panic）。
#[test]
fn observface_before_build_fails_visible() {
    let plugin = TrojanPlugin::default();
    assert!(plugin.built_validator().is_err());
    assert!(plugin.built_fallbacks().is_err());
    assert!(plugin.inbound_handler("trojan-in").is_err());
}

// ── L4 行为夹具接线（P1-L4：每协议 crate 必调，缺=CI 红）──
// 按 contract() 声明面（src/plugin.rs TROJAN_CLAUSES，12 条全适用）：
// 跑 conn_id(3) / deadline(2) / log(10,11) / pool(4)，无跳过项。

/// 夹具一（坑约束 3）：conn_id 非零/唯一/单调——无例外条款。
///
/// 执行面：`contract_test_context` 的指纹随进程掷点（`derive_fingerprint(None)`），
/// 基址落 0xFFF 邻域时同毫秒 64 连发会撞 IdGen fail-closed 配额臂（约 1.5%/掷点，
/// panic 消息含「配额耗尽」）——夹具整体在 catch_unwind 内彩排，撞配额臂则重掷
/// 指纹重跑（8 连败联合概率 ~1e-15），其余 panic 原样上抛。成功返回 = 宏断言在
/// 本 ctx 上真实执行且通过。
fn l4_run_conn_id_fixture(plugin: &'static str) {
    use std::{
        any::Any,
        panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    };

    let mut last: Option<Box<dyn Any + Send>> = None;
    for _ in 0..8 {
        let ctx = xray_frame::contract_assert::contract_test_context(plugin);
        match catch_unwind(AssertUnwindSafe(|| xray_frame::assert_conn_id_present!(ctx, 64))) {
            Ok(()) => return,
            Err(payload) => {
                let quota =
                    payload.downcast_ref::<String>().is_some_and(|m| m.contains("配额耗尽"))
                        || payload
                            .downcast_ref::<&'static str>()
                            .is_some_and(|m| m.contains("配额耗尽"));
                if !quota {
                    resume_unwind(payload);
                }
                last = Some(payload);
            },
        }
    }
    resume_unwind(last.expect("重掷循环至少记录一次失败 payload"));
}

#[test]
fn l4_conn_id_present() {
    l4_run_conn_id_fixture("trojan");
}

/// 夹具二（坑约束 2）：deadline 双入口（with_deadline / HandshakeDeadline::guard）
/// 期限内 Ok、永不完成 Err(Elapsed) 且真超时。d 钉 100ms 上限（CI 慢机安全）。
#[tokio::test]
async fn l4_deadline_effective() {
    xray_frame::assert_deadline_effective!(std::time::Duration::from_millis(100), || async {})
        .await;
}

/// 夹具三（坑约束 10/11）：target 前缀 `xray_frame::trojan` + conn_id/stage/
/// peer/dest 四元组齐全 + secrets 掩码（条款 11 适用 → 表传真实形态凭据样例）。
#[test]
fn l4_log_fields() {
    xray_frame::assert_log_fields!(
        domain: "trojan",
        conn_id: 0x1234u128,
        stage: "Handshake",
        peer: "203.0.113.7:443",
        dest: "example.com:80",
        secrets: ["trojan-credential-sample"],
    );
}

/// 夹具四（坑约束 4/9）：借 N 还 N → PoolMetrics 配平（borrowed=0 且零溢出丢弃）。
#[test]
fn l4_pool_discipline() {
    let pool =
        xray_frame::pool::ManagedBufferPool::new(xray_frame::pool::XrayBufPool::new(8, 8), 8, 8);
    xray_frame::assert_pool_discipline!(pool, 4);
}

// ── L4 真实实例夹具（bd 2zi1o）──
// 上面四条 l4_*（含兄弟 crate 的同族 56 条）验的是**框架原语**：ctx/池由夹具自造、
// work 闭包为空，插件类型从未出场。本条把契约断言接到真实 `TrojanPlugin` 实例上，
// 并补上既有装配链测试判不出的面——`report.is_clean()` 对**空报告**也返回 true
// （零组件无可失败），所以「stop 从未注册」同样能绿；只有按插件名逐条核对报告
// 条目才算条款 6 StopRegistered 的执行面。

/// 真实实例契约夹具：声明面取实例值 → lifecycle 三相经 bring_up 真实编排 → stop
/// 闭包按插件名注册进 ShutdownCoordinator → build 产物行为可用。
///
/// 证伪面（实测）：lifecycle 断（start/stop 返 Err）→ bring_up/report 红；build
/// 空壳化 → `built_validator()` 返 Err → 红；name 改名 → 报告条目名不匹配红。
#[tokio::test]
async fn l4_real_instance_contract_lifecycle_and_stop_registered() {
    let plugin = Arc::new(TrojanPlugin::default());

    // ① 声明面：实例真实值（deps/contract 都有默认或静态面，单测默认实现判不出接线）。
    assert_eq!(plugin.name(), "trojan", "插件名 = 段路由 key（坑约束 7）");
    assert_eq!(plugin.version(), env!("CARGO_PKG_VERSION"), "version 随 crate 版本");
    assert!(plugin.deps().is_empty(), "trojan 不依赖其他插件");
    assert_eq!(plugin.contract().clauses.len(), 12, "12 条通用条款全适用");

    // ② lifecycle：init→start 由 bring_up 按真实 lifecycle 对象编排，stop 由
    //    coordinator 执行（插件级三相直通，连接级 accept 属实例面，见 src/plugin.rs）。
    let mut framework = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(trojan_section_config(json!({
            "clients": [{ "password": "test-pass-12345", "email": "alice" }],
            "fallbacks": [{ "dest": 80 }]
        })))
        .register(Arc::clone(&plugin) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect("build phase");
    framework.bring_up().expect("bring_up: init/start 三相（真实 lifecycle 对象）");
    assert!(framework.is_running(), "bring_up 后账本必须是运行态");

    // ③ 条款 6 StopRegistered 执行面：报告里必须恰有该插件名的条目。
    let report = framework.shutdown().await;
    let stopped: Vec<&str> = report.per_component.iter().map(|o| o.name.as_str()).collect();
    assert_eq!(stopped, ["trojan"], "stop 闭包必须按插件名注册进 ShutdownCoordinator");
    assert!(report.is_clean(), "健康链必须全 Stopped: {report:?}");

    // ④ 行为：段 → build 产物来自真实实例（空壳插件 build 空转 → 下面全 Err）。
    let validator = plugin.built_validator().expect("build 产出 validator");
    assert_eq!(validator.get_count(), 1, "段内 client 进 email 索引");
    assert_eq!(validator.get_key_count(), 1, "同一 client 进 hex(key) 索引");
    assert!(validator.get_by_email("alice").is_some(), "段内用户可按 email 取出");
    assert!(validator.get_by_email("mallory").is_none(), "未配置用户不得通过查找");
    assert_eq!(
        plugin.inbound_handler("trojan-in").expect("build 产出入站 handler").tag(),
        "trojan-in",
        "handler 由插件按注入 tag 产出"
    );
}
