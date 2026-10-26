//! P2 批次 A 首族验收：L4 契约夹具（12 条全适用 + SOCKS-B1）+ 装配链
//! register → build → bring_up → shutdown（`is_clean()`）。
//!
//! （注册不进 xray-frame——xray-frame 禁依赖协议 crate，拍板 P2.1；同
//! blackhole P1-7 的做法，注册写在协议 crate 自己的装配链里。）

use std::sync::Arc;

use serde_json::json;
use xray_features::inbound::InboundHandler;
use xray_frame::{
    ClauseId, Plugin, PluginDep, PluginError,
    assembly::{Framework, FrameworkOptions},
    assert_plugin_contract,
};
use xray_proxy_socks::{AuthType, ServerConfig, SocksPlugin};

fn framework_options() -> FrameworkOptions {
    FrameworkOptions { registry_cap: 8, id_fingerprint: Some(1), shutdown_timeout: None }
}

/// 段形态：inbounds[] 按 protocol 路由（坑约束 7；socks 生产形态是入站，
/// 段路由的 inbounds[] 回落半边在此被真实覆盖）。
fn socks_section_config(settings: serde_json::Value) -> serde_json::Value {
    json!({ "inbounds": [
        { "protocol": "socks", "tag": "socks-in", "settings": settings }
    ] })
}

#[test]
fn contract_macro_holds_for_socks() {
    assert_plugin_contract!(SocksPlugin);
}

/// 契约面内容断言：12 条通用条款全适用（无 N/A）、SOCKS-B1 协议专属。
#[test]
fn contract_surface_declares_all_applicable_and_extra() {
    let plugin = SocksPlugin::default();
    let contract = plugin.contract();

    assert_eq!(plugin.name(), "socks");
    assert_eq!(plugin.version(), "0.1.0");
    let deps: &[PluginDep] = plugin.deps();
    assert!(deps.is_empty(), "socks 无依赖插件");

    assert_eq!(contract.clauses.len(), 12, "socks 12 条全适用（差异表 §2.2 第 5 行）");
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
        &[("SOCKS-B1", "SOCKS5 地址/端口长度字段必须显式边界检查，禁饱和截断")],
        "协议专属条款 SOCKS-B1"
    );
}

/// 完整装配链：段路由解析 → bring_up 三相 → 停机报告干净；
/// build 产物逐字段核对（auth/accounts/udp/userLevel）。
#[tokio::test]
async fn socks_assembles_bring_up_and_shuts_down_clean() {
    let plugin = Arc::new(SocksPlugin::default());
    let mut framework = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(socks_section_config(json!({
            "auth": "password",
            "accounts": [{ "user": "alice", "pass": "p1" }],
            "udp": true,
            "userLevel": 2
        })))
        .register(Arc::clone(&plugin) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect("build phase");
    assert!(!framework.is_running(), "build 成功但未 bring_up，不得误报运行态");

    framework.bring_up().expect("bring_up: init/start 三相");
    assert!(framework.is_running());

    let report = framework.shutdown().await;
    let stopped: Vec<&str> = report.per_component.iter().map(|o| o.name.as_str()).collect();
    assert_eq!(stopped, ["socks"], "stop 闭包必须按插件名注册进 ShutdownCoordinator");
    assert!(report.is_clean(), "健康链必须全 Stopped: {report:?}");

    let expected = ServerConfig {
        auth_type: AuthType::Password,
        accounts: [("alice".to_string(), "p1".to_string())].into_iter().collect(),
        udp_enabled: true,
        user_level: 2,
        ..ServerConfig::default()
    };
    assert_eq!(plugin.built_config().expect("built"), &expected);
}

/// 边界钉（bd wkemq Change-3）：空报告（无任何停机注册行）在旧判定 `is_clean()`
/// 下恒绿——条款 6 曾形同虚设的根因；按名断言必须对空报告判红。未 bring_up 的链
/// shutdown = 空报告（xray-frame assembly_e2e 用例②同源语义），借它构造空报告面。
/// 13 个 crate 的条款 6 断言为同一形态文本，本钉即覆盖该形态；断言不炸 = 本测试红。
#[tokio::test]
#[should_panic(expected = "stop 闭包必须按插件名注册进 ShutdownCoordinator")]
async fn clause6_name_assertion_rejects_empty_report() {
    let framework = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(socks_section_config(json!({
            "auth": "password",
            "accounts": [{ "user": "alice", "pass": "p1" }],
            "udp": true,
            "userLevel": 2
        })))
        .register(Arc::new(SocksPlugin::default()) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect("build phase");
    // 未 bring_up → 无停机注册 → shutdown = 空报告。
    let report = framework.shutdown().await;
    assert!(report.per_component.is_empty(), "未启动链无停机组件行");
    assert!(report.is_clean(), "空报告 is_clean 恒真——旧判定盲区语义锚");
    let stopped: Vec<&str> = report.per_component.iter().map(|o| o.name.as_str()).collect();
    assert_eq!(stopped, ["socks"], "stop 闭包必须按插件名注册进 ShutdownCoordinator");
}

/// L5 装配门负向：缺段 fail-fast（坑约束 7 装配半边），
/// build 失败 → 无 Framework 产出（无半启动态）。
#[tokio::test]
async fn missing_section_fails_fast_at_build() {
    let err = Framework::builder(framework_options())
        .expect("registry cap")
        .register(Arc::new(SocksPlugin::default()) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect_err("config 根无 socks 段必须 fail-fast");
    assert!(matches!(err, PluginError::Config(_)), "实际: {err}");
}

/// 入站 handler 由插件产出（tag 注入 + 认证配置从段注入；bind/handshake
/// 行为属既有 InboundHandler 实测——tests/e2e_proxy.rs）。
#[tokio::test]
async fn inbound_handler_produced_by_plugin() {
    let plugin = Arc::new(SocksPlugin::default());
    let framework = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(socks_section_config(json!({
            "auth": "password",
            "accounts": [{ "user": "u", "pass": "p" }]
        })))
        .register(Arc::clone(&plugin) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect("build");

    let inbound = plugin.inbound_handler("socks-in").expect("inbound handler");
    assert_eq!(inbound.tag(), "socks-in");
    assert!(plugin.built_config().expect("built").requires_auth(), "认证配置随插件注入");

    framework.shutdown().await;
}

// ── L4 行为夹具接线（P1-L4：每协议 crate 必调，缺=CI 红）──
// 按 contract() 声明面（src/plugin.rs SOCKS_CLAUSES，12 条全适用）：
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
    l4_run_conn_id_fixture("socks");
}

/// 夹具二（坑约束 2）：deadline 双入口（with_deadline / HandshakeDeadline::guard）
/// 期限内 Ok、永不完成 Err(Elapsed) 且真超时。d 钉 100ms 上限（CI 慢机安全）。
#[tokio::test]
async fn l4_deadline_effective() {
    xray_frame::assert_deadline_effective!(std::time::Duration::from_millis(100), || async {})
        .await;
}

/// 夹具三（坑约束 10/11）：target 前缀 `xray_frame::socks` + conn_id/stage/
/// peer/dest 四元组齐全 + secrets 掩码（条款 11 适用 → 表传真实形态凭据样例）。
#[test]
fn l4_log_fields() {
    xray_frame::assert_log_fields!(
        domain: "socks",
        conn_id: 0x1234u128,
        stage: "Accept",
        peer: "203.0.113.7:443",
        dest: "example.com:80",
        secrets: ["socks-credential-sample"],
    );
}

/// 夹具四（坑约束 4/9）：借 N 还 N → PoolMetrics 配平（borrowed=0 且零溢出丢弃）。
#[test]
fn l4_pool_discipline() {
    let pool =
        xray_frame::pool::ManagedBufferPool::new(xray_frame::pool::XrayBufPool::new(8, 8), 8, 8);
    xray_frame::assert_pool_discipline!(pool, 4);
}
