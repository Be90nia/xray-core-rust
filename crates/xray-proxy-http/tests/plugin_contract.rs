//! P2 批次 B 验收：L4 契约夹具（通用 8 条适用 + 3 条 N/A + HTTP-H2W 协议专属）
//! + 装配链 register → build → bring_up → shutdown（`is_clean()`）。
//!
//! （注册不进 xray-frame——xray-frame 禁依赖协议 crate，拍板 P2.1；同
//! blackhole P1-7 / socks P2-A 的做法，注册写在协议 crate 自己的装配链里。）

use std::sync::Arc;

use serde_json::json;
use xray_features::inbound::InboundHandler;
use xray_frame::{
    ClauseId, Plugin, PluginDep, PluginError,
    assembly::{Framework, FrameworkOptions},
    assert_plugin_contract,
};
use xray_proxy_http::{HttpPlugin, ServerConfig};

fn framework_options() -> FrameworkOptions {
    FrameworkOptions { registry_cap: 8, id_fingerprint: Some(1), shutdown_timeout: None }
}

/// 段形态：inbounds[] 按 protocol 路由（坑约束 7；http 生产形态是入站，
/// 段路由的 inbounds[] 半边在此被真实覆盖）。
fn http_section_config(settings: serde_json::Value) -> serde_json::Value {
    json!({ "inbounds": [
        { "protocol": "http", "tag": "http-in", "settings": settings }
    ] })
}

#[test]
fn contract_macro_holds_for_http() {
    assert_plugin_contract!(HttpPlugin);
}

/// 契约面内容断言：差异表 §2.2 第 6 行——9 条适用（3/5/6/7/8/9/10/12 + 条款 1
/// 按 PM 拍板归 clauses）、2/4/11 走 N/A（理由非空）、HTTP-H2W 协议专属
/// （bd rjzw2：h2 窗 ≥ RTT 阶梯下限 8MB + Linux 服务端 TCP_NOTSENT_LOWAT）。
#[test]
fn contract_surface_declares_subset_na_and_extra() {
    let plugin = HttpPlugin::default();
    let contract = plugin.contract();

    assert_eq!(plugin.name(), "http");
    assert_eq!(plugin.version(), "0.1.0");
    let deps: &[PluginDep] = plugin.deps();
    assert!(deps.is_empty(), "http 无依赖插件");

    let expected: &[ClauseId] = &[
        ClauseId::AuthErrorClassified,
        ClauseId::ConnIdPresent,
        ClauseId::SpawnManaged,
        ClauseId::StopRegistered,
        ClauseId::ConfigSectionOnly,
        ClauseId::ErrorClassifiedNoPanicEscape,
        ClauseId::BoundedResources,
        ClauseId::LogDiscipline,
        ClauseId::HotPathFreeze,
    ];
    assert_eq!(
        contract.clauses.len(),
        expected.len(),
        "http 适用 9 条（差异表 §2.2 第 6 行 + 条款 1 PM 拍板）"
    );
    for clause in expected {
        assert!(contract.clauses.contains(clause), "缺条款 {clause:?}");
    }

    let na: &[ClauseId] =
        &[ClauseId::HandshakeDeadline, ClauseId::PoolDiscipline, ClauseId::SecretMasking];
    assert_eq!(contract.not_applicable.len(), na.len(), "http 声明 3 条 N/A");
    for clause in na {
        let reason = contract
            .not_applicable
            .iter()
            .find(|(id, _)| id == clause)
            .map(|(_, reason)| *reason)
            .unwrap_or_else(|| panic!("缺 N/A 声明 {clause:?}"));
        assert!(!reason.trim().is_empty(), "N/A {clause:?} 理由不得为空");
        assert!(!contract.clauses.contains(clause), "{clause:?} 不得同时出现在 clauses");
    }

    assert_eq!(
        contract.extra,
        &[(
            "HTTP-H2W",
            "h2 流窗/服务端 send_buf 不得低于 RTT 阶梯下限 8MB，且 Linux 服务端必须设 \
             TCP_NOTSENT_LOWAT 削峰（bd rjzw2；静态保底 32MB/16MB 为阶梯最高档）"
        )],
        "协议专属条款 HTTP-H2W"
    );
}

/// 完整装配链：段路由解析 → bring_up 三相 → 停机报告干净；
/// build 产物逐字段核对（users/allowTransparent/userLevel）。
#[tokio::test]
async fn http_assembles_bring_up_and_shuts_down_clean() {
    let plugin = Arc::new(HttpPlugin::default());
    let mut framework = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(http_section_config(json!({
            "users": [{ "user": "alice", "pass": "p1" }],
            "allowTransparent": true,
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
    assert_eq!(stopped, ["http"], "stop 闭包必须按插件名注册进 ShutdownCoordinator");
    assert!(report.is_clean(), "健康链必须全 Stopped: {report:?}");

    let expected = ServerConfig {
        accounts: [("alice".to_string(), "p1".to_string())].into_iter().collect(),
        allow_transparent: true,
        user_level: 2,
    };
    assert_eq!(plugin.built_config().expect("built"), &expected);
}

/// L5 装配门负向：缺段 fail-fast（坑约束 7 装配半边），
/// build 失败 → 无 Framework 产出（无半启动态）。
#[tokio::test]
async fn missing_section_fails_fast_at_build() {
    let err = Framework::builder(framework_options())
        .expect("registry cap")
        .register(Arc::new(HttpPlugin::default()) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect_err("config 根无 http 段必须 fail-fast");
    assert!(matches!(err, PluginError::Config(_)), "实际: {err}");
}

/// 入站 handler 由插件产出（tag 注入 + 认证配置从段注入；bind/handshake
/// 行为属既有 InboundHandler 实测——tests/http_proxy_e2e.rs）。
#[tokio::test]
async fn inbound_handler_produced_by_plugin() {
    let plugin = Arc::new(HttpPlugin::default());
    let framework = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(http_section_config(json!({
            "users": [{ "user": "u", "pass": "p" }]
        })))
        .register(Arc::clone(&plugin) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect("build");

    let inbound = plugin.inbound_handler("http-in").expect("inbound handler");
    assert_eq!(inbound.tag(), "http-in");
    assert!(plugin.built_config().expect("built").requires_auth(), "认证配置随插件注入");

    framework.shutdown().await;
}

// ── L4 行为夹具接线（P1-L4：每协议 crate 必调，缺=CI 红）──
// 按 contract() 声明面（src/plugin.rs HTTP_CLAUSES / HTTP_NOT_APPLICABLE）：
// 跑 conn_id(3) / log(10)；跳过 deadline(2)——HTTP 无协议握手（首包即请求头，
// 读头 deadline 由 serve 路径既有 REQUEST_HEADER_TIMEOUT 承担，不经
// ctx.with_deadline，本条款无落点）；跳过 pool(4)——hyper/h2 内部缓冲不由本仓
// 管，全路径无缓冲池消费点；log(11) N/A → secrets 表传空（仍断 target/四元组）。

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
    l4_run_conn_id_fixture("http");
}

/// 夹具三（坑约束 10；11 N/A → secrets 表传空）：target 前缀 `xray_frame::http`
/// + conn_id/stage/peer/dest 四元组齐全。无密钥材料面，无掩码断言项。
#[test]
fn l4_log_fields() {
    xray_frame::assert_log_fields!(
        domain: "http",
        conn_id: 0x1234u128,
        stage: "Accept",
        peer: "203.0.113.7:443",
        dest: "example.com:80",
    );
}
