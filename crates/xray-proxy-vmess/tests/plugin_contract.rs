//! P2 批次 B 验收：L4 契约夹具（12 条全适用 + VMESS-U16）+ 装配链
//! register → build → bring_up → shutdown（`is_clean()`）。
//!
//! （注册不进 xray-frame——xray-frame 禁依赖协议 crate，拍板 P2.1；同
//! blackhole P1-7 / socks P2-A / trojan 的做法，注册写在协议 crate 自己的装配链里。）

use std::sync::Arc;

use serde_json::json;
use xray_frame::{
    ClauseId, Plugin, PluginDep, PluginError,
    assembly::{Framework, FrameworkOptions},
    assert_plugin_contract,
};
use xray_proxy_vmess::{Validator, VmessPlugin};

fn framework_options() -> FrameworkOptions {
    FrameworkOptions { registry_cap: 8, id_fingerprint: Some(1), shutdown_timeout: None }
}

const UUID_A: &str = "66ad4540-b58c-4ad2-9926-ea63445a9b57";

/// 段形态：入站/出站各按 protocol 路由（坑约束 7）；vmess 两侧配置面互斥
/// （入站 `clients`/`users`，出站 `vnext`/扁平 `address`）。
fn vmess_inbound_config(settings: serde_json::Value) -> serde_json::Value {
    json!({ "inbounds": [
        { "protocol": "vmess", "tag": "vmess-in", "settings": settings }
    ] })
}

fn vmess_outbound_config(settings: serde_json::Value) -> serde_json::Value {
    json!({ "outbounds": [
        { "protocol": "vmess", "tag": "vmess-out", "settings": settings }
    ] })
}

#[test]
fn contract_macro_holds_for_vmess() {
    assert_plugin_contract!(VmessPlugin);
}

/// 契约面内容断言：12 条通用条款全适用（无 N/A）、VMESS-U16 协议专属。
#[test]
fn contract_surface_declares_all_applicable_and_extra() {
    let plugin = VmessPlugin::default();
    let contract = plugin.contract();

    assert_eq!(plugin.name(), "vmess");
    assert_eq!(plugin.version(), "0.1.0");
    let deps: &[PluginDep] = plugin.deps();
    assert!(deps.is_empty(), "vmess 无依赖插件");

    assert_eq!(contract.clauses.len(), 12, "vmess 12 条全适用（差异表 §2.2 第 2 行）");
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
        &[("VMESS-U16", "VMess chunk size u16 截断必须显式报错，禁静默替换 u16::MAX")],
        "协议专属条款 VMESS-U16"
    );
}

/// 入站装配链：段路由解析 → bring_up 三相 → 停机报告干净；
/// `clients` 灌入用户表（出站面在同实例上必须 fail-visible）。
#[tokio::test]
async fn vmess_inbound_assembles_bring_up_and_shuts_down_clean() {
    let plugin = Arc::new(VmessPlugin::default());
    let mut framework = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(vmess_inbound_config(json!({
            "clients": [{ "id": UUID_A, "email": "alice", "level": 0 }]
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
    assert_eq!(stopped, ["vmess"], "stop 闭包必须按插件名注册进 ShutdownCoordinator");
    assert!(report.is_clean(), "健康链必须全 Stopped: {report:?}");

    assert_eq!(Validator::count(&**plugin.built_validator().expect("built")), 1, "clients 灌入");
    assert!(plugin.built_outbound().is_err(), "入站段无出站配置");
    assert!(plugin.dial_fn().is_err(), "入站段不可产出拨号闭包");
}

/// 出站装配链：`vnext` → 出站配置 + 拨号闭包（wire 构造仍是既有
/// `make_vmess_dial_fn`，本测只验证接缝，不发起真实拨号）。
#[tokio::test]
async fn vmess_outbound_assembles_bring_up_and_shuts_down_clean() {
    let plugin = Arc::new(VmessPlugin::default());
    let mut framework = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(vmess_outbound_config(json!({
            "vnext": [{ "address": "example.com", "port": 443,
                        "users": [{ "id": UUID_A, "security": "aes-128-gcm", "level": 1 }] }]
        })))
        .register(Arc::clone(&plugin) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect("build phase");
    framework.bring_up().expect("bring_up: init/start 三相");
    let report = framework.shutdown().await;
    let stopped: Vec<&str> = report.per_component.iter().map(|o| o.name.as_str()).collect();
    assert_eq!(stopped, ["vmess"], "stop 闭包必须按插件名注册进 ShutdownCoordinator");
    assert!(report.is_clean(), "健康链必须全 Stopped: {report:?}");

    let outbound = plugin.built_outbound().expect("built");
    assert_eq!(outbound.server_port.value(), 443);
    assert_eq!(outbound.level, 1);
    assert_eq!(outbound.email, "");
    assert!(plugin.built_validator().is_err(), "出站段无入站用户表");
    assert!(plugin.dial_fn().is_ok(), "出站段产出拨号闭包");
}

/// L5 装配门负向：缺段 fail-fast（坑约束 7 装配半边），
/// build 失败 → 无 Framework 产出（无半启动态）。
#[tokio::test]
async fn missing_section_fails_fast_at_build() {
    let err = Framework::builder(framework_options())
        .expect("registry cap")
        .register(Arc::new(VmessPlugin::default()) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect_err("config 根无 vmess 段必须 fail-fast");
    assert!(matches!(err, PluginError::Config(_)), "实际: {err}");
}

/// L5 装配门负向：legacy `alterId`≠0 → build `Err`（同规生产
/// `build_vmess_validator` 硬错，拒启不静默忽略）。
#[tokio::test]
async fn legacy_alter_id_fails_fast_at_build() {
    let err = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(vmess_inbound_config(json!({
            "clients": [{ "id": UUID_A, "alterId": 64 }]
        })))
        .register(Arc::new(VmessPlugin::default()) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect_err("alterId=64 必须 fail-fast");
    assert!(err.to_string().contains("not supported"), "实际: {err}");
}

/// L5 装配门负向：vnext 多成员 → build `Err`（Go 同规：多端点须拆多出站 + balancer）。
#[tokio::test]
async fn multi_vnext_fails_fast_at_build() {
    let err = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(vmess_outbound_config(json!({
            "vnext": [
                { "address": "a.com", "port": 443, "users": [{ "id": UUID_A }] },
                { "address": "b.com", "port": 443, "users": [{ "id": UUID_A }] }
            ]
        })))
        .register(Arc::new(VmessPlugin::default()) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect_err("vnext 多成员必须 fail-fast");
    assert!(err.to_string().contains("one and only one"), "实际: {err}");
}

/// build 前调用观察面 → `Err`（fail-visible，不 panic）。
#[test]
fn observface_before_build_fails_visible() {
    let plugin = VmessPlugin::default();
    assert!(plugin.built_validator().is_err());
    assert!(plugin.built_outbound().is_err());
    assert!(plugin.dial_fn().is_err());
}

// ── L4 行为夹具（P1-L4：声明面之外的「跑起来验证」；对照 contract() 声明
// ——vmess 12 条全适用 → 四夹具全接）──

/// 夹具一 conn_id（坑约束 3 / ConnIdPresent）：宏形取单枚验非零；唯一/单调
/// 面用逐 id 跨毫秒 drip——协议 crate 不直依赖 skeleton，无法注入固定指纹，
/// `contract_test_context` 随机指纹下宏形 n 连取有 (n−1)/4096 同毫秒配额
/// fail-closed flake（std_ext::id：每毫秒配额 = 4096 − 基址，基址随机）；
/// 逐毫秒领取配额下界恒 1 = 零 flake（挂钟回拨走停走 armor，保序不变）。
#[test]
fn l4_behavior_conn_id_present_unique_monotonic() {
    let ctx = xray_frame::contract_assert::contract_test_context("vmess");
    xray_frame::assert_conn_id_present!(ctx, 1);
    let ids: Vec<u128> = (0..8)
        .map(|_| {
            std::thread::sleep(std::time::Duration::from_millis(1));
            ctx.next_conn_id()
        })
        .collect();
    xray_frame::contract_assert::assert_conn_id_sequence("vmess", ids);
}

/// 夹具二 deadline（坑约束 2 / HandshakeDeadline）：双入口期限内 Ok +
/// pending 任务掐断 Err(Elapsed) 真超时（d = 100ms 派单上限）。
#[tokio::test]
async fn l4_behavior_deadline_effective() {
    xray_frame::assert_deadline_effective!(std::time::Duration::from_millis(100), || async {
        tokio::task::yield_now().await;
    })
    .await;
}

/// 夹具三 日志字段（坑约束 3/10/11 / LogDiscipline + SecretMasking）：log 域
/// 约定 = 插件名 → target = xray_frame::vmess，四元组齐全 + secrets 掩码。
#[test]
fn l4_behavior_log_fields_quadruple_masked() {
    xray_frame::assert_log_fields!(
        domain: "vmess",
        conn_id: 0x1234u128,
        stage: "Handshake",
        peer: "203.0.113.7:443",
        dest: "example.com:80",
        secrets: ["vmess-uuid-redacted"]
    );
}

/// 夹具四 池纪律（坑约束 4/9 / PoolDiscipline）：借 4 还 4 终态配平
/// （borrowed = 0 且零溢出丢弃）。
#[test]
fn l4_behavior_pool_discipline_balances() {
    let pool =
        xray_frame::pool::ManagedBufferPool::new(xray_frame::pool::XrayBufPool::new(8, 8), 8, 8);
    xray_frame::assert_pool_discipline!(pool, 4);
}
