//! P2 批次 B 最高风险族验收：L4 契约夹具（12 条全适用 + VLESS-VISION /
//! VLESS-MUX）+ 装配链 register → build → bring_up → shutdown（`is_clean()`）
//! + 装配门负向（缺段 / decryption 缺省 / 非法 flow / vnext 多成员）。
//!
//! （注册不进 xray-frame——xray-frame 禁依赖协议 crate，拍板 P2.1；同
//! blackhole P1-7 / socks P2-A / vmess / trojan P2-B 做法，注册写在协议 crate
//! 自己的装配链里。）

use std::sync::Arc;

use serde_json::json;
use xray_frame::{
    ClauseId, Plugin, PluginDep, PluginError,
    assembly::{Framework, FrameworkOptions},
    assert_plugin_contract,
};
use xray_proxy_vless::{Validator, VlessPlugin};

fn framework_options() -> FrameworkOptions {
    FrameworkOptions { registry_cap: 8, id_fingerprint: Some(1), shutdown_timeout: None }
}

const UUID_A: &str = "66ad4540-b58c-4ad2-9926-ea63445a9b57";

/// 段形态：入站/出站各按 protocol 路由（坑约束 7）；vless 两侧配置面互斥
/// （入站 `clients`/`users` + `decryption`，出站 `vnext`/扁平 `address`）。
fn vless_inbound_config(settings: serde_json::Value) -> serde_json::Value {
    json!({ "inbounds": [
        { "protocol": "vless", "tag": "vless-in", "settings": settings }
    ] })
}

fn vless_outbound_config(settings: serde_json::Value) -> serde_json::Value {
    json!({ "outbounds": [
        { "protocol": "vless", "tag": "vless-out", "settings": settings }
    ] })
}

#[test]
fn contract_macro_holds_for_vless() {
    assert_plugin_contract!(VlessPlugin);
}

/// 契约面内容断言：12 条通用条款全适用（无 N/A）、VLESS-VISION + VLESS-MUX
/// 协议专属（原文照抄差异表 §2.2 第 1 行）。
#[test]
fn contract_surface_declares_all_applicable_and_extra() {
    let plugin = VlessPlugin::default();
    let contract = plugin.contract();

    assert_eq!(plugin.name(), "vless");
    assert_eq!(plugin.version(), "0.1.0");
    let deps: &[PluginDep] = plugin.deps();
    assert!(deps.is_empty(), "vless 无依赖插件");

    assert_eq!(contract.clauses.len(), 12, "vless 12 条全适用（差异表 §2.2 第 1 行）");
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
        &[
            ("VLESS-VISION", "vision splice gate 禁碰（d8562b56 + a427613b 双 revert 史实）"),
            (
                "VLESS-MUX",
                "mux carrier 判据=目的地域名 v1.mux.cool，不校验 VLESS command 字段与端口"
            ),
        ],
        "协议专属条款 VLESS-VISION + VLESS-MUX"
    );
}

/// 入站装配链：段路由解析 → bring_up 三相 → 停机报告干净；`clients` 灌入
/// 用户表 + fallback 数字 dest 推导（Go vless.go:177-179）+ 出站面在同实例
/// fail-visible。
#[tokio::test]
async fn vless_inbound_assembles_bring_up_and_shuts_down_clean() {
    let plugin = Arc::new(VlessPlugin::default());
    let mut framework = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(vless_inbound_config(json!({
            "clients": [{ "id": UUID_A, "email": "alice", "level": 0 }],
            "decryption": "none",
            "fallbacks": [{ "dest": 8080 }]
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

    assert_eq!(
        Validator::get_uuid_count(&**plugin.built_validator().expect("built")),
        1,
        "clients 灌入"
    );
    assert!(plugin.built_decryption().expect("built").is_none(), "decryption=none → 无 ENC 实例");
    let fallbacks = plugin.built_fallbacks().expect("built").as_ref().expect("有 fallback");
    let dest = fallbacks.find("", "", "").expect("default entry");
    assert_eq!(dest.dest, "localhost:8080", "数字 dest → localhost:N");
    assert_eq!(dest.xver, 0);
    assert!(plugin.built_outbound().is_err(), "入站段无出站配置");
    assert!(plugin.dial_fn().is_err(), "入站段不可产出拨号闭包");
}

/// 出站装配链：`vnext` → 出站配置 + 拨号闭包（wire 构造仍是既有
/// `make_dial_fn`，本测只验证接缝，不发起真实拨号）。
#[tokio::test]
async fn vless_outbound_assembles_bring_up_and_shuts_down_clean() {
    let plugin = Arc::new(VlessPlugin::default());
    let mut framework = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(vless_outbound_config(json!({
            "vnext": [{ "address": "example.com", "port": 443,
                        "users": [{ "id": UUID_A, "flow": "xtls-rprx-vision", "level": 1 }] }]
        })))
        .register(Arc::clone(&plugin) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect("build phase");
    framework.bring_up().expect("bring_up: init/start 三相");
    let report = framework.shutdown().await;
    assert!(report.is_clean(), "健康链停机报告必须干净");

    let outbound = plugin.built_outbound().expect("built");
    assert_eq!(outbound.server_port.value(), 443);
    assert_eq!(outbound.flow, "xtls-rprx-vision");
    assert_eq!(outbound.encryption, "none");
    assert_eq!(outbound.level, 1);
    assert!(plugin.built_validator().is_err(), "出站段无入站用户表");
    assert!(plugin.dial_fn().is_ok(), "出站段产出拨号闭包");
}

/// L5 装配门负向：缺段 fail-fast（坑约束 7 装配半边），
/// build 失败 → 无 Framework 产出（无半启动态）。
#[tokio::test]
async fn missing_section_fails_fast_at_build() {
    let err = Framework::builder(framework_options())
        .expect("registry cap")
        .register(Arc::new(VlessPlugin::default()) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect_err("config 根无 vless 段必须 fail-fast");
    assert!(matches!(err, PluginError::Config(_)), "实际: {err}");
}

/// L5 装配门负向：decryption 缺省拒启（Go vless.go:155-157；3hsv① 语义——
/// 禁 unwrap_or("none") 静默兜底）。
#[tokio::test]
async fn missing_decryption_fails_fast_at_build() {
    let err = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(vless_inbound_config(json!({ "clients": [{ "id": UUID_A }] })))
        .register(Arc::new(VlessPlugin::default()) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect_err("decryption 缺省必须 fail-fast");
    assert!(err.to_string().contains("please add/set"), "实际: {err}");
}

/// L5 装配门负向：非法 client flow 拒启（vision 静默降级根除，Go vless.go:71-78）。
#[tokio::test]
async fn invalid_client_flow_fails_fast_at_build() {
    let err = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(vless_inbound_config(json!({
            "clients": [{ "id": UUID_A, "flow": "xtls-rprx-direct" }],
            "decryption": "none"
        })))
        .register(Arc::new(VlessPlugin::default()) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect_err("非法 client flow 必须 fail-fast");
    assert!(err.to_string().contains("\"flow\" doesn't support"), "实际: {err}");
}

/// L5 装配门负向：vnext 多成员拒启（Go 同规：多端点须拆多出站 + balancer）。
#[tokio::test]
async fn multi_vnext_fails_fast_at_build() {
    let err = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(vless_outbound_config(json!({
            "vnext": [
                { "address": "a.com", "port": 443, "users": [{ "id": UUID_A }] },
                { "address": "b.com", "port": 443, "users": [{ "id": UUID_A }] }
            ]
        })))
        .register(Arc::new(VlessPlugin::default()) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect_err("vnext 多成员必须 fail-fast");
    assert!(err.to_string().contains("one and only one"), "实际: {err}");
}

/// build 前调用观察面 → `Err`（fail-visible，不 panic）。
#[test]
fn observface_before_build_fails_visible() {
    let plugin = VlessPlugin::default();
    assert!(plugin.built_validator().is_err());
    assert!(plugin.built_decryption().is_err());
    assert!(plugin.built_fallbacks().is_err());
    assert!(plugin.built_outbound().is_err());
    assert!(plugin.dial_fn().is_err());
}
