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

// ── L4 行为夹具（P1-L4：声明面之外的「跑起来验证」；对照 contract() 声明
// ——vless 12 条全适用 → 四夹具全接）──

/// 夹具一 conn_id（坑约束 3 / ConnIdPresent）：宏形取单枚验非零；唯一/单调
/// 面用逐 id 跨毫秒 drip——协议 crate 不直依赖 skeleton，无法注入固定指纹，
/// `contract_test_context` 随机指纹下宏形 n 连取有 (n−1)/4096 同毫秒配额
/// fail-closed flake（std_ext::id：每毫秒配额 = 4096 − 基址，基址随机）；
/// 逐毫秒领取配额下界恒 1 = 零 flake（挂钟回拨走停走 armor，保序不变）。
#[test]
fn l4_behavior_conn_id_present_unique_monotonic() {
    let ctx = xray_frame::contract_assert::contract_test_context("vless");
    xray_frame::assert_conn_id_present!(ctx, 1);
    let ids: Vec<u128> = (0..8)
        .map(|_| {
            std::thread::sleep(std::time::Duration::from_millis(1));
            ctx.next_conn_id()
        })
        .collect();
    xray_frame::contract_assert::assert_conn_id_sequence("vless", ids);
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
/// 约定 = 插件名 → target = xray_frame::vless，四元组齐全 + secrets 掩码。
#[test]
fn l4_behavior_log_fields_quadruple_masked() {
    xray_frame::assert_log_fields!(
        domain: "vless",
        conn_id: 0x1234u128,
        stage: "Handshake",
        peer: "203.0.113.7:443",
        dest: "example.com:80",
        secrets: ["vless-uuid-redacted"]
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

// ── L4 真实实例夹具（bd 2zi1o）──
// 上面四条 l4_*（含兄弟 crate 的同族 56 条）验的是**框架原语**：ctx/池由夹具自造、
// work 闭包为空，插件类型从未出场。本条把契约断言接到真实 `VlessPlugin` 实例上，
// 并补上既有装配链测试判不出的面——`report.is_clean()` 对**空报告**也返回 true
// （零组件无可失败），所以「stop 从未注册」同样能绿；只有按插件名逐条核对报告
// 条目才算条款 6 StopRegistered 的执行面。

/// 真实实例契约夹具：声明面取实例值 → lifecycle 三相经 bring_up 真实编排 →
/// stop 闭包按插件名注册进 ShutdownCoordinator → build 产物行为可用。
///
/// 证伪面（实测）：lifecycle 断（start/stop 返 Err）→ bring_up/report 红；build
/// 空壳化 → `built_validator()` 返 Err → 红；name 改名 → 报告条目名不匹配红。
#[tokio::test]
async fn l4_real_instance_contract_lifecycle_and_stop_registered() {
    let plugin = Arc::new(VlessPlugin::default());

    // ① 声明面：实例真实值（deps/contract 都有默认或静态面，单测默认实现判不出接线）。
    assert_eq!(plugin.name(), "vless", "插件名 = 段路由 key（坑约束 7）");
    assert_eq!(plugin.version(), env!("CARGO_PKG_VERSION"), "version 随 crate 版本");
    assert!(plugin.deps().is_empty(), "vless 不依赖其他插件");
    assert_eq!(plugin.contract().clauses.len(), 12, "12 条通用条款全适用");

    // ② lifecycle：init→start 由 bring_up 按真实 lifecycle 对象编排，stop 由
    //    coordinator 执行（插件级三相直通，连接级 pump 属实例面，见 src/plugin.rs）。
    let mut framework = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(vless_inbound_config(json!({
            "clients": [{ "id": UUID_A, "email": "alice", "level": 0 }],
            "decryption": "none"
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
    assert_eq!(stopped, ["vless"], "stop 闭包必须按插件名注册进 ShutdownCoordinator");
    assert!(report.is_clean(), "健康链必须全 Stopped: {report:?}");

    // ④ 行为：段 → build 产物来自真实实例（空壳插件 build 空转 → 下面全 Err）。
    let validator = plugin.built_validator().expect("build 产出用户表");
    assert!(validator.get_by_email("alice").is_some(), "段内 client 进 UUID 索引");
    assert!(validator.get_by_email("mallory").is_none(), "未配置用户不得通过查找");
    assert_eq!(validator.get_uuid_count(), 1, "UUID 索引计数同 build 输入");
    assert!(plugin.built_decryption().expect("built").is_none(), "decryption=none → 无 ENC");
}
