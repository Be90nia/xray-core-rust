//! P2 批次 D 验收：L4 契约夹具（12 条全适用 + TUIC-FRAG-U16 / TUIC-OWNPOOL
//! 协议专属条款）+ 装配链 register → build → bring_up → shutdown（`is_clean()`）。
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
use xray_proxy_tuic::{CongestionControl, TuicPlugin};

fn framework_options() -> FrameworkOptions {
    FrameworkOptions { registry_cap: 8, id_fingerprint: Some(1), shutdown_timeout: None }
}

/// 段形态：inbounds[] 按 protocol 路由（坑约束 7；tuic 生产形态是入站，
/// 段级 listen/port 随元素进 build 期拼装 bind_addr）。
fn tuic_section_config(settings: serde_json::Value) -> serde_json::Value {
    json!({ "inbounds": [
        {
            "protocol": "tuic",
            "tag": "tuic-in",
            "listen": "127.0.0.1",
            "port": 18443,
            "settings": settings
        }
    ] })
}

#[test]
fn contract_macro_holds_for_tuic() {
    assert_plugin_contract!(TuicPlugin);
}

/// 契约面内容断言：12 条通用条款全适用（无 N/A）、TUIC-FRAG-U16 /
/// TUIC-OWNPOOL 两条协议专属（任务书 §2.2 差异表第 13 行）。
#[test]
fn contract_surface_declares_all_applicable_and_extra() {
    let plugin = TuicPlugin::default();
    let contract = plugin.contract();

    assert_eq!(plugin.name(), "tuic");
    assert_eq!(plugin.version(), "0.1.0");
    let deps: &[PluginDep] = plugin.deps();
    assert!(deps.is_empty(), "tuic 无依赖插件");

    assert_eq!(contract.clauses.len(), 12, "tuic 12 条全适用");
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

    assert_eq!(contract.extra.len(), 2, "协议专属条款两条");
    assert_eq!(contract.extra[0].0, "TUIC-FRAG-U16");
    assert_eq!(contract.extra[1].0, "TUIC-OWNPOOL");
    assert!(!contract.extra[0].1.is_empty() && !contract.extra[1].1.is_empty());
}

/// 完整装配链：段路由解析 → bring_up 三相 → 停机报告干净；
/// build 产物逐字段核对（uuid/password/serverName/CC/brutal/证书缺省自签）。
#[tokio::test]
async fn tuic_assembles_bring_up_and_shuts_down_clean() {
    let plugin = Arc::new(TuicPlugin::default());
    let mut framework = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(tuic_section_config(json!({
            "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
            "password": "pw1",
            "serverName": "relay.example.com",
            "congestion_control": "hysteria_brutal",
            "brutal_up_bps": 10485760
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
    assert_eq!(stopped, ["tuic"], "stop 闭包必须按插件名注册进 ShutdownCoordinator");
    assert!(report.is_clean(), "健康链必须全 Stopped: {report:?}");

    let cfg = plugin.built_config().expect("built");
    assert_eq!(cfg.listen, "127.0.0.1:18443".parse().unwrap(), "listen = 段级 listen+port 拼装");
    assert_eq!(cfg.server_name, "relay.example.com");
    assert_eq!(cfg.uuid.to_string(), "b831381d-6324-4d53-ad4f-8cda48b30811");
    assert_eq!(cfg.password, "pw1");
    assert_eq!(cfg.congestion_control, Some(CongestionControl::HysteriaBrutal));
    assert_eq!(cfg.brutal_up_bps, 10485760);
    assert!(cfg.cert_der.is_none() && cfg.key_der.is_none(), "缺省 rcgen 自签（start 期）");
}

/// L5 装配门负向：缺段 fail-fast（坑约束 7 装配半边），
/// build 失败 → 无 Framework 产出（无半启动态）。
#[tokio::test]
async fn missing_section_fails_fast_at_build() {
    let err = Framework::builder(framework_options())
        .expect("registry cap")
        .register(Arc::new(TuicPlugin::default()) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect_err("config 根无 tuic 段必须 fail-fast");
    assert!(matches!(err, PluginError::Config(_)), "实际: {err}");
}

/// 入站 handler 由插件产出（tag 注入 + 配置从段注入；QUIC accept/relay 行为属
/// 既有 InboundHandler 实测——tests/loopback.rs / inbound_dispatch.rs /
/// udp_loopback.rs）。
#[tokio::test]
async fn inbound_handler_produced_by_plugin() {
    let plugin = Arc::new(TuicPlugin::default());
    let framework = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(tuic_section_config(json!({
            "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
            "password": "pw"
        })))
        .register(Arc::clone(&plugin) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect("build");

    let handler = plugin.inbound_handler("tuic-in").expect("inbound handler");
    assert!(handler.cert_der().is_none(), "start 前无证书 DER（自签在 start 期生成）");
    let cfg = plugin.built_config().expect("built");
    assert_eq!(cfg.server_name, "tuic", "serverName 缺省值对齐官方 tuic-server");
    assert_eq!(cfg.congestion_control, Some(CongestionControl::Cubic), "缺省 cubic");

    framework.shutdown().await;
}

// ── L4 行为夹具（P1-L4：声明面之外的「跑起来验证」；对照 contract() 声明
// ——tuic 12 条全适用 → 四夹具全接）──

/// 夹具一 conn_id（坑约束 3 / ConnIdPresent）：宏形取单枚验非零；唯一/单调
/// 面用逐 id 跨毫秒 drip——协议 crate 不直依赖 skeleton，无法注入固定指纹，
/// `contract_test_context` 随机指纹下宏形 n 连取有 (n−1)/4096 同毫秒配额
/// fail-closed flake（std_ext::id：每毫秒配额 = 4096 − 基址，基址随机）；
/// 逐毫秒领取配额下界恒 1 = 零 flake（挂钟回拨走停走 armor，保序不变）。
#[test]
fn l4_behavior_conn_id_present_unique_monotonic() {
    let ctx = xray_frame::contract_assert::contract_test_context("tuic");
    xray_frame::assert_conn_id_present!(ctx, 1);
    let ids: Vec<u128> = (0..8)
        .map(|_| {
            std::thread::sleep(std::time::Duration::from_millis(1));
            ctx.next_conn_id()
        })
        .collect();
    xray_frame::contract_assert::assert_conn_id_sequence("tuic", ids);
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
/// 约定 = 插件名 → target = xray_frame::tuic，四元组齐全 + secrets 掩码。
#[test]
fn l4_behavior_log_fields_quadruple_masked() {
    xray_frame::assert_log_fields!(
        domain: "tuic",
        conn_id: 0x1234u128,
        stage: "Handshake",
        peer: "203.0.113.7:443",
        dest: "example.com:80",
        secrets: ["tuic-password-redacted"]
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
