//! P2 最后一族验收：L4 契约夹具（10 条适用 + 2 N/A + TUN-OS-FROZEN 协议专属）+
//! 装配链 register → build → bring_up → shutdown（`is_clean()`）+ 装配门负向
//! （缺段 fail-fast / MTU 越界 fail-visible）+ handler 工厂产出。
//!
//! （注册不进 xray-frame——xray-frame 禁依赖协议 crate，拍板 P2.1；注册写在
//! 协议 crate 自己的装配链里，同 wireguard / dns P2 做法。）

use std::{sync::Arc, time::Duration};

use serde_json::json;
use xray_app_dispatcher::{DispatchHandler, default::PinFuture};
use xray_common::net::destination::Destination;
use xray_features::inbound::InboundHandler;
use xray_frame::{
    ClauseId, Plugin, PluginDep, PluginError,
    assembly::{Framework, FrameworkOptions},
    assert_plugin_contract,
};
use xray_proxy_tun::{StackOptions, TunPlugin};
use xray_transport::link::Link;

fn framework_options() -> FrameworkOptions {
    FrameworkOptions { registry_cap: 8, id_fingerprint: Some(1), shutdown_timeout: None }
}

/// 段形态：inbounds[] 按 protocol 路由（坑约束 7；tun 生产主形态是入站，
/// 入站/出站同 kind——core `register.rs` TUN_KINDS 同款全 kind 注册）。
fn tun_section_config(settings: serde_json::Value) -> serde_json::Value {
    json!({ "inbounds": [
        { "protocol": "tun", "tag": "tun-in", "settings": settings }
    ] })
}

#[test]
fn contract_macro_holds_for_tun() {
    assert_plugin_contract!(TunPlugin);
}

/// 契约面内容断言：差异表 §2.2 第 15 行——10 条适用（3,4,5,6,7,8,9,10,12 +
/// 条款 2 落定适用：smoltcp 握手内聚同 WG 判例）、1/11 N/A（理由非空，同
/// dns 先例）、TUN-OS-FROZEN 协议专属（派单契约原文逐字）。
#[test]
fn contract_surface_declares_subset_na_and_extra() {
    let plugin = TunPlugin::default();
    let contract = plugin.contract();

    assert_eq!(plugin.name(), "tun");
    assert_eq!(plugin.version(), "0.1.0");
    let deps: &[PluginDep] = plugin.deps();
    assert!(deps.is_empty(), "tun 无依赖插件");

    let expected: &[ClauseId] = &[
        ClauseId::HandshakeDeadline,
        ClauseId::ConnIdPresent,
        ClauseId::PoolDiscipline,
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
        "tun 适用 10 条（差异表 §2.2 第 15 行 + 条款 2 落定适用）"
    );
    for clause in expected {
        assert!(contract.clauses.contains(clause), "缺条款 {clause:?}");
    }

    let na: &[ClauseId] = &[ClauseId::AuthErrorClassified, ClauseId::SecretMasking];
    assert_eq!(contract.not_applicable.len(), na.len(), "tun 声明 2 条 N/A");
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
            "TUN-OS-FROZEN",
            "TUN 设备创建/MTU 校验（config.rs:173-176 mtu>65535 报错）属 OS 面，禁在插件层重实现；平台门控语义不变",
        )],
        "协议专属条款 TUN-OS-FROZEN"
    );
}

/// 完整装配链：段路由解析 → bring_up 三相 → 停机报告干净；
/// build 产物逐字段核对（缺省归一 name=xray0/mtu=1500 = config.rs parse_json
/// 默认路径；占位设备注入）。
#[tokio::test]
async fn tun_assembles_bring_up_and_shuts_down_clean() {
    let plugin = Arc::new(TunPlugin::default());
    let mut framework = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(tun_section_config(json!({
            "name": "tun0",
            "gateway": ["10.0.0.1/24", "fd00::1/64"],
            "dns": ["1.1.1.1"],
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
    assert!(report.is_clean(), "健康链停机报告必须干净");

    let opts: &StackOptions = plugin.built_config().expect("built");
    assert_eq!(opts.name, "tun0");
    assert_eq!(opts.mtu, 1500, "MTU 缺省 → 1500（Go infra/conf/tun.go:37-39）");
    assert_eq!(opts.desc, "Wintun");
    assert_eq!(opts.gateway, vec!["10.0.0.1/24".to_string(), "fd00::1/64".to_string()]);
    assert_eq!(opts.dns, vec!["1.1.1.1".to_string()]);
    assert_eq!(opts.user_level, 2);
    assert_eq!(opts.idle_timeout, Duration::from_secs(30));
    assert!(opts.tun.is_some(), "占位设备已注入（core TunPlaceholder 同构）");
}

/// L5 装配门负向①：缺段 fail-fast（坑约束 7 装配半边），
/// build 失败 → 无 Framework 产出（无半启动态）。
#[tokio::test]
async fn missing_section_fails_fast_at_build() {
    let err = Framework::builder(framework_options())
        .expect("registry cap")
        .register(Arc::new(TunPlugin::default()) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect_err("config 根无 tun 段必须 fail-fast");
    assert!(matches!(err, PluginError::Config(_)), "实际: {err}");
}

/// L5 装配门负向②：MTU > 65535 → build `Err` fail-visible——冻结校验
/// （config.rs:173-176）经插件解析面原样复用，零重实现（TUN-OS-FROZEN 实证）。
#[tokio::test]
async fn mtu_overflow_fails_fast_at_build() {
    let err = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(tun_section_config(json!({ "mtu": 70000 })))
        .register(Arc::new(TunPlugin::default()) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect_err("mtu > 65535 必须 fail-visible（禁饱和截断）");
    assert!(err.to_string().contains("65535"), "实际: {err}");
}

/// 入站 handler 由插件产出（构建接缝 = 既有 `TunInboundHandler::new`，core
/// inbound.rs:3856 同构；构造仅参数校验，设备创建仍走 start()——本测试不调
/// start()，无 OS 设备副作用，Windows 语义安全）。
#[tokio::test]
async fn inbound_handler_produced_by_plugin() {
    let plugin = Arc::new(TunPlugin::default());
    let framework = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(tun_section_config(json!({ "name": "tun0" })))
        .register(Arc::clone(&plugin) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect("build");

    let handler =
        plugin.inbound_handler("tun-in", Arc::new(NoopDispatch)).await.expect("handler 构建接缝");
    assert_eq!(InboundHandler::tag(&handler), "tun-in");

    framework.shutdown().await;
}

#[derive(Debug)]
struct NoopDispatch;

impl DispatchHandler for NoopDispatch {
    fn tag(&self) -> &str {
        "noop"
    }

    fn dispatch(&self, _dest: &Destination, _link: Link) -> PinFuture<()> {
        Box::pin(async {})
    }
}

// ── L4 行为夹具（P1-L4：声明面之外的「跑起来验证」；对照 contract() 声明
// ——tun 10 条适用（条款 2 落定适用 → deadline 夹具接）；条款 11 N/A → log
// 夹具不带 secrets 表。四夹具全部只验证框架缝（ctx/LogFacade/池/deadline
// 语义件），零插件实例化、零 start()、零 OS 设备触碰（派单红线）──

/// 夹具一 conn_id（坑约束 3 / ConnIdPresent）：宏形取单枚验非零；唯一/单调
/// 面用逐 id 跨毫秒 drip——协议 crate 不直依赖 skeleton，无法注入固定指纹，
/// `contract_test_context` 随机指纹下宏形 n 连取有 (n−1)/4096 同毫秒配额
/// fail-closed flake（std_ext::id：每毫秒配额 = 4096 − 基址，基址随机）；
/// 逐毫秒领取配额下界恒 1 = 零 flake（挂钟回拨走停走 armor，保序不变）。
#[test]
fn l4_behavior_conn_id_present_unique_monotonic() {
    let ctx = xray_frame::contract_assert::contract_test_context("tun");
    xray_frame::assert_conn_id_present!(ctx, 1);
    let ids: Vec<u128> = (0..8)
        .map(|_| {
            std::thread::sleep(std::time::Duration::from_millis(1));
            ctx.next_conn_id()
        })
        .collect();
    xray_frame::contract_assert::assert_conn_id_sequence("tun", ids);
}

/// 夹具二 deadline（坑约束 2 / HandshakeDeadline，条款 2 适用：smoltcp
/// netstack 三次握手内聚存在）：双入口期限内 Ok + pending 任务掐断
/// Err(Elapsed) 真超时（d = 100ms 派单上限）。夹具自造 work，不触设备。
#[tokio::test]
async fn l4_behavior_deadline_effective() {
    xray_frame::assert_deadline_effective!(std::time::Duration::from_millis(100), || async {
        tokio::task::yield_now().await;
    })
    .await;
}

/// 夹具三 日志字段（坑约束 3/10 / LogDiscipline）：log 域约定 = 插件名 →
/// target = xray_frame::tun，四元组齐全；不带 secrets 表——条款 11
/// （SecretMasking）N/A（plugin.rs：「TUN 无密钥材料」）。
#[test]
fn l4_behavior_log_fields_quadruple() {
    xray_frame::assert_log_fields!(
        domain: "tun",
        conn_id: 0x1234u128,
        stage: "Accept",
        peer: "203.0.113.7:443",
        dest: "example.com:80",
    );
}

/// 夹具四 池纪律（坑约束 4/9 / PoolDiscipline，判据 = inbound.rs:71 xray-buf
/// io 接缝）：借 4 还 4 终态配平（borrowed = 0 且零溢出丢弃）。
#[test]
fn l4_behavior_pool_discipline_balances() {
    let pool =
        xray_frame::pool::ManagedBufferPool::new(xray_frame::pool::XrayBufPool::new(8, 8), 8, 8);
    xray_frame::assert_pool_discipline!(pool, 4);
}
