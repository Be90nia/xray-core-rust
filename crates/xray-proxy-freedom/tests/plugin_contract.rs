//! P2 批次 B 末位验收：L4 契约夹具（9 条适用 + 3 条 N/A + FREEDOM-SPLICE /
//! FREEDOM-FINALRULES 协议专属）+ 装配链 register → build → bring_up →
//! shutdown（`is_clean()`）+ 装配门负向 + handler 工厂产出。
//!
//! （注册不进 xray-frame——xray-frame 禁依赖协议 crate，拍板 P2.1；注册写在
//! 协议 crate 自己的装配链里，同 blackhole P1-7 / socks / http P2-B 做法。）

use std::sync::Arc;

use serde_json::json;
use xray_app_dispatcher::default::SimpleOhm;
use xray_common::net::{address::Address, destination::Destination, network::Network, port::Port};
use xray_features::{inbound::InboundHandler, outbound::OutboundHandler};
use xray_frame::{
    ClauseId, Plugin, PluginDep, PluginError,
    assembly::{Framework, FrameworkOptions},
    assert_plugin_contract,
};
use xray_proxy_freedom::{
    Config, DomainStrategy, FinalRuleConfig, FreedomHandler, FreedomInboundHandler, FreedomPlugin,
    RuleAction,
};

fn framework_options() -> FrameworkOptions {
    FrameworkOptions { registry_cap: 8, id_fingerprint: Some(1), shutdown_timeout: None }
}

/// 段形态：outbounds[] 按 protocol 路由（坑约束 7；freedom 生产形态是出站）。
fn freedom_section_config(settings: serde_json::Value) -> serde_json::Value {
    json!({ "outbounds": [
        { "protocol": "freedom", "tag": "freedom-out", "settings": settings }
    ] })
}

#[test]
fn contract_macro_holds_for_freedom() {
    assert_plugin_contract!(FreedomPlugin);
}

/// 契约面内容断言：差异表 §2.2 第 8 行——9 条适用（3/5/6/7/8/9/10/12 + 4：
/// 直连面走 buf）、1/2/11 走 N/A（理由非空，条款 1 PM 拍板 2026-10-24 补齐）、
/// FREEDOM-SPLICE / FREEDOM-FINALRULES 协议专属。
#[test]
fn contract_surface_declares_subset_na_and_extra() {
    let plugin = FreedomPlugin::default();
    let contract = plugin.contract();

    assert_eq!(plugin.name(), "freedom");
    assert_eq!(plugin.version(), "0.1.0");
    let deps: &[PluginDep] = plugin.deps();
    assert!(deps.is_empty(), "freedom 无依赖插件");

    let expected: &[ClauseId] = &[
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
        "freedom 适用 9 条（差异表 §2.2 第 8 行 + 条款 4 直连面走 buf）"
    );
    for clause in expected {
        assert!(contract.clauses.contains(clause), "缺条款 {clause:?}");
    }

    let na: &[ClauseId] =
        &[ClauseId::AuthErrorClassified, ClauseId::HandshakeDeadline, ClauseId::SecretMasking];
    assert_eq!(contract.not_applicable.len(), na.len(), "freedom 声明 3 条 N/A");
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
        &[
            (
                "FREEDOM-SPLICE",
                "splice 直连面禁动（判定点 dispatcher default.rs:1805-1818），插件化不触碰"
            ),
            (
                "FREEDOM-FINALRULES",
                "裸 freedom outbound 必带 settings.finalRules=[{action:allow}]，否则 final rule 默认 blackholing，会伪装成数据面 bug"
            ),
        ],
        "协议专属条款 FREEDOM-SPLICE + FREEDOM-FINALRULES"
    );
}

/// 完整装配链：段路由解析 → bring_up 三相 → 停机报告干净；
/// build 产物逐字段核对（domainStrategy/userLevel/proxyProtocol/finalRules）。
#[tokio::test]
async fn freedom_assembles_bring_up_and_shuts_down_clean() {
    let plugin = Arc::new(FreedomPlugin::default());
    let mut framework = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(freedom_section_config(json!({
            "domainStrategy": "UseIP",
            "userLevel": 2,
            "proxyProtocol": 2,
            "finalRules": [{ "action": "allow" }]
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

    let expected = Config {
        domain_strategy: DomainStrategy::UseIP as i32,
        user_level: 2,
        proxy_protocol: 2,
        final_rules: vec![FinalRuleConfig {
            action: RuleAction::Allow,
            ..FinalRuleConfig::default()
        }],
        ..Config::default()
    };
    assert_eq!(plugin.built_config().expect("built"), &expected);
}

/// FREEDOM-FINALRULES 语义保留：settings 缺 finalRules → 空规则表，
/// 不静默注入 allow（默认规则 blackholing 行为归部署面显式配置）。
#[tokio::test]
async fn final_rules_absent_stays_empty_no_silent_allow() {
    let plugin = Arc::new(FreedomPlugin::default());
    let framework = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(freedom_section_config(json!({ "domainStrategy": "AsIs" })))
        .register(Arc::clone(&plugin) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect("build");
    assert!(plugin.built_config().expect("built").final_rules.is_empty(), "缺省不得静默注入 allow");
    framework.shutdown().await;
}

/// L5 装配门负向：缺段 fail-fast（坑约束 7 装配半边），
/// build 失败 → 无 Framework 产出（无半启动态）。
#[tokio::test]
async fn missing_section_fails_fast_at_build() {
    let err = Framework::builder(framework_options())
        .expect("registry cap")
        .register(Arc::new(FreedomPlugin::default()) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect_err("config 根无 freedom 段必须 fail-fast");
    assert!(matches!(err, PluginError::Config(_)), "实际: {err}");
}

/// 解析期硬错（Go FreedomConfig.Build 拒启语义）：未知 domainStrategy，
/// 错误信息保留原始大小写。
#[tokio::test]
async fn unknown_domain_strategy_fails_build() {
    let err = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(freedom_section_config(json!({ "domainStrategy": "UseIPv3" })))
        .register(Arc::new(FreedomPlugin::default()) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect_err("未知 domainStrategy 必须硬错拒启");
    match err {
        PluginError::Other(source) => assert!(
            source.to_string().contains("unsupported domain strategy: UseIPv3"),
            "实际: {source}"
        ),
        other => panic!("应为 Other 硬错，实际: {other:?}"),
    }
}

/// 解析期硬错：finalRules 单条非法整出站拒启（Go freedom.go:186-191）。
#[tokio::test]
async fn invalid_final_rule_fails_build() {
    let err = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(freedom_section_config(json!({ "finalRules": [{ "action": "bogus" }] })))
        .register(Arc::new(FreedomPlugin::default()) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect_err("非法 finalRule 必须硬错拒启");
    match err {
        PluginError::Other(source) => {
            assert!(source.to_string().contains("freedom finalRule"), "实际: {source}")
        },
        other => panic!("应为 Other 硬错，实际: {other:?}"),
    }
}

/// build 前调用工厂/观察面 → `Err`（fail-visible，无半构建态）。
#[test]
fn handlers_before_build_fail_visible() {
    let plugin = FreedomPlugin::default();
    assert!(plugin.built_config().is_err(), "build 前观察产物必须 Err");
    assert!(plugin.dispatch_handler("t").is_err(), "build 前产出出站 handler 必须 Err");
}

/// 出/入站 handler 由插件产出（tag 注入 + finalRules 预构建硬错语义沿用；
/// 转发行为属既有 OutboundHandler/InboundHandler 实测——handler.rs/inbound.rs 零 diff）。
#[tokio::test]
async fn handlers_produced_by_plugin() {
    let plugin = Arc::new(FreedomPlugin::default());
    let framework = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(freedom_section_config(json!({
            "finalRules": [{ "action": "block", "ip": ["10.0.0.0/8"] }]
        })))
        .register(Arc::clone(&plugin) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect("build");

    let outbound: FreedomHandler =
        plugin.dispatch_handler("freedom-out").expect("outbound handler");
    assert_eq!(outbound.tag(), "freedom-out");

    let dest = Destination::new(
        Address::from(std::net::Ipv4Addr::LOCALHOST),
        Port::from(443_u16),
        Network::TCP,
    );
    let inbound: FreedomInboundHandler = plugin
        .inbound_handler("freedom-in", "127.0.0.1:0", dest, Arc::new(SimpleOhm::new()))
        .expect("inbound handler");
    assert_eq!(inbound.tag(), "freedom-in");

    framework.shutdown().await;
}

// ── L4 行为夹具接线（P1-L4：每协议 crate 必调，缺=CI 红）──
// 按 contract() 声明面（src/plugin.rs FREEDOM_CLAUSES / FREEDOM_NOT_APPLICABLE）：
// 跑 conn_id(3) / log(10) / pool(4)；跳过 deadline(2)——freedom 无协议握手
// （直连拨号，无协商轮次，无首包 deadline 面）；log(11) N/A → secrets 表传空
// （仍断 target/四元组）。

/// 夹具一（坑约束 3）：conn_id 非零/唯一/单调——无例外条款。
///
/// 执行面：`contract_test_context` 的指纹随进程掷点（`derive_fingerprint(None)`），
/// 基址落 0xFFF 邻域时同毫秒 64 连发会撞 IdGen fail-closed 配额臂（约 1.5%/掷点，
/// panic 消息含「配额耗尽」）——夹具整体在 catch_unwind 内彩排，撞配额臂则重掷
/// 指纹重跑（8 连败联合概率 ~1e-15），其余 panic 原样上抛。成功返回 = 宏断言在
/// 本 ctx 上真实执行且通过。
fn l4_run_conn_id_fixture(plugin: &'static str) {
    use std::any::Any;
    use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

    let mut last: Option<Box<dyn Any + Send>> = None;
    for _ in 0..8 {
        let ctx = xray_frame::contract_assert::contract_test_context(plugin);
        match catch_unwind(AssertUnwindSafe(|| xray_frame::assert_conn_id_present!(ctx, 64))) {
            Ok(()) => return,
            Err(payload) => {
                let quota = payload.downcast_ref::<String>().is_some_and(|m| m.contains("配额耗尽"))
                    || payload
                        .downcast_ref::<&'static str>()
                        .is_some_and(|m| m.contains("配额耗尽"));
                if !quota {
                    resume_unwind(payload);
                }
                last = Some(payload);
            }
        }
    }
    resume_unwind(last.expect("重掷循环至少记录一次失败 payload"));
}

#[test]
fn l4_conn_id_present() {
    l4_run_conn_id_fixture("freedom");
}

/// 夹具三（坑约束 10；11 N/A → secrets 表传空）：target 前缀 `xray_frame::freedom`
/// + conn_id/stage/peer/dest 四元组齐全。无密钥材料面，无掩码断言项。
#[test]
fn l4_log_fields() {
    xray_frame::assert_log_fields!(
        domain: "freedom",
        conn_id: 0x1234u128,
        stage: "Dial",
        peer: "203.0.113.7:443",
        dest: "example.com:80",
    );
}

/// 夹具四（坑约束 4/9）：借 N 还 N → PoolMetrics 配平（borrowed=0 且零溢出丢弃）。
/// 条款 4 适用（直连面走 buf，受 BufferPool 接缝约束）。
#[test]
fn l4_pool_discipline() {
    let pool = xray_frame::pool::ManagedBufferPool::new(xray_frame::pool::XrayBufPool::new(8, 8), 8, 8);
    xray_frame::assert_pool_discipline!(pool, 4);
}
