//! P2 批次 D 验收：L4 契约夹具（9 条适用 + 3 N/A + DNS-U16 / DNS-ANTILOOP
//! 协议专属）+ 装配链 register → build → bring_up → shutdown（`is_clean()`）
//! + 装配门负向 + DNS-U16 行为断言 + handler 工厂产出。
//!
//! （注册不进 xray-frame——xray-frame 禁依赖协议 crate，拍板 P2.1；注册写在
//! 协议 crate 自己的装配链里，同 blackhole P1-7 / socks / freedom P2 做法。）

use std::{sync::Arc, time::Duration};

use serde_json::json;
use xray_features::inbound::InboundHandler;
use xray_frame::{
    ClauseId, Plugin, PluginDep, PluginError,
    assembly::{Framework, FrameworkOptions},
    assert_plugin_contract,
};
use xray_proxy_dns::{DnsOutbound, DnsPlugin, RuleAction, encode_tcp_dns_message};

fn framework_options() -> FrameworkOptions {
    FrameworkOptions { registry_cap: 8, id_fingerprint: Some(1), shutdown_timeout: None }
}

/// 段形态：outbounds[] 按 protocol 路由（坑约束 7；dns 生产形态是出站）。
fn dns_section_config(settings: serde_json::Value) -> serde_json::Value {
    json!({ "outbounds": [
        { "protocol": "dns", "tag": "dns-out", "settings": settings }
    ] })
}

#[test]
fn contract_macro_holds_for_dns() {
    assert_plugin_contract!(DnsPlugin);
}

/// 契约面内容断言：差异表 §2.2 第 16 行 + PM 拍板 2026-10-24——9 条适用
/// （3,4,5,6,7,8,9,10,12；4 = 转发面走 buf 受 BufferPool 接缝约束）、1/2/11
/// 走 N/A（理由非空，条款 1 同 freedom 先例）、DNS-U16 / DNS-ANTILOOP 协议专属。
#[test]
fn contract_surface_declares_subset_na_and_extra() {
    let plugin = DnsPlugin::default();
    let contract = plugin.contract();

    assert_eq!(plugin.name(), "dns");
    assert_eq!(plugin.version(), "0.1.0");
    let deps: &[PluginDep] = plugin.deps();
    assert!(deps.is_empty(), "dns 无依赖插件");

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
        "dns 适用 9 条（差异表 §2.2 第 16 行 + PM 拍板条款 4）"
    );
    for clause in expected {
        assert!(contract.clauses.contains(clause), "缺条款 {clause:?}");
    }

    let na: &[ClauseId] =
        &[ClauseId::AuthErrorClassified, ClauseId::HandshakeDeadline, ClauseId::SecretMasking];
    assert_eq!(contract.not_applicable.len(), na.len(), "dns 声明 3 条 N/A");
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
            ("DNS-U16", "TCP DNS 长度前缀 u16 超限必须 Err（样板 handler.rs:234-236），禁改回截断"),
            ("DNS-ANTILOOP", "fakedns 与真实 DNS 回环防护语义不变"),
        ],
        "协议专属条款 DNS-U16 + DNS-ANTILOOP"
    );
}

/// DNS-U16 行为断言（L4 逐条断言半边）：u16 超限必须 Err，禁静默截断
/// （样板 handler.rs:234-236）。DNS-ANTILOOP 的运行时半边（ownLink 判定）
/// 在 xray-core/app-dns，本 crate 零实现——契约文本断言见上。
#[test]
fn dns_u16_overflow_fails_visible() {
    let oversized = vec![0u8; (u16::MAX as usize) + 1];
    let err = encode_tcp_dns_message(&oversized).expect_err("超限必须 Err（禁截断）");
    assert!(err.to_string().contains("too long for u16"), "实际: {err}");
    // 边界内不误伤：u16::MAX 恰好可编码（2B 前缀 + body）。
    let boundary = vec![0u8; u16::MAX as usize];
    assert_eq!(
        encode_tcp_dns_message(&boundary).expect("边界内必须成功").len(),
        2 + boundary.len()
    );
}

/// 完整装配链：段路由解析 → bring_up 三相 → 停机报告干净；
/// build 产物逐字段核对（Go 方言 rules + userLevel）。
#[tokio::test]
async fn dns_assembles_bring_up_and_shuts_down_clean() {
    let plugin = Arc::new(DnsPlugin::default());
    let mut framework = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(dns_section_config(json!({
            "rules": [
                {
                    "action": "drop",
                    "qType": [1, 28],
                    "domain": ["domain:ads.example.com"]
                }
            ],
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

    let built = plugin.built_config().expect("built");
    assert_eq!(built.user_level, 2);
    assert_eq!(built.rule.len(), 1);
    assert_eq!(built.rule[0].action, RuleAction::Drop);
    assert_eq!(built.rule[0].q_type, vec![1, 28]);
    assert_eq!(built.rule[0].domain.len(), 1);
}

/// L5 装配门负向①：缺段 fail-fast（坑约束 7 装配半边），
/// build 失败 → 无 Framework 产出（无半启动态）。
#[tokio::test]
async fn missing_section_fails_fast_at_build() {
    let err = Framework::builder(framework_options())
        .expect("registry cap")
        .register(Arc::new(DnsPlugin::default()) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect_err("config 根无 dns 段必须 fail-fast");
    assert!(matches!(err, PluginError::Config(_)), "实际: {err}");
}

/// L5 装配门负向②：未知 action 硬错拒启（Go DNSOutboundRuleConfig.Build 文案）。
#[tokio::test]
async fn unknown_action_fails_build() {
    let err = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(dns_section_config(json!({ "rules": [{ "action": "DropAll" }] })))
        .register(Arc::new(DnsPlugin::default()) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect_err("未知 action 必须硬错拒启");
    match err {
        PluginError::Other(source) => {
            assert!(source.to_string().contains("unknown action: DropAll"), "实际: {source}")
        },
        other => panic!("应为 Other 硬错，实际: {other:?}"),
    }
}

/// build 前调用工厂/观察面 → `Err`（fail-visible，无半构建态）。
#[test]
fn handlers_before_build_fail_visible() {
    let plugin = DnsPlugin::default();
    assert!(plugin.built_config().is_err(), "build 前观察产物必须 Err");
    assert!(plugin.rule_handler(Duration::from_secs(5)).is_err(), "build 前产出规则核必须 Err");
}

/// handler 由插件产出：规则核（[`xray_proxy_dns::Handler::init`] fail-closed
/// 生产同构，规则数随配置）+ 入站 handler（`DnsInbound::new` 接缝；处理行为
/// 属既有实测——handler.rs/inbound.rs 零 diff）。
#[tokio::test]
async fn handlers_produced_by_plugin() {
    let plugin = Arc::new(DnsPlugin::default());
    let framework = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(dns_section_config(json!({
            "rules": [{ "action": "return", "qType": [28] }]
        })))
        .register(Arc::clone(&plugin) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect("build");

    let handler = plugin.rule_handler(Duration::from_secs(5)).expect("rule handler");
    assert_eq!(handler.rule_count(), 1, "规则数随 build 产物");

    let outbound = DnsOutbound::new_with_servers("up", &[]).expect("empty-server resolver");
    let inbound = plugin
        .inbound_handler("dns-in", Duration::from_secs(5), outbound)
        .expect("inbound handler");
    assert_eq!(InboundHandler::tag(&inbound), "dns-in");

    framework.shutdown().await;
}

// ── L4 行为夹具（P1-L4：声明面之外的「跑起来验证」；对照 contract() 声明
// ——dns 9 条适用（3,4,5,6,7,8,9,10,12）；条款 2 N/A → deadline 夹具按声明
// 跳过；条款 11 N/A → log 夹具不带 secrets 表）──

/// 夹具一 conn_id（坑约束 3 / ConnIdPresent）：宏形取单枚验非零；唯一/单调
/// 面用逐 id 跨毫秒 drip——协议 crate 不直依赖 skeleton，无法注入固定指纹，
/// `contract_test_context` 随机指纹下宏形 n 连取有 (n−1)/4096 同毫秒配额
/// fail-closed flake（std_ext::id：每毫秒配额 = 4096 − 基址，基址随机）；
/// 逐毫秒领取配额下界恒 1 = 零 flake（挂钟回拨走停走 armor，保序不变）。
#[test]
fn l4_behavior_conn_id_present_unique_monotonic() {
    let ctx = xray_frame::contract_assert::contract_test_context("dns");
    xray_frame::assert_conn_id_present!(ctx, 1);
    let ids: Vec<u128> = (0..8)
        .map(|_| {
            std::thread::sleep(std::time::Duration::from_millis(1));
            ctx.next_conn_id()
        })
        .collect();
    xray_frame::contract_assert::assert_conn_id_sequence("dns", ids);
}

// 夹具二 deadline：**按声明跳过**——条款 2（HandshakeDeadline）N/A（
// plugin.rs DNS_NOT_APPLICABLE：「DNS 无会话握手：UDP 单包查询、TCP 2B
// 长度帧直读，无协商轮次与首包 deadline 面」）。声明与夹具矛盾时按派单
// 约束两侧都不改，仅记录跳过。

/// 夹具三 日志字段（坑约束 3/10 / LogDiscipline）：log 域约定 = 插件名 →
/// target = xray_frame::dns，四元组齐全；不带 secrets 表——条款 11
/// （SecretMasking）N/A（plugin.rs：「DNS 无密钥材料」）。
#[test]
fn l4_behavior_log_fields_quadruple() {
    xray_frame::assert_log_fields!(
        domain: "dns",
        conn_id: 0x1234u128,
        stage: "Accept",
        peer: "203.0.113.7:443",
        dest: "example.com:80",
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
