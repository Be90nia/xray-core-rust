//! P2 ss 插件化验收：L4 契约夹具（12 条全适用 + SS-2022-WIRE）+ 装配链
//! register → build → bring_up → shutdown（`is_clean()`）。
//!
//! 本文件**替换** B6 豁免清单（bd 7dce，2026-10-24）：声明面 `impl Plugin` +
//! `PluginContract` + `assert_plugin_contract!` + 装配正/负向 + L4 行为夹具四件
//! 全部落地，豁免登记（原头注释）随之失效。条款声明态权威标注面：
//! `xray_frame::contract_assert` 模块文档「条款声明态」节。
//!
//! （注册不进 xray-frame——xray-frame 禁依赖协议 crate，拍板 P2.1；同
//! trojan P2 批次 B / socks P2-A 的做法，注册写在协议 crate 自己的装配链里。）

use std::sync::Arc;

use serde_json::json;
use xray_frame::{
    ClauseId, Framework, FrameworkOptions, Plugin, PluginDep, PluginError, assert_conn_id_present,
    assert_deadline_effective, assert_log_fields, assert_plugin_contract, assert_pool_discipline,
};
use xray_proxy_ss::{SsFace, SsPlugin};

fn framework_options() -> FrameworkOptions {
    FrameworkOptions { registry_cap: 8, id_fingerprint: Some(1), shutdown_timeout: None }
}

/// 段形态：inbounds[] 按 protocol 路由（坑约束 7；ss 生产形态是入站，
/// 段路由的 inbounds[] 回落半边在此被真实覆盖）。
fn ss_section_config(settings: serde_json::Value) -> serde_json::Value {
    json!({ "inbounds": [{ "protocol": "shadowsocks", "settings": settings }] })
}

/// 段形态：outbounds[]（出站面；section() 先查 outbounds，此布局被真实覆盖）。
fn ss_outbound_section_config(settings: serde_json::Value) -> serde_json::Value {
    json!({ "outbounds": [{ "protocol": "shadowsocks", "settings": settings }] })
}

/// 装配链直达 build 产物（正向用例）。
fn build_framework(plugin: &Arc<SsPlugin>, config: serde_json::Value) -> Framework {
    Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(config)
        .register(Arc::clone(plugin) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect("build phase")
}

/// 装配链 build 失败错误（L5 负向用例；build 失败无 Framework 产出，无需停机）。
fn build_err(config: serde_json::Value) -> PluginError {
    Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(config)
        .register(Arc::new(SsPlugin::default()) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect_err("负向配置必须 build Err")
}

#[test]
fn contract_macro_holds_for_ss() {
    assert_plugin_contract!(SsPlugin);
}

/// 契约面内容断言：12 条通用条款全适用（无 N/A）、SS-2022-WIRE 协议专属。
#[test]
fn contract_surface_declares_all_applicable_and_extra() {
    let plugin = SsPlugin::default();
    let contract = plugin.contract();

    assert_eq!(plugin.name(), "shadowsocks");
    assert_eq!(plugin.version(), "0.1.0");
    let deps: &[PluginDep] = plugin.deps();
    assert!(deps.is_empty(), "ss 无依赖插件");

    assert_eq!(contract.clauses.len(), 12, "ss 12 条全适用（差异表 trojan/vmess 同行）");
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
    let (key, value) = contract.extra[0];
    assert_eq!(key, "SS-2022-WIRE");
    assert!(!value.is_empty(), "协议专属条款理由非空");
}

/// 完整装配链（legacy AEAD 多用户入站段）：段路由解析 → bring_up 三相 →
/// 停机报告干净；build 产物面判别（users 数组 → LegacyInbound）。
#[tokio::test]
async fn ss_assembles_bring_up_and_shuts_down_clean() {
    let plugin = Arc::new(SsPlugin::default());
    let mut framework = build_framework(
        &plugin,
        ss_section_config(json!({
            "users": [
                { "password": "test-pass", "email": "alice", "method": "aes-256-gcm" },
                { "password": "test-pass-2", "email": "bob", "method": "aes-128-gcm" }
            ]
        })),
    );
    assert!(!framework.is_running(), "build 成功但未 bring_up，不得误报运行态");

    framework.bring_up().expect("bring_up: init/start 三相");
    assert!(framework.is_running());

    let report = framework.shutdown().await;
    assert!(report.is_clean(), "健康链停机报告必须干净");

    assert!(matches!(plugin.face().expect("built"), SsFace::LegacyInbound(_)));
}

/// 入站五形态判定：legacy 扁平单用户 / ss2022 单用户 / ss2022 多用户 /
/// ss2022 Go 形中继各产出对应面（判定语义同规 xray-core parse_ss_inbound_config）。
#[tokio::test]
async fn inbound_faces_parse_per_mode() {
    // legacy 扁平单用户（缺 method → aes-128-gcm 缺省同规生产）。
    let plugin = Arc::new(SsPlugin::default());
    let framework = build_framework(
        &plugin,
        ss_section_config(json!({ "method": "aes-256-gcm", "password": "test-pass" })),
    );
    assert!(matches!(plugin.face().expect("built"), SsFace::LegacyInbound(_)));
    framework.shutdown().await;

    // ss2022 单用户（16 字节 PSK 的标准 base64）。
    let plugin = Arc::new(SsPlugin::default());
    let framework = build_framework(
        &plugin,
        ss_section_config(json!({
            "method": "2022-blake3-aes-128-gcm", "password": "9uQBlkLt6MtyKzbEw3LhWQ=="
        })),
    );
    assert!(matches!(plugin.face().expect("built"), SsFace::Ss2022(_)));
    framework.shutdown().await;

    // ss2022 多用户（users 数组无 address）。
    let plugin = Arc::new(SsPlugin::default());
    let framework = build_framework(
        &plugin,
        ss_section_config(json!({
            "method": "2022-blake3-aes-128-gcm",
            "password": "9uQBlkLt6MtyKzbEw3LhWQ==",
            "users": [{ "password": "9uQBlkLt6MtyKzbEw3LhWQ==", "email": "alice" }]
        })),
    );
    assert!(matches!(plugin.face().expect("built"), SsFace::Ss2022Multi(_)));
    framework.shutdown().await;

    // ss2022 Go 形中继（users 首元素带 address → relay）。
    let plugin = Arc::new(SsPlugin::default());
    let framework = build_framework(
        &plugin,
        ss_section_config(json!({
            "method": "2022-blake3-aes-128-gcm",
            "password": "9uQBlkLt6MtyKzbEw3LhWQ==",
            "users": [{
                "password": "9uQBlkLt6MtyKzbEw3LhWQ==",
                "address": "127.0.0.1", "port": 8388, "email": "relay-1"
            }]
        })),
    );
    assert!(matches!(plugin.face().expect("built"), SsFace::Ss2022Relay(_)));
    framework.shutdown().await;
}

/// 出站面：`servers` 数组（parse_ss_config 形 1）→ Outbound，产物逐字段核对
/// + dial_fn 产出（既有构造，wire 不变）。
#[tokio::test]
async fn outbound_face_parses_servers_and_produces_dial_fn() {
    let plugin = Arc::new(SsPlugin::default());
    let framework = build_framework(
        &plugin,
        ss_outbound_section_config(json!({
            "servers": [{ "address": "127.0.0.1", "port": 8388,
                           "method": "aes-256-gcm", "password": "test-pass" }]
        })),
    );
    let SsFace::Outbound(config) = plugin.face().expect("built") else {
        panic!("servers 数组 → Outbound 面");
    };
    assert_eq!(config.account.password, "test-pass", "账户随 parse_ss_config 构造");
    assert_eq!(config.server_port, 8388);
    plugin.dial_fn().expect("dial_fn 由既有 make_ss_dial_fn 构造");
    framework.shutdown().await;
}

/// 出站面判定之二：扁平 `address` 形态（parse_ss_config 形 2）同样 → Outbound。
#[tokio::test]
async fn outbound_face_parses_flat_address_form() {
    let plugin = Arc::new(SsPlugin::default());
    let framework = build_framework(
        &plugin,
        ss_outbound_section_config(json!({
            "address": "127.0.0.1", "port": 8388,
            "method": "aes-256-gcm", "password": "test-pass"
        })),
    );
    assert!(matches!(plugin.face().expect("built"), SsFace::Outbound(_)));
    framework.shutdown().await;
}

// ── L5 装配门负向（fail-visible，无半启动态）──

/// L5：缺段 fail-fast（坑约束 7 装配半边）。
#[tokio::test]
async fn missing_section_fails_fast_at_build() {
    let err = Framework::builder(framework_options())
        .expect("registry cap")
        .register(Arc::new(SsPlugin::default()) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect_err("config 根无 shadowsocks 段必须 fail-fast");
    assert!(matches!(err, PluginError::Config(_)), "实际: {err}");
}

/// L5：legacy 缺 password / 未知 cipher → build `Err`（同规 xray-core
/// parse_ss_inbound_config 硬错，禁静默回落。注：`method` 缺省 `aes-128-gcm`
/// 是同规生产的合法缺省，非负向）。
#[test]
fn legacy_missing_password_and_unknown_cipher_fail_fast() {
    let err = build_err(ss_section_config(json!({ "method": "aes-256-gcm" })));
    assert!(err.to_string().contains("missing password"), "实际: {err}");

    let err = build_err(ss_section_config(json!({ "method": "rc4-md5", "password": "p" })));
    assert!(err.to_string().contains("unsupported ss cipher: rc4-md5"), "实际: {err}");
}

/// L5：ss2022 缺 server PSK / PSK 非 base64 → build `Err`（缺 PSK 硬错同规
/// parse_ss2022_inbound_config；server PSK 的 base64 校验在同规路径上发生在
/// 既有构造函数内——错误原样 fail-visible，禁静默回落）。
#[test]
fn ss2022_bad_psk_fails_fast() {
    let err = build_err(ss_section_config(json!({ "method": "2022-blake3-aes-128-gcm" })));
    assert!(err.to_string().contains("missing server PSK"), "实际: {err}");

    let err = build_err(ss_section_config(json!({
        "method": "2022-blake3-aes-128-gcm",
        "password": "not-valid-base64!!!"
    })));
    assert!(err.to_string().contains("ss2022 single"), "实际: {err}");
}

/// build 前调用观察面 → `Err`（fail-visible，不 panic）。
#[test]
fn observation_before_build_fails_visible() {
    let plugin = SsPlugin::default();
    assert!(plugin.face().is_err());
    assert!(plugin.built_outbound().is_err());
    assert!(plugin.dial_fn().is_err());
}

// ── L4 行为夹具接线（P1-L4：每协议 crate 必调，缺=CI 红）──
// 按 contract() 声明面（src/plugin.rs SS_CLAUSES，12 条全适用）：
// 跑 conn_id(3) / deadline(2) / log(10,11) / pool(4)，无跳过项。
// 确定性指纹 + MockClock 冻结 ms=1 已在 contract_test_context 构造侧消除
// 同毫秒 IdGen 配额风险（contract_assert 模块文档拍板），不写重试 helper。

/// 夹具一（坑约束 3）：conn_id 非零/唯一/单调——无例外条款。
#[test]
fn l4_conn_id_present() {
    let ctx = xray_frame::contract_assert::contract_test_context("shadowsocks");
    assert_conn_id_present!(ctx, 64);
}

/// 夹具二（坑约束 2）：deadline 双入口期限内 Ok / 永不完成 Err(Elapsed) 且
/// 真超时。d 钉 100ms 上限（CI 慢机安全）。
#[tokio::test]
async fn l4_deadline_effective() {
    assert_deadline_effective!(std::time::Duration::from_millis(100), || async {}).await;
}

/// 夹具三（坑约束 10/11）：target 前缀 `xray_frame::shadowsocks` + 四元组齐全 +
/// secrets 掩码（条款 11 适用 → 表传真实形态凭据样例）。
#[test]
fn l4_log_fields() {
    assert_log_fields!(
        domain: "shadowsocks",
        conn_id: 0x1234u128,
        stage: "Handshake",
        peer: "203.0.113.7:443",
        dest: "example.com:80",
        secrets: ["ss-credential-sample"],
    );
}

/// 夹具四（坑约束 4/9）：借 N 还 N → PoolMetrics 配平（borrowed=0 且零溢出丢弃）。
#[test]
fn l4_pool_discipline() {
    let pool =
        xray_frame::pool::ManagedBufferPool::new(xray_frame::pool::XrayBufPool::new(8, 8), 8, 8);
    assert_pool_discipline!(pool, 4);
}
