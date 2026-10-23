//! P2 批次 D 验收：L4 契约夹具（11 条适用 + 条款 2 N/A + ATLS-AUTHFRAME 协议专属）
//! + 装配链 register → build → bring_up → shutdown（`is_clean()`）+ 装配门负向
//! + handler 工厂产出。
//!
//! （注册不进 xray-frame——xray-frame 禁依赖协议 crate，拍板 P2.1；注册写在协议
//! crate 自己的装配链里，同 blackhole P1-7 / dns P2 做法。）
//!
//! ATLS-AUTHFRAME 的行为锚在 `src/server.rs` 的
//! `oversized_padding0_len_rejected`（认证帧 `padding0_len = u16::MAX` → 服务端不等
//! 65535 字节 padding 即关连接，2s 内必须读到 EOF/重置）——本文件只断言契约文本，
//! 时序语义由该既有单测锁定，不在此复制第二份裸 TLS 探针。

use std::{
    net::SocketAddr,
    sync::{Arc, Once},
};

use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::PrivateKeyDer;
use serde_json::json;
use tokio_rustls::TlsAcceptor;
use xray_features::inbound::InboundHandler;
use xray_frame::{
    ClauseId, Plugin, PluginDep, PluginError,
    assembly::{Framework, FrameworkOptions},
    assert_plugin_contract,
};
use xray_proxy_anytls::AnytlsPlugin;

static INIT_CRYPTO: Once = Once::new();

/// 自签证书 acceptor（构造面探针用；证书链语义沿用 inbound.rs 单测的既有做法）。
fn make_tls_acceptor() -> TlsAcceptor {
    INIT_CRYPTO.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
    let key_pair = KeyPair::generate().expect("rcgen keypair");
    let params = CertificateParams::new(vec!["localhost".into()]).expect("rcgen params");
    let cert = params.self_signed(&key_pair).expect("rcgen self_signed");
    let key_der = PrivateKeyDer::try_from(key_pair.serialize_der()).expect("key der");
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().to_owned()], key_der)
        .expect("rustls server config");
    TlsAcceptor::from(Arc::new(config))
}

fn framework_options() -> FrameworkOptions {
    FrameworkOptions { registry_cap: 8, id_fingerprint: Some(1), shutdown_timeout: None }
}

/// 段形态：inbounds[] 按 protocol 路由（坑约束 7；anytls 生产形态是入站）。
fn anytls_section_config(settings: serde_json::Value) -> serde_json::Value {
    json!({ "inbounds": [
        { "protocol": "anytls", "tag": "anytls-in", "settings": settings }
    ] })
}

#[test]
fn contract_macro_holds_for_anytls() {
    assert_plugin_contract!(AnytlsPlugin);
}

/// 契约面内容断言：差异表 §2.2 第 12 行 + PM 拍板 2026-10-24——11 条适用 +
/// 条款 2（HandshakeDeadline）走 N/A（理由非空；握手时限缺失已立 bd 债票）、
/// ATLS-AUTHFRAME 协议专属。
#[test]
fn contract_surface_declares_all_clauses_and_extra() {
    let plugin = AnytlsPlugin::default();
    let contract = plugin.contract();

    assert_eq!(plugin.name(), "anytls");
    assert_eq!(plugin.version(), "0.1.0");
    let deps: &[PluginDep] = plugin.deps();
    assert!(deps.is_empty(), "anytls 无依赖插件");

    assert_eq!(contract.clauses.len(), 11, "12 条去掉条款 2（N/A）");
    assert!(
        !contract.clauses.contains(&ClauseId::HandshakeDeadline),
        "条款 2 必须走 N/A 声明而非 clauses"
    );
    assert!(contract.clauses.contains(&ClauseId::HotPathFreeze), "数据面热路径零改动必填");

    let [(na_clause, na_reason)] = contract.not_applicable else {
        panic!("anytls 必须恰好声明一条 N/A（条款 2）");
    };
    assert_eq!(na_clause, &ClauseId::HandshakeDeadline);
    assert!(!na_reason.trim().is_empty(), "N/A 理由必须非空（拍板 P2.2）");
    assert!(
        na_reason.contains("dial_out/accept 无超时") && na_reason.contains("不在数据面新增时限"),
        "N/A 理由必须是 PM 拍板的诚实版: {na_reason}"
    );

    assert_eq!(
        contract.extra,
        &[(
            "ATLS-AUTHFRAME",
            "认证帧 padding0_len=u16::MAX 时服务端直接丢弃连接（server.rs:653-659），禁改为「读满再判」"
        )],
        "协议专属条款 ATLS-AUTHFRAME"
    );
}

/// 完整装配链：段路由解析 → bring_up 三相 → 停机报告干净；build 产物核对。
#[tokio::test]
async fn anytls_assembles_bring_up_and_shuts_down_clean() {
    let plugin = Arc::new(AnytlsPlugin::default());
    let mut framework = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(anytls_section_config(json!({ "password": "s3cret" })))
        .register(Arc::clone(&plugin) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect("build phase");
    assert!(!framework.is_running(), "build 成功但未 bring_up，不得误报运行态");

    framework.bring_up().expect("bring_up: init/start 三相");
    assert!(framework.is_running());

    let report = framework.shutdown().await;
    assert!(report.is_clean(), "健康链停机报告必须干净");

    assert_eq!(plugin.built_password().expect("built"), Some("s3cret"), "build 产物 = 段密码");
}

/// L5 装配门负向①：缺段 fail-fast（坑约束 7 装配半边），
/// build 失败 → 无 Framework 产出（无半启动态）。
#[tokio::test]
async fn missing_section_fails_fast_at_build() {
    let err = Framework::builder(framework_options())
        .expect("registry cap")
        .register(Arc::new(AnytlsPlugin::default()) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect_err("config 根无 anytls 段必须 fail-fast");
    assert!(matches!(err, PluginError::Config(_)), "实际: {err}");
}

/// L5 装配门负向②：`password` 非字符串 → build 硬错（静默忽略 = 认证面静默失效）。
#[tokio::test]
async fn non_string_password_fails_build() {
    let err = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(anytls_section_config(json!({ "password": 123 })))
        .register(Arc::new(AnytlsPlugin::default()) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect_err("非字符串 password 必须 hard fail");
    assert!(err.to_string().contains("must be a string"), "实际: {err}");
}

/// build 前调用工厂/观察面 → `Err`（fail-visible，无半构建态）。
#[test]
fn handlers_before_build_fail_visible() {
    let plugin = AnytlsPlugin::default();
    assert!(plugin.built_password().is_err(), "build 前观察产物必须 Err");
    let addr: SocketAddr = "127.0.0.1:0".parse().expect("addr");
    assert!(
        plugin.inbound_handler("anytls-in", addr, make_tls_acceptor()).is_err(),
        "build 前产出 handler 必须 Err"
    );
}

/// handler 由插件产出：`AnytlsInboundHandler::new` + `with_password` 接缝
/// （inbound.rs 零 diff；监听/TLS 行为属既有实测）。密码缺省（段无 password）→
/// 不校验认证帧（同 core `parse_anytls_tls_acceptor` 语义）。
#[tokio::test]
async fn inbound_handler_produced_by_plugin() {
    let with_pw = Arc::new(AnytlsPlugin::default());
    let framework = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(anytls_section_config(json!({ "password": "s3cret" })))
        .register(Arc::clone(&with_pw) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect("build");

    let addr: SocketAddr = "127.0.0.1:0".parse().expect("addr");
    let inbound =
        with_pw.inbound_handler("anytls-in", addr, make_tls_acceptor()).expect("inbound handler");
    assert_eq!(InboundHandler::tag(&inbound), "anytls-in");
    assert_eq!(inbound.bind_addr(), addr);
    assert_eq!(InboundHandler::port(&inbound), 0, "未 start 前端口为配置值");

    framework.shutdown().await;

    let no_pw = Arc::new(AnytlsPlugin::default());
    let framework = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(anytls_section_config(json!({})))
        .register(Arc::clone(&no_pw) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect("build: 无 password 段合法（不校验认证帧）");
    assert_eq!(no_pw.built_password().expect("built"), None);
    framework.shutdown().await;
}

// ── L4 行为夹具（P1-L4：声明面之外的「跑起来验证」；对照 contract() 声明
// ——anytls 11 条适用；条款 2 N/A → deadline 夹具按声明跳过；条款 11 适用
// → log 夹具带 secrets 表）──

/// 夹具一 conn_id（坑约束 3 / ConnIdPresent）：宏形取单枚验非零；唯一/单调
/// 面用逐 id 跨毫秒 drip——协议 crate 不直依赖 skeleton，无法注入固定指纹，
/// `contract_test_context` 随机指纹下宏形 n 连取有 (n−1)/4096 同毫秒配额
/// fail-closed flake（std_ext::id：每毫秒配额 = 4096 − 基址，基址随机）；
/// 逐毫秒领取配额下界恒 1 = 零 flake（挂钟回拨走停走 armor，保序不变）。
#[test]
fn l4_behavior_conn_id_present_unique_monotonic() {
    let ctx = xray_frame::contract_assert::contract_test_context("anytls");
    xray_frame::assert_conn_id_present!(ctx, 1);
    let ids: Vec<u128> = (0..8)
        .map(|_| {
            std::thread::sleep(std::time::Duration::from_millis(1));
            ctx.next_conn_id()
        })
        .collect();
    xray_frame::contract_assert::assert_conn_id_sequence("anytls", ids);
}

// 夹具二 deadline：**按声明跳过**——条款 2（HandshakeDeadline）N/A（PM 拍板
// 2026-10-24，plugin.rs ANYTLS_NOT_APPLICABLE：「anytls 的握手/首包时限当前
// 未在本 crate 实现（dial_out/accept 无超时），时限由 transport/TLS 与连接
// 空闲策略覆盖；本插件不在数据面新增时限（避免改行为）」；缺失已立 bd 债票）。
// 声明与夹具矛盾时按派单约束两侧都不改，仅记录跳过。

/// 夹具三 日志字段（坑约束 3/10/11 / LogDiscipline + SecretMasking）：log 域
/// 约定 = 插件名 → target = xray_frame::anytls，四元组齐全 + secrets 掩码。
#[test]
fn l4_behavior_log_fields_quadruple_masked() {
    xray_frame::assert_log_fields!(
        domain: "anytls",
        conn_id: 0x1234u128,
        stage: "Handshake",
        peer: "203.0.113.7:443",
        dest: "example.com:80",
        secrets: ["anytls-password-redacted"]
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
