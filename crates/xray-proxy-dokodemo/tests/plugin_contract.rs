//! P2 批次 B 验收：L4 契约夹具（差异表 §2.2 第 7 行：8 条适用 + 2/11 N/A +
//! DKD-TPROXY）+ 装配链 register → build → bring_up → shutdown（`is_clean()`）。
//!
//! （注册不进 xray-frame——xray-frame 禁依赖协议 crate，拍板 P2.1；同
//! blackhole P1-7 / socks P2 批次 A 的做法，注册写在协议 crate 自己的装配链里。）

use std::sync::Arc;

use serde_json::json;
use xray_features::inbound::InboundHandler;
use xray_frame::{
    ClauseId, Plugin, PluginError,
    assembly::{Framework, FrameworkOptions},
    assert_plugin_contract,
};
use xray_proto::xray::common::net::{
    IpOrDomain as ProtoIpOrDomain, ip_or_domain::Address as ProtoAddress,
};
use xray_proxy_dokodemo::{Config, DokodemoPlugin, Network};

fn framework_options() -> FrameworkOptions {
    FrameworkOptions { registry_cap: 8, id_fingerprint: Some(1), shutdown_timeout: None }
}

/// 段形态：inbounds[] 按 protocol 路由（坑约束 7；dokodemo 生产形态是入站）。
fn dokodemo_section_config(settings: serde_json::Value) -> serde_json::Value {
    json!({ "inbounds": [
        { "protocol": "dokodemo-door", "tag": "dkd-in", "settings": settings }
    ] })
}

#[test]
fn contract_macro_holds_for_dokodemo() {
    assert_plugin_contract!(DokodemoPlugin);
}

/// 契约面内容断言：适用子集 9 条（差异表 §2.2 第 7 行 3,5,6,7,8,9,10,12 +
/// PM 拍板 2026-10-24 补 4）、1/2/11 N/A + 非空理由、DKD-TPROXY 协议专属、
/// 协议名 `dokodemo-door`。
#[test]
fn contract_surface_declares_subset_na_and_extra() {
    let plugin = DokodemoPlugin::default();
    let contract = plugin.contract();

    assert_eq!(plugin.name(), "dokodemo-door", "Go 注册名（xray-conf 段路由同名）");
    assert_eq!(plugin.version(), "0.1.0");
    let deps: &[xray_frame::PluginDep] = plugin.deps();
    assert!(deps.is_empty(), "dokodemo 无依赖插件");

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
    assert_eq!(contract.clauses.len(), expected.len(), "适用子集 9 条（含 PM 拍板补的 4）");
    for clause in expected {
        assert!(contract.clauses.contains(clause), "缺条款 {clause:?}");
    }

    assert_eq!(contract.not_applicable.len(), 3, "1/2/11 N/A");
    let na: Vec<ClauseId> = contract.not_applicable.iter().map(|(c, _)| *c).collect();
    assert!(na.contains(&ClauseId::AuthErrorClassified), "1 无认证 → N/A（PM 拍板 2026-10-24）");
    assert!(na.contains(&ClauseId::HandshakeDeadline), "2 无握手 → N/A");
    assert!(na.contains(&ClauseId::SecretMasking), "11 无密钥 → N/A");
    for (_, reason) in contract.not_applicable {
        assert!(!reason.trim().is_empty(), "N/A 理由必须非空");
    }

    assert_eq!(
        contract.extra,
        &[("DKD-TPROXY", "TPROXY 路径仅 Linux，平台门控不得在非 Linux 编译期裁掉语义测试")],
        "协议专属条款 DKD-TPROXY"
    );
}

/// 完整装配链：段路由解析 → bring_up 三相 → 停机报告干净；
/// build 产物逐字段核对（address/port/network/followRedirect/userLevel/portMap）。
#[tokio::test]
async fn dokodemo_assembles_bring_up_and_shuts_down_clean() {
    let plugin = Arc::new(DokodemoPlugin::default());
    let mut framework = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(dokodemo_section_config(json!({
            "address": "8.8.8.8",
            "port": 53,
            "network": ["tcp", "udp"],
            "followRedirect": true,
            "userLevel": 2,
            "portMap": { "53": ":5353" }
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
        rewrite_address: Some(ProtoIpOrDomain {
            address: Some(ProtoAddress::Ip(vec![8, 8, 8, 8])),
        }),
        rewrite_port: 53,
        allowed_networks: vec![Network::Tcp, Network::Udp],
        port_map: [("53".to_string(), ":5353".to_string())].into_iter().collect(),
        follow_redirect: true,
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
        .register(Arc::new(DokodemoPlugin::default()) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect_err("config 根无 dokodemo-door 段必须 fail-fast");
    assert!(matches!(err, PluginError::Config(_)), "实际: {err}");
}

/// 入站 handler 由插件产出（tag 注入 + 配置从段注入；start/close 生命周期与
/// accept 行为属既有 InboundHandler 实测，本文件零改动）。
#[tokio::test]
async fn inbound_handler_produced_by_plugin() {
    let plugin = Arc::new(DokodemoPlugin::default());
    Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(dokodemo_section_config(json!({
            "address": "127.0.0.1",
            "port": 10800
        })))
        .register(Arc::clone(&plugin) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect("build");

    let inbound = plugin.inbound_handler("dkd-in").expect("inbound handler");
    assert_eq!(inbound.tag(), "dkd-in");
}

/// DKD-TPROXY 语义锚：平台门控是**运行时语义**而非编译期裁剪——本测试**不做
/// cfg 门控**，所有平台都编译执行：非 Linux 上 `fake_udp` 可调且返回 Err
/// （对齐 Go `fakeudp_other.go` 的 `!linux`），证明门控语义面存在而非被裁掉；
/// Linux 上两态皆合法（`IP_TRANSPARENT` 需 CAP_NET_ADMIN，syscall 层裁决）。
#[test]
fn tproxy_gate_is_runtime_semantics_not_compiled_away() {
    let addr: std::net::SocketAddr = "127.0.0.1:0".parse().expect("addr");
    let result = xray_proxy_dokodemo::fakeudp::fake_udp(addr, 0);
    #[cfg(target_os = "linux")]
    {
        // Linux：有 CAP_NET_ADMIN → Ok，无 → Err；仅断言调用面存在不 panic。
        let _ = result;
    }
    #[cfg(not(target_os = "linux"))]
    {
        let err = result.expect_err("非 Linux 平台 fake_udp 必须返回 Err（fakeudp_other 语义）");
        assert!(err.to_string().contains("!linux"), "实际: {err}");
    }
}

// ── L4 行为夹具接线（P1-L4：每协议 crate 必调，缺=CI 红）──
// 按 contract() 声明面（src/plugin.rs DOKODEMO_CLAUSES / DOKODEMO_NOT_APPLICABLE）：
// 跑 conn_id(3) / log(10) / pool(4)；跳过 deadline(2)——dokodemo 无协议握手
// （连接建立即按 rewrite/followRedirect 目标转发，无首包 deadline 面）；
// log(11) N/A → secrets 表传空（仍断 target/四元组）。

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
    l4_run_conn_id_fixture("dokodemo-door");
}

/// 夹具三（坑约束 10；11 N/A → secrets 表传空）：target 前缀
/// `xray_frame::dokodemo-door` + conn_id/stage/peer/dest 四元组齐全。
/// 无认证凭据/密钥面，无掩码断言项。
#[test]
fn l4_log_fields() {
    xray_frame::assert_log_fields!(
        domain: "dokodemo-door",
        conn_id: 0x1234u128,
        stage: "Accept",
        peer: "203.0.113.7:443",
        dest: "example.com:80",
    );
}

/// 夹具四（坑约束 4/9）：借 N 还 N → PoolMetrics 配平（borrowed=0 且零溢出丢弃）。
/// 条款 4 适用（PM 拍板 2026-10-24：转发数据面走 buf，受 BufferPool 接缝约束）。
#[test]
fn l4_pool_discipline() {
    let pool = xray_frame::pool::ManagedBufferPool::new(xray_frame::pool::XrayBufPool::new(8, 8), 8, 8);
    xray_frame::assert_pool_discipline!(pool, 4);
}
