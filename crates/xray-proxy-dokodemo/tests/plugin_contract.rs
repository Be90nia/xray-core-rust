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

/// 契约面内容断言：适用子集 8 条（差异表 §2.2 第 7 行 3,5,6,7,8,9,10,12）、
/// 2/11 N/A + 非空理由、DKD-TPROXY 协议专属、协议名 `dokodemo-door`。
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
        ClauseId::SpawnManaged,
        ClauseId::StopRegistered,
        ClauseId::ConfigSectionOnly,
        ClauseId::ErrorClassifiedNoPanicEscape,
        ClauseId::BoundedResources,
        ClauseId::LogDiscipline,
        ClauseId::HotPathFreeze,
    ];
    assert_eq!(contract.clauses.len(), expected.len(), "适用子集 8 条");
    for clause in expected {
        assert!(contract.clauses.contains(clause), "缺条款 {clause:?}");
    }

    assert_eq!(contract.not_applicable.len(), 2, "2/11 N/A（差异表 §2.2 第 7 行）");
    let na: Vec<ClauseId> = contract.not_applicable.iter().map(|(c, _)| *c).collect();
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
