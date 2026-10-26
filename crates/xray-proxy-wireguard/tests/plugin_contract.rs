//! P2 批次验收：L4 契约夹具（12 条全适用 + WG-TUN-FROZEN 协议专属条款）+
//! 装配链 register → build → bring_up → shutdown（`is_clean()`）+ 缺段
//! fail-fast。
//!
//! （注册不进 xray-frame——xray-frame 禁依赖协议 crate，拍板 P2.1；同
//! blackhole P1-7 / tuic 批次 D 的做法，注册写在协议 crate 自己的装配链里。）

use std::sync::Arc;

use serde_json::json;
use xray_app_dispatcher::{DispatchHandler, default::PinFuture};
use xray_common::net::destination::Destination;
use xray_features::inbound::InboundHandler;
use xray_frame::{
    ClauseId, Plugin, PluginDep, PluginError,
    assembly::{Framework, FrameworkOptions},
    assert_plugin_contract,
};
use xray_proxy_wireguard::WireguardPlugin;
use xray_transport::link::Link;

fn framework_options() -> FrameworkOptions {
    FrameworkOptions { registry_cap: 8, id_fingerprint: Some(1), shutdown_timeout: None }
}

/// 段形态：inbounds[] 按 protocol 路由（坑约束 7；wireguard 生产形态入站/出站
/// 皆可，settings 级 `port` 随 settings 进 build 期读（UDP 监听端口，缺省
/// 51820；同规 xray-core `parse_wireguard_inbound_config`））。
fn wg_section_config(mut settings: serde_json::Value, port: u16) -> serde_json::Value {
    settings["port"] = json!(port);
    json!({ "inbounds": [
        {
            "protocol": "wireguard",
            "tag": "wg-in",
            "settings": settings
        }
    ] })
}

fn hex_key(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

/// 最小服务端段：1 peer + keepAlive + reserved（keys 走 hex 直通形态）。
fn server_settings() -> serde_json::Value {
    json!({
        "secretKey": hex_key(0x11),
        "peers": [{ "publicKey": hex_key(0x22), "endpoint": "203.0.113.7:51820", "keepAlive": 25 }],
        "mtu": 1420,
        "reserved": [2, 5, 1]
    })
}

#[test]
fn contract_macro_holds_for_wireguard() {
    assert_plugin_contract!(WireguardPlugin);
}

/// 契约面内容断言：12 条通用条款全适用（无 N/A）、WG-TUN-FROZEN 协议专属
/// （差异表 §2.2 第 14 行 + 派单契约）。
#[test]
fn contract_surface_declares_all_applicable_and_extra() {
    let plugin = WireguardPlugin::default();
    let contract = plugin.contract();

    assert_eq!(plugin.name(), "wireguard");
    assert_eq!(plugin.version(), "0.1.0");
    let deps: &[PluginDep] = plugin.deps();
    assert!(deps.is_empty(), "wireguard 无依赖插件");

    assert_eq!(contract.clauses.len(), 12, "wireguard 12 条全适用");
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

    assert_eq!(contract.extra.len(), 1, "协议专属条款一条（数据面冻结）");
    assert_eq!(contract.extra[0].0, "WG-TUN-FROZEN");
    assert!(!contract.extra[0].1.is_empty());
}

/// 完整装配链：段路由解析 → bring_up 三相 → 停机报告干净；
/// build 产物逐字段核对（hex 密钥直通、keepAlive 字符串化、allowedIPs 缺省
/// 全路由、mtu/reserved/port）。
#[tokio::test]
async fn wireguard_assembles_bring_up_and_shuts_down_clean() {
    let plugin = Arc::new(WireguardPlugin::default());
    let mut framework = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(wg_section_config(server_settings(), 18443))
        .register(Arc::clone(&plugin) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect("build phase");
    assert!(!framework.is_running(), "build 成功但未 bring_up，不得误报运行态");

    framework.bring_up().expect("bring_up: init/start 三相");
    assert!(framework.is_running());

    let report = framework.shutdown().await;
    let stopped: Vec<&str> = report.per_component.iter().map(|o| o.name.as_str()).collect();
    assert_eq!(stopped, ["wireguard"], "stop 闭包必须按插件名注册进 ShutdownCoordinator");
    assert!(report.is_clean(), "健康链必须全 Stopped: {report:?}");

    let cfg = plugin.built_config().expect("built");
    assert_eq!(cfg.listen_port, 18443, "settings 级 port 显式");
    assert_eq!(cfg.device.secret_key, "11".repeat(32), "hex 私钥直通");
    assert_eq!(cfg.device.effective_mtu(), 1420);
    assert_eq!(cfg.device.reserved, vec![2, 5, 1]);
    let peer = &cfg.device.peers[0];
    assert_eq!(peer.public_key, "22".repeat(32));
    assert_eq!(peer.endpoint, "203.0.113.7:51820");
    assert_eq!(peer.keep_alive, "25", "KeepAlive → 十进制字符串（票 o7ns D1）");
    assert_eq!(
        peer.allowed_ips,
        vec!["0.0.0.0/0".to_string(), "::0/0".to_string()],
        "allowedIPs 字段缺失 → 全路由双栈（bd 7v0k①）"
    );
}

/// L5 装配门负向：缺段 fail-fast（坑约束 7 装配半边），
/// build 失败 → 无 Framework 产出（无半启动态）。
#[tokio::test]
async fn missing_section_fails_fast_at_build() {
    let err = Framework::builder(framework_options())
        .expect("registry cap")
        .register(Arc::new(WireguardPlugin::default()) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect_err("config 根无 wireguard 段必须 fail-fast");
    assert!(matches!(err, PluginError::Config(_)), "实际: {err}");
}

/// L5 装配门负向第二例：reserved 非 3 字节 → build `Err` fail-visible。
#[tokio::test]
async fn bad_reserved_fails_fast_at_build() {
    let settings = json!({ "secretKey": hex_key(0x11), "reserved": [1, 2] });
    let err = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(wg_section_config(settings, 51820))
        .register(Arc::new(WireguardPlugin::default()) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect_err("reserved 非 3 字节必须 fail-visible");
    assert!(err.to_string().contains("reserved"), "实际: {err}");
}

/// 入站 handler 由插件产出（构建接缝 = 既有 `WireguardInboundHandler::new`，
/// dispatch 注入同规 xray-core `inbound.rs` wireguard 臂；构造仅参数校验，
/// driver 启动仍走 start()——数据面行为不变，integration_wireguard_dataplane
/// 红线回归实测）。
#[tokio::test]
async fn inbound_handler_produced_by_plugin() {
    let plugin = Arc::new(WireguardPlugin::default());
    let framework = Framework::builder(framework_options())
        .expect("registry cap")
        .with_config(wg_section_config(server_settings(), 18443))
        .register(Arc::clone(&plugin) as Arc<dyn Plugin>)
        .expect("register")
        .build()
        .expect("build");

    let handler =
        plugin.inbound_handler("wg-in", Arc::new(NoopDispatch)).await.expect("handler 构建接缝");
    assert_eq!(InboundHandler::tag(&handler), "wg-in");
    assert_eq!(InboundHandler::port(&handler), 18443);

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
