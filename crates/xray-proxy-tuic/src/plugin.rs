//! TUIC 协议插件（P2 批次 D，统一迁移契约模板）。
//!
//! 五层映射：
//! - **L1**：[`TuicPlugin`] 实现必选方法集（name/version/deps/contract/
//!   lifecycle/build），缺一编译不过。
//! - **L2**：能力只经 [`PluginContext`] 取——build 期 `ctx.section()` 读 per-plugin 段（缺段
//!   fail-fast，坑约束 7 装配半边）。
//! - **L3**：无裸能力（无 println/裸 spawn/裸 sleep/Instant）。
//! - **L4**：`assert_plugin_contract!(TuicPlugin)`（tests/plugin_contract.rs）。
//! - **L5**：装配门——缺段 / 坏 uuid / CC 白名单外 / brutal 缺带宽 / PEM 解析失败 → build `Err` →
//!   整链 fail-visible（tests/plugin_contract.rs 装配负向）。
//!
//! wire 零改动：`protocol/` / `udp.rs` / `pool.rs` / `inbound.rs` 编解码与数据面
//! 一行不动；QUIC 入站行为仍走 [`TuicInboundHandler`]（既有 `InboundHandler`
//! 实现原样复用，插件只负责配置注入与构建）。协议专属条款两条**只登记**：
//! `TUIC-FRAG-U16` 的 packet.rs:67 饱和截断是存量违规点，本单禁修（另单）；
//! `TUIC-OWNPOOL` 的池管理面接线属 P3（池内实现红线禁动）。
//!
//! udf 判定（A7，非通用件）：TUIC v5 wire/QUIC 装配是协议方向件——按
//! CLAUDE.md §3.5.3「带领域方向的件不进 udf-frame」，留主仓最近消费方；
//! 无提炼候选。

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::OnceLock,
};

use xray_frame::{
    ClauseId, Lifecycle, Plugin, PluginContext, PluginContract, PluginDep, PluginError,
};

use crate::{
    client::CongestionControl,
    inbound::{TuicInboundConfig, TuicInboundHandler},
};

/// 通用条款适用子集（tuic 12 条全适用：有 uuid/password 认证 → 1/11 适用；
/// QUIC 握手 → 2 适用；缓冲/任务/停机/配置/错误/有界/日志/热路径照常）。
static TUIC_CLAUSES: &[ClauseId] = &[
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

/// 协议专属条款（差异表 §2.2 第 13 行：分片饱和截断登记 + 自有池管理面约束）。
static TUIC_EXTRA: &[(&str, &str)] = &[
    (
        "TUIC-FRAG-U16",
        "protocol/packet.rs:67 的 unwrap_or(u16::MAX) 是现存违规点，禁在此路径新增饱和截断（存量修复另单）",
    ),
    ("TUIC-OWNPOOL", "自有连接池必须接 PoolBase 管理面且有界；池内实现禁动（管理面套壳）"),
];

static TUIC_CONTRACT: PluginContract =
    PluginContract { clauses: TUIC_CLAUSES, extra: TUIC_EXTRA, not_applicable: &[] };

static TUIC_LIFECYCLE: TuicLifecycle = TuicLifecycle;

/// TUIC 协议插件（L1 必选方法集全量）。
///
/// `build(ctx)` 从 per-plugin 段（`inbounds[]/outbounds[]` 内
/// `protocol == "tuic"` 的元素）解析 `settings` + 段级 `listen`/`port`/
/// `streamSettings` → [`TuicInboundConfig`] 并持有；入站 handler 经
/// [`inbound_handler`](TuicPlugin::inbound_handler) 由插件产出（tag 属实例
/// 注册期信息，不在 build 期定）。
#[derive(Debug, Default)]
pub struct TuicPlugin {
    /// build 期解析产物（装配根单线程 build → OnceLock 单写安全）。
    config: OnceLock<TuicInboundConfig>,
}

impl TuicPlugin {
    /// build 产物观察面；build 前调用 → `Err`（fail-visible）。
    pub fn built_config(&self) -> Result<&TuicInboundConfig, PluginError> {
        self.config.get().ok_or_else(|| {
            PluginError::Other("tuic plugin not built yet (build must run first)".into())
        })
    }

    /// 插件产出：入站 handler（`InboundHandler` 实现与行为不变，
    /// [`TuicInboundHandler::new`] 即构建接缝——inbound.rs 零 diff）。
    pub fn inbound_handler(&self, tag: &str) -> Result<TuicInboundHandler, PluginError> {
        TuicInboundHandler::new(tag, self.built_config()?.clone())
            .map_err(|e| PluginError::Other(Box::new(e)))
    }
}

impl Plugin for TuicPlugin {
    fn name(&self) -> &'static str {
        "tuic"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn deps(&self) -> &'static [PluginDep] {
        &[]
    }

    fn contract(&self) -> &PluginContract {
        &TUIC_CONTRACT
    }

    fn lifecycle(&self) -> &dyn Lifecycle {
        &TUIC_LIFECYCLE
    }

    fn build(&self, ctx: &mut PluginContext) -> Result<(), PluginError> {
        let config = parse_tuic_section(ctx.section()?)?;
        self.config
            .set(config)
            .map_err(|_| PluginError::Other("tuic plugin built twice (assembly bug)".into()))?;
        Ok(())
    }
}

/// TUIC 生命周期三相：插件级无在途异步任务 / 无外部资源，三相直通。
/// 连接级 QUIC accept loop 的托管（坑约束 5/6 运行时半边）属
/// [`TuicInboundHandler`] 实例面（既有行为，close = slot abort；
/// FxScope/ShutdownCoordinator 接线随 P3 入口收口统一迁移）。自有
/// [`QuinnConnectionPool`](crate::pool::QuinnConnectionPool) 的管理面接线
/// （TUIC-OWNPOOL：PoolBase 套壳）同属 P3；池内实现红线禁动。
pub struct TuicLifecycle;

impl Lifecycle for TuicLifecycle {
    fn init(&self, _ctx: &PluginContext) -> Result<(), PluginError> {
        Ok(())
    }

    fn start(&self, _ctx: &PluginContext) -> Result<(), PluginError> {
        Ok(())
    }

    fn stop(&self) -> Result<(), PluginError> {
        Ok(())
    }
}

/// per-plugin 段 → [`TuicInboundConfig`]。
///
/// 同规 xray-core `inbound.rs::parse_tuic_inbound_settings`（权威生产解析），
/// 字段对齐官方 tuic-server：`{"uuid":"...","password":"...",
/// "serverName":"...","certificate":"<PEM>","certificateKey":"<PEM>",
/// "congestion_control":"cubic","brutal_up_bps":10485760}`（缺省 rcgen 自签、
/// CC 缺省 cubic、hysteria_brutal 必须 brutal_up_bps > 0）。段级
/// `listen`/`port` 拼装 bind_addr（同规 `parse_listen_addr`）；sockopt 经
/// `StreamSettings::from_json(section.streamSettings)`（生产
/// `parse_tuic_inbound_config` 同构）。与 xray-core 解析面的收敛属 P3 入口
/// 收口，此处不回头改 core。
fn parse_tuic_section(section: &serde_json::Value) -> Result<TuicInboundConfig, PluginError> {
    let settings = section.get("settings").unwrap_or(section);
    let uuid_str = settings
        .get("uuid")
        .and_then(|x| x.as_str())
        .ok_or_else(|| PluginError::Other("tuic: missing uuid".into()))?;
    let uuid = uuid::Uuid::parse_str(uuid_str)
        .map_err(|e| PluginError::Other(format!("tuic invalid uuid: {e}").into()))?;
    let password = settings
        .get("password")
        .and_then(|x| x.as_str())
        .ok_or_else(|| PluginError::Other("tuic: missing password".into()))?;
    let server_name = settings.get("serverName").and_then(|x| x.as_str()).unwrap_or("tuic");
    let port = parse_port(section)?;
    let bind_addr =
        parse_bind_addr(section.get("listen").and_then(|x| x.as_str()).unwrap_or(""), port)?;
    // certificate/certificateKey（PEM 内容）→ 真实证书；缺省 rcgen 自签（handler start 期）。
    let cert_der = match settings.get("certificate").and_then(|x| x.as_str()) {
        Some(pem) => Some(pem_first_cert_der(pem)?),
        None => None,
    };
    let key_der = match settings.get("certificateKey").and_then(|x| x.as_str()) {
        Some(pem) => Some(pem_key_der(pem)?),
        None => None,
    };
    // 服务端 CC：官方 tuic-server 缺省 "cubic"，白名单与带宽校验同生产解析。
    let congestion_name =
        settings.get("congestion_control").and_then(|x| x.as_str()).unwrap_or("cubic");
    let congestion_control = CongestionControl::from_name(congestion_name)
        .map(Some)
        .ok_or_else(|| {
            PluginError::Other(format!(
                "invalid tuic inbound congestion_control: {congestion_name} (valid: bbr, cubic, new_reno, hysteria_bbr, hysteria_brutal)"
            )
            .into())
        })?;
    let brutal_up_bps = settings.get("brutal_up_bps").and_then(|x| x.as_u64()).unwrap_or(0);
    if congestion_control == Some(CongestionControl::HysteriaBrutal) && brutal_up_bps == 0 {
        return Err(PluginError::Other(
            "tuic inbound congestion_control=hysteria_brutal requires brutal_up_bps (> 0)".into(),
        ));
    }
    // QUIC 端点缓冲：streamSettings.sockopt 的 receiveBufferSize/sendBufferSize
    // （缺省 = QUIC 系端点默认 8MB 下限语义，bind_udp_endpoint）。
    let sockopt = xray_transport::dialer::StreamSettings::from_json(section.get("streamSettings"))
        .socket_options();
    Ok(TuicInboundConfig {
        listen: bind_addr,
        server_name: server_name.to_owned(),
        uuid,
        password: password.to_owned(),
        cert_der,
        key_der,
        congestion_control,
        brutal_up_bps,
        sockopt,
    })
}

/// 段级 `port` → `u16`：数字形态走 `try_from` 显式边界检查（禁饱和截断，
/// TUIC-FRAG-U16 同款纪律）；字符串收单值形态；其余 fail-fast。
fn parse_port(section: &serde_json::Value) -> Result<u16, PluginError> {
    let port =
        section.get("port").ok_or_else(|| PluginError::Other("tuic: missing port".into()))?;
    if let Some(n) = port.as_u64() {
        return u16::try_from(n).map_err(|_| {
            PluginError::Other(format!("tuic parse addr: port {n} exceeds u16").into())
        });
    }
    port.as_str().and_then(|s| s.parse::<u16>().ok()).ok_or_else(|| {
        PluginError::Other(format!("tuic parse addr: unsupported port shape: {port}").into())
    })
}

/// listen 串 + port → [`SocketAddr`]（同规 xray-core `inbound.rs:4583`
/// parse_listen_addr：空/`::` → V6 未指定、`0.0.0.0` → V4 未指定、裸 IPv6
/// 补方括号）。
fn parse_bind_addr(listen: &str, port: u16) -> Result<SocketAddr, PluginError> {
    let addr = listen.trim();
    if addr.is_empty() || addr == "::" {
        return Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port));
    }
    if addr == "0.0.0.0" {
        return Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port));
    }
    if let Ok(sa) = addr.parse::<SocketAddr>() {
        return Ok(sa);
    }
    // 裸 IPv6 须加方括号：字面拼接 "::1:18923" 会被解析器当作整体 IPv6 拒绝。
    let candidate = if addr.parse::<Ipv6Addr>().is_ok() {
        format!("[{addr}]:{port}")
    } else {
        format!("{addr}:{port}")
    };
    candidate
        .parse()
        .map_err(|e| PluginError::Other(format!("tuic parse addr {addr:?}: {e}").into()))
}

/// PEM 文本 → 首张证书 DER（tuic certificate 键；同规 xray-core
/// `tuic_pem_first_cert_der`）。
fn pem_first_cert_der(pem: &str) -> Result<Vec<u8>, PluginError> {
    let mut rd = std::io::BufReader::new(pem.as_bytes());
    match rustls_pemfile::certs(&mut rd).next() {
        None => Err(PluginError::Other("tuic certificate: no cert in PEM".into())),
        Some(Ok(cert)) => Ok(cert.to_vec()),
        Some(Err(e)) => Err(PluginError::Other(format!("tuic certificate PEM: {e}").into())),
    }
}

/// PEM 文本 → 私钥 DER（tuic certificateKey 键；PKCS8/SEC1/RSA 皆可；同规
/// xray-core `tuic_pem_key_der`）。
fn pem_key_der(pem: &str) -> Result<Vec<u8>, PluginError> {
    let mut rd = std::io::BufReader::new(pem.as_bytes());
    match rustls_pemfile::private_key(&mut rd) {
        Ok(Some(key)) => Ok(key.secret_der().to_vec()),
        Ok(None) => Err(PluginError::Other("tuic certificateKey: no key in PEM".into())),
        Err(e) => Err(PluginError::Other(format!("tuic certificateKey PEM: {e}").into())),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const TEST_UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    fn section(settings: serde_json::Value) -> serde_json::Value {
        json!({ "protocol": "tuic", "listen": "127.0.0.1", "port": 18443, "settings": settings })
    }

    #[test]
    fn section_defaults_official_server() {
        // 官方 tuic-server 缺省：CC=cubic（→ Option 内显式值）、serverName="tuic"、
        // 证书缺省 rcgen 自签（cert/key DER 皆 None）。
        let parsed = parse_tuic_section(&section(json!({ "uuid": TEST_UUID, "password": "pw" })))
            .expect("defaults");
        assert_eq!(parsed.listen, "127.0.0.1:18443".parse().unwrap());
        assert_eq!(parsed.server_name, "tuic");
        assert_eq!(parsed.congestion_control, Some(CongestionControl::Cubic));
        assert_eq!(parsed.brutal_up_bps, 0);
        assert!(parsed.cert_der.is_none() && parsed.key_der.is_none());
    }

    #[test]
    fn section_listen_empty_falls_back_to_v6_unspecified() {
        let mut sect = section(json!({ "uuid": TEST_UUID, "password": "pw" }));
        sect["listen"] = json!("");
        let parsed = parse_tuic_section(&sect).expect("empty listen");
        assert_eq!(parsed.listen, "[::]:18443".parse().unwrap(), "同规 parse_listen_addr 空串语义");
    }

    #[test]
    fn section_full_fields_with_pem_cert() {
        // 正向 PEM：rcgen 自签对（与 inbound.rs start 期生成同款库）。
        let key_pair = rcgen::KeyPair::generate().expect("keypair");
        let mut params =
            rcgen::CertificateParams::new(vec!["relay.example.com".to_owned()]).expect("params");
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.distinguished_name.push(rcgen::DnType::CommonName, "relay.example.com");
        let cert = params.self_signed(&key_pair).expect("self signed");
        let parsed = parse_tuic_section(&section(json!({
            "uuid": TEST_UUID,
            "password": "pw",
            "serverName": "relay.example.com",
            "certificate": cert.pem(),
            "certificateKey": key_pair.serialize_pem(),
            "congestion_control": "hysteria_brutal",
            "brutal_up_bps": 10485760
        })))
        .expect("full fields");
        assert!(parsed.cert_der.is_some(), "PEM 证书 → DER");
        assert!(parsed.key_der.is_some(), "PEM 私钥 → DER");
        assert_eq!(parsed.congestion_control, Some(CongestionControl::HysteriaBrutal));
        assert_eq!(parsed.brutal_up_bps, 10485760);
    }

    #[test]
    fn section_missing_uuid_or_password_fails() {
        let err = parse_tuic_section(&section(json!({ "password": "pw" })))
            .expect_err("missing uuid must fail");
        assert!(err.to_string().contains("missing uuid"), "实际: {err}");

        let err = parse_tuic_section(&section(json!({ "uuid": TEST_UUID })))
            .expect_err("missing password must fail");
        assert!(err.to_string().contains("missing password"), "实际: {err}");
    }

    #[test]
    fn section_bad_uuid_and_congestion_fail() {
        let err = parse_tuic_section(&section(json!({ "uuid": "not-a-uuid", "password": "pw" })))
            .expect_err("bad uuid must fail");
        assert!(err.to_string().contains("invalid uuid"), "实际: {err}");

        let err = parse_tuic_section(&section(json!(
            { "uuid": TEST_UUID, "password": "pw", "congestion_control": "bogus" }
        )))
        .expect_err("unknown CC must fail");
        assert!(err.to_string().contains("invalid tuic inbound congestion_control"), "实际: {err}");
    }

    #[test]
    fn section_brutal_requires_bps() {
        let err = parse_tuic_section(&section(json!(
            { "uuid": TEST_UUID, "password": "pw", "congestion_control": "hysteria_brutal" }
        )))
        .expect_err("brutal without bps must fail");
        assert!(err.to_string().contains("requires brutal_up_bps"), "实际: {err}");
    }

    #[test]
    fn section_port_overflow_rejected_without_saturation() {
        let mut sect = section(json!({ "uuid": TEST_UUID, "password": "pw" }));
        sect["port"] = json!(70_000);
        let err = parse_tuic_section(&sect).expect_err("u16 overflow must fail, not saturate");
        assert!(err.to_string().contains("exceeds u16"), "实际: {err}");
    }

    #[test]
    fn section_bad_pem_fails_visible() {
        let err = parse_tuic_section(&section(json!(
            { "uuid": TEST_UUID, "password": "pw", "certificate": "!!!not-pem!!!" }
        )))
        .expect_err("bad PEM must fail");
        assert!(err.to_string().contains("tuic certificate"), "错误必须标明证书解析失败: {err}");
    }
}
