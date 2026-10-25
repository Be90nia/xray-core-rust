//! Hysteria 协议插件（P2 批次 D，统一迁移契约模板 A1–A12）。
//!
//! 五层映射：
//! - **L1**：[`HysteriaPlugin`] 实现必选方法集（name/version/deps/contract/
//!   lifecycle/build），缺一编译不过。
//! - **L2**：能力只经 [`PluginContext`] 取——build 期 `ctx.section()` 读 per-plugin 段 （缺段
//!   fail-fast，坑约束 7 装配半边）。
//! - **L3**：无裸能力（无 println/裸 spawn/裸 sleep/Instant）。
//! - **L4**：`assert_plugin_contract!(HysteriaPlugin)`（tests/plugin_contract.rs）。
//! - **L5**：装配门——缺段 / 面歧义（`users` 与 `address` 并存）/ settings 非法 → build `Err` → 整链
//!   fail-visible（tests/plugin_contract.rs 装配负向）。
//!
//! wire 零改动：`protocol.rs`（UdpMessage/Defragger 帧编解码）、`dispatcher.rs`
//! （QUIC stream/datagram pump 桥）、`inbound.rs` / `outbound.rs`（两 Handler）、
//! `config.rs`（配置类型）一行不动。插件只做配置注入与构建接缝：
//! - 入站面：settings → [`HysteriaInboundConfig`]（既有构造 + 既有 `validate`）；
//! - 出站面：settings → [`HysteriaConfig`] （既有构造 + 既有 `validate`）；
//! - handler 产出需运行期句柄（QUIC transport / listener factory / dispatcher）， build
//!   期不可得——由装配侧携句柄调用 [`outbound_handler`](HysteriaPlugin::outbound_handler) /
//!   [`inbound_handler`](HysteriaPlugin::inbound_handler)（P3 入口收口接线； 句柄借用纪律见
//!   HY-QUINN 条款）。
//!
//! 段 schema（P3-2 配置解析接注册链前的壳层自持形态）：入站
//! `{"bind","users":[{"email","auth","level"}],"serverName","alpn","udpIdleTimeout",
//! "masquerade"}`；出站 `{"address","port","auth","serverName","alpn","udpIdleTimeout"}`
//! （`address`=host、`port`=独立字段，Go `infra/conf/hysteria.go:13-17`；拨号目标
//! 由二者合成 `host:port`）；另有 Rust 方言 `{"servers":[{...}]}` 数组形态
//! （`servers[0]` 选择，收口 [`crate::servers::select_server`]，与生产面
//! `xray-core` `parse_hysteria_config` 同语义）。
//! transport 层深键（quicParams / masquerade 展开 / brutal 带宽）属 xray-conf
//! 解析面，随 P3-2 收口，本壳不解析。
//!
//! udf 判定（A7，非通用件）：QUIC/UDP relay/认证帧是协议方向件——按 CLAUDE.md
//! §3.5.3「带领域方向的件不进 udf-frame」，留主仓最近消费方；无提炼候选。

use std::sync::{Arc, OnceLock};

use xray_frame::{
    ClauseId, Lifecycle, Plugin, PluginContext, PluginContract, PluginDep, PluginError,
};
use xray_transport_hysteria::{dialer::HysteriaTransport, hub::HysteriaListenerFactory};

use crate::{
    config::{HysteriaConfig, HysteriaInboundConfig, HysteriaUser},
    inbound::{HysteriaInboundHandler, TcpDispatcher},
    outbound::HysteriaOutboundHandler,
};

/// 通用条款适用子集（hysteria **12 条全适用**，差异表 §2.2 第 11 行；表注
/// 「2 待定：QUIC 握手有 deadline 需求」= 有需求即适用，无确凿 N/A 证据——
/// QUIC 握手在（auth 帧/HTTP/3 auth），有认证 → 1/11；有握手 → 2；
/// dispatcher 64KiB duplex/recv 缓冲 → 4；auth token 属密钥 → 11；其余照常）。
static HYSTERIA_CLAUSES: &[ClauseId] = &[
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

/// 协议专属条款（差异表 §2.2 第 11 行 hysteria-quinn-borrow-guard）。
static HYSTERIA_EXTRA: &[(&str, &str)] =
    &[("HY-QUINN", "quinn Connection 句柄禁跨线程裸转移；插件生命周期内持句柄必须登记停机")];

static HYSTERIA_CONTRACT: PluginContract =
    PluginContract { clauses: HYSTERIA_CLAUSES, extra: HYSTERIA_EXTRA, not_applicable: &[] };

static HYSTERIA_LIFECYCLE: HysteriaLifecycle = HysteriaLifecycle;

/// 段解析产物：一份 hysteria 段只可能是入站（`users`）或出站（`address` /
/// `servers[]`）之一（Go `proxy/hysteria` 两侧配置面互斥）；两键并存/全缺均硬错，
/// 禁静默择一。
#[derive(Debug)]
pub enum HysteriaFace {
    /// 入站服务端配置（[`HysteriaInboundHandler::with_inbound_config`] 消费）。
    Inbound(Arc<HysteriaInboundConfig>),
    /// 出站客户端配置（[`HysteriaOutboundHandler::new`] / dial 闭包消费）。
    Outbound(Arc<HysteriaConfig>),
}

/// Hysteria 协议插件（L1 必选方法集全量）。
///
/// `build(ctx)` 从 per-plugin 段（`outbounds[]/inbounds[]` 内
/// `protocol == "hysteria"` 的元素）解析 `settings` → [`HysteriaFace`] 并持有；
/// handler 由装配侧携运行期句柄经 [`inbound_handler`](HysteriaPlugin::inbound_handler)
/// / [`outbound_handler`](HysteriaPlugin::outbound_handler) 产出（tag/policy 属
/// 实例注册期信息，不在 build 期定）。
#[derive(Debug, Default)]
pub struct HysteriaPlugin {
    /// build 期解析产物（装配根单线程 build → OnceLock 单写安全）。
    face: OnceLock<HysteriaFace>,
}

impl HysteriaPlugin {
    fn built_face(&self) -> Result<&HysteriaFace, PluginError> {
        self.face.get().ok_or_else(|| {
            PluginError::Other("hysteria plugin not built yet (build must run first)".into())
        })
    }

    /// build 产物观察面（入站配置）；build 前或出站段 → `Err`（fail-visible）。
    pub fn built_inbound(&self) -> Result<&Arc<HysteriaInboundConfig>, PluginError> {
        match self.built_face()? {
            HysteriaFace::Inbound(config) => Ok(config),
            HysteriaFace::Outbound(_) => Err(PluginError::Other(
                "hysteria plugin built for outbound (no inbound config)".into(),
            )),
        }
    }

    /// build 产物观察面（出站配置）；build 前或入站段 → `Err`（fail-visible）。
    pub fn built_outbound(&self) -> Result<&Arc<HysteriaConfig>, PluginError> {
        match self.built_face()? {
            HysteriaFace::Outbound(config) => Ok(config),
            HysteriaFace::Inbound(_) => Err(PluginError::Other(
                "hysteria plugin built for inbound (no outbound config)".into(),
            )),
        }
    }

    /// 插件产出：出站 handler（transport 句柄 = QUIC+H3 运行期注入，P3 收口接线；
    /// HY-QUINN 条款约束句柄借用与停机登记纪律）。
    pub fn outbound_handler(
        &self,
        tag: &str,
        transport: Arc<dyn HysteriaTransport>,
    ) -> Result<HysteriaOutboundHandler, PluginError> {
        HysteriaOutboundHandler::new(tag, self.built_outbound()?.as_ref().clone(), transport)
            .map_err(|e| PluginError::Other(format!("hysteria outbound handler: {e}").into()))
    }

    /// 插件产出：入站 handler（服务端多用户模式；factory/dispatcher 运行期注入，
    /// P3 收口接线）。单 auth 客户端监听模式不经插件段（属 transport listen 装配面）。
    pub fn inbound_handler(
        &self,
        tag: &str,
        factory: Arc<dyn HysteriaListenerFactory>,
        dispatcher: Option<Arc<dyn TcpDispatcher>>,
    ) -> Result<HysteriaInboundHandler, PluginError> {
        HysteriaInboundHandler::with_inbound_config(
            tag,
            self.built_inbound()?.as_ref().clone(),
            factory,
            dispatcher,
        )
        .map_err(|e| PluginError::Other(format!("hysteria inbound handler: {e}").into()))
    }
}

impl Plugin for HysteriaPlugin {
    fn name(&self) -> &'static str {
        "hysteria"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn deps(&self) -> &'static [PluginDep] {
        &[]
    }

    fn contract(&self) -> &PluginContract {
        &HYSTERIA_CONTRACT
    }

    fn lifecycle(&self) -> &dyn Lifecycle {
        &HYSTERIA_LIFECYCLE
    }

    fn build(&self, ctx: &mut PluginContext) -> Result<(), PluginError> {
        let face = parse_section(ctx.section()?)?;
        self.face
            .set(face)
            .map_err(|_| PluginError::Other("hysteria plugin built twice (assembly bug)".into()))?;
        Ok(())
    }
}

/// Hysteria 生命周期三相：插件级无在途异步任务 / 无外部资源，三相直通。
/// 连接级 QUIC accept/pump 任务的托管（坑约束 5/6 运行时半边）属
/// `HysteriaInboundHandler`（listener slot + accept task）/ `ClientManager`
/// 实例面（既有行为；FxScope/ShutdownCoordinator 接线随 P3 入口收口统一迁移）。
pub struct HysteriaLifecycle;

impl Lifecycle for HysteriaLifecycle {
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

/// per-plugin 段 → 面判定 + 解析。入站/出站互斥：`users` 在场（非 null）→ 入站；
/// `address` 非空或 `servers[]` 在场 → 出站；并存/全缺硬错（fail-visible，面歧义
/// 禁静默择一）。
fn parse_section(section: &serde_json::Value) -> Result<HysteriaFace, PluginError> {
    let settings = section.get("settings").unwrap_or(section);
    let has_users = settings.get("users").is_some_and(|u| !u.is_null());
    let has_address =
        settings.get("address").and_then(|a| a.as_str()).is_some_and(|a| !a.is_empty());
    let has_servers = settings.get("servers").and_then(serde_json::Value::as_array).is_some();
    match (has_users, has_address || has_servers) {
        (true, true) => Err(PluginError::Other(
            "hysteria settings ambiguous: users and address/servers both present".into(),
        )),
        (true, false) => parse_inbound_config(settings).map(|c| HysteriaFace::Inbound(Arc::new(c))),
        (false, true) => {
            parse_outbound_config(settings).map(|c| HysteriaFace::Outbound(Arc::new(c)))
        },
        (false, false) => Err(PluginError::Other(
            "hysteria settings: neither users (inbound) nor address/servers (outbound)".into(),
        )),
    }
}

/// 入站 settings → [`HysteriaInboundConfig`]（既有 `validate` 收口）。
///
/// `bind` 缺失/空硬错（装配期 fail-visible）；`users[].auth` 缺失/空硬错
/// （Go `account.Account{auth}` 必填，同 `failed to get hysteria user` 拒启语义）；
/// 重复 email 由既有 `validate` 硬错。`masquerade` 空串 = NotFound 语义原样透传。
fn parse_inbound_config(
    settings: &serde_json::Value,
) -> Result<HysteriaInboundConfig, PluginError> {
    let bind = settings.get("bind").and_then(|b| b.as_str()).filter(|b| !b.is_empty()).ok_or_else(
        || PluginError::Other("hysteria inbound settings: bind missing/empty".into()),
    )?;
    let mut config = HysteriaInboundConfig::new(bind);
    if let Some(sni) = str_field(settings, "serverName") {
        config = config.with_server_name(sni);
    }
    if let Some(alpn) = alpn_field(settings)? {
        config = config.with_alpn(alpn);
    }
    for user in settings.get("users").and_then(|u| u.as_array()).into_iter().flatten() {
        let email = user.get("email").and_then(|e| e.as_str()).unwrap_or("");
        let auth = user.get("auth").and_then(|a| a.as_str()).filter(|a| !a.is_empty()).ok_or_else(
            || PluginError::Other(format!("hysteria user {email}: auth missing/empty").into()),
        )?;
        let level = user.get("level").and_then(serde_json::Value::as_u64).unwrap_or(0) as u32;
        config = config.with_user(HysteriaUser::new(email, auth).with_level(level));
    }
    if let Some(secs) = settings.get("udpIdleTimeout").and_then(serde_json::Value::as_u64) {
        config = config.with_udp_idle_timeout(secs);
    }
    if let Some(masq) = str_field(settings, "masquerade") {
        config = config.with_masq_type(masq);
    }
    config
        .validate()
        .map_err(|e| PluginError::Other(format!("hysteria inbound config: {e}").into()))?;
    Ok(config)
}

/// 出站 settings → [`HysteriaConfig`]。
///
/// 服务器选择（扁平 / `servers[]` 双形态）收口 [`crate::servers::select_server`]
/// ——与生产面 `xray-core` `parse_hysteria_config` 同一语义的共享实现（错误文案
/// 逐字一致，对拍口径）。既有 `validate` 收口；auth 空 = 客户端将被服务端拒，
/// 同 Go dial 配置形态，不在此加码。
fn parse_outbound_config(settings: &serde_json::Value) -> Result<HysteriaConfig, PluginError> {
    let sel = crate::servers::select_server(settings).map_err(|e| PluginError::Other(e.into()))?;
    // with_server_name 无条件应用（生产消费形态 `arm_builders/outbound.rs` 同型）；
    // 缺省时 sel.server_name = address host，与 `HysteriaConfig::new` 自推导等值。
    let mut config =
        HysteriaConfig::new(sel.server_addr, sel.auth).with_server_name(sel.server_name);
    if let Some(alpn) = alpn_field(settings)? {
        config = config.with_alpn(alpn);
    }
    if let Some(secs) = settings.get("udpIdleTimeout").and_then(serde_json::Value::as_u64) {
        config = config.with_udp_idle_timeout(secs);
    }
    config
        .validate()
        .map_err(|e| PluginError::Other(format!("hysteria outbound config: {e}").into()))?;
    Ok(config)
}

/// 非空字符串字段观察（缺失/空 → None）。
fn str_field(settings: &serde_json::Value, key: &str) -> Option<String> {
    settings.get(key).and_then(|v| v.as_str()).filter(|s| !s.is_empty()).map(str::to_owned)
}

/// `alpn` 字段 → `Vec<String>`（缺省 → None；在场必须为字符串数组，元素非字符串
/// 硬错）。显式空数组交由既有 `validate` 的 alpn-empty 拒启。
fn alpn_field(settings: &serde_json::Value) -> Result<Option<Vec<String>>, PluginError> {
    match settings.get("alpn") {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(items) => items
            .as_array()
            .ok_or_else(|| {
                PluginError::Other("hysteria settings: alpn must be a string array".into())
            })?
            .iter()
            .map(|item| {
                item.as_str().map(str::to_owned).ok_or_else(|| {
                    PluginError::Other("hysteria settings: alpn must be a string array".into())
                })
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Some),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn outbound_settings_parse_defaults() {
        let face = parse_section(
            &json!({ "settings": { "address": "us1.example.com", "port": 443, "auth": "tok" } }),
        )
        .expect("outbound face");
        let config = match face {
            HysteriaFace::Outbound(config) => config,
            HysteriaFace::Inbound(_) => panic!("expected outbound face"),
        };
        assert_eq!(config.server_addr, "us1.example.com:443", "address:port 合成（Go 语义）");
        assert_eq!(config.server_name, "us1.example.com", "SNI 默认 = address host 部分");
        assert_eq!(config.auth, "tok");
        assert_eq!(config.alpn, vec!["hysteria".to_string(), "h3".to_string()]);
        assert_eq!(config.udp_idle_timeout_secs, HysteriaConfig::DEFAULT_UDP_IDLE_TIMEOUT);
    }

    /// 缺 `port` 硬错（Go `infra/conf/hysteria.go:16` 独立 port 字段；缺端口的
    /// 拨号目标无意义——装配期 fail-visible，文案与生产面 `parse_hysteria_config`
    /// 逐字一致）。
    #[test]
    fn outbound_settings_missing_port_fails_fast() {
        let err = parse_section(&json!({ "settings": { "address": "us1.example.com" } }))
            .expect_err("port missing must fail");
        assert!(err.to_string().contains("missing servers[0].port"), "实际: {err}");
    }

    /// `servers[]` 多服务器形态：构造成功 + `servers[0]` 选择（与生产面一致）。
    #[test]
    fn outbound_settings_servers_array_selects_first() {
        let face = parse_section(&json!({ "settings": {
            "servers": [
                { "address": "a.example.com", "port": 443, "auth": "tok-a", "sni": "a-sni.example.com" },
                { "address": "b.example.com", "port": 8443, "auth": "tok-b" }
            ],
            "udpIdleTimeout": 45
        } }))
        .expect("servers face");
        let config = match face {
            HysteriaFace::Outbound(config) => config,
            HysteriaFace::Inbound(_) => panic!("expected outbound face"),
        };
        assert_eq!(config.server_addr, "a.example.com:443", "servers[0] 选择（生产同序）");
        assert_eq!(config.auth, "tok-a", "auth 别名照常解析");
        assert_eq!(config.server_name, "a-sni.example.com", "sni 别名解析");
        assert_eq!(config.udp_idle_timeout_secs, 45, "段级可选键照常生效");
    }

    /// `servers[]` 缺字段 / 空数组 → fail-visible（文案与生产面一致）。
    #[test]
    fn outbound_settings_servers_array_invalid_fails_visible() {
        for (settings, expect) in [
            (json!({ "servers": [] }), "servers array is empty"),
            (json!({ "servers": [{ "port": 443 }] }), "missing servers[0].address"),
            (json!({ "servers": [{ "address": "a.com" }] }), "missing servers[0].port"),
            (
                json!({ "servers": [{ "address": "a.com", "port": 1 }], "version": 1 }),
                "not supported (only version 2)",
            ),
        ] {
            let err = parse_section(&json!({ "settings": settings }))
                .expect_err("invalid servers[] must fail");
            assert!(err.to_string().contains(expect), "实际: {err}");
        }
    }

    /// `servers[]` 在场即出站面标记（无扁平 address 也可判定）；
    /// users + servers 并存 = 面歧义硬错。
    #[test]
    fn face_detection_accepts_servers_marker() {
        let face = parse_section(&json!(
            { "settings": { "servers": [{ "address": "a.com", "port": 443 }] } }
        ))
        .expect("servers-only outbound face");
        assert!(matches!(face, HysteriaFace::Outbound(_)), "实际: {face:?}");

        let err = parse_section(&json!(
            { "settings": { "users": [{ "auth": "t" }], "servers": [] } }
        ))
        .expect_err("users+servers must be ambiguous");
        assert!(err.to_string().contains("hysteria settings"), "实际: {err}");
    }

    #[test]
    fn inbound_settings_parse_users_and_dup_email_fails() {
        let face = parse_section(&json!({
            "settings": {
                "bind": "0.0.0.0:443",
                "users": [{ "email": "a@b", "auth": "tok1", "level": 2 }],
                "udpIdleTimeout": 30,
                "masquerade": ""
            }
        }))
        .expect("inbound face");
        let config = match face {
            HysteriaFace::Inbound(config) => config,
            HysteriaFace::Outbound(_) => panic!("expected inbound face"),
        };
        assert_eq!(config.bind_addr, "0.0.0.0:443");
        assert_eq!(config.users.len(), 1);
        assert_eq!(config.users[0].email, "a@b");
        assert_eq!(config.users[0].auth, "tok1");
        assert_eq!(config.users[0].level, 2);
        assert_eq!(config.udp_idle_timeout_secs, 30);
        assert_eq!(config.masq_type, "", "masquerade 空串 = NotFound 语义原样透传");

        let dup = parse_section(&json!({
            "settings": {
                "bind": "0.0.0.0:443",
                "users": [
                    { "email": "a@b", "auth": "t1" },
                    { "email": "a@b", "auth": "t2" }
                ]
            }
        }))
        .expect_err("dup email must fail validate");
        assert!(dup.to_string().contains("duplicate user email"), "实际: {dup}");
    }

    #[test]
    fn face_detection_failures_are_explicit() {
        for settings in [
            json!({}),                                               // 全缺
            json!({ "users": [{ "auth": "t" }], "address": "h:1" }), // 并存歧义
        ] {
            let err = parse_section(&json!({ "settings": settings }))
                .expect_err("ambiguous/empty settings must fail");
            assert!(err.to_string().contains("hysteria settings"), "实际: {err}");
        }
    }

    #[test]
    fn user_without_auth_fails_fast() {
        let err = parse_section(&json!({
            "settings": { "bind": "0.0.0.0:443", "users": [{ "email": "a@b" }] }
        }))
        .expect_err("auth missing must fail");
        assert!(err.to_string().contains("auth missing"), "实际: {err}");
    }

    #[test]
    fn non_string_alpn_fails_fast() {
        let err = parse_section(&json!({
            "settings": { "address": "h", "port": 1, "alpn": ["hysteria", 3] }
        }))
        .expect_err("non-string alpn must fail");
        assert!(err.to_string().contains("alpn must be a string array"), "实际: {err}");
    }
}
