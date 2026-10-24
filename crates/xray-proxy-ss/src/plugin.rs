//! Shadowsocks 协议插件（P2 补课：最小 `impl Plugin`，解锁 L4 契约对拍）。
//!
//! 五层映射：
//! - **L1**：[`SsPlugin`] 实现必选方法集（name/version/deps/contract/
//!   lifecycle/build），缺一编译不过。
//! - **L2**：能力只经 [`PluginContext`] 取——build 期 `ctx.section()` 读 per-plugin 段（缺段
//!   fail-fast，坑约束 7 装配半边）。
//! - **L3**：无裸能力（无 println/裸 spawn/裸 sleep/Instant）。
//! - **L4**：`assert_plugin_contract!(SsPlugin)`（tests/plugin_contract.rs）。
//! - **L5**：装配门——缺段 / 密码 / PSK 缺失 → build `Err` → 整链 fail-visible
//!   （tests/plugin_contract.rs 装配负向）。
//!
//! wire 零改动：`protocol.rs` / `ss2022/` 编解码与 `inbound.rs` / `dispatcher.rs`
//! 一行不动。插件只做配置解析与构建接缝：
//! - 出站面复用 crate 既有 [`parse_ss_config`] + [`make_ss_dial_fn`]（生产同源， ss2022
//!   出站分支同在 parse_ss_config 内）；
//! - 入站面复用 crate 既有 [`SsInbound`] / [`Ss2022Inbound`] / [`MultiUserInbound`] /
//!   [`RelayInbound`] 构造函数（生产构造原样，无第二份 handler 构造）；
//! - 入站解析语义同规 `xray-core` 的 `parse_ss_inbound_config` /
//!   `parse_ss2022_inbound_config`（权威生产解析，`pub(crate)` 不可跨 crate 直 调；与 core
//!   解析面的收敛属 P3 入口收口，此处不回头改 core）。
//!
//! udf 判定（A7，非通用件）：ss AEAD/ss2022 wire 是协议方向件——按 CLAUDE.md
//! §3.5.3「带领域方向的件不进 udf-frame」，留主仓最近消费方；无提炼候选。

use std::sync::{Arc, OnceLock};

use xray_common::net::address::Address;
use xray_frame::{
    ClauseId, Lifecycle, Plugin, PluginContext, PluginContract, PluginDep, PluginError,
};

use crate::{
    config::{CipherType, MemoryAccount},
    dispatcher::{SsOutboundConfig, make_ss_dial_fn, parse_ss_config},
    inbound::SsInbound,
    psk_from_base64,
    ss2022::{MultiUserInbound, RelayDestination, RelayInbound, Ss2022Inbound, Ss2022User},
    validator::MemoryUser,
};

/// 通用条款适用子集（12 条全适用，差异表同 trojan/vmess 行：密码/PSK 认证 →
/// 1/11 适用；SS 请求头/salt 握手 → 2 适用；AEAD chunk 分帧/缓冲 → 4 照常）。
static SS_CLAUSES: &[ClauseId] = &[
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

/// 协议专属条款（B6 豁免清单点名的 ss2022 wire 语义，bd 7dce）。
static SS_EXTRA: &[(&str, &str)] = &[(
    "SS-2022-WIRE",
    "ss2022 分帧/响应头/subkey 重计数以 sing 对端读路径为准；流解析必须容忍 TCP 重分段（禁单次 Read 语义）",
)];

static SS_CONTRACT: PluginContract =
    PluginContract { clauses: SS_CLAUSES, extra: SS_EXTRA, not_applicable: &[] };

static SS_LIFECYCLE: SsLifecycle = SsLifecycle;

/// 段解析产物：一份 ss 段只可能是入站（legacy AEAD / ss2022 单用户、多用户、
/// 中继）或出站（`servers` 数组 / 扁平 `address`）之一（Go
/// `infra/conf/shadowsocks.go` 两侧配置面互斥；`PluginContext::section()` 先
/// outbounds 后 inbounds 取首个 `protocol == "shadowsocks"` 元素）。
pub enum SsFace {
    /// legacy AEAD 入站（`serve_ss` / transport 入站消费）。
    LegacyInbound(Arc<SsInbound>),
    /// ss2022 单用户入站。
    Ss2022(Arc<Ss2022Inbound>),
    /// ss2022 多用户入站。
    Ss2022Multi(Arc<MultiUserInbound>),
    /// ss2022 中继入站。
    Ss2022Relay(Arc<RelayInbound>),
    /// 出站配置（[`make_ss_dial_fn`] 消费）。
    Outbound(Arc<SsOutboundConfig>),
}

/// Shadowsocks 协议插件（L1 必选方法集全量）。
///
/// `build(ctx)` 从 per-plugin 段（`inbounds[]/outbounds[]` 内
/// `protocol == "shadowsocks"` 的元素）解析 `settings` 并持有；出站拨号闭包经
/// [`dial_fn`](SsPlugin::dial_fn)、全量产物经
/// [`built_face`](SsPlugin::built_face) 由插件产出（tag/listen 属实例注册期
/// 信息，不在 build 期定）。
#[derive(Default)]
pub struct SsPlugin {
    /// build 期解析产物（装配根单线程 build → OnceLock 单写安全）。
    face: OnceLock<SsFace>,
}

impl SsPlugin {
    fn built_face(&self) -> Result<&SsFace, PluginError> {
        self.face.get().ok_or_else(|| {
            PluginError::Other("ss plugin not built yet (build must run first)".into())
        })
    }

    /// build 产物观察面（入站/出站五形态判别）；build 前调用 → `Err`
    /// （fail-visible，不 panic）。
    pub fn face(&self) -> Result<&SsFace, PluginError> {
        self.built_face()
    }

    /// build 产物观察面（出站配置）；build 前或入站段 → `Err`（fail-visible）。
    pub fn built_outbound(&self) -> Result<&Arc<SsOutboundConfig>, PluginError> {
        match self.built_face()? {
            SsFace::Outbound(config) => Ok(config),
            SsFace::LegacyInbound(_)
            | SsFace::Ss2022(_)
            | SsFace::Ss2022Multi(_)
            | SsFace::Ss2022Relay(_) => {
                Err(PluginError::Other("ss plugin built for inbound (no outbound config)".into()))
            },
        }
    }

    /// 插件产出：出站拨号闭包（[`make_ss_dial_fn`] 既有构造，wire 不变）。
    pub fn dial_fn(&self) -> Result<xray_app_dispatcher::default::DialFn, PluginError> {
        Ok(make_ss_dial_fn(Arc::clone(self.built_outbound()?)))
    }
}

impl Plugin for SsPlugin {
    fn name(&self) -> &'static str {
        "shadowsocks"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn deps(&self) -> &'static [PluginDep] {
        &[]
    }

    fn contract(&self) -> &PluginContract {
        &SS_CONTRACT
    }

    fn lifecycle(&self) -> &dyn Lifecycle {
        &SS_LIFECYCLE
    }

    fn build(&self, ctx: &mut PluginContext) -> Result<(), PluginError> {
        let face = parse_section(ctx.section()?)?;
        self.face
            .set(face)
            .map_err(|_| PluginError::Other("ss plugin built twice (assembly bug)".into()))?;
        Ok(())
    }
}

/// SS 生命周期三相：插件级无在途异步任务 / 无外部资源，三相直通。
/// 连接级 accept/pump 任务的托管（坑约束 5/6 运行时半边）属 `serve_ss` /
/// ss2022 serve 实例面（既有行为；FxScope/ShutdownCoordinator 接线随 P3 入口
/// 收口统一迁移）。
pub struct SsLifecycle;

impl Lifecycle for SsLifecycle {
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

/// per-plugin 段 → 面判定 + 解析。出站判据：`servers` 键在场（parse_ss_config
/// 形 1）或扁平 `address` 非空（形 2，v2rayN/旧 v2ray-core 形态）；否则入站。
fn parse_section(section: &serde_json::Value) -> Result<SsFace, PluginError> {
    let settings = section.get("settings").unwrap_or(section);
    let flat_outbound =
        settings.get("address").and_then(|a| a.as_str()).is_some_and(|a| !a.is_empty());
    if settings.get("servers").is_some() || flat_outbound {
        let bytes = serde_json::to_vec(settings).map_err(|e| {
            PluginError::Other(format!("ss outbound settings re-encode: {e}").into())
        })?;
        return parse_ss_config(&bytes)
            .map(|config| SsFace::Outbound(Arc::new(config)))
            .map_err(|e| PluginError::Other(format!("ss outbound settings: {e}").into()));
    }
    parse_inbound(settings)
}

/// `settings` → 入站面。语义同规 xray-core `parse_ss_inbound_config`（权威生产
/// 解析）：`method` 以 `2022-blake3-` 开头 → ss2022 面；否则 legacy AEAD——
/// `users`/`clients` 数组 → [`SsInbound::with_users`]（users 主键，Go
/// shadowsocks.go:46-47），扁平 `password` → 单用户 [`SsInbound::new`]。
fn parse_inbound(settings: &serde_json::Value) -> Result<SsFace, PluginError> {
    let method = settings.get("method").and_then(|x| x.as_str()).unwrap_or("aes-128-gcm");
    if method.starts_with("2022-blake3-") {
        return parse_ss2022_inbound(method, settings);
    }
    if let Some(clients) =
        settings.get("users").or_else(|| settings.get("clients")).and_then(|c| c.as_array())
    {
        let mut users = Vec::with_capacity(clients.len());
        for c in clients {
            users.push(parse_legacy_user(c)?);
        }
        if users.is_empty() {
            return Err(PluginError::Other("ss inbound: no users".into()));
        }
        return Ok(SsFace::LegacyInbound(Arc::new(SsInbound::with_users(users))));
    }
    let password = settings
        .get("password")
        .and_then(|x| x.as_str())
        .ok_or_else(|| PluginError::Other("ss inbound: missing password".into()))?;
    let account = legacy_account(password, method)?;
    Ok(SsFace::LegacyInbound(Arc::new(SsInbound::new(account, "u@ss.local"))))
}

/// legacy 用户数组项 → [`MemoryUser`]（逐用户 `method`，缺省 `aes-128-gcm`；
/// 同规 xray-core parse_ss_inbound_config，level 不在该解析面消费）。
fn parse_legacy_user(c: &serde_json::Value) -> Result<MemoryUser, PluginError> {
    let password = c.get("password").and_then(|x| x.as_str()).unwrap_or("");
    let email = c.get("email").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let method = c.get("method").and_then(|x| x.as_str()).unwrap_or("aes-128-gcm");
    Ok(MemoryUser::new(email, legacy_account(password, method)?))
}

/// legacy 密码 + cipher 名 → [`MemoryAccount`]（同规 xray-core 的 ProtoAccount
/// 路径；cipher 未知硬错，禁静默回落）。
fn legacy_account(password: &str, method: &str) -> Result<MemoryAccount, PluginError> {
    let cipher = CipherType::from_name(method)
        .ok_or_else(|| PluginError::Other(format!("unsupported ss cipher: {method}").into()))?;
    MemoryAccount::from_proto(&xray_proto::xray::proxy::shadowsocks::Account {
        password: password.to_string(),
        cipher_type: cipher.as_i32(),
        iv_check: false,
    })
    .map_err(|e| PluginError::Other(format!("ss account parse: {e}").into()))
}

/// ss2022 入站解析。形态判定对齐 Go `buildShadowsocks2022`（infra/conf/
/// shadowsocks.go:113-177，同规 xray-core parse_ss2022_inbound_config）：
/// `destinations[]`（Rust 旧形）或 `users[]`/`clients[]` 首元素带 `address`
/// （Go 形 relay，:130）→ 中继；数组无 `address` → 多用户；无数组 → 单用户。
/// `users` 主键，`clients` 旧名回退（:46-47,54-56）。
fn parse_ss2022_inbound(method: &str, settings: &serde_json::Value) -> Result<SsFace, PluginError> {
    let server_psk = settings
        .get("password")
        .and_then(|x| x.as_str())
        .ok_or_else(|| PluginError::Other("ss2022 inbound: missing server PSK".into()))?;

    // 中继模式：destinations 数组（Rust 旧形：server/server_port 键）。
    if let Some(dests) = settings.get("destinations").and_then(|d| d.as_array()) {
        let mut destinations = Vec::with_capacity(dests.len());
        for d in dests {
            let email = d.get("email").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let level = d.get("level").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
            let addr_str = d.get("server").and_then(|x| x.as_str()).unwrap_or("127.0.0.1");
            let port = d.get("server_port").and_then(|x| x.as_u64()).unwrap_or(0) as u16;
            destinations.push(RelayDestination {
                key: parse_psk(d.get("password").and_then(|x| x.as_str()).unwrap_or(""))?,
                address: parse_address_str(addr_str),
                port,
                email,
                level,
            });
        }
        if destinations.is_empty() {
            return Err(PluginError::Other("ss2022 relay: no destinations".into()));
        }
        return RelayInbound::new(method, server_psk, destinations)
            .map(|relay| SsFace::Ss2022Relay(Arc::new(relay)))
            .map_err(|e| PluginError::Other(format!("ss2022 relay: {e}").into()));
    }

    // users/clients 双读（Go shadowsocks.go:46-47,54-56）。
    let users_arr =
        settings.get("users").or_else(|| settings.get("clients")).and_then(|c| c.as_array());

    if let Some(user_list) = users_arr {
        // 中继模式（Go 形）：首元素带 address → address/port 主键，
        // server/server_port 旧名回退（Go shadowsocks.go:130 判定 + :162-175）。
        if user_list.first().is_some_and(|u| u.get("address").and_then(|x| x.as_str()).is_some()) {
            let mut destinations = Vec::with_capacity(user_list.len());
            for u in user_list {
                let email = u.get("email").and_then(|x| x.as_str()).unwrap_or("").to_string();
                let level = u.get("level").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
                let addr_str = u
                    .get("address")
                    .or_else(|| u.get("server"))
                    .and_then(|x| x.as_str())
                    .unwrap_or("127.0.0.1");
                let port = u
                    .get("port")
                    .or_else(|| u.get("server_port"))
                    .and_then(|x| x.as_u64())
                    .unwrap_or(0) as u16;
                destinations.push(RelayDestination {
                    key: parse_psk(u.get("password").and_then(|x| x.as_str()).unwrap_or(""))?,
                    address: parse_address_str(addr_str),
                    port,
                    email,
                    level,
                });
            }
            if destinations.is_empty() {
                return Err(PluginError::Other("ss2022 relay: no destinations".into()));
            }
            return RelayInbound::new(method, server_psk, destinations)
                .map(|relay| SsFace::Ss2022Relay(Arc::new(relay)))
                .map_err(|e| PluginError::Other(format!("ss2022 relay: {e}").into()));
        }

        // 多用户模式：数组无 address（Go shadowsocks.go:130 → MultiUserServerConfig）。
        let mut users = Vec::with_capacity(user_list.len());
        for c in user_list {
            let email = c.get("email").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let level = c.get("level").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
            users.push(Ss2022User {
                email,
                level,
                psk: parse_psk(c.get("password").and_then(|x| x.as_str()).unwrap_or(""))?,
            });
        }
        if users.is_empty() {
            return Err(PluginError::Other("ss2022 multi: no users".into()));
        }
        return MultiUserInbound::new(method, server_psk, users)
            .map(|multi| SsFace::Ss2022Multi(Arc::new(multi)))
            .map_err(|e| PluginError::Other(format!("ss2022 multi: {e}").into()));
    }

    // 单用户模式。
    let single = Ss2022Inbound::new(method, server_psk, "u@ss2022.local")
        .map_err(|e| PluginError::Other(format!("ss2022 single: {e}").into()))?;
    Ok(SsFace::Ss2022(Arc::new(single)))
}

/// base64 PSK → 原始字节（透传 [`psk_from_base64`] 错误）。
fn parse_psk(b64: &str) -> Result<Vec<u8>, PluginError> {
    psk_from_base64(b64).map_err(|e| PluginError::Other(format!("ss2022 PSK: {e}").into()))
}

/// 字符串解析为 [`Address`]：IPv4 → IPv6 → 域名（同规 xray-core
/// `parse_address_str`，Go `net.ParseIP` 轻量版）。
fn parse_address_str(s: &str) -> Address {
    if let Ok(v4) = s.parse::<std::net::Ipv4Addr>() {
        Address::IPv4(v4)
    } else if let Ok(v6) = s.parse::<std::net::Ipv6Addr>() {
        Address::IPv6(v6)
    } else {
        Address::Domain(s.to_string())
    }
}
