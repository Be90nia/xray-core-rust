//! Socks 协议插件（P2 批次 A 首族，统一迁移契约模板 A1–A12）。
//!
//! 五层映射：
//! - **L1**：[`SocksPlugin`] 实现必选方法集（name/version/deps/contract/
//!   lifecycle/build），缺一编译不过。
//! - **L2**：能力只经 [`PluginContext`] 取——build 期 `ctx.section()` 读 per-plugin 段（缺段
//!   fail-fast，坑约束 7 装配半边）。
//! - **L3**：无裸能力（无 println/裸 spawn/裸 sleep/Instant）。
//! - **L4**：`assert_plugin_contract!(SocksPlugin)`（tests/plugin_contract.rs）。
//! - **L5**：装配门——缺段 → build `Err` → 整链 fail-visible （tests/plugin_contract.rs 装配负向）。
//!
//! wire 零改动：`protocol.rs` / `udp.rs` 编解码与 UDP associate 语义一行不动；
//! 握手/认证/请求解析仍走 [`SocksServer`]（既有 `InboundHandler` 实现原样
//! 复用，插件只负责配置注入与构建）。
//!
//! udf 判定（A7，非通用件）：SOCKS5 wire/认证语义是协议方向件——按
//! CLAUDE.md §3.5.3「带领域方向的件不进 udf-frame」，留主仓最近消费方；
//! 无提炼候选。

use std::sync::OnceLock;

use xray_common::net::address::Address;
use xray_frame::{
    ClauseId, Lifecycle, Plugin, PluginContext, PluginContract, PluginDep, PluginError,
};

use crate::{
    config::{AuthType, ServerConfig},
    server::SocksServer,
};

/// 通用条款适用子集（socks 12 条全适用：有密码认证 → 1/11 适用；有握手 →
/// 2 适用；缓冲/任务/停机/配置/错误/有界/日志/热路径照常）。
static SOCKS_CLAUSES: &[ClauseId] = &[
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

/// 协议专属条款（差异表 §2.2 第 5 行：u16-u8-boundary-explicit 的 socks 变体）。
static SOCKS_EXTRA: &[(&str, &str)] =
    &[("SOCKS-B1", "SOCKS5 地址/端口长度字段必须显式边界检查，禁饱和截断")];

static SOCKS_CONTRACT: PluginContract =
    PluginContract { clauses: SOCKS_CLAUSES, extra: SOCKS_EXTRA, not_applicable: &[] };

static SOCKS_LIFECYCLE: SocksLifecycle = SocksLifecycle;

/// Socks 协议插件（L1 必选方法集全量）。
///
/// `build(ctx)` 从 per-plugin 段（`inbounds[]/outbounds[]` 内
/// `protocol == "socks"` 的元素）解析 `settings` → [`ServerConfig`] 并持有；
/// 入站 handler 经 [`inbound_handler`](SocksPlugin::inbound_handler) 由插件
/// 产出（tag 属实例注册期信息，不在 build 期定）。
#[derive(Debug, Default)]
pub struct SocksPlugin {
    /// build 期解析产物（装配根单线程 build → OnceLock 单写安全）。
    config: OnceLock<ServerConfig>,
}

impl SocksPlugin {
    /// build 产物观察面；build 前调用 → `Err`（fail-visible）。
    pub fn built_config(&self) -> Result<&ServerConfig, PluginError> {
        self.config.get().ok_or_else(|| {
            PluginError::Other("socks plugin not built yet (build must run first)".into())
        })
    }

    /// 插件产出：入站 handler（`InboundHandler` 实现与行为不变，
    /// [`SocksServer::new`] 即构建接缝——server.rs 零 diff）。
    pub fn inbound_handler(&self, tag: &str) -> Result<SocksServer, PluginError> {
        Ok(SocksServer::new(tag, self.built_config()?.clone()))
    }
}

impl Plugin for SocksPlugin {
    fn name(&self) -> &'static str {
        "socks"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn deps(&self) -> &'static [PluginDep] {
        &[]
    }

    fn contract(&self) -> &PluginContract {
        &SOCKS_CONTRACT
    }

    fn lifecycle(&self) -> &dyn Lifecycle {
        &SOCKS_LIFECYCLE
    }

    fn build(&self, ctx: &mut PluginContext) -> Result<(), PluginError> {
        let config = parse_server_section(ctx.section()?)?;
        self.config
            .set(config)
            .map_err(|_| PluginError::Other("socks plugin built twice (assembly bug)".into()))?;
        Ok(())
    }
}

/// Socks 生命周期三相：插件级无在途异步任务 / 无外部资源，三相直通。
/// 连接级 accept loop 的托管（坑约束 5/6 运行时半边）属 [`SocksServer`]
/// 实例面（既有行为，close = abort；FxScope/ShutdownCoordinator 接线随
/// P3 入口收口统一迁移）。
pub struct SocksLifecycle;

impl Lifecycle for SocksLifecycle {
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

/// per-plugin 段 → [`ServerConfig`]。
///
/// 同规 xray-core `inbound.rs::parse_socks_server_config`（权威生产解析），
/// 字段对齐 Go `infra/conf/socks.go::SocksServerConfig`：
/// `{"auth":"password","accounts":[{"user":"u","pass":"p"}],"udp":true,
/// "userLevel":0,"ip":"127.0.0.1"}`。`accounts` 在场则覆盖 `users`
/// （Go socks.go:54-56）；`ip` 仅收字符串形态（IPv4 → IPv6 → 域名回落），
/// 未配置时 address 保持 None（socks 侧回退 127.0.0.1，既有默认行为）。
/// 与 xray-core 解析面的收敛属 P3 入口收口，此处不回头改 core。
fn parse_server_section(section: &serde_json::Value) -> Result<ServerConfig, PluginError> {
    let settings = section.get("settings").unwrap_or(section);
    let mut cfg = ServerConfig::default();
    if settings.get("auth").and_then(|x| x.as_str()) == Some("password") {
        cfg.auth_type = AuthType::Password;
    }
    // accounts 在场则覆盖 users（Go socks.go:54-56）。
    if let Some(users) =
        settings.get("accounts").or_else(|| settings.get("users")).and_then(|x| x.as_array())
    {
        for u in users {
            let user = u.get("user").and_then(|x| x.as_str()).unwrap_or("");
            let pass = u.get("pass").and_then(|x| x.as_str()).unwrap_or("");
            cfg.accounts.insert(user.to_string(), pass.to_string());
        }
    }
    cfg.udp_enabled = settings.get("udp").and_then(|x| x.as_bool()).unwrap_or(false);
    cfg.user_level = settings.get("userLevel").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
    if let Some(ip) = settings.get("ip").and_then(|x| x.as_str()) {
        cfg.address = Some(proto_ip_or_domain(parse_address_str(ip)));
    }
    Ok(cfg)
}

/// 字符串解析为 [`Address`]：IPv4 → IPv6 → 域名（同规 xray-core
/// `inbound.rs:1443` parse_address_str）。
fn parse_address_str(s: &str) -> Address {
    if let Ok(v4) = s.parse::<std::net::Ipv4Addr>() {
        Address::IPv4(v4)
    } else if let Ok(v6) = s.parse::<std::net::Ipv6Addr>() {
        Address::IPv6(v6)
    } else {
        Address::Domain(s.to_owned())
    }
}

/// [`Address`] → proto `IpOrDomain`（xray-core 同款转形）。
fn proto_ip_or_domain(addr: Address) -> xray_proto::xray::common::net::IpOrDomain {
    use xray_proto::xray::common::net::ip_or_domain::Address as ProtoAddress;
    let address = match addr {
        Address::IPv4(ip) => ProtoAddress::Ip(ip.octets().to_vec()),
        Address::IPv6(ip) => ProtoAddress::Ip(ip.octets().to_vec()),
        Address::Domain(d) => ProtoAddress::Domain(d),
    };
    xray_proto::xray::common::net::IpOrDomain { address: Some(address) }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn section_password_auth_maps_to_password() {
        let section = json!({"protocol": "socks", "settings": {"auth": "password"}});
        let parsed = parse_server_section(&section).expect("password auth");
        assert_eq!(parsed.auth_type, AuthType::Password);
    }

    #[test]
    fn section_accounts_override_users() {
        // Go socks.go:54-56：accounts 在场则覆盖 users。
        let section = json!({
            "settings": {
                "auth": "password",
                "users": [{"user": "bob", "pass": "p2"}],
                "accounts": [{"user": "alice", "pass": "p1"}]
            }
        });
        let parsed = parse_server_section(&section).expect("accounts override users");
        assert!(parsed.has_account("alice", "p1"));
        assert!(!parsed.has_account("bob", "p2"));
    }

    #[test]
    fn section_users_only_when_no_accounts() {
        let section = json!({
            "settings": {
                "auth": "password",
                "users": [{"user": "bob", "pass": "p2"}]
            }
        });
        let parsed = parse_server_section(&section).expect("users fallback");
        assert!(parsed.has_account("bob", "p2"));
    }

    #[test]
    fn section_udp_and_user_level() {
        let section = json!({"settings": {"udp": true, "userLevel": 3}});
        let parsed = parse_server_section(&section).expect("udp + userLevel");
        assert!(parsed.udp_enabled);
        assert_eq!(parsed.user_level, 3);
    }

    #[test]
    fn section_ip_v4_v6_and_domain_shapes() {
        let v4 = parse_server_section(&json!({"settings": {"ip": "127.0.0.1"}})).expect("v4");
        assert!(v4.address.is_some(), "IPv4 → proto Ip");

        let v6 = parse_server_section(&json!({"settings": {"ip": "::1"}})).expect("v6");
        assert!(v6.address.is_some(), "IPv6 → proto Ip");

        let domain = parse_server_section(&json!({"settings": {"ip": "relay.example.com"}}))
            .expect("domain");
        assert!(domain.address.is_some(), "非 IP 字符串 → proto Domain（消费侧回退 127.0.0.1）");
    }

    #[test]
    fn section_empty_defaults() {
        let section = json!({"protocol": "socks"});
        let parsed = parse_server_section(&section).expect("no settings → default");
        assert_eq!(parsed, ServerConfig::default());
    }
}
