//! Trojan 协议插件（P2 批次 B，统一迁移契约模板 A1–A12）。
//!
//! 五层映射：
//! - **L1**：[`TrojanPlugin`] 实现必选方法集（name/version/deps/contract/
//!   lifecycle/build），缺一编译不过。
//! - **L2**：能力只经 [`PluginContext`] 取——build 期 `ctx.section()` 读 per-plugin 段（缺段
//!   fail-fast，坑约束 7 装配半边）。
//! - **L3**：无裸能力（无 println/裸 spawn/裸 sleep/Instant）。
//! - **L4**：`assert_plugin_contract!(TrojanPlugin)`（tests/plugin_contract.rs）。
//! - **L5**：装配门——缺段 / fallback `dest` 缺失 → build `Err` → 整链 fail-visible
//!   （tests/plugin_contract.rs 装配负向）。
//!
//! wire 零改动：`protocol.rs` 编解码与 `fallback.rs` 分流决策树一行不动；
//! 握手/用户校验仍走 [`TrojanServer`]（既有 `InboundHandler` 实现原样复用，
//! 插件只负责配置注入与构建——[`TrojanServer::new`] + `with_fallbacks` 即
//! 接缝，server.rs 零 diff）。Trojan `flow` 已被 Go 移除（Go
//! infra/conf/trojan.go:134-136 服务端硬报错；Rust 生产 warn+忽略），插件
//! 同规 warn+忽略，勿复活。
//!
//! udf 判定（A7，非通用件）：trojan wire/认证/fallback 决策树是协议方向件
//! ——按 CLAUDE.md §3.5.3「带领域方向的件不进 udf-frame」，留主仓最近消费方；
//! 无提炼候选。

use std::sync::{Arc, OnceLock};

use xray_common::errors::removed_feature_message;
use xray_frame::{
    ClauseId, Lifecycle, Plugin, PluginContext, PluginContract, PluginDep, PluginError,
};

use crate::{
    config::MemoryAccount,
    fallback::{Fallback, FallbackPolicy},
    server::TrojanServer,
    validator::{MemoryUser, Validator},
};

/// 通用条款适用子集（trojan 12 条全适用，差异表 §2.2 第 3 行：有密码认证 →
/// 1/11 适用；有握手 → 2 适用；缓冲/任务/停机/配置/错误/有界/日志/热路径照常）。
static TROJAN_CLAUSES: &[ClauseId] = &[
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

/// 协议专属条款（差异表 §2.2 第 3 行：u16-u8-boundary-explicit 的 trojan 变体；
/// 存量违规点 protocol.rs:333 `unwrap_or(u16::MAX)` 已登记待修，本单不动）。
static TROJAN_EXTRA: &[(&str, &str)] = &[("TRJ-1", "u16/u8 边界必须显式检查禁饱和截断")];

static TROJAN_CONTRACT: PluginContract =
    PluginContract { clauses: TROJAN_CLAUSES, extra: TROJAN_EXTRA, not_applicable: &[] };

static TROJAN_LIFECYCLE: TrojanLifecycle = TrojanLifecycle;

/// Trojan 协议插件（L1 必选方法集全量）。
///
/// `build(ctx)` 从 per-plugin 段（`inbounds[]/outbounds[]` 内
/// `protocol == "trojan"` 的元素）解析 `settings` → [`Validator`] + fallback
/// 决策树并持有；入站 handler 经 [`inbound_handler`](TrojanPlugin::inbound_handler)
/// 由插件产出（tag 属实例注册期信息，不在 build 期定）。
#[derive(Debug, Default)]
pub struct TrojanPlugin {
    /// build 期解析产物（装配根单线程 build → OnceLock 单写安全）。
    validator: OnceLock<Arc<Validator>>,
    fallbacks: OnceLock<Option<Arc<FallbackPolicy>>>,
}

impl TrojanPlugin {
    /// build 产物观察面（Validator）；build 前调用 → `Err`（fail-visible）。
    pub fn built_validator(&self) -> Result<&Arc<Validator>, PluginError> {
        self.validator.get().ok_or_else(|| {
            PluginError::Other("trojan plugin not built yet (build must run first)".into())
        })
    }

    /// build 产物观察面（fallback 决策树；无 fallback 配置 → `None`）。
    pub fn built_fallbacks(&self) -> Result<&Option<Arc<FallbackPolicy>>, PluginError> {
        self.fallbacks.get().ok_or_else(|| {
            PluginError::Other("trojan plugin not built yet (build must run first)".into())
        })
    }

    /// 插件产出：入站 handler（`InboundHandler` 实现与行为不变，
    /// [`TrojanServer::new`] + `with_fallbacks` 即构建接缝——server.rs 零 diff）。
    pub fn inbound_handler(&self, tag: &str) -> Result<TrojanServer, PluginError> {
        let mut server = TrojanServer::new(tag, self.built_validator()?.clone());
        if let Some(policy) = self.built_fallbacks()?.clone() {
            server = server.with_fallbacks(policy);
        }
        Ok(server)
    }
}

impl Plugin for TrojanPlugin {
    fn name(&self) -> &'static str {
        "trojan"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn deps(&self) -> &'static [PluginDep] {
        &[]
    }

    fn contract(&self) -> &PluginContract {
        &TROJAN_CONTRACT
    }

    fn lifecycle(&self) -> &dyn Lifecycle {
        &TROJAN_LIFECYCLE
    }

    fn build(&self, ctx: &mut PluginContext) -> Result<(), PluginError> {
        let (validator, fallbacks) = parse_server_section(ctx.section()?)?;
        self.validator
            .set(validator)
            .map_err(|_| PluginError::Other("trojan plugin built twice (assembly bug)".into()))?;
        self.fallbacks
            .set(fallbacks)
            .map_err(|_| PluginError::Other("trojan plugin built twice (assembly bug)".into()))?;
        Ok(())
    }
}

/// Trojan 生命周期三相：插件级无在途异步任务 / 无外部资源，三相直通。
/// 连接级 accept loop 的托管（坑约束 5/6 运行时半边）属 [`TrojanServer`]
/// 实例面（既有行为，close = abort；FxScope/ShutdownCoordinator 接线随
/// P3 入口收口统一迁移）。
pub struct TrojanLifecycle;

impl Lifecycle for TrojanLifecycle {
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

/// per-plugin 段 → ([`Validator`], fallback 决策树)。
///
/// 同规 xray-core `inbound.rs::build_trojan_users` + `::build_trojan_fallbacks`
/// （权威生产解析），字段对齐 Go `infra/conf/trojan.go`：
/// `{"clients":[{"password":"p","email":"a@b","level":0}],"fallbacks":
/// [{"dest":80,"xver":0}]}`。`clients` 在场则覆盖 `users`（Go trojan.go:124-126）；
/// 带 `flow` 的 client 同规生产 warn+忽略（Go 已移除该字段，勿复活）。
/// fallback `dest` 形态推导同规生产：数字 → `localhost:N`；`/`/`@` 前缀 → unix
/// （`@@` 抽象套接字做 108 字节 NUL padding）；`host:port` → tcp；dest 缺失 →
/// 硬错（Go trojan.go:196-198）。与 xray-core 解析面的收敛属 P3 入口收口，
/// 此处不回头改 core。
fn parse_server_section(
    section: &serde_json::Value,
) -> Result<(Arc<Validator>, Option<Arc<FallbackPolicy>>), PluginError> {
    let settings = section.get("settings").unwrap_or(section);
    let validator = Arc::new(parse_users(settings));
    let fallbacks = parse_fallbacks(settings)?;
    Ok((validator, fallbacks))
}

/// `clients`/`users` → [`Validator`]（`clients` 在场则覆盖 `users`，Go
/// trojan.go:124-126）。重复用户 warn + skip（同规生产两个装配分支的语义）。
fn parse_users(settings: &serde_json::Value) -> Validator {
    let validator = Validator::new();
    let clients =
        settings.get("clients").or_else(|| settings.get("users")).and_then(|c| c.as_array());
    if let Some(clients) = clients {
        for c in clients {
            // Trojan Flow 已移除（Go infra/conf/trojan.go:134-136 服务端逐用户检查）。
            // 同规生产：warn + 忽略该字段继续建用户。
            if flow_removed_warning(c) {
                tracing::warn!("{}", removed_feature_message("Flow for Trojan", ""));
            }
            let password = c.get("password").and_then(|x| x.as_str()).unwrap_or("");
            let email = c.get("email").and_then(|x| x.as_str()).unwrap_or("");
            let level = c.get("level").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
            let user = MemoryUser::new(email, level, MemoryAccount::new(password));
            if let Err(e) = validator.add(user) {
                tracing::warn!(error = %e, "skip duplicate user during trojan inbound init");
            }
        }
    }
    validator
}

/// Trojan `flow` 字段已移除检测（同规 xray-core outbound.rs:1636
/// `trojan_flow_removed_warning`，Go infra/conf/trojan.go:74/:135——无迁移目标）。
fn flow_removed_warning(user: &serde_json::Value) -> bool {
    user.get("flow").and_then(|f| f.as_str()).is_some_and(|f| !f.is_empty())
}

/// `fallbacks` → 决策树；缺失/空数组 → `None`（无 fallback 直连路径）。
/// dest 形态推导与缺失硬错同规生产 `build_trojan_fallbacks`（Go trojan.go:151-198）。
fn parse_fallbacks(
    settings: &serde_json::Value,
) -> Result<Option<Arc<FallbackPolicy>>, PluginError> {
    let Some(fbs) = settings.get("fallbacks").and_then(|f| f.as_array()) else {
        return Ok(None);
    };
    let mut list = Vec::with_capacity(fbs.len());
    for fb in fbs {
        let name = fb.get("name").and_then(|x| x.as_str()).unwrap_or("").into();
        let alpn = fb.get("alpn").and_then(|x| x.as_str()).unwrap_or("").into();
        let path = fb.get("path").and_then(|x| x.as_str()).unwrap_or("").into();
        let xver = fb.get("xver").and_then(|x| x.as_u64()).unwrap_or(0);
        let mut dest = match fb.get("dest") {
            Some(serde_json::Value::Number(n)) => n.to_string(),
            Some(serde_json::Value::String(s)) => s.clone(),
            _ => String::new(),
        };
        let mut fb_type = fb.get("type").and_then(|x| x.as_str()).unwrap_or("").to_string();
        if fb_type.is_empty() && !dest.is_empty() {
            if dest == "serve-ws-none" {
                // Go trojan.go:178-179：内建 ws 服务标记，透传给 serve 侧。
            } else if dest.starts_with('/') || dest.starts_with('@') {
                fb_type = "unix".into();
                dest = apply_unix_abstract_padding(&dest);
            } else {
                if dest.parse::<i64>().is_ok() {
                    dest = format!("localhost:{dest}");
                }
                if looks_like_host_port(&dest) {
                    fb_type = "tcp".into();
                }
            }
        }
        if fb_type.is_empty() {
            return Err(PluginError::Other(
                r#"trojan fallbacks: please fill in a valid value for every "dest""#.into(),
            ));
        }
        list.push(Fallback { name, alpn, path, r#type: fb_type, dest, xver });
    }
    if list.is_empty() { Ok(None) } else { Ok(Some(FallbackPolicy::from_list(&list))) }
}

/// `@@` 抽象 unix 套接字路径的 108 字节 NUL padding（同规 xray-core
/// inbound.rs `apply_unix_abstract_padding`，Go trojan.go:196 `Dest[1:]`）。
fn apply_unix_abstract_padding(dest: &str) -> String {
    #[cfg(unix)]
    {
        // ponytail: hardcoded 108 对齐 syscall.RawSockaddrUnix.Path；改需联动内核常量。
        const UNIX_PATH_MAX: usize = 108;
        if dest.starts_with("@@") {
            let mut buf = [0u8; UNIX_PATH_MAX];
            let src = &dest.as_bytes()[1..]; // Go trojan.go:196 Dest[1:]: 跳过首个 @，保留第二个
            let copy_len = src.len().min(UNIX_PATH_MAX - 1);
            buf[1..1 + copy_len].copy_from_slice(&src[..copy_len]);
            // NUL 字节在 Rust String 中合法（`\0` 是 valid char），Linux 拨号时按
            // 首个 NUL 截断 abstract namespace path。
            return String::from_utf8_lossy(&buf).into_owned();
        }
    }
    dest.to_string()
}

/// `host:port` 形态判定（同规 xray-core inbound.rs `looks_like_host_port`，
/// Go `net.SplitHostPort` 轻量版）：host 非空、port 全数字非空；host 含裸冒号
/// 视为非法（方括号 IPv6 例外，`]` 结尾即合法）。
fn looks_like_host_port(s: &str) -> bool {
    match s.rsplit_once(':') {
        Some((h, p)) => {
            !h.is_empty()
                && !p.is_empty()
                && p.bytes().all(|b| b.is_ascii_digit())
                && (!h.contains(':') || h.ends_with(']'))
        },
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn clients_fill_validator() {
        let section = json!({
            "clients": [
                { "password": "pass-1", "email": "alice", "level": 2 },
                { "password": "pass-2" }
            ]
        });
        let (validator, fallbacks) = parse_server_section(&section).expect("parse");
        assert!(fallbacks.is_none(), "无 fallbacks 配置 → None");
        assert_eq!(validator.get_key_count(), 2, "key_hash 表计数（空 email 用户也入表）");
        assert_eq!(validator.get_count(), 1, "email 索引计数（仅 alice）");
        let alice = validator.get_by_email("alice").expect("alice");
        assert_eq!(alice.level, 2);
        // key = hex(sha224(password))，同规 config.rs hex_sha224 已测向量。
        assert!(
            validator
                .get_by_key(b"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01")
                .is_none(),
            "pass-1 ≠ 'password' 的已知向量，反例防巧合"
        );
        assert!(
            validator.get(&crate::config::hex_string(&alice.account.key)).is_some(),
            "hex(key) 索引可查"
        );
    }

    #[test]
    fn clients_override_users() {
        // Go trojan.go:124-126：clients 在场则覆盖 users。
        let section = json!({
            "users": [{ "password": "old-pass", "email": "bob" }],
            "clients": [{ "password": "new-pass", "email": "alice" }]
        });
        let (validator, _) = parse_server_section(&section).expect("parse");
        assert!(validator.get_by_email("alice").is_some());
        assert!(validator.get_by_email("bob").is_none(), "clients 覆盖 users");
    }

    #[test]
    fn users_alias_when_no_clients() {
        let section = json!({ "users": [{ "password": "p", "email": "bob" }] });
        let (validator, _) = parse_server_section(&section).expect("parse");
        assert!(validator.get_by_email("bob").is_some());
    }

    #[test]
    fn flow_field_warns_and_skips_not_rejects() {
        // Trojan Flow 已移除（Go trojan.go:134-136）：warn + 忽略，勿复活。
        let section = json!({ "clients": [{ "password": "p", "flow": "xtls-rprx-vision" }] });
        let (validator, _) = parse_server_section(&section).expect("flow 不阻断");
        assert_eq!(validator.get_key_count(), 1);
    }

    #[test]
    fn empty_clients_yields_empty_validator() {
        let (validator, fallbacks) = parse_server_section(&json!({})).expect("parse");
        assert_eq!(validator.get_count(), 0);
        assert!(fallbacks.is_none());
    }

    #[test]
    fn numeric_dest_becomes_localhost_tcp() {
        let section = json!({ "fallbacks": [{ "dest": 8080, "xver": 1 }] });
        let (_, fallbacks) = parse_server_section(&section).expect("parse");
        let policy = fallbacks.expect("fallbacks 在场");
        let fb = policy.decide("", "", "").expect("通配命中");
        assert_eq!(fb.dest, "localhost:8080", "数字 dest → localhost:N");
        assert_eq!(fb.r#type, "tcp");
        assert_eq!(fb.xver, 1);
    }

    #[test]
    fn host_port_dest_derives_tcp() {
        let section = json!({ "fallbacks": [{ "dest": "127.0.0.1:9000" }] });
        let (_, fallbacks) = parse_server_section(&section).expect("parse");
        let policy = fallbacks.expect("在场");
        let fb = policy.decide("", "", "").expect("通配命中");
        assert_eq!(fb.dest, "127.0.0.1:9000");
        assert_eq!(fb.r#type, "tcp");
    }

    #[test]
    fn sni_fallback_tree_matches() {
        let section = json!({
            "fallbacks": [
                { "dest": 80 },
                { "name": "a.com", "dest": "127.0.0.1:8001" }
            ]
        });
        let (_, fallbacks) = parse_server_section(&section).expect("parse");
        let policy = fallbacks.expect("在场");
        assert_eq!(policy.decide("a.com", "", "").expect("SNI 精确").dest, "127.0.0.1:8001");
        assert_eq!(policy.decide("b.com", "", "").expect("通配回落").dest, "localhost:80");
    }

    #[test]
    fn missing_dest_is_error() {
        // Go trojan.go:196-198：dest 缺失（type 也缺省）→ 硬错，同规生产。
        let section = json!({ "fallbacks": [{ "name": "sni" }] });
        let err = parse_server_section(&section).expect_err("dest 缺失必须 fail-fast");
        assert!(
            err.to_string().contains(r#"please fill in a valid value for every "dest""#),
            "实际: {err}"
        );
    }

    #[test]
    fn unix_dest_derives_unix() {
        let section = json!({ "fallbacks": [{ "dest": "@@haproxy" }] });
        let (_, fallbacks) = parse_server_section(&section).expect("parse");
        let policy = fallbacks.expect("在场");
        let fb = policy.decide("", "", "").expect("通配命中");
        assert_eq!(fb.r#type, "unix");
    }

    #[test]
    fn host_port_shape_judgement() {
        assert!(looks_like_host_port("127.0.0.1:9000"));
        assert!(looks_like_host_port("[::1]:9000"));
        assert!(!looks_like_host_port("localhost:"));
        assert!(!looks_like_host_port(":9000"));
        assert!(!looks_like_host_port("a:b:c"));
    }
}
