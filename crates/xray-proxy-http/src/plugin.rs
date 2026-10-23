//! HTTP 协议插件（P2 批次 B，统一迁移契约模板 A1–A12）。
//!
//! 五层映射：
//! - **L1**：[`HttpPlugin`] 实现必选方法集（name/version/deps/contract/
//!   lifecycle/build），缺一编译不过。
//! - **L2**：能力只经 [`PluginContext`] 取——build 期 `ctx.section()` 读 per-plugin 段（缺段
//!   fail-fast，坑约束 7 装配半边）。
//! - **L3**：无裸能力（无 println/裸 spawn/裸 sleep/Instant）。
//! - **L4**：`assert_plugin_contract!(HttpPlugin)`（tests/plugin_contract.rs）。
//! - **L5**：装配门——缺段 → build `Err` → 整链 fail-visible（tests/plugin_contract.rs 装配负向）。
//!
//! wire 零改动：`server.rs`（CONNECT 隧道 + plain HTTP 转发 + 407 认证）与
//! `client.rs`（HTTP 出站 + h2 CONNECT 隧道）一行不动；`HttpServer::new` 即构建
//! 接缝（既有 `InboundHandler` 实现原样复用，插件只负责配置注入与构建）。
//!
//! h2 窗口参数**不变量**（坑约束 12 + 协议专属 HTTP-H2W）：`client.rs` 的
//! `initial_window_size` / `initial_connection_window_size` 现值各 32MB
//! （≥ enc8x 战役定的 16MB 下限）——回落到 hyper 默认（每流 2MB / server
//! send_buf 400KB）即重新钉死在 `min(send_buf, 窗)/RTT` 量级（bd enc8x）。
//!
//! udf 判定（A7，非通用件）：HTTP/1.1 + h2 CONNECT 装配与 `ServerConfig` 段解析
//! 都是协议方向件——按 CLAUDE.md §3.5.3「带领域方向的件不进 udf-frame」，留主仓
//! 最近消费方；无提炼候选。

use std::sync::OnceLock;

use xray_frame::{
    ClauseId, Lifecycle, Plugin, PluginContext, PluginContract, PluginDep, PluginError,
};

use crate::{config::ServerConfig, server::HttpServer};

/// 通用条款适用子集（差异表 §2.2 第 6 行：3/5/6/7/8/9/10/12 适用；
/// 2/4/11 走 [`HTTP_NOT_APPLICABLE`]）。
static HTTP_CLAUSES: &[ClauseId] = &[
    ClauseId::ConnIdPresent,
    ClauseId::SpawnManaged,
    ClauseId::StopRegistered,
    ClauseId::ConfigSectionOnly,
    ClauseId::ErrorClassifiedNoPanicEscape,
    ClauseId::BoundedResources,
    ClauseId::LogDiscipline,
    ClauseId::HotPathFreeze,
];

/// 协议专属条款（差异表 §2.2 第 6 行：enc8x 战役成果，禁改回默认 400KB）。
static HTTP_EXTRA: &[(&str, &str)] =
    &[("HTTP-H2W", "h2 客户端流窗 16MB + 服务端 send_buf 16MB 不得改回默认 400KB")];

/// N/A 声明（P1-7 拍板 P2.2：允许声明不适用但必须带非空理由）。
static HTTP_NOT_APPLICABLE: &[(ClauseId, &str)] = &[
    (
        ClauseId::HandshakeDeadline,
        "HTTP 无协议握手（首包即请求头，无协商轮次）：读头 deadline 由 serve 路径\
         既有 REQUEST_HEADER_TIMEOUT（60s，Go policy.Timeouts.Handshake）承担，不经 \
         ctx.with_deadline，本条款无落点",
    ),
    (
        ClauseId::PoolDiscipline,
        "hyper/h2 内部缓冲不由本仓管：h2 CONNECT 隧道的流控/发送缓冲由 h2 crate 自行分配，\
         本仓只透传 bytes::Bytes；server 侧读头用局部 Vec，全路径无缓冲池消费点",
    ),
    (
        ClauseId::SecretMasking,
        "http 无密钥材料（无 TLS 私钥/session key 面）：唯一凭据面是 \
         Proxy-Authorization 头，handshake 内解析成 (user, pass) 即用即弃，\
         不落日志（失败只报 AuthFailed 分类，不带口令）",
    ),
];

static HTTP_CONTRACT: PluginContract = PluginContract {
    clauses: HTTP_CLAUSES,
    extra: HTTP_EXTRA,
    not_applicable: HTTP_NOT_APPLICABLE,
};

static HTTP_LIFECYCLE: HttpLifecycle = HttpLifecycle;

/// HTTP 协议插件（L1 必选方法集全量）。
///
/// `build(ctx)` 从 per-plugin 段（`inbounds[]` 内 `protocol == "http"` 的元素）
/// 解析 `settings` → [`ServerConfig`] 并持有；入站 handler 经
/// [`inbound_handler`](HttpPlugin::inbound_handler) 由插件产出（tag 属实例注册期
/// 信息，不在 build 期定）。
#[derive(Debug, Default)]
pub struct HttpPlugin {
    /// build 期解析产物（装配根单线程 build → OnceLock 单写安全）。
    config: OnceLock<ServerConfig>,
}

impl HttpPlugin {
    /// build 产物观察面；build 前调用 → `Err`（fail-visible）。
    pub fn built_config(&self) -> Result<&ServerConfig, PluginError> {
        self.config.get().ok_or_else(|| {
            PluginError::Other("http plugin not built yet (build must run first)".into())
        })
    }

    /// 插件产出：入站 handler（`InboundHandler` 实现与行为不变，
    /// [`HttpServer::new`] 即构建接缝——server.rs 零 diff）。
    pub fn inbound_handler(&self, tag: &str) -> Result<HttpServer, PluginError> {
        Ok(HttpServer::new(tag, self.built_config()?.clone()))
    }
}

impl Plugin for HttpPlugin {
    fn name(&self) -> &'static str {
        "http"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn deps(&self) -> &'static [PluginDep] {
        &[]
    }

    fn contract(&self) -> &PluginContract {
        &HTTP_CONTRACT
    }

    fn lifecycle(&self) -> &dyn Lifecycle {
        &HTTP_LIFECYCLE
    }

    fn build(&self, ctx: &mut PluginContext) -> Result<(), PluginError> {
        let config = parse_server_section(ctx.section()?);
        self.config
            .set(config)
            .map_err(|_| PluginError::Other("http plugin built twice (assembly bug)".into()))?;
        Ok(())
    }
}

/// HTTP 生命周期三相：插件级无在途异步任务 / 无外部资源，三相直通。
/// 连接级 accept loop 的托管（坑约束 5/6 运行时半边）属 [`HttpServer`] 实例面
/// （既有行为，close = abort；FxScope/ShutdownCoordinator 接线随 P3 入口收口统一迁移）。
pub struct HttpLifecycle;

impl Lifecycle for HttpLifecycle {
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
/// 同规 xray-core `inbound.rs::parse_http_config`（权威生产解析），字段对齐
/// Go `infra/conf/http.go:25-30`：`{"users":[{"user":"u","pass":"p"}],
/// "allowTransparent":true,"userLevel":3}`。`users`/`accounts` 同义（Go
/// http.go:26-27 两字段都收），`users` 在场优先；空用户名条目丢弃（xray-core
/// 同款）。与 xray-core 解析面的收敛属 P3-2 入口收口，此处不回头改 core。
fn parse_server_section(section: &serde_json::Value) -> ServerConfig {
    let settings = section.get("settings").unwrap_or(section);
    let mut config = ServerConfig::default();
    if let Some(accounts) =
        settings.get("users").or_else(|| settings.get("accounts")).and_then(|c| c.as_array())
    {
        for a in accounts {
            let user = a.get("user").and_then(|x| x.as_str()).unwrap_or("");
            let pass = a.get("pass").and_then(|x| x.as_str()).unwrap_or("");
            if !user.is_empty() {
                config.accounts.insert(user.to_string(), pass.to_string());
            }
        }
    }
    config.allow_transparent =
        settings.get("allowTransparent").and_then(|c| c.as_bool()).unwrap_or(false);
    config.user_level = settings.get("userLevel").and_then(|c| c.as_u64()).unwrap_or(0) as u32;
    config
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn section_users_mapped_and_password_auth_on() {
        let section =
            json!({"protocol": "http", "settings": {"users": [{"user": "u", "pass": "p"}]}});
        let parsed = parse_server_section(&section);
        assert!(parsed.has_account("u", "p"));
        assert!(parsed.requires_auth());
    }

    #[test]
    fn section_users_preferred_over_accounts() {
        // xray-core parse_http_config：users 在场优先于 accounts。
        let section = json!({
            "settings": {
                "users": [{"user": "alice", "pass": "p1"}],
                "accounts": [{"user": "bob", "pass": "p2"}]
            }
        });
        let parsed = parse_server_section(&section);
        assert!(parsed.has_account("alice", "p1"));
        assert!(!parsed.has_account("bob", "p2"));
    }

    #[test]
    fn section_empty_user_dropped() {
        // xray-core parse_http_config：空用户名条目不进表。
        let section = json!({"settings": {"accounts": [{"user": "", "pass": "p"}]}});
        assert!(parse_server_section(&section).accounts.is_empty());
    }

    #[test]
    fn section_flags_and_level() {
        let section = json!({"settings": {"allowTransparent": true, "userLevel": 3, "users": []}});
        let parsed = parse_server_section(&section);
        assert!(parsed.allow_transparent);
        assert_eq!(parsed.user_level, 3);
        assert!(!parsed.requires_auth(), "空 users 数组 = 匿名访问");
    }

    #[test]
    fn section_without_settings_uses_section_body() {
        // 无 settings 子对象时退化用段本体（装配根自持 fixture 形态）。
        let section = json!({"protocol": "http", "users": [{"user": "u", "pass": "p"}]});
        assert!(parse_server_section(&section).has_account("u", "p"));
    }
}
