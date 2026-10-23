//! AnyTLS 协议插件（P2 批次 D，统一迁移契约模板 A1–A12）。
//!
//! 五层映射：
//! - **L1**：[`AnytlsPlugin`] 实现必选方法集（name/version/deps/contract/
//!   lifecycle/build），缺一编译不过。
//! - **L2**：能力只经 [`PluginContext`] 取——build 期 `ctx.section()` 读 per-plugin 段（缺段
//!   fail-fast，坑约束 7 装配半边）。
//! - **L3**：无裸能力（无 println/裸 spawn/裸 sleep/Instant）。
//! - **L4**：`assert_plugin_contract!(AnytlsPlugin)`（tests/plugin_contract.rs）。
//! - **L5**：装配门——缺段 / `password` 非字符串 → build `Err` → 整链 fail-visible
//!   （tests/plugin_contract.rs 装配负向）。
//!
//! wire 零改动：`client.rs`（认证帧构造 + 会话池）、`server.rs`（含认证帧
//! `padding0_len` 超限**直接丢弃**语义）、`socks.rs`、`dispatcher.rs`、`inbound.rs`、
//! `outbound.rs` 逐行不动；插件只解析 per-plugin 段并经既有构造器接缝注入
//! （[`AnytlsInboundHandler::new`] + `with_password`）。
//!
//! ATLS-AUTHFRAME 条款（禁改面）：认证帧 `padding0_len` 超上限即关连接，**不**等客户端
//! 补齐 65535 字节 padding——改成「读满再判」= 每连接 64KB 保留 = DoS 面
//! （`server.rs` 的 `oversized_padding0_len_rejected` 测试锁定该时序）。
//!
//! udf 判定（A7，非通用件）：TLS 会话多路复用 + SOCKS5 目标地址 + 认证帧是协议方向件
//! ——按 CLAUDE.md §3.5.3「带领域方向的件不进 udf-frame」，留主仓最近消费方；无提炼候选。

use std::{net::SocketAddr, sync::OnceLock};

use tokio_rustls::TlsAcceptor;
use xray_frame::{
    ClauseId, Lifecycle, Plugin, PluginContext, PluginContract, PluginDep, PluginError,
};

use crate::inbound::AnytlsInboundHandler;

/// 通用条款适用子集（11 条；条款 2 = [`ANYTLS_NOT_APPLICABLE`]，PM 拍板 2026-10-24）。
static ANYTLS_CLAUSES: &[ClauseId] = &[
    ClauseId::AuthErrorClassified,
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

/// 协议专属条款（差异表 §2.2 第 12 行）。
static ANYTLS_EXTRA: &[(&str, &str)] = &[(
    "ATLS-AUTHFRAME",
    "认证帧 padding0_len=u16::MAX 时服务端直接丢弃连接（server.rs:653-659），禁改为「读满再判」",
)];

static ANYTLS_CONTRACT: PluginContract = PluginContract {
    clauses: ANYTLS_CLAUSES,
    extra: ANYTLS_EXTRA,
    not_applicable: ANYTLS_NOT_APPLICABLE,
};

/// N/A 声明（PM 拍板 2026-10-24：条款 2 走 N/A + 非空理由；缺失本身已立 bd 债票
/// 跟踪，禁在插件化这一单顺手改数据面时限）。
static ANYTLS_NOT_APPLICABLE: &[(ClauseId, &str)] = &[(
    ClauseId::HandshakeDeadline,
    "anytls 的握手/首包时限当前未在本 crate 实现（dial_out/accept 无超时），时限由 \
     transport/TLS 与连接空闲策略覆盖；本插件不在数据面新增时限（避免改行为）",
)];

static ANYTLS_LIFECYCLE: AnytlsLifecycle = AnytlsLifecycle;

/// AnyTLS 协议插件（L1 必选方法集全量）。
///
/// `build(ctx)` 从 per-plugin 段（`inbounds[]` 内 `protocol == "anytls"` 的元素）
/// 解析 `settings.password` 并持有；入站 handler 经
/// [`inbound_handler`](AnytlsPlugin::inbound_handler) 由插件产出（tag / 监听地址 /
/// TLS acceptor 属实例注册期信息，不在 build 期定）。
#[derive(Debug, Default)]
pub struct AnytlsPlugin {
    /// build 期解析产物（装配根单线程 build → OnceLock 单写安全）；
    /// `None` = 不校验认证帧（同 core `parse_anytls_tls_acceptor`）。
    password: OnceLock<Option<String>>,
}

impl AnytlsPlugin {
    /// build 产物观察面；build 前调用 → `Err`（fail-visible）。
    pub fn built_password(&self) -> Result<Option<&str>, PluginError> {
        self.password.get().map(|p| p.as_deref()).ok_or_else(|| {
            PluginError::Other("anytls plugin not built yet (build must run first)".into())
        })
    }

    /// 插件产出：入站 handler（[`AnytlsInboundHandler::new`] + `with_password`
    /// 即接缝——`inbound.rs` 零 diff；TLS acceptor 由装配层按 streamSettings 构造，
    /// 属实例注册期信息）。
    pub fn inbound_handler(
        &self,
        tag: &str,
        bind_addr: SocketAddr,
        tls_acceptor: TlsAcceptor,
    ) -> Result<AnytlsInboundHandler, PluginError> {
        let password = self.built_password()?.map(str::to_owned);
        Ok(AnytlsInboundHandler::new(tag, bind_addr, tls_acceptor).with_password(password))
    }
}

impl Plugin for AnytlsPlugin {
    fn name(&self) -> &'static str {
        "anytls"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn deps(&self) -> &'static [PluginDep] {
        &[]
    }

    fn contract(&self) -> &PluginContract {
        &ANYTLS_CONTRACT
    }

    fn lifecycle(&self) -> &dyn Lifecycle {
        &ANYTLS_LIFECYCLE
    }

    fn build(&self, ctx: &mut PluginContext) -> Result<(), PluginError> {
        let password = parse_password_section(ctx.section()?)?;
        self.password
            .set(password)
            .map_err(|_| PluginError::Other("anytls plugin built twice (assembly bug)".into()))?;
        Ok(())
    }
}

/// AnyTLS 生命周期三相：插件级无在途异步任务 / 无外部资源，三相直通。
/// 连接级 accept/session 任务的托管（坑约束 5/6 运行时半边）属
/// [`AnytlsMockServer`](crate::server::AnytlsMockServer) 实例面（既有行为）；
/// FxScope/ShutdownCoordinator 接线随 P3 入口收口统一迁移。
pub struct AnytlsLifecycle;

impl Lifecycle for AnytlsLifecycle {
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

/// per-plugin 段 → 服务端认证密码。
///
/// 同规 xray-core `inbound.rs::parse_anytls_tls_acceptor`（权威生产解析）：
/// `settings.password` 取字符串，空串视为未配置（认证帧只在密码非空时校验）。
/// `password` 在场但非字符串 → 硬错：静默忽略 = 认证面静默失效（坑约束 1 的
/// 静默放行面）。出站段字段（`server`/`server_port`/`sni`/`insecure`）连同
/// rustls `ClientConfig` 构造仍属 core 解析面（P3 入口收口），此处不复制第二套。
fn parse_password_section(section: &serde_json::Value) -> Result<Option<String>, PluginError> {
    let settings = section.get("settings").unwrap_or(section);
    match settings.get("password") {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(s)) if s.is_empty() => Ok(None),
        Some(serde_json::Value::String(s)) => Ok(Some(s.clone())),
        Some(other) => Err(PluginError::Other(
            format!("anytls settings.password must be a string, got {other}").into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn section_password_absent_is_none() {
        let section = json!({"protocol": "anytls", "settings": {}});
        assert_eq!(parse_password_section(&section).expect("absent → None"), None);
    }

    #[test]
    fn section_password_empty_is_none() {
        // 同规 core：空串 filter 成未配置。
        let section = json!({"settings": {"password": ""}});
        assert_eq!(parse_password_section(&section).expect("empty → None"), None);
    }

    #[test]
    fn section_password_string_is_some() {
        let section = json!({"settings": {"password": "s3cret"}});
        assert_eq!(
            parse_password_section(&section).expect("string → Some"),
            Some("s3cret".to_owned())
        );
    }

    #[test]
    fn section_password_non_string_fails_visible() {
        let section = json!({"settings": {"password": 123}});
        let err = parse_password_section(&section).expect_err("非字符串密码必须硬错");
        assert!(
            err.to_string().contains("must be a string"),
            "错误必须标明 password 类型非法: {err}"
        );
    }
}
