//! MASQUE 协议插件（L1/L4 面：12 条通用契约 + 3 条 masque extra，规划 §4.4）。
//!
//! 五层映射（对齐 wireguard plugin 形态）：
//! - **L1**：[`MasquePlugin`] 实现必选方法集（name/version/contract/lifecycle/build）。
//! - **L2**：build 期经 `ctx.section()` 读 per-plugin 段做**装配校验**（users/address/ mtu 负向
//!   fail-fast——坑约束 7 装配半边）；权威生产解析面 = xray-core 装配器 （arm_builders
//!   `masque_entry`）经 [`server::parse_server_settings`] /
//!   [`client::parse_client_settings`]，两者共用本 crate 解析（同规）。
//! - **L3**：无裸能力（无 println/裸 spawn/裸 sleep）。
//! - **L4**：`assert_plugin_contract!(MasquePlugin)`（tests/plugin_contract.rs）。
//! - **L5**：装配门——缺 address / 空 users / 非 TLS / warp / 每族多前缀 → build `Err` → 整链
//!   fail-visible（tests/plugin_contract.rs 装配负向）。

use xray_frame::{
    PluginContext,
    error::PluginError,
    plugin::{ClauseId, Lifecycle, Plugin, PluginContract, PluginDep},
};

use crate::server;

/// 通用条款适用子集（规划 §4.4：12 条全适用）。逐条锚：
/// 1 AuthErrorClassified — Basic 失败 → 401（`MasqueError::Auth` 分类）；
/// 2 HandshakeDeadline — hub TLS/answer 均有 10s 窗；3 ConnIdPresent — 隧道
/// 注册表键 = 分配地址（每连接唯一）；4 PoolDiscipline — 栈桥缓冲复用 scratch；
/// 5 SpawnManaged — 全部任务走 ComponentScope/PluginContext；6 StopRegistered —
/// scope close_gate 随 listener close；7 ConfigSectionOnly — settings 经本 crate
/// 解析；8 ErrorClassifiedNoPanicEscape — [`crate::server::MasqueError`] 分类 +
/// 泵任务 catch_unwind（FxScope 归一）；9 BoundedResources — 隧道间 512 有界
/// 队列 + 栈 UDP 会话表有界清扫；10 LogDiscipline — [`crate::LOG`] 门面；
/// 11 SecretMasking — 401/日志只记 email，密码面禁打；12 HotPathFreeze —
/// 数据面逐包泵零改动红线。
static MASQUE_CLAUSES: &[ClauseId] = &[
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

/// 协议专属条款（规划 §4.4 extra 三条）。
static MASQUE_EXTRA: &[(&str, &str)] = &[
    (
        "MASQUE-TLS-REQUIRED",
        "必须 security=tls 且服务端 ALPN 强制 h2（Go hub.go:52-60 listenHTTP2 覆写 NextProtos）",
    ),
    (
        "MASQUE-ADDR-POOL",
        "每族仅一个前缀；服务器自身地址与网络/广播地址不得分配（Go pool.go:31-45 逐值直译）",
    ),
    (
        "MASQUE-H2-ONLY",
        "本批只支持 h2；客户端 ALPN 缺省硬错（不静默走 h3——Go hub.go:47-50 的反向语义，规划 §7 R9/R11）",
    ),
];

static MASQUE_CONTRACT: PluginContract =
    PluginContract { clauses: MASQUE_CLAUSES, extra: MASQUE_EXTRA, not_applicable: &[] };

/// 生命周期三相（L4）：插件级无在途异步任务/无外部资源——隧道任务与 hub
/// 账本寿命 = 装配实例（`ComponentScope` close_gate 随 listener close，三相直通）。
pub struct MasqueLifecycle;

impl Lifecycle for MasqueLifecycle {
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

/// MASQUE 协议插件（L1 必选方法集全量）。
#[derive(Debug, Default)]
pub struct MasquePlugin;

impl MasquePlugin {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Plugin for MasquePlugin {
    fn name(&self) -> &'static str {
        crate::MASQUE_PROTOCOL
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn deps(&self) -> &'static [PluginDep] {
        &[]
    }

    fn contract(&self) -> &PluginContract {
        &MASQUE_CONTRACT
    }

    fn lifecycle(&self) -> &dyn Lifecycle {
        &MasqueLifecycle
    }

    /// 装配校验（L5）：per-plugin 段（`outbounds[]/inbounds[]` 内
    /// `protocol == "masque"` 元素，缺段 fail-fast 对齐 wireguard 同款）的
    /// `settings` 经 [`server::parse_server_settings`] 校验——含服务端面
    /// （address/users 任一存在）时逐条验证；outbound 面的 address/port 校验在
    /// [`crate::client::parse_client_settings`]，由 outbound 装配器同规调用。
    fn build(&self, ctx: &mut PluginContext) -> Result<(), PluginError> {
        let section = ctx.section()?;
        let settings = section.get("settings").unwrap_or(section);
        let has_server_face = settings.get("address").is_some() || settings.get("users").is_some();
        if has_server_face {
            server::parse_server_settings(settings)
                .map_err(|e| PluginError::Other(format!("masque: {e}").into()))?;
        }
        Ok(())
    }
}
