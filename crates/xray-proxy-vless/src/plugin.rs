//! VLESS 协议插件（P2 批次 B 最高风险族，统一迁移契约模板 A1–A12）。
//!
//! 五层映射：
//! - **L1**：[`VlessPlugin`] 实现必选方法集（name/version/deps/contract/
//!   lifecycle/build），缺一编译不过。
//! - **L2**：能力只经 [`PluginContext`] 取——build 期 `ctx.section()` 读 per-plugin 段（缺段
//!   fail-fast，坑约束 7 装配半边）。
//! - **L3**：无裸能力（无 println/裸 spawn/裸 sleep/Instant）。
//! - **L4**：`assert_plugin_contract!(VlessPlugin)`（tests/plugin_contract.rs）。
//! - **L5**：装配门——缺段 / `decryption` 缺省 / `settings.flow` 非法 / vnext 多成员 / encryption
//!   非法 → build `Err` → 整链 fail-visible（tests/plugin_contract.rs）。
//!
//! wire 零改动：`encoding/`、`encryption/`（vision）、`inbound/`、`outbound/`
//! 一行不动。两条协议专属红线（见 `VLESS_EXTRA`）：
//! - **VLESS-VISION**：vision splice gate 禁碰（d8562b56 + a427613b 双 revert
//!   史实）；`inbound.rs:3445-3449` 三件套（dup 裸 TCP / RecordFramer / raw 克隆） 是 39824 修 A
//!   成果，不得拆——本插件是纯壳层，零触碰。
//! - **VLESS-MUX**：mux carrier 判据 = 目的地域名 `v1.mux.cool`，不校验 VLESS command
//!   字段与端口（9527 只是惯例）；禁把 carrier 改成 `VlessCommand::Mux` （e2e 红 + Go
//!   实测不需要，两度证伪）。插件不触碰 command 决策面。
//!
//! 插件只做配置解析与构建接缝：
//! - 出站面：[`VlessOutboundConfig`] 既有 builder 装配 + 拨号闭包走 crate 既有
//!   [`make_dial_fn`]（生产同源，wire 不变）；
//! - 入站面：[`MemoryValidator`] / [`MemoryUser`] / [`MemoryAccount::from_proto_account`]
//!   装配用户表 + ENC 解密实例 + [`FallbackPolicy`]，字段语义同规 xray-core `parse_vless_config` /
//!   `build_vless_validator` / `build_vless_decryption` / `build_vless_fallbacks` （权威生产解析为
//!   xray-core 私有 fn，且 xray-core 反向依赖本 crate，不可直连； 逐条对齐，收敛属 P3
//!   入口收口）。**ENC 字符串解析复用 crate 既有 `parse_client_encryption` /
//!   `parse_server_decryption`（禁另写一份）**—— 拼错 mlkem 串静默降级明文是机密性回退（Go
//!   vless.go:355-360）。
//!
//! udf 判定（A7，非通用件）：vless wire/vision/mux 是协议方向件——按
//! CLAUDE.md §3.5.3「带领域方向的件不进 udf-frame」，留主仓最近消费方；
//! 无提炼候选。

use std::sync::{Arc, LazyLock, OnceLock};

use xray_app_dispatcher::default::DialFn;
use xray_common::{
    net::{address::Address, port::Port},
    uuid::UUID,
};
use xray_frame::{
    ClauseId, Lifecycle, LogFacade, Plugin, PluginContext, PluginContract, PluginDep, PluginError,
};
use xray_proto::xray::proxy::vless::Account as ProtoAccount;

use crate::{
    FLOW_XRV, MemoryAccount, VlessOutboundConfig,
    dispatcher::make_dial_fn,
    encryption::{ServerInstance, parse_client_encryption, parse_server_decryption},
    inbound::{
        handler::{FallbackDest, FallbackPolicy},
        reverse::{PortalConfig, ReverseRegistry},
    },
    validator::{MemoryUser, MemoryValidator, Validator},
};

/// 配置解析诊断门面（nn8os 2b 同型处置：tracing 宏 → LogFacade——本项目工具链
/// 上 `disallowed_macros` 对 proc-macro 不认任何 allow（fn/stmt/文件顶三形态
/// 实测无效），迁移为唯一关红路径。域 = "vless"，target `xray_frame::vless` +
/// mask_secrets。只在配置解析告警/装配信息分支发射（冷路径）。
static PLUGIN_LOG: LazyLock<LogFacade> = LazyLock::new(|| LogFacade::new("vless", vec![]));

/// 通用条款适用子集（差异表 §2.2 第 1 行：vless **12 条全适用**——UUID 认证 →
/// 1/11；请求头握手 → 2；body 长度前缀分帧/缓冲 → 4；其余照常）。
static VLESS_CLAUSES: &[ClauseId] = &[
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

/// 协议专属条款（差异表 §2.2 第 1 行，原文照抄派单）。
static VLESS_EXTRA: &[(&str, &str)] = &[
    ("VLESS-VISION", "vision splice gate 禁碰（d8562b56 + a427613b 双 revert 史实）"),
    ("VLESS-MUX", "mux carrier 判据=目的地域名 v1.mux.cool，不校验 VLESS command 字段与端口"),
];

static VLESS_CONTRACT: PluginContract =
    PluginContract { clauses: VLESS_CLAUSES, extra: VLESS_EXTRA, not_applicable: &[] };

static VLESS_LIFECYCLE: VlessLifecycle = VlessLifecycle;

/// 段解析产物：一份 vless 段只可能是入站（`clients`/`users` + `decryption`）或
/// 出站（`vnext` / 扁平 `address`）之一（Go `infra/conf/vless.go` 两侧配置面互斥）。
pub enum VlessFace {
    /// 入站构建产物（用户表 + 可选 ENC 解密实例 + 可选 fallback 决策树）。
    Inbound(VlessInboundBuild),
    /// 出站配置（[`make_dial_fn`] 消费）。
    Outbound(Arc<VlessOutboundConfig>),
}

/// 入站构建产物（xray-core `build_vless_*` 三件的插件期等价物）；handler 装配
/// 所需 tag/listen/ohm/握手限时属实例注册期信息，不在 build 期定。
pub struct VlessInboundBuild {
    /// 用户表（UUID → `MemoryUser`，`serve_vless` / transport 入站消费）。
    pub validator: Arc<MemoryValidator>,
    /// ENC 解密实例（Go `inbound.go:104-114 handler.decryption`，handler 级共享；
    /// settings.decryption 非 "none" 时启用）。
    pub decryption: Option<Arc<ServerInstance>>,
    /// fallback 决策树（无 fallback 配置 → `None`）。
    pub fallbacks: Option<Arc<FallbackPolicy>>,
}

/// VLESS 协议插件（L1 必选方法集全量）。
///
/// `build(ctx)` 从 per-plugin 段（`inbounds[]/outbounds[]` 内
/// `protocol == "vless"` 的元素）解析 `settings` 并持有；产物经
/// [`built_validator`](VlessPlugin::built_validator) /
/// [`built_decryption`](VlessPlugin::built_decryption) /
/// [`built_fallbacks`](VlessPlugin::built_fallbacks) /
/// [`dial_fn`](VlessPlugin::dial_fn) 由插件产出（tag/listen/policy 属实例注册期信息）。
#[derive(Default)]
pub struct VlessPlugin {
    /// build 期解析产物（装配根单线程 build → OnceLock 单写安全）。
    face: OnceLock<VlessFace>,
}

impl VlessPlugin {
    fn built_face(&self) -> Result<&VlessFace, PluginError> {
        self.face.get().ok_or_else(|| {
            PluginError::Other("vless plugin not built yet (build must run first)".into())
        })
    }

    /// build 产物观察面（入站用户表）；build 前或出站段 → `Err`（fail-visible）。
    pub fn built_validator(&self) -> Result<&Arc<MemoryValidator>, PluginError> {
        match self.built_face()? {
            VlessFace::Inbound(build) => Ok(&build.validator),
            VlessFace::Outbound(_) => {
                Err(PluginError::Other("vless plugin built for outbound (no inbound users)".into()))
            },
        }
    }

    /// build 产物观察面（ENC 解密实例，`decryption:"none"` → `None`）；
    /// build 前或出站段 → `Err`（fail-visible）。
    pub fn built_decryption(&self) -> Result<&Option<Arc<ServerInstance>>, PluginError> {
        match self.built_face()? {
            VlessFace::Inbound(build) => Ok(&build.decryption),
            VlessFace::Outbound(_) => Err(PluginError::Other(
                "vless plugin built for outbound (no inbound decryption)".into(),
            )),
        }
    }

    /// build 产物观察面（fallback 决策树；无 fallback 配置 → `None`）；
    /// build 前或出站段 → `Err`（fail-visible）。
    pub fn built_fallbacks(&self) -> Result<&Option<Arc<FallbackPolicy>>, PluginError> {
        match self.built_face()? {
            VlessFace::Inbound(build) => Ok(&build.fallbacks),
            VlessFace::Outbound(_) => Err(PluginError::Other(
                "vless plugin built for outbound (no inbound fallbacks)".into(),
            )),
        }
    }

    /// build 产物观察面（出站配置）；build 前或入站段 → `Err`（fail-visible）。
    pub fn built_outbound(&self) -> Result<&Arc<VlessOutboundConfig>, PluginError> {
        match self.built_face()? {
            VlessFace::Outbound(config) => Ok(config),
            VlessFace::Inbound(_) => Err(PluginError::Other(
                "vless plugin built for inbound (no outbound config)".into(),
            )),
        }
    }

    /// 插件产出：出站拨号闭包（[`make_dial_fn`] 既有构造，wire 不变）。
    pub fn dial_fn(&self) -> Result<DialFn, PluginError> {
        Ok(make_dial_fn(Arc::clone(self.built_outbound()?)))
    }
}

impl Plugin for VlessPlugin {
    fn name(&self) -> &'static str {
        "vless"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn deps(&self) -> &'static [PluginDep] {
        &[]
    }

    fn contract(&self) -> &PluginContract {
        &VLESS_CONTRACT
    }

    fn lifecycle(&self) -> &dyn Lifecycle {
        &VLESS_LIFECYCLE
    }

    fn build(&self, ctx: &mut PluginContext) -> Result<(), PluginError> {
        let face = parse_section(ctx.section()?)?;
        self.face
            .set(face)
            .map_err(|_| PluginError::Other("vless plugin built twice (assembly bug)".into()))?;
        Ok(())
    }
}

/// VLESS 生命周期三相：插件级无在途异步任务 / 无外部资源，三相直通。
/// 连接级 accept/vision pump 任务的托管（坑约束 5/6 运行时半边）属
/// `serve_vless` / `handle_vless_connection` 实例面（既有行为；
/// FxScope/ShutdownCoordinator 接线随 P3 入口收口统一迁移）。
pub struct VlessLifecycle;

impl Lifecycle for VlessLifecycle {
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

/// per-plugin 段 → 面判定 + 解析。入站/出站互斥（Go `infra/conf/vless.go`
/// 两个 Build 分支消费不同键）：`vnext` 在场或顶层 `address` 在场 → 出站
/// （同规 xray-core `parse_vless_config` 扁平形式判定）。
fn parse_section(section: &serde_json::Value) -> Result<VlessFace, PluginError> {
    let settings = section.get("settings").unwrap_or(section);
    let flat_outbound = settings.get("address").and_then(|a| a.as_str()).is_some();
    if settings.get("vnext").is_some() || flat_outbound {
        parse_outbound_config(settings).map(|config| VlessFace::Outbound(Arc::new(config)))
    } else {
        parse_inbound_build(settings).map(VlessFace::Inbound)
    }
}

/// 出站段 → [`VlessOutboundConfig`]。
///
/// 同规 xray-core `outbound.rs::parse_vless_config`（权威生产解析），字段对齐
/// Go `infra/conf/vless.go`：顶层 `address` 在场 → 以顶层 id/flow/encryption/
/// level/email/reverse 构造 vnext[0]（Go :263-271 扁平形式，覆盖显式 vnext）；
/// vnext/users 必须恰好 1 个（多端点拆多出站 + balancer）；非空非 none 的
/// encryption 解析失败 = 启动硬错（Go :355-360，拼错 mlkem 串静默降级明文是
/// 机密性回退）；`testseed`/`testpre` user 级优先、顶层回退（Go :296-321）；
/// `reverse.tag` 挂 user 上派生 Bridge 注册表（Go :302-308）。
fn parse_outbound_config(settings: &serde_json::Value) -> Result<VlessOutboundConfig, PluginError> {
    // 扁平形式归一（xray-core 同款 json! 合成，testseed/testpre 顶层回退随之成立）。
    let v = if settings.get("address").and_then(|a| a.as_str()).is_some() {
        serde_json::json!({
            "vnext": [{
                "address": settings.get("address"),
                "port": settings.get("port"),
                "users": [{
                    "id": settings.get("id"),
                    "flow": settings.get("flow"),
                    "encryption": settings.get("encryption"),
                    "level": settings.get("level"),
                    "email": settings.get("email"),
                    "reverse": settings.get("reverse"),
                }],
            }],
            "testseed": settings.get("testseed"),
            "testpre": settings.get("testpre"),
        })
    } else {
        settings.clone()
    };
    let vnext = v
        .get("vnext")
        .and_then(|v| v.as_array())
        .ok_or_else(|| PluginError::Other("missing vnext array".into()))?;
    // Go infra/conf/vless.go：vnext/users 必须恰好 1 个，多端点应配多个 outbound + balancer。
    if vnext.len() != 1 {
        return Err(PluginError::Other(
            r#"vless "vnext" should have one and only one member. Multiple endpoints should use multiple VLESS outbounds and routing balancer instead"#
                .into(),
        ));
    }
    let first = vnext.first().expect("vnext.len() == 1 checked above");
    let address = first
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or_else(|| PluginError::Other("missing vnext[0].address".into()))?;
    let port = first
        .get("port")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| PluginError::Other("missing vnext[0].port".into()))?;
    let users = first
        .get("users")
        .and_then(|v| v.as_array())
        .ok_or_else(|| PluginError::Other("missing vnext[0].users".into()))?;
    if users.len() != 1 {
        return Err(PluginError::Other(
            r#"vless "users" should have one and only one member. Multiple members should use multiple VLESS outbounds and routing balancer instead"#
                .into(),
        ));
    }
    let user = users.first().expect("users.len() == 1 checked above");
    let user_id = user
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| PluginError::Other("missing vnext[0].users[0].id".into()))?;
    // UUID 即认证凭据：错误信息不回显 id（坑约束 11 密钥掩码；同规
    // MemoryAccount::InvalidUuid 之外的展示面纪律）。
    let uuid = UUID::parse(user_id)
        .ok_or_else(|| PluginError::Other("vless outbound users[0].id: invalid UUID".into()))?;
    let flow = user.get("flow").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let encryption = user.get("encryption").and_then(|v| v.as_str()).unwrap_or("none").to_string();
    // Go infra/conf/vless.go:355-360：非空且非 none 的 encryption 解析失败 = 启动
    // 硬错；空串/none 走明文通过（Rust 缺字段 unwrap_or("none")，较 Go 宽松，
    // 存量配置兼容，同规生产）。encryption 串只含公钥材料，回显同规生产。
    let enc_params = parse_client_encryption(&encryption);
    if enc_params.is_none() && !encryption.is_empty() && encryption != "none" {
        return Err(PluginError::Other(
            format!(r#"VLESS users: unsupported "encryption": {encryption}"#).into(),
        ));
    }
    let level = user.get("level").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let email = user.get("email").and_then(|v| v.as_str()).unwrap_or("").to_string();
    // 反向代理 Bridge 装配（Go infra/conf/vless.go:302-308：`reverse.tag` 挂在
    // user 上；空 tag（或未配置）→ 普通出站，反向域名拨号显式报错）。
    let reverse_tag = user
        .get("reverse")
        .and_then(|r| r.get("tag"))
        .and_then(|t| t.as_str())
        .filter(|t| !t.is_empty())
        .map(String::from);
    // testseed/testpre（Go infra/conf/vless.go:296-321）：user 级优先、顶层回退。
    let testseed = user
        .get("testseed")
        .or_else(|| v.get("testseed"))
        .and_then(|s| s.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_u64().map(|n| n as u32)).collect::<Vec<u32>>())
        .unwrap_or_default();
    let testpre =
        user.get("testpre").or_else(|| v.get("testpre")).and_then(|x| x.as_u64()).unwrap_or(0)
            as u32;
    let config = VlessOutboundConfig::new(
        uuid,
        Address::Domain(address.to_string()),
        Port::new(
            u16::try_from(port)
                .map_err(|_| PluginError::Other("vless outbound: port out of range".into()))?,
        ),
    )
    .with_flow(flow)
    .with_encryption(encryption)
    .with_encryption_params(enc_params)
    .with_testseed(testseed)
    .with_testpre(testpre)
    .with_level(level)
    .with_email(email);
    let Some(tag) = reverse_tag else {
        return Ok(config);
    };
    // portal 注册表：tag → PortalConfig{domain: v1.rvs.cool}。出站拨该域名
    // （port 0）时判为反向 carrier，发 command=Rvs（VLESS-MUX：command 决策面
    // 既有逻辑，本插件零触碰）。
    let registry = ReverseRegistry::new();
    registry
        .add_reverse(PortalConfig::new(tag))
        .map_err(|e| PluginError::Other(format!("vless reverse: {e}").into()))?;
    Ok(config.with_reverse(Some(Arc::new(registry))))
}

/// 入站段 → [`VlessInboundBuild`]（validator + decryption + fallbacks 三件，
/// 同规 xray-core "vless" 装配臂的 build_vless_validator → build_vless_decryption
/// → build_vless_fallbacks 顺序）。
fn parse_inbound_build(settings: &serde_json::Value) -> Result<VlessInboundBuild, PluginError> {
    let validator = Arc::new(parse_validator(settings)?);
    let decryption = parse_decryption(settings)?;
    let fallbacks = parse_fallbacks(settings)?;
    Ok(VlessInboundBuild { validator, decryption, fallbacks })
}

/// `clients`/`users` → [`MemoryValidator`]。
///
/// 同规 xray-core `inbound.rs::build_vless_validator`（权威生产解析），字段对齐
/// Go `infra/conf/vless.go`：settings.flow 仅空 / `xtls-rprx-vision` 合法，非法
/// 值整 inbound 拒启（Go :57-73）；clients 键在场（非 null，含空数组）完全覆盖
/// users（Go :46-48）；client flow 空则继承 settings.flow，非空非法拒启（Go
/// :71-78，vision 静默降级根除）；user 级 testseed 不足 4 个 → settings 级覆盖
/// （Go :80-82）；UUID 非法硬错（经 `MemoryAccount::from_proto_account`）、重名
/// 用户 warn+skip。
fn parse_validator(settings: &serde_json::Value) -> Result<MemoryValidator, PluginError> {
    let validator = MemoryValidator::new();
    let settings_flow = settings.get("flow").and_then(|x| x.as_str()).unwrap_or("");
    if !settings_flow.is_empty() && settings_flow != FLOW_XRV {
        return Err(PluginError::Other(
            format!(r#"VLESS "settings.flow" doesn't support "{settings_flow}" in this version"#)
                .into(),
        ));
    }
    let cfg_testseed: Vec<u32> = settings
        .get("testseed")
        .and_then(|s| s.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_u64().map(|n| n as u32)).collect::<Vec<u32>>())
        .unwrap_or_default();
    fn user_testseed(c: &serde_json::Value) -> Vec<u32> {
        c.get("testseed")
            .and_then(|s| s.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_u64().map(|n| n as u32)).collect::<Vec<u32>>())
            .unwrap_or_default()
    }
    let client_list = settings
        .get("clients")
        .filter(|c| !c.is_null())
        .or_else(|| settings.get("users"))
        .and_then(|c| c.as_array());
    if let Some(clients) = client_list {
        for c in clients {
            let id = c.get("id").and_then(|x| x.as_str()).unwrap_or("");
            let email = c.get("email").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let level = c.get("level").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
            let flow = match c.get("flow").and_then(|x| x.as_str()).unwrap_or("") {
                "" => settings_flow.to_string(),
                f if f == FLOW_XRV => f.to_string(),
                f => {
                    return Err(PluginError::Other(
                        format!(r#"VLESS users: "flow" doesn't support "{f}" in this version"#)
                            .into(),
                    ));
                },
            };
            let mut testseed = user_testseed(c);
            if testseed.len() < 4 {
                testseed = cfg_testseed.clone();
            }
            let proto = ProtoAccount {
                id: id.to_string(),
                flow,
                encryption: "none".to_string(),
                testseed,
                ..Default::default()
            };
            let account = MemoryAccount::from_proto_account(&proto)
                .map_err(|e| PluginError::Other(format!("vless account parse: {e}").into()))?;
            let user = MemoryUser::new(email, level, account);
            if let Err(e) = Validator::add(&validator, user) {
                PLUGIN_LOG
                    .warn(format!("skip duplicate vless user during validator build error={e}"));
            }
        }
    }
    Ok(validator)
}

/// settings.decryption → handler 级共享 ENC 解密实例（Go `inbound.go:104-114`）。
///
/// 同规 xray-core `inbound.rs::build_vless_decryption`：`"none"` → `None`（无
/// ENC 层）；`"mlkem768x25519plus.<mode>.<seconds>s.<keys>"` → 初始化
/// [`ServerInstance`]（私钥 32B=X25519 / 64B=ML-KEM-768 seed）。缺省/空串/非法
/// 非 none 值拒启（Go vless.go:152-159，**禁** unwrap_or("none") 静默兜底）；
/// ENC 启用时 fallbacks 字段在场即互斥拒启（Go :161-163）。
fn parse_decryption(
    settings: &serde_json::Value,
) -> Result<Option<Arc<ServerInstance>>, PluginError> {
    let raw = settings.get("decryption").and_then(|d| d.as_str()).unwrap_or("");
    let Some(p) = parse_server_decryption(raw) else {
        if raw.is_empty() {
            return Err(PluginError::Other(
                r#"VLESS settings: please add/set "decryption":"none" to every settings"#.into(),
            ));
        }
        if raw != "none" {
            return Err(PluginError::Other(
                format!(r#"VLESS settings: unsupported "decryption": {raw}"#).into(),
            ));
        }
        return Ok(None);
    };
    if settings.get("fallbacks").is_some() {
        return Err(PluginError::Other(
            r#"VLESS settings: "fallbacks" can not be used together with "decryption""#.into(),
        ));
    }
    let mut inst = ServerInstance::new();
    let key_count = p.keys.len();
    inst.init(
        p.keys,
        p.xor_mode,
        p.seconds_from,
        p.seconds_to,
        &p.padding,
        // 自持 for_plugin ctx（PluginContext 非 Clone，build(&mut) 无法移交句柄）；
        // P3 装配接线时改传装配根 ctx。
        std::sync::Arc::new(xray_frame::PluginContext::for_plugin("vless")),
    )
    .map_err(|e| PluginError::Other(format!("vless decryption init: {e}").into()))?;
    PLUGIN_LOG.info(format!(
        "vless enc decryption enabled seconds_from={} seconds_to={} keys={key_count}",
        p.seconds_from, p.seconds_to
    ));
    Ok(Some(Arc::new(inst)))
}

/// `fallbacks` → [`FallbackPolicy`]；字段缺失/空数组 → `None`（无 fallback 直连
/// 路径）。
///
/// 同规 xray-core `inbound.rs::build_vless_fallbacks`（权威生产解析），字段对齐
/// Go `infra/conf/vless.go`：`path` 必须为空或以 `/` 开头；`xver` 仅 0/1/2，
/// 负数/非整数/越界一律拒启不钳制（Go :209-211）；`dest` 数字 → `localhost:N`
/// （Go :177-179，非 uint16 硬错）；type 推导（`serve-ws-none` → serve、`/`/`@`
/// 前缀 → unix、纯数字 → localhost:N、host:port → tcp，Go :186-202）；dest/type
/// 缺失拒启（Go :206-208）；unix/serve 目标本构建运行面未实现 → 显式拒启。
fn parse_fallbacks(
    settings: &serde_json::Value,
) -> Result<Option<Arc<FallbackPolicy>>, PluginError> {
    let Some(fbs) = settings.get("fallbacks").and_then(|f| f.as_array()) else {
        return Ok(None);
    };
    let mut policy = FallbackPolicy::new();
    for (i, fb) in fbs.iter().enumerate() {
        let name = fb.get("name").and_then(|x| x.as_str()).unwrap_or("");
        let alpn = fb.get("alpn").and_then(|x| x.as_str()).unwrap_or("");
        let path = fb.get("path").and_then(|x| x.as_str()).unwrap_or("");
        if !path.is_empty() && !path.starts_with('/') {
            return Err(PluginError::Other(
                r#"VLESS fallbacks: "path" must be empty or start with "/""#.into(),
            ));
        }
        let xver = match fb.get("xver") {
            None | Some(serde_json::Value::Null) => 0u8,
            Some(x) => match x.as_u64() {
                Some(n @ 0..=2) => n as u8,
                Some(_) => {
                    return Err(PluginError::Other(
                        r#"VLESS fallbacks: invalid PROXY protocol version, "xver" only accepts 0, 1, 2"#
                            .into(),
                    ));
                },
                None => {
                    return Err(PluginError::Other(
                        format!("VLESS fallbacks[{i}]: invalid \"xver\" (need unsigned integer)")
                            .into(),
                    ));
                },
            },
        };
        let mut dest = match fb.get("dest") {
            Some(serde_json::Value::Number(n)) => match n.as_u64() {
                Some(port @ 0..=65_535) => format!("localhost:{port}"),
                _ => {
                    return Err(PluginError::Other(
                        format!(
                            "VLESS fallbacks[{i}]: invalid numeric \"dest\" (need uint16 port)"
                        )
                        .into(),
                    ));
                },
            },
            Some(serde_json::Value::String(s)) => s.clone(),
            None | Some(serde_json::Value::Null) => String::new(),
            Some(other) => {
                return Err(PluginError::Other(
                    format!("VLESS fallbacks[{i}]: invalid \"dest\": {other}").into(),
                ));
            },
        };
        let mut fb_type = fb.get("type").and_then(|x| x.as_str()).unwrap_or("").to_string();
        if fb_type.is_empty() && !dest.is_empty() {
            if dest == "serve-ws-none" {
                fb_type = "serve".into();
            } else if dest.starts_with('/') || dest.starts_with('@') {
                fb_type = "unix".into();
            } else {
                if dest.parse::<i64>().is_ok() {
                    dest = format!("localhost:{dest}");
                }
                if looks_like_host_port(&dest) {
                    fb_type = "tcp".into();
                }
            }
        }
        if fb_type.is_empty() || dest.is_empty() {
            return Err(PluginError::Other(
                r#"VLESS fallbacks: please fill in a valid value for every "dest""#.into(),
            ));
        }
        if fb_type != "tcp" {
            return Err(PluginError::Other(format!(
                "VLESS fallbacks[{i}]: fallback type \"{fb_type}\" is not supported by this build (only \"tcp\")"
            )
            .into()));
        }
        policy.add(name, alpn, path, FallbackDest::new(dest, xver));
    }
    if policy.is_empty() { Ok(None) } else { Ok(Some(Arc::new(policy))) }
}

/// `host:port` 形态判定（同规 xray-core `inbound.rs` `looks_like_host_port`，
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
    use base64::Engine as _;
    use serde_json::json;

    use super::*;

    const UUID_A: &str = "66ad4540-b58c-4ad2-9926-ea63445a9b57";
    const UUID_B: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    fn parse_err(section: &serde_json::Value) -> PluginError {
        match parse_section(section) {
            Ok(_) => panic!("expected parse error"),
            Err(e) => e,
        }
    }

    #[test]
    fn inbound_clients_fill_validator() {
        let VlessFace::Inbound(build) = parse_section(&json!({
            "clients": [
                { "id": UUID_A, "email": "alice", "level": 2 },
                { "id": UUID_B }
            ],
            "decryption": "none"
        }))
        .expect("parse") else {
            panic!("入站段必须解析为 Inbound")
        };
        assert_eq!(Validator::get_uuid_count(&*build.validator), 2);
        assert!(build.decryption.is_none(), "decryption=none → 无 ENC 实例");
        assert!(build.fallbacks.is_none(), "无 fallback 配置 → None");
    }

    #[test]
    fn clients_non_null_overrides_users_alias() {
        // Go vless.go:46-48：clients 键在场（非 null，含空数组）完全覆盖 users。
        let VlessFace::Inbound(both) = parse_section(&json!({
            "users": [{ "id": UUID_B }],
            "clients": [{ "id": UUID_A }],
            "decryption": "none"
        }))
        .expect("parse") else {
            panic!("入站段必须解析为 Inbound")
        };
        let a = UUID::parse(UUID_A).expect("uuid a");
        assert!(both.validator.get(&a).is_some(), "clients 覆盖 users");
        let VlessFace::Inbound(null_case) = parse_section(&json!({
            "clients": null,
            "users": [{ "id": UUID_A }],
            "decryption": "none"
        }))
        .expect("parse") else {
            panic!("入站段必须解析为 Inbound")
        };
        assert_eq!(Validator::get_uuid_count(&*null_case.validator), 1, "clients: null 回落 users");
    }

    #[test]
    fn client_flow_inherits_settings_and_validates() {
        // Go vless.go:71-78：空 client flow 继承 settings.flow；非空非法拒启。
        let VlessFace::Inbound(build) = parse_section(&json!({
            "clients": [{ "id": UUID_A }],
            "flow": "xtls-rprx-vision",
            "decryption": "none"
        }))
        .expect("parse") else {
            panic!("入站段必须解析为 Inbound")
        };
        let a = UUID::parse(UUID_A).expect("uuid a");
        let user = build.validator.get(&a).expect("user registered");
        assert_eq!(user.account.flow, FLOW_XRV, "client 继承 settings.flow");

        let err = parse_err(&json!({
            "clients": [{ "id": UUID_A, "flow": "xtls-rprx-direct" }]
        }));
        assert!(err.to_string().contains("\"flow\" doesn't support"), "实际: {err}");
    }

    #[test]
    fn settings_flow_invalid_rejected() {
        let err = parse_err(&json!({
            "clients": [{ "id": UUID_A }],
            "flow": "xtls-rprx-vision-44"
        }));
        assert!(err.to_string().contains("settings.flow"), "实际: {err}");
    }

    #[test]
    fn testseed_user_over_settings_fallback() {
        // Go vless.go:80-82：user 级 ≥4 个生效；不足 4 个 → settings 级覆盖。
        let VlessFace::Inbound(build) = parse_section(&json!({
            "clients": [
                { "id": UUID_A, "testseed": [1, 2, 3] },
                { "id": UUID_B, "testseed": [7, 8, 9, 10] }
            ],
            "testseed": [900, 500, 900, 256],
            "decryption": "none"
        }))
        .expect("parse") else {
            panic!("入站段必须解析为 Inbound")
        };
        let a = UUID::parse(UUID_A).expect("uuid a");
        let b = UUID::parse(UUID_B).expect("uuid b");
        assert_eq!(
            build.validator.get(&a).expect("a").account.testseed,
            vec![900, 500, 900, 256],
            "user 级不足 4 个 → settings 级覆盖"
        );
        assert_eq!(
            build.validator.get(&b).expect("b").account.testseed,
            vec![7, 8, 9, 10],
            "user 级 ≥4 个生效"
        );
    }

    #[test]
    fn decryption_missing_or_empty_rejected() {
        for section in [json!({ "clients": [{ "id": UUID_A }] }), json!({ "decryption": "" })] {
            let err = parse_err(&section);
            assert!(
                err.to_string().contains("please add/set"),
                "expected empty-decryption hard error, got: {err}"
            );
        }
    }

    #[test]
    fn decryption_unsupported_rejected() {
        let err = parse_err(&json!({ "decryption": "bogus-dec" }));
        assert!(err.to_string().contains("unsupported \"decryption\""), "实际: {err}");
    }

    #[tokio::test]
    async fn enc_decryption_initializes_and_conflicts_with_fallbacks() {
        // 合法 mlkem 串 → ENC 实例初始化成功；同段 fallbacks 在场 → 互斥拒启
        // （Go vless.go:161-163，字段在场即拒）。tokio 运行时必需：0-RTT 启用时
        // ServerInstance::init 会 spawn 60s 清理任务（生产继承行为，同 xray-core
        // build_vless_decryption 的异步装配期约束）。
        let keys = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]);
        let enc = format!("mlkem768x25519plus.native.1000s.{keys}");
        let VlessFace::Inbound(build) =
            parse_section(&json!({ "decryption": enc })).expect("parse")
        else {
            panic!("入站段必须解析为 Inbound")
        };
        assert!(build.decryption.is_some(), "ENC 解密实例已初始化");

        let enc_fb =
            format!(r#"{{"decryption":"mlkem768x25519plus.native.1000s.{keys}","fallbacks":[]}}"#);
        let err = parse_err(&serde_json::from_str::<serde_json::Value>(&enc_fb).expect("json"));
        assert!(
            err.to_string().contains("can not be used together"),
            "expected mutual-exclusion hard error, got: {err}"
        );
    }

    #[test]
    fn fallbacks_numeric_dest_maps_to_localhost() {
        // Go vless.go:177-179：数字 dest → localhost:N。
        let VlessFace::Inbound(build) = parse_section(&json!({
            "decryption": "none",
            "fallbacks": [{ "dest": 8080 }]
        }))
        .expect("parse") else {
            panic!("入站段必须解析为 Inbound")
        };
        let policy = build.fallbacks.expect("policy built");
        let d = policy.find("", "", "").expect("default entry");
        assert_eq!(d.dest, "localhost:8080");
        assert_eq!(d.xver, 0);
    }

    #[test]
    fn fallbacks_hard_errors_mirror_production() {
        // dest 缺失 / 非法 xver / 非 tcp 目标 → 拒启（Go vless.go:206-211）。
        for section in [
            json!({ "decryption": "none", "fallbacks": [{ "alpn": "h2" }] }),
            json!({ "decryption": "none", "fallbacks": [{ "dest": "127.0.0.1:80", "xver": 3 }] }),
            json!({ "decryption": "none", "fallbacks": [{ "dest": "/run/xray.sock" }] }),
            json!({ "decryption": "none", "fallbacks": [{ "dest": "serve-ws-none" }] }),
        ] {
            let err = parse_err(&section);
            let msg = err.to_string();
            assert!(
                msg.contains("please fill in a valid value")
                    || msg.contains("xver")
                    || msg.contains("not supported by this build"),
                "expected fallback hard error, got: {msg}"
            );
        }
    }

    #[test]
    fn outbound_vnext_and_flat_forms_parse() {
        let VlessFace::Outbound(vnext) = parse_section(&json!({
            "vnext": [{ "address": "example.com", "port": 443,
                        "users": [{ "id": UUID_A, "flow": "xtls-rprx-vision", "level": 1,
                                    "email": "cli@x" }] }]
        }))
        .expect("vnext parse") else {
            panic!("vnext 段必须解析为 Outbound")
        };
        assert_eq!(vnext.server_port.value(), 443);
        assert_eq!(vnext.flow, "xtls-rprx-vision");
        assert_eq!(vnext.level, 1);
        assert_eq!(vnext.email, "cli@x");
        assert!(vnext.reverse.is_none(), "无 reverse.tag → 普通出站");

        let VlessFace::Outbound(flat) = parse_section(&json!({
            "address": "flat.example.com",
            "port": 8443,
            "id": UUID_B
        }))
        .expect("flat parse") else {
            panic!("扁平 address 段必须解析为 Outbound")
        };
        assert_eq!(flat.server_port.value(), 8443);
        assert_eq!(flat.flow, "", "扁平形式缺省 flow 为空");
    }

    #[test]
    fn outbound_multi_vnext_and_multi_users_rejected() {
        let err = parse_err(&json!({
            "vnext": [
                { "address": "a.com", "port": 443, "users": [{ "id": UUID_A }] },
                { "address": "b.com", "port": 443, "users": [{ "id": UUID_A }] }
            ]
        }));
        assert!(err.to_string().contains("one and only one"), "实际: {err}");

        let err = parse_err(&json!({
            "vnext": [{ "address": "a.com", "port": 443,
                        "users": [{ "id": UUID_A }, { "id": UUID_B }] }]
        }));
        assert!(err.to_string().contains("one and only one"), "实际: {err}");
    }

    #[test]
    fn outbound_unsupported_encryption_rejected() {
        // Go vless.go:355-360：拼错 mlkem 串 = 启动硬错，禁静默降级明文。
        let err = parse_err(&json!({
            "vnext": [{ "address": "a.com", "port": 443,
                        "users": [{ "id": UUID_A, "encryption": "mlkem768x25519plus.bogus.0rtt.x" }] }]
        }));
        assert!(err.to_string().contains("unsupported \"encryption\""), "实际: {err}");
    }

    #[test]
    fn outbound_reverse_tag_wires_registry() {
        // Go infra/conf/vless.go:302-308：reverse.tag 挂 user 上 → Bridge 注册表。
        let VlessFace::Outbound(config) = parse_section(&json!({
            "vnext": [{ "address": "a.com", "port": 443,
                        "users": [{ "id": UUID_A, "reverse": { "tag": "portal-1" } }] }]
        }))
        .expect("parse") else {
            panic!("出站段必须解析为 Outbound")
        };
        assert!(config.reverse.is_some(), "reverse.tag → Bridge 注册表接线");
    }

    #[test]
    fn outbound_testseed_testpre_user_over_top_level() {
        let VlessFace::Outbound(config) = parse_section(&json!({
            "testseed": [1, 2, 3, 4],
            "testpre": 1,
            "vnext": [{ "address": "a.com", "port": 443,
                        "users": [{ "id": UUID_A, "testseed": [9, 9, 9, 9], "testpre": 2 }] }]
        }))
        .expect("parse") else {
            panic!("出站段必须解析为 Outbound")
        };
        assert_eq!(config.testseed, vec![9, 9, 9, 9], "user 级优先");
        assert_eq!(config.testpre, 2);
    }
}
