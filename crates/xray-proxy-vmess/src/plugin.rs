//! VMess 协议插件（P2 批次 B，统一迁移契约模板 A1–A12）。
//!
//! 五层映射：
//! - **L1**：[`VmessPlugin`] 实现必选方法集（name/version/deps/contract/
//!   lifecycle/build），缺一编译不过。
//! - **L2**：能力只经 [`PluginContext`] 取——build 期 `ctx.section()` 读 per-plugin 段（缺段
//!   fail-fast，坑约束 7 装配半边）。
//! - **L3**：无裸能力（无 println/裸 spawn/裸 sleep/Instant）。
//! - **L4**：`assert_plugin_contract!(VmessPlugin)`（tests/plugin_contract.rs）。
//! - **L5**：装配门——缺段 / alterId≠0 / vnext 形态非法 → build `Err` → 整链 fail-visible。
//!
//! wire 零改动：`aead/`（KDF + AuthID）、`encoding/`（body chunk / size parser）、
//! `inbound/`、`outbound/` 一行不动。插件只做配置解析与构建接缝：
//! - 出站面复用 crate 既有 [`parse_vmess_config`] + [`make_vmess_dial_fn`]（生产同源）；
//! - 入站面用 crate 既有 [`MemoryAccount`] / [`MemoryUser`] / [`Validator`] 装配用户表。
//! - 用户表语义同规 `xray-core` 的 `build_vmess_validator`：clients 覆盖 users。
//! - `default.level` 为 level 回落；alterId≠0 与非法 UUID 硬错。
//! - 与 core 的解析面收敛属 P3 入口收口，此处不回头改 core。
//!
//! **AEAD KDF 是每连接 CPU 成本**（互喂禁入面）：插件不包装认证/加密路径，也不引入
//! 任何缓冲拷贝或线程池转手（差异表 §2.2 第 2 行 ★ 注）。
//!
//! udf 判定（A7，非通用件）：vmess AEAD/chunk wire 是协议方向件——按 CLAUDE.md
//! §3.5.3「带领域方向的件不进 udf-frame」，留主仓最近消费方；无提炼候选。

use std::sync::{Arc, OnceLock};

use xray_app_dispatcher::default::DialFn;
use xray_common::uuid::UUID;
use xray_frame::{
    ClauseId, Lifecycle, Plugin, PluginContext, PluginContract, PluginDep, PluginError,
};

use crate::{
    account::MemoryAccount,
    dispatcher::{VmessOutboundConfig, make_vmess_dial_fn, parse_vmess_config},
    error::VmessError,
    validator::{MemoryUser, TimedUserValidator, Validator},
};

/// 通用条款适用子集（差异表 §2.2 第 2 行：vmess **12 条全适用**——AEAD 认证 →
/// 1/11；AEAD 请求头握手 → 2；body chunk 分帧/缓冲 → 4；其余照常）。
static VMESS_CLAUSES: &[ClauseId] = &[
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

/// 协议专属条款（差异表 §2.2 第 2 行 vmess-chunk-u16-explicit；存量落点：
/// `inbound/server.rs:510-513`（中止流）/ `:588-591`（UDP 显式报错）/
/// `dispatcher.rs:854-857` / `aead/mod.rs:243 PayloadTooLarge`——本单不碰）。
static VMESS_EXTRA: &[(&str, &str)] =
    &[("VMESS-U16", "VMess chunk size u16 截断必须显式报错，禁静默替换 u16::MAX")];

static VMESS_CONTRACT: PluginContract =
    PluginContract { clauses: VMESS_CLAUSES, extra: VMESS_EXTRA, not_applicable: &[] };

static VMESS_LIFECYCLE: VmessLifecycle = VmessLifecycle;

/// 段解析产物：一份 vmess 段只可能是入站（`clients`/`users`）或出站
/// （`vnext` / 扁平 `address`）之一（Go `infra/conf/vmess.go` 两侧配置面互斥）。
pub enum VmessFace {
    /// 入站用户表（`TimedUserValidator`，`serve_vmess` / transport 入站消费）。
    Inbound(Arc<TimedUserValidator>),
    /// 出站配置（`make_vmess_dial_fn` 消费）。
    Outbound(Arc<VmessOutboundConfig>),
}

/// VMess 协议插件（L1 必选方法集全量）。
///
/// `build(ctx)` 从 per-plugin 段（`inbounds[]/outbounds[]` 内
/// `protocol == "vmess"` 的元素）解析 `settings` 并持有；handler / 拨号闭包经
/// [`built_validator`](VmessPlugin::built_validator) /
/// [`dial_fn`](VmessPlugin::dial_fn) 由插件产出（tag/listen/policy 属实例注册期信息）。
#[derive(Default)]
pub struct VmessPlugin {
    /// build 期解析产物（装配根单线程 build → OnceLock 单写安全）。
    face: OnceLock<VmessFace>,
}

impl VmessPlugin {
    fn built_face(&self) -> Result<&VmessFace, PluginError> {
        self.face.get().ok_or_else(|| {
            PluginError::Other("vmess plugin not built yet (build must run first)".into())
        })
    }

    /// build 产物观察面（入站用户表）；build 前或出站段 → `Err`（fail-visible）。
    pub fn built_validator(&self) -> Result<&Arc<TimedUserValidator>, PluginError> {
        match self.built_face()? {
            VmessFace::Inbound(validator) => Ok(validator),
            VmessFace::Outbound(_) => {
                Err(PluginError::Other("vmess plugin built for outbound (no inbound users)".into()))
            },
        }
    }

    /// build 产物观察面（出站配置）；build 前或入站段 → `Err`（fail-visible）。
    pub fn built_outbound(&self) -> Result<&Arc<VmessOutboundConfig>, PluginError> {
        match self.built_face()? {
            VmessFace::Outbound(config) => Ok(config),
            VmessFace::Inbound(_) => Err(PluginError::Other(
                "vmess plugin built for inbound (no outbound config)".into(),
            )),
        }
    }

    /// 插件产出：出站拨号闭包（[`make_vmess_dial_fn`] 既有构造，wire 不变）。
    ///
    /// 本接缝暂自持 `for_plugin` ctx（PluginContext 非 Clone，build(&mut) 无法
    /// 移交句柄）；P3 装配接线时改传装配根 ctx。
    pub fn dial_fn(&self) -> Result<DialFn, PluginError> {
        Ok(make_vmess_dial_fn(
            Arc::clone(self.built_outbound()?),
            Arc::new(PluginContext::for_plugin("vmess")),
        ))
    }
}

impl Plugin for VmessPlugin {
    fn name(&self) -> &'static str {
        "vmess"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn deps(&self) -> &'static [PluginDep] {
        &[]
    }

    fn contract(&self) -> &PluginContract {
        &VMESS_CONTRACT
    }

    fn lifecycle(&self) -> &dyn Lifecycle {
        &VMESS_LIFECYCLE
    }

    fn build(&self, ctx: &mut PluginContext) -> Result<(), PluginError> {
        let face = parse_section(ctx.section()?)?;
        self.face
            .set(face)
            .map_err(|_| PluginError::Other("vmess plugin built twice (assembly bug)".into()))?;
        Ok(())
    }
}

/// VMess 生命周期三相：插件级无在途异步任务 / 无外部资源，三相直通。
/// 连接级 accept/pump 任务的托管（坑约束 5/6 运行时半边）属 `serve_vmess` /
/// `handle_vmess_connection` 实例面（既有行为；FxScope/ShutdownCoordinator
/// 接线随 P3 入口收口统一迁移）。
pub struct VmessLifecycle;

impl Lifecycle for VmessLifecycle {
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

/// per-plugin 段 → 面判定 + 解析。入站/出站互斥（Go `infra/conf/vmess.go`
/// 两个 Build 分支消费不同键）：`vnext` 在场或扁平 `address` 非空 → 出站。
fn parse_section(section: &serde_json::Value) -> Result<VmessFace, PluginError> {
    let settings = section.get("settings").unwrap_or(section);
    let flat_outbound =
        settings.get("address").and_then(|a| a.as_str()).is_some_and(|a| !a.is_empty());
    if settings.get("vnext").is_some() || flat_outbound {
        parse_vmess_config(&serde_json::to_vec(settings).map_err(|e| {
            PluginError::Other(format!("vmess outbound settings re-encode: {e}").into())
        })?)
        .map(|config| VmessFace::Outbound(Arc::new(config)))
        .map_err(|e| PluginError::Other(format!("vmess outbound settings: {e}").into()))
    } else {
        parse_inbound_validator(settings).map(VmessFace::Inbound)
    }
}

/// `clients`/`users` → [`TimedUserValidator`]。
///
/// 语义同规 `xray-core` 的 `build_vmess_validator`（权威生产解析，JSON 格式
/// `{"clients":[{"id":"uuid","level":0,"alterId":0,"email":""}]}`）：
/// - `clients` 键在场（非 null，含空数组）完全覆盖 `users`（Go vmess.go:73-75）；
/// - `default.level` 是用户缺 level 时的回落（Go VMessDefaultConfig）；
/// - `alterId`≠0 = legacy VMess 意图，AEAD-only 直接拒启（数字/字符串都认）；
/// - UUID 非法 / 重名用户分别硬错 / warn+skip。
fn parse_inbound_validator(
    settings: &serde_json::Value,
) -> Result<Arc<TimedUserValidator>, PluginError> {
    let validator = TimedUserValidator::new();
    let default_level = settings
        .get("default")
        .and_then(|d| d.get("level"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0) as u32;
    let clients = settings
        .get("clients")
        .filter(|c| !c.is_null())
        .or_else(|| settings.get("users"))
        .and_then(|c| c.as_array());
    if let Some(clients) = clients {
        for c in clients {
            let id = c.get("id").and_then(|x| x.as_str()).unwrap_or("");
            let email = c.get("email").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let level = c
                .get("level")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(u64::from(default_level)) as u32;
            let alter_id = c
                .get("alterId")
                .and_then(|x| x.as_i64().or_else(|| x.as_str().and_then(|s| s.parse::<i64>().ok())))
                .unwrap_or(0);
            if alter_id != 0 {
                crate::VMESS_LOG.warn(format!(
                    "vmess inbound: legacy VMess is not supported alter_id={alter_id}"
                ));
                return Err(PluginError::Other(
                    VmessError::UnsupportedLegacyAlterId(alter_id).to_string().into(),
                ));
            }
            let uuid =
                UUID::parse(id).ok_or_else(|| PluginError::Other("vmess invalid uuid".into()))?;
            let user = MemoryUser::new(email, MemoryAccount::new(uuid)).with_level(level);
            if let Err(e) = Validator::add(&validator, user) {
                crate::VMESS_LOG.warn(format!("skip vmess user during validator build error={e}"));
            }
        }
    }
    Ok(Arc::new(validator))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const UUID_A: &str = "66ad4540-b58c-4ad2-9926-ea63445a9b57";
    const UUID_B: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    /// `VmessFace` 无 Debug（内持 validator 锁）→ 不用 `expect_err`，手取 `Err`。
    fn parse_err(section: &serde_json::Value) -> PluginError {
        match parse_section(section) {
            Ok(_) => panic!("expected parse error"),
            Err(e) => e,
        }
    }

    #[test]
    fn inbound_clients_fill_validator_with_default_level() {
        let face = parse_section(&json!({
            "protocol": "vmess",
            "settings": {
                "default": { "level": 2 },
                "clients": [{ "id": UUID_A, "email": "alice" }, { "id": UUID_B }]
            }
        }))
        .expect("parse");
        let VmessFace::Inbound(validator) = face else {
            panic!("入站段必须解析为 Inbound")
        };
        assert_eq!(Validator::count(&*validator), 2);
    }

    #[test]
    fn clients_override_users_and_null_falls_back() {
        let VmessFace::Inbound(override_case) = parse_section(&json!({
            "users": [{ "id": UUID_B }],
            "clients": [{ "id": UUID_A }]
        }))
        .expect("parse") else {
            panic!("入站段必须解析为 Inbound")
        };
        assert_eq!(Validator::count(&*override_case), 1, "clients 覆盖 users");
        let VmessFace::Inbound(null_case) =
            parse_section(&json!({ "clients": null, "users": [{ "id": UUID_A }] })).expect("parse")
        else {
            panic!("入站段必须解析为 Inbound")
        };
        assert_eq!(Validator::count(&*null_case), 1, "clients: null 回落 users");
    }

    #[test]
    fn legacy_alter_id_is_rejected_not_ignored() {
        let err = parse_err(&json!({
            "clients": [{ "id": UUID_A, "alterId": "64" }]
        }));
        assert!(err.to_string().contains("not supported"), "实际: {err}");
    }

    #[test]
    fn invalid_uuid_is_rejected() {
        let long_id = "x".repeat(40);
        let err = parse_err(&json!({ "clients": [{ "id": long_id }] }));
        assert!(err.to_string().contains("invalid uuid"), "实际: {err}");
    }

    #[test]
    fn outbound_vnext_and_flat_forms_parse() {
        let VmessFace::Outbound(vnext) = parse_section(&json!({
            "vnext": [{ "address": "example.com", "port": 443,
                        "users": [{ "id": UUID_A, "security": "aes-128-gcm", "level": 1 }] }]
        }))
        .expect("vnext parse") else {
            panic!("vnext 段必须解析为 Outbound")
        };
        assert_eq!(vnext.server_port.value(), 443);
        assert_eq!(vnext.level, 1);

        let VmessFace::Outbound(flat) = parse_section(&json!({
            "settings": { "address": "example.com", "port": 8443, "id": UUID_B }
        }))
        .expect("flat parse") else {
            panic!("扁平 address 段必须解析为 Outbound")
        };
        assert_eq!(flat.server_port.value(), 8443);
    }

    #[test]
    fn outbound_multi_vnext_is_rejected() {
        let err = parse_err(&json!({
            "vnext": [
                { "address": "a.com", "port": 443, "users": [{ "id": UUID_A }] },
                { "address": "b.com", "port": 443, "users": [{ "id": UUID_A }] }
            ]
        }));
        assert!(err.to_string().contains("one and only one"), "实际: {err}");
    }

    // ── 安全 F1（bd 0rtm）：UUID 掩码 ──
    /// 日志捕获闭环 writer（同 xray-frame/tests/log_discipline.rs 配方）。
    #[derive(Clone, Default)]
    struct SharedBuf(Arc<std::sync::Mutex<Vec<u8>>>);

    impl SharedBuf {
        fn snapshot(&self) -> String {
            String::from_utf8(self.0.lock().expect("no poison").clone()).expect("utf8")
        }
    }

    impl std::io::Write for SharedBuf {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("no poison").extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// `set_default` 重建 callsite interest（换订阅者后首评估不残留 never）。
    fn capture_log(buf: SharedBuf) -> tracing::subscriber::DefaultGuard {
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(move || buf.clone())
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();
        guard
    }

    #[test]
    fn legacy_and_invalid_uuid_paths_never_leak_raw_uuid() {
        let log = SharedBuf::default();
        let _guard = capture_log(log.clone());

        let err = parse_err(&json!({ "clients": [{ "id": UUID_A, "alterId": 64 }] })).to_string();
        assert!(err.contains("legacy VMess"), "错误链: {err}");
        assert!(!err.contains(UUID_A), "错误链泄露 UUID: {err}");

        let bad_id = "x".repeat(40);
        let err = parse_err(&json!({ "clients": [{ "id": bad_id }] })).to_string();
        assert!(err.contains("invalid uuid"), "错误链: {err}");
        assert!(!err.contains(&bad_id), "错误链泄露 UUID: {err}");

        let out = log.snapshot();
        assert!(out.contains("legacy VMess"), "warn 必须仍有诊断信息: {out}");
        assert!(!out.contains(UUID_A), "日志泄露 UUID: {out}");
    }
}
