//! TUN 协议插件（P2 最后一族，统一迁移契约模板 A1–A12）。
//!
//! 五层映射：
//! - **L1**：[`TunPlugin`] 实现必选方法集（name/version/deps/contract/
//!   lifecycle/build），缺一编译不过。
//! - **L2**：能力只经 [`PluginContext`] 取——build 期 `ctx.section()` 读 per-plugin 段（缺段
//!   fail-fast，坑约束 7 装配半边）。
//! - **L3**：无裸能力（无 println/裸 spawn/裸 sleep/Instant）。
//! - **L4**：`assert_plugin_contract!(TunPlugin)`（tests/plugin_contract.rs）。
//! - **L5**：装配门——缺段 / MTU > 65535（冻结校验复用，禁饱和截断）→ build `Err` → 整链
//!   fail-visible（tests/plugin_contract.rs 装配负向）。
//!
//! wire 零改动（TUN-OS-FROZEN）：`inbound.rs` / `config.rs` / `netstack.rs` /
//! `device.rs` / `device_stub.rs` / `outbound.rs` / `error.rs` / `wfp/` /
//! `sysroute/` 一行不动——TUN 设备创建/MTU 校验/平台门控属 OS 面，禁在插件层
//! 重实现；入站行为仍走 [`TunInboundHandler`]（既有 `InboundHandler` 实现原样
//! 复用，插件只负责配置注入与构建，构建接缝 = [`TunInboundHandler::new`]，
//! core `inbound.rs:3856` 同构；构造仅参数校验，设备创建仍走 `start()`）。
//!
//! udf 判定（A7，非通用件）：TUN 设备装配与系统路由/WFP 接管是 OS 方向件——按
//! CLAUDE.md §3.5.3「带领域方向的件不进 udf-frame」，留主仓最近消费方；
//! 无提炼候选。

use std::sync::OnceLock;

use xray_app_dispatcher::DispatchHandler;
use xray_frame::{
    ClauseId, Lifecycle, Plugin, PluginContext, PluginContract, PluginDep, PluginError,
};

use crate::{
    config::{StackOptions, Tun},
    inbound::TunInboundHandler,
};

/// 通用条款适用子集（差异表 §2.2 第 15 行：3,4,5,6,7,8,9,10,12 + 条款 2 落定
/// 适用；1/11 走 [`TUN_NOT_APPLICABLE`]——TUN 无认证面、无密钥材料）。
///
/// 逐条判据：smoltcp netstack TCP 三次握手内聚存在（同 WG 判例），运行时
/// deadline 接线属实例面（OS 面冻结范围）随 P3 收口 → 2；netstack 会话
/// conn_id → 3；`inbound.rs:71` xray-buf io 接缝（new_reader/new_writer）→ 4；
/// driver/UDP sweep task 托管 → 5；close = rollback + abort 既有 → 6；build
/// 段路由 → 7；[`crate::TunError`] 分类 + panic 不逃逸 IO 线程 → 8；UDP 会话
/// cmd/reply 队列硬顶 1024（`UDP_SESSION_QUEUE_CAP`，票 euv9）→ 9；tracing
/// 既有 → 10；热路径冻结 = TUN-OS-FROZEN 本体 → 12。
static TUN_CLAUSES: &[ClauseId] = &[
    ClauseId::HandshakeDeadline,
    ClauseId::ConnIdPresent,
    ClauseId::PoolDiscipline,
    ClauseId::SpawnManaged,
    ClauseId::StopRegistered,
    ClauseId::ConfigSectionOnly,
    ClauseId::ErrorClassifiedNoPanicEscape,
    ClauseId::BoundedResources,
    ClauseId::LogDiscipline,
    ClauseId::HotPathFreeze,
];

/// 协议专属条款（差异表 §2.2 第 15 行 + 本单派单契约：OS 面冻结红线，原文逐字）。
static TUN_EXTRA: &[(&str, &str)] = &[(
    "TUN-OS-FROZEN",
    "TUN 设备创建/MTU 校验（config.rs:173-176 mtu>65535 报错）属 OS 面，禁在插件层重实现；平台门控语义不变",
)];

/// N/A 声明（P1-7 拍板 P2.2：允许声明不适用但必须带非空理由）。
static TUN_NOT_APPLICABLE: &[(ClauseId, &str)] = &[
    (
        ClauseId::AuthErrorClassified,
        "TUN 无凭证/无认证协商（L3 设备接入；netstack 帧校验非认证语义）",
    ),
    (
        ClauseId::SecretMasking,
        "TUN 无密钥材料（StackOptions 字段皆非敏感：name/desc/mtu/gateway/dns/userLevel/auto*）",
    ),
];

static TUN_CONTRACT: PluginContract =
    PluginContract { clauses: TUN_CLAUSES, extra: TUN_EXTRA, not_applicable: TUN_NOT_APPLICABLE };

static TUN_LIFECYCLE: TunLifecycle = TunLifecycle;

/// TUN 协议插件（L1 必选方法集全量）。
///
/// `build(ctx)` 从 per-plugin 段（`outbounds[]`/`inbounds[]` 内
/// `protocol == "tun"` 的元素；入站/出站同 kind，core `register.rs` TUN_KINDS
/// 同款）解析 `settings` → [`StackOptions`] 并持有；入站 handler 经
/// [`inbound_handler`](TunPlugin::inbound_handler) 由插件产出。TUN 入站不需
/// port/addr（core `inbound.rs:3842` 同款），段级 `port` 不读。
#[derive(Default)]
pub struct TunPlugin {
    /// build 期解析产物（装配根单线程 build → OnceLock 单写安全）。
    options: OnceLock<StackOptions>,
}

impl TunPlugin {
    /// build 产物观察面；build 前调用 → `Err`（fail-visible）。
    pub fn built_config(&self) -> Result<&StackOptions, PluginError> {
        self.options.get().ok_or_else(|| {
            PluginError::Other("tun plugin not built yet (build must run first)".into())
        })
    }

    /// 插件产出：入站 handler（`InboundHandler` 实现与行为不变，
    /// [`TunInboundHandler::new`] 即构建接缝——inbound.rs 零 diff；构造仅
    /// 参数校验，设备创建仍走 `start()`——TUN-OS-FROZEN 范围禁包装）。
    pub async fn inbound_handler(
        &self,
        tag: &str,
        dispatch: std::sync::Arc<dyn DispatchHandler>,
    ) -> Result<TunInboundHandler, PluginError> {
        // StackOptions 含 tun 设备 trait object 不可 Clone：观察面产物在
        // handler 构建期做数据字段重建（设备本体仍由 start() 经
        // TunDevice::create 硬编码创建，OS 面语义不变）。
        let options = self
            .built_config()
            .map(options_for_handler)
            .map_err(|e| PluginError::Other(Box::new(e)))?;
        TunInboundHandler::new(tag, options, dispatch)
            .await
            .map_err(|e| PluginError::Other(Box::new(e)))
    }
}

impl Plugin for TunPlugin {
    fn name(&self) -> &'static str {
        "tun"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn deps(&self) -> &'static [PluginDep] {
        &[]
    }

    fn contract(&self) -> &PluginContract {
        &TUN_CONTRACT
    }

    fn lifecycle(&self) -> &dyn Lifecycle {
        &TUN_LIFECYCLE
    }

    fn build(&self, ctx: &mut PluginContext) -> Result<(), PluginError> {
        let options = parse_tun_section(ctx.section()?)?;
        self.options
            .set(options)
            .map_err(|_| PluginError::Other("tun plugin built twice (assembly bug)".into()))?;
        Ok(())
    }
}

/// TUN 生命周期三相：插件级无在途异步任务 / 无外部资源，三相直通。
/// 连接级 driver task（TUN 设备 pump + smoltcp poll + UDP sweep）的托管
/// （坑约束 5/6 运行时半边）属 [`TunInboundHandler`] 实例面（既有行为；
/// FxScope/ShutdownCoordinator 接线随 P3 入口收口统一迁移）。设备创建与
/// netstack 本体在 TUN-OS-FROZEN 冻结范围内，禁在此层包装。
pub struct TunLifecycle;

impl Lifecycle for TunLifecycle {
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

/// per-plugin 段 → [`StackOptions`]（段无 `settings` 时退化用段本体，
/// socks/freedom/dns 同款约定）。
///
/// 同规 xray-core `inbound.rs::parse_tun_inbound_config`（权威生产解析：
/// `StackOptions::parse_json` + 占位设备注入；JSON 字段与默认值对齐 Go
/// `infra/conf/tun.go::TunConfig.Build`，含 config.rs:173-176 MTU 冻结校验）。
/// 与 core 解析面的收敛属 P3 入口收口，此处不回头改 core。
fn parse_tun_section(section: &serde_json::Value) -> Result<StackOptions, PluginError> {
    let settings = section.get("settings").unwrap_or(section);
    let data = serde_json::to_vec(settings)
        .map_err(|e| PluginError::Other(format!("tun plugin: settings serialize: {e}").into()))?;
    let mut opts = StackOptions::parse_json(&data)
        .map_err(|e| PluginError::Other(format!("tun plugin: {e}").into()))?;
    opts.tun = Some(Box::new(PlaceholderDevice));
    Ok(opts)
}

/// 满足 [`TunInboundHandler`] 存在性校验的占位设备（同规 xray-core
/// `inbound.rs::TunPlaceholder`：`TunInboundHandler::new` 校验
/// `options.tun.is_some()`，而 `start()` 内部经 `TunDevice::create` 硬编码
/// 参数真实创建设备、不消费该对象——OS 面语义不变）。
struct PlaceholderDevice;

impl Tun for PlaceholderDevice {
    fn start(&self) -> crate::Result<()> {
        Ok(())
    }

    fn close(&self) -> crate::Result<()> {
        Ok(())
    }

    fn name(&self) -> crate::Result<String> {
        Ok("placeholder".into())
    }

    fn index(&self) -> crate::Result<i32> {
        Ok(0)
    }
}

/// 观察面产物 → handler 构建用 owned 选项（数据字段逐一搬运 + 重新注入
/// [`PlaceholderDevice`]；`StackOptions` 含 trait object 不可 Clone，字段
/// 列举由编译器穷尽性保证不漏）。
fn options_for_handler(src: &StackOptions) -> StackOptions {
    StackOptions {
        tun: Some(Box::new(PlaceholderDevice)),
        idle_timeout: src.idle_timeout,
        name: src.name.clone(),
        desc: src.desc.clone(),
        mtu: src.mtu,
        gateway: src.gateway.clone(),
        dns: src.dns.clone(),
        user_level: src.user_level,
        auto_system_routing_table: src.auto_system_routing_table.clone(),
        auto_outbounds_interface: src.auto_outbounds_interface.clone(),
        auto_system_dns_to_gateway: src.auto_system_dns_to_gateway,
        auto_system_wfp_block_leak: src.auto_system_wfp_block_leak.clone(),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::json;

    use super::*;

    #[test]
    fn section_defaults_match_core() {
        let opts = parse_tun_section(&json!({ "settings": {} })).expect("empty settings");
        assert_eq!(opts.name, "xray0"); // Go tun.go:34-36
        assert_eq!(opts.mtu, 1500); // Go tun.go:37-39
        assert_eq!(opts.desc, "Wintun");
        assert_eq!(opts.idle_timeout, Duration::from_secs(30));
        assert!(opts.gateway.is_empty() && opts.dns.is_empty());
        let device = opts.tun.expect("占位设备注入");
        assert_eq!(device.name().expect("name"), "placeholder");
    }

    #[test]
    fn section_full_fields() {
        // autoSystemWfpBlockLeak 是 Windows 专有机制（config.rs 平台分支），
        // 非 Windows 传非空值必须拒启 → 全字段用例按平台裁剪，Linux CI 才能过
        // （run 40050627499 实证：无条件带上该键 → xray-proxy-tun lib 测试红）。
        let mut settings = json!({
            "name": "utun10",
            "desc": "TestDesc",
            "mtu": 1280,
            "gateway": ["172.16.0.1/24", "fd00::1/64"],
            "dns": ["1.1.1.1"],
            "userLevel": 2,
            "autoSystemRoutingTable": ["60"],
            "autoOutboundsInterface": "auto",
            "autoSystemDnsToGateway": true
        });
        if cfg!(windows) {
            settings["autoSystemWfpBlockLeak"] = json!(["dns"]);
        }
        let opts = parse_tun_section(&settings).expect("full settings");
        assert_eq!(opts.name, "utun10");
        assert_eq!(opts.desc, "TestDesc");
        assert_eq!(opts.mtu, 1280);
        assert_eq!(opts.gateway, vec!["172.16.0.1/24".to_string(), "fd00::1/64".to_string()]);
        assert_eq!(opts.dns, vec!["1.1.1.1".to_string()]);
        assert_eq!(opts.user_level, 2);
        assert_eq!(opts.auto_system_routing_table, vec!["60".to_string()]);
        assert_eq!(opts.auto_outbounds_interface.as_deref(), Some("auto"));
        assert!(opts.auto_system_dns_to_gateway);
        if cfg!(windows) {
            assert_eq!(opts.auto_system_wfp_block_leak, vec!["dns".to_string()]);
        } else {
            assert!(opts.auto_system_wfp_block_leak.is_empty(), "非 Windows 平台该键不可用");
        }
    }

    #[test]
    fn section_mtu_overflow_fails_visible() {
        // 冻结校验复用（config.rs:173-176，TUN-OS-FROZEN 零重实现）：越界
        // 必须报错，禁饱和截断。match 解包：expect_err 需 Ok 侧 Debug，
        // StackOptions 含 trait object 无 Debug（禁区文件不加 derive）。
        let err = match parse_tun_section(&json!({ "settings": { "mtu": 70000 } })) {
            Ok(_) => panic!("mtu 越界必须 fail-visible"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("65535"), "{err}");
    }

    #[test]
    fn options_for_handler_rebuilds_with_placeholder() {
        let opts = parse_tun_section(&json!({ "settings": { "name": "tun0", "mtu": 1400 } }))
            .expect("parse");
        let rebuilt = options_for_handler(&opts);
        assert_eq!(rebuilt.name, "tun0");
        assert_eq!(rebuilt.mtu, 1400);
        assert!(rebuilt.tun.is_some());
    }
}
