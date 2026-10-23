//! Loopback 协议插件（P1-8，五层强约束第二个全层试点——验证 P1-7 骨架可复用：
//! 换协议不改骨架）。
//!
//! 五层映射（与 blackhole 样板同构）：
//! - **L1**：[`LoopbackPlugin`] 实现必选方法集（name/version/deps/contract/
//!   lifecycle/build），缺一编译不过。
//! - **L2**：能力只经 `PluginContext` 取——build 期 `ctx.section()` 读 per-plugin 段（缺段
//!   fail-fast，坑约束 7 装配半边）；loopback 不取 `ctx.pool()`（转发
//!   面零改动，池纪律条款按"全适用"声明、能力暂不消费，见 `LOOPBACK_CONTRACT`）。
//! - **L3**：无裸能力（无 println/裸 spawn/裸 sleep）。
//! - **L4**：`assert_plugin_contract!(LoopbackPlugin)`（tests/plugin_contract.rs）。
//! - **L5**：装配门——缺段 / 缺 `inboundTag` → build `Err` → 整链 fail-visible。
//!
//! 与 blackhole 样板的两处协议差：
//! - **deps = []**（拍板 P1-8.1）：loopback 对 dispatcher 的回环依赖**运行期
//!   查表**解决——[`crate::LoopbackSink`] 经 `with_sink` 注入（生产装配 functions.rs 注入
//!   `DispatcherLoopbackSink`）；静态依赖声明成环 = 拓扑序 死锁。
//! - **sniffing 不在本面解析**：完整语义（destOverride 别名归一 / domainsExcluded / ipsExcluded 的
//!   geodata matcher 与资产目录）权威在 xray-core wiring
//!   （`sniffing_request_from_json`），本面零复制；P2 切换时装配侧经 `with_sniffing_request` 注入。
//!
//! 转发零改动（LB-1 / 坑约束 12）：handler 产出仍走 lib.rs 既有构造
//! （`with_inbound_tag`），dispatch/dial 链路与转发字节逐字节不变——锁定见
//! tests/plugin_contract.rs 的 LB-1 字节冻结测试。

use std::sync::OnceLock;

use xray_frame::{
    ClauseId, Lifecycle, Plugin, PluginContract, PluginDep, PluginError, context::PluginContext,
};

use crate::LoopbackHandler;

/// 通用条款适用子集——loopback 走真实数据面转发，坑约束 1-12 **全适用**
/// （含坑约束 4 池纪律与坑约束 12 热路径冻结；零 N/A 声明）。
static LOOPBACK_CLAUSES: &[ClauseId] = &[
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

/// 协议专属条款（LB-1：回环转发不经外部网络，转发字节原样零改写——黑盒锁定
/// 见 tests/plugin_contract.rs 的字节冻结测试）。
static LOOPBACK_EXTRA: &[(&str, &str)] = &[("LB-1", "回环转发不经外部网络；转发字节原样零改写")];

static LOOPBACK_CONTRACT: PluginContract =
    PluginContract { clauses: LOOPBACK_CLAUSES, extra: LOOPBACK_EXTRA, not_applicable: &[] };

static LOOPBACK_LIFECYCLE: LoopbackLifecycle = LoopbackLifecycle;

/// Loopback 协议插件（L1 必选方法集全量）。
///
/// `build(ctx)` 从 per-plugin 段（`outbounds[]/inbounds[]` 内
/// `protocol == "loopback"` 的元素）解析 `settings.inboundTag` 并持有；出/入站
/// handler 经 [`handler`](LoopbackPlugin::handler) 由插件产出（loopback 是
/// outbound-only 协议，入站侧为 no-op 占位注册，同 Go 无 inbound；tag 属实例
/// 注册期信息，不在 build 期定）。
#[derive(Debug, Default)]
pub struct LoopbackPlugin {
    /// build 期解析产物（装配根单线程 build → OnceLock 单写安全）。
    inbound_tag: OnceLock<String>,
}

impl LoopbackPlugin {
    /// build 产物观察面；build 前调用 → `Err`（fail-visible）。
    pub fn built_inbound_tag(&self) -> Result<&str, PluginError> {
        self.inbound_tag.get().map(String::as_str).ok_or_else(|| {
            PluginError::Other("loopback plugin not built yet (build must run first)".into())
        })
    }

    /// 插件产出：出/入站 handler（loopback 两向同为 [`LoopbackHandler`]——
    /// 出站=回环转发，入站=no-op 占位；既有构造与行为不变）。
    pub fn handler(&self, tag: &str) -> Result<LoopbackHandler, PluginError> {
        Ok(LoopbackHandler::with_inbound_tag(tag, self.built_inbound_tag()?.to_owned()))
    }
}

impl Plugin for LoopbackPlugin {
    fn name(&self) -> &'static str {
        "loopback"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn deps(&self) -> &'static [PluginDep] {
        // 拍板 P1-8.1：不声明 deps——对 dispatcher 的回环依赖运行期查表
        // （LoopbackSink 注入），静态依赖声明成环 = 拓扑序死锁。
        &[]
    }

    fn contract(&self) -> &PluginContract {
        &LOOPBACK_CONTRACT
    }

    fn lifecycle(&self) -> &dyn Lifecycle {
        &LOOPBACK_LIFECYCLE
    }

    fn build(&self, ctx: &mut PluginContext) -> Result<(), PluginError> {
        let inbound_tag = parse_section(ctx.section()?)?;
        self.inbound_tag
            .set(inbound_tag)
            .map_err(|_| PluginError::Other("loopback plugin built twice (assembly bug)".into()))?;
        Ok(())
    }
}

/// Loopback 生命周期三相：无在途异步任务 / 无外部资源，三相直通（dispatch
/// future 交调用方 await，生产 spawn 归 dispatcher；stop 的注册由装配门强制，
/// 本体幂等）。
pub struct LoopbackLifecycle;

impl Lifecycle for LoopbackLifecycle {
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

/// per-plugin 段 → 目标 inbound tag。
///
/// xray JSON 布局：`{"settings": {"inboundTag": "..."}}`（无 `settings` 时退化
/// 用段本体）。presence 校验与 xray-core `parse_loopback_config` 同规
/// （src/outbound.rs）；**空 tag 硬拒**对齐 Go `Loopback.init`
/// （proxy/loopback/loopback.go：`InboundTag == "" → newError`）——插件面是
/// 新路径，config 边界 fail-fast，不改既有构造面（构造器仍允许空 tag，见
/// lib.rs 既有单测）。sniffing 不解析，见模块文档。
fn parse_section(section: &serde_json::Value) -> Result<String, PluginError> {
    let settings = section.get("settings").unwrap_or(section);
    let inbound_tag = settings
        .get("inboundTag")
        .and_then(|v| v.as_str())
        .ok_or_else(|| PluginError::Other("loopback: missing settings.inboundTag".into()))?;
    if inbound_tag.is_empty() {
        return Err(PluginError::Other(
            "loopback: settings.inboundTag is empty (Go Loopback.init rejects empty tag)".into(),
        ));
    }
    Ok(inbound_tag.to_owned())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn section_parses_inbound_tag() {
        let section = json!({"protocol": "loopback", "settings": {"inboundTag": "in-main"}});
        assert_eq!(parse_section(&section).expect("ok"), "in-main");
    }

    #[test]
    fn section_missing_settings_fails_visible() {
        let section = json!({"protocol": "loopback"});
        let err = parse_section(&section).expect_err("missing settings must fail");
        assert!(err.to_string().contains("inboundTag"), "错误必须携带键名: {err}");
    }

    #[test]
    fn section_missing_inbound_tag_fails_visible() {
        let section = json!({"settings": {"sniffing": {"enabled": true}}});
        let err = parse_section(&section).expect_err("missing inboundTag must fail");
        assert!(err.to_string().contains("inboundTag"), "错误必须携带键名: {err}");
    }

    #[test]
    fn section_empty_inbound_tag_rejected_go_parity() {
        let section = json!({"settings": {"inboundTag": ""}});
        let err = parse_section(&section).expect_err("Go Loopback.init rejects empty tag");
        assert!(err.to_string().contains("empty"), "错误必须标明空 tag: {err}");
    }

    #[test]
    fn built_observer_fails_before_build() {
        let plugin = LoopbackPlugin::default();
        let err = plugin.built_inbound_tag().expect_err("not built yet");
        assert!(err.to_string().contains("not built yet"), "实际: {err}");
    }
}
