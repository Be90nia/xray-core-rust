//! Blackhole 协议插件（P1-7，五层强约束首个实证件）。
//!
//! 五层映射：
//! - **L1**：[`BlackholePlugin`] 实现必选方法集（name/version/deps/contract/
//!   lifecycle/build），缺一编译不过。
//! - **L2**：能力只经 [`PluginContext`] 取——build 期 `ctx.section()` 读 per-plugin 段（缺段
//!   fail-fast，坑约束 7 装配半边）；blackhole 不取 `ctx.pool()`（坑约束 4 按 N/A 声明，见
//!   [`BLACKHOLE_CONTRACT`]）。
//! - **L3**：无裸能力（无 println/裸 spawn/裸 sleep）。
//! - **L4**：`assert_plugin_contract!(BlackholePlugin)`（tests/plugin_contract.rs）。
//! - **L5**：装配门——缺段 / 未知 response type / base64 解码失败 → build `Err` → 整链
//!   fail-visible（tests/plugin_assembly.rs）。
//!
//! wire 零改动：响应体构造仍走 `response.rs`（[`HTTP_403_RESPONSE`] 常量与
//! [`get_internal_response`] 解析语义原样复用），Http403 字节形态逐字节不变。

use std::sync::OnceLock;

use base64::Engine as _;
use xray_frame::{
    ClauseId, Lifecycle, Plugin, PluginContract, PluginDep, PluginError, context::PluginContext,
};
use xray_proto::xray::proxy::blackhole::Config;

use crate::{
    BlackholeError,
    dispatcher::BlackholeHandler,
    inbound::BlackholeInboundHandler,
    response::{ResponseConfig, get_internal_response, proto_response},
};

/// 通用条款适用子集（坑约束 1/2/3/5/6/7/8/9/10/11；4 = [`ClauseId::PoolDiscipline`]
/// 走 [`BLACKHOLE_NOT_APPLICABLE`] 声明）。
static BLACKHOLE_CLAUSES: &[ClauseId] = &[
    ClauseId::AuthErrorClassified,
    ClauseId::HandshakeDeadline,
    ClauseId::ConnIdPresent,
    ClauseId::SpawnManaged,
    ClauseId::StopRegistered,
    ClauseId::ConfigSectionOnly,
    ClauseId::ErrorClassifiedNoPanicEscape,
    ClauseId::BoundedResources,
    ClauseId::LogDiscipline,
    ClauseId::SecretMasking,
];

/// 协议专属条款（BH-1：响应体字节形态 Go 兼容恒定——黑盒锁定见
/// tests/plugin_contract.rs 的逐字节 fixture 比对）。
static BLACKHOLE_EXTRA: &[(&str, &str)] = &[("BH-1", "Http403 响应体字节形态恒定（Go 兼容）")];

/// N/A 声明（P1-7 拍板 P2.2：允许声明不适用但必须带非空理由）。
static BLACKHOLE_NOT_APPLICABLE: &[(ClauseId, &str)] = &[(
    ClauseId::PoolDiscipline,
    "blackhole 零缓冲分配：drain 逐帧丢弃、预置响应单次整写，全路径无缓冲池消费点",
)];

static BLACKHOLE_CONTRACT: PluginContract = PluginContract {
    clauses: BLACKHOLE_CLAUSES,
    extra: BLACKHOLE_EXTRA,
    not_applicable: BLACKHOLE_NOT_APPLICABLE,
};

static BLACKHOLE_LIFECYCLE: BlackholeLifecycle = BlackholeLifecycle;

/// Blackhole 协议插件（L1 必选方法集全量）。
///
/// `build(ctx)` 从 per-plugin 段（`outbounds[]/inbounds[]` 内
/// `protocol == "blackhole"` 的元素）解析 `settings.response` →
/// [`ResponseConfig`] 并持有；出/入站 handler 经
/// [`dispatch_handler`](BlackholePlugin::dispatch_handler) /
/// [`inbound_handler`](BlackholePlugin::inbound_handler) 由插件产出
/// （tag/listen 属实例注册期信息，不在 build 期定）。
#[derive(Debug, Default)]
pub struct BlackholePlugin {
    /// build 期解析产物（装配根单线程 build → OnceLock 单写安全）。
    response: OnceLock<ResponseConfig>,
}

impl BlackholePlugin {
    /// build 产物观察面；build 前调用 → `Err`（fail-visible）。
    pub fn built_response(&self) -> Result<&ResponseConfig, PluginError> {
        self.response.get().ok_or_else(|| {
            PluginError::Other("blackhole plugin not built yet (build must run first)".into())
        })
    }

    /// 插件产出：出站 handler（[`BlackholeHandler`] 的既有 `DispatchHandler`
    /// 实现与行为不变，配置改由插件 build 解析注入）。
    pub fn dispatch_handler(&self, tag: &str) -> Result<BlackholeHandler, PluginError> {
        Ok(BlackholeHandler::with_response(tag, self.built_response()?.clone()))
    }

    /// 插件产出：入站 handler（`InboundHandler` 实现不变）。
    pub fn inbound_handler(
        &self,
        tag: &str,
        listen_addr: &str,
    ) -> Result<BlackholeInboundHandler, PluginError> {
        Ok(BlackholeInboundHandler::new(tag, self.built_response()?.clone(), listen_addr))
    }
}

impl Plugin for BlackholePlugin {
    fn name(&self) -> &'static str {
        "blackhole"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn deps(&self) -> &'static [PluginDep] {
        &[]
    }

    fn contract(&self) -> &PluginContract {
        &BLACKHOLE_CONTRACT
    }

    fn lifecycle(&self) -> &dyn Lifecycle {
        &BLACKHOLE_LIFECYCLE
    }

    fn build(&self, ctx: &mut PluginContext) -> Result<(), PluginError> {
        let response = parse_response_section(ctx.section()?)?;
        self.response.set(response).map_err(|_| {
            PluginError::Other("blackhole plugin built twice (assembly bug)".into())
        })?;
        Ok(())
    }
}

/// Blackhole 生命周期三相：无在途异步任务 / 无外部资源，三相直通
/// （stop 的注册由装配门强制，本体幂等）。
pub struct BlackholeLifecycle;

impl Lifecycle for BlackholeLifecycle {
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

/// per-plugin 段 → [`ResponseConfig`]。
///
/// xray JSON 布局：`{"settings": {"response": {"type": "http",
/// "customResponseData": "<base64>"}}}`（无 `settings` 时退化用段本体）。
/// `customResponseData` base64 标准解码对齐 Go conf 层（Go :38-42，解码失败
/// 硬错）；type 的运行时解析权威仍是 [`get_internal_response`]（精确匹配，
/// 单份实现不复制）。与 `xray-conf` 的 `parse_blackhole_response` 同规；
/// conf 层收敛到本解析面属 P2 迁移，此处不回头改 conf。
fn parse_response_section(section: &serde_json::Value) -> Result<ResponseConfig, PluginError> {
    let settings = section.get("settings").unwrap_or(section);
    let response = settings.get("response");
    let (ty, data) = match response {
        None => (String::new(), Vec::new()),
        Some(resp) => {
            let ty = resp.get("type").and_then(|t| t.as_str()).unwrap_or_default().to_owned();
            let data = match resp.get("customResponseData").and_then(|d| d.as_str()) {
                Some(raw) => {
                    base64::engine::general_purpose::STANDARD.decode(raw).map_err(|e| {
                        PluginError::Other(
                            format!("blackhole customResponseData base64 decode failed: {e}")
                                .into(),
                        )
                    })?
                },
                None => Vec::new(),
            };
            (ty, data)
        },
    };
    let config = Config { response: Some(proto_response(ty, data)) };
    get_internal_response(&config).map_err(|e: BlackholeError| PluginError::Other(Box::new(e)))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn section_none_when_response_missing() {
        let section = json!({"protocol": "blackhole", "settings": {}});
        let parsed = parse_response_section(&section).expect("empty settings → None");
        assert_eq!(parsed, ResponseConfig::None);
    }

    #[test]
    fn section_http_type_maps_to_http403() {
        let section = json!({"protocol": "blackhole", "settings": {"response": {"type": "http"}}});
        let parsed = parse_response_section(&section).expect("http type → Http403");
        assert_eq!(parsed, ResponseConfig::Http403);
    }

    #[test]
    fn section_custom_type_decodes_base64() {
        // "eHlheQ==" = "xyay" 的 base64（Go conf 层同规标准表）。
        let section = json!({
            "settings": {
                "response": {"type": "custom", "customResponseData": "eHlheQ=="}
            }
        });
        let parsed = parse_response_section(&section).expect("custom type → Custom(bytes)");
        assert_eq!(parsed, ResponseConfig::Custom(b"xyay".to_vec()));
    }

    #[test]
    fn section_unknown_type_fails_visible() {
        let section = json!({"settings": {"response": {"type": "!!!mystery"}}});
        let err = parse_response_section(&section).expect_err("unknown type must fail");
        assert!(err.to_string().contains("mystery"), "错误必须携带未知 type: {err}");
    }

    #[test]
    fn section_bad_base64_fails_visible() {
        let section = json!({
            "settings": {
                "response": {"type": "custom", "customResponseData": "!!!not-base64!!!"}
            }
        });
        let err = parse_response_section(&section).expect_err("bad base64 must fail");
        assert!(
            err.to_string().contains("base64 decode failed"),
            "错误必须标明 base64 解码失败: {err}"
        );
    }
}
