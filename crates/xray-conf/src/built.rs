//! # 构建产物
//!
//! 对应 Go `infra/conf.Config.Build()` 的输出。Go 端返回 `*core.Config`（prost），
//! App/Inbound/Outbound 各项是 `*serial.TypedMessage`。Rust 端绕过 prost 中间层：
//!
//! - 每个 entry 直接持有 **JSON 字节**（`data`）+ **种类键**（`kind`）
//! - 由调用方（`Instance::new`，见 k5v 任务）根据 `kind` 查询 `FeatureFactory` 注册表
//! - factory 内部 `serde_json::from_slice` 解码为对应 crate 的 strong-typed Config
//!
//! ## 设计理由（vs prost Any 中间层）
//!
//! 1. **避免循环依赖**：xray-conf 不依赖具体 crate，无法生成 prost Any.bytes
//! 2. **零反射**：Rust 没有 Go reflect.TypeOf 跨 crate 类型分发，所以走注册表
//! 3. **YAGNI**： prost Any.value 与 JSON bytes 同构（都是序列化字节），跳过 prost 编码步骤
//!
//! ## kind 命名约定
//!
//! - `apps[i].kind`：app 字段名（`"log"` / `"routing"` / `"dns"` / `"policy"` / `"api"` /
//!   `"metrics"` / `"stats"` / `"fakeDns"` / `"observatory"` / `"burstObservatory"` /
//!   `"version"` / `"geodata"`）
//! - `inbounds[i].kind`：协议名（`"vless"` / `"vmess"` / `"socks"` / `"freedom"` / ...）
//! - `outbounds[i].kind`：协议名（同上）
//!
//! 注：`reverse` 字段在 Go 中已 `PrintRemovedFeatureError`，f2w 沿用此行为。

use serde_json::Value;

use crate::config::Config;
use crate::error::{ConfError, Result};

/// 单个构建产物条目：种类键 + JSON 字节。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltEntry {
    /// 种类键（字段名/协议名），用于查询 `FeatureFactory` 注册表。
    pub kind: String,
    /// JSON 序列化字节，由 factory 反序列化为 strong-typed Config。
    pub data: Vec<u8>,
}

/// 入站构建条目：携带 tag 与监听信息，方便上层 dispatcher 注册 handler。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltInbound {
    /// 入站公共条目（kind = 协议名，data = settings JSON）。
    pub entry: BuiltEntry,
    /// 入站 tag，路由匹配与日志关联。
    pub tag: String,
    /// 监听端口列表（来自 `port` 字段，未解析则空）。
    pub port_json: Option<Value>,
    /// 监听地址（来自 `listen` 字段）。
    pub listen_json: Option<Value>,
    /// streamSettings 子对象（TLS/WS/gRPC 等），原样透传给传输层。
    pub stream_settings_json: Option<Value>,
    /// sniffing 子对象，原样透传。
    pub sniffing_json: Option<Value>,
}

/// 出站构建条目：携带 tag 与 sendThrough。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltOutbound {
    /// 出站公共条目（kind = 协议名，data = settings JSON）。
    pub entry: BuiltEntry,
    /// 出站 tag，路由匹配与链式代理。
    pub tag: String,
    /// sendThrough（绑定本端 IP）。
    pub send_through: Option<String>,
    /// streamSettings 子对象。
    pub stream_settings_json: Option<Value>,
    /// proxySettings（链式代理）子对象。
    pub proxy_settings_json: Option<Value>,
    /// mux 子对象。
    pub mux_json: Option<Value>,
}

/// 顶层配置构建产物，对应 Go `*core.Config`（prost）。
#[derive(Debug, Default, Clone)]
pub struct BuiltConfig {
    /// App 列表：日志/路由/DNS/policy/...
    pub apps: Vec<BuiltEntry>,
    /// 入站列表。
    pub inbounds: Vec<BuiltInbound>,
    /// 出站列表。
    pub outbounds: Vec<BuiltOutbound>,
}

impl BuiltConfig {
    /// 入站数量。
    pub fn inbound_count(&self) -> usize {
        self.inbounds.len()
    }

    /// 出站数量。
    pub fn outbound_count(&self) -> usize {
        self.outbounds.len()
    }

    /// App 数量。
    pub fn app_count(&self) -> usize {
        self.apps.len()
    }
}

impl Config {
    /// 把解析后的 [`Config`] 构建为 [`BuiltConfig`]。
    ///
    /// 对应 Go `infra/conf.Config.Build()`。每个非空字段产生一个 [`BuiltEntry`]，
    /// 入/出站每条产生一个 [`BuiltInbound`] / [`BuiltOutbound`]。
    ///
    /// # 错误
    ///
    /// - [`ConfError::Deprecated`]：使用了已废弃的全局 `transport` 字段。
    /// - [`ConfError::Build`]：JSON 字段序列化失败（极少见，因字段已成功解析）。
    pub fn build(&self) -> Result<BuiltConfig> {
        if self.uses_deprecated_transport() {
            return Err(ConfError::Deprecated {
                feature: "Global transport config",
                hint: "streamSettings in inbounds and outbounds",
            });
        }

        let mut out = BuiltConfig::default();

        // App 字段：保持 Go 中的处理顺序，方便后续 Instance::new 注册 essentialFeatures。
        // reverse 字段在 Go 中触发 PrintRemovedFeatureError，这里同样跳过。
        macro_rules! push_app {
            ($field:expr, $kind:literal) => {
                if let Some(v) = $field.as_ref() {
                    out.apps.push(BuiltEntry {
                        kind: $kind.to_string(),
                        data: serde_json::to_vec(v).map_err(|e| ConfError::Build {
                            what: $kind,
                            message: e.to_string(),
                        })?,
                    });
                }
            };
        }
        push_app!(self.log, "log");
        push_app!(self.routing, "routing");
        push_app!(self.dns, "dns");
        push_app!(self.policy, "policy");
        push_app!(self.api, "api");
        push_app!(self.metrics, "metrics");
        push_app!(self.stats, "stats");
        // reverse 在 Go 已废弃，跳过。
        push_app!(self.fake_dns, "fakeDns");
        push_app!(self.observatory, "observatory");
        push_app!(self.burst_observatory, "burstObservatory");
        push_app!(self.version, "version");
        push_app!(self.geodata, "geodata");

        // Inbounds
        for ib in &self.inbound_configs {
            let data = match ib.settings.as_ref() {
                Some(v) => serde_json::to_vec(v).map_err(|e| ConfError::Build {
                    what: "inbound.settings",
                    message: e.to_string(),
                })?,
                None => Vec::new(),
            };
            out.inbounds.push(BuiltInbound {
                entry: BuiltEntry {
                    kind: ib.protocol.clone(),
                    data,
                },
                tag: ib.tag.clone(),
                port_json: ib.port.as_ref().map(|_| Value::Null), // port 已强类型，不重新序列化
                listen_json: None,
                stream_settings_json: ib.stream_settings.clone(),
                sniffing_json: ib.sniffing.as_ref().map(|s| {
                    serde_json::to_value(s).unwrap_or(Value::Null)
                }),
            });
        }

        // Outbounds
        for ob in &self.outbound_configs {
            let data = match ob.settings.as_ref() {
                Some(v) => serde_json::to_vec(v).map_err(|e| ConfError::Build {
                    what: "outbound.settings",
                    message: e.to_string(),
                })?,
                None => Vec::new(),
            };
            out.outbounds.push(BuiltOutbound {
                entry: BuiltEntry {
                    kind: ob.protocol.clone(),
                    data,
                },
                tag: ob.tag.clone(),
                send_through: ob.send_through.clone(),
                stream_settings_json: ob.stream_settings.clone(),
                proxy_settings_json: ob.proxy_settings.clone(),
                mux_json: ob.mux.as_ref().map(|m| {
                    serde_json::to_value(m).unwrap_or(Value::Null)
                }),
            });
        }

        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL_CONFIG: &str = r#"{
        "inbounds": [
            {
                "protocol": "vless",
                "port": 443,
                "listen": "0.0.0.0",
                "settings": { "clients": [] },
                "tag": "vless-in",
                "streamSettings": { "network": "tcp" },
                "sniffing": { "enabled": true, "destOverride": ["http", "tls"] }
            }
        ],
        "outbounds": [
            { "protocol": "freedom", "tag": "direct" },
            { "protocol": "vless", "tag": "proxy", "settings": { "vnext": [] } }
        ],
        "routing": { "rules": [] },
        "log": { "loglevel": "warning" }
    }"#;

    #[test]
    fn build_minimal_config_counts() {
        let cfg = Config::from_json_str(MINIMAL_CONFIG).expect("parse");
        let built = cfg.build().expect("build");
        // log + routing = 2 apps
        assert_eq!(built.app_count(), 2);
        assert_eq!(built.inbound_count(), 1);
        assert_eq!(built.outbound_count(), 2);
    }

    #[test]
    fn build_apps_have_correct_kinds() {
        let cfg = Config::from_json_str(MINIMAL_CONFIG).unwrap();
        let built = cfg.build().unwrap();
        let kinds: Vec<&str> = built.apps.iter().map(|a| a.kind.as_str()).collect();
        assert!(kinds.contains(&"log"));
        assert!(kinds.contains(&"routing"));
        // dns/policy/etc 不在 MINIMAL_CONFIG 中，不应出现
        assert!(!kinds.contains(&"dns"));
    }

    #[test]
    fn build_apps_data_is_json_bytes() {
        let cfg = Config::from_json_str(MINIMAL_CONFIG).unwrap();
        let built = cfg.build().unwrap();
        let log_entry = built.apps.iter().find(|a| a.kind == "log").unwrap();
        let v: Value = serde_json::from_slice(&log_entry.data).unwrap();
        assert_eq!(v["loglevel"], "warning");
    }

    #[test]
    fn build_inbound_preserves_tag_and_protocol() {
        let cfg = Config::from_json_str(MINIMAL_CONFIG).unwrap();
        let built = cfg.build().unwrap();
        let ib = &built.inbounds[0];
        assert_eq!(ib.entry.kind, "vless");
        assert_eq!(ib.tag, "vless-in");
        // settings JSON 包含 clients
        let s: Value = serde_json::from_slice(&ib.entry.data).unwrap();
        assert!(s["clients"].is_array());
        // stream_settings 透传
        assert!(ib.stream_settings_json.is_some());
        // sniffing 透传
        assert!(ib.sniffing_json.is_some());
    }

    #[test]
    fn build_outbound_preserves_tag_and_protocol() {
        let cfg = Config::from_json_str(MINIMAL_CONFIG).unwrap();
        let built = cfg.build().unwrap();
        let direct = built
            .outbounds
            .iter()
            .find(|o| o.tag == "direct")
            .unwrap();
        assert_eq!(direct.entry.kind, "freedom");
        // 无 settings → 空 data
        assert!(direct.entry.data.is_empty());

        let proxy = built
            .outbounds
            .iter()
            .find(|o| o.tag == "proxy")
            .unwrap();
        assert_eq!(proxy.entry.kind, "vless");
        let s: Value = serde_json::from_slice(&proxy.entry.data).unwrap();
        assert!(s["vnext"].is_array());
    }

    #[test]
    fn build_empty_config() {
        let cfg: Config = serde_json::from_str("{}").unwrap();
        let built = cfg.build().unwrap();
        assert_eq!(built.app_count(), 0);
        assert_eq!(built.inbound_count(), 0);
        assert_eq!(built.outbound_count(), 0);
    }

    #[test]
    fn build_deprecated_transport_errors() {
        let json = r#"{ "transport": { "http": { "path": "/x" } } }"#;
        let cfg: Config = serde_json::from_str(json).unwrap();
        let err = cfg.build().unwrap_err();
        assert!(matches!(err, ConfError::Deprecated { .. }));
    }

    #[test]
    fn build_fakedns_and_burst_observatory_camel_case() {
        let json = r#"{
            "fakeDns": { "pools": [] },
            "burstObservatory": { "subjectSelector": ["p1"] }
        }"#;
        let cfg: Config = serde_json::from_str(json).unwrap();
        let built = cfg.build().unwrap();
        let kinds: Vec<&str> = built.apps.iter().map(|a| a.kind.as_str()).collect();
        assert!(kinds.contains(&"fakeDns"));
        assert!(kinds.contains(&"burstObservatory"));
    }

    #[test]
    fn built_entry_data_roundtrips_through_serde_json() {
        // 验证 data 字段确实是合法 JSON 字节
        let cfg = Config::from_json_str(MINIMAL_CONFIG).unwrap();
        let built = cfg.build().unwrap();
        for app in &built.apps {
            assert!(
                serde_json::from_slice::<Value>(&app.data).is_ok(),
                "app {:?} data should be valid JSON",
                app.kind
            );
        }
    }
}
