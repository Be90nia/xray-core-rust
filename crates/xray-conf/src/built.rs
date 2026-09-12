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
//! 注：顶层 `reverse` 字段在 Go 中已 `PrintRemovedFeatureError`（removed feature），
//! Rust 端 `Config::build()` 遇 `reverse` 同样返回 `ConfError::Removed` 硬报错。

use serde_json::Value;

use crate::config::Config;
use crate::error::{ConfError, Result};
use crate::outbound_security::validate_outbound_transport_security;

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
    /// 监听端口（取 PortList 第一个 range 的起始端口）。
    pub port: Option<u16>,
    /// 监听地址（IP / Domain 字符串）。
    pub listen: Option<String>,
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
    /// 出站目标解析策略（JSON `targetStrategy`，Go `OutboundDetourConfig.TargetStrategy`）。
    ///
    /// 原样字符串；合法性已在 [`Config::build`] 校验（对齐 Go
    /// `infra/conf/xray.go:257-282` Build 时的 switch + 硬报错），
    /// 枚举转换由消费端（`xray-core`）完成。
    pub target_strategy: Option<String>,
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
    /// - [`ConfError::Removed`]：使用了全局 `transport` 字段（Go `xray.go:624-626`
    ///   PrintRemovedFeatureError）或顶层 `reverse` 字段（`xray.go:569-571`）。
    /// - [`ConfError::Build`]：JSON 字段序列化失败（极少见，因字段已成功解析）。
    pub fn build(&self) -> Result<BuiltConfig> {
        // bd 5x41/1c4z：三级严格度硬错的执行点。Go 在 decode 后、Build 前跑
        // `PostProcessConfigureFile`（allowInsecure / 已移除 transport / hysteria
        // version 等硬错都在该链触发）。Rust 的 lint 注册表此前仅测试调用
        // （生产死代码），而 build() 是所有配置的唯一生产 funnel（xray-cli
        // run.rs `load_first_config` → `Config::build`），故在此自举内置阶段
        // （register_stage 同名覆盖，幂等）并执行。阶段回调需要 `&mut Config`
        // （FakeDNS 默认池填充），而 build(&self) 不可变：在克隆体上校验，
        // 填充不回写——除新增硬错外，生产行为与既有完全一致。
        crate::init::register_builtin_stages();
        crate::lint::post_process(&mut self.clone())?;

        // Go xray.go:532-536：Build 第一步注入 env，先于后续 env:VAR 值展开。
        // SAFETY: build_config 在进程启动早期、工作线程/异步 runtime 创建之前
        // 单次调用，与 Go os.Setenv（xray.go:534）语义对齐；无并发 env 访问窗口。
        if let Some(env) = &self.env {
            for (key, value) in env {
                unsafe { std::env::set_var(key, value) };
            }
        }
        if self.uses_deprecated_transport() {
            // Go infra/conf/xray.go:624-626：Global transport config 已移除。
            return Err(ConfError::Removed {
                feature: "Global transport config",
                migrate: "streamSettings in inbounds and outbounds",
            });
        }

        // Go infra/conf/xray.go: `c.Reverse != nil` → PrintRemovedFeatureError 硬报错。
        if self.reverse.is_some() {
            return Err(ConfError::Removed {
                feature: r#""legacy reverse""#,
                migrate: r#""VLESS Reverse Proxy""#,
            });
        }
        let mut out = BuiltConfig::default();

        // App 字段：保持 Go 中的处理顺序，方便后续 Instance::new 注册 essentialFeatures。
        // reverse 已在 build() 开头报 `ConfError::Removed`（Go v26 已移除该 feature）。


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
        // reverse 在 Go v26 已移除，见 build() 开头的 ConfError::Removed 检查。
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
            // 展开 PortList 所有 range 为多个 BuiltInbound（对齐 Go 多端口监听）。
            let ports: Vec<u16> = match &ib.port {
                Some(pl) => pl.0.iter().flat_map(|r| r.start..=r.end).collect(),
                None => vec![],
            };
            // 6k4h：UDS/tun 协议可无端口（tun 用网络接口而非 socket，UDS 走 listen
            // 域套接字路径）。Go xray.go:140-168 对 tun/ListenOn 域套接字分支豁免。
            let listen_is_uds = ib
                .listen
                .as_ref()
                .map(|a| {
                    let d = a.0.as_str();
                    d.starts_with('/') || d.starts_with('@')
                })
                .unwrap_or(false);
            let portless_ok = ib.protocol.eq_ignore_ascii_case("tun") || listen_is_uds;
            if ports.is_empty() && !portless_ok {
                return Err(ConfError::Build {
                    what: "inbound.port",
                    message: format!(
                        "inbound '{}' has no port (UDS/tun: set 'listen' to a domain-socket path or protocol='tun')",
                        ib.tag
                    ),
                });
            }
            if ports.is_empty() && portless_ok {
                // UDS/tun 无端口 → 推一个占位 BuiltInbound（port=None, listen=Some），
                // 上层 listener 会按 UDS/tun 形态接管（不依赖 port 字段）。
                out.inbounds.push(BuiltInbound {
                    entry: BuiltEntry {
                        kind: ib.protocol.clone(),
                        data: data.clone(),
                    },
                    tag: ib.tag.clone(),
                    port: None,
                    listen: ib.listen.as_ref().map(|a| a.0.clone()),
                    stream_settings_json: ib.stream_settings.clone(),
                    sniffing_json: ib.sniffing.as_ref().map(|s| {
                        serde_json::to_value(s).unwrap_or(Value::Null)
                    }),
                });
                continue;
            }
            for port in ports {
                out.inbounds.push(BuiltInbound {
                    entry: BuiltEntry {
                        kind: ib.protocol.clone(),
                        data: data.clone(),
                    },
                    tag: ib.tag.clone(),
                    port: Some(port),
                    listen: ib.listen.as_ref().map(|a| a.0.clone()),
                    stream_settings_json: ib.stream_settings.clone(),
                    sniffing_json: ib.sniffing.as_ref().map(|s| {
                        serde_json::to_value(s).unwrap_or(Value::Null)
                    }),
                });
            }
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
            if let Some(s) = ob.target_strategy.as_deref() {
                if !is_valid_target_strategy(s) {
                    return Err(ConfError::Build {
                        what: "outbound.targetStrategy",
                        message: format!("unsupported target domain strategy: {s}"),
                    });
                }
            }
            // transportLayer 代理门控（bd enk，Go infra/conf/xray.go:244-252 + 316-327）：
            let (stream_settings_json, proxy_settings_json) =
                normalize_outbound_proxy(ob.stream_settings.as_ref(), ob.proxy_settings.as_ref())?;
            // 明文出站禁令（d7fa2076，对应 Go infra/conf/xray.go:245-266）：
            // vless encryption=none 或 trojan 无 TLS 且目标非私网时报错。
            validate_outbound_transport_security(
                &ob.protocol,
                &data,
                stream_settings_json.as_ref(),
            )?;
            out.outbounds.push(BuiltOutbound {
                entry: BuiltEntry {
                    kind: ob.protocol.clone(),
                    data,
                },
                tag: ob.tag.clone(),
                send_through: ob.send_through.clone(),
                stream_settings_json,
                proxy_settings_json,
                mux_json: ob.mux.as_ref().map(|m| {
                    serde_json::to_value(m).unwrap_or(Value::Null)
                }),
                target_strategy: ob.target_strategy.clone(),
            });
        }

        Ok(out)
    }
}

/// 校验 `targetStrategy` 字符串合法性（大小写不敏感）。
///
/// 对应 Go `infra/conf/xray.go:257-282`：`strings.ToLower` switch 的 11 个合法值
/// + 空串（等价 AsIs），其余 Build 硬报错。枚举转换在消费端完成（见
/// `xray_core::outbound::parse_target_strategy`）。
fn is_valid_target_strategy(s: &str) -> bool {
    matches!(
        s.to_lowercase().as_str(),
        "" | "asis"
            | "useip"
            | "useipv4"
            | "useipv6"
            | "useipv4v6"
            | "useipv6v4"
            | "forceip"
            | "forceipv4"
            | "forceipv6"
            | "forceipv4v6"
            | "forceipv6v4"
    )
}

/// proxySettings/streamSettings 的代理门控归一化（bd enk）。
///
/// 对应 Go `infra/conf/xray.go`：
/// - `checkChainProxyConfig`（:244-252）：`proxySettings.tag` 与
///   `sockopt.dialerProxy` 同时非空 → Build 硬报错（warning 级）。
/// - transportLayer 注入（:316-327）：`transportLayer: true` 时把 tag 注入
///   `sockopt.dialerProxy`（sockopt/streamSettings 不存在则创建），并清空
///   proxySettings（应用层链路 → transport 层代理）。
fn normalize_outbound_proxy(
    stream_settings: Option<&Value>,
    proxy_settings: Option<&Value>,
) -> Result<(Option<Value>, Option<Value>)> {
    let Some(ps) = proxy_settings else {
        return Ok((stream_settings.cloned(), proxy_settings.cloned()));
    };
    let tag = ps.get("tag").and_then(|v| v.as_str()).unwrap_or("");
    // 冲突检查（Go xray.go:248-250）。
    let dialer_proxy = stream_settings
        .and_then(|s| s.get("sockopt"))
        .and_then(|s| s.get("dialerProxy"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if !tag.is_empty() && !dialer_proxy.is_empty() {
        return Err(ConfError::Build {
            what: "outbound.proxySettings",
            message: "proxySettings.tag is conflicted with sockopt.dialerProxy".to_string(),
        });
    }
    // transportLayer 注入（Go xray.go:316-327）。JSON key 为 `transportLayer`
    //（Go infra/conf/transport_internet.go:2251）。
    if !ps.get("transportLayer").and_then(|v| v.as_bool()).unwrap_or(false) {
        return Ok((stream_settings.cloned(), proxy_settings.cloned()));
    }
    let mut ss = match stream_settings.cloned() {
        Some(v) if v.is_object() => v,
        _ => serde_json::json!({}),
    };
    let obj = ss.as_object_mut().expect("guarded to object");
    let sockopt = obj
        .entry("sockopt")
        .or_insert_with(|| serde_json::json!({}));
    if let Some(so) = sockopt.as_object_mut() {
        so.insert("dialerProxy".to_string(), Value::String(tag.to_string()));
    }
    Ok((Some(ss), None))
}

#[cfg(test)]
mod tests {
    use super::*;

    static ENV_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

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
    fn build_injects_env_vars() {
        // Go xray.go:532-536：Build 第一步把 env 逐 key os.Setenv 注入进程环境，
        // 使后续 env:VAR 值展开（PostProcessConfigureFile）能读到配置注入的变量。
        let _g = ENV_LOCK.lock();
        let probe = "XRAY_CONF_BUILD_ENV_PROBE";
        unsafe { std::env::remove_var(probe) };

        let cfg =
            Config::from_json_str(r#"{ "env": { "XRAY_CONF_BUILD_ENV_PROBE": "injected" } }"#)
                .unwrap();
        cfg.build().expect("build must succeed");

        assert_eq!(std::env::var(probe).as_deref(), Ok("injected"));
        unsafe { std::env::remove_var(probe) };
    }

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
    fn build_outbound_target_strategy_passthrough() {
        let json = r#"{
            "outbounds": [
                { "protocol": "freedom", "tag": "direct", "targetStrategy": "UseIP" },
                { "protocol": "freedom", "tag": "asis-out" }
            ]
        }"#;
        let cfg = Config::from_json_str(json).unwrap();
        let built = cfg.build().unwrap();
        assert_eq!(built.outbounds[0].target_strategy.as_deref(), Some("UseIP"));
        assert_eq!(built.outbounds[1].target_strategy, None);
    }

    #[test]
    fn build_outbound_target_strategy_invalid_rejected() {
        // Go infra/conf/xray.go:280-281：非法值 Build 硬报错。
        let json = r#"{
            "outbounds": [
                { "protocol": "freedom", "tag": "direct", "targetStrategy": "Nonsense" }
            ]
        }"#;
        let cfg = Config::from_json_str(json).unwrap();
        let err = cfg.build().expect_err("invalid targetStrategy must fail build");
        assert!(
            err.to_string().contains("unsupported target domain strategy"),
            "unexpected error: {err}"
        );
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
        // Go xray.go:624-626：PrintRemovedFeatureError（硬报错，文案对齐）。
        assert!(matches!(err, ConfError::Removed { .. }));
        assert_eq!(
            err.to_string(),
            "The feature Global transport config has been removed and migrated to \
             streamSettings in inbounds and outbounds. Please update your config(s) \
             according to release note and documentation."
        );
    }

    #[test]
    fn build_reverse_config_errors() {
        // Go infra/conf/xray.go: `c.Reverse != nil` → PrintRemovedFeatureError。
        let json = r#"{ "reverse": { "bridges": [ { "tag": "b", "domain": "test.example.com" } ] } }"#;
        let cfg: Config = serde_json::from_str(json).unwrap();
        let err = cfg.build().unwrap_err();
        assert!(matches!(err, ConfError::Removed { .. }));
        // 文案对齐 Go common/errors/feature_errors.go:27
        assert_eq!(
            err.to_string(),
            "The feature \"legacy reverse\" has been removed and migrated to \
             \"VLESS Reverse Proxy\". Please update your config(s) according \
             to release note and documentation."
        );
    }

    #[test]
    fn build_fakedns_and_burst_observatory_camel_case() {
        let json = r#"{
            "fakeDns": { "pools": [] },
            "burstObservatory": { "subjectSelector": ["p1"], "pingConfig": { "destination": "https://x" } }
        }"#;
        let cfg: Config = serde_json::from_str(json).unwrap();
        let built = cfg.build().unwrap();
        let kinds: Vec<&str> = built.apps.iter().map(|a| a.kind.as_str()).collect();
        assert!(kinds.contains(&"fakeDns"));
        assert!(kinds.contains(&"burstObservatory"));
    }

    // ===== transportLayer 代理门控（bd enk）=====

    /// transportLayer=true → tag 注入 sockopt.dialerProxy，proxySettings 清空。
    #[test]
    fn build_transport_layer_proxy_injects_dialer_proxy() {
        let json = r#"{
            "outbounds": [
                {
                    "protocol": "vless", "tag": "out",
                    "proxySettings": { "tag": "proxy-out", "transportLayer": true },
                    "streamSettings": { "network": "tcp", "security": "tls" }
                }
            ]
        }"#;
        let cfg: Config = serde_json::from_str(json).unwrap();
        let built = cfg.build().unwrap();
        let ob = &built.outbounds[0];
        assert!(ob.proxy_settings_json.is_none(), "proxySettings should be cleared");
        let ss = ob.stream_settings_json.as_ref().unwrap();
        assert_eq!(ss["sockopt"]["dialerProxy"], "proxy-out");
        // 已有字段保留。
        assert_eq!(ss["network"], "tcp");
        assert_eq!(ss["security"], "tls");
    }

    /// transportLayer=true 且无 streamSettings → 创建 sockopt 容器。
    #[test]
    fn build_transport_layer_proxy_without_stream_settings() {
        let json = r#"{
            "outbounds": [
                {
                    "protocol": "vless", "tag": "out",
                    "proxySettings": { "tag": "proxy-out", "transportLayer": true }
                }
            ]
        }"#;
        let cfg: Config = serde_json::from_str(json).unwrap();
        let built = cfg.build().unwrap();
        let ob = &built.outbounds[0];
        assert!(ob.proxy_settings_json.is_none());
        assert_eq!(
            ob.stream_settings_json.as_ref().unwrap()["sockopt"]["dialerProxy"],
            "proxy-out"
        );
    }

    /// transportLayer 缺省（false）→ 原样保留（应用层链路，Go xray.go:328）。
    #[test]
    fn build_plain_proxy_settings_passthrough() {
        let json = r#"{
            "outbounds": [
                {
                    "protocol": "vless", "tag": "out",
                    "proxySettings": { "tag": "proxy-out" }
                }
            ]
        }"#;
        let cfg: Config = serde_json::from_str(json).unwrap();
        let built = cfg.build().unwrap();
        assert_eq!(
            built.outbounds[0].proxy_settings_json.as_ref().unwrap()["tag"],
            "proxy-out"
        );
        assert!(built.outbounds[0].stream_settings_json.is_none());
    }

    /// proxySettings.tag 与 sockopt.dialerProxy 同时设置 → 冲突报错（Go xray.go:248-250）。
    #[test]
    fn build_tag_conflicts_with_dialer_proxy_errors() {
        let json = r#"{
            "outbounds": [
                {
                    "protocol": "vless", "tag": "out",
                    "proxySettings": { "tag": "proxy-out" },
                    "streamSettings": { "sockopt": { "dialerProxy": "other-out" } }
                }
            ]
        }"#;
        let cfg: Config = serde_json::from_str(json).unwrap();
        let err = cfg.build().unwrap_err();
        assert!(
            err.to_string().contains("conflicted"),
            "unexpected error: {err}"
        );
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

    /// 6k4h: UDS listen（域套接字路径）允许无 port（Go xray.go:140-168 豁免）。
    #[test]
    fn build_inbound_uds_path_no_port_ok() {
        let json = r#"{
            "inbounds": [
                { "protocol": "vless", "tag": "uds-in", "listen": "/tmp/xray.sock" }
            ],
            "outbounds": [{ "protocol": "freedom", "tag": "direct" }]
        }"#;
        let cfg: Config = serde_json::from_str(json).unwrap();
        let built = cfg.build().expect("UDS inbound without port should build");
        assert_eq!(built.inbounds.len(), 1);
        let ib = &built.inbounds[0];
        assert_eq!(ib.tag, "uds-in");
        assert!(ib.port.is_none(), "UDS inbound should have port=None");
        assert_eq!(ib.listen.as_deref(), Some("/tmp/xray.sock"));
    }

    /// 6k4h: `@`-prefixed abstract UDS 路径也允许无 port。
    #[test]
    fn build_inbound_abstract_uds_path_no_port_ok() {
        let json = r#"{
            "inbounds": [
                { "protocol": "vless", "tag": "abs", "listen": "@xray" }
            ],
            "outbounds": [{ "protocol": "freedom", "tag": "direct" }]
        }"#;
        let cfg: Config = serde_json::from_str(json).unwrap();
        let built = cfg.build().expect("abstract UDS inbound should build");
        assert!(built.inbounds[0].port.is_none());
    }

    /// 6k4h: protocol=tun 不需要 port（Go xray.go:140-143 豁免）。
    #[test]
    fn build_inbound_tun_no_port_ok() {
        let json = r#"{
            "inbounds": [
                { "protocol": "tun", "tag": "tun0" }
            ],
            "outbounds": [{ "protocol": "freedom", "tag": "direct" }]
        }"#;
        let cfg: Config = serde_json::from_str(json).unwrap();
        let built = cfg.build().expect("tun inbound should build without port");
        assert_eq!(built.inbounds[0].entry.kind, "tun");
        assert!(built.inbounds[0].port.is_none());
    }

    /// 6k4h: 其它协议（vless）无 port 仍应硬报错（保持原行为）。
    #[test]
    fn build_inbound_no_port_no_uds_still_errors() {
        let json = r#"{
            "inbounds": [
                { "protocol": "vless", "tag": "in", "listen": "0.0.0.0" }
            ],
            "outbounds": [{ "protocol": "freedom", "tag": "direct" }]
        }"#;
        let cfg: Config = serde_json::from_str(json).unwrap();
        let err = cfg.build().unwrap_err();
        assert!(
            err.to_string().contains("inbound.port"),
            "unexpected error: {err}"
        );
    }
}
