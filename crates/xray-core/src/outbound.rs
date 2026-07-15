//! Outbound handler 注册：从 BuiltConfig 构建 DialBridge 注册到 SimpleOhm。
//!
//! 对应 Go `core.addOutboundHandlers`：遍历配置中的 outbound 列表，
//! 按协议创建 handler（DialBridge 包装 dial_fn），注册到 Ohm（OutboundHandlerManager）。
//!
//! ## 当前支持
//!
//! - **freedom**：完整支持（无 settings）
//! - **vless**：JSON 解析 `vnext` → [`VlessOutboundConfig`] → `make_dial_fn`（raw TCP，不含 streamSettings）
//! - **trojan**：JSON 解析 `servers` → [`TrojanOutboundConfig`] → `make_dial_fn`（raw TCP，不含 streamSettings）
//! - 其他协议（anytls/tuic/vmess/...）：warn 跳过（需 TLS transport 层，待后续切片）
//!
//! ## streamSettings
//!
//! 当前不处理 streamSettings（TLS/WS/Reality）—— vless/trojan 走裸 TCP `dial_system`。
//! transport 层补全后，`try_build_handler` 将在此注入 TLS-wrapped 拨号闭包。

use std::str::FromStr;
use std::sync::Arc;

use xray_app_dispatcher::default::{DialBridge, SimpleOhm};
use xray_app_dispatcher::DispatchHandler;
use xray_common::net::address::Address;
use xray_common::net::port::Port;
use xray_common::uuid::UUID;
use xray_conf::{BuiltConfig, BuiltOutbound};
use xray_features::Result;
use xray_proxy_trojan::{MemoryAccount, TrojanOutboundConfig};
use xray_proxy_vless::VlessOutboundConfig;
use xray_transport::dialer::StreamSettings;

/// 从 BuiltConfig 注册 outbound handlers 到 SimpleOhm。
///
/// 遍历 `built.outbounds`，按协议名创建 DialBridge 注册到 `ohm`。
/// 第一个 outbound 或 tag 为 `"direct"` 的设为 default（与 Go `SetDefaultHandler` 语义一致）。
/// 不支持的协议或配置解析失败均 warn 跳过（不返回错误，不阻止其他 outbound 注册）。
pub fn register_outbounds(built: &BuiltConfig, ohm: &SimpleOhm) -> Result<()> {
    for (i, ob) in built.outbounds.iter().enumerate() {
        match try_build_handler(ob) {
            Ok(handler) => {
                let is_default = i == 0 || ob.tag == "direct";
                if is_default {
                    ohm.set_default(handler.clone());
                }
                ohm.add(&ob.tag, handler);
                tracing::debug!(
                    tag = %ob.tag,
                    protocol = %ob.entry.kind,
                    default = is_default,
                    "outbound registered"
                );
            }
            Err(BuildError::Unsupported(protocol)) => {
                tracing::warn!(
                    tag = %ob.tag,
                    protocol = %protocol,
                    "outbound protocol not yet supported, skipping"
                );
            }
            Err(BuildError::Parse(e)) => {
                tracing::warn!(
                    tag = %ob.tag,
                    protocol = %ob.entry.kind,
                    error = %e,
                    "failed to parse outbound config, skipping"
                );
            }
        }
    }
    Ok(())
}

/// 构建单个 outbound 的 DispatchHandler（DialBridge）。
fn try_build_handler(
    ob: &BuiltOutbound,
) -> std::result::Result<Arc<dyn DispatchHandler>, BuildError> {
    match ob.entry.kind.as_str() {
        "freedom" => {
            let dial_fn = xray_proxy_freedom::make_freedom_dial_fn();
            Ok(Arc::new(DialBridge::new(ob.tag.clone(), dial_fn)))
        }
        "vless" => {
            let config = parse_vless_config(&ob.entry.data)?;
            let config = config.with_stream_settings(parse_stream_settings(&ob.stream_settings_json));
            let dial_fn = xray_proxy_vless::make_vless_dial_fn(Arc::new(config));
            Ok(Arc::new(DialBridge::new(ob.tag.clone(), dial_fn)))
        }
        "trojan" => {
            let config = parse_trojan_config(&ob.entry.data)?;
            let config = config.with_stream_settings(parse_stream_settings(&ob.stream_settings_json));
            let dial_fn = xray_proxy_trojan::make_trojan_dial_fn(Arc::new(config));
            Ok(Arc::new(DialBridge::new(ob.tag.clone(), dial_fn)))
        }
        other => Err(BuildError::Unsupported(other.to_string())),
    }
}

/// 解析 vless outbound settings JSON → VlessOutboundConfig。
///
/// JSON 格式：`{ "vnext": [{ "address": "...", "port": 443, "users": [{ "id": "uuid" }] }] }`
fn parse_vless_config(data: &[u8]) -> std::result::Result<VlessOutboundConfig, String> {
    let v: serde_json::Value = serde_json::from_slice(data).map_err(|e| e.to_string())?;
    let vnext = v
        .get("vnext")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "missing vnext array".to_string())?;
    let first = vnext
        .first()
        .ok_or_else(|| "vnext array is empty".to_string())?;
    let address = first
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing vnext[0].address".to_string())?;
    let port = first
        .get("port")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "missing vnext[0].port".to_string())?;
    let user_id = first
        .get("users")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|u| u.get("id"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing vnext[0].users[0].id".to_string())?;
    let uuid = UUID::from_str(user_id)?;
    Ok(VlessOutboundConfig::new(
        uuid,
        Address::Domain(address.to_string()),
        Port::new(u16::try_from(port).map_err(|_| "port out of range")?),
    ))
}

/// 解析 trojan outbound settings JSON → TrojanOutboundConfig。
///
/// JSON 格式：`{ "servers": [{ "address": "...", "port": 443, "password": "..." }] }`
fn parse_trojan_config(data: &[u8]) -> std::result::Result<TrojanOutboundConfig, String> {
    let v: serde_json::Value = serde_json::from_slice(data).map_err(|e| e.to_string())?;
    let servers = v
        .get("servers")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "missing servers array".to_string())?;
    let first = servers
        .first()
        .ok_or_else(|| "servers array is empty".to_string())?;
    let address = first
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing servers[0].address".to_string())?;
    let port = first
        .get("port")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "missing servers[0].port".to_string())?;
    let password = first
        .get("password")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing servers[0].password".to_string())?;
    Ok(TrojanOutboundConfig::new(
        MemoryAccount::new(password),
        Address::Domain(address.to_string()),
        Port::new(u16::try_from(port).map_err(|_| "port out of range")?),
    ))
}

/// 从 outbound 的 stream_settings_json 构造 StreamSettings。
///
/// None 或非 object 返回 None（走 raw TCP）。
fn parse_stream_settings(json: &Option<serde_json::Value>) -> Option<StreamSettings> {
    let s = StreamSettings::from_json(json.as_ref());
    // TCP + 无 security 等于没 streamSettings，返回 None 保持 raw TCP 路径。
    if s.protocol == "tcp" && !s.is_tls() {
        None
    } else {
        Some(s)
    }
}

#[derive(Debug)]
enum BuildError {
    Unsupported(String),
    Parse(String),
}

impl From<String> for BuildError {
    fn from(s: String) -> Self {
        Self::Parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xray_app_dispatcher::default::SimpleOhm;
    use xray_app_dispatcher::OutboundHandlerManager;
    use xray_conf::{BuiltConfig, BuiltEntry, BuiltOutbound};

    fn make_outbound(kind: &str, tag: &str, data: &str) -> BuiltOutbound {
        BuiltOutbound {
            entry: BuiltEntry {
                kind: kind.to_string(),
                data: data.as_bytes().to_vec(),
            },
            tag: tag.to_string(),
            send_through: None,
            stream_settings_json: None,
            proxy_settings_json: None,
            mux_json: None,
        }
    }

    #[test]
    fn register_freedom_sets_default_and_tagged() {
        let mut built = BuiltConfig::default();
        built.outbounds.push(make_outbound("freedom", "direct", "{}"));

        let ohm = SimpleOhm::new();
        register_outbounds(&built, &ohm).unwrap();

        assert!(ohm.get_default_handler().is_some(), "freedom should be default");
        assert!(ohm.get_handler("direct").is_some(), "freedom should be tagged");
    }

    #[test]
    fn register_multiple_outbounds_first_is_default() {
        let mut built = BuiltConfig::default();
        built.outbounds.push(make_outbound("freedom", "proxy", "{}"));
        built.outbounds.push(make_outbound("freedom", "direct", "{}"));

        let ohm = SimpleOhm::new();
        register_outbounds(&built, &ohm).unwrap();

        // 第一个设为 default，"direct" 也设为 default（覆盖）
        assert!(ohm.get_default_handler().is_some());
        assert!(ohm.get_handler("proxy").is_some());
        assert!(ohm.get_handler("direct").is_some());
    }

    #[test]
    fn register_vless_parses_vnext() {
        let settings = r#"{
            "vnext": [{
                "address": "example.com",
                "port": 443,
                "users": [{ "id": "b831381d-6324-4d53-ad4f-8cda48b30811" }]
            }]
        }"#;
        let mut built = BuiltConfig::default();
        built.outbounds.push(make_outbound("vless", "vless-out", settings));

        let ohm = SimpleOhm::new();
        register_outbounds(&built, &ohm).unwrap();

        assert!(ohm.get_handler("vless-out").is_some(), "vless should be registered");
    }

    #[test]
    fn register_trojan_parses_servers() {
        let settings = r#"{
            "servers": [{
                "address": "example.com",
                "port": 443,
                "password": "mypassword"
            }]
        }"#;
        let mut built = BuiltConfig::default();
        built.outbounds.push(make_outbound("trojan", "trojan-out", settings));

        let ohm = SimpleOhm::new();
        register_outbounds(&built, &ohm).unwrap();

        assert!(ohm.get_handler("trojan-out").is_some(), "trojan should be registered");
    }

    #[test]
    fn register_unsupported_protocol_skipped() {
        let mut built = BuiltConfig::default();
        built.outbounds.push(make_outbound("vmess", "vmess-out", "{}"));

        let ohm = SimpleOhm::new();
        register_outbounds(&built, &ohm).unwrap();

        assert!(ohm.get_handler("vmess-out").is_none(), "vmess should be skipped");
        assert!(ohm.get_default_handler().is_none(), "no default for unsupported");
    }

    #[test]
    fn register_vless_invalid_uuid_skipped() {
        let settings = r#"{
            "vnext": [{
                "address": "example.com",
                "port": 443,
                "users": [{ "id": "not-a-uuid" }]
            }]
        }"#;
        let mut built = BuiltConfig::default();
        built.outbounds.push(make_outbound("vless", "bad-vless", settings));

        let ohm = SimpleOhm::new();
        register_outbounds(&built, &ohm).unwrap();

        assert!(
            ohm.get_handler("bad-vless").is_none(),
            "invalid uuid should skip"
        );
    }

    #[test]
    fn register_empty_outbounds_noop() {
        let built = BuiltConfig::default();
        let ohm = SimpleOhm::new();
        register_outbounds(&built, &ohm).unwrap();
        assert!(ohm.get_default_handler().is_none());
    }

    #[test]
    fn parse_vless_config_extracts_fields() {
        let data = r#"{
            "vnext": [{
                "address": "server.example.com",
                "port": 8443,
                "users": [{ "id": "b831381d-6324-4d53-ad4f-8cda48b30811" }]
            }]
        }"#;
        let config = parse_vless_config(data.as_bytes()).unwrap();
        assert_eq!(config.server_port.value(), 8443);
        match &config.server_address {
            Address::Domain(d) => assert_eq!(d, "server.example.com"),
            other => panic!("expected Domain, got {other:?}"),
        }
    }

    #[test]
    fn parse_trojan_config_extracts_fields() {
        let data = r#"{
            "servers": [{
                "address": "trojan.example.com",
                "port": 443,
                "password": "secret"
            }]
        }"#;
        let config = parse_trojan_config(data.as_bytes()).unwrap();
        assert_eq!(config.server_port.value(), 443);
        assert_eq!(config.account.password, "secret");
        match &config.server_address {
            Address::Domain(d) => assert_eq!(d, "trojan.example.com"),
            other => panic!("expected Domain, got {other:?}"),
        }
    }

    #[test]
    fn parse_stream_settings_none_returns_none() {
        assert!(parse_stream_settings(&None).is_none());
        assert!(parse_stream_settings(&Some(serde_json::Value::Null)).is_none());
    }

    #[test]
    fn parse_stream_settings_tcp_no_security_returns_none() {
        let v: serde_json::Value = serde_json::from_str(r#"{"network":"tcp"}"#).unwrap();
        assert!(parse_stream_settings(&Some(v)).is_none());
    }

    #[test]
    fn parse_stream_settings_ws_tls_returns_some() {
        let v: serde_json::Value = serde_json::from_str(
            r#"{"network":"ws","security":"tls","wsSettings":{"path":"/ray"}}"#
        ).unwrap();
        let s = parse_stream_settings(&Some(v)).unwrap();
        assert_eq!(s.protocol, "ws");
        assert!(s.is_tls());
    }
}
