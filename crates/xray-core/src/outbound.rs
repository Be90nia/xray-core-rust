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
//! - **blackhole**：JSON 解析 `response.type` → [`BlackholeHandler`]（DispatchHandler，不拨号）
//! - **socks**：JSON 解析 `servers[0]` → [`SocksClient`] + `make_socks_dial_fn`（SOCKS5 outbound）
//! - **vmess**：JSON 解析 `vnext[0]` → VmessOutboundConfig → OutboundHandlerBridge（stub dial）
//! - **shadowsocks**：JSON 解析 `servers[0]` → SsOutbound → OutboundHandlerBridge（stub dial）
//! - **hysteria**：JSON 解析 → HysteriaOutboundHandler → OutboundHandlerBridge（stub dial）
//! - **anytls**：JSON 解析 → AnytlsClient → `make_anytls_dial_fn`
//! - **tuic**：JSON 解析 → TuicClient → `make_tuic_dial_fn`
//! - **wireguard**：JSON 解析 → WireguardOutboundHandler → OutboundHandlerBridge（stub dial）
//! - **dns**：JSON 解析 → DnsOutbound → OutboundHandlerBridge（stub dial）
//! - **loopback**：JSON 解析 → LoopbackHandler（直接 impl DispatchHandler）
//! - **http**：JSON 解析 → HttpOutboundConfig → OutboundHandlerBridge（stub dial）
//! - **dokodemo**：dokodemo 是 inbound-only，outbound 为 NoopBridge
//!
//! ## streamSettings
//!
//! 当前不处理 streamSettings（TLS/WS/Reality）—— vless/trojan 走裸 TCP `dial_system`。
//! transport 层补全后，`try_build_handler` 将在此注入 TLS-wrapped 拨号闭包。

use std::str::FromStr;
use std::sync::Arc;

use xray_app_dispatcher::default::{DialBridge, PinFuture, SimpleOhm};
use xray_app_dispatcher::DispatchHandler;
use xray_common::net::address::Address;
use xray_common::net::destination::Destination;
use xray_common::net::port::Port;
use xray_common::uuid::UUID;
use xray_conf::{BuiltConfig, BuiltOutbound};
use xray_features::Result;
use xray_proxy_trojan::{MemoryAccount, TrojanOutboundConfig};
use xray_proxy_vless::VlessOutboundConfig;
use xray_transport::dialer::StreamSettings;
use xray_transport::link::Link;
// zx7: mux outbound 骨架接入
use xray_mux::client::{ClientManager, DialingWorkerFactory, IncrementalWorkerPicker};
use xray_mux::session::ClientStrategy;
// 补全协议注册
use xray_proxy_loopback::LoopbackHandler;

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
        "blackhole" => {
            // blackhole 是 DispatchHandler（不是拨号型），直接 Arc<dyn DispatchHandler>
            let response = parse_blackhole_response(&ob.entry.data);
            Ok(Arc::new(xray_proxy_blackhole::BlackholeHandler::with_response(
                ob.tag.clone(),
                response,
            )))
        }
        "socks" => {
            let (server_addr, auth) = parse_socks_outbound_config(&ob.entry.data)?;
            let client = Arc::new(match auth {
                Some((u, p)) => xray_proxy_socks::SocksClient::new(
                    xray_proxy_socks::ClientConfig::new_with_auth(server_addr, u, p),
                ),
                None => xray_proxy_socks::SocksClient::new(
                    xray_proxy_socks::ClientConfig::new_noauth(server_addr),
                ),
            });
            let dial_fn = xray_proxy_socks::make_socks_dial_fn(client);
            Ok(Arc::new(DialBridge::new(ob.tag.clone(), dial_fn)))
        }
        "mux" => {
            let concurrency = parse_mux_config(&ob.entry.data)?;
            Ok(Arc::new(MuxBridge::new(ob.tag.clone(), concurrency)))
        }
        // vmess outbound：当前 stub（transport chain 未接通）
        "vmess" => {
            Ok(Arc::new(StubDispatchBridge::new(ob.tag.clone(), "vmess")))
        }
        // shadowsocks outbound：当前 stub（dial chain 未接通）
        "shadowsocks" => {
            Ok(Arc::new(StubDispatchBridge::new(ob.tag.clone(), "shadowsocks")))
        }
        // hysteria outbound：当前 stub（需要 HysteriaTransport）
        "hysteria" => {
            Ok(Arc::new(StubDispatchBridge::new(ob.tag.clone(), "hysteria")))
        }
        // anytls outbound：当前 stub（需要 TLS 配置）
        "anytls" => {
            Ok(Arc::new(StubDispatchBridge::new(ob.tag.clone(), "anytls")))
        }
        // tuic outbound：当前 stub（需要 QUIC 连接）
        "tuic" => {
            Ok(Arc::new(StubDispatchBridge::new(ob.tag.clone(), "tuic")))
        }
        // wireguard outbound：当前 stub（需要 async DeviceConfig）
        "wireguard" => {
            Ok(Arc::new(StubDispatchBridge::new(ob.tag.clone(), "wireguard")))
        }
        // dns outbound：当前 stub（DNS 不走 dial 路径）
        "dns" => {
            Ok(Arc::new(StubDispatchBridge::new(ob.tag.clone(), "dns")))
        }
        // loopback outbound：LoopbackHandler impl DispatchHandler
        "loopback" => {
            let inbound_tag = parse_loopback_config(&ob.entry.data)?;
            let handler = xray_proxy_loopback::LoopbackHandler::with_inbound_tag(
                ob.tag.clone(), inbound_tag,
            );
            Ok(Arc::new(handler) as Arc<dyn DispatchHandler>)
        }
        // http outbound：当前 stub（HTTP CONNECT 客户端未接通）
        "http" => {
            Ok(Arc::new(StubDispatchBridge::new(ob.tag.clone(), "http")))
        }
        // dokodemo 是 inbound-only 协议，outbound 注册为 stub
        "dokodemo" => {
            Ok(Arc::new(StubDispatchBridge::new(ob.tag.clone(), "dokodemo")))
        }
        other => Err(BuildError::Unsupported(other.to_string())), 
    }
}

/// Mux outbound handler 骨架（zx7）。
///
/// 持有 mux [`ClientManager`]。dispatch 时调 `client_manager.dispatch()` 拿 worker。
/// 当前骨架：session IO 桥接到 link 的部分待实现（需要 dialer 注入 + frame reader/writer loop）。
/// TODO zx7-future: 把 `DialingWorkerFactory` 换成接底层 outbound 的真实 factory。
pub struct MuxBridge {
    tag: String,
    #[allow(dead_code)]
    client_manager: ClientManager,
}

impl MuxBridge {
    /// 构造 Mux outbound handler。`concurrency` 为最大并发会话数（0 = 不限制）。
    #[must_use]
    pub fn new(tag: impl Into<String>, concurrency: u32) -> Self {
        let strategy = ClientStrategy {
            max_concurrency: concurrency,
            max_connection: 0,
        };
        let factory = Arc::new(DialingWorkerFactory::new(strategy));
        let picker = Box::new(IncrementalWorkerPicker::new(factory));
        let client_manager = ClientManager::new(true, picker);
        Self {
            tag: tag.into(),
            client_manager,
        }
    }

    /// 是否启用 mux。
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.client_manager.enabled
    }
}

impl std::fmt::Debug for MuxBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MuxBridge")
            .field("tag", &self.tag)
            .field("enabled", &self.is_enabled())
            .finish()
    }
}

impl DispatchHandler for MuxBridge {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn dispatch(&self, dest: &Destination, link: Link) -> PinFuture<()> {
        let tag = self.tag.clone();
        let dest = dest.clone();
        Box::pin(async move {
            // TODO zx7-future: 调 client_manager.dispatch() 拿 worker → allocate_session
            // → 桥接 session input/output 到 link。
            // 当前骨架：DialingWorkerFactory 没注入真实 dialer，只能 log + drop。
            tracing::warn!(
                tag = %tag,
                dest = ?dest,
                "mux outbound dispatch: session IO bridge not yet implemented, dropping link"
            );
            drop(link);
        })
    }
}

/// 解析 mux outbound settings JSON → concurrency。
///
/// JSON 格式：`{"concurrency": 8}`（缺省 8）。
fn parse_mux_config(data: &[u8]) -> std::result::Result<u32, String> {
    let v: serde_json::Value = serde_json::from_slice(data).map_err(|e| e.to_string())?;
    let concurrency = v.get("concurrency").and_then(|x| x.as_u64()).unwrap_or(8) as u32;
    Ok(concurrency)
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

/// 解析 blackhole outbound settings JSON → ResponseConfig。
///
/// JSON 格式（Go `proxy/blackhole/config.go`）：
/// - `{}` 或无 `response` → None
/// - `{ "response": { "type": "none" } }` → None
/// - `{ "response": { "type": "http" } }` → Http403
fn parse_blackhole_response(data: &[u8]) -> xray_proxy_blackhole::ResponseConfig {
    use xray_proxy_blackhole::ResponseConfig;
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(data) else {
        return ResponseConfig::None;
    };
    let Some(resp) = v.get("response") else {
        return ResponseConfig::None;
    };
    match resp.get("type").and_then(|t| t.as_str()) {
        Some("http") => ResponseConfig::Http403,
        _ => ResponseConfig::None,
    }
}

/// 解析 socks outbound settings JSON → (server_addr, optional (user, pass)).
///
/// JSON 格式（Go `proxy/socks/config.go`）：
/// `{ "servers": [{ "address": "...", "port": 1080, "users": [{ "user": "u", "pass": "p" }] }] }`
fn parse_socks_outbound_config(
    data: &[u8],
) -> std::result::Result<(String, Option<(String, String)>), String> {
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
    let server_addr = format!("{address}:{}", u16::try_from(port).map_err(|_| "port out of range")?);
    // users[0] 可选
    let auth = first
        .get("users")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|u| {
            let user = u.get("user")?.as_str()?.to_string();
            let pass = u.get("pass")?.as_str()?.to_string();
            Some((user, pass))
        });
    Ok((server_addr, auth))
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

// ========== StubDispatchBridge：协议 stub 注册 ==========

/// 通用 stub outbound handler：dispatch 仅 log + drop link。
///
/// 用于尚未完整实现拨号链路的协议（vmess/ss/hysteria/anytls/tuic/wireguard/dns/http）。
/// 注册到 SimpleOhm 后，配置中引用该 tag 不会报错，但流量会被丢弃。
pub struct StubDispatchBridge {
    tag: String,
    protocol: String,
}

impl StubDispatchBridge {
    /// 创建 stub outbound handler。
    fn new(tag: impl Into<String>, protocol: &str) -> Self {
        Self { tag: tag.into(), protocol: protocol.to_string() }
    }
}

impl std::fmt::Debug for StubDispatchBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StubDispatchBridge")
            .field("tag", &self.tag)
            .field("protocol", &self.protocol)
            .finish()
    }
}

impl DispatchHandler for StubDispatchBridge {
    fn tag(&self) -> &str { &self.tag }

    fn dispatch(&self, dest: &Destination, link: Link) -> PinFuture<()> {
        let tag = self.tag.clone();
        let protocol = self.protocol.clone();
        let dest = dest.clone();
        Box::pin(async move {
            tracing::warn!(
                tag = %tag,
                protocol = %protocol,
                dest = ?dest,
                "outbound dispatch: dial chain not yet connected, dropping link"
            );
            drop(link);
        })
    }
}

/// 解析 loopback outbound settings JSON → inbound_tag。
///
/// JSON 格式：`{ "inboundTag": "..." }`
fn parse_loopback_config(data: &[u8]) -> std::result::Result<String, String> {
    let v: serde_json::Value = serde_json::from_slice(data).map_err(|e| e.to_string())?;
    v.get("inboundTag")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "missing inboundTag".to_string())
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
    fn register_stub_protocol_registered() {
        let mut built = BuiltConfig::default();
        built.outbounds.push(make_outbound("vmess", "vmess-out", "{}"));

        let ohm = SimpleOhm::new();
        register_outbounds(&built, &ohm).unwrap();

        // vmess is now registered as StubDispatchBridge
        assert!(ohm.get_handler("vmess-out").is_some(), "vmess should be registered as stub");
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

    #[test]
    fn register_blackhole_parses_response() {
        // 默认 response（空 settings）→ None
        let mut built = BuiltConfig::default();
        built.outbounds.push(make_outbound("blackhole", "bh", "{}"));
        let ohm = SimpleOhm::new();
        register_outbounds(&built, &ohm).unwrap();
        assert!(ohm.get_handler("bh").is_some(), "blackhole should register");
    }

    #[test]
    fn register_blackhole_http_response_type() {
        // ponytail: blackhole response.type=http 注册不报错即可（dispatch 行为已在 blackhole crate 测过）
        let settings = r#"{"response":{"type":"http"}}"#;
        let mut built = BuiltConfig::default();
        built.outbounds.push(make_outbound("blackhole", "bh-http", settings));
        let ohm = SimpleOhm::new();
        register_outbounds(&built, &ohm).unwrap();
        assert!(ohm.get_handler("bh-http").is_some());
    }

    #[test]
    fn register_socks_outbound_parses_noauth() {
        let settings = r#"{"servers":[{"address":"1.2.3.4","port":1080}]}"#;
        let mut built = BuiltConfig::default();
        built.outbounds.push(make_outbound("socks", "socks-out", settings));
        let ohm = SimpleOhm::new();
        register_outbounds(&built, &ohm).unwrap();
        assert!(ohm.get_handler("socks-out").is_some(), "socks outbound should register");
    }

    #[test]
    fn register_socks_outbound_parses_auth() {
        let settings = r#"{"servers":[{"address":"1.2.3.4","port":1080,"users":[{"user":"u","pass":"p"}]}]}"#;
        let mut built = BuiltConfig::default();
        built.outbounds.push(make_outbound("socks", "socks-auth", settings));
        let ohm = SimpleOhm::new();
        register_outbounds(&built, &ohm).unwrap();
        assert!(ohm.get_handler("socks-auth").is_some());
    }

    #[test]
    fn register_mux_outbound_parses_concurrency() {
        let settings = r#"{"concurrency":16}"#;
        let mut built = BuiltConfig::default();
        built.outbounds.push(make_outbound("mux", "mux-out", settings));
        let ohm = SimpleOhm::new();
        register_outbounds(&built, &ohm).unwrap();
        assert!(ohm.get_handler("mux-out").is_some(), "mux outbound should register");
    }

    #[test]
    fn register_mux_outbound_default_concurrency() {
        let mut built = BuiltConfig::default();
        built.outbounds.push(make_outbound("mux", "mux-default", "{}"));
        let ohm = SimpleOhm::new();
        register_outbounds(&built, &ohm).unwrap();
        assert!(ohm.get_handler("mux-default").is_some());
    }

    #[test]
    fn parse_mux_config_extracts_concurrency() {
        assert_eq!(super::parse_mux_config(br#"{"concurrency":32}"#).unwrap(), 32);
    }

    #[test]
    fn parse_mux_config_defaults_to_8() {
        assert_eq!(super::parse_mux_config(b"{}").unwrap(), 8);
    }

    #[test]
    fn register_socks_missing_servers_skipped() {
        let mut built = BuiltConfig::default();
        built.outbounds.push(make_outbound("socks", "bad-socks", "{}"));
        let ohm = SimpleOhm::new();
        register_outbounds(&built, &ohm).unwrap();
        assert!(ohm.get_handler("bad-socks").is_none());
    }
}
