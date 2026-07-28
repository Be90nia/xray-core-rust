//! VMess outbound → DialBridge 适配器。
//!
//! 把 VMess 协议接入 dispatcher 的 [`DialBridge`]：提供
//! [`make_vmess_dial_fn`] 闭包，内部拨号到 VMess 服务器 →
//! 写 AEAD 加密请求头 → 返回连接。
//!
//! ## 范围
//!
//! 当前实现：VMess over **raw TCP**（请求头 AEAD 加密，body 透传）。
//! VMess body chunk 加密（AEAD chunk stream）依赖 `EncodeRequestBody`/
//! `DecodeResponseHeader`/`DecodeResponseBody` 完整链路，当前 body 走透传。
//! transport 层补全后可注入 TLS-wrapped 拨号闭包。
//!
//! [`DialBridge`]: xray_app_dispatcher::default::DialBridge
//! [`DialFn`]: xray_app_dispatcher::default::DialFn

use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use xray_app_dispatcher::default::DialFn;
use xray_common::net::address::Address;
use xray_common::net::destination::Destination;
use xray_common::net::network::Network;
use xray_common::net::port::Port;
use xray_common::protocol::{Command, RequestHeader, SecurityType};
use xray_common::uuid::UUID;
use xray_transport::connection::Connection;
use xray_transport::sockopt::SocketOptions;

use crate::account::MemoryAccount;
use crate::encoding::client::ClientSession;
use crate::encoding::VERSION;


/// VMess outbound 配置。
#[derive(Debug, Clone)]
pub struct VmessOutboundConfig {
    /// 用户 UUID。
    pub user_uuid: UUID,
    /// VMess 服务器地址。
    pub server_address: Address,
    /// VMess 服务器端口。
    pub server_port: Port,
    /// 安全类型（决定 body 加密方式）。
    pub security: SecurityType,
    /// 可选 streamSettings（TLS/WS/gRPC/...）。None 走 raw TCP。
    pub stream_settings: Option<xray_transport::dialer::StreamSettings>,
}


impl VmessOutboundConfig {
    /// 构造配置（默认 security=Auto）。
    #[must_use]
    pub fn new(user_uuid: UUID, server_address: Address, server_port: Port) -> Self {
        Self {
            user_uuid,
            server_address,
            server_port,
            security: SecurityType::Auto,
            stream_settings: None,
        }
    }
    /// 设置安全类型（builder 风格）。
    #[must_use]
    pub fn with_security(mut self, security: SecurityType) -> Self {
        self.security = security;
        self
    }

    /// 指定 streamSettings（builder 风格）。
    #[must_use]
    pub fn with_stream_settings(mut self, settings: Option<xray_transport::dialer::StreamSettings>) -> Self {
        self.stream_settings = settings;
        self
    }

    /// 服务器 Destination（TCP）。
    fn server_destination(&self) -> Destination {
        Destination::new(
            self.server_address.clone(),
            self.server_port,
            Network::TCP,
        )
    }
}

/// 从 JSON 字符串解析 security 类型。
///
/// Go 端 `security` 字段值：`"aes-128-gcm"` / `"chacha20-poly1305"` / `"auto"` / `"none"` / `"zero"`。
fn parse_security(s: &str) -> SecurityType {
    match s {
        "aes-128-gcm" | "aes-128-gcm@shadowsocks.org" => SecurityType::Aes128Gcm,
        "chacha20-poly1305" | "chacha20-poly1305@shadowsocks.org" => SecurityType::Chacha20Poly1305,
        "auto" => SecurityType::Auto,
        "none" => SecurityType::None,
        "zero" => SecurityType::Zero,
        _ => SecurityType::Auto,
    }
}

/// 解析 VMess outbound settings JSON → VmessOutboundConfig。
///
/// JSON 格式：`{ "vnext": [{ "address": "...", "port": 443, "users": [{ "id": "uuid", "security": "aes-128-gcm" }] }] }`
pub fn parse_vmess_config(data: &[u8]) -> Result<VmessOutboundConfig, String> {
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
    let user = first
        .get("users")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .ok_or_else(|| "missing vnext[0].users[0]".to_string())?;
    let user_id = user
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing vnext[0].users[0].id".to_string())?;
    let uuid = UUID::from_str(user_id)?;
    let security_str = user
        .get("security")
        .and_then(|v| v.as_str())
        .unwrap_or("auto");
    Ok(VmessOutboundConfig::new(
        uuid,
        Address::Domain(address.to_string()),
        Port::new(u16::try_from(port).map_err(|_| "port out of range")?),
    )
    .with_security(parse_security(security_str)))
}

use std::str::FromStr;

/// 构造 VMess 的 DialFn 闭包。
///
/// 闭包捕获 `Arc<VmessOutboundConfig>`，每次调用：
/// 1. `dial_system` 到 VMess 服务器 → `Box<dyn Connection>`
/// 2. `ClientSession::new` + `encode_request_header` 写 AEAD 加密请求头
/// 3. 返回连接（已写 VMess 头的 TCP，后续双向透传）
///
/// # Panics
///
/// 不会 panic；任何错误以 `Err(String)` 返回。
pub fn make_vmess_dial_fn(config: Arc<VmessOutboundConfig>) -> DialFn {
    Arc::new(move |dest: &Destination| {
        let config = Arc::clone(&config);
        let target_addr = dest.address().clone();
        let target_port = dest.port();
        Box::pin(async move {
            let server_dest = config.server_destination();
            let sockopt = SocketOptions::default();
            let mut conn: Box<dyn Connection> = match &config.stream_settings {
                Some(s) => xray_transport::dialer::dial(&server_dest, s, &sockopt)
                    .await
                    .map_err(|e| format!("vmess dial server ({}): {e}", s.protocol))?,
                None => xray_transport::system_dialer::dial_system(&server_dest, &sockopt)
                    .await
                    .map_err(|e| format!("vmess dial server (tcp): {e}"))?,
            };

            // 2. 构造 VMess 请求头
            let account = MemoryAccount::new(config.user_uuid.clone())
                .with_security(config.security.clone());
            let session = ClientSession::new();
            let header = RequestHeader::new(
                VERSION,
                Command::Tcp,
                Destination::new(target_addr, target_port, Network::TCP),
                config.security.clone(),
            );

            // 3. 编码 + 写入 AEAD 加密请求头
            let sealed = session
                .encode_request_header(&header, &account.cmd_key())
                .map_err(|e| format!("vmess encode header: {e}"))?;
            conn.write_all(&sealed)
                .await
                .map_err(|e| format!("vmess write header: {e}"))?;

            // 4. 返回连接（body 透传；chunk AEAD 留 EncodeRequestBody 接入后激活）
            Ok(conn)
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_server_destination_roundtrip() {
        let uuid = UUID::new();
        let cfg = VmessOutboundConfig::new(
            uuid,
            Address::from_ipv4_bytes([127, 0, 0, 1]),
            Port::new(443),
        );
        let dest = cfg.server_destination();
        assert!(dest.is_tcp());
        assert_eq!(dest.port(), Port::new(443));
    }

    #[test]
    fn parse_security_mapping() {
        assert!(matches!(super::parse_security("aes-128-gcm"), SecurityType::Aes128Gcm));
        assert!(matches!(super::parse_security("chacha20-poly1305"), SecurityType::Chacha20Poly1305));
        assert!(matches!(super::parse_security("auto"), SecurityType::Auto));
        assert!(matches!(super::parse_security("none"), SecurityType::None));
        assert!(matches!(super::parse_security("zero"), SecurityType::Zero));
        assert!(matches!(super::parse_security("unknown"), SecurityType::Auto));
    }

    #[test]
    fn make_dial_fn_returns_arc_closure() {
        let uuid = UUID::new();
        let cfg = Arc::new(VmessOutboundConfig::new(
            uuid,
            Address::new_domain("example.com"),
            Port::new(443),
        ));
        let _dial = make_vmess_dial_fn(Arc::clone(&cfg));
        assert_eq!(Arc::strong_count(&cfg), 2);
    }

    #[test]
    fn parse_vmess_config_extracts_fields() {
        let data = r#"{
            "vnext": [{
                "address": "server.example.com",
                "port": 8443,
                "users": [{ "id": "b831381d-6324-4d53-ad4f-8cda48b30811", "security": "aes-128-gcm" }]
            }]
        }"#;
        let config = parse_vmess_config(data.as_bytes()).unwrap();
        assert_eq!(config.server_port.value(), 8443);
        assert!(matches!(config.security, SecurityType::Aes128Gcm));
        match &config.server_address {
            Address::Domain(d) => assert_eq!(d, "server.example.com"),
            other => panic!("expected Domain, got {other:?}"),
        }
    }

    #[test]
    fn parse_vmess_config_missing_vnext_fails() {
        let result = parse_vmess_config(b"{}");
        assert!(result.is_err());
    }
}
