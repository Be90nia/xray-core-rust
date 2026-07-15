//! Trojan outbound → DialBridge 适配器（阶段 1 切片 1e）。
//!
//! Trojan 协议：拨号到 Trojan 服务器 → 在 TCP 流上写请求头（hex(sha224(password))
//! + CRLF + cmd + addr + port + CRLF）→ 返回连接，后续双向透传。
//!
//! ## 范围
//!
//! 当前实现：Trojan over **raw TCP**（与现有 trojan_proxy_e2e 测试模式一致）。
//! 生产场景（Trojan + TLS / WS）需在上层注入 TLS-wrapped 拨号闭包。
//!
//! [`DialBridge`]: xray_app_dispatcher::default::DialBridge
//! [`DialFn`]: xray_app_dispatcher::default::DialFn

use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use xray_app_dispatcher::default::DialFn;
use xray_common::net::address::Address;
use xray_common::net::destination::Destination;
use xray_common::net::network::Network as XrayNetwork;
use xray_common::net::port::Port;
use xray_transport::connection::Connection;
use xray_transport::dialer::{dial, StreamSettings};
use xray_transport::sockopt::SocketOptions;

use crate::config::MemoryAccount;
use crate::protocol::{write_request_header, Network as TrojanNetwork};

/// Trojan outbound 配置（最小集）。
#[derive(Debug, Clone)]
pub struct TrojanOutboundConfig {
    /// Trojan 账户（含 hex(sha224(password))）。
    pub account: MemoryAccount,
    /// Trojan 服务器地址。
    pub server_address: Address,
    /// Trojan 服务器端口。
    pub server_port: Port,
    /// 可选 streamSettings（TLS/WS/gRPC/...）。None 走 raw TCP。
    pub stream_settings: Option<StreamSettings>,
}

impl TrojanOutboundConfig {
    /// 构造（raw TCP，无 streamSettings）。
    #[must_use]
    pub fn new(account: MemoryAccount, server_address: Address, server_port: Port) -> Self {
        Self {
            account,
            server_address,
            server_port,
            stream_settings: None,
        }
    }

    /// 指定 streamSettings（builder 风格）。
    #[must_use]
    pub fn with_stream_settings(mut self, settings: Option<StreamSettings>) -> Self {
        self.stream_settings = settings;
        self
    }

    /// 服务器 Destination（TCP）。
    fn server_destination(&self) -> Destination {
        Destination::new(
            self.server_address.clone(),
            self.server_port,
            XrayNetwork::TCP,
        )
    }
}

/// 构造 Trojan 的 DialFn 闭包。
///
/// 闭包捕获 `Arc<TrojanOutboundConfig>`，每次调用：
/// 1. dial_system 到 Trojan 服务器 → `Box<dyn Connection>`
/// 2. `write_request_header` 构造 Trojan 头（hex key + CRLF + cmd + addr/port + CRLF）
/// 3. `conn.write_all(&header)` 写入连接
/// 4. 返回连接（已是带 Trojan 头的 TCP）
///
/// # Panics
///
/// 不会 panic；任何错误以 `Err(String)` 返回。
pub fn make_dial_fn(config: Arc<TrojanOutboundConfig>) -> DialFn {
    Arc::new(move |dest: &Destination| {
        let config = Arc::clone(&config);
        let target_addr = dest.address().clone();
        let target_port = dest.port().value();
        Box::pin(async move {
            // 1. dial Trojan server：有 streamSettings 走 transport dialer（ws/grpc/...），否则裸 TCP。
            let server_dest = config.server_destination();
            let sockopt = SocketOptions::default();
            let mut conn: Box<dyn Connection> = match &config.stream_settings {
                Some(s) => dial(&server_dest, s, &sockopt)
                    .await
                    .map_err(|e| format!("trojan dial server ({}): {e}", s.protocol))?,
                None => xray_transport::system_dialer::dial_system(&server_dest, &sockopt)
                    .await
                    .map_err(|e| format!("trojan dial server (tcp): {e}"))?,
            };

            // 2. 构造 Trojan 请求头
            let mut header = Vec::with_capacity(128);
            write_request_header(
                &mut header,
                &config.account,
                TrojanNetwork::Tcp,
                &target_addr,
                target_port,
            );

            // 3. 写头到连接
            conn.write_all(&header)
                .await
                .map_err(|e| format!("trojan write header: {e}"))?;

            Ok(conn)
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use xray_common::net::address::Address;

    #[test]
    fn config_server_destination_roundtrip() {
        let account = MemoryAccount::new("test_password".to_string());
        let cfg = TrojanOutboundConfig::new(
            account,
            Address::from_ipv4_bytes([127, 0, 0, 1]),
            Port::new(443),
        );
        let dest = cfg.server_destination();
        assert!(dest.is_tcp());
        assert_eq!(dest.port(), Port::new(443));
    }

    #[test]
    fn make_dial_fn_returns_arc_closure() {
        let account = MemoryAccount::new("test_password".to_string());
        let cfg = Arc::new(TrojanOutboundConfig::new(
            account,
            Address::new_domain("example.com"),
            Port::new(443),
        ));
        let _dial = make_dial_fn(Arc::clone(&cfg));
        assert_eq!(Arc::strong_count(&cfg), 2);
    }
}
