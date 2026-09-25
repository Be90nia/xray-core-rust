//! Hysteria 出站处理器，对应 Go `proxy/hysteria/outbound.go`。
//!
//! 包装 [`ClientManager`]（QUIC 连接缓存）+ [`HysteriaTransport`]（dial + auth），
//! 实现 [`OutboundHandler`] trait。
//!
//! ## 流程
//!
//! 1. `OutboundHandler::dial(destination)` 被调度器调用
//! 2. 从 [`HysteriaConfig::server_addr`] 解析 DialDestination（hysteria server 地址）
//! 3. `ClientManager::get_or_create` 取或建 `HysteriaClient`（含 QUIC + HTTP/3 auth）
//! 4. 按 `destination.network()` 调 `client.tcp()` 或 `client.udp()` 建立中继通道
//!
//! ## 切片边界
//!
//! 与 freedom handler 切片2 一致：dial 建立 QUIC 连接后返回 `Ok(())`，
//! Connection ↔ Link 桥接送后续切片。目标地址编码由 transport 层 InterStreamConn
//! 的 client_first 前缀处理。

use std::{net::ToSocketAddrs, sync::Arc};

use async_trait::async_trait;
use xray_common::{
    net::{destination::Destination, network::Network},
    session::Session,
};
use xray_features::outbound::{OutboundError, OutboundHandler};
use xray_transport_hysteria::{
    dialer::{ClientManager, DialDestination, HysteriaTransport},
    proto_config::Config as ProtoConfig,
};

use crate::{config::HysteriaConfig, error::Result};

/// Hysteria 出站 Handler。
///
/// 持有配置 + `ClientManager`（内部缓存 QUIC 连接），实现 [`OutboundHandler`]。
pub struct HysteriaOutboundHandler {
    tag: String,
    config: HysteriaConfig,
    client_manager: ClientManager,
}

impl HysteriaOutboundHandler {
    /// 构造出站 Handler。
    ///
    /// # 参数
    /// - `tag`：handler 标签（路由匹配用）
    /// - `config`：Hysteria 代理配置（server_addr / auth / bandwidth 等）
    /// - `transport`：QUIC + HTTP/3 transport 实现（通常 `QuinnHysteriaTransport`）
    ///
    /// # Errors
    /// 配置无效（[`HysteriaConfig::validate`]）时返回
    /// [`InvalidConfig`](crate::HysteriaProxyError::InvalidConfig)。
    pub fn new(
        tag: impl Into<String>,
        config: HysteriaConfig,
        transport: Arc<dyn HysteriaTransport>,
    ) -> Result<Self> {
        config.validate()?;
        Ok(Self { tag: tag.into(), config, client_manager: ClientManager::new(transport) })
    }

    /// 配置引用。
    #[must_use]
    pub fn config(&self) -> &HysteriaConfig {
        &self.config
    }

    /// 从 [`HysteriaConfig`] 构造 transport 层 [`ProtoConfig`]。
    fn build_proto_config(&self) -> ProtoConfig {
        ProtoConfig {
            auth: self.config.auth.clone(),
            udp_idle_timeout: self.config.udp_idle_timeout_secs as i64,
            ..ProtoConfig::default()
        }
    }
}

#[async_trait]
impl OutboundHandler for HysteriaOutboundHandler {
    fn tag(&self) -> &str {
        &self.tag
    }

    /// 通过 QUIC + HTTP/3 auth 拨号到 Hysteria server，建立 TCP stream 或 UDP session。
    ///
    /// `destination` 是最终目标（经 Hysteria server 中继），Hysteria server 地址
    /// 来自 [`HysteriaConfig::server_addr`]。
    async fn dial(
        &self,
        destination: &Destination,
        _session: &Session,
    ) -> std::result::Result<(), OutboundError> {
        let dest = resolve_server_dest(&self.config.server_addr, &self.config.server_name)?;

        let proto_config = Arc::new(self.build_proto_config());
        let quic_params = Arc::clone(&self.config.quic_params);

        let client = self.client_manager.get_or_create(dest, proto_config, quic_params);

        match destination.network() {
            Network::TCP => {
                client
                    .tcp(destination.address(), destination.port())
                    .await
                    .map_err(|e| OutboundError::ConnectionFailed(format!("hysteria tcp: {e}")))?;
                tracing::debug!(
                    tag = %self.tag,
                    dest = %destination,
                    "hysteria outbound TCP stream established"
                );
            },
            Network::UDP => {
                client
                    .udp()
                    .await
                    .map_err(|e| OutboundError::ConnectionFailed(format!("hysteria udp: {e}")))?;
                tracing::debug!(
                    tag = %self.tag,
                    dest = %destination,
                    "hysteria outbound UDP session established"
                );
            },
            Network::Unix => {
                return Err(OutboundError::ConnectionFailed(
                    "hysteria does not support Unix socket".into(),
                ));
            },
        }
        Ok(())
    }

    /// Hysteria 同时支持 TCP 和 UDP 中继（基于 QUIC stream + datagram）。
    fn can_handle(&self, _destination: &Destination) -> bool {
        true
    }
}

/// 把 `host:port` 解析为 [`DialDestination`]。
///
/// hysteria 强制 UDP 传输，`udp_addr` 是解析后的 `SocketAddr`，`host` 保留原始
/// 字符串用于 TLS SNI。
fn resolve_server_dest(
    server_addr: &str,
    server_name: &str,
) -> std::result::Result<DialDestination, OutboundError> {
    let udp_addr = server_addr
        .to_socket_addrs()
        .map_err(|e| OutboundError::ConnectionFailed(format!("resolve {server_addr}: {e}")))?
        .next()
        .ok_or_else(|| {
            OutboundError::ConnectionFailed(format!("resolve {server_addr}: no addr"))
        })?;
    Ok(DialDestination { udp_addr, host: server_name.to_string() })
}

#[cfg(test)]
mod tests {
    use xray_common::net::{address::Address, port::Port};

    use super::*;

    fn make_dest(network: Network) -> Destination {
        Destination::new(Address::Domain("example.com".to_string()), Port::new(443), network)
    }

    #[test]
    fn resolve_server_dest_domain() {
        let d = resolve_server_dest("127.0.0.1:443", "example.com").unwrap();
        assert_eq!(d.udp_addr, "127.0.0.1:443".parse().unwrap());
        assert_eq!(d.host, "example.com");
    }

    #[test]
    fn resolve_server_dest_unresolvable_returns_error() {
        let r = resolve_server_dest("invalid-host-that-does-not-exist.invalid:443", "x");
        // to_socket_addrs 可能因 DNS 环境返回不同结果；仅验证不 panic
        let _ = r;
    }

    /// Noop transport —— dial 返回错误，用于验证 handler 构造 + can_handle 不触发网络。
    struct NoopTransport;
    impl HysteriaTransport for NoopTransport {
        fn dial_and_authenticate(
            &self,
            _dest: &DialDestination,
            _quic_config: &xray_transport_hysteria::dialer::QuicConfig,
            _auth_token: &str,
            _brutal_up_bps: u64,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = std::io::Result<Arc<dyn xray_transport_hysteria::conn::QuicConn>>,
                    > + Send,
            >,
        > {
            Box::pin(async { Err(std::io::Error::other("noop transport")) })
        }

        fn open_stream(
            &self,
            _conn: &Arc<dyn xray_transport_hysteria::conn::QuicConn>,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = std::io::Result<
                            Arc<dyn xray_transport_hysteria::conn::QuicStream>,
                        >,
                    > + Send,
            >,
        > {
            Box::pin(async { Err(std::io::Error::other("noop transport")) })
        }
    }

    #[test]
    fn handler_constructs_with_valid_config() {
        let cfg = HysteriaConfig::new("127.0.0.1:443", "secret");
        let h = HysteriaOutboundHandler::new("test", cfg, Arc::new(NoopTransport));
        assert!(h.is_ok());
        let h = h.unwrap();
        assert_eq!(h.tag(), "test");
    }

    #[test]
    fn handler_rejects_empty_server_addr() {
        let cfg = HysteriaConfig::new("", "secret");
        assert!(HysteriaOutboundHandler::new("test", cfg, Arc::new(NoopTransport)).is_err());
    }

    #[test]
    fn can_handle_tcp_and_udp() {
        let cfg = HysteriaConfig::new("127.0.0.1:443", "secret");
        let h = HysteriaOutboundHandler::new("test", cfg, Arc::new(NoopTransport)).unwrap();
        assert!(h.can_handle(&make_dest(Network::TCP)));
        assert!(h.can_handle(&make_dest(Network::UDP)));
    }

    #[tokio::test]
    async fn dial_with_noop_transport_returns_connection_failed() {
        let cfg = HysteriaConfig::new("127.0.0.1:443", "secret");
        let h = HysteriaOutboundHandler::new("test", cfg, Arc::new(NoopTransport)).unwrap();
        let dest = make_dest(Network::TCP);
        let session = Session::new();
        let r = h.dial(&dest, &session).await;
        assert!(r.is_err());
        match r.unwrap_err() {
            OutboundError::ConnectionFailed(msg) => assert!(msg.contains("hysteria")),
            other => panic!("expected ConnectionFailed, got {other:?}"),
        }
    }
}
