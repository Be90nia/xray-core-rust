//! Dokodemo-door 入站服务端。
//!
//! 对应 Go `proxy/dokodemo/dokodemo.go` 的 `DokodemoDoor` + `Process`。
//!
//! ## 切片边界（P6-5 切片2）
//!
//! 实现 [`DokodemoServer`] + `impl InboundHandler`（start/accept/close lifecycle）。
//! Accept 后直接用 [`Config::predefined_address`] + `rewrite_port` 构造目标 dest
//! （dokodemo 协议无握手，连接建立即转发）。
//!
//! 切片3 待办：dispatch to outbound handler + `follow_redirect`（SO_ORIGINAL_DST）+
//! port_map 端口映射 + TCP/UDP 双栈 + Unix socket 支持。

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use xray_common::net::address::Address;
use xray_common::net::destination::Destination;
use xray_common::net::port::Port;
use xray_features::inbound::{InboundError, InboundHandler};

use crate::config::{Config, Network, PredefinedAddress};
use crate::error::Result;

/// Dokodemo-door 入站服务端。对应 Go `DokodemoDoor`。
///
/// 启动后监听指定端口，每个入站连接按 [`Config::predefined_address`] +
/// `rewrite_port` 构造目标 dest。无握手协议——连接建立即转发。
pub struct DokodemoServer {
    /// Handler 唯一标识。
    tag: String,
    /// 配置（含 predefined address + port + allowed_networks）。
    config: Config,
    /// tokio 监听器。`None` 表示未启动或已关闭。
    listener: Arc<Mutex<Option<TcpListener>>>,
}

impl DokodemoServer {
    /// 构造服务端实例。不立即监听——监听在 [`InboundHandler::start`] 时触发。
    #[must_use]
    pub fn new(tag: impl Into<String>, config: Config) -> Self {
        Self {
            tag: tag.into(),
            config,
            listener: Arc::new(Mutex::new(None)),
        }
    }

    /// 构造目标 Destination。对应 Go `Process` 中 dest 构造逻辑。
    ///
    /// 用 [`Config::predefined_address`] + `rewrite_port` 构造。
    /// `follow_redirect=true` 时本应从 SO_ORIGINAL_DST 获取，切片2 暂不支持。
    ///
    /// 返回 `None` 表示配置不完整（无 predefined_address 且非 follow_redirect）。
    fn build_destination(&self) -> Option<Destination> {
        let addr = self.config.predefined_address()?;
        let port = Port::new(u16::try_from(self.config.rewrite_port).ok()?);
        let address = match addr {
            PredefinedAddress::Ip(ip) => match ip {
                std::net::IpAddr::V4(v4) => Address::IPv4(v4),
                std::net::IpAddr::V6(v6) => Address::IPv6(v6),
            },
            PredefinedAddress::Domain(s) => Address::Domain(s),
        };
        // dokodemo 默认 TCP 网络；UDP 由 config.allowed_networks 决定，切片2 仅 TCP。
        Some(Destination::tcp(address, port))
    }

    /// 网络类型是否被配置允许。
    fn is_network_allowed(&self, net: Network) -> bool {
        self.config.allows_network(net)
    }
}

#[async_trait]
impl InboundHandler for DokodemoServer {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn start(&self) -> std::result::Result<(), InboundError> {
        let mut guard = self.listener.lock().await;
        if guard.is_some() {
            return Err(InboundError::AlreadyStarted(self.tag.clone()));
        }
        // 切片2 固定绑定 127.0.0.1:0（端口由 OS 分配），与 socks/trojan/http 切片2 一致。
        // 切片3 从 config 读取 bind 地址。
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| InboundError::ListenError(e.to_string()))?;
        *guard = Some(listener);
        tracing::info!(tag = %self.tag, "dokodemo inbound started");

        Ok(())
    }

    async fn close(&self) -> std::result::Result<(), InboundError> {
        let mut guard = self.listener.lock().await;
        if guard.is_none() {
            return Err(InboundError::Closed(self.tag.clone()));
        }
        // drop listener 即关闭监听
        *guard = None;
        tracing::info!(tag = %self.tag, "dokodemo inbound closed");
        Ok(())
    }

    fn port(&self) -> u16 {
        // 同步方法无法 await Mutex，用 try_lock 或 blocking_lock。
        // ponytail: 端口查询不频繁，blocking_lock 可接受。
        // 但 tokio::sync::Mutex 没有 blocking_lock；用 try_lock + 处理失败。
        // 切片2 用 0 占位（实际端口在 start 后可通过 local_addr 获取，但需 async）。
        // 切片3 改为 async port 或缓存在 struct 中。
        let guard = self.listener.try_lock();
        match guard {
            Ok(g) => match &*g {
                Some(l) => l.local_addr().map(|a| a.port()).unwrap_or(0),
                None => 0,
            },
            Err(_) => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpStream;
    use xray_proto::xray::common::net::ip_or_domain::Address as ProtoAddress;
    use xray_proto::xray::common::net::IpOrDomain as ProtoIpOrDomain;

    fn make_ipv4_config(ip: [u8; 4], port: u32) -> Config {
        Config {
            rewrite_address: Some(ProtoIpOrDomain {
                address: Some(ProtoAddress::Ip(ip.to_vec())),
            }),
            rewrite_port: port,
            allowed_networks: vec![Network::Tcp],
            ..Default::default()
        }
    }

    #[test]
    fn build_destination_ipv4() {
        let server = DokodemoServer::new("test", make_ipv4_config([192, 168, 1, 1], 8080));
        let dest = server.build_destination().expect("dest should exist");
        assert_eq!(dest.port().value(), 8080);
        match dest.address() {
            Address::IPv4(v4) => assert_eq!(v4.octets(), [192, 168, 1, 1]),
            other => panic!("expected IPv4, got {other:?}"),
        }
    }

    #[test]
    fn build_destination_domain() {
        let cfg = Config {
            rewrite_address: Some(ProtoIpOrDomain {
                address: Some(ProtoAddress::Domain("example.com".into())),
            }),
            rewrite_port: 443,
            allowed_networks: vec![Network::Tcp],
            ..Default::default()
        };
        let server = DokodemoServer::new("test", cfg);
        let dest = server.build_destination().expect("dest should exist");
        assert_eq!(dest.port().value(), 443);
        match dest.address() {
            Address::Domain(s) => assert_eq!(s, "example.com"),
            other => panic!("expected Domain, got {other:?}"),
        }
    }

    #[test]
    fn build_destination_none_when_no_address() {
        let server = DokodemoServer::new("test", Config::default());
        assert!(server.build_destination().is_none());
    }

    #[test]
    fn build_destination_none_when_port_overflow() {
        let server = DokodemoServer::new(
            "test",
            Config {
                rewrite_address: Some(ProtoIpOrDomain {
                    address: Some(ProtoAddress::Ip(vec![192, 168, 1, 1])),
                }),
                rewrite_port: 70_000, // u16 overflow
                ..Default::default()
            },
        );
        assert!(server.build_destination().is_none());
    }

    #[test]
    fn network_allowed_checks_config() {
        let server = DokodemoServer::new("test", make_ipv4_config([1, 2, 3, 4], 80));
        assert!(server.is_network_allowed(Network::Tcp));
        assert!(!server.is_network_allowed(Network::Udp));
    }






    #[test]
    fn tag_returns_constructor_tag() {
        let server = DokodemoServer::new("my-tag", Config::default());
        assert_eq!(server.tag(), "my-tag");
    }

    #[test]
    fn port_zero_before_start() {
        let server = DokodemoServer::new("test", Config::default());
        assert_eq!(server.port(), 0);
    }

    #[test]
    fn ipv6_address_handled() {
        let server = DokodemoServer::new(
            "test",
            Config {
                rewrite_address: Some(ProtoIpOrDomain {
                    address: Some(ProtoAddress::Ip(vec![
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                    ])),
                }),
                rewrite_port: 443,
                allowed_networks: vec![Network::Tcp],
                ..Default::default()
            },
        );
        let dest = server.build_destination().unwrap();
        assert_eq!(dest.port().value(), 443);
        match dest.address() {
            Address::IPv6(v6) => assert_eq!(v6.octets(), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            other => panic!("expected IPv6, got {other:?}"),
        }
    }
}
