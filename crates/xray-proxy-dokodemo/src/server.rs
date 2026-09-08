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

/// 将 [`PredefinedAddress`] 转为 [`Address`]。
fn predefined_to_address(addr: PredefinedAddress) -> Address {
    match addr {
        PredefinedAddress::Ip(ip) => match ip {
            std::net::IpAddr::V4(v4) => Address::IPv4(v4),
            std::net::IpAddr::V6(v6) => Address::IPv6(v6),
        },
        PredefinedAddress::Domain(s) => Address::Domain(s),
    }
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
    /// 优先级：
    /// 1. `follow_redirect=true` + fd 有效 → 从 SO_ORIGINAL_DST 获取原始目的地
    /// 2. `predefined_address` + `rewrite_port` + `port_map` 构造
    ///
    /// `local_port` 用于 `port_map` 查找（监听端口字符串），`None` 跳过映射。
    /// `is_udp` 为 true 时返回 UDP 目标，否则 TCP。
    ///
    /// 返回 `None` 表示无法确定目标。
    fn build_destination_ex(
        &self,
        fd: Option<i32>,
        local_port: Option<u16>,
        is_udp: bool,
    ) -> Option<Destination> {
        // 3pbz：SO_ORIGINAL_DST 是 Linux-only（iptables REDIRECT 生态）。
        // 非 Linux 平台虽 cfg 允许 `follow_redirect=true`，
        // `get_original_dst` 永远返回 Err → silently 降级 fallback，
        // 运维侧疑惑"配了 follow_redirect 怎么还是固定地址"。
        // 启动期 / 首次分发时记 warn 让排障一目了然。
        #[cfg(not(target_os = "linux"))]
        if self.config.follow_redirect {
            tracing::warn!(
                target: "xray.dokodemo",
                tag = %self.tag,
                "follow_redirect is a no-op on this platform (Linux-only SO_ORIGINAL_DST); \
                 inbound will silently fall back to rewrite_address"
            );
        }

        if self.config.follow_redirect {
            if let Some(fd) = fd {
                if let Ok(addr) = xray_transport::sockopt::get_original_dst(fd) {
                    let address = match addr.ip() {
                        std::net::IpAddr::V4(v4) => Address::IPv4(v4),
                        std::net::IpAddr::V6(v6) => Address::IPv6(v6),
                    };
                    let port = Port::new(addr.port());
                    return Some(if is_udp {
                        Destination::udp(address, port)
                    } else {
                        Destination::tcp(address, port)
                    });
                }
            }
        }

        // 降级到 predefined_address + port_map
        let addr = self.config.predefined_address()?;
        let mut address = predefined_to_address(addr);
        let mut port_val = u16::try_from(self.config.rewrite_port).ok()?;

        // port_map：当监听端口匹配时覆盖地址/端口（对应 Go Process() 第 101-109 行）
        if let Some(lp) = local_port {
            if let Some((host_override, port_override)) =
                self.config.apply_port_map(&lp.to_string())
            {
                if let Some(h) = host_override {
                    address = h.parse::<Address>().unwrap_or(address);
                }
                if let Some(p) = port_override {
                    port_val = p;
                }
            }
        }

        let port = Port::new(port_val);
        Some(if is_udp {
            Destination::udp(address, port)
        } else {
            Destination::tcp(address, port)
        })
    }

    /// 构造 TCP 目标（兼容旧调用方）。等价于 `build_destination_ex(fd, None, false)`。
    fn build_destination(&self, fd: Option<i32>) -> Option<Destination> {
        self.build_destination_ex(fd, None, false)
    }

    /// 构造 UDP 目标。用于 dokodemo UDP relay。
    fn build_udp_destination(&self, local_port: Option<u16>) -> Option<Destination> {
        self.build_destination_ex(None, local_port, true)
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
        let dest = server.build_destination(None).expect("dest should exist");
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
        let dest = server.build_destination(None).expect("dest should exist");
        assert_eq!(dest.port().value(), 443);
        match dest.address() {
            Address::Domain(s) => assert_eq!(s, "example.com"),
            other => panic!("expected Domain, got {other:?}"),
        }
    }

    #[test]
    fn build_destination_none_when_no_address() {
        let server = DokodemoServer::new("test", Config::default());
        assert!(server.build_destination(None).is_none());
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
        assert!(server.build_destination(None).is_none());
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
        let dest = server.build_destination(None).unwrap();
        assert_eq!(dest.port().value(), 443);
        match dest.address() {
            Address::IPv6(v6) => assert_eq!(v6.octets(), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            other => panic!("expected IPv6, got {other:?}"),
        }
    }

    #[test]
    fn follow_redirect_without_fd_falls_back_to_predefined() {
        let server = DokodemoServer::new(
            "test",
            Config {
                follow_redirect: true,
                rewrite_address: Some(ProtoIpOrDomain {
                    address: Some(ProtoAddress::Ip(vec![10, 0, 0, 1])),
                }),
                rewrite_port: 443,
                allowed_networks: vec![Network::Tcp],
                ..Default::default()
            },
        );
        // 无 fd 时降级到 predefined_address
        let dest = server.build_destination(None).expect("should fall back to predefined");
        match dest.address() {
            Address::IPv4(v4) => assert_eq!(v4.octets(), [10, 0, 0, 1]),
            other => panic!("expected IPv4, got {other:?}"),
        }
    }

    #[test]
    fn follow_redirect_with_invalid_fd_falls_back_to_predefined() {
        let server = DokodemoServer::new(
            "test",
            Config {
                follow_redirect: true,
                rewrite_address: Some(ProtoIpOrDomain {
                    address: Some(ProtoAddress::Ip(vec![10, 0, 0, 1])),
                }),
                rewrite_port: 443,
                allowed_networks: vec![Network::Tcp],
                ..Default::default()
            },
        );
        // 无效 fd 时 get_original_dst 会失败，降级到 predefined_address
        let dest = server.build_destination(Some(-1)).expect("should fall back to predefined");
        match dest.address() {
            Address::IPv4(v4) => assert_eq!(v4.octets(), [10, 0, 0, 1]),
            other => panic!("expected IPv4, got {other:?}"),
        }
    }

    #[test]
    fn build_udp_destination_returns_udp_network() {
        let server = DokodemoServer::new("test", make_ipv4_config([1, 2, 3, 4], 53));
        let dest = server.build_udp_destination(None).expect("dest should exist");
        assert!(dest.is_udp());
        assert_eq!(dest.port().value(), 53);
    }

    #[test]
    fn build_destination_ex_applies_port_map() {
        let cfg = Config {
            rewrite_address: Some(ProtoIpOrDomain {
                address: Some(ProtoAddress::Ip(vec![10, 0, 0, 1])),
            }),
            rewrite_port: 80,
            port_map: [("80".to_string(), "192.168.99.1:9090".to_string())]
                .into_iter()
                .collect(),
            ..Default::default()
        };
        let server = DokodemoServer::new("test", cfg);
        let dest = server
            .build_destination_ex(None, Some(80), false)
            .expect("dest should exist");
        assert_eq!(dest.port().value(), 9090);
        match dest.address() {
            Address::IPv4(v4) => assert_eq!(v4.octets(), [192, 168, 99, 1]),
            other => panic!("expected mapped IPv4, got {other:?}"),
        }
    }

    #[test]
    fn build_destination_ex_port_map_no_match_uses_predefined() {
        let cfg = Config {
            rewrite_address: Some(ProtoIpOrDomain {
                address: Some(ProtoAddress::Ip(vec![10, 0, 0, 1])),
            }),
            rewrite_port: 80,
            port_map: [("443".to_string(), "192.168.99.1:9090".to_string())]
                .into_iter()
                .collect(),
            ..Default::default()
        };
        let server = DokodemoServer::new("test", cfg);
        let dest = server
            .build_destination_ex(None, Some(80), false)
            .expect("dest should exist");
        // port 80 not in port_map → use predefined
        assert_eq!(dest.port().value(), 80);
    }

    #[test]
    fn build_udp_destination_with_port_map() {
        let cfg = Config {
            rewrite_address: Some(ProtoIpOrDomain {
                address: Some(ProtoAddress::Ip(vec![10, 0, 0, 1])),
            }),
            rewrite_port: 53,
            port_map: [("53".to_string(), ":5353".to_string())]
                .into_iter()
                .collect(),
            ..Default::default()
        };
        let server = DokodemoServer::new("test", cfg);
        let dest = server
            .build_udp_destination(Some(53))
            .expect("dest should exist");
        assert!(dest.is_udp());
        assert_eq!(dest.port().value(), 5353);
    }
}
