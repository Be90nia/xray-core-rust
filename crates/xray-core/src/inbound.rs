//! SOCKS5 inbound listener：接收连接 → SOCKS5 握手 → dispatcher 分发。
//!
//! 对应 Go `app/proxyman/inbound/always.go::handle_connection` + `proxy/socks/server.go`。
//! 这里实现最小端到端切片：TCP accept → socks5 handshake → SocksAddr → Destination →
//! `DispatchHandler::dispatch(dest, link)`。
//!
//! 不含：sniffing（协议嗅探）、UDP associate、多 inbound 注册管理（由 proxyman::InboundManager 负责）。

use std::net::Ipv4Addr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use xray_app_dispatcher::default::SimpleOhm;
use xray_app_dispatcher::OutboundHandlerManager;
use xray_buf::io::{new_reader, new_writer};
use xray_common::net::address::Address;
use xray_common::net::destination::Destination;
use xray_common::net::network::Network;
use xray_common::net::port::Port;
use xray_proxy_socks::protocol::{Host, SocksAddr};
use xray_proxy_socks::server::socks5_server_handshake;
use xray_proxy_socks::ServerConfig;
use xray_transport::link::Link;

/// SOCKS5 inbound 服务入口。
///
/// 绑定 `addr` 监听，每个连接 spawn 独立 task：
/// 1. SOCKS5 握手得目标 `SocksAddr`
/// 2. 转 `Destination`，构造 `Link`（用 TcpStream 的 read/write half）
/// 3. `ohm` 的 default handler `dispatch(dest, link)` 拨号并桥接
///
/// # 参数
/// - `listener`：已绑定的 TCP listener
/// - `ohm`：出站管理器（至少有 default handler）
/// - `config`：SOCKS5 server 配置（auth method 等）
///
/// # 错误
/// accept 循环自身错误返回；单个连接错误只 log 不中断循环。
pub async fn serve_socks5(
    listener: TcpListener,
    ohm: Arc<SimpleOhm>,
    config: Arc<ServerConfig>,
) -> std::io::Result<()> {
    let handler = ohm
        .get_default_handler()
        .ok_or_else(|| std::io::Error::other("no default outbound handler registered"))?;

    tracing::info!(
        addr = %listener.local_addr()?,
        "socks5 inbound listening"
    );

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "socks5 accept failed");
                continue;
            }
        };

        let handler = Arc::clone(&handler);
        let config = Arc::clone(&config);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, &config, &handler).await {
                tracing::debug!(error = %e, "socks5 connection ended with error");
            }
        });

        let _ = peer; // 仅 log 级别可用，当前不记
    }
}

/// 处理单个 SOCKS5 连接：handshake → dispatch。
async fn handle_connection(
    mut stream: TcpStream,
    config: &ServerConfig,
    handler: &Arc<dyn xray_app_dispatcher::DispatchHandler>,
) -> std::io::Result<()> {
    // 1. SOCKS5 握手
    let socks_addr = socks5_server_handshake(&mut stream, config)
        .await
        .map_err(|e| std::io::Error::other(format!("socks5 handshake: {e}")))?;

    // 2. SocksAddr → Destination
    let dest = socks_addr_to_destination(&socks_addr)?;

    // 3. 拆 TcpStream → (read, write) → Link
    // ponytail: tokio::io::split 返回的 ReadHalf/WriteHalf 是 'static + Send，
    // new_reader/new_writer 接受 AsyncRead/AsyncWrite + Unpin + Send + 'static。
    let (read_half, write_half) = tokio::io::split(stream);
    let link = Link::new(new_reader(read_half), new_writer(write_half));

    // 4. dispatch（dispatch 内部拨号 + bridge，消耗 link）
    let _ = handler.dispatch(&dest, link).await;

    Ok(())
}

/// `SocksAddr` → `Destination`（TCP）。
///
/// `Host::Ipv4` → `Address::IPv4`，`Ipv6` → `Address::IPv6`，`Domain` → `Address::Domain`。
fn socks_addr_to_destination(addr: &SocksAddr) -> std::io::Result<Destination> {
    let address = match &addr.host {
        Host::Ipv4(ip) => Address::IPv4(*ip),
        Host::Ipv6(ip) => Address::IPv6(*ip),
        Host::Domain(d) => Address::Domain(d.clone()),
    };
    Ok(Destination::new(address, Port::new(addr.port), Network::TCP))
}

#[cfg(test)]
mod tests {
    use super::*;
    use xray_app_dispatcher::default::SimpleOhm;
    use xray_proxy_freedom::make_freedom_dial_fn;
    use xray_proxy_socks::protocol::{ATYP_DOMAIN, ATYP_IPV4};

    /// 端到端：SOCKS5 client → SOCKS5 inbound → freedom outbound → echo server。
    #[tokio::test]
    async fn socks5_inbound_to_freedom_outbound_e2e() {
        // 1. 起 echo server
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = echo_listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if sock.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });

        // 2. 配置 dispatcher：freedom outbound → SimpleOhm default
        let ohm = Arc::new(SimpleOhm::new());
        let dial_fn = make_freedom_dial_fn();
        let bridge = std::sync::Arc::new(xray_app_dispatcher::default::DialBridge::new(
            "freedom",
            dial_fn,
        )) as std::sync::Arc<dyn xray_app_dispatcher::DispatchHandler>;
        ohm.set_default(bridge);

        // 3. 起 SOCKS5 inbound
        let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_addr = socks_listener.local_addr().unwrap();
        let config = Arc::new(ServerConfig::default());
        let ohm_clone = Arc::clone(&ohm);
        tokio::spawn(async move {
            let _ = serve_socks5(socks_listener, ohm_clone, config).await;
        });

        // 4. SOCKS5 client：连 socks5 → handshake → 请求 echo server → 写数据 → 读 echo
        let mut client = TcpStream::connect(socks_addr).await.unwrap();
        // 握手：版本 5，1 method，no-auth(0)
        client
            .write_all(&[0x05, 0x01, 0x00])
            .await
            .unwrap();
        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [0x05, 0x00], "server should select no-auth");

        // 请求 CONNECT echo_addr（IPv4）
        let ip = echo_addr.ip();
        assert!(ip.is_ipv4(), "echo addr should be ipv4");
        let ipv4_bytes = match ip {
            std::net::IpAddr::V4(v4) => v4.octets(),
            _ => unreachable!(),
        };
        let port_bytes = echo_addr.port().to_be_bytes();
        let mut req = vec![0x05, 0x01, 0x00, ATYP_IPV4];
        req.extend_from_slice(&ipv4_bytes);
        req.extend_from_slice(&port_bytes);
        client.write_all(&req).await.unwrap();

        // 读 CONNECT 成功响应（10 字节）
        let mut connect_resp = [0u8; 10];
        client.read_exact(&mut connect_resp).await.unwrap();
        assert_eq!(connect_resp[1], 0x00, "CONNECT should succeed");

        // 5. 发数据 + 读 echo
        let payload = b"hello socks5 proxy!";
        client.write_all(payload).await.unwrap();

        let mut got = vec![0u8; payload.len()];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, payload, "should receive echo through proxy");
    }

    #[test]
    fn socks_addr_to_destination_ipv4() {
        let addr = SocksAddr {
            host: Host::Ipv4(Ipv4Addr::new(1, 2, 3, 4)),
            port: 8080,
        };
        let dest = socks_addr_to_destination(&addr).unwrap();
        assert!(dest.is_tcp());
        assert_eq!(dest.port(), Port::new(8080));
        match dest.address() {
            Address::IPv4(ip) => assert_eq!(ip.octets(), [1, 2, 3, 4]),
            other => panic!("expected IPv4, got {other:?}"),
        }
    }

    #[test]
    fn socks_addr_to_destination_domain() {
        let addr = SocksAddr {
            host: Host::Domain("example.com".to_string()),
            port: 443,
        };
        let dest = socks_addr_to_destination(&addr).unwrap();
        assert_eq!(dest.port(), Port::new(443));
        match dest.address() {
            Address::Domain(d) => assert_eq!(d, "example.com"),
            other => panic!("expected Domain, got {other:?}"),
        }
        let _ = ATYP_DOMAIN; // 确认 import 路径
    }
}
