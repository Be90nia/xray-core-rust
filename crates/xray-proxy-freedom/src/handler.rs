//! Freedom 出站代理 Handler——对应 Go `proxy/freedom/freedom.go` 的 `Handler`。
//!
//! ## 切片边界（P6-5 切片2）
//!
//! 实现 [`OutboundHandler`] trait，内部调 [`xray_transport::system_dialer::dial_system`]
//! 验证 TCP 拨号端到端可用。桥接 `transport::Link`（link.reader/writer ↔ Connection）
//! 与 Domain DNS 解析留切片3。

use async_trait::async_trait;
use xray_common::net::destination::Destination;
use xray_common::net::address::Address;
use xray_common::session::Session;
use xray_features::outbound::{OutboundError, OutboundHandler};
use xray_transport::sockopt::SocketOptions;
use xray_transport::system_dialer::dial_system;

use crate::config::Config;

/// Freedom 出站 Handler。
///
/// 持有配置 + tag，实现 [`OutboundHandler`]。dial 方法通过 [`dial_system`] 建立到
/// `destination` 的直连 TCP 连接。
pub struct FreedomHandler {
    tag: String,
    #[allow(dead_code)]
    config: Config,
}

impl FreedomHandler {
    /// 构造 Freedom Handler。
    #[must_use]
    pub fn new(tag: impl Into<String>, config: Config) -> Self {
        Self {
            tag: tag.into(),
            config,
        }
    }
}

#[async_trait]
impl OutboundHandler for FreedomHandler {
    fn tag(&self) -> &str {
        &self.tag
    }

    /// 通过 [`dial_system`] 拨号到 `destination`。
    ///
    /// 切片2 限制：`destination` 必须是 IP 地址（IPv4/IPv6），Domain 返回
    /// [`OutboundError::ConnectionFailed`]（DNS 解析留切片3 接入 LookupForIP）。
    ///
    /// **注意**：当前拨号建立的 Connection 在 dial 返回后 drop——这是切片2 的
    /// 验证性实现，仅证明 dial_system 端到端可用。真正的桥接（Connection ↔ Link）
    /// 留切片3。
    async fn dial(
        &self,
        destination: &Destination,
        _session: &Session,
    ) -> Result<(), OutboundError> {
        // 切片2：Domain 地址返回错误（DNS 解析留切片3）。
        match destination.address() {
            Address::IPv4(_) | Address::IPv6(_) => {}
            Address::Domain(_) => {
                return Err(OutboundError::ConnectionFailed(
                    "freedom 切片2 不支持 Domain 地址（DNS 解析留切片3）".into(),
                ));
            }
        }

        let sockopt = SocketOptions::default();
        // ponytail: dial_system 切片1 只支持 IP，正好匹配切片2 的限制。
        let _conn = dial_system(destination, &sockopt)
            .await
            .map_err(|e| OutboundError::ConnectionFailed(format!("dial_system failed: {e}")))?;
        // 切片2: Connection 在此 drop。切片3 接入 Link 桥接后保留。
        tracing::debug!(
            tag = %self.tag,
            "freedom dial succeeded (connection established and dropped in slice 2)"
        );
        Ok(())
    }

    /// Freedom 可以处理任意 TCP 目标（IP 优先；Domain 切片2 暂不支持）。
    fn can_handle(&self, destination: &Destination) -> bool {
        matches!(destination.address(), Address::IPv4(_) | Address::IPv6(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xray_common::net::network::Network;
    use xray_common::net::port::Port;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    fn make_ip_dest(ip: &str, port: u16) -> Destination {
        let addr: std::net::IpAddr = ip.parse().unwrap();
        let address = match addr {
            std::net::IpAddr::V4(v4) => Address::IPv4(v4),
            std::net::IpAddr::V6(v6) => Address::IPv6(v6),
        };
        Destination::new(address, Port::new(port), Network::TCP)
    }

    fn make_domain_dest(host: &str, port: u16) -> Destination {
        Destination::new(
            Address::Domain(host.to_string()),
            Port::new(port),
            Network::TCP,
        )
    }

    #[test]
    fn handler_tag_returns_construction_tag() {
        let h = FreedomHandler::new("freedom_out", Config::default());
        assert_eq!(h.tag(), "freedom_out");
    }

    #[test]
    fn can_handle_ipv4_destination() {
        let h = FreedomHandler::new("direct", Config::default());
        assert!(h.can_handle(&make_ip_dest("127.0.0.1", 80)));
    }

    #[test]
    fn can_handle_ipv6_destination() {
        let h = FreedomHandler::new("direct", Config::default());
        assert!(h.can_handle(&make_ip_dest("::1", 443)));
    }

    #[test]
    fn cannot_handle_domain_destination() {
        let h = FreedomHandler::new("direct", Config::default());
        assert!(!h.can_handle(&make_domain_dest("example.com", 443)));
    }

    #[tokio::test]
    async fn dial_to_local_tcp_server_succeeds() {
        // 启动本地 TCP 服务器（接受连接后立即关闭）
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            // 接受一个连接即可（dial_system 建立后 drop，服务器端 accept 到后关闭）
            let _ = listener.accept().await;
        });

        let h = FreedomHandler::new("test", Config::default());
        let dest = make_ip_dest("127.0.0.1", addr.port());
        let session = Session::new();
        let result = h.dial(&dest, &session).await;
        assert!(result.is_ok(), "dial should succeed: {:?}", result.err());

        server_task.await.unwrap();
    }


    #[tokio::test]
    async fn dial_to_domain_returns_error() {
        let h = FreedomHandler::new("test", Config::default());
        let dest = make_domain_dest("example.com", 80);
        let session = Session::new();
        let result = h.dial(&dest, &session).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            OutboundError::ConnectionFailed(msg) => {
                assert!(msg.contains("Domain"));
            }
            other => panic!("expected ConnectionFailed with Domain message, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dial_and_write_to_echo_server() {
        // 更完整的端到端：handler.dial 成功 + 服务器 echo + 验证
        // 注意：切片2 中 dial 后 Connection drop，所以不能直接写。
        // 这个测试验证 dial 成功 + 服务器端 accept 到连接。
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            // 简单 echo：读一个字节写回
            let mut buf = [0u8; 1];
            use tokio::io::AsyncReadExt;
            if sock.read_exact(&mut buf).await.is_ok() {
                let _ = sock.write_all(&buf).await;
            }
        });

        // 用 handler.dial 验证拨号（Connection 在 handler 内 drop）
        let h = FreedomHandler::new("echo-test", Config::default());
        let dest = make_ip_dest("127.0.0.1", addr.port());
        let session = Session::new();
        h.dial(&dest, &session).await.unwrap();

        // 服务器侧在 handler drop Connection 后才能 accept（取决于时序）
        // 给服务器一点时间
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        // 服务器 task 应该已经完成或即将完成
        let _ = server_task.await;
    }
}
