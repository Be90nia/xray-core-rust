//! Trojan 出站处理器（client），对应 Go `proxy/trojan/client.go`。
//!
//! 实现 [`ProxyOutbound`] trait，通过 Trojan 代理出站连接。
//!
//! # 流程
//!
//! 1. `dialer.dial(server_dest)` 拨号到 Trojan 服务器
//! 2. `write_request_header` 写 Trojan 请求头
//! 3. 桥接 `link`（入站）↔ `server_conn`（出站）双向数据

use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::AsyncWriteExt;
use tracing::debug;
use xray_app_proxyman::error::ProxymanError;
use xray_app_proxyman::outbound::proxy_outbound::{OutboundDialer, ProxyOutbound};
use xray_common::net::network::Network as XrayNetwork;
use xray_common::session::Session;
use xray_transport::bridge::bridge_link_with_stream_full;
use xray_transport::link::Link;

use crate::config::MemoryAccount;
use crate::protocol::{write_request_header, Network as TrojanNetwork};
/// Trojan 出站客户端。
///
/// 持有账户信息，实现 [`ProxyOutbound`] trait。
/// `process()` 被调度器调用时：拨号到 Trojan 服务器 → 写请求头 → 桥接数据。
pub struct TrojanClient {
    /// Trojan 用户账户（含 hex(sha224(password)) key）。
    account: MemoryAccount,
}

impl TrojanClient {
    /// 创建 Trojan 出站客户端。
    pub fn new(account: MemoryAccount) -> Self {
        Self { account }
    }
}

#[async_trait]
impl ProxyOutbound for TrojanClient {
    /// 处理出站连接：拨号到 Trojan 服务器 → 写请求头 → 桥接数据。
    ///
    /// 对应 Go `proxy/trojan/client.go::Client.Process`。
    async fn process(
        &self,
        session: &Session,
        link: Link,
        dialer: Arc<dyn OutboundDialer>,
    ) -> Result<(), ProxymanError> {
        let dest = session
            .destination()
            .ok_or_else(|| ProxymanError::Other("trojan: no destination in session".to_string()))?;

        // 1. 拨号到 Trojan 服务器（Go client.go:62 — retry.ExponentialBackoff(5, 100)）
        let mut server_conn = xray_transport::retry::exponential_backoff(5, 100, || dialer.dial(&dest))
            .await
            .map_err(|e| ProxymanError::Other(format!("trojan dial server: {e}")))?;

        // 2. 构造 Trojan 请求头
        let network = match dest.network() {
            XrayNetwork::UDP => TrojanNetwork::Udp,
            _ => TrojanNetwork::Tcp,
        };
        let mut header = Vec::with_capacity(128);
        write_request_header(
            &mut header,
            &self.account,
            network,
            dest.address(),
            dest.port().value(),
        );

        // 3. 写请求头到服务器连接
        server_conn
            .write_all(&header)
            .await
            .map_err(|e| ProxymanError::Other(format!("trojan write header: {e}")))?;

        debug!(
            tag = "trojan_client",
            dest = %dest,
            network = ?network,
            "trojan outbound connected"
        );

        // 4. 双向桥接：link.reader/writer ↔ server_conn
        bridge_link_with_stream_full(link, server_conn)
            .await
            .map_err(|e| ProxymanError::Other(format!("trojan bridge: {e}")))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xray_common::net::address::Address;
    use xray_common::net::destination::Destination;
    use xray_common::net::port::Port;

    #[test]
    fn trojan_client_new_stores_account() {
        let account = MemoryAccount::new("test_password");
        let client = TrojanClient::new(account);
        assert_eq!(client.account.password, "test_password");
    }

    #[test]
    fn trojan_header_format_is_valid() {
        let account = MemoryAccount::new("test_password");
        let dest = Destination::new(
            Address::from_ipv4_bytes([127, 0, 0, 1]),
            Port::new(80),
            XrayNetwork::TCP,
        );

        let mut header = Vec::new();
        write_request_header(&mut header, &account, TrojanNetwork::Tcp, dest.address(), 80);

        // 验证 header 格式：56字节key + CRLF + cmd + addr + CRLF
        assert!(header.len() > 56 + 2 + 1 + 1 + 2 + 2, "header too short: {}", header.len());
        assert_eq!(&header[56..58], b"\r\n", "CRLF after key");
        assert_eq!(header[58], 1, "COMMAND_TCP byte");
    }

    #[test]
    fn trojan_udp_header_uses_command_udp() {
        let account = MemoryAccount::new("test_password");
        let dest = Destination::new(
            Address::from_ipv4_bytes([10, 0, 0, 1]),
            Port::new(53),
            XrayNetwork::UDP,
        );

        let mut header = Vec::new();
        write_request_header(&mut header, &account, TrojanNetwork::Udp, dest.address(), 53);

        assert_eq!(header[58], 3, "COMMAND_UDP byte");
    }
}
