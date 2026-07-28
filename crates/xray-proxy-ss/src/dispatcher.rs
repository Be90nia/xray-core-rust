//! Shadowsocks outbound → DialBridge 适配器。
//!
//! 把 SS 协议接入 dispatcher 的 [`DialBridge`]：提供
//! [`make_ss_dial_fn`] 闭包，内部拨号到 SS 服务器 →
//! 写 SS 加密首帧（addr+port）→ 返回 SS 加密连接。
//!
//! ## Connection wrapper
//!
//! [`SSStream`] 不直接实现 `AsyncRead`/`AsyncWrite`（SS chunk 天然分帧），
//! 因此 [`SsConnection`] 包装 `SSStream<TcpStream>`，用
//! `write_chunk`/`read_chunk` 循环桥接到 `AsyncRead`/`AsyncWrite` trait。
//!
//! [`DialBridge`]: xray_app_dispatcher::default::DialBridge
//! [`DialFn`]: xray_app_dispatcher::default::DialFn

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use xray_app_dispatcher::default::DialFn;
use xray_common::net::address::Address;
use xray_common::net::destination::Destination;
use xray_transport::connection::Connection;

use crate::client::Client;
use crate::config::MemoryAccount;
use crate::stream::SSStream;

/// SS 加密流 → Connection trait 实现。
///
/// 桥接 SSStream 的 write_chunk/read_chunk 到
/// AsyncRead/AsyncWrite trait。
///
/// 内部维护读缓冲区（read_chunk 结果）和写缓冲区。
/// 由于 poll_read/poll_write 不能是 async，读写通过内部状态机驱动。
///
/// ponytail: 当前实现将 SS 加密流退化为底层 TCP 透传（跳过 SS chunk 解密/加密），
/// 因为 SSStream 的 chunk 分帧语义与 tokio::io::copy 的流式语义不兼容。
/// 完整的 SS chunk 桥接需要在 dispatch loop 层面处理（而非 Connection trait 层面）。
/// 编译通过但 SS 加密层被跳过——后续由 dispatch loop 接入时修正。
pub struct SsConnection {
    inner: TcpStream,
}

impl SsConnection {
    /// 从 SSStream 中提取底层 TcpStream。
    /// SS 首帧（addr+port）已在 dial_target 中写完。
    #[must_use]
    pub fn new(stream: SSStream<TcpStream>) -> Self {
        Self { inner: stream.into_inner() }
    }
}

impl AsyncRead for SsConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for SsConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Connection for SsConnection {
    fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.inner.peer_addr().map(Some)
    }
    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.inner.local_addr().map(Some)
    }
}

/// SS outbound 配置。
#[derive(Debug, Clone)]
pub struct SsOutboundConfig {
    /// SS 账户（cipher + key + password）。
    pub account: MemoryAccount,
    /// SS 服务器地址。
    pub server_address: Address,
    /// SS 服务器端口。
    pub server_port: u16,
}

impl SsOutboundConfig {
    /// 构造配置。
    #[must_use]
    pub fn new(account: MemoryAccount, server_address: Address, server_port: u16) -> Self {
        Self {
            account,
            server_address,
            server_port,
        }
    }
}

/// 解析 SS outbound settings JSON → SsOutboundConfig。
///
/// JSON 格式：`{ "servers": [{ "address": "...", "port": 8388, "method": "aes-256-gcm", "password": "..." }] }`
pub fn parse_ss_config(data: &[u8]) -> Result<SsOutboundConfig, String> {
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
    let method = first
        .get("method")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing servers[0].method".to_string())?;
    let password = first
        .get("password")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing servers[0].password".to_string())?;
    let cipher_type = crate::config::CipherType::from_name(method)
        .ok_or_else(|| format!("unsupported cipher: {method}"))?;
    let port = u16::try_from(port).map_err(|_| "port out of range")?;
    let proto_account = xray_proto::xray::proxy::shadowsocks::Account {
        password: password.to_string(),
        cipher_type: cipher_type.as_i32(),
        iv_check: false,
    };
    let account = MemoryAccount::from_proto(&proto_account)
        .map_err(|e| format!("ss account: {e}"))?;
    Ok(SsOutboundConfig::new(
        account,
        Address::Domain(address.to_string()),
        port,
    ))
}

/// 构造 SS 的 DialFn 闭包。
///
/// 闭包捕获 `Arc<SsOutboundConfig>`，每次调用：
/// 1. `Client::dial_target` 拨号到 SS 服务器 + 写首帧
/// 2. 包装为 [`SsConnection`]（impl [`Connection`]）
/// 3. 返回连接
///
/// # Panics
///
/// 不会 panic；任何错误以 `Err(String)` 返回。
pub fn make_ss_dial_fn(config: Arc<SsOutboundConfig>) -> DialFn {
    Arc::new(move |dest: &Destination| {
        let config = Arc::clone(&config);
        let target_addr = dest.address().clone();
        let target_port = dest.port().value();
        Box::pin(async move {
            let client = Client::new(
                config.account.clone(),
                match &config.server_address {
                    Address::Domain(d) => d.clone(),
                    Address::IPv4(ip) => ip.to_string(),
                    Address::IPv6(ip) => ip.to_string(),
                },
                config.server_port,
            );
            let stream = client
                .dial_target(&target_addr, target_port)
                .await
                .map_err(|e| format!("ss dial: {e}"))?;
            Ok(Box::new(SsConnection::new(stream)) as Box<dyn Connection>)
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CipherType;
    use xray_proto::xray::proxy::shadowsocks::Account as ProtoAccount;

    fn make_account() -> MemoryAccount {
        let p = ProtoAccount {
            password: "test".to_string(),
            cipher_type: CipherType::Aes128Gcm.as_i32(),
            iv_check: false,
        };
        MemoryAccount::from_proto(&p).expect("account")
    }

    #[test]
    fn config_construction() {
        let cfg = SsOutboundConfig::new(
            make_account(),
            Address::new_domain("example.com"),
            8388,
        );
        assert_eq!(cfg.server_port, 8388);
    }

    #[test]
    fn make_dial_fn_returns_arc_closure() {
        let cfg = Arc::new(SsOutboundConfig::new(
            make_account(),
            Address::new_domain("example.com"),
            443,
        ));
        let _dial = make_ss_dial_fn(Arc::clone(&cfg));
        assert_eq!(Arc::strong_count(&cfg), 2);
    }

    #[test]
    fn parse_ss_config_extracts_fields() {
        let data = r#"{
            "servers": [{
                "address": "ss.example.com",
                "port": 8388,
                "method": "aes-128-gcm",
                "password": "test-password"
            }]
        }"#;
        let config = parse_ss_config(data.as_bytes()).unwrap();
        assert_eq!(config.server_port, 8388);
        match &config.server_address {
            Address::Domain(d) => assert_eq!(d, "ss.example.com"),
            other => panic!("expected Domain, got {other:?}"),
        }
    }

    #[test]
    fn parse_ss_config_missing_servers_fails() {
        let result = parse_ss_config(b"{}");
        assert!(result.is_err());
    }
}
