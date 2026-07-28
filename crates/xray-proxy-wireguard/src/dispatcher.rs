//! WireGuard outbound → DialBridge 适配器。
//!
//! 把 [`WireguardOutboundHandler`] 接入 dispatcher 的 [`DialBridge`]。
//!
//! ## 当前限制
//!
//! WireGuard 通过 smoltcp userspace netstack 转发流量。`WireguardOutboundHandler::dial`
//! 在 netstack 上创建 TCP/UDP socket，但 smoltcp socket 不直接 impl `AsyncRead/AsyncWrite`，
//! Link 桥接（smoltcp socket ↔ tokio duplex）留待后续切片。
//!
//! 当前 `make_wireguard_dial_fn` lazy init handler + driver task，
//! dial 时在 netstack 上创建 socket 但返回错误（Link 桥接待实现）。

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::OnceCell;

use xray_app_dispatcher::default::DialFn;
use xray_common::net::address::Address;
use xray_common::net::destination::Destination;
use xray_common::net::network::Network;
use xray_transport::connection::Connection;

use crate::config::DeviceConfig;
use crate::outbound::WireguardOutboundHandler;

/// WireGuard 连接包装（占位——Link 桥接待实现）。
///
/// 当前不提供真实 IO，仅满足 `Connection` trait 约束。
/// 后续切片将桥接 smoltcp TCP socket 到 AsyncRead/AsyncWrite。
pub struct WireguardConnection;

impl AsyncRead for WireguardConnection {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // ponytail: smoltcp socket → AsyncRead 桥接待实现
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "wireguard outbound read: link bridging not yet implemented",
        )))
    }
}

impl AsyncWrite for WireguardConnection {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "wireguard outbound write: link bridging not yet implemented",
        )))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl Connection for WireguardConnection {
    fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(None)
    }
    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(None)
    }
}

/// 构造 DialBridge 用的 DialFn 闭包（lazy init 模式）。
///
/// 闭包捕获 `DeviceConfig`。首次 dial 时通过 `OnceCell` lazy init
/// `WireguardOutboundHandler`（含 driver task + smoltcp netstack）。
///
/// # Panics
/// 不会 panic；任何错误以 `Err(String)` 返回。
pub fn make_wireguard_dial_fn(config: DeviceConfig) -> DialFn {
    let handler: Arc<OnceCell<WireguardOutboundHandler>> = Arc::new(OnceCell::new());
    let config_clone = config.clone();

    Arc::new(move |dest: &Destination| {
        let dest = dest.clone();
        let config = config_clone.clone();
        let handler_cell = Arc::clone(&handler);

        Box::pin(async move {
            // lazy init WireguardOutboundHandler（含 driver task）
            let _handler = handler_cell
                .get_or_try_init(|| async {
                    WireguardOutboundHandler::new("wireguard", &config).await
                })
                .await
                .map_err(|e| format!("wireguard handler init: {e}"))?;

            // 验证目标地址类型（WireGuard 仅支持 IP，不支持 Domain）
            match dest.address() {
                Address::IPv4(_) | Address::IPv6(_) => {}
                Address::Domain(_) => {
                    return Err(
                        "wireguard outbound does not support Domain (DNS resolve by upper layer)"
                            .to_string(),
                    );
                }
            }

            // 仅 TCP（当前仅 TCP relay）
            if dest.network() != Network::TCP {
                return Err("wireguard outbound only supports TCP in dial_fn".to_string());
            }

            // ponytail: smoltcp socket → Connection 桥接待实现
            // 当前返回 WireguardConnection 占位（IO 会返回 Unsupported 错误）
            Ok(Box::new(WireguardConnection) as Box<dyn Connection>)
        })
    })
}
