//! Hysteria outbound → DialBridge 适配器。
//!
//! 把 [`HysteriaClient`]（QUIC stream）接入 dispatcher 的 [`DialBridge`]：
//! [`make_dial_fn`] 闭包内部 dial → `HysteriaClient::tcp()` → pump 桥接到 duplex。

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::sync::OnceCell;

use xray_app_dispatcher::default::DialFn;
use xray_common::net::address::Address;
use xray_common::net::destination::Destination;
use xray_common::net::network::Network;
use xray_transport::connection::Connection;
use xray_transport_hysteria::conn::InterStreamConn;
use xray_transport_hysteria::dialer::{
    ClientManager, DialDestination, HysteriaTransport,
};
use xray_transport_hysteria::proto_config::Config as ProtoConfig;

use crate::config::HysteriaConfig;

/// Hysteria duplex 缓冲（与 tuic 一致：64 KiB）。
const DUPLEX_BUF_SIZE: usize = 64 * 1024;

/// Hysteria 连接包装：内部用 `tokio::io::duplex` 桥接 InterStreamConn。
///
/// `_pump` 字段保证桥接 task 生命周期与连接一致——drop 时自动 abort。
pub struct HysteriaConnection {
    inner: DuplexStream,
    _pump: tokio::task::JoinHandle<()>,
}

impl AsyncRead for HysteriaConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for HysteriaConnection {
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

impl Connection for HysteriaConnection {
    fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(None)
    }
    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(None)
    }
}

impl HysteriaConnection {
    /// 从 InterStreamConn 构造：spawn pump 桥接，返回 duplex 客户端包装。
    fn from_stream(stream: Arc<InterStreamConn>) -> Self {
        let (client_io, server_io) = tokio::io::duplex(DUPLEX_BUF_SIZE);
        let pump = tokio::spawn(pump_hysteria_stream(stream, server_io));
        Self {
            inner: client_io,
            _pump: pump,
        }
    }
}

async fn pump_hysteria_stream(
    stream: Arc<InterStreamConn>,
    server_io: DuplexStream,
    ) {
    let (mut rd, mut wr) = tokio::io::split(server_io);
    let stream_down = Arc::clone(&stream);

    // up: duplex rd → hysteria stream write
    let up = async move {
        let mut buf = vec![0u8; 8 * 1024];
        loop {
            match rd.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = stream.write(&buf[..n]).await {
                        tracing::debug!("hysteria pump up write error: {e}");
                        break;
                    }
                }
                Err(e) => {
                    tracing::debug!("hysteria pump up read error: {e}");
                    break;
                }
            }
        }
        let _ = stream.close().await;
    };

    // down: hysteria stream read → duplex wr
    let down = async move {
        let mut buf = vec![0u8; 8 * 1024];
        loop {
            match stream_down.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = wr.write_all(&buf[..n]).await {
                        tracing::debug!("hysteria pump down write error: {e}");
                        break;
                    }
                }
                Err(e) => {
                    tracing::debug!("hysteria pump down read error: {e}");
                    break;
                }
            }
        }
        let _ = wr.shutdown().await;
    };

    tokio::join!(up, down);
}

/// 构造 DialBridge 用的 DialFn 闭包（lazy init 模式）。
///
/// 闭包捕获 `HysteriaConfig` + `Arc<dyn HysteriaTransport>`。
/// 首次 dial 时通过 `OnceCell` lazy init `ClientManager`，
/// 然后 `client_manager.get_or_create` → `client.tcp()` → pump 桥接。
///
/// # Panics
/// 不会 panic；任何错误以 `Err(String)` 返回。
pub fn make_hysteria_dial_fn(
    config: HysteriaConfig,
    transport: Arc<dyn HysteriaTransport>,
) -> DialFn {
    let client_manager: Arc<OnceCell<ClientManager>> = Arc::new(OnceCell::new());
    // 闭包外 clone，避免 move 闭包内重复 clone 导致 Copy trait 缺失
    let config_clone = config.clone();
    let transport_clone = Arc::clone(&transport);

    Arc::new(move |dest: &Destination| {
        // clone dest 以获得 'static 所有权，满足 PinFuture 要求
        let dest = dest.clone();
        let config = config_clone.clone();
        let transport = Arc::clone(&transport_clone);
        let client_manager = Arc::clone(&client_manager);

        Box::pin(async move {
            // lazy init ClientManager（首次 dial 时构造）
            let manager = client_manager
                .get_or_init(|| async {
                    ClientManager::new(transport)
                })
                .await;

            // resolve server address from config
            let server_addr_str = &config.server_addr;
            let server_name = &config.server_name;
            let udp_addr: SocketAddr = server_addr_str
                .parse()
                .map_err(|e| format!("hysteria server addr parse: {e}"))?;
            let dial_dest = DialDestination {
                udp_addr,
                host: server_name.clone(),
            };

            let proto_config = Arc::new(ProtoConfig {
                auth: config.auth.clone(),
                udp_idle_timeout: config.udp_idle_timeout_secs as i64,
                ..ProtoConfig::default()
            });
            let quic_params = Arc::new(xray_proto::xray::transport::internet::QuicParams::default());

            let client = manager.get_or_create(dial_dest, proto_config, quic_params);

            // 仅 TCP（hysteria TCP 中继）
            if dest.network() != Network::TCP {
                return Err("hysteria outbound only supports TCP relay in dial_fn".to_string());
            }

            let stream = client
                .tcp()
                .await
                .map_err(|e| format!("hysteria tcp dial: {e}"))?;

            Ok(Box::new(HysteriaConnection::from_stream(stream)) as Box<dyn Connection>)
        })
    })
}
