//! QUIC transport: quinn-based bi-stream tunnel.
//!
//! 对应 Go `transport/internet/quic/dialer.go` + `transport/internet/quic/hub.go`。
//!
//! ## 拨号流程
//!
//! 1. `xray_tls::client_config::build_client_config` 构建客户端 rustls config
//! 2. `quinn::crypto::rustls::QuicClientConfig::try_from` 转为 QUIC 客户端配置
//! 3. `quinn::Endpoint::client("0.0.0.0:0")` 绑定临时 UDP socket
//! 4. `endpoint.connect_with(cfg, socket_addr, server_name)` 拨号
//! 5. `connection.open_bi()` 打开双向 stream
//! 6. `tokio::io::duplex(64*1024)` 桥接 (SendStream, RecvStream) ↔ DuplexConn
//!
//! ## 监听流程
//!
//! 1. `xray_tls::server_config::build_server_config` 构建服务端 rustls config
//! 2. `quinn::Endpoint::server(server_config, addr)` 绑定 UDP socket
//! 3. spawn accept loop：每个 QUIC 连接 → 内层 accept_bi loop → handler
//!
//! ## DNS
//!
//! quinn 需要 `SocketAddr`（不做 DNS）；若 dest 是域名，用 `tokio::net::lookup_host` 解析。

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use xray_common::net::destination::Destination;
use xray_transport::connection::Connection;
use xray_transport::dialer::StreamSettings;
use xray_transport::listener_registry::{ConnHandler, TransportListener};

/// 主动拨号 QUIC 连接。对应 Go `quic::Dial`。
///
/// `settings.security` 必须为 `"tls"`（QUIC 强制 TLS）；否则返回 `InvalidInput`。
pub async fn dial(dest: &Destination, settings: &StreamSettings) -> io::Result<Box<dyn Connection>> {
    // 1. TLS client config（QUIC 强制 TLS，无 None 兜底）。
    let sni = dest.address().to_string();
    let tls_cfg = xray_tls::client_config::build_client_config(
        &settings.security,
        settings.security_json.as_ref(),
        &sni,
    )?
    .ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "QUIC requires security=tls (got none/unsupported)",
        )
    })?;

    // 2. DNS 解析（quinn 需 SocketAddr，不做域名解析）。
    let addr_str = format!("{}:{}", dest.address(), dest.port().value());
    let socket_addr = tokio::net::lookup_host(&addr_str)
        .await?
        .next()
        .ok_or_else(|| io::Error::other(format!("DNS resolution returned no addr for {addr_str}")))?;

    // 3. QUIC 特有配置（congestion 等）。
    let qc = crate::config::QuicConfig::from_json(settings.transport_json.as_ref())?;
    // 4. rustls ClientConfig → quinn ClientConfig（+ congestion control TransportConfig）。
    let quic_client = quinn::crypto::rustls::QuicClientConfig::try_from((*tls_cfg).clone())
        .map_err(|e| io::Error::other(format!("rustls→quic client: {e}")))?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client));
    client_config.transport_config(Arc::new(qc.build_transport_config()));

    // 4. Endpoint + connect。
    let endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())
        .map_err(|e| io::Error::other(format!("quinn bind: {e}")))?;
    let conn = endpoint
        .connect_with(client_config, socket_addr, &sni)
        .map_err(|e| io::Error::other(format!("quinn connect: {e}")))?
        .await
        .map_err(|e| io::Error::other(format!("quinn handshake: {e}")))?;

    let local = endpoint.local_addr().ok();
    let remote = conn.remote_address();
    // endpoint 必须保持存活——否则连接立即关闭。放进桥接任务里持有。
    let (send, recv) = conn.open_bi().await.map_err(io_err)?;
    Ok(Box::new(QuicConn::new(send, recv, local, Some(remote), endpoint)))
}

/// 监听 QUIC 入站连接。对应 Go `quic::Listen`。
///
/// accept loop：每个 QUIC 连接 → 内层 `accept_bi` loop → 每个新 bi-stream 调用 `handler`。
/// 这与 Go xray-core `hub.go` 一致：一个 QUIC 连接可承载多个 bi-stream。
pub async fn listen(
    addr: SocketAddr,
    settings: &StreamSettings,
    handler: ConnHandler,
) -> io::Result<Box<dyn TransportListener>> {
    let tls_cfg = xray_tls::server_config::build_server_config(
        &settings.security,
        settings.security_json.as_ref(),
    )?
    .ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "QUIC server requires security=tls (got none/unsupported)",
        )
    })?;

    // QUIC 特有配置（congestion 等）。
    let qc = crate::config::QuicConfig::from_json(settings.transport_json.as_ref())?;
    let quic_server = quinn::crypto::rustls::QuicServerConfig::try_from((*tls_cfg).clone())
        .map_err(|e| io::Error::other(format!("rustls→quic server: {e}")))?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server));
    server_config.transport_config(Arc::new(qc.build_transport_config()));

    let endpoint = quinn::Endpoint::server(server_config, addr)
        .map_err(|e| io::Error::other(format!("quinn bind: {e}")))?;
    let local = endpoint.local_addr()?;

    tokio::spawn(async move {
        loop {
            let incoming = match endpoint.accept().await {
                Some(c) => c,
                None => break, // endpoint closed
            };
            let h = handler.clone();
            tokio::spawn(async move {
                let conn = match incoming.await {
                    Ok(c) => c,
                    Err(_) => return,
                };
                let local = conn.local_ip().map(|ip| SocketAddr::new(ip, 0));
                let remote = conn.remote_address();
                // 每个 QUIC 连接上接受任意数量的 bi-stream，每个 stream 都作为独立 Connection 上报。
                while let Ok((send, recv)) = conn.accept_bi().await {
                    let c = QuicConn::new(send, recv, local, Some(remote), ());
                    h(Box::new(c));
                }
            });
        }
    });

    Ok(Box::new(QuicListener { local }))
}

/// quinn (SendStream, RecvStream) + tokio DuplexStream 桥接的 Connection。
///
/// 设计与 [`xray_transport_grpc::transport::DuplexConn`] 一致：
/// - 写方向：DuplexStream → quinn SendStream
/// - 读方向：quinn RecvStream → DuplexStream
/// - `extra` 持有 endpoint（dial 路径）或 `()`（listen 路径，endpoint 在外层 task 持有）
struct QuicConn<E> {
    inner: tokio::io::DuplexStream,
    _extra: E,
    local: Option<SocketAddr>,
    remote: Option<SocketAddr>,
}

impl<E: Send + Sync + Unpin> QuicConn<E> {
    /// 构造桥接：spawn 双向 copy task 把 quinn (send, recv) ↔ DuplexStream。
    fn new(
        mut send: quinn::SendStream,
        mut recv: quinn::RecvStream,
        local: Option<SocketAddr>,
        remote: Option<SocketAddr>,
        extra: E,
    ) -> Self {
        let (client, server) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let (mut rd, mut wr) = tokio::io::split(server);
            // s: 读 duplex-write 半边 → 写到 quinn send；EOF 时 finish() 半关闭
            let s = async {
                let mut buf = vec![0u8; 32 * 1024];
                loop {
                    let n = rd.read(&mut buf).await?;
                    if n == 0 {
                        let _ = send.finish();
                        break;
                    }
                    send.write_chunk(Bytes::copy_from_slice(&buf[..n]))
                        .await
                        .map_err(io_err)?;
                }
                Ok::<_, io::Error>(())
            };
            // r: 读 quinn recv → 写到 duplex-read 半边
            let r = async {
                let mut buf = vec![0u8; 32 * 1024];
                loop {
                    match recv.read(&mut buf).await {
                        Ok(Some(n)) => wr.write_all(&buf[..n]).await?,
                        Ok(None) => break,
                        Err(e) => return Err(io_err(e)),
                    }
                }
                Ok::<_, io::Error>(())
            };
            let _ = tokio::try_join!(s, r);
        });
        Self {
            inner: client,
            _extra: extra,
            local,
            remote,
        }
    }
}

impl<E: Send + Sync + Unpin> AsyncRead for QuicConn<E> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<E: Send + Sync + Unpin> AsyncWrite for QuicConn<E> {
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

impl<E: Send + Sync + Unpin> Connection for QuicConn<E> {
    fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(self.remote)
    }
    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(self.local)
    }
}

struct QuicListener {
    local: SocketAddr,
}

impl TransportListener for QuicListener {
    fn close(&self) -> io::Result<()> {
        tracing::info!("QUIC listener close addr={}", self.local);
        Ok(())
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }
}

fn io_err<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::other(e.to_string())
}
