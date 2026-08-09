//! SplitHTTP transport: h2 server tunnel.
//!
//! 对应 Go `transport/internet/splithttp/config.go` 里的 h2 监听入口。镜像
//! `xray-transport-grpc::transport` 的 `listen`/`accept_h2` 模式：TCP listener
//! → accept → 可选 TLS → h2 server handshake → accept POST → duplex bridge。

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use h2::server;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio_rustls::TlsAcceptor;
use xray_transport::connection::Connection;
use xray_transport::dialer::StreamSettings;
use xray_transport::listener_registry::{ConnHandler, TransportListener};
use xray_transport::sockopt::SocketOptions;

/// SplitHTTP 监听入口。
///
/// 镜像 [`xray_transport_grpc::transport::listen`]：bind TCP → 可选 TLS →
/// accept loop → `accept_h2` → duplex bridge → handler。
pub async fn listen_splithttp(
    addr: SocketAddr,
    settings: &StreamSettings,
    _sockopt: &SocketOptions,
    handler: ConnHandler,
) -> io::Result<Box<dyn TransportListener>> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;

    let tls_cfg = if !settings.security.is_empty() && settings.security != "none" {
        Some(
                xray_tls::server_config::build_server_config(
                    &settings.security,
                    settings.security_json.as_ref(),
                )?
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "TLS server config None")
                })?,
        )
    } else {
        None
    };

    tokio::spawn(async move {
        loop {
            let (tcp, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => continue,
            };
            tcp.set_nodelay(true).ok();
            let h = handler.clone();
            let tls = tls_cfg.clone();
            tokio::spawn(async move {
                if let Some(tc) = tls {
                    let acc = TlsAcceptor::from(tc);
                    match acc.accept(tcp).await {
                        Ok(c) => accept_h2(c, h).await,
                        Err(_) => {}
                    }
                } else {
                    accept_h2(tcp, h).await;
                }
            });
        }
    });

    Ok(Box::new(SplithttpListener { local }))
}

/// h2 server handshake → accept requests → 对每个 POST 起一个 duplex bridge。
///
/// 与 gRPC `accept_h2` 同构：非 POST 直接 404；POST 取出 `recv_body`，
/// 发送 200 响应（不立刻 end_stream），spawn 任务把 duplex 双向数据桥起来，
/// 最终把 `DuplexConn(client)` 交给 `handler`。
async fn accept_h2<T>(conn: T, handler: ConnHandler)
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let mut h2_srv = match server::handshake(conn).await {
        Ok(s) => s,
        Err(_) => return,
    };
    while let Some(r) = h2_srv.accept().await {
        let (req, mut respond) = match r {
            Ok(v) => v,
            Err(_) => continue,
        };
        if req.method() != "POST" {
            let resp = http::Response::builder().status(404).body(()).unwrap();
            let _ = respond.send_response(resp, true);
            continue;
        }
        let mut recv_body = req.into_body();
        let mut send_resp = match respond
            .send_response(http::Response::builder().status(200).body(()).unwrap(), false)
        {
            Ok(s) => s,
            Err(_) => continue,
        };
        let (client, server) = tokio::io::duplex(64 * 1024);
        let h2 = handler.clone();
        tokio::spawn(async move {
            let (mut rd, mut wr) = tokio::io::split(server);
            let s = async {
                let mut buf = vec![0u8; 32 * 1024];
                loop {
                    let n = rd.read(&mut buf).await?;
                    if n == 0 {
                        let _ = send_resp.send_data(Bytes::new(), true);
                        break;
                    }
                    send_resp
                        .send_data(Bytes::copy_from_slice(&buf[..n]), false)
                        .map_err(io_err)?;
                }
                Ok::<_, io::Error>(())
            };
            let r = async {
                while let Some(d) = recv_body.data().await {
                    let d = d.map_err(io_err)?;
                    wr.write_all(&d).await?;
                    let _ = recv_body.flow_control().release_capacity(d.len());
                }
                Ok::<_, io::Error>(())
            };
            let _ = tokio::try_join!(s, r);
        });
        h2(Box::new(DuplexConn(client)));
    }
}

fn io_err<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e.to_string())
}

struct DuplexConn(tokio::io::DuplexStream);

impl AsyncRead for DuplexConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for DuplexConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl Connection for DuplexConn {
    fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(None)
    }
    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(None)
    }
}

struct SplithttpListener {
    local: SocketAddr,
}

impl TransportListener for SplithttpListener {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }
    fn close(&self) -> io::Result<()> {
        tracing::info!("splithttp listener close addr={}", self.local);
        Ok(())
    }
}
