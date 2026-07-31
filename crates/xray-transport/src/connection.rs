//! 网络连接抽象 + TcpConnection 参考实现。
//!
//! 对应 Go 版本 `transport/internet/stat/connection.go` 的 `Connection` 接口
//! （即 Go 的 `net.Conn`）。在 Rust 端基于 tokio `AsyncRead + AsyncWrite`，
//! 额外暴露 `remote_addr` / `local_addr` 供代理层记录路由信息。
//!
//! # Box<dyn Connection>
//!
//! `Connection: AsyncRead + AsyncWrite + Unpin + Send + Sync`——supertrait 约束。
//! tokio 提供 `impl<T: AsyncRead + ?Sized> AsyncRead for Box<T>` blanket impl，
//! 因此 `Box<dyn Connection>` 无需手写 forward 即自动 `AsyncRead + AsyncWrite`。
//! 调用 `Box<dyn Connection>.poll_read` 时，通过 dyn 内嵌的 AsyncRead vtable 跳转
//! 到具体实现的 poll_read。Connection 的 `remote_addr`/`local_addr` 也由 Box 的
//! Deref 自动可用，无需 forward。
//!
//! # 当前范围
//!
//! - `Connection` trait
//! - `TcpConnection`（包装 `tokio::net::TcpStream`，作为参考实现 + 测试用）
//!
//! 不在本会话范围：TLS / WebSocket / KCP 等 Connection 实现，留待各传输协议 crate。

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

/// 网络连接抽象。
///
/// 对应 Go 的 `stat.Connection`（即 `net.Conn`）。
pub trait Connection: AsyncRead + AsyncWrite + Send + Sync + Unpin {
    /// 对端地址（peer addr）。底层未提供时返回 `Ok(None)`。
    fn remote_addr(&self) -> io::Result<Option<SocketAddr>>;

    /// 本端地址（local addr）。底层未提供时返回 `Ok(None)`。
    fn local_addr(&self) -> io::Result<Option<SocketAddr>>;
}


/// TCP 连接。
///
/// 包装 `tokio::net::TcpStream`，提供 `Connection` 实现。作为参考实现存在，
/// 让 trait 可被真实测试；下游 TLS / WebSocket 等传输层 crate 可以参考此模式。
#[derive(Debug)]
pub struct TcpConnection {
    inner: TcpStream,
}

impl TcpConnection {
    /// 用已建立的 `TcpStream` 构造连接。
    #[must_use]
    pub fn new(stream: TcpStream) -> Self {
        Self { inner: stream }
    }

    /// 拆出底层 `TcpStream`。
    #[must_use]
    pub fn into_inner(self) -> TcpStream {
        self.inner
    }
}

impl AsyncRead for TcpConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for TcpConnection {
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

impl Connection for TcpConnection {
    fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(Some(self.inner.peer_addr()?))
    }
    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(Some(self.inner.local_addr()?))
    }
}

impl AsyncRead for DuplexConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for DuplexConnection {
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

impl Connection for DuplexConnection {
    fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(None)
    }
    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(None)
    }
}

/// Pipe/Duplex 连接。
///
/// 包装 `tokio::io::DuplexStream`，用于代理链（DialerProxy）场景：
/// 创建 pipe pair，一端交给 chained handler dispatch，另一端返回给调用者。
pub struct DuplexConnection {
    inner: tokio::io::DuplexStream,
}

impl DuplexConnection {
    /// 从 DuplexStream 创建连接。
    pub fn new(stream: tokio::io::DuplexStream) -> Self {
        Self { inner: stream }
    }
}

impl Connection for Box<dyn Connection> {
    fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
        (**self).remote_addr()
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        (**self).local_addr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn tcp_connection_addrs_populated() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            TcpConnection::new(stream)
        });

        let client_stream = tokio::net::TcpStream::connect(server_addr).await.unwrap();
        let client_local = client_stream.local_addr().unwrap();
        let client = TcpConnection::new(client_stream);

        let server = server.await.unwrap();
        let server_remote = server.remote_addr().unwrap();
        let server_local = server.local_addr().unwrap();
        let client_remote = client.remote_addr().unwrap();

        // 互为对端。
        assert_eq!(server_remote.unwrap(), client_local);
        assert_eq!(client_remote.unwrap(), server_local.unwrap());
    }

    #[tokio::test]
    async fn box_dyn_connection_used_as_async_read_write() {
        // 验证 Box<dyn Connection> 可被 tokio::io::copy 使用。
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let conn: Box<dyn Connection> = Box::new(TcpConnection::new(stream));
            // 这里能编译就证明 Box<dyn Connection>: AsyncRead + AsyncWrite。
            let mut buf = [0u8; 5];
            let mut c = conn;
            c.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"hello");
        });

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut client = TcpConnection::new(stream);
        client.write_all(b"hello").await.unwrap();

        server.await.unwrap();
    }

    #[tokio::test]
    async fn tcp_connection_into_inner_recovers_stream() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (_s, _) = listener.accept().await.unwrap();
        });
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let conn = TcpConnection::new(stream);
        let _ = conn.into_inner();
        server.await.unwrap();
    }
}
