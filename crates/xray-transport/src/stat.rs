//! 传输统计：连接级字节计数包装。
//!
//! 对应 Go `transport/internet/stat/connection.go::CounterConnection`。
//!
//! Go 原版嵌入 `stat.Counter` 接口（来自 features/stats），依赖 Phase 4+ 未实现。
//! Rust 版本 ponytail 化：直接用 `AtomicU64` 内联计数，待 `xray-features-stats`
//! crate 就绪后再考虑是否抽象为 trait。

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::connection::Connection;

/// 连接统计包装器，记录读写字节总数。对应 Go `CounterConnection`。
///
/// 泛型 `C: Connection` 允许包装任何实现 `Connection` 的具体类型
/// （如 `TcpConnection`）。Delegating 包装模式，零运行时开销。
pub struct CounterConnection<C> {
    inner: C,
    read_bytes: AtomicU64,
    written_bytes: AtomicU64,
}

impl<C: Connection> CounterConnection<C> {
    /// 包装一个连接，计数初始化为 0。
    pub fn new(inner: C) -> Self {
        Self {
            inner,
            read_bytes: AtomicU64::new(0),
            written_bytes: AtomicU64::new(0),
        }
    }

    /// 取回内部连接。
    pub fn into_inner(self) -> C {
        self.inner
    }

    /// 迄今读取的字节总数。
    pub fn read_bytes(&self) -> u64 {
        self.read_bytes.load(Ordering::Relaxed)
    }

    /// 迄今写入的字节总数。
    pub fn written_bytes(&self) -> u64 {
        self.written_bytes.load(Ordering::Relaxed)
    }
}

impl<C: Connection> AsyncRead for CounterConnection<C> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // CounterConnection<C>: Unpin（因为 C: Connection: Unpin 且 AtomicU64: Unpin），
        // 可安全使用 Pin::get_mut + Pin::new 而非 unsafe unchecked 投影。
        let this = self.get_mut();
        let filled_before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let delta = buf.filled().len() - filled_before;
                if delta > 0 {
                    this.read_bytes.fetch_add(delta as u64, Ordering::Relaxed);
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<C: Connection> AsyncWrite for CounterConnection<C> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                if n > 0 {
                    this.written_bytes.fetch_add(n as u64, Ordering::Relaxed);
                }
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

impl<C: Connection> Connection for CounterConnection<C> {
    fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.inner.remote_addr()
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.inner.local_addr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::TcpConnection;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    #[tokio::test]
    async fn read_write_counters_increment() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut conn = CounterConnection::new(TcpConnection::new(stream));
            // 读取 5 字节后回写 3 字节
            let mut buf = [0u8; 5];
            conn.read_exact(&mut buf).await.unwrap();
            conn.write_all(b"xyz").await.unwrap();
            assert_eq!(conn.read_bytes(), 5);
            assert_eq!(conn.written_bytes(), 3);
        });

        let client = TcpStream::connect(addr).await.unwrap();
        let mut client = CounterConnection::new(TcpConnection::new(client));
        client.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 3];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(client.written_bytes(), 5);
        assert_eq!(client.read_bytes(), 3);

        server.await.unwrap();
    }

    #[tokio::test]
    async fn into_inner_recovers_inner_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let conn = CounterConnection::new(TcpConnection::new(stream));
            let _inner: TcpConnection = conn.into_inner();
        });

        let _client = TcpStream::connect(addr).await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn addresses_forwarded_to_inner() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            let conn = CounterConnection::new(TcpConnection::new(stream));
            assert_eq!(conn.remote_addr().unwrap(), Some(peer));
            assert_eq!(conn.local_addr().unwrap(), Some(addr));
        });

        let _client = TcpStream::connect(addr).await.unwrap();
        server.await.unwrap();
    }
}
