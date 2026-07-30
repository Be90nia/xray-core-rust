//! SplitHTTP 客户端连接（reader/writer + addr 元数据）。
//!
//! 翻译自 Go `transport/internet/splithttp/connection.go` 的 `splitConn`。
//!
//! # 设计
//!
//! [`SplitConn`] 把独立的 reader（下载流）+ writer（上传管道写端）+ 地址元数据
//! 组合为单一 `AsyncRead + AsyncWrite` 类型，供上层 proxy handler 透明使用。
//!
//! - 切片 A：reader = `BodyDataStream`，writer = `tokio::io::DuplexStream` 写端
//! - 切片 D：stream-up/stream-one 改为 streaming body（`StreamBody`）
//!
//! # Sync 兼容
//!
//! `PacketUpConn = SplitConn<Box<dyn AsyncRead + Send + Unpin>, DuplexStream>` 的
//! reader 是 `!Sync`，无法直接 impl [`Connection`]（要求 `Send + Sync + Unpin`）。
//! 解决方案：[`MutexReader`] 包装 reader 使其 `Sync`，通过 [`SplitConn::into_sync_reader`]
//! 转换后满足 `Connection` bound。

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Mutex;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};

/// SplitHTTP 客户端连接（reader/writer + addr 元数据）。
///
/// 对应 Go `splitConn struct { writer, reader, remoteAddr, localAddr, onClose }`。
/// 上层 proxy handler 把它当普通 `AsyncRead + AsyncWrite` 连接使用。
pub struct SplitConn<R, W> {
    /// 下载流读端（来自 [`crate::client::DefaultDialerClient::open_stream`]
    /// 返回的 `BodyDataStream`）。
    pub reader: R,
    /// 上传管道写端（packet-up mode 由 [`crate::dialer`] 用 `tokio::io::duplex`
    /// 创建 + 后台 `post_packet` 任务消费）。
    pub writer: W,
    /// 远端地址（来自 [`crate::client::HttpInfo`]::`remote_addr`）。
    pub remote_addr: SocketAddr,
    /// 本地地址（来自 [`crate::client::HttpInfo`]::`local_addr`）。
    pub local_addr: SocketAddr,
    /// 关闭回调（packet-up mode 用于 `xmuxClient.OpenUsage -= 1` 等清理）。
    /// 包在 `Mutex` 内允许 `Drop` 时 take 调用。
    on_close: Mutex<Option<Box<dyn FnOnce() + Send + Sync>>>,
}

impl<R, W> SplitConn<R, W> {
    /// 构造新 `SplitConn`。
    #[must_use]
    pub fn new(reader: R, writer: W, remote: SocketAddr, local: SocketAddr) -> Self {
        Self {
            reader,
            writer,
            remote_addr: remote,
            local_addr: local,
            on_close: Mutex::new(None),
        }
    }

    /// 设置关闭回调（ [`Drop`] 时调用一次）。对应 Go `splitConn.onClose` 字段。
    pub fn set_on_close<F: FnOnce() + Send + Sync + 'static>(&self, f: F) {
        let mut guard = self.on_close.lock().expect("on_close mutex poisoned");
        *guard = Some(Box::new(f));
    }

    /// 显式触发 on_close（用于手动 drop 之外的清理路径）。
    pub fn fire_on_close(&self) {
        if let Some(f) = self.on_close.lock().expect("on_close mutex poisoned").take() {
            f();
        }
    }

    /// 把 reader 包装在 [`MutexReader`] 中，使 `SplitConn` 满足 `Sync` bound。
    ///
    /// 当 `R: Send`（但不是 `Sync`）时，`MutexReader<R>` 是 `Send + Sync`，
    /// 因此 `SplitConn<MutexReader<R>, W>` 满足
    /// [`Connection`](xray_transport::connection::Connection) 的 `Sync` 要求。
    ///
    /// 典型用法：`PacketUpConn`（`R = Box<dyn AsyncRead + Send + Unpin>`）→
    /// `SplitConn<MutexReader<Box<dyn AsyncRead + Send + Unpin>>, DuplexStream>`。
    #[must_use]
    pub fn into_sync_reader(self) -> SplitConn<MutexReader<R>, W>
    where
        R: Send,
    {
        // Must prevent Drop from firing on `self` since we're moving fields out.
        let this = std::mem::ManuallyDrop::new(self);
        // SAFETY: we move every field out and reconstruct on_close before any panic path.
        // ManuallyDrop ensures the old SplitConn's Drop won't fire.
        let on_close = this.on_close.lock().expect("on_close mutex poisoned").take();
        SplitConn {
            reader: MutexReader::new(unsafe { std::ptr::read(&this.reader) }),
            writer: unsafe { std::ptr::read(&this.writer) },
            remote_addr: this.remote_addr,
            local_addr: this.local_addr,
            on_close: Mutex::new(on_close),
        }
    }
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> AsyncRead for SplitConn<R, W> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> AsyncWrite for SplitConn<R, W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.writer).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

impl<R, W> Drop for SplitConn<R, W> {
    fn drop(&mut self) {
        if let Some(f) = self.on_close.lock().expect("on_close mutex poisoned").take() {
            f();
        }
    }
}

// ===== MutexReader: Sync wrapper for !Sync readers =====

/// Wrapper that makes any `AsyncRead + Send` also `Sync` via `Mutex`.
///
/// Used to make [`SplitConn`]`<R, W>` satisfy [`Connection`](xray_transport::connection::Connection)'s
/// `Sync` bound when `R` is `Box<dyn AsyncRead + Send + Unpin>` (which is `!Sync`).
///
/// `Mutex<T: Send>` is `Send + Sync`, so `MutexReader<R: Send>` is `Send + Sync`.
/// `Mutex<T: Unpin>` is `Unpin`, so `MutexReader<R: Unpin>` is `Unpin`.
pub struct MutexReader<R> {
    inner: Mutex<R>,
}

impl<R> MutexReader<R> {
    /// Wrap a reader in `Mutex` to add `Sync`.
    #[must_use]
    pub fn new(reader: R) -> Self {
        Self { inner: Mutex::new(reader) }
    }
}

impl<R: AsyncRead + Unpin + Send> AsyncRead for MutexReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // MutexReader<R: Unpin> is Unpin (Mutex<R> is Unpin), so get_mut is safe.
        let this = self.get_mut();
        let mut guard = this.inner.lock().expect("MutexReader poisoned");
        Pin::new(&mut *guard).poll_read(cx, buf)
    }
}

// ===== Connection impl for Sync-compatible SplitConn =====

impl<R: AsyncRead + Send + Sync + Unpin, W: AsyncWrite + Send + Sync + Unpin> xray_transport::connection::Connection
    for SplitConn<R, W>
{
    fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(Some(self.remote_addr))
    }
    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(Some(self.local_addr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    #[tokio::test]
    async fn split_conn_read_write_through() {
        let (client, mut server) = duplex(1024);
        let (read_half, write_half) = tokio::io::split(client);
        server.write_all(b"download").await.unwrap();

        let remote: SocketAddr = "1.2.3.4:80".parse().unwrap();
        let local: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let mut conn = SplitConn::new(read_half, write_half, remote, local);

        let mut buf = [0u8; 8];
        conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf, b"download");

        conn.write_all(b"upload").await.unwrap();
        let mut rbuf = [0u8; 6];
        server.read_exact(&mut rbuf).await.unwrap();
        assert_eq!(&rbuf, b"upload");
    }

    #[tokio::test]
    async fn on_close_fires_on_drop() {
        let counter = Arc::new(AtomicUsize::new(0));
        let c2 = counter.clone();
        let (client, _server) = duplex(64);
        let (r, w) = tokio::io::split(client);
        let conn = SplitConn::new(
            r,
            w,
            "1.2.3.4:80".parse().unwrap(),
            "127.0.0.1:1234".parse().unwrap(),
        );
        conn.set_on_close(move || {
            c2.fetch_add(1, Ordering::Relaxed);
        });
        drop(conn);
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn fire_on_close_idempotent() {
        let counter = Arc::new(AtomicUsize::new(0));
        let c2 = counter.clone();
        let (client, _server) = duplex(64);
        let (r, w) = tokio::io::split(client);
        let conn = SplitConn::new(
            r,
            w,
            "1.2.3.4:80".parse().unwrap(),
            "127.0.0.1:1234".parse().unwrap(),
        );
        conn.set_on_close(move || {
            c2.fetch_add(1, Ordering::Relaxed);
        });
        conn.fire_on_close();
        conn.fire_on_close();
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn into_sync_reader_satisfies_connection() {
        let (client, mut server) = duplex(1024);
        let (read_half, write_half) = tokio::io::split(client);
        server.write_all(b"hello").await.unwrap();

        let remote: SocketAddr = "1.2.3.4:80".parse().unwrap();
        let local: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let conn = SplitConn::new(read_half, write_half, remote, local);
        let sync_conn = conn.into_sync_reader();

        // 验证 into_sync_reader 后满足 Connection trait
        let conn: Box<dyn xray_transport::connection::Connection> = Box::new(sync_conn);
        assert_eq!(conn.remote_addr().unwrap().unwrap(), remote);
        assert_eq!(conn.local_addr().unwrap().unwrap(), local);

        // 验证 AsyncRead 可用
        let mut conn = conn;
        let mut buf = [0u8; 5];
        conn.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
    }

    #[tokio::test]
    async fn into_sync_reader_with_boxed_dyn_reader() {
        // 模拟 PacketUpConn 的实际类型：Box<dyn AsyncRead + Send + Unpin>
        let (client, mut server) = duplex(1024);
        let (read_half, write_half) = tokio::io::split(client);
        server.write_all(b"world").await.unwrap();

        let remote: SocketAddr = "5.6.7.8:443".parse().unwrap();
        let local: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let boxed_reader: Box<dyn AsyncRead + Send + Unpin> = Box::new(read_half);
        let conn = SplitConn::new(boxed_reader, write_half, remote, local);
        let sync_conn = conn.into_sync_reader();

        // 验证 Sync + Connection
        let conn: Box<dyn xray_transport::connection::Connection> = Box::new(sync_conn);
        assert_eq!(conn.remote_addr().unwrap().unwrap(), remote);

        let mut conn = conn;
        let mut buf = [0u8; 5];
        conn.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"world");
    }

    #[tokio::test]
    async fn into_sync_reader_preserves_on_close() {
        let counter = Arc::new(AtomicUsize::new(0));
        let c2 = counter.clone();
        let (client, _server) = duplex(64);
        let (read_half, write_half) = tokio::io::split(client);

        let conn = SplitConn::new(
            read_half,
            write_half,
            "1.2.3.4:80".parse().unwrap(),
            "127.0.0.1:1234".parse().unwrap(),
        );
        conn.set_on_close(move || {
            c2.fetch_add(1, Ordering::Relaxed);
        });
        let sync_conn = conn.into_sync_reader();
        drop(sync_conn);
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }
}
