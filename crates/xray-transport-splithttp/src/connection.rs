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

use std::net::SocketAddr;
use std::sync::Mutex;
use std::pin::Pin;
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
}
