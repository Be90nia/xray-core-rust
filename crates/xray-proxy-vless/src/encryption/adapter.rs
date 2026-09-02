//! VLESS ENC 输出连接适配器。
//!
//! 把 `Box<dyn EncryptionConn>` 包成 `Box<dyn xray_transport::connection::Connection>`，
//! 使生产路径 make_dial_fn 套上 ENC 层后仍能返回 transport `Connection`。
//!
//! 对应 Go `encryption.Handshake` 返回 `*CommonConn`（即 `net.Conn`），Go 端直接用；
//! Rust 端因 transport 层用 trait object，需要 adapter。
//!
//! 地址信息：底层可能不知道（ws/grpc/httpupgrade 包装后丢原始 SocketAddr），
//! 返回 Ok(None)（与 VisionConn 同样保守，见 encryption/vision_conn.rs:249）。
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use xray_transport::connection::Connection;

use crate::encryption::EncryptionConn;

/// 把 `Box<dyn EncryptionConn>` 适配为 `xray_transport::connection::Connection`。
///
/// 注意：tokio 提供 `impl<T: AsyncRead + ?Sized> AsyncRead for Box<T>` 的 blanket impl，
/// 因此 `&mut Box<dyn EncryptionConn>` 本身已是 `AsyncRead + AsyncWrite`。
/// 这里再加 Connection 的 addr/close_* 方法即可。
pub struct EncConnectionAdapter {
    inner: Box<dyn EncryptionConn>,
}

impl EncConnectionAdapter {
    pub fn new(inner: Box<dyn EncryptionConn>) -> Self {
        Self { inner }
    }
}

impl AsyncRead for EncConnectionAdapter {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // EncryptionConn: Unpin → &mut self.inner is Unpin → Pin::new is safe.
        Pin::new(&mut *self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for EncConnectionAdapter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

impl Connection for EncConnectionAdapter {
    fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(None)
    }
    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(None)
    }
    fn close_read(&mut self) -> io::Result<()> {
        // 加密层没有原生 shutdown 读半边的概念；默认 no-op 与 tls 等高层一致。
        Ok(())
    }
    fn close_write(&mut self) -> io::Result<()> {
        // 同上；上层若需要 shutdown 请调 AsyncWrite::poll_shutdown。
        Ok(())
    }
}
