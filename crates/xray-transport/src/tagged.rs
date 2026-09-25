//! # Tagged connection
//!
//! 给 Connection 附加 tag 字段的包装。对应 Go `transport/internet/tagged.go`。
//!
//! Go `transport/internet/tagged/taggedimpl` 的 `DialTaggedOutbound`（forced outbound
//! tag + SkipDNSResolve 经 dispatcher 定向拨号，bd kz1）Rust 等价物在
//! `xray_app_dispatcher::default::DefaultDispatcher::dispatch_tagged`——transport 层
//! 不依赖 dispatcher，故不在此实现。

use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::connection::Connection;

pub struct TaggedConnection<C> {
    pub tag: String,
    pub inner: C,
}

impl<C> TaggedConnection<C> {
    #[must_use]
    pub fn new(tag: impl Into<String>, inner: C) -> Self {
        Self { tag: tag.into(), inner }
    }
}

impl<C: AsyncRead + Unpin> AsyncRead for TaggedConnection<C> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<C: AsyncWrite + Unpin> AsyncWrite for TaggedConnection<C> {
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

impl<C: Connection> Connection for TaggedConnection<C> {
    fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.inner.remote_addr()
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.inner.local_addr()
    }
}
