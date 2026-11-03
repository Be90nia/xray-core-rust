//! HTTPUpgrade 连接包装——覆盖 `remote_addr`，对应 Go `connection.go`。
//!
//! 切片1 仅声明类型 + 注释说明用途。实际 `Connection` trait impl 需要
//! 包装一个 `Box<dyn xray_transport::Connection>`，留切片2 与真实 IO 接通后实现。
//!
//! 设计：HTTPUpgrade 握手后底层字节流就是 raw TCP/TLS，无需任何额外封装。
//! 仅在地址上需要覆盖（X-Forwarded-For 注入），所以 wrapper 只是简单持有
//! 内层连接 + 一个替代的 `remote_addr`。

use std::net::SocketAddr;

/// 占位 wrapper 类型。切片2 接入 `xray_transport::Connection` impl。
///
/// `inner` 是握手完成后的底层字节流（TCP/TLS），`remote_addr` 是从
/// `X-Forwarded-For` 解析得到的源 IP（端口为 0，与 Go `connection.go` 一致）。
pub struct HttpUpgradeConnection<C> {
    /// 内层连接（TCP / TLS / 其他）。切片2 由调用方注入。
    pub inner: C,
    /// 替换后的对端地址。`Ok(Some(addr))` 时 Connection::remote_addr 返回此值。
    pub remote_addr_override: Option<SocketAddr>,
    /// 101 响应读取时已消费的余留字节（服务端 101 与首包同批到达时由握手保留）。
    pending: Vec<u8>,
}

impl<C: std::fmt::Debug> std::fmt::Debug for HttpUpgradeConnection<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpUpgradeConnection")
            .field("inner", &self.inner)
            .field("remote_addr_override", &self.remote_addr_override)
            .finish()
    }
}

impl<C> HttpUpgradeConnection<C> {
    /// 构造 wrapper。
    #[must_use]
    pub fn new(inner: C, remote_addr: Option<SocketAddr>) -> Self {
        Self { inner, remote_addr_override: remote_addr, pending: Vec::new() }
    }

    /// 构造 wrapper，附带握手阶段已读出的余留字节（先于 inner 数据返回）。
    #[must_use]
    pub fn new_with_pending(inner: C, remote_addr: Option<SocketAddr>, pending: Vec<u8>) -> Self {
        Self { inner, remote_addr_override: remote_addr, pending }
    }

    /// 拆出内层连接。
    #[must_use]
    pub fn into_inner(self) -> C {
        self.inner
    }

    /// 构造 wrapper，指定 remote_addr。
    #[must_use]
    pub fn with_remote_addr(inner: C, remote_addr: SocketAddr) -> Self {
        Self { inner, remote_addr_override: Some(remote_addr), pending: Vec::new() }
    }
}

impl<C: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for HttpUpgradeConnection<C> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if !self.pending.is_empty() {
            let n = self.pending.len().min(buf.remaining());
            buf.put_slice(&self.pending[..n]);
            self.pending.drain(..n);
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<C: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for HttpUpgradeConnection<C> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    /// 转发向量写能力（y1yx 聚合写）：Upgrade 之后的字节流与 inner 是同一条流，
    /// 内层支持 writev 时上层可把多块一次写出（syscall ÷8），字节序不变。
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_write_vectored(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<C: xray_transport::connection::Connection + Unpin> xray_transport::connection::Connection
    for HttpUpgradeConnection<C>
{
    fn remote_addr(&self) -> std::io::Result<Option<SocketAddr>> {
        if let Some(addr) = self.remote_addr_override {
            Ok(Some(addr))
        } else {
            self.inner.remote_addr()
        }
    }

    fn local_addr(&self) -> std::io::Result<Option<SocketAddr>> {
        self.inner.local_addr()
    }

    /// F3：TLS 读批信号透传（rustls 64KB 读批，减少 poll 往返；btls 缺省 0）。
    ///
    /// httpupgrade over TLS 时 inner 是 TLS 流，读批由 TLS 栈决定——包装层不转发
    /// 即白丢 64KB 读批（utls.rs `tls_readbuf_size` 注释记 harness 148→332 MB/s）。
    /// 只影响读缓冲尺寸，不改字节流内容（TLS record 边界由 TLS 栈自己定）。
    fn tls_readbuf_size(&self) -> usize {
        self.inner.tls_readbuf_size()
    }

    // `is_raw_tcp` / `raw_tcp_clone` **不转发**（Go 对齐 + 语义约束）：
    // 1. Go 侧 httpupgrade 连接不是裸 TCP：客户端返回 `*httpupgrade.ConnRF`
    //    （dialer.go:126-130）、服务端返回 `*httpupgrade.connection` （hub.go
    //    newConnection）——两者都不是 `*net.TCPConn`，故 Go 的
    //    `IsRAWTransportWithoutSecurity`（proxy/proxy.go:820-829）判 **false**： Go 的 httpupgrade
    //    同样走 SingleReader（8KB），无 readv 批读、无 splice。 转发会让本仓比 Go 多出 readv 批读腿
    //    + splice 候选 = 行为分叉。
    // 2. splice 准入面：转发 `is_raw_tcp` 会让 Linux splice 路径把 httpupgrade 纳入候选（vision
    //    splice gate 是红线，CLAUDE.md §4）。
    // 3. readv dup 读腿会绕过本 wrapper 的 `pending`（101 响应同批到达时已消费 的余留字节）→
    //    丢首包。
    // 结论：保持缺省 false（包装层天然拒绝），与 Go 逐字节一致。
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4};

    use super::*;

    #[test]
    fn construction_preserves_inner() {
        let inner = vec![1u8, 2, 3];
        let addr: SocketAddr = SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 0).into();
        let conn = HttpUpgradeConnection::new(inner.clone(), Some(addr));
        assert_eq!(conn.remote_addr_override, Some(addr));
        assert_eq!(conn.into_inner(), inner);
    }

    #[test]
    fn none_override_preserved() {
        let conn = HttpUpgradeConnection::new(42u8, None);
        assert!(conn.remote_addr_override.is_none());
    }

    /// 快路径透传（T1）：Upgrade 之后的字节流与 inner 同一条流——
    /// ① 向量写能力（writev 聚合）② TLS 64KB 读批（F3）必须透传；
    /// ③ `is_raw_tcp` 必须**保持 false**（Go 的 httpupgrade 连接不是裸 TCP，
    /// `IsRAWTransportWithoutSecurity` 判 false；转发会让本仓多出 readv 批读腿
    /// + splice 候选 = 与 Go 行为分叉）。
    #[test]
    fn forwards_fast_path_signals_but_not_raw_tcp() {
        use std::{
            io,
            pin::Pin,
            task::{Context, Poll},
        };

        use tokio::io::AsyncWrite as _;
        use xray_transport::connection::Connection as _;

        /// 内层 mock：支持向量写 + 报 64KB 读批 + 是裸 TCP。
        struct Inner {
            written: Vec<u8>,
        }
        impl tokio::io::AsyncRead for Inner {
            fn poll_read(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                _buf: &mut tokio::io::ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }
        impl tokio::io::AsyncWrite for Inner {
            fn poll_write(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                self.written.extend_from_slice(buf);
                Poll::Ready(Ok(buf.len()))
            }

            fn poll_write_vectored(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                bufs: &[io::IoSlice<'_>],
            ) -> Poll<io::Result<usize>> {
                let mut total = 0;
                for b in bufs {
                    self.written.extend_from_slice(b);
                    total += b.len();
                }
                Poll::Ready(Ok(total))
            }

            fn is_write_vectored(&self) -> bool {
                true
            }

            fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }

            fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }
        impl xray_transport::connection::Connection for Inner {
            fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
                Ok(None)
            }

            fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
                Ok(None)
            }

            fn is_raw_tcp(&self) -> bool {
                true
            }

            fn tls_readbuf_size(&self) -> usize {
                64 * 1024
            }
        }

        let conn = HttpUpgradeConnection::new(Inner { written: Vec::new() }, None);
        assert!(conn.is_write_vectored(), "向量写能力必须透传（否则丢 writev 聚合）");
        assert_eq!(conn.tls_readbuf_size(), 64 * 1024, "TLS 读批信号必须透传");
        assert!(!conn.is_raw_tcp(), "httpupgrade 不得声明裸 TCP（Go 语义 + splice 红线）");
        assert!(conn.raw_tcp_clone().is_none(), "不得暴露裸 TCP 克隆（splice 准入面）");
    }
}
