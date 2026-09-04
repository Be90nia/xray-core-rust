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

    /// 半关闭读方向（SHUT_RD）。告诉内核丢弃后续入站数据。
    /// 默认 no-op（非 TCP 连接或不支持的平台）。
    fn close_read(&mut self) -> io::Result<()> {
        Ok(())
    }

    /// 半关闭写方向（SHUT_WR）。通知对端本地已写完。
    /// 默认 no-op。TCP 连接可通过 [`tokio::io::AsyncWriteExt::shutdown`] 实现等价效果。
    fn close_write(&mut self) -> io::Result<()> {
        Ok(())
    }

    /// 尝试克隆底层裸 TCP socket（Go `UnwrapRawConn` 的等价物）。
    ///
    /// TLS/REALITY 等安全层实现应穿透自身返回内层 TcpStream 的 `try_clone()`
    /// （共享同一 socket，不占用所有权）。裸 TCP 连接返回自身克隆。
    /// 用于 vless vision splice：splice 切换后双方在裸 TCP 上传输端到端
    /// TLS records（TLS 终结点移至 curl↔origin），必须绕过本地安全层读写。
    fn raw_tcp_clone(&self) -> Option<TcpStream> {
        None
    }
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
    fn raw_tcp_clone(&self) -> Option<TcpStream> {
        // tokio::net::TcpStream 没有 try_clone；通过 dup(fd) 复制底层 socket 后
        // 用 TcpStream::from_std 构造独立 AsyncRead/AsyncWrite handle。
        // 两个 handle 共享同一个内核 socket,可独立 poll,关闭其一不影响另一。
        #[cfg(unix)]
        {
            use std::os::unix::io::{AsRawFd, FromRawFd};
            let fd = self.inner.as_raw_fd();
            let new_fd = unsafe { libc::dup(fd) };
            if new_fd < 0 { return None; }
            let std_stream = unsafe { std::net::TcpStream::from_raw_fd(new_fd) };
            // from_std 要求非阻塞模式。tokio 持有的 fd 是非阻塞的；dup 继承同样 flags。
            TcpStream::from_std(std_stream).ok()
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::{AsRawSocket, FromRawSocket};
            // tokio TcpStream 无 try_clone：借 raw SOCKET 构造不接管所有权的
            // std 视图（ManuallyDrop 防 drop 关闭原 handle），std TcpStream::
            // try_clone（内部 DuplicateHandle）复制独立 handle，再转回 tokio
            // （from_std 要求非阻塞，tokio 持有的 socket 已是）。
            // SAFETY: raw handle 由 self.inner 持有且调用期间有效；视图被
            // ManuallyDrop 包裹不会关闭它，克隆出的 handle 独立拥有新句柄。
            let raw = self.inner.as_raw_socket();
            let view = std::mem::ManuallyDrop::new(unsafe { std::net::TcpStream::from_raw_socket(raw) });
            let cloned = match view.try_clone() {
                Ok(s) => s,
                Err(_) => return None,
            };
            TcpStream::from_std(cloned).ok()
        }
        #[cfg(not(any(unix, windows)))]
        {
            None
        }
    }
    fn close_read(&mut self) -> io::Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            // SAFETY: shutdown 对已验证的 fd 设置 SHUT_RD，内核丢弃后续入站数据。
            let ret = unsafe { libc::shutdown(self.inner.as_raw_fd(), libc::SHUT_RD) };
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
    fn close_write(&mut self) -> io::Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            // SAFETY: shutdown 对已验证的 fd 设置 SHUT_WR，通知对端本地已写完。
            let ret = unsafe { libc::shutdown(self.inner.as_raw_fd(), libc::SHUT_WR) };
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
}

/// Unix domain socket 连接。仅 unix 目标编译。
///
/// 包装 `tokio::net::UnixStream`，提供 `Connection` 实现。供 splithttp unix
/// listener 把 accepted UnixStream 经 tcpmask 包装后再下传（Go
/// `splithttp/hub.go:547-549` 的 WrapListener 语义）。
#[cfg(unix)]
#[derive(Debug)]
pub struct UnixConnection {
    inner: tokio::net::UnixStream,
}

#[cfg(unix)]
impl UnixConnection {
    #[must_use]
    pub fn new(stream: tokio::net::UnixStream) -> Self {
        Self { inner: stream }
    }
}

#[cfg(unix)]
impl AsyncRead for UnixConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

#[cfg(unix)]
impl AsyncWrite for UnixConnection {
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

#[cfg(unix)]
impl Connection for UnixConnection {
    fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
        // UnixStream 无标准 SocketAddr；返回 None。
        Ok(None)
    }
    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(None)
    }
    fn close_read(&mut self) -> io::Result<()> {
        use std::os::unix::io::AsRawFd;
        let ret = unsafe { libc::shutdown(self.inner.as_raw_fd(), libc::SHUT_RD) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    fn close_write(&mut self) -> io::Result<()> {
        use std::os::unix::io::AsRawFd;
        let ret = unsafe { libc::shutdown(self.inner.as_raw_fd(), libc::SHUT_WR) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
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

    fn close_read(&mut self) -> io::Result<()> {
        (**self).close_read()
    }

    fn close_write(&mut self) -> io::Result<()> {
        (**self).close_write()
    }

    fn raw_tcp_clone(&self) -> Option<TcpStream> {
        // 穿透 Box 转发到内层具体连接（vision splice 依赖此链路）。
        (**self).raw_tcp_clone()
    }
}

/// 带前缀缓冲的读取器（sniffing 缓存回放）。
///
/// sniffer 读取前 N 字节分析协议后，用 [`PrefixedReader`] 包装原始连接，
/// 让后续协议处理器先读取缓存的字节再读取新数据。
/// 对应 Go dispatcher 的 `buf.MultiBuffer` 前缀回放模式。
pub struct PrefixedReader<R> {
    inner: R,
    prefix: Vec<u8>,
    pos: usize,
}

impl<R> PrefixedReader<R> {
    /// 用前缀缓冲 + 内部读取器构造。
    #[must_use]
    pub fn new(inner: R, prefix: Vec<u8>) -> Self {
        Self { inner, prefix, pos: 0 }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for PrefixedReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // 先消费前缀缓冲。
        if self.pos < self.prefix.len() {
            let n = std::cmp::min(buf.remaining(), self.prefix.len() - self.pos);
            buf.put_slice(&self.prefix[self.pos..self.pos + n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        // 前缀耗尽后透传到内部读取器。
        Pin::new(&mut self.inner).poll_read(cx, buf)
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

    #[tokio::test]
    async fn prefixed_reader_replays_prefix_then_passthrough() {
        use tokio::io::AsyncReadExt;
        // inner reader: 20 bytes (0..20)
        let inner = std::io::Cursor::new((0u8..20).collect::<Vec<_>>());
        // sniffer 缓存了前 5 字节，用 PrefixedReader 包装
        let prefix = vec![100, 101, 102];
        let mut reader = PrefixedReader::new(inner, prefix);
        let mut buf = [0u8; 25];
        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(n, 3); // 只返回 prefix
        assert_eq!(&buf[..3], &[100, 101, 102]);
        // 后续读从 inner 开始
        let n2 = reader.read(&mut buf).await.unwrap();
        assert_eq!(n2, 20); // inner 的 20 字节
        assert_eq!(&buf[..20], &(0u8..20).collect::<Vec<_>>());
    }
}
