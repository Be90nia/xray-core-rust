//! 网络连接抽象 + TcpConnection 参考实现。
//!
//! 对应 Go 版本 `transport/internet/stat/connection.go` 的 `Connection` 接口
//! （即 Go 的 `net.Conn`）。在 Rust 端基于 tokio `AsyncRead + AsyncWrite`，
//! 额外暴露 `remote_addr` / `local_addr` 供代理层记录路由信息。
//!
//! # `Box<dyn Connection>`
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

use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};

/// 网络连接抽象。
///
/// 对应 Go 的 `stat.Connection`（即 `net.Conn`）。
pub trait Connection: AsyncRead + AsyncWrite + Send + Sync + Unpin {
    /// 对端地址（peer addr）。底层未提供时返回 `Ok(None)`。
    fn remote_addr(&self) -> io::Result<Option<SocketAddr>>;

    /// 本端地址（local addr）。底层未提供时返回 `Ok(None)`。
    fn local_addr(&self) -> io::Result<Option<SocketAddr>>;

    /// 默认返回 `Unsupported`：未实现半关闭的平台/连接类型不假装成功,
    /// 调用方需检查错误。Windows 上 `TcpConnection` 用 `shutdown(SHUT_RD/SHUT_WR)`
    /// 实现（见下）；Unix 同。
    fn close_read(&mut self) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "close_read not supported on this connection",
        ))
    }

    /// 默认返回 `Unsupported`（见 [`Connection::close_read`] 注释）。
    fn close_write(&mut self) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "close_write not supported on this connection",
        ))
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

    /// 是否为**无包装层的裸 TCP 连接**（Go `IsRAWTransportWithoutSecurity` 等价物，
    /// proxy.go:802-809：proxyproto.Conn / net.TCPConn / UnixConnWrapper 三型）。
    ///
    /// splice(2) 零拷贝桥接的准入信号。与 [`Connection::raw_tcp_clone`] 的区别：
    /// 后者为 vision splice 穿透 TLS 等安全层克隆内层 socket（返回 `Some` 不能
    /// 证明连接本身是裸 TCP）；本方法默认 `false`，仅具体裸 TCP 类型覆写为
    /// `true`——TLS/REALITY/fragment 等包装层不覆写即天然拒绝。
    fn is_raw_tcp(&self) -> bool {
        false
    }

    /// 下行多缓冲聚合读的 poll 钩子（bd 2o9l，对应 Go ReadVReader 的
    /// `syscall.RawConn` 通道）。TCP 实现覆写为真 readv——一次系统调用
    /// （Unix `readv(2)` / Windows `WSARecv`）把数据分散填入多个 iovec；
    /// 默认实现顺序读入首个非空缓冲，行为等价 Go `NewReader` 无
    /// `syscall.Conn` 时退回 `SingleReader`（common/buf/io.go:124-145）。
    ///
    /// # 参数
    ///
    /// - `bufs`：各缓冲的可写区（TCP 实现经 `xray_buf::readv` 的零分配 IovecBatch
    ///   栈数组路径构建）。
    fn poll_read_multi(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &mut [io::IoSliceMut<'_>],
    ) -> Poll<io::Result<usize>> {
        let dst: &mut [u8] = match bufs.iter_mut().find(|b| !b.is_empty()) {
            Some(b) => b,
            None => return Poll::Ready(Ok(0)),
        };
        if dst.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut rb = ReadBuf::new(dst);
        std::task::ready!(Pin::new(self).poll_read(cx, &mut rb))?;
        Poll::Ready(Ok(rb.filled().len()))
    }
}

/// 复制 `tokio::net::TcpStream` 底层 socket 为独立 handle（vision splice 用）。
///
/// tokio TcpStream 无 `try_clone`：unix 走 `dup(fd)`，windows 走
/// `DuplicateHandle`（经 std `try_clone`）。两个 handle 共享同一内核 socket，
/// 可独立 poll，关闭其一不影响另一。失败返回 `None`。
pub fn dup_tcp_stream(stream: &TcpStream) -> Option<TcpStream> {
    #[cfg(unix)]
    {
        use std::os::unix::io::{AsRawFd, FromRawFd};
        let fd = stream.as_raw_fd();
        let new_fd = unsafe { libc::dup(fd) };
        if new_fd < 0 {
            return None;
        }
        let std_stream = unsafe { std::net::TcpStream::from_raw_fd(new_fd) };
        // from_std 要求非阻塞模式。tokio 持有的 fd 是非阻塞的；dup 继承同样 flags。
        TcpStream::from_std(std_stream).ok()
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::{AsRawSocket, FromRawSocket};
        // 借 raw SOCKET 构造不接管所有权的 std 视图（ManuallyDrop 防 drop
        // 关闭原 handle），try_clone 复制独立 handle，再转回 tokio。
        // SAFETY: raw handle 由 stream 持有且调用期间有效；视图被
        // ManuallyDrop 包裹不会关闭它，克隆出的 handle 独立拥有新句柄。
        let raw = stream.as_raw_socket();
        let view =
            std::mem::ManuallyDrop::new(unsafe { std::net::TcpStream::from_raw_socket(raw) });
        let cloned = view.try_clone().ok()?;
        TcpStream::from_std(cloned).ok()
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = stream;
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

    /// Windows 半关闭：借 raw SOCKET 的 std 视图调 `shutdown(SD_RECEIVE/SD_SEND)`。
    ///
    /// std 将 `Shutdown::Read/Write` 映射为 Winsock `SD_RECEIVE/SD_SEND`——
    /// Go `net.TCPConn.CloseRead/CloseWrite` 在 Windows 走的就是同款 syscall。
    /// tokio 句柄只暴露 `Shutdown::Both` 方向语义，故不经 tokio（bd 09c4）。
    #[cfg(windows)]
    fn winsock_shutdown(&self, how: std::net::Shutdown) -> io::Result<()> {
        use std::os::windows::io::{AsRawSocket, FromRawSocket};
        let raw = self.inner.as_raw_socket();
        // SAFETY: raw SOCKET 由 self.inner 持有且调用期间有效；ManuallyDrop
        // 包裹的 std 视图不接管所有权，drop 不会关闭原 handle
        // （dup_tcp_stream 同款惯例）。
        let view =
            std::mem::ManuallyDrop::new(unsafe { std::net::TcpStream::from_raw_socket(raw) });
        view.shutdown(how)
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

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
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
        dup_tcp_stream(&self.inner)
    }

    /// 真 scatter-gather 读（bd 2o9l，Go ReadVReader rawConn 分支的 Rust 等价）：
    /// readiness + `try_read_vectored`。`WouldBlock` 时 readiness 已被 tokio 消费，
    /// 重新 poll_read_ready 注册 waker，不空转。
    fn poll_read_multi(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &mut [io::IoSliceMut<'_>],
    ) -> Poll<io::Result<usize>> {
        loop {
            std::task::ready!(self.inner.poll_read_ready(cx))?;
            match self.inner.try_read_vectored(bufs) {
                Ok(n) => return Poll::Ready(Ok(n)),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }

    /// 裸 TCP 连接保持 splice 准入信号（fb0e7ba 引入；fc9050c 误删致 Linux
    /// splice 准入 outbound_raw 恒 false——此处恢复）。
    fn is_raw_tcp(&self) -> bool {
        true
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
        #[cfg(windows)]
        self.winsock_shutdown(std::net::Shutdown::Read)?;
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
        #[cfg(windows)]
        self.winsock_shutdown(std::net::Shutdown::Write)?;
        Ok(())
    }
}

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

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
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

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
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

    fn is_raw_tcp(&self) -> bool {
        // Box 透传：内层是裸 TCP（如 TcpConnection）时保持 splice 准入信号。
        (**self).is_raw_tcp()
    }

    fn poll_read_multi(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &mut [io::IoSliceMut<'_>],
    ) -> Poll<io::Result<usize>> {
        (**self).poll_read_multi(cx, bufs)
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

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
    /// bd 09c4：close_write 必须让对端读到 EOF（FIN），close_read 之后对端
    /// 新写入的数据不得再被本端读出——Windows 静默 no-op 在此必红。
    #[tokio::test]
    async fn tcp_half_close_directional_semantics() {
        use std::time::Duration;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpConnection::new(tokio::net::TcpStream::connect(addr).await.unwrap());
        let (stream, _) = listener.accept().await.unwrap();
        let mut server = stream;

        // close_write：对端读端必须看到 EOF，本端读方向不受影响。
        client.close_write().expect("close_write must succeed");
        let mut eof_buf = [0u8; 8];
        let n = tokio::time::timeout(Duration::from_secs(5), server.read(&mut eof_buf))
            .await
            .expect("close_write: peer must observe EOF within 5s (Windows no-op stalls here)");
        assert_eq!(n.unwrap(), 0, "close_write: peer must see EOF");
        server.write_all(b"resp").await.unwrap();
        let mut buf = [0u8; 4];
        let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut buf))
            .await
            .expect("read after close_write must still work")
            .unwrap();
        assert_eq!(&buf[..n], b"resp");

        // close_read：对端之后写入的数据不得再被本端读出。
        client.close_read().expect("close_read must succeed");
        let _ = server.write_all(b"late").await; // Windows 侧对端可能收 RST，不 assert
        let mut late = [0u8; 4];
        match tokio::time::timeout(Duration::from_secs(5), client.read(&mut late)).await {
            Err(_) => panic!("close_read: neither EOF nor error — half-close is a silent no-op"),
            Ok(Ok(0)) => {}, // unix SHUT_RD → EOF
            Ok(Ok(n)) => {
                panic!("close_read: still read {n} bytes of new peer data: {:?}", &late[..n])
            },
            Ok(Err(e)) => {
                // Windows SD_RECEIVE → WSAESHUTDOWN；非 WouldBlock 即真实半关闭。
                assert_ne!(e.kind(), std::io::ErrorKind::WouldBlock, "unexpected WouldBlock: {e}");
            },
        }
    }
}
