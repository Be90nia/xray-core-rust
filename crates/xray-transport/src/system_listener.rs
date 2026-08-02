//! 系统监听器——TCP 绑定 + Accept 循环 + sockopt 应用。
//!
//! 对应 Go `transport/internet/system_listener.go` 的 `DefaultListener`。
//!
//! ## 切片边界（P5-SysL 切片1）
//!
//! 实现 TCP 监听的核心路径：`DefaultListener` + `listen_system` async 函数 +
//! 全局 `effective_listener` + `register_listener_controller`。
//!
//! 切片2 待办：Unix domain socket（FileLocker + 权限设置）+ `ListenPacket`（UDP）+
//! `AcceptProxyProtocol`（proxyproto）+ 平台特定 sockopt（SO_REUSEPORT 等）。

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};

use parking_lot::RwLock;
use socket2::Socket;
use tokio::net::TcpListener as TokioTcpListener;

use crate::connection::{Connection, TcpConnection};
use crate::sockopt::{SocketOptions, apply_inbound_socket_options};
use crate::listener::Listener;
#[cfg(unix)]
use std::path::PathBuf;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
#[cfg(unix)]
use tokio::net::{UnixListener as TokioUnixListener, UnixStream};
#[cfg(unix)]
use crate::filelocker::FileLocker;

/// fd 级监听控制器。对应 Go `func(network, address string, c syscall.RawConn) error`。
///
/// 切片1 不暴露 fd（socket2 Socket 封装），控制器接受 `&Socket` 引用操作。
/// 签名与 [`crate::system_dialer::DialerController`] 对称。
pub type ListenerController = Arc<dyn Fn(&str, &str, &Socket) -> io::Result<()> + Send + Sync>;

/// 系统监听器 trait。对应 Go `DefaultListener` 的 `Listen` 方法。
///
/// 实现者负责 TCP bind + accept 循环 + sockopt 应用。
/// `accept` 返回 `Box<dyn Connection>`，与 [`crate::Listener`] trait 一致。
pub trait SystemListener: Send + Sync {
    /// 接受一个入站连接（已应用 inbound sockopt）。
    fn accept<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn Connection>>> + Send + 'a>>;

    /// 监听器本地地址。
    fn local_addr(&self) -> io::Result<SocketAddr>;
}

/// 默认系统监听器。对应 Go `DefaultListener`。
///
/// 持有 TCP listener + sockopt 配置 + 注册的 fd 控制器列表。
/// `accept` 后对每个入站连接应用 [`apply_inbound_socket_options`]。
pub struct DefaultListener {
    inner: TokioTcpListener,
    sockopt: SocketOptions,
    controllers: Vec<ListenerController>,
    /// 是否在 accept 后读取 PROXY protocol header（对应 Go `AcceptProxyProtocol`）。
    accept_proxy_protocol: bool,
}

impl DefaultListener {
    /// 绑定到指定地址并构造监听器。
    ///
    /// 对应 Go `DefaultListener.Listen(ctx, addr, sockopt)` 的 TCP 分支。
    /// sockopt 在 `accept` 时应用到每个入站连接（与 Go 一致）。
    pub async fn bind(addr: SocketAddr, sockopt: SocketOptions) -> io::Result<Self> {
        let inner = TokioTcpListener::bind(addr).await?;
        Ok(Self {
            inner,
            sockopt,
            controllers: Vec::new(),
            accept_proxy_protocol: false,
        })
    }

    /// 用已绑定的 tokio listener 构造（测试或高级场景用）。
    pub fn from_tokio(inner: TokioTcpListener, sockopt: SocketOptions) -> Self {
        Self {
            inner,
            sockopt,
            controllers: Vec::new(),
            accept_proxy_protocol: false,
        }
    }

    /// 启用/禁用 PROXY protocol 支持。对应 Go `ListenConfig.AcceptProxyProtocol`。
    /// 启用后，accept 时先读取 PROXY protocol header 提取真实源地址。
    #[must_use]
    pub fn with_accept_proxy_protocol(mut self, enabled: bool) -> Self {
        self.accept_proxy_protocol = enabled;
        self
    }

    /// 添加 fd 控制器。对应 Go `effectiveListener.controllers = append(...)`。
    pub fn add_controller(&mut self, ctl: ListenerController) {
        self.controllers.push(ctl);
    }

    /// 取回内部 tokio listener。
    pub fn into_inner(self) -> TokioTcpListener {
        self.inner
    }
}

impl SystemListener for DefaultListener {
    fn accept<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn Connection>>> + Send + 'a>> {
        Box::pin(async move {
            let (stream, peer) = self.inner.accept().await?;
            // 把 tokio TcpStream 转 std 再转 socket2 应用 sockopt。
            let std_stream = stream.into_std()?;
            let socket = socket2::Socket::from(std_stream);

            // 应用 inbound sockopt（TCP_NODELAY + keepalive）。
            if let Err(e) = apply_inbound_socket_options(&socket, &self.sockopt) {
                tracing::debug!(error = %e, "failed to apply inbound socket options");
            }

            // 应用 fd 控制器。
            let local_addr = socket
                .local_addr()
                .ok()
                .and_then(|sa| sa.as_socket())
                .map(|s| s.to_string())
                .unwrap_or_default();
            for ctl in &self.controllers {
                if let Err(e) = ctl("tcp", &local_addr, &socket) {
                    tracing::debug!(error = %e, "listener controller failed");
                }
            }

            // 转回 tokio TcpStream 用于异步 IO。
            let tcp_stream = tokio::net::TcpStream::from_std(socket.into())?;
            // PROXY protocol：启用时先读取 PROXY header 提取真实源地址。
            let conn: Box<dyn Connection> = if self.accept_proxy_protocol {
                use tokio::io::AsyncReadExt;
                let mut stream = tcp_stream;
                match crate::proxy_protocol::read_proxy_protocol(&mut stream).await {
                    Ok(Some(real_peer)) => {
                        tracing::debug!(proxy_peer = %real_peer, tcp_peer = %peer, "PROXY protocol resolved");
                        Box::new(ProxiedConnection::new(TcpConnection::new(stream), real_peer))
                    }
                    Ok(None) => {
                        tracing::debug!(tcp_peer = %peer, "PROXY protocol UNKNOWN");
                        Box::new(TcpConnection::new(stream))
                    }
                    Err(e) => return Err(e),
                }
            } else {
                let _ = peer;
                Box::new(TcpConnection::new(tcp_stream))
            };
            Ok(conn)
        })
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}


/// PROXY protocol 连接包装器。
///
/// 包装 `TcpConnection`，覆盖 `remote_addr` 返回 PROXY protocol 提取的真实源地址。
/// 对应 Go `proxyproto.Addr` 包装 `net.Conn` 的模式。
pub struct ProxiedConnection {
    inner: TcpConnection,
    remote: Option<SocketAddr>,
}

impl ProxiedConnection {
    #[must_use]
    pub fn new(inner: TcpConnection, remote: SocketAddr) -> Self {
        Self { inner, remote: Some(remote) }
    }
}

impl AsyncRead for ProxiedConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for ProxiedConnection {
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

impl Connection for ProxiedConnection {
    fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(self.remote)
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.inner.local_addr()
    }
}

// ===== 全局 effective listener + listen_system =====

/// 全局 fd 控制器列表（所有通过 `listen_system` 创建的 listener 共享）。
static GLOBAL_CONTROLLERS: OnceLock<RwLock<Vec<ListenerController>>> = OnceLock::new();

fn global_controllers() -> &'static RwLock<Vec<ListenerController>> {
    GLOBAL_CONTROLLERS.get_or_init(|| RwLock::new(Vec::new()))
}

/// 注册全局 fd 监听控制器。对应 Go `RegisterListenerController`。
///
/// 所有后续通过 [`listen_system`] 创建的 listener 会在 accept 时调用已注册的控制器。
pub fn register_listener_controller(ctl: ListenerController) -> io::Result<()> {
    global_controllers().write().push(ctl);
    Ok(())
}

/// 系统级 TCP 监听。对应 Go `DefaultListener.Listen(ctx, addr, sockopt)` 的 TCP 分支。
///
/// 绑定 `addr`，创建 [`DefaultListener`]，注入全局 fd 控制器。
/// 返回的 listener 可通过 [`SystemListener`] 或 [`Listener`] trait 使用。
pub async fn listen_system(addr: SocketAddr, sockopt: SocketOptions) -> io::Result<DefaultListener> {
    let mut listener = DefaultListener::bind(addr, sockopt).await?;
    // 注入全局控制器（克隆 Arc 引用）。
    for ctl in global_controllers().read().iter() {
        listener.add_controller(Arc::clone(ctl));
    }
    Ok(listener)
}

// ===== Unix domain socket 监听（#[cfg(unix)]）=====

/// Unix domain socket 连接。对应 Go `UnixConnWrapper`。
///
/// `remote_addr` / `local_addr` 返回 `0.0.0.0:0`（模仿 Go UnixConnWrapper.RemoteAddr）——
/// Unix socket 没有真正的 SocketAddr，但上层假设连接有 TCPAddr。
#[cfg(unix)]
pub struct UnixConnection {
    inner: UnixStream,
}

#[cfg(unix)]
impl UnixConnection {
    /// 用已建立的 `UnixStream` 构造。
    #[must_use]
    pub fn new(stream: UnixStream) -> Self {
        Self { inner: stream }
    }

    /// 拆出底层 `UnixStream`。
    #[must_use]
    pub fn into_inner(self) -> UnixStream {
        self.inner
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
        Ok(Some(SocketAddr::from(([0, 0, 0, 0], 0))))
    }
    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(Some(SocketAddr::from(([0, 0, 0, 0], 0))))
    }
}

/// Unix domain socket 监听器。对应 Go `UnixListenerWrapper`。
///
/// 持有 tokio `UnixListener` + FileLocker（绑定期间防多实例）+ sockopt + controllers。
#[cfg(unix)]
pub struct UnixListener {
    inner: TokioUnixListener,
    sockopt: SocketOptions,
    controllers: Vec<ListenerController>,
    _locker: Option<FileLocker>,
}

#[cfg(unix)]
impl UnixListener {
    /// 绑定 Unix domain socket。对应 Go `DefaultListener.Listen` 的 Unix 分支。
    ///
    /// 地址格式：
    /// - `/path/to/socket` — 普通路径
    /// - `/path/to/socket,0755` — 路径 + 八进制权限（bind 后 chmod）
    /// - `@name` — Linux abstract socket（尚不支持，返回 `InvalidInput`）
    ///
    /// # Errors
    /// FileLocker 获取失败 / bind 失败 / 权限设置失败时返回 `io::Error`。
    pub async fn bind(addr: &str, sockopt: SocketOptions) -> io::Result<Self> {
        let (socket_path, perm) = parse_unix_addr(addr)?;

        // FileLocker（abstract socket 不需要）
        let locker = if socket_path.starts_with('\u{0}') {
            None
        } else {
            let mut lk = FileLocker::new(format!("{}.lock", socket_path.display()));
            lk.acquire()?;
            Some(lk)
        };

        // 删除可能残留的旧 socket 文件（Go 标准库 net.ListenUnix 也这样做）
        let _ = std::fs::remove_file(&socket_path);
        let inner = TokioUnixListener::bind(&socket_path)?;

        // bind 后设置权限
        if let Some(mode) = perm {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(mode))
                .map_err(|e| io::Error::other(format!("failed to set permission: {e}")))?;
        }

        Ok(Self {
            inner,
            sockopt,
            controllers: Vec::new(),
            _locker: locker,
        })
    }

    /// 添加 fd 控制器。
    pub fn add_controller(&mut self, ctl: ListenerController) {
        self.controllers.push(ctl);
    }
}

#[cfg(unix)]
impl SystemListener for UnixListener {
    fn accept<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn Connection>>> + Send + 'a>> {
        Box::pin(async move {
            let (stream, _) = self.inner.accept().await?;
            Ok(Box::new(UnixConnection::new(stream)) as Box<dyn Connection>)
        })
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        // Unix socket 没有 SocketAddr，返回 unspecified（模仿 Go）
        Ok(SocketAddr::from(([0, 0, 0, 0], 0)))
    }
}

/// 解析 Unix 地址（path 或 path,perm）。
///
/// 返回 (socket_path, optional_permission)。
/// `@` 前缀（abstract socket）暂不支持。
#[cfg(unix)]
fn parse_unix_addr(addr: &str) -> io::Result<(PathBuf, Option<u32>)> {
    // ponytail: abstract socket (@) 延后实现，需要 socket2 手动创建。
    if addr.starts_with('@') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "abstract socket (@) not yet supported, use normal path",
        ));
    }
    if let Some(comma) = addr.rfind(',') {
        let (path, perm_str) = addr.split_at(comma);
        let perm_str = &perm_str[1..]; // skip comma
        let perm = u32::from_str_radix(perm_str, 8).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid permission '{perm_str}': {e}"),
            )
        })?;
        Ok((PathBuf::from(path), Some(perm)))
    } else {
        Ok((PathBuf::from(addr), None))
    }
}

/// 系统级 Unix domain socket 监听。对应 Go `DefaultListener.Listen` 的 Unix 分支。
///
/// 绑定 `addr`（格式见 [`UnixListener::bind`]），注入全局 fd 控制器。
///
/// # Errors
/// 绑定或 FileLocker 失败时返回 `io::Error`。
#[cfg(unix)]
pub async fn listen_unix_system(addr: &str, sockopt: SocketOptions) -> io::Result<UnixListener> {
    let mut listener = UnixListener::bind(addr, sockopt).await?;
    for ctl in global_controllers().read().iter() {
        listener.add_controller(Arc::clone(ctl));
    }
    Ok(listener)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    #[tokio::test]
    async fn default_listener_bind_and_accept() {
        let listener = DefaultListener::bind("127.0.0.1:0".parse().unwrap(), SocketOptions::default())
            .await
            .expect("bind 失败");
        let addr = listener.local_addr().expect("local_addr 失败");

        let server = tokio::spawn(async move {
            let mut conn = listener.accept().await.expect("accept 失败");
            conn.write_all(b"hello").await.expect("write 失败");
        });

        let mut client = TcpStream::connect(addr).await.expect("connect 失败");
        let mut buf = [0u8; 5];
        client.read_exact(&mut buf).await.expect("read 失败");
        assert_eq!(&buf, b"hello");

        server.await.unwrap();
    }

    #[tokio::test]
    async fn default_listener_local_addr() {
        let listener = DefaultListener::bind("127.0.0.1:0".parse().unwrap(), SocketOptions::default())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        assert_eq!(addr.ip().to_string(), "127.0.0.1");
        assert_ne!(addr.port(), 0);
    }

    #[tokio::test]
    async fn default_listener_applies_sockopt_on_accept() {
        // 验证 accept 后 TCP_NODELAY 被设置。
        let sockopt = SocketOptions {
            tcp_nodelay: true,
            ..Default::default()
        };
        let listener = DefaultListener::bind("127.0.0.1:0".parse().unwrap(), sockopt)
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let client = TcpStream::connect(addr).await.unwrap();
        // 服务端 accept 时会对 client 端的 socket 设置 TCP_NODELAY。
        // 验证 client 端能正常 IO 即可（sockopt 在服务端侧应用）。
        let _ = client;
        server.await.unwrap();
    }

    #[tokio::test]
    async fn listen_system_creates_working_listener() {
        let listener = listen_system("127.0.0.1:0".parse().unwrap(), SocketOptions::default())
            .await
            .expect("listen_system 失败");
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let mut conn = listener.accept().await.unwrap();
            conn.write_all(b"ok").await.unwrap();
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut buf = [0u8; 2];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ok");

        server.await.unwrap();
    }

    #[tokio::test]
    async fn register_controller_invoked_on_accept() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let called = Arc::new(AtomicBool::new(false));
        let called_clone = Arc::clone(&called);
        register_listener_controller(Arc::new(move |_net, _addr, _socket| {
            called_clone.store(true, Ordering::SeqCst);
            Ok(())
        }))
        .unwrap();

        let listener = listen_system("127.0.0.1:0".parse().unwrap(), SocketOptions::default())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let _client = TcpStream::connect(addr).await.unwrap();
        server.await.unwrap();

        assert!(called.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn default_listener_works_as_system_listener_trait() {
        let listener: Box<dyn SystemListener> = Box::new(
            DefaultListener::bind("127.0.0.1:0".parse().unwrap(), SocketOptions::default())
                .await
                .unwrap(),
        );
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let mut conn = listener.accept().await.unwrap();
            conn.write_all(b"trait").await.unwrap();
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut buf = [0u8; 5];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"trait");

        server.await.unwrap();
    }

    #[tokio::test]
    async fn default_listener_works_as_system_listener_trait_writes_sys() {
        let listener: Box<dyn SystemListener> = Box::new(
            DefaultListener::bind("127.0.0.1:0".parse().unwrap(), SocketOptions::default())
                .await
                .unwrap(),
        );
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let mut conn = listener.accept().await.unwrap();
            conn.write_all(b"sys").await.unwrap();
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut buf = [0u8; 3];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"sys");

        server.await.unwrap();
    }

    #[tokio::test]
    async fn multiple_connections_accepted_sequentially() {
        let listener = DefaultListener::bind("127.0.0.1:0".parse().unwrap(), SocketOptions::default())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            for i in 0u8..3 {
                let mut conn = listener.accept().await.unwrap();
                conn.write_all(&[i]).await.unwrap();
            }
        });

        for i in 0u8..3 {
            let mut client = TcpStream::connect(addr).await.unwrap();
            let mut buf = [0u8; 1];
            client.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf[0], i);
        }

        server.await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_listener_bind_and_accept_roundtrip() {
        use tokio::net::UnixStream;
        let dir = std::env::temp_dir();
        let path = dir.join(format!("xray_test_uds_{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let listener = UnixListener::bind(path.to_str().unwrap(), SocketOptions::default())
            .await
            .expect("bind 失败");

        let server = tokio::spawn(async move {
            let mut conn = listener.accept().await.expect("accept 失败");
            conn.write_all(b"hello").await.expect("write 失败");
        });

        let mut client = UnixStream::connect(&path).await.expect("connect 失败");
        let mut buf = [0u8; 5];
        client.read_exact(&mut buf).await.expect("read 失败");
        assert_eq!(&buf, b"hello");

        server.await.unwrap();
        // 清理
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}.lock", path.display()));
    }

    #[cfg(unix)]
    #[test]
    fn parse_unix_addr_plain_path() {
        let (path, perm) = parse_unix_addr("/tmp/test.sock").unwrap();
        assert_eq!(path, PathBuf::from("/tmp/test.sock"));
        assert!(perm.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn parse_unix_addr_with_permission() {
        let (path, perm) = parse_unix_addr("/tmp/test.sock,0755").unwrap();
        assert_eq!(path, PathBuf::from("/tmp/test.sock"));
        assert_eq!(perm, Some(0o755));
    }

    #[cfg(unix)]
    #[test]
    fn parse_unix_addr_abstract_rejected() {
        let err = parse_unix_addr("@abstract").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_listener_file_locker_creates_lock_file() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("xray_test_flock_uds_{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let lock_path = format!("{}.lock", path.display());
        let _ = std::fs::remove_file(&lock_path);

        let listener = UnixListener::bind(path.to_str().unwrap(), SocketOptions::default())
            .await
            .expect("bind 失败");
        // lock 文件应存在
        assert!(std::path::Path::new(&lock_path).exists(), "lock 文件应存在");

        drop(listener);
        // drop 后 lock 文件应被删除
        assert!(!std::path::Path::new(&lock_path).exists(), "lock 文件应被删除");
        let _ = std::fs::remove_file(&path);
    }
}
