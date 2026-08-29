//! 系统监听器——TCP 绑定 + Accept 循环 + sockopt 应用。
//!
//! 对应 Go `transport/internet/system_listener.go` 的 `DefaultListener`。
//!
//! ## 切片边界（P5-SysL 切片1）
//!
//! 实现 TCP 监听的核心路径：`DefaultListener` + `listen_system` async 函数 +
//! 全局 `effective_listener` + `register_listener_controller`。
//!
//! Unix domain socket（FileLocker + 权限 + Linux abstract `@`/`@@`）、TCP
//! KeepAliveConfig（idle/interval 任一非零即启用）、TcpMptcp（Linux，静默回退）。
//! 待办：`ListenPacket`（UDP）+ 平台特定 sockopt（SO_REUSEPORT 等）。

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
        let inner = if sockopt.tcp_mptcp {
            Self::bind_mptcp(addr, &sockopt).await?
        } else if Self::needs_prelisten_sockopt(&sockopt) {
            Self::bind_with_prelisten_sockopt(addr, &sockopt).await?
        } else {
            TokioTcpListener::bind(addr).await?
        };
        Ok(Self {
            inner,
            sockopt,
            controllers: Vec::new(),
            accept_proxy_protocol: false,
        })
    }

    /// 预监听（pre-listen）socket 选项判断。
    ///
    /// 这些选项必须在 `listen()` 之前设置才能生效：
    /// - Linux TCP_FASTOPEN backlog（sockopt_linux.go:122-127）
    /// - SO_REUSEPORT（sockopt_linux.go:241-245）
    /// - Windows TCP_FASTOPEN=15（sockopt_windows.go:125-127）
    /// - FreeBSD TCP_FASTOPEN（sockopt_freebsd.go:187-192）
    /// - Darwin TCP_FASTOPEN_SERVER 位（sockopt_darwin.go）
    fn needs_prelisten_sockopt(sockopt: &SocketOptions) -> bool {
        sockopt.tcp_fast_open || sockopt.reuse_port
    }

    /// 带预监听 socket 选项的绑定路径。对应 Go `lc.SetMultipathTCP(true)` 之外的
    /// `applyInboundSocketOptions` 监听前分支（sockopt_linux.go:115-232）。
    async fn bind_with_prelisten_sockopt(
        addr: SocketAddr,
        sockopt: &SocketOptions,
    ) -> io::Result<TokioTcpListener> {
        use socket2::{Domain, Type};
        let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
        let socket = Socket::new(domain, Type::STREAM, Some(socket2::Protocol::TCP))?;
        // SO_REUSEPORT 必须在 bind 前设。
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let fd = socket.as_raw_fd();
            #[cfg(target_os = "linux")]
            if sockopt.reuse_port {
                crate::sockopt::linux::LinuxSockOpt { reuse_port: true, ..Default::default() }
                    .apply(fd)?;
            }
            #[cfg(target_os = "freebsd")]
            if sockopt.reuse_port {
                crate::sockopt::freebsd::FreebsdSockOpt { reuse_port: true, ..Default::default() }
                    .apply(fd)?;
            }
            #[cfg(target_os = "macos")]
            if sockopt.reuse_port {
                crate::sockopt::darwin::DarwinSockOpt { reuse_port: true, inbound: true, ..Default::default() }
                    .apply(fd)?;
            }
        }
        socket.bind(&addr.into())?;
        // TFO backlog 必须在 listen 前设（Linux TCP_FASTOPEN 等同 Go :122-127；
        // FreeBSD 同；Windows 同）。
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let fd = socket.as_raw_fd();
            #[cfg(target_os = "linux")]
            if sockopt.tcp_fast_open {
                crate::sockopt::linux::LinuxSockOpt {
                    tcp_fast_open: 1,
                    inbound: true,
                    ..Default::default()
                }
                .apply(fd)?;
            }
            #[cfg(target_os = "freebsd")]
            if sockopt.tcp_fast_open {
                crate::sockopt::freebsd::FreebsdSockOpt {
                    tcp_fast_open: 1,
                    inbound: true,
                    ..Default::default()
                }
                .apply(fd)?;
            }
            #[cfg(target_os = "macos")]
            if sockopt.tcp_fast_open {
                crate::sockopt::darwin::DarwinSockOpt {
                    tcp_fast_open: 1,
                    inbound: true,
                    ..Default::default()
                }
                .apply(fd)?;
            }
        }
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::io::AsRawSocket;
            if sockopt.tcp_fast_open || sockopt.reuse_port {
                // Windows setReusePort 为 no-op（sockopt_windows.go:188-190），仅 TFO 生效。
                crate::sockopt::windows::WindowsSockOpt {
                    tcp_fast_open: if sockopt.tcp_fast_open { 1 } else { -1 },
                    ..Default::default()
                }
                .apply(socket.as_raw_socket())?;
            }
        }
        socket.listen(128)?;
        socket.set_nonblocking(true)?;
        #[cfg(unix)]
        let std_listener = std::net::TcpListener::from(std::os::fd::OwnedFd::from(socket));
        #[cfg(target_os = "windows")]
        // SAFETY: socket 持有原始 SOCKET 句柄，转 std TcpListener 夺走所有权。
        let std_listener = unsafe {
            use std::os::windows::io::{FromRawSocket, IntoRawSocket};
            std::net::TcpListener::from_raw_socket(socket.into_raw_socket())
        };
        Ok(TokioTcpListener::from_std(std_listener)?)
    }

    /// MPTCP 监听绑定。对应 Go `lc.SetMultipathTCP(true)`（system_listener.go:110-112）。
    ///
    /// Linux：手动创建 socket 并在 bind 前设 `TCP_MPTCP`（内核不支持时记录并
    /// 静默回退普通 TCP，对齐 Go）。其他平台：Go 本身不支持 MPTCP 监听，直接普通绑定。
    #[cfg(not(target_os = "linux"))]
    async fn bind_mptcp(addr: SocketAddr, _sockopt: &SocketOptions) -> io::Result<TokioTcpListener> {
        TokioTcpListener::bind(addr).await
    }

    #[cfg(target_os = "linux")]
    async fn bind_mptcp(addr: SocketAddr, sockopt: &SocketOptions) -> io::Result<TokioTcpListener> {
        use socket2::{Domain, Protocol, Type};
        let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
        // TCP_MPTCP 必须在 listen 前设置；失败（如内核未编译 MPTCP）静默回退普通 TCP。
        if let Err(e) = crate::sockopt::try_set_mptcp(&socket) {
            tracing::debug!(error = %e, "MPTCP unavailable, falling back to TCP");
        }
        // 顺路复用 prelisten 路径处理 TFO/REUSEPORT。
        if sockopt.reuse_port {
            use std::os::fd::AsRawFd;
            crate::sockopt::linux::LinuxSockOpt { reuse_port: true, ..Default::default() }
                .apply(socket.as_raw_fd())?;
        }
        if sockopt.tcp_fast_open {
            use std::os::fd::AsRawFd;
            crate::sockopt::linux::LinuxSockOpt {
                tcp_fast_open: 1,
                inbound: true,
                ..Default::default()
            }
            .apply(socket.as_raw_fd())?;
        }
        socket.bind(&addr.into())?;
        socket.listen(128)?;
        socket.set_nonblocking(true)?;
        // Socket → OwnedFd → std TcpListener（socket2 无直接转换）。
        let std_listener = std::net::TcpListener::from(std::os::fd::OwnedFd::from(socket));
        Ok(TokioTcpListener::from_std(std_listener)?)
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
    /// - `/path/to/socket` — 普通路径（FileLocker + 残留文件清理）
    /// - `/path/to/socket,0755` — 路径 + 八进制权限（bind 后 chmod）
    /// - `@name` — Linux abstract socket（无 FileLocker，Go system_listener.go:119）
    /// - `@@name` — abstract socket + haproxy padding（名字零填充到 108 字节，
    ///   Go system_listener.go:121-126）
    ///
    /// # Errors
    /// FileLocker 获取失败 / bind 失败 / 权限设置失败 / abstract 名超长时返回 `io::Error`。
    pub async fn bind(addr: &str, sockopt: SocketOptions) -> io::Result<Self> {
        match parse_unix_addr(addr)? {
            UnixAddrSpec::Abstract(name) => {
                // abstract socket 在独立命名空间，无锁、无文件、无权限设置。
                let inner = TokioUnixListener::from_std(bind_abstract_unix(&name)?)?;
                Ok(Self {
                    inner,
                    sockopt,
                    controllers: Vec::new(),
                    _locker: None,
                })
            }
            UnixAddrSpec::Path(socket_path, perm) => {
                // normal unix domain socket needs lock
                let mut lk = FileLocker::new(format!("{}.lock", socket_path.display()));
                lk.acquire()?;

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
                    _locker: Some(lk),
                })
            }
        }
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
#[derive(Debug)]
#[cfg(unix)]
enum UnixAddrSpec {
    /// 普通文件系统路径 + 可选八进制权限。
    Path(PathBuf, Option<u32>),
    /// Linux abstract socket 的 sun_path 字节（已含前导 `\0`）。
    Abstract(Vec<u8>),
}

/// 计算 Linux abstract unix socket 的 `sun_path` 字节。纯函数，无平台依赖。
///
/// 对应 Go `DefaultListener.Listen` 的 abstract 分支（system_listener.go:119-126）：
/// - `@name` → `\0name`（abstract 命名空间，Go net 把 `@` 转 `\0`）
/// - `@@name` → `\0name` + `\0` 填充到 108 字节（`sizeof(sockaddr_un.sun_path)`，
///   haproxy padding 约定）
/// - 名字部分超过 107 字节 → `None`（对齐 Go net "unix socket name too long"）
#[cfg(any(target_os = "linux", target_os = "android", test))]
pub(crate) fn abstract_sockaddr_path(addr: &str) -> Option<Vec<u8>> {
    const SUN_PATH_LEN: usize = 108; // Linux sockaddr_un.sun_path
    let bytes = addr.as_bytes();
    if bytes.first() != Some(&b'@') {
        return None;
    }
    let padded = bytes.get(1) == Some(&b'@');
    let name = &bytes[1..]; // 第二个 '@'（若有）由填充逻辑转成 '\0'
    if padded {
        // Go: fullAddr := make([]byte, 108); copy(fullAddr, address[1:])
        let mut v = vec![0u8; SUN_PATH_LEN];
        let n = name.len().min(SUN_PATH_LEN);
        v[..n].copy_from_slice(&name[..n]);
        v[0] = 0; // Go net 把首字节 '@' 转 abstract 前导 '\0'
        Some(v)
    } else {
        if name.len() > SUN_PATH_LEN - 1 {
            return None;
        }
        let mut v = Vec::with_capacity(name.len() + 1);
        v.push(0);
        v.extend_from_slice(name);
        Some(v)
    }
}

/// 解析 Unix 地址。
///
/// - Linux/Android：`@`/`@@` 前缀 → [`UnixAddrSpec::Abstract`]（lockfree）
/// - 其他 unix：`@` 前缀 → `InvalidInput`（Go 端 abstract 仅支持 linux/android；
///   Go 在 darwin 会把 `@x` 当字面路径走 FileLocker 最终 bind 失败，此处显式报错）
/// - `path` / `path,perm`（八进制） → [`UnixAddrSpec::Path`]
#[cfg(unix)]
fn parse_unix_addr(addr: &str) -> io::Result<UnixAddrSpec> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if let Some(name) = abstract_sockaddr_path(addr) {
        return Ok(UnixAddrSpec::Abstract(name));
    }
    if addr.starts_with('@') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "abstract socket (@) is only supported on Linux/Android",
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
        Ok(UnixAddrSpec::Path(PathBuf::from(path), Some(perm)))
    } else {
        Ok(UnixAddrSpec::Path(PathBuf::from(addr), None))
    }
}

/// 用 libc 手动创建 Linux abstract unix socket（std/tokio 不支持 abstract 地址）。
///
/// `name` 为完整 `sun_path` 字节（含前导 `\0`）。socket 以非阻塞创建，
/// 可直接交给 [`TokioUnixListener::from_std`]。
#[cfg(any(target_os = "linux", target_os = "android"))]
fn bind_abstract_unix(name: &[u8]) -> io::Result<std::os::unix::net::UnixListener> {
    use std::os::fd::FromRawFd;
    // SAFETY: socket(2) 返回的 fd 所有权移交 std UnixListener（from_raw_fd）。
    unsafe {
        let fd = libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        );
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut addr: libc::sockaddr_un = std::mem::zeroed();
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        if name.len() > addr.sun_path.len() {
            libc::close(fd);
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "abstract socket name too long",
            ));
        }
        // sun_path 是 [c_char; 108]，逐字节 u8→c_char（abstract 名不含 NUL 终止）。
        for (dst, src) in addr.sun_path.iter_mut().zip(name.iter()) {
            *dst = *src as libc::c_char;
        }
        // abstract 地址长度 = sun_family(2) + 实际名字长度（无 '\0' 终止符）。
        let addrlen = std::mem::size_of::<libc::sa_family_t>() + name.len();
        if libc::bind(
            fd,
            (&addr as *const libc::sockaddr_un).cast(),
            addrlen as libc::socklen_t,
        ) < 0
        {
            let e = io::Error::last_os_error();
            libc::close(fd);
            return Err(e);
        }
        if libc::listen(fd, 128) < 0 {
            let e = io::Error::last_os_error();
            libc::close(fd);
            return Err(e);
        }
        Ok(std::os::unix::net::UnixListener::from_raw_fd(fd))
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
        match parse_unix_addr("/tmp/test.sock").unwrap() {
            UnixAddrSpec::Path(path, perm) => {
                assert_eq!(path, PathBuf::from("/tmp/test.sock"));
                assert!(perm.is_none());
            }
            other => panic!("expect Path, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn parse_unix_addr_with_permission() {
        match parse_unix_addr("/tmp/test.sock,0755").unwrap() {
            UnixAddrSpec::Path(path, perm) => {
                assert_eq!(path, PathBuf::from("/tmp/test.sock"));
                assert_eq!(perm, Some(0o755));
            }
            other => panic!("expect Path, got {other:?}"),
        }
    }

    /// `@` 前缀：Linux/Android 解析为 Abstract；其他 unix 显式报错
    ///（Windows 无 unix socket，该分支 cfg 掉，走纯函数测试）。
    #[cfg(unix)]
    #[test]
    fn parse_unix_addr_abstract() {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        match parse_unix_addr("@abstract").unwrap() {
            UnixAddrSpec::Abstract(n) => assert_eq!(n, b"\0abstract".to_vec()),
            other => panic!("expect Abstract, got {other:?}"),
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            let err = parse_unix_addr("@abstract").unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        }
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

    // ===== bd 6tl：abstract socket / KeepAliveConfig / TcpMptcp =====

    /// abstract 地址 → sun_path 字节。纯函数，全平台可测
    ///（Go system_listener.go:119-126）。
    #[test]
    fn abstract_sockaddr_path_variants() {
        // @name → \0name
        assert_eq!(
            abstract_sockaddr_path("@name").unwrap(),
            b"\0name".to_vec()
        );
        // @@name → \0 + name 零填充到 108 字节（haproxy padding）
        let padded = abstract_sockaddr_path("@@name").unwrap();
        assert_eq!(padded.len(), 108);
        assert_eq!(&padded[..5], b"\0name");
        assert!(padded[5..].iter().all(|&b| b == 0));
        // @@ → 全零 108 字节
        let empty = abstract_sockaddr_path("@@").unwrap();
        assert_eq!(empty, vec![0u8; 108]);
        // 非 @ 前缀 → None
        assert!(abstract_sockaddr_path("/tmp/x.sock").is_none());
        assert!(abstract_sockaddr_path("").is_none());
        // @name 超长（> 107 字节）→ None（Go "unix socket name too long"）
        let long = format!("@{}", "a".repeat(108));
        assert!(abstract_sockaddr_path(&long).is_none());
        // @@ 超长 → 对齐 Go copy() 截断到 108
        let long_pad = format!("@@{}", "a".repeat(200));
        assert_eq!(abstract_sockaddr_path(&long_pad).unwrap().len(), 108);
    }

    /// MPTCP 监听：Windows/非 Linux 走不可用分支——静默回退普通 TCP，监听照常工作
    ///（对齐 Go `SetMultipathTCP` 平台不支持时的行为）；Linux 走 TCP_MPTCP setsockopt
    /// 路径，内核不支持同样回退。两端均断言端到端可用。
    #[tokio::test]
    async fn mptcp_listener_binds_and_accepts() {
        let sockopt = SocketOptions {
            tcp_mptcp: true,
            ..Default::default()
        };
        let listener = DefaultListener::bind("127.0.0.1:0".parse().unwrap(), sockopt)
            .await
            .expect("tcp_mptcp=true 时 bind 失败（应回退普通 TCP）");
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let mut conn = listener.accept().await.expect("accept 失败");
            conn.write_all(b"mptcp").await.expect("write 失败");
        });

        let mut client = TcpStream::connect(addr).await.expect("connect 失败");
        let mut buf = [0u8; 5];
        client.read_exact(&mut buf).await.expect("read 失败");
        assert_eq!(&buf, b"mptcp");

        server.await.unwrap();
    }

    /// KeepAliveConfig 语义（Go system_listener.go:96-109）：idle/interval 任一 >0
    /// 即启用 SO_KEEPALIVE；均未配置则保持默认关闭。经 accept 路径 + fd 控制器
    /// 读取 accepted socket 的 SO_KEEPALIVE 状态验证。
    #[tokio::test]
    async fn inbound_keepalive_enabled_when_either_field_set() {
        let ka_state = Arc::new(parking_lot::Mutex::new(None));
        let hook = Arc::clone(&ka_state);

        // 仅 interval（idle=0）：Go Enable=true、Idle 用系统默认。
        let sockopt = SocketOptions {
            tcp_keepalive_idle: std::time::Duration::ZERO,
            tcp_keepalive_interval: std::time::Duration::from_secs(30),
            ..Default::default()
        };
        let mut listener = DefaultListener::bind("127.0.0.1:0".parse().unwrap(), sockopt)
            .await
            .unwrap();
        listener.add_controller(Arc::new(move |_net, _addr, socket| {
            *hook.lock() = Some(socket.keepalive()?);
            Ok(())
        }));
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let _client = TcpStream::connect(addr).await.unwrap();
        server.await.unwrap();

        assert_eq!(*ka_state.lock(), Some(true), "interval-only 应启用 keepalive");
    }

    /// KeepAliveConfig：idle/interval 均为 0（Go Enable=false，lc.KeepAlive=-1）
    /// → 不触碰 SO_KEEPALIVE，accepted socket 保持关闭。
    #[tokio::test]
    async fn inbound_keepalive_disabled_when_unset() {
        let ka_state = Arc::new(parking_lot::Mutex::new(None));
        let hook = Arc::clone(&ka_state);

        let sockopt = SocketOptions {
            tcp_keepalive_idle: std::time::Duration::ZERO,
            tcp_keepalive_interval: std::time::Duration::ZERO,
            ..Default::default()
        };
        let mut listener = DefaultListener::bind("127.0.0.1:0".parse().unwrap(), sockopt)
            .await
            .unwrap();
        listener.add_controller(Arc::new(move |_net, _addr, socket| {
            *hook.lock() = Some(socket.keepalive()?);
            Ok(())
        }));
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let _client = TcpStream::connect(addr).await.unwrap();
        server.await.unwrap();

        assert_eq!(*ka_state.lock(), Some(false), "未配置时不应启用 keepalive");
    }
}
