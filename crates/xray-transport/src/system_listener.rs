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

#[cfg(unix)]
use std::path::PathBuf;
use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, OnceLock},
    task::{Context, Poll},
};

use parking_lot::RwLock;
use socket2::Socket;
#[cfg(unix)]
use tokio::net::{UnixListener as TokioUnixListener, UnixStream};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpListener as TokioTcpListener,
};

/// Go `syscall.SOMAXCONN` 的平台值（maxListenerBacklog 各失败分支的 fallback）：
/// linux amd64 = 0x80 = 128（zerrors_linux_amd64.go:999）、darwin/freebsd 同为 128；
/// windows = 0x7fffffff（types_windows.go:622——listen backlog 仅是 hint，内核取
/// "reasonable maximum"，Go sock_windows.go:13-16 同语义）。
#[cfg(windows)]
const SOMAXCONN: i32 = 0x7fff_ffff;
#[cfg(not(windows))]
const SOMAXCONN: i32 = 128;

/// 生效 backlog。逐平台对齐 Go `net.listenerBacklog()`（net.go:404-407 进程内
/// 缓存一次，平台实现在 maxListenerBacklog）：
/// - Linux（sock_linux.go:34-59）：读 `/proc/sys/net/core/somaxconn`；读失败 / 首字段解析失败 /
///   值为 0 → `syscall.SOMAXCONN`；>65535 交给 `max_ack_backlog` 按内核版本钳制 （backlog 存储宽度
///   <4.1 为 u16、≥4.1 为 u32，issue 5030/41470）。
/// - 非 Linux：`syscall.SOMAXCONN`。BSD/darwin 的 sysctl 读取变体（sock_bsd.go:14-40）
///   未复刻——fallback 值与各平台 SOMAXCONN 缺省一致（darwin 缺省 sysctl 即 128）。
#[must_use]
pub fn effective_listen_backlog() -> i32 {
    *EFFECTIVE_LISTEN_BACKLOG
}

/// Go sock_linux.go:34-48 `maxListenerBacklog` 的解析段：首字段十进制，0 / 非数字 →
/// fallback（None）。
#[cfg(target_os = "linux")]
fn somaxconn_from_proc(text: &str) -> Option<i32> {
    text.split_whitespace().next()?.parse::<i32>().ok().filter(|&n| n > 0)
}

/// Go sock_linux.go:18-31 `maxAckBacklog`：内核 backlog 存储宽度 <4.1 为 u16、
/// ≥4.1 为 u32；版本解析失败按 16 位钳制（Go `unix.KernelVersion()` 失败返回
/// (0,0) → 走 16 位分支，同款）。≥4.1 的 u32 上限超出 `i32` 表示域，入参必满足。
#[cfg(target_os = "linux")]
fn max_ack_backlog(n: i32, kernel: (u32, u32)) -> i32 {
    if kernel.0 > 4 || (kernel.0 == 4 && kernel.1 >= 1) { n } else { n.min((1 << 16) - 1) }
}

/// Go internal/syscall/unix `KernelVersion` 同款：读 `/proc/sys/kernel/osrelease`
/// 取前两个十进制段（如 `6.6.0-14-generic` → (6, 6)）；读失败/解析不全 → (0, 0)。
#[cfg(target_os = "linux")]
fn kernel_version() -> (u32, u32) {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .and_then(|s| {
            let mut it = s
                .split(|c: char| !c.is_ascii_digit())
                .filter(|seg| !seg.is_empty())
                .filter_map(|seg| seg.parse::<u32>().ok());
            Some((it.next()?, it.next()?))
        })
        .unwrap_or((0, 0))
}

#[cfg(target_os = "linux")]
static EFFECTIVE_LISTEN_BACKLOG: std::sync::LazyLock<i32> = std::sync::LazyLock::new(|| {
    std::fs::read_to_string("/proc/sys/net/core/somaxconn")
        .ok()
        .and_then(|s| somaxconn_from_proc(&s))
        .map_or(SOMAXCONN, |n| max_ack_backlog(n, kernel_version()))
});

#[cfg(not(target_os = "linux"))]
static EFFECTIVE_LISTEN_BACKLOG: std::sync::LazyLock<i32> = std::sync::LazyLock::new(|| SOMAXCONN);

/// 指定 backlog 绑定 TCP listener（socket2 bind + listen）。
///
/// 全仓 listener 创建点统一入口（bd hjtt）：`std`/`tokio` 的 `bind` 不暴露
/// backlog（内核缺省 128）。语义对齐 `std::net::TcpListener::bind`：解析
/// 主机名取首个地址；Unix 置 SO_REUSEADDR、Windows 不置（std 同款行为）。
/// 生产调用点传 [`effective_listen_backlog()`]（Go `net.listenerBacklog` 同款）。
///
/// # Errors
/// 地址解析失败 / socket 创建 / bind / listen 失败时返回 `io::Error`。
pub async fn bind_tcp_listener<A: tokio::net::ToSocketAddrs>(
    addr: A,
    backlog: i32,
) -> io::Result<TokioTcpListener> {
    let addr = tokio::net::lookup_host(addr)
        .await?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no addresses resolved"))?;
    let domain = if addr.is_ipv4() { socket2::Domain::IPV4 } else { socket2::Domain::IPV6 };
    let socket = Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    #[cfg(unix)]
    // std::net::TcpListener::bind 在 Unix 上置 SO_REUSEADDR（TIME_WAIT 重绑）；
    // Windows 上 std 不置，保持同款平台差异。
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.listen(backlog)?;
    socket.set_nonblocking(true)?;
    #[cfg(unix)]
    let std_listener = std::net::TcpListener::from(std::os::fd::OwnedFd::from(socket));
    #[cfg(target_os = "windows")]
    // SAFETY: socket 持有原始 SOCKET 句柄，转 std TcpListener 夺走所有权。
    let std_listener = unsafe {
        use std::os::windows::io::{FromRawSocket, IntoRawSocket};
        std::net::TcpListener::from_raw_socket(socket.into_raw_socket())
    };
    TokioTcpListener::from_std(std_listener)
}

#[cfg(unix)]
use crate::filelocker::FileLocker;
use crate::{
    connection::{Connection, TcpConnection},
    sockopt::{SocketOptions, apply_inbound_socket_options},
};

/// fd 级监听控制器。对应 Go `func(network, address string, c syscall.RawConn) error`。
///
/// 切片1 不暴露 fd（socket2 Socket 封装），控制器接受 `&Socket` 引用操作。
/// 签名与 [`crate::system_dialer::DialerController`] 对称。
pub type ListenerController = Arc<dyn Fn(&str, &str, &Socket) -> io::Result<()> + Send + Sync>;

/// 系统监听器 trait。对应 Go `DefaultListener` 的 `Listen` 方法。
///
/// 实现者负责 TCP bind + accept 循环 + sockopt 应用。
/// `accept` 返回 `Box<dyn Connection>`，与 `crate::Listener` trait 一致。
pub trait SystemListener: Send + Sync {
    /// 接受一个入站连接（已应用 inbound sockopt）。
    fn accept<'a>(&'a self) -> crate::connection::BoxedConnFuture<'a>;

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
            bind_tcp_listener(addr, effective_listen_backlog()).await?
        };
        // PROXY protocol 开关接线：sockopt.acceptProxyProtocol 自动传入
        // （Go system_listener.go:169-172 按 sockopt 包 proxyproto.Listener；
        // tcpSettings 等传输级值由 transport 装配处 OR 进 sockopt 后到达这里）。
        let accept_proxy_protocol = sockopt.accept_proxy_protocol;
        Ok(Self { inner, sockopt, controllers: Vec::new(), accept_proxy_protocol })
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
    // 75rv deny(warnings) 隐性回归:iOS/Android 平台下 cfg(target_os) 三分支不进入,
    // sockopt 形参不被消费 → 用 allow 抑制 unused_variables 警告
    #[allow(unused_variables)]
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
            let _fd = socket.as_raw_fd();
            #[cfg(target_os = "linux")]
            if sockopt.reuse_port {
                crate::sockopt::linux::LinuxSockOpt { reuse_port: true, ..Default::default() }
                    .apply(_fd)?;
            }
            #[cfg(target_os = "freebsd")]
            if sockopt.reuse_port {
                crate::sockopt::freebsd::FreebsdSockOpt { reuse_port: true, ..Default::default() }
                    .apply(_fd)?;
            }
            #[cfg(target_os = "macos")]
            if sockopt.reuse_port {
                crate::sockopt::darwin::DarwinSockOpt {
                    reuse_port: true,
                    inbound: true,
                    ..Default::default()
                }
                .apply(_fd)?;
            }
        }
        socket.bind(&addr.into())?;
        // TFO backlog 必须在 listen 前设（Linux TCP_FASTOPEN 等同 Go :122-127；
        // FreeBSD 同；Windows 同）。
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            // iOS/Android 平台下 cfg(target_os) 三分支不进入,fd 不被消费
            // (75rv deny(warnings) 隐性回归)
            let _fd = socket.as_raw_fd();
            #[cfg(target_os = "linux")]
            if sockopt.tcp_fast_open {
                crate::sockopt::linux::LinuxSockOpt {
                    tcp_fast_open: 1,
                    inbound: true,
                    ..Default::default()
                }
                .apply(_fd)?;
            }
            #[cfg(target_os = "freebsd")]
            if sockopt.tcp_fast_open {
                crate::sockopt::freebsd::FreebsdSockOpt {
                    tcp_fast_open: 1,
                    inbound: true,
                    ..Default::default()
                }
                .apply(_fd)?;
            }
            #[cfg(target_os = "macos")]
            if sockopt.tcp_fast_open {
                crate::sockopt::darwin::DarwinSockOpt {
                    tcp_fast_open: 1,
                    inbound: true,
                    ..Default::default()
                }
                .apply(_fd)?;
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
        socket.listen(effective_listen_backlog())?;
        socket.set_nonblocking(true)?;
        #[cfg(unix)]
        let std_listener = std::net::TcpListener::from(std::os::fd::OwnedFd::from(socket));
        #[cfg(target_os = "windows")]
        // SAFETY: socket 持有原始 SOCKET 句柄，转 std TcpListener 夺走所有权。
        let std_listener = unsafe {
            use std::os::windows::io::{FromRawSocket, IntoRawSocket};
            std::net::TcpListener::from_raw_socket(socket.into_raw_socket())
        };
        TokioTcpListener::from_std(std_listener)
    }

    /// MPTCP 监听绑定。对应 Go `lc.SetMultipathTCP(true)`（system_listener.go:110-112）。
    ///
    /// Linux：手动创建 socket 并在 bind 前设 `TCP_MPTCP`（内核不支持时记录并
    /// 静默回退普通 TCP，对齐 Go）。其他平台：Go 本身不支持 MPTCP 监听，直接普通绑定。
    #[cfg(not(target_os = "linux"))]
    async fn bind_mptcp(
        addr: SocketAddr,
        _sockopt: &SocketOptions,
    ) -> io::Result<TokioTcpListener> {
        bind_tcp_listener(addr, effective_listen_backlog()).await
    }

    #[cfg(target_os = "linux")]
    async fn bind_mptcp(addr: SocketAddr, sockopt: &SocketOptions) -> io::Result<TokioTcpListener> {
        use socket2::{Domain, Protocol, Type};
        let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
        // TCP_MPTCP 必须在 listen 前设置；失败（如内核未编译 MPTCP）静默回退普通 TCP。
        if let Err(e) = crate::sockopt::try_set_mptcp(&socket) {
            crate::LOG.debug(format!("error={e} MPTCP unavailable, falling back to TCP"));
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
        socket.listen(effective_listen_backlog())?;
        socket.set_nonblocking(true)?;
        // Socket → OwnedFd → std TcpListener（socket2 无直接转换）。
        let std_listener = std::net::TcpListener::from(std::os::fd::OwnedFd::from(socket));
        TokioTcpListener::from_std(std_listener)
    }

    /// 用已绑定的 tokio listener 构造（测试或高级场景用）。
    pub fn from_tokio(inner: TokioTcpListener, sockopt: SocketOptions) -> Self {
        let accept_proxy_protocol = sockopt.accept_proxy_protocol;
        Self { inner, sockopt, controllers: Vec::new(), accept_proxy_protocol }
    }

    /// 启用/禁用 PROXY protocol 支持。对应 Go `ListenConfig.AcceptProxyProtocol`。
    /// 启用后，accept 时先读取 PROXY protocol header 提取真实源地址。
    /// 构造时已从 `sockopt.accept_proxy_protocol` 自动接线（双入口：sockopt 与
    /// 传输级 settings）；本方法用于显式覆盖该值。
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
                crate::LOG.debug(format!("error={e} failed to apply inbound socket options"));
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
                    crate::LOG.debug(format!("error={e} listener controller failed"));
                }
            }

            // 转回 tokio TcpStream 用于异步 IO。
            let tcp_stream = tokio::net::TcpStream::from_std(socket.into())?;
            // PROXY protocol：启用时先读取 PROXY header 提取真实源地址。
            let conn: Box<dyn Connection> = if self.accept_proxy_protocol {
                let mut stream = tcp_stream;
                match crate::proxy_protocol::read_proxy_protocol(&mut stream).await {
                    Ok(Some(real_peer)) => {
                        crate::LOG.debug(format!(
                            "proxy_peer={real_peer} tcp_peer={peer} PROXY protocol resolved"
                        ));
                        Box::new(ProxiedConnection::new(TcpConnection::new(stream), real_peer))
                    },
                    Ok(None) => {
                        crate::LOG.debug(format!("tcp_peer={peer} PROXY protocol UNKNOWN"));
                        Box::new(TcpConnection::new(stream))
                    },
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
/// 返回的 listener 可通过 [`SystemListener`] 或 `Listener` trait 使用。
pub async fn listen_system(
    addr: SocketAddr,
    sockopt: SocketOptions,
) -> io::Result<DefaultListener> {
    let mut listener = DefaultListener::bind(addr, sockopt).await?;
    // 注入全局控制器（克隆 Arc 引用）。
    for ctl in global_controllers().read().iter() {
        listener.add_controller(Arc::clone(ctl));
    }
    Ok(listener)
}

/// inbound 裸 TCP listener：accept 时应用 inbound sockopt（bd e7le）。
///
/// 对应 Go `applyInboundSocketOptions` 的 per-accept 语义
/// （system_listener.go:91-109；tokio/std 默认 nodelay=false，Go net.TCPConn
/// 默认 NoDelay=true）。与 [`DefaultListener`] 的差异：本包装返回原生
/// `(TcpStream, SocketAddr)` 元组（协议 serve 层 socks/mixed/vless/trojan/
/// vmess/http/dokodemo/ss/dns 的裸 TCP 路径直接消费），不经 `Box<dyn Connection>`。
pub struct InboundTcpListener {
    inner: TokioTcpListener,
    sockopt: SocketOptions,
    /// `tcpSettings.header` 伪装头 authenticator（Go hub.go:85-95 `l.authConfig`）。
    /// plain-TCP 装配由 xray-core 注入；serve 层按 Go keepAccepting 顺序在
    /// TLS/REALITY 解包后应用。`None` → 不包装（零开销）。
    header: Option<Arc<crate::headers::http::HttpAuthenticator>>,
    /// `finalmask.tcp` 伪装链（Go hub.go WrapListener）。plain-TCP 装配由
    /// xray-core 注入；[`Self::accept_masked`] 在 accept 后立即套上（wire 最外层，
    /// TLS/REALITY 之前）。`None` → 不包装（零开销）。
    tcpmask: Option<Arc<crate::finalmask::TcpmaskManager>>,
}

impl InboundTcpListener {
    /// 绑定 `addr`（`host:port` 字符串，与 `TcpListener::bind` 同形）。
    ///
    /// # Errors
    /// bind 失败时返回 `io::Error`。
    pub async fn bind(addr: &str, sockopt: SocketOptions) -> io::Result<Self> {
        // bd hjtt：统一走 backlog=1024 helper（tokio 缺省 128 生产 listen overflow）。
        Ok(Self {
            inner: bind_tcp_listener(addr, effective_listen_backlog()).await?,
            sockopt,
            header: None,
            tcpmask: None,
        })
    }

    /// 监听器本地地址（serve 层日志 / local addr 兜底用）。
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// 用已绑定的 tokio listener 构造（测试或高级场景用）。
    /// 与 [`DefaultListener::from_tokio`] 对称。
    #[must_use]
    pub fn from_tokio(inner: TokioTcpListener, sockopt: SocketOptions) -> Self {
        Self { inner, sockopt, header: None, tcpmask: None }
    }

    /// 注入 `tcpSettings.header` 伪装头 authenticator（`None` → 清除）。
    ///
    /// 对应 Go `hub.go:85-95` `l.authConfig`；serve 层按 Go `keepAccepting`
    /// （hub.go:106-113）顺序在 TLS 解包后应用。
    #[must_use]
    pub fn with_header_auth(
        mut self,
        auth: Option<Arc<crate::headers::http::HttpAuthenticator>>,
    ) -> Self {
        self.header = auth;
        self
    }

    /// 已注入的 `tcpSettings.header` 伪装 authenticator（未配置 → `None`）。
    #[must_use]
    pub fn header_auth(&self) -> Option<&Arc<crate::headers::http::HttpAuthenticator>> {
        self.header.as_ref()
    }

    /// 注入 `finalmask.tcp` 伪装链（`None` → 清除；空链等价 `None`）。
    ///
    /// 对应 Go `tcp/hub.go` `WrapListener`；由 [`Self::accept_masked`] 在 accept
    /// 后立即套上——mask 处于 wire 最外层，TLS/REALITY 握手在 mask 之内。
    #[must_use]
    pub fn with_tcpmask_manager(
        mut self,
        mask: Option<Arc<crate::finalmask::TcpmaskManager>>,
    ) -> Self {
        self.tcpmask = mask;
        self
    }

    /// 已注入的 `finalmask.tcp` 伪装链（未配置 → `None`）。
    #[must_use]
    pub fn tcpmask_manager(&self) -> Option<&Arc<crate::finalmask::TcpmaskManager>> {
        self.tcpmask.as_ref()
    }

    /// accept 一个连接并应用 inbound sockopt（TCP_NODELAY / keepalive 等）。
    ///
    /// sockopt 应用失败仅 debug log 不拒绝连接（与 [`DefaultListener::accept`]
    /// 及 Go Log 级处理一致）。
    ///
    /// # Errors
    /// accept 或 fd 往返转换失败时返回 `io::Error`。
    pub async fn accept(&self) -> io::Result<(tokio::net::TcpStream, SocketAddr)> {
        let (stream, peer) = self.inner.accept().await?;
        // tokio TcpStream → std → socket2 应用 sockopt（DefaultListener 同款转换）。
        let std_stream = stream.into_std()?;
        let socket = Socket::from(std_stream);
        if let Err(e) = apply_inbound_socket_options(&socket, &self.sockopt) {
            crate::LOG.debug(format!("error={e} failed to apply inbound socket options"));
        }
        Ok((tokio::net::TcpStream::from_std(socket.into())?, peer))
    }

    /// accept 一个连接并按 `finalmask.tcp` 链套 server 侧 mask（Go `hub.go`
    /// `WrapListener` → `WrapConnServer`）。
    ///
    /// 未配置 mask → [`MaybeTcpMaskConn::Plain`](crate::finalmask::MaybeTcpMaskConn::Plain)
    /// （与 [`Self::accept`] 等价，零包装）。
    /// mask 生效时返回的连接读写已是解伪装后的明文，TLS/REALITY 应在其上再握手。
    ///
    /// # Errors
    /// accept / sockopt / mask 链构造失败时返回 `io::Error`。
    pub async fn accept_masked(
        &self,
    ) -> io::Result<(crate::finalmask::MaybeTcpMaskConn<tokio::net::TcpStream>, SocketAddr)> {
        let (stream, peer) = self.accept().await?;
        match self.tcpmask.as_deref() {
            Some(mgr) => Ok((crate::finalmask::maybe_mask_server(mgr, stream)?, peer)),
            None => Ok((crate::finalmask::MaybeTcpMaskConn::Plain(stream), peer)),
        }
    }
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
    // sockopt 在 Unix accept 路径由内核 socket 直接生效，字段保留对齐 Go 装配面
    #[allow(dead_code)] // Unix accept 路径 sockopt 由内核 socket 直接生效，字段对齐 Go 装配面
    sockopt: SocketOptions,
    controllers: Vec<ListenerController>,
    _locker: Option<FileLocker>,
}

/// UDS socket 文件缺省权限（bd c4qff 安全收口）：0700 owner-only，与 umask 无关。
/// libc 缺省 = `0777 & ~umask`（umask 0 时裸 0777，本地任意用户可连）；需要跨
/// 用户共享时显式 `/path,0755` 覆盖。
#[cfg(unix)]
const DEFAULT_UNIX_SOCKET_MODE: u32 = 0o700;

/// bind 前的陈旧 socket 判定（bd 45t3k）。
///
/// Go 语义 = bind 撞现存文件报错、仅 Close 时 unlink、从不预删；本仓保留预删是
/// 崩溃残留的运维补偿，但只在「确认无人监听的 socket 文件」时删：
/// - 可连接 → 有活监听（无论谁起的）→ 禁删，报 `AddrInUse`；
/// - `ConnectionRefused` → 监听已死；**但 Linux 对「路径存在而非 socket」同样回
///   ECONNREFUSED**（af_unix unix_find_other），删除前必须 `S_ISSOCK` 复核， 普通文件/symlink
///   一律拒绝；
/// - `NotFound` → 本就无文件；
/// - 其余（EACCES=他人 0700 socket、backlog 满=WoulBlock 等）→ 状态未知不删、 原样上抛。
///
/// 残余窗口：探测→删除→bind 之间有 TOCTOU，本仓多实例由 `.lock` flock 串行化，
/// 非本仓进程的竞态不在本收口范围。
#[cfg(unix)]
fn ensure_stale_or_absent(socket_path: &std::path::Path) -> io::Result<()> {
    use std::os::unix::fs::FileTypeExt;
    match std::os::unix::net::UnixStream::connect(socket_path) {
        Ok(_probe) => Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            format!(
                "unix socket {} is live (connectable); refusing to replace a listening socket",
                socket_path.display()
            ),
        )),
        Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
            // symlink_metadata 不跟随 symlink：symlink 占位 ≠ 我们的 socket 文件。
            match std::fs::symlink_metadata(socket_path) {
                Ok(md) if md.file_type().is_socket() => {
                    std::fs::remove_file(socket_path)?;
                    Ok(())
                },
                Ok(_) => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "{} exists and is not a socket file; refusing to remove it",
                        socket_path.display()
                    ),
                )),
                // 探测期间文件自行消失（无害竞态）→ 直接走后续 bind
                Err(e2) if e2.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(e2) => Err(e2),
            }
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// 记录 UDS 对端凭据（bd c4qff）。Linux/Android 经 SO_PEERCRED 拿 peer
/// uid/pid/gid 记 debug 日志；其余平台无对应接口，显式日志说明不可用。
#[cfg(unix)]
fn log_peer_credentials(stream: &UnixStream) {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use std::os::fd::AsRawFd;
        let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: cred/len 是有效可写缓冲，getsockopt 以 len 为上界写入。
        let ret = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut cred as *mut libc::ucred).cast(),
                &mut len,
            )
        };
        if ret == 0 {
            tracing::debug!(
                pid = cred.pid,
                uid = cred.uid,
                gid = cred.gid,
                "uds peer credentials (SO_PEERCRED)"
            );
        } else {
            tracing::debug!(
                error = %io::Error::last_os_error(),
                "uds peer credentials unavailable: SO_PEERCRED getsockopt failed"
            );
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let _ = stream;
        tracing::debug!(
            "uds peer credentials unavailable: SO_PEERCRED not supported on this platform"
        );
    }
}

#[cfg(unix)]
impl UnixListener {
    /// 绑定 Unix domain socket。对应 Go `DefaultListener.Listen` 的 Unix 分支。
    ///
    /// 地址格式：
    /// - `/path/to/socket` — 普通路径（FileLocker + 陈旧 socket 清理 + 权限）
    /// - `/path/to/socket,0755` — 路径 + 八进制权限（bind 后 chmod）。**缺省 0700 owner-only**（bd
    ///   c4qff，与 umask 无关；Go 缺省 `0777 & ~umask` 在 umask 0 时裸
    ///   0777）。**本地多用户风险**：显式放宽（如 `,0755`）即允许其他本地 用户连接此
    ///   socket，需自行评估
    /// - `@name` — Linux abstract socket（无 FileLocker、**无文件权限位**，任何
    ///   本地进程知道名字即可连接，Go system_listener.go:119）
    /// - `@@name` — abstract socket + haproxy padding（名字零填充到 108 字节， Go
    ///   system_listener.go:121-126）
    ///
    /// # Errors
    /// FileLocker 获取失败 / bind 失败 / 权限设置失败 / abstract 名超长 / 路径被
    /// 活动监听或非 socket 文件占用（bd 45t3k，不偷换）时返回 `io::Error`。
    pub async fn bind(addr: &str, sockopt: SocketOptions) -> io::Result<Self> {
        match parse_unix_addr(addr)? {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            UnixAddrSpec::Abstract(name) => {
                // abstract socket 在独立命名空间，无锁、无文件、无权限设置。
                let inner = TokioUnixListener::from_std(bind_abstract_unix(&name)?)?;
                Ok(Self { inner, sockopt, controllers: Vec::new(), _locker: None })
            },
            #[cfg(not(any(target_os = "linux", target_os = "android")))]
            UnixAddrSpec::Abstract(_) => {
                // parse_unix_addr 非 Linux/Android 不产出 Abstract（'@' 前缀已报
                // InvalidInput）；防御分支仅为匹配完备（CI macos 首跑 E0425 暴露）。
                Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "abstract socket (@) is only supported on Linux/Android",
                ))
            },
            UnixAddrSpec::Path(socket_path, perm) => {
                // normal unix domain socket needs lock
                let mut lk = FileLocker::new(format!("{}.lock", socket_path.display()));
                lk.acquire()?;

                // bd 45t3k：不再无条件预删（旧注释「Go net.ListenUnix 也这样做」
                // 不实——Go 是 bind 撞活文件报 EADDRINUSE、仅在 Close 时 unlink）。
                // 预删作为崩溃残留的运维补偿保留，但收紧为只清「确认无人监听的
                // 陈旧 socket」；活动监听报 AddrInUse，普通文件绝不删。
                ensure_stale_or_absent(&socket_path)?;
                let inner = TokioUnixListener::bind(&socket_path)?;

                // bd c4qff：bind 后固定权限（与 umask 无关）。缺省 0700
                // owner-only；显式 `,mode` 覆盖。abstract socket 无文件权限位，
                // 该面风险已在 bind 文档声明。
                let mode = perm.unwrap_or(DEFAULT_UNIX_SOCKET_MODE);
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(mode))
                        .map_err(|e| io::Error::other(format!("failed to set permission: {e}")))?;
                }
                if perm.is_none() {
                    let mode_str = format!("{mode:o}");
                    tracing::info!(
                        path = %socket_path.display(),
                        mode = %mode_str,
                        "uds socket permission defaulted to owner-only (Go default \
                         0777&~umask is too permissive); append ',mode' (e.g. \
                         /path,0755) to allow other local users, at your own risk"
                    );
                }

                Ok(Self { inner, sockopt, controllers: Vec::new(), _locker: Some(lk) })
            },
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
            log_peer_credentials(&stream);
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
    // 75rv deny(warnings) 隐性回归:仅 linux/android 在 abstract_sockaddr_path 内构造,
    // iOS/其他 unix 平台 dead_code → 抑制 dead_code 警告
    #[allow(dead_code)]
    Abstract(Vec<u8>),
}

/// 计算 Linux abstract unix socket 的 `sun_path` 字节。纯函数，无平台依赖。
///
/// 对应 Go `DefaultListener.Listen` 的 abstract 分支（system_listener.go:119-126）：
/// - `@name` → `\0name`（abstract 命名空间，Go net 把 `@` 转 `\0`）
/// - `@@name` → `\0name` + `\0` 填充到 108 字节（`sizeof(sockaddr_un.sun_path)`， haproxy padding
///   约定）
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
/// - 其他 unix：`@` 前缀 → `InvalidInput`（Go 端 abstract 仅支持 linux/android； Go 在 darwin 会把
///   `@x` 当字面路径走 FileLocker 最终 bind 失败，此处显式报错）
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
        if libc::bind(fd, (&addr as *const libc::sockaddr_un).cast(), addrlen as libc::socklen_t)
            < 0
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
    /// hjtt：两次调用一致 = 进程内缓存（Go net.go:404 listenerBacklogCache 同款）。
    #[test]
    fn effective_listen_backlog_is_cached() {
        let v = effective_listen_backlog();
        assert_eq!(v, effective_listen_backlog(), "backlog lookup must be cached");
    }

    /// 平台生效值对齐 Go maxListenerBacklog：Linux 读 somaxconn（fallback 128）；
    /// Windows = 0x7fffffff；其余 unix fallback = SOMAXCONN（128）。
    #[test]
    fn effective_listen_backlog_matches_go_platform_semantics() {
        let v = effective_listen_backlog();
        #[cfg(target_os = "linux")]
        assert!(v >= 128, "linux must be somaxconn or SOMAXCONN fallback, got {v}");
        #[cfg(windows)]
        assert_eq!(v, 0x7fff_ffff, "windows must be syscall.SOMAXCONN");
        #[cfg(all(not(target_os = "linux"), not(windows)))]
        assert_eq!(v, 128, "non-linux fallback must be syscall.SOMAXCONN");
    }

    /// Go sock_linux.go:18-31 maxAckBacklog：backlog 存储宽度随内核版本
    /// （<4.1 u16 / ≥4.1 u32；版本解析失败 (0,0) 按 u16，同 Go）。
    #[cfg(target_os = "linux")]
    #[test]
    fn max_ack_backlog_clamps_by_kernel_width() {
        assert_eq!(super::max_ack_backlog(65_535, (4, 15)), 65_535);
        assert_eq!(super::max_ack_backlog(65_536, (4, 1)), 65_536); // ≥4.1 u32 宽
        assert_eq!(super::max_ack_backlog(i32::MAX, (5, 10)), i32::MAX);
        assert_eq!(super::max_ack_backlog(65_536, (3, 16)), 65_535); // <4.1 u16 钳
        assert_eq!(super::max_ack_backlog(65_536, (0, 0)), 65_535); // 版本未知按 u16
    }

    /// Go sock_linux.go:36-48 解析段：首字段十进制，0/非数字 → fallback。
    #[cfg(target_os = "linux")]
    #[test]
    fn somaxconn_from_proc_matches_go_parse() {
        assert_eq!(super::somaxconn_from_proc("4096\n"), Some(4096));
        assert_eq!(super::somaxconn_from_proc("  2048  \n"), Some(2048));
        assert_eq!(super::somaxconn_from_proc("0\n"), None);
        assert_eq!(super::somaxconn_from_proc("abc\n"), None);
        assert_eq!(super::somaxconn_from_proc(""), None);
    }

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
    };

    use super::*;

    #[tokio::test]
    async fn default_listener_bind_and_accept() {
        let listener =
            DefaultListener::bind("127.0.0.1:0".parse().unwrap(), SocketOptions::default())
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
        let listener =
            DefaultListener::bind("127.0.0.1:0".parse().unwrap(), SocketOptions::default())
                .await
                .unwrap();
        let addr = listener.local_addr().unwrap();
        assert_eq!(addr.ip().to_string(), "127.0.0.1");
        assert_ne!(addr.port(), 0);
    }

    #[tokio::test]
    async fn inbound_tcp_listener_sets_nodelay_on_accept() {
        // bd e7le：accept 出的连接必须默认 TCP_NODELAY（SocketOptions::default
        // tcp_nodelay=true），helper 层直接断言。
        let listener =
            InboundTcpListener::bind("127.0.0.1:0", SocketOptions::default()).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _peer) = listener.accept().await.expect("accept 失败");
            stream
        });

        let _client = TcpStream::connect(addr).await.unwrap();
        let stream = server.await.unwrap();
        let sock = Socket::from(stream.into_std().unwrap());
        assert!(sock.nodelay().unwrap(), "accepted inbound socket should have TCP_NODELAY set");
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

    /// sockopt.acceptProxyProtocol → DefaultListener 开关端到端（Go
    /// system_listener.go:169-172）：开启时 accept 读掉 PROXY v1 header，
    /// remote_addr 覆盖为声明源地址，应用流从 header 之后开始。
    #[tokio::test]
    async fn sockopt_accept_proxy_protocol_switch_on() {
        use crate::proxy_protocol::build_proxy_header;
        let fake_src: SocketAddr = "198.51.100.17:47211".parse().unwrap();
        let sockopt = SocketOptions { accept_proxy_protocol: true, ..SocketOptions::default() };
        let listener =
            DefaultListener::bind("127.0.0.1:0".parse().unwrap(), sockopt).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let mut conn = listener.accept().await.expect("accept 失败");
            // remote_addr 被 PROXY header 声明源覆盖。
            assert_eq!(conn.remote_addr().unwrap().unwrap(), fake_src);
            // header 被消费，不泄漏进应用流。
            let mut buf = [0u8; 5];
            conn.read_exact(&mut buf).await.expect("read 失败");
            assert_eq!(&buf, b"PING!");
        });

        let mut client = TcpStream::connect(addr).await.expect("connect 失败");
        client.write_all(&build_proxy_header(1, fake_src, addr)).await.unwrap();
        client.write_all(b"PING!").await.unwrap();
        server.await.unwrap();
    }

    /// 默认（sockopt.acceptProxyProtocol=false）：开关关闭，PROXY header 不被
    /// 消费——首读原样拿到 header 字节，remote_addr 仍是真实 TCP peer
    /// （既有行为不回归）。
    #[tokio::test]
    async fn sockopt_accept_proxy_protocol_default_off_keeps_header_in_stream() {
        use crate::proxy_protocol::build_proxy_header;
        let fake_src: SocketAddr = "198.51.100.17:47212".parse().unwrap();
        let listener =
            DefaultListener::bind("127.0.0.1:0".parse().unwrap(), SocketOptions::default())
                .await
                .unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let mut conn = listener.accept().await.expect("accept 失败");
            // remote_addr 是真实 TCP peer（loopback），不是 PROXY 声明源。
            let remote = conn.remote_addr().unwrap().unwrap();
            assert_ne!(remote, fake_src);
            // 首读 = header 原样字节（开关关闭时不消费）。
            let mut buf = [0u8; 6];
            conn.read_exact(&mut buf).await.expect("read 失败");
            assert_eq!(&buf, b"PROXY ");
        });

        let mut client = TcpStream::connect(addr).await.expect("connect 失败");
        client.write_all(&build_proxy_header(1, fake_src, addr)).await.unwrap();
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

        let listener =
            listen_system("127.0.0.1:0".parse().unwrap(), SocketOptions::default()).await.unwrap();
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
        let listener =
            DefaultListener::bind("127.0.0.1:0".parse().unwrap(), SocketOptions::default())
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
            },
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
            },
            other => panic!("expect Path, got {other:?}"),
        }
    }

    /// `@` 前缀：Linux/Android 解析为 Abstract；其他 unix 显式报错
    /// （Windows 无 unix socket，该分支 cfg 掉，走纯函数测试）。
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
    /// （Go system_listener.go:119-126）。
    #[test]
    fn abstract_sockaddr_path_variants() {
        // @name → \0name
        assert_eq!(abstract_sockaddr_path("@name").unwrap(), b"\0name".to_vec());
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
    /// （对齐 Go `SetMultipathTCP` 平台不支持时的行为）；Linux 走 TCP_MPTCP setsockopt
    /// 路径，内核不支持同样回退。两端均断言端到端可用。
    #[tokio::test]
    async fn mptcp_listener_binds_and_accepts() {
        let sockopt = SocketOptions { tcp_mptcp: true, ..Default::default() };
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
        let mut listener =
            DefaultListener::bind("127.0.0.1:0".parse().unwrap(), sockopt).await.unwrap();
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
        let mut listener =
            DefaultListener::bind("127.0.0.1:0".parse().unwrap(), sockopt).await.unwrap();
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

    // ===== bd c4qff / bd 45t3k：UDS 缺省权限 + 预删策略（unix 真跑，WSL 验收）=====

    /// 缺省（无 `,perm`）→ socket 文件 0700 owner-only，与 umask 无关。
    #[cfg(unix)]
    #[tokio::test]
    async fn uds_default_mode_is_owner_only() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("xray_test_uds_mode_{}.sock", std::process::id()));
        let lock = format!("{}.lock", path.display());
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&lock);

        let listener = UnixListener::bind(path.to_str().unwrap(), SocketOptions::default())
            .await
            .expect("bind 失败");
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).expect("stat socket").permissions().mode();
        assert_eq!(mode & 0o777, 0o700, "缺省必须 0700 owner-only（bd c4qff）");
        drop(listener);
        let _ = std::fs::remove_file(&path);
    }

    /// 显式 `,perm` 覆盖仍生效（放宽路径是文档化逃生门，兼容不破坏）。
    #[cfg(unix)]
    #[tokio::test]
    async fn uds_explicit_perm_still_applies() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("xray_test_uds_perm_{}.sock", std::process::id()));
        let lock = format!("{}.lock", path.display());
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&lock);

        let listener =
            UnixListener::bind(&format!("{},0755", path.display()), SocketOptions::default())
                .await
                .expect("bind 失败");
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).expect("stat socket").permissions().mode();
        assert_eq!(mode & 0o777, 0o755, "显式 ,0755 必须生效");
        drop(listener);
        let _ = std::fs::remove_file(&path);
    }

    /// 活动监听占位 → 拒绝（AddrInUse），socket 文件原样保留、原监听不被偷换。
    #[cfg(unix)]
    #[tokio::test]
    async fn uds_bind_refuses_live_listener() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("xray_test_uds_live_{}.sock", std::process::id()));
        let lock = format!("{}.lock", path.display());
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&lock);

        // 真实存活的第三方监听（std，不持我们的 .lock）。
        let live = std::os::unix::net::UnixListener::bind(&path).expect("std bind");

        // UnixListener 未实现 Debug，不能用 expect_err。
        let err = match UnixListener::bind(path.to_str().unwrap(), SocketOptions::default()).await {
            Ok(_) => panic!("活监听必须拒绝（bd 45t3k）"),
            Err(e) => e,
        };
        assert_eq!(err.kind(), io::ErrorKind::AddrInUse);
        assert!(path.exists(), "活动 socket 文件不得被删除");
        assert!(
            std::os::unix::net::UnixStream::connect(&path).is_ok(),
            "原监听必须仍可连接（未被偷换）"
        );

        drop(live);
        let _ = std::fs::remove_file(&path);
    }

    /// 崩溃残留（文件在、监听已死）→ 自动清走并成功绑定（运维补偿保留）。
    #[cfg(unix)]
    #[tokio::test]
    async fn uds_bind_removes_stale_socket() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("xray_test_uds_stale_{}.sock", std::process::id()));
        let lock = format!("{}.lock", path.display());
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&lock);

        // 制造残留：std bind 后直接 drop（std 不 unlink，文件留下、监听已死）。
        {
            let _dead = std::os::unix::net::UnixListener::bind(&path).expect("std bind");
        }
        assert!(path.exists(), "前置：残留文件应存在");

        let listener = UnixListener::bind(path.to_str().unwrap(), SocketOptions::default())
            .await
            .expect("陈旧残留应被清理并成功绑定");
        drop(listener);
        let _ = std::fs::remove_file(&path);
    }

    /// 普通文件占位（非 socket）→ 拒绝且内容原样保留（绝不删非 socket 文件；
    /// Linux 对非 socket 文件 connect 也回 ECONNREFUSED，必须 S_ISSOCK 复核）。
    #[cfg(unix)]
    #[tokio::test]
    async fn uds_bind_refuses_regular_file_placeholder() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("xray_test_uds_reg_{}.sock", std::process::id()));
        let lock = format!("{}.lock", path.display());
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&lock);
        std::fs::write(&path, b"user-data").expect("写占位文件");

        let result = UnixListener::bind(path.to_str().unwrap(), SocketOptions::default()).await;
        assert!(result.is_err(), "普通文件占位必须拒绝");
        assert_eq!(
            std::fs::read(&path).expect("读回").as_slice(),
            b"user-data",
            "占位文件不得被删/截断（bd 45t3k 安全收口）"
        );
        let _ = std::fs::remove_file(&path);
    }
}

/// inbound `finalmask.tcp`（bd dppv）：`accept_masked` 的落位与对称性。
#[cfg(test)]
mod tcpmask_tests {
    use sha2::{Digest, Sha256};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
    };

    use super::*;
    use crate::finalmask::{AsyncIo, TcpmaskManager, build_tcpmask_manager_from_json};

    fn manager(json: serde_json::Value) -> Arc<TcpmaskManager> {
        Arc::new(build_tcpmask_manager_from_json(Some(&json)).expect("mask 构建"))
    }

    fn sudoku() -> Arc<TcpmaskManager> {
        manager(serde_json::json!({"tcp": [{"type": "sudoku", "settings": {}}]}))
    }

    fn xmc() -> Arc<TcpmaskManager> {
        manager(serde_json::json!({"tcp": [{"type": "xmc", "settings": {
            "password": "night-run-shared-secret",
            "hostname": "localhost",
            "profiles": [{
                "username": "NightRunner",
                "uuid": "b3f5d0e0-1111-4222-8333-444455556666",
                "texturesValue": "textures-value",
                "texturesSignature": "textures-signature"
            }]
        }}]}))
    }

    fn payload(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    fn sha256(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    /// 配了 finalmask → `accept_masked` 返回 `Masked`；裸 TCP 入站与客户端
    /// 同一 mask 链对打 131072B 双向回显，sha256 一致。
    async fn roundtrip_131072(mask: Arc<TcpmaskManager>) {
        let listener = InboundTcpListener::bind("127.0.0.1:0", SocketOptions::default())
            .await
            .expect("bind")
            .with_tcpmask_manager(Some(Arc::clone(&mask)));
        let addr = listener.local_addr().expect("local_addr");

        let data = payload(131_072);
        let expect = data.clone();
        let server = tokio::spawn(async move {
            let (mut conn, _peer) = listener.accept_masked().await.expect("accept_masked");
            assert!(conn.plain().is_none(), "配了 finalmask 必须走 Masked");
            let mut buf = vec![0u8; expect.len()];
            conn.read_exact(&mut buf).await.expect("server read");
            assert_eq!(sha256(&buf), sha256(&expect), "server 侧 sha256 必须一致");
            conn.write_all(&buf).await.expect("server echo");
            conn.shutdown().await.expect("server shutdown");
        });

        // 客户端侧同一 mask 链（xray-transport-tcp dialer 同款 client 包装）。
        let raw = TcpStream::connect(addr).await.expect("connect");
        let raw: Box<dyn AsyncIo> = Box::new(raw);
        let mut client = mask.wrap_conn_client(raw).expect("client mask");
        client.write_all(&data).await.expect("client write");
        let mut got = vec![0u8; data.len()];
        client.read_exact(&mut got).await.expect("client read");
        assert_eq!(sha256(&got), sha256(&data), "客户端 131072B 回显 sha256 必须一致");
        server.await.expect("server task");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn inbound_mask_roundtrip_sudoku_131072() {
        roundtrip_131072(sudoku()).await;
    }

    /// 互通：tcp + xmc（生产形态的 padding 未关）131072B 双向。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn inbound_mask_roundtrip_xmc_131072() {
        tokio::time::timeout(std::time::Duration::from_secs(60), roundtrip_131072(xmc()))
            .await
            .expect("xmc 互通超时（mask 握手或 padding 卡住）");
    }

    /// 反证一：未配 finalmask → `Plain` 直通，明文原样到达（零行为变化）。
    #[tokio::test]
    async fn unmasked_inbound_passes_plaintext_through() {
        let listener =
            InboundTcpListener::bind("127.0.0.1:0", SocketOptions::default()).await.expect("bind");
        assert!(listener.tcpmask_manager().is_none());
        let addr = listener.local_addr().expect("local_addr");

        let server = tokio::spawn(async move {
            let (mut conn, _peer) = listener.accept_masked().await.expect("accept_masked");
            assert!(conn.plain().is_some(), "未配 finalmask 必须走 Plain");
            let mut buf = [0u8; 14];
            conn.read_exact(&mut buf).await.expect("server read");
            assert_eq!(&buf, b"vless-header!!");
        });

        let mut client = TcpStream::connect(addr).await.expect("connect");
        client.write_all(b"vless-header!!").await.expect("client write");
        server.await.expect("server task");
    }

    /// 反证二：配了 finalmask 时，未伪装的明文不会被原样还原（证明 mask 真的
    /// 在解伪装，不是 no-op 直通）。
    #[tokio::test]
    async fn masked_inbound_does_not_pass_plaintext_through() {
        let listener = InboundTcpListener::bind("127.0.0.1:0", SocketOptions::default())
            .await
            .expect("bind")
            .with_tcpmask_manager(Some(sudoku()));
        let addr = listener.local_addr().expect("local_addr");

        let plaintext = b"vless-header!!".to_vec();
        let expect_len = plaintext.len();
        let expect = plaintext.clone();
        let server = tokio::spawn(async move {
            let (mut conn, _peer) = listener.accept_masked().await.expect("accept_masked");
            assert!(conn.plain().is_none());
            let mut buf = vec![0u8; expect_len];
            // sudoku 每个明文字节解出 4 字节编码，读不满即视为「未原样还原」。
            let n = tokio::time::timeout(std::time::Duration::from_secs(2), conn.read(&mut buf))
                .await
                .expect("read 超时")
                .expect("read");
            assert_ne!(&buf[..n], &expect[..], "明文不得原样穿过 mask 入站");
        });

        let mut client = TcpStream::connect(addr).await.expect("connect");
        client.write_all(&plaintext).await.expect("client write");
        let _ = client.shutdown().await;
        server.await.expect("server task");
    }
}
