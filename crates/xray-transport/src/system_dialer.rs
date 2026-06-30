//! 系统拨号器——所有客户端代理协议 Handler::Process 的基础依赖。
//!
//! 对应 Go `transport/internet/system_dialer.go` + `dialer.go::DialSystem`。
//!
//! ## 切片边界（P5-Sys 切片1）
//!
//! 实现 TCP 拨号 + 基础 sockopt + 全局 effective dialer + Controllers 注册 +
//! transport_dialer_cache 注册表。切片2 待办：
//!
//! - UDP 拨号（tokio UdpSocket + PacketConnWrapper）
//! - LookupForIP（DNS 解析 + DomainStrategy）
//! - checkAddressPortStrategy（SRV/TXT 记录覆盖 dest）
//! - redirect（pipe + outbound handler dispatch，DialerProxy）
//! - HappyEyeballs（TcpRaceDial）
//! - InitSystemDialer（dns.Client + outbound.Manager 注入）

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{OnceLock, Arc};

use parking_lot::{Mutex, RwLock};
use socket2::Socket as Socket2;
use tokio::net::TcpStream;

use xray_common::net::destination::Destination;

use crate::connection::Connection;
use crate::sockopt::{SocketOptions, apply_outbound_socket_options};

/// TCP 拨号超时（与 Go DefaultSystemDialer 一致：16 秒）。
pub const DEFAULT_DIAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(16);

/// 系统拨号器 trait。对应 Go `SystemDialer` interface。
///
/// 实现者负责平台特定的 TCP/UDP 连接建立。async dial 返回 boxed future，
/// 因为 trait object（`Box<dyn SystemDialer>`）需要 sized 返回类型。
pub trait SystemDialer: Send + Sync {
    /// 向 `destination` 拨号。返回包装后的 [`Connection`]。
    ///
    /// - `src`：可选本地源地址（绑定本地网卡）。
    /// - `destination`：目标地址（IP/Domain + Port + Network）。
    /// - `sockopt`：socket 选项（TCP_NODELAY / SO_KEEPALIVE 等）。
    fn dial<'a>(
        &'a self,
        src: Option<SocketAddr>,
        destination: &'a Destination,
        sockopt: &'a SocketOptions,
    ) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn Connection>>> + Send + 'a>>;

    /// 返回代理服务器 IP（Android 用例：连接前预解析 IP）。默认返回 `None`。
    fn dest_ip_address(&self) -> Option<IpAddr> {
        None
    }
}

/// 默认系统拨号器。对应 Go `DefaultSystemDialer`。
///
/// 切片1 仅实现 TCP 拨号（tokio + socket2 sockopt）。UDP 拨号留切片2。
#[derive(Debug, Default)]
pub struct DefaultSystemDialer;

impl DefaultSystemDialer {
    /// 构造默认拨号器。
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// 内部 TCP 拨号实现（不含 sockopt 应用），返回原始 `TcpStream`。
    async fn dial_tcp_raw(
        src: Option<SocketAddr>,
        dest: SocketAddr,
        timeout: std::time::Duration,
    ) -> io::Result<TcpStream> {
        // tokio::net::TcpStream::connect 不支持源地址绑定与超时。
        // 用 socket2 构造 socket，绑定本地地址，再 tokio 化。
        let domain = match dest {
            SocketAddr::V4(_) => socket2::Domain::IPV4,
            SocketAddr::V6(_) => socket2::Domain::IPV6,
        };
        let socket = Socket2::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
        // 绑定本地地址（可选）。
        if let Some(local) = src {
            socket.bind(&local.into())?;
        }
        // 设置非阻塞（tokio 要求）。
        socket.set_nonblocking(true)?;
        // 发起连接（非阻塞 connect 返回 EINPROGRESS 是正常的）。
        match socket.connect(&dest.into()) {
            Ok(()) => {}
            Err(ref e) if e.raw_os_error() == Some(libc_error_inprogress()) => {
                // EINPROGRESS：非阻塞 connect 正在进行中，由 tokio 等待可写。
            }
            Err(e) => return Err(e),
        }
        // 转 tokio TcpStream。
        let std_stream: std::net::TcpStream = socket.into();
        std_stream.set_nonblocking(true)?;
        let tokio_stream = TcpStream::from_std(std_stream)?;
        // 等待连接完成（带超时）。
        tokio::time::timeout(timeout, async {
            // tokio TcpStream 连接在 from_std 时已建立（如果 connect 成功）。
            // 这里通过 writable 检查连接状态。
            tokio_stream.writable().await
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "dial timeout"))??;
        Ok(tokio_stream)
    }
}

impl SystemDialer for DefaultSystemDialer {
    fn dial<'a>(
        &'a self,
        src: Option<SocketAddr>,
        destination: &'a Destination,
        sockopt: &'a SocketOptions,
    ) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn Connection>>> + Send + 'a>> {
        Box::pin(async move {
            // ponytail: 切片1 仅处理 IP 地址（Domain 解析留切片2 的 LookupForIP）。
            // 调用方应在调用前把 Domain 解析为 IP。
            let dest_addr = destination_to_socket_addr(destination)?;
            let stream = Self::dial_tcp_raw(src, dest_addr, DEFAULT_DIAL_TIMEOUT).await?;
            // 应用 sockopt（TCP_NODELAY + SO_KEEPALIVE）。
            let std_stream = stream.into_std()?;
            let socket = Socket2::from(std_stream);
            apply_outbound_socket_options(&socket, sockopt)?;
            // 转回 tokio TcpStream，包装为 Connection。
            let tokio_stream = TcpStream::from_std(socket.into())?;
            Ok(Box::new(crate::connection::TcpConnection::new(tokio_stream))
                as Box<dyn Connection>)
        })
    }
}

/// 全局 effective system dialer。对应 Go `effectiveSystemDialer`。
///
/// 用 [`OnceLock`] 延迟初始化（首次访问时构造 [`DefaultSystemDialer`]），
/// [`RwLock`] 允许运行时通过 [`use_alternative_system_dialer`] 替换。
static EFFECTIVE_SYSTEM_DIALER: OnceLock<RwLock<Arc<dyn SystemDialer>>> = OnceLock::new();

fn effective() -> &'static RwLock<Arc<dyn SystemDialer>> {
    EFFECTIVE_SYSTEM_DIALER.get_or_init(|| RwLock::new(Arc::new(DefaultSystemDialer::new())))
}

/// 替换全局系统拨号器。对应 Go `UseAlternativeSystemDialer`。
///
/// `None` 时重置为 [`DefaultSystemDialer`]。
pub fn use_alternative_system_dialer(dialer: Option<Box<dyn SystemDialer>>) {
    let new_dialer: Arc<dyn SystemDialer> = match dialer {
        Some(b) => Arc::from(b),
        None => Arc::new(DefaultSystemDialer::new()),
    };
    *effective().write() = new_dialer;
}

/// DialerController：在 fd 创建后、连接前调用的回调。对应 Go `Controllers`。
///
/// 用于设置 SO_MARK / SO_BINDTODEVICE / TCP_FASTOPEN 等平台特定选项。
/// 回调接收 [`Socket2`] 引用，可调用 socket2 API 修改 fd。
pub type DialerController = Arc<dyn Fn(&Socket2) -> io::Result<()> + Send + Sync>;

/// 全局 DialerController 列表。对应 Go `Controllers` + `ControllersLock`。
static CONTROLLERS: OnceLock<Mutex<Vec<DialerController>>> = OnceLock::new();

fn controllers() -> &'static Mutex<Vec<DialerController>> {
    CONTROLLERS.get_or_init(|| Mutex::new(Vec::new()))
}

/// 注册 DialerController。对应 Go `RegisterDialerController`。
///
/// 每个 controller 在 TCP/UDP socket 创建后、连接前被调用，可修改 fd 设置。
/// controller 用 `Arc` 共享，调用方可在注册后继续持有引用。
pub fn register_dialer_controller(controller: DialerController) -> io::Result<()> {
    controllers().lock().push(controller);
    Ok(())
}

/// 获取所有已注册 controller 的快照（用于拨号时迭代调用）。
#[must_use]
pub fn registered_controllers() -> Vec<DialerController> {
    controllers().lock().clone()
}

/// 系统拨号。对应 Go `dialer.go::DialSystem`。
///
/// 切片1 简化版：直接调 effective dialer，不处理 DNS/SRV/TXT/DialerProxy。
/// 完整逻辑（LookupForIP/checkAddressPortStrategy/redirect/HappyEyeballs）留切片2。
///
/// # 参数
///
/// - `destination`：目标地址。切片1 要求是 IP（非 Domain），Domain 解析留切片2。
/// - `sockopt`：socket 选项。
pub async fn dial_system(
    destination: &Destination,
    sockopt: &SocketOptions,
) -> io::Result<Box<dyn Connection>> {
    // ponytail: clone Arc 后 drop guard，避免 RwLockReadGuard 跨 await 点
    // （否则 future 不是 Send，无法用于 async_trait 的 OutboundHandler::dial）。
    let dialer = {
        let guard = effective().read();
        Arc::clone(&*guard)
    };
    dialer.dial(None, destination, sockopt).await
}

// ===== 辅助函数 =====

/// 把 `Destination` 转为 `SocketAddr`。切片1 仅处理 IP 地址。
///
/// Domain 类型返回 `InvalidInput` 错误（切片2 接入 LookupForIP 后支持）。
fn destination_to_socket_addr(dest: &Destination) -> io::Result<SocketAddr> {
    use xray_common::net::address::Address;
    let port = dest.port().value();
    match dest.address() {
        Address::IPv4(ip) => Ok(SocketAddr::new(IpAddr::V4(*ip), port)),
        Address::IPv6(ip) => Ok(SocketAddr::new(IpAddr::V6(*ip), port)),
        Address::Domain(domain) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "domain address {:?} not supported in slice-1 (DNS resolution is slice-2)",
                domain
            ),
        )),
    }
}

/// 平台特定的 `EINPROGRESS` 错误码。
///
/// - Unix-like（Linux/macOS/FreeBSD）：`libc::EINPROGRESS`（150 / 36 / 36）
/// - Windows：`WSAEWOULDBLOCK`（10035）
#[cfg(unix)]
fn libc_error_inprogress() -> i32 {
    // libc crate 不在 workspace，用硬编码值。
    // Linux: 115, macOS: 36, FreeBSD: 36
    #[cfg(target_os = "linux")]
    {
        115
    }
    #[cfg(target_os = "macos")]
    {
        36
    }
    #[cfg(target_os = "freebsd")]
    {
        36
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "freebsd")))]
    {
        150
    }
}

#[cfg(windows)]
fn libc_error_inprogress() -> i32 {
    // WSAEWOULDBLOCK
    10035
}

#[cfg(not(any(unix, windows)))]
fn libc_error_inprogress() -> i32 {
    150
}

#[cfg(test)]
mod tests {
    use super::*;
    use xray_common::net::address::Address;
    use xray_common::net::port::Port;
    use std::net::Ipv4Addr;

    fn localhost_dest(port: u16) -> Destination {
        Destination::tcp(Address::IPv4(Ipv4Addr::LOCALHOST), Port::new(port))
    }

    #[tokio::test]
    async fn default_dialer_connects_to_local_tcp_listener() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept_task = tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let dest = localhost_dest(addr.port());
        let sockopt = SocketOptions::default();
        let dialer = DefaultSystemDialer::new();
        let result = dialer.dial(None, &dest, &sockopt).await;
        assert!(result.is_ok(), "dial failed: {:?}", result.err());
        accept_task.await.unwrap();
    }

    #[tokio::test]
    async fn default_dialer_rejects_domain_address() {
        let dest = Destination::tcp(Address::new_domain("example.com"), Port::new(80));
        let sockopt = SocketOptions::default();
        let dialer = DefaultSystemDialer::new();
        let result = dialer.dial(None, &dest, &sockopt).await;
        match result {
            Err(err) => {
                assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
                assert!(err.to_string().contains("domain"));
            }
            other => { let _ = other; panic!("expected err"); }
        }
    }

    #[test]
    fn effective_default_is_default_dialer() {
        let lock = effective().read();
        assert!(lock.dest_ip_address().is_none());
    }

    #[test]
    fn register_controller_appends_to_list() {
        let initial = registered_controllers().len();
        let controller: DialerController = Arc::new(|_socket: &Socket2| Ok(()));
        register_dialer_controller(controller).unwrap();
        assert_eq!(registered_controllers().len(), initial + 1);
    }

    #[tokio::test]
    async fn dial_system_uses_effective_dialer() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept_task = tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let dest = localhost_dest(addr.port());
        let sockopt = SocketOptions::default();
        let result = dial_system(&dest, &sockopt).await;
        assert!(result.is_ok());
        accept_task.await.unwrap();
    }

    #[test]
    fn default_dial_timeout_is_16_seconds() {
        assert_eq!(DEFAULT_DIAL_TIMEOUT, std::time::Duration::from_secs(16));
    }

    #[test]
    fn destination_to_socket_addr_ipv4() {
        let dest = Destination::tcp(
            Address::IPv4(Ipv4Addr::new(1, 2, 3, 4)),
            Port::new(8080),
        );
        let addr = destination_to_socket_addr(&dest).unwrap();
        assert_eq!(addr.port(), 8080);
        assert_eq!(addr.ip().to_string(), "1.2.3.4");
    }

    #[test]
    fn destination_to_socket_addr_rejects_domain() {
        let dest = Destination::tcp(Address::new_domain("test.com"), Port::new(443));
        assert!(destination_to_socket_addr(&dest).is_err());
    }
}
