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
//! - redirect 已实现（bd enk，[`set_dialer_proxy_hook`]，DialerProxy）
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
            // 域名解析：Domain → IP（tokio lookup_host，使用系统 DNS）
            let dest_addr = match destination_to_socket_addr(destination) {
                Ok(addr) => addr,
                Err(_) => {
                    // Domain 地址：tokio DNS 解析
                    let port = destination.port().value();
                    let host = match destination.address() {
                        xray_common::net::address::Address::Domain(d) => d.as_str(),
                        other => {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidInput,
                                format!("unsupported address type for dial: {other:?}"),
                            ));
                        }
                    };
                    let mut socket_addrs = tokio::net::lookup_host((host, port)).await?;
                    socket_addrs.next().ok_or_else(|| {
                        io::Error::new(io::ErrorKind::NotFound, format!("DNS resolve failed: {host}"))
                    })?
                }
            };
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

/// sendThrough 源地址规格。对应 Go `proxyman.SenderConfig` 的 `Via`/`ViaCidr`
/// （infra/conf/xray.go:287-301 解析）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendThroughSpec {
    /// 固定源 IP（Go `Via` 为 IP 地址）。
    Fixed(IpAddr),
    /// CIDR 内随机源 IP（Go `ViaCidr`，拨号时 `ParseRandomIP` 取址）。
    Cidr { base: IpAddr, prefix: u8 },
    /// "origin"：入站本地 IP。
    ///
    /// ponytail: DialFn 链无 inbound 会话上下文，resolve 恒 None（等价 Go
    /// inbound 无效时不设 Gateway 的分支，handler.go:337-342）；
    /// 接入会话上下文时在此取 inbound.Local.Address。
    Origin,
    /// "srcip"：入站客户端源 IP（同 Origin 的 ponytail 边界）。
    SrcIp,
}

impl SendThroughSpec {
    /// 解析为本次拨号使用的源 IP；`None` 表示不 bind。
    #[must_use]
    pub fn resolve(&self) -> Option<IpAddr> {
        match *self {
            Self::Fixed(ip) => Some(ip),
            Self::Cidr { base, prefix } => random_ip_in_cidr(base, prefix),
            Self::Origin | Self::SrcIp => None,
        }
    }
}

/// CIDR 内随机取一 IP。对齐 Go `ParseRandomIP`（app/proxyman/outbound/handler.go:400-418）：
/// 网络地址 + [0, 2^(bits-ones)) 随机偏移（不排除网络/广播地址，与 Go 一致）。
fn random_ip_in_cidr(base: IpAddr, prefix: u8) -> Option<IpAddr> {
    match base {
        IpAddr::V4(v4) if prefix <= 32 => {
            let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
            let size = 1u64 << (32 - prefix);
            let offset = rand::random::<u32>() as u64 % size;
            let ip = (u32::from(v4) & mask) as u64 + offset;
            Some(IpAddr::V4(std::net::Ipv4Addr::from(ip as u32)))
        }
        IpAddr::V6(v6) if prefix <= 128 => {
            let shift = 128 - prefix;
            let mask = if shift >= 128 { 0 } else { u128::MAX << shift };
            let network = u128::from(v6) & mask;
            let size: u128 = 1u128.checked_shl(u32::try_from(shift).ok()?).unwrap_or(0);
            let offset = if size == 0 {
                rand::random::<u128>()
            } else {
                rand::random::<u128>() % size
            };
            Some(IpAddr::V6(std::net::Ipv6Addr::from(network + offset)))
        }
        _ => None,
    }
}

tokio::task_local! {
    /// 本次拨号的源 IP。对应 Go `session.Outbound.Gateway`（Handler.Dial 由
    /// SenderConfig.Via 设置）经 `DialSystem` 传给 system dialer 的 `src`。
    pub static DIAL_SRC: Option<IpAddr>;
}

/// DialerProxy 拨号钩子：`(tag, dest) → 经 tag outbound handler 建立的连接`。
///
/// 对应 Go `transport/internet/dialer.go:270-279`——`DialSystem` 遇到
/// `sockopt.DialerProxy` 时经 outbound manager 查 handler 并 `redirect`
/// （pipe + `h.Dispatch`，dialer.go:111-136）。本 crate 不能依赖 dispatcher
/// （依赖反向），故由 xray-core 启动时注入实现（回调注入 trait 模式）。
pub type DialerProxyHook = Arc<
    dyn Fn(&str, &Destination) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn Connection>>> + Send>>
        + Send
        + Sync,
>;

static DIALER_PROXY_HOOK: std::sync::RwLock<Option<DialerProxyHook>> =
    std::sync::RwLock::new(None);

/// 注册全局 DialerProxy 钩子（xray-core `register_outbounds` 调用）。
pub fn set_dialer_proxy_hook(hook: DialerProxyHook) {
    *DIALER_PROXY_HOOK.write().expect("DIALER_PROXY_HOOK lock poisoned") = Some(hook);
}

/// 清除钩子（测试隔离用）。
pub fn clear_dialer_proxy_hook() {
    *DIALER_PROXY_HOOK.write().expect("DIALER_PROXY_HOOK lock poisoned") = None;
}

/// 系统拨号。对应 Go `dialer.go::DialSystem`。
///
/// `sockopt.dialer_proxy` 非空时经 [`DIALER_PROXY_HOOK`] 重定向（bd enk）。
/// DNS/SRV/TXT/HappyEyeballs 仍留切片2。
///
/// # 参数
///
/// - `destination`：目标地址。切片1 要求是 IP（非 Domain），Domain 解析留切片2。
/// - `sockopt`：socket 选项（含 `dialer_proxy`）。
pub async fn dial_system(
    destination: &Destination,
    sockopt: &SocketOptions,
) -> io::Result<Box<dyn Connection>> {
    // DialerProxy（bd enk）：对应 Go dialer.go:270-279——非空时不直连，经指定
    // tag 的 outbound handler 拨号（redirect）。src/DIAL_SRC 不参与（对齐
    // Go dialer.go:233-235 `len(sockopt.DialerProxy) == 0` 才取 ob.Gateway）。
    if !sockopt.dialer_proxy.is_empty() {
        let hook = DIALER_PROXY_HOOK
            .read()
            .expect("DIALER_PROXY_HOOK lock poisoned")
            .clone();
        let Some(hook) = hook else {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "there is no outbound manager for dialerProxy",
            ));
        };
        return hook(&sockopt.dialer_proxy, destination).await;
    }
    // ponytail: clone Arc 后 drop guard，避免 RwLockReadGuard 跨 await 点
    // （否则 future 不是 Send，无法用于 async_trait 的 OutboundHandler::dial）。
    let dialer = {
        let guard = effective().read();
        Arc::clone(&*guard)
    };
    // sendThrough 源地址：对应 Go DialSystem 的 `src = ob.Gateway`
    // （dialer.go:228-235）+ `resolveSrcAddr` 端口 0（system_dialer.go:33-46）。
    // task-local 由上层 dial_fn 包装层建立（等价 Go Handler.Dial 设 ob.Gateway）。
    let src = DIAL_SRC
        .try_with(|v| *v)
        .ok()
        .flatten()
        .map(|ip| SocketAddr::new(ip, 0));
    dialer.dial(src, destination, sockopt).await
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
    async fn default_dialer_resolves_domain_address() {
        // 域名不再被拒绝——dialer 会尝试 tokio DNS 解析。
        // 在无网环境中解析可能失败（NotFound），但不应该是 InvalidInput "domain not supported"。
        let dest = Destination::tcp(Address::new_domain("nonexistent.invalid"), Port::new(80));
        let sockopt = SocketOptions::default();
        let dialer = DefaultSystemDialer::new();
        let result = dialer.dial(None, &dest, &sockopt).await;
        match result {
            Err(err) => {
                // .invalid 域名 DNS 解析必失败，但错误不应是 InvalidInput（domain rejected）
                assert_ne!(err.kind(), io::ErrorKind::InvalidInput, "domain should not be rejected");
            }
            Ok(conn) => { drop(conn); }
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

    #[test]
    fn send_through_spec_resolve_forms() {
        let fixed: IpAddr = "192.168.1.5".parse().unwrap();
        assert_eq!(SendThroughSpec::Fixed(fixed).resolve(), Some(fixed));
        // origin/srcip 无会话上下文 → 不 bind（等价 Go inbound 无效分支）
        assert_eq!(SendThroughSpec::Origin.resolve(), None);
        assert_eq!(SendThroughSpec::SrcIp.resolve(), None);
    }

    #[test]
    fn send_through_spec_cidr_random_within_subnet() {
        let base: IpAddr = "10.0.0.0".parse().unwrap();
        for _ in 0..64 {
            let ip = SendThroughSpec::Cidr { base, prefix: 24 }.resolve().unwrap();
            let o = match ip {
                IpAddr::V4(v4) => v4.octets(),
                _ => panic!("cidr base v4 should resolve v4"),
            };
            assert_eq!(&o[..3], &[10, 0, 0][..], "10.0.0.0/24 内：{ip}");
        }
        let base6: IpAddr = "fd00::".parse().unwrap();
        let ip6 = SendThroughSpec::Cidr { base: base6, prefix: 120 }.resolve().unwrap();
        assert!(ip6.is_ipv6());
        // 非法前缀 → None
        assert_eq!(random_ip_in_cidr(base, 33), None);
        assert_eq!(random_ip_in_cidr(base6, 129), None);
    }

    /// bd 7zc：DIAL_SRC scope 内 dial_system 以指定源 IP bind（对齐 Go
    /// system_dialer.go:103-110 dialer.LocalAddr）。127.0.0.2 是 loopback /8
    /// 内非默认源——未生效时 OS 默认源是 127.0.0.1，断言有区分度。
    #[tokio::test]
    async fn dial_system_binds_dial_src_as_source_ip() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let peer_ip = Arc::new(parking_lot::Mutex::new(None::<IpAddr>));
        let recorder = Arc::clone(&peer_ip);
        let accept_task = tokio::spawn(async move {
            let (_sock, peer) = listener.accept().await.unwrap();
            *recorder.lock() = Some(peer.ip());
        });
        let dest = localhost_dest(addr.port());
        let sockopt = SocketOptions::default();
        let src: IpAddr = "127.0.0.2".parse().unwrap();
        let conn = DIAL_SRC
            .scope(Some(src), dial_system(&dest, &sockopt))
            .await
            .expect("dial with DIAL_SRC should succeed");
        drop(conn);
        accept_task.await.unwrap();
        assert_eq!(*peer_ip.lock(), Some(src));
    }

    /// bd 7zc：源地址族与目标不符 → 拨号错误（对齐 Go net.Dialer 在
    /// LocalAddr bind 失败时直接返回错误，不静默回退）。环境无 IPv6
    /// loopback 时跳过。
    #[tokio::test]
    async fn dial_system_family_mismatch_v4_src_v6_dest_fails() {
        let listener = match tokio::net::TcpListener::bind("[::1]:0").await {
            Ok(l) => l,
            Err(_) => return,
        };
        let addr = listener.local_addr().unwrap();
        let _accept = tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let dest = Destination::tcp(
            xray_common::net::address::Address::IPv6(std::net::Ipv6Addr::LOCALHOST),
            Port::new(addr.port()),
        );
        let sockopt = SocketOptions::default();
        let v4_src: IpAddr = "127.0.0.2".parse().unwrap();
        let result = DIAL_SRC
            .scope(Some(v4_src), dial_system(&dest, &sockopt))
            .await;
        assert!(result.is_err(), "v4 源 + v6 目标应拨号失败（对齐 Go）");
    }

    // ===== DialerProxy（bd enk）=====

    /// 钩子测试共享锁：全局静态钩子需要串行设置/清除。
    static HOOK_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    /// dialerProxy 设置但无钩子（无 outbound manager）→ 报错（Go dialer.go:271-272）。
    #[tokio::test]
    async fn dial_system_dialer_proxy_without_hook_errors() {
        let _guard = HOOK_TEST_LOCK.lock();
        clear_dialer_proxy_hook();
        let mut sockopt = SocketOptions::default();
        sockopt.dialer_proxy = "proxy-out".into();
        let dest = Destination::tcp(
            xray_common::net::address::Address::from_ipv4_bytes([127, 0, 0, 1]),
            xray_common::net::port::Port::new(1),
        );
        let err = match dial_system(&dest, &sockopt).await {
            Err(e) => e,
            Ok(_) => panic!("dialerProxy without hook should fail"),
        };
        assert!(
            err.to_string().contains("no outbound manager"),
            "unexpected error: {err}"
        );
    }

    /// dialerProxy 设置 + 钩子 → 连接经钩子建立（tag 透传，Go dialer.go:274-278）。
    #[tokio::test]
    async fn dial_system_dialer_proxy_routes_via_hook() {
        use std::sync::Arc as StdArc;
        let _guard = HOOK_TEST_LOCK.lock();
        let seen: StdArc<parking_lot::Mutex<Vec<(String, u16)>>> =
            StdArc::new(parking_lot::Mutex::new(Vec::new()));
        let seen_hook = Arc::clone(&seen);
        set_dialer_proxy_hook(Arc::new(move |tag: &str, dest: &Destination| {
            let tag = tag.to_string();
            let port = dest.port().value();
            let seen = Arc::clone(&seen_hook);
            Box::pin(async move {
                seen.lock().push((tag, port));
                let (client, _server) = tokio::io::duplex(64);
                Ok(Box::new(crate::connection::DuplexConnection::new(client))
                    as Box<dyn Connection>)
            })
        }));
        let mut sockopt = SocketOptions::default();
        sockopt.dialer_proxy = "socks-out".into();
        let dest = Destination::tcp(
            xray_common::net::address::Address::from_ipv4_bytes([127, 0, 0, 1]),
            xray_common::net::port::Port::new(8080),
        );
        let conn = dial_system(&dest, &sockopt).await.expect("hook dial ok");
        drop(conn);
        assert_eq!(
            seen.lock().as_slice(),
            &[("socks-out".to_string(), 8080)],
            "hook should receive tag and dest"
        );
        clear_dialer_proxy_hook();
    }
}

/// DNS 解析系统拨号器——在 DefaultSystemDialer 前增加 DNS 解析能力。
///
/// 当目标地址为 Domain 时，使用 `tokio::net::lookup_host` 解析为 IP，
/// 再委托给 DefaultSystemDialer 拨号。对应 Go `InitSystemDialer` 的 DNS 解析部分。
pub struct DnsResolvingDialer {
    inner: DefaultSystemDialer,
}

impl DnsResolvingDialer {
    /// 构造 DNS 解析拨号器。
    #[must_use]
    pub fn new() -> Self {
        Self { inner: DefaultSystemDialer::new() }
    }
}

impl SystemDialer for DnsResolvingDialer {
    fn dial<'a>(
        &'a self,
        src: Option<SocketAddr>,
        destination: &'a Destination,
        sockopt: &'a SocketOptions,
    ) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn Connection>>> + Send + 'a>> {
        Box::pin(async move {
            match destination.address() {
                xray_common::net::address::Address::Domain(domain) => {
                    let port = destination.port().value();
                    let lookup = format!("{domain}:{port}");
                    tracing::debug!(target = %lookup, "resolving domain via system DNS");
                    match tokio::net::lookup_host(&lookup).await {
                        Ok(mut addrs) => {
                            if let Some(resolved) = addrs.next() {
                                tracing::debug!(target = %lookup, resolved = %resolved, "domain resolved");
                                let ip_dest = Destination::tcp(
                                    xray_common::net::address::Address::from(resolved.ip()),
                                    destination.port(),
                                );
                                self.inner.dial(src, &ip_dest, sockopt).await
                            } else {
                                Err(io::Error::new(
                                    io::ErrorKind::AddrNotAvailable,
                                    format!("DNS lookup returned no addresses for {domain}"),
                                ))
                            }
                        }
                        Err(e) => {
                            tracing::warn!(target = %domain, error = %e, "DNS lookup failed");
                            Err(io::Error::new(
                                io::ErrorKind::AddrNotAvailable,
                                format!("DNS lookup failed for {domain}: {e}"),
                            ))
                        }
                    }
                }
                _ => self.inner.dial(src, destination, sockopt).await,
            }
        })
    }
}

/// 初始化系统拨号器：安装 DNS 解析能力。对应 Go `InitSystemDialer`。
///
/// 首次调用时将全局 effective dialer 替换为 [`DnsResolvingDialer`]。
/// 后续调用幂等（不会重复包装）。
pub fn init_system_dialer() {
    use_alternative_system_dialer(Some(Box::new(DnsResolvingDialer::new())));
    tracing::info!("system dialer initialized with DNS resolution");
}
