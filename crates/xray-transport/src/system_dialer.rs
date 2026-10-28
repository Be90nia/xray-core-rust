//! 系统拨号器——所有客户端代理协议 Handler::Process 的基础依赖。
//!
//! 对应 Go `transport/internet/system_dialer.go` + `dialer.go::DialSystem`。
//!
//! ## 切片边界（P5-Sys 切片1 + 后续批次）
//!
//! 实现 TCP 拨号 + 基础 sockopt + 全局 effective dialer + Controllers 注册 +
//! transport_dialer_cache 注册表 + redirect/DialerProxy（bd enk，
//! [`set_dialer_proxy_hook`]）+ Happy Eyeballs 竞争拨号（bd 0ko，
//! [`crate::happy_eyeballs`]）+ LookupForIP/checkAddressPortStrategy/
//! dns.Client 注入（bd 5y8，[`lookup_for_ip`] /
//! [`check_address_port_strategy`] / [`init_system_dialer`]）。仍留待办：
//!
//! - UDP 拨号（tokio UdpSocket + PacketConnWrapper）
//! - Go dialer.go:253-255 freedom-UDP 动态策略（GetDynamicStrategy，需会话上下文）

use std::{
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{Arc, OnceLock},
};

use async_trait::async_trait;
use parking_lot::{Mutex, RwLock};
use socket2::{SockRef, Socket as Socket2};
use tokio::{net::TcpStream, time::Instant};
use xray_common::net::{address::Address, destination::Destination, network::Network, port::Port};
use xray_features::dns::{DnsClient, IpOption};
use xray_frame::deadline::Budget;

use crate::{
    connection::Connection,
    sockopt::{
        AddressPortStrategy, DomainStrategy, HappyEyeballsConfig, SocketOptions,
        apply_outbound_socket_options,
    },
};

/// TCP 拨号超时（与 Go DefaultSystemDialer 一致：16 秒）。Go 语义是**整次拨号**
/// 的预算（`net.Dialer.Timeout` → ctx deadline，system_dialer.go:118），多地址时
/// 按 `partial_deadline` 分片，不是每地址各 16s。
pub const DEFAULT_DIAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(16);

/// 双栈拨号里回退族的启动延迟（Go `net.Dialer.FallbackDelay` 默认值，net/dial.go:291-297）。
const FALLBACK_DELAY: std::time::Duration = std::time::Duration::from_millis(300);

/// 单地址分片 deadline 的下限（Go `saneMinimum`，net/dial.go:280）。
const PARTIAL_DIAL_MIN: std::time::Duration = std::time::Duration::from_secs(2);

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
    ) -> crate::connection::BoxedConnFuture<'a>;

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
    ///
    /// `client_tfo`：Linux 上 connect 前设 `TCP_FASTOPEN_CONNECT`（AI7：transport
    /// 裸拨号路径 [`crate::sockopt::dial_client_tcp`] 复用本函数时置 true；
    /// dial_system 路径的 TFO 走 post-connect sockopt，保持 false 原语义）。
    pub(crate) async fn dial_tcp_raw(
        src: Option<SocketAddr>,
        dest: SocketAddr,
        timeout: std::time::Duration,
        bind_if_index: u32,
        client_tfo: bool,
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
        // Go system_dialer.go Control 回调：controllers 先于 sockopt 应用，失败即
        // 拨号失败；sockopt 的接口绑定在后（后写覆盖 = 配置优先，Go 同序）。
        run_dialer_controllers(&socket, &dest)?;
        // Go system_dialer.go:144-148：sockopt 的接口绑定在 controllers 之后应用
        // （后写覆盖 = 配置优先，Go 同序）。IP_UNICAST_IF/SO_BINDTODEVICE 仅对
        // connect 前的 socket 生效，post-connect 设置无法改变出站接口。
        if bind_if_index > 0 {
            crate::sockopt::bind_socket_to_interface(&socket, bind_if_index, dest.is_ipv4())?;
        }
        if client_tfo {
            crate::sockopt::apply_client_tfo_linux(&socket);
        }
        // 设置非阻塞（tokio 要求）。
        socket.set_nonblocking(true)?;
        // 发起连接（非阻塞 connect 返回 EINPROGRESS 是正常的）。
        match socket.connect(&dest.into()) {
            Ok(()) => {},
            Err(ref e) if e.raw_os_error() == Some(libc_error_inprogress()) => {
                // EINPROGRESS：非阻塞 connect 正在进行中，由 tokio 等待可写。
            },
            Err(e) => return Err(e),
        }
        // 转 tokio TcpStream。
        // 转 tokio TcpStream。
        let std_stream: std::net::TcpStream = socket.into();
        std_stream.set_nonblocking(true)?;
        let tokio_stream = TcpStream::from_std(std_stream)?;
        // 等待连接完成（带超时）。writable 触发 ≠ 连接成功——连接被拒/失败
        // 同样触发 writable，必须查 SO_ERROR（Go net.Dialer 内建行为）。
        Budget::tokio()
            .deadline(timeout)
            .timeout(tokio_stream.writable())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "dial timeout"))??;
        if let Some(e) = SockRef::from(&tokio_stream).take_error()? {
            return Err(e);
        }
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
            // 域名解析：Domain → IP（tokio lookup_host，使用系统 DNS）。
            let addrs = match destination_to_socket_addr(destination) {
                Ok(addr) => vec![addr],
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
                        },
                    };
                    let socket_addrs: Vec<SocketAddr> =
                        tokio::net::lookup_host((host, port)).await?.collect();
                    if socket_addrs.is_empty() {
                        return Err(io::Error::new(
                            io::ErrorKind::NotFound,
                            format!("DNS resolve failed: {host}"),
                        ));
                    }
                    socket_addrs
                },
            };
            dial_first_reachable(src, &addrs, sockopt).await
        })
    }
}

/// 多地址拨号入口。语义对齐 Go `net.Dialer.DialContext`（net/dial.go:659-694
/// `dialSerial` + :585-655 `dialParallel`）：
///
/// - **整次拨号共享** [`DEFAULT_DIAL_TIMEOUT`] 预算（Go `dialer.Timeout` 是 ctx
///   deadline，不是每地址各一份）——多地址不再出现 `N × 16s`。
/// - 同族地址顺序尝试，每地址分片 deadline = 剩余/剩余数（[`partial_deadline`]）。
/// - 双栈时两族并发，回退族 [`FALLBACK_DELAY`] 后启动；主族先失败则回退族立即 启动（Go
///   `fallbackTimer.Reset(0)`）——某族地址静默丢包不再拖死整次拨号。
/// - 全部失败时错误含每个尝试过的地址（[`all_addresses_failed`]）。
async fn dial_first_reachable(
    src: Option<SocketAddr>,
    addrs: &[SocketAddr],
    sockopt: &SocketOptions,
) -> io::Result<Box<dyn Connection>> {
    let (addr, stream) =
        dial_addr_list(addrs, Instant::now() + DEFAULT_DIAL_TIMEOUT, |addr, budget| {
            DefaultSystemDialer::dial_tcp_raw(src, addr, budget, sockopt.bind_if_index, false)
        })
        .await?;
    // 应用 sockopt（TCP_NODELAY + SO_KEEPALIVE）。配置错误不换地址重试。
    let std_stream = stream.into_std()?;
    let socket = Socket2::from(std_stream);
    apply_outbound_socket_options(&socket, sockopt, Some(addr))?;
    let tokio_stream = TcpStream::from_std(socket.into())?;
    Ok(Box::new(crate::connection::TcpConnection::new(tokio_stream)) as Box<dyn Connection>)
}

/// 地址列表拨号：按族分组后走 [`dial_serial`] 或 [`dial_parallel`]。
///
/// `attempt` 是单地址拨号接缝（生产传 [`DefaultSystemDialer::dial_tcp_raw`]，
/// 测试传可控假拨号以钉住超时分布）。成功返回 `(胜出地址, 连接)`。
async fn dial_addr_list<F, Fut>(
    addrs: &[SocketAddr],
    deadline: Instant,
    attempt: F,
) -> io::Result<(SocketAddr, TcpStream)>
where
    F: Fn(SocketAddr, std::time::Duration) -> Fut,
    Fut: Future<Output = io::Result<TcpStream>>,
{
    let Some(&first) = addrs.first() else {
        return Err(io::Error::new(io::ErrorKind::NotFound, "no address to dial"));
    };
    // Go `addrList.forResolve`：首地址所属族为主族，另一族为回退族。
    let (primaries, fallbacks): (Vec<SocketAddr>, Vec<SocketAddr>) =
        addrs.iter().copied().partition(|a| a.is_ipv4() == first.is_ipv4());
    if fallbacks.is_empty() {
        return dial_serial(&attempt, &primaries, deadline).await;
    }
    dial_parallel(&attempt, &primaries, &fallbacks, deadline).await
}

/// 单族地址顺序拨号（Go `dialSerial`，net/dial.go:659-694）。
async fn dial_serial<F, Fut>(
    attempt: &F,
    addrs: &[SocketAddr],
    deadline: Instant,
) -> io::Result<(SocketAddr, TcpStream)>
where
    F: Fn(SocketAddr, std::time::Duration) -> Fut,
    Fut: Future<Output = io::Result<TcpStream>>,
{
    let mut tried: Vec<(SocketAddr, io::Error)> = Vec::with_capacity(addrs.len());
    for (i, &addr) in addrs.iter().enumerate() {
        let Ok(partial) = partial_deadline(Instant::now(), deadline, addrs.len() - i) else {
            // 预算耗尽：余下地址不再尝试（Go dialSerial 同：errTimeout 即 break），
            // 但要留痕——否则"试过哪些"在日志里不可见。
            crate::LOG.debug(format!(
                "tried={} skipped={} dial budget exhausted, remaining addresses untried",
                i,
                addrs.len() - i
            ));
            break;
        };
        let budget = partial.saturating_duration_since(Instant::now());
        // 外层 timeout：接缝实现自己不守时也保证单地址吃不满整个预算。
        match tokio::time::timeout(budget, attempt(addr, budget)).await {
            Ok(Ok(stream)) => return Ok((addr, stream)),
            Ok(Err(e)) => {
                crate::LOG.debug(format!("addr={addr} error={e} dial attempt failed"));
                tried.push((addr, e));
            },
            Err(_) => tried.push((addr, io::Error::new(io::ErrorKind::TimedOut, "dial timeout"))),
        }
    }
    Err(all_addresses_failed(&tried))
}

/// 双族并发拨号（Go `dialParallel`，net/dial.go:585-655）：首个成功的胜出，
/// 另一族随 future drop 取消（Go `primaryCancel`/`fallbackCancel`）。
async fn dial_parallel<F, Fut>(
    attempt: &F,
    primaries: &[SocketAddr],
    fallbacks: &[SocketAddr],
    deadline: Instant,
) -> io::Result<(SocketAddr, TcpStream)>
where
    F: Fn(SocketAddr, std::time::Duration) -> Fut,
    Fut: Future<Output = io::Result<TcpStream>>,
{
    let primary = dial_serial(attempt, primaries, deadline);
    let fallback = dial_serial(attempt, fallbacks, deadline);
    tokio::pin!(primary, fallback);
    let delay = tokio::time::sleep(FALLBACK_DELAY);
    tokio::pin!(delay);

    let mut primary_err: Option<io::Error> = None;
    let mut fallback_err: Option<io::Error> = None;
    let mut primary_done = false;
    let mut fallback_started = false;
    let mut fallback_done = false;
    loop {
        tokio::select! {
            r = &mut primary, if !primary_done => {
                primary_done = true;
                match r {
                    Ok(conn) => return Ok(conn),
                    // Go net/dial.go:643-648：主族在回退计时器触发前失败 →
                    // 回退族立即启动（对齐 `fallbackTimer.Reset(0)`）。
                    Err(e) => {
                        primary_err = Some(e);
                        fallback_started = true;
                    },
                }
            },
            () = &mut delay, if !fallback_started => fallback_started = true,
            r = &mut fallback, if fallback_started && !fallback_done => {
                fallback_done = true;
                match r {
                    Ok(conn) => return Ok(conn),
                    Err(e) => fallback_err = Some(e),
                }
            },
        }
        if primary_done && fallback_done {
            return Err(match (primary_err.take(), fallback_err.take()) {
                // Go 返回主族错误（dial.go:651）；回退族细节追加保留可观测性。
                (Some(p), Some(f)) => {
                    io::Error::new(p.kind(), format!("{p}; fallback family: {f}"))
                },
                (Some(p), None) => p,
                (None, Some(f)) => f,
                (None, None) => io::Error::other("both address families failed without error"),
            });
        }
    }
}

/// 单地址分片 deadline（Go `partialDeadline`，net/dial.go:269-288）：剩余预算按
/// 剩余地址数均分，不足 [`PARTIAL_DIAL_MIN`] 时取 2s（剩余本身更少则用剩余）。
fn partial_deadline(
    now: Instant,
    deadline: Instant,
    addrs_remaining: usize,
) -> io::Result<Instant> {
    let remaining = deadline.saturating_duration_since(now);
    if remaining.is_zero() {
        return Err(io::Error::new(io::ErrorKind::TimedOut, "dial timeout"));
    }
    let share = remaining / u32::try_from(addrs_remaining).unwrap_or(u32::MAX);
    let share = if share < PARTIAL_DIAL_MIN { remaining.min(PARTIAL_DIAL_MIN) } else { share };
    Ok((now + share).min(deadline))
}

/// 全部地址失败：留首个错误的 kind（Go 用 firstErr，错误类别最相关），消息里列出
/// **每个尝试过的地址**与其错误。
fn all_addresses_failed(tried: &[(SocketAddr, io::Error)]) -> io::Error {
    let Some((_, first)) = tried.first() else {
        return io::Error::new(io::ErrorKind::TimedOut, "dial timeout");
    };
    let detail: Vec<String> = tried.iter().map(|(addr, e)| format!("{addr}: {e}")).collect();
    io::Error::new(
        first.kind(),
        format!("all {} address(es) failed: {}", tried.len(), detail.join("; ")),
    )
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

/// DialerController：在 fd 创建后、连接前调用的回调。对应 Go `Controllers`
/// （`func(network, address string, c syscall.RawConn) error`）。
///
/// 用于设置 SO_MARK / SO_BINDTODEVICE / TCP_FASTOPEN 等平台特定选项。
/// 回调接收 [`Socket2`] 引用 + 拨号目标地址（Go 的 `address` 参数；TUN 出站
/// 绑定 controller 据此跳过 loopback——Go proxy/tun/handler.go:145-147）。
pub type DialerController = Arc<dyn Fn(&Socket2, &SocketAddr) -> io::Result<()> + Send + Sync>;

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

/// 对刚创建、未 connect 的 socket 执行全部已注册 controller。
///
/// 对应 Go `DefaultSystemDialer.Dial` TCP/UDP 两个 Control 回调内的 controllers
/// 循环（main 分支 system_dialer.go TCP `dialer.Control` / UDP `lc.Control`）：
/// 任一错误即拨号失败。常态空列表零开销（一次锁判空，无堆分配）；仅 TUN 等
/// 注册方存在时才克隆快照。Go 语义锚点：controllers 全部执行完才轮到
/// `applyOutboundSocketOptions`（含 `SocketConfig.Interface` 绑定）——后写覆盖，
/// 用户显式 interface 配置优先，controller 无需自行检测。
pub(crate) fn run_dialer_controllers(socket: &Socket2, dest: &SocketAddr) -> io::Result<()> {
    if !controllers().lock().is_empty() {
        for ctl in registered_controllers() {
            ctl(socket, dest)?;
        }
    }
    Ok(())
}

/// UDP 出站 PacketConn：bind `bind_addr` → controllers → 返回**未 connect** 的
/// socket。对应 Go `DefaultSystemDialer.Dial` 的 UDP 分支（system_dialer.go:52-102）：
/// `lc.ListenPacket` 阶段 controllers 收 `destAddr` 而非本地地址（Go 源注释：
/// ListenPacket supplies a local address; dialer controllers need the destination）；
/// 返回 PacketConn 不 connect——per-packet 目标由调用方 `send_to`（Go
/// `PacketConnWrapper` 同）。controller 错误即失败（Go :74-77 同语义）。
///
/// freedom UDP relay 与 [`crate::udp::relay::UdpRelay`] 复用本函数（Go 中两者
/// 均经 `DialSystem` UDP 分支），保证 TUN 出站绑定等注册方对 UDP 同样生效。
///
/// # Errors
/// socket 创建 / bind / controller 失败时返回 `io::Error`。
pub async fn dial_udp_packet_conn(
    bind_addr: SocketAddr,
    dest: SocketAddr,
) -> io::Result<tokio::net::UdpSocket> {
    let socket = Socket2::new(
        socket2::Domain::for_address(bind_addr),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    socket.bind(&socket2::SockAddr::from(bind_addr))?;
    run_dialer_controllers(&socket, &dest)?;
    socket.set_nonblocking(true)?;
    let std_sock: std::net::UdpSocket = socket.into();
    tokio::net::UdpSocket::from_std(std_sock)
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
        },
        IpAddr::V6(v6) if prefix <= 128 => {
            let shift = 128 - prefix;
            let mask = if shift >= 128 { 0 } else { u128::MAX << shift };
            let network = u128::from(v6) & mask;
            let size: u128 = 1u128.checked_shl(u32::from(shift)).unwrap_or(0);
            let offset =
                if size == 0 { rand::random::<u128>() } else { rand::random::<u128>() % size };
            Some(IpAddr::V6(std::net::Ipv6Addr::from(network + offset)))
        },
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
    dyn Fn(
            &str,
            &Destination,
        ) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn Connection>>> + Send>>
        + Send
        + Sync,
>;

static DIALER_PROXY_HOOK: parking_lot::RwLock<Option<DialerProxyHook>> =
    parking_lot::RwLock::new(None);

/// 注册全局 DialerProxy 钩子（xray-core `register_outbounds` 调用）。
pub fn set_dialer_proxy_hook(hook: DialerProxyHook) {
    *DIALER_PROXY_HOOK.write() = Some(hook);
}

/// 清除钩子（测试隔离用）。
pub fn clear_dialer_proxy_hook() {
    *DIALER_PROXY_HOOK.write() = None;
}

// ===== LookupForIP（bd 5y8，Go dialer.go:87-109）=====

/// 全局 DNS 客户端。对应 Go dialer.go:82-85 的包级 `dnsClient`（由
/// `InitSystemDialer(dc dns.Client, ...)` 注入）。回调注入而非直接依赖
/// xray-app-dns（依赖方向：app-dns → transport，反向成环）。
static DNS_CLIENT: parking_lot::RwLock<Option<Arc<dyn DnsClient>>> = parking_lot::RwLock::new(None);

/// 注入全局 DNS 客户端。对应 Go `InitSystemDialer` 的 `dnsClient = dc`。
/// `None` 清除（测试隔离）。
pub fn set_dns_client(client: Option<Arc<dyn DnsClient>>) {
    *DNS_CLIENT.write() = client;
}

fn dns_client() -> Option<Arc<dyn DnsClient>> {
    DNS_CLIENT.read().clone()
}

/// DomainStrategy 感知的 DNS 解析。对应 Go `LookupForIP`（dialer.go:87-109）：
///
/// - IPOption 的 v4/v6 使能按 strategy 的 prefer 列 + `local_addr` 家族共同决定
///   （dialer.go:92-95）；`local_addr == None` 时不受家族约束。
/// - 首查空/错 + 有回退家族 + 无 `local_addr` → 按 fallback 家族重查（dialer.go:96-103）。
/// - 成功但 0 IP → `EmptyResponse` 错误（dialer.go:105-107）。
///
/// # Errors
/// - DNS 客户端未注入（Go "DNS client not initialized"）
/// - 底层解析错误 / 空响应
pub async fn lookup_for_ip(
    domain: &str,
    strategy: DomainStrategy,
    local_addr: Option<IpAddr>,
) -> io::Result<Vec<IpAddr>> {
    let Some(client) = dns_client() else {
        return Err(io::Error::other("DNS client not initialized"));
    };

    let v4_enable = (local_addr.is_none() && strategy.prefer_ipv4())
        || (local_addr.is_some_and(|a| a.is_ipv4())
            && (strategy.prefer_ipv4() || strategy.fallback_ipv4()));
    let v6_enable = (local_addr.is_none() && strategy.prefer_ipv6())
        || (local_addr.is_some_and(|a| a.is_ipv6())
            && (strategy.prefer_ipv6() || strategy.fallback_ipv6()));

    let mut ips: Vec<IpAddr> = Vec::new();
    let mut err: Option<xray_features::dns::DnsError> = None;
    match client
        .lookup_ip(
            domain,
            IpOption { ipv4_enable: v4_enable, ipv6_enable: v6_enable, fake_enable: false },
        )
        .await
    {
        Ok((resolved, _ttl)) => ips = resolved,
        Err(e) => err = Some(e),
    }
    // Resolve fallback（dialer.go:96-103）：首查空/错 + 有回退 + 无 local_addr 约束。
    if (ips.is_empty() || err.is_some()) && strategy.has_fallback() && local_addr.is_none() {
        crate::LOG.debug(format!(
            "domain={domain} err={err:?} lookup_for_ip falling back to fallback family"
        ));
        match client
            .lookup_ip(
                domain,
                IpOption {
                    ipv4_enable: strategy.fallback_ipv4(),
                    ipv6_enable: strategy.fallback_ipv6(),
                    fake_enable: false,
                },
            )
            .await
        {
            Ok((resolved, _ttl)) => {
                ips = resolved;
                err = None;
            },
            Err(e) => err = Some(e),
        }
    }

    if err.is_none() && ips.is_empty() {
        // Go dns.ErrEmptyResponse（dialer.go:105-107）。
        return Err(io::Error::other("empty DNS response"));
    }
    match err {
        Some(e) => Err(io::Error::other(format!("failed to resolve ip for {domain}: {e}"))),
        None => Ok(ips),
    }
}

// ===== checkAddressPortStrategy（bd 5y8，Go dialer.go:138-223）=====

/// SRV/TXT 系统解析 trait。对应 Go 对 `net.DefaultResolver.LookupSRV/LookupTXT`
/// 的调用（dialer.go:184/199）；抽象出 seam 供测试注入假 resolver。
#[async_trait]
pub trait SrvTxtResolver: Send + Sync {
    /// SRV 查询 `_service._proto.name`，返回 (target, port) 列表
    /// （对齐 Go `LookupSRV` 返回的记录切片）。
    ///
    /// # Errors
    /// 系统 resolver 失败（Go：`failed to lookup SRV record`）。
    async fn lookup_srv(
        &self,
        service: &str,
        proto: &str,
        name: &str,
    ) -> io::Result<Vec<(String, u16)>>;
    /// TXT 查询，返回 TXT 字符串列表（一条记录内多段已拼接，对齐 Go `LookupTXT`）。
    ///
    /// # Errors
    /// 系统 resolver 失败。
    async fn lookup_txt(&self, name: &str) -> io::Result<Vec<String>>;
}

/// 默认系统 resolver：hickory 系统 DNS 配置（等价 Go `net.DefaultResolver`）。
pub struct SystemSrvTxtResolver;

impl SystemSrvTxtResolver {
    fn resolver() -> io::Result<&'static hickory_resolver::TokioResolver> {
        static RESOLVER: std::sync::LazyLock<Option<hickory_resolver::TokioResolver>> =
            std::sync::LazyLock::new(|| match hickory_resolver::TokioResolver::builder_tokio() {
                Ok(builder) => match builder.build() {
                    Ok(r) => Some(r),
                    Err(e) => {
                        crate::LOG.warn(format!("error={e} build system DNS resolver failed"));
                        None
                    },
                },
                Err(e) => {
                    crate::LOG.warn(format!("error={e} read system DNS config failed"));
                    None
                },
            });
        RESOLVER.as_ref().ok_or_else(|| io::Error::other("system DNS resolver unavailable"))
    }
}

#[async_trait]
impl SrvTxtResolver for SystemSrvTxtResolver {
    async fn lookup_srv(
        &self,
        service: &str,
        proto: &str,
        name: &str,
    ) -> io::Result<Vec<(String, u16)>> {
        use hickory_resolver::proto::rr::{RData, RecordType};
        // Go net.Resolver.LookupSRV 查询 `_service._proto.name`（lookup.go:628）。
        let fqdn = format!("_{service}._{proto}.{name}");
        let lookup = SystemSrvTxtResolver::resolver()?
            .lookup(&fqdn, RecordType::SRV)
            .await
            .map_err(|e| io::Error::other(format!("failed to lookup SRV record: {e}")))?;
        let mut out = Vec::new();
        for record in lookup.answers() {
            if let RData::SRV(srv) = &record.data {
                // hickory Name 是 FQDN（带尾点）；Go LookupSRV 返回的 target 语义
                // 为可拨号主机名——剥尾点。
                let target = srv.target.to_string();
                let target = target.strip_suffix('.').unwrap_or(&target).to_string();
                out.push((target, srv.port));
            }
        }
        Ok(out)
    }

    async fn lookup_txt(&self, name: &str) -> io::Result<Vec<String>> {
        use hickory_resolver::proto::rr::{RData, RecordType};
        let lookup = SystemSrvTxtResolver::resolver()?
            .lookup(name, RecordType::TXT)
            .await
            .map_err(|e| io::Error::other(format!("failed to lookup TXT record: {e}")))?;
        let mut out = Vec::new();
        for record in lookup.answers() {
            if let RData::TXT(txt) = &record.data {
                // Go LookupTXT 把一条记录内的多段 character-strings 拼接为一个字符串。
                let joined = txt
                    .txt_data
                    .iter()
                    .map(|s| String::from_utf8_lossy(s).into_owned())
                    .collect::<String>();
                out.push(joined);
            }
        }
        Ok(out)
    }
}

/// SRV/TXT 记录覆盖目标地址/端口。对应 Go `checkAddressPortStrategy`
/// （dialer.go:138-223），用 [`SystemSrvTxtResolver`]。
///
/// # Errors
/// SRV/TXT 查询失败或地址格式非法（Go dialer.go:182/186/201-202）。
pub async fn check_address_port_strategy(
    dest: &Destination,
    sockopt: &SocketOptions,
) -> io::Result<Option<Destination>> {
    check_address_port_strategy_with(&SystemSrvTxtResolver, dest, sockopt).await
}

/// [`check_address_port_strategy`] 的可注入版本（测试 seam）。
pub(crate) async fn check_address_port_strategy_with(
    resolver: &dyn SrvTxtResolver,
    dest: &Destination,
    sockopt: &SocketOptions,
) -> io::Result<Option<Destination>> {
    // Go dialer.go:139-141：None → 不覆盖。
    let strategy = sockopt.address_port_strategy;
    if strategy == AddressPortStrategy::None {
        return Ok(None);
    }
    let (by_srv, override_port, override_address) = strategy.override_flags();

    // Go dialer.go:174-176：非域名目标不覆盖。
    let Address::Domain(domain) = dest.address() else {
        return Ok(None);
    };

    if by_srv {
        // Go dialer.go:180-183：地址须为 `_service._proto.name` 三段式
        // （SplitN "." 3；parts[0][1:]/parts[1][1:] 剥前导下划线）。
        let parts: Vec<&str> = domain.splitn(3, '.').collect();
        if parts.len() != 3 || parts[0].len() < 2 || parts[1].len() < 2 {
            return Err(io::Error::other(format!("invalid address format: {domain}")));
        }
        let service = &parts[0][1..];
        let proto = &parts[1][1..];
        let name = parts[2];
        crate::LOG.debug(format!("domain={domain} querying SRV record for address port strategy"));
        let records = resolver
            .lookup_srv(service, proto, name)
            .await
            .map_err(|e| io::Error::other(format!("failed to lookup SRV record: {e}")))?;
        // Go dialer.go:188-194：取首条 SRV 记录。
        let Some((target, port)) = records.first() else {
            return Err(io::Error::other("failed to lookup SRV record: empty response"));
        };
        let new_dest = Destination::new(
            if override_address { parse_override_address(target) } else { dest.address().clone() },
            if override_port { Port::new(*port) } else { dest.port() },
            dest.network(),
        );
        return Ok(Some(new_dest));
    }

    // TXT（Go dialer.go:197-221）。
    crate::LOG.debug(format!("domain={domain} querying TXT record for address port strategy"));
    let txts = resolver
        .lookup_txt(domain)
        .await
        .map_err(|e| io::Error::other(format!("failed to lookup TXT record: {e}")))?;
    for txt in &txts {
        let Some((host, port_s)) = split_host_port(txt) else {
            continue; // Go dialer.go:206-211：SplitHostPort/Port 失败 → 下一条
        };
        let Ok(port) = port_s.parse::<u16>() else {
            continue; // Go dialer.go:208-210：PortFromString 失败 → 下一条
        };
        let new_dest = Destination::new(
            if override_address { parse_override_address(&host) } else { dest.address().clone() },
            if override_port { Port::new(port) } else { dest.port() },
            dest.network(),
        );
        return Ok(Some(new_dest));
    }
    Ok(None)
}

/// Go `net.ParseAddress`：IP 字符串 → IP 地址，否则原样域名。
fn parse_override_address(s: &str) -> Address {
    match s.parse::<IpAddr>() {
        Ok(ip) => Address::from(ip),
        Err(_) => Address::Domain(s.to_string()),
    }
}

/// Go `net.SplitHostPort` 的子集：`host:port` / `[v6]:port` → (host, port)。
/// 括号剥离仅对 IPv6 字面量形式。
fn split_host_port(s: &str) -> Option<(String, String)> {
    let (host, port) = s.rsplit_once(':')?;
    if host.is_empty() || port.is_empty() {
        return None;
    }
    let host = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
    Some((host.to_string(), port.to_string()))
}

/// 系统拨号。对应 Go `dialer.go::DialSystem`（dialer.go:226-282），按 Go 原顺序：
///
/// 1. sendThrough 源地址（`DIAL_SRC`；`dialer_proxy` 非空时不取，dialer.go:233-235）
/// 2. [`check_address_port_strategy`]：SRV/TXT 记录可能改写目标（bd 5y8）
/// 3. `domain_strategy` 有策略 + 域名目标 → [`lookup_for_ip`] 预解析（bd 5y8）： Happy Eyeballs
///    条件满足时竞争拨号（bd 0ko），否则随机取一 IP 改写目标； 解析失败时 ForceIP
///    报错、否则保留域名走系统 resolver（dialer.go:251-267）
/// 4. `dialer_proxy` 非空 → 经 `DIALER_PROXY_HOOK` 重定向（bd enk，redirect）
/// 5. effective dialer 直连
///
/// # 参数
///
/// - `destination`：目标地址（IP 或 Domain）
/// - `sockopt`：socket 选项（含 `dialer_proxy` / `happy_eyeballs` / 策略字段）。
pub async fn dial_system(
    destination: &Destination,
    sockopt: &SocketOptions,
) -> io::Result<Box<dyn Connection>> {
    // sendThrough 源地址：对应 Go DialSystem 的 `src = ob.Gateway`
    // （dialer.go:228-235）+ `resolveSrcAddr` 端口 0（system_dialer.go:33-46）。
    // dialer_proxy 非空时不参与（Go dialer.go:233 `len(sockopt.DialerProxy) == 0`）。
    let src = if sockopt.dialer_proxy.is_empty() {
        DIAL_SRC.try_with(|v| *v).ok().flatten().map(|ip| SocketAddr::new(ip, 0))
    } else {
        None
    };

    // 1. checkAddressPortStrategy（bd 5y8，Go dialer.go:246-249）：SRV/TXT 覆盖
    //    目标地址/端口；查询失败仅 warn 不中断（Go：err != nil 时保留原目标）。
    let mut dest = destination.clone();
    match check_address_port_strategy(&dest, sockopt).await {
        Ok(Some(new_dest)) => {
            crate::LOG.info(format!(
                "from={destination} to={new_dest} replace destination with SRV/TXT record"
            ));
            dest = new_dest;
        },
        Ok(None) => {},
        Err(e) => crate::LOG.warn(format!("error={e} address port strategy lookup failed")),
    }

    // ponytail: clone Arc 后 drop guard，避免 RwLockReadGuard 跨 await 点
    // （否则 future 不是 Send，无法用于 async_trait 的 OutboundHandler::dial）。
    let dialer = {
        let guard = effective().read();
        Arc::clone(&*guard)
    };

    // 2. DomainStrategy 预解析（bd 5y8，Go dialer.go:251-267）。 ponytail: Go dialer.go:253-255 的
    //    freedom-UDP 动态策略 （GetDynamicStrategy）需要 session 的 outboundName/OriginalTarget，
    //    dial_system 无会话上下文——留待 freedom 出站层接入。
    if sockopt.domain_strategy.has_strategy() && dest.address().is_domain() {
        let strategy = sockopt.domain_strategy;
        let Address::Domain(domain) = dest.address() else { unreachable!("is_domain 已保证") };
        let domain = domain.clone();
        match lookup_for_ip(&domain, strategy, src.map(|s| s.ip())).await {
            Ok(ips) => {
                let he = sockopt.happy_eyeballs.as_ref();
                let he_eligible = dest.network() == Network::TCP
                    && sockopt.dialer_proxy.is_empty()
                    && he.is_some_and(|c| c.try_delay_ms > 0 && c.max_concurrent_try > 0);
                if he_eligible && ips.len() >= 2 {
                    // Happy Eyeballs（bd 0ko，Go dialer.go:262-266）。
                    return crate::happy_eyeballs::tcp_race_dial(
                        dialer,
                        src,
                        &ips,
                        dest.port(),
                        sockopt,
                        he.unwrap_or(&HappyEyeballsConfig::default()),
                    )
                    .await;
                }
                // Go dialer.go:262-264：随机取一 IP 改写目标（dice.Roll）。
                let ip = ips[rand::random_range(0..ips.len())];
                dest = Destination::new(Address::from(ip), dest.port(), dest.network());
                crate::LOG.info(format!("to={dest} replace destination with resolved ip"));
            },
            Err(e) => {
                crate::LOG.warn(format!("domain={domain} error={e} failed to resolve ip"));
                if strategy.force_ip() {
                    // Go dialer.go:258-261：ForceIP 解析失败即失败。
                    return Err(e);
                }
                // 非 Force：保留域名，走下方 effective dialer 的系统解析。
            },
        }
    }

    // 3. DialerProxy（bd enk）：对应 Go dialer.go:270-279——非空时不直连，经指定 tag 的 outbound
    //    handler 拨号（redirect）。可能已带上步骤 2 解析的 IP。
    if !sockopt.dialer_proxy.is_empty() {
        let hook = DIALER_PROXY_HOOK.read().clone();
        let Some(hook) = hook else {
            return Err(io::Error::other("there is no outbound manager for dialerProxy"));
        };
        return hook(&sockopt.dialer_proxy, &dest).await;
    }

    dialer.dial(src, &dest, sockopt).await
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
    // 历史布局：正式 item（DnsResolvingDialer/init_system_dialer 等）在测试模块之后，
    // 整体移动是大 diff 重构，保持现状。
    #![allow(clippy::items_after_test_module)]
    // 测试串行锁（HOOK/DNS_TEST_LOCK）guard 跨 await：#[tokio::test] 默认
    // current-thread runtime，测试体内无其他任务竞争该锁，无死锁面。
    #![allow(clippy::await_holding_lock)]

    use std::net::Ipv4Addr;

    use xray_common::net::{address::Address, port::Port};

    use super::*;

    fn localhost_dest(port: u16) -> Destination {
        Destination::tcp(Address::IPv4(Ipv4Addr::LOCALHOST), Port::new(port))
    }

    #[tokio::test]
    async fn default_dialer_connects_to_local_tcp_listener() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        #[allow(clippy::disallowed_methods, reason = "测试：accept 任务")]
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

    /// xqk4：多地址顺序回退——首地址不可达（closed port）→ 次地址（listener）连通。
    #[tokio::test]
    async fn dial_first_reachable_falls_back_to_second_address() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let good = listener.local_addr().unwrap();
        // 取一个当前无人监听的端口（bind 后立即释放）。
        let dead = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap()
        };
        #[allow(clippy::disallowed_methods, reason = "测试：accept 任务")]
        let accept_task = tokio::spawn(async move { listener.accept().await });
        let conn = dial_first_reachable(None, &[dead, good], &SocketOptions::default())
            .await
            .expect("second address should connect after first refused");
        assert_eq!(conn.remote_addr().unwrap(), Some(good));
        accept_task.await.unwrap().unwrap();
    }

    /// T1（Go `dialParallel`，net/dial.go:585-655）：首地址静默丢包（connect 永不
    /// 返回）→ 另一族 [`FALLBACK_DELAY`] 后启动并胜出，整次拨号 < 3s。旧实现
    /// 每地址独占 16s，这里要等满 16s 才轮到第二个地址。
    #[tokio::test]
    async fn blackholed_first_addr_falls_through_fast() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let good = listener.local_addr().unwrap();
        #[allow(clippy::disallowed_methods, reason = "测试：accept 任务")]
        let accept_task = tokio::spawn(async move { listener.accept().await });
        // 静默丢包地址（v6 文档网段）：假拨号永不返回，不依赖本机路由/防火墙行为。
        let blackhole: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let started = Instant::now();
        let (addr, stream) = dial_addr_list(
            &[blackhole, good],
            Instant::now() + DEFAULT_DIAL_TIMEOUT,
            |addr, _budget| async move {
                if addr == blackhole {
                    return std::future::pending::<io::Result<TcpStream>>().await;
                }
                DefaultSystemDialer::dial_tcp_raw(None, addr, DEFAULT_DIAL_TIMEOUT, 0, false).await
            },
        )
        .await
        .expect("reachable family should win while blackholed addr hangs");
        let elapsed = started.elapsed();
        assert_eq!(addr, good);
        drop(stream);
        assert!(elapsed < std::time::Duration::from_secs(3), "dial took {elapsed:?}, want < 3s");
        accept_task.await.unwrap().unwrap();
    }

    /// T1b（Go `partialDeadline`，net/dial.go:269-288）：同族多地址共享总预算，
    /// 首地址吃不满整个人 deadline（3s / 2 地址 = 1.5s），超时后立即推进。
    #[tokio::test]
    async fn blackholed_addr_does_not_eat_whole_budget() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let good = listener.local_addr().unwrap();
        #[allow(clippy::disallowed_methods, reason = "测试：accept 任务")]
        let accept_task = tokio::spawn(async move { listener.accept().await });
        let blackhole: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let budget = std::time::Duration::from_secs(3);
        let started = Instant::now();
        let (addr, stream) =
            dial_addr_list(&[blackhole, good], Instant::now() + budget, |addr, _| async move {
                if addr == blackhole {
                    return std::future::pending::<io::Result<TcpStream>>().await;
                }
                DefaultSystemDialer::dial_tcp_raw(None, addr, DEFAULT_DIAL_TIMEOUT, 0, false).await
            })
            .await
            .expect("second same-family address should connect");
        let elapsed = started.elapsed();
        assert_eq!(addr, good);
        drop(stream);
        assert!(
            elapsed >= std::time::Duration::from_millis(1400),
            "首地址未被分片超时截断: {elapsed:?}"
        );
        assert!(elapsed < budget, "整体超出预算: {elapsed:?}");
        accept_task.await.unwrap().unwrap();
    }

    /// T2：全部地址失败时错误串含**每个尝试过的地址**（可观测性）。
    #[tokio::test]
    async fn all_addresses_failed_error_lists_every_addr() {
        // 两个 bind 后立即释放的端口（无人监听 → connection refused）。
        let closed = || {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap()
        };
        let addrs = [closed(), closed()];
        assert_ne!(addrs[0], addrs[1]);
        let err = match dial_first_reachable(None, &addrs, &SocketOptions::default()).await {
            Ok(_) => panic!("both addresses are dead"),
            Err(e) => e,
        };
        let msg = err.to_string();
        for addr in addrs {
            assert!(msg.contains(&addr.to_string()), "missing {addr} in: {msg}");
        }
    }

    #[test]
    fn partial_deadline_shares_remaining_budget() {
        use std::time::Duration;
        let now = Instant::now();
        let deadline = now + Duration::from_secs(16);
        assert_eq!(partial_deadline(now, deadline, 4).unwrap(), now + Duration::from_secs(4));
        // 均分值低于 2s 下限 → 取下限
        assert_eq!(partial_deadline(now, deadline, 16).unwrap(), now + Duration::from_secs(2));
        // 剩余本身不足下限 → 用剩余
        let near = now + Duration::from_secs(1);
        assert_eq!(partial_deadline(now, near, 4).unwrap(), near);
        // 预算已耗尽 → 报超时（不再尝试）
        assert!(partial_deadline(deadline, deadline, 1).is_err());
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
                assert_ne!(
                    err.kind(),
                    io::ErrorKind::InvalidInput,
                    "domain should not be rejected"
                );
            },
            Ok(conn) => {
                drop(conn);
            },
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
        let controller: DialerController = Arc::new(|_socket: &Socket2, _dest: &SocketAddr| Ok(()));
        register_dialer_controller(controller).unwrap();
        assert_eq!(registered_controllers().len(), initial + 1);
    }

    #[tokio::test]
    async fn controllers_run_pre_connect_with_destination() {
        // loopback 目标：controller 在 connect 前被调用且拿到 dest；绑不绑由
        // controller 决策（TUN 侧跳 loopback），dialer 只负责传递（Go handler.go:145）。
        // 端口大概率关闭，connect 失败可接受——断言的是 controller 已先运行。
        static SAW: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        const PROBE_PORT: u16 = 59998;
        register_dialer_controller(Arc::new(|_socket: &Socket2, dest: &SocketAddr| {
            if dest.port() == PROBE_PORT {
                SAW.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            Ok(())
        }))
        .unwrap();
        let dest: SocketAddr = format!("127.0.0.1:{PROBE_PORT}").parse().unwrap();
        let _ = DefaultSystemDialer::dial_tcp_raw(
            None,
            dest,
            std::time::Duration::from_millis(500),
            0,
            false,
        )
        .await;
        assert_eq!(SAW.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn controller_error_aborts_dial() {
        // controller 失败 = 拨号失败（Go system_dialer.go:137-141 同语义）。
        // 只对魔数端口生效，避免污染同进程并行测试的其他拨号。
        const PROBE_PORT: u16 = 59999;
        register_dialer_controller(Arc::new(|_socket: &Socket2, dest: &SocketAddr| {
            if dest.port() == PROBE_PORT {
                return Err(io::Error::other("controller boom"));
            }
            Ok(())
        }))
        .unwrap();
        let dest: SocketAddr = format!("127.0.0.1:{PROBE_PORT}").parse().unwrap();
        let err = DefaultSystemDialer::dial_tcp_raw(
            None,
            dest,
            std::time::Duration::from_millis(500),
            0,
            false,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("controller boom"), "got: {err}");
    }

    #[tokio::test]
    async fn dial_system_uses_effective_dialer() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        #[allow(clippy::disallowed_methods, reason = "测试：accept 任务")]
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
        let dest = Destination::tcp(Address::IPv4(Ipv4Addr::new(1, 2, 3, 4)), Port::new(8080));
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
        #[allow(clippy::disallowed_methods, reason = "测试：accept+peer 记录任务")]
        let accept_task = tokio::spawn(async move {
            let (_sock, peer) = listener.accept().await.unwrap();
            *recorder.lock() = Some(peer.ip());
        });
        let dest = localhost_dest(addr.port());
        let sockopt = SocketOptions::default();
        // macOS/FreeBSD lo0 默认只配 127.0.0.1（127/8 全段仅 Linux 隐式可用，
        // bind 127.0.0.2 AddrNotAvailable）——平台感知退化 127.0.0.1，断言跟随
        // （与 freedom UDP sendThrough 同族修法）；Linux 保留 127.0.0.2 的
        // 区分度（未生效时 OS 默认源是 127.0.0.1）。
        #[cfg(any(target_os = "macos", target_os = "freebsd"))]
        let src: IpAddr = "127.0.0.1".parse().unwrap();
        #[cfg(not(any(target_os = "macos", target_os = "freebsd")))]
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
        #[allow(clippy::disallowed_methods, reason = "测试：accept 任务")]
        let _accept = tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let dest = Destination::tcp(
            xray_common::net::address::Address::IPv6(std::net::Ipv6Addr::LOCALHOST),
            Port::new(addr.port()),
        );
        let sockopt = SocketOptions::default();
        let v4_src: IpAddr = "127.0.0.2".parse().unwrap();
        let result = DIAL_SRC.scope(Some(v4_src), dial_system(&dest, &sockopt)).await;
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
        let sockopt =
            SocketOptions { dialer_proxy: "proxy-out".into(), ..SocketOptions::default() };
        let dest = Destination::tcp(
            xray_common::net::address::Address::from_ipv4_bytes([127, 0, 0, 1]),
            xray_common::net::port::Port::new(1),
        );
        let err = match dial_system(&dest, &sockopt).await {
            Err(e) => e,
            Ok(_) => panic!("dialerProxy without hook should fail"),
        };
        assert!(err.to_string().contains("no outbound manager"), "unexpected error: {err}");
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
        let sockopt =
            SocketOptions { dialer_proxy: "socks-out".into(), ..SocketOptions::default() };
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

    // ===== LookupForIP / checkAddressPortStrategy（bd 5y8）=====

    /// 全局 DNS 客户端测试锁（全局静态需串行设置/清除）。
    static DNS_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    /// 记录查询参数的假 DNS 客户端：按脚本返回结果。
    struct FakeDns {
        /// 每次查询记录 (domain, ipv4_enable, ipv6_enable)。
        seen: parking_lot::Mutex<Vec<(String, bool, bool)>>,
        /// 依次返回的结果。
        script: parking_lot::Mutex<Vec<Result<Vec<IpAddr>, xray_features::dns::DnsError>>>,
    }

    impl FakeDns {
        fn new(script: Vec<Result<Vec<IpAddr>, xray_features::dns::DnsError>>) -> Arc<Self> {
            Arc::new(Self {
                seen: parking_lot::Mutex::new(Vec::new()),
                script: parking_lot::Mutex::new(script),
            })
        }
    }

    #[async_trait::async_trait]
    impl DnsClient for FakeDns {
        async fn lookup_ip(
            &self,
            domain: &str,
            option: IpOption,
        ) -> Result<(Vec<IpAddr>, u32), xray_features::dns::DnsError> {
            self.seen.lock().push((domain.to_string(), option.ipv4_enable, option.ipv6_enable));
            match self.script.lock().remove(0) {
                Ok(ips) => Ok((ips, 60)),
                Err(e) => Err(e),
            }
        }
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(std::net::Ipv4Addr::new(a, b, c, d))
    }

    /// 未注入 DNS 客户端 → "DNS client not initialized"（Go dialer.go:88-90）。
    #[tokio::test]
    async fn lookup_for_ip_without_client_errors() {
        let _guard = DNS_TEST_LOCK.lock();
        set_dns_client(None);
        let err = lookup_for_ip("example.com", DomainStrategy::UseIP, None).await.unwrap_err();
        assert!(err.to_string().contains("DNS client not initialized"), "got: {err}");
    }

    /// IPOption 计算：UseIP（prefer both）→ v4+v6；UseIPv4v6 → 仅 v4 首查
    /// （Go dialer.go:92-95）。
    #[tokio::test]
    async fn lookup_for_ip_ip_option_by_strategy() {
        let _guard = DNS_TEST_LOCK.lock();
        let fake = FakeDns::new(vec![Ok(vec![v4(1, 1, 1, 1)])]);
        set_dns_client(Some(fake.clone() as Arc<dyn DnsClient>));

        lookup_for_ip("example.com", DomainStrategy::UseIP, None).await.unwrap();
        assert_eq!(fake.seen.lock().as_slice(), &[("example.com".into(), true, true)]);

        let fake = FakeDns::new(vec![Ok(vec![v4(1, 1, 1, 1)])]);
        set_dns_client(Some(fake.clone() as Arc<dyn DnsClient>));
        lookup_for_ip("example.com", DomainStrategy::UseIPv4, None).await.unwrap();
        assert_eq!(fake.seen.lock().as_slice(), &[("example.com".into(), true, false)]);
        set_dns_client(None);
    }

    /// localAddr 家族约束：v4 源 + UseIPv4v6 → 仅 v4 使能（Go dialer.go:93）。
    #[tokio::test]
    async fn lookup_for_ip_local_addr_constrains_family() {
        let _guard = DNS_TEST_LOCK.lock();
        let fake = FakeDns::new(vec![Ok(vec![v4(1, 1, 1, 1)])]);
        set_dns_client(Some(fake.clone() as Arc<dyn DnsClient>));
        lookup_for_ip("example.com", DomainStrategy::UseIPv4v6, Some(v4(192, 168, 1, 1)))
            .await
            .unwrap();
        // v4 源：v6 使能仅当 prefer_v6||fallback_v6——UseIPv4v6 二者皆否。
        assert_eq!(fake.seen.lock().as_slice(), &[("example.com".into(), true, false)]);
        set_dns_client(None);
    }

    /// 回退解析：首查空 + UseIPv4v6（fallback v6）→ 二查 v6 only（dialer.go:96-103）。
    #[tokio::test]
    async fn lookup_for_ip_falls_back_on_empty() {
        let _guard = DNS_TEST_LOCK.lock();
        let fake = FakeDns::new(vec![
            Ok(Vec::new()), // 首查空
            Ok(vec![IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)]),
        ]);
        set_dns_client(Some(fake.clone() as Arc<dyn DnsClient>));
        let ips = lookup_for_ip("example.com", DomainStrategy::UseIPv4v6, None).await.unwrap();
        assert_eq!(ips, vec![IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)]);
        assert_eq!(
            fake.seen.lock().as_slice(),
            &[("example.com".into(), true, false), ("example.com".into(), false, true),]
        );
        set_dns_client(None);
    }

    /// 成功但 0 IP 且无回退 → EmptyResponse 错误（dialer.go:105-107）。
    #[tokio::test]
    async fn lookup_for_ip_empty_response_errors() {
        let _guard = DNS_TEST_LOCK.lock();
        let fake = FakeDns::new(vec![Ok(Vec::new())]);
        set_dns_client(Some(fake as Arc<dyn DnsClient>));
        let err = lookup_for_ip("example.com", DomainStrategy::UseIP, None).await.unwrap_err();
        assert!(err.to_string().contains("empty DNS response"), "got: {err}");
        set_dns_client(None);
    }

    /// 假 SRV/TXT resolver。
    struct FakeSrvTxt {
        srv: Vec<(String, u16)>,
        txt: Vec<String>,
    }

    #[async_trait::async_trait]
    impl SrvTxtResolver for FakeSrvTxt {
        async fn lookup_srv(&self, _s: &str, _p: &str, _n: &str) -> io::Result<Vec<(String, u16)>> {
            Ok(self.srv.clone())
        }

        async fn lookup_txt(&self, _n: &str) -> io::Result<Vec<String>> {
            Ok(self.txt.clone())
        }
    }

    fn aps_sockopt(s: AddressPortStrategy) -> SocketOptions {
        SocketOptions { address_port_strategy: s, ..Default::default() }
    }

    /// None 策略 / IP 目标 → 不覆盖（Go dialer.go:139-141/174-176）。
    #[tokio::test]
    async fn aps_none_and_ip_dest_no_override() {
        let resolver = FakeSrvTxt { srv: vec![], txt: vec![] };
        let dest = Destination::tcp(Address::new_domain("example.com"), Port::new(80));
        assert!(
            check_address_port_strategy_with(
                &resolver,
                &dest,
                &aps_sockopt(AddressPortStrategy::None)
            )
            .await
            .unwrap()
            .is_none()
        );

        let dest = Destination::tcp(Address::from_ipv4_bytes([1, 2, 3, 4]), Port::new(80));
        assert!(
            check_address_port_strategy_with(
                &resolver,
                &dest,
                &aps_sockopt(AddressPortStrategy::SrvPortAndAddress)
            )
            .await
            .unwrap()
            .is_none()
        );
    }

    /// SrvPortAndAddress：端口+地址均覆盖；下划线前缀剥除后查询（dialer.go:178-195）。
    #[tokio::test]
    async fn aps_srv_port_and_address() {
        let resolver = FakeSrvTxt { srv: vec![("srv.example.com".into(), 8443)], txt: vec![] };
        let dest = Destination::tcp(Address::new_domain("_sip._tcp.example.com"), Port::new(5060));
        let new_dest = check_address_port_strategy_with(
            &resolver,
            &dest,
            &aps_sockopt(AddressPortStrategy::SrvPortAndAddress),
        )
        .await
        .unwrap()
        .expect("should override");
        assert_eq!(new_dest.port().value(), 8443);
        assert_eq!(new_dest.address(), &Address::new_domain("srv.example.com"));
        assert_eq!(new_dest.network(), dest.network());
    }

    /// SrvPortOnly：仅端口覆盖，地址保留域名（dialer.go:146-149）。
    #[tokio::test]
    async fn aps_srv_port_only_keeps_address() {
        let resolver = FakeSrvTxt { srv: vec![("x.y".into(), 993)], txt: vec![] };
        let dest = Destination::tcp(Address::new_domain("_imaps._tcp.example.com"), Port::new(143));
        let new_dest = check_address_port_strategy_with(
            &resolver,
            &dest,
            &aps_sockopt(AddressPortStrategy::SrvPortOnly),
        )
        .await
        .unwrap()
        .expect("should override");
        assert_eq!(new_dest.port().value(), 993);
        assert_eq!(new_dest.address(), &Address::new_domain("_imaps._tcp.example.com"));
    }

    /// SRV 目标是 IP 字符串 → 覆盖为 IP 地址（Go net.ParseAddress）。
    #[tokio::test]
    async fn aps_srv_address_parses_ip() {
        let resolver = FakeSrvTxt { srv: vec![("10.0.0.1".into(), 80)], txt: vec![] };
        let dest = Destination::tcp(Address::new_domain("_a._b.example.com"), Port::new(80));
        let new_dest = check_address_port_strategy_with(
            &resolver,
            &dest,
            &aps_sockopt(AddressPortStrategy::SrvAddressOnly),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(new_dest.address(), &Address::from_ipv4_bytes([10, 0, 0, 1]));
        assert_eq!(new_dest.port().value(), 80);
    }

    /// SRV 域名格式非三段式 → 错误（dialer.go:180-183）。
    #[tokio::test]
    async fn aps_srv_invalid_format_errors() {
        let resolver = FakeSrvTxt { srv: vec![], txt: vec![] };
        let dest = Destination::tcp(Address::new_domain("example.com"), Port::new(80));
        let err = check_address_port_strategy_with(
            &resolver,
            &dest,
            &aps_sockopt(AddressPortStrategy::SrvPortOnly),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("invalid address format"), "got: {err}");
    }

    /// TXT：首条 host:port 有效 → 覆盖；无效端口跳到下一条（dialer.go:197-221）。
    #[tokio::test]
    async fn aps_txt_skips_invalid_records() {
        let resolver = FakeSrvTxt {
            srv: vec![],
            txt: vec![
                "no-port-host".into(),             // 无冒号 → SplitHostPort 失败
                "bad.example.com:notaport".into(), // 端口非数字 → 跳过
                "good.example.com:8443".into(),    // 有效
            ],
        };
        let dest = Destination::tcp(Address::new_domain("example.com"), Port::new(80));
        let new_dest = check_address_port_strategy_with(
            &resolver,
            &dest,
            &aps_sockopt(AddressPortStrategy::TxtPortAndAddress),
        )
        .await
        .unwrap()
        .expect("third record should win");
        assert_eq!(new_dest.port().value(), 8443);
        assert_eq!(new_dest.address(), &Address::new_domain("good.example.com"));
    }

    /// TXT 全部无效 → Ok(None)（dialer.go:220-222 兜底）。
    #[tokio::test]
    async fn aps_txt_all_invalid_returns_none() {
        let resolver = FakeSrvTxt { srv: vec![], txt: vec!["garbage".into()] };
        let dest = Destination::tcp(Address::new_domain("example.com"), Port::new(80));
        assert!(
            check_address_port_strategy_with(
                &resolver,
                &dest,
                &aps_sockopt(AddressPortStrategy::TxtPortOnly)
            )
            .await
            .unwrap()
            .is_none()
        );
    }

    /// dial_system 集成：UseIPv4 + 假 DNS 返回 127.0.0.1 → 拨号成功打到本地
    /// echo listener（证明 dest 被解析出的 IP 改写，Go dialer.go:262-264）。
    #[tokio::test]
    async fn dial_system_domain_strategy_resolves_via_dns_client() {
        let _guard = DNS_TEST_LOCK.lock();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        #[allow(clippy::disallowed_methods, reason = "测试：accept 任务")]
        let accept_task = tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let fake = FakeDns::new(vec![Ok(vec![v4(127, 0, 0, 1)])]);
        set_dns_client(Some(fake as Arc<dyn DnsClient>));

        let dest = Destination::tcp(Address::new_domain("echo.invalid"), Port::new(addr.port()));
        let sockopt =
            SocketOptions { domain_strategy: DomainStrategy::UseIPv4, ..SocketOptions::default() };
        let result = dial_system(&dest, &sockopt).await;
        set_dns_client(None);
        drop(result);
        accept_task.await.unwrap();
    }

    /// dial_system 集成：ForceIP + 解析失败 → 拨号报错（Go dialer.go:258-261）；
    /// UseIP（非 Force）+ 解析失败 → 保留域名走系统 resolver（dialer.go:257+262 前置条件）。
    #[tokio::test]
    async fn dial_system_force_ip_fails_hard_use_ip_falls_back() {
        let _guard = DNS_TEST_LOCK.lock();
        let fake = FakeDns::new(vec![
            Err(xray_features::dns::DnsError::DomainNotFound("x".into())),
            Err(xray_features::dns::DnsError::DomainNotFound("x".into())),
        ]);
        set_dns_client(Some(fake as Arc<dyn DnsClient>));

        let dest = Destination::tcp(Address::new_domain("nonexistent.invalid"), Port::new(80));
        let sockopt = SocketOptions {
            domain_strategy: DomainStrategy::ForceIPv4,
            ..SocketOptions::default()
        };
        let err = match dial_system(&dest, &sockopt).await {
            Err(e) => e,
            Ok(_) => panic!("ForceIPv4 + DNS failure should error"),
        };
        assert!(
            err.to_string().contains("domain not found"),
            "ForceIP should surface DNS error, got: {err}"
        );

        // 非 Force：解析失败不中断——域名交给 effective dialer 的系统解析，
        // .invalid 必失败但错误来自系统 resolver 而非 LookupForIP。
        let sockopt =
            SocketOptions { domain_strategy: DomainStrategy::UseIPv4, ..SocketOptions::default() };
        let result = dial_system(&dest, &sockopt).await;
        let err = match result {
            Err(e) => e.to_string(),
            Ok(_) => panic!("nonexistent.invalid should fail eventually"),
        };
        assert!(
            !err.contains("failed to resolve ip"),
            "non-Force should not surface LookupForIP error, got: {err}"
        );
        set_dns_client(None);
    }
}

/// DNS 解析系统拨号器——在 DefaultSystemDialer 前增加 DNS 解析能力。
///
/// 当目标地址为 Domain 时，使用 `tokio::net::lookup_host` 解析为 IP，
/// 再委托给 DefaultSystemDialer 拨号。对应 Go `InitSystemDialer` 的 DNS 解析部分。
pub struct DnsResolvingDialer {
    inner: DefaultSystemDialer,
}

impl Default for DnsResolvingDialer {
    fn default() -> Self {
        Self::new()
    }
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
                    crate::LOG.debug(format!("target={lookup} resolving domain via system DNS"));
                    match tokio::net::lookup_host(&lookup).await {
                        Ok(addrs) => {
                            let addrs: Vec<SocketAddr> = addrs.collect();
                            if addrs.is_empty() {
                                return Err(io::Error::new(
                                    io::ErrorKind::AddrNotAvailable,
                                    format!("DNS lookup returned no addresses for {domain}"),
                                ));
                            }
                            crate::LOG
                                .debug(format!("target={lookup} addrs={addrs:?} domain resolved"));
                            // 全部解析地址顺序尝试（首个失败换下一个，Go net.Dialer 语义）。
                            dial_first_reachable(src, &addrs, sockopt).await
                        },
                        Err(e) => {
                            crate::LOG.warn(format!("target={domain} error={e} DNS lookup failed"));
                            Err(io::Error::new(
                                io::ErrorKind::AddrNotAvailable,
                                format!("DNS lookup failed for {domain}: {e}"),
                            ))
                        },
                    }
                },
                _ => self.inner.dial(src, destination, sockopt).await,
            }
        })
    }
}

/// 初始化系统拨号器。对应 Go `InitSystemDialer(dc dns.Client, om outbound.Manager)`
/// （dialer.go:284-287）：
///
/// - `dns_client`：注入全局 DNS 客户端（`LookupForIP` 数据源）；`None` 时 `LookupForIP` 报 "DNS
///   client not initialized"，域名拨号仍走系统 resolver。 outbound manager（`obm`）等价物
///   [`DIALER_PROXY_HOOK`](set_dialer_proxy_hook) 由 xray-core `register_outbounds` 单独注入（bd
///   enk）。
/// - effective dialer 替换为 [`DnsResolvingDialer`]（域名兜底解析）。
pub fn init_system_dialer(dns_client: Option<Arc<dyn DnsClient>>) {
    set_dns_client(dns_client);
    use_alternative_system_dialer(Some(Box::new(DnsResolvingDialer::new())));
    crate::LOG.info("system dialer initialized with DNS resolution");
}
