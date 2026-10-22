//! DNS 查询经路由出站的拨号抽象（bd mcpo）。
//!
//! 对应 Go `app/dns/nameserver.go:41-78`：`NewServer` 收 `routing.Dispatcher`，
//! TCP/DoH/UDP-classic 查询经 `dispatcher.Dispatch` 完整路由出站（可被规则代理，
//! 防污染拓扑下经代理转发）。Rust 侧 xray-app-dns 不能反向依赖 xray-core/dispatcher，
//! 比照 fakedns 共享槽（bd 9vu4）与 observatory ProbeExecutor（f23r）先例：
//! 本 crate 定义 [`QueryDialer`] trait + 进程级共享槽，装配层（xray-core
//! functions.rs）在 dispatcher init 完成后注入。
//!
//! - 未注入（直连兜底）：nameserver 行为与既往一致（IP 直连；域名走 [`HostResolver`]
//!   每查询现解析——弃启动期钉死 IP）。
//! - 已注入：TCP/DoH/DoT 查询经 [`QueryDialer::dial_tcp`]（Link 流）， UDP-classic 经
//!   [`QueryDialer::dial_udp`]（数据报会话，XUDP 帧约定）。
//! - DoQ（`quic://`）：Go `nameserver_quic.go` 无 dispatcher 接线（仅 `quic+local`
//!   直连形态），维持直连。

use std::{
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use parking_lot::RwLock;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use xray_buf::{
    io::{Reader as MbReader, Writer as MbWriter},
    multi::MultiBuffer,
};
use xray_common::net::destination::Destination;
use xray_transport::connection::Connection;

/// TCP 形态查询流。直连 = `TcpConnection`；经路由 = [`LinkStream`]。
pub type DnsStream = Box<dyn Connection>;

/// 域名解析器（直连兜底路径；经路由时解析交给路由系统/outbound，Go 正统语义）。
pub trait HostResolver: Send + Sync {
    fn resolve(
        &self,
        host: String,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send>>;
}

/// 系统解析器：每查询现解析（系统 getaddrinfo，OS 解析栈，4s 超时）。
///
/// 票内"域名 NS 运行期解析"：上游 IP 变更后新查询自然用新 IP，
/// 无启动期钉死缓存。bd ypsl：曾用 hickory TokioResolver，其对部分域名
/// A 响应空返回且 v6-only 让直连撞本机 v6 不可达——见 resolve 内注释。
pub struct SystemHostResolver;

impl HostResolver for SystemHostResolver {
    fn resolve(
        &self,
        host: String,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send>> {
        Box::pin(async move {
            // bd ypsl：曾用 hickory TokioResolver——实测对部分域名的 A 响应空
            // 返回（上游 114/223.5.5.5/8.8.8.8 手工 wire 查询均正常，纯 hickory
            // 层问题），v6-only 结果又让直连撞本机 v6 不可达（os error 10051）
            // → DoH 必挂。改用系统 getaddrinfo（OS 解析栈，python/curl/nslookup
            // 同路径三方验证可用），双栈结果 v4 优先。
            let host2 = host.clone();
            let resolve_fut = tokio::task::spawn_blocking(move || {
                use std::net::ToSocketAddrs as _;
                let mut ips: Vec<IpAddr> = (host2.as_str(), 0)
                    .to_socket_addrs()
                    .map_err(|e| io::Error::other(format!("getaddrinfo: {e}")))?
                    .map(|sa| sa.ip())
                    .collect::<Vec<IpAddr>>();
                // v4 优先（稳定排序保持族内相对序）：v6 不可达场景常见，先试 v4。
                ips.sort_by_key(|ip| !matches!(ip, IpAddr::V4(_)));
                Ok::<Vec<IpAddr>, io::Error>(ips)
            });
            let ips = tokio::time::timeout(Duration::from_secs(4), resolve_fut)
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, format!("resolve {host} timeout"))
                })?
                .map_err(|e| io::Error::other(format!("getaddrinfo join: {e}")))??;
            if ips.is_empty() {
                return Err(io::Error::other(format!(
                    "resolve {host}: getaddrinfo returned no address"
                )));
            }
            Ok(ips)
        })
    }
}

/// UDP 数据报会话（Go nameserver_udp.go:134 `udpServer.Dispatch` 包粒度语义）。
pub trait UdpPacketSession: Send {
    fn send_packet(
        &mut self,
        dest: &Destination,
        payload: &[u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + '_>>;

    /// `Ok(None)` = 会话已关闭。
    fn recv_packet(&mut self) -> UdpRecvFuture<'_>;
}

/// UDP 会话收包 future（`Ok(None)` = 会话已关闭）。
type UdpRecvFuture<'a> = Pin<Box<dyn Future<Output = io::Result<Option<Vec<u8>>>> + Send + 'a>>;

/// DNS 流式链路 future（Go nameserver_tcp.go:43-47 / dohnameserver.go:68）。
type DnsStreamFuture<'a> = Pin<Box<dyn Future<Output = io::Result<DnsStream>> + Send + 'a>>;

/// DNS UDP 会话 future（Go nameserver_udp.go:134）。
type UdpSessionFuture<'a> =
    Pin<Box<dyn Future<Output = io::Result<Box<dyn UdpPacketSession>>> + Send + 'a>>;

/// DNS 查询拨号器（Go `routing.Dispatcher` 在 DNS 查询场景的用法）。
pub trait QueryDialer: Send + Sync {
    /// 建立到 `dest` 的流式链路（Go nameserver_tcp.go:43-47 / dohnameserver.go:68）。
    fn dial_tcp(&self, dest: &Destination) -> DnsStreamFuture<'_>;

    /// 建立 UDP 数据报会话（Go nameserver_udp.go:134）。
    fn dial_udp(&self, dest: &Destination) -> UdpSessionFuture<'_>;
}

// ========== 进程级共享槽（fakedns 9vu4 同模式） ==========

static SHARED_DIALER: RwLock<Option<Arc<dyn QueryDialer>>> = RwLock::new(None);

/// 注入/清除共享 dialer。装配层 dispatcher init 完成后调用；测试用 `None` 复位。
pub fn set_shared_dialer(dialer: Option<Arc<dyn QueryDialer>>) {
    *SHARED_DIALER.write() = dialer;
}

/// 测试用：共享 dialer 槽是**进程级全局**，涉槽测试必须串行——全 crate 共用
/// 这一把锁（各模块各持一把锁 = 槽仍会被别的模块的测试改写，跨模块串扰）。
#[cfg(test)]
pub(crate) static DIALER_SLOT_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

/// 惰性取用（DNS app 可能先于 dispatcher 构建）。
pub fn shared_dialer() -> Option<Arc<dyn QueryDialer>> {
    SHARED_DIALER.read().clone()
}

// ========== Link 流适配 ==========

/// `Link`（MultiBuffer 粒度 reader/writer）→ `AsyncRead + AsyncWrite` 流适配。
///
/// dispatcher 返回的链路端是 `Box<dyn Reader/Writer>`（MultiBuffer 粒度），
/// TLS/h2/TCP 长度前缀逻辑需要字节流接口，此桥做粒度转换。
pub struct LinkStream {
    reader: Box<dyn MbReader>,
    /// 已从 MultiBuffer 拆出、尚未交付给调用方的字节。
    pending: MultiBuffer,
    writer: Box<dyn MbWriter>,
}

impl LinkStream {
    pub fn new(reader: Box<dyn MbReader>, writer: Box<dyn MbWriter>) -> Self {
        Self { reader, pending: MultiBuffer::new(), writer }
    }
}

impl AsyncRead for LinkStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.pending.is_empty() {
                let spare = buf.initialize_unfilled();
                let n = this.pending.read_to(spare);
                if n > 0 {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                // pending 非空但无字节（全空 buffer）：释放后驱动底层。
                this.pending.release();
            }
            // poll 形态直驱：每次 poll 重建并丢弃 read future 会让 pipe 的
            // waiter 注册随 future 销毁 → 下行数据到达不再唤醒读端（丢唤醒，
            // bd 34nk）。`poll_read_multi_buffer` 的 waker 注册持久于共享槽。
            let got = xray_buf::io::Reader::poll_read_multi_buffer(&mut this.reader, cx);
            match got {
                Poll::Ready(Ok(mb)) => {
                    if mb.is_empty() {
                        // EOF：0 字节填充即 EOF 语义。
                        return Poll::Ready(Ok(()));
                    }
                    this.pending.merge(mb);
                },
                // pipe 关闭/idle 超时（Error::Eof）→ 流 EOF。
                Poll::Ready(Err(xray_buf::io::Error::Eof)) => return Poll::Ready(Ok(())),
                Poll::Ready(Err(e)) => {
                    return Poll::Ready(Err(io::Error::other(e.to_string())));
                },
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for LinkStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.get_mut();
        let mut mb = MultiBuffer::new();
        mb.write_from(buf);
        // 同 poll_read：写端直驱 poll 形态，管道满时 waker 持久注册（bd 34nk）。
        let got = xray_buf::io::Writer::poll_write_multi_buffer(&mut this.writer, cx, &mut mb);
        match got {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Err(xray_buf::io::Error::Eof)) => {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "link closed")))
            },
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::other(e.to_string()))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // MultiBuffer writer 无本地缓冲层，写即下发。
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().writer.shutdown();
        Poll::Ready(Ok(()))
    }
}

// SAFETY: LinkStream 的 reader/pending/writer 字段仅在 &mut self 方法
// （poll_read/poll_write/AsyncRead/AsyncWrite）中访问；&self 方法
// （remote_addr/local_addr）不读取任何字段。MultiBuffer 粒度 reader/writer
// trait 无 Sync supertrait，但 LinkStream 从不并发共享 &self 可变状态。
// SAFETY: LinkStream 无共享可变内部态；&self 方法只读自有字段，trait 缺 Sync supertrait
// 仅为对象安全
unsafe impl Sync for LinkStream {}

impl Connection for LinkStream {
    fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(None)
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(None)
    }
}

// ========== 直连兜底辅助 ==========

/// 把 `dest` 解析为可直连的 `SocketAddr` **候选列表**：IP 目标返回单地址；域名
/// 经 resolver 现解析返回全部候选（按 resolver 返回序）。调用方必须按序尝试
/// connect——v6 优先返回而本机 v6 不可达时靠后续地址回退（bd ypsl 实测：
/// alidns 解析出 2400:3200::1 优先，本机 v6 无路由 os error 10051，单地址无
/// 回退致 DoH 必挂；Go net.Dialer 多地址回退同语义）。
pub(crate) async fn resolve_dest_addrs(
    dest: &Destination,
    resolver: &dyn HostResolver,
) -> io::Result<Vec<SocketAddr>> {
    let port = dest.port().value();
    if let Some(ip) = dest.address().ip() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let host = dest
        .address()
        .as_domain()
        .ok_or_else(|| io::Error::other("empty destination address"))?
        .to_string();
    let ips = resolver.resolve(host).await?;
    if ips.is_empty() {
        return Err(io::Error::other("resolver returned no address"));
    }
    Ok(ips.into_iter().map(|ip| SocketAddr::new(ip, port)).collect())
}

/// 把 `dest` 解析为单个可直连 `SocketAddr`（首候选）。UDP 数据报路径专用
/// （单 send_to 语义）；TCP 流路径用 [`resolve_dest_addrs`] 多地址回退。
pub(crate) async fn resolve_dest_addr(
    dest: &Destination,
    resolver: &dyn HostResolver,
) -> io::Result<SocketAddr> {
    let addrs = resolve_dest_addrs(dest, resolver).await?;
    addrs.into_iter().next().ok_or_else(|| io::Error::other("resolver returned no address"))
}

/// 建立查询用 TCP 流：共享 dialer 在场经路由出站（Go nameserver.go:41-78
/// 查询 ctx 带路由语义）；缺席直连兜底（域名每查询现解析）。
///
/// `force_local`（`+local` server）绕过共享 dialer 强制直连——Go Local mode
/// 传 nil dispatcher 的等价语义（bd wmdn②）。
///
/// `what` 用于错误消息前缀（"tcp"/"doh"/"dot"/"udp-tcp-fallback"）。
pub(crate) async fn connect_stream(
    dest: &Destination,
    resolver: &dyn HostResolver,
    query_timeout: Duration,
    what: &str,
    force_local: bool,
) -> Result<DnsStream, crate::error::DnsError> {
    // 共享 dialer 在场且非 `+local` → 查询经路由出站（Go nameserver.go:41-78
    // 查询 ctx 带路由语义；bd mcpo）。`+local` 绕过 dialer 强制直连（Go Local
    // mode 传 nil dispatcher 的等价语义，bd wmdn②）。
    if !force_local {
        if let Some(dialer) = shared_dialer() {
            return tokio::time::timeout(query_timeout, dialer.dial_tcp(dest))
                .await
                .map_err(|_| {
                    crate::error::DnsError::WireFormat(format!(
                        "{what} dial timeout after {query_timeout:?}"
                    ))
                })?
                .map_err(|e| crate::error::DnsError::WireFormat(format!("{what} dial: {e}")));
        }
    }
    let addrs = resolve_dest_addrs(dest, resolver).await.map_err(|e| {
        tracing::debug!(target: "xray.dns.doh", what = %what, error = %e, "doh: resolve failed");
        crate::error::DnsError::WireFormat(format!("{what} resolve: {e}"))
    })?;
    // 多地址顺序尝试（bd ypsl：解析 v6 优先而本机 v6 不可达时回退后续地址；
    // Go net.Dialer 同语义）。
    let mut last_err: Option<io::Error> = None;
    for sock_addr in &addrs {
        // TUN 接管的 DNS 服务器：Xray 自身上游查询拒拨（Go localdns
        // client.go:99-103 同语义），跳过该候选试后续地址。
        if xray_transport::dns_skip::is_skipped_dns_query(*sock_addr) {
            tracing::debug!(target: "xray.dns.doh", what = %what, addr = %sock_addr,
                "skipped DNS server");
            last_err = Some(io::Error::other(format!("skipped DNS server {sock_addr}")));
            continue;
        }
        match tokio::time::timeout(query_timeout, tokio::net::TcpStream::connect(sock_addr)).await {
            Ok(Ok(tcp)) => {
                return Ok(Box::new(xray_transport::connection::TcpConnection::new(tcp)));
            },
            Ok(Err(e)) => {
                tracing::debug!(target: "xray.dns.doh", what = %what, addr = %sock_addr,
                    error = %e, "doh: connect failed");
                last_err = Some(e);
            },
            Err(_) => {
                tracing::debug!(target: "xray.dns.doh", what = %what, addr = %sock_addr,
                    "doh: connect TIMEOUT");
                last_err = Some(io::Error::new(io::ErrorKind::TimedOut, "connect timeout"));
            },
        }
    }
    Err(crate::error::DnsError::WireFormat(format!(
        "{what} dial failed after {} addr(s): {}",
        addrs.len(),
        last_err.map(|e| e.to_string()).unwrap_or_else(|| "no address attempted".into())
    )))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use xray_common::net::{address::Address, port::Port};
    use xray_transport::link::Link;

    use super::*;
    /// 共享 dialer 槽是进程级全局：涉槽测试须串行（全 crate 共用一把锁）。
    use crate::dial::DIALER_SLOT_LOCK;

    /// 记录调用次数的 dialer：任何拨号都计数并返回错误（走不到真流）。
    struct MarkingDialer {
        calls: AtomicUsize,
    }
    impl QueryDialer for MarkingDialer {
        fn dial_tcp(
            &self,
            _dest: &Destination,
        ) -> Pin<Box<dyn Future<Output = io::Result<DnsStream>> + Send + '_>> {
            Box::pin(async {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Err(io::Error::other("dialer invoked"))
            })
        }

        fn dial_udp(
            &self,
            _dest: &Destination,
        ) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn UdpPacketSession>>> + Send + '_>>
        {
            Box::pin(async {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Err(io::Error::other("dialer invoked"))
            })
        }
    }

    /// bd wmdn② 回归：共享 dialer 在场时，`force_local=true`（`+local`）的查询
    /// 绕过 dialer 强制直连（Go nameserver.go:51-61 Local mode 传 nil
    /// dispatcher）；`force_local=false` 的查询必须经共享 dialer 路由出站
    /// （bd mcpo 验收②，bd 34nk 回滚 P0 旁路后恢复）。
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // 测试全局槽位锁刻意跨 await 串行化（无争用场景）
    async fn connect_stream_force_local_bypasses_shared_dialer() {
        let _slot = DIALER_SLOT_LOCK.lock();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let dest = Destination::tcp(Address::from(addr.ip()), Port::new(addr.port()));

        let dialer = Arc::new(MarkingDialer { calls: AtomicUsize::new(0) });
        set_shared_dialer(Some(dialer.clone() as Arc<dyn QueryDialer>));

        // force_local=true：直连 listener 成功，dialer 不被调用。
        let resolver = SystemHostResolver;
        let stream = connect_stream(&dest, &resolver, Duration::from_secs(2), "tcp", true)
            .await
            .expect("force_local 应直连（IP 目标无需解析）");
        drop(stream);
        assert_eq!(dialer.calls.load(Ordering::SeqCst), 0, "force_local 不得走共享 dialer");

        // force_local=false：必须走共享 dialer（dialer 故意返回错误 → 查询失败）。
        let err = match connect_stream(&dest, &resolver, Duration::from_secs(2), "tcp", false).await
        {
            Ok(_) => panic!("force_local=false 应走共享 dialer（dialer 返回错误）"),
            Err(e) => e,
        };
        assert!(
            matches!(&err, crate::error::DnsError::WireFormat(s) if s.contains("dialer invoked")),
            "unexpected error: {err:?}"
        );
        assert_eq!(dialer.calls.load(Ordering::SeqCst), 1, "非 local 查询必须走共享 dialer");

        set_shared_dialer(None);
    }

    /// duplex 管道 → Link → LinkStream 字节 roundtrip。
    #[tokio::test]
    #[allow(clippy::let_unit_value)] // 存量清零批次：let_unit_value
    async fn link_stream_roundtrip() {
        #[allow(unused_mut)] // 存量清零批次
        let (mut peer_r, mut peer_w) = tokio::io::duplex(64 * 1024);
        let (up_r, mut up_w) = tokio::io::duplex(64 * 1024);
        let link = xray_transport::link::Link::new(
            xray_buf::io::new_reader(up_r),
            xray_buf::io::new_writer(peer_w),
        );
        let Link { reader, writer } = link;
        let mut stream = LinkStream::new(reader, writer);

        // 写经 LinkStream → pipe → 对端。
        stream.write_all(b"ping-bytes").await.unwrap();
        stream.flush().await.unwrap();

        // 对端回写 → LinkStream 读。
        let _ = up_w.write_all(b"pong-bytes").await.unwrap();
        let mut buf = [0u8; 10];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong-bytes");

        // 对端直接读我们写的。
        drop(stream); // shutdown → pipe close
        let mut echo = Vec::new();
        peer_r.read_to_end(&mut echo).await.unwrap();
        assert_eq!(echo, b"ping-bytes");
    }

    /// 对端 shutdown → LinkStream 读到 0 字节（EOF）。
    #[tokio::test]
    async fn link_stream_eof_on_close() {
        let (up_r, up_w) = tokio::io::duplex(1024);
        let (dn_r, dn_w) = tokio::io::duplex(1024);
        let link = xray_transport::link::Link::new(
            xray_buf::io::new_reader(dn_r),
            xray_buf::io::new_writer(up_w),
        );
        drop(up_r); // 对端写端关闭 → 读端 EOF
        let Link { reader, writer } = link;
        drop(dn_w);
        let mut stream = LinkStream::new(reader, writer);
        let mut buf = [0u8; 4];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(n, 0, "closed link must read as EOF");
    }

    /// 跨多次 poll 的大块数据（MultiBuffer pending 交付路径）。
    #[tokio::test]
    async fn link_stream_large_payload() {
        let (_up_r, up_w) = tokio::io::duplex(256 * 1024);
        let (dn_r, mut dn_w) = tokio::io::duplex(256 * 1024);
        let link = xray_transport::link::Link::new(
            xray_buf::io::new_reader(dn_r),
            xray_buf::io::new_writer(up_w),
        );
        let Link { reader, writer } = link;
        let mut stream = LinkStream::new(reader, writer);

        let payload = vec![0xA5u8; 100_000];
        let writer_task = tokio::spawn(async move {
            dn_w.write_all(&payload).await.unwrap();
            drop(dn_w);
        });
        let mut received = Vec::new();
        stream.read_to_end(&mut received).await.unwrap();
        writer_task.await.unwrap();
        assert_eq!(received.len(), 100_000);
        assert!(received.iter().all(|&b| b == 0xA5));
    }

    /// 回归（bd 34nk）：LinkStream 读端必须被下行 pipe 数据唤醒。
    ///
    /// 修复前 `LinkStream::poll_read` 每次 poll 新建并丢弃 read future →
    /// pipe 读端 `Notify` waiter 注册随 future 丢弃销毁 → 下行数据到达不再
    /// 唤醒读端（DoH 应答被压到调用方 `query_timeout` 才交付，4s 台阶）。
    #[tokio::test]
    async fn link_stream_pipe_read_woken_by_downlink_data() {
        let (dn_r, mut dn_w) = xray_buf::pipe::new();
        let (_up_r, up_w) = xray_buf::pipe::new();
        let mut stream = LinkStream::new(Box::new(dn_r), Box::new(up_w));

        // 下行数据稍后到达（模拟 dispatcher 管线回包）
        let writer_task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let mut mb = MultiBuffer::new();
            mb.write_from(b"hello");
            dn_w.write_multi_buffer(mb).await.unwrap();
        });

        let mut buf = [0u8; 5];
        // 超时给足（3s）：tokio `Timeout` 先 poll inner 再查 deadline，丢唤醒时
        // 数据会在 deadline 那一刻才被交付（tokio 的 Timeout 先 poll inner 的
        // 副作用）——故用「交付时刻」而非「是否拿到数据」判定唤醒是否丢失。
        let start = std::time::Instant::now();
        let res = tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut buf)).await;
        let elapsed = start.elapsed();
        writer_task.await.unwrap();
        assert!(res.is_ok(), "LinkStream 读端未取到下行数据");
        assert_eq!(&buf, b"hello");
        assert!(
            elapsed < Duration::from_millis(500),
            "LinkStream 读端未被下行数据唤醒（丢唤醒）：数据在 {elapsed:?} 才交付（等超时轮询）"
        );
    }

    /// 回归（bd d881③）：满管道下经 LinkStream 写入不丢数据。
    ///
    /// 写路径直驱 poll 形态（waker 槽跨 poll 存活，bd 34nk）；pipe 写端
    /// 全有全无消费（Pending 时 `mb` 原样留给调用方，pipe.rs `WriteAction::Wait`
    /// 不碰数据），tokio `AsyncWrite` 契约下调用方以同一 buf 重试——
    /// N 字节进，N 字节出。
    #[tokio::test]
    async fn link_stream_full_pipe_write_delivers_every_byte() {
        let (dn_r, _dn_w) = xray_buf::pipe::new();
        // uplink 管道（LinkStream 写端 → 远端）：4KB 上限制造满管道阻塞。
        let (mut up_r, up_w) = xray_buf::pipe::new_with_option(xray_buf::pipe::PipeOption {
            limit: 4096,
            ..Default::default()
        });
        let stream = LinkStream::new(Box::new(dn_r), Box::new(up_w));

        const TOTAL: usize = 64 * 1024;
        let payload: Vec<u8> = (0..TOTAL).map(|i| i as u8).collect();
        let expected = payload.clone();

        let (_rd, mut wr) = tokio::io::split(stream);
        let w_task = tokio::spawn(async move {
            // 8KB 分块：第 2 块起管道已满（>4KB limit），必须走 Pending 重试路径。
            for chunk in payload.chunks(8 * 1024) {
                wr.write_all(chunk).await.unwrap();
            }
            AsyncWriteExt::shutdown(&mut wr).await.unwrap();
        });
        let r_task = tokio::spawn(async move {
            let mut received = Vec::new();
            loop {
                match up_r.read_multi_buffer().await {
                    Ok(mut mb) => {
                        let mut tmp = vec![0u8; mb.len()];
                        let n = mb.read_to(&mut tmp);
                        received.extend_from_slice(&tmp[..n]);
                    },
                    Err(xray_buf::io::Error::Eof) => break,
                    Err(e) => panic!("uplink read error: {e:?}"),
                }
            }
            received
        });

        let (w_res, r_res) = tokio::join!(
            tokio::time::timeout(Duration::from_secs(10), w_task),
            tokio::time::timeout(Duration::from_secs(10), r_task),
        );
        w_res.expect("满管道写未在 10s 内完成（疑似丢唤醒挂死）").unwrap();
        let received =
            r_res.expect("满管道读未在 10s 内完成（疑似丢唤醒挂死）").expect("reader task failed");
        assert_eq!(received.len(), TOTAL, "满管道下写入的字节必须全部可达远端");
        assert_eq!(received, expected, "字节必须逐一致（无丢失/重复/错序）");
    }

    /// dns_skip 测试的进程级集合守卫：测试退出即清除，防串扰其他用例。
    struct SkipDnsGuard;
    impl Drop for SkipDnsGuard {
        fn drop(&mut self) {
            xray_transport::dns_skip::skip_dns_servers(&[]);
        }
    }

    /// TUN 接管场景行为测例（Go localdns client.go:99-103 拒拨语义）：带上游查询
    /// 标记的直连拨号命中进程级 skip 集合 → 拒拨；集合清除后同目标恢复正常连接
    /// （默认零影响）。
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // 测试全局槽位锁刻意跨 await 串行化（无争用场景）
    async fn skipped_dns_server_rejected_on_direct_dial() {
        let _slot = DIALER_SLOT_LOCK.lock();
        let _skip = SkipDnsGuard;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = listener.local_addr().unwrap();
        let dest = Destination::tcp(Address::from(server.ip()), Port::new(server.port()));
        let resolver = SystemHostResolver;
        xray_transport::dns_skip::skip_dns_servers(&[server.ip()]);

        // 模拟「DNS 查询经出站发出」：带标记的上游查询 task 直连被 skip 的服务器。
        // （Ok 值 Box<dyn Connection> 无 Debug，expect_err 不可用，match 形态。）
        let err = match xray_transport::dns_skip::scope_dns_upstream_query(async {
            connect_stream(&dest, &resolver, Duration::from_secs(2), "tcp", true).await
        })
        .await
        {
            Ok(_) => panic!("被 skip 的 DNS 服务器应拒拨"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("skipped DNS server"), "unexpected error: {err}");

        // 集合清除（Go SkipDNSServers(nil) 语义）→ 同目标正常连接。
        xray_transport::dns_skip::skip_dns_servers(&[]);
        let stream = xray_transport::dns_skip::scope_dns_upstream_query(async {
            connect_stream(&dest, &resolver, Duration::from_secs(2), "tcp", true).await
        })
        .await
        .expect("集合清除后同目标应正常连接（默认零影响）");
        drop(stream);
    }

    /// task-local 隔离：同一目标同一时刻，带标记 task 拒拨、不带标记 task 正常
    /// 连接——并发互不串味（用户流量拨 DNS 服务器不受 skip 判定影响）。
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // 测试全局槽位锁刻意跨 await 串行化（无争用场景）
    async fn dns_skip_scope_isolation_across_tasks() {
        let _slot = DIALER_SLOT_LOCK.lock();
        let _skip = SkipDnsGuard;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = listener.local_addr().unwrap();
        let make_dest =
            move || Destination::tcp(Address::from(server.ip()), Port::new(server.port()));
        xray_transport::dns_skip::skip_dns_servers(&[server.ip()]);

        let marked = tokio::spawn(xray_transport::dns_skip::scope_dns_upstream_query(async move {
            connect_stream(&make_dest(), &SystemHostResolver, Duration::from_secs(2), "tcp", true)
                .await
                .is_err()
        }));
        let plain = tokio::spawn(async move {
            connect_stream(&make_dest(), &SystemHostResolver, Duration::from_secs(2), "tcp", true)
                .await
                .is_ok()
        });
        let (marked, plain) = tokio::join!(marked, plain);
        assert!(marked.unwrap(), "带标记 task 应拒拨被 skip 服务器");
        assert!(plain.unwrap(), "不带标记 task 不受影响，应正常连接");
    }
}
