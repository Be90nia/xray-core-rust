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

/// 系统解析器：每查询现解析（hickory TokioResolver，4s 超时）。
///
/// 票内"域名 NS 运行期解析"：上游 IP 变更后新查询自然用新 IP，
/// 无启动期钉死缓存。
pub struct SystemHostResolver;

impl HostResolver for SystemHostResolver {
    fn resolve(
        &self,
        host: String,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send>> {
        Box::pin(async move {
            let resolver = hickory_resolver::TokioResolver::builder_tokio()
                .map_err(|e| io::Error::other(format!("resolver builder: {e}")))?
                .build()
                .map_err(|e| io::Error::other(format!("resolver build: {e}")))?;
            let lookup = tokio::time::timeout(
                Duration::from_secs(4),
                resolver.lookup_ip(format!("{host}.")),
            )
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, format!("resolve {host} timeout"))
            })?
            .map_err(|e| io::Error::other(format!("resolve {host}: {e}")))?;
            Ok(lookup.iter().collect())
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
    fn recv_packet(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = io::Result<Option<Vec<u8>>>> + Send + '_>>;
}

/// DNS 查询拨号器（Go `routing.Dispatcher` 在 DNS 查询场景的用法）。
pub trait QueryDialer: Send + Sync {
    /// 建立到 `dest` 的流式链路（Go nameserver_tcp.go:43-47 / dohnameserver.go:68）。
    fn dial_tcp(
        &self,
        dest: &Destination,
    ) -> Pin<Box<dyn Future<Output = io::Result<DnsStream>> + Send + '_>>;

    /// 建立 UDP 数据报会话（Go nameserver_udp.go:134）。
    fn dial_udp(
        &self,
        dest: &Destination,
    ) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn UdpPacketSession>>> + Send + '_>>;
}

// ========== 进程级共享槽（fakedns 9vu4 同模式） ==========

static SHARED_DIALER: RwLock<Option<Arc<dyn QueryDialer>>> = RwLock::new(None);

/// 注入/清除共享 dialer。装配层 dispatcher init 完成后调用；测试用 `None` 复位。
pub fn set_shared_dialer(dialer: Option<Arc<dyn QueryDialer>>) {
    *SHARED_DIALER.write() = dialer;
}

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
            let got = {
                let mut fut = this.reader.read_multi_buffer();
                fut.as_mut().poll(cx)
            };
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
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e.to_string())));
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
        let got = {
            let mut fut = this.writer.write_multi_buffer(mb);
            fut.as_mut().poll(cx)
        };
        match got {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Err(xray_buf::io::Error::Eof)) => {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "link closed")))
            },
            Poll::Ready(Err(e)) => {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e.to_string())))
            },
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

/// 把 `dest` 解析为可直连的 `SocketAddr`：IP 直返；域名经 resolver 现解析。
pub(crate) async fn resolve_dest_addr(
    dest: &Destination,
    resolver: &dyn HostResolver,
) -> io::Result<SocketAddr> {
    let port = dest.port().value();
    if let Some(ip) = dest.address().ip() {
        return Ok(SocketAddr::new(ip, port));
    }
    let host = dest
        .address()
        .as_domain()
        .ok_or_else(|| io::Error::other("empty destination address"))?
        .to_string();
    let ips = resolver.resolve(host).await?;
    ips.into_iter()
        .next()
        .map(|ip| SocketAddr::new(ip, port))
        .ok_or_else(|| io::Error::other("resolver returned no address"))
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
    let sock_addr = resolve_dest_addr(dest, resolver)
        .await
        .map_err(|e| crate::error::DnsError::WireFormat(format!("{what} resolve: {e}")))?;
    let tcp = tokio::time::timeout(query_timeout, tokio::net::TcpStream::connect(sock_addr))
        .await
        .map_err(|_| {
            crate::error::DnsError::WireFormat(format!(
                "{what} connect timeout after {query_timeout:?}"
            ))
        })?
        .map_err(|e| crate::error::DnsError::WireFormat(format!("{what} connect: {e}")))?;
    Ok(Box::new(xray_transport::connection::TcpConnection::new(tcp)))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use xray_common::net::{address::Address, port::Port};
    use xray_transport::link::Link;

    use super::*;

    /// 共享 dialer 槽是进程级全局：涉槽测试须串行（udp.rs DIALER_SLOT_LOCK 同款）。
    static DIALER_SLOT_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

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

    /// bd wmdn② 回归：共享 dialer 在场时，`force_local=true` 的查询绕过
    /// dialer 强制直连（Go nameserver.go:51-61 Local mode 传 nil dispatcher）；
    /// `force_local=false` 仍走 dialer。
    #[tokio::test]
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

        // force_local=false：走共享 dialer（此处 dialer 报错即证据）。
        let r = connect_stream(&dest, &resolver, Duration::from_secs(2), "tcp", false).await;
        assert!(r.is_err(), "共享 dialer 返回错误 → connect_stream 失败");
        assert_eq!(dialer.calls.load(Ordering::SeqCst), 1, "非 local 应走共享 dialer");

        set_shared_dialer(None);
    }

    /// duplex 管道 → Link → LinkStream 字节 roundtrip。
    #[tokio::test]
    async fn link_stream_roundtrip() {
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
        let (up_r, up_w) = tokio::io::duplex(256 * 1024);
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
}
