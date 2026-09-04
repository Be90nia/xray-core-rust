//! AnyTLS 服务端实现——loopback 直连 + dispatcher 接入两种模式。
//!
//! 协议要求：服务端接到新 session 后，从 session 首帧读 SOCKS5 目标地址：
//! - `dispatch = Some(h)`：构造 Destination + Link → `h.dispatch(&dest, link)`
//!   （reader=InitialedReader{consumed}, writer=SessionBridge{duplex}）。
//! - `dispatch = None`：直连 TCP（仅 loopback 测试）。
//!
//! 桥接策略：Session 仅暴露 `async fn read/write(&self, ...)`，非 `AsyncRead`
//! trait。在 `poll_read/poll_write` 里直接 poll future 会遇到 buf 生命周期问题。
//! 复用 client.rs 的 `duplex + pump` 模式：构造 `tokio::io::duplex(64KiB)`，
//! server_io 端交给 Session pump，client_io 端供 InitialedReader/Link 用。
//!
//! 见 bd Xray-core-rust-dax。

use std::net::SocketAddr;
use std::sync::Arc;

use anytls::proxy::session::{Session, new_server_session};
use anytls::runtime::DefaultPaddingFactory;
use anytls::AsyncReadWrite;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use tracing::debug;

use xray_app_dispatcher::DispatchHandler;
use xray_buf::io::{new_reader, new_writer};
use xray_common::net::address::Address as XAddress;
use xray_common::net::destination::Destination;
use xray_common::net::network::Network;
use xray_common::net::port::Port;
use xray_transport::link::Link;

use crate::error::Result;
use crate::socks::SocksAddr;

/// anytls duplex 缓冲（64 KiB，与 client.rs 一致）。
const DUPLEX_BUF_SIZE: usize = 64 * 1024;


/// AnyTLS mock 服务端句柄，`stop()` 后 listener 关闭。
pub struct AnytlsMockServer {
    pub local_addr: SocketAddr,
    join: tokio::task::JoinHandle<()>,
    stop_tx: tokio::sync::oneshot::Sender<()>,
}

impl AnytlsMockServer {
    /// 启动 mock server。`tls_acceptor` 决定证书；listener 绑定到 `bind_addr`。
    /// `dispatch` 为 Some 时，session 内流量经 dispatcher/router 分发；为 None 时
    /// 直连 TCP（仅供 loopback 测试）。
    pub async fn start(
        bind_addr: SocketAddr,
        tls_acceptor: TlsAcceptor,
        dispatch: Option<Arc<dyn DispatchHandler>>,
    ) -> Result<Self> {
        let listener = TcpListener::bind(bind_addr).await?;
        let local_addr = listener.local_addr()?;
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let join = tokio::spawn(serve_loop(listener, tls_acceptor, dispatch, stop_rx));
        Ok(Self {
            local_addr,
            join,
            stop_tx,
        })
    }


    /// 停止 server 并等待 task 结束。
    pub async fn stop(self) {
        let _ = self.stop_tx.send(());
        let _ = self.join.await;
    }
}

async fn serve_loop(
    listener: TcpListener,
    tls_acceptor: TlsAcceptor,
    dispatch: Option<Arc<dyn DispatchHandler>>,
    mut stop_rx: tokio::sync::oneshot::Receiver<()>,
) {
    loop {
        tokio::select! {
            _ = &mut stop_rx => break,
            res = listener.accept() => {
                let Ok((tcp, _peer)) = res else { continue };
                let tls_acceptor = tls_acceptor.clone();
                let dispatch = dispatch.clone();
                tokio::spawn(handle_conn(tcp, tls_acceptor, dispatch));
            }
        }
    }
}


async fn handle_conn(
    tcp: TcpStream,
    tls_acceptor: TlsAcceptor,
    dispatch: Option<Arc<dyn DispatchHandler>>,
) {
    let mut tls: TlsStream<TcpStream> = match tls_acceptor.accept(tcp).await {
        Ok(t) => t,
        Err(e) => {
            debug!("anytls mock server TLS accept failed: {e}");
            return;
        }
    };
    // 消费客户端认证帧（protocol.md Authentication）：
    // `sha256(password)`(32B) || padding0 长度（BE u16）|| padding0。
    // mock 不校验密码，但必须按帧格式读掉，否则 auth 字节会被 session loop 误解析为 session frame。
    let mut auth_head = [0u8; 34];
    if let Err(e) = tls.read_exact(&mut auth_head).await {
        debug!("anytls mock server: read auth head failed: {e}");
        return;
    }
    let padding0_len = u16::from_be_bytes([auth_head[32], auth_head[33]]) as usize;
    if padding0_len > 0 {
        let mut pad0 = vec![0u8; padding0_len];
        if let Err(e) = tls.read_exact(&mut pad0).await {
            debug!("anytls mock server: read padding0 failed: {e}");
            return;
        }
    }
    let padding = DefaultPaddingFactory::load();
    let on_new_session: Box<dyn Fn(Arc<Session>) + Send + Sync> = Box::new(move |session| {
        let dispatch = dispatch.clone();
        tokio::spawn(handle_session(session, dispatch));
    });
    let session = Arc::new(
        new_server_session(Box::new(tls) as Box<dyn AsyncReadWrite>, on_new_session, padding).await,
    );
    if let Err(e) = session.ensure_started().await {
        debug!("anytls mock server: session ensure_started failed: {e}");
        return;
    }
    // spawn run 循环——主循环结束后 session 自然清理
    let session_run = session.clone();
    tokio::spawn(async move {
        let _ = session_run.run().await;
    });
}


/// 处理一个 incoming session：读 SOCKS5 target → 直连或 dispatcher 桥接。
async fn handle_session(session: Arc<Session>, dispatch: Option<Arc<dyn DispatchHandler>>) {
    // 1. 读 SOCKS5 target（首帧 application data）
    let mut buf = vec![0u8; 1024];
    let n = match session.read(&mut buf).await {
        Ok(n) => n,
        Err(e) => {
            debug!("anytls mock server: read socks5 target failed: {e}");
            return;
        }
    };
    if n == 0 {
        debug!("anytls mock server: empty first read");
        return;
    }

    let (target, consumed) = match SocksAddr::decode(&buf[..n]) {
        Ok(v) => v,
        Err(e) => {
            debug!("anytls mock server: decode socks5 failed: {e}");
            return;
        }
    };

    if let Some(handler) = dispatch {
        // 生产路径：dispatcher/router 分发。
        // Link 的 reader 用 InitialedReader{consumed 前缀 + duplex read_half}
        // ——reader 先吐出多读的 payload，再透传 session 后续 application data。
        // writer 用 duplex write_half，dispatcher 关闭 writer 时 pump 收到 EOF。
        let dest = socks_to_destination(&target);
        let (client_io, server_io) = tokio::io::duplex(DUPLEX_BUF_SIZE);
        let (rd_half, wr_half) = tokio::io::split(client_io);
        tokio::spawn(pump_session_to_duplex(session.clone(), server_io));
        let reader = new_reader(InitialedReader::new(
            buf[consumed..n].to_vec(),
            rd_half,
        ));
        let writer = new_writer(wr_half);
        let link = Link::new(reader, writer);
        handler.dispatch(&dest, link).await;
        // dispatch 返回后 dispatch handle 已 drop，关闭 writer 半部让 pump 退出。
        if let Err(e) = session.terminate().await {
            debug!("anytls mock server: terminate after dispatch: {e}");
        }
    } else {
        // mock/直连路径（loopback 测试）。
        let target_str = match &target {
            SocksAddr::Domain(h, p) => format!("{h}:{p}"),
            SocksAddr::Ipv4(a) => a.to_string(),
            SocksAddr::Ipv6(a) => a.to_string(),
        };
        let mut outbound = match TcpStream::connect(&target_str).await {
            Ok(s) => s,
            Err(e) => {
                debug!("anytls mock server: dial target {target_str} failed: {e}");
                return;
            }
        };

        if n > consumed {
            if let Err(e) = outbound.write_all(&buf[consumed..n]).await {
                debug!("anytls mock server: forward extra failed: {e}");
                return;
            }
        }

        if let Err(e) = bridge(session, outbound).await {
            debug!("anytls mock server: bridge ended: {e}");
        }
    }
}

/// SOCKS5 地址 → xray Destination（TCP）。
fn socks_to_destination(addr: &SocksAddr) -> Destination {
    let (xaddr, p) = match addr {
        SocksAddr::Domain(h, port) => (XAddress::Domain(h.clone()), *port),
        SocksAddr::Ipv4(a) => (XAddress::IPv4(*a.ip()), a.port()),
        SocksAddr::Ipv6(a) => (XAddress::IPv6(*a.ip()), a.port()),
    };
    Destination::new(xaddr, Port::new(p), Network::TCP)
}

/// 双向桥接 anytls Session 与 `tokio::io::duplex` 的 server 端。
///
/// 与 client.rs::pump_stream 同一模式：任何一端 EOF/出错都终止。
async fn pump_session_to_duplex(session: Arc<Session>, server_io: DuplexStream) {
    let (mut rd, mut wr) = tokio::io::split(server_io);
    let session_down = session.clone();
    let down = async move {
        let mut buf = vec![0u8; 8 * 1024];
        loop {
            match session_down.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if wr.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    debug!("pump session→duplex read: {e}");
                    break;
                }
            }
        }
        let _ = wr.shutdown().await;
    };
    let up = async move {
        let mut buf = vec![0u8; 8 * 1024];
        loop {
            match rd.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if session.write(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    debug!("pump duplex→session read: {e}");
                    break;
                }
            }
        }
        let _ = session.terminate().await;
    };
    tokio::join!(down, up);
}

/// 前缀已读字节的 reader：先吐 `initial`，再透传内层流（dispatch Link 场景）。
struct InitialedReader<R> {
    initial: std::io::Cursor<Vec<u8>>,
    inner: R,
}

impl<R> InitialedReader<R> {
    fn new(initial: Vec<u8>, inner: R) -> Self {
        Self {
            initial: std::io::Cursor::new(initial),
            inner,
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for InitialedReader<R> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.initial.position() < self.initial.get_ref().len() as u64 {
            let unfilled = buf.initialize_unfilled();
            let n = std::io::Read::read(&mut self.initial, unfilled)
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            buf.advance(n);
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

/// 双向桥接 anytls Session 与 TcpStream（mock 直连路径）。
async fn bridge(session: Arc<Session>, outbound: TcpStream) -> std::io::Result<()> {
    let (mut rd, mut wr) = outbound.into_split();
    let session_down = session.clone();
    let down = async move {
        let mut buf = vec![0u8; 8 * 1024];
        loop {
            match session_down.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => wr.write_all(&buf[..n]).await?,
                Err(e) => return Err(e),
            }
        }
        let _ = wr.shutdown().await;
        Ok::<_, std::io::Error>(())
    };
    let up = async move {
        let mut buf = vec![0u8; 8 * 1024];
        loop {
            match rd.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => { let _ = session.write(&buf[..n]).await?; }
                Err(e) => return Err(e),
            }
        }
        let _ = session.terminate().await;
        Ok::<_, std::io::Error>(())
    };
    tokio::try_join!(down, up)?;
    Ok(())
}
