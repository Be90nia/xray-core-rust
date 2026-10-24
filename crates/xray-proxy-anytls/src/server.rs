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

use std::{net::SocketAddr, sync::Arc};

use anytls::{
    AsyncReadWrite,
    core::{Command, Frame},
    proxy::session::{DEFAULT_SID, Session, new_server_session},
    runtime::DefaultPaddingFactory,
};
use sha2::{Digest, Sha256};
use skeleton_infra::fx::{FxScope, Spawned};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt, DuplexStream},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use tracing::debug;
use xray_app_dispatcher::DispatchHandler;
use xray_buf::io::{new_reader, new_writer};
use xray_common::{
    net::{address::Address as XAddress, destination::Destination, network::Network, port::Port},
    padding::validate_padding_len,
};
use xray_transport::link::Link;

use crate::{error::Result, socks::SocksAddr};

/// anytls duplex 缓冲（64 KiB，与 client.rs 一致）。
const DUPLEX_BUF_SIZE: usize = 64 * 1024;

/// 服务端握手/首包限时（绝对 deadline，从 accept 起算，覆盖 TLS 握手、认证帧
/// 读取、session 启动与 SOCKS5 target 首包）。产品缺省对齐 policy
/// `Timeouts.Handshake`（Go SessionDefault 60s 同源）；cfg(test) 收短为 100ms
/// （vless inbound 先例，静默连接超时测试可在秒级完成）。
#[cfg(not(test))]
fn handshake_timeout() -> std::time::Duration {
    xray_features::policy::DEFAULT_HANDSHAKE_TIMEOUT
}

#[cfg(test)]
fn handshake_timeout() -> std::time::Duration {
    std::time::Duration::from_millis(100)
}

/// 认证帧 padding0 长度上限（16 KiB − 34B 认证头 = 16350）。
///
/// Go 参考实现无显式常量，有效上界来自首包缓冲：anytls-go
/// `cmd/server/inbound_tcp.go`（`handleTcpConnection`）`buf.NewPacket()` 单次
/// `ReadOnceFrom` 读入（容量 = sing `common/buf/buffer_standard.go` 的
/// `UDPBufferSize`，standard build 16 KiB），先读 32B password sha256 + 2B
/// padding0_len 再 `ReadBytes(paddingLen)`，任何一段超出已缓冲内容即 `io.EOF`
/// → fallback 拒连。即 Go 侧有效上界 = 16384 − 34 = 16350（sing
/// `with_low_memory` build 的 4096 更小，不取），客户端声明 16351..=16384 必被
/// Go 拒。Rust 侧读法不同（read_exact 跨段攒），此处按「客户端可声明上限」
/// 对齐同一判定值。
const MAX_PADDING0_LEN: usize = 16 * 1024 - 34;

/// AnyTLS mock 服务端句柄，`stop()` 后 listener 关闭。
pub struct AnytlsMockServer {
    pub local_addr: SocketAddr,
    join: Spawned<()>,
    stop_tx: tokio::sync::oneshot::Sender<()>,
    /// 组件内自持托管 scope（B6，坑约束 5）：serve_loop/每连接/每会话任务记账，
    /// scope 随 MockServer drop 兜底 abort 在途任务（数据面 pump 同账本）。
    #[allow(dead_code)]
    // 仅经 drop glue 生效（JoinSet 随 drop abort），无直接读取——app 家族 B6 先例
    fx: Arc<FxScope>,
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
        Self::start_with_password(bind_addr, tls_acceptor, dispatch, None).await
    }

    /// 带密码校验启动（protocol.md Authentication）。
    ///
    /// TLS 握手完成后读 34 字节认证帧 `sha256(password)(32B) || padding0_len(BE u16)`，
    /// 对 `sha256(password)` 做常数时间比对（XOR 折叠，无早退分支），不匹配拒绝连接。
    /// `password` 为 None 时不校验（与既有 mock 行为一致，仅按帧格式读掉）。
    pub async fn start_with_password(
        bind_addr: SocketAddr,
        tls_acceptor: TlsAcceptor,
        dispatch: Option<Arc<dyn DispatchHandler>>,
        password: Option<&str>,
    ) -> Result<Self> {
        let expected_password_sha256: Option<[u8; 32]> =
            password.map(|p| Sha256::digest(p.as_bytes()).into());
        let listener = TcpListener::bind(bind_addr).await?;
        let local_addr = listener.local_addr()?;
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let fx = Arc::new(FxScope::new());
        let join = fx
            .spawn(serve_loop(
                listener,
                tls_acceptor,
                dispatch,
                expected_password_sha256,
                stop_rx,
                Arc::clone(&fx),
            ))
            .expect("internal FxScope is never closed");
        Ok(Self { local_addr, join, stop_tx, fx })
    }

    /// 停止 server 并等待 task 结束。
    pub async fn stop(self) {
        let _ = self.stop_tx.send(());
        let _ = self.join.join().await;
    }
}

async fn serve_loop(
    listener: TcpListener,
    tls_acceptor: TlsAcceptor,
    dispatch: Option<Arc<dyn DispatchHandler>>,
    expected_password_sha256: Option<[u8; 32]>,
    mut stop_rx: tokio::sync::oneshot::Receiver<()>,
    fx: Arc<FxScope>,
) {
    loop {
        tokio::select! {
            _ = &mut stop_rx => break,
            res = listener.accept() => {
                let Ok((tcp, _peer)) = res else { continue };
                let tls_acceptor = tls_acceptor.clone();
                let dispatch = dispatch.clone();
                // 预制克隆传入 handle_conn：避免参数 move 与 spawn 接收者借用冲突（E0505）
                let fx_conn = Arc::clone(&fx);
                fx.spawn(handle_conn(
                    tcp,
                    tls_acceptor,
                    dispatch,
                    expected_password_sha256,
                    fx_conn,
                ))
                .expect("internal FxScope is never closed");
            }
        }
    }
}

async fn handle_conn(
    tcp: TcpStream,
    tls_acceptor: TlsAcceptor,
    dispatch: Option<Arc<dyn DispatchHandler>>,
    expected_password_sha256: Option<[u8; 32]>,
    fx: Arc<FxScope>,
) {
    // socket kill 通道：anytls-rs Session 不暴露底层连接，其 terminate() 是纯
    // 本地标记（不关 TLS socket、不唤醒阻塞在 TLS read 的 recv_loop）——没有它
    // 会话 fd 永不释放（s9 压测 fd +5222/min 根因）。持有 dup 句柄，会话流结束
    // 时 shutdown 双向，驱动本端 recv_loop 退出、Arc<Session> 全量 drop、fd 关闭。
    let tcp_std = match tcp.into_std() {
        Ok(s) => s,
        Err(e) => {
            debug!("anytls mock server: tcp into_std failed: {e}");
            return;
        },
    };
    let kill_sock = match tcp_std.try_clone() {
        Ok(s) => s,
        Err(e) => {
            debug!("anytls mock server: tcp try_clone failed: {e}");
            return;
        },
    };
    if let Err(e) = tcp_std.set_nonblocking(true) {
        debug!("anytls mock server: tcp set_nonblocking failed: {e}");
        return;
    }
    let tcp = match TcpStream::from_std(tcp_std) {
        Ok(s) => s,
        Err(e) => {
            debug!("anytls mock server: tcp from_std failed: {e}");
            return;
        },
    };
    let (kill_tx, kill_rx) = tokio::sync::oneshot::channel::<()>();
    fx.spawn(async move {
        if kill_rx.await.is_ok() {
            let _ = kill_sock.shutdown(std::net::Shutdown::Both);
        }
    })
    .expect("internal FxScope is never closed");
    // 握手/首包绝对 deadline：对端 accept 后不发数据（或 TLS 后不发认证帧）时，
    // 到期关闭连接，防止静默连接永久占住任务与 fd（bd v57c）。
    let handshake_deadline = tokio::time::Instant::now() + handshake_timeout();
    let mut tls: TlsStream<TcpStream> =
        match tokio::time::timeout_at(handshake_deadline, tls_acceptor.accept(tcp)).await {
            Ok(Ok(t)) => t,
            Ok(Err(e)) => {
                debug!("anytls mock server TLS accept failed: {e}");
                return;
            },
            Err(_) => {
                debug!(
                    "anytls mock server: handshake timeout after {:?}, closing silent \
                     connection (TLS accept)",
                    handshake_timeout()
                );
                return;
            },
        };
    // 读取并校验客户端认证帧（protocol.md Authentication）：
    // `sha256(password)`(32B) || padding0 长度（BE u16）|| padding0。
    // expected 为 None 时不校验密码，但仍必须按帧格式读掉，
    // 否则 auth 字节会被 session loop 误解析为 session frame。
    let mut auth_head = [0u8; 34];
    if let Err(e) = tokio::time::timeout_at(handshake_deadline, tls.read_exact(&mut auth_head))
        .await
        .unwrap_or_else(|_| {
            Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "anytls auth head timeout"))
        })
    {
        debug!("anytls mock server: read auth head failed: {e}");
        return;
    }
    if let Some(expected) = expected_password_sha256 {
        // 常数时间比对（XOR 折叠，无早退分支；32B 等长由类型保证）
        let mismatch =
            auth_head[..32].iter().zip(expected.iter()).fold(0u8, |acc, (a, b)| acc | (a ^ b));
        if mismatch != 0 {
            debug!("anytls mock server: auth rejected (password mismatch)");
            return;
        }
    }
    let padding0_len = u16::from_be_bytes([auth_head[32], auth_head[33]]) as usize;
    if validate_padding_len(padding0_len as u64, MAX_PADDING0_LEN as u64).is_err() {
        debug!(
            "anytls mock server: auth rejected (padding0_len {padding0_len} > max \
             {MAX_PADDING0_LEN})"
        );
        return;
    }
    if padding0_len > 0 {
        let mut pad0 = vec![0u8; padding0_len];
        if let Err(e) = tokio::time::timeout_at(handshake_deadline, tls.read_exact(&mut pad0))
            .await
            .unwrap_or_else(|_| {
                Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "anytls padding0 timeout"))
            })
        {
            debug!("anytls mock server: read padding0 failed: {e}");
            return;
        }
    }
    let padding = DefaultPaddingFactory::load();
    // Fn 闭包不能 move out kill_tx：用 take 单次取出（回调单次触发由
    // anytls 单流模式的 handler_started 保护保证）。
    let kill_tx_cell = parking_lot::Mutex::new(Some(kill_tx));
    // 闭包用独立克隆：fx 本体留给下方 session_run spawn（E0382）
    let fx_session = Arc::clone(&fx);
    let on_new_session: Box<dyn Fn(Arc<Session>) + Send + Sync> = Box::new(move |session| {
        let dispatch = dispatch.clone();
        let kill_tx = kill_tx_cell.lock().take();
        let fx = Arc::clone(&fx_session);
        fx.spawn(handle_session(session, dispatch, kill_tx, handshake_deadline))
            .expect("internal FxScope is never closed");
    });
    let session = Arc::new(
        match tokio::time::timeout_at(
            handshake_deadline,
            new_server_session(Box::new(tls) as Box<dyn AsyncReadWrite>, on_new_session, padding),
        )
        .await
        {
            Ok(s) => s,
            Err(_) => {
                debug!(
                    "anytls mock server: handshake timeout after {:?}, closing silent \
                     connection (session setup)",
                    handshake_timeout()
                );
                return;
            },
        },
    );
    if let Err(e) = tokio::time::timeout_at(handshake_deadline, session.ensure_started())
        .await
        .unwrap_or_else(|_| Err(std::io::Error::other("anytls ensure_started timeout")))
    {
        debug!("anytls mock server: session ensure_started failed: {e}");
        return;
    }
    // spawn run 循环——主循环结束后 session 自然清理
    let session_run = session.clone();
    fx.spawn(async move {
        let _ = session_run.run().await;
    })
    .expect("internal FxScope is never closed");
}

/// 处理一个 incoming session：读 SOCKS5 target → 直连或 dispatcher 桥接。
///
/// SOCKS5 target 首包受 `first_packet_deadline` 限时（与握手段共用的绝对
/// deadline）：对端认证通过后不发首包，到期发 FIN + shutdown 关闭连接（bd v57c）。
async fn handle_session(
    session: Arc<Session>,
    dispatch: Option<Arc<dyn DispatchHandler>>,
    kill_tx: Option<tokio::sync::oneshot::Sender<()>>,
    first_packet_deadline: tokio::time::Instant,
) {
    // 1. 读 SOCKS5 target（首帧 application data）
    let mut buf = vec![0u8; 1024];
    let n = match tokio::time::timeout_at(first_packet_deadline, session.read(&mut buf)).await {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => {
            debug!("anytls mock server: read socks5 target failed: {e}");
            return;
        },
        Err(_) => {
            debug!(
                "anytls mock server: first packet timeout, closing silent connection \
                 (deadline elapsed)"
            );
            finish_session(&session, kill_tx).await;
            return;
        },
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
        },
    };

    if let Some(handler) = dispatch {
        // 生产路径：dispatcher/router 分发。
        // Link 的 reader 用 InitialedReader{consumed 前缀 + duplex read_half}
        // ——reader 先吐出多读的 payload，再透传 session 后续 application data。
        // writer 用 duplex write_half，dispatcher 关闭 writer 时 pump 收到 EOF。
        let dest = socks_to_destination(&target);
        let (client_io, server_io) = tokio::io::duplex(DUPLEX_BUF_SIZE);
        let (rd_half, wr_half) = tokio::io::split(client_io);
        #[allow(
            clippy::disallowed_methods,
            reason = "存量债：未接 PluginContext 托管句柄，接线归 P1 插件装配（B3 T3.1 登记）"
        )]
        tokio::spawn(pump_session_to_duplex(session.clone(), server_io));
        let reader = new_reader(InitialedReader::new(buf[consumed..n].to_vec(), rd_half));
        let writer = new_writer(wr_half);
        let link = Link::new(reader, writer);
        handler.dispatch(&dest, link).await;
        // dispatch 返回后 dispatch handle 已 drop，pump 随 duplex EOF 退出；
        // 按 FIN + shutdown 收尾释放会话（同 mock 直连分支）。
        finish_session(&session, kill_tx).await;
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
            },
        };

        if n > consumed {
            if let Err(e) = outbound.write_all(&buf[consumed..n]).await {
                debug!("anytls mock server: forward extra failed: {e}");
                return;
            }
        }

        if let Err(e) = bridge(session.clone(), outbound).await {
            debug!("anytls mock server: bridge ended: {e}");
        }
        finish_session(&session, kill_tx).await;
    }
}

/// 会话流结束收尾：按协议发 FIN + 标记本地半关，然后 shutdown 底层 TCP。
///
/// FIN 让客户端收到干净 EOF（数据先于连接关闭送达）；shutdown 驱动本端
/// recv_loop 退出 → `run()` 结束 → Arc<Session> 全量 drop → TLS fd 释放。
/// anytls-rs 的 terminate() 做不到后者（纯本地标记），单流会话里它是 fd
/// 挂死的根因（s9 压测）。
async fn finish_session(session: &Session, kill_tx: Option<tokio::sync::oneshot::Sender<()>>) {
    let _ = session.write_frame(Frame::new(Command::Fin, DEFAULT_SID)).await;
    let _ = session.mark_local_stream_closed(DEFAULT_SID).await;
    if let Some(kill_tx) = kill_tx {
        let _ = kill_tx.send(());
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
                },
                Err(e) => {
                    debug!("pump session→duplex read: {e}");
                    break;
                },
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
                },
                Err(e) => {
                    debug!("pump duplex→session read: {e}");
                    break;
                },
            }
        }
        // 会话收尾（FIN + shutdown）由 handle_session::finish_session 统一执行。
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
        Self { initial: std::io::Cursor::new(initial), inner }
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
                Ok(n) => {
                    let _ = session.write(&buf[..n]).await?;
                },
                Err(e) => return Err(e),
            }
        }
        // 会话收尾（FIN + shutdown）由 handle_session::finish_session 统一执行。
        Ok::<_, std::io::Error>(())
    };
    tokio::try_join!(down, up)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    /// Go anytls-go 有效上界：sing standard build 首包缓冲 16384 − 34B 认证头。
    #[test]
    fn max_padding0_len_matches_go_effective_bound() {
        assert_eq!(super::MAX_PADDING0_LEN, 16 * 1024 - 34);
    }

    use rustls::{ClientConfig as RustlsClientConfig, ServerConfig as RustlsServerConfig};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::client::{AnytlsClient, ClientConfig};

    /// 简单 echo TCP server（tests/loopback.rs 同款）。
    async fn start_echo_server() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else { break };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    loop {
                        match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if sock.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            },
                        }
                    }
                });
            }
        });
        addr
    }

    /// rcgen 自签证书 → (server config, cert DER)。
    fn make_server_config() -> (RustlsServerConfig, Vec<u8>) {
        use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
        let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, "localhost");
        let key_pair = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        let cert_der = cert.der().clone();
        let rustls_cert = rustls::pki_types::CertificateDer::from(cert_der.to_vec());
        let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der());
        let config = RustlsServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![rustls_cert], key_der.into())
            .unwrap();
        (config, cert_der.to_vec())
    }

    async fn start_server_with_password(password: Option<&str>) -> (AnytlsMockServer, Vec<u8>) {
        let (cfg, cert_der) = make_server_config();
        let server = AnytlsMockServer::start_with_password(
            "127.0.0.1:0".parse().unwrap(),
            TlsAcceptor::from(Arc::new(cfg)),
            None,
            password,
        )
        .await
        .expect("start server");
        (server, cert_der)
    }

    fn make_client(
        server_addr: SocketAddr,
        password: &str,
        server_cert_der: &[u8],
    ) -> AnytlsClient {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(server_cert_der.to_vec().into()).unwrap();
        let tls = Arc::new(
            RustlsClientConfig::builder().with_root_certificates(root_store).with_no_client_auth(),
        );
        AnytlsClient::new(ClientConfig::new(server_addr.to_string(), "localhost", password, tls))
    }

    /// 对密码：认证通过，端到端 echo 完整走通。
    #[tokio::test]
    async fn correct_password_end_to_end_echo() {
        let echo = start_echo_server().await;
        let (server, cert_der) = start_server_with_password(Some("s3cret")).await;
        let client = make_client(server.local_addr, "s3cret", &cert_der);
        let mut conn =
            client.dial(&SocksAddr::from_socket(echo)).await.expect("dial with correct password");
        conn.write_all(b"ping").await.expect("write");
        let mut buf = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(5), conn.read_exact(&mut buf))
            .await
            .expect("read within timeout")
            .expect("echo read");
        assert_eq!(&buf, b"ping");
        client.close().await.ok();
        server.stop().await;
    }

    /// 带活跃连接计数的 echo server：断言 client 流结束后服务端连接被释放。
    async fn start_tracked_echo_server() -> (SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
        let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let active_spawn = active.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else { break };
                active_spawn.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let counter = active_spawn.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    loop {
                        match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if sock.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            },
                        }
                    }
                    counter.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                });
            }
        });
        (addr, active)
    }

    /// s9 fd 泄漏回归：client 流结束（写 FIN）后，服务端 session/TLS 必须释放——
    /// echo 计数归零。修复前 terminate() 不发 FIN 不关 socket，计数永不归零。
    #[tokio::test]
    async fn stream_close_releases_server_connection() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (echo, active) = start_tracked_echo_server().await;
        let (server, cert_der) = start_server_with_password(Some("s3cret")).await;
        let client = make_client(server.local_addr, "s3cret", &cert_der);
        let mut conn = client.dial(&SocksAddr::from_socket(echo)).await.expect("dial");
        conn.write_all(b"ping").await.expect("write");
        let mut buf = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(5), conn.read_exact(&mut buf))
            .await
            .expect("read within timeout")
            .expect("echo read");
        assert_eq!(&buf, b"ping");
        drop(conn);

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            if active.load(std::sync::atomic::Ordering::SeqCst) == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(
            active.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "server-side echo connection must be released after client stream close"
        );
        client.close().await.ok();
        server.stop().await;
    }

    /// 错密码：认证帧比对失败，连接被拒，数据永远到不了 echo。
    #[tokio::test]
    async fn wrong_password_rejected() {
        let echo = start_echo_server().await;
        let (server, cert_der) = start_server_with_password(Some("s3cret")).await;
        let client = make_client(server.local_addr, "wrong", &cert_der);
        // 客户端侧拨号可能在本地 duplex 提前返回 Ok；断言点：数据到不了 echo
        //（读侧 EOF/错误，或 5s 内读不到回显即失败）。
        match client.dial(&SocksAddr::from_socket(echo)).await {
            Err(_) => {}, // 拨号即失败也算拒绝证据
            Ok(mut conn) => {
                let _ = conn.write_all(b"ping").await;
                let mut buf = [0u8; 4];
                match tokio::time::timeout(Duration::from_secs(5), conn.read_exact(&mut buf)).await
                {
                    Ok(Ok(n)) => {
                        assert_ne!(&buf[..n], b"ping", "wrong-password data must never be echoed")
                    },
                    Ok(Err(_)) => {}, // 服务端拒后连接断开
                    Err(_) => panic!("wrong-password connection stayed open (timeout)"),
                }
            },
        }
        client.close().await.ok();
        server.stop().await;
    }

    /// bd 8tfh：padding0_len 由客户端 u16 控制（最大 65535），超上限必须在
    /// `vec![0u8; padding0_len]` 分配前拒绝——用裸 TLS 直连绕过 AnytlsClient。
    #[tokio::test]
    async fn oversized_padding0_len_rejected() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (server, cert_der) = start_server_with_password(Some("s3cret")).await;
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(cert_der.into()).unwrap();
        let tls = Arc::new(
            RustlsClientConfig::builder().with_root_certificates(root_store).with_no_client_auth(),
        );
        let connector = tokio_rustls::TlsConnector::from(tls);
        let tcp = TcpStream::connect(server.local_addr).await.expect("tcp connect");
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let mut tls_stream = connector.connect(server_name, tcp).await.expect("tls handshake");

        // 认证帧：正确 sha256(password) + padding0_len = u16::MAX（不跟随 padding 字节）。
        let mut frame = Vec::with_capacity(34);
        frame.extend_from_slice(&Sha256::digest(b"s3cret"));
        frame.extend_from_slice(&u16::MAX.to_be_bytes());
        tls_stream.write_all(&frame).await.expect("write auth head");

        // 断言点：服务端在上限校验处直接丢弃连接，不等 65535 字节 padding。
        let mut buf = [0u8; 1];
        match tokio::time::timeout(Duration::from_secs(2), tls_stream.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => {}, // EOF / 连接重置 = 拒绝
            Ok(Ok(n)) => panic!("server sent {n} byte(s) instead of dropping the connection"),
            Err(_) => panic!("oversized padding0_len connection stayed open (2s timeout)"),
        }
        server.stop().await;
    }

    /// bd v57c：TLS 握手完成后不发认证帧（静默对端）→ 服务端握手限时到期
    /// 关闭连接，客户端读到 EOF/RST，连接不永久挂起。cfg(test) 下限时收短
    /// 为 100ms（见 handshake_timeout()）。
    #[tokio::test]
    async fn server_closes_connection_after_first_packet_timeout() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (server, cert_der) = start_server_with_password(Some("s3cret")).await;
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(cert_der.into()).unwrap();
        let tls = Arc::new(
            RustlsClientConfig::builder().with_root_certificates(root_store).with_no_client_auth(),
        );
        let connector = tokio_rustls::TlsConnector::from(tls);
        let tcp = TcpStream::connect(server.local_addr).await.expect("tcp connect");
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let mut tls_stream = connector.connect(server_name, tcp).await.expect("tls handshake");

        // 故意不发认证帧，保持静默；断言服务端在限时内关闭连接。
        let started = std::time::Instant::now();
        let mut buf = [0u8; 1];
        match tokio::time::timeout(Duration::from_secs(5), tls_stream.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => {}, // EOF / RST = 服务端按期关闭
            Ok(Ok(n)) => panic!("server sent {n} byte(s) instead of closing"),
            Err(_) => {
                panic!("silent connection stayed open beyond 5s (elapsed {:?})", started.elapsed())
            },
        }
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "close must fire at the injected handshake timeout, took {:?}",
            started.elapsed()
        );
        server.stop().await;
    }
}
