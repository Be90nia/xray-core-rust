//! Hysteria outbound → DialBridge 适配器。
//!
//! 把 [`HysteriaClient`]（QUIC stream）接入 dispatcher 的 [`DialBridge`]：
//! [`make_dial_fn`] 闭包内部 dial → `HysteriaClient::tcp()` → pump 桥接到 duplex。

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::sync::OnceCell;

use xray_app_dispatcher::default::DialFn;
use xray_common::net::address::Address;
use xray_common::net::destination::Destination;
use xray_common::net::network::Network;
use xray_common::net::port::Port;
use xray_transport::connection::Connection;
use xray_transport_hysteria::conn::{InterConn, InterStreamConn};
use xray_transport_hysteria::dialer::{
    ClientManager, DialDestination, HysteriaTransport,
};
use xray_transport_hysteria::proto_config::Config as ProtoConfig;
use xray_xudp::packet::{PacketError, PacketReader, PacketWriter};

use crate::config::HysteriaConfig;
use crate::protocol::{Defragger, UdpMessage};

/// Hysteria duplex 缓冲（与 tuic 一致：64 KiB）。
const DUPLEX_BUF_SIZE: usize = 64 * 1024;

/// XUDP GlobalID 长度（与 Go `xudp` 一致）。
const GLOBAL_ID_LEN: usize = 8;

/// 单个 UDP datagram 读缓冲上限。
const RECV_BUF_SIZE: usize = 65535;

/// Hysteria 连接包装：内部用 `tokio::io::duplex` 桥接底层连接。
///
/// - TCP：duplex 字节流 ↔ `InterStreamConn`（QUIC stream）
/// - UDP：duplex 内的 XUDP 帧流 ↔ `InterConn`（QUIC datagram session）
///
/// `_pump` 字段保证桥接 task 生命周期与连接一致——drop 时自动 abort。
pub struct HysteriaConnection {
    inner: DuplexStream,
    _pump: tokio::task::JoinHandle<()>,
}

impl AsyncRead for HysteriaConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for HysteriaConnection {
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

impl Connection for HysteriaConnection {
    fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(None)
    }
    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(None)
    }
}

impl HysteriaConnection {
    /// 从 InterStreamConn 构造：spawn pump 桥接，返回 duplex 客户端包装。
    fn from_stream(stream: Arc<InterStreamConn>) -> Self {
        let (client_io, server_io) = tokio::io::duplex(DUPLEX_BUF_SIZE);
        let pump = tokio::spawn(pump_hysteria_stream(stream, server_io));
        Self {
            inner: client_io,
            _pump: pump,
        }
    }
}

impl HysteriaConnection {
    /// 从 InterConn（UDP session）构造：spawn XUDP↔UdpMessage 桥接 pump。
    fn from_udp(conn: Arc<InterConn>, default_dest: Destination) -> Self {
        let (client_io, server_io) = tokio::io::duplex(DUPLEX_BUF_SIZE);
        let pump = tokio::spawn(pump_hysteria_udp(conn, server_io, default_dest));
        Self {
            inner: client_io,
            _pump: pump,
        }
    }
}

async fn pump_hysteria_stream(
    stream: Arc<InterStreamConn>,
    server_io: DuplexStream,
    ) {
    let (mut rd, mut wr) = tokio::io::split(server_io);
    let stream_down = Arc::clone(&stream);

    // up: duplex rd → hysteria stream write
    let up = async move {
        let mut buf = vec![0u8; 8 * 1024];
        loop {
            match rd.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = stream.write(&buf[..n]).await {
                        tracing::debug!("hysteria pump up write error: {e}");
                        break;
                    }
                }
                Err(e) => {
                    tracing::debug!("hysteria pump up read error: {e}");
                    break;
                }
            }
        }
        let _ = stream.close().await;
    };

    // down: hysteria stream read → duplex wr
    let down = async move {
        let mut buf = vec![0u8; 8 * 1024];
        loop {
            match stream_down.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = wr.write_all(&buf[..n]).await {
                        tracing::debug!("hysteria pump down write error: {e}");
                        break;
                    }
                }
                Err(e) => {
                    tracing::debug!("hysteria pump down read error: {e}");
                    break;
                }
            }
        }
        let _ = wr.shutdown().await;
    };

    tokio::join!(up, down);
}

/// XUDP 帧 ↔ hysteria UdpMessage 双向桥（对应 Go `Client.Process` UDP 分支）。
///
/// - up：duplex 字节流内的 XUDP 帧 → [`PacketReader`] 拆帧 → [`UdpMessage`]
///   （frag 0/1，per-packet target 或 default dest）→ [`InterConn::write`]。
/// - down：[`InterConn::read`] → [`UdpMessage::parse`] → [`Defragger`] →
///   回包来源 addr → XUDP 帧写回 duplex。
async fn pump_hysteria_udp(
    conn: Arc<InterConn>,
    server_io: DuplexStream,
    default_dest: Destination,
) {
    let (mut rd, mut wr) = tokio::io::split(server_io);
    let default_addr = dest_net_addr(&default_dest);
    let up_conn = Arc::clone(&conn);

    // up: duplex rd → XUDP 帧解析 → UdpMessage → InterConn write
    let up = async move {
        let mut accum: Vec<u8> = Vec::new();
        let mut buf = vec![0u8; 8 * 1024];
        loop {
            // 先把 accum 里所有完整帧消费掉
            let mut progress = true;
            while progress {
                match parse_and_forward(&up_conn, &mut accum, &default_addr).await {
                    Ok(made) => progress = made,
                    Err(e) => {
                        tracing::debug!("hysteria udp up forward error: {e}");
                        return;
                    }
                }
            }
            match rd.read(&mut buf).await {
                Ok(0) => return, // link EOF
                Ok(n) => accum.extend_from_slice(&buf[..n]),
                Err(e) => {
                    tracing::debug!("hysteria udp up read error: {e}");
                    return;
                }
            }
        }
    };

    // down: InterConn read → UdpMessage → Defragger → XUDP 帧 → duplex wr
    let close_conn = Arc::clone(&conn);
    let down = async move {
        let mut df = Defragger::new();
        let global_id: [u8; GLOBAL_ID_LEN] = rand::random();
        let mut buf = vec![0u8; RECV_BUF_SIZE];
        loop {
            let n = match conn.read(&mut buf).await {
                Ok(n) => n,
                Err(e) => {
                    tracing::debug!("hysteria udp down read error: {e}");
                    break;
                }
            };
            if n == 0 {
                break;
            }
            // UdpSessionManager 投递时已剥除 4B session id 信封（Go 由
            // ParseUDPMessage 读出、本桥不消费）→ 前补哑元对齐 8B 头布局
            let mut full = Vec::with_capacity(4 + n);
            full.extend_from_slice(&[0u8; 4]);
            full.extend_from_slice(&buf[..n]);
            // Go UDPReader.ReadFrom：解析/重组失败 continue 跳过
            let Ok(msg) = UdpMessage::parse(&full) else {
                continue;
            };
            let Some(msg) = df.feed(&msg) else {
                continue;
            };
            let Some(source) = parse_udp_source(&msg.addr) else {
                continue;
            };
            // 回包帧来源 = UdpMessage.addr（与 freedom pump_response 同款 per-packet 帧）
            let mut frame = Vec::with_capacity(msg.data.len() + 64);
            let mut pw = PacketWriter::new(&mut frame, source, global_id);
            if pw.write_packet(&msg.data).is_err() {
                break;
            }
            drop(pw);
            if wr.write_all(&frame).await.is_err() {
                break; // client 侧已关闭
            }
        }
        let _ = wr.shutdown().await;
    };

    tokio::select! {
        _ = up => {}
        _ = down => {}
    }
    let _ = close_conn.close().await;
}

/// 从 accum 前端解析一个 XUDP 帧 → `UdpMessage` → 写 InterConn。
///
/// 返回 `true` 表示有进展（消费了一帧）；accum 为空或帧不完整返回 `false`；
/// 致命错误返回 `Err`。
async fn parse_and_forward(
    conn: &Arc<InterConn>,
    accum: &mut Vec<u8>,
    default_addr: &str,
) -> io::Result<bool> {
    if accum.is_empty() {
        return Ok(false);
    }
    let (result, consumed) = {
        let mut cursor = std::io::Cursor::new(&accum[..]);
        let mut pr = PacketReader::new(&mut cursor);
        let r = pr.read_packet();
        (r, cursor.position() as usize)
    };
    match result {
        Ok(Some(pkt)) => {
            accum.drain(..consumed);
            let (data, udp_target) = pkt.into_parts();
            let addr = udp_target
                .as_ref()
                .map(dest_net_addr)
                .unwrap_or_else(|| default_addr.to_string());
            let msg = UdpMessage {
                session_id: 0, // 真实 id 由 InterConn::write 信封注入
                packet_id: 0,
                frag_id: 0,
                frag_count: 1,
                addr,
                data,
            };
            let mut wire = vec![0u8; msg.size()];
            let n = msg.serialize(&mut wire);
            // 剥掉 serialize 的 4B session_id 字段：wire 布局 = [id 信封][body]，
            // 对齐 Go（Serialize 跳过 SessionID 写入、InterConn.Write 覆盖为 c.id）。
            // ponytail: 不做超限分片——Go 依赖 quic.DatagramTooLargeError 携带的
            // MaxDatagramPayloadSize，Rust io::Error 无此信息；超限包 send_datagram
            // 报错断开
            conn.write(&wire[4..n]).await?;
            Ok(true)
        }
        Ok(None) => Ok(false), // 流内干净结束，但 accum 可能有残留 → 等更多数据
        Err(PacketError::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(e) => Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string())),
    }
}

/// Destination → `"host:port"`（Address Display 对 IPv6 已加方括号，与 Go `NetAddr` 一致）。
fn dest_net_addr(dest: &Destination) -> String {
    format!("{}:{}", dest.address(), dest.port().value())
}

/// `"host:port"` → UDP Destination（对应 Go `net.ParseDestination("udp:"+addr)`）。
///
/// 解析失败返回 `None`（调用方跳过该消息，对齐 Go `ReadFrom` 的 continue）。
fn parse_udp_source(addr: &str) -> Option<Destination> {
    let (host, port) = addr.rsplit_once(':')?;
    let port = Port::new(port.parse::<u16>().ok()?);
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    let address = host
        .parse::<std::net::IpAddr>()
        .map(Address::from)
        .unwrap_or_else(|_| Address::new_domain(host));
    Some(Destination::udp(address, port))
}

/// 构造 DialBridge 用的 DialFn 闭包（lazy init 模式）。
///
/// 闭包捕获 `HysteriaConfig` + `Arc<dyn HysteriaTransport>`。
/// 首次 dial 时通过 `OnceCell` lazy init `ClientManager`，
/// 然后 `client_manager.get_or_create` → 按 dest.network 走 `client.tcp()`（QUIC stream）
/// 或 `client.udp()`（QUIC datagram session）→ pump 桥接到 duplex。
///
/// # Panics
/// 不会 panic；任何错误以 `Err(String)` 返回。
pub fn make_hysteria_dial_fn(
    config: HysteriaConfig,
    transport: Arc<dyn HysteriaTransport>,
) -> DialFn {
    let client_manager: Arc<OnceCell<ClientManager>> = Arc::new(OnceCell::new());
    // 闭包外 clone，避免 move 闭包内重复 clone 导致 Copy trait 缺失
    let config_clone = config.clone();
    let transport_clone = Arc::clone(&transport);

    Arc::new(move |dest: &Destination| {
        // clone dest 以获得 'static 所有权，满足 PinFuture 要求
        let dest = dest.clone();
        let config = config_clone.clone();
        let transport = Arc::clone(&transport_clone);
        let client_manager = Arc::clone(&client_manager);

        Box::pin(async move {
            // lazy init ClientManager（首次 dial 时构造）
            let manager = client_manager
                .get_or_init(|| async {
                    ClientManager::new(transport)
                })
                .await;

            // resolve server address from config
            let server_addr_str = &config.server_addr;
            let server_name = &config.server_name;
            let udp_addr: SocketAddr = server_addr_str
                .parse()
                .map_err(|e| format!("hysteria server addr parse: {e}"))?;
            let dial_dest = DialDestination {
                udp_addr,
                host: server_name.clone(),
            };

            let proto_config = Arc::new(ProtoConfig {
                auth: config.auth.clone(),
                udp_idle_timeout: config.udp_idle_timeout_secs as i64,
                ..ProtoConfig::default()
            });
            let quic_params = Arc::clone(&config.quic_params);

            let client = manager.get_or_create(dial_dest, proto_config, quic_params);

            // TCP 走 QUIC stream 中继；UDP 走 QUIC datagram session（InterConn）
            match dest.network() {
                Network::TCP => {
                    let stream = client
                        .tcp(dest.address(), dest.port())
                        .await
                        .map_err(|e| format!("hysteria tcp dial: {e}"))?;
                    Ok(Box::new(HysteriaConnection::from_stream(stream)) as Box<dyn Connection>)
                }
                Network::UDP => {
                    let conn = client
                        .udp()
                        .await
                        .map_err(|e| format!("hysteria udp dial: {e}"))?;
                    Ok(Box::new(HysteriaConnection::from_udp(conn, dest)) as Box<dyn Connection>)
                }
                Network::Unix => {
                    Err("hysteria outbound does not support unix network in dial_fn".to_string())
                }
            }
        })
    })
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::sync::Arc;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::mpsc;

    use xray_common::net::address::Address;
    use xray_common::net::destination::Destination;
    use xray_common::net::network::Network;
    use xray_common::net::port::Port;
    use crate::protocol::UdpMessage;
    use xray_transport_hysteria::conn::QuicConn;
    use xray_transport_hysteria::dialer::{DialDestination, HysteriaTransport, QuicConfig};
    use xray_xudp::packet::{PacketReader, PacketWriter};

    use super::*;

    /// 回声 mock QUIC conn——扮演 hysteria server。
    ///
    /// `send_datagram` 收到 wire 格式 `[session_id(4)][UdpMessage body]`：
    /// 解析后记录，并回投一条 `UdpMessage`（addr = 请求 addr）到 `receive_datagram` 侧。
    #[derive(Clone)]
    struct MockEchoConn {
        tx: mpsc::UnboundedSender<Vec<u8>>,
        rx: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<Vec<u8>>>>,
        seen: Arc<parking_lot::Mutex<Vec<(u32, UdpMessage)>>>,
    }

    impl MockEchoConn {
        fn new() -> (Arc<Self>, Arc<parking_lot::Mutex<Vec<(u32, UdpMessage)>>>) {
            let (tx, rx) = mpsc::unbounded_channel();
            let seen = Arc::new(parking_lot::Mutex::new(Vec::new()));
            (
                Arc::new(Self {
                    tx,
                    rx: Arc::new(tokio::sync::Mutex::new(rx)),
                    seen: Arc::clone(&seen),
                }),
                seen,
            )
        }

        /// server 侧处理一个 client datagram：解析 + 记录 + 回投。
        fn echo(&self, wire: &[u8]) {
            if wire.len() < 4 {
                return;
            }
            let id = u32::from_be_bytes([wire[0], wire[1], wire[2], wire[3]]);
            // datagram body 不含 session id（client InterConn 信封已注入并占位 0..4）
            // → 前补 4 字节哑元对齐 UdpMessage::parse 的 8 字节头布局
            let mut full = Vec::with_capacity(wire.len());
            full.extend_from_slice(&[0u8; 4]);
            full.extend_from_slice(&wire[4..]);
            let Ok(msg) = UdpMessage::parse(&full) else {
                return;
            };
            self.seen.lock().push((id, msg.clone()));
            // 回包：真实 server 的回包来源 = 请求目标
            let resp = UdpMessage {
                session_id: 0,
                packet_id: 0,
                frag_id: 0,
                frag_count: 1,
                addr: msg.addr,
                data: msg.data,
            };
            let mut buf = vec![0u8; resp.size()];
            let n = resp.serialize(&mut buf);
            let mut wire_resp = Vec::with_capacity(n);
            // server 侧 InterConn 同 flow 复用同一 session id
            wire_resp.extend_from_slice(&id.to_be_bytes());
            wire_resp.extend_from_slice(&buf[4..n]);
            let _ = self.tx.send(wire_resp);
        }
    }

    impl QuicConn for MockEchoConn {
        fn send_datagram<'a>(
            &'a self,
            data: &'a [u8],
        ) -> Pin<Box<dyn Future<Output = std::io::Result<()>> + Send + 'a>> {
            Box::pin(async move {
                self.echo(data);
                Ok(())
            })
        }

        fn receive_datagram(
            &self,
        ) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<u8>>> + Send>> {
            let rx = Arc::clone(&self.rx);
            Box::pin(async move {
                rx.lock()
                    .await
                    .recv()
                    .await
                    .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "mock closed"))
            })
        }

        fn close_with_error(&self, _code: u64, _reason: &str) {}

        fn local_addr(&self) -> SocketAddr {
            "127.0.0.1:12345".parse().unwrap()
        }

        fn remote_addr(&self) -> SocketAddr {
            "127.0.0.1:443".parse().unwrap()
        }
    }

    struct MockTransport {
        conn: Arc<MockEchoConn>,
    }

    impl HysteriaTransport for MockTransport {
        fn dial_and_authenticate(
            &self,
            _dest: &DialDestination,
            _quic_config: &QuicConfig,
            _auth_token: &str,
            _brutal_down_bps: u64,
        ) -> Pin<Box<dyn Future<Output = std::io::Result<Arc<dyn QuicConn>>> + Send>> {
            let conn = Arc::clone(&self.conn) as Arc<dyn QuicConn>;
            Box::pin(async move { Ok(conn) })
        }

        fn open_stream(
            &self,
            _conn: &Arc<dyn QuicConn>,
        ) -> Pin<Box<dyn Future<Output = std::io::Result<Arc<dyn xray_transport_hysteria::conn::QuicStream>>> + Send>>
        {
            Box::pin(async { Err(std::io::Error::other("mock: udp-only transport")) })
        }
    }

    /// e2e：XUDP 帧流 → hysteria dial_fn（UDP dest）→ 桥 → InterConn → echo → 回包帧。
    #[tokio::test]
    async fn udp_dial_fn_relays_xudp_frames_through_interconn() {
        let (mock_conn, seen) = MockEchoConn::new();
        let transport = MockTransport { conn: mock_conn };
        let dial = make_hysteria_dial_fn(
            HysteriaConfig::new("127.0.0.1:443", "secret"),
            Arc::new(transport),
        );

        let target =
            Destination::new(Address::new_domain("dns.example.com"), Port::new(53), Network::UDP);
        let alt =
            Destination::new(Address::new_domain("alt.example.com"), Port::new(5353), Network::UDP);

        let mut conn = dial(&target).await.expect("udp dial should succeed");

        // request 方向：两帧 XUDP（首帧 New + Keep 带 per-packet target）写入 Connection
        let mut frames = Vec::new();
        {
            let mut pw = PacketWriter::new(&mut frames, target.clone(), [9u8; 8]);
            pw.write_packet(b"query-1").unwrap();
            pw.write_packet_with_udp_target(b"query-2", &alt).unwrap();
        }
        conn.write_all(&frames).await.unwrap();

        // response 方向：读回 echo 帧，凑齐两帧为止
        let (p1, p2) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let mut acc = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                let n = conn.read(&mut buf).await.expect("read from bridge");
                assert!(n > 0, "unexpected EOF before both echo frames");
                acc.extend_from_slice(&buf[..n]);
                let mut pr = PacketReader::new(std::io::Cursor::new(&acc));
                match (pr.read_packet(), pr.read_packet()) {
                    (Ok(Some(a)), Ok(Some(b))) => break (a, b),
                    _ => continue,
                }
            }
        })
        .await
        .expect("timed out waiting for echo frames");

        assert_eq!(p1.data(), b"query-1".as_slice());
        assert_eq!(p1.udp_target(), Some(&target));
        assert_eq!(p2.data(), b"query-2".as_slice());
        assert_eq!(p2.udp_target(), Some(&alt));

        // server 侧收到两条 hysteria UdpMessage；wire session id = InterConn 分配的首个 id
        let seen = seen.lock();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].0, 1);
        assert_eq!(seen[0].1.addr, "dns.example.com:53");
        assert_eq!(seen[0].1.data, b"query-1".as_slice());
        assert_eq!(seen[1].0, 1);
        assert_eq!(seen[1].1.addr, "alt.example.com:5353");
        assert_eq!(seen[1].1.data, b"query-2".as_slice());
    }

    #[test]
    fn parse_udp_source_handles_domain_ip_and_ipv6() {
        let d = parse_udp_source("dns.example.com:53").unwrap();
        assert_eq!(d.address(), &Address::new_domain("dns.example.com"));
        assert_eq!(d.port().value(), 53);
        assert_eq!(d.network(), Network::UDP);

        let d = parse_udp_source("8.8.8.8:53").unwrap();
        assert_eq!(d.address(), &Address::IPv4("8.8.8.8".parse().unwrap()));

        // Go NetAddr 格式的 IPv6（带方括号）
        let d = parse_udp_source("[2001:db8::1]:443").unwrap();
        assert_eq!(d.address(), &Address::IPv6("2001:db8::1".parse().unwrap()));
        assert_eq!(d.port().value(), 443);

        assert!(parse_udp_source("no-port").is_none());
        assert!(parse_udp_source("host:notaport").is_none());
        assert!(parse_udp_source("").is_none());
    }
}
