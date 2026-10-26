//! SOCKS 客户端 UDP 出站——UDP ASSOCIATE 会话（TCP ctrl 保活）+ relay 数据报收发。
//!
//! 对应 Go `proxy/socks/client.go:112`（ASSOCIATE 请求）与 `:142-160`
//! （BND.ADDR/PORT 解析 + relay 收发）。Go 同样不支持 UDP 分片：
//! `FRAG != 0` 的帧丢弃并计数。
//!
//! ## 生命周期
//!
//! - **ctrl（TCP）**：UDP ASSOCIATE 的关联载体。断开（drop / [`SocksUdpClient::shutdown`]）
//!   即会话终结——服务端依 ctrl EOF 收割 UDP 会话（Go server.go 同）。
//! - **relay（UDP）**：connect 到 BND.ADDR/PORT（`0.0.0.0`/`::` 回落 server 地址， RFC 1928 §7；BND
//!   为域名时本地解析一次），之后 send/recv 免带地址； connect 语义同时过滤非 relay 来源的数据报。
//! - [`relay`]：与 freedom `relay_policy` 同形态的双向泵入口 （XUDP 帧流 ↔ SOCKS5 UDP
//!   数据报），xray-core 的 socks outbound UDP 分支已接线（`SocksUdpDispatch`， 响应泵经
//!   `ctx.spawn` 托管）。

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc, LazyLock,
        atomic::{AtomicU64, Ordering},
    },
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
};
use xray_buf::{
    io::{Reader, Writer},
    multi::MultiBuffer,
};
use xray_common::net::{address::Address, destination::Destination, port::Port};
use xray_frame::{LogFacade, PluginContext};
use xray_transport::link::Link;
use xray_xudp::packet::{PacketError, PacketReader, PacketWriter};

use crate::{
    client::{ClientConfig, SOCKS_HANDSHAKE_TIMEOUT, negotiate, read_reply_addr},
    dispatcher::dest_to_socks,
    error::{Result, SocksError},
    protocol::{
        ATYP_IPV4, CMD_UDP_ASSOCIATE, Host, SOCKS5_VERSION, STATUS_SUCCESS, SocksAddr,
        decode_udp_packet, encode_udp_packet,
    },
};

/// XUDP GlobalID 长度（与 freedom / Go `xudp` 一致）。
const GLOBAL_ID_LEN: usize = 8;

/// UDP recv 缓冲区大小（单数据报最大 65535 字节）。
const RECV_BUF_SIZE: usize = 65535;

/// 请求泵 accum 缓冲上限（防 peer 灌爆内存；与 freedom 同值）。
const ACCUM_MAX_BYTES: usize = 2 * 1024 * 1024;

/// SOCKS5 UDP 出站会话：TCP ctrl（关联载体）+ relay UDP socket。
///
/// ctrl 必须保活（Go 靠它维持关联）：drop 本结构或调用 [`SocksUdpClient::shutdown`]
/// 都会使服务端收割 UDP 会话。
pub struct SocksUdpClient {
    /// UDP ASSOCIATE 的 TCP ctrl 连接。
    ctrl: TcpStream,
    /// 已 connect 到 relay 地址的 UDP socket。
    relay: UdpSocket,
    /// 解析后的 relay 地址（BND.ADDR/PORT；0.0.0.0 回落 server 地址后的最终值）。
    relay_addr: SocketAddr,
    /// FRAG != 0 丢帧计数（Go 同样不支持分片）。
    frag_dropped: AtomicU64,
}

impl SocksUdpClient {
    /// 握手 NoAuth/Password → `UDP ASSOCIATE(0.0.0.0:0)` → 解析 BND.ADDR/PORT。
    ///
    /// 连接级退避与握手 deadline 与 TCP 路径同源（Go `client.go:66`/`:104`）。
    pub async fn associate(cfg: &ClientConfig) -> Result<Self> {
        let server_addr = &cfg.server_addr;
        let mut ctrl =
            xray_transport::retry::exponential_backoff(5, 100, || TcpStream::connect(server_addr))
                .await
                .map_err(|e| {
                    SocksError::HandshakeFailed(format!(
                        "connect to socks server {server_addr}: {e}"
                    ))
                })?;

        // 握手 deadline 只约束握手往返，不约束数据面（与 TCP 路径同语义）
        let bnd = match tokio::time::timeout(
            SOCKS_HANDSHAKE_TIMEOUT,
            associate_handshake(&mut ctrl, cfg),
        )
        .await
        {
            Ok(reply) => reply?,
            Err(_) => {
                return Err(SocksError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "socks udp associate timeout",
                )));
            },
        };

        let relay_addr = resolve_relay_addr(bnd, server_addr).await?;
        let bind_addr = match relay_addr {
            SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        let relay = UdpSocket::bind(bind_addr).await?;
        relay.connect(relay_addr).await?;
        Ok(Self { ctrl, relay, relay_addr, frag_dropped: AtomicU64::new(0) })
    }

    /// relay 地址（BND.ADDR/PORT 解析结果，含 0.0.0.0 回落后的最终值）。
    #[must_use]
    pub fn relay_addr(&self) -> SocketAddr {
        self.relay_addr
    }

    /// `FRAG != 0` 丢帧计数。
    #[must_use]
    pub fn frag_dropped(&self) -> u64 {
        self.frag_dropped.load(Ordering::Relaxed)
    }

    /// 一个 XUDP 目标 + 载荷 → SOCKS5 UDP 帧（RSV=0 FRAG=0 ATYP/ADDR/PORT）→ relay send。
    /// 帧内域名原样透传（ATYP=Domain），不在本地解析。
    pub async fn send_frame(&self, dest: &Destination, payload: &[u8]) -> Result<()> {
        let frame = encode_udp_packet(&dest_to_socks(dest), payload);
        self.relay.send(&frame).await?;
        Ok(())
    }

    /// relay recv → 剥 SOCKS5 头 → (来源, payload)。
    /// `FRAG != 0` / 畸形帧丢弃并计数，循环取下一个合法帧。
    pub async fn recv_frame(&self) -> Result<(Destination, Vec<u8>)> {
        let mut buf = vec![0u8; RECV_BUF_SIZE];
        loop {
            let n = self.relay.recv(&mut buf).await?;
            if let Some((source, payload)) = parse_relay_frame(&buf[..n], &self.frag_dropped) {
                return Ok((socks_to_destination(source), payload.to_vec()));
            }
        }
    }

    /// 主动终结会话：shutdown ctrl → 服务端依 ctrl EOF 收割 UDP 会话；
    /// relay 随 self drop 关闭。
    pub async fn shutdown(&mut self) -> Result<()> {
        self.ctrl.shutdown().await?;
        Ok(())
    }
}

/// ASSOCIATE 握手本体（method 协商 + auth + ASSOCIATE 往返），返回 BND 地址。
/// deadline 由 [`SocksUdpClient::associate`] 的 timeout 施加，此处不设。
async fn associate_handshake(stream: &mut TcpStream, cfg: &ClientConfig) -> Result<SocksAddr> {
    negotiate(stream, cfg).await?;

    // ASSOCIATE 请求：DST.ADDR = 0.0.0.0 DST.PORT = 0（Go client.go:112 同形态）
    let req = [SOCKS5_VERSION, CMD_UDP_ASSOCIATE, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0];
    stream.write_all(&req).await?;

    // 响应 [VER REP RSV ATYP] + BND.ADDR/PORT
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != SOCKS5_VERSION {
        return Err(SocksError::HandshakeFailed(format!(
            "invalid version in associate response: {}",
            head[0]
        )));
    }
    if head[1] != STATUS_SUCCESS {
        return Err(SocksError::HandshakeFailed(format!(
            "udp associate rejected with status: {}",
            head[1]
        )));
    }
    read_reply_addr(stream, head[3]).await
}

/// BND.ADDR/PORT → relay [`SocketAddr`]。
///
/// `0.0.0.0`/`::` 回落 server 地址（RFC 1928 §7，Go 同）；域名本地解析一次。
async fn resolve_relay_addr(bnd: SocksAddr, server_addr: &str) -> Result<SocketAddr> {
    match bnd.host {
        Host::Ipv4(ip) if ip.is_unspecified() => {
            Ok(SocketAddr::new(resolve_first(server_addr).await?, bnd.port))
        },
        Host::Ipv6(ip) if ip.is_unspecified() => {
            Ok(SocketAddr::new(resolve_first(server_addr).await?, bnd.port))
        },
        Host::Ipv4(ip) => Ok(SocketAddr::new(IpAddr::V4(ip), bnd.port)),
        Host::Ipv6(ip) => Ok(SocketAddr::new(IpAddr::V6(ip), bnd.port)),
        Host::Domain(d) => {
            tokio::net::lookup_host((&d[..], bnd.port)).await?.next().ok_or_else(|| {
                SocksError::HandshakeFailed(format!("cannot resolve relay domain: {d}"))
            })
        },
    }
}

/// 解析 server 地址串的第一个 IP（0.0.0.0 BND 回落用）。
async fn resolve_first(server_addr: &str) -> Result<IpAddr> {
    tokio::net::lookup_host(server_addr).await?.next().map(|sa| sa.ip()).ok_or_else(|| {
        SocksError::HandshakeFailed(format!("cannot resolve socks server: {server_addr}"))
    })
}

/// relay 丢弃路径诊断门面（nn8os 2b 打回处置：tracing 宏 → LogFacade——
/// 本项目工具链上 `disallowed_macros` 对 proc-macro 不认任何 allow（fn/stmt/
/// 文件顶三形态实测无效；仓内 91 处先例豁免的是 macro_rules 的 println），
/// 迁移为唯一关红路径。域 = "socks"，target `xray_frame::socks` + mask_secrets。
/// 只在丢弃分支发射（非转发热路径，坑约束⑫不触）。
static RELAY_LOG: LazyLock<LogFacade> = LazyLock::new(|| LogFacade::new("socks", vec![]));

/// 解析一帧 relay 数据报。
///
/// `FRAG != 0` → 丢弃 + 计数（Go 同样不支持分片）；畸形帧 → 丢弃；
/// 合法帧 → `Some((source, payload))`。两种丢弃都打 debug 日志，
/// 不让帧静默消失（分片属预期协议行为，畸形帧值得排查）。
fn parse_relay_frame<'a>(buf: &'a [u8], frag_dropped: &AtomicU64) -> Option<(SocksAddr, &'a [u8])> {
    if buf.len() < 5 {
        RELAY_LOG.debug(format!("socks udp: dropped undersized datagram len={}", buf.len()));
        return None;
    }
    if buf[2] != 0 {
        let dropped = frag_dropped.fetch_add(1, Ordering::Relaxed) + 1;
        RELAY_LOG.debug(format!(
            "socks udp: dropped fragmented datagram fragment={} dropped={}",
            buf[2], dropped
        ));
        return None;
    }
    match decode_udp_packet(buf) {
        Ok((addr, payload)) => Some((addr, payload)),
        Err(e) => {
            RELAY_LOG.debug(format!("socks udp: dropped malformed datagram error={e}"));
            None
        },
    }
}

/// [`SocksAddr`] → XUDP [`Destination`]（UDP 网络；域名原样透传）。
fn socks_to_destination(addr: SocksAddr) -> Destination {
    let address = match addr.host {
        Host::Ipv4(ip) => Address::IPv4(ip),
        Host::Ipv6(ip) => Address::IPv6(ip),
        Host::Domain(d) => Address::Domain(d),
    };
    Destination::udp(address, Port::new(addr.port))
}

/// freedom `relay_policy` 同形态入口：XUDP 帧流 ↔ SOCKS5 UDP 数据报双向泵。
///
/// - 请求方向：link.reader 的 XUDP 帧 → `send_frame`（帧内目标；无目标帧回退 `default_dest`，对齐
///   freedom 的会话默认目标语义）。
/// - 响应方向：relay recv → 剥 SOCKS5 头 → XUDP 帧（source = 帧内 DST/回包地址）→ link.writer。
/// - **ctrl 断开** → 中止响应泵、关闭 relay 与会话；请求方向结束（link EOF）→ shutdown
///   ctrl（服务端收割会话）。
///
/// 异步托管走 `ctx.spawn`（坑约束 5 唯一口；nn8os 2b 迁移，原裸 spawn 存量债
/// 已清）。由 xray-core socks outbound UDP 分支接线（`SocksUdpDispatch`）。
pub async fn relay(
    ctx: &PluginContext,
    client: SocksUdpClient,
    default_dest: &Destination,
    link: Link,
) -> io::Result<()> {
    let Link { mut reader, writer } = link;
    let SocksUdpClient { mut ctrl, relay, relay_addr: _, frag_dropped } = client;
    let relay = Arc::new(relay);
    let global_id: [u8; GLOBAL_ID_LEN] = rand::random();

    // 响应泵：relay recv → XUDP 帧 → link.writer（FRAG 计数器随任务走）
    // for_plugin/装配根 scope 均不 close——闸关态=装配 bug，fail-visible。
    let resp_task = ctx
        .spawn(pump_response(Arc::clone(&relay), global_id, frag_dropped, writer))
        .expect("plugin ctx FxScope is never closed (assembly-owned)");

    // 请求泵与 ctrl 监视并发：任一方向结束即终结会话
    let req = pump_request(&relay, default_dest.clone(), &mut reader);
    tokio::select! {
        result = req => {
            // link EOF：关 ctrl（服务端收割 UDP 会话），中止响应泵
            let _ = ctrl.shutdown().await;
            resp_task.abort();
            result
        },
        result = monitor_ctrl(&mut ctrl) => {
            // ctrl 断开：中止响应泵；relay 随任务/本函数 drop 关闭，会话终结
            resp_task.abort();
            result
        },
    }
}

/// ctrl 监视：读到 EOF / 错误即返回（ctrl 上不应有应用数据，读掉即可）。
async fn monitor_ctrl(ctrl: &mut TcpStream) -> io::Result<()> {
    let mut sink = [0u8; 256];
    loop {
        match ctrl.read(&mut sink).await {
            Ok(0) => return Ok(()),
            Ok(_) => {},
            Err(e) => return Err(e),
        }
    }
}

/// 请求方向：link.reader 读 XUDP 帧 → SOCKS5 UDP 帧 → relay.send。
///
/// 帧解析语义对齐 freedom `parse_and_send`：半帧（UnexpectedEof）继续读字节，
/// 终止帧（`Ok(None)` / MetadataTooShort）正常退出——误判会让整条流在突发中途死亡。
async fn pump_request(
    relay: &UdpSocket,
    default_dest: Destination,
    reader: &mut Box<dyn Reader>,
) -> io::Result<()> {
    let mut accum: Vec<u8> = Vec::new();
    loop {
        // 尽量从 accum 前端解析完整帧
        loop {
            if accum.is_empty() {
                break;
            }
            let (result, consumed) = {
                let mut cursor = std::io::Cursor::new(&accum[..]);
                let mut pr = PacketReader::new(&mut cursor);
                (pr.read_packet(), cursor.position() as usize)
            };
            match result {
                Ok(Some(pkt)) => {
                    accum.drain(..consumed);
                    let (data, target) = pkt.into_parts();
                    let dest = target.unwrap_or_else(|| default_dest.clone());
                    let frame = encode_udp_packet(&dest_to_socks(&dest), &data);
                    relay.send(&frame).await?;
                },
                // 协议层终止帧（流内非数据帧）
                Ok(None) => return Ok(()),
                // 半帧：读边界切开，继续追加字节而非终止
                Err(PacketError::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(PacketError::MetadataTooShort(_)) => return Ok(()),
                Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string())),
            }
        }
        match reader.read_multi_buffer().await {
            Ok(mb) if !mb.is_empty() => {
                accum.reserve(mb.len());
                for buf in mb.iter() {
                    accum.extend_from_slice(buf.bytes());
                }
                if accum.len() > ACCUM_MAX_BYTES {
                    return Err(io::Error::new(
                        io::ErrorKind::OutOfMemory,
                        format!("udp accum exceeded {ACCUM_MAX_BYTES} bytes"),
                    ));
                }
            },
            _ => return Ok(()), // link EOF / 读错误 → 请求方向结束
        }
    }
}

/// 响应方向：relay recv → 剥 SOCKS5 头 → XUDP 帧（source = 帧内 DST/回包地址）→
/// link.writer。`FRAG != 0` 丢弃并计数；writer 关闭即退出。
async fn pump_response(
    relay: Arc<UdpSocket>,
    global_id: [u8; GLOBAL_ID_LEN],
    frag_dropped: AtomicU64,
    mut writer: Box<dyn Writer>,
) -> io::Result<()> {
    let mut buf = vec![0u8; RECV_BUF_SIZE];
    loop {
        let n = match relay.recv(&mut buf).await {
            Ok(n) => n,
            Err(_) => return Ok(()),
        };
        let Some((source, payload)) = parse_relay_frame(&buf[..n], &frag_dropped) else {
            continue;
        };
        let mut frame = Vec::with_capacity(n + 64);
        let mut pw = PacketWriter::new(&mut frame, socks_to_destination(source), global_id);
        if pw.write_packet(payload).is_err() {
            return Ok(());
        }
        drop(pw);

        let mut mb = MultiBuffer::new();
        mb.merge_bytes(&frame);
        if writer.write_multi_buffer(mb).await.is_err() {
            return Ok(()); // writer 关闭
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, sync::Arc, time::Duration};

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, UdpSocket},
        sync::oneshot,
    };
    use xray_common::net::{address::Address, destination::Destination, port::Port};

    use super::*;
    use crate::{
        config::ServerConfig,
        protocol::{CMD_UDP_ASSOCIATE, Host, SocksAddr, decode_udp_packet, encode_udp_packet},
        server::{SocksRequest, socks5_server_handshake},
    };

    /// 单次收发超时（CI 负载下给足余量）。
    const ECHO_TIMEOUT: Duration = Duration::from_secs(5);

    /// 构造 IPv4 UDP Destination。
    fn udp_dest(ip: Ipv4Addr, port: u16) -> Destination {
        Destination::udp(Address::IPv4(ip), Port::new(port))
    }

    /// crate 内 in-process SOCKS5 UDP server：handshake（UdpAssociate）→
    /// 可选先发一个 FRAG≠0 帧 → 把首帧原样回显（source = 帧 DST）。
    /// 首帧经 `tx` 回传给测试断言「server 收到正确目标+载荷」。
    async fn run_udp_echo_server(
        listener: TcpListener,
        config: ServerConfig,
        inject_frag: bool,
        tx: oneshot::Sender<(SocksAddr, Vec<u8>)>,
    ) {
        let (mut ctrl, _) = listener.accept().await.expect("accept");
        let relay = match socks5_server_handshake(&mut ctrl, &config).await {
            Ok(SocksRequest::UdpAssociate(_, relay)) => relay,
            Ok(other) => panic!("expected UdpAssociate, got {other:?}"),
            Err(e) => panic!("server handshake failed: {e}"),
        };
        // ctrl 保活到回包完成（SOCKS UDP 语义：ctrl 断则关联终结）
        let mut buf = vec![0u8; 65535];
        let (n, peer) = relay.recv_from(&mut buf).await.expect("relay recv_from");
        let (dest, payload) = decode_udp_packet(&buf[..n]).expect("decode server-side");
        let payload = payload.to_vec();
        let _ = tx.send((dest.clone(), payload.clone()));
        if inject_frag {
            // FRAG != 0 的帧：客户端应丢弃并计数，不影响后续真实帧
            let mut frag = encode_udp_packet(&dest, b"fragmented");
            frag[2] = 1;
            let _ = relay.send_to(&frag, peer).await;
        }
        let resp = encode_udp_packet(&dest, &payload);
        let _ = relay.send_to(&resp, peer).await;
        // 保活 relay socket 至回包送达对端
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    /// 红→绿验收：associate → send_frame → server 收到正确目标+载荷 →
    /// server 回包 → recv_frame 拿到原始 payload。
    #[tokio::test]
    async fn socks_outbound_udp_associate_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let server_addr = listener.local_addr().unwrap();
        let (tx, rx) = oneshot::channel();
        let config = ServerConfig { udp_enabled: true, ..Default::default() };
        let server = xray_common::testing::spawn(
            "socks-outbound-udp-associate-roundtrip-echo",
            run_udp_echo_server(listener, config, false, tx),
        );

        let client = SocksUdpClient::associate(&ClientConfig::new_noauth(server_addr.to_string()))
            .await
            .expect("associate");

        let dest = udp_dest(Ipv4Addr::new(8, 8, 8, 8), 53);
        client.send_frame(&dest, b"hello-udp").await.expect("send_frame");

        let (seen_dest, seen_payload) = rx.await.expect("server task");
        assert_eq!(socks_to_destination(seen_dest), dest, "server 收到的目标应与发送一致");
        assert_eq!(seen_payload, b"hello-udp", "server 收到的载荷应原样");

        let (src, payload) = tokio::time::timeout(ECHO_TIMEOUT, client.recv_frame())
            .await
            .expect("recv timeout")
            .expect("recv_frame");
        assert_eq!(src, dest, "回包来源应等于帧 DST（echo 以 DST 为 source）");
        assert_eq!(payload, b"hello-udp", "recv_frame 应拿到原始 payload");

        server.abort();
    }

    /// FRAG != 0 的帧丢弃并计数（Go 同样不支持分片）：真实回显不受影响。
    #[tokio::test]
    async fn fragmented_frames_dropped_and_counted() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let server_addr = listener.local_addr().unwrap();
        let (tx, _rx) = oneshot::channel();
        let config = ServerConfig { udp_enabled: true, ..Default::default() };
        let server = xray_common::testing::spawn(
            "fragmented-frames-dropped-and-counted-echo",
            run_udp_echo_server(listener, config, true, tx),
        );

        let client = SocksUdpClient::associate(&ClientConfig::new_noauth(server_addr.to_string()))
            .await
            .expect("associate");
        let dest = udp_dest(Ipv4Addr::new(1, 1, 1, 1), 443);
        client.send_frame(&dest, b"real-frame").await.expect("send_frame");

        let (_, payload) = tokio::time::timeout(ECHO_TIMEOUT, client.recv_frame())
            .await
            .expect("recv timeout")
            .expect("recv_frame");
        assert_eq!(payload, b"real-frame", "FRAG 帧被丢弃后真实帧应照常收到");
        assert_eq!(client.frag_dropped(), 1, "FRAG != 0 应计数 1");

        server.abort();
    }

    /// BND.ADDR = 0.0.0.0 时按 RFC 1928 §7 回落到代理服务器地址（裸 mock server）。
    #[tokio::test]
    async fn associate_falls_back_to_server_addr_when_bnd_unspecified() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let server_addr = listener.local_addr().unwrap();
        let mock_relay = UdpSocket::bind("127.0.0.1:0").await.expect("bind relay");
        let relay_port = mock_relay.local_addr().unwrap().port();
        let server = xray_common::testing::spawn(
            "associate-falls-back-to-server-addr-when-bnd-unspeci-accept",
            async move {
                let (mut s, _) = listener.accept().await.expect("accept");
                let mut m = [0u8; 3]; // method 请求 [05 01 00] 共 3 字节
                s.read_exact(&mut m).await.expect("method req");
                s.write_all(&[0x05, 0x00]).await.expect("method reply");
                let mut req = [0u8; 10];
                s.read_exact(&mut req).await.expect("associate req");
                assert_eq!(req[1], CMD_UDP_ASSOCIATE, "客户端应发 UDP ASSOCIATE");
                // BND.ADDR = 0.0.0.0, BND.PORT = mock relay 端口
                let mut reply = vec![0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0];
                reply.extend_from_slice(&relay_port.to_be_bytes());
                s.write_all(&reply).await.expect("associate reply");
            },
        );

        let client = SocksUdpClient::associate(&ClientConfig::new_noauth(server_addr.to_string()))
            .await
            .expect("associate");
        assert_eq!(client.relay_addr().port(), relay_port, "BND.PORT 应取回包端口");
        assert_eq!(
            client.relay_addr().ip(),
            server_addr.ip(),
            "BND.ADDR=0.0.0.0 应回落 server 地址"
        );

        // 数据路径：send_frame 抵达 mock relay
        client.send_frame(&udp_dest(Ipv4Addr::LOCALHOST, 9999), b"via-bnd").await.expect("send");
        let mut buf = [0u8; 1024];
        let (n, _) = tokio::time::timeout(ECHO_TIMEOUT, mock_relay.recv_from(&mut buf))
            .await
            .expect("mock relay recv timeout")
            .expect("mock relay recv");
        let (dest, payload) = decode_udp_packet(&buf[..n]).expect("decode");
        assert_eq!(dest.host, Host::Ipv4(Ipv4Addr::LOCALHOST));
        assert_eq!(dest.port, 9999);
        assert_eq!(payload, b"via-bnd");

        server.await.expect("mock server task");
    }

    /// ctrl 连接断开 → 服务端 ctrl 读到 EOF（会话随之收割的先决条件）。
    #[tokio::test]
    async fn ctrl_disconnect_closes_session() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let server_addr = listener.local_addr().unwrap();
        let config = ServerConfig { udp_enabled: true, ..Default::default() };
        let (tx, rx) = oneshot::channel();
        let server =
            xray_common::testing::spawn("ctrl-disconnect-closes-session-accept", async move {
                let (mut ctrl, _) = listener.accept().await.expect("accept");
                let relay = Arc::new(match socks5_server_handshake(&mut ctrl, &config).await {
                    Ok(SocksRequest::UdpAssociate(_, relay)) => relay,
                    Ok(other) => panic!("expected UdpAssociate, got {other:?}"),
                    Err(e) => panic!("handshake: {e}"),
                });
                // ctrl EOF 监视（独立任务持续读，EOF 时通知）
                let eof =
                    xray_common::testing::spawn("ctrl-disconnect-closes-session", async move {
                        let mut sink = [0u8; 64];
                        while matches!(ctrl.read(&mut sink).await, Ok(n) if n > 0) {}
                        let _ = tx.send(());
                    });
                // relay 上回显一帧，证明会话已建立
                let mut buf = vec![0u8; 2048];
                let (n, peer) = relay.recv_from(&mut buf).await.expect("relay recv");
                let (dest, payload) = decode_udp_packet(&buf[..n]).expect("decode");
                let resp = encode_udp_packet(&dest, payload);
                let _ = relay.send_to(&resp, peer).await;
                eof.await.ok();
            });

        let mut client =
            SocksUdpClient::associate(&ClientConfig::new_noauth(server_addr.to_string()))
                .await
                .expect("associate");
        let dest = udp_dest(Ipv4Addr::LOCALHOST, 7777);
        client.send_frame(&dest, b"alive").await.expect("send");
        let (_, payload) = tokio::time::timeout(ECHO_TIMEOUT, client.recv_frame())
            .await
            .expect("recv timeout")
            .expect("recv");
        assert_eq!(payload, b"alive", "会话建立后应能收到回显");

        // ctrl 断开（shutdown）→ 服务端 ctrl 读侧 EOF
        client.shutdown().await.expect("shutdown");
        tokio::time::timeout(ECHO_TIMEOUT, rx)
            .await
            .expect("server must see ctrl EOF after shutdown")
            .ok();
        server.abort();
    }

    /// UDP 未启用时 associate 被拒（服务端回 CMD not supported）。
    #[tokio::test]
    async fn associate_rejected_when_udp_disabled() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let server_addr = listener.local_addr().unwrap();
        let server = xray_common::testing::spawn(
            "associate-rejected-when-udp-disabled-accept",
            async move {
                let (mut s, _) = listener.accept().await.expect("accept");
                // udp_enabled=false → handshake 自动回 CMD not supported 并 Err
                let _ = socks5_server_handshake(&mut s, &ServerConfig::default()).await;
            },
        );
        let r = SocksUdpClient::associate(&ClientConfig::new_noauth(server_addr.to_string())).await;
        assert!(r.is_err(), "udp disabled 时 associate 必须失败");
        server.abort();
    }

    /// Destination ↔ SocksAddr 转换保持（域名原样透传，不在本地解析）。
    #[test]
    fn socks_destination_conversion_roundtrip() {
        let d = Destination::udp(Address::Domain("example.com".into()), Port::new(443));
        let back = socks_to_destination(dest_to_socks(&d));
        assert_eq!(back, d);

        let v6 = Destination::udp(Address::IPv6("2001:db8::1".parse().unwrap()), Port::new(80));
        assert_eq!(socks_to_destination(dest_to_socks(&v6)), v6);
    }

    /// 互通（尽力，需真实 Go xray socks inbound `"udp": true` + freedom outbound）。
    ///
    /// 运行（先起 Go 服务端，见 reports/night-run-2026-10-21/A-4-socks-udp.md）：
    /// ```bat
    /// set GO_SOCKS_ADDR=127.0.0.1:10808
    /// cargo test --offline -p xray-proxy-socks --all-targets -- --ignored --nocapture go_socks
    /// ```
    /// 拓扑：SocksUdpClient → Go socks inbound(udp:true) → freedom → 本测试内 UDP echo。
    #[tokio::test]
    #[ignore = "interop: needs real Go xray socks inbound (udp:true); set GO_SOCKS_ADDR"]
    async fn interop_go_socks_inbound_udp_echo() {
        let Some(go_addr) = std::env::var("GO_SOCKS_ADDR").ok() else {
            panic!("GO_SOCKS_ADDR 未设置（形如 127.0.0.1:10808）");
        };
        // 测试进程内 UDP echo target（Go freedom 把数据报送回这里）
        let echo = UdpSocket::bind("127.0.0.1:0").await.expect("bind echo");
        let echo_port = echo.local_addr().unwrap().port();
        let echo_task =
            xray_common::testing::spawn("interop-go-socks-inbound-udp-echo-echo", async move {
                let mut buf = [0u8; 2048];
                let (n, peer) = echo.recv_from(&mut buf).await.expect("echo recv");
                let _ = echo.send_to(&buf[..n], peer).await;
            });

        let client = SocksUdpClient::associate(&ClientConfig::new_noauth(go_addr))
            .await
            .expect("associate with Go socks server");
        #[allow(clippy::print_stdout)] // interop 取证输出（--nocapture 人眼核对）
        {
            println!("relay_addr = {}", client.relay_addr());
        }

        let dest = udp_dest(Ipv4Addr::LOCALHOST, echo_port);
        client.send_frame(&dest, b"interop-ping").await.expect("send_frame");
        let (src, payload) = tokio::time::timeout(ECHO_TIMEOUT, client.recv_frame())
            .await
            .expect("recv timeout")
            .expect("recv_frame");
        assert_eq!(src, dest, "回包 source 应等于帧 DST");
        assert_eq!(payload, b"interop-ping", "echo 载荷应原样");
        echo_task.await.ok();
        #[allow(clippy::print_stdout)] // interop 取证输出（--nocapture 人眼核对）
        {
            println!("interop OK: Rust SocksUdpClient <-> Go socks inbound udp:true roundtrip");
        }
    }
}
