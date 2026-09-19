//! TUIC v5 mock server（切片1：TCP relay + 切片2：UDP relay）。
//!
//! Mock 行为：
//! 1. 自签 TLS 证书（rcgen）
//! 2. quinn Endpoint::server 监听，ALPN 协商 h3 + tuic
//! 3. accept_uni → Authenticate 校验 token（export_keying_material）
//! 4. accept_bi → Connect → tokio TCP dial 目标 → 双向 copy（true relay）
//! 5. UDP Packet：quic 模式经 uni stream（spec 同模 open_uni 回包）、
//!    native 模式经 QUIC DATAGRAM → per-assoc UDP 会话表（bd 1ur/7ry），
//!    Dissociate 销毁会话

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use xray_app_dispatcher::{DispatchHandler, UdpDispatchSession};
use xray_common::net::address::Address as XAddress;
use xray_common::net::destination::Destination;
use xray_common::net::port::Port;

use crate::error::{Result, TuicError};
use crate::protocol::command::{type_code, TOKEN_LEN};
use crate::protocol::{Address, Command, Packet};
use crate::udp::{quinn_read_exact_err, read_packet_payload};

/// 自签证书产物（仅 mock 用）。
struct TlsCert {
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
}

fn gen_self_signed(server_name: &str) -> std::result::Result<TlsCert, rcgen::Error> {
    let mut params = CertificateParams::new(vec![server_name.to_string()])?;
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, server_name);
    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;
    Ok(TlsCert {
        cert_der: cert.der().to_vec(),
        key_der: key_pair.serialize_der(),
    })
}

/// TUIC mock server。用于 loopback 测试，**不是生产 server**。
///
/// 支持切片1（TCP relay）与切片2（UDP relay，bi-stream 模式）。
pub struct TuicMockServer {
    endpoint: quinn::Endpoint,
    expected_uuid: Uuid,
    password: String,
    cert_der: Vec<u8>,
}

impl TuicMockServer {
    /// 绑定 + 配置 TLS。返回 `(server, cert_der)`，cert_der 用于客户端 trust store。
    pub async fn bind(
        listen: SocketAddr,
        server_name: &str,
        uuid: Uuid,
        password: String,
    ) -> Result<(Self, Vec<u8>)> {
        xray_common::ensure_default_crypto_provider();

        let tls = gen_self_signed(server_name).map_err(|e| {
            TuicError::Io(std::io::Error::other(format!("rcgen self-signed failed: {e}")))
        })?;

        let private_key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(tls.key_der.clone()),
        );
        let cert_chain = vec![rustls::pki_types::CertificateDer::from(tls.cert_der.clone())];

        let mut server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)?;
        server_crypto.alpn_protocols = vec![b"h3".to_vec(), b"tuic".to_vec()];

        let quic_server_cfg = quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .map_err(|e| TuicError::Io(std::io::Error::other(format!("quinn rustls convert: {e}"))))?;
        let server_crypto_arc = Arc::new(quic_server_cfg);

        let mut transport = quinn::TransportConfig::default();
        transport.datagram_receive_buffer_size(Some(8 * 1024));
        let mut server_cfg = quinn::ServerConfig::with_crypto(server_crypto_arc);
        server_cfg.transport_config(Arc::new(transport));

        let std_sock = xray_transport::sockopt::bind_udp_endpoint(listen, &Default::default())?;
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server_cfg),
            std_sock,
            Arc::new(quinn::TokioRuntime),
        )?;

        Ok((
            Self {
                endpoint,
                expected_uuid: uuid,
                password,
                cert_der: tls.cert_der.clone(),
            },
            tls.cert_der,
        ))
    }

    /// 监听地址。
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.endpoint.local_addr().expect("local_addr")
    }

    /// 自签证书 DER（客户端 trust store 用）。
    #[must_use]
    pub fn cert_der(&self) -> &[u8] {
        &self.cert_der
    }

    /// 关闭 endpoint。
    pub fn close(&self) {
        self.endpoint.close(0u32.into(), b"");
    }

    /// 运行 accept loop（TCP + UDP relay）。
    pub async fn run(self) -> Result<()> {
        let password = self.password.clone();
        let uuid = self.expected_uuid;
        loop {
            let incoming = self.endpoint.accept().await;
            let Some(incoming) = incoming else {
                break;
            };
            let pwd = password.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_connection(incoming, uuid, &pwd).await {
                    tracing::warn!("tuic mock server connection error: {e:?}");
                }
            });
        }
        Ok(())
    }
}

async fn handle_connection(
    incoming: quinn::Incoming,
    expected_uuid: Uuid,
    password: &str,
) -> Result<()> {
    let conn = incoming.await?;

        // 生成 expected_token (对齐官方 tuic v5: label=UUID 16字节)
        let mut expected_token = [0u8; TOKEN_LEN];
        conn.export_keying_material(&mut expected_token, expected_uuid.as_bytes(), password.as_bytes())
            .map_err(|_| TuicError::KeyingMaterialExport)?;
    // accept_uni 读 Authenticate
    let mut uni = conn.accept_uni().await?;
    let cmd = read_authenticate(&mut uni).await?;
    match cmd {
        crate::protocol::Command::Authenticate {
            uuid_bytes,
            token,
        } => {
            if uuid_bytes != *expected_uuid.as_bytes() || token != expected_token {
                conn.close(1u32.into(), b"auth failed");
                return Err(TuicError::Io(std::io::Error::other("auth failed")));
            }
        }
        _ => {
            return Err(TuicError::Io(std::io::Error::other(
                "first uni stream must be Authenticate",
            )));
        }
    }

    // accept_bi + accept_uni + read_datagram 三路循环（bd 8hb + 7ry/1ur）：
    // Heartbeat/Dissociate 走 uni stream；UDP 包可走 bi-stream（quic 模式）
    // 或 QUIC DATAGRAM（native 模式，spec：datagram 承载完整 Packet 命令帧）。
    let mut udp_table = UdpAssocTable::new(None);
    loop {
        tokio::select! {
            bi = conn.accept_bi() => {
                let (send_bi, recv_bi) = match bi {
                    Ok(p) => p,
                    Err(quinn::ConnectionError::ApplicationClosed(_)) => break,
                    Err(e) => return Err(e.into()),
                };
                handle_bi_frame(send_bi, recv_bi).await;
            }
            uni = conn.accept_uni() => {
                let uni = match uni {
                    Ok(u) => u,
                    Err(quinn::ConnectionError::ApplicationClosed(_)) => break,
                    Err(e) => return Err(e.into()),
                };
                handle_incoming_uni(uni, &conn, &mut udp_table, "tuic server").await;
            }
            dg = conn.read_datagram() => {
                match dg {
                    Ok(dg) => handle_datagram(&dg, &conn, &mut udp_table),
                    Err(e) => {
                        tracing::debug!("tuic server: datagram read: {e:?}");
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

/// 处理一个 QUIC DATAGRAM（native UDP 模式，bd 7ry）。
///
/// spec：datagram 承载完整命令帧（VER + TYPE + 负载）；Packet 路由到
/// assoc 会话并以 datagram 模式回写，Heartbeat 等保活命令忽略。
fn handle_datagram(
    dg: &bytes::Bytes,
    conn: &quinn::Connection,
    table: &mut UdpAssocTable,
) {
    let mut cursor = &dg[..];
    match crate::protocol::parse_header(&mut cursor) {
        Ok(t) if t == type_code::PACKET => match Packet::read_payload(&mut cursor) {
            Ok(pkt) => table.handle_packet(pkt, ReplySink::Dgram(conn.clone())),
            Err(e) => tracing::debug!("tuic server: datagram packet parse: {e:?}"),
        },
        Ok(_) => {} // Heartbeat 可走 datagram（spec），保活语义无需处理
        Err(e) => tracing::debug!("tuic server: datagram header: {e:?}"),
    }
}

/// 处理一条 bi stream：读 Connect 帧并 spawn relay。
///
/// spec：bi stream 只承载 Connect（Packet 走 uni/datagram，票 d1zr）。
async fn handle_bi_frame(send_bi: quinn::SendStream, recv_bi: quinn::RecvStream) {
    match read_frame_from_recv(recv_bi, 256).await {
        Ok((Command::Connect(addr), recv_bi, initial_bytes)) => {
            let Some(target) = addr_to_socket_addr(&addr) else {
                tracing::warn!("tuic server: addr not ip literal: {addr:?}");
                return;
            };
            tokio::spawn(async move {
                if let Err(e) = relay_to_tcp(target, send_bi, recv_bi, initial_bytes).await {
                    tracing::debug!("tuic relay {target}: {e:?}");
                }
            });
        }
        Ok((_, _, _)) => {}
        Err(e) => {
            // bi 收到 Packet（TYPE 0x02）等非 Connect 帧落此路径，忽略（spec，票 d1zr）
            tracing::debug!("tuic server: bi frame skipped/invalid: {e:?}");
        }
    }
}

/// uni stream 中收到的帧：Command（Authenticate/Heartbeat/Dissociate）或 Packet。
pub(crate) enum UniFrame {
    Command(Command),
    Packet(Packet),
}

/// 从 uni stream 流式读出一帧（`VER + TYPE` 后按类型分段 `read_exact`）。
///
/// QUIC 流单次 read 可能分片（票 ieik：Authenticate 半帧被旧单 read 解析
/// 即 auth failed），故 PACKET 帧走 [`read_packet_payload`] 布局消费；
/// 命令帧（Authenticate 50B / Dissociate 4B / Heartbeat 2B，均为固定短帧，
/// 变长 Connect 只走 bi）循环累积到 [`Command::read_payload`] 可解析为止。
pub(crate) async fn read_uni_frame(stream: &mut quinn::RecvStream) -> Result<UniFrame> {
    let mut vt = [0u8; 2];
    stream
        .read_exact(&mut vt)
        .await
        .map_err(quinn_read_exact_err)?;
    let mut vh: &[u8] = &vt;
    let type_byte = crate::protocol::parse_header(&mut vh)?;
    if type_byte == type_code::PACKET {
        return read_packet_payload(stream).await.map(UniFrame::Packet);
    }
    let mut buf: Vec<u8> = Vec::with_capacity(64);
    loop {
        let mut cursor: &[u8] = &buf;
        match Command::read_payload(type_byte, &mut cursor) {
            Ok(cmd) => return Ok(UniFrame::Command(cmd)),
            Err(TuicError::UnexpectedEof(_)) => {}
            Err(e) => return Err(e),
        }
        let mut chunk = [0u8; 64];
        let n = stream
            .read(&mut chunk)
            .await?
            .ok_or_else(|| TuicError::UnexpectedEof("command stream closed"))?;
        if n == 0 {
            return Err(TuicError::UnexpectedEof("command stream closed"));
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > 1024 {
            return Err(TuicError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "uni command too long",
            )));
        }
    }
}

/// 读首条 uni stream 的 Authenticate 帧（流式分段读，QUIC 分片安全）。
pub(crate) async fn read_authenticate(stream: &mut quinn::RecvStream) -> Result<Command> {
    match read_uni_frame(stream).await? {
        UniFrame::Command(cmd) => Ok(cmd),
        UniFrame::Packet(_) => Err(TuicError::Io(std::io::Error::other(
            "first uni stream must be Authenticate",
        ))),
    }
}

/// 处理一条入向 uni stream：认证后的 Heartbeat/Dissociate 命令或
/// quic 模式 Packet（spec：Packet 只经 uni stream，server 同模 open_uni 回包）。
pub(crate) async fn handle_incoming_uni(
    mut uni: quinn::RecvStream,
    conn: &quinn::Connection,
    udp_table: &mut UdpAssocTable,
    ctx: &str,
) {
    match read_uni_frame(&mut uni).await {
        Ok(UniFrame::Command(Command::Heartbeat)) => {}
        Ok(UniFrame::Command(Command::Dissociate { assoc_id })) => {
            udp_table.dissociate(assoc_id);
        }
        Ok(UniFrame::Command(_)) => {}
        Ok(UniFrame::Packet(pkt)) => {
            // 路由进 assoc 会话，响应由会话 task open_uni 回写（票 d1zr）
            udp_table.handle_packet(pkt, ReplySink::Uni(conn.clone()));
        }
        Err(e) => tracing::debug!("{ctx}: uni stream read: {e:?}"),
    }
}


/// 真正的双向 relay：client ↔ (quinn bi) ↔ server ↔ (tcp) ↔ 目标。
///
/// `initial_bytes` 是客户端随 Connect header 一并发的 TCP payload 前缀。
pub(crate) async fn relay_to_tcp(
    target: SocketAddr,
    mut send_bi: quinn::SendStream,
    mut recv_bi: quinn::RecvStream,
    initial_bytes: Vec<u8>,
) -> std::io::Result<()> {
    let mut tcp = tokio::net::TcpStream::connect(target).await?;
    let (mut tcp_read, mut tcp_write) = tcp.split();

    // 先把 header 后客户端已发送的 payload 转给 TCP
    if !initial_bytes.is_empty() {
        tcp_write.write_all(&initial_bytes).await?;
    }

    let c2s = async {
        tokio::io::copy(&mut recv_bi, &mut tcp_write).await?;
        tcp_write.shutdown().await
    };
    let s2c = async {
        tokio::io::copy(&mut tcp_read, &mut send_bi).await?;
        let _ = send_bi.finish();
        Ok::<(), std::io::Error>(())
    };

    let _ = tokio::try_join!(c2s, s2c)?;
    Ok(())
}

/// 从 quinn RecvStream 读出 bi-stream Connect 帧，
/// 返回 (命令, 已消费的 RecvStream, header 之后的剩余字节)。
///
/// 剩余字节留给 relay，避免 quinn 一次 read 把 header 和后续 payload 都读出。
///
/// spec：bi stream 只承载 Connect；Packet（TYPE 0x02）不经 bi（票 d1zr），
/// 落入 [`Command::read_payload`] 的 UnknownCommandType 错误路径由调用方忽略。
pub(crate) async fn read_frame_from_recv(
    mut stream: quinn::RecvStream,
    max_len: usize,
) -> Result<(Command, quinn::RecvStream, Vec<u8>)> {
    let mut buf = vec![0u8; max_len];
    let n = stream.read(&mut buf).await?.ok_or_else(|| {
        TuicError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "stream closed before command",
        ))
    })?;
    let mut cursor = &buf[..n];
    let type_byte = crate::protocol::parse_header(&mut cursor)?;
    let cmd = Command::read_payload(type_byte, &mut cursor)?;
    Ok((cmd, stream, cursor.to_vec()))
}

/// UDP assoc 会话空闲淘汰（对齐 Go `CancelAfterInactivity(1min)` 与 SS inbound 样板）。
const UDP_ASSOC_IDLE: Duration = Duration::from_secs(60);

/// 会话上行项：(目标, 负载, 回写目标, 请求 pkt_id——响应帧原样回显，
/// 客户端 quic 模式按 (assoc_id, pkt_id) 配对)。
type UdpAssocItem = (Destination, Bytes, ReplySink, u16);

/// UDP 响应回写目标：与请求到达通道同模式（spec：server 按首包模式回写）。
///
/// bi 模式下每请求独占一个 stream，响应写回最近一个请求的 stream
/// （ponytail: 逐个请求-响应的客户端精确正确；同 assoc 流水线并发时最佳努力）。
pub(crate) enum ReplySink {
    Dgram(quinn::Connection),
    /// quic 模式：响应经 server 新开的 uni stream 回写（票 d1zr，spec 同模回包）。
    Uni(quinn::Connection),
}

impl ReplySink {
    /// 以 Packet 帧格式（VER + TYPE + 负载）回写一个响应。
    async fn write_packet(&mut self, pkt: &Packet) -> Result<()> {
        let mut out = BytesMut::with_capacity(pkt.encoded_len());
        out.put_u8(crate::protocol::VERSION);
        out.put_u8(type_code::PACKET);
        pkt.write_payload(&mut out);
        match self {
            ReplySink::Dgram(c) => {
                c.send_datagram(out.freeze()).map_err(TuicError::QuinnSendDatagram)?;
            }
            ReplySink::Uni(c) => {
                let mut uni = c.open_uni().await?;
                uni.write_all(&out).await?;
                let _ = uni.finish();
            }
        }
        Ok(())
    }
}

/// per-connection UDP 会话表（bd 1ur/7ry）：assoc_id → 会话 task sender。
///
/// 对应 TUIC v5 spec UDP relaying：客户端为每个 UDP 关联分配 assoc_id，
/// server 维护 assoc_id → 长生命周期出口的映射；Dissociate 销毁。
/// - dispatch 模式（Some）：走 [`UdpDispatchSession`] 路由，域名目标原样透传
/// - 直连模式（None，mock）：长生命周期 UdpSocket + 本地 DNS 解析
///
/// bi-stream Packet 与 native datagram 共享本表（spec：同一 assoc 混用两种
/// 到达模式时共用一个出口）。
pub(crate) struct UdpAssocTable {
    dispatcher: Option<Arc<dyn DispatchHandler>>,
    sessions: HashMap<u16, tokio::sync::mpsc::Sender<UdpAssocItem>>,
    /// per-assoc 分片重组器（bd 2x5 分片实装）。
    frags: HashMap<u16, crate::protocol::FragmentAssembler>,
}

impl UdpAssocTable {
    pub(crate) fn new(dispatcher: Option<Arc<dyn DispatchHandler>>) -> Self {
        Self {
            dispatcher,
            sessions: HashMap::new(),
            frags: HashMap::new(),
        }
    }

    /// 路由一个客户端 Packet 到其 assoc 会话；无则新建。
    ///
    /// 分片包走 per-assoc [`FragmentAssembler`] 重组：
    /// 全部到齐后才路由；中间片静默缓存；非法 frag_total/frag_id 警告丢包。
    /// 通道满时丢包（UDP 有损语义）。
    pub(crate) fn handle_packet(&mut self, pkt: Packet, sink: ReplySink) {
        // ponytail: 收包时顺带清扫已退出（空闲淘汰/出错）会话的残留 sender
        self.sessions.retain(|_, tx| !tx.is_closed());
        // 分片路径：喂给该 assoc 的 assembler，未到齐则缓存
        if pkt.frag_total > 1 {
            let assoc = pkt.assoc_id;
            let assembler = self
                .frags
                .entry(assoc)
                .or_insert_with(crate::protocol::FragmentAssembler::new);
            match assembler.feed(pkt) {
                Ok(Some(complete)) => {
                    // 重组成功 → 走常规路由
                    self.route_packet(complete, sink);
                }
                Ok(None) => {
                    // 等待其他片
                }
                Err(e) => {
                    tracing::debug!(
                        "tuic udp relay: fragment assemble error assoc={assoc}: {e:?}"
                    );
                }
            }
            return;
        }
        self.route_packet(pkt, sink);
    }

    /// 内部：把（完整）Packet 投递到 assoc 会话。
    fn route_packet(&mut self, pkt: Packet, sink: ReplySink) {
        let Some(dest) = tuic_addr_to_udp_dest(&pkt.addr) else {
            tracing::warn!("tuic udp relay: packet without target addr");
            return;
        };
        let assoc_id = pkt.assoc_id;
        let pkt_id = pkt.pkt_id;
        let item = (dest, pkt.data, sink, pkt_id);
        let tx = self.sessions.entry(assoc_id).or_insert_with(|| {
            let (tx, rx) = tokio::sync::mpsc::channel(16);
            let dispatcher = self.dispatcher.clone();
            tokio::spawn(udp_assoc_task(assoc_id, dispatcher, rx));
            tx
        });
        if tx.try_send(item).is_err() {
            tracing::debug!("tuic udp assoc {assoc_id} backlogged, dropping packet");
        }
    }

    /// Dissociate（spec 0x03）：销毁会话，释放出口资源。
    pub(crate) fn dissociate(&mut self, assoc_id: u16) {
        self.sessions.remove(&assoc_id);
        // 清掉对应 assoc 的分片缓存（避免 GC）
        self.frags.remove(&assoc_id);
    }
}

/// 单 assoc 会话 task：上行（客户端包 → outbound）+ 下行（outbound 响应 → 客户端）。
///
/// 发送端（表 entry）drop 或 60s 双向无活动时退出。
async fn udp_assoc_task(
    assoc_id: u16,
    dispatcher: Option<Arc<dyn DispatchHandler>>,
    mut rx: tokio::sync::mpsc::Receiver<UdpAssocItem>,
) {
    match dispatcher {
        Some(d) => udp_assoc_dispatch(assoc_id, d, rx).await,
        None => udp_assoc_direct(assoc_id, rx).await,
    }
}

/// 直连模式（mock）：assoc 生命周期内单个 UdpSocket（cone 出口）。
async fn udp_assoc_direct(assoc_id: u16, mut rx: tokio::sync::mpsc::Receiver<UdpAssocItem>) {
    let udp = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!("tuic udp assoc {assoc_id} bind: {e:?}");
            return;
        }
    };
    let mut sink: Option<ReplySink> = None;
    let mut cur_pkt_id: u16 = 0;
    let mut resp_buf = vec![0u8; 65_536];
    let idle = tokio::time::sleep(UDP_ASSOC_IDLE);
    tokio::pin!(idle);
    loop {
        tokio::select! {
            item = rx.recv() => {
                match item {
                    Some((dest, payload, s, pkt_id)) => {
                        sink = Some(s);
                        cur_pkt_id = pkt_id;
                        if let Some(target) = resolve_udp_dest(&dest).await {
                            if let Err(e) = udp.send_to(&payload, target).await {
                                tracing::debug!("tuic udp assoc {assoc_id} send: {e:?}");
                            }
                        } else {
                            tracing::debug!("tuic udp assoc {assoc_id} resolve failed: {dest:?}");
                        }
                        idle.as_mut().reset(tokio::time::Instant::now() + UDP_ASSOC_IDLE);
                    }
                    None => break, // Dissociate 或表清理
                }
            }
            r = udp.recv_from(&mut resp_buf) => {
                match r {
                    Ok((n, peer)) => {
                        if let Some(s) = sink.as_mut() {
                            let pkt = Packet::new(
                                assoc_id,
                                cur_pkt_id,
                                socket_addr_to_tuic(peer),
                                Bytes::copy_from_slice(&resp_buf[..n]),
                            );
                            if let Err(e) = s.write_packet(&pkt).await {
                                tracing::debug!("tuic udp assoc {assoc_id} reply: {e:?}");
                            }
                        }
                        idle.as_mut().reset(tokio::time::Instant::now() + UDP_ASSOC_IDLE);
                    }
                    Err(e) => {
                        tracing::debug!("tuic udp assoc {assoc_id} recv: {e:?}");
                        break;
                    }
                }
            }
            _ = &mut idle => break, // 60s 空闲淘汰
        }
    }
}

/// dispatch 模式（生产）：[`UdpDispatchSession`] 路由，域名透传由 outbound 解析。
async fn udp_assoc_dispatch(
    assoc_id: u16,
    dispatcher: Arc<dyn DispatchHandler>,
    mut rx: tokio::sync::mpsc::Receiver<UdpAssocItem>,
) {
    let mut session = UdpDispatchSession::new(dispatcher);
    let mut sink: Option<ReplySink> = None;
    let mut cur_pkt_id: u16 = 0;
    let idle = tokio::time::sleep(UDP_ASSOC_IDLE);
    tokio::pin!(idle);
    loop {
        tokio::select! {
            item = rx.recv() => {
                match item {
                    Some((dest, payload, s, pkt_id)) => {
                        sink = Some(s);
                        cur_pkt_id = pkt_id;
                        if let Err(e) = session.send_packet(&dest, &payload).await {
                            tracing::debug!("tuic udp assoc {assoc_id} dispatch send: {e:?}");
                            break;
                        }
                        idle.as_mut().reset(tokio::time::Instant::now() + UDP_ASSOC_IDLE);
                    }
                    None => break, // Dissociate 或表清理
                }
            }
            r = session.recv_packet() => {
                match r {
                    Ok(Some((source, payload))) => {
                        if let Some(s) = sink.as_mut() {
                            // Vec → Bytes 零拷贝（recv_packet 的 owned 载荷）
                            let pkt = Packet::new(
                                assoc_id,
                                cur_pkt_id,
                                dest_to_tuic_addr(&source),
                                Bytes::from(payload),
                            );
                            if let Err(e) = s.write_packet(&pkt).await {
                                tracing::debug!("tuic udp assoc {assoc_id} reply: {e:?}");
                            }
                        }
                        idle.as_mut().reset(tokio::time::Instant::now() + UDP_ASSOC_IDLE);
                    }
                    Ok(None) => break, // outbound 关闭
                    Err(e) => {
                        // qyn8：recv 错误结束会话（Go read 错误语义），
                        // continue 与滞留坏帧构成忙旋
                        tracing::debug!("tuic udp assoc {assoc_id} dispatch recv: {e:?}");
                        break;
                    }
                }
            }
            _ = &mut idle => break, // 60s 空闲淘汰
        }
    }
}

/// TUIC Address → UDP Destination（域名原样保留，由 outbound 解析）。
pub(crate) fn tuic_addr_to_udp_dest(addr: &Address) -> Option<Destination> {
    match addr {
        Address::Domain(d, p) => {
            Some(Destination::udp(XAddress::Domain(d.clone()), Port::new(*p)))
        }
        Address::Ipv4(ip, p) => Some(Destination::udp(XAddress::IPv4(*ip), Port::new(*p))),
        Address::Ipv6(ip, p) => Some(Destination::udp(XAddress::IPv6(*ip), Port::new(*p))),
        Address::None => None,
    }
}

/// xray Destination 来源 → TUIC Address（响应帧 ADDR 字段）。
fn dest_to_tuic_addr(source: &Destination) -> Address {
    let port = source.port().value();
    match source.address() {
        XAddress::Domain(d) => Address::Domain(d.clone(), port),
        XAddress::IPv4(ip) => Address::Ipv4(*ip, port),
        XAddress::IPv6(ip) => Address::Ipv6(*ip, port),
    }
}

/// SocketAddr 来源 → TUIC Address（直连模式响应帧 ADDR 字段）。
fn socket_addr_to_tuic(addr: SocketAddr) -> Address {
    match addr.ip() {
        IpAddr::V4(ip) => Address::Ipv4(ip, addr.port()),
        IpAddr::V6(ip) => Address::Ipv6(ip, addr.port()),
    }
}

/// 直连模式目标解析：IP 直用，域名走系统 DNS（dispatch 模式不经过本函数）。
async fn resolve_udp_dest(dest: &Destination) -> Option<SocketAddr> {
    let port = dest.port().value();
    match dest.address() {
        XAddress::IPv4(ip) => Some(SocketAddr::new(IpAddr::V4(*ip), port)),
        XAddress::IPv6(ip) => Some(SocketAddr::new(IpAddr::V6(*ip), port)),
        XAddress::Domain(d) => tokio::net::lookup_host((d.as_str(), port))
            .await
            .ok()
            .and_then(|mut i| i.next()),
    }
}

pub(crate) fn addr_to_socket_addr(addr: &crate::protocol::Address) -> Option<SocketAddr> {
    match addr {
        crate::protocol::Address::Ipv4(ip, port) => Some(SocketAddr::new(IpAddr::V4(*ip), *port)),
        crate::protocol::Address::Ipv6(ip, port) => Some(SocketAddr::new(IpAddr::V6(*ip), *port)),
        crate::protocol::Address::Domain(_, _) | crate::protocol::Address::None => None,
    }
}

#[cfg(test)]
mod udp_assoc_tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UdpSocket;
    use uuid::Uuid;

    use xray_app_dispatcher::default::PinFuture;
    use xray_app_dispatcher::DispatchHandler;
    use xray_features::inbound::InboundHandler;
    use xray_common::net::address::Address as XAddress;
    use xray_common::net::destination::Destination;
    use xray_common::net::network::Network;
    use xray_common::net::port::Port;
    use xray_transport::link::Link;

    use crate::client::{CongestionControl, TuicClient};
    use crate::inbound::{TuicInboundConfig, TuicInboundHandler};
    use crate::pool::QuinnConnectionPool;
    use crate::protocol::command::type_code;
    use crate::protocol::{Address, Command, Packet};
    use bytes::BufMut;
    use crate::server::TuicMockServer;

    /// 普通 UDP echo server。
    async fn start_udp_echo() -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind echo");
        let addr = sock.local_addr().expect("local_addr");
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_536];
            loop {
                let Ok((n, peer)) = sock.recv_from(&mut buf).await else { break };
                if sock.send_to(&buf[..n], peer).await.is_err() {
                    break;
                }
            }
        });
        addr
    }

    /// 元信息 echo：回 `{对端端口}|{payload}`，用于观测服务端出口端口。
    async fn start_udp_meta_echo() -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind meta echo");
        let addr = sock.local_addr().expect("local_addr");
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_536];
            loop {
                let Ok((n, peer)) = sock.recv_from(&mut buf).await else { break };
                let resp =
                    format!("{}|{}", peer.port(), String::from_utf8_lossy(&buf[..n]));
                if sock.send_to(resp.as_bytes(), peer).await.is_err() {
                    break;
                }
            }
        });
        addr
    }

    fn make_client_config(cert_der: &[u8]) -> Arc<rustls::ClientConfig> {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(cert_der.to_vec().into()).expect("add cert");
        Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth(),
        )
    }

    async fn connect_mock(
        password: &str,
    ) -> (TuicClient, tokio::task::JoinHandle<()>) {
        let uuid = Uuid::new_v4();
        let (server, cert_der) = TuicMockServer::bind(
            "127.0.0.1:0".parse().expect("parse addr"),
            "localhost",
            uuid,
            password.to_string(),
        )
        .await
        .expect("mock server bind");
        let server_addr = server.local_addr();
        let task = tokio::spawn(async move {
            let _ = server.run().await;
        });
        let client = tokio::time::timeout(
            Duration::from_secs(10),
            TuicClient::connect(
                server_addr,
                "localhost",
                uuid,
                password,
                make_client_config(&cert_der),
                QuinnConnectionPool::new(),
            ),
        )
        .await
        .expect("connect timed out")
        .expect("connect failed");
        (client, task)
    }

    /// 捕获 dispatch 收到的 dest 并持续 drain link（不回包）的 handler。
    #[derive(Debug)]
    struct CaptureHandler(std::sync::Arc<parking_lot::Mutex<Vec<Destination>>>);

    impl DispatchHandler for CaptureHandler {
        fn tag(&self) -> &str {
            "capture"
        }
        fn dispatch(&self, dest: &Destination, link: Link) -> PinFuture<()> {
            self.0.lock().push(dest.clone());
            Box::pin(async move {
                use xray_buf::io::Reader;
                let mut reader = link.reader;
                while reader.read_multi_buffer().await.is_ok() {}
            })
        }
    }

    /// relay echo：link 数据原样写回（iq1o⑦：bi-stream relay 双向通路观测）。
    #[derive(Debug)]
    struct EchoHandler;

    impl DispatchHandler for EchoHandler {
        fn tag(&self) -> &str {
            "echo"
        }
        fn dispatch(&self, _dest: &Destination, link: Link) -> PinFuture<()> {
            Box::pin(async move {
                use xray_buf::io::{Reader, Writer};
                let mut reader = link.reader;
                let mut writer = link.writer;
                while let Ok(mb) = reader.read_multi_buffer().await {
                    if mb.is_empty() {
                        continue;
                    }
                    if writer.write_multi_buffer(mb).await.is_err() {
                        break;
                    }
                }
            })
        }
    }

    async fn connect_inbound(
        handler: Arc<dyn DispatchHandler>,
        password: &str,
        congestion_control: Option<CongestionControl>,
    ) -> TuicClient {
        let uuid = Uuid::new_v4();
        let inbound = TuicInboundHandler::new(
            "tuic-in-test",
            TuicInboundConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                server_name: "localhost".to_string(),
                uuid,
                password: password.to_string(),
                cert_der: None,
                key_der: None,
                congestion_control,
                brutal_up_bps: 0,
                sockopt: Default::default(),
            },
        )
        .unwrap()
        .with_dispatch(handler);
        inbound.start().await.expect("inbound start");
        let server_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), inbound.port());
        let cert_der = inbound.cert_der().expect("cert after start");
        tokio::time::timeout(
            Duration::from_secs(10),
            TuicClient::connect(
                server_addr,
                "localhost",
                uuid,
                password,
                make_client_config(&cert_der),
                QuinnConnectionPool::new(),
            ),
        )
        .await
        .expect("connect timed out")
        .expect("connect failed")
    }

    /// ① 同一 assoc_id 的第二个包必须复用会话（不重建 outbound socket）。
    #[tokio::test]
    async fn udp_assoc_reuses_session_across_packets() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let echo_addr = start_udp_meta_echo().await;
        let (client, _server) = connect_mock("assoc-reuse").await;

        let assoc = client.dial_udp(0x0007);
        let target = Address::Ipv4(Ipv4Addr::new(127, 0, 0, 1), echo_addr.port());
        let mut ports = Vec::new();
        for payload in ["first", "second"] {
            let resp = tokio::time::timeout(
                Duration::from_secs(10),
                assoc.send_recv(target.clone(), payload.as_bytes(), None),
            )
            .await
            .expect("send_recv timed out")
            .expect("send_recv failed");
            let resp = String::from_utf8(resp).expect("utf8");
            let (port, echo_payload) = resp.split_once('|').expect("meta echo format");
            assert_eq!(echo_payload, payload);
            ports.push(port.to_string());
        }
        assert_eq!(ports[0], ports[1], "same assoc must reuse one outbound socket");
        client.close(0u32.into(), b"");
    }

    /// ③ native datagram：服务端处理 QUIC DATAGRAM 并按同模式回写。
    #[tokio::test]
    async fn native_datagram_server_path() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let echo_addr = start_udp_echo().await;
        let (client, _server) = connect_mock("native-dgram").await;

        let assoc = client.dial_udp(0x0D11);
        let target = Address::Ipv4(Ipv4Addr::new(127, 0, 0, 1), echo_addr.port());
        let payload = b"native dgram ping";
        let resp = tokio::time::timeout(
            Duration::from_secs(10),
            assoc.send_recv_native(target, payload, None),
        )
        .await
        .expect("native send_recv timed out")
        .expect("native send_recv failed");
        assert_eq!(resp, payload);
        client.close(0u32.into(), b"");
    }

    /// ② 域名目标不丢弃：dispatch 收到的 dest 域名原样（Network::UDP）。
    #[tokio::test]
    async fn udp_domain_dest_reaches_dispatch_verbatim() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let store = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
        let client = connect_inbound(
            Arc::new(CaptureHandler(std::sync::Arc::clone(&store))),
            "domain-dest",
            None,
        )
        .await;

        let assoc = client.dial_udp(0x0DD0);
        let target = Address::Domain("example.invalid".to_string(), 53);
        // 无 echo handler：预期超时，仅验证 dest 送达 dispatch
        let _ = assoc
            .send_recv(target, b"dns-q", Some(Duration::from_millis(500)))
            .await;

        for _ in 0..50 {
            if store.lock().len() >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let got = store.lock().clone();
        assert_eq!(got.len(), 1, "domain packet must reach dispatch exactly once");
        assert_eq!(
            got[0],
            Destination::new(
                XAddress::Domain("example.invalid".to_string()),
                Port::new(53),
                Network::UDP,
            ),
            "dispatch dest must carry verbatim domain over UDP"
        );
        client.close(0u32.into(), b"");
    }

    /// ④ Dissociate 销毁会话：同 assoc 再发包 → 新会话（dispatch 二次建立）。
    #[tokio::test]
    async fn dissociate_destroys_session() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let store = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
        let client = connect_inbound(
            Arc::new(CaptureHandler(std::sync::Arc::clone(&store))),
            "dissociate",
            None,
        )
        .await;

        let assoc_id = 0x0D55;
        let assoc = client.dial_udp(assoc_id);
        let target = Address::Ipv4(Ipv4Addr::new(127, 0, 0, 1), 9);
        let _ = assoc
            .send_recv(target.clone(), b"a", Some(Duration::from_millis(500)))
            .await;
        for _ in 0..50 {
            if store.lock().len() >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(store.lock().len(), 1, "first packet establishes session");

        // 客户端 Dissociate（uni stream，spec 0x03）
        let mut uni = client.quinn_conn().open_uni().await.expect("open uni");
        let cmd = Command::Dissociate { assoc_id };
        let mut buf = bytes::BytesMut::with_capacity(cmd.encoded_len());
        cmd.write_to(&mut buf);
        uni.write_all(&buf).await.expect("write dissociate");
        let _ = uni.finish();

        // 同 assoc 再发包 → 新会话
        let _ = assoc
            .send_recv(target, b"b", Some(Duration::from_millis(500)))
            .await;
        for _ in 0..50 {
            if store.lock().len() >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(
            store.lock().len(),
            2,
            "dissociate must destroy session; next packet re-establishes"
        );
        client.close(0u32.into(), b"");
    }

    /// 票 d1zr：quic 模式 Packet 走 uni stream（spec uni-stream 模型）。
    /// ① send_recv echo 成功 = 客户端 open_uni 发送 + server 同模 open_uni 回包；
    /// ② 手动 bi-stream Packet 不再被 server 处理（bi 只承载 Connect）。
    #[tokio::test]
    async fn quic_mode_packet_goes_uni_stream() {
        use crate::protocol::VERSION;

        let _ = rustls::crypto::ring::default_provider().install_default();
        let echo_addr = start_udp_echo().await;
        let (client, _server) = connect_mock("uni-packet").await;

        // ① quic 模式 echo
        let assoc = client.dial_udp(0x0A11);
        let target = Address::Ipv4(Ipv4Addr::new(127, 0, 0, 1), echo_addr.port());
        let resp = tokio::time::timeout(
            Duration::from_secs(10),
            assoc.send_recv(target.clone(), b"uni ping", None),
        )
        .await
        .expect("send_recv timed out")
        .expect("send_recv failed");
        assert_eq!(resp, b"uni ping");

        // ② bi-stream Packet 被忽略（无响应 → 读端超时）
        let pkt = Packet::new(0x0A11, 999, target, bytes::Bytes::from_static(b"bi ping"));
        let (mut send, mut recv) =
            client.quinn_conn().open_bi().await.expect("open bi");
        let mut buf = bytes::BytesMut::with_capacity(pkt.encoded_len() + 2);
        buf.put_u8(VERSION);
        buf.put_u8(type_code::PACKET);
        pkt.write_payload(&mut buf);
        use tokio::io::AsyncWriteExt as _;
        send.write_all(&buf.freeze()).await.expect("write bi packet");
        let _ = send.finish();
        let r = tokio::time::timeout(
            Duration::from_millis(800),
            crate::udp::read_response_packet(&mut recv),
        )
        .await;
        // 不被 relay 的观测 = 无合法响应：要么超时无数据，要么 server 忽略帧后
        // 流被关闭（FinishedEarly）——两者都不是 UDP relay 回包
        assert!(
            matches!(r, Err(_) | Ok(Err(_))),
            "bi-stream Packet must NOT be relayed (spec: bi carries Connect only), got {r:?}"
        );
        client.close(0u32.into(), b"");
    }

    /// 票 ieik②：Heartbeat 经 QUIC datagram 承载（spec），连接保持不挂。
    #[tokio::test]
    async fn heartbeat_goes_datagram() {
        let (client, _server) = connect_mock("hb-dgram").await;
        client.heartbeat().await.expect("heartbeat datagram send");
        client.close(0u32.into(), b"");
    }

    /// 票 7ykg + iq1o⑦：服务端带 hysteria_bbr CC 配置真建链——CC 预装经共享槽
    /// [`HysteriaCCSlot`]，不得破坏 QUIC 握手 / Authenticate / bi-stream relay。
    /// 原"名为 relays 实则零 relay 断言"（store 建而未读）→ EchoHandler 原样
    /// 回写 + 客户端读回断言（对齐 928-935 的 timeout+expect+assert 形态）。
    #[tokio::test]
    async fn inbound_with_hysteria_bbr_cc_connects_and_relays() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = connect_inbound(
            Arc::new(EchoHandler),
            "cc-e2e",
            Some(CongestionControl::HysteriaBbr),
        )
        .await;

        // bi stream Connect → 写数据 → dispatch echo 回来 = relay 双向活
        let mut conn = client
            .dial(Address::Domain("cc-e2e.invalid".to_string(), 443))
            .await
            .expect("dial over hysteria_bbr server");
        conn.send.write_all(b"ping").await.expect("write over relay");
        let mut echoed = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(10), conn.recv.read_exact(&mut echoed))
            .await
            .expect("relay echo timed out")
            .expect("read relay echo failed");
        assert_eq!(echoed, *b"ping", "relay must carry payload back over bi stream");
        client.close(0u32.into(), b"");
    }
}

/// TLS 证书验证 + 连接选项 e2e（bd 7p0）。
#[cfg(test)]
mod tls_connect_tests {
    use std::sync::Arc;
    use std::time::Duration;

    use uuid::Uuid;

    use crate::error::TuicError;
    use crate::client::{CongestionControl, TuicClient, TuicConnectOptions};
    use crate::pool::QuinnConnectionPool;
    use crate::server::TuicMockServer;

    /// 验证路径必须拒绝自签证书：空 trust store 的客户端握手失败
    /// （等效 webpki-only 根对自签的行为——默认路径不再是 NoVerifier）。
    #[tokio::test]
    async fn verifying_client_rejects_self_signed() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let uuid = Uuid::new_v4();
        let (server, _cert) = TuicMockServer::bind(
            "127.0.0.1:0".parse().expect("parse addr"),
            "localhost",
            uuid,
            "tls-reject".to_string(),
        )
        .await
        .expect("mock server bind");
        let addr = server.local_addr();
        tokio::spawn(async move { let _ = server.run().await; });

        let cfg = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth(),
        );
        // quinn 客户端验证失败经 ~30s idle timeout 才浮现错误（实测 31s），
        // 故超时预算 45s；断言最终以 UnknownIssuer 类 TLS 错误拒绝
        let res = tokio::time::timeout(
            Duration::from_secs(45),
            TuicClient::connect(addr, "localhost", uuid, "tls-reject", cfg, QuinnConnectionPool::new()),
        )
        .await;
        assert!(
            matches!(res, Ok(Err(TuicError::Quinn(_)))),
            "verifying client must reject self-signed cert"
        );
    }
    /// connect_with：BBR 拥塞控制生效 + 用户 ALPN 不被默认 [h3, tuic] 覆盖。
    ///
    /// ① 用户 ALPN=["tuic"] + BBR → 握手成功（CC factory 与非空 ALPN 路径可用）；
    /// ② 用户 ALPN=["h3x"]（服务端不认识）→ 握手失败——若被默认覆盖则会成功。
    #[tokio::test]
    async fn connect_with_bbr_and_custom_alpn_ok() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let uuid = Uuid::new_v4();
        let (server, cert_der) = TuicMockServer::bind(
            "127.0.0.1:0".parse().expect("parse addr"),
            "localhost",
            uuid,
            "bbr-alpn".to_string(),
        )
        .await
        .expect("mock server bind");
        let addr = server.local_addr();
        tokio::spawn(async move { let _ = server.run().await; });

        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(cert_der.to_vec().into()).expect("add cert");

        // ① 用户 ALPN=["tuic"]：connect_with（BBR）握手成功——CC factory + 非空 ALPN 路径可用
        let mut cfg = rustls::ClientConfig::builder()
            .with_root_certificates(root_store.clone())
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"tuic".to_vec()];
        let options = TuicConnectOptions {
            congestion_control: CongestionControl::Bbr,
            ..TuicConnectOptions::default()
        };
        let client = tokio::time::timeout(
            Duration::from_secs(10),
            TuicClient::connect_with(
                addr,
                "localhost",
                uuid,
                "bbr-alpn",
                Arc::new(cfg),
                options,
                QuinnConnectionPool::new(),
            ),
        )
        .await
        .expect("connect timed out")
        .expect("connect failed");
        client.close(0u32.into(), b"");

        // ② 用户 ALPN=["h3x"]（服务端不认识）：必须握手失败——
        // 若 create_quic_connection 仍用默认 [h3, tuic] 覆盖用户列表，这里会连接成功
        let mut bogus = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        bogus.alpn_protocols = vec![b"h3x".to_vec()];
        let res = tokio::time::timeout(
            // ALPN 协商失败与证书验证失败同样经 ~30s idle timeout 浮现
            Duration::from_secs(45),
            TuicClient::connect(
                addr,
                "localhost",
                uuid,
                "bbr-alpn",
                Arc::new(bogus),
                QuinnConnectionPool::new(),
            ),
        )
        .await
        .expect("connect timed out");
        assert!(
            res.is_err(),
            "user-supplied ALPN must be honored, not clobbered by default"
        );
    }
}
