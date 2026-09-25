//! TUIC v5 入站处理器，对应 Go `proxy/tuic/server.go`。
//!
//! 生产版 inbound：quinn QUIC server → accept bi/uni stream → authenticate → TCP/UDP relay。
//! 复用 [`crate::server`] 中的协议解析与 relay 逻辑。

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use async_trait::async_trait;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use tokio::{sync::Mutex, task::JoinHandle};
use uuid::Uuid;
use xray_features::inbound::{InboundError, InboundHandler};

use crate::{
    client::{CongestionControl, apply_congestion_to_transport},
    error::{Result, TuicError},
    protocol::{
        Command, Packet,
        command::{TOKEN_LEN, type_code},
    },
    server::{
        ReplySink, UdpAssocTable, addr_to_socket_addr, handle_incoming_uni, read_authenticate,
        read_frame_from_recv, relay_to_tcp,
    },
};

/// TUIC inbound 配置。
#[derive(Debug, Clone)]
pub struct TuicInboundConfig {
    /// 监听地址。
    pub listen: SocketAddr,
    /// 服务器名称（TLS SNI / 自签证书 CN）。
    pub server_name: String,
    /// 用户 UUID（认证校验用）。
    pub uuid: Uuid,
    /// 用户密码（与 UUID 一起导出 keying material 生成 token）。
    pub password: String,
    /// 自签证书 DER（None 则自动生成）。
    pub cert_der: Option<Vec<u8>>,
    /// 私钥 DER（None 则自动生成）。
    pub key_der: Option<Vec<u8>>,
    /// 拥塞控制（None = 不预装，quinn 默认 CUBIC——官方 tuic-server 缺省
    /// `congestion_control: "cubic"`，行为等价零变化）。
    pub congestion_control: Option<CongestionControl>,
    /// Brutal 上行带宽（bps）；仅 [`CongestionControl::HysteriaBrutal`] 消费，
    /// 0 = 未配置（crate 层回落 BBR，解析层显式拒绝）。
    pub brutal_up_bps: u64,
    /// QUIC 端点 UDP socket 选项（缓冲调谐消费；默认空 = Go quic-go `wrapConn`
    /// 8MB 下限语义，见 [`xray_transport::sockopt::bind_udp_endpoint`]）。
    pub sockopt: xray_transport::sockopt::SocketOptions,
}

/// 自签证书产物。
struct TlsCert {
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
}

fn gen_self_signed(server_name: &str) -> std::result::Result<TlsCert, rcgen::Error> {
    let mut params = CertificateParams::new(vec![server_name.to_string()])?;
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, server_name);
    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;
    Ok(TlsCert { cert_der: cert.der().to_vec(), key_der: key_pair.serialize_der() })
}

/// TUIC 入站 Handler。
///
/// 持有配置 + quinn Endpoint，实现 [`InboundHandler`]。
/// `start` 时创建 quinn server 并 spawn accept loop。
pub struct TuicInboundHandler {
    tag: String,
    started: AtomicBool,
    config: TuicInboundConfig,
    /// 出站 dispatch（Some 时 Connect 走 dispatcher/router；None 直连目标——mock 场景）。
    dispatch: Option<Arc<dyn xray_app_dispatcher::DispatchHandler>>,
    /// listener + accept 任务句柄，close 时 abort。
    slot: Mutex<Option<InboundSlot>>,
    /// 自签证书 DER（start 时生成，供 client trust store）。
    cert_der: std::sync::Mutex<Option<Vec<u8>>>,
    /// 实际监听端口（start 后有效；listen 配置 0 时由 OS 分配）。
    local_port: std::sync::atomic::AtomicU16,
}

struct InboundSlot {
    endpoint: Arc<quinn::Endpoint>,
    _accept_task: JoinHandle<()>,
}

impl TuicInboundHandler {
    /// 构造入站 Handler。
    pub fn new(tag: impl Into<String>, config: TuicInboundConfig) -> Result<Self> {
        Ok(Self {
            tag: tag.into(),
            started: AtomicBool::new(false),
            config,
            dispatch: None,
            slot: Mutex::new(None),
            cert_der: std::sync::Mutex::new(None),
            local_port: std::sync::atomic::AtomicU16::new(0),
        })
    }

    /// 自签证书 DER（start 后可用，client trust store 用）。
    pub fn cert_der(&self) -> Option<Vec<u8>> {
        self.cert_der.lock().unwrap().clone()
    }

    /// 注入出站 dispatcher（生产路径：Connect 经 router 分发而非直连）。
    #[must_use]
    pub fn with_dispatch(
        mut self,
        dispatch: Arc<dyn xray_app_dispatcher::DispatchHandler>,
    ) -> Self {
        self.dispatch = Some(dispatch);
        self
    }

    /// 构建 Quinn server 配置（TLS + transport）。
    fn build_server_config(&self) -> Result<quinn::ServerConfig> {
        xray_common::ensure_default_crypto_provider();

        let (cert_der, key_der) =
            if let (Some(c), Some(k)) = (&self.config.cert_der, &self.config.key_der) {
                (c.clone(), k.clone())
            } else {
                let tls = gen_self_signed(&self.config.server_name).map_err(|e| {
                    TuicError::Io(std::io::Error::other(format!("rcgen self-signed failed: {e}")))
                })?;
                // 暴露自签证书给 client trust store
                *self.cert_der.lock().unwrap() = Some(tls.cert_der.clone());
                (tls.cert_der, tls.key_der)
            };

        let private_key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(key_der),
        );
        let cert_chain = vec![rustls::pki_types::CertificateDer::from(cert_der)];

        let mut server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)?;
        server_crypto.alpn_protocols = vec![b"h3".to_vec(), b"tuic".to_vec()];

        let quic_server_cfg = quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .map_err(|e| {
                TuicError::Io(std::io::Error::other(format!("quinn rustls convert: {e}")))
            })?;

        let mut transport = quinn::TransportConfig::default();
        transport.datagram_receive_buffer_size(Some(8 * 1024));
        // 服务端 CC 预装（对称 outbound 侧）：TUIC v5 无 Hysteria-CC 协商头，
        // 无 auth 后热切换事件，建链前预装即最终算法。
        if let Some(cc) = self.config.congestion_control {
            apply_congestion_to_transport(&mut transport, cc, self.config.brutal_up_bps);
        }
        let mut server_cfg = quinn::ServerConfig::with_crypto(Arc::new(quic_server_cfg));

        server_cfg.transport_config(Arc::new(transport));

        Ok(server_cfg)
    }
}

#[async_trait]
impl InboundHandler for TuicInboundHandler {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn start(&self) -> std::result::Result<(), InboundError> {
        if self.started.swap(true, Ordering::SeqCst) {
            return Err(InboundError::AlreadyStarted(self.tag.clone()));
        }

        let server_cfg = self
            .build_server_config()
            .map_err(|e| InboundError::ListenError(format!("tuic server config: {e}")))?;

        let std_sock =
            xray_transport::sockopt::bind_udp_endpoint(self.config.listen, &self.config.sockopt)
                .map_err(|e| {
                    InboundError::ListenError(format!("tuic bind {}: {e}", self.config.listen))
                })?;
        let endpoint = Arc::new(
            quinn::Endpoint::new(
                quinn::EndpointConfig::default(),
                Some(server_cfg),
                std_sock,
                Arc::new(quinn::TokioRuntime),
            )
            .map_err(|e| {
                InboundError::ListenError(format!("tuic bind {}: {e}", self.config.listen))
            })?,
        );

        let local_addr = endpoint
            .local_addr()
            .map_err(|e| InboundError::ListenError(format!("tuic local_addr: {e}")))?;

        self.local_port.store(local_addr.port(), std::sync::atomic::Ordering::SeqCst);
        tracing::info!(
            tag = %self.tag,
            addr = %local_addr,
            "tuic inbound listening"
        );

        let uuid = self.config.uuid;
        let password = self.config.password.clone();
        let tag = self.tag.clone();
        let endpoint_for_accept = Arc::clone(&endpoint);

        let dispatch = self.dispatch.clone();
        let accept_task = tokio::spawn(async move {
            loop {
                let incoming = endpoint_for_accept.accept().await;
                let Some(incoming) = incoming else {
                    break;
                };
                let pwd = password.clone();
                let t = tag.clone();
                let dispatch = dispatch.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(incoming, uuid, &pwd, dispatch).await {
                        tracing::debug!(tag = %t, error = ?e, "tuic inbound connection error");
                    }
                });
            }
        });

        let mut slot = self.slot.lock().await;
        *slot = Some(InboundSlot { endpoint, _accept_task: accept_task });
        Ok(())
    }

    async fn close(&self) -> std::result::Result<(), InboundError> {
        self.started.store(false, Ordering::SeqCst);
        let slot = self.slot.lock().await.take();
        if let Some(s) = slot {
            s.endpoint.close(0u32.into(), b"");
            s._accept_task.abort();
            tracing::info!(tag = %self.tag, "tuic inbound closed");
        }
        Ok(())
    }

    fn port(&self) -> u16 {
        let p = self.local_port.load(std::sync::atomic::Ordering::SeqCst);
        if p != 0 { p } else { self.config.listen.port() }
    }
}

async fn handle_connection(
    incoming: quinn::Incoming,
    expected_uuid: Uuid,
    password: &str,
    dispatch: Option<Arc<dyn xray_app_dispatcher::DispatchHandler>>,
) -> Result<()> {
    let conn = incoming.await?;
    // 生成 expected_token (对齐官方 tuic v5: label=UUID 16字节)
    let mut expected_token = [0u8; TOKEN_LEN];
    conn.export_keying_material(&mut expected_token, expected_uuid.as_bytes(), password.as_bytes())
        .map_err(|_| TuicError::KeyingMaterialExport)?;

    // accept_uni 读 Authenticate（流式分段读——QUIC 流分片安全，票 ieik）
    let mut uni = conn.accept_uni().await?;
    let cmd = read_authenticate(&mut uni).await?;
    match cmd {
        Command::Authenticate { uuid_bytes, token } => {
            if uuid_bytes != *expected_uuid.as_bytes() || token != expected_token {
                conn.close(1u32.into(), b"auth failed");
                return Err(TuicError::Io(std::io::Error::other("auth failed")));
            }
        },
        _ => {
            return Err(TuicError::Io(std::io::Error::other(
                "first uni stream must be Authenticate",
            )));
        },
    }

    // accept_bi + accept_uni + read_datagram 三路循环（bd 8hb + 7ry/1ur）：
    // Heartbeat/Dissociate 走 uni stream；UDP 包可走 bi-stream（quic 模式）
    // 或 QUIC DATAGRAM（native 模式，spec：datagram 承载完整 Packet 命令帧）。
    // UDP 会话表注入 dispatch（with_dispatch 生产路径；None 回退 mock 直连）。
    let mut udp_table = UdpAssocTable::new(dispatch.clone());
    loop {
        tokio::select! {
            bi = conn.accept_bi() => {
                let (send_bi, recv_bi) = match bi {
                    Ok(p) => p,
                    Err(quinn::ConnectionError::ApplicationClosed(_)) => break,
                    Err(e) => return Err(e.into()),
                };
                handle_bi_frame(send_bi, recv_bi, dispatch.clone()).await;
            }
            uni = conn.accept_uni() => {
                let uni = match uni {
                    Ok(u) => u,
                    Err(quinn::ConnectionError::ApplicationClosed(_)) => break,
                    Err(e) => return Err(e.into()),
                };
                handle_incoming_uni(uni, &conn, &mut udp_table, "tuic inbound").await;
            }
            dg = conn.read_datagram() => {
                match dg {
                    Ok(dg) => handle_datagram(&dg, &conn, &mut udp_table),
                    Err(e) => {
                        tracing::debug!("tuic inbound: datagram read: {e:?}");
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
fn handle_datagram(dg: &bytes::Bytes, conn: &quinn::Connection, table: &mut UdpAssocTable) {
    let mut cursor = &dg[..];
    match crate::protocol::parse_header(&mut cursor) {
        Ok(t) if t == type_code::PACKET => match Packet::read_payload(&mut cursor) {
            Ok(pkt) => table.handle_packet(pkt, ReplySink::Dgram(conn.clone())),
            Err(e) => tracing::debug!("tuic inbound: datagram packet parse: {e:?}"),
        },
        Ok(_) => {}, // Heartbeat 可走 datagram（spec），保活语义无需处理
        Err(e) => tracing::debug!("tuic inbound: datagram header: {e:?}"),
    }
}

/// 处理一条 bi stream：Connect → dispatcher 生产路径 / mock 直连。
///
/// spec：bi stream 只承载 Connect（Packet 走 uni/datagram，票 d1zr）。
async fn handle_bi_frame(
    send_bi: quinn::SendStream,
    recv_bi: quinn::RecvStream,
    dispatch: Option<Arc<dyn xray_app_dispatcher::DispatchHandler>>,
) {
    match read_frame_from_recv(recv_bi, 256).await {
        Ok((Command::Connect(addr), recv_bi, initial_bytes)) => {
            if let Some(handler) = dispatch {
                // 生产路径：构造 Destination + Link → dispatcher/router 分发。
                // initial_bytes 前置回 Link reader（read 一次读出 Connect+payload 的场景）。
                if let Some(dest) = tuic_addr_to_destination(&addr) {
                    let link = xray_transport::link::Link::new(
                        xray_buf::io::new_reader(InitialedReader::new(initial_bytes, recv_bi)),
                        xray_buf::io::new_writer(send_bi),
                    );
                    tokio::spawn(async move {
                        let _ = handler.dispatch(&dest, link).await;
                    });
                } else {
                    tracing::warn!("tuic inbound: unsupported addr: {addr:?}");
                }
            } else {
                // mock/直连路径（loopback 测试用）
                let Some(target) = addr_to_socket_addr(&addr) else {
                    tracing::warn!("tuic inbound: addr not ip literal: {addr:?}");
                    return;
                };
                tokio::spawn(async move {
                    if let Err(e) = relay_to_tcp(target, send_bi, recv_bi, initial_bytes).await {
                        tracing::debug!("tuic relay {target}: {e:?}");
                    }
                });
            }
        },
        Ok((_, _, _)) => {},
        Err(e) => {
            // bi 收到 Packet（TYPE 0x02）等非 Connect 帧落此路径，忽略（spec，票 d1zr）
            tracing::debug!("tuic inbound: bi frame skipped/invalid: {e:?}");
        },
    }
}

/// 前缀已读字节的 reader：先吐 `initial`，再透传内层流。
struct InitialedReader<R> {
    initial: std::io::Cursor<Vec<u8>>,
    inner: R,
}

impl<R> InitialedReader<R> {
    fn new(initial: Vec<u8>, inner: R) -> Self {
        Self { initial: std::io::Cursor::new(initial), inner }
    }
}

impl<R: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for InitialedReader<R> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if !self.initial.get_ref().is_empty()
            && self.initial.position() < self.initial.get_ref().len() as u64
        {
            let unfilled = buf.initialize_unfilled();
            let n = std::io::Read::read(&mut self.initial, unfilled)
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            buf.advance(n);
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

/// TUIC Address → xray Destination（TCP）。支持 Domain（dispatcher 解析 DNS）。
fn tuic_addr_to_destination(
    addr: &crate::protocol::Address,
) -> Option<xray_common::net::destination::Destination> {
    use xray_common::net::{
        address::Address as XAddress, destination::Destination, network::Network, port::Port,
    };
    let (addr, port) = match addr {
        crate::protocol::Address::Domain(d, p) => (XAddress::Domain(d.clone()), *p),
        crate::protocol::Address::Ipv4(ip, p) => (XAddress::IPv4(*ip), *p),
        crate::protocol::Address::Ipv6(ip, p) => (XAddress::IPv6(*ip), *p),
        crate::protocol::Address::None => return None,
    };
    Some(Destination::new(addr, Port::new(port), Network::TCP))
}

#[cfg(test)]
mod cc_tests {
    use uuid::Uuid;

    use super::*;

    fn make_handler(cc: Option<CongestionControl>, brutal_up_bps: u64) -> TuicInboundHandler {
        TuicInboundHandler::new(
            "cc-test",
            TuicInboundConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                server_name: "localhost".to_string(),
                uuid: Uuid::new_v4(),
                password: "cc-test".to_string(),
                cert_der: None,
                key_der: None,
                congestion_control: cc,
                brutal_up_bps,
                sockopt: Default::default(),
            },
        )
        .unwrap()
    }

    /// 票 7ykg 契约：服务端预装走共享槽——Hysteria* 算法 slot.has_active()
    /// （预装即最终算法，TUIC 无 auth 后热切换事件）；quinn 内建三臂返回 None。
    /// apply 层契约与 outbound 侧同源（同一 pub(crate) 函数）。
    #[test]
    fn inbound_congestion_preload_contract() {
        use crate::client::apply_congestion_to_transport;

        let mut t = quinn::TransportConfig::default();
        let slot = apply_congestion_to_transport(&mut t, CongestionControl::HysteriaBbr, 0)
            .expect("server-side hysteria_bbr must install the swappable slot");
        assert!(slot.has_active(), "BBR must be preloaded before accept");

        let mut t = quinn::TransportConfig::default();
        let slot =
            apply_congestion_to_transport(&mut t, CongestionControl::HysteriaBrutal, 10_000_000)
                .expect("server-side hysteria_brutal must install the swappable slot");
        assert!(slot.has_active(), "Brutal must be preloaded before accept");

        let mut t = quinn::TransportConfig::default();
        assert!(
            apply_congestion_to_transport(&mut t, CongestionControl::Bbr, 0).is_none(),
            "quinn builtin arms must not install the swappable slot"
        );
    }

    /// 票 7ykg 契约：未配置（None）= 零行为变化——不预装 factory，
    /// quinn 默认 CUBIC（官方 tuic-server 缺省），build_server_config 照常构建。
    #[test]
    fn build_server_config_without_cc_unchanged() {
        assert!(make_handler(None, 0).build_server_config().is_ok());
    }

    /// 带 CC 配置的 build_server_config 照常构建（e2e 真建链见 server.rs）。
    #[test]
    fn build_server_config_with_cc_builds() {
        assert!(
            make_handler(Some(CongestionControl::HysteriaBbr), 0).build_server_config().is_ok()
        );
        assert!(
            make_handler(Some(CongestionControl::HysteriaBrutal), 10_000_000)
                .build_server_config()
                .is_ok()
        );
    }
}
