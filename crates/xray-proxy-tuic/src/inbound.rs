//! TUIC v5 入站处理器，对应 Go `proxy/tuic/server.go`。
//!
//! 生产版 inbound：quinn QUIC server → accept bi/uni stream → authenticate → TCP/UDP relay。
//! 复用 [`crate::server`] 中的协议解析与 relay 逻辑。

use std::{
    net::SocketAddr,
    sync::{
        Arc, LazyLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use skeleton_infra::fx::{FxScope, Spawned};
use tokio::sync::Mutex;
use uuid::Uuid;
use xray_features::inbound::{InboundError, InboundHandler};
use xray_frame::LogFacade;
use xray_transport::handshake_gate::HandshakeGate;

use crate::{
    client::{CongestionControl, apply_congestion_to_transport, apply_default_windows},
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

/// 入站诊断门面（nn8os 2b 同型处置：tracing 宏 → LogFacade——本项目工具链上
/// `disallowed_macros` 对 proc-macro 不认任何 allow（fn/stmt/文件顶三形态实测
/// 无效），迁移为唯一关红路径。域 = "tuic"，target `xray_frame::tuic` +
/// mask_secrets。只在 listen/close/连接错误/datagram·bi 帧解析错误分支发射
/// （连接级/错误分支，非逐包稳态）。
static INBOUND_LOG: LazyLock<LogFacade> = LazyLock::new(|| LogFacade::new("tuic", vec![]));

/// 认证读窗（rd8yj②）：QUIC 握手完成后，`accept_uni` 等 Authenticate 帧必须
/// 在此窗内完成；超窗即 `close(1, "auth timeout")` 放弃连接——慢速/不发数据的
/// 客户端不再能长期占用 per-conn 任务与连接状态（quinn idle 超时缺省 300s 才回收）。
///
/// 取 4s = 本仓应用层「首个协议交换窗」家族口径（`xray_transport::tls_handshake_gate::
/// TLS_HANDSHAKE_TIMEOUT` 4s、ws H14 `HandshakeTimeout` 4s、httpupgrade 合并窗 4s）；
/// 真实客户端连上即发 Authenticate（loopback 常耗 <100ms），4s 为 >40× 余量。
const AUTH_WINDOW: Duration = Duration::from_secs(4);

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
    /// listener + accept 任务句柄，close 时 abort。任务归组件自持 [`FxScope`]
    /// 托管（B6，bd t975；scope 不接 close，闸关不可达，组件释放兜底 abort）。
    slot: Mutex<Option<InboundSlot>>,
    /// 组件内自持托管 scope（B6，app 家族同款；accept/per-conn/per-flow 任务
    /// 统一经此 spawn——生命周期记账 + 停机兜底 abort）。
    fx: Arc<FxScope>,
    /// 自签证书 DER（start 时生成，供 client trust store）。
    cert_der: parking_lot::Mutex<Option<Vec<u8>>>,
    /// 实际监听端口（start 后有效；listen 配置 0 时由 OS 分配）。
    local_port: std::sync::atomic::AtomicU16,
}

struct InboundSlot {
    endpoint: Arc<quinn::Endpoint>,
    _accept_task: Spawned<()>,
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
            fx: Arc::new(FxScope::new()),
            cert_der: parking_lot::Mutex::new(None),
            local_port: std::sync::atomic::AtomicU16::new(0),
        })
    }

    /// 自签证书 DER（start 后可用，client trust store 用）。
    pub fn cert_der(&self) -> Option<Vec<u8>> {
        self.cert_der.lock().clone()
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
                *self.cert_der.lock() = Some(tls.cert_der.clone());
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
        // bd wp9o：quinn 缺省 1.25MB 流收窗高 BDP 钉——显式 16MB 流窗 + 32MB 连接窗
        // （与 outbound client.rs 同款，wz2b W4 窗钉族收口）。
        apply_default_windows(&mut transport);
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
        INBOUND_LOG.info(format!("tuic inbound listening tag={} addr={}", self.tag, local_addr));

        let uuid = self.config.uuid;
        let password = self.config.password.clone();
        let tag = self.tag.clone();
        let endpoint_for_accept = Arc::clone(&endpoint);

        let dispatch = self.dispatch.clone();
        // B6（bd t975）：accept/per-conn 任务经组件自持 scope 托管（生命周期记账 +
        // 组件释放兜底 abort；scope 不接 close，闸关不可达）。
        // 接收者与被捕获绑定分离（外层接收者 = self.fx，内层接收者 = 外层捕获的
        // fx 本体，future 各捕获独立 clone），规避 E0505。
        let fx = Arc::clone(&self.fx);
        let accept_loop = async move {
            // rd8yj①：每监听握手并发闸——满即 fail-fast 丢弃该 Incoming（不排队，
            // HandshakeGate 家族纪律，ws/httpupgrade 同款；预算依据见常量注释）。
            let gate =
                HandshakeGate::new(xray_transport::handshake_gate::effective_inflight_limit());
            loop {
                let incoming = endpoint_for_accept.accept().await;
                let Some(incoming) = incoming else {
                    break;
                };
                // 许可决策在 spawn 之前同步完成：超额连接不进任务。
                let Some(permit) = gate.try_admit() else {
                    gate.record_reject("tuic");
                    drop(incoming);
                    continue;
                };
                let pwd = password.clone();
                let t = tag.clone();
                let dispatch = dispatch.clone();
                let fx_task = Arc::clone(&fx);
                // 每连接 spawn 前先收割（bd 86i4h 阶段2）：条目不随累计连接数增长。
                xray_frame::compat::spawn_reaping(&fx, &INBOUND_LOG, "tuic conn", async move {
                    // rd8yj①：QUIC 握手应用层窗——quinn idle 超时（缺省 300s）只管
                    // 空闲期，攻击者持续发包可无限续命，故对 `incoming.await` 显式
                    // 罩窗；取值与 QUIC transport 同源（Go QUIC 族 8s 口径）。
                    let conn = match tokio::time::timeout(
                        xray_transport_quic::transport::QUIC_HANDSHAKE_TIMEOUT,
                        incoming,
                    )
                    .await
                    {
                        Ok(Ok(c)) => c,
                        // 握手失败/超窗：Incoming drop 即静默丢弃，许可随 task 结束归还。
                        Ok(Err(_)) | Err(_) => return,
                    };
                    drop(permit); // 握手完成即让位
                    if let Err(e) = handle_connection(conn, uuid, &pwd, dispatch, &fx_task).await {
                        INBOUND_LOG
                            .debug(format!("tuic inbound connection error tag={t} error={e:?}"));
                    }
                })
                .expect("internal FxScope is never closed");
            }
        };
        let accept_task =
            self.fx.spawn_tracked(accept_loop).expect("internal FxScope is never closed");

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
            INBOUND_LOG.info(format!("tuic inbound closed tag={}", self.tag));
        }
        Ok(())
    }

    fn port(&self) -> u16 {
        let p = self.local_port.load(std::sync::atomic::Ordering::SeqCst);
        if p != 0 { p } else { self.config.listen.port() }
    }
}

async fn handle_connection(
    conn: quinn::Connection,
    expected_uuid: Uuid,
    password: &str,
    dispatch: Option<Arc<dyn xray_app_dispatcher::DispatchHandler>>,
    fx: &Arc<FxScope>,
) -> Result<()> {
    // 生成 expected_token (对齐官方 tuic v5: label=UUID 16字节)
    let mut expected_token = [0u8; TOKEN_LEN];
    conn.export_keying_material(&mut expected_token, expected_uuid.as_bytes(), password.as_bytes())
        .map_err(|_| TuicError::KeyingMaterialExport)?;

    // rd8yj②：认证读窗——accept_uni + read_authenticate 全程罩窗（读仍为流式
    // 分段，票 ieik 不变）。慢速/不发数据的客户端超窗即被 close 放弃，不再占
    // task + 连接状态等 quinn idle（300s）回收（行为断言见 tests::auth_window_tests）。
    let cmd = match tokio::time::timeout(AUTH_WINDOW, async {
        let mut uni = conn.accept_uni().await?;
        read_authenticate(&mut uni).await
    })
    .await
    {
        Ok(cmd) => cmd?,
        Err(_) => {
            conn.close(1u32.into(), b"auth timeout");
            return Err(TuicError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "auth window timeout",
            )));
        },
    };
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
    let mut udp_table = UdpAssocTable::new(dispatch.clone(), Arc::clone(fx));
    loop {
        tokio::select! {
            bi = conn.accept_bi() => {
                let (send_bi, recv_bi) = match bi {
                    Ok(p) => p,
                    Err(quinn::ConnectionError::ApplicationClosed(_)) => break,
                    Err(e) => return Err(e.into()),
                };
                handle_bi_frame(send_bi, recv_bi, dispatch.clone(), fx).await;
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
                        INBOUND_LOG.debug(format!("tuic inbound: datagram read: {e:?}"));
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
    let log = &*INBOUND_LOG;
    let mut cursor = &dg[..];
    match crate::protocol::parse_header(&mut cursor) {
        Ok(t) if t == type_code::PACKET => match Packet::read_payload(&mut cursor) {
            Ok(pkt) => table.handle_packet(pkt, ReplySink::Dgram(conn.clone())),
            Err(e) => log.debug(format!("tuic inbound: datagram packet parse: {e:?}")),
        },
        Ok(_) => {}, // Heartbeat 可走 datagram（spec），保活语义无需处理
        Err(e) => log.debug(format!("tuic inbound: datagram header: {e:?}")),
    }
}

/// 处理一条 bi stream：Connect → dispatcher 生产路径 / mock 直连。
///
/// spec：bi stream 只承载 Connect（Packet 走 uni/datagram，票 d1zr）。
async fn handle_bi_frame(
    send_bi: quinn::SendStream,
    recv_bi: quinn::RecvStream,
    dispatch: Option<Arc<dyn xray_app_dispatcher::DispatchHandler>>,
    fx: &Arc<FxScope>,
) {
    // bd irtg9：arm body 内联 await，Connect 帧读必须有硬超时（否则半开 bi 流冻结
    // 整条 QUIC 连接的全部中继与 datagram）。
    let frame = match tokio::time::timeout(
        crate::server::FRAME_READ_TIMEOUT,
        read_frame_from_recv(recv_bi, 256),
    )
    .await
    {
        Ok(r) => r,
        Err(_) => {
            INBOUND_LOG.debug(format!(
                "tuic inbound: bi Connect frame read timeout ({:?}), dropping stream",
                crate::server::FRAME_READ_TIMEOUT
            ));
            return;
        },
    };
    match frame {
        Ok((Command::Connect(addr), recv_bi, initial_bytes)) => {
            if let Some(handler) = dispatch {
                // 生产路径：构造 Destination + Link → dispatcher/router 分发。
                // initial_bytes 前置回 Link reader（read 一次读出 Connect+payload 的场景）。
                if let Some(dest) = tuic_addr_to_destination(&addr) {
                    let link = xray_transport::link::Link::new(
                        xray_buf::io::new_reader(InitialedReader::new(initial_bytes, recv_bi)),
                        xray_buf::io::new_writer(send_bi),
                    );
                    // B6（bd t975）：per-flow dispatch 任务经组件 scope 托管。
                    // 每 flow spawn 前先收割（bd 86i4h 阶段2）：条目不随流数增长。
                    let fx_flow = Arc::clone(fx);
                    xray_frame::compat::spawn_reaping(
                        &fx_flow,
                        &INBOUND_LOG,
                        "tuic flow",
                        async move {
                            let _ = handler.dispatch(&dest, link).await;
                        },
                    )
                    .expect("internal FxScope is never closed");
                } else {
                    INBOUND_LOG.warn(format!("tuic inbound: unsupported addr: {addr:?}"));
                }
            } else {
                // mock/直连路径（loopback 测试用）
                let Some(target) = addr_to_socket_addr(&addr) else {
                    INBOUND_LOG.warn(format!("tuic inbound: addr not ip literal: {addr:?}"));
                    return;
                };
                let fx_relay = Arc::clone(fx);
                // 每 relay spawn 前先收割（bd 86i4h 阶段2）：条目不随流数增长。
                xray_frame::compat::spawn_reaping(
                    &fx_relay,
                    &INBOUND_LOG,
                    "tuic relay",
                    async move {
                        if let Err(e) = relay_to_tcp(target, send_bi, recv_bi, initial_bytes).await
                        {
                            INBOUND_LOG.debug(format!("tuic relay {target}: {e:?}"));
                        }
                    },
                )
                .expect("internal FxScope is never closed");
            }
        },
        Ok((_, _, _)) => {},
        Err(e) => {
            // bi 收到 Packet（TYPE 0x02）等非 Connect 帧落此路径，忽略（spec，票 d1zr）
            INBOUND_LOG.debug(format!("tuic inbound: bi frame skipped/invalid: {e:?}"));
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

    /// 票 7ykg 契约：服务端预装走共享槽——Hysteria* 算法 slot 有算法
    /// （hysteria_bbr = quinn 内建 BBR 走 fallback 通道，bd hfb94；hysteria_brutal =
    /// hysteria active 算法）；quinn 内建三臂返回 None。
    /// apply 层契约与 outbound 侧同源（同一 pub(crate) 函数）。
    #[test]
    fn inbound_congestion_preload_contract() {
        use crate::client::apply_congestion_to_transport;

        let mut t = quinn::TransportConfig::default();
        let slot = apply_congestion_to_transport(&mut t, CongestionControl::HysteriaBbr, 0)
            .expect("server-side hysteria_bbr must install the swappable slot");
        assert!(slot.is_bbr(), "BBR must be preloaded before accept");

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

#[cfg(test)]
mod auth_window_tests {
    use std::time::Instant;

    use super::*;

    /// rd8yj② 行为断言：握手完成但**从不发 Authenticate** 的连接，必须在认证读窗
    /// 超时后被真实关闭——对端以 `ApplicationClosed("auth timeout")` 可观测，
    /// per-conn 任务随之结束（不是只打日志）。客户端 idle 超时抬高到 60s ⇒ 唯一
    /// 关连方 = 服务器认证读窗。窗改大（如 60s）⇒ 本测试 6s 观测截止必红。
    // 测试耗时断言用 std 即时读数（墙钟差），非生产时钟取用（nn8os 2b 同款豁免）。
    #[allow(clippy::disallowed_methods, reason = "测试耗时断言配套，非生产时钟取用")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn auth_window_closes_connection_that_never_authenticates() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let handler = TuicInboundHandler::new(
            "auth-window-test",
            TuicInboundConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                server_name: "localhost".to_string(),
                uuid: Uuid::new_v4(),
                password: "auth-window".to_string(),
                cert_der: None,
                key_der: None,
                congestion_control: None,
                brutal_up_bps: 0,
                sockopt: Default::default(),
            },
        )
        .unwrap();
        handler.start().await.expect("start");
        let addr = std::net::SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), handler.port());
        let cert_der = handler.cert_der().expect("cert after start");

        // 真实 quinn 客户端：信任自签证书、ALPN=tuic，握手完成后静默。
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der.into()).expect("add cert");
        let mut client_tls =
            rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
        client_tls.alpn_protocols = vec![b"tuic".to_vec()];
        let mut client_cfg = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_tls).unwrap(),
        ));
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(quinn::IdleTimeout::from(quinn::VarInt::from_u32(60_000))));
        client_cfg.transport_config(Arc::new(transport));
        let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        ep.set_default_client_config(client_cfg);

        let started = Instant::now();
        let conn = ep.connect(addr, "localhost").unwrap().await.expect("handshake");

        // 服务器认证读窗超时 ⇒ close(1, "auth timeout") 必须以 ApplicationClosed
        // 形态抵达客户端；观测截止固定 6s（窗 4s + 2s 余量）。
        let err = tokio::time::timeout(Duration::from_secs(6), conn.closed())
            .await
            .expect("auth window must fire within 6s");
        let elapsed = started.elapsed();
        match err {
            quinn::ConnectionError::ApplicationClosed(closed) => {
                assert_eq!(closed.reason.as_ref(), b"auth timeout", "关闭原因必须是认证读窗超时");
            },
            other => panic!("期望 ApplicationClosed(\"auth timeout\")，实际 {other:?}"),
        }
        assert!(
            elapsed >= AUTH_WINDOW - Duration::from_millis(300),
            "连接在认证读窗之前就被关（{elapsed:?}）——窗失效"
        );

        handler.close().await.ok();
        ep.close(0u32.into(), b"test done");
    }
}
