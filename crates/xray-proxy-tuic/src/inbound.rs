//! TUIC v5 入站处理器，对应 Go `proxy/tuic/server.go`。
//!
//! 生产版 inbound：quinn QUIC server → accept bi/uni stream → authenticate → TCP/UDP relay。
//! 复用 [`crate::server`] 中的协议解析与 relay 逻辑。

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use uuid::Uuid;

use xray_features::inbound::{InboundError, InboundHandler};

use crate::error::{Result, TuicError};
use crate::protocol::command::TOKEN_LEN;
use crate::protocol::Command;
use crate::server::{
    addr_to_socket_addr, read_command_from_stream, read_frame_from_recv, relay_to_tcp,
    relay_udp, BiFrame,
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
}

/// 自签证书产物。
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

/// TUIC 入站 Handler。
///
/// 持有配置 + quinn Endpoint，实现 [`InboundHandler`]。
/// `start` 时创建 quinn server 并 spawn accept loop。
pub struct TuicInboundHandler {
    tag: String,
    started: AtomicBool,
    config: TuicInboundConfig,
    /// listener + accept 任务句柄，close 时 abort。
    slot: Mutex<Option<InboundSlot>>,
}

struct InboundSlot {
    endpoint: Arc<quinn::Endpoint>,
    _accept_task: JoinHandle<()>,
}

impl TuicInboundHandler {
    /// 构造入站 Handler。
    ///
    /// # 参数
    /// - `tag`：handler 标签
    /// - `config`：TUIC 入站配置
    pub fn new(tag: impl Into<String>, config: TuicInboundConfig) -> Result<Self> {
        Ok(Self {
            tag: tag.into(),
            started: AtomicBool::new(false),
            config,
            slot: Mutex::new(None),
        })
    }

    /// 构建 Quinn server 配置（TLS + transport）。
    fn build_server_config(&self) -> Result<quinn::ServerConfig> {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let (cert_der, key_der) = if let (Some(c), Some(k)) =
            (&self.config.cert_der, &self.config.key_der)
        {
            (c.clone(), k.clone())
        } else {
            let tls = gen_self_signed(&self.config.server_name).map_err(|e| {
                TuicError::Io(std::io::Error::other(format!("rcgen self-signed failed: {e}")))
            })?;
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
            .map_err(|e| TuicError::Io(std::io::Error::other(format!("quinn rustls convert: {e}"))))?;

        let mut transport = quinn::TransportConfig::default();
        transport.datagram_receive_buffer_size(Some(8 * 1024));
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

        let server_cfg = self.build_server_config().map_err(|e| {
            InboundError::ListenError(format!("tuic server config: {e}"))
        })?;

        let endpoint = Arc::new(
            quinn::Endpoint::server(server_cfg, self.config.listen).map_err(|e| {
                InboundError::ListenError(format!("tuic bind {}: {e}", self.config.listen))
            })?
        );

        let local_addr = endpoint.local_addr().map_err(|e| {
            InboundError::ListenError(format!("tuic local_addr: {e}"))
        })?;

        tracing::info!(
            tag = %self.tag,
            addr = %local_addr,
            "tuic inbound listening"
        );

        let uuid = self.config.uuid;
        let password = self.config.password.clone();
        let tag = self.tag.clone();
        let endpoint_for_accept = Arc::clone(&endpoint);

        let accept_task = tokio::spawn(async move {
            loop {
                let incoming = endpoint_for_accept.accept().await;
                let Some(incoming) = incoming else {
                    break;
                };
                let pwd = password.clone();
                let t = tag.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(incoming, uuid, &pwd).await {
                        tracing::debug!(tag = %t, error = ?e, "tuic inbound connection error");
                    }
                });
            }
        });

        let mut slot = self.slot.lock().await;
        *slot = Some(InboundSlot {
            endpoint,
            _accept_task: accept_task,
        });
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
        self.config.listen.port()
    }
}

/// 处理单个 TUIC QUIC 连接：authenticate → accept_bi loop。
async fn handle_connection(
    incoming: quinn::Incoming,
    expected_uuid: Uuid,
    password: &str,
) -> Result<()> {
    let conn = incoming.await?;

    // 生成 expected_token（TLS keying Material Exporter）
    let mut expected_token = [0u8; TOKEN_LEN];
    let uuid_str = expected_uuid.to_string();
    conn.export_keying_material(&mut expected_token, uuid_str.as_bytes(), password.as_bytes())
        .map_err(|_| TuicError::KeyingMaterialExport)?;

    // accept_uni 读 Authenticate
    let mut uni = conn.accept_uni().await?;
    let cmd = read_command_from_stream(&mut uni, 64).await?;
    match cmd {
        Command::Authenticate {
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

    // accept_bi loop
    loop {
        let (send_bi, recv_bi) = match conn.accept_bi().await {
            Ok(p) => p,
            Err(quinn::ConnectionError::ApplicationClosed(_)) => break,
            Err(e) => return Err(e.into()),
        };

        match read_frame_from_recv(recv_bi, 256).await {
            Ok((frame, recv_bi, initial_bytes)) => match frame {
                BiFrame::Command(Command::Connect(addr)) => {
                    let Some(target) = addr_to_socket_addr(&addr) else {
                        tracing::warn!("tuic inbound: addr not ip literal: {addr:?}");
                        continue;
                    };
                    tokio::spawn(async move {
                        if let Err(e) =
                            relay_to_tcp(target, send_bi, recv_bi, initial_bytes).await
                        {
                            tracing::debug!("tuic relay {target}: {e:?}");
                        }
                    });
                }
                BiFrame::Command(Command::Heartbeat) => {}
                BiFrame::Command(_) => {}
                BiFrame::Packet(pkt) => {
                    tokio::spawn(async move {
                        if let Err(e) = relay_udp(pkt, send_bi, recv_bi, initial_bytes).await {
                            tracing::debug!("tuic udp relay: {e:?}");
                        }
                    });
                }
            },
            Err(e) => {
                tracing::warn!("tuic inbound: failed to read frame: {e:?}");
            }
        }
    }

    Ok(())
}

