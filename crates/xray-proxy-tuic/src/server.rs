//! TUIC v5 mock server（切片1：用于 loopback 测试，不是生产 server）。
//!
//! Mock 行为：
//! 1. 自签 TLS 证书（rcgen）
//! 2. quinn Endpoint::server 监听
//! 3. accept_uni → Authenticate 校验 token（export_keying_material）
//! 4. accept_bi → Connect → tokio TCP dial 目标 → 双向 copy（true relay）

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

use crate::error::{Result, TuicError};
use crate::protocol::command::TOKEN_LEN;

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
/// 切片1 仅支持 TCP relay。UDP relay 留切片2。
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
        let _ = rustls::crypto::ring::default_provider().install_default();

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

        let endpoint = quinn::Endpoint::server(server_cfg, listen)?;

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

    /// 运行 accept loop（TCP relay）。
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

    // 生成 expected_token
    let mut expected_token = [0u8; TOKEN_LEN];
    let uuid_str = expected_uuid.to_string();
    conn.export_keying_material(&mut expected_token, uuid_str.as_bytes(), password.as_bytes())
        .map_err(|_| TuicError::KeyingMaterialExport)?;

    // accept_uni 读 Authenticate
    let mut uni = conn.accept_uni().await?;
    let cmd = read_command_from_stream(&mut uni, 64).await?;
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

    // accept_bi loop
    loop {
        let (send_bi, recv_bi) = match conn.accept_bi().await {
            Ok(p) => p,
            Err(quinn::ConnectionError::ApplicationClosed(_)) => break,
            Err(e) => return Err(e.into()),
        };

        // 读 Connect header（仅消费必要字节，剩余字节留给 relay）
        match read_command_from_recv(recv_bi, 256).await {
            Ok((cmd, recv_bi, initial_bytes)) => match cmd {
                crate::protocol::Command::Connect(addr) => {
                    let Some(target) = addr_to_socket_addr(&addr) else {
                        tracing::warn!("tuic server: addr not ip literal: {addr:?}");
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
                crate::protocol::Command::Heartbeat => {}
                _ => {} // Packet/Dissociate 切片2
            },
            Err(e) => {
                tracing::warn!("tuic server: failed to read connect: {e:?}");
            }
        }
    }

    Ok(())
}

/// 从通用 AsyncRead 流读出 Command。
pub(crate) async fn read_command_from_stream<S>(
    stream: &mut S,
    max_len: usize,
) -> Result<crate::protocol::Command>
where
    S: AsyncReadExt + Unpin,
{
    let mut buf = vec![0u8; max_len];
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        return Err(TuicError::UnexpectedEof("command stream closed"));
    }
    let mut cursor = &buf[..n];
    let type_byte = crate::protocol::parse_header(&mut cursor)?;
    crate::protocol::Command::read_payload(type_byte, &mut cursor)
}

/// 从 quinn RecvStream 读出 Command，返回 (Command, 已消费的 RecvStream, header 之后的剩余字节)。
///
/// 剩余字节留给 relay，避免 quinn 一次 read 把 Connect header 和后续 payload 都读出。
async fn read_command_from_recv(
    mut stream: quinn::RecvStream,
    max_len: usize,
) -> Result<(crate::protocol::Command, quinn::RecvStream, Vec<u8>)> {
    let mut buf = vec![0u8; max_len];
    let n = stream.read(&mut buf).await?.ok_or_else(|| {
        TuicError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "stream closed before command",
        ))
    })?;
    let mut cursor = &buf[..n];
    let type_byte = crate::protocol::parse_header(&mut cursor)?;
    let cmd = crate::protocol::Command::read_payload(type_byte, &mut cursor)?;
    // header 之后的所有字节，留给后续 relay
    let remaining = cursor.to_vec();
    Ok((cmd, stream, remaining))
}

/// 真正的双向 relay：client ↔ (quinn bi) ↔ server ↔ (tcp) ↔ 目标。
///
/// `initial_bytes` 是客户端随 Connect header 一并发的 TCP payload 前缀。
async fn relay_to_tcp(
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

fn addr_to_socket_addr(addr: &crate::protocol::Address) -> Option<SocketAddr> {
    match addr {
        crate::protocol::Address::Ipv4(ip, port) => Some(SocketAddr::new(IpAddr::V4(*ip), *port)),
        crate::protocol::Address::Ipv6(ip, port) => Some(SocketAddr::new(IpAddr::V6(*ip), *port)),
        crate::protocol::Address::Domain(_, _) | crate::protocol::Address::None => None,
    }
}
