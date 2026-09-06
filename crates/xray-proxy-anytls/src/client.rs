//! AnyTLS 客户端 outbound 实现。
//!
//! 设计要点：
//! - `AnytlsClient` 持有 long-lived `anytls::Client`（复用 session 池）
//! - `dial()` 内部 `create_stream` → 协议首帧写 SOCKS5 目标 → spawn pump 桥接 `tokio::io::duplex`
//! - `AnytlsConn` 包装 duplex client 端，天然 `impl AsyncRead + AsyncWrite + Unpin`
//!
//! 选用 `tokio::io::duplex` 桥接而非手动 `impl AsyncRead`：`anytls::Session` 只暴露
//! `async fn read/write(&self, ...)`（非 `AsyncRead` trait），在 `poll_read` 里直接 poll
//! 它的 future 会遇到 buf 生命周期问题（future 借用 buf 无法存到 self）。`duplex + pump`
//! 一次性桥接，代码最简。
//!
//! 协议参考：[anytls-go protocol.md](https://github.com/anytls/anytls-go)。

use std::sync::Arc;
use std::time::Duration;

use anytls::core::{Command, Frame};
use anytls::proxy::session::{Client as AnytlsClientInner, DEFAULT_SID};
use anytls::runtime::DefaultPaddingFactory;
use anytls::{AsyncReadWrite, DialOutFunc};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio_rustls::TlsConnector;

use crate::error::Result;
use crate::socks::SocksAddr;

/// anytls duplex 缓冲（64 KiB）。
const DUPLEX_BUF_SIZE: usize = 64 * 1024;

/// AnyTLS 客户端配置。
#[derive(Clone)]
pub struct ClientConfig {
    /// 服务端地址（`host:port`）。
    pub server_addr: String,
    /// TLS SNI（伪装域名）。
    pub sni: String,
    /// 协议认证密码（`anytls://<password>@host:port`）。
    pub password: String,
    /// TLS 客户端配置（验证服务端证书）。
    pub tls_config: Arc<rustls::ClientConfig>,
    /// 空闲会话检查间隔。
    pub idle_check_interval: Duration,
    /// 空闲会话超时。
    pub idle_timeout: Duration,
    /// 最少保留空闲会话数（预热）。
    pub min_idle_sessions: usize,
}

impl ClientConfig {
    /// 用最少参数构造（其它字段 anytls 推荐默认值）。
    #[must_use]
    pub fn new(
        server_addr: impl Into<String>,
        sni: impl Into<String>,
        password: impl Into<String>,
        tls_config: Arc<rustls::ClientConfig>,
    ) -> Self {
        Self {
            server_addr: server_addr.into(),
            sni: sni.into(),
            password: password.into(),
            tls_config,
            idle_check_interval: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(60),
            min_idle_sessions: 0,
        }
    }
}

/// AnyTLS 客户端，复用 TLS 会话池。
pub struct AnytlsClient {
    inner: AnytlsClientInner,
}

impl AnytlsClient {
    /// 创建客户端。`tls_config` 决定 TLS 验证策略。
    #[must_use]
    pub fn new(config: ClientConfig) -> Self {
        let server_addr = config.server_addr.clone();
        let sni = config.sni.clone();
        let password_sha256: [u8; 32] = Sha256::digest(config.password.as_bytes()).into();
        let tls_config = config.tls_config.clone();
        let padding = DefaultPaddingFactory::load();

        // dial_out：会话池 miss 时被调用，建立到 server 的 TLS 连接。
        // 协议要求（protocol.md Authentication）：TLS 握手完成后必须立即发送认证帧
        // `sha256(password) || padding0_len(BE u16) || padding0`，不发则 server 拒识/挂起。
        let dial_padding = padding.clone();
        let dial_out: DialOutFunc = Box::new(move || {
            let server_addr = server_addr.clone();
            let sni = sni.clone();
            let tls_config = tls_config.clone();
            let padding = dial_padding.clone();
            Box::pin(async move {
                let tcp = tokio::net::TcpStream::connect(&server_addr).await?;
                let connector = TlsConnector::from(tls_config);
                let server_name =
                    rustls::pki_types::ServerName::try_from(sni.clone())
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
                let mut tls = connector.connect(server_name, tcp).await?;
                let padding_len = {
                    let factory = padding.read().await;
                    factory
                        .generate_record_payload_sizes(0)
                        .first()
                        .copied()
                        .unwrap_or(0) as u16
                };
                let auth_frame = build_auth_frame(&password_sha256, padding_len);
                tls.write_all(&auth_frame).await?;
                Ok(Box::new(tls) as Box<dyn AsyncReadWrite>)
            })
        });

        let inner = AnytlsClientInner::new(
            dial_out,
            padding,
            config.idle_check_interval,
            config.idle_timeout,
            config.min_idle_sessions,
        );
        Self { inner }
    }

    /// 拨号到目标地址。返回的 `AnytlsConn` 实现 `AsyncRead + AsyncWrite + Unpin`。
    ///
    /// 流程：create_stream → 写 SOCKS5 目标 → spawn pump → 返回 duplex 包装。
    pub async fn dial(&self, target: &SocksAddr) -> Result<AnytlsConn> {
        let stream = self.inner.create_stream().await?;
        // 补发 cmdSYN：anytls-rs 0.3.x 单流模式不再自动发 SYN，但 sing-box/anytls-go
        // server 为多路复用语义——须收到 cmdSYN(sid=1) 才打开流，否则 Psh 被静默忽略。
        // 帧序 Settings → SYN → PSH(socks target)，对齐 protocol.md packet 1 定义。
        stream
            .write_frame(Frame::new(Command::Syn, DEFAULT_SID))
            .await?;
        // 协议要求：客户端在 stream 首帧写 SOCKS5 格式目标地址
        let socks_bytes = target.encode()?;
        stream.write(&socks_bytes).await?;

        let (client_io, server_io) = tokio::io::duplex(DUPLEX_BUF_SIZE);
        let pump = tokio::spawn(pump_stream(stream, server_io));

        Ok(AnytlsConn {
            inner: client_io,
            _pump: pump,
        })
    }

    /// 关闭客户端，回收所有 session 池资源。
    pub async fn close(&self) -> Result<()> {
        self.inner.close().await?;
        Ok(())
    }
}

/// AnyTLS 协议层连接，包装 `tokio::io::DuplexStream`。
///
/// 天然 `impl AsyncRead + AsyncWrite + Unpin`。`_pump` 字段确保桥接 task 生命周期与
/// 连接一致——`AnytlsConn` drop 时 pump task 被 abort（`JoinHandle::drop` 自动 abort）。
pub struct AnytlsConn {
    inner: DuplexStream,
    _pump: tokio::task::JoinHandle<()>,
}

impl AsyncRead for AnytlsConn {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for AnytlsConn {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// 双向桥接 anytls `Session` 与 `tokio::io::duplex` 的 server 端。
///
/// 任何一端 EOF 或出错都终止。
async fn pump_stream(
    session: Arc<anytls::proxy::session::Session>,
    server_io: DuplexStream,
) {
    let (mut rd, mut wr) = tokio::io::split(server_io);
    let session_clone = session.clone();
    let down = async move {
        let mut buf = vec![0u8; 8 * 1024];
        loop {
            match session_clone.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = wr.write_all(&buf[..n]).await {
                        tracing::debug!("pump session→duplex write error: {e}");
                        break;
                    }
                }
                Err(e) => {
                    tracing::debug!("pump session→duplex read error: {e}");
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
                    if let Err(e) = session.write(&buf[..n]).await {
                        tracing::debug!("pump duplex→session write error: {e}");
                        break;
                    }
                }
                Err(e) => {
                    tracing::debug!("pump duplex→session read error: {e}");
                    break;
                }
            }
        }
        let _ = session.terminate().await;
    };
    tokio::join!(down, up);
}

/// 构造 AnyTLS 认证帧（protocol.md Authentication，开销 34 字节 + padding0）：
/// `sha256(password)`(32B) || padding0 长度（Big-Endian uint16）|| padding0（全零）。
fn build_auth_frame(password_sha256: &[u8; 32], padding_len: u16) -> Vec<u8> {
    let mut frame = Vec::with_capacity(34 + padding_len as usize);
    frame.extend_from_slice(password_sha256);
    frame.extend_from_slice(&padding_len.to_be_bytes());
    frame.resize(frame.len() + padding_len as usize, 0);
    frame
}

#[cfg(test)]
mod tests {
    use super::*;

    /// sha256(b"test-password") 预期值（sha256sum 实算锚定，防算法被误改）。
    const TEST_PASSWORD_SHA256_HEX: &str =
        "c638833f69bbfb3c267afa0a74434812436b8f08a81fd263c6be6871de4f1265";

    fn expected_sha256() -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, chunk) in TEST_PASSWORD_SHA256_HEX.as_bytes().chunks(2).enumerate() {
            out[i] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap();
        }
        out
    }

    #[test]
    fn auth_frame_layout_matches_protocol() {
        let sha: [u8; 32] = Sha256::digest(b"test-password").into();
        assert_eq!(sha, expected_sha256());

        // 默认 paddingScheme `0=30-30` → padding0 = 30B，总长 64B。
        let frame = build_auth_frame(&sha, 30);
        assert_eq!(frame.len(), 64);
        assert_eq!(&frame[..32], &sha);
        // padding0 长度 Big-Endian u16
        assert_eq!(&frame[32..34], &[0x00, 0x1e]);
        assert!(frame[34..].iter().all(|&b| b == 0));
    }

    #[test]
    fn auth_frame_zero_padding() {
        let sha = expected_sha256();
        let frame = build_auth_frame(&sha, 0);
        assert_eq!(frame.len(), 34);
        assert_eq!(&frame[..32], &sha);
        assert_eq!(&frame[32..34], &[0x00, 0x00]);
    }
}
