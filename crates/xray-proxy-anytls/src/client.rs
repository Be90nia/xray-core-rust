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

use anytls::proxy::session::Client as AnytlsClientInner;
use anytls::runtime::DefaultPaddingFactory;
use anytls::{AsyncReadWrite, DialOutFunc};
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
        tls_config: Arc<rustls::ClientConfig>,
    ) -> Self {
        Self {
            server_addr: server_addr.into(),
            sni: sni.into(),
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
        let tls_config = config.tls_config.clone();

        // dial_out：会话池 miss 时被调用，建立到 server 的 TLS 连接
        let dial_out: DialOutFunc = Box::new(move || {
            let server_addr = server_addr.clone();
            let sni = sni.clone();
            let tls_config = tls_config.clone();
            Box::pin(async move {
                let tcp = tokio::net::TcpStream::connect(&server_addr).await?;
                let connector = TlsConnector::from(tls_config);
                let server_name =
                    rustls::pki_types::ServerName::try_from(sni.clone())
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
                let tls = connector.connect(server_name, tcp).await?;
                Ok(Box::new(tls) as Box<dyn AsyncReadWrite>)
            })
        });

        let padding = DefaultPaddingFactory::load();
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
        // 协议要求：客户端在 stream 首帧写 SOCKS5 格式目标地址
        let socks_bytes = target.encode();
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
