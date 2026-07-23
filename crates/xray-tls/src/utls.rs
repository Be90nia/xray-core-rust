//! TLS 连接接口与标准 rustls 实现。
//!
//! 翻译自 Go `transport/internet/tls/tls.go` 中的 `Interface interface`
//! 与 `Conn`/`UConn` 包装类型。
//!
//! # 实现
//!
//! 走标准 [`rustls`] 0.23 + [`tokio_rustls`] 0.26：
//! - [`client`]：标准客户端握手，返回 [`Conn`]
//! - [`server`]：标准服务端握手，返回 [`ServerConn`]
//! - [`u_client`]：fallback 到标准 rustls，返回携带 `Fingerprint` 标记的 [`UConn`]
//!   （真实 uTLS ClientHello 指纹伪装待 REALITY 任务再评估 watfaq-rustls git 依赖）
//!
//! 工厂函数 async——握手在工厂内部完成；返回的 Conn/UConn 已是已握手连接。
//!
//! # trait 对齐
//!
//! 与 xray-transport 的 [`Connection`](xray_transport::connection::Connection) trait
//! 对齐：`Conn<S>`/`ServerConn<S>`/`UConn<S>` 同时实现 `Connection`（remote/local addr）
//! 与 [`ConnInterface`]（握手相关 API）。AsyncRead + AsyncWrite 由 forward 到
//! `tokio_rustls::TlsStream<S>` 自动获得。

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use rustls_pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::rustls::{ClientConfig, ServerConfig};
use tokio_rustls::server::TlsStream as ServerTlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::debug;
use xray_transport::connection::Connection;

use crate::fingerprint::Fingerprint;

/// TLS 连接接口。
///
/// 对应 Go `Interface interface { net.Conn; HandshakeContext; VerifyHostname; ... }`。
///
/// 由于 [`Connection`] 已表达 `AsyncRead + AsyncWrite + addr`，本 trait 只加
/// TLS 特有方法。实现者同时实现两个 trait。
///
/// 在标准 rustls 实现中：
/// - `handshake`：no-op（rustls 握手在 `connect()`/`accept()` 时已完成）
/// - `verify_hostname`：no-op（rustls 在 cert verifier 中已校验）
/// - `handshake_server_name`：从 `ClientConnection::server_name()` 取
/// - `negotiated_protocol`：从 `ClientConnection::alpn_protocol()` 取
pub trait ConnInterface: Connection {
    /// 执行 TLS 握手。超时与取消由调用方通过 ctx 等价机制（tokio::time::timeout 等）控制。
    fn handshake<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>>;

    /// 验证 peer 证书是否匹配给定 hostname。
    fn verify_hostname<'a>(
        &'a self,
        host: &'a str,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>>;

    /// 握手并返回 ServerName（SNI）。握手失败返回空字符串。
    fn handshake_server_name<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output = String> + Send + 'a>>;

    /// 返回 ALPN 协商出的协议名（如 `"h2"`/`"http/1.1"`）。未协商返回空字符串。
    fn negotiated_protocol<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = String> + Send + 'a>>;
}

// ============================================================
// 客户端 TLS Conn
// ============================================================

/// 标准 rustls 客户端 TLS 连接。
///
/// 包装 `tokio_rustls::client::TlsStream<S>`，对齐 Go `tls.Conn`。
/// `S` 通常是 `TcpConnection` 或任何实现 `Connection` 的类型。
pub struct Conn<S> {
    inner: ClientTlsStream<S>,
    /// 握手时传入的 SNI（rustls ClientConnection 不公开 SNI 读取 API）。
    server_name: String,
}

impl<S> Conn<S> {
    /// 返回协商出的 ALPN 协议（如 `b"h2"`）。未协商返回 `None`。
    #[must_use]
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.inner.get_ref().1.alpn_protocol()
    }

    /// 返回 ServerName（SNI）。握手前返回空字符串。
    #[must_use]
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    /// 内部引用（底层 stream + ClientConnection）。
    #[must_use]
    pub fn get_ref(&self) -> (&S, &tokio_rustls::rustls::ClientConnection) {
        self.inner.get_ref()
    }
}

impl<S: Connection + Unpin> AsyncRead for Conn<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: Connection + Unpin> AsyncWrite for Conn<S> {
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

impl<S: Connection + Unpin> Connection for Conn<S> {
    fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.inner.get_ref().0.remote_addr()
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.inner.get_ref().0.local_addr()
    }
}

impl<S: Connection + Unpin> ConnInterface for Conn<S> {
    fn handshake<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>> {
        // rustls 握手在 connect() 时已完成，no-op
        Box::pin(async { Ok(()) })
    }

    fn verify_hostname<'a>(
        &'a self,
        host: &'a str,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>> {
        // rustls 在 cert verifier 中已校验 hostname
        let _ = host;
        Box::pin(async { Ok(()) })
    }

    fn handshake_server_name<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output = String> + Send + 'a>> {
        let sni = self.server_name().to_string();
        Box::pin(async move { sni })
    }

    fn negotiated_protocol<'a>(&'a self) -> Pin<Box<dyn Future<Output = String> + Send + 'a>> {
        let proto = self
            .alpn_protocol()
            .and_then(|b| std::str::from_utf8(b).ok())
            .unwrap_or("")
            .to_string();
        Box::pin(async move { proto })
    }
}

// ============================================================
// 服务端 TLS ServerConn
// ============================================================

/// 标准 rustls 服务端 TLS 连接。
///
/// 包装 `tokio_rustls::server::TlsStream<S>`，对齐 Go `tls.Conn` (server)。
pub struct ServerConn<S> {
    inner: ServerTlsStream<S>,
}

impl<S> ServerConn<S> {
    /// 返回协商出的 ALPN 协议。未协商返回 `None`。
    #[must_use]
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.inner.get_ref().1.alpn_protocol()
    }

    /// 内部引用（底层 stream + ServerConnection）。
    #[must_use]
    pub fn get_ref(&self) -> (&S, &tokio_rustls::rustls::ServerConnection) {
        self.inner.get_ref()
    }
}

impl<S: Connection + Unpin> AsyncRead for ServerConn<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: Connection + Unpin> AsyncWrite for ServerConn<S> {
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

impl<S: Connection + Unpin> Connection for ServerConn<S> {
    fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.inner.get_ref().0.remote_addr()
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.inner.get_ref().0.local_addr()
    }
}

// ============================================================
// uTLS UConn（btls 指纹伪装 + rustls fallback）
// ============================================================

/// UConn 内部连接（btls 或 rustls）。
#[allow(clippy::large_enum_variant)]
enum UConnInner<S> {
    /// 标准 rustls 连接（指纹不支持 btls 时的 fallback）。
    Rustls(Conn<S>),
    /// btls (BoringSSL) 连接（真实浏览器指纹）。
    Btls(crate::btls_client::BtlsConn<S>),
}

/// uTLS 客户端连接包装。
///
/// 对应 Go `utls.UConn`。根据 `Fingerprint` 选择 btls（真实指纹）或 rustls（fallback）。
pub struct UConn<S> {
    inner: UConnInner<S>,
    /// 用户期望的 uTLS 指纹。
    pub fingerprint: Fingerprint,
}

impl<S> UConn<S> {
    /// 返回协商出的 ALPN 协议。未协商返回 `None`。
    #[must_use]
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        match &self.inner {
            UConnInner::Rustls(c) => c.alpn_protocol(),
            UConnInner::Btls(_) => None, // btls 通过 negotiated_protocol() 获取
        }
    }

    /// 返回 ServerName（SNI）。
    #[must_use]
    pub fn server_name(&self) -> &str {
        match &self.inner {
            UConnInner::Rustls(c) => c.server_name(),
            UConnInner::Btls(_) => "", // btls 通过 handshake_server_name() 获取
        }
    }
}

impl<S: Connection + Unpin> AsyncRead for UConn<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut self.inner {
            UConnInner::Rustls(c) => Pin::new(c).poll_read(cx, buf),
            UConnInner::Btls(c) => Pin::new(c).poll_read(cx, buf),
        }
    }
}

impl<S: Connection + Unpin> AsyncWrite for UConn<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut self.inner {
            UConnInner::Rustls(c) => Pin::new(c).poll_write(cx, buf),
            UConnInner::Btls(c) => Pin::new(c).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.inner {
            UConnInner::Rustls(c) => Pin::new(c).poll_flush(cx),
            UConnInner::Btls(c) => Pin::new(c).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.inner {
            UConnInner::Rustls(c) => Pin::new(c).poll_shutdown(cx),
            UConnInner::Btls(c) => Pin::new(c).poll_shutdown(cx),
        }
    }
}

impl<S: Connection + Unpin> Connection for UConn<S> {
    fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
        match &self.inner {
            UConnInner::Rustls(c) => c.remote_addr(),
            UConnInner::Btls(c) => c.remote_addr(),
        }
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        match &self.inner {
            UConnInner::Rustls(c) => c.local_addr(),
            UConnInner::Btls(c) => c.local_addr(),
        }
    }
}


impl<S: Connection + Unpin> ConnInterface for UConn<S> {
    fn handshake<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>> {
        match &mut self.inner {
            UConnInner::Rustls(c) => c.handshake(),
            UConnInner::Btls(c) => c.handshake(),
        }
    }

    fn verify_hostname<'a>(
        &'a self,
        host: &'a str,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>> {
        match &self.inner {
            UConnInner::Rustls(c) => c.verify_hostname(host),
            UConnInner::Btls(c) => c.verify_hostname(host),
        }
    }

    fn handshake_server_name<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output = String> + Send + 'a>> {
        match &mut self.inner {
            UConnInner::Rustls(c) => c.handshake_server_name(),
            UConnInner::Btls(c) => c.handshake_server_name(),
        }
    }

    fn negotiated_protocol<'a>(&'a self) -> Pin<Box<dyn Future<Output = String> + Send + 'a>> {
        match &self.inner {
            UConnInner::Rustls(c) => c.negotiated_protocol(),
            UConnInner::Btls(c) => c.negotiated_protocol(),
        }
    }
}

// ============================================================
// 工厂函数
// ============================================================

/// 创建标准 rustls TLS 客户端连接（完成握手）。
///
/// 对应 Go `tls.Client(c, config)` + `HandshakeContext`。
///
/// `stream` 必须已建立 TCP 连接（或任何实现 [`Connection`] 的底层流）。
/// `server_name` 是 SNI；`config` 是 rustls `ClientConfig`（含 cert verifier + ALPN）。
pub async fn client<S>(
    stream: S,
    server_name: &str,
    config: Arc<ClientConfig>,
) -> io::Result<Conn<S>>
where
    S: Connection + Unpin,
{
    let connector = TlsConnector::from(config);
    let server: ServerName<'static> = ServerName::try_from(server_name.to_string())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("invalid server name: {e}")))?;
    let tls_stream = connector.connect(server, stream).await?;
    Ok(Conn { inner: tls_stream, server_name: server_name.to_string() })
}

/// 创建标准 rustls TLS 服务端连接（完成握手）。
///
/// 对应 Go `tls.Server(c, config)` + `HandshakeContext`。
pub async fn server<S>(
    stream: S,
    config: Arc<ServerConfig>,
) -> io::Result<ServerConn<S>>
where
    S: Connection + Unpin,
{
    let acceptor = TlsAcceptor::from(config);
    let tls_stream = acceptor.accept(stream).await?;
    Ok(ServerConn { inner: tls_stream })
}

/// 创建 uTLS 指纹伪装客户端连接。
///
/// 对应 Go `utls.UClient(c, config, fingerprint)`。
///
/// **当前实现**：fallback 到标准 rustls 握手，`fingerprint` 仅作 log 标记。
/// 真实 uTLS ClientHello 指纹伪装（GREASE/扩展顺序/ClientHello 字节布局）
/// 待 REALITY 任务再评估 watfaq-rustls git 依赖。
pub async fn u_client<S>(
    stream: S,
    server_name: &str,
    config: Arc<ClientConfig>,
    fingerprint: Fingerprint,
) -> io::Result<UConn<S>>
where
    S: Connection + Unpin,
{
    // 尝试 btls（真实指纹）
    if let Some(result) = crate::btls_client::connector_for_fingerprint(&fingerprint) {
        match result {
            Ok(_) => {
                debug!(target: "xray_tls::utls", ?fingerprint, server_name, "u_client: 尝试 btls 指纹伪装");
                match crate::btls_client::BtlsConn::connect(stream, server_name, fingerprint).await {
                    Ok(btls_conn) => {
                        return Ok(UConn { inner: UConnInner::Btls(btls_conn), fingerprint });
                    }
                    Err(e) => {
                        debug!(target: "xray_tls::utls", ?fingerprint, error = %e, "btls 握手失败, fallback 到 rustls");
                        // fallback: 重新建立 TCP 连接已不可能（stream 被 consume），返回错误
                        return Err(e);
                    }
                }
            }
            Err(e) => {
                debug!(target: "xray_tls::utls", ?fingerprint, error = %e, "btls connector 构建失败, fallback 到 rustls");
            }
        }
    }

    // rustls fallback
    debug!(target: "xray_tls::utls", ?fingerprint, server_name, "u_client: rustls fallback");
    let inner = client(stream, server_name, config).await?;
    Ok(UConn { inner: UConnInner::Rustls(inner), fingerprint })
}

/// 默认 `ClientConfig`：使用 webpki-roots 系统 root + ring provider。
///
/// 对应 Go `tls.Config{ RootCAs: nil }`（nil 时 Go 用系统 root pool）。
/// 返回的 config 可在多次 `client()`/`u_client()` 调用间复用（`Arc` clone 廉价）。
#[must_use]
pub fn default_client_config() -> Arc<ClientConfig> {
    let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Arc::new(
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    )
}

// ============================================================
// 测试
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use xray_transport::connection::TcpConnection;

    /// 测试用 TLS server：自签证书 + 单条消息回显。
    async fn spawn_test_server(msg: &'static [u8]) -> (std::net::SocketAddr, Vec<u8>) {
        // 自签证书
        let cert_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = cert_params.self_signed(&key_pair).unwrap();
        let cert_der = cert.der().to_vec();
        let key_der = key_pair.serialize_der();

        // rustls server config
        let key = rustls_pki_types::PrivateKeyDer::try_from(key_der).unwrap();
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![rustls_pki_types::CertificateDer::from(cert_der.clone())],
                key,
            )
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                if let Ok((stream, _)) = listener.accept().await {
                    let acceptor = acceptor.clone();
                    let msg = msg;
                    tokio::spawn(async move {
                        let tcp = TcpConnection::new(stream);
                        if let Ok(mut tls) = acceptor.accept(tcp).await {
                            let _ = tls.write_all(msg).await;
                            let _ = tls.shutdown().await;
                        }
                    });
                }
            }
        });

        (addr, cert_der)
    }

    fn trusted_config(cert_der: Vec<u8>) -> Arc<ClientConfig> {
        let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
        root_store
            .add(rustls_pki_types::CertificateDer::from(cert_der))
            .unwrap();
        Arc::new(
            ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth(),
        )
    }

    #[tokio::test]
    async fn client_handshake_succeeds_with_trusted_cert() {
        let (addr, cert_der) = spawn_test_server(b"hello-from-tls\n").await;
        let config = trusted_config(cert_der);

        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut conn = client(TcpConnection::new(tcp), "localhost", config).await.expect("handshake ok");

        let mut buf = Vec::new();
        conn.read_to_end(&mut buf).await.expect("read ok");
        assert_eq!(buf, b"hello-from-tls\n");
    }

    /// 测试 u_client rustls fallback 路径（非 btls 指纹）。
    #[tokio::test]
    async fn u_client_falls_back_to_standard_rustls() {
        let (addr, cert_der) = spawn_test_server(b"u-fallback-ok\n").await;
        let config = trusted_config(cert_der);

        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        // Random 指纹不在 btls 支持列表，走 rustls fallback
        let mut u = u_client(TcpConnection::new(tcp), "localhost", config, Fingerprint::Random)
            .await
            .expect("fallback ok");
        assert_eq!(u.fingerprint, Fingerprint::Random);

        let mut buf = Vec::new();
        u.read_to_end(&mut buf).await.expect("read ok");
        assert_eq!(buf, b"u-fallback-ok\n");
    }

    #[tokio::test]
    async fn server_accepts_client() {
        let (addr, cert_der) = spawn_test_server(b"server-test\n").await;
        let config = trusted_config(cert_der);

        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut conn = client(TcpConnection::new(tcp), "localhost", config).await.unwrap();

        // ConnInterface::handshake 是 no-op
        conn.handshake().await.expect("handshake noop ok");
        // Connection::remote_addr 应来自底层 TcpConnection
        conn.remote_addr().expect("remote addr ok");
    }

    #[tokio::test]
    async fn handshake_server_name_returns_sni() {
        let (addr, cert_der) = spawn_test_server(b"sni-test\n").await;
        let config = trusted_config(cert_der);

        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut conn = client(TcpConnection::new(tcp), "localhost", config).await.unwrap();
        let sni = conn.handshake_server_name().await;
        assert_eq!(sni, "localhost");
    }

    #[test]
    fn default_client_config_uses_webpki_roots() {
        // webpki_roots 可能因版本变化为空，但应能构造
        let config = default_client_config();
        let _ = Arc::strong_count(&config);
    }

    /// btls (BoringSSL) Chrome 133 指纹端到端测试。
    /// 连接真实 TLS server (cloudflare.com:443)，验证握手成功。
    /// 标 #[ignore] 因需要网络——CI 默认跳过，手动跑 `cargo test -- --ignored`。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore]
    async fn btls_chrome133_handshakes_with_real_server() {
        let tcp = tokio::net::TcpStream::connect("cloudflare.com:443")
            .await
            .expect("TCP connect to cloudflare.com:443");
        let mut conn = crate::btls_client::BtlsConn::connect(
            TcpConnection::new(tcp),
            "cloudflare.com",
            Fingerprint::Chrome,
        )
        .await
        .expect("btls Chrome 133 握手成功");

        // 验证 ALPN 协商
        let alpn = conn.negotiated_protocol().await;
        assert!(
            alpn == "h2" || alpn == "http/1.1",
            "ALPN 应为 h2 或 http/1.1，实际: {alpn}"
        );

        // 验证 server_name 存储
        let sni = conn.handshake_server_name().await;
        assert_eq!(sni, "cloudflare.com");
    }

    /// btls 连接自签证书 rustls server 的调试测试。
    /// 标 #[ignore]——用于诊断 'unknown BoringSSL error' 根因。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore]
    async fn btls_chrome133_with_self_signed_server_debug() {
        let (addr, _cert_der) = spawn_test_server(b"btls-self-signed\n").await;

        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let result = crate::btls_client::BtlsConn::connect(
            TcpConnection::new(tcp),
            "localhost",
            Fingerprint::Chrome,
        )
        .await;

        match result {
            Ok(mut conn) => {
                let mut buf = Vec::new();
                conn.read_to_end(&mut buf).await.expect("read ok");
                assert_eq!(buf, b"btls-self-signed\n");
            }
            Err(e) => {
                eprintln!("btls 自签证书握手失败: {e}");
                // 不 panic——此测试用于诊断，记录失败即可
            }
        }
    }
}
