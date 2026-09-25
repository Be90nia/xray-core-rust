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
//! - [`u_client`]：btls（BoringSSL）真实浏览器指纹握手，返回携带 `Fingerprint` 标记的
//!   [`UConn`]；清单外指纹硬错（不静默回退）。ALPN 覆盖变体见
//!   [`u_client_with_alpn`]（ws/httpupgrade WebsocketHandshakeContext 语义）
//!
//! 工厂函数 async——握手在工厂内部完成；返回的 Conn/UConn 已是已握手连接。
//!
//! # trait 对齐
//!
//! 与 xray-transport 的 `Connection` trait
//! 对齐：`Conn<S>`/`ServerConn<S>`/`UConn<S>` 同时实现 `Connection`（remote/local addr）
//! 与 [`ConnInterface`]（握手相关 API）。AsyncRead + AsyncWrite 由 forward 到
//! `tokio_rustls::TlsStream<S>` 自动获得。

use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};

use rustls_pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::{
    TlsAcceptor, TlsConnector,
    client::TlsStream as ClientTlsStream,
    rustls::{ClientConfig, ServerConfig},
    server::TlsStream as ServerTlsStream,
};
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
    fn handshake_server_name<'a>(&'a mut self)
    -> Pin<Box<dyn Future<Output = String> + Send + 'a>>;

    /// 返回 ALPN 协商出的协议名（如 `"h2"`/`"http/1.1"`）。未协商返回空字符串。
    fn negotiated_protocol<'a>(&'a self) -> Pin<Box<dyn Future<Output = String> + Send + 'a>>;
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
    /// write 后底层尚有滞留未冲净（见 `Conn::poll_write` 的实现注释）。
    dirty: bool,
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

    /// 启用 REALITY Spider 流量填充。
    ///
    /// 当前为 no-op：rustls 不提供 per-record 大小控制 API。
    /// 未来可通过 TLS record layer 手动分段实现。
    pub fn enable_spider_padding(&mut self, _limit: Option<usize>) {
        // TODO: rustls 无 set_plaintext_buffer_limit API。
        // 需自定义 TLS record wrapper 或等待 rustls PR #2382 合入。
    }
}

impl<S: Connection + Unpin> AsyncRead for Conn<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // dirty 期间借读侧 poll 机会推进滞留：对端通常阻塞在读我们的
        // 尾部数据上（请求没发全它不回响应），duplex/TCP 窗口一旦空出
        // 即唤醒本任务，此处 flush 得以继续，否则滞留无 poll 机会可推。
        // flush 的 Pending/Err 不改变 read 结果（底层若断，read 自会报）。
        if self.dirty {
            match Pin::new(&mut self.inner).poll_flush(cx) {
                Poll::Ready(Ok(())) => self.dirty = false,
                Poll::Pending | Poll::Ready(Err(_)) => {},
            }
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: Connection + Unpin> AsyncWrite for Conn<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let n = ready!(Pin::new(&mut self.inner).poll_write(cx, buf))?;
        // tokio-rustls 0.26 是 BufWriter 语义：poll_write Ok(n) 只保证
        // 数据进入 rustls session 缓冲，write_io Pending（底层窗口满）时
        // 尾部 TLS record 滞留缓冲，须 poll_flush 才落底层。上层 pump
        // （bridge write_all 循环）不 flush——若尾 chunk 滞留后上层转入
        // 等响应，滞留永不发出，对端凑不齐请求 → 双向死锁。此处尽力
        // flush；Pending 时不得上传（上层会把 Pending 视为 0 进展而重发
        // 整段 buf，内层已接受的数据被重复加密），记 dirty 留给读侧推进。
        match Pin::new(&mut self.inner).poll_flush(cx) {
            Poll::Ready(Ok(())) => self.dirty = false,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => self.dirty = true,
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let res = Pin::new(&mut self.inner).poll_flush(cx);
        if matches!(res, Poll::Ready(Ok(()))) {
            self.dirty = false;
        }
        res
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

    fn raw_tcp_clone(&self) -> Option<tokio::net::TcpStream> {
        // 穿透 rustls 层克隆内层流的裸 TCP（vision splice 用）。
        self.inner.get_ref().0.raw_tcp_clone()
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
    /// write 后底层尚有滞留未冲净（同 `Conn::dirty`，见其 poll_write 注释）。
    dirty: bool,
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

    /// 启用 Spider 流量填充（服务端）。
    ///
    /// 当前为 no-op：rustls 不提供 per-record 大小控制 API。
    pub fn enable_spider_padding(&mut self, _limit: Option<usize>) {
        // TODO: 同 Conn::enable_spider_padding
    }
}

impl<S: Connection + Unpin> AsyncRead for ServerConn<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // 同 Conn::poll_read：dirty 期间借读侧 poll 机会推进 write 滞留。
        if self.dirty {
            match Pin::new(&mut self.inner).poll_flush(cx) {
                Poll::Ready(Ok(())) => self.dirty = false,
                Poll::Pending | Poll::Ready(Err(_)) => {},
            }
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: Connection + Unpin> AsyncWrite for ServerConn<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // 同 Conn::poll_write：尽力冲净 session 滞留，Pending 记 dirty。
        let n = ready!(Pin::new(&mut self.inner).poll_write(cx, buf))?;
        match Pin::new(&mut self.inner).poll_flush(cx) {
            Poll::Ready(Ok(())) => self.dirty = false,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => self.dirty = true,
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let res = Pin::new(&mut self.inner).poll_flush(cx);
        if matches!(res, Poll::Ready(Ok(()))) {
            self.dirty = false;
        }
        res
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

    fn raw_tcp_clone(&self) -> Option<tokio::net::TcpStream> {
        match &self.inner {
            UConnInner::Rustls(c) => c.raw_tcp_clone(),
            UConnInner::Btls(c) => c.raw_tcp_clone(),
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
    let server: ServerName<'static> =
        ServerName::try_from(server_name.to_string()).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("invalid server name: {e}"))
        })?;
    let tls_stream = connector.connect(server, stream).await?;
    Ok(Conn { inner: tls_stream, server_name: server_name.to_string(), dirty: false })
}

/// 创建标准 rustls TLS 服务端连接（完成握手）。
///
/// 对应 Go `tls.Server(c, config)` + `HandshakeContext`。
pub async fn server<S>(stream: S, config: Arc<ServerConfig>) -> io::Result<ServerConn<S>>
where
    S: Connection + Unpin,
{
    let acceptor = TlsAcceptor::from(config);
    let tls_stream = acceptor.accept(stream).await?;
    Ok(ServerConn { inner: tls_stream, dirty: false })
}

/// 创建 uTLS 指纹伪装客户端连接。
///
/// 对应 Go `utls.UClient(c, config, fingerprint)`。
/// **当前实现**：指纹在 btls 支持清单内走 [`crate::btls_client::BtlsConn`]
/// 真实浏览器指纹握手；清单外指纹返回 `InvalidData` 硬错（不再静默回退
/// rustls），connector 构建失败同样硬错。
pub async fn u_client<S>(
    stream: S,
    server_name: &str,
    config: Arc<ClientConfig>,
    fingerprint: Fingerprint,
    ech_config_list: Option<&str>,
    security_json: Option<&serde_json::Value>,
) -> io::Result<UConn<S>>
where
    S: Connection + Unpin,
{
    u_client_with_alpn(
        stream,
        server_name,
        config,
        fingerprint,
        ech_config_list,
        security_json,
        None,
    )
    .await
}

/// [`u_client`] 的 ALPN 覆盖版（ws/httpupgrade 出站接线用，md5i）。
///
/// 对应 Go `tls.UClient` + `UConn.WebsocketHandshakeContext`（websocket/
/// httpupgrade dialer 共用，tls.go:98-133）：指纹模板的其余 ClientHello 形态
/// 保持，仅把 ALPN 扩展重写为 `alpn`；`None` = 保持模板 ALPN。
pub async fn u_client_with_alpn<S>(
    stream: S,
    server_name: &str,
    config: Arc<ClientConfig>,
    fingerprint: Fingerprint,
    ech_config_list: Option<&str>,
    // btls 回接验证（pz6c）：`tlsSettings` 原文，内部构建服务端证书验证器
    // （allowInsecure/pinned/vcn/用户根，语义同 rustls 路径）。
    security_json: Option<&serde_json::Value>,
    alpn: Option<&[Vec<u8>]>,
) -> io::Result<UConn<S>>
where
    S: Connection + Unpin,
{
    let alpn_wire = alpn.map(encode_alpn_wire);
    // 尝试 btls（真实指纹）
    if let Some(result) = crate::btls_client::connector_for_fingerprint(&fingerprint) {
        match result {
            Ok(_) => {
                debug!(target: "xray_tls::utls", ?fingerprint, server_name, "u_client: 尝试 btls 指纹伪装");
                // ECH DNS 形式（Go ech.go ApplyECH "://" 分支）：握手前真实查询
                // （DoH，`ech_doh::query_ech_config`），结果 base64 回灌——resolve 的
                // base64 分支原样解码，且 base64 不含 "://" 不会误入占位分支；
                // 查询失败保持原串 → resolve 走 Full 语义落 INVALID_ECH_CONFIG
                // （对齐 Go defer 失败语义：ECH 获取失败必须连接失败，不静默明文）。
                let ech_resolved;
                let ech_list: Option<&str> = match ech_config_list {
                    Some(list) if list.contains("://") => {
                        use base64::Engine as _;
                        match crate::ech_doh::query_ech_config(list, server_name, None).await {
                            Ok(bytes) => {
                                ech_resolved =
                                    base64::engine::general_purpose::STANDARD.encode(bytes);
                                Some(ech_resolved.as_str())
                            },
                            Err(e) => {
                                debug!(target: "xray_tls::utls", error = %e,
                                    "ECH DoH query failed; falling back to invalid config (connection will fail)");
                                Some(list)
                            },
                        }
                    },
                    other => other,
                };
                match crate::btls_client::BtlsConn::connect_with_alpn(
                    stream,
                    server_name,
                    fingerprint,
                    ech_list,
                    // 回接证书验证（pz6c）：allowInsecure=true → None 跳过；
                    // 否则 webpki/pinned verifier 对 btls peer 链做链+主机名验证。
                    crate::client_config::build_server_cert_verifier(security_json)?,
                    alpn_wire.as_deref(),
                )
                .await
                {
                    Ok(btls_conn) => {
                        return Ok(UConn { inner: UConnInner::Btls(btls_conn), fingerprint });
                    },
                    Err(e) => {
                        debug!(target: "xray_tls::utls", ?fingerprint, error = %e, "btls 握手失败, fallback 到 rustls");
                        // fallback: 重新建立 TCP 连接已不可能（stream 被 consume），返回错误
                        return Err(e);
                    },
                }
            },
            Err(e) => {
                // 清单外指纹（InvalidData）等 connector 构建失败：硬错。
                // 配置了指纹却静默回退标准 rustls 等于伪装失效（批3 裁决）。
                return Err(e);
            },
        }
    }
    // rustls fallback：无 ECH 能力（rustls 无该 feature），配置了 ECH 时 warn。
    if let Some(list) = ech_config_list {
        tracing::warn!(
            target: "xray_tls::utls",
            len = list.len(),
            "ECH config list ignored on rustls fallback (btls fingerprint unavailable); connection proceeds without ECH"
        );
    }
    debug!(target: "xray_tls::utls", ?fingerprint, server_name, "u_client: rustls fallback");
    let inner = client(stream, server_name, config).await?;
    Ok(UConn { inner: UConnInner::Rustls(inner), fingerprint })
}

/// ALPN 协议列表 → openssl wire 格式（每项前缀单字节长度）。
fn encode_alpn_wire(protocols: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::with_capacity(protocols.iter().map(|p| p.len() + 1).sum());
    for p in protocols {
        out.push(p.len() as u8);
        out.extend_from_slice(p);
    }
    out
}

/// ws/httpupgrade 出站的握手 ALPN（Go `WebsocketHandshakeContext` +
/// `WithNextProto("http/1.1")` 语义，tls.go:98-104 + config.go:506-511）。
///
/// 用户 `tlsSettings.alpn` 恰为 `["h2","http/1.1"]`（伪装场景）→ 原样保留；
/// 其余情形（未配置 / 其他组合）→ 强制 `["http/1.1"]`（upgrade 是 HTTP/1.1
/// 语义，h2 协商会令 h1 upgrade 帧解析失败）。
#[must_use]
pub fn websocket_handshake_alpn(security_json: Option<&serde_json::Value>) -> Vec<Vec<u8>> {
    let user: Option<Vec<Vec<u8>>> = security_json
        .and_then(|j| j.get("alpn"))
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|s| s.as_str().map(|x| x.as_bytes().to_vec())).collect());
    let h2_h1 = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    match user {
        Some(a) if a == h2_h1 => a,
        _ => vec![b"http/1.1".to_vec()],
    }
}

/// 默认 `ClientConfig`：使用 webpki-roots 系统 root + ring provider。
///
/// 对应 Go `tls.Config{ RootCAs: nil }`（nil 时 Go 用系统 root pool）。
/// 返回的 config 可在多次 `client()`/`u_client()` 调用间复用（`Arc` clone 廉价）。
#[must_use]
pub fn default_client_config() -> Arc<ClientConfig> {
    xray_common::ensure_default_crypto_provider();
    let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Arc::new(ClientConfig::builder().with_root_certificates(root_store).with_no_client_auth())
}

// ============================================================
// 测试
// ============================================================

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use xray_transport::connection::TcpConnection;

    use super::*;

    /// 测试用 TLS server：自签证书 + 单条消息回显。
    async fn spawn_test_server(msg: &'static [u8]) -> (std::net::SocketAddr, Vec<u8>) {
        let _ = rustls::crypto::ring::default_provider().install_default();
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
            .with_single_cert(vec![rustls_pki_types::CertificateDer::from(cert_der.clone())], key)
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
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
        root_store.add(rustls_pki_types::CertificateDer::from(cert_der)).unwrap();
        Arc::new(ClientConfig::builder().with_root_certificates(root_store).with_no_client_auth())
    }

    #[tokio::test]
    async fn client_handshake_succeeds_with_trusted_cert() {
        let (addr, cert_der) = spawn_test_server(b"hello-from-tls\n").await;
        let config = trusted_config(cert_der);

        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut conn =
            client(TcpConnection::new(tcp), "localhost", config).await.expect("handshake ok");

        let mut buf = Vec::new();
        conn.read_to_end(&mut buf).await.expect("read ok");
        assert_eq!(buf, b"hello-from-tls\n");
    }

    /// 测试 u_client btls 路径 `allowInsecure=true`（verifier=None）连自签 server。
    ///
    /// 注：本测试原名 `u_client_falls_back_to_standard_rustls`——pz6c 修正：
    /// Random 指纹实际映射 Chrome 133 走 btls（connector_for_fingerprint 对
    /// 全清单返回 Some，rustls fallback 分支已随"清单外指纹硬错"裁决成为
    /// 死代码），修复后自签证书必须经 allowInsecure 显式放行。
    #[tokio::test]
    async fn u_client_btls_accepts_with_allow_insecure() {
        let (addr, _cert_der) = spawn_test_server(b"u-insecure-ok\n").await;

        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let insecure_json = serde_json::json!({ "allowInsecure": true });
        let mut u = u_client(
            TcpConnection::new(tcp),
            "localhost",
            default_client_config(),
            Fingerprint::Random,
            None,
            Some(&insecure_json),
        )
        .await
        .expect("allowInsecure must accept self-signed cert");
        assert_eq!(u.fingerprint, Fingerprint::Random);

        let mut buf = Vec::new();
        u.read_to_end(&mut buf).await.expect("read ok");
        assert_eq!(buf, b"u-insecure-ok\n");
    }

    /// md5i：websocket_handshake_alpn —— Go `WebsocketHandshakeContext` +
    /// `WithNextProto("http/1.1")` 的 ALPN 解析语义。
    #[test]
    fn websocket_handshake_alpn_forces_h1_unless_h2_camouflage() {
        // 未配置 → 强制 http/1.1（WithNextProto 缺省）
        assert_eq!(websocket_handshake_alpn(None), vec![b"http/1.1".to_vec()]);
        assert_eq!(
            websocket_handshake_alpn(Some(&serde_json::json!({}))),
            vec![b"http/1.1".to_vec()]
        );
        // 伪装组合 ["h2","http/1.1"] → 原样保留
        assert_eq!(
            websocket_handshake_alpn(Some(&serde_json::json!({"alpn": ["h2", "http/1.1"]}))),
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        // 其他组合（如仅 ["h2"]）→ Go 强制回 http/1.1
        assert_eq!(
            websocket_handshake_alpn(Some(&serde_json::json!({"alpn": ["h2"]}))),
            vec![b"http/1.1".to_vec()]
        );
    }

    /// md5i：encode_alpn_wire —— openssl wire 格式（每项单字节长度前缀）。
    #[test]
    fn encode_alpn_wire_prepends_lengths() {
        assert_eq!(encode_alpn_wire(&[b"http/1.1".to_vec()]), b"\x08http/1.1".to_vec());
        assert_eq!(
            encode_alpn_wire(&[b"h2".to_vec(), b"http/1.1".to_vec()]),
            b"\x02h2\x08http/1.1".to_vec()
        );
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
            None,
            // 真实服务器：走完整验证（cloudflare 证书合法，webpki-roots 应过）
            crate::client_config::build_server_cert_verifier(None).unwrap(),
        )
        .await
        .expect("btls Chrome 133 握手成功");

        // 验证 ALPN 协商
        let alpn = conn.negotiated_protocol().await;
        assert!(alpn == "h2" || alpn == "http/1.1", "ALPN 应为 h2 或 http/1.1，实际: {alpn}");

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
            None,
            None, // 自签证书诊断：跳过验证
        )
        .await;

        match result {
            Ok(mut conn) => {
                let mut buf = Vec::new();
                conn.read_to_end(&mut buf).await.expect("read ok");
                assert_eq!(buf, b"btls-self-signed\n");
            },
            Err(e) => {
                eprintln!("btls 自签证书握手失败: {e}");
                // 不 panic——此测试用于诊断，记录失败即可
            },
        }
    }

    /// 全指纹端到端测试：所有 Modern 指纹 × 3 真实 TLS 服务器。
    /// 标 #[ignore] 因需要网络——CI 默认跳过，手动跑 `cargo test -- --ignored`。
    ///
    /// 验证每个指纹都能成功握手 + ALPN 协商为 h2 或 http/1.1。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore]
    async fn btls_all_modern_fingerprints_handshake() {
        let fingerprints: Vec<(Fingerprint, &str)> = vec![
            (Fingerprint::Chrome, "Chrome(preset)"),
            (Fingerprint::HelloChrome133, "Chrome133"),
            (Fingerprint::HelloChrome131, "Chrome131"),
            (Fingerprint::HelloChrome120, "Chrome120"),
            (Fingerprint::Firefox, "Firefox(preset)"),
            (Fingerprint::HelloFirefox148, "Firefox148"),
            (Fingerprint::HelloFirefox120, "Firefox120"),
            (Fingerprint::Safari, "Safari(preset)"),
            (Fingerprint::HelloSafari26_3, "Safari26.3"),
            (Fingerprint::Ios, "iOS(preset)"),
            (Fingerprint::HelloIos14, "iOS14"),
            (Fingerprint::HelloIos13, "iOS13"),
            (Fingerprint::Edge, "Edge(preset)"),
            (Fingerprint::HelloEdge106, "Edge106"),
            (Fingerprint::Qihoo360, "360(preset)"),
            (Fingerprint::Hello360_11_0, "360_11.0"),
            (Fingerprint::Qq, "QQ(preset)"),
            (Fingerprint::HelloQq_11_1, "QQ_11.1"),
        ];

        let servers = ["cloudflare.com:443", "google.com:443", "github.com:443"];

        let mut ok = 0usize;
        let mut fail = 0usize;
        let mut errors = Vec::new();

        for (fp, fp_name) in &fingerprints {
            for server in &servers {
                let tcp = match tokio::net::TcpStream::connect(server).await {
                    Ok(t) => t,
                    Err(e) => {
                        errors.push(format!("{fp_name} → {server}: TCP 失败: {e}"));
                        fail += 1;
                        continue;
                    },
                };

                match crate::btls_client::BtlsConn::connect(
                    TcpConnection::new(tcp),
                    server.trim_end_matches(":443"),
                    *fp,
                    None,
                    crate::client_config::build_server_cert_verifier(None).unwrap(),
                )
                .await
                {
                    Ok(conn) => {
                        let alpn = conn.negotiated_protocol().await;
                        if alpn == "h2" || alpn == "http/1.1" || alpn.is_empty() {
                            ok += 1;
                        } else {
                            errors.push(format!("{fp_name} → {server}: ALPN 异常: {alpn}"));
                            fail += 1;
                        }
                    },
                    Err(e) => {
                        errors.push(format!("{fp_name} → {server}: 握手失败: {e}"));
                        fail += 1;
                    },
                }
            }
        }

        if !errors.is_empty() {
            eprintln!("\n=== btls 全指纹测试失败详情 ===");
            for e in &errors {
                eprintln!("  {e}");
            }
        }
        assert_eq!(fail, 0, "{fail} 个指纹握手失败（{ok} 成功），见上方详情");
    }
    // ============================================================
    // btls 回接证书验证（pz6c）：指纹路径不得等价 InsecureSkipVerify=true
    // ============================================================

    /// btls 指纹客户端 + 默认 webpki verifier：自签证书必须被拒
    /// （修复前该路径恒成功——零验证）。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn btls_client_rejects_untrusted_cert() {
        let (addr, _cert_der) = spawn_test_server(b"never-read\n").await;
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();

        let result = crate::btls_client::BtlsConn::connect(
            TcpConnection::new(tcp),
            "localhost",
            Fingerprint::HelloChrome133,
            None,
            crate::client_config::build_server_cert_verifier(None).unwrap(),
        )
        .await;

        let err = match result {
            Ok(_) => panic!("self-signed cert must be rejected without allowInsecure"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("certificate verification failed"),
            "expected verification error, got: {err}"
        );
    }

    /// btls 指纹客户端 + verifier=None（allowInsecure=true 等价）：连接成功且可读数据。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn btls_client_accepts_without_verifier() {
        let (addr, _cert_der) = spawn_test_server(b"btls-insecure-ok\n").await;
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();

        let mut conn = crate::btls_client::BtlsConn::connect(
            TcpConnection::new(tcp),
            "localhost",
            Fingerprint::HelloChrome133,
            None,
            None,
        )
        .await
        .expect("allowInsecure (verifier=None) must accept");

        let mut buf = Vec::new();
        conn.read_to_end(&mut buf).await.expect("read ok");
        assert_eq!(buf, b"btls-insecure-ok\n");
    }

    /// btls 指纹客户端 + 生产 pinnedPeerCertSha256 配置：pin 命中必须通过
    /// （verifier 走 PinnedServerCertVerifier，与 rustls 路径同源）。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn btls_client_accepts_pinned_cert() {
        let (addr, cert_der) = spawn_test_server(b"btls-pinned-ok\n").await;
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();

        let pin_hex = crate::pin::generate_cert_hash_hex(&cert_der);
        let pinned_json = serde_json::json!({ "pinnedPeerCertSha256": pin_hex });
        let verifier = crate::client_config::build_server_cert_verifier(Some(&pinned_json))
            .unwrap()
            .expect("pinned config yields a verifier");

        let mut conn = crate::btls_client::BtlsConn::connect(
            TcpConnection::new(tcp),
            "localhost",
            Fingerprint::HelloChrome133,
            None,
            Some(verifier),
        )
        .await
        .expect("pinned cert must be accepted");

        let mut buf = Vec::new();
        conn.read_to_end(&mut buf).await.expect("read ok");
        assert_eq!(buf, b"btls-pinned-ok\n");
    }

    /// 端到端（生产入口）：tcp/grpc/splithttp register 共用的 u_client，
    /// 配置指纹 + 默认安全配置（无 allowInsecure）连自签 server 必须被拒
    /// （修复前该路径恒成功——零验证，等价 InsecureSkipVerify=true）。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn u_client_btls_fingerprint_rejects_untrusted_cert() {
        let (addr, _cert_der) = spawn_test_server(b"never-read\n").await;
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();

        let result = u_client(
            TcpConnection::new(tcp),
            "localhost",
            default_client_config(),
            Fingerprint::HelloChrome133,
            None,
            None, // 无 allowInsecure → 默认全验证
        )
        .await;

        let err = match result {
            Ok(_) => panic!("u_client must reject untrusted cert by default"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("certificate verification failed"),
            "expected verification error, got: {err}"
        );
    }
}
