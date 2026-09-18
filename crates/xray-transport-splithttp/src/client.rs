//! SplitHTTP 客户端——HTTP/2 (含 HTTP/1.1 fallback) 拨号 + 上传 + 下载。
//!
//! 翻译自 Go `transport/internet/splithttp/client.go`。
//!
//! # 切片 A-D 范围
//!
//! - [`DefaultDialerClient`]：基于 `hyper-util legacy Client` + `hyper-rustls`，
//!   自动 ALPN 协商 h2 / h1.1
//! - [`DefaultDialerClient::open_stream`]：GET 下载流（stream-down）/ POST 一次性 body
//!   （packet-up 的 GET 下载、stream-down 模式）
//! - [`DefaultDialerClient::post_packet`]：POST 单个分包（packet-up），等 200 OK
//! - [`DefaultDialerClient::open_stream_uploading`]：POST streaming body
//!   （stream-up / stream-one，支持全双工流式上传）
//! - 内部 [`Self::build_request`] / [`Self::build_request_with_body`]：把
//!   [`crate::config::RequestMeta`] + 任意 body 转换为 `hyper::Request<ReqBody>`
//!
//! # 不实现（留后续切片）
//!
//! - `WaitReadCloser` 异步等待机制（Go 用来同步 GotConn 与响应到达）→ GET 分支以
//!   [`Self::open_stream`] 的 lazy reader 等价实现（同步 await 响应头会在 Go 26.9.9
//!   hub `SetFlushNext` 语义下与上传侧形成环形死锁，见 `spawn_h2_lazy_reader`）。
//! - `browser_dialer` 路径 → 切片 b7f 独立任务
//! - HTTP/3 / QUIC → 切片 G（可选）
//! - xmux 多路复用 → 切片 E

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use futures_util::{Stream, TryStreamExt};
use http::request::Request;
use http::{Method, StatusCode, Uri};
use hyper::body::Frame;
use http_body_util::{BodyDataStream, BodyExt, Full, StreamBody};
use http_body_util::combinators::BoxBody;
use hyper_rustls::{FixedServerNameResolver, HttpsConnector, HttpsConnectorBuilder, MaybeHttpsStream};
use hyper_util::client::legacy::connect::{Connected, Connection as HttpConnection, HttpConnector, HttpInfo};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::dns::Name as DnsName;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use rustls::ClientConfig as RustlsClientConfig;
use rustls::pki_types::ServerName;
use tokio::io::AsyncRead as AsyncReadTrait;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::io::StreamReader;
use tracing::debug;
use tower_service::Service as TowerService;
pub use xray_tls::fingerprint::Fingerprint;
use xray_tls::utls::{ConnInterface, UConn};
use xray_transport::connection::TcpConnection;

use crate::config::{Config, RequestMeta};
use crate::error::{Result, SplitHttpError};

/// 拨号目标——Go `splithttp/dialer.go::dialContext` 语义：TCP 恒拨出站 `dest`
/// （`internet.DialSystem(ctxInner, dest, ...)`），URL authority（`config.host`）
/// 仅作 Host/:authority 头；TLS SNI 用 tlsSettings.serverName（缺省 dest 地址）。
///
/// 域名前置（domain fronting）部署下 URI host 与 dest 是两个不同域名：解析
/// URI host 会连到错误入口（实测 CF argo 隧道边缘对直连 h2 GET 不回包→挂死）。
#[derive(Debug, Clone)]
pub struct DialTarget {
    /// TCP 拨号主机（dest.address 原样；域名在 resolver 内做系统 DNS）。
    pub host: String,
    /// TCP 拨号端口（dest.port）。
    pub port: u16,
    /// TLS SNI。空 = 回退 hyper 默认（URI authority host）。
    pub sni: String,
}

/// 忽略 URI host、恒解析 `DialTarget` 的 DNS resolver（hyper-util Service 语义）。
#[derive(Debug, Clone)]
pub struct DestResolver {
    host: std::sync::Arc<str>,
    port: u16,
}

impl TowerService<DnsName> for DestResolver {
    type Response = std::vec::IntoIter<SocketAddr>;
    type Error = std::io::Error;
    type Future = std::pin::Pin<
        Box<dyn Future<Output = std::io::Result<std::vec::IntoIter<SocketAddr>>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, _name: DnsName) -> Self::Future {
        let host = std::sync::Arc::clone(&self.host);
        let port = self.port;
        Box::pin(async move {
            tokio::net::lookup_host((host.as_ref(), port))
                .await
                .map(|it| it.collect::<Vec<_>>().into_iter())
        })
    }
}

/// 统一 hyper 请求 body 类型（允许 `Full<Bytes>` 和 `StreamBody` 都能发送）。
///
/// error 类型用 `std::io::Error`（`StreamBody` 的错误类型）；`Full<Bytes>` 的
/// error 是 `Infallible`，通过 `map_err` 闭包转换（match infallible {} unreachable）。
pub type ReqBody = BoxBody<Bytes, std::io::Error>;

/// hyper-util legacy Client 类型别名。
///
/// packet-up 用 `Full<Bytes>`（一次性 body）；stream-up/stream-one 用 `StreamBody`
///（流式上传）。两者都 box 成 [`ReqBody`]。
pub type HyperClient = Client<SplitConnector, ReqBody>;

/// 出站 connector（[`TowerService`] for `Uri`）。
///
/// - [`SplitConnector::Rustls`]：hyper-rustls 现有路径（fingerprint 空），原样转发。
/// - [`SplitConnector::Btls`]：fingerprint 非空，TCP 后用 `xray_tls::utls::u_client`
///   完成 btls 真实浏览器指纹握手（对应 Go splithttp `dialContext` 的 `tls.UClient`）。
#[derive(Clone)]
pub enum SplitConnector {
    Rustls(HttpsConnector<HttpConnector<DestResolver>>),
    Btls(BtlsDial),
}

/// [`SplitConnector::Btls`] 分支的拨号参数（忽略 URI authority，恒拨 dest）。
#[derive(Clone)]
pub struct BtlsDial {
    pub host: Arc<str>,
    pub port: u16,
    /// TLS SNI（tlsSettings.serverName，空回退 dest host）。
    pub sni: String,
    /// 自建 config，清单外指纹由 u_client 回退此 config 走 rustls）。
    pub config: Arc<RustlsClientConfig>,
    pub fingerprint: Fingerprint,
    /// `tlsSettings` 原文（pz6c）：btls 指纹握手后回接证书验证用
    /// （allowInsecure/pinned/vcn 语义，见 `xray_tls::client_config::build_server_cert_verifier`）。
    pub security_json: Option<serde_json::Value>,
}

/// [`SplitConnector`] 的统一 response 流。满足 hyper-util legacy Client 的
/// Connect bound：`hyper::rt::Read/Write` + legacy `Connection` + Unpin + Send。
///
/// - Rustls 分支原生 `MaybeHttpsStream` 自带 rt traits（转发保留 `connected()`
///   的 ALPN/HttpInfo 元数据）。
/// - Btls 分支 `UConn` 只实现 tokio traits，用 `TokioIo` 桥接。
pub enum SplitStream {
    Rustls(MaybeHttpsStream<TokioIo<tokio::net::TcpStream>>),
    Btls {
        io: TokioIo<UConn<TcpConnection>>,
        /// ALPN 协商出 `h2` 时 hyper 须走 HTTP/2（`Connected::negotiated_h2`）。
        alpn_h2: bool,
    },
}

impl TowerService<Uri> for SplitConnector {
    type Response = SplitStream;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = std::result::Result<SplitStream, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<std::result::Result<(), Self::Error>> {
        match self {
            SplitConnector::Rustls(c) => c.poll_ready(cx),
            SplitConnector::Btls(_) => Poll::Ready(Ok(())),
        }
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        match self {
            SplitConnector::Rustls(c) => {
                let fut = c.call(uri);
                Box::pin(async move { Ok(SplitStream::Rustls(fut.await?)) })
            }
            SplitConnector::Btls(dial) => {
                let dial = dial.clone();
                Box::pin(async move {
                    // Go dialContext：TCP 恒拨出站 dest，忽略 URI authority。
                    let tcp =
                        tokio::net::TcpStream::connect((dial.host.to_string(), dial.port)).await?;
                    tcp.set_nodelay(true).ok();
                    let conn = xray_tls::utls::u_client(
                        TcpConnection::new(tcp),
                        &dial.sni,
                        dial.config.clone(),
                        dial.fingerprint,
                        None,
                        dial.security_json.as_ref(),
                    )
                    .await?;
                    // ALPN 协商结果决定 hyper 的 HTTP 版本（浏览器预设 [h2, http/1.1]）。
                    let alpn_h2 = ConnInterface::negotiated_protocol(&conn).await == "h2";
                    Ok(SplitStream::Btls { io: TokioIo::new(conn), alpn_h2 })
                })
            }
        }
    }
}

impl hyper::rt::Read for SplitStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            SplitStream::Rustls(s) => Pin::new(s).poll_read(cx, buf),
            SplitStream::Btls { io, .. } => Pin::new(io).poll_read(cx, buf),
        }
    }
}

impl hyper::rt::Write for SplitStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            SplitStream::Rustls(s) => Pin::new(s).poll_write(cx, buf),
            SplitStream::Btls { io, .. } => Pin::new(io).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            SplitStream::Rustls(s) => Pin::new(s).poll_flush(cx),
            SplitStream::Btls { io, .. } => Pin::new(io).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            SplitStream::Rustls(s) => Pin::new(s).poll_shutdown(cx),
            SplitStream::Btls { io, .. } => Pin::new(io).poll_shutdown(cx),
        }
    }
}

impl HttpConnection for SplitStream {
    fn connected(&self) -> Connected {
        match self {
            SplitStream::Rustls(s) => s.connected(),
            SplitStream::Btls { alpn_h2, .. } => {
                let connected = Connected::new();
                if *alpn_h2 {
                    connected.negotiated_h2()
                } else {
                    connected
                }
            }
        }
    }
}

/// 构造一次性 body（`Vec<u8>` → `Full<Bytes>` boxed）。
fn make_full_body(b: Vec<u8>) -> ReqBody {
    Full::new(Bytes::from(b))
        .map_err(|e: std::convert::Infallible| -> std::io::Error { match e {} })
        .boxed()
}

/// 空 body（GET 请求用）。
fn empty_body() -> ReqBody {
    Full::new(Bytes::new())
        .map_err(|e: std::convert::Infallible| -> std::io::Error { match e {} })
        .boxed()
}

/// 构造流式 body（`Stream<Item=io::Result<Bytes>>` → `StreamBody` boxed）。
///
/// 用于 stream-up / stream-one 的 POST 请求 body。
pub(crate) fn make_stream_body<S>(s: S) -> ReqBody
where
    S: Stream<Item = std::io::Result<Bytes>> + Send + Sync + 'static,
{
    StreamBody::new(s.map_ok(Frame::data)).boxed()
}

/// HTTP 拨号客户端——封装 hyper-util Client + splithttp Config。
///
/// 对应 Go `DefaultDialerClient` struct。线程安全（`Client` 内部带连接池 +
/// `Arc` 计数）。
pub struct DefaultDialerClient {
    /// splithttp 配置引用（用于构造 RequestMeta）。
    pub config: Arc<Config>,
    /// hyper-util 客户端（含连接池 + TLS）。
    pub client: HyperClient,
    /// 连接是否已关闭（任何 IO 错误后置 true，等价 Go `closed` 字段）。
    closed: Arc<AtomicBool>,
}

impl DefaultDialerClient {
    /// 创建新客户端。`tls_config` 由调用方（[`crate::dialer`]）从 `stream_settings`
    /// 构造；`dial` 指定 Go 语义：TCP 恒拨出站 `dest`，URL authority 仅作 Host 头；
    /// 域名前置（domain fronting）部署：dest=home.begonia92.top，URL host=sg-argo
    /// （TLS SNI 与 Host 头），与 Go `splithttp/dialer.go::dialContext` 等价。
    ///
    /// `fingerprint` 非空时出站用 btls `u_client` 完成真实浏览器指纹握手
    /// （Go `tls.UClient` 等价）；`None` 保持 hyper-rustls 路径零变化。
    ///
    /// ponytail: hyper-rustls 0.27.9 enable_http1+enable_http2 会把 alpn 设回
    /// `[h2, http/1.1]`（builder.rs:346），覆盖我们传入 `tls_settings.alpn` 的
    /// 用户偏好——splithttp Go 端空 alpn 默认亦此值，行为一致。
    #[must_use]
    pub fn new(
        config: Arc<Config>,
        tls_config: RustlsClientConfig,
        dial: DialTarget,
        fingerprint: Option<Fingerprint>,
        security_json: Option<serde_json::Value>,
    ) -> Self {
        // SNI 用 tlsSettings.serverName（Go WithDestination 等价：空回退 dest.host）。
        let sni = if dial.sni.is_empty() { dial.host.clone() } else { dial.sni };
        let connector = if let Some(fp) = fingerprint {
            // Go dial.go:138-145：fingerprint 配置时 tls.UClient。TCP 由
            // [`SplitConnector::Btls`] 恒拨 dest 后在 connector 内完成指纹握手。
            SplitConnector::Btls(BtlsDial {
                host: std::sync::Arc::from(dial.host.as_str()),
                port: dial.port,
                sni,
                config: Arc::new(tls_config),
                fingerprint: fp,
                security_json,
            })
        } else {
            let mut builder = HttpsConnectorBuilder::new()
                .with_tls_config(tls_config)
                .https_or_http();
            // 1) 锁定 TCP 拨号到 dest；忽略 URI authority（Go dialContext 语义）。
            let mut http = HttpConnector::new_with_resolver(DestResolver {
                host: std::sync::Arc::from(dial.host.as_str()),
                port: dial.port,
            });
            http.enforce_http(false);
            if let Ok(sn) = ServerName::try_from(sni) {
                builder = builder.with_server_name_resolver(FixedServerNameResolver::new(sn));
            }
            let https = builder.enable_http1().enable_http2().wrap_connector(http);
            SplitConnector::Rustls(https)
        };
        // （hyper-util 默认值，等价 Go http.Transport.IdleConnTimeout）。pool_timer
        // 必须配，否则 idle_timeout 不生效（hyper-util 已知坑）。
        let client = Client::builder(TokioExecutor::new())
            .pool_timer(TokioTimer::new())
            .pool_idle_timeout(Some(Duration::from_secs(90)))
            .build(connector);
        Self {
            config,
            client,
            closed: Arc::new(AtomicBool::new(false)),
        }
    }

    /// 连接是否已关闭。
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    /// 把 [`RequestMeta`] 转换为 `hyper::Request<ReqBody>`，body 用 `Full<Bytes>`。
    ///
    /// 合并多个 cookies 为单个 `Cookie:` header（HTTP/1.1+ 标准）。
    fn build_request(mut meta: RequestMeta) -> Result<Request<ReqBody>> {
        let body = match meta.body.take() {
            Some(b) => make_full_body(b),
            None => empty_body(),
        };
        Self::build_request_with_body(meta, body)
    }

    /// 从 `RequestMeta` + 任意 `ReqBody` 构造 hyper Request。
    ///
    /// [`Self::build_request`] 用 `Full<Bytes>` body 调用此函数；
    /// [`Self::open_stream_uploading`] 用 `StreamBody` body 调用此函数。
    pub(crate) fn build_request_with_body(meta: RequestMeta, body: ReqBody) -> Result<Request<ReqBody>> {
        let method = Method::from_bytes(meta.method.as_bytes())
            .map_err(|e| SplitHttpError::InvalidUrl(format!("method {e}")))?;
        let uri: Uri = meta
            .uri
            .parse()
            .map_err(|e| SplitHttpError::InvalidUrl(format!("uri {e}")))?;

        // h2/2 协议层禁止 Host 作为常规 header——它由 :authority 伪头承载。
        // hyper-util client.rs:300 会按 URI authority 自动补 Host，与 config.host
        // 拼成 `Host: sg-argo...` + `:authority: sg-argo...` 双发。CF argo 隧道
        // 实测对这种双发不响应（vs Go http2 在 wire 上剥 Host，仅发 :authority）。
        // ponytail: 显式去掉 Host header，让 wire 上只走 :authority，对齐 Go。
        let mut builder = Request::builder().method(method.clone()).uri(uri.clone());
        for (name, value) in meta.headers.iter() {
            if name.eq_ignore_ascii_case("Host") {
                continue;
            }
            builder = builder.header(name.as_str(), value.as_str());
        }
        if !meta.cookies.is_empty() {
            let cookie_str = meta
                .cookies
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; ");
            builder = builder.header("Cookie", cookie_str.as_str());
        }
        builder
            .body(body)
            .map_err(|e| SplitHttpError::InvalidUrl(format!("body {e}")))
    }

    /// 打开 stream（stream-down / 一次性 POST body）。
    ///
    /// - `body = None` → GET（stream-down，下载流）
    /// - `body = Some` → POST/PUT/etc.（一次性 body 上传，等响应）
    ///
    /// 返回 `(下载流, remote_addr, local_addr)`。
    ///
    /// **streaming body** 请用 [`Self::open_stream_uploading`]。
    ///
    /// GET 分支（`body = None`）**发出即返回**（lazy reader，对齐 Go gotConn+
    /// `WaitReadCloser` 语义）；`remote/local_addr` 仅 POST 分支可得 `HttpInfo`
    ///（GotConn 等价物），GET 分支恒为 `0.0.0.0:0` 占位（不致命，仅日志用）。
    ///
    /// # Errors
    /// - [`SplitHttpError::Hyper`]：拨号 / TLS / HTTP 协议错误（POST 分支同步报；
    ///   GET 分支读端以 EOF/`io::Error` 呈现）
    /// - [`SplitHttpError::BadStatus`]：非 200 响应（仅 POST 分支；GET 分支非 200
    ///   记日志 + 读端 EOF，对齐 Go `"unexpected status"` 分支）
    pub async fn open_stream(
        &self,
        base_uri: &str,
        session_id: &str,
        body: Option<Vec<u8>>,
    ) -> Result<(Box<dyn AsyncReadTrait + Send + Unpin>, SocketAddr, SocketAddr)> {
        let is_get = body.is_none();
        let meta = self
            .config
            .build_stream_request_meta(base_uri, session_id, body)?;
        let req = Self::build_request(meta)?;

        if is_get {
            // stream-down GET：发出即返回。server 端（Go 26.9.9 hub `SetFlushNext`）
            // 把 GET 响应头缓冲到首块下行数据，而下行数据依赖上传侧到达；
            // packet-up/stream-up 的 POST 上传任务在 GET 返回后才 spawn——旧实现
            // 同步 `request().await` 等响应头会环形死锁，dial 挂到外层超时。
            let reader = spawn_h2_lazy_reader(self.closed.clone(), self.client.clone(), req);
            let placeholder = SocketAddr::from(([0, 0, 0, 0], 0));
            return Ok((reader, placeholder, placeholder));
        }

        // body = Some（一次性 POST）：对齐 Go `PostPacket`，同步等响应。
        let resp = self.client.request(req).await.map_err(|e| {
            self.closed.store(true, Ordering::Relaxed);
            SplitHttpError::Hyper(e.to_string())
        })?;

        if resp.status() != StatusCode::OK {
            // 读 status 后丢弃 body（drain）
            let status = resp.status();
            #[allow(unused_must_use)]
            {
                resp.into_body().collect().await;
            }
            return Err(SplitHttpError::BadStatus(status.as_u16()));
        }

        let remote = resp
            .extensions()
            .get::<HttpInfo>()
            .map(HttpInfo::remote_addr)
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
        let local = resp
            .extensions()
            .get::<HttpInfo>()
            .map(HttpInfo::local_addr)
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));

        let stream = BodyDataStream::new(resp.into_body()).map_err(hyper_err_to_io);
        Ok((Box::new(StreamReader::new(stream)), remote, local))
    }

    /// 打开 streaming 上传流（stream-up / stream-one mode）。
    ///
    /// - `upload_only = true` → stream-up：POST streaming body 后不等响应（fire-and-forget 上传）。
    ///   配合独立的 GET 下载流（调用方另行 [`Self::open_stream`]`(body=None)` 拿下载流）。
    /// - `upload_only = false` → stream-one：POST streaming body 并等响应流（全双工）。
    ///
    /// 对应 Go `DefaultDialerClient.OpenStream(ctx, url, sessionId, body, uploadOnly)` 的 POST 分支。
    ///
    /// # Errors
    /// - [`SplitHttpError::Hyper`]：拨号 / TLS / HTTP 协议错误
    /// - [`SplitHttpError::BadStatus`]：非 200 响应（仅 `upload_only=false` 时检查）
    pub async fn open_stream_uploading<S>(
        &self,
        base_uri: &str,
        session_id: &str,
        body_stream: S,
        upload_only: bool,
    ) -> Result<(
        Option<BodyDataStream<hyper::body::Incoming>>,
        SocketAddr,
        SocketAddr,
    )>
    where
        S: Stream<Item = std::io::Result<Bytes>> + Send + Sync + 'static,
    {
        // 1. 构造 RequestMeta（body 用空 Vec 占位走 POST 分支，实际 body 由 StreamBody 提供）
        let mut meta = self
            .config
            .build_stream_request_meta(base_uri, session_id, Some(Vec::new()))?;
        // body 不在 RequestMeta，清空（避免 Vec 与 BoxBody 语义混淆）
        meta.body = None;

        // H7：padding 注入只在 build_stream_request_meta 内做一次（Go config.go:323-350
        // FillStreamRequest 单次 ApplyXPaddingToRequest）。此前这里再次 apply，
        // append 语义导致 wire 上双 Referer / 双 query x_padding。

        // 2. 构造 hyper Request，body 用 StreamBody
        let streaming_body = make_stream_body(body_stream);
        let req = Self::build_request_with_body(meta, streaming_body)?;

        // 3. 发送请求
        let resp = self.client.request(req).await.map_err(|e| {
            self.closed.store(true, Ordering::Relaxed);
            SplitHttpError::Hyper(e.to_string())
        })?;

        let remote = resp
            .extensions()
            .get::<HttpInfo>()
            .map(HttpInfo::remote_addr)
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
        let local = resp
            .extensions()
            .get::<HttpInfo>()
            .map(HttpInfo::local_addr)
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));

        if upload_only {
            // stream-up：drain body，返回 None
            #[allow(unused_must_use)]
            {
                resp.into_body().collect().await;
            }
            Ok((None, remote, local))
        } else {
            // stream-one：检查 200 + 返回 body stream
            if resp.status() != StatusCode::OK {
                let status = resp.status();
                #[allow(unused_must_use)]
                {
                    resp.into_body().collect().await;
                }
                return Err(SplitHttpError::BadStatus(status.as_u16()));
            }
            Ok((Some(BodyDataStream::new(resp.into_body())), remote, local))
        }
    }

    /// 发送单个上传分包（packet-up mode）。
    ///
    /// 构造 POST 请求（method 由 [`Config::normalized_uplink_http_method`] 决定），
    /// 等待 200 OK 后返回。body 完整发送（非 streaming）。
    ///
    /// GOAWAY / 连接级错误后重放一次（Go dffc7ada：packet-up 请求定义
    /// `Request.GetBody` 使 h2 可重放）。body 是内存 `Vec<u8>`，请求天然可重产
    /// （`meta.clone()` + 重新 `build_request` = Go `GetBody` 新 reader），重放仅限
    /// 连接级失败（`is_closed`/`is_incomplete_message`），HTTP 层错误（非 200）
    /// 不重放——与 Go `shouldRetryRequest`+`canRetryError`（x/net http2
    /// transport_common.go:328-368）同界。hyper-util 已内置重试"复用连接上未启动
    /// 即被取消"的请求（legacy client.rs:252-269，`retry_canceled_requests` 默认
    /// 开）；此处补的是它不覆盖的窗口：新连接拨出后 / 响应头到达前连接死亡。
    /// REFUSED_STREAM 重放（Go canRetryError StreamError 分支）未做：hyper
    /// `h2_reason` 为 `pub(super)` 不可达，且 splithttp server 侧不产生该错误。
    ///
    /// # Errors
    /// - [`SplitHttpError::Hyper`]：拨号 / TLS / HTTP 协议错误（重放后再失败）
    /// - [`SplitHttpError::BadStatus`]：非 200 响应
    pub async fn post_packet(
        &self,
        base_uri: &str,
        session_id: &str,
        seq_str: &str,
        payload: Vec<u8>,
    ) -> Result<()> {
        let meta = self
            .config
            .build_packet_request_meta(base_uri, session_id, seq_str, payload)?;
        match self.client.request(Self::build_request(meta.clone())?).await {
            Ok(resp) => return Self::post_packet_finish(resp).await,
            Err(e) if is_packet_replayable(&e) => {
                debug!(target: "splithttp", error = %e, seq = seq_str, "packet-up request failed on connection level, replaying once (GetBody)");
            }
            Err(e) => {
                self.closed.store(true, Ordering::Relaxed);
                return Err(SplitHttpError::Hyper(e.to_string()));
            }
        }
        match self.client.request(Self::build_request(meta)?).await {
            Ok(resp) => Self::post_packet_finish(resp).await,
            Err(e) => {
                self.closed.store(true, Ordering::Relaxed);
                Err(SplitHttpError::Hyper(e.to_string()))
            }
        }
    }

    /// packet-up 响应收尾：drain body + 200 校验。
    async fn post_packet_finish(
        resp: http::Response<hyper::body::Incoming>,
    ) -> Result<()> {
        let status = resp.status();
        // drain body（hyper-util 要求消费 body 释放连接回 pool）
        #[allow(unused_must_use)]
        {
            resp.into_body().collect().await;
        }

        if status != StatusCode::OK {
            return Err(SplitHttpError::BadStatus(status.as_u16()));
        }
        Ok(())
    }
}

/// `hyper::Error` → `std::io::Error`（h2 body 流转发用）。
pub(crate) fn hyper_err_to_io(e: hyper::Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
}

/// packet-up 重放资格判定（Go `canRetryError`，x/net http2 transport_common.go:
/// 360-368）。legacy Client 的错误把 `hyper::Error` 挂在 `source()` 链上：
/// - hyper `is_closed`：连接在请求派发前死亡 / pool 关闭（≈ `errClientConnUnusable`）
/// - hyper `is_incomplete_message`：响应头到达前连接断（GOAWAY 后断连的表现）
/// - h2 cause `is_go_away`：GOAWAY 收到且本流未处理（≈ `errClientConnGotGoAway`）
/// - h2 cause `is_reset` + `REFUSED_STREAM`：服务端明示未处理（Go StreamError 分支）
///
/// 拨号/TLS 失败（`is_connect`）与 HTTP 语义错误（非 200 / body 错误）一律不
/// 重放——packet-up 每包一条 UDP 报文，非"确定未被处理"的失败重放会双投。
fn is_packet_replayable(e: &hyper_util::client::legacy::Error) -> bool {
    if e.is_connect() {
        return false;
    }
    let mut src: Option<&(dyn std::error::Error + 'static)> = Some(e);
    while let Some(s) = src {
        if let Some(he) = s.downcast_ref::<hyper::Error>() {
            if he.is_closed() || he.is_incomplete_message() {
                return true;
            }
            let mut hsrc: Option<&(dyn std::error::Error + 'static)> = Some(he);
            while let Some(hs) = hsrc {
                if let Some(h2e) = hs.downcast_ref::<h2::Error>() {
                    if h2e.is_reset() {
                        return h2e.reason() == Some(h2::Reason::REFUSED_STREAM);
                    }
                    return h2e.is_go_away();
                }
                hsrc = hs.source();
            }
        }
        src = s.source();
    }
    false
}

/// stream-down GET 的 lazy 读端（对齐 Go `WaitReadCloser` 语义，与 h3
/// `spawn_h3_lazy_reader` 同构）。
///
/// dial 调用方不被响应头阻塞：spawn 的后台任务持有响应 future——200 则把 body
/// 块转发进 channel；非 200 仅记日志并结束（读端 EOF，对齐 Go `"unexpected
/// status"` 分支）；请求错误则 `closed` 置位 + EOF。
fn spawn_h2_lazy_reader(
    closed: Arc<AtomicBool>,
    mut client: HyperClient,
    req: Request<ReqBody>,
) -> Box<dyn AsyncReadTrait + Send + Unpin> {
    let (tx, rx) = mpsc::channel::<std::io::Result<Bytes>>(8);
    tokio::spawn(async move {
        match client.request(req).await {
            Ok(resp) if resp.status() == StatusCode::OK => {
                let mut chunks = BodyDataStream::new(resp.into_body()).map_err(hyper_err_to_io);
                loop {
                    match chunks.try_next().await {
                        Ok(Some(chunk)) => {
                            if tx.send(Ok(chunk)).await.is_err() {
                                return; // 接收端 drop，结束
                            }
                        }
                        Ok(None) => return,
                        Err(e) => {
                            let _ = tx.send(Err(e)).await;
                            return;
                        }
                    }
                }
            }
            Ok(resp) => {
                debug!(target: "splithttp", status = %resp.status(), "unexpected GET status");
            }
            Err(e) => {
                closed.store(true, Ordering::Relaxed);
                debug!(target: "splithttp", error = %e, "GET request failed");
            }
        }
    });
    Box::new(StreamReader::new(ReceiverStream::new(rx)))
}

#[cfg(test)]
mod tests {
    // 单元测试见 tests/mock_server.rs（mock HTTP server 端到端验证）。
    // 这里仅放与 hyper-util 配置相关的轻量断言。

    use super::*;

    #[test]
    fn build_request_basic_get() {
        let meta = RequestMeta {
            method: "GET".into(),
            uri: "https://example.com/ws/sess".into(),
            headers: vec![("User-Agent".into(), "test".into())],
            cookies: vec![],
            body: None,
        };
        let req = DefaultDialerClient::build_request(meta).unwrap();
        assert_eq!(req.method(), Method::GET);
        assert_eq!(req.uri().path(), "/ws/sess");
        assert_eq!(req.headers().get("user-agent").unwrap(), "test");
    }

    #[test]
    fn build_request_post_with_body_and_cookies() {
        let meta = RequestMeta {
            method: "POST".into(),
            uri: "https://example.com/ws/sess/0".into(),
            headers: vec![],
            cookies: vec![("k1".into(), "v1".into()), ("k2".into(), "v2".into())],
            body: Some(b"payload".to_vec()),
        };
        let req = DefaultDialerClient::build_request(meta).unwrap();
        assert_eq!(req.method(), Method::POST);
        // 多 cookie 合并为单个 Cookie header
        assert_eq!(req.headers().get("cookie").unwrap(), "k1=v1; k2=v2");
    }

    #[test]
    fn build_request_invalid_method_rejected() {
        let meta = RequestMeta {
            method: "BAD METHOD".into(),
            uri: "https://example.com/".into(),
            headers: vec![],
            cookies: vec![],
            body: None,
        };
        let err = DefaultDialerClient::build_request(meta).unwrap_err();
        assert!(matches!(err, SplitHttpError::InvalidUrl(_)));
    }

    #[test]
    fn make_full_body_and_empty_body_compile() {
        // 编译时验证：Full + BoxBody 类型转换正确
        let _b1: ReqBody = make_full_body(b"hello".to_vec());
        let _b2: ReqBody = empty_body();
    }

    #[test]
    fn make_stream_body_accepts_bytes_stream() {
        use futures_util::stream;
        let s = stream::iter(vec![Ok(Bytes::from_static(b"a")), Ok(Bytes::from_static(b"b"))]);
        let _b: ReqBody = make_stream_body(s);
    }
    // ── dffc7ada：packet-up GetBody 重放（mock h2+TLS，断言重放调用）──

    fn self_signed_cert() -> (rustls_pki_types::CertificateDer<'static>, rustls_pki_types::PrivateKeyDer<'static>) {
        let params =
            rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()]).expect("rcgen params");
        let key_pair = rcgen::KeyPair::generate().expect("rcgen keypair");
        let cert = params.self_signed(&key_pair).expect("rcgen self_signed");
        (
            rustls_pki_types::CertificateDer::from(cert.der().to_vec()),
            rustls_pki_types::PrivateKeyDer::Pkcs8(key_pair.serialize_der().into()),
        )
    }

    fn server_tls(
        cert: rustls_pki_types::CertificateDer<'static>,
        key: rustls_pki_types::PrivateKeyDer<'static>,
    ) -> rustls::ServerConfig {
        let mut cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .expect("server cert");
        cfg.alpn_protocols = vec![b"h2".to_vec()];
        cfg
    }

    fn client_tls(cert: rustls_pki_types::CertificateDer<'static>) -> RustlsClientConfig {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert).expect("add cert");
        RustlsClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    }

    /// 响应收尾：驱动连接把帧刷出。直接 drop Connection 会未 flush 即断 TLS，
    /// 客户端只见 EOF（hyper UnexpectedEof）而收不到任何帧。
    async fn drain_h2_conn(
        conn: &mut h2::server::Connection<
            tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
            bytes::Bytes,
        >,
    ) {
        let _ =
            tokio::time::timeout(std::time::Duration::from_millis(300), conn.accept()).await;
    }

    /// h2 mock：等请求到达后显式回 REFUSED_STREAM（Go `canRetryError`
    /// StreamError 分支——服务端明示"本流未处理"，唯一可重放的流级错误）。
    async fn mock_h2_refused(
        listener: &tokio::net::TcpListener,
        tls: std::sync::Arc<tokio_rustls::TlsAcceptor>,
    ) {
        let (tcp, _) = listener.accept().await.expect("mock conn1 accept");
        let tls_stream = tls.accept(tcp).await.expect("mock tls accept");
        let mut conn = h2::server::handshake(tls_stream).await.expect("mock h2 handshake");
        if let Some(Ok((_req, mut respond))) = conn.accept().await {
            respond.send_reset(h2::Reason::REFUSED_STREAM);
            drain_h2_conn(&mut conn).await;
        }
    }

    /// h2 mock：200 空响应（重放目标连接）。
    async fn mock_h2_ok(
        listener: &tokio::net::TcpListener,
        tls: std::sync::Arc<tokio_rustls::TlsAcceptor>,
    ) {
        let (tcp, _) = listener.accept().await.expect("mock conn2 accept");
        let tls_stream = tls.accept(tcp).await.expect("mock tls accept");
        let mut conn = h2::server::handshake(tls_stream).await.expect("mock h2 handshake");
        if let Some(Ok((_req, mut respond))) = conn.accept().await {
            let resp = http::Response::builder()
                .status(StatusCode::OK)
                .body(())
                .unwrap();
            let _ = respond.send_response(resp, true);
            drain_h2_conn(&mut conn).await;
        }
    }

    // Windows loopback 上 h2 crate 偶发在 RST 帧刷出前断连（客户端见 EOF 而非
    // REFUSED_STREAM——EOF 按 Go canRetryError 语义不可重放，实现正确、mock 有
    // 竞态），Windows 上忽略防红灯；503 对照测试锁定"HTTP 错误不重放"，重放
    // 资格判定 is_packet_replayable 与 Go shouldRetryRequest 逐分支对齐（见其
    // 文档）。iq1o⑨：ignore 收窄为 Windows-only——Linux/macOS 激活正向重放
    // 回归守卫。
    #[cfg_attr(windows, ignore = "mock RST flush race on Windows loopback; predicate + no-replay control covered by post_packet_http_error_does_not_replay")]
    #[tokio::test]
    async fn post_packet_replays_after_h2_stream_error() {
        // workspace feature unification 可能双 CryptoProvider 并存，
        // rustls 进程级自动裁决 panic；显式安装（幂等容忍重复）。
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let (cert, key) = self_signed_cert();
        let tls = std::sync::Arc::new(tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(
            server_tls(cert.clone(), key),
        )));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        // 同一 listener 串行 accept：conn 1 = REFUSED_STREAM（可重放流错误），
        // conn 2 = 重放命中（200）。
        let l = listener;
        let tls2 = std::sync::Arc::clone(&tls);
        let server = tokio::spawn(async move {
            mock_h2_refused(&l, tls2).await;
            mock_h2_ok(&l, tls).await;
        });

        let config = Arc::new(Config::default());
        let c = std::sync::Arc::new(DefaultDialerClient::new(
            config,
            client_tls(cert),
            DialTarget { host: "127.0.0.1".into(), port, sni: "127.0.0.1".into() },
            None,
            None,
        ));

        let base = format!("https://127.0.0.1:{port}/");
        let cc = std::sync::Arc::clone(&c);
        let pp = tokio::spawn(async move {
            cc.post_packet(&base, "sess", "0", b"hello xray".to_vec()).await
        });

        let result = tokio::time::timeout(std::time::Duration::from_secs(10), pp)
            .await
            .expect("post_packet must not hang")
            .expect("join");
        assert!(result.is_ok(), "REFUSED_STREAM 后重放的 post_packet 必须成功: {result:?}");
        server.await.expect("mock server");
        assert!(!c.closed.load(Ordering::Relaxed), "重放成功后 closed 不得置位");
    }

    #[tokio::test]
    async fn post_packet_http_error_does_not_replay() {
        // 非 200 是 HTTP 语义错误：不重放（服务端只被连一次）。
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let (cert, key) = self_signed_cert();
        let tls = std::sync::Arc::new(tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(
            server_tls(cert.clone(), key),
        )));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let tls2 = std::sync::Arc::clone(&tls);
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("accept");
            let tls_stream = tls2.accept(tcp).await.expect("tls accept");
            let mut conn = h2::server::handshake(tls_stream).await.expect("handshake");
            if let Some(Ok((_req, mut respond))) = conn.accept().await {
                let resp = http::Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .body(())
                    .unwrap();
                let _ = respond.send_response(resp, true);
                let _ = tokio::time::timeout(
                    std::time::Duration::from_millis(300),
                    conn.accept(),
                ).await;
            }
        });

        let config = Arc::new(Config::default());
        let c = DefaultDialerClient::new(
            config,
            client_tls(cert),
            DialTarget { host: "127.0.0.1".into(), port, sni: "127.0.0.1".into() },
            None,
            None,
        );

        let base = format!("https://127.0.0.1:{port}/");
        let err = c.post_packet(&base, "sess", "0", b"x".to_vec()).await;
        assert!(matches!(err, Err(SplitHttpError::BadStatus(503))), "{err:?}");
        server.await.expect("mock server");
    }
}
