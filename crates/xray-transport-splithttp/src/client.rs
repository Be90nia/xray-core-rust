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
//! - `WaitReadCloser` 异步等待机制（Go 用来同步 GotConn 与响应到达）→ ponytail
//!   简化：直接 await response（hyper 已内部处理）
//! - `browser_dialer` 路径 → 切片 b7f 独立任务
//! - HTTP/3 / QUIC → 切片 G（可选）
//! - xmux 多路复用 → 切片 E

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures_util::{Stream, TryStreamExt};
use http::request::Request;
use http::{Method, StatusCode, Uri};
use hyper::body::Frame;
use http_body_util::{BodyDataStream, BodyExt, Full, StreamBody};
use http_body_util::combinators::BoxBody;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::connect::{HttpConnector, HttpInfo};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use rustls::ClientConfig as RustlsClientConfig;

use crate::config::{Config, RequestMeta};
use crate::error::{Result, SplitHttpError};
use crate::xpadding::apply_xpadding_to_request_meta;

/// 统一 hyper 请求 body 类型（允许 `Full<Bytes>` 和 `StreamBody` 都能发送）。
///
/// error 类型用 `std::io::Error`（`StreamBody` 的错误类型）；`Full<Bytes>` 的
/// error 是 `Infallible`，通过 `map_err` 闭包转换（match infallible {} unreachable）。
pub type ReqBody = BoxBody<Bytes, std::io::Error>;

/// hyper-util legacy Client 类型别名。
///
/// packet-up 用 `Full<Bytes>`（一次性 body）；stream-up/stream-one 用 `StreamBody`
///（流式上传）。两者都 box 成 [`ReqBody`]。
pub type HyperClient = Client<HttpsConnector<HttpConnector>, ReqBody>;

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
fn make_stream_body<S>(s: S) -> ReqBody
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
    closed: AtomicBool,
}

impl DefaultDialerClient {
    /// 创建新客户端。`tls_config` 由调用方（[`crate::dialer`]）从 `stream_settings`
    /// 构造，简化为 webpki-roots + ring provider 默认（切片 F 接入 REALITY 时改）。
    #[must_use]
    pub fn new(config: Arc<Config>, tls_config: RustlsClientConfig) -> Self {
        let https = HttpsConnectorBuilder::new()
            .with_tls_config(tls_config)
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();
        // ponytail: 默认 pool_idle_timeout=90s + pool_max_idle_per_host=usize::MAX
        // （hyper-util 默认值，等价 Go http.Transport.IdleConnTimeout）。pool_timer
        // 必须配，否则 idle_timeout 不生效（hyper-util 已知坑）。
        let client = Client::builder(TokioExecutor::new())
            .pool_timer(TokioTimer::new())
            .pool_idle_timeout(Some(Duration::from_secs(90)))
            .build(https);
        Self {
            config,
            client,
            closed: AtomicBool::new(false),
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
    fn build_request_with_body(meta: RequestMeta, body: ReqBody) -> Result<Request<ReqBody>> {
        let method = Method::from_bytes(meta.method.as_bytes())
            .map_err(|e| SplitHttpError::InvalidUrl(format!("method {e}")))?;
        let uri: Uri = meta
            .uri
            .parse()
            .map_err(|e| SplitHttpError::InvalidUrl(format!("uri {e}")))?;

        let mut builder = Request::builder().method(method).uri(uri);
        for (name, value) in meta.headers {
            builder = builder.header(name, value);
        }
        if !meta.cookies.is_empty() {
            let cookie_str = meta
                .cookies
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; ");
            builder = builder.header("Cookie", cookie_str);
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
    /// 返回 `(下载流, remote_addr, local_addr)`。`remote/local_addr` 来自 hyper-util
    /// [`HttpInfo`]（GotConn 等价物），获取失败返回 `0.0.0.0:0` 占位（不致命，仅日志用）。
    ///
    /// **streaming body** 请用 [`Self::open_stream_uploading`]。
    ///
    /// # Errors
    /// - [`SplitHttpError::Hyper`]：拨号 / TLS / HTTP 协议错误
    /// - [`SplitHttpError::BadStatus`]：非 200 响应
    pub async fn open_stream(
        &self,
        base_uri: &str,
        session_id: &str,
        body: Option<Vec<u8>>,
    ) -> Result<(BodyDataStream<hyper::body::Incoming>, SocketAddr, SocketAddr)> {
        let meta = self
            .config
            .build_stream_request_meta(base_uri, session_id, body)?;
        let req = Self::build_request(meta)?;
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

        let stream = BodyDataStream::new(resp.into_body());
        Ok((stream, remote, local))
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

        // 注入 XPadding
        let xpad = self.config.build_xpadding_config(base_uri);
        apply_xpadding_to_request_meta(&mut meta, &xpad);

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
    /// # Errors
    /// - [`SplitHttpError::Hyper`]：拨号 / TLS / HTTP 协议错误
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
        let req = Self::build_request(meta)?;
        let resp = self.client.request(req).await.map_err(|e| {
            self.closed.store(true, Ordering::Relaxed);
            SplitHttpError::Hyper(e.to_string())
        })?;

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
}
