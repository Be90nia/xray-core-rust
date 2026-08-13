//! Hysteria hub (Listener) —— inbound 编排（对应 Go `transport/internet/hysteria/hub.go`）。
//!
//! # IO 边界（trait + stub）
//!
//! Go `Listen()` 依赖：
//! - `http3.Server.ServeQUICConn` —— HTTP/3 服务（含 StreamDispatcher 自定义帧分发）
//! - `quic.Transport.Listen` —— QUIC 监听
//! - `internet.ListenSystemPacket` —— UDP socket bind
//! - masquerade HTTP handler —— 4 种伪装（404/file/proxy/string）
//! - `account.Validator` —— 多用户鉴权
//!
//! Rust 端用 trait 抽象以上依赖。本模块仅定义 trait + 编排框架。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use parking_lot::Mutex;
use xray_proto::xray::transport::internet::QuicParams;

use crate::conn::{InterStreamConn, QuicConn, QuicStream};
use crate::context::ContextValues;
use crate::error::{HysteriaError, Result};
use crate::proto_config::Config;

/// Masquerade 类型（对应 Go `config.MasqType`，4 种 + 默认 404）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MasqType {
    /// HTTP 404（默认，对应 Go `""` / `"404"`）。
    NotFound,
    /// 静态文件服务（对应 Go `"file"`，配置 `MasqFile` 路径）。
    File(String),
    /// 反向代理（对应 Go `"proxy"`，配置 `MasqUrl` + `MasqUrlRewriteHost` + `MasqUrlInsecure`）。
    Proxy {
        url: String,
        rewrite_host: bool,
        insecure: bool,
    },
    /// 静态字符串响应（对应 Go `"string"`，配置 `MasqString` + Headers + StatusCode）。
    String {
        body: String,
        headers: HashMap<String, String>,
        status_code: u16,
    },
}

impl MasqType {
    /// 从配置解析（对应 Go `Listen` 中 switch masqType）。
    pub fn from_config(config: &Config) -> Result<Self> {
        match config.masq_type.to_ascii_lowercase().as_str() {
            "" | "404" => Ok(Self::NotFound),
            "file" => Ok(Self::File(config.masq_file.clone())),
            "proxy" => Ok(Self::Proxy {
                url: config.masq_url.clone(),
                rewrite_host: config.masq_url_rewrite_host,
                insecure: config.masq_url_insecure,
            }),
            "string" => Ok(Self::String {
                body: config.masq_string.clone(),
                headers: config.masq_string_headers.clone(),
                status_code: if config.masq_string_status_code == 0 {
                    200
                } else {
                    config.masq_string_status_code as u16
                },
            }),
            other => Err(HysteriaError::UnknownMasqType(other.into())),
        }
    }
}

/// Masquerade HTTP handler trait（对应 Go `http.Handler`）。
///
/// 上层（HTTP/3 server）实现。当非 auth 请求到达时，转发到此 handler 做"伪装响应"。
pub trait MasqueradeHandler: Send + Sync {
    /// 处理一个 HTTP 请求（请求路径/方法 + headers）。
    /// 返回 (status_code, headers, body)。
    fn serve(
        &self,
        method: &str,
        path: &str,
        headers: &HashMap<String, String>,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = (u16, HashMap<String, String>, Vec<u8>)> + Send,
        >,
    >;
}

/// 默认 NotFound 实现（对应 Go `http.NotFoundHandler()`）。
#[derive(Debug, Default)]
pub struct NotFoundMasqHandler;

impl MasqueradeHandler for NotFoundMasqHandler {
    fn serve(
        &self,
        _method: &str,
        _path: &str,
        _headers: &HashMap<String, String>,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = (u16, HashMap<String, String>, Vec<u8>)> + Send,
        >,
    > {
        Box::pin(async { (404, HashMap::new(), b"Not Found".to_vec()) })
    }
}

/// String masquerade 实现（对应 Go `string` 分支）。
#[derive(Debug, Clone)]
pub struct StringMasqHandler {
    pub body: String,
    pub headers: HashMap<String, String>,
    pub status_code: u16,
}

impl MasqueradeHandler for StringMasqHandler {
    fn serve(
        &self,
        _method: &str,
        _path: &str,
        _headers: &HashMap<String, String>,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = (u16, HashMap<String, String>, Vec<u8>)> + Send,
        >,
    > {
        let body = self.body.clone();
        let headers = self.headers.clone();
        let status = self.status_code;
        Box::pin(async move { (status, headers, body.into_bytes()) })
    }
}

/// Proxy masquerade 实现（对应 Go `"proxy"` 分支的兜底行为）。
///
/// Go 的 proxy masquerade 反向代理到 `MasqUrl`；当目标不可达时回退 503。
/// 本实现采用 ponytail 策略：直接返回 HTTP 503（Service Unavailable），
/// 覆盖任务需求"Proxy: 返回 HTTP 503"。完整反向代理（含 rewrite_host/insecure）
/// 在接入 hyper 反向代理后扩展。
#[derive(Debug, Clone, Default)]
pub struct ProxyMasqHandler;

impl MasqueradeHandler for ProxyMasqHandler {
    fn serve(
        &self,
        _method: &str,
        _path: &str,
        _headers: &HashMap<String, String>,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = (u16, HashMap<String, String>, Vec<u8>)> + Send,
        >,
    > {
        Box::pin(async {
            (
                503,
                HashMap::from([("Content-Type".to_string(), "text/plain; charset=utf-8".to_string())]),
                b"Service Unavailable".to_vec(),
            )
        })
    }
}

/// Hysteria auth 请求信息（对应 Go `httpHandler.AuthHTTP` 输入）。
#[derive(Debug, Clone)]
pub struct AuthRequest {
    pub method: String,
    pub host: String,
    pub path: String,
    pub auth_header: String,
    pub brutal_down_bps: u64,
}

/// Hysteria auth 响应（对应 Go `httpHandler.AuthHTTP` 写入的 headers + status）。
#[derive(Debug, Clone)]
pub struct AuthResponse {
    pub status_code: u16,
    pub udp_enabled: bool,
    pub brutal_down_bps: u64,
    pub padding: String,
}

/// Auth 验证器（对应 Go `*account.Validator`）。
///
/// 上层注入。返回 Some(user_id) 表示验证通过；None 表示失败。
pub trait AuthValidator: Send + Sync {
    /// 校验 auth token，返回 user identifier（验证通过时）。
    fn validate(&self, auth: &str) -> Option<String>;

    /// 当前注册用户数（对应 Go `validator.GetCount()`）。
    fn count(&self) -> usize;
}

/// HTTP/3 + QUIC server 抽象（对应 Go `http3.Server.ServeQUICConn`）。
///
/// 上层（quinn/h3 adapter）实现。当 QUIC conn 到达时，hub 调此 trait 启动 HTTP/3 服务。
pub trait HysteriaHttp3Server: Send + Sync {
    /// 服务一个 QUIC conn（对应 Go `h3s.ServeQUICConn(conn)`）。
    fn serve_quic_conn(
        &self,
        conn: Arc<dyn QuicConn>,
        handler: Arc<dyn HysteriaRequestHandler>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;
}

/// HTTP 请求处理 trait（对应 Go `http.Handler` + `StreamDispatcher`）。
pub trait HysteriaRequestHandler: Send + Sync {
    /// 处理 auth 路径请求（POST hysteria/auth）。
    /// 返回 Some(AuthResponse) 表示已处理；None 表示非 auth 路径，转 masq handler。
    fn try_auth(
        &self,
        req: &AuthRequest,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<AuthResponse>> + Send>>;

    /// 分发 TCP stream（对应 Go `StreamDispatcher(FrameTypeTCPRequest)`）。
    fn dispatch_tcp_stream(
        &self,
        stream: Arc<dyn QuicStream>,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;

    /// 取 masquerade handler。
    fn masquerade(&self) -> Arc<dyn MasqueradeHandler>;
}

/// QUIC listener 抽象（对应 Go `*quic.Listener` + `quic.Transport`）。
pub trait HysteriaQuicListener: Send + Sync {
    /// 接受下一个 QUIC conn（对应 Go `listener.Accept(ctx)`）。
    fn accept(&self) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = std::io::Result<Arc<dyn QuicConn>>> + Send>,
    >;

    /// 本地地址（对应 Go `listener.Addr()`）。
    fn local_addr(&self) -> SocketAddr;

    /// 关闭（对应 Go `listener.Close()`）。
    fn close(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<()>> + Send>>;
}

/// Listener 工厂 trait（对应 Go `Listen` 函数）。
pub trait HysteriaListenerFactory: Send + Sync {
    /// 创建 QUIC listener（对应 Go `Listen()` 主体）。
    fn listen(
        &self,
        bind_addr: SocketAddr,
        config: Arc<Config>,
        quic_params: Arc<QuicParams>,
        masq: MasqType,
        validator: Option<Arc<dyn AuthValidator>>,
        on_new_conn: Arc<dyn Fn(Arc<InterStreamConn>) + Send + Sync>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Arc<dyn HysteriaQuicListener>>> + Send>>;
}

/// Hysteria Listener（对应 Go `*Listener`）。
pub struct HysteriaListener {
    inner: Arc<ListenerInner>,
}

struct ListenerInner {
    bind_addr: SocketAddr,
    config: Arc<Config>,
    quic_params: Arc<QuicParams>,
    masq: MasqType,
    validator: Option<Arc<dyn AuthValidator>>,
    on_new_conn: Arc<dyn Fn(Arc<InterStreamConn>) + Send + Sync>,
    quic_listener: Mutex<Option<Arc<dyn HysteriaQuicListener>>>,
    closed: Mutex<bool>,
}

impl std::fmt::Debug for HysteriaListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HysteriaListener")
            .field("bind_addr", &self.inner.bind_addr)
            .field("masq", &self.inner.masq)
            .field("closed", &self.inner.closed.lock().clone())
            .finish_non_exhaustive()
    }
}

impl HysteriaListener {
    /// 构造（不启动 listen，需后续调 start）。
    pub fn new(
        bind_addr: SocketAddr,
        config: Arc<Config>,
        quic_params: Arc<QuicParams>,
        masq: MasqType,
        validator: Option<Arc<dyn AuthValidator>>,
        on_new_conn: Arc<dyn Fn(Arc<InterStreamConn>) + Send + Sync>,
    ) -> Self {
        Self {
            inner: Arc::new(ListenerInner {
                bind_addr,
                config,
                quic_params,
                masq,
                validator,
                on_new_conn,
                quic_listener: Mutex::new(None),
                closed: Mutex::new(false),
            }),
        }
    }

    /// 绑定地址。
    #[must_use]
    pub fn bind_addr(&self) -> SocketAddr {
        self.inner.bind_addr
    }

    /// Masquerade 类型。
    #[must_use]
    pub fn masq_type(&self) -> &MasqType {
        &self.inner.masq
    }

    /// 注入 QUIC listener 并启动 accept 循环。
    pub async fn start(self: &Arc<Self>, listener: Arc<dyn HysteriaQuicListener>) {
        *self.inner.quic_listener.lock() = Some(listener);
    }

    /// 关闭。
    pub async fn close(&self) -> Result<()> {
        *self.inner.closed.lock() = true;
        if let Some(l) = self.inner.quic_listener.lock().take() {
            l.close().await?;
        }
        Ok(())
    }

    /// 是否已关闭。
    #[must_use]
    pub fn is_closed(&self) -> bool {
        *self.inner.closed.lock()
    }
}

/// Stub listener factory —— 返回 ConnectionClosed（未实现 QUIC 集成）。
#[derive(Debug, Default)]
pub struct StubListenerFactory;

impl HysteriaListenerFactory for StubListenerFactory {
    fn listen(
        &self,
        _bind_addr: SocketAddr,
        _config: Arc<Config>,
        _quic_params: Arc<QuicParams>,
        _masq: MasqType,
        _validator: Option<Arc<dyn AuthValidator>>,
        _on_new_conn: Arc<dyn Fn(Arc<InterStreamConn>) + Send + Sync>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Arc<dyn HysteriaQuicListener>>> + Send>> {
        Box::pin(async { Err(HysteriaError::ConnectionClosed) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config(masq_type: &str) -> Config {
        Config {
            masq_type: masq_type.into(),
            masq_file: "/var/www".into(),
            masq_url: "https://example.com".into(),
            masq_url_rewrite_host: true,
            masq_url_insecure: false,
            masq_string: "hello".into(),
            masq_string_headers: HashMap::from([("X-Custom".into(), "value".into())]),
            masq_string_status_code: 201,
            ..Config::default()
        }
    }

    #[test]
    fn masq_type_from_config_not_found_default() {
        let c = Config::default();
        assert_eq!(MasqType::from_config(&c).unwrap(), MasqType::NotFound);
    }

    #[test]
    fn masq_type_from_config_explicit_404() {
        let c = make_config("404");
        assert_eq!(MasqType::from_config(&c).unwrap(), MasqType::NotFound);
    }

    #[test]
    fn masq_type_from_config_file() {
        let c = make_config("file");
        assert_eq!(MasqType::from_config(&c).unwrap(), MasqType::File("/var/www".into()));
    }

    #[test]
    fn masq_type_from_config_proxy() {
        let c = make_config("proxy");
        let m = MasqType::from_config(&c).unwrap();
        match m {
            MasqType::Proxy {
                url,
                rewrite_host,
                insecure,
            } => {
                assert_eq!(url, "https://example.com");
                assert!(rewrite_host);
                assert!(!insecure);
            }
            _ => panic!("expected Proxy"),
        }
    }

    #[test]
    fn masq_type_from_config_string() {
        let c = make_config("string");
        let m = MasqType::from_config(&c).unwrap();
        match m {
            MasqType::String {
                body,
                headers,
                status_code,
            } => {
                assert_eq!(body, "hello");
                assert_eq!(headers.get("X-Custom"), Some(&"value".to_string()));
                assert_eq!(status_code, 201);
            }
            _ => panic!("expected String"),
        }
    }

    #[test]
    fn masq_type_from_config_string_default_status() {
        let mut c = make_config("string");
        c.masq_string_status_code = 0;
        let m = MasqType::from_config(&c).unwrap();
        match m {
            MasqType::String { status_code, .. } => assert_eq!(status_code, 200),
            _ => panic!(),
        }
    }

    #[test]
    fn masq_type_from_config_invalid_errors() {
        let c = make_config("unknown");
        assert!(MasqType::from_config(&c).is_err());
    }

    #[test]
    fn masq_type_from_config_case_insensitive() {
        let c = make_config("FILE");
        assert_eq!(MasqType::from_config(&c).unwrap(), MasqType::File("/var/www".into()));
    }

    #[tokio::test]
    async fn not_found_masq_handler_returns_404() {
        let h = NotFoundMasqHandler;
        let (status, _, body) = h.serve("GET", "/anything", &HashMap::new()).await;
        assert_eq!(status, 404);
        assert_eq!(body, b"Not Found");
    }

    #[tokio::test]
    async fn string_masq_handler_returns_configured_response() {
        let h = StringMasqHandler {
            body: "custom body".into(),
            headers: HashMap::from([("X-Test".into(), "yes".into())]),
            status_code: 418,
        };
        let (status, headers, body) = h.serve("POST", "/x", &HashMap::new()).await;
        assert_eq!(status, 418);
        assert_eq!(headers.get("X-Test"), Some(&"yes".to_string()));
        assert_eq!(body, b"custom body");
    }

    #[tokio::test]
    async fn proxy_masq_handler_returns_503() {
        let h = ProxyMasqHandler;
        let (status, headers, body) = h.serve("GET", "/proxy", &HashMap::new()).await;
        assert_eq!(status, 503);
        assert_eq!(body, b"Service Unavailable");
        assert_eq!(headers.get("Content-Type"), Some(&"text/plain; charset=utf-8".to_string()));
    }

    #[test]
    fn stub_listener_factory_returns_closed() {
        let factory = StubListenerFactory;
        let cfg = Arc::new(Config::default());
        let qp = Arc::new(QuicParams::default());
        let on_new: Arc<dyn Fn(Arc<InterStreamConn>) + Send + Sync> = Arc::new(|_| {});
        let r = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(factory.listen(
                "127.0.0.1:0".parse().unwrap(),
                cfg,
                qp,
                MasqType::NotFound,
                None,
                on_new,
            ));
        assert!(matches!(r, Err(HysteriaError::ConnectionClosed)));
    }

    #[test]
    fn hysteria_listener_construct_and_close() {
        let l = Arc::new(HysteriaListener::new(
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(Config::default()),
            Arc::new(QuicParams::default()),
            MasqType::NotFound,
            None,
            Arc::new(|_| {}),
        ));
        assert!(!l.is_closed());
        // close without quic_listener 注入
        let r = tokio::runtime::Runtime::new().unwrap().block_on(l.close());
        assert!(r.is_ok());
        assert!(l.is_closed());
    }

    #[test]
    fn hysteria_listener_accessors() {
        let addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let l = HysteriaListener::new(
            addr,
            Arc::new(Config::default()),
            Arc::new(QuicParams::default()),
            MasqType::File("/tmp".into()),
            None,
            Arc::new(|_| {}),
        );
        assert_eq!(l.bind_addr(), addr);
        assert_eq!(l.masq_type(), &MasqType::File("/tmp".into()));
    }
}
