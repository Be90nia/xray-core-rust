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

use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use parking_lot::Mutex;
use xray_proto::xray::transport::internet::QuicParams;

use crate::{
    conn::{InterConn, InterStreamConn, QuicConn, QuicStream},
    error::{HysteriaError, Result},
    proto_config::Config,
};

/// Masquerade 类型（对应 Go `config.MasqType`，4 种 + 默认 404）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MasqType {
    /// HTTP 404（默认，对应 Go `""` / `"404"`）。
    NotFound,
    /// 静态文件服务（对应 Go `"file"`，配置 `MasqFile` 路径）。
    File(String),
    /// 反向代理（对应 Go `"proxy"`，配置 `MasqUrl` + `MasqUrlRewriteHost` + `MasqUrlInsecure`）。
    Proxy { url: String, rewrite_host: bool, insecure: bool },
    /// 静态字符串响应（对应 Go `"string"`，配置 `MasqString` + Headers + StatusCode）。
    String { body: String, headers: HashMap<String, String>, status_code: u16 },
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

    /// 把 masquerade 运行时值写回 proto Config 的 masq 8 字段
    /// （[`Self::from_config`] 的对偶，to_proto 方向）。
    ///
    /// 归一化语义（与 from_config 的解析默认一致）：
    /// - NotFound → `masq_type = ""`（Go 默认分支，hub.go:212）
    /// - String status_code 恒写非 0 值（from_config 已把 0 归一为 200）
    ///
    /// `version`/`auth`/`udp_idle_timeout` 三字段不在 masq 范围，
    /// 由上层直接读写 prost Config（Go hub.go:63/95、dialer.go:202）。
    pub fn to_config(&self, config: &mut Config) {
        match self {
            Self::NotFound => {
                config.masq_type = String::new();
            },
            Self::File(dir) => {
                config.masq_type = "file".into();
                config.masq_file = dir.clone();
            },
            Self::Proxy { url, rewrite_host, insecure } => {
                config.masq_type = "proxy".into();
                config.masq_url = url.clone();
                config.masq_url_rewrite_host = *rewrite_host;
                config.masq_url_insecure = *insecure;
            },
            Self::String { body, headers, status_code } => {
                config.masq_type = "string".into();
                config.masq_string = body.clone();
                config.masq_string_headers = headers.clone();
                config.masq_string_status_code = i32::from(*status_code);
            },
        }
    }

    /// 构造 masquerade handler（对应 Go `hub.go:210-254` listen 时 switch masqType）。
    #[must_use]
    pub fn build_handler(&self) -> std::sync::Arc<dyn MasqueradeHandler> {
        match self {
            Self::NotFound => std::sync::Arc::new(NotFoundMasqHandler),
            Self::File(dir) => std::sync::Arc::new(FileMasqHandler::new(dir.clone())),
            // Go 用 httputil.ReverseProxy 真反代（ErrorHandler 502）；本实现保持
            // 503 类兜底响应（任务授权 "proxy 503 类"），url/rewrite_host/insecure
            // 暂不消费（ponytail: 接入 hyper 反代时再扩展）。
            Self::Proxy { .. } => std::sync::Arc::new(ProxyMasqHandler),
            Self::String { body, headers, status_code } => std::sync::Arc::new(StringMasqHandler {
                body: body.clone(),
                headers: headers.clone(),
                status_code: *status_code,
            }),
        }
    }
}

/// Masquerade HTTP handler trait（对应 Go `http.Handler`）。
///
/// 上层（HTTP/3 server）实现。当非 auth 请求到达时，转发到此 handler 做"伪装响应"。
pub trait MasqueradeHandler: Send + Sync {
    /// 处理一个 HTTP 请求（请求路径/方法 + headers）。
    /// 返回 (status_code, headers, body)。
    #[allow(clippy::type_complexity)] // trait 签名形态固定（Server trait 对称）
    fn serve(
        &self,
        method: &str,
        path: &str,
        headers: &HashMap<String, String>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = (u16, HashMap<String, String>, Vec<u8>)> + Send>,
    >;
}

/// 默认 NotFound 实现（对应 Go `http.NotFoundHandler()`）。
///
/// body/headers 对齐 Go `http.Error(w, "404 page not found", 404)`：
/// `"404 page not found\n"` + `Content-Type: text/plain; charset=utf-8` + `nosniff`。
#[derive(Debug, Default)]
pub struct NotFoundMasqHandler;

/// Go `http.Error` 风格 404（FileServer/NotFoundHandler 共用）。
fn go_not_found() -> (u16, HashMap<String, String>, Vec<u8>) {
    (
        404,
        HashMap::from([
            ("Content-Type".to_string(), "text/plain; charset=utf-8".to_string()),
            ("X-Content-Type-Options".to_string(), "nosniff".to_string()),
        ]),
        b"404 page not found\n".to_vec(),
    )
}

impl MasqueradeHandler for NotFoundMasqHandler {
    fn serve(
        &self,
        _method: &str,
        _path: &str,
        _headers: &HashMap<String, String>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = (u16, HashMap<String, String>, Vec<u8>)> + Send>,
    > {
        Box::pin(async { go_not_found() })
    }
}

/// File masquerade 实现（对应 Go `"file"` 分支 `http.FileServer(http.Dir(MasqFile))`）。
///
/// 最小语义对齐：GET/HEAD 之外 405（Go `serveFile`）；路径穿越（`..` 组件）拒绝；
/// 目录 → `index.html`；缺失 404（Go body）。Go FileServer 的目录列表与 301
/// 尾斜杠重定向未复刻（ponytail: 伪装场景只需文件内容，需要时再加）。
#[derive(Debug, Clone)]
pub struct FileMasqHandler {
    /// 服务根目录（对应 Go `http.Dir(config.MasqFile)`）。
    pub root: std::path::PathBuf,
}

impl FileMasqHandler {
    #[must_use]
    pub fn new(root: impl Into<std::path::PathBuf>) -> Self {
        Self { root: root.into() }
    }
}

/// URL path → root 内文件路径；目录解析到 index.html，`..` 组件拒绝（对应 Go http.Dir）。
fn resolve_masq_file(
    root: &std::path::Path,
    url_path: &str,
) -> std::io::Result<std::path::PathBuf> {
    let mut full = root.to_path_buf();
    for comp in url_path.trim_start_matches('/').split('/') {
        match comp {
            "" | "." => continue,
            ".." => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "path traversal",
                ));
            },
            c => full.push(c),
        }
    }
    if full.is_dir() {
        full.push("index.html");
    }
    if !full.starts_with(root) {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "outside root"));
    }
    Ok(full)
}

/// 扩展名 → Content-Type（对应 Go `mime.TypeByExtension` 常见子集）。
fn masq_content_type(p: &std::path::Path) -> String {
    match p.extension().and_then(|e| e.to_str()).unwrap_or("") {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" => "text/javascript; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "txt" => "text/plain; charset=utf-8",
        "woff2" => "font/woff2",
        _ => "application/octet-stream",
    }
    .to_string()
}

impl MasqueradeHandler for FileMasqHandler {
    fn serve(
        &self,
        method: &str,
        path: &str,
        _headers: &HashMap<String, String>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = (u16, HashMap<String, String>, Vec<u8>)> + Send>,
    > {
        let root = self.root.clone();
        let method = method.to_string();
        let path = path.to_string();
        Box::pin(async move {
            if method != "GET" && method != "HEAD" {
                return (
                    405,
                    HashMap::from([
                        ("Allow".to_string(), "GET, HEAD".to_string()),
                        ("Content-Type".to_string(), "text/plain; charset=utf-8".to_string()),
                        ("X-Content-Type-Options".to_string(), "nosniff".to_string()),
                    ]),
                    b"Method Not Allowed\n".to_vec(),
                );
            }
            let resolved = match resolve_masq_file(&root, &path) {
                Ok(p) => p,
                Err(_) => return go_not_found(),
            };
            match tokio::fs::read(&resolved).await {
                Ok(bytes) => (
                    200,
                    HashMap::from([("Content-Type".to_string(), masq_content_type(&resolved))]),
                    if method == "HEAD" { Vec::new() } else { bytes },
                ),
                Err(_) => {
                    // HEAD 不写 body（Go net/http HEAD 短路）
                    let (s, h, _) = go_not_found();
                    (
                        s,
                        h,
                        if method == "HEAD" {
                            Vec::new()
                        } else {
                            b"404 page not found\n".to_vec()
                        },
                    )
                },
            }
        })
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
        Box<dyn std::future::Future<Output = (u16, HashMap<String, String>, Vec<u8>)> + Send>,
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
        Box<dyn std::future::Future<Output = (u16, HashMap<String, String>, Vec<u8>)> + Send>,
    > {
        Box::pin(async {
            (
                503,
                HashMap::from([(
                    "Content-Type".to_string(),
                    "text/plain; charset=utf-8".to_string(),
                )]),
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
    fn accept(
        &self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = std::io::Result<Arc<dyn QuicConn>>> + Send>,
    >;

    /// 本地地址（对应 Go `listener.Addr()`）。
    fn local_addr(&self) -> SocketAddr;

    /// 关闭（对应 Go `listener.Close()`）。
    fn close(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<()>> + Send>>;
}

/// Listener 工厂 trait（对应 Go `Listen` 函数）。
pub trait HysteriaListenerFactory: Send + Sync {
    /// 创建 QUIC listener（对应 Go `Listen()` 主体）。
    #[allow(clippy::too_many_arguments)] // 存量清零批次
    fn listen(
        &self,
        bind_addr: SocketAddr,
        config: Arc<Config>,
        quic_params: Arc<QuicParams>,
        masq: MasqType,
        validator: Option<Arc<dyn AuthValidator>>,
        on_new_conn: Arc<dyn Fn(Arc<InterStreamConn>) + Send + Sync>,
        // auth 后每个新 UDP session（4B session id 首包触发，对应 Go udpSessionManager.addConn）。
        // None = 不启用 UDP 数据面。
        on_new_udp_session: Option<Arc<dyn Fn(Arc<InterConn>) + Send + Sync>>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Arc<dyn HysteriaQuicListener>>> + Send>,
    >;
}

/// Hysteria Listener（对应 Go `*Listener`）。
pub struct HysteriaListener {
    inner: Arc<ListenerInner>,
}

struct ListenerInner {
    bind_addr: SocketAddr,
    #[allow(dead_code)] // 存量清零批次
    config: Arc<Config>,
    #[allow(dead_code)] // Go 对齐装配面字段
    quic_params: Arc<QuicParams>,
    masq: MasqType,
    #[allow(dead_code)] // Go 对齐装配面字段
    validator: Option<Arc<dyn AuthValidator>>,
    #[allow(dead_code)]
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
        // guard 有意跨 await 存活（close 路径持锁清理）
        #[allow(clippy::await_holding_lock)]
        let l = self.inner.quic_listener.lock().take();
        if let Some(l) = l {
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
        _on_new_udp_session: Option<Arc<dyn Fn(Arc<InterConn>) + Send + Sync>>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Arc<dyn HysteriaQuicListener>>> + Send>,
    > {
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
            MasqType::Proxy { url, rewrite_host, insecure } => {
                assert_eq!(url, "https://example.com");
                assert!(rewrite_host);
                assert!(!insecure);
            },
            _ => panic!("expected Proxy"),
        }
    }

    #[test]
    fn masq_type_from_config_string() {
        let c = make_config("string");
        let m = MasqType::from_config(&c).unwrap();
        match m {
            MasqType::String { body, headers, status_code } => {
                assert_eq!(body, "hello");
                assert_eq!(headers.get("X-Custom"), Some(&"value".to_string()));
                assert_eq!(status_code, 201);
            },
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
        assert_eq!(body, b"404 page not found\n");
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
        let r = tokio::runtime::Runtime::new().unwrap().block_on(factory.listen(
            "127.0.0.1:0".parse().unwrap(),
            cfg,
            qp,
            MasqType::NotFound,
            None,
            on_new,
            None,
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

    // ===== masquerade handler（bd ect：对齐 Go hub.go:210-254 switch + FileServer） =====

    #[tokio::test]
    async fn build_handler_maps_all_masq_types() {
        // ""/"404" → NotFound；"file" → File；"proxy" → Proxy(503 类)；"string" → String
        // 行为断言（trait object 无法 matches 具体类型）：
        // NotFound → Go 404 body；Proxy → 503；String → 配置 body/status。
        let n = MasqType::NotFound.build_handler();
        let (status, _, body) = n.serve("GET", "/", &HashMap::new()).await;
        assert_eq!((status, body.as_slice()), (404, &b"404 page not found\n"[..]));
        let p =
            MasqType::Proxy { url: "https://e.com".into(), rewrite_host: false, insecure: false }
                .build_handler();
        assert_eq!(p.serve("GET", "/", &HashMap::new()).await.0, 503);
        let s = MasqType::String { body: "ok".into(), headers: HashMap::new(), status_code: 200 }
            .build_handler();
        let (status, _, body) = s.serve("GET", "/", &HashMap::new()).await;
        assert_eq!((status, body.as_slice()), (200, &b"ok"[..]));
    }

    #[tokio::test]
    async fn not_found_handler_go_exact_body() {
        // Go http.NotFoundHandler → http.Error(w, "404 page not found", 404)
        let (status, headers, body) =
            NotFoundMasqHandler.serve("GET", "/anything", &HashMap::new()).await;
        assert_eq!(status, 404);
        assert_eq!(body, b"404 page not found\n");
        assert_eq!(headers.get("Content-Type").unwrap(), "text/plain; charset=utf-8");
        assert_eq!(headers.get("X-Content-Type-Options").unwrap(), "nosniff");
    }

    #[tokio::test]
    async fn file_masq_serves_file_content() {
        let dir = std::env::temp_dir().join("hys_masq_test_file");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("page.html"), b"<h1>hi</h1>").unwrap();
        let h = FileMasqHandler::new(dir);
        let (status, headers, body) = h.serve("GET", "/page.html", &HashMap::new()).await;
        assert_eq!(status, 200);
        assert_eq!(body, b"<h1>hi</h1>");
        assert_eq!(headers.get("Content-Type").unwrap(), "text/html; charset=utf-8");
    }

    #[tokio::test]
    async fn file_masq_directory_serves_index_html() {
        let dir = std::env::temp_dir().join("hys_masq_test_dir");
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("sub").join("index.html"), b"index page").unwrap();
        let h = FileMasqHandler::new(dir);
        // Go FileServer：目录路径（无/有尾斜杠）→ index.html
        let (status, _, body) = h.serve("GET", "/sub", &HashMap::new()).await;
        assert_eq!((status, body.as_slice()), (200, &b"index page"[..]));
        let (status, _, body) = h.serve("GET", "/sub/", &HashMap::new()).await;
        assert_eq!((status, body.as_slice()), (200, &b"index page"[..]));
        // 根路径 → root/index.html（不存在 → 404）
        let (status, _, _) = h.serve("GET", "/", &HashMap::new()).await;
        assert_eq!(status, 404);
    }

    #[tokio::test]
    async fn file_masq_missing_file_404_go_body() {
        let dir = std::env::temp_dir().join("hys_masq_test_404");
        std::fs::create_dir_all(&dir).unwrap();
        let h = FileMasqHandler::new(dir);
        let (status, headers, body) = h.serve("GET", "/nope.html", &HashMap::new()).await;
        assert_eq!(status, 404);
        assert_eq!(body, b"404 page not found\n");
        assert_eq!(headers.get("Content-Type").unwrap(), "text/plain; charset=utf-8");
    }

    #[tokio::test]
    async fn file_masq_traversal_rejected() {
        let dir = std::env::temp_dir().join("hys_masq_test_trav");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("secret.txt"), b"secret").unwrap();
        let h = FileMasqHandler::new(dir.clone());
        // Go http.Dir：root 外路径 → 打开失败 → 404
        let (status, _, body) = h.serve("GET", "/../secret.txt", &HashMap::new()).await;
        assert_eq!(status, 404);
        assert_ne!(body, b"secret");
        // URL 编码穿越（%2e%2e）同理拒绝——path 未解码前也含 ".." 组件即可拦
        let (status, _, _) = h.serve("GET", "/%2e%2e/secret.txt", &HashMap::new()).await;
        assert_eq!(status, 404);
    }

    #[tokio::test]
    async fn file_masq_method_not_allowed() {
        // Go serveFile：非 GET/HEAD → 405 + Allow 头
        let h = FileMasqHandler::new(std::env::temp_dir());
        let (status, headers, _) = h.serve("POST", "/x.html", &HashMap::new()).await;
        assert_eq!(status, 405);
        assert_eq!(headers.get("Allow").unwrap(), "GET, HEAD");
        // HEAD → 200 无 body
        let (status, _, body) = h.serve("HEAD", "/", &HashMap::new()).await;
        assert_eq!(status, 404, "HEAD 也走查找，仅 body 为空");
        assert!(body.is_empty());
    }
}
