//! MASQUE 服务端 hub（B4.1：Go `transport/internet/masque/hub.go` 直译形态）。
//!
//! 层序：TCP listen → finalmask wrap（B4.7，Go `hub.go:168-169`）→ TLS
//! （ALPN 强制 `h2`，Go `listenHTTP2` 覆写 `NextProtos`）→ hyper **纯 h2** 服务
//! （`enable_connect_protocol` + `MAX_CONCURRENT_STREAMS=100`，Go
//! `http2_server.go` SETTINGS 面）→ path 匹配 + extended-CONNECT 校验
//! （404/405/501/400，Go `ServeHTTP` + `connectip.ParseProxyRequest`）→
//! [`TunnelGate`]（认证 401 / 分配 503，proxy 层决策）→ 200 + `Capsule-Protocol: ?1`
//! → upgraded IO → [`ServerConn::accept`] 交给 proxy 层。
//!
//! ## 与 Go 的形态差异
//!
//! - Go `ServerConn.Reject` 经 `http.ResponseWriter` 延迟写头；hyper 的响应头在 service_fn
//!   返回时发出 ⇒ 决策（gate + accept/reject）在 service_fn 内等待 [`ServerConn`] 的 answer
//!   通道（10s fail-safe，超时 503 + WARN）。净行为等价： 拒绝状态码/头逐字节同 Go，Accept
//!   前不向对端发任何头。
//! - h3 分支（`serverVersions` 的 `!h2 → h3`）不实现——本批 h2-only （extra 条款
//!   `MASQUE-H2-ONLY`，规划 §7 R11 押后 h3）。
//!
//! udf 不适用判定（CLAUDE.md §3.5.5）：协议 wire 语义（CONNECT-IP 拒绝码 /
//! 胶囊升级握手），单消费方，无提炼候选。

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use http::{HeaderMap, Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper::{body::Incoming, ext::Protocol};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::sync::{Notify, mpsc, oneshot};
use xray_transport::{
    connection::Connection, dialer::StreamSettings, listener_registry::TransportListener,
    sockopt::SocketOptions,
};

/// CONNECT-IP 请求的 `:protocol` 值（Go `connectip/request.go:20`；h2.rs 同源）。
use crate::h2::CONNECT_IP_PROTOCOL;
use crate::{
    config::Config,
    error::{MasqueError, Result as MasqueResult},
};

/// `Capsule-Protocol` 头（Go `http3.CapsuleProtocolHeader`）合法值前缀
/// （Go `connectip/request.go:21 capsuleProtocolHeaderValue = "?1"`）。
const CAPSULE_PROTOCOL_HEADER: &str = "capsule-protocol";
const CAPSULE_PROTOCOL_VALUE: &str = "?1";

/// 401 的 `WWW-Authenticate`（Go `proxy/masque/server.go:31 authenticateHeader`）。
pub const WWW_AUTHENTICATE: &str = "Basic realm=\"masque\", charset=\"UTF-8\"";

/// gate 决策 fail-safe：proxy 层 accept/reject 的最长等待（Go 无显式超时——
/// handler 卡死时连接挂在 ServeHTTP select；本仓以 10s 收口 = 握手期预算同源）。
const GATE_ANSWER_TIMEOUT: Duration = Duration::from_secs(10);

/// h2 服务端 SETTINGS_MAX_CONCURRENT_STREAMS（Go `http2_server.go` = 100）。
const MAX_CONCURRENT_STREAMS: u32 = 100;

/// B4 日志门面（hub 消费站点 = accept/拒绝/升级留痕，非逐包热路径）。
static LOG: std::sync::LazyLock<xray_frame::logging::LogFacade> = std::sync::LazyLock::new(|| {
    xray_frame::logging::LogFacade::new("transport::masque::hub", vec![])
});

/// CONNECT-IP 请求元数据（Go `ServerConn.request` 的可观察面；hub 提取，proxy 层消费）。
#[derive(Debug, Clone)]
pub struct RequestMeta {
    /// 请求方法（恒 `CONNECT`——校验失败不会到达 gate）。
    pub method: Method,
    /// 请求路径（`req.uri().path()`）。
    pub path: String,
    /// 请求查询串（`req.uri().query()`）。
    pub query: Option<String>,
    /// extended CONNECT 协议名（恒 `connect-ip`——校验失败不会到达 gate）。
    pub protocol: String,
    /// `:authority`（Go `r.Host`）。
    pub authority: String,
    /// Basic 认证用户名（头缺失/畸形 = `None`；校验在 gate）。
    pub auth_user: Option<String>,
    /// Basic 认证密码（同上；**掩码纪律**：日志面禁打）。
    pub auth_pass: Option<String>,
    /// 客户端源地址。
    pub peer: SocketAddr,
}

/// gate 拒绝（B4.1 拒绝语义；Go `proxy/masque/server.go` Process 前置段）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateDeny {
    /// 401 + `WWW-Authenticate: Basic realm="masque"`（认证失败，Go :271-282）。
    Auth,
    /// 503（无地址可分配等资源拒绝，Go :289-293）。
    Unavailable,
}

/// gate 授权产物。
#[derive(Debug, Clone)]
pub struct GateGrant {
    /// 认证用户 email（AccessContext.email 挂接用；Go `user.Email`）。
    pub email: String,
    /// 认证用户策略层级（AccessContext.level 挂接用；Go `user.Level`）。
    pub level: u32,
    /// gate 侧 opaque 载荷（hub 不解释）：proxy 层经 gate 把 per-连接分配结果
    /// （地址分配等）传递给 [`TunnelAcceptor`] 消费方（`Arc<dyn Any>` 下转）。
    pub extra: Option<Arc<dyn std::any::Any + Send + Sync>>,
}

/// 隧道闸门（proxy 层认证 + 地址分配决策；Go Process 前置段的强类型对应）。
pub type TunnelGate =
    Arc<dyn Fn(&RequestMeta) -> std::result::Result<GateGrant, GateDeny> + Send + Sync>;

// ===== 共享认证闸（bd anygg G2：transport 注册表形态的 users 校验委托面） =====

/// 进程级共享 masque users 闸：proxy 层（`xray_proxy_masque::server::serve`）装配时
/// 注册首个 users gate；transport 注册表形态（`register::register_listener`）查此槽
/// 委托认证。单槽 + 首个成功：同实例多 masque 入站时委托面取首张 users 表（各
/// listener 自身的直连 gate 不经此槽，不受影响）。槽随进程存活不注销——与
/// transport listener/dialer 注册表同生命周期语义。
static SHARED_AUTH_GATE: std::sync::LazyLock<std::sync::RwLock<Option<TunnelGate>>> =
    std::sync::LazyLock::new(|| std::sync::RwLock::new(None));

/// proxy 层注册共享 users 闸。首个注册返回 `true`；已有注册时忽略（返回 `false`
/// ——注册方自身 listener 仍用自己的直连 gate，行为不变）。
pub fn register_shared_auth_gate(gate: TunnelGate) -> bool {
    let mut slot = SHARED_AUTH_GATE.write().unwrap_or_else(std::sync::PoisonError::into_inner);
    if slot.is_some() {
        return false;
    }
    *slot = Some(gate);
    true
}

/// 查共享 users 闸（transport listener 形态消费；`None` = 本进程无 masque users
/// 源，调用方按 Go `hub.go:53` 语义放行——transport 层无认证，协议层自认证）。
pub(crate) fn shared_auth_gate() -> Option<TunnelGate> {
    SHARED_AUTH_GATE.read().unwrap_or_else(std::sync::PoisonError::into_inner).clone()
}

/// 隧道接受器（Go `internet.ConnHandler` 的强类型对应）：hub 校验/gate 通过后
/// 把 [`ServerConn`] 交给 proxy 层。
pub trait TunnelAcceptor: Send + Sync {
    /// 接收新隧道。实现方不得阻塞（Go `addConn` 非阻塞投递同款）。
    fn add_tunnel(&self, conn: ServerConn);
}

/// answer 通道载荷（hub service_fn ↔ ServerConn 决策传递）。
enum Answer {
    /// 接受：service_fn 返回 200 + upgrade，IO 经 io 通道转交 [`ServerConn::accept`]。
    Accept,
    /// 拒绝：service_fn 返回对应状态码（连接结束，Go Reject 语义）。
    Reject(GateDeny),
}

/// 服务端隧道连接（未决状态）。proxy 层二选一：
/// - [`accept`](Self::accept)：等 upgraded IO（hub 已发 200 响应）→ 隧道字节流；
/// - [`reject`](Self::reject)：发拒绝响应（401/503），连接关闭。
///
/// 双通道序：`answer_tx.send(Accept)` → service_fn 返回 200 → hyper 发响应头 →
/// upgrade 完成 → IO 经 `io_tx` 转交。drop 而不决策 = service_fn 侧 answer_rx
/// 断开 → 503 兜底（不静默挂连接）。
pub struct ServerConn {
    /// 请求元数据（认证/审计用）。
    pub meta: RequestMeta,
    /// gate 授权产物（email 挂接）。
    pub grant: GateGrant,
    answer_tx: Option<oneshot::Sender<Answer>>,
    io_rx: Option<mpsc::Receiver<TokioIo<hyper::upgrade::Upgraded>>>,
}

impl ServerConn {
    /// 接受隧道：等 hub 返回 200 + upgraded IO。会话级错误（hub 已关）= Err。
    pub async fn accept(mut self) -> MasqueResult<TunnelStream> {
        let Some(tx) = self.answer_tx.take() else {
            return Err(MasqueError::Protocol("masque: server conn already answered".into()));
        };
        if tx.send(Answer::Accept).is_err() {
            return Err(MasqueError::Io(io::Error::new(
                io::ErrorKind::NotConnected,
                "masque: hub gone before accept",
            )));
        }
        let Some(mut rx) = self.io_rx.take() else {
            return Err(MasqueError::Protocol("masque: server conn already answered".into()));
        };
        let io = rx.recv().await.ok_or_else(|| {
            MasqueError::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "masque: hub dropped before stream upgrade",
            ))
        })?;
        Ok(TunnelStream { io, meta: self.meta.clone() })
    }

    /// 拒绝隧道（Go `ServerConn.Reject`）：发对应状态码；连接由 hub 关闭。
    pub fn reject(mut self, deny: GateDeny) -> MasqueResult<()> {
        let Some(tx) = self.answer_tx.take() else {
            return Err(MasqueError::Protocol("masque: server conn already answered".into()));
        };
        tx.send(Answer::Reject(deny))
            .map_err(|_| MasqueError::Io(io::Error::other("masque: hub gone before reject")))
    }
}

impl Drop for ServerConn {
    fn drop(&mut self) {
        // 未决策即丢弃 = 拒绝兜底（Go closeOnce: Reject(500) 等价形态；service_fn
        // 侧 answer_rx 已断 → 503，两路均不静默）。
        if let Some(tx) = self.answer_tx.take() {
            let _ = tx.send(Answer::Reject(GateDeny::Unavailable));
        }
    }
}

/// 服务端隧道字节流（upgraded h2 流；IP 包胶囊已由对端/本端会话编解码）。
///
/// 消费形态：。
pub struct TunnelStream {
    io: TokioIo<hyper::upgrade::Upgraded>,
    meta: RequestMeta,
}

impl TunnelStream {
    /// 请求元数据（审计面）。
    #[must_use]
    pub fn meta(&self) -> &RequestMeta {
        &self.meta
    }
}

impl tokio::io::AsyncRead for TunnelStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::pin!(&mut self.io).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for TunnelStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::pin!(&mut self.io).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::pin!(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::pin!(&mut self.io).poll_shutdown(cx)
    }
}

// 注：TunnelStream 不实现 `Connection`——`hyper::upgrade::Upgraded` 内部
// `dyn Io + Send` 非 `Sync`，不满足 `Connection: Sync` 界。消费面 = proxy 层
// [`ConnectIpSession::server_session`]（只需 AsyncRead+AsyncWrite+Send+Unpin）。

/// path 匹配器（Go `pathMatcher`：path 精确 + query 逐键逐值相等）。
#[derive(Debug, Clone)]
struct PathMatcher {
    path: String,
    query: Vec<(String, String)>,
}

impl PathMatcher {
    /// 解析（Go `newPathMatcher`：非法 path（不以 `/` 开头）即 Err）。
    fn new(path: &str) -> MasqueResult<Self> {
        let Some((p, q)) = path.split_once('?') else {
            if !path.starts_with('/') {
                return Err(MasqueError::Protocol(format!("masque: invalid path: {path}")));
            }
            return Ok(Self { path: path.to_owned(), query: Vec::new() });
        };
        if !p.starts_with('/') {
            return Err(MasqueError::Protocol(format!("masque: invalid path: {path}")));
        }
        // query 按 Go `url.Values`：键 → 值列表；比较按键升序 + 值序列相等。
        let mut pairs: Vec<(String, String)> = q
            .split('&')
            .filter(|s| !s.is_empty())
            .map(|kv| match kv.split_once('=') {
                Some((k, v)) => (k.to_owned(), v.to_owned()),
                None => (kv.to_owned(), String::new()),
            })
            .collect();
        pairs.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        Ok(Self { path: p.to_owned(), query: pairs })
    }

    /// 匹配（Go `pathMatcher.match`）。
    fn matches(&self, path: &str, query: Option<&str>) -> bool {
        if path != self.path {
            return false;
        }
        let mut req_pairs: Vec<(String, String)> = query
            .unwrap_or("")
            .split('&')
            .filter(|s| !s.is_empty())
            .map(|kv| match kv.split_once('=') {
                Some((k, v)) => (k.to_owned(), v.to_owned()),
                None => (kv.to_owned(), String::new()),
            })
            .collect();
        req_pairs.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        req_pairs == self.query
    }
}

/// 监听器句柄（TransportListener 形态；close = 停 accept + 关闸）。
struct MasqueHubListener {
    local: SocketAddr,
    stop: Arc<Notify>,
    scope: xray_frame::scope::ComponentScope,
}

impl TransportListener for MasqueHubListener {
    fn close(&self) -> io::Result<()> {
        self.stop.notify_waiters();
        // transport 族关闸档（ADR-0004 §2.2 Q1）：停新任务，不杀已建立隧道。
        self.scope.close_gate();
        Ok(())
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }
}

/// MASQUE 服务端监听（Go `Listen` h2 分支直译；h3 不实现——`MASQUE-H2-ONLY`）。
///
/// 硬约束：`security=tls` 必选（Go `hub.go:52-60`）；ALPN 强制 `h2`
/// （Go `listenHTTP2` 覆写 `NextProtos`）；10s TLS 握手窗（Go
/// `http2HandshakeTimeout`）；100 并发流（Go SETTINGS）。
pub async fn listen_masque(
    addr: SocketAddr,
    settings: &StreamSettings,
    _sockopt: &SocketOptions,
    gate: TunnelGate,
    acceptor: Arc<dyn TunnelAcceptor>,
) -> io::Result<Box<dyn TransportListener>> {
    // TLS 硬要求（Go hub.go:52-60 `tls config is nil`）。
    if settings.security != "tls" {
        return Err(io::Error::other("masque: tls config is nil (\"security\": \"tls\" required)"));
    }
    let Some(tls_cfg) = xray_tls::server_config::build_server_config(
        &settings.security,
        settings.security_json.as_ref(),
    )?
    else {
        return Err(io::Error::other("masque: tls config is nil (\"security\": \"tls\" required)"));
    };
    // ALPN 强制 h2（Go listenHTTP2：`gotlsConfig.NextProtos = [http2.NextProtoTLS]`）。
    let mut tls_cfg = (*tls_cfg).clone();
    tls_cfg.alpn_protocols = vec![b"h2".to_vec()];
    let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_cfg));

    // path 匹配器（服务端消费 Config.path；host/headers 是客户端面字段）。
    let config = Config::from_json(settings.transport_json.as_ref())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    let matcher = Arc::new(
        PathMatcher::new(&config.path)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?,
    );

    // finalmask（B4.7，Go hub.go:168-169 `FinalMask.Listen` 对应面；空 = 恒等）。
    let tcpmask = Arc::new(xray_transport::finalmask::build_tcpmask_manager_from_json(
        settings.finalmask_json.as_ref(),
    )?);

    let tcp = xray_transport::system_listener::bind_tcp_listener(
        addr,
        xray_transport::system_listener::effective_listen_backlog(),
    )
    .await?;
    let local = tcp.local_addr()?;

    // §3.5.6 ①类托管：hub 账本 owner（accept 循环 + 每连接任务）；acceptor 经
    // Arc 反向持 proxy 层不回持 scope（无自引用环）。
    let scope = xray_frame::scope::ComponentScope::new("masque-hub");
    let stop = Arc::new(Notify::new());

    let accept_gate = xray_transport::handshake_gate::HandshakeGate::new(
        xray_transport::handshake_gate::effective_inflight_limit(),
    );
    let stop_loop = Arc::clone(&stop);
    let hub_scope_ref = scope.downgrade();
    let accept_task = scope
        .spawn(async move {
            loop {
                let accepted = tokio::select! {
                    r = tcp.accept() => r,
                    _ = stop_loop.notified() => break,
                };
                let Ok((stream, peer)) = accepted else {
                    // accept 瞬时错误分类退避（accept_policy 纪律）；闸关态随 select 退出。
                    continue;
                };
                let _ = stream.set_nodelay(true);
                // Tcpmask wrap（Go hub.go:546-549 同位；wrap 失败丢连接继续）。
                let stream: Box<dyn Connection> =
                    match xray_transport::finalmask::wrap_conn_server_into_connection(
                        &tcpmask,
                        Box::new(xray_transport::connection::TcpConnection::new(stream)),
                    ) {
                        Ok(c) => c,
                        Err(e) => {
                            LOG.warn(format!("masque hub: tcpmask wrap failed: {e}"));
                            continue;
                        },
                    };
                // 并发握手闸（jcnjb⑤ 同款）：满即 fail-fast 丢弃，不排队。
                let Some(permit) = accept_gate.try_admit() else {
                    accept_gate.record_reject("masque-hub");
                    LOG.warn("masque hub: handshake inflight limit reached, connection dropped");
                    continue;
                };
                let tls = tls_acceptor.clone();
                let gate = Arc::clone(&gate);
                let acceptor = Arc::clone(&acceptor);
                let matcher = Arc::clone(&matcher);
                let conn_scope = hub_scope_ref.clone();
                let _ = hub_scope_ref.spawn(async move {
                    let _permit = permit; // 握手窗随任务体释放
                    serve_tls_conn(stream, peer, tls, matcher, gate, acceptor, conn_scope).await;
                });
            }
        })
        .expect("freshly created scope never closed");
    // 意外退出监控（accept 循环 panic 静默死亡 = 端口仍绑不服务；splithttp 同款）。
    let _supervise = scope
        .spawn(xray_transport::accept_policy::supervise_accept_loop(
            "masque",
            local.to_string(),
            accept_task.join(),
        ))
        .expect("freshly created scope never closed");

    LOG.info(format!("{local} listening TCP for MASQUE over HTTP/2"));
    Ok(Box::new(MasqueHubListener { local, stop, scope }))
}

/// 单连接：TLS（10s 窗 + ALPN=h2 校验）→ 纯 h2 服务（extended CONNECT 打开）。
///
/// `scope` = hub 账本的弱引用句柄（[`xray_frame::scope::ScopeRef`]）：upgrade 泵
/// 住本账本，故只传弱引用（ADR-0004 §2.2 Q4 形态①，禁自引用环）。
async fn serve_tls_conn(
    stream: Box<dyn Connection>,
    peer: SocketAddr,
    tls: tokio_rustls::TlsAcceptor,
    matcher: Arc<PathMatcher>,
    gate: TunnelGate,
    acceptor: Arc<dyn TunnelAcceptor>,
    scope: xray_frame::scope::ScopeRef,
) {
    // TLS 握手（Go serveHTTP2Conn：HandshakeContext(http2HandshakeTimeout)）。
    let tls_stream = match xray_transport::tls_handshake_gate::accept_tls_with_timeout(
        &tls,
        stream,
        xray_transport::tls_handshake_gate::TLS_HANDSHAKE_TIMEOUT,
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            LOG.debug(format!("masque hub: tls handshake failed from {peer}: {e}"));
            return;
        },
    };
    // ALPN 校验（Go：NegotiatedProtocol != h2 → 关闭）。
    let alpn = tls_stream.get_ref().1.alpn_protocol();
    if alpn != Some(b"h2") {
        LOG.debug(format!(
            "masque hub: client negotiated {:?} instead of h2, closing",
            alpn.map(String::from_utf8_lossy)
        ));
        return;
    }
    // h2 服务（extended CONNECT 需 upgrades 面；TLS 层已强制 ALPN=h2，auto
    // builder 的 h1 探测分支不可达——spike 同款形态，B0 R1 已验证）。
    let mut builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
    builder
        .http2()
        .timer(TokioTimer::new())
        .enable_connect_protocol()
        .max_concurrent_streams(MAX_CONCURRENT_STREAMS);
    let service = hyper::service::service_fn(move |req: Request<Incoming>| {
        let matcher = Arc::clone(&matcher);
        let gate = Arc::clone(&gate);
        let acceptor = Arc::clone(&acceptor);
        let scope = scope.clone();
        async move { handle_request(req, peer, matcher, gate, acceptor, scope).await }
    });
    if let Err(e) = builder.serve_connection_with_upgrades(TokioIo::new(tls_stream), service).await
    {
        LOG.debug(format!("masque hub: h2 connection from {peer} ended: {e}"));
    }
}

type HyperResult = std::result::Result<Response<Full<bytes::Bytes>>, std::convert::Infallible>;

/// 单请求处理：path → CONNECT/protocol/Capsule-Protocol → gate → answer。
async fn handle_request(
    req: Request<Incoming>,
    peer: SocketAddr,
    matcher: Arc<PathMatcher>,
    gate: TunnelGate,
    acceptor: Arc<dyn TunnelAcceptor>,
    scope: xray_frame::scope::ScopeRef,
) -> HyperResult {
    // 1) path 匹配（Go ServeHTTP 首段：不匹配 = 404）。
    if !matcher.matches(req.uri().path(), req.uri().query()) {
        return Ok(empty_response(StatusCode::NOT_FOUND, None));
    }
    // 2) extended CONNECT 校验（Go connectip.ParseProxyRequest）。
    if req.method() != Method::CONNECT {
        return Ok(empty_response(StatusCode::METHOD_NOT_ALLOWED, None));
    }
    let protocol =
        req.extensions().get::<Protocol>().map_or(String::new(), |p| p.as_str().to_owned());
    if protocol != CONNECT_IP_PROTOCOL {
        return Ok(empty_response(StatusCode::NOT_IMPLEMENTED, None));
    }
    if !capsule_protocol_ok(req.headers()) {
        return Ok(empty_response(StatusCode::BAD_REQUEST, None));
    }
    // 3) 元数据提取 + gate 决策（proxy 层认证/分配）。
    let meta = extract_meta(&req, peer);
    let grant = match gate(&meta) {
        Ok(g) => g,
        Err(GateDeny::Auth) => {
            return Ok(empty_response(StatusCode::UNAUTHORIZED, Some(WWW_AUTHENTICATE)));
        },
        Err(GateDeny::Unavailable) => {
            return Ok(empty_response(StatusCode::SERVICE_UNAVAILABLE, None));
        },
    };
    // 4) 决策通道 + upgrade future（先建后答——响应头发出后 upgrade 才能完成）。
    let (answer_tx, answer_rx) = oneshot::channel::<Answer>();
    let (io_tx, io_rx) = mpsc::channel(1);
    acceptor.add_tunnel(ServerConn {
        meta: meta.clone(),
        grant,

        answer_tx: Some(answer_tx),
        io_rx: Some(io_rx),
    });
    let upgrade = hyper::upgrade::on(req);
    tokio::select! {
        answer = answer_rx => match answer {
            Ok(Answer::Accept) => {
                // 200 + Capsule-Protocol（Go connectip.Proxy.Proxy 响应头同值）；
                // upgrade IO 异步转交 ServerConn::accept（§3.5.6 ①类：走 hub 账本）。
                let _ = scope.spawn(async move {
                    match upgrade.await {
                        Ok(io) => {
                            let _ = io_tx.send(TokioIo::new(io)).await;
                        },
                        Err(e) => LOG.debug(format!("masque hub: upgrade failed: {e}")),
                    }
                });
                Ok(empty_response(StatusCode::OK, None))
            },
            Ok(Answer::Reject(deny)) => Ok(match deny {
                GateDeny::Auth => empty_response(StatusCode::UNAUTHORIZED, Some(WWW_AUTHENTICATE)),
                GateDeny::Unavailable => empty_response(StatusCode::SERVICE_UNAVAILABLE, None),
            }),
            Err(_) => {
                // ServerConn 被 drop（proxy 层消失）—— 503 兜底（不静默挂）。
                Ok(empty_response(StatusCode::SERVICE_UNAVAILABLE, None))
            },
        },
        _ = tokio::time::sleep(GATE_ANSWER_TIMEOUT) => {
            LOG.warn(format!(
                "masque hub: gate answer timeout from {}, rejecting 503",
                meta.peer
            ));
            Ok(empty_response(StatusCode::SERVICE_UNAVAILABLE, None))
        },
    }
}

/// 元数据提取（Basic 头解析 = Go `r.BasicAuth()`；畸形/缺失 → None——校验在 gate）。
fn extract_meta(req: &Request<Incoming>, peer: SocketAddr) -> RequestMeta {
    let (auth_user, auth_pass) = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(basic_auth_decode)
        .map_or((None, None), |(u, p)| (Some(u), Some(p)));
    RequestMeta {
        method: req.method().clone(),
        path: req.uri().path().to_owned(),
        query: req.uri().query().map(str::to_owned),
        protocol: req
            .extensions()
            .get::<Protocol>()
            .map_or(String::new(), |p| p.as_str().to_owned()),
        authority: req.uri().host().unwrap_or_default().to_owned(),
        auth_user,
        auth_pass,
        peer,
    }
}

/// `Basic base64(user:pass)` 解码（Go `r.BasicAuth()` 同形；UTF-8 失败 = None）。
fn basic_auth_decode(value: &str) -> Option<(String, String)> {
    use base64::Engine as _;
    let rest = value.strip_prefix("Basic ").or_else(|| value.strip_prefix("basic "))?;
    let decoded = base64::engine::general_purpose::STANDARD.decode(rest.trim()).ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let (user, pass) = text.split_once(':')?;
    Some((user.to_owned(), pass.to_owned()))
}

/// `Capsule-Protocol` 合法性（Go `isCapsuleProtocolEnabled`：join 后 trim，
/// `?1` 精确或 `?1;` 前缀）。
fn capsule_protocol_ok(headers: &HeaderMap) -> bool {
    let joined = headers
        .get_all(CAPSULE_PROTOCOL_HEADER)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect::<Vec<_>>()
        .join(",");
    let v = joined.trim();
    v == CAPSULE_PROTOCOL_VALUE || v.starts_with(&format!("{CAPSULE_PROTOCOL_VALUE};"))
}

/// 空体响应（拒绝/接受统一形态；Go `WriteHeader` 无 body 同款）。
fn empty_response(
    status: StatusCode,
    www_authenticate: Option<&str>,
) -> Response<Full<bytes::Bytes>> {
    let mut builder = Response::builder().status(status);
    if let Some(www) = www_authenticate {
        builder = builder.header("www-authenticate", www);
    }
    builder.body(Full::new(bytes::Bytes::new())).expect("static response builds")
}

#[cfg(test)]
mod tests {
    use http::HeaderValue;

    use super::*;

    #[test]
    fn path_matcher_exact_and_query() {
        let m = PathMatcher::new(crate::config::DEFAULT_PATH).expect("default path ok");
        assert!(m.matches("/.well-known/masque/ip/*/*/", None));
        assert!(!m.matches("/.well-known/masque/ip/*/*/extra", None));
        assert!(!m.matches("/", None));
        let m2 = PathMatcher::new("/p?a=1&b=2").expect("path with query ok");
        assert!(m2.matches("/p", Some("a=1&b=2")));
        assert!(m2.matches("/p", Some("b=2&a=1")));
        assert!(!m2.matches("/p", Some("a=1")));
        assert!(!m2.matches("/p", None));
    }

    #[test]
    fn path_matcher_rejects_relative() {
        assert!(PathMatcher::new("no-slash").is_err());
    }

    #[test]
    fn capsule_header_semantics() {
        let mut h = HeaderMap::new();
        assert!(!capsule_protocol_ok(&h), "missing header must fail (400)");
        h.insert("capsule-protocol", HeaderValue::from_static("?1"));
        assert!(capsule_protocol_ok(&h));
        h.insert("capsule-protocol", HeaderValue::from_static("?0"));
        assert!(!capsule_protocol_ok(&h));
        h.clear();
        h.insert("capsule-protocol", HeaderValue::from_static("?1;foo"));
        assert!(capsule_protocol_ok(&h), "Go accepts ?1; prefix");
    }

    #[test]
    fn basic_auth_decode_roundtrip() {
        use base64::Engine as _;
        let enc = |s: &str| base64::engine::general_purpose::STANDARD.encode(s);
        let v = format!("Basic {}", enc("alice:secret"));
        assert_eq!(basic_auth_decode(&v), Some(("alice".into(), "secret".into())));
        // 密码含冒号：首冒号切分（Go strings.Cut 同款）。
        let v2 = format!("Basic {}", enc("bob:pa:ss"));
        assert_eq!(basic_auth_decode(&v2), Some(("bob".into(), "pa:ss".into())));
        assert_eq!(basic_auth_decode("Bearer x"), None);
        assert_eq!(basic_auth_decode("Basic !!!not-base64!!!"), None);
    }

    #[test]
    fn reject_response_carries_www_authenticate() {
        let r = empty_response(StatusCode::UNAUTHORIZED, Some(WWW_AUTHENTICATE));
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(r.headers().get("www-authenticate").unwrap(), WWW_AUTHENTICATE);
        let r2 = empty_response(StatusCode::SERVICE_UNAVAILABLE, None);
        assert!(r2.headers().get("www-authenticate").is_none());
    }
}
