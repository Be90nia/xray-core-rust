//! SplitHTTP transport 监听入口（生产 listener）。
//!
//! 对应 Go `transport/internet/splithttp/hub.go::ListenXH`（449-582 行）：
//! - **isH3 判定**（hub.go:469）：`tlsSettings.alpn == ["h3"]` → UDP + QUIC + h3 server
//! - **TCP**（hub.go:536-545）：accept → 可选 TLS（hub.go:553-556）/ REALITY（hub.go:558-560） →
//!   hyper auto（h1 + h2c，hub.go:565-567）→ [`crate::hub::handler::handle_request`]
//! - **unix**（hub.go:472-480 `port == 0` → `ListenUnix`）：不支持——Rust 生产入口
//!   `listen_splithttp` 只分 h3/TCP，`SocketAddr` 无法承载 unix 路径。
//!
//! Go 的 `requestHandler.ServeHTTP` 与传输无关（同一 handler 服务 h1/h2/h3 三路），
//! 本文件把 hub handler 接到 h3/TCP 两种监听形态上。

use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use base64::Engine as _;
use bytes::{Buf as _, Bytes};
use http_body_util::BodyExt as _;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use xray_transport::{
    connection::Connection,
    dialer::StreamSettings,
    fallback::fallback_to_dest,
    listener_registry::{ConnHandler, TransportListener},
    sockopt::SocketOptions,
};

use crate::{
    config::Config,
    hub::{
        HubConnHandler, ServerConn, SessionMap,
        handler::{self, HandlerContext},
    },
};

/// h1 请求头读取超时。对应 Go hub.go:570 `ReadHeaderTimeout: time.Second * 4`。
const READ_HEADER_TIMEOUT: Duration = Duration::from_secs(4);

/// duplex bridge 缓冲。与 `hub::handler::DUPLEX_BUF` 对齐（64 KiB）。
const DUPLEX_BUF: usize = 64 * 1024;

/// serve 空闲兜底窗（bd lfeu：hyper h2 serve 对客户端 hard-close/静默对端
/// 不退出——724cc20 ws serve_h2_reject 同族 N-1）。与 ws 的差异：serve_http_conn
/// 承载长活数据流（GET 下行流随代理会话存活），硬杀全连接会切断 >30s 活跃
/// 传输，故按 I/O 进度滚动续期——静默连接最迟 30s 强杀释放，活跃连接不受限。
const SERVE_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// h2 连接级 keep-alive PING 间隔（服务端/客户端同值）。
///
/// 客户端对齐 Go `common/net/net.go:20` `ChromeH2KeepAlivePeriod = 45s`
/// （http2.Transport ReadIdleTimeout 缺省，dialer.go http2 分支）；服务端 Go
/// http.Server 无对应配置，hyper server http2 Builder 显式取同值。连接层 PING
/// 是对抗 NAT/中间盒空闲回收的官方手段（librarian 调研
/// reports/research-go-xhttp-padding-20261016.md），in-band body 填充方案已被
/// 上游两次拒绝（#6422/#6755），勿再引入。
pub(crate) const H2_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(45);

/// bd wz2b C2 + bd c9oc F-A h2 窗钉修复常量（commit 8780187e，防回档）：
/// client.rs 主 builder 与 dialer.rs stream-one 共用（同批同值）。削弱任一值
/// 必红 client.rs `h2_window_pins_match_wz2b_c9oc`。
pub(crate) const H2_INITIAL_STREAM_WINDOW: u32 = 32 * 1024 * 1024;
/// 连接窗不低于流窗即不另成钉（bd c9oc F-A）。
pub(crate) const H2_INITIAL_CONNECTION_WINDOW: u32 = 32 * 1024 * 1024;
/// h2 每流发送缓冲（bd wz2b：服务端收窗放大后 send buf 成次级钉；回档 1MB =
/// 上行钉 1MB/RTT）。
pub(crate) const H2_MAX_SEND_BUF_SIZE: usize = 16 * 1024 * 1024;

/// SplitHTTP 监听入口（listener registry 注册的目标）。
///
/// 镜像 Go `ListenXH`：isH3（alpn==["h3"]）走 QUIC，其余走 TCP + TLS/REALITY 包装。
pub async fn listen_splithttp(
    addr: SocketAddr,
    settings: &StreamSettings,
    sockopt: &SocketOptions,
    handler: ConnHandler,
) -> io::Result<Box<dyn TransportListener>> {
    let config =
        Arc::new(crate::register::parse_splithttp_config(settings.transport_json.as_ref())?);
    let tls_cfg = xray_tls::server_config::build_server_config(
        &settings.security,
        settings.security_json.as_ref(),
    )?;

    // isH3：Go hub.go:469 — `len(NextProtos) == 1 && NextProtos[0] == "h3"`。
    // REALITY 不进 H3（Go REALITY config 无 NextProtos，且 hub.go:558 只包装 tcp/unix
    // listener），故限定 security == "tls"。
    let is_h3 = settings.security == "tls"
        && tls_cfg
            .as_ref()
            .is_some_and(|c| c.alpn_protocols.len() == 1 && c.alpn_protocols[0] == b"h3");

    if is_h3 {
        let tls = tls_cfg.expect("is_h3 implies Some");
        listen_h3(addr, tls, &config, sockopt, handler).await
    } else {
        // Tcpmask（Go splithttp/hub.go:547-549：`!isH3 && TcpmaskManager != nil`
        // 才 WrapListener——H3/QUIC 分支不接 Tcpmask）。空 manager = 恒等。
        let tcpmask = Some(Arc::new(xray_transport::finalmask::build_tcpmask_manager_from_json(
            settings.finalmask_json.as_ref(),
        )?));
        listen_tcp(
            addr,
            &settings.security,
            tls_cfg,
            settings.security_json.as_ref(),
            &config,
            tcpmask,
            handler,
        )
        .await
    }
}

/// [`listen_splithttp`] 的底层连接源（Go splithttp/hub.go:526-531
/// `port == net.Port(0)` unix 分支）。unix 侧无 PROXY protocol/finalmask，
/// 对齐 Go system_listener UnixAddr 分支。
// UnixListener 明显大于 TcpListener；本枚举每 listener 只构造一次，
// 体积差异不进入 accept 热路径，Box 化只增一次间接寻址与维护面。
#[allow(clippy::large_enum_variant)]
enum XhSource {
    Tcp(tokio::net::TcpListener),
    #[cfg(unix)]
    Unix(xray_transport::system_listener::UnixListener),
}

/// accept 错误分类处置（Resource 退避 / 单连接 debug / 未知 warn），永不退出。
async fn log_xh_accept_err(e: &io::Error, tag: &str, log_ident: &str) {
    use xray_transport::accept_policy::{AcceptErrorKind, backoff_if_resource, classify};
    match classify(e) {
        AcceptErrorKind::Resource => {
            crate::LOG.warn(format!("tag={tag} local={log_ident} error={e} splithttp inbound: 资源/瞬时类 accept 错误，退避 500ms 后继续"));
            backoff_if_resource(e).await;
        },
        AcceptErrorKind::Connection => {
            crate::LOG.debug(format!(
                "tag={tag} error={e} splithttp inbound: 单连接级 accept 错误，继续监听"
            ));
        },
        AcceptErrorKind::Unknown => {
            crate::LOG.warn(format!("tag={tag} local={log_ident} error={e} splithttp inbound: accept 错误（未知类别），继续监听"));
        },
    }
}

/// 连接获取 + Tcpmask wrap（仅 TCP 分支）。
///
/// 返回 `None` = 该连接丢弃/accept 瞬时错误已分类退避，循环继续（错误永不
/// 退出——退出唯一来源是 close() 的 abort 句柄）。
async fn accept_xh_conn(
    source: &XhSource,
    tcpmask: Option<&Arc<xray_transport::finalmask::TcpmaskManager>>,
    tag: &str,
    log_ident: &str,
) -> Option<(Box<dyn xray_transport::connection::Connection>, SocketAddr)> {
    match source {
        XhSource::Tcp(tcp) => {
            let (stream, peer) = match tcp.accept().await {
                Ok(v) => v,
                Err(e) => {
                    log_xh_accept_err(&e, tag, log_ident).await;
                    return None;
                },
            };
            let _ = stream.set_nodelay(true);
            // Tcpmask wrap（Go hub.go:546-549 WrapListener：mask 在 TLS/REALITY
            // 之内、最贴近 wire；wrap 失败丢连接继续 accept）。
            let stream: Box<dyn xray_transport::connection::Connection> = match tcpmask.as_ref() {
                Some(m) => {
                    match xray_transport::finalmask::wrap_conn_server_into_connection(
                        m,
                        Box::new(xray_transport::connection::TcpConnection::new(stream)),
                    ) {
                        Ok(c) => c,
                        Err(e) => {
                            crate::LOG.debug(format!("error={e} XHTTP tcpmask wrap failed"));
                            return None;
                        },
                    }
                },
                None => Box::new(xray_transport::connection::TcpConnection::new(stream)),
            };
            Some((stream, peer))
        },
        #[cfg(unix)]
        XhSource::Unix(listener) => {
            use xray_transport::system_listener::SystemListener as _;
            let stream = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    log_xh_accept_err(&e, tag, log_ident).await;
                    return None;
                },
            };
            Some((stream, SocketAddr::from(([0, 0, 0, 0], 0))))
        },
    }
}

async fn listen_tcp(
    addr: SocketAddr,
    security: &str,
    tls_cfg: Option<Arc<rustls::ServerConfig>>,
    security_json: Option<&serde_json::Value>,
    config: &Arc<Config>,
    tcpmask: Option<Arc<xray_transport::finalmask::TcpmaskManager>>,
    handler: ConnHandler,
) -> io::Result<Box<dyn TransportListener>> {
    let tcp = xray_transport::system_listener::bind_tcp_listener(
        addr,
        xray_transport::system_listener::effective_listen_backlog(),
    )
    .await?;
    let local = tcp.local_addr()?;
    let source = XhSource::Tcp(tcp);
    // REALITY listener：Go hub.go:558-560 `goreality.NewListener`。
    let reality = reality_server_config(security, security_json)?;
    // bd frxi：配置启用探测时 spawn CCS 探测写 ProbeTable（Go tcp/hub.go:79
    // `go goreality.DetectPostHandshakeRecordsLens` 等价；Rust 侧 opt-in）。
    let reality_probe =
        reality.as_ref().filter(|rc| rc.max_useless_records.is_enabled()).map(|rc| {
            let table = xray_reality::probe::ProbeTable::new();
            xray_reality::probe::detect_max_useless_records(
                table.clone(),
                rc.fallback_dest.clone(),
                rc.server_names.clone(),
                "tcp".to_string(),
                rc.xver,
            );
            xray_reality::probe::detect_post_handshake_record_lens(
                table.clone(),
                rc.fallback_dest.clone(),
                rc.server_names.clone(),
                "tcp".to_string(),
                rc.xver,
            );
            crate::LOG
                .info(format!("dest={} reality maxUselessRecords probe started", rc.fallback_dest));
            Arc::new(xray_reality::server::ProbeContext {
                table,
                dest: rc.fallback_dest.clone(),
                fallback: rc.max_useless_records,
            })
        });
    let ctx = build_context(config, local, handler);
    crate::LOG.info(format!("{local} listening TCP for XHTTP"));

    #[allow(
        clippy::disallowed_methods,
        reason = "数据面热路径豁免（坑约束⑫）+ ctx 不可达：splithttp 为 h2/h3 传输层，transport 无 PluginContext 注入面；本 allow 覆盖 2 处（TCP accept 循环 + 循环内每连接处理任务）；显式脱管：托管无收益（ctx 不可达），寿命随其所属连接/会话对象，句柄无需持有（bd hj3jf 裁定）"
    )]
    let accept_task = tokio::spawn(async move {
        loop {
            // 连接获取 + Tcpmask wrap（仅 TCP 分支）；None = 丢弃继续（accept
            // 瞬时错误已分类退避）。
            let Some((stream, peer)) =
                accept_xh_conn(&source, tcpmask.as_ref(), "splithttp", &local.to_string()).await
            else {
                continue;
            };
            let ctx = Arc::clone(&ctx);
            let tls = tls_cfg.clone();
            let rc = reality.clone();
            let probe = reality_probe.clone();
            tokio::spawn(async move {
                handle_accepted_stream(stream, peer, local, tls, rc, probe, ctx).await;
            });
        }
    });
    let tcp_abort = accept_task.abort_handle();
    // 意外退出监控：循环只应经 close() 的 abort 句柄退出；panic 会静默杀掉监听。
    #[allow(
        clippy::disallowed_methods,
        reason = "数据面热路径豁免（坑约束⑫）+ ctx 不可达：splithttp 为 h2/h3 传输层，transport 无 PluginContext 注入面；accept 循环意外退出监控任务；显式脱管：托管无收益（ctx 不可达），寿命随其所属连接/会话对象，句柄无需持有（bd hj3jf 裁定）"
    )]
    tokio::spawn(xray_transport::accept_policy::supervise_accept_loop(
        "splithttp",
        local.to_string(),
        accept_task,
    ));
    Ok(Box::new(SplithttpListener { local, tcp_abort: Some(tcp_abort), h3_endpoint: None }))
}

/// unix 路径 SplitHTTP 监听（对应 Go splithttp/hub.go:526-531 `port==0` 分支：
/// `net.UnixAddr` → `internet.ListenSystem`，TLS/REALITY/h1+h2c 服务层全复用）。
///
/// Go 该分支支持 `FinalMask.Listen(ctx, unixAddr)`；Rust tcpmask 为 TCP 语义
/// 载体，unix 上无对应能力——非空显式拒绝而非静默忽略（对齐 tcp/ws/httpupgrade
/// hub unix finalmask 拒绝惯例）。H3（QUIC）无 unix 载体，不在本入口范围。
#[cfg(unix)]
pub async fn listen_unix_splithttp(
    path: String,
    settings: StreamSettings,
    sockopt: SocketOptions,
    handler: ConnHandler,
) -> io::Result<Box<dyn TransportListener>> {
    if settings.finalmask_json.as_ref().is_some_and(|v| !v.is_null()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "finalmask is not supported on unix listeners; remove the finalmask key",
        ));
    }
    let config =
        Arc::new(crate::register::parse_splithttp_config(settings.transport_json.as_ref())?);
    let tls_cfg = xray_tls::server_config::build_server_config(
        &settings.security,
        settings.security_json.as_ref(),
    )?;

    let listener =
        xray_transport::system_listener::UnixListener::bind(&path, sockopt.clone()).await?;
    // unix socket 无 SocketAddr：全零占位（对齐 tcp/ws/httpupgrade hub unix 契约）。
    let local = SocketAddr::from(([0, 0, 0, 0], 0));
    let source = XhSource::Unix(listener);
    let reality = reality_server_config(&settings.security, settings.security_json.as_ref())?;
    let reality_probe =
        reality.as_ref().filter(|rc| rc.max_useless_records.is_enabled()).map(|rc| {
            let table = xray_reality::probe::ProbeTable::new();
            xray_reality::probe::detect_max_useless_records(
                table.clone(),
                rc.fallback_dest.clone(),
                rc.server_names.clone(),
                "unix".to_string(),
                rc.xver,
            );
            xray_reality::probe::detect_post_handshake_record_lens(
                table.clone(),
                rc.fallback_dest.clone(),
                rc.server_names.clone(),
                "unix".to_string(),
                rc.xver,
            );
            crate::LOG
                .info(format!("dest={} reality maxUselessRecords probe started", rc.fallback_dest));
            Arc::new(xray_reality::server::ProbeContext {
                table,
                dest: rc.fallback_dest.clone(),
                fallback: rc.max_useless_records,
            })
        });
    let ctx = build_context(&config, local, handler);
    crate::LOG.info(format!("{path} listening unix for XHTTP"));

    // 恒等 manager 占位（unix 无 finalmask，入口已拒绝非空配置）。
    let tcpmask = Some(Arc::new(xray_transport::finalmask::TcpmaskManager::new(Vec::new())));
    let log_ident = path.clone();
    #[allow(
        clippy::disallowed_methods,
        reason = "数据面热路径豁免（坑约束⑫）+ ctx 不可达：splithttp 为 h2/h3 传输层，transport 无 PluginContext 注入面；本 allow 覆盖 2 处（unix accept 循环 + 循环内每连接处理任务）；显式脱管：托管无收益（ctx 不可达），寿命随其所属连接/会话对象，句柄无需持有（bd hj3jf 裁定）"
    )]
    let accept_task = tokio::spawn(async move {
        loop {
            let Some((stream, peer)) =
                accept_xh_conn(&source, tcpmask.as_ref(), "splithttp-unix", &log_ident).await
            else {
                continue;
            };
            let ctx = Arc::clone(&ctx);
            let tls = tls_cfg.clone();
            let rc = reality.clone();
            let probe = reality_probe.clone();
            tokio::spawn(async move {
                handle_accepted_stream(stream, peer, local, tls, rc, probe, ctx).await;
            });
        }
    });
    let abort = accept_task.abort_handle();
    #[allow(
        clippy::disallowed_methods,
        reason = "数据面热路径豁免（坑约束⑫）+ ctx 不可达：splithttp 为 h2/h3 传输层，transport 无 PluginContext 注入面；unix accept 循环意外退出监控任务；显式脱管：托管无收益（ctx 不可达），寿命随其所属连接/会话对象，句柄无需持有（bd hj3jf 裁定）"
    )]
    tokio::spawn(xray_transport::accept_policy::supervise_accept_loop(
        "splithttp-unix",
        path,
        accept_task,
    ));
    Ok(Box::new(SplithttpListener { local, tcp_abort: Some(abort), h3_endpoint: None }))
}

/// 单个已 accept 的流：REALITY / TLS 包装 → h1+h2c HTTP 服务。
///
/// Go hub.go:551-560：TLS 与 REALITY 互斥包装（security 二选一），
/// hub.go:564-578：同一 http.Server 同时处理明文 HTTP/1.1 与 h2c。
async fn handle_accepted_stream<S>(
    stream: S,
    peer: SocketAddr,
    local: SocketAddr,
    tls: Option<Arc<rustls::ServerConfig>>,
    reality: Option<RealityServerConfig>,
    probe: Option<Arc<xray_reality::server::ProbeContext>>,
    ctx: Arc<HandlerContext>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if let Some(rc) = reality {
        serve_reality_conn(stream, peer, local, rc, probe, ctx).await;
    } else if let Some(tc) = tls {
        // Go hub.go:553-556 `gotls.NewListener`
        if let Ok(tls_stream) = tokio_rustls::TlsAcceptor::from(tc).accept(stream).await {
            serve_http_conn(tls_stream, peer, ctx).await;
        }
    } else {
        serve_http_conn(stream, peer, ctx).await;
    }
}

/// I/O 进度跟踪包装：记录最近一次 read/write 有实际进展的时刻，供空闲兜底判定
/// （bd lfeu）。纯透传，不改动字节流。
type ProgressClock = parking_lot::Mutex<Instant>;

struct ProgressIo<T> {
    inner: T,
    last_progress: Arc<ProgressClock>,
}

impl<T> ProgressIo<T> {
    // 赋值表达式语句位挂属性在本工具链 E0658（无 stmt_expr_attributes），故挂 fn 位。
    #[allow(
        clippy::disallowed_methods,
        reason = "数据面热路径豁免（坑约束⑫）+ ctx 不可达：splithttp 传输层无 Clock 注入面；IO 进展墙钟锚点（空闲兜底判定基准），FxScope/Clock 迁移收口见 bd 39hko"
    )]
    fn touch(&self) {
        *self.last_progress.lock() = Instant::now();
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for ProgressIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let filled_before = buf.filled().len();
        let r = Pin::new(&mut this.inner).poll_read(cx, buf);
        if matches!(r, Poll::Ready(Ok(()))) && buf.filled().len() > filled_before {
            this.touch();
        }
        r
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for ProgressIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let r = Pin::new(&mut this.inner).poll_write(cx, buf);
        if matches!(r, Poll::Ready(Ok(n)) if n > 0) {
            this.touch();
        }
        r
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// serve 空闲兜底驱动（bd lfeu）。每轮 `timeout(SERVE_IDLE_TIMEOUT)` 到点后复查
/// 真实 I/O 进度：静默/hard-close 连接在最后进度 +30s 内强杀释放 fd；窗口内有
/// 进度的连接续期下一轮——活跃传输（含 >30s 长流）不受硬杀。
///
/// serve future 经 `Box<dyn Future + Send>` 擦除：泛型 `Pin<&mut F>` 形态下
/// rustc 推不出 hyper `Serving` 的 Send（higher-ranked "not general enough"
/// 限制），trait 对象形态 Send 显式成立于类型本身。
async fn drive_serve_guarded(
    mut serve: Pin<Box<dyn Future<Output = ()> + Send>>,
    last_progress: &ProgressClock,
    max_idle: Duration,
) {
    loop {
        match tokio::time::timeout(max_idle, serve.as_mut()).await {
            Ok(()) => return,
            Err(_) => {
                if last_progress.lock().elapsed() >= max_idle {
                    return; // 真静默 30s → 强杀（N-1 fd 泄漏族兜底）
                }
            },
        }
    }
}

/// h1 + h2c 自动协商的 HTTP 服务。对应 Go hub.go:564-578
/// （`protocols.SetHTTP1(true)` + `SetUnencryptedHTTP2(true)` 的 http.Server）。
async fn serve_http_conn<S>(stream: S, peer: SocketAddr, ctx: Arc<HandlerContext>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    use hyper::service::service_fn;
    use hyper_util::rt::{TokioExecutor, TokioIo};

    #[allow(
        clippy::disallowed_methods,
        reason = "数据面热路径豁免（坑约束⑫）+ ctx 不可达：splithttp 传输层无 Clock 注入面；IO 进展墙钟初始锚点（空闲兜底判定基准），FxScope/Clock 迁移收口见 bd 39hko"
    )]
    let last_progress = Arc::new(ProgressClock::new(Instant::now()));
    let io = TokioIo::new(ProgressIo { inner: stream, last_progress: Arc::clone(&last_progress) });
    let svc = service_fn(move |req| {
        let ctx = Arc::clone(&ctx);
        async move { Ok::<_, std::convert::Infallible>(handler::handle_request(req, peer, &ctx).await) }
    });
    // bd lfeu：30s 外挂兜底——hyper h2 serve 对客户端 hard-close/静默对端不退出
    // （724cc20 ws serve_h2_reject 同族）。判定按 I/O 进度：静默连接最迟 30s 强杀；
    // 活跃传输（含 >30s 长流）持续续期，不受硬杀。
    // builder 由 async move 块持有：serve_connection 借用 &self，装箱 future
    // 生命周期超出本函数栈帧。
    let serve: Pin<Box<dyn Future<Output = ()> + Send>> = Box::pin(async move {
        let mut builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
        builder
            .http1()
            .timer(hyper_util::rt::TokioTimer::new())
            .header_read_timeout(READ_HEADER_TIMEOUT);
        // r2lq：默认 ALPN=["h2","http/1.1"]（xray-tls server_config.rs:246）时协商
        // 走 h2；无显式 .http2() 时 h2 路径落默认 Builder（Time::Empty），依赖 timer
        // 的路径 panic / 行为不完整。Go hub.go:564-578 同一 http.Server 启 h1+h2。
        builder
            .http2()
            .timer(hyper_util::rt::TokioTimer::new())
            // h2 连接级 keep-alive PING（Go ChromeH2KeepAlivePeriod=45s 同值）：
            // 双向对抗 NAT/中间盒空闲回收——CDN 100s idle 切断（#6554 场景）时，
            // 45s 周期 PING 维持连接活跃度。keep_alive_timeout 取 hyper 默认 20s。
            .keep_alive_interval(H2_KEEP_ALIVE_INTERVAL)
            // hyper h2 每流发送缓冲默认 400KB（DEFAULT_MAX_SEND_BUF_SIZE）——发送速率
            // 被钉在 min(send_buf, 客户端窗口)/RTT：400KB 时代高 BDP 路径钉 2.7MB/s；
            // 4MB 时代 min(4MB, Go 客户端 4MB)/0.45s≈8.8MB/s（bd enc8x 窗钉模型三组
            // 历史数字闭环）。16MB 配合客户端 16MB 流窗（dialer.rs 同批）→ 40-60MB/s。
            // Go 服务端无此上限（仅受客户端窗口约束）。
            .max_send_buf_size(16 * 1024 * 1024)
            // bd wz2b W2：hyper server h2 缺省收窗 1MB/1MB（proto/h2/server.rs:36-37），
            // 上行钉 1MB/RTT@169ms≈5.9MB/s（RTT50ms 实测 17.3MB/s，verify/audit-r2-w2-ab
            // U-A 组）。显式 16MB 流窗 + 32MB 连接窗 → U-B 组 210.7MB/s（12.2×）。窗=
            // SETTINGS 计数器零预分配，单连接聚合上限=32MB 连接窗。
            .initial_stream_window_size(16 * 1024 * 1024)
            .initial_connection_window_size(32 * 1024 * 1024);
        // ponytail: Go hub.go:571 MaxHeaderBytes（GetNormalizedServerMaxHeaderBytes）无
        // hyper 字节级对应（仅 max_headers 条数），默认值即 Go 默认 1MiB 量级，未接入。
        let _ = builder.serve_connection(io, svc).await;
    });
    drive_serve_guarded(serve, &last_progress, SERVE_IDLE_TIMEOUT).await;
}

// ===== REALITY（Go hub.go:558-560 goreality.NewListener 的 Rust 等价物） =====

/// REALITY 服务端配置（`realitySettings` JSON）。
#[derive(Clone)]
struct RealityServerConfig {
    private_key: [u8; 32],
    /// t38j：SNI 白名单（非空，parse 层硬错保证）；精确匹配，供 server_tls 前置门。
    server_names: Vec<String>,
    short_ids: Vec<[u8; 8]>,
    max_time_diff: u32,
    /// fs0o: 客户端 TLS legacy_version 最小版本门控（字节字典序）；
    /// `Vec::new()`=不限制（兼容旧配置）。
    min_client_ver: Vec<u8>,
    /// fs0o: 客户端 TLS legacy_version 最大版本门控。
    max_client_ver: Vec<u8>,
    fallback_dest: String,
    xver: u8,
    /// bd frxi：启动期 CCS 探测开关（缺省 Disabled 保持现行为）。
    max_useless_records: xray_reality::MaxUselessRecordsSetting,
    /// bd tce2：TLS acceptor 选择（缺省 Rustls 保持现行为）。
    server_acceptor: xray_reality::ServerAcceptorSetting,
}

/// security == "reality" 时解析服务端 REALITY 配置，否则返回 None。
fn reality_server_config(
    security: &str,
    json: Option<&serde_json::Value>,
) -> io::Result<Option<RealityServerConfig>> {
    if security != "reality" {
        return Ok(None);
    }
    let json = json.ok_or_else(|| io::Error::other("reality: missing realitySettings"))?;
    let key_str = json
        .get("privateKey")
        .and_then(|v| v.as_str())
        .ok_or_else(|| io::Error::other("reality: missing privateKey"))?;
    let private_key = <[u8; 32]>::try_from(base64_url_decode(key_str)?)
        .map_err(|_| io::Error::other("reality: privateKey must be 32 bytes"))?;
    // t38j：serverNames 非空硬错（Go transport_security.go:94-96），
    // 与 xray-core inbound.rs 的 parse_reality_config 同语义（同族路径对齐）。
    let mut server_names = Vec::new();
    if let Some(arr) = json.get("serverNames").and_then(|x| x.as_array()) {
        for v in arr {
            let Some(name) = v.as_str() else {
                return Err(io::Error::other("reality: invalid serverNames entry (need string)"));
            };
            server_names.push(name.to_string());
        }
    }
    if server_names.is_empty() {
        return Err(io::Error::other("reality: empty \"serverNames\""));
    }

    // 257w 同族：shortIds 三重硬错对齐 Go transport_security.go:135-147
    // （空数组/过长/奇数或非法 hex 拒启），合法项左对齐补零 8 字节。
    let sid_arr = json
        .get("shortIds")
        .and_then(|x| x.as_array())
        .ok_or_else(|| io::Error::other("reality: empty \"shortIds\""))?;
    if sid_arr.is_empty() {
        return Err(io::Error::other("reality: empty \"shortIds\""));
    }
    let mut short_ids = Vec::with_capacity(sid_arr.len());
    for (i, sid) in sid_arr.iter().enumerate() {
        let Some(hex) = sid.as_str() else {
            return Err(io::Error::other(format!(
                "reality: invalid \"shortIds[{i}]\" (need hex string)"
            )));
        };
        if hex.len() > 16 {
            return Err(io::Error::other(format!("reality: too long \"shortIds[{i}]\": {hex}")));
        }
        let bytes = hex::decode(hex)
            .map_err(|_| io::Error::other(format!("reality: invalid \"shortIds[{i}]\": {hex}")))?;
        let mut id = [0u8; 8];
        id[..bytes.len()].copy_from_slice(&bytes);
        short_ids.push(id);
    }

    // dest/target：int（端口→localhost:port）或字符串 host:port
    let dest_raw =
        json.get("target").or_else(|| json.get("dest")).cloned().unwrap_or(serde_json::Value::Null);
    let fallback_dest = match dest_raw.as_u64() {
        Some(port) => format!("localhost:{port}"),
        None => dest_raw.as_str().unwrap_or("localhost:443").to_string(),
    };
    let xver = json.get("xver").and_then(|x| x.as_u64()).unwrap_or(0).min(2) as u8;
    // bd frxi：realitySettings.maxUselessRecords 三态（缺省/true/数值）。
    let max_useless_records =
        xray_reality::MaxUselessRecordsSetting::from_json(json.get("maxUselessRecords"))
            .map_err(io::Error::other)?;
    // bd tce2：realitySettings.serverAcceptor（"rustls" 默认 / "btls" opt-in）。
    let server_acceptor =
        xray_reality::ServerAcceptorSetting::from_json(json.get("serverAcceptor"))
            .map_err(io::Error::other)?;
    // mldsa65Seed：后量子签名未实现（cz5x）。配置在场即显式报错，
    // 不静默忽略——避免运营者误以为 PQC 已生效。
    if let Some(seed) = json.get("mldsa65Seed").and_then(|x| x.as_str()) {
        if !seed.is_empty() {
            return Err(io::Error::other(
                "reality: mldsa65Seed configured but ML-DSA-65 signing is not implemented \
                 in Rust (remove mldsa65Seed or use a Go server)",
            ));
        }
    }
    // maxTimeDiff：Go 默认 0（禁用），单位毫秒 → 转换为秒传给 verify。
    // 之前注入 43200 + 按秒解释 = 三重语义偏差（详见 docs/audit/crypto.md）。
    let max_time_diff_ms = json.get("maxTimeDiff").and_then(|x| x.as_u64()).unwrap_or(0);
    let max_time_diff = (max_time_diff_ms / 1000) as u32;

    // fs0o: 解析 minClientVer/maxClientVer（"26.3.27" → `[26, 3, 27]`）。
    // 镜像 Go `infra/conf/transport_security.go` 103-130：split(".") → u8 数组。
    let parse_version = |key: &str| -> io::Result<Vec<u8>> {
        let Some(s) = json.get(key).and_then(|v| v.as_str()) else {
            return Ok(Vec::new());
        };
        let mut v = Vec::new();
        for (i, part) in s.split('.').enumerate() {
            if i >= 3 {
                return Err(io::Error::other(format!(
                    "reality: invalid {key}: too many segments (max 3)"
                )));
            }
            let n: u64 = part.parse().map_err(|e| {
                io::Error::other(format!("reality: invalid {key} segment '{part}': {e}"))
            })?;
            if n > 255 {
                return Err(io::Error::other(format!("reality: {key} segment {n} > 255")));
            }
            v.push(n as u8);
        }
        Ok(v)
    };
    let min_client_ver = parse_version("minClientVer")?;
    let max_client_ver = parse_version("maxClientVer")?;

    Ok(Some(RealityServerConfig {
        private_key,
        server_names,
        short_ids,
        max_time_diff,
        min_client_ver,
        max_client_ver,
        fallback_dest,
        xver,
        max_useless_records,
        server_acceptor,
    }))
}

/// REALITY 握手：Verified → h1/h2c 服务；Invalid → 透明转发 fallback dest。
///
/// 镜像 Go `goreality.NewListener`（xtls/reality 库内置 fallback），Rust 侧组合
/// `xray_reality::server::server_tls` + `fallback_to_dest`（与 xray-core inbound
/// 的 VLESS+REALITY 路径同构）。
async fn serve_reality_conn<S>(
    stream: S,
    peer: SocketAddr,
    local: SocketAddr,
    rc: RealityServerConfig,
    probe: Option<Arc<xray_reality::server::ProbeContext>>,
    ctx: Arc<HandlerContext>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    use xray_reality::server::{RealityServerOutcome, server_tls};

    // bd tce2：serverAcceptor="btls" 走 BoringSSL 握手（含 26zn 后握手记录
    // 模仿消费）；默认 rustls 路径行为不变。
    let outcome = if matches!(rc.server_acceptor, xray_reality::ServerAcceptorSetting::Btls) {
        #[cfg(not(target_os = "ios"))]
        {
            xray_reality::server::server_tls_btls(
                stream,
                &rc.private_key,
                &rc.short_ids,
                rc.max_time_diff,
                &rc.min_client_ver,
                &rc.max_client_ver,
                &rc.server_names,
                probe.as_deref(),
            )
            .await
        }
        #[cfg(target_os = "ios")]
        {
            xray_reality::server::server_tls(
                stream,
                &rc.private_key,
                &rc.short_ids,
                rc.max_time_diff,
                &rc.min_client_ver,
                &rc.max_client_ver,
                &rc.server_names,
                probe.as_deref(),
            )
            .await
        }
    } else {
        server_tls(
            stream,
            &rc.private_key,
            &rc.short_ids,
            rc.max_time_diff,
            &rc.min_client_ver,
            &rc.max_client_ver,
            &rc.server_names,
            probe.as_deref(),
        )
        .await
    };
    match outcome {
        Ok(RealityServerOutcome::Verified { tls, max_useless_records }) => {
            // bd frxi：探测值随连接交付（rustls 无 record 层消费点，
            // mygg 后握手记录模仿落地前仅可观察）。
            crate::LOG.debug(format!("peer={peer} max_useless_records={max_useless_records} reality verified with probe result"));
            serve_http_conn(tls, peer, ctx).await
        },
        Ok(RealityServerOutcome::Invalid { conn, record, reason }) => {
            crate::LOG.debug(format!(
                "error={reason:?} dest={} splithttp reality fallback",
                rc.fallback_dest
            ));
            let _ = fallback_to_dest(conn, &record, &rc.fallback_dest, peer, local, rc.xver).await;
        },
        Err(e) => crate::LOG.warn(format!("error={e} splithttp reality handshake error")),
    }
}

/// base64 RawURL 解码（无 padding，兼容 std 变体）。
fn base64_url_decode(s: &str) -> io::Result<Vec<u8>> {
    let normalized = s.replace('+', "-").replace('/', "_");
    let normalized = normalized.trim_end_matches('=');
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(normalized)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(s))
        .map_err(|e| io::Error::other(format!("reality: base64 privateKey: {e}")))
}

// ===== H3（Go hub.go:481-535：UDP + QUIC + http3.Server） =====

/// H3 监听：UDP socket + QUIC endpoint + h3 server accept 循环。
///
/// `quinn::Endpoint::server` 等价 Go `ListenSystemPacket` + `quic.ListenEarly` 的组合。
/// ponytail: Go QuicParams（hub.go:498-514 InitStreamReceiveWindow/BBR 等）未在 Rust
/// 配置层建模，用 quinn 默认 TransportConfig；接入时在此覆盖 transport_config。
/// ListenEarly 的 0-RTT 接受同样依赖 rustls max_early_data_size，未启用。
async fn listen_h3(
    addr: SocketAddr,
    tls: Arc<rustls::ServerConfig>,
    config: &Arc<Config>,
    sockopt: &SocketOptions,
    handler: ConnHandler,
) -> io::Result<Box<dyn TransportListener>> {
    let quic_server = quinn::crypto::rustls::QuicServerConfig::try_from((*tls).clone())
        .map_err(|e| io::Error::other(format!("rustls→quic server: {e}")))?;
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server));
    let std_sock = xray_transport::sockopt::bind_udp_endpoint(addr, sockopt)?;
    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config),
        std_sock,
        Arc::new(quinn::TokioRuntime),
    )?;
    let local = endpoint.local_addr()?;
    // endpoint clone 给 listener 句柄；本体 move 进 accept task。
    let ctx = build_context(config, local, handler);
    crate::LOG.info(format!("{local} listening QUIC for XHTTP/3"));

    let listener_endpoint = endpoint.clone();
    // accept 循环托管（bd x2ywg）：panic 后 endpoint clone 仍留在 listener 句柄里，
    // UDP 端口保持绑定但永不 accept——监听的死必须留痕（accept_policy 铁律 3）。
    spawn_supervised_h3_accept(local, async move {
        while let Some(incoming) = endpoint.accept().await {
            let ctx = Arc::clone(&ctx);
            #[allow(
                clippy::disallowed_methods,
                reason = "数据面热路径豁免（坑约束⑫）+ ctx 不可达：splithttp 为 h2/h3 传输层，transport 无 PluginContext 注入面；QUIC 循环内每连接处理任务；显式脱管：托管无收益（ctx 不可达），寿命随其所属连接/会话对象，句柄无需持有（bd hj3jf 裁定）"
            )]
            tokio::spawn(async move {
                let conn = match incoming.await {
                    Ok(c) => c,
                    Err(_) => return,
                };
                serve_h3_conn(conn, ctx).await;
            });
        }
    });
    Ok(Box::new(SplithttpListener { local, tcp_abort: None, h3_endpoint: Some(listener_endpoint) }))
}

/// H3 accept 循环 spawn + 意外退出监督（bd x2ywg）。
///
/// 循环唯一合法退出是 listener `close()`（endpoint 关闭 → `accept` 返回 `None`）；
/// panic 则监听静默消失——endpoint 的另一 clone 留在 `SplithttpListener` 里，
/// UDP 端口仍绑定但永不 accept（`accept_policy` 铁律 3：意外退出必须 `error!` 留痕）。
fn spawn_supervised_h3_accept(local: SocketAddr, body: impl Future<Output = ()> + Send + 'static) {
    #[allow(
        clippy::disallowed_methods,
        reason = "数据面 QUIC accept 泵（splithttp h3 listener）；显式脱管：ctx 不可达（transport 层无 PluginContext）+ 寿命随 endpoint close，句柄仅作监控入参（bd hj3jf）"
    )]
    let accept_task = tokio::spawn(body);
    #[allow(
        clippy::disallowed_methods,
        reason = "accept 循环意外退出监控（panic 留痕）；显式脱管：寿命随被监控的 accept 任务（bd hj3jf）"
    )]
    tokio::spawn(xray_transport::accept_policy::supervise_accept_loop(
        "splithttp-h3",
        local.to_string(),
        accept_task,
    ));
}

/// 单个 QUIC 连接：h3 server handshake → accept 请求循环。
async fn serve_h3_conn(conn: quinn::Connection, ctx: Arc<HandlerContext>) {
    let mut h3_conn =
        match h3::server::Connection::new(h3_quinn::Connection::new(conn.clone())).await {
            Ok(c) => c,
            Err(_) => return,
        };
    while let Ok(Some(resolver)) = h3_conn.accept().await {
        let ctx = Arc::clone(&ctx);
        let conn = conn.clone();
        let peer = conn.remote_address();
        #[allow(
            clippy::disallowed_methods,
            reason = "数据面热路径豁免（坑约束⑫）+ ctx 不可达：splithttp 为 h2/h3 传输层，transport 无 PluginContext 注入面；h3 每请求任务（+ 请求体桥接任务 + 连接终结 abort 任务）；显式脱管：托管无收益（ctx 不可达），寿命随其所属连接/会话对象，句柄无需持有（bd hj3jf 裁定）"
        )]
        tokio::spawn(async move {
            let Ok((req, stream)) = resolver.resolve_request().await else {
                return;
            };
            let task = tokio::spawn(serve_h3_request(req, stream, peer, Arc::clone(&ctx)));
            // 连接终结（客户端断开 / idle / error）必须强制终结该连接上的全部
            // 请求——对齐 Go hub.go:394-398 `request.Context().Done()` 中断
            // handler + `defer conn.Close()`：abort 触发 response body（含
            // SessionDropGuard）drop，会话删除 + queue.close + ServerConn 上行
            // EOF 级联，hub copy / forward / dispatcher 桥全链解体。否则
            // response body 循环滞留至永久（实测 100%/conn 死锁，s12 泄漏根因）。
            let closer = conn.clone();
            tokio::spawn(async move {
                let _ = closer.closed().await;
                task.abort();
            });
        });
    }
}

/// h3 服务端请求流（bidi）。split 后 send/recv 两半分属不同 task。
type H3ServerStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

/// 单个 h3 请求：请求体桥接为 `ReqBody` 喂给 hub handler，响应帧序列发回。
///
/// 对应 Go `http3.Server{Handler: requestHandler}`——同一 handler 服务 h1/h2/h3。
/// stream-up 需边收上传 body 边发响应，故 split（h3 RequestStream::split 官方支持）。
async fn serve_h3_request(
    req: http::Request<()>,
    stream: H3ServerStream,
    peer: SocketAddr,
    ctx: Arc<HandlerContext>,
) {
    let (send_half, recv_half) = stream.split();
    let (parts, ()) = req.into_parts();
    let req = http::Request::from_parts(parts, H3RecvBody { stream: recv_half });

    let resp = handler::handle_request(req, peer, &ctx).await;

    let (parts, mut body) = resp.into_parts();
    let mut send = send_half;
    if send.send_response(http::Response::from_parts(parts, ())).await.is_err() {
        return;
    }
    while let Some(frame) = body.frame().await {
        let Ok(frame) = frame else { break };
        if let Ok(data) = frame.into_data() {
            if send.send_data(data).await.is_err() {
                return;
            }
        }
    }
    let _ = send.finish().await;
}

/// h3 请求体 → `http_body::Body` 桥接。
///
/// `poll_recv_data` 是注册函数（非 async），可直接在 `poll_frame` 里调用。
struct H3RecvBody {
    stream: h3::server::RequestStream<h3_quinn::RecvStream, Bytes>,
}

impl hyper::body::Body for H3RecvBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Bytes>, io::Error>>> {
        match self.stream.poll_recv_data(cx) {
            Poll::Ready(Ok(Some(mut chunk))) => {
                let n = chunk.remaining();
                Poll::Ready(Some(Ok(hyper::body::Frame::data(chunk.copy_to_bytes(n)))))
            },
            Poll::Ready(Ok(None)) => Poll::Ready(None),
            Poll::Ready(Err(e)) => {
                Poll::Ready(Some(Err(io::Error::other(format!("h3 recv_data: {e}")))))
            },
            Poll::Pending => Poll::Pending,
        }
    }
}

// ===== hub handler ↔ listener registry 适配 =====

/// 构造 hub handler 上下文（镜像 `HubListener::serve` 的构造）。
fn build_context(
    config: &Arc<Config>,
    local: SocketAddr,
    handler: ConnHandler,
) -> Arc<HandlerContext> {
    Arc::new(HandlerContext {
        config: Arc::clone(config),
        host: config.host.clone(),
        base_path: config.normalized_path(),
        local_addr: local,
        sessions: Arc::new(SessionMap::new()),
        conn_handler: Arc::new(ConnHandlerAdapter(handler)),
        max_buffered_posts: config.normalized_sc_max_buffered_posts() as usize,
        sc_max_each_post_bytes: config.normalized_sc_max_each_post_bytes().to as usize,
    })
}

/// `ConnHandler`（registry 的 `Arc<dyn Fn(Box<dyn Connection>)>`）→ `HubConnHandler`。
///
/// `ServerConn` 的 box 字段非 `Sync`，不满足 `Connection: Sync` 约束，故沿用
/// duplex bridge 模式：`tokio::io::duplex` 一端交 registry handler（`DuplexConn`），
/// 另一端与 `ServerConn` 的 reader/writer 双向 copy。
struct ConnHandlerAdapter(ConnHandler);

impl HubConnHandler for ConnHandlerAdapter {
    fn add_conn(&self, conn: ServerConn) {
        let (client, server) = tokio::io::duplex(DUPLEX_BUF);
        let remote = conn.remote_addr;
        let local = conn.local_addr;
        (self.0)(Box::new(DuplexConn { inner: client, remote: Some(remote), local: Some(local) }));
        #[allow(
            clippy::disallowed_methods,
            reason = "数据面热路径豁免（坑约束⑫）+ ctx 不可达：splithttp 为 h2/h3 传输层，transport 无 PluginContext 注入面；duplex 双向 copy 桥任务（ServerConn ↔ registry handler）；显式脱管：托管无收益（ctx 不可达），寿命随其所属连接/会话对象，句柄无需持有（bd hj3jf 裁定）"
        )]
        tokio::spawn(async move {
            let ServerConn { reader: mut up, writer: mut down, .. } = conn;
            let (mut rd, mut wr) = tokio::io::split(server);
            // 上行（客户端上传 → dispatcher 读）/ 下行（dispatcher 写 → HTTP 响应）。
            // 显式 64KB 缓冲：tokio::io::copy 内部 DEFAULT_BUF_SIZE=8KB 会把 DATA
            // 帧粒度钉死在 8KB，高 RTT 路径帧数放大 ~8x（对照 Go dispatcher
            // MultiBuffer 合并写）。
            let a = copy_large(&mut up, &mut wr);
            let b = copy_large(&mut rd, &mut down);
            let _ = tokio::join!(a, b);
        });
    }
}

/// 64KB 缓冲单向拷贝（替代 [`tokio::io::copy`] 的 8KB 内部缓冲）。
/// 错误传播语义一致：Err 即终止该方向；调用方 `join!` 吞返回值（原语义）。
async fn copy_large<R: tokio::io::AsyncRead + Unpin, W: tokio::io::AsyncWrite + Unpin>(
    r: &mut R,
    w: &mut W,
) -> std::io::Result<u64> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = vec![0u8; DUPLEX_BUF];
    let mut total = 0u64;
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        w.write_all(&buf[..n]).await?;
        total += n as u64;
    }
    w.flush().await?;
    Ok(total)
}

/// duplex 半部，满足 `Connection: AsyncRead + AsyncWrite + Send + Sync + Unpin`。
struct DuplexConn {
    inner: tokio::io::DuplexStream,
    remote: Option<SocketAddr>,
    local: Option<SocketAddr>,
}

impl AsyncRead for DuplexConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for DuplexConn {
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

impl Connection for DuplexConn {
    fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(self.remote)
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(self.local)
    }
}

/// listener 句柄。对应 Go `Listener`（h3listener/listener 二选一）。
/// 两条监听形态各持一个关闭句柄：TCP 分支 abort accept task（TcpListener drop
/// 释放端口），H3 分支直接关 QUIC endpoint（对齐 Go tr.Close()）。
struct SplithttpListener {
    local: SocketAddr,
    tcp_abort: Option<tokio::task::AbortHandle>,
    h3_endpoint: Option<quinn::Endpoint>,
}

impl TransportListener for SplithttpListener {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }

    fn close(&self) -> io::Result<()> {
        crate::LOG.info(format!("splithttp listener close addr={}", self.local));
        if let Some(task) = &self.tcp_abort {
            task.abort();
        }
        if let Some(ep) = &self.h3_endpoint {
            ep.close(quinn::VarInt::from_u32(0), b"listener closed");
        }
        Ok(())
    }
}

impl Drop for SplithttpListener {
    fn drop(&mut self) {
        // v7nqa：停机只 drop 监听句柄 → 不关则 accept task / QUIC endpoint 继续
        // 持有 socket（Go worker.close 显式 hub.Close()，worker.go:151-158；
        // splithttp 侧 hub.go:588-591）。
        let _ = TransportListener::close(self);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::TcpStream,
    };

    use super::*;

    /// 捕获日志 (级别, message)：xray-transport-splithttp 无 tracing-subscriber
    /// dev-dep（不动 Cargo.toml），手写最小 Subscriber 足够断言留痕。
    struct CaptureLogs(Arc<std::sync::Mutex<Vec<String>>>);

    impl tracing::Subscriber for CaptureLogs {
        fn enabled(&self, _meta: &tracing::Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, _attrs: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _a: &tracing::span::Id, _b: &tracing::span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            struct MsgVisitor(String);
            impl tracing::field::Visit for MsgVisitor {
                fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                    if field.name() == "message" {
                        self.0.push_str(value);
                    }
                }

                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    if field.name() == "message" {
                        self.0.push_str(&format!("{value:?}"));
                    }
                }
            }
            let mut v = MsgVisitor(String::new());
            event.record(&mut v);
            let line = format!("{} {}", event.metadata().level(), v.0);
            self.0.lock().expect("log capture lock").push(line);
        }

        fn enter(&self, _span: &tracing::span::Id) {}

        fn exit(&self, _span: &tracing::span::Id) {}
    }

    /// x2ywg 判别器：H3 accept 循环 panic 后必须 error! 留痕（否则 endpoint clone
    /// 留在 listener 里 = 端口仍绑、永不 accept、零线索）。删掉
    /// [`spawn_supervised_h3_accept`] 里的 `supervise_accept_loop` → 本测试红。
    #[tokio::test]
    async fn h3_accept_loop_panic_is_reported() {
        let logs = Arc::new(std::sync::Mutex::new(Vec::new()));
        let _guard = tracing::subscriber::set_default(CaptureLogs(Arc::clone(&logs)));
        let addr: SocketAddr = "127.0.0.1:8443".parse().expect("addr");
        spawn_supervised_h3_accept(addr, async { panic!("h3 accept loop exploded") });
        // 监督 task 与被监督 task 的调度次序不确定：墙钟截止轮询等到监控落日志
        // （取时走 clock 端口，裸 Instant::now 被 lint 禁）
        let deadline = xray_frame::compat::clock().now_instant() + Duration::from_secs(5);
        loop {
            if !logs.lock().expect("log capture lock").is_empty() {
                break;
            }
            assert!(
                xray_frame::compat::clock().now_instant() < deadline,
                "accept 循环 panic 无任何日志 = 静默死亡（端口仍绑、永不 accept）"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let got = logs.lock().expect("log capture lock");
        assert!(
            got.iter().any(|m| m.contains("ERROR")
                && m.contains("splithttp-h3")
                && m.contains("127.0.0.1:8443")
                && m.contains("h3 accept loop exploded")),
            "意外退出必须 error 级留痕（含 tag/local/panic 摘要），实际: {got:?}"
        );
    }

    /// 服务端 h2 keep-alive PING 接线（wp9o 形态：hyper server http2 Builder
    /// 无配置 getter——断言常量值 + setter 链可调用；不 serve）。
    #[test]
    fn h2_keep_alive_wired_at_45s() {
        assert_eq!(H2_KEEP_ALIVE_INTERVAL, Duration::from_secs(45));
        let mut builder =
            hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
        let _h2 = builder
            .http2()
            .timer(hyper_util::rt::TokioTimer::new())
            .keep_alive_interval(H2_KEEP_ALIVE_INTERVAL);
    }

    fn ensure_provider() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    /// echo 型 ConnHandler：每收到 ServerConn 即写一条下行消息后放弃（触发响应 body EOF）。
    fn greeting_handler() -> (ConnHandler, Arc<AtomicUsize>) {
        let count = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&count);
        let h: ConnHandler = Arc::new(move |conn: Box<dyn Connection>| {
            c.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut conn = conn;
                let _ = conn.write_all(b"hello-from-server").await;
                let _ = conn.flush().await;
                // drop → 下行 EOF → 响应 body 结束
            });
        });
        (h, count)
    }

    fn plain_settings() -> StreamSettings {
        StreamSettings { protocol: "splithttp".into(), ..Default::default() }
    }

    /// h1 客户端接入（stream-one）：明文 HTTP/1.1 GET → 200 + 下行数据。
    /// 验证 hyper auto 的 h1 兼容（Go hub.go:566 SetHTTP1(true)）。
    ///
    /// padding：Go 服务端对空 padding 恒 400（hub.go:141-148 + IsPaddingValid ""
    /// → false 无豁免），真实客户端恒携带 `?x_padding=`（FillStreamRequest，默认
    /// range 100..1000）——裸请求须同样携带，否则测的是 Go 会拒的非协议行为。
    #[tokio::test]
    async fn h1_client_stream_one_roundtrip() {
        let (handler, count) = greeting_handler();
        let listener = listen_splithttp(
            "127.0.0.1:0".parse().unwrap(),
            &plain_settings(),
            &SocketOptions::default(),
            handler,
        )
        .await
        .expect("listen");
        let addr = listener.local_addr().unwrap();

        let mut tcp = TcpStream::connect(addr).await.expect("connect");
        // 100 个 'X'：默认 xPaddingBytes range 100..1000 的下界（repeat-x 按字节计长）。
        tcp.write_all(
            format!(
                "GET /?x_padding={} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
                "X".repeat(100)
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        let mut resp = Vec::new();
        tcp.read_to_end(&mut resp).await.unwrap();
        let text = String::from_utf8_lossy(&resp);
        assert!(text.contains("200"), "h1 status line missing: {text}");
        assert!(text.contains("hello-from-server"), "h1 stream-one download missing: {text}");
        assert_eq!(count.load(Ordering::SeqCst), 1, "handler should see 1 conn");
    }

    /// H3 server 接收：alpn=["h3"] → QUIC listener；quinn+h3 客户端 GET stream-one。
    #[tokio::test]
    async fn h3_server_receives_stream_one() {
        ensure_provider();
        let (handler, count) = greeting_handler();
        let mut settings = plain_settings();
        settings.security = "tls".into();
        settings.security_json = Some(serde_json::json!({ "alpn": ["h3"] }));
        let listener = listen_splithttp(
            "127.0.0.1:0".parse().unwrap(),
            &settings,
            &SocketOptions::default(),
            handler,
        )
        .await
        .expect("listen h3");
        let addr = listener.local_addr().unwrap();

        // quinn + h3 客户端（自签证书 → allowInsecure）
        let client_tls = xray_tls::client_config::build_client_config(
            "tls",
            Some(&serde_json::json!({"allowInsecure": true, "alpn": ["h3"]})),
            "127.0.0.1",
        )
        .unwrap()
        .expect("client tls config");
        let quic_cfg = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_tls).unwrap(),
        ));
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(quic_cfg);
        let conn = endpoint.connect(addr, "127.0.0.1").unwrap().await.expect("quic connect");
        let (mut driver, mut send_req) =
            h3::client::new(h3_quinn::Connection::new(conn)).await.unwrap();
        tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        let req = http::Request::builder()
            .method("GET")
            // padding：Go 服务端对空 padding 恒 400（IsPaddingValid），真实客户端
            // （FillStreamRequest）恒携带；与 h1 roundtrip 同理。
            .uri(format!("/?x_padding={}", "X".repeat(100)))
            .header("host", format!("127.0.0.1:{}", addr.port()))
            .body(())
            .unwrap();
        let mut stream = send_req.send_request(req).await.unwrap();
        stream.finish().await.unwrap();

        let resp = stream.recv_response().await.expect("h3 response");
        assert_eq!(resp.status(), 200);
        let mut got = Vec::new();
        loop {
            match stream.recv_data().await {
                Ok(Some(mut chunk)) => {
                    let n = chunk.remaining();
                    got.extend_from_slice(&chunk.copy_to_bytes(n));
                },
                Ok(None) => break,
                Err(e) => panic!("h3 recv_data: {e}"),
            }
        }
        assert_eq!(got, b"hello-from-server");
        assert_eq!(count.load(Ordering::SeqCst), 1, "handler should see 1 conn");
        drop(send_req);
        drop(endpoint);
    }

    /// REALITY listener 创建 + 非 REALITY 流量 fallback：
    /// 垃圾字节 ClientHello → Invalid → 透明转发 dest（goreality.NewListener 语义）。
    #[tokio::test]
    async fn reality_listener_creation_and_fallback() {
        ensure_provider();
        // fallback dest listener
        let fb = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fb_addr = fb.local_addr().unwrap();
        let (fb_tx, fb_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut s, _) = fb.accept().await.expect("fallback accept");
            let mut buf = vec![0u8; 128];
            let n = s.read(&mut buf).await.unwrap_or(0);
            buf.truncate(n);
            let _ = fb_tx.send(buf);
        });

        let (handler, count) = greeting_handler();
        let mut settings = plain_settings();
        settings.security = "reality".into();
        settings.security_json = Some(serde_json::json!({
            "privateKey": base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode([7u8; 32]),
            "serverNames": ["localhost"],
            "shortIds": [""],
            "dest": format!("127.0.0.1:{}", fb_addr.port()),
            "xver": 0,
        }));
        let listener = listen_splithttp(
            "127.0.0.1:0".parse().unwrap(),
            &settings,
            &SocketOptions::default(),
            handler,
        )
        .await
        .expect("reality listener created");
        let addr = listener.local_addr().unwrap();

        // 非 REALITY 客户端：垃圾字节 → 验证失败 → fallback 转发原文
        let mut tcp = TcpStream::connect(addr).await.expect("connect");
        // 构造可完整读取但解析必失败的 ClientHello record（content_type=0x16, len=5）：
        // read_tls_record Ok → parse_client_hello Err → Invalid → fallback 转发 record 原文。
        // （纯随机垃圾若 length 字段 >16384 会让 read_tls_record 直接 Err，走 handshake
        // error 分支不 fallback——与 Go goreality 读错误即断连一致。）
        let garbage: &[u8] = &[0x16, 0x03, 0x01, 0x00, 0x05, b'G', b'A', b'R', b'B', b'A'];
        tcp.write_all(garbage).await.unwrap();
        let _ = tcp.shutdown().await;
        let got = tokio::time::timeout(std::time::Duration::from_secs(5), fb_rx)
            .await
            .expect("fallback within 5s")
            .expect("fallback channel open");
        assert!(got.starts_with(garbage), "fallback should receive original record, got {got:?}");
        assert_eq!(count.load(Ordering::SeqCst), 0, "fallback conn must not reach dispatcher");
    }
    /// TCP 分支：close() abort accept task → TcpListener drop → 端口释放
    /// （票 4kjs 回归锚：修复前 close 仅日志，连接一直成功）。
    #[tokio::test]
    async fn close_rejects_new_tcp_connections() {
        let (handler, _count) = greeting_handler();
        let listener = listen_splithttp(
            "127.0.0.1:0".parse().unwrap(),
            &plain_settings(),
            &SocketOptions::default(),
            handler,
        )
        .await
        .expect("listen");
        let addr = listener.local_addr().unwrap();

        listener.close().unwrap();

        // abort → socket drop 是异步的：轮询直至 connect 被拒。
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            match TcpStream::connect(addr).await {
                Err(_) => break,
                Ok(_) => {
                    assert!(
                        tokio::time::Instant::now() < deadline,
                        "close 后端口仍接受连接（accept task 未终止）"
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                },
            }
        }
    }

    /// v7nqa 回归锚：停机只 drop 监听句柄、不显式 close()——无 `Drop → close`
    /// 兜底时 accept task 继续持有 TcpListener，端口在进程内继续 accept。
    #[tokio::test]
    async fn drop_without_close_rejects_new_tcp_connections() {
        let (handler, _count) = greeting_handler();
        let listener = listen_splithttp(
            "127.0.0.1:0".parse().unwrap(),
            &plain_settings(),
            &SocketOptions::default(),
            handler,
        )
        .await
        .expect("listen");
        let addr = listener.local_addr().unwrap();
        TcpStream::connect(addr).await.expect("drop 前应可连接");

        drop(listener); // 只 drop，不调 close——走 Drop 兜底

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            match TcpStream::connect(addr).await {
                Err(_) => break,
                Ok(_) => {
                    assert!(
                        tokio::time::Instant::now() < deadline,
                        "drop 后端口仍接受连接（Drop→close 未生效/accept task 未终止）"
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                },
            }
        }
    }

    /// H3 分支：close() 关 QUIC endpoint → 新 QUIC 握手失败（对齐 Go tr.Close()）。
    #[tokio::test]
    async fn close_rejects_new_h3_connections() {
        ensure_provider();
        let (handler, _count) = greeting_handler();
        let mut settings = plain_settings();
        settings.security = "tls".into();
        settings.security_json = Some(serde_json::json!({ "alpn": ["h3"] }));
        let listener = listen_splithttp(
            "127.0.0.1:0".parse().unwrap(),
            &settings,
            &SocketOptions::default(),
            handler,
        )
        .await
        .expect("listen h3");
        let addr = listener.local_addr().unwrap();

        listener.close().unwrap();

        let client_tls = xray_tls::client_config::build_client_config(
            "tls",
            Some(&serde_json::json!({"allowInsecure": true, "alpn": ["h3"]})),
            "127.0.0.1",
        )
        .unwrap()
        .expect("client tls config");
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(quinn::IdleTimeout::from(quinn::VarInt::from_u32(1_000))));
        let mut quic_cfg = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_tls).unwrap(),
        ));
        quic_cfg.transport_config(Arc::new(transport));
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(quic_cfg);

        let result = endpoint.connect(addr, "127.0.0.1").unwrap().await;
        assert!(result.is_err(), "post-close h3 connect must fail");
        endpoint.close(0u32.into(), b"test done");
    }

    /// bd lfeu：静默连接在空闲窗内被兜底强杀——pending 的挂死 serve 在
    /// max_idle 到点后被 drive_serve_guarded 切断（生产传 SERVE_IDLE_TIMEOUT=30s，
    /// 测试用 80ms 窗验证同一判定逻辑）。
    #[tokio::test]
    async fn idle_guard_kills_silent_serve() {
        let last = Arc::new(ProgressClock::new(Instant::now()));
        let serve: Pin<Box<dyn Future<Output = ()> + Send>> = Box::pin(std::future::pending());
        let t0 = Instant::now();
        drive_serve_guarded(serve, &last, Duration::from_millis(80)).await;
        let took = t0.elapsed();
        assert!(
            took >= Duration::from_millis(80),
            "guard must not return before the idle window: {took:?}"
        );
        assert!(
            took < Duration::from_secs(5),
            "guard must kill a silent serve promptly instead of hanging: {took:?}"
        );
    }

    /// bd lfeu：ProgressIo 读/写实际进展刷新进度钟——空闲续期的判定依据。
    /// 钟预拨到 60s 前：若 read/write 未 touch，断言（elapsed < 30s）必失败。
    #[tokio::test]
    async fn progress_io_records_read_write_progress() {
        use tokio::io::duplex;

        let last = Arc::new(ProgressClock::new(Instant::now() - Duration::from_secs(60)));
        // 读方向：client → ProgressIo 包装端
        let (mut client, server) = duplex(64 * 1024);
        let mut io = ProgressIo { inner: server, last_progress: Arc::clone(&last) };
        client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        io.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        assert!(
            last.lock().elapsed() < Duration::from_secs(30),
            "read progress must refresh the clock"
        );
        // 写方向：ProgressIo 包装端 → client
        let (mut client2, server2) = duplex(64 * 1024);
        let mut io2 = ProgressIo { inner: server2, last_progress: Arc::clone(&last) };
        io2.write_all(b"pong").await.unwrap();
        let mut buf2 = [0u8; 4];
        client2.read_exact(&mut buf2).await.unwrap();
        assert_eq!(&buf2, b"pong");
        assert!(
            last.lock().elapsed() < Duration::from_secs(30),
            "write progress must refresh the clock"
        );
    }
}
