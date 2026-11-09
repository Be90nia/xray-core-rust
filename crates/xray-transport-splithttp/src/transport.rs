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
/// 是对抗 NAT/中间盒空闲回收的官方手段；in-band body 填充方案已被上游两次拒绝
/// （xray-core PR #6422/#6755），勿再引入。
/// <!-- bd z4sks(b)：此处原引 `reports/research-go-xhttp-padding-20261016.md`，
///      该文件在本仓历史里从未存在（git log --all 无记录）⇒ 出处不可核验，改引
///      上游 PR 号。 -->
pub(crate) const H2_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(45);

/// bd wz2b C2 + bd c9oc F-A h2 窗钉修复常量（commit 8780187e，防回档）：
/// client.rs 主 builder 与 dialer.rs stream-one 共用（同批同值）。削弱任一值
/// 必红 client.rs `h2_window_pins_match_wz2b_c9oc`；内存面由 xray-core
/// `memory_budget` 登记簿交叉断言钉住（bd sgdwm）。
pub const H2_INITIAL_STREAM_WINDOW: u32 = 32 * 1024 * 1024;
/// 连接窗不低于流窗即不另成钉（bd c9oc F-A）。
pub const H2_INITIAL_CONNECTION_WINDOW: u32 = 32 * 1024 * 1024;
/// h2 每连接发送缓冲（bd wz2b：服务端收窗放大后 send buf 成次级钉；回档 1MB =
/// 上行钉 1MB/RTT）。**真缓冲**（连接级，SETTINGS 窗是零预分配计数器与此不同）⇒
/// 96MB 预算按连接数 × 本值入簿（bd sgdwm）。
pub const H2_MAX_SEND_BUF_SIZE: usize = 16 * 1024 * 1024;

/// 服务端 h2 收窗原静态值（bd rjzw2：修前 `serve_http_conn` 内联值——服务端**不得**
/// 复用客户端的 `H2_INITIAL_STREAM_WINDOW` 32MB，否则保底路径把服务端原静态
/// 16MB 抬到 32MB：保底被偷改 + 「现状静态 vs 自适应」对比基线失效）。
pub const H2_SERVER_INITIAL_STREAM_WINDOW: u32 = 16 * 1024 * 1024;
/// 服务端 h2 连窗原静态值（32MB）。
pub const H2_SERVER_INITIAL_CONNECTION_WINDOW: u32 = 32 * 1024 * 1024;
/// 服务端 h2 每连接发送缓冲原静态值（16MiB）。
pub const H2_SERVER_MAX_SEND_BUF_SIZE: usize = 16 * 1024 * 1024;

/// 服务端 h2 允许的对端并发流数（票 2xgln）。
///
/// 对齐 Go `net/http` h2 服务端缺省 `MaxConcurrentStreams = 250`（xray hub 用
/// `http.Server` + `SetUnencryptedHTTP2(true)`，故 Go 侧实际生效值即 250）。
/// 不设时 hyper/h2 取 `usize::MAX`：单 TCP 可无限开流，每流一份 handler 状态
/// + 收流窗（16MiB），一个连接即把内存打满。250 留足真实 xmux 并发余量。
pub(crate) const H2_MAX_CONCURRENT_STREAMS: u32 = 250;

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
        // bd 4bd2i：Go hub.go:480-514 的服务端也消费 `streamSettings.QuicParams`
        // （窗口 / idle / MaxIncomingStreams / PMTU）。此前 Rust 监听端**零
        // TransportConfig** ⇒ quinn 缺省 receive_window=VarInt::MAX（连接级无上限）。
        let quic_params = xray_transport::memory_settings::parse_quic_params_config(
            settings.finalmask_json.as_ref().and_then(|f| f.get("quicParams")),
        )?;
        listen_h3(addr, tls, &config, quic_params.as_ref(), sockopt, handler).await
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
    // §3.5.6 ①类托管：hub 级托管口（ctx 内 SessionMap 持有），每连接任务归它；
    // listener close 关闸（transport 族关闸档，ADR-0004 §2.2 Q1：不杀已建立
    // 连接，在途服务到 EOF）；Drop 不作中止保证（§2.2 Q3）。
    let hub_scope = ctx.sessions.scope().clone();
    let listener_scope = hub_scope.clone();
    crate::LOG.info(format!("{local} listening TCP for XHTTP"));

    #[allow(
        clippy::disallowed_methods,
        reason = "②豁免（bd kwevg · §3.5.6）：数据面连接任务（splithttp TCP accept 泵）；任务必须长于组件（进程级/数据面逐包泵/公开契约外返），不迁托管口"
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
            // 闸关（停机中）：连接随 stream 释放，留可诊断日志（禁静默）。
            if hub_scope
                .spawn(async move {
                    handle_accepted_stream(stream, peer, local, tls, rc, probe, ctx).await;
                })
                .is_err()
            {
                crate::LOG.debug("splithttp: scope closed at shutdown, connection dropped");
            }
        }
    });
    let tcp_abort = accept_task.abort_handle();
    // 意外退出监控：循环只应经 close() 的 abort 句柄退出；panic 会静默杀掉监听。
    #[allow(
        clippy::disallowed_methods,
        reason = "②豁免（bd kwevg · §3.5.6）：数据面热路径豁免（坑约束⑫）+ ctx 不可达：splithttp 为 h2/h3 传输层，transport 无 PluginContext 注入面；accept 循环意外退出监控任务；任务必须长于组件（进程级/数据面逐包泵/公开契约外返），不迁托管口"
    )]
    tokio::spawn(xray_transport::accept_policy::supervise_accept_loop(
        "splithttp",
        local.to_string(),
        accept_task,
    ));
    Ok(Box::new(SplithttpListener {
        local,
        tcp_abort: Some(tcp_abort),
        h3_endpoint: None,
        scope: listener_scope,
    }))
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
    // §3.5.6 ①类托管：hub 级托管口（同 TCP 路径）。
    let hub_scope = ctx.sessions.scope().clone();
    let listener_scope = hub_scope.clone();
    crate::LOG.info(format!("{path} listening unix for XHTTP"));

    // 恒等 manager 占位（unix 无 finalmask，入口已拒绝非空配置）。
    let tcpmask = Some(Arc::new(xray_transport::finalmask::TcpmaskManager::new(Vec::new())));
    let log_ident = path.clone();
    #[allow(
        clippy::disallowed_methods,
        reason = "②豁免（bd kwevg · §3.5.6）：数据面连接任务（splithttp unix accept 泵）；任务必须长于组件（进程级/数据面逐包泵/公开契约外返），不迁托管口"
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
            if hub_scope
                .spawn(async move {
                    handle_accepted_stream(stream, peer, local, tls, rc, probe, ctx).await;
                })
                .is_err()
            {
                crate::LOG.debug("splithttp unix: scope closed at shutdown, connection dropped");
            }
        }
    });
    let abort = accept_task.abort_handle();
    #[allow(
        clippy::disallowed_methods,
        reason = "②豁免（bd kwevg · §3.5.6）：数据面热路径豁免（坑约束⑫）+ ctx 不可达：splithttp 为 h2/h3 传输层，transport 无 PluginContext 注入面；unix accept 循环意外退出监控任务；任务必须长于组件（进程级/数据面逐包泵/公开契约外返），不迁托管口"
    )]
    tokio::spawn(xray_transport::accept_policy::supervise_accept_loop(
        "splithttp-unix",
        path,
        accept_task,
    ));
    Ok(Box::new(SplithttpListener {
        local,
        tcp_abort: Some(abort),
        h3_endpoint: None,
        scope: listener_scope,
    }))
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
        // bd xmv43：eager 握手套显式超时窗——「连了不发 ClientHello」的半开连接
        // 在窗尾被清（stream 随 future drop 释放），不再无限期占任务 + fd。
        let acceptor = tokio_rustls::TlsAcceptor::from(tc);
        if let Ok(tls_stream) = xray_transport::tls_handshake_gate::accept_tls_with_timeout(
            &acceptor,
            stream,
            xray_transport::tls_handshake_gate::TLS_HANDSHAKE_TIMEOUT,
        )
        .await
        {
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
    // bd imhvg(b)：Go hub.go:562-563 把 `GetNormalizedServerMaxHeaderBytes()`（缺省 8192）
    // 装进 `http.Server.MaxHeaderBytes` —— 此前本栈该键零消费者（解析/归一化/单测俱全但
    // 没接线），Go 的 8KiB 头上界形同虚设。在 ctx 移入 svc 闭包前取值。
    let max_head_bytes = ctx.config.normalized_server_max_header_bytes().max(8192);
    let svc = service_fn(move |req| {
        let ctx = Arc::clone(&ctx);
        async move { Ok::<_, std::convert::Infallible>(handler::handle_request(req, peer, &ctx).await) }
    });
    // bd lfeu：30s 外挂兜底——hyper h2 serve 对客户端 hard-close/静默对端不退出
    // （724cc20 ws serve_h2_reject 同族）。判定按 I/O 进度：静默连接最迟 30s 强杀；
    // 活跃传输（含 >30s 长流）持续续期，不受硬杀。
    // builder 由 async move 块持有：serve_connection 借用 &self，装箱 future
    // 生命周期超出本函数栈帧。
    let serve: Pin<Box<dyn Future<Output = ()> + Send>> = Box::pin(
        // 站点归因（S3）：整个 serve future 标 xhttp_srv_h2conn——hyper server
        // 的 h2 帧解析/HPACK/流控/发送缓冲全在此 future 的 poll 段内；跨 await
        // 必须 scope（bd a65px），svc/handler 内层已有更细站点（xhttp_srv_send
        // 等）按嵌套覆盖。
        xray_common::alloc_site::scope(xray_common::alloc_site::XHTTP_SRV_H2CONN, async move {
            // 窗组 = 静态保底（RTT 阶梯已撤；服务端 accept 计时随之删除，lf51l）。
            let win = crate::flow_window::server_windows();
            // hyper 对应 Go 的 MaxHeaderBytes：h1 head 缓冲上限
            // （协议下限 8192，已在上面钳住）+ h2 `SETTINGS_MAX_HEADER_LIST_SIZE`。
            let mut builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
            builder
                .http1()
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(READ_HEADER_TIMEOUT)
                .max_buf_size(max_head_bytes as usize);
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
                .max_send_buf_size(win.max_send_buf)
                // bd wz2b W2：hyper server h2 缺省收窗 1MB/1MB（proto/h2/server.rs:36-37），
                // 上行钉 1MB/RTT@169ms≈5.9MB/s（RTT50ms 实测 17.3MB/s，verify/audit-r2-w2-ab
                // U-A 组）。显式 16MB 流窗 + 32MB 连接窗 → U-B 组 210.7MB/s（12.2×）。窗=
                // SETTINGS 计数器零预分配，单连接聚合上限=32MB 连接窗。
                // bd rjzw2：值 = 静态保底 16MB/32MB（RTT 阶梯已撤）。
                .initial_stream_window_size(win.stream_window)
                .initial_connection_window_size(win.connection_window)
                // 票 2xgln：对端并发流上限（Go net/http h2 缺省 250）。h2 侧据此
                // 发 SETTINGS，并对越限的 HEADERS 回 RST_STREAM(REFUSED_STREAM)。
                .max_concurrent_streams(H2_MAX_CONCURRENT_STREAMS)
                // bd imhvg(b)：`serverMaxHeaderBytes` → SETTINGS_MAX_HEADER_LIST_SIZE
                // （Go 把同一值给 http.Server.MaxHeaderBytes，h2 侧同样生效）。
                .max_header_list_size(max_head_bytes as u32);
            let _ = builder.serve_connection(io, svc).await;
        }),
    );
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
    // 之前注入 43200 + 按秒解释 = 三重语义偏差（详见 Go 端 maxTimeDiff 语义）。
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

    // bd rjzw2：REALITY 握手同为 TLS 1.3 往返（≈1 RTT + 认证/HMAC 毫秒级）
    // —— 服务端 RTT 探针。阶梯已撤：该值只进定窗日志。
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

/// 服务端 H3 的 quinn `TransportConfig`（bd 4bd2i）。
///
/// 与客户端 [`crate::h3_client`] 的窗口口径同源（bd wz2b W4 的 16MB 流窗 / 32MB
/// 连接窗，`Max*` 优先），区别：
/// - **必须显式设 `receive_window`**：quinn 缺省 `VarInt::MAX`（连接级无上限）， 配合
///   `max_incoming_streams=100`（各 1.25MB 流窗）⇒ 单条**未认证**连接可被推入 上百 MB
///   接收缓冲（QUIC 握手完成后、任何应用层认证之前）。显式 32MB 把它压回 有界（对齐 Go
///   hub.go:498-514 的 `InitialConnectionReceiveWindow`）。
/// - idle 超时只在显式配置时设（Go 服务端传 `quicParams.MaxIdleTimeout`，0 = quic-go 缺省
///   30s；不抬到客户端的 300s——服务端长空闲连接是资源面）。
fn build_h3_server_transport_config(
    quic_params: Option<&xray_transport::memory_settings::QuicParamsConfig>,
) -> io::Result<quinn::TransportConfig> {
    let mut tc = quinn::TransportConfig::default();
    let mut stream_win = crate::h3_client::DEFAULT_H3_STREAM_RECEIVE_WINDOW;
    let mut conn_win = crate::h3_client::DEFAULT_H3_CONNECTION_RECEIVE_WINDOW;
    if let Some(qp) = quic_params {
        if qp.init_stream_receive_window > 0 {
            stream_win = qp.init_stream_receive_window;
        }
        if qp.max_stream_receive_window > 0 {
            stream_win = qp.max_stream_receive_window;
        }
        if qp.init_connection_receive_window > 0 {
            conn_win = qp.init_connection_receive_window;
        }
        if qp.max_connection_receive_window > 0 {
            conn_win = qp.max_connection_receive_window;
        }
        if qp.max_idle_timeout > 0 {
            let secs = u64::try_from(qp.max_idle_timeout).unwrap_or(u64::MAX);
            if let Ok(v) = quinn::VarInt::from_u64(secs.saturating_mul(1000)) {
                tc.max_idle_timeout(Some(quinn::IdleTimeout::from(v)));
            }
        }
        if qp.max_incoming_streams > 0 {
            if let Ok(v) = quinn::VarInt::from_u64(qp.max_incoming_streams.unsigned_abs()) {
                tc.max_concurrent_bidi_streams(v);
            }
        }
        if qp.disable_path_mtu_discovery {
            tc.mtu_discovery_config(None);
        }
    }
    tc.stream_receive_window(
        quinn::VarInt::from_u64(stream_win)
            .map_err(|e| io::Error::other(format!("h3 server streamWindow VarInt: {e}")))?,
    );
    tc.receive_window(
        quinn::VarInt::from_u64(conn_win)
            .map_err(|e| io::Error::other(format!("h3 server connWindow VarInt: {e}")))?,
    );
    Ok(tc)
}

/// H3 监听：UDP socket + QUIC endpoint + h3 server accept 循环。
///
/// `quinn::Endpoint::server` 等价 Go `ListenSystemPacket` + `quic.ListenEarly` 的组合。
/// ListenEarly 的 0-RTT 接受依赖 rustls max_early_data_size，未启用。
async fn listen_h3(
    addr: SocketAddr,
    tls: Arc<rustls::ServerConfig>,
    config: &Arc<Config>,
    quic_params: Option<&xray_transport::memory_settings::QuicParamsConfig>,
    sockopt: &SocketOptions,
    handler: ConnHandler,
) -> io::Result<Box<dyn TransportListener>> {
    let quic_server = quinn::crypto::rustls::QuicServerConfig::try_from((*tls).clone())
        .map_err(|e| io::Error::other(format!("rustls→quic server: {e}")))?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server));
    // bd 4bd2i：显式窗口，勿用 quinn 缺省（conn 级 VarInt::MAX = 无上限）。
    server_config.transport_config(Arc::new(build_h3_server_transport_config(quic_params)?));
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
    // §3.5.6 ①类托管：hub 级托管口（同 TCP/unix 路径）。
    let listener_scope = ctx.sessions.scope().clone();
    crate::LOG.info(format!("{local} listening QUIC for XHTTP/3"));

    let listener_endpoint = endpoint.clone();
    // accept 循环托管（bd x2ywg）：panic 后 endpoint clone 仍留在 listener 句柄里，
    // UDP 端口保持绑定但永不 accept——监听的死必须留痕（accept_policy 铁律 3）。
    // jcnjb⑤：每监听握手并发闸 + 应用层握手窗（rd8yj① 同款配方，见 [`spawn_h3_accept`]）。
    let gate = xray_transport::handshake_gate::HandshakeGate::new(
        xray_transport::handshake_gate::effective_inflight_limit(),
    );
    spawn_h3_accept(endpoint, gate, ctx);
    Ok(Box::new(SplithttpListener {
        local,
        tcp_abort: None,
        h3_endpoint: Some(listener_endpoint),
        scope: listener_scope,
    }))
}

/// H3 accept 循环 spawn + 意外退出监督（bd x2ywg）。
///
/// 循环唯一合法退出是 listener `close()`（endpoint 关闭 → `accept` 返回 `None`）；
/// panic 则监听静默消失——endpoint 的另一 clone 留在 `SplithttpListener` 里，
/// UDP 端口仍绑定但永不 accept（`accept_policy` 铁律 3：意外退出必须 `error!` 留痕）。
fn spawn_supervised_h3_accept(local: SocketAddr, body: impl Future<Output = ()> + Send + 'static) {
    #[allow(
        clippy::disallowed_methods,
        reason = "②豁免（bd kwevg · §3.5.6）：数据面 QUIC accept 泵（splithttp h3 listener）；任务必须长于组件（进程级/数据面逐包泵/公开契约外返），不迁托管口"
    )]
    let accept_task = tokio::spawn(body);
    #[allow(
        clippy::disallowed_methods,
        reason = "②豁免（bd kwevg · §3.5.6）：accept 循环意外退出监控（panic 留痕）；任务必须长于组件（进程级/数据面逐包泵/公开契约外返），不迁托管口"
    )]
    tokio::spawn(xray_transport::accept_policy::supervise_accept_loop(
        "splithttp-h3",
        local.to_string(),
        accept_task,
    ));
}

/// H3 accept 泵 + 每连接握手并发闸 + 应用层握手窗（jcnjb⑤，rd8yj① 同款配方）。
///
/// - **并发闸**：accept 循环内同步 `try_admit`，满即 fail-fast 丢弃该 Incoming
///   （**不排队**——`handshake_gate` 家族纪律；决策在 accept 循环同步完成，超额 连接不 spawn
///   任务；预算依据见 `xray_transport::handshake_gate::MAX_INFLIGHT_HANDSHAKES` 常量注释）。
///   修复前形态：每 Incoming 无条件 spawn、握手无窗——「发 Initial 不完成握手」 的连接占 task +
///   连接状态直到 idle 超时（持续发包可续命）。
/// - **握手窗**：per-conn 以 `xray_transport_quic::transport::QUIC_HANDSHAKE_TIMEOUT` （8s，Go
///   `nameserver_quic.go:27` 口径）罩 `incoming.await`（quinn 握手）； 握手完成即 `drop(permit)`
///   让位，已建连接的活性归 idle 超时管。
fn spawn_h3_accept(
    endpoint: quinn::Endpoint,
    gate: std::sync::Arc<xray_transport::handshake_gate::HandshakeGate>,
    ctx: Arc<HandlerContext>,
) {
    let local = endpoint.local_addr().unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], 0)));
    // §3.5.6 ①类托管：hub 级托管口（每 QUIC 连接的握手+服务任务归它）。
    let hub_scope = ctx.sessions.scope().clone();
    spawn_supervised_h3_accept(local, async move {
        while let Some(incoming) = endpoint.accept().await {
            // jcnjb⑤：闸满即丢（不排队）；同步决策，超额连接不 spawn 任务。
            let Some(permit) = gate.try_admit() else {
                gate.record_reject("splithttp-h3");
                drop(incoming);
                continue;
            };
            let ctx = Arc::clone(&ctx);
            let g = Arc::clone(&gate);
            let spawned = hub_scope.spawn(async move {
                let conn = match tokio::time::timeout(
                    xray_transport_quic::transport::QUIC_HANDSHAKE_TIMEOUT,
                    incoming,
                )
                .await
                {
                    Ok(Ok(c)) => c,
                    Ok(Err(_)) => return, // 握手协议层失败（对端放弃/参数错）
                    Err(_) => {
                        // 握手窗超时：Incoming 被 drop = 静默丢弃；许可随 task 归还
                        // （行为断言见 tests）。
                        g.record_failure("splithttp-h3", &"handshake window timeout");
                        return;
                    },
                };
                drop(permit); // 握手完成即让位；已建连接活性归 idle 超时管
                serve_h3_conn(conn, ctx).await;
            });
            if spawned.is_err() {
                crate::LOG.debug("splithttp h3: scope closed at shutdown, connection dropped");
            }
        }
    });
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
            reason = "②豁免（bd kwevg · §3.5.6）：h3 每请求任务（单条）；连接终结取消已并入同 task 的 select!（父任务终则本任务终），独立托管无增益，不迁托管口"
        )]
        tokio::spawn(async move {
            let Ok((req, stream)) = resolver.resolve_request().await else {
                return;
            };
            // 连接终结（客户端断开 / idle / error）必须强制终结该连接上的全部
            // 请求——对齐 Go hub.go:394-398 `request.Context().Done()` 中断
            // handler + `defer conn.Close()`：取消触发 response body（含
            // SessionDropGuard）drop，会话删除 + queue.close + ServerConn 上行
            // EOF 级联，hub copy / forward / dispatcher 桥全链解体。否则
            // response body 循环滞留至永久（实测 100%/conn 死锁，s12 泄漏根因）。
            //
            // bd 1a2yy：原实现再 spawn 一条 `conn.closed()` watcher 去 abort 请求
            // task——请求正常结束后 watcher 仍驻留（只在连接关闭时返回），长连接
            // 下 task 数随请求单调增长。改为同 task 内 race（见 [`race_conn_close`]）。
            race_conn_close(&conn, serve_h3_request(req, stream, peer, ctx)).await;
        });
    }
}

/// 请求 future 与连接关闭 race：连接终结即丢弃请求（等价原 `task.abort()`）。
///
/// 请求先完成时 `closed()` future 随 select 一起释放，不留驻留任务（bd 1a2yy）。
async fn race_conn_close<F: Future<Output = ()>>(conn: &quinn::Connection, req: F) {
    tokio::select! {
        _ = req => {},
        _ = conn.closed() => {},
    }
}

/// h3 服务端请求流（bidi）。split 后 send/recv 两半分属不同 task。
type H3ServerStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

/// h3 服务端响应发送半（`RequestStream::split` 的 send 侧）。
type H3SendStream = h3::server::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;

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

    let (parts, body) = resp.into_parts();
    let mut send = send_half;
    if send.send_response(http::Response::from_parts(parts, ())).await.is_err() {
        return;
    }
    pump_h3_response_body(&mut send, body).await;
}

/// 响应体帧泵：body 出错即 WARN 留痕 + RST 该 stream。
///
/// 出错不能当正常提前结束（否则客户端拿到 200 + 截短 body 且错误零留痕）；
/// RST 对齐 Go net/http 的 `Write` 错误终止语义（bd 1a2yy）。
async fn pump_h3_response_body(
    send: &mut H3SendStream,
    mut body: http_body_util::combinators::BoxBody<Bytes, io::Error>,
) {
    while let Some(frame) = body.frame().await {
        let frame = match frame {
            Ok(frame) => frame,
            Err(e) => {
                crate::hot_log!(
                    tracing::Level::WARN,
                    "error={e} h3 response body frame, resetting stream"
                );
                send.stop_stream(h3::error::Code::H3_INTERNAL_ERROR);
                return;
            },
        };
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
            reason = "②豁免（bd kwevg · §3.5.6）：数据面逐包泵（坑约束⑫零改动红线）——duplex 双向 copy 桥任务（ServerConn ↔ registry handler）；随两端 EOF 自终，停机不拆在途泵，不迁托管口"
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
    /// §3.5.6 ①类托管：hub 级托管口（每连接任务账本，本字段是 hub 账本的克隆
    /// 句柄，owner 见 `SessionMap.scope`）。stop 面 = transport 族关闸档
    /// （ADR-0004 §2.2 Q1）：`close()` 只关闸拒新，不杀已建立连接（Go 26.10.17
    /// `listener.Close()` 口径，在途服务到 EOF）；无 drain 面 ⇒ 不声称 abort；
    /// Drop 不作中止保证（§2.2 Q3）。
    /// 已知自引用环（任务持 SessionMap/HandlerContext 强引用，bd hnicl）⇒ 纯
    /// Drop 路径不触发在途中止；破环见 ADR-0004 B2 批次。
    scope: xray_frame::scope::ComponentScope,
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
        // 托管口关闸：停机后拒新连接任务（transport 族关闸档：在途按 Go 口径
        // 服务到 EOF，ADR-0004 §2.2 Q1；Drop 不作中止保证，§2.2 Q3）。
        self.scope.close_gate();
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
        // udf CI 教训②：callsite interest 是进程级缓存，thread-local `subscriber::set_default`
        // 不触发重建——本进程内其他测试先评估过该 ERROR callsite 时，本测试恒捕 0 条
        // （多核调度序决定谁先跑，s42cg 轮侥幸绿、lf51l 轮恒红）。`set_global_default`
        // 注册全局 dispatcher 会 bump generation，强制全部 callsite 重算 interest。
        let _ = tracing::subscriber::set_global_default(CaptureLogs(Arc::clone(&logs)));
        let addr: SocketAddr = "127.0.0.1:8443".parse().expect("addr");
        spawn_supervised_h3_accept(addr, async { panic!("h3 accept loop exploded") });
        // 监督 task 与被监督 task 的调度次序不确定：墙钟截止轮询等到监控落日志
        // （取时走 clock 端口，裸 Instant::now 被 lint 禁）
        let deadline = xray_frame::compat::clock().now_instant() + Duration::from_secs(5);
        // 注意：**不能**「见到任何首条日志就 break」——crate 内各 LogFacade 懒初始化的
        // banner（INFO）可能先于监督 ERROR 落进捕获（lf51l 轮实测），必须等到**内容
        // 匹配**的行出现或超时。
        loop {
            {
                let got = logs.lock().expect("log capture lock");
                if got.iter().any(|m| {
                    m.contains("ERROR")
                        && m.contains("splithttp-h3")
                        && m.contains("127.0.0.1:8443")
                        && m.contains("h3 accept loop exploded")
                }) {
                    break;
                }
            }
            assert!(
                xray_frame::compat::clock().now_instant() < deadline,
                "accept 循环 panic 无 error 留痕 = 静默死亡（端口仍绑、永不 accept），捕获: {:?}",
                logs.lock().expect("log capture lock")
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
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
        // 服务端必须配真证书：缺证书 → 每条握手 `no server certificate chain
        // resolved`（bd mwvwd F2，不再自签）；客户端用
        // `pinnedPeerCertSha256` 钉住它，不依赖已收紧的 allowInsecure。
        let (cert_pem, key_pem) =
            xray_tls::certificate::generate_self_signed_cert(&["localhost"]).unwrap();
        let (certs, _) = xray_tls::certificate::entry_certs_and_key(&serde_json::json!({
            "certificate": cert_pem,
        }))
        .unwrap();
        let pin = xray_tls::pin::generate_cert_hash_hex(certs[0].as_ref());
        let (handler, count) = greeting_handler();
        let mut settings = plain_settings();
        settings.security = "tls".into();
        settings.security_json = Some(serde_json::json!({
            "alpn": ["h3"],
            "certificates": [{ "certificate": cert_pem, "key": key_pem }],
        }));
        let listener = listen_splithttp(
            "127.0.0.1:0".parse().unwrap(),
            &settings,
            &SocketOptions::default(),
            handler,
        )
        .await
        .expect("listen h3");
        let addr = listener.local_addr().unwrap();

        // quinn + h3 客户端（钉扎证书；SNI/主机名取证书 SAN "localhost"）
        let client_tls = xray_tls::client_config::build_client_config(
            "tls",
            Some(&serde_json::json!({
                "pinnedPeerCertSha256": pin,
                "alpn": ["h3"],
            })),
            "localhost",
        )
        .unwrap()
        .expect("client tls config");
        let quic_cfg = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_tls).unwrap(),
        ));
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(quic_cfg);
        let conn = endpoint.connect(addr, "localhost").unwrap().await.expect("quic connect");
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

    // ---- jcnjb⑤：握手并发闸 + 应用层握手窗（rd8yj① 同款判据） ----

    /// 永挂式证书验证器（rd8yj 同款）：进入 `verify_server_cert` 即驻留——
    /// Initial 合法发出（服务器接纳并回飞行包）、Finished 永不到达 ⇒ 握手永远
    /// 无法完成，闸许可唯一的让出途径 = 握手窗（QUIC_HANDSHAKE_TIMEOUT）超时放弃。
    #[derive(Debug)]
    struct ParkedVerifier {
        entered: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
        release: Arc<std::sync::atomic::AtomicBool>,
    }

    impl rustls::client::danger::ServerCertVerifier for ParkedVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            if let Some(entered) = self.entered.lock().expect("parked verifier lock").take() {
                let _ = entered.send(());
            }
            while !self.release.load(std::sync::atomic::Ordering::SeqCst) {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(rustls::Error::General("parked verifier released".into()))
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                rustls::SignatureScheme::RSA_PSS_SHA256,
                rustls::SignatureScheme::RSA_PKCS1_SHA256,
            ]
        }
    }

    /// 测试收尾守卫（rd8yj 同款）：无论断言过红，Drop 都解除验证器自旋——
    /// 否则 panic 路径下 quinn 驱动线程卡在自旋里，测试进程 runtime drop 卡死。
    struct ReleaseGuard(Arc<std::sync::atomic::AtomicBool>);

    impl Drop for ReleaseGuard {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// 行为断言（jcnjb⑤，rd8yj① 判据）：h3 accept 泵（[`spawn_h3_accept`]，
    /// 与 [`listen_h3`] 同一生产泵函数）的握手闸必须在握手窗超时后**真实释放**
    /// 许可——许可被占满整窗、窗后回到可再取。
    ///
    /// 容量 1 闸注入；永挂验证器客户端占住唯一名额。
    /// - 删掉 try_admit 接线 ⇒ 持有探针期间许可恒可取 ⇒ 红；
    /// - 窗改大（60s）/删掉超时 ⇒ 释放探针 20s 截止拿不到 ⇒ 红。
    ///
    /// 结构纪律（rd8yj 同款）：**先清理、后断言**——panic 只允许发生在解除
    /// 验证器自旋并关闭 endpoint 之后。
    #[allow(clippy::disallowed_methods, reason = "测试耗时断言配套，非生产时钟取用")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn handshake_gate_releases_quota_after_window_timeout() {
        use std::time::Duration;

        ensure_provider();

        // 服务端：真证书 + h3 ALPN（生产 listen_h3 同构的手工端点，闸容量注入 1）。
        let (cert_pem, key_pem) =
            xray_tls::certificate::generate_self_signed_cert(&["localhost"]).unwrap();
        let tls = xray_tls::server_config::build_server_config(
            "tls",
            Some(&serde_json::json!({
                "alpn": ["h3"],
                "certificates": [{ "certificate": cert_pem, "key": key_pem }],
            })),
        )
        .expect("build server tls config")
        .expect("is_h3 implies Some");
        let std_sock = xray_transport::sockopt::bind_udp_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            &SocketOptions::default(),
        )
        .expect("bind udp endpoint");
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(quinn::ServerConfig::with_crypto(Arc::new(
                quinn::crypto::rustls::QuicServerConfig::try_from((*tls).clone())
                    .expect("rustls→quic server"),
            ))),
            std_sock,
            Arc::new(quinn::TokioRuntime),
        )
        .expect("server endpoint");
        let server_addr = endpoint.local_addr().expect("local addr");
        let keepalive = endpoint.clone(); // endpoint 本体 move 进 accept 泵，clone 保活

        let config = Arc::new(crate::register::parse_splithttp_config(None).expect("parse config"));
        let (handler, _count) = greeting_handler();
        let ctx = build_context(&config, server_addr, handler);
        let gate = xray_transport::handshake_gate::HandshakeGate::new(1); // 容量 1：单名额可观测
        spawn_h3_accept(endpoint, Arc::clone(&gate), ctx);

        // 永挂验证器客户端：占住唯一名额（entered ⇒ 服务器已接纳、许可已被占）。
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let release = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let _release_guard = ReleaseGuard(Arc::clone(&release));
        let mut hang_tls = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(ParkedVerifier {
                entered: std::sync::Mutex::new(Some(entered_tx)),
                release: Arc::clone(&release),
            }))
            .with_no_client_auth();
        hang_tls.alpn_protocols = vec![b"h3".to_vec()];
        let mut hang_ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        hang_ep.set_default_client_config(quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(hang_tls).unwrap(),
        )));
        // 不 await Connecting：Initial 由 endpoint 驱动发出，握手卡死在验证器。
        let _connecting = hang_ep.connect(server_addr, "localhost").unwrap();

        tokio::time::timeout(Duration::from_secs(15), entered_rx)
            .await
            .expect("verifier must be reached within 15s (stall not established)")
            .expect("entered channel");
        let admitted_at = std::time::Instant::now();

        // 持有探针（2s 窗）：许可必须被占（删掉 try_admit 接线 ⇒ 恒可取 ⇒ 红）。
        let mut held = true;
        while admitted_at.elapsed() < Duration::from_secs(2) {
            if gate.try_admit().is_some() {
                held = false;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // 释放观测窗口（固定 20s）：窗改大/删掉 ⇒ released_at = None。
        let mut released_at = None;
        while admitted_at.elapsed() < Duration::from_secs(20) {
            if gate.try_admit().is_some() {
                released_at = Some(std::time::Instant::now());
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // ---- 清理先行（此时不得有任何 panic）：解除自旋 + 关两端 endpoint ----
        release.store(true, std::sync::atomic::Ordering::SeqCst);
        drop(_connecting);
        drop(hang_ep);
        tokio::time::sleep(Duration::from_millis(200)).await;
        keepalive.close(0u32.into(), b"test done");

        // ---- 断言（全部在清理之后）----
        assert!(held, "握手未完成期间闸许可必须被占（try_admit 接线被删 = 恒可取）");
        let released_at = released_at
            .expect("握手窗超时后名额必须被释放（连接放弃、许可归还）——闸失效或窗被改大/删掉");
        let held_for = released_at.duration_since(admitted_at);
        assert!(
            held_for
                >= xray_transport_quic::transport::QUIC_HANDSHAKE_TIMEOUT - Duration::from_secs(1),
            "名额仅被占 {held_for:?}（窗 = 8s）——提前让位 = 闸未按窗工作"
        );
    }

    /// h3 + stream-one：Rust 客户端 POST（带 body）→ Rust h3 服务端 → **完整响应体**回传。
    ///
    /// bd 1xfap：修前 Rust h3 客户端的 stream-one 走「**发完 body 才读响应**」的顺序
    /// 两段（h3 的 RequestStream 收发共用 `&mut self`），而服务端 stream-one 是
    /// **边收 body 边回响应**（Go 同款全双工）——客户端在 body 发完前等不到响应，
    /// 连接被关、下行 0 字节（curl 52 Empty reply from server）。
    ///
    /// 本用例锁「h3 + stream-one 必须拿到完整响应体」（64 KiB 逐字节一致）。
    #[tokio::test]
    async fn h3_stream_one_returns_full_response_body() {
        ensure_provider();
        let (cert_pem, key_pem) =
            xray_tls::certificate::generate_self_signed_cert(&["localhost"]).unwrap();
        let (certs, _) = xray_tls::certificate::entry_certs_and_key(&serde_json::json!({
            "certificate": cert_pem,
        }))
        .unwrap();
        let pin = xray_tls::pin::generate_cert_hash_hex(certs[0].as_ref());

        // 服务端：echo 型 handler（上行读多少回多少）。
        let count = Arc::new(AtomicUsize::new(0));
        let c2 = Arc::clone(&count);
        let handler: ConnHandler = Arc::new(move |mut conn: Box<dyn Connection>| {
            let c = Arc::clone(&c2);
            c.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    let n = match conn.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    if conn.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                    let _ = conn.flush().await;
                }
            });
        });

        let mut settings = plain_settings();
        settings.security = "tls".into();
        settings.security_json = Some(serde_json::json!({
            "alpn": ["h3"],
            "certificates": [{ "certificate": cert_pem, "key": key_pem }],
        }));
        settings.transport_json =
            Some(serde_json::json!({ "path": "/xhttp", "host": "localhost" }));
        let listener = listen_splithttp(
            "127.0.0.1:0".parse().unwrap(),
            &settings,
            &SocketOptions::default(),
            handler,
        )
        .await
        .expect("listen h3");
        let addr = listener.local_addr().unwrap();

        // 客户端：真 H3Conn（生产同路径：connect → dial_h3_stream_one）。
        let client_tls = xray_tls::client_config::build_client_config(
            "tls",
            Some(&serde_json::json!({
                "pinnedPeerCertSha256": pin,
                "alpn": ["h3"],
            })),
            "localhost",
        )
        .unwrap()
        .expect("client tls config");
        let client_config = Arc::new(crate::config::Config {
            host: "localhost".into(),
            path: "/xhttp".into(),
            mode: "stream-one".into(),
            ..Default::default()
        });
        let h3 = crate::h3_client::H3Conn::connect_with_quic_params(
            Arc::clone(&client_config),
            addr,
            "localhost",
            (*client_tls).clone(),
            None,
            &SocketOptions::default(),
        )
        .await
        .expect("h3 connect");
        let base_uri = crate::dialer::build_request_url(
            "https",
            &format!("localhost:{}", addr.port()),
            &client_config.normalized_path(),
            &client_config.normalized_query(),
        );
        let mut conn = crate::dialer::dial_h3_stream_one(
            crate::mux::wrap_xmux_client(h3),
            base_uri,
            String::new(),
        )
        .await
        .expect("dial h3 stream-one");

        // 上行 64 KiB（服务端 echo）→ **上传不结束**（不半关写向）也必须能读到完整
        // 下行——xhttp stream-one 的真实形态就是活流上传（Go 侧收发并发）。
        let payload: Vec<u8> = (0..65536u32).map(|i| (i % 251) as u8).collect();
        conn.write_all(&payload).await.expect("write upload");
        let _ = conn.flush().await;
        let mut got = vec![0u8; payload.len()];
        tokio::time::timeout(Duration::from_secs(10), conn.read_exact(&mut got))
            .await
            .expect("h3 stream-one download must finish while upload is still open")
            .expect("h3 stream-one download must succeed");
        assert_eq!(got, payload, "h3 stream-one must return the full response body");
        assert_eq!(count.load(Ordering::SeqCst), 1, "handler should see 1 conn");
        let _ = conn.shutdown().await;
    }

    /// bd 1a2yy(a)：连接关闭必须取消在途 h3 请求，且不留 per-request watcher。
    ///
    /// 修前给每个请求额外 spawn 一条 `conn.closed()` watcher（请求正常结束后仍驻留，
    /// 长连接下 task 数随请求单调增长）；现由 [`race_conn_close`] 在同 task 内 race。
    /// 本用例用**真实 QUIC 连接**钉住 race 语义：关连接 ⇒ 请求 future 被 drop。
    #[tokio::test]
    async fn race_conn_close_drops_request_future() {
        ensure_provider();
        let (cert_pem, key_pem) =
            xray_tls::certificate::generate_self_signed_cert(&["localhost"]).unwrap();
        let (certs, _) = xray_tls::certificate::entry_certs_and_key(&serde_json::json!({
            "certificate": cert_pem,
        }))
        .unwrap();
        let pin = xray_tls::pin::generate_cert_hash_hex(certs[0].as_ref());
        let (handler, _count) = greeting_handler();
        let mut settings = plain_settings();
        settings.security = "tls".into();
        settings.security_json = Some(serde_json::json!({
            "alpn": ["h3"],
            "certificates": [{ "certificate": cert_pem, "key": key_pem }],
        }));
        let listener = listen_splithttp(
            "127.0.0.1:0".parse().unwrap(),
            &settings,
            &SocketOptions::default(),
            handler,
        )
        .await
        .expect("listen h3");
        let addr = listener.local_addr().unwrap();

        let client_tls = xray_tls::client_config::build_client_config(
            "tls",
            Some(&serde_json::json!({
                "pinnedPeerCertSha256": pin,
                "alpn": ["h3"],
            })),
            "localhost",
        )
        .unwrap()
        .expect("client tls config");
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_tls).unwrap(),
        )));
        let conn = endpoint.connect(addr, "localhost").unwrap().await.expect("quic connect");

        // 探针：请求 future 被丢弃时置位。
        struct DropProbe(std::sync::Arc<std::sync::atomic::AtomicBool>);
        impl Drop for DropProbe {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let probe = DropProbe(std::sync::Arc::clone(&dropped));
        let race_conn = conn.clone();
        let task = tokio::spawn(async move {
            race_conn_close(&race_conn, async move {
                let _probe = probe;
                std::future::pending::<()>().await;
            })
            .await;
        });

        // 关连接 ⇒ `closed()` 完成 ⇒ 请求 future 被 drop ⇒ race task 退出。
        conn.close(0u32.into(), b"test close");
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("race task must exit on conn close")
            .expect("race task must not panic");
        assert!(dropped.load(Ordering::SeqCst), "request future must be dropped on conn close");
        endpoint.close(0u32.into(), b"test done");
    }

    /// bd 1a2yy(b)：h3 响应体上游出错 ⇒ RST 该 stream（不留痕地当 EOF 是修前的坑）。
    ///
    /// 修前 `let Ok(frame) = frame else { break }` 把错误当正常提前结束：客户端拿到
    /// 200 + 截短 body，服务端零留痕。本用例用真 QUIC/h3 对端直喂
    /// [`pump_h3_response_body`] 一个出错 body，断言客户端读到的是 stream 错误
    /// 而不是干净 EOF。
    #[tokio::test]
    async fn h3_response_body_error_resets_stream() {
        ensure_provider();
        let (cert_pem, key_pem) =
            xray_tls::certificate::generate_self_signed_cert(&["localhost"]).unwrap();
        let server_tls = xray_tls::server_config::build_server_config(
            "tls",
            Some(&serde_json::json!({
                "alpn": ["h3"],
                "certificates": [{ "certificate": cert_pem, "key": key_pem }],
            })),
        )
        .unwrap()
        .expect("server tls config");
        let quic_server =
            quinn::crypto::rustls::QuicServerConfig::try_from((*server_tls).clone()).unwrap();
        let endpoint = quinn::Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(quic_server)),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let addr = endpoint.local_addr().unwrap();

        struct ErrBody;
        impl hyper::body::Body for ErrBody {
            type Data = Bytes;
            type Error = io::Error;

            fn poll_frame(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<Option<Result<hyper::body::Frame<Bytes>, io::Error>>> {
                Poll::Ready(Some(Err(io::Error::other("upstream body broke"))))
            }
        }

        let srv = tokio::spawn(async move {
            let conn = endpoint.accept().await.expect("accept").await.expect("handshake");
            let quinn_conn = conn.clone();
            let mut h3_conn =
                h3::server::Connection::new(h3_quinn::Connection::new(conn)).await.unwrap();
            let resolver = h3_conn.accept().await.unwrap().expect("request");
            let (_req, stream) = resolver.resolve_request().await.unwrap();
            let (mut send, _recv) = stream.split();
            send.send_response(http::Response::builder().status(200).body(()).unwrap())
                .await
                .unwrap();
            pump_h3_response_body(&mut send, http_body_util::combinators::BoxBody::new(ErrBody))
                .await;
            // 连接必须活到 RST 送达客户端：`h3::server::Connection` drop 会先发
            // GOAWAY/close，客户端只会看到「连接被关」而非本用例要断言的 stream 错误。
            let _ = quinn_conn.closed().await;
        });

        let (certs, _) = xray_tls::certificate::entry_certs_and_key(&serde_json::json!({
            "certificate": cert_pem,
        }))
        .unwrap();
        let pin = xray_tls::pin::generate_cert_hash_hex(certs[0].as_ref());
        let client_tls = xray_tls::client_config::build_client_config(
            "tls",
            Some(&serde_json::json!({
                "pinnedPeerCertSha256": pin,
                "alpn": ["h3"],
            })),
            "localhost",
        )
        .unwrap()
        .expect("client tls config");
        let mut client_ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client_ep.set_default_client_config(quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_tls).unwrap(),
        )));
        let conn = client_ep.connect(addr, "localhost").unwrap().await.expect("quic connect");
        let (mut driver, mut send_req) =
            h3::client::new(h3_quinn::Connection::new(conn)).await.unwrap();
        tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        let req = http::Request::builder()
            .method("GET")
            .uri("/")
            .header("host", format!("127.0.0.1:{}", addr.port()))
            .body(())
            .unwrap();
        let mut stream = send_req.send_request(req).await.unwrap();
        stream.finish().await.unwrap();
        // 读完整响应：错误体必须让客户端在 headers/body 任一阶段看到 stream 错误
        // （RST），而不是 200 + 干净 EOF——后者正是修前 `break` 的行为（bd 1a2yy）。
        let outcome = async {
            let _resp = stream.recv_response().await?;
            loop {
                match stream.recv_data().await? {
                    Some(_) => continue,
                    None => return Ok::<(), h3::error::StreamError>(()),
                }
            }
        };
        let outcome = tokio::time::timeout(Duration::from_secs(10), outcome)
            .await
            .expect("client must not hang on errored response body");
        assert!(
            outcome.is_err(),
            "errored body must surface as a stream error, not 200 + clean EOF (bd 1a2yy)"
        );
        client_ep.close(0u32.into(), b"test done");
        tokio::time::timeout(Duration::from_secs(5), srv)
            .await
            .expect("server task must exit once client closes")
            .expect("server task must not panic");
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

    /// bd 4bd2i 契约：H3 **监听端**必须显式设流/连接接收窗。
    ///
    /// 回归前：`quinn::ServerConfig::with_crypto` 走缺省 TransportConfig ⇒
    /// `receive_window = VarInt::MAX`（连接级无上限）+ 流窗 1.25MB +
    /// `max_incoming_streams=100` ⇒ 单条**未认证**连接可被推入上百 MB。
    /// `quinn::TransportConfig` 无 getter，用 Debug 回读字段（同 quic crate 手法）。
    #[test]
    fn h3_server_transport_config_bounds_receive_window() {
        let tc = build_h3_server_transport_config(None).expect("default server transport config");
        let dbg = format!("{tc:?}");
        assert!(
            dbg.contains(&format!(
                "receive_window: {}",
                crate::h3_client::DEFAULT_H3_CONNECTION_RECEIVE_WINDOW
            )),
            "连接接收窗必须显式有界：{dbg}"
        );
        assert!(
            dbg.contains(&format!(
                "stream_receive_window: {}",
                crate::h3_client::DEFAULT_H3_STREAM_RECEIVE_WINDOW
            )),
            "流接收窗必须显式：{dbg}"
        );
        // VarInt::MAX = 2^62-1：quinn 缺省值，绝不允许出现在监听端。
        assert!(!dbg.contains("receive_window: 4611686018427387903"), "{dbg}");
    }

    /// bd 4bd2i：`quicParams` 显式值优先（与客户端 h3_client 同源口径），
    /// 且 `maxIncomingStreams` / `maxIdleTimeout` 在服务端同样生效。
    #[test]
    fn h3_server_transport_config_honours_quic_params() {
        let v: serde_json::Value = serde_json::from_str(
            r#"{"maxStreamReceiveWindow":1048576,"maxConnectionReceiveWindow":2097152,
                "maxIncomingStreams":8,"maxIdleTimeout":42}"#,
        )
        .unwrap();
        let qp = xray_transport::memory_settings::parse_quic_params_config(Some(&v))
            .expect("parse")
            .expect("present");
        let dbg = format!("{:?}", build_h3_server_transport_config(Some(&qp)).expect("build"));
        assert!(dbg.contains("stream_receive_window: 1048576"), "{dbg}");
        assert!(dbg.contains("receive_window: 2097152"), "{dbg}");
        assert!(dbg.contains("max_concurrent_bidi_streams: 8"), "{dbg}");
        assert!(dbg.contains("max_idle_timeout: Some(42000)"), "{dbg}");
    }
}
