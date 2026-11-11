//! HTTP 客户端栈 + XMUX 接线。对应 Go `client.go`（`serviceTransport`/
//! `secureTransport`/`connPool`/`poolConn`/`sessionTransport`）。
//!
//! 归属（规划 §4.1）：停滞检测/per-host 连接编排属协议方向件、单消费方——
//! `udf-promotion-candidate`（第二消费方出现时上浮）。
//!
//! ## 与 Go 形态的映射（规划 §5 B2 契约）
//!
//! | Go | Rust |
//! |---|---|
//! | `serviceTransport.RoundTrip`（停滞检测 + `progressBody` 16KiB 推进） | `service_round_trip` + `StallGuard` + `ProgressBody` |
//! | `secureTransport`（h2 每 host 一连接；h1 回退多连接 + `h1Hosts` 共享表） | hyper-util 连接池 + ALPN 原生承担：rustls ALPN 协商 h2/h1；h1 并发由池按需开连接（无共享表——两形态等价，每池单元仍 ≈ 一条 h2 连接） |
//! | `connPool`（每 storage 一个 `XmuxManager`） | `ConnPool` |
//! | `poolConn`（xmux 连接单元：closing/inflight/取消） | `XdriveHttpClient` |
//! | `sessionTransport`（会话在池连接间迁移 + 慢连接退役） | `SessionTransport`（退役 `stalled` 钩子随 B4 drive 的 `do()` 接入——template 不消费，Go 同款） |
//!
//! 差异登记：h3 分支（`http3.Transport`）属 B6；btls uTLS 指纹出站随 B6 互操作轮
//! 接入（B2 只走 rustls + 明文两路，Go 指纹仅在显式配置时启用）。

use std::{
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use http::{Method, StatusCode, Uri, request::Request};
use http_body_util::{BodyExt, combinators::BoxBody};
use hyper::body::Frame;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder, MaybeHttpsStream};
use hyper_util::{
    client::legacy::{
        Client,
        connect::{Connected, Connection as HttpConnection},
    },
    rt::{TokioExecutor, TokioIo, TokioTimer},
};
use rustls::ClientConfig as RustlsClientConfig;
use skeleton::clock::Clock;
use tower_service::Service as TowerService;
use xray_common::net::address::Address;
use xray_transport::dialer::StreamSettings;
use xray_transport_splithttp::{
    RangeConfig, XmuxConfig,
    mux::{XmuxClient, XmuxConn, XmuxManager},
};

use crate::config::Config;

/// 请求停滞上限（Go `driveTimeout`）：发送/应答/读响应任一阶段 60s 无字节推进即断。
pub(crate) const DRIVE_TIMEOUT: Duration = Duration::from_secs(60);
/// 重试次数（Go `driveMaxAttempts`）。
pub(crate) const DRIVE_MAX_ATTEMPTS: u32 = 8;
/// 初始退避（Go `driveInitialBackoff`）。
pub(crate) const DRIVE_INITIAL_BACKOFF_MS: u64 = 200;
/// 退避总预算（Go 每步 `driveMaxBackoff`=8s 封顶 ⇒ 序列和 0.2+0.4+…+8 ≈ 20.6s；
/// `exponential_backoff_if` 无每步上限参数 ⇒ 用总预算表达同一上限）。
pub(crate) const DRIVE_BACKOFF_BUDGET: Duration = Duration::from_millis(20_600);
/// template 并发缺省（Go `driveMaxInflight`）与上限（Go `maxTemplateConcurrency`）。
pub(crate) const DRIVE_MAX_INFLIGHT: usize = 64;
pub(crate) const MAX_TEMPLATE_CONCURRENCY: usize = 256;
/// h2 keep-alive PING 缺省周期（Go `net.ChromeH2KeepAlivePeriod` 45s）。
const CHROME_H2_KEEP_ALIVE: Duration = Duration::from_secs(45);
/// 请求体按 16KiB 帧推进（Go `progressBody.Read` 的 16<<10 上限：h2 一次读可达
/// 512KiB，慢链路上会伪装成无进展）。
const REQUEST_PROGRESS_CHUNK: usize = 16 << 10;
/// 每池单元（= 每 xmux 连接）的空闲连接上界：h2 单连接复用语义的池面表达
/// （Go `secure(1)` MaxConnsPerHost=1；h1 并发由池按需开连接、空闲只留一条）。
const POOL_MAX_IDLE_PER_HOST: usize = 1;

pub(crate) type ReqBody = BoxBody<Bytes, io::Error>;
pub(crate) type HyperClient = Client<XdriveConnector, ReqBody>;

/// 对外一条请求（Go `http.NewRequestWithContext` 的入参面）。
#[derive(Debug, Clone)]
pub(crate) struct OutRequest {
    pub(crate) method: Method,
    pub(crate) uri: Uri,
    /// 同名覆盖（Go `Header.Set` 语义）。
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Option<Bytes>,
}

// ── 停滞检测（Go serviceTransport + progressBody + stalled）─────────────────

/// 「最近一次字节推进」时刻（时钟走 compat 端口，测试可注入）。select 看门狗
/// 每步检查静默时长，超过 stall 即断（Go `errStalled`）。
struct StallGuard {
    clock: Arc<dyn Clock>,
    last: parking_lot::Mutex<std::time::Instant>,
}

impl StallGuard {
    fn new(clock: Arc<dyn Clock>) -> Self {
        Self { last: parking_lot::Mutex::new(clock.now_instant()), clock }
    }

    fn bump(&self) {
        *self.last.lock() = self.clock.now_instant();
    }

    fn silence(&self) -> Duration {
        self.clock.now_instant().saturating_duration_since(*self.last.lock())
    }
}

/// 请求体：按 16KiB 帧推进（Go `progressBody` 的请求侧）。
struct ProgressBody {
    data: Bytes,
    pos: usize,
    guard: Arc<StallGuard>,
}

impl http_body::Body for ProgressBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if this.pos >= this.data.len() {
            return Poll::Ready(None);
        }
        let end = (this.pos + REQUEST_PROGRESS_CHUNK).min(this.data.len());
        let chunk = this.data.slice(this.pos..end);
        this.pos = end;
        this.guard.bump();
        Poll::Ready(Some(Ok(Frame::data(chunk))))
    }

    fn is_end_stream(&self) -> bool {
        self.pos >= self.data.len()
    }
}

fn err_stalled() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "the request made no progress")
}

fn progress_body(body: Option<Bytes>, guard: Arc<StallGuard>) -> ReqBody {
    ProgressBody { data: body.unwrap_or_default(), pos: 0, guard }.boxed()
}

/// 服务级一次请求：停滞检测包发送与响应缓冲两段（Go `serviceTransport.RoundTrip`
/// + `doneBody` 的全量读等价——template/drive 的 `do()` 恒全量缓冲）。
///
/// # Errors
/// 连接/协议错误（可重试面）或 `stall` 内无字节推进（[`err_stalled`]）。
pub(crate) async fn service_round_trip(
    client: &HyperClient,
    req: OutRequest,
    stall: Duration,
) -> io::Result<(StatusCode, Bytes)> {
    let guard = Arc::new(StallGuard::new(xray_frame::compat::clock()));

    let mut builder = Request::builder().method(req.method).uri(req.uri);
    for (key, value) in req.headers {
        builder = builder.header(key, value);
    }
    let http_req =
        builder.body(progress_body(req.body, Arc::clone(&guard))).map_err(io::Error::other)?;

    // 发送段：body 帧推进 + 等响应头，stall 静默即断。
    let mut send = Box::pin(client.request(http_req));
    let response = loop {
        tokio::select! {
            r = send.as_mut() => match r {
                Ok(response) => break response,
                Err(e) => return Err(io::Error::other(e)),
            },
            _ = tokio::time::sleep(stall) => {
                if guard.silence() >= stall {
                    return Err(err_stalled());
                }
            },
        }
    };
    guard.bump();

    // 响应缓冲段：帧推进，stall 静默即断（Go `progressBody` 的响应侧 + ReadAll）。
    let (parts, mut body) = response.into_parts();
    let mut payload = Vec::new();
    loop {
        tokio::select! {
            frame = body.frame() => match frame {
                Some(Ok(f)) => {
                    if let Ok(data) = f.into_data() {
                        payload.extend_from_slice(&data);
                        guard.bump();
                    }
                },
                Some(Err(e)) => return Err(io::Error::other(e)),
                None => break,
            },
            _ = tokio::time::sleep(stall) => {
                if guard.silence() >= stall {
                    return Err(err_stalled());
                }
            },
        }
    }
    Ok((parts.status, payload.into()))
}

// ── 连接器（Go dial / dialPlain / dialTLS）────────────────────────────────

/// 出站共享构造参数（Go `newServiceClient` 从 streamSettings 读取的面）。
#[derive(Clone)]
pub(crate) struct ClientCore {
    /// rustls 客户端配置（Go `tlsConfig.GetTLSConfig`；None = 明文）。
    pub(crate) tls: Option<Arc<RustlsClientConfig>>,
    /// fronting 拨号覆盖（Go `streamSettings.Destination`；端口 0 = 沿用 URL 端口）。
    pub(crate) fronting: Option<(Address, u16)>,
    /// h2 keep-alive PING 周期（Go `keepAlive`；None = 关，Go `HKeepAlivePeriod` <0）。
    pub(crate) keepalive: Option<Duration>,
}

impl ClientCore {
    /// 从流设置构造（Go `newServiceClient` 头段）。`h_keep_alive_period` 取
    /// xmux 的 `HKeepAlivePeriod`（>0 覆盖 / <0 关闭 / 其余缺省 45s）。
    ///
    /// # Errors
    /// 安全层配置解析失败（[`xray_tls::client_config::build_client_config`]）。
    pub(crate) fn from_settings(
        settings: &StreamSettings,
        h_keep_alive_period: i64,
    ) -> io::Result<Self> {
        let tls = xray_tls::client_config::build_client_config(
            &settings.security,
            settings.security_json.as_ref(),
            "",
        )?;
        let keepalive = match h_keep_alive_period {
            p if p > 0 => Some(Duration::from_secs(u64::try_from(p).unwrap_or(u64::MAX))),
            p if p < 0 => None,
            _ => Some(CHROME_H2_KEEP_ALIVE),
        };
        Ok(Self { tls, fronting: settings.fronting.clone(), keepalive })
    }
}

/// TCP 流包装（Go `ctxConn` 的连接面；connCtx 生命周期托管随 B5 spareBox 接入）。
pub(crate) struct XdriveTcpStream(TokioIo<tokio::net::TcpStream>);

impl hyper::rt::Read for XdriveTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        TokioIo::poll_read(Pin::new(&mut self.get_mut().0), cx, buf)
    }
}

impl hyper::rt::Write for XdriveTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        TokioIo::poll_write(Pin::new(&mut self.get_mut().0), cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        TokioIo::poll_flush(Pin::new(&mut self.get_mut().0), cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        TokioIo::poll_shutdown(Pin::new(&mut self.get_mut().0), cx)
    }
}

impl HttpConnection for XdriveTcpStream {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

/// 按 URI 寻址的 TCP 连接器：fronting 只覆盖拨号目标（地址 + 端口 0 沿用），
/// URL host 仍作 Host 头与 SNI（Go `dial` 的 target 覆盖语义）。
#[derive(Clone)]
pub(crate) struct XdriveTcpConnector {
    fronting: Option<(Address, u16)>,
}

impl XdriveTcpConnector {
    async fn dial(&self, uri: &Uri) -> io::Result<XdriveTcpStream> {
        let host =
            uri.host().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "bad address"))?;
        let default_port = if uri.scheme_str() == Some("https") { 443 } else { 80 };
        let port = uri.port_u16().unwrap_or(default_port);
        let (addr, port) = match self.fronting.as_ref() {
            Some((address, fronting_port)) => {
                (address.clone(), if *fronting_port != 0 { *fronting_port } else { port })
            },
            None => (Address::new_domain(host), port),
        };
        let tcp = match addr.ip() {
            Some(ip) => tokio::net::TcpStream::connect((ip, port)).await,
            // 域名走 tokio 系统解析（sockopt/finalmask 随 B6 收口；Go DialSystem 同位）。
            None => {
                tokio::net::TcpStream::connect((addr.as_domain().unwrap_or_default(), port)).await
            },
        }
        .map_err(|e| io::Error::other(format!("failed to dial to dest: {e}")))?;
        tcp.set_nodelay(true).ok();
        Ok(XdriveTcpStream(TokioIo::new(tcp)))
    }
}

impl TowerService<Uri> for XdriveTcpConnector {
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<XdriveTcpStream>> + Send>>;
    type Response = XdriveTcpStream;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let this = self.clone();
        Box::pin(async move { this.dial(&uri).await })
    }
}

/// scheme 分派连接器（Go `serviceTransport` 的 plain/secure 选择）：http 走明文，
/// https 走 rustls（ALPN 协商 h2/h1）。
#[derive(Clone)]
pub(crate) enum XdriveConnector {
    Plain(XdriveTcpConnector),
    Tls(HttpsConnector<XdriveTcpConnector>),
}

/// 连接产物（Go `tlsConn` / `conn` 的两路）。
#[allow(
    clippy::large_enum_variant,
    reason = "TLS 分支携带 rustls 会话状态（~1.1KB vs 明文 48B）是固有尺寸；Box 化会给每请求热路径加一层间接——splithttp SplitConnector 同款豁免"
)]
pub(crate) enum XdriveStream {
    Plain(XdriveTcpStream),
    Tls(MaybeHttpsStream<XdriveTcpStream>),
}

impl hyper::rt::Read for XdriveStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Self::Tls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl hyper::rt::Write for XdriveStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Self::Tls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_flush(cx),
            Self::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Self::Tls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

impl HttpConnection for XdriveStream {
    fn connected(&self) -> Connected {
        match self {
            Self::Plain(s) => s.connected(),
            Self::Tls(s) => s.connected(),
        }
    }
}

impl TowerService<Uri> for XdriveConnector {
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<XdriveStream>> + Send>>;
    type Response = XdriveStream;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self {
            Self::Plain(c) => c.poll_ready(cx),
            // HttpsConnector 的 Service 错误是 Box<dyn Error>，收敛到 io::Error。
            Self::Tls(c) => match c.poll_ready(cx) {
                Poll::Ready(Ok(v)) => Poll::Ready(Ok(v)),
                Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::other(e))),
                Poll::Pending => Poll::Pending,
            },
        }
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        match self {
            Self::Plain(c) => {
                if uri.scheme_str() == Some("https") {
                    return Box::pin(async {
                        Err(io::Error::other("https request without TLS settings"))
                    });
                }
                let fut = TowerService::call(c, uri);
                Box::pin(async move { fut.await.map(XdriveStream::Plain) })
            },
            Self::Tls(c) => {
                let fut = TowerService::call(c, uri);
                Box::pin(async move { fut.await.map_err(io::Error::other).map(XdriveStream::Tls) })
            },
        }
    }
}

/// hyper 客户端装配（Go `secure()`/plain `http.Transport` 的 builder 面）。
/// 每次调用产出**一个**独立 hyper 客户端（≈ Go 每个新 client 一次 `newServiceClient`）。
#[must_use]
pub(crate) fn build_hyper_client(core: &ClientCore) -> HyperClient {
    let connector = match core.tls.as_ref() {
        Some(tls) => {
            // bd 3ze9 前科：with_tls_config 对预定义 ALPN 直接 assert panic——
            // build_client_config 缺省填 [h2, http/1.1]，清空后由
            // enable_http1+enable_http2 覆写为同值。
            let mut cfg = (**tls).clone();
            cfg.alpn_protocols.clear();
            let https = HttpsConnectorBuilder::new()
                .with_tls_config(cfg)
                .https_or_http()
                .enable_http1()
                .enable_http2()
                .wrap_connector(XdriveTcpConnector { fronting: core.fronting.clone() });
            XdriveConnector::Tls(https)
        },
        None => XdriveConnector::Plain(XdriveTcpConnector { fronting: core.fronting.clone() }),
    };
    let mut client_builder = Client::builder(TokioExecutor::new());
    client_builder
        .pool_timer(TokioTimer::new())
        // Go http.Transport.IdleConnTimeout 同值（splithttp 同款 90s）。
        .pool_idle_timeout(Some(Duration::from_secs(90)))
        .pool_max_idle_per_host(POOL_MAX_IDLE_PER_HOST)
        .timer(TokioTimer::new())
        .http2_keep_alive_while_idle(true)
        .http2_keep_alive_timeout(Duration::from_secs(15));
    if let Some(period) = core.keepalive {
        client_builder.http2_keep_alive_interval(period);
    }
    client_builder.build(connector)
}

// ── xmux 连接单元（Go poolConn）───────────────────────────────────────────

/// xmux 池连接单元：每单元一个 hyper 客户端（≈ 一条 h2 连接），closing/inflight
/// 记账对齐 Go `poolConn`（IsClosed=closing 立即真；取消面 = inflight 归零才撤客户端）。
pub(crate) struct XdriveHttpClient {
    state: parking_lot::Mutex<PoolConnState>,
    /// 单元出生时刻（hMaxReusableSecs 的近似退役判定：Go sessionTransport 读
    /// `UnreusableAt`（XmuxClient 私有字段不可见），此处按出生时刻 + 自采样上限
    /// 判定——同分布同语义，逐单元采样值与池内记账独立，登记为偏差）。
    born: std::time::Instant,
    reuse_limit: Option<Duration>,
}

struct PoolConnState {
    client: Option<HyperClient>,
    inflight: usize,
    closing: bool,
}

impl XdriveHttpClient {
    fn new(core: &ClientCore, reuse_limit: Option<Duration>, clock: Arc<dyn Clock>) -> Self {
        Self {
            state: parking_lot::Mutex::new(PoolConnState {
                client: Some(build_hyper_client(core)),
                inflight: 0,
                closing: false,
            }),
            born: clock.now_instant(),
            reuse_limit,
        }
    }

    /// 请求开始记账（Go `conn.inflight++`；调用方在持会话锁时调用防迁移竞态）。
    fn begin(&self) {
        self.state.lock().inflight += 1;
    }

    /// 请求结束记账：closing 且在途归零即撤客户端（Go `poolConn.done`）。
    fn finish(&self) {
        let mut state = self.state.lock();
        state.inflight -= 1;
        if state.closing && state.inflight == 0 {
            state.client = None;
        }
    }

    /// 关闭单元（Go `poolConn.Close`）：closing 立即生效，在途请求跑完后撤客户端。
    /// 消费方 = 会话慢连接退役（Go `sessionTransport.stalled` → `poolConn.Close`），
    /// 随 B4 drive 的 `do()` 接入。
    #[allow(dead_code)] // B4 接线位：template 不消费退役路径（Go template 同款）
    fn close(&self) {
        let mut state = self.state.lock();
        state.closing = true;
        if state.inflight == 0 {
            state.client = None;
        }
    }

    fn client(&self) -> Option<HyperClient> {
        self.state.lock().client.clone()
    }

    fn reuse_expired(&self, clock: &dyn Clock) -> bool {
        self.reuse_limit
            .is_some_and(|limit| clock.now_instant().saturating_duration_since(self.born) > limit)
    }
}

impl XmuxConn for XdriveHttpClient {
    fn is_closed(&self) -> bool {
        self.state.lock().closing
    }
}

// ── 池与 xmux 缺省（Go newConnPool + XDriveConfig.Build）───────────────────

/// 每共享存储一个 xmux 管理器（Go `connPool`：单元工厂 = [`XdriveHttpClient`]）。
/// 池单元 `C = XdriveHttpClient`（孤儿规则禁 `impl XmuxConn for Arc<本地类型>`，
/// splithttp 同款即其本地 `DefaultDialerClient` 直作单元）。
pub(crate) struct ConnPool {
    pub(crate) xmux: Arc<XmuxManager<XdriveHttpClient>>,
}

impl ConnPool {
    /// 按流设置 + 配置构造（Go `newConnPool(config, newClient)`；TLS 构建在池外
    /// 一次完成、闭包只做装配，工厂闭包不可失败）。
    ///
    /// # Errors
    /// 安全层配置解析失败。
    pub(crate) fn new(settings: &StreamSettings, config: &Config) -> io::Result<Self> {
        let xmux = xdrive_xmux_config(config.xmux.as_ref(), &config.service, config.h3)?;
        let core = ClientCore::from_settings(settings, xmux.h_keep_alive_period)?;
        Self::with_core(core, xmux)
    }

    /// 按已解析的 xmux 配置 + 客户端核构造（[`TemplateStorage`](crate::template::TemplateStorage)
    /// 复用同一核建独立客户端，免重复解析 TLS 配置）。
    pub(crate) fn with_core(core: ClientCore, xmux: XmuxConfig) -> io::Result<Self> {
        let clock = xray_frame::compat::clock();
        // Go newXmuxClient 对 hMaxReusableSecs 逐单元采样；此处同分布自采样
        // （XmuxClient 私有字段不可见，见 [`XdriveHttpClient::born`] 的偏差登记）。
        let sample_xmux = xmux.clone();
        let xmux = Arc::new(XmuxManager::new(xmux, move || {
            let secs = sample_xmux.normalized_h_max_reusable_secs().rand();
            let reuse_limit =
                (secs > 0).then(|| Duration::from_secs(u64::try_from(secs).unwrap_or(u64::MAX)));
            XdriveHttpClient::new(&core, reuse_limit, Arc::clone(&clock))
        }));
        Ok(Self { xmux })
    }
}

/// xmux 配置解析 + Go `XDriveConfig.Build` 缺省（规划 §5 B2）：
/// 整体为空 ⇒ `maxConnections {1,1}`（google-drive + h2 ⇒ `{4,4}`，Go：h2 每
/// 连接 1MiB 窗，长 RTT 多会话会互相挤占；h3 无此限）+ `hMaxReusableSecs
/// {1800,3000}`；`maxConnections` 与 `maxConcurrency` 同时 `to>0` ⇒ 拒。
///
/// # Errors
/// 字段类型非法（数字必须是整数）或双上限同配。
pub(crate) fn xdrive_xmux_config(
    xmux: Option<&serde_json::Value>,
    service: &str,
    h3: bool,
) -> io::Result<XmuxConfig> {
    let range = |v: Option<&serde_json::Value>| -> io::Result<Option<RangeConfig>> {
        match v {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(obj) => {
                let field = |key: &str| -> io::Result<i32> {
                    let raw = obj.get(key).map_or(Ok(0), |n| {
                        n.as_i64().ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                format!("xmux range {key} must be an integer, got {n}"),
                            )
                        })
                    })?;
                    i32::try_from(raw).map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("xmux range {key} exceeds i32: {raw}"),
                        )
                    })
                };
                Ok(Some(RangeConfig::new(field("from")?, field("to")?)))
            },
        }
    };
    let keep_alive = match xmux.and_then(|v| v.get("hKeepAlivePeriod")) {
        None | Some(serde_json::Value::Null) => 0i64,
        Some(n) => n.as_i64().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "xmux hKeepAlivePeriod must be an integer")
        })?,
    };

    let obj = xmux.filter(|v| !v.is_null());
    let mut cfg = XmuxConfig {
        max_concurrency: range(obj.and_then(|v| v.get("maxConcurrency")))?,
        max_connections: range(obj.and_then(|v| v.get("maxConnections")))?,
        c_max_reuse_times: range(obj.and_then(|v| v.get("cMaxReuseTimes")))?,
        h_max_request_times: range(obj.and_then(|v| v.get("hMaxRequestTimes")))?,
        h_max_reusable_secs: range(obj.and_then(|v| v.get("hMaxReusableSecs")))?,
        h_keep_alive_period: keep_alive,
    };

    let is_empty = |r: &Option<RangeConfig>| r.as_ref().is_none_or(|r| r.from == 0 && r.to == 0);
    let drive = matches!(service, "google-drive" | "Google Drive");
    if cfg.max_connections.as_ref().is_some_and(|r| r.to > 0)
        && cfg.max_concurrency.as_ref().is_some_and(|r| r.to > 0)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "maxConnections cannot be specified together with maxConcurrency",
        ));
    }
    if is_empty(&cfg.max_connections)
        && is_empty(&cfg.max_concurrency)
        && is_empty(&cfg.c_max_reuse_times)
        && is_empty(&cfg.h_max_request_times)
        && is_empty(&cfg.h_max_reusable_secs)
        && cfg.h_keep_alive_period == 0
    {
        let connections = if drive && !h3 { 4 } else { 1 };
        cfg.max_connections = Some(RangeConfig::new(connections, connections));
        cfg.h_max_reusable_secs = Some(RangeConfig::new(1800, 3000));
    }
    Ok(cfg)
}

// ── 会话传输（Go sessionTransport）────────────────────────────────────────

/// 一会话一个：在池连接间迁移（closed/leftRequests 耗尽/复用到期即换新），
/// 在途记账防迁移竞态（Go `sessionTransport`；慢连接退役 `stalled` 钩子随 B4）。
pub(crate) struct SessionTransport {
    pool: Arc<XmuxManager<XdriveHttpClient>>,
    state: parking_lot::Mutex<SessionState>,
}

struct SessionState {
    client: Option<Arc<XmuxClient<XdriveHttpClient>>>,
    closed: bool,
}

impl SessionTransport {
    pub(crate) fn new(pool: Arc<XmuxManager<XdriveHttpClient>>) -> Self {
        Self { pool, state: parking_lot::Mutex::new(SessionState { client: None, closed: false }) }
    }

    /// 发送一条请求（Go `sessionTransport.RoundTrip`：挑选/迁移 + inflight 记账 +
    /// 停滞检测透传）。响应全量缓冲。
    ///
    /// # Errors
    /// 会话已关闭、池无客户端、连接/协议错误或停滞。
    pub(crate) async fn round_trip(
        &self,
        req: OutRequest,
        stall: Duration,
    ) -> io::Result<(StatusCode, Bytes)> {
        let clock = xray_frame::compat::clock();
        let client = {
            let mut session = self.state.lock();
            if session.closed {
                return Err(io::Error::other("the session is closed"));
            }
            // 挑选/迁移（Go 锁段）：closed / leftRequests 耗尽 / 复用到期即换新。
            let mut migrate = false;
            if let Some(current) = session.client.as_ref() {
                let conn = &current.conn;
                if conn.is_closed() || conn.reuse_expired(clock.as_ref()) {
                    migrate = true;
                } else {
                    // Go LeftRequests.Add(-1) < 0 的等价判定（dec 钳 0：到 0 即耗尽）。
                    current.dec_left_requests();
                    migrate = current.left_requests() <= 0;
                }
            }
            if session.client.is_none() || migrate {
                let next = self.pool.get_xmux_client();
                next.inc_open_usage();
                next.dec_left_requests();
                if let Some(current) = session.client.take() {
                    current.dec_open_usage();
                }
                session.client = Some(Arc::clone(&next));
            }
            let client = Arc::clone(session.client.as_ref().expect("client set above"));
            // 记账在持锁段内（Go：另一请求先迁移会抢在发送前关连接）。
            client.conn.begin();
            client
        };
        let conn = &client.conn;

        let hyper_client = match conn.client() {
            Some(client) => client,
            None => {
                conn.finish();
                return Err(io::Error::other("the session is closed"));
            },
        };
        let result = service_round_trip(&hyper_client, req, stall).await;
        // served 标记（退役判定输入）随 B4 stalled 钩子接入。
        conn.finish();
        result
    }

    /// 会话收尾（Go `sessionTransport.Close`）：归还池记账。
    pub(crate) fn close(&self) {
        let mut session = self.state.lock();
        session.closed = true;
        if let Some(current) = session.client.take() {
            current.dec_open_usage();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xmux_defaults_when_empty() {
        // 空 xmux ⇒ maxConnections {1,1} + hMaxReusableSecs {1800,3000}（Go Build）。
        let cfg = xdrive_xmux_config(None, "template", false).unwrap();
        assert_eq!(cfg.max_connections, Some(RangeConfig::new(1, 1)));
        assert_eq!(cfg.h_max_reusable_secs, Some(RangeConfig::new(1800, 3000)));
        assert_eq!(cfg.max_concurrency, None);
        assert_eq!(cfg.h_keep_alive_period, 0);
    }

    #[test]
    fn xmux_defaults_drive_h2_gets_four() {
        let cfg = xdrive_xmux_config(None, "google-drive", false).unwrap();
        assert_eq!(cfg.max_connections, Some(RangeConfig::new(4, 4)));
        // drive + h3 回 {1,1}。
        let cfg = xdrive_xmux_config(None, "google-drive", true).unwrap();
        assert_eq!(cfg.max_connections, Some(RangeConfig::new(1, 1)));
    }

    #[test]
    fn xmux_explicit_passthrough_and_conflict() {
        let v = serde_json::json!({
            "maxConnections": {"from": 2, "to": 2},
            "hMaxRequestTimes": {"from": 100, "to": 100},
            "hKeepAlivePeriod": 60
        });
        let cfg = xdrive_xmux_config(Some(&v), "template", false).unwrap();
        assert_eq!(cfg.max_connections, Some(RangeConfig::new(2, 2)));
        assert_eq!(cfg.h_max_request_times, Some(RangeConfig::new(100, 100)));
        assert_eq!(cfg.h_keep_alive_period, 60);
        assert_eq!(cfg.h_max_reusable_secs, None, "非空 xmux 不套缺省");

        let bad = serde_json::json!({
            "maxConnections": {"from": 1, "to": 1},
            "maxConcurrency": {"from": 1, "to": 1}
        });
        let err = xdrive_xmux_config(Some(&bad), "template", false).unwrap_err();
        assert!(err.to_string().contains("maxConnections"));
    }

    #[test]
    fn keepalive_defaults_and_overrides() {
        let settings = StreamSettings::tcp();
        // 缺省 45s（ChromeH2KeepAlivePeriod）。
        assert_eq!(
            ClientCore::from_settings(&settings, 0).unwrap().keepalive,
            Some(CHROME_H2_KEEP_ALIVE)
        );
        // >0 覆盖 / <0 关闭（Go HKeepAlivePeriod 语义）。
        assert_eq!(
            ClientCore::from_settings(&settings, 60).unwrap().keepalive,
            Some(Duration::from_secs(60))
        );
        assert_eq!(ClientCore::from_settings(&settings, -1).unwrap().keepalive, None);
    }
}
