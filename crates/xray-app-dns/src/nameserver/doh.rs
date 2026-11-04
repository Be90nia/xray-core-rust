//! DoH (DNS over HTTPS) nameserver。对应 Go `app/dns/nameserver_doh.go`。
//!
//! ## 实现
//!
//! - `tokio::net::TcpStream` → `xray_tls::client` TLS 握手 → `h2::client::handshake` → POST
//!   /dns-query。
//! - DNS wire format 由 `hickory-proto` 处理，body 为裸 DNS message（无 2B 长度前缀，HTTP/2 自带
//!   framing）。
//! - RFC 8484：POST + Content-Type: application/dns-message。
//! - 默认端口 443。
//! - 自动接入 cache（实现 `CachedNameserver`）。
//!
//! ## 会话复用（bd yzhb4）
//!
//! 同一 NS 复用一条 h2 连接（h2 多路复用，1 条承载全部查询）：`DOH_SESSIONS_*`
//! 三条硬上限见常量注释。连接失效（对端关闭/半开/GOAWAY）→ 复用时探测到失败即
//! 丢弃并回退新建；空闲 `DOH_IDLE_TIMEOUT` 由看门狗关闭，复用前另有懒判兜底。
//!
//! 会话在**查询期间留在槽里**（只克隆发送端），并发 A/AAAA 共享同一条连接
//! ⇒ 双栈并发化不翻倍连接数；冷启动由建连门串行建档（同样只建一条）。
//!
//! deadline 语义（不变）：`query_timeout` 是**整条查询的绝对时刻**，dial/TLS/h2/
//! response 与「复用失败→重建」全部共享它（Go `nameserver_doh.go:167-172`）——
//! 复用只省时间，不新增预算。
//!
//! ## 跳过范围
//!
//! - 走 Xray routing/dispatcher 出口（直接用 tokio socket + xray_tls + h2）

use std::{
    future::Future,
    net::IpAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use h2::client::{self, SendRequest};
use hickory_proto::rr::RecordType;
use http::{Method, Request, StatusCode, header::CONTENT_TYPE};
use parking_lot::Mutex;
use skeleton_infra::fx::{FxScope, ScopeClosed};
use tokio_rustls::rustls::ClientConfig;
use xray_common::net::{destination::Destination, port::Port};
use xray_frame::deadline::{Budget, BudgetDeadline, BudgetTimer};
use xray_tls::utls::client as tls_client;

use crate::{
    cache_controller::CacheController,
    config::IpOption,
    dnscommon::{
        AtomicReqIdGen, IpRecord, ReqIdGen, build_dns_query, parse_dns_response,
        parsed_to_ip_record,
    },
    error::DnsError,
    nameserver::{
        NameServerConfig, Server,
        cached::{CachedNameserver, QueryOutcome, query_ip},
    },
};

/// DoH 响应最大字节数。
const DOH_RECV_MAX: usize = 65535;

/// DoH 默认 URL 路径（RFC 8484）。
const DEFAULT_DOH_PATH: &str = "/dns-query";

/// DoH 热会话全局上限（显式常量，非内存推导）：8 条 h2 连接。
///
/// 内存核算（256MB 机 xray 预算 ~96MB）：单条空闲 h2 连接 ≈ 50KB（h2 连接态 +
/// TLS 读写缓冲，流级缓冲随请求释放）⇒ 8 × 50KB ≈ 400KB ≤ 1MB 上限。
const DOH_MAX_SESSIONS: usize = 8;

/// 热会话空闲上限（显式常量）：到点关闭，不常驻。
const DOH_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// 全局在用热会话数（[`SessionLease`] 记账）。
static LIVE_SESSIONS: AtomicUsize = AtomicUsize::new(0);

/// 全局会话名额租约：Drop 归还；取不到名额 ⇒ 本次查询照常但不落槽（用完即关）。
struct SessionLease;

impl SessionLease {
    fn try_acquire() -> Option<Self> {
        LIVE_SESSIONS
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < DOH_MAX_SESSIONS).then_some(n + 1)
            })
            .ok()
            .map(|_| Self)
    }
}

impl Drop for SessionLease {
    fn drop(&mut self) {
        LIVE_SESSIONS.fetch_sub(1, Ordering::AcqRel);
    }
}

/// 一条可复用的 DoH 会话（`ready()` 后的 h2 发送端 + 空闲计时 + 全局名额）。
struct DohSession {
    /// h2 发送端（克隆即并发复用；h2 多路复用无需多条连接）。
    send: SendRequest<Bytes>,
    /// 空闲计时（存入时重置；复用前 `is_expired` 懒判到期）。
    idle: BudgetTimer,
    /// 全局名额（`None` = 满额，仅本次查询用，不落槽）。
    lease: Option<SessionLease>,
}

/// 单 NS 热会话槽（容量 1 条；加上在飞查询即「每 NS ≤2 条」上限）。
struct SessionSlot {
    /// 当前热会话（查询期间**留在槽里**：并发 A/AAAA 各克隆一个发送端，
    /// 同一连接承载两条查询——h2 多路复用，连接数不翻倍）。
    current: Mutex<Option<DohSession>>,
    /// 建连门（异步互斥）：冷启动/失效后并发多条查询只建一条连接。
    connecting: tokio::sync::Mutex<()>,
}

impl SessionSlot {
    fn new() -> Self {
        Self { current: Mutex::new(None), connecting: tokio::sync::Mutex::new(()) }
    }
}

/// DoH DNS nameserver。
///
/// 结构与 `DotNameServer` 对称，区别：TLS 之上多一层 HTTP/2。
pub struct DohNameServer {
    /// 服务名。
    name: String,
    /// 远端 DNS 服务器地址（IP 直连；域名运行期解析——bd mcpo）。
    dest: Destination,
    /// TLS SNI（ServerName）。
    server_name: String,
    /// TLS 客户端配置。
    tls_config: Arc<ClientConfig>,
    /// h2c 明文模式（Go `h2c://`）：跳过 TLS，HTTP/2 直接跑 TCP。
    plain_h2c: bool,
    /// 缓存控制器。
    cache: Arc<CacheController>,
    /// EDNS0 client subnet。
    client_ip: Vec<u8>,
    /// 单次查询总超时（整条查询共享的绝对 deadline）。
    query_timeout: Duration,
    /// 请求 ID 生成器。
    id_gen: AtomicReqIdGen,
    /// 域名解析器（直连兜底路径）。
    resolver: Arc<dyn crate::dial::HostResolver>,
    /// `+local`：强制直连（绕过共享 dialer，Go Local mode nil dispatcher）。
    force_local: bool,
    /// 热会话槽（bd yzhb4：同 NS 复用一条 h2 连接）。
    session: Arc<SessionSlot>,
}

/// h2c authority 取目的地址字符串（bd d881①：空 `server_name` →
/// `https:///dns-query` 非法 URI → `body(())` Err 静默早退，h2c 全不可用）。
fn h2c_server_name(ns: &NameServerConfig) -> String {
    ns.address.to_string()
}

/// DoH 查询兜底超时（bd cjwc G13）。
///
/// 对齐 Go `app/dns/nameserver_doh.go:167-172`：上层 ctx 带 deadline 时优先，
/// 否则兜底 `now+5s`——**一个绝对时刻覆盖整条查询**（dial/TLS/h2/response 共享
/// 同一预算，`context.WithDeadline`（:194）把同一 `deadline` 传给每个 req）。
/// Rust 查询链无 ctx deadline 概念，`ns.timeout_ms > 0` 为等价的显式 deadline
/// 通道（配置注入优先），缺省 5s。
///
/// 结构对齐（bd ezrg4）：`query_once` 全部等待点共用查询入口算出的绝对
/// deadline（`timeout_at`），而非各段独立满额计时——分段制下慢握手会把
/// response 段的 5s 起点推后，整条查询可远超 5s（macOS CI 实测 7.5s）；Go
/// 语义是查询自入口 5s 必有结论。
fn effective_query_timeout(timeout_ms: u32) -> Duration {
    if timeout_ms > 0 {
        Duration::from_millis(u64::from(timeout_ms))
    } else {
        Duration::from_secs(5)
    }
}

impl DohNameServer {
    /// 构造。
    #[must_use]
    #[allow(clippy::too_many_arguments)] // Go NewServerClient 装配面 7 参直译，打包结构属 API 变更
    pub fn new(
        dest: Destination,
        server_name: String,
        tls_config: Arc<ClientConfig>,
        cache: Arc<CacheController>,
        client_ip: Vec<u8>,
        query_timeout: Duration,
        plain_h2c: bool,
    ) -> Self {
        let name = if plain_h2c {
            format!("DoH-h2c:{}:{}", dest.address(), dest.port())
        } else {
            format!("DoH:{}:{}", dest.address(), dest.port())
        };
        Self {
            name,
            dest,
            server_name,
            tls_config,
            plain_h2c,
            cache,
            client_ip,
            query_timeout,
            id_gen: AtomicReqIdGen::new(),
            resolver: Arc::new(crate::dial::SystemHostResolver),
            force_local: false,
            session: Arc::new(SessionSlot::new()),
        }
    }

    /// 标记 `+local`（强制直连，绕过共享 dialer；bd wmdn②）。
    #[must_use]
    pub fn force_local(mut self, v: bool) -> Self {
        self.force_local = v;
        self
    }

    /// 从 `NameServerConfig` 构造。
    pub fn from_config(
        ns: &NameServerConfig,
        server_name: String,
        tls_config: Arc<ClientConfig>,
    ) -> Result<Box<dyn Server>, DnsError> {
        let dest = Destination::tcp(ns.address.clone(), Port::new(ns.port));
        let timeout_dur = effective_query_timeout(ns.timeout_ms);
        let cache = Arc::new(CacheController::new(
            format!("DoH:{}", dest),
            ns.disable_cache.unwrap_or(false),
            ns.serve_stale.unwrap_or(false),
            ns.serve_expired_ttl.unwrap_or(0),
            ns.negative_ttl_secs.unwrap_or(0),
        ));
        // P1-11：cleanup 不在配置期 spawn——启动期经 Server::start_managed_tasks 注册。
        Ok(Box::new(Arc::new(
            Self::new(
                dest,
                server_name,
                tls_config,
                cache,
                ns.client_ip.clone(),
                timeout_dur,
                false,
            )
            .force_local(ns.force_local),
        )))
    }

    /// h2c（明文 HTTP/2）构造。对应 Go `NewDoHNameServer(u, dispatcher, true, ...)`。
    pub fn from_config_h2c(ns: &NameServerConfig) -> Result<Box<dyn Server>, DnsError> {
        let dest = Destination::tcp(ns.address.clone(), Port::new(ns.port));
        // bd ypsl P2①：server_name 空串 → query_once 构造 `https:///dns-query`
        // 非法 URI → 构造失败被上层吞成 record not found（h2c 完全不可用且报错
        // 误导）。authority 取目的地址字符串（域名或 IP 字面量）。
        let server_name = h2c_server_name(ns);
        let timeout_dur = effective_query_timeout(ns.timeout_ms);
        let cache = Arc::new(CacheController::new(
            format!("DoH-h2c:{}", dest),
            ns.disable_cache.unwrap_or(false),
            ns.serve_stale.unwrap_or(false),
            ns.serve_expired_ttl.unwrap_or(0),
            ns.negative_ttl_secs.unwrap_or(0),
        ));
        // P1-11：cleanup 不在配置期 spawn——启动期经 Server::start_managed_tasks 注册。
        Ok(Box::new(Arc::new(
            Self::new(
                dest,
                server_name,
                xray_tls::utls::default_client_config(),
                cache,
                ns.client_ip.clone(),
                timeout_dur,
                true,
            )
            .force_local(ns.force_local),
        )))
    }

    /// 取一条仍新鲜的热会话发送端（**会话留在槽里**：克隆即并发复用，h2 一条
    /// 连接同时承载多条查询 ⇒ 并发化不翻倍连接数）。
    ///
    /// 空闲到期即丢弃关闭。
    fn session_sender(&self) -> Option<SendRequest<Bytes>> {
        let mut guard = self.session.current.lock();
        let session = guard.as_mut()?;
        if session.idle.is_expired() {
            // 懒判兜底：看门狗被停机取消时同样带不出过期连接。
            drop(guard.take());
            tracing::debug!(target: "xray.dns.doh", server = %self.name,
                "doh: 热会话空闲到期，丢弃");
            return None;
        }
        // 在用即非空闲：看门狗不得在查询中途把连接抽走。
        session.idle.reset(DOH_IDLE_TIMEOUT);
        Some(session.send.clone())
    }

    /// 丢弃当前热会话（对端关闭/半开/GOAWAY；连接驱动随之收尾）。
    fn drop_session(&self) {
        drop(self.session.current.lock().take());
    }

    /// 取一条可用会话的发送端（热会话优先；冷启动/失效后经建连门串行建档）。
    async fn ensure_session(
        &self,
        fx: &FxScope,
        deadline: &BudgetDeadline,
    ) -> Result<SendRequest<Bytes>, DnsError> {
        if let Some(send) = self.session_sender() {
            return Ok(send);
        }
        // 建连门：并发 A/AAAA 同时冷启动时只建一条连接（门内复查）。
        let _gate = self.session.connecting.lock().await;
        if let Some(send) = self.session_sender() {
            return Ok(send);
        }
        let session = self.open_session(fx, deadline).await?;
        let send = session.send.clone();
        self.store_session(session);
        Ok(send)
    }

    /// 归还会话入槽（空闲计时重置；无名额 ⇒ 用完即关，不落槽）。
    fn store_session(&self, mut session: DohSession) {
        if session.lease.is_none() {
            return;
        }
        session.idle.reset(DOH_IDLE_TIMEOUT);
        let replaced = self.session.current.lock().replace(session);
        drop(replaced); // 同 NS 竞态顶替的旧会话随 drop 关闭
    }

    /// 空闲会话看门狗（每 NS 一条生命周期任务，不随查询数增长）。
    ///
    /// 扫描粒度 = `DOH_IDLE_TIMEOUT`（到期后 ≤1 个周期关闭），精确关闭另有
    /// 复用前懒判（[`Self::session_sender`]）兜底。
    fn start_session_watchdog(&self, fx: &FxScope) {
        if fx.is_closed() {
            return;
        }
        let slot = Arc::clone(&self.session);
        let watchdog = async move {
            let mut tick = Budget::tokio().arm_timer(DOH_IDLE_TIMEOUT);
            loop {
                tick.expired().await;
                let mut guard = slot.current.lock();
                if guard.as_ref().is_some_and(|s| s.idle.is_expired()) {
                    drop(guard.take()); // drop 即关闭（连接驱动随之收尾）
                }
                drop(guard);
                tick.reset(DOH_IDLE_TIMEOUT);
            }
        };
        if xray_frame::compat::spawn_reaping(
            fx,
            &xray_frame::compat::log(),
            "dns doh session idle",
            watchdog,
        )
        .is_err()
        {
            tracing::debug!(target: "xray.dns.doh", server = %self.name,
                "doh: 停机中，空闲看门狗不启动");
        }
    }

    /// 建立一条新 h2 会话（dial → TLS → h2 → ready），全部等待点共用查询 deadline。
    async fn open_session(
        &self,
        fx: &FxScope,
        deadline: &BudgetDeadline,
    ) -> Result<DohSession, DnsError> {
        // 名额先占：满额则本次查询照常进行，但会话不落槽（用完即关）。
        let lease = SessionLease::try_acquire();

        // 经路由出站或直连兜底（域名每查询现解析）——Go dohnameserver.go:68
        // dispatcher.Dispatch 语义。connect_stream 内部仍按单次拨号计预算，
        // 总量由外层整查询 deadline 封顶。
        let stream = deadline
            .timeout(crate::dial::connect_stream(
                &self.dest,
                self.resolver.as_ref(),
                self.query_timeout,
                "doh",
                self.force_local,
            ))
            .await
            .map_err(|_| {
                tracing::debug!(target: "xray.dns.doh", "doh: dial TIMEOUT (query deadline)");
                DnsError::WireFormat("doh dial timeout".to_string())
            })??;

        // TLS 握手（h2c 明文跳过）+ HTTP/2 handshake。
        tracing::debug!(target: "xray.dns.doh", "doh: stream connected");
        let (h2, h2_conn): (_, Pin<Box<dyn Future<Output = ()> + Send>>) = if self.plain_h2c {
            let (h2, conn) = deadline
                .timeout(client::handshake(stream))
                .await
                .map_err(|_| DnsError::WireFormat("doh h2c handshake timeout".to_string()))?
                .map_err(|e| DnsError::WireFormat(format!("doh h2c handshake: {e}")))?;
            (
                h2,
                Box::pin(async move {
                    let _ = conn.await;
                }),
            )
        } else {
            let tls_stream = deadline
                .timeout(tls_client(stream, &self.server_name, Arc::clone(&self.tls_config)))
                .await
                .map_err(|_| {
                    tracing::debug!(target: "xray.dns.doh", "doh: TLS handshake TIMEOUT");
                    DnsError::WireFormat("doh tls handshake timeout".to_string())
                })?
                .map_err(|e| DnsError::WireFormat(format!("doh tls handshake: {e}")))?;
            tracing::debug!(target: "xray.dns.doh", alpn = ?tls_stream.alpn_protocol(),
                "doh: tls established");
            let (h2, conn) = deadline
                .timeout(client::handshake(tls_stream))
                .await
                .map_err(|_| {
                    tracing::debug!(target: "xray.dns.doh", "doh: h2 handshake TIMEOUT");
                    DnsError::WireFormat("doh h2 handshake timeout".to_string())
                })?
                .map_err(|e| DnsError::WireFormat(format!("doh h2 handshake: {e}")))?;
            tracing::debug!(target: "xray.dns.doh", "doh: h2 handshake done");
            (
                h2,
                Box::pin(async move {
                    let _ = conn.await;
                }),
            )
        };
        // h2 连接驱动迁 FxScope 托管（P1-11 坑约束 5）——闸关（查询过入口检查
        // 后才被 close 的竞态窗）拒新：连接驱动随之丢弃，本次查询按错误收场，
        // 不裸 spawn、不 panic。
        // 每次查询 spawn 前先收割（bd 86i4h 阶段2）：条目不随累计查询数增长。
        let _spawned = xray_frame::compat::spawn_reaping(
            fx,
            &xray_frame::compat::log(),
            "dns doh h2 conn",
            h2_conn,
        )
        .map_err(|_: ScopeClosed| DnsError::WireFormat("doh: fx scope closed".to_string()))?;

        // 等待 h2 连接 ready（ready 消费 self 后返回 ready 态的 SendRequest）。
        let h2 = deadline
            .timeout(h2.ready())
            .await
            .map_err(|_| {
                tracing::debug!(target: "xray.dns.doh", "doh: h2 ready TIMEOUT");
                DnsError::WireFormat("doh h2 ready timeout".to_string())
            })?
            .map_err(|e| DnsError::WireFormat(format!("doh h2 ready: {e}")))?;
        tracing::debug!(target: "xray.dns.doh", "doh: h2 ready");

        Ok(DohSession { send: h2, idle: Budget::tokio().arm_timer(DOH_IDLE_TIMEOUT), lease })
    }

    /// 在给定会话上完成一次 RFC 8484 POST（复用与新建共用同一实现）。
    ///
    /// 复用失败（对端关闭/半开/GOAWAY）由调用方丢弃会话并回退新建，不在此重试。
    async fn exchange(
        &self,
        send: &SendRequest<Bytes>,
        payload: &[u8],
        req_id: u16,
        record_type: RecordType,
        deadline: &BudgetDeadline,
    ) -> Result<IpRecord, DnsError> {
        // 复用：从槽里取出的发送端每次请求前重新 ready（连接已死则此处报错）。
        let mut h2 = deadline
            .timeout(send.clone().ready())
            .await
            .map_err(|_| {
                tracing::debug!(target: "xray.dns.doh", "doh: h2 ready TIMEOUT");
                DnsError::WireFormat("doh h2 ready timeout".to_string())
            })?
            .map_err(|e| DnsError::WireFormat(format!("doh h2 ready: {e}")))?;

        // POST /dns-query + Content-Type: application/dns-message
        // bd ypsl：h2 HEADERS 必须带 :authority——相对形式 uri("/dns-query") 发出的
        // 请求无 authority，真实 DoH server（cloudflare/alidns 实测）收到后不响应
        // （resp 4s 超时）。完整 URL 让 h2 拆出 :scheme/:authority/:path。
        let request = Request::builder()
            .method(Method::POST)
            .uri(format!("https://{}{}", self.server_name, DEFAULT_DOH_PATH))
            .header(CONTENT_TYPE, "application/dns-message")
            .body(())
            .map_err(|e| DnsError::WireFormat(format!("doh build request: {e}")))?;

        // bd ypsl 追查（临时）：真实环境 4s 无响应，定位请求是否发出/响应是否到达
        tracing::debug!(target: "xray.dns.doh", uri = ?request.uri(),
            headers = ?request.headers(), "doh: request built");

        let (resp_future, mut send_stream) = h2
            .send_request(request, false)
            .map_err(|e| DnsError::WireFormat(format!("doh send_request: {e}")))?;
        tracing::debug!(target: "xray.dns.doh", "doh: send_request ok");

        // 发送 DNS query body + end_of_stream。
        send_stream
            .send_data(Bytes::copy_from_slice(payload), true)
            .map_err(|e| DnsError::WireFormat(format!("doh send_data: {e}")))?;
        tracing::debug!(target: "xray.dns.doh", "doh: body sent");

        // 读 HTTP 响应。
        let response = deadline
            .timeout(resp_future)
            .await
            .map_err(|_| {
                tracing::debug!(target: "xray.dns.doh", "doh: response TIMEOUT ({}ms)",
                    self.query_timeout.as_millis());
                DnsError::WireFormat("doh response timeout".to_string())
            })?
            .map_err(|e| DnsError::WireFormat(format!("doh response: {e}")))?;
        tracing::debug!(target: "xray.dns.doh", status = ?response.status(),
            "doh: response headers received");

        if response.status() != StatusCode::OK {
            return Err(DnsError::WireFormat(format!("doh http status: {}", response.status())));
        }

        // 读 body（DNS wire format，无长度前缀）。
        let mut body = response.into_body();
        let mut buf = Vec::new();
        loop {
            match deadline.timeout(body.data()).await {
                Ok(Some(chunk)) => {
                    let chunk =
                        chunk.map_err(|e| DnsError::WireFormat(format!("doh body: {e}")))?;
                    buf.extend_from_slice(&chunk);
                    if buf.len() > DOH_RECV_MAX {
                        return Err(DnsError::WireFormat(format!(
                            "doh response too large: {}",
                            buf.len()
                        )));
                    }
                },
                Ok(None) => break,
                Err(_) => {
                    return Err(DnsError::WireFormat("doh body read timeout".to_string()));
                },
            }
        }

        if buf.is_empty() {
            return Err(DnsError::WireFormat("doh empty response body".to_string()));
        }

        // 713x6：解析时刻取自注入时钟（CacheController P1-12 单钟语义）。
        let now = self.cache.clock().now_instant();
        let parsed = parse_dns_response(&buf, req_id, record_type, now)?;
        Ok(parsed_to_ip_record(&parsed, now))
    }

    /// 单族查询（族未启用返回 `None`，不建连）。
    async fn query_once_if_enabled(
        &self,
        enabled: bool,
        fqdn: &str,
        record_type: RecordType,
    ) -> Option<Result<IpRecord, DnsError>> {
        if !enabled {
            return None;
        }
        Some(self.query_once(fqdn, record_type).await)
    }

    /// 发送单次 DNS 查询（DoH），等待响应。
    async fn query_once(&self, fqdn: &str, record_type: RecordType) -> Result<IpRecord, DnsError> {
        // P1-11：h2 conn 驱动的托管口先验——未注单（实例未 start）或已关
        // （停机中）快速失败，不发起新上游连接，不裸 spawn（坑约束 5）。
        let fx = self.cache.fx_scope().ok_or_else(|| {
            DnsError::WireFormat(
                "doh: fx scope not attached (dns instance not started)".to_string(),
            )
        })?;
        if fx.is_closed() {
            return Err(DnsError::WireFormat("doh: fx scope closed (shutting down)".to_string()));
        }

        let req_id = self.id_gen.next_id();
        let payload = build_dns_query(fqdn, record_type, req_id, &self.client_ip)?;

        // bd ezrg4：兜底 deadline 在查询入口算一次（Go nameserver_doh.go:167-172
        // 绝对时刻），dial/TLS/h2/response 共享，慢握手不推出新预算。
        // W4 面 3：取时统一走 Budget::tokio()（Tokio 源内部 = tokio Instant，
        // pause/advance 语义不变）。
        let deadline = Budget::tokio().deadline(self.query_timeout);

        // bd yzhb4：热会话复用（同 NS 1 条 h2 承载全部查询），握手成本只在重建时付。
        if let Some(send) = self.session_sender() {
            match self.exchange(&send, &payload, req_id, record_type, &deadline).await {
                Ok(rec) => return Ok(rec),
                Err(e) => {
                    // 对端已关/半开/GOAWAY：丢弃会话，回退新建（同一 deadline 封顶）。
                    tracing::debug!(target: "xray.dns.doh", server = %self.name, error = %e,
                        "doh: 热会话失效，重建连接");
                    if deadline.is_expired() {
                        // 预算已尽：原错误即结论（重建只会立即超时）。
                        return Err(e);
                    }
                    self.drop_session();
                },
            }
        }

        // 冷启动或失效后重建：建连门内建档，并发 A/AAAA 只建一条连接。
        let send = self.ensure_session(fx, &deadline).await?;
        let result = self.exchange(&send, &payload, req_id, record_type, &deadline).await;
        if result.is_err() {
            self.drop_session();
        }
        result
    }
}

impl CachedNameserver for DohNameServer {
    fn cache_controller(&self) -> &CacheController {
        &self.cache
    }

    fn query_timeout(&self) -> Duration {
        self.query_timeout
    }

    async fn send_query(&self, fqdn: &str, option: IpOption) -> QueryOutcome {
        let mut outcome = QueryOutcome::default();

        // A/AAAA 并发（Go `nameserver_doh.go` 每个 req 独立 goroutine）：串行 =
        // 2×RTT，并发 = 1×RTT。两条查询共享同一条 h2 会话（`session_sender`
        // 只克隆发送端，连接数不翻倍），冷启动时由建连门只建一条。
        let (v4, v6) = tokio::join!(
            self.query_once_if_enabled(option.ipv4_enable, fqdn, RecordType::A),
            self.query_once_if_enabled(option.ipv6_enable, fqdn, RecordType::AAAA),
        );
        match v4 {
            Some(Ok(rec)) => outcome.rec_v4 = Some(rec),
            Some(Err(e)) => {
                // bd d881①：失败路径必须可观察（此前 body(()) Err `?` 静默早退）。
                tracing::debug!(target: "xray.dns.doh", server = %self.name, fqdn,
                    family = "v4", error = %e, "doh: query failed");
                outcome.errors.push(e);
            },
            None => {},
        }
        match v6 {
            Some(Ok(rec)) => outcome.rec_v6 = Some(rec),
            Some(Err(e)) => {
                tracing::debug!(target: "xray.dns.doh", server = %self.name, fqdn,
                    family = "v6", error = %e, "doh: query failed");
                outcome.errors.push(e);
            },
            None => {},
        }

        outcome
    }
}

impl Server for Arc<DohNameServer> {
    fn name(&self) -> &str {
        self.name.as_str()
    }

    fn is_disable_cache(&self) -> bool {
        self.cache.disable_cache
    }

    fn is_serve_stale(&self) -> bool {
        self.cache.serve_stale
    }

    fn start_managed_tasks(&self, fx: &Arc<FxScope>) {
        self.cache.start_managed(fx, crate::cache_controller::CLEANUP_INTERVAL);
        self.start_session_watchdog(fx);
    }

    fn query_ip<'a>(
        &'a self,
        domain: &'a str,
        option: IpOption,
    ) -> Pin<Box<dyn Future<Output = Result<(Vec<IpAddr>, u32), DnsError>> + Send + 'a>> {
        Box::pin(query_ip(self.clone(), domain, option))
    }
}

/// 构造 DoH nameserver。
pub fn new_doh_name_server(
    ns: &NameServerConfig,
    server_name: String,
    tls_config: Arc<ClientConfig>,
) -> Result<Box<dyn Server>, DnsError> {
    DohNameServer::from_config(ns, server_name, tls_config)
}

/// 构造 h2c（明文 HTTP/2）nameserver。
pub fn new_doh_h2c_name_server(ns: &NameServerConfig) -> Result<Box<dyn Server>, DnsError> {
    DohNameServer::from_config_h2c(ns)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::disallowed_methods,
        reason = "713x6：测试计时不得改语义（契约）——测试取时/等待窗口保持原语义，时钟禁令只约束生产路径"
    )]
    use std::{
        net::{Ipv4Addr, SocketAddr},
        time::Instant,
    };

    use h2::server;
    use hickory_proto::{
        op::{Message, MessageType, OpCode, Query},
        rr::{Name, RData, Record, RecordType},
    };
    use http::Response;
    use tokio::net::TcpListener;
    use tokio_rustls::{TlsAcceptor, rustls::ServerConfig};
    use xray_common::net::address::Address;
    use xray_transport::connection::TcpConnection;

    use super::*;
    use crate::config::IpOption;

    fn ip_dest(addr: SocketAddr) -> Destination {
        Destination::tcp(Address::from(addr.ip()), Port::new(addr.port()))
    }

    /// 确保 rustls CryptoProvider 在并行测试中只初始化一次
    fn ensure_crypto_provider() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        });
    }

    fn make_a_response(req_id: u16, fqdn: &str, ips: Vec<Ipv4Addr>, ttl: u32) -> Vec<u8> {
        let name = Name::parse(fqdn, None).unwrap();
        let mut msg = Message::new(req_id, MessageType::Response, OpCode::Query);
        msg.add_query(Query::query(name.clone(), RecordType::A));
        for ip in ips {
            let rec =
                Record::from_rdata(name.clone(), ttl, RData::A(hickory_proto::rr::rdata::A(ip)));
            msg.add_answer(rec);
        }
        msg.to_vec().unwrap()
    }

    /// 启动 mock DoH server：自签 TLS + h2 server + accept 一次 + 回 DNS 响应。
    async fn spawn_mock_doh_server(
        fqdn: &str,
        ips: Vec<Ipv4Addr>,
        ttl: u32,
    ) -> (SocketAddr, Arc<ClientConfig>, tokio::task::JoinHandle<()>) {
        ensure_crypto_provider();
        // rcgen 自签证书（SAN: localhost）。
        let cert_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = cert_params.self_signed(&key_pair).unwrap();
        let cert_der = cert.der().to_vec();
        let key_der = key_pair.serialize_der();

        // rustls server config。
        let key = tokio_rustls::rustls::pki_types::PrivateKeyDer::try_from(key_der).unwrap();
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![tokio_rustls::rustls::pki_types::CertificateDer::from(cert_der.clone())],
                key,
            )
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let fqdn_owned = fqdn.to_string();

        let handle = xray_common::testing::spawn("spawn-mock-doh-server-accept", async move {
            let (sock, _) = listener.accept().await.unwrap();
            let tcp = TcpConnection::new(sock);
            let tls = acceptor.accept(tcp).await.unwrap();

            // h2 server handshake。
            let mut h2_conn = server::handshake(tls).await.unwrap();
            // accept 循环（send_data 后需继续 poll 连接刷出数据）。
            while let Some(req_result) = h2_conn.accept().await {
                let (req, mut respond) = match req_result {
                    Ok(r) => r,
                    Err(_) => break,
                };

                // 读 body（DNS query wire format）。
                let mut body = req.into_body();
                let mut query_buf = Vec::new();
                while let Some(chunk) = body.data().await {
                    query_buf.extend_from_slice(&chunk.unwrap());
                }

                // 解析 query ID，构造响应。
                let query_msg = Message::from_vec(&query_buf).unwrap();
                let resp_payload =
                    make_a_response(query_msg.metadata.id, &fqdn_owned, ips.clone(), ttl);

                // 发回 HTTP 200 + body。
                let resp = Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, "application/dns-message")
                    .body(())
                    .unwrap();
                let mut send = respond.send_response(resp, false).unwrap();
                send.send_data(Bytes::from(resp_payload), true).unwrap();
                // 循环回 accept → poll 连接刷出数据 → client 关闭后 None 退出
            }
        });

        // 信任自签证书的 client config。
        let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
        root_store.add(tokio_rustls::rustls::pki_types::CertificateDer::from(cert_der)).unwrap();
        let client_config = Arc::new(
            ClientConfig::builder().with_root_certificates(root_store).with_no_client_auth(),
        );

        (addr, client_config, handle)
    }

    /// 计数版 mock DoH server：逐连接独立任务、连接内可多请求（bd yzhb4 会话复用）。
    ///
    /// `close_after_first_response`：每条连接回完第一个响应后，等客户端复用（第二个
    /// 请求到达）即断开——模拟对端关连接（测「会话失效 → 重建」）。
    async fn spawn_counting_doh_server(
        fqdn: &str,
        ips: Vec<Ipv4Addr>,
        ttl: u32,
        close_after_first_response: bool,
    ) -> (SocketAddr, Arc<ClientConfig>, Arc<AtomicUsize>) {
        ensure_crypto_provider();
        let cert_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = cert_params.self_signed(&key_pair).unwrap();
        let cert_der = cert.der().to_vec();
        let key_der = key_pair.serialize_der();
        let key = tokio_rustls::rustls::pki_types::PrivateKeyDer::try_from(key_der).unwrap();
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![tokio_rustls::rustls::pki_types::CertificateDer::from(cert_der.clone())],
                key,
            )
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        let accepts_c = Arc::clone(&accepts);
        let fqdn = fqdn.to_string();

        xray_common::testing::spawn("counting-doh-server-accept", async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else { return };
                accepts_c.fetch_add(1, Ordering::SeqCst);
                let acceptor = acceptor.clone();
                let fqdn = fqdn.clone();
                let ips = ips.clone();
                xray_common::testing::spawn("counting-doh-server-conn", async move {
                    let Ok(tls) = acceptor.accept(TcpConnection::new(sock)).await else { return };
                    let Ok(mut h2_conn) = server::handshake(tls).await else { return };
                    let mut served = 0usize;
                    while let Some(req_result) = h2_conn.accept().await {
                        let Ok((req, mut respond)) = req_result else { break };
                        if close_after_first_response && served > 0 {
                            return; // 复用的第二个请求：断开连接（对端关闭语义）
                        }
                        let mut body = req.into_body();
                        let mut query_buf = Vec::new();
                        while let Some(chunk) = body.data().await {
                            let Ok(chunk) = chunk else { return };
                            query_buf.extend_from_slice(&chunk);
                        }
                        let Ok(query_msg) = Message::from_vec(&query_buf) else { return };
                        let resp_payload =
                            make_a_response(query_msg.metadata.id, &fqdn, ips.clone(), ttl);
                        let resp = Response::builder()
                            .status(StatusCode::OK)
                            .header(CONTENT_TYPE, "application/dns-message")
                            .body(())
                            .unwrap();
                        let Ok(mut send) = respond.send_response(resp, false) else { return };
                        if send.send_data(Bytes::from(resp_payload), true).is_err() {
                            return;
                        }
                        served += 1;
                    }
                });
            }
        });

        let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
        root_store.add(tokio_rustls::rustls::pki_types::CertificateDer::from(cert_der)).unwrap();
        let client_config = Arc::new(
            ClientConfig::builder().with_root_certificates(root_store).with_no_client_auth(),
        );
        (addr, client_config, accepts)
    }

    /// bd d881① 回归：h2c 的 server_name 取目的地址——空串会构造
    /// `https:///dns-query` 非法 URI（Request builder 拒绝 → `?` 静默早退）。
    #[test]
    fn h2c_config_yields_valid_query_uri() {
        let ns = NameServerConfig {
            address: Address::IPv4(Ipv4Addr::new(192, 0, 2, 1)),
            ..NameServerConfig::default()
        };
        let server_name = h2c_server_name(&ns);
        let uri = format!("https://{server_name}{DEFAULT_DOH_PATH}");
        let built = Request::builder()
            .method(Method::POST)
            .uri(&uri)
            .header(CONTENT_TYPE, "application/dns-message")
            .body(());
        assert!(built.is_ok(), "h2c URI 必须可构造: {uri}");
        assert_eq!(built.unwrap().uri().host(), Some("192.0.2.1"));

        // 旧形态锚定：空 server_name 的 URI 必须被拒绝（回归成空串即此形态）。
        let legacy = Request::builder().uri(format!("https:///{DEFAULT_DOH_PATH}")).body(());
        assert!(legacy.is_err(), "空 server_name 的 URI 必须非法（bd d881① 回归锚）");
    }

    /// bd d881① e2e：h2c（明文 HTTP/2）真实查询路径——此前非法 URI 使该形态
    /// 完全不可用且失败被吞成 record not found。
    #[tokio::test]
    async fn h2c_plain_roundtrip_through_query_ip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        xray_common::testing::spawn("h2c-plain-roundtrip-through-query-ip-accept", async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut h2_conn = server::handshake(sock).await.unwrap();
            while let Some(req_result) = h2_conn.accept().await {
                let Ok((req, mut respond)) = req_result else { break };
                let mut body = req.into_body();
                let mut query_buf = Vec::new();
                while let Some(chunk) = body.data().await {
                    query_buf.extend_from_slice(&chunk.unwrap());
                }
                let query_msg = Message::from_vec(&query_buf).unwrap();
                let resp_payload = make_a_response(
                    query_msg.metadata.id,
                    "h2c.com.",
                    vec![Ipv4Addr::new(10, 1, 2, 3)],
                    60,
                );
                let resp = Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, "application/dns-message")
                    .body(())
                    .unwrap();
                let mut send = respond.send_response(resp, false).unwrap();
                send.send_data(Bytes::from(resp_payload), true).unwrap();
            }
        });

        let ns = NameServerConfig {
            address: Address::from(addr.ip()),
            port: addr.port(),
            timeout_ms: 3000,
            ..NameServerConfig::default()
        };
        let srv = DohNameServer::from_config_h2c(&ns).unwrap();
        // P1-11：查询前启动期注册（生产等价 = 实例 start）。
        srv.start_managed_tasks(&Arc::new(skeleton_infra::fx::FxScope::new()));
        let (ips, _) = srv
            .query_ip(
                "h2c.com.",
                IpOption { ipv4_enable: true, ipv6_enable: false, fake_enable: false },
            )
            .await
            .unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))]);
    }

    /// bd d881① 失败路径 e2e：上游不回 → h2c 错误原样返回（经 bd d881② 透传），
    /// 不再被吞成 record not found。
    #[tokio::test]
    async fn h2c_failure_error_is_observable() {
        // 监听但永不 accept：h2c 握手/响应超时。
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let ns = NameServerConfig {
            address: Address::from(addr.ip()),
            port: addr.port(),
            timeout_ms: 150,
            ..NameServerConfig::default()
        };
        let srv = DohNameServer::from_config_h2c(&ns).unwrap();
        // P1-11：查询前启动期注册（生产等价 = 实例 start）。
        srv.start_managed_tasks(&Arc::new(skeleton_infra::fx::FxScope::new()));
        let err = srv
            .query_ip(
                "dead.com.",
                IpOption { ipv4_enable: true, ipv6_enable: false, fake_enable: false },
            )
            .await
            .unwrap_err();
        assert!(
            !matches!(err, DnsError::RecordNotFound),
            "h2c 失败不得吞成 RecordNotFound, got: {err:?}"
        );
    }

    /// P1-11 验收①：scope 已关（停机中）DoH 查询快速失败——不发起新上游
    /// 连接、不裸 spawn、不 panic（入口先验于任何 IO）。
    #[tokio::test]
    async fn doh_query_after_scope_close_fails_fast() {
        let cache = Arc::new(CacheController::new("test", true, false, 0, 0));
        let fx = Arc::new(skeleton_infra::fx::FxScope::new());
        cache.attach_scope(&fx);
        fx.close();

        ensure_crypto_provider();
        let tls_config = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(tokio_rustls::rustls::RootCertStore::empty())
                .with_no_client_auth(),
        );
        let ns = DohNameServer::new(
            ip_dest(SocketAddr::from(([127, 0, 0, 1], 1))),
            "localhost".to_string(),
            tls_config,
            cache,
            Vec::new(),
            Duration::from_secs(1),
            true, // h2c：入口先验先于任何 IO，空根证书库不会被触达
        );
        let err = ns.query_once("closed.com.", RecordType::A).await.unwrap_err();
        assert!(err.to_string().contains("fx scope"), "got: {err}");
        assert_eq!(fx.in_flight(), 0, "closed scope must not gain new tasks");
    }

    #[tokio::test]
    async fn doh_query_once_returns_a_record() {
        let (addr, tls_config, _h) =
            spawn_mock_doh_server("example.com.", vec![Ipv4Addr::new(10, 0, 0, 1)], 120).await;

        let ns = DohNameServer::new(
            ip_dest(addr),
            "localhost".to_string(),
            tls_config,
            {
                // P1-11：查询前注单托管 scope（生产等价 = 实例 start）。
                let cache = Arc::new(CacheController::new("test", true, false, 0, 0));
                cache.attach_scope(&Arc::new(skeleton_infra::fx::FxScope::new()));
                cache
            },
            Vec::new(),
            Duration::from_secs(5),
            false,
        );
        let rec = ns.query_once("example.com.", RecordType::A).await.unwrap();
        assert_eq!(rec.ips.len(), 1);
        assert_eq!(rec.ips[0], IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(rec.ttl_seconds(Instant::now()) <= 120);
    }

    #[tokio::test]
    async fn doh_send_query_v4_only() {
        let (addr, tls_config, _h) =
            spawn_mock_doh_server("z.com.", vec![Ipv4Addr::new(8, 8, 8, 8)], 60).await;

        let ns = DohNameServer::new(
            ip_dest(addr),
            "localhost".to_string(),
            tls_config,
            {
                // P1-11：查询前注单托管 scope（生产等价 = 实例 start）。
                let cache = Arc::new(CacheController::new("test", true, false, 0, 0));
                cache.attach_scope(&Arc::new(skeleton_infra::fx::FxScope::new()));
                cache
            },
            Vec::new(),
            Duration::from_secs(5),
            false,
        );
        let outcome = ns
            .send_query(
                "z.com.",
                IpOption { ipv4_enable: true, ipv6_enable: false, fake_enable: false },
            )
            .await;
        assert!(outcome.rec_v4.is_some());
        assert!(outcome.rec_v6.is_none());
        assert!(outcome.errors.is_empty());
    }

    #[tokio::test]
    async fn doh_query_http_status_error() {
        ensure_crypto_provider();
        let cert_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = cert_params.self_signed(&key_pair).unwrap();
        let cert_der = cert.der().to_vec();
        let key_der = key_pair.serialize_der();

        let key = tokio_rustls::rustls::pki_types::PrivateKeyDer::try_from(key_der).unwrap();
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![tokio_rustls::rustls::pki_types::CertificateDer::from(cert_der.clone())],
                key,
            )
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        xray_common::testing::spawn("doh-query-http-status-error-accept", async move {
            let (sock, _) = listener.accept().await.unwrap();
            let tcp = TcpConnection::new(sock);
            let tls = acceptor.accept(tcp).await.unwrap();
            let mut h2_conn = server::handshake(tls).await.unwrap();
            while let Some(req_result) = h2_conn.accept().await {
                let (_req, mut respond) = match req_result {
                    Ok(r) => r,
                    Err(_) => break,
                };
                // 回 500 + empty body + end_of_stream。
                let resp =
                    Response::builder().status(StatusCode::INTERNAL_SERVER_ERROR).body(()).unwrap();
                let mut send = respond.send_response(resp, false).unwrap();
                send.send_data(Bytes::new(), true).unwrap();
            }
        });

        let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
        root_store.add(tokio_rustls::rustls::pki_types::CertificateDer::from(cert_der)).unwrap();
        let tls_config = Arc::new(
            ClientConfig::builder().with_root_certificates(root_store).with_no_client_auth(),
        );

        let ns = DohNameServer::new(
            ip_dest(addr),
            "localhost".to_string(),
            tls_config,
            {
                // P1-11：查询前注单托管 scope（生产等价 = 实例 start）。
                let cache = Arc::new(CacheController::new("test", true, false, 0, 0));
                cache.attach_scope(&Arc::new(skeleton_infra::fx::FxScope::new()));
                cache
            },
            Vec::new(),
            Duration::from_secs(5),
            false,
        );
        let result = ns.query_once("bad.com.", RecordType::A).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("http status"), "expected http status error, got: {err}");
    }

    /// 启动 accept + TLS + h2 握手后不回响应的 mock DoH server（测超时路径）。
    async fn spawn_hanging_doh_server() -> (SocketAddr, Arc<ClientConfig>) {
        spawn_hanging_doh_server_delayed(Duration::ZERO).await
    }

    /// 同上，但 accept 前先 mock 时钟 sleep `pre_accept_delay`——模拟慢握手
    /// （bd ezrg4：macOS CI 负载下握手链消耗 ~2.5s mock 时钟的场景）。
    async fn spawn_hanging_doh_server_delayed(
        pre_accept_delay: Duration,
    ) -> (SocketAddr, Arc<ClientConfig>) {
        ensure_crypto_provider();
        let cert_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = cert_params.self_signed(&key_pair).unwrap();
        let cert_der = cert.der().to_vec();
        let key_der = key_pair.serialize_der();

        let key = tokio_rustls::rustls::pki_types::PrivateKeyDer::try_from(key_der).unwrap();
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![tokio_rustls::rustls::pki_types::CertificateDer::from(cert_der.clone())],
                key,
            )
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        xray_common::testing::spawn("spawn-hanging-doh-server-accept", async move {
            if !pre_accept_delay.is_zero() {
                tokio::time::sleep(pre_accept_delay).await;
            }
            let Ok((sock, _)) = listener.accept().await else { return };
            let Ok(tls) = acceptor.accept(TcpConnection::new(sock)).await else { return };
            let Ok(mut h2_conn) = server::handshake(tls).await else { return };
            // drop Responder 会触发 h2 RST_STREAM（客户端立刻收 "stream no longer
            // needed" 而非挂到 query timeout）——持有不回，模拟慢上游。
            let mut hanging_responds = Vec::new();
            while let Some(req) = h2_conn.accept().await {
                let Ok((req, respond)) = req else { break };
                let mut body = req.into_body();
                while let Some(chunk) = body.data().await {
                    if chunk.is_err() {
                        break;
                    }
                }
                hanging_responds.push(respond);
            }
        });

        let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
        root_store.add(tokio_rustls::rustls::pki_types::CertificateDer::from(cert_der)).unwrap();
        let client_config = Arc::new(
            ClientConfig::builder().with_root_certificates(root_store).with_no_client_auth(),
        );
        (addr, client_config)
    }

    /// 在 tokio pause 时钟下跑 query_ip，按 100ms 步进推进并返回（累计推进量, 结果）。
    async fn run_paused_query(
        srv: Box<dyn Server>,
        fqdn: &'static str,
    ) -> (Duration, Result<(Vec<IpAddr>, u32), DnsError>) {
        tokio::time::pause();
        let handle = xray_common::testing::spawn("run-paused-query", async move {
            srv.query_ip(
                fqdn,
                IpOption { ipv4_enable: true, ipv6_enable: false, fake_enable: false },
            )
            .await
        });
        let mut advanced = Duration::ZERO;
        let result = loop {
            if handle.is_finished() {
                break handle.await.unwrap();
            }
            tokio::time::advance(Duration::from_millis(100)).await;
            advanced += Duration::from_millis(100);
            assert!(advanced <= Duration::from_secs(30), "no timeout fired within 30s mock time");
        };
        (advanced, result)
    }

    /// bd cjwc G13：`ns.timeout_ms == 0`（等价 Go 上层 ctx 无 deadline）时兜底
    /// 必须是 5s——Go `nameserver_doh.go:166-172` `else deadline = now.Add(5*time.Second)`。
    /// 此前 Rust 缺省 4s，慢上游早 1s 被掐。
    #[tokio::test]
    async fn doh_fallback_timeout_is_5s_without_explicit_deadline() {
        let (addr, tls_config) = spawn_hanging_doh_server().await;
        let ns = NameServerConfig {
            address: Address::from(addr.ip()),
            port: addr.port(),
            timeout_ms: 0,
            ..NameServerConfig::default()
        };
        let srv = DohNameServer::from_config(&ns, "localhost".to_string(), tls_config).unwrap();
        // P1-11：查询前启动期注册（生产等价 = 实例 start）。
        srv.start_managed_tasks(&Arc::new(skeleton_infra::fx::FxScope::new()));

        let (advanced, result) = run_paused_query(srv, "hang.com.").await;
        let err = result.unwrap_err();
        assert!(err.to_string().contains("timeout"), "expected timeout error, got: {err}");
        // 整查询 deadline 下失败点 = entry(~0.1s) + 预算 + 观测收敛(~0.2s)，
        // Windows/WSL 实测 5.3s 稳定。[4.8, 6.0] 双侧 ≥0.5s 余量：下界抓历史
        // 4s 回退（observed 4.3s 必红），上界防负载下观测周期数漂移（分段制
        // 泄漏的判别由下方 doh_total_deadline_covers_slow_handshake 承担）。
        assert!(
            advanced >= Duration::from_millis(4800) && advanced <= Duration::from_millis(6000),
            "fallback must be 5s, advanced={advanced:?}"
        );
    }

    /// bd ezrg4 回归钉：兜底 deadline 覆盖**整条查询**——即使握手链消耗 2s
    /// mock 时钟（模拟 macOS CI 负载下真实 IO 只随 advance 步进推进、实测
    /// advanced=7.5s 的场景），整条查询仍须自入口 5s 收场。分段独立预算制下
    /// 本场景停在 ~7.2s（response 段另起 5s），此测试即钉死 Go 语义。
    #[tokio::test]
    async fn doh_total_deadline_covers_slow_handshake() {
        let (addr, tls_config) = spawn_hanging_doh_server_delayed(Duration::from_secs(2)).await;
        let ns = NameServerConfig {
            address: Address::from(addr.ip()),
            port: addr.port(),
            timeout_ms: 0,
            ..NameServerConfig::default()
        };
        let srv = DohNameServer::from_config(&ns, "localhost".to_string(), tls_config).unwrap();
        // P1-11：查询前启动期注册（生产等价 = 实例 start）。
        srv.start_managed_tasks(&Arc::new(skeleton_infra::fx::FxScope::new()));

        let (advanced, result) = run_paused_query(srv, "hang.com.").await;
        let err = result.unwrap_err();
        assert!(err.to_string().contains("timeout"), "expected timeout error, got: {err}");
        // 整查询 deadline：握手 2s 不推出额外预算，observed 与无延迟同（5.3s）；
        // 分段制回退 = 2s 延迟 + response 段另起 5s ≈ 7.3s 必红（余量 1.3s）。
        assert!(
            advanced >= Duration::from_millis(4800) && advanced <= Duration::from_millis(6000),
            "total query deadline must be 5s even with slow handshake, advanced={advanced:?}"
        );
    }

    /// bd cjwc G13：显式配置优先于兜底（等价 Go `ctx.Deadline()` 存在时优先）。
    #[tokio::test]
    async fn doh_explicit_timeout_overrides_fallback() {
        let (addr, tls_config) = spawn_hanging_doh_server().await;
        let ns = NameServerConfig {
            address: Address::from(addr.ip()),
            port: addr.port(),
            timeout_ms: 2000,
            ..NameServerConfig::default()
        };
        let srv = DohNameServer::from_config(&ns, "localhost".to_string(), tls_config).unwrap();
        // P1-11：查询前启动期注册（生产等价 = 实例 start）。
        srv.start_managed_tasks(&Arc::new(skeleton_infra::fx::FxScope::new()));

        let (advanced, result) = run_paused_query(srv, "hang.com.").await;
        assert!(result.is_err());
        // 显式 2s 生效（若兜底 5s 泄漏会停在 ~5.x s）。上界给到兜底之下：
        // 负载 runner 上暂停时钟随真实时间爬行，实测可到 3.2s（CI run 39592783255）。
        assert!(
            advanced >= Duration::from_millis(1500) && advanced < Duration::from_secs(5),
            "explicit 2s must win over 5s fallback, advanced={advanced:?}"
        );
    }

    /// bd cjwc G13：数值契约——缺省 5s，显式值透传。
    #[test]
    fn effective_query_timeout_defaults_to_5s() {
        assert_eq!(effective_query_timeout(0), Duration::from_secs(5));
        assert_eq!(effective_query_timeout(4000), Duration::from_millis(4000));
        assert_eq!(effective_query_timeout(12345), Duration::from_millis(12345));
    }

    /// 构造带托管 scope 的 DoH nameserver（生产等价 = 实例 start）。
    fn counting_ns(addr: SocketAddr, tls_config: Arc<ClientConfig>) -> Arc<DohNameServer> {
        let cache = Arc::new(CacheController::new("test", true, false, 0, 0));
        Arc::new(DohNameServer::new(
            ip_dest(addr),
            "localhost".to_string(),
            tls_config,
            cache,
            Vec::new(),
            Duration::from_secs(5),
            false,
        ))
    }

    /// bd yzhb4：同一 NS 连续查询复用同一条 h2 连接（上游 accept 只发生一次）。
    #[tokio::test]
    async fn doh_reuses_h2_session_across_queries() {
        let (addr, tls_config, accepts) =
            spawn_counting_doh_server("reuse.com.", vec![Ipv4Addr::new(10, 9, 9, 9)], 60, false)
                .await;
        let ns = counting_ns(addr, tls_config);
        let fx = Arc::new(skeleton_infra::fx::FxScope::new());
        ns.cache.attach_scope(&fx);

        for i in 0..3 {
            let rec = ns
                .query_once(&format!("q{i}.reuse.com."), RecordType::A)
                .await
                .unwrap_or_else(|e| panic!("第 {i} 次查询失败: {e}"));
            assert_eq!(rec.ips, vec![IpAddr::V4(Ipv4Addr::new(10, 9, 9, 9))]);
        }
        assert_eq!(accepts.load(Ordering::SeqCst), 1, "3 次查询必须复用同一条连接");
        let _ = fx.shutdown().await;
    }

    /// bd yzhb4：热会话被对端关闭后，下一次查询自动重建（不把错误抛给调用方）。
    #[tokio::test]
    async fn doh_rebuilds_session_after_peer_close() {
        let (addr, tls_config, accepts) =
            spawn_counting_doh_server("rebuild.com.", vec![Ipv4Addr::new(10, 8, 8, 8)], 60, true)
                .await;
        let ns = counting_ns(addr, tls_config);
        let fx = Arc::new(skeleton_infra::fx::FxScope::new());
        ns.cache.attach_scope(&fx);

        for i in 0..2 {
            let rec = ns
                .query_once(&format!("q{i}.rebuild.com."), RecordType::A)
                .await
                .unwrap_or_else(|e| panic!("第 {i} 次查询失败（会话销毁后必须重建）: {e}"));
            assert_eq!(rec.ips, vec![IpAddr::V4(Ipv4Addr::new(10, 8, 8, 8))]);
        }
        assert_eq!(accepts.load(Ordering::SeqCst), 2, "对端关连接后必须重建一条新连接");
        let _ = fx.shutdown().await;
    }

    /// bd yzhb4：空闲 `DOH_IDLE_TIMEOUT` 后看门狗关闭热会话（不常驻）。
    #[tokio::test]
    async fn doh_idle_session_is_closed_by_watchdog() {
        let (addr, tls_config, _accepts) =
            spawn_counting_doh_server("idle.com.", vec![Ipv4Addr::new(10, 7, 7, 7)], 60, false)
                .await;
        let ns = counting_ns(addr, tls_config);
        let fx = Arc::new(skeleton_infra::fx::FxScope::new());
        ns.cache.attach_scope(&fx);
        ns.start_managed_tasks(&fx); // 生产等价：DNS 实例 start（看门狗由此启动）

        ns.query_once("idle.com.", RecordType::A).await.unwrap();
        assert!(ns.session.current.lock().is_some(), "查询后应留下一条热会话");

        tokio::time::pause();
        tokio::time::advance(DOH_IDLE_TIMEOUT * 2).await;
        for _ in 0..50 {
            if ns.session.current.lock().is_none() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(ns.session.current.lock().is_none(), "空闲到期后热会话必须关闭");
        let _ = fx.shutdown().await;
    }
}
