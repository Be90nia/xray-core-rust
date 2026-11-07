//! # xdns DoH-over-QUIC（RFC 8484 over HTTP/3，对应 Go `resolver_doh.go:52-104`）
//!
//! 仅当 `tlsConfig.alpn == ["h3"]`（Go `len(NextProtocol) == 1 && NextProtocol[0] ==
//! "h3"`）时启用：quinn `Endpoint` + `h3::client`，POST `application/dns-message`
//! 与 h2 路径逐项同形（body = 裸 DNS wire，无 2B 长度前缀）。
//!
//! ## quicConfig 映射（Go `internet.QuicParams` → quinn `TransportConfig`）
//!
//! | Go | 本栈 |
//! |---|---|
//! | `initStreamReceiveWindow` / `maxStreamReceiveWindow` | `stream_receive_window`（取二者较大；都 0 = quinn 缺省） |
//! | `initConnectionReceiveWindow` / `maxConnectionReceiveWindow` | `receive_window`（同上） |
//! | `maxIdleTimeout`（秒） | `max_idle_timeout`（0 = quinn 缺省 30s，与 quic-go 缺省同值） |
//! | `keepAlivePeriod`（秒） | `keep_alive_interval`（0 = 不发 PING，同 quic-go） |
//! | `disablePathMTUDiscovery` | `mtu_discovery_config(None)`（quinn 缺省开） |
//! | `maxIncomingStreams` | `max_concurrent_bidi_streams` |
//! | `congestion` "" / `reno` | 不动，就地用 quinn 缺省 CUBIC（Go 同样不改 quic-go 缺省） |
//! | `congestion` `bbr` | quinn 内建 BBR（`quinn::congestion::BbrConfig`） |
//! | `disableChromeParrot` | false（Go 缺省）= 零长 CID（Go `ZeroLengthConnectionIDGenerator`） |
//!
//! ## 与 Go 的差异（bd lf69h）
//!
//! 1. **拨号面**：Go 经 finalmask `dialer.DialUDP`（可挂代理链/屏蔽）；本栈直连 （同 `doh`
//!    模块头差异 1，本票非目标）。
//! 2. **拥塞控制**：Go 的 `bbr` / `force-brutal` 走 hysteria 控制器（`congestion.UseBBR` /
//!    `UseBrutal`）。本栈 `bbr` = quinn 内建 BBR 近似（无 `bbrProfile` 三档差异， 统一 standard
//!    语义）；`brutal` / `force-brutal` 无等价控制器 ⇒ **配置期硬错** （Go 对 `brutal` 是
//!    `panic`、对 `force-brutal` 用 Brutal——两者都不静默）。
//! 3. **ChromeParrot**：只落零长 CID 半面；Go 还清 `tlsCfg.GetCertificate`（服务端回调， rustls
//!    客户端本就不设置）。
//! 4. **连接复用**：复用同一条 QUIC/h3 会话（Go `http3.Transport` 连接池对位；bd 5lpw3）。
//!    会话离场（超时/传输错误/被新会话顶替/resolver 关闭）一律 RAII 显式 CONNECTION_CLOSE（bd
//!    0x4tl：Go `context.AfterFunc(qc.Context(), tr.Close)` 对位—— 禁把连接留给服务端干等 idle
//!    timeout）。
//! 5. **`disableGSO` / `disableStatelessReset` / `debug`**：quinn 无对应旋钮（GSO 自动、 无
//!    stateless-reset key、`debug` 只影响 hysteria 控制器日志环境变量）⇒ 键接受、无效果。

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use bytes::{Buf, Bytes};
use http::{
    Method, StatusCode, Uri,
    header::{ACCEPT, CONTENT_TYPE, RETRY_AFTER, USER_AGENT},
};
use parking_lot::Mutex;
use quinn::VarInt;
use serde_json::Value;
use xray_proto::xray::transport::internet::QuicParams as QuicParamsProto;

use super::doh::{
    Cooldown, DNS_MEDIA_TYPE, DOH_RECV_MAX, REQUEST_TIMEOUT, extend_cooldown, retry_after_until,
};
use crate::{
    finalmask::mask_err,
    memory_settings::{QuicParamsConfig, parse_quic_params_config},
    sockopt::{SocketOptions, bind_udp_endpoint},
};

/// 本地 UDP socket 的 bind 地址（跟随目标 IP 族，与 `Endpoint::client` 同款）。
const BIND_V4: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);
/// 见 [`BIND_V4`]。
const BIND_V6: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0);

/// `h3::client::new` 返回的 request sender 类型（同 splithttp `H3SendRequest`）。
type H3SendRequest = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

/// `quicConfig` 在本栈生效的字段；`Default` = Go 零值 `&internet.QuicParams{}`
/// （`DisableChromeParrot == false` ⇒ ChromeParrot 开）。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct QuicOptions {
    /// `congestion == "bbr"`（其余可选值都落 quinn 缺省 CUBIC）。
    bbr: bool,
    /// 流接收窗口（0 = quinn 缺省）。
    stream_receive_window: u64,
    /// 连接接收窗口（0 = quinn 缺省）。
    conn_receive_window: u64,
    /// `maxIdleTimeout`（0 = quinn 缺省 30s）。
    max_idle_timeout: Option<Duration>,
    /// `keepAlivePeriod`（0 = 不发 PING）。
    keep_alive_period: Option<Duration>,
    /// `disablePathMTUDiscovery`。
    disable_path_mtu_discovery: bool,
    /// `maxIncomingStreams`（0 = quinn 缺省）。
    max_incoming_streams: u64,
    /// `disableChromeParrot`（false = 零长 CID）。
    disable_chrome_parrot: bool,
}

impl QuicOptions {
    /// JSON `quicConfig`：JSON 解析走 [`parse_quic_params_config`]（复用既有宽容解析），
    /// 校验按 Go `QuicParamsConfig.Build()`（`transport_finalmask.go:1197-1280`）。
    pub(super) fn from_json(v: Option<&Value>) -> io::Result<Self> {
        let Some(v) = v.filter(|v| !v.is_null()) else { return Ok(Self::default()) };
        let qp = parse_quic_params_config(Some(v))?.unwrap_or_default();
        let disable_chrome_parrot =
            v.get("disableChromeParrot").and_then(Value::as_bool).unwrap_or(false);
        Self::build(&qp, disable_chrome_parrot)
    }

    /// proto `quicConfig`（`ResolverConfig::from_proto` 的 wire 形态）。
    pub(super) fn from_proto(p: Option<&QuicParamsProto>) -> io::Result<Self> {
        let Some(p) = p else { return Ok(Self::default()) };
        let qp = QuicParamsConfig {
            congestion: p.congestion.clone(),
            bbr_profile: p.bbr_profile.clone(),
            // brutal* 无消费方（本栈不支持 Brutal，见模块头差异 2）；带宽在 proto 里
            // 已是 bps，`QuicParamsConfig.brutal_up` 是 JSON 带宽串口径，此处不参与判定。
            brutal_up: String::new(),
            brutal_down: String::new(),
            brutal_disable_loss_compensation: p.brutal_disable_loss_compensation,
            init_stream_receive_window: p.init_stream_receive_window,
            max_stream_receive_window: p.max_stream_receive_window,
            init_connection_receive_window: p.init_conn_receive_window,
            max_connection_receive_window: p.max_conn_receive_window,
            max_idle_timeout: p.max_idle_timeout,
            keep_alive_period: p.keep_alive_period,
            disable_path_mtu_discovery: p.disable_path_mtu_discovery,
            max_incoming_streams: p.max_incoming_streams,
            debug: false,
        };
        Self::build(&qp, p.disable_chrome_parrot)
    }

    /// Go conf 层校验 + 本栈能力闸（不支持的值一律配置期硬错，禁静默忽略）。
    fn build(qp: &QuicParamsConfig, disable_chrome_parrot: bool) -> io::Result<Self> {
        for (name, v) in [
            ("InitStreamReceiveWindow", qp.init_stream_receive_window),
            ("MaxStreamReceiveWindow", qp.max_stream_receive_window),
            ("InitConnectionReceiveWindow", qp.init_connection_receive_window),
            ("MaxConnectionReceiveWindow", qp.max_connection_receive_window),
        ] {
            if v > 0 && v < 16384 {
                return Err(mask_err(format!("xdns: quicConfig {name} must be at least 16384")));
            }
        }
        if qp.max_idle_timeout != 0 && !(4..=120).contains(&qp.max_idle_timeout) {
            return Err(mask_err("xdns: quicConfig MaxIdleTimeout must be between 4 and 120"));
        }
        if qp.keep_alive_period != 0 && !(2..=60).contains(&qp.keep_alive_period) {
            return Err(mask_err("xdns: quicConfig KeepAlivePeriod must be between 2 and 60"));
        }
        if qp.max_incoming_streams != 0 && qp.max_incoming_streams < 8 {
            return Err(mask_err("xdns: quicConfig MaxIncomingStreams must be at least 8"));
        }
        match qp.bbr_profile.to_ascii_lowercase().as_str() {
            "" | "conservative" | "standard" | "aggressive" => {},
            other => {
                return Err(mask_err(format!("xdns: quicConfig unknown bbr profile {other:?}")));
            },
        }
        let bbr = match qp.congestion.to_ascii_lowercase().as_str() {
            "" | "reno" => false,
            "bbr" => true,
            other => {
                return Err(mask_err(format!(
                    "xdns: quicConfig congestion {other:?} is not implemented by this stack \
                     (DoH-over-QUIC supports \"\", \"reno\", \"bbr\")"
                )));
            },
        };
        Ok(Self {
            bbr,
            // quinn 只有固定窗口（无 quic-go 的 initial→max 自动调谐）⇒ 取上限。
            stream_receive_window: qp.max_stream_receive_window.max(qp.init_stream_receive_window),
            conn_receive_window: qp
                .max_connection_receive_window
                .max(qp.init_connection_receive_window),
            max_idle_timeout: seconds(qp.max_idle_timeout),
            keep_alive_period: seconds(qp.keep_alive_period),
            disable_path_mtu_discovery: qp.disable_path_mtu_discovery,
            max_incoming_streams: u64::try_from(qp.max_incoming_streams).unwrap_or(0),
            disable_chrome_parrot,
        })
    }

    /// 映射到 quinn `TransportConfig`（模块头映射表；0 值一律不覆盖 quinn 缺省）。
    fn transport_config(&self) -> io::Result<quinn::TransportConfig> {
        let mut transport = quinn::TransportConfig::default();
        if self.bbr {
            transport
                .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
        }
        let varint = |v: u64, key: &str| {
            VarInt::from_u64(v).map_err(|e| mask_err(format!("xdns: quicConfig {key}={v}: {e}")))
        };
        if self.stream_receive_window > 0 {
            transport
                .stream_receive_window(varint(self.stream_receive_window, "streamReceiveWindow")?);
        }
        if self.conn_receive_window > 0 {
            transport.receive_window(varint(self.conn_receive_window, "connReceiveWindow")?);
        }
        if self.max_incoming_streams > 0 {
            transport.max_concurrent_bidi_streams(varint(
                self.max_incoming_streams,
                "maxIncomingStreams",
            )?);
        }
        if let Some(d) = self.max_idle_timeout {
            transport
                .max_idle_timeout(Some(quinn::IdleTimeout::try_from(d).map_err(|e| {
                    mask_err(format!("xdns: quicConfig MaxIdleTimeout={d:?}: {e}"))
                })?));
        }
        transport.keep_alive_interval(self.keep_alive_period);
        if self.disable_path_mtu_discovery {
            transport.mtu_discovery_config(None);
        }
        Ok(transport)
    }
}

/// 秒数 → Duration；0（Go「未设置」）= `None`（不覆盖 quinn 缺省）。
fn seconds(secs: i64) -> Option<Duration> {
    (secs > 0).then(|| Duration::from_secs(secs.unsigned_abs()))
}

/// Go `ZeroLengthConnectionIDGenerator` 对位（quinn 内建只有 `RandomConnectionIdGenerator`）。
#[derive(Debug)]
struct ZeroLenCid;

impl quinn::ConnectionIdGenerator for ZeroLenCid {
    fn generate_cid(&mut self) -> quinn::ConnectionId {
        quinn::ConnectionId::new(&[])
    }

    fn cid_len(&self) -> usize {
        0
    }

    fn cid_lifetime(&self) -> Option<Duration> {
        None
    }
}

/// h3 DoH 端点（复用一条 QUIC/h3 会话，见模块头差异 4）。
pub(super) struct Doh3Endpoint {
    uri: Uri,
    host: String,
    port: u16,
    tls: Arc<tokio_rustls::rustls::ClientConfig>,
    /// SNI / 证书校验名（Go `serverName`，缺省 URL host）。
    server_name: String,
    quic: QuicOptions,
    /// 复用会话槽（Go `http3.Transport` 连接池对位，bd 5lpw3）：worker 完成一次交换后
    /// 放回，下一个 worker 直接复用；`None` = 下次拨新。锁内只取/放（不跨 await）。
    /// rjaxs-①（单槽非池，评估不改）：Go 对并发请求复用**同一条** origin 连接
    /// （h3 流多路复用）；本槽 worker 独占会话整个交换期 ⇒ 并发 post 各自拨新
    /// 连接，`put_session` 后写覆盖先写（旧会话 RAII CONNECTION_CLOSE）
    /// ——突发 N 并发最坏 N 次握手、复用退化到零，churn 有界（≤ worker 数，
    /// Go 缺省 32；`QUEUE_CAP=1` 只界排队**不界在飞**）。不改依据：h3 仅
    /// ALPN==["h3"] 的 opt-in 形态、生产无用量数据；顶替频率不可观测（无计数
    /// 器，单独加表无消费方）；若重访，正解是 Arc 共享会话（对位 Go 单连接
    /// 多路复用；代价 = 一处失败殃及在飞全体）而非 N 槽小池（悬崖只挪到 N+1
    /// 并发）。触发条件：生产启用 h3 且实测突发 DNS 尾延迟劣化。
    session: Mutex<Option<Doh3Session>>,
    /// 单请求超时（生产 = [`REQUEST_TIMEOUT`]；测试注入短超时验证 0x4tl 关闭语义）。
    timeout: Duration,
}

/// 一条可复用的 h3 会话：endpoint（socket + 连接驱动存活）+ QUIC 连接 + h3 请求句柄。
struct Doh3Session {
    endpoint: quinn::Endpoint,
    conn: quinn::Connection,
    send_request: H3SendRequest,
}

impl Drop for Doh3Session {
    fn drop(&mut self) {
        // bd 0x4tl：会话离场必须显式 CONNECTION_CLOSE（Go `context.AfterFunc(qc.Context(),
        // tr.Close)` 对位）。否则 future 被 drop（超时）时连接留在服务端，要干等
        // idle timeout（实测残留 30s）。`close` 同步置关闭态，重复调用无害。
        // 判别签名：error_code=0 + b"xdns: DoH session closed"（h3 last-SendRequest
        // 兜底是 H3_NO_ERROR=0x100 + "Connection closed by client"，见超时测试）。
        self.conn.close(VarInt::from_u32(0), b"xdns: DoH session closed");
    }
}

impl Doh3Endpoint {
    pub(super) fn new(
        uri: Uri,
        host: String,
        port: u16,
        tls: Arc<tokio_rustls::rustls::ClientConfig>,
        server_name: String,
        quic: QuicOptions,
    ) -> Self {
        Self {
            uri,
            host,
            port,
            tls,
            server_name,
            quic,
            session: Mutex::new(None),
            timeout: REQUEST_TIMEOUT,
        }
    }

    /// POST 一条 DNS 查询，返回响应体（≤ [`DOH_RECV_MAX`] 字节）。
    ///
    /// bd 0x4tl：超时把内层 future（连同其持有的会话）一起 drop——[`Doh3Session::drop`]
    /// 同步发 CONNECTION_CLOSE，超时分支无需（也无法）补 close；槽里的**空闲**会话
    /// 状态健康、不属于本次请求，不清场。
    pub(super) async fn post(
        &self,
        body: &[u8],
        remote: &Mutex<SocketAddr>,
        cooldown: &Cooldown,
    ) -> io::Result<Vec<u8>> {
        tokio::time::timeout(self.timeout, self.post_any(body, remote, cooldown))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "xdns: DoH request timed out"))?
    }

    /// 目标解析出多个地址时逐个尝试（QUIC 无 happy-eyeballs，顺序即优先级）。
    async fn post_any(
        &self,
        body: &[u8],
        remote: &Mutex<SocketAddr>,
        cooldown: &Cooldown,
    ) -> io::Result<Vec<u8>> {
        let addrs =
            tokio::net::lookup_host((self.host.as_str(), self.port)).await.map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("xdns: DoH resolve {}:{}: {e}", self.host, self.port),
                )
            })?;
        let mut last: Option<io::Error> = None;
        for addr in addrs {
            match self.post_to(addr, body, remote, cooldown).await {
                Ok(out) => return Ok(out),
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap_or_else(|| {
            io::Error::other(format!(
                "xdns: DoH resolve {}:{} yielded no address",
                self.host, self.port
            ))
        }))
    }

    async fn post_to(
        &self,
        addr: SocketAddr,
        body: &[u8],
        remote: &Mutex<SocketAddr>,
        cooldown: &Cooldown,
    ) -> io::Result<Vec<u8>> {
        // bd 5lpw3：先取复用会话（健康 + 同地址族），取不到再拨新。
        let session = match self.take_session(addr) {
            Some(s) => s,
            None => self.dial(addr, remote).await?,
        };
        // 克隆请求句柄（mpsc sender 克隆，便宜）避免借用冲突；连接本体仍在 session 里。
        let mut send_request = session.send_request.clone();
        match self.exchange(&mut send_request, body, cooldown).await {
            // 200：会话回槽（bd 5lpw3）。
            Ok(H3Exchange::Body(out)) => {
                self.put_session(session);
                Ok(out)
            },
            // 服务端应答了但状态非 200（含 429，冷却窗已在 exchange 内落地）：连接健康，
            // 会话照常回槽（Go http.Transport 同款——应用层错误不毁连接）。
            Ok(H3Exchange::Rejected(e)) => {
                self.put_session(session);
                Err(e)
            },
            // 传输层坏了：弃用会话（Drop ⇒ CONNECTION_CLOSE，0x4tl），下次拨新。
            Err(e) => {
                drop(session);
                Err(e)
            },
        }
    }

    /// 取复用会话：已断（idle timeout / 对端关闭）或地址族不匹配（本地 bind socket
    /// 单栈）⇒ 弃用（Drop 发 CONNECTION_CLOSE）返回 `None`。
    fn take_session(&self, addr: SocketAddr) -> Option<Doh3Session> {
        let s = self.session.lock().take()?;
        // 本地 bind socket 是单栈的：地址族不匹配 ⇒ 复用必死，重拨；socket 已失效
        // （local_addr 失败）⇒ 会话同样报废。
        match s.endpoint.local_addr() {
            Ok(local) if local.is_ipv4() == addr.is_ipv4() => {},
            _ => return None,
        }
        if s.conn.close_reason().is_some() {
            return None;
        }
        Some(s)
    }

    /// 会话回槽；槽已被并发 worker 占用 ⇒ 旧会话 drop（RAII CONNECTION_CLOSE），新会话顶替。
    fn put_session(&self, s: Doh3Session) {
        *self.session.lock() = Some(s);
    }

    /// 拨一条全新 QUIC/h3 会话（socket 缓冲仍走 [`bind_udp_endpoint`] 的 Go
    /// `wrapConn` 8 MiB 下限——复用后每 resolver 只 bind 一次，无每查询 churn）。
    async fn dial(&self, addr: SocketAddr, remote: &Mutex<SocketAddr>) -> io::Result<Doh3Session> {
        let bind = if addr.is_ipv4() { BIND_V4 } else { BIND_V6 };
        let sock = bind_udp_endpoint(bind, &SocketOptions::default())
            .map_err(|e| io::Error::other(format!("xdns: DoH QUIC bind {bind}: {e}")))?;
        // ChromeParrot（Go 缺省开）：零长 CID。
        let mut endpoint_config = quinn::EndpointConfig::default();
        if !self.quic.disable_chrome_parrot {
            endpoint_config.cid_generator(|| Box::new(ZeroLenCid));
        }
        let endpoint =
            quinn::Endpoint::new(endpoint_config, None, sock, Arc::new(quinn::TokioRuntime))
                .map_err(|e| io::Error::other(format!("xdns: DoH QUIC endpoint: {e}")))?;
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(self.tls.clone())
            .map_err(|e| io::Error::other(format!("xdns: DoH QUIC tls config: {e}")))?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(crypto));
        client_config.transport_config(Arc::new(self.quic.transport_config()?));
        let conn = endpoint
            .connect_with(client_config, addr, self.server_name.as_str())
            .map_err(|e| io::Error::other(format!("xdns: DoH QUIC connect {addr}: {e}")))?
            .await
            .map_err(|e| io::Error::other(format!("xdns: DoH QUIC handshake {addr}: {e}")))?;
        // Go `setaddr`：记录拨号对端，供响应包 addr 标签。
        *remote.lock() = conn.remote_address();

        let (mut driver, send_request) = h3::client::new(h3_quinn::Connection::new(conn.clone()))
            .await
            .map_err(|e| io::Error::other(format!("xdns: DoH h3 handshake: {e}")))?;
        #[allow(
            clippy::disallowed_methods,
            reason = "①类·脱管债（bd kwevg · §3.5.6）：DoH h3 连接 driver（数据面）；寿命绑定复用会话，无托管收益（同 doh.rs h2 driver 与 splithttp h3 driver，bd hj3jf）；寿命随所属连接或会话 ⇒ 本应随组件停机取消，因本层无 PluginContext/ctx 可穿而临时脱管；接线 = xray_frame::compat::ManagedScope（P1 插件装配）"
        )]
        tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        Ok(Doh3Session { endpoint, conn, send_request })
    }

    /// 一轮 POST/响应交换（RFC 8484 §4：请求体 = 裸 DNS message）。
    ///
    /// 返回 [`H3Exchange`]：传输层错误（连接报废）与非 200 应用层应答（连接健康）
    /// 分开报告，由调用方决定会话去留。
    async fn exchange(
        &self,
        send_request: &mut H3SendRequest,
        body: &[u8],
        cooldown: &Cooldown,
    ) -> Result<H3Exchange, io::Error> {
        let req = http::Request::builder()
            .method(Method::POST)
            .uri(self.uri.clone())
            .header(CONTENT_TYPE, DNS_MEDIA_TYPE)
            .header(ACCEPT, DNS_MEDIA_TYPE)
            .header(USER_AGENT, "") // Go：req.Header.Set("User-Agent", "")
            .body(())
            .map_err(|e| io::Error::other(format!("xdns: DoH build request: {e}")))?;
        let mut stream = send_request
            .send_request(req)
            .await
            .map_err(|e| io::Error::other(format!("xdns: DoH h3 request: {e}")))?;
        stream
            .send_data(Bytes::copy_from_slice(body))
            .await
            .map_err(|e| io::Error::other(format!("xdns: DoH h3 send body: {e}")))?;
        stream.finish().await.map_err(|e| io::Error::other(format!("xdns: DoH h3 finish: {e}")))?;
        let response = stream
            .recv_response()
            .await
            .map_err(|e| io::Error::other(format!("xdns: DoH h3 response: {e}")))?;
        let status = response.status();
        if status != StatusCode::OK {
            // bd 6eqgp：与 h2 路（Go `resolver_doh.go:224-233`）同款——429 只读
            // `Retry-After`，delta-seconds 形式落共享冷却窗；解析不出 ⇒ 不设冷却。
            // h3 的响应头经 `recv_response` 直接拿到完整 `http::Response`，非 h2 流式形态。
            if status == StatusCode::TOO_MANY_REQUESTS {
                if let Some(until) = response
                    .headers()
                    .get(RETRY_AFTER)
                    .and_then(|v| v.to_str().ok())
                    .and_then(retry_after_until)
                {
                    extend_cooldown(cooldown, until);
                }
            }
            return Ok(H3Exchange::Rejected(io::Error::other(format!(
                "xdns: DoH status {status}"
            ))));
        }
        let mut out = Vec::with_capacity(DOH_RECV_MAX);
        while let Some(chunk) = stream
            .recv_data()
            .await
            .map_err(|e| io::Error::other(format!("xdns: DoH h3 read body: {e}")))?
        {
            let take = chunk.remaining().min(DOH_RECV_MAX.saturating_sub(out.len()));
            out.extend_from_slice(&chunk.chunk()[..take]);
            if out.len() >= DOH_RECV_MAX {
                break;
            }
        }
        Ok(H3Exchange::Body(out))
    }
}

/// 一轮 h3 交换的结果（连接健康性判别，供会话去留）。
enum H3Exchange {
    /// 200 + 响应体。
    Body(Vec<u8>),
    /// 服务端应答但状态非 200（429 已落冷却窗）；连接健康，会话可复用。
    Rejected(io::Error),
}

#[cfg(test)]
mod tests {
    use http::Response;

    use super::*;
    use crate::finalmask::xdns::doh::{DohParams, DohResolver};

    /// 我方 RAII 关连接发送的专属 reason 字节（与 `Doh3Session::drop` 里
    /// `conn.close` 的 reason 字面量一致；改任一侧必须同步另一侧——0x4tl
    /// 超时测试用它与 h3 兜底的 "Connection closed by client" 区分「谁关的」）。
    const RAII_CLOSE_REASON: &[u8] = b"xdns: DoH session closed";

    /// Go 缺省（无 quicConfig）= 全零值 + ChromeParrot 开。
    #[test]
    fn quic_options_default() {
        let q = QuicOptions::from_json(None).unwrap();
        assert_eq!(q, QuicOptions::default());
        assert!(!q.disable_chrome_parrot, "Go 缺省 ChromeParrot 开");
        assert!(!q.bbr);
    }

    /// 全字段映射：窗口取上限、idle/keepalive 转 Duration、MTU 发现可关。
    #[test]
    fn quic_options_map_all_fields() {
        let q = QuicOptions::from_json(Some(&serde_json::json!({
            "congestion": "BBR",
            "bbrProfile": "Aggressive",
            "initStreamReceiveWindow": 16384,
            "maxStreamReceiveWindow": 65536,
            "initConnectionReceiveWindow": 32768,
            "maxConnectionReceiveWindow": 131072,
            "maxIdleTimeout": 30,
            "keepAlivePeriod": 10,
            "disablePathMTUDiscovery": true,
            "disableChromeParrot": true,
            "maxIncomingStreams": 8
        })))
        .unwrap();
        assert!(q.bbr);
        assert_eq!(q.stream_receive_window, 65536);
        assert_eq!(q.conn_receive_window, 131072);
        assert_eq!(q.max_idle_timeout, Some(Duration::from_secs(30)));
        assert_eq!(q.keep_alive_period, Some(Duration::from_secs(10)));
        assert!(q.disable_path_mtu_discovery);
        assert!(q.disable_chrome_parrot);
        assert_eq!(q.max_incoming_streams, 8);
        // 映射后的 TransportConfig 构造不失败（0 值不覆盖 quinn 缺省）
        q.transport_config().unwrap();
        QuicOptions::default().transport_config().unwrap();
    }

    /// Go conf 校验面 + 本栈能力闸：非法值/未实现控制器一律配置期硬错。
    #[test]
    fn quic_options_reject_unsupported() {
        let bad = |v: serde_json::Value| {
            QuicOptions::from_json(Some(&v)).expect_err(&format!("必须硬错: {v}"))
        };
        // 本栈无 Brutal 控制器（Go 侧 brutal = panic、force-brutal = Brutal）
        assert!(bad(serde_json::json!({"congestion": "brutal"})).to_string().contains("brutal"));
        assert!(
            bad(serde_json::json!({"congestion": "force-brutal"})).to_string().contains("brutal")
        );
        assert!(bad(serde_json::json!({"congestion": "vegas"})).to_string().contains("vegas"));
        assert!(
            bad(serde_json::json!({"bbrProfile": "turbo"})).to_string().contains("bbr profile")
        );
        assert!(
            bad(serde_json::json!({"initStreamReceiveWindow": 1024})).to_string().contains("16384")
        );
        assert!(
            bad(serde_json::json!({"maxIdleTimeout": 3})).to_string().contains("between 4 and 120")
        );
        assert!(
            bad(serde_json::json!({"keepAlivePeriod": 61}))
                .to_string()
                .contains("between 2 and 60")
        );
        assert!(
            bad(serde_json::json!({"maxIncomingStreams": 4})).to_string().contains("at least 8")
        );
    }

    /// 固定的 DNS 应答报文（wire 形态，`x.example. IN A 1.2.3.4`，TTL 60）。
    ///
    /// bd x677s 修正：旧 fixture 声明 an=1 但 answer 段只剩 2B 截断 NAME——任何真解析器
    /// 读它都失败，而 h3 e2e 只验「字节原样往返」，从未过解析器。现为合法报文：answer
    /// 含完整 RR（压缩指针名 + type/class/TTL/rdlength/rdata），并被生产解析器断言消费
    /// （[`self::dns_reply_is_valid_for_production_parser`]）。
    const DNS_REPLY: [u8; 43] = [
        // header：ID=0，QR|RD|RA，QDCOUNT=1，ANCOUNT=1，NSCOUNT=0，ARCOUNT=0
        0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        // question：x.example. IN A
        0x01, b'x', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x00, 0x00, 0x01, 0x00, 0x01,
        // answer：压缩指针 → 偏移 12（question name），IN A TTL 60 rdlen 4 rdata 1.2.3.4
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 0x01, 0x02, 0x03,
        0x04,
    ];

    /// 测试时钟（生产面禁裸 `Instant::now`，同 doh.rs `now`）。
    fn now() -> std::time::Instant {
        xray_frame::compat::clock().now_instant()
    }

    /// bd x677s ②：fixture 必须能被**生产解析器**（`dns::message_from_wire_format`，
    /// Go `MessageFromWireFormat` 对位）解析并取出预期记录——不许只断言字节相等。
    #[test]
    fn dns_reply_is_valid_for_production_parser() {
        let msg = crate::finalmask::xdns::dns::message_from_wire_format(&DNS_REPLY)
            .expect("fixture 必须是合法 DNS 报文（an 数与 answer 段一致）");
        assert_eq!(msg.question.len(), 1);
        assert_eq!(msg.question[0].name.flat(), b"\x01x\x07example", "question name = x.example.");
        assert_eq!(msg.question[0].qtype, 1); // A
        assert_eq!(msg.question[0].qclass, 1); // IN
        assert_eq!(msg.answer.len(), 1, "ANCOUNT=1 ⇒ answer 段必须有完整 RR");
        let rr = &msg.answer[0];
        assert_eq!(rr.name.flat(), b"\x01x\x07example");
        assert_eq!(rr.rtype, 1); // A
        assert_eq!(rr.rclass, 1); // IN
        assert_eq!(rr.ttl, 60);
        assert_eq!(rr.data, vec![1, 2, 3, 4], "rdata = 1.2.3.4");
    }

    /// h3 假 DoH 服务器通用构造：ALPN `h3` + 自签证书（SAN localhost）。第 n 个请求回
    /// `script[min(n, len-1)]`（状态 + `Retry-After`），200 时附 `body`；请求体经
    /// `query_tx` 送回测试体。返回 (地址, CA PEM, **连接计数**——会话复用断言用)。
    async fn spawn_h3_doh_server(
        query_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
        script: Vec<(StatusCode, Option<&'static str>)>,
        body: Vec<u8>,
    ) -> (SocketAddr, String, Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let cert_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = cert_params.self_signed(&key_pair).unwrap();
        let cert_pem = cert.pem();
        let cert_der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
        let key_der = rustls::pki_types::PrivateKeyDer::try_from(key_pair.serialize_der()).unwrap();
        let mut server_tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();
        server_tls.alpn_protocols = vec![b"h3".to_vec()];
        let crypto =
            quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(server_tls)).unwrap();
        let endpoint = quinn::Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(crypto)),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let addr = endpoint.local_addr().unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        let accepts_srv = accepts.clone();
        let requests = Arc::new(AtomicUsize::new(0));
        #[allow(clippy::disallowed_methods, reason = "测试：H3 DoH 假服务器 accept 环")]
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                // 一条 QUIC 连接 = 一次 accept（bd 5lpw3 会话复用断言：多次查询 ⇒ 计数不涨）。
                accepts_srv.fetch_add(1, Ordering::SeqCst);
                let query_tx = query_tx.clone();
                let script = script.clone();
                let body = body.clone();
                let requests = requests.clone();
                #[allow(clippy::disallowed_methods, reason = "测试：H3 DoH 假服务器每连接一任务")]
                tokio::spawn(async move {
                    let Ok(conn) = incoming.await else { return };
                    let Ok(mut h3_conn) =
                        h3::server::Connection::new(h3_quinn::Connection::new(conn)).await
                    else {
                        return;
                    };
                    while let Ok(Some(resolver)) = h3_conn.accept().await {
                        let query_tx = query_tx.clone();
                        let script = script.clone();
                        let body = body.clone();
                        let requests = requests.clone();
                        #[allow(clippy::disallowed_methods, reason = "测试：H3 DoH 每请求一任务")]
                        tokio::spawn(async move {
                            let Ok((req, mut stream)) = resolver.resolve_request().await else {
                                return;
                            };
                            // RFC 8484 形态断言（与 h2 路径逐项同形）
                            assert_eq!(req.method(), Method::POST);
                            assert_eq!(req.headers().get(CONTENT_TYPE).unwrap(), DNS_MEDIA_TYPE);
                            assert_eq!(req.headers().get(ACCEPT).unwrap(), DNS_MEDIA_TYPE);
                            let mut query = Vec::new();
                            while let Ok(Some(chunk)) = stream.recv_data().await {
                                let n = chunk.remaining();
                                query.extend_from_slice(&chunk.chunk()[..n]);
                            }
                            let _ = query_tx.send(query);
                            let n = requests.fetch_add(1, Ordering::SeqCst);
                            let (status, retry_after) = script[n.min(script.len() - 1)];
                            let mut resp = Response::builder().status(status);
                            if let Some(v) = retry_after {
                                resp = resp.header(RETRY_AFTER, v);
                            }
                            if status == StatusCode::OK {
                                resp = resp.header(CONTENT_TYPE, DNS_MEDIA_TYPE);
                            }
                            let _ = stream.send_response(resp.body(()).unwrap()).await;
                            if status == StatusCode::OK {
                                let _ = stream.send_data(Bytes::from(body)).await;
                                let _ = stream.finish().await;
                            }
                        });
                    }
                });
            }
        });
        (addr, cert_pem, accepts)
    }

    /// bd 0x4tl：**不响应**的 h3 服务器（模拟服务端挂死）。返回服务端 QUIC 连接的
    /// 关闭观测接收端——断言客户端 `REQUEST_TIMEOUT` 后立刻观测到**对端主动**
    /// CONNECTION_CLOSE（`ApplicationClosed`），而非等 idle timeout（quinn 缺省 30s）。
    async fn spawn_h3_silent_server(
        query_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    ) -> (SocketAddr, String, tokio::sync::oneshot::Receiver<quinn::ConnectionError>) {
        let cert_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = cert_params.self_signed(&key_pair).unwrap();
        let cert_pem = cert.pem();
        let cert_der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
        let key_der = rustls::pki_types::PrivateKeyDer::try_from(key_pair.serialize_der()).unwrap();
        let mut server_tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();
        server_tls.alpn_protocols = vec![b"h3".to_vec()];
        let crypto =
            quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(server_tls)).unwrap();
        let endpoint = quinn::Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(crypto)),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let addr = endpoint.local_addr().unwrap();
        let (closed_tx, closed_rx) = tokio::sync::oneshot::channel();
        // endpoint 句柄留在测试帧里（accept 循环用克隆）：即使 accept 任务退出，
        // 驱动仍存活，观测不会被服务端本地 teardown 污染。
        let ep_loop = endpoint.clone();
        #[allow(clippy::disallowed_methods, reason = "测试：H3 假服务器 accept")]
        tokio::spawn(async move {
            let Some(incoming) = ep_loop.accept().await else { return };
            let Ok(conn) = incoming.await else { return };
            // 连接关闭观测：客户端应主动 close（bd 0x4tl）
            let watcher = conn.clone();
            #[allow(clippy::disallowed_methods, reason = "测试：连接关闭观测")]
            tokio::spawn(async move {
                let err = watcher.closed().await;
                let _ = closed_tx.send(err);
            });
            let Ok(mut h3_conn) =
                h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(conn)).await
            else {
                return;
            };
            // 只受理**一个**请求并读空 body，然后整体挂起——不响应（客户端只能
            // 超时）、也不回到 accept 循环：h3 服务端在 accept 返回 None 时会走
            // `shutdown(0)` 本地关闭连接（LocallyClosed），那会冒充/抢跑客户端的
            // wire close，污染 0x4tl 的观测。挂起态下 h3 内部状态机不被 poll，
            // 不可能本地关闭；唯一能让 watcher 醒来的就是对端 CONNECTION_CLOSE。
            let Ok(Some(resolver)) = h3_conn.accept().await else { return };
            let Ok((_req, mut stream)) = resolver.resolve_request().await else { return };
            let mut query = Vec::new();
            while let Ok(Some(chunk)) = stream.recv_data().await {
                let n = chunk.remaining();
                query.extend_from_slice(&chunk.chunk()[..n]);
            }
            let _ = query_tx.send(query);
            std::future::pending::<()>().await;
        });
        (addr, cert_pem, closed_rx)
    }

    /// 指向 h3 mock 的 resolver（alpn ["h3"] + 自签根；`worker` 个 worker）。
    fn h3_resolver(
        addr: SocketAddr,
        cert_pem: &str,
        worker: usize,
    ) -> (DohResolver, tokio::sync::mpsc::Receiver<(usize, Vec<u8>)>) {
        let params = DohParams::from_json(
            &format!("https://{}:{}/dns-query", addr.ip(), addr.port()),
            Some(&serde_json::json!({
                "serverName": "localhost",
                "alpn": ["h3"],
                "certificates": [{"certificate": cert_pem}]
            })),
            None,
        )
        .unwrap();
        assert!(params.h3, "alpn [\"h3\"] 必须走 DoH-over-QUIC");
        let (resp_tx, resp_rx) = tokio::sync::mpsc::channel(8);
        (DohResolver::new(&params, worker as i32, 0, resp_tx).unwrap(), resp_rx)
    }

    /// 直构 [`Doh3Endpoint`]（0x4tl 超时测试用：注入短超时）。
    fn h3_endpoint(addr: SocketAddr, cert_pem: &str) -> Doh3Endpoint {
        let params = DohParams::from_json(
            &format!("https://{}:{}/dns-query", addr.ip(), addr.port()),
            Some(&serde_json::json!({
                "serverName": "localhost",
                "alpn": ["h3"],
                "certificates": [{"certificate": cert_pem}]
            })),
            None,
        )
        .unwrap();
        let tls = crate::finalmask::realm::tls::build_rustls_client_config(&params.tls)
            .unwrap()
            .expect("h3 client config");
        Doh3Endpoint::new(
            format!("https://{}:{}/dns-query", addr.ip(), addr.port()).parse().unwrap(),
            addr.ip().to_string(),
            addr.port(),
            Arc::new(tls),
            "localhost".to_string(),
            QuicOptions::default(),
        )
    }

    /// 验收 A：真实 `DohResolver::send` → worker → h3 POST → QUIC 服务端 → 响应回投，
    /// 端到端字节断言（非 mock、非只测底层）。顺带覆盖缺省 ChromeParrot（零长 CID）
    /// 与 bd 5lpw3 会话复用（两次查询一条 QUIC 连接）。
    #[tokio::test]
    async fn doh3_resolver_end_to_end() {
        xray_common::ensure_default_crypto_provider();
        let (query_tx, mut query_rx) = tokio::sync::mpsc::unbounded_channel();
        let (addr, cert_pem, accepts) =
            spawn_h3_doh_server(query_tx, vec![(StatusCode::OK, None)], DNS_REPLY.to_vec()).await;

        // 配置面走生产入口：alpn ["h3"] + quicConfig（bbr / idle / keepalive）
        let params = DohParams::from_json(
            &format!("https://127.0.0.1:{}/dns-query", addr.port()),
            Some(&serde_json::json!({
                "serverName": "localhost",
                "alpn": ["h3"],
                "certificates": [{"certificate": cert_pem}]
            })),
            Some(&serde_json::json!({
                "congestion": "bbr",
                "maxIdleTimeout": 30,
                "keepAlivePeriod": 10,
                "initStreamReceiveWindow": 16384,
                "maxStreamReceiveWindow": 65536
            })),
        )
        .expect("h3 配置必须可读入");
        assert!(params.h3, "alpn [\"h3\"] 必须走 DoH-over-QUIC");

        let (resp_tx, mut resp_rx) = tokio::sync::mpsc::channel(4);
        let resolver = DohResolver::new(&params, 1, 7, resp_tx).expect("DohResolver::new");
        let query = b"\x00\x03\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01x\x00\x00\x01\x00\x01";
        resolver.send(query).await.expect("DohResolver::send");

        let (index, body) = tokio::time::timeout(Duration::from_secs(10), resp_rx.recv())
            .await
            .expect("DoH-over-QUIC 响应超时")
            .expect("resolver 关闭");
        assert_eq!(index, 7, "响应必须带原 resolver 下标");
        assert_eq!(body, DNS_REPLY, "响应体必须是服务端回的裸 DNS 报文");
        let wire = query_rx.recv().await.expect("服务端必须收到查询");
        assert_eq!(wire, query, "请求体必须是裸 DNS wire（无 2B 前缀）");
        // 复用同一 resolver 再发一条：bd 5lpw3 会话复用 ⇒ 仍是同一条 QUIC 连接。
        resolver.send(query).await.expect("second send");
        let (_, body2) = tokio::time::timeout(Duration::from_secs(10), resp_rx.recv())
            .await
            .expect("第二次响应超时")
            .expect("resolver 关闭");
        assert_eq!(body2, DNS_REPLY);
        assert_eq!(
            accepts.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "会话复用：两次查询只建 1 条 QUIC 连接"
        );
    }

    /// bd 5lpw3 ②（验收「连接建立次数 = 1」）：同一 resolver 连续 3 次查询，
    /// 服务器侧 QUIC accept 计数必须停在 1（会话槽复用，可断言计数器非肉眼）。
    #[tokio::test]
    async fn doh3_reuses_session_across_queries() {
        xray_common::ensure_default_crypto_provider();
        let (query_tx, query_rx) = tokio::sync::mpsc::unbounded_channel();
        let (addr, cert_pem, accepts) =
            spawn_h3_doh_server(query_tx, vec![(StatusCode::OK, None)], DNS_REPLY.to_vec()).await;
        let (resolver, mut resp_rx) = h3_resolver(addr, &cert_pem, 1);

        for i in 0..3u8 {
            resolver.send(&[i]).await.unwrap();
            let (_, body) = tokio::time::timeout(Duration::from_secs(10), resp_rx.recv())
                .await
                .expect("响应超时")
                .expect("resolver 关闭");
            assert_eq!(body, DNS_REPLY);
        }
        assert_eq!(query_rx.len(), 3, "3 次查询必须全部到达服务端");
        assert_eq!(
            accepts.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "会话复用：3 次查询只建 1 条 QUIC 连接"
        );
    }

    /// bd 0x4tl（验收）：mock h3 服务器**故意不响应** ⇒ 触发 REQUEST_TIMEOUT ⇒
    /// 超时后连接**立即**被服务端观测到对端主动关闭（ApplicationClosed），
    /// 不是等 idle timeout（quinn 缺省 30s；修复前这里 5s 内只会一片寂静）。
    #[tokio::test]
    async fn doh3_timeout_closes_connection_immediately() {
        xray_common::ensure_default_crypto_provider();
        let (query_tx, mut query_rx) = tokio::sync::mpsc::unbounded_channel();
        let (addr, cert_pem, closed_rx) = spawn_h3_silent_server(query_tx).await;

        let mut endpoint = h3_endpoint(addr, &cert_pem);
        // 生产 = REQUEST_TIMEOUT(30s)；测试注入 1s 验证同一关闭路径。
        endpoint.timeout = Duration::from_secs(1);

        let remote = Mutex::new(SocketAddr::from(([0u8, 0, 0, 0], 0)));
        let cooldown = Cooldown::default();
        let err = endpoint
            .post(
                b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01x\x00\x00\x01\x00\x01",
                &remote,
                &cooldown,
            )
            .await
            .expect_err("服务端不响应 ⇒ 必须超时");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        let wire = tokio::time::timeout(Duration::from_secs(5), query_rx.recv())
            .await
            .expect("服务端必须先收到查询")
            .expect("query_tx dropped");
        assert!(!wire.is_empty(), "查询体非空");

        // 0x4tl 核心：RAII（Doh3Session::drop）随超时 future drop 同步发 CONNECTION_CLOSE。
        // 判据带「谁关的」签名：我方 RAII 发 error_code=0 + 专属 reason 字节
        // （doh3.rs `Doh3Session::drop`）；h3 0.0.8 的 last-SendRequest drop 兜底
        // 发的是 H3_NO_ERROR(0x100) + "Connection closed by client"
        // （h3 client/connection.rs:262-265）——error_code 与 reason 双双不同，
        // 本断言据此区分「我方 RAII 关」与「h3 内部兜底关」，RAII 摘除必红。
        let closed = tokio::time::timeout(Duration::from_secs(5), closed_rx)
            .await
            .expect("5s 内未观测到 CONNECTION_CLOSE（这是修复前的等 idle timeout 形态）")
            .expect("closed watcher dropped");
        match closed {
            quinn::ConnectionError::ApplicationClosed(close) => {
                assert_eq!(
                    close.error_code,
                    VarInt::from_u32(0),
                    "错误码必须是我方 RAII 的 0（h3 兜底是 H3_NO_ERROR=0x100）"
                );
                assert_eq!(
                    close.reason.as_ref(),
                    RAII_CLOSE_REASON,
                    "reason 必须是我方 RAII 的专属字节（h3 兜底是 \"Connection closed by client\"）"
                );
            },
            other => {
                panic!("必须是对端主动应用层关闭（CONNECTION_CLOSE），实际 {other:?}")
            },
        }
    }

    /// bd 6eqgp（验收「429 + Retry-After: 60 ⇒ 60s 内不再发请求；h2/h3 共用同一窗」）：
    /// h3 首请求 429 ⇒ 冷却窗落在 **resolver 级共享窗**（worker 侧 cooling 检查与
    /// h2 同源），窗内后续查询直接丢弃、不再建连/发请求。
    #[tokio::test]
    async fn doh3_429_sets_shared_cooldown_and_drops_queries() {
        xray_common::ensure_default_crypto_provider();
        let (query_tx, mut query_rx) = tokio::sync::mpsc::unbounded_channel();
        let (addr, cert_pem, accepts) = spawn_h3_doh_server(
            query_tx,
            vec![(StatusCode::TOO_MANY_REQUESTS, Some("60")), (StatusCode::OK, None)],
            DNS_REPLY.to_vec(),
        )
        .await;
        let (resolver, _resp_rx) = h3_resolver(addr, &cert_pem, 1);

        resolver.send(b"q1").await.unwrap();
        let wire = tokio::time::timeout(Duration::from_secs(10), query_rx.recv())
            .await
            .expect("服务端必须收到首个查询")
            .expect("query_tx dropped");
        assert_eq!(wire, b"q1");

        // 429 → 冷却窗落地（与 h2 同一 `extend_cooldown` / 同一 Arc 实例）。
        let deadline = now() + Duration::from_secs(5);
        while !resolver.test_cooldown_state().0 {
            assert!(now() < deadline, "h3 429 未设置冷却窗");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let (cooling, until) = resolver.test_cooldown_state();
        assert!(cooling && until.is_some());
        assert!(
            until.unwrap().duration_since(now()) > Duration::from_secs(50),
            "Retry-After: 60 的窗不足 50s"
        );

        // 窗内查询：worker 直接丢（不排队、不发请求、不建新连接）。q1 已被上面
        // recv 消费，通道归零 = 无新请求到达。
        for _ in 0..4 {
            resolver.send(b"q2").await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(query_rx.len(), 0, "冷却窗内不得有新请求到达服务端");
        assert_eq!(
            accepts.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "冷却窗内不得新建 QUIC 连接"
        );
    }

    /// bd 6eqgp（「非法值不设窗」，与 h2 一致）：h3 的 429 带 HTTP-date / 乱串 /
    /// 超 u32 的 `Retry-After` ⇒ 不设冷却、不硬失败（Go 两形式都失败时同款）。
    #[tokio::test]
    async fn doh3_429_illegal_retry_after_does_not_cool() {
        xray_common::ensure_default_crypto_provider();
        let (query_tx, mut query_rx) = tokio::sync::mpsc::unbounded_channel();
        let (addr, cert_pem, _accepts) = spawn_h3_doh_server(
            query_tx,
            vec![
                (StatusCode::TOO_MANY_REQUESTS, Some("Wed, 21 Oct 2015 07:28:00 GMT")),
                (StatusCode::TOO_MANY_REQUESTS, Some("nonsense")),
                (StatusCode::TOO_MANY_REQUESTS, Some("99999999999999")),
            ],
            DNS_REPLY.to_vec(),
        )
        .await;
        let (resolver, _resp_rx) = h3_resolver(addr, &cert_pem, 1);

        for i in 0..3u8 {
            resolver.send(&[i]).await.unwrap();
        }
        for _ in 0..3 {
            tokio::time::timeout(Duration::from_secs(10), query_rx.recv())
                .await
                .expect("服务端必须收到查询")
                .expect("query_tx dropped");
        }
        // 429 已回（非 200 无响应回投，worker 只记 DEBUG），给处理留窗口。
        tokio::time::sleep(Duration::from_millis(300)).await;
        let (cooling, slot) = resolver.test_cooldown_state();
        assert!(!cooling && slot.is_none(), "非法 Retry-After 不得设冷却窗");
    }

    /// bd 6eqgp（「窗到期 worker 续跑」，与 h2 一致）：h3 的 429 + `Retry-After: 1`
    /// ⇒ 1s 窗内丢弃、窗到点后同一 worker 继续服务（响应回投恢复）。
    #[tokio::test]
    async fn doh3_cooldown_expires_and_worker_stays_alive() {
        xray_common::ensure_default_crypto_provider();
        let (query_tx, mut query_rx) = tokio::sync::mpsc::unbounded_channel();
        let (addr, cert_pem, _accepts) = spawn_h3_doh_server(
            query_tx,
            vec![(StatusCode::TOO_MANY_REQUESTS, Some("1")), (StatusCode::OK, None)],
            DNS_REPLY.to_vec(),
        )
        .await;
        let (resolver, mut resp_rx) = h3_resolver(addr, &cert_pem, 1);

        resolver.send(b"q1").await.unwrap();
        tokio::time::timeout(Duration::from_secs(10), query_rx.recv())
            .await
            .expect("服务端必须收到 q1")
            .expect("query_tx dropped");
        let deadline = now() + Duration::from_secs(5);
        while !resolver.test_cooldown_state().0 {
            assert!(now() < deadline, "429 未设置冷却窗");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        resolver.send(b"q2").await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(query_rx.len(), 0, "1s 窗内不该再发请求（q1 已消费，归零 = q2 未到达）");

        // 窗到点后同一 worker 继续服务：q3 打到服务器并回投响应（无永久停摆）。
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let (cooling, _) = resolver.test_cooldown_state();
        assert!(!cooling, "1s 的窗必须已过期");
        resolver.send(b"q3").await.unwrap();
        let wire = tokio::time::timeout(Duration::from_secs(10), query_rx.recv())
            .await
            .expect("窗到点后必须继续发请求")
            .expect("query_tx dropped");
        assert_eq!(wire, b"q3");
        let (_, body) = tokio::time::timeout(Duration::from_secs(10), resp_rx.recv())
            .await
            .expect("响应超时")
            .expect("resolver 关闭");
        assert_eq!(body, DNS_REPLY);
    }

    /// bd x677s ③（A-01）：响应体超 `DOH_RECV_MAX`(4096) ⇒ **静默截断**到 4096 字节
    /// （Go `pool4K` 同界：4KiB 缓冲读满即止，多余字节丢弃不报错——这是与 Go 对齐的
    /// 既有行为，本测试把行为钉住，非缺陷）。
    #[tokio::test]
    async fn doh3_body_over_recv_max_is_silently_truncated() {
        xray_common::ensure_default_crypto_provider();
        let big = vec![0xa5u8; 5_000];
        let (query_tx, mut query_rx) = tokio::sync::mpsc::unbounded_channel();
        let (addr, cert_pem, _accepts) =
            spawn_h3_doh_server(query_tx, vec![(StatusCode::OK, None)], big.clone()).await;
        let (resolver, mut resp_rx) = h3_resolver(addr, &cert_pem, 1);

        resolver.send(b"q").await.unwrap();
        tokio::time::timeout(Duration::from_secs(10), query_rx.recv())
            .await
            .expect("服务端必须收到查询")
            .expect("query_tx dropped");
        let (_, body) = tokio::time::timeout(Duration::from_secs(10), resp_rx.recv())
            .await
            .expect("响应超时")
            .expect("resolver 关闭");
        assert_eq!(body.len(), DOH_RECV_MAX, "超界响应体必须截断到 4096");
        assert_eq!(body, big[..DOH_RECV_MAX], "截断保留前 4096 字节");
    }

    /// 非 h3（缺省 alpn）走 h2 路径：`DohParams` 不打 h3 标记。
    #[tokio::test]
    async fn non_h3_alpn_stays_on_h2() {
        let p = DohParams::from_json("https://127.0.0.1/dns-query", None, None).unwrap();
        assert!(!p.h3);
        let p = DohParams::from_json(
            "https://127.0.0.1/dns-query",
            Some(&serde_json::json!({"alpn": ["h2"]})),
            None,
        )
        .unwrap();
        assert!(!p.h3);
    }
}
