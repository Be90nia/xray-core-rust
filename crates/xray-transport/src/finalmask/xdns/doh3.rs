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
//! 4. **连接复用**：每请求独立 QUIC 连接（Go 一个 `http3.Transport` 复用连接；同 `doh` 模块头差异
//!    3，本票非目标）。
//! 5. **`disableGSO` / `disableStatelessReset` / `debug`**：quinn 无对应旋钮（GSO 自动、 无
//!    stateless-reset key、`debug` 只影响 hysteria 控制器日志环境变量）⇒ 键接受、无效果。

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use bytes::{Buf, Bytes};
use http::{
    Method, StatusCode, Uri,
    header::{ACCEPT, CONTENT_TYPE, USER_AGENT},
};
use parking_lot::Mutex;
use quinn::VarInt;
use serde_json::Value;
use xray_proto::xray::transport::internet::QuicParams as QuicParamsProto;

use super::doh::{DNS_MEDIA_TYPE, DOH_RECV_MAX, REQUEST_TIMEOUT};
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

/// h3 DoH 端点（每次 POST 一条独立 QUIC 连接，见模块头差异 4）。
pub(super) struct Doh3Endpoint {
    uri: Uri,
    host: String,
    port: u16,
    tls: Arc<tokio_rustls::rustls::ClientConfig>,
    /// SNI / 证书校验名（Go `serverName`，缺省 URL host）。
    server_name: String,
    quic: QuicOptions,
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
        Self { uri, host, port, tls, server_name, quic }
    }

    /// POST 一条 DNS 查询，返回响应体（≤ [`DOH_RECV_MAX`] 字节）。
    pub(super) async fn post(
        &self,
        body: &[u8],
        remote: &Mutex<SocketAddr>,
    ) -> io::Result<Vec<u8>> {
        tokio::time::timeout(REQUEST_TIMEOUT, self.post_any(body, remote))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "xdns: DoH request timed out"))?
    }

    /// 目标解析出多个地址时逐个尝试（QUIC 无 happy-eyeballs，顺序即优先级）。
    async fn post_any(&self, body: &[u8], remote: &Mutex<SocketAddr>) -> io::Result<Vec<u8>> {
        let addrs =
            tokio::net::lookup_host((self.host.as_str(), self.port)).await.map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("xdns: DoH resolve {}:{}: {e}", self.host, self.port),
                )
            })?;
        let mut last: Option<io::Error> = None;
        for addr in addrs {
            match self.post_to(addr, body, remote).await {
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
    ) -> io::Result<Vec<u8>> {
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

        let (mut driver, mut send_request) =
            h3::client::new(h3_quinn::Connection::new(conn.clone()))
                .await
                .map_err(|e| io::Error::other(format!("xdns: DoH h3 handshake: {e}")))?;
        #[allow(
            clippy::disallowed_methods,
            reason = "DoH h3 连接 driver（数据面）；寿命绑定单次请求连接，无托管收益（同 doh.rs h2 driver 与 splithttp h3 driver，bd hj3jf）"
        )]
        tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        let result = self.exchange(&mut send_request, body).await;
        // Go `context.AfterFunc(qc.Context(), tr.Close)` 对位：请求结束即发
        // CONNECTION_CLOSE，否则服务端要干等 idle timeout。
        conn.close(VarInt::from_u32(0), b"xdns: DoH request done");
        result
    }

    /// 一轮 POST/响应交换（RFC 8484 §4：请求体 = 裸 DNS message）。
    async fn exchange(&self, send_request: &mut H3SendRequest, body: &[u8]) -> io::Result<Vec<u8>> {
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
            // shortcut: 非 200（含 429 Retry-After 冷却）只报错丢弃，同 h2 路径。
            return Err(io::Error::other(format!("xdns: DoH status {status}")));
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
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use http::Response;

    use super::*;
    use crate::finalmask::xdns::doh::{DohParams, DohResolver};

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

    /// 固定的 DNS 应答报文（wire 形态，`x.y.example.com. A 1.2.3.4`）。
    const DNS_REPLY: [u8; 29] = [
        0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, b'x', 0x07,
        b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
    ];

    /// 起一个 H3 DoH 服务器：ALPN `h3` + 自签证书（SAN localhost），把收到的请求体
    /// 经 `query_tx` 送回测试体，并回 [`DNS_REPLY`]。
    async fn spawn_h3_doh_server(
        query_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    ) -> (SocketAddr, String) {
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
        #[allow(clippy::disallowed_methods, reason = "测试：H3 DoH 假服务器 accept 环")]
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let query_tx = query_tx.clone();
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
                            let resp = Response::builder()
                                .status(StatusCode::OK)
                                .header(CONTENT_TYPE, DNS_MEDIA_TYPE)
                                .body(())
                                .unwrap();
                            let _ = stream.send_response(resp).await;
                            let _ = stream.send_data(Bytes::from_static(&DNS_REPLY)).await;
                            let _ = stream.finish().await;
                        });
                    }
                });
            }
        });
        (addr, cert_pem)
    }

    /// 验收 A：真实 `DohResolver::send` → worker → h3 POST → QUIC 服务端 → 响应回投，
    /// 端到端字节断言（非 mock、非只测底层）。顺带覆盖缺省 ChromeParrot（零长 CID）。
    #[tokio::test]
    async fn doh3_resolver_end_to_end() {
        xray_common::ensure_default_crypto_provider();
        let (query_tx, mut query_rx) = tokio::sync::mpsc::unbounded_channel();
        let (addr, cert_pem) = spawn_h3_doh_server(query_tx).await;

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
        // 复用同一 resolver 再发一条：证明 per-request 建连可重复
        resolver.send(query).await.expect("second send");
        let (_, body2) = tokio::time::timeout(Duration::from_secs(10), resp_rx.recv())
            .await
            .expect("第二次响应超时")
            .expect("resolver 关闭");
        assert_eq!(body2, DNS_REPLY);
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
