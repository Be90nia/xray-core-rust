//! # xdns DoH resolver（对应 Go `resolver_doh.go`，v26.10.17）
//!
//! RFC 8484：`POST` + `Content-Type: application/dns-message`，body 与响应都是裸
//! DNS message（无 2B 长度前缀，HTTP/2 自带 framing）。传输 = TCP + TLS（ALPN
//! 固定 `h2`）+ 树内 `h2` 客户端（`h2`/`http`/`bytes` 均为 workspace 既有依赖，
//! 未引新外部 crate）。
//!
//! `worker` = 并发 POST 任务数（Go `NewDOHResolver` 的 `for range config.Worker`
//! 起 goroutine 组，共享一个无缓冲 `sendCh`）；JSON 层 worker 缺省 32（Go
//! `transport_finalmask.go:860-862`）。
//!
//! ALPN `["h3"]`（且仅此形态）改走 DoH-over-QUIC（`http3.Transport` 对位），见
//! `doh3` 子模块——与 Go `resolver_doh.go:52-104` 的 `len(NextProtocol)==1 &&
//! NextProtocol[0]=="h3"` 判据一致；其余 ALPN 组合零行为变化。
//!
//! ## 与 Go 的差异（bd lf69h）
//!
//! 1. **拨号面**：Go 用 finalmask `dialer.DialTCP` 拨 DoH 服务器（可带代理链/拨号 选项）；Rust xdns
//!    wrap 期只拿得到 `Box<dyn UdpIo>`（UDP-only，无 TCP 拨号 句柄）⇒ 本实现直连，不带 dialer
//!    能力面。
//! 2. **协议**：h2 路只做 HTTP/2（Go 默认 ALPN `["h2","http/1.1"]`，仅 h1.1 的服务器 Go 也能用）；
//!    本栈 ALPN 固定 `h2`，握手失败记日志（不静默降级到明文）。`["h3"]` 走 QUIC（差异见 `doh3`
//!    模块头）。
//! 3. **连接复用**：每请求独立建连（Go `http.Transport` 复用 keep-alive 连接）。
//! 4. **超时**：单请求 30s（Go `http.Client` 无 timeout，挂死的 worker 永久失能）。
//! 5. **429 冷却**：Go 解析 `Retry-After` 到点前不发；本栈丢弃该请求并记日志。
//! 6. **缺 `tlsConfig`**：按 URL host 取 SNI + webpki 根（Go 硬错 "empty tls config" = 更严）；Go
//!    合法配置不受影响。
//!
//! ## 配置期口径
//!
//! `tlsConfig` 只接受 `serverName` / `alpn` / `certificates[].certificate` /
//! `disableSystemRoot` / `minVersion`（`allowInsecure: false` 也无害放行），其余键
//! 配置期硬错点名（禁静默忽略）；`quicConfig` 按 Go `QuicParamsConfig.Build()` 校验
//! 后落 `doh3::QuicOptions`，只在 ALPN `h3` 时生效（Go 只在 h3 分支读它）。

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use bytes::Bytes;
use h2::client;
use http::{
    Method, StatusCode, Uri,
    header::{ACCEPT, CONTENT_TYPE},
};
use parking_lot::Mutex;
use serde_json::Value;
use tokio::sync::mpsc;
use tokio_rustls::TlsConnector;
use xray_proto::xray::transport::internet::{QuicParams, tls::Config as TlsConfigProto};

use super::doh3;
use crate::finalmask::{
    mask_err,
    realm::tls::{MinTlsVersion, TlsConfig, build_rustls_client_config, pem_certificates_to_der},
};

/// DoH 响应体上限（Go `resolver_doh.go` `pool4K`）。
pub(super) const DOH_RECV_MAX: usize = 4096;
/// 请求队列深度（Go `sendCh` 无缓冲；深度 1 等效「生产端等空闲 worker」）。
const QUEUE_CAP: usize = 1;
/// 单请求超时（Go 无 timeout，见模块头差异 4）。
pub(super) const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// DoH 媒体类型（RFC 8484 §4）。
pub(super) const DNS_MEDIA_TYPE: &str = "application/dns-message";
/// 本轮支持的 `tlsConfig` 顶层键；其余硬错。
const TLS_KEYS: [&str; 5] =
    ["serverName", "alpn", "certificates", "disableSystemRoot", "minVersion"];
/// 缺省 HTTPS 端口（Go `url.URL` 无端口时由 http 栈取 443）。
const DEFAULT_HTTPS_PORT: u16 = 443;

/// `quic://` / `http3://` scheme 的配置期硬错文案。
///
/// Go `transport_finalmask.go:903-904` 对 tcp/udp/https 之外的 scheme 一律
/// "invalid protocol"（`quic://` 同样被拒），本栈保留更明确的指路文案：
/// DoH-over-QUIC 走 `https://` + `tlsConfig.alpn ["h3"]`。
pub(crate) fn doh_over_quic() -> io::Error {
    mask_err(
        "xdns: scheme quic:// is not a Go xdns resolver scheme (Go rejects any scheme other \
         than tcp/udp/https): use https:// with tlsConfig.alpn [\"h3\"] for DoH-over-QUIC",
    )
}

/// `https` resolver 的配置期产物（JSON / proto 两路校验后同形）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DohParams {
    /// 完整 URL（Go `url.String()`，scheme = https）。
    pub(crate) url: String,
    /// SNI / 校验名覆盖（Go `tlsConfig.serverName`）；缺省取 URL host。
    pub(crate) sni: Option<String>,
    /// 已校验 TLS 参数（信任根 / ALPN / 协议版本）。
    pub(crate) tls: TlsConfig,
    /// `tlsConfig.alpn == ["h3"]`（Go `resolver_doh.go:52`）⇒ 走 HTTP/3 over QUIC。
    pub(crate) h3: bool,
    /// Go `quicConfig`（缺省 = Go 零值 `&internet.QuicParams{}`）；只在 [`Self::h3`] 时生效。
    pub(crate) quic: doh3::QuicOptions,
}

impl DohParams {
    /// JSON 层：`addrs` 里的 `https://` 项 + 同组 `tlsConfig`/`quicConfig`。
    pub(crate) fn from_json(
        url: &str,
        tls: Option<&Value>,
        quic: Option<&Value>,
    ) -> io::Result<Self> {
        // Go `XDNS.Build` 对每个带 quicConfig 的 resolver 都调 `QuicConfig.Build()`
        // （校验与 ALPN 无关），只在 h3 分支消费其值。
        let quic = doh3::QuicOptions::from_json(quic)?;
        parse_target(url)?; // 配置期校验 scheme/host（构造期不再失败）
        let mut out = Self {
            url: url.to_string(),
            sni: None,
            tls: TlsConfig { alpn: vec!["h2".to_string()], ..TlsConfig::default() },
            h3: false,
            quic,
        };
        let Some(tls) = tls.filter(|v| !v.is_null()) else {
            return Ok(out); // 缺省：URL host 作 SNI + webpki 根（见模块头差异 6）
        };
        let obj = tls
            .as_object()
            .ok_or_else(|| mask_err(format!("xdns: tlsConfig must be an object, got {tls}")))?;

        // Go `transport_security.go:362-364`：allowInsecure 已移除；false 无害放行。
        if obj.get("allowInsecure").and_then(Value::as_bool).unwrap_or(false) {
            return Err(mask_err(
                "xdns: tlsConfig \"allowInsecure\" is removed; DoH resolver never skips \
                 verification (use \"certificates\" with a CA PEM instead)",
            ));
        }
        if let Some(key) =
            obj.keys().find(|k| k.as_str() != "allowInsecure" && !TLS_KEYS.contains(&k.as_str()))
        {
            return Err(mask_err(format!(
                "xdns: tlsConfig key {key:?} is not supported by the DoH resolver (supported: \
                 serverName/alpn/certificates/disableSystemRoot/minVersion)"
            )));
        }

        if let Some(sn) = obj.get("serverName").and_then(Value::as_str).filter(|s| !s.is_empty()) {
            out.sni = Some(sn.to_string());
        }
        out.apply_alpn(obj.get("alpn"))?;
        if let Some(arr) = obj.get("certificates").filter(|v| !v.is_null()) {
            out.apply_certificates(arr)?;
        }
        out.tls.disable_system_root =
            obj.get("disableSystemRoot").and_then(Value::as_bool).unwrap_or(false);
        out.apply_min_version(obj.get("minVersion").and_then(Value::as_str))?;
        Ok(out)
    }

    /// proto 层：`ResolverConfig::from_proto` 的 `https` 分派（wire 对齐用）。
    pub(crate) fn from_proto(
        url: &str,
        tls: Option<&TlsConfigProto>,
        quic: Option<&QuicParams>,
    ) -> io::Result<Self> {
        let quic = doh3::QuicOptions::from_proto(quic)?;
        parse_target(url)?;
        let mut out = Self {
            url: url.to_string(),
            sni: None,
            tls: TlsConfig { alpn: vec!["h2".to_string()], ..TlsConfig::default() },
            h3: false,
            quic,
        };
        let Some(p) = tls else { return Ok(out) };

        out.sni = Some(p.server_name.clone()).filter(|s| !s.is_empty());
        out.apply_alpn(Some(&Value::Array(
            p.next_protocol.iter().cloned().map(Value::String).collect(),
        )))?;
        out.tls.disable_system_root = p.disable_system_root;
        out.apply_min_version(Some(p.min_version.as_str()))?;
        // Go `loadCertificates` 把证书文件字节（PEM）放进 `Certificate.certificate`。
        for cert in &p.certificate {
            let pem = String::from_utf8_lossy(&cert.certificate);
            out.tls.ca_certificates.extend(pem_certificates_to_der(&pem)?);
        }

        let unsupported: Vec<&str> = [
            (p.enable_session_resumption, "enableSessionResumption"),
            (!p.max_version.is_empty(), "maxVersion"),
            (!p.cipher_suites.is_empty(), "cipherSuites"),
            (!p.fingerprint.is_empty(), "fingerprint"),
            (p.reject_unknown_sni, "rejectUnknownSni"),
            (!p.master_key_log.is_empty(), "masterKeyLog"),
            (!p.curve_preferences.is_empty(), "curvePreferences"),
            (!p.verify_peer_cert_by_name.is_empty(), "verifyPeerCertByName"),
            (!p.ech_server_keys.is_empty(), "echServerKeys"),
            (!p.ech_config_list.is_empty(), "echConfigList"),
            (p.ech_socket_settings.is_some(), "echSockopt"),
            (!p.pinned_peer_cert_sha256.is_empty(), "pinnedPeerCertSha256"),
            (p.use_system_ca, "useSystemCa"),
        ]
        .into_iter()
        .filter(|(set, _)| *set)
        .map(|(_, name)| name)
        .collect();
        if !unsupported.is_empty() {
            return Err(mask_err(format!(
                "xdns: tlsConfig keys {unsupported:?} are not supported by the DoH resolver"
            )));
        }
        Ok(out)
    }

    /// ALPN：空 = `h2`；`["h2"]` 放行；`["h3"]` = DoH-over-QUIC（Go `resolver_doh.go:52`
    /// 的 `len==1 && [0]=="h3"` 判据）；其余硬错。
    fn apply_alpn(&mut self, alpn: Option<&Value>) -> io::Result<()> {
        let Some(alpn) = alpn.filter(|v| !v.is_null()) else { return Ok(()) };
        let arr =
            alpn.as_array().ok_or_else(|| mask_err("xdns: tlsConfig alpn must be an array"))?;
        let mut protocols = Vec::with_capacity(arr.len());
        for p in arr {
            let p = p
                .as_str()
                .ok_or_else(|| mask_err("xdns: tlsConfig alpn must contain only strings"))?;
            protocols.push(p.to_string());
        }
        match protocols.as_slice() {
            [] => Ok(()),
            [one] if one == "h2" => Ok(()),
            [one] if one == "h3" => {
                self.h3 = true;
                self.tls.alpn = vec!["h3".to_string()];
                Ok(())
            },
            other => Err(mask_err(format!(
                "xdns: tlsConfig alpn {other:?} is not supported: DoH resolver speaks HTTP/2 \
                 (h2) or, as exactly [\"h3\"], HTTP/3 over QUIC"
            ))),
        }
    }

    /// `certificates[]`：只取 CA PEM（Go `getCertPool` 把所有项当信任根）。
    fn apply_certificates(&mut self, certs: &Value) -> io::Result<()> {
        let arr = certs
            .as_array()
            .ok_or_else(|| mask_err("xdns: tlsConfig certificates must be an array"))?;
        for entry in arr {
            let entry = entry
                .as_object()
                .ok_or_else(|| mask_err("xdns: tlsConfig certificates entry must be an object"))?;
            // `usage` 在 Go getCertPool 同样不参与根池选择 ⇒ 放行；其余键是服务端
            // 侧字段，客户端静默丢会让人以为生效 ⇒ 硬错点名。
            if let Some(key) = entry.keys().find(|k| !matches!(k.as_str(), "certificate" | "usage"))
            {
                return Err(mask_err(format!(
                    "xdns: tlsConfig certificates[].{key} is not supported (DoH client only \
                     needs the CA PEM \"certificate\")"
                )));
            }
            let pem = entry.get("certificate").and_then(Value::as_str).ok_or_else(|| {
                mask_err("xdns: tlsConfig certificates entry missing PEM \"certificate\"")
            })?;
            self.tls.ca_certificates.extend(pem_certificates_to_der(pem)?);
        }
        Ok(())
    }

    /// `minVersion`：1.2/1.3 生效；1.0/1.1 低于 rustls 下限 ⇒ 硬错（禁静默按默认）。
    fn apply_min_version(&mut self, min_version: Option<&str>) -> io::Result<()> {
        match min_version {
            None | Some("") => Ok(()),
            Some("1.2") => {
                self.tls.min_version = Some(MinTlsVersion::Tls12);
                Ok(())
            },
            Some("1.3") => {
                self.tls.min_version = Some(MinTlsVersion::Tls13);
                Ok(())
            },
            Some(other) => Err(mask_err(format!(
                "xdns: tlsConfig minVersion {other:?} is not supported: rustls floor is TLS 1.2 \
                 (use \"1.2\" or \"1.3\")"
            ))),
        }
    }
}

/// 解析后的 DoH 目标（绝对 URI，供 h2 生成 `:scheme`/`:authority`/`:path`）。
struct DohTarget {
    uri: Uri,
    host: String,
    port: u16,
}

/// URL → [`DohTarget`]：只认 `https://`，host 必填，端口缺省 443，路径缺省 `/`
/// （Go `http.NewRequest` 对空路径同样用 `/`）。
fn parse_target(url: &str) -> io::Result<DohTarget> {
    let uri: Uri =
        url.parse().map_err(|e| mask_err(format!("xdns: invalid DoH url {url:?}: {e}")))?;
    if uri.scheme_str() != Some("https") {
        return Err(mask_err(format!("xdns: DoH url {url:?} must use the https:// scheme")));
    }
    let host = uri
        .host()
        .filter(|h| !h.is_empty())
        .ok_or_else(|| mask_err(format!("xdns: DoH url {url:?} has no host")))?
        .to_string();
    let port = uri.port_u16().unwrap_or(DEFAULT_HTTPS_PORT);
    // 规范化：空路径补 "/"，保留 query（Go 直接 POST 配置的 URL，同形）。
    let authority = match uri.port() {
        Some(_) => format!("{host}:{port}"),
        None => host.clone(),
    };
    let path = if uri.path().is_empty() { "/" } else { uri.path() };
    let path_and_query = match uri.query() {
        Some(q) => format!("{path}?{q}"),
        None => path.to_string(),
    };
    let uri = format!("https://{authority}{path_and_query}")
        .parse()
        .map_err(|e| mask_err(format!("xdns: invalid DoH url {url:?}: {e}")))?;
    Ok(DohTarget { uri, host, port })
}

/// 单次请求的固定参数（所有 worker 共享）。
struct DohEndpoint {
    uri: Uri,
    host: String,
    port: u16,
    tls: Arc<tokio_rustls::rustls::ClientConfig>,
    server_name: tokio_rustls::rustls::pki_types::ServerName<'static>,
}

impl DohEndpoint {
    /// POST 一条 DNS 查询，返回响应体（≤ [`DOH_RECV_MAX`] 字节）。
    async fn post(&self, body: &[u8], remote: &Mutex<SocketAddr>) -> io::Result<Vec<u8>> {
        tokio::time::timeout(REQUEST_TIMEOUT, self.do_post(body, remote))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "xdns: DoH request timed out"))?
    }

    async fn do_post(&self, body: &[u8], remote: &Mutex<SocketAddr>) -> io::Result<Vec<u8>> {
        let tcp =
            tokio::net::TcpStream::connect((self.host.as_str(), self.port)).await.map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("xdns: DoH connect {}:{}: {e}", self.host, self.port),
                )
            })?;
        // Go `setaddr`：记录拨号对端，供响应包 addr 标签（见模块头）。
        if let Ok(peer) = tcp.peer_addr() {
            *remote.lock() = peer;
        }
        let tls = TlsConnector::from(self.tls.clone())
            .connect(self.server_name.clone(), tcp)
            .await
            .map_err(|e| io::Error::other(format!("xdns: DoH TLS handshake failed: {e}")))?;
        let (mut send_request, conn) = client::handshake(tls).await.map_err(|e| {
            io::Error::other(format!("xdns: DoH HTTP/2 handshake failed (server may need h2): {e}"))
        })?;
        // h2 连接驱动：寿命 = 本请求（见模块头差异 3）。
        #[allow(
            clippy::disallowed_methods,
            reason = "DoH h2 连接驱动（数据面）；寿命绑定单次请求流，无托管收益（同 client 泵，bd hj3jf）"
        )]
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let req = http::Request::builder()
            .method(Method::POST)
            .uri(self.uri.clone())
            .header(CONTENT_TYPE, DNS_MEDIA_TYPE)
            .header(ACCEPT, DNS_MEDIA_TYPE)
            .header(http::header::USER_AGENT, "") // Go：req.Header.Set("User-Agent", "")
            .body(())
            .map_err(|e| io::Error::other(format!("xdns: DoH build request: {e}")))?;
        let (response, mut stream) = send_request
            .send_request(req, false)
            .map_err(|e| io::Error::other(format!("xdns: DoH send request: {e}")))?;
        stream
            .send_data(Bytes::copy_from_slice(body), true)
            .map_err(|e| io::Error::other(format!("xdns: DoH send body: {e}")))?;
        let response =
            response.await.map_err(|e| io::Error::other(format!("xdns: DoH response: {e}")))?;

        let status = response.status();
        if status != StatusCode::OK {
            // shortcut: 非 200（含 429 Retry-After 冷却）只报错丢弃，Go 会冷却到点
            // 才发下一条；出现吞吐/限流问题再补冷却表。
            return Err(io::Error::other(format!("xdns: DoH status {status}")));
        }
        let mut recv = response.into_body();
        let mut out = Vec::with_capacity(DOH_RECV_MAX);
        while let Some(chunk) = recv.data().await {
            let chunk = chunk.map_err(|e| io::Error::other(format!("xdns: DoH read body: {e}")))?;
            let take = chunk.len().min(DOH_RECV_MAX - out.len());
            out.extend_from_slice(&chunk[..take]);
            if out.len() >= DOH_RECV_MAX {
                break;
            }
        }
        Ok(out)
    }
}

/// DoH 传输选择（Go `resolver_doh.go:52-104` 的 `switch`）：`alpn == ["h3"]` 走
/// HTTP/3 over QUIC，其余走既有 TLS+h2（该路径一行未改）。
enum DohTransport {
    H2(DohEndpoint),
    H3(doh3::Doh3Endpoint),
}

impl DohTransport {
    /// POST 一条 DNS 查询，返回响应体（≤ [`DOH_RECV_MAX`] 字节）。
    async fn post(&self, body: &[u8], remote: &Mutex<SocketAddr>) -> io::Result<Vec<u8>> {
        match self {
            Self::H2(endpoint) => endpoint.post(body, remote).await,
            Self::H3(endpoint) => endpoint.post(body, remote).await,
        }
    }
}

/// DoH 传输端：`worker` 个 POST 任务共享一条请求队列（Go `DOHResolver`）。
pub(crate) struct DohResolver {
    tx: mpsc::Sender<Vec<u8>>,
    /// 最近一次拨号的对端地址（Go `setaddr`）。
    remote: Arc<Mutex<SocketAddr>>,
}

impl DohResolver {
    /// 校验配置并起 `worker` 个 POST 任务；响应字节经 `resp_tx` 回投（带 resolver 下标）。
    pub(crate) fn new(
        params: &DohParams,
        worker: i32,
        index: usize,
        resp_tx: mpsc::Sender<(usize, Vec<u8>)>,
    ) -> io::Result<Self> {
        // Go `NewDOHResolver`：`config.Worker < 1` → "invalid worker"。
        if worker < 1 {
            return Err(mask_err("xdns: invalid worker"));
        }
        let target = parse_target(&params.url)?;
        let tls = build_rustls_client_config(&params.tls)?
            .ok_or_else(|| io::Error::other("xdns: DoH tls config produced no client config"))?;
        let sni = params.sni.clone().unwrap_or_else(|| target.host.clone());
        let tls = Arc::new(tls);
        let endpoint = Arc::new(if params.h3 {
            DohTransport::H3(doh3::Doh3Endpoint::new(
                target.uri,
                target.host,
                target.port,
                tls,
                sni,
                params.quic.clone(),
            ))
        } else {
            let server_name =
                tokio_rustls::rustls::pki_types::ServerName::try_from(sni).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("xdns: invalid DoH SNI: {e}"),
                    )
                })?;
            DohTransport::H2(DohEndpoint {
                uri: target.uri,
                host: target.host,
                port: target.port,
                tls,
                server_name,
            })
        });

        let (tx, rx) = mpsc::channel::<Vec<u8>>(QUEUE_CAP);
        let rx = Arc::new(tokio::sync::Mutex::new(rx));
        let remote = Arc::new(Mutex::new(SocketAddr::from(([0u8, 0, 0, 0], 0))));
        for _ in 0..worker {
            let endpoint = endpoint.clone();
            let rx = rx.clone();
            let resp_tx = resp_tx.clone();
            let remote = remote.clone();
            #[allow(
                clippy::disallowed_methods,
                reason = "DoH worker（数据面 DoH 泵）；显式脱管：托管无收益（本层无 PluginContext 可穿），寿命随所属 xdns client（bd hj3jf 同款裁定）"
            )]
            tokio::spawn(async move {
                loop {
                    // 锁只覆盖 recv（有队列项时立即返回），无序化代价。
                    let Some(payload) = rx.lock().await.recv().await else { return };
                    match endpoint.post(&payload, &remote).await {
                        Ok(body) => {
                            if resp_tx.send((index, body)).await.is_err() {
                                return; // 读端已关（client 已 drop）
                            }
                        },
                        Err(e) => crate::hot_log!(DEBUG, "error={e} xdns: DoH request failed"),
                    }
                }
            });
        }
        Ok(Self { tx, remote })
    }

    /// 记录的对端地址（Go `DOHResolver.Addr`）。
    pub(crate) fn remote_addr(&self) -> SocketAddr {
        *self.remote.lock()
    }

    /// 投递一条 DNS 查询（Go `Send`：队列满时等待空闲 worker）。
    pub(crate) async fn send(&self, payload: &[u8]) -> io::Result<()> {
        self.tx
            .send(payload.to_vec())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "xdns: DoH resolver closed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(tls: Option<Value>) -> io::Result<DohParams> {
        DohParams::from_json("https://127.0.0.1:8443/dns-query", tls.as_ref(), None)
    }

    /// 缺省：URL host 作 SNI、ALPN 固定 h2、无自定义根。
    #[test]
    fn json_defaults() {
        let p = params(None).unwrap();
        assert_eq!(p.sni, None);
        assert_eq!(p.tls.alpn, vec!["h2".to_string()]);
        assert!(p.tls.ca_certificates.is_empty());
        assert!(!p.tls.disable_system_root);
        assert!(p.tls.min_version.is_none());
    }

    /// `serverName` 生效（与 URL host 解耦）；`allowInsecure: false` 无害放行。
    #[test]
    fn json_server_name_and_allow_insecure_false() {
        let p = params(Some(serde_json::json!({
            "serverName": "dns.example.net",
            "allowInsecure": false,
            "alpn": ["h2"]
        })))
        .unwrap();
        assert_eq!(p.sni.as_deref(), Some("dns.example.net"));
    }

    /// `allowInsecure: true` 硬错（禁用跳过校验）。
    #[test]
    fn json_rejects_allow_insecure_true() {
        let e = params(Some(serde_json::json!({"allowInsecure": true}))).unwrap_err();
        assert!(e.to_string().contains("allowInsecure"), "{e}");
    }

    /// 未支持键配置期硬错点名（禁静默忽略）。
    #[test]
    fn json_rejects_unknown_key_by_name() {
        let e = params(Some(serde_json::json!({"fingerprint": "chrome"}))).unwrap_err();
        assert!(e.to_string().contains("fingerprint"), "{e}");
        let e = params(Some(serde_json::json!({"maxVersion": "1.3"}))).unwrap_err();
        assert!(e.to_string().contains("maxVersion"), "{e}");
    }

    /// ALPN：`["h3"]` → DoH-over-QUIC（`h3` 标记 + ALPN 落 rustls）；其它 → 只支持 h2。
    #[test]
    fn json_alpn_h3_and_other_rejected() {
        let p = params(Some(serde_json::json!({"alpn": ["h3"]}))).unwrap();
        assert!(p.h3, "alpn [\"h3\"] 必须走 HTTP/3");
        assert_eq!(p.tls.alpn, vec!["h3".to_string()]);
        let e = params(Some(serde_json::json!({"alpn": ["http/1.1"]}))).unwrap_err();
        assert!(e.to_string().contains("h2"), "{e}");
        // `["h3","h2"]` 不是 Go 的 h3 判据（要求 len==1）⇒ 硬错不静默择一
        let e = params(Some(serde_json::json!({"alpn": ["h3", "h2"]}))).unwrap_err();
        assert!(e.to_string().contains("alpn"), "{e}");
        // 显式 ["h2"] 放行，走 h2
        let p = params(Some(serde_json::json!({"alpn": ["h2"]}))).unwrap();
        assert!(!p.h3);
    }

    /// `quicConfig` 解析并按 Go `QuicParamsConfig.Build()` 校验（只在 h3 生效）。
    #[test]
    fn json_accepts_quic_config() {
        let p = DohParams::from_json(
            "https://127.0.0.1/dns-query",
            None,
            Some(&serde_json::json!({"congestion": "bbr", "maxIdleTimeout": 30})),
        )
        .unwrap();
        assert!(!p.h3, "quicConfig 单独出现不走 h3（Go 只在 alpn h3 时读它）");
        assert_eq!(p.tls.alpn, vec!["h2".to_string()]);

        // 未实现控制器硬错点名（禁静默忽略）
        let e = DohParams::from_json(
            "https://127.0.0.1/dns-query",
            Some(&serde_json::json!({"alpn": ["h3"]})),
            Some(&serde_json::json!({"congestion": "force-brutal"})),
        )
        .unwrap_err();
        assert!(e.to_string().contains("force-brutal"), "{e}");
    }

    /// `minVersion` 1.2/1.3 生效；1.0/1.1 与乱值硬错。
    #[test]
    fn json_min_version() {
        assert_eq!(
            params(Some(serde_json::json!({"minVersion": "1.3"}))).unwrap().tls.min_version,
            Some(MinTlsVersion::Tls13)
        );
        assert_eq!(
            params(Some(serde_json::json!({"minVersion": "1.2"}))).unwrap().tls.min_version,
            Some(MinTlsVersion::Tls12)
        );
        assert!(params(Some(serde_json::json!({"minVersion": "1.1"}))).is_err());
        assert!(params(Some(serde_json::json!({"minVersion": "2"}))).is_err());
    }

    /// `certificates[].certificate` 转 DER 信任根；`key`/`certificatePath` 硬错。
    #[test]
    fn json_certificates_take_ca_pem_only() {
        let (pem, _) = test_cert();
        let p = params(Some(serde_json::json!({
            "certificates": [{"certificate": pem, "usage": "AUTHORITY_VERIFY"}],
            "disableSystemRoot": true
        })))
        .unwrap();
        assert_eq!(p.tls.ca_certificates.len(), 1);
        assert!(p.tls.disable_system_root);
        let err =
            params(Some(serde_json::json!({"certificates": [{"certificate": pem, "key": "x"}]})))
                .unwrap_err();
        assert!(err.to_string().contains("key"), "{err}");
    }

    /// URL 规范化：`https://host` → 路径补 `/`；非 https / 无 host 硬错。
    #[test]
    fn url_normalization() {
        let t = parse_target("https://dns.google").unwrap();
        assert_eq!(t.uri.to_string(), "https://dns.google/");
        assert_eq!(t.port, 443);
        let t = parse_target("https://1.1.1.1:8443/dns-query?x=1").unwrap();
        assert_eq!(t.uri.to_string(), "https://1.1.1.1:8443/dns-query?x=1");
        assert_eq!(t.port, 8443);
        assert!(parse_target("http://dns.google/dns-query").is_err());
        assert!(parse_target("https:///dns-query").is_err());
    }

    /// 自签证书 PEM + 私钥 DER（SNI：localhost）。
    fn test_cert() -> (String, Vec<u8>) {
        let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        (cert.pem(), key_pair.serialize_der())
    }
}
