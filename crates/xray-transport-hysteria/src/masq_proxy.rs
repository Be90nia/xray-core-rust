//! masquerade「proxy」反代（Go `transport/internet/hysteria/hub.go:219-265`）。
//!
//! Go 侧 = `httputil.ReverseProxy` + `Rewrite` 回调，语义逐条对齐：
//!
//! | Go 行为 | 本实现 |
//! |---|---|
//! | `r.SetURL(u)`：出站 scheme/host 取 `MasqUrl`；path = `joinURLPath(MasqUrl.path, 入站 path)`；query = `MasqUrl.query` + "&" + 入站 query；`r.Out.Host = ""` | [`MasqTarget`] 解析 + [`join_url_path`] / [`join_query`] |
//! | `if !MasqUrlRewriteHost { r.Out.Host = r.In.Host }` | `rewrite_host=false`（**Go 默认**）→ Host 头保留**客户端原始 Host**；`true` → Host 头 = 上游 authority |
//! | `MasqUrlInsecure`（仅 http/https）→ 上游 TLS `InsecureSkipVerify` | [`tls_connector`] 的 `insecure` 分支（跳过证书校验） |
//! | Rewrite 前剥除客户端自带 `X-Forwarded-*` | [`strip_forwarded_headers`] |
//! | hop-by-hop 头不转发（Go `ReverseProxy`） | [`HOP_BY_HOP`] |
//! | `ErrorHandler` → `502 Bad Gateway` | [`proxy_bad_gateway`] |
//! | scheme `""`/`unix` → unix socket 上游 | 未实现：构造期报错（Rust 侧无 unix socket 上游面） |
//!
//! 未对齐（已知偏差，报告登记）：Go 的 `MasqUrlXForwarded`（本仓配置面无该字段）、
//! Go 的 `cleanQueryParams`（丢弃不可解析的 query 参数）、Go 的连接池
//! （`MaxIdleConns=100`；本实现每请求一次连接，伪装面低频可接受）。

use std::{collections::HashMap, sync::Arc};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{
    Request,
    header::{HeaderName, HeaderValue},
};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::hub::{MasqRequest, MasqResponse, MasqueradeHandler};

/// hop-by-hop 头（Go `ReverseProxy` 不转发；RFC 7230 §6.1）。
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "proxy-connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// 客户端自带的转发头（Go `Rewrite` 前剥除）。
const FORWARDED_HEADERS: &[&str] =
    &["forwarded", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto"];

/// 上游 URL 解析结果（Go `url.Parse(config.MasqUrl)`）。
#[derive(Debug, Clone)]
pub struct MasqTarget {
    /// `http` / `https`。
    scheme: String,
    /// 主机名（TLS SNI / DNS 用，不含端口）。
    host: String,
    /// 端口（缺省 http=80 / https=443）。
    port: u16,
    /// URL 里显式写的 authority（Host 头用；Go `URL.Host` 保留原样，含端口）。
    authority: String,
    /// `MasqUrl` 的 path（参与 `joinURLPath`）。
    path: String,
    /// `MasqUrl` 的 query（参与 query 拼接）。
    query: String,
}

impl MasqTarget {
    /// 上游 authority（Host 头；Go `URL.Host` 语义：无显式端口则不含端口）。
    fn authority(&self) -> &str {
        &self.authority
    }
}

/// 解析 `MasqUrl`（Go `url.Parse` + scheme 分支）。
///
/// # Errors
/// scheme 缺失/非 http(s)、端口非法 → Err（Go：`Listen` 直接报错；本仓构造期
/// 报错并让 handler 固定回 502，见 [`ProxyMasqHandler`]）。
pub fn parse_masq_target(url: &str) -> Result<MasqTarget, String> {
    let Some((scheme, rest)) = url.split_once("://") else {
        return Err(format!("masq url missing scheme: {url}"));
    };
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(format!("masq url unsupported scheme: {scheme}"));
    }
    let (authority, path_query) = match rest.find(['/', '?']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let (host, port, authority) = split_authority(authority, &scheme)?;
    let (path, query) = match path_query.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (path_query.to_string(), String::new()),
    };
    Ok(MasqTarget { scheme, host, port, authority, path, query })
}

/// authority → (host, port, 原样 authority)；IPv6 `[::1]:port` 形态。
fn split_authority(authority: &str, scheme: &str) -> Result<(String, u16, String), String> {
    let default_port = if scheme == "https" { 443 } else { 80 };
    if let Some(stripped) = authority.strip_prefix('[') {
        let Some(close) = stripped.find(']') else {
            return Err(format!("masq url bad ipv6 authority: {authority}"));
        };
        let host = &stripped[..close];
        let tail = &stripped[close + 1..];
        let (port, raw) = match tail.strip_prefix(':') {
            Some(p) => (
                p.parse::<u16>().map_err(|_| format!("masq url bad port: {p}"))?,
                authority.to_string(),
            ),
            None => (default_port, authority.to_string()),
        };
        return Ok((host.to_string(), port, raw));
    }
    match authority.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
            let port = p.parse::<u16>().map_err(|_| format!("masq url bad port: {p}"))?;
            Ok((h.to_string(), port, authority.to_string()))
        },
        _ => Ok((authority.to_string(), default_port, authority.to_string())),
    }
}

/// Go `joinURLPath`（`httputil` 内部）：目标 path 与入站 path 拼接。
///
/// 无转义 path 时等价 Go `singleJoiningSlash`：目标以 `/` 结尾且入站以 `/` 开头
/// → 去重斜杠；两侧都无斜杠 → 补一个；其余直连。
fn join_url_path(target_path: &str, in_path: &str) -> String {
    let aslash = target_path.ends_with('/');
    let bslash = in_path.starts_with('/');
    match (aslash, bslash) {
        (true, true) => format!("{target_path}{}", &in_path[1..]),
        (false, false) => format!("{target_path}/{in_path}"),
        _ => format!("{target_path}{in_path}"),
    }
}

/// Go `rewriteRequestURL` 的 query 拼接：目标 query + "&" + 入站 query。
fn join_query(target_query: &str, in_query: &str) -> String {
    match (target_query.is_empty(), in_query.is_empty()) {
        (true, _) => in_query.to_string(),
        (false, true) => target_query.to_string(),
        (false, false) => format!("{target_query}&{in_query}"),
    }
}

/// 剥除 hop-by-hop 与客户端自带转发头（Go `ReverseProxy` + `Rewrite`）。
fn strip_forwarded_headers(headers: &mut HashMap<String, String>) {
    headers.retain(|k, _| {
        let lower = k.to_ascii_lowercase();
        !HOP_BY_HOP.contains(&lower.as_str()) && !FORWARDED_HEADERS.contains(&lower.as_str())
    });
}

/// 上游 TLS 连接器（`MasqUrlInsecure` → 跳过证书校验）。
fn tls_connector(insecure: bool) -> Result<tokio_rustls::TlsConnector, String> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let config = if insecure {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth()
    };
    Ok(tokio_rustls::TlsConnector::from(Arc::new(config)))
}

/// 上游 IO（明文 TCP 或 TLS）——`dyn` 需要单一主 trait，故用组合 trait。
trait UpstreamIo: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> UpstreamIo for T {}

/// `MasqUrlInsecure` 的校验器：接受任意证书（Go `InsecureSkipVerify`）。
#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
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
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Go `ErrorHandler`：反代失败 → 502 Bad Gateway。
fn proxy_bad_gateway(reason: &str) -> MasqResponse {
    (
        502,
        HashMap::from([("Content-Type".to_string(), "text/plain; charset=utf-8".to_string())]),
        format!("Bad Gateway: {reason}\n").into_bytes(),
    )
}

/// masquerade「proxy」反代 handler（Go `httputil.ReverseProxy`）。
#[derive(Debug, Clone)]
pub struct ProxyMasqHandler {
    /// 上游目标（解析失败 → 固定 502，fail-visible）。
    target: Result<MasqTarget, String>,
    /// `MasqUrlRewriteHost`：false（Go 默认）保留客户端原始 Host。
    rewrite_host: bool,
    /// `MasqUrlInsecure`：跳过上游 TLS 证书校验。
    insecure: bool,
}

impl ProxyMasqHandler {
    /// 构造反代 handler（对应 Go `Listen` 的 `"proxy"` 分支）。
    #[must_use]
    pub fn new(url: &str, rewrite_host: bool, insecure: bool) -> Self {
        Self { target: parse_masq_target(url), rewrite_host, insecure }
    }

    /// 反代一次请求（Go `ReverseProxy.ServeHTTP`）。
    async fn forward(
        target: &MasqTarget,
        rewrite_host: bool,
        insecure: bool,
        req: MasqRequest,
    ) -> Result<MasqResponse, String> {
        let (in_path, in_query) = match req.path.split_once('?') {
            Some((p, q)) => (p.to_string(), q.to_string()),
            None => (req.path.clone(), String::new()),
        };
        let path = join_url_path(&target.path, &in_path);
        let query = join_query(&target.query, &in_query);
        let uri = if query.is_empty() { path } else { format!("{path}?{query}") };

        // 连接上游（DNS + TCP；TLS 由 scheme 决定）。
        let stream = tokio::net::TcpStream::connect((target.host.as_str(), target.port))
            .await
            .map_err(|e| format!("connect upstream: {e}"))?;
        let io: Box<dyn UpstreamIo + Unpin + Send> = if target.scheme == "https" {
            let connector = tls_connector(insecure)?;
            let name = rustls::pki_types::ServerName::try_from(target.host.clone())
                .map_err(|e| format!("bad server name: {e}"))?;
            let tls =
                connector.connect(name, stream).await.map_err(|e| format!("tls handshake: {e}"))?;
            Box::new(tls)
        } else {
            Box::new(stream)
        };

        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
            .await
            .map_err(|e| format!("upstream handshake: {e}"))?;
        #[allow(
            clippy::disallowed_methods,
            reason = "上游 HTTP/1.1 连接驱动任务（hyper conn）：随上游响应/错误结束即退出，生命周期短于本 handler；本 crate 无 PluginContext 托管面（xray-frame 仅 dev-dependency），显式脱管：句柄无需持有"
        )]
        tokio::spawn(async move {
            let _ = conn.await;
        });

        // 请求头：剥 hop-by-hop + 客户端转发头；Host 按 MasqUrlRewriteHost 语义。
        let mut headers = req.headers.clone();
        strip_forwarded_headers(&mut headers);
        headers.retain(|k, _| !k.eq_ignore_ascii_case("host"));
        let host_header = if rewrite_host {
            target.authority().to_string()
        } else if !req.host.is_empty() {
            req.host.clone()
        } else {
            target.authority().to_string()
        };
        let mut builder = Request::builder().method(req.method.as_str()).uri(uri);
        for (k, v) in &headers {
            if let (Ok(name), Ok(value)) =
                (HeaderName::from_bytes(k.as_bytes()), HeaderValue::from_str(v))
            {
                builder = builder.header(name, value);
            }
        }
        builder = builder.header(
            http::header::HOST,
            HeaderValue::from_str(&host_header).map_err(|e| format!("bad host header: {e}"))?,
        );
        let request = builder
            .body(Full::new(Bytes::from(req.body)))
            .map_err(|e| format!("build request: {e}"))?;

        let response =
            sender.send_request(request).await.map_err(|e| format!("upstream request: {e}"))?;
        let (parts, body) = response.into_parts();
        let bytes = body.collect().await.map_err(|e| format!("upstream body: {e}"))?.to_bytes();
        let mut out_headers = HashMap::new();
        for (name, value) in parts.headers.iter() {
            let lower = name.as_str().to_ascii_lowercase();
            if HOP_BY_HOP.contains(&lower.as_str()) {
                continue;
            }
            if let Ok(v) = value.to_str() {
                out_headers.insert(name.as_str().to_string(), v.to_string());
            }
        }
        Ok((parts.status.as_u16(), out_headers, bytes.to_vec()))
    }
}

impl MasqueradeHandler for ProxyMasqHandler {
    fn serve(
        &self,
        method: &str,
        path: &str,
        headers: &HashMap<String, String>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = MasqResponse> + Send>> {
        let req = MasqRequest {
            method: method.to_string(),
            path: path.to_string(),
            headers: headers.clone(),
            host: headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("host"))
                .map(|(_, v)| v.clone())
                .unwrap_or_default(),
            body: Vec::new(),
        };
        self.serve_request(req)
    }

    fn serve_request(
        &self,
        req: MasqRequest,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = MasqResponse> + Send>> {
        let target = self.target.clone();
        let rewrite_host = self.rewrite_host;
        let insecure = self.insecure;
        Box::pin(async move {
            let target = match &target {
                Ok(t) => t.clone(),
                Err(e) => {
                    crate::LOG.debug(format!("masq proxy target invalid: {e}"));
                    return proxy_bad_gateway(e);
                },
            };
            match Self::forward(&target, rewrite_host, insecure, req).await {
                Ok(resp) => resp,
                Err(e) => {
                    crate::LOG.debug(format!("masq proxy error: {e}"));
                    proxy_bad_gateway(&e)
                },
            }
        })
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    //! 反代测试夹具：记录请求的本地 HTTP 上游（Rust/Go 对照共用观测面）。

    use std::sync::Arc;

    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::TcpListener,
    };

    /// 上游观测到的请求（method / path / query / Host / body）。
    #[derive(Debug, Clone, Default)]
    pub(crate) struct UpstreamSeen {
        pub(crate) method: String,
        pub(crate) path: String,
        pub(crate) query: String,
        pub(crate) host: String,
        pub(crate) body: String,
    }

    /// 起一个记录请求的本地 HTTP 上游（响应固定 200 + "upstream-ok"）。
    pub(crate) async fn start_recording_upstream()
    -> (u16, Arc<tokio::sync::Mutex<Vec<UpstreamSeen>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind upstream");
        let port = listener.local_addr().expect("addr").port();
        let seen: Arc<tokio::sync::Mutex<Vec<UpstreamSeen>>> =
            Arc::new(tokio::sync::Mutex::new(vec![]));
        let sink = Arc::clone(&seen);
        xray_common::testing::spawn("masq-proxy-upstream", async move {
            while let Ok((mut sock, _peer)) = listener.accept().await {
                let sink = Arc::clone(&sink);
                xray_common::testing::spawn("masq-proxy-upstream-conn", async move {
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 1024];
                    // 读到请求头结束
                    let head_end = loop {
                        let Ok(n) = sock.read(&mut tmp).await else { return };
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                        if let Some(p) = find_head_end(&buf) {
                            break p;
                        }
                    };
                    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
                    let mut lines = head.split("\r\n");
                    let request_line = lines.next().unwrap_or_default().to_string();
                    let mut parts = request_line.split(' ');
                    let method = parts.next().unwrap_or_default().to_string();
                    let target = parts.next().unwrap_or_default().to_string();
                    let (path, query) = match target.split_once('?') {
                        Some((p, q)) => (p.to_string(), q.to_string()),
                        None => (target.clone(), String::new()),
                    };
                    let mut host = String::new();
                    let mut content_length = 0usize;
                    for line in lines {
                        let Some((k, v)) = line.split_once(':') else { continue };
                        let key = k.trim().to_ascii_lowercase();
                        let val = v.trim().to_string();
                        if key == "host" {
                            host = val;
                        } else if key == "content-length" {
                            content_length = val.parse().unwrap_or(0);
                        }
                    }
                    // 读 body
                    let mut body = buf[head_end..].to_vec();
                    while body.len() < content_length {
                        let Ok(n) = sock.read(&mut tmp).await else { break };
                        if n == 0 {
                            break;
                        }
                        body.extend_from_slice(&tmp[..n]);
                    }
                    sink.lock().await.push(UpstreamSeen {
                        method,
                        path,
                        query,
                        host,
                        body: String::from_utf8_lossy(&body).to_string(),
                    });
                    let payload = b"upstream-ok";
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        payload.len()
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.write_all(payload).await;
                    let _ = sock.flush().await;
                });
            }
        });
        (port, seen)
    }

    /// buf 中 "\r\n\r\n" 的结束位置（None = 尚未出现）。
    pub(crate) fn find_head_end(buf: &[u8]) -> Option<usize> {
        buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, time::Duration};

    use tokio::net::TcpListener;

    use super::*;
    use crate::{hub::MasqueradeHandler, masq_proxy::test_support::start_recording_upstream};

    fn masq_request(method: &str, path: &str, host: &str, body: &str) -> MasqRequest {
        MasqRequest {
            method: method.to_string(),
            path: path.to_string(),
            headers: HashMap::from([("x-test".to_string(), "1".to_string())]),
            host: host.to_string(),
            body: body.as_bytes().to_vec(),
        }
    }

    /// bd 4zcki：`MasqUrlRewriteHost=false`（Go 默认）→ 上游 Host 头 = 客户端原始
    /// Host；path/query 按 Go `rewriteRequestURL` 拼接；body 透传。
    #[tokio::test]
    async fn proxy_forwards_request_to_upstream_keeping_client_host() {
        let (port, seen) = start_recording_upstream().await;
        let handler = ProxyMasqHandler::new(&format!("http://127.0.0.1:{port}/base"), false, false);
        let resp = handler
            .serve_request(masq_request("POST", "/probe?x=1", "masq.example.com", "hello-body"))
            .await;

        assert_eq!(resp.0, 200, "上游 200 必须原样回传");
        assert_eq!(resp.2, b"upstream-ok");

        let seen = seen.lock().await;
        assert_eq!(seen.len(), 1, "上游必须收到恰好一个请求");
        let got = &seen[0];
        assert_eq!(got.method, "POST", "method 透传");
        assert_eq!(got.path, "/base/probe", "path = joinURLPath(目标 path, 入站 path)");
        assert_eq!(got.query, "x=1", "query 透传");
        assert_eq!(got.host, "masq.example.com", "rewrite_host=false → 保留客户端原始 Host");
        assert_eq!(got.body, "hello-body", "body 透传");
    }

    /// `MasqUrlRewriteHost=true` → 上游 Host 头 = 上游 authority（Go
    /// `r.Out.Host = ""` → transport 用 URL.Host）。
    #[tokio::test]
    async fn proxy_rewrites_host_when_rewrite_host_enabled() {
        let (port, seen) = start_recording_upstream().await;
        let handler = ProxyMasqHandler::new(&format!("http://127.0.0.1:{port}/base"), true, false);
        let _ = handler.serve_request(masq_request("GET", "/probe", "masq.example.com", "")).await;
        let seen = seen.lock().await;
        assert_eq!(seen.len(), 1);
        assert_eq!(
            seen[0].host,
            format!("127.0.0.1:{port}"),
            "rewrite_host=true → Host = 上游 authority"
        );
    }

    /// 上游不可达 → 502（Go `ErrorHandler`），不是 503。
    #[tokio::test]
    async fn proxy_upstream_unreachable_returns_502() {
        // 监听后立刻 drop → 端口大概率无监听（连接被拒）
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        let handler = ProxyMasqHandler::new(&format!("http://127.0.0.1:{port}/"), false, false);
        let resp = handler.serve_request(masq_request("GET", "/", "masq.example.com", "")).await;
        assert_eq!(resp.0, 502, "上游不可达 → Go ErrorHandler 的 502");
    }

    /// 上游 URL 非法 → 502（fail-visible；Go 是 Listen 期报错）。
    #[tokio::test]
    async fn proxy_invalid_target_returns_502() {
        let handler = ProxyMasqHandler::new("not-a-url", false, false);
        let resp = handler.serve_request(masq_request("GET", "/", "h", "")).await;
        assert_eq!(resp.0, 502);
    }

    /// Go `joinURLPath` / `rewriteRequestURL` 的 query 拼接语义。
    #[test]
    fn go_path_and_query_join_semantics() {
        assert_eq!(join_url_path("", "/x"), "/x");
        assert_eq!(join_url_path("/base", "/x"), "/base/x");
        assert_eq!(join_url_path("/base/", "/x"), "/base/x");
        assert_eq!(join_url_path("/base", "x"), "/base/x");
        // Go singleJoiningSlash("/base", "") = "/base/"（两侧都无斜杠 → 补一个）
        assert_eq!(join_url_path("/base", ""), "/base/");
        assert_eq!(join_query("", "a=1"), "a=1");
        assert_eq!(join_query("t=1", ""), "t=1");
        assert_eq!(join_query("t=1", "a=1"), "t=1&a=1");
    }

    /// `MasqUrl` 解析（Go `url.Parse` + scheme 分支）。
    #[test]
    fn masq_target_parsing() {
        let t = parse_masq_target("http://example.com:8080/base?x=1").expect("parse");
        assert_eq!(t.scheme, "http");
        assert_eq!(t.host, "example.com");
        assert_eq!(t.port, 8080);
        assert_eq!(t.authority(), "example.com:8080");
        assert_eq!(t.path, "/base");
        assert_eq!(t.query, "x=1");

        let t = parse_masq_target("https://example.com").expect("parse");
        assert_eq!(t.port, 443);
        assert_eq!(t.authority(), "example.com");

        assert!(parse_masq_target("example.com").is_err(), "缺 scheme 必须报错");
        assert!(parse_masq_target("unix:/tmp/s.sock").is_err(), "unix scheme 未实现");
    }

    /// 上游沉默时**不早退**（Go 默认 transport 无响应头超时：`ResponseHeaderTimeout`
    /// 零值 → 一直等；本实现同款，不擅自加超时）。
    #[tokio::test]
    async fn proxy_silent_upstream_does_not_early_return() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        xray_common::testing::spawn("masq-proxy-silent-upstream", async move {
            if let Ok((sock, _)) = listener.accept().await {
                let _ = tokio::time::sleep(Duration::from_secs(30)).await;
                drop(sock);
            }
        });
        let handler = ProxyMasqHandler::new(&format!("http://127.0.0.1:{port}/"), false, false);
        let fut = handler.serve_request(masq_request("GET", "/", "h", ""));
        // 500ms 后仍未返回 = 与 Go 一致（等上游，不早退）
        let pending = tokio::time::timeout(Duration::from_millis(500), fut).await;
        assert!(pending.is_err(), "上游沉默时不得早退（Go 默认 transport 无响应超时）");
    }
}
