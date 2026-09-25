//! ECH 配置的真实 DNS 查询（HTTPS RR / type65）。
//!
//! 对应 Go `transport/internet/tls/ech.go`：
//! - `ApplyECH` client 分支的 `://` 形式拆分（`example.com+https://1.1.1.1/dns-query`）
//! - `QueryRecord`：进程级 TTL 缓存（Go `GlobalECHConfigCache`）
//! - `dnsQuery` 的 DoH 分支：`https://`/`h2c://` → POST（RFC 8484，body 为裸 DNS message），响应交
//!   [`crate::ech_https_rr::extract_ech_and_ttl_from_dns_response`]
//!
//! # 对齐差异（有意为之）
//! - Go 的 EDNS0(4096)+随机 padding 与 `X-Padding` 头是流量指纹混淆项，不 影响正确性（DoH 无 UDP
//!   512B 限制，主流 DoH 对无 EDNS 查询正常回答）。 ponytail: 指纹级对齐需要时再加。
//! - Go `udp://` 经典 UDP 查询：本版明确报错（Go 可成功），待真实需求再补 datagram 路径。
//! - Go `QueryRecord` 的「4h 内旧值+后台刷新」分支：TTL 过期一律同步重查 （无 singleflight
//!   去重，并发 miss 只多打几次 DoH，无正确性影响）。

use std::{
    collections::HashMap,
    sync::{Arc, LazyLock},
    time::{Duration, Instant},
};

use bytes::Bytes;
use h2::client;
use http::{Method, Request, StatusCode, header::CONTENT_TYPE};
use parking_lot::Mutex;
use tokio::{net::TcpStream, time::timeout};
use tokio_rustls::rustls::ClientConfig;
use xray_transport::connection::TcpConnection;

use crate::{
    ech::EchConfigRecord, ech_https_rr::extract_ech_and_ttl_from_dns_response, error::TlsError,
};

/// DoH 单次查询整体超时（对应 Go `http.Client{Timeout: 30s}`）。
const DOH_TIMEOUT: Duration = Duration::from_secs(30);

/// DoH 响应最大字节数（Go `io.ReadAll` 无上限；Rust 防御性上限，同 xray-app-dns）。
const DOH_RECV_MAX: usize = 65535;

/// DoH 查询默认 TLS 配置：系统 roots + ALPN h2。
///
/// ALPN 必须协商 h2：Go 用 `http2.Transport`（强制 h2）。缺 ALPN 时真实
/// DoH server（如 cloudflare-dns.com）回 HTTP/1.1，被 h2 client 当坏 frame
/// 拒绝（"frame with invalid size"）。
static DEFAULT_DOH_TLS_CONFIG: LazyLock<Arc<ClientConfig>> = LazyLock::new(|| {
    let mut cfg = (*crate::utls::default_client_config()).clone();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    Arc::new(cfg)
});

/// 进程级 ECH 配置缓存。对应 Go `GlobalECHConfigCache`
/// （key 为 [`crate::ech::ech_cache_key`] 形态，sockopt 恒 0——Rust 侧 ECH
/// DoH 连接 sockopt 未接线，见 `client_config` 的 echSockopt warn）。
static GLOBAL_ECH_CACHE: LazyLock<Mutex<HashMap<String, EchConfigRecord>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// 解析 `echConfigList` 的 DNS 形式为 `(待查域名, DNS 服务器 URL)`。
///
/// 对齐 Go `ApplyECH`（ech.go `strings.SplitN(c.EchConfigList, "+", 2)`）：
/// - `example.com+https://1.1.1.1/dns-query` → (`example.com`, `https://...`)； 多个 `+` 归入
///   server 段（SplitN limit=2 语义）。
/// - `https://1.1.1.1/dns-query`（单段）→ (`server_name`, server)；`server_name` 为 IP 字面量时（Go
///   `net.ParseAddress(...).IsDomain()` 为 false）无查询名 → 硬错，错误文案对齐 Go。
pub fn parse_ech_dns_server(
    config_list: &str,
    server_name: &str,
) -> Result<(String, String), TlsError> {
    let (name_to_query, dns_server) = match config_list.split_once('+') {
        Some((name, server)) => (name.to_string(), server.to_string()),
        None => {
            let is_domain = server_name.parse::<std::net::IpAddr>().is_err();
            (
                if is_domain { server_name.to_string() } else { String::new() },
                config_list.to_string(),
            )
        },
    };
    if name_to_query.is_empty() {
        return Err(TlsError::EchApply(
            "Using DNS for ECH Config needs serverName or use Server format example.com+https://1.1.1.1/dns-query"
                .to_string(),
        ));
    }
    Ok((name_to_query, dns_server))
}

/// 查询 ECH config（含 TTL 缓存）。对应 Go `QueryRecord(domain, server, sockopt)`。
///
/// - 缓存未过期 → 直接返回（零网络 IO）。
/// - 否则真实查询 [`dns_query_doh`] 并按响应 TTL 回填缓存。
/// - `tls_config`：`https://` 查询的 TLS 配置；`None` 用 [`DEFAULT_DOH_TLS_CONFIG`] （系统 roots +
///   ALPN h2，对应 Go `http2.Transport` + `utls.Config{ServerName}` 默认验证）。测试可注入信任 mock
///   自签证书的 config；注入方需自带 ALPN h2 方可对真实 DoH server 查询。
/// - 查询失败返回 `Err`；调用方（`utls::u_client_with_alpn`）保持原串，由 resolve 落
///   [`crate::ech::INVALID_ECH_CONFIG`]（Go defer 失败语义：ECH 获取失败必须连接失败，不静默明文
///   SNI）。
pub async fn query_ech_config(
    config_list: &str,
    server_name: &str,
    tls_config: Option<Arc<ClientConfig>>,
) -> Result<Vec<u8>, TlsError> {
    let (name, server) = parse_ech_dns_server(config_list, server_name)?;
    let cache_key = crate::ech::ech_cache_key(&server, &name, 0);
    if let Some(rec) = GLOBAL_ECH_CACHE.lock().get(&cache_key) {
        if !rec.is_expired(Instant::now()) {
            tracing::debug!(target: "xray_tls::ech_doh", name = %name, server = %server, "ECH config cache hit");
            return Ok(rec.config.clone());
        }
    }
    let (config, ttl) = dns_query_doh(&server, &name, tls_config).await?;
    GLOBAL_ECH_CACHE.lock().insert(
        cache_key,
        EchConfigRecord {
            config: config.clone(),
            expire: Some(Instant::now() + Duration::from_secs(u64::from(ttl))),
        },
    );
    Ok(config)
}

/// 发送 type65(HTTPS) 查询并提取 ECH config。对应 Go `dnsQuery` 的 DoH 分支。
/// 返回 `(config bytes, ttl)`。
async fn dns_query_doh(
    server: &str,
    name: &str,
    tls_config: Option<Arc<ClientConfig>>,
) -> Result<(Vec<u8>, u32), TlsError> {
    let Some((scheme, rest)) = server.split_once("://") else {
        return Err(TlsError::InvalidEchDnsServerFormat(server.to_string()));
    };
    let use_tls = match scheme {
        "https" => true,
        "h2c" => false,
        _ => {
            return Err(TlsError::InvalidEchDnsServerFormat(format!(
                "{server} (ECH DNS query supports https:// and h2c:// only; udp:// not implemented)"
            )));
        },
    };
    let (host, port, path) = parse_authority(rest)?;

    // wire request：type65(HTTPS) question，`Id=0`（RFC 8484 §4.1；Go `m.Id = 0`）。
    let query_name = hickory_proto::rr::Name::from_utf8(format!("{name}."))
        .map_err(|e| TlsError::EchApply(format!("invalid ECH query name {name}: {e}")))?;
    let mut msg = hickory_proto::op::Message::new(
        0,
        hickory_proto::op::MessageType::Query,
        hickory_proto::op::OpCode::Query,
    );
    msg.add_query(hickory_proto::op::Query::query(
        query_name,
        hickory_proto::rr::RecordType::HTTPS,
    ));
    // EDNS0(4096)：Go `m.SetEdns0(4096, false)`（ech.go dnsQuery）。缺 EDNS 的
    // type65 查询经真实 resolver（实测 dns.google）会 SERVFAIL——非可省项。
    let mut edns = hickory_proto::op::Edns::new();
    edns.set_max_payload(4096);
    edns.set_version(0);
    msg.set_edns(edns);
    let payload = msg.to_vec().map_err(|e| TlsError::EchApply(format!("pack dns query: {e}")))?;

    // TCP 连接（域名字段走系统 resolver，对应 Go net/http 默认行为）。
    let tcp = timeout(DOH_TIMEOUT, TcpStream::connect((host.as_str(), port)))
        .await
        .map_err(|_| TlsError::EchApply(format!("ECH DoH connect timeout: {server}")))?
        .map_err(|e| TlsError::EchApply(format!("ECH DoH connect {host}:{port}: {e}")))?;

    // 完整 URL（scheme://authority/path）：h2 请求需 :authority 伪头——仅 path
    // 时 h2 不发送 authority，真实 DoH server（如 cloudflare）回 400。对齐 Go
    // `http.NewRequest("POST", server, ...)` 的完整 URL 语义。
    let authority =
        if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") };
    let url = format!("{}://{authority}{path}", if use_tls { "https" } else { "http" });

    let wire = if use_tls {
        let tls_cfg = tls_config.unwrap_or_else(|| Arc::clone(&DEFAULT_DOH_TLS_CONFIG));
        let stream = crate::utls::client(TcpConnection::new(tcp), &host, tls_cfg)
            .await
            .map_err(|e| TlsError::EchApply(format!("ECH DoH tls handshake: {e}")))?;
        doh_post(stream, &url, payload).await?
    } else {
        doh_post(TcpConnection::new(tcp), &url, payload).await?
    };
    extract_ech_and_ttl_from_dns_response(&wire, name).map_err(|e| {
        // 失败携带响应 wire 摘要（head 256B hex）：真实 DoH server 的 RR 形态
        // 多样（param 顺序/未知 param/压缩指针），无上下文的 NoEchConfig 无法定位。
        let head: String = wire.iter().take(256).map(|b| format!("{b:02x}")).collect();
        TlsError::EchApply(format!(
            "parse ECH from DNS response ({e}; wire {} bytes: {head})",
            wire.len()
        ))
    })
}

/// 拆 DoH URL 的 `host[:port][/path]`。
///
/// 默认端口 443；无路径时请求 `/`（Go `URL.RequestURI()` 对空 path 的行为）。
/// 支持 IPv6 方括号形态 `[h]:p`。
fn parse_authority(rest: &str) -> Result<(String, u16, String), TlsError> {
    const DEFAULT_PORT: u16 = 443;
    let (authority, path) = match rest.split_once('/') {
        Some((a, p)) => (a, format!("/{p}")),
        None => (rest, "/".to_string()),
    };
    let (host, port) = if let Some(idx) = authority.find(']') {
        // IPv6：[h] 或 [h]:p
        let host = authority[1..idx].to_string();
        let port = authority[idx + 1..]
            .strip_prefix(':')
            .map(|p| p.parse::<u16>())
            .transpose()
            .map_err(|_| TlsError::InvalidEchDnsServerFormat(authority.to_string()))?
            .unwrap_or(DEFAULT_PORT);
        (host, port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => {
                let port = p
                    .parse::<u16>()
                    .map_err(|_| TlsError::InvalidEchDnsServerFormat(authority.to_string()))?;
                (h.to_string(), port)
            },
            None => (authority.to_string(), DEFAULT_PORT),
        }
    };
    if host.is_empty() {
        return Err(TlsError::InvalidEchDnsServerFormat(format!("//{rest}")));
    }
    Ok((host, port, path))
}

/// h2 POST：发 DNS query，收完整响应 body（RFC 8484 裸 DNS message）。
///
/// `url` 为完整 URL（scheme://authority/path），供 h2 生成 `:authority` 伪头。
async fn doh_post<S>(io: S, url: &str, payload: Vec<u8>) -> Result<Vec<u8>, TlsError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (send_request, conn) = timeout(DOH_TIMEOUT, client::handshake(io))
        .await
        .map_err(|_| TlsError::EchApply("ECH DoH h2 handshake timeout".to_string()))?
        .map_err(|e| TlsError::EchApply(format!("ECH DoH h2 handshake: {e}")))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let mut ready = timeout(DOH_TIMEOUT, send_request.ready())
        .await
        .map_err(|_| TlsError::EchApply("ECH DoH h2 ready timeout".to_string()))?
        .map_err(|e| TlsError::EchApply(format!("ECH DoH h2 ready: {e}")))?;

    let request = Request::builder()
        .method(Method::POST)
        .uri(url)
        .header(CONTENT_TYPE, "application/dns-message")
        .header(http::header::ACCEPT, "application/dns-message")
        .header(http::header::CONTENT_LENGTH, payload.len())
        .body(())
        .map_err(|e| TlsError::EchApply(format!("build DoH request: {e}")))?;
    let (response, mut send_stream) = ready
        .send_request(request, false)
        .map_err(|e| TlsError::EchApply(format!("DoH send_request: {e}")))?;
    send_stream
        .send_data(Bytes::from(payload), true)
        .map_err(|e| TlsError::EchApply(format!("DoH send_data: {e}")))?;

    let response = timeout(DOH_TIMEOUT, response)
        .await
        .map_err(|_| TlsError::EchApply("ECH DoH response timeout".to_string()))?
        .map_err(|e| TlsError::EchApply(format!("DoH response: {e}")))?;
    if response.status() != StatusCode::OK {
        return Err(TlsError::EchApply(format!(
            "query failed with response code: {}",
            response.status().as_u16()
        )));
    }

    let mut body = response.into_body();
    let mut buf = Vec::new();
    loop {
        match timeout(DOH_TIMEOUT, body.data()).await {
            Ok(Some(chunk)) => {
                let chunk = chunk.map_err(|e| TlsError::EchApply(format!("DoH body: {e}")))?;
                buf.extend_from_slice(&chunk);
                if buf.len() > DOH_RECV_MAX {
                    return Err(TlsError::EchApply(format!(
                        "DoH response too large: {}",
                        buf.len()
                    )));
                }
            },
            Ok(None) => break,
            Err(_) => return Err(TlsError::EchApply("DoH body read timeout".to_string())),
        }
    }
    if buf.is_empty() {
        return Err(TlsError::EchApply("DoH empty response body".to_string()));
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use std::{
        net::SocketAddr,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use hickory_proto::{
        op::{Message, MessageType, OpCode},
        rr::{
            Name, RData, Record,
            rdata::{
                HTTPS,
                svcb::{EchConfigList, SVCB, SvcParamKey, SvcParamValue},
            },
        },
    };
    use tokio::net::TcpListener;

    use super::*;

    // ---- parse_ech_dns_server（Go ApplyECH 拆分语义） ----

    #[test]
    fn parse_single_segment_defaults_to_server_name() {
        let got = parse_ech_dns_server("https://1.1.1.1/dns-query", "example.com").unwrap();
        assert_eq!(got, ("example.com".to_string(), "https://1.1.1.1/dns-query".to_string()));
    }

    #[test]
    fn parse_plus_format_splits_domain_and_server() {
        let got = parse_ech_dns_server("example.com+https://1.1.1.1/dns-query", "ignored.invalid")
            .unwrap();
        assert_eq!(got, ("example.com".to_string(), "https://1.1.1.1/dns-query".to_string()));
    }

    #[test]
    fn parse_second_plus_belongs_to_server_segment() {
        // Go SplitN(list, "+", 2)：第二个 + 归入 server 段。
        let got = parse_ech_dns_server("a.com+https://x/q+extra", "sni.invalid").unwrap();
        assert_eq!(got, ("a.com".to_string(), "https://x/q+extra".to_string()));
    }

    #[test]
    fn parse_ip_server_name_without_plus_hard_errors() {
        // Go：nameToQuery 为空 → 硬错（SNI 是 IP 且无 + 前缀段）。
        let err = parse_ech_dns_server("https://1.1.1.1/dns-query", "8.8.8.8").unwrap_err();
        assert!(err.to_string().contains("needs serverName"), "got: {err}");
        // 域名 SNI 单段 → 正常。
        let got = parse_ech_dns_server("h2c://doh.internal", "cloudflare.com").unwrap();
        assert_eq!(got.0, "cloudflare.com");
    }

    // ---- parse_authority ----

    #[test]
    fn authority_defaults_port_and_path() {
        assert_eq!(parse_authority("1.1.1.1").unwrap(), ("1.1.1.1".into(), 443, "/".into()));
        assert_eq!(
            parse_authority("dns.google:8443/dns-query").unwrap(),
            ("dns.google".into(), 8443, "/dns-query".into())
        );
        assert_eq!(
            parse_authority("[2606:4700::1]:53/x").unwrap(),
            ("2606:4700::1".into(), 53, "/x".into())
        );
        assert!(parse_authority(":9999").is_err());
    }

    // ---- 端到端：mock DoH server ----

    fn ensure_crypto_provider() {
        xray_common::ensure_default_crypto_provider();
    }

    /// 构造带 ECH SvcParam 的 HTTPS RR DNS response。
    fn https_rr_response(req_id: u16, fqdn: &str, ech: Vec<u8>, ttl: u32) -> Vec<u8> {
        let owner = Name::from_ascii(fqdn).unwrap();
        let svcb = SVCB::new(
            1,
            Name::from_ascii(".").unwrap(),
            vec![(SvcParamKey::EchConfigList, SvcParamValue::EchConfigList(EchConfigList(ech)))],
        );
        let mut msg = Message::new(req_id, MessageType::Response, OpCode::Query);
        msg.add_answer(Record::from_rdata(owner, ttl, RData::HTTPS(HTTPS(svcb))));
        msg.to_vec().unwrap()
    }

    /// h2c（明文 HTTP/2）mock DoH server：每个连接独立任务，应答任意多个请求；
    /// 返回地址 + 已 accept 连接数（缓存测试用）。
    async fn spawn_mock_h2c_doh(
        fqdn: String,
        ech: Vec<u8>,
        ttl: u32,
    ) -> (SocketAddr, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let conn_count = Arc::new(AtomicUsize::new(0));
        let count = conn_count.clone();
        tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else { break };
                count.fetch_add(1, Ordering::SeqCst);
                let fqdn = fqdn.clone();
                let ech = ech.clone();
                tokio::spawn(async move {
                    let mut h2_conn = match h2::server::handshake(sock).await {
                        Ok(c) => c,
                        Err(_) => return,
                    };
                    while let Some(Ok((req, mut respond))) = h2_conn.accept().await {
                        let mut body = req.into_body();
                        let mut q = Vec::new();
                        while let Some(chunk) = body.data().await {
                            q.extend_from_slice(&chunk.unwrap());
                        }
                        let query_msg = match Message::from_vec(&q) {
                            Ok(m) => m,
                            Err(_) => return,
                        };
                        let resp_payload =
                            https_rr_response(query_msg.metadata.id, &fqdn, ech.clone(), ttl);
                        let resp = http::Response::builder()
                            .status(StatusCode::OK)
                            .header(CONTENT_TYPE, "application/dns-message")
                            .body(())
                            .unwrap();
                        let mut send = match respond.send_response(resp, false) {
                            Ok(s) => s,
                            Err(_) => return,
                        };
                        if send.send_data(Bytes::from(resp_payload), true).is_err() {
                            return;
                        }
                    }
                });
            }
        });
        (addr, conn_count)
    }

    #[tokio::test]
    async fn query_via_h2c_doh_returns_ech_config() {
        let ech = vec![0xde, 0xad, 0xbe, 0xef];
        let (addr, _count) =
            spawn_mock_h2c_doh("query-ech.example.com.".into(), ech.clone(), 600).await;
        let got = query_ech_config(
            &format!("query-ech.example.com+h2c://{addr}"),
            "unused.invalid",
            None,
        )
        .await
        .unwrap();
        assert_eq!(got, ech, "DoH 响应中的 ECH bytes 必须原样透传");
    }

    #[tokio::test]
    async fn second_query_hits_cache_without_new_connection() {
        let ech = vec![0x01, 0x02, 0x03];
        let (addr, count) =
            spawn_mock_h2c_doh("cached-ech.example.com.".into(), ech.clone(), 600).await;
        let url = format!("cached-ech.example.com+h2c://{addr}");
        let first = query_ech_config(&url, "unused.invalid", None).await.unwrap();
        assert_eq!(first, ech);
        assert_eq!(count.load(Ordering::SeqCst), 1);
        let second = query_ech_config(&url, "unused.invalid", None).await.unwrap();
        assert_eq!(second, ech);
        assert_eq!(count.load(Ordering::SeqCst), 1, "第二次查询必须走缓存（不新建连接）");
    }

    #[tokio::test]
    async fn refused_connection_yields_err() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let got = query_ech_config(
            &format!("refused.example.com+https://{addr}"),
            "unused.invalid",
            None,
        )
        .await;
        assert!(got.is_err(), "连接拒绝必须报错（不得静默返回垃圾 config）");
    }

    #[tokio::test]
    async fn unsupported_scheme_yields_err() {
        let got = query_ech_config("q.example.com+udp://8.8.8.8", "unused.invalid", None).await;
        let err = got.unwrap_err();
        assert!(matches!(err, TlsError::InvalidEchDnsServerFormat(_)), "got: {err:?}");
    }

    /// `https://` 分支：真实 TLS 握手（自签证书 + 注入信任根）→ DoH 查询。
    #[tokio::test]
    async fn query_via_https_doh_with_self_signed_mock() {
        use tokio_rustls::{
            TlsAcceptor,
            rustls::{RootCertStore, ServerConfig, pki_types::CertificateDer},
        };

        ensure_crypto_provider();

        // rcgen 自签证书（SAN: localhost；client 以 host=localhost 连接）。
        let cert_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = cert_params.self_signed(&key_pair).unwrap();
        let cert_der = cert.der().to_vec();
        let key_der = key_pair.serialize_der();
        let key = tokio_rustls::rustls::pki_types::PrivateKeyDer::try_from(key_der).unwrap();
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![CertificateDer::from(cert_der.clone())], key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let ech = vec![0x5a, 0x5a];
        let ech_expected = ech.clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else { break };
                let acceptor = acceptor.clone();
                let ech_inner = ech.clone();
                tokio::spawn(async move {
                    let tls = match acceptor.accept(sock).await {
                        Ok(t) => t,
                        Err(_) => return,
                    };
                    let mut h2_conn = match h2::server::handshake(tls).await {
                        Ok(c) => c,
                        Err(_) => return,
                    };
                    while let Some(Ok((req, mut respond))) = h2_conn.accept().await {
                        let mut body = req.into_body();
                        let mut q = Vec::new();
                        while let Some(chunk) = body.data().await {
                            q.extend_from_slice(&chunk.unwrap());
                        }
                        let query_msg = match Message::from_vec(&q) {
                            Ok(m) => m,
                            Err(_) => return,
                        };
                        let payload = https_rr_response(
                            query_msg.metadata.id,
                            "tls-ech.example.com.",
                            ech_inner.clone(),
                            300,
                        );
                        let resp = http::Response::builder()
                            .status(StatusCode::OK)
                            .header(CONTENT_TYPE, "application/dns-message")
                            .body(())
                            .unwrap();
                        let mut send = match respond.send_response(resp, false) {
                            Ok(s) => s,
                            Err(_) => return,
                        };
                        if send.send_data(Bytes::from(payload), true).is_err() {
                            return;
                        }
                    }
                });
            }
        });

        // client：信任自签根的 rustls config。
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(cert_der)).unwrap();
        let tls_config = Arc::new(
            tokio_rustls::rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );

        // 缓存 key 含 server URL（含随机端口），与其他测试天然隔离。
        let got = query_ech_config(
            &format!("tls-ech.example.com+https://localhost:{}/dns-query", addr.port()),
            "unused.invalid",
            Some(tls_config),
        )
        .await
        .unwrap();
        assert_eq!(got, ech_expected, "https:// 分支必须完成 TLS 握手并拿到 ECH config");
    }
}
