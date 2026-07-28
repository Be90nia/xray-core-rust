//! DoH (DNS over HTTPS) nameserver。对应 Go `app/dns/nameserver_doh.go`。
//!
//! ## 实现
//!
//! - `tokio::net::TcpStream` → `xray_tls::client` TLS 握手 → `h2::client::handshake` → POST /dns-query。
//! - DNS wire format 由 `hickory-proto` 处理，body 为裸 DNS message（无 2B 长度前缀，HTTP/2 自带 framing）。
//! - RFC 8484：POST + Content-Type: application/dns-message。
//! - 默认端口 443。
//! - 自动接入 cache（实现 `CachedNameserver`）。
//!
//! ## 跳过范围
//!
//! - 走 Xray routing/dispatcher 出口（直接用 tokio socket + xray_tls + h2）
//! - 长连接复用（每次查询都新 h2 连接；ponytail：连接池可后续加）

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use hickory_proto::rr::RecordType;
use h2::client;
use h2::server;
use http::header::CONTENT_TYPE;
use http::{Method, Request, Response, StatusCode};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::rustls::ClientConfig;

use xray_common::net::address::Address;
use xray_tls::utls::client as tls_client;
use xray_transport::connection::TcpConnection;

use crate::cache_controller::CacheController;
use crate::config::IpOption;
use crate::dnscommon::{
    build_dns_query, parse_dns_response, parsed_to_ip_record, AtomicReqIdGen, IpRecord, ReqIdGen,
};
use crate::error::DnsError;
use crate::nameserver::cached::{query_ip, CachedNameserver, QueryOutcome};
use crate::nameserver::{NameServerConfig, Server};

/// DoH 响应最大字节数。
const DOH_RECV_MAX: usize = 65535;

/// DoH 默认 URL 路径（RFC 8484）。
const DEFAULT_DOH_PATH: &str = "/dns-query";

/// DoH DNS nameserver。
///
/// 结构与 `DotNameServer` 对称，区别：TLS 之上多一层 HTTP/2。
pub struct DohNameServer {
    /// 服务名。
    name: String,
    /// 远端 DNS 服务器地址。
    addr: SocketAddr,
    /// TLS SNI（ServerName）。
    server_name: String,
    /// TLS 客户端配置。
    tls_config: Arc<ClientConfig>,
    /// DoH URL 路径（默认 `/dns-query`）。
    url_path: String,
    /// 缓存控制器。
    cache: Arc<CacheController>,
    /// EDNS0 client subnet。
    client_ip: Vec<u8>,
    /// 单次查询超时。
    query_timeout: Duration,
    /// 请求 ID 生成器。
    id_gen: AtomicReqIdGen,
}

impl DohNameServer {
    /// 构造。
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        addr: SocketAddr,
        server_name: String,
        tls_config: Arc<ClientConfig>,
        cache: Arc<CacheController>,
        client_ip: Vec<u8>,
        query_timeout: Duration,
    ) -> Self {
        let name = format!("DoH:{}", addr);
        Self {
            name,
            addr,
            server_name,
            tls_config,
            url_path: DEFAULT_DOH_PATH.to_string(),
            cache,
            client_ip,
            query_timeout,
            id_gen: AtomicReqIdGen::new(),
        }
    }

    /// 从 `NameServerConfig` 构造。
    pub fn from_config(
        ns: &NameServerConfig,
        server_name: String,
        tls_config: Arc<ClientConfig>,
    ) -> Result<Box<dyn Server>, DnsError> {
        let socket_addr = match &ns.address {
            Address::IPv4(v) => SocketAddr::new(IpAddr::V4(*v), ns.port),
            Address::IPv6(v) => SocketAddr::new(IpAddr::V6(*v), ns.port),
            other => {
                return Err(DnsError::WireFormat(format!(
                    "doh nameserver requires IP address, got: {other:?}"
                )));
            }
        };
        let timeout_dur = if ns.timeout_ms > 0 {
            Duration::from_millis(u64::from(ns.timeout_ms))
        } else {
            Duration::from_millis(4000)
        };
        let cache = Arc::new(CacheController::new(
            format!("DoH:{}", socket_addr),
            ns.disable_cache.unwrap_or(false),
            ns.serve_stale.unwrap_or(false),
            ns.serve_expired_ttl.unwrap_or(0),
        ));
        Ok(Box::new(Self::new(
            socket_addr,
            server_name,
            tls_config,
            cache,
            ns.client_ip.clone(),
            timeout_dur,
        )))
    }

    /// 发送单次 DNS 查询（DoH），等待响应。
    async fn query_once(
        &self,
        fqdn: &str,
        record_type: RecordType,
    ) -> Result<IpRecord, DnsError> {
        let req_id = self.id_gen.next_id();
        let payload = build_dns_query(fqdn, record_type, req_id, &self.client_ip)?;

        // TCP connect。
        let tcp = timeout(self.query_timeout, TcpStream::connect(self.addr))
            .await
            .map_err(|_| {
                DnsError::WireFormat(format!(
                    "doh connect timeout after {:?}",
                    self.query_timeout
                ))
            })?
            .map_err(|e| DnsError::WireFormat(format!("doh connect: {e}")))?;

        // TLS 握手。
        let tls_stream = timeout(
            self.query_timeout,
            tls_client(
                TcpConnection::new(tcp),
                &self.server_name,
                Arc::clone(&self.tls_config),
            ),
        )
        .await
        .map_err(|_| DnsError::WireFormat("doh tls handshake timeout".to_string()))?
        .map_err(|e| DnsError::WireFormat(format!("doh tls handshake: {e}")))?;

        // HTTP/2 handshake。
        let (mut h2, h2_conn) = timeout(self.query_timeout, client::handshake(tls_stream))
            .await
            .map_err(|_| DnsError::WireFormat("doh h2 handshake timeout".to_string()))?
            .map_err(|e| DnsError::WireFormat(format!("doh h2 handshake: {e}")))?;
        tokio::spawn(async move {
            let _ = h2_conn.await;
        });

        // 等待 h2 连接 ready（ready 消费 self 后返回 ready 态的 SendRequest）。
        h2 = timeout(self.query_timeout, h2.ready())
            .await
            .map_err(|_| DnsError::WireFormat("doh h2 ready timeout".to_string()))?
            .map_err(|e| DnsError::WireFormat(format!("doh h2 ready: {e}")))?;

        // POST /dns-query + Content-Type: application/dns-message
        let request = Request::builder()
            .method(Method::POST)
            .uri(&self.url_path)
            .header(CONTENT_TYPE, "application/dns-message")
            .body(())
            .map_err(|e| DnsError::WireFormat(format!("doh build request: {e}")))?;

        let (resp_future, mut send_stream) = h2
            .send_request(request, false)
            .map_err(|e| DnsError::WireFormat(format!("doh send_request: {e}")))?;

        // 发送 DNS query body + end_of_stream。
        send_stream
            .send_data(Bytes::from(payload), true)
            .map_err(|e| DnsError::WireFormat(format!("doh send_data: {e}")))?;

        // 读 HTTP 响应。
        let response = timeout(self.query_timeout, resp_future)
            .await
            .map_err(|_| DnsError::WireFormat("doh response timeout".to_string()))?
            .map_err(|e| DnsError::WireFormat(format!("doh response: {e}")))?;

        if response.status() != StatusCode::OK {
            return Err(DnsError::WireFormat(format!(
                "doh http status: {}",
                response.status()
            )));
        }

        // 读 body（DNS wire format，无长度前缀）。
        let mut body = response.into_body();
        let mut buf = Vec::new();
        loop {
            match timeout(self.query_timeout, body.data()).await {
                Ok(Some(chunk)) => {
                    let chunk = chunk.map_err(|e| DnsError::WireFormat(format!("doh body: {e}")))?;
                    buf.extend_from_slice(&chunk);
                    if buf.len() > DOH_RECV_MAX {
                        return Err(DnsError::WireFormat(format!(
                            "doh response too large: {}",
                            buf.len()
                        )));
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    return Err(DnsError::WireFormat(
                        "doh body read timeout".to_string(),
                    ));
                }
            }
        }

        if buf.is_empty() {
            return Err(DnsError::WireFormat("doh empty response body".to_string()));
        }

        let now = Instant::now();
        let parsed = parse_dns_response(&buf, req_id, record_type, now)?;
        Ok(parsed_to_ip_record(&parsed, now))
    }
}

impl CachedNameserver for DohNameServer {
    fn cache_controller(&self) -> &CacheController {
        &self.cache
    }

    async fn send_query(&self, fqdn: &str, option: IpOption) -> QueryOutcome {
        let mut outcome = QueryOutcome::default();

        if option.ipv4_enable {
            match self.query_once(fqdn, RecordType::A).await {
                Ok(rec) => outcome.rec_v4 = Some(rec),
                Err(e) => outcome.errors.push(e),
            }
        }
        if option.ipv6_enable {
            match self.query_once(fqdn, RecordType::AAAA).await {
                Ok(rec) => outcome.rec_v6 = Some(rec),
                Err(e) => outcome.errors.push(e),
            }
        }

        outcome
    }
}

impl Server for DohNameServer {
    fn name(&self) -> &str {
        &self.name
    }

    fn is_disable_cache(&self) -> bool {
        self.cache.disable_cache
    }

    fn query_ip<'a>(
        &'a self,
        domain: &'a str,
        option: IpOption,
    ) -> Pin<Box<dyn Future<Output = Result<(Vec<IpAddr>, u32), DnsError>> + Send + 'a>> {
        Box::pin(query_ip(self, domain, option))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::IpOption;
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use std::net::Ipv4Addr;
    use tokio::net::TcpListener;
    use tokio_rustls::rustls::ServerConfig;
    use tokio_rustls::TlsAcceptor;
    use xray_transport::connection::TcpConnection;

    /// 确保 rustls CryptoProvider 在并行测试中只初始化一次
    fn ensure_crypto_provider() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| { let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default(); });
    }

    fn make_a_response(req_id: u16, fqdn: &str, ips: Vec<Ipv4Addr>, ttl: u32) -> Vec<u8> {
        let name = Name::parse(fqdn, None).unwrap();
        let mut msg = Message::new(req_id, MessageType::Response, OpCode::Query);
        msg.add_query(Query::query(name.clone(), RecordType::A));
        for ip in ips {
            let rec = Record::from_rdata(name.clone(), ttl, RData::A(hickory_proto::rr::rdata::A(ip)));
            msg.add_answer(rec);
        }
        msg.to_vec().unwrap()
    }

    /// 启动 mock DoH server：自签 TLS + h2 server + accept 一次 + 回 DNS 响应。
    async fn spawn_mock_doh_server(
        fqdn: &str,
        ips: Vec<Ipv4Addr>,
        ttl: u32,
    ) -> (
        SocketAddr,
        Arc<ClientConfig>,
        tokio::task::JoinHandle<()>,
    ) {
        ensure_crypto_provider();
        // rcgen 自签证书（SAN: localhost）。
        let cert_params =
            rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = cert_params.self_signed(&key_pair).unwrap();
        let cert_der = cert.der().to_vec();
        let key_der = key_pair.serialize_der();

        // rustls server config。
        let key = tokio_rustls::rustls::pki_types::PrivateKeyDer::try_from(key_der).unwrap();
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![tokio_rustls::rustls::pki_types::CertificateDer::from(
                    cert_der.clone(),
                )],
                key,
            )
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let fqdn_owned = fqdn.to_string();

        let handle = tokio::spawn(async move {
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
                let resp_payload = make_a_response(
                    query_msg.metadata.id,
                    &fqdn_owned,
                    ips.clone(),
                    ttl,
                );

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
        root_store
            .add(tokio_rustls::rustls::pki_types::CertificateDer::from(
                cert_der,
            ))
            .unwrap();
        let client_config = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth(),
        );

        (addr, client_config, handle)
    }

    #[tokio::test]
    async fn doh_query_once_returns_a_record() {
        let (addr, tls_config, _h) =
            spawn_mock_doh_server("example.com.", vec![Ipv4Addr::new(10, 0, 0, 1)], 120).await;

        let ns = DohNameServer::new(
            addr,
            "localhost".to_string(),
            tls_config,
            Arc::new(CacheController::new("test", true, false, 0)),
            Vec::new(),
            Duration::from_secs(5),
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
            addr,
            "localhost".to_string(),
            tls_config,
            Arc::new(CacheController::new("test", true, false, 0)),
            Vec::new(),
            Duration::from_secs(5),
        );
        let outcome = ns
            .send_query(
                "z.com.",
                IpOption {
                    ipv4_enable: true,
                    ipv6_enable: false,
                    fake_enable: false,
                },
            )
            .await;
        assert!(outcome.rec_v4.is_some());
        assert!(outcome.rec_v6.is_none());
        assert!(outcome.errors.is_empty());
    }

    #[tokio::test]
    async fn doh_query_http_status_error() {
        ensure_crypto_provider();
        let cert_params =
            rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = cert_params.self_signed(&key_pair).unwrap();
        let cert_der = cert.der().to_vec();
        let key_der = key_pair.serialize_der();

        let key = tokio_rustls::rustls::pki_types::PrivateKeyDer::try_from(key_der).unwrap();
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![tokio_rustls::rustls::pki_types::CertificateDer::from(
                    cert_der.clone(),
                )],
                key,
            )
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
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
                let resp = Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(())
                    .unwrap();
                let mut send = respond.send_response(resp, false).unwrap();
                send.send_data(Bytes::new(), true).unwrap();
            }
        });

        let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
        root_store
            .add(tokio_rustls::rustls::pki_types::CertificateDer::from(
                cert_der,
            ))
            .unwrap();
        let tls_config = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth(),
        );

        let ns = DohNameServer::new(
            addr,
            "localhost".to_string(),
            tls_config,
            Arc::new(CacheController::new("test", true, false, 0)),
            Vec::new(),
            Duration::from_secs(5),
        );
        let result = ns.query_once("bad.com.", RecordType::A).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("http status"),
            "expected http status error, got: {err}"
        );
    }
}
