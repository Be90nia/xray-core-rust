//! DNS-over-QUIC (DoQ) nameserver。对应 Go `app/dns/nameserver_quic.go`。
//!
//! ## 实现
//!
//! - quinn QUIC endpoint → connect → open_bi → 2B len prefix + DNS wire format（与 DoT 一致）。
//! - ALPN: `doq`（RFC 9250）。
//! - 默认端口 853。
//! - 自动接入 cache（实现 `CachedNameserver`）。
//!
//! ## 跳过范围
//!
//! - 走 Xray routing/dispatcher 出口（直接用 quinn）
//! - 长连接/endpoint 复用（每次查询都新 endpoint+connection；ponytail：可后续加池化）

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::rr::RecordType;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig as QuinnClientConfig, Endpoint, ServerConfig as QuinnServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use tokio_rustls::rustls::ClientConfig;

use xray_common::net::address::Address;

use crate::cache_controller::CacheController;
use crate::config::IpOption;
use crate::dnscommon::{
    build_dns_query, parse_dns_response, parsed_to_ip_record, AtomicReqIdGen, IpRecord, ReqIdGen,
};
use crate::error::DnsError;
use crate::nameserver::cached::{query_ip, CachedNameserver, QueryOutcome};
use crate::nameserver::{NameServerConfig, Server};

/// DoQ 单次响应最大字节数。
const DOQ_RECV_MAX: usize = 65535;

/// DoQ ALPN 协议标识（RFC 9250）。
const DOQ_ALPN: &[u8] = b"doq";

/// DoQ DNS nameserver。
///
/// 结构与 `DotNameServer` 对称，区别：QUIC transport（quinn）替代 TCP+TLS。
pub struct DoqNameServer {
    name: String,
    addr: SocketAddr,
    server_name: String,
    tls_config: Arc<ClientConfig>,
    cache: Arc<CacheController>,
    client_ip: Vec<u8>,
    query_timeout: Duration,
    id_gen: AtomicReqIdGen,
}

impl DoqNameServer {
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
        let name = format!("DoQ:{}", addr);
        Self {
            name,
            addr,
            server_name,
            tls_config,
            cache,
            client_ip,
            query_timeout,
            id_gen: AtomicReqIdGen::new(),
        }
    }

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
                    "doq nameserver requires IP address, got: {other:?}"
                )));
            }
        };
        let timeout_dur = if ns.timeout_ms > 0 {
            Duration::from_millis(u64::from(ns.timeout_ms))
        } else {
            Duration::from_millis(4000)
        };
        let cache = Arc::new(CacheController::new(
            format!("DoQ:{}", socket_addr),
            ns.disable_cache.unwrap_or(false),
            ns.serve_stale.unwrap_or(false),
            ns.serve_expired_ttl.unwrap_or(0),
            ns.negative_ttl_secs.unwrap_or(0),
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

    /// 从 rustls ClientConfig 构造 quinn ClientConfig（加 ALPN doq）。
    fn make_quinn_client_config(&self) -> Result<QuinnClientConfig, DnsError> {
        let mut tls = (*self.tls_config).clone();
        tls.alpn_protocols = vec![DOQ_ALPN.to_vec()];
        let quic = QuicClientConfig::try_from(Arc::new(tls))
            .map_err(|e| DnsError::WireFormat(format!("quinn QuicClientConfig: {e}")))?;
        Ok(QuinnClientConfig::new(Arc::new(quic)))
    }

    /// 创建 quinn client endpoint，bind 地址匹配 target 的 IP 族。
    fn make_client_endpoint(&self) -> Result<Endpoint, DnsError> {
        let bind_addr: SocketAddr = if self.addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        }
        .parse()
        .map_err(|e| DnsError::WireFormat(format!("parse bind addr: {e}")))?;

        let mut endpoint = Endpoint::client(bind_addr)
            .map_err(|e| DnsError::WireFormat(format!("quinn endpoint: {e}")))?;
        endpoint.set_default_client_config(self.make_quinn_client_config()?);
        Ok(endpoint)
    }

    async fn query_once(
        &self,
        fqdn: &str,
        record_type: RecordType,
    ) -> Result<IpRecord, DnsError> {
        let req_id = self.id_gen.next_id();
        let payload = build_dns_query(fqdn, record_type, req_id, &self.client_ip)?;

        let len_be = u16::try_from(payload.len())
            .map_err(|_| DnsError::WireFormat("query too large for DoQ".to_string()))?
            .to_be_bytes();

        let endpoint = self.make_client_endpoint()?;

        // QUIC connect。
        let connect_fut = endpoint
            .connect(self.addr, &self.server_name)
            .map_err(|e| DnsError::WireFormat(format!("doq connect initiate: {e}")))?;
        let conn = timeout(self.query_timeout, connect_fut)
            .await
            .map_err(|_| {
                DnsError::WireFormat(format!(
                    "doq connect timeout after {:?}",
                    self.query_timeout
                ))
            })?
            .map_err(|e| DnsError::WireFormat(format!("doq connect: {e}")))?;

        // open bidirectional stream。
        let (mut send, mut recv) = timeout(self.query_timeout, conn.open_bi())
            .await
            .map_err(|_| DnsError::WireFormat("doq open_bi timeout".to_string()))?
            .map_err(|e| DnsError::WireFormat(format!("doq open_bi: {e}")))?;

        // 写 2B 长度前缀 + payload。
        send.write_all(&len_be)
            .await
            .map_err(|e| DnsError::WireFormat(format!("doq write len: {e}")))?;
        send.write_all(&payload)
            .await
            .map_err(|e| DnsError::WireFormat(format!("doq write payload: {e}")))?;
        send.finish()
            .map_err(|e| DnsError::WireFormat(format!("doq finish send: {e}")))?;

        // 读 2 字节长度前缀。
        let mut len_buf = [0u8; 2];
        timeout(self.query_timeout, recv.read_exact(&mut len_buf))
            .await
            .map_err(|_| DnsError::WireFormat("doq read len timeout".to_string()))?
            .map_err(|e| DnsError::WireFormat(format!("doq read len: {e:?}")))?;
        let resp_len = usize::from(u16::from_be_bytes(len_buf));
        if resp_len == 0 || resp_len > DOQ_RECV_MAX {
            return Err(DnsError::WireFormat(format!(
                "invalid doq response length: {resp_len}"
            )));
        }

        // 读响应 payload。
        let mut buf = vec![0u8; resp_len];
        timeout(self.query_timeout, recv.read_exact(&mut buf))
            .await
            .map_err(|_| DnsError::WireFormat("doq read payload timeout".to_string()))?
            .map_err(|e| DnsError::WireFormat(format!("doq read payload: {e}")))?;

        let now = Instant::now();
        let parsed = parse_dns_response(&buf, req_id, record_type, now)?;
        Ok(parsed_to_ip_record(&parsed, now))
    }
}

impl CachedNameserver for DoqNameServer {
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

impl Server for DoqNameServer {
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

/// 构造 DoQ nameserver。
pub fn new_quic_name_server(
    ns: &NameServerConfig,
    server_name: String,
    tls_config: Arc<ClientConfig>,
) -> Result<Box<dyn Server>, DnsError> {
    DoqNameServer::from_config(ns, server_name, tls_config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::IpOption;
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use std::net::Ipv4Addr;
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

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
            let rec = Record::from_rdata(
                name.clone(),
                ttl,
                RData::A(hickory_proto::rr::rdata::A(ip)),
            );
            msg.add_answer(rec);
        }
        msg.to_vec().unwrap()
    }

    /// 启动 mock DoQ server：自签 TLS + ALPN doq + accept 一次连接 + 回一个预设 DNS 响应。
    async fn spawn_mock_doq_server(
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

        // rustls server config + ALPN doq。
        let key = PrivateKeyDer::try_from(key_der).unwrap();
        let mut server_config = tokio_rustls::rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![CertificateDer::from(cert_der.clone())], key)
            .unwrap();
        server_config.alpn_protocols = vec![DOQ_ALPN.to_vec()];

        let quic_server_config = QuicServerConfig::try_from(Arc::new(server_config)).unwrap();
        let quinn_server_config =
            QuinnServerConfig::with_crypto(Arc::new(quic_server_config));

        let endpoint =
            Endpoint::server(quinn_server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();
        let fqdn_owned = fqdn.to_string();

        let handle = tokio::spawn(async move {
            if let Some(incoming) = endpoint.accept().await {
                let conn = match incoming.await {
                    Ok(c) => c,
                    Err(_) => return,
                };
                let (mut send, mut recv) = match conn.accept_bi().await {
                    Ok(s) => s,
                    Err(_) => return,
                };

                let mut len_buf = [0u8; 2];
                if recv.read_exact(&mut len_buf).await.is_err() { return; }
                let plen = usize::from(u16::from_be_bytes(len_buf));
                let mut buf = vec![0u8; plen];
                if recv.read_exact(&mut buf).await.is_err() { return; }

                let query_msg = Message::from_vec(&buf).unwrap();
                let resp = make_a_response(query_msg.metadata.id, &fqdn_owned, ips.clone(), ttl);
                let resp_len = u16::try_from(resp.len()).unwrap().to_be_bytes();
                let _ = send.write_all(&resp_len).await;
                let _ = send.write_all(&resp).await;
                let _ = send.finish();

                // 保持连接活着等 client 读完响应，再让 endpoint 自然结束
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            // endpoint drop 后关闭所有连接，但此时 client 已读完
        });

        // 信任自签证书的 client config。
        let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
        root_store
            .add(CertificateDer::from(cert_der))
            .unwrap();
        let client_config = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth(),
        );

        (addr, client_config, handle)
    }

    #[tokio::test]
    async fn doq_query_once_returns_a_record() {
        let (addr, tls_config, _h) =
            spawn_mock_doq_server("example.com.", vec![Ipv4Addr::new(10, 0, 0, 1)], 120).await;

        let ns = DoqNameServer::new(
            addr,
            "localhost".to_string(),
            tls_config,
            Arc::new(CacheController::new("test", true, false, 0, 0)),
            Vec::new(),
            Duration::from_secs(5),
        );
        let rec = ns.query_once("example.com.", RecordType::A).await.unwrap();
        assert_eq!(rec.ips.len(), 1);
        assert_eq!(rec.ips[0], IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(rec.ttl_seconds(Instant::now()) <= 120);
    }

    #[tokio::test]
    async fn doq_send_query_v4_only() {
        let (addr, tls_config, _h) =
            spawn_mock_doq_server("z.com.", vec![Ipv4Addr::new(8, 8, 8, 8)], 60).await;

        let ns = DoqNameServer::new(
            addr,
            "localhost".to_string(),
            tls_config,
            Arc::new(CacheController::new("test", true, false, 0, 0)),
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
    async fn doq_connect_failure_returns_error() {
        // 连一个不存在的端口，连接应超时或失败。
        let listener = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let cert_params =
            rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = cert_params.self_signed(&key_pair).unwrap();
        let cert_der = cert.der().to_vec();
        let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
        root_store.add(CertificateDer::from(cert_der)).unwrap();
        let tls_config = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth(),
        );

        let ns = DoqNameServer::new(
            addr,
            "localhost".to_string(),
            tls_config,
            Arc::new(CacheController::new("test", true, false, 0, 0)),
            Vec::new(),
            Duration::from_millis(500),
        );
        let outcome = ns
            .send_query(
                "bad.com.",
                IpOption {
                    ipv4_enable: true,
                    ipv6_enable: false,
                    fake_enable: false,
                },
            )
            .await;
        assert!(outcome.rec_v4.is_none());
        assert_eq!(outcome.errors.len(), 1);
    }
}
