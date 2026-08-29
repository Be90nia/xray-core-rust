//! UDP (Classic) DNS nameserver。对应 Go `app/dns/nameserver_udp.go`。
//!
//! ## 实现
//!
//! - `tokio::net::UdpSocket` 直连远端 DNS 服务器（不走 Xray dispatcher，
//!   dispatcher 接入留 follow-up）。
//! - DNS wire format 由 `hickory-proto` 处理（覆盖 A/AAAA/MX/TXT/EDNS0）。
//! - 自动接入 cache（实现 `CachedNameserver`，由 `cached::query_ip` 统一调度）。
//! - truncated 响应自动 TCP 重试（RFC 7766 §5）。
//!
//! ## 跳过范围
//!
//! - 走 Xray routing/dispatcher 出口（直接用 tokio socket）
//! - 请求去重 singleflight（CacheController 层面已部分缓解）

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::rr::RecordType;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use xray_common::net::address::Address;

use crate::cache_controller::CacheController;
use crate::config::IpOption;
use crate::dnscommon::{
    build_dns_query, parse_dns_response, parsed_to_ip_record, AtomicReqIdGen, IpRecord, ReqIdGen,
};
use crate::error::DnsError;
use crate::nameserver::cached::{query_ip, CachedNameserver, QueryOutcome};
use crate::nameserver::{NameServerConfig, Server};

/// UDP DNS 查询缓冲区大小（Go 默认 4096；hickory 推荐 1232 + EDNS0）。
const UDP_RECV_BUF: usize = 4096;

/// UDP DNS nameserver。对应 Go `ClassicNameServer`。
pub struct UdpNameServer {
    /// 服务名（含地址，用于日志）。
    name: String,
    /// 远端 DNS 服务器地址（已规范化为 SocketAddr）。
    addr: SocketAddr,
    /// 缓存控制器。
    cache: Arc<CacheController>,
    /// EDNS0 client subnet（空 Vec 表示不加）。
    client_ip: Vec<u8>,
    /// 单次查询超时。
    query_timeout: Duration,
    /// 请求 ID 生成器。
    id_gen: AtomicReqIdGen,
    /// TCP fallback 缓冲区大小。
    tcp_recv_max: usize,
}

impl UdpNameServer {
    /// 构造 UDP nameserver。
    ///
    /// `client_ip` 长度须为 0/4/16（EDNS0 subnet 规范）。
    #[must_use]
    pub fn new(
        addr: SocketAddr,
        cache: Arc<CacheController>,
        client_ip: Vec<u8>,
        query_timeout: Duration,
    ) -> Self {
        let name = format!("UDP:{}", addr);
        Self {
            name,
            addr,
            cache,
            client_ip,
            query_timeout,
            id_gen: AtomicReqIdGen::new(),
            tcp_recv_max: 65535,
        }
    }


    /// 从 `NameServerConfig` 构造（Box<dyn Server> 形态）。
    ///
    /// `ns.address` 必须能解析为 IP（域名地址会失败，调用方先做 DNS 查询）。
    pub fn from_config(ns: &NameServerConfig) -> Result<Box<dyn Server>, DnsError> {
        Ok(Box::new(Self::from_config_bare(ns)?))
    }

    /// 从 `NameServerConfig` 构造具体类型。cache 4 字段
    /// （disable_cache/serve_stale/serve_expired_ttl/negative_ttl_secs）
    /// 流入 CacheController（Go nameserver.go NewServer 收全量 proto 语义）。
    fn from_config_bare(ns: &NameServerConfig) -> Result<Self, DnsError> {
        let socket_addr = match &ns.address {
            Address::IPv4(v) => SocketAddr::new(IpAddr::V4(*v), ns.port),
            Address::IPv6(v) => SocketAddr::new(IpAddr::V6(*v), ns.port),
            other => {
                return Err(DnsError::WireFormat(format!(
                    "udp nameserver requires IP address, got: {other:?}"
                )));
            }
        };
        let timeout = if ns.timeout_ms > 0 {
            Duration::from_millis(u64::from(ns.timeout_ms))
        } else {
            Duration::from_millis(4000)
        };
        let cache = Arc::new(CacheController::new(
            format!("UDP:{}", socket_addr),
            ns.disable_cache.unwrap_or(false),
            ns.serve_stale.unwrap_or(false),
            ns.serve_expired_ttl.unwrap_or(0),
            ns.negative_ttl_secs.unwrap_or(0),
        ));
        Ok(Self::new(socket_addr, cache, ns.client_ip.clone(), timeout))
    }

    /// 发送单次 DNS 查询并等待响应。
    async fn query_once(
        &self,
        fqdn: &str,
        record_type: RecordType,
    ) -> Result<IpRecord, DnsError> {
        let req_id = self.id_gen.next_id();
        let wire = build_dns_query(fqdn, record_type, req_id, &self.client_ip)?;

        // 绑定任意本地端口。失败多为系统 fd 限制。
        let sock = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| DnsError::WireFormat(format!("udp bind: {e}")))?;
        sock.send_to(&wire, self.addr)
            .await
            .map_err(|e| DnsError::WireFormat(format!("udp send: {e}")))?;

        let mut buf = vec![0u8; UDP_RECV_BUF];
        let n = timeout(self.query_timeout, sock.recv(&mut buf))
            .await
            .map_err(|_| {
                DnsError::WireFormat(format!(
                    "udp recv timeout after {:?}",
                    self.query_timeout
                ))
            })?
            .map_err(|e| DnsError::WireFormat(format!("udp recv: {e}")))?;

        let now = Instant::now();
        let parsed = parse_dns_response(&buf[..n], req_id, record_type, now)?;
        if parsed.truncated {
            return self.tcp_fallback_query(fqdn, record_type).await;
        }
        Ok(parsed_to_ip_record(&parsed, now))
    }

    /// UDP truncated (TC=1) 后自动 TCP 重试。
    ///
    /// 对应 Go `(*ClassicNameServer).query` TCP fallback 路径。
    /// RFC 7766 §5: 客户端必须支持 TCP 重试。
    async fn tcp_fallback_query(
        &self,
        fqdn: &str,
        record_type: RecordType,
    ) -> Result<IpRecord, DnsError> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        let req_id = self.id_gen.next_id();
        let payload = build_dns_query(fqdn, record_type, req_id, &self.client_ip)?;

        // TCP: 2B big-endian 长度前缀。
        let len_be = u16::try_from(payload.len())
            .map_err(|_| DnsError::WireFormat("query too large for TCP".into()))?
            .to_be_bytes();

        let mut stream = timeout(self.query_timeout, TcpStream::connect(self.addr))
            .await
            .map_err(|_| DnsError::WireFormat(format!(
                "tcp fallback connect timeout after {:?}",
                self.query_timeout
            )))?
            .map_err(|e| DnsError::WireFormat(format!("tcp fallback connect: {e}")))?;

        timeout(self.query_timeout, stream.write_all(&len_be))
            .await
            .map_err(|_| DnsError::WireFormat("tcp fallback write len timeout".into()))?
            .map_err(|e| DnsError::WireFormat(format!("tcp fallback write len: {e}")))?;
        timeout(self.query_timeout, stream.write_all(&payload))
            .await
            .map_err(|_| DnsError::WireFormat("tcp fallback write payload timeout".into()))?
            .map_err(|e| DnsError::WireFormat(format!("tcp fallback write payload: {e}")))?;

        // 读 2B 长度前缀。
        let mut len_buf = [0u8; 2];
        timeout(self.query_timeout, stream.read_exact(&mut len_buf))
            .await
            .map_err(|_| DnsError::WireFormat("tcp fallback read len timeout".into()))?
            .map_err(|e| DnsError::WireFormat(format!("tcp fallback read len: {e}")))?;
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        if resp_len == 0 || resp_len > self.tcp_recv_max {
            return Err(DnsError::WireFormat(format!(
                "tcp fallback invalid response length: {resp_len}"
            )));
        }

        let mut resp_buf = vec![0u8; resp_len];
        timeout(self.query_timeout, stream.read_exact(&mut resp_buf))
            .await
            .map_err(|_| DnsError::WireFormat("tcp fallback read response timeout".into()))?
            .map_err(|e| DnsError::WireFormat(format!("tcp fallback read response: {e}")))?;

        let now = Instant::now();
        let parsed = parse_dns_response(&resp_buf, req_id, record_type, now)?;
        // TCP 响应不应有 truncated（如果仍有，说明服务端异常，忽略 TC 标志）。
        Ok(parsed_to_ip_record(&parsed, now))
    }
}

impl CachedNameserver for UdpNameServer {
    fn cache_controller(&self) -> &CacheController {
        &self.cache
    }

    async fn send_query(&self, fqdn: &str, option: IpOption) -> QueryOutcome {
        let mut outcome = QueryOutcome::default();

        // 顺序发起 A/AAAA。
        // ponytail: 串行 await。真正并行需 tokio::join! 或 JoinSet，业务上串行也能完成
        // （多 1 个 RTT 的延迟换简化代码）。高并发场景可在 query_once 外层 spawn。
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

impl Server for UdpNameServer {
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

/// 构造 UDP nameserver。对应 Go `NewClassicNameServer`。
///
/// 入参：服务端地址（IP + 端口）+ 缓存配置 + EDNS0 client IP。
pub fn new_classic_name_server(
    ns: &NameServerConfig,
) -> Result<Box<dyn Server>, DnsError> {
    UdpNameServer::from_config(ns)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::IpOption;
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    /// 用 hickory 构造一个 DNS 响应 wire bytes（含 A 记录）。
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

    /// 启动 mock UDP DNS server：收到查询后 echo 请求 ID 回复 A 记录。
    async fn spawn_mock_udp_server(
        fqdn: &str,
        ips: Vec<Ipv4Addr>,
        ttl: u32,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let fqdn_owned = fqdn.to_string();
        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let (n, peer) = sock.recv_from(&mut buf).await.unwrap();
            // 解析 query 取 ID。
            let query_msg = Message::from_vec(&buf[..n]).unwrap();
            let resp = make_a_response(query_msg.metadata.id, &fqdn_owned, ips.clone(), ttl);
            sock.send_to(&resp, peer).await.unwrap();
        });
        (addr, handle)
    }

    #[tokio::test]
    async fn query_once_returns_parsed_a_record() {
        let (addr, _h) = spawn_mock_udp_server("example.com.", vec![Ipv4Addr::new(1, 2, 3, 4)], 60).await;

        let ns = UdpNameServer::new(
            addr,
            Arc::new(CacheController::new("test", true, false, 0, 0)),
            Vec::new(),
            Duration::from_secs(2),
        );
        let rec = ns.query_once("example.com.", RecordType::A).await.unwrap();
        assert_eq!(rec.ips.len(), 1);
        assert_eq!(rec.ips[0], IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(rec.rcode, 0);
    }

    #[tokio::test]
    async fn send_query_populates_rec_v4_only() {
        let (addr, _h) = spawn_mock_udp_server("x.com.", vec![Ipv4Addr::new(9, 9, 9, 9)], 30).await;

        let ns = UdpNameServer::new(
            addr,
            Arc::new(CacheController::new("test", true, false, 0, 0)),
            Vec::new(),
            Duration::from_secs(2),
        );
        let outcome = ns
            .send_query("x.com.", IpOption {
                ipv4_enable: true,
                ipv6_enable: false,
                fake_enable: false,
            })
            .await;
        assert!(outcome.rec_v4.is_some());
        assert!(outcome.rec_v6.is_none());
        assert!(outcome.errors.is_empty());
    }

    #[tokio::test]
    async fn send_query_records_error_when_server_silent() {
        // 启 server 但不响应。
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        // _sock drop 后端口仍由 OS 保留 TIME_WAIT，超时测试不依赖 server。
        drop(sock);

        let ns = UdpNameServer::new(
            addr,
            Arc::new(CacheController::new("test", true, false, 0, 0)),
            Vec::new(),
            Duration::from_millis(100),
        );
        let outcome = ns
            .send_query("y.com.", IpOption {
                ipv4_enable: true,
                ipv6_enable: false,
                fake_enable: false,
            })
            .await;
        assert!(outcome.rec_v4.is_none());
        assert_eq!(outcome.errors.len(), 1);
    }

    /// 4ah3：from_config 消费 NameServerConfig 的 cache 4 字段
    /// （disable_cache/serve_stale/serve_expired_ttl/negative_ttl_secs → CacheController），
    /// 即 Go nameserver.go NewServer 收全量 proto 的语义。serveExpiredTTL 存负值。
    #[test]
    fn from_config_propagates_cache_fields() {
        let ns = NameServerConfig {
            address: Address::IPv4(Ipv4Addr::from_str("8.8.8.8").unwrap()),
            port: 53,
            disable_cache: Some(true),
            serve_stale: Some(true),
            serve_expired_ttl: Some(45),
            negative_ttl_secs: Some(15),
            ..Default::default()
        };
        let server = UdpNameServer::from_config_bare(&ns).unwrap();
        assert!(server.cache.disable_cache);
        assert!(server.cache.serve_stale);
        assert_eq!(server.cache.serve_expired_ttl_secs, -45, "serveExpiredTTL 存为负值（Go 语义）");
        assert_eq!(server.cache.negative_ttl_secs, 15);
    }

    #[test]
    fn from_config_rejects_domain_address() {
        let ns = NameServerConfig {
            address: Address::Domain("dns.example.com".to_string()),
            port: 53,
            ..Default::default()
        };
        assert!(matches!(
            UdpNameServer::from_config(&ns),
            Err(DnsError::WireFormat(_))
        ));
    }

    #[test]
    fn from_config_accepts_ipv4_address() {
        let ns = NameServerConfig {
            address: Address::IPv4(Ipv4Addr::from_str("8.8.8.8").unwrap()),
            port: 53,
            timeout_ms: 1000,
            ..Default::default()
        };
        let server = UdpNameServer::from_config(&ns).unwrap();
        assert_eq!(server.name(), "UDP:8.8.8.8:53");
    }
}
