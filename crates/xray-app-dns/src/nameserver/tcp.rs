//! TCP DNS nameserver。对应 Go `app/dns/nameserver_tcp.go`。
//!
//! ## 实现
//!
//! - `tokio::net::TcpStream` 直连远端 DNS 服务器。
//! - DNS wire format 由 `hickory-proto` 处理。
//! - TCP 协议：每条 message 前 2 字节 big-endian 长度前缀（RFC 1035 §4.2.2）。
//! - 自动接入 cache（实现 `CachedNameserver`）。
//!
//! ## 跳过范围
//!
//! - 走 Xray routing/dispatcher 出口（直接用 tokio socket）
//! - TLS 包装（DoT 见 follow-up 任务）
//! - 长连接复用（每次查询都新连接；ponytail：简化代码，连接池可后续加）

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::rr::RecordType;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use xray_common::net::address::Address;

use crate::cache_controller::CacheController;
use crate::config::IpOption;
use crate::dnscommon::{
    build_dns_query, parse_dns_response, parsed_to_ip_record, AtomicReqIdGen, IpRecord, ReqIdGen,
};
use crate::error::DnsError;
use crate::nameserver::cached::{query_ip, CachedNameserver, QueryOutcome};
use crate::nameserver::{local, NameServerConfig, Server};

/// TCP DNS 单次响应最大字节数（DNS over TCP 理论上限 65535；实际 rarely > 4096）。
const TCP_RECV_MAX: usize = 65535;

/// TCP DNS nameserver。对应 Go `TCPNameServer`。
pub struct TcpNameServer {
    /// 服务名。
    name: String,
    /// 远端 DNS 服务器地址。
    addr: SocketAddr,
    /// 缓存控制器。
    cache: Arc<CacheController>,
    /// EDNS0 client subnet。
    client_ip: Vec<u8>,
    /// 单次查询超时。
    query_timeout: Duration,
    /// 请求 ID 生成器。
    id_gen: AtomicReqIdGen,
    /// 连接池：复用 TCP 连接。
    conn: tokio::sync::Mutex<Option<TcpStream>>,
}

impl TcpNameServer {
    /// 构造。
    #[must_use]
    pub fn new(
        addr: SocketAddr,
        cache: Arc<CacheController>,
        client_ip: Vec<u8>,
        query_timeout: Duration,
    ) -> Self {
        let name = format!("TCP:{}", addr);
        Self {
            name,
            addr,
            cache,
            client_ip,
            query_timeout,
            id_gen: AtomicReqIdGen::new(),
            conn: tokio::sync::Mutex::new(None),
        }
    }

    /// 从 `NameServerConfig` 构造。
    pub fn from_config(ns: &NameServerConfig) -> Result<Box<dyn Server>, DnsError> {
        let socket_addr = match &ns.address {
            Address::IPv4(v) => SocketAddr::new(IpAddr::V4(*v), ns.port),
            Address::IPv6(v) => SocketAddr::new(IpAddr::V6(*v), ns.port),
            other => {
                return Err(DnsError::WireFormat(format!(
                    "tcp nameserver requires IP address, got: {other:?}"
                )));
            }
        };
        let timeout_dur = if ns.timeout_ms > 0 {
            Duration::from_millis(u64::from(ns.timeout_ms))
        } else {
            Duration::from_millis(4000)
        };
        let cache = Arc::new(CacheController::new(
            format!("TCP:{}", socket_addr),
            ns.disable_cache.unwrap_or(false),
            ns.serve_stale.unwrap_or(false),
            ns.serve_expired_ttl.unwrap_or(0),
            ns.negative_ttl_secs.unwrap_or(0),
        ));
        cache.start_cleanup_task(crate::cache_controller::CLEANUP_INTERVAL);
        Ok(Box::new(Self::new(
            socket_addr,
            cache,
            ns.client_ip.clone(),
            timeout_dur,
        )))
    }

    /// 建立 TCP 连接。
    async fn connect(&self) -> Result<TcpStream, DnsError> {
        timeout(self.query_timeout, TcpStream::connect(self.addr))
            .await
            .map_err(|_| DnsError::WireFormat(format!("tcp connect timeout after {:?}", self.query_timeout)))?
            .map_err(|e| DnsError::WireFormat(format!("tcp connect: {e}")))
    }

    /// 在已有连接上执行单次 TCP 查询。
    async fn try_query(
        &self,
        stream: &mut TcpStream,
        len_be: &[u8; 2],
        payload: &[u8],
        req_id: u16,
        record_type: RecordType,
    ) -> Result<IpRecord, DnsError> {
        timeout(self.query_timeout, stream.write_all(len_be))
            .await.map_err(|_| DnsError::WireFormat("tcp write len timeout".to_string()))?
            .map_err(|e| DnsError::WireFormat(format!("tcp write len: {e}")))?;
        timeout(self.query_timeout, stream.write_all(payload))
            .await.map_err(|_| DnsError::WireFormat("tcp write payload timeout".to_string()))?
            .map_err(|e| DnsError::WireFormat(format!("tcp write payload: {e}")))?;
        stream.flush().await.map_err(io_to_dns)?;

        let mut len_buf = [0u8; 2];
        timeout(self.query_timeout, stream.read_exact(&mut len_buf))
            .await.map_err(|_| DnsError::WireFormat("tcp read len timeout".to_string()))?
            .map_err(|e| DnsError::WireFormat(format!("tcp read len: {e}")))?;
        let resp_len = usize::from(u16::from_be_bytes(len_buf));
        if resp_len == 0 || resp_len > TCP_RECV_MAX {
            return Err(DnsError::WireFormat(format!("invalid tcp response length: {resp_len}")));
        }

        let mut buf = vec![0u8; resp_len];
        timeout(self.query_timeout, stream.read_exact(&mut buf))
            .await.map_err(|_| DnsError::WireFormat("tcp read payload timeout".to_string()))?
            .map_err(|e| DnsError::WireFormat(format!("tcp read payload: {e}")))?;

        let now = Instant::now();
        let parsed = parse_dns_response(&buf, req_id, record_type, now)?;
        Ok(parsed_to_ip_record(&parsed, now))
    }

    /// 发送单次 DNS 查询（TCP），等待响应。连接池复用连接，失败时重试一次。
    async fn query_once(
        &self,
        fqdn: &str,
        record_type: RecordType,
    ) -> Result<IpRecord, DnsError> {
        let req_id = self.id_gen.next_id();
        let payload = build_dns_query(fqdn, record_type, req_id, &self.client_ip)?;
        let len_be = u16::try_from(payload.len())
            .map_err(|_| DnsError::WireFormat("query too large for TCP".to_string()))?
            .to_be_bytes();

        let mut conn_guard = self.conn.lock().await;
        if conn_guard.is_none() {
            *conn_guard = Some(self.connect().await?);
        }

        match self.try_query(conn_guard.as_mut().unwrap(), &len_be, &payload, req_id, record_type).await {
            Ok(result) => Ok(result),
            Err(_) => {
                *conn_guard = None;
                *conn_guard = Some(self.connect().await?);
                self.try_query(conn_guard.as_mut().unwrap(), &len_be, &payload, req_id, record_type).await
            }
        }
    }
}

impl CachedNameserver for TcpNameServer {
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

impl Server for TcpNameServer {
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

fn io_to_dns(e: io::Error) -> DnsError {
    DnsError::WireFormat(format!("tcp io: {e}"))
}

/// 构造 TCP nameserver。对应 Go `NewTCPNameServer`。
pub fn new_tcp_name_server(ns: &NameServerConfig) -> Result<Box<dyn Server>, DnsError> {
    TcpNameServer::from_config(ns)
}

/// 构造 TCP 本地 nameserver（暂与普通 TCP 一致；Go 版本走 system resolver，留 follow-up）。
pub fn new_tcp_local_name_server(ns: &NameServerConfig) -> Result<Box<dyn Server>, DnsError> {
    TcpNameServer::from_config(ns)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::IpOption;
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use std::net::Ipv4Addr;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

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

    /// 启动 mock TCP DNS server：accept 一次连接，回一个预设响应。
    async fn spawn_mock_tcp_server(
        fqdn: &str,
        ips: Vec<Ipv4Addr>,
        ttl: u32,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let fqdn_owned = fqdn.to_string();
        let handle = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            // 读 2 字节长度 + payload。
            let mut len_buf = [0u8; 2];
            use tokio::io::AsyncReadExt;
            sock.read_exact(&mut len_buf).await.unwrap();
            let plen = usize::from(u16::from_be_bytes(len_buf));
            let mut buf = vec![0u8; plen];
            sock.read_exact(&mut buf).await.unwrap();
            // 解析 query 取 ID，用同一 ID 构造响应。
            let query_msg = Message::from_vec(&buf).unwrap();
            let resp = make_a_response(query_msg.metadata.id, &fqdn_owned, ips.clone(), ttl);
            // 回写 2B 长度 + response。
            let len = u16::try_from(resp.len()).unwrap().to_be_bytes();
            sock.write_all(&len).await.unwrap();
            sock.write_all(&resp).await.unwrap();
            sock.flush().await.unwrap();
        });
        (addr, handle)
    }

    #[tokio::test]
    async fn tcp_query_once_returns_a_record() {
        let (addr, _h) = spawn_mock_tcp_server("example.com.", vec![Ipv4Addr::new(10, 0, 0, 1)], 120).await;

        let ns = TcpNameServer::new(
            addr,
            Arc::new(CacheController::new("test", true, false, 0, 0)),
            Vec::new(),
            Duration::from_secs(2),
        );
        let rec = ns.query_once("example.com.", RecordType::A).await.unwrap();
        assert_eq!(rec.ips.len(), 1);
        assert_eq!(rec.ips[0], IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(rec.ttl_seconds(Instant::now()) <= 120);
    }

    #[tokio::test]
    async fn tcp_send_query_v4_only() {
        let (addr, _h) = spawn_mock_tcp_server("z.com.", vec![Ipv4Addr::new(8, 8, 8, 8)], 60).await;

        let ns = TcpNameServer::new(
            addr,
            Arc::new(CacheController::new("test", true, false, 0, 0)),
            Vec::new(),
            Duration::from_secs(2),
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
    async fn tcp_query_timeout_records_error() {
        // 监听但永不 accept。
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // 不 spawn accept task，让客户端 connect 成功但读永远等。

        let ns = TcpNameServer::new(
            addr,
            Arc::new(CacheController::new("test", true, false, 0, 0)),
            Vec::new(),
            Duration::from_millis(100),
        );
        let outcome = ns
            .send_query(
                "slow.com.",
                IpOption {
                    ipv4_enable: true,
                    ipv6_enable: false,
                    fake_enable: false,
                },
            )
            .await;
        // TCP connect 成功（listener 在），但 read 等到 timeout。
        assert!(outcome.rec_v4.is_none());
        assert_eq!(outcome.errors.len(), 1);
    }
}
