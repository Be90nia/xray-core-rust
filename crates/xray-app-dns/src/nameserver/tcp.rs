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
use tokio::time::timeout;

use xray_common::net::address::Address;
use xray_common::net::destination::Destination;
use xray_common::net::port::Port;

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
    /// 远端 DNS 服务器地址（IP 直连；域名运行期解析——bd mcpo：经路由出站
    /// 时由路由系统解析，直连兜底每查询现解析）。
    dest: Destination,
    /// 缓存控制器。
    cache: Arc<CacheController>,
    /// EDNS0 client subnet。
    client_ip: Vec<u8>,
    /// 单次查询超时。
    query_timeout: Duration,
    /// 请求 ID 生成器。
    id_gen: AtomicReqIdGen,
    /// 连接池：复用查询流（直连 TcpConnection 或经路由 Link 流）。
    conn: tokio::sync::Mutex<Option<crate::dial::DnsStream>>,
    /// 域名解析器（直连兜底路径）。
    resolver: Arc<dyn crate::dial::HostResolver>,
    /// `+local`：强制直连（绕过共享 dialer，Go Local mode nil dispatcher）。
    force_local: bool,
}
impl TcpNameServer {
    /// 构造。
    #[must_use]
    pub fn new(
        dest: Destination,
        cache: Arc<CacheController>,
        client_ip: Vec<u8>,
        query_timeout: Duration,
        resolver: Arc<dyn crate::dial::HostResolver>,
    ) -> Self {
        let name = format!("TCP:{}:{}", dest.address(), dest.port());
        Self {
            name,
            dest,
            cache,
            client_ip,
            query_timeout,
            id_gen: AtomicReqIdGen::new(),
            conn: tokio::sync::Mutex::new(None),
            resolver,
            force_local: false,
        }
    }

    /// 标记 `+local`（强制直连，绕过共享 dialer；bd wmdn②）。
    #[must_use]
    pub fn force_local(mut self, v: bool) -> Self {
        self.force_local = v;
        self
    }

    /// 从 `NameServerConfig` 构造（地址接受 IP 或域名，bd mcpo）。
    pub fn from_config(ns: &NameServerConfig) -> Result<Box<dyn Server>, DnsError> {
        let dest = Destination::tcp(ns.address.clone(), Port::new(ns.port));
        let timeout_dur = if ns.timeout_ms > 0 {
            Duration::from_millis(u64::from(ns.timeout_ms))
        } else {
            Duration::from_millis(4000)
        };
        let cache = Arc::new(CacheController::new(
            format!("TCP:{}", dest),
            ns.disable_cache.unwrap_or(false),
            ns.serve_stale.unwrap_or(false),
            ns.serve_expired_ttl.unwrap_or(0),
            ns.negative_ttl_secs.unwrap_or(0),
        ));
        cache.start_cleanup_task(crate::cache_controller::CLEANUP_INTERVAL);
        Ok(Box::new(Arc::new(
            Self::new(
                dest,
                cache,
                ns.client_ip.clone(),
                timeout_dur,
                Arc::new(crate::dial::SystemHostResolver),
            )
            .force_local(ns.force_local),
        )))
    }

    /// 建立查询流：共享 dialer 在场经路由出站（Go nameserver_tcp.go:43-47
    /// dispatcher.Dispatch 语义）；缺席直连兜底（域名每查询现解析）。
    async fn connect(&self) -> Result<crate::dial::DnsStream, DnsError> {
        crate::dial::connect_stream(
            &self.dest,
            self.resolver.as_ref(),
            self.query_timeout,
            "tcp",
            self.force_local,
        )
        .await
    }

    /// 在已有连接上执行单次 TCP 查询。
    async fn try_query(
        &self,
        stream: &mut crate::dial::DnsStream,
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

        if self.dest.address().is_domain() {
            // 域名 NS（bd mcpo）：每查询新建流——连接池会把旧解析钉死，
            // 地址变更后新查询必须用新 IP。运行期解析在 connect() 内
            // （经路由出站交路由系统；直连兜底每查询现解析）。
            let mut stream = self.connect().await?;
            return self
                .try_query(&mut stream, &len_be, &payload, req_id, record_type)
                .await;
        }

        let mut conn_guard = self.conn.lock().await;
        if conn_guard.is_none() {
            *conn_guard = Some(self.connect().await?);
        }

        match self.try_query(conn_guard.as_mut().unwrap(), &len_be, &payload, req_id, record_type).await {
            Ok(result) => Ok(result),
            Err(e) => {
                // 首查失败静默重连不可观测（iq1o）：记录首查错误再重试。
                tracing::debug!(error = %e, "DNS-over-TCP query on pooled connection failed, reconnecting");
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

impl Server for Arc<TcpNameServer> {
    fn name(&self) -> &str {
        self.name.as_str()
    }

    fn is_disable_cache(&self) -> bool {
        self.cache.disable_cache
    }

    fn is_serve_stale(&self) -> bool {
        self.cache.serve_stale
    }

    fn query_ip<'a>(
        &'a self,
        domain: &'a str,
        option: IpOption,
    ) -> Pin<Box<dyn Future<Output = Result<(Vec<IpAddr>, u32), DnsError>> + Send + 'a>> {
        Box::pin(query_ip(self.clone(), domain, option))
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
    use std::net::{Ipv4Addr, Ipv6Addr};
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;
    use xray_transport::connection::TcpConnection;

    /// 共享 dialer 槽是进程级全局：涉 dialer 的测试须串行。
    static DIALER_SLOT_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    fn ip_dest(addr: SocketAddr) -> Destination {
        Destination::tcp(Address::from(addr.ip()), Port::new(addr.port()))
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
        let _slot = DIALER_SLOT_LOCK.lock();
        let (addr, _h) = spawn_mock_tcp_server("example.com.", vec![Ipv4Addr::new(10, 0, 0, 1)], 120).await;
        let ns = TcpNameServer::new(
            ip_dest(addr),
            Arc::new(CacheController::new("test", true, false, 0, 0)),
            Vec::new(),
            Duration::from_secs(2),
            Arc::new(crate::dial::SystemHostResolver),
        );
        let rec = ns.query_once("example.com.", RecordType::A).await.unwrap();
        assert_eq!(rec.ips.len(), 1);
        assert_eq!(rec.ips[0], IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(rec.ttl_seconds(Instant::now()) <= 120);
    }

    #[tokio::test]
    async fn tcp_send_query_v4_only() {
        let _slot = DIALER_SLOT_LOCK.lock();
        let (addr, _h) = spawn_mock_tcp_server("z.com.", vec![Ipv4Addr::new(8, 8, 8, 8)], 60).await;
        let ns = TcpNameServer::new(
            ip_dest(addr),
            Arc::new(CacheController::new("test", true, false, 0, 0)),
            Vec::new(),
            Duration::from_secs(2),
            Arc::new(crate::dial::SystemHostResolver),
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
        let _slot = DIALER_SLOT_LOCK.lock();
        // 监听但永不 accept。
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // 不 spawn accept task，让客户端 connect 成功但读永远等。

        let ns = TcpNameServer::new(
            ip_dest(addr),
            Arc::new(CacheController::new("test", true, false, 0, 0)),
            Vec::new(),
            Duration::from_millis(100),
            Arc::new(crate::dial::SystemHostResolver),
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

    /// 记录拨号目标的 mock dialer：真连 dest（TCP pump），验收"查询经路由出站"。
    #[derive(Default)]
    struct RecordingDialer {
        recorded: parking_lot::Mutex<Vec<Destination>>,
    }

    impl crate::dial::QueryDialer for RecordingDialer {
        fn dial_tcp(
            &self,
            dest: &Destination,
        ) -> Pin<Box<dyn Future<Output = io::Result<crate::dial::DnsStream>> + Send + '_>> {
            self.recorded.lock().push(dest.clone());
            let dest = dest.clone();
            Box::pin(async move {
                let ip = dest.address().ip().expect("test dest is IP");
                let sock =
                    tokio::net::TcpStream::connect(SocketAddr::new(ip, dest.port().value())).await?;
                Ok(Box::new(TcpConnection::new(sock)) as crate::dial::DnsStream)
            })
        }

        fn dial_udp(
            &self,
            _dest: &Destination,
        ) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn crate::dial::UdpPacketSession>>> + Send + '_>>
        {
            Box::pin(async {
                Err(io::Error::new(io::ErrorKind::Unsupported, "tcp test dialer"))
            })
        }
    }

    /// bd mcpo 验收②：dialer 注入后查询经路由出站——dialer 收到查询目标
    /// （dest 原样传递），数据经 dialer 建立的链路往返。
    #[tokio::test]
    async fn tcp_query_routes_through_dialer() {
        let _slot = DIALER_SLOT_LOCK.lock();
        let (addr, _h) = spawn_mock_tcp_server("routed.com.", vec![Ipv4Addr::new(10, 0, 0, 9)], 60).await;

        let dialer = Arc::new(RecordingDialer::default());
        crate::dial::set_shared_dialer(Some(dialer.clone()));
        let ns = TcpNameServer::new(
            ip_dest(addr),
            Arc::new(CacheController::new("test", true, false, 0, 0)),
            Vec::new(),
            Duration::from_secs(2),
            Arc::new(crate::dial::SystemHostResolver),
        );

        let rec = ns.query_once("routed.com.", RecordType::A).await.unwrap();
        crate::dial::set_shared_dialer(None);

        assert_eq!(rec.ips, vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9))]);
        let recorded = dialer.recorded.lock();
        assert_eq!(recorded.len(), 1, "query must dial through the routing dialer");
        assert_eq!(
            recorded[0].address(),
            &Address::from(addr.ip()),
            "dialer must receive the query destination"
        );
        assert_eq!(recorded[0].port().value(), addr.port());
    }

    /// 地址切换解析器：先返回 IP_A 后返回 IP_B（模拟上游 NS 地址变更）。
    struct SwitchResolver {
        to_b: std::sync::atomic::AtomicBool,
        addr_a: IpAddr,
        addr_b: IpAddr,
    }

    impl crate::dial::HostResolver for SwitchResolver {
        fn resolve(
            &self,
            _host: String,
        ) -> Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send>> {
            let target = if self.to_b.load(std::sync::atomic::Ordering::SeqCst) {
                self.addr_b
            } else {
                self.addr_a
            };
            Box::pin(async move { Ok(vec![target]) })
        }
    }

    /// bd mcpo 验收①：域名 NS 运行期解析——上游地址变更后，新查询用新 IP
    /// （旧解析不残留：连接池按域名字段每查询新建流）。
    #[tokio::test]
    async fn tcp_domain_ns_resolves_at_query_time() {
        let _slot = DIALER_SLOT_LOCK.lock();
        // A/B 两个 mock server：同一端口、不同 loopback 地址（模拟上游 NS 换 IP）。
        // B 用 v6 ::1——127.0.0.2 仅 Linux 隐式可用（macOS lo0 默认只有
        // 127.0.0.1，bind 报 AddrNotAvailable code 49，CI 首跑实证）；
        // v4/v6 双栈回环全平台齐备，保持"同端口异地址"可区分性，
        // 不依赖特定单播 IP。
        let listener_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener_a.local_addr().unwrap().port();
        let listener_b = TcpListener::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port))
            .await
            .unwrap();
        let task_a = spawn_echo_server(listener_a, Ipv4Addr::new(10, 9, 0, 1));
        let task_b = spawn_echo_server(listener_b, Ipv4Addr::new(10, 9, 0, 2));

        let resolver = Arc::new(SwitchResolver {
            to_b: std::sync::atomic::AtomicBool::new(false),
            addr_a: IpAddr::V4(Ipv4Addr::LOCALHOST),
            addr_b: IpAddr::V6(Ipv6Addr::LOCALHOST),
        });
        let dest = Destination::tcp(Address::Domain("var.example".to_string()), Port::new(port));
        let ns = TcpNameServer::new(
            dest,
            Arc::new(CacheController::new("test", true, false, 0, 0)),
            Vec::new(),
            Duration::from_secs(2),
            resolver.clone(),
        );

        // 第一次查询 → 解析到 A server，回 A 记录。
        let r1 = ns.query_once("var.com.", RecordType::A).await.unwrap();
        assert_eq!(r1.ips, vec![IpAddr::V4(Ipv4Addr::new(10, 9, 0, 1))]);

        // 上游地址"变更"。
        resolver
            .to_b
            .store(true, std::sync::atomic::Ordering::SeqCst);

        // 新查询 → 解析到 B server，回 B 记录（新 IP 生效）。
        let r2 = ns.query_once("var.com.", RecordType::A).await.unwrap();
        assert_eq!(
            r2.ips,
            vec![IpAddr::V4(Ipv4Addr::new(10, 9, 0, 2))],
            "query after address change must use the new IP"
        );
        let _ = (task_a, task_b);
    }

    /// 在指定 listener 上 accept 一次并回 A 记录响应。
    fn spawn_echo_server(
        listener: TcpListener,
        reply_ip: Ipv4Addr,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut len_buf = [0u8; 2];
            use tokio::io::AsyncReadExt;
            sock.read_exact(&mut len_buf).await.unwrap();
            let plen = usize::from(u16::from_be_bytes(len_buf));
            let mut buf = vec![0u8; plen];
            sock.read_exact(&mut buf).await.unwrap();
            let query_msg = Message::from_vec(&buf).unwrap();
            let resp = make_a_response(query_msg.metadata.id, "var.com.", vec![reply_ip], 60);
            let len = u16::try_from(resp.len()).unwrap().to_be_bytes();
            use tokio::io::AsyncWriteExt;
            sock.write_all(&len).await.unwrap();
            sock.write_all(&resp).await.unwrap();
        })
    }
}
