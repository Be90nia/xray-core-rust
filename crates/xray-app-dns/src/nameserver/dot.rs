//! DoT (DNS over TLS) nameserver。对应 Go `app/dns/nameserver_tls.go`（隐含在 nameserver.go 的 TLS
//! 分支）。
//!
//! ## 实现
//!
//! - `tokio::net::TcpStream` → `xray_tls::client` TLS 握手 → 在 `Conn` 上读写 TCP wire format。
//! - DNS wire format 由 `hickory-proto` 处理。
//! - DoT 协议：TCP + TLS 包装，wire format 与 TCP 完全相同（2B 长度前缀，RFC 7858）。
//! - 默认端口 853。
//! - 自动接入 cache（实现 `CachedNameserver`）。
//!
//! ## 跳过范围
//!
//! - 走 Xray routing/dispatcher 出口（直接用 tokio socket + xray_tls）
//! - 长连接复用（每次查询都新连接；ponytail：连接池可后续加）

use std::{future::Future, io, net::IpAddr, pin::Pin, sync::Arc, time::Duration};

use hickory_proto::rr::RecordType;
use skeleton_infra::fx::FxScope;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::rustls::ClientConfig;
use xray_common::net::{destination::Destination, port::Port};
use xray_frame::deadline::{Budget, BudgetDeadline};
use xray_tls::utls::client as tls_client;

use crate::{
    cache_controller::CacheController,
    config::IpOption,
    dnscommon::{
        AtomicReqIdGen, IpRecord, ReqIdGen, build_dns_query, parse_dns_response,
        parsed_to_ip_record,
    },
    error::DnsError,
    nameserver::{
        NameServerConfig, Server,
        cached::{CachedNameserver, QueryOutcome, query_ip},
    },
};

/// DoT 单次响应最大字节数（与 TCP 一致）。
const DOT_RECV_MAX: usize = 65535;

/// DoT DNS nameserver。
///
/// 结构与 `TcpNameServer` 对称，区别：connect 后多一步 TLS 握手。
pub struct DotNameServer {
    /// 服务名。
    name: String,
    /// 远端 DNS 服务器地址（IP 直连；域名运行期解析——bd mcpo）。
    dest: Destination,
    /// TLS SNI（ServerName）。通常等于域名或 IP 字符串。
    server_name: String,
    /// TLS 客户端配置（含 root certs + ALPN）。
    tls_config: Arc<ClientConfig>,
    /// 缓存控制器。
    cache: Arc<CacheController>,
    /// EDNS0 client subnet。
    client_ip: Vec<u8>,
    query_timeout: Duration,
    /// 请求 ID 生成器。
    id_gen: AtomicReqIdGen,
    /// 连接池：复用 TLS 连接（流形态：直连 TcpConnection 或经路由 Link 流）。
    conn: tokio::sync::Mutex<
        Option<xray_tls::utls::Conn<Box<dyn xray_transport::connection::Connection>>>,
    >,
    /// 域名解析器（直连兜底路径）。
    resolver: Arc<dyn crate::dial::HostResolver>,
    /// `+local`：强制直连（绕过共享 dialer，Go Local mode nil dispatcher）。
    force_local: bool,
}

/// 查询流类型别名：TLS 之下的字节流。
type DotStream = Box<dyn xray_transport::connection::Connection>;

impl DotNameServer {
    /// 构造。
    #[must_use]
    #[allow(clippy::too_many_arguments)] // Go NewServerClient 装配面 6 参直译，打包结构属 API 变更
    pub fn new(
        dest: Destination,
        server_name: String,
        tls_config: Arc<ClientConfig>,
        cache: Arc<CacheController>,
        client_ip: Vec<u8>,
        query_timeout: Duration,
    ) -> Self {
        let name = format!("DoT:{}:{}", dest.address(), dest.port());
        Self {
            name,
            dest,
            server_name,
            tls_config,
            cache,
            client_ip,
            query_timeout,
            id_gen: AtomicReqIdGen::new(),
            conn: tokio::sync::Mutex::new(None),
            resolver: Arc::new(crate::dial::SystemHostResolver),
            force_local: false,
        }
    }

    /// 标记 `+local`（强制直连，绕过共享 dialer；bd wmdn②）。
    #[must_use]
    pub fn force_local(mut self, v: bool) -> Self {
        self.force_local = v;
        self
    }

    /// 从 `NameServerConfig` 构造。调用方提供 `server_name`（TLS SNI）和 `tls_config`。
    pub fn from_config(
        ns: &NameServerConfig,
        server_name: String,
        tls_config: Arc<ClientConfig>,
    ) -> Result<Box<dyn Server>, DnsError> {
        let dest = Destination::tcp(ns.address.clone(), Port::new(ns.port));
        let timeout_dur = if ns.timeout_ms > 0 {
            Duration::from_millis(u64::from(ns.timeout_ms))
        } else {
            Duration::from_millis(4000)
        };
        let cache = Arc::new(CacheController::new(
            format!("DoT:{}", dest),
            ns.disable_cache.unwrap_or(false),
            ns.serve_stale.unwrap_or(false),
            ns.serve_expired_ttl.unwrap_or(0),
            ns.negative_ttl_secs.unwrap_or(0),
        ));
        // P1-11：cleanup 不在配置期 spawn——启动期经 Server::start_managed_tasks 注册。
        Ok(Box::new(Arc::new(
            Self::new(dest, server_name, tls_config, cache, ns.client_ip.clone(), timeout_dur)
                .force_local(ns.force_local),
        )))
    }

    /// 建立 DoT TLS 连接：经路由出站或直连兜底（域名每查询现解析）。
    ///
    /// bd 2iauj：拨号 + TLS 握手共享整条查询的绝对 `deadline`（Go 无独立 DoT
    /// nameserver，语义等同 nameserver_tcp.go:124-129/151 的 ctx deadline）——
    /// 内部 `connect_stream` 仍按单次拨号计 `query_timeout`，总量由外层封顶。
    async fn connect_tls(
        &self,
        deadline: BudgetDeadline,
    ) -> Result<xray_tls::utls::Conn<DotStream>, DnsError> {
        // W4 面 3：预算超时统一走 `BudgetDeadline::timeout`（Tokio 源 = tokio
        // `timeout_at` 绝对截止点，与迁移前 `timeout_at(deadline, ..)` 逐点等价：
        // 整条查询共享同一绝对时刻，慢阶段不推出新预算）。
        //
        // 注：本函数的 `try_query` 同胞函数因持有 `&mut Conn<DotStream>`
        // （内含 `Box<dyn Connection>`）触发 rustc HRTB 推断限制，那里走相对
        // 形态（见 `try_query` 内的例外登记注释）。
        let stream = deadline
            .timeout(crate::dial::connect_stream(
                &self.dest,
                self.resolver.as_ref(),
                self.query_timeout,
                "dot",
                self.force_local,
            ))
            .await
            .map_err(|_| {
                DnsError::WireFormat(format!("dot dial timeout after {:?}", self.query_timeout))
            })??;
        let tls = deadline
            .timeout(tls_client(stream, &self.server_name, Arc::clone(&self.tls_config)))
            .await
            .map_err(|_| DnsError::WireFormat("dot tls handshake timeout".to_string()))?
            .map_err(|e| DnsError::WireFormat(format!("dot tls handshake: {e}")))?;
        Ok(tls)
    }

    /// 在已有连接上执行单次 DoT 查询（bd 2iauj：写/刷新/读全按整条查询的
    /// `deadline` 收场，慢握手不把读段起点推后）。
    async fn try_query(
        &self,
        stream: &mut xray_tls::utls::Conn<DotStream>,
        len_be: &[u8; 2],
        payload: &[u8],
        req_id: u16,
        record_type: RecordType,
        deadline: BudgetDeadline,
    ) -> Result<IpRecord, DnsError> {
        // W4 面 3 例外登记（本函数独用相对形态）：`BudgetDeadline::timeout` 是
        // `async fn` + 泛型 future（匿名 future 类型），在本函数的具体化组合下
        // 触发 rustc HRTB 推断限制（"implementation of `Connection` is not general
        // enough"）——本函数持有 `&mut Conn<DotStream>`（内含
        // `Box<dyn Connection>`），其 `write_all`/`read_exact` future 的
        // 高阶生命周期约束与匿名 future 类型叠加即不可generalize。
        // 改走既有构造形态 `xray_frame::deadline::timeout(fut, remaining)`
        // （返回具名 `tokio::time::Timeout<F>` 类型，规避该推断限制）。
        // 语义等价性：`remaining()` 每次调用点现算 = `绝对截止点 - now`，
        // 故本段实际到期时刻 ≈ 同一绝对截止点（漂移 = 计算 remaining 与构造
        // timeout 之间的纳秒级间隙），整条查询仍被同一绝对预算封顶，
        // 慢握手不推出新预算。
        // 写长度前缀 + payload。
        // 实测（2026-10-27 W4V5 复验）：直写 `deadline.timeout(stream.write_all(..))`
        // 必报 `implementation of Connection is not general enough`
        //（`Box<dyn Connection + '0>` vs `'static`），故此形态保留。
        xray_frame::deadline::timeout(stream.write_all(len_be), deadline.remaining())
            .await
            .map_err(|_| DnsError::WireFormat("dot write len timeout".to_string()))?
            .map_err(|e| DnsError::WireFormat(format!("dot write len: {e}")))?;
        xray_frame::deadline::timeout(stream.write_all(payload), deadline.remaining())
            .await
            .map_err(|_| DnsError::WireFormat("dot write payload timeout".to_string()))?
            .map_err(|e| DnsError::WireFormat(format!("dot write payload: {e}")))?;
        xray_frame::deadline::timeout(stream.flush(), deadline.remaining())
            .await
            .map_err(|_| DnsError::WireFormat("dot flush timeout".to_string()))?
            .map_err(io_to_dns)?;

        // 读 2 字节长度前缀。
        let mut len_buf = [0u8; 2];
        xray_frame::deadline::timeout(stream.read_exact(&mut len_buf), deadline.remaining())
            .await
            .map_err(|_| DnsError::WireFormat("dot read len timeout".to_string()))?
            .map_err(|e| DnsError::WireFormat(format!("dot read len: {e}")))?;
        let resp_len = usize::from(u16::from_be_bytes(len_buf));
        if resp_len == 0 || resp_len > DOT_RECV_MAX {
            return Err(DnsError::WireFormat(format!("invalid dot response length: {resp_len}")));
        }

        // 读响应 payload。
        let mut buf = vec![0u8; resp_len];
        xray_frame::deadline::timeout(stream.read_exact(&mut buf), deadline.remaining())
            .await
            .map_err(|_| DnsError::WireFormat("dot read payload timeout".to_string()))?
            .map_err(|e| DnsError::WireFormat(format!("dot read payload: {e}")))?;

        // 713x6：解析时刻取自注入时钟（CacheController P1-12 单钟语义）。
        let now = self.cache.clock().now_instant();
        let parsed = parse_dns_response(&buf, req_id, record_type, now)?;
        Ok(parsed_to_ip_record(&parsed, now))
    }

    /// 发送单次 DNS 查询（DoT），等待响应。连接池复用 TLS 连接，失败时重试一次
    /// （bd 2iauj：重试共享调用方传入的同一 `deadline`，不另起预算）。
    async fn query_once(
        &self,
        fqdn: &str,
        record_type: RecordType,
        deadline: BudgetDeadline,
    ) -> Result<IpRecord, DnsError> {
        let req_id = self.id_gen.next_id();
        let payload = build_dns_query(fqdn, record_type, req_id, &self.client_ip)?;
        let len_be = u16::try_from(payload.len())
            .map_err(|_| DnsError::WireFormat("query too large for DoT".to_string()))?
            .to_be_bytes();

        let mut conn_guard = self.conn.lock().await;
        if conn_guard.is_none() {
            *conn_guard = Some(self.connect_tls(deadline.clone()).await?);
        }

        // 尝试在已有连接上查询，失败则丢弃重连。
        match self
            .try_query(
                conn_guard.as_mut().expect("conn established above when None"),
                &len_be,
                &payload,
                req_id,
                record_type,
                deadline.clone(),
            )
            .await
        {
            Ok(result) => Ok(result),
            Err(e) => {
                // 整条查询 deadline 已耗尽（本段超时）→ 重连必然立即失败，且会用
                // 拨号/握手错误掩盖真正原因：直接返回首查错误（Go 本无重试）。
                if deadline.is_expired() {
                    return Err(e);
                }
                // 首查失败静默重连不可观测（iq1o）：记录首查错误再重试。
                tracing::debug!(error = %e, "DoT query on pooled connection failed, reconnecting");
                *conn_guard = None;
                *conn_guard = Some(self.connect_tls(deadline.clone()).await?);
                self.try_query(
                    conn_guard.as_mut().expect("reconnected just above"),
                    &len_be,
                    &payload,
                    req_id,
                    record_type,
                    deadline.clone(),
                )
                .await
            },
        }
    }
}

impl CachedNameserver for DotNameServer {
    fn cache_controller(&self) -> &CacheController {
        &self.cache
    }

    async fn send_query(&self, fqdn: &str, option: IpOption) -> QueryOutcome {
        let mut outcome = QueryOutcome::default();

        // bd 2iauj：整条查询只算一次绝对 deadline（Go nameserver_tcp.go:124-129
        // 入口算一次、:151 每个 req 复用；DoT 走同一 TCP 语义）——A/AAAA、
        // 拨号、TLS 握手、写、读、重试共享。
        // W4 面 3：取时统一走 Budget::tokio()（Tokio 源内部 = tokio Instant，
        // pause/advance 语义不变）。
        let deadline = Budget::tokio().deadline(self.query_timeout);

        if option.ipv4_enable {
            match self.query_once(fqdn, RecordType::A, deadline.clone()).await {
                Ok(rec) => outcome.rec_v4 = Some(rec),
                Err(e) => outcome.errors.push(e),
            }
        }
        if option.ipv6_enable {
            match self.query_once(fqdn, RecordType::AAAA, deadline.clone()).await {
                Ok(rec) => outcome.rec_v6 = Some(rec),
                Err(e) => outcome.errors.push(e),
            }
        }

        outcome
    }
}

impl Server for Arc<DotNameServer> {
    fn name(&self) -> &str {
        self.name.as_str()
    }

    fn is_disable_cache(&self) -> bool {
        self.cache.disable_cache
    }

    fn is_serve_stale(&self) -> bool {
        self.cache.serve_stale
    }

    fn start_managed_tasks(&self, fx: &Arc<FxScope>) {
        self.cache.start_managed(fx, crate::cache_controller::CLEANUP_INTERVAL);
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
    DnsError::WireFormat(format!("dot io: {e}"))
}

/// 构造 DoT nameserver。
pub fn new_dot_name_server(
    ns: &NameServerConfig,
    server_name: String,
    tls_config: Arc<ClientConfig>,
) -> Result<Box<dyn Server>, DnsError> {
    DotNameServer::from_config(ns, server_name, tls_config)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::disallowed_methods,
        reason = "713x6：测试计时不得改语义（契约）——测试取时/等待窗口保持原语义，时钟禁令只约束生产路径"
    )]
    use std::{
        net::{Ipv4Addr, SocketAddr},
        time::Instant,
    };

    use hickory_proto::{
        op::{Message, MessageType, OpCode, Query},
        rr::{Name, RData, Record, RecordType},
    };
    use tokio::net::TcpListener;
    use tokio_rustls::{TlsAcceptor, rustls::ServerConfig};
    use xray_common::net::address::Address;
    use xray_transport::connection::TcpConnection;

    use super::*;
    use crate::config::IpOption;

    fn ip_dest(addr: SocketAddr) -> Destination {
        Destination::tcp(Address::from(addr.ip()), Port::new(addr.port()))
    }

    /// 确保 rustls CryptoProvider 在并行测试中只初始化一次
    fn ensure_crypto_provider() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        });
    }

    fn make_a_response(req_id: u16, fqdn: &str, ips: Vec<Ipv4Addr>, ttl: u32) -> Vec<u8> {
        let name = Name::parse(fqdn, None).unwrap();
        let mut msg = Message::new(req_id, MessageType::Response, OpCode::Query);
        msg.add_query(Query::query(name.clone(), RecordType::A));
        for ip in ips {
            let rec =
                Record::from_rdata(name.clone(), ttl, RData::A(hickory_proto::rr::rdata::A(ip)));
            msg.add_answer(rec);
        }
        msg.to_vec().unwrap()
    }

    /// 启动 mock DoT server：自签 TLS + accept 一次连接 + 回一个预设 DNS 响应。
    async fn spawn_mock_dot_server(
        fqdn: &str,
        ips: Vec<Ipv4Addr>,
        ttl: u32,
    ) -> (SocketAddr, Arc<ClientConfig>, tokio::task::JoinHandle<()>) {
        spawn_mock_dot_server_delayed(fqdn, ips, ttl, Duration::ZERO, Duration::ZERO).await
    }

    /// 同上，但响应拆两段回：先睡 `len_delay` 回 2B 长度前缀，再睡 `payload_delay`
    /// 回响应体（bd 2iauj：分段预算制下两段读各起一份满额预算）。
    async fn spawn_mock_dot_server_delayed(
        fqdn: &str,
        ips: Vec<Ipv4Addr>,
        ttl: u32,
        len_delay: Duration,
        payload_delay: Duration,
    ) -> (SocketAddr, Arc<ClientConfig>, tokio::task::JoinHandle<()>) {
        ensure_crypto_provider();
        // rcgen 自签证书（SAN: localhost）。
        let cert_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = cert_params.self_signed(&key_pair).unwrap();
        let cert_der = cert.der().to_vec();
        let key_der = key_pair.serialize_der();

        // rustls server config。
        let key = tokio_rustls::rustls::pki_types::PrivateKeyDer::try_from(key_der).unwrap();
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![tokio_rustls::rustls::pki_types::CertificateDer::from(cert_der.clone())],
                key,
            )
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let fqdn_owned = fqdn.to_string();

        let handle = xray_common::testing::spawn("spawn-mock-dot-server-accept", async move {
            let (sock, _) = listener.accept().await.unwrap();
            let tcp = TcpConnection::new(sock);
            let mut tls = acceptor.accept(tcp).await.unwrap();

            // 读 2B 长度 + payload。
            let mut len_buf = [0u8; 2];
            tls.read_exact(&mut len_buf).await.unwrap();
            let plen = usize::from(u16::from_be_bytes(len_buf));
            let mut buf = vec![0u8; plen];
            tls.read_exact(&mut buf).await.unwrap();

            // 用 query ID 构造响应。
            let query_msg = Message::from_vec(&buf).unwrap();
            let resp = make_a_response(query_msg.metadata.id, &fqdn_owned, ips.clone(), ttl);

            // 回写 2B 长度 + response（两段中间可按需延迟）。
            let len = u16::try_from(resp.len()).unwrap().to_be_bytes();
            tokio::time::sleep(len_delay).await;
            tls.write_all(&len).await.unwrap();
            tokio::time::sleep(payload_delay).await;
            tls.write_all(&resp).await.unwrap();
            tls.flush().await.unwrap();
        });

        // 信任自签证书的 client config。
        let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
        root_store.add(tokio_rustls::rustls::pki_types::CertificateDer::from(cert_der)).unwrap();
        let client_config = Arc::new(
            ClientConfig::builder().with_root_certificates(root_store).with_no_client_auth(),
        );

        (addr, client_config, handle)
    }

    #[tokio::test]
    async fn dot_query_once_returns_a_record() {
        let (addr, tls_config, _h) =
            spawn_mock_dot_server("example.com.", vec![Ipv4Addr::new(10, 0, 0, 1)], 120).await;

        let ns = DotNameServer::new(
            ip_dest(addr),
            "localhost".to_string(),
            tls_config,
            Arc::new(CacheController::new("test", true, false, 0, 0)),
            Vec::new(),
            Duration::from_secs(2),
        );
        let rec = ns
            .query_once(
                "example.com.",
                RecordType::A,
                Budget::tokio().deadline(Duration::from_secs(2)),
            )
            .await
            .unwrap();
        assert_eq!(rec.ips.len(), 1);
        assert_eq!(rec.ips[0], IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(rec.ttl_seconds(Instant::now()) <= 120);
    }

    #[tokio::test]
    async fn dot_send_query_v4_only() {
        let (addr, tls_config, _h) =
            spawn_mock_dot_server("z.com.", vec![Ipv4Addr::new(8, 8, 8, 8)], 60).await;

        let ns = DotNameServer::new(
            ip_dest(addr),
            "localhost".to_string(),
            tls_config,
            Arc::new(CacheController::new("test", true, false, 0, 0)),
            Vec::new(),
            Duration::from_secs(2),
        );
        let outcome = ns
            .send_query(
                "z.com.",
                IpOption { ipv4_enable: true, ipv6_enable: false, fake_enable: false },
            )
            .await;
        assert!(outcome.rec_v4.is_some());
        assert!(outcome.rec_v6.is_none());
        assert!(outcome.errors.is_empty());
    }

    #[tokio::test]
    async fn dot_query_tls_handshake_failure() {
        ensure_crypto_provider();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // 不 spawn accept，connect 成功但 TLS 握手必失败。

        // 用信任 localhost 的 config（自签）。
        let cert_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = cert_params.self_signed(&key_pair).unwrap();
        let cert_der = cert.der().to_vec();
        let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
        root_store.add(tokio_rustls::rustls::pki_types::CertificateDer::from(cert_der)).unwrap();
        let tls_config = Arc::new(
            ClientConfig::builder().with_root_certificates(root_store).with_no_client_auth(),
        );

        let ns = DotNameServer::new(
            ip_dest(addr),
            "localhost".to_string(),
            tls_config,
            Arc::new(CacheController::new("test", true, false, 0, 0)),
            Vec::new(),
            Duration::from_millis(500),
        );
        let outcome = ns
            .send_query(
                "bad.com.",
                IpOption { ipv4_enable: true, ipv6_enable: false, fake_enable: false },
            )
            .await;
        // TLS 握手失败或超时。
        assert!(outcome.rec_v4.is_none());
        assert_eq!(outcome.errors.len(), 1);
    }

    /// 实时跑 `send_query`，返回（墙钟耗时, 结果）。
    ///
    /// 不用 tokio 暂停时钟：暂停下真实 socket/TLS IO 不随 advance 推进（本机实测
    /// 拨号在 1s mock 预算内始终未完成），只能靠墙钟测「整条查询多久收场」。
    async fn timed_query(
        ns: Arc<DotNameServer>,
        fqdn: &'static str,
        option: IpOption,
    ) -> (Duration, QueryOutcome) {
        let started = Instant::now();
        let outcome = ns.send_query(fqdn, option).await;
        (started.elapsed(), outcome)
    }

    /// bd 2iauj 回归钉：整条查询 deadline 覆盖**所有阶段**——mock 上游拆两段回
    /// （长度前缀 700ms、正文再 700ms），1s 预算下第二段必须按入口绝对时刻失败。
    /// 分段预算制下两段各起 1s（700+700 都在各段预算内），查询 ~1.4s 成功返回，
    /// 本测试必红。
    #[tokio::test]
    async fn dot_total_deadline_covers_slow_response() {
        let (addr, tls_config, _h) = spawn_mock_dot_server_delayed(
            "slow.com.",
            vec![Ipv4Addr::new(10, 0, 0, 3)],
            60,
            Duration::from_millis(700),
            Duration::from_millis(700),
        )
        .await;
        let ns = Arc::new(DotNameServer::new(
            ip_dest(addr),
            "localhost".to_string(),
            tls_config,
            Arc::new(CacheController::new("test", true, false, 0, 0)),
            Vec::new(),
            Duration::from_secs(1),
        ));

        let (elapsed, outcome) = timed_query(
            ns,
            "slow.com.",
            IpOption { ipv4_enable: true, ipv6_enable: false, fake_enable: false },
        )
        .await;

        // 判别证据：必须死在**第二段读**上（握手/首段失败 = 前提没成立，测试无效）。
        assert_eq!(outcome.errors.len(), 1);
        assert!(
            outcome.errors[0].to_string().contains("dot read payload timeout"),
            "必须在第二段读上按绝对 deadline 失败，got: {:?}",
            outcome.errors
        );
        assert!(
            elapsed >= Duration::from_millis(900) && elapsed <= Duration::from_millis(1350),
            "total query deadline must be 1s, elapsed={elapsed:?}"
        );
    }
}
