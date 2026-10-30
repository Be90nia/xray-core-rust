//! UDP (Classic) DNS nameserver。对应 Go `app/dns/nameserver_udp.go`。
//!
//! ## 实现
//!
//! - `tokio::net::UdpSocket` 直连远端 DNS 服务器（不走 Xray dispatcher， dispatcher 接入留
//!   follow-up）。
//! - DNS wire format 由 `hickory-proto` 处理（覆盖 A/AAAA/MX/TXT/EDNS0）。
//! - 自动接入 cache（实现 `CachedNameserver`，由 `cached::query_ip` 统一调度）。
//! - truncated（TC=1）响应：按 Go 语义在同一 UDP 通道上追加 EDNS0 OPT 重发一次， **不建 TCP
//!   连接**（Go `nameserver_udp.go:118-137` 无 TCP fallback 分支）。
//!
//! ## 跳过范围
//!
//! - 走 Xray routing/dispatcher 出口（直接用 tokio socket）
//! - 请求去重 singleflight（CacheController 层面已部分缓解）

use std::{future::Future, net::IpAddr, pin::Pin, sync::Arc, time::Duration};

use hickory_proto::rr::RecordType;
use skeleton_infra::fx::FxScope;
use tokio::net::UdpSocket;
use xray_common::net::{destination::Destination, port::Port};
use xray_frame::deadline::{Budget, BudgetDeadline};

use crate::{
    cache_controller::CacheController,
    config::IpOption,
    dnscommon::{
        AtomicReqIdGen, IpRecord, ReqIdGen, build_dns_query, build_dns_query_with_opt,
        parse_dns_response, parsed_to_ip_record,
    },
    error::DnsError,
    nameserver::{
        NameServerConfig, Server,
        cached::{CachedNameserver, QueryOutcome, query_ip},
    },
};

/// UDP DNS 查询缓冲区大小（Go 默认 4096；hickory 推荐 1232 + EDNS0）。
const UDP_RECV_BUF: usize = 4096;

/// UDP DNS nameserver。对应 Go `ClassicNameServer`。
pub struct UdpNameServer {
    /// 服务名（含地址，用于日志）。
    name: String,
    /// 远端 DNS 服务器地址（IP 直连；域名运行期解析——bd mcpo）。
    dest: Destination,
    /// 缓存控制器。
    cache: Arc<CacheController>,
    /// EDNS0 client subnet（空 Vec 表示不加）。
    client_ip: Vec<u8>,
    /// 单次查询超时。
    query_timeout: Duration,
    /// 请求 ID 生成器。
    id_gen: AtomicReqIdGen,
    /// 域名解析器（直连兜底路径）。
    resolver: Arc<dyn crate::dial::HostResolver>,
    /// `+local`：强制直连（绕过共享 dialer，Go Local mode nil dispatcher）。
    force_local: bool,
}

impl UdpNameServer {
    /// 构造 UDP nameserver。
    ///
    /// `client_ip` 长度须为 0/4/16（EDNS0 subnet 规范）。
    #[must_use]
    pub fn new(
        dest: Destination,
        cache: Arc<CacheController>,
        client_ip: Vec<u8>,
        query_timeout: Duration,
        resolver: Arc<dyn crate::dial::HostResolver>,
    ) -> Self {
        let name = format!("UDP:{}:{}", dest.address(), dest.port().value());
        Self {
            name,
            dest,
            cache,
            client_ip,
            query_timeout,
            id_gen: AtomicReqIdGen::new(),
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

    /// 从 `NameServerConfig` 构造（`Box<dyn Server>` 形态）。
    ///
    /// `ns.address` 接受 IP 或域名（bd mcpo：域名运行期解析）。
    pub fn from_config(ns: &NameServerConfig) -> Result<Box<dyn Server>, DnsError> {
        // Arc 包装：serveStale 后台 pull 需要共享句柄（Go interface 值共享语义）。
        Ok(Box::new(Arc::new(Self::from_config_bare(ns)?)))
    }

    /// 从 `NameServerConfig` 构造具体类型。cache 4 字段
    /// （disable_cache/serve_stale/serve_expired_ttl/negative_ttl_secs）
    /// 流入 CacheController（Go nameserver.go NewServer 收全量 proto 语义）。
    fn from_config_bare(ns: &NameServerConfig) -> Result<Self, DnsError> {
        let dest = Destination::udp(ns.address.clone(), Port::new(ns.port));
        let timeout = if ns.timeout_ms > 0 {
            Duration::from_millis(u64::from(ns.timeout_ms))
        } else {
            Duration::from_millis(4000)
        };
        let cache = Arc::new(CacheController::new(
            format!("UDP:{}", dest),
            ns.disable_cache.unwrap_or(false),
            ns.serve_stale.unwrap_or(false),
            ns.serve_expired_ttl.unwrap_or(0),
            ns.negative_ttl_secs.unwrap_or(0),
        ));
        // P1-11：cleanup 不在配置期 spawn——启动期经 Server::start_managed_tasks 注册。
        Ok(Self::new(
            dest,
            cache,
            ns.client_ip.clone(),
            timeout,
            Arc::new(crate::dial::SystemHostResolver),
        )
        .force_local(ns.force_local))
    }

    /// 发送单次 DNS 查询并等待响应。
    ///
    /// bd 2iauj：拨号/解析/发送/收包共享调用方传入的整条查询绝对 `deadline`
    /// （Go nameserver_udp.go:161-189 的 dispatch 与等待都在外层 ctx 预算内，
    /// 见 nameserver.go:183 `WithTimeout(ctx, c.timeoutMs)`）。
    ///
    /// TC=1（bd a42ht）：按 Go `nameserver_udp.go:118-137` 在同一条 UDP 通道上追加
    /// EDNS0 OPT + 新 ID 重发**一次**，重发与首包共享同一 `deadline`（Go 复用同一 ctx），
    /// 第二次仍截断则照 Go 把截断应答直接交给 cache（不循环）。
    async fn query_once(
        &self,
        fqdn: &str,
        record_type: RecordType,
        deadline: BudgetDeadline,
    ) -> Result<IpRecord, DnsError> {
        let req_id = self.id_gen.next_id();
        let wire = build_dns_query(fqdn, record_type, req_id, &self.client_ip)?;

        // 共享 dialer 在场：查询经路由出站（Go nameserver_udp.go:134
        // udpServer.Dispatch 包粒度语义，XUDP 帧约定由 dialer 适配层处理）。
        // `+local`（force_local）绕过 dialer 强制直连——Go Local mode nil
        // dispatcher 语义，防 DNS 查询经路由进 proxy（bd wmdn②）。
        let dialer = if self.force_local { None } else { crate::dial::shared_dialer() };
        if let Some(dialer) = dialer {
            let mut session = deadline
                .timeout(dialer.dial_udp(&self.dest))
                .await
                .map_err(|_| {
                    DnsError::WireFormat(format!("udp dial timeout after {:?}", self.query_timeout))
                })?
                .map_err(|e| DnsError::WireFormat(format!("udp dial: {e}")))?;
            deadline
                .timeout(session.send_packet(&self.dest, &wire))
                .await
                .map_err(|_| DnsError::WireFormat("udp dial send timeout".to_string()))?
                .map_err(|e| DnsError::WireFormat(format!("udp dial send: {e}")))?;
            let resp = deadline
                .timeout(session.recv_packet())
                .await
                .map_err(|_| {
                    DnsError::WireFormat(format!(
                        "udp dial recv timeout after {:?}",
                        self.query_timeout
                    ))
                })?
                .map_err(|e| DnsError::WireFormat(format!("udp dial recv: {e}")))?;
            let Some(resp) = resp else {
                return Err(DnsError::WireFormat("udp dial session closed".to_string()));
            };
            // 713x6：解析时刻取自注入时钟（CacheController P1-12 单钟语义）。
            let now = self.cache.clock().now_instant();
            let parsed = parse_dns_response(&resp, req_id, record_type, now)?;
            if !self.should_retry_with_edns0(parsed.truncated) {
                return Ok(parsed_to_ip_record(&parsed, now));
            }
            let (retry_id, retry_wire) = self.edns0_retry_wire(fqdn, record_type)?;
            deadline
                .timeout(session.send_packet(&self.dest, &retry_wire))
                .await
                .map_err(|_| DnsError::WireFormat("udp retry send timeout".to_string()))?
                .map_err(|e| DnsError::WireFormat(format!("udp retry send: {e}")))?;
            let resp = deadline
                .timeout(session.recv_packet())
                .await
                .map_err(|_| {
                    DnsError::WireFormat(format!(
                        "udp retry recv timeout after {:?}",
                        self.query_timeout
                    ))
                })?
                .map_err(|e| DnsError::WireFormat(format!("udp retry recv: {e}")))?;
            let Some(resp) = resp else {
                return Err(DnsError::WireFormat("udp dial session closed".to_string()));
            };
            let now = self.cache.clock().now_instant();
            let parsed = parse_dns_response(&resp, retry_id, record_type, now)?;
            return Ok(parsed_to_ip_record(&parsed, now));
        }

        // 直连兜底：IP 直发；域名每查询现解析（bd mcpo 运行期解析）。
        let sock_addr = deadline
            .timeout(crate::dial::resolve_dest_addr(&self.dest, self.resolver.as_ref()))
            .await
            .map_err(|_| DnsError::WireFormat("udp resolve timeout".to_string()))?
            .map_err(|e| DnsError::WireFormat(format!("udp resolve: {e}")))?;

        // TUN 接管的 DNS 服务器：Xray 自身上游查询拒拨（Go localdns
        // client.go:99-103 同语义），防查询经 TUN 绕回自身。
        if xray_transport::dns_skip::is_skipped_dns_query(sock_addr) {
            return Err(DnsError::SkipDnsServer(sock_addr.to_string()));
        }

        // 绑定任意本地端口。失败多为系统 fd 限制。
        let sock = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| DnsError::WireFormat(format!("udp bind: {e}")))?;
        deadline
            .timeout(sock.send_to(&wire, sock_addr))
            .await
            .map_err(|_| DnsError::WireFormat("udp send timeout".to_string()))?
            .map_err(|e| DnsError::WireFormat(format!("udp send: {e}")))?;

        // 栈上收包缓冲（4 KiB）：免每查询堆分配（NF-7）。
        let mut buf = [0u8; UDP_RECV_BUF];
        let n = deadline
            .timeout(sock.recv(&mut buf))
            .await
            .map_err(|_| {
                DnsError::WireFormat(format!("udp recv timeout after {:?}", self.query_timeout))
            })?
            .map_err(|e| DnsError::WireFormat(format!("udp recv: {e}")))?;

        // 713x6：解析时刻取自注入时钟（CacheController P1-12 单钟语义）。
        let now = self.cache.clock().now_instant();
        let parsed = parse_dns_response(&buf[..n], req_id, record_type, now)?;
        if !self.should_retry_with_edns0(parsed.truncated) {
            return Ok(parsed_to_ip_record(&parsed, now));
        }
        // Go nameserver_udp.go:118-137：同一 UDP 通道追加 EDNS0 OPT + 新 ID 重发一次。
        let (retry_id, retry_wire) = self.edns0_retry_wire(fqdn, record_type)?;
        deadline
            .timeout(sock.send_to(&retry_wire, sock_addr))
            .await
            .map_err(|_| DnsError::WireFormat("udp retry send timeout".to_string()))?
            .map_err(|e| DnsError::WireFormat(format!("udp retry send: {e}")))?;
        let n = deadline
            .timeout(sock.recv(&mut buf))
            .await
            .map_err(|_| {
                DnsError::WireFormat(format!(
                    "udp retry recv timeout after {:?}",
                    self.query_timeout
                ))
            })?
            .map_err(|e| DnsError::WireFormat(format!("udp retry recv: {e}")))?;
        let now = self.cache.clock().now_instant();
        let parsed = parse_dns_response(&buf[..n], retry_id, record_type, now)?;
        Ok(parsed_to_ip_record(&parsed, now))
    }

    /// TC=1 是否要追加 EDNS0 重发。
    ///
    /// Go `nameserver_udp.go:119-121`：截断且**原查询的 Additionals 为空**才重发；
    /// 首包已带 OPT（`clientIp` 在场，见 `build_dns_query`）时直接按截断应答收场。
    fn should_retry_with_edns0(&self, truncated: bool) -> bool {
        truncated && !matches!(self.client_ip.len(), 4 | 16)
    }

    /// 构造重发查询：新 req ID + 追加 OPT（Go `newMsg.ID = s.newReqID()`）。
    fn edns0_retry_wire(
        &self,
        fqdn: &str,
        record_type: RecordType,
    ) -> Result<(u16, Vec<u8>), DnsError> {
        let req_id = self.id_gen.next_id();
        Ok((req_id, build_dns_query_with_opt(fqdn, record_type, req_id)?))
    }
}

impl CachedNameserver for UdpNameServer {
    fn cache_controller(&self) -> &CacheController {
        &self.cache
    }

    async fn send_query(&self, fqdn: &str, option: IpOption) -> QueryOutcome {
        let mut outcome = QueryOutcome::default();

        // bd 2iauj：整条查询只算一次绝对 deadline（Go 语义 = 上层
        // nameserver.go:183 `WithTimeout(ctx, c.timeoutMs)` 一个时刻覆盖整条查询；
        // nameserver_udp.go:161-189 的 dispatch 与响应等待都在该预算内）。
        // W4 面 3：取时统一走 Budget::tokio()（Tokio 源内部 = tokio Instant，
        // pause/advance 语义不变）。
        let deadline = Budget::tokio().deadline(self.query_timeout);

        // 顺序发起 A/AAAA。
        // ponytail: 串行 await。真正并行需 tokio::join! 或 JoinSet，业务上串行也能完成
        // （多 1 个 RTT 的延迟换简化代码）。高并发场景可在 query_once 外层 spawn。
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

impl Server for Arc<UdpNameServer> {
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

/// 构造 UDP nameserver。对应 Go `NewClassicNameServer`。
///
/// 入参：服务端地址（IP + 端口）+ 缓存配置 + EDNS0 client IP。
pub fn new_classic_name_server(ns: &NameServerConfig) -> Result<Box<dyn Server>, DnsError> {
    UdpNameServer::from_config(ns)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::disallowed_methods,
        reason = "713x6：测试计时不得改语义（契约）——测试取时/等待窗口保持原语义，时钟禁令只约束生产路径"
    )]
    use std::{
        io,
        net::{Ipv4Addr, SocketAddr},
        str::FromStr,
        time::Instant,
    };

    use hickory_proto::{
        op::{Message, MessageType, OpCode, Query},
        rr::{Name, RData, Record, RecordType},
    };
    use xray_common::net::address::Address;

    use super::*;
    use crate::config::IpOption;
    /// 共享 dialer 槽是进程级全局：涉 dialer 的测试须串行（全 crate 共用一把锁）。
    use crate::dial::DIALER_SLOT_LOCK;

    fn udp_dest(addr: SocketAddr) -> Destination {
        Destination::udp(Address::from(addr.ip()), Port::new(addr.port()))
    }
    /// 用 hickory 构造一个 DNS 响应 wire bytes（含 A 记录）。
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

    /// 启动 mock UDP DNS server：收到查询后 echo 请求 ID 回复 A 记录。
    async fn spawn_mock_udp_server(
        fqdn: &str,
        ips: Vec<Ipv4Addr>,
        ttl: u32,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let fqdn_owned = fqdn.to_string();
        let handle = xray_common::testing::spawn("spawn-mock-udp-server-udp", async move {
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
    #[allow(clippy::await_holding_lock)] // 测试全局槽位锁刻意跨 await 串行化（无争用场景）
    async fn query_once_returns_parsed_a_record() {
        let _slot = DIALER_SLOT_LOCK.lock();
        let (addr, _h) =
            spawn_mock_udp_server("example.com.", vec![Ipv4Addr::new(1, 2, 3, 4)], 60).await;

        let ns = UdpNameServer::new(
            udp_dest(addr),
            Arc::new(CacheController::new("test", true, false, 0, 0)),
            Vec::new(),
            Duration::from_secs(2),
            Arc::new(crate::dial::SystemHostResolver),
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
        assert_eq!(rec.ips[0], IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(rec.rcode, 0);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // 测试全局槽位锁刻意跨 await 串行化（无争用场景）
    async fn send_query_populates_rec_v4_only() {
        let _slot = DIALER_SLOT_LOCK.lock();
        let (addr, _h) = spawn_mock_udp_server("x.com.", vec![Ipv4Addr::new(9, 9, 9, 9)], 30).await;

        let ns = UdpNameServer::new(
            udp_dest(addr),
            Arc::new(CacheController::new("test", true, false, 0, 0)),
            Vec::new(),
            Duration::from_secs(2),
            Arc::new(crate::dial::SystemHostResolver),
        );
        let outcome = ns
            .send_query(
                "x.com.",
                IpOption { ipv4_enable: true, ipv6_enable: false, fake_enable: false },
            )
            .await;
        assert!(outcome.rec_v4.is_some());
        assert!(outcome.rec_v6.is_none());
        assert!(outcome.errors.is_empty());
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // 测试全局槽位锁刻意跨 await 串行化（无争用场景）
    async fn send_query_records_error_when_server_silent() {
        let _slot = DIALER_SLOT_LOCK.lock();
        // 启 server 但不响应。
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        // _sock drop 后端口仍由 OS 保留 TIME_WAIT，超时测试不依赖 server。
        drop(sock);

        let ns = UdpNameServer::new(
            udp_dest(addr),
            Arc::new(CacheController::new("test", true, false, 0, 0)),
            Vec::new(),
            Duration::from_millis(100),
            Arc::new(crate::dial::SystemHostResolver),
        );
        let outcome = ns
            .send_query(
                "y.com.",
                IpOption { ipv4_enable: true, ipv6_enable: false, fake_enable: false },
            )
            .await;
        assert!(outcome.rec_v4.is_none());
        assert_eq!(outcome.errors.len(), 1);
    }

    /// bd d881② e2e：真实 UDP 上游 + 真实 fetch 路径——正常查询通；静默上游
    /// 的超时错误必须原样透传（不得吞成 RecordNotFound）。
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // 测试全局槽位锁刻意跨 await 串行化（无争用场景）
    async fn fetch_real_upstream_ok_then_timeout_error_passthrough() {
        let _slot = DIALER_SLOT_LOCK.lock();

        // 正常：mock 应答 → fetch Ok。
        let (addr, _h) =
            spawn_mock_udp_server("e2e.com.", vec![Ipv4Addr::new(7, 7, 7, 7)], 60).await;
        let ns = UdpNameServer::new(
            udp_dest(addr),
            Arc::new(CacheController::new("e2e", true, false, 0, 0)),
            Vec::new(),
            Duration::from_secs(2),
            Arc::new(crate::dial::SystemHostResolver),
        );
        let (ips, _) = crate::nameserver::cached::fetch(
            &ns,
            "e2e.com.",
            IpOption { ipv4_enable: true, ipv6_enable: false, fake_enable: false },
        )
        .await
        .unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(7, 7, 7, 7))]);

        // 超时：静默 socket（保持存活，不 drop——端口无监听时 Windows 会以
        // ICMP 不可达打断 recv，只有存活 socket 才能走确定性的 recv 超时路径）
        // → fetch 返回原始超时错误（非 RecordNotFound）。
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let saddr = silent.local_addr().unwrap();
        let ns = UdpNameServer::new(
            udp_dest(saddr),
            Arc::new(CacheController::new("e2e-slow", true, false, 0, 0)),
            Vec::new(),
            Duration::from_millis(150),
            Arc::new(crate::dial::SystemHostResolver),
        );
        let err = crate::nameserver::cached::fetch(
            &ns,
            "slow.com.",
            IpOption { ipv4_enable: true, ipv6_enable: false, fake_enable: false },
        )
        .await
        .unwrap_err();
        assert!(
            matches!(&err, DnsError::WireFormat(s) if s.contains("udp recv timeout")),
            "超时错误必须原样透传，got: {err:?}"
        );
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

    /// bd mcpo：from_config 接受域名（运行期解析，弃启动期钉死）。
    #[test]
    fn from_config_accepts_domain_address() {
        let ns = NameServerConfig {
            address: Address::Domain("dns.example.com".to_string()),
            port: 53,
            ..Default::default()
        };
        let server = UdpNameServer::from_config(&ns).unwrap();
        assert_eq!(server.name(), "UDP:dns.example.com:53");
    }

    /// 记录拨号目标的 mock dialer：真连 dest（UDP echo），验收"查询经路由出站"。
    #[derive(Default)]
    struct RecordingUdpDialer {
        recorded: parking_lot::Mutex<Vec<Destination>>,
    }

    impl crate::dial::QueryDialer for RecordingUdpDialer {
        fn dial_tcp(
            &self,
            _dest: &Destination,
        ) -> Pin<Box<dyn Future<Output = io::Result<crate::dial::DnsStream>> + Send + '_>> {
            Box::pin(async { Err(io::Error::new(io::ErrorKind::Unsupported, "udp test dialer")) })
        }

        fn dial_udp(
            &self,
            dest: &Destination,
        ) -> Pin<
            Box<
                dyn Future<Output = io::Result<Box<dyn crate::dial::UdpPacketSession>>> + Send + '_,
            >,
        > {
            self.recorded.lock().push(dest.clone());
            let dest = dest.clone();
            Box::pin(async move {
                let ip = dest.address().ip().expect("test dest is IP");
                let sock = UdpSocket::bind("0.0.0.0:0").await?;
                sock.connect(SocketAddr::new(ip, dest.port().value())).await?;
                Ok(Box::new(ConnectedUdpSession { sock }) as Box<dyn crate::dial::UdpPacketSession>)
            })
        }
    }

    /// 直连 UDP 会话（单包请求-响应）。
    struct ConnectedUdpSession {
        sock: UdpSocket,
    }

    impl crate::dial::UdpPacketSession for ConnectedUdpSession {
        fn send_packet<'s>(
            &'s mut self,
            _dest: &Destination,
            payload: &'s [u8],
        ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 's>> {
            let sock = &self.sock;
            Box::pin(async move { sock.send(payload).await.map(|_| ()) })
        }

        fn recv_packet(
            &mut self,
        ) -> Pin<Box<dyn Future<Output = io::Result<Option<Vec<u8>>>> + Send + '_>> {
            let sock = &self.sock;
            Box::pin(async move {
                let mut buf = vec![0u8; 4096];
                let n = sock.recv(&mut buf).await?;
                Ok(Some(buf[..n].to_vec()))
            })
        }
    }

    /// bd mcpo 验收②：UDP 查询经路由出站——dialer 收到查询目标，
    /// 数据经 dialer 数据报会话往返。
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // 测试全局槽位锁刻意跨 await 串行化（无争用场景）
    async fn udp_query_routes_through_dialer() {
        let _slot = DIALER_SLOT_LOCK.lock();
        let (addr, _h) =
            spawn_mock_udp_server("routed.com.", vec![Ipv4Addr::new(10, 0, 0, 8)], 60).await;

        let dialer = Arc::new(RecordingUdpDialer::default());
        crate::dial::set_shared_dialer(Some(dialer.clone()));
        let ns = UdpNameServer::new(
            udp_dest(addr),
            Arc::new(CacheController::new("test", true, false, 0, 0)),
            Vec::new(),
            Duration::from_secs(2),
            Arc::new(crate::dial::SystemHostResolver),
        );

        let rec = ns
            .query_once(
                "routed.com.",
                RecordType::A,
                Budget::tokio().deadline(Duration::from_secs(2)),
            )
            .await
            .unwrap();
        crate::dial::set_shared_dialer(None);

        assert_eq!(rec.ips, vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 8))]);
        let recorded = dialer.recorded.lock();
        assert_eq!(recorded.len(), 1, "query must dial through the routing dialer");
        assert_eq!(recorded[0].address(), &Address::from(addr.ip()));
        assert_eq!(recorded[0].port().value(), addr.port());
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

    /// 慢解析器：`resolve` 睡 `delay`（真实时间）后返回固定 IP——模拟域名解析吃掉
    /// 前段预算（Go 的地址解析同样在查询 ctx 预算内）。
    struct SlowResolver {
        delay: Duration,
        ip: IpAddr,
    }

    impl crate::dial::HostResolver for SlowResolver {
        fn resolve(
            &self,
            _host: String,
        ) -> Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send>> {
            let (delay, ip) = (self.delay, self.ip);
            Box::pin(async move {
                tokio::time::sleep(delay).await;
                Ok(vec![ip])
            })
        }
    }

    /// 实时跑 `send_query`，返回（墙钟耗时, 结果）。
    ///
    /// 不用 tokio 暂停时钟：暂停下真实 IO 不随 advance 推进（本机实测拨号在 1s
    /// mock 预算内始终未完成），只能靠墙钟测「整条查询多久收场」。
    async fn timed_query(
        ns: Arc<UdpNameServer>,
        fqdn: &'static str,
        option: IpOption,
    ) -> (Duration, QueryOutcome) {
        let started = Instant::now();
        let outcome = ns.send_query(fqdn, option).await;
        (started.elapsed(), outcome)
    }

    /// bd 2iauj 回归钉：整条查询 deadline 覆盖解析 + 收包——解析吃掉 700ms 后，
    /// 收包只剩 300ms 预算，1s 内必须失败。分段预算制下 recv 另起 1s（≈1.7s 收场），
    /// 本测试必红。
    ///
    /// 不注入共享 dialer（那是进程级全局，会污染并行跑的 doh/dot 测试）；改用域名
    /// NS + 慢解析器走直连路径，同样在「前段吃掉预算」这一判别点上。
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // 测试全局槽位锁刻意跨 await 串行化（无争用场景）
    async fn udp_total_deadline_covers_slow_resolve() {
        // 持锁保证查询不会被别的测试并发装上的共享 dialer 截走。
        let _slot = DIALER_SLOT_LOCK.lock();
        // 存活的静默上游：端口无监听时 Windows 会用 ICMP 不可达打断 recv，
        // 只有存活 socket 才走确定性的 recv 超时路径。
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let saddr = silent.local_addr().unwrap();
        let ns = Arc::new(UdpNameServer::new(
            Destination::udp(Address::Domain("slow.example".to_string()), Port::new(saddr.port())),
            Arc::new(CacheController::new("test", true, false, 0, 0)),
            Vec::new(),
            Duration::from_secs(1),
            Arc::new(SlowResolver { delay: Duration::from_millis(700), ip: saddr.ip() }),
        ));

        let (elapsed, outcome) = timed_query(
            ns,
            "slow.com.",
            IpOption { ipv4_enable: true, ipv6_enable: false, fake_enable: false },
        )
        .await;

        // 判别证据：必须死在**收包**上（解析失败 = 前提没成立，测试无效）。
        assert_eq!(outcome.errors.len(), 1);
        assert!(
            outcome.errors[0].to_string().contains("udp recv timeout"),
            "必须在收包段按绝对 deadline 失败，got: {:?}",
            outcome.errors
        );
        assert!(
            elapsed >= Duration::from_millis(900) && elapsed <= Duration::from_millis(1350),
            "total query deadline must be 1s, elapsed={elapsed:?}"
        );
    }

    /// 断言查询包尾部追加了 Go 语义的 EDNS0 OPT：
    /// root / TYPE=41 / CLASS=1350 / TTL=0xE0008000(DO=1) / RDLENGTH=0
    /// （Go `SetEDNS0(1350, 0xfe00, true)` + 空 `OPTResource`）。
    fn assert_go_edns0_opt(wire: &[u8]) {
        assert_eq!(&wire[10..12], [0x00, 0x01], "ARCOUNT=1（追加 OPT）");
        let tail = &wire[wire.len() - 11..];
        assert_eq!(
            tail,
            [0x00, 0x00, 0x29, 0x05, 0x46, 0xe0, 0x00, 0x80, 0x00, 0x00, 0x00],
            "OPT 字节 = root|TYPE=41|CLASS=1350|TTL=0xE0008000|RDLENGTH=0, got {tail:02x?}"
        );
    }

    /// 上游 mock 记下的查询包（原始字节 + 来源地址）。
    type RecordedQuery = (Vec<u8>, SocketAddr);

    /// bd a42ht：UDP 应答 TC=1 → Go 语义是「同一 UDP 通道追加 EDNS0 OPT(1350, DO=1)
    /// + 新 req ID 重发」，不是 TCP fallback（Go `nameserver_udp.go:118-137` 无 TCP 分支）。
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // 测试全局槽位锁刻意跨 await 串行化（无争用场景）
    async fn truncated_response_retries_with_edns0_over_udp() {
        let _slot = DIALER_SLOT_LOCK.lock();
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let seen: Arc<parking_lot::Mutex<Vec<RecordedQuery>>> = Arc::default();
        let seen_srv = seen.clone();
        let _srv = xray_common::testing::spawn("dns-tc1-edns0-retry", async move {
            let mut buf = vec![0u8; 4096];
            // 第一包 → 回 TC=1（0 答案，真实截断应答形态）。
            let (n, peer) = sock.recv_from(&mut buf).await.unwrap();
            seen_srv.lock().push((buf[..n].to_vec(), peer));
            let first = Message::from_vec(&buf[..n]).unwrap();
            let mut trunc = Message::new(first.metadata.id, MessageType::Response, OpCode::Query);
            trunc.add_query(Query::query(Name::parse("tc1.com.", None).unwrap(), RecordType::A));
            trunc.metadata.truncation = true;
            sock.send_to(&trunc.to_vec().unwrap(), peer).await.unwrap();

            // 第二包 → 回 A 记录。
            let (n, peer) = sock.recv_from(&mut buf).await.unwrap();
            seen_srv.lock().push((buf[..n].to_vec(), peer));
            let second = Message::from_vec(&buf[..n]).unwrap();
            let resp = make_a_response(
                second.metadata.id,
                "tc1.com.",
                vec![Ipv4Addr::new(1, 1, 1, 1)],
                60,
            );
            sock.send_to(&resp, peer).await.unwrap();
        });

        let ns = UdpNameServer::new(
            udp_dest(addr),
            Arc::new(CacheController::new("test", true, false, 0, 0)),
            Vec::new(),
            Duration::from_secs(2),
            Arc::new(crate::dial::SystemHostResolver),
        );
        let rec = ns
            .query_once("tc1.com.", RecordType::A, Budget::tokio().deadline(Duration::from_secs(2)))
            .await
            .expect("TC=1 后 EDNS0 UDP 重发必须拿到答案");
        assert_eq!(rec.ips, vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]);

        let seen = seen.lock();
        assert_eq!(seen.len(), 2, "TC=1 必须在 UDP 上重发一次（走 TCP fallback 时这里只有 1 包）");
        assert_eq!(seen[0].1, seen[1].1, "重发必须复用同一 UDP 源端口（零额外连接）");
        let first_id = u16::from_be_bytes([seen[0].0[0], seen[0].0[1]]);
        let retry_id = u16::from_be_bytes([seen[1].0[0], seen[1].0[1]]);
        assert_ne!(retry_id, first_id, "重发必须用新 req ID");
        assert_eq!(&seen[0].0[10..12], [0x00, 0x00], "首包无 EDNS0（ARCOUNT=0）");
        assert_go_edns0_opt(&seen[1].0);
    }

    /// bd a42ht：首包已带 EDNS0（clientIp 在场）时 Go 不再重发，直接按截断应答收场
    /// （Go `nameserver_udp.go:121` `len(req.msg.Additionals) == 0` 门）。
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // 测试全局槽位锁刻意跨 await 串行化（无争用场景）
    async fn truncated_response_with_existing_edns0_is_not_retried() {
        let _slot = DIALER_SLOT_LOCK.lock();
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let resends: Arc<parking_lot::Mutex<u32>> = Arc::default();
        let resends_srv = resends.clone();
        let _srv = xray_common::testing::spawn("dns-tc1-edns0-gate", async move {
            let mut buf = vec![0u8; 4096];
            let (n, peer) = sock.recv_from(&mut buf).await.unwrap();
            let query = Message::from_vec(&buf[..n]).unwrap();
            let mut trunc = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
            trunc.add_query(Query::query(Name::parse("tc2.com.", None).unwrap(), RecordType::A));
            trunc.metadata.truncation = true;
            sock.send_to(&trunc.to_vec().unwrap(), peer).await.unwrap();
            // 重发窗：Go 语义下不该再来第二包。
            let mut buf2 = [0u8; 4096];
            if tokio::time::timeout(Duration::from_millis(300), sock.recv_from(&mut buf2))
                .await
                .is_ok()
            {
                *resends_srv.lock() += 1;
            }
        });

        let ns = UdpNameServer::new(
            udp_dest(addr),
            Arc::new(CacheController::new("test", true, false, 0, 0)),
            vec![1, 2, 3, 4],
            Duration::from_secs(2),
            Arc::new(crate::dial::SystemHostResolver),
        );
        let rec = ns
            .query_once("tc2.com.", RecordType::A, Budget::tokio().deadline(Duration::from_secs(2)))
            .await
            .expect("已有 EDNS0 的截断应答按 Go 语义直接收场");
        assert!(rec.ips.is_empty(), "截断应答无答案，got {:?}", rec.ips);
        assert_eq!(*resends.lock(), 0, "已有 EDNS0 时不得重发");
    }

    /// 记录查询包的假 UDP 会话：首包回 TC=1，重发包回 A 记录。
    struct Tc1RecordingSession {
        sent: Arc<parking_lot::Mutex<Vec<Vec<u8>>>>,
        req_id: u16,
        calls: u8,
    }

    impl crate::dial::UdpPacketSession for Tc1RecordingSession {
        fn send_packet<'s>(
            &'s mut self,
            _dest: &'s Destination,
            payload: &'s [u8],
        ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 's>> {
            self.sent.lock().push(payload.to_vec());
            if let [hi, lo, ..] = payload {
                self.req_id = u16::from_be_bytes([*hi, *lo]);
            }
            Box::pin(async { Ok(()) })
        }

        fn recv_packet(
            &mut self,
        ) -> Pin<Box<dyn Future<Output = io::Result<Option<Vec<u8>>>> + Send + '_>> {
            self.calls += 1;
            let first = self.calls == 1;
            let req_id = self.req_id;
            Box::pin(async move {
                let name = Name::parse("rt.com.", None).unwrap();
                let mut msg = Message::new(req_id, MessageType::Response, OpCode::Query);
                msg.add_query(Query::query(name.clone(), RecordType::A));
                if first {
                    msg.metadata.truncation = true;
                    return Ok(Some(msg.to_vec().unwrap()));
                }
                msg.add_answer(Record::from_rdata(
                    name,
                    60,
                    RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::new(2, 2, 2, 2))),
                ));
                Ok(Some(msg.to_vec().unwrap()))
            })
        }
    }

    /// 记录查询包的假 dialer：UDP 会话按首包/重发包作答，供路由路径验证重发。
    #[derive(Default)]
    struct Tc1RecordingDialer {
        sent: Arc<parking_lot::Mutex<Vec<Vec<u8>>>>,
    }

    impl crate::dial::QueryDialer for Tc1RecordingDialer {
        fn dial_tcp(
            &self,
            _dest: &Destination,
        ) -> Pin<Box<dyn Future<Output = io::Result<crate::dial::DnsStream>> + Send + '_>> {
            Box::pin(async { Err(io::Error::new(io::ErrorKind::Unsupported, "tc1 test dialer")) })
        }

        fn dial_udp(
            &self,
            _dest: &Destination,
        ) -> Pin<
            Box<
                dyn Future<Output = io::Result<Box<dyn crate::dial::UdpPacketSession>>> + Send + '_,
            >,
        > {
            let sent = self.sent.clone();
            Box::pin(async move {
                Ok(Box::new(Tc1RecordingSession { sent, req_id: 0, calls: 0 }) as Box<_>)
            })
        }
    }

    /// 路由出站路径（共享 dialer）同样按 Go 语义在**同一 UDP 会话**上重发。
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // 测试全局槽位锁刻意跨 await 串行化（无争用场景）
    async fn dialer_path_retries_truncated_with_edns0_over_udp() {
        let _slot = DIALER_SLOT_LOCK.lock();
        let dialer = Arc::new(Tc1RecordingDialer::default());
        crate::dial::set_shared_dialer(Some(dialer.clone()));
        let ns = UdpNameServer::new(
            udp_dest(SocketAddr::from_str("127.0.0.1:53").unwrap()),
            Arc::new(CacheController::new("test", true, false, 0, 0)),
            Vec::new(),
            Duration::from_secs(2),
            Arc::new(crate::dial::SystemHostResolver),
        );
        let outcome = ns
            .query_once("rt.com.", RecordType::A, Budget::tokio().deadline(Duration::from_secs(2)))
            .await;
        crate::dial::set_shared_dialer(None);

        let rec = outcome.expect("路由路径的 EDNS0 重发必须拿到答案");
        assert_eq!(rec.ips, vec![IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2))]);
        let sent = dialer.sent.lock();
        assert_eq!(sent.len(), 2, "TC=1 必须在同一 UDP 会话上重发一次");
        assert_eq!(&sent[0][10..12], [0x00, 0x00], "首包无 EDNS0（ARCOUNT=0）");
        assert_go_edns0_opt(&sent[1]);
        assert_ne!(
            u16::from_be_bytes([sent[0][0], sent[0][1]]),
            u16::from_be_bytes([sent[1][0], sent[1][1]]),
            "重发必须用新 req ID"
        );
    }
}
