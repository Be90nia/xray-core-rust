//! B 组实测探针：DNS 五种 NS 的单次查询耗时与上界。
//!
//! 审计 2026-11-04 · outbound/dns/fallback 三侧逐路径。
//!
//! **只读探针**：不改任何产品代码。
//!
//! 覆盖：
//! - B-1 UDP NS：正常应答耗时 / 黑洞上界（= 单次查询 timeout）。
//! - B-1c UDP NS：单 socket 复用（连查 N 次 → `UdpSocket::bind` 只 1 次）。
//! - B-2 TCP NS：正常应答耗时 / 黑洞上界。
//! - B-3 DoT NS：正常应答耗时（含 TLS 握手）/ 黑洞上界。
//! - B-4 DoH NS：黑洞上界（整条查询共享一个 deadline ⇒ 1×query_timeout）。
//! - B-4b DoH NS：**会话复用**（bd yzhb4：3 次查询上游 accept ≤2）。
//! - B-4c DoH NS：会话被对端关闭后自动重建（下次查询仍成功，accept +1）。
//! - B-5 DoQ NS：黑洞上界。
//! - B-6 `cached.rs` singleflight 等待者超时（`SF_WAIT_TIMEOUT = 4s`）。
//! - B-7 `server.rs` `serial_query` N 个 NS 串行 fallback 的总上界（N=2 / N=3）。
//!
//! 复现（**必须 release**——debug 构建会放大闭包/分配成本一个量级）：
//! ```text
//! cargo test --release -p xray-app-dns --test ns_query_latency_probe -- --nocapture --test-threads=1
//! ```
//!
//! 纪律：探针产物只读；不改 src；不复用其他 crate 的私有 seam。
//!
//! L3 闸豁免（探针文件专属性状，与生产路径无关）：`unwrap` = 本地 mock 夹具；
//! `Instant::now` = 测真实墙钟耗时（禁止注入钟，否则测的不是真延迟）；
//! `println!` = `[PROBE]` 取证行本身（`--nocapture` 采集）。生产代码零豁免。
#![allow(
    clippy::unwrap_used,
    clippy::disallowed_methods,
    clippy::disallowed_macros,
    reason = "探针文件：mock 夹具 unwrap + 真实墙钟计时 + [PROBE] stdout 取证行（拒注入钟即失去测量意义）；生产代码不受此豁免"
)]

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use hickory_proto::{
    op::{Message, MessageType, OpCode, Query},
    rr::{Name, RData, Record, RecordType},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};
use xray_app_dns::{
    cache_controller::CacheController,
    config::IpOption,
    nameserver::{
        NameServerConfig, Server, cached::CachedNameserver, tcp::TcpNameServer, udp::UdpNameServer,
    },
    server::DnsService,
};
use xray_common::net::{address::Address, destination::Destination, port::Port};

/// 打印一行探针结果（`[PROBE]` 前缀便于 grep）。
fn probe(label: &str, detail: impl std::fmt::Display) {
    println!("[PROBE] {label:<52} {detail}");
}

/// 生产缺省单次查询超时（`nameserver/mod.rs` Client.timeout 缺省 4000ms；
/// DoH 缺省 5000ms，见 `nameserver/doh.rs:96-102`）。
const DEFAULT_QUERY_TIMEOUT_MS: u32 = 4000;
/// 探针用**缩短**的 query timeout（黑洞上界按此值实测，生产值另注）。
const PROBE_TIMEOUT_MS: u32 = 400;

/// UDP destination 构造（对齐 nameserver 单测 helper）。
fn udp_dest(addr: SocketAddr) -> Destination {
    Destination::udp(Address::from(addr.ip()), Port::new(addr.port()))
}

/// TCP destination 构造。
fn tcp_dest(addr: SocketAddr) -> Destination {
    Destination::tcp(Address::from(addr.ip()), Port::new(addr.port()))
}

/// 构造 A 族应答（req_id 由调用方从查询里取）。
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

/// 起一个 mock UDP DNS server：收查询 → 立即回 A 记录。
/// 返回 (地址, 收到查询数)。
async fn spawn_mock_udp_server(
    fqdn: &str,
    ips: Vec<Ipv4Addr>,
    ttl: u32,
) -> (SocketAddr, Arc<AtomicUsize>) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let count_c = Arc::clone(&count);
    let fqdn = fqdn.to_string();
    xray_common::testing::spawn("ns-latency-probe-udp-server", async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((n, peer)) = sock.recv_from(&mut buf).await else { return };
            count_c.fetch_add(1, Ordering::SeqCst);
            let Ok(query_msg) = Message::from_vec(&buf[..n]) else { continue };
            let resp = make_a_response(query_msg.metadata.id, &fqdn, ips.clone(), ttl);
            let _ = sock.send_to(&resp, peer).await;
        }
    });
    (addr, count)
}

/// 起一个 mock TCP DNS server：2 字节大端长度前缀分帧（Go
/// `app/dns/nameserver_tcp.go:171` 同形）→ 回 A 记录。
/// 返回 (地址, 收到查询数)。
async fn spawn_mock_tcp_server(
    fqdn: &str,
    ips: Vec<Ipv4Addr>,
    ttl: u32,
) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let count_c = Arc::clone(&count);
    let fqdn = fqdn.to_string();
    xray_common::testing::spawn("ns-latency-probe-tcp-server", async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else { return };
            let count_c = Arc::clone(&count_c);
            let fqdn = fqdn.clone();
            let ips = ips.clone();
            xray_common::testing::spawn("ns-latency-probe-tcp-conn", async move {
                let mut len_buf = [0u8; 2];
                if sock.read_exact(&mut len_buf).await.is_err() {
                    return;
                }
                let len = usize::from(u16::from_be_bytes(len_buf));
                if len == 0 || len > 65535 {
                    return;
                }
                let mut payload = vec![0u8; len];
                if sock.read_exact(&mut payload).await.is_err() {
                    return;
                }
                let Ok(query_msg) = Message::from_vec(&payload) else { return };
                count_c.fetch_add(1, Ordering::SeqCst);
                let resp = make_a_response(query_msg.metadata.id, &fqdn, ips, ttl);
                let _ = sock.write_all(&(resp.len() as u16).to_be_bytes()).await;
                let _ = sock.write_all(&resp).await;
                let _ = sock.flush().await;
            });
        }
    });
    (addr, count)
}

/// 起一个**黑洞** UDP server：收包但永不回应（模拟上游静默丢包）。
async fn spawn_blackhole_udp_server() -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    xray_common::testing::spawn("ns-latency-probe-blackhole-udp", async move {
        let mut buf = vec![0u8; 4096];
        loop {
            if sock.recv_from(&mut buf).await.is_err() {
                return;
            }
        }
    });
    addr
}

/// 起一个**黑洞** TCP server：accept 后永不回应（模拟上游连上但不答）。
async fn spawn_blackhole_tcp_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    xray_common::testing::spawn("ns-latency-probe-blackhole-tcp", async move {
        let mut held = Vec::new();
        loop {
            let Ok((sock, _)) = listener.accept().await else { return };
            held.push(sock);
        }
    });
    addr
}

/// 起一个 **h2c 计数** DoH server（明文 HTTP/2，对应产品 `plain_h2c` 形态）：
/// 逐连接独立任务、连接内可多请求，记录 TCP accept 次数。
///
/// 复用 TLS 形态与 h2c 形态走同一条会话槽路径（`open_session`/`exchange`），
/// TLS 握手段的复用由 `nameserver::doh` 单测（真实自签 TLS + ALPN h2）覆盖。
///
/// `close_after_first_response`：每条连接回完第一个响应后，等客户端复用（第二个
/// 请求到达）即断开——模拟对端关连接（测「会话失效 → 重建」）。
async fn spawn_counting_h2c_doh_server(
    fqdn: &str,
    ips: Vec<Ipv4Addr>,
    ttl: u32,
    close_after_first_response: bool,
) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepts = Arc::new(AtomicUsize::new(0));
    let accepts_c = Arc::clone(&accepts);
    let fqdn = fqdn.to_string();
    xray_common::testing::spawn("ns-latency-probe-h2c-doh", async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else { return };
            accepts_c.fetch_add(1, Ordering::SeqCst);
            let fqdn = fqdn.clone();
            let ips = ips.clone();
            xray_common::testing::spawn("ns-latency-probe-h2c-doh-conn", async move {
                let Ok(mut h2) = h2::server::handshake(sock).await else { return };
                let mut served = 0usize;
                while let Some(req) = h2.accept().await {
                    let Ok((req, mut respond)) = req else { break };
                    if close_after_first_response && served > 0 {
                        return; // 复用的第二个请求：断开连接（对端关闭语义）
                    }
                    let mut body = req.into_body();
                    let mut buf = Vec::new();
                    while let Some(chunk) = body.data().await {
                        let Ok(chunk) = chunk else { return };
                        buf.extend_from_slice(&chunk);
                    }
                    let Ok(q) = Message::from_vec(&buf) else { return };
                    let payload = make_a_response(q.metadata.id, &fqdn, ips.clone(), ttl);
                    let resp = http::Response::builder()
                        .status(http::StatusCode::OK)
                        .header(http::header::CONTENT_TYPE, "application/dns-message")
                        .body(())
                        .unwrap();
                    let Ok(mut send) = respond.send_response(resp, false) else { return };
                    if send.send_data(bytes::Bytes::from(payload), true).is_err() {
                        return;
                    }
                    served += 1;
                }
            });
        }
    });
    (addr, accepts)
}

/// 构造 h2c 形态的 DoH NS（禁缓存，避免跨用例污染）。
fn h2c_doh_ns(addr: SocketAddr, tag: &str) -> Arc<xray_app_dns::nameserver::doh::DohNameServer> {
    Arc::new(xray_app_dns::nameserver::doh::DohNameServer::new(
        tcp_dest(addr),
        addr.to_string(),
        xray_tls::utls::default_client_config(),
        Arc::new(CacheController::new(tag, true, false, 0, 0)),
        Vec::new(),
        Duration::from_millis(u64::from(PROBE_TIMEOUT_MS)),
        true,
    ))
}

/// 构造一个 UDP NS server（禁缓存，避免跨用例污染）。
fn udp_ns_server(addr: SocketAddr, timeout_ms: u32) -> Box<dyn Server> {
    Box::new(Arc::new(UdpNameServer::new(
        udp_dest(addr),
        Arc::new(CacheController::new("probe-udp", true, false, 0, 0)),
        Vec::new(),
        Duration::from_millis(u64::from(timeout_ms)),
        Arc::new(xray_app_dns::dial::SystemHostResolver),
    )))
}

/// 构造一个 TCP NS server（禁缓存）。
fn tcp_ns_server(addr: SocketAddr, timeout_ms: u32) -> Box<dyn Server> {
    Box::new(Arc::new(TcpNameServer::new(
        tcp_dest(addr),
        Arc::new(CacheController::new("probe-tcp", true, false, 0, 0)),
        Vec::new(),
        Duration::from_millis(u64::from(timeout_ms)),
        Arc::new(xray_app_dns::dial::SystemHostResolver),
    )))
}

/// 构造 `Client`（包 server + timeout）。
fn client_for(server: Box<dyn Server>, timeout_ms: u32) -> Arc<xray_app_dns::nameserver::Client> {
    let ns = NameServerConfig {
        address: Address::IPv4(Ipv4Addr::UNSPECIFIED),
        timeout_ms,
        ..NameServerConfig::default()
    };
    Arc::new(
        xray_app_dns::nameserver::Client::new(
            ns,
            IpOption { ipv4_enable: true, ipv6_enable: false, fake_enable: false },
            server,
        )
        .expect("client"),
    )
}

/// 构造 `DnsService`（串行/并行由 `parallel` 决定）。
fn dns_service(clients: Vec<Arc<xray_app_dns::nameserver::Client>>, parallel: bool) -> DnsService {
    use xray_app_dns::{hosts::StaticHosts, server::DnsServiceConfig};

    DnsService::new(DnsServiceConfig {
        client_ip: Vec::new(),
        query_strategy: xray_app_dns::config::QueryStrategy::UseIp,
        tag: "ns-latency-probe".to_string(),
        hosts: StaticHosts::new(Vec::new()).expect("empty hosts"),
        clients,
        disable_fallback: false,
        disable_fallback_if_match: false,
        enable_parallel_query: parallel,
        disable_cache: false,
        serve_stale: false,
        serve_expired_ttl: 0,
        use_system_hosts: false,
        domain_matcher: None,
        matcher_infos: Vec::new(),
    })
}

/// B-1：UDP NS 正常应答耗时（loopback mock ⇒ 纯协议开销）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn b1_udp_ns_normal_response_latency() {
    let (addr, count) =
        spawn_mock_udp_server("example.com.", vec![Ipv4Addr::new(1, 2, 3, 4)], 60).await;
    let client =
        client_for(udp_ns_server(addr, DEFAULT_QUERY_TIMEOUT_MS), DEFAULT_QUERY_TIMEOUT_MS);

    let t0 = Instant::now();
    let (ips, _ttl) = client
        .query_ip(
            "example.com",
            IpOption { ipv4_enable: true, ipv6_enable: false, fake_enable: false },
        )
        .await
        .expect("udp query");
    let elapsed = t0.elapsed();
    probe(
        "B-1 UDP NS 正常应答耗时（loopback mock）",
        format!("{elapsed:?} ips={ips:?} queries={}", count.load(Ordering::SeqCst)),
    );
    assert_eq!(ips.len(), 1);
    assert_eq!(count.load(Ordering::SeqCst), 1, "一次查询 ⇒ 上游收 1 次");
}

/// B-1c：单 socket 复用——同一 NS 连查 N 次，`UdpSocket::bind` 只发生 1 次
/// （修复前 = 每查询 1 次 bind，55.1µs/次）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn b1c_udp_ns_reuses_one_socket_across_queries() {
    const QUERIES: usize = 5;
    let (addr, count) =
        spawn_mock_udp_server("example.com.", vec![Ipv4Addr::new(1, 2, 3, 4)], 60).await;
    let ns = Arc::new(UdpNameServer::new(
        udp_dest(addr),
        Arc::new(CacheController::new("probe-udp-single-socket", true, false, 0, 0)),
        Vec::new(),
        Duration::from_millis(u64::from(DEFAULT_QUERY_TIMEOUT_MS)),
        Arc::new(xray_app_dns::dial::SystemHostResolver),
    ));
    let client = client_for(Box::new(Arc::clone(&ns)), DEFAULT_QUERY_TIMEOUT_MS);

    for _ in 0..QUERIES {
        client
            .query_ip(
                "example.com",
                IpOption { ipv4_enable: true, ipv6_enable: false, fake_enable: false },
            )
            .await
            .expect("udp query");
    }

    let binds = ns.socket_bind_count();
    probe(
        "B-1c UDP NS 连查 5 次 → UdpSocket::bind 次数",
        format!("binds={binds} queries={}", count.load(Ordering::SeqCst)),
    );
    assert_eq!(count.load(Ordering::SeqCst), QUERIES, "每次查询都应打上游");
    assert_eq!(binds, 1, "单 socket 复用：{QUERIES} 次查询只应 bind 1 次，实测 {binds}");
}

/// B-1b：UDP NS 黑洞上界 = 单次 query timeout（**不叠加**）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn b1_udp_ns_blackhole_upper_bound_is_one_timeout() {
    let addr = spawn_blackhole_udp_server().await;
    let client = client_for(udp_ns_server(addr, PROBE_TIMEOUT_MS), PROBE_TIMEOUT_MS);

    let t0 = Instant::now();
    let r = client
        .query_ip(
            "blackhole.test",
            IpOption { ipv4_enable: true, ipv6_enable: false, fake_enable: false },
        )
        .await;
    let elapsed = t0.elapsed();
    probe(
        "B-1b UDP NS 黑洞上界（timeout=400ms）",
        format!("{elapsed:?} err={:?}", r.as_ref().err().map(|e| e.to_string())),
    );
    assert!(r.is_err(), "黑洞查询必须失败");
    // 上界判据：≈1×timeout（不是 2×，不是无界）。
    assert!(
        elapsed >= Duration::from_millis(u64::from(PROBE_TIMEOUT_MS)),
        "黑洞查询应至少吃满 timeout，实测 {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_millis(u64::from(PROBE_TIMEOUT_MS) * 2),
        "黑洞查询应 <2×timeout（单次预算不叠加），实测 {elapsed:?}"
    );
}

/// B-2：TCP NS 正常应答耗时 + 黑洞上界。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn b2_tcp_ns_normal_and_blackhole_latency() {
    // 正常
    let (addr, count) =
        spawn_mock_tcp_server("example.com.", vec![Ipv4Addr::new(1, 2, 3, 4)], 60).await;
    let client =
        client_for(tcp_ns_server(addr, DEFAULT_QUERY_TIMEOUT_MS), DEFAULT_QUERY_TIMEOUT_MS);
    let t0 = Instant::now();
    let (ips, _ttl) = client
        .query_ip(
            "example.com",
            IpOption { ipv4_enable: true, ipv6_enable: false, fake_enable: false },
        )
        .await
        .expect("tcp query");
    let normal = t0.elapsed();
    probe(
        "B-2 TCP NS 正常应答耗时（loopback mock）",
        format!("{normal:?} ips={ips:?} queries={}", count.load(Ordering::SeqCst)),
    );
    assert_eq!(ips.len(), 1);

    // 黑洞
    let bh = spawn_blackhole_tcp_server().await;
    let client = client_for(tcp_ns_server(bh, PROBE_TIMEOUT_MS), PROBE_TIMEOUT_MS);
    let t0 = Instant::now();
    let r = client
        .query_ip(
            "blackhole.test",
            IpOption { ipv4_enable: true, ipv6_enable: false, fake_enable: false },
        )
        .await;
    let elapsed = t0.elapsed();
    probe(
        "B-2b TCP NS 黑洞上界（timeout=400ms）",
        format!("{elapsed:?} err={:?}", r.as_ref().err().map(|e| e.to_string())),
    );
    assert!(r.is_err(), "黑洞查询必须失败");
    assert!(
        elapsed >= Duration::from_millis(u64::from(PROBE_TIMEOUT_MS)),
        "黑洞查询应至少吃满 timeout，实测 {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_millis(u64::from(PROBE_TIMEOUT_MS) * 2),
        "黑洞查询应 <2×timeout，实测 {elapsed:?}"
    );
}

/// B-3：DoT NS 黑洞上界（TLS 握手 + 查询共享整条查询 deadline）。
///
/// DoT 需 TLS server ⇒ 用**黑洞 TCP**（accept 后不答）模拟「TLS 握手悬挂」：
/// 客户端的 TLS 握手等不到 ServerHello ⇒ 整条查询吃满 query_timeout。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn b3_dot_ns_blackhole_upper_bound_is_one_timeout() {
    // 黑洞 TCP：accept 后不写任何字节 ⇒ TLS 握手悬挂。
    let bh = spawn_blackhole_tcp_server().await;
    let cfg = xray_tls::utls::default_client_config();
    let ns = Arc::new(xray_app_dns::nameserver::dot::DotNameServer::new(
        tcp_dest(bh),
        "localhost".to_string(),
        cfg,
        Arc::new(CacheController::new("probe-dot", true, false, 0, 0)),
        Vec::new(),
        Duration::from_millis(u64::from(PROBE_TIMEOUT_MS)),
    ));
    let client = client_for(Box::new(ns) as Box<dyn Server>, PROBE_TIMEOUT_MS);

    let t0 = Instant::now();
    let r = client
        .query_ip(
            "blackhole.test",
            IpOption { ipv4_enable: true, ipv6_enable: false, fake_enable: false },
        )
        .await;
    let elapsed = t0.elapsed();
    probe(
        "B-3 DoT NS 黑洞上界（timeout=400ms）",
        format!("{elapsed:?} err={:?}", r.as_ref().err().map(|e| e.to_string())),
    );
    assert!(r.is_err(), "黑洞 DoT 查询必须失败");
    assert!(
        elapsed >= Duration::from_millis(u64::from(PROBE_TIMEOUT_MS)),
        "DoT 黑洞查询应至少吃满 timeout，实测 {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_millis(u64::from(PROBE_TIMEOUT_MS) * 2),
        "DoT 黑洞查询应 <2×timeout（TLS 握手不另起预算），实测 {elapsed:?}"
    );
}

/// B-4：DoH NS 黑洞上界（整条查询共享一个 deadline）。
///
/// 黑洞对端从不完成 TLS 握手 ⇒ 握手悬挂吃满 query_timeout（**不叠加**）。
/// 会话复用（bd yzhb4）不改这条语义：新建连接的握手同样受整查询 deadline 封顶，
/// 复用失败回退重建也共享同一 deadline。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn b4_doh_ns_blackhole_upper_bound_is_one_timeout() {
    let bh = spawn_blackhole_tcp_server().await;
    let cfg = xray_tls::utls::default_client_config();
    let ns = Arc::new(xray_app_dns::nameserver::doh::DohNameServer::new(
        tcp_dest(bh),
        "localhost".to_string(),
        cfg,
        Arc::new(CacheController::new("probe-doh", true, false, 0, 0)),
        Vec::new(),
        Duration::from_millis(u64::from(PROBE_TIMEOUT_MS)),
        false,
    ));
    // DoH 的 `query_once` 要求 cache 已附着 fx scope（生产由 `DnsService::start()`
    // → `Server::start_managed_tasks` 注单）。探针走同一注单面。
    let fx = std::sync::Arc::new(skeleton_infra::fx::FxScope::new());
    ns.start_managed_tasks(&fx);
    let client = client_for(Box::new(ns) as Box<dyn Server>, PROBE_TIMEOUT_MS);

    let t0 = Instant::now();
    let r = client
        .query_ip(
            "blackhole.test",
            IpOption { ipv4_enable: true, ipv6_enable: false, fake_enable: false },
        )
        .await;
    let elapsed = t0.elapsed();
    probe(
        "B-4 DoH NS 黑洞上界（timeout=400ms）",
        format!("{elapsed:?} err={:?}", r.as_ref().err().map(|e| e.to_string())),
    );
    assert!(r.is_err(), "黑洞 DoH 查询必须失败");
    assert!(
        elapsed >= Duration::from_millis(u64::from(PROBE_TIMEOUT_MS)),
        "DoH 黑洞查询应至少吃满 timeout，实测 {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_millis(u64::from(PROBE_TIMEOUT_MS) * 2),
        "DoH 黑洞查询应 <2×timeout（单查询共享 deadline），实测 {elapsed:?}"
    );
    let _ = fx.shutdown().await;
}

/// B-4b：DoH **会话复用**（bd yzhb4）——同一 NS 连续 N 次查询只建 1 条连接。
///
/// 改前：`query_once` 每查询都 `connect_stream` + TLS + `client::handshake`
/// ⇒ N 次查询 = N 次 accept。改后热会话入槽复用（h2 多路复用 1 条承载全部
/// 查询）⇒ 3 次查询 accepts ≤2。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn b4b_doh_ns_reuses_session_across_queries() {
    let (addr, accepts) =
        spawn_counting_h2c_doh_server("reuse.test.", vec![Ipv4Addr::new(10, 1, 2, 3)], 60, false)
            .await;
    let ns = h2c_doh_ns(addr, "probe-doh-reuse");
    let fx = std::sync::Arc::new(skeleton_infra::fx::FxScope::new());
    ns.start_managed_tasks(&fx);
    let client = client_for(Box::new(ns) as Box<dyn Server>, PROBE_TIMEOUT_MS);

    const N: usize = 3;
    let mut ok = 0usize;
    for i in 0..N {
        let r = client
            .query_ip(
                &format!("q{i}.reuse.test"),
                IpOption { ipv4_enable: true, ipv6_enable: false, fake_enable: false },
            )
            .await;
        if r.is_ok() {
            ok += 1;
        }
    }
    let accepts = accepts.load(Ordering::SeqCst);
    probe(
        "B-4b DoH N 次查询 → 上游 accept 次数",
        format!("accepts={accepts} (N={N}) ⇒ 会话复用（第 2、3 次不新建）"),
    );
    assert_eq!(ok, N, "N 次查询必须全部成功（ok={ok}/{N}）");
    assert!(accepts <= 2, "3 次查询 accept 应 ≤2（复用生效），实测 {accepts}");
    let _ = fx.shutdown().await;
}

/// B-4c：会话失效可重建——对端关连接后，下一次查询自动新建连接并成功（bd yzhb4）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn b4c_doh_session_rebuilds_after_peer_close() {
    let (addr, accepts) =
        spawn_counting_h2c_doh_server("rebuild.test.", vec![Ipv4Addr::new(10, 4, 5, 6)], 60, true)
            .await;
    let ns = h2c_doh_ns(addr, "probe-doh-rebuild");
    let fx = std::sync::Arc::new(skeleton_infra::fx::FxScope::new());
    ns.start_managed_tasks(&fx);
    let client = client_for(Box::new(ns) as Box<dyn Server>, PROBE_TIMEOUT_MS);

    let opt = || IpOption { ipv4_enable: true, ipv6_enable: false, fake_enable: false };
    let r1 = client.query_ip("a.rebuild.test", opt()).await;
    // 第 1 次查询后对端已关连接：第 2 次必须先探测失效再重建，仍须成功。
    let r2 = client.query_ip("b.rebuild.test", opt()).await;
    let accepts = accepts.load(Ordering::SeqCst);
    probe(
        "B-4c DoH 会话失效 → 重建",
        format!(
            "q1={} q2={} accepts={accepts}",
            if r1.is_ok() { "ok" } else { "err" },
            if r2.is_ok() { "ok" } else { "err" }
        ),
    );
    assert!(r1.is_ok(), "首次查询必须成功: {:?}", r1.err());
    assert!(r2.is_ok(), "会话失效后查询必须成功（自动重建）: {:?}", r2.err());
    assert_eq!(accepts, 2, "第 2 次查询必须新建一条连接（rebuild）");
    let _ = fx.shutdown().await;
}

/// B-5：DoQ NS 黑洞上界（QUIC 握手共享整条查询 deadline）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn b5_doq_ns_blackhole_upper_bound_is_one_timeout() {
    // 黑洞 UDP：收包不回 ⇒ QUIC 握手悬挂。
    let bh = spawn_blackhole_udp_server().await;
    let cfg = xray_tls::utls::default_client_config();
    let ns = Arc::new(xray_app_dns::nameserver::quic::DoqNameServer::new(
        bh,
        "localhost".to_string(),
        cfg,
        Arc::new(CacheController::new("probe-doq", true, false, 0, 0)),
        Vec::new(),
        Duration::from_millis(u64::from(PROBE_TIMEOUT_MS)),
    ));
    let client = client_for(Box::new(ns) as Box<dyn Server>, PROBE_TIMEOUT_MS);

    let t0 = Instant::now();
    let r = client
        .query_ip(
            "blackhole.test",
            IpOption { ipv4_enable: true, ipv6_enable: false, fake_enable: false },
        )
        .await;
    let elapsed = t0.elapsed();
    probe(
        "B-5 DoQ NS 黑洞上界（timeout=400ms）",
        format!("{elapsed:?} err={:?}", r.as_ref().err().map(|e| e.to_string())),
    );
    assert!(r.is_err(), "黑洞 DoQ 查询必须失败");
    assert!(
        elapsed >= Duration::from_millis(u64::from(PROBE_TIMEOUT_MS)),
        "DoQ 黑洞查询应至少吃满 timeout，实测 {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_millis(u64::from(PROBE_TIMEOUT_MS) * 2),
        "DoQ 黑洞查询应 <2×timeout，实测 {elapsed:?}"
    );
}

/// B-6：`cached.rs` singleflight 等待者超时上界（bd 26v9t：等待上限 = 本 NS
/// `query_timeout` + 1s；本用例 NS 走 trait 缺省 4s ⇒ 5s）。
///
/// 语义（`nameserver/cached.rs`）：
/// ```text
/// match tokio::time::timeout(sf_wait_timeout(server), rx.recv()).await {
///     Ok(Ok(o)) => o,           // 领导者先完成 ⇒ 共享结果
///     _ => server.send_query(...).await,  // 超时 ⇒ 等待者自己再查一次
/// }
/// ```
/// ⇒ 领导者挂死（永不返回）时等待者最多等 5s，**之后自己发一次查询**（该查询
/// 自身还有自己的 timeout）⇒ 单个等待者的总耗时上界 ≈ 5s + 自身查询 timeout。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn b6_singleflight_waiter_timeout_upper_bound() {
    use xray_app_dns::nameserver::cached::QueryOutcome;

    /// 第一个调用者（领导者）挂死；第二个调用者（等待者）超时后自查询。
    struct HangingLeader {
        cache: CacheController,
        queries: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl CachedNameserver for HangingLeader {
        fn cache_controller(&self) -> &CacheController {
            &self.cache
        }

        fn send_query(
            &self,
            _fqdn: &str,
            _option: IpOption,
        ) -> impl std::future::Future<Output = QueryOutcome> + Send {
            let queries = Arc::clone(&self.queries);
            async move {
                let n = queries.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    // 领导者：挂死（永远 pending）⇒ 等待者 4s 后超时自查询。
                    std::future::pending::<()>().await;
                    unreachable!()
                }
                // 等待者自查询：100ms 后返回空结果。
                tokio::time::sleep(Duration::from_millis(100)).await;
                QueryOutcome::default()
            }
        }
    }

    let queries = Arc::new(AtomicUsize::new(0));
    let server = Arc::new(HangingLeader {
        cache: CacheController::new("probe-sf", true, false, 0, 0),
        queries: Arc::clone(&queries),
    });

    // ① 先起一个**领导者**调用（挂死）⇒ 占住 singleflight 条目。
    let leader_server = Arc::clone(&server);
    let leader = xray_common::testing::spawn("b6-singleflight-leader", async move {
        let _ = xray_app_dns::nameserver::cached::query_ip(
            leader_server,
            "sf.test",
            IpOption { ipv4_enable: true, ipv6_enable: false, fake_enable: false },
        )
        .await;
    });
    // 等领导者真正进入 send_query（计数器 == 1）。
    for _ in 0..100 {
        if queries.load(Ordering::SeqCst) >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(queries.load(Ordering::SeqCst), 1, "领导者应已进入 send_query");

    // ② 第二个调用 = **等待者**：等派生上限（缺省 4s + 1s = 5s）后自查询。
    let t0 = Instant::now();
    let r = xray_app_dns::nameserver::cached::query_ip(
        server,
        "sf.test",
        IpOption { ipv4_enable: true, ipv6_enable: false, fake_enable: false },
    )
    .await;
    let elapsed = t0.elapsed();
    probe(
        "B-6 singleflight 等待者 5s（派生）超时后自查询总耗时",
        format!(
            "{elapsed:?} err={:?} queries={}",
            r.as_ref().err().map(|e| e.to_string()),
            queries.load(Ordering::SeqCst)
        ),
    );
    // 领导者挂死 ⇒ 等待者先等派生上限（缺省 4s + 1s）再自查询（+100ms）。
    assert!(
        elapsed >= Duration::from_secs(5),
        "等待者应至少等满派生上限 5s（query_timeout 4s + 1s），实测 {elapsed:?}"
    );
    // 上界：5s + 自查询 100ms + 余量。
    assert!(
        elapsed < Duration::from_millis(6500),
        "等待者总耗时应 <6.5s（5s 等待 + 自身查询），实测 {elapsed:?}"
    );
    assert_eq!(queries.load(Ordering::SeqCst), 2, "领导者 1 次 + 等待者自查询 1 次");
    leader.abort();
}

/// B-7：`server.rs` `serial_query` N 个 NS 串行 fallback 的总上界。
///
/// 语义（`server.rs:365-393`）：**逐个 client 串行 await**，前一个失败才问下一个
/// ⇒ N 个全黑洞 NS ⇒ 总耗时 ≈ N × 单 NS timeout。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn b7_serial_query_n_ns_total_upper_bound() {
    // 起 3 个黑洞 UDP server（收包不回）。
    let mut addrs = Vec::new();
    for _ in 0..3 {
        addrs.push(spawn_blackhole_udp_server().await);
    }

    for n in [2usize, 3usize] {
        let mut clients = Vec::with_capacity(n);
        for addr in addrs.iter().take(n) {
            clients.push(client_for(udp_ns_server(*addr, PROBE_TIMEOUT_MS), PROBE_TIMEOUT_MS));
        }
        let svc = dns_service(clients, false);
        let t0 = Instant::now();
        let r = svc
            .lookup_ip(
                "serial.test",
                IpOption { ipv4_enable: true, ipv6_enable: false, fake_enable: false },
            )
            .await;
        let elapsed = t0.elapsed();
        let expected_min = Duration::from_millis(u64::from(PROBE_TIMEOUT_MS) * n as u64);
        probe(
            &format!("B-7 serial_query N={n} 全黑洞 NS 总耗时"),
            format!("{elapsed:?} err={:?}", r.as_ref().err().map(|e| e.to_string())),
        );
        assert!(r.is_err(), "全黑洞串行查询必须失败");
        assert!(
            elapsed >= expected_min,
            "N={n} 串行总耗时应 ≥N×timeout={expected_min:?}，实测 {elapsed:?}"
        );
    }
}

/// B-7b：并行模式对照（`enable_parallel_query = true` ⇒ N 个并发 ⇒ ≈1×timeout）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn b7b_parallel_query_n_ns_total_upper_bound() {
    let mut addrs = Vec::new();
    for _ in 0..3 {
        addrs.push(spawn_blackhole_udp_server().await);
    }
    let mut clients = Vec::with_capacity(3);
    for a in &addrs {
        clients.push(client_for(udp_ns_server(*a, PROBE_TIMEOUT_MS), PROBE_TIMEOUT_MS));
    }
    let svc = dns_service(clients, true);
    let t0 = Instant::now();
    let r = svc
        .lookup_ip(
            "parallel.test",
            IpOption { ipv4_enable: true, ipv6_enable: false, fake_enable: false },
        )
        .await;
    let elapsed = t0.elapsed();
    probe(
        "B-7b parallel_query N=3 全黑洞 NS 总耗时",
        format!("{elapsed:?} err={:?}", r.as_ref().err().map(|e| e.to_string())),
    );
    assert!(r.is_err(), "全黑洞并行查询必须失败");
    assert!(
        elapsed < Duration::from_millis(u64::from(PROBE_TIMEOUT_MS) * 2),
        "并行总耗时应 ≈1×timeout（不按 N 累加），实测 {elapsed:?}"
    );
}

/// 附：缺省超时常量打印（报告引用）。
#[test]
fn b0_probe_constants() {
    probe("生产缺省 query timeout (UDP/TCP/DoT/DoQ)", format!("{DEFAULT_QUERY_TIMEOUT_MS}ms"));
    probe("DoH 缺省 query timeout", "5000ms (doh.rs effective_query_timeout)");
    probe("探针用 query timeout", format!("{PROBE_TIMEOUT_MS}ms"));
    let _ = IpAddr::V4(Ipv4Addr::LOCALHOST);
}
