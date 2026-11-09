//! A/AAAA 双栈并发化回归（bd urbvy）：TCP / DoT / DoQ / DoH 一次查询 = 1×RTT。
//!
//! 改前这四种 NS 是「A 完成后再查 AAAA」串行（mock 200ms RTT 实测 416.7ms），
//! 改后与 `udp.rs` 同形 `tokio::join!`（208.7ms）。本文件用**固定应答延迟**的
//! mock 上游逐协议实测：
//!
//! - 整次查询耗时 ≈ 1×`MOCK_RTT`（串行会 ≈ 2×，断言上界 1.5× 即区分）；
//! - DoH **连接数不翻倍**：并发 A/AAAA 共享同一条 h2 会话（`accepts == 1`）。
//!
//! 复现（必须 release——debug 构建放大闭包/分配成本一个量级）：
//! ```text
//! cargo test --release -p xray-app-dns --test ns_dualstack_concurrency -- --nocapture --test-threads=1
//! ```
//!
//! L3 闸豁免（测试文件专属性状）：`unwrap` = 本地 mock 夹具；`Instant::now` =
//! 测真实墙钟延迟（注入钟即失去测量意义）。生产代码零豁免。
#![allow(
    clippy::unwrap_used,
    clippy::disallowed_methods,
    clippy::disallowed_macros,
    reason = "回归测试：mock 夹具 unwrap + 真实墙钟计时 + [PROBE] stdout 取证行（拒注入钟即失去测量意义）；生产代码不受此豁免"
)]

use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use hickory_proto::{
    op::{Message, MessageType, OpCode, Query},
    rr::{RData, Record, RecordType, rdata},
};
use quinn::{Endpoint, ServerConfig as QuinnServerConfig, crypto::rustls::QuicServerConfig};
use skeleton_infra::fx::FxScope;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};
use tokio_rustls::rustls::{
    ClientConfig,
    pki_types::{CertificateDer, PrivateKeyDer},
};
use xray_app_dns::{
    cache_controller::CacheController,
    config::IpOption,
    nameserver::{
        Server, cached::CachedNameserver, doh::DohNameServer, dot::DotNameServer,
        quic::DoqNameServer, tcp::TcpNameServer, udp::UdpNameServer,
    },
};
use xray_common::net::{address::Address, destination::Destination, port::Port};

/// mock 上游的固定应答延迟（模拟真实 RTT）。
const MOCK_RTT: Duration = Duration::from_millis(200);

/// 并发门槛：串行 = 2×RTT(400ms)，并发 ≈ 1×RTT(208ms)，取中间值区分。
const CONCURRENT_UPPER: Duration = Duration::from_millis(300);

/// DoQ ALPN（RFC 9250）。
const DOQ_ALPN: &[u8] = b"doq";

fn probe(label: &str, detail: impl std::fmt::Display) {
    println!("[PROBE] {label:<44} {detail}");
}

/// 双栈查询选项。
fn both() -> IpOption {
    IpOption { ipv4_enable: true, ipv6_enable: true, fake_enable: false }
}

/// 按查询类型构造应答（A → 一条 A；AAAA → 一条 AAAA）。
fn make_response(query: &Message, ttl: u32) -> Vec<u8> {
    let q = query.queries.first().unwrap();
    let name = q.name().clone();
    let qtype = q.query_type();
    let mut msg = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
    msg.add_query(Query::query(name.clone(), qtype));
    let answer = match qtype {
        RecordType::AAAA => {
            Record::from_rdata(name, ttl, RData::AAAA(rdata::AAAA(Ipv6Addr::LOCALHOST)))
        },
        _ => Record::from_rdata(name, ttl, RData::A(rdata::A(Ipv4Addr::new(10, 0, 0, 1)))),
    };
    msg.add_answer(answer);
    msg.to_vec().unwrap()
}

/// 读一个 TCP 长度前缀帧（2B 大端 + payload）。
async fn read_frame<S>(sock: &mut S) -> Option<Vec<u8>>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut len = [0u8; 2];
    sock.read_exact(&mut len).await.ok()?;
    let mut buf = vec![0u8; usize::from(u16::from_be_bytes(len))];
    sock.read_exact(&mut buf).await.ok()?;
    Some(buf)
}

/// 写一个 TCP 长度前缀帧。
async fn write_frame<S>(sock: &mut S, payload: &[u8]) -> bool
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let len = u16::try_from(payload.len()).unwrap().to_be_bytes();
    sock.write_all(&len).await.is_ok() && sock.write_all(payload).await.is_ok()
}

// ---------------------------------------------------------------------------
// mock 上游（每个都：多连接 + 连接内多查询 + 应答前固定睡 MOCK_RTT）
// ---------------------------------------------------------------------------

async fn spawn_udp_server() -> SocketAddr {
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = sock.local_addr().unwrap();
    xray_common::testing::spawn("dualstack-udp-mock", async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((n, peer)) = sock.recv_from(&mut buf).await else { return };
            let data = buf[..n].to_vec();
            // 逐包独立任务：应答延迟不得阻塞收包循环（否则夹具自己把并发串行化）。
            let sock = Arc::clone(&sock);
            xray_common::testing::spawn("dualstack-udp-answer", async move {
                let Ok(query) = Message::from_vec(&data) else { return };
                let resp = make_response(&query, 60);
                tokio::time::sleep(MOCK_RTT).await;
                let _ = sock.send_to(&resp, peer).await;
            });
        }
    });
    addr
}

async fn spawn_tcp_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    xray_common::testing::spawn("dualstack-tcp-mock", async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else { return };
            xray_common::testing::spawn("dualstack-tcp-conn", async move {
                loop {
                    let Some(buf) = read_frame(&mut sock).await else { return };
                    let Ok(query) = Message::from_vec(&buf) else { return };
                    let resp = make_response(&query, 60);
                    tokio::time::sleep(MOCK_RTT).await;
                    if !write_frame(&mut sock, &resp).await {
                        return;
                    }
                }
            });
        }
    });
    addr
}

/// 自签证书：返回（信任它的 client config，证书 DER，私钥 DER）。
fn self_signed_tls() -> (Arc<ClientConfig>, Vec<u8>, Vec<u8>) {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    });
    let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    let cert_der = cert.der().to_vec();
    let key_der = key_pair.serialize_der();

    let mut roots = tokio_rustls::rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(cert_der.clone())).unwrap();
    let client =
        Arc::new(ClientConfig::builder().with_root_certificates(roots).with_no_client_auth());
    (client, cert_der, key_der)
}

async fn spawn_dot_server() -> (SocketAddr, Arc<ClientConfig>) {
    let (client, cert_der, key_der) = self_signed_tls();
    let key = PrivateKeyDer::try_from(key_der).unwrap();
    let server_config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(cert_der)], key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    xray_common::testing::spawn("dualstack-dot-mock", async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else { return };
            let acceptor = acceptor.clone();
            xray_common::testing::spawn("dualstack-dot-conn", async move {
                let Ok(mut tls) = acceptor.accept(sock).await else { return };
                loop {
                    let Some(buf) = read_frame(&mut tls).await else { return };
                    let Ok(query) = Message::from_vec(&buf) else { return };
                    let resp = make_response(&query, 60);
                    tokio::time::sleep(MOCK_RTT).await;
                    if !write_frame(&mut tls, &resp).await {
                        return;
                    }
                }
            });
        }
    });
    (addr, client)
}

async fn spawn_doq_server() -> (SocketAddr, Arc<ClientConfig>) {
    let (client, cert_der, key_der) = self_signed_tls();
    let key = PrivateKeyDer::try_from(key_der).unwrap();
    let mut server_config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(cert_der)], key)
        .unwrap();
    server_config.alpn_protocols = vec![DOQ_ALPN.to_vec()];
    let quic = QuicServerConfig::try_from(Arc::new(server_config)).unwrap();
    let endpoint = Endpoint::server(
        QuinnServerConfig::with_crypto(Arc::new(quic)),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let addr = endpoint.local_addr().unwrap();

    xray_common::testing::spawn("dualstack-doq-mock", async move {
        loop {
            let Some(incoming) = endpoint.accept().await else { return };
            xray_common::testing::spawn("dualstack-doq-conn", async move {
                let Ok(conn) = incoming.await else { return };
                loop {
                    let Ok((mut send, mut recv)) = conn.accept_bi().await else { return };
                    let Some(buf) = read_frame(&mut recv).await else { return };
                    let Ok(query) = Message::from_vec(&buf) else { return };
                    let resp = make_response(&query, 60);
                    tokio::time::sleep(MOCK_RTT).await;
                    if !write_frame(&mut send, &resp).await {
                        return;
                    }
                    let _ = send.finish();
                }
            });
        }
    });
    (addr, client)
}

/// h2c（明文 HTTP/2）DoH mock：逐连接独立任务、连接内多请求，记录 TCP accept 次数。
///
/// 第三个返回值是**失败回报通道**（bd h36x2）：逐请求任务由
/// `xray_common::testing::spawn` 启动且 JoinHandle 被丢弃（detached）——detached 任务里的
/// 判定性 assert 无人观测（panic 被 tokio 吞掉 ⇒ 假绿）。故 mock 任务只**报告**失败，
/// 由测试主体 select! 断言。
async fn spawn_h2c_doh_server()
-> (SocketAddr, Arc<AtomicUsize>, tokio::sync::mpsc::UnboundedReceiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepts = Arc::new(AtomicUsize::new(0));
    let accepts_c = Arc::clone(&accepts);
    let (fail_tx, fail_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    xray_common::testing::spawn("dualstack-doh-mock", async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else { return };
            accepts_c.fetch_add(1, Ordering::SeqCst);
            let fail_tx = fail_tx.clone();
            xray_common::testing::spawn("dualstack-doh-conn", async move {
                let Ok(mut h2) = h2::server::handshake(sock).await else { return };
                while let Some(req) = h2.accept().await {
                    let Ok((req, mut respond)) = req else { return };
                    let fail_tx = fail_tx.clone();
                    // 逐请求独立任务：请求体排空与应答都不得阻塞 h2 accept 循环——
                    // accept 环是连接 I/O 的唯一驱动者，环内 `await` `data()` 自堵
                    // （DATA 未入缓冲时永久挂起，bd ll2hr 同款）；延迟在环外也保住
                    // 同连接并发请求不被夹具串行化。
                    xray_common::testing::spawn("dualstack-doh-answer", async move {
                        let mut body = req.into_body();
                        let mut buf = Vec::new();
                        let drained = tokio::time::timeout(Duration::from_secs(5), async {
                            while let Some(chunk) = body.data().await {
                                let chunk = chunk.map_err(|e| format!("请求体读取失败：{e}"))?;
                                buf.extend_from_slice(&chunk);
                            }
                            Ok::<_, String>(())
                        })
                        .await;
                        match drained {
                            Ok(Ok(())) => {},
                            Ok(Err(e)) => {
                                let _ = fail_tx.send(e);
                                return;
                            },
                            Err(_) => {
                                let _ = fail_tx
                                    .send("请求体未在 5s 内收齐：h2 连接驱动被堵".to_string());
                                return;
                            },
                        }
                        let Ok(query) = Message::from_vec(&buf) else {
                            let _ = fail_tx.send("请求体不是合法 DNS 报文".to_string());
                            return;
                        };
                        let payload = make_response(&query, 60);
                        tokio::time::sleep(MOCK_RTT).await;
                        let resp = http::Response::builder()
                            .status(http::StatusCode::OK)
                            .header(http::header::CONTENT_TYPE, "application/dns-message")
                            .body(())
                            .unwrap();
                        let Ok(mut send) = respond.send_response(resp, false) else { return };
                        let _ = send.send_data(bytes::Bytes::from(payload), true);
                    });
                }
            });
        }
    });
    (addr, accepts, fail_rx)
}

// ---------------------------------------------------------------------------
// nameserver 构造
// ---------------------------------------------------------------------------

fn udp_dest(addr: SocketAddr) -> Destination {
    Destination::udp(Address::from(addr.ip()), Port::new(addr.port()))
}

fn tcp_dest(addr: SocketAddr) -> Destination {
    Destination::tcp(Address::from(addr.ip()), Port::new(addr.port()))
}

fn cache(tag: &str) -> Arc<CacheController> {
    // 禁缓存：测量的是上游查询本身，不经缓存命中。
    Arc::new(CacheController::new(tag, true, false, 0, 0))
}

// ---------------------------------------------------------------------------
// 用例
// ---------------------------------------------------------------------------

/// 双栈一次查询的实测耗时（先预热一遍，让连接/会话建立成本落在预热里）。
async fn measure<S: CachedNameserver + Sync>(ns: &S, label: &str) -> Duration {
    let warm = ns.send_query("example.com.", both()).await;
    assert!(warm.rec_v4.is_some() && warm.rec_v6.is_some(), "{label}: 预热两族都应有记录");

    let t0 = Instant::now();
    let outcome = ns.send_query("example.com.", both()).await;
    let elapsed = t0.elapsed();
    probe(label, format!("{elapsed:?}"));
    assert!(outcome.rec_v4.is_some(), "{label}: v4 记录缺失");
    assert!(outcome.rec_v6.is_some(), "{label}: v6 记录缺失");
    assert!(elapsed >= MOCK_RTT, "{label}: 耗时小于 mock RTT，夹具异常（{elapsed:?}）");
    assert!(
        elapsed < CONCURRENT_UPPER,
        "{label}: 双栈应为 1×RTT（并发），实测 {elapsed:?}（串行会 ≈2×RTT = {:?}）",
        MOCK_RTT * 2
    );
    elapsed
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_dual_stack_is_concurrent() {
    let ns = UdpNameServer::new(
        udp_dest(spawn_udp_server().await),
        cache("dualstack-udp"),
        Vec::new(),
        Duration::from_secs(2),
        Arc::new(xray_app_dns::dial::SystemHostResolver),
    );
    measure(&ns, "UDP 双栈耗时").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_dual_stack_is_concurrent() {
    let ns = TcpNameServer::new(
        tcp_dest(spawn_tcp_server().await),
        cache("dualstack-tcp"),
        Vec::new(),
        Duration::from_secs(2),
        Arc::new(xray_app_dns::dial::SystemHostResolver),
    );
    measure(&ns, "TCP 双栈耗时").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dot_dual_stack_is_concurrent() {
    let (addr, tls_config) = spawn_dot_server().await;
    let ns = DotNameServer::new(
        tcp_dest(addr),
        "localhost".to_string(),
        tls_config,
        cache("dualstack-dot"),
        Vec::new(),
        Duration::from_secs(2),
    );
    measure(&ns, "DoT 双栈耗时").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn doq_dual_stack_is_concurrent() {
    let (addr, tls_config) = spawn_doq_server().await;
    let ns = DoqNameServer::new(
        addr,
        "localhost".to_string(),
        tls_config,
        cache("dualstack-doq"),
        Vec::new(),
        Duration::from_secs(2),
    );
    measure(&ns, "DoQ 双栈耗时").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn doh_dual_stack_is_concurrent_without_extra_connection() {
    let (addr, accepts, mut failures) = spawn_h2c_doh_server().await;
    let ns = Arc::new(DohNameServer::new(
        tcp_dest(addr),
        addr.to_string(),
        xray_tls::utls::default_client_config(),
        cache("dualstack-doh"),
        Vec::new(),
        // 查询预算必须 > mock 排空守卫（5s）：否则客户端先超时，mock 的根因诊断
        // （h2 连接驱动被堵）永远轮不到上报，失败被误判为"查询超时"。
        Duration::from_secs(10),
        true,
    ));
    // 生产由 `DnsService::start()` 注单托管 scope；测试走同一注单面。
    ns.start_managed_tasks(&Arc::new(FxScope::new()));

    // mock 侧失败优先：detached 任务里的 panic 无人观测（bd h36x2），故 mock 只
    // 上报失败原因，由本主体断言 ⇒ 失败必红。
    tokio::select! {
        biased;
        Some(reason) = failures.recv() => panic!("DoH mock 夹具失败：{reason}"),
        _ = measure(&*ns, "DoH 双栈耗时") => {}
    }
    probe("DoH accepts（预热 + 测量 = 4 条请求）", accepts.load(Ordering::SeqCst));
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        1,
        "并发 A/AAAA 必须共享同一条 h2 会话（连接数不得翻倍）"
    );
}

/// 黑洞 UDP 上游（收包不回）+ 收包计数。
async fn spawn_blackhole_udp() -> (SocketAddr, Arc<AtomicUsize>) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let packets = Arc::new(AtomicUsize::new(0));
    let packets_c = Arc::clone(&packets);
    xray_common::testing::spawn("dualstack-blackhole-udp", async move {
        let mut buf = vec![0u8; 4096];
        while sock.recv_from(&mut buf).await.is_ok() {
            packets_c.fetch_add(1, Ordering::SeqCst);
        }
    });
    (addr, packets)
}

/// singleflight 重复查询实测（bd 26v9t）：等待上限固定 4s 时恰等于缺省
/// `query_timeout`（4000ms）⇒ 领导者在 4s 收场时等待者同刻超时、自起一轮上游
/// 查询（每轮多 2 包 = A + AAAA）。改后等待上限 = 本 NS `query_timeout` + 1s，
/// 等待者共享领导者结论，一轮只打 2 包。
///
/// 慢（每组 4-6s），不进常规 CI：`cargo test --release -p xray-app-dns --test
/// ns_dualstack_concurrency -- --ignored --nocapture`。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "秒级慢测（每组 4-6s），手动 --ignored 跑"]
async fn singleflight_waiter_shares_leader_result_instead_of_requerying() {
    /// 一轮：领导者 + 等待者同 key 并发，返回（等待者耗时，上游收包数增量）。
    async fn one_round(fqdn: &str, timeout: Duration) -> (Duration, usize) {
        let fqdn = fqdn.to_string();
        let (addr, packets) = spawn_blackhole_udp().await;
        let ns = Arc::new(UdpNameServer::new(
            udp_dest(addr),
            cache("sf-blackhole"),
            Vec::new(),
            timeout,
            Arc::new(xray_app_dns::dial::SystemHostResolver),
        ));

        let leader = xray_common::testing::spawn("sf-blackhole-leader", {
            let ns = Arc::clone(&ns);
            let fqdn = fqdn.clone();
            async move { xray_app_dns::nameserver::cached::query_ip(ns, &fqdn, both()).await }
        });
        // 等领导者的两条查询到达上游（双栈 = 2 包），再起等待者。
        while packets.load(Ordering::SeqCst) < 2 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        let started = Instant::now();
        let _ = xray_app_dns::nameserver::cached::query_ip(Arc::clone(&ns), &fqdn, both()).await;
        let elapsed = started.elapsed();
        let _ = leader.await;
        (elapsed, packets.load(Ordering::SeqCst))
    }

    // ① 领导者 6s：改前等待者 4s 超时 + 自查询 6s ≈ 10.02s、上游 4 包。
    let (waiter_elapsed, packets) = one_round("sf6.example.com.", Duration::from_secs(6)).await;
    probe("SF 领导者 6s：等待者耗时 / 上游包数", format!("{waiter_elapsed:?} / {packets} 包"));
    assert!(
        packets < 4,
        "等待者必须共享领导者结论（上游应只收 2 包 = 领导者 A+AAAA），实测 {packets} 包"
    );
    assert!(
        waiter_elapsed < Duration::from_secs(8),
        "等待者不应再等 4s + 自查询（改前 10.02s），实测 {waiter_elapsed:?}"
    );

    // ② 缺省 4000ms 档连跑 3 轮：每轮重复查询 0 次（上游每轮只 2 包）。
    for round in 0..3 {
        let fqdn = format!("sf4-{round}.example.com.");
        let (waiter_elapsed, packets) = one_round(&fqdn, Duration::from_secs(4)).await;
        probe(
            &format!("SF 4s 档第 {} 轮：等待者耗时 / 上游包数", round + 1),
            format!("{waiter_elapsed:?} / {packets} 包"),
        );
        assert_eq!(
            packets, 2,
            "第 {round} 轮出现重复查询（上游应收领导者 A+AAAA 共 2 包），实测 {packets} 包"
        );
        assert!(
            waiter_elapsed < Duration::from_secs(6),
            "第 {round} 轮等待者应在领导者 4s 收场时共享结论，实测 {waiter_elapsed:?}"
        );
    }
}
