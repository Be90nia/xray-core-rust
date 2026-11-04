//! 回归测试（bd oab4a）：**A / AAAA 必须并发发出**，一次查询 = 1×RTT。
//!
//! 背景：Go `app/dns/dnscommon.go:130 buildReqMsgs` 一次性构建 A+AAAA 两条请求，
//! `app/dns/nameserver_*.go` 连续 dispatch **并发发出** ⇒ 一次查询 = 1 个 RTT。
//! 修复前 Rust UDP NS 为「A 完成后再 await AAAA」串行 ⇒ 2 个 RTT（200ms 网络下
//! 实测 421ms，两条查询间隔 206ms）。
//!
//! 本测试用「每次应答固定延迟」的 mock UDP DNS server 实测：
//! - 记录 A 与 AAAA 两条查询被**收到**的时刻，算出发起时刻差；
//! - 记录整次查询耗时。
//!
//! 断言（修复后口径）：`gap < 50ms` 且 `MOCK_RTT <= 总耗时 < 250ms`（≈1×RTT）。
//!
//! 复现命令：
//! ```text
//! cargo test --release -p xray-app-dns --test dns_a_aaaa_serial_latency -- --nocapture --test-threads=1
//! ```
#![allow(
    clippy::unwrap_used,
    clippy::disallowed_methods,
    clippy::disallowed_macros,
    reason = "只读延迟探针：测试面裸计时与 [PM] 直印是探针契约（713x6：测试计时不得改语义）"
)]

use std::{
    net::{Ipv4Addr, SocketAddr},
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
use tokio::net::UdpSocket;
use xray_app_dns::{
    cache_controller::CacheController,
    config::IpOption,
    nameserver::{cached::CachedNameserver, udp::UdpNameServer},
};

/// mock 上游的固定应答延迟（模拟真实 RTT）。
const MOCK_RTT: Duration = Duration::from_millis(200);

/// 记录 mock server 收到的查询到达时刻（相对起点）与查询类型。
#[derive(Debug, Clone)]
struct Arrival {
    at: Duration,
    qtype: RecordType,
}

/// 起一个 mock UDP DNS server：每次收到查询都等 `MOCK_RTT` 再应答。
///
/// 返回：监听地址 / 查询到达记录 / 收到的查询总数（AtomicUsize）。
async fn spawn_delaying_mock_dns()
-> (SocketAddr, Arc<tokio::sync::Mutex<Vec<Arrival>>>, Arc<AtomicUsize>) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let arrivals = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let counter = Arc::new(AtomicUsize::new(0));

    let arrivals_c = Arc::clone(&arrivals);
    let counter_c = Arc::clone(&counter);
    xray_common::testing::spawn("delaying-mock-dns", async move {
        let start = Instant::now();
        let sock = Arc::new(sock);
        let mut buf = vec![0u8; 4096];
        loop {
            let (n, peer) = match sock.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => return,
            };
            let Ok(query_msg) = Message::from_vec(&buf[..n]) else {
                continue;
            };
            let req_id = query_msg.metadata.id;
            let qtype = query_msg.queries.first().map(|q| q.query_type()).unwrap_or(RecordType::A);
            let qname =
                query_msg.queries.first().map(|q| q.name().clone()).unwrap_or_else(Name::root);
            counter_c.fetch_add(1, Ordering::Relaxed);
            arrivals_c.lock().await.push(Arrival { at: start.elapsed(), qtype });

            // 每条查询**独立**延迟应答：真实上游并发处理，（旧版在收包循环里
            // 串行 sleep 会把并发查询排成队，把被测对象测成自己）。
            let sock = Arc::clone(&sock);
            xray_common::testing::spawn("delaying-mock-dns-reply", async move {
                tokio::time::sleep(MOCK_RTT).await;
                let mut resp = Message::new(req_id, MessageType::Response, OpCode::Query);
                resp.add_query(Query::query(qname.clone(), qtype));
                if qtype == RecordType::A {
                    resp.add_answer(Record::from_rdata(
                        qname,
                        60,
                        RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::new(1, 2, 3, 4))),
                    ));
                }
                let Ok(wire) = resp.to_vec() else { return };
                let _ = sock.send_to(&wire, peer).await;
            });
        }
    });
    (addr, arrivals, counter)
}

fn udp_dest(addr: SocketAddr) -> xray_common::net::destination::Destination {
    use xray_common::net::{address::Address, destination::Destination, port::Port};
    Destination::udp(Address::from(addr.ip()), Port::new(addr.port()))
}

#[tokio::test]
async fn a_aaaa_queries_are_issued_concurrently() {
    // 禁缓存（否则第二次查询走缓存不发网络）。
    let (addr, arrivals, counter) = spawn_delaying_mock_dns().await;

    let ns = UdpNameServer::new(
        udp_dest(addr),
        Arc::new(CacheController::new("pm-aaaa-latency", true, false, 0, 0)),
        Vec::new(),
        Duration::from_secs(5),
        Arc::new(xray_app_dns::dial::SystemHostResolver),
    );

    let t0 = Instant::now();
    let outcome = ns
        .send_query(
            "dual.example.",
            IpOption { ipv4_enable: true, ipv6_enable: true, fake_enable: false },
        )
        .await;
    let elapsed = t0.elapsed();

    // 两条查询都应发出（A + AAAA）。
    assert_eq!(counter.load(Ordering::Relaxed), 2, "A 与 AAAA 两条查询都应发出");
    assert!(outcome.rec_v4.is_some(), "A 记录应有应答");
    // AAAA 应答：mock 回的是 NOERROR 空 AAAA 表 → rec_v6 存在但 ips 空。
    assert!(outcome.rec_v6.is_some(), "AAAA 查询也应完成（空答案）");

    let arrivals = arrivals.lock().await.clone();
    let a_at =
        arrivals.iter().find(|a| a.qtype == RecordType::A).map(|a| a.at).expect("A 查询到达记录");
    let aaaa_at = arrivals
        .iter()
        .find(|a| a.qtype == RecordType::AAAA)
        .map(|a| a.at)
        .expect("AAAA 查询到达记录");

    let gap = aaaa_at.saturating_sub(a_at);

    println!("[PM] A 到达时刻   = {a_at:?}");
    println!("[PM] AAAA 到达时刻 = {aaaa_at:?}");
    println!("[PM] 两条查询发起间隔 = {gap:?}（mock RTT = {MOCK_RTT:?}）");
    println!("[PM] 整次查询耗时   = {elapsed:?}");
    println!(
        "[PM] 若并发，间隔应 ≈ 0 且总耗时 ≈ {:?}；若串行，间隔 ≈ {:?} 且总耗时 ≈ 2×",
        MOCK_RTT, MOCK_RTT
    );

    // ── 修复后验收（bd oab4a）：A/AAAA 并发 ⇒ 两条查询同时发出、总耗时 ≈ 1×RTT ──
    assert!(
        gap < Duration::from_millis(50),
        "并发后 A/AAAA 应几乎同时发出（间隔 <50ms），实测 {gap:?}"
    );
    assert!(
        elapsed < Duration::from_millis(250),
        "并发后总耗时应 ≈ 1×RTT（<250ms，mock RTT = {MOCK_RTT:?}），实测 {elapsed:?}"
    );
    // 下界：不得快于单 RTT（否则说明 mock 延迟没生效，测试无效）。
    assert!(
        elapsed >= MOCK_RTT,
        "总耗时不应低于 1×RTT（{MOCK_RTT:?}），实测 {elapsed:?} —— 前提不成立"
    );
}
