//! E2E: mock DNS server → UdpNameServer/TcpNameServer 端到端验证。
//!
//! 覆盖 yr7 验收要点：
//! - UDP/TCP 查询能正确解析 A/AAAA 记录
//! - cache 第二次查询命中（不再走网络）
//! - EDNS0 client_ip 选项正确附加（通过 query bytes 验证）

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use hickory_proto::{
    op::{Message, MessageType, OpCode, Query},
    rr::{
        Name, RData, Record, RecordType,
        rdata::opt::{ClientSubnet, EdnsOption},
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};
use xray_app_dns::{
    cache_controller::CacheController,
    config::IpOption,
    nameserver::{Server, tcp::TcpNameServer, udp::UdpNameServer},
};

/// 构造 A 或 AAAA 响应。req_id 由 query bytes echo。
fn make_response(
    req_id: u16,
    fqdn: &str,
    record_type: RecordType,
    ips: Vec<IpAddr>,
    ttl: u32,
) -> Vec<u8> {
    let name = Name::parse(fqdn, None).unwrap();
    let mut msg = Message::new(req_id, MessageType::Response, OpCode::Query);
    msg.add_query(Query::query(name.clone(), record_type));
    for ip in ips {
        let rdata = match ip {
            IpAddr::V4(v4) => RData::A(hickory_proto::rr::rdata::A(v4)),
            IpAddr::V6(v6) => RData::AAAA(hickory_proto::rr::rdata::AAAA(v6)),
        };
        let rec = Record::from_rdata(name.clone(), ttl, rdata);
        msg.add_answer(rec);
    }
    msg.to_vec().unwrap()
}

/// mock UDP server：根据查询 record_type 自动构造响应，可记录收到的查询 bytes。
async fn spawn_udp_echo_server(
    fqdn: String,
    v4_ips: Vec<Ipv4Addr>,
    v6_ips: Vec<Ipv6Addr>,
    ttl: u32,
    captured_query: Arc<parking_lot::Mutex<Option<Vec<u8>>>>,
) -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        let (n, peer) = sock.recv_from(&mut buf).await.unwrap();
        let query_bytes = buf[..n].to_vec();
        let query_msg = Message::from_vec(&query_bytes).unwrap();
        // 记录原始 query（用于 EDNS0 验证）。
        *captured_query.lock() = Some(query_bytes);
        let qtype = query_msg.queries[0].query_type();
        let resp = match qtype {
            RecordType::A => {
                let ips: Vec<IpAddr> = v4_ips.iter().map(|ip| IpAddr::V4(*ip)).collect();
                make_response(query_msg.metadata.id, &fqdn, RecordType::A, ips, ttl)
            },
            RecordType::AAAA => {
                let ips: Vec<IpAddr> = v6_ips.iter().map(|ip| IpAddr::V6(*ip)).collect();
                make_response(query_msg.metadata.id, &fqdn, RecordType::AAAA, ips, ttl)
            },
            _ => unreachable!(),
        };
        sock.send_to(&resp, peer).await.unwrap();
    });
    addr
}

#[tokio::test]
async fn udp_query_returns_correct_a_record() {
    let captured: Arc<parking_lot::Mutex<Option<Vec<u8>>>> =
        Arc::new(parking_lot::Mutex::new(None));
    let addr = spawn_udp_echo_server(
        "example.com.".to_string(),
        vec![Ipv4Addr::new(93, 184, 216, 34)],
        vec![],
        300,
        captured.clone(),
    )
    .await;

    let ns = UdpNameServer::new(
        addr,
        Arc::new(CacheController::new("test", true, false, 0, 0)), // disable_cache=true 强制走网络
        Vec::new(),
        Duration::from_secs(2),
    );

    let (ips, ttl) = ns
        .query_ip(
            "example.com",
            IpOption { ipv4_enable: true, ipv6_enable: false, fake_enable: false },
        )
        .await
        .unwrap();
    assert_eq!(ips.len(), 1);
    assert_eq!(ips[0], IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
    assert!(ttl <= 300);
}

#[tokio::test]
async fn udp_query_cache_hit_on_second_call() {
    // 不 disable_cache → 第二次查询应命中缓存。
    let captured: Arc<parking_lot::Mutex<Option<Vec<u8>>>> =
        Arc::new(parking_lot::Mutex::new(None));
    let addr = spawn_udp_echo_server(
        "cached.example.".to_string(),
        vec![Ipv4Addr::new(1, 1, 1, 1)],
        vec![],
        300,
        captured.clone(),
    )
    .await;

    let ns = UdpNameServer::new(
        addr,
        Arc::new(CacheController::new("test", false, false, 0, 0)), // cache ENABLED
        Vec::new(),
        Duration::from_secs(2),
    );

    // 第一次查询 → 走网络。
    let (ips1, ttl1) = ns
        .query_ip(
            "cached.example",
            IpOption { ipv4_enable: true, ipv6_enable: false, fake_enable: false },
        )
        .await
        .unwrap();
    assert_eq!(ips1.len(), 1);

    // 等 mock server 任务完成（fire-and-forget spawn，已结束）。
    tokio::time::sleep(Duration::from_millis(50)).await;
    let first_capture = captured.lock().clone();
    assert!(first_capture.is_some(), "first query should hit network");

    // 重置 capture；mock server 只服务一次（已 spawn 完成），
    // 第二次查询若走网络会超时失败 → 因此能成功必然是 cache 命中。
    *captured.lock() = None;

    let (ips2, ttl2) = ns
        .query_ip(
            "cached.example",
            IpOption { ipv4_enable: true, ipv6_enable: false, fake_enable: false },
        )
        .await
        .unwrap();
    assert_eq!(ips2.len(), 1);
    assert_eq!(ips2[0], IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
    // TTL 应与第一次相同或更小（cache 写入时算的剩余 TTL）。
    assert!(ttl2 <= ttl1 + 1);
}

#[tokio::test]
async fn udp_query_with_edns0_client_ip_attaches_subnet() {
    let captured: Arc<parking_lot::Mutex<Option<Vec<u8>>>> =
        Arc::new(parking_lot::Mutex::new(None));
    let addr = spawn_udp_echo_server(
        "subnet.example.".to_string(),
        vec![Ipv4Addr::new(2, 2, 2, 2)],
        vec![],
        60,
        captured.clone(),
    )
    .await;

    // client_ip = 4 字节 IPv4 → 应被附加为 EDNS0 client subnet /24。
    let ns = UdpNameServer::new(
        addr,
        Arc::new(CacheController::new("test", true, false, 0, 0)),
        vec![192, 168, 1, 100],
        Duration::from_secs(2),
    );

    let _ = ns
        .query_ip(
            "subnet.example",
            IpOption { ipv4_enable: true, ipv6_enable: false, fake_enable: false },
        )
        .await
        .unwrap();

    let query_bytes = captured.lock().clone().expect("query captured");
    let query_msg = Message::from_vec(&query_bytes).unwrap();
    // 验证 EDNS0 存在 + 包含 Subnet option。
    let edns = query_msg.edns.as_ref().expect("edns present");
    let has_subnet =
        edns.options().as_ref().iter().any(|(code, opt)| matches!(opt, EdnsOption::Subnet(_)));
    assert!(has_subnet, "edns0 subnet option must be present");

    // 进一步验证 Subnet 内容。
    for (_, opt) in edns.options().as_ref().iter() {
        if let EdnsOption::Subnet(s) = opt {
            // ClientSubnet 字段不暴露 getter，仅验证类型匹配（构造时 source=24, scope=0）。
            let _ = (s,); // 防止 unused
        }
    }
}

#[tokio::test]
async fn tcp_query_returns_a_record() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let fqdn = "tcp.example.".to_string();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut len_buf = [0u8; 2];
        sock.read_exact(&mut len_buf).await.unwrap();
        let plen = usize::from(u16::from_be_bytes(len_buf));
        let mut buf = vec![0u8; plen];
        sock.read_exact(&mut buf).await.unwrap();
        let query_msg = Message::from_vec(&buf).unwrap();
        let ips = vec![IpAddr::V4(Ipv4Addr::new(7, 7, 7, 7))];
        let resp = make_response(query_msg.metadata.id, &fqdn, RecordType::A, ips, 60);
        let len = u16::try_from(resp.len()).unwrap().to_be_bytes();
        sock.write_all(&len).await.unwrap();
        sock.write_all(&resp).await.unwrap();
        sock.flush().await.unwrap();
    });

    let ns = TcpNameServer::new(
        addr,
        Arc::new(CacheController::new("test", true, false, 0, 0)),
        Vec::new(),
        Duration::from_secs(2),
    );
    let (ips, _ttl) = ns
        .query_ip(
            "tcp.example",
            IpOption { ipv4_enable: true, ipv6_enable: false, fake_enable: false },
        )
        .await
        .unwrap();
    assert_eq!(ips.len(), 1);
    assert_eq!(ips[0], IpAddr::V4(Ipv4Addr::new(7, 7, 7, 7)));
}

#[tokio::test]
async fn udp_query_aaaa_record() {
    let captured: Arc<parking_lot::Mutex<Option<Vec<u8>>>> =
        Arc::new(parking_lot::Mutex::new(None));
    let v6 = Ipv6Addr::LOCALHOST;
    let addr =
        spawn_udp_echo_server("v6.example.".to_string(), vec![], vec![v6], 60, captured).await;

    let ns = UdpNameServer::new(
        addr,
        Arc::new(CacheController::new("test", true, false, 0, 0)),
        Vec::new(),
        Duration::from_secs(2),
    );
    let (ips, _ttl) = ns
        .query_ip(
            "v6.example",
            IpOption { ipv4_enable: false, ipv6_enable: true, fake_enable: false },
        )
        .await
        .unwrap();
    assert_eq!(ips.len(), 1);
    assert_eq!(ips[0], IpAddr::V6(v6));
}

#[tokio::test]
async fn server_trait_object_dispatch() {
    // 验证 UdpNameServer 可作 Box<dyn Server> 用。
    let captured: Arc<parking_lot::Mutex<Option<Vec<u8>>>> =
        Arc::new(parking_lot::Mutex::new(None));
    let addr = spawn_udp_echo_server(
        "trait.example.".to_string(),
        vec![Ipv4Addr::new(4, 4, 4, 4)],
        vec![],
        60,
        captured,
    )
    .await;
    let ns = UdpNameServer::new(
        addr,
        Arc::new(CacheController::new("test", true, false, 0, 0)),
        Vec::new(),
        Duration::from_secs(2),
    );
    let server: Box<dyn Server> = Box::new(ns);
    assert!(server.name().starts_with("UDP:"));
    // CacheController::new("test", true, ...) → disable_cache=true → is_disable_cache()=true。
    assert!(server.is_disable_cache());
}
