//! TCP 兜底验收（Go 无此步；RFC 7766 §5）。
//!
//! 三条红线：上游序列 `[udp, udp, tcp]`、兜底以 **TCP 网络位** 拨号、UDP 完整答案
//! 零额外查询。夹具（`make_a_response` / `udp_dest` 等）来自 `udp::tests`。

use super::*;

/// bd a42ht：首包已带 EDNS0（clientIp 在场）时 Go 不再重发
/// （Go `nameserver_udp.go:121` `len(req.msg.Additionals) == 0` 门）——Go 此后按截断
/// 应答收场，Rust 则继续走 TCP 兜底（Go 无此步）。
#[tokio::test]
#[allow(clippy::await_holding_lock)] // 测试全局槽位锁刻意跨 await 串行化（无争用场景）
async fn truncated_response_with_existing_edns0_is_not_retried() {
    let _slot = DIALER_SLOT_LOCK.lock();
    let (addr, trace) =
        spawn_tc1_udp_tcp_upstream("tc2.com.", vec![Ipv4Addr::new(6, 6, 6, 6)]).await;

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
        .expect("已有 EDNS0 的截断应答走 TCP 兜底必须拿到答案");
    assert_eq!(rec.ips, vec![IpAddr::V4(Ipv4Addr::new(6, 6, 6, 6))]);

    // Go 门控保留：首包已带 OPT → 不得 UDP 重发；但 TCP 兜底照走。
    let kinds: Vec<&str> = trace.lock().iter().map(|(k, _)| *k).collect();
    assert_eq!(kinds, vec!["udp", "tcp"], "已有 EDNS0 时不得 UDP 重发，只能走 TCP");
}

// ============ TCP 兜底（Go 无此步；RFC 7766 §5） ============

/// 同一端口上起 UDP + TCP 监听（UDP/TCP 端口空间独立，可共存；端口被抢则重试）。
async fn bind_udp_tcp_same_port() -> (UdpSocket, tokio::net::TcpListener, SocketAddr) {
    for _ in 0..5 {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = udp.local_addr().unwrap();
        if let Ok(tcp) = tokio::net::TcpListener::bind(addr).await {
            return (udp, tcp, addr);
        }
    }
    panic!("bind udp+tcp on the same port failed");
}

/// 上游看到的查询序列（`("udp"|"tcp", 查询字节)`；TCP 侧已剥离 2B 长度前缀）。
type UpstreamTrace = Arc<parking_lot::Mutex<Vec<(&'static str, Vec<u8>)>>>;

/// 起「UDP 恒回 TC=1 / TCP 回完整答案」的假上游（同一端口双协议）。
///
/// 记录上游收到的查询序列，供断言「先 UDP 后 TCP」与「TCP 侧收到裸 DNS 报文」。
async fn spawn_tc1_udp_tcp_upstream(
    fqdn: &'static str,
    ips: Vec<Ipv4Addr>,
) -> (SocketAddr, UpstreamTrace) {
    let (udp, tcp, addr) = bind_udp_tcp_same_port().await;
    let trace: UpstreamTrace = Arc::default();
    let trace_udp = trace.clone();
    let trace_tcp = trace.clone();
    let _udp_task = xray_common::testing::spawn("dns-tc1-upstream-udp", async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((n, peer)) = udp.recv_from(&mut buf).await else { return };
            trace_udp.lock().push(("udp", buf[..n].to_vec()));
            let Ok(query) = Message::from_vec(&buf[..n]) else { continue };
            let mut trunc = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
            trunc.add_query(Query::query(Name::parse(fqdn, None).unwrap(), RecordType::A));
            trunc.metadata.truncation = true;
            let _ = udp.send_to(&trunc.to_vec().unwrap(), peer).await;
        }
    });
    let _tcp_task = xray_common::testing::spawn("dns-tc1-upstream-tcp", async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        loop {
            let Ok((mut stream, _)) = tcp.accept().await else { return };
            let mut len_buf = [0u8; 2];
            if stream.read_exact(&mut len_buf).await.is_err() {
                continue;
            }
            let mut query = vec![0u8; usize::from(u16::from_be_bytes(len_buf))];
            if stream.read_exact(&mut query).await.is_err() {
                continue;
            }
            trace_tcp.lock().push(("tcp", query.clone()));
            // 裸 DNS 报文才能从偏移 0 解出 Message；XUDP 帧在这必解失败。
            let Ok(msg) = Message::from_vec(&query) else { continue };
            let resp = make_a_response(msg.metadata.id, fqdn, ips.clone(), 60);
            let _ = stream.write_all(&u16::try_from(resp.len()).unwrap().to_be_bytes()).await;
            let _ = stream.write_all(&resp).await;
        }
    });
    (addr, trace)
}

/// TCP 兜底：UDP 恒回 TC=1 → EDNS0 重发（仍 TC=1）→ TCP 拿到完整答案。
///
/// 判别点：上游先收到 UDP 首包、再收到带 OPT 的 EDNS0 重发包、最后才收到 TCP 查询。
#[tokio::test]
#[allow(clippy::await_holding_lock)] // 测试全局槽位锁刻意跨 await 串行化（无争用场景）
async fn truncated_response_falls_back_to_tcp_and_gets_full_answer() {
    let _slot = DIALER_SLOT_LOCK.lock();
    let (addr, trace) =
        spawn_tc1_udp_tcp_upstream("fb.com.", vec![Ipv4Addr::new(5, 6, 7, 8)]).await;

    let ns = UdpNameServer::new(
        udp_dest(addr),
        Arc::new(CacheController::new("test", true, false, 0, 0)),
        Vec::new(),
        Duration::from_secs(2),
        Arc::new(crate::dial::SystemHostResolver),
    );
    let rec = ns
        .query_once("fb.com.", RecordType::A, Budget::tokio().deadline(Duration::from_secs(2)))
        .await
        .expect("TC=1 后 TCP 兜底必须拿到完整答案");
    assert_eq!(rec.ips, vec![IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8))]);

    let trace = trace.lock();
    let kinds: Vec<&str> = trace.iter().map(|(k, _)| *k).collect();
    assert_eq!(kinds, vec!["udp", "udp", "tcp"], "必须先 UDP（首包 + EDNS0 重发）再 TCP");
    assert_eq!(&trace[0].1[10..12], [0x00, 0x00], "首包无 EDNS0（ARCOUNT=0）");
    assert_go_edns0_opt(&trace[1].1);
    assert!(Message::from_vec(&trace[2].1).is_ok(), "TCP 侧必须是裸 DNS 报文（不是 XUDP 帧）");
}

/// 恒回 TC=1 的假 UDP 会话（首包与 EDNS0 重发都截断）。
struct AlwaysTruncatedSession {
    req_id: u16,
}

impl crate::dial::UdpPacketSession for AlwaysTruncatedSession {
    fn send_packet<'s>(
        &'s mut self,
        _dest: &'s Destination,
        payload: &'s [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 's>> {
        if let [hi, lo, ..] = payload {
            self.req_id = u16::from_be_bytes([*hi, *lo]);
        }
        Box::pin(async { Ok(()) })
    }

    fn recv_packet(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = io::Result<Option<Vec<u8>>>> + Send + '_>> {
        let req_id = self.req_id;
        Box::pin(async move {
            let mut msg = Message::new(req_id, MessageType::Response, OpCode::Query);
            msg.add_query(Query::query(Name::parse("fb.com.", None).unwrap(), RecordType::A));
            msg.metadata.truncation = true;
            Ok(Some(msg.to_vec().unwrap()))
        })
    }
}

/// 记录 TCP 拨号的假 dialer：UDP 恒回 TC=1；TCP 侧记 dest 并真连上游。
#[derive(Default)]
struct TcpFallbackDialer {
    tcp_dests: parking_lot::Mutex<Vec<Destination>>,
}

impl crate::dial::QueryDialer for TcpFallbackDialer {
    fn dial_tcp(
        &self,
        dest: &Destination,
    ) -> Pin<Box<dyn Future<Output = io::Result<crate::dial::DnsStream>> + Send + '_>> {
        self.tcp_dests.lock().push(dest.clone());
        let dest = dest.clone();
        Box::pin(async move {
            // 复刻生产判别点：dispatcher 把 dest 原样交给 freedom，freedom 按
            // `dest.network()` 选 UDP 中继（不是流式 link）。
            if dest.network() != Network::TCP {
                return Err(io::Error::other(format!(
                    "freedom relays {:?} dest as datagrams",
                    dest.network()
                )));
            }
            let ip = dest.address().ip().ok_or_else(|| io::Error::other("test dest is IP"))?;
            let tcp =
                tokio::net::TcpStream::connect(SocketAddr::new(ip, dest.port().value())).await?;
            Ok(Box::new(xray_transport::connection::TcpConnection::new(tcp))
                as crate::dial::DnsStream)
        })
    }

    fn dial_udp(
        &self,
        _dest: &Destination,
    ) -> Pin<Box<dyn Future<Output = io::Result<Box<dyn crate::dial::UdpPacketSession>>> + Send + '_>>
    {
        Box::pin(async { Ok(Box::new(AlwaysTruncatedSession { req_id: 0 }) as Box<_>) })
    }
}

/// bd wxr6u 回归钉：TCP 兜底必须以 **TCP 网络位** 拨号，且线上写「2B 长度前缀 +
/// 裸 DNS 报文」而非 XUDP 帧。
///
/// 生产症状（勿复现验证）：dest 沿用 UDP 网络 → freedom 走 UDP 中继 → 长度前缀
/// 流被当 XUDP 帧解析 → 上游零 tcp-accept、客户端读长度超时。
#[tokio::test]
#[allow(clippy::await_holding_lock)] // 测试全局槽位锁刻意跨 await 串行化（无争用场景）
async fn tcp_fallback_dials_tcp_network_with_bare_dns() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let _slot = DIALER_SLOT_LOCK.lock();

    // 真 TCP DNS 上游：读 2B 长度 + 报文，回一条 A 记录（请求 ID 回显）。
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_addr = listener.local_addr().unwrap();
    let seen: Arc<parking_lot::Mutex<Vec<Vec<u8>>>> = Arc::default();
    let seen_srv = seen.clone();
    let _server = xray_common::testing::spawn("dns-tcp-fallback-server", async move {
        let (mut stream, _) = listener.accept().await.expect("fallback dialed no TCP conn");
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await.unwrap();
        let mut query = vec![0u8; usize::from(u16::from_be_bytes(len_buf))];
        stream.read_exact(&mut query).await.unwrap();
        seen_srv.lock().push(query.clone());
        // 裸 DNS 报文才能从偏移 0 解出 Message；XUDP 帧在这必解失败。
        let msg = Message::from_vec(&query)
            .expect("fallback wire bytes must be a bare DNS message, not an XUDP frame");
        let resp = make_a_response(msg.metadata.id, "fb.com.", vec![Ipv4Addr::new(5, 6, 7, 8)], 60);
        stream.write_all(&u16::try_from(resp.len()).unwrap().to_be_bytes()).await.unwrap();
        stream.write_all(&resp).await.unwrap();
    });

    let dialer = Arc::new(TcpFallbackDialer::default());
    crate::dial::set_shared_dialer(Some(dialer.clone()));

    let ns = UdpNameServer::new(
        // 与 TCP 上游同 IP/端口：兜底只改网络位，地址沿用 `self.dest`。
        udp_dest(tcp_addr),
        Arc::new(CacheController::new("test", true, false, 0, 0)),
        Vec::new(),
        Duration::from_secs(2),
        Arc::new(crate::dial::SystemHostResolver),
    );
    let outcome = ns
        .query_once("fb.com.", RecordType::A, Budget::tokio().deadline(Duration::from_secs(2)))
        .await;
    crate::dial::set_shared_dialer(None);

    let rec = outcome.expect("TCP 兜底必须返回答案");
    assert_eq!(rec.ips, vec![IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8))]);

    let dests = dialer.tcp_dests.lock();
    assert_eq!(dests.len(), 1, "兜底必须拨号恰好一次");
    assert_eq!(
        dests[0].network(),
        Network::TCP,
        "兜底必须以 TCP 网络拨号，否则 freedom 按 UDP 中继吃掉长度前缀流"
    );
    assert_eq!(dests[0].address(), &Address::from(tcp_addr.ip()));
    assert_eq!(dests[0].port().value(), tcp_addr.port());
}

/// 上游 UDP 直接回完整答案 → **零额外查询**（既不 EDNS0 重发也不 TCP 兜底）。
#[tokio::test]
#[allow(clippy::await_holding_lock)] // 测试全局槽位锁刻意跨 await 串行化（无争用场景）
async fn complete_udp_response_triggers_no_extra_query() {
    let _slot = DIALER_SLOT_LOCK.lock();
    let (udp, tcp, addr) = bind_udp_tcp_same_port().await;
    let udp_queries = Arc::new(parking_lot::Mutex::new(0u32));
    let tcp_accepts = Arc::new(parking_lot::Mutex::new(0u32));
    let uq = udp_queries.clone();
    let _udp_task = xray_common::testing::spawn("dns-full-udp", async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((n, peer)) = udp.recv_from(&mut buf).await else { return };
            *uq.lock() += 1;
            let Ok(query) = Message::from_vec(&buf[..n]) else { continue };
            let resp = make_a_response(
                query.metadata.id,
                "full.com.",
                vec![Ipv4Addr::new(3, 3, 3, 3)],
                60,
            );
            let _ = udp.send_to(&resp, peer).await;
        }
    });
    let ta = tcp_accepts.clone();
    let _tcp_task = xray_common::testing::spawn("dns-full-tcp-watch", async move {
        while let Ok((_stream, _)) = tcp.accept().await {
            *ta.lock() += 1;
        }
    });

    let ns = UdpNameServer::new(
        udp_dest(addr),
        Arc::new(CacheController::new("test", true, false, 0, 0)),
        Vec::new(),
        Duration::from_secs(2),
        Arc::new(crate::dial::SystemHostResolver),
    );
    let rec = ns
        .query_once("full.com.", RecordType::A, Budget::tokio().deadline(Duration::from_secs(2)))
        .await
        .expect("完整答案必须直接收场");
    assert_eq!(rec.ips, vec![IpAddr::V4(Ipv4Addr::new(3, 3, 3, 3))]);
    assert_eq!(*udp_queries.lock(), 1, "完整答案不得触发额外 UDP 查询");
    assert_eq!(*tcp_accepts.lock(), 0, "完整答案不得触发 TCP 兜底");
}
