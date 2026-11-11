//! B5 端到端实证（规划 §5 B5.1/B5.3 + 任务书 M2-5/U3）：
//!
//! 1. [`two_seeds_ping_each_other_via_tunnel_forwarding`] — 两 seed 隧道间互 ping （Go
//!    `server.go:428-437` 隧道间转发路径：512 有界队列 → 对端写泵），ICMP 双向
//!    往返逐包校验；并断言转发**不进本机栈/dispatch**（`server.go:405-413` 命中即 continue 语义）。
//! 2. [`masque_inbound_private_target_blocked_without_dialing`] — 私有地址阻断实证： masque 入站 →
//!    freedom 出站（真 `FreedomDispatchBridge` + Go 默认规则表 `get_default_rule_type("masque") =
//!    BlockPrivate`）→ `10.0.0.1` 被黑洞且**零拨号** （计数拨号 canary；正控 = 无默认规则的桥必拨号
//!    1 次，证明观察手段看得见拨号， xray-cli v787x 同款判别力设计）。
//!
//! 链路：Rust 客户端（生产 `make_masque_dial_fn`：隧道 + 栈内 TCP connect）→ Rust
//! 服务端（生产 `serve()`：hub + gate + 包路由 + 栈桥）→ `dispatch_with_access`
//! （`inbound_tag = "masque-in"`）→ freedom 默认规则。
//!
//! 测试基建 spawn 豁免（坑约束 #5）：echo 监听任务为测试基建（spawn 三分类②）。
#![allow(clippy::disallowed_methods)]

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use xray_app_dispatcher::{
    DispatchHandler,
    default::{DialBridge, DialFn, PinFuture},
};
use xray_common::net::{address::Address, destination::Destination, port::Port};
use xray_frame::scope::ComponentScope;
use xray_proxy_freedom::FreedomDispatchBridge;
use xray_proxy_masque::{
    client::{make_masque_dial_fn, parse_client_settings},
    server::{MasqueServer, parse_server_settings, serve},
};
use xray_transport::{
    connection::Connection, dialer::StreamSettings, listener_registry::TransportListener,
    sockopt::SocketOptions,
};

const ECHO_USER: &str = "t@example.com";
const ECHO_PASS: &str = "secret";

/// 服务端实例序号（temp 目录唯一化——同用例起双服务端）。
static SERVER_SEQ: AtomicUsize = AtomicUsize::new(0);

// ===== 共享 harness =====

struct MasqueServerGuard {
    listener: Box<dyn TransportListener>,
    server: Arc<MasqueServer>,
    tmp: PathBuf,
    pin: String,
}

impl MasqueServerGuard {
    fn port(&self) -> u16 {
        self.listener.local_addr().expect("local addr").port()
    }
}

impl Drop for MasqueServerGuard {
    fn drop(&mut self) {
        self.server.close();
        let _ = self.listener.close();
        let _ = std::fs::remove_dir_all(&self.tmp);
    }
}

/// 起 MASQUE 服务端（生产 `serve()` 全链：hub TLS(h2) + gate + 地址池 +
/// 包路由 + 栈桥），dispatch 由用例注入。
async fn masque_server(tag: &str, dispatch: Arc<dyn DispatchHandler>) -> MasqueServerGuard {
    let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("params");
    let key_pair = rcgen::KeyPair::generate().expect("keypair");
    let cert = params.self_signed(&key_pair).expect("self signed");
    let pin = xray_tls::pin::generate_cert_hash_hex(cert.der());

    let tmp = std::env::temp_dir().join(format!(
        "masque-b5-server-{}-{}-{}",
        tag.replace('/', "_"),
        std::process::id(),
        SERVER_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&tmp).expect("mkdir");
    let cert_path = tmp.join("cert.pem");
    let key_path = tmp.join("key.pem");
    std::fs::write(&cert_path, cert.pem()).expect("write cert");
    std::fs::write(&key_path, key_pair.serialize_pem()).expect("write key");

    let settings = parse_server_settings(&serde_json::json!({
        "users": [{ "email": ECHO_USER, "pass": ECHO_PASS }],
        "address": ["198.18.0.1/15"],
    }))
    .expect("server settings");

    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind probe");
    let addr = probe.local_addr().expect("addr");
    drop(probe);

    let stream = StreamSettings {
        protocol: "masque".into(),
        security: "tls".into(),
        security_json: Some(serde_json::json!({
            "alpn": ["h2"],
            "certificates": [
                {
                    "certificateFile": cert_path.display().to_string(),
                    "keyFile": key_path.display().to_string(),
                },
            ],
        })),
        ..StreamSettings::tcp()
    };
    let (listener, server) = serve(
        addr,
        tag,
        settings,
        dispatch,
        ComponentScope::new("b5-e2e"),
        stream,
        SocketOptions::default(),
    )
    .await
    .expect("serve masque");
    MasqueServerGuard { listener, server, tmp, pin }
}

/// 拨一条隧道到指定端口的服务端（transport 层生产 dial 全链）。
async fn dial_seed(port: u16, pin: &str) -> xray_transport_masque::connect::ConnectIpSession {
    let settings = StreamSettings {
        protocol: "masque".into(),
        security: "tls".into(),
        security_json: Some(serde_json::json!({
            "serverName": "localhost",
            "alpn": ["h2"],
            "pinnedPeerCertSha256": pin,
        })),
        ..StreamSettings::tcp()
    };
    let masque_cfg = xray_transport_masque::Config::from_json(Some(&serde_json::json!({
        "user": ECHO_USER,
        "pass": ECHO_PASS,
    })))
    .expect("masque settings");
    let dest = Destination::tcp(Address::ipv4(Ipv4Addr::LOCALHOST), Port::new(port));
    xray_transport_masque::dialer::dial(&dest, &SocketOptions::default(), &settings, &masque_cfg)
        .await
        .expect("seed tunnel dial")
}

fn seed_v4(session: &xray_transport_masque::connect::ConnectIpSession) -> Ipv4Addr {
    session
        .local_addrs()
        .iter()
        .find_map(|a| if let IpAddr::V4(v) = a { Some(*v) } else { None })
        .expect("server must assign a v4 address")
}

/// ICMP echo request/reply（proto=1；转发链路不校验 ICMP 校验和——
/// 客户端入站验证只查地址归属，校验和语义属栈内路径）。
fn icmp_ping(src: Ipv4Addr, dst: Ipv4Addr, id: u16, seq: u16, reply: bool) -> Vec<u8> {
    let mut p = vec![0u8; 20 + 8];
    p[0] = 0x45;
    let total = p.len() as u16;
    p[2..4].copy_from_slice(&total.to_be_bytes());
    p[8] = 64;
    p[9] = 1; // ICMP
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    p[20] = if reply { 0 } else { 8 };
    p[24..26].copy_from_slice(&id.to_be_bytes());
    p[26..28].copy_from_slice(&seq.to_be_bytes());
    p
}

fn is_icmp(pkt: &[u8], dst: Ipv4Addr, icmp_type: u8, id: u16, seq: u16) -> bool {
    pkt.len() == 28
        && pkt[9] == 1
        && pkt[16..20] == dst.octets()
        && pkt[20] == icmp_type
        && pkt[24..26] == id.to_be_bytes()
        && pkt[26..28] == seq.to_be_bytes()
}

/// 等待匹配包（整体 10s / 单次读 5s；不匹配包跳过——两 seed 场景可能有迟到的
/// 迟响应包）。超时 panic（fail-loud）。
async fn recv_matching(
    session: &mut xray_transport_masque::connect::ConnectIpSession,
    want: impl Fn(&[u8]) -> bool,
    what: &str,
) -> Vec<u8> {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(5), session.recv_packet()).await {
            Ok(Ok(p)) if want(&p) => return p,
            Ok(Ok(_)) => continue,
            _ => break,
        }
    }
    panic!("timed out waiting for {what}");
}

/// 环回 echo 监听器（被拨号即计数 + 逐字节回显）。
async fn echo_listener() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("echo bind");
    let addr = listener.local_addr().expect("echo addr");
    let accepts = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepts);
    // 测试基建任务（spawn 三分类②）：canary 监听，随用例生命周期。
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else { break };
            counter.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buf = [0u8; 512];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        },
                    }
                }
            });
        }
    });
    (addr, accepts)
}

/// 计数拨号闭包（canary）：目标恒为本地 echo 监听器——一旦被 freedom 真实拨号
/// 计数必 > 0 且能收到回显；BlockPrivate 命中时计数必须停在 0。
fn counting_dial(target: SocketAddr) -> (Arc<AtomicUsize>, DialFn) {
    let dials = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&dials);
    let dial: DialFn = Arc::new(move |_dest: &Destination| {
        counter.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            let stream = tokio::net::TcpStream::connect(target)
                .await
                .map_err(|e| format!("test dial: {e}"))?;
            Ok(Box::new(xray_transport::connection::TcpConnection::new(stream))
                as Box<dyn Connection>)
        }) as PinFuture<Result<Box<dyn Connection>, String>>
    });
    (dials, dial)
}

/// 构造生产客户端 DialFn（`make_masque_dial_fn`：隧道 + 栈内拨号全链）。
fn masque_client(port: u16, pin: &str, ctx: &Arc<xray_frame::PluginContext>) -> DialFn {
    let client = parse_client_settings(&serde_json::json!({
        "address": "127.0.0.1",
        "port": port,
    }))
    .expect("client settings");
    let transport = StreamSettings {
        protocol: "masque".into(),
        security: "tls".into(),
        security_json: Some(serde_json::json!({
            "serverName": "localhost",
            "alpn": ["h2"],
            "pinnedPeerCertSha256": pin,
        })),
        // make_masque_dial_fn 从 transport_json 解析 masqueSettings（user/pass →
        // Basic 认证）；缺失 = gate 401（曾漏配，假过阶段1）。
        transport_json: Some(serde_json::json!({ "user": ECHO_USER, "pass": ECHO_PASS })),
        ..StreamSettings::tcp()
    };
    make_masque_dial_fn(client, transport, SocketOptions::default(), Arc::clone(ctx))
}

// ===== U3：双 seed 隧道间互 ping =====

/// 两 seed（两条隧道）互 ping：ICMP 双向 × 4 包逐包校验（Go `server.go:428-437`
/// 隧道间转发 + `tunnelQueueSize=512` 有界队列语义）；并断言隧道间命中的包
/// **不进本机栈/dispatch**（`server.go:405-413` 命中即 continue）。
#[tokio::test]
async fn two_seeds_ping_each_other_via_tunnel_forwarding() {
    let dispatch_calls = Arc::new(AtomicUsize::new(0));

    #[derive(Debug)]
    struct CountingDispatch(Arc<AtomicUsize>);
    impl DispatchHandler for CountingDispatch {
        fn tag(&self) -> &str {
            "b5-no-dispatch"
        }

        fn dispatch(
            &self,
            _dest: &Destination,
            _link: xray_transport::link::Link,
        ) -> PinFuture<()> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {})
        }
    }

    let srv =
        masque_server("masque-in", Arc::new(CountingDispatch(Arc::clone(&dispatch_calls)))).await;

    let mut s1 = dial_seed(srv.port(), &srv.pin).await;
    let mut s2 = dial_seed(srv.port(), &srv.pin).await;
    let a1 = seed_v4(&s1);
    let a2 = seed_v4(&s2);
    assert_ne!(a1, a2, "two seeds must get distinct addresses");
    // 收敛窗：隧道的注册发生在分配胶囊写出之后（服务端任务内），留确定性余量。
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 方向 1：s1 → a2 四连 ping，s2 逐包回应。
    for seq in 0..4u16 {
        let sent = s1.send_packet(&icmp_ping(a1, a2, 0xB501, seq, false)).await.expect("send ping");
        assert!(sent.is_none(), "ICMP within MTU must not yield ICMP-too-big");
    }
    for seq in 0..4u16 {
        let req = recv_matching(
            &mut s2,
            |p| is_icmp(p, a2, 8, 0xB501, seq),
            &format!("echo request seq={seq} on seed2"),
        )
        .await;
        assert_eq!(&req[12..16], &a1.octets(), "request src must be seed1");
        let _ = s2.send_packet(&icmp_ping(a2, a1, 0xB501, seq, true)).await;
    }
    for seq in 0..4u16 {
        let rep = recv_matching(
            &mut s1,
            |p| is_icmp(p, a1, 0, 0xB501, seq),
            &format!("echo reply seq={seq} on seed1"),
        )
        .await;
        assert_eq!(&rep[12..16], &a2.octets(), "reply src must be seed2");
    }

    // 方向 2：s2 → a1 四连 ping（转发路径对称性）。
    for seq in 0..4u16 {
        let _ = s2.send_packet(&icmp_ping(a2, a1, 0xB502, seq, false)).await;
    }
    for seq in 0..4u16 {
        recv_matching(
            &mut s1,
            |p| is_icmp(p, a1, 8, 0xB502, seq),
            &format!("reverse echo request seq={seq}"),
        )
        .await;
        let _ = s1.send_packet(&icmp_ping(a1, a2, 0xB502, seq, true)).await;
    }
    for seq in 0..4u16 {
        recv_matching(
            &mut s2,
            |p| is_icmp(p, a2, 0, 0xB502, seq),
            &format!("reverse echo reply seq={seq}"),
        )
        .await;
    }

    // 隧道间命中即转发——本机栈/dispatch 必须零消费。
    assert_eq!(
        dispatch_calls.load(Ordering::SeqCst),
        0,
        "tunnel-to-tunnel hits must never reach the local stack/dispatch"
    );
    println!("门 B5 U3 PASS: two seeds pinged each other (8 requests, 8 replies, lossless)");

    s1.close();
    s2.close();
    drop(srv);
}

// ===== B5.3：私有地址阻断实证（黑洞且不拨号） =====

/// masque 入站 → freedom 出站：`10.0.0.1:80` 命中 Go 默认规则
/// `get_default_rule_type("masque") = BlockPrivate` → 黑洞 + **零拨号**。
///
/// 正控（判别力）：无默认规则的 freedom 桥（对齐 Go `inbound == nil`）同链路必
/// 拨号 1 次并回显——证明「0」是真阻断而非观察手段失明（xray-cli v787x 同款设计）。
#[tokio::test]
async fn masque_inbound_private_target_blocked_without_dialing() {
    // 预检：Go 默认规则表确有 masque → BlockPrivate（端到端断言的前提）。
    assert_eq!(
        xray_proxy_freedom::get_default_rule_type("masque"),
        Some(xray_proxy_freedom::DefaultRuleType::BlockPrivate),
        "freedom default rule table must map masque to BlockPrivate"
    );

    let (echo_addr, accepts) = echo_listener().await;
    let (dials_blocked, dial_blocked) = counting_dial(echo_addr);
    let (dials_open, dial_open) = counting_dial(echo_addr);

    let ctx_freedom = Arc::new(xray_frame::PluginContext::for_plugin("masque-e2e-freedom"));
    // 阻断桥：inbound tag "masque-in" → BlockPrivate（生产 `inbound_default_rules`
    // 同形：tag → get_default_rule_type(kind)）。
    let blocked_bridge = FreedomDispatchBridge::from_bridge(
        Arc::clone(&ctx_freedom),
        Arc::new(DialBridge::new("freedom-out", dial_blocked)),
    )
    .with_inbound_default_rules(HashMap::from([(
        "masque-in".to_string(),
        xray_proxy_freedom::DefaultRuleType::BlockPrivate,
    )]));
    // 正控桥：无默认规则（Go `inbound == nil`）。
    let open_bridge = FreedomDispatchBridge::from_bridge(
        Arc::clone(&ctx_freedom),
        Arc::new(DialBridge::new("freedom-out", dial_open)),
    );

    let blocked = masque_server("masque-in", Arc::new(blocked_bridge)).await;
    let open = masque_server("masque-in", Arc::new(open_bridge)).await;
    let ctx_client = Arc::new(xray_frame::PluginContext::for_plugin("masque-e2e-client"));
    let client_blocked = masque_client(blocked.port(), &blocked.pin, &ctx_client);
    let client_open = masque_client(open.port(), &open.pin, &ctx_client);

    // 阶段 1：隧道内目标 10.0.0.1:80（RFC1918 私有）→ BlockPrivate → 黑洞 + 零拨号。
    let dest_private = Destination::tcp(Address::ipv4(Ipv4Addr::new(10, 0, 0, 1)), Port::new(80));
    let dialed = tokio::time::timeout(Duration::from_secs(15), client_blocked(&dest_private))
        .await
        .expect("blocked dial must resolve (tunnel + stack handshake converge)")
        .map_err(|e| format!("tunnel dial: {e}"));
    if let Ok(mut conn) = dialed {
        // 黑洞语义（Go blockedDest :352-366 慢速丢弃防探测，block_delay 缺省
        // 30-90s 后才关链）：不拨号、不回数据；窗口内必须静默（超时/EOF/错误
        // 都是收敛形态，唯独「读到数据」= 未阻断）。
        let _ = conn.write_all(b"b5-blocked-probe").await;
        let mut probe = [0u8; 16];
        match tokio::time::timeout(Duration::from_secs(2), conn.read(&mut probe)).await {
            Err(_) | Ok(Ok(0)) | Ok(Err(_)) => {},
            Ok(Ok(n)) => panic!("blackholed target must not return data, got {n} bytes"),
        }
    }
    assert_eq!(
        dials_blocked.load(Ordering::SeqCst),
        0,
        "10.0.0.1 must be blackholed by freedom default BlockPrivate with ZERO dials"
    );
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        0,
        "echo canary must never see a connection for the blocked target"
    );

    // 阶段 2 正控：无默认规则的桥 + 公网标签目的（TEST-NET-3 203.0.113.1）→
    // 必拨号 + 回显。目的**禁用环回**：bd t8pm `not_forwardable` 在栈入口静默吞
    // dst=loopback 包（隧道对端不应请求本机自身——设计语义），会得到假 Ok 半开
    // 连接；计数拨号 canary 只看「是否拨号」，连接目标恒为本地 echo 监听器
    // （拨号目标被测试内 intercept，零真实外网流量）。
    let dest_echo = Destination::tcp(Address::ipv4(Ipv4Addr::new(203, 0, 113, 1)), Port::new(9999));
    let mut conn = tokio::time::timeout(Duration::from_secs(15), client_open(&dest_echo))
        .await
        .expect("open dial must resolve")
        .map_err(|e| format!("tunnel dial: {e}"))
        .expect("open dial must succeed");
    conn.write_all(b"b5-e2e-ping").await.expect("write through tunnel");
    let mut buf = [0u8; 32];
    let read = tokio::time::timeout(Duration::from_secs(10), conn.read(&mut buf)).await;
    if read.is_err() {
        println!(
            "[diag] dials_open={} accepts={} (read timeout)",
            dials_open.load(Ordering::SeqCst),
            accepts.load(Ordering::SeqCst)
        );
    }
    let n = read.expect("echo read must converge").expect("echo read must not error");
    assert_eq!(
        &buf[..n],
        b"b5-e2e-ping",
        "payload must roundtrip through masque tunnel + freedom bridge"
    );
    assert_eq!(
        dials_open.load(Ordering::SeqCst),
        1,
        "正控: bridge without default rules must dial exactly once (canary discriminative power)"
    );
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        1,
        "echo canary must have accepted the dialed connection"
    );

    println!(
        "门 B5 B5.3 PASS: 10.0.0.1 blackholed with 0 dials; positive control dialed 1 + echoed"
    );

    drop(conn);
    drop(blocked);
    drop(open);
}

// ===== 诊断探针：裸 TCP 握手过隧道（定位 dispatch 不触发的断点面） =====

/// 裸 IPv4/TCP 包（真实校验和；flags: 0x02=SYN 0x10=ACK 0x12=SYN|ACK 0x18=ACK|PSH）。
#[allow(
    clippy::too_many_arguments,
    reason = "8/7 参：裸 TCP 包构造器逐字段对齐头布局（src/sport/dst/dport/seq/ack/flags/payload），借用结构体无语义收益（server.rs 同款台账）"
)]
#[allow(dead_code)] // 诊断探针基建
fn ipv4_tcp(
    src: Ipv4Addr,
    sport: u16,
    dst: Ipv4Addr,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut p = vec![0u8; 20 + 20 + payload.len()];
    p[0] = 0x45;
    let total = p.len() as u16;
    p[2..4].copy_from_slice(&total.to_be_bytes());
    p[8] = 64;
    p[9] = 6; // TCP
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    p[20..22].copy_from_slice(&sport.to_be_bytes());
    p[22..24].copy_from_slice(&dport.to_be_bytes());
    p[24..28].copy_from_slice(&seq.to_be_bytes());
    p[28..32].copy_from_slice(&ack.to_be_bytes());
    p[32] = 5 << 4; // data offset = 5 words
    p[33] = flags;
    p[34..36].copy_from_slice(&65535u16.to_be_bytes()); // window
    p[20 + 20..].copy_from_slice(payload);
    // TCP 校验和：伪头（src/dst/zero/proto/len）+ 段（校验和清零）。
    let mut sum: u32 = 0;
    let mut chunks = [
        src.octets().as_slice(),
        dst.octets().as_slice(),
        &[0u8, 6],
        &((p.len() - 20) as u16).to_be_bytes()[..],
        &p[20..],
    ]
    .concat();
    if chunks.len() % 2 == 1 {
        chunks.push(0);
    }
    for c in chunks.chunks_exact(2) {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    while (sum >> 16) > 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    p[20 + 16..20 + 18].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    p
}

/// 诊断探针（#[ignore]）：transport 级裸 TCP 握手过隧道 → 观察 freedom 桥是否
/// 拨号。剥离 masque 客户端，二分「server 栈 accept→dispatch」vs「client」。
#[tokio::test]
#[ignore = "诊断探针：裸 TCP 握手定位 dispatch 断点（b5 排障用）"]
async fn probe_raw_tcp_handshake_fires_dispatch() {
    let (echo_addr, accepts) = echo_listener().await;
    let (dials, dial) = counting_dial(echo_addr);
    let ctx = Arc::new(xray_frame::PluginContext::for_plugin("probe-freedom"));
    let bridge =
        FreedomDispatchBridge::from_bridge(ctx, Arc::new(DialBridge::new("freedom-out", dial)));
    let srv = masque_server("masque-in", Arc::new(bridge)).await;
    let mut seed = dial_seed(srv.port(), &srv.pin).await;
    let a = seed_v4(&seed);
    tokio::time::sleep(Duration::from_millis(200)).await;

    // SYN → 10.9.9.9:9999（非环回私有，open 桥无规则 → 应拨号）。
    seed.send_packet(&ipv4_tcp(a, 40000, Ipv4Addr::new(10, 9, 9, 9), 9999, 1000, 0, 0x02, b""))
        .await
        .expect("send SYN");
    // SYN-ACK。
    let mut server_seq = 0u32;
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        let pkt = match tokio::time::timeout(Duration::from_secs(2), seed.recv_packet()).await {
            Ok(Ok(p)) if p.len() >= 40 && p[9] == 6 => p,
            Ok(Ok(_)) => continue,
            _ => break,
        };
        let flags = pkt[20 + 13];
        if flags & 0x12 == 0x12 {
            server_seq = u32::from_be_bytes([pkt[24], pkt[25], pkt[26], pkt[27]]);
            break;
        }
    }
    assert!(server_seq != 0, "no SYN-ACK from server stack");
    println!("[probe] SYN-ACK ok, server_seq={server_seq}");
    // ACK。
    seed.send_packet(&ipv4_tcp(
        a,
        40000,
        Ipv4Addr::new(10, 9, 9, 9),
        9999,
        1001,
        server_seq + 1,
        0x10,
        b"",
    ))
    .await
    .expect("send ACK");
    // PSH 数据。
    seed.send_packet(&ipv4_tcp(
        a,
        40000,
        Ipv4Addr::new(10, 9, 9, 9),
        9999,
        1001,
        server_seq + 1,
        0x18,
        b"probe-data",
    ))
    .await
    .expect("send PSH");
    tokio::time::sleep(Duration::from_secs(2)).await;
    println!(
        "[probe] dials={} accepts={} (non-loopback dst 10.9.9.9:9999)",
        dials.load(Ordering::SeqCst),
        accepts.load(Ordering::SeqCst)
    );
    assert!(dials.load(Ordering::SeqCst) >= 1, "open bridge must dial on raw TCP data");

    // 对照组：masque 客户端（make_masque_dial_fn）→ 同服务器 → 非环回目的。
    // 计数拨号忽略 dest 直连 target——拨了就计数，回显即数据面通。
    let ctx_client = Arc::new(xray_frame::PluginContext::for_plugin("probe-masque-client"));
    let client = masque_client(srv.port(), &srv.pin, &ctx_client);
    let dest_m = Destination::tcp(Address::ipv4(Ipv4Addr::new(10, 9, 9, 9)), Port::new(9999));
    let dialed = tokio::time::timeout(Duration::from_secs(15), client(&dest_m)).await;
    match dialed {
        Err(_) => println!("[probe] masque client dial TIMEOUT"),
        Ok(Err(e)) => println!("[probe] masque client dial ERR: {e}"),
        Ok(Ok(mut conn)) => {
            if let Err(e) = conn.write_all(b"mprobe").await {
                println!("[probe] masque client write ERR: {e}");
            } else {
                let mut buf = [0u8; 16];
                match tokio::time::timeout(Duration::from_secs(5), conn.read(&mut buf)).await {
                    Err(_) => println!("[probe] masque client read TIMEOUT (no echo)"),
                    Ok(Err(e)) => println!("[probe] masque client read ERR: {e}"),
                    Ok(Ok(0)) => println!("[probe] masque client read EOF"),
                    Ok(Ok(n)) => println!("[probe] masque client echo {n} bytes OK"),
                }
            }
        },
    }
    println!(
        "[probe] final dials={} accepts={}",
        dials.load(Ordering::SeqCst),
        accepts.load(Ordering::SeqCst)
    );
}
