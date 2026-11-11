//! MASQUE 三方向对拍矩阵（任务书 §5.2：**A/B/C 缺一不算过**）+ 方向 C 的 64KB 连续往返。
//!
//! 规划：`docs/architecture/xray-frame-masque-实施计划-2026-11-11.md` §5 B5.1 / §6 门 B5；
//! 方向矩阵与判据：`docs/architecture/xray-frame-masque-契约级任务书-2026-10-30.md` §5.2。
//!
//! | 方向 | 测试 | 门控 | 判据 |
//! |---|---|---|---|
//! | A：Rust client → **Go server** | `go_server_dns_roundtrip` | `#[ignore]` + `MASQUE_GO_XRAY` | ①ADDRESS_ASSIGN 非 0.0.0.0 ②IPv4/UDP DNS 同 id 往返 ③Go 日志 `assigned [...]` |
//! | B：**Go client** → Rust server | `go_client_dns_roundtrip_via_rust_server` | `#[ignore]` + `MASQUE_GO_XRAY` | 同 ②，判据换 Rust 侧（gate 认证记录 + 分配记录；Go 侧拿到的分配由 dokodemo 透明往返行为证明——抓包面沿用 B2 先例以行为断言替代） |
//! | C：Rust client ↔ **Rust server** | `rust_to_rust_dns_and_64k_roundtrip` | 默认跑（零外部依赖） | 同 ② + 64KB（64×1KB）连续 IP 包往返不丢 |
//!
//! 运行（A/B）：
//! ```text
//! cargo test -p xray-transport-masque --test connectip_go_interop -- --ignored --nocapture
//! ```
//!
//! Rust 服务端 = 测试内 echo harness（hub + gate + 最小 acceptor：主动分配 + 全路由
//! 通告 + ADDRESS_REQUEST 回应 + 隧道层 UDP 回声）。Go 客户端（方向 B）经
//! dokodemo-door（UDP 透明转发）驱动——不解析 Go 内部栈，只断言端到端行为。
//!
//! 测试基建 spawn 豁免（坑约束 #5）：Go 服务端进程与 server/echo 任务均为测试基建
//! （spawn 三分类②）。
#![allow(clippy::disallowed_methods)]

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::{Duration, Instant},
};

use base64::Engine as _;
use xray_common::net::{address::Address, destination::Destination, port::Port};
use xray_transport::{
    dialer::StreamSettings, listener_registry::TransportListener, sockopt::SocketOptions,
};
use xray_transport_masque::{
    capsule::{AddressRequestEntry, AssignedAddress, IpPrefix, IpRoute},
    connect::ConnectIpSession,
    hub::{self, GateDeny, GateGrant, RequestMeta, ServerConn, TunnelAcceptor, TunnelGate},
};

// ===== 共享面：证书 / Go 二进制 / 包构造 / DNS =====

/// Go xray 二进制（v26.11.9；`D:/Project/Xray-core` @ 676eaf66 `go build -o ... ./main`）。
fn go_binary() -> PathBuf {
    let bin = std::env::var("MASQUE_GO_XRAY")
        .unwrap_or_else(|_| r"D:/tmp/xray-v2611/xray.exe".to_string());
    let bin = PathBuf::from(&bin);
    assert!(
        bin.is_file(),
        "Go xray binary missing at {}: build via `cd D:/Project/Xray-core && go build -o {} ./main`",
        bin.display(),
        bin.display()
    );
    bin
}

fn self_signed_cert() -> (String, String, String) {
    let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("params");
    let key_pair = rcgen::KeyPair::generate().expect("keypair");
    let cert = params.self_signed(&key_pair).expect("self signed");
    let pin = xray_tls::pin::generate_cert_hash_hex(cert.der());
    (cert.pem(), key_pair.serialize_pem(), pin)
}

fn tls_server_settings(cert_path: &Path, key_path: &Path) -> StreamSettings {
    StreamSettings {
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
    }
}

fn tls_client_settings(pin: &str) -> StreamSettings {
    StreamSettings {
        protocol: "masque".into(),
        security: "tls".into(),
        security_json: Some(serde_json::json!({
            "serverName": "localhost",
            "alpn": ["h2"],
            "pinnedPeerCertSha256": pin,
        })),
        ..StreamSettings::tcp()
    }
}

/// 构造 IPv4/UDP 包（src=src:sport → dst=remote:remote_port；TTL 64）。UDP 校验和
/// 按 IPv4 伪头真实计算——Go 侧 netstack（gVisor）按「来自网络」的包校验传输层
/// 校验和，置 0 会被静默丢弃（B2 实录）。
fn ipv4_udp(
    src: Ipv4Addr,
    sport: u16,
    remote: Ipv4Addr,
    remote_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut p = vec![0u8; 20 + 8 + payload.len()];
    p[0] = 0x45;
    let total = p.len() as u16;
    p[2..4].copy_from_slice(&total.to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&remote.octets());
    p[20..22].copy_from_slice(&sport.to_be_bytes());
    p[22..24].copy_from_slice(&remote_port.to_be_bytes());
    let udp_len = (8 + payload.len()) as u16;
    p[20 + 4..20 + 6].copy_from_slice(&udp_len.to_be_bytes());
    p[20 + 8..].copy_from_slice(payload);
    // UDP 校验和：伪头（src/dst/zero/proto/len）+ UDP 头（校验和字段清零）+ 载荷。
    let mut sum: u32 = 0;
    let mut chunks = [
        src.octets().as_slice(),
        remote.octets().as_slice(),
        &[0u8, 17],
        &udp_len.to_be_bytes()[..],
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
    p[20 + 6..20 + 8].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    p
}

/// 最小 DNS A 查询（example.com，RD 置位）。
fn dns_query(id: u16) -> Vec<u8> {
    let mut dns = Vec::new();
    dns.extend_from_slice(&id.to_be_bytes());
    dns.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]); // RD, QD=1
    dns.extend_from_slice(b"\x07example\x03com\x00");
    dns.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // type A, class IN
    dns
}

/// 等待 DNS 应答（src=1.1.1.1 → dst=local、sport=53、同 id + QR=1）。
/// 超时（整体 15s / 单次读 5s）返回 None。
async fn recv_dns_reply(
    session: &mut ConnectIpSession,
    local: Ipv4Addr,
    query_id: u16,
) -> Option<Vec<u8>> {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        let pkt = match tokio::time::timeout(Duration::from_secs(5), session.recv_packet()).await {
            Ok(Ok(p)) => p,
            _ => continue,
        };
        println!(
            "[recv] len={} proto={} src={:?} dst={:?} sport={}",
            pkt.len(),
            pkt.get(9).copied().unwrap_or(0),
            pkt.get(12..16),
            pkt.get(16..20),
            pkt.get(20..22).map(|b| u16::from_be_bytes([b[0], b[1]])).unwrap_or(0),
        );
        if pkt.len() >= 20 + 8 + 12
            && pkt[9] == 17
            && pkt[12..16] == [1, 1, 1, 1]
            && pkt[16..20] == local.octets()
            && pkt[20..22] == [0, 53]
        {
            let id = u16::from_be_bytes([pkt[28], pkt[29]]);
            let qr = pkt[30] >> 7; // DNS flags 在 DNS 头偏移 2（id 占 2 字节）
            if id == query_id && qr == 1 {
                return Some(pkt);
            }
        }
    }
    None
}

/// 从会话分配地址里取首个 v4（测试断言面）。
fn local_v4(session: &ConnectIpSession) -> Ipv4Addr {
    session
        .local_addrs()
        .iter()
        .find_map(|a| if let IpAddr::V4(v) = a { Some(*v) } else { None })
        .expect("server must assign a v4 address")
}

// ===== Rust echo 服务端 harness（方向 B/C 共用） =====

const ECHO_USER: &str = "t@example.com";
const ECHO_PASS: &str = "secret";

/// gate/acceptor 侧可观察记录（方向 B 的判据①③ Rust 侧替代证据面）。
#[derive(Default)]
struct EchoObservation {
    users: Mutex<Vec<String>>,
    assigned: Mutex<Vec<IpAddr>>,
}

struct EchoServer {
    tmp: PathBuf,
    listener: Box<dyn TransportListener>,
    observed: Arc<EchoObservation>,
    pin: String,
}

impl EchoServer {
    fn port(&self) -> u16 {
        self.listener.local_addr().expect("local addr").port()
    }

    fn users(&self) -> MutexGuard<'_, Vec<String>> {
        self.observed.users.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn assigned(&self) -> MutexGuard<'_, Vec<IpAddr>> {
        self.observed.assigned.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Drop for EchoServer {
    fn drop(&mut self) {
        let _ = self.listener.close();
        let _ = std::fs::remove_dir_all(&self.tmp);
    }
}

/// 起 Rust echo 服务端（hub TLS(h2) + gate（认证 + `198.18.0.x` 顺序分配）+ echo
/// acceptor）。证书/配置自建自清（temp dir）。
async fn start_echo_server() -> EchoServer {
    let (cert_pem, key_pem, pin) = self_signed_cert();
    let tmp = std::env::temp_dir().join(format!("masque-echo-server-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).expect("mkdir");
    let cert_path = tmp.join("cert.pem");
    let key_path = tmp.join("key.pem");
    std::fs::write(&cert_path, &cert_pem).expect("write cert");
    std::fs::write(&key_path, &key_pem).expect("write key");

    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind probe");
    let addr = probe.local_addr().expect("addr");
    drop(probe);

    let observed = Arc::new(EchoObservation::default());
    let next_host: Arc<Mutex<u32>> = Arc::new(Mutex::new(2));
    let observed_gate = Arc::clone(&observed);
    let gate: TunnelGate = Arc::new(move |meta: &RequestMeta| {
        let (Some(user), Some(pass)) = (&meta.auth_user, &meta.auth_pass) else {
            return Err(GateDeny::Auth);
        };
        if user != ECHO_USER || pass != ECHO_PASS {
            return Err(GateDeny::Auth);
        }
        let host = {
            let mut n = next_host.lock().unwrap_or_else(PoisonError::into_inner);
            let host = Ipv4Addr::new(198, 18, 0, (*n).min(253) as u8);
            *n += 1;
            host
        };
        observed_gate.users.lock().unwrap_or_else(PoisonError::into_inner).push(user.clone());
        observed_gate
            .assigned
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(IpAddr::V4(host));
        Ok(GateGrant {
            email: user.clone(),
            level: 0,
            extra: Some(Arc::new(vec![IpAddr::V4(host)]) as Arc<dyn std::any::Any + Send + Sync>),
        })
    });

    let settings = tls_server_settings(&cert_path, &key_path);
    let listener = hub::listen_masque(
        addr,
        &settings,
        &SocketOptions::default(),
        gate,
        Arc::new(EchoAcceptor),
    )
    .await
    .expect("listen masque");
    EchoServer { tmp, listener, observed, pin }
}

struct EchoAcceptor;

impl TunnelAcceptor for EchoAcceptor {
    fn add_tunnel(&self, conn: ServerConn) {
        let addrs = conn
            .grant
            .extra
            .as_ref()
            .and_then(|a| a.downcast_ref::<Vec<IpAddr>>().cloned())
            .unwrap_or_default();
        if addrs.is_empty() {
            let _ = conn.reject(GateDeny::Unavailable);
            return;
        }
        // 测试基建任务（spawn 三分类②）：随隧道生命周期，acceptor 非阻塞投递。
        tokio::spawn(echo_tunnel(conn, addrs));
    }
}

/// 单隧道 echo 服务：主动分配 + 全路由通告（Go `AssignAddresses`/`AdvertiseRoute`）
/// + ADDRESS_REQUEST 回应（按族分配 / 无址拒绝）+ UDP 回声（隧道层，不进栈）。
async fn echo_tunnel(conn: ServerConn, addrs: Vec<IpAddr>) {
    let stream = match conn.accept().await {
        Ok(s) => s,
        Err(e) => {
            println!("[echo] accept failed: {e}");
            return;
        },
    };
    let mut session = ConnectIpSession::server_session(stream);
    let mut writer = match session.writer() {
        Ok(w) => w,
        Err(e) => {
            println!("[echo] writer unavailable: {e}");
            return;
        },
    };
    let prefixes: Vec<IpPrefix> = addrs
        .iter()
        .map(|a| IpPrefix { addr: *a, prefix_len: if a.is_ipv4() { 32 } else { 128 } })
        .collect();
    if let Err(e) = writer.assign_addresses(&prefixes) {
        println!("[echo] assign_addresses failed: {e}");
        return;
    }
    if addrs.iter().any(IpAddr::is_ipv4) {
        let routes = [IpRoute {
            start_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            end_ip: IpAddr::V4(Ipv4Addr::BROADCAST),
            ip_protocol: 0,
        }];
        if let Err(e) = writer.advertise_route(&routes) {
            println!("[echo] advertise_route failed: {e}");
            return;
        }
    }

    let mut request_rx = session.take_request_rx();
    loop {
        tokio::select! {
            pkt = session.recv_packet() => match pkt {
                Ok(p) => {
                    if let Some(reply) = udp_echo_reply(&p) {
                        if let Err(e) = writer.send_packet(&reply).await {
                            println!("[echo] reply send failed: {e}");
                            break;
                        }
                    }
                },
                Err(_) => break,
            },
            req = async {
                match request_rx.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                let Some(entries) = req else { break };
                let assigned: Vec<AssignedAddress> = entries
                    .iter()
                    .map(|e| AddressRequestEntry { request_id: e.request_id, prefix: e.prefix.clone() })
                    .map(|entry| AssignedAddress {
                        request_id: entry.request_id,
                        prefix: addrs
                            .iter()
                            .find(|a| a.is_ipv4() == entry.prefix.addr.is_ipv4())
                            .map(|a| IpPrefix {
                                addr: *a,
                                prefix_len: if a.is_ipv4() { 32 } else { 128 },
                            })
                            .unwrap_or_else(|| reject_prefix(entry.prefix.addr)),
                    })
                    .collect();
                if let Err(e) = writer.respond_assignments(assigned) {
                    println!("[echo] respond_assignments failed: {e}");
                }
            },
        }
    }
}

/// 同族拒绝前缀（Go `address.go` Respond 拒绝形态）。
fn reject_prefix(for_addr: IpAddr) -> IpPrefix {
    match for_addr {
        IpAddr::V4(_) => IpPrefix { addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED), prefix_len: 32 },
        IpAddr::V6(_) => {
            IpPrefix { addr: IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), prefix_len: 128 }
        },
    }
}

/// UDP 回声：交换 v4 src/dst（IP + 端口）；DNS 形载荷（原 dport=53）置 QR 位
/// （查询 → 应答）。非 v4/UDP 或畸形包 = None（丢弃）。
fn udp_echo_reply(pkt: &[u8]) -> Option<Vec<u8>> {
    let ver = pkt.first().copied().unwrap_or(0);
    if ver >> 4 != 4 || pkt.len() < 28 || pkt[9] != 17 {
        return None;
    }
    let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    let sport = u16::from_be_bytes([pkt[20], pkt[21]]);
    let dport = u16::from_be_bytes([pkt[22], pkt[23]]);
    let mut payload = pkt[28..].to_vec();
    if dport == 53 && payload.len() >= 4 {
        payload[2] |= 0x80; // DNS QR
    }
    Some(ipv4_udp(dst, dport, src, sport, &payload))
}

/// 拨 Rust echo 服务端隧道（establish 全链：finalmask 无 → TLS(pin) → h2 → 协商）。
async fn dial_echo(srv: &EchoServer) -> ConnectIpSession {
    let settings = tls_client_settings(&srv.pin);
    let masque_cfg = xray_transport_masque::Config::from_json(Some(&serde_json::json!({
        "user": ECHO_USER,
        "pass": ECHO_PASS,
    })))
    .expect("masque settings");
    let dest = Destination::tcp(Address::ipv4(Ipv4Addr::LOCALHOST), Port::new(srv.port()));
    xray_transport_masque::dialer::dial(&dest, &SocketOptions::default(), &settings, &masque_cfg)
        .await
        .expect("Rust client → Rust echo server CONNECT-IP tunnel")
}

/// 断言分配地址合格（判据①：非 0.0.0.0、非服务器自占、在池内）。
fn assert_assigned_ok(local4: Ipv4Addr) {
    assert!(!local4.is_unspecified(), "assigned address must not be 0.0.0.0, got {local4}");
    assert!(
        local4 != Ipv4Addr::new(198, 18, 0, 1),
        "assigned address {local4} must not be the server's own address"
    );
    assert!(
        u32::from(local4) >= u32::from(Ipv4Addr::new(198, 18, 0, 0))
            && u32::from(local4) <= u32::from(Ipv4Addr::new(198, 19, 255, 255)),
        "assigned address {local4} outside configured pool 198.18.0.0/15"
    );
}

// ===== 方向 A：Rust client → Go server =====

/// B2.5 门 B2 / B5 方向 A：Rust client → **Go v26.11.9 server**，IPv4/UDP DNS 往返。
///
/// 判据（任务书 §5.2 A）：①ADDRESS_ASSIGN 非 0.0.0.0 ②手工构造 IPv4/UDP DNS 查询
/// → 隧道 → 同 id 应答 ③Go 日志 `MASQUE: tunnel from ... assigned [...]`。
#[tokio::test]
#[ignore = "env 门控：需要 Go v26.11.9 二进制（MASQUE_GO_XRAY）——规划 §6 门 B2/B5 方向 A"]
async fn go_server_dns_roundtrip() {
    let bin = go_binary();

    // 证书（SAN localhost；客户端钉叶子哈希）。
    let (cert_pem, key_pem, pin) = self_signed_cert();

    // 端口：先占一个随机端口再让出；取证配方（任务书 §5.3）经
    // MASQUE_FORENSICS_PORT 固定端口（dumpcap 过滤面）。
    let port = match std::env::var("MASQUE_FORENSICS_PORT").ok().and_then(|p| p.parse::<u16>().ok())
    {
        Some(p) => p,
        None => {
            let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind probe");
            let port = probe.local_addr().expect("addr").port();
            drop(probe);
            port
        },
    };

    // 客户端 TLS：pin 钉扎；MASQUE_KEYLOG_PATH 在场时落 TLS 密钥（client keylog
    // 即可解双向会话——TLS 1.3 密钥两端同源），供 tshark H2 帧断言（B5.2）。
    let client_security = {
        let mut v = serde_json::json!({
            "serverName": "localhost",
            "alpn": ["h2"],
            "pinnedPeerCertSha256": pin,
        });
        if let Ok(kl) = std::env::var("MASQUE_KEYLOG_PATH") {
            v["masterKeyLog"] = serde_json::json!(kl);
        }
        v
    };
    let settings = StreamSettings {
        protocol: "masque".into(),
        security: "tls".into(),
        security_json: Some(client_security),
        ..StreamSettings::tcp()
    };

    // Go 服务端配置（Go masque_test.go:351-356 形态 + R9：显式 alpn ["h2"]）。
    let tmp = std::env::temp_dir().join(format!("masque-go-interop-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).expect("mkdir");
    let cert_path = tmp.join("cert.pem");
    let key_path = tmp.join("key.pem");
    std::fs::write(&cert_path, &cert_pem).expect("write cert");
    std::fs::write(&key_path, &key_pem).expect("write key");
    let go_config = serde_json::json!({
        "log": { "loglevel": "debug" },
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "masque",
            "settings": {
                "users": [{ "email": "t@example.com", "pass": "secret" }],
                "address": ["198.18.0.1/15"],
            },
            "streamSettings": {
                "network": "masque",
                "security": "tls",
                "tlsSettings": {
                    "alpn": ["h2"],
                    "certificates": [
                        { "certificateFile": cert_path.display().to_string(), "keyFile": key_path.display().to_string() },
                    ],
                },
            },
        }],
        "outbounds": [{ "protocol": "freedom" }],
    });
    let cfg_path = tmp.join("server.json");
    std::fs::write(&cfg_path, serde_json::to_string_pretty(&go_config).expect("config json"))
        .expect("write config");

    // 启动 Go 服务端并等端口可连。
    let mut child = tokio::process::Command::new(&bin)
        .arg("run")
        .arg("-c")
        .arg(&cfg_path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn go xray");
    // 子进程输出收集器（诊断用；失败时整段吐出）
    let go_log: Arc<tokio::sync::Mutex<Vec<String>>> =
        Arc::new(tokio::sync::Mutex::new(Vec::new()));
    {
        let go_log = Arc::clone(&go_log);
        let stdout = child.stdout.take().expect("child stdout");
        #[allow(
            clippy::disallowed_methods,
            reason = "测试基建日志收集任务（spawn 三分类②），随用随弃"
        )]
        tokio::spawn(async move {
            use tokio::io::AsyncBufReadExt as _;
            let mut lines = tokio::io::BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                go_log.lock().await.push(line);
            }
        });
    }
    let mut ready = false;
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if tokio::net::TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
            .await
            .is_ok()
        {
            ready = true;
            break;
        }
        if let Ok(Some(_)) = child.try_wait() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    if !ready {
        // fail-loud：Go 进程的启动错误必须浮出（xray 横幅与错误都走 stdout；
        // 静默 = 排障全靠猜）。
        let mut msg = format!("Go masque server did not become reachable on port {port}");
        let streams: [(&str, Option<Box<dyn tokio::io::AsyncRead + Unpin>>); 2] = [
            (
                "stdout",
                child.stdout.take().map(|s| Box::new(s) as Box<dyn tokio::io::AsyncRead + Unpin>),
            ),
            (
                "stderr",
                child.stderr.take().map(|s| Box::new(s) as Box<dyn tokio::io::AsyncRead + Unpin>),
            ),
        ];
        for (name, stream) in streams {
            if let Some(mut s) = stream {
                use tokio::io::AsyncReadExt as _;
                let mut buf = Vec::new();
                let _ = tokio::time::timeout(Duration::from_secs(2), s.read_to_end(&mut buf)).await;
                msg.push_str(&format!("\n---- go {name} ----\n{}", String::from_utf8_lossy(&buf)));
            }
        }
        let _ = child.kill().await;
        panic!("{msg}");
    }

    // Rust 客户端拨号（生产路径 dial()：finalmask 无 → TLS(ALPN h2, pin) → h2）。
    let masque_cfg = xray_transport_masque::Config::from_json(Some(&serde_json::json!({
        "user": "t@example.com",
        "pass": "secret",
    })))
    .expect("masque settings");
    let dest = Destination::tcp(Address::ipv4(Ipv4Addr::LOCALHOST), Port::new(port));
    let mut session = xray_transport_masque::dialer::dial(
        &dest,
        &SocketOptions::default(),
        &settings,
        &masque_cfg,
    )
    .await
    .expect("Rust client → Go server CONNECT-IP tunnel");

    // 判据 ①：ADDRESS_ASSIGN 非 0.0.0.0——本端地址含真实 v4（198.18.0.0/15 内）。
    let local4 = local_v4(&session);
    assert_assigned_ok(local4);
    println!("assigned local v4 = {local4}");

    // 判据 ②：IPv4/UDP DNS 查询（1.1.1.1:53，example.com A）收到同 id 应答。
    let query_id: u16 = 0x1234;
    let packet = ipv4_udp(local4, 12345, Ipv4Addr::new(1, 1, 1, 1), 53, &dns_query(query_id));
    let sent = session.send_packet(&packet).await.expect("send DNS");
    assert!(sent.is_none(), "normal DNS packet must not yield ICMP");

    let got = recv_dns_reply(&mut session, local4, query_id).await;
    let go_assigned = go_log.lock().await.iter().any(|l| l.contains("assigned ["));
    if got.is_none() || !go_assigned {
        println!("---- go server log ({} lines) ----", go_log.lock().await.len());
        for l in go_log.lock().await.iter() {
            println!("| {l}");
        }
        let _ = child.kill().await;
        let _ = std::fs::remove_dir_all(&tmp);
    }
    assert!(got.is_some(), "判据②: IPv4/UDP DNS roundtrip must return the same id from 1.1.1.1");
    // 判据 ③：Go 日志锚（server.go:355-357 形 `MASQUE: tunnel from ... assigned [...]`）。
    assert!(go_assigned, "判据③: Go server log must record the tunnel assignment");

    println!("门 B5 方向 A PASS: assignment={local4}, dns id={query_id:#06x} roundtrip OK");

    session.close();
    let _ = child.kill().await;
    let _ = std::fs::remove_dir_all(&tmp);
}

// ===== 方向 B：Go client → Rust server =====

/// 门 B5 方向 B：**Go client**（dokodemo-door UDP 透明转发 + masque 出站）→ 本仓
/// Rust server（hub + gate + echo acceptor）。
///
/// 判据（任务书 §5.2 B = A 的 ②③ 换 Rust 侧证据面）：
/// - ① Rust gate 记录了给 Go 客户端的 v4 分配（非 0.0.0.0 / 非服务器自占 / 池内）； Go
///   侧实际拿到该分配由 ② 的端到端往返行为证明（dokodemo 应答只能经隧道回来）。
/// - ② DNS 查询 → dokodemo → Go masque 隧道 → Rust echo → 同 id + QR=1 应答。
/// - ③ gate 认证记录（Rust 侧日志锚的可观察面：`masque: tunnel from ... assigned ... (user ...)` 的
///   gate 记录等价物）。
#[tokio::test]
#[ignore = "env 门控：需要 Go v26.11.9 二进制（MASQUE_GO_XRAY）——门 B5 方向 B"]
async fn go_client_dns_roundtrip_via_rust_server() {
    let bin = go_binary();
    let srv = start_echo_server().await;

    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind probe");
    let dokodemo_port = probe.local_addr().expect("addr").port();
    drop(probe);

    let auth = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{ECHO_USER}:{ECHO_PASS}"))
    );
    let go_config = serde_json::json!({
        "log": { "loglevel": "debug" },
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": dokodemo_port,
            "protocol": "dokodemo-door",
            "settings": { "address": "1.1.1.1", "port": 53, "network": "udp" },
        }],
        "outbounds": [{
            "protocol": "masque",
            "settings": { "address": "127.0.0.1", "port": srv.port() },
            "streamSettings": {
                "network": "masque",
                "security": "tls",
                "tlsSettings": {
                    "serverName": "localhost",
                    "alpn": ["h2"],
                    "pinnedPeerCertSha256": srv.pin,
                },
                "masqueSettings": { "headers": { "Authorization": auth } },
            },
        }],
    });
    let tmp = std::env::temp_dir().join(format!("masque-go-client-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).expect("mkdir");
    let cfg_path = tmp.join("client.json");
    std::fs::write(&cfg_path, serde_json::to_string_pretty(&go_config).expect("config json"))
        .expect("write config");

    let mut child = tokio::process::Command::new(&bin)
        .arg("run")
        .arg("-c")
        .arg(&cfg_path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn go xray");
    let go_log: Arc<tokio::sync::Mutex<Vec<String>>> =
        Arc::new(tokio::sync::Mutex::new(Vec::new()));
    {
        let go_log = Arc::clone(&go_log);
        let stdout = child.stdout.take().expect("child stdout");
        #[allow(
            clippy::disallowed_methods,
            reason = "测试基建日志收集任务（spawn 三分类②），随用随弃"
        )]
        tokio::spawn(async move {
            use tokio::io::AsyncBufReadExt as _;
            let mut lines = tokio::io::BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                go_log.lock().await.push(line);
            }
        });
    }
    // 就绪判据：dokodemo（network=udp）**只监听 UDP**——无 TCP 探测面（曾用
    // TCP connect 探活恒失败）；改为进程存活 + 固定收敛窗，首个查询的重发循环
    // 兜底监听启动竞态。
    tokio::time::sleep(Duration::from_secs(1)).await;
    if let Ok(Some(code)) = child.try_wait() {
        let log = go_log.lock().await;
        let mut msg = format!("Go client exited early: {code}");
        msg.push_str(&format!("\n---- go stdout ({} lines) ----", log.len()));
        for l in log.iter() {
            msg.push_str(&format!("\n| {l}"));
        }
        drop(log);
        let _ = std::fs::remove_dir_all(&tmp);
        panic!("{msg}");
    }

    // ② DNS 查询经 dokodemo（UDP 透明转发）→ Go masque 隧道 → Rust echo → 回来。
    // 无应答即 2s 重发（覆盖 Go 监听启动竞态）。
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("udp bind");
    let query_id: u16 = 0x4321;
    let dokodemo = SocketAddr::from((Ipv4Addr::LOCALHOST, dokodemo_port));

    let mut buf = vec![0u8; 1500];
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut got = None;
    while got.is_none() && Instant::now() < deadline {
        sock.send_to(&dns_query(query_id), dokodemo).await.expect("send DNS via dokodemo");
        let recv_deadline = Instant::now() + Duration::from_secs(2);
        while got.is_none() && Instant::now() < recv_deadline {
            let (n, _) = match tokio::time::timeout(
                Duration::from_secs(2),
                sock.recv_from(&mut buf),
            )
            .await
            {
                Ok(Ok(x)) => x,
                _ => break, // 本次窗口到期 → 外层重发
            };
            if n >= 4 {
                let id = u16::from_be_bytes([buf[0], buf[1]]);
                let qr = buf[2] >> 7;
                if id == query_id && qr == 1 {
                    got = Some(buf[..n].to_vec());
                }
            }
        }
    }
    let users = srv.users().clone();
    let assigned = srv.assigned().clone();
    let gate_auth = users.iter().any(|u| u == ECHO_USER);
    let go_v4 = assigned.iter().find_map(|a| if let IpAddr::V4(v) = a { Some(*v) } else { None });
    if got.is_none() {
        println!("---- go client log ({} lines) ----", go_log.lock().await.len());
        for l in go_log.lock().await.iter() {
            println!("| {l}");
        }
    }
    // 判据 ③：gate 认证记录（Rust 侧）。
    assert!(gate_auth, "判据③: Rust gate must have authenticated the Go client");
    // 判据 ①：Rust gate 给 Go 客户端分配了合格 v4。
    assert_assigned_ok(go_v4.expect("判据①: gate must have assigned a v4 to the Go client"));
    // 判据 ②：dokodemo 透明往返同 id + QR=1（应答只能经 masque 隧道回来）。
    assert!(got.is_some(), "判据②: DNS roundtrip via Go client → Rust server must return same id");
    println!(
        "门 B5 方向 B PASS: go_client assigned={:?}, dns id={query_id:#06x} roundtrip OK",
        go_v4
    );

    let _ = child.kill().await;
    let _ = std::fs::remove_dir_all(&tmp);
    drop(srv);
}

// ===== 方向 C：Rust client ↔ Rust server =====

/// 门 B5 方向 C：本仓双端自环。判据（任务书 §5.2 C）：
/// ①ADDRESS_ASSIGN 非 0.0.0.0 ②IPv4/UDP DNS 同 id 往返；
/// 另加 **64KB 连续 IP 包往返不丢**（64 × 1KB 逐包序号校验）。
#[tokio::test]
async fn rust_to_rust_dns_and_64k_roundtrip() {
    let srv = start_echo_server().await;
    let mut s1 = dial_echo(&srv).await;
    let mut s2 = dial_echo(&srv).await;

    // 判据 ①：两条隧道各自分配合格且互不相同（gate 顺序分配语义）。
    let local1 = local_v4(&s1);
    let local2 = local_v4(&s2);
    assert_assigned_ok(local1);
    assert_assigned_ok(local2);
    assert_ne!(local1, local2, "two seeds must get distinct addresses");
    println!("assigned seeds: s1={local1} s2={local2}");

    // 判据 ②：IPv4/UDP DNS 同 id 往返。
    let query_id: u16 = 0x0c01;
    let packet = ipv4_udp(local1, 12345, Ipv4Addr::new(1, 1, 1, 1), 53, &dns_query(query_id));
    let sent = s1.send_packet(&packet).await.expect("send DNS");
    assert!(sent.is_none(), "normal DNS packet must not yield ICMP");
    let got = recv_dns_reply(&mut s1, local1, query_id).await;
    assert!(got.is_some(), "判据②: DNS roundtrip must return the same id from 1.1.1.1");

    // 附加判据：64KB 连续 IP 包往返不丢（64 × 1KB，逐包序号 + 内容校验）。
    const BURST: u32 = 64;
    const BULK_LEN: usize = 1024; // 20(IP) + 8(UDP) + 1024 = 1052 ≤ MTU 1280
    let mut expect: Vec<Vec<u8>> = Vec::with_capacity(BURST as usize);
    for seq in 0..BURST {
        let mut payload = Vec::with_capacity(BULK_LEN);
        payload.extend_from_slice(&seq.to_be_bytes());
        payload.extend((0..BULK_LEN - 4).map(|i| (i % 251) as u8));
        let pkt = ipv4_udp(local1, 12345, Ipv4Addr::new(1, 1, 1, 1), 9999, &payload);
        let sent = s1.send_packet(&pkt).await.expect("send bulk");
        assert!(sent.is_none(), "bulk packet {seq} within MTU must not yield ICMP");
        expect.push(payload);
    }
    for (seq, want) in expect.iter().enumerate() {
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut hit = None;
        while Instant::now() < deadline {
            let pkt = match tokio::time::timeout(Duration::from_secs(5), s1.recv_packet()).await {
                Ok(Ok(p)) => p,
                _ => break,
            };
            if pkt.len() == 20 + 8 + BULK_LEN
                && pkt[9] == 17
                && pkt[12..16] == [1, 1, 1, 1]
                && pkt[16..20] == local1.octets()
                && pkt[20..22] == 9999u16.to_be_bytes()
            {
                hit = Some(pkt);
                break;
            }
        }
        let Some(pkt) = hit else {
            panic!("64KB 往返不丢: bulk echo #{seq} never returned");
        };
        assert_eq!(&pkt[28..], want, "bulk echo #{seq} payload must roundtrip byte-exact");
    }
    println!("门 B5 方向 C PASS: dns id={query_id:#06x} roundtrip OK + 64×1KB burst lossless");

    s1.close();
    s2.close();
    drop(srv);
}
