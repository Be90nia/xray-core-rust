//! B2.5 Go 对拍（方向 A）：Rust client → **Go v26.11.9 server**，IPv4/UDP DNS 往返。
//!
//! 规划：`docs/architecture/xray-frame-masque-实施计划-2026-11-11.md` §5 B2.5 / §6 门 B2。
//!
//! **`#[ignore]` + env 门控**（不进默认 CI）：
//! - `MASQUE_GO_XRAY`：Go xray 二进制（缺省 `D:/tmp/xray-v2611/xray.exe`；从 `D:/Project/Xray-core`
//!   @ 676eaf66 `go build -o ... ./main` 产出）。
//!
//! 运行：
//! ```text
//! cargo test -p xray-transport-masque --test connectip_go_interop -- --ignored --nocapture
//! ```
//! 测试自管证书（rcgen 自签 + pinnedPeerCertSha256 钉扎）与 Go 配置（门 B2 期望：
//! ADDRESS_ASSIGN 非 0.0.0.0；IPv4/UDP DNS 查询收到同 id 应答）。
//!
//! 测试基建 spawn 豁免（坑约束 #5）：Go 服务端进程与 server 任务均为测试基建
//! （spawn 三分类②）。
#![allow(clippy::disallowed_methods)]

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    time::{Duration, Instant},
};

use xray_common::net::{address::Address, destination::Destination, port::Port};
use xray_transport::{dialer::StreamSettings, sockopt::SocketOptions};

/// 生成自签证书 + Go 服务端配置 + 启动 + Rust 客户端 DNS 往返。
#[tokio::test]
#[ignore = "env 门控：需要 Go v26.11.9 二进制（MASQUE_GO_XRAY）——规划 §6 门 B2 方向 A"]
async fn go_server_dns_roundtrip() {
    let bin = std::env::var("MASQUE_GO_XRAY")
        .unwrap_or_else(|_| r"D:/tmp/xray-v2611/xray.exe".to_string());
    let bin = PathBuf::from(&bin);
    assert!(
        bin.is_file(),
        "Go xray binary missing at {}: build via `cd D:/Project/Xray-core && go build -o {} ./main`",
        bin.display(),
        bin.display()
    );

    // 证书（SAN localhost；客户端钉叶子哈希）。
    let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("params");
    let key_pair = rcgen::KeyPair::generate().expect("keypair");
    let cert = params.self_signed(&key_pair).expect("self signed");
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    let pin = xray_tls::pin::generate_cert_hash_hex(cert.der());

    // 端口：先占一个随机端口再让出。
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind probe");
    let port = probe.local_addr().expect("addr").port();
    drop(probe);

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
    // 子进程输出收集器（诊断用；DNS 失败时整段吐出）
    let go_log: std::sync::Arc<tokio::sync::Mutex<Vec<String>>> =
        std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new()));
    {
        let go_log = std::sync::Arc::clone(&go_log);
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

    // Rust 客户端拨号（本批生产路径 dial()：finalmask 无 → TLS(ALPN h2, pin) → h2）。
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

    // 门 B2 期望 ①：ADDRESS_ASSIGN 非 0.0.0.0——本端地址含真实 v4（198.18.0.0/15 内）。
    let local4 = session
        .local_addrs()
        .iter()
        .find_map(|a| if let IpAddr::V4(v) = a { Some(*v) } else { None })
        .expect("Go server must assign a v4 address");
    assert!(!local4.is_unspecified(), "门 B2: assigned address must not be 0.0.0.0, got {local4}");
    assert!(
        local4 != Ipv4Addr::new(198, 18, 0, 1),
        "assigned address {local4} must not be the server's own address"
    );
    assert!(
        u32::from(local4) >= u32::from(Ipv4Addr::new(198, 18, 0, 0))
            && u32::from(local4) <= u32::from(Ipv4Addr::new(198, 19, 255, 255)),
        "assigned address {local4} outside configured pool 198.18.0.0/15"
    );
    println!("assigned local v4 = {local4}");

    // 门 B2 期望 ②：IPv4/UDP DNS 查询（1.1.1.1:53，example.com A）收到同 id 应答。
    let query_id: u16 = 0x1234;
    let mut dns = Vec::new();
    dns.extend_from_slice(&query_id.to_be_bytes());
    dns.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]); // RD, QD=1
    dns.extend_from_slice(b"\x07example\x03com\x00");
    dns.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // type A, class IN
    let packet = ipv4_udp(local4, Ipv4Addr::new(1, 1, 1, 1), 53, &dns);
    let sent = session.send_packet(&packet).await.expect("send DNS");
    assert!(sent.is_none(), "normal DNS packet must not yield ICMP");

    let deadline = Instant::now() + Duration::from_secs(15);
    let mut got_id = None;
    while Instant::now() < deadline {
        let pkt = match tokio::time::timeout(Duration::from_secs(5), session.recv_packet()).await {
            Ok(Ok(p)) => p,
            _ => break,
        };
        println!(
            "[recv] len={} proto={} src={} dst={} sport={}",
            pkt.len(),
            pkt.get(9).copied().unwrap_or(0),
            pkt.get(12..16).map(|b| Ipv4Addr::from(<[u8; 4]>::try_from(b).unwrap())).unwrap(),
            pkt.get(16..20).map(|b| Ipv4Addr::from(<[u8; 4]>::try_from(b).unwrap())).unwrap(),
            pkt.get(20..22).map(|b| u16::from_be_bytes([b[0], b[1]])).unwrap_or(0),
        );
        // 期望：src=1.1.1.1, dst=local4, proto=17, sport=53，DNS id 同值 + QR 位。
        if pkt.len() >= 20 + 8 + 12
            && pkt[9] == 17
            && pkt[12..16] == [1, 1, 1, 1]
            && pkt[16..20] == local4.octets()
            && pkt[20..22] == [0, 53]
        {
            let id = u16::from_be_bytes([pkt[20 + 8], pkt[20 + 9]]);
            let qr = pkt[20 + 8 + 2] >> 7; // DNS flags 在 DNS 头偏移 2（id 占 2 字节）
            if id == query_id && qr == 1 {
                got_id = Some(id);
                break;
            }
        }
    }
    if got_id != Some(query_id) {
        println!("---- go server log ({} lines) ----", go_log.lock().await.len());
        for l in go_log.lock().await.iter() {
            println!("| {l}");
        }
        let _ = child.kill().await;
        let _ = std::fs::remove_dir_all(&tmp);
    }
    assert_eq!(
        got_id,
        Some(query_id),
        "门 B2: IPv4/UDP DNS roundtrip must return the same id from 1.1.1.1"
    );
    println!("门 B2 方向 A PASS: assignment={local4}, dns id={query_id:#06x} roundtrip OK");

    session.close();
    let _ = child.kill().await;
    let _ = std::fs::remove_dir_all(&tmp);
}

/// 构造 IPv4/UDP 包（src=本端地址, dst=对端:port；TTL 64）。UDP 校验和按 IPv4
/// 伪头真实计算——Go 侧 netstack（gVisor）按「来自网络」的包校验传输层校验和，
/// 置 0 会被静默丢弃。
fn ipv4_udp(src: Ipv4Addr, remote: Ipv4Addr, remote_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0u8; 20 + 8 + payload.len()];
    p[0] = 0x45;
    let total = p.len() as u16;
    p[2..4].copy_from_slice(&total.to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&remote.octets());
    p[20..22].copy_from_slice(&12345u16.to_be_bytes()); // sport：非 0（netstack 转发元组）
    p[20 + 2..20 + 4].copy_from_slice(&remote_port.to_be_bytes()); // dport
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
