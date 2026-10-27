//! WireGuard 隧道数据面 e2e（ft58 A7/S8）。
//!
//! Go 对照：`testing/scenarios/wireguard_test.go::TestWireguard`——3×TCP 1MB +
//! IPv6 TCP 1MB + UDP 1KB 全经隧道并回显校验。Rust 等价拓扑（双实例，与 Go 一致）：
//!
//! ```text
//! client 实例                                server 实例
//! ┌─────────────────────────┐              ┌──────────────────────────────┐
//! │ dokodemo TCP/UDP in     │              │ wireguard in (UDP)           │
//! │   预定义目标=隧道内地址  │   WG UDP     │   dispatch → default outbound│
//! │ wireguard out (driver)  │ ───────────► │ freedom "lan"                │
//! └─────────────────────────┘  127.0.0.1:P  │   (destinationOverride 可选) │
//!                                           └──────────────────────────────┘
//!                                                       │
//!                                                真实 echo server
//! ```
//!
//! 断言：载荷逐字节一致（Go xor 回显等价于明文回显往返比对）。
//!
//! 用例 × Go 映射：
//! - `wg_dataplane_tcp_echo_1mb_three_concurrent` ← Go `testTCPConn(clientPort, 1MB)` ×3
//! - `wg_dataplane_tcp_echo_1mb_inner_ipv6`       ← Go `testTCPConn(client6Port, 1MB)`
//! - `wg_dataplane_udp_echo_1kb`                  ← Go `testUDPConn(clientUDPPort, 1KB)`
//! - `wg_dataplane_udp_echo_loopback_override`    ← 同上拓扑，隧道内 192.0.2.1 + override
//!
//! UDP 回包源 = 隧道内**原目标**（Go `tun/udp_fullcone.go` `Write` → `c.dst`），故
//! override 指向回环 echo 时回显照样通（`wg_dataplane_udp_echo_loopback_override`）；
//! `wg_dataplane_udp_echo_1kb` 的隧道内目标用本机非回环 IPv4（freedom 无 override）。

use std::{
    net::{Ipv4Addr, SocketAddr},
    time::{Duration, Instant},
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    task::JoinSet,
    time::timeout,
};
use xray_conf::{BuiltConfig, BuiltEntry, BuiltInbound, BuiltOutbound};
use xray_core::functions::start_full;

// ============================================================
// 常量
// ============================================================

/// 1 MiB（Go TCP 用例载荷大小）。
const MB: usize = 1024 * 1024;

/// 1 KiB（Go UDP 用例载荷大小）。
const KB: usize = 1024;

/// 单条 TCP 往返预算（Go `testTCPConn` 20s 同值）。
const TCP_ROUNDTRIP_TIMEOUT: Duration = Duration::from_secs(20);

/// 实例启动后监听就绪延迟（对齐 e2e_p2 基线）。
const READY_DELAY: Duration = Duration::from_millis(120);

/// 诊断用：装 tracing subscriber（幂等，多测试并发下仅首个生效）。
/// 事件经 `with_test_writer` 进 libtest 捕获输出（失败时随 panic 打印，
/// `--nocapture` 下实时可见）。聚焦 xray crate，屏蔽 smoltcp/boringtun 噪音。
fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(
            "info,xray_proxy_wireguard=debug,xray_core=debug,xray_app_dispatcher=debug,\
             xray_proxy_freedom=debug,xray_proxy_dokodemo=debug,xray_transport=debug",
        ))
        .with_test_writer()
        .try_init();
}

// ============================================================
// 载荷与端口工具
// ============================================================

/// 确定性伪随机载荷（xorshift64*）——能抓乱序/改写/截断，不依赖 rand。
fn make_payload(len: usize, seed: u64) -> Vec<u8> {
    let mut s = seed | 1;
    let mut v = Vec::with_capacity(len);
    for _ in 0..len {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        v.push((s >> 33) as u8);
    }
    v
}

/// 本机非回环 IPv4（UDP connect 技巧，零发包）。
///
/// UDP 用例的隧道内目标地址——回环地址会被客户端 netstack 的
/// `not_forwardable`（loopback src/dst）过滤，见模块注释。
fn host_lan_v4() -> Option<Ipv4Addr> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("8.8.8.8:80").ok()?;
    match s.local_addr().ok()? {
        SocketAddr::V4(v4) if !v4.ip().is_loopback() && !v4.ip().is_unspecified() => Some(*v4.ip()),
        _ => None,
    }
}

// ============================================================
// echo server
// ============================================================

/// TCP echo（读到什么写回什么）。返回绑定地址。
async fn spawn_tcp_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = listener.local_addr().expect("echo addr");
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
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
    addr
}

/// UDP echo。绑定 `bind_addr`（UDP 用例须 0.0.0.0 才能经非回环本机地址到达）。
/// 返回 bind 结果（占用由调用方按 TOCTOU 重试）。
async fn spawn_udp_echo(bind_addr: &str) -> std::io::Result<()> {
    let sock = UdpSocket::bind(bind_addr).await?;
    tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
            let _ = sock.send_to(&buf[..n], peer).await;
        }
    });
    Ok(())
}

// ============================================================
// 配置构造（键名对齐 e2e_p2_test.rs 既有 wireguard 形态）
// ============================================================

/// 生成一对 x25519 hex 密钥（确定性 seed，对齐 e2e_p2::wg_keypair）。
fn wg_keypair(seed: u8) -> (String, String) {
    use boringtun::x25519::{PublicKey, StaticSecret};
    let secret_bytes = [seed; 32];
    let secret = StaticSecret::from(secret_bytes);
    let public = PublicKey::from(&secret);
    (hex::encode(secret_bytes), hex::encode(public.as_bytes()))
}

/// 回环放行 CIDR（对齐 e2e_p2 freedom_outbound 惯例形态）。
fn loopback_allow() -> Vec<String> {
    ["127.0.0.0/8", "::1/128"].iter().map(|s| (*s).to_string()).collect()
}

/// dokodemo inbound（预定义目标 = 隧道内地址）。
fn dokodemo_in(
    port: u16,
    tag: &str,
    dest_addr: &str,
    dest_port: u16,
    network: &str,
) -> BuiltInbound {
    BuiltInbound {
        entry: BuiltEntry {
            kind: "dokodemo".into(),
            data: serde_json::json!({
                "address": dest_addr,
                "port": dest_port,
                "network": network,
            })
            .to_string()
            .into_bytes(),
        },
        tag: tag.into(),
        port: Some(port),
        listen: Some("127.0.0.1".into()),
        stream_settings_json: None,
        sniffing_json: None,
    }
}

/// wireguard outbound（client 视角；endpoint = 本机 wg-in UDP 端口）。
fn wg_outbound(secret: &str, peer_pub: &str, wg_port: u16, addresses: &[&str]) -> BuiltOutbound {
    BuiltOutbound {
        entry: BuiltEntry {
            kind: "wireguard".into(),
            data: serde_json::json!({
                "secretKey": secret,
                "address": addresses,
                "peers": [{
                    "publicKey": peer_pub,
                    "endpoint": format!("127.0.0.1:{wg_port}"),
                }],
            })
            .to_string()
            .into_bytes(),
        },
        tag: "wg-out".into(),
        send_through: None,
        stream_settings_json: None,
        proxy_settings_json: None,
        mux_json: None,
        target_strategy: None,
    }
}

/// wireguard inbound（server 视角；peer = client 公钥 + allowedIps）。
fn wg_inbound(
    secret: &str,
    peer_pub: &str,
    wg_port: u16,
    addresses: &[&str],
    allowed_ips: &[&str],
) -> BuiltInbound {
    BuiltInbound {
        entry: BuiltEntry {
            kind: "wireguard".into(),
            data: serde_json::json!({
                "secretKey": secret,
                "address": addresses,
                "peers": [{
                    "publicKey": peer_pub,
                    "endpoint": format!("127.0.0.1:{wg_port}"),
                    "allowedIps": allowed_ips,
                }],
                "port": wg_port,
            })
            .to_string()
            .into_bytes(),
        },
        tag: "wg-in".into(),
        port: Some(wg_port),
        listen: Some("127.0.0.1".into()),
        stream_settings_json: None,
        sniffing_json: None,
    }
}

/// freedom 出站（server 实例 default；显式 allow finalRules 压过 wireguard 入站
/// 推导的 BlockPrivate 默认规则；可选 destinationOverride 改写隧道内目标）。
///
/// allow 列表须用显式 CIDR（`0.0.0.0/0`/`::/0` 零前缀实测不命中，见报告
/// finding-4）——对齐 e2e_p2_test.rs freedom_outbound 的回环放行形态。
fn freedom_lan(allow_ips: &[String], ov: Option<(&str, u16)>) -> BuiltOutbound {
    let mut settings = serde_json::json!({
        "finalRules": [
            {"action": "allow", "network": "tcp,udp", "ip": allow_ips}
        ]
    });
    if let Some((addr, port)) = ov {
        settings["destinationOverride"] =
            serde_json::json!({"server": {"address": addr, "port": port}});
    }
    BuiltOutbound {
        entry: BuiltEntry { kind: "freedom".into(), data: settings.to_string().into_bytes() },
        tag: "lan".into(),
        send_through: None,
        stream_settings_json: None,
        proxy_settings_json: None,
        mux_json: None,
        target_strategy: None,
    }
}

// ============================================================
// 往返驱动
// ============================================================

/// 单条 TCP 往返：连接 → 写 size 字节 → 回读 → 逐字节比对。
async fn tcp_roundtrip(port: u16, size: usize, seed: u64) -> Result<(), String> {
    let payload = make_payload(size, seed);
    let mut sock = timeout(TCP_ROUNDTRIP_TIMEOUT, TcpStream::connect(("127.0.0.1", port)))
        .await
        .map_err(|_| "connect timeout".to_string())?
        .map_err(|e| format!("connect: {e}"))?;

    timeout(TCP_ROUNDTRIP_TIMEOUT, sock.write_all(&payload))
        .await
        .map_err(|_| "write timeout".to_string())?
        .map_err(|e| format!("write: {e}"))?;

    let mut got = vec![0u8; size];
    timeout(TCP_ROUNDTRIP_TIMEOUT, sock.read_exact(&mut got))
        .await
        .map_err(|_| "read timeout".to_string())?
        .map_err(|e| format!("read_exact: {e}"))?;

    if got != payload {
        let diff = got.iter().zip(payload.iter()).position(|(a, b)| a != b);
        return Err(format!(
            "payload mismatch: len {size}, first diff at {diff:?}, got {} bytes of match",
            diff.unwrap_or(size)
        ));
    }
    Ok(())
}

// ============================================================
// 用例 1（Go：3× testTCPConn(clientPort, 1MB)）
// ============================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wg_dataplane_tcp_echo_1mb_three_concurrent() {
    init_tracing();
    let echo = spawn_tcp_echo().await;
    let (sec_c, pub_c) = wg_keypair(0x51);
    let (sec_s, pub_s) = wg_keypair(0x52);

    // 端口探测 TOCTOU 加固：占用（Windows 10048 / Unix EADDRINUSE）时整组换端口重试至多 5 次。
    let (_wg_port, entry_port, handles_c, handles_s) = loop {
        let ports = xray_common::testing::pick_free_ports(2).await;
        let (wg_port, entry_port) = (ports[0], ports[1]);

        // client 实例：dokodemo TCP → wg-out（唯一 outbound = default）
        let mut client_cfg = BuiltConfig::default();
        client_cfg.inbounds.push(dokodemo_in(entry_port, "dokodemo-tcp", "10.0.0.1", 7, "tcp"));
        client_cfg.outbounds.push(wg_outbound(&sec_c, &pub_s, wg_port, &["10.0.0.2/32"]));
        let (_inst_c, _ohm_c, handles_c) = match start_full(&client_cfg).await {
            Ok(v) => v,
            Err(e) if xray_common::testing::is_addr_in_use_err(&e) => continue,
            Err(e) => panic!("client instance: {e:?}"),
        };

        // server 实例：wg-in → freedom lan（override → 真实 echo）
        let mut server_cfg = BuiltConfig::default();
        server_cfg.inbounds.push(wg_inbound(
            &sec_s,
            &pub_c,
            wg_port,
            &["10.0.0.1/32"],
            &["10.0.0.2/32"],
        ));
        server_cfg.outbounds.push(freedom_lan(&loopback_allow(), Some(("127.0.0.1", echo.port()))));
        let (_inst_s, _ohm_s, handles_s) = match start_full(&server_cfg).await {
            Ok(v) => v,
            Err(e) if xray_common::testing::is_addr_in_use_err(&e) => {
                for h in handles_c {
                    h.abort();
                }
                continue;
            },
            Err(e) => panic!("server instance: {e:?}"),
        };
        break (wg_port, entry_port, handles_c, handles_s);
    };

    tokio::time::sleep(READY_DELAY).await;

    // 3 条 1MB 往返，连接与传输全并发（Go errgroup 同形态）。连接阶段原按 300ms
    // 错开规避惰性监听单槽位互撞 RST（bd n07t F5）；修复后同 tuple 监听池化排队
    // （netstack::MAX_LISTENS_PER_TUPLE），不再错开以锁死并发受理行为。
    let started = Instant::now();
    let mut tasks = JoinSet::new();
    for i in 0u64..3 {
        tasks.spawn(tcp_roundtrip(entry_port, MB, 0xA000 + i));
    }
    while let Some(res) = tasks.join_next().await {
        res.expect("task join").expect("tcp roundtrip via wg tunnel");
    }
    println!("[timing] 3x1MB TCP via wg tunnel: {:?}", started.elapsed());

    for h in handles_c.into_iter().chain(handles_s) {
        h.abort();
    }
}

// ============================================================
// 用例 2（Go：testTCPConn(client6Port, 1MB)，隧道内 IPv6）
// ============================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wg_dataplane_tcp_echo_1mb_inner_ipv6() {
    init_tracing();
    let echo = spawn_tcp_echo().await;
    let (sec_c, pub_c) = wg_keypair(0x61);
    let (sec_s, pub_s) = wg_keypair(0x62);

    // 端口探测 TOCTOU 加固：占用（Windows 10048 / Unix EADDRINUSE）时整组换端口重试至多 5 次。
    let (_wg_port, entry_port, handles_c, handles_s) = loop {
        let ports = xray_common::testing::pick_free_ports(2).await;
        let (wg_port, entry_port) = (ports[0], ports[1]);

        let mut client_cfg = BuiltConfig::default();
        client_cfg.inbounds.push(dokodemo_in(entry_port, "dokodemo-tcp6", "fd00::1", 7, "tcp"));
        client_cfg.outbounds.push(wg_outbound(
            &sec_c,
            &pub_s,
            wg_port,
            &["10.0.0.2/32", "fd00::2/128"],
        ));
        let (_inst_c, _ohm_c, handles_c) = match start_full(&client_cfg).await {
            Ok(v) => v,
            Err(e) if xray_common::testing::is_addr_in_use_err(&e) => continue,
            Err(e) => panic!("client instance: {e:?}"),
        };

        let mut server_cfg = BuiltConfig::default();
        server_cfg.inbounds.push(wg_inbound(
            &sec_s,
            &pub_c,
            wg_port,
            &["10.0.0.1/32", "fd00::1/128"],
            &["10.0.0.2/32", "fd00::2/128"],
        ));
        server_cfg.outbounds.push(freedom_lan(&loopback_allow(), Some(("127.0.0.1", echo.port()))));
        let (_inst_s, _ohm_s, handles_s) = match start_full(&server_cfg).await {
            Ok(v) => v,
            Err(e) if xray_common::testing::is_addr_in_use_err(&e) => {
                for h in handles_c {
                    h.abort();
                }
                continue;
            },
            Err(e) => panic!("server instance: {e:?}"),
        };
        break (wg_port, entry_port, handles_c, handles_s);
    };

    tokio::time::sleep(READY_DELAY).await;

    let started = Instant::now();
    tcp_roundtrip(entry_port, MB, 0xB000).await.expect("ipv6 tcp roundtrip via wg tunnel");
    println!("[timing] 1MB TCP (inner v6) via wg tunnel: {:?}", started.elapsed());

    for h in handles_c.into_iter().chain(handles_s) {
        h.abort();
    }
}

// ============================================================
// 用例 3（Go：testUDPConn(clientUDPPort, 1KB)）
// ============================================================

/// 首包可能落在 WG 握手完成前被 boringtun 丢弃（无队列语义，见报告 finding），
/// 客户端以有界重发对齐 Go wireguard-go 的握手期排队行为；载荷恒定，任意一次
/// 回包逐字节相等即通过。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wg_dataplane_udp_echo_1kb() {
    // 隧道内目标 = 本机非回环 IPv4 : 空闲 UDP 端口（freedom 无 override，直连）
    init_tracing();
    let lan_ip = host_lan_v4().expect("host must have a non-loopback IPv4 for the udp case");
    let (sec_c, pub_c) = wg_keypair(0x71);
    let (sec_s, pub_s) = wg_keypair(0x72);

    // 端口探测 TOCTOU 加固：占用（Windows 10048 / Unix EADDRINUSE）时整组换端口重试至多
    // 5 次（含隧道内 UDP echo 端口的自绑）。
    let (_inner_port, entry_port, _wg_port, handles_c, handles_s) = loop {
        let ports = xray_common::testing::pick_free_ports(3).await;
        let (inner_port, entry_port, wg_port) = (ports[0], ports[1], ports[2]);

        // 真实 UDP echo 绑 0.0.0.0（经本机 LAN IP 可达）
        if let Err(e) = spawn_udp_echo(&format!("0.0.0.0:{inner_port}")).await {
            if xray_common::testing::is_addr_in_use_err(&e) {
                continue;
            }
            panic!("bind udp echo: {e}");
        }

        // client 实例：dokodemo UDP → wg-out；隧道内目标 = {lan_ip}:{inner_port}（无 override）
        let mut client_cfg = BuiltConfig::default();
        client_cfg.inbounds.push(dokodemo_in(
            entry_port,
            "dokodemo-udp",
            &lan_ip.to_string(),
            inner_port,
            "udp",
        ));
        client_cfg.outbounds.push(wg_outbound(&sec_c, &pub_s, wg_port, &["10.0.0.2/32"]));
        let (_inst_c, _ohm_c, handles_c) = match start_full(&client_cfg).await {
            Ok(v) => v,
            Err(e) if xray_common::testing::is_addr_in_use_err(&e) => continue,
            Err(e) => panic!("client instance: {e:?}"),
        };

        // server 实例：wg-in → freedom lan（无 override，目标即真实地址）
        let mut server_cfg = BuiltConfig::default();
        server_cfg.inbounds.push(wg_inbound(
            &sec_s,
            &pub_c,
            wg_port,
            &["10.0.0.1/32"],
            &["10.0.0.2/32"],
        ));
        let mut allow = loopback_allow();
        allow.push(format!("{lan_ip}/32"));
        server_cfg.outbounds.push(freedom_lan(&allow, None));
        let (_inst_s, _ohm_s, handles_s) = match start_full(&server_cfg).await {
            Ok(v) => v,
            Err(e) if xray_common::testing::is_addr_in_use_err(&e) => {
                for h in handles_c {
                    h.abort();
                }
                continue;
            },
            Err(e) => panic!("server instance: {e:?}"),
        };
        break (inner_port, entry_port, wg_port, handles_c, handles_s);
    };

    tokio::time::sleep(READY_DELAY).await;

    let payload = make_payload(KB, 0xC700);
    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");

    let started = Instant::now();
    let mut got: Option<Vec<u8>> = None;
    // 有界重发：握手窗口（首个数据报大概率被吞）+ 调度延迟；20×500ms 上限 10s
    for attempt in 0..20u32 {
        client.send_to(&payload, ("127.0.0.1", entry_port)).await.expect("client send");
        let mut buf = vec![0u8; 4096];
        match timeout(Duration::from_millis(500), client.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => {
                got = Some(buf[..n].to_vec());
                println!(
                    "[timing] 1KB UDP via wg tunnel: {:?} (attempt {attempt})",
                    started.elapsed()
                );
                break;
            },
            _ => continue,
        }
    }
    assert_eq!(
        got.as_deref(),
        Some(payload.as_slice()),
        "udp echo payload mismatch through wg tunnel"
    );

    for h in handles_c.into_iter().chain(handles_s) {
        h.abort();
    }
}

// ============================================================
// 用例 4（Go 拓扑：隧道内 192.0.2.1 + 服务端 override → 回环 echo）
// ============================================================

/// bd n07t F1：回包源 = **隧道内原目标**（Go `tun/udp_fullcone.go` `Write` → `c.dst`）。
/// override 后真实应答方是 127.0.0.1，若以其为回包源，客户端 `WgNetStack::not_forwardable`
/// （loopback src）静默丢弃 → 回显必失。与 Go `TestWireguard` 的 UDP 拓扑一致。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wg_dataplane_udp_echo_loopback_override() {
    init_tracing();
    let (sec_c, pub_c) = wg_keypair(0x81);
    let (sec_s, pub_s) = wg_keypair(0x82);

    // 端口探测 TOCTOU 加固：占用（Windows 10048 / Unix EADDRINUSE）时整组换端口重试至多
    // 5 次（含隧道内 UDP echo 端口的自绑）。
    let (_inner_port, entry_port, _wg_port, handles_c, handles_s) = loop {
        let ports = xray_common::testing::pick_free_ports(3).await;
        let (inner_port, entry_port, wg_port) = (ports[0], ports[1], ports[2]);

        // 真实 echo 在回环（freedom override 的终点）
        if let Err(e) = spawn_udp_echo(&format!("127.0.0.1:{inner_port}")).await {
            if xray_common::testing::is_addr_in_use_err(&e) {
                continue;
            }
            panic!("bind udp echo: {e}");
        }

        // client：dokodemo UDP → wg-out；隧道内目标 = 192.0.2.1:inner_port
        let mut client_cfg = BuiltConfig::default();
        client_cfg.inbounds.push(dokodemo_in(
            entry_port,
            "dokodemo-udp",
            "192.0.2.1",
            inner_port,
            "udp",
        ));
        client_cfg.outbounds.push(wg_outbound(&sec_c, &pub_s, wg_port, &["10.0.0.2/32"]));
        let (_inst_c, _ohm_c, handles_c) = match start_full(&client_cfg).await {
            Ok(v) => v,
            Err(e) if xray_common::testing::is_addr_in_use_err(&e) => continue,
            Err(e) => panic!("client instance: {e:?}"),
        };

        // server：wg-in → freedom lan（override → 回环 echo）
        let mut server_cfg = BuiltConfig::default();
        server_cfg.inbounds.push(wg_inbound(
            &sec_s,
            &pub_c,
            wg_port,
            &["10.0.0.1/32"],
            &["10.0.0.2/32"],
        ));
        let mut allow = loopback_allow();
        allow.push("192.0.2.1/32".to_string());
        server_cfg.outbounds.push(freedom_lan(&allow, Some(("127.0.0.1", inner_port))));
        let (_inst_s, _ohm_s, handles_s) = match start_full(&server_cfg).await {
            Ok(v) => v,
            Err(e) if xray_common::testing::is_addr_in_use_err(&e) => {
                for h in handles_c {
                    h.abort();
                }
                continue;
            },
            Err(e) => panic!("server instance: {e:?}"),
        };
        break (inner_port, entry_port, wg_port, handles_c, handles_s);
    };

    tokio::time::sleep(READY_DELAY).await;

    let payload = make_payload(KB, 0xC800);
    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");

    let started = Instant::now();
    let mut got: Option<Vec<u8>> = None;
    // 有界重发（同用例 3：握手窗口首个数据报可能被 boringtun 吞）
    for attempt in 0..20u32 {
        client.send_to(&payload, ("127.0.0.1", entry_port)).await.expect("client send");
        let mut buf = vec![0u8; 4096];
        match timeout(Duration::from_millis(500), client.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => {
                got = Some(buf[..n].to_vec());
                println!(
                    "[timing] 1KB UDP (loopback override) via wg tunnel: {:?} (attempt {attempt})",
                    started.elapsed()
                );
                break;
            },
            _ => continue,
        }
    }
    assert_eq!(
        got.as_deref(),
        Some(payload.as_slice()),
        "udp echo via loopback override must survive: reply source must be the inner target"
    );

    for h in handles_c.into_iter().chain(handles_s) {
        h.abort();
    }
}
