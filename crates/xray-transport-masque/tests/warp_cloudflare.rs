//! WARP 变体（`masqueSettings.warp`）**真连 Cloudflare**：静态地址 + 自签客户端证书 +
//! 端点 SPKI pin + `cf-connect-proto`/`pq-enabled` 请求形态 → 隧道内 IPv4/UDP DNS 往返。
//!
//! env 门控（无凭据即跳过，零外部依赖不影响 CI）：
//!
//! ```text
//! WARP_CREDS=D:/tmp/warp-2026-11-11/creds.json \
//!   cargo test -p xray-transport-masque --test warp_cloudflare -- --ignored --nocapture
//! ```
//!
//! `creds.json` 由 `D:/tmp/warp-2026-11-11/register.py`（POST
//! `api.cloudflareclient.com/v0i190905/reg`）
//! + `enroll.py`（PATCH `reg/{id}` 登记 ECDSA P-256 公钥，`key_type=secp256r1`/`tun_type=masque`）
//!   产出，字段：`client_priv_pkcs8_b64`（MASQUE
//!   客户端私钥）、`enrolled_reg.config.interface.addresses` （静态 v4/v6）。**凭据不入库**。
//!
//! 可选 env：
//! - `WARP_ENDPOINT`：`ip:port`，缺省 `162.159.198.2:443`（usque `config/endpoints.go`
//!   `DefaultEndpointH2V4` = **WARP 免费版的 h2 端点**）。 ⚠️ 旧默认 `162.159.192.1`（engage
//!   anycast）**不可用**：该端点只服务 `cloudflareclient.com` 证书族，CONNECT-IP 一律被 CF 判 **400
//!   Bad Request** （2026-11-12 在 176 实测：Rust 与 Go 参考实现同样 400）。
//! - `WARP_SPKI`：端点证书 SPKI base64（`warp.publicKey` 的 pin 目标）。缺省读 creds 的
//!   `endpoint_spki_b64`；两者皆无 → 走 `allowInsecure`（只验 TLS 通道，不验端点身份）。 ⚠️ pin
//!   必须取自 **h2 端点 `162.159.198.2`**（证书 CN=`masque.cloudflareclient.com`， SPKI sha256 前缀
//!   `eb591b36ab26`）；engage anycast 的证书族（`4c9b9a0b422a`）是另一把 钥，与之不通用。

#![allow(clippy::disallowed_methods)]

use std::{
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};

use xray_common::net::{address::Address, destination::Destination, port::Port};
use xray_transport::{dialer::StreamSettings, sockopt::SocketOptions};
use xray_transport_masque::config::Config;

/// Cloudflare MASQUE 的 SNI（usque `internal/consts.go: ConnectSNI`；**无 A 记录**，仅 SNI）。
const CONNECT_SNI: &str = "consumer-masque.cloudflareclient.com";

fn creds_path() -> Option<String> {
    std::env::var("WARP_CREDS").ok().filter(|p| !p.is_empty())
}

/// IPv4 + UDP 包（含端口与校验和）。
fn udp_v4_packet(src: Ipv4Addr, sport: u16, dst: Ipv4Addr, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0u8; 20 + 8 + payload.len()];
    let total = p.len() as u16;
    p[0] = 0x45;
    p[2..4].copy_from_slice(&total.to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    let ip_ck = checksum(&p[..20], 0);
    p[10..12].copy_from_slice(&ip_ck.to_be_bytes());
    p[20..22].copy_from_slice(&sport.to_be_bytes());
    p[22..24].copy_from_slice(&dport.to_be_bytes());
    p[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    p[28..].copy_from_slice(payload);
    // UDP 校验和含伪首部（IPv4 允许 0 = 未计算，但 CF 侧按全零更安全）。
    let mut pseudo = Vec::with_capacity(12 + p.len() - 20);
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&[0, 17]);
    pseudo.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    pseudo.extend_from_slice(&p[20..]);
    let mut ck = !checksum(&pseudo, 0);
    if ck == 0 {
        ck = 0xffff;
    }
    p[26..28].copy_from_slice(&ck.to_be_bytes());
    p
}

fn checksum(data: &[u8], mut sum: u32) -> u16 {
    for chunk in data.chunks(2) {
        let w = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum += u32::from(w);
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// 最小 DNS A 查询：`id` 由调用方给，`qname` 形如 `example.com`。
fn dns_query(id: u16, qname: &str) -> Vec<u8> {
    let mut q = Vec::with_capacity(32);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    q.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    q.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // AN/NS/AR
    for label in qname.split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&1u16.to_be_bytes()); // A
    q.extend_from_slice(&1u16.to_be_bytes()); // IN
    q
}

/// `(udp 载荷, 目的端口, DNS id, QR, ANCOUNT)`
fn parse_udp_v4_response(packet: &[u8]) -> Option<(&[u8], u16, u16, bool, u16)> {
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    if packet[9] != 17 || packet.len() < ihl + 8 {
        return None;
    }
    let udp = &packet[ihl..];
    let dport = u16::from_be_bytes([udp[0], udp[1]]);
    let payload = &udp[8..];
    if payload.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([payload[0], payload[1]]);
    let qr = payload[2] & 0x80 != 0;
    let ancount = u16::from_be_bytes([payload[6], payload[7]]);
    Some((payload, dport, id, qr, ancount))
}

#[tokio::test]
#[ignore = "真连 Cloudflare WARP：需 WARP_CREDS=<creds.json>"]
async fn warp_tunnel_dns_roundtrip() {
    let Some(creds_path) = creds_path() else {
        eprintln!("SKIP: WARP_CREDS not set");
        return;
    };
    let creds: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&creds_path).expect("read creds"))
            .expect("creds json");
    let private_key = creds["client_priv_pkcs8_b64"].as_str().expect("client_priv_pkcs8_b64");
    let reg = &creds["enrolled_reg"]["config"];
    let v4: Ipv4Addr = reg["interface"]["addresses"]["v4"]
        .as_str()
        .expect("interface.addresses.v4")
        .parse()
        .expect("v4 addr");
    let v6 =
        reg["interface"]["addresses"]["v6"].as_str().expect("interface.addresses.v6").to_string();
    let spki = std::env::var("WARP_SPKI")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| creds["endpoint_spki_b64"].as_str().map(str::to_string));
    let endpoint = std::env::var("WARP_ENDPOINT")
        .unwrap_or_else(|_| "162.159.198.2:443".to_string())
        .trim()
        .to_string();
    let (host, port) = endpoint.rsplit_once(':').expect("WARP_ENDPOINT as ip:port");
    let host: Ipv4Addr = host.parse().expect("WARP_ENDPOINT ip");

    // 无 pin 值时用自签 CLI 证书的 SPKI 占位 + allowInsecure（Go `InsecureSkipVerify` ⇒ useWarp
    // 不装自带 pin 的同义路径）；有 pin 值 → 走 WARP 自带 SPKI 校验。
    let masque_settings = match &spki {
        Some(spki) => serde_json::json!({
            "warp": { "privateKey": private_key, "publicKey": spki, "address": [v4.to_string(), v6] }
        }),
        None => {
            let placeholder = creds["client_spki_b64"].as_str().expect("client_spki_b64");
            serde_json::json!({
                "warp": {
                    "privateKey": private_key,
                    "publicKey": placeholder,
                    "address": [v4.to_string(), v6]
                }
            })
        },
    };
    let config = Config::from_json(Some(&masque_settings)).expect("warp settings parse");
    eprintln!(
        "warp config: host={} path={} addrs={:?} pin={}",
        config.host,
        config.path,
        config.warp.as_ref().expect("warp").local_addrs(),
        spki.is_some()
    );

    let mut security = serde_json::json!({ "serverName": CONNECT_SNI, "alpn": ["h2"] });
    if spki.is_none() {
        security["allowInsecure"] = serde_json::Value::Bool(true);
    }
    let settings = StreamSettings {
        protocol: "masque".into(),
        security: "tls".into(),
        security_json: Some(security),
        ..StreamSettings::tcp()
    };
    let dest = Destination::tcp(Address::ipv4(host), Port::new(port.parse().expect("port")));

    // 公网抖动重试：本机到 WARP anycast 443 的握手实测 ~1/4 成功率（RST / 超时交替，
    // 同一 IP 同一 SNI 同一证书，属链路层扰动而非协议拒绝）。
    let mut session = {
        let mut last = None;
        let mut ok = None;
        for attempt in 1..=6 {
            match tokio::time::timeout(
                Duration::from_secs(30),
                xray_transport_masque::dialer::dial(
                    &dest,
                    &SocketOptions::default(),
                    &settings,
                    &config,
                ),
            )
            .await
            {
                Ok(Ok(s)) => {
                    eprintln!("dial attempt {attempt}: tunnel up");
                    ok = Some(s);
                    break;
                },
                Ok(Err(e)) => eprintln!("dial attempt {attempt} failed: {e}"),
                Err(_) => eprintln!("dial attempt {attempt} timed out"),
            }
            last = Some(attempt);
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        ok.unwrap_or_else(|| panic!("warp dial to {endpoint} failed after {last:?} attempts"))
    };

    let local: Vec<IpAddr> = session.local_addrs().to_vec();
    eprintln!("tunnel up: local_addrs={local:?}");
    assert!(local.contains(&IpAddr::V4(v4)), "static v4 address must be registered: {local:?}");

    // 隧道内 IPv4/UDP DNS（1.1.1.1:53）
    let id: u16 = 0x5a5a;
    let query = dns_query(id, "cloudflare.com");
    let packet = udp_v4_packet(v4, 40000, Ipv4Addr::new(1, 1, 1, 1), 53, &query);
    session.send_packet(&packet).await.expect("send DNS query");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(!remaining.is_zero(), "no DNS response within 15s");
        let got = tokio::time::timeout(remaining, session.recv_packet())
            .await
            .expect("recv timeout")
            .expect("recv failed");
        let Some((_payload, dport, rid, qr, ancount)) = parse_udp_v4_response(&got) else {
            eprintln!("skip non-UDP-IPv4 packet ({} bytes)", got.len());
            continue;
        };
        eprintln!(
            "got {}-byte packet, udp src port={dport}, dns id={rid:#06x}, qr={qr}, ancount={ancount}",
            got.len()
        );
        if rid == id && dport == 53 && qr {
            eprintln!(
                "DNS OK: cloudflare.com resolved with {ancount} answer(s) through WARP tunnel"
            );
            return;
        }
    }
}
