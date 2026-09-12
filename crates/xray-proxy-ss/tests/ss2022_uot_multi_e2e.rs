//! SS-2022 UDP-over-TCP（uot）多用户链路 e2e。
//!
//! 参照 D:/tmp/ss2022_multi_e2e.py（Go server ↔ Rust client TCP 多 PSK）与
//! ss2022 模块既有 UDP 测试（packet.rs 单元 + dispatcher.rs legacy AEAD UDP）：
//! 补齐「outbound 配置 `uot:true` + 多用户 `iPSK:uPSK`」的 dispatcher UDP 链路——
//!
//! `parse_ss_config`（uot/uotVersion 解析 + iPSK:uPSK 拆分）→ `make_ss_dial_fn`
//! UDP 分支 → `pump_ss2022_udp`（XUDP 帧 ↔ 2022 会话帧，EIH 多用户）→
//! 真实 UDP socket → mock SS-2022 多用户 server（`server_decode_header` +
//! `ServerUdpSession2022`）echo → 回程 decode → dispatch 会话收回。
//!
//! uot 语义对齐 Go 基准 v26.6.1：配置层解析、运行时 UDP 走原生数据报
//! （dispatcher.rs `Network::UDP` 注释；Go shadowsocks_2022 无 uot 消费点），
//! 因此本测试同时证明 uot 字段在场不改变多用户 UDP wire 行为。

use std::{sync::Arc, time::Duration};

use base64::Engine as _;
use tokio::net::UdpSocket;
use xray_app_dispatcher::UdpDispatchSession;
use xray_common::net::{address::Address, destination::Destination, port::Port};
use xray_proxy_ss::{
    dispatcher::{make_ss_dial_fn, parse_ss_config},
    ss2022::{
        key::{CipherKind2022, psk_identity},
        packet::{ServerUdpSession2022, server_decode_header},
    },
};

const KIND: CipherKind2022 = CipherKind2022::Aes256Gcm;
/// 32B iPSK / uPSK（对齐 harness 的可读 ASCII PSK 风格）。
const IPSK: &[u8; 32] = b"0123456789abcdef0123456789abcdef";
const UPSK: &[u8; 32] = b"alice-psk-alice-psk-alice-psk-aa";

fn b64(psk: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(psk)
}

/// mock SS-2022 多用户 UDP server：解 EIH 识别用户 → echo 回包（多用户全路径）。
async fn spawn_multi_user_udp_server(sock: UdpSocket) {
    let ipsk = IPSK.to_vec();
    let upsk = UPSK.to_vec();
    let users = vec![(psk_identity(&upsk), upsk)];
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65_535];
        while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
            let Ok(hdr) = server_decode_header(KIND, &ipsk, &users, &buf[..n]) else {
                continue;
            };
            let Ok(session) =
                ServerUdpSession2022::new(KIND, hdr.aead_psk.to_vec(), hdr.session_id)
            else {
                continue;
            };
            let Ok((addr, port, payload)) =
                session.decode_body(&hdr.hdr, hdr.packet_id, &buf[16 + hdr.eih_len..n])
            else {
                continue;
            };
            let Ok(enc) = session.encode(&addr, port, &payload) else {
                continue;
            };
            let _ = sock.send_to(&enc, peer).await;
        }
    });
}

fn outbound_config_json(server_port: u16) -> serde_json::Value {
    serde_json::json!({
        "servers": [{
            "address": "127.0.0.1",
            "port": server_port,
            "method": "2022-blake3-aes-256-gcm",
            "password": format!("{}:{}", b64(IPSK), b64(UPSK)),
            "uot": true,
            "uotVersion": 1,
        }]
    })
}

/// uot 多用户 dispatcher UDP 链路 e2e：配置解析 → XUDP 会话 → 2022 会话帧
/// （EIH 多用户）→ mock server echo → roundtrip。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ss2022_uot_multi_user_udp_dispatch_roundtrip() {
    // ===== 1. mock SS-2022 多用户 UDP server =====
    let server = UdpSocket::bind("127.0.0.1:0").await.expect("bind server");
    let server_port = server.local_addr().unwrap().port();
    spawn_multi_user_udp_server(server).await;

    // ===== 2. outbound 配置：uot + 多用户 iPSK:uPSK =====
    let cfg = Arc::new(
        parse_ss_config(serde_json::to_vec(&outbound_config_json(server_port)).unwrap().as_slice())
            .expect("parse ss2022 uot config"),
    );
    // uot/uotVersion 解析进配置（Go shadowsocks.go:243-244 口径）
    assert!(cfg.udp_over_tcp.enabled, "uot:true must be parsed");
    assert_eq!(cfg.udp_over_tcp.version, 1);
    // 多用户密码拆分：iPSK:uPSK → identity + user PSK
    let ss2022 = cfg.ss2022.as_ref().expect("ss2022 params");
    assert_eq!(ss2022.psk_b64, b64(UPSK));
    assert_eq!(ss2022.identity_psk_b64.as_deref(), Some(b64(IPSK).as_str()));

    // ===== 3. dispatcher UDP 会话（XUDP 帧 ↔ 2022 会话帧 pump）=====
    let handler: Arc<dyn xray_app_dispatcher::DispatchHandler> =
        Arc::new(xray_app_dispatcher::default::DialBridge::new(
            "ss2022-uot-out",
            make_ss_dial_fn(Arc::clone(&cfg)),
        ));
    let mut session = UdpDispatchSession::new(handler);

    // ===== 4. 发 UDP 包（DNS 查询形态）→ echo 回包 roundtrip =====
    let dest = Destination::udp(Address::Domain("dns.example.local".into()), Port::new(5353));
    let payload = b"ss2022-uot-multi-user-e2e-query".to_vec();
    session.send_packet(&dest, &payload).await.expect("send");

    let (source, got) = tokio::time::timeout(Duration::from_secs(5), session.recv_packet())
        .await
        .expect("echo within 5s")
        .expect("recv ok")
        .expect("session alive");
    assert_eq!(&got[..], &payload[..], "payload roundtrip through uot multi-user link");
    assert_eq!(source.address(), dest.address());
    assert_eq!(source.port(), dest.port());
}
