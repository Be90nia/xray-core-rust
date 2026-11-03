//! UoT v2 线格式对齐取证（bd b5e77）。
//!
//! spec = sing `common/uot/{protocol,conn,server}.go`（sing-box anytls outbound 的
//! `uotClient` 用它，故这是与真实对端互通的唯一判据）：
//!
//! - 会话首帧 `Request`：`[1B isConnect][SOCKS5 addr]`（`crate::uot::encode_request`）；
//! - isConnect=true 时每个数据报：`[2B BE len][payload]`，**载荷层不带任何帧头**。
//!
//! 两个用例：
//! 1. [`uot_wire_bytes_match_sing_spec`]——裸字节级：客户端写出的 wire 必须逐字节 等于 `[2B
//!    len][payload]`，且同一段字节喂给服务端组合后能还原同一载荷； 边界尺寸 1 / 1500 / 65000（u16
//!    长度前缀上限附近）。两侧任一漂移即红。
//! 2. [`uot_client_server_udp_roundtrip`]——端到端：真 anytls 客户端 → TLS → `AnytlsMockServer`（UoT
//!    分支）→ dispatcher(freedom) → UDP echo，验证生产 装配下整链可用（bd b5e77
//!    的「帧已发但对不上」现象即此用例的失败形态）。

#![cfg(test)]
#![cfg_attr(test, allow(clippy::disallowed_macros))] // 测试脚手架：spawn 走 xray_common::testing（L3 闸不豁免）

use std::{net::SocketAddr, sync::Arc, time::Duration};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt, DuplexStream},
    net::UdpSocket,
};
use tokio_rustls::TlsAcceptor;
use xray_app_dispatcher::{
    DispatchHandler, OutboundHandlerManager,
    default::{DialBridge, SimpleOhm},
    udp_session::{XudpReframer, XudpWireConn},
};
use xray_buf::{
    buffer::Buffer,
    io::{Reader, Writer, new_reader, new_writer},
    multi::MultiBuffer,
};
use xray_common::net::{address::Address, destination::Destination, network::Network, port::Port};
use xray_proxy_anytls::{AnytlsMockServer, client::AnytlsClient, dispatcher::make_dial_fn};

/// 单次用例的墙钟上限：本仓无 per-test 超时，挂死形态会让整个 `--test` 跑到超时被 kill。
const CASE_TIMEOUT: Duration = Duration::from_secs(20);

fn udp_dest(port: u16) -> Destination {
    Destination::new(Address::from_ipv4_bytes([127, 0, 0, 1]), Port::new(port), Network::UDP)
}

/// 造一帧 XUDP 帧（= dispatch link 的内部表示，出站侧写的字节）。
///
/// global_id 随机（`XudpReframer::new` 内 `rand::random()`），故用例里只比较
/// **载荷**与 **UoT wire 字节**，不比较两侧 meta 的会话 ID。
fn xudp_frame(dest: &Destination, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    XudpReframer::new(dest.clone()).write_header(payload.len(), None, &mut out).unwrap();
    out.extend_from_slice(payload);
    out
}

/// 从裸 wire 字节流里读出一个 UoT 帧（`[2B BE len][payload]`）。
async fn read_uot_wire_frame(peer: &mut DuplexStream, payload_len: usize) -> Vec<u8> {
    let mut frame = vec![0u8; 2 + payload_len];
    peer.read_exact(&mut frame).await.expect("读取 UoT wire 帧");
    frame
}

/// 从 link 读端（Reader）取出一个 XUDP 帧的载荷（跨 Buffer 累积）。
async fn read_link_payload(reader: &mut Box<dyn Reader>) -> Vec<u8> {
    let mut accum = Vec::new();
    loop {
        if let Some(payload) = parse_frame_payload(&accum) {
            return payload;
        }
        let mb = reader.read_multi_buffer().await.expect("link read");
        assert!(!mb.is_empty(), "XUDP 帧未读完就 EOF");
        for buf in mb.iter() {
            accum.extend_from_slice(buf.bytes());
        }
    }
}

/// 从 AsyncRead 端（连接流）取出一个 XUDP 帧的载荷。
async fn read_conn_payload(conn: &mut (impl AsyncRead + Unpin)) -> Vec<u8> {
    let mut meta_len = [0u8; 2];
    conn.read_exact(&mut meta_len).await.expect("读 meta 长度");
    let mut meta = vec![0u8; usize::from(u16::from_be_bytes(meta_len))];
    conn.read_exact(&mut meta).await.expect("读 meta");
    let mut data_len = [0u8; 2];
    conn.read_exact(&mut data_len).await.expect("读 data 长度");
    let mut payload = vec![0u8; usize::from(u16::from_be_bytes(data_len))];
    conn.read_exact(&mut payload).await.expect("读载荷");
    payload
}

/// 解析完整 XUDP 帧的载荷（`[2B meta_len][meta][2B data_len][data]`，opt bit0 置位）。
/// `None` = 字节还不足一帧。
fn parse_frame_payload(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.len() < 6 {
        return None;
    }
    let meta_len = usize::from(u16::from_be_bytes([bytes[0], bytes[1]]));
    assert!(bytes[5] & 1 == 1, "本用例只写带 data 段的帧");
    if bytes.len() < 4 + meta_len {
        return None;
    }
    let data_len = usize::from(u16::from_be_bytes([bytes[2 + meta_len], bytes[3 + meta_len]]));
    let start = 4 + meta_len;
    (bytes.len() >= start + data_len).then(|| bytes[start..start + data_len].to_vec())
}

/// 服务端组合（与 `server::serve_uot_session` 同形）：wire 流 → dispatch link。
///
/// 复制这 3 行是刻意的：用例要钉的是「wire `[2B len][payload]` ↔ XUDP 帧」这条
/// 表示转换本身；生产组合的端到端覆盖由 [`uot_client_server_udp_roundtrip`] 提供。
fn server_link(
    stream: impl AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    dest: &Destination,
) -> (Box<dyn Reader>, Box<dyn Writer>) {
    let (rh, wh) = tokio::io::split(XudpWireConn::new(stream, dest.clone()));
    (new_reader(rh), new_writer(wh))
}

#[tokio::test]
async fn uot_wire_bytes_match_sing_spec() {
    let dest = udp_dest(53);
    for payload_len in [1usize, 1500, 65000] {
        let payload = vec![0xA5u8; payload_len];
        let expected_wire = {
            let mut w = (payload_len as u16).to_be_bytes().to_vec();
            w.extend_from_slice(&payload);
            w
        };

        // ── 上行：客户端转换器写出的 wire 逐字节 = `[2B len][payload]` ──
        let (client_end, mut client_peer) = tokio::io::duplex(2 * 1024 * 1024);
        let mut client = XudpWireConn::new(client_end, dest.clone());
        client.write_all(&xudp_frame(&dest, &payload)).await.expect("client 写 XUDP 帧");
        let wire =
            tokio::time::timeout(CASE_TIMEOUT, read_uot_wire_frame(&mut client_peer, payload_len))
                .await
                .expect("客户端写出 UoT 帧超时");
        assert_eq!(wire, expected_wire, "len={payload_len}: 客户端 wire 必须=长度前缀+裸载荷");

        // 同一段字节喂服务端组合 → 还原出同一载荷（两侧表示一致）
        let (mut feed, server_end) = tokio::io::duplex(2 * 1024 * 1024);
        feed.write_all(&wire).await.expect("灌入 wire 字节");
        let (mut server_reader, _server_writer) = server_link(server_end, &dest);
        let got = tokio::time::timeout(CASE_TIMEOUT, read_link_payload(&mut server_reader))
            .await
            .expect("服务端读 link 超时");
        assert_eq!(got, payload, "len={payload_len}: 服务端必须还原同一载荷");
        drop(feed);

        // ── 下行：服务端写 XUDP 帧 → wire 逐字节 = `[2B len][payload]` ──
        let (server_end, mut server_peer) = tokio::io::duplex(2 * 1024 * 1024);
        let (_reader, mut server_writer) = server_link(server_end, &dest);
        let frame = xudp_frame(&dest, &payload);
        server_writer
            .write_multi_buffer(MultiBuffer::from_buffer(Buffer::from_vec(frame)))
            .await
            .expect("服务端写 XUDP 帧");
        let wire =
            tokio::time::timeout(CASE_TIMEOUT, read_uot_wire_frame(&mut server_peer, payload_len))
                .await
                .expect("服务端写出 UoT 帧超时");
        assert_eq!(wire, expected_wire, "len={payload_len}: 服务端 wire 必须=长度前缀+裸载荷");

        // 同一段字节喂客户端转换器 → 还原出同一载荷
        let (mut feed, client_end) = tokio::io::duplex(2 * 1024 * 1024);
        feed.write_all(&wire).await.expect("灌入 wire 字节");
        let mut client = XudpWireConn::new(client_end, dest.clone());
        let got = tokio::time::timeout(CASE_TIMEOUT, read_conn_payload(&mut client))
            .await
            .expect("客户端读响应超时");
        assert_eq!(got, payload, "len={payload_len}: 客户端必须还原同一载荷");
        drop(feed);
    }
}

/// UDP echo：收到什么回什么（足够验证 UoT 双向帧）。
async fn start_udp_echo() -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    xray_common::testing::spawn("anytls-uot-udp-echo", async move {
        let mut buf = vec![0u8; 65535];
        while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
            let _ = sock.send_to(&buf[..n], peer).await;
        }
    });
    addr
}

fn make_server_config() -> (rustls::ServerConfig, Vec<u8>) {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
    let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, "localhost");
    let key_pair = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    let cert_der = cert.der().clone();
    let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der());
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(cert_der.to_vec())],
            key_der.into(),
        )
        .unwrap();
    (server_config, cert_der.to_vec())
}

fn make_client_config(server_cert_der: &[u8]) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(server_cert_der.to_vec().into()).unwrap();
    Arc::new(rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth())
}

#[tokio::test]
async fn uot_client_server_udp_roundtrip() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    const PASSWORD: &str = "uot-test-password";

    // 1. UDP echo（真实目标）
    let echo_addr = start_udp_echo().await;

    // 2. dispatcher：freedom（UDP 分支按 XUDP 帧消费 link）
    let (server_config, cert_der) = make_server_config();
    let ohm = Arc::new(SimpleOhm::new());
    ohm.set_default(Arc::new(xray_proxy_freedom::FreedomDispatchBridge::from_bridge(
        Arc::new(xray_frame::PluginContext::for_plugin("freedom")),
        Arc::new(DialBridge::new("freedom", xray_proxy_freedom::make_freedom_dial_fn())),
    )));
    let dispatch: Arc<dyn DispatchHandler> = ohm.get_default_handler().unwrap();

    // 3. anytls 服务端（UoT 分支走 serve_uot_session）
    let server = AnytlsMockServer::start_with_password(
        "127.0.0.1:0".parse().unwrap(),
        TlsAcceptor::from(Arc::new(server_config)),
        Some(dispatch),
        Some(PASSWORD),
    )
    .await
    .expect("anytls mock server start");

    // 4. anytls 客户端：dial_fn 的 UDP 分支即 UoT 客户端实现
    let client = Arc::new(AnytlsClient::new(
        xray_proxy_anytls::ClientConfig::new(
            server.local_addr.to_string(),
            "localhost",
            PASSWORD,
            make_client_config(&cert_der),
        ),
        Arc::new(xray_frame::PluginContext::for_plugin("anytls")),
    ));
    let dial = make_dial_fn(Arc::clone(&client));
    let dest = udp_dest(echo_addr.port());

    let mut conn = tokio::time::timeout(CASE_TIMEOUT, dial(&dest))
        .await
        .expect("UoT dial 超时")
        .expect("UoT dial 失败");

    // 5. 多尺寸往返：单包 → 多包 → u16 长度前缀上限附近
    for payload in [b"uot-hello".as_slice(), &[0x5Au8; 1400][..], &[0xC3u8; 60000][..]] {
        conn.write_all(&xudp_frame(&dest, payload)).await.expect("写 UoT 数据报");
        conn.flush().await.expect("flush");
        let got = tokio::time::timeout(CASE_TIMEOUT, read_conn_payload(&mut conn))
            .await
            .expect("UoT 回包超时（帧格式对不上 = 服务端解析失败）");
        assert_eq!(got, payload, "UoT 往返载荷必须逐字节一致");
    }

    drop(conn);
    let _ = client.close().await;
    server.stop().await;
}
