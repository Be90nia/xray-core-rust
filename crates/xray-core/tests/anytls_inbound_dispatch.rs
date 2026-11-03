//! anytls **生产 inbound** 注入 dispatcher 的取证（bd b5e77）。
//!
//! 修复前 `build_anytls_inbound`（`crates/xray-core/src/arm_builders/inbound.rs`）
//! 不传 dispatcher，服务端 `dispatch = None` 落两条错误分支：
//!
//! - TCP：走 mock 直连（`TcpStream::connect(target)`）——**绕过 router**（DNS/
//!   fake-IP/路由规则全不生效）；
//! - UoT：`anytls uot: inbound without dispatcher cannot serve UDP` 告警 + 关会话。
//!
//! 本用例走**生产主路**（`Config::build()` → `start_full`，与默认可执行文件同源），
//! 用真 anytls 客户端打该入站：
//!
//! 1. **TCP 往返**（回归）：接线后 TCP 由 mock 直连改为经 router，行为必须仍可用；
//! 2. **UoT 往返**（判别器）：UDP 目标经 freedom 到达 echo。去掉 dispatcher 注入后 服务端只会 warn
//!    + 关会话 → 本断言必红（反向自检）。

#![cfg(test)]

use std::{net::SocketAddr, sync::Arc, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};
use xray_app_dispatcher::udp_session::XudpReframer;
use xray_common::net::{address::Address, destination::Destination, network::Network, port::Port};
use xray_conf::Config;
use xray_core::start_full;
use xray_proxy_anytls::{client::AnytlsClient, dispatcher::make_dial_fn};

/// 单次用例墙钟上限：挂死形态会让整个 `--test` 跑到超时被 kill。
const CASE_TIMEOUT: Duration = Duration::from_secs(20);
const PASSWORD: &str = "anytls-wiring-password";

fn dest(port: u16, network: Network) -> Destination {
    Destination::new(Address::from_ipv4_bytes([127, 0, 0, 1]), Port::new(port), network)
}

/// 一帧 XUDP（dispatch link 的内部表示；`opt` bit0 = New）。
fn xudp_frame(dest: &Destination, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    XudpReframer::new(dest.clone()).write_header(payload.len(), None, &mut out).expect("XUDP 帧头");
    out.extend_from_slice(payload);
    out
}

/// 客户端 conn 读端逐帧取载荷（`[2B meta_len][meta][2B data_len][data]`）。
async fn read_xudp_payload(conn: &mut (impl AsyncReadExt + Unpin)) -> Vec<u8> {
    let meta_len = conn.read_u16().await.expect("XUDP meta_len") as usize;
    let mut meta = vec![0u8; meta_len];
    conn.read_exact(&mut meta).await.expect("XUDP meta");
    let data_len = conn.read_u16().await.expect("XUDP data_len") as usize;
    let mut data = vec![0u8; data_len];
    conn.read_exact(&mut data).await.expect("XUDP data");
    data
}

async fn start_tcp_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind tcp echo");
    let addr = listener.local_addr().expect("local addr");
    xray_common::testing::spawn("anytls-wiring-tcp-echo", async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            xray_common::testing::spawn("anytls-wiring-tcp-echo-conn", async move {
                let (mut r, mut w) = sock.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr
}

async fn start_udp_echo() -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp echo");
    let addr = sock.local_addr().expect("local addr");
    xray_common::testing::spawn("anytls-wiring-udp-echo", async move {
        let mut buf = vec![0u8; 65535];
        while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
            let _ = sock.send_to(&buf[..n], peer).await;
        }
    });
    addr
}

/// 自签证书（SAN=localhost）：入站走 `settings.cert/key` 的 PEM 分支，客户端拿
/// DER 作信任锚——与真机 `{"cert":..,"key":..}` 配置同形，不走自签兜底。
fn make_cert() -> (String, String, Vec<u8>) {
    use rcgen::{CertificateParams, KeyPair};
    let params = CertificateParams::new(vec!["localhost".to_string()]).expect("cert params");
    let key_pair = KeyPair::generate().expect("keypair");
    let cert = params.self_signed(&key_pair).expect("self signed");
    (cert.pem(), key_pair.serialize_pem(), cert.der().to_vec())
}

fn client_tls(cert_der: Vec<u8>) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der.into()).expect("trust self-signed");
    Arc::new(rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn anytls_inbound_dispatches_through_router() {
    xray_common::ensure_default_crypto_provider();
    let (cert_pem, key_pem, cert_der) = make_cert();
    let tcp_echo = start_tcp_echo().await;
    let udp_echo = start_udp_echo().await;

    let port = xray_common::testing::pick_free_ports(1).await[0];
    let cfg = Config::from_json_str(
        &serde_json::json!({
            "log": {"loglevel": "warning"},
            "inbounds": [{
                "tag": "anytls-in",
                "listen": "127.0.0.1",
                "port": port,
                "protocol": "anytls",
                "settings": {"cert": cert_pem, "key": key_pem, "password": PASSWORD},
            }],
            // 默认出站 = freedom：dispatcher 生效的必要条件（无默认出站 = 启动期硬错）。
            "outbounds": [{"protocol": "freedom", "tag": "direct"}],
        })
        .to_string(),
    )
    .expect("config json parses");
    let built = cfg.build().expect("config builds");
    let (_instance, _ohm, _handles) =
        start_full(&built).await.expect("anytls inbound starts with dispatcher");

    let client = Arc::new(AnytlsClient::new(
        xray_proxy_anytls::ClientConfig::new(
            format!("127.0.0.1:{port}"),
            "localhost",
            PASSWORD,
            client_tls(cert_der),
        ),
        Arc::new(xray_frame::PluginContext::for_plugin("anytls")),
    ));
    let dial = make_dial_fn(Arc::clone(&client));

    // ② TCP（回归）：接线后走 router 而非 mock 直连，链路必须照样通。
    let tcp_dest = dest(tcp_echo.port(), Network::TCP);
    let mut tcp = tokio::time::timeout(CASE_TIMEOUT, dial(&tcp_dest))
        .await
        .expect("TCP dial 超时")
        .expect("TCP dial");
    tcp.write_all(b"anytls-tcp-echo").await.expect("写 TCP 载荷");
    tcp.flush().await.expect("flush");
    let mut echo = [0u8; 15];
    tokio::time::timeout(CASE_TIMEOUT, tcp.read_exact(&mut echo))
        .await
        .expect("TCP 回包超时")
        .expect("TCP 回包");
    assert_eq!(&echo, b"anytls-tcp-echo", "TCP 往返必须逐字节一致（经 router → freedom）");

    // ① UoT（判别器）：dispatch=None 时服务端关会话，这里必错。
    let udp_dest = dest(udp_echo.port(), Network::UDP);
    let mut uot = tokio::time::timeout(CASE_TIMEOUT, dial(&udp_dest))
        .await
        .expect("UoT dial 超时")
        .expect("UoT dial（会话被服务端关闭 = dispatcher 未注入）");
    for payload in [b"uot-hello".as_slice(), &[0x5Au8; 1400][..]] {
        uot.write_all(&xudp_frame(&udp_dest, payload)).await.expect("写 UoT 数据报");
        uot.flush().await.expect("flush");
        let got = tokio::time::timeout(CASE_TIMEOUT, read_xudp_payload(&mut uot))
            .await
            .expect("UoT 回包超时");
        assert_eq!(got, payload, "UoT 往返必须逐字节一致（经 router → freedom）");
    }
    drop(uot);

    let _ = client.close().await;
}
