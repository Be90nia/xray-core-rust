//! 集成测试：裸 TCP（无 TLS）+ finalmask 双向互通（bd dppv 缺陷二）。
//!
//! 走两端生产入口：
//! - 客户端 `dial_with_settings("tcp", ...)` → `xray-transport-tcp` dialer → `WrapConnClient`（Go
//!   `tcp/dialer.go:28`）；
//! - 服务端 `InboundTcpListener::accept_masked()` → `WrapConnServer` （Go `tcp/hub.go`
//!   WrapListener）。
//!
//! 断言 131072B 双向逐字节一致（逐字节相等蕴含 sha256 相等；本 crate 未引 sha2
//! dev 依赖，禁改 Cargo.toml）。

use std::{net::Ipv4Addr, sync::Arc};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use xray_common::net::{address::Address, destination::Destination, port::Port};
use xray_transport::{
    dialer::{StreamSettings, dial_with_settings},
    finalmask::{TcpmaskManager, build_tcpmask_manager_from_json},
    sockopt::SocketOptions,
    system_listener::InboundTcpListener,
};

const PAYLOAD_LEN: usize = 131_072;

fn payload() -> Vec<u8> {
    (0..PAYLOAD_LEN).map(|i| (i % 251) as u8).collect()
}

/// xmc（Minecraft 握手伪装）配置：password 派生 RSA，生产形态 padding 未关。
fn xmc_json() -> serde_json::Value {
    serde_json::json!({"tcp": [{"type": "xmc", "settings": {
        "password": "dppv-night-run-secret",
        "hostname": "localhost",
        "profiles": [{
            "username": "NightRunner",
            "uuid": "b3f5d0e0-1111-4222-8333-444455556666",
            "texturesValue": "textures-value",
            "texturesSignature": "textures-signature"
        }]
    }}]})
}

fn server_mask() -> Arc<TcpmaskManager> {
    Arc::new(build_tcpmask_manager_from_json(Some(&xmc_json())).expect("server mask"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn naked_tcp_finalmask_xmc_roundtrip_131072() {
    tokio::time::timeout(std::time::Duration::from_secs(120), async {
        let listener = InboundTcpListener::bind("127.0.0.1:0", SocketOptions::default())
            .await
            .expect("bind")
            .with_tcpmask_manager(Some(server_mask()));
        let addr = listener.local_addr().expect("local_addr");

        let data = payload();
        let expect = data.clone();
        #[allow(clippy::disallowed_methods, reason = "测试：mask echo server 任务")]
        let server = tokio::spawn(async move {
            let (mut conn, _peer) = listener.accept_masked().await.expect("accept_masked");
            assert!(conn.plain().is_none(), "服务端必须走 mask 包装");
            let mut buf = vec![0u8; expect.len()];
            conn.read_exact(&mut buf).await.expect("server read");
            assert_eq!(buf, expect, "上传 131072B 必须逐字节一致");
            conn.write_all(&buf).await.expect("server echo");
            conn.shutdown().await.expect("server shutdown");
        });

        // 客户端：与 outbound.rs `parse_stream_settings` 同一条解析路径。
        let _ = xray_transport_tcp::register::register_dialer();
        let json = serde_json::json!({"network": "tcp", "finalmask": xmc_json()});
        let settings = StreamSettings::from_json(Some(&json));
        let dest = Destination::tcp(Address::IPv4(Ipv4Addr::LOCALHOST), Port::new(addr.port()));
        let mut conn = dial_with_settings("tcp", &dest, &SocketOptions::default(), &settings)
            .await
            .expect("裸 TCP + finalmask 拨号应成功");

        conn.write_all(&data).await.expect("client write");
        let mut got = vec![0u8; data.len()];
        conn.read_exact(&mut got).await.expect("client read");
        assert_eq!(got, data, "下行 131072B 必须逐字节一致");
        server.await.expect("server task");
    })
    .await
    .expect("裸 TCP + finalmask 互通超时");
}

/// bd 1jt9v：`tcp + finalmask + security=tls` 组合——客户端 mask 必须在安全层**之内**
/// （Go `tcp/dialer.go:26-32`：`FinalMask.DialTCP` **取代** `DialSystem`），与服务端
/// （accept 即解包、TLS 跑在其上）同侧。次序反了 = 客户端 mask 吃明文、服务端吃密文
/// ⇒ TLS 握手字节本身就被打成两种编码，握手必失败。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_finalmask_tls_roundtrip_131072() {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    tokio::time::timeout(std::time::Duration::from_secs(120), async {
        rustls::crypto::ring::default_provider().install_default().ok();
        // 自签证书：客户端配 allowInsecure=true 跳过验证（本测试只验分层次序）。
        let key_pair = rcgen::KeyPair::generate().expect("keypair");
        let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("params");
        let cert = params.self_signed(&key_pair).expect("self signed");
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert.der().to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der())),
            )
            .expect("server config");
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

        let listener = InboundTcpListener::bind("127.0.0.1:0", SocketOptions::default())
            .await
            .expect("bind")
            .with_tcpmask_manager(Some(server_mask()));
        let addr = listener.local_addr().expect("local_addr");

        let data = payload();
        let expect = data.clone();
        #[allow(clippy::disallowed_methods, reason = "测试：mask+TLS echo server 任务")]
        let server = tokio::spawn(async move {
            let (conn, _peer) = listener.accept_masked().await.expect("accept_masked");
            assert!(conn.plain().is_none(), "服务端必须走 mask 包装");
            let mut tls = acceptor.accept(conn).await.expect("服务端 TLS 握手（mask 在 TLS 之下）");
            let mut buf = vec![0u8; expect.len()];
            tls.read_exact(&mut buf).await.expect("server read");
            assert_eq!(buf, expect, "经 mask + TLS 的上行必须逐字节一致");
            tls.write_all(&buf).await.expect("server echo");
            tls.shutdown().await.expect("server shutdown");
        });

        let _ = xray_transport_tcp::register::register_dialer();
        let json = serde_json::json!({
            "network": "tcp",
            "security": "tls",
            "tlsSettings": {"serverName": "localhost", "allowInsecure": true},
            "finalmask": xmc_json(),
        });
        let settings = StreamSettings::from_json(Some(&json));
        let dest = Destination::tcp(Address::IPv4(Ipv4Addr::LOCALHOST), Port::new(addr.port()));
        let mut conn = dial_with_settings("tcp", &dest, &SocketOptions::default(), &settings)
            .await
            .expect("tcp + finalmask + tls 拨号应成功");

        conn.write_all(&data).await.expect("client write");
        let mut got = vec![0u8; data.len()];
        conn.read_exact(&mut got).await.expect("client read");
        assert_eq!(got, data, "下行必须逐字节一致");
        server.await.expect("server task");
    })
    .await
    .expect("tcp + finalmask + tls 互通超时");
}
