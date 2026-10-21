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
