//! TUIC outbound 域名 server_addr 端到端测试（bd #17）。
//!
//! `tuic://...@sg.example.top:443` 的 settings.address 是域名。
//! `make_dial_fn_lazy` 必须在拨号时经系统 DNS 解析（`ToSocketAddrs`），
//! 而不是在配置解析期 `parse::<SocketAddr>()` 硬拒绝。
//!
//! 拓扑：make_dial_fn_lazy("localhost:port") → TuicMockServer（证书 CN=localhost）
//!       → echo server（TCP 全链路回声）。

#![cfg(test)]

use std::{net::SocketAddr, sync::Arc, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use uuid::Uuid;
use xray_common::net::{address::Address, destination::Destination, network::Network, port::Port};
use xray_proxy_tuic::{
    client::TuicConnectOptions, dispatcher::make_dial_fn_lazy, server::TuicMockServer,
};

fn make_client_config(cert_der: &[u8]) -> Arc<rustls::ClientConfig> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(cert_der.to_vec().into()).unwrap();
    Arc::new(
        rustls::ClientConfig::builder().with_root_certificates(root_store).with_no_client_auth(),
    )
}

async fn start_echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else { break };
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

/// 域名 server_addr（"localhost:port"）应在 dial 时解析并完成 QUIC 连接 + 认证 + TCP 回声。
#[tokio::test]
async fn dial_fn_lazy_resolves_domain_server_addr() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let echo_addr = start_echo_server().await;

    let uuid = Uuid::new_v4();
    let password = "domain-dial-password";
    // quinn 在本机对具体 IPv6 回环地址建 endpoint 会返回 WSAEINVAL（bd ky9z）。
    // 绑通配 IPv6（dual-stack：bind_udp_endpoint 显式置 IPV6_V6ONLY=0）同时覆盖
    // ::1 与 127.0.0.1，客户端继续用域名 localhost 走懒解析路径。
    let bind_addr: std::net::SocketAddr = "[::]:0".parse().unwrap();
    let (server, cert_der) =
        TuicMockServer::bind(bind_addr, "localhost", uuid, password.to_string())
            .await
            .expect("mock server bind");
    // 故意用域名形式，等价真实节点的域名 address（localhost → 本机回环）
    let server_addr = format!("localhost:{}", server.local_addr().port());
    tokio::spawn(async move {
        let _ = server.run().await;
    });

    let client_cfg = make_client_config(&cert_der);
    let dial = make_dial_fn_lazy(
        server_addr,
        "localhost".to_string(),
        uuid,
        password.to_string(),
        client_cfg,
        TuicConnectOptions::default(),
    );

    let dest = Destination::new(
        Address::ipv4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
        Port::new(echo_addr.port()),
        Network::TCP,
    );
    let mut conn = tokio::time::timeout(Duration::from_secs(15), dial(&dest))
        .await
        .expect("dial timed out")
        .expect("dial with domain server_addr should succeed");

    let payload = b"hello tuic domain dial";
    conn.write_all(payload).await.unwrap();

    let mut buf = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(15), conn.read_exact(&mut buf))
        .await
        .expect("timeout waiting for echo response")
        .unwrap();
    assert_eq!(buf, payload);

    drop(conn);
    tokio::time::sleep(Duration::from_millis(100)).await;
}
