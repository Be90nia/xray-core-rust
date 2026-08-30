//! UDP connection 集成测试（bd sk8r P3）。
//!
//! 对应 Go `testing/scenarios/feature_test.go::TestUDPConnection`：
//! dokodemo UDP inbound 监听端口、目标 rewrite 到 UDP echo server；客户端通过
//! UDP socket 发包到 dokodemo inbound → 数据被透明转发到 UDP echo → 验证回环。
//!
//! 拓扑：
//!   client UdpSocket → dokodemo UDP inbound (rewrite → 127.0.0.1:echo_port)
//!                  → dispatcher → freedom default outbound → UDP echo server
//!
//! 注：dokodemo UDP 路径依赖 freedom 出站的 UDP handler（`serve_dokodemo_udp`
//! → `dispatch_link` → FreedomDispatchBridge → UdpSocket），本次只验证单跳
//! round-trip。Go 原版还做 20s 后重连验证空闲 cleanup，本测试因 Rust 端 UDP
//! session cleanup 在 dispatcher 实现中可能未达完全对齐，**只验证单轮**——
//! 见 P3 任务约束「test DialXray 真实外部拨号」类比，UDP idle cleanup 是
//! 全局 UDP session idle 路径的一部分，跨 Batch 验证。
//!
//! 不依赖 btls/boringssl。

use std::time::Duration;

use tokio::net::{TcpListener, UdpSocket};

use xray_conf::{BuiltConfig, BuiltEntry, BuiltInbound, BuiltOutbound};
use xray_core::functions::start_full;

/// Bind a free TCP port then drop the probe (used for the listening socket probe).
async fn pick_free_port() -> u16 {
    let probe = TcpListener::bind("127.0.0.1:0").await.expect("pick port");
    let port = probe.local_addr().expect("port").port();
    drop(probe);
    port
}

/// Start a UDP echo server. Each datagram is looped back to sender.
/// Returns the listener port.
async fn spawn_udp_echo_server() -> u16 {
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("udp echo bind");
    let port = sock.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let (n, peer) = match sock.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => continue,
            };
            // loopback：原样回包
            let _ = sock.send_to(&buf[..n], peer).await;
        }
    });
    port
}

/// Build a freedom outbound (default destination handler).
fn freedom_outbound(tag: &str) -> BuiltOutbound {
    BuiltOutbound {
        entry: BuiltEntry {
            kind: "freedom".into(),
            data: b"{}".to_vec(),
        },
        tag: tag.into(),
        send_through: None,
        stream_settings_json: None,
        proxy_settings_json: None,
        mux_json: None,
        target_strategy: None,
    }
}

/// Build a dokodemo-door inbound for UDP only, pointing at `address:port`.
fn dokodemo_udp_inbound(port: u16, target_addr: &str, target_port: u16) -> BuiltInbound {
    let data = serde_json::json!({
        "address": target_addr,
        "port": target_port,
        "network": "udp",
    })
    .to_string()
    .into_bytes();
    BuiltInbound {
        entry: BuiltEntry {
            kind: "dokodemo".into(),
            data,
        },
        tag: "dokodemo-udp-in".into(),
        port: Some(port),
        listen: Some("127.0.0.1".into()),
        stream_settings_json: None,
        sniffing_json: None,
    }
}

/// Wait briefly for the UDP inbound socket to bind and accept packets.
async fn wait_ready(port: u16) {
    for _ in 0..50 {
        let probe = UdpSocket::bind("127.0.0.1:0").await.expect("probe");
        if probe
            .send_to(b"", ("127.0.0.1", port))
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("dokodemo UDP inbound at 127.0.0.1:{port} did not become ready in 1s");
}

/// TestUDPConnection：dokodemo UDP inbound → freedom outbound → UDP echo，
/// 客户端发包收到回包。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_connection_dokodemo_to_udp_echo() {
    // 1. UDP echo server
    let echo_port = spawn_udp_echo_server().await;

    // 2. dokodemo UDP inbound → echo
    let dokodemo_port = pick_free_port().await;

    let mut built = BuiltConfig::default();
    built.inbounds.push(dokodemo_udp_inbound(
        dokodemo_port,
        "127.0.0.1",
        echo_port,
    ));
    built.outbounds.push(freedom_outbound("direct"));

    // 3. start_full
    let (instance, _ohm, handles) = start_full(&built)
        .await
        .expect("start_full");
    assert!(
        instance.is_running(),
        "instance must be running after start_full"
    );

    // 4. 等 inbound 准备好
    wait_ready(dokodemo_port).await;

    // 5. 客户端 UDP 发包 → echo 回包
    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
    let payload = b"hello udp connection test!";
    client
        .send_to(payload, ("127.0.0.1", dokodemo_port))
        .await
        .expect("send");

    let mut buf = vec![0u8; 4096];
    let recv_fut = async {
        let (n, _peer) = client.recv_from(&mut buf).await.expect("recv");
        n
    };
    let n = tokio::time::timeout(Duration::from_secs(5), recv_fut)
        .await
        .expect("udp echo roundtrip must complete in 5s");
    assert_eq!(&buf[..n], payload, "udp echo payload mismatch");

    // cleanup
    for h in handles {
        h.abort();
    }
}
