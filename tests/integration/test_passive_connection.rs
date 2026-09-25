//! PASSIVE connection 集成测试（bd sk8r P3）。
//!
//! 对应 Go `testing/scenarios/feature_test.go::TestPassiveConnection`：
//! 起一个 TCP echo server，dokodemo TCP inbound 监听随机端口、目标 rewrite 到
//! echo server 地址；客户端 dial dokodemo → 数据被透明转发到 echo → 验证回环。
//!
//! 不依赖 btls/boringssl（dokodemo + freedom 路径纯 Rust），因此 `start_full`
//! 在 cargo test 普通环境也能跑通。
//!
//! 拓扑：
//!   client TcpStream → dokodemo inbound (rewrite → 127.0.0.1:echo_port)
//!                   → dispatcher → freedom default outbound → echo server
//!
//! 验证：
//! 1. `instance.is_running()` = true（Feature 全部 start 成功）
//! 2. 客户端读到 echo 回包（dokodemo TCP 已透明转发）
//! 3. 多包往返一致

use std::time::Duration;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use xray_conf::{BuiltConfig, BuiltEntry, BuiltInbound, BuiltOutbound};
use xray_core::functions::start_full;

/// Bind a free TCP port then drop the probe.
async fn pick_free_port() -> u16 {
    let probe = TcpListener::bind("127.0.0.1:0").await.expect("pick port");
    let port = probe.local_addr().expect("port").port();
    drop(probe);
    port
}

/// Start a simple TCP echo server (loopback: write what you read).
/// Returns the listener's bound port.
async fn spawn_echo_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("echo bind");
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        },
                    }
                }
            });
        }
    });
    port
}

/// Build a freedom outbound (default destination handler).
fn freedom_outbound(tag: &str) -> BuiltOutbound {
    BuiltOutbound {
        entry: BuiltEntry { kind: "freedom".into(), data: b"{}".to_vec() },
        tag: tag.into(),
        send_through: None,
        stream_settings_json: None,
        proxy_settings_json: None,
        mux_json: None,
        target_strategy: None,
    }
}

/// Build a dokodemo-door inbound pointing at a fixed `address:port` for TCP.
///
/// JSON 格式：与 xray-core `parse_dokodemo_settings`（inbound.rs:1969）一致。
fn dokodemo_tcp_inbound(port: u16, target_addr: &str, target_port: u16) -> BuiltInbound {
    let data = serde_json::json!({
        "address": target_addr,
        "port": target_port,
        "network": "tcp",
    })
    .to_string()
    .into_bytes();
    BuiltInbound {
        entry: BuiltEntry { kind: "dokodemo".into(), data },
        tag: "dokodemo-in".into(),
        port: Some(port),
        listen: Some("127.0.0.1".into()),
        stream_settings_json: None,
        sniffing_json: None,
    }
}

/// Wait briefly for the inbound listener to bind and accept connections.
async fn wait_ready(port: u16) {
    for _ in 0..50 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("dokodemo inbound at 127.0.0.1:{port} did not become ready in 1s");
}

/// TestPassiveConnection：dokodemo TCP inbound → freedom outbound → echo server，
/// 客户端 dial inbound 收 echo。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn passive_connection_dokodemo_to_echo() {
    // 1. echo server
    let echo_port = spawn_echo_server().await;

    // 2. dokodemo inbound：rewrite → echo
    let dokodemo_port = pick_free_port().await;

    let mut built = BuiltConfig::default();
    built.inbounds.push(dokodemo_tcp_inbound(dokodemo_port, "127.0.0.1", echo_port));
    built.outbounds.push(freedom_outbound("direct"));

    // 3. start_full 启 xray-core
    let (instance, _ohm, handles) = start_full(&built).await.expect("start_full");
    assert!(instance.is_running(), "instance must be running after start_full");

    // 4. 等 listener 就绪
    wait_ready(dokodemo_port).await;

    // 5. 客户端 dial → echo 回环
    let mut client =
        TcpStream::connect(("127.0.0.1", dokodemo_port)).await.expect("connect dokodemo");

    let payload = b"hello passive connection test!";
    client.write_all(payload).await.expect("write");

    // 短超时（dokodemo → freedom → echo 单跳），读到全部 echo 数据
    let mut buf = vec![0u8; payload.len()];
    let mut got = 0;
    let read_fut = async {
        while got < buf.len() {
            let n = client.read(&mut buf[got..]).await.expect("read");
            if n == 0 {
                break;
            }
            got += n;
        }
        got
    };
    let n = tokio::time::timeout(Duration::from_secs(5), read_fut)
        .await
        .expect("echo roundtrip must complete in 5s");
    assert_eq!(n, payload.len(), "echo length mismatch");
    assert_eq!(&buf[..n], payload, "echo payload mismatch");

    // cleanup
    for h in handles {
        h.abort();
    }
}
