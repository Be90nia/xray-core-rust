//! Integration tests for `register_dialer` + end-to-end ws dial through `dial_with_settings`.
//!
//! 覆盖：
//! 1. `register_dialer()` 后 `get_transport_dialer("ws")` / `"websocket"` 都返回 Some。
//! 2. 重复 `register_dialer()` 不报错（幂等）。
//! 3. e2e：本地起 tokio-tungstenite accept_async server → register →
//!    `dial_with_settings("ws", dest, sockopt, settings)` 能拨上、能收发字节。

use std::net::Ipv4Addr;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

use xray_common::net::address::Address;
use xray_common::net::destination::Destination;
use xray_common::net::network::Network;
use xray_common::net::port::Port;
use xray_transport::dialer::{StreamSettings, dial_with_settings, get_transport_dialer};
use xray_transport::sockopt::SocketOptions;
use xray_transport_websocket::register_dialer;

/// `register_dialer()` 后两个协议名都应能在全局表查到。
#[test]
fn register_dialer_makes_ws_and_websocket_resolvable() {
    register_dialer().expect("register_dialer should succeed");
    assert!(get_transport_dialer("ws").is_some(), "ws dialer should be registered");
    assert!(
        get_transport_dialer("websocket").is_some(),
        "websocket dialer should be registered"
    );
}

/// 重复 `register_dialer()` 不应 panic 或返回 Err。
#[test]
fn register_dialer_is_idempotent() {
    register_dialer().unwrap();
    register_dialer().unwrap();
    register_dialer().unwrap();
}

/// e2e：本地 ws echo server → 客户端通过 `dial_with_settings` 拨号 → 收发验证。
#[tokio::test]
async fn e2e_dial_with_settings_ws_roundtrip() {
    register_dialer().unwrap();

    // 1. 起 TCP listener + ws echo server。
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
        // echo loop：收到 Binary 就回写。
        while let Some(Ok(msg)) = ws.next().await {
            match msg {
                Message::Binary(b) => {
                    let b: Vec<u8> = b.into();
                    if ws.send(Message::binary(b)).await.is_err() {
                        break;
                    }
                }
                Message::Close(_) | Message::Ping(_) | Message::Pong(_) => break,
                _ => {}
            }
        }
    });

    // 2. 构造 StreamSettings：protocol=ws，无 TLS，无 wsSettings（用默认）。
    let dest = Destination::new(
        Address::IPv4(Ipv4Addr::LOCALHOST),
        Port::new(addr.port()),
        Network::TCP,
    );
    let settings = StreamSettings {
        protocol: "ws".into(),
        ..StreamSettings::tcp()
    };
    let sockopt = SocketOptions::default();

    // 3. 拨号。
    let mut conn = tokio::time::timeout(
        Duration::from_secs(5),
        dial_with_settings("ws", &dest, &sockopt, &settings),
    )
    .await
    .expect("dial should not time out")
    .expect("dial should succeed");

    // 4. 写 + 读 echo。
    conn.write_all(b"hello-ws").await.unwrap();
    conn.flush().await.unwrap();
    let mut buf = [0u8; 8];
    let n = tokio::time::timeout(Duration::from_secs(5), conn.read(&mut buf))
        .await
        .expect("read should not time out")
        .expect("read should succeed");
    assert_eq!(&buf[..n], b"hello-ws");

    // 让 server 任务自然结束。
    drop(conn);
    let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
}

/// `dial_with_settings` 用别名 `"websocket"` 也能拨通（与 `"ws"` 等价）。
#[tokio::test]
async fn e2e_alias_websocket_protocol_dials() {
    register_dialer().unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let _ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
        // 接受即关闭——只验证握手成功。
    });

    let dest = Destination::new(
        Address::IPv4(Ipv4Addr::LOCALHOST),
        Port::new(addr.port()),
        Network::TCP,
    );
    let settings = StreamSettings {
        protocol: "websocket".into(),
        ..StreamSettings::tcp()
    };
    let sockopt = SocketOptions::default();

    let result = tokio::time::timeout(
        Duration::from_secs(5),
        dial_with_settings("websocket", &dest, &sockopt, &settings),
    )
    .await
    .expect("dial should not time out");
    assert!(
        result.is_ok(),
        "dial via alias websocket should succeed: {:?}",
        result.err()
    );

    let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
}
