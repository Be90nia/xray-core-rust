//! Freedom outbound → DialBridge 适配器（阶段 1 切片 1e）。
//!
//! Freedom 是直连代理——直接拨号到目标，无中间服务器。所以 DialFn 闭包不需要
//! 捕获任何 client 配置，直接调 [`dial_system`] 返回 [`Connection`]。
//!
//! `dial_system` 已返回 `Box<dyn Connection>`，无需 wrapper。
//!
//! [`DialBridge`]: xray_app_dispatcher::default::DialBridge
//! [`DialFn`]: xray_app_dispatcher::default::DialFn
//! [`Connection`]: xray_transport::connection::Connection

use std::sync::Arc;

use xray_app_dispatcher::default::DialFn;
use xray_common::net::destination::Destination;
use xray_transport::connection::Connection;
use xray_transport::sockopt::SocketOptions;
use xray_transport::system_dialer::dial_system;

/// 构造 Freedom 的 DialFn 闭包。
///
/// 闭包无状态——每次调用直接 `dial_system(dest)`。Domain 目标在 dial_system
/// 内部返回 `InvalidInput` 错误（DNS 解析留 transport 切片2）。
///
/// # Panics
///
/// 不会 panic；错误以 `Err(String)` 返回。
pub fn make_dial_fn() -> DialFn {
    Arc::new(|dest: &Destination| {
        // dial_system 接收 &Destination，无需 clone——内部不持有引用跨 await
        // 但 DialFn 要求 'static future，故 dest 必须 clone 进闭包
        let dest = dest.clone();
        Box::pin(async move {
            let sockopt = SocketOptions::default();
            let conn: Box<dyn Connection> = dial_system(&dest, &sockopt)
                .await
                .map_err(|e| format!("freedom dial: {e}"))?;
            Ok(conn)
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use xray_app_dispatcher::default::{DefaultDispatcher, DialBridge, SimpleOhm, SniffingRequest};
    use xray_buf::io::{Reader, Writer};
    use xray_buf::multi::MultiBuffer;
    use xray_common::net::address::Address;
    use xray_common::net::network::Network;
    use xray_common::net::port::Port;

    #[tokio::test]
    async fn dispatcher_e2e_freedom_to_echo() {
        // echo server
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if sock.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });

        // dispatcher + DialBridge(freedom)
        let ohm = SimpleOhm::new();
        ohm.set_default(Arc::new(DialBridge::new("freedom-out", make_dial_fn())));
        let mut dispatcher = DefaultDispatcher::new();
        dispatcher.ohm = Some(Arc::new(ohm));

        let dest = Destination::new(
            Address::from_ipv4_bytes([127, 0, 0, 1]),
            Port::new(echo_addr.port()),
            Network::TCP,
        );
        let inbound = dispatcher
            .dispatch(&dest, &SniffingRequest::default(), None, None)
            .expect("dispatch returns inbound Link");

        let mut w = inbound.writer;
        let mut r = inbound.reader;

        let payload = b"hello freedom via dispatcher";
        let mut mb = MultiBuffer::new();
        mb.merge_bytes(payload);
        w.write_multi_buffer(mb).await.unwrap();

        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            r.read_multi_buffer(),
        )
        .await
        .expect("timeout")
        .unwrap();

        assert_eq!(resp.to_vec(), payload);
        w.shutdown();
    }
}
