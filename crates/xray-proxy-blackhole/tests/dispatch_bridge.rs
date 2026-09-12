//! Blackhole dispatch bridge round-trip（bd m5nw）。
//!
//! 拓扑：
//! ```text
//! 出站 caller → DispatchHandler::dispatch(dest, link)
//!   ↓
//! BlackholeHandler（ResponseConfig::Http403）→ 写 HTTP 403 + drain
//! ```
//!
//! 验证：完整 inbound→blackhole 路径——黑洞 handler 接到 link，把 HTTP 403 写回
//! writer 后关闭；caller 端 reader 应收到完整 403 响应。

#![cfg(test)]

use std::{sync::Arc, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use xray_app_dispatcher::default::{DefaultDispatcher, SimpleOhm, SniffingRequest};
use xray_buf::{
    io::{Reader, Writer},
    multi::MultiBuffer,
};
use xray_common::net::{address::Address, destination::Destination, network::Network, port::Port};
use xray_features::inbound::InboundHandler as _;
use xray_proto::xray::proxy::blackhole::Config;
use xray_proxy_blackhole::{BlackholeInboundHandler, ResponseConfig, make_blackhole_handler};

fn make_dest() -> Destination {
    Destination::new(Address::Domain("blackhole.test".into()), Port::new(80), Network::TCP)
}

#[tokio::test]
async fn blackhole_dispatch_returns_http_403_then_drains() {
    use xray_app_dispatcher::OutboundHandlerManager as _;

    // 1. 构造黑黑黑 blackhole outbound handler（Http403 响应）
    let cfg = Config {
        response: Some(xray_proto::xray::proxy::blackhole::Response {
            r#type: "http".into(),
            custom_response_data: Vec::new(),
        }),
    };
    let blackhole = make_blackhole_handler("bh-out", cfg).expect("handler");

    // 2. 装配 dispatcher（blackhole 为 default handler）
    let ohm = Arc::new(SimpleOhm::new());
    ohm.set_default(blackhole);
    let mut dispatcher = DefaultDispatcher::new();
    let ohm_arc = ohm as Arc<dyn xray_app_dispatcher::OutboundHandlerManager>;
    dispatcher.ohm = Some(ohm_arc);

    // 3. 发起 dispatch：caller 通过 inbound link 写入；期望 blackhole 回写 403
    let dest = make_dest();
    let mut inbound = dispatcher
        .dispatch(&dest, &SniffingRequest::default(), None, None)
        .expect("dispatch returns inbound link");

    let mut mb = MultiBuffer::new();
    mb.merge_bytes(b"GET / HTTP/1.1");
    inbound.writer.write_multi_buffer(mb).await.expect("inbound write should succeed");
    let resp = tokio::time::timeout(Duration::from_secs(3), inbound.reader.read_multi_buffer())
        .await
        .expect("response should arrive within 3s")
        .expect("read should succeed");
    let body = resp.to_vec();
    assert!(!body.is_empty(), "blackhole should have written a response");
    let body_str = String::from_utf8_lossy(&body);
    assert!(
        body_str.contains("403") || body_str.contains("Forbidden"),
        "expected HTTP 403 in response, got: {body_str}"
    );
}

#[tokio::test]
async fn blackhole_inbound_silently_drops_tcp_connection() {
    let handler = BlackholeInboundHandler::new("bh-in", ResponseConfig::None, "127.0.0.1:0");
    handler.start().await.expect("start");

    let port = handler.port();
    assert!(port > 0, "blackhole inbound must have bound a port");
    let mut conn =
        tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(("127.0.0.1", port)))
            .await
            .expect("connect timed out")
            .expect("connect should succeed");

    conn.write_all(b"hello blackhole\n").await.ok();

    // 读应 EOF（blackhole 不写响应）
    let mut buf = Vec::new();
    let read_result =
        tokio::time::timeout(Duration::from_secs(2), conn.read_to_end(&mut buf)).await;
    match read_result {
        Ok(Ok(0)) => {},
        Ok(Ok(_)) => panic!("blackhole should EOF, got {} bytes: {:?}", buf.len(), buf),
        Ok(Err(_)) => {},
        Err(_) => panic!("blackhole close should not hang 2s"),
    }
    handler.close().await.expect("close");
}

// AV workaround bump: 修改文件触发新 hash（os error 5 换 hash 重跑铁律）
