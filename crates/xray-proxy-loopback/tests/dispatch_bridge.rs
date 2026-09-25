//! Loopback + dispatcher 桥接的 round-trip 端到端测试（bd m5nw）。
//!
//! 拓扑：
//! ```text
//! LoopbackHandler::dispatch(dest, link)
//!   ↓ (sink injected by test)
//! CaptureSink::dispatch_loopback → 完整回收 link 字节 + 验证 inbound_tag
//! ```
//!
//! 测试目标：loopback sink 注入（dispatcher 桥）建立后，端到端验证
//! `DispatchHandler::dispatch` 真实桥接到 `LoopbackSink::dispatch_loopback`，
//! 对应 Go `(*Loopback).Process(ctx, link, dispatcher)`。

#![cfg(test)]

use std::sync::Arc;

use xray_app_dispatcher::default::DispatchHandler;
use xray_buf::{
    io::{Reader, Writer},
    multi::MultiBuffer,
};
use xray_common::net::{
    address::Address as XrayAddress, destination::Destination, network::Network, port::Port,
};
use xray_proxy_loopback::{LoopbackFuture, LoopbackHandler, LoopbackSink};

fn dummy_dest() -> Destination {
    Destination::new(XrayAddress::Domain("loopback.test".into()), Port::new(0), Network::TCP)
}

/// 记录（inbound_tag, dest, payload）的 sink，调用方通过回调取出 link 后
/// 自行消费/写入以验证完整桥接路径。
/// 记录 (tag, dest, payload) 的共享日志类型。
type ReceivedLog = Arc<parking_lot::Mutex<Vec<(String, Destination, Vec<u8>)>>>;

#[derive(Debug, Clone)]
struct CaptureSink {
    received: ReceivedLog,
}

impl LoopbackSink for CaptureSink {
    fn dispatch_loopback(
        &self,
        inbound_tag: String,
        destination: Destination,
        _sniffing: xray_app_dispatcher::default::SniffingRequest,
        link: xray_transport::link::Link,
    ) -> LoopbackFuture<std::result::Result<(), xray_proxy_loopback::LoopbackError>> {
        let captured = Arc::clone(&self.received);
        let tag = inbound_tag.clone();
        let dest = destination.clone();
        Box::pin(async move {
            let mut link = link;
            // 阻塞读 link 字节并入栈 sink captured 列表
            let read = tokio::time::timeout(
                std::time::Duration::from_millis(500),
                link.reader.read_multi_buffer(),
            )
            .await
            .ok()
            .and_then(|r| r.ok())
            .map(|mb| mb.to_vec())
            .unwrap_or_default();
            captured.lock().push((tag, dest, read));
            link.writer.shutdown();
            Ok(())
        })
    }
}

#[tokio::test]
async fn loopback_dispatch_bridges_to_sink_with_link_roundtrip() {
    let sink = Arc::new(CaptureSink { received: Arc::new(parking_lot::Mutex::new(Vec::new())) });

    let handler =
        LoopbackHandler::with_inbound_tag("loopback-out", "target-in").with_sink(sink.clone());
    let link = {
        let (client_read, loopback_write) = xray_buf::pipe::new();
        let (loopback_read, mut client_write) = xray_buf::pipe::new();
        let _ = client_read;
        let payload = b"ping loopback";
        client_write
            .write_multi_buffer({
                let mut mb = MultiBuffer::new();
                mb.merge_bytes(payload);
                mb
            })
            .await
            .expect("client write to loopback");
        xray_transport::link::Link::new(Box::new(loopback_read), Box::new(loopback_write))
    };

    let dest = dummy_dest();
    handler.dispatch(&dest, link).await;

    // 等 sink callback 跑完
    tokio::time::sleep(std::time::Duration::from_millis(80)).await;

    let received = sink.received.lock().clone();
    assert_eq!(received.len(), 1, "sink must record exactly one dispatch");
    assert_eq!(received[0].0, "target-in");
    assert_eq!(received[0].1.port().value(), 0);
    assert_eq!(received[0].1.address(), &XrayAddress::Domain("loopback.test".into()));
    assert_eq!(received[0].2, b"ping loopback".to_vec());
}
