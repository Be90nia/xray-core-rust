//! 下行 body 直推：dispatcher 写半 → `mpsc<Bytes>` → hyper body `Frame::data`。
//!
//! C3（campaign-plan §4.5）删掉原 `tokio::io::duplex(64KiB)` 中转环：原形态每字节
//! 3 次拷贝（CoalescingWriter 聚合 + duplex 环 + `PoolStream` 池化读）+ 每 64KiB
//! 一次环翻转唤醒；现形态 AsyncWrite 适配器一次拷贝产 `Bytes`，`ReceiverStream`
//! 直接产帧，对齐 Go hub.go:427-436「1 写 + 1 Flush 无中转」的数据流形态。wire 上
//! 帧内容与顺序不变（h2 帧切分粒度随写粒度，Go 同样按 dispatcher 写边界切帧）。
//!
//! `PoolStream` 本体（池化读流）仍被 dialer 上行消费（`UPLINK_CHUNK`），共享件不动。
//!
//! 留主仓（方向件）：依赖 hyper `Frame` / `bytes::Bytes`，不上浮。

use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use hyper::body::Frame;
use tokio::{
    io::AsyncWrite,
    sync::mpsc::{self, OwnedPermit, error::TrySendError},
};

use crate::pool_stream::PoolStream;

/// body 半已 drop（GET 响应终结/取消）后的写错误。
fn downlink_closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "downlink body dropped")
}

#[cfg(test)]
mod tests {
    use futures_util::StreamExt;
    use tokio::io::AsyncWriteExt;
    use tokio_stream::wrappers::ReceiverStream;

    use super::*;

    #[tokio::test]
    async fn writes_reach_body_frames_in_order_and_shutdown_yields_eof() {
        let (tx, rx) = mpsc::channel::<io::Result<Frame<Bytes>>>(DOWNLINK_QUEUE_CAP);
        let mut writer = MpscDownlinkWriter::new(tx);
        let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        writer.write_all(&payload).await.expect("write must not fail");
        writer.shutdown().await.expect("shutdown must not fail");

        let mut got = Vec::new();
        let mut stream = ReceiverStream::new(rx);
        while let Some(item) = stream.next().await {
            got.extend_from_slice(item.expect("frames only").data_ref().expect("data frames"));
        }
        assert_eq!(got, payload, "bytes must be complete and in order");
    }

    /// 写入时 body 半已被 drop（模拟 hyper 取消 GET）：写必须报错（fail-visible），
    /// 不许静默吞字节（duplex 写半对已关读半同语义）。
    #[tokio::test]
    async fn write_after_body_drop_errors() {
        let (tx, rx) = mpsc::channel::<io::Result<Frame<Bytes>>>(DOWNLINK_QUEUE_CAP);
        let mut writer = MpscDownlinkWriter::new(tx);
        drop(rx);
        let err = writer.write_all(b"payload").await.expect_err("write to dropped body must fail");
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }

    /// 背压回归（rig probe 实锤 4.0MB 卡死 = 满仓 64 条 ×64KiB）：队列满后写挂起，
    /// body 消费一帧后必须继续——reserve future 跨 poll 存活（waker 不丢）的直接证据。
    /// 初版缺陷：每次 poll 重建 reserve future，Drop 撤掉 waker ⇒ 满仓后永久停摆。
    #[tokio::test]
    async fn write_backpressure_resumes_when_body_consumes() {
        let (tx, mut rx) = mpsc::channel::<io::Result<Frame<Bytes>>>(2);
        let mut writer = MpscDownlinkWriter::new(tx);

        writer.write_all(b"a").await.expect("第一块直接入队");
        writer.write_all(b"b").await.expect("第二块直接入队");

        // 第三块满仓挂起；消费 'a' 后必须被唤醒完成（waker 注册存活才会发生）。
        let third = tokio::spawn(async move {
            writer.write_all(b"c").await.expect("满仓写必须恢复完成")
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!third.is_finished(), "满仓后第三块必须挂起而非已完成/已失败");

        let first = rx.recv().await.expect("帧1");
        assert_eq!(first.expect("帧 io ok").into_data().expect("数据帧").as_ref(), b"a");

        tokio::time::timeout(std::time::Duration::from_secs(2), third)
            .await
            .expect("消费后第三块必须完成——初版缺陷此处超时（waker 丢失）")
            .expect("任务不 panic");
    }
}
