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

/// 满仓时的容量预约 future：**必须跨 poll 存活**（bd 34nk 同族——每次 poll 重建会
/// 在 Drop 时撤掉 waker 注册，满仓后容量释放无人唤醒 ⇒ 写半永久停摆）。
/// std Mutex 为满足 `ServerConn.writer` 的 `Sync` 箱子界（future 本身非 Sync）；
/// 单写者独占，锁无争用。
type ReserveOut =
    std::result::Result<OwnedPermit<io::Result<Frame<Bytes>>>, mpsc::error::SendError<()>>;
type ReserveFut = Pin<Box<dyn Future<Output = ReserveOut> + Send>>;

/// `ServerConn.writer` 的 mpsc 载体：dispatcher 侧 AsyncWrite → body 侧 `Frame::data`。
pub(crate) struct MpscDownlinkWriter {
    /// `None` = 已 shutdown（发送半关闭：rx 排空既有帧后 EOF）。
    tx: Option<mpsc::Sender<io::Result<Frame<Bytes>>>>,
    /// 在途容量预约（满仓时挂起等待，waker 注册于 mpsc；Ready 即取即还）。
    reserve: Option<std::sync::Mutex<ReserveFut>>,
}

impl MpscDownlinkWriter {
    pub(crate) fn new(tx: mpsc::Sender<io::Result<Frame<Bytes>>>) -> Self {
        Self { tx: Some(tx), reserve: None }
    }
}

impl AsyncWrite for MpscDownlinkWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let Some(tx) = this.tx.as_ref() else {
            return Poll::Ready(Err(downlink_closed()));
        };
        // 先确认容量再拷贝：满仓挂起等唤醒，不白拷（body 慢时零复制浪费）。
        loop {
            if this.reserve.is_some() {
                let polled = {
                    let mut locked =
                        this.reserve.as_ref().expect("reserve checked").lock().expect("poisoned");
                    locked.as_mut().poll(cx)
                };
                match polled {
                    Poll::Pending => return Poll::Pending,
                    // permit 即取即还：单发送者 ⇒ 释放的容量必被本写者 try_send 拿到。
                    Poll::Ready(Ok(_)) => {
                        this.reserve = None;
                        break;
                    },
                    Poll::Ready(Err(_)) => {
                        this.reserve = None;
                        return Poll::Ready(Err(downlink_closed()));
                    },
                }
            }
            if tx.capacity() > 0 {
                break;
            }
            let sender = tx.clone();
            this.reserve =
                Some(std::sync::Mutex::new(Box::pin(sender.reserve_owned()) as ReserveFut));
        }
        match tx.try_send(Ok(Frame::data(Bytes::copy_from_slice(buf)))) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            // 单发送者不变量：预约到的容量只会被本写者消费，Full 不应达。
            Err(TrySendError::Full(_)) => {
                Poll::Ready(Err(io::Error::other("downlink mpsc capacity lost after reserve")))
            },
            Err(TrySendError::Closed(_)) => Poll::Ready(Err(downlink_closed())),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // 每次写已直推队列，写者侧无缓冲可排。
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // 关发送半：drop Sender ⇒ rx 排空既有帧后 EOF（对齐 duplex 写半 shutdown 语义）。
        let this = self.get_mut();
        this.tx.take();
        this.reserve = None;
        Poll::Ready(Ok(()))
    }
}

/// 下行队列深度（条目 = 一次 `poll_write` 交付的聚合块，≤256KiB）：与桥条目闸
/// 同档（`PIPE_BUF_CAP=64`）。满仓 = hyper 消费不掉，背压传导回 dispatcher 写半。
pub(crate) const DOWNLINK_QUEUE_CAP: usize = 64;

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
