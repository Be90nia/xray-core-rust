//! issue #49 回归：UploadQueue push/close 竞态确定性测试。
//!
//! 硬不变量：**被 close 丢弃的包绝不能被 ack 成功**（push 返回 Ok ⇒ 包被保留）。
//! 全部用受控同步（手动 poll 驱动 / 顺序编排），无 timing sleep 交织。
//!
//! HTTP 面（packet-up 409 / stream-up 上浮）的确定性测试在
//! `src/hub/handler.rs` 的 `mod tests`（`HandlerContext` 含 `pub(crate)` 字段，
//! 外部集成测试无法构造）。

use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures_util::task::noop_waker;
use xray_transport_splithttp::{Packet, SplitHttpError, UploadQueue};

/// 手动 poll 一次（noop waker）。被测 future 的推进完全由测试的调用顺序控制。
fn poll_once<F: Future, P: std::ops::DerefMut<Target = F>>(fut: &mut Pin<P>) -> Poll<F::Output> {
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    fut.as_mut().poll(&mut cx)
}

/// #49 场景 5：已完成的 close 之后 push 必须返回 `QueueClosed`。
#[tokio::test]
async fn push_after_completed_close_returns_queue_closed() {
    let q = UploadQueue::new(8);
    q.close().await;
    let err = q.push(Packet::new(Bytes::from_static(b"x"), 0)).await.unwrap_err();
    assert!(matches!(err, SplitHttpError::QueueClosed));
}

/// #49 场景 1+2：close 在并发 send 完成前 drain——被 close 丢弃的包必须报错，
/// 绝不 ack 成功；drain 到的缓冲包必须全部保留。
///
/// 确定性构造：先填满 channel（cap 64，`UploadQueue::new` 硬编码），第 65 个
/// push 手动 poll 驱动到 Pending（挂起在 send 上，waker 已注册）；随后完整跑完
/// close（drain 64 缓冲包 → 置位 closed → drop receiver）。racing push 复查时
/// receiver 已消失：包从未进入缓冲（tokio 把包原样退还调用方）→ 必须
/// `QueueClosed`。
#[tokio::test]
async fn close_drains_buffered_packets_and_rejects_suspended_push() {
    let q = Arc::new(UploadQueue::new(64));
    // upload_queue.rs `mpsc::channel(64)`（new() 硬编码；改容量时本测试的
    // 「Pending 断言」会先红，即维护信号）。
    const CHANNEL_CAP: u64 = 64;
    for i in 0..CHANNEL_CAP {
        q.push(Packet::new(vec![i as u8], i)).await.unwrap();
    }

    // 第 CAP+1 个 push：channel 满 → 挂起（确定性验证挂起点）
    let mut racing = Box::pin(q.push(Packet::new(vec![0xEE], CHANNEL_CAP)));
    assert!(
        matches!(poll_once(&mut racing), Poll::Pending),
        "channel 满时 push 必须挂起在 send 上"
    );

    // close：drain 全部缓冲包（保留进堆）→ closed=true → drop receiver
    q.close().await;

    // racing push 恢复：包被退还调用方（从未保留）→ 必须报 QueueClosed
    match poll_once(&mut racing) {
        Poll::Ready(Err(SplitHttpError::QueueClosed)) => {},
        other => panic!("close 后挂起的 push 必须报 QueueClosed，got {other:?}"),
    }

    // drain 的 64 个包全部保留、按 seq 有序可读
    let mut buf = [0u8; 4];
    for i in 0..CHANNEL_CAP {
        let n = q.read(&mut buf).await.unwrap();
        assert_eq!(n, 1);
        assert_eq!(buf[0], i as u8);
    }
    // 排空后 EOF；被丢弃的 racing 包绝不出现在读侧
    assert_eq!(q.read(&mut buf).await.unwrap(), 0);
}

/// 线性化支持面：push 成功返回 ⇒ 包被保留（close 后完整读出）。
#[tokio::test]
async fn successful_push_implies_packet_retained_through_close() {
    let q = UploadQueue::new(8);
    for i in 0..3u64 {
        q.push(Packet::new(vec![0xA0 + i as u8], i)).await.unwrap();
    }
    q.close().await;
    let mut buf = [0u8; 4];
    for i in 0..3u64 {
        let n = q.read(&mut buf).await.unwrap();
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0xA0 + i as u8);
    }
    assert_eq!(q.read(&mut buf).await.unwrap(), 0);
}

/// 乱序到达的包同样受「成功 ⇒ 保留」保护（close drain 走堆路径）。
#[tokio::test]
async fn out_of_order_packets_retained_through_close() {
    let q = UploadQueue::new(8);
    q.push(Packet::new(Bytes::from_static(b"second"), 1)).await.unwrap();
    q.push(Packet::new(Bytes::from_static(b"first"), 0)).await.unwrap();
    q.close().await;
    let mut buf = [0u8; 8];
    let n = q.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"first");
    let n = q.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"second");
    assert_eq!(q.read(&mut buf).await.unwrap(), 0);
}

/// 重复 close 幂等且无害；close 后 push 恒拒；首个包仍保留。
#[tokio::test]
async fn double_close_is_idempotent_and_push_still_rejected() {
    let q = UploadQueue::new(8);
    q.push(Packet::new(Bytes::from_static(b"a"), 0)).await.unwrap();
    q.close().await;
    q.close().await;
    assert!(matches!(
        q.push(Packet::new(Bytes::from_static(b"b"), 1)).await,
        Err(SplitHttpError::QueueClosed)
    ));
    let mut buf = [0u8; 2];
    assert_eq!(q.read(&mut buf).await.unwrap(), 1);
    assert_eq!(q.read(&mut buf).await.unwrap(), 0);
}
