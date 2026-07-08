//! SplitHTTP upload_queue——分包按 seq 重组为有序字节流。
//!
//! 对应 Go `transport/internet/splithttp/upload_queue.go`。
//!
//! ## 协议层定位
//!
//! SplitHTTP 客户端把上行字节流切片为多个 HTTP POST，每个 POST 携带一个
//! `seq` 编号。服务端收到分包后必须按 seq 顺序交付给上层 proxy handler，
//! 但 HTTP/2 stream 之间不保证到达顺序——upload_queue 是接收侧的 reorder
//! 缓冲区，把乱序 packet 按顺序重组为 `Read` 输出。
//!
//! ## Ponytail 决策
//!
//! 完整 SplitHTTP 还涉及 HTTP server + dialer + xmux + XPadding，依赖
//! hyper/h2 重型栈（>2000 行工程量）。本切片只交付协议层最独立的核心——
//! upload_queue reorder，不依赖任何 HTTP 实现，纯 tokio mpsc + BinaryHeap。
//!
//! 简化点：Packet 不含 `Reader: io.ReadCloser` 字段（Go 端是流式优化路径），
//! 只保留 Payload + Seq。Reader 流式优化留 follow-up（依赖 xray_buf::Reader
//! trait 适配）。

use std::cmp::Reverse;
use std::collections::BinaryHeap;

use tokio::sync::{mpsc, Mutex, Notify};

use crate::error::{Result, SplitHttpError};

/// 单个上传分包。对应 Go `upload_queue.Packet`。
#[derive(Debug, Clone)]
pub struct Packet {
    /// 分包字节载荷。
    pub payload: Vec<u8>,
    /// 分包序号（从 0 开始严格递增）。
    pub seq: u64,
}

impl Packet {
    /// 构造新 Packet。
    #[must_use]
    pub fn new(payload: Vec<u8>, seq: u64) -> Self {
        Self { payload, seq }
    }
}

/// BinaryHeap 元素包装：按 seq 升序（heap 默认是 max-heap，用 Reverse 转为 min-heap）。
#[derive(Debug)]
struct BySeq(Reverse<u64>, Packet);

impl PartialEq for BySeq {
    fn eq(&self, other: &Self) -> bool {
        self.0 .0 == other.0 .0
    }
}
impl Eq for BySeq {}
impl PartialOrd for BySeq {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for BySeq {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Reverse<u64> 自身就有 reverse 比较，BinaryHeap 取 max 即等价于 seq 升序出队
        self.0.cmp(&other.0)
    }
}

/// 接收侧 reorder 状态（受 Mutex 保护）。
struct Inner {
    /// 待消费的已排序 packet 堆（min-heap by seq）。
    heap: BinaryHeap<BySeq>,
    /// push 端 channel receiver（push 完所有 packet 后 close）。
    pushed: Option<mpsc::Receiver<Packet>>,
    /// 期望的下一个 seq。
    next_seq: u64,
    /// 当前正在 partial read 的 packet（已取部分字节，余下保留）。
    current: Option<Packet>,
    /// 是否已 Close。
    closed: bool,
    /// reorder 缓冲上限（防恶意客户端耗尽内存）。
    max_packets: usize,
}

/// SplitHTTP 接收侧 reorder 队列。对应 Go `uploadQueue`。
pub struct UploadQueue {
    inner: Mutex<Inner>,
    push_tx: mpsc::Sender<Packet>,
    notify: Notify,
}

impl UploadQueue {
    /// 构造新的 reorder 队列。
    ///
    /// `max_packets` 是 reorder 缓冲上限。当乱序 packet 累计超过此值时
    /// `read` 返回 `PacketQueueTooLarge` 错误（对齐 Go 行为：tear down）。
    #[must_use]
    pub fn new(max_packets: usize) -> Self {
        // ponytail: channel buffer 独立于 max_packets（max_packets 是 heap 上限）
        let (tx, rx) = mpsc::channel(64);
        Self {
            inner: Mutex::new(Inner {
                heap: BinaryHeap::new(),
                pushed: Some(rx),
                next_seq: 0,
                current: None,
                closed: false,
                max_packets,
            }),
            push_tx: tx,
            notify: Notify::new(),
        }
    }

    /// 推送一个分包（HTTP server 收到 POST 后调用）。
    ///
    /// # Errors
    /// - [`SplitHttpError::QueueClosed`]：队列已关闭（push 在 close 后调用）
    pub async fn push(&self, packet: Packet) -> Result<()> {
        self.push_tx
            .send(packet)
            .await
            .map_err(|_| SplitHttpError::QueueClosed)?;
        self.notify.notify_one();
        Ok(())
    }

    /// 关闭 push 端（不再接受新分包）。后续 `read` 在缓冲耗尽后返回 EOF。
    pub async fn close(&self) {
        let mut inner = self.inner.lock().await;
        // 先把 channel 里已 push 的 packet drain 出来（避免与 inner.heap 同时 borrow）
        let mut drained: Vec<Packet> = Vec::new();
        if let Some(rx) = inner.pushed.as_mut() {
            while let Ok(packet) = rx.try_recv() {
                drained.push(packet);
            }
        }
        for packet in drained {
            if packet.seq == inner.next_seq && inner.current.is_none() {
                inner.current = Some(packet);
            } else {
                inner.heap.push(BySeq(Reverse(packet.seq), packet));
            }
        }
        inner.closed = true;
        inner.pushed = None;
        drop(inner);
        self.notify.notify_one();
    }

    /// 读取已重组的字节流。对应 Go `uploadQueue.Read`。
    ///
    /// - 顺序到达：直接返回 nextSeq 对应 packet 的 payload
    /// - 乱序到达：缓冲到 heap 直到 nextSeq 到来，超过 maxPackets 报错
    /// - partial read：payload 比 buf 大时分多次返回
    ///
    /// # Errors
    /// - [`SplitHttpError::PacketQueueTooLarge`]：乱序 packet 累计超过 max_packets
    pub async fn read(&self, dst: &mut [u8]) -> Result<usize> {
        loop {
            // 1. 优先消费 current（partial read）
            {
                let mut inner = self.inner.lock().await;
                if let Some(packet) = inner.current.take() {
                    let n = std::cmp::min(dst.len(), packet.payload.len());
                    dst[..n].copy_from_slice(&packet.payload[..n]);
                    if n < packet.payload.len() {
                        // 余下保留为 current，下次继续读
                        let mut rest = packet;
                        rest.payload = rest.payload[n..].to_vec();
                        inner.current = Some(rest);
                    } else {
                        // 完整消费，nextSeq++
                        inner.next_seq += 1;
                    }
                    return Ok(n);
                }
            }

            // 2. 检查 heap 中是否已有 nextSeq
            {
                let mut inner = self.inner.lock().await;
                if let Some(by_seq) = inner.heap.peek() {
                    if by_seq.0 .0 == inner.next_seq {
                        // 命中 nextSeq，pop 出来
                        let packet = inner.heap.pop().unwrap().1;
                        drop(inner);
                        {
                            let mut inner = self.inner.lock().await;
                            inner.current = Some(packet);
                        }
                        continue;
                    }
                    if inner.heap.len() > inner.max_packets {
                        return Err(SplitHttpError::PacketQueueTooLarge {
                            max: inner.max_packets,
                            current: inner.heap.len(),
                        });
                    }
                }
                // heap 中没 nextSeq，需要从 channel 拉新 packet
            }

            // 3. 从 channel 拉新 packet
            {
                let mut inner = self.inner.lock().await;
                let closed = inner.closed;
                let receiver_opt = inner.pushed.as_mut();
                match receiver_opt {
                    None => {
                        // 已 close：heap 没匹配 packet → gap（客户端漏发）返 EOF
                        return Ok(0);
                    }
                    Some(rx) => {
                        // 持锁 await 会有死锁风险，先 try_recv 非阻塞
                        match rx.try_recv() {
                            Ok(packet) => {
                                if packet.seq == inner.next_seq {
                                    inner.current = Some(packet);
                                } else {
                                    inner.heap.push(BySeq(Reverse(packet.seq), packet));
                                    if inner.heap.len() > inner.max_packets {
                                        return Err(SplitHttpError::PacketQueueTooLarge {
                                            max: inner.max_packets,
                                            current: inner.heap.len(),
                                        });
                                    }
                                }
                                drop(inner);
                                continue;
                            }
                            Err(mpsc::error::TryRecvError::Empty) => {
                                if closed {
                                    drop(inner);
                                    continue;
                                }
                                drop(inner);
                                self.notify.notified().await;
                                continue;
                            }
                            Err(mpsc::error::TryRecvError::Disconnected) => {
                                inner.pushed = None;
                                drop(inner);
                                continue;
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn read_returns_payload_in_order() {
        let q = UploadQueue::new(10);
        q.push(Packet::new(b"hello".to_vec(), 0)).await.unwrap();
        let mut buf = [0u8; 32];
        let n = q.read(&mut buf).await.unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf[..n], b"hello");
    }

    #[tokio::test]
    async fn read_zero_byte_payload_returns_one() {
        // Go Test_regression_readzero：seq=0 + payload "x"，buf=20B → n=1
        let q = UploadQueue::new(10);
        q.push(Packet::new(b"x".to_vec(), 0)).await.unwrap();
        let mut buf = [0u8; 20];
        let n = q.read(&mut buf).await.unwrap();
        assert_eq!(n, 1);
    }

    #[tokio::test]
    async fn read_handles_out_of_order_arrival() {
        let q = UploadQueue::new(10);
        q.push(Packet::new(b"second".to_vec(), 1)).await.unwrap();
        q.push(Packet::new(b"first".to_vec(), 0)).await.unwrap();

        let mut buf = [0u8; 32];
        let n = q.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"first");
        let n = q.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"second");
    }

    #[tokio::test]
    async fn read_partial_returns_remaining_next_call() {
        let q = UploadQueue::new(10);
        q.push(Packet::new(b"hello world".to_vec(), 0)).await.unwrap();
        let mut small = [0u8; 5];
        let n1 = q.read(&mut small).await.unwrap();
        assert_eq!(n1, 5);
        assert_eq!(&small, b"hello");

        let mut rest = [0u8; 32];
        let n2 = q.read(&mut rest).await.unwrap();
        assert_eq!(n2, 6);
        assert_eq!(&rest[..n2], b" world");
    }

    #[tokio::test]
    async fn read_multiple_packets_in_order() {
        let q = UploadQueue::new(20);
        for i in 0..5 {
            q.push(Packet::new(vec![i as u8; 3], i)).await.unwrap();
        }
        let mut buf = [0u8; 32];
        for i in 0..5u8 {
            let n = q.read(&mut buf).await.unwrap();
            assert_eq!(n, 3);
            assert_eq!(&buf[..n], &[i, i, i]);
        }
    }

    #[tokio::test]
    async fn read_eof_after_close_and_drained() {
        let q = UploadQueue::new(10);
        q.push(Packet::new(b"abc".to_vec(), 0)).await.unwrap();
        q.close().await;

        let mut buf = [0u8; 32];
        let n = q.read(&mut buf).await.unwrap();
        assert_eq!(n, 3);
        // 再读 → EOF
        let n = q.read(&mut buf).await.unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn read_too_large_heap_errors() {
        // max_packets=2，乱序 push 5 个，触发 PacketQueueTooLarge
        let q = UploadQueue::new(2);
        for seq in 1..=4 {
            q.push(Packet::new(vec![seq as u8], seq)).await.unwrap();
        }
        let mut buf = [0u8; 32];
        let err = q.read(&mut buf).await.unwrap_err();
        match err {
            SplitHttpError::PacketQueueTooLarge { max, current } => {
                assert_eq!(max, 2);
                assert!(current > 2);
            }
            other => panic!("expected PacketQueueTooLarge, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn push_after_close_errors() {
        let q = UploadQueue::new(10);
        q.close().await;
        let err = q.push(Packet::new(vec![1], 0)).await.unwrap_err();
        assert!(matches!(err, SplitHttpError::QueueClosed));
    }

    #[tokio::test]
    async fn interleaved_push_and_read() {
        // 模拟真实场景：read 在 push 前 await，被 notify 唤醒
        let q = std::sync::Arc::new(UploadQueue::new(20));

        let q2 = std::sync::Arc::clone(&q);
        let reader = tokio::spawn(async move {
            let mut out = Vec::new();
            let mut buf = [0u8; 8];
            loop {
                let n = q2.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                out.extend_from_slice(&buf[..n]);
            }
            out
        });

        // 顺序 push 10 个 packet
        for i in 0..10u64 {
            q.push(Packet::new(vec![i as u8; 2], i)).await.unwrap();
        }
        q.close().await;

        let result = reader.await.unwrap();
        assert_eq!(result.len(), 20);
        for (i, &byte) in result.iter().enumerate() {
            assert_eq!(byte, (i / 2) as u8);
        }
    }
}
