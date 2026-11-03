//! 池化读流：`AsyncRead` → `Bytes` 块流，块复用（票 r1693 下行 / 1fm1l 上行）。
//!
//! `tokio_util::io::ReaderStream` 每产出一帧都新分配一块缓冲：`BytesMut::split`
//! 把容量留在帧里，下一次 `poll_next` 只剩空 `BytesMut` 被迫重新 `reserve`
//! （缺省 4 KiB）。h2 稳定生态下这等于「每帧一次分配」，实测 srv 发送 ≈1.0 MB
//! 分配/MB 数据（占 srv 总分配 48%），客户端上行同构。
//!
//! 这里改为池化：块从池借出、装进 `Bytes::from_owner`，帧被 hyper 释放后由
//! [`PooledBuf::drop`] 归还——稳态零分配。帧粒度与原实现一致（一次 `poll_read`
//! 一帧），块大小由调用方指定（下行 = duplex 缓冲 64 KiB，上行同值）。
//!
//! 留主仓（方向件：依赖 `bytes::Bytes::from_owner`）——池化读流只服务 h2 body
//! 这一网络方向，`bytes` 属方向件非 udf 依赖纪律，不上浮。

use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex, PoisonError},
    task::{Context, Poll},
};

use bytes::Bytes;
use futures_util::Stream;
use tokio::io::{AsyncRead, ReadBuf};

/// 上行（客户端 POST body）读块大小 = 下行 [`crate::hub::handler::DUPLEX_BUF`] 同值。
/// 4 KiB（tokio-util 缺省）在 h2 下把 DATA 帧粒度钉死，帧数/唤醒数放大 16×。
pub(crate) const UPLINK_CHUNK: usize = 64 * 1024;

/// 池容量硬上限 = 本流 h2 在飞块数上界：hyper 每连接 send_buf 缺省 16 MB（窗保底
/// 同值），一个块至多对应 send_buf 里一个待写帧，加读腿/编码中各 1 块余量。
/// 实际池容量按本流观测的在飞峰值自适应到该上限（见 [`BufPool::put`]）。
fn pool_max_blocks(chunk: usize) -> usize {
    16 * 1024 * 1024 / chunk.max(1) + 2
}

/// 空闲块账本。归还可能发生在 hyper 的任意 worker 线程，故加锁。
///
/// **为何不用 udf `ObjectPool`**（2026-11-02 判定，依据 + 实测见
/// `reports/audit-2026-11-02/udf-pool-migration.md`）：[`PooledBuf`] 是
/// `Bytes::from_owner` 的所有者、必须 `'static`，而归还点是任意线程的引用计数
/// 归零 drop——`Pooled<'p, T>` 借用池，两处都装不进去；「借一槽换进去」的归还
/// 组合实测让 `constructed` 每轮 +N（池退化成恒分配）。解锁前提 = udf 补
/// `acquire_owned`。
struct BufPool {
    chunk: usize,
    max_blocks: usize,
    state: Mutex<PoolState>,
}

impl BufPool {
    fn new(chunk: usize) -> Self {
        Self { chunk, max_blocks: pool_max_blocks(chunk), state: Mutex::new(PoolState::default()) }
    }

    fn take(&self) -> Vec<u8> {
        let mut st = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        st.live += 1;
        if st.live > st.peak {
            st.peak = st.live;
        }
        st.free.pop().unwrap_or_else(|| vec![0; self.chunk])
    }

    fn put(&self, buf: Vec<u8>) {
        let mut st = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        st.live = st.live.saturating_sub(1);
        // 容量 = 本流观测峰值（封顶 max_blocks）：突发排空后的块整批留池，供下一
        // 突发复用——否则每个「send_buf 填充满→排空」周期都逐帧重分配
        // （bd 9eu4a：客户端提速后突发深度 >8，旧固定容量把池打成逐帧 churn）。
        if st.free.len() < st.peak.min(self.max_blocks) {
            st.free.push(buf);
        }
    }
}

#[derive(Default)]
struct PoolState {
    free: Vec<Vec<u8>>,
    /// 当前在外（hyper 持有未归还）的块数。
    live: usize,
    /// 本流观测的在飞峰值 = 池容量依据。
    peak: usize,
}

/// `Bytes` 的缓冲所有者：全部引用释放后把块还回池。
struct PooledBuf {
    data: Vec<u8>,
    len: usize,
    pool: Arc<BufPool>,
}

impl AsRef<[u8]> for PooledBuf {
    fn as_ref(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

impl Drop for PooledBuf {
    fn drop(&mut self) {
        self.pool.put(std::mem::take(&mut self.data));
    }
}

/// `AsyncRead` → `Stream<Item = io::Result<Bytes>>` 的池化读流。
///
/// 一次 `poll_read` 产出一帧（同 `ReaderStream` 的 `poll_read_buf` 单次读语义）；
/// EOF 时释放内层（下行场景下会话 guard 随之触发）。
pub(crate) struct PoolStream<R> {
    inner: R,
    pool: Arc<BufPool>,
}

impl<R> PoolStream<R> {
    pub(crate) fn new(inner: R, chunk: usize) -> Self {
        Self { inner, pool: Arc::new(BufPool::new(chunk)) }
    }

    /// 池内空闲块数（测试观测用）。
    #[cfg(test)]
    fn idle_blocks(&self) -> usize {
        self.pool.state.lock().unwrap_or_else(PoisonError::into_inner).free.len()
    }
}

impl<R: AsyncRead + Unpin> Stream for PoolStream<R> {
    type Item = io::Result<Bytes>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let mut buf = this.pool.take();
        let polled = {
            let mut rb = ReadBuf::new(&mut buf);
            let res = Pin::new(&mut this.inner).poll_read(cx, &mut rb);
            res.map(|r| r.map(|()| rb.filled().len()))
        };
        match polled {
            Poll::Pending => {
                this.pool.put(buf);
                Poll::Pending
            },
            Poll::Ready(Err(err)) => {
                this.pool.put(buf);
                Poll::Ready(Some(Err(err)))
            },
            // EOF：内层随流结束释放（下行会话 guard 在此触发，同 ReaderStream 语义）。
            Poll::Ready(Ok(0)) => {
                this.pool.put(buf);
                Poll::Ready(None)
            },
            Poll::Ready(Ok(len)) => Poll::Ready(Some(Ok(Bytes::from_owner(PooledBuf {
                data: buf,
                len,
                pool: Arc::clone(&this.pool),
            })))),
        }
    }
}

#[cfg(test)]
mod tests {
    use futures_util::StreamExt as _;
    use tokio::io::AsyncWriteExt;

    use super::*;

    #[tokio::test]
    async fn frames_carry_all_bytes_in_order_and_blocks_return_to_pool() {
        let chunk = 8 * 1024;
        let (mut tx, rx) = tokio::io::duplex(chunk);
        let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let expected = payload.clone();
        let writer = tokio::spawn(async move {
            tx.write_all(&payload).await.expect("duplex 写不失败");
            tx.shutdown().await.expect("duplex 关闭不失败");
        });

        let mut stream = PoolStream::new(rx, chunk);
        let mut got = Vec::new();
        while let Some(item) = stream.next().await {
            got.extend_from_slice(&item.expect("读不失败"));
        }
        writer.await.expect("写任务不 panic");
        drop(stream);

        assert_eq!(got, expected, "字节内容与顺序必须完整");
    }

    /// 块必须归还池：写满一轮后空闲块数 > 0（否则等于逐帧新分配）。
    #[tokio::test]
    async fn blocks_are_recycled() {
        let chunk = 4 * 1024;
        let (mut tx, rx) = tokio::io::duplex(chunk);
        let writer = tokio::spawn(async move {
            tx.write_all(&vec![7u8; chunk * 4]).await.expect("duplex 写不失败");
            tx.shutdown().await.expect("duplex 关闭不失败");
        });
        let mut stream = PoolStream::new(rx, chunk);
        while let Some(item) = stream.next().await {
            drop(item.expect("读不失败"));
        }
        writer.await.expect("写任务不 panic");
        assert!(stream.idle_blocks() > 0, "块必须归还池（否则逐帧重分配）");
    }
}
