//! 下行 body 流：duplex 读 → h2 DATA 帧，读缓冲池化复用（票 r1693）。
//!
//! hyper 的 `Frame::data(Bytes)` 会持有 `Bytes` 直到帧编码写出，`Bytes` 无法主动
//! 回收——原 `ReaderStream` 因此每帧新分配一块 64 KiB `BytesMut`（实测 srv 发送
//! ≈1.0 MB 分配/MB 数据，占 srv 总分配 48%）。这里改为池化：读入池借出的固定块，
//! 交给 hyper 的 `Bytes` 由 `PooledBuf::drop` 归还（`Bytes::from_owner`），稳态零分配。
//!
//! 帧粒度与原实现一致：一次 `poll_read` 产出一帧（同 `ReaderStream` 的
//! `poll_read_buf` 单次读语义），故 h2 DATA 帧尺寸分布不变。
//!
//! 留主仓（方向件：依赖 `bytes::Bytes::from_owner`）——池化读流只服务 h2 DATA
//! 帧这一网络方向，`bytes` 属方向件非 udf 依赖纪律，不上浮。

use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex, PoisonError},
    task::{Context, Poll},
};

use bytes::Bytes;
use futures_util::Stream;
use hyper::body::Frame;
use tokio::io::{AsyncRead, ReadBuf};
use xray_common::alloc_site;

/// 池化块大小（= 下行 duplex 缓冲 `DUPLEX_BUF`）。
const CHUNK: usize = super::handler::DUPLEX_BUF;

/// 硬上限 = 本流 h2 在飞块数上界：hyper 每连接 send_buf 缺省 16 MB（窗保底同值），
/// 一个块至多对应 send_buf 里一个待写帧，加读腿/编码中各 1 块余量。实际池容量按
/// 本流观测的在飞峰值自适应到该上限（见 `PoolState::put`）。
const POOL_MAX: usize = 16 * 1024 * 1024 / CHUNK + 2;

/// 空闲块账本。归还可能发生在 hyper 的任意 worker 线程，故加锁。
#[derive(Default)]
struct BufPool {
    state: Mutex<PoolState>,
}

#[derive(Default)]
struct PoolState {
    free: Vec<Vec<u8>>,
    /// 当前在外（hyper 持有未归还）的块数。
    live: usize,
    /// 本流观测的在飞峰值 = 池容量依据。
    peak: usize,
}

impl BufPool {
    fn take(&self) -> Vec<u8> {
        let mut st = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        st.live += 1;
        if st.live > st.peak {
            st.peak = st.live;
        }
        st.free.pop().unwrap_or_else(|| vec![0; CHUNK])
    }

    fn put(&self, buf: Vec<u8>) {
        let mut st = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        st.live = st.live.saturating_sub(1);
        // 容量 = 本流观测峰值（封顶 POOL_MAX）：突发排空后的块整批留池，供下一
        // 突发复用——否则每个「send_buf 填充满→排空」周期都逐帧重分配 64 KiB
        //（bd 9eu4a：客户端提速后突发深度 >8，旧固定容量把池打成逐帧 churn）。
        // 驻留 ≤ 本流 send_buf 本就要占的量，且只在真突发过的流上发生。
        if st.free.len() < st.peak.min(POOL_MAX) {
            st.free.push(buf);
        }
    }
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

/// duplex → `Frame<Bytes>` 的池化读流（下行响应 body）。
pub(crate) struct DlStream<R> {
    inner: R,
    pool: Arc<BufPool>,
}

impl<R> DlStream<R> {
    pub(crate) fn new(inner: R) -> Self {
        Self { inner, pool: Arc::new(BufPool::default()) }
    }
}

impl<R: AsyncRead + Unpin> Stream for DlStream<R> {
    type Item = io::Result<Frame<Bytes>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // 站点归因（z02z8）：本段一次 poll 的分配（含池未命中时的取块）归 srv 发送站点。
        let _site = alloc_site::enter(alloc_site::XHTTP_SRV_SEND);
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
            // EOF：内层随流结束释放（会话 guard 在此触发，同 ReaderStream 语义）。
            Poll::Ready(Ok(0)) => {
                this.pool.put(buf);
                Poll::Ready(None)
            },
            Poll::Ready(Ok(len)) => {
                Poll::Ready(Some(Ok(Frame::data(Bytes::from_owner(PooledBuf {
                    data: buf,
                    len,
                    pool: Arc::clone(&this.pool),
                })))))
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use futures_util::StreamExt;
    use tokio::io::AsyncWriteExt;

    use super::*;

    #[tokio::test]
    async fn frames_carry_all_bytes_in_order_and_blocks_return_to_pool() {
        let (mut tx, rx) = tokio::io::duplex(CHUNK);
        let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let expected = payload.clone();
        let writer = tokio::spawn(async move {
            tx.write_all(&payload).await.expect("duplex 写不失败");
            tx.shutdown().await.expect("duplex 关闭不失败");
        });

        let mut stream = DlStream::new(rx);
        let pool = Arc::clone(&stream.pool);
        let mut got = Vec::new();
        while let Some(item) = stream.next().await {
            let frame = item.expect("读不失败");
            got.extend_from_slice(frame.data_ref().expect("仅数据帧"));
        }
        writer.await.expect("写任务不 panic");

        assert_eq!(got, expected, "字节内容与顺序必须完整");
        assert!(!pool.state.lock().expect("池锁未中毒").free.is_empty(), "块必须归还池");
    }
}
