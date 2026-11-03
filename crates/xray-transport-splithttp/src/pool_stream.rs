//! 池化读流：`AsyncRead` → `Bytes` 块流，块复用（票 r1693 下行 / 1fm1l 上行）。
//!
//! `tokio_util::io::ReaderStream` 每产出一帧都新分配一块缓冲：`BytesMut::split`
//! 把容量留在帧里，下一次 `poll_next` 只剩空 `BytesMut` 被迫重新 `reserve`
//! （缺省 4 KiB）。h2 稳定生态下这等于「每帧一次分配」，实测 srv 发送 ≈1.0 MB
//! 分配/MB 数据（占 srv 总分配 48%），客户端上行同构。
//!
//! 这里改为池化：块从池借出、装进 `Bytes::from_owner`，帧被 hyper 释放后由池句柄
//! Drop 归还——稳态零分配。帧粒度与原实现一致（一次 `poll_read` 一帧），块大小由
//! 调用方指定（下行 = duplex 缓冲 64 KiB，上行同值）。块池实体是 udf `ObjectPool`
//! （2026-11-03 迁移，见 [`PoolStream`] 文档）。
//!
//! 留主仓（方向件：依赖 `bytes::Bytes::from_owner`）——池化读流只服务 h2 body
//! 这一网络方向，`bytes` 属方向件非 udf 依赖纪律，不上浮。

use std::{
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};

use bytes::Bytes;
use futures_util::Stream;
use skeleton_infra::{ObjectPool, ObjectPoolTuning, Owned, ResetPhase};
use tokio::io::{AsyncRead, ReadBuf};

/// 上行（客户端 POST body）读块大小 = 下行 [`crate::hub::handler::DUPLEX_BUF`] 同值。
/// 4 KiB（tokio-util 缺省）在 h2 下把 DATA 帧粒度钉死，帧数/唤醒数放大 16×。
pub(crate) const UPLINK_CHUNK: usize = 64 * 1024;

/// 池容量硬上限 = 本流 h2 在飞块数上界：hyper 每连接 send_buf 缺省 16 MB（窗保底
/// 同值），一个块至多对应 send_buf 里一个待写帧，加读腿/编码中各 1 块余量。
/// 实际空闲额度按本流观测的在飞峰值自适应到该上限（见 [`PoolStream::take_block`]）。
fn pool_max_blocks(chunk: usize) -> usize {
    16 * 1024 * 1024 / chunk.max(1) + 2
}

/// `Bytes` 的缓冲所有者：`Bytes` 最后一个引用释放 ⇒ 本结构 Drop ⇒ 池句柄 Drop ⇒
/// 块回池（复位与容量裁决走池的归还路径，无需手写归还）。
struct PooledBuf {
    data: Owned<Vec<u8>>,
    len: usize,
}

impl AsRef<[u8]> for PooledBuf {
    fn as_ref(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

/// `AsyncRead` → `Stream<Item = io::Result<Bytes>>` 的池化读流。
///
/// 一次 `poll_read` 产出一帧（同 `ReaderStream` 的 `poll_read_buf` 单次读语义）；
/// EOF 时释放内层（下行场景下会话 guard 随之触发）。
///
/// 块池由 udf [`ObjectPool`] 承担（2026-11-03 迁移，依据见
/// `reports/audit-2026-11-03/bufpool-migration.md`）：
/// - 在飞块数 = `metrics().core.borrowed`：块以 `'static` 句柄（`acquire_owned`） 随 [`PooledBuf`]
///   存续到 `Bytes` 最后一个引用释放，句柄 Drop 即归还——
///   「最后一个引用释放才归还」由引用计数天然保证，不需要第二套借还账本；
/// - 空闲额度按本流观测的在飞峰值 `resize` 抬升（封顶 [`pool_max_blocks`]）： `idle_cap`
///   是固定值，`resize` 是旧自适应策略最接近的等价物（峰值单调 ⇒ 只增长、不触缩容裁剪）；
/// - reset 钩子做容量归一（红线：池化对象等重，防池毒化）。
pub(crate) struct PoolStream<R> {
    inner: R,
    pool: Arc<ObjectPool<Vec<u8>>>,
    /// 本流观测的在飞峰值（空闲额度的输入量，**不是**借还账本：在飞数读数走
    /// `metrics().core.borrowed`，此处只留单调峰值供 `resize` 用）。
    peak: AtomicUsize,
}

impl<R> PoolStream<R> {
    pub(crate) fn new(inner: R, chunk: usize) -> Self {
        Self {
            inner,
            pool: Arc::new(ObjectPool::with_reset(
                pool_max_blocks(chunk),
                // 初始空闲额度 1（首次借出后观测到的峰值）：容量随在飞峰值增长。
                // 分片数 = 构造期 `idle_cap.clamp(1, 8)` ⇒ 单分片，与旧单锁形态一致，
                // 且额度不会被 8 片均分压成「小块峰值下份额 0、块留不住」。
                1,
                move || vec![0; chunk],
                move |buf: &mut Vec<u8>| {
                    // 容量归一：合规块只付一次 len 比较（`ReadBuf` 不改 Vec 的 len）。
                    if buf.len() != chunk {
                        buf.clear();
                        buf.resize(chunk, 0);
                    }
                },
                ResetPhase::OnReturn,
            )),
            peak: AtomicUsize::new(0),
        }
    }

    /// 借一块（`'static` 句柄：归还点是任意 worker 线程的引用计数归零），顺带按
    /// 观测在飞峰值抬高空闲额度。
    fn take_block(&self) -> Owned<Vec<u8>> {
        let handle = self.pool.acquire_owned();
        let core = self.pool.metrics().core;
        if core.borrowed > self.peak.load(Ordering::Relaxed) {
            self.peak.store(core.borrowed, Ordering::Relaxed);
            // 峰值单调 ⇒ 只增长（不触缩容裁剪）；形状恒合法（1 ≤ idle_cap ≤ max）。
            let idle_cap = core.borrowed.min(core.max);
            if let Err(err) = self.pool.resize(ObjectPoolTuning { max: core.max, idle_cap }) {
                // 钳位后不可达；真出现说明上面的上界算错，别静默吞掉。
                crate::LOG.warn(format_args!(
                    "pool resize rejected (idle_cap={idle_cap}, max={}): {err}",
                    core.max
                ));
            }
        }
        handle
    }

    /// 池内空闲块数（测试观测用）。
    #[cfg(test)]
    fn idle_blocks(&self) -> usize {
        self.pool.metrics().core.idle
    }
}

impl<R: AsyncRead + Unpin> Stream for PoolStream<R> {
    type Item = io::Result<Bytes>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let mut buf = this.take_block();
        let polled = {
            let mut rb = ReadBuf::new(buf.as_mut_slice());
            let res = Pin::new(&mut this.inner).poll_read(cx, &mut rb);
            res.map(|r| r.map(|()| rb.filled().len()))
        };
        match polled {
            Poll::Pending => {
                drop(buf); // 句柄 Drop ⇒ 块回池
                Poll::Pending
            },
            Poll::Ready(Err(err)) => {
                drop(buf);
                Poll::Ready(Some(Err(err)))
            },
            // EOF：内层随流结束释放（下行会话 guard 在此触发，同 ReaderStream 语义）。
            Poll::Ready(Ok(0)) => {
                drop(buf);
                Poll::Ready(None)
            },
            Poll::Ready(Ok(len)) => {
                Poll::Ready(Some(Ok(Bytes::from_owner(PooledBuf { data: buf, len }))))
            },
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

    /// 在飞块数 = `metrics().core.borrowed`；峰值抬高空闲额度后块整批留池复用
    /// （改前 `live`/`peak` 两个本地计数器的等价读数）。
    #[test]
    fn live_blocks_map_to_borrowed_and_peak_raises_idle_cap() {
        let chunk = 4 * 1024;
        let stream = PoolStream::new(tokio::io::empty(), chunk);

        let b1 = stream.take_block();
        let b2 = stream.take_block();
        let m = stream.pool.metrics();
        assert_eq!(m.core.borrowed, 2, "在外块数 = borrowed");
        assert_eq!(stream.peak.load(Ordering::Relaxed), 2, "峰值随在飞数抬升");
        assert_eq!(m.constructed, 2, "两块都是新造");
        drop(b1);
        drop(b2);
        let m = stream.pool.metrics();
        assert_eq!(m.core.idle, 2, "空闲额度 = 峰值 ⇒ 两块都留池");
        assert_eq!(m.reset_panicked, 0, "归一路径只有赋值，不得 panic");

        let _b3 = stream.take_block();
        let _b4 = stream.take_block();
        let m = stream.pool.metrics();
        assert_eq!(m.constructed, 2, "复用时不得再分配");
        assert_eq!(m.reused, 2, "两块都命中 idle 槽");
        assert_eq!(m.core.borrowed, 2);
    }

    /// 红线：reset 钩子负责容量归一——`Bytes` 所有者塞回异形块后必须归一到 chunk
    /// 才可能被借出。**反向自检锚点**：把钩子改成 no-op，本断言必红。
    #[test]
    fn pool_reset_normalizes_poisoned_block() {
        let chunk = 4 * 1024;
        let stream = PoolStream::new(tokio::io::empty(), chunk);

        // peak=0 时空闲额度是构造初值 1，足够收下这一块。
        drop(stream.pool.insert(vec![0xCD; chunk * 3]));
        assert_eq!(stream.pool.metrics().core.idle, 1, "归一到定长的块才入池");

        let reused = stream.take_block();
        assert_eq!(reused.len(), chunk, "reset 必须把块归一到定长");
        assert!(
            reused.iter().all(|&b| b == 0),
            "归一后必须清零：禁把上一轮的脏数据发给下一个借出方"
        );
    }
}
