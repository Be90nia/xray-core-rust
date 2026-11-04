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

/// 本流块池的**常驻字节预算**：256 MB 小机场口径下 xray 只有 ~96 MB，本池独占
/// ≤2 MB（`reports/audit-2026-11-04/MEMORY-BUDGET-256MB.md` §1「全部池/缓存合计
/// ≤4 MB」）。
///
/// 旧口径按 hyper 16 MB send_buf 推导块数（64 KiB chunk ⇒ 258 块 ≈ 16.5 MB/流），
/// 且 `idle_cap` 随在飞峰值涨到该上限 ⇒ 高负载后空闲常驻可逼近 16.5 MB。
/// hyper 的 send_buf 属另一份账（连接缓冲面），**不是**本池可以跟着涨的理由。
pub(super) const POOL_BYTE_BUDGET: usize = 2 * 1024 * 1024;

/// 块数下限：chunk 偏大时预算算出的块数可能小于窗口必要量，保底 4 块——
/// 池外降级直构 64 KiB 实测 3.7–4.1 µs/次，而池借还仅 ~100–300 ns
/// （`reports/audit-2026-11-04/POOL-IMPLEMENTATION-PLAN.md` §0），
/// 下限换的是「窗口小包不逐帧走直构」。
const POOL_MIN_BLOCKS: usize = 4;

/// 池容量硬上限 = 本流**空闲块数**上界（按 [`POOL_BYTE_BUDGET`] 推导）：64 KiB
/// chunk ⇒ 32 块 = 2 MB。在飞块数不受此限——超上限时 `acquire_owned` 降级直构，
/// 只是不进 idle 常驻（`ObjectPool` 语义，见 `take_block` 的峰值抬升）。
fn pool_max_blocks(chunk: usize) -> usize {
    (POOL_BYTE_BUDGET / chunk.max(1)).max(POOL_MIN_BLOCKS)
}

/// `Bytes` 的缓冲所有者：`Bytes` 最后一个引用释放 ⇒ 本结构 Drop ⇒ 池句柄 Drop ⇒
/// 块回池（复位与容量裁决走池的归还路径，无需手写归还）。
struct PooledBuf {
    data: Owned<Vec<u8>>,
    len: usize,
}

impl Drop for PooledBuf {
    fn drop(&mut self) {
        // 归还契约（bd hdugl）：h2 body 是用户明文，还池前清零；清零范围 = **本帧实际写入的
        // `[..len]`**（`ReadBuf` 只写 `[0..len)`，尾部从未承载本流数据），不是整块 64 KiB。
        // 清零量必须与写入量同阶：全量 memset 64 KiB 实测 190.8µs/次，而池借还仅
        // ~100-300ns ⇒ 全清直接吃掉池化收益（本次修法就是为避开这一形态）。
        // 不变量：块借出时 `[..len]` 恒为零（每次写入都在本 Drop 里按同一范围清零，
        // 未写入就归还的路径不会引入新数据）⇒ 跨帧/跨连接无明文残留。
        self.data[..self.len].fill(0);
    }
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
/// - reset 钩子只做容量归一（红线：池化对象等重，防池毒化）；明文清零**不在钩子里**： 钩子跑在整块
///   64 KiB 上（memset 实测 190.8µs/次，直接吃掉池化收益），改由持有方在 [`PooledBuf::drop`]
///   里按实际写入量 `[..len]` 清零（见该 Drop 的契约注）。
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
                // 出错时填了多少字节不可知（`AsyncRead` 契约：返回 Err 时 buffer 内容未定义）
                // ⇒ 整块清零后再回池；错误罕见，这次 64 KiB memset 不构成路径成本。
                buf.fill(0);
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

    /// 串味防护（bd hdugl · P0）：帧被消费掉后，块归还前必须清零**实际写入区**——
    /// 下一位借出方读不到上一帧的明文（h2 body = 用户明文）。
    /// **反向自检锚点**：删掉 `PooledBuf::drop` 里的 `fill(0)`，本断言必红。
    #[tokio::test]
    async fn released_frame_leaves_no_plaintext_in_pooled_block() {
        const PAYLOAD: usize = 1024;
        let chunk = 8 * 1024;
        let (mut tx, rx) = tokio::io::duplex(chunk);
        let writer = tokio::spawn(async move {
            tx.write_all(&[0x5Au8; PAYLOAD]).await.expect("duplex 写不失败");
            tx.shutdown().await.expect("duplex 关闭不失败");
        });

        let mut stream = PoolStream::new(rx, chunk);
        let frame = stream.next().await.expect("一帧").expect("读不失败");
        assert_eq!(frame.len(), PAYLOAD);
        assert!(frame.iter().all(|&b| b == 0x5A), "帧内容原样交付");
        drop(frame); // 最后一个引用释放 ⇒ 清零 + 归还
        writer.await.expect("写任务不 panic");

        let reused = stream.take_block();
        assert_eq!(reused.len(), chunk);
        // 读完**整块**（B 可能读到的最大范围）：归还方按 `[..len]` 清零 + 工厂零化 ⇒
        // 不变量是「块借出时全零」，比「A 的写入区为零」更强（跨帧/跨连接零残留）。
        assert!(
            reused.iter().all(|&b| b == 0),
            "归还前必须清零已写入区：禁把上一帧明文发给下一个借出方"
        );
    }

    /// 归还预算守卫（bd hdugl 验收）：64 KiB 块归还只付「已写区」清零成本。
    /// 反例 = reset 钩子整块 memset（debug 实测 190.8µs/次，吃掉全部池化收益；
    /// 见 `reports/audit-2026-11-04/pooling-implementation-plan` §1 实测账）。
    #[test]
    fn returning_64k_block_costs_only_written_region() {
        const CHUNK: usize = 64 * 1024;
        const WRITTEN: usize = 16 * 1024; // 一帧 h2 DATA 的量级
        let stream = PoolStream::new(tokio::io::empty(), CHUNK);

        let mut worst = std::time::Duration::ZERO;
        for _ in 0..8 {
            let mut buf = stream.take_block();
            buf[..WRITTEN].fill(0xAA);
            let frame = Bytes::from_owner(PooledBuf { data: buf, len: WRITTEN });
            let t0 = std::time::Instant::now();
            drop(frame);
            worst = worst.max(t0.elapsed());
        }
        // 绝对阈值只在 release 口径压（PM 判据：debug 会高估一个量级 —— 本机 debug 实测
        // 16 KiB 填充 30~90µs，release 200~300ns）；release 预算同时被
        // `xray-transport/tests/new_vs_pooled.rs::cmp_64k_buffer_return_budget` 压一次。
        if !cfg!(debug_assertions) {
            assert!(
                worst < std::time::Duration::from_micros(20),
                "64 KiB 块归还实测 {worst:?} ≥ 20µs：清零量必须限于已写区（[..len]），不是整块"
            );
        }

        let reused = stream.take_block();
        assert!(
            reused[..WRITTEN].iter().all(|&b| b == 0),
            "复用的块前 len 字节必须为 0（串味防护）"
        );
    }

    /// 字节预算（96 MB 预算口径）：单流块池常驻 ≤ [`POOL_BYTE_BUDGET`]。
    /// **反向自检锚点**：把 `pool_max_blocks` 改回 `16 MB / chunk + 2`，本断言必红
    /// （64 KiB ⇒ 258 块 ≈ 16.5 MB）。
    #[test]
    fn pool_max_blocks_fits_byte_budget() {
        for chunk in [4 * 1024, UPLINK_CHUNK] {
            let blocks = pool_max_blocks(chunk);
            assert!(
                blocks * chunk <= POOL_BYTE_BUDGET,
                "chunk={chunk} 时 {blocks} 块 = {} 字节，超 POOL_BYTE_BUDGET={POOL_BYTE_BUDGET}",
                blocks * chunk
            );
        }
        assert_eq!(pool_max_blocks(UPLINK_CHUNK), 32, "64 KiB chunk ⇒ 2 MB 预算 32 块");
        // chunk 极大时保底块数（预算让位于下限，免窗口小包逐帧走降级直构）。
        assert_eq!(pool_max_blocks(POOL_BYTE_BUDGET), POOL_MIN_BLOCKS);
    }

    /// 复用率不回退（64 KiB = 生产 `UPLINK_CHUNK` / 下行 `DUPLEX_BUF`）：预算把 idle
    /// 上限从 258 块砍到 32 块后，逐帧消费（每帧释放后才取下一块）仍零重分配，且
    /// 稳态不走降级直构（走降级 = 逐帧 3.7 µs 直构，即"上界换来吞吐塌"）。
    #[tokio::test]
    async fn uplink_chunk_blocks_are_recycled_under_byte_budget() {
        const FRAMES: usize = 64;
        let (mut tx, rx) = tokio::io::duplex(UPLINK_CHUNK);
        let writer = tokio::spawn(async move {
            for _ in 0..FRAMES {
                tx.write_all(&vec![9u8; UPLINK_CHUNK]).await.expect("duplex 写不失败");
            }
            tx.shutdown().await.expect("duplex 关闭不失败");
        });

        let mut stream = PoolStream::new(rx, UPLINK_CHUNK);
        let mut frames = 0usize;
        while let Some(item) = stream.next().await {
            drop(item.expect("读不失败"));
            frames += 1;
        }
        writer.await.expect("写任务不 panic");
        assert!(frames >= FRAMES, "帧数 = 数据量 / 块大小，实测 {frames}");

        let m = stream.pool.metrics();
        assert_eq!(m.core.max, 32, "64 KiB ⇒ idle 上限 32 块（2 MB 预算）");
        assert!(
            m.constructed <= 4,
            "{frames} 帧只允许 ≤4 次新分配（首块 + 读腿/在飞余量），constructed={}",
            m.constructed
        );
        assert_eq!(m.degraded, 0, "稳态不得走降级直构");
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
