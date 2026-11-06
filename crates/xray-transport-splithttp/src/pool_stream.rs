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
//! （2026-11-03 迁移，见 `PoolStream` 文档）。
//!
//! **进程级共享池（bd kw2si）**：同 chunk 全进程唯一一份 `ObjectPool`（上行
//! `UPLINK_CHUNK` 与下行 `DUPLEX_BUF` 同为 64 KiB ⇒ 上行/下行全部流共享同一份），
//! 预算 [`POOL_BYTE_BUDGET`] 从「每流一份」的乘积面（N 流 = N × 2 MiB）收敛为
//! 进程级常量上界。并发借还线程安全由池自身保证（分片 + 片锁），测试用
//! `PoolStream::with_pool` 注入独立池隔离读数。
//!
//! 留主仓（方向件：依赖 `bytes::Bytes::from_owner`）——池化读流只服务 h2 body
//! 这一网络方向，`bytes` 属方向件非 udf 依赖纪律，不上浮。

use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures_util::Stream;
use skeleton_infra::{ObjectPool, Owned, ResetPhase};
use tokio::io::{AsyncRead, ReadBuf};

/// 上行（客户端 POST body）读块大小 = 下行 [`crate::hub::handler::DUPLEX_BUF`] 同值。
/// 4 KiB（tokio-util 缺省）在 h2 下把 DATA 帧粒度钉死，帧数/唤醒数放大 16×。
pub(crate) const UPLINK_CHUNK: usize = 64 * 1024;

/// 进程级共享块池的**常驻字节预算**（每 chunk 一池、同池全进程共享）：256 MB
/// 小机场口径下 xray 只有 ~96 MB，本池独占 ≤2 MB（
/// `reports/audit-2026-11-04/MEMORY-BUDGET-256MB.md`；登记于 xray-core
/// `memory_budget::SPLITHTTP_SHARED_BLOCK_POOL_MAX_BYTES`，交叉断言钉住，bd sgdwm）。
///
/// 旧口径按 hyper 16 MB send_buf 推导块数（64 KiB chunk ⇒ 258 块 ≈ 16.5 MB/流），
/// 且 `idle_cap` 随在飞峰值涨到该上限 ⇒ 高负载后空闲常驻可逼近 16.5 MB。
/// hyper 的 send_buf 属另一份账（连接缓冲面），**不是**本池可以跟着涨的理由。
///
/// 生产只存在 64 KiB 一种 chunk（上行 `UPLINK_CHUNK` = 下行
/// `DUPLEX_BUF`，hub handler）⇒ 进程级合计 ≤ [`POOL_BYTE_BUDGET`]；
/// 测试面的小 chunk 各自成池，不进生产预算口径。
pub const POOL_BYTE_BUDGET: usize = 2 * 1024 * 1024;

/// 块数下限：chunk 偏大时预算算出的块数可能小于窗口必要量，保底 4 块——
/// 池外降级直构 64 KiB 实测 3.7–4.1 µs/次，而池借还仅 ~100–300 ns
/// （`reports/audit-2026-11-04/POOL-IMPLEMENTATION-PLAN.md` §0），
/// 下限换的是「窗口小包不逐帧走直构」。
const POOL_MIN_BLOCKS: usize = 4;

/// 池容量硬上限 = 共享池**空闲块数**上界（按 [`POOL_BYTE_BUDGET`] 推导）：64 KiB
/// chunk ⇒ 32 块 = 2 MB（进程级）。在飞块数不受此限——超上限时 `acquire_owned`
/// 降级直构，只是不进 idle 常驻（`ObjectPool` 语义）。
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
        // 不变量：块借出时 `[..len]` 恒为零——数据帧由本 Drop 按 `[..len]` 清零，
        // Pending/EOF/Err 三个未产出帧的归还路径由 `poll_next` 就地清零（bd vjii0）
        // ⇒ 跨帧/跨连接无明文残留。
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
/// `reports/audit-2026-11-03/bufpool-migration.md`）；2026-11-05 起为**进程级共享**
/// （bd kw2si）——同 chunk 全进程唯一一份：
/// - 在飞块数 = `metrics().core.borrowed`：块以 `'static` 句柄（`acquire_owned`） 随 [`PooledBuf`]
///   存续到 `Bytes` 最后一个引用释放，句柄 Drop 即归还——
///   「最后一个引用释放才归还」由引用计数天然保证，不需要第二套借还账本；
/// - `idle_cap` 恒等于池上界（[`pool_max_blocks`]）：共享池的 2 MiB 是进程级预算
///   承诺，恒定上界可审计；`idle_cap` 不预分配内存（块只有借过才占 idle 槽）， 低负载下常驻 =
///   历史峰值在飞数 × chunk，与旧自适应抬升的稳态一致；
/// - reset 钩子只做容量归一（红线：池化对象等重，防池毒化）；明文清零**不在钩子里**，
///   在**写入现场**按实际写入量做（bd vjii0 收口）：数据帧 [`PooledBuf::drop`] 的
///   `[..len]`、Pending 臂 `[..filled]`（违约型内层写后挂起，合规路径零成本）、 EOF/Err
///   臂整块（写入量不可知 / 内容未定义，且两者每流一次不构成路径成本）。 **不采用 udf
///   `with_zeroing_reset`**：池的归还钩子看不到「本次借出的写入区」 （`ReadBuf` 不改 `Vec` 的
///   len），钩子内清零只能整块 memset——64 KiB 实测 190.8µs/次跑在含 Pending
///   的热路径上，直接吃掉池化收益（bd hdugl 判据 「清零成本必须与写入量同阶」）。
pub(crate) struct PoolStream<R> {
    inner: R,
    pool: Arc<ObjectPool<Vec<u8>>>,
}

/// 共享池构造（单源）：生产取口 [`shared_pool`] 与测试隔离
/// `isolated_pool`（mod tests）同一形状——预算见 [`POOL_BYTE_BUDGET`]、
/// 块数公式见 [`pool_max_blocks`]。
///
/// **表本体已上浮（bd ccy5d / ARCH-05）**：进程级共享表 = 框架
/// [`xray_frame::pool::SharedPoolRegistry`]——本 crate 的静态表已删（禁双套），
/// 按尺寸 class 分桶 / first-wins / 中毒恢复等语义文档见该件；本 crate 只留
/// 池构造形状（预算公式 + reset 钩子，方向件留主仓口径不变）。
fn build_chunk_pool(chunk: usize) -> Arc<ObjectPool<Vec<u8>>> {
    Arc::new(ObjectPool::with_reset(
        // idle_cap = max = 池上界：归还即留池（不预分配）；分片数 =
        // 构造期 `idle_cap.clamp(1, 8)` ⇒ 8 分片摊薄并发借还争用。
        pool_max_blocks(chunk),
        pool_max_blocks(chunk),
        move || vec![0u8; chunk],
        move |buf: &mut Vec<u8>| {
            // 容量归一：合规块只付一次 len 比较（`ReadBuf` 不改 Vec 的 len）。
            if buf.len() != chunk {
                buf.clear();
                buf.resize(chunk, 0);
            }
        },
        ResetPhase::OnReturn,
    ))
}

/// 进程级共享池取口（每 chunk 一份）：生产路径 [`PoolStream::new`] 的唯一入口。
///
/// 借出**永不阻塞、永不失败**（池空即 factory 新造，宇宙满即降级直构交付），
/// 共享不引入单流独占饿死；N 流并发 > 池宇宙时的代价是降级直构的性能差异
/// （实测 3.7–4.1 µs/次 vs 池借还 ~100–300 ns），不是饥饿。
fn shared_pool(chunk: usize) -> Arc<ObjectPool<Vec<u8>>> {
    xray_frame::pool::SharedPoolRegistry::shared().get_or_init(chunk, || build_chunk_pool(chunk))
}

impl<R> PoolStream<R> {
    pub(crate) fn new(inner: R, chunk: usize) -> Self {
        Self::with_pool(inner, shared_pool(chunk))
    }

    /// 注入缝：测试面隔离（独立池的 metrics 读数不被并行测试污染）；生产一律走
    /// [`Self::new`] 的进程级共享池。`pool` 的 chunk 与读流 chunk 必须一致
    /// （reset 钩子按构造期 chunk 归一）。
    pub(crate) fn with_pool(inner: R, pool: Arc<ObjectPool<Vec<u8>>>) -> Self {
        Self { inner, pool }
    }

    /// 借一块（`'static` 句柄：归还点是任意 worker 线程的引用计数归零）。
    fn take_block(&self) -> Owned<Vec<u8>> {
        self.pool.acquire_owned()
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
        let (polled, filled) = {
            let mut rb = ReadBuf::new(buf.as_mut_slice());
            let res = Pin::new(&mut this.inner).poll_read(cx, &mut rb);
            let filled = rb.filled().len();
            (res.map(|r| r.map(|()| filled)), filled)
        };
        match polled {
            Poll::Pending => {
                // vjii0：Pending 合约上不写数据，但违约型内层（写后 Pending——探针
                // `pending_path_leaves_no_plaintext_in_pooled_block` 实证）会把明文
                // 留在块里裸归还；进程级共享池（bd kw2si）下一个租户即读到上一连接
                // 的 h2 body 明文。按实际写入区清零（合规内层 filled=0 ⇒ 零成本）；
                // 禁整块清零（hdugl：Pending 是热路径）。
                // rjaxs-③（「写而不推进 filled」的违约形态，评估不加防御）：
                // `ReadBuf::new` 起 `initialized()` 恒满长 ⇒ 无 API 观测「初始化未
                // 推进」的写入区，残余防御手段只剩整块 memset（hdugl 禁）或违约
                // 计数器（同样不可实现）。生产内层面 = tokio 1.54 `duplex` 两半
                // （dialer ×4 上行 + dl_stream 下行，`GuardedReader` 纯转发）：
                // tokio `io/util/mem.rs:308-334` `poll_read_internal` 有数据 ⇒
                // `put_slice` + Ready 同步提交、Pending 臂零写入 ⇒ 违约形态对唯一
                // 生产内层不可构造。重访触发：PoolStream 接非仓内/非 tokio reader
                // 时，先补「Pending 零写入」契约测试再接。
                buf[..filled].fill(0);
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
            // vjii0：违约型内层可能「已写入却不推进 filled」（探针
            // `eof_path_leaves_no_plaintext_in_pooled_block` 实证）⇒ 写入量不可知，
            // 整块清零再回池；EOF 每流一次，同 Err 臂口径不构成路径成本。
            Poll::Ready(Ok(0)) => {
                buf.fill(0);
                drop(buf);
                Poll::Ready(None)
            },
            // vjii0：数据帧由 `PooledBuf::drop` 按 `[..len]` 清零（成本与写入量同阶）。
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

    /// 独立池（测试隔离）：形状与生产 [`shared_pool`] 完全一致（同走
    /// [`build_chunk_pool`] 单源，bd ccy5d）——断言读数不被共享池上其他并行
    /// 测试的借还污染。
    fn isolated_pool(chunk: usize) -> Arc<ObjectPool<Vec<u8>>> {
        build_chunk_pool(chunk)
    }

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

        let mut stream = PoolStream::with_pool(rx, isolated_pool(chunk));
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
        let mut stream = PoolStream::with_pool(rx, isolated_pool(chunk));
        while let Some(item) = stream.next().await {
            drop(item.expect("读不失败"));
        }
        writer.await.expect("写任务不 panic");
        assert!(stream.idle_blocks() > 0, "块必须归还池（否则逐帧重分配）");
    }

    /// 在飞块数 = `metrics().core.borrowed`；归还后整批留池复用（共享池改造后
    /// `idle_cap` 恒等于池上界，原「每流峰值抬升」逻辑随之删除）。
    #[test]
    fn live_blocks_map_to_borrowed_and_idle_retains_on_return() {
        let chunk = 4 * 1024;
        let stream = PoolStream::with_pool(tokio::io::empty(), isolated_pool(chunk));

        let b1 = stream.take_block();
        let b2 = stream.take_block();
        let m = stream.pool.metrics();
        assert_eq!(m.core.borrowed, 2, "在外块数 = borrowed");
        assert_eq!(m.constructed, 2, "两块都是新造");
        drop(b1);
        drop(b2);
        let m = stream.pool.metrics();
        assert_eq!(m.core.idle, 2, "idle_cap = 池上界 ⇒ 归还即留池");
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

        let mut stream = PoolStream::with_pool(rx, isolated_pool(chunk));
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

    // ===== vjii0 探针：Pending / EOF 归还路径的明文残留 =====

    /// 探针 reader（vjii0）：把可识别明文写进 `ReadBuf` 后按指定结局返回——
    /// `advance=true`：`put_slice` 推进 filled 后**违约**返回 Pending（写后挂起）；
    /// `advance=false`：只写不推进（filled=0）——poll_next 会把它判进 EOF 臂。
    struct LeakyReader {
        pattern: Vec<u8>,
        advance: bool,
        done: bool,
    }

    impl AsyncRead for LeakyReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            rb: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.done {
                return Poll::Pending; // 探针只 poll 一次，此后挂住即可
            }
            self.done = true;
            let n = self.pattern.len().min(rb.remaining());
            let pattern = &self.pattern[..n];
            if self.advance {
                rb.put_slice(pattern);
                Poll::Pending
            } else {
                // 只写不推进：filled 仍 0 ⇒ poll_next 按 EOF 臂处置；明文已入块。
                // （tokio 1.54 ReadBuf 是纯 u8 版：initialize_unfilled_to 返回 &mut [u8]。）
                let slots = rb.initialize_unfilled_to(n);
                for (slot, &byte) in slots.iter_mut().zip(pattern) {
                    *slot = byte;
                }
                Poll::Ready(Ok(()))
            }
        }
    }

    /// 探针 A（vjii0 · Pending）：违约型 reader 写入明文（filled>0）后返回
    /// Pending——该路径此前对块裸 `drop` 归还，明文留在进程级共享池里（同 chunk
    /// 全进程唯一一份，bd kw2si），下一个租户即可读到上一连接的 h2 body 明文。
    /// 断言：归还后取同块残余全零；且清零只覆盖已写入区（写入区外哨兵不被抹，
    /// hdugl 成本纪律）。
    /// **反向自检锚点**：删掉 Pending 臂的 `buf[..filled].fill(0)`，本断言必红。
    #[tokio::test]
    async fn pending_path_leaves_no_plaintext_in_pooled_block() {
        const PAYLOAD: usize = 512;
        const SENTINEL: usize = 16;
        let chunk = 8 * 1024;
        let pool = isolated_pool(chunk);
        // 预置哨兵：写入区之外的既有字节，清零不得越界抹除。
        {
            let mut block = pool.acquire_owned();
            block[PAYLOAD..PAYLOAD + SENTINEL].fill(0xC3);
        }
        let stream = PoolStream::with_pool(
            LeakyReader { pattern: vec![0xA7u8; PAYLOAD], advance: true, done: false },
            pool.clone(),
        );
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        let mut pinned = std::pin::pin!(stream);
        assert!(
            pinned.as_mut().poll_next(&mut cx).is_pending(),
            "探针 reader 首次 poll 应返回 Pending（块随之归还池）"
        );
        // 空闲表此刻恰有一块（埋哨兵的那块，已被本次 poll 写入明文）⇒ 取回同块。
        let reused = pool.acquire_owned();
        assert!(
            reused[..PAYLOAD].iter().all(|&b| b == 0),
            "Pending 路径归还的块不得残留明文（vjii0；明文=0xA7×{PAYLOAD}）"
        );
        assert!(
            reused[PAYLOAD..PAYLOAD + SENTINEL].iter().all(|&b| b == 0xC3),
            "清零只覆盖已写入区：写入区外哨兵不得被抹（hdugl 成本纪律）"
        );
    }

    /// 探针 B（vjii0 · EOF）：违约型 reader 写入明文但不推进 filled（filled=0）
    /// ——poll_next 按 EOF 臂处置并裸归还，明文留池。断言：归还后块内无残留。
    /// **反向自检锚点**：删掉 EOF 臂的整块清零，本断言必红。
    #[tokio::test]
    async fn eof_path_leaves_no_plaintext_in_pooled_block() {
        const PAYLOAD: usize = 512;
        let chunk = 8 * 1024;
        let pool = isolated_pool(chunk);
        let stream = PoolStream::with_pool(
            LeakyReader { pattern: vec![0x5Eu8; PAYLOAD], advance: false, done: false },
            pool.clone(),
        );
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        let mut pinned = std::pin::pin!(stream);
        match pinned.as_mut().poll_next(&mut cx) {
            Poll::Ready(None) => {},
            other => panic!("EOF 探针应收 Ready(None)，实际 {other:?}"),
        }
        let reused = pool.acquire_owned();
        assert!(
            reused[..PAYLOAD].iter().all(|&b| b == 0),
            "EOF 路径归还的块不得残留明文（vjii0；明文=0x5E×{PAYLOAD}）"
        );
    }

    /// 归还预算守卫（bd hdugl 验收）：64 KiB 块归还只付「已写区」清零成本。
    /// 反例 = reset 钩子整块 memset（debug 实测 190.8µs/次，吃掉全部池化收益；
    /// 见 `reports/audit-2026-11-04/pooling-implementation-plan` §1 实测账）。
    #[test]
    fn returning_64k_block_costs_only_written_region() {
        const CHUNK: usize = 64 * 1024;
        const WRITTEN: usize = 16 * 1024; // 一帧 h2 DATA 的量级
        let stream = PoolStream::with_pool(tokio::io::empty(), isolated_pool(CHUNK));

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

    /// **内存审计锚点（2026-11-04 audit4-memory）**：`POOL_BYTE_BUDGET` 是
    /// 池级预算。锚点登记时预算是**单实例**口径（每个 `PoolStream` 一份
    /// `Arc::new(ObjectPool::…)`，N 流 = N × 2 MiB 乘积面，见
    /// `reports/audit-2026-11-04/audit4-memory.md`）；**bd kw2si 落地进程级共享池
    /// 后，本锚点的上界即进程级上界**——同 chunk 全进程唯一一份池，在飞峰值
    /// 32 × 64 KiB = 2 MiB 全部留池仍可达（hyper send_buf 侧积压形态），但不再
    /// 随流数相乘。
    #[test]
    fn idle_cap_reaches_single_instance_budget_ceiling() {
        let stream = PoolStream::with_pool(tokio::io::empty(), isolated_pool(UPLINK_CHUNK));
        let cap = pool_max_blocks(UPLINK_CHUNK);
        assert_eq!(cap, 32, "前置：64 KiB chunk ⇒ 32 块");

        // 模拟突发：在飞峰值打到 max（hyper send_buf 侧积压时的真实形态）。
        let held: Vec<_> = (0..cap).map(|_| stream.take_block()).collect();
        let m = stream.pool.metrics();
        assert_eq!(m.core.borrowed, cap, "在飞 = 池宇宙上限");
        assert_eq!(m.core.idle, 0, "全部在外");

        drop(held); // 突发收回：块按池上界全留
        let m = stream.pool.metrics();
        assert_eq!(m.core.idle, cap, "idle_cap 恒 = 池上界 ⇒ 全量留池");
        assert!(
            m.core.idle * UPLINK_CHUNK <= POOL_BYTE_BUDGET,
            "单实例留池 {} 字节须 ≤ 预算 {POOL_BYTE_BUDGET}",
            m.core.idle * UPLINK_CHUNK
        );
        // 实测锚（审计取证）：2 MiB / 单流 —— `cargo test -p xray-transport-splithttp
        // idle_cap_reaches_single_instance_budget_ceiling -- --nocapture` 回读。
        #[allow(clippy::print_stdout)]
        {
            println!(
                "per-PoolStream idle resident = {} bytes ({} blocks × {} B)",
                m.core.idle * UPLINK_CHUNK,
                m.core.idle,
                UPLINK_CHUNK
            );
        }
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

        let mut stream = PoolStream::with_pool(rx, isolated_pool(UPLINK_CHUNK));
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
        let stream = PoolStream::with_pool(tokio::io::empty(), isolated_pool(chunk));

        // idle_cap 恒 = 池上界，足够收下这一块。
        drop(stream.pool.insert(vec![0xCD; chunk * 3]));
        assert_eq!(stream.pool.metrics().core.idle, 1, "归一到定长的块才入池");

        let reused = stream.take_block();
        assert_eq!(reused.len(), chunk, "reset 必须把块归一到定长");
        assert!(
            reused.iter().all(|&b| b == 0),
            "归一后必须清零：禁把上一轮的脏数据发给下一个借出方"
        );
    }

    /// 契约测试（bd kw2si 验收）：进程级共享池 = 同 chunk 全进程唯一；并发借还
    /// 线程安全且账面配平。8 任务 × 256 轮借还并发打满后：
    /// - 全局唯一性：两条 `PoolStream::new`（生产路径）拿到同一个 `Arc` 池；
    /// - `borrowed == 0`：所有句柄归还，无泄漏；
    /// - 构造数守恒：`constructed == idle`（无降级/丢弃时，每件构造的块要么在
    ///   池里要么在飞，全部归还后必然全在池里）；
    /// - `degraded == 0`：8 并发在飞 < 32 池宇宙，不降级；
    /// - 每个任务每一轮都拿到块——借出永不阻塞（池空即造、宇宙满即降级交付），
    ///   共享池不引入单流独占饿死（本测试任务全部跑完即证）。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn shared_pool_is_unique_and_balances_under_concurrent_borrow_return() {
        // 生产路径（new）全局唯一性：Arc::ptr_eq。
        let a = PoolStream::new(tokio::io::empty(), UPLINK_CHUNK);
        let b = PoolStream::new(tokio::io::empty(), UPLINK_CHUNK);
        assert!(Arc::ptr_eq(&a.pool, &b.pool), "同 chunk 的 PoolStream 必须共享同一份进程级池");

        let chunk = UPLINK_CHUNK;
        let cap = pool_max_blocks(chunk);
        let pool = isolated_pool(chunk);
        let tasks = 8usize;
        let rounds = 256u32;
        let mut joins = Vec::with_capacity(tasks);
        for _ in 0..tasks {
            let pool = Arc::clone(&pool);
            joins.push(tokio::spawn(async move {
                for i in 0..rounds {
                    let mut block = pool.acquire_owned();
                    assert_eq!(block.len(), chunk, "池块定长");
                    block[0] = (i % 251) as u8; // 摸一下内存，防止借还被优化掉
                    drop(block); // 归还
                }
            }));
        }
        for joined in joins {
            joined.await.expect("并发借还任务不 panic");
        }

        let m = pool.metrics();
        assert_eq!(m.core.borrowed, 0, "配平：所有句柄已归还");
        assert!(m.core.idle <= cap, "空闲 ≤ 池上界（{cap} 块）");
        assert_eq!(m.constructed as usize, m.core.idle, "构造数守恒：constructed = 留池数");
        assert_eq!(m.degraded, 0, "{tasks} 并发在飞 < {cap} 池宇宙，不得降级");
        assert_eq!(m.core.dropped_overflow, 0, "idle_cap = 池上界 ⇒ 归还不得溢出丢弃");
        // 配平断言输出（bd kw2si 验收取证）：`-- --nocapture` 回读。
        #[allow(clippy::print_stdout)]
        {
            println!(
                "shared-pool balance: constructed={} reused={} idle={} borrowed={} \
                 degraded={} dropped_overflow={}",
                m.constructed,
                m.reused,
                m.core.idle,
                m.core.borrowed,
                m.degraded,
                m.core.dropped_overflow
            );
        }
    }
}
