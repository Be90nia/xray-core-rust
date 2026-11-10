//! 热替换快照持有件：无锁读 + 原子整体替换（bd 9u35o）。
//!
//! 四栏归属（ADR-1 宪法条款）：
//!
//! - **udf 基件**：**无等价件**（逐条审计见下节）；实现底座是第三方 `arc-swap`——已在依赖树内 （经
//!   `ocsp-stapler` 传递引入，`Cargo.lock` 早有 `arc-swap 1.9.2`），**不新增 crate 入图**。
//! - **派生方式**：**组合包装**——`arc_swap::ArcSwap` 之上把 API 面收窄为「取快照 + 整体替换」
//!   两条，**禁**部分更新 / 可变访问（防快照退化成可变状态）。
//! - **xray-frame 派生件**：本件 [`HotSlot`]。
//! - **消费点**（各自票内接线）：geoip 注册表 IP matcher 热替换（bd hdgz9）、 TLS 证书热重载（bd
//!   5ctu1）。
//!
//! `udf-promotion-candidate`：本件零 Xray 语义（进程级机制，与 `cache`/`retry`/`scheduler` 同族）
//! ⇒ 按 `CLAUDE.md` §3.5.5 判据① 归属 udf。当下留在 xray-frame 的唯一理由：改父仓须走提炼回路
//! （独立 PR + 三平台 CI 绿 + 换依赖复测 32/32），派生成熟后再上浮；上浮时主仓侧 API 面不变。
//!
//! # 为何没有等价件（派生审计结论）
//!
//! - udf `skeleton_infra::runtime::SyncStore::snapshot`：读路径 `lock(&self.inner.state)` 后才
//!   `Arc::clone` —— **读侧持锁**，不是无锁读。
//! - udf `std_ext::cache::{LruCache, TtlCache}`：单线程 `&mut self`；`SyncTtlCache` 是
//!   `Mutex<LruCore>` —— 读侧仍持锁，且语义是 TTL 淘汰而非整体替换。
//! - udf `skeleton_infra::memgov::BoundedRegistry`：有界 KV + 淘汰策略（BTreeMap），无原子换指针。
//! - xray-frame `pool::SharedPoolRegistry`：`Mutex<HashMap>` 查表；`compat`：一次性安装的全局槽
//!   （`RwLock<Option<Arc<_>>>`，读侧持锁且语义是 one-shot install，禁重复写）；
//!   `logging::HotLog`：原子级别序数，无值替换；`reload`：文件面 stage→swap→apply→rollback 编排。
//!   逐条均非「无锁读 + 原子整体换 `Arc`」等价物。
//!
//! # 边界语义
//!
//! - **读**（[`HotSlot::current`]）：一次原子读 + 一次引用计数自增，**零锁零分配**。返回的 `Arc<T>`
//!   可跨线程 / 跨 `.await` 持有；旧值活到最后一个 `Arc` 落地为止。
//! - **写**（[`HotSlot::replace`]）：单次原子换指针，对**所有后续** `current()` 立即可见；
//!   替换点上若已无读者，旧值当场释放。
//! - **不提供**部分更新 / `&mut T` / 按 key 增删：`T` 只以 `Arc<T>` 整体进出。`T` 不要求 `Clone`
//!   （只换指针，不克隆内容）。
//! - **无后台线程、无定时器、无锁**：旧值释放时机完全由 `Arc` 引用计数决定。
//!
//! # 读形态为何选 `Arc<T>` 而非 Guard
//!
//! `arc-swap` 的 `Guard` 自述「不应存进数据结构、不应跨 async yield point 持有」（其
//! `docs/limitations.rs`：*"These are not intended to be stored in data structures or used across
//! async yield points"*）——本仓任务全在 tokio 上跨线程迁移，跨 `.await` 是常态。且 `Guard` 无法
//! 再变成 `Arc<T>`，而 TLS 握手要 owned `Arc<ServerConfig>`。代价仅是一次读多写少 cacheline 上的
//! refcount 自增，相对 IP 前缀匹配（数十 ns 起）与一次握手（数十 µs 起）在噪声内
//! （实测量级见测试 `current_cost_magnitude`）。
//!
//! # 与 `xray_frame::reload` 的分工
//!
//! `reload` 负责**文件面**编排（stage → swap → apply(deadline) → rollback）；本件只负责「内存里
//! 换快照」——`reload` 的 apply 回调里调 [`HotSlot::replace`]，两者不重叠。

use std::sync::Arc;

use arc_swap::ArcSwap;

/// 热替换快照持有件：持有一个 `Arc<T>`，读侧无锁，写侧整体替换。
///
/// 见模块文档的边界语义与派生归属。
pub struct HotSlot<T> {
    inner: ArcSwap<T>,
}

impl<T> HotSlot<T> {
    /// 以初始快照构造。
    pub fn new(value: Arc<T>) -> Self {
        Self { inner: ArcSwap::new(value) }
    }

    /// 当前快照（一次原子读 + 一次 refcount 自增；持有期内该快照不被释放）。
    #[must_use]
    pub fn current(&self) -> Arc<T> {
        self.inner.load_full()
    }

    /// 整体替换（原子可见）；旧值随最后一个 `Arc` 释放。
    pub fn replace(&self, value: Arc<T>) {
        // 上一代 Arc 就地落地：无读者即当场释放，有读者则活到最后一个读者 drop。
        drop(self.inner.swap(value));
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        thread,
        time::Instant,
    };

    use super::HotSlot;

    /// 释放计数载荷：Drop 时给计数 +1（验证旧值释放时机）。
    struct Tracked {
        id: u64,
        drops: Arc<AtomicUsize>,
    }

    impl Drop for Tracked {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// 非 `Clone` 载荷：本件不要求 `T: Clone`（只换指针）——不实现 `Clone` 即可编译 = 语义证明。
    struct NoClone {
        payload: u64,
    }

    /// 双字段载荷：`seq == mirror` 必须恒成立（验证快照整体可见，非撕裂）。
    struct Pair {
        seq: u64,
        mirror: u64,
    }

    #[test]
    fn value_not_required_clone() {
        let slot = HotSlot::new(Arc::new(NoClone { payload: 7 }));
        let seen = slot.current();
        assert_eq!(seen.payload, 7);
        slot.replace(Arc::new(NoClone { payload: 8 }));
        assert_eq!(slot.current().payload, 8);
    }

    /// 消费方都在 tokio 上跨线程持有：`Send + Sync` 必须成立（由 `ArcSwap<T>` 自动派生）。
    #[test]
    fn slot_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<HotSlot<NoClone>>();
    }

    #[test]
    fn replace_visible_to_next_read() {
        let slot = HotSlot::new(Arc::new(1u64));
        assert_eq!(*slot.current(), 1);
        slot.replace(Arc::new(2));
        assert_eq!(*slot.current(), 2, "替换后新读必须立即看到新值");
        slot.replace(Arc::new(3));
        assert_eq!(*slot.current(), 3);
    }

    #[test]
    fn old_value_lives_while_reader_holds_it() {
        let drops = Arc::new(AtomicUsize::new(0));
        let slot = HotSlot::new(Arc::new(Tracked { id: 1, drops: Arc::clone(&drops) }));

        let held = slot.current();
        slot.replace(Arc::new(Tracked { id: 2, drops: Arc::clone(&drops) }));

        assert_eq!(drops.load(Ordering::SeqCst), 0, "读者持有时旧值不得释放");
        assert_eq!(held.id, 1);

        drop(held);
        assert_eq!(drops.load(Ordering::SeqCst), 1, "最后一个读者落地即释放旧值");
    }

    #[test]
    fn concurrent_read_and_replace_never_tears() {
        const READERS: usize = 4;
        const WRITES: u64 = 20_000;

        let slot = Arc::new(HotSlot::new(Arc::new(Pair { seq: 0, mirror: 0 })));
        let stop = Arc::new(AtomicBool::new(false));

        let readers: Vec<_> = (0..READERS)
            .map(|_| {
                let slot = Arc::clone(&slot);
                let stop = Arc::clone(&stop);
                thread::spawn(move || {
                    let mut reads = 0u64;
                    while !stop.load(Ordering::Relaxed) {
                        let snapshot = slot.current();
                        assert_eq!(snapshot.seq, snapshot.mirror, "快照撕裂：seq/mirror 不一致");
                        reads += 1;
                    }
                    reads
                })
            })
            .collect();

        for seq in 1..=WRITES {
            slot.replace(Arc::new(Pair { seq, mirror: seq }));
        }
        stop.store(true, Ordering::Relaxed);

        let total_reads: u64 =
            readers.into_iter().map(|h| h.join().expect("reader 未 panic")).sum();
        assert!(total_reads > 0, "并发读者一个读都没跑");
        let last = slot.current();
        assert_eq!(last.seq, WRITES, "写入序收敛后最终读必须是最后写入值");
        assert_eq!(last.mirror, WRITES);
    }

    /// 读侧成本量级（非门限断言，量级异常才拒；数字进交付报告）。
    #[allow(
        clippy::print_stdout,
        clippy::disallowed_macros,
        reason = "取证数字须打印（--nocapture 人眼核对），同 q1r4q 先例"
    )]
    #[test]
    fn current_cost_magnitude() {
        const ITERS: usize = 1_000_000;
        let slot = HotSlot::new(Arc::new(41u64));

        let start = Instant::now();
        let mut acc = 0u64;
        for _ in 0..ITERS {
            acc = acc.wrapping_add(*std::hint::black_box(slot.current()));
        }
        let ns_per_op = start.elapsed().as_nanos() as f64 / ITERS as f64;
        std::hint::black_box(acc);

        // 参照：裸 `Arc::clone` 一次（= 本件的 refcount 自增成本本体）。
        let base = Arc::new(41u64);
        let start = Instant::now();
        let mut acc = 0u64;
        for _ in 0..ITERS {
            let snapshot = std::hint::black_box(Arc::clone(&base));
            acc = acc.wrapping_add(*snapshot);
        }
        let ns_per_clone = start.elapsed().as_nanos() as f64 / ITERS as f64;
        std::hint::black_box(acc);

        println!(
            "HotSlot::current ≈ {ns_per_op:.2} ns/op；裸 Arc::clone ≈ {ns_per_clone:.2} ns/op\
             （{ITERS} 次迭代）"
        );
        assert!(ns_per_op < 1000.0, "读侧量级异常：{ns_per_op:.2} ns/op");
    }
}
