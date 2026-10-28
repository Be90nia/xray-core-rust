//! 站点级分配归因标记（bd z02z8）：代码路径用 `enter` 声明"当前处于站点 X"，
//! 计数分配器（xray-cli `StatsAlloc`）在 alloc 钩子里按当前线程站点把增量记到
//! 对应站点计数上，周期 dump 按 `[xray-alloc-sites]` 前缀输出。
//!
//! # 门控
//!
//! `ENABLED`（私有）由 xray-cli `alloc_stats::init()` 按 `XRAY_ALLOC_STATS_SITES` 置位。
//! 未启用时 `enter` 直通（不触碰 TLS、不返回需恢复的守卫）、`scope` 只多一层
//! no-op 守卫，alloc 钩子在 COUNTING 分支短路——默认零记账开销（对齐 alloc_stats
//! 直通纪律）。
//!
//! # 线程局部语义 与 `scope`（未来域）
//!
//! [`enter`] 的标记是**线程局部**的，只在同一个 poll 段内成立（`poll_read`/
//! `poll_write` 这类同步 poll 函数用它是精确的）。跨 `.await` 用 [`enter`] 则
//! 标记留在取值时的线程：任务被调度到别的线程续跑后站点丢失（分配归"未标记"），
//! 且原线程留下永久残留——bd a65px 实证：桥层 `read_downlink` 的 `BUF_READ`
//! 因此把 cli 侧 99.8% 的分配吃掉，站点分布是假的。
//!
//! 跨 `.await` 一律用 [`scope`]：站点随 future 走，每次 poll 现取现放，跨线程
//! 续跑仍归对站点，poll 之间不驻留线程局部。
//!
//! # udf 判定
// udf-promotion-candidate: 提炼条件=零 xray 具体类型（本文件已满足：纯进程级
// 机制，站点目录由消费方编译期注册）；待 udf 接线闸（P0-9）开后上浮 skeleton-infra。

use std::{
    cell::Cell,
    future::{Future, poll_fn},
    pin::pin,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};

/// 无站点（线程默认态）。
pub const NONE: u8 = 0;
/// TLS 记录封装写路径（审计 §3 #2：tcp-tls 客户端写路径 9.24 MB/MB → 票 4y9ns）。
pub const TLS_WRITE: u8 = 1;
/// xhttp/h2 服务端发送路径（审计 §3 #1：srv 发送 ~1.06 MB/MB → 票 r1693）。
pub const XHTTP_SRV_SEND: u8 = 2;
/// vless AEAD 封装 seal（审计 §3 #3：mlkem-enc 客户端 +0.60 MB/MB）。
pub const VLESS_ENC_SEAL: u8 = 3;
/// TLS 记录**读**路径（解密 + 明文交付，票 4y9ns 归因：tcp-tls 客户端 9.24 MB/MB）。
/// 与 [`TLS_WRITE`] 对称——W0 工具只标了写面，读面（客户端下行主路径）此前无站点。
pub const TLS_READ: u8 = 4;
/// 读缓冲分配（票 4y9ns Phase 0：桥层 `read_multi_buffer` 的读缓冲）。
///
/// 标记点在**调用侧**（`xray-transport` 桥下行读）而非分配点：
/// `xray-common` 依赖 `xray-buf`（反向不成立），`xray-buf` 内的分配点引不到
/// 本模块。站点覆盖一次 `read_multi_buffer`（读缓冲 + MultiBuffer 包装），
/// 比单标分配行略宽——读缓冲容量远大于包装开销，不干扰判读。
pub const BUF_READ: u8 = 5;

/// 站点目录（索引 = 站点 id；新站点只能追加，禁重编号——dump 行与归集脚本按名对齐）。
pub const SITE_NAMES: [&str; 6] =
    ["(none)", "tls_write", "xhttp_srv_send", "vless_enc_seal", "tls_read", "buf_read"];

/// 站点归集开关：xray-cli init() 一次性置位，热路径只读。
static ENABLED: AtomicBool = AtomicBool::new(false);

/// 各站点累计记账（仅 ENABLED=true 时更新；Relaxed 同 alloc_stats 无同步语义需求）。
struct SiteCounters {
    n: AtomicU64,
    bytes: AtomicU64,
}

static SITES: [SiteCounters; SITE_NAMES.len()] =
    [const { SiteCounters { n: AtomicU64::new(0), bytes: AtomicU64::new(0) } }; SITE_NAMES.len()];

thread_local! {
    /// 当前线程站点标记。const 初始化 = 访问无懒初始化分支、无分配、无析构——
    /// 在 GlobalAlloc::alloc 钩子内调用安全（不会重入分配器）。
    static CURRENT: Cell<u8> = const { Cell::new(NONE) };
}

/// 站点归集是否已启用（alloc 钩子热路径判定）。
#[inline]
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// 启用/停用站点归集（xray-cli alloc_stats::init 启动期调用一次）。
pub fn set_enabled(on: bool) {
    ENABLED.store(on, Ordering::Relaxed);
}

/// 供分配器钩子读取当前线程站点（一次 const-init TLS 访问）。
#[inline]
pub fn current() -> u8 {
    CURRENT.with(Cell::get)
}

/// 供分配器钩子记账（调用方已保证 `site != NONE`）。
#[inline]
pub fn record(site: u8, n: u64, bytes: u64) {
    let s = &SITES[site as usize];
    s.n.fetch_add(n, Ordering::Relaxed);
    s.bytes.fetch_add(bytes, Ordering::Relaxed);
}

/// 单站点快照（dump 侧读）。
#[derive(Clone, Copy)]
pub struct SiteSnap {
    pub n: u64,
    pub bytes: u64,
}

/// 全站点快照（索引 = 站点 id，含 NONE 位恒 0）。
pub fn snapshot() -> [SiteSnap; SITE_NAMES.len()] {
    let mut out = [SiteSnap { n: 0, bytes: 0 }; SITE_NAMES.len()];
    for (i, s) in SITES.iter().enumerate() {
        out[i] =
            SiteSnap { n: s.n.load(Ordering::Relaxed), bytes: s.bytes.load(Ordering::Relaxed) };
    }
    out
}

/// 站点作用域守卫：drop 恢复进入前标记（panic 安全、早退安全、可嵌套）。
///
/// 未启用时为 no-op 守卫——零 TLS 访问、零记账（`SiteGuard(None)` 2 字节）。
pub struct SiteGuard(Option<u8>);

impl Drop for SiteGuard {
    fn drop(&mut self) {
        if let Some(prev) = self.0 {
            CURRENT.with(|c| c.set(prev));
        }
    }
}

/// 进入站点作用域。仅限**同一个 poll 段**（无 `.await`）：
///
/// ```ignore
/// fn poll_write(...) {
///     let _g = xray_common::alloc_site::enter(xray_common::alloc_site::TLS_WRITE);
///     ...
/// }
/// ```
pub fn enter(site: u8) -> SiteGuard {
    if !enabled() {
        return SiteGuard(None);
    }
    let prev = CURRENT.with(|c| c.replace(site));
    SiteGuard(Some(prev))
}

/// 未来域站点作用域：站点在**每次 poll 期间**生效（bd a65px）。
///
/// [`enter`] 的标记是线程局部的，跨 `.await` 会把标记留在取值时的线程——tokio
/// 把任务挂到别的线程续跑后站点丢失，原线程则永久残留。本函数把站点带进
/// future 的 poll 段：每次 poll 现取现放，跨线程续跑仍归对站点，poll 之间无线程
/// 局部驻留。
///
/// 用法（守卫需要覆盖 `.await` 时一律用它）：
///
/// ```ignore
/// async fn read_downlink(r: &mut dyn Reader) -> Result<MultiBuffer> {
///     xray_common::alloc_site::scope(BUF_READ, r.read_multi_buffer()).await
/// }
/// ```
///
/// 单次、不跨 `.await` 的 poll 段（`poll_read`/`poll_write` 等）仍用 [`enter`]：
/// 少一层包装，且守卫随 poll 调用自然复原。
pub async fn scope<F: Future>(site: u8, fut: F) -> F::Output {
    let mut fut = pin!(fut);
    // 守卫在闭包内取放：poll 返回（含 panic 展开）即复原，不跨 poll 边界留存。
    poll_fn(move |cx| {
        let _g = enter(site);
        fut.as_mut().poll(cx)
    })
    .await
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        sync::Mutex,
        task::{Context, Poll, Waker},
    };

    use super::*;

    /// 三个用例共享进程级 `ENABLED` 静态，并行跑会互踩（disabled 用例断言全局关，
    /// enabled 用例临时开）——串行化。
    static STATE_LOCK: Mutex<()> = Mutex::new(());

    /// 还原开关，避免影响并行测试进程内的其他用例（同进程测试共享静态）。
    struct EnabledGuard;
    impl EnabledGuard {
        fn set() -> Self {
            set_enabled(true);
            EnabledGuard
        }
    }
    impl Drop for EnabledGuard {
        fn drop(&mut self) {
            set_enabled(false);
        }
    }

    #[test]
    fn disabled_guard_is_noop() {
        let _serial = STATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        set_enabled(false);
        // 未启用：enter 不改当前标记、drop 无副作用（零记账路径）。
        {
            let _g = enter(TLS_WRITE);
            assert_eq!(current(), NONE);
        }
        assert_eq!(current(), NONE);
    }

    #[test]
    fn guard_sets_and_restores() {
        let _serial = STATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _on = EnabledGuard::set();
        assert_eq!(current(), NONE);
        {
            let _g = enter(TLS_WRITE);
            assert_eq!(current(), TLS_WRITE);
            // 嵌套：内层替换、内层 drop 恢复到外层。
            {
                let _inner = enter(XHTTP_SRV_SEND);
                assert_eq!(current(), XHTTP_SRV_SEND);
            }
            assert_eq!(current(), TLS_WRITE);
        }
        assert_eq!(current(), NONE);
    }

    #[test]
    fn guard_restores_on_panic() {
        let _serial = STATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _on = EnabledGuard::set();
        let result = std::panic::catch_unwind(|| {
            let _g = enter(VLESS_ENC_SEAL);
            panic!("scope abort");
        });
        assert!(result.is_err());
        assert_eq!(current(), NONE);
    }

    #[test]
    fn record_accumulates_per_site() {
        let _serial = STATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _on = EnabledGuard::set();
        let before = snapshot();
        record(TLS_WRITE, 2, 128);
        record(XHTTP_SRV_SEND, 1, 64);
        let after = snapshot();
        assert_eq!(after[TLS_WRITE as usize].n, before[TLS_WRITE as usize].n + 2);
        assert_eq!(after[TLS_WRITE as usize].bytes, before[TLS_WRITE as usize].bytes + 128);
        assert_eq!(
            after[XHTTP_SRV_SEND as usize].bytes,
            before[XHTTP_SRV_SEND as usize].bytes + 64
        );
        // NONE 位恒不记账。
        assert_eq!(after[NONE as usize].n, 0);
    }

    /// 让出点：首次 poll 返回 Pending 并自唤醒，再次 poll 通过。
    ///
    /// 手动 poll（不经 tokio）以便把"续跑线程"钉死在别的线程——这是 tokio
    /// 把 Pending 任务挂到其他 worker 的等价复现，且不带调度随机性。
    struct YieldOnce(bool);

    impl Future for YieldOnce {
        type Output = ();

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            let this = self.get_mut(); // YieldOnce: Unpin（bool）
            if this.0 {
                return Poll::Ready(());
            }
            this.0 = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }

    /// 模型化统计分配器钩子（与 xray-cli `StatsAlloc::alloc` 同形）：读当前
    /// 线程站点 → 记到该站点。迁移线程上读到 NONE 就是站点丢失。
    fn alloc_like_hook() {
        let site = current();
        if site != NONE {
            record(site, 1, 0);
        }
    }

    /// bd a65px 回归：两个并发任务各带不同站点、途中让出、再换线程续跑。
    /// 两处断言都是判别式——旧写法（`enter` 后 `.await`）都会红：
    /// ①poll 之间原线程残留标记（后续同线程分配被串到该站点）；
    /// ②续跑线程上站点丢失（`current()` 读到 NONE，归因静默丢弃）。
    #[test]
    fn scope_keeps_sites_apart_across_threads() {
        let _serial = STATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _on = EnabledGuard::set();
        let before = snapshot();

        let mut a = std::pin::pin!(scope(TLS_WRITE, async {
            alloc_like_hook();
            YieldOnce(false).await;
            alloc_like_hook();
        }));
        let mut b = std::pin::pin!(scope(XHTTP_SRV_SEND, async {
            alloc_like_hook();
            YieldOnce(false).await;
            alloc_like_hook();
        }));

        let mut cx = Context::from_waker(Waker::noop());

        // 线程 1：两任务各 poll 一次，都停在让出点。
        assert!(a.as_mut().poll(&mut cx).is_pending());
        assert!(b.as_mut().poll(&mut cx).is_pending());
        assert_eq!(current(), NONE, "poll 之间不得残留站点标记");

        // 线程 2：两任务迁到这里续跑完（模拟 tokio 任务换 worker）。
        std::thread::scope(|s| {
            s.spawn(move || {
                // Context 非 Send，须在续跑线程本地构造。
                let mut cx = Context::from_waker(Waker::noop());
                assert_eq!(current(), NONE, "续跑线程起始无站点标记");
                assert!(a.as_mut().poll(&mut cx).is_ready());
                assert_eq!(current(), NONE, "poll 结束后不得残留站点标记");
                assert!(b.as_mut().poll(&mut cx).is_ready());
                assert_eq!(current(), NONE, "poll 结束后不得残留站点标记");
            });
        });

        // 归因计数不串：两站点各 2 次，一次都没落到"未标记"桶。
        let after = snapshot();
        assert_eq!(after[TLS_WRITE as usize].n, before[TLS_WRITE as usize].n + 2);
        assert_eq!(after[XHTTP_SRV_SEND as usize].n, before[XHTTP_SRV_SEND as usize].n + 2);
        assert_eq!(after[NONE as usize].n, before[NONE as usize].n);
    }
}
