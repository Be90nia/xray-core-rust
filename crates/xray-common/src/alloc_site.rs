//! 站点级分配归因标记（bd z02z8）：代码路径用 `enter` 声明"当前处于站点 X"，
//! 计数分配器（xray-cli `StatsAlloc`）在 alloc 钩子里按当前线程站点把增量记到
//! 对应站点计数上，周期 dump 按 `[xray-alloc-sites]` 前缀输出。
//!
//! # 门控
//!
//! `ENABLED`（私有）由 xray-cli `alloc_stats::init()` 按 `XRAY_ALLOC_STATS_SITES` 置位。
//! 未启用时 `enter` 直通（不触碰 TLS、不返回需恢复的守卫），alloc 钩子在
//! COUNTING 分支短路——默认零记账开销（对齐 alloc_stats 直通纪律）。
//!
//! # 线程局部语义（限制）
//!
//! 站点标记是**线程局部**的：async 任务跨 `.await`/跨线程移动后标记不跟随，
//! 只归集守卫存活期间在当前线程上的同步分配。写路径（poll_write/poll_next）
//! 是无 `.await` 的 poll 段，语义精确成立；跨线程聚合归"未标记"桶。
//!
//! # udf 判定
// udf-promotion-candidate: 提炼条件=零 xray 具体类型（本文件已满足：纯进程级
// 机制，站点目录由消费方编译期注册）；待 udf 接线闸（P0-9）开后上浮 skeleton-infra。

use std::{
    cell::Cell,
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

/// 站点目录（索引 = 站点 id；新站点只能追加，禁重编号——dump 行与归集脚本按名对齐）。
pub const SITE_NAMES: [&str; 4] = ["(none)", "tls_write", "xhttp_srv_send", "vless_enc_seal"];

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

/// 进入站点作用域。典型用法（poll 段内，无 `.await`）：
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

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

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
}
