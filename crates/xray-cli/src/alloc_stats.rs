#![allow(clippy::disallowed_macros, clippy::print_stdout, clippy::print_stderr)] // CLI 分配统计瞬时告警直写 stderr（初始化早期 tracing 未装）
//! 计数分配器（框架支线 P0 护栏，oracle-framing-arch Phase 0）。
//!
//! `XRAY_ALLOC_STATS=1|true|on` 启用进程级 alloc/dealloc 次数与字节数统计；
//! 默认关闭时 [`StatsAlloc`] 只做一次 Relaxed load 的直通分支——不更新计数、
//! 不起线程，行为与裸 mimalloc 一致（零开销路径）。
//!
//! 启用后由后台线程按 `XRAY_ALLOC_STATS_INTERVAL_MS`（默认 1000）向 stderr
//! 输出 `[xray-alloc-stats]` 前缀的累计行。选周期输出而非 atexit/退出 dump：
//! loopback 采集用 terminate() 杀进程（Windows TerminateProcess 不跑 atexit），
//! 且 relay 空闲期无分配，最后一个周期行即近似终值。
//!
//! 站点级归集（bd z02z8）：`XRAY_ALLOC_STATS_SITES=1` 额外启用，每周期追加
//! `[xray-alloc-sites]` 前缀的按站点行（累计 + 周期增量）。标记机制见
//! `xray_common::alloc_site`；未启用时标记与记账全零开销。
//!
//! 仅 feature `mimalloc`（默认开）下由 bin 接线为全局分配器；
//! `--no-default-features` 回退系统分配器时计数不可用。

use std::{
    alloc::{GlobalAlloc, Layout},
    sync::{
        OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use xray_common::alloc_site::{SITE_NAMES, SiteSnap};

/// 计数开关：init() 一次性置位，热路径只读。
static COUNTING: AtomicBool = AtomicBool::new(false);

/// 累计计数（仅 COUNTING=true 时更新；Relaxed 足够，无同步语义需求）。
static ALLOC_N: AtomicU64 = AtomicU64::new(0);
static ALLOC_BYTES: AtomicU64 = AtomicU64::new(0);
static DEALLOC_N: AtomicU64 = AtomicU64::new(0);
static DEALLOC_BYTES: AtomicU64 = AtomicU64::new(0);

// OnceLock 而非 LazyLock：锚点必须是 init() 被调用的时刻（运行时输入），
// 声明期初始化会把锚点漂移到首次 dump 访问。
static START: OnceLock<Instant> = OnceLock::new();

/// dump 行前缀，采集脚本按此 grep。
pub const STATS_PREFIX: &str = "[xray-alloc-stats]";

/// 站点行前缀（仅 XRAY_ALLOC_STATS_SITES 开启时输出），采集脚本按此 grep。
pub const SITES_PREFIX: &str = "[xray-alloc-sites]";

/// 启用判定独立成纯函数便于单测。
fn parse_flag(v: Option<&str>) -> bool {
    matches!(v, Some("1") | Some("true") | Some("on"))
}

/// dump 间隔解析：非法/零值回落默认 1000ms。
fn parse_interval_ms(v: Option<&str>) -> u64 {
    v.and_then(|s| s.parse().ok()).filter(|&ms| ms > 0).unwrap_or(1000)
}

/// 启动期调用一次（main 首行）。未启用时无任何线程与计数开销。
pub fn init() {
    let flag = std::env::var("XRAY_ALLOC_STATS").ok();
    if !parse_flag(flag.as_deref()) {
        return;
    }
    COUNTING.store(true, Ordering::Relaxed);
    // 站点归集是计数器的附加开关：主开关关时整体直通（零开销纪律）。
    let sites_raw = std::env::var("XRAY_ALLOC_STATS_SITES").ok();
    xray_common::alloc_site::set_enabled(parse_flag(sites_raw.as_deref()));
    #[allow(
        clippy::disallowed_methods,
        reason = "alloc-stats 诊断启动锚点取时；Clock 端口注入待 bd 39hko"
    )]
    let _ = START.set(Instant::now());
    let interval_raw = std::env::var("XRAY_ALLOC_STATS_INTERVAL_MS").ok();
    let interval = Duration::from_millis(parse_interval_ms(interval_raw.as_deref()));
    // init 期前置条件，fail-fast：dump 线程起不来 = 计数无法观测，静默继续没有意义。
    std::thread::Builder::new()
        .name("alloc-stats".into())
        .spawn(move || {
            let mut prev_sites: Option<[SiteSnap; SITE_NAMES.len()]> = None;
            loop {
                std::thread::sleep(interval);
                dump(&mut prev_sites);
            }
        })
        .expect("spawn alloc-stats dumper thread");
}

fn dump(prev_sites: &mut Option<[SiteSnap; SITE_NAMES.len()]>) {
    let a_n = ALLOC_N.load(Ordering::Relaxed);
    let a_b = ALLOC_BYTES.load(Ordering::Relaxed);
    let d_n = DEALLOC_N.load(Ordering::Relaxed);
    let d_b = DEALLOC_BYTES.load(Ordering::Relaxed);
    let t = START.get().map_or(0.0, |s| s.elapsed().as_secs_f64());
    eprintln!(
        "{STATS_PREFIX} t={t:.3}s alloc_n={a_n} alloc_bytes={a_b} \
         dealloc_n={d_n} dealloc_bytes={d_b} live_bytes={}",
        a_b.wrapping_sub(d_b)
    );
    if xray_common::alloc_site::enabled() {
        let snap = xray_common::alloc_site::snapshot();
        // 周期增量：dump 线程序列化输出，prev 即上一周期末累计；首周期增量 = 累计
        // （起点 = 进程零时刻）。累计口径无周期边界误差，站点行供脚本对账。
        let prev = prev_sites.unwrap_or([SiteSnap { n: 0, bytes: 0 }; SITE_NAMES.len()]);
        for (i, name) in SITE_NAMES.iter().enumerate().skip(1) {
            eprintln!(
                "{SITES_PREFIX} t={t:.3}s site={name} alloc_n={} alloc_bytes={} \
                 d_n={} d_bytes={}",
                snap[i].n,
                snap[i].bytes,
                snap[i].n - prev[i].n,
                snap[i].bytes - prev[i].bytes,
            );
        }
        *prev_sites = Some(snap);
    }
}

/// 全局分配器 wrapper：内层为 mimalloc（或测试中的任意 GlobalAlloc）。
pub struct StatsAlloc<A>(pub A);

// SAFETY: 全部方法逐字转发内层 GlobalAlloc，分配契约不变；
// 计数为原子旁路观测，不改变返回值（失败分配不计数）。
unsafe impl<A: GlobalAlloc> GlobalAlloc for StatsAlloc<A> {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: layout 满足 Alloc 契约（调用方前置条件），内层 GlobalAlloc 保证
        let ptr = unsafe { self.0.alloc(layout) };
        if COUNTING.load(Ordering::Relaxed) && !ptr.is_null() {
            ALLOC_N.fetch_add(1, Ordering::Relaxed);
            ALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
            // 站点归集（XRAY_ALLOC_STATS_SITES）：附加开关关闭时仅多一次
            // Relaxed load；current() 是 const-init TLS 访问，无分配不重入。
            if xray_common::alloc_site::enabled() {
                let site = xray_common::alloc_site::current();
                if site != xray_common::alloc_site::NONE {
                    xray_common::alloc_site::record(site, 1, layout.size() as u64);
                }
            }
        }
        ptr
    }

    #[inline]
    // SAFETY: Dealloc 契约——ptr/layout 必须来自配对 alloc 且未释放过（trait 前置条件）
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if COUNTING.load(Ordering::Relaxed) {
            DEALLOC_N.fetch_add(1, Ordering::Relaxed);
            DEALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        }
        // SAFETY: ptr/layout 来自配对 alloc，内层实现保证
        unsafe { self.0.dealloc(ptr, layout) };
    }

    // realloc/alloc_zeroed 用默认实现：路由到 self.alloc/self.dealloc，恰好各计一次。
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 同进程并行测试共享 COUNTING 静态：置位的用例互斥，避免窗口互相污染
    /// （精确 +1 断言要求窗口内无其他计数源）。
    static COUNTING_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn flag_parsing() {
        assert!(parse_flag(Some("1")));
        assert!(parse_flag(Some("true")));
        assert!(parse_flag(Some("on")));
        assert!(!parse_flag(Some("0")));
        assert!(!parse_flag(Some("")));
        assert!(!parse_flag(None));
    }

    #[test]
    fn interval_parsing() {
        assert_eq!(parse_interval_ms(None), 1000);
        assert_eq!(parse_interval_ms(Some("250")), 250);
        assert_eq!(parse_interval_ms(Some("abc")), 1000);
        assert_eq!(parse_interval_ms(Some("0")), 1000);
    }

    #[test]
    fn counters_move_through_wrapper() {
        let _lock = COUNTING_LOCK.lock().unwrap();
        // 用 System 作为内层分配器直接驱动 wrapper，验证计数路径。
        use std::alloc::System;
        COUNTING.store(true, Ordering::Relaxed);
        let alloc = StatsAlloc(System);
        let before_n = ALLOC_N.load(Ordering::Relaxed);
        let before_b = ALLOC_BYTES.load(Ordering::Relaxed);
        let before_dn = DEALLOC_N.load(Ordering::Relaxed);
        let before_db = DEALLOC_BYTES.load(Ordering::Relaxed);
        let layout = Layout::from_size_align(128, 8).unwrap();
        // SAFETY: layout=(128,8) 合法；ptr 所有权归测试并配对 dealloc
        let ptr = unsafe { alloc.alloc(layout) };
        assert!(!ptr.is_null());
        // COUNTING=true 时同进程其他 libtest 线程的分配也计入全局计数——精确
        // 总数（==before+1）在并行进程里不可断言，改相对增量（计数通路仍被钉死：
        // 至少本线程这一笔必须入账，字节数同理）。
        assert!(ALLOC_N.load(Ordering::Relaxed) > before_n);
        assert!(ALLOC_BYTES.load(Ordering::Relaxed) >= before_b + 128);
        // SAFETY: 与上行 alloc 配对，layout 一致且未释放过
        unsafe { alloc.dealloc(ptr, layout) };
        assert!(DEALLOC_N.load(Ordering::Relaxed) > before_dn);
        assert!(DEALLOC_BYTES.load(Ordering::Relaxed) >= before_db + 128);
        // 还原开关，避免影响并行测试进程内的其他用例（同进程测试共享静态）。
        COUNTING.store(false, Ordering::Relaxed);
    }

    #[test]
    fn site_scoped_accounting_and_zero_when_disabled() {
        let _lock = COUNTING_LOCK.lock().unwrap();
        use std::alloc::System;
        let alloc = StatsAlloc(System);
        let layout = Layout::from_size_align(96, 8).unwrap();
        let site = |id: usize| xray_common::alloc_site::snapshot()[id];

        // 未启用（默认态）：站点计数零增量——零记账验收。
        let before = site(xray_common::alloc_site::TLS_WRITE as usize);
        // SAFETY: layout=(96,8) 合法；ptr 所有权归测试并配对 dealloc
        let ptr = unsafe { alloc.alloc(layout) };
        assert!(!ptr.is_null());
        // SAFETY: 与上行 alloc 配对，layout 一致且未释放过
        unsafe { alloc.dealloc(ptr, layout) };
        assert_eq!(
            site(xray_common::alloc_site::TLS_WRITE as usize).n,
            before.n,
            "未启用时站点记账必须为零"
        );

        // 启用：守卫作用域内的 alloc 归集到站点，作用域外不归集。
        COUNTING.store(true, Ordering::Relaxed);
        xray_common::alloc_site::set_enabled(true);
        let before = site(xray_common::alloc_site::TLS_WRITE as usize);
        let before_none = site(xray_common::alloc_site::NONE as usize);
        {
            let _g = xray_common::alloc_site::enter(xray_common::alloc_site::TLS_WRITE);
            // SAFETY: layout 合法；ptr 配对 dealloc
            let ptr = unsafe { alloc.alloc(layout) };
            assert!(!ptr.is_null());
            // SAFETY: 与上行 alloc 配对
            unsafe { alloc.dealloc(ptr, layout) };
        }
        let after = site(xray_common::alloc_site::TLS_WRITE as usize);
        assert_eq!(after.n, before.n + 1);
        assert_eq!(after.bytes, before.bytes + 96);
        // NONE 位恒不记账。
        assert_eq!(site(xray_common::alloc_site::NONE as usize).n, before_none.n);
        // 还原开关，避免影响并行测试进程内的其他用例（同进程测试共享静态）。
        COUNTING.store(false, Ordering::Relaxed);
        xray_common::alloc_site::set_enabled(false);
    }
}
