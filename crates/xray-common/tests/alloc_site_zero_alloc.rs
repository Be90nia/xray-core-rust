//! 站点查表零堆分配（bd 24a5k 验收）：`find` 全路径不触发 `GlobalAlloc`。
//!
//! 集成测试二进制独占一个全局分配器，不影响 crate 内的单测。
//!
//! # 计数口径：按线程归属（bd orbq6）
//!
//! 分配事件计数**按线程归属**——每个线程各数各的，测量只读**发起测量的那个
//! 线程**的计数。原实现用进程级全局计数器，计数窗覆盖全进程：全量并行跑时
//! 其它线程（libtest 输出线程、运行时后台线程）的分配落进同一计数窗，
//! 「零分配」被误判成「有分配」⇒ `find_does_not_allocate` 偶发 FAILED
//! （独立跑该测试恒绿，故只在全量并行门禁上暴露）。
//!
//! 同族教训（udf-frame CI flake 三族之一）：全局 live 计数被并发线程净漂移
//! 打穿——治法是给计数窗加线程归属门，本件即该门的落地形态。
//!
//! 归属判定不依赖任何全局可变状态：计数器本身就是线程局部量，谁分配记到谁
//! 头上，归属天生可靠（无 Relaxed 序、无跨线程竞争面）。
//!
//! 分配器内读 TLS 一律走 `try_with`（TLS 析构期 `with` 会 panic，而分配器内
//! panic = abort）。本件计数器是 `Cell<usize>`（无 Drop ⇒ 无析构注册 ⇒ 无
//! 惰性分配 ⇒ 分配器内读取不递归进分配器）。

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    hint::black_box,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use skeleton_infra::alloc_site::find;
use xray_common::alloc_site::SITE_TABLE;

struct Counting;

// 本线程的分配事件计数（const 初始化：分配器内读取无惰性分配、无析构注册）。
thread_local! {
    static EVENTS: Cell<usize> = const { Cell::new(0) };
}

// SAFETY: 全部方法逐字转发 System 分配器（realloc/alloc_zeroed 走默认实现的
// 转发路径，同样经本 alloc 计数），分配契约不变。
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // try_with: TLS 析构期 `with` 会 panic（分配器内 panic=abort），
        // 取不到就跳过本次记账（本线程此时已不可测）。
        let _ = EVENTS.try_with(|c| c.set(c.get() + 1));
        // SAFETY: 调用方满足 Alloc 契约，System 保证返回值语义
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: ptr 由本分配器 alloc 产出，layout 与之一致
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

/// 本线程累计分配事件数。
fn events() -> usize {
    EVENTS.with(Cell::get)
}

/// 仪器自检：分配事件必须被计到——防「分配器没挂上 ⇒ 恒零 ⇒ 零分配断言假绿」。
#[test]
fn alloc_counter_sees_allocations() {
    let before = events();
    let buf: Vec<u8> = Vec::with_capacity(32);
    black_box(&buf);
    assert!(events() > before, "窗内分配必须被计数（仪器在位）");
}

/// 计数窗的线程归属门回归锚：并发线程的分配**不得**进入本线程的计数窗。
///
/// 原实现用进程级全局计数器，计数窗覆盖全进程 ⇒ 并发线程（libtest 输出
/// 线程、运行时后台线程）的分配落进同一窗口，「零分配」被误判成「有分配」。
/// 本锚用一条持续分配的并发线程把该窗口确定性撑脏：若计数窗再退回进程级
/// 口径，本断言必红。
#[test]
fn concurrent_allocations_stay_out_of_the_window() {
    // 预热：先取一次，把任何一次性初始化排除在计数窗之外。
    assert!(find(SITE_TABLE, "tls_read").is_some());

    let stop = AtomicBool::new(false);
    std::thread::scope(|scope| {
        // 并发线程持续分配，制造真实的跨线程分配流。
        // 每轮新建 Vec（不复用容量）⇒ 每轮必有真实堆分配落进全局分配器。
        let churn = scope.spawn(|| {
            while !stop.load(Ordering::Relaxed) {
                let buf: Vec<u8> = vec![0u8; 4096];
                black_box(&buf);
            }
        });

        // 让并发线程先跑起来，确保窗口期内确有跨线程分配发生。
        std::thread::sleep(Duration::from_millis(50));

        let before = events();
        for _ in 0..1000 {
            assert!(find(SITE_TABLE, "tls_read").is_some(), "命中");
            assert!(find(SITE_TABLE, "no_such_site").is_none(), "未命中");
        }
        let during = events() - before;

        stop.store(true, Ordering::Relaxed);
        churn.join().expect("并发分配线程 panic");

        assert_eq!(during, 0, "并发线程的分配不得进入本线程的计数窗");
    });
}

#[test]
fn find_does_not_allocate() {
    // 预热：先取一次，把任何一次性初始化排除在计数窗之外。
    assert!(find(SITE_TABLE, "tls_read").is_some());
    let before = events();

    for _ in 0..1000 {
        assert!(find(SITE_TABLE, "tls_read").is_some(), "命中");
        assert!(find(SITE_TABLE, "no_such_site").is_none(), "未命中");
    }

    assert_eq!(events() - before, 0, "站点查表必须零堆分配");
}
