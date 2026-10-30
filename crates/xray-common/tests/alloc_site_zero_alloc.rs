//! 站点查表零堆分配（bd 24a5k 验收）：`find` 全路径不触发 `GlobalAlloc`。
//!
//! 集成测试二进制独占一个全局分配器，不影响 crate 内的单测。

use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicUsize, Ordering},
};

use skeleton_infra::alloc_site::find;
use xray_common::alloc_site::SITE_TABLE;

struct Counting;

static ALLOCS: AtomicUsize = AtomicUsize::new(0);

// SAFETY: 全部方法逐字转发 System 分配器（realloc/alloc_zeroed 走默认实现的
// 转发路径，同样经本 alloc 计数），分配契约不变。
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
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

#[test]
fn find_does_not_allocate() {
    // 预热：先取一次，把任何一次性初始化排除在计数窗之外。
    assert!(find(SITE_TABLE, "tls_read").is_some());
    let before = ALLOCS.load(Ordering::Relaxed);

    for _ in 0..1000 {
        assert!(find(SITE_TABLE, "tls_read").is_some(), "命中");
        assert!(find(SITE_TABLE, "no_such_site").is_none(), "未命中");
    }

    assert_eq!(ALLOCS.load(Ordering::Relaxed), before, "站点查表必须零堆分配");
}
