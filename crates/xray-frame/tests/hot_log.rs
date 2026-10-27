//! 面 4 验收（G4）：热路径门面 —— 栈缓冲**零堆分配** + 截断计数正确 +
//! 级别前置过滤（未命中级别零成本）。
//!
//! 分配计数用**线程局部**计数分配器（只计当前线程的分配 → 免受测试框架
//! 其他线程干扰）；分配器内读 thread_local 必须 `try_with`（TLS 析构期
//! `with` 会 panic → 分配器内 panic = abort）。

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    io::Write,
    sync::{Arc, Mutex},
};

use xray_frame::logging::{HotBuf, HotLog};

thread_local! {
    static ALLOCS: Cell<u64> = const { Cell::new(0) };
}

struct CountingAlloc;

fn note_alloc() {
    // TLS 析构期 `with` 会 panic（分配器内 panic = abort）→ 必须 try_with。
    let _ = ALLOCS.try_with(|c| c.set(c.get() + 1));
}

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note_alloc();
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note_alloc();
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        note_alloc();
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

fn alloc_count() -> u64 {
    ALLOCS.with(|c| c.get())
}

#[derive(Clone, Default)]
struct SharedBuf(Arc<Mutex<Vec<u8>>>);

impl SharedBuf {
    fn snapshot(&self) -> String {
        String::from_utf8(self.0.lock().expect("no poison").clone()).expect("utf8")
    }
}

impl Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("no poison").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn capture(buf: SharedBuf) -> tracing::subscriber::DefaultGuard {
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(move || buf.clone())
        .finish();
    tracing::subscriber::set_default(subscriber)
}

#[test]
fn hot_buf_formats_without_heap_allocation() {
    let mut buf = HotBuf::<64>::new();
    // 预热（首次调用可能触发一次性初始化）+ 复位缓冲。
    buf.write_fmt(format_args!("warmup {}", 1));
    buf.clear();
    let before = alloc_count();
    buf.write_fmt(format_args!("seq={} peer={}", 42, "1.2.3.4:443"));
    let after = alloc_count();
    assert_eq!(after - before, 0, "栈缓冲格式化零堆分配");
    assert_eq!(buf.as_str(), "seq=42 peer=1.2.3.4:443");
    assert!(!buf.truncated(), "未溢出");
}

#[test]
fn hot_buf_truncates_and_counts() {
    let mut buf = HotBuf::<8>::new();
    buf.write_fmt(format_args!("0123456789abcdef"));
    assert!(buf.truncated(), "溢出 → 截断标记");
    assert_eq!(buf.as_str(), "01234567", "保留能放下的前缀");
}

#[test]
fn hot_buf_truncation_keeps_char_boundary() {
    let mut buf = HotBuf::<3>::new();
    // "aéb" = 4 字节（é 占 2 字节）；3 字节缓冲放不下 → 只能放 3 字节（"aé"）。
    buf.write_fmt(format_args!("aéb"));
    assert!(buf.truncated(), "溢出 → 截断标记");
    assert_eq!(buf.as_str(), "aé", "截断不切碎多字节字符");
}

#[test]
fn disabled_level_costs_zero_allocation() {
    let hot = HotLog::with_target("xray_frame::hot_test")
        .with_max_level(tracing::level_filters::LevelFilter::INFO);
    // 预热（级别判定本身零分配，此处只作对照）。
    let _ = hot.enabled(tracing::Level::DEBUG);
    let before = alloc_count();
    assert!(!hot.enabled(tracing::Level::DEBUG), "本地级别上限拦下 DEBUG");
    let after = alloc_count();
    assert_eq!(after - before, 0, "未命中级别 → 零堆分配");
}

#[test]
fn hot_log_emits_message_with_target() {
    let buf = SharedBuf::default();
    let _guard = capture(buf.clone());
    let hot = HotLog::with_target("xray_frame::hot_emit");
    let mut hb = HotBuf::<64>::new();
    hb.write_fmt(format_args!("vision inner read error"));
    hot.log(tracing::Level::WARN, &hb);
    let out = buf.snapshot();
    assert!(out.contains("xray_frame::hot_emit"), "target 缺失: {out}");
    assert!(out.contains("vision inner read error"), "message 缺失: {out}");
}

#[test]
fn hot_log_debug_fmt_formats_into_stack_buffer() {
    let buf = SharedBuf::default();
    let _guard = capture(buf.clone());
    let hot = HotLog::with_target("xray_frame::hot_fmt");
    hot.debug_fmt(format_args!("peer={} bytes={}", "10.0.0.1", 128));
    let out = buf.snapshot();
    assert!(out.contains("peer=10.0.0.1 bytes=128"), "message 缺失: {out}");
}
