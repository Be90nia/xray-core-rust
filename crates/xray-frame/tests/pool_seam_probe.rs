//! 池接缝 idle 记账方向回归锚（审计 A-03 / P1-7）。
//!
//! **语义（修复后）**：接缝**不持有闲槽**（物理存储委托 `xray_buf::alloc/release`）⇒
//! `idle` 恒 `0`（「已归还次数」不是「闲槽数」）、`dropped_overflow` 恒 `0`（接缝不做
//! 去留裁决，归还恒回 xray-buf）、归还不因 `idle_cap` 触顶而被挡在池外。
//!
//! **修复前症状（E1，`pooling-census-app-framework.md` §2.1）**：生产常量
//! `MAX=1024`/`IDLE_CAP=64` 下连续借还 100 次 ⇒ `idle==64`、`dropped_overflow==36`
//! ⇒ 第 65 次起的归还全被判「槽满丢弃」，缓冲再也回不到 xray-buf 分层池（接线即静默退化）。
//!
//! 复现：
//! ```text
//! set BORING_BSSL_ASSUME_PATCHED=1
//! set BORING_BSSL_PATH=D:\Project\Xray-core-rust\target\boringssl-asm\prebuilt
//! set PROTOC=D:/Project/tools/bin/protoc.exe
//! set LIBCLANG_PATH=D:\Program Files\llvm\bin
//! cargo test -p xray-frame --test pool_seam_probe -- --nocapture
//! ```

use std::sync::{Mutex, MutexGuard, PoisonError};

use xray_frame::{BufferPool, ManagedBufferPool, XrayBufPool};

/// 生产 `production_buffer_pool()` 的常量（`xray-core/src/feature_framework.rs`）。
const MAX: usize = 1024;
const IDLE_CAP: usize = 64;

/// 触碰 xray-buf 全局池（TLS 缓存/分片）的测试必须串行：`alloc` 先弹本线程 TLS
/// 缓存，同文件内并发用例会把别案的块取走。
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

/// 探针①：越过 `idle_cap` 的归还**仍是归还**（不计闲槽、不计丢弃）。
#[test]
fn seam_idle_stays_zero_past_idle_cap() {
    let _g = serial();
    let pool = XrayBufPool::new(MAX, IDLE_CAP);
    for i in 0..200 {
        pool.acquire(4096).expect("within max").release();
        let m = pool.metrics();
        assert_eq!(m.borrowed, 0, "第 {i} 次归还后 borrowed 必须归零");
        assert_eq!(m.idle, 0, "第 {i} 次：接缝不持闲槽 ⇒ idle 恒 0（旧实现此处累加到 64）");
        assert_eq!(m.dropped_overflow, 0, "第 {i} 次：接缝不做去留裁决 ⇒ 无溢出丢弃");
    }
}

/// 探针②：双层壳（`ManagedBufferPool` 外套 `XrayBufPool`）同一个口径——
/// 外层账本读数同样不得把归还计成闲槽/丢弃。
#[test]
fn managed_seam_idle_stays_zero_past_idle_cap() {
    let _g = serial();
    let pool = ManagedBufferPool::new(XrayBufPool::new(MAX, IDLE_CAP), MAX, IDLE_CAP);
    for _ in 0..200 {
        pool.acquire(8192).expect("within max").release();
    }
    let m = pool.metrics();
    assert_eq!((m.borrowed, m.idle, m.dropped_overflow), (0, 0, 0), "外层账本同口径");
}

/// 探针③：**归还成功且能再次取出**——归还后同线程再借，必须拿回同一块
/// （xray-buf 的 TLS 层缓存是 LIFO，同线程 `alloc` 先弹 TLS）。
///
/// 旁证口径（与 xray-buf 自己的 `alloc_64k_request_lands_exact_tier` 同款）：只证明
/// 「块回到了池的复用路径」，不证明「一定是同一物理地址」（分配器 free-list 巧合
/// 理论上可同址）。硬判据是探针①②的记账断言 + `pool.rs` 单测
/// `managed_pool_routes_every_return_to_inner_storage` 的底层归还计数。
#[test]
fn seam_release_is_reusable_from_xray_buf() {
    let _g = serial();
    let pool = XrayBufPool::new(MAX, IDLE_CAP);
    let first = pool.acquire(64 * 1024).expect("within max");
    let addr = first.payload().as_ptr() as usize;
    first.release();

    // 越过 idle_cap 后仍必须复用（旧实现此处已开始丢弃 ⇒ 走新鲜分配）。
    for _ in 0..(IDLE_CAP + 8) {
        let buf = pool.acquire(64 * 1024).expect("within max");
        assert_eq!(buf.payload().capacity(), 64 * 1024, "64KB 请求仍落精确 64KB 层");
        buf.release();
    }
    let again = pool.acquire(64 * 1024).expect("within max");
    assert_eq!(
        again.payload().as_ptr() as usize,
        addr,
        "归还的块必须回到池的复用路径（TLS LIFO 同块）"
    );
    again.release();
}
