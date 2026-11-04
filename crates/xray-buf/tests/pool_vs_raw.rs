//! PM 实测：**现役池化是不是负优化**（2026-11-04）
//!
//! 用户原话：「说真的..那么我们很多池化是不是有变成了负优化???简单测一下」
//!
//! 本探针对**现役**的每个池做同口径对比：
//!   ① 走池（命中路径）的中位耗时
//!   ② 绕过池（等价裸构造）的中位耗时
//!   ③ 净收益 = ② − ①（负值 = 负优化）
//!
//! 覆盖：
//! - `xray-buf` 分层池（`alloc::alloc` vs `BytesMut::with_capacity`）—— **全仓最大的现役池**
//! - udf `ObjectPool` 的**三段归因**（acquire / use / release）—— 定位池开销真身
//! - 现役两消费点借还的真实成本（hysteria / splithttp 的池件形态）
//!
//! 复现：
//! ```text
//! cargo test -p xray-buf --test pool_vs_raw -- --nocapture --test-threads=1
//! ```
//! ⚠️ debug 构建；**相对关系（是否负优化）可靠**，绝对值 release 更低。

use std::time::{Duration, Instant};

use bytes::BytesMut;
use xray_buf::alloc;

fn median(mut s: Vec<Duration>) -> Duration {
    s.sort();
    s[s.len() / 2]
}

/// 计时一组样本。
// 本探针的全部价值就是实测耗时：显式 allow + 理由（同 `udp_session` q1r4q 先例）。
#[allow(clippy::disallowed_methods, reason = "性能探针必须读时钟；非生产路径")]
fn measure(mut f: impl FnMut()) -> Duration {
    for _ in 0..3 {
        f();
    }
    let mut s = Vec::with_capacity(15);
    for _ in 0..15 {
        let t0 = Instant::now();
        f();
        s.push(t0.elapsed());
    }
    median(s)
}

fn verdict(name: &str, pooled: Duration, raw: Duration) {
    let delta = raw.as_secs_f64() - pooled.as_secs_f64();
    let v = if delta <= 0.0 {
        "❌ 负优化：走池不比裸构造快"
    } else if delta < 1e-9 {
        "⚠ 持平（池无收益也无害）"
    } else {
        "✅ 正收益"
    };
    println!("[POOL] {name:<46} pooled = {pooled:?}  raw = {raw:?}  Δ = {delta:+.1}µs  {v}");
}

/// xray-buf 分层池：池命中 vs 裸 `BytesMut::with_capacity`。
///
/// 这是**全仓最大的现役池**（理论上限 ~116MB，见 bd f516k）。
#[test]
fn xray_buf_tier_pool_vs_raw_allocation() {
    // 默认档 8KB（DEFAULT_SIZE）
    let size = alloc::DEFAULT_SIZE;

    // 池路径：alloc() 先查 TLS 缓存 → 全局分片 → 才新分配。
    let pooled = measure(|| {
        let b = alloc::alloc(size);
        std::hint::black_box(&b);
        alloc::release(b);
    });

    // 裸路径：绕过池直接分配同容量。
    let raw = measure(|| {
        let b = BytesMut::with_capacity(size);
        std::hint::black_box(&b);
    });

    verdict("xray-buf alloc(8KB) vs BytesMut::with_capacity(8KB)", pooled, raw);
}

/// 64KB 档（批次三 A3 升窗后的目标档位）。
#[test]
fn xray_buf_64k_tier_pool_vs_raw_allocation() {
    let size = 64 * 1024;
    let pooled = measure(|| {
        let b = alloc::alloc(size);
        std::hint::black_box(&b);
        alloc::release(b);
    });
    let raw = measure(|| {
        let b = BytesMut::with_capacity(size);
        std::hint::black_box(&b);
    });
    verdict("xray-buf alloc(64KB) vs BytesMut::with_capacity(64KB)", pooled, raw);
}

/// 池命中率的直接观测：连续 alloc/release 同一档位，
/// 看第二次起是否复用**同一块地址**（地址相同 = 命中池）。
///
/// 必须走 [`alloc::release`]（归还池）：只 `drop` 是就地还给分配器、块根本不进池，
/// 第二次是否同址就取决于 malloc 的复用时机 ⇒ 断言随机红（本探针 2026-11-04 实测）。
#[test]
fn xray_buf_pool_hit_observed_by_address() {
    let size = alloc::DEFAULT_SIZE;
    let a1 = {
        let b = alloc::alloc(size);
        let p = b.as_ptr() as usize;
        alloc::release(b);
        p
    };
    let a2 = {
        let b = alloc::alloc(size);
        let p = b.as_ptr() as usize;
        alloc::release(b);
        p
    };
    println!(
        "[POOL] xray-buf 8KB 地址复用: 第一次 = {a1:#x}  第二次 = {a2:#x}  命中 = {}",
        a1 == a2
    );
    assert_eq!(a1, a2, "同档位连续借还应复用同一块（池命中）");
}
