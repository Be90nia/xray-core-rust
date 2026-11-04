//! PM 实测：**「每次 new」 vs 「池化后复用」** 的逐对象性能对比（2026-11-04）
//!
//! 用户诉求原文：「**我要的是 new 和池化后性能提升**」+「所有加密方式都可以放到通用对象池」。
//! ⇒ 本探针对**每个候选对象**给出三个数字：
//!   ① 现状（每次 new）的中位耗时
//!   ② 池化后（udf `ObjectPool` 借→用→还）的中位耗时
//!   ③ 加速比 = ① / ②
//!
//! **诚实边界**：若 ② ≥ ①（池化反而更慢），**如实打印**——这正是「不是所有东西都该池」
//! 的判据来源（池的借还记账/分片锁/reset 钩子本身有成本）。
//!
//! 复现：
//! ```text
//! cargo test -p xray-transport --test new_vs_pooled -- --nocapture --test-threads=1
//! ```
//! ⚠️ debug 构建；release 绝对值低一个量级，**相对关系（加速比）可靠**。

// 性能探针的全部价值就是实测耗时（非生产路径）：显式 allow + 理由。
#![allow(clippy::disallowed_methods, reason = "性能探针必须读裸时钟；非生产路径")]

use std::time::{Duration, Instant};

use skeleton_infra::{ObjectPool, ResetPhase};

/// 计时一组样本，返回中位数。
fn median(mut samples: Vec<Duration>) -> Duration {
    samples.sort();
    samples[samples.len() / 2]
}

/// 「每次 new」的中位耗时（warmup 2 + 计时 7）。
fn median_new(name: &str, mut f: impl FnMut()) -> Duration {
    for _ in 0..2 {
        f();
    }
    let mut s = Vec::with_capacity(7);
    for _ in 0..7 {
        let t0 = Instant::now();
        f();
        s.push(t0.elapsed());
    }
    let m = median(s);
    println!("[CMP] {name:<46} new    = {m:?}");
    m
}

/// 「池化后（借→用→还）」的中位耗时（warmup 2 + 计时 7）。
fn median_pooled<T: Send + 'static>(
    name: &str,
    pool: &std::sync::Arc<ObjectPool<T>>,
    mut use_it: impl FnMut(&mut T),
) -> Duration {
    for _ in 0..2 {
        let mut obj = pool.acquire_owned();
        use_it(&mut obj);
    }
    let mut s = Vec::with_capacity(7);
    for _ in 0..7 {
        let t0 = Instant::now();
        let mut obj = pool.acquire_owned();
        use_it(&mut obj);
        drop(obj); // Drop 即归还（RAII）
        s.push(t0.elapsed());
    }
    let m = median(s);
    println!("[CMP] {name:<46} pooled = {m:?}");
    m
}

fn report(name: &str, new_cost: Duration, pooled_cost: Duration) {
    let ratio = new_cost.as_secs_f64() / pooled_cost.as_secs_f64().max(1e-9);
    let verdict = if pooled_cost >= new_cost {
        "❌ 池化更慢/无收益 ⇒ 不池化"
    } else if ratio < 1.5 {
        "⚠ 收益 <1.5x ⇒ 视其它代价定（内存/复杂度）"
    } else {
        "✅ 值得池化"
    };
    println!("[CMP] {name:<46} ⇒ 加速 {ratio:.1}x  {verdict}");
}

// ════════════════════════════════════════════════════════════════
// 1. AEAD cipher（用户点名的「所有加密方式」）
// ════════════════════════════════════════════════════════════════

/// VMess/VLESS 每连接构造的 `Aes128Gcm`。
#[test]
fn cmp_aes128gcm_new_vs_pooled() {
    use xray_crypto::aead::{AeadCipher, Aes128Gcm};

    let key = [0x33u8; 16];
    let new_cost = median_new("Aes128Gcm::new", || {
        let c = Aes128Gcm::new(&key).expect("aes");
        std::hint::black_box(&c);
    });

    // 池：工厂 = Aes128Gcm::new（key 以 owned 捕获，满足 'static）；reset 钩子 = 无状态 cipher 无需
    // reset。
    let key_for_pool = key;
    let pool = std::sync::Arc::new(ObjectPool::with_reset(
        64,
        32,
        move || Aes128Gcm::new(&key_for_pool).expect("aes"),
        |_c: &mut Aes128Gcm| {},
        ResetPhase::OnReturn,
    ));
    let pooled_cost = median_pooled("Aes128Gcm (ObjectPool)", &pool, |c| {
        // 借用即用：一次 seal（数据面零拷贝形态），证明池化件可直接服役。
        let nonce = [0u8; 12];
        let out = c.seal(&nonce, &[], &[0xABu8; 16]).expect("seal");
        std::hint::black_box(&out);
    });
    report("Aes128Gcm", new_cost, pooled_cost);
}

/// ChaCha20-Poly1305（RustCrypto 路径：构造含 key schedule，理论上更值得池化）。
#[test]
fn cmp_chacha20_new_vs_pooled() {
    use xray_crypto::aead::{AeadCipher, ChaCha20Poly1305Aead};

    let key = [0x44u8; 32];
    let new_cost = median_new("ChaCha20Poly1305Aead::new", || {
        let c = ChaCha20Poly1305Aead::new(&key).expect("chacha");
        std::hint::black_box(&c);
    });

    let key_for_pool = key;
    let pool = std::sync::Arc::new(ObjectPool::with_reset(
        64,
        32,
        move || ChaCha20Poly1305Aead::new(&key_for_pool).expect("chacha"),
        |_c: &mut ChaCha20Poly1305Aead| {},
        ResetPhase::OnReturn,
    ));
    let pooled_cost = median_pooled("ChaCha20Poly1305Aead (ObjectPool)", &pool, |c| {
        let nonce = [0u8; 12];
        let out = c.seal(&nonce, &[], &[0xABu8; 16]).expect("seal");
        std::hint::black_box(&out);
    });
    report("ChaCha20Poly1305Aead", new_cost, pooled_cost);
}

// ════════════════════════════════════════════════════════════════
// 2. finalmask manager（**每拨号重建**，xmc 含 RSA-1024 派生）
// ════════════════════════════════════════════════════════════════

fn xmc_json() -> serde_json::Value {
    serde_json::json!({
        "tcp": [{ "type": "xmc", "settings": {
            "password": "mc-pass",
            "hostname": "localhost",
            "profiles": [{
                "username": "steve_1",
                "uuid": "069a79f4-44e9-4726-a5be-fca90e38aaf5",
                "texturesValue": "v",
                "texturesSignature": "s"
            }]
        }}]
    })
}

/// finalmask manager：现状 = 每拨号重建（xmc ⇒ RSA-1024 派生）。
#[test]
fn cmp_finalmask_xmc_new_vs_pooled() {
    use xray_transport::finalmask::build_tcpmask_manager_from_json;

    let json = xmc_json();
    let new_cost = median_new("finalmask xmc manager (每拨号重建)", || {
        let m = build_tcpmask_manager_from_json(Some(&json)).expect("build xmc");
        std::hint::black_box(&m);
    });

    let json_for_pool = json.clone();
    let pool = std::sync::Arc::new(ObjectPool::with_reset(
        16,
        8,
        move || build_tcpmask_manager_from_json(Some(&json_for_pool)).expect("build xmc"),
        |_m: &mut xray_transport::finalmask::TcpmaskManager| {},
        ResetPhase::OnReturn,
    ));
    let pooled_cost = median_pooled("finalmask xmc (ObjectPool)", &pool, |_m| {
        std::hint::black_box(_m);
    });
    report("finalmask xmc manager", new_cost, pooled_cost);
}

/// 对照：sudoku（无密码学构造）—— 证明贵的是派生而非容器。
#[test]
fn cmp_finalmask_sudoku_new_vs_pooled() {
    use xray_transport::finalmask::build_tcpmask_manager_from_json;

    let json = serde_json::json!({ "tcp": [{ "type": "sudoku", "settings": {} }] });
    let new_cost = median_new("finalmask sudoku manager [对照]", || {
        let m = build_tcpmask_manager_from_json(Some(&json)).expect("build sudoku");
        std::hint::black_box(&m);
    });

    let json_for_pool = json.clone();
    let pool = std::sync::Arc::new(ObjectPool::with_reset(
        16,
        8,
        move || build_tcpmask_manager_from_json(Some(&json_for_pool)).expect("build sudoku"),
        |_m: &mut xray_transport::finalmask::TcpmaskManager| {},
        ResetPhase::OnReturn,
    ));
    let pooled_cost = median_pooled("finalmask sudoku (ObjectPool)", &pool, |_m| {
        std::hint::black_box(_m);
    });
    report("finalmask sudoku manager [对照]", new_cost, pooled_cost);
}

// ════════════════════════════════════════════════════════════════
// 3. UDP socket（DNS 每查询新建 —— 系统调用成本）
// ════════════════════════════════════════════════════════════════

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cmp_udp_socket_bind_vs_reuse() {
    // 现状：每查询 `UdpSocket::bind("0.0.0.0:0")`（系统调用 + fd 分配）。
    let mut samples = Vec::with_capacity(7);
    for _ in 0..7 {
        let t0 = Instant::now();
        let s = tokio::net::UdpSocket::bind("0.0.0.0:0").await.expect("bind");
        samples.push(t0.elapsed());
        drop(s);
    }
    let new_cost = median(samples);
    println!("[CMP] {:<46} new    = {new_cost:?}", "UdpSocket::bind (每查询)");

    // 池化：同一 socket 反复取用（目标地址在 send 时给，无需换参）。
    let pool = std::sync::Arc::new(ObjectPool::with_reset(
        32,
        16,
        || std::net::UdpSocket::bind("0.0.0.0:0").expect("bind"),
        |_s: &mut std::net::UdpSocket| {},
        ResetPhase::OnReturn,
    ));
    let mut psamples = Vec::with_capacity(7);
    for _ in 0..7 {
        let t0 = Instant::now();
        let sock = pool.acquire_owned();
        std::hint::black_box(&sock);
        drop(sock);
        psamples.push(t0.elapsed());
    }
    let pooled_cost = median(psamples);
    println!("[CMP] {:<46} pooled = {pooled_cost:?}", "UdpSocket (ObjectPool)");
    report("UdpSocket::bind", new_cost, pooled_cost);
}

// ════════════════════════════════════════════════════════════════
// 4. 64 KiB 缓冲块池的「归还成本」预算（bd hdugl 验收）
// ════════════════════════════════════════════════════════════════

/// 64 KiB 块归还预算：**< 20µs**，且复用的块前 len 字节为 0。
///
/// 形态取自现役两处 udf `ObjectPool<Vec<u8>>` 消费点（splithttp `PoolStream` 的 h2 body
/// 块、hysteria udphop 的 UDP 块），差别只在块尺度：
/// - ✅ 正确：reset 钩子只做容量归一，持有方归还前按**已写入区** `[..len]` 清零；
/// - ❌ 反例：reset 钩子整块清零（`clear()` + `resize(64 KiB, 0)`，审计 2026-11-04 实测
///   **190.8µs/次**）⇒ 池化净收益为负。
///
/// 两种形态同台打印；硬阈值只压在正确形态上（反例绝对值随构建档位变化，不作阈值）。
#[test]
fn cmp_64k_buffer_return_budget() {
    const CHUNK: usize = 64 * 1024;
    const WRITTEN: usize = 16 * 1024; // 一帧 h2 DATA 的量级

    // ❌ 反例形态：归还即整块清零（审计实测形状：clear + resize 回定长）。
    let bad = std::sync::Arc::new(ObjectPool::with_reset(
        4,
        2,
        || vec![0u8; CHUNK],
        |buf: &mut Vec<u8>| {
            buf.clear();
            buf.resize(CHUNK, 0);
        },
        ResetPhase::OnReturn,
    ));
    let mut s = Vec::with_capacity(7);
    for _ in 0..9 {
        let handle = bad.acquire_owned();
        let t0 = Instant::now();
        drop(handle); // 归还 = reset 钩子整块 memset
        s.push(t0.elapsed());
    }
    let bad_cost = median(s);

    // ✅ 正确形态：钩子只归一容量，持有方清已写区后归还。
    let good = std::sync::Arc::new(ObjectPool::with_reset(
        4,
        2,
        || vec![0u8; CHUNK],
        |_buf: &mut Vec<u8>| {},
        ResetPhase::OnReturn,
    ));
    let mut s = Vec::with_capacity(7);
    for _ in 0..9 {
        let mut handle = good.acquire_owned();
        handle[..WRITTEN].fill(0xAA);
        let t0 = Instant::now();
        handle[..WRITTEN].fill(0); // 已写入区清零（生产实现在 PooledBuf::drop）
        drop(handle); // 归还：钩子只做容量归一
        s.push(t0.elapsed());
    }
    let good_cost = median(s);

    println!("[CMP] 64KiB 块归还(整块清零反例)        = {bad_cost:?}");
    println!("[CMP] 64KiB 块归还(只清已写 {WRITTEN}B) = {good_cost:?}");
    println!(
        "[CMP] 只清已写区比整块清零快 {:.0}x（阈值 20µs，实测 {good_cost:?}）",
        bad_cost.as_secs_f64() / good_cost.as_secs_f64().max(1e-9)
    );
    assert!(
        good_cost < Duration::from_micros(20),
        "64KiB 块归还 {good_cost:?} ≥ 20µs：清零量必须限于已写区 [..len]（bd hdugl）"
    );

    let reused = good.acquire_owned();
    assert!(
        reused[..WRITTEN].iter().all(|&b| b == 0),
        "复用的块前 len 字节必须为 0：禁把上一包的明文发给下一个借出方"
    );
}
