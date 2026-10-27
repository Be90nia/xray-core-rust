//! SimpleOhm 查表面 A/B 采集器（C 面 R1a 性能门 · ns/op）。
//!
//! 对应 gate：`docs/architecture/xray-frame-能力收敛方案-2026-10-27.md` §10.1 **R1 行**
//! 「热路径改动 → 同窗 A/B 吞吐 ≥3 轮不降」的**查表面微观锚**——SimpleOhm 的
//! `get_handler`/`select_handler` 是 dispatch 每次选路的唯一查表面。
//!
//! 只用 `SimpleOhm` 的**公开 API**，故同一份源码可分别对
//! A 态（`RwLock<HashMap>` 时期）/ B 态（udf `BoundedRegistry`）编译，两态只差
//! SimpleOhm 内部实现 ⇒ 同窗相对差直接归因该实现差。
//!
//! 采集口径：32 个 outbound tag（真实配置量级），每轮 200k 次
//! `select_handler`（生产选择面）+ `get_handler`（旧登记表）= 400k 查表，
//! 5 个样本取中位数。
//!
//! ## 用法（A/B 各 ≥3 轮交错；禁跨窗口比绝对值）
//! ```text
//! export CARGO_TARGET_DIR=D:/Project/Xray-core-rust/target-<你的目录>
//! # B 态（当前树：BoundedRegistry）
//! cargo run --release -p xray-app-dispatcher --example ohm_lookup_ab
//! # A 态（回退 SimpleOhm 实现到任一基准版本，其余在树增量保留）
//! git show <rev>:crates/xray-app-dispatcher/src/default.rs > crates/xray-app-dispatcher/src/default.rs
//! cargo run --release -p xray-app-dispatcher --example ohm_lookup_ab
//! ```
//!
//! ## 预期输出与判据
//! ```text
//! warmup ok (hits=400000)
//! sample ns/op = 87.85 (hits=400000)   ×5
//! MEDIAN ns/op = 87.85
//! MIN ns/op = 87.23
//! MEDIAN alloc-only ns/op = 35.83
//! ```
//! （数值为本机实测样本：`BoundedRegistry` 态 MEDIAN ≈ 87 ns/op、`HashMap` 态 ≈ 26 ns/op、
//! `alloc-only` ≈ 35 ns/op——归因见报告。）
//! 判据：同机同窗 A/B 的 **MEDIAN ns/op 相对差不劣化**；本轮实测数值见
//! `reports/audit-2026-10-27/c-r1a-registry-bounded.md` 性能表。

// 采集器必须读墙钟测 ns/op：`Instant::now` 是本题的测量手段本身，非生产站点。
#![allow(clippy::disallowed_methods, reason = "examples: A/B 计时锚点，非生产路径")]

use std::{sync::Arc, time::Instant};

use xray_app_dispatcher::{
    DispatchHandler, OutboundHandlerManager,
    default::{PinFuture, SimpleOhm},
};

#[derive(Debug)]
struct H(Arc<str>);

impl DispatchHandler for H {
    fn tag(&self) -> &str {
        &self.0
    }

    fn dispatch(
        &self,
        _dest: &xray_common::net::destination::Destination,
        _link: xray_transport::link::Link,
    ) -> PinFuture<()> {
        Box::pin(async {})
    }
}

const TAGS: usize = 32;
const ROUNDS: usize = 200_000;
const SAMPLES: usize = 5;

fn main() {
    let ohm = SimpleOhm::new();
    let tags: Vec<String> = (0..TAGS).map(|i| format!("out-{i:02}")).collect();
    for t in &tags {
        ohm.add(t, Arc::new(H(Arc::from(t.as_str()))) as Arc<dyn DispatchHandler>);
    }

    let mut hits = 0usize;
    for i in 0..ROUNDS {
        let t = &tags[i % TAGS];
        if ohm.select_handler(t).is_some() {
            hits += 1;
        }
        if ohm.get_handler(t).is_some() {
            hits += 1;
        }
    }
    assert_eq!(hits, ROUNDS * 2, "warmup must hit every lookup");
    println!("warmup ok (hits={hits})");

    let mut samples: Vec<f64> = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let start = Instant::now();
        let mut hit = 0usize;
        for i in 0..ROUNDS {
            let t = &tags[i % TAGS];
            if ohm.select_handler(t).is_some() {
                hit += 1;
            }
            if ohm.get_handler(t).is_some() {
                hit += 1;
            }
            std::hint::black_box(hit);
        }
        let ns = start.elapsed().as_nanos() as f64 / (ROUNDS as f64 * 2.0);
        println!("sample ns/op = {ns:.2} (hits={hit})");
        samples.push(ns);
    }
    samples.sort_by(f64::total_cmp);
    println!("MEDIAN ns/op = {:.2}", samples[SAMPLES / 2]);
    println!("MIN ns/op = {:.2}", samples[0]);

    // 归因面：`&str` → `String` 分配本身的成本。`BoundedRegistry::get(&K)` 无
    // `Borrow<Q>` 泛型 ⇒ String 键实现每次查表都要构造 `&String`；本块是同一分配
    // 的单变量锚，用于把 A/B 差值拆成「分配」与「表结构」两部分。
    let mut alloc_samples: Vec<f64> = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let start = Instant::now();
        for i in 0..ROUNDS {
            std::hint::black_box(tags[i % TAGS].to_string());
        }
        alloc_samples.push(start.elapsed().as_nanos() as f64 / ROUNDS as f64);
    }
    alloc_samples.sort_by(f64::total_cmp);
    println!("MEDIAN alloc-only ns/op = {:.2}", alloc_samples[SAMPLES / 2]);
}
