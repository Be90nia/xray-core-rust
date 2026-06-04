//! Router matching performance benchmarks
//!
//! Benchmarks for routing rule matching speed.

use criterion::{criterion_group, criterion_main, Criterion};

fn bench_router_placeholder(c: &mut Criterion) {
    c.bench_function("router_placeholder", |b| {
        b.iter(|| {
            std::hint::black_box(1_usize)
        })
    });
}

criterion_group!(benches, bench_router_placeholder);
criterion_main!(benches);
