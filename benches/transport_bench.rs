//! Transport performance benchmarks
//!
//! Benchmarks for transport layer throughput.

use criterion::{criterion_group, criterion_main, Criterion};

fn bench_transport_placeholder(c: &mut Criterion) {
    c.bench_function("transport_placeholder", |b| {
        b.iter(|| {
            std::hint::black_box(1_usize)
        })
    });
}

criterion_group!(benches, bench_transport_placeholder);
criterion_main!(benches);
