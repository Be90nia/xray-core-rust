//! Crypto performance benchmarks
//!
//! Benchmarks for AEAD encryption/decryption operations.

use criterion::{criterion_group, criterion_main, Criterion};

fn bench_crypto_placeholder(c: &mut Criterion) {
    c.bench_function("crypto_placeholder", |b| {
        b.iter(|| {
            std::hint::black_box(1_usize)
        })
    });
}

criterion_group!(benches, bench_crypto_placeholder);
criterion_main!(benches);
