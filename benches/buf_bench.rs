//! Buffer 性能基准测试
//!
//! 测量 xray-buf 核心操作吞吐量，对比 Go 版本 buf.Buffer 性能。

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use xray_buf::buffer::Buffer;

fn bench_buffer_alloc(c: &mut Criterion) {
    c.bench_function("buffer_new_8k", |b| {
        b.iter(|| Buffer::new())
    });
}

fn bench_buffer_write(c: &mut Criterion) {
    let mut group = c.benchmark_group("buffer_write");
    for size in [64, 512, 4096, 8192] {
        let data = vec![0xABu8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, d| {
            b.iter(|| {
                let mut buf = Buffer::new();
                buf.write_from(d);
                buf
            })
        });
    }
    group.finish();
}

fn bench_buffer_read(c: &mut Criterion) {
    let mut group = c.benchmark_group("buffer_read");
    for size in [64, 512, 4096, 8192] {
        let data = vec![0xABu8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, d| {
            b.iter_batched(
                || {
                    let mut buf = Buffer::new();
                    buf.write_from(d);
                    buf
                },
                |mut buf| {
                    let mut dst = vec![0u8; size];
                    buf.read_to(&mut dst);
                    dst
                },
                criterion::BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

fn bench_buffer_copy(c: &mut Criterion) {
    let mut group = c.benchmark_group("buffer_copy_to_vec");
    for size in [64, 512, 4096, 8192] {
        let data = vec![0xABu8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, d| {
            b.iter_batched(
                || {
                    let mut buf = Buffer::new();
                    buf.write_from(d);
                    buf
                },
                |buf| buf.bytes().to_vec(),
                criterion::BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

fn bench_buffer_advance(c: &mut Criterion) {
    c.bench_function("buffer_advance_4k", |b| {
        b.iter_batched(
            || {
                let mut buf = Buffer::new();
                buf.write_from(&vec![0u8; 8192]);
                buf
            },
            |mut buf| {
                buf.advance(4096);
                buf
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

criterion_group!(
    benches,
    bench_buffer_alloc,
    bench_buffer_write,
    bench_buffer_read,
    bench_buffer_copy,
    bench_buffer_advance,
);
criterion_main!(benches);
