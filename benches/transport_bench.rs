//! Transport 层性能基准测试
//!
//! 测量数据拷贝、帧编解码等传输层热路径吞吐量。

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

/// 零拷贝 vs 拷贝对比：测量不同大小数据的内存拷贝开销。
/// 这是传输层的基础操作，所有协议都涉及数据搬运。
fn bench_memcpy_baseline(c: &mut Criterion) {
    let mut group = c.benchmark_group("memcpy_baseline");
    for size in [64, 512, 4096, 16384, 65536] {
        let src = vec![0xABu8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &src, |b, s| {
            b.iter(|| {
                let dst = s.clone();
                std::hint::black_box(dst);
            })
        });
    }
    group.finish();
}

/// 测量 Vec<u8> 扩容策略对传输层的影响。
/// 传输层频繁分配/释放 buffer，扩容策略直接影响吞吐。
fn bench_vec_extend(c: &mut Criterion) {
    let mut group = c.benchmark_group("vec_extend_from_slice");
    for size in [64, 512, 4096] {
        let data = vec![0xABu8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, d| {
            b.iter(|| {
                let mut v = Vec::with_capacity(8192);
                v.extend_from_slice(d);
                std::hint::black_box(v);
            })
        });
    }
    group.finish();
}

/// 测量分块传输的帧头解析开销。
/// VMess/VLESS/Trojan 等协议都需要解析 2-4 字节的长度头。
fn bench_length_header_parse(c: &mut Criterion) {
    c.bench_function("parse_2byte_length", |b| {
        b.iter(|| {
            let header: [u8; 2] = [0x10, 0x00];
            let len = u16::from_be_bytes(header) as usize;
            std::hint::black_box(len)
        })
    });

    c.bench_function("parse_4byte_length", |b| {
        b.iter(|| {
            let header: [u8; 4] = [0x00, 0x00, 0x10, 0x00];
            let len = u32::from_be_bytes(header) as usize;
            std::hint::black_box(len)
        })
    });
}

criterion_group!(
    benches,
    bench_memcpy_baseline,
    bench_vec_extend,
    bench_length_header_parse,
);
criterion_main!(benches);
