//! Crypto 性能基准测试
//!
//! 测量 AEAD 加密/解密吞吐量，对应 Go xray-core 的 crypto 热路径。

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use xray_crypto::aead::{AeadCipher, Aes128Gcm, Aes256Gcm, ChaCha20Poly1305Aead, XChaCha20Poly1305Aead};

fn bench_aes128_gcm_seal(c: &mut Criterion) {
    let key = [0x42u8; 16];
    let nonce = [0u8; 12];
    let aad = b"xray-bench";
    let cipher = Aes128Gcm::new(&key).expect("创建 AES-128-GCM");

    let mut group = c.benchmark_group("aes128_gcm_seal");
    for size in [64, 512, 4096, 16384] {
        let plaintext = vec![0xABu8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &plaintext, |b, pt| {
            b.iter(|| cipher.seal(&nonce, aad, pt).expect("seal"))
        });
    }
    group.finish();
}

fn bench_aes128_gcm_open(c: &mut Criterion) {
    let key = [0x42u8; 16];
    let nonce = [0u8; 12];
    let aad = b"xray-bench";
    let cipher = Aes128Gcm::new(&key).expect("创建 AES-128-GCM");

    let mut group = c.benchmark_group("aes128_gcm_open");
    for size in [64, 512, 4096, 16384] {
        let plaintext = vec![0xABu8; size];
        let ciphertext = cipher.seal(&nonce, aad, &plaintext).expect("seal");
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &ciphertext, |b, ct| {
            b.iter(|| cipher.open(&nonce, aad, ct).expect("open"))
        });
    }
    group.finish();
}

fn bench_aes256_gcm_seal(c: &mut Criterion) {
    let key = [0x42u8; 32];
    let nonce = [0u8; 12];
    let aad = b"xray-bench";
    let cipher = Aes256Gcm::new(&key).expect("创建 AES-256-GCM");

    let mut group = c.benchmark_group("aes256_gcm_seal");
    for size in [64, 512, 4096, 16384] {
        let plaintext = vec![0xABu8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &plaintext, |b, pt| {
            b.iter(|| cipher.seal(&nonce, aad, pt).expect("seal"))
        });
    }
    group.finish();
}

fn bench_chacha20_poly1305_seal(c: &mut Criterion) {
    let key = [0x42u8; 32];
    let nonce = [0u8; 12];
    let aad = b"xray-bench";
    let cipher = ChaCha20Poly1305Aead::new(&key).expect("创建 ChaCha20-Poly1305");

    let mut group = c.benchmark_group("chacha20_poly1305_seal");
    for size in [64, 512, 4096, 16384] {
        let plaintext = vec![0xABu8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &plaintext, |b, pt| {
            b.iter(|| cipher.seal(&nonce, aad, pt).expect("seal"))
        });
    }
    group.finish();
}

fn bench_xchacha20_poly1305_seal(c: &mut Criterion) {
    let key = [0x42u8; 32];
    let nonce = [0u8; 24];
    let aad = b"xray-bench";
    let cipher = XChaCha20Poly1305Aead::new(&key).expect("创建 XChaCha20-Poly1305");

    let mut group = c.benchmark_group("xchacha20_poly1305_seal");
    for size in [64, 512, 4096, 16384] {
        let plaintext = vec![0xABu8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &plaintext, |b, pt| {
            b.iter(|| cipher.seal(&nonce, aad, pt).expect("seal"))
        });
    }
    group.finish();
}

fn bench_aes128_gcm_roundtrip(c: &mut Criterion) {
    let key = [0x42u8; 16];
    let nonce = [0u8; 12];
    let aad = b"xray-bench";
    let cipher = Aes128Gcm::new(&key).expect("创建 AES-128-GCM");
    let plaintext = vec![0xABu8; 4096];

    c.bench_function("aes128_gcm_roundtrip_4k", |b| {
        b.iter(|| {
            let ct = cipher.seal(&nonce, aad, &plaintext).expect("seal");
            cipher.open(&nonce, aad, &ct).expect("open");
        })
    });
}

criterion_group!(
    benches,
    bench_aes128_gcm_seal,
    bench_aes128_gcm_open,
    bench_aes256_gcm_seal,
    bench_chacha20_poly1305_seal,
    bench_xchacha20_poly1305_seal,
    bench_aes128_gcm_roundtrip,
);
criterion_main!(benches);
