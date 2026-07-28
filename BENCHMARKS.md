# Xray-core-rust 性能基准测试

## 运行方式

```bash
# 全部 benchmark
cargo bench -p xray-benchmarks

# 单个 suite
cargo bench -p xray-benchmarks --bench crypto_bench
cargo bench -p xray-benchmarks --bench buf_bench
cargo bench -p xray-benchmarks --bench router_bench
cargo bench -p xray-benchmarks --bench transport_bench
```

## 基线数据（Windows x64, release profile）

### Crypto (AEAD)

| 操作 | 64B | 512B | 4KB | 16KB |
|------|-----|------|-----|------|
| AES-128-GCM seal | 199 ns | 288 ns | 914 ns | 3.37 μs |
| AES-128-GCM open | 194 ns | 285 ns | 883 ns | 3.28 μs |
| AES-256-GCM seal | 202 ns | 316 ns | 1.12 μs | 4.37 μs |
| ChaCha20-Poly1305 seal | 1.22 μs | 1.54 μs | 4.45 μs | 14.6 μs |
| XChaCha20-Poly1305 seal | 1.30 μs | 1.61 μs | 4.52 μs | 14.6 μs |
| AES-128-GCM roundtrip 4K | - | - | 1.80 μs | - |

**AES-GCM 吞吐量**（ring 后端，AES-NI 硬件加速）：4K ~4.5 GB/s
**ChaCha20-Poly1305 吞吐量**（RustCrypto 纯软件）：4K ~0.9 GB/s

### Buffer

| 操作 | 64B | 512B | 4KB | 8KB |
|------|-----|------|-----|-----|
| 分配 8KB | 31 ns | - | - | - |
| 写入 | 40 ns | 47 ns | 79 ns | 164 ns |
| 读取 | 148 ns | 204 ns | 582 ns | 1.11 μs |
| 拷贝到 Vec | 155 ns | 199 ns | 560 ns | 1.12 μs |
| 游标前进 4KB | 10 ns | - | - | - |

### Router

| 操作 | 延迟 |
|------|------|
| 端口列表匹配（10 端口，命中） | 5 ns |
| 端口列表匹配（10 端口，未命中） | 8 ns |
| 端口范围匹配（1000-2000，命中） | 1 ns |

### Transport 基础

| 操作 | 64B | 512B | 4KB | 16KB | 64KB |
|------|-----|------|-----|------|------|
| Vec clone（基线） | 44 ns | 49 ns | 84 ns | 370 ns | 1.76 μs |
| Vec extend | 48 ns | 50 ns | 87 ns | - | - |
| 2 字节长度头解析 | 0 ns | - | - | - | - |
| 4 字节长度头解析 | 0 ns | - | - | - | - |

## 与 Go 版本对比要点

1. **AES-GCM**: ring 后端利用 AES-NI 指令，与 Go 的 crypto/tls 性能相当
2. **ChaCha20-Poly1305**: RustCrypto 无硬件加速，比 Go 的 asm 实现慢约 2-3x；VMess 用户可优先选择 AES-GCM
3. **Buffer**: BytesMut 池化分配（8KB 默认），Go 版本使用 sync.Pool + []byte，两者性能相近
4. **Router**: 端口匹配 O(n) 线性扫描（n=端口范围数），Go 版本相同；生产环境通常 <10 个范围，5ns 完全可接受
5. **零拷贝**: Rust 版本利用所有权系统避免 Go 的 copy开销，但实际吞吐受网络 IO 限制，差异 <5%

## 优化方向

- ChaCha20-Poly1305: 考虑 `chacha20poly1305` 的 SIMD feature 或回退到 ring 后端
- Router IP 匹配: 当前 O(n) CIDR 扫描，可改为 Trie/IPCidrTree 加速
- Buffer 池化: 当前 8KB 固定分层，可改为按需分档（4K/8K/16K/32K）
