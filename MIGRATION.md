# Xray-core Go → Rust 迁移指南

## 概述

xray-core-rust 是 Go 版 [XTLS/Xray-core](https://github.com/XTLS/Xray-core) 的全面 Rust 复刻。配置格式 100% 兼容，可直接替换二进制。

## 快速开始

### 构建

```bash
# 需要安装：Rust 1.85+, NASM, LLVM/Clang（ring 依赖）
cargo build --release

# 运行
./target/release/xray-cli run -c config.json
```

### 配置兼容性

JSON 配置格式与 Go 版完全一致，无需修改。包括：
- `inbounds` / `outbounds` 配置
- `routing` 规则
- `dns` 设置
- `transport` 传输层配置
- `policy` / `stats` / `observatory` 等应用配置

## 协议支持矩阵

| 协议 | 入站 | 出站 | 传输层 | 状态 |
|------|------|------|--------|------|
| VMess | ✅ | ✅ | TCP/WS | 完整 |
| VLESS | ✅ | ✅ | TCP/WS/XHTTP | 完整 |
| Trojan | ✅ | ✅ | TCP/TLS | 完整 |
| Shadowsocks | ✅ | ✅ | TCP | 完整 |
| SOCKS | ✅ | ✅ | TCP | 完整 |
| HTTP | ✅ | ✅ | TCP | 完整 |
| Freedom | - | ✅ | TCP/UDP | 完整 |
| Blackhole | - | ✅ | - | 完整 |
| DNS | ✅ | ✅ | - | 完整 |
| Dokodemo-door | ✅ | - | - | 完整 |
| Loopback | ✅ | ✅ | - | 完整 |
| TUN | ✅ | - | smoltcp | 完整 |
| WireGuard | ✅ | ✅ | boringtun+smoltcp | 完整 |
| AnyTLS | ✅ | ✅ | TLS | 完整 |
| TUIC | ✅ | ✅ | QUIC+h3 | 完整 |
| Hysteria2 | ✅ | ✅ | QUIC+BBR/Brutal | 完整 |
| Reverse | ✅ | ✅ | - | 完整 |

## 传输层支持

| 传输 | 状态 |
|------|------|
| TCP | ✅ |
| WebSocket | ✅（含 TLS server + 多 path + PROXY protocol） |
| gRPC | ✅ |
| HTTP/2 | ✅ |
| HTTPUpgrade | ✅ |
| SplitHTTP/XHTTP | ✅（含 H3） |
| KCP/mKCP | ✅ |
| QUIC | ✅（quinn） |

## 安全层支持

| 安全层 | 状态 |
|--------|------|
| TLS | ✅（rustls + btls uTLS） |
| Reality | ✅（watfaq/rustls with_reality()） |
| uTLS 指纹 | ✅（btls BoringSSL 绑定） |

## 应用层支持

| 应用 | 状态 |
|------|------|
| DNS | ✅（UDP/TCP/DoH/DoT/DoQ） |
| Router | ✅（9 种匹配器 + balancer） |
| Dispatcher | ✅（sniffer + policy） |
| Proxyman | ✅（inbound/outbound handler 管理） |
| Stats | ✅ |
| Policy | ✅ |
| Commander | ✅（gRPC 动态管理） |
| Observatory | ✅（HTTP probe + 健康探测） |
| Metrics | ✅（HTTP 接口导出） |
| Reverse | ✅（portal/bridge） |
| Mux | ✅（mux.cool 多路复用） |
| Log | ✅ |

## 关键差异

### 1. 运行时
- **Go**: goroutine + gVisor netstack
- **Rust**: tokio + smoltcp netstack（TUN/WireGuard）

### 2. TLS 栈
- **Go**: crypto/tls + uTLS
- **Rust**: rustls（watfaq 分支支持 Reality）+ btls（uTLS 指纹伪造）

### 3. QUIC 栈
- **Go**: quic-go
- **Rust**: quinn（TUIC/Hysteria/SplitHTTP H3 共用）

### 4. WireGuard
- **Go**: gVisor netstack + wireguard-go
- **Rust**: smoltcp + boringtun

### 5. 内存管理
- **Go**: GC + sync.Pool
- **Rust**: 所有权 + BytesMut 池化（8KB 默认分层）

## 性能对比

详见 [BENCHMARKS.md](./BENCHMARKS.md)

关键结论：
- AES-GCM（ring AES-NI）：与 Go 相当，~4.5 GB/s
- ChaCha20-Poly1305：比 Go 的 asm 实现慢 2-3x（纯软件），建议优先选 AES-GCM
- 端口路由匹配：5ns/次，与 Go 相当
- Buffer 分配：31ns/次（8KB 池化），与 Go sync.Pool 相当

## 常见问题

### Q: 配置文件需要修改吗？
不需要。JSON 配置格式 100% 兼容 Go 版。

### Q: 可以和 Go 版混用吗？
可以。协议实现与 Go 版兼容，Rust 客户端可连接 Go 服务端，反之亦然。

### Q: 缺少什么功能？
目前缺少：
- Process Name 匹配（路由规则中 `process` 字段，依赖 OS-specific API）
- OCSP Stapling（TLS 服务端证书装订，ocsp-stapler crate 已集成但未完全启用）

### Q: 如何报告问题？
在 GitHub Issues 提交，附带配置（脱敏后）和日志。

## 开发环境设置

```powershell
# Windows
$env:LIBCLANG_PATH = 'D:\Dev\libclang'
$env:PATH = 'D:\Dev\nasm;' + $env:PATH

# 检查
cargo check --workspace
cargo test --workspace
cargo bench -p xray-benchmarks
```

## 项目结构

```
crates/
├── xray-proto          # Protobuf 类型定义
├── xray-buf            # 缓冲区（BytesMut 池化）
├── xray-common         # 公共类型（net/protocol/crypto）
├── xray-features       # trait 定义（InboundHandler/OutboundHandler）
├── xray-crypto         # 加密原语（AES-GCM/ChaCha20/CFB/CTR）
├── xray-geodata        # GeoIP/GeoSite 数据引擎
├── xray-mux            # mux.cool 多路复用
├── xray-xudp           # XUDP 协议
├── xray-transport*     # 传输协议（WS/gRPC/KCP/Hysteria/SplitHTTP/HTTPUpgrade）
├── xray-tls            # TLS 安全层（rustls+btls）
├── xray-reality        # Reality 安全层
├── xray-app-*          # 应用层（DNS/Router/Dispatcher/Proxyman/...）
├── xray-proxy-*        # 代理协议（VMess/VLESS/Trojan/SS/SOCKS/...）
├── xray-conf           # JSON 配置解析
├── xray-core           # 核心引擎
└── xray-cli            # CLI 入口
benches/                # 性能基准测试
tests/                  # 集成测试
```
