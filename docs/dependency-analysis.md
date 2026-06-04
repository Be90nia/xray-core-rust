# Xray-core Rust 重写 — 依赖库分析报告

> 基于 Xray-core Go 项目知识图谱（9006节点/15210边/715社区）分析，结合 GitHub/crates.io 实地调研
> 生成日期：2026-06-03

---

## 目录

1. [总览：依赖策略](#1-总览依赖策略)
2. [核心基础设施](#2-核心基础设施)
3. [加密与安全](#3-加密与安全)
4. [TLS 与指纹伪装](#4-tls-与指纹伪装)
5. [传输协议](#5-传输协议)
6. [代理协议](#6-代理协议)
7. [网络栈与 TUN](#7-网络栈与-tun)
8. [DNS](#8-dns)
9. [GeoIP/GeoSite](#9-geoipgeosite)
10. [可观测性](#10-可观测性)
11. [参考项目评估](#11-参考项目评估)
12. [风险与缓解](#12-风险与缓解)
13. [推荐依赖清单](#13-推荐依赖清单)

---

## 1. 总览：依赖策略

### 核心原则

| 原则 | 说明 |
|------|------|
| **直接依赖 > 参考实现** | crates.io 发布的独立 crate 优先；未发布的参考源码重构 |
| **活跃维护 > 历史星数** | 2025-2026 有提交 > 2024 停更的高星项目 |
| **模块化 > 单体** | 独立 crate > feature flag 模块 > 单一巨型 crate |
| **零 fork 依赖** | 避免 patched 依赖，长期维护成本高 |
| **许可证兼容** | MIT/Apache-2.0/BSD-3 优先，GPL 系列排除 |

### 依赖分级

| 级别 | 定义 | 示例 |
|------|------|------|
| **A - 直接依赖** | crates.io 发布，API 稳定，活跃维护 | tokio, quinn, ring, hickory-resolver |
| **B - 参考重构** | 未发布或耦合过紧，需提取重构 | clash-rs VMess/VLESS, shoes REALITY |
| **C - 自研** | 无现成实现，必须自研 | SplitHTTP, GeoSite 匹配引擎 |

### 预计代码量节省

| 类别 | Go 原始行数 | Rust 自研行数 | 使用库后行数 | 节省 |
|------|-----------|-------------|------------|------|
| 加密引擎 | ~8,000 | ~6,000 | ~1,500 | 75% |
| TLS/指纹 | ~13,000 | ~10,000 | ~800 | 92% |
| 传输协议 | ~18,000 | ~14,000 | ~4,000 | 71% |
| 代理协议 | ~15,000 | ~12,000 | ~5,000 | 58% |
| 网络栈/TUN | ~10,000 | ~8,000 | ~1,500 | 81% |
| DNS | ~5,000 | ~4,000 | ~500 | 88% |
| **合计** | **~69,000** | **~54,000** | **~13,300** | **75%** |

---

## 2. 核心基础设施

### 2.1 异步运行时

| 库 | 版本 | 推荐度 | 说明 |
|----|------|--------|------|
| **tokio** | 1.x (最新) | ⭐⭐⭐⭐⭐ | 主力运行时，87% Rust async 生态兼容 |
| **monoio** | 0.2.4 | ⭐⭐⭐ | io_uring 加速，ByteDance 生产验证，5.7x 快于 tokio |

**决策**：tokio 为主力运行时。monoio 作为 Linux 高性能路径的可选加速，通过 feature gate 切换。

**理由**：
- tokio 生态覆盖最广，所有依赖库（quinn, hyper, hickory 等）原生支持
- monoio 的 FusionDriver 可在 Linux 上自动选择 io_uring/fallback，但仅 Linux 受益
- 不推荐 async-std（RUSTSEC 废弃通告）

### 2.2 缓冲区

| 库 | 版本 | 推荐度 | 用途 |
|----|------|--------|------|
| **bytes** | 1.11.1 | ⭐⭐⭐⭐⭐ | 标准零拷贝缓冲区，所有网络库的基础 |
| **bytes-utils** | - | ⭐⭐⭐⭐ | SegmentedBuf，流式拼接 |
| **buf-list** | - | ⭐⭐⭐ | BufList，多 buffer 聚合 |
| **bytes-handoff** | 1.2.0 | ⭐⭐⭐ | WriteCoalescer，写合并优化 |

**决策**：bytes 为基础，bytes-utils 用于协议层流式处理。

### 2.3 Socket

| 库 | 版本 | 推荐度 | 说明 |
|----|------|--------|------|
| **socket2** | 0.6.4 | ⭐⭐⭐⭐⭐ | IP_TRANSPARENT (tproxy)、SO_MARK 等底层 socket 控制 |

### 2.4 Protobuf / gRPC

| 库 | 版本 | 推荐度 | 说明 |
|----|------|--------|------|
| **prost** | 0.14.3 | ⭐⭐⭐⭐⭐ | Protobuf 实现，Google 官方 Rust 团队维护 |
| **tonic** | 0.14.6 | ⭐⭐⭐⭐ | gRPC over HTTP/2，prost 上层 |
| **connectrpc-rs** | - | ⭐⭐⭐ | Anthropic 开源，1.95x 快于 tonic，备选 |

**决策**：prost + tonic 为主。Xray-core 有 71 个 proto 文件，prost 是唯一成熟选择。

---

## 3. 加密与安全

### 3.1 对称加密

| 库 | 版本 | 推荐度 | AES-GCM 吞吐 | ChaCha20-P1305 吞吐 | 说明 |
|----|------|--------|-------------|-------------------|------|
| **ring** | 0.17.14 | ⭐⭐⭐⭐⭐ | 3393 MB/s | 1804 MB/s | BoringSSL 绑定，最高性能 |
| **RustCrypto** aes-gcm | - | ⭐⭐⭐⭐ | ~1300 MB/s | - | 纯 Rust，stream cipher 模式适配协议层 |
| **RustCrypto** chacha20-poly1305 | - | ⭐⭐⭐⭐ | - | ~1100 MB/s | stream cipher，VMess 协议层必需 |

**决策**：双引擎策略
- **ring**：热路径加密（TLS 握手、大批量数据），in-place API
- **RustCrypto**：协议层流式加密（VMess AEAD、SS AEAD），stream cipher API 天然适配

**理由**：ring 的 in-place API 不适合流式加密场景（需要预知长度），RustCrypto 的 stream cipher 模式完美匹配 VMess/SS 的逐块加密需求。

### 3.2 非对称加密 / 密钥交换

| 库 | 推荐度 | 用途 |
|----|--------|------|
| **ring** (ECDH/Ed25519) | ⭐⭐⭐⭐⭐ | TLS 密钥交换、REALITY 认证 |
| **x25519-dalek** | ⭐⭐⭐⭐ | WireGuard Noise 协议 |

### 3.3 随机数

| 库 | 推荐度 | 说明 |
|----|--------|------|
| **ring** (rand) | ⭐⭐⭐⭐⭐ | CSPRNG，所有安全场景 |
| **rand** | ⭐⭐⭐⭐ | 非安全场景（测试、模拟） |

---

## 4. TLS 与指纹伪装

> 这是整个项目最关键的依赖决策点。Go 版 uTLS ~8000 行，REALITY ~5000 行。

### 4.1 标准 TLS

| 库 | 版本 | 推荐度 | 说明 |
|----|------|--------|------|
| **rustls** | 0.23.x | ⭐⭐⭐⭐⭐ | 纯 Rust TLS，aws-lc-rs/ring 双 backend |
| **btls** (cloudflare/boring) | - | ⭐⭐⭐⭐⭐ | BoringSSL 绑定，**含指纹控制 API** |

**⚠ 关键发现**：rustls 社区明确拒绝指纹伪装功能（无底层控制 API），**无法用于 uTLS 场景**。

### 4.2 TLS 指纹伪装（uTLS 等价）

| 方案 | 推荐度 | 说明 | 预计工作量 |
|------|--------|------|-----------|
| **🏆 btls + fingerprint 模块** | ⭐⭐⭐⭐⭐ | cloudflare/boring 硬分叉，增加指纹控制 API | ~500-800 行 |
| **wreq** (0x676e67) | ⭐⭐⭐⭐ | HTTP client，100+ 浏览器配置文件，JA4/Akamai 验证 | 配合 btls |
| **wreq-util** | ⭐⭐⭐⭐ | 浏览器模拟配置库（Chrome 100~133+, Firefox 109~136+, Safari 15.3~26+） | 配合 btls |
| **tokio-btls / compio-btls** | ⭐⭐⭐⭐ | async TLS stream 适配 | 直接使用 |
| shadowsocks/ech-tls-tunnel fingerprint.rs | ⭐⭐⭐ | 独立模块 ~300 行，配置来自 metacubex/utls | 参考复用 |

**决策**：btls 为主 TLS + 指纹伪装方案。

**理由**：
1. btls 是 BoringSSL 的 Rust 绑定，天然支持底层 TLS 控制
2. 已有 `set_grease_enabled`, `set_permute_extensions`, `set_cipher_list` 等指纹控制 API
3. wreq + wreq-util 提供完整的浏览器指纹配置库，覆盖 Chrome/Firefox/Safari
4. tokio-btls 提供与 tokio 生态的 async 适配
5. **无需 FFI-to-Go**，btls 已完全等价于 Go uTLS

### 4.3 REALITY

| 方案 | 推荐度 | 说明 |
|------|--------|------|
| **shoes** (cfal, 1112⭐) | ⭐⭐⭐⭐⭐ | 最完整的 REALITY Rust 实现，含 XTLS Vision |
| **clash-rs** (patched rustls) | ⭐⭐⭐ | 通过 fork rustls 实现，长期维护风险 |
| **meow-rs** (madeye, 261⭐) | ⭐⭐⭐⭐ | VLESS + XTLS-Vision + ECH + uTLS(BoringSSL) |

**决策**：参考 shoes 的 REALITY 实现，基于 btls（而非 patched rustls）重构。

**理由**：
- shoes 的 REALITY 实现最完整且活跃维护（2026-05-26 更新）
- clash-rs 的 patched rustls fork 有长期维护风险
- btls 已有底层控制能力，比 fork rustls 更适合实现 REALITY
- 预计重构工作量 ~2000-3000 行

### 4.4 ECH (Encrypted Client Hello)

| 方案 | 推荐度 | 说明 |
|------|--------|------|
| **rustls** (已合并 RFC 9849) | ⭐⭐⭐⭐ | 客户端 ECH 已合并，需 aws-lc-rs backend |
| rustls 服务端 ECH | ⭐⭐⭐ | PR 进行中，暂不可用 |

### 4.5 AnyTLS

| 库 | 推荐度 | 说明 |
|----|--------|------|
| **anytls-rs** (jxo-me, v0.5.2) | ⭐⭐⭐⭐ | 独立 AnyTLS 服务端/客户端 |
| **clash-rs AnyTLS** | ⭐⭐⭐ | 内置实现，入站+出站 |

**注意**：AnyTLS 是传输层协议（抗检测），与 uTLS 指纹伪装正交互补，不是替代关系。

---

## 5. 传输协议

### 5.1 QUIC

| 库 | 版本 | 推荐度 | 说明 |
|----|------|--------|------|
| **quinn** | 0.11.9 | ⭐⭐⭐⭐⭐ | 标准 QUIC 实现，内置 BBR v1，纯 Rust |
| **TQUIC** (腾讯) | - | ⭐⭐⭐⭐ | BBRv3 + Multipath QUIC，高性能场景备选 |
| **dquic** | - | ⭐⭐⭐ | RFC 9221 Datagram 扩展 |

**决策**：quinn 为主，TQUIC 作为 Multipath QUIC 场景备选。

**理由**：
- quinn 生态最成熟，与 tokio/h3 原生集成
- 内置 BBR v1 拥塞控制（零代码），覆盖大多数场景
- TQUIC 的 BBRv3 可在需要时移植（~1500 行）

### 5.2 HTTP/2 & HTTP/3

| 库 | 版本 | 推荐度 | 说明 |
|----|------|--------|------|
| **hyper** | 1.10.1 | ⭐⭐⭐⭐⭐ | HTTP/1.1 + HTTP/2 标准库 |
| **h2** | - | ⭐⭐⭐⭐ | HTTP/2 底层，hyper 依赖 |
| **h3** | - | ⭐⭐⭐⭐ | HTTP/3 over QUIC |

**⚠ 已知问题**：h2 有流式延迟问题（p95 17x 于 proxygen），高并发场景需关注。

### 5.3 WebSocket

| 库 | 版本 | 推荐度 | 说明 |
|----|------|--------|------|
| **tokio-tungstenite** | 0.29.0 | ⭐⭐⭐⭐⭐ | 标准 WebSocket 实现 |

### 5.4 KCP

| 库 | 版本 | 推荐度 | 说明 |
|----|------|--------|------|
| **kcp-tokio** (leihuxi/rust-kcp) | - | ⭐⭐⭐⭐ | 核心 KCP + tokio async |
| **kcp2** | 0.2.2 | ⭐⭐⭐ | async 支持 (std/no_std/Embassy)，加密层参考 |
| **kcp** | 0.6.0 | ⭐⭐⭐ | 老牌稳定，缺 async |

**决策**：kcp-tokio 核心协议 + kcp2 加密层参考。预计省 ~4500 行。

### 5.5 Hysteria2

| 方案 | 推荐度 | 说明 |
|------|--------|------|
| **clash-rs Hysteria2** | ⭐⭐⭐⭐⭐ | Brutal + Salamander 实现，quinn + h3 |
| **hysteria2 crate** | ⭐⭐⭐⭐ | 客户端实现 |

**决策**：参考 clash-rs Hysteria2 实现，重构为独立 crate。预计省 ~7000 行。

### 5.6 TUIC

| 库 | 推荐度 | 说明 |
|----|--------|------|
| **tuic-core** v1.8.5 | ⭐⭐⭐⭐ | clash-rs 使用的 TUIC 核心 |

### 5.7 SplitHTTP

| 状态 | 说明 |
|------|------|
| **❌ 无现成实现** | 底层用 h2 + h3 + quinn，应用层需自实现 |
| 预计工作量 | ~2000-3000 行 |

### 5.8 BBR 拥塞控制

| 方案 | 推荐度 | 说明 |
|------|--------|------|
| **quinn 内置 BBR v1** | ⭐⭐⭐⭐⭐ | 零代码，默认可用 |
| **TQUIC BBRv3** | ⭐⭐⭐⭐ | 参考，~1500 行移植 |
| **rat_congestion** | ⭐⭐⭐ | 新项目，不推荐生产 |

---

## 6. 代理协议

### 6.1 协议覆盖矩阵

| 协议 | 现成实现 | 入站(服务端) | 出站(客户端) | 推荐来源 | 策略 |
|------|---------|-------------|-------------|---------|------|
| **VLESS** | ✅ | ❌(需自研) | ✅ | shoes / clash-rs | B-参考重构 |
| **VMess** | ✅ | ❌(需自研) | ✅ | clash-rs | B-参考重构 |
| **Trojan** | ✅ | ❌(需自研) | ✅ | clash-rs / trojan-rs | B-参考重构 |
| **Shadowsocks** | ✅ | ✅ | ✅ | shadowsocks crate v1.24 | A-直接依赖 |
| **WireGuard** | ✅ | ✅ | ✅ | boringtun v0.7.1 | A-直接依赖 |
| **Hysteria2** | ✅ | ❌(需自研) | ✅ | clash-rs | B-参考重构 |
| **TUIC** | ✅ | ❌(需自研) | ✅ | tuic-core v1.8.5 | A-直接依赖 |
| **SOCKS5** | ✅ | ✅ | ✅ | clash-rs / 自研 | B-参考重构 |
| **HTTP Proxy** | ✅ | ✅ | ✅ | hyper | A-直接依赖 |

### 6.2 关键发现：clash-rs 架构分析

**版本**: 0.10.6, Rust Edition 2024, Resolver 3

**Workspace 结构**:
- `clash-bin` (不发布) - 主二进制
- `clash-lib` (不发布) - 核心库，所有协议在此单一 crate 内
- `clash-dns` (watfaq-dns) - DNS 组件
- `clash-netstack` (watfaq-netstack) - 网络栈
- `clash-ffi` (发布为 clashrs) - FFI 绑定

**⚠ 关键限制**：协议不是独立 crate，是 `clash-lib/src/proxy/` 下的模块，通过 feature flag 控制。

**clash-rs 协议成熟度**:

| 协议 | Feature Gate | 入站 | 出站 | 成熟度 | 备注 |
|------|-------------|------|------|--------|------|
| VLESS | 无(始终编译) | ❌ | ✅ | 高 | 含 XTLS Vision splice |
| VMess | 无 | ❌ | ✅ | 高 | 完整 AEAD + KDF |
| Trojan | 无 | ❌ | ✅ | 高 | TCP + UDP relay |
| SS | ✅ shadowsocks | ✅ | ✅ | 高 | 外部 crate v1.24 |
| Hysteria2 | 无 | ❌ | ✅ | 高 | Brutal + Salamander |
| TUIC | ✅ tuic | ❌ | ✅ | 中高 | tuic-core v1.8.5 |
| WireGuard | ✅ wireguard | ❌ | ✅ | 中高 | boring-noise fork |
| SSH | ✅ ssh | ❌ | ✅ | 中 | russh |
| AnyTLS | 无 | ✅ | ✅ | 中 | 传输层协议 |
| SOCKS5 | 无 | ✅ | ✅ | 高 | 标准实现 |

**⚠ clash-rs 依赖风险**:
1. `clash-lib` 不发布 crates.io，无法选择性依赖
2. 协议耦合在单一 crate，VMess/VLESS/Trojan/Hysteria2 始终编译
3. 依赖 patched rustls fork (Watfaq/rustls)，长期维护风险
4. 多个 git 依赖 (shadowsocks/tuic-core/boring-noise)
5. VLESS/VMess 无入站（服务端）支持

### 6.3 推荐策略

**方案 A（推荐）- 模块化重构**:
- shadowsocks crate → 直接依赖（A 级）
- boringtun → 直接依赖（A 级）
- tuic-core → 直接依赖（A 级）
- VMess/VLESS/Trojan/Hysteria2 → 参考 clash-rs 重构为独立 crate（B 级）
- 入站支持 → 自研（C 级）

**方案 B - 单体集成**:
- 直接 fork clash-rs，添加入站支持
- 风险：patched rustls fork 维护负担、git 依赖不稳定

**决策**：方案 A。理由：
- 模块化架构更易维护和测试
- 避免 patched rustls fork 的长期风险
- 独立 crate 可被社区复用
- 入站支持是 Xray-core 的核心需求，clash-rs 不满足

### 6.4 各协议详细分析

#### Shadowsocks

| 库 | 版本 | 推荐度 | 说明 |
|----|------|--------|------|
| **shadowsocks** | 1.24.0 | ⭐⭐⭐⭐⭐ | 官方 Rust 实现，SIP004 AEAD + SIP022 AEAD 2022 |
| shadowsocks-service | 1.24.0 | ⭐⭐⭐⭐ | 服务端/客户端完整实现 |

**决策**：直接依赖 shadowsocks crate。实际非常活跃（每日 renovate 更新）。

#### WireGuard

| 库 | 版本 | 星数 | 推荐度 | 说明 |
|----|------|------|--------|------|
| **boringtun** | 0.7.1 | 7073⭐ | ⭐⭐⭐⭐⭐ | Cloudflare 官方，生产验证（1.1.1.1），BSD-3 |
| defguard_boringtun | 0.6.5 | - | ⭐⭐⭐⭐ | fork，更多功能开发 |

**决策**：直接依赖 boringtun v0.7.1。

#### Trojan

| 库 | 星数 | 更新日期 | 推荐度 | 说明 |
|----|------|---------|--------|------|
| lazytiger/trojan-rs | 224⭐ | 2026-05-31 | ⭐⭐⭐⭐ | 完整服务器 + tproxy，Windows 支持 |
| willoong9559/trojan-rs | 3⭐ | - | ⭐⭐ | rustls + WS + gRPC，规模小 |

**决策**：参考 clash-rs Trojan 实现（更成熟），lazytiger/trojan-rs 作为备选。

#### VLESS/VMess

| 项目 | 星数 | 更新日期 | 推荐度 | 说明 |
|------|------|---------|--------|------|
| **shoes** | 1112⭐ | 2026-05-26 | ⭐⭐⭐⭐⭐ | VLESS + XTLS(Reality+Vision) + VMess |
| **clash-rs** | 1661⭐ | 2026-06-02 | ⭐⭐⭐⭐⭐ | VLESS + REALITY + VMess + 完整传输层 |
| **meow-rs** | 261⭐ | 2026-05-29 | ⭐⭐⭐⭐ | VLESS + XTLS-Vision + ECH + uTLS(BoringSSL) |

**决策**：参考 clash-rs VMess/VLESS 实现，shoes 的 XTLS Vision 实现作为补充参考。

**⚠ 注意**：所有现成实现都缺少入站（服务端）支持，需自研。

---

## 7. 网络栈与 TUN

### 7.1 TUN 设备

| 库 | 版本 | 下载量 | 推荐度 | 说明 |
|----|------|--------|--------|------|
| **tun-rs** | 2.8.3 | 中 | ⭐⭐⭐⭐⭐ | 最优，70.6 Gbps，TAP + 多 IP + 硬件卸载 |
| **tun** | 0.8.10 | 1.99M | ⭐⭐⭐⭐ | 稳定，广泛使用 |

**决策**：tun-rs 为主（性能最优），tun 作为备选（生态成熟）。

### 7.2 用户态网络栈

| 库 | 版本 | 推荐度 | 说明 |
|----|------|--------|------|
| **netstack-smoltcp** | - | ⭐⭐⭐⭐⭐ | 最成熟，shadowsocks-rust/leaf/proxydroid 使用 |
| **smoltcp** | 0.13.1 | ⭐⭐⭐⭐⭐ | 底层 TCP/IP 栈，bare-metal 友好 |
| **watfaq-netstack** | - | ⭐⭐⭐⭐ | clash-rs 使用，基于 smoltcp |

**决策**：netstack-smoltcp 为主，smoltcp 0.13.1 为底层。

**理由**：
- netstack-smoltcp 已被多个生产项目验证
- smoltcp 0.13.1 是最新稳定版
- 替代 Go 版 gVisor netstack（~10,000 行）

### 7.3 Netlink

| 库 | 推荐度 | 说明 |
|----|--------|------|
| **rtnetlink** | ⭐⭐⭐⭐ | Linux 网络配置（路由、IP、网桥） |

---

## 8. DNS

### 8.1 DNS 解析器

| 库 | 版本 | 下载量 | 推荐度 | 说明 |
|----|------|--------|--------|------|
| **hickory-resolver** | 0.26.1 | 25M+ | ⭐⭐⭐⭐⭐ | DoT/DoH/DoQ/DoH3 全协议支持 |

**决策**：hickory-resolver 为主 DNS 解析器。

**理由**：
- 支持 DoT、DoH、DoQ、DoH3 全协议
- 25M+ 下载量，生态成熟
- 替代 Go 版 DNS 实现（~5,000 行）

### 8.2 FakeDNS

| 来源 | 推荐度 | 说明 |
|------|--------|------|
| **leaf** | ⭐⭐⭐⭐ | 完整实现 ~200 行，LRU + 多池 |

**决策**：参考 leaf 的 FakeDNS 实现自研。

---

## 9. GeoIP/GeoSite

### 9.1 GeoIP/GeoSite 解析

| 库 | 推荐度 | 说明 |
|----|--------|------|
| **geosite-rs** | ⭐⭐⭐ | 唯一专用库，但仅解析无匹配引擎 |
| **prost** | ⭐⭐⭐⭐⭐ | 解析 protobuf 格式的 GeoIP/GeoSite 数据 |

**决策**：prost 解析 + 自建匹配引擎。

### 9.2 最小完美哈希（MPH）

| 库 | 版本 | 下载量 | 推荐度 | 说明 |
|----|------|--------|--------|------|
| **boomphf** | 0.6.0 | 612K | ⭐⭐⭐⭐ | BBHash，最成熟的 MPH 实现 |

**决策**：boomphf 用于 GeoSite 匹配引擎。

### 9.3 预计工作量

| 组件 | 预计行数 | 说明 |
|------|---------|------|
| GeoIP 匹配引擎 | ~500 | CIDR 前缀树 + MMDB 读取 |
| GeoSite 匹配引擎 | ~1000 | boomphf MPH + domain 规则匹配 |
| **合计** | ~1500 | - |

---

## 10. 可观测性

### 10.1 日志与追踪

| 库 | 推荐度 | 说明 |
|----|--------|------|
| **tracing** | ⭐⭐⭐⭐⭐ | 应用级追踪标准 |
| **opentelemetry-rust** | ⭐⭐⭐⭐ | OpenTelemetry 集成 |
| **fast-telemetry** | ⭐⭐⭐ | 热路径优化，~2ns sharded counter |

**决策**：tracing + opentelemetry-rust 为主，fast-telemetry 用于热路径。

---

## 11. 参考项目评估

### 11.1 项目对比

| 项目 | 星数 | 更新日期 | 协议覆盖 | 许可证 | 推荐度 | 策略 |
|------|------|---------|---------|--------|--------|------|
| **clash-rs** | 1661⭐ | 2026-06-02 | VLESS/VMess/SS/Trojan/Hysteria2/TUIC/WG | Apache-2.0 | ⭐⭐⭐⭐⭐ | B-参考重构 |
| **shoes** | 1112⭐ | 2026-05-26 | VLESS/XTLS/VMess | MIT | ⭐⭐⭐⭐⭐ | B-参考重构 |
| **shadowsocks-rust** | 10676⭐ | 2026-06-02 | SS AEAD/2022 | MIT | ⭐⭐⭐⭐⭐ | A-直接依赖 |
| **meow-rs** | 261⭐ | 2026-05-29 | VLESS/XTLS/ECH/uTLS | MIT | ⭐⭐⭐⭐ | B-参考重构 |
| **boringtun** | 7073⭐ | 2026-05-04 | WireGuard | BSD-3 | ⭐⭐⭐⭐⭐ | A-直接依赖 |
| **trojan-rs** (lazytiger) | 224⭐ | 2026-05-31 | Trojan | MIT | ⭐⭐⭐⭐ | B-参考重构 |

### 11.2 关键结论

1. **clash-rs 是最佳参考项目**：协议覆盖最全、活跃维护、Apache-2.0 许可证
2. **shoes 的 XTLS/REALITY 实现最完整**：可直接参考
3. **shadowsocks-rust 和 boringtun 可直接依赖**：无需重构
4. **所有项目均缺少入站（服务端）支持**：需自研

---

## 12. 风险与缓解

### 12.1 依赖风险

| 风险 | 严重度 | 缓解措施 |
|------|--------|---------|
| btls 维护中断 | 中 | rustls 作为 fallback，牺牲指纹伪装 |
| quinn BBR v1 性能不足 | 低 | TQUIC BBRv3 移植（~1500 行） |
| h2 流式延迟问题 | 中 | 监控 p95 延迟，必要时优化 |
| clash-rs patched rustls fork | 高 | 不直接依赖，仅参考实现 |
| 入站支持缺失 | 高 | 自研，参考 Go 版实现 |

### 12.2 技术风险

| 风险 | 严重度 | 缓解措施 |
|------|--------|---------|
| uTLS 指纹检测升级 | 中 | btls + wreq-util 持续更新浏览器配置 |
| REALITY 协议变更 | 低 | shoes 活跃维护，及时同步 |
| KCP 性能不达预期 | 低 | kcp-tokio 已验证，备选 kcp2 |
