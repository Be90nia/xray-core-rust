**部署调优入口**：高 RTT / 跨洋链路 sockopt 指南（`sockopt.receiveBufferSize` 运维配方与床实测数据）→ [docs/guide-highrtt-sockopt.md](docs/guide-highrtt-sockopt.md)

# Xray-core-rust

[Go Xray-core](https://github.com/XTLS/Xray-core) v26.9.9 的 Rust 复刻：53 个 crate 组成的 workspace，覆盖 Xray 完整数据面与控制面（代理协议 / 传输 / TLS·REALITY / 路由·DNS / 统计·API），32 个真实节点场景与 Go 服务端全通，并带双向互操作 CI。

- **语言与版本**：Rust edition 2024，MSRV 1.85，许可证 MPL-2.0
- **平台**：发行二进制 linux-amd64 / windows-amd64 / macos-amd64+arm64；另有 Android（aarch64 build）、iOS（aarch64 check）编译门
- **性能基线**：mimalloc 全局分配器默认开（`c9e11fc2`）、tokio 1.53、release profile `lto=fat + codegen-units=1 + strip=symbols`

## 架构总览

53 个 crate 按 8 层组织（与根 [Cargo.toml](Cargo.toml) 的 members 分层注释一一对应）：

| 层 | crate | 数 |
|---|---|---|
| Protobuf | `xray-proto` | 1 |
| L0 基础类型 | `xray-buf` `xray-common` `xray-features` | 3 |
| L1 加密与数据引擎 | `xray-crypto` `xray-geodata` `xray-mux` `xray-xudp` | 4 |
| L2 传输基础设施 | `xray-transport` `xray-tls` `xray-reality` | 3 |
| L3 传输协议 | `xray-transport-{tcp,kcp,hysteria,splithttp,grpc,websocket,httpupgrade,quic,naive}` | 9 |
| L4 应用服务 | `xray-app-{dns,router,dispatcher,proxyman,stats,log,commander,observatory,policy,reverse,metrics,geodata,version}` | 13 |
| L5 代理协议 | `xray-proxy-{vless,vmess,ss,trojan,socks,http,dns,blackhole,freedom,dokodemo,loopback,tun,wireguard,anytls,tuic,hysteria}` | 16 |
| L6 配置 | `xray-conf` | 1 |
| L7 核心与 CLI | `xray-core` `xray-cli` | 2 |
| 压测 | `xray-stress` | 1 |

另有 `tests/`（集成测试）与 `benches/`（性能基准）两个 workspace member。数据面接线：inbound/outbound handler 由 `xray-core` 注册（`register.rs`），生产拨号路径走 `xray-app-dispatcher` 的 `make_*_dial_fn`，UDP 经 `UdpDispatchSession` + XUDP 帧约定。

## 协议清单

**代理协议**（inbound + outbound）：VLESS（Vision / REALITY）、VMess、Shadowsocks（含 2022）、Trojan（含 v2 草案）、SOCKS、HTTP、DNS、Dokodemo-door、Freedom、Blackhole、Loopback、TUN、WireGuard、AnyTLS、TUIC v5、Hysteria2（协议名 `hysteria`/`hysteria2` 双注册）

**传输层**：TCP、mKCP、WebSocket、HTTPUpgrade、gRPC（HTTP/2）、SplitHTTP/XHTTP（含 HTTP/3）、QUIC、Hysteria（QUIC + UDP hop）、NaiveProxy（outbound-only）

**安全层**：TLS（uTLS 指纹 / btls·BoringSSL、ECH、OCSP stapling、后量子 X25519MLKEM768 混合密钥交换 + ML-DSA-65 证书验签）、REALITY（服务端 btls acceptor opt-in + 抗主动探测 maxUselessRecords）

**应用面**：DNS（UDP/TCP/DoH/DoT/DoQ/FakeDNS、per-NS serveStale/缓存）、路由（geoip/geosite/进程匹配）、Sniffing、Stats/Policy/Observatory/Metrics/Reverse/Commander（gRPC API）

## 构建与运行

依赖：Rust 1.85+、CMake、Clang/libclang、protoc（`btls-sys` 需现场编译 BoringSSL）。

```bash
cargo build --release -p xray-cli
# 产物: target/release/xray
./xray run -c config.json
```

CLI 子命令（对应 Go `main/`）：`run`（默认，v4 兼容）、`version`、`uuid`、`api`（23 个子命令）、`tls`、`convert`，以及密钥工具 `x25519`、`wg`、`mlkem768`、`mldsa65`、`vlessenc`。

## 测试

```bash
# workspace 库测试（CI 同款见 ci.yml 的 cargo test --workspace，Linux runner）
cargo test --workspace --lib     # 本机快速口径；Windows 下 tests/ 集成套件可能挂死
cargo test --lib -p xray-proxy-vless    # 单 crate

# 双向互操作矩阵（默认套件 37 测：Rust↔Rust 12 + Go→Rust 6 + Rust→Go 6 + 新协议 13）
# 需要 Go v26.9.9 官方 release 二进制与 Python `cryptography` 包
python dist/interop_ci.py

# 长时压测（12 场景协议矩阵，RSS/FD/吞吐/延迟分位采样）
# 载体: crates/xray-stress/docker/Dockerfile + crates/xray-stress/scripts/run_stress.{ps1,sh}
```

## CI

`.github/workflows/` 下 6 条流水线：

| workflow | 内容 |
|---|---|
| `ci.yml` | fmt + clippy(`-D warnings`) + 三平台 build + `cargo test --workspace`（debug/release）+ cargo-deny + doc |
| `interop.yml` | 互通矩阵：ubuntu-24.04 + macos-14，workspace `--lib` 全测 + release 构建 + `dist/interop_ci.py` 37 测；Go 基线 = 官方 v26.9.9 release 二进制 |
| `stress.yml` | `xray-stress` 压测矩阵（12 场景分批，macOS + Linux + Windows 三平台，长时硬顶） |
| `release.yml` | tag `v*` → 4 平台二进制（linux/windows amd64 + macos amd64/arm64），通用 target（`RUSTFLAGS` 覆盖 native） |
| `build-linux-release.yml` | workflow_dispatch PGO 三段构建（instrument → loopback workload → optimize） |
| `mobile.yml` | Android aarch64 全量 build + iOS aarch64 check 双编译门 |

## 文档

- [docs/](docs/) — 29 份文档：28 份战役与审计报告（`audit2-*`/`audit3-*` 配置/路由/HTTP/并发/安全/wire-format 审计、`impl-*` 修复战役、`interop-expand-2026-09-24.md` 互通矩阵扩展、`impl-perf-wave-a-2026-09-24.md` 性能波 A、`impl-stress-leak-{a,b}-2026-09-22.md` 压测泄漏修复）+ 1 份部署调优 [guide-highrtt-sockopt.md](docs/guide-highrtt-sockopt.md)
- [HANDOFF.md](HANDOFF.md) — 会话交接状态（当前基线、验收口径、CI 打法）
