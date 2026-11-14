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

**代理协议**（inbound + outbound）：VLESS（Vision / REALITY）、VMess、Shadowsocks（含 2022）、Trojan、SOCKS、HTTP、DNS、Dokodemo-door、Freedom、Blackhole、Loopback、TUN、WireGuard、AnyTLS、TUIC v5、Hysteria2（协议名 `hysteria`/`hysteria2` 双注册）

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

# 双向互操作矩阵（默认 54 测：Rust↔Rust 12 + Go→Rust 12 + Rust→Go 12 + extra 18；
# Go 不支持的方向运行时探测自动跳过）
# Go 基准 = v26.11.9（commit 676eaf66）自建二进制（CI 由 .github/actions/fetch-go-baseline
# 现场构建并断言版本号），另需 Python `cryptography` 包
python dist/interop_ci.py --rust <rust 二进制> --go <go 基准二进制>

# 长时压测（12 场景协议矩阵，RSS/FD/吞吐/延迟分位采样）
# 载体: crates/xray-stress/docker/Dockerfile + crates/xray-stress/scripts/run_stress.{ps1,sh}
```

## CI

`.github/workflows/` 下 7 条流水线：

| workflow | 触发 | 内容 |
|---|---|---|
| `ci.yml` | push（main/dev/master/`feature/**`）+ PR | 15 个 job：`Format` / `Clippy` / `Build`（3 靶：linux-gnu、windows-msvc、macos-arm64）/ `Test`（debug+release）/ `Test (windows, xray-proxy-tun)` / `Test (linux, privileged tproxy gate)` / `Parser Parity (Go ruling baseline vs Rust)` / `Security & License`（cargo-deny + osv-scanner）/ `Docs` / `Fuzz Smoke`（仅手动）/ `Proto Drift Gate` / `Asset Gate` / `Framework Assembly (clippy + lib test)` / `Quality Gates` / `UDP Bind Gate` |
| `interop.yml` | push + PR + 手动 + nightly 03:17 UTC | `Interop (os)`（ubuntu-24.04 + macos-14）：workspace `--lib` + release 构建 + `dist/interop_ci.py` 54 测；Go 基准 = **v26.11.9（commit `676eaf66`）按源码现场构建**（`.github/actions/fetch-go-baseline`）。`Full 32-node matrix` 只在 nightly/手动跑（需 secret 节点表） |
| `stress.yml` | 手动 | `xray-stress` 压测矩阵（12 场景分批：macos a/b、linux a/b、windows all；6h 硬顶） |
| `release.yml` | tag `v*` | **5 个产物**：`xray-linux-amd64`、`xray-linux-amd64-musl`、`xray-windows-amd64.exe`、`xray-macos-amd64`、`xray-macos-arm64`。指令集由 `.cargo/config.toml` 的 x86_64 分目标 `+sse4.1,+sse4.2,+popcnt` 决定（**不**用 `RUSTFLAGS` 覆盖），要求 Nehalem 2008+ / AMD Barcelona 2007+ |
| `build-linux-release.yml` | 手动（+ 本文件变更时 push main） | PGO 三段构建（instrument → loopback workload → optimize），ubuntu:22.04 容器锚定 glibc 2.35 |
| `mobile.yml` | 手动 + push（master/main/dev） | `Android aarch64 build gate` + `iOS aarch64 check gate` |
| `musl-probe.yml` | 手动 | `musl x86_64 build probe`：全静态链接 + `./xray version` 冒烟 |

## 文档

- [docs/](docs/) — 治理文档：宪法 [ARCHITECTURE.md](docs/ARCHITECTURE.md) + 裁决输入 [refs/](docs/refs/) + 框架契约 [architecture/](docs/architecture/) + 性能基线 [benchmarks/](docs/benchmarks/) + 改造空间 [research/](docs/research/) + 立项级审计（`audit-*-2026-10-12.md`）+ 部署调优 [guide-highrtt-sockopt.md](docs/guide-highrtt-sockopt.md)
- 历史轮次快照（一次性审计/战役报告）已清理，不入仓；当前轮次产物在 `reports/`（本地，不入仓）
