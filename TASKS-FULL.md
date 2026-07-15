# Xray-core-rust 100% 复刻任务清单

> 目标：1:1 对标 Go xray-core（HEAD 对照 `E:\Projcet\Xray-core`）
> 原则：Go 用第三方库的地方 → Rust 用对应库；Go 自研的地方 → Rust 自研
> 当前：46%（13922/30581 nodes），P0+P1 核心完成
> 剩余：~55 个任务，~19K 行自研 + 引入 8 个库
> 生成时间：2026-07-15（HEAD 28f697c）

---

## 〇、Go 依赖对标表（引入 Rust 对等库）

Go xray-core **本身就是大量用第三方库组装的**（不是全自研）。Rust 对等用库是 1:1 复刻。

| Go 库 | 用途 | Rust 对等库 | 版本 | 许可证 | 已引入 |
|---|---|---|---|---|---|
| `sing-shadowsocks` | SS 协议加密栈 | `shadowsocks` | 1.24.0 | MIT | ❌ 需引入 |
| `gVisor` | TUN netstack | `netstack-smoltcp` | 0.2 | Apache-2.0 | ❌ 需引入 |
| `utls` | uTLS 指纹模拟 | `boring` + `tokio-boring` | 5.1 | BSD+ISC | ❌ 需引入 |
| `quic-go` | QUIC 协议 | `quinn` | 0.11 | MIT/Apache | ✅ 已用 |
| `wireguard-go` | WireGuard | `boringtun` | 0.7.1 | BSD | ✅ 已用 |
| `miekg/dns` | DNS 协议 | `hickory-resolver` | 0.26 | MIT/Apache | ❌ 需引入 |
| `grpc` | gRPC API | `tonic` + `prost-build` | 0.14 | MIT | ❌ 需引入 |
| `gorilla/websocket` | WebSocket | `tokio-tungstenite` | — | MIT | ✅ 已用 |
| `wintun` | Windows TUN | `tun-rs` | 2.8.7 | MIT | ✅ 已用 |
| `xtls/reality` | REALITY 协议 | `rustls-reality` fork 或自研 | — | — | ⚠️ 需评估 |
| `pion/stun` | STUN | `stun-rs` | — | MIT/Apache | ❌ 需引入 |
| `blake3` | BLAKE3 哈希 | `blake3` | 1 | MIT/Apache | ✅ 已用 |
| `google/protobuf` | protobuf | `prost` | — | MIT | ✅ 已用 |
| `cloudflare/circl` | 密码学原语 | `ring` / `rustls` | — | — | ✅ 已用 |
| `sysinfo` 对标 | 进程枚举 | `sysinfo` | 0.39 | MIT | ❌ 需引入 |
| `net/http` 解析 | HTTP 头解析 | `httparse` | 1.10 | MIT/Apache | ❌ 需引入 |
| OCSP 对标 | OCSP stapling | `ocsp-stapler` | 0.3 | — | ❌ 需引入 |

---

## 阶段总览

| 阶段 | 内容 | 任务数 | 估行 | 优先级 |
|---|---|---|---|---|
| **A** | 依赖引入（8 个库） | 8 | ~200 | P2（最先） |
| **B** | transport register_dialer（4 个） | 4 | ~400 | P2 |
| **C** | proxy 协议 dispatcher 接入（8 个协议） | 12 | ~1700 | P2 |
| **D** | transport 空骨架补全（含 finalmask） | 16 | ~8500 | P3 |
| **E** | mux 接入 | 3 | ~500 | P2 |
| **F** | 功能性 TODO 修复（58 处→12 任务） | 12 | ~2900 | P3 |
| **G** | TUN netstack 集成 | 4 | ~1000 | P3 |
| **H** | CLI 完整命令 | 3 | ~1500 | P3 |
| **I** | 集成测试矩阵 | 3 | ~2300 | P4 |
| | **总计** | **65** | **~19K** | |

---

## 阶段 A：依赖引入（8 个库，~200 行）

每个库 = Cargo.toml 加依赖 + feature 配置 + 可选 lib.rs re-export。

| # | 任务 | Go 对标 | Rust 库 + feature | 估行 | 注意 |
|---|---|---|---|---|---|
| A1 | 引入 shadowsocks crate | sing-shadowsocks | `shadowsocks = { version = "1.24", default-features = false, features = ["aead-cipher", "aead-cipher-2022"] }` | ~30 | MIT 非 GPL，无传染 |
| A2 | 引入 hickory-resolver | miekg/dns | `hickory-resolver = { version = "0.26", features = ["tokio-runtime", "tls-ring", "https-ring", "quic-ring"] }` | ~20 | MSRV 1.88 |
| A3 | 引入 tonic（gRPC） | google.golang.org/grpc | `tonic = "0.14"` + `tonic-build` (build-dependencies) + prost | ~50 | 从现有 .proto 生成 Rust 代码 |
| A4 | 引入 netstack-smoltcp | gVisor | `netstack-smoltcp = "0.2"` | ~20 | 需 smoltcp 0.13+（workspace 已有 0.12，可能需升级） |
| A5 | 引入 boring（uTLS 对标） | utls | `boring = "5"` + `tokio-boring = "5"` | ~30 | 需 BoringSSL 编译环境（C 依赖） |
| A6 | 引入 sysinfo | Go syscall 进程枚举 | `sysinfo = "0.39"` | ~10 | MSRV 1.95 偏高，验证兼容 |
| A7 | 引入 httparse | net/http | `httparse = "1.10"` | ~10 | 零依赖 |
| A8 | 引入 ocsp-stapler | crypto/x509 OCSP | `ocsp-stapler = "0.3"` | ~10 | 配合 rustls 使用 |

**出口条件**：`cargo build --workspace` 通过，所有库编译验证。

---

## 阶段 B：transport register_dialer（4 个，~400 行）

4 个 transport 有大量实现代码但没注册到全局 dialer 表。配置 `streamSettings.network=xxx` 时找不到 transport → fallback 裸 TCP = 功能坏。

每个任务模式相同（参照 websocket/grpc/httpupgrade 的 `register_dialer()`）：
1. `crates/xray-transport-XXX/src/register.rs`：`register_dialer() -> io::Result<()>` 注册到 `TRANSPORT_DIALER_CACHE`
2. 闭包：clone dest/settings → 解析协议配置 → 构建 TLS config（如需）→ 协议拨号 → `Box::new(conn)`
3. lib.rs re-export

| # | 任务 | Go 对标 | Rust 现状 | 估行 |
|---|---|---|---|---|
| B1 | kcp register_dialer | `transport/internet/kcp` | xray-transport-kcp 4471 行实现没注册 | ~100 |
| B2 | splithttp register_dialer | `transport/internet/splithttp` | xray-transport-splithttp 6061 行没注册 | ~100 |
| B3 | hysteria transport register_dialer | `transport/internet/hysteria` | xray-transport-hysteria 5695 行没注册 | ~100 |
| B4 | reality register_dialer | `transport/internet/reality` | xray-reality crate，需作为 transport 注册 | ~100 |

**出口条件**：配置文件 `network: kcp/splithttp/hysteria/reality` 能拨号成功。

---

## 阶段 C：proxy 协议 dispatcher 接入（12 任务，~1700 行）

7+ 个协议有实现代码但没接 DialBridge（无 `dispatcher.rs`）。参照已验证的 vless/trojan/anytls/tuic dispatcher adapter 模式。

| # | 任务 | Go 对标 | Rust 现状 | 方案 | 估行 |
|---|---|---|---|---|---|
| C1 | shadowsocks outbound dispatcher | `proxy/shadowsocks` outbound | xray-shadowsocks 3063 行没 dispatcher.rs | 用 shadowsocks crate `CryptoStream` 包装 | ~300 |
| C2 | shadowsocks inbound | `proxy/shadowsocks` inbound | 缺 inbound server | CryptoStream 解密 → dispatch | ~300 |
| C3 | shadowsocks_2022 chacha20-poly1305 | `proxy/shadowsocks_2022` | 仅 aes-256-gcm，缺 chacha20 | shadowsocks crate 已支持，启 feature | ~50 |
| C4 | http proxy inbound | `proxy/http` inbound | xray-proxy-http 843 行没接入 | HTTP CONNECT 解析 → dispatch | ~150 |
| C5 | http proxy outbound dispatcher | `proxy/http` outbound | 同上 | dispatcher adapter | ~100 |
| C6 | dokodemo inbound | `proxy/dokodemo` | xray-proxy-dokodemo 541 行没接入 | 固定目标地址转发 → dispatch | ~200 |
| C7 | dns proxy inbound | `proxy/dns` | xray-proxy-dns 1125 行没接入 | DNS query 拦截 → 上游转发 | ~300 |
| C8 | dns proxy outbound | `proxy/dns` outbound | 同上 | DNS 拨号 adapter | ~100 |
| C9 | blackhole outbound dispatcher | `proxy/blackhole` | xray-proxy-blackhole 350 行没接入 | 空实现 dispatcher（直接 drop link） | ~30 |
| C10 | socks outbound dispatcher | `proxy/socks` outbound | 有 client.rs 没接 dispatcher | SOCKS5 client adapter | ~150 |
| C11 | hysteria inbound+outbound | `proxy/hysteria` | 推迟（TRANSPORT 非 proxy） | 等 transport stack 完整后接入 | ~0（推迟） |
| C12 | wireguard inbound+outbound | `proxy/wireguard` | 推迟（需 UDP driver） | 等 UDP transport | ~0（推迟） |

**出口条件**：所有协议能从配置文件启动，inbound→dispatcher→outbound 全链路通。

---

## 阶段 D：transport 空骨架补全（16 任务，~8500 行）

**最大工作量阶段**。Go 自研部分（无第三方库可替代）。其中 finalmask 是 Go 最新版抗封锁功能集，~7500 行。

### D-1: finalmask 流量伪装（10 子模块，~7500 行）

Go `transport/internet/finalmask/`，对应 Rust `xray-transport/src/finalmask/`。

| # | 子模块 | Go 行数(核心) | 功能 | 估行 |
|---|---|---|---|---|
| D1 | finalmask 主入口 | 284 | TCP/UDP 包 final mask 调度 | ~150 |
| D2 | fragment（TCP 分片） | ~140 | TCP 数据分片伪装对抗 DPI | ~200 |
| D3 | header/custom（自定义头） | ~1500 | 自定义流量头部评估器+状态机 | ~1200 |
| D4 | mkcp（mKCP 伪装头） | ~750 | mKCP 子协议头（aes128gcm/header/original）+ dns/dtls/srtp/utp/wechat/wireguard 伪装 | ~600 |
| D5 | noise（噪声填充） | ~310 | 随机噪声注入对抗流量分析 | ~250 |
| D6 | realm（REALM 协议） | ~1450 | client/server/http/punch/stun | ~1000 |
| D7 | salamander | ~720 | conn/gecko 编码 | ~500 |
| D8 | sudoku（数独编码） | ~1470 | codec/table/conn_tcp/conn_udp 包编码 | ~1000 |
| D9 | xdns（DNS 伪装传输） | ~1970 | client/server/dns/record_transport DNS over 伪装 | ~1500 |
| D10 | xicmp（ICMP 伪装传输） | ~870 | client/server ICMP 包伪装 | ~600 |

注：Go 的 `.pb.go`（protobuf 生成）用 prost 替代，省 ~1500 行手写。

### D-2: 其他 transport 空骨架（6 任务，~1000 行）

| # | 任务 | Go 对标 | Rust 现状 | 估行 |
|---|---|---|---|---|
| D11 | browser_dialer | `transport/internet/browser_dialer` | 1 行注释 | ~300（含 HTML/JS dialer 资源） |
| D12 | happy_eyeballs 双栈拨号 | `transport/internet/dialer` happyEyeballs | 1 行注释 | ~100 |
| D13 | sockopt 4 平台 | `transport/internet/sockopt_{darwin,linux,windows,freebsd}` | 4 个文件 1 行注释 | ~800 |
| D14 | headers 流量伪装头（dtls/srtp/utp/wechat/wireguard） | `transport/internet/headers` | 5 文件 1 行注释 | ~500 |
| D15 | tcp hub + udp hub/dialer/UoT | `transport/internet/{tcp,udp}` | 4 文件 1 行注释 | ~500 |
| D16 | tagged + memory_settings + pipe + config | `transport/internet/{tagged,memory_settings}` | 3 文件 1 行注释 | ~200 |

**出口条件**：`xray-transport/src/` 下所有文件从 1 行注释变为有实现。

---

## 阶段 E：mux 接入（3 任务，~500 行）

xray-mux 有 ~3004 行代码（client/worker/session/frame/reader/writer）但没接 outbound/inbound handler。

| # | 任务 | Go 对标 | 估行 |
|---|---|---|---|
| E1 | mux client 接入 outbound handler | `app/mux/client` | ~200 |
| E2 | mux server 接入 inbound handler | `app/mux/server`（含 mux.cool） | ~200 |
| E3 | mux e2e 测试 | Go scenarios | ~100 |

**出口条件**：配置 `mux.concurrency > 0` 时多连接复用单 TCP 通道。

---

## 阶段 F：功能性 TODO 修复（12 任务，~2900 行）

58 处 TODO 中重要的（已用图谱+grep 定位）。

| # | 任务 | Go 对标 | Rust 位置 | 方案 | 估行 |
|---|---|---|---|---|---|
| F1 | sniffer 5 协议（HTTP/TLS/BT/QUIC/UTP） | `app/dispatcher/sniffer` | sniffer.rs:263-319 全 TODO | 用 httparse 做 HTTP 嗅探，其余手写 | ~500 |
| F2 | dns LocalNameServer | `app/dns/local` | local.rs:10 | 用 hickory-resolver 系统解析 | ~300 |
| F3 | dns checkSystem 系统路由探测 | `app/dns/server` | server.rs:183 | 探测系统 DNS 配置 | ~200 |
| F4 | OCSP stapling | `crypto/tls` OCSP | common/ocsp/mod.rs 全 TODO | 用 ocsp-stapler crate | ~200 |
| F5 | uTLS handshake（REALITY/TLS 指纹） | utls | tls/error.rs:60, reality/error.rs:63 | 用 boring crate 适配层 | ~500 |
| F6 | router webhook post | `app/router/webhook` | webhook.rs:134-137 | 用 reqwest POST | ~100 |
| F7 | router find_process 进程匹配 | `app/router/condition` | condition.rs:443 | 用 sysinfo crate | ~200 |
| F8 | proxyman command TypedMessage 解码 | `app/proxyman/command` | command/mod.rs:327,424 | prost TypedMessage → 具体 Account 类型 | ~300 |
| F9 | proxyman UoT (UDP over TCP) | `app/proxyman` | outbound/handler.rs:12 | UDP 包封装 TCP 流 | ~200 |
| F10 | proxyman workers listener 接入 | `app/proxyman` | inbound/mod.rs:285 | worker 管理 listener 生命周期 | ~100 |
| F11 | UUID cmd_key MD5 + ss2022 chacha20 + BBR 完善 | 散落 | uuid/mod.rs:69 等 | 小修 | ~200 |
| F12 | 其他散落 TODO（vless padding 等） | 散落 | 58 处 grep | 逐个修 | ~100 |

**出口条件**：`grep -rn "TODO" crates/ | wc -l` < 5（剩余仅为外部依赖阻塞的）。

---

## 阶段 G：TUN netstack 集成（4 任务，~1000 行）

Go `proxy/tun/` 17 文件用 gVisor netstack。Rust 用 netstack-smoltcp。

| # | 任务 | Go 对标 | Rust 现状 | 方案 | 估行 |
|---|---|---|---|---|---|
| G1 | TUN inbound handler（IP 包→流） | `proxy/tun` handler.go | 仅 device.rs | netstack-smoltcp 的 `TcpListener`/`UdpSocket` → dispatch | ~500 |
| G2 | TUN icmp handler | `proxy/tun/icmp` | 缺 | ICMP 包处理 | ~200 |
| G3 | TUN udp_fullone | `proxy/tun` udp_fullone.go | 缺 | UDP 单包全连接 | ~100 |
| G4 | TUN 多平台适配验证 | `proxy/tun_{darwin,linux,windows,freebsd,android}` | tun-rs 已覆盖设备层 | 验证 + 平台特定配置 | ~200 |

**出口条件**：TUN inbound 能接收 IP 包 → 解析 TCP/UDP → dispatch → outbound。

---

## 阶段 H：CLI 完整命令（3 任务，~1500 行）

Go `main/commands/all/` 有 `api/` + `convert/` + `tls/`。

| # | 任务 | Go 对标 | Rust 现状 | 估行 |
|---|---|---|---|---|
| H1 | CLI 框架（xray run/version/convert） | `main/commands` | xray-cli 只有 main.rs | ~200（clap 参数解析 + config 路径 + 日志） |
| H2 | API 命令（20+ gRPC CLI） | `main/commands/all/api` | 缺 | ~800（tonic client → gRPC commander，含 balancer/inbound/outbound/rules/stats 管理） |
| H3 | 工具命令（convert/curve25519/mldsa65/mlkem768/tls/uuid/vlessenc/wg/x25519） | `main/commands/all/{convert,tls}` | 缺 | ~500 |

**出口条件**：`xray run config.json` 能启动完整代理 + `xray api inbound-user list` 等 API 命令可用。

---

## 阶段 I：集成测试矩阵（3 任务，~2300 行）

Go `testing/scenarios/` 20 个场景文件。Rust `tests/integration/` 仅 5 个。

| # | 任务 | Go 对标 | 估行 |
|---|---|---|---|
| I1 | 测试矩阵框架（inbound × outbound × transport 组合） | `testing/scenarios` 框架 | ~300 |
| I2 | 全组合 e2e（含 dns/dokodemo/policy/reverse/ss/ss2022/transport/wireguard 场景） | `testing/scenarios/*` | ~1500 |
| I3 | Go 互通测试（Rust client ↔ Go server + 反向） | 跨语言验证 | ~500 |

**出口条件**：所有 inbound × outbound × transport 组合 e2e 通过 + Go 互通验证。

---

## 执行纪律

1. **串行执行**：按 A → B → C → E → F → D → G → H → I 顺序（D 最大放中间）
2. **每个任务完成后**：测试全绿 → 索引图谱（`index_repository mode=moderate`）→ git commit → 下一个
3. **子代理 + 主代理都必须用 codebase-memory 查代码**（铁律）
4. **性能/内存优化任务动手前必查 git 历史 + beads**（负优化审查）
5. **软件安装铁律**：检查已存在 → 询问用户 → 不自作主张 → 不轻易装 C 盘
6. **测试 80% 覆盖，TDD，全绿才算过**
7. **Go 对照**：查 Go 实现时用 codebase-memory project=`E-Projcet-Xray-core`

## 建议委派策略

| 阶段 | 委派方式 | 理由 |
|---|---|---|
| A | 主代理直接做 | 小改动，需协调 workspace Cargo.toml |
| B | 4 个子代理并行 | 模式相同（参照 websocket register_dialer） |
| C | 逐个委派（deep category） | 每个协议独立，需图谱调研 |
| D-1 finalmask | 子模块委派（10 个子代理） | 各子模块独立，最大并行化 |
| D-2 | 子代理并行 | 独立模块 |
| E | 主代理直接做 | 需理解 mux 内部架构 |
| F | 逐个委派 | 各 TODO 独立 |
| G | 子代理（deep category） | 需 smoltcp 调研 |
| H | 子代理（quick/unspecified） | CLI 模板化 |
| I | 子代理并行 | 测试编写 |

---

## 完成度追踪

| 维度 | 当前 | 目标 | 进度 |
|---|---|---|---|
| 图谱节点 | 13922 | ~28000+ | 46% |
| Rust 文件 | 478 | ~800+ | 60% |
| 代码行 | ~108K | ~130K | 83% |
| TODO 数 | 58 | <5 | — |
| 测试场景 | 5 | 20 | 25% |
| Go 依赖覆盖 | 10/17 | 17/17 | 59% |
