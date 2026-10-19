# Go → Rust 同步：v26.9.30 → v26.10.10（2026-10-16）

> **目的**：把 XTLS/Xray-core v26.10.10 的实质改动落到本仓知识图谱，作为 Rust 端 port / 借鉴的索引入口。
> **基线**：本仓 Rust `master = 87d72569`，Go 端同步到 `701af607`（v26.10.10），cbm 索引已重建（29511 → 46749 节点）。
> **对比窗口**：`v26.9.30 (b26a91d) ... v26.10.10 (701af60)`，23 commit / 97 file / +6389 −514。
> **方法**：本仓库每份 Go diff 配 cbm `search_code --project D-Project-Xray-core` 命中点 + Rust 端同名 crate grep，结论 = 同行 = 同行，缺位 = 待办。

---

## 0. 一图速览

| 类别 | Go 端变化 | Rust 端状态 | 动作 |
|---|---|---|---|
| **新特性（不需 port）** | XDNS finalmask / MASQUE WARP / Lua scripting / WireGuard ICMP pong | 全无 | 不动（用户指令 Lua 脚本不进 udf-frame，xdns/warp 类同） |
| **bug 修复（应 port）** | Mux race+UDP 帧 / gRPC redial ctx / Socks UDP stats / TLS RootCAs 默认值 / TLS ECH DoH h2c / Hysteria 闭 conn / DNS pubsub 清理 / QUIC sniffer 零尾 / TUN Win IPv6+弱主机+iOS dup fd / WG kernelTun IPv6 表 + 空闲 UDP 内存 | 同结构 crate 全在，修复点未跟进 | **建 11 条 P1+P2 bd 票**，按四查-共识审先后 |
| **新基建（生态外）** | `common/lua/`（9 文件含 pool/program/luar）+ `x509roots/fallback/bundle` Go 1.24 std | 我们依赖零，OK 不引 | 观察学习。

---

## 1. 23 commit 按行内影响分桶

### 1.1 新增特性（4 项 · 不 port）

| 提交 | PR | 模块 | 行数 | Rust 端处置 |
|---|---|---|---|---|
| `8855145e` | #6823 | **Lua scripting for dns/routing** | +2000+ | **不引**：用户红线 = Lua 脚本机制属半成品栈，与 udf-frame 边界冲突；Go 端即用户方案一致（v3 裁决已记）。RPRX 在 `common/lua/{pool,program,utils,luar}.go` + `app/{dns,router}/{lua,script}.go` + `common/{geodata,log}/lua.go` 共 18 文件 |
| `9e55a6ed` + `aa7aa9ad` | #6878 + #7106 | **MASQUE WARP**（Cloudflare WARP proxy） | +440 | **不引**：本仓 `xray-transport-masque` 暂无，且 WARP 域属 CF 私有协议 — 与 Go `transport/internet/masque/warp.go` 同 |
| `37184948` + `eddad37c` + `a3c6cc6a` | #7095 + #7089 + #7090 | **XDNS finalmask**（UDP 包尾置 0 抖型） | +600−140 | **不引**：新 finalmask 实现，本仓 `xray-finalmask` 暂无对应 `xdns` 子 crate |
| `e0bae212` | #6855 | **WireGuard inbound ICMP fake pong**（标准 WG ping 响应） | +270 | **待议**：与本仓 `xray-proxy-wireguard` 同位，但需要 "源行为表" 决策（默认 fake vs 默认丢弃）— 留给性能/安全 audit |

### 1.2 Bug 修复（11 项 · 应 port）

| Go 提交 | PR | 修复性质 | 本仓对应 crate | 文件落点 | 严重 |
|---|---|---|---|---|---|
| `7da5dae6` | #6871 | **Mux client race** — Dispatch vs SessionManager.Close 写入 input/output 顺序改 Allocate 时机 | `xray-mux/src/{client,session}.rs` | `client.rs::dispatch_worker` | P1 |
| `836a6fed` | #6822 | **Mux UDP frame 被下一帧覆盖** — `reader.go` 解帧 buf 复用 | `xray-mux/src/reader.rs` | `frame.rs::deframe` | P1 |
| `9d9a7a1c` | #6877 | **gRPC client redial 用旧 ctx** — `dial.go:130` `ctx` → `gctx` | `xray-transport-grpc/src/dial*.rs` | dialer.rs | P1 |
| `2a14c507` | #7101 | **Socks inbound UDP stats 零** — wrap `tempUDPConn` 进 `CounterConnection` | `xray-proxy-socks/src/server.rs` | UDP Associate handler | P2 |
| `08775afd` | #6856 | **WireGuard idle UDP flow 内存高** — gvisor `pkt.Clone().Data()` → `pkt.Data()` | `xray-proxy-tun/src/netstack.rs` (gvisor) | udp_forwarder 入口 | P1 |
| `92f7e724` | #6881 | **WireGuard kernelTun IPv6 表索引** — `sync.Mutex` → `sync/atomic.Int64` | `xray-proxy-tun/src/outbound.rs` 或 driver | tun linux 部分 | P2 |
| `1e08d48d` | #6874 | **TUN Win IPv6 关闭时启动失败** — +5 行 NIC 探测 | `xray-proxy-tun/src/{inbound,outbound}.rs` | Win 平台判断 | P2 |
| `1a60fc78` | #6883 | **iOS TUN fd dup** — 启动后 dup fd 防 tunnel 回收 | 暂不适用（本仓无 iOS 目标） | — | skip |
| `8989adfd` | #7092 | **TUN Win 弱主机发送/出口转发** — 新文件 `tun_windows_outbound.go`（+120） | `xray-proxy-tun/src/outbound.rs` | Win 出口 | P2 |
| `c7dbfd5e` | #7107 | **Hysteria client 闭 conn 不释放** — 加 `forced` flag + `core.Instance` 关联 | `xray-transport-hysteria/src/dialer.rs` + `xray-proxy-hysteria` | dialer | P1 |
| `5121c28b` | #6882 | **QUIC sniffer 零尾数据报** — 嗅探时不预判 long-header | `xray-transport-quic/src/sniff.rs`（若有） | sniffer | P3 |

### 1.3 协议配置层修复（2 项 · 应 port）

| Go 提交 | PR | 性质 | 本仓落点 |
|---|---|---|---|
| `5af2e9c2` | #7105 | **TLS RootCAs 默认走内置 bundle**（拒 OS 注入 CA）— 引入 `golang.org/x/crypto/x509roots/fallback/bundle` 替换 `config_other.go` | `xray-tls/src/{config,root_cas}.rs` — 当前是否走 OS 根？如走 = 应同步换 rustls-webpki-roots 内置 |
| `2cc08769` | #6246 | **TLS ECH DoH h2c 支持 `verifyPeerCertByName` "fromMitm"** | `xray-tls/src/ech.rs`（如有 ECH 模块） |
| `2cc08769` 同 | — | RAW outbound `tlsSettings` 经 `dialerProxy` 后置 | `xray-proxy-freedom/src/outbound.rs` |

### 1.4 公共/底层修复（2 项 · 应 port）

| Go 提交 | PR | 性质 | 本仓落点 |
|---|---|---|---|
| `2eedef51` | #7091 | **DNS pubsub cleanup 按 topic 数扩切片容量** — `pubsub.go` +1−1 | `xray-common/src/{pubsub,signal}.rs`（如有） |
| `00cde72a` | #6863 | **scenario 测试进程 leak** | 测试基建（本仓 `testing/`） |

### 1.5 配置层 / infra（不直接 port）

| Go 提交 | 性质 |
|---|---|
| `infra/conf/{dns,router,transport_security,transport_method,transport_finalmask}.go` | Lua 拨号方案 + XDNS finalmask conf 入口 + TLS RootCAs conf 默认 — 跟 §1.1/§1.3 同源 |

---

## 2. 关键深度

### 2.1 Lua scripting（拒绝 port 的理由加固）

Go 端构成（cbm 命中 `D-Project-Xray-core.app.router.startLuaRouter Function app/router/script_test.go:53-72`）：

- **9 个基建文件**（`common/lua/{lua,luar,luar_test,pool,pool_test,program,program_test,utils,utils_test}.go`） — 池/工具/反射桥
- **11 个集成文件** (`app/{dns,router}/{lua,lua_test,lua_benchmark_test,script,script_test}.go`) — 业务侧注册 `startLuaRouter` / `newScriptEngine`
- **3 个外溢** (`common/{geodata,log}/lua.go`) — geodata 查询与日志门面也被 Lua 调

总规模 ≈ **2200+ 行 / 18 文件 / 12 测试文件** — 已是半个嵌入运行时。

**Rust 端裁定**：与本仓 v3 裁决（`oracle-framing-v3.md` §7.5「血肉自定义事件 YAGNI 否决」）同源 — 脚本化机制 = 把配置语义挪出归一入口 = 破坏 MVVM 边界。除非出现可证伪需求（§7.5 三判据全过），否则不引。**已记红线**。

### 2.2 Mux race（6871）— 4 行修复，工作量 0.5h

Go diff（`common/mux/{client,session}.go`，7+ 行）：

```diff
 sm := m.sessionManager
-s := sm.Allocate(&m.strategy)
+s := sm.Allocate(&m.strategy, link.Reader, link.Writer)
 if s == nil {
     return false
 }
-s.input = link.Reader
-s.output = link.Writer
```

**修法核心**：把 input/output 在 `Allocate` 一并传入，避免 Dispatch 与 Close 间的两步写分裂 — `session.input/output` 改为 Allocate 内一次性设。本仓 `crates/xray-mux/src/{client,session}.rs` 同型结构，需核：

1. `session.rs::allocate` 签名是否含 reader/writer ？（大概率否 — 多走两步写）
2. `client.rs::dispatch_worker` 是否同型两步写？（大概率是）

**修法**：照搬 4 行，工作量 ≤0.5h，0 风险（race 在 normal path 上不影响正确性，仅 close 期间新 dispatch 写入 input 后立刻 close 可能丢首包）。

### 2.3 Mux UDP 帧覆盖（6822）— 8 行修复

`common/mux/reader.go` 9 行 diff，`framer.feed`/`framer.read` 复用 buf 的字段被下一帧覆盖。Rust 端 `crates/xray-mux/src/frame.rs::deframe` 同型 — `MultiBuffer` 切片后 next frame 同 slot 重写。需补：每帧 `clone()` 或借用 bound。

**工作量 ≤0.5h**，回归测试 = mux UDP 连续小包（已有 `mux-e2e`？待查）。

### 2.4 TLS RootCAs 默认（7105）— 安全债

Go 端改 `config.go` 引入 `golang.org/x/crypto/x509roots/fallback/bundle`（x509roots 增量更新源）替换 `config_other.go` 的 OS root 查询。

本仓 `xray-tls` 走 rustls + webpki-roots（cbm 抽） — 已走内置根，无 OS 注入风险。**此项本仓已合规**，无需 port。

但配置接口层 `infra/conf/transport_security.go` 的 `allowInsecure` / `disableSystemRoot` 是否对齐？待核（低优）。

### 2.5 WireGuard gvisor Clone 去掉（6856）— 内存税

Go diff（`proxy/tun/stack_gvisor.go` 1 行）：

```diff
-data := pkt.Clone().Data().AsRange().ToSlice()
+data := pkt.Data().AsRange().ToSlice()
```

`pkt.Clone()` 会复制整个 packet buffer — TUN 满载时吞吐 = N×PacketSize 拷贝。Rust 端 `xray-proxy-tun/src/netstack.rs` 如走 gvisor（`smoltcp` 或 `tun` crate），需核 UDP 转发路径是否 clone `Bytes`。

**工作量 ≤1h**，回归 = gvisor 模式 UDP 吞吐基准。

### 2.6 Hysteria 闭 conn（7107）— 39 行改动

Go diff（`transport/internet/hysteria/dialer.go` + `core/xray.go`）：加 `forced` flag，关联 `core.Instance` 在 instance stop 时强制 clean。本仓 `xray-transport-hysteria/src/dialer.rs` 同型 — 大概率有 `DialerManager` 但无 `forced` 路径。

**工作量 ≤30h**（结构略大），需派单。

### 2.7 gRPC redial ctx（6877）— 1 字修复

```diff
-c, err = internet.DialSystem(ctx, dest, streamSettings.SocketSettings)
+c, err = internet.DialSystem(gctx, net.TCPDestination(address, port), streamSettings.SocketSettings)
```

**修法**：ctx 改 gctx（redial loop 的 ctx）。本仓 `xray-transport-grpc` 同型位置大概率用 `&ctx` — **30 秒 diff + commit**。

### 2.8 Socks UDP stats（7101）— 8 行 wrap

`proxy/socks/server.go` 把 `tempUDPConn` 包成 `stat.CounterConnection` 以继承外层 conn 的 counters。本仓 `xray-proxy-socks/src/server.rs` UDP Associate 路径大概率没接 — **5 行 wrap**，需补 stats 测试。

### 2.9 TUN Windows（6874/7092）— 120+5 行

- 6874（+5 行）：Win IPv6 关闭时跳过 NIC 探测
- 7092（+120 行）：新文件 `tun_windows_outbound.go` 处理弱主机发送与出口转发

本仓 `xray-proxy-tun/src/outbound.rs` 是 Win 实现？还是 stub？需核（cbm: 11 文件含 `device.rs`+`device_stub.rs` —— **说明有 stub 分支**）。如果 Win 路径是 stub，影响低；如是真实现，必须 port。

---

## 3. 不在本窗口但同步可见的项

| 项 | 出处 |
|---|---|
| v26.10.10 是 pre-release（GitHub 元数据 `Pre-release`），但已有完整 Windows 构建（CI 产物 `Build and Release for Windows 7` 跑过 commit 701af60） | `https://github.com/XTLS/Xray-core/releases/tag/v26.10.10` 元数据 |
| 主仓 `v26.10.10 → main` 还有 17 commit（自 10-10 后） | `meta-author: 17 commits to main since this release` |
| `libXray` v1.260930.0 已 publish（v26.9.30 对齐） | `https://pkg.go.dev/github.com/xtls/libxray` |
| 9e55a6ed 改了 `transport/internet/masque/dialer.go` + warp.go 共 +150 行 | MASQUE WARP 体量 |

---

## 4. 推荐同步次序（PM 拍板）

| 序 | 项 | 工作量 | 拍板门槛 |
|---|---|---|---|
| 1 | gRPC redial ctx（6877）— 30 秒 | ≤0.1h | 直接派 fullstack |
| 2 | Mux race（6871） | 0.5h | 同 |
| 3 | Mux UDP 帧覆盖（6822） | 0.5h | 同 |
| 4 | Socks UDP stats（7101） | 0.5h | 同 |
| 5 | WireGuard gvisor Clone 去掉（6856） | 1h | 同（gvisor 路径用着才做） |
| 6 | TLS RootCAs 合规核查 | 0.5h 调研 | 我们已合规，预计 0 改动 |
| 7 | TUN Win IPv6（6874/7092） | 2-4h | 视 Win 真实现 vs stub |
| 8 | WireGuard kernelTun IPv6 表（6881） | 1h | 视 Linux 实现 |
| 9 | DNS pubsub 清理（7091） | 0.5h | 同 |
| 10 | Hysteria 闭 conn（7107） | 2-3h | 同 |
| 11 | QUIC sniffer 零尾（6882） | 0.5h | 同 |
| 12 | WireGuard ICMP pong（6855） | 2h + 安全决策 | 拍板后派 |

**总工作量**：≤16h，按 bd 现状分批（首批 §1.1-§4 共 6 项 ≤4h，可一次冲刺）。

---

## 5. 待 PM 拍板项

1. **是否同时更新本仓 Rust 端 docs/refs/go-sync-v26.10.10.md 入 CHANGELOG**？（已记）
2. **是否开 bd 票包** go-sync-2026-10-10 涵盖 §2.1-§2.9？（建议：建父票 + 子票，避免一次塞 11 条）
3. **是否新增 Lua 脚本在 Rust 端的红线文件**？（建议：在本文件 §2.1 加进 v3 决策.md §7.5 的 YAGNI 清单末尾）
4. **是否派性能子代理在 v26.10.10 上跑一遍 32 节点**？（建议：派 — 31 协议可能有 mux 影响面回归）

---

## 6. 索引元数据

- 同步日期：2026-10-16
- Go cbm：`D-Project-Xray-core` 节点 46749 / 边 122989（索引于 `701af607`）
- 本仓 cbm：`D-Project-Xray-core-rust` 节点基线未变（master `87d72569`）
- Git log：23 commit，详见 §1 各表
- 工作区状态：Go 仓已 checkout `v26.10.10`（detached），Rust 仓未动