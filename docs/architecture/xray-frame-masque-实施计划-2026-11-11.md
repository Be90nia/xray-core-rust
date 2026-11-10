VERDICT: DONE

# MASQUE 实施规划（2026-11-11）

> **裁定基准（上游）**：`D:/Project/Xray-core` @ `676eaf66` = tag **v26.11.9**（`git tag --points-at HEAD` → `v26.11.9`）。
> **本仓快照**：HEAD `3659167d`（工作树干净）。
> **前身**：`docs/architecture/xray-frame-masque-契约级任务书-2026-10-30.md`（rev 快照，行号锚基于 `92ccc939`=v26.10.17）。本文是它的**现行版**：§0 逐条列出它成立/过期的条目，其后各节以今日实测重建。
> **一句话**：**做**，分层与任务书同构，但**必须押后 h3**（`h3` 0.0.8 的 `:protocol` 是闭集，表达不了 `connect-ip`，见 §7 R11），且**零新机制**——H2 帧层、TLS、finalmask、netstack、UDP 会话、池、scope、注册表全部用现有件。

---

## 0. 与前身任务书的差异（成立 / 过期 / 漏项）

| # | 任务书口径（2026-10-30） | 今日实测（676eaf66 / 3659167d） | 处置 |
|---|---|---|---|
| 1 | Go 有完整 MASQUE（≈5218 行） | **成立**：`git grep -il masque` → 39 文件；`proxy/masque` + `transport/internet/masque` 非测试非 pb `.go` = **5218 行**（逐文件见 §2） | 沿用 |
| 2 | 裁定基准 26.10.17 | **过期**：基准已升 v26.11.9。但 masque 源码 **26.10.17→26.11.9 零差异**（masque 两目录 `git diff --stat` = 仅两个 `config.pb.go` 各 2+2 行生成器版本头；`infra/conf/masque.go` 未变；`infra/conf/{transport_internet,xray}.go` 的 24+3 行变化全是 xdrive 门控与入站 App 顺序） | 语义结论全部沿用；锚点按 676eaf66 重取 |
| 3 | `TransportProtocol::Masque` 枚举已存在 | **成立**：`crates/xray-common/src/net/transport.rs:55,76,100` | 沿用，不新增枚举 |
| 4 | 配置层硬拒 | **成立**：`crates/xray-conf/src/init.rs:332-349`（四键 + `network=masque|xdrive` 双硬错），测试锚 `:826-850` | 沿用（放开顺序见 §7 R13） |
| 5 | proto 已生成、无需新增 | **成立**：`crates/xray-proto/src/lib.rs:176-178,306-308`；镜像 `protos/transport/internet/masque/config.proto` 与 Go 逐字段一致（`xmux` 复用 `splithttp.XmuxConfig`） | 沿用 |
| 6 | 复用 hyper **1.12** 的 extended CONNECT | **过期（版本）**：workspace 锁 `hyper = 1.10.1` / `hyper-util = 0.1.20`。**能力已静态核实**：`hyper-1.10.1/src/server/conn/http2.rs:257-261 enable_connect_protocol()`；`hyper-util-0.1.20/src/server/conn/auto/mod.rs:1059-1063` 透传；客户端 `hyper-1.10.1/src/proto/h2/client.rs:27,716-733`（`ext::Protocol` → `h2::ext::Protocol`；**CONNECT 请求体非零长度直接 `Err(new_user_invalid_connect())`**） | 结论不变，U1 spike 仍必须跑（§5 B0） |
| 7 | 可复用 `flow_window.rs` | **过期**：`crates/xray-transport-splithttp/src/flow_window.rs` 是 `pub(crate)`（`lib.rs:75`）。可用的是 `transport.rs:71-85` 的 6 个 `pub const` | 改为**上浮常量**到 `xray-transport`（§5 B2 小项） |
| 8 | `xray-frame::ipstack` 需 PM 授权（R6） | **已裁定**（PM 2026-11-11）：授权**移动 + re-export**，独立批次，先于 masque M2 接线 | §4.2 + §5 B3 |
| 9 | 注册入口「`xray-cli` 或 `xray-core`」 | **过期（定位）**：唯一聚合口 = `crates/xray-core/src/register.rs:102 register_all_transports()`（`splithttp` 在 `:137-138`） | 接线点改为该函数 |
| 10 | arm_builders 两处 | **成立但更精确**：数据源 = `crates/xray-core/src/arm_builders/mod.rs:217 INBOUND_CTORS` / `:295 OUTBOUND_CTORS`；装配成 `xray-frame::PluginRegistry` 在 `crates/xray-core/src/arm_registry.rs:177-185` | 沿用意 |
| 11 | 插件契约参照 `wireguard plugin.rs:44-57` | **成立（路径变）**：`crates/xray-proxy-wireguard/src/plugin.rs` 的 `WG_CLAUSES` / `WG_CONTRACT` | 沿用 |
| 12 | **未提 finalmask** | **漏项（Go 实测消费 4 处）**：`dialer.go:163-164`（h2 TCP 拨号）、`:84-85`（h3 UDP）、`hub.go:168-169`（listen）、`:122-123`（listen packet） | 新增接线项（§3 第 9 行） |
| 13 | **未提内存预算账本** | **漏项**：`crates/xray-core/src/memory_budget.rs` 已按协议登记 `H2_MAX_SEND_BUF_PER_CONN_BYTES` / `SPLITHTTP_H2_*_WINDOW_BYTES`；masque 单隧道 16MiB send_buf 不入账则 256MB 档超配 | 新增接线项（§7 R14） |
| 14 | **未提 h3 crate 能力边界** | **漏项（硬约束）**：`h3-0.0.8/src/ext.rs` 的 `ProtocolInner` 只有 `WebTransport`/`ConnectUdp`，`Protocol` 无 `from_static`；0.0.8 即 crates.io 最新 | h3 押后 + vendor patch 决策（§7 R11） |
| 15 | 任务书 §1.1「无 per-UDP-session stream，多路复用发生在 IP 层」 | **成立**（`proxy/masque/server.go:37 tunnelQueueSize=512`、`connectip/request.go:20 requestProtocol="connect-ip"` 均在 676eaf66 实测在位） | 沿用；**本文明确纠正一个常见误设**：Go 的 MASQUE **不是**「HTTP/3 上的 CONNECT-UDP 每 UDP 会话一条流」，而是 **RFC 9484 CONNECT-IP over HTTP/2**（`connect-ip` 扩展 CONNECT），一条流承载全部 5 元组；h3 只是可选承载（`hub.go:47-50 serverVersions`：`h3 = contains(h3) \|\| !h2`） |

---

## 1. 目标与非目标

### 1.1 目标（一句话）

在 Rust 侧补齐 Go v26.11.9 的 MASQUE 能力：**transport 层**（`xray-transport-masque`：CONNECT-IP 胶囊内核 + h2 绑定 + 地址池）与 **proxy 层**（`xray-proxy-masque`：客户端隧道内目标拨号 / 服务端地址分配 + 包路由 + dispatcher 桥），接通配置、构造表与注册表，并达成 Go↔Rust 双向互通（h2；h3 押后）。

### 1.2 非目标（明确不做）

1. **Cloudflare WARP 变体**（`warp.go` 78 行：ECDSA 临时证书 + 公钥 pin + 20 字节 CID + draft datagram setting `0x276`）——配置出现 `warp` 即装配期 fail-visible 拒绝。
2. **CONNECT-UDP（RFC 9298）本体**与 `connect-udp` `:protocol`——Xray 用 connect-ip，二者不共存（`connectip/request.go` 仅认 `connect-ip`）。
3. **URI 模板形式的 IP flow forwarding**（Go 直接报错）+ 多跳 forwarding 链。
4. **H3 模式的实现**——本规划只给「需 vendor patch h3」的决策与验收，不排进必做批次（§7 R11）。
5. **xmux 隧道池**——B1–B5 只做「每 outbound 连接一条隧道」，池化留到有测量证据再说（§3 第 16 行、§7 R15）。
6. **收编 `xray-proxy-tun` 的 netstack 副本**（1449 行）——超出本票，另立 bd 票（§7 R6）。
7. 不动红线：`tests/**`、`dist/**`、`.github/workflows/**`、`protos/**`、`vendor/**`、`docs/refs/**`、`crates/xray-transport-tcp/register.rs`、`crates/udf-frame`。
8. 不重构 `xray-frame` 与 `xray-proxy-wireguard` 的任何数据面语义（净移动除外，见 §5 B3）。

---

## 2. 上游基准（Go 676eaf66 = v26.11.9）

### 2.1 「Go 有没有 MASQUE」——判定证据

```bash
cd D:/Project/Xray-core
git grep -il masque | wc -l        # → 39
git diff --stat 92ccc939 676eaf66 -- proxy/masque transport/internet/masque infra/conf/masque.go
# → proxy/masque/config.pb.go              | 4 ++--
#    transport/internet/masque/config.pb.go | 4 ++--
#    2 files changed, 4 insertions(+), 4 deletions(-)     ← 全是 protoc-gen-go 版本头
git diff --stat 92ccc939 676eaf66 -- infra/conf/transport_internet.go infra/conf/xray.go
# → 2 files changed, 24 insertions(+), 3 deletions(-)     ← xdrive 门控 + 入站 App 顺序，与 masque 无关
```

**结论：Go v26.11.9 有完整 MASQUE，且与前身任务书撰写的 v26.10.17 语义零差异。**

### 2.2 要移植的文件与体量（实测 `wc -l`，非测试非 pb）

| 区 | 文件 | 行 | 本规划处置 |
|---|---|---|---|
| `proxy/masque` | `server.go` | 554 | 移植（服务端：地址分配 / 包路由 / dispatcher 桥） |
| | `client.go` | 397 | 移植（客户端：隧道内目标拨号） |
| | `pool.go` | 80 | **新写**（Rust 侧小模块，§3 第 17 行） |
| | `account.go` | 108 | 移植（Basic 认证 + 常数时间比较） |
| `transport/internet/masque` | `dialer.go` | 347 | 移植（client dial；finalmask 接线） |
| | `hub.go` | 422 | 移植（server listen；ALPN 选择 + 拒绝语义） |
| | `conn.go` | 129 | 移植（会话外壳：读写 IP 包 / MTU） |
| | `config.go` | 27 | 移植（path 缺省 / keepalive 缺省） |
| | `warp.go` | 78 | **不移植**（非目标 1） |
| | `http2.go`(614) + `http2_server.go`(680) | 1294 | **不移植**（手写 H2 帧层 → 用 hyper，§3 第 1/2 行） |
| `connectip`（协议内核） | `conn.go` 721 · `capsule.go` 308 · `http2.go` 218 · `client.go` 115 · `request.go` 101 · `icmp.go` 94 · `address.go` 86 · `iprange.go` 73 · `proxy.go` 43 · `checksum.go` 23 | 1782 | 移植（协议 wire 语义；Rust 侧按 §3 第 18/19 行评估体积） |
| `infra/conf` | `masque.go` | 103 | 移植（settings 校验：每族最多一前缀、`mtu∈[1280,65535]`、users） |
| 合计 | | **5218 + 103** | 需移植 ≈ **3949 行**（剔除手写 H2 1294 与 warp 78 → 3846，加 conf 103） |

### 2.3 语义锚点（676eaf66 实测，供执行者对照）

| 语义 | 锚 |
|---|---|
| 请求协议名 | `connectip/request.go:20 requestProtocol = "connect-ip"` |
| 缺省路径 | `transport/internet/masque/config.go`（`/.well-known/masque/ip/*/*/`，字面 `*` 原样发） |
| 服务端 ALPN → h2/h3 | `hub.go:47-50 serverVersions`（**无 h2 即 h3**，风险 R9） |
| TLS 硬要求 | `hub.go:52-60`（无 tls config → `Err`） |
| 服务端 SETTINGS | `http2_server.go`（`ENABLE_CONNECT_PROTOCOL=1`、`MAX_CONCURRENT_STREAMS=100`、握手 10s） |
| 拒绝语义 | `405`/`501`/`400`/`401 + WWW-Authenticate: Basic realm="masque"`/`503` |
| 地址请求应答 | `proxy/masque/server.go:343-371`（`serveAddressRequests`：按族取首个未用地址 + 其余作为 additional） |
| 全路由通告 | `proxy/masque/server.go:fullRoutes`（`0.0.0.0/0`、`::/0`） |
| 隧道间转发有界队列 | `proxy/masque/server.go:37 tunnelQueueSize = 512` |
| 胶囊类型值 | `connectip/capsule.go`：DATAGRAM=0 / ADDRESS_ASSIGN=1 / ADDRESS_REQUEST=2 / ROUTE_ADVERTISEMENT=3；单胶囊 payload ≤ `1<<16-1`，条目 ≤ 8192 |
| finalmask 消费 | `dialer.go:163-164`、`hub.go:168-169`、`hub.go:122-123`、`dialer.go:84-85` |
| MTU / ICMP 回灌 | `connectip/conn.go`（超 MTU 返回 ICMP packet-too-big，由上层回灌）；`MinPacketSize=1280` |

---

## 3. 现有件映射表（评审打回项核心）

> **口径**：每行给真实符号 + 路径。**「新写」行必须带举证**（三类现有件都装不下的理由）。

| # | 能力需求 | 现有件（符号 + 路径） | 采用方式 | 消费点 |
|---|---|---|---|---|
| 1 | h2 客户端 extended CONNECT（`:protocol`） | `hyper::ext::Protocol`（`C:\...\hyper-1.10.1\src\ext\mod.rs:86`）+ CONNECT 分支 `src/proto/h2/client.rs:716-733`（**请求体必须为空**） | **直用**（workspace 已有 `hyper = 1`，锁定 1.10.1） | `xray-transport-masque/src/h2.rs` 拨号 |
| 2 | h2 服务端 extended CONNECT | `hyper::server::conn::http2::Builder::enable_connect_protocol()`（`hyper-1.10.1/src/server/conn/http2.rs:257`）+ `hyper-util-0.1.20/src/server/conn/auto/mod.rs:1059-1063` | **直用** | `xray-transport-masque/src/hub.rs` accept |
| 3 | h3 帧层（M6 押后时用） | `crates/xray-transport-splithttp/src/h3_client.rs`（`H3Conn`，1314 行）+ `src/transport.rs` h3 服务端（`h3::server::Connection`，`:1093-1199`）；依赖 `h3 0.0.8` + `h3-quinn 0.0.10` | **直用的能力面**，但 `:protocol` 表达不了 `connect-ip`（§7 R11）⇒ **h3 批次阻塞** | 未来 `xray-transport-masque/src/h3.rs` |
| 4 | TLS 客户端（含指纹 / ALPN） | `xray_tls::client_config::build_client_config(security, security_json, server_name)`（`crates/xray-tls/src/client_config.rs:80`）+ `xray_tls::utls::client`（`utls.rs:410`）+ `btls_client::connect_with_alpn`（`btls_client.rs:1341`） | **直用** | masque dial 的 TLS 段（与 splithttp 同款调用序） |
| 5 | TLS 服务端（SNI / 证书） | `xray_tls::server_config::build_server_config(security, security_json)`（`crates/xray-tls/src/server_config.rs:397`）+ `SniCertResolver`（`:142`） | **直用** | masque hub 的 TLS accept |
| 6 | IP 包 ↔ 用户态栈 | `crates/xray-proxy-wireguard/src/netstack.rs`（`WgNetStack`：`new/ingest_rx/drain_tx/poll/drain_accepted/drain_udp/udp_send_reply`，1218 行，仅依赖 smoltcp+std） | **移动 + re-export** 到 `xray-frame::ipstack`（PM 裁定，§4.2） | masque server/client 两侧 |
| 7 | UDP → dispatcher | `xray_app_dispatcher::UdpDispatchSession`（`crates/xray-app-dispatcher/src/udp_session.rs:99`，`send_packet`/`recv_packet`）+ wireguard 的 per-源会话形态（`crates/xray-proxy-wireguard/src/inbound.rs:507-525`） | **直用**（照抄形态，不新写） | masque server 的 UDP 出站、client 的 UDP 目标 |
| 8 | TCP → dispatcher | `xray_app_dispatcher::DispatchHandler` + `crate::wiring::InboundDispatchHandler`（`crates/xray-core/src/wiring.rs:570`）+ `xray_buf::io::{new_reader,new_writer}` | **直用** | masque inbound 的 TCP 流接入 |
| 9 | finalmask（Go 实测消费 4 处） | `xray_transport::finalmask::{shared_tcpmask_manager_from_json, wrap_conn_client_into_connection, wrap_conn_server_into_connection, parse_finalmask_udp_chain}`（`crates/xray-transport/src/finalmask/mod.rs`） | **直用**（与 splithttp/kcp 同款接线） | masque dial（h2 TCP 层）/ hub（listen 层） |
| 10 | 任务托管 / 停机 | `xray_frame::scope::ComponentScope`（`crates/xray-frame/src/scope.rs:509`：`new/spawn/downgrade/close_gate/in_flight/live_refs`）+ `ScopeRef`（`:387`）+ `xray_frame::compat::spawn_reaping` | **直用**（ADR-0004 持有者契约；禁自持 JoinSet） | 隧道任务、包泵、accept 循环 |
| 11 | 缓冲池 | `xray_buf::Buffer::new_pooled`（`crates/xray-buf/src/buffer.rs:70`）/ `alloc::alloc`（`alloc.rs:167`）+ `xray_frame::pool::{BufferPool, XrayBufPool, PooledBuffer}`（`crates/xray-frame/src/pool.rs:133,157,74`）经 `ctx.pool()`（`crates/xray-frame/src/context.rs:340`） | **直用** | IP 包缓冲 / 胶囊读写缓冲 |
| 12 | 插件契约（L1–L5） | `xray_frame::plugin::{Plugin, PluginContract, ClauseId}`（`crates/xray-frame/src/plugin.rs:13,48,87`）+ `contract_assert::assert_plugin_contract!`（`lib.rs:42`） | **直用**（12 条全适用 + 3 条 extra，见 §4.4） | `xray-proxy-masque/src/plugin.rs` |
| 13 | 构造表 / 装配注册表 | `crates/xray-core/src/arm_builders/mod.rs:217 INBOUND_CTORS`、`:295 OUTBOUND_CTORS` → `crates/xray-core/src/arm_registry.rs:177-185`（`xray_frame::registry::PluginRegistry`，`registry.rs:23`） | **直用**（各加一行） | `inbound:masque` / `outbound:masque` |
| 14 | transport 注册表 | `xray_transport::dialer::register_transport_dialer`（`crates/xray-transport/src/dialer.rs:669`）/ `listener_registry::register_transport_listener`（`listener_registry.rs:80`）；聚合口 `crates/xray-core/src/register.rs:102 register_all_transports()` | **直用**（在聚合口加两行 `reg(...)`） | masque dialer/listener 注册 |
| 15 | 超时 / 空闲 / 预算 | `xray_frame::deadline::{with_deadline, HandshakeDeadline, IdleDeadline}`（`deadline.rs`）+ `xray_frame::budget`（`crates/xray-frame/src/budget.rs`） | **直用** | 握手 10s、隧道空闲、send_buf 入账 |
| 16 | 隧道池（Go 用 `splithttp.XmuxManager`） | `crates/xray-transport-splithttp/src/mux.rs`：`XmuxConn`(:44) / `XmuxClient<C>`(:52) / `XmuxManager<C>`(:150) / `ManagerPool<C>`(:292)；配置 `config.rs:139 XmuxConfig`、`RangeConfig` | **B1–B5 不接**（`shortcut:` 每 outbound 连接一条隧道，Go 的池是握手节省非正确性）；若 A/B 证明握手成本成瓶颈 → 移动至 `xray-frame::xmux` + splithttp re-export（同 PM 授权形态） | 未来 masque client 池 |
| 17 | 服务端地址池 | **未找到等价件**。检索方式：`grep -n "IpCidr\|allocate\|next_host\|address_pool" crates/xray-proxy-wireguard/src/users.rs;crates/xray-common/src/net`；udf `skeleton_infra::memgov::{BoundedRegistry, MemoryPool}` 是 KV/字节池、`std_ext::cache` 是缓存，均无「前缀内排除网络/广播/服务器地址 + 环形游标 + used 集」语义 | **新写**（≈80 行，`xray-transport-masque/src/pool.rs`）。举证：纯 Xray 配置语义（`infra/conf/masque.go` 每族一前缀、`mtu` 范围），非进程级通用机制 ⇒ 按 §3.5.3 不进 udf；体量低于提炼门槛且只有一个消费方 ⇒ 不设 `udf-promotion-candidate` | masque server 地址分配 |
| 18 | 胶囊编解码（RFC 9297 + 9484 四类） | **帧容器未找到等价件**。检索：udf 三 crate 全域（`pool/retry/cache/fx/shutdown/scheduler/clock/config/logx/compose/json/lint/id/parse_mock`）无 capsule 容器；**varint 已有等价件** = `crates/xray-proxy-hysteria/src/protocol.rs:39 read_varint` / `:62 write_varint` / `:91 varint_len`（纯 RFC 9000 varint，零 xray 语义）。注：`h3::proto::varint` **不可直用**——`h3-0.0.8/src/lib.rs:33` 的 `pub mod proto` 挂在 feature `i-implement-a-third-party-backend-and-opt-into-breaking-changes` 下 | **胶囊帧容器新写**（`capsule.rs`，≈400 行；举证：RFC wire 语义属协议方向件，§3.5.3 明令不进 udf）；**varint 用「移动 + re-export」**：三函数上浮到 `xray-transport` 的 wire helper 模块，hysteria 侧改 `pub use`（件头打 `udf-promotion-candidate`——零 xray 语义机制终态归 udf，但本票不动 udf 仓） | connect 会话读写 |
| 19 | CONNECT-IP 会话状态机 | **未找到等价件**（同上）。Go `connectip/conn.go` 721 行里约一半是 Go 的 h2 手写流控（`:467-477,592-700`），Rust 侧由 hyper 承担 | **新写**（`connect.rs`，≈350 行：地址面 + 包收发 + MTU/ICMP 回灌） | `xray-transport-masque` 对外会话面 |
| 20 | 安全默认策略（私有地址） | `xray_proxy_freedom::config::get_default_rule_type`（`crates/xray-proxy-freedom/src/config.rs:1200`）**已把 `"masque"` 映射到 `DefaultRuleType::BlockPrivate`**；CIDR 表 `DEFAULT_BLOCK_PRIVATE_CIDRS`（`:967`）+ `private_ip_matcher()`（`:1178`） | **直用，零新写**——前提：masque inbound 把协议名填进 `AccessContext.protocol`（`crates/xray-app-dispatcher/src/default.rs:352`）；UDP 侧同（`crates/xray-proxy-freedom/src/udp.rs:439,536`） | freedom 出站对 masque 入站的默认阻断 |
| 21 | 日志 | `xray_frame::logging::{LogFacade, HotLog}`（`logging.rs`）+ `xray-common/src/log` 三通道 | **直用**（target `xray_frame::transport::masque` / `xray_frame::proxy::masque`） | 全模块日志 |
| 22 | 配置段路由 | `xray_frame::config::PluginConfig` + `build_plugins_from_config`（`config.rs`） | **直用** | `xray-proxy-masque` settings 段 |
| 23 | h2 流控窗参数 | `crates/xray-transport-splithttp/src/transport.rs:71-85`：`H2_INITIAL_STREAM_WINDOW=32MiB`、`H2_INITIAL_CONNECTION_WINDOW=32MiB`、`H2_MAX_SEND_BUF_SIZE=16MiB`、`H2_SERVER_INITIAL_STREAM_WINDOW=16MiB`、`H2_SERVER_INITIAL_CONNECTION_WINDOW=32MiB` | **上浮 + re-export**（`pub const` 但属 splithttp 模块；移到 `xray-transport` 供两 crate 共用，splithttp 改 `pub use`，值不变） | masque h2 client/server 的 `.initial_stream_window_size()` 等 |

### 3.1 「本仓已有 X，不新写」清单（至少 2 处，此处 8 处）

1. **H2 帧层**：hyper/h2 的 extended CONNECT ⇒ **不移植 Go 的 `http2.go` + `http2_server.go`（1294 行）**，也不自造流控/GOAWAY。
2. **h3 栈**：`splithttp::h3_client::H3Conn` + `transport.rs` 的 h3 server（h3 0.0.8 + h3-quinn 0.0.10 已在树内）⇒ **h3 批次不新增第三方依赖**，只缺 `:protocol=connect-ip` 表达力。
3. **finalmask**：`xray_transport::finalmask::*` ⇒ 不新写 TCP/UDP 伪装层（Go 侧 4 个消费点全覆盖）。
4. **smoltcp 用户态栈**：`WgNetStack` 净移动 ⇒ **不写第三份 netstack**（现有两份：`xray-proxy-tun` 1449 行、`xray-proxy-wireguard` 1218 行）。
5. **UDP 会话到 dispatcher**：`UdpDispatchSession` + wireguard 的 per-源会话形态 ⇒ 不新写 XUDP 适配。
6. **私有地址默认阻断**：freedom 的协议→默认规则表已含 `"masque"` ⇒ 不新写地址安全策略。
7. **varint**：`xray-proxy-hysteria::protocol::{read_varint, write_varint, varint_len}` 已是 RFC 9000 varint 的现成实现 ⇒ 不新写，上浮到 `xray-transport` 共用（`h3::proto` 不可用作替代：受 breaking-changes feature 门控，`h3-0.0.8/src/lib.rs:33`）。
8. **h2 流控窗数值**：splithttp 的 6 个 `pub const`（32/32/16/16/32MiB）⇒ 不重新调参、不复制数值。

---

## 4. 架构归属判定（§3.5.5 三判据逐条）

### 4.1 判定总表

| 件 | 判据 1（零 xray 语义 → udf） | 判据 2（否则 → xray-frame） | 判据 3（派生层不合适 → 留主仓，须举证） | 结论 |
|---|---|---|---|---|
| IP 包 ↔ TCP/UDP ↔ dispatcher 桥 | 不成立：含 `DispatchHandler`/`AccessContext`（Xray 语义）+ smoltcp 是网络方向件（§3.5.3） | **成立**：三消费方跨 crate，公共祖先 = `xray-frame`（已依赖 udf + xray-buf + smoltcp 可为 workspace 依赖） | 不成立 | **`xray-frame::ipstack`（移动 + re-export）** |
| 胶囊帧容器 / CONNECT-IP 会话 / 地址池 / h2 绑定 | 不成立：全是 Xray 消费的协议 wire 语义与配置语义 | 不成立：只有 masque 一个消费方，进框架 = 为单消费方造抽象（违 ponytail） | **成立，举证**：①协议 wire 语义（§3.5.3 明令不进 udf，且框架层无需知 connect-ip 字节格式）②无第二消费方，`xray-frame` 收它会使其感知协议细节（§3.5.3「骨架不感知血肉」） | **留 `xray-transport-masque`**（件头写「udf 不适用」+ 无提炼候选） |
| proxy 客户端/服务端（隧道内拨号、地址分配、包路由、认证） | 不成立 | 不成立（单消费方 + 依赖 dispatcher） | **成立**：协议内容，非机制 | **留 `xray-proxy-masque`（薄适配）** |
| h2 窗常量 | 不成立（Go 兼容数值） | 成立（机制跨 crate 复用） | — | **上浮 `xray-transport` + splithttp re-export** |
| QUIC varint 编解码 | 成立（零 xray 语义）→ 终态应归 udf，但**本票禁动 udf 仓** | 退档成立（两个消费方：hysteria 协议 + masque 胶囊） | — | **上浮 `xray-transport::wire::varint` + hysteria re-export**，打 `udf-promotion-candidate` |
| 隧道池（xmux） | 不成立（`XmuxConfig` 是 Go 兼容配置） | 成立（若需要，跨 crate 复用） | — | **暂不接；需要时移动至 `xray-frame::xmux`** |
| 私有地址安全策略 | — | — | — | **零新写**：freedom 现有件直用 |

### 4.2 PM 裁定（2026-11-11，本节为执行依据，非建议）

> **R6 / ADR-M2：授权提炼，但只允许「移动 + re-export」形态。**

1. **移动式**：把 `crates/xray-proxy-wireguard/src/netstack.rs` 的语义键搬进 `crates/xray-frame/src/ipstack/`，wireguard 侧改为 `pub use`，其内部路径与对外行为**字节不变**。
2. **独立批次、先于 masque M2 接线**：单独验收 = `cargo test -p xray-proxy-wireguard --all-targets` + 红线回归 `cargo test -p xray-integration-tests --test integration_wireguard_dataplane` + `git diff` 复核「纯移动、零逻辑改动」（出现任何条件分支/常量变化即打回）。
3. `crates/xray-proxy-wireguard/src/plugin.rs` 的 `WG-TUN-FROZEN` 声明文案同步改为「netstack 已提炼至 xray-frame，本 crate 经 re-export 冻结」，`tests/plugin_contract.rs` 的 extra 条款断言同步。
4. `xray-proxy-tun` 的那份副本**本票不动**（超出票面，另立 bd 票登记，见 §7 R6）。

**执行约束（本文补充）**：`xray-frame` 目前不依赖 `smoltcp`（`crates/xray-frame/Cargo.toml` 依赖面 = udf 三 crate + tokio/serde/tracing/log/bytes/xray-buf/arc-swap）。移动批次须给 `xray-frame` 加 `smoltcp = { workspace = true }`（**workspace 已有，零新第三方**），并保持 clippy `unwrap_used = "deny"` 与 `disallowed_methods = "warn"` 纪律不变。

### 4.3 层的模块边界（契约，不是实现）

```text
xray-transport-masque（新 crate，薄协议层）
  ├─ capsule.rs   CapsuleReader<W>/CapsuleWriter<R>：四类胶囊 + 上限（payload ≤ 65535、条目 ≤ 8192）
  ├─ connect.rs   ConnectIpSession：send_packet/recv_packet/request_addresses/assign_addresses/
  │               advertise_route/serve_address_requests/max_packet_size/close
  ├─ h2.rs        connect_h2(io, cfg, authority) -> ConnectIpSession；ServerConn{request_meta, accept, reject}
  ├─ pool.rs      AddressPool（每族一前缀、环形游标、used 集）
  ├─ config.rs    Config{host,path,headers,xmux?} ← masqueSettings JSON + proto Config
  ├─ error.rs     MasqueError{Auth|Protocol|Io|Mtu|Rejected(StatusCode)}（ClauseId::ErrorClassifiedNoPanicEscape）
  └─ register.rs  register_dialer() / register_listener()（→ xray_transport 注册表）

xray-proxy-masque（新 crate，薄适配 + 插件）
  ├─ plugin.rs    MasquePlugin: Plugin + PluginContract（12 条 + 3 extra）
  ├─ client.rs    隧道建立 → ipstack 目标 Dial(tcp|udp) → 双向 copy
  ├─ server.rs    Basic 认证 → 地址分配 → 包路由（隧道间 512 有界队列 / 本机栈）→ dispatcher 桥
  └─ config.rs    settings.users / settings.address[] / settings.mtu 校验

xray-frame/ipstack（移动来源 = wireguard netstack.rs，语义键同名）
  ├─ PacketStack    ingest_rx(..) / drain_tx() / poll(now) / drain_accepted() / drain_udp(now) / udp_send_reply(..)
  └─ （bridge 面在 masque 侧薄适配：复用 xray_app_dispatcher 的 DispatchHandler/UdpDispatchSession）
```

**契约纪律**：`ConnectIpSession` 的 `recv_packet` 返回**整包 `Vec<u8>`**，**不照抄** Go 的 `io::ErrShortBuffer` 续读约定（Rust 无此惯例，照抄只会制造第二套约定）。

### 4.4 插件契约声明（L1/L4 内容）

- `clauses` = 12 条全适用（`AuthErrorClassified` / `HandshakeDeadline` / `ConnIdPresent` / `PoolDiscipline` / `SpawnManaged` / `StopRegistered` / `ConfigSectionOnly` / `ErrorClassifiedNoPanicEscape` / `BoundedResources` / `LogDiscipline` / `SecretMasking` / `HotPathFreeze`）。
- `extra` = 3 条：
  - `MASQUE-TLS-REQUIRED`：必须 `security=tls` 且 ALPN 含 `h2`（Go `hub.go:52-60`）。
  - `MASQUE-ADDR-POOL`：每族仅一个前缀；服务器自身地址与网络/广播地址不得分配（Go `pool.go:31-45`）。
  - `MASQUE-H2-ONLY`：本批只支持 `h2`；`security=tls` 且 ALPN 缺省时**硬错**（不静默走 h3；对齐 Go `hub.go:47-50` 的反向语义）。
- `not_applicable` = 空（本批不复用 wireguard 的冻结豁免）。

---

## 5. 分批次实施计划

> **依赖顺序**：B0 → B1 → B2 →（B3 与 B2 可并行）→ B4 → B5；B6 阻塞待决策。
> **每批都是可独立验证的出口**；批内任务按 2–5 分钟到 1 天粒度切。

### B0 —— U1 spike：hyper extended CONNECT 全链路（**第一批第一件事**，0.5 人日）

| 步骤 | 内容 |
|---|---|
| B0.1 | 建 crate 骨架：`crates/xray-transport-masque/{Cargo.toml,src/lib.rs}` + 根 `Cargo.toml` members 一行（依赖面：hyper/hyper-util/http/http-body-util/tokio/bytes/xray-buf/xray-common/xray-transport/xray-tls/xray-proto/xray-frame —— **不引 h3**，varint 走上浮件） |
| B0.2 | 写 `tests/h2_extended_connect_spike.rs`：自建 hyper auto server `.http2().enable_connect_protocol()` + hyper h2 client 插 `ext::Protocol("connect-ip")`；断言 ① server 侧收到 `:protocol=connect-ip` 与 `:method=CONNECT` ② client 拿到 200 + `Upgraded` ③ 双向各传 1 KB 字节一致 ④ 空请求体（非空必须 `Err`） |
| B0.3 | 记录结论到本文 §7 R1（成功 / 回退 raw `h2`） |

**失败回退（已预核）**：`h2` 0.4.19 已在 workspace（`Cargo.toml:142`）；`h2::server::Builder::enable_connect_protocol`（`h2-0.4.19/src/server.rs:1043`，连接级 `:500`）与 `h2::ext::Protocol`（`h2-0.4.19/src/ext.rs:13`，`value: BytesStr` 即**任意字符串**，含 `connect-ip`）均在位；仍是复用而非自造帧层。回退代价 +2 人日。

### B1 —— 胶囊内核 + 配置面（2.5 人日）

| 步骤 | 内容 |
|---|---|
| B1.1 | `capsule.rs`：四类胶囊编解码 + 上限校验 + 未知类型跳过；varint 用**上浮后的** `xray_transport::wire::varint::{read_varint, write_varint, varint_len}`（移动自 `xray-proxy-hysteria/src/protocol.rs`，见 B1.5） |
| B1.2 | `tests/capsule_golden.rs`：按 Go `connectip/capsule.go` 构造形态逐字节 golden（含 `DATAGRAM` 的 `contextID=0` 前缀、`ADDRESS_ASSIGN` 的 `{varint reqID, varint prefixLen, addr}`） |
| B1.3 | `config.rs`：`masqueSettings` 解析（`host`/`path`（缺省 `/.well-known/masque/ip/*/*/`）/`headers`）+ proto `Config.warp` 出现即 `Err`；`error.rs` 分类 |
| B1.4 | `register.rs`：`register_dialer()`/`register_listener()`（此批**不调用**注册聚合口，避免半成品进生产） |
| B1.5 | **varint 上浮**：把 `crates/xray-proxy-hysteria/src/protocol.rs` 的 `read_varint`/`write_varint`/`varint_len`（+ 其单测）移到 `crates/xray-transport/src/wire/varint.rs`，hysteria 侧改 `pub use`（行为字节不变，件头打 `udf-promotion-candidate`）；验收含 `cargo test -p xray-proxy-hysteria --all-targets` |

### B2 —— CONNECT-IP client over h2 + 环回互验（3.5 人日）

| 步骤 | 内容 |
|---|---|
| B2.1 | `h2.rs`：TLS(ALPN=h2) → CONNECT-IP 请求（`:protocol`、`Capsule-Protocol: ?1`、空 body）→ 200 校验 → `Upgraded` → `ConnectIpSession`；ALPN 非 h2 硬错 |
| B2.2 | `connect.rs`：`request_addresses` / `recv_assignment` / `send_packet` / `recv_packet` / `max_packet_size`；超 MTU 返回 ICMP 回灌包 |
| B2.3 | 环回自测：进程内 hyper server（回环 echo IP 包 + 地址分配）↔ 客户端，验地址分配 + 连续 IP 包往返 |
| B2.4 | **h2 窗常量上浮**：6 个 `pub const` 从 `xray-transport-splithttp/src/transport.rs` 移到 `xray-transport`（值不变），splithttp 改 `pub use`；masque 用 `H2_INITIAL_STREAM_WINDOW` / `H2_MAX_SEND_BUF_SIZE` |
| B2.5 | Go 对拍（方向 A，env 门控 `#[ignore]`）：Rust client → Go server，跑 IPv4/UDP DNS 查询往返 |
| B2.6 | finalmask 接线（客户端侧）：`shared_tcpmask_manager_from_json` + `wrap_conn_client_into_connection`（TCP 后、TLS 前） |

### B3 —— `xray-frame::ipstack` 净移动批次（**独立验收**，2 人日；可与 B2 并行）

| 步骤 | 内容 |
|---|---|
| B3.1 | 新建 `crates/xray-frame/src/ipstack/mod.rs`：把 `crates/xray-proxy-wireguard/src/netstack.rs`（1218 行）整文件语义搬入（`WgNetStack`→`PacketStack` 仅改名，字段/常量/分支/注释一字不改） |
| B3.2 | `crates/xray-proxy-wireguard/src/netstack.rs` 改为 `pub use xray_frame::ipstack::*;` + **别名一行** `pub use xray_frame::ipstack::PacketStack as WgNetStack;`（保证 `crate::netstack::WgNetStack` 与 `lib.rs:73` 的对外 re-export **签名零变化**；该行属门 B3-M 白名单的 `pub use`） |
| B3.3 | `xray-frame/Cargo.toml` 加 `smoltcp = { workspace = true }`（零新第三方） |
| B3.4 | `xray-proxy-wireguard/src/plugin.rs` 的 `WG-TUN-FROZEN` 文案改为「netstack 已提炼至 xray-frame，本 crate 经 re-export 冻结」；`tests/plugin_contract.rs` 的 extra 断言同步 |
| B3.5 | **「纯移动」机器判据**（见 §6 门 B3-M）不过即回滚 |

### B4 —— 服务端 + proxy 双侧 + 全接线（7–8 人日）

| 步骤 | 内容 |
|---|---|
| B4.1 | `hub.rs`：TCP accept → TLS（`build_server_config`）→ hyper auto h2（**必须** `enable_connect_protocol()`）→ path 匹配 + 10s 握手超时 + 100 并发流 → `ServerConn`（405/501/400/401/503 拒绝语义） |
| B4.2 | `pool.rs`：地址池（排除网络/广播/服务器自身 + 环形游标 + used 集 + 释放归还） |
| B4.3 | `xray-proxy-masque`：`plugin.rs`（契约）+ `server.rs`（Basic 认证常数时间比较 → 地址分配 + 全路由通告 → 包路由：隧道间 512 有界队列 / 本机 ipstack → `DispatchHandler`/`UdpDispatchSession`）+ `client.rs`（隧道 → ipstack 目标 Dial） |
| B4.4 | `xray-conf/src/init.rs`：**同批**放开 `masqueSettings` 与 `network=masque`（`xdrive` 继续拒）；改 `:826-850` 测试断言 |
| B4.5 | `arm_builders/mod.rs`：`INBOUND_CTORS` / `OUTBOUND_CTORS` 各加一行；`xray-core/src/register.rs::register_all_transports()` 加 masque dialer/listener 两行 |
| B4.6 | 安全/可观测接线：`AccessContext.protocol = "masque"`（→ freedom 默认 BlockPrivate）；`SecretMasking` 登记 password；`memory_budget` 按隧道数登记 16MiB send_buf |
| B4.7 | 服务端 finalmask 接线（`hub.go:168-169` 对应面） |

### B5 —— 对拍矩阵 + 取证 + 安全策略实测（2.5 人日）

| 步骤 | 内容 |
|---|---|
| B5.1 | 方向 A/B/C 全跑（A=Rust→Go，B=Go→Rust，C=Rust↔Rust） |
| B5.2 | tshark H2 帧断言 + 胶囊逐帧解析（残留非零帧 = 0） |
| B5.3 | 私有地址阻断实证（masque 入站 → freedom 出站 → `10.0.0.1` 被黑洞且不拨号） |
| B5.4 | 文档收口：本文 §7 结论回填 + `bd update Xray-core-rust-55yh7 --append-notes` |

### B6 —— h3 模式（**阻塞，待决策**，4–6 人日）

前置条件：`h3` crate 能表达 `:protocol=connect-ip`。当前 `h3-0.0.8/src/ext.rs` 的 `ProtocolInner` 是闭集（仅 `WebTransport`/`ConnectUdp`），**0.0.8 已是 crates.io 最新**。三个选项（需 PM 拍板，见 §7 R11 + ADR 建议 ADR-M4）：① `vendor/h3` patch（增 `ConnectIp` 变体 + `Protocol::from_static`），代价≈2 人日 + 上游追赶债；② 自写 QUIC DATAGRAM 承载（Go h3 分支走 QUIC DATAGRAM 而非胶囊，`conn.go:673-683`），代价高且违「禁造轮子」；③ 押后到 h3 上游支持（本仓 h3 主要用于 splithttp，升级需复测）。

---

## 6. 每批验收（可执行命令 + 期望）

### 门 B0（U1）

```bash
cd D:/Project/Xray-core-rust
cargo test -p xray-transport-masque --test h2_extended_connect_spike -- --nocapture
# 期望：4 条断言全过（server 见 :protocol=connect-ip；client 200+Upgraded；双向 1KB 一致；非空 body → Err）
```

### 门 B1

```bash
cargo test -p xray-transport-masque --lib                # capsule/config/error 单测全绿
cargo test -p xray-transport-masque --test capsule_golden # 逐字节 golden
cargo test -p xray-proxy-hysteria --all-targets          # varint 上浮后的回归（B1.5）
cargo clippy -p xray-transport-masque -p xray-transport -p xray-proxy-hysteria --all-targets -- -D warnings
cargo fmt -p xray-transport-masque -- --check
```

### 门 B2（含 Go 对拍方向 A）

```bash
# 1) Go 服务端（v26.11.9；alpn 必须显式 h2 —— 见 R9）
D:/tmp/xray-v2611/xray.exe run -c D:/tmp/masque-go-server.json
# 2) Rust 侧
cargo test -p xray-transport-masque --test connectip_go_interop -- --ignored --nocapture
# 期望：ADDRESS_ASSIGN 非 0.0.0.0；手工构造 IPv4/UDP DNS 查询收到同 id 应答
# 3) 抓包断言（硬指标）
D:/Project/tools/Wireshark/tshark.exe -r D:/tmp/masque.pcapng -d tcp.port==443,http2 \
  -Y "http2" -T fields -e http2.type -e http2.header.name -e http2.header.value
# 期望：SETTINGS ENABLE_CONNECT_PROTOCOL(0x8)=1；HEADERS 含 :method=CONNECT / :protocol=connect-ip /
#       :path=/.well-known/masque/ip/*/*/（原样 *）/ capsule-protocol: ?1；响应 :status=200 + capsule-protocol: ?1
```

### 门 B3（ipstack 净移动）

```bash
cargo test -p xray-frame --all-targets
cargo test -p xray-proxy-wireguard --all-targets
cargo test -p xray-integration-tests --test integration_wireguard_dataplane   # 红线回归
cargo clippy -p xray-frame -p xray-proxy-wireguard --all-targets -- -D warnings
```

**门 B3-M（「纯移动」机器判据，任一不过即打回）**

```bash
# M1 只允许 use/mod/注释变化：词级 diff 里不许出现逻辑/常量行（命中即打回）
git diff -M --word-diff=porcelain HEAD~1 -- crates/xray-frame/src/ipstack crates/xray-proxy-wireguard/src/netstack.rs > D:/tmp/ipstack-move.diff
python -c "import re;L=[l for l in open('D:/tmp/ipstack-move.diff',encoding='utf-8') if l[:1] in '+-' and not l.startswith(('+++','---')) and not re.match(r'^[+-]\s*(///|//!|use |pub use |mod |pub mod )',l)];print('logic_changed_lines=',len(L))"
# 期望 logic_changed_lines= 0
# M2 行数守恒：两份 numstat 的 增/删 必须近似对称（净差 ≤ 20，只允许 use/重导出样板波动）
git diff -M --numstat HEAD~1 -- crates/xray-frame/src/ipstack crates/xray-proxy-wireguard/src/netstack.rs
# M3 语义键同名：导出面计数与移动前一致（除 WgNetStack→PacketStack 这一处显式改名）
python -c "import re;t=open('crates/xray-frame/src/ipstack/mod.rs',encoding='utf-8').read();print('pub_fns=',len(re.findall(r'pub (?:async )?fn ',t)),'pub_structs=',len(re.findall(r'pub struct ',t)))"
git show HEAD~1:crates/xray-proxy-wireguard/src/netstack.rs > D:/tmp/netstack-before.rs
python -c "import re;t=open('D:/tmp/netstack-before.rs',encoding='utf-8').read();print('pub_fns=',len(re.findall(r'pub (?:async )?fn ',t)),'pub_structs=',len(re.findall(r'pub struct ',t)))"
# 两行输出必须相同
```

### 门 B4

```bash
cargo test -p xray-proxy-masque --all-targets                       # 含 assert_plugin_contract!
cargo test -p xray-conf                                            # 含 masque 放行 / xdrive 仍拒 断言
cargo test -p xray-core --lib
cargo test -p xray-core --test assembly_path_equivalence           # 差异台账不得引入未知差异
# 装配负向（缺 address / 缺 users / 非 TLS / warp 出现 / ALPN 非 h2）→ build Err
cargo test -p xray-proxy-masque --test plugin_contract
# 全量门（收尾）
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
cargo doc --workspace --no-deps                                    # CLAUDE.md §7 推送前必跑
```

### 门 B5

```bash
# A/B/C 三方向（C 另加 64KB 连续 IP 包往返不丢）
cargo test -p xray-integration-tests --test masque_interop -- --ignored --nocapture
# 私有地址阻断实证：期望 freedom 日志 "blocked by final rule" 且目标端口零连接
# 抓包残留
python tools/masque_capsule_residue.py --pcap D:/tmp/masque.pcapng   # 期望 residue_frames=0
```

### 门 B6（h3，仅当决策为「patch」时）

```bash
python vendor/patch_h3.py --check        # 期望：Protocol::CONNECT_IP 存在
cargo test -p xray-integration-tests --test masque_interop_h3 -- --ignored --nocapture
D:/Project/tools/Wireshark/tshark.exe -r D:/tmp/masque-h3.pcapng -d udp.port==443,quic
# 期望：H3 SETTINGS H3_DATAGRAM(0x33)=1；CONNECT 流 :protocol=connect-ip；IP 包走 QUIC DATAGRAM
```

---

## 7. 风险与未决

| # | 风险 | 现状证据 | 处置 | 等级 |
|---|---|---|---|---|
| **R1** | hyper extended CONNECT 全链路未跑过 | 静态已核（`hyper-1.10.1` 上述三处 + `h2-0.4.19`）；本仓 `enable_connect_protocol` 全仓 0 命中 | **B0 spike 前置**；失败 → raw `h2` 兜底（+2 人日） | 高 |
| **R2** | 单流载全部流量 → h2 流窗成全局瓶颈 | 历史 h2 窗钉战役（CLAUDE.md §5 enc8x） | B2 起用 16MiB send_buf / 32MiB 流窗；M2 加「隧道数 × 每隧道带宽」观测；**禁自造流控** | 中 |
| **R3** | WARP 误入 M1 | `warp.go` 78 行、`WarpHost=cloudflareaccess.com` | 配置含 `warp` 即 `Err`（L5 装配门） | 低 |
| **R4** | 与 splithttp/xhttp 命名混淆 | `dialer.rs:604 Masque => "masqueSettings"` 已对齐 Go | 零共享模块，只共享依赖与窗常量 | 低 |
| **R5** | 零 xray 语义部分误上浮 udf | §4.1 已判 | 胶囊/connect-ip 留 transport crate，件头写「udf 不适用」 | 中 |
| **R6** | ipstack 提炼触红线 | PM 已裁定（§4.2） | B3 独立批次 + 门 B3-M；`xray-proxy-tun` 副本**未收编**（实测 1449 行，另立 bd 票） | 中（已缓解） |
| **R7** | 隧道间转发漏做 | Go `server.go:37`(512) + `:428-437` | B4.3 显式做 + B5 双向 ping 验收；溢出计数 | 中 |
| **R8** | 凭据落日志 | Go `server.go` 只记 email | `ClauseId::SecretMasking` + `LogFacade` secrets 表；401 只记 email | 中 |
| **R9** | **Go 服务端 ALPN 缺省即 h3** | `hub.go:47-50 serverVersions`：`h3 = contains(h3) \|\| !h2`（676eaf66 实测） | 所有互通配置**必须显式** `alpn:["h2"]`；Rust 侧 `security=tls` 且 ALPN 缺省 → 硬错（不静默） | **高（易踩）** |
| **R10** | 地址池边界（网络/广播/服务器自身） | Go `pool.go:31-45` | 照抄三条校验 + 表驱动单测（QAS-2） | 中 |
| **R11** | **h3 表达不了 `connect-ip`** | `h3-0.0.8/src/ext.rs:28-31`（`ProtocolInner` 仅 `WebTransport`/`ConnectUdp`，无 `from_static`）；0.0.8 = crates.io 最新 | h3 单独批次 + **ADR-M4 决策**：①`vendor/h3` patch ②自写 QUIC datagram（否决）③等上游 | **高（决定 M3 生死）** |
| **R12** | finalmask 消费漏接（Go 4 处） | `dialer.go:163-164,84-85`；`hub.go:168-169,122-123` | B2.6 + B4.7 显式接线；配置含 finalmask 而未接线 → 不得静默（fail-visible） | 中 |
| **R13** | lint 放行与注册表不同步 | `xray-conf/src/init.rs:332-349` 现为 fail-closed | 放行与 `register_all_transports` **同批**（B4.4+B4.5），否则配置过 lint 却在拨号期 NotFound | 中 |
| **R14** | 内存预算账本未登记 | `crates/xray-core/src/memory_budget.rs`（`H2_MAX_SEND_BUF_PER_CONN_BYTES` 等按协议入账） | B4.6 按「隧道数 × 16MiB」入硬账；装不下走降档 + WARN（不拒启） | 中 |
| **R15** | 不接 xmux 池 → 每连接一次 TLS+h2 握手 | Go 用 `splithttp.NewXmuxManager` 池化 | `shortcut:` 注释登记；M3 前若有 A/B 证据（握手占 TTFB 显著）→ 移动 `mux.rs` 至 `xray-frame::xmux` + re-export | 中 |
| **R16** | 上游未稳定点 | 26.10.17→26.11.9 masque 零改动（本文 §0 #2） | 若下个基准再动 masque，重跑本文 §2.1/§2.3 取证 | 低 |
| **R17** | 「上浮/提炼」批次混入逻辑改动 | 三处上浮：B3 ipstack、B1.5 varint、B2.4 h2 窗常量 | 三处统一用**门 B3-M 的「纯移动」机器判据**（§6）；出任何逻辑/常量变化即打回 | 中 |

### 未决（需 PM 拍板）

1. **h3 路线**（R11）三选一——建议 ① `vendor/h3` patch，与 `vendor/quinn-proto` 同类先例；需另立 ADR-M4。
2. **是否在 M2 就做隧道路由的通配（`0.0.0.0/0`）**——Go 恒通告全路由（`fullRoutes`），安全面依赖 freedom 默认规则；若要求「默认只通告内网段」则为 Go 语义偏离，须显式裁决。
3. **xmux 池是否进本票**（R15）——建议不进。

---

## 8. 工作量估计

| 批次 | 人日 | 依据 |
|---|---|---|
| B0 U1 spike | 0.5 | 单测级 spike；静态已核三处 API |
| B1 胶囊 + 配置 | 2.5 | Rust ≈ 500 行（capsule ≈400 + config/error ≈100）+ golden 测试 |
| B2 h2 client + 环回 + Go 对拍 | 3.5 | h2 ≈200 + connect ≈350 + 环回测试 ≈150 + 窗常量上浮 |
| B3 ipstack 净移动 | 2 | 1218 行移动 + 3 处 re-export + 契约文案 + 3 门验收 |
| B4 server + proxy + 接线 | 7–8 | hub ≈400 + pool ≈80 + proxy 双侧 ≈900 + conf/arm/register/budget ≈150（对照 Go 非 H2 部分 3949 行，Rust 因复用件净减） |
| B5 对拍 + 取证 + 安全 | 2.5 | 三方向 + tshark + 安全实证 + 文档 |
| **h2 全通小计** | **18–19.5** | |
| B6 h3（押后，含 vendor patch） | 4–6 | patch ≈2 + h3 绑定 ≈200 行 + 对拍 ≈2 |
| **总计** | **22–25.5** | |

**口径**：单人、熟悉本仓、不含中途返工。与任务书（30–42 人日）差异来源：① h3 押后（−6~12，且其前置是 vendor patch 决策）② finalmask / 安全策略 / h3 栈 / UDP 会话全部复用现有件（−3~4）③ 新增 B3 移动批次（+2）与 B0 显式批次（+0.5）。

**并行性**：B2 与 B3 可两路并行（文件面不相交）；B1 必须在 B2 前；B4 依赖 B2+B3；B5 依赖 B4。

---

## 附录 A：ADR 建议（供 PM 立）

- **ADR-M4（新增，Proposed）**：MASQUE h3 承载的 `:protocol=connect-ip` 表达路径——选项 ①`vendor/h3` patch ②自写 QUIC DATAGRAM ③等上游；建议 ①，理由 = 与 `vendor/quinn-proto` 同类先例、保持「复用 h3 栈」而非造第二套 QUIC 应用层。
- **ADR-M1（沿用任务书决策，状态更新为 Accepted）**：MASQUE 的 H2 栈复用形态 = hyper/h2 extended CONNECT，不移植 Go 手写 H2（省 1294 行）。租约条件：B0 spike 通过。
- **ADR-M2（已由 PM 2026-11-11 裁定）**：ipstack 归 `xray-frame`，「移动 + re-export」形态（见 §4.2）。
- **ADR-M3（沿用）**：里程碑切分 = transport 层先于 proxy 层（本文 B1/B2 先于 B4）。

---

## 附录 B：read 调用审计

**读过的文档 / 规范**
- `docs/architecture/xray-frame-masque-契约级任务书-2026-10-30.md`（全文 516 行，两段读完）
- `docs/architecture/adr/adr-0004-component-scope-holder-contract.md:1-83`（持有者契约 + 归属裁决）
- `CLAUDE.md`（autoload；§3.5/§3.5.2/§3.5.3/§3.5.5/§3.5.6）

**上游 Go（D:/Project/Xray-core @ 676eaf66 = v26.11.9）**
- `git grep -il masque`（39 文件）· `git diff --stat 92ccc939 676eaf66 -- proxy/masque transport/internet/masque infra/conf/masque.go`
- `wc -l` 全量非测试非 pb 源文件（5218 行）
- `proxy/masque/server.go:340-400` · `transport/internet/masque/dialer.go:150-210` · `hub.go:40-60` · `connectip/request.go` · `transport/internet/masque/config.proto` · `proxy/masque/config.proto`

**本仓（D:/Project/Xray-core-rust @ 3659167d）**
- 结构：`crates/xray-frame/src/`（25 模块）· `crates/xray-frame/src/lib.rs:1-117` · `crates/xray-frame/Cargo.toml`
- 框架件：`scope.rs`（ComponentScope/ScopeRef/ArmScope/ConnScope）· `pool.rs`（BufferPool/XrayBufPool/ManagedBufferPool/SharedPoolRegistry）· `registry.rs`（PluginRegistry）· `plugin.rs:1-63`（ClauseId/PluginContract/Plugin）· `context.rs`（spawn/clock/log/audit/pool）· `dispatch.rs`（HandlerCapability/lookup）
- 传输面：`xray-transport/src/dialer.rs`（TransportDialFn/StreamSettings/register）· `listener_registry.rs` · `finalmask/` 目录 · `xray-transport-splithttp/src/{lib.rs,mux.rs,flow_window.rs,transport.rs,h3_client.rs,register.rs,config.rs}` · `Cargo.toml`（hyper 1 / h2 0.4 / h3 0.0.8 / h3-quinn 0.0.10 / quinn 0.11 / smoltcp 0.12）+ `Cargo.lock` 实测版本
- 代理/核心面：`xray-proxy-wireguard/src/{netstack.rs,inbound.rs,dispatcher.rs,plugin.rs,lib.rs}` · `xray-proxy-freedom/src/{config.rs,udp.rs,handler.rs,dispatcher.rs}` · `xray-app-dispatcher/src/{udp_session.rs,default.rs}` · `xray-core/src/{register.rs,inbound.rs,outbound.rs,wiring.rs,memory_budget.rs,arm_builders/mod.rs,arm_registry.rs}` · `xray-conf/src/init.rs:332-349,826-850` · `xray-common/src/net/` · `xray-buf/src/{alloc.rs,buffer.rs,reader.rs,writer.rs}` · `xray-tls/src/{client_config.rs,server_config.rs,utls.rs,btls_client.rs}` · `xray-proto/src/lib.rs:175-178,305-308` · `protos/transport/internet/masque/config.proto`
- udf-frame：`crates/udf-frame/{skeleton,skeleton-infra,std-ext}` 目录（查「是否已有等价件」）

**第三方源码（本地 registry，锁定版本）**
- `hyper-1.10.1/src/{ext/mod.rs, server/conn/http2.rs, proto/h2/{server.rs,client.rs}}` · `hyper-util-0.1.20/src/server/conn/auto/mod.rs` · `h3-0.0.8/src/{ext.rs,config.rs,client/builder.rs,server/builder.rs,proto/frame.rs}` · `h2-0.4.19`（tshark/CLI 未跑）

**工具**：`read` / `grep` / `glob`-等效 (`ls`) / `bash`（git、wc）/ `web_search`（h3 0.0.8 版本确认）
**未运行**：任何 `cargo` 构建/测试（纯规划，禁改产品代码）；tshark；Go 二进制。
