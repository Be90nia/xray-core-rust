# API 记账表——批次 `e737e904..HEAD` 新增公共 API（67 项）

> 37vjq-b 交付物。统计口径：`git diff -U0 e737e904..HEAD -- crates` 中
> `^\+\s*pub (async fn|fn|struct|enum|trait|const|static|type|mod|use)` 声明行，
> 共 **67 项**；另有 10 行 `pub` 结构体**字段**（随宿主结构体记账，不单列）。
> 每项归入 [ADR-0001](adr-0001-spawn-idle-pruner-derived-not-promoted.md) /
> [ADR-0002](adr-0002-memory-budget-ownership-split.md)，或记「无需 ADR」并给理由。

## A. 归入 ADR-0002（装配面登记簿拆分）——16 项

| 项 | 位置 | 归属理由 |
|---|---|---|
| `pub mod memory_budget` | xray-core/src/lib.rs | 登记簿模块声明；ADR-0002 裁决后随常量簿上浮 xray-frame::budget |
| `XRAY_BUDGET_BYTES` | xray-core/src/memory_budget.rs | 纯常量簿 → 上浮 xray-frame::budget（ADR-0002） |
| `MAX_PER_CONN_BUFFER_BYTES` | 同上 | 同上 |
| `MAX_EXPLICIT_SOCKET_BUFFER_BYTES` | 同上 | 同上（执行点 = xray_transport::sockopt，值对齐交叉断言） |
| `QUIC_UDP_DEFAULT_RECV_BUFFER_BYTES` | 同上 | 同上（quic-go parity，Xray 语义归派生层） |
| `SOCKET_KERNEL_BOOKKEEPING_FACTOR` | 同上 | 同上 |
| `QUIC_UDP_DEFAULT_RECV_BUFFER_BOOKED_BYTES` | 同上 | 同上 |
| `HANDSHAKE_INFLIGHT_MAX` | 同上 | 同上（执行点 = xray_transport::handshake_gate） |
| `DNS_PENDING_MAX_BYTES` | 同上 | 同上 |
| `DNS_CACHE_MAX_ENTRIES` | 同上 | 同上 |
| `TLS_SESSION_CACHE_MAX_ENTRIES` | 同上 | 同上 |
| `FINALMASK_XMC_POOL_MAX_BYTES` | 同上 | 同上（登记口径；桥在途=满载瞬态上界不进门算式） |
| `HYPER_MAX_IDLE_PER_HOST_BYTES` | 同上 | 同上 |
| `NEW_POOLS_TOTAL_MAX_BYTES` | 同上 | 同上 |
| `RESERVE_MARGIN_MIN_BYTES` | 同上 | 同上 |
| `check_startup_budget` | 同上 | **留 xray-core**（吃 `BuiltConfig`，上浮即 xray-frame→xray-conf 反向依赖成环；ADR-0002） |

## B. 归入 ADR-0001（池机制派生件）——1 项

| 项 | 位置 | 归属理由 |
|---|---|---|
| `spawn_idle_pruner<T>` | xray-frame/src/pool.rs | B 类派生件：组合包装 udf `prune_idle_with_clock` + `FxScope::spawn_tracked`，**不上浮 udf**（issue#23 NOT_PLANNED）；消费点 xray-transport-hysteria/udphop.rs。ADR-0001 |

## C. 无需 ADR——既有治理条款已覆盖——2 项

| 项 | 位置 | 理由 |
|---|---|---|
| `CompatExt::fx_scope` | xray-frame/src/compat.rs | §3.5.5 ADR-2（compat 进程级能力入口）既有裁决面：fx 句柄只读 accessor，属已裁决入口的方法扩面，非新归属决策 |
| `exponential_backoff_if` | xray-transport/src/retry.rs | **提炼候选**（udf-promotion-candidate）：通用 async 重试机制，与 udf `std_ext::retry` 族归一走 §3.5.3 提炼回路（独立 PR + 三平台 CI 绿 + 主仓换依赖删副本）；本轮不动代码，仅登记归属方向。⚠️ 造件时未过 §3.5.2 查重——消费方接线前应先核对 udf retry 是否可承接 |

## D. 无需 ADR——方向件留主仓（§3.5.3 正面裁决）——21 项

网络方向件（accept 准入门 / sockopt 拨号面 / TLS 门），§3.5.3 明文「方向件不进
udf-frame」：

| 项 | 位置 | 理由 |
|---|---|---|
| `pub mod handshake_gate` | xray-transport/src/lib.rs | 模块公开；accept 准入门 = 网络方向件，留主仓 |
| `HandshakeGate` / `new` / `try_admit` / `record_reject` / `record_failure` / `wait_first_byte` / `MAX_INFLIGHT_HANDSHAKES` / `FIRST_BYTE_TIMEOUT` | xray-transport/src/handshake_gate.rs | 同上（入站在飞闸 + 首字节超时；8 项合记） |
| `pub mod tls_handshake_gate` / `TLS_HANDSHAKE_TIMEOUT` / `accept_tls_with_timeout` | xray-transport/src/tls_handshake_gate.rs | 同上（TLS 握手门；3 项合记） |
| `SO_RCVBUF_FREE_TIER_MAX` / `SO_RCVBUF_HARD_MAX` / `ALLOW_LARGE_RCVBUF_ENV` / `MAX_EXPLICIT_RECEIVE_BUFFER_SIZE` / `check_explicit_receive_buffer_size` / `apply_explicit_receive_buffer_size` / `QUIC_UDP_MIN_BUFFER` / `MAX_EXPLICIT_UDP_BUFFER_SIZE` | xray-transport/src/sockopt/mod.rs | sockopt 拨号面 = 传输方向件；值与 ADR-0002 登记簿交叉对齐（bd u91se ④ 执行点）；8 项合记 |
| `dial_system_with_retry_budget` | xray-transport/src/system_dialer.rs | 系统 dialer 拨号面（方向件） |
| `shared_tcpmask_manager_from_json` / `DohParams` | xray-transport/src/finalmask/** | finalmask 传输语义（红线面，本轮禁碰区）；2 项合记 |

## E. 无需 ADR——Xray 语义常量/读数，留主仓 crate——26 项

**xray-buf 分层池容量簿与读数**（9 项；另有 4 个 `PoolStats` 字段随结构体）：
`TIER_SIZES` / `TLS_MAX_PER_TIER` / `SHARD_COUNT` / `SHARD_MAX_PER_TIER` /
`POOL_BYTE_BUDGET` / `SHARD_BYTE_BUDGET` / `TLS_BYTE_BUDGET` /
`PoolStats` / `stats()`（xray-buf/src/alloc.rs）——池调参簿含 xray 缓冲语义
（tier 档位/64KB 窗口径），留主仓；`stats()` 为管理面观测读数。

**测试夹具**（2 项）：`alloc_block` / `release_block`（xray-buf/tests/
shard_accounting_bench.rs）——bench 共享夹具，非产品 API。

**协议传输语义**（1 项）：`MAX_IDLE_PER_HOST`（xray-transport-splithttp/
client.rs）——hyper 连接池调参，splithttp wire/传输语义留协议 crate。

**proto wire 映射**（2 项）：`from_proto_type` / `to_proto_type`（xray-geodata/
matcher/domain.rs）——DomainType ↔ proto 枚举，wire 语义留主仓。

**观测/读数面**（8 项）：`current_skip_dns_resolve` / `proxy_chain_failures`
（xray-app-dispatcher/default.rs）；`socket_bind_count`
（xray-app-dns/nameserver/udp.rs）；`MAX_CACHE_ENTRIES`
（xray-app-dns/cache_controller.rs）；`threads` / `mem_pool`
（xray-app-geodata/loader.rs，池接入白拿直透面）；`fallback_count` /
`last_fallback_reason`（xray-app-router/balancing.rs）——诊断读数与容量登记，
零归属争议；`MAX_CACHE_ENTRIES` 与 ADR-0002 `DNS_CACHE_MAX_ENTRIES` 登记簿
值对齐。

**API 面**（4 项）：`pub use manager::Manager` / `Manager::new`
（xray-app-policy）——模块 re-export + 构造器，纯 API 整形；另有 4 个
`sockopt` 字段（splithttp/websocket client）与 `single_flight`（app-dns）、
`doh`（finalmask xdns）3 个字段随宿主结构体，不单列。

## 记账口径备注

- 「无需 ADR」≠「无需遵守纪律」：D/E 类仍受 §3.5.2 查重、§3.5.5 三判据约束，
  只是不产生**新的**归属裁决。
- 本表为批次快照（`e737e904..HEAD`）；后续批次新增公开 API 另起批次表。
