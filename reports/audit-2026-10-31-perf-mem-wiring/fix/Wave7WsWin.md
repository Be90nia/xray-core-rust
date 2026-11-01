# Wave7 · s8eio — ws 预连接池默认与 Go 对齐 + gRPC 流窗内存预算

VERDICT: PASS —— ws 预连接池默认改为 0（与 Go 26.10.17「无池」对齐，显式 `poolSize>0` 才启用），gRPC 流窗内存预算文档化；门禁 test / clippy / fmt 全绿，反证已取。

- [x] §1 Go 事实核查
- [x] §2 Rust 现状（默认值位置 + 池确已接线）
- [x] §3 拍板（选 A）
- [x] §4 实现（改动清单，已落盘）
- [x] §5 连接数证据锚（服务端 accept 实测：默认 1 条）
- [x] §6 反证（默认改回 12 → 断言红，4 vs 1）
- [x] §7 gRPC 内存预算（文档 + 代码注释）
- [x] §8 门禁（test / clippy / fmt 全绿）
- [x] §9 残余风险

---

## §1 Go 事实核查（基准 `D:/Project/Xray-core` @ `92ccc939` = v26.10.17）

**结论：Go 无任何形式的 ws 连接预热/复用。** 逐项排查（含旁路机制）：

| 检查项 | 结果 |
|---|---|
| `transport/internet/websocket/dialer.go` | `Dial()` 每次调用**现拨**一条：`dialWebSocket()` 内 `dialer.DialContext(ctx, uri, header)` 一次；无缓存、无池、无复用、无归还路径 |
| `websocket/config.proto` 字段面 | 只有 `host=1 / path=2 / headers=3 / accept_proxy_protocol=4 / ed=5 / heartbeatPeriod=6` —— **无 poolSize** |
| 全仓 grep `poolSize\|PoolSize\|connectionPool\|ConnectionPool` | 仅命中 `common/bytespool/pool.go`（内存缓冲池，`GetPool`/`Put`）与 `infra/conf/fakedns.go:15`（FakeDNS LRU 大小）—— **均与 ws 连接无关** |
| 旁路机制①：`heartbeatPeriod` | `websocket/connection.go:25-27` 起 goroutine 周期发 ping —— **保活，不是池** |
| 旁路机制②：`ed`（early data） | `dialer.go` `Ed > 0` → `delayDialConn`（把握手推迟到首次 Write）—— **延迟拨号，不是池** |
| 旁路机制③：`browser_dialer` | `HasBrowserDialer()` 分支走浏览器桥拨号 —— **换执行者，不是池** |
| 旁路机制④：`internet.DialSystem` | 每次新建 TCP（含 sockopt），go stdlib 无跨调用连接复用 |

⇒ 服务端在 Go 基准下看到的连接数 = **实际会话数**（一条链路一条连接）。

**gRPC 侧（Go）**：`grpc/dial.go:169-171` 仅在 `InitialWindowsSize > 0` 时
`grpc.WithInitialWindowSize`；未配则落 grpc-go 缺省（流窗 64KB 量级，票面记实测
98340 / 服务端 131070）。连接窗 Go 侧无显式设置。

## §2 Rust 现状

**默认 12 + burst 3 的代码位置**（改前）：

| 位置 | 内容 |
|---|---|
| `crates/xray-transport-websocket/src/config.rs:58-60` | `Config::default().pool_size = 12` |
| `crates/xray-transport-websocket/src/config.rs:89-91` | `Config::from_proto()` **硬编码** `pool_size: 12`（proto 无该字段，`to_proto` 也不输出） |
| `crates/xray-transport-websocket/src/register.rs:643-645` | JSON `poolSize` 缺省 `12`（显式 `0` 才关） |
| `crates/xray-transport-websocket/src/pool.rs:125-131` | `WsPoolConfig::default()` = `max_idle_per_key: 12` + TTL 10s |
| `crates/xray-transport-websocket/src/register.rs:431` | `BURST_REPLENISH_FANOUT = 3`（burst = 主 replenish + 2 并行 = 3 条补拨） |

**池确已接线（不是"实现存在未接线"）**：`register.rs:350-387` 的 `dial_ws`：
`global_pool()` → 池启用时 `try_acquire` → 命中直接交付 + `spawn_replenish`；
未命中 → 现拨 → `spawn_replenish_burst`（3 条后台补拨）→ `release` 入池。
ED 路径（`ed > 0`）走 `DelayDialConn` 早返回，**不碰池**。

**gRPC 窗口位置**：`xray-transport-grpc/src/transport.rs:310-322`（客户端 `dial_h2`：
`initial_window_size` = 16MiB（`initialWindowsSize>0` 时按配置覆盖）+
`initial_connection_window_size` 32MiB + `max_send_buffer_size` 16MiB）与
`transport.rs:784-791`（服务端 `accept_h2`：16MiB / 32MiB / 16MiB +
`max_concurrent_streams(250)`）。
历史意图：`git log -S"initial_connection_window_size"` → `4a5ea630`
（`perf(splithttp): h2 流控窗钉三连修…0.3s RTT 高 BDP 路径 8.8→40-60MB/s (bd enc8x)`），
另见 `b9a5ba44`（窗钉族全收口）。⇒ 16MB/32MB 是**刻意性能修复**，本票不动其数值。

## §3 拍板：选项 A（默认与 Go 对齐，池改成显式 opt-in）

**决定**：`pool_size` 默认 = **0（不预连接）**，`wsSettings.poolSize > 0` 才开池。
池代码保留（能力不删）。

**理由**
1. Go 26.10.17 是本仓裁定基准，其 ws 无池 ⇒ 默认关池 = 行为对齐；票面实测的
   「服务端连接数 ×4」是真实副作用（撞服务端连接上限/限流/CDN 计费），且这份代价
   在 Go 基准里不存在。
2. 池的收益（省 1 RTT 握手）是 Rust 独有优化，用户要就显式开 —— 能力与代价绑定，
   默认不替用户选代价。
3. 配置仍双向兼容：Go `WebSocketConfig` 无 `poolSize` 字段，JSON 未知键静默忽略，
   同一份配置在 Go 只是空操作。
4. 项目铁律：框架支线未发版 ⇒ **不做**「先默认关、env 再开」的渐进门控，直接把默认
   值改成基准值，测试/文档同步（本次即如此）。

**选错的代价**：若实际用户群重度依赖池带来的首包收益（浏览器整页多 subresource），
关闭默认池会让这类场景回到「每会话一次 TCP+TLS+WS 握手」（同 Go 表现，非回归，
是失去一项额外优化）。用户只需在 `wsSettings` 写 `"poolSize": 12` 即恢复，
故误判可逆、代价有界。

## §4 实现（改动清单，全部落在允许的两个 crate）

`crates/xray-transport-websocket/src/config.rs`
- `Config::default().pool_size`: `12` → `0`（注释改为 bd s8eio 依据）
- `Config::from_proto().pool_size`: `12` → `0`（proto 无该字段 = 未配置 = 关池）
- 字段文档与模块表格更新（默认 0 + 为何 + 代价 + 如何开启）

`crates/xray-transport-websocket/src/pool.rs`
- `WsPoolConfig::default().max_idle_per_key`: `12` → `0`（默认关池，单一真相源）
- 模块文档/`global_pool`/`reconfigure_global_pool` 文档同步
- `init_config`：`if cfg.max_idle_per_key < n` 死逻辑删除（默认 0 后恒真）→ 一次
  性无条件赋值，语义 = 文档所述「首个 wsSettings 生效」
- 测试：新增 `pool_cfg_12()` helper，机制测试显式启用（默认关池后不再隐式开）

`crates/xray-transport-websocket/src/register.rs`
- JSON `poolSize` 缺省 `12` → `0`；doc 同步
- 测试 `parse_ws_config_pool_size_default_12` → `parse_ws_config_pool_size_default_off`（断言 0）
- 池语义测试 `dial_ws_used_connection_never_returns_and_replenish_fires` 改为显式
  `{"path":"/ws","poolSize":12}`（测机制就该显式开）

`crates/xray-transport-websocket/tests/pool_default_off.rs`（新增，证据锚）
- `default_config_opens_exactly_one_server_connection`：默认配置 ⇒ 服务端 accept == 1
- `explicit_pool_size_still_preconnects`：显式 `poolSize:12` ⇒ 服务端 accept > 1

`crates/xray-transport-grpc/src/{lib.rs,config.rs,transport.rs}`
- crate 级新增「内存预算（h2 流控窗）」节（算账 + 为何不加假限制）
- 两个 builder 站点各加一行预算指针注释；`initial_windows_size` 字段文档补充语义

**`git diff --stat`（改动落盘确认）**：见 §8（完整输出 + 与并行代理改动的分界说明）。

## §5 连接数证据锚（服务端 accept 计数，非客户端日志）

手法：测试内置**计数型 ws echo server**（每条 TCP accept `fetch_add(1)` = 服务端可见
连接数）；客户端走真实生产入口 `dial_with_settings("ws", …)` 拨一条链路、echo 一轮、
关连接，再留 700ms 补拨窗口。

命令与输出（`cargo test -p xray-transport-websocket --all-targets`）：

```
running 2 tests
test default_config_opens_exactly_one_server_connection ... ok
test explicit_pool_size_still_preconnects ... ok
test result: ok. 2 passed; 0 failed
```

- **改后（默认关池）：1 条 accept** —— 与 Go 水平一致（一条链路一条连接）
- **显式 `poolSize: 12`：> 1** —— 池能力仍在（后台补拨照旧）

## §6 反证（把默认值改回 12 → 断言变红）

临时把 `Config::default().pool_size` 改回 `12`（`// REVERSE-PROOF TEMP`），单跑证据锚：

```
test explicit_pool_size_still_preconnects ... ok
test default_config_opens_exactly_one_server_connection ... FAILED
thread '...' panicked at crates\xray-transport-websocket\tests\pool_default_off.rs:97:5:
assertion `left == right` failed: 默认配置必须只开 1 条服务端连接（Go 26.10.17 ws 无池）；多出即池默认被打开
  left: 4
 right: 1
test result: FAILED. 1 passed; 1 failed
```

⇒ **实测「一条代理链路 × 4 条服务端连接」**（1 条会话 + 3 条 burst 补拨），与票面
「连接数 ×4」吻合。恢复默认 0 后复跑：`1 passed / 1 passed`（见 §5）。

（顺带实证一个副作用：`LNK1104 无法打开 .exe` —— Windows Defender 扫描紧接上一轮测试
产物，重编链接会短暂锁文件；重跑即过，与代码无关。）

## §7 gRPC 内存预算（文档 + 代码注释，不动窗口数值）

落点：`crates/xray-transport-grpc/src/lib.rs` crate 级「内存预算（h2 流控窗）」节
+ `transport.rs` 两处 builder 注释 + `config.rs::initial_windows_size` 字段文档。

**算账（上限，非预留）**

| 参数 | 值 | 含义 |
|---|---|---|
| `initial_window_size` | 16 MiB | 每 stream 收窗（配 `initialWindowsSize>0` 时按配置覆盖） |
| `initial_connection_window_size` | 32 MiB | 连接级收窗 = **所有 stream 合计的天花板** |
| `max_send_buffer_size` | 16 MiB | 发送队列上限 |

- 每 h2 连接上界 ≈ **32 MiB（收，连接窗封顶）+ 16 MiB（发）≈ 48 MiB**
- **「16 MiB × 并发流」是错算**：`max_concurrent_streams = 250`，250×16MiB = 4 GiB；
  实际被 32 MiB 连接窗先封顶，16 MiB/流的额度只在单流独占连接时吃得到
- gRPC 拨号每次 `dial` 建一条 TCP(+TLS)+h2，**无连接复用/池**（`transport::dial`
  → `connect_once` → `dial_h2`）⇒ 客户端并发 C 条会话 = C × ~48 MiB 上界；
  服务端每个 accept 同理
- **不加**「超预算 warn/fail」：配置只描述流窗，并发会话数在解析期不可知，任何阈值
  都是假限制（会拒掉合法的大内存机器配置）——按票面要求「不得引入假的限制」，此处
  以文档自算替代（例：100 并发 ⇒ ≲4.8 GiB 上界）

**未改窗口数值** ⇒ 按票面「若本票不动窗口数值，则只需把草算预算写清」，不另跑吞吐
回归（enc8x 的 8.8→40-60MB/s 收益结构未受影响）。

## §8 门禁（全部实测通过）

环境：`CARGO_TARGET_DIR=D:/Project/Xray-core-rust/target-Wave7Ws` +
`BORING_BSSL_PATH=target/boringssl-asm/prebuilt`（跳过 cmake 冷编）+ `PROTOC` + `LIBCLANG_PATH`。

**1. `cargo test -p xray-transport-websocket -p xray-transport-grpc --all-targets`**

```
Running unittests src\lib.rs (xray_transport_grpc)      running 94 tests
test result: ok. 94 passed; 0 failed; 0 ignored
Running unittests src\lib.rs (xray_transport_websocket) running 114 tests
test result: ok. 113 passed; 0 failed; 1 ignored
Running tests\pool_default_off.rs                       running 2 tests
test result: ok. 2 passed; 0 failed
Running tests\register_dialer.rs                        running 4 tests
test result: ok. 4 passed; 0 failed
Running tests\ws_e2e.rs                                 running 7 tests
test result: ok. 7 passed; 0 failed
```

**2. `cargo clippy … --all-targets -- -D warnings`**

```
Checking xray-transport-websocket v0.1.0
Checking xray-transport-grpc v0.1.0
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 2.05s
```

（输出中仅有的 warning 来自 `vendor/rustls`：`dead_code` + `unreachable_pub`，是 vendor
patch 的既有噪声，不属本次改动面。）

过程中被 clippy 拦下并修掉的两处（记录以防回归）：
- `doc_lazy_continuation`：grpc `config.rs` 字段文档里 `/// >0 时…` 被当成 blockquote
  起点 → 改成「配置非 0 时…」（`#![deny(warnings)]` 下直接编译失败）。
- `unwrap_used`：新测试文件的**非 `#[test]` 辅助函数**里 `.unwrap()` 不受
  `clippy.toml allow-unwrap-in-tests` 豁免（豁免只认 `#[test]`/`#[cfg(test)]` 体内）
  → 改 `.expect("…")`。

**3. `cargo fmt -p xray-transport-websocket -p xray-transport-grpc -- --check`**

```
FMT_CLEAN_OK
```

（`cargo fmt` 应用前 `--check` 只列出 3 个本人改动的文件：`pool.rs:16`、`register.rs:624`、
`tests/pool_default_off.rs` —— 未触碰他人代码。）

**改动面确认（`git diff --stat`）**

```
 crates/xray-transport-grpc/src/config.rs        |   5 +-
 crates/xray-transport-grpc/src/lib.rs           |  24 ++
 crates/xray-transport-grpc/src/transport.rs     |   5 +
 crates/xray-transport-websocket/src/config.rs   |  34 +--
 crates/xray-transport-websocket/src/pool.rs     | 301 ++++++++++++++++++++----
 crates/xray-transport-websocket/src/register.rs |  24 +-
 6 files changed, 323 insertions(+), 70 deletions(-)
 ?? crates/xray-transport-websocket/tests/pool_default_off.rs
```

⚠️ `pool.rs` 的 301 行里 **~219 行是并行代理 bd il9lh 的未提交 sweeper 改动**（惰性 TTL
回收），本票在其上叠加的是：模块文档 5 行、`WsPoolConfig::default` 1 行、字段文档 4 行、
`init_config` 简化 3 行、`global_pool`/`reconfigure` 文档 4 行、测试 helper + 10 处测试
启用调用。**未触碰其逻辑**。仅动允许的两个 crate，未碰 splithttp / mux / xudp /
core / hysteria / commander。

## §9 残余风险

1. **默认关池是行为变更**：此前未写 `poolSize` 的配置失去池化（回到 Go 表现，非回归，
   是少了一项额外优化）。恢复方式：`wsSettings.poolSize: 12`。Go 侧忽略该未知键，配置
   仍双向兼容。
2. **`WsPoolConfig::default()` 公开默认值 12 → 0**：仓内消费者仅 ws crate 自身
   （grep `global_pool|WsPoolConfig|reconfigure_global_pool` 无跨 crate 命中）；外部若
   直接构造 `WsPoolConfig::default()` 会得到「关池」，文档已注明。
3. **`init_config` 语义微调**：原「取较大者」→「首个生效无条件赋值」。多 outbound 首配置
   竞争时由"取较大"变"先到者胜"；与函数文档「首个 wsSettings 生效」一致。要 per-outbound
   容量需把池改 per-outbound 句柄（`config_init` 一并删）。
4. **开池的副作用仍在**（设计如此）：显式 `poolSize>0` 时服务端可见连接数 =
   会话数 + 池深；实测单链路首拨后总 accept = 4（1 会话 + 3 burst 补拨）。
5. **gRPC 预算是上界不是实测峰值**：32MiB 连接窗 + 16MiB 发送缓冲是上限；真实驻留量随
   RTT×带宽 涨、通常远低于上界，但未做高并发内存实测。因未改窗口数值，按票面口径不另跑
   吞吐回归（enc8x 的 8.8→40-60MB/s 收益结构未动）。也未跑真实 Go↔Rust grpc 互通吞吐。
6. **未加配置期预算闸门**（刻意为之）：并发会话数在解析期不可知，任何阈值都是假限制；
   已在 crate 文档给出算账式与示例。
7. **证据锚只覆盖 ws**：票面写「splithttp/ws」，但 splithttp 的复用是 xmux（另一机制、
   另一票/代理，本票红线禁触）；ws 才是预连接池所在面，故以 ws 生产入口
   `dial_with_settings("ws", …)` + 服务端 accept 计数取证。

## §10 收尾

- **构建目录**：`D:/Project/Xray-core-rust/target-Wave7Ws`（6.8G）已按要求删除。
- **未 commit**（按派单）。
- **知识图谱**：`codebase-memory-mcp cli index_status --project=D-Project-Xray-core-rust`
  → `status: ready`，`indexed_at: 2026-10-31T15:09:00Z`（落后于本次改动）。**未在本轮重建**：
  当前有 40+ 并行代理持续改同一棵树，单独重建立即再过期且可能与其他代理的索引任务撞车；
  建议战役收口后统一 `index_repository`。本票改动是默认值 + 文档 + 新增一个测试文件，
  不新增/删除符号，图谱滞后不影响本票的符号级检索（`Config::default` / `parse_ws_config`
  位置未变）。
- **沉淀**（两条语言级坑，已写入用户规则）：
  - `~/.omp/agent/rules/rust-testing.md` ← `clippy.toml allow-unwrap-in-tests` 只豁免
    `#[test]`/`#[cfg(test)]` 体内，集成测试的普通 helper 里 `unwrap()` 仍触发
    `unwrap_used`（`-D warnings` 直接失败）。
  - `~/.omp/agent/rules/rust-pitfalls.md` ← doc 注释行首 `>`（写「大于 0」）会被当
    Markdown blockquote，触发 `clippy::doc_lazy_continuation` 且报错指向下一行；
    `cargo fmt` 不管这类问题。
