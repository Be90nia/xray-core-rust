# W4 合并波报告：面 3 步 2+4 + 面 6（xray-core inbound 单人改 + xray-mux + xray-app-dns）

> 波次：W4（能力收敛方案 §5.2）｜crate：xray-core / xray-mux / xray-app-dns
> 日期：2026-10-27｜执行：W4V5（续跑 W4V3/W4V4 盘上 10 文件半成品；前任因 provider 429 中断 3 轮，磁盘成果全在）
> 树态：master 未 commit 的工作树（16 改动文件中本面 10 个；其余为 CR1aC / W5V5 面）

## VERDICT

**CONDITIONAL-PASS** — 代码面全绿（3 crate check/test + workspace clippy `-D warnings` exit 0 + fmt 全仓零 diff），互操作 **12/12 PASS**（判据替换为可达 URL，原 YouTube 判据本窗被环境阻塞：直连控制实验失败，见 §2.1）；**追加复核**：按 W5V5 的栈足迹回归口径核全本面，`xray-core/inbound.rs` 4 处 UDP relay 站点已由 async-fn 形态转构造式（app-dns 39 处经判据核为安全、保留，见 §8），转换后 477/0 + clippy exit 0；**32/32 真机归 PM**（release 二进制为转换前构建，语义等价，见 §5.1）。

## 0. 10 文件半成品核对结论（采纳 / 修正 / 废弃）

| # | 文件 | 前任落地内容 | 我的核对结论 |
|---|---|---|---|
| 1 | `xray-app-dns/Cargo.toml` | +`xray-frame` path dep（依赖方向 血肉→骨架，无环） | **采纳**（`cargo check -p xray-app-dns` 绿；Cargo.lock 同步 1 行） |
| 2 | `nameserver/doh.rs` | 8 站点（1 取时 + 7 `timeout_at`）→ `Budget`/`deadline.timeout` | **采纳** |
| 3 | `nameserver/dot.rs` | 10 站点迁移 + `try_query` 走 `deadline::timeout(fut, remaining())` 相对形态（称 HRTB 限制） | **采纳 + 复验**：我实测把一处改回直写 `deadline.timeout(stream.write_all(..))` → `error: implementation of xray_transport::connection::Connection is not general enough`（dot.rs:296 指向 `send_query`）。HRTB 限制为真，相对形态保留；已补一行「实测复验」注记 |
| 4 | `nameserver/quic.rs` | 8 站点迁移 | **采纳** |
| 5 | `nameserver/tcp.rs` | 9 站点迁移（含 `is_expired()` 判定）+ 测试 `test_deadline()` 返回 `BudgetDeadline` | **采纳**（断言原文零改动） |
| 6 | `nameserver/udp.rs` | 14 站点迁移（含 TCP fallback 段） | **采纳** |
| 7 | `xray-core/src/inbound.rs` | 面 3（11 取时点 + 2 `sleep_until` + 2 pinned sleep）+ 面 6（mux×4 arm scope / SS 泵×1 conn scope / 监控壳内层×1 arm scope / vision×2 redline 口）+ 文件头 allow 台账重写 + `mod tests` inner allow | **采纳 + 2 处修正**：①**redline 调用形态改全路径**（见下）；②**新增 G6 的 xray-core 半契约测试**（方案 §6 要求"契约测试钉住 spawn 后立即断连不杀 sibling"，前任未补） |
| 8 | `xray-core/src/arm_builders/inbound.rs` | arm ctx 参数穿透（`spawn_inbound_serve` ×18、`spawn_transport_listener_inbound` ×4、5 个 builder 加 `plugin_ctx` 形参、6 个 `*_entry` 适配） | **采纳**（纯机械联动，零新增机制 = 不造轮子） |
| 9 | `xray-mux/src/client.rs` | 仅加 `interval_at` 例外的 `#[allow]` + 注释 | **修正**：删 `#[allow]`（本 crate L3 闸**未禁** `tokio::time::Instant::now`，属性无的放矢 = 台账失真），保留理由注释 |
| 10 | `xray-mux/src/worker.rs` | 同上 | **修正**：同上 |

**修正 ①（redline 调用形态）实证**：`crates/xray-frame/tests/redline_sites.rs::escape_hatch_call_sites_are_registered` 按**字面量** `redline::spawn_unchecked` / `redline::event` 扫 `crates/**`。前任写成 `spawn_unchecked as redline_spawn` → 本文件对门**隐形**；实测扫全 `crates/`（排除 xray-frame 本体）字面量调用点为 **0**（门靠 `found.is_empty()` 直接跳过）。后果：W7 迁移 `vision_conn.rs` 后 `found` 非空，门会断言"`VisionSpliceSpawn` 期望文件 `crates/xray-core/src/inbound.rs` 无逃逸口调用"→ **红**。已改为 `use xray_frame::redline::{self, RedlineSite};` + 两处 `redline::spawn_unchecked(RedlineSite::VisionSpliceSpawn, ..)`，并在 import 上方留一行"禁 alias"注记。

**无废弃内容**：前置成果全部建立在方案与 W1 真实 API 之上（`Budget`/`BudgetDeadline`/`PluginContext::conn_scope`/`ConnScope`/`redline::spawn_unchecked` 均经源码核对存在），无臆造件，无需回退。

## 1. 站点迁移表（HEAD 数 = 删除侧，逐点）

### 面 3 步 2（app-dns 49 + mux 2 例外）

| # | 文件:行（HEAD） | 站点 | 处置 |
|---|---|---|---|
| 1 | nameserver/doh.rs:226 | `Instant::now() + query_timeout` | ✅ `Budget::tokio().deadline()`（allow 删） |
| 2 | nameserver/dot.rs:296 | 同上 | ✅ 迁（allow 删） |
| 3 | nameserver/dot.rs:260 | `Instant::now() >= deadline` | ✅ `deadline.is_expired()`（allow 删） |
| 4 | nameserver/quic.rs:239 | 取时位 | ✅ 迁（allow 删） |
| 5 | nameserver/tcp.rs:280 | 取时位 | ✅ 迁（allow 删） |
| 6 | nameserver/tcp.rs:244 | 剩余判定位 | ✅ `is_expired()`（allow 删） |
| 7 | nameserver/udp.rs:317 | 取时位 | ✅ 迁（allow 删） |
| 8 | xray-mux/src/client.rs:672 | `interval_at(Instant::now()+I, I)` | ⚠️ 例外保留（见 1.1） |
| 9 | xray-mux/src/worker.rs:219 | 同上 | ⚠️ 例外保留（见 1.1） |

配套机械联动（同 diff）：**9 处**私有方法签名位 `deadline: tokio::time::Instant` → `BudgetDeadline`（dot 3 / tcp 3 / udp 2 / quic 1；doh 无签名位，只有局部 deadline）；**37 处 `timeout_at(deadline, fut)` → `deadline.timeout(fut)`**（doh 7 / dot 7 / quic 6 / tcp 6 / udp 11）；dot.rs `try_query` 因 rustc HRTB 限制走既有构造形态 `deadline::timeout(fut, deadline.remaining())`（同构 `tokio::time::Timeout<F>`，绝对预算语义等价，注释 + 实测注记在位）。

**站点对账（自跑计数，`git show HEAD:<f>` vs 工作树）**：

| 文件 | `tokio Instant::now` | `timeout_at` | 迁移 | 残余 |
|---|---|---|---|---|
| doh.rs | 1 → 0 | 7 → 0 | 8 | 0 |
| dot.rs | 3 → 0 | 7 → 0 | 10 | 0（唯一 `timeout_at` 命中是注释） |
| quic.rs | 2 → 0 | 6 → 0 | 8 | 0 |
| tcp.rs | 3 → 0 | 6 → 0 | 9 | 0 |
| udp.rs | 3 → 0 | 11 → 0 | 14 | 0 |
| **合计** | **12 → 0** | **37 → 0** | **49** | **0** |

### 1.1 mux 2 处例外理由（逐处登记）

`tokio::time::interval_at` 的首参是 **tokio Instant 类型位**（非"取时点"语义），`BudgetDeadline` 不暴露 tokio Instant（`BudgetInstant` 私有）；且两处 ticker 均为 **select 臂**（与 done/close 信号竞争），改写成 `deadline+pending` 链会改变 missed-tick（Burst 补发）与 done 响应语义 = 非机械替换，方案面 3 风险节明令禁止。两处均保留"W4 面 3 残余登记"注释；**mux clippy.toml 未禁 `tokio::time::Instant::now`（只禁 std 面）→ 不挂 allow**（前任挂的 allow 已由我删除：无禁令可压，留着即台账失真）。

### 面 3 步 4（inbound.rs 11 处）

| # | 函数 | 站点（HEAD 行） | 迁移形态 |
|---|---|---|---|
| 1-3 | handle_udp_associate | 564/572/595 + `sleep_until` 567 | `Budget::tokio().deadline(idle)` + `timeout(pending())`，活动臂重造 deadline |
| 4-8 | serve_dokodemo_udp_on | 1773/1810/1814/1824 + `sleep_until` 1819 | cleanup_at → `BudgetDeadline`；`PeerSession.last_active: Instant → Budget`（`elapsed()` 语义同） |
| 9-10 | ss_udp_client_relay | 2379/2400 + pinned sleep 2368 | pinned sleep+reset → `Budget::tokio().deadline()` 重造 + `timeout(pending())` |
| 11-12 | ss2022_udp_client_relay | 2550/2570 + pinned sleep 2539 | 同上 |

（11 处 = `Instant::now` 调用位口径；`sleep_until` ×2 与 pinned sleep ×2 为配套 timer 形态。）

### 面 6（inbound.rs 生产 10 spawn）

| # | 站点（HEAD 行） | 归属（方案） | 处置 |
|---|---|---|---|
| 1-4 | mux link ×4（460/716/783/886） | arm scope | ✅ `ctx.spawn(...)` + `.expect("arm FxScope is never closed")`（batch1/2 先例同款） |
| 5 | SS 泵 ×1（1980 spawn_ss_pump） | connection scope | ✅ 每连接 `ConnScope`（`plugin_ctx.conn_scope()`），泵任务持 `Arc<ConnScope>` 锚——泵自然死亡后 scope Drop 收账；arm 停机经父闸级联取消 |
| 6-7 | 监控壳 ×2（外层 / 内层） | arm scope | ✅ 内层迁 `arm.spawn`（panic 经 FxScope `catch_unwind` 归一 `TaskError::Panicked`，51d50459 语义逐字保留）；⚠️ 外层壳例外保留（见 1.2） |
| 8-9 | vision ×2（serve_reality_vless / serve_reality_trojan） | 面 5 受控入口 | ✅ `redline::spawn_unchecked(RedlineSite::VisionSpliceSpawn, ...)`（spawn 语义逐字等价，红线本体零改动） |
| 10 | tun ×1 | 方案本身判保留 | ✅ 未动（JoinHandle 外返契约 + 4 平台门控，方案"不可迁残余 1"） |

**站点对账（inbound.rs）**：`tokio::spawn` 62 → **54**（62 = 52 tests + 10 生产 → 迁 8 生产，余 52 tests（`mod tests` inner allow）+ 2 生产（外层壳 / tun 逐点 allow））；`tokio::time::Instant::now` 13 → **2**（迁 11 生产，余 2 tests）；`sleep_until` 2 → **0**；`std::time::Instant::now` 5 → 5（1 生产（ss2022 500s 惰性清扫锚点）+ 4 tests，逐点 allow 登记）。

### 1.2 监控壳外层壳例外理由

`spawn_inbound_serve` 返回 `JoinHandle<()>`，契约横跨 `InboundRuntime::start_inbound → spawn_inbounds → functions.rs start_full* → xray-cli/grpc_server/全测试面`；改返回类型 = 越出本波文件面（functions.rs 非本波）。外层壳保留裸 `tokio::spawn`（逐点 allow + 理由在位），内层 serve 任务真受益（arm scope 记账 + in_flight + 停机级联）。与方案"tun 保留"同源举证（JoinHandle 外返契约是派生层做不了的事）。

### 机械联动（面 6 参数穿透）

- `spawn_inbound_serve` 加首参 `arm: &Arc<PluginContext>`：调用点 inbound.rs ×3 + arm_builders/inbound.rs ×15 + tests panic-probe ×1（本面文件面内闭合，`functions.rs` 等外部调用点 = 0）。
- `spawn_transport_listener_inbound` 加首参同款：4 调用点全在 arm_builders。unix transport 分支按既有先例就地 `arm_plugin_ctx(kind)`。
- `spawn_ss_pump` / `ss_legacy_pipeline` / `ss_mode_conn_pipeline` 加尾参 `plugin_ctx: Arc<PluginContext>`：serve_ss / UDS per-conn ×2 / arm_builders `ss_transport_on_conn`（就地构造 arm ctx）。
- **arm scope 生命周期锚**：`arm_plugin_ctx` = `PluginContext::for_plugin` = **每 arm 独立 FxScope**，其 `Arc` 强引用若只活在 builder 形参里，构造函数返回即 drop → serve 任务被 abort → 端口静默失效。故外层壳持 `Arc<PluginContext>` 锚覆盖 inner 存活期（同款先例 `let _ctx = task_ctx;`）。由此 `.expect("arm FxScope is never closed")` 的断言为真：arm scope 无 `close()/shutdown()` 调用点，只在 Arc 归零时 Drop。

## 2. 验证证据

| 门 | 命令 | 结果 |
|---|---|---|
| check · app-dns | `cargo check -p xray-app-dns --all-targets -j 8` | `Finished dev profile ... in 23.28s`，0 error |
| check · mux | `cargo check -p xray-mux --all-targets -j 8` | `Finished ... in 42.83s`，0 error |
| check · core（收尾态） | `cargo check -p xray-core --all-targets -j 8` | `Finished ... in 2m 48s`，0 error |
| test · app-dns | `cargo test -p xray-app-dns --all-targets` | lib `230 passed; 0 failed`；`dns_e2e 6 passed; 0 failed` |
| test · core | `cargo test -p xray-core --all-targets` | lib `477 passed; 0 failed; 2 ignored`；`bind_failure_fatal 1`；`invalid_inline_cert_startup 1` |
| test · mux | `cargo test -p xray-mux --all-targets` | lib `143 passed; 0 failed`；`integration 23 passed; 0 failed` |
| clippy | `cargo clippy --workspace --all-targets -j 8 -- -D warnings` | `CLIPPY_REAL_EXIT=0`，error 行 0（仅 vendor/rustls 既有 2 warning）；workspace 全 targets |
| interop | `python D:/tmp/interop_matrix_w4v5.py`（原 YouTube 判据） | **0/12 — 环境阻塞**（YouTube 直连也超时，控制实验见 §2.1） |
| interop（替代判据） | `python D:/tmp/interop_matrix_w4v5_cf.py`（同一脚本，URL→cloudflare 200KB） | **12/12 PASS**，每项 body=200000B |

**一次 flake 的完整交代**：首轮全量 `cargo test -p xray-core --lib` 出现 1 failed —— `functions::tests::integration_socks_through_trojan_to_echo` panic 在 `functions.rs:2137 .expect("trojan client")`。该测试用 `bind(127.0.0.1:0)` → `local_addr().port()` → `drop(probe)` 探头取端口（探后释放再 bind = 天生竞态），且当时同机有 2 个兄弟代理在跑各自 `cargo test`。单测复跑 `1 passed`、全量重跑 `477 passed; 0 failed` ⇒ 判为**跨进程端口抢用**（非本面缺陷）；本面未改该测试、未放宽任何断言。

### 2.1 原 interop 判据被环境阻塞（控制实验取证）

首跑原判据 **0/12**（全部 `curl(28) Connection timed out`）。控制实验（不经任何代理）证明是环境而非本面代码：

| 实验 | 结果 |
|---|---|
| `curl --max-time 20 https://www.youtube.com/`（直连，两次） | `HTTP:000`，20s/21s 超时 |
| `curl https://speed.cloudflare.com/__down?bytes=2000`（直连） | `HTTP:200` time 0.79s |
| `curl https://www.google.com/`（直连） | `HTTP:000` 12s 超时 |
| `nslookup www.youtube.com`（DNS=114.114.114.114） | `2001::1` / `157.240.7.20`（污染值） |
| Rust server 日志（#09 Go→Rust trojan） | `trojan dispatching ... dest=tcp:www.youtube.com:443` → `resolved [185.45.5.35:443]` → 数据面正确发起，回程被环境吞掉 |

结论：本窗 YouTube/Google 不可达（云flare 可达）。故把**同一脚本**的 URL 判据替换为 `https://speed.cloudflare.com/__down?bytes=200000`（保留 >5000B 体量判据、marker 置真，其余 0 改动，含 6 协议 × 2 方向全部拓扑与证书 pin）→ **12/12 PASS，每项 200000B**。这比 0/12 更能证明"协议双向互通 + 真实数据回程"。

## 3. L3 台账减项

- **xray-app-dns**：12 处 `#[allow(clippy::disallowed_methods)]`（`tokio::time::Instant::now` 取时/判定）全删（迁 `Budget` 后无裸取时）。
- **xray-core/inbound.rs**：文件级 `#![allow(clippy::disallowed_methods)]`（67 处存量）**撤掉**，改为 ①`mod tests` 模块级 inner allow（52 spawn + 4 std Instant + 2 tokio Instant，测试计时不得改语义）+ ②生产面 3 处逐点 allow（监控壳外层 1、tun 1、ss2022 惰性清扫 std 墙钟 1）。
- **xray-mux**：前任挂的 2 处 `#[allow]`（`interval_at`）删除——本 crate 闸未禁 tokio Instant，属性无禁令可压。

## 4. 雷区自查（逐条声明）

1. **mux carrier 判据 = destination 域名 `v1.mux.cool`**：`is_mux_destination` / carrier 语义 **0 hunk**；本波只把 carrier 任务的**宿主**从裸 spawn 换成 arm scope，未动 command/端口/域名判据。
2. **panic 监督（51d50459）与 InboundRuntime slots**：监督文案/`tag`/上下文逐字保留（外层壳 `TaskError::Panicked(_)` → 同一条 `error!`）；`InboundRuntime` / slots 结构 **0 hunk**（120 个 hunk 已逐个核对：无一处落在 `InboundRuntime` impl）。
3. **TtlDnsCache（bd 9zxyl）接 udf 时钟**：本面只迁 **tokio 虚拟钟预算面**（`Budget::tokio()` 内部仍是 tokio `timeout_at`，`#[tokio::test(start_paused)]` + `advance` 语义不变）；`cache_controller` / `clock()` 注入面 **0 改动**，TTL 语义与并发面零变化。
4. **xray-core 一文件一 check**：面 3 一批 → check；面 6 一批 → check；redline 形态修正后 → 再 check（三次全绿）。
5. **非目标遵守**：未碰 vision gate/DIRECT 分流（vision 两处只换 spawn 包装，装配三件套逐字不动）、未碰注册表族整面、未碰 `xray-frame` 源码 / `.github` / `vendor` / `protos`、未 commit / 未 push。

## 5. 门尾摘要

```
$ cargo clippy --workspace --all-targets -j 8 -- -D warnings
warning: `rustls` (lib) generated 2 warnings (...)      # vendor 既有，非本面
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 16.47s
CLIPPY_REAL_EXIT=0 ; error 行数=0

$ cargo fmt --all -- --check
# 本面 10 文件 0 diff（仅 crates/xray-transport-splithttp/src/dialer.rs 3 处 —— W6 面 `hot_log!` 折行，非本面）

$ cargo test -p xray-mux -p xray-app-dns -p xray-core --all-targets
xray-app-dns lib     230 passed; 0 failed      dns_e2e              6 passed; 0 failed
xray-core   lib      477 passed; 0 failed; 2 ignored
                        bind_failure_fatal 1 / invalid_inline_cert_startup 1 passed
xray-mux    lib      143 passed; 0 failed      integration         23 passed; 0 failed

$ cargo build --release -p xray-cli -j 8
    Finished `release` profile [optimized] target(s) in 16m 41s
    -> target-W4V5/release/xray.exe (50,488,320 B)

$ python D:/tmp/interop_matrix_w4v5_cf.py          # 本面二进制，URL 判据替换（见 §2.1）
[PASS] #01..#12  6 协议 × 2 方向 = 12/12 PASS（每项 body=200000B）
=== 互操作矩阵: 12/12 PASS ===
```

复跑口径：`dist/interop_matrix.py` 里 `RUST`/`WORK` 是硬编码，我未改验证资产——用 `/tmp` 副本 patch 两行（`RUST → target-W4V5/release/xray.exe`、`WORK → 独立目录`）。PM 若要原判据：网络恢复后直接
`python D:/tmp/interop_matrix_w4v5.py`（YouTube 判据，已备好）。

### 5.1 追加复核（§8 栈足迹转换）后复跑

```
$ cargo test -p xray-core --lib -j 8
test result: ok. 477 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out; finished in 31.57s

$ cargo clippy --workspace --all-targets -j 8 -- -D warnings   # 转换后
CLIPPY_REAL_EXIT=0 ; error 行数=0 ; Finished in 1m 25s

$ cargo fmt --all -- --check
（全仓 0 diff——含 PM 已修的 crates/xray-transport-splithttp/src/dialer.rs）
```

**二进制时效（给 PM 的重要提示）**：`target-W4V5/release/xray.exe` 时间戳 **19:06 = §8 转换之前**的构建。转换只改定时器包装形态（`async fn` → 具名 `Timeout<F>`，语义等价、不影响 wire/行为），故用它跑 32/32 结论仍然有效；但若要 **tree-exact** 二进制，需在空闲窗口 `cargo build --release -p xray-cli` 重建一次（约 17 分钟）——我未在 CR1aC 的 loopback 测量窗内起这次重建，以免污染其读数。debug 目录已清（`target-W4V5` 现 1.8G）。

## 6. 残余风险（本波未消，逐条交代）

1. **arm scope 的 JoinSet 无收割 API**（udf `FxScope` 事实：`set: Mutex<JoinSet<()>>`，只有 `shutdown()` 会 `join_next` 排空）。mux carrier 每会话结束会在 arm scope 留一条已完成条目 → 长期运行的单 inbound 上是**缓慢增长**，不是零成本。与本文件既有 `ss_transport_on_conn` 例外注释同源（"FxScope 完工 JoinSet 条目无收割 API 会无界累积，待 udf 扩 drain 后迁（bd 39hko）"）。收口 = udf 扩 drain/`try_join_next` 面（bd 39hko）。选择不在本波改 xray-frame/udf 的原因：改父仓走 `n539c` 独立 PR 回路，且 `FxScope` 是编译期全局依赖（D2）。
2. **`ConnScope::child_of` 的父闸轮询**（xray-frame `scope.rs`：`PARENT_POLL_INTERVAL = 20ms`，父 `close()` 不发取消信号，只能闸位轮询）。SS 每条 TCP 连接带一个 20ms 轮询任务 ≈ 50 次唤醒/秒/连接。SS 长连接面可接受（数据面每连接流量远大于此），但**高连接数场景是可观常数开销**；建议 W1 后续把 FxScope 闸关改为 close-notify 通道（`watch`/`Notify`），子 scope 无需轮询。本波不改：`scope.rs` 属 W1 文件面（非本波）。
3. **停机语义收紧**（有意）：SS 泵与 mux carrier 随 arm scope 关闭被**取消**（原裸 spawn 会 detached 跑完）。方向上对齐坑约束 ⑥"停机必注册"，但确实改变"连接 drain"粒度 → 32/32 真机门由 PM 复核。
4. **监控壳外层 + tun 仍裸 spawn**（JoinHandle 外返契约，见 §1.2），属面 6 未闭合残余。
5. **`dot.rs try_query` 相对形态**：到期时刻 = `绝对截止点 - now` 现算，与 `timeout_at` 有纳秒级构造间隙（语义等价，非缺陷）；根因是 rustc HRTB 限制（实测证据见 §0 修正 ③），若后续 rustc 放宽或 `Conn` 换掉 `Box<dyn Connection>`，可回归直写形态。

## 7. 5 轴自评

- **准确性 5/5** — 每条结论都有可复跑命令或源码/实测证据：站点对账来自自跑计数（`git show HEAD:<f>` vs 工作树）；HRTB 例外是我亲测复现的编译错误原文；redline 门隐形是我扫全 `crates/` 得 0 字面量命中；JoinHandle 契约有 `inbound.rs:2932/3118/3259` + 消费者 `.abort()` 佐证。
- **完整性 4/5** — 面 3 步 2+4 与面 6 的迁移、站点对账、雷区自查、半成品核对、G6 契约测试补齐、CI 门隐形修正均完成；扣分项：面 6 的"监控壳外层 1 + tun 1"按方案举证保留（未闭合），且 arm scope JoinSet 累积需 udf drain（残留风险 1，非本波可解）。
- **清晰度 4/5** — 迁移表按 HEAD 行号 + 处置逐点给出，例外单列小节；扣分项：§1 与 §0 有少量信息重叠（核对结论 vs 迁移细节）。
- **可执行性 5/5** — 每张门都给了完整命令与尾部输出；复跑口径（`cargo test/clippy` 具体 -p 列表、interop 用 `/tmp` 副本并 patch RUST/WORK）可直接照抄。
- **简洁性 4/5** — 无过程流水账，只留结论 + 条件 + 证据；扣分项：残余风险节偏长（5 条中有 2 条属他面待办）。

## 8. 追加：栈足迹回归复核（PM 2026-10-27 转达 W5V5 发现）

> 形状：`BudgetDeadline::timeout` 是 **async fn** 形态，在**巨型 future / 非装箱 await** 里会逐站点加厚栈帧；W5V5 在 vmess 3 站点触发 `vmess_inbound_udp_relay_e2e` 确定性 `STATUS_STACK_OVERFLOW`（2MiB 线程栈），改用**构造式** `xray_frame::deadline::timeout(fut, budget.remaining())`（返回具名 `tokio::time::Timeout<F>`，与裸调用同体积）后复测绿。

**判据**：该 timeout 站点是否处在「巨型 future」内 = ①外层有 `join!`/`select!` 组合多个未装箱 future，或 ②该 future 被**非装箱**地 await（典型：测试直接 await 整条 relay 循环，2MiB 测试线程）。

**逐面结论**

| crate / 文件 | 站点数 | 形态 | 判定与处置 |
|---|---|---|---|
| `xray-app-dns/nameserver/{doh,dot,quic,tcp,udp}.rs` | 39（async-fn）+ 5（dot 构造式） | 生产路径**无 `join!`/`select!`**（实测：5 个 nameserver + `server.rs` + `cached.rs` 的生产段 `join!`=0、`select!`=0）；每个 nameserver 查询由 `server.rs:468` `set.spawn(async move { c.query_ip(..) })` **装箱**进 JoinSet，无组合封装 | **保留 async-fn 形态**（单链请求/响应，不满足判据 ①②）。`dot.rs::try_query` 的 5 处本就是构造式（HRTB 所需，见 §0 修正 ③）——与本回归要求恰好同向 |
| `xray-core/src/inbound.rs` | 4（原 async-fn） | `handle_udp_associate`（select 3 臂 / 测试 9378 · 9407 · 9452 **裸 await**）、`serve_dokodemo_udp_on`（select 2 臂 / 测试 9483 · 9543 **裸 await**）、`ss_udp_client_relay` / `ss2022_udp_client_relay`（生产巨型 select 环） | **命中判据 ②（UDP relay 族 = W5V5 溢出的同种形状）→ 已全部转构造式**：4 处 `X.timeout(std::future::pending::<()>())` → `xray_frame::deadline::timeout(std::future::pending::<()>(), X.remaining())`（剩余量在 select 臂构造点现算 = 与绝对截止点等价，每轮重建语义不变），并就地留注释说明栈足迹理由 |
| `xray-mux/src/{client,worker}.rs` | 0 | 只有 `interval_at`（面 3 例外，未迁） | 无站点，无需处置 |

**证据**：`cargo fmt --all -- --check` 本面 0 diff；`cargo test -p xray-core --lib` 477 passed / 0 failed（转换后复跑，见 §5 门尾）；`cargo clippy --workspace --all-targets -- -D warnings` exit 0。
