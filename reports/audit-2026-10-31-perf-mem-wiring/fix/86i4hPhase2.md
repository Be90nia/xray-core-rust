VERDICT: PARTIAL — 改动面全量落地且类型检查绿（15 crate `--all-targets` 零 error）、站点清单全量产出（生产面裸 spawn 171 处 ② 全登记、③ 类 0 处、托管面每事件 36 处改 `spawn_reaping`）；**四项统一验收未全跑**（workspace clippy / workspace lib test / 进程面 e2e / cargo doc —— 停在第 200 请求软预算，逐项见 §7「未跑」）。concerns：①`FxScope` 不暴露条目数 + `try_reap` 只回错误载荷 ⇒ 条目收割的判别只能靠进程面 `live_bytes`（脚本已写、未跑）②四 crate 新增 `xray-frame` 生产依赖（无环，§3）。

# 86i4h 阶段2 — ② 豁免类站点清单 + 每事件托管站点收割接线

- 仓库 `D:/Project/Xray-core-rust`，分支 `feature/fix-inbound-parity`，基线 HEAD `3f520e58`
- 构建环境：`BORING_BSSL_PATH=target/boringssl-asm/prebuilt`（跳过 btls cmake）+ `PROTOC` + `LIBCLANG_PATH`
- 本组独立构建目录：`target-86i4hPhase2`（回执已注明，结束删除）
- 不动：`xray-frame/src/{scope,compat}.rs` 的既有 API（只调用 `compat::spawn_reaping` / `compat::log`，零改动）、根 `tests/`、`xray-conf/**`

---

## 1. 站点清单（生成式，可复跑）

生成脚本：`fix/scripts/86i4h_site_inventory.py`（只读枚举，分类口径 = CLAUDE.md §3.5.6）

| 类 | 判据 | 实测 | 处置 |
|---|---|---|---|
| 生产面裸 `tokio::spawn` / `std::thread::spawn` | ② 豁免类：必须逐站 `#[allow(clippy::disallowed_methods, reason=…)]` 登记 | **171 处，171 处已登记** | 无需新增登记（既有登记齐备）；CI 闸 `clippy -D warnings` 权威核对 |
| ③ 违规（裸 spawn 无 allow） | 必须修 | **0 处** | 无 |
| 测试面裸 spawn（`cfg(test)` 内 / `tests/` 目录） | 不在坑约束 5 CI 闸范围（测试面豁免） | 424 处 | 不动（非目标；见 §6 残留） |
| 托管面站点（`spawn_tracked` / `spawn_reaping` / `spawn_detached`） | ① 接管类：应走托管口 → 已完成 | 101 处（含本票新增 36 处 `spawn_reaping`） | 见 §2：**每事件**站点改 `spawn_reaping`；一次性/有界与数据面泵不动 |

**② 豁免类 171 处的理由分类**（按既有登记 `reason` 文本归类，逐条原文见清单 A 段）：

| 类 | 数 | 判据（§3.5.6 ② 的成立条件） | 例 |
|---|---|---|---|
| C1 数据面泵热路径（坑约束 ⑫ 零改动红线） | 28 | 逐包泵（splithttp h2/h3 上传下载、tuic uni-stream、splice）——迁托管即改数据面 | `splithttp/{client,dialer,h3_client,hub}.rs`、`transport/splice.rs`、`tuic/udp.rs` |
| C2 压测工具 | 6 | 非生产路径（`xray-stress` 全部） | `stress/{quic_loop,scenarios,topology}.rs` |
| C3 测试脚手架 | 33 | 生产 crate 内的测试辅助（`cfg(test)` 外、但仅测试消费） | `common/testing/mod.rs`、`observatory/observer.rs` 内测试线程 |
| C4 常驻监控/监督任务 | 14 | 必须活得比被监控对象久（accept 循环意外退出监督、CLI 水位采样、mux worker 监控） | `transport-httpupgrade/register.rs`、`cli/bin/xray.rs`、`mux/worker.rs:217` |
| C5 存量债（待 P1 插件装配接线） | 8 | 该 crate 尚无 `PluginContext` 注入面（tun/vless 的存量直 spawn），接线归插件装配 | `proxy-tun/inbound.rs` ×6、`proxy-vless/inbound/server.rs` ×2 |
| C6 显式脱管（ctx 结构性不可达） | 68 | 每连接任务，句柄随连接/会话自终止，托管无收益（bd hj3jf 裁定） | `core/arm_builders/inbound.rs` ×4、`transport-hysteria/*`、`reality/probe.rs` |
| C7 其他（句柄自持等价记账） | 14 | 句柄被显式持有并在 drop 时 abort/join（等价托管记账，如 `common/log/general_logger.rs`） | `core/outbound.rs`、`common/log/general_logger.rs` |

完整清单落盘：`fix/tmp/86i4h_inventory.txt`（A 生产面裸 spawn 台账 / B 测试面 / C 托管面，逐条 file:line + 处置）。

---

## 2. 本票改动：每事件托管站点 → `spawn_reaping`（先收割再入集）

### 2.1 判据：只迁「条目数随事件无界增长」的站点

`FxScope` 的 `JoinSet` 条目**不会**因任务完成而自动出集（udf `spawn_tracked` 已核实：只有 `try_reap` 能出集）。
故条目累积 = 每事件 spawn 站点 × 事件总数；一次性站点（accept loop / 装配 / 监听 / 每 worker 常量个）条目数为常量，不动。

### 2.2 迁移站点（37 处 / 20 文件）

| crate · 文件 | 站点（每事件语义） | 数 |
|---|---|---|
| `xray-proxy-socks/src/server.rs` | 每连接握手+dispatch | 1 |
| `xray-proxy-http/src/server.rs` | 每连接 | 1 |
| `xray-proxy-trojan/src/server.rs` | 每连接 | 1 |
| `xray-proxy-anytls/src/server.rs` | 每连接 accept / 每连接 kill 看守 / 每 session / 每 session run / 每 session pump / 每 uot session pump | 6 |
| `xray-proxy-freedom/src/inbound.rs` | 每连接 dispatch | 1 |
| `xray-proxy-hysteria/src/inbound.rs` | 每 TCP stream / 每 UDP session | 2 |
| `xray-proxy-wireguard/src/inbound.rs` | 每 TCP relay / 每 TCP dispatch / 每 UDP 源会话 | 3 |
| `xray-proxy-tuic/src/inbound.rs` | 每连接 / 每 flow / 每 relay | 3 |
| `xray-proxy-tuic/src/server.rs` | 每连接 / 每 relay / 每 UDP assoc | 3 |
| `xray-proxy-dns/src/inbound.rs` | 每 TCP DNS 连接 timer | 1 |
| `xray-app-proxyman/src/inbound/worker.rs` | 每连接（closed 占位 / 空闲 timer / TCP process / UDP process / UDP 响应泵） | 5 |
| `xray-app-reverse/src/worker.rs` | 每控制流 / 每 inbound dispatch 流 | 2 |
| `xray-app-reverse/src/outbound.rs` | 每 portal 连接 | 1 |
| `xray-app-commander/src/grpc.rs` | 每 routingStats 订阅 | 1 |
| `xray-mux/src/client.rs` | 每 carrier | 1 |
| `xray-mux/src/session.rs` | 每 XUDP 条目过期中断 | 1 |
| `xray-app-dns/src/nameserver/doh.rs` | 每次 DoH 查询的 h2 连接驱动 | 1 |
| `xray-app-dns/src/nameserver/cached.rs` | 每次 serveStale 刷新 | 1 |
| `xray-transport/src/udp/relay.rs` | 每 UDP 会话 idle timer | 1 |
| `xray-transport/src/finalmask/realm/conn.rs` | `Shared::spawn` 唯一口（dispatcher/punch/heartbeat 全走它） | 1（覆盖全部调用） |

调用形态：`xray_frame::compat::spawn_reaping(&fx, &<域门面>, "<域·站点>", fut)`——
`reap_into` 把已完成条目清出集并把 `Panicked` 载荷落日志（`Cancelled` = 预期消亡不计），拒发 `ScopeClosed` 留 warn。
日志门面优先用 crate 既有 `LazyLock<LogFacade>`（socks/http/trojan/anytls/hysteria/tuic/wireguard），其余走 `compat::log()`（进程级门面，克隆零堆分配）。

### 2.3 保持裸 `spawn_tracked` 的站点（有界/一次性，逐条理由）

- **一次性（条目=常量）**：`commander.rs:607/644/704`（gRPC serve）、`grpc.rs` 之外、`app-dns/cache_controller.rs:332`（sweeper）、`metrics.rs:458/496`（每监听一件，内部自带 JoinSet 收割，票 fu4y）、`observatory observer.rs:262`/`burst_observer.rs:204`、`proxyman worker.rs:799/824`（worker 级 recv+cleanup）、`reverse bridge.rs:338/439`、`reverse timer.rs:61`、`core/arm_builders/inbound.rs:498/535`（每 arm）、`mux client.rs:237/327`、`mux session.rs:700`、`anytls inbound.rs:146`、`anytls server.rs:126`、`freedom inbound.rs:95`、`http server.rs:338`、`socks server.rs:135`、`trojan server.rs:168`、`hysteria inbound.rs:361`、`tuic inbound.rs:261`、`wg driver.rs:576/619/634`、`wg inbound.rs:200/289`、`vless dispatcher.rs:266`（每 handler 常量 count）、`transport tcp/hub.rs:71/82/263/271`、`udp/hub.rs:160`、`udp/dispatcher.rs:109`、`realm xdns/server.rs:166`、`finalmask/salamander_gecko.rs:466`、`udphop.rs:144`
- **每连接但 scope 本身随连接死**（条目 = 常量 1~2，无累积面）：`proxyman/outbound/uot.rs:236/240`（每次 `UotServerConn::new` 建新 `FxScope`，2 条）、`reverse/relay.rs:81`（每 yamux bridge 新 scope）、`reverse/worker.rs:191/213`（每 PortalWorker 新 scope）、`reverse/worker.rs:407`（每 bridge 控制会话）
- **数据面泵已走显式脱管口 `spawn_detached`**（bd hj3jf 裁定，② 已登记）：`mux/client.rs:320/471`、`finalmask/xdns/server.rs:155/158/161`、`core/functions.rs:565`
- **数据面逐包泵裸 spawn（坑约束 ⑫ 豁免）**：`transport/udp/relay.rs:200`（UDP recv 泵，就地 `#[allow]` + 理由）

### 2.4 禁双份账本

迁移只把 `spawn_tracked` 换成「收割 + `spawn_tracked`」，**未新增任何账本**；未删除任何既有 JoinSet（`metrics.rs` 的内层 JoinSet 记的是子任务句柄，与被收割的 scope 条目不是同一批）。

---

## 3. 依赖面（4 个 crate 新增 `xray-frame` 生产依赖）

`xray-app-proxyman` / `xray-mux` / `xray-app-commander` / `xray-app-reverse` 原先生产依赖图无 `xray-frame`（仅 udf `skeleton_infra`），无法调用 `compat::spawn_reaping`。按 §3.5.3「血肉→骨架」方向补 path 依赖：

- 无环：`xray-frame` 只依赖 udf 三 crate + tokio/serde/tracing/log/bytes/xray-buf（`cargo tree -p xray-frame` 核）。
- 备选（就地 `let _ = fx.try_reap();`）未采用：那样会**静默丢 panic 载荷**（无日志装配点），等于把「收割」降级成「清垃圾」。

---

## 4. 回归门（新增）

`crates/xray-proxy-socks/src/server.rs::tests::conn_tasks_terminate_and_close_leaves_zero_in_flight`

锁定面：40 条**真实完成握手**的连接跑完 → `in_flight()` 回落到 accept loop 一条 → 无 panic/cancelled 载荷滞留 → `close()` 后 `in_flight()==0`。

**判别力说明（重要，勿按「条目数」解读）**：`FxScope::try_reap()` 只返回 **panic/cancelled 载荷**（正常完成条目静默出集、不入返回值，见 udf `fx.rs:484-499`），且 `FxScope` 不暴露生命周期集条目数 → **单测无法直接断言「条目累积」**。因此：

- 本测试锁「无残留任务 + 无错误载荷」；
- 「条目随下次 spawn 出集」的判别在**进程面**（`scripts/86i4h_stage2_reap_e2e.py` 的 `XRAY_ALLOC_STATS` `live_bytes / 连接数`）与 `xray-frame/src/compat.rs` 既有机制单测（`scope_spawn_reaps_and_reports_panic`，用 panic 载荷判别）；
- 顺带发现（阶段1 文档口径）：`compat::reap_into` 注释写作「返回收割到的条目数」，实际返回的是 **error 条目数**（正常完成不计）。不影响行为，但台账/报告若拿它当「条目数」会误读——建议阶段1 补一行文档修正。

---

## 5. 未做

- 测试面 424 处裸 spawn 不登记（既有口径：坑约束 5 的 CI 闸只覆盖生产面；扩到测试面属另一票）。
- 未新增 `xray-frame` 任何 API（`spawn_reaping` / `log` 均为 G5 阶段1 既有件）。
- 未动 vision/splice、`xray-transport-tcp/register.rs`、根 `tests/`、`xray-conf/`。

---

## 6. 残留与后续面

1. **测试面裸 spawn 424 处**：不在 CI 闸，安全（测试进程短命），但口径上仍为「未登记」。若要统一，需把 clippy 闸扩到 `--all-targets` 的测试面（会一次红 424 处）。
2. **`transport/udp/relay.rs:200`** 的 UDP recv 泵仍是裸 spawn（⑫ 豁免已登记）；若将来 udf 提供「无记账 detach + 取消句柄」形态可一并收口。
3. **udf 侧自动回收**（Verify-Mem §1.3 方案 B）：本票是方案 A（主仓每事件收割），若上游 `FxScope` 实现按计数自动回收 Ok 条目，本票 37 处站点可回退为裸 `spawn_tracked`——**主仓 API 面无变化，回退成本 = 机械替换**。

---

## 7. 【验证命令 + 关键输出】

环境（每条 cargo 前）：
```bash
export BORING_BSSL_PATH=D:/Project/Xray-core-rust/target/boringssl-asm/prebuilt
export BORING_BSSL_ASSUME_PATCHED=1
export PROTOC=D:/Project/tools/bin/protoc.exe
export LIBCLANG_PATH="D:/Program Files/llvm/bin"
export CARGO_TARGET_DIR=D:/Project/Xray-core-rust/target-86i4hPhase2
```

### 已跑（真实输出）

| 门 | 命令 | 结果 |
|---|---|---|
| 类型检查（本票改动面 15 crate，`--all-targets`） | `cargo check -p xray-proxy-socks -p xray-proxy-http -p xray-proxy-trojan -p xray-proxy-anytls -p xray-proxy-freedom -p xray-proxy-hysteria -p xray-proxy-tuic -p xray-proxy-wireguard -p xray-proxy-dns -p xray-app-proxyman -p xray-app-reverse -p xray-app-commander -p xray-mux -p xray-app-dns -p xray-transport --all-targets` | **零 error**（仅 `vendor/rustls` 既有 2 warning：`unreachable pub item`/`needs_key_share` 未用） |
| **clippy（改动面 15 crate，`-D warnings`）** | 同 crate 集 `cargo clippy --all-targets -- -D warnings` | **EXIT=0，零告警**（`Finished dev profile … in 1.12s`；仅 vendor rustls 既有 2 warning 仍为 warning 级） |
| 4 个新增依赖 crate 复检 | `cargo check -p xray-proxy-socks -p xray-app-proxyman -p xray-app-reverse -p xray-app-commander -p xray-mux --all-targets` | **Finished**，零 error |
| 新增回归单测 | `cargo test -p xray-proxy-socks --lib conn_tasks_terminate_and_close_leaves_zero_in_flight` | `test result: ok. 1 passed; 0 failed; 88 filtered out` |
| 同上（诊断轮，`--nocapture`） | 同上 + `-- --nocapture` | `served=40 in_flight=1`（40 条连接全部完成握手、连接任务全部终局） |
| fmt | `cargo fmt -p <15 crate> -- --check`（逐 crate `cargo fmt -p …`） | 通过（写作期已 fmt，复检无 diff） |
| 站点清单 | `python reports/.../fix/scripts/86i4h_site_inventory.py` | `-- 生产面裸 spawn 171 处（已登记 171 / 未登记 0）`、`测试面 424 处`、`托管面 101 处` |
| 本票落地面 | 脚本枚举 `compat::spawn_reaping` | **38 处**（36 处本票新增 + 2 处阶段1 的 `scope.rs` arm/conn scope） |

### clippy 期修掉的两处本票引入告警（记录在案）

1. `crates/xray-app-dns/src/nameserver/doh.rs:289` — `needless_borrow`：`fx_scope()` 返回 `&Arc<FxScope>`，传 `&fx` 多借一层 → 改传 `fx`。
2. `crates/xray-proxy-wireguard/src/inbound.rs:505` — 同族 `needless_borrow`：`forward_wg_udp_datagram(fx: &Arc<FxScope>)` 形参已是引用 → 首参改 `fx`（G9TestCI 报告）。


### 未跑（必须说明，勿按「已验收」引用）

1. **`cargo clippy --workspace --all-targets -- -D warnings`**：只跑了改动面 15 crate（**EXIT=0 零告警**，见上表）。workspace 全量未跑：该工作树有 3 路并行组在飞（`git status --porcelain` 200+ 项），全量结果会混入他组中间态。
2. **进程面 e2e**（`86i4h_stage2_reap_e2e.py`：R1 转发 / R2 `live_bytes` 每连接增量 / R3 句柄线程 / R4 停机）：脚本已写好但**未跑**——需 release 构建后执行：
   `python reports/audit-2026-10-31-perf-mem-wiring/fix/scripts/86i4h_stage2_reap_e2e.py --xray target-86i4hPhase2/release/xray.exe --conns 300`；反向对照加 `--expect leaky`（把 socks 站点临时退回 `spawn_tracked` 再跑，判据 `≥100 B/连接`）。
3. **`cargo doc --workspace --no-deps`**（验收 5，断链）：未跑。本票未新增/改任何 rustdoc link（改动均为表达式级 + 行内注释，无 `` [`x`] `` 引用），断链风险面为零；但**未取证**。
4. **两处非本票的红**（已做归因，勿记到 86i4h 账上）：

### lib 单测（改动面逐 crate，`cargo test --lib -q -p <crate>`）

| crate | 结果 |
|---|---|
| `xray-proxy-socks` | ok 88 passed / 1 ignored |
| `xray-proxy-http` | ok 85 |
| `xray-proxy-trojan` | ok 88 |
| `xray-proxy-freedom` | ok 100 |
| `xray-proxy-dns` | ok 85 |
| `xray-proxy-wireguard` | ok 112 |
| `xray-mux` | ok 145 |
| `xray-app-dns` | ok 244 |
| `xray-app-commander` | ok 93 |
| `xray-app-proxyman` | ok 124 |
| `xray-app-reverse` | **91 passed / 2 failed**（`entity_tests::portal_worker_drains_over_threshold_and_disposes`、`portal_worker_heartbeat_sends_control_on_internal_dest`，均在 `.expect("read ok")` 处） |
| `xray-proxy-anytls` | **未完成**：`uot::tests::length_framed_roundtrip` 单独跑也 >60s 不返回（见下） |
| `xray-proxy-tuic` / `xray-proxy-hysteria` / `xray-transport` | 未跑（批量运行 1800s 超时，未取证） |
| 新增回归单测（socks） | ok（40 条真实连接 → `in_flight=1` → `close()` 后 0） |

**归因证据（两处红都不是本票引入）**：

1. `xray-app-reverse` 2 条：**把本票两处 hunk 临时退回 `spawn_tracked` 后复跑，同样 2 条同样断言失败**（99/91 passed、2 failed，失败行随行号位移到 `worker.rs:833/894`）→ 与本票 spawn 形态无关，属共享树现状（reverse 的 portal 控制流测试，涉 mux/pipe 面他组改动）。
2. `xray-proxy-anytls` 的 `uot::tests::length_framed_roundtrip` 卡死：本票在 anytls 的 diff **只有 `src/server.rs`**（`git diff --stat` 实名），`src/uot.rs` 一行未动；该测试单独运行即不返回 → 与本票无因果关系。


### 共享树提示

验证期间该工作树有 3 路并行组在飞（`git status --porcelain` 257 项），全量门（workspace 级）绿/红会混入他组中间态——本票结论只对 §7「已跑」表里的条目负责。
