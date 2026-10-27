# 停机级联修复（bd a9xgp）——登记表 + 逆序显式 ArmScope::close + 有界 drain

VERDICT: PASS —— 闸门测试 3/3 绿，`xray-core --lib` 478/0，`xray-frame --all-targets` 22 个测试二进制全绿，REALITY 互通 2/2、六协议双向矩阵 12/12，clippy `-D warnings` 0 error，fmt clean。停机（token cancel 与 `Instance::close()` 双形态）现在真实终止在途长连接：闸门测试取消后 **0.03–0.04s** 观察到传输终止（修复前 3/3 确定性红：2s 窗口内持续回传 1.2–1.5MB）。

---

## 1. 修复设计

### 1.1 根因 → 机制映射（直接沿用 longconn-shutdown-test.md §3 根因链）

| 根因 | 修复 |
|---|---|
| `ArmScope::close()` 全仓零调用点，父闸广播结构性不可达 | ①宿主 `Instance` 持**登记表**，`close()` 在 token cancel 后**逆序显式 close**；②每 arm 的外层壳任务内置**停机监视臂**，裸 token cancel 形态兜底 close+排空（闸门测试即此形态） |
| per-conn 任务不监听 token | 级联不改 per-conn 代码：父闸广播 → `ConnScope` 监视任务（mzput 既有件）→ `CancelSource` 取消 → 泵/`run_until_cancelled` 任务即时死亡 |
| arm 托管任务（socks/mixed/http 每连接、mux carrier、UDP relay、dns serve）不监听任何信号 | arm 排空 = udf `FxScope::shutdown_timeout`（关闸 + **abort_all** + 超时兜底），硬终止 |
| `ArmScope::shutdown_timeout` 不广播（排空形态绕过父闸的陷阱位） | `shutdown_timeout` 入口先 `send_replace(true)` 广播——排空与 close 两形态**同必级联** |

### 1.2 登记表位置（§验收 6）

- **类型**：`crates/xray-frame/src/scope.rs` 新增 `ArmScopeRegistry`（`Mutex<Vec<(tag, Arc<ArmScope>)>>`，登记序 = 装配序；`register` / `close_all_reverse() -> usize`（逆序 close + 出清 + 返回条数）/ `registered()`；毒锁容忍取用，同 arm_builders intern 表先例）。`lib.rs` 导出。
- **登记点**：`crates/xray-core/src/inbound.rs::spawn_inbound_serve` —— 全部 inbound arm 的**唯一构造漏斗**（arm_builders 各构造函数 + transport/unix 分支均经此 spawn），一处登记零散点。
- **表的属主与注入链**：`Instance::new()` 建表（字段 `arm_scopes` + getter）→ `start_full_dispatched` 注入 `InboundRuntime::new`（新增参数）→ `spawn_one_inbound` 经既有 `api: Option<&InboundRuntime>` 注入 `PluginContext`（新增 `with_arm_registry` builder + `arm_registry()`/`arm_scope()` 观察面，`new` 8 参签名零变化）→ `spawn_inbound_serve` 消费。
- **接线点（5 处，全部生产 inbound 构造路径）**：spawn_one_inbound TCP 表分派臂、spawn_unix_inbound、spawn_unix_transport_inbound（vless decryption ctx + 监听保活 ctx）、arm_builders `ss_transport_on_conn`（ss-over-transport 泵宿主）。`api=None`（独立/测试构造）不接线，行为同旧。

### 1.3 逆序点与 drain 预算值（§验收 6）

- **逆序点**：`instance.rs::Instance::close()` —— `self.shutdown_token.cancel()` 之后、feature stop 序列（`shutdown_bridge::close_features`）之前：`self.arm_scopes.close_all_reverse()`（后装配先关，逐条 `ArmScope::close()` 关闸+广播；带 info 日志）。幂等：裸 token cancel 形态下监视任务先关过的 arm 重复 close 无害。
- **drain 预算**：`inbound.rs::ARM_SCOPE_DRAIN_TIMEOUT = 5s`（保守默认，对齐 xray-frame `DEFAULT_SHUTDOWN_TIMEOUT` P0-8 与 `shutdown_bridge::DEFAULT_CLOSE_TIMEOUT` 同族停机档）。**无新增可配参数**：排空在后台监视任务进行，不阻塞任何调用方返回路径，预算只界定"取消广播后至多容忍 5s 收净，超时剩余任务已被 abort 兜底（udf close_and_take 零残留）"——**停机永不无限等**。

### 1.4 停机监视臂（闸门测试路径的关键）

`spawn_inbound_serve` 外层壳任务（既有 raw spawn，allow 已登记，零新增任务面）扩为双臂 select：

- token 臂：`arm.arm_scope().shutdown_timeout(5s)`（广播 → ConnScope 级联 → abort_all → 有界排空）；
- join 臂（panic 监督语义逐字保留）：**serve 与监视令牌同听一个 token，`select!` 双臂同就绪随机裁决**——join 臂胜出且 token 已取消时**必须兜底执行同一排空**；token 未取消（listener 自然终局）不排空，保留既有「连接任务不随 listener 死亡」的 detach 语义。

> **修复过程中踩中并修掉的真坑（留档）**：首版只有 token 臂，3 连跑出现 **1 红 2 绿**（RUN 2 复现原失败签名）——join 臂抢先即跳过级联，闸门从"确定性绿"退化成"裁决随机性绿"。修复 = 双臂收敛（join 臂 `watch_token.is_cancelled()` 时兜底排空）后 3/3 稳定绿。

## 2. 验收输出（实跑）

### 2.1 闸门测试 3 连绿（修复后）

```
===== RUN 1 =====
test functions::tests::shutdown_token_cancel_terminates_inflight_long_connection ... ok
test result: ok. 1 passed; 0 failed; ... finished in 0.04s
===== RUN 2 =====
test functions::tests::shutdown_token_cancel_terminates_inflight_long_connection ... ok
test result: ok. 1 passed; 0 failed; ... finished in 0.04s
===== RUN 3 =====
test functions::tests::shutdown_token_cancel_terminates_inflight_long_connection ... ok
test result: ok. 1 passed; 0 failed; ... finished in 0.03s
```

（取消后 30–40ms 观察到 EOF，预算 2s；修复前同测试 3/3 红、2s 窗口持续 1.2–1.5MB。）

### 2.2 `cargo test -p xray-core --lib`

```
test result: ok. 478 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out; finished in 31.64s
```

含守护面全绿：`graceful_shutdown_cancels_inbound_tasks`、instance.rs 的 `close_invokes_in_reverse_order` / `close_panicking_feature_is_isolated_and_others_still_closed` / `close_timeout_abandons_stuck_feature_and_returns_err`、arm_builders 表测试、unix e2e 族。

### 2.3 `cargo test -p xray-frame --all-targets`

22 个测试二进制全 0 failed（lib 48 + assembly_e2e 5 + compat_caps 4 + compat_fallback 2 + config_merge 8 + config_routing 3 + **conn_scope 8** + contract_assert 2 + deadline_budget 6 + deadline_contract 7 + fx_managed_spawn 4 + hot_log 6 + l4_fixtures 15 + lifecycle_order 5 + log_discipline 4 + observe_fields 4 + plugin_context 11 + plugin_registry 6 + pool_isolation 7 + redline_sites 4 + reload_rollback 6 + shutdown_wiring 6 = 171 tests）。含 mzput 的 conn_scope 级联族与 shutdown_wiring——`ArmScope::shutdown_timeout` 新增广播未破坏任何既有断言。

### 2.4 互通不回退

```
=== reality 互操作: 2/2 PASS ===
  [PASS] #01 Rust->Go  vless+reality/tcp  HTTP=HTTP:200 body=200014B marker=True
  [PASS] #02 Go->Rust  vless+reality/tcp  HTTP=HTTP:200 body=200014B marker=True

=== 互操作矩阵: 12/12 PASS ===
  vmess / vless_vision_tls / trojan_tls / vless_ws / ss / ss2022 × Rust->Go 与 Go->Rust 全 PASS
```

（release 二进制按当前树全量重编 `cargo build --release -p xray-cli`，拷至 `target/release/xray.exe` 供脚本消费。）

### 2.5 clippy / fmt

```
cargo clippy -p xray-core -p xray-frame --all-targets -- -D warnings
    Finished `dev` profile ... in 35.83s        （0 error 0 warning）
cargo fmt -p xray-core -p xray-frame -- --check
FMT-CLEAN
```

## 3. 两条已知陷阱核对结果（§验收 3）

### 3.1 `child_of` 监视任务持父 Arc 锚

**语义不变，无泄漏，无双关。** 显式 close 广播后：conn scope 监视任务从 `wait_closed` 醒来 → `source.cancel()` → 监视任务 return（其 Arc 锚释放）→ conn scope 任务被取消 → 各任务 `_ctx`/`_scope` 锚释放 → 父 `Arc<ArmScope>` 引用计数自然归零 → Drop 再走一遍幂等 close（CAS 闸 + watch 同值写，均无害）。关键点：**登记表/`Instance::close` 不等待 Arc 归零**——逆序 close 是同步广播段，锚排空完全交给既有 Drop 语义，两条路径零耦合。双触发（`Instance::close` sweep + 监视任务）只产生幂等重复 close。

### 3.2 mux carrier 在 arm scope 的 JoinSet 残条（W4 §6.1 债）

**结论：close 路径覆盖 carrier 层，不覆盖 xray-mux 内部每会话原生任务（明写欠账，按非目标不建收割 API）。**

- carrier 任务（`handle_mux_inbound_link`）四处均 `plugin_ctx.spawn`（socks/mixed×2/http 的 arm scope）→ 归 arm FxScope → 停机 `shutdown_timeout` **abort_all 硬终止** carrier（`worker.close()` 协作面因 abort 不执行，carrier link 随 future drop 关闭，客户端侧看到 carrier EOF——停机场景语义正确）。
- 每会话任务在 xray-mux `worker.rs` 内是 **raw `tokio::spawn`**（dispatch/session-output/monitor 各处，allow 均登记）——不在任何 scope 的 JoinSet 内，arm 排空**不直接杀**它们；carrier 死后其队列关闭 → 会话泵 EOF → 自终（尽力而为、实践毫秒级，非硬保证）。此即 W4 §6.1「FxScope 完工 JoinSet 条目无收割 API 会无界累积，bd 39hko」同族欠账的停机面残条，本票不修（非目标），留 39hko。

## 4. 改后是否多了等待路径（§验收 6）

**调用方可感知路径零新增阻塞：**

- `Instance::close()`：新增的逆序 sweep 是**同步非阻塞**广播（每 arm 一次 CAS + watch 写），close 返回耗时与修复前同量级（微秒级 + N×广播）；有界排空全部在后台监视任务。
- 数据面：零改动（不碰 vision gate/splice、不碰传输路径、不加任何热路径分支）。
- 新增的 5s `shutdown_timeout` 是每 arm 停机一次的后台有界等待，不落在任何函数返回值上；`graceful_shutdown_cancels_inbound_tasks`（2s 预算内 await handles）实测仍绿——空闲 arm 排空即时完成。
- `ArmScope::shutdown_timeout` 新增的入口广播对 xray-frame `Framework::shutdown` 路径冗余无害（其 ①段本就先 `fx.close()`）。

## 5. 覆盖边界（诚实申报）

- **已覆盖**：SS 泵（ConnScope 级联）、socks/mixed/http 每连接 + UDP associate relay + mux carrier + dns serve（arm abort_all）、unix 裸 TCP 五协议臂、ss-over-transport（ws/grpc/kcp 等 hub 解包后的 SS 泵）。
- **未覆盖（既有欠账，非本票范围）**：①transport on_conn 工厂的每连接 raw spawn（vless/trojan/vmess transport 分支——bd 39hko JoinSet 收割债，停机后随 link EOF 自终，非硬终止）；②TUN inbound（longconn 报告 §4 明写）；③vision redline 受控口 spawn；④xray-mux 每会话原生任务（§3.2）；⑤dispatcher 后台 link 持有任务（EOF 驱动自终）。
- 语义变化 = 修复目标本身：per-inbound `RemoveInbound`（child token cancel）现在也会终止该 inbound 的在途连接（此前为 detached 泄漏形态）；listener 自然终局（accept 硬错）不改变连接任务命运。

## 6. 风险与回退预案

| 风险 | 评估 | 缓解/回退 |
|---|---|---|
| 停机竞态窗内 conn 任务 spawn 撞上已关闸（`.expect("arm FxScope is never closed")`） | 概率≈0（spawn 须恰好落在广播与 abort 之间）；即使命中，FxScope catch_unwind 归一 `TaskError::Panicked`，仅 error! 日志噪声，任务本在拆除中 | 后续可将 expect 降级 warn+skip（15+ 处，不在本票） |
| 停机掐连接语义变化影响长连接复用型客户端 | 即修复目标；互通矩阵 12/12 证明正常建连/传输路径零影响 | 回退 = revert 本票 7 文件（见下） |
| 发布物与在飞兄弟代理改动耦合 | release 二进制按当前树全量重编，矩阵/REALITY 全绿即含兄弟改动的联合验证 | — |

**回退预案**：改动面 = `xray-frame/{scope,context,lib}.rs` + `xray-core/{instance,inbound,arm_builders/inbound,functions}.rs`，全部为**加法**（新类型/新方法/新字段/双臂收敛）；唯一行为改动点 = `ArmScope::shutdown_timeout` 入口广播与 `Instance::close` sweep、监视臂。逐点回退：去掉 shutdown_timeout 广播 → 排空形态退回不级联（其余无影响）；去 sweep + 监视臂 → 完全恢复修复前行为。

## 7. 改动文件清单

- `crates/xray-frame/src/scope.rs`：`ArmScope::shutdown_timeout` 入口广播；新增 `ArmScopeRegistry`
- `crates/xray-frame/src/context.rs`：`PluginContext.arm_registry` 字段 + `with_arm_registry`/`arm_registry`/`arm_scope`
- `crates/xray-frame/src/lib.rs`：导出 `ArmScopeRegistry`
- `crates/xray-core/src/instance.rs`：`arm_scopes` 字段 + getter；`close()` token cancel 后逆序 sweep
- `crates/xray-core/src/inbound.rs`：`InboundRuntime` 字段/参数/getter；`spawn_inbound_serve` 登记 + 双臂停机监视 + `ARM_SCOPE_DRAIN_TIMEOUT` + `drain_warn`；4 处接线
- `crates/xray-core/src/arm_builders/inbound.rs`：`ss_transport_on_conn` 接线
- `crates/xray-core/src/functions.rs`：`InboundRuntime::new` 调用点

---

*执行：ShutdownCascade（bd a9xgp 修复单）｜2026-10-28｜独立 target：`target-ShutdownCascade`（验收完删除）；未 commit / 未 push；未改 udf 父仓、未改 tests/、未改 CI。*
