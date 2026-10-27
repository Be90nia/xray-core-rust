# mzput — ConnScope::child_of 去轮询（close-notify 级联）

VERDICT: PASS

（初判 CONDITIONAL 的唯一原因已消除：组合 clippy 门 `cargo clippy -p xray-frame
-p xray-core --all-targets -- -D warnings` 在 peer PortToctou-2 修复其未提交文件
`crates/xray-common/src/testing/mod.rs`（`pick_free_ports` 内 `unwrap()` → `expect`，
命中 unwrap_used=deny）后**复跑 Finished 零 error**。该文件非本件改动面，本件
自始至终未触碰。）

## 1. 背景

`ConnScope::child_of`（`crates/xray-frame/src/scope.rs`）原以 **20ms 闸位轮询**实现父→子
级联关闭：监视任务每 20ms 醒来查一次 `parent.is_closed()`。根因：udf `FxScope::close()`
只 CAS accepting 闸（`skeleton-infra/src/fx.rs` `close()` 实现事实），**不发任何取消/通知
信号**。代价 = 每连接 ≈50 次空转唤醒/秒；单连接可忽略，长连数千连接时是纯 CPU 税
（bd mzput，P3）。

## 2. 机制选型

**`tokio::sync::watch`（xray-frame 侧新件 `ArmScope`）**，udf 侧零改动（`crates/udf-frame/`
git diff 为空，已核实）。

- **为什么 watch 而非 Notify**：级联语义 = 「状态」（已关/未关），不是「事件脉冲」。
  watch 携带终值 + 每接收端独立版本账，天然覆盖「父先关、子后注册」窗口（订阅即读
  终值 true）；Notify 的 permit 是一次性脉冲，先 close 后 register 会**丢唤醒**，还得自己
  补一个状态位 + 双检查——等于手搓半个 watch。
- **关闭事件的落点**：裸 `FxScope::close()` 无法被拦截（外部 AtomicBool CAS），故 arm 级
  父 scope 一律改经新件 **`ArmScope`**（内嵌 `FxScope` + `watch::Sender<bool>`）持有，
  `ArmScope::close()` = 关闸 + `send_replace(true)` 同一同步段落账。绕过本件的裸
  `FxScope::close()` 不会级联（ArmScope 头注已写明契约）。
- **子侧**：`ConnScope::child_of(&Arc<ArmScope>)` 订阅 watch，监视任务挂起在
  `changed()`（事件驱动，无定时器）→ 父关 → `source.cancel()` 级联取消本 scope。监视
  任务仍归子 scope 自身托管（本 scope 先关时 biased select 下自行了结，不泄漏
  in_flight），并持 `Arc<ArmScope>` 锚（旧轮询任务持 `Arc<FxScope>` 锚同款——子任务
  存活期间父 scope 不 drop，寿命语义不变）。

### 丢失唤醒论证（两窗口 + 幂等）

| 窗口 | 机制 | 结果 |
|---|---|---|
| a) 父已关、子后注册 | `subscribe()` 即得当前值；`borrow_and_update()` 读到 true → **同步** cancel + 关闸，不 spawn 监视任务 | 观察零延迟、确定性 |
| b) 子挂起在 `changed()` 期间父关 | `borrow_and_update` 已把已读版本钉在 false；此后 `send_replace(true)` 使接收端版本落后 → `changed()` 就绪（翻转发生在 borrow 与首次 poll 之间也一样——watch 按版本号判定，不依赖等待起点） | 即时唤醒 |
| 重复关闭 | `close()` 幂等（闸 CAS 幂等；watch 重复写同值仅一次无害伪唤醒，`wait_closed` 循环重读终值即退出） | 幂等 |
| 子先关 | biased select：`token.cancelled()` 优先 → 监视任务了结，不触父 | 父不受影响 |
| 发送端全亡（父中枢先 drop） | `changed()` 返回 Err → 按已关兜底取消（fail-closed） | 不挂死 |

**非轮询证明**（验收 2b 的第二形态）：新增测试 `cascade_has_no_timer_dependency` 用
`#[tokio::test(start_paused = true)]`——tokio 计时器全虚拟化且不自动推进，若级联依赖
sleep 轮询（旧 20ms 形态）该测试**永久挂起**；事件驱动则 watch 通知真实穿透、立即
完成。实测通过 = 挂起期间无定时器。

## 3. 调用点清单（签名确需变更，已全量同步）

公开形态变化 3 处，消费方全量更新，**W4 inbound/mux/DNS 的 scope 归属逻辑 0 行改动**
（`crates/xray-core/` 本件 0 diff；全部消费经 `PluginContext::conn_scope()` /
`PluginContext::spawn`，方法形态不变）：

1. `ConnScope::child_of(&Arc<FxScope>)` → `child_of(&Arc<ArmScope>)`
   调用点：`src/context.rs::conn_scope`（生产唯一调用点，行形态不变）；
   `tests/conn_scope.rs`（测试构造 ×6）。
2. `PluginContext::new` 第二参 `Arc<FxScope>` → `Arc<ArmScope>`，调用点：
   `src/assembly.rs::new_ctx`、`src/config.rs::build_plugins_from_config`、
   `src/contract_assert.rs::contract_test_context_with`、`src/context.rs::for_plugin`
   （xray-core 测试面 `test_plugin_ctx` 走此入口，0 改动）+ 模块内测试 ×3；
   tests：`fx_managed_spawn.rs`（helper+×4）、`lifecycle_order.rs`、`observe_fields.rs`（×2）、
   `plugin_context.rs`（×4）、`pool_isolation.rs`、`shutdown_wiring.rs`。
3. `Framework::scope()` 返回 `&Arc<ArmScope>`（原 `&Arc<FxScope>`）。生产消费方
   xray-cli / xray-core 均 0 调用（grep 证据）；tests：`assembly_e2e.rs` ×2
   （`expect_idle(fx.fx())`）、assembly.rs 模块内测试 1 处（`fw.scope().spawn` 形态不变，
   经 `ArmScope::spawn` 透传）。

`ArmScope` 经 `lib.rs` re-export（`pub use scope::{ArmScope, ConnScope}`）。compat.rs 进程级
caps scope、DNS 实例 scope、lib.rs 类型冒烟测试**不是** conn 父级，保持裸 `FxScope` 不动。

## 4. 稳态唤醒次数

监视任务挂起于 watch 内核等待队列，无定时器：**≈50 次唤醒/秒/连接 → 0 次**。事件时
（父 close）恰 1 次唤醒；子 close 先行时监视任务 1 次唤醒即退。

## 5. 验收输出

1. `cargo test -p xray-frame --all-targets` → **0 failed**（22 个测试二进制全 ok，
   含 lib 48 项；conn_scope 8/8）。
2. 级联行为测试（`tests/conn_scope.rs`，8/8 ok）：
   ```
   test parent_closed_before_child_registers_observed_immediately ... ok   (验收 2a)
   test child_wakes_on_parent_close_while_suspended ... ok                 (验收 2b, <50ms 断言)
   test cascade_has_no_timer_dependency ... ok                             (start_paused 非轮询证明)
   test parent_close_cancels_child_tasks ... ok
   test child_close_does_not_affect_parent ... ok
   test closed_scope_rejects_new_tasks ... ok
   test completed_task_joins_with_some ... ok
   test cancelled_task_joins_with_none ... ok
   ```
3. `cargo test -p xray-core --lib` → **477 passed; 0 failed; 2 ignored**（W4 inbound/mux
   级联断言护栏在内，含 `conn_scope_anchor_survives_host_return_and_spares_siblings`）。
4. clippy：`cargo clippy -p xray-frame -p xray-core --all-targets -- -D warnings` →
   **Finished 零 error**（peer 文件修复后组合门复跑通过；本件文件面自始即绿）。
5. `cargo fmt -p xray-frame -p xray-core -- --check` → **clean**（全仓 `--all` 未跑，按约
   报备；本两包已覆盖本件全部文件面）。

### 过程存证：一次真实回归的归因与修复（对本件验收 3 的护栏价值实证）

全量首跑 `xray-core --lib` 曾曝 `inbound::tests::mixed_socks_udp_associate_roundtrip`
**STATUS_STACK_OVERFLOW**。归因链（全部实测）：

- 单测隔离复现（确定性）；
- **stash 掉本件 14 个文件后同测 PASS**（同树含其他代理在飞改动，归因干净）→ 本件回归；
- 本件改动后 `RUST_MIN_STACK=8MB` 同测 PASS → 非失控递归，是**边际深度**；
- 机制：debug 构建不内联，`ArmScope::spawn` 薄透传在 `serve_mixed` → per-conn task →
  UDP associate 的深轮询链上多落一层真实栈帧，而该链在共享树（含其他代理未提交的
  inbound.rs 深化改动）上对 2MB 测试线程默认栈的余量已薄到「一层帧即击穿」；
- 修复：透传面 `#[inline(always)]`（栈中性 + 钉死内联决策防未来重编译翻转）→
  默认栈全量 477/0 复跑通过。

**给 Main 的树级警示**：xray-core inbound 深轮询链对 2MB 测试线程栈的余量已被压到
「一层 debug 帧」量级（本件实证 stash/恢复即翻转）。后续任何代理在该链上加非内联
调用层都可能复现同类溢出；建议单开 bd 评估（测试线程 `RUST_MIN_STACK` 抬档或链路
减深），本件不动 inbound.rs（非目标）。

## 6. 纪律项

- udf 零改动：`git diff -- crates/udf-frame` 为空（已核实）。
- `crates/xray-core/`、`crates/xray-frame/src/logging.rs`、`tests/zz_bench_tmp.rs`、
  `crates/xray-transport/**`：本件 0 触碰。
- 未 commit / 未 push。
- 自有 target 目录 `target-ConnNotify` 验收后删除。

## 7. 五维自评

| 维度 | 分 | 依据 |
|---|---|---|
| 正确性 | 5 | 两窗口 + 幂等 + 事件语义逐条有测试；一次真实回归（栈边际）被全量护栏抓到并实测归因修复；组合 clippy 门终态复跑绿 |
| 性能 | 5 | 50 次/s 空转 → 0；事件路径一次唤醒；`#[inline(always)]` 保证透传零栈/零调用开销 |
| 可维护性 | 4.5 | 机制收敛单件（ArmScope 头注 = 契约：绕过即不级联）；签名变更调用点全量清单化；扣 0.5 = 共享树测试栈余量是雷（已上报，非本件可修） |
| 风格 | 5 | 组合包装派生（ADR-1 三段式），不复制 udf 机制；文件头「实现事实」注释同步更新；rustfmt clean |
| 测试 | 5 | 新增 4 测（两窗口 + start_paused 非轮询证明 + 幂等/拒新）；xray-frame 193 项 + xray-core 477 项全绿 |
