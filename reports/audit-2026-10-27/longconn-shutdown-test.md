# 长连接停机行为回归测试（W4 面 6 停机语义钉子）

VERDICT: CONDITIONAL-PASS —— 测试已落地且按契约断言确定不变量；实测 **3/3 次确定性红**：在途长连接在停机信号后继续传输（token cancel 与 `Instance::close` 双形态均不终止）。按契约「测试暴露真实缺陷 → 不改修、上报」，缺陷点与日志证据如下，是否留红测试/派修复票由 PM 拍板。

---

## 1. 交付物

- **测试**：`crates/xray-core/src/functions.rs` `mod tests::shutdown_token_cancel_terminates_inflight_long_connection`（紧邻既有 `graceful_shutdown_cancels_inbound_tasks`，复用 `start_full_retrying_eaddrinuse` / `FREEDOM_ALLOW_ALL_SETTINGS` 同风格）。
- **新增测试本地 helper**（同文件，仅测试用）：`bind_echo_retrying_eaddrinuse`（echo 端口同款 `pick_free_ports` + EADDRINUSE 换端口重试 5 次）、`wait_socks_ready`（就绪探针：轮询 socks 握手至应答，**非固定 sleep**）。
- **拓扑**（复用 `integration_socks_through_ss_to_echo`，命中 W4 面 6 目标路径 `spawn_ss_pump`）：
  `test-client → client 实例 [socks-in → ss-out(aes-256-gcm)] → server 实例 [ss-in(spawn_ss_pump) → freedom] → echo`
- **传输形态**：8KB 位置确定性分块（字节值 = 全局偏移/8192 % 255 + 1，部分尾块同可校验）+ 1ms 间隔——v52 loopback 大块全速病理规避形态。链路先完整回传 3 块（证明传输确实在进行）再触发停机。
- **停机触发**：传输进行中 cancel **server 实例** `shutdown_token()`（SS 泵所在 arm scope 的停机信号；client 实例保持运行以隔离观测 server 侧级联）。
- **断言（确定不变量）**：
  - (a) 传输端 ≤2s 内观察到终止（EOF/读错），悬挂/持续收到数据 = 违约 panic（panic 消息携带 post-cancel 字节数、writer 已写块数）；
  - (b) server inbound 任务 ≤2s 内退出；
  - (c) 无 panic 逃逸（`JoinError::is_panic` 即失败；内层 panic 由 FxScope catch_unwind 归一后经外层壳 error! 留痕，属日志面非断言面）；
  - (d) in_flight 归零：**不可观测，未断言（不伪造）**——arm FxScope 在 serve 任务闭包内部，`Instance`/`InboundRuntime` 无公开访问面，测试侧拿不到引用（`FxScope::in_flight()` 存在于 udf `skeleton-infra/src/fx.rs:272`，但无可达路径）。
- **端口纪律**：全部端口来自 `xray_common::testing::pick_free_ports`（实例经 `start_full_retrying_eaddrinuse`，echo 经同款重试 helper）。未自造 `bind(:0)+drop`。
- **禁固定 sleep 遵守**：就绪用轮询探针；契约提到的常量 `READY_DELAY` **全仓 grep 0 命中不存在**（`crates/` 范围），按契约备选路径「轮询到就绪」执行。
- **产品代码零改动**；未 commit / 未 push。

## 2. 实测结果（新测试连跑 3 次）

**3/3 确定性红，违约点 = 断言 (a)**（(b)(c) 未及执行——(a) panic 先行；链路预检 3 块回传与逐字节校验三次全过，排除「链路本身不通/坏数据」假阳）：

```
===== RUN 1 =====
thread 'functions::tests::shutdown_token_cancel_terminates_inflight_long_connection' (22488) panicked at crates\xray-core\src\functions.rs:2002:13:
长连接未随停机终止：server shutdown_token cancel 后 2011ms 内仍持续收到 1540096 bytes (writer 已写 191 块)——停机级联未达在途连接（W4 面 6「connection drain 留后续」实测）
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 479 filtered out; finished in 2.04s

===== RUN 2 =====
thread 'functions::tests::shutdown_token_cancel_terminates_inflight_long_connection' (22572) panicked at crates\xray-core\src\functions.rs:2002:13:
长连接未随停机终止：server shutdown_token cancel 后 2000ms 内仍持续收到 1376256 bytes (writer 已写 171 块)——停机级联未达在途连接（W4 面 6「connection drain 留后续」实测）
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 479 filtered out; finished in 2.03s

===== RUN 3 =====
thread 'functions::tests::shutdown_token_cancel_terminates_inflight_long_connection' (14096) panicked at crates\xray-core\src\functions.rs:2002:13:
长连接未随停机终止：server shutdown_token cancel 后 2011ms 内仍持续收到 1286144 bytes (writer 已写 160 块)——停机级联未达在途连接（W4 面 6「connection drain 留后续」实测）
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 479 filtered out; finished in 2.03s
```

（命令：`cargo test -p xray-core --lib shutdown_token_cancel_terminates_inflight_long_connection -- --nocapture`，env 按 CLAUDE.md §5 + `RUST_MIN_STACK=16777216` + 独立 `CARGO_TARGET_DIR=target-LongConn`。cancel 后 2s 窗口内持续收到 1.2–1.5 MB 回传数据 ≈ 8MB/s 泵速未受任何影响，逐字节校验零损坏。）

### 2.1 `Instance::close()` 对照探针（临时测试，已删除）

契约问「close 是否更贴合真实停机」——用一次性探针实测（同一拓扑，`Arc::try_unwrap` 取 `&mut` 后调 `close()`，探针已删不留树）：

```
PROBE close() result=Ok(()) elapsed=1.3021ms
PROBE close() observation: terminated=None post_cancel_bytes=1253376 elapsed=2.0136219s
PROBE handles drain ok=true
```

**`Instance::close()` 同样不终止在途长连接**（close 本身 1.3ms 完成，之后 2s 内继续回传 1.25MB）。差异注明：`close` = token cancel + 逆序 close features（`instance.rs:337` 起）；features（dns/routing/policy/stats 默认四件）不持有连接任务，故对在途连接与 token cancel 语义等价（实测证实）。accept 任务退出（`handles drain ok=true`）与既有 `graceful_shutdown_cancels_inbound_tasks` 断言一致——停机只到达了 accept 层。

## 3. 该测试**证明**了什么

1. **`shutdown_token().cancel()` 与 `Instance::close()` 都不会终止已建立的在途长连接**——SS 泵路径（spawn_ss_pump，ConnScope 托管）在停机信号后以全速继续双向中继（三连实测 1.2–1.5MB/2s，逐字节无损坏）。这是**确定性**行为，非 flaky。
2. W4 面 6 声称的「停机级联取消」（SS 泵/mux carrier 随 arm scope 关闭被级联取消）**在两种停机触发形态下均不可达**。根因链（静态定位，未修）：
   - shutdown token 只被 inbound **accept serve 任务** select（`inbound.rs` `spawn_inbound_serve` 内 `select!` → cancelled 臂）；per-conn 任务（`serve_ss` 每连接 `plugin_ctx.spawn` + `_ctx` Arc 锚）**不监听 token**；
   - ConnScope 父闸 = `ArmScope::close()` 的 watch 广播（xray-frame `scope.rs::ConnScope::child_of`）；而 `ArmScope::close()` 在 xray-core **零调用点**（W4 报告 §1.2 自己记录「arm scope 无 close()/shutdown() 调用点，只在 Arc 归零时 Drop」），且 child_of 的监视任务**持父 Arc 锚**——子活着父就 drop 不了 → 父闸广播在「token cancel」触发形态下**结构性不可达**，级联只剩「scope Drop 兜底」，而 Drop 又要求全部任务先死（先有鸡还是先有蛋）；
   - `spawn_inbound_serve` 文档自证：`inbound.rs:3264-3265`「token cancel 时取消 serve future…对应 Go 有序关闭的"先停 accept"阶段。**connection drain 留后续**」——即当前行为是已知欠账，本测试把它变成可执行断言。
3. 「停机语义收紧」的**实际生效面**只限：任务不再脱离 scope 生命周期（drop-abort 兜底）+ accept 层停机——对「在途连接 drain 粒度」的观测行为**零变化**（与收紧前裸 spawn 在此触发形态下的表现一致）。
4. 回归钉子价值：将来谁实现「停机级联/连接 drain」（如 arm scope 登记进 ShutdownCoordinator + 停机时显式 `close()`，或 per-conn 任务 select token），本测试自动转绿——修复验收命令现成。

## 4. 该测试**不能**证明什么（明写）

- **未覆盖 mux carrier 多路复用场景**：mux link 任务同为 arm scope 托管，按同构外推结论应一致，但未实测（需要 mux 配置 + 多 session 载具，超出本票面）。
- **未覆盖 TUN inbound**（W4 面 6 判「不可迁残余 1」，仍裸 spawn）。
- **未覆盖 vision splice / REALITY / TLS 传输路径**——纯裸 TCP + SS legacy AEAD；transport 解包后的 ss_transport_on_conn 分支未走。
- **未覆盖 client 实例侧在途连接**（socks per-conn 同为 arm scope + Arc 锚，静态同构；本测试只 cancel server 实例以隔离归因）。
- **(d) in_flight 归零未断言**：不可观测（无公开访问面，见 §1），非「断言了且过了」。
- **未追 xray-cli 生产信号路径**（SIGINT→close 的调用链）与「连接自然结束后 scope 收账」路径（ConnScope Drop→close）。
- 未证明「Go 行为如何」——Go 侧停机对在途连接的语义未做对照（Go `os.Interrupt` 后活跃连接同样依赖各 handler 自行关闭，属后续互通取证票范围）。

## 5. 验收对照

| 契约验收 | 结果 |
|---|---|
| 1. 新测试连跑 3 次全绿 | **未达成（3/3 红，确定性）**——契约预设的缺陷暴露路径，证据见 §2 |
| 2. `cargo test -p xray-core --lib` → 0 failed | **1 failed = 本测试（预期红）**，其余全绿，见 §5.1 |
| 3. fmt clean | `cargo fmt --all -- --check` **全仓 clean**（未被他人 untracked 阻塞，无需降级 -p） |
| 报告证明/不证明节 + 3 次输出 | 本文件 §3/§4/§2 |

### 5.1 全量 `cargo test -p xray-core --lib` 尾部输出（env 同 §2；finished in 31.69s）

```
test functions::tests::repro_three_layer_vision_rustls_tcp_512k ... ok
test functions::tests::integration_vless_vision_over_tls_to_echo ... ok
test outbound::tests::target_strategy_end_to_end_json_to_echo ... ok
test functions::tests::shutdown_token_cancel_terminates_inflight_long_connection ... FAILED
test outbound::tests::freedom_user_level_drives_conn_idle ... ok
test outbound::tests::tuic_default_tls_rejects_self_signed ... ok

failures:

---- functions::tests::shutdown_token_cancel_terminates_inflight_long_connection stdout ----

thread 'functions::tests::shutdown_token_cancel_terminates_inflight_long_connection' (26488) panicked at crates\xray-core\src\functions.rs:2002:13:
长连接未随停机终止：server shutdown_token cancel 后 2012ms 内仍持续收到 1458176 bytes (writer 已写 181 块)——停机级联未达在途连接（W4 面 6「connection drain 留后续」实测）
failures:
    functions::tests::shutdown_token_cancel_terminates_inflight_long_connection

test result: FAILED. 477 passed; 1 failed; 2 ignored; 0 measured; 0 filtered out; finished in 31.69s
```

唯一 failed = 本测试（预期红）；其余 477 项全绿，无连带回归。

## 6. 修复方向建议（不在本票实施，供 PM 派票）

最小闭环 = 停机时显式关闭 arm scope：装配期为每个 inbound arm 的 `Arc<PluginContext>` 建登记表（arm_builders 构造点已集中），`Instance::close()` 在 token cancel 后逆序调 `ArmScope::close()`（父闸广播 → ConnScope 级联取消泵 → per-conn 任务 select token 或被 close 后 abort）——即把「停机必注册」（坑约束 ⑥）从泵/载具层补到宿主层。注意两点：① child_of 监视任务持父 Arc 锚，显式 close 广播后父 Arc 仍需任务排空才归零（Drop 语义不变，无碍）；② mux carrier 在 arm scope 的 JoinSet 残条（W4 §6.1 无收割 API 债）在 close 路径会被 `shutdown` 排空语义覆盖与否需一并核对。

## 7. 5 维自评

- **准确性 5/5** —— 每条结论有实跑证据：3 连红 + close 探针 + 逐字节校验；根因链每跳有符号定位（`spawn_inbound_serve` select 臂、`serve_ss` per-conn spawn、`scope.rs child_of` 父 Arc 锚、`instance.rs close`），无推断冒充实测。
- **完整性 4/5** —— 契约四断言 (a)–(d) 逐条处置（含 (d) 的不可观测明写）、双触发形态实测、helper 纪律（pick_free_ports/无固定 sleep）全守；扣分：mux carrier 场景未实测（票面明写不覆盖）。
- **清晰度 4/5** —— 证明/不证明/根因链/修复方向分层，红点 panic 消息自带证据；扣分：根因链一节信息密度偏高。
- **可执行性 5/5** —— 复跑命令、env、预期输出齐备；测试即修复验收闸（转绿即闭环）。
- **简洁性 4/5** —— 测试一文件一份 + 两小 helper，临时探针已删零残留；扣分：报告偏长（缺陷上报需自含证据，属必要体量）。

---

*执行：LongConnStop（审计子代理，Ponytail 只报告不修码）｜日期：2026-10-28｜产物：`crates/xray-core/src/functions.rs`（仅测试面）+ 本报告；`target-LongConn` 用毕删除。*
