# DOD 收口修复：D8 / D3 + 文档漂移（D4/D6 附带项）

日期 2026-10-31 · 分支 `feature/fix-inbound-parity` · 执行人 DodFixD3D8Docs（fullstack 派单，PM 提交前）
来源复核：`dod-D7-D8-D9.md`（D8 CONDITIONAL）、`dod-D3-D4-D5.md`（D3 CONDITIONAL）、`dod-D1-D2-D6.md`（D6 文档漂移两行）
改动面：`crates/xray-frame`、`crates/xray-buf`、`crates/xray-proxy-tuic/src/server.rs`（reason 字符串）、`crates/xray-proxy-anytls/src/server.rs`（reason 字符串）、`CLAUDE.md` §3.5.4 两行、本报告。**未 commit（PM 提交）**。

---

## D8 — 14 处未登记 Instant/SystemTime 站点 + 两 crate 无时钟门 → **PASS**

### 处置总表（14 站点 = 4 接线 udf Clock + 10 登记 allow+reason）

| 站点 | 处置 | 依据 |
|---|---|---|
| `xray-frame/src/context.rs:35` 指纹启动锚 | **接线**：`SystemTime::now()` → `SystemClock.now_system()`（udf Clock 合同面；SystemClock/Clock 原已 import，零签名变更、零调用方影响） | 唯一性锚走合同面即可，无需可注入 |
| `xray-frame/src/reload.rs:190` 暂存件命名纳秒 | **接线**：同上 → `SystemClock.now_system()`（新增 `use skeleton::clock::{Clock as _, SystemClock}`；`SystemTime` import 移除） | 唯一性锚走合同面即可 |
| `xray-frame/src/contract_assert.rs:291/302` L4 夹具真超时测量 | **接线**：`Instant::now()` → `SystemClock.now_instant()`（测量须**真实**单调时——被注入的 clock 可能是冻结 MockClock，拿它测真实等待是同义反复；SystemClock = 合同的系统钟实现，两义兼得）；`Instant` import 移除 | 夹具测量本体即真实墙钟 |
| `xray-frame/src/deadline.rs` ×9（:192/219/221/231/236/272/279/297/307；复核报告 ×11 计入了 ：180 文档注释行） | **登记**：`impl Budget` 与 `impl BudgetDeadline` 各 1 条 item 级 `#[allow(clippy::disallowed_methods, reason=…)]`（共 2 条覆盖 9 站点）。理由：本件即仓内唯一 tokio 虚拟钟取时桥——tokio `advance`/`timeout_at` 只收 `tokio::time::Instant`，接 udf Clock 即作废虚拟推进测试语义（713x6 裁决 tokio 面不迁）；墙钟语义已有 `Budget::wall(Clock)` 出口；std Instant 臂为跨源构造漂移的防御兜底（源与起点同源构造，实际不可达） | 桥本体，豁免即台账 |
| `xray-buf/src/alloc.rs:44` 池惰性清扫时戳锚 | **登记**：`fn now_ms` 上 1 条 fn 级 allow+reason。理由：非时限语义（60s 清扫周期去重锚）；xray-buf **零 skeleton 依赖**（Cargo.toml 仅 bytes/tokio/parking_lot/thiserror/tracing），接 udf Clock = 新增依赖（红线）；crate 内唯一时钟站点 | 分配器内时戳，派单预判项 |

### 门洞补齐（两份 clippy.toml）

- `crates/xray-frame/clippy.toml`：`disallowed-methods` 增 3 条——`std::time::Instant::now` / `tokio::time::Instant::now` / `std::time::SystemTime::now`（写法对齐 16 协议 crate 样板；tokio 条指名 `deadline::Budget::tokio()` 为唯一登记桥）。
- `crates/xray-buf/clippy.toml`：同 3 条（措辞按数据面零时钟纪律，SystemTime 条指名 alloc.rs now_ms 为现存唯一登记点）。

### 测试区配套（禁令生效后 tests/ 编译单元会被点名，按仓内惯例豁免）

- `xray-frame/src/lib.rs`：`#![cfg_attr(test, allow(clippy::disallowed_methods))]`（罩 src 内单元测试；惯例同 xray-buf/xray-proxy-* lib.rs，注释注明集成测试另行豁免）。
- `tests/{compat_caps,compat_fallback,conn_scope,deadline_contract,reload_rollback,shutdown_wiring}.rs` ×6：文件顶 `#![allow(clippy::disallowed_methods)]` + 惯例注释（集成测试为独立编译单元，cfg_attr(test) 不覆盖；样板 `xray-app-router/tests/router_parallel_build.rs`）。合计罩住 7 处测试区时钟站点（src/compat.rs:297 + tests/ 6 处）。

### 探针证据（新增禁令真的会报错）

```
$ cargo clippy -p xray-frame --test zz_probe_clock_gate -- -D warnings   # 临时违规文件（三种裸取时各一处）
error: use of a disallowed method `std::time::Instant::now`
error: use of a disallowed method `std::time::SystemTime::now`
error: use of a disallowed method `tokio::time::Instant::now`
CLIPPY_EXIT=101
# 探针文件已删除；复跑 cargo clippy -p xray-frame --tests → Finished, exit 0
```

---

## D3 — 闸数权威口径 + 5 处豁免票锚 → **PASS**

### B1：豁免票锚（bd 23vrp）

新票 **`Xray-core-rust-23vrp`**（P3，label framework+gap）：《Budget 补 timer-arm 面：tuic/anytls 生产 tokio-Instant 豁免迁移跟踪》——迁移条件 = Budget 补绝对时刻/重置锚 API（保 tokio 虚拟推进语义），补齐后 5 站点迁移并删豁免；epic 99ifi D3。
reason 更新（语义零变化，仅补锚）：

- `xray-proxy-tuic/src/server.rs` ×2（udp_assoc_direct / udp_assoc_dispatch 的 fn 级 allow）：`…（待 Budget 补 timer-arm 面）` → `…（迁移跟踪 bd 23vrp：Budget 补 timer-arm 面后迁）`
- `xray-proxy-anytls/src/server.rs` ×1（handle_conn）：追加 `（Budget timer-arm 迁移跟踪 bd 23vrp）`

### B2：闸数权威口径 = **54/54 产品 crate**（可机械复现）

```bash
python -c "
import subprocess, glob, json, os
gates = sorted(p.replace(os.sep,'/') for p in glob.glob('crates/*/clippy.toml'))
meta = json.loads(subprocess.check_output(['cargo','metadata','--no-deps','--format-version','1'], stderr=subprocess.DEVNULL).decode())
members = sorted(p['name'] for p in meta['packages'])
harness = [m for m in members if m in ('xray-integration-tests','xray-benchmarks')]
print(f'crates/*/clippy.toml (产品 crate 闸数) = {len(gates)}')
print(f'workspace 成员数 (cargo metadata --no-deps) = {len(members)}')
print(f'无闸成员 = {harness} (纯测试/基准 harness crate，不在 16 协议运行面)')
missing = [m for m in members if ('crates/'+m+'/clippy.toml') not in gates and m not in harness]
print(f'产品 crate 缺闸 = {missing if missing else \"无 (54/54)\"}')"
```

实测输出（本日）：

```
crates/*/clippy.toml (产品 crate 闸数) = 55
workspace 成员数 (cargo metadata --no-deps) = 56
无闸成员 = ['xray-benchmarks', 'xray-integration-tests'] (纯测试/基准 harness crate，不在 16 协议运行面)
产品 crate 缺闸 = 无 (54/54)
```

**口径权威表述**：
- 产品 crate 闸 = **54/54**（56 个 workspace 成员 − 2 个 harness 成员 `tests`(xray-integration-tests)/`benches`(xray-benchmarks)——纯测试/基准，无 PluginContext 运行面，不在 L3 闸范围；DOD 字面「56/56」按此口径不可达也无需达）。
- 盘面 `crates/*/clippy.toml` = **55 份**：54 份属产品 crate，第 55 份 = `crates/udf-frame/clippy.toml`——udf-frame 是 workspace `exclude`（根 Cargo.toml :88）的**独立仓工作副本**，自带闸、自受其仓 CI 管辖，不计入本仓闸数（dodB 报告「54 份（udf-frame 工作副本不计）」与此一致；W0 的「55/55」系把 udf 工作副本计入所致，a5r4j 的「56/56」系按 workspace 成员数误读）。

---

## C — 文档/注释漂移（两处，均按 D4/D6 复核结论对齐）

1. `crates/xray-frame/src/contract_assert.rs` 头注：「接线现状（bd 2zi1o…仅 vless/ss/trojan 3 crate…其余 13 crate 框架原语夹具）」→「**16/16**，D4 复核 2026-10-31：全部接真实插件实例（Default → register → bring_up → shutdown → 报告内容断言 `stopped==["<crate>"]` 钉死空报告边界，bd wkemq 已偿）」；条款表第 6 行同步（声明态 部分 → 已实现）。
2. `CLAUDE.md` §3.5.4 仅两行（不重写整节）：
   - 「配置 lint 阶段编排」行：`⏳ 留仓至 P4（bd d95us）` → `✅ 已归一化（bd bx7my 上浮 udf skeleton::lint；udf n539c W7）`，现状列对齐 lint.rs 窗口层实态（pub use + 一行转调族）。
   - 「中央 match 臂」行：`BTreeMap + 显式注册…明确不用 xray-frame::PluginRegistry` → `INBOUND_CTORS/OUTBOUND_CTORS 纯数据源切片（BTreeMap 已删）→ arm_registry.rs 装配成 xray-frame::PluginRegistry`，备注列注明旧「明确不用」判定已被 W1 表实现收口作废（arm_builders/mod.rs 选型节已改写）。行号引用按 pzjpj 锚点纪律只写符号名。

---

## 验收

### code-level

| 门 | 命令 | 结果 |
|---|---|---|
| 全仓 clippy 宽门 | `cargo clippy --workspace --all-targets -- -D warnings`（`CARGO_TARGET_DIR=target-dodFix`） | **exit 0**（Finished dev in 2m29s，含全部新禁令与登记） |
| 两 crate scoped clippy | `cargo clippy -p xray-frame -p xray-buf --all-targets -- -D warnings` | **exit 0** |
| 双 crate lib 测试 | `cargo test -p xray-frame -p xray-buf --lib` | **xray-buf 207 passed / 0 failed；xray-frame 93 passed / 0 failed**（exit 0） |
| fmt | `cargo fmt --all -- --check` | **本票改动文件全部干净**；D5 姊妹票在飞文件 state_loop.rs:1281 的 fmt 脏点已由 DodFixD5 修复并回执（`cargo fmt -p xray-frame -- --check` exit 0）；终态全树残留 diff **仅** `crates/udf-frame/**`——workspace exclude 的独立仓工作副本（红线禁碰），`cargo fmt --all` 按 path 依赖扫到它，其格式归 udf 仓自身 CI 管辖（workspace 成员树面 = 干净：`cargo fmt -p xray-frame -p xray-buf -p xray-proxy-tuic -p xray-proxy-anytls -- --check` → **exit 0**） |

### end-to-end

1. **新口径复现**：上方 B2 命令 + 实测输出（54/54 产品 crate、55 份盘面闸、两 harness 成员、缺闸=无）。
2. **禁令生效探针**：D8 节探针证据（三变体各一条 `use of a disallowed method` → `-D warnings` exit 101 → 探针删除 → 复绿 exit 0）。

## 红线遵守

未 commit；未触碰 `crates/udf-frame`、`vendor/`、`protos/`、`tests/`（根）、`.github/`、`xray-transport-tcp/register.rs`；零新增依赖（接线全用既有 import 面：SystemClock/Clock 原已在两文件作用域或属 udf 既有件）；豁免全部带 reason 一句话裁决。收尾动作：`target-dodFix` 整目录删除（独立编译目录，含全部产物与缓存）。
