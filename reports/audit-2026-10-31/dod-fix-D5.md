# D5 缺口修复报告（dodFixD5）

- 日期：2026-10-31 · 执行：DodFixD5（fullstack 子代理）· 分支 `feature/fix-inbound-parity`（未 commit，PM 提交）
- 缺口来源：`reports/audit-2026-10-31/dod-D3-D4-D5.md` §D5（FAIL 11/13：testing 零消费 + ConfigFile 无生产调用点）
- 工作目录：`D:/Project/Xray-core-rust` · 独立 target：`target-dodD5`（战役结束已整目录删除）

---

## 裁决摘要

**D5 达标。** 原 13 项口径：**13/13**（11 项既有生产消费 + testing 族接线完成 + ConfigFile 按既有 NO-GO 裁决如实归零有据）；bd 77r0q 的 11 族重裁口径：**11/11**（ConfigFile/config-toml 已移出分母，testing 已接线）。

---

## 改了什么 / 为何

### ① testing 族：接真实消费点（判定：接消费点比归零更正确）

**为何接**：`skeleton_infra::testing::{TestStore, ScriptedRuntime}` 的靶面（reducer 逐动作断言 / 效果回收断言 / 非法迁移负例 / 脚本化回灌）与主仓 xray-frame `state_loop` 的装配状态环**严丝合缝**——该 reducer 环（`AssemblyRoot` = LifecycleReducer+AuditReducer 的 combine 组合）此前只有经真 LoopFx 解释器的全环 Probe 测试，效果序列、id 单调、相位门负例、审计分片派生**均无独立于解释器的契约钉**。这不是造消费方凑数，是补真实缺口；替身全部白拿 udf 基件（§3.5.2），零复制语义。

**改动（2 文件，纯测试面+feature 门，生产代码零改动）**：
1. `crates/xray-frame/Cargo.toml`：dev-dep `udf-skeleton-infra` features 加 `"testing"`（resolver 2：只进测试构建，生产构建 feature 集不变）。
2. `crates/xray-frame/src/state_loop.rs` tests 模块新增 4 测试（用例⑮-⑱，约 +180 行）：
   - `test_store_pins_start_effect_contract`（**TestStore**）：Start 效果序列逐条断言——依赖序 `BringUp×N`+`FinishStart`、`EffectId` 从 0 单调、CollectRuntime 只回收不解释（相位停 Starting）。
   - `test_store_pins_outcome_stop_and_audit_trail`（**TestStore**）：驱动层回灌同款 `StartOutcome` → Running/账本相位；`Stop` 恰发一条 `BeginStop`（id 跨动作连续=3）；审计分片对同动作流的 kind+plugin 序逐条断言。
   - `test_store_pins_phase_gate_rejections`（**TestStore**）：相位门负例——Empty 相位 Start/Stop 拒、Registered 相位 StartOutcome 拒（rejections 单调、相位不变、rejected 记痕）；拒绝路径零效果由后续合法 Start 的效果序断言背书。
   - `scripted_runtime_pins_outcome_feedback_round_trip`（**ScriptedRuntime**，`#[tokio::test]`）：脚本 `Script::Emit(StartOutcome)` 经 FxScope 回灌 → 相位 Running + started/审计推进——驱动协议「效果出→解释器回灌→相位迁移」的确定性复现，零真实插件。
3. `parse_mock`（MockJson/MockSqlDialect/MockMarkdown）：**如实计 0**。硬依据：全仓（src+tests）零 `JsonPort`/`SqlDialectPort`/`MarkdownPort` 采用方（grep 0 命中）——三个替身是解析**端口**的 mock，主仓无端口接缝可注入；接缝需先把生产代码改为端口依赖 = 新抽象，违本票「禁新抽象」；且主仓亦无手写解析替身可替换（xray-conf 走 `std_ext::json` 自由函数，非端口 trait）。已落 `CLAUDE.md` §3.5.2 白拿清单行。

### ② ConfigFile：归「不切的硬依据」分支（判定依据：裁决已在案，且依据充分）

**事实校正（对任务书前提）**：任务书下发依据的审计快照（tree @65733da7）之后，树面已演进——**bd `77r0q`（P2，2026-10-26 CLOSED）已对 ConfigFile 接管做出 NO-GO 裁决，硬依据已落 `CLAUDE.md` §3.5.4 配置装配台账行**，且 PM 已据此把 D5 分母重裁为 11 族（剔除 config-json/config-toml）。裁决依据（bd 77r0q 原文要点，PM 复核 udf 源码）：
1. 三条差异中两条是 **Xray/Go 特有语义**（tag 感知数组合并+outbounds prepend；JSON 注释容忍）——按 §3.5.4「机制上浮、内容留仓」**本就应留主仓**；
2. udf `merge_over` 数组整体替换是**刻意设计**（fail-visible，config.rs 文档原文判否 config-rs 式吞并/下标合并）——不是缺口，不应改父仓；
3. 净收益≈0：折叠与 Xray 需求冲突、读文件被自解析替代。

**本票补充核实（不重复写入台账）**：
- `ConfigFile::file_layer` 实现为裸 `serde_json::from_slice`（udf config.rs 直接读源核实）——切换即丢注释容忍，与影子测试钉住的 `shadow_comment_tolerance_gap` 一致。
- **W2 生产切换其实已发生但走的是另一条 ADR-1 派生路线**：`xray-conf::serial::merge_configs` 生产路径 = `confloader::load_value`（`std_ext::json` Tolerant 解码 = udf 基件生产消费，D5 第 13 项 ✅）→ xray-frame `XrayConfigLayers::merge(xray_policy())`（tag 感知折叠 = D5 第 2 项 compose 所在 crate 的派生件）→ typed 装配。即：融合目标已通过派生路线达成，`ConfigFile<C>` 整件无零语义接入口——「不切」是正确工程判断，不是放弃。
- 端到端复验：`cargo test -p xray-conf --test config_file_shadow` **10/10 全绿**（真实夹具配置装载；typed 域差异 0、注释容忍差异钉住、失败注入钉住、W2 未知键保留钉住）——生产装载行为不变的直接证据。

**CLAUDE.md 改动（1 处）**：§3.5.2 白拿清单行更新——`testing::{TestStore, ScriptedRuntime}` 标注已消费（本票接线）；`MockEnv` 实体归属勘正（住 `skeleton::config` 契约层）；`parse_mock` 归零理由落档。§3.5.4 配置装配行 NO-GO 裁决（bd 77r0q）已在案，**未重复写入**。

---

## 证据（全部一手实测，target-dodD5）

| 项 | 命令 | 结果 |
|---|---|---|
| 测试（受影响 crate 全目标） | `cargo test -p xray-frame` | 全目标 0 failed；lib 97 passed（含新增 4 测试，state_loop 18/18）；20+ 集成目标全绿；doctests ok |
| clippy | `cargo clippy -p xray-frame --all-targets -- -D warnings` | exit 0（Finished，零告警） |
| fmt（本票文件） | `cargo fmt -p xray-frame -- --check` | exit 0 |
| fmt（全树） | `cargo fmt --all -- --check` | 残留 diff **仅** `crates/udf-frame/**`（workspace `exclude` 的独立仓工作副本，本票红线禁碰、非本票造成、零 xray 侧文件） |
| E2E 配置装载 | `cargo test -p xray-conf --test config_file_shadow` | 10/10 ok（真实夹具装载，生产行为不变） |
| 新测试实跑 | `cargo test -p xray-frame --lib state_loop` | `test_store_pins_start_effect_contract ... ok` / `test_store_pins_outcome_stop_and_audit_trail ... ok` / `test_store_pins_phase_gate_rejections ... ok` / `scripted_runtime_pins_outcome_feedback_round_trip ... ok`（18 passed; 0 failed） |

## D5 新口径逐项（13 项原口径）

| # | 项 | 状态 | 一句话证据 |
|---|---|---|---|
| 1 | memgov BoundedRegistry | ✅（既有） | dispatcher `new_handler_registry()` 生产字段（audit 表既有，未动） |
| 2 | compose combine! | ✅（既有） | xray-frame `state_loop.rs` AssemblyRoot 两处 combine! |
| 3 | **testing 族** | ✅（**本票接线**） | TestStore×3 + ScriptedRuntime×1 真实消费于 `state_loop` reducer 契约测试；parse_mock 子件如实归零（无端口接缝，§3.5.2 落档） |
| 4 | **ConfigFile** | ✅（**如实归零有据**） | bd 77r0q NO-GO 已闭 + §3.5.4 台账在案（两条 Xray 语义留仓 + udf 刻意设计不可覆盖 + 净收益≈0）；生产融合经 std_ext::json + xray-frame 折叠达成（影子 10/10 背书）；77r0q 口径下该项已移出分母 |
| 5-13 | pool/fx/shutdown/logx/cache/retry/scheduler/clock/json | ✅（既有） | audit §D5 表 1-13 既有 call-chain，未动 |

→ **13/13**（原口径）；**11/11**（bd 77r0q 重裁口径）。

## 剩余风险 / 交接

1. **fmt 全树残留**：`cargo fmt --all -- --check` 会扫进被 workspace `exclude` 的 udf-frame 工作副本（cargo-fmt 对目录内 path 依赖的遍历行为），残留 diff 全在 udf-frame。CI 侧 udf 由拉料步骤重新生成、不受本地工作副本影响；树面收口时按红线对该目录「另计」即可（姊妹票 DodFixD3D8Docs 已知会并确认）。
2. `parse_mock` 归零判定依赖「主仓无端口采用方」这一 grep 事实——若未来某 crate 引入 `skeleton::parse` 端口，白拿清单行需随之解除归零标注。
3. 分母口径两套并存（13 原口径 / 11 族重裁）——D5 收口归档时建议以 bd 77r0q 的 11 族为准并在 DOD 文档统一写法。
4. 未 commit（PM 提交）；`target-dodD5` 已删除（编译产物零残留）。

## 新增/修改文件

- 改 `crates/xray-frame/Cargo.toml`（dev-dep features +testing）
- 改 `crates/xray-frame/src/state_loop.rs`（tests 模块 +4 测试，用例⑮-⑱）
- 改 `CLAUDE.md`（§3.5.2 白拿清单行 1 处）
- 新增本报告 `reports/audit-2026-10-31/dod-fix-D5.md`
