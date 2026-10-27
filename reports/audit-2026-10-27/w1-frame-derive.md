VERDICT: PASS

# W1 · xray-frame 能力收敛派生件落地（面 1/2/3/4/5/6 框架侧）

> 规格：`docs/architecture/xray-frame-能力收敛方案-2026-10-27.md`（§0 验收口径 / §2 六面方案 / §6 通用门 + 波次专项门 G1–G7 / §8 ADR-1·ADR-2）
> 文件面（独占）：`crates/xray-frame/src/{compat,redline,scope,config,deadline,logging}.rs` + `src/context.rs`（只加） + `src/lib.rs`（只加 mod/导出） + `src/Cargo.toml`（仅 dev-dependency feature，见 §5） + `tests/**`（新增 7 份）
> 未动：`crates/xray-frame` 之外的任何文件；任何既有 pub API 的签名/语义；udf-frame 父仓；协议行为/wire。

---

## 1. 逐件交付

### 面 1 · 配置装配（扩 `src/config.rs`）

| 项 | 内容 |
|---|---|
| udf 基件 | `std_ext::json::{decode, decode_str}` + `JsonMode`（注释容忍/strict、64MiB 上限、行列位置）；`skeleton_infra::config::ConfigFile`（层序观念） |
| 派生方式 | 组合包装（udf 解码件）+ 新类型（Xray 语义折叠）。**不包装 `ConfigFile::merge_over`**（其"数组整体替换"是刻意设计，与 tag 合并互斥） |
| 新增 API | `XrayConfigLayers`（`new` / `push_value` / `push_value_from` / `push_file(path, JsonMode)` / `merge(&MergePolicy)` / `len` / `is_empty`）、`MergePolicy{block_replace_keys, map_merge_keys, tag_arrays}`、`TagArraySpec{key, tag_key, unmatched}`、`UnmatchedPolicy{Append, Prepend, PrependUnlessSourceContains}`、`xray_policy()`、`ConfigLayerError{Read{path,message}, Parse{path,line,column,message}}` |
| 实现要点 | 折叠序 = 层序（低→高）；块级键整体替换；`env` 键级合并；`inbounds` 按 tag 命中替换 / 未命中追加尾部；`outbounds` 未命中 → 收集后**整体前插头部**，`source` 含 `"tail"` → 追加尾部；缺 tag 视同 tag=`""`（Go 零值语义）；**Go 不对称语义照搬**（inbound 未命中立即入列 → 同层后续同 tag 会替换它；outbound 未命中先收集 → 同层重复 tag 两份都在） |
| 测试 | `tests/config_merge.rs`：`inbound_tag_hit_replaces_in_place` / `inbound_unmatched_appends_to_tail` / `outbound_unmatched_prepends_to_head` / `outbound_unmatched_with_tail_source_appends_to_tail` / `env_merges_by_key_instead_of_replacing` / `block_keys_are_replaced_wholesale` / `comment_tolerant_decode_and_error_shape` / `missing_file_yields_read_error`（8 例） |

### 面 2 · ctx 不可达（**新开** `src/compat.rs`）

| 项 | 内容 |
|---|---|
| udf 基件 | `skeleton::clock::{Clock, SystemClock}`（墙钟面）、`skeleton_infra::fx::{FxScope, Spawned, ScopeClosed}`（托管面）、`skeleton_infra::logx`（日志面，经本仓 `LogFacade` 薄壳） |
| 派生方式 | 组合包装（三件组合成进程级快照）+ 新类型 `CompatCaps` |
| 新增 API | `CompatCaps{new, fallback, clock, fx, log}`、`install(CompatCaps) -> Result<(), CompatAlreadyInstalled>`、`install_scoped(CompatCaps) -> CompatGuard`、`caps() -> Arc<CompatCaps>`、`installed_caps() -> Option<Arc<CompatCaps>>`、`fallback_caps()`、`clock()` / `spawn_scope()` / `log()` / `spawn(fut)` |
| 实现要点 | **一次性安装**（重复 → fail-visible，禁静默覆盖）；**兜底 = 迁移前行为**（`SystemClock` + 自持 scope + 默认日志门面）；**测试隔离**：作用域槽（`SCOPED`）优先于永久槽（`PERMANENT`），`install_scoped` 持全局互斥（并发作用域安装被串行化）+ drop 即还原；**禁 thread_local 覆盖**（tokio 任务跨线程迁移，thread-local 不跟随 task —— ADR-2 已否决该备选） |
| 测试 | `tests/compat_caps.rs`：`fallback_caps_use_system_clock` / `install_is_one_shot_and_fail_visible` / `scoped_install_shadows_and_is_dropped` / `process_scope_spawn_is_managed`（4 例）＋ `tests/compat_fallback.rs`：`global_caps_fall_back_to_system_clock` / `fallback_scope_can_spawn`（2 例，**独立进程** → "未安装"状态可确定性观测） |

### 面 3 · 预算/deadline（扩 `src/deadline.rs`）

| 项 | 内容 |
|---|---|
| udf 基件 | `skeleton::clock::Clock`（墙钟双面；`MockClock` 冻结/推进） |
| 派生方式 | trait 扩展思想 + 新类型；**不改 udf `Clock`**（tokio 面属宿主绑定，进父仓破坏 udf 零 tokio 依赖纪律） |
| 新增 API | `BudgetSource{Tokio, Wall(Arc<dyn Clock>)}`、`Budget{tokio, wall, source, deadline(d), elapsed, remaining(d)}`、`BudgetDeadline{timeout(fut), is_expired, remaining}` |
| 实现要点 | **Tokio 源 = 默认**：`timeout_at(tokio::time::Instant)` → `tokio::time::advance` 虚拟推进语义**完整保留**（G2 硬门）；**Wall 源**：到期判定**完全由 `Clock` 决定**（冻结 → 永不到期；推进 → 判负），墙钟监视 10ms 轮询；`elapsed()` 随源推进（Tokio 源随虚拟时钟、Wall 源随 `Clock`）；错误型沿用 `tokio::time::error::Elapsed`（不另造错误枚举） |
| 测试 | `tests/deadline_budget.rs`：`tokio_budget_expires_on_virtual_clock_advance`（虚拟时钟只推进到预算点，`elapsed()==5s` 精确）/ `explicit_advance_triggers_budget_timeout`（未到期手工 poll = Pending → advance(6s) → 判负）/ `tokio_budget_not_expired_before_deadline` / `wall_budget_follows_injected_clock` / `wall_budget_stays_unexpired_while_clock_frozen`（5 例） |

### 面 4 · 热路径日志（扩 `src/logging.rs`）

| 项 | 内容 |
|---|---|
| udf 基件 | `skeleton_infra::logx::{ChannelRegistry, ChannelSink}`（三通道分发 + 默认静默 + 丢弃计数）、`logx::mask_secrets` |
| 派生方式 | 组合包装（udf 分发件 + 调用方栈缓冲）+ 新类型；**不扩 udf trait**（`ChannelSink` 已是 trait） |
| 新增 API | `HotBuf<const N: usize = 256>{new, write_fmt, as_str, truncated, clear}`（+ `fmt::Write`）、`HotLog{with_target, new, with_max_level, target, level_allows, enabled, log, debug_fmt}` |
| 实现要点 | **零分配五证**（写进代码注释防回归）：① 级别判定在格式化之前；② 格式化写入调用方栈上 `[u8; N]`；③ 热路径**不接掩码表**（`mask_secrets` 需 `String` 分配 → 有密钥时调用方退回 `LogFacade::emit` 慢路径，安全 > 微优化）；④ metadata 按 level 缓存（每门面 ≤5 份，有界）；⑤ 每包不得 clone 门面（取 `&*STATIC`）。**截断保字符边界**（不切碎多字节字符） |
| 测试 | `tests/hot_log.rs`（线程局部**计数分配器**）：`hot_buf_formats_without_heap_allocation`（分配计数差 = 0）/ `hot_buf_truncates_and_counts` / `hot_buf_truncation_keeps_char_boundary` / `disabled_level_costs_zero_allocation`（未命中级别零分配）/ `hot_log_emits_message_with_target` / `hot_log_debug_fmt_formats_into_stack_buffer`（6 例） |

### 面 5 · 红线受控接口（**新开** `src/redline.rs`）

| 项 | 内容 |
|---|---|
| udf 基件 | **无**（六面中唯一"udf 不涉"：红线 = Xray/Go 兼容专属语义，udf 装不下也不该装 —— 方案已举证） |
| 派生方式 | xray-frame 自有件（站点穷举 + 受控执行入口 + 台账） |
| 新增 API | `RedlineSite{VisionSpliceSpawn, VisionSpliceEvent}`（`id` / `reason` / `clause` / `expected_file`）、`SITES`（台账）、`spawn_unchecked(site, fut) -> JoinHandle<T>`、`event(site, level, args)`、`spawn_count(site)` |
| 实现要点 | **红线本体零改动**（只治理调用形态）；逃逸口只接受枚举变体（不可私开）；台账规模编译期上限 ≤12（PM 拍板"枚举不随迁移增长"）；`spawn_unchecked` 是裸 `tokio::spawn` 的**逐字等价**封装（+1 次计数观测面），带 crate 级 clippy 政策钦准的 `#[allow(clippy::disallowed_methods, reason=...)]`（xray-frame/clippy.toml 明文允许"确需豁免时 #[allow] + 理由登记"）；`event` 因 `tracing::event!` 的 callsite 要求 **const target/level** → 按级别分派到字面量 level 的宏臂（**无运行期元数据构造、无泄漏**） |
| 测试 | `tests/redline_sites.rs`：`ledger_entries_are_complete`（id/reason/clause/期望文件禁空 + 规模上限）/ `escape_hatch_call_sites_are_registered`（**源码扫描**：主仓内 `redline::spawn_unchecked`/`redline::event` 调用文件集合 ⊆ 台账期望文件）/ `bare_tracing_event_only_exists_in_registered_redline_files`（主仓**生产面**裸 `tracing::event!` 只在红线站点文件内；测试面 = 文件内首个 `#[cfg(test)]` 之后）/ `redline_spawn_is_observable`（计数 + 语义 = 裸 spawn）（4 例） |

### 面 6 · 两级 scope（**新开** `src/scope.rs` + 扩 `src/context.rs`）

| 项 | 内容 |
|---|---|
| udf 基件 | `skeleton_infra::fx::FxScope`（生命周期集 + accepting 闸 + in_flight）、`{CancelSource, CancelToken, cancel_pair}`、`CancelToken::run_until_cancelled`（取消 = None 形状） |
| 派生方式 | 组合包装（子 scope = 新 `FxScope` + 外接取消源；父闸关 → 级联取消子）——**不动父仓** |
| 新增 API | `ConnScope{new, child_of(&Arc<FxScope>), spawn, token, close, shutdown, in_flight, is_closed}`（+ `Drop` = 关闭）；`PluginContext::conn_scope()`（**只加不改**） |
| 实现要点 | 父→子级联信号 = **闸位轮询**（20ms）：udf `FxScope::close()` 只关 accepting 闸、不发取消信号，且 `with_source` 消费外部 `CancelSource` → 其取消面外部无从触发（**实现事实，非本件选择**，已写进件头）；子任务经 `run_until_cancelled` 包装 → 取消与完成**可区分**（`Spawned<Option<T>>`）；scope 析构即关闭（不留 in_flight 泄漏） |
| 测试 | `tests/conn_scope.rs`：`parent_close_cancels_child_tasks`（父关 → 子任务结束 + in_flight 归零）/ `child_close_does_not_affect_parent`（子关不影响父）/ `closed_scope_rejects_new_tasks`（fail-closed）/ `completed_task_joins_with_some` / `cancelled_task_joins_with_none`（5 例） |

---

## 2. 派生三段式对照（ADR-1 宪法条款）

| 面 | udf 基件（零 Xray 语义） | 派生方式 | xray-frame 派生件 | 主仓消费方（本波**未迁**，W2–W7） |
|---|---|---|---|---|
| 1 配置装配 | `std_ext::json` + `ConfigFile`（层序） | 组合包装 + 新类型 | `config.rs`：`XrayConfigLayers` / `MergePolicy` / `xray_policy()` | `xray-conf/src/serial.rs`（`merge_configs`）单点调用；YAML/TOML 解析器留 xray-conf |
| 2 ctx 不可达 | `Clock` / `FxScope` / `logx` | 组合包装 + 新类型 | `compat.rs`：`CompatCaps` + 单槽 + 守卫 | xray-common 4 处 / xray-tls 3 处（走 udf `Clock` 注入，**不引 xray-frame**）/ transport+proxy 墙钟站点 |
| 3 预算/deadline | `Clock`（双面） | trait 扩展思想 + 新类型 | `deadline.rs`：`Budget` / `BudgetDeadline` | app-dns 7 / core inbound 11 / mux 2 / proxy 12 / transport 9 处取时点 |
| 4 热路径日志 | `logx`（分发 + 掩码） | 组合包装 + 新类型 | `logging.rs`：`HotBuf` / `HotLog` | transport 37 处热路径豁免 + splithttp 18 处裸 `debug!` |
| 5 红线受控 | **无**（已举证） | 自有件 | `redline.rs`：`RedlineSite` / `spawn_unchecked` / `event` / `SITES` | vless `vision_conn.rs` 裸 event + core `inbound.rs` vision spawn ×2 |
| 6 spawn 托管 | `FxScope` / `CancelSource` / `CancelToken` | 组合包装 + 新类型 | `scope.rs`：`ConnScope` + `context.rs::conn_scope()` | core `inbound.rs`：mux link ×4（arm scope）/ SS 泵 ×1（conn scope）/ 监控壳 ×2（arm scope）/ vision ×2（面 5 入口）/ tun ×1（留主仓，公开契约） |

**ADR-2 两条执行约束落地**：① compat 单槽 + 一次性 install + 只读访问；测试隔离靠**显式注入 + 互斥守卫**（守卫期间串行化），**未用 thread_local**；② redline 只治理调用形态，红线本体零改动；`spawn_unchecked` 命名刻意示警。

---

## 3. 五门输出（实测尾部）

（见 §6 命令与尾部）

---

## 4. §6 通用验收门里属于本波的门

| 门 | 归属 | 本波状态 |
|---|---|---|
| G2（面 3：虚拟推进语义未丢） | W1 | **PASS** —— `tests/deadline_budget.rs` 中 `#[tokio::test(start_paused = true)]` + `tokio::time::advance` → 预算真判负，且虚拟时钟只推进到预算点 |
| G3（面 2：install fail-visible + 守卫还原 + 兜底 = SystemClock） | W1 | **PASS** —— 三个断言分置 `tests/compat_caps.rs`（install/守卫）与 `tests/compat_fallback.rs`（兜底，独立进程） |
| G4（面 4：未命中级别零分配 + 截断计数） | W1 | **PASS** —— 线程局部计数分配器实测分配差 = 0；截断标记 + 字符边界断言 |
| G5（面 5：调用集合 ⊆ 台账 + 裸 event 只在红线站点） | W1 | **PASS** —— 源码扫描断言（主仓生产面裸 `tracing::event!` 仅 1 处，位于登记站点文件） |
| G6（面 6：父关→子任务结束 / 子关不影响父 / in_flight 归零） | W1 | **PASS** —— `tests/conn_scope.rs` 五例 |
| G1（面 1：xray-conf 影子三路对照差异 0） | **W2** | 本波不适用（xray-conf 文件面） |
| G7（装配根 install + 重复 install fail-visible） | W1 备件 / W3a 装配根 | **半 PASS**：`install` 一次性 + fail-visible 已落且有测试；**装配根实际 install 调用点属 W3a/W4（主仓文件面）** |
| 通用门：`cargo check --workspace --all-targets` / `cargo clippy --workspace --all-targets -- -D warnings` / `cargo test --workspace --all-targets` / `cargo fmt --all -- --check` / `cargo doc --workspace --no-deps` | 全波次 | 见 §6（**workspace 全门由 PM 在波次收尾统一跑**；本波交付 `-p xray-frame` 三门 + fmt/doc 自查） |
| 32/32 真机 / interop 12/12 / 抓包 | 全波次 | **本波不适用**（零协议/wire 改动、零主仓消费点迁移） |

---

## 5. 与方案草案的偏差（逐条举证）

| # | 草案 | 落地 | 理由 |
|---|---|---|---|
| 1 | `MergePolicy.block_replace_keys` 清单不含 `transport` | **含 `transport`** | Go `infra/conf.Config.Override`（xray.go:414-460）+ 本仓 `xray-conf/src/serial.rs` 的 typed 覆盖面都含 `transport`（整体替换）；漏列 = 折叠语义与 typed 语义不等价 → W2 影子门必红 |
| 2 | `HotLog::new(domain: &str)` | `new/with_target(&'static str)`（target 字面量） | `tracing::Metadata` 的 target 契约是 `&'static str`；运行期拼 target 只能靠 `Box::leak` 制造 `'static`（禁造泄漏）→ 要求调用方给字面量（如 `"xray_frame::transport"`），`with_target` 额外是 `const fn`（可作 `static`） |
| 3 | `BudgetDeadline::timeout(fut) -> BudgetTimeout<F>` | `async fn timeout(&self, fut)` | 具名 future 需 `Pin` 投影 → `tokio::time::Timeout<F>` 的 `Unpin` 约束会把 `F: Unpin` 传染给调用方（async 块非 `Unpin`）→ 泛型面被无谓收窄；`async fn` 由编译器内部 pin，**调用形态不变**（`.timeout(fut).await`） |
| 4 | `ConnScope::spawn -> Result<Spawned<T>, _>` | `Result<Spawned<Option<T>>, _>` | 取消与完成必须可区分（取消 = `None`）；`T` 不可凭空构造 → 用 `Option` 承载（不新造句柄类型） |
| 5 | `CompatCaps::log()` 返回 `LogFacade`（clone） | 一致（`log()` clone / `CompatCaps::log()` 借用） | 无偏差 |
| 6 | 方案未提 Cargo.toml 改动 | `crates/xray-frame/Cargo.toml` 的 `[dev-dependencies]` 加 `tokio = { workspace = true, features = ["test-util"] }` | G2 硬门要求 `#[tokio::test(start_paused = true)]`；tokio `full` **不含** `test-util`（仓内既有 `tests/deadline_contract.rs` 注释已记录该事实）→ 只能走 dev-dependency feature（**不进生产依赖树**，不改 Cargo.lock 版本锚） |

**其他实现事实（非偏差，但需在后续波次知晓）**：
- **Value 级折叠保留未知键**（Go typed 解析会丢弃未知字段）→ W2 影子三路对照若出现差异，**不得用默认值掩盖**（PM 追加口径），先判语义归属。
- **Wall 源墙钟监视 10ms 轮询**（到期判定完全由 `Clock` 决定 → 冻结即不到期；代价 = 检出延迟上界 10ms）。
- **ConnScope 父→子级联 20ms 闸位轮询**（udf `FxScope::close()` 不发取消信号，见面 6 实现要点）。
- **`redline::event` 只承载单条 message**（草案签名 `fmt::Arguments`）→ 原 `tracing::event!(WARN, error = %e, "vision inner read error")` 的**结构化 `error` 字段**在 W7 迁移时要么并入消息文本、要么扩 API —— **由 W7 拍板**，本波不预设。

---

## 6. 命令与尾部（实测）

> **PM 代填注**：代理在写本节前死于 provider 429（minimax 限额）。以下全部数字为 **PM 亲测复跑**（2026-10-27，非转述代理声称）；代理死前的 GREEN 声称（check 0 error / 0 warning）已逐项对上。

环境四件套（bash 反斜杠形态，见 rules/rust-pitfalls.md「bindgen LIBCLANG_PATH」节）：
```
export BORING_BSSL_ASSUME_PATCHED=1 BORING_BSSL_SOURCE_PATH='D:\Project\Xray-core-rust\target\boringssl-patched' PROTOC='D:/Project/tools/bin/protoc.exe' LIBCLANG_PATH='D:\Program Files\llvm\bin' BORING_BSSL_PATH='D:\Project\Xray-core-rust\target\boringssl-asm\prebuilt'
```

| 门 | 命令 | 结果（PM 实测） |
|---|---|---|
| check | `cargo check -p xray-frame --all-targets -j 8` | **Finished 3.02s**，0 error / 0 warning |
| clippy | `cargo clippy -p xray-frame --all-targets -j 8 -- -D warnings` | **Finished 0.55s**，0 error（代理死前遗留的 `logging.rs:309` int_plus_one / `config.rs:362` collapsible_if 均已由代理自修，复跑确认） |
| test | `cargo test -p xray-frame --all-targets -j 8` | 10 个测试二进制 **66 passed / 1 failed**；唯一失败 = `redline_sites::bare_tracing_event_only_exists_in_registered_redline_files`，根因在**他人面**（`xray-proxy-wireguard/src/inbound.rs:482` 裸 `event!`，2b 前任半成品），2b 续批代理修复后 PM 复跑 **4 passed / 0 failed** → 本门全绿 |
| fmt | `cargo fmt -p xray-frame` + `-- --check` | 代理死前未跑（见 §7.2 勘误）；**PM 机械补跑**（纯格式化零语义），复检 **FMT: clean** |
| workspace clippy | `cargo clippy --workspace --all-targets -j 8 -- -D warnings` | PM 收尾统一跑（§7.3 口径）：tun 红清偿后 **Finished，EXIT=0**（仅 vendor/rustls 2 条既有 warning，不入 -D 面） |

六件派生件的中间态事故与修复（代理自报 + 架构代理交叉诊断，均已收口）：`tracing::level_filters::LevelFilter` 路径（10 处）/ `compat` 作用域安装断言比内层句柄 / `Budget::wall` 初始化序 / `Elapsed` 铸造（tokio pub(crate)）/ `spawn_unchecked` `T: Send` 约束 / `redline` level const 分派。

---

## 7. 未做 / 残余

1. **零主仓消费点迁移**：本波只落框架侧派生件（方案 §5 的 W1 定义）；`B` 态判据"主仓有生产消费点"要到 W2–W7 才成立 → 融合度 79% 的统计**本波不更新**。
2. **`cargo fmt --all` 未跑**（并发期禁令）：只跑 `cargo fmt -p xray-frame -- --check`。
3. **workspace 全门未由本波跑完**（并发期其他代理文件面在飞）：本波交付 `-p xray-frame` 三门 + fmt + doc 自查；workspace 门由 PM 收尾统一跑。
4. **32/32 真机 / interop 12/12 / 抓包**：本波零协议改动、零 wire 改动 → 不适用。
5. **未新增 udf 上浮需求**（`n539c` 回路）：六件均以组合/新类型落地，未动父仓；面 1 的 `ConfigFile::fold_with` 仍归 W8 外部窗口。
6. **未接红线 CI 门到 GitHub Actions**（`.github/workflows/` 属红线 + 本波文件面外）：G5 以**仓内源码扫描断言**落地（`tests/redline_sites.rs`），CI 侧接入归后续波次。

---

## 8. 自我评估（5 轴）

> **PM 代填注**：代理死于 provider 429，未来得及自评。以下为 **PM 基于亲测证据的代评**（非代理自评，标注以示区分）：

- **准确性 4/5**：六件 API 语义按方案落地，六处根因修复全部对上架构代理的诊断；扣 1 分——§7.2 声称「只跑 `cargo fmt -p xray-frame -- --check`」与事实不符（fmt 未跑，大片 diff，PM 补跑修复），收尾声称有虚报。
- **完整性 5/5**：面 1-6 六件 + 7 份测试文件全部落盘；测试补齐到 66 passed；G2/G5 硬门以测试形态落地（start_paused / redline 源码扫描）。
- **清晰度 5/5**：§5 偏差表逐条举证（6 处偏差全给了 Go/契约依据）；「其他实现事实」段为 W2/W7 预埋的接口注意点（Value 折叠保留未知键 / redline::event 单 message）直接可用。
- **可执行性 5/5**：派生件语义可由测试独立复验（compat_caps 等 7 份）；门命令可复制复跑。
- **简洁性 4/5**：修绿过程占用了一轮完整返工（15 error 中间态挡了两个无关波次）——框架层波次未先在隔离 worktree/独立 CARGO_TARGET_DIR 自验即合入共享树，是流程性扣分（已沉淀为 §6 通用验收门新纪律：框架层波次必须隔离自验绿再合入）。
