# DOD 机械复核：D1 / D2 / D6（战役 epic `99ifi`）

> 复核人：DodD1D2D6 · 日期：2026-10-31 · 分支：`feature/fix-inbound-parity` · HEAD `65733da7`
> 性质：**只读复核**，未改任何产品代码。所有命令可复现（见 §4）。
> 构建环境：`BORING_BSSL_PATH=target/boringssl-asm/prebuilt`（预构建 BoringSSL，跳过 cmake）+ `PROTOC`/`LIBCLANG_PATH`；测试用独立 `CARGO_TARGET_DIR=target-DodD1D2D6`。

---

## 总裁决

| DOD | 判据 | VERDICT |
|---|---|---|
| **D1** | 生产装配主路 = xray-frame PluginRegistry | **PASS** |
| **D2** | L5 装配门三条契约测试（缺 deps→Err / 成环→Err / 缺段→Err） | **PASS**（附 zhvi3 双主路口径注意项） |
| **D6** | 七面 7/7（注册表族 BoundedRegistry + lint 编排上浮，老 API grep 0 命中） | **CONDITIONAL**（7 面机制全部落地；条件项 = 配置装配面以 bd 77r0q NO-GO 裁决收口，非迁出收口 + CLAUDE.md §3.5.4 两行台账未同步代码现状） |

---

## D1 — 生产装配主路 = xray-frame PluginRegistry

**VERDICT: PASS**

### 表现状：fn 表已「降级为纯数据源」，BTreeMap 已删

`crates/xray-core/src/arm_builders/mod.rs`：
- 两张 `BTreeMap<&'static str, fn>` 已**删除**，改为 `pub(crate) static INBOUND_CTORS: &[(&str, InboundCtor)]`（:213）与 `OUTBOUND_CTORS: &[(&str, OutboundBuilder)]`（:277）——`&'static` **纯数据源切片**，零查找逻辑；文档原文：「原为 `BTreeMap` 裸 fn 表(与生产装配面的框架注册表两套并存)。现改为**纯数据源** …由 `crate::arm_registry` 装配成 xray-frame `PluginRegistry`」。
- 实测键数：INBOUND_CTORS **20 键**（socks/mixed/vless/trojan/vmess/http/dokodemo-door/dokodemo/shadowsocks/hysteria/hysteria2/anytls/tuic/naive/wireguard/dns/loopback/blackhole/freedom/**tun**）+ OUTBOUND_CTORS **18 键** = **38 构造器**（`dokodemo-door` 与 `dokodemo` 双键别名；tun 自 bd 7y07s 起入站同表）。

### 唯一查表入口

`crates/xray-core/src/arm_registry.rs`：
- `ARM_REGISTRY`（LazyLock 构造）= xray-frame `PluginRegistry`：38 条 `ArmEntry`（`Arc<dyn Plugin>` 载荷 `ArmCtor`）注册；构造时即跑一遍 `reg.start_order()` deps 门（:186 段：`// deps 门：生产路径走一遍拓扑排序`）。
- **唯一查表函数** `lookup_ctor`（:210 附近）：`ARM_REGISTRY.get(key)? → plugin.payload()? → downcast_ref::<ArmCtor>()`；`lookup_inbound_builder`（:218）/ `lookup_outbound_builder`（:226）是仅有的两个出口。

### 生产调用点（各恰 1 处，无第二构造路径）

| 方向 | 调用点 | 证据 |
|---|---|---|
| inbound | `crates/xray-core/src/inbound.rs:4166` `let Some(ctor) = crate::arm_registry::lookup_inbound_builder(ib.entry.kind.as_str()) else { warn+skip }` | 未命中显式失败（不静默构造） |
| inbound UDS/transport | 同一 `ctor` 的 `uds_stream`/`uds_transport` 槽（inbound.rs:4191-4192、:4361、:4421）——UDS 形态**查同一张表**，无内联 match / 白名单 | `spawn_unix_inbound` 收入口查得的 `ctor` 传参 |
| outbound | `crates/xray-core/src/outbound.rs:694` `if let Some(builder) = crate::arm_registry::lookup_outbound_builder(ob.entry.kind.as_str())` … else `Err(BuildError::Unsupported)`（:708） | 未命中显式失败 |

**grep 迁出探针（当前 HEAD 实跑）**：
- `grep "lookup_inbound_builder|lookup_outbound_builder|INBOUND_CTORS|OUTBOUND_CTORS|BTreeMap" crates/xray-core/src` → 命中仅：`arm_registry.rs`（定义+测试）、`inbound.rs:4166`、`outbound.rs:694`、`arm_builders/{mod,inbound,tests}.rs`（纯数据源 + 文档 + 测试 import）；`BTreeMap` 仅存于**文档注释**（arm_builders/mod.rs:16 描述旧设计、inbound.rs:3099 描述 BoundedRegistry 底座），**零代码命中**。
- `grep "match ib.entry.kind|match ob.entry.kind" crates/xray-core/src` → **0 命中**（`entry.kind.as_str()` 只作 lookup / `arm_plugin_ctx` 实参）。
- `grep "fn lookup_|LazyLock" crates/xray-core/src/arm_builders` → 无 `fn lookup_*`（仅 `intern_protocol_kind` 的名称驻留表，非构造路径）。
- `grep "UDS_SUPPORTED_PROTOCOLS" crates/` → **0 代码命中**（仅 tests.rs:163 一行注释留痕「原白名单已删」）。

### 硬门证据（双写对照）

`dual_write` 测试（`arm_registry.rs` tests）：三路对拍（PluginRegistry 查表 vs 数据源直查 vs 测试内独立硬编码期望），配置变体 3 × 协议 37 → **比较 88 次，差异 0 处**（本轮实跑输出见 §3 T2b）。

历史验证链：bd `di8wy`（CLOSED）close 记录载明双写硬门 PM 复跑确认 + 32/32 + interop 12/12 + `--no-default-features`/Linux 床 clippy 全绿；报告 `reports/audit-2026-10-26/w1-1a-registry.md`（实现）与 `w1-verify.md`（十门全绿收口）。

**口径注意（zhvi3，不降级 D1）**：CLAUDE.md §3.5.4 双主路口径——默认可执行文件走**生产主路**（`Config::build() → start_full`，出站经 arm_builders 表 + `register_outbounds` 填 `SimpleOhm`）；xray-cli `framework-assembly` 为**目标主路**（未进默认构建）。两条主路由 `crates/xray-core/tests/assembly_path_equivalence.rs` 差异台账契约测试锁定（已知差异四类登记，未知差异即红）。D1 判据「构造必经 PluginRegistry」在**两条主路上都成立**（同一张 `arm_registry` 表）。

---

## D2 — L5 装配门三条契约测试

**VERDICT: PASS**（三条测试全部存在、实跑全绿；附一条口径注意项）

### 测试清单（缺依赖→Err / 成环→Err / 缺段→Err）

| # | 情形 | 测试名 | 位置 |
|---|---|---|---|
| 1 | 缺依赖→Err(MissingDep) | `l5_gates_fail_visible_at_assembly` ① | `crates/xray-core/src/arm_registry.rs:542`（断言 :574） |
| 2 | 成环→Err(CyclicDep) | `l5_gates_fail_visible_at_assembly` ② | 同上（断言 :611） |
| 3 | 缺配置段→Err | `l5_gates_fail_visible_at_assembly` ③（`PluginConfig::section` 缺段断言 "section missing"，:614-619）+ `missing_section_fails_fast_not_global_fallback` | `crates/xray-core/src/tests_config_parity.rs:263` |
| 框架侧同源 | 缺依赖 / 成环 | `missing_dep_fails_at_assembly`（:88）/ `two_node_cycle_reports_both_names`（:102）+ 有界时限变体 `two_node_cycle_returns_within_bounded_time`（:120） | `crates/xray-frame/tests/plugin_registry.rs` |

三条情形均在 `start_order()` / `build(ctx)` 阶段（启动前）报 `Err`，无半启动态。生产注册表装配时也真跑该门（`build_arm_registry` 内 `reg.start_order().expect(...)`，当前 38 条目 deps 全空 = 门恒过）。

### 实跑输出（本轮实跑，独立 CARGO_TARGET_DIR）

T1（xray-frame）与 T2/T3（xray-core）输出见 §3 附录。

### 口径注意项（zhvi3 关键事实，需 PM 知悉，不否决 D2）

CLAUDE.md §3.5.4 载明（bd `zhvi3` CLOSED 留档）：**fail-fast 门目前只在框架路（assembly）生效**——生产主路 `register_outbounds` 对「协议不支持/配置解析失败」是 `warn + skip`（静默丢弃）；生产路启动期硬门 = 入站构造/绑定失败 + `xray-conf` build 期 `ValidationStage`（两路共用）。即「配置写错 → 启动即报」在默认可执行文件上对**出站配置错误**不完全成立。D2 的机械判据（三条 Err 测试存在且绿）**满足**；该行为缺口是已登记的双主路已知差异（差异台账契约测试锁住），归 PM 决定是否另开票。

---

## D6 — 七面 7/7

**VERDICT: CONDITIONAL**（7 面全部有落地证据；条件 = 面④按 NO-GO 裁决收口 + 两行文档台账漂移）

| # | 面 | 状态 | 证据（file:line @ `65733da7`） |
|---|---|---|---|
| 1 | **JSON 工具壳** | ✅（P1-9，战役前已归一） | `xray-conf/src/json.rs:14` `use std_ext::json::{self, JsonMode}`；4 个 `decode_json*` 全部一行转调 udf（:36/:44/:51/:56/:61），零本地解码实现 |
| 2 | **配置 lint 阶段编排** | ✅ 上浮（bd `bx7my` CLOSED 2026-10-29；udf `n539c` W7 CLOSED） | `xray-conf/src/lint.rs` 头注：「编排机制在 udf `skeleton::lint`，本文件只留 Go 语义那一层…本文件由 335 行降为窗口层」；`pub use skeleton::lint::LintStage`（:27），`register_stage`/`clear_stages`/`registered_stages`/`post_process` 全部一行转调 `skeleton::lint::*`；grep `OnceLock|RwLock|Mutex|HashMap|BTreeMap` 于本文件 → 仅 `#[cfg(test)] TEST_LOCK`（测试串行化）与文档，零注册表机制代码 |
| 3 | **日志 Handler 分发 + 双写** | ✅（P1-10-b，战役前已归一） | `xray-common/src/log/mod.rs:100` `static CHANNELS: LazyLock<ChannelRegistry>`（udf `logx` 单入口，general/access/dns 三通道）；`HANDLERS` 仅存文档注释（:5/:97「旧 HANDLERS 无差别扇出…已收敛」），零代码符号 |
| 4 | **配置装配** | ✅ 按 ADR 收口（**非迁出收口**） | 双轨定案：①udf `ConfigFile<C>` 接管判 **NO-GO**（bd `77r0q` CLOSED：「3 条差异属 Xray 语义…影子比对后不进产」；CLAUDE.md §3.5.4 同步）；②生产分层装载已切 **xray-frame 派生件**：`xray-conf/src/serial.rs:40` `use xray_frame::config::{XrayConfigLayers, xray_policy}`，`merge_configs`（:195-208）逐文件取 Value 进 `XrayConfigLayers` 按 `xray_policy` 折叠，「影子三路对照差异 0」（tests/config_file_shadow.rs W2 组钉住）；typed `override_with` 存续消费者 = xray-cli `convert pb`（文档载明，非死副本）。与 ADR-1 裁决一致（MergePolicy 归 xray-frame，与 udf `merge_over` 数组整体替换语义并存可见） |
| 5 | **注册表族** | ✅ | inbound：`xray-core/src/inbound.rs:3101` `slots: RwLock<BoundedRegistry<String, InboundSlot>>`（cap=1024 Reject fail-closed；六方法全 O(log n)：`get/remove/insert`，:3151/:3159/:3168/:3179/:3207/:3218；`InboundSlot` 无 tag 字段 :3072-3075；xiuvr3a 19 键×3 变体行为矩阵测试在树）；outbound：`xray-app-dispatcher/src/default.rs:2042` `type HandlerRegistry = BoundedRegistry<String, Arc<dyn DispatchHandler>>`（SimpleOhm = 生产出站表，:2060-2063 注明 proxyman 无 Manager 类型）；`copy_handler_registry` 全仓 **0 命中**（已删，UdfConsume.md 记录迁移） |
| 6 | **中央 match 臂** | ✅（T4.2 phase 4 + bd 7y07s） | 见 §D1：唯一构造路径 = `arm_registry` 查表；UDS/tun 9 臂已收进同一张 `INBOUND_CTORS`（20 键含 tun；`uds_stream`/`uds_transport` 槽承载 5+4 协议，tests.rs:162-188 钉覆盖矩阵）；`match ib.entry.kind`/内联白名单 0 命中 |
| 7 | **任务托管 / 停机编排** | ✅（按 §3.5.6 三分类口径） | 停机：`instance.rs:342 close()` → `shutdown_bridge::close_features`（udf `ShutdownCoordinator`：5s 超时 + panic 隔离 + 逐组件 outcome 报告，:338-341/:374）+ `arm_scopes.close_all_reverse()`（:364，连接级级联取消）；托管：dispatcher 后台任务迁 `xray_frame::compat::ManagedScope`（commit `02a00cca`「后台任务托管迁 ManagedScope + 停机 watcher——删双份账本」；default.rs:22 `use xray_frame::compat::ManagedScope`）；①类站点走托管口（PluginContext fx / ManagedScope）、②类逐站 `#[allow(disallowed_methods, reason=...)]` 登记（§3.5.6 = D7 同判据，D7 对账归姊妹票复核） |

### 老 API grep 0 命中（迁出探针，本轮实跑）

| 探针 | 命令（cwd=仓根） | 结果 |
|---|---|---|
| 旧 BTreeMap fn 表 | `grep "BTreeMap" crates/xray-core/src` | 0 代码命中（仅 arm_builders/mod.rs:16、inbound.rs:3099 两处文档注释） |
| 旧查表函数残留于 arm_builders | `grep "fn lookup_" crates/xray-core/src/arm_builders` | 0 命中 |
| 旧内联 match 分派 | `grep "match ib.entry.kind|match ob.entry.kind" crates/xray-core/src` | 0 命中 |
| UDS 白名单 | `grep "UDS_SUPPORTED_PROTOCOLS" crates/` | 0 代码命中（1 行测试注释留痕） |
| 旧手写注册表拷贝 | `grep "copy_handler_registry" crates/` | 0 命中 |
| 日志旧扇出 | `grep "HANDLERS" crates/xray-common/src` | 0 代码命中（2 处文档注释描述旧机制已收敛） |
| lint 本地注册表机制 | `grep "OnceLock|RwLock|Mutex|HashMap|BTreeMap" crates/xray-conf/src/lint.rs` | 仅 `#[cfg(test)] TEST_LOCK` + 文档，0 生产机制代码 |
| inbound 线性扫 | `grep "\.iter\(\)\.any|\.position\(|\.retain\(" crates/xray-core/src/inbound.rs`（InboundRuntime 六方法） | InboundRuntime 方法体全为 `get/insert/remove` 树查；命中的 `position/retain` 均属无关面（HTTP 头解析、UDP 会话表自清） |

### D6 的两条条件项（报告，不修）

1. **面④是「裁决收口」不是「迁出收口」**：udf `ConfigFile<C>` 未接管（NO-GO，bd 77r0q），生产分层装载走 xray-frame `XrayConfigLayers`/`xray_policy` 派生件。按 ADR-1 归属判据（含 Xray 语义 → 归 xray-frame，udf 装不下不硬塞）这是**合规终态**；但若 PM 对「七面 7/7」的字面预期是「全部迁 udf」，则面④应记为「按裁决豁免」而非「迁出完成」——D6 verdict 据此给 CONDITIONAL。
2. **CLAUDE.md §3.5.4 两行台账漂移（文档 vs 代码）**：lint 行仍写「⏳ 留仓至 P4（bd d95us）」而代码已上浮（bd bx7my）；中央 match 臂行仍写「BTreeMap + 显式注册…**明确不用** `xray-frame::PluginRegistry`」而 W1 后代码恰恰**用的就是** PluginRegistry（arm_builders/mod.rs 表实现选型节已改写）。建议 PM 排一次文档同步（本票禁改，未动）。

---

## 3. 测试实跑输出（附录，本轮实跑 @ `65733da7`）

**T1 — `cargo test -p xray-frame --test plugin_registry`**（冷编 18.6s + 跑 0.00s）：

```
running 7 tests
test capacity_is_fail_closed ... ok
test duplicate_name_rejected ... ok
test start_order_reverses_single_dep ... ok
test independent_plugins_keep_registration_order ... ok
test missing_dep_fails_at_assembly ... ok
test two_node_cycle_reports_both_names ... ok
test two_node_cycle_returns_within_bounded_time ... ok
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

**T2 — `cargo test -p xray-core --lib arm_registry`**（冷编 3m35s + 跑 0.01s；含 D1 双写硬门）：

```
running 5 tests
test arm_registry::tests::unknown_protocol_is_absent ... ok
test arm_registry::tests::l5_gates_fail_visible_at_assembly ... ok      ← ①MissingDep ②CyclicDep ③缺段 三情形
test arm_registry::tests::registry_keyspace_is_direction_prefixed_and_unique ... ok
test arm_registry::tests::inbound_loopback_dual_write_matches ... ok
test arm_registry::tests::dual_write_diff_rate_is_zero ... ok
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 502 filtered out
```

**T2b — 双写硬门 `--nocapture` 复跑**（当前 HEAD 数字：协议 37 / 比较 88，较 W1 时 35/86 增量为 tun 入表 + dokodemo 别名键）：

```
test arm_registry::tests::inbound_loopback_dual_write_matches ... ok
[dual-write] 配置变体 3 × 协议 37 → 比较 88 次，差异 0 处
test arm_registry::tests::dual_write_diff_rate_is_zero ... ok
test result: ok. 2 passed; 0 failed; 505 filtered out
```

**T3 — `cargo test -p xray-core --lib missing_section`**：

```
running 1 test
test tests_config_parity::missing_section_fails_fast_not_global_fallback ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 506 filtered out
```

## 4. 可复现命令清单

```bash
# 环境（每次 cargo 前导出）
export CARGO_TARGET_DIR="D:/Project/Xray-core-rust/target-DodD1D2D6"   # 独立编译目录，复核完可整目录删除
export BORING_BSSL_PATH="D:/Project/Xray-core-rust/target/boringssl-asm/prebuilt"
export BORING_BSSL_ASSUME_PATCHED=1
export BORING_BSSL_SOURCE_PATH="D:/Project/Xray-core-rust/target/boringssl-patched"
export PROTOC="D:/Project/tools/bin/protoc.exe"
export LIBCLANG_PATH="D:/Program Files/llvm/bin"

# D2：三条契约测试实跑
cargo test -p xray-frame --test plugin_registry
cargo test -p xray-core --lib arm_registry        # 含 l5_gates_fail_visible_at_assembly + dual_write 硬门
cargo test -p xray-core --lib missing_section     # tests_config_parity::missing_section_fails_fast_not_global_fallback

# D1/D6 迁出探针（期望 0 代码命中）
grep "match ib\.entry\.kind\|match ob\.entry\.kind" -r crates/xray-core/src
grep "fn lookup_" -r crates/xray-core/src/arm_builders
grep "UDS_SUPPORTED_PROTOCOLS" -r crates/
grep "copy_handler_registry" -r crates/

# bd 票面（read-only）
export BD_IGNORE_SCHEMA_SKEW=1
bd show 99ifi   # epic OPEN
bd show di8wy xiuvr n539c bx7my 77r0q zhvi3   # 均 CLOSED，close reason 载证据
```

## 5. 自评（5 维）

| 维 | 分 | 依据 |
|---|---|---|
| 准确性 | 5/5 | 每条裁决均有 file:line / grep 实跑 / 测试实跑；未跑项明示 |
| 完整性 | 5/5 | D1 唯一性 + D2 三测试实跑 + D6 七面逐面 + 探针 8 条 + 口径注意项与条件项齐全 |
| 清晰度 | 4/5 | 表格化；zhvi3 双主路口径需回读 CLAUDE.md §3.5.4 才有完整语境 |
| 可执行性 | 5/5 | §4 命令清单可直接粘贴复跑 |
| 简洁性 | 4/5 | 证据优先；面④的「裁决收口 vs 迁出收口」辨析占篇幅但必要 |
