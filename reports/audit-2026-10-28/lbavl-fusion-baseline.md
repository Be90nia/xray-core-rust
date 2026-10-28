VERDICT: PASS

**一句话**：五轴**同法**基线 = **65.7%**（`7b336a12`，票面 70% 的取数点）→ **82.1%**（HEAD `f288377c`，`feature/fix-inbound-parity`）。票面 70% 是它自己那**五个轴值**的等权均值取整（`(100+75+57+58+55)/5 = 69.0`），与本脚本同法基线差 4.3pt，**差值全部来自两处分母口径**（契约族 12 vs 14、依赖接地 43 vs 56），与树状态无关。

- 测量锚：`HEAD = f288377c`（branch `feature/fix-inbound-parity`）；基线快照 = `git archive 7b336a12` 展开树。
- 方法：**纯静态只读扫描**（`crates/*/src/**/*.rs`，剥注释 + brace 级剥 `#[cfg(test)]` 模块）、根 `Cargo.toml` members 解析、per-crate `clippy.toml` 文本判定。零构建、零测试、零 clippy 实跑。
- 脚本：`reports/audit-2026-10-28/fusion_baseline.py`（320 行，无第三方依赖）。

---

## 1. 五轴定义与数据来源（引文档原文，不自创）

五轴取自 `bd lbavl`（P3，audit/metrics）原始五轴，逐轴回指治理文档的**原文条款**：

| # | 轴 | 定义原文（出处） | 脚本操作化 |
|---|---|---|---|
| 1 | 方向纪律 | `CLAUDE.md:103`「**地基/骨架不引 Xray 类型**（提炼判据：零 xray 类型 = 全泛型/trait）」+ `CLAUDE.md:81`「**依赖方向单向**：硬装血肉 → 骨架 → 地基」 | udf 三 crate `src/**/*.rs` 剥注释后搜 `xray`（不分大小写）+ 三份 `Cargo.toml` 剥注释后的**真实依赖条目**含 xray → 违规数。**零容忍判据**：违规 0 = 100%，违规 >0 不折算百分比 |
| 2 | 契约族使用 | `docs/architecture/xray-frame-深度融合战役计划-2026-10-26.md:16` D5「**udf 契约族 13/13**：memgov/compose/testing/ConfigFile 有生产调用点」+ `CLAUDE.md` §3.5.2 第 5 条白拿清单（池化/异步停机/日志/缓存重试调度/配置/契约替身） | 族矩阵 = `reports/audit-2026-10-25/udf-xray-fusion.md` §2.2 的 **14 行**（族名 → 探针正则）；「taken」= 非 udf crate 的**生产面**（剥注释 + 剥 cfg(test)）命中 ≥1 次 |
| 3 | §3.5.4 七面 | `CLAUDE.md:109` §3.5.4「归一化面（主仓已自造、但属通用件 → **必须提炼回 udf**，主仓不得留副本）」表 **7 行**：JSON 工具壳 / 配置 lint 阶段编排 / 日志 Handler 分发+双写 / 配置装配 / 注册表族 / 中央 match 臂 / 任务托管·停机 | 逐面一个静态探针（见 §2.3）；计分：已迁 = 1，部分 = 0.5，未动 = 0（沿用 10-25/10-27 报告的同一计分，非本次新造） |
| 4 | 依赖接地 | `CLAUDE.md:81` 依赖方向单向（消费方必须声明依赖）+ `bd lbavl`「依赖接地 25÷(25+18)=58%」 | 根 `Cargo.toml` members（56）中，`Cargo.toml` **生产依赖面**（切到 `[dev-dependencies]`/`[build-dependencies]` 之前）声明 `udf-skeleton`/`udf-skeleton-infra`/`udf-std-ext` 的 member 数 |
| 5 | L3 静态闸 | `docs/architecture/xray-frame-强约束插件模型-2026-10-23.md:88`「**L3 lint 层**：per-crate `clippy.toml` 路径限定 `disallowed-methods`/`disallowed-macros` + 存量点 `#[allow]` 豁免并写理由」 | members 中「存在 `clippy.toml` 且含 `disallowed-methods=` 或 `disallowed-macros=`」的占比 |

> 口径纠正注记（`bd lbavl` notes，2026-10-27 10:00 用户口供）：这五轴只量 **udf 地基层接地率**，已被降级为「地基层指标」；主结论口径是 **功能融合度 = (A+B)/功能面总数**（`docs/architecture/xray-frame-能力收敛方案-2026-10-27.md:27`，四态定义在同文件 §0.1 表）。本票按契约只交五轴基线，14 面四态**本次不重测**（见 §5 局限 10）。

---

## 2. 五轴实测值与计算方法

### 2.1 总表（HEAD `f288377c`）

| # | 轴 | 定义（出处见 §1） | 分子 / 分母 | 百分比 | 复跑命令 |
|---|---|---|---|---|---|
| 1 | 方向纪律 | 地基/骨架不引 Xray 类型 + 依赖单向 | 违规 **0**（udf 源码 46 文件搜 `xray` = 0；3 份 udf `Cargo.toml` 依赖条目 = 0） | **100.0%** | `python reports/audit-2026-10-28/fusion_baseline.py`（轴 1 行） |
| 2 | 契约族使用 | D5「udf 契约族…有生产调用点」 | **11 / 14 族** | **78.6%** | 同上，`[轴2 契约族明细]` |
| 3 | §3.5.4 七面 | §3.5.4 表 7 行 | **5.5 / 7**（已迁 5 + 部分 1） | **78.6%** | 同上，`[轴3 七面明细]` |
| 4 | 依赖接地 | 声明 udf-* 生产依赖的 member | **32 / 56**（生产面口径 32/54） | **57.1%**（生产面 59.3%） | 同上，轴 4 行 / `--json` 的 `axes[3]` |
| 5 | L3 静态闸 | per-crate `clippy.toml` 含 disallowed 条目 | **54 / 56**（生产面口径 54/54） | **96.4%**（生产面 100.0%） | 同上，轴 5 行 / `axes[4]` |
| — | **总分** | 五轴**等权**均值（票面同一算法） | `(100.0+78.6+78.6+57.1+96.4)/5` | **82.1%** | 脚本末行 |

### 2.2 轴 2 明细（14 族，`taken` = 有生产调用点）

| 族 | 状态 | 生产面 files / occ |
|---|---|---|
| `FxScope`（spawn 托管） | taken | 63 / 305 |
| `ShutdownCoordinator`（停机编排） | taken | 3 / 9 |
| `logx`（ChannelRegistry/ChannelSink/mask_secrets） | taken | 4 / 19 |
| `skeleton::clock`（Clock/SystemClock/MockClock） | taken | 26 / 73 |
| `std_ext::scheduler` | taken | 5 / 13 |
| `std_ext::json` | taken | 3 / 12 |
| 池族 ThreadPool/PooledThreadPool/MemoryPool | taken | 2 / 16 |
| `PoolBase`/`PoolManaged` | taken | 2 / 8 |
| `ConfigPort`/`EnvSource` | taken | 1 / 7 |
| `std_ext::{hash,id}` | taken | 2 / 12 |
| `memgov`（BoundedRegistry/CountingAllocator/LeakGuard） | taken（**基线为未取**） | 3 / 9 |
| `std_ext::compose`（combine） | **未取** | 0 / 0 |
| `testing::{TestStore,ScriptedRuntime}` | **未取** | 0 / 0 |
| `skeleton_infra::config::ConfigFile<C>` | **未取**（`XrayConfigLayers` 是**派生件**，按 §面板 1 刻意**不**包装 `ConfigFile::merge_over`） | 0 / 0 |

`memgov` 取件证据：`crates/xray-core/src/inbound.rs:3123`（`slots: RwLock<BoundedRegistry<String, InboundSlot>>`）、`crates/xray-app-dispatcher/src/default.rs:2048`（`type HandlerRegistry = BoundedRegistry<String, Arc<dyn DispatchHandler>>`）、`crates/xray-frame/src/audit.rs:52`。`CountingAllocator`/`LeakGuard` 仍零生产消费（族口径按"整族有消费点"计入，见局限 4）。

### 2.3 轴 3 明细（§3.5.4 七面）

| 面 | 状态 | 探针与证据 |
|---|---|---|
| #1 JSON 工具壳 | **已迁** | `crates/xray-conf/src/json.rs` 剥注释后含 `std_ext::json`；本地解析器已删（file 头：机制已上浮 udf，留 Xray 语义薄壳） |
| #2 配置 lint 阶段编排 | **未动（PM 裁决留仓）** | `crates/xray-conf/src/lint.rs` 全套自持；`lint.rs:22-29` 记 bd `d95us` 裁决「留仓至 P4 + 补标准标注」→ 判 0 但**不是遗漏** |
| #3 日志 Handler 分发/双写 | **已迁** | `crates/xray-common/src/log/mod.rs` 剥注释后含 `ChannelRegistry`（三通道单入口） |
| #4 配置装配 | **已迁**（基线为部分） | `crates/xray-conf/src/serial.rs:205,211,213`：`merge_configs` → `XrayConfigLayers::new()` / `push_value_from` / `merge(xray_policy())`；`Config::override_with` 生产调用点 0（仅 `serial.rs` 内置测试 + `tests/config_file_shadow.rs`），**残留死 pub API 未删**（clean cutover 未收尾，见局限 9） |
| #5 注册表族 | **已迁**（基线为未动） | 两半均 udf `BoundedRegistry`：`xray-core/src/inbound.rs:3123` + `xray-app-dispatcher/src/default.rs:2048`（`SimpleOhm.tagged`/`shadow` 两表） |
| #6 中央 match 臂 | **已迁** | 构造表 `crates/xray-core/src/arm_registry.rs`（或基线的 `arm_builders/mod.rs`）+ 入口 `inbound.rs:4247` / `outbound.rs:694` 调 `lookup_*_builder` |
| #7 任务托管/停机 | **部分（0.5）** | `Instance::close` 经 `ShutdownCoordinator`（`xray-core/src/shutdown_bridge.rs`，注释剥离后 2 处代码命中）；`FxScope` 生产消费 305 处；**残余裸 `tokio::spawn(` 148 处**（基线 209） |

### 2.4 轴 5 交叉表

| | 有 udf 依赖 | 无 udf 依赖 |
|---|---|---|
| **有闸** | 32 | 22 |
| **无闸** | 0 | 2（`tests`、`benches`，非生产 member） |

---

## 3. 与 70% 口径的差异说明

### 3.1 70% 是什么

票面写「加权 70%（=结构分 3.5/5）」并给出五轴值 100 / 75 / 57 / 58 / 55。**它的等权均值 = 69.0 → 取整 70%**（结构分 3.5/5 = 70%，两条来源同数）。所以 70% **不是**独立测出的第二套数，就是这五个票面百分比的算术均值。

### 3.2 同法复测基线（`7b336a12`，票面取数点）

| 轴 | 票面值 | 本脚本同法值 | 采信 |
|---|---|---|---|
| 方向纪律 | 100% | n/a（快照无 udf 工作副本，见局限 2）→ 按票面/10-25 报告实测 0 违规计 **100%** | 一致 |
| 契约族使用 | 75%（9/12） | **71.4%（10/14）** | **分母不同** |
| §3.5.4 七面 | 57% | **57.1%（4.0/7）** | 一致（精确复现） |
| 依赖接地 | 58%（25÷43） | **44.6%（25/56）** | **分母不同** |
| L3 静态闸 | 55% | **55.4%（31/56）** | 一致（精确复现） |
| **等权总分** | **70%**（69.0） | **65.7%** | **差 4.3pt = 两处分母** |

### 3.3 两处分母差异的来源（都可证伪地核过）

1. **契约族分母 12 vs 14**：票面 12；同段文字又称「12 契约族中 9 族」但矩阵列了 **14 行**（`udf-xray-fusion.md` §2.2）；D5 又写「13/13」。同一概念三个分母。本脚本取**矩阵 14 行**（唯一可枚举复现的口径），`taken` 判定条件与矩阵一致。
2. **依赖接地分母 43 vs 56**：票面 `25÷(25+18)` 的 43 无法复原——同刻交叉表是 both 19 / udf-only 6 / gate-only 12 / neither 19，任何组合都得不出 43（`reports/audit-2026-10-27/fusion-measure.md:39` 已独立得出同一结论）。本脚本统一 **member 全员 56**（另附生产面 54 口径），基线同法 25/56。

### 3.4 结论：70% → 82.1% 不能直接相减

- **正确对照**：同法基线 **65.7%（7b336a12）→ 82.1%（f288377c）**，Δ = **+16.4pt**。
- 若拿票面 70% 直接比 HEAD 82.1%，会把 4.3pt 的口径差算成进展 → **高估**。故本报告把 70% 保留为「票面历史锚」，并在 §6 明确禁止混比。

### 3.5 基线 → HEAD 的增量来自哪里（逐项可核）

| 轴 | Δ | 驱动（实测） |
|---|---|---|
| 方向纪律 | 0 | 两端都 0 违规 |
| 契约族 | +1 族（71.4→78.6） | `memgov` 由未取 → 取件（inbound slots / dispatcher HandlerRegistry / audit 环） |
| §3.5.4 七面 | +1.5 面（57.1→78.6） | 面 4 配置装配 部分→已迁（`serial.rs` 切 `XrayConfigLayers`，W2）；面 5 注册表族 未动→已迁（两半 `BoundedRegistry`） |
| 依赖接地 | +7 crate（25→32） | 新增声明：`xray-app-dispatcher`、`xray-app-stats`、`xray-proxy-{hysteria,ss,vmess}`、`xray-tls`、`xray-transport-kcp` |
| L3 闸 | +23 crate（31→54） | 基线无闸的 23 个 member 全部补齐（transport 族 ×9 / core / common / conf / cli / mux / tls / reality / geodata / crypto / features / proto / xudp / stress 等），余 `tests`+`benches` |

---

## 4. 脚本与运行输出

脚本：`reports/audit-2026-10-28/fusion_baseline.py`（只读；`--root` 指向任意快照树；`--json` 出机器可读结果）。

```
python reports/audit-2026-10-28/fusion_baseline.py
```

**HEAD 实跑输出（原文粘贴）**：

```
root = D:\Project\Xray-core-rust
生产面扫描文件 = 712

#  轴                      值  口径
----------------------------------------------------------------------------------------------------
1  方向纪律              100.0%  违规 0（源码 0 / 依赖条目 0）
2  契约族使用              78.6%  11/14
3  §3.5.4 七面          78.6%  5.5/7
4  依赖接地            57.1% (生产面 59.3%)  32/56
5  L3 静态闸          96.4% (生产面 100.0%)  54/56
----------------------------------------------------------------------------------------------------
总分（五轴等权）           82.1
```

**基线快照实跑输出（`git archive 7b336a12` 展开树，原文粘贴）**：

```
root = ...\reports\audit-2026-10-28\tmp\base-7b336a12
生产面扫描文件 = 704

#  轴                      值  口径
----------------------------------------------------------------------------------------------------
1  方向纪律                 n/a  N/A（快照无 udf 工作副本）
2  契约族使用              71.4%  10/14
3  §3.5.4 七面          57.1%  4.0/7
4  依赖接地            44.6% (生产面 46.3%)  25/56
5  L3 静态闸          55.4% (生产面 57.4%)  31/56
----------------------------------------------------------------------------------------------------
总分（五轴等权）           57.1        ← 轴 1 缺失，按 4 轴均值；计入轴 1=100 后为 65.7
```

> 基线总分 57.1 = `(71.4+57.1+44.6+55.4)/4`；把轴 1 按 100% 计入（票面与 10-25 报告同判据实测 0 违规）得 `(100+71.4+57.1+44.6+55.4)/5 = 65.7`。**对照 70% 与 HEAD 82.1% 时一律用 65.7 这一端**。

---

## 5. 已知局限（哪些是真测、哪些是近似、哪些必须运行时数据）

1. **轴 5 量的是「闸在位」，不是「闸生效」**。真生效须 `cargo clippy --workspace --all-targets -- -D warnings`（本票非目标，未跑，且会抢 target 锁）。每份 `clippy.toml` 的**内容完备度**（禁令条数、`path` 是否被写成 glob——P0-6 探针实测该写法静默失效）本脚本不校验。
2. **轴 1 基线为引用值**：`crates/udf-frame/` 是嵌套 git 仓，`git archive` 不含它 → 基线快照测不出轴 1。本报告按 10-25 报告同判据的实测（0 违规）计 100%，**非同法实测**。
3. **轴 4 只量「声明依赖」不量「真实消费」**：声明了 udf 但零符号消费的 crate 会虚高。符号级 call-chain 证据是 D5 的要求，本脚本未做。
4. **轴 2 的「族」粒度是整族**：`memgov`/池族只要有一个符号有生产调用即计 taken（`CountingAllocator`/`LeakGuard` 实际仍零消费）。按行数计会得到不同答案。
5. **三个分母并存**：12（票面）/ 13（D5）/ 14（矩阵）。本脚本取可枚举的 14；换分母必须重跑并对齐，不能互相折算。
6. **`56` 含 2 个非生产 member**（`tests`、`benches`）：轴 4/5 已并列生产面口径（54），但总分仍用 56（与票面同基）。
7. **字符串字面量会算进符号命中**（剥了注释、剥了 `cfg(test)` 模块，没剥字符串）。实测影响：`ConfigFile` 一族曾因 `xray-frame/src/config.rs` 的文档引用误判 taken，改为剥注释后修正 → 现 0 命中；同类误差上界约 ±1 族。
8. **轴 3 的 migrated/partial 阈值是本报告固定下来的规则**（§2.3 探针表），不是文档原文给的阈值；对面 #7 需 per-site ledger 才能判「残余是否已登记」，脚本只给 raw 计数。
9. **面 4 已迁但 cutover 未收尾**：`Config::override_with`（`serial.rs:63`）生产调用点 0 但函数仍在 → 按机制口径判已迁，按「clean cutover」口径未完成。本报告不把这类残留计为 partial（否则与 10-25/10-27 历史口径不可比），单列在此。
10. **14 面功能融合度（主指标）本次未重测**：本次只证明了两面翻转（面 6 配置装配 → B、面 12 注册表族 → B/两半）。按 `能力收敛方案` 同表其余面不动，则 8/14 → **10/14 ≈ 71.4%**——**这是推演值，不是实测值，不入本报告结论**，需 14 面逐面重测票单独做。
11. **需运行时才能真测的**：轴 5 生效性（clippy 实跑）；轴 2/轴 4 的真实消费（符号级 call-chain / 运行时埋点）；面 7 残余归属（ledger + clippy 输出对照）。

---

## 6. 结论：基线定稿值 + 下次对照怎么比

### 6.1 定稿值（本票口径，可复跑可对照）

| 项 | 值 | 锚 |
|---|---|---|
| 五轴 | **100.0 / 78.6 / 78.6 / 57.1 / 96.4** | `f288377c`（`feature/fix-inbound-parity`） |
| 等权总分 | **82.1%** | 同上 |
| 同法基线 | **65.7%** | `7b336a12`（注：脚本原始输出 57.1 = 缺轴 1 的四轴均值） |
| 票面历史锚 | **70%**（= 其自身五数均值 69.0） | `bd lbavl` description @ `7b336a12` |

### 6.2 下次对照协议（三步，禁混口径）

```bash
# 1) 取对照快照（任意 rev；7b336a12 为本票基线）
mkdir -p reports/audit-2026-10-28/tmp/base-<rev> && \
git archive <rev> Cargo.toml crates | tar -x -C reports/audit-2026-10-28/tmp/base-<rev>

# 2) 两端各跑一次，机器可读
python reports/audit-2026-10-28/fusion_baseline.py --root reports/audit-2026-10-28/tmp/base-<rev> --json > base.json
python reports/audit-2026-10-28/fusion_baseline.py --json > head.json

# 3) 只比同法两数 + 单轴绝对值；用完删快照
rm -rf reports/audit-2026-10-28/tmp/base-<rev>
```

判断题（三条硬规则）：
1. **只比同法两数**（本次 `head.json` vs `base.json`），**禁止**把票面百分比与同法百分比相减。
2. 单轴看**绝对值**（`x/56` crate、`x/14` 族、`x/7` 面），总分只看趋势（等权，权重随战役阶段变化，`bd lbavl` notes 已裁决**不设目标值**）。
3. 若某项口径变化（分母换法/探针改法），必须在报告里单列「口径变更」并**重算基线**，否则不可比。

### 6.3 与 70% 的关系（一句话交接）

**70% 是 udf 地基层口径的历史锚，不是当前状态**。同一棵树用同法量出来是 65.7%（该锚点）→ 82.1%（HEAD）。主结论口径已按 2026-10-27 用户口供改为「功能融合度 = (A+B)/14 面」，其数字需另票逐面重测（红线：`能力收敛方案` §0.1 四态 + 「收敛强度」判假 100%）。

---

## 7. 五维自评

| 维度 | 分 | 理由 |
|---|---|---|
| 准确性 | 4 | 五轴中三轴（七面/闸/方向）精确复现票面值；两轴分母不可复原之处已逐条举证并给同法替代值；扣分：轴 3 的 migrated/partial 阈值是沿用历史口径而非文档原文阈值，面 #7 只能给 raw 计数 |
| 完整性 | 4 | 定义出处、分子分母、复跑命令、同法基线、差异归因、脚本、输出、局限全给；未做：14 面主指标重测（已声明推演值不入结论）、clippy 实跑、符号级 call-chain |
| 清晰度 | 4 | 70% 与 82.1% 的「不可相减」在首段、§3.4、§6.2 三处钉死；基线总分 57.1 与 65.7 的差别单独解释 |
| 可执行性 | 5 | 一条命令复跑；`--root`/`--json` 支持任意 rev 对照；§6.2 给出三步协议与三条禁混规则；快照可随时重建（14MB） |
| 诚实度 | 5 | 主动写出「70% 不能直接比 82.1%」「轴 1 基线非同法实测」「面 4 cutover 未收尾」「主指标 71.4% 是推演值不入结论」「轴 5 不含量生效」 |

---

*脚本口径：生产面 = `crates/*/src/**/*.rs` 剥 `//`+`/* */` 注释后 brace 级剥 `#[cfg(test)] mod`；members = 根 `Cargo.toml` `members = [...]` 剥注释展开（`exclude = ["crates/udf-frame"]` 天然不在内）；依赖判定 = 切到 `[dev-dependencies]`/`[build-dependencies]` 之前的文本；闸判定 = `clippy.toml` 含 `disallowed-methods=`/`disallowed-macros=`。零构建、零测试、零 clippy 实跑。*
