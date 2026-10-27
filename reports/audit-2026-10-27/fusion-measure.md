VERDICT: CONDITIONAL

完工状态：DONE（六轴全部实测落数；条件 = 树在动 + 2b 门未回填 + 两处基线分母口径注记，见 §0/§6）

# 能力收敛融合度测量报告（六轴 · 接续 FusionMeasure）

- 测量时点：2026-10-27（本会话内连续实测）；`HEAD = 377c712d`（与前任 FusionMeasure 测量锚**相同，期间零新 commit**）。
- 树状态：crates/ 内 **76 个在飞文件**（W1 六件 + L3GapSweep + tracing 批 2a + 批 2b，均未提交）；`crates/udf-frame/` 为 git-ignored 工作副本（P0-9 拉料形态，见 §5 卫生观察）。
- 基线（对照锚）：`bd lbavl`（2026-10-26 PM 复测 @ `7b336a12` 五轴）+ 功能融合度基线 8/14 ≈ **57%**（`docs/architecture/xray-frame-能力收敛方案-2026-10-27.md` §1.1/§7.2）。
- 方法：**只读**。git grep / 文件系统扫描（`#[cfg(test)]` brace 级剥除后计数）/ `.measure/{base,head}` 快照对照（base=7b336a12，head=377c712d，前任 `git archive` 落盘）/ 既有报告门尾引用。**零构建、零测试、零门重跑**（非目标）。
- 前任遗产：`.measure/` 双快照（可用，已用于基线差分）；其五轴+功能面采集命令可追溯（history://FusionMeasure），报告未写即阵亡——本报告为其续篇。

---

## 0. 可比性声明：真进展 vs 口径变化

**测量期间树在动**（批 2b 在本会话中段完成 vmess/freedom 迁移，本人前后两次计数分别抓到 31 站残留与 0 残留，已并入 2b 归账）。凡引用"基线"处一律用 `.measure/base`（=7b336a12）同法复测值对照，不混用票面转述值；两处无法复原的票面分母在对应轴显式标注。

**已提交的真进展**（`7b336a12..377c712d` 共 42 commit，10-26 夜班 + 10-27 晨）：+4 个 udf 依赖 crate、+23 个 L3 闸 crate、注册表族半收口（xiuvr-3a）、memgov 族取件、fakedns LRU 换 udf 件、inbound spawn 三批托管、tracing 批 1（33 站）。
**在飞真进展**（未提交）：W1 六件、L3 台账 +43、tracing 批 2a（109 站）+ 2b（89 站）。

---

## 1. 六轴总表（基线 → 当前）

| # | 轴 | 基线（lbavl @7b336a12） | 当前（HEAD+在飞） | Δ | 主驱动 |
|---|---|---|---|---|---|
| 1 | 方向纪律 | 100%（0 违规） | **100%**（0 违规） | = | udf-frame 全源码剥注释后 `xray` 命中 **0** |
| 2 | 契约族使用 | 9 taken / 4 未取（票面 9/12=75%） | **10 taken / 3 未取**（按基线矩阵 14 行折算 ≈77%） | **+1 族** | memgov 取件（`BoundedRegistry` 进生产） |
| 3 | §3.5.4 七面 | 4/7 = 57%（已迁3+部分2） | **4.5/7 ≈ 64%**（已迁3+部分**3**） | **+0.5 面** | 注册表族 ❌→⚠️（xiuvr-3a，committed） |
| 4 | 依赖接地 | 25 crate（票面 25÷43=58%） | **29/56 成员 = 52%**（全员口径） | **+4 crate** | ss/vmess/hysteria/app-stats（全 committed） |
| 5 | L3 静态闸 | 31/56 = 55% | **54/56 = 96%**（余 benches/tests 2 个非生产 crate） | **+23 crate** | 10-26 夜班 l3-core/rest-gates（committed）；今日闸内容增补（tracing 五宏）不计票数 |
| 6 | **功能融合度（主指标）** | **8/14 ≈ 57%**（A=2,B=6,C=6,D=0） | **8/14 = 57%**（A=2,B=6,C=6,D=0，严格口径未变） | **=** | W2–W7 未飞：六件框架件零主仓消费点（§2 逐面） |

**一句话判读**：地基五轴全线抬升（闸 55%→96%、接地 +4、契约族 +1、七面 +0.5、纪律保持 100%），但**主指标功能融合度严格口径仍钉在 57%**——因为 (A+B) 的判据是"主仓生产消费"，而今天落地的全部是**框架侧供给**（W1 六件零消费点）与**面内残差清偿**（tracing 217→0、spawn/时钟台账化），没有任何一个 C 面完成"整面翻转"。这不是停滞：79% 所需的全部前置件（W1）已就位，W4/W5 的串行阻塞（FusionMeasure 测量、tracing 2a/2b 面重叠）已全部解除（§4）。

### 票面口径两处注记（诚实边界）

1. **依赖接地 58% 的分母**：lbavl 写 `25÷(25+18)=58%`，分母 43 的构成无法从票面复原（当时 crosstab：both 19 / udf-only 6 / gate-only 12 / neither 19，任何组合都对不上 43）。本报告统一改用**全员口径** `29/56=52%`，基线同法复测为 25/56=45%——**真进展 = +4 crate（crosstab both 19→29、gate-only 12→25、neither 19→2），趋势与票面一致**。
2. **契约族 "9/12"**：票面分母 12 与其矩阵 14 行不一致（9+4=13）。本报告沿用其矩阵：taken 9→10（memgov 经 `xray-core/src/inbound.rs:3043` 生产 slots + `xray-frame/src/audit.rs:52` 审计环取件；`CountingAllocator/LeakGuard` 仍零消费），未取 4→3（compose::combine / testing::{TestStore,ScriptedRuntime} / ConfigFile 全仓生产仍 0 引用；ConfigFile 仅 `xray-conf/tests/config_file_shadow.rs` 影子比对态）。

---

## 2. 第六轴逐面四态表（14 面 · 前 → 当前）

判据：A/B 态必须给**生产消费点**（file:line 可 grep）；C 态给"各自实现"证据；本表状态列 = 方案 §1（前）vs 本报告实测（后）。

| # | 功能面 | 前 | 现 | 证据（当前树实测） |
|---|---|---|---|---|
| 1 | 插件契约与装配门 | B | **B** | `xray-frame/src/{plugin,registry,assembly}.rs`；生产消费 `xray-core/src/arm_registry.rs`（36 构造器查表，committed） |
| 2 | 生命周期与停机 | A | **A** | udf `ShutdownCoordinator`；`xray-core/src/instance.rs` + `shutdown_bridge.rs`（committed） |
| 3 | L2 能力供给（ctx 八柄） | B（D 缺口） | **B（D 缺口未动）** | spawn 6 / clock 2 / log 4 生产点（nn8os-reaudit §五）；nn8os-2a 已给 audit 柄装配接线，但 **R3 未解**：pool/ids/audit 三柄生产**零消费**（今日 grep `take_events()/ctx.pool()` 生产面仅测试；`CountingAllocator/LeakGuard` 0 命中） |
| 4 | L4 契约测试夹具 | B | **B** | `contract_assert.rs` + 16 crate `tests/plugin_contract.rs`（真实实例 3/16 残，另波） |
| 5 | L3 静态闸与豁免台账 | C | **C**（质量推进） | ledger-audit 实测 per-site allow **458**（today 晨）；L3GapSweep 净增 **39** 条 allow 属性（43 站全台账化）→ 现 ≈**497**（下次台账审计复算）；闸 54/56 |
| 6 | 配置装配与解析 | C | **C**（供给就绪） | 生产仍在 `xray-conf/src/serial.rs`（merge_configs）；W1 `XrayConfigLayers/MergePolicy`（611 行）已落 `xray-frame/src/config.rs` 但**主仓消费者 0**；xiuvr-3c 影子比对测试已备（`xray-conf/tests/config_file_shadow.rs`，committed） |
| 7 | 时钟与预算 | C | **C**（供给就绪） | W1 `Budget/BudgetSource`（344 行）落 `xray-frame/src/deadline.rs`，**消费者 0**；生产裸时钟站点维持台账（clock 台账 27 + proxy-clock-sweep 族，committed） |
| 8 | 任务托管 | C | **C**（部分收敛加深） | FxScope 生产消费 685 处（transport 73/frame 53/dns 51/reverse 36/core 35/tuic 32…）；`inbound.rs` 文件级 allow 现覆盖生产 16（inbound-spawn-batch1 迁 13 + uds 批 + cfg(unix) 6，全 committed）；残：`outbound.rs` 29 / `functions.rs` 46 / transport 29 |
| 9 | 日志分发与掩码 | A | **A**（C 残大幅清偿） | udf `logx` 三通道单入口（`xray-common/src/log/mod.rs`）；**proxy 16 crate 生产裸 tracing = 0**（本报告两次独立实测；批1 33 + 2a 109 + 2b 89 + W2Supply 4 crate）；**全仓生产残 = 490 站/26 crate**（core 202 / transport 37 / tls 36 / app-dns 34 / commander 23 / dispatcher 19 / splithttp 18 / …，transport/app/cli 排队面） |
| 10 | 缓冲池化与接缝 | B | **B** | `xray-frame/src/pool.rs` + `xray-buf`（17d23baa） |
| 11 | 观测字段与审计流 | B | **B**（残未动） | `observe.rs`/`audit.rs`；observatory/geodata 消费；**audit 环生产零发射方**（R3 项） |
| 12 | 注册表族 | C | **C→半收口** | **inbound 半已收口（committed fe8d5481）**：`xray-core/src/inbound.rs:3043` slots = udf `BoundedRegistry<String,InboundSlot>`（`Eviction::Reject` fail-closed + tag 确定序 + 生命周期回归测试）；**outbound 半未动**：dispatcher `SimpleOhm`（`default.rs:2038`，`RwLock<HashMap>`）仍主仓自造 |
| 13 | 查表分发 | B | **B** | `dispatch.rs` Lookup + `arm_registry.rs` 生产唯一查表路径 |
| 14 | 通用散件 | C | **C**（1/4 轮子已清） | fakedns 外购 `lru` **已删、换 `std_ext::cache::LruCache`**（bd b2qdu 闭环，committed）；残：wireguard `TtlDnsCache`（11 命中，bd 9zxyl）、DNS `cache_controller`、geo weak cache、自造 uuid |

**严格口径**：(A+B)/14 = (2+6)/14 = **8/14 = 57%，与基线持平**。若按方案 §7.1 对面 8 的先例（"主机制已入框架即记 B，残面另波"）把半收口的面 12 记 B，则为 9/14 ≈ 64%——**本报告不采信该宽松口径进主数**（SimpleOhm 仍整只在产），仅在 §4 的 100% 路径里记 R1 已完成一半。

---

## 3. 波次归账（W1 / L3 / 2a / 2b → 计划表贡献）

| 波 | 状态（按实数） | 交付物 | 对计划表的贡献 | 门 |
|---|---|---|---|---|
| **W1** 框架派生件 | **落地（未提交）**——按代码在树计（其报告 §6/§8 门尾为 PM 待回填的「填充中」） | 6 件 1873 行：`config.rs` 611 / `deadline.rs` 344 / `logging.rs` 399 / `compat.rs` 222 / `redline.rs` 159 / `scope.rs` 138 + `context.rs` +12 + `lib.rs` 导出 + 7 个测试文件 710 行（全部 `??`/M 在飞） | **W2–W7 的唯一前置**已就位；**零主仓消费点 → 融合度贡献 0 个面翻转**（`XrayConfigLayers/Budget/HotLog/compat/ConnScope/redline::` 主仓消费 grep 全 0）；解锁路径见 §4 | 报告内 G2–G6 声明 PASS；`-p xray-frame` 三门 + fmt/doc 自查；workspace 门归 PM 收尾（§6.1 D2 教训：框架层未提交期间是全局编译风险源） |
| **L3GapSweep**（txmhr） | **落地（未提交）** | 43 生产站全台账化 / **迁移 0 处**（ctx 不可达 + 坑约束⑫，逐站 reason）；dispatcher 补 spawn 族、kcp 补 3 条、splithttp 一次性补 6 条；9 轮探针实证 def-path 写法 | **闭环 ledger-audit §3 的"4 crate 无 spawn 禁令"finding 中的 3 个**（dispatcher/kcp/splithttp；`xray-buf` 仍只禁 to_vec，残）；台账 458→≈497；axi 5 闸**票数不变**（三 crate 本已有 toml），贡献为**闸内容完备度** | 报告含 workspace check/clippy（当时尾部红在 W1 面已点给 owner）+ 三 crate 测试 + fmt |
| **tracing 批 2a** | **落地+独立复核（未提交）** | 109 站 1:1（tuic 42/anytls 28/trojan 20/hysteria 19），15 个 `LazyLock<LogFacade>`，4 crate 补五宏禁令 | 面 9 的 C 残 -109；**解锁 W5**（tuic/anytls 面重叠解除） | workspace check/clippy -D warnings/test 314 绿/fmt 四 crate CLEAN（报告 §6 完整尾部）+ **2a-verify 独立对账 1:1 闭合、四门全绿** |
| **tracing 批 2b** | **迁移完成度 100%（在飞，门未回填）**——本会话实测：开工时 vmess 18 + freedom 13 残留 → 收尾时 **0** | **89 站 1:1**（wireguard 26/tun 26/freedom 19/vmess 18；含阵亡前任 12 站续用 + 2 处 `event!` 逃生按 PM 裁决拆除改迁）；4 门面（WG/TUN 续用 + FREEDOM/VMESS 新增）；4 clippy.toml 五宏禁令**探针实证真拦截** | 面 9 的 C 残 -89；**proxy 层 16 crate 裸 tracing 清零**（nn8os 217 基线 → **0**，全批次合计 ≈231 站，含口径差 ±5/ crate）；与 2a 共同**解锁 W5** | **报告 §4 四门 + §6 自评 = 待回填**（代理仍在飞）；本报告独立旁证：8 crate 生产残 0 + 8/8 clippy 禁令在位（§2 计数脚本） |

**对 79% 路径的净效果**：W1 供给侧 100% 就位；W4 的测量前置（本报告血脉）解除；W5 的 tracing 前置解除；W2 的影子比对前置（xiuvr-3c）早已 committed。**79% 所需五波（W2/W3a/W3b/W4/W5）当前零阻塞、可并行派单**（文件面互斥需按 §4 重核，见下）。

---

## 4. 剩余缺口清单

### 4.1 到 79%（还需翻转 C 面 6/7/8 + 关 D 缺口 → 11/14）

| 波 | 内容 | 前置现状 | 注意 |
|---|---|---|---|
| **W2** | xray-conf 影子三路对照 → 切 `XrayConfigLayers`（面 6 翻 B） | 影子测试已备（xiuvr-3c committed）；W1 件在树 | PM 口径：默认值差异禁掩盖，先判语义归属 |
| **W3a** | xray-common / xray-tls 走 udf `Clock`（不引 xray-frame） | 无阻塞 | ⚠️ 与在飞无重叠，但 `xray-common` 有 5 处 tracing 残（排队面，不属 W3a） |
| **W3b** | transport / proxy-ss / proxy-wireguard / proxy-tun 的 std 墙钟 + 删对应 allow | 无阻塞 | ⚠️ **文件面重核**：wireguard/tun 刚被 2b 改过（clippy.toml + src），派单前以当日 `git status` 为准重核互斥 |
| **W4** | 面 3 步 2+4 + 面 6 合并（inbound.rs 单人改；core/mux/app-dns） | **FusionMeasure 测量前置 = 本报告，已解除** | `inbound.rs` 文件级 allow 现覆盖生产 16（移交 W4 时按 16 对账，非方案稿的 10——inbound-spawn-batch1 已收 13）；W7 串行其后 |
| **W5** | proxy tokio 虚拟钟预算点（vmess/vless/tuic/transport） | **tracing 2a/2b 前置 = 已解除** | 串行于 W3b（transport 同 crate） |
| （D 缺口） | face 3 pool/ids/audit 生产消费点（nn8os R3） | PM 二选一未拍板：接线 or 降格 DOD | 不阻塞面翻转计数（face 3 已是 B），但 79% 口径含"D→0" |

W6（热路径日志）/W7（红线受控）**不改变 79% 数字**（W6 提升面 9 的 A 质量、W7 清面 5 一批 allow + vision 站点入 `RedlineSite` 台账），按串行链（W4→W7、W5→W7）排在数字路径之外。

### 4.2 到 100%（残余三 C 面，均非"加框架件"可解）

| 步 | 面 | 还差什么 | 现状进度 |
|---|---|---|---|
| **R1** | 12 注册表族 | **outbound 半：`SimpleOhm` → udf `BoundedRegistry`**（禁整面 impl PoolManaged） | **inbound 半已完成**（fe8d5481，比计划表预期早——xiuvr-3a 提前做了 W9/R1 的 inbound 切片） |
| **R2** | 14 通用散件 | TtlDnsCache→udf `TtlCache`（9zxyl，11 命中在树）；DNS `cache_controller`、key cache、geo weak cache 换 udf；自造 uuid→`std_ext::id::IdGen`；各处重试退避→`std_ext::retry` | **fakedns lru 已清**（b2qdu，外购依赖已删）——4 项轮子/自造清单已划掉 1 项 |
| **R3** | 5 L3 台账 | 随 R1/R2/六面迁移自然减项（458+39≈497 起算）；残余 = per-crate clippy.toml 分布 + 测试面 cfg_attr 豁免 = **机制性不可归零**（§10.1 口径，计入分子） | 闸 96% 已封顶；台账纯度 20/20 抽查成立（ledger-audit） |

**留主仓举证面**（不挡 100% 口径，方案 §7.3 已裁决）：smoltcp 栈时钟 28 处（第三方契约）、`xray-transport-tcp/register.rs` + bridge.rs P7LM（红线/归因通道）、YAML/TOML/JSON5 解析器、lint 编排（bd d95us 留仓至 P4）、L4 真实实例 15/16（P2 波次）。

---

## 5. 静默失败 / 卫生观察（silent-failure 视角，交 PM 派修，本报告不自修）

1. **2b 门悬空**（建议·应修）：批 2b 迁移 89 站已进共享树但其报告 §4 四门/§6 自评"待四门跑完回填"，代理仍在飞。若再次阵亡，共享树将滞留 ~76 个未提交 crate 文件、其中 4 crate 门未验——正是方案 §6.1 D2"框架层红挡全场"的变体。PM 收尾必须先追 2b 门或自行补跑 workspace 四门再批下一波。
2. **udf 工作副本漂移**（建议·应修）：`crates/udf-frame/` 相对其 HEAD 脏 101 文件（src 41），diff 形态 = rustfmt 风格注释重排 + use 合并（抽样 `id.rs`/`fx.rs`），但逐文件空白归一化比对 **40/41 不等**，不能判定纯格式。风险：CI fetch-udf 重拉即丢弃（若含真实修复如 `skeleton-infra/src/config.rs:33 use std::fmt` 的既有 warning，则修复随拉料蒸发且无人知）。方向纪律不受影响（代码面 xray 引用 0）。建议 PM 决策：重拉对齐 upstream 或授权单独审该副本 diff。
3. **台账总数漂移**（吹毛）：per-site allow 总量账面 458 已三重过期（inbound.rs 计数修正 72→73、L3GapSweep +39、后续波还会删）→ 建议下次台账审计以"重算总量"开头，本报告 §2 面 5 行的 ≈497 只是线性外推。
4. **`xray-buf` 禁令缺口**（吹毛）：ledger-audit §3 点名的 4 crate 中 3 个已被 L3GapSweep 闭环，`xray-buf` 仍只禁 to_vec——无 spawn/时钟禁令。生产面站点未盘点（本报告未测，非本票面）。

---

## 6. 未覆盖 / 未验（诚实边界）

- **零构建、零测试、零门重跑**（任务非目标）：所有门结论引用自既有报告（W1 报告体、2a 报告 §6、2a-verify §1/§4、l3-gap-sweep §6、ledger-audit 方法节、uds-spawn-batch PASS）；**2b 的门在本报告落稿时仍未回填**——2b 相关的"四门绿"声明在树态上**无独立实跑证据**，仅本报告的 grep 旁证（0 残留 + 禁令在位）。
- **基线两处分母**（lbavl 依赖接地 43、契约族 12）不可复原，已按 §1 注记改用可复现口径；若 PM 需要与 58%/75% 严格同基对比，须先回溯 lbavl 取数会话（history:// 可查其命令面）。
- udf-frame 工作副本 41 src 脏文件的**语义级**甄别未做（仅空白归一化判定 + 抽样读 diff）；`.measure/head` 快照晚于 fe8d5481 等 10-26 提交，故"基线以来 committed 进展"的逐 commit 归因（哪票贡献哪个数）未逐票对账，只做了基线↔当前两端差分。
- 全仓 tracing 残 490 的**逐站 ctx 可达性分类**未做（那是 transport/app/cli 迁移批的开工活，同 2b 开工重 derive 先例）。

---

## 7. 五轴自评

| 维度 | 分 | 理由 |
|---|---|---|
| 准确性 | 5 | 每个数字带可复跑方法（脚本口径 + git grep + 快照差分）；两处自抓自纠（路径错致假 0、basename 缺 dirname 臺全表 0，均当场修正并复验 raw=stripped 误差界）；2b 中段落地被前后两次计数实抓 |
| 完整性 | 4 | 六轴 + 14 面逐面 + 四波归账 + 79%/100% 双路径缺口全给；未做：逐 commit 归因、490 站逐站分类、udf 副本语义级甄别（均在 §6 声明） |
| 清晰度 | 5 | 主判读一句话（地基升/主指标平/原因=供给 vs 消费）；严格 vs 宽松口径分开给数不混算；真进展 vs 口径变化单列 §0 |
| 可执行性 | 4 | §4 缺口表逐波带前置现状与派单注意（W3b 文件面重核、W4 对账基数 16）；§5 四条卫生观察可直接派修；未给的是波次排期（归 PM） |
| 诚实度 | 5 | 主结论对自己不利也直说：**功能融合度严格口径仍是 57%，今天零面翻转**；2b 门未验、基线分母不可复原全部前置声明，不用"约 79% 在望"类注水话术 |

---

*测量脚本口径：生产面 = `#[cfg(test)]` brace 级剥除 + 行注释剥除 + `tests/` 目录排除；宏计数 = `tracing::(trace|debug|info|warn|error)!` 全限定 + `(?<![:\w])(name)!` 短导入双形态；成员/依赖/闸 = 根 Cargo.toml members 展开（exclude udf-frame）+ Cargo.toml `[dev-dependencies]` 前切分 + clippy.toml 含 `disallowed` 计数。*
