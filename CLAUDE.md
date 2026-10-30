# CLAUDE.md — Xray-core-rust 项目指南

> **给 OMP/AI 子代理 + 人类贡献者的"5 分钟上手"**
> **优先级**：本文件覆盖**全局** `AGENTS.md`（`C:\Users\Begonia\.omp\agent\AGENTS.md`）的本项目规则
> **必读对象**：所有 PM/子代理派单、新协作者、审计师

---

## 0. 项目一句话

**Xray-core-rust** = Go Xray-core **v26.10.17** Rust 复刻（起点 v26.9.9；**对拍裁定基准 = 26.10.17**，源码 `D:/Project/Xray-core` @ `92ccc939`，26.9.9 仅用于解释「上游改了什么」不得用于裁定；上游已达 26.10.21，**待 10.17 全量复刻完成后**再讨论提升，禁提前把 10.21 新增项当缺口），私有仓 `github.com/Be90nia/xray-core-rust`，master `ceb6a487`（`feature/framework` 领先 695 commit，`7b336a12` 实测），CI 10 门，32/32 协议全通，crates/ 下 804 个 `.rs` ≈ 36.4 万行 Rust，55 个 crate 条目（54 自建 + `udf-frame` 外部仓工作副本）。

---

## 1. 5 分钟上手

```bash
# 1. 构建（btls-sys 冷编坑——见 §6 踩坑；PROTOC/LIBCLANG 缺任一即构建/测试链挂）
cmd /c "set BORING_BSSL_ASSUME_PATCHED=1&& set BORING_BSSL_SOURCE_PATH=D:\Project\Xray-core-rust\target\boringssl-patched&& set PROTOC=D:/Project/tools/bin/protoc.exe&& set LIBCLANG_PATH=D:\Program Files\llvm\bin&& cargo build --release -p xray-cli"

# 2. 测试（CI 10 门宽门镜像）
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
cargo doc --workspace --no-deps

# 3. 跑
./target/release/xray.exe run -c <config.json>
```

**工作流（高频用）**：
- `python tools/loopback_alloc_bench.py --tag <feature> --xray target/release/xray.exe --runs 3` —— 性能 baseline
- `cmd /c "set BORING_BSSL_ASSUME_PATCHED=1 && set BORING_BSSL_SOURCE_PATH=... && python tools/inject_btls_cache.py"` —— btls 冷编注入
- `bd create --title "..." --priority N --label audit` —— 新建 bd 票（前置 `export BD_IGNORE_SCHEMA_SKEW=1`）

---

## 2. 状态快照（2026-10-12 立项级审计——**历史快照，非当前状态**：其后 `feature/framework` 已累积数百 commit，评分与票面均过期）

| 维度 | 评分 | 报告 |
|---|---|---|
| 架构 | 3.8/5 | `docs/audit-架构-2026-10-12.md` |
| 性能 | 3.6/5 | `docs/audit-性能-2026-10-12.md` |
| 安全 | 3.4/5 | `docs/audit-安全-2026-10-12.md` |
| 规范（3 维合一）| 3.3/5 | `docs/audit-规范-2026-10-12.md` |
| 9 票架构审视（专项）| 4.3/5 | `D:/tmp/audit-bd-arch-report.md` |
| **综合** | **3.5/5** | `docs/audit-立项级别-2026-10-12.md` **GO-WITH-CONDITIONS** |

**当前活跃票面**：以 `bd list --status open` 实时输出为准（上表审计时点的票号 `6su8`/`2ktp`/`fzir`/`75rv`/`sf5b`/`syvm`/`mc11`/`akqh`/`8pne` 均已 CLOSED，快照不写死票号）。

---

## 3. 文档地图

| 文档 | 用途 |
|---|---|
| **`ARCHITECTURE.md`（在 `docs/`）** | **治理宪法**——MVVM 五层 + 八条原则 + 五阶段映射（必读）|
| **`docs/refs/`** | 治理输入（v1/v2/v3 裁决 + alloc-audit 报告）——**红线** |
| **`docs/benchmarks/baseline.md`** | 性能 baseline（loopback 154-167 MB/s + alloc/MB 2.15/2.22）|
| **`docs/audit-*.md`** | 5 维审计 6 份 + 综合 + 立项级 |
| **`D:/tmp/audit-*.md`** | PM 工具链产物（审计上下文 + 9 票审视 + 框架前瞻债 v1/v2）|
| **`bd list --status open`** | 当前活跃票面（label=audit/framework/standards 等）|
| **`docs/architecture/xray-frame-强约束插件模型-2026-10-23.md`** | **框架纪律核心**——三层定位 + 五层强制约束 L1-L5 + 协议坑约束表 12 条（造件/评审必读）|
| `docs/architecture/xray-frame-派生件全景与工作列表-2026-10-23.md` | 继承面全表 + 派生面 8 件 + 差距分析 + P0-P4 工作列表（本地规划文档，未入库）|
| `docs/architecture/xray-frame-契约级任务书-*.md` | P0 / P1-P4 契约级任务书（可派单形态，本地文档）|
| `docs/research/xray-frame-*.md` | 盘点底料：主仓 53 crate 能力盘点 / udf 机制差距 / 池化归 udf / DNS 面 / inbound-outbound 面（本地文档）|
| **`docs/architecture/xray-frame-udf功能域全景-2026-10-23.md`** | **udf 32 域全景 × 主仓覆盖对照**——udf 有什么/没什么/主仓哪些面能接管/10 个未接线高价值域/3 条反模式（造件选依托件前先查）|

---

## 3.5 三层定位与继承派生纪律（硬约束）

### 3.5.1 三层比喻（用户 2026-10-23 定调：udf 是地基，udf-frame 是骨架，xray-frame 是硬装血肉）

| 层 | 载体 | 定位 | 边界 |
|---|---|---|---|
| **地基** | `udf-frame` 仓的 `skeleton`（契约层，零依赖）/ `skeleton-infra`（实现层）/ `std-ext`（十三域散件） | 零业务语义的**地基**：机制、契约、标准件、踩坑沉淀 | 不含任何 Xray 语义；不引业务类型 |
| **骨架** | `udf-frame` 仓整体（独立仓 `github.com/Be90nia/udf-frame`，跨项目复用） | **骨架**：机制/契约/规范的整理与演进场所，给派生层装 | 不含 Xray 语义；不做产品装配 |
| **硬装血肉** | 主仓 `crates/xray-frame`（装配与插件骨架）+ 各 `xray-proxy-*` / `xray-app-*`（Xray 特有） | Xray 特有的**硬装血肉**：协议插件、装配、硬连接入 | 依赖骨架与地基；**禁复制骨架已有的功能**（§3.5.2） |

**依赖方向单向**：硬装血肉 → 骨架 → 地基。反向只走**提炼回路**：血肉里的通用件提炼上浮骨架/地基 → udf 发版 → 血肉换依赖并删本地副本。**不锁版本，但锚是显式的**：主仓对 udf 走 **path 依赖**（`crates/udf-frame/*`，整目录被 `.git/info/exclude` 排除在工作树外），`Cargo.lock` **只记 `path`、不记 commit**——实际 commit 由工作副本 HEAD 决定（`git -C crates/udf-frame rev-parse HEAD`），并钉进 `crates/udf-frame/REV`；校验件 `crates/xray-conf/tests/udf_rev_anchor.rs` 比对两侧，不一致即测试失败（bd jyjko）。

### 3.5.2 禁重复造轮子（评审打回项）

1. **造件前必查三处**：udf 三 crate（地基+骨架）→ 主仓 `crates/xray-frame` → 主仓既有 crate 是否已有同功能件。查法：serena-cli 查符号与 API 面（禁凭印象写"这个 udf 没有"）。
2. **udf 已有等价功能时，只允许三种做法**：
   - **直接用**（A 类接线）
   - **继承派生**（B 类：实现 udf 契约 / 组合其组合件——如 `impl PoolManaged` + `PoolBase` 公共逻辑白拿）
   - **回灌提炼**（C 类：件成熟后提炼上浮 udf，再换依赖删本地副本）
   - **禁止**：在主仓复制一份同类实现（"我先写着，以后再说"= 打回项）。
3. **确需例外**（语义/性能/红线冲突）：件头必须写一行「udf 为什么不适用」的判定 + 标注提炼候选（`udf-promotion-candidate` 注释），并经 review 认可。
4. **审计口径**：任何"新增功能"类改动，review 必查"udf 是否已有等价件"；命中重复即打回。
5. **常用白拿清单**（免得重新发明——核对最新签名以 udf 源码为准）：
   - 池化：`skeleton::pool::PoolManaged`（resize/metrics/subscribe_audit 三挂点）｜`skeleton_infra::pool::PoolBase`（校验/水位线/审计环/溢出计数/借还记账）｜`ThreadPool`（core/max/queue_cap、零自旋、优雅缩容）｜`RejectPolicy` 四件套（Abort/CallerRuns/Discard/DiscardOldest）｜`skeleton_infra::memgov::{MemoryPool, BoundedRegistry, CountingAllocator, LeakGuard}`
   - 异步与停机：`skeleton_infra::fx::FxScope`（spawn 唯一托管口）｜`skeleton_infra::shutdown::ShutdownCoordinator`（注册窗+编排窗+超时/panic 隔离）
   - 日志观测：`skeleton_infra::logx`（唯一入口 + `mask_secrets`）｜`log-embed` 埋点规范（target `xray_frame::<域>`）
   - 缓存/重试/调度/时钟：`std_ext::cache::{LruCache, TtlCache}`（⚠️ **单线程 `&mut self`**，并发面另批）｜`std_ext::retry::{RetryPolicy, retry, retry_if, Sleeper}`｜`std_ext::scheduler::Scheduler`（after/every/close/`panic_count`/优雅 join）｜`skeleton::clock::{Clock, MockClock}`
   - 配置/JSON：`skeleton::config::{ConfigPort, EnvSource, StdEnv, MockEnv}`｜`skeleton_infra::config::ConfigFile<C>`（`config-json`/`config-toml` feature：分层折叠 `layer`/`default_layer`/`file_layer` + `load`/`save`，真相不静默丢）｜`skeleton_infra::parse_mock`（解析测试替身）
   - 契约与测试替身：`skeleton::{Reducer, Store, EffectBuf, JournalPort, Driver, Subscription}`｜`skeleton_infra::compose::combine`｜`skeleton_infra::testing::{TestStore, ScriptedRuntime, MockEnv}`｜`parse_mock`

### 3.5.3 分层纪律边界

- **地基/骨架不引 Xray 类型**（提炼判据：零 xray 类型 = 全泛型/trait）——这是血肉能上浮的前提
- **udf-frame 只放「大部分软件框架通用」的功能；xray-frame 是我们项目的框架**（用户口供 2026-10-23）——**带领域方向的件不进 udf-frame**（即使零 xray 类型）：网络（accept 循环纪律 `accept_policy.rs` 留主仓 xray-transport）/文件/加密/协议等方向件，留主仓最近消费方；udf 只收无方向进程级机制（cache/retry/clock/id/logx/compose 族）
- **血肉不复制骨架功能**（§3.5.2）；需求差异用**组合/特化**解决，不靠复制
- **骨架不感知血肉**（不因某协议需求污染地基语义）
- **改 udf 仓走提炼回路**：独立 PR + CI 三平台绿 + xray-frame 换依赖复测 32/32
- **新功能一律长在框架上（用户口供 2026-10-30 · 硬约束）**：新增能力**不得在框架之外开发** —— 机制落 `udf-frame`（地基/骨架，零 xray 语义）或 `xray-frame`（派生层，可含 xray 语义），协议/应用 crate 只允许留**薄适配**（接线 + Xray 特有语义）。
  - 判据：新功能是否需要被多个协议/场景复用？→ 是 → 机制进 xray-frame；是否零 xray 语义且进程级通用？→ 是 → 进 udf-frame（走提炼回路）。
  - 禁：在 `xray-app-*` / `xray-proxy-*` / `xray-transport-*` 里自造机制再让别的协议来抄；禁把机制留在只有它自己在用的 crate 里。
  - 落地顺序：先在 xray-frame 落机制件（能力句柄挂 `PluginContext`）→ 协议 crate 只调框架 API → 通用部分按 §3.5.4 提炼上浮 udf。
  - 例外：纯协议 wire 语义（字节序/加解密/握手格式）与 Go 对拍差异修正，**留在协议 crate**（属内容不属机制），但必须走 §3.5.2 查重。

### 3.5.4 归一化面（主仓已自造、但属通用件 → **必须提炼回 udf**，主仓不得留副本）

这些是"血肉里已长出的通用骨架"——按 §3.5.2 纪律，它们**不该待在主仓**，应提炼上浮 udf 后主仓换依赖删本地副本：

| 面 | 主仓现状 | 归一化目标 | 备注 |
|---|---|---|---|
| **JSON 工具壳** ✅ 已归一化（P1-9） | 实体机制（RFC 8259 严格解码 / 注释容忍 / 64MiB 输入上限 / 行列位置错误）已上浮 udf `std_ext::json`（`decode`/`decode_str`/`decode_slice` + `JsonMode`）；主仓 `xray-conf/src/json.rs` 只剩 Xray 语义薄壳：4 个 `decode_json*` 按 env 切 strict 后转调 udf | ——（已完成，无剩余动作） | Go 兼容的**序列化**语义（`serial.rs` `to_json_string` 的 `JSONMarshalWithoutEscape` + 4 空格缩进）属 Xray 特有，**留主仓** |
| **配置 lint 阶段编排** ⏳ 留仓至 P4（2026-10-26 PM 裁决，bd d95us） | `xray-conf/src/lint.rs`：`LintStage` trait + 全局注册表 `register_stage`(:95)/`clear_stages`/`registered_stages` + `post_process`(:117，**阶段在锁外执行**，避免回调注册表时死锁) | 编排机制零 xray 语义（"端口 + 注册表 + 阶段编排"模式，与 `JournalPort`/`ConfigPort`/`ShutdownCoordinator` 同族），符合提炼判据；**裁决 = 留仓至 P4 + 补标准标注**，本窗口不上浮 | 阶段内容（Xray 配置语义）留主仓，编排机制 P4 上浮 |
| **日志 Handler 分发 + 双写** ✅ 已归一化（P1-10-b） | 旧 `HANDLERS` 扇出 + tracing 双写已删；主仓 `xray-common/src/log/mod.rs` 收敛为 udf `logx::ChannelRegistry` 单入口：general/access/dns 三通道，`register_channel` 装配期注册（同通道二次注册 fail-visible），`Channel`/`ChannelSink` re-export，便捷入口 `debug`/`info`/`warning`/`error` 只走 general 通道 | ——（已完成；udf 侧多通道 sink 缺口已由 udf `2f586c1` 补上并被主仓消费，原「单 sink 缺口」警示作废） | Go 级别名（`Severity::as_str`）与 Go 消息语义留主仓 |
| **配置装配** | `xray-conf`：`confloader.rs:18 load_file`/`serial.rs:185 merge_configs`+`:211 build_config`/`protocols.rs:35`（各协议 settings 结构体集）/`init.rs:34 register_builtin_stages`/`built.rs:86 BuiltConfig` | 分层装载/端口/测试替身归 udf `ConfigFile<C>`/`ConfigPort`/`MockEnv`/`parse_mock` | `BuiltConfig` 中间态 + proto 双向属 Xray 语义，留主仓 |
| **注册表族** | 生产 outbound 表 = dispatcher `SimpleOhm`（定位：`grep -n "pub struct SimpleOhm" crates/xray-app-dispatcher/src/default.rs`）；生产 inbound 表 = xray-core `InboundRuntime`（**`ohm: Arc<SimpleOhm>`** —— 与 outbound 同底座，已归一化到 udf `BoundedRegistry`；⚠️ 旧记「slots `RwLock<Vec>` / **O(n) 线性扫**」**已过期**，定位：`grep -n "pub struct InboundRuntime" crates/xray-core/src/inbound.rs`）；proxyman 只提供 handler 载体与 gRPC 命令编排（`lib.rs` 的 pub use 导出面），**无** `InboundManager`/`OutboundManager` 类型（全仓 grep 0 命中）；`TcpWorker`/`UdpWorker` 存在但生产零消费 | 走 udf `BoundedRegistry`（fail-closed insert/确定序 iter/泄漏断言）或 xray-frame `PluginRegistry` 查表 | ⚠️ **反模式警示**：注册表≠池深借还模型，`borrowed` 恒 0 = **假同构**——**禁把注册表整面 impl `PoolManaged`** |
| **中央 match 臂** ✅ 已落地（T4.2 phase 4） | 主路径已表化：`xray-core/src/arm_builders/`（BTreeMap + 显式注册，构造表 = 唯一构造路径——inbound 入口 `lookup_inbound_builder`、outbound 入口 `lookup_outbound_builder`；未命中显式失败：inbound warn+skip / outbound `BuildError::Unsupported`；旧 match 与回退 feature 已删） | 残留 = inbound unix 变体 4 臂（定位：`grep -n "match ib.entry.kind.as_str" crates/xray-core/src/inbound.rs`），收口方式 = 复用 `arm_builders::inbound` 构造函数 | **明确不用** `xray-frame::PluginRegistry`（`arm_builders/mod.rs` 「表实现选型」节：`PluginRegistry` 值类型 `Arc<dyn Plugin>` 与裸 fn 表不匹配，34 个 fn 伪造全套 Plugin 语义零增益）；wire 语义与协议特化臂 |
| **任务托管 / 停机编排** | dispatcher `background_tasks` 单把 async Mutex + 收割债（定位：`grep -n "background_tasks" crates/xray-app-dispatcher/src/default.rs`）；停机多风格并存（各组件自持停机路径，现场为准：`grep -rn "shutdown" crates/xray-core/src/inbound.rs`）；`Instance.close` 逆序无超时无隔离（定位：`grep -n "pub fn close" crates/xray-core/src/instance.rs`） | `FxScope`（spawn 唯一托管口）+ `ShutdownCoordinator`（注册窗/编排窗/超时/panic 隔离/报告） | 组件内容与停机顺序的业务语义 |

> **判定口径**：件内**无 Xray 语义**（Go 兼容语义算 Xray 语义）→ 可提炼；机制与内容分离时**机制上浮、内容留仓**。提炼走 §3.5.3 回路，件头标注 `udf-promotion-candidate`。
>
> **锚点纪律（pzjpj）**：本文档只写**符号名 + 所属 crate**；精确行号仅允许出现在**带 rev 的审计快照**里（行号随树漂移，已多轮实证腐烂）。需要定位时跑可复现命令，如 `grep -n "pub struct SimpleOhm" crates/xray-app-dispatcher/src/default.rs`。

### 3.5.5 能力归属三层判定与派生回路（ADR-1，2026-10-27 PM 拍板 · 评审打回项）

> 背景：融合度若只量"udf 依赖接地率"，会把"udf 装不下"误判成"不可迁/天花板"，于是**一批 Xray 语义机制散在主仓各 crate 各自实现**。本条是**归属宪法条款**，与 §3.5.2（禁造轮子）同级。

**三判据（顺序固定，不可跳步）**
1. 该能力是否**零 Xray 语义**（Go 兼容语义算 Xray 语义）？→ 是 → 归 **udf**（走提炼回路：独立 PR + 三平台 CI 绿 + 主仓换依赖删副本）
2. 否 → 归 **xray-frame**（派生层，**可含 Xray 语义**）——**默认答案**
3. 仅当"**连派生层都放不合适**"才留主仓，且必须**逐条举证**：反向依赖 / 破坏 udf 零依赖纪律 / 第三方栈驱动契约 / 红线文件 / 平台门控公开契约。**不举证 = 判"留主仓" = 打回**

**派生 ≠ 复制**：每件必须写清 `udf 基件 → 派生方式（trait 扩展 / 组合包装 / 新类型）→ xray-frame 派生件 → 主仓消费点`。复制同类实现 = 打回（§3.5.2）。

**优先在 xray-frame 用组合/包装实现**；确需动 udf 父仓 → 走 `n539c` 回路（独立 PR + 三平台 CI 绿 + 主仓换依赖复测 32/32），且**主仓侧 API 面不得因此变化**（将来切换零成本）。

**配套两条（ADR-2）**
- `xray-frame::compat` 进程级能力入口：只读访问 + 一次性 install + 兜底语义 = 迁移前行为；**测试隔离靠显式注入 + 互斥守卫（守卫期间串行化）**。**禁 `thread_local`**（tokio 任务跨线程迁移，thread-local 不跟随 task，语义错）
- `xray-frame::redline` 红线受控入口：治理**调用形态**，红线本体零改动；只登记真正使用逃逸口的站点（**枚举不随迁移增长**），CI 门核对"调用集合 ⊆ 登记集合"

**已定裁决**：`MergePolicy`（tag-aware 数组合并 / outbounds prepend）归 xray-frame，且必须与 udf `merge_over` 的"数组整体替换"语义**并存可见**（后者是 udf 刻意设计，不得被覆盖或混淆）；本轮**不动父仓**加 `ConfigFile::fold_with`。

**详案**（本地文档，未入库）：`docs/architecture/xray-frame-能力收敛方案-2026-10-27.md`（六面派生方案 + 8 波次实施表 + 融合度预估 57%→79%→100% 路径）

---

| 红线 | 备注 |
|---|---|
| `dist/xray.exe` | baseline 二进制 |
| `xray-transport-tcp/register.rs` | 已知债（4 维不动）|
| `vendor/` | quinn-proto patch |
| `tests/`、`.github/workflows/`、`.gitignore`、根 `cargo*` 配置 | 验证资产 |
| `docs/refs/` | 治理裁决（v1/v2/v3 + alloc-audit）|
| `docs/ARCHITECTURE.md`（**新位置**：从根移来）| 治理宪法 |
| `protos/` | Go proto 镜像——**只读** |
| `cloudflared` 配置 + cert / sing-box 二进制 | 用户自管红线 |
| `feature/framework` 分支起点 `f242e67b` | 框架资产**先验证再合 master**（d820547f 教训）|
| **udf 已有功能的重复实现** | 继承派生时禁自造轮子（§3.5.2）——评审打回项 |

**13 红线来源**：`docs/audit-架构-2026-10-12.md` §13.1

---

## 5. 已知踩坑（必须知道）

### btls-sys 冷编（5-10 min 全量重编）
- **症状**：build/main.rs:646 run() 静默早退 + bindings.rs 缺失
- **解决**：`BORING_BSSL_ASSUME_PATCHED=1` + `BORING_BSSL_SOURCE_PATH=D:/Project/Xray-core-rust/target/boringssl-patched`（**指向已打补丁树**，非主仓 out/boringssl）
- **共享**：`python tools/inject_btls_cache.py`（CI CMakeCache 注入）

### ⚠️ Windows 上 btls 无汇编 → 指纹用户慢 ~7.6×（bd jyipl，P1）
- **根因**：`btls-sys` 的 build.rs 在 Windows 分支**无条件**设 `OPENSSL_NO_ASM=YES`（注释原文：*"not set up for cross-compiling using Visual Studio. Disable assembly support so that it at least builds."*）→ `crypto/cpu_intel.cc` 被排除 → **AES-NI/AVX2 探测恒 false** → 协商 **CHACHA20** 且 chacha 也无汇编 → **纯 C 回退** → 每 record CPU ~7-11×、客户端单核打满
- **症状**：带 `fingerprint`（= 走 btls，即**所有真实节点**）的客户端吞吐塌到 31.6 MB/s；无指纹（rustls/ring）339.5 MB/s。**同一台机器、同一拓扑**，交叉配对定责在客户端侧 btls
- **解决**：`python tools/build_boringssl_asm.py`（用 `D:/Project/tools/nasm.exe` 编**带汇编**的 BoringSSL，产出 `target/boringssl-asm/prebuilt/{crypto.lib,ssl.lib,include/openssl}`），构建时加 `BORING_BSSL_PATH=<该目录>`（btls-sys 走预构建路线，**跳过 cmake → 不触发 NO_ASM**）
- **实测（vless+tcp+tls + chrome 指纹，`D:/tmp/aj0n3_ab.py`）**：31.6 → **241.2 MB/s**（best 253.0），cli CPU 18.8s → **2.48s**；REALITY 组 33.4 → **241.2**。32/32 + interop 12/12 保持
- **副作用（正向）**：开汇编后能探测 AES-NI → 协商 **TLS_AES_128_GCM_SHA256**，与 Go `crypto/tls` 偏好一致（Go 也是 AES-NI 硬件支持则优先 AES-GCM）
- **体检**：`python tools/build_boringssl_asm.py --check`（查 CMakeCache 无 `OPENSSL_NO_ASM` + `CMAKE_ASM_NASM_COMPILER_WORKS=1` + crypto.lib 大小）
- **未覆盖**：CI 的 Windows 产物仍是 NO_ASM 构建（`.github/workflows/release.yml` 直走 cargo）→ 发给用户的 Windows 版仍是慢的，见 bd `jyipl` 相邻票

### vision splice 触发逻辑（雷区）
- **历史**：d8562b56 + a427613b 双 revert
- **禁**：池化改造**不碰** vision gate/DIRECT 切换
- **池化方式**：caller-scratch + padding_scratch mem::take 容量流转（已 commit 7681f7cc）

### framework merge 摩擦（d820547f 教训）
- **症状**：poll 化全仓重编 4 轮 CI 红
- **预防**：缺**渐进开关** `#[cfg(feature = "framework-poll")]` + 缺**小步合入粒度拆分**
- **修复方向**：见 `D:/tmp/framework-tech-debt-2026-10-12.md`（v1+v2 共 30 条债）

### 整数边界（7 处 u16 截断已识）
- **VMess chunk size u16 截断静默替换 u16::MAX**——M2 onv9 短期 sync 含此条

### tcping window 钉窗（88m0 战役）
- **症状**：吞吐 = 64KB / RTT
- **修复**：TCP SO_RCVBUF 4MB 缺省（已落地 bd 88m0 + 3e755458）

### h2 窗钉（enc8x 战役）
- **症状**：hyper 默认 send_buf 400KB → min(4MB, 4MB)/0.45s ≈ 8.8 Mbps
- **修复**：客户端流窗 16MB + 服务端 send_buf 16MB

---

## 6. OMP 偏好（用户多会话重申）

| 偏好 | 出处 | 应用 |
|---|---|---|
| **"log 经常功能要调用..应该写到框架里面"** | 5 维审计 9 票审视 D1 多源验证 | 5 维报告 P1-001 + 5 维规范 P1-001 → 6su8 P3 log facade |
| **诚实交付不注水** | PM 工作流 | 子代理报告"完成"必须可验证 |
| **审计 5 维自评** | 5 维审计模板 | 所有 specialist 报告结尾必带 5 维自评 |
| **Ponytail 模式只出报告** | 5 维审计红线 | 子代理不实施修复，由 fullstack 执行 |
| **CLAUDE.md/AGENTS.md 优先于全局** | 5 维盲区债 DEBT-028 | 派单任务书必带 CLAUDE.md 路径 |
| **跨会话引用基础设施 IP 以 MEMORY.md 为准** | 5 维盲区教训 | 不信压缩摘要里的 IP 字面值 |
| **kill -9 失败先杀子进程再父进程** | 5 维盲区教训 | bash 工具的 OMP 拦截经验 |

---

## 7. 派单约定（PM 工作流）

- **3 并行上限**（实测高并发曾互斥崩盘+拖垮机器）→ 滚动补位
- **任务书 7-part contract**：目标 / 上下文 / 验收 / 非目标 / 调研源 / 目标环境 / 输出格式
- **只派自家 specialist**：architect / performance-reviewer / security-reviewer / reviewer / debugger / e2e-runner / docs-writer / test-engineer / tdd-guide / metis / momus / oracle / librarian
- **禁派** scout / fullstack-engineer 做审计
- **Ponytail 模式**：只出报告不修代码（红线外可建议改，**不实施**）
- **红线条目**（§4）= 触动一次 = 派回原 agent + 全报告重审

---

## 8. bd 票面约定

```bash
# 必用 prefix
export BD_IGNORE_SCHEMA_SKEW=1   # db v65 领先 binary v53

# 常用命令
bd list --status open
bd create --title "..." --priority N --label "audit,framework,perf,security,standards" --description "..."
bd close <id> --force  # 遇到 blocks 关系
bd update <id> --append-notes "..."  # 追加，不删历史
```

**当前标签**：`audit` / `framework` / `perf` / `security` / `standards` / `debt` / `gap` / `evaluation` / `supply-chain` / `sync`

---

## 9. 文档同步策略

- 每次新裁决（v4/v5）→ `docs/refs/` + `docs/ARCHITECTURE.md` 同步双更新
- 每次审计 → `docs/audit-*.md` 落档 + `bd update <id> --append-notes`
- 每次 commit → `git log --oneline` 简短，不写废文
- 5 维+9 票+立项级 3 份大报告**未 commit**（per 5 维审计 §14.2）—— 待 PM 评审后批量 commit

---

## 10. 给未来协作者的最快路径

1. **读完本文**（10 min）
2. **读 §3.5 三层定位与继承派生纪律**（10 min）——造件前必读，禁重复造轮子
3. **读 `docs/ARCHITECTURE.md` §0.1 三层隐喻**（30 min）—— 宪法骨架
3. **读 `docs/refs/oracle-framing-v3.md`**（1h）—— MVVM 增补裁决
4. **读 `docs/audit-立项级别-2026-10-12.md`**（30 min）—— 立项决议
5. **跑 §1 上手命令**（5 min）
6. **看 `bd list --status open`**（5 min）—— 当前在飞

总计 ~2.5 小时达到"理解项目 + 能上手"。

---

**CLAUDE.md 优先于全局 AGENTS.md 在本项目的规则**

— PM 维护，下次更新：立项级审计后任何状态变化（master commit / 5 维重审 / bd 重大决议）
