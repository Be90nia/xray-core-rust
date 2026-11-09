# xray-frame 强约束插件模型 + 双向依赖模型（2026-10-23 定调）

> **用户定调三条（2026-10-23 口供，本文件是这三条的落地设计）**：
> ① **udf 不锁版本，要跟着项目一起成长**——好的东西直接更新进 udf-frame；udf 有更新我们也要跟进。
> ② **插件形式 = Go 插件模式那种形态，但我们是强约束**——不是 Go 那种弱插件化；把协议里经常踩的坑**全部强约束进插件规则**，协议必须严格按规则调用。
> ③ 本轮**只做规划细化，不开工**。
> **配套**：`xray-frame-派生件全景与工作列表-2026-10-23.md`（全景与批次）｜`xray-frame-impl-plan-2026-10-19.md`（P0-P4 顺序）｜`udf-frame继承派生规划-2026-10-23.md`（A/B/C 分流）

---

## 0. 两个模型的定位

| 模型 | 解决什么 | 影响 |
|---|---|---|
| **双向依赖模型**（§1） | udf ↔ xray-frame 谁是上游、版本怎么走、CI 怎么拿料 | 推翻此前"锁 rev `f507ee23`"的规划；替代 bd `zhj8` 的三选一（不再选型，改机制） |
| **强约束插件模型**（§2） | 协议插件"必须怎么写"——把踩过的坑变成可执行条款 | 把 impl-plan 的"Plugin trait 可选装配"升级为**五层强制约束**；缺口清单 #9 从"建议"升为"CI 门" |

---

## 1. 双向依赖模型（udf 不锁版本）

### 1.1 关系与流向

```
        ┌──────────────────────────────────────────────┐
        │  udf-frame（活的上游：机制/契约/标准件/踩坑沉淀）  │
        │  ← 提炼回灌（主动，不攒批次）                    │
        │  → 更新即跟进（消费最新，不锁 rev）               │
        └───────────────▲──────────────────────────────┘
                        │ 依赖（path/CI 拉最新）
        ┌───────────────┴──────────────────────────────┐
        │  xray-frame（派生层：插件骨架 + 协议插件集）        │
        └──────────────────────────────────────────────┘
```

**三条流向规则**

| 流向 | 触发时机 | 动作 | 闸门 |
|---|---|---|---|
| xray-frame → udf（回灌） | **随时**（发现通用件即刻，不必等 P1/P3 大节点） | 件挪进 udf 对应 crate → udf 提 PR → udf CI 三平台绿 → xray-frame 换用 udf 版、**删本地副本** → 复测 32/32 | 提炼判据：零 xray 类型 + 头部 `udf-promotion-candidate` 注释 |
| udf → xray-frame（跟进） | udf 发版/合 main 后 | xray-frame 拉最新 udf → 重编 → 冒烟四线 + 32/32 回归 | udf CI 三平台绿（udf 红则不进 xray-frame） |
| xray-frame 内（新件自用） | P0/P1 建件时 | 零 xray 类型写成本地件 → 成熟后回灌 | 同提炼判据 |

### 1.2 版本策略（不锁 rev 的正确做法）

- **不写死 `rev = ...`**：规划文档旧写法（`rev = "f507ee23"`）作废。
- **主仓 `Cargo.lock` 自然记录实际解析到的 udf commit**——这就是版本锚（谁构建谁锁定，可追溯），无需人手 pin。
- **主仓 CI 拉 udf 最新**：CI 步骤在 checkout 后 clone udf 仓到 `crates/udf-frame`（工作区路径，与本地 path 依赖同构），用 udf `main` 最新。
  - ⚠️ **红线提示**：这一步要改 `.github/workflows/`（CLAUDE.md §4 红线"验证资产"）。用户已定调"udf 更新我们也要跟进"，故本项按红线流程走：**改动单独成 commit + 附全量验证报告**。
  - 风险与对冲：udf 波动会直接反映到主仓 CI。对冲 = udf 仓自身 CI 三平台绿是前置闸（udf 红 → xray-frame 不消费该 commit，主仓 CI 应显式失败并提示）。
- **本地开发**：仍是 path 依赖指向 `crates/udf-frame` 工作副本（联调即改即用），udf 更新 = `git pull` 该副本。

### 1.3 与提炼飞轮四环的对应

| 飞轮环（用户 2026-10-19 口供） | 本模型对应 |
|---|---|
| ①xray-frame 业务实现（真实需求验证） | P2 协议插件落地 |
| ②通用功能提炼上浮 udf | §1.1 流向规则 1（**主动**回灌） |
| ③udf 层做优化/性能提升 | udf 侧迭代（一次优化所有消费者受益） |
| ④发版反哺 xray-frame | §1.1 流向规则 2（跟进更新） |

### 1.4 决策留白（PM 待拍板）

- 回灌 PR 的**节奏**：随时提（用户口径）vs 每周批量？——建议随时提，udf 仓 CI 成本低。
- udf 仓"零改动"原则的例外：原 impl-plan 写"P4 之前零改动零 PR"，本模型**作废该条**（用户已授权回灌），但保留"回灌件必须零 xray 类型 + 独立 PR + CI 绿"。

---

## 2. 强约束插件模型

### 2.1 与 Go 插件模式的差异（用户口径：形似但强约束）

| 维度 | Go 插件模式（弱插件化） | xray-frame 强约束插件 |
|---|---|---|
| 接口约定 | 文档 + 自觉，运行时才知道对不对 | **必选 trait 方法集**：不实现编译不过 |
| 注册装配 | 运行时 map 注册，顺序靠自觉 | **编译期静态注册 + deps 拓扑序启动**（注册序≠启动序） |
| 能力获取 | 全局可达（随便 spawn/读全局/写文件） | **能力集受限**：`PluginContext` 暴露句柄，裸能力靠 lint 拦 |
| 违规后果 | 运行时行为错、难复现 | 编译失败 / clippy deny / 契约测试红 —— **三类都在 CI 拦下** |
| 生命周期 | 约定式（自己管 goroutine） | **三相状态机**（init/start/stop）+ 停机注册强制 |
| 协议踩坑 | 各协议自由发挥，历史坑重复踩 | **坑约束表逐条化**（§2.4，12 条） |

### 2.2 五层约束（每层给强制手段与执行位置）

| 层 | 强制什么 | 手段 | 执行位置 | 失败形态 |
|---|---|---|---|---|
| **L1 类型层** | 插件必选方法集 | `ProtocolPlugin` trait 必选方法：`contract()`（声明遵守的条款集）/`lifecycle()`/`observe_fields()`/`deps()` | `crates/xray-frame/src/plugin.rs` | 编译不过 |
| **L2 能力层** | 插件只能经受限 API 取能力 | `PluginContext` 句柄集：`spawn/log/deadline/pool/config/ids/audit/clock`；插件不持有裸 FxScope/裸 tokio 句柄 | `crates/xray-frame/src/context.rs` | 缺能力 = 编译不过（拿不到句柄） |
| **L3 lint 层** | 禁用裸能力/裸惯例 | per-crate `clippy.toml` 路径限定 `disallowed-methods`/`disallowed-macros` + 存量点 `#[allow]` 豁免并写理由（详见 §2.3；P0-6 探针定案：clippy 配置按 crate 生效，**根 `clippy.toml` 不是 L3 闸**，只承载 `allow-unwrap-in-tests`[bd g3cr]） | 各 crate 自己的 `crates/<crate>/clippy.toml`（现状 32 个 xray crate 已落） | clippy deny（CI 门） |
| **L4 契约测试层** | 每个协议插件必须过同一组断言 | `assert_plugin_contract!(P)` + 行为夹具（宏出口 `crates/xray-frame/src/contract_assert.rs`；12 条坑约束中通用行为夹具覆盖 4 条、部分覆盖 3 条，余 5 条仅声明——见该模块「条款声明态」表） | 各协议 crate 的 `tests/plugin_contract.rs`（现状 16 个 crate、63 个 `l4_*` 函数；vless/ss/trojan 3 crate 已接真实插件实例[bd 2zi1o]，其余仍是框架原语夹具；`crates/xray-frame/tests/plugin_contract.rs` 不存在，§3 表为设计目标形态） | 测试红（CI 门） |
| **L5 装配门层** | 装配期硬校验 | deps 缺失/成环 → 启动前失败；配置段缺失 → fail-fast；停机未注册 → 拒绝启动 | `crates/xray-frame/src/registry.rs` | 启动失败（fail-visible） |

**关键性质**：L1/L2 是**编译期**（最便宜），L3 是**静态**（零运行时成本），L4 是**行为**（可执行断言），L5 是**装配期**（错配早暴露）。四层叠加 = 用户要的"严格按规则调用"。

### 2.3 L3 lint 清单（建议集，逐条给依据）

| # | 禁（disallowed） | 路径范围 | 依据（约束条款/史实） |
|---|---|---|---|
| 1 | `tokio::spawn` | `crates/xray-frame/**`、`crates/xray-proxy-*/**`、`crates/xray-app-*/**` | 坑约束 §2.4-5（裸 spawn 失管，706 处存量）；替代：`ctx.spawn` |
| 2 | `tokio::time::sleep`（直接调用） | 同上 | 坑约束 §2.4-2（超时唯一入口 = deadline）；替代：`ctx.deadline` |
| 3 | `tracing::info!`/`warn!`/`error!`/`debug!` 宏 | 同上 | 坑约束 §2.4-10（日志唯一入口 = logx + 埋点 target 规范）；替代：`ctx.log()` / `logx::` |
| 4 | `println!`/`eprintln!` | 同上 | 同上（绕过掩码 = 密钥泄漏面） |
| 5 | `std::time::Instant::now`/`SystemTime::now` | 同上 | 时钟走 `clock` 契约（可测/可注入）；替代：`ctx.clock()` |
| 6 | `std::thread::spawn` | 同上 | 互喂只走 `PooledThreadPool`（RAII 归还纪律） |
| 7 | `std::fs::File::create`/`fs::write`（配置面） | 同上 | 配置只走 per-plugin 段路由（坑约束 §2.4-7） |
| 8 | `unwrap()`/`expect()`（在协议 crate 的非 test 代码） | `crates/xray-proxy-*/src/**` | 坑约束 §2.4-8（panic 不得逃逸到 IO 线程）——**注意：需谨慎排除测试与初始化期** |
| 9 | `xray_common::session::Session` 直接引用 | 协议插件层 | 坑约束 §2.4-12（session 全量上下文不可继承，只做窄投影） |
| 10 | `xray_buf::` 分配路径直调（`alloc`/`release`） | 插件层 | 坑约束 §2.4-4（缓冲必走 BufferPool 接缝，管理面继承） |

> lint 逐条落地前须验证：clippy `disallowed-methods` 支持**路径限定**（`{ path = "crates/xray-proxy-vless/**", method = "tokio::spawn" }`）；本仓工具链是 **nightly-2026-05-28**（rust-toolchain.toml 钉，CI 用 1.96.0 stable——schema 差异需实测）。**P0-6 派单时先做可行性探针**（任一字段不支持则改用 `#[deny]` + 内部 lint crate 兜底）。注意：udf 仓现役 clippy.toml 为**平铺形态**（无 path 限定），主仓若要路径限定需先实测语法可行性——**臆造 schema = 返工点**。

### 2.4 协议插件坑约束表（12 条 · 强约束核心）

> 每条 = 条款（协议必须怎么做）｜强制手段｜**本仓真实史实依据**（不是假想）｜违反后果。
> 这张表就是"把协议里经常踩的坑全部强约束到插件里面"的落地物。

| # | 条款 | 强制手段 | 本仓史实依据 | 违反后果 |
|---|---|---|---|---|
| 1 | **认证/校验失败必须返回统一错误分类**，禁止静默放行或自定义错误码 | L1 `ErrorKind` + L4 断言 | vless/trojan/ss 认证拒绝日志级别与 Go 对齐轮（`AtInfo` 口径） | 安全事件被吞，审计失真 |
| 2 | **握手/首包必须带 deadline**，禁止无限等待 | L2 `ctx.deadline()` 唯一入口 + L3 禁裸 sleep | `xray-app-reverse/timer.rs:35` InactivityTimer 缺 set_timeout 回调（Go CancelAfterInactivity 等价件缺失） | 慢速攻击面/资源挂死 |
| 3 | **每条连接必有 conn_id**（观测可追溯） | L1 必选 + L4 断言 | observe 件需求（conn_id/stage/peer/dest 字段模板） | 线上问题无法定位 |
| 4 | **缓冲必须走 BufferPool 接缝**，禁止绕过池直接分配 | L3-10 + 池审计断言 | **from_vec 假池污染**：假块被标 Pooled 经 TLS_CACHE 粘死 worker 线程 → per-node 选择性死 | 隐蔽的 per-node 死亡 |
| 5 | **异步任务必须托管**（FxScope），禁止裸 spawn；**组件自有账本唯一形态 = `xray_frame::scope::ComponentScope`**（ADR-0004）：`close_gate`（关闸档，Go 口径不杀已建立连接）/ `drain`（排空档，唯一「在途归零」口）两词分档禁混用；禁自引用环（被托管任务不得持所在账本 owner 强引用）；禁伪 Drop-abort 断言文案（A5 静态门 `tools/check_scope_claims.py`）；`live_refs()` 诊断面证伪环（A4） | L3-1 + L4 `in_flight` 归零断言 + B3 静态门 | 706 处裸 spawn 失管（存量计数引自旧规划，未复数）；12 处组件 scope 持有件三派语义分裂 + splithttp/tun 自引用环使 Drop-abort 恒不可达（ADR-0004，bd os4kz / hnicl） | 任务泄漏 / 停机不干净 / 停机语义随 crate 漂移 |
| 6 | **停机必须注册**到 ShutdownCoordinator | L1 `lifecycle()` + L4 注册断言 | 各处自拼停机序（`ShutdownCoordinator` 编排纪律现成） | 停机挂死/资源泄漏 |
| 7 | **配置必须走 per-plugin 段路由 + ConfigPort**，禁止读全局/读文件 | L2 `ctx.config()` + L3-7 + L5 缺段 fail-fast | `xray-conf` 三格式+built 中间态；udf `ConfigFile` 无段路由语义（缺口 #7） | 配置错配在运行期才炸 |
| 8 | **错误必须归类；panic 不得逃逸到 IO 线程** | L4 断言（panic 隔离） | v49/v50/v52 三轮挂死战役：poll_write 丢唤醒、包装层 flush Pending 语义 | 连接级崩溃扩散 |
| 9 | **资源必须上有界**（连接表/会话表/队列） | L4 断言 + 规范（禁无界结构） | `BoundedRegistry` fail-closed 先例；ws/tuic/splithttp 三处自有池 | 内存无界增长 |
| 10 | **日志必须走 logx + 埋点 target 规范 `xray_frame::<域>`** | L3-3/4 + L4 字段断言 | 642 处散装 log（未复数）；目标 = 装配/插件层唯一入口 | 日志无法按域治理/审计 |
| 11 | **密钥必须掩码**（`mask_secrets` 布点） | L4 断言 | `xray-app-log/mask.rs:279` 掩码面；logx 提供 `mask_secrets` | 密钥泄漏到日志 |
| 12 | **数据面热路径零改动**（buf/copy/splice/poll 语义） | L5 + code review 门（不可 lint） | vision splice gate 双 revert（d8562b56 + a427613b）；bridge.rs 三轮战役战场；性能锚 154-167 MB/s | 吞吐/挂死回归 |

> **条款的落地形态**：L4 契约测试夹具把这 12 条做成**可执行断言**（每条至少一条断言）；L3 lint 覆盖能静态检的 10 条；余下（12）靠 review 门 + 装配门。
> **协议专属坑**（不进通用表，留在协议插件自己的 `contract()` 声明里）：mux carrier 判据 = destination 域名（不校验 VLESS command）｜VMess chunk size u16 截断禁止静默替换 u16::MAX｜u16/u8 边界必须显式检查而非饱和。

### 2.5 协议插件的强约束契约形态（v0.1）

```rust
// 目标形态（草案，落码由 P0-1 派单细化；此处只定约束语义）
pub trait ProtocolPlugin: Send + Sync {
    // 必选：插件身份与依赖声明
    fn name(&self) -> &'static str;
    fn version(&self) -> &'static str;
    fn deps(&self) -> &[PluginDep] { &[] }

    // 必选：声明本插件遵守的坑约束条款集（12 条中适用的子集 + 协议专属条款）
    fn contract(&self) -> &PluginContract;

    // 必选：生命周期三相（init/start/stop），stop 必注册到 ShutdownCoordinator
    fn lifecycle(&self) -> &dyn Lifecycle;

    // 必选：装配入口——只经 ctx 取能力
    fn build(&self, ctx: &mut PluginContext) -> Result<(), PluginError>;
}
```

- `PluginContract` = 条款声明结构（适用条款 id 列表 + 协议专属条款），**可被夹具校验**（声明了却没实现 = 契约测试红）。
- 强约束的落点：**协议不能"选择遵守"**——L1 让条款声明成为必填，L4 让声明与实现一致性成为断言。

---

## 3. 契约测试夹具设计（L4）

夹具宏出口在 `crates/xray-frame/src/contract_assert.rs`，夹具文件落在各协议 crate 的 `tests/plugin_contract.rs`（现状 16 个 crate；`crates/xray-frame/tests/plugin_contract.rs` **不存在**——本节初稿误记）。下表为**设计目标形态**：已落码 = `assert_plugin_contract!` 与 4 个行为夹具（`assert_conn_id_present!`/`assert_deadline_effective!`/`assert_log_fields!`/`assert_pool_discipline!`）；`assert_registered!`/`assert_lifecycle_order!`/`assert_error_classified!`/`assert_inflight_zero!` 未落码：

| 夹具 | 覆盖条款 | 断言要点 |
|---|---|---|
| `assert_plugin_contract!(P)` | 全部适用条款 | 12 条逐条断言（按 `P.contract()` 声明的适用集） |
| `assert_registered!(P)` | L5 | 注册可见、deps 序正确、缺依赖 fail-visible |
| `assert_lifecycle_order!(P)` | 坑约束 6 | init→start→stop 序；stop 注册进 coordinator；超时/panic 隔离 |
| `assert_error_classified!(P)` | 坑约束 1/8 | 认证失败/非法输入 → 统一 ErrorKind；panic 不逃逸 |
| `assert_deadline_effective!(P)` | 坑约束 2 | 超时真发生（真超时必红，不放宽） |
| `assert_conn_id_present!(P)` | 坑约束 3 | 每连接有 id，观测字段齐 |
| `assert_pool_discipline!(P)` | 坑约束 4/9 | 借还配平、无越界集合 |
| `assert_log_fields!(P)` | 坑约束 10/11 | target 前缀 `xray_frame::`、字段模板齐、密钥已掩码 |
| `assert_inflight_zero!(P)` | 坑约束 5 | 停机后 in_flight 归零 |

- 协议 crate 以 **dev-dependency** 引 xray-frame（避免运行期依赖环）。
- 夹具只断言**可观察行为**，不窥探内部实现（守"测行为不测实现"）。

---

## 4. 插件能力获取规则（能碰什么 / 不能碰什么）

| 能力 | 获取方式 | 禁止的等价写法 |
|---|---|---|
| 异步托管 | `ctx.spawn(fut)` → 走 FxScope | `tokio::spawn` / `std::thread::spawn` |
| 日志与埋点 | `ctx.log()`（logx 门面 + `xray_frame::<域>` target） | `tracing::info!` / `println!` |
| 超时 | `ctx.deadline(d)` / `ctx.with_deadline(fut, d)` | `tokio::time::sleep` / 自建 timer |
| 时钟 | `ctx.clock()`（可注入，测试确定性） | `Instant::now` / `SystemTime::now` |
| 缓冲 | `ctx.pool()`（BufferPool 接缝 + PoolBase 管理面） | 直接 `xray_buf::alloc` |
| 配置 | `ctx.config()`（per-plugin 段路由 + ConfigPort） | 读全局 config / 读文件 |
| 标识 | `ctx.ids()`（conn_id 生成） | 自造 id 生成器 |
| 审计 | `ctx.audit()`（审计事件流） | 裸 tracing 事件 |

---

## 5. 对既有规划条目的影响（升级 / 作废 / 新增）

| 原条目 | 处置 | 说明 |
|---|---|---|
| impl-plan「udf-frame 仓库 P4 之前零改动、零 PR」 | **作废** | 用户授权主动回灌；改为主动提炼 + 独立 PR + CI 绿 |
| 继承派生规划「rev 锁 f507ee23」 | **作废** | 改 §1.2 不锁 rev，Cargo.lock 记录 |
| bd `zhj8`（依赖形态三选一） | **改写** | 不再选型；改为 §1.2 的 CI 拉最新 + 工作副本 path 依赖 |
| 缺口清单 #9「插件契约测试模板」 | **升级为 L4 强制门** | 每协议插件必须调用夹具，缺 = CI 红 |
| 缺口 #7「per-plugin 配置段路由」 | **升级为 L5 装配门** | 缺段 fail-fast 在启动期 |
| 缺口 #5「生命周期状态机」 | **升级为 L1/L4 强制项** | 三相 + 停机注册为必选 |
| — | **新增 L2 能力层 / L3 lint 层** | 强约束的骨架：受限 API + 静态禁令 |
| — | **新增协议坑约束表 12 条** | 用户诉求②的直接落地物 |

---

### 5.5 三层定位与归一化面（用户 2026-10-23 定调，已同步进 CLAUDE.md §3.5）

**三层比喻**：**udf = 地基**（机制/契约/标准件/踩坑沉淀，零业务语义）｜**udf-frame = 骨架**（独立仓，机制与规范的演进场所，跨项目复用）｜**xray-frame = 硬装血肉**（Xray 特有协议插件/装配/硬连接入）。依赖单向：血肉 → 骨架 → 地基；反向只走提炼回路。

**禁重复造轮子**（评审打回项，已入 CLAUDE.md §3.5.2）：udf 已有功能时只允许三种做法——直接用 / 继承派生（实现 udf 契约或组合其组合件）/ 回灌提炼；**禁止在主仓复制一份**。确需例外须写明「udf 为什么不适用」的一行判定 + 标注提炼候选。

**归一化面**（用户点名 json 工具壳与 log 都要用 udf 改造规范使用）——首批提炼回路实战件：

| 面 | 主仓现状 | 上浮目标 | 留仓的 Xray 语义 |
|---|---|---|---|
| JSON 工具壳 ✅ 已归一化（P1-9） | 实体机制已上浮 udf `std_ext::json`（`decode`/`decode_str`/`decode_slice` + `JsonMode`）；主仓 `xray-conf/src/json.rs` 只剩 Xray 语义薄壳（4 个 `decode_json*` 按 env 切 strict 转调 udf） | ——（已完成） | Go 兼容序列化（`serial.rs` `to_json_string` 的 `JSONMarshalWithoutEscape` + 4 空格缩进） |
| 配置 lint 阶段编排 | `xray-conf/src/lint.rs`：`LintStage` trait + 全局注册表（:95）/`post_process`(:117，阶段锁外执行) | udf「端口+注册表+阶段编排」件 | 阶段内容（Xray 配置语义） |
| 日志 Handler 分发 + 双写 ✅ 已归一化（P1-10-b） | 旧 `HANDLERS` 扇出 + tracing 双写已删；主仓 `xray-common/src/log/mod.rs` 收敛为 udf `logx::ChannelRegistry` 单入口（general/access/dns 三通道，`register_channel` 装配期注册） | ——（已完成；udf 多通道 sink 已由 udf `2f586c1` 补上并被主仓消费，原「单 sink」警示作废） | Go 级别名（`Severity::as_str`）与 Go 消息语义 |
| 配置装配 | `xray-conf`：`confloader.rs:18 load_file`/`serial.rs:185 merge_configs`+`:211 build_config`/`protocols.rs:35`/`init.rs:34 register_builtin_stages`/`built.rs:86 BuiltConfig` | udf `ConfigFile<C>`/`ConfigPort`/`MockEnv`/`parse_mock` | `BuiltConfig` 中间态 + proto 双向 |
| **注册表族** | 生产 outbound 表 = dispatcher `SimpleOhm`（`xray-app-dispatcher/src/default.rs`，parking_lot RwLock<HashMap>）；生产 inbound 表 = xray-core `InboundRuntime`（slots `RwLock<Vec>`，contains/remove **O(n) 线性扫**）；proxyman **无** `InboundManager`/`OutboundManager` 类型（全仓 grep 0 命中），`TcpWorker`/`UdpWorker` 存在但生产零消费；`xray-features/src/registry.rs` FeatureFactory | 注册表 ≠ 池深借还模型（`borrowed` 恒 0 = **假同构**）→ 走 `BoundedRegistry`（fail-closed insert / 确定序 iter / 泄漏断言）**或** xray-frame `PluginRegistry` 查表；**禁整面 impl `PoolManaged`** | 协议 handler 语义、动态增删需求、gRPC 动态注册与 Go 无上限行为的偏差 |
| **中央 match 臂** ✅ 已落地（T4.2 phase 4） | 主路径已表化：`xray-core/src/arm_builders/`（BTreeMap + 显式注册，唯一构造路径——`lookup_inbound_builder` / `lookup_outbound_builder`，未命中显式失败；旧 match 已删） | 残留 = inbound unix 变体 4 臂（`match ib.entry.kind.as_str`），收口 = 复用 `arm_builders::inbound` 构造函数 | **明确不用** `PluginRegistry`（`arm_builders/mod.rs` 「表实现选型」节：值类型不匹配 + 34 fn 伪造全套 Plugin 语义零增益）；wire 语义与协议特化臂 |
| **任务托管 / 停机编排** | dispatcher `background_tasks` 单把 async Mutex + 收割债（定位：`grep -n "background_tasks" crates/xray-app-dispatcher/src/default.rs`）；停机多风格并存（token-select/notify/abort，现场为准）；`Instance.close` 逆序无超时无隔离（定位：`grep -n "pub fn close" crates/xray-core/src/instance.rs`） | `FxScope`（spawn 唯一托管口）+ `ShutdownCoordinator`（注册窗/编排窗/超时/panic 隔离/报告） | 组件内容与停机顺序的业务语义 |

> 判定口径：件内**无 Xray 语义**（Go 兼容语义算 Xray 语义）→ 可提炼；机制与内容分离时**机制上浮、内容留仓**。

---

## 6. 规划未决项（下一轮细化要填）

1. `PluginContract` 的条款 id 集合与声明格式（草案见 §2.5，需与 P0-1 派单契约对齐）
2. `PluginContext` 能力集的具体 API 签名（spawn 返回句柄语义、deadline 组合子、pool 句柄泛型）
3. clippy.toml 路径限定 `disallowed-methods` 的 schema 实测（Rust 1.96）
4. P2 协议插件的**协议专属条款**清单（每族一张，随该族迁移任务书写）
5. 契约测试夹具的**跨 crate 组织**（xray-frame 提供夹具，协议 crate 调用——dev-dep 环风险验证）

— PM 定调文档 · 2026-10-23 · 配套契约级任务书见同目录
