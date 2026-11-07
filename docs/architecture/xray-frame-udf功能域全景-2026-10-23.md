# udf-frame 功能域全景 × 主仓覆盖对照（2026-10-23）

> **用户问**：udf 除了 DNS / inbound / outbound 还有什么功能？
> **答**：udf **没有** DNS 解析、inbound/outbound handler、路由、传输、TLS 这些**协议/业务域**——它是**机制层**（地基）。共 **32 个公开模块域 / 20,257 行 / 8 类机制**。主仓目前真正用上的只有 4 条类型可见性冒烟线，**可白拿但还没用上的域有一大批**（fsx / id / hash / encode / iter / text / ratelimit / paths / clock / journal / backoff …）。
> **来源**：`docs/research/xray-frame-udf机制差距-2026-10-23.md` §1 全集表（49 个 src 文件逐行扫描）＋ `docs/research/xray-frame-主仓能力盘点-2026-10-23.md`（53 crate）｜api 位置以 `crates/udf-frame/` 相对路径给出

---

## 0. 一句话定位

| 层 | udf 是什么 | 不是什么 |
|---|---|---|
| **机制层（地基+骨架）** | 数据流契约、异步托管、停机编排、池化、状态持久化、观测、内存治理、13 域通用散件 | **不解析 DNS、不认 inbound/outbound、不路由、不传字节、不碰 TLS** |
| 主仓（血肉） | 协议语义、装配、硬连接入 | —— |

---

## 1. udf 全域清单（32 域）

### 1.1 skeleton 契约层（零依赖零 feature，5 模块）

| 域 | 件（位置） | 公开 API 要点 | 主仓受益面 |
|---|---|---|---|
| **数据流** | `Reducer`（lib.rs:86） | `initial()`/`reduce(&state, action, &mut EffectBuf)->State`；**纯函数禁 IO 是编译期保证**（零依赖） | 插件逻辑层状态迁移 |
| | `Effect`/`EffectBuf`/`EffectId`（:117/:148/:122） | 三变体 Emit/Run/Cancel；EffectBuf clear 保容量 | 插件效果词表（宿主定义） |
| | `Store`（:395） | dispatch/snapshot/subscribe/sender/close/is_closed；**非 dyn-safe**（subscribe 泛型参） | 装配层状态环 |
| | `ActionSender`（:227） | `dispatch(A)->bool`，`#[must_use]` 停机显式化 | 异步侧回灌 |
| | `EffectRuntime`（:204） | 解释器可插拔（`NoFx` 缺省 / `fx` 真实现 / `ScriptedRuntime` 脚本） | **效果托管插件化**：同 reducer 词汇换后端 |
| | `Driver`/`Subscription`（:354/:315） | 下行呈现 + 变更通知；票据 Drop=注销，`#[must_use]` 拦裸调用 | 配置热更推送（当前主仓无消费位） |
| | `JournalPort`/`Restore`（:503/:526） | append/persist_snapshot/restore，后端自换 | 插件状态持久化 |
| **基础端口** | `Clock`/`SystemClock`/`MockClock`（clock.rs:56/82/128） | now_instant/now_system 双面；MockClock 冻结+advance = **确定性时间线地基** | deadline/重试/调度/测试全靠它 |
| | `EnvSource`/`StdEnv`/`MockEnv`（config.rs:92/123/157） | env 读取，NotUnicode 保真原始字节 | 配置 env 覆盖口 + 测试注入 |
| | `ConfigPort`/`ConfigError`（config.rs:259/276） | 缺必填报 Missing（**禁静默默认**）；错误 Display 含键名 + source 链 | 每插件一个配置口 |
| | `LogPathResolver`（logpath.rs:23） | log_root() | 装配层日志根目录 |
| | `Json`/`JsonPort`（parse.rs:42/97） | 保序 JSON 值面 + encode/decode 端口 | **udf 侧 JSON 面现成**（但无 strict 解码与 64MB 上限 → 见归一化面） |
| | `SqlDialectPort`/`MarkdownPort`（parse.rs:157/283） | SQL 方言/Markdown 事件流端口 | 主仓无消费位（未来可接 stats 导出） |
| **池契约** | `PoolManaged`/`PoolMetrics`/`PoolResizeError`/`PoolAudit*`（pool.rs:237/42/64/104/120/132） | 三挂点 resize/metrics/subscribe_audit；Borrow 核心形 | 资源型插件统一管理面 |

### 1.2 skeleton-infra 实现层（14 域，13 feature 门 + full）

| 域 | 件（位置） | 白拿什么 | 主仓受益面 |
|---|---|---|---|
| **停机编排** | `ShutdownCoordinator`（shutdown.rs:257） | 注册窗（Closed/Duplicate 显式拒）+ 编排窗（注册序串行/逐组件超时/panic 隔离/报告） | 宿主停机三段式（替掉主仓三风格并存） |
| **异步托管** | `FxScope`（fx.rs:199）+ `Spawned`/`CancelToken`/`CancelSource`/`expect_idle`/`TaskError` | spawn 唯一托管口、闸关显式拒、`in_flight` 归零泄漏断言 | 替掉裸 spawn（706 处存量）与 dispatcher background_tasks 收割债 |
| **状态环** | `SyncStore`（runtime.rs:233） | 同步排空环 + 回灌预算 64 + 计数读侧族（subscriber_count/pending_actions/reducer_panic_count/feedback_budget_exceeded…） | 装配层共享态（注册表/连接表/统计快照） |
| **持久化** | `Journal`/`JsonlJournal`（journal.rs:155/238） | 先落盘后 apply；`open` 崩溃残行截断 fail-visible；`with_snapshot_every`；`skipped_unknown` 计数 | **主仓当前无状态持久化 → 新能力** |
| **池化** | `PoolBase`（pool.rs:99） | 校验（max==0/idle_cap==0/idle_cap>max 三类恒不合法，构造 panic / 运行 Err 两档出口）+ 水位线 O(1) + 审计 seq 环 + 溢出丢弃计数 + 借还记账 | 连接池管理面（ws/tuic/xmux/preconnect） |
| | `MemoryPool<T,F>`（memgov.rs:441） | **acquire 超时必填**（D21）+ RAII `PoolGuard` 只还真借的 + panic 自动还 + align(64) 防伪共享 | 装配层非热路径池（连接表/会话缓存/插件态） |
| | `ThreadPool`（pool.rs:570） | 三参封顶 core/max/queue_cap、零自旋 condvar park、**优雅缩容**（执行中任务必跑完）、需求性扩容、worker panic 摘除池不砖 | CPU 密集同步段（geodata/规则匹配/DNS 启动期） |
| | `RejectPolicy` 四件套（pool.rs:403-459） | Abort/CallerRuns/Discard/DiscardOldest；`on_reject` 锁外调用；`PoolHandle` 封死策略自指递归 | 池满时的显式拒绝语义（主仓各池自造） |
| | `PooledThreadPool<T,F>`（pooled_thread_pool.rs:67） | **worker 内借缓冲 → 跑 → RAII 还**（构造期 borrow_timeout 必填） | **双池互喂的载体**（数据面缓冲 ↔ 装配层任务） |
| **观测栈** | `logx`：`init_tracing_default`/`init_tracing_from_env`/`init_with_file`/`FileSink`（按日懒开 + `dropped_lines` 计数）/`FileSinkWriter`/`DefaultPathResolver`/`mask_secrets` | 唯一日志入口 + 密钥掩码 + 丢弃可见 | 642 处散装 log 收敛（**⚠️ 单 sink，无 general/access/dns 多通道 → udf 侧需先扩**） |
| | `embed_event!` 宏（lib.rs:53-76） | 埋点纪律：只埋行为决策点 + 字段化禁格式化 + target `skeleton::<域>`；feature 关=宏消除 | 埋点 target 规范 `xray_frame::<域>`（**宏是文本作用域双副本，需单源化**） |
| | `bridge_events_to_tracing`（tracingx.rs:45） | 审计事件流→tracing 桥（常挂 ~21ns） | observe 件数据源 |
| | `AuditEvent`/`AuditTicket`（audit.rs:39/97） | seq + kind 生命周期事件（Dispatch/ReducerPanic/RuntimePanic/FeedbackBudgetExceeded…） | 观测/审计面 |
| **内存治理** | `BoundedRegistry`（memgov.rs:50） | fail-closed insert + **升序确定序 iter** + 泄漏断言 + `Eviction::{Reject,PopFirst}` | 注册表族（**≠池模型，见反模式**） |
| | `CountingAllocator`（memgov.rs:131） | live_bytes/live_allocs/peak/total 五计数器 | 基准与泄漏测量（主仓已有同款，重复面） |
| | `LeakGuard`/`LeakReport`/`expect_empty`（memgov.rs:233/287/296） | arm/check 泄漏断言 | 测试形态 |
| **组合器** | `combine`/`Combine`（compose.rs:97/246） | 父子分片（闭包五件套）、零 dyn 零装箱、`initial` panic「分片非根」 | 插件状态分片（32 协议是否走此形态 = P2 留白） |
| **配置装配** | `ConfigFile<C>`（config.rs:108）+ `load_toml`/`save_toml` | 分层折叠（low→high）+ default_layer/file_layer + serde_json::Value 统一值面 | 主仓 xray-conf 的层叠装载面（**BuiltConfig 中间态留主仓**） |
| **测试替身** | `TestStore`/`ScriptedRuntime`/`Script`/`ExpectedEffect`（testing.rs:181/104） | 效果 FIFO 逐条断言 + 脚本化解释器（Emit/Panic/Never） | 插件 reducer 逐动作断言 |
| | `MockJson`/`MockSqlDialect`/`MockMarkdown`/`MockParseError`（parse_mock.rs） | 脚本化解析替身 | 解析面测试 |

### 1.3 std-ext 十三域（默认全开）

| 域 | 关键件 | 白拿什么 | 主仓受益面（**多数尚未接线**） |
|---|---|---|---|
| `backoff` | `backoff_delay`(:32) | 线性退避 `min(base*n, max)` + 埋点 | 替主仓自造退避 |
| `cache` | `LruCache`(:339)、`TtlCache`(:438) | O(1) arena 双向链零 unsafe；Ttl 惰性过期 + Clock 注入（ttl==0 fail-fast） | **DNS 缓存**、key cache、geo weak cache（三处自造 → 收编） |
| `clock` | `format_duration`(:42) + `rfc3339` 子模块(:86) | RFC3339 双向恒 UTC | 时间戳/日志时间格式（主仓 Record 用 SystemTime::now） |
| `encode` | hex（:103/:133）、base64（:249/:307）、`strip_bom`(:440)、`detect_unicode_scheme`(:474)、UTF-16 编解码(:549/:583) | 显式策略禁静默（BOM 矛盾 Err） | **ss2022 等协议** hex/base64、订阅/流量解析 |
| `fsx` | `walk`(:148，max_depth/min_depth/follow_links/sort)、`copy_tree`(:545)、`rm_all`(:700)、`TempDir`(:777)、`atomic_write`(:59) | **崩溃安全原子写**（同卷 rename）+ 目录遍历 + 临时目录显式清理 | **geodata 原子更新**（app-geodata swap）、loader 遍历、临时文件 |
| `hash` | `stable64`(:104, FNV-1a 64 RFC 9923)、`xxh64`(:212) | **算法集版本化 = 输出永不变承诺** | conn_id 指纹派生 |
| `id` | `IdGen`(:236)、`Id(u128)`(:139) | UUIDv7 确定性变体 RFC 9562 + 指纹 + **同毫秒 4096 配额 fail-closed** | **conn_id 生成**（替主仓自造 uuid） |
| `iter` | `zip_longest`/`interleave`/`minmax`/`dedup`/`process_results` | itertools 语义子集 | 通用迭代（零成本白拿） |
| `paths` | `normalize_lexical`(:133)、`simplify`(:204)、`ensure_inside`(:328)、`home_dir`/`config_dir`/`cache_dir`/`data_dir` | dunce 同形 + XDG + **containment 校验** | 路径规范化（主仓 paths 域重复面） |
| `ratelimit` | `TokenBucket`(:163) | 令牌桶 + MockClock 确定性 + 零自旋 | **主仓限流缺位 → 直接补位**（异步用 try_acquire + FxScope 定时） |
| `retry` | `RetryPolicy`(:89)、`retry`/`retry_if`(:220/:245)、`Sleeper`(:66) | 次数/退避/总预算 + Exhausted/OutOfBudget 双失败分类 + 足额等待禁缩短 | **DNS 上游重试**、下载重试（app-geodata） |
| `scheduler` | `Scheduler`(:206)、`TaskHandle`(:504)、`WorkerHandle`(:536) | after/every/tick/next_deadline/close + `panic_count` + `worker_passes` 零自旋证据 + 优雅 join | accept 辅助、deadline、定时任务（fakedns 回收/hosts 刷新） |
| `text` | `decode_bytes`(:57, 严格/损失化显式选择)、`truncate_chars`(:95)、大小写转换(:275)、`edit_distance`(:361) | UTF-8 边界安全 | 文本处理面 |

---

## 2. 覆盖对照：主仓哪些面 udf 能接管

| 主仓面 | udf 依托件 | 判定 |
|---|---|---|
| 装配/状态共享 | `SyncStore`/`Store`/`JournalPort`/`JsonlJournal` | A 直接用（+ 新增持久化能力） |
| 协议注册与分发 | **udf 无** → xray-frame `PluginRegistry`（自建，C） | C 自有 |
| DNS 解析本体（DoH/DoT/hosts/fakedns） | **udf 无 DNS 域** → 留主仓 | 留仓；其缓存/重试/调度/时钟 → udf（`TtlCache`/`RetryPolicy`/`Scheduler`/`Clock`） |
| 路由引擎 | **udf 无** | 留主仓（规则匹配 CPU 密集 → `PooledThreadPool` 互喂） |
| 连接池（ws/tuic/xmux/preconnect） | `PoolBase` 组合 + `MemoryPool` + `BoundedRegistry` | B 继承派生 |
| 任务托管 | `FxScope` + `CancelToken` + `expect_idle` | A 直接用 |
| 停机编排 | `ShutdownCoordinator` | A 直接用 |
| 日志 | `logx` + `mask_secrets` + `FileSink` + `embed_event!` + `bridge_events_to_tracing` | A 直接用（**需先扩多通道**） |
| 统计/观测 | `AuditEvent` + `PoolMetrics` + `CountingAllocator` | A 直接用（统计语义留主仓） |
| 配置装配 | `ConfigPort`/`ConfigFile`/`EnvSource`/`MockEnv`/`parse_mock` | A/B |
| 超时/定时 | `Clock`/`MockClock`/`Scheduler` + xray-frame `deadline.rs` | A/B |
| 重试退避 | `RetryPolicy`/`backoff_delay`/`Sleeper` | A 直接用 |
| 限流 | `TokenBucket` | A 直接补位（主仓缺位） |
| 缓存 | `LruCache`/`TtlCache` | A（收编三处自造） |
| ID 生成 | `IdGen` + `hash::stable64` | A（替自造 uuid） |
| 编码 | hex/base64/BOM/UTF-16 | A（ss2022 等） |
| 文件系统 | `fsx`（原子写/遍历/TempDir） | A（geodata 更新） |
| 路径 | `paths`（含 `ensure_inside` containment） | A |
| 文本 | `text` | A |
| 迭代 | `iter` | A |
| 内存治理 | `CountingAllocator`/`LeakGuard`/`BoundedRegistry` | A |
| 测试 | `TestStore`/`ScriptedRuntime`/`MockEnv`/`MockClock`/`MockJson` | A（dev-dep） |
| 传输层 / TLS / REALITY / 协议 wire | **udf 无，且红线禁动** | 不动 |

---

## 3. udf 完全没有、必须 xray-frame 自建的（C 类）

1. `Plugin` trait + `PluginRegistry`（含 deps 拓扑序）
2. `PluginContext` 能力句柄集
3. `PluginError` + `ErrorKind`
4. 生命周期三相状态机（init/start/stop，udf 只有 stop 半边）
5. handler trait + 查表分发（唯一含 xray 类型的件）
6. per-plugin 配置段路由（`ConfigFile` 是整体层叠，无段路由）
7. version 兼容语义
8. 插件契约测试模板
9. `accept.rs` / `deadline.rs` / `observe.rs` / `reload.rs` / `pool.rs`（BufferPool 接缝）

---

## 4. udf 有、但主仓**完全没用上**的高价值域（优先接线候选）

| 序 | 域/件 | 主仓对应重复面 | 收益 |
|---|---|---|---|
| 1 | `fsx::atomic_write` + `walk` + `TempDir` | app-geodata 下载更新、loader 遍历、临时文件 | 崩溃安全（半写文件不再毒化） |
| 2 | `id::IdGen` + `hash::stable64` | 自造 uuid（xray-common uuid） | 同毫秒 4096 配额 fail-closed；指纹可复现 |
| 3 | `cache::TtlCache` + `cache::LruCache` | DNS cache_controller、key_cache、geo weak_cache 三处自造 | TTL/Clock 注入可测；统一读侧 |
| 4 | `retry::RetryPolicy` + `Sleeper` | DNS 上游重试、geodata 下载重试 | 预算/双失败分类/确定性时间线 |
| 5 | `ratelimit::TokenBucket` | **全仓缺位** | 直接补位 |
| 6 | `scheduler::Scheduler` | accept 退避、fakedns 回收、hosts 刷新 | 零自旋 + panic_count 证据 |
| 7 | `encode`（hex/base64/BOM/UTF-16） | ss2022 等协议编码 | 显式策略禁静默 |
| 8 | `text` + `iter` + `paths` | 文本处理/迭代/路径 | 零成本白拿 |
| 9 | `Journal`/`JsonlJournal` | **主仓无状态持久化** | 新能力（插件态/统计快照可回放） |
| 10 | `compose::combine` | — | 插件状态分片机制（P2 留白项的候选底座） |

---

## 5. 反模式警示（三条）

1. **注册表 ≠ 池模型**：主仓四套注册表（dispatcher `SimpleOhm`、xray-core `InboundRuntime`、proxyman Managers、features `FeatureFactory`）是"插入后常驻 + 按 key 查找 + 显式 remove"模型，与 `PoolManaged` 的"池深 + 借还"**不同构**（`borrowed` 恒 0 = 假同构）→ 走 `BoundedRegistry` 或 xray-frame Registry，**禁整面 impl PoolManaged**。
2. **udf 侧空白 ≠ 可以留副本**：udf 没有严格 JSON 解码、没有多通道日志 sink——这是"该提炼上浮"的信号（归一化面），不是"主仓自造即可"的许可。
3. **宏与双副本**：`embed_event!` 是文本作用域双副本（infra + std-ext 各一份），xray 侧接入需**单源化**或自备同款——复制第三份即违反 §3.5.2。

— PM 汇总 · 2026-10-23 · api 位置以 crates/udf-frame/ 相对路径给出
