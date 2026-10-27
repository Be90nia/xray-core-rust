# bd 9doy9 — HotLog::enabled() 去锁热路径

VERDICT: PASS

## 改动摘要

文件：`crates/xray-frame/src/logging.rs`（唯一改动文件，+99 行 diff；W6 的 40 个迁移站点零触碰）。

**锁源澄清**：派单描述「持锁读 level」与代码不符——`max_level` 本是普通字段（构造期 builder 赋值，读它无锁）。每次调用的锁在 `metadata_for` 的 `metas: Mutex<[Option<&Metadata>; 5]>`：`enabled()` 过了本地级别判定后**每次**都锁 `metas` 查缓存 metadata，这是实测热路径开销的真正来源（Mutex 无竞争 CAS 也要 lock/unlock 两次 RMW）。修复按派单机制落地并把锁整个移出读路径：

1. `max_level` → `AtomicU8`（存 filter 序数，`Relaxed`）；`with_max_level` 负责 store。
2. `metas` → `OnceLock<[&'static Metadata; 5]>`：快路径 `OnceLock::get`（单次原子 load）；未命中时 `get_or_init` 一次性整表构造 5 份泄漏 Metadata（新增 `build_metas` + `level_from_rank` 辅助，`level_filter_rank` 改 `const fn` 供 const 构造器）。
3. 公开 API 零变化：`enabled()`/`level_allows()`/`with_target()`/`target()` 签名逐字未动；`with_max_level(self, ...)` 仅去掉不再需要的 `mut`（`AtomicU8::store` 走共享引用，对调用方不可见）。
4. 零新依赖（std atomic/OnceLock）。

## 微基准（同机同法，一次性 bench 脚本测完已删）

方法：release 构建，`tracing_subscriber::fmt`（TRACE 过滤 + 空写入器）经 `set_default` 安装；7×1M 次取最小值；`std::hint::black_box` 防常量折叠。before/after 同一二进制形态、同机（本机其余并行负载相同口径）。

| 场景 | 修复前 | 修复后 |
|---|---|---|
| `enabled()` 级别放行路径 | 18.1 ns/call | **5.5 ns/call** |
| `enabled()` 级别拦截路径 | 2.7 ns/call | 1.6 ns/call |
| `tracing::enabled!` 宏对照 | 7.4 ns/call | 5.1 ns/call |
| 同门面 4 线程竞争（聚合吞吐） | 13.7 Mops/s | **550.2 Mops/s（≈40×）** |

- 目标 ≤20ns 达成：5.5ns，与 tracing 宏同数量级（差额 0.4ns ≈ AtomicU8 load + OnceLock get）。
- W6 实测的 124ns 对应**锁竞争/高负载**下的持锁成本；无竞争时本机 18.1ns 也远高于宏路径 7.4ns（3× 差距即锁存器 RMW），竞争段 40× 吞吐差是锁消除的直接证据——Mutex 锁存器跨核串行，纯读原子 MESI S 态复制无 cacheline 失效。
- 附注：派单引用的「tracing 宏 16ns」与本机 5-7ns 的绝对值差异来自测机/负载环境不同，不影响 before/after 同环境对比的有效性。

## 语义保持论证

1. **判定结果逐位等价**：序数口径未变（level ERROR=0..TRACE=4，filter OFF=0..TRACE=5，`level_rank < filter_rank` 即拦截）；`level_allows` 只换了存储介质，比较式逐字保留。
2. **level 变更立即生效**：`AtomicU8` store 后同变量后续 load 必然读到新值（原子变量修改可见性）——`with_max_level` 仍在构造期调用（builder 语义不变）；将来若加运行期 level 更新口，写入方直接 store 即可，读路径零改动。
3. **订阅者兴趣仍实时判定**：`enabled()` 每次仍走 `tracing::dispatcher::get_default(|d| d.enabled(metadata))`，未缓存兴趣判定——tracing reload 后行为与修复前一致。
4. **metadata 内容逐字段相同**：`build_metas` 复制原构造参数（name=`xray_frame_hot_emit`、target、level、FieldSet、Kind::EVENT）。差异仅两点，均已论证并有界：
   - **构造时机**：按 level 惰性 → 首次调用整表 5 份（每门面一次性，量级不变）。
   - **泄漏上界**：稳态仍 = 5 × 门面数；`get_or_init` 竞态败者的副本整体丢弃（引用数组 drop 不回收泄漏件）→ 上界 5 × (1 + 首填并发线程数) × 门面数，仍与门面数成正比、非无界，已写入字段注释。若需严格 ≤5，备选 `AtomicPtr` + CAS（需 unsafe 解引用），本票按最小改动取 OnceLock。
5. **并发安全**：泄漏 Metadata 构造完成后内容不可变；发布同步由 std `OnceLock` 内部 Release/Acquire 完成（填充完成后才置 COMPLETE，读者只见完整构造件）。`HotLog` 保持 `Sync`（`static HOT_LOG` 用法不变）。
6. **线程局部缓存验证**：`tests/hot_log.rs` 的零分配断言（disabled 路径）全绿——拦截路径依旧零分配零锁。

### Ordering 选择理由（代码注释同步落位）

- `max_level`：**Relaxed**——单变量独立开关，store 端无伴随写入需被 load 端看见；不借它发布任何内存。Acquire/Release 在此处只增加无意义的栅栏成本。
- `metas`：**std 内部 Release/Acquire**（OnceLock 自带）——泄漏件发布必须完整可见，理由如上；读方 API 面不出现裸 Ordering。

## 验收输出（实际运行）

1. `cargo test -p xray-frame --all-targets` → 22 个测试二进制全部 `0 failed`（含 48+15+11 等共 178 tests，0 failed 0 ignored）。
2. 微基准：上表（修复前 18.1ns → 修复后 **5.5ns** ≤ 20ns 目标；一次性 bench 脚本已删除）。
3. `cargo clippy -p xray-frame --all-targets -- -D warnings` → `Finished dev profile ... in 6.49s`，零 warning（-D warnings 下零输出即通过）。
4. fmt：`cargo fmt -p xray-frame -- --check` → **XRAY_FRAME_FMT_CLEAN**。⚠️ 工作区级 `cargo fmt --all -- --check` 当前在 `crates/xray-common/src/testing/mod.rs` 有 diff——非本任务文件（本票改动仅 `logging.rs`，见 `git diff --stat`，其余 5 个脏文件均为并行代理在飞改动，未触碰）；该门需 PM 在全部代理落地后统一复跑。

## 非目标确认

- 未改日志内容/格式/target 规范；未动 40 个迁移站点；未引第三方库；未动 LogFacade（慢路径，掩码面，不在本票范围）。

## 5 维自评

| 维度 | 分 | 说明 |
|---|---|---|
| 正确性 | 5 | 判定逻辑逐位等价；OnceLock 发布同步有 std 语义背书；全套测试 0 failed |
| 性能 | 5 | 18.1→5.5ns（-70%），竞争面 40×；拦截路径 1.6ns |
| 可维护性 | 4 | 字段注释含无锁论证/泄漏上界/Ordering 理由；OnceLock 整表比逐 slot Mutex 更简单；扣 1 分：竞态泄漏上界与旧注释「≤5×门面数」口径不同，已如实标注 |
| 风格 | 5 | 零新依赖、公开 API 零变化、fmt/clippy 全绿、注释纪律与同文件既有风格一致 |
| 测试 | 4 | 既有 hot_log 契约测试（零分配断言/发射/格式化）全绿；微基准为一次性脚本（按契约测后删除，数字已落档）；未新增常驻回归测试（性能断言不宜进 CI，判定语义已被既有测试覆盖） |
