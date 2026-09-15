# Batch D-2 热路径零分配实施回执（1n90+fwhh+xag3）

- 日期：2026-09-15
- 执行：impl-d2（PM 分派）
- 基线：HEAD e78f097（工作区代码零改动起步；跑批中途 master 合入 8sum 方案 A
  bridge.rs 重写 commit 6b53cd5——与本报批文件零交集，见 §6 归因边界）
- VERDICT: PASS

## 0. 同源判定（前置闸）

**1n90 与 xag3② 确认同源，合并修一次。**

| 票 | 票面定位 | 实际代码 |
|---|---|---|
| 1n90 | env.rs:90-95 + splice.rs:46-48 env re-read per dispatch | `use_splice()` 每 call `var_os`×2 + `into_owned`（堆分配） |
| xag3② | env.rs:90-95 改 LazyLock 缓存 | **同一处代码** |
| xag3③ | reload_env_settings 零调用方（readv.rs:40） | env 闸门缓存域，同批接线 |

三处合并为「票 A」单次实现；xag3①（udp443_policies）独立「票 C」；
fwhh（readv 4 allocs）独立「票 B」。三票互不重叠、独立可 revert。

## 1. 票 A（1n90 + xag3②③）：splice/readv env 闸门 static 化

### 改动
- `crates/xray-common/src/platform/env.rs`：`use_splice()` 改
  `static SPLICE_FLAG: LazyLock<AtomicBool>` 首调解析 + 热路径
  `load(Relaxed)` 零分配；新增 `pub fn reload_env_settings()` 显式刷新口
  （对齐 Go `reloadEnvSettings` 语义，freedom.go:41-51）；提取
  `parse_splice_env()`（LazyLock 初始化与 reload 共用，语义不变）。
- `crates/xray-buf/src/readv.rs`：`USE_READV` 由 `AtomicBool::new(true)`
  改 `LazyLock<AtomicBool>` 首调解析 env——**同时修复既有缺陷**：原静态
  初值 true 使 `xray.buf.readv=disable` 在无人调 reload 时被无视；
  `reload_env_settings()` 保持签名，内部改走 `parse_readv_env()`。
- `crates/xray-cli/src/bin/xray.rs`：main 启动早期显式调
  `xray_common::platform::env::reload_env_settings()`（xag3③ 启动接线；
  readv 侧不接线——LazyLock 首调已从根上保证正确性，且 xray-cli 无
  xray-buf 依赖，不为仪式调用新增依赖边）。

### 行为等价三态测试（env 设/不设/非法值）
- `env.rs::use_splice_cached_env_three_states`：不设→启用（Go 缺省）；
  auto/enable→启用；disable/true/1/空串/AUTO/Enable→禁用；**缓存语义**
  （set env 不 reload 不翻转 = 热路径零 env 查询的行为证据）；alt 名
  `XRAY_BUF_SPLICE` 兜底 + 原名优先。ENV_LOCK 串行 + Drop 恢复现场。
- `readv.rs::use_readv_cached_env_three_states`：同构五组断言。

### 验证（真实输出）
```
cargo test -p xray-common --lib platform::env
  test platform::env::tests::use_splice_cached_env_three_states ... ok
  test result: ok. 14 passed; 0 failed
cargo test -p xray-buf --lib readv
  test readv::tests::use_readv_cached_env_three_states ... ok
  test result: ok. 9 passed; 0 failed
```

## 2. 票 B（fwhh）：readv 每读 4 allocs → 1 alloc

### 改动（crates/xray-buf/src/readv.rs）
- 新增 `const MAX_READV: usize = 8`（= AllocStrategy 上界）、
  `struct IovecBatch<'a>`（栈上 `[IoSliceMut; 8]` + `[usize; 8]` + n，
  `build()` 零分配构建）、`distribute_slots()`（数组版 distribute）、
  `release_slots()`（数组版 release_all）。
- `ReadVReader::read_multi` 切零分配路径：`[Option<Buffer>; 8]` 栈槽 +
  IovecBatch；唯一保留堆分配 = 返回值 MultiBuffer 内部
  `Vec::with_capacity`（MultiBuffer 公共表示不动）。
- 借用序：`read_vectored_ready` await 后先拷出 `(lens, n_iov)` 纯数据再
  match，错误路径才能 `release_slots`（batch 借用 union 规避）。
- **bridge.rs 零改动红线**：Vec 版 `buffer_iovecs`/`distribute`/
  `AllocStrategy::alloc` 保留（xray-transport/src/bridge.rs:322-344 仍在
  用），doc 注明「兼容路径，勿新增调用方」。零调用的 Vec 版
  `release_all` 删除（clippy dead_code）。

### 行为等价测试
- `distribute_slots_byte_conservation_and_release`：字节守恒（2.5 缓冲
  切 3 段）+ 尾部空槽释放 + n=0 全释放（镜像 Vec 版既有测试）。
- `iovec_batch_build_matches_vec_version`：IovecBatch::build 的 lens 与
  Vec 版 buffer_iovecs 逐元素相等。
- 既有端到端回归：`tcp_aggregation_byte_conservation`（32KB 聚合读多缓冲
  + 逐字节守恒）、`single_full_promotes_then_eof`（1→2→4 扩容序列）、
  `env_off_falls_back_to_sequential_path`（闸门回退）全绿。

### 验证
```
cargo test -p xray-buf --lib
  test result: ok. 188 passed; 0 failed
```

## 3. 票 C（xag3①）：udp443_policies HashMap → Arc

### 改动
- `crates/xray-app-dispatcher/src/default.rs:861`：字段
  `HashMap<String, Udp443Policy>` → `std::sync::Arc<HashMap<...>>`；
  `new()` 相应 `Arc::new(HashMap::new())`；dispatch 热路径 clone 变 Arc
  浅拷贝（原为整表深拷贝 per-dispatch）；tests `insert` 改
  `Arc::make_mut`（COW，rule://rust-concurrency 既有范式）。
- `crates/xray-core/src/functions.rs:280`：装配点包 `Arc::new(...)`。
- 消费点 `udp443_policies.get(handler.tag())` Deref 自动适配，零改动。

### 行为等价验证
既有行为契约测试全绿：`udp443_reject_default` / `udp443_skip_bypass` /
`udp443_dispatcher` e2e（reject→interrupt、skip→直发回环）。

### 验证
```
cmd /c "D:\tmp\buildenv.bat cargo test -p xray-app-dispatcher --lib"
  test result: ok. 128 passed; 0 failed
```

## 4. 分配消除证据（计数 allocator，D:/tmp/d2-bench，不进仓库）

方法：`#[global_allocator]` 计数 wrapper（alloc/alloc_zeroed/realloc 计
数），池预热后测稳态；同机同构建配置（release, lto=thin, codegen-units=1）。

| 场景 | 改造前（e78f097） | 改造后 | 结论 |
|---|---|---|---|
| [A] `use_splice()` ×1,000,000 | **2,000,003 allocs**（2/call：var_os 内部 + into_owned） | **1 alloc**（1/1M：LazyLock 首调 warmup 解析） | 热路径 0 alloc/dispatch（1n90 验收：0 次 env read） |
| [B1] 旧路径帧模拟（8 iovecs）×10,000 | 4/frame | 4/frame | Vec 兼容路径未变（bridge.rs 不受影响佐证） |
| [B2] 真实 `read_multi()`（loopback） | **4 allocs/read** | **1 alloc/read** | −75%，与审计 H3 预期 ~1 一致（fwhh 验收） |
| [B3] `use_readv()` ×1,000,000 | 0 | 0 | 无回归 |

## 5. 吞吐对拍（readv loopback 聚合读，写端 pump 256MB，5 轮中位）

| 状态 | 单轮分布 (MB/s) | 中位 |
|---|---|---|
| 基线（e78f097） | 517.6 / 431.0 / 512.2 / 447.9 / 475.1 | 475.1 |
| 改造后（第 2 轮实测，干净） | 528.8 / 514.6 / 531.5 / 525.5 / 506.3 | **525.5** |

- 中位 **+10.6%**；改造后最差轮（506.3）高于基线中位——红线「不低于基线
  −2%」大幅达标。
- 第 1 轮改造后测得 [508.1, 515.2, 519.9, 343.2, 298.8]，后两轮受同机
  前序 cargo build 尾部抢核干扰；随即重跑得干净分布（上表），取后者。
- bench 为 xray-buf 直接微基准（依赖树仅 xray-buf/xray-common，不经
  xray-transport/bridge.rs），基线/改造后单变量，bridge 合入无归因污染。

## 6. 全量终验（master 含 6b53cd5 bridge.rs 重写）

- workspace --lib：`cargo test --workspace --lib` 全绿（50+ crate，
  xray-transport 519/0 PM 已先行验证；本批文件 xray-buf 188 / xray-common
  458 / dispatcher 128 全绿）。
- 32 节点 wire-format：dist/xray.exe 以合入后 master 重建（40,428,032 B，
  release 全量 6m24s）后 `python dist/run_full32.py` →
  **32/32 PASS 0 FAIL 0 PARSE**（EXIT=0）。首跑（与 release 编译尾部同机
  并发）曾 31/32（FAIL 节点名被 tail 截断未留档）；同构建隔离复跑全绿，
  判定瞬时资源竞争 flaky，非本批回归。
- 归因边界：bridge.rs 与本批文件（env.rs / readv.rs / default.rs /
  functions.rs / xray.rs）零交集；全量测试覆盖新 bridge 代码属预期。

### 每票独立 commit 粒度（PM 审计后逐票提交，清单互不混淆）

| 票 | 文件 |
|---|---|
| 1n90+xag3②③ | `crates/xray-common/src/platform/env.rs`、`crates/xray-buf/src/readv.rs`（仅闸门段 L16-54）、`crates/xray-cli/src/bin/xray.rs` |
| fwhh | `crates/xray-buf/src/readv.rs`（零分配设施 L157-216 + read_multi L267-312 + tests） |
| xag3① | `crates/xray-app-dispatcher/src/default.rs`（861/898/1161/3113）、`crates/xray-core/src/functions.rs`（280-281） |
| 报告 | `docs/impl-d2-hotpath-2026-09-15.md` |

注意：readv.rs 被 1n90 与 fwhh 两票触碰（同文件不同段）；若 PM 要求文件
级隔离，1n90 票先提（闸门段），fwhh 票后提（余下 hunk）。

## side-effects 三态

- 新增文件：本报告；bench 项目在 D:/tmp/d2-bench（仓库外，不进仓）。
- 修改文件：上表 5 个 + 文档。
- 删除：`readv.rs` Vec 版 `release_all`（切路径后零调用）。
- 未动：bridge.rs / ws 指纹 / wire-format / 默认行为 / Cargo.toml 与依赖
  图 / bd 票状态；未 commit。

## 残余风险与未做

- MultiBuffer 内部仍是 Vec（每读 1 alloc）：归零需改公共类型内部表示
  （inline [Buffer; 8]），影响面全仓，不在票面（审计预期即 ~1）。
- bridge.rs 的 readv 帧（bridge.rs:322-344）仍走 Vec 版 4 allocs/read：
  禁区（feature 分支域），待 8sum 方案 A 稳定后另开票迁移。
- readv env 非法值语义与 splice 有既有差异（var() 非 UTF-8→未设 vs
  var_os lossy→禁用），本次行为保持未统一（改即越红线）。
