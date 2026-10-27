# W3a · compat 面·底层 crate（udf Clock 接线）报告

- 执行体：W3aCompatLow（fullstack-engineer）
- 日期：2026-10-27
- 规格：`docs/architecture/xray-frame-能力收敛方案-2026-10-27.md` §4 面 2 步骤 2 / §5.2 W3a 行 / §6.1 D1-D4
- 契约：底层两 crate（xray-common、xray-tls）裸 std 墙钟改走 udf `skeleton::clock::{Clock, SystemClock}`，**直接消费 udf，不引 xray-frame**

# VERDICT: PASS

---

## 1. 站点迁移表（HEAD 裸墙钟 9 = diff 删除侧 9 = 现存 0，1:1）

| # | 文件（HEAD 行号） | 裸站点 | 语义面 | 迁移后 | allow 处置 |
|---|---|---|---|---|---|
| 1 | `xray-common/src/browser.rs:40` | `SystemTime::now`（`today_unix_days`，UA 版本锚定日历，Go `Unix()/86400`） | 挂钟展示 | `SystemClock.now_system()` | 删（bd 39hko 台账） |
| 2 | `browser.rs:145` | `SystemTime::now`（`sample_safari_version` 日界判定） | 挂钟展示 | `SystemClock.now_system()` | 删 |
| 3 | `log/mod.rs:95` | `SystemTime::now`（`Record::new` 时间戳） | 挂钟展示 | `SystemClock.now_system()` | 删 |
| 4 | `protocol/time.rs:57` | `SystemTime::now`（`now_time`，Go `NowTime()` 兼容 wire 面） | 挂钟展示 | `SystemClock.now_system()` | 删 |
| 5 | `protocol/time.rs:89`（test） | `SystemTime::now`（邻近性断言 before） | 测试取时 | `SystemClock.now_system()` | 删 |
| 6 | `protocol/time.rs:94`（test） | `SystemTime::now`（邻近性断言 after） | 测试取时 | `SystemClock.now_system()` | 删 |
| 7 | `xray-tls/src/ech_doh.rs:109` | `Instant::now`（ECH config 缓存过期判定） | 单调测量 | `SystemClock.now_instant()` | 删 |
| 8 | `ech_doh.rs:123` | `Instant::now`（ECH config TTL 锚点） | 单调测量 | `SystemClock.now_instant()` | 删 |
| 9 | `tls_session_cache.rs:112` | `Instant::now`（session `stored_at`，TTL 24h 惰性淘汰） | 单调测量 | `SystemClock.now_instant()` | 删 |

**对账取证**（2026-10-27 实测）：
- HEAD 侧裸墙钟数 = **9**（上表）
- `git diff` 删除侧 `\b(Instant|SystemTime)::now\b` = **9**，新增侧 = **0**
- 迁移后 5 文件现存 = **0**（grep 实证；命中均在非本票文件）
- 例外 allow：**0 处**（无需保留）
- `#[allow(clippy::disallowed_methods)]` 删除 **8** / 新增 **0**（站点级台账 = 债，随迁移退役；两 crate `clippy.toml` 的时钟禁令本体保留——禁令是闸不是债）

**本票面外残留**（归属其他票，未动）：`xray-common` antireplay（`new()` 缺省路径，allow 带豁免理由）/ ocsp / platform / signal（tokio Instant，非 std 面）+ `xray-tls/ech.rs` 测试面——即盘点中「27 处 clock 台账」的其余部分。

## 2. 形态决策（降级自我质疑已做，见下）

1. **取时形态 = `SystemClock` unit struct 直调**（非 `Arc<dyn Clock>` 参数注入）。理由：
   - 站点宿主全为自由函数 / 进程级 `LazyLock` 锚，注入需改 pub 签名 → 波及他人面 crate（文件面独占禁改）；
   - 两 crate `clippy.toml` 禁令理由的明文处方即「时钟唯一源 = `skeleton::clock::{Clock, SystemClock, MockClock}`」——直调 `SystemClock` = 消费时钟端口的生产实现；
   - `SystemClock::now_system()/now_instant()` = std 直通（udf 源码实证），**值语义零变化**；`now_time()` 的 Go `NowTime()` 兼容面只换取时来源，**wire 字节零变化**（互操作门实证）；
   - MockClock 注入能力留待宿主结构体化时加（房内先例 = antireplay `clock` 字段 + `with_clock`）；本次不造无人消费的注入缝。
2. **依赖**：xray-common 已有 `udf-skeleton` ✅；`xray-tls/Cargo.toml` 新增 `udf-skeleton = { path = "../udf-frame/skeleton" }`（规格面 2 步骤 2 明示）→ `Cargo.lock` 随动（纯 path 依赖，无版本漂移）。
3. **依赖方向**：两 crate 零 xray-frame 引用 ✓（底层不背框架层）。

## 3. 验证门（全部真实输出）

| 门 | 命令 | 结果 |
|---|---|---|
| 编译 | `cargo check -p xray-common -p xray-tls -j 8`（独立 target-w2） | Finished dev 1m15s，0 error |
| 测试 | `cargo test -p xray-common -p xray-tls --all-targets -j 8` | xray-common **467 passed / 0 failed**（lib 461 + log_single_entry 5 + unregistered_channel_warn 1）；xray-tls **206 passed / 0 failed**（3 ignored = 既有） |
| clippy | `cargo clippy --workspace --all-targets -j 8 -- -D warnings` | Finished 3m46s，**0 error**（仅 vendor/rustls 上游 2 条预存 warning：非 workspace 成员 lint 被 cap，不归属任何 W 面） |
| fmt | `rustfmt --check`（5 文件，无 `--edition` 探针形态） | **FMT_CLEAN**（修 1 处 log/mod.rs import 排序后） |
| 互操作 | `dist/interop_matrix.py` 双向 6 协议 | **12/12 PASS**（body 200028B + YouTube marker ×12） |

**互操作执行方式说明**：脚本硬编码 `RUST = 'dist/xray.exe'`（红线 baseline，不含本改动且不可覆盖）。为使门真正测到迁移后代码，以模块导入覆写 `RUST = target-w2/release/xray.exe`（本树 release 构建，16m35s）并逐字复刻 `__main__` 双向循环——门语义不变，测的是本票产物。`tls_session_cache` 直面协议（vless_vision_tls / trojan_tls 的 TLS 握手复用路径）双向全过。

**时间敏感测试语义**：`test_now_time_near_system_clock` 断言原文零改动（`ts ∈ [before, after]` 原样），仅换取时源为同一端口实现——符合非目标约束。

## 4. 改动清单

| 文件 | 变更 |
|---|---|
| `crates/xray-common/src/browser.rs` | +import；2 站点换 `SystemClock.now_system()`；删 2 allow（净 -5 行） |
| `crates/xray-common/src/log/mod.rs` | +import；1 站点换 `now_system()`；删 1 allow |
| `crates/xray-common/src/protocol/time.rs` | import 调整（去 `SystemTime`）；`now_time()` + 测试 2 站点换端口；删 2 allow |
| `crates/xray-tls/src/ech_doh.rs` | +import（`Instant` 从 std import 移除，仅剩 `Duration`）；2 站点换 `now_instant()`；删 2 allow |
| `crates/xray-tls/src/tls_session_cache.rs` | +import（`Instant` 保留作字段类型）；1 站点换 `now_instant()`；删 1 allow |
| `crates/xray-tls/Cargo.toml` | +`udf-skeleton` path 依赖（规格明示） |
| `Cargo.lock` | cargo 自动随动（新 path 依赖记账） |

合计 +31 / -40（`git diff --stat`）。**未 commit/push**（归 PM）。

## 5. 非目标确认

- 未碰 xray-frame / 其他 crate / `.github` / vendor ✓
- 未动 `dist/xray.exe`（红线 baseline 原样）✓
- 未 commit/push ✓
- 时间敏感测试断言零改动 ✓

## 6. 资源收尾

`target-w2`（本票独立 target）**本票未删**：目录名三票撞名——W3a（本票）、W2ConfigShadow（config 影子三路 + interop）、W3bCompatHigh（四 crate 测试 + interop）均在用（2026-10-27 协调确认，三方互已通气）。删除动作归**最后完工方**执行并注明（`rm -rf` 幂等，先完工方跳过即可）；避免中途抽走在飞票的编译缓存。`dist/xray.exe` 与共享 `target/` 未触碰。

## 7. 自我评估（5 轴）

- **准确性 5/5** — 每条声明可溯源：站点行号取自 HEAD grep；udf API 签名读自 `crates/udf-frame/skeleton/src/clock.rs:56-68`（`fn now_instant(&self) -> Instant; fn now_system(&self) -> SystemTime`）；门结果全部为真实命令输出。
- **完整性 5/5** — 验收 4 条逐项闭环：对账三数（9=9=0）+ 测试/clippy 门 + 互操作 12/12 + 本报告；规格点名的 7 生产站点 + 2 测试站点全迁，8 allow 全删。
- **清晰度 4/5** — 扣 1：互操作覆写执行方式（§3）需读者理解「红线 baseline vs 迁移产物」两个二进制的区别，已尽力一段说清。
- **可执行性 5/5** — 站点表带 HEAD 行号可 1:1 复查；复现命令全在 §3 表内（含 target-w2 已删的重建提示：复测需重跑 `cargo build --release -p xray-cli`）。
- **简洁性 4/5** — 扣 1：形态决策 3 条中第 1 条与前文 clippy.toml 处方有呼应重复，保留是为让评审不必回查 clippy.toml。

## 8. 残余风险

- workspace clippy 的 vendor/rustls 2 条 warning 为上游预存（非成员 crate cap-lints），若未来上游收紧需另票处理——与本票无关，留档防归属误判。
- `cargo fmt --all -- --check` 全仓门未跑（他人面文件可能有在飞未格式化改动，跑了会产生归属噪音）；本票 5 文件 rustfmt 探针全清，fmt 责任面已闭合。
