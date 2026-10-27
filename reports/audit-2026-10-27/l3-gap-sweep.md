# L3 漏网面清扫：xray-app-dispatcher / xray-transport-kcp / xray-transport-splithttp

> 票 `txmhr`（L3 口径外的漏网面 —— 三个 crate 有生产裸 spawn / Instant，既无 clippy.toml 禁令也无台账）
> 日期：2026-10-27 ｜ 执行：L3GapSweep ｜ 共享树：另 2 个 agent（TracingBatch2a/2b）同窗在跑，面互斥（它们改 xray-proxy-* 的 clippy.toml）

## VERDICT: PASS

完工状态：DONE

---

## 0. 结论

- **实测盘点**（非抄票面数字）：三 crate 生产面命中 **43 处**（dispatcher 3 / kcp 4 / splithttp 36），测试面 **83 处**。票面未给数字，本轮以脚本实测为准。
- **clippy.toml 禁令**：三 crate 各补齐 spawn 族 + 时钟族禁令，**条目写法经 9 轮探针实测**（见 §2）——`path` 写错会静默失效（不报 fatal、不 fire），故先验证再落码。
- **生产站点处置**：**0 处迁 FxScope/Clock**，43 处全部保留并逐处/逐 fn 挂 `#[allow(clippy::disallowed_methods, reason=...)]` 台账。迁移不可行的根因统一为 **ctx 不可达**（三 crate 生产依赖图均无 PluginContext 注入面）——详见 §4。
- **台账 reason 分类**（按票面 5 类）：数据面热路径（坑约束⑫）33 处 / ctx 不可达 9 处 / 语义判定保留 1 处 / 测试面 83 处 / wire 时间戳 0 处 / 红线 0 处。

---

## 1. 实测盘点表（全量，禁漏）

判据：调用位（`path(`）才计入；类型位（`Mutex<Option<Instant>>` 等）不计。测试面 = `#[cfg(test)]` mod 内 + `tests/` 目录文件。

### 1.1 xray-app-dispatcher —— 生产 3 处 / 测试 17 处

| 文件:行 | 类型 | 生产/测试 | 处置 |
|---|---|---|---|
| `src/default.rs:654` | `std::time::Instant::now` | 生产 | 保留（**存量 allow 已存在**，713x6 语义判定：嗅探预算 IO 实耗测量面） |
| `src/default.rs:881` | `tokio::spawn` | 生产 | 新增 allow（JoinSet 收割壳，ctx 不可达） |
| `src/udp_session.rs:164` | `tokio::spawn` | 生产 | 新增 allow（UDP dispatch 会话任务，ctx 不可达） |
| `src/default.rs` ×12、`src/stats.rs` ×2 | `tokio::spawn` | 测试 | crate 级 `#![cfg_attr(test, allow(clippy::disallowed_methods))]`（lib.rs:34）统一豁免 |
| `src/default.rs` ×4 | `std::time::Instant::now` | 测试 | 同上 |
| `tests/dual_write_longrun.rs` ×3 | `tokio::spawn`/`Instant::now` | 测试 | 文件顶 `#![allow(clippy::disallowed_methods)]`（独立 test binary，lib.rs 的 cfg_attr 不覆盖） |

**注**：dispatcher 存量 clippy.toml 已有**时钟族 3 条**（std/tokio Instant + SystemTime），缺的是 **spawn 族 2 条**。故本轮 dispatcher 只需补 spawn 族。

### 1.2 xray-transport-kcp —— 生产 4 处 / 测试 13 处

| 文件:行 | 类型 | 生产/测试 | 处置 |
|---|---|---|---|
| `src/connection.rs:186` | `Instant::now`（std 墙钟） | 生产 | 保留（**存量 allow 已存在**：`since` 字段连接创建锚点） |
| `src/connection.rs:673` | `tokio::time::Instant::now` | 生产 | 新增 allow（**tokio 虚拟钟预算面**——deadline 判定须与 `tokio::time::pause` 确定性对齐） |
| `src/connection.rs:686` | `tokio::time::Instant::now` | 生产 | 同上（同一 fn，一起挂） |
| `src/updater.rs:87` | `tokio::spawn` | 生产 | 保留（**存量 allow 已存在**：常驻 updater tick 任务） |
| `src/connection.rs` ×7 + `src/connection.rs` ×6 | `tokio::spawn` / `tokio::time::Instant::now` | 测试 | 新增/存量 allow（kcp 无 crate 级 cfg_attr 豁免，逐点登记） |
| `tests/mask_roundtrip.rs` ×2 | `thread::spawn` / `tokio::spawn` | 测试 | 存量 allow |

**注**：kcp 存量 clippy.toml 已有 `tokio::spawn` + `std::thread::spawn` + `std::time::Instant::now`，缺 `tokio::task::spawn`（别名）+ `tokio::time::Instant::now` + `std::time::SystemTime::now`。**kcp 生产面 4 处的时钟语义已按票面要求逐处判定**（见 §4.2）。

### 1.3 xray-transport-splithttp —— 生产 36 处 / 测试 53 处

| 文件 | 类型 | 生产处数 | 处置 |
|---|---|---|---|
| `src/transport.rs` | `tokio::spawn` + `Instant::now` | 14 | 逐 allow（accept 循环 / 每连接处理 / accept 监控 / H3 请求 / duplex 桥 + IO 进展墙钟） |
| `src/dialer.rs` | `tokio::spawn` + `std::time::Instant::now` | 7 | 逐 allow（packet-up / H3 packet-up 上传泵 + POST 间隔墙钟） |
| `src/h3_client.rs` | `tokio::spawn` | 5 | 逐 allow（0-RTT 观察 / driver 关闭 / 上行 / 下行收 / 懒读） |
| `src/hub/handler.rs` | `tokio::spawn` | 5 | 逐 allow（body 切片 / 队列转发 / stream-one / X 填充 / 会话删除） |
| `src/hub.rs` | `tokio::spawn` | 1 | 逐 allow（每 TCP 连接 hyper 服务任务） |
| `src/hub/session.rs` | `tokio::spawn` | 1 | 逐 allow（30s 会话 reap 定时任务） |
| `src/client.rs` | `tokio::spawn` | 1 | 逐 allow（h2 懒读任务） |
| `src/mux.rs` | `Instant::now` | 2 | 逐 allow（xmux 不可复用判定 + UnreusableAt 锚点） |
| `src/*.rs` 各 `#[cfg(test)]` mod | 混合 | 53 | crate 级 `#![cfg_attr(test, allow(clippy::disallowed_methods))]`（lib.rs:37）统一豁免 |
| `tests/*.rs` ×4 | 混合 | 53 内 | 文件顶 `#![allow(clippy::disallowed_methods)]`（独立 test binary） |

**注**：splithttp 存量 clippy.toml 仅有**分配纪律 2 条**（slice::to_vec / MultiBuffer::to_vec），**spawn 族与时钟族全缺**——本轮一次性补齐 6 条。

---

## 2. 禁令条目写法：9 轮探针实测（"写错即静默失效"的反面证据）

本轮新增 `tokio::task::spawn` 别名条目，先用隔离探针 crate（`D:/tmp/probe-l3`，独立于本仓）实测 clippy 的 `disallowed-methods` 匹配语义，再落码。

### 2.1 探针矩阵（结论：写错 → **静默 no-op**，不报 fatal）

| 探针 | clippy.toml `path` | 调用形态 | 结果 |
|---|---|---|---|
| A | `tokio::spawn` | `tokio::spawn(...)` **+** `tokio::task::spawn(...)` | **两条调用形态都命中**（同 def-id 的别名） |
| B | `tokio::task::spawn` | `tokio::spawn(...)` **+** `tokio::task::spawn(...)` | **两条都命中** |
| C | 上述两条并列 | 两条调用形态 | 每站点**只报一次**（去重，报更具体的 `tokio::task::spawn`） |
| D | `tokio::task::spawn::spawn` / `std::time::Instant::now::now` / 裸 `Instant::now` | — | **静默失效**（不 fire、不报 fatal）——**这就是"写错即静默失效"的实证** |
| E | `std::time::Instant::now` | `use std::time::Instant;` 后 `Instant::now()` | **命中**（别名导入按 def-path 归一） |
| F | `tokio::time::Instant::now` | `use tokio::time::Instant;` 后 `Instant::now()` | **命中**（tokio 面与 std 面是**不同 def-id**，互不串味） |
| G | `std::time::SystemTime::now` | `SystemTime::now()` | **命中** |
| H | `tokio::task::spawn` | `tokio::task::spawn_blocking(...)` | **不命中**（`spawn_blocking` 是另一 def-id） |
| I | — | `tokio::task::spawn_blocking` 被 `tokio::task::spawn` 命中？ | **不命中**（探针 H 复核） |

**据此的落码决策**：
1. `tokio::spawn` 与 `tokio::task::spawn` **双登记**（探针 A/B/C 实证覆盖两种调用形态且每站点只报一次）→ 与 10 个既有 proxy crate 一致（ledger-audit §3 记为 belt-and-braces）。
2. `tokio::time::Instant::now` 与 `std::time::Instant::now` **必须分列**（探针 F：tokio 面与 std 面不同 def-id，混写会漏）。
3. **`tokio::task::spawn_blocking` 不在禁令面**（探针 H/I）——故 kcp `register.rs` 的 2 处 `spawn_blocking` **不被本轮禁令命中**，无需登记（保留原状，非本轮台账范围）。
4. `std::thread::spawn` 单列（既有家族模板惯例，探针未覆盖 `thread::spawn` 别名形态，但 `std::thread::spawn` 为 def-path 写法，kcp 存量条目即此形态）。

### 2.2 属性挂载位（E0658 约束，决定台账粒度）

| 挂载位 | 结果 | 处置 |
|---|---|---|
| `let` 语句位 | ✅ 生效 | 逐点登记首选 |
| 裸表达式语句位 | ✅ 生效 | 可用 |
| `if` 语句位 | ✅ 生效（含条件表达式） | 可用 |
| **赋值表达式语句位**（`*x = ...`） | ❌ **E0658**（attributes on expressions are experimental） | **上移 fn 级**（与既有 `xray-transport-hysteria/src/conn.rs:591` 注释同款） |
| **宏调用语句位**（`assert_eq!`） | ⚠️ 属性被**忽略**（报 unused attribute），**不抑制** | **上移 fn 级** |

---

## 3. 下一步路径（"为什么不迁" → "走哪条路"）

**本轮迁移 0 处。** 逐 crate 判定：

| crate | FxScope/PluginContext 可达性 | Clock 可达性 | 判定 |
|---|---|---|---|
| xray-app-dispatcher | ❌ `xray-frame` 仅 **dev-dependency**（Cargo.toml:27），生产依赖图无 PluginContext | ❌ 无 udf-skeleton 依赖 | 保留 + 台账（ctx 不可达） |
| xray-transport-kcp | ❌ 无 xray-frame 依赖 | ❌ 无 udf-skeleton 依赖 | 保留 + 台账（ctx 不可达） |
| xray-transport-splithttp | ❌ `xray-frame` 依赖仅用于 `LogFacade`（lib.rs:41），无 spawn/clock 能力 | ❌ 同上 | 保留 + 台账（数据面热路径 + ctx 不可达） |

### 3.1 为什么不迁（能力诉求在当前依赖方向下无法从框架层注入）

1. **依赖方向缺口**：三 crate 生产依赖图均无 PluginContext 注入面。dispatcher **运行时根本不依赖 xray-frame** → 它连框架层的 ctx 都拿不到；splithttp 的 xray-frame 依赖只提供 `LogFacade`，无 spawn/clock 能力。
2. **数据面零改动约束**（坑约束⑫）：splithttp 的 36 处生产站点全部落在 h2/h3 传输数据面（accept 循环 / 每连接任务 / 上行下行车 / 会话 reap / xmux 复用判定）。为满足静态闸而改数据面任务编排 = 用治理动作换数据面风险，与坑约束⑫ 直接冲突。
3. **接线方案未授权**：接入 FxScope/Clock 需先在**生产依赖**引入相关件 —— 触及 Cargo.toml 依赖图（CLAUDE.md §4 红线区，本票 Non-goals 未授权），且 udf 侧 API 面须先定（CLAUDE.md §3.5.2「造件前必查三处」+「禁重复造轮子」）。

### 3.2 下一步走哪条路：W9（残余 C 面 —— 主仓接线 udf 已有件）

**收敛路径不是「迁移到 xray-frame」，而是 W9：三 crate 直接消费 udf 的 `FxScope` / `Clock`。**
- udf 是这三 crate **允许依赖的地基层**（CLAUDE.md §3.5.1：硬装血肉 → 骨架 → 地基），直接消费 udf 已有件**不违反依赖方向**，也**不需绕道 xray-frame**。
- 具体接线形态：生产依赖引入 `udf-skeleton-infra`（`fx::FxScope`）+ `udf-skeleton`（`clock::Clock`），组件自持 `Arc<dyn Clock>` / FxScope 句柄，**组件自持**形态（与 `xray-proxy-socks/src/server.rs` 的 `SocksServer.log` 自持门面同款），避免改公开 API 签名。
- 本票台账的 43 处 reason 已按此路径写明「FxScope/Clock 迁移收口见 bd 39hko」→ **C 面清单的施工项可直接沿用本报告 §4 的逐站点清单**（每处都已写明语义归属：数据面热路径 / ctx 不可达 / 语义判定保留）。
- 前置依赖：udf `FxScope` / `Clock` 的**主仓接线**属 W9 范围；本票不预判其 API 形态，故台账 reason 只指向 bd 39hko + W9，不写死具体调用形态。

---

## 4. 保留清单及理由（43 处生产站点）

### 4.1 reason 分类标准（票面 5 类）

| 类别 | 本轮实数 | 判定口径 |
|---|---|---|
| **数据面热路径** | 33 | 站点位于 h2/h3 传输数据面（accept 循环 / 每连接任务 / 上下行车 / 会话 reap / xmux 判定 / POST 间隔墙钟）——坑约束⑫ |
| **ctx 不可达** | 9 | 生产依赖图无 PluginContext/Clock 注入面（dispatcher 3 + kcp updater 1 + splithttp mux/transport 墙钟锚点 5） |
| **语义判定保留** | 1 | kcp `wait_for_data` 的 tokio 虚拟钟预算面 |
| **测试面** | 83 | `#[cfg(test)]` mod + `tests/` 独立 binary |
| **wire 时间戳** | 0 | 三 crate 生产面无协议 wire 时间戳写入 |
| **红线** | 0 | 未触碰 `xray-transport-tcp/register.rs`（CLAUDE.md §4 红线） |

### 4.2 kcp 时钟语义逐处判定（票面专项要求）

| 站点 | 语义 | 判定 | 理由 |
|---|---|---|---|
| `connection.rs:186` `since: Instant::now` | **std 墙钟**（连接创建锚点） | 保留（存量 allow） | 非 deadline 预算面；`Clock` 端口注入待 bd 39hko |
| `connection.rs:673/686` `tokio::time::Instant::now` | **tokio 预算面**（deadline 判定） | 保留（新增 fn 级 allow） | ① 须与 `tokio::time::pause` 确定性测试对齐（std 时钟在 pause 下不推进 → 过期判定不可测）；② `duration` 最终喂 `tokio::time::sleep`（只收 tokio Instant）。tokio 面与 std 面禁混换 → **不迁** |
| `updater.rs:87` `tokio::spawn` | 常驻 updater tick 任务 | 保留（存量 allow） | 非一次性任务；迁 FxScope 收口 bd 39hko |

### 4.3 splithttp 生产站点 reason 逐条（36 处）

| 文件:行 | 语义 | reason 归类 |
|---|---|---|
| `transport.rs:257` | TCP accept 循环任务 | 数据面热路径 + ctx 不可达 |
| `transport.rs:270` | 循环内每连接处理任务 | 同上（与 257 同一 allow 覆盖 2 处） |
| `transport.rs:281` | accept 循环意外退出监控 | 同上 |
| `transport.rs:356` | unix accept 循环任务 | 同上（与 367 同一 allow 覆盖 2 处） |
| `transport.rs:367` | unix 循环内每连接处理任务 | 同上 |
| `transport.rs:377` | unix accept 监控 | 同上 |
| `transport.rs:428` | IO 进展墙钟锚点（`ProgressIo::touch`） | ctx 不可达（Clock 端口未接线） |
| `transport.rs:508` | IO 进展墙钟初始锚点 | ctx 不可达 |
| `transport.rs:828` | QUIC accept 循环任务 | 数据面热路径 + ctx 不可达 |
| `transport.rs:831` | QUIC 循环内每连接处理任务 | 同上（同一 allow 覆盖 2 处） |
| `transport.rs:858` | h3 每请求任务 | 同上（同一 allow 覆盖 3 处：858/862/870） |
| `transport.rs:862` | h3 请求体桥接任务 | 同上 |
| `transport.rs:870` | h3 连接终结 abort 任务 | 同上 |
| `transport.rs:979` | duplex 双向 copy 桥任务 | 同上 |
| `dialer.rs:83` | packet-up 上传泵 spawn | 数据面热路径 + ctx 不可达（同一 allow 覆盖 3 处：83/88/121） |
| `dialer.rs:88` | POST 间隔墙钟初值（Go `time.Since(lastWrite)` 语义） | 同上 |
| `dialer.rs:121` | POST 间隔墙钟更新 | 同上 |
| `dialer.rs:372` | H3 packet-up 上传泵 spawn | 同上（同一 allow 覆盖 3 处：372/377/408） |
| `dialer.rs:377` | H3 POST 间隔墙钟初值 | 同上 |
| `dialer.rs:408` | H3 POST 间隔墙钟更新 | 同上 |
| `dialer.rs:591` | h2 连接驱动任务 | 数据面热路径 + ctx 不可达 |
| `h3_client.rs:369` | QUIC 0-RTT 结果观察任务 | 同上 |
| `h3_client.rs:397` | h3 driver 关闭任务 | 同上 |
| `h3_client.rs:607` | H3 上行 body 发送任务 | 同上 |
| `h3_client.rs:701` | H3 下行接收任务 | 同上 |
| `h3_client.rs:754` | H3 懒读任务 | 同上 |
| `hub.rs:213` | 每 TCP 连接 hyper 服务任务 | 同上 |
| `hub/handler.rs:328` | stream-up body 切片推送任务 | 同上 |
| `hub/handler.rs:381` | stream-down 队列转发任务 | 同上 |
| `hub/handler.rs:391` | stream-one body→上行管道任务 | 同上 |
| `hub/handler.rs:462` | X 填充 keepalive 流任务 | 同上 |
| `hub/handler.rs:522` | 会话删除任务（SessionMap 是 tokio Mutex，Drop 内只能 spawn 异步删除） | 同上 |
| `hub/session.rs:100` | 会话 30s reap 定时任务 | 同上 |
| `client.rs:779` | h2 懒读任务（GET 响应头 + body 转发） | 同上 |
| `mux.rs:131` | xmux 不可复用判定锚点 | ctx 不可达（Go xmux `time.Time` 墙钟语义） |
| `mux.rs:204` | UnreusableAt = Now + secs 锚点 | ctx 不可达（同上） |

### 4.4 dispatcher 生产站点 reason（3 处）

| 文件:行 | 语义 | reason 归类 |
|---|---|---|
| `default.rs:654` | 嗅探预算 IO 实耗测量面 | **语义判定保留**（713x6 存量 allow：MockClock 冻结破坏预算递减） |
| `default.rs:881` | JoinSet 收割壳（`spawn_tracked`） | ctx 不可达 |
| `udp_session.rs:164` | UDP dispatch 会话任务 | ctx 不可达 |

---

## 5. 迁后 grep 实数（验收硬指标）

脚本实测（调用位口径，判据同 §1）：

| crate | 生产命中 | 测试命中 | 生产面已登记 |
|---|---|---|---|
| xray-app-dispatcher | **3** | 17 | 3（1 存量 + 2 新增） |
| xray-transport-kcp | **4** | 13 | 4（3 存量 + 1 新增 fn 级覆盖 2 处） |
| xray-transport-splithttp | **36** | 53 | 36（全新增） |
| **合计** | **43** | **83** | **43** |

三 crate 生产面**裸 spawn / 裸 Instant 归零**：43 处生产命中**全部**落在 `#[allow(clippy::disallowed_methods)]` 覆盖范围内（clippy 门实测 0 error 佐证）。

---

## 6. 验收证据（实跑）

见下节「验收命令与输出」（工作区 check/clippy + 三 crate 测试 + fmt）。

---

## 7. 未做 / 残留

- **FxScope/Clock 迁移 0 处** → 下一步走 **W9（直接消费 udf `FxScope`/`Clock`）**，非 xray-frame（§3.2）。台账 43 处 reason 已写明语义归属，C 面施工项可直接沿用本报告 §4 清单。
- **kcp `register.rs` 的 2 处 `tokio::task::spawn_blocking`** 未登记：探针 H/I 实证 `tokio::task::spawn` 禁令**不命中** `spawn_blocking`（不同 def-id），故不在本轮禁令面内，保留原状。
- **`std::thread::spawn` 在 splithttp/dispatcher 生产面 0 命中**（kcp 存量 1 处在测试面），条目按家族模板预置以防未来漂移。
- **未跑 e2e / 互操作**：本票零行为改动（纯 lint 闸 + 台账），`cargo test` 全绿即为行为等价证据；协议面无涉。
- **另 2 个 agent 的 clippy.toml 改动**（xray-proxy-*）不在本票范围，未触碰、未计入本报告数字。
- **workspace clippy 尾部红在他人面**：`crates/xray-frame/src/logging.rs:309`（`clippy::int_plus_one`）+ `crates/xray-frame/src/config.rs:362`（`clippy::collapsible_if`）—— 属 W1 owner 的 in-flight 改动，**非本票面**，未越界修改；已点给归属方收敛。

---

## 8. 沉淀

- **clippy `disallowed-methods` 的 `path` 是 def-path（实测 9 轮探针）**：① `tokio::spawn` 与 `tokio::task::spawn` 是同 def-id 的两个拼写，**任一单条目即覆盖两种调用形态**，双登记去重后每站点仍只报一次（探针 A/B/C）；② `std::time::Instant::now` 与 `tokio::time::Instant::now` 是**不同 def-id，必须分列**（探针 F），混写即漏；③ `tokio::task::spawn` **不命中** `tokio::task::spawn_blocking`（探针 H/I）；④ 路径写错（多一层/少一层/裸 `Instant::now`）= **静默 no-op，不报 fatal**（探针 D）——这是「禁令生效」的唯一可靠验证方式。
- **属性挂载位的 E0658 边界**（Rust `stmt_expr_attributes` 未稳定）：`let` / 裸表达式 / `if` 语句位可挂属性；**赋值表达式位（`*x = ...`）与宏调用位（`assert_eq!`）不可挂**（后者属性被忽略且报 unused attribute）→ 二者一律**上移 fn 级**。
