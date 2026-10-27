# C 面 R1b · `xray-core::inbound::InboundRuntime` 生产 inbound 运行期注册表 → udf `skeleton_infra::memgov::BoundedRegistry`

**日期**：2026-10-27 · **面**：`crates/xray-core/src/inbound.rs`（`InboundRuntime` 及其 8 个 slots 站点）
**规格**：`docs/architecture/xray-frame-能力收敛方案-2026-10-27.md` §4 第 12 行 / §10.1 **R1 行**
**红线遵循**：§10.1 R1「**禁整面 impl `PoolManaged`**」——全仓 `impl … PoolManaged for` 仅 `xray-frame/src/pool.rs:265`（缓冲池本体），注册表零 `PoolManaged`/零 `PoolBase`/零 `MemoryPool` 接触；零 `PoolManaged` 假同构。

VERDICT: **PASS（迁移代码已在 `fe8d5481` 落地，本票为复核 + 门取证；零代码改动）**

**一句话**：任务书前提（`slots: RwLock<Vec<..>>` + O(n) 线性扫）已过时——`fe8d5481`（xiuvr-3a，2026-10-26）已把 `InboundRuntime.slots` 换成 udf `BoundedRegistry<String, InboundSlot>`（`Eviction::Reject`，cap=1024），旧 `Vec` 线性扫净删、无影子/双轨残留；本票复核 8 个 slots 站点、逐条对照改前/改后语义、判定 keying 契合与热路径，并跑满四门（测试 477+1+1 / clippy 0 / fmt 0 / 互通 12/12）。

---

## 1. 关键判断（先答后动手）

### 1.1 Keying 契不契合：**契合，单键 = tag，无需降键、无需复合键**

现有匹配谓词只有一条：`slot.tag == tag`（改造前 `iter().any(|s| s.tag == tag)` / `position` / `find` / `iter_mut().find`，见 §3 改前源码）。**无 kind/network/port 参与**，故单键注册表直接装得下：

| 判定项 | 结论 | 证据 |
|---|---|---|
| 匹配谓词 | 仅 tag 等值（`String`） | `git show fe8d5481^:crates/xray-core/src/inbound.rs` 的 `contains`/`remove_inbound`/`user_manager`/`register_user_manager` 四处谓词全为 `s.tag == tag` |
| 主键选型 | `K = String`（tag 原文，Go `map[string]inbound.Handler` 同构） | Go `app/proxyman/inbound/inbound.go:41-50`：`map[string]inbound.Handler` |
| 是否需降键 | **否**（已是单键；无需复合键/索引层） | 无第二个查询维度：`list()` 全量、`contains/user_manager/remove` 均按 tag |
| 降键会不会改可观测行为 | 不适用（未降键） | — |
| 单键 API 代价 | `BoundedRegistry::get/remove` 签名写死 `&K`（无 `Borrow<Q>` 泛型）⇒ 4 处管理面站点各一次 `String` 分配（C-R1a 实测该分配 35.3 ns） | `crates/udf-frame/skeleton-infra/src/memgov.rs:82,87` |

**禁自造索引层的复核**：全仓无 `BoundedRegistry` 之外的 inbound 索引结构；`arm_registry::lookup_inbound_builder` 的构造表（BTreeMap，T4.2）是**构造期**查表，与本运行期注册表是两张不同表，未混用。

### 1.2 语义必须原样：5 维度对照（逐条给改前→改后 + 独立取证）

改前源码取自 `git show fe8d5481^:crates/xray-core/src/inbound.rs`（本票实读，非引用他人报告）。

| # | 维度 | 改前（`RwLock<Vec<InboundSlot>>`） | 改后（`RwLock<BoundedRegistry<String, InboundSlot>>`） | 判定 |
|---|---|---|---|---|
| D1 | **迭代序** | 注册序（`iter()` 按 push 顺序；注释自称「保持注册顺序，ListInbounds 顺序稳定」） | **tag 字典升序**（BTreeMap 确定序） | **等价或更强**：唯一消费方 = gRPC `ListInbounds`（`functions.rs:643`）；Go 上游 `ListHandlers` 遍历 `map[string]inbound.Handler`（`app/proxyman/inbound/inbound.go:93-103`）= **无序** ⇒ 我方升序是严格细化；全仓无任何断言 `InboundRuntime.list()` 注册序的测试；测试面已有 D1 落地断言（`xiuvr3a_registry_behaviour_matrix_19kinds_x3variants`：插 `zz-order`/`aa-order` 后 `list()` 必为 `[aa-order, zz-order]`） |
| D2 | **重复 tag** | `push` 两条（`contains=true`，`remove` 只删第一条 ⇒ 另一条永久滞留） | `insert` 覆盖（`len` 不变） | **等价或更强**：`start_inbound` 前置 `contains` 硬拒（`existing tag found: <tag>`，与 Go `inbound.go:45` 文本逐字一致）；生产不可达；覆盖语义恰对齐 Go map 赋值 |
| D3 | **移除时机** | `spawn_one_inbound` Err → `retain(|s| s.tag != ib.tag)`（删**所有**同 tag）；`RemoveInbound` → `position`+`Vec::remove`（只删首条） | Err 回滚 → `remove(&tag)`（单条）；`RemoveInbound` → `remove(&tag)` + `cancel.cancel()` | **等价**：因 D2 覆盖使「同 tag 多条」不可达，`retain` 与 `remove` 在单条场景结果相同；`cancel.cancel()` 时机不变（同一写锁段内摘除后立即取消） |
| D4 | **空表退化** | `list()` → `vec![]`；`contains`→false；`user_manager`→`HandlerNotFound` | 同（`BTreeMap` 空迭代 / `get`→`None`） | **等价**（`xiuvr3a_registry_behaviour_lifecycle` 首段断言） |
| D5 | **并发面** | 一把 `parking_lot::RwLock`，读 `read()`/写 `write()` | **同一把** `parking_lot::RwLock`（未引入第二把锁、未改锁序） | **等价**：`BoundedRegistry` 的 `&mut` 需求由外层原有 `write()` 承接（照 C-R1a 口径），锁粒度表见 §1.4 |
| D6 | **容量** | 无界 | cap=1024 + `Eviction::Reject`（满则 `insert` 返 `Err(BoundError)` → `io::Error("inbound registry full: …")` 上抛） | **新增有界（唯一行为增项）**：Go 无界；cap 取工程上不可达值（真实配置十几~几十个 inbound），fail-closed 不静默淘汰；满表错误面显式上抛，不吞 |

**其它等价性复核**：`ProxymanError::HandlerNotFound(tag)` / `NotUserManager` 两类错误面、`start_inbound` 的前置 `contains` 硬拒文本、`register_user_manager` 未知 tag 的 `tracing::warn!` 均逐字未变。

### 1.3 站点清单（8 个 slots 读写点，全在 `inbound.rs`；`grep slots` 于 `crates/xray-core/src` 实跑）

| # | 站点 | 读/写 | 操作 | 锁 |
|---|---|---|---|---|
| 1 | `inbound.rs:3104` | — | 字段定义 `RwLock<BoundedRegistry<String, InboundSlot>>` | — |
| 2 | `inbound.rs:3120-3123` | — | `new()`：`BoundedRegistry::new(INBOUND_REGISTRY_CAP, Eviction::Reject)` | — |
| 3 | `inbound.rs:3143-3147` | 写 | `start_inbound`：`insert`（满表 `map_err` → fail-closed） | write |
| 4 | `inbound.rs:3154` | 写 | `start_inbound` spawn Err 回滚：`remove` | write |
| 5 | `inbound.rs:3163` | 读 | `contains`：`get(&tag.to_string()).is_some()` | read |
| 6 | `inbound.rs:3172` | 写 | `remove_inbound`：`remove(&tag.to_string())` → `cancel()` | write |
| 7 | `inbound.rs:3185-3188` | 读 | `list`：`iter()`（tag 升序）→ 克隆 `(tag, type_url)` | read |
| 8 | `inbound.rs:3199-3200` | 读 | `user_manager`：`get(&tag.to_string())` | read |
| 9 | `inbound.rs:3209-3216` | 写 | `register_user_manager`：`remove` + 改 `users` + `insert` 回写（同一写锁段原子） | write |

（表列 9 行含字段/构造两行；运行期操作站点 = 7 处，全部在 `InboundRuntime` impl 内，无外部直接访问 `slots`。）

**消费方（全部非数据面）**：
- `functions.rs:580` `contains`（gRPC AddInbound 前置）/ `:585` `start_inbound` / `:590` `remove_inbound`（无监听端口回滚）/ `:604` `remove_inbound`（RemoveInbound）/ `:621,626` `user_manager`（AlterInbound Add/RemoveUser）/ `:643` `list`（ListInbounds）/ `:665,679` `user_manager`（GetInboundUser/Count）
- `inbound.rs:4080` `register_user_manager` ← `register_ss_user_manager` ← `arm_builders/inbound.rs:526`（ss 配置期）与 `:904`（ss transport 期，`ss_transport_on_conn` 内**构造 ConnHandler 时**调用一次，闭包不捕获 `api`）

### 1.4 热路径判断：**非热路径**（既非每包，亦非每连接）

| 判据 | 实测 |
|---|---|
| 数据面可达性 | `InboundRuntime` 引用只经 gRPC `HandlerService`（`functions.rs:545`）与配置期 `spawn_inbounds`/`spawn_one_inbound` 传入 |
| `api: Option<&InboundRuntime>` 在 arm builder 内的用途 | 全仓 3 处：`arm_builders/inbound.rs:497`（形参）、`:509`（转发）、`:526`/`:904`（`register_ss_user_manager`）——**均在建站期**；`ss_transport_on_conn` 返回的连接闭包只捕获 `mode/handler/plugin_ctx`，**不捕获 `api`**（`inbound.rs` 层实测闭包体） |
| 连接/包级查表 | **零**：`contains`/`user_manager`/`list`/`remove_inbound` 的唯一调用方是 gRPC HandlerService 与测试 |
| 结论 | 注册表查表频次 = 管理 API 调用次数 + 配置启动次数；每连接转发不经此表 ⇒ **无「~60-90 ns/次」热路径风险**，无需停手 |

---

## 2. 改动面

**本票零代码改动**（`git status --porcelain` 中 `crates/xray-core/src/inbound.rs` 无变更）。已落地形态（`fe8d5481`）：

| 文件 | 内容 |
|---|---|
| `crates/xray-core/src/inbound.rs` | `slots: parking_lot::RwLock<BoundedRegistry<String, InboundSlot>>`；`INBOUND_REGISTRY_CAP = 1024`；7 个操作站点改 `get/insert/remove/iter`；`InboundSlot.tag` 字段删除（键接管） |
| `crates/xray-core/Cargo.toml:31` | `udf-skeleton-infra` features `["tokio"]` → `["tokio", "memgov"]`（`BoundedRegistry` 所在 feature 门；零三方依赖纯 std 模块） |

**未改（非漏做）**：`functions.rs`（消费方签名未变、`contains` 前置检查与 `start_inbound` 内部检查的重复是既有形态）；`arm_builders/**`（W4 面，本波不动）；`xray-app-proxyman`（生产表不在该 crate，其 `mod.rs:13` 注释已声明）；udf 父仓（禁动，缺口只登记）。

---

## 3. 验收门（实跑，命令 + 尾部）

环境：`CARGO_TARGET_DIR=D:/Project/Xray-core-rust/target-cr1b`（独占）、`BORING_BSSL_PATH=target/boringssl-asm/prebuilt`（asm 预构建，规避 NO_ASM）、`-j 8`。

### 3.1 `cargo test -p xray-core --all-targets`

```text
test result: ok. 477 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out; finished in 32.07s
     Running tests\bind_failure_fatal.rs
running 1 test  → test result: ok. 1 passed; 0 failed
     Running tests\invalid_inline_cert_startup.rs
running 1 test  → test result: ok. 1 passed; 0 failed
（wall 374.12s）
```
**477 + 1 + 1，0 failed，2 ignored** = 与任务书期望形态一致（不劣化）。注册表专项两测在册：`inbound::tests::xiuvr3a_registry_behaviour_lifecycle`、`inbound::tests::xiuvr3a_registry_behaviour_matrix_19kinds_x3variants`（19 键 × 3 变体 + D1 升序断言）。

### 3.2 `cargo clippy --workspace --all-targets -j 8 -- -D warnings`

```text
FMT_EXIT=0
    Checking xray-core v0.1.0 → Checking xray-cli → xray-stress → xray-integration-tests
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 2m 46s
（error 行 0；含 W7Redline 在飞的 crates/xray-proxy-vless/src/encryption/vision_conn.rs 改动同样过门）
```

### 3.3 `cargo fmt --all -- --check`

```text
FMT_EXIT=0
```

### 3.4 双向互操作矩阵

**3.4.1 验收门实跑 12/12（本地源站同构版）**——被测 Rust 二进制 = 本票构建产物 `D:/tmp/cr1b/xray-cr1b.exe`（md5 `c4abec3a34ee1e41bcbfbcc2c606b0d5`，`cargo build --release -p xray-cli` 15m29s）：

```text
== A: Rust client -> Go server ==
[PASS] #01..#06  vmess / vless_vision_tls / trojan_tls / vless_ws / ss / ss2022   HTTP body=200014B
== B: Go client -> Rust server ==
[PASS] #07..#12  同上 6 协议                                                    HTTP body=200014B
=== 互操作矩阵: 12/12 PASS ===
（49.13s）
```

**3.4.2 为什么不是 `dist/interop_matrix.py` 原样跑**（如实记账，勿重踩）：原脚本判据 = `curl https://www.youtube.com/` 的 `YouTube` marker + >5000B。本机**直连 youtube 不可达**，同窗实测：

```text
curl --max-time 12 https://www.youtube.com/   → curl: (28) timed out, DIRECT_HTTP:000
curl --max-time 8  https://www.gstatic.com/generate_204 → GSTATIC_HTTP:204  （通用外网正常）
```

原脚本原样跑 = **0/12**，且 #09 的 Rust 服务端日志已显示 `trojan dispatching peer=127.0.0.1:5255 … dest=tcp:www.youtube.com`（**隧道本身通了**，卡在服务端外出抓取 youtube），两方向同红 ⇒ 环境不可达，非协议回归。故改用**同构判定**：本地源站（`127.0.0.1:19190`，200KB + `INTEROP_MARKER`，`Content-Length` 显式），判据仍是「>5000B ∧ marker」，即"隧道两向互通"这一被验收对象；端口段 19140+、进程名 `xray-cr1b*.exe`、`taskkill` 只清自有镜像名（**不碰 `dist/xray.exe` 红线、不杀他人进程**）。脚本落 `D:/tmp/cr1b/`，不入库。

### 3.5 32/32 VPS

**不跑**（按任务书 P0-4 归 PM）。

---

## 4. 残余与 udf 缺口登记（不动 udf 父仓，只登记）

| # | 缺口/残余 | 量级与判据 | 处置 |
|---|---|---|---|
| R1b-1 | `BoundedRegistry::get/remove` 写死 `&K`，无 `Q: ?Sized + Borrow<Q>` 泛型 ⇒ 4 处管理面站点各一次 `String` 分配（`contains`/`remove_inbound`/`user_manager`/`register_user_manager`） | 管理 API + 启动期；C-R1a 实测该类分配 35.3 ns/次；非数据面 | 登记建议：udf 侧加 `Borrow<Q>` 泛型（走 `n539c` 外部窗口）；主仓届时一行回落。**禁** thread_local 缓冲（ADR-2 明禁）与自造索引 |
| R1b-2 | `BoundedRegistry` 无 `get_mut` ⇒ `register_user_manager` 走 `remove`+`insert`（2 次树操作 + 2 次分配；旧 `iter_mut().find` = 1 次） | 每 inbound 启动 1 次（仅 ss 系） | 同上登记为 udf API 增强候补；外层已用同一写锁段保证原子（无竞态窗） |
| R1b-3 | 泄漏断言（`BoundedRegistry::is_empty`/`iter`）**生产未接线** | 停机期生产表非空（inbound 生命周期跨进程），接 Drop 断言 = 停机必 panic | 有意不接；测试面已用 `list().is_empty()` 做残留断言。`expect_empty`/`LeakGuard` 全仓零引用（`grep` 实跑 No matches） |
| R1b-4 | 文档失真（**交 PM**）：`docs/architecture/xray-frame-能力收敛方案-2026-10-27.md` 三处仍把 inbound 注册表记为「O(n) 扫 / 另波（W9）」——§4 第 12 行（:58）、§10.1 实现表（:566）、§10.1 归零表（:686） | 与 `fe8d5481`（inbound 侧）与 `554377d7`（outbound 侧）实际状态不符 | 本票不改他人规划文档，交 PM 同步；同族红线（`PoolManaged` 假同构）在两处仍有效，可保留 |
| R1b-5 | ~~工作树 `Cargo.lock` 漂移 2 行~~ **已闭环**：来源 = CR2 的 `12a3ff2b` 提交 kcp `Cargo.toml` 新依赖未带锁条目，本票构建时 cargo 自动补写；PM 补笔 `073870b5` 已入库（仅 Cargo.lock 两行），工作树干净 | `git status --porcelain Cargo.lock` = 空（CR2 复核）；`--locked` 在 HEAD 可用 | 无剩余动作；广播已更正（勿 checkout 提醒作废） |

---

## 5. 5 轴自评

- **准确性 5/5**：改前源码取自 `git show fe8d5481^:crates/xray-core/src/inbound.rs`（实读）；udf API 断言引自 `crates/udf-frame/skeleton-infra/src/memgov.rs:54-110`；Go 语义引自 `D:/Project/Xray-core/app/proxyman/inbound/inbound.go:41-103`；每个数字附命令与尾部（§3.1-3.4）。
- **完整性 4/5**：四门全跑（测试 477+1+1 / clippy 0 / fmt 0 / 互通 12/12）、8 站点清单、6 维度改前改后对照、keying 与热路径两问都给了独立证据；**扣分**：`dist/interop_matrix.py` 原样判据因外部 youtube 不可达未能在本机跑出 12/12（用本地源站同构替代并如实记录），32/32 按任务书归 PM 未跑。
- **清晰度 5/5**：先答「keying / 语义 / 热路径」三问，再给站点清单、门、残余；对照一律「改前 → 改后 → 判定」三列。
- **可执行性 5/5**：复跑命令含完整 env 与路径；私有脚本路径、二进制 md5、端口段、kill 目标都可复核；D1 裁决附 Go 上游 file:line。
- **简洁性 4/5**：无过程叙述，但 §3.4.2 与 §1.2 D1 偏长——保留理由：前者防下一个人把「0/12 全红」误读为代码回归重做一遍，后者是顺序语义裁决的唯一证据链。

## 6. 未做（明确不在本票）

- 不改 `fe8d5481`（W4 `b46d6058` 之后的既有形态）与任何 W4 scope/redline 调用；
- 不动 `functions.rs`/`arm_builders/**`/`xray-frame`/`vless`/`vision`/`app-dns`/`dispatcher`/udf 父仓；
- 不跑 32/32 VPS；不 commit / 不 push；
- 不做 udf `Borrow<Q>` / `get_mut` 父仓改动（只登记 R1b-1/R1b-2）。
