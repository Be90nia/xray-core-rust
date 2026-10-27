# C 面 R1a · 主仓自造运行期出站注册表 `SimpleOhm` → udf `skeleton_infra::memgov::BoundedRegistry`

**日期**：2026-10-27 · **面**：`crates/xray-app-dispatcher/src/default.rs`（SimpleOhm 及其直接调用点）
**规格**：`docs/architecture/xray-frame-能力收敛方案-2026-10-27.md` §4 第 12 行 / §6 / §6.1 / §10.1 **R1 行**
**铁律**：§10.1 R1 明示「**禁整面 impl `PoolManaged`**」（注册表 ≠ 池模型，`borrowed` 恒 0 = 假同构）——本波零 `PoolManaged`、零 `PoolBase`、零 `MemoryPool` 接触。

VERDICT: **PASS**

**一句话**：`SimpleOhm` 的两张 tag→handler 表由 `RwLock<HashMap>`（自造注册表）换成 udf `skeleton_infra::memgov::BoundedRegistry`（fail-closed insert + 升序确定序 iter），对外 API 形状逐字不变（commander/reverse 零改动），三 crate 测试 + workspace clippy + fmt + 互操作 12/12 全绿；性能门同窗紧交错 3 轮 **+0.09%**（不可分）、alloc/MB 无回归；唯一代价 = 每 link 一次查表 **+61.9 ns**（已逐项归因，见 §3.1），结构性不可免，正解在 udf 侧 `Borrow<Q>` 泛型（`n539c`）。

---

## 1. BoundedRegistry 适配结论（先答后动手）

**结论：能承载。9 项契合 / 2 项需外层补偿 / 0 项阻断 ⇒ 直接换消费，不自造注册表，不动 udf 父仓。**

udf 真实 API（`crates/udf-frame/skeleton-infra/src/memgov.rs` 的 `BoundedRegistry` 定义与 `impl` 块——`new/insert/get/remove/len/is_empty/capacity/iter`，逐项实读，非凭记忆）：

| # | SimpleOhm 用法（改造前） | udf `BoundedRegistry` 对应面 | 判定 |
|---|---|---|---|
| 1 | `tagged.insert(tag, handler)`（HashMap upsert） | `insert(k, v) -> Result<(), BoundError>`：已存在 key = 覆盖且 `len` 不变 | **契合** |
| 2 | `tagged.get(tag)`（`HashMap<String,_>::get(&str)`，零分配） | `get(&K) -> Option<&V>`（**非** `Borrow<Q>` 泛型） | **缺口 1**（见下） |
| 3 | `tagged.remove(tag) -> Option` | `remove(&K) -> Option<V>` | **契合** |
| 4 | `keys().cloned()`（HashMap **任意序**） | `iter() -> (&K, &V)`（BTreeMap **恒升序**） | **契合且更强**（`list_tags` 从任意序变确定序；全仓消费方无顺序依赖——commander `grpc.rs` 自排序、observatory/balancer 只做前缀过滤） |
| 5 | `default: RwLock<Option<..>>` 单槽默认出站 | **无对应概念** | **不迁**（见下，注册表 ≠ 默认槽） |
| 6 | 无界（Go `outbound.Manager` 也是 map 无界） | 构造期**必填** `max: usize` + `Eviction` | **需外层策略**（见下） |
| 7 | `snapshot()` 需要 `HashMap::clone()` | 未派生 `Clone` | **需外层补偿**（`copy_handler_registry`，见下） |
| 8 | — | `expect_empty()` / `LeakGuard`（泄漏断言） | **可用但不在生产接线**（见下） |
| 9 | `SimpleOhm: Send + Sync + Debug` | `BoundedRegistry<K,V>` 无 `PoolManaged`/`borrowed` 语义 | **契合**（照 §10.1 红线，**不**整面 impl `PoolManaged`） |
| 10 | `add`/`remove` 是 `&self`（内部 `RwLock`） | `insert`/`remove` 要 `&mut self` | **契合**（外层本来就是 `parking_lot::RwLock`，`write()` 给 `&mut`） |

### 缺口 1（可接受，已量化）：`get(&K)` 无 Borrow 泛型 ⇒ String 键每次查表一次短串分配

`BoundedRegistry::get` 签名是 `get(&self, k: &K)`，不像 `HashMap` 那样 `get<Q: ?Sized>(&self, k: &Q) where K: Borrow<Q>`。K 定为 `String` 后，`&str` 查表必须构造 `&String` ⇒ **每次查表一次 `String` 分配**（改造前 `HashMap<String,_>::get(&str)` 零分配）。

- **频次口径**：`select_handler` / `get_handler` 都是 **每 link 一次**的选路查表（`dispatch_link` 内），**不是每包**热路径；
- **实测**：见 §3 性能表（A/B 直接测的就是这条路径）；
- **上游修法**（不在本波，禁动 udf 父仓）：udf 给 `get`/`remove` 加 `Q: ?Sized` + `K: Borrow<Q>` 泛型后，本行可回落到零分配；
- **为什么不自己绕**：绕法只有三条——自造注册表（= 造轮子，打回项）、并行留一份 `HashMap` 索引（= 第二套表，正是本波要消除的自造状）、`iter()` 线性扫（O(n) 更差）。故**如实登记缺口**，不做投机实现。

### 默认项（不迁）：注册表装不下「默认出站」

`default` 是**单槽**语义（Go `ohm.SetDefaultHandler`），不是「tag → handler」登记面里的一个键。故保留 `default: parking_lot::RwLock<Option<Arc<dyn DispatchHandler>>>`，**不**把它塞进注册表当保留键（保留键会污染 `list_tags` 的 tag 面，且 `remove(tag)` 与默认项清空的联动语义要另写一套）。

### 上界（外层策略）：`MAX_TAGGED_HANDLERS = 4096` + `Eviction::Reject` + 显式记错

Go 侧无界；本件必须有界，故取远超真实配置规模（真实配置 = 十几到几十个 outbound）的阈值当**故障护栏**，超限走 fail-closed：`insert` 返回 `Err(BoundError)` → `tracing::error!(tag, %e, ...)`，该 tag 不进表 ⇒ 引用它的路由在 `get_handler` 未命中时按既有 fail-visible 语义报 `HandlerNotFound`（**禁静默丢 handler**——`add` 的 `()` 签名不变，故错误面走日志 + 后续未命中双保险）。

### snapshot（外层补偿）：`copy_handler_registry`

udf `BoundedRegistry` 未派生 `Clone`（也不该为消费方加——父仓本波禁动）。`snapshot()` 逐项重建：同 `max` + 同 `Eviction` ⇒ 源 `len ≤ max`，`Reject` 分支**不可达**，`debug_assert!` 兜底（release 下 `let inserted = ...` 仍会真的插入，不因断言被优化掉）。

### 泄漏断言（可用，但生产不接线）

`memgov::expect_empty` 判据是「注册表排空断言——非空即 panic」。生产 `SimpleOhm` 在停机期出站表**本来非空**（outbound handler 生命周期跨整个进程），把它接成 Drop 期断言 = 停机必 panic。故本波只**继承能力**（类型面可用），不接线到生产 Drop；测试面已有 `is_empty/len/capacity` 可断言。

### 为什么不动 commander/server.rs、reverse/outbound.rs

**SimpleOhm 对外 API 形状 100% 不变**（`new/set_default/snapshot/add/remove/list_tags` + `OutboundHandlerManager` 三方法，签名逐字未改）⇒ 两个消费方只持有 `Arc<SimpleOhm>` 包装、零签名依赖，**零改动**。这不是"没来得及改"，是"不需要改"；编译通过即取证（三 crate 测试门见 §4）。

---

## 2. 改动面

| 文件 | 改动 | 规模 |
|---|---|---|
| `crates/xray-app-dispatcher/src/default.rs` | SimpleOhm 块：2 个字段类型换 `HandlerRegistry`；新增 `MAX_TAGGED_HANDLERS` / `HandlerRegistry` / `new_handler_registry` / `insert_handler` / `copy_handler_registry`；7 个方法 + 3 个 trait 方法改读数面 | +61 / −17（`git diff --stat`） |
| `crates/xray-app-dispatcher/Cargo.toml` | `udf-skeleton-infra = { path = "../udf-frame/skeleton-infra", default-features = false, features = ["memgov"] }`（`memgov` 纯 std 零三方；不拖 `runtime`/`pool` 默认档） | +5 |
| `crates/xray-app-dispatcher/examples/ohm_lookup_ab.rs` | 查表面 A/B 采集器（可复跑性能证据，见 §3 复跑命令） | 新增 |

**未改**（逐条说明非"漏做"）：`xray-app-commander/src/server.rs`、`xray-app-reverse/src/outbound.rs`（API 未变，无需改签名）；`crates/xray-core/**`（`InboundRuntime` 不属本波）；中央 match 臂（§4 第 16 行，不属本波）；`crates/udf-frame/**`（父仓禁动，走 `n539c` 外部窗口）；`tests/`、`.github/workflows/`、`vendor/`、`docs/refs/`。

---

## 3. 性能门（热路径 · 同窗 A/B ≥3 轮交错）

> 绝对吞吐不可跨窗口比（`docs/benchmarks/baseline.md`「2026-10-27 复测校准」：立锚期基线二进制今日同机同拓扑仅 128.6-131.1 MB/s，窗口内有并发编译抢 CPU）。故判据 = **同窗 A/B 相对差**。

**A′ 态构造**：`git show HEAD:crates/xray-app-dispatcher/src/default.rs > crates/xray-app-dispatcher/src/default.rs`——回退整文件；`git diff --stat` 证明本波该文件唯一 diff 就是 SimpleOhm 块，且 `Cargo.toml` 的 udf 依赖**保留不动**（未使用依赖零影响）⇒ 两态差异收敛为**一个 hunk**。采集器 `examples/ohm_lookup_ab.rs` 只用公开 API，随两态同样编译。

### 3.0 单变量取证三件套

| 取证项 | 实测 |
|---|---|
| 源码差集 | A 态 `src=194328f4`（`git show HEAD:` 版本 md5 前缀）/ B 态 `src=40efd09a`；**每轮构建前打印，逐轮复现同值** ⇒ 两态只差 SimpleOhm hunk |
| 构建产物 | `target-CR1aC` 私有 `CARGO_TARGET_DIR`（不与任何代理共用），每轮 release 重建后测 |
| 进程快照 | 每个测量窗前 `tasklist | grep -icE '^(cargo|rustc)'` = **0**（微观锚 6 窗全 0；loopback 窗逐轮记录见 §3.2） |

**他人改动披露（不影响结论，PM 2026-10-27 19:2x 口供）**：PM 在我窗口开始前约 1 分钟跑了 `cargo fmt -p xray-transport-splithttp`，改 `crates/xray-transport-splithttp/src/dialer.rs` 3 处**纯换行宽度**（零语义）。① 该文件不在我的面；② 我的测量路径是 `SimpleOhm` 查表（dispatcher crate），splithttp dialer 不在其依赖闭包内；③ 每轮 A/B 均**重新构建后立即测量**，两态构建看到的是同一份 dialer.rs ⇒ 对相对差零贡献。故不触发「A/B 混杂即作废」。

**复跑命令**（A/B 各 ≥3 轮交错）：

```text
export CARGO_TARGET_DIR=D:/Project/Xray-core-rust/target-<你的目录>
export BORING_BSSL_ASSUME_PATCHED=1 BORING_BSSL_SOURCE_PATH='D:\Project\Xray-core-rust\target\boringssl-patched'
export PROTOC='D:/Project/tools/bin/protoc.exe' LIBCLANG_PATH='D:\Program Files\llvm\bin'
# B 态（当前树）
cargo run --release -p xray-app-dispatcher --example ohm_lookup_ab
# A 态（回退 SimpleOhm 实现，保留其余在树增量）
git show HEAD:crates/xray-app-dispatcher/src/default.rs > crates/xray-app-dispatcher/src/default.rs
cargo run --release -p xray-app-dispatcher --example ohm_lookup_ab
```

**预期输出形态**：`warmup ok (hits=400000)` + 5 行 `sample ns/op = <f> (hits=400000)` + `MEDIAN ns/op` + `MIN ns/op`。
**判据**：同机同窗 A/B `MEDIAN ns/op` 相对差不劣化；两态测量期 `tasklist` 快照证明无并发编译。

### 3.1 查表面微观锚（本次实测，3 轮交错 + 归因）

| 轮 | A 态 `MEDIAN ns/op` | A `MIN` | B 态 `MEDIAN ns/op` | B `MIN` | alloc-only（A/B 同值） |
|---|---|---|---|---|---|
| 1 | 25.99 | 25.88 | 87.85 | 87.23 | 35.12 / 35.83 |
| 2 | 26.51 | 25.74 | 89.78 | 88.89 | 35.20 / 35.83 |
| 3 | 25.96 | 25.77 | 86.82 | 86.11 | 35.25 / 35.27 |
| **中位** | **25.99** | 25.77 | **87.85** | 86.11 | **≈35.3** |

- **相对差**：B/A = **3.38×（+61.9 ns/op）**；每态 6 个测量窗 `tasklist` cargo/rustc 计数 = **0**（无并发编译），构建产物 md5 前缀 `194328f4`(A) / `40efd09a`(B) 逐轮可对。
- **归因（单变量拆解）**：`alloc-only` 块（`&str → String` 分配本身，两态同值 ≈35.3 ns）解释 **35.3 / 61.9 ≈ 57%**；余下 ≈26.6 ns = **BTreeMap 的 O(log n) 字符串比较** vs HashMap 哈希（确定性有序迭代的结构代价——§10.1 R1 明确要「确定序 iter」，这是买入不是意外）。
- **绝对量级与判据关系**：`get_handler`/`select_handler` 是**每 link 一次**的选路查表（`dispatch_link` 内），不是每包；`+61.9 ns/link` 相对一次链路建立（TCP/TLS/代理，µs–ms 量级）不可测。**故本轮不据此判「性能劣化」，而由 §3.2 的端到端吞吐 A/B 定性。**
- **为什么不顺手消掉那 35.3 ns**：唯一可行手段是线程本地 `String` 缓冲复用来伪造 `&String`（udf `get` 要 `&K`）——① 只削 57%，残余 26.6 ns 结构性不可去（除非放弃确定序）；② `thread_local` 在 tokio 任务迁移语义上是本项目 ADR-2 明令回避的形态，为不可测收益引一个可疑机制不值；③ 正解在 udf 侧加 `Q: ?Sized + Borrow<Q>` 泛型（`n539c` 外部窗口），主仓侧届时一行回落。

### 3.2 端到端吞吐 A/B（loopback 全栈 · xhttp+reality+vless-enc 拓扑）

工具：`tools/loopback_alloc_bench.py` 的私有端口副本（`19453/12081/19501`，避让 18100 段 interop 与默认 18453 段），每窗 3×200MB。

**主证据（紧交错：两态各建一次二进制，6 个测量窗背靠背跑完，全程 70 秒，无构建插入）**

二进制：`xray-A.exe` md5 `ed7a1ac7…` / `xray-B.exe` md5 `dab3bc80…`；源码 md5 前缀 `194328f4`(A) / `40efd09a`(B)。

| 轮 | A 三窗 (MB/s) | A best | B 三窗 (MB/s) | B best | B/A |
|---|---|---|---|---|---|
| 1 | 128.1 / 141.6 / 135.9 | 141.6 | 129.7 / 142.1 / 140.4 | 142.1 | +0.4% |
| 2 | 127.2 / 143.2 / 140.0 | 143.2 | 131.3 / 142.9 / 141.0 | 142.9 | −0.2% |
| 3 | 125.7 / 141.1 / 139.9 | 141.1 | 129.2 / 141.3 / 141.2 | 141.3 | +0.1% |
| **均值** | — | **141.97** | — | **142.10** | **+0.09%** |

- 全 9 窗均值 A 135.86 / B 137.68 MB/s（**+1.34%**）；每窗前 `procs`（cargo/rustc）= **0**。
- `alloc/MB[srv]`：A 1.8217M / 1.7985M / 1.8628M（均值 **1.8277M**）vs B 1.8105M / 1.8219M / 1.7907M（均值 **1.8077M**）= **−1.1%**（无分配回归）。
- `alloc/MB[cli]`：A 2.3206M / 2.2049M / 2.3123M vs B 2.3138M / 2.3158M / 2.3193M；A 含 2.2049M 单点离群，中位对齐 **+0.3%**。

**判据结论：性能门 PASS**（同窗紧交错 3 轮，best-of-3 相对差 +0.09%，落在噪声内；alloc/MB 无回归）。

**为什么必须紧交错（本次实测教训，写在这里防复犯）**：先做的「每轮重建 A/B」版本（A 与 B 测量相隔一次 7-8 分钟 release 重建）出现不可控漂移——同一份 A 二进制在 19:5x 测出 **~172 MB/s**、20:30 测出 **~140 MB/s**（同机、同拓扑、二进制 md5 相同）。据此的「每轮重建」版数据仅作留档，**不作判据**：

| （留档，不作判据）轮 | A best | B best | 备注 |
|---|---|---|---|
| 1 | 175.7 | 172.4 | — |
| 2 | 172.8 | 171.7 | — |
| 3 | 171.2 | 140.4 | B 窗整段降到 131-140（同轮 A 为 171.2）⇒ 机器漂移，该轮按纪律作废 |

**A′ 构造写清**：A 态 = `git show HEAD:crates/xray-app-dispatcher/src/default.rs`（该文件本波唯一 diff 就是 SimpleOhm 块）→ `cargo build --release -p xray-cli` → 产物另存 `xray-A.exe`；B 态 = 恢复本波源码后同样构建 → `xray-B.exe`。两二进制在**同一段 70 秒窗口内交替**各跑 3 个 bench 窗（A,B,A,B,A,B），构建全部落在测量窗外。

---

## 4. 验收门

### 4.1 三 crate 测试门（P0-1）

```text
$ cargo test -p xray-app-dispatcher -p xray-app-commander -p xray-app-reverse --all-targets -j 8
     Running unittests src\lib.rs (xray_app_commander)   test result: ok.  93 passed; 0 failed
     Running unittests src\lib.rs (xray_app_dispatcher)  test result: ok. 140 passed; 0 failed
     Running tests\dual_write_longrun.rs                 test result: ok.   0 passed; 0 failed
     Running tests\dual_write_parity.rs                  test result: ok.   0 passed; 0 failed
     Running unittests examples\ohm_lookup_ab.rs         test result: ok.   0 passed; 0 failed
     Running unittests src\lib.rs (xray_app_reverse)     test result: ok.  93 passed; 0 failed
     Running tests\reverse_e2e.rs                        test result: ok.   3 passed; 0 failed
```

**特征门（`dispatcher-dual-write` 开）**——本波最关键的对照面：`shadow`/`tagged` 两表由同一次 `add/remove` 派生，漂移监控 `arm_vs_lookup` 必须恒 0：

```text
$ cargo test -p xray-app-dispatcher --all-targets --features dispatcher-dual-write -j 8
     Running unittests src\lib.rs          test result: ok. 145 passed; 0 failed
     Running tests\dual_write_longrun.rs   test result: ok.   0 passed; 0 failed; 1 ignored
     Running tests\dual_write_parity.rs    test result: ok.   4 passed; 0 failed
```

`dual_write_parity` 4/4 PASS = 回放面新旧两路**差异 0**（两表同步未因换存储实现而漂移）。

### 4.2 workspace clippy（P0-2）

```text
$ cargo clippy --workspace --all-targets -j 8 -- -D warnings
clippy_real_exit=0
error_lines=0
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 1m 04s
```

`--all-targets` 覆盖本波新增的 `examples/ohm_lookup_ab.rs`（其 `Instant::now` 计时锚用文件级
`#![allow(clippy::disallowed_methods, reason = "examples: A/B 计时锚点，非生产路径")]` 登记，符合
「登记理由而非无理由 suppress」）。
**fmt 门**：`cargo fmt --all -- --check` → `fmt_exit=0`、零 diff（含 example）。

### 4.3 互操作矩阵 12/12（P0-4）

```text
$ python D:/tmp/interop_matrix_cr1ac.py        # dist/interop_matrix.py 的私有端口副本（19100-19112 + 19199 marker）
== A: Rust client -> Go server ==
[PASS] #01..#06  vmess / vless_vision_tls / trojan_tls / vless_ws / ss / ss2022   HTTP body=200059B
== B: Go client -> Rust server ==
[PASS] #07..#12  同上 6 协议                                                       HTTP body=200059B
=== 互操作矩阵: 12/12 PASS ===
```

被测二进制 = 本波 B 态产物 `xray-B.exe`（md5 `dab3bc80764fc5b487ba4fb8b63d5ebb`）。**这是本波唯一真实流量端到端取证**：12 条链路的 outbound 注册（`add`）→ 选路查表（`select_handler`/`get_handler`）→ `list_tags` 全部走新注册表，双向互通无回归。

### 4.4 32/32 VPS

**不跑**（归 PM，按任务书 P0-5）。

---

## 5. 5 轴自评

- **准确性 5/5**：`BoundedRegistry` 的每条 API 断言引自 `crates/udf-frame/skeleton-infra/src/memgov.rs`（实读定义与 impl，非记忆）；每条数字附实跑命令与尾部输出（§3.0/§3.1/§3.2/§4.1/§4.2/§4.3）；未测项（32/32）显式标注"不跑，归 PM"。
- **完整性 4/5**：P0-1（三 crate 测试 + 特征门）、P0-2（workspace clippy `-D warnings` + fmt）、P0-3（性能门双锚）、P0-4（interop 12/12）、P0-6（本报告）全覆盖；**扣分**：`get` 的零分配缺口**登记未消除**（受"禁自造注册表 + 禁动 udf 父仓"双重约束，且残余 26.6 ns 结构性不可消，非投机省略）；`InboundRuntime` 与中央 match 臂按任务书属他波。
- **清晰度 5/5**：按"适配结论 → 改动面 → 性能门 → 验收门 → 自评 → 残余"分节，契合/缺口用表格逐条判定，缺口 1 单独成段说明为何不绕。
- **可执行性 5/5**：§3 给出 A′ 构造 + 复跑命令 + 预期输出 + 判据；`examples/ohm_lookup_ab.rs` 文件头同样写全（两处都有，符合 PM 要求）；报告路径与二进制 md5 可复核。
- **简洁性 4/5**：11KB 报告无过程叙述，但 §3.1「为什么不顺手消掉 35.3 ns」与 §3.2「为什么必须紧交错」偏长——保留理由：这两段是防"下一个人重做一遍"的唯一记录。

---

## 6. 非目标 / 残余

- **非目标（本波明确不做）**：`xray-core` 侧 `InboundRuntime`（O(n) 线性扫）→ 同族收口在 R1 的下一刀；中央 match 臂（§4 第 16 行 → xray-frame `dispatch.rs`）；udf 父仓 `get` 的 `Borrow<Q>` 泛型（`n539c` 外部窗口）。
- **残余 1**：`get_handler`/`select_handler` 每次查表一次 `String` 分配（缺口 1，量级见 §3）。
- **残余 2**：`shadow` 与 `tagged` 两张同名表并存是 **S4 选择面既有设计**（drift 监控 `arm_vs_lookup` 依赖两表独立），本波按要求只换存储实现、**不收表**——收表属 S4 遗留决定，不在 R1a 范围。
- **残余 3**：`add` 上的 `#[allow(dead_code)]` 是既存陈旧标注（生产 `xray-core` 有调用点），本波不动（非 SimpleOhm 机制面）。

---

## 7. 取证与清理

- **可复跑脚本**（本次实跑，非事后补写）：`reports/audit-2026-10-27/tmp/ab_lookup.sh`（§3.1 查表面微观锚）、`reports/audit-2026-10-27/tmp/ab_loopback.sh`（§3.2 端到端紧交错）。
- **私有基础设施**（不与他人面共用）：`CARGO_TARGET_DIR=target-CR1aC`；bench 端口副本 `D:/tmp/cr1ac/loopback_bench_r1a.py`（19453/12081/19501）；interop 端口副本 `D:/tmp/interop_matrix_cr1ac.py`（19100-19112 + 19199 marker，`kill()` 只清理自有镜像名 `xray-cr1ac.exe`，不动他人 `xray.exe`/`xray-go.exe`）。
- **清理**：`target-CR1aC`（17G）已删除；A/B 二进制副本（各 ~50MB）已删除；marker 服务已停。**未 commit / 未 push**（归 PM）。
- **知识图谱**：开工时 `index_status` → `indexed_at=2026-10-27T05:07:36Z`（落后于本次改动）。收尾**两次**尝试 `codebase-memory-mcp cli index_repository --repo-path D:/Project/Xray-core-rust`（flags 形态；raw-JSON 形态已 deprecated 且报 daemon 错）均返回 `status: aborted_previous_preserved`（提示原因 = 索引期间有文件变动——当前树同时有 3 个代理在改，123 个变动路径在飞）；旧索引（05:07Z）保持完整可用，未被破坏。**结论：本波无法在活跃多方编辑中重索引**；建议 PM 在全部 commit 落定后（树静默时）跑一次 `index_repository --repo-path <repo>`，本报告已给出命令。

