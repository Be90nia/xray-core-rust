# R2（面 14 通用散件）：主仓自造通用件换 udf std-ext 已有件

- 执行人：CR2Generic（fullstack-engineer）
- 日期：2026-10-27
- 依据：`docs/architecture/xray-frame-能力收敛方案-2026-10-27.md` §4 行 14 / §7.3 行 14 / §10.1 R2 行；CLAUDE.md §3.5.2/§3.5.5
- **VERDICT：DONE —— 4 面中 1 面实换（kcp RetryableWriter → `std_ext::retry`）；3 面经逐件核实**不换**（非任务书预设的"三处缓存全换"，而是 1 换 + 6 项有据不换）；DNS cache_controller 经四缺口论证报 PM，**PM 已裁决：路径 B 维持现状登记（ADR-1 判据③正常出口，显式豁免项）**。宁可不换不硬套。**

---

## 0. 总账

| 任务书面目 | 树内实况 | 结论 |
|---|---|---|
| 1. DNS `cache_controller` → `TtlCache` | `crates/xray-app-dns/src/cache_controller.rs`（`RwLock<HashMap<String, Arc<Record>>>`） | **不契合**（4 缺口，§1；登记待裁决，未动一行） |
| 2. 自造 uuid（config.rs:132 / tool.rs:55）→ `IdGen` | 两处均为 **`uuid` crate 直用（生态标准件，非自造）**，v4 随机语义 | **不需要换**（§2） |
| 3. key cache / geo weak cache 三处 | 全树扫遍：fakedns **已是** udf `LruCache`（bd b2qdu）；`weight.rs` memo cache 形态不契合；**"geo weak cache" 树内不存在**（任务书前提与树不符） | **1 已接 + 1 不契合 + 1 不存在**（§3） |
| 4. 重试/退避各处自造 → `std_ext::retry` | 7 处定位，**1 处真契合已换**（kcp），6 处有据不换 | **1 换 + 6 登记**（§4） |

---

## 1. 面 1：DNS CacheController → udf `std_ext::cache::TtlCache` —— **不契合（停下报 PM）**

对象：`crates/xray-app-dns/src/cache_controller.rs`（Go `app/dns/cache_controller.go` 对应物）。
现状形态：`ips: RwLock<HashMap<String, Arc<Record>>>` + `high_watermark: RwLock<usize>` + `broadcast` 事件 + `single_flight` + 注入 `Clock`；读路径 `find_records(&self)` 走 `read()` 锁（DNS 热路径，多任务并发读）。

### 缺口论证（四条，逐条对着 udf 源码 `crates/udf-frame/std-ext/src/cache.rs` 实读）

1. **条目级双 TTL vs 单 TTL/键**。`Record { a: Option<IpRecord>, aaaa: Option<IpRecord> }`——A/AAAA **各自独立 `expire`**，cleanup 只清过期家族、保留活家族（`cleanup_and_maybe_shrink` 内 `rec_mut.a = None` 而 aaaa 不动）。`TtlCache` 契约是**每键一个 TTL**（`insert(k, v, ttl)` expire-after-write）。承载它须把键改成 `(domain, is_v4)` 拆两表 → `find_records`/`merge_records`/shrink 语义全改 = 行为变更 + 造一层索引（§3.5.2 禁项）。测试 `dual_family_ttl_independent`（cache_controller.rs:637）已把双家族独立 TTL 钉成契约。
2. **serveStale 要求"读过期条目"，TtlCache 结构性相反**。`effective_now` 把 now 回移 `serve_expired_ttl` 秒以**保留并提供已过期数据**（`CacheOptimiste` 路径，Go serveStale 语义）。`TtlCache` 读面（get/peek）**触碰即回收**过期条目 + 计入 `expired`——过期数据到手即毁，serveStale 在 TtlCache 上不可表达。这不是缺方法，是回收语义与保留语义对撞。
3. **淘汰策略不同类**。Go 语义 = **无容量界** + 300s 周期清理 + 收缩策略（`MIN_SIZE_FOR_EMPTY_REBUILD=512` 空表重建 / `SHRINK_ABSOLUTE_THRESHOLD=10240`×`0.65` 比例收缩 / high watermark）。`TtlCache`/`LruCache` 是**容量界 + 满 插入逐 LRU 尾**。套上必选容量 = 发明 Go 没有的淘汰常量，DNS 记录会被 LRU 压力挤掉而非 TTL 自然过期——wire 可见行为变更。
4. **并发面禁降级**。`TtlCache` 单线程 `&mut self`（udf 源码明示"并发另批，无内部锁"）。承载并发读须外层 `Mutex`——DNS 查询热路径全部读操作串行化（`get` 本身还 mutate recency/惰性过期，读也须写锁）。**任务书明令禁止，fakedns 先例（bd b2qdu 外层 Mutex + LruCache）不适用**：fakedns 是低频查询面，cache_controller 是每域名解析热路径。

### 两种收敛路径（待 PM 裁决，本轮不动）

- **路径 A（等 udf 补并发面）**：udf `cache` 域补并发形态（`RwLock` 内核 + 条目级多 TTL + 过期保留读面）。范围大，且"过期保留读"与"惰性回收"需要并存语义拍板——建议 udf 侧立票设计，不在主仓硬套。
- **路径 B（维持现状登记）**：`cache_controller` 属 Go 平行实现（带 shrink/水位线/pubsub/singleflight 控制面语义），**不是纯缓存存储件**——其"控制器"半边（收缩策略/清理编排/广播）本就是 Xray 语义留主仓，只有存储内核理论上可外购。登记 `udf-promotion-candidate` 语义缺口即可，不构成融合度损失主因。

**本轮动作：零改动。** cache_controller 现有实现已走 `skeleton::clock`（P1-12）+ `FxScope`（P1-11），通用面（时钟/spawn）已接 udf，唯存储内核留仓。

---

## 2. 面 2：自造 uuid → udf `std_ext::id::IdGen` —— **不需要换（非自造件 + 语义不同类）**

| 站点 | 实况 | 判定 |
|---|---|---|
| `crates/xray-app-dns/src/config.rs:132` `generate_random_tag()` | `format!("xray.system.{}", uuid::Uuid::new_v4())`，Go `app/dns/config.go::generateRandomTag` 对拍（随机 tag 防多 DNS config 冲突） | `uuid` crate = 生态标准件，**无自造轮子**；§3.5.2 打击对象是"主仓自造副本"，不是"消费标准 crate" |
| `crates/xray-cli/src/commands/tool.rs:55` `resolve_uuid(None)` | `uuid::Uuid::new_v4().to_string()`；`xray uuid` 命令（用户**凭据生成工具**，产物进 VLESS user id 等密钥位）；测试钉死 `get_version_num() == 4` + Go v4 对拍 | 见下 |

**`IdGen` 是不同类产品，不是 v4 的等价件**（`crates/udf-frame/std-ext/src/id.rs` 实读）：
- udf 域契约**明写反随机**："随机 id 破坏确定性测试与回放——本域契约：同指纹 + 同钟时间线 + 同调用序 → 逐位同 id 序列"；UUIDv7 **确定性变体**，需要调用方注入机器指纹，counter 基址=指纹派生（可预测是**刻意拍板**）。
- 换 v4 → v7 的后果：① CLI 凭据生成面产出**可预测** id（指纹+时间线可推导）= 安全回归，v4 随机不可预测；② 版本 nibble 7 ≠ 4，Go 对拍与既有测试（`uuid_no_input_generates_v4` 断言 version 4）直接红——**绝不为过门改测试断言**；③ DNS tag 面换 v7 无收益（tag 只需进程内唯一，`uuid` crate 已满足；换掉省不下依赖——workspace 里 `uuid` 仍被 CLI/其他面消费）。
- 方案稿 §6 行 13「自造 uuid → `crates/xray-common`（uuid crate 直用）」的"自造"定性与树内实况不符：xray-common 是 uuid crate 的薄 parse 包装（Go 对拍语义），不是 uuid 生成的自造副本。

**本轮动作：零改动。** 若未来 udf 出"随机 v4 语义"件可再评估；当下 IdGen 的确定性是设计决定不是缺口。

---

## 3. 面 3：key cache / geo weak cache 三处 —— **1 已接 + 1 不契合 + 1 不存在**

全 xray-app-*（8 crate）扫遍（`cache|Cache|lru|Lru|weak|Weak` + `struct \w*(Cache|Lru|Memo)\w*` 两轮）：

| # | 位置 | 形态 | 判定 |
|---|---|---|---|
| 1 | `crates/xray-app-dns/src/fakedns/mod.rs` | fake domain IP 池 LRU——**已接 udf `std_ext::cache::LruCache`**（Cargo.toml:18 注释 bd b2qdu；外层 `HolderInner` `parking_lot::Mutex` 承载单线程 `&mut self`） | **已是 udf 件**（任务书"三处自造"的第一处实为已完成态） |
| 2 | `crates/xray-app-router/src/weight.rs:26` | `cache: Mutex<HashMap<String, f64>>`——tag→权重 **memoization**（键空间 = 配置静态 tag 集，有界且小；无 TTL/LRU 需求） | **不契合**：`LruCache` 构造强制容量上界（无默认无界构造），套上 = 发明容量常量 + insert 路径 `K: Clone` 开销；memo 键集有限无淘汰需求，强套纯属性能/行为噪声。若未来 tag 空间失控再评估 |
| 3 | "geo weak cache" | **树内不存在**（xray-app-geodata 全 crate `Weak|cache` 0 命中；geodata matcher 构建走 `PooledThreadPool` 互喂已接 udf；`xray-app-router/webhook.rs:394` 的 `ponytail:` 注释是"未来才建"的登记不是现存缓存） | **任务书前提与树不符**（方案稿 §4 行 14 的"三处"口径未核对树内现状——fakedns 已接、geo weak cache 无实体） |

另核实（非缓存域，防漏）：`xray-app-dns/server.rs:670` `ROUTE_CACHE: OnceLock<(bool,bool)>` = 一次性系统路由探测结果（OnceLock 惰性初始化非缓存淘汰域）；`xray-app-metrics/debug.rs:31` `PROCESS_START` 同理。

**本轮动作：零改动。**

---

## 4. 面 4：重试/退避 → `std_ext::retry::{RetryPolicy, retry, retry_if, Sleeper}` —— **1 换 + 6 登记**

udf retry 实读结论（`crates/udf-frame/std-ext/src/retry.rs`）：**同步域**（`Sleeper: Clock`，`SystemClock` 线程阻塞 / `MockClock` 虚拟推进）；`RetryPolicy::new(max_attempts 含首试, base, max_delay)` 线性退避饱和截平、**禁 jitter**（确定性拍板）；`RetryError::{Exhausted, OutOfBudget}` 末次错误原样回灌；末次失败后不再睡眠。文档明示"取消协作属 tokio 门内异步形态，本批不入"。

### 4.1 已换：kcp `RetryableWriter`（唯一真契合）

- 位置：`crates/xray-transport-kcp/src/output.rs`（Go `output.go` `RetryableWriter` 对应物，`register.rs:447` 生产接线：KCP worker 同步 flush 上下文）。
- 原形态：手写 `for _ in 0..=retries` 循环 + `std::thread::sleep(interval)` 固定间隔。
- 契合论证：**同步** ✓；固定间隔 = `RetryPolicy::new(retries+1, interval, interval)`（base=max → 线性饱和截平恰为恒 interval）✓；尝试次数语义逐次保留（`0..=retries` = retries+1 次 = max_attempts 含首试）✓；错误回灌 `RetryError::Exhausted.last` → `io::Error` 原样上抛 ✓。**行为差两处且均为严格改善**：① 原实现末次失败后还空睡一个 interval 再返回（Go 实现浪费），udf 裁决序"不为不会发生的重试付出等待"——失败路径省 100ms，成功/失败结局不变；② `interval == 0` 时 udf 构造期 fail-closed panic（原实现是 0 间隔忙等风暴），现网无零间隔调用点（`new()` 固定 100ms，`with_retries` 仅测试用 1ms）。既有 3 个测试（首试成功 / 恰好失败 / 第 3 次成功）断言全部原样通过。
- 改动：`Cargo.toml` +2 path 依赖（`udf-skeleton`/`udf-std-ext`，全零依赖纯 std 件，与 xray-conf/xray-app-dns 同形态）；`output.rs` impl 体 11 行 → udf 调用，结构体 API/字段/测试零动。

### 4.2 不换登记（6 处）

| # | 位置 | 形态 | 不换理由 |
|---|---|---|---|
| 1 | `crates/xray-transport/src/retry.rs` `exponential_backoff` | **async** 指数（实线性）退避，Go `common/retry` 对拍（错误去重聚合 `RetryError{errors:Vec}`）；**10 个消费面**（freedom/http/socks/ss/trojan/vless/vmess dispatcher+client、transport fallback） | **不契合：异步面**。udf retry 同步域（线程阻塞 sleep 会钉死 tokio worker）；且错误聚合语义是 Go 对拍契约（去重累积 Vec vs udf Exhausted.last 单错误）。**udf 缺口登记：异步重试编排（tokio sleep + 取消协作）udf 明示另批**——此件是主仓最大自造重试件，等 udf 异步形态落地后再走 n539c 回路收敛 |
| 2 | `crates/xray-app-commander/src/commander.rs:1201` `dial_with_retry` | async deadline 指数退避（tonic dial） | **双不换**：async（同上）+ commander crate 属 CR1aC 在飞面（本波非目标） |
| 3 | `crates/xray-proxy-tuic/src/pool.rs:265` | async 指数退避取连接环（`sleep(delay).await`） | **不契合：异步面**（同 #1；登记待 udf 异步形态） |
| 4 | `crates/xray-transport-grpc/src/transport.rs:258` `grpc_backoff_delay` | grpc-go `backoff.Backoff` 对拍：封顶后加 **jitter**（±20%） | **不契合：Go 对拍抖动语义**。udf **禁 jitter** 是确定性拍板（禁 jitter ≠ 缺陷）；grpc 抖动防 thundering herd 是 Go 语义保留项，强行换 = 抖动消失 = 行为变更 |
| 5 | `crates/xray-app-observatory/src/observer.rs:155` `backoff_multiplier` | 纯函数：失败轮 → linear 倍率（cap 8×）乘 probe interval，**调度退避非 op 重试编排**（探针环 `tokio::select!` 驱动） | **不适用**：udf retry 是"重试一个 op"的编排件；这是周期任务的间隔计算，无 op 编排可换（且 async 面） |
| 6 | `crates/xray-proxy-tun/src/sysroute/mod.rs:518` `retry_with_backoff` | Windows-only 8 行纯函数：bool 结果 + **注入 sleep 闭包**（测试无真睡） | **换 = 净增代码**：适配 udf 须把闭包包成 `Sleeper`（trait bound `Clock` 全套方法都得实现）——适配层 > 本体；cfg(windows) 面小、既有测试锚定。登记为"成本>收益"留仓 |

另核实非重试项（防漏）：`xray-core/outbound.rs` `dispatch_via_picker` = mux picker 语义环（Go client.go:30-53 对拍，无退避无睡眠，非 backoff-retry 域）；vless `handshake_with_retry`/`functions.rs` port retry = 测试 helper 非生产编排。

---

## 5. 改动面汇总

| 文件 | 改动 |
|---|---|
| `crates/xray-transport-kcp/Cargo.toml` | +`udf-skeleton`、`udf-std-ext` path 依赖（带 R2 面 14 注释） |
| `crates/xray-transport-kcp/src/output.rs` | `RetryableWriter::write_segment` 手写循环 → udf `retry` + `RetryPolicy`；struct doc +2 行（udf 接线 + 末次不空睡）；imports +2 行 |

其余全部零改动（§1–§4 登记处）。未触碰：xray-frame / dispatcher / commander / reverse / vless vision / `crates/udf-frame/**` / 任何测试断言。

---

## 6. 验收门（P0 全实跑）

- `cargo check -p xray-transport-kcp -j 8`：**绿**（1m19s，含 udf 依赖首编；`Finished dev profile`）。
- `cargo test -p xray-transport-kcp --all-targets -j 8`：**179 passed / 0 failed + 2 doc-test passed**（`test result: ok. 179 passed; 0 failed`；含 RetryableWriter 既有 3 测原样通过，测试断言零改动）。
- `cargo fmt --all -- --check`：**clean（exit 0）**。
- `cargo clippy --workspace --all-targets -j 8 -- -D warnings`：**0 error**（`Finished dev profile ... in 2m 51s`；仅第三方 `rustls (lib)` 2 条历史 warning——path-patched 依赖不带 `-D`，非 workspace 面，与本 diff 无关，本波未新增任何 warning）。
- `python dist/interop_matrix.py`：**12/12 PASS**（`=== 互操作矩阵: 12/12 PASS ===`；A/B 两象限 200028B 全量 marker）。口径注记：矩阵 Rust 侧用 `dist/xray.exe`（红线 baseline 二进制，本波禁碰未重编），且 6 协议（vmess/vless vision/ws/trojan/ss/ss2022）**不含 kcp、不含 DNS 缓存路径**（DNS 面本轮零改动）——本门验证的是基线互通完好性，非本 diff 的行为面；kcp 行为面由上列 crate 测试承载。

---

## 附录：门尾部原文

```
cargo check -p xray-transport-kcp:
    Checking xray-transport-kcp v0.1.0 (.../crates/xray-transport-kcp)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 1m 19s

cargo test -p xray-transport-kcp --all-targets:
running 179 tests
    ...
    test result: ok. 179 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.14s
running 2 tests
    test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.22s

cargo fmt --all -- --check:   → 退出码 0（零输出）

cargo clippy --workspace --all-targets -j 8 -- -D warnings:
    warning: method `needs_key_share` is never used          ← 第三方 rustls (lib)
    warning: unreachable `pub` item                          ← 第三方 rustls (lib)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 2m 51s   ← 0 error

python dist/interop_matrix.py:
    [PASS] #01..#06 Rust->Go  vmess / vless_vision_tls / trojan_tls / vless_ws / ss / ss2022  (body=200028B)
    [PASS] #07..#12 Go->Rust  同上六协议                                                       (body=200028B)
    === 互操作矩阵: 12/12 PASS ===
```

---

## 7. DNS `cache_controller`（面 1）—— **PM 已裁决：路径 B（维持现状登记），不走 A**（2026-10-27）

PM 按 ADR-1 三判据逐条裁定：
1. **判据①（零 Xray 语义）不成立**：双家族条目级 TTL / serveStale 过期保留读 / 无界+收缩/水位线 / pubsub / singleflight 全是 Go `app/dns/cache_controller.go` 语义（Go 兼容语义算 Xray 语义）。
2. **判据②（归 xray-frame）不成立**：xray-frame 是机制层，`cache_controller` 是带方向的具体组件——按 CLAUDE.md §3.5.3 方向件纪律留主仓最近消费方。
3. **判据③（连派生层都放不合适，逐条举证）成立**：DNS 方向件 + Go 语义逐字对齐（测试钉契约）+ 热路径并发面（`&mut self` 适配必须全局锁=明令禁止）+ serveStale 与惰性回收语义对撞（不是缺 API，是两种语义不能共存）。

**裁定：留 `xray-app-dns`，登记 `udf-promotion-candidate` + 语义缺口**；将来 udf 若做出「并发 + 条目级多 TTL + 过期保留读」缓存件，走 `n539c` 换装，主仓侧 API 面不变。PM 口径：**这是 ADR-1 判据③的正常出口，收尾报告记"显式豁免项"，不混进"未完成"**。PM 已同步完成：方案稿 §4 行 13/14/15 勘误（含 geo weak cache 不存在 / uuid 不需要换 / retry 仅同步面可换）、kcp 改动入库 `12a3ff2b`、udf 异步 retry 缺口登记进 `n539c` 域。

---

## 8. 5 轴自评

- **准确性 5/5** — 每条判定均实读源码背书：udf 三件（cache.rs/retry.rs/id.rs）签名与语义逐行核对；7 个重试站点、8 个 app crate 缓存面全 grep 定位后逐个开庭；`uuid` 两站点实读确认为 crate 直用非自造。
- **完整性 4/5** — 扣分：面 1 按任务书条款停在"报 PM"未产出代码（条款要求的行为，裁决已落：路径 B 显式豁免，收敛闭环由 PM 收尾报告承接）；面 3 的"geo weak cache"以树内 0 命中为准判"不存在"（PM 已采信并勘误方案稿）。
- **清晰度 5/5** — 总账表 → 逐面论证 → 裁决请求三段式；每个"不换"都给形态 + 理由 + 分类（不契合/不适用/不存在/已完成）。
- **可执行性 5/5** — 门命令全量可复制复跑；§7 给出两条路径的具体下一步；改动面精确到文件与行。
- **简洁性 4/5** — 扣分：§1/§4.2 部分条目论证略冗（为 PM 复核保留证据链，可接受）。

---

**改动统计**：`git diff --stat` = 2 文件，+16/-11（`Cargo.toml` +6（含 4 行注释）/`output.rs` +10/-11）。测试断言零改动，红线零触碰（`git status` 确认 udf-frame/ 与他人面零污染），无 commit/push。

**待补提交（漏项登记，CR1bRuntime 2026-10-27 报告 + 本代理核实）**：`Cargo.lock` 尚有 2 行未提交——`xray-transport-kcp` 包块内 `+"udf-skeleton"` / `+"udf-std-ext"`（本波 Cargo.toml 依赖边的锁条目，由构建时 cargo 自动补写）。PM 的 `12a3ff2b` 只带 `Cargo.toml` + `output.rs`。CI 无 `cargo build --locked` 硬门（`.github/workflows` 仅 `cargo install --locked`，无关），故不挂 CI；但锁文件与已提交的 Cargo.toml 不同步 = 复现性缺口 + 他人 `--locked` 会失败 + 易被无关 `git add -A` 扫入。**需 PM 补一笔提交（本代理受"禁 commit"约束不执行）**。

## 9. 图谱与沉淀

- **知识图谱**：本次实跑 `index_repository --mode fast` 一次，`status: aborted_previous_preserved`（在飞共享树写冲突：W7/CR1aC 正改 `vision_conn.rs`/`default.rs`，索引与写互斥；前序索引完好仍在服务）。**本波改动（2 文件）未入图**——多代理在飞窗口全量重索引必然竞态，建议 PM 在 W7/CR1aC 全部落地、树静默后统一重索引收口。
- **沉淀**：本波经验均为项目绑定事实（udf retry 次数语义换算 `0..=n → n+1`、base=max 截平形模拟固定间隔、任务书"三处缓存"与树漂移）——已全部落本报告 §4.1/§3，无跨项目通用新坑，不新增全局 rules。
