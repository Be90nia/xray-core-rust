VERDICT: PASS_WITH_CONCERNS — 3 票全落地且验收命令全绿（rjt2o 机制+E1、86i4h 阶段1、sex3y 日志/metrics 面）；concerns: ①sex3y 的生产注入点 `crates/xray-core/src/functions.rs`（obs collector）与 DNS 侧 `record_dns` 调用点属 G7 文件面，已交接口给对方（本组不动）；②rjt2o 残留「双向同时停读」形态无判定可搬运，属票面已登记的 follow-up。

# G5IOFrame — rjt2o / 86i4h / sex3y

- 仓库 `D:/Project/Xray-core-rust`，分支 `feature/fix-inbound-parity`，HEAD `a8534efd`（工作树内有其他组在飞改动，本组只落自己文件面）
- 构建环境：`BORING_BSSL_PATH=target/boringssl-asm/prebuilt`（跳过 btls cmake）+ `PROTOC` + `LIBCLANG_PATH`
- 本组独立构建目录：`target-G5IOFrame`（回执已注明，结束删除）

---

## rjt2o（P1）数据面写臂无 deadline：中止闸

### 改动（`crates/xray-transport/src/bridge.rs`；`git diff -w` 实质 +344/-34，其余是 fmt 缩进）

票面给的修法已在验资报告里探针实测过，按其 §3.2 形态原样落地，**不新造判定**：

1. 新增 `wait_abort(&mut watch::Receiver<bool>)`（`:318`）：闸已关立即 Ready，否则挂起；发送端全亡 = fail-closed。**零分配、零拷贝，每批一次 watch poll**。
2. `bridge_link_with_stream_full`（八腿解耦泵）：
   - `:418` 新增 `watch::channel(false)` 中止闸（与既有 up_done/down_done 同族，四腿各持 clone）。
   - 既有读侧 deadline 分支（connIdle `:441`、uplink_only 半窗 `:448`、下行 §同构 `:531/:536`）→ 命中即 `abort_tx.send(true)` 再 break（**判定源不变 = 单一超时账本**，不违反 §3.5.6 禁双份账）。
   - 4 个可阻塞 await 点（`up_tx.send` / `write_all_mb` / `down_tx.send` / `writer.write_multi_buffer`）改 `select!{wait_abort, op}`。
   - `up_writer` 收尾 `s_write.shutdown()` 补 3s 界（与既有 `shutdown_flush` 对称）。
   - `join!` 结构、mpsc 容量、vectored/readv/frozen 读腿、splice 分支**一个不动**；写错误仍只关本向（50074b2 教训保持）。
3. `bridge_link_with_link`（代理链）同款：读侧 deadline 关闸 + 两个 `write_multi_buffer` 可中断；`shutdown_flush` 既有 3s 界不动。
4. `bridge_link_with_stream_downlink_splice`（Linux/Android 专面）同上行同款（下行内核 splice 不接闸，Go 语义 24h+EOF）。

### 证据

**E1 真实二进制（多轮，含泄漏判据）** — `reports/audit-2026-10-31-perf-mem-wiring/fix/scripts/rjt2o_abort_e2e.py`：

```
[baseline] pid=35512 handles=167 threads=24
[R1 真实转发] 65536B 往返一致=True got=65536B
[round 1] filled=67.6MB during_est=6/6 after_idle_est=0 client_eof=6/6 residual={} handles=182 threads=25
[round 2] filled=67.6MB during_est=6/6 after_idle_est=0 client_eof=6/6 residual={} handles=182 threads=25
[round 3] filled=67.6MB during_est=6/6 after_idle_est=0 client_eof=6/6 residual={} handles=184 threads=25
[R3 states] hole={} echo={} socks={'LISTEN': 1}
VERDICT: R2/R2b PASS | round1..3 PASS | R3 PASS（逐轮句柄持平 [182,182,184]，Δ=2） | R3b PASS（入站侧只剩 LISTEN）
```

读法（与审计 Verify-C1 同仪器：psutil 句柄数 + 按 PID 的连接状态表）：
- R1 = 数据面未被闸破坏（64KB 往返逐字节一致）。
- S1 形态（6 条对「accept 后永不 read」黑洞的写阻塞连接，connIdle=2s）：**during=6 ESTABLISHED**（前置成立）→ connIdle 到点后 **after=0**、6/6 客户端见 EOF/重置。审计基线是「6/6 永久 ESTABLISHED、句柄 Δ+37 不回落」。
- 3 轮重复：每轮 6→0，句柄按轮持平（Δ=2），**无每连接泄漏**；收尾后出站/入站连接表只剩 socks 的 LISTEN。
- 收尾态说明：若对端黑洞侧不关闭，xray 侧出站会停在 `FIN_WAIT1`（己方已发 FIN、对端未收尾）= 正常收尾态；脚本先关对端再量，确保「无残留」判的是真泄漏。

**单测回归门（in-crate，2 条）** + **反向对照（闸禁用 ⇒ 必红）**：

```
# 反面控制：把 wait_abort 改成永不就绪（= 等价修前行为）
cargo test -p xray-transport --lib abort_gate
  bridge_stream_full_abort_gate_releases_stalled_downlink_writer ... FAILED  Elapsed(())
  bridge_stream_full_abort_gate_releases_stalled_uplink_writer   ... FAILED  Elapsed(())
  test result: FAILED. 0 passed; 2 failed

# 还原实现后
cargo test -p xray-transport --lib abort_gate
  both ... ok    test result: ok. 2 passed; 0 failed; finished in 3.12s
```

即：两条测试是**真**回归门（不是恒绿断言），修前形态（`join!` 等被堵腿）实测永不返回。

### 非目标/残留
- 双向同时停读（两条读腿都卡在 send、无人处于 deadline 之下）仍无判定可搬运 —— 票面已登记的 follow-up，本次不扩。
- vision gate / splice 热路径语义未动；`git log -S"wait_abort"/"abort_tx"` 无历史回档（此形态首次落地）。

---

## 86i4h（P2）`spawn_reaping` API + ArmScope/ConnScope 内部接线（阶段1）

### 改动

- `crates/xray-frame/src/compat.rs`
  - 新增 `pub fn reap_into(&FxScope, &LogFacade, label) -> usize`：udf `try_reap` 的**唯一上报装配点**（Panicked → error 带域标识；Cancelled = 预期消亡不计；不动在途任务/不改 in_flight）。
  - 新增 `pub fn spawn_reaping<T>(scope, log, label, fut)`（`#[inline(always)]`，栈中性）：**先收割已完成条目再入集**；拒发 `ScopeClosed` 落 warn（fail-visible）。→ 条目数跟随在途数而非累计 spawn 数。
  - `ManagedScope::spawn` 改为委托 `spawn_reaping`（删掉重复的私有 reap），并把它暴露为 `ManagedScope::reap()`（空闲期显式触发口）。
- `crates/xray-frame/src/scope.rs`
  - `ArmScope::spawn` / `ConnScope::spawn`（含 `child_of` 的父关闭监视任务）全部改走 `spawn_reaping`，域门面 `xray_frame::scope`（进程级单例，克隆零堆分配）。
  - 派生子句柄语义不变（`ConnScope::spawn` 仍返回 `Spawned<Option<T>>`，取消≠完成）。

### 证据

```
cargo test -p xray-frame --lib
  test result: ok. 99 passed; 0 failed; 0 ignored
# 其中新增：
  compat::tests::spawn_reaping_classifies_panic_cancelled_ok_and_rejects ... ok
  compat::tests::scope_spawn_reaps_and_reports_panic ... ok
```

新增单测覆盖的**分类**（票面要求含 panic/超时分类）：
- `Panicked` → error + 载荷 + 域标识（`background task panicked: reap-boom`）；
- `Cancelled`（abort = 超时/取消形态）→ **不上报**（断言全局只有 1 条 panic 上报）；
- `Ok` → 静默出集（`try_reap` 不回 Ok 条目：一次收割 `reaped==2`，二次 `reaped==0` 幂等）；
- 闸关拒发 → warn 可见；
- 接线判别器：`ArmScope::fx().try_reap()` 收割后 == 0（未接线时 panic 条目仍滞留 → 1），且 `ConnScope` 的 panic 同样在**下一次 spawn** 被上报。

```
RUSTDOCFLAGS="-D warnings" cargo doc -p xray-transport -p xray-frame -p xray-app-log -p xray-app-metrics --no-deps
  Finished ... （无 broken intra-doc link；`-D warnings` 下零告警）
```

### 非目标（票面明示）
- **不做**阶段2 的 25 处组件自持 `FxScope` 替换（B 类），也不动 dispatcher 的 pipe；
- 无双份账本：收割口只有 udf `JoinSet` 一处，`spawn_reaping` 只是「收割 + 入集」的装配点。

---

## sex3y（P2）dnsLog 生产者 + 写失败 fail-visible + obs collector 注入

### 改动

**`crates/xray-app-log`**
1. **DNS 日志生产者**（`instance.rs`）：进程级出口 `ACTIVE_DNS_INSTANCE` + `install_dns_producer/uninstall_dns_producer`（`LogFeature::start/close` 装/卸）+ `pub fn record_dns(DnsLog)`（Go `log.Record(&DNSLog{})` 等价物）。未装出口时**首条 warn 后静默**（「写了没人看见」留痕）。`lib.rs` 导出 `record_dns`。
2. **写失败 fail-visible**：
   - 装配期：`FileHandlerCreator::create` 同参数探测 open（create+append），失败 → `HandlerCreate("cannot open log file ...")`；`LogInstance::start` 对 **File** 类日志把该错误**硬错上抛**（Go `CreateFileLogWriter` 语义）。非 File 类（creator 未注册等装配面问题）保持原有 warn 容忍。
   - 运行期：`FileHandler` 首条写失败（open/writeln）落一次 warn（带 path；之后只计数不刷屏），`dropped` 计数照旧可观测。

**`crates/xray-app-metrics`**
3. **obs collector 注入口**：新增 `MetricsFeature::set_obs_collector(&self, Arc<dyn ObservationCollector>)`（`with_obs_collector` 吃所有权，装配面只有 `Arc<MetricsFeature>` 句柄，与既有 `set_stats_collector` 同款 bd 3xmjx 形态）。

### 证据

```
cargo test -p xray-app-log          # 87 lib + 各集成二进制
  tests/dns_log_and_write_failure.rs:
    record_dns_produces_dns_log_line ... ok        # 注入前 observatory 类缺口：E1 零 DNS 行
    unwritable_access_log_path_fails_feature_start ... ok
    runtime_write_failure_is_warned_once ... ok
  test result: ok. 3 passed; 0 failed; 0 ignored

cargo test -p xray-app-metrics
  feature_start::set_obs_collector_changes_debug_vars_observatory ... ok
  test result: ok. 6 passed (+ 3 prometheus_e2e) 0 failed
```

注入前后观测差异（同一 test 内两段，真实 HTTP 请求 `/debug/vars`）：
- 未注入：`"observatory":null`（= 审计实证的生产形态）；
- 注入后：`"observatory":{"out_obs":{"alive":"true"}}`。

DNS 生产者差异：`record_dns(...)` 后 access 日志文件出现 `d.io` / `9.9.9.9` 行；`LogFeature::close` 后再 `record_dns` 不再写入（不写已关实例）。
写失败差异（运行期）：目录被删后的**首条**写入 → 恰好 1 条 `log file write failed` 告警 + `dropped_total >= 1`；装配期不可写路径 → `LogFeature::start()` 直接 Err（错误文案含 `cannot open log file`），`is_active()==false`。

### 交接（不在本组文件面，已消息 G7DnsObs）
- DNS 查询完成处调用 `xray_app_log::record_dns(DnsLog{...})`（`crates/xray-app-dns` = G7 面）；
- obs collector 的生产注入点 `crates/xray-core/src/functions.rs:364-368`（stats 注入块旁，G7 面）：需要 observatory `StatusStore` → `ObservationEntry{outbound_tag, extra}` 适配 + 一行 `set_obs_collector`。已告知可用 `set_obs_collector`（本次交付）。

---

## 【验证命令 + 关键输出】

```bash
# 环境（每条 cargo 前）
export BORING_BSSL_PATH=D:/Project/Xray-core-rust/target/boringssl-asm/prebuilt
export BORING_BSSL_ASSUME_PATCHED=1
export PROTOC=D:/Project/tools/bin/protoc.exe
export LIBCLANG_PATH="D:/Program Files/llvm/bin"
export CARGO_TARGET_DIR=D:/Project/Xray-core-rust/target-G5IOFrame
```

| 门 | 命令 | 结果 |
|---|---|---|
| 单测（票面验收 1） | `cargo test -p xray-core -p xray-frame -p xray-app-log -p xray-app-metrics --lib` | **xray-core 510 passed/2 ignored、xray-frame 99、xray-app-log 87、xray-app-metrics 77，0 failed** |
| bridge 全量 | `cargo test -p xray-transport --lib bridge` | **30 passed，0 failed** |
| app-log 集成 | `cargo test -p xray-app-log` | 全部二进制绿（新增 3 条 sex3y） |
| metrics 集成 | `cargo test -p xray-app-metrics` | 9 passed（新增 obs 注入差异） |
| clippy | `cargo clippy -p xray-transport -p xray-frame -p xray-app-log -p xray-app-metrics --all-targets -- -D warnings` | **零告警**（仅 vendor rustls 既有 2 条） |
| fmt | `cargo fmt -p xray-transport -p xray-frame -p xray-app-log -p xray-app-metrics -- --check` | **FMT OK** |
| doc（验收 3） | `RUSTDOCFLAGS="-D warnings" cargo doc -p ... --no-deps` | **绿，无断链** |
| e2e（验收 2） | `python reports/audit-2026-10-31-perf-mem-wiring/fix/scripts/rjt2o_abort_e2e.py --xray target-G5IOFrame/release/xray.exe --n 6 --idle 2 --rounds 3` | **R1/R2/R2b/R3/R3b 全 PASS**（见上） |
| 反向对照 | 闸禁用版 `cargo test -p xray-transport --lib abort_gate` | **2 failed（Elapsed）** ⇒ 测试是真回归门 |
| ⑫ 性能门 | `python tools/loopback_alloc_bench.py --tag rjt2o-abort --xray target-G5IOFrame/release/xray.exe --runs 3 --alloc-stats` | 见下「性能门」段 |

### 性能门（坑约束 ⑫）

本修法唯一热路径成本 = 每批多一次 `watch` poll，故做了**同会话 A/B**（同机、同拓扑、交替跑；
控制臂 = 把 `wait_abort` 改成永不就绪的等价修前唤醒面，release 重编）：

```
# 带闸（本改动）
tag=rjt2o-abort  : 122.6 / 136.2 / 137.2 MB/s        best=137.2   alloc/MB[cli]=2.175  alloc/MB[srv]=1.167
tag=rjt2o-gated2 : 125.7 / 138.0 / 137.9 MB/s        best=138.0
# 控制臂（闸永不就绪 = 修前唤醒面）
tag=rjt2o-nogate : 125.0 / 137.3 / 138.8 MB/s        best=138.8
tag=rjt2o-nogate2: 126.8 / 136.4 / 139.6 MB/s        best=139.6
floor check: 两臂均 > floor 120.0 MB/s
```

判读：
- 带闸 vs 控制臂 best 差 **≈ -1.1%**（137.6 vs 139.2，低于 `docs/benchmarks/baseline.md` 自记的
  16% loopback 窗口摆动）⇒ **⑫ 性能门通过**（闸本身不构成回归）。
- `alloc/MB[cli]=2.175` 与基线 2.22 持平（略低）；`alloc/MB[srv]=1.167` 与基线 2.15 不同代（当前树已有
  oarfu 等下行零拷贝改动），本次未引入新分配点（`watch` 通道一次分配、`wait_abort` 零分配）。
- **诚实标注**：两臂 best 都落在 137–140 MB/s，低于 2026-10-11 基线记的 154–167 MB/s。该差距**不是**本
  改动带来的（控制臂同样在 137–140 区间）；它落在当前树（含其他组在飞改动）与该基线时点之间，未做
  bisect（超出本组文件面），仅记录事实。

### 直连锚（统一验收「直连 ≥27 MB/s」）

```
python（socks 入站 21281 + freedom 出站 → 本地 http 200MB，curl --socks5-hostname ×3）
[direct #1] speed=695.4 MB/s size=210 MB
[direct #2] speed=1095.0 MB/s size=210 MB
[direct #3] speed=1226.4 MB/s size=210 MB
```

直连路径 695–1226 MB/s ≫ 27 MB/s 锚（本机 loopback，无 TLS）；数据面未被中止闸碰到。
CDN/argo 锚（50–60 MB/s）需外部 CDN 目标，本轮未测（可达 VPS 批次已下线，见 MEMORY）——如实标注。

## 文档同步
- 未涉及（纯内部机制/实现微调；`docs/benchmarks/baseline.md` 基线数值未变，性能门结果见上）。

## 未做（明确不做）
- 86i4h 阶段2 的 25 处 B 类组件替换；dispatcher pipe 未动；
- sex3y 的 DNS 侧调用点与 `functions.rs` 的 obs 注入点（G7 文件面，已交接）；
- 双向同时停读形态（rjt2o follow-up）。
