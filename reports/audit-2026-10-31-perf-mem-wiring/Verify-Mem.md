# Verify-Mem：内存维度审计断言第二轮对抗复核（独立证伪）

- 复核人：VerifyMem（reviewer，只读复核；**未改产品代码、未改 udf**）
- 日期：2026-10-31
- 仓库：`D:/Project/Xray-core-rust`，分支 `feature/fix-inbound-parity`，HEAD `5fe98b90`
- 被复核对象：`reports/audit-2026-10-31-perf-mem-wiring/MemWiring.md`（MW-1~MW-8）
- 取证原则：不抄原报告推理；每条结论给**我自己跑出的命令与输出**或**我读到的源码原文**。
- 已 CLOSED 票不重开：`4y9ns` / `r1693` / `q1r4q` / `9eu4a` / `pv70`。`crates/xray-buf/src/alloc.rs` 只判授权、不实施。

**首行判据**：`VERDICT: CONDITIONAL` —— 最大一条（MW-1）的**机制与线性增长经我独立 E1 证实**（不靠字节数，靠分配笔数：**+2.01~2.02 条存活分配/连接**，与 udf `FxScope` 条目签名逐位吻合），但**站点枚举与一条 E1 归因必须改写**才能进排期：被点名的 `vless` 服务端（原报告自己的 E1 数据点）根本不走 `ctx.spawn`，其 +218/+225 B/conn 是**少量大 buffer 的高水位**（+0.01~0.03 分配/连接），不是托管条目；MW-2 的「+419 B/conn = SessionHistory」高估一个数量级。

---

## 0. 我的 E1 复现（同环境、命令可复跑）

脚本：复制原报告脚本到隔离目录（**不覆盖原报告证据**，改端口/工作目录 + 追加两项测量：

`live_allocs`（`alloc_n - dealloc_n`，即存活分配**笔数**）与**第二轮同量 churn**）：

```bash
python reports/audit-2026-10-31-perf-mem-wiring/scripts/verify/mem_churn_v.py \
    --proto vless --conns 3000 --warmup 500 --idle 10 --threads 8
python reports/audit-2026-10-31-perf-mem-wiring/scripts/verify/mem_churn_v.py \
    --proto vmess --conns 2000 --warmup 500 --idle 5  --threads 6
```

### 0.1 vless（拓扑 = socks 客户端 → vless/tcp → vless 服务端 → freedom → echo）

| 阶段 | srv live_bytes / live_allocs | cli live_bytes / live_allocs |
|---|---|---|
| baseline（warmup 500 后） | 488 864 / 453 | 437 575 / 1 430 |
| churn#1（ok=2439） | 1 020 560 / 529 | 1 402 983 / 6 365 |
| churn#1 增量 | **+531 696 B（+218 B/conn）, +76 allocs（+0.03/conn）** | **+965 408 B（+396 B/conn）, +4 935 allocs（+2.02/conn）** |
| 空闲 10s | 1 020 560 / 529（一位不动） | — |
| churn#2（ok=2703） | +289 024 B（+107 B/conn）, **+36 allocs（+0.01/conn）** | +774 432 B（+287 B/conn）, **+5 423 allocs（+2.01/conn）** |

**两轮 churn 的判别力**（这是原报告缺的一步，也是最关键的一步）：

- **cli 侧**：每轮都稳定 +2.01~2.02 条存活分配/连接 ⇒ **每连接新增固定条目**，= 线性泄漏。
- **srv 侧**：字节涨、**分配笔数几乎不涨**（+0.03 / +0.01 每连接）⇒ 涨的是**少数几个大块**（+76 条分配共 531 KB，均 7 KB），属 buffer 高水位/惰性扩容，把它除以连接数得到「218 B/conn」是**除法假象**——第二轮同样的连接量只再涨 107 B/conn（趋饱和），不是线性条目。
- 「空闲不回落」这一点原报告成立（我这轮 10s 窗逐位相同），但它**只能证明没有回收动作，不能区分「条目滞留」与「高水位 buffer 永不缩」**——必须配分配笔数才有归因力。

### 0.2 vmess（同拓扑换 vmess/tcp）

| 阶段 | srv live_bytes / live_allocs | cli live_bytes / live_allocs |
|---|---|---|
| baseline（warmup 500 后，ok=206） | 446 991 / 883 | 529 696 / 1 333 |
| churn#1（ok=1653，345 失败） | 2 005 119 / 4 292 | 2 055 128 / 8 046 |
| churn#1 增量 | +1 558 128 B（+942.6 B/conn）, **+3 409（+2.06 allocs/conn）** | +1 525 432 B（+922.8 B/conn）, **+6 713（+4.06 allocs/conn）** |
| 空闲 5s | 一位不动 | — |
| churn#2（ok=1531） | +540 920 B（+353.3 B/conn）, **+3 092（+2.02 allocs/conn）** | +1 089 744 B（+711.8 B/conn）, **+6 203（+4.05 allocs/conn）** |

- 与原报告（+620 srv / +905 cli）**同量级复现**，「25s 空闲零回落」也复现。
- **关键是笔数**：两轮 churn 的 `allocs/conn` 稳定在 **2.06→2.02（srv）/ 4.06→4.05（cli）**，而字节/连接从 942→353、923→712 大幅漂移 ⇒ 字节里混着 buffer 高水位噪声，**笔数才是条目指纹**。
- 解码：srv（vmess 入站 `ctx.spawn` 每连接）= **1 条 FxScope 条目**（2 条分配/条目）；cli = **2 条条目** = socks 入站每连接 1 条（`inbound.rs:557`）+ vmess **出站**每连接 1 条（`xray-proxy-vmess/src/dispatcher.rs:423`，vless 出站无此 spawn ⇒ 这解释了 vless cli 只有 2.02）。


### 0.3 `FxScope` 条目滞留最小复现（机制级 E1，零产品代码改动）

`reports/audit-2026-10-31-perf-mem-wiring/scripts/verify/fxretain/`（独立 cargo 项目，path 依赖 udf `skeleton-infra`，用 udf 自带 `memgov::CountingAllocator` 量存活字节）：

```bash
cd reports/audit-2026-10-31-perf-mem-wiring/scripts/verify/fxretain
CARGO_TARGET_DIR=D:/Project/Xray-core-rust/target-VerifyMem cargo run --release --offline
```

输出（multi_thread 运行时装 4 线程，任务全部跑完但**不 join**）：

```
case,n,retained_B_per_entry,retained_allocs_per_entry,after_reap_B_per_entry,in_flight_after_done,reaped
tiny,2000,440,2.00,0,0,0
tiny,20000,440,2.00,0,0,0
vec4k,20000,440,2.00,0,0,0
inline4k,2000,440,2.00,0,0,0
```

三条读数：

1. 每个「已完成、未收割」的托管任务滞留 **440 B / 2 条分配**，`in_flight()==0`（任务确实完成）。
2. **与 future 大小无关**（tiny / 堆 4 KiB / 内联 4 KiB 全 440 B）⇒ 滞留成本 = 任务控制块，不是载荷缓冲。
3. `try_reap()` 一次调用后 **滞留归零**（after_reap=0）⇒ 滞留字节就是 JoinSet 条目本身，回收口有效。

**与真实二进制的锚点比对**：cli 实测 **+2.01~2.02 allocs/conn** = 复现的 **2.00 allocs/条目**；字节 396 B/conn（真实）vs 440 B/条目（复现）同一数量级（真实进程里 future 尺寸/尺寸类不同，笔数才是硬指纹）。→ **MW-1 机制归因成立，且比原报告更硬：原报告只有字节数，我给出笔数。**

---

## 1. MW-1 裁决：**CONFIRMED（机制+线性）/ 站点枚举与一条归因 ADJUSTED**

### 1.1 udf 侧责任判定：**不是 udf 缺陷，是主仓接线缺口**（原文证据）

- `crates/udf-frame/skeleton-infra/src/fx.rs:249-253`（`FxScope` 文档）：
  > 「…任务进 JoinSet 生命周期集…（生命周期集，短临界区零 await；条目载荷 = panic 归一面——**完成条目滞留至 [`Self::try_reap`] 或停机排空显式收割**，见 issue#13）」
- `fx.rs:484` 起的 `try_reap` 文档：
  > 「**增量收割口**（issue#13 缺口一）：锁内同步扫集合中**已完成**条目——正常完成丢弃、panic 载荷归集返回… **幂等可反复调**。」
- `fx.rs:1009` 起的 udf 自测 `try_reap_drains_retained_entries_and_is_idempotent`，注释写明：
  > 「101 条目全部已终局，**滞留集合** → try_reap 清空，二次 reap 空且零分配」

⇒ udf 的契约是**显式收割**（语义已文档化、被自测钉死、回收口已交付），滞留是设计内的「需调用方收割」，**不是上游 bug**。归属 = **主仓接线缺口**（可修，不走提炼回路）。

**旁证（本仓早就知道这条语义）**：`crates/xray-core/src/arm_builders/inbound.rs:797-800 / 852-855 / 896-899 / 944-947` 四处裸 `tokio::spawn` 的 allow 理由原文：

> 「显式脱管：上游 drain 缺口——**FxScope 的 JoinSet 无收割接口，每连接登记一条会无界累积，登记收益为负**；句柄随连接任务自然结束（bd hj3jf 裁定）」

即：**这四处（vless fallback / trojan fallback / vmess transport / ss transport 的每连接任务）已经因这条语义被显式豁免**，`crates/xray-proxy-vless/src/inbound/server.rs:148` 的 vless TCP 每连接任务同样是裸 `tokio::spawn`。原报告把这些路径一并算进「全部 `ctx.spawn`」，是枚举错误。

**票面状态（不得新开重复票）**：`Xray-core-rust-86i4h`（P2, **BLOCKED**，label 含 `blocked-udf debt framework`）正是这条：「FxScope 缺增量收割口 + 停机 panic 上报 —— 已提 udf#13，等上游」，解锁条件写的是「udf #13 合入 main → 本仓换依赖…」，并自列「需要量化：滞留条目单条大小 × 累计任务量级；若百万连接量级几十 MB 应升 P1」。**udf 已交付 `try_reap`，本票的阻塞前提已消失——应据此重开/续做，而不是新建 MW-1 票。** 我本次实测即该票「需要量化」的答案：**440 B/条目（2 条分配）**。

### 1.2 需要补 `try_reap` 的**完整枚举**（file:line，按修法归类）

**A 类 · 经 `ArmScope`/`PluginContext::spawn`（根修一处全覆盖）**

根：`crates/xray-frame/src/scope.rs:72-74`（`ArmScope::spawn` → `spawn_tracked`，**零 reap**）；`crates/xray-frame/src/context.rs:192-197`（`PluginContext::spawn` 透传 `self.fx.spawn`）。

| 站点 file:line | 每事件语义 |
|---|---|
| `crates/xray-core/src/inbound.rs:557` | mixed/socks 每连接 |
| `crates/xray-core/src/inbound.rs:645` | socks UDP associate 每会话 |
| `crates/xray-core/src/inbound.rs:632 / 698 / 800` | mux carrier 每 carrier 连接 |
| `crates/xray-core/src/inbound.rs:744` | http inbound 每连接 |
| `crates/xray-core/src/inbound.rs:1576` | dokodemo(TCP) 每连接 |
| `crates/xray-core/src/inbound.rs:1737` | dokodemo(UDP) 每 peer 会话 |
| `crates/xray-core/src/inbound.rs:2072 / 2117` | ss legacy UDP 中继 / ss 连接流水线 |
| `crates/xray-core/src/inbound.rs:2300 / 2483 / 2548` | ss / ss2022 UDP client relay |
| `crates/xray-core/src/inbound.rs:2719` | dns inbound 每 TCP 连接（`conn_ctx` 是 `Arc<PluginContext>` 克隆 ⇒ **同一 arm scope**，不是 ConnScope，计入） |
| `crates/xray-proxy-vmess/src/inbound/server.rs:185` | vmess TCP 每连接 **（我的 E1 直接量化：+2.06 allocs/conn）** |
| `crates/xray-proxy-trojan/src/server.rs:511` | trojan 每连接 |
| `crates/xray-proxy-blackhole/src/inbound.rs:100` | blackhole 每连接 |
| `crates/xray-proxy-freedom/src/udp.rs:135` | 每 UDP 关联响应泵 |
| `crates/xray-proxy-http/src/client.rs:341` | 每 h2 连接 driver |
| `crates/xray-proxy-wireguard/src/dispatcher.rs:669` | 每 relay |
| `crates/xray-proxy-tuic/src/dispatcher.rs:232` | 每 stream pump |
| `crates/xray-proxy-vmess/src/dispatcher.rs:423` | **vmess outbound 每 TCP 连接**双向 chunk pump（我的 E1 直接量化：cli 比 vless cli 多 +2.04 allocs/conn = 多 1 条条目） |
| `crates/xray-proxy-vmess/src/dispatcher.rs:544` | vmess outbound 每 UDP 连接下行解密任务 |

**B 类 · 组件自持 `FxScope`（直接 `fx.spawn_tracked(...)`，根修**不**覆盖 —— 原报告几乎全漏）**

原报告只数了「`ctx.spawn` + dns/udp-relay/tuic/wg 少量站点」。我按 `spawn_tracked(` 全仓枚举（排除 `crates/udf-frame`）后，**每事件 spawn 的组件自持 scope 共 12 个 crate / 25 处**：

| crate · scope 持有 | 每事件 spawn 站点 file:line |
|---|---|
| `xray-proxy-socks`（server 自持 fx） | `src/server.rs:143`（每连接） |
| `xray-proxy-http`（server 自持 fx） | `src/server.rs:345`（每连接） |
| `xray-proxy-trojan`（server 自持 fx） | `src/server.rs:177`（每连接） |
| `xray-proxy-anytls`（server 自持 fx） | `src/server.rs:159`（每连接）、`:296`（每 session）、`:326`、`:381`；`src/inbound.rs:135` |
| `xray-proxy-freedom`（inbound 自持 fx） | `src/inbound.rs:108`（每连接） |
| `xray-proxy-hysteria`（inbound 自持 fx） | `src/inbound.rs:300`（每 TCP stream）、`:320`（每 UDP session） |
| `xray-proxy-wireguard` | `src/inbound.rs:351`（每 relay）、`:374`（每 dispatch）、`:497`（每 UDP session）；`src/driver.rs:515`、`:558`、`:573` |
| `xray-proxy-tuic` | `src/inbound.rs:249`、`:392`、`:407`；`src/server.rs:159`、`:270`、`:524` |
| `xray-app-proxyman`（**原报告把它整段判「正确」，只看了会话表 `cleanup_inactive`**） | `src/inbound/worker.rs:355`、`:370`（每 TCP 连接）、`:658`（每 UDP 会话）、`:680`、`:775`、`:800`；`src/outbound/uot.rs:236`、`:240`（每连接） |
| `xray-app-reverse` | `src/worker.rs:191`、`:407`、`:558`、`:588`；`src/outbound.rs:169` |
| `xray-mux` | `src/client.rs:326`（每 worker）、`src/session.rs:733`（**每 XUDP 条目 interrupt**） |
| `xray-app-dns` | `src/nameserver/doh.rs:288`（**每次 DoH 查询**，最陡）、`src/nameserver/cached.rs:315`（每 serveStale 刷新） |
| `xray-transport` | `src/udp/relay.rs:217`（每 UDP 会话 idle timer）、`src/udp/hub.rs:160`（每 hub，一次性）、`src/tcp/hub.rs:71/82/263/271`（每监听，一次性） |

**C 类 · `ConnScope`**：`crates/xray-frame/src/scope.rs:172-174`（`ConnScope::spawn` 零 reap）。条目随 scope drop 释放 ⇒ 短连接**不泄漏**；但 mux carrier / keep-alive 长连接内每请求一任务 ⇒ 该连接内无界。

**D 类 · 同类已知-正确范本（说明「接 reap」是仓内既有惯例，不是新机制）**

- `crates/xray-app-metrics/src/metrics.rs:458-461 / 496-499`：注释原文「每连接 task 由本 task 内的 JoinSet 持有：完成即收割（join_next 分支），**不再 push 到共享 Vec——否则句柄簿记随抓取次数线性增长（票 fu4y）**」——仓内已有两处主动收割范本（另一处 = `crates/xray-frame/src/compat.rs:235-249`）。

**e 类 · 已登记豁免（不该算进泄漏面；修好后可评估回收豁免）**

`crates/xray-proxy-vless/src/inbound/server.rs:148`（vless TCP 每连接）、`:675`（uplink 泵）；`crates/xray-core/src/arm_builders/inbound.rs:800 / 855 / 899 / 947`（vless/trojan fallback、vmess transport、ss transport 每连接）——四处 allow 理由原文见 §1.1。

**不改的**：一次性 spawn（每监听/每 arm/每实例：`tcp/hub.rs`、`udp/hub.rs`、`commander.rs:563/600/660`、`dns/cache_controller.rs:332`、`observatory/*`、`mux/client.rs:236`、`wg/inbound.rs:200/289` 等）——条目数 = 常量，无需处理。


### 1.3 最小修法形态（两条路，按覆盖面选）

**方案 A（主仓接线，先做）** —— 加一个框架级 helper，A/B/C 三类统一走它：

`crates/xray-frame/src/scope.rs`（照抄同仓 `crates/xray-frame/src/compat.rs:243-253` 的成熟形态）：

```rust
/// 托管 spawn 的唯一推荐入口：reap-before-spawn + panic 落日志。
pub fn spawn_reaping<T>(fx: &FxScope, fut: impl Future<Output = T> + Send + 'static)
    -> Result<Spawned<T>, ScopeClosed> {
    for o in fx.try_reap() {
        if let TaskError::Panicked(msg) = o { tracing::error!(%msg, "managed task panicked"); }
    }
    fx.spawn_tracked(fut)
}
```

- A 类：`ArmScope::spawn`（`scope.rs:72-74`）内部改调 `spawn_reaping(&self.fx, fut)`（1 行）——**一处覆盖 A 类全部 19 处站点**（含 vmess 出站 pump）。
- C 类：`ConnScope::spawn`（`scope.rs:172-174`）同 1 行。
- B 类：12 个 crate / 25 处把 `fx.spawn_tracked(x)` → `xray_frame::scope::spawn_reaping(&fx, x)`（纯机械 1 行/处；`xray-app-dns`/`xray-transport` 若不想依赖 `xray-frame`，则就地 1 行 `let _ = fx.try_reap();`）。
- 代价：每 spawn 多一次 JoinSet 互斥 + 一次 `try_join_next`（空集即返回）；这些都是 per-conn / per-session 级（非逐包），实测 8 conn/s 量级下不可测。
- **禁做**：给 udf 加「自动收割且静默丢弃 panic」——会破坏 `try_reap` 的显式收割契约（`fx.rs:249/484` 文档 + `fx.rs:1009` 自测）。见方案 B 的正确形态。

**方案 B（提炼回路 / 治本，随后做）** —— 上游 `FxScope` 自身「按计数回收已完成 Ok 条目、panic 载荷仍留存到 `try_reap`/停机报告」：

- 严格说这是 udf 的语义缺口：**回收口有了但无自动回收，任何消费者忘调就无界**（本仓实证：25+ 处忘调，且已有 2 处自行发明（`metrics.rs` 票 fu4y、`compat.rs`）——典型的「机制该上浮」信号）。
- 走 §3.5.3 提炼回路：独立 PR + 三平台 CI 绿 + 主仓换依赖 + 32/32 复测；主仓 API 面不变。
- 收益：方案 A 的 25 处站点全部可回退到裸 `spawn_tracked`，长期不再靠人记得。

**不建议**：`ArmScope` 内 `AtomicUsize` 每 N 次 spawn 收割——`N` 是新的魔法数，且不覆盖 B 类。


### 1.4 验证门（进排期用）

1. `cargo test -p xray-frame -p xray-core -p xray-proxy-tuic -p xray-proxy-wireguard -p xray-app-dns`（含 `scope.rs` 既有 arm/conn scope 契约测试 + 新增「spawn 后条目出集」断言）。
2. **我这条复核脚本**（回归判据，可复跑）：cli 侧 `live_allocs` 每连接增量应从 **+2.01 降到 ≈0**；srv 侧不变（它不是本条修法能治的）。
3. `cargo test --workspace --all-targets` + `cargo clippy --workspace --all-targets -- -D warnings` + `cargo fmt --all -- --check`。
4. `python tools/run_full32.py`（32/32；本改动不触 wire ⇒ 不要求 interop 双向抓包，但 32/32 必过）。
5. `python tools/loopback_alloc_bench.py --tag fxreap --runs 3`（每 spawn 多一次锁的代价必须 < 5%，否则改「每 N 次收割」）。
6. 停机面：`shutdown_timeout` 报告 panic 清单不得因收割而变空（既有 `drain_report` 路径重测）。

### 1.5 原报告必须改写的地方（MW-1 内）

- 「生产主路 socks/mixed/**vmess/vless/ss/tuic/wg** 入站全部 `ctx.spawn`」→ **错**：vless TCP / ss transport / vmess transport / trojan fallback 是登记豁免的裸 spawn。真泄漏面 = §1.2 的 A/B/C 类清单。
- 「vless 服务端 +201 B/conn = arm scope 条目」→ **错**（我实测 +0.01~0.03 allocs/conn）。该路径的字节增长是**少数大 buffer 的高水位**（+76 条分配/531 KB，第二轮只再 +36 条/289 KB，趋饱和）——**这是原报告没有的一条独立发现**，需另立票定责（候选面：池化缓冲的高水位不缩；是否受 `xray-buf` 红线 §2a 上界约束需单独核，**本复核不判红线票**）。
- 「增速 500 conn/min ⇒ +139~434 MB/天 ⇒ OOM 级」→ **方向对、分母要换**：只用**笔数线性**的路径重算。以 cli 侧实测 287~396 B/conn：500 conn/min（72 万/天）= **+207~285 MB/天**；30 conn/s（259 万/天）= **+0.74~1.03 GB/天**。仍是 OOM 级，但不要引用 srv 侧的 218/225（那不是条目）。

---

## 2. MW-2 裁决：**CONFIRMED（清理任务从未实现）／E1 归因 ADJUSTED**

### 2.1 三选一确证：**「任务未实现」**（不是「实现存在但未启动」，也不是「清理语义退化」）

`crates/xray-proxy-vmess/src/encoding/server.rs`：

- `:51-56` 文件/结构文档写「改为启动时 spawn 一次性后台任务，周期 30s（对齐 Go）做 retain」——**与代码不符**。
- `:62-63` `const CLEANUP_INTERVAL: Duration = Duration::from_secs(30);` 挂 `#[allow(dead_code)]`，注释自认「清理接线随 dispatcher 稳定批次跟进」。
- `:66-71` `pub fn new() -> Self { Self { inner: Mutex::new(HashMap::new()), ttl: Duration::from_secs(180) } }` —— **函数体内没有任何 `spawn`/`tokio::spawn`/interval**。`with_ttl` 同款。
- `:83-110` `add_if_not_exists`：唯一清理是 `if inner.len() >= RETAIN_THRESHOLD(10_000) { inner.retain(...) }` —— 惰性、阈值触发、且在**插入热路径**做 O(n) 全表扫描。
- `SessionHistory` 是**per-inbound 单例**（`crates/xray-core/src/arm_builders/inbound.rs:886`/`:1068`、`crates/xray-proxy-vmess/src/inbound/server.rs:162`），per-conn 只插 1 条（`:237`）⇒ TTL 180s 在 <1 万条时**完全不生效**，条目驻留到进程退出。

⇒ 结论：**「保证清理的任务从未被写出」**（连 spawn 语句都不存在），文档自述与实现背离。属于「实现缺失 + 文档谎言」双缺陷。

### 2.2 bd 票面：**无票**

`BD_IGNORE_SCHEMA_SKEW=1 bd search vmess` → `No issues found`；`bd search SessionHistory` / `try_reap` / `reap` → 均 0；`bd list --status open` 只剩 3 票（`zg6eg`/`23vrp`/`a5pe6`）。⇒ MW-2 需**新建票**；与 `86i4h` 不同票（那是 FxScope 收割口，这是 vmess 会话表 TTL）。

### 2.3 E1 归因校准（原报告「vmess−vless = +419 B/conn = SessionHistory」不成立）

- **笔数证据（决定性）**：vmess srv 每连接 **+2.06 / +2.02 allocs/conn**（两轮 churn）——这是 §0.3 复现的 **FxScope 条目签名（2 条分配/条目）**，而 `SessionHistory` 的 `HashMap` 增长**不产生每连接分配**（只在扩容时批量申请数组）。⇒ vmess−vless 的差额**主要是 vmess 独有的每连接 `ctx.spawn`（§1.2 A 类，vmess TCP 入站 `xray-proxy-vmess/src/inbound/server.rs:185` 用 `ctx.spawn`，而 vless TCP 入站 `xray-proxy-vless/src/inbound/server.rs:148` 是登记豁免的裸 spawn）**。
- 量级估算（E2）：`SessionId` = 3×`[u8;16]` = 48 B，value = `Instant`(16 B) ⇒ `HashMap` 每条 ≈ 64 B + hashbrown 摊平 ≈ **70~110 B/conn**，不是 419 B。
- 同样按笔数校准：cli vmess **+4.06 allocs/conn** = 2 条条目（socks 入站 1 条 + vmess **出站** pump 1 条，`xray-proxy-vmess/src/dispatcher.rs:423`）；vless cli 只有 2.02（vless 出站无此 spawn）。
- ⇒ **严重度校准：MW-2 单条 = Medium（不是 High）**；但它同时是「文档承诺的清理不存在」+「≥1 万条后每连接 O(10k) 扫描」，须与 MW-1 分票。
- 修法（最小）：装配点（`xray-core/src/arm_builders/inbound.rs:886/1068`、`xray-proxy-vmess/src/inbound/server.rs:162`）用 `ctx.spawn` 起一个 30s `retain` 任务（`SessionHistory` 无需改契约：`Arc<SessionHistory>::clone` 进任务即可），同时**删掉插入路径上的阈值全表扫描**；并把 `:51-56` 的文档改成事实。`TtlCache` 不可直接用（`std_ext::cache` 是单线程 `&mut self`，此处是并发共享表）——原报告这句是对的。
- 门：`cargo test -p xray-proxy-vmess -p xray-core`（新增「30s 后过期条目被清」断言）+ 我的 churn 脚本（vmess srv `live_allocs` **≈2.0 → 由 MW-1 修复归零**；`SessionHistory` 侧看字节增量下降 ~70~110 B/conn）+ 32/32。


---

## 3. MW-3~MW-7 裁决（E2，三要素：生产可达性 / 增长对象 / 上限）

| 编号 | 生产可达性（我核的源码证据） | 增长对象 | 上限 | 裁决 |
|---|---|---|---|---|
| **MW-3** dokodemo TPROXY fake_cache | `crates/xray-core/src/inbound.rs:1885-1901`（`#[cfg(target_os="linux")] fn fake_responder`）+ `:1802-1804` 缓存声明在 **per-peer relay 任务内**。需 Linux + `followRedirect`（TPROXY）+ CAP_NET_ADMIN。**Windows 本机不可实测**（理由：需要 iptables TPROXY 重定向与 root 能力，本机无） | `HashMap<(IpAddr,u16), Arc<UdpSocket>>` 每「响应源 IP:端口」一条 fd + socket 缓冲 | **无上限/无 TTL**，仅随 peer 会话（60s 双向空闲）drop 释放 | **CONFIRMED**（E2，Medium 保留；单 peer 可推高 fd） |
| **MW-4** ws 预连接池 | `crates/xray-transport-websocket/src/pool.rs:305 global_pool` 进程级单例；默认 `max_idle_per_key=12`（`:130`）、`max_idle_duration=10s`（`:130`）；`config.rs:60` 与 `register.rs:645` 默认 `poolSize=12`，`0` 才关 | 每 `PoolKey`（`host=dest.address()`、port、path、serverName、fingerprint、mask —— `register.rs:340-350`）≤12 条空闲 TCP/TLS/WS 连接 | **有上限但常数大**：`release` 受 12 约束（`pool.rs:263`），但 TTL 只在**同 key 下次 acquire** 时才扫（`pool.rs:219-237`），冷 key 的空 `VecDeque` 也从不摘除（无 `retain`/无后台清扫，`:161-171`）。key 数 = 每 outbound 固定 `dest`（**不是业务目的地址**）⇒ 与配置规模线性，不随流量增长 | **CONFIRMED / 严重度 ADJUSTED：Medium → Low**（原报告把 key 当成「每个访问过的拨号目标」，实际 key 的 host 是 outbound 的服务器地址，`register.rs:341` 原文 `host: dest.address()`；key 数受配置约束） |
| **MW-5** `ArmScopeRegistry` 只登记不摘除 | `crates/xray-frame/src/scope.rs:252-282`：`register` = 无条件 `push`，只有 `close_all_reverse` 清；登记点 `crates/xray-core/src/inbound.rs:3303-3305`。运行期可达：gRPC `AddInbound` → `crates/xray-core/src/functions.rs:603-629` → `InboundRuntime::add_inbound`（`inbound.rs:3131`）→ `spawn_inbound_serve`；CLI `xray api add-inbound`（`crates/xray-cli/src/commands/api_exec.rs:282-298`） | `Vec<(String, Arc<ArmScope>)>` 每条 +1，且**钉住该 arm 的 `FxScope`**（含 §1.2 A 类滞留） | **无上限**（每次 AddInbound 同 tag +1） | **CONFIRMED**（E2，Low 保留） |
| **MW-6** hysteria `clean_inactive` | 定义 `crates/xray-transport-hysteria/src/dialer.rs:351`；**全仓 0 调用点**（grep 仅命中定义自身） | 无（键 = `format!("{}|{}", dest.host, dest.udp_addr)`，`dialer.rs:339`，而 `dest` = `resolve_server_dest(&config.server_addr, ...)`（`crates/xray-proxy-hysteria/src/outbound.rs:104`）⇒ 单 outbound 恒 1 项） | 有界（= outbound 数） | **CONFIRMED（非增长）**：原报告对派单线索「池无清理⇒无界增长」的**证伪正确**；死代码需删或接 30s 任务 |
| **MW-7** 死件 | 我 grep（排除 `crates/udf-frame`）：`with_pool(` 仅 `crates/xray-frame/src/assembly.rs:222`（定义）+ `:475`（**装配测试**）；`XudpManager` 仅 `crates/xray-xudp/src/extension.rs` 自身测试 + `tests/integration.rs`；`ReverseMonitor`/`PreConnectPool` 仅 `crates/xray-proxy-vless/src/lib.rs:65-66` re-export + 自身测试；`ErrorCollector` 仅 `crates/xray-app-observatory/src/lib.rs:53` re-export + 自身测试 | 无（零生产消费） | n/a | **CONFIRMED**（Info；「看起来有清理」的假象风险成立） |

---

## 4. 「已被证实正确的 14 项」抽检（3 项，防把真接线误判为未接线）

| 抽检项 | 结果 | 证据 |
|---|---|---|
| `UdpDispatcher`（15s + 4096 + Drop） | **✅ 接线正确** | `crates/xray-transport/src/udp/dispatcher.rs:31` `MAX_NAT_ENTRIES=4096`；`:109-112` `spawn_tracked(cleanup_loop)` 在 `new()` 即起；`:131-146` 满表先 `retain` 再报 `InvalidInput`；`:205` `cleanup_loop` |
| mux `XUDPManager::start_cleanup` + picker 清理 | **✅ 接线正确** | `crates/xray-mux/src/worker.rs:147-148` `xudp_manager.start_cleanup()`；`crates/xray-mux/src/client.rs:205-207` `spawn_cleanup_task()` |
| hysteria `UdpSessionManager` 清理 + `close_fn` 摘除 | **✅ 接线正确** | `crates/xray-transport-hysteria/src/conn.rs:821-824` 清理 ticker 在 `start()` 内起；`:907-911` `set_close_fn` 内 `sessions.remove` |

---

## 5. 未覆盖范围（诚实边界）

- **B 类 25 处只做了「存在性 + 每事件语义」枚举（E2），未逐处做 E1**：我读了 `spawn_tracked(` 全部命中点及所在函数签名/循环位置，但没有为每个 crate 造 churn 拓扑。其中 **只有 1 处被 E1 直接量化**（A 类的 `xray-proxy-vmess/src/inbound/server.rs:185`，+2.06 allocs/conn）。
- **vless srv 侧 +218/+225 B/conn 的来源未定位到具体结构**（只证否「托管条目」、证成「+76 条大分配、第二轮 +36 条趋饱和」）。原因：该面无 `xray_common::alloc_site` 站点标记（标记只覆盖 TLS/BUF_READ/VLESS_ENC/XHTTP_SRV_SEND 等处），且红线面 `crates/xray-buf/src/alloc.rs` 只判授权不深挖。**建议另立票**，工具用 `live_allocs` + 尺寸直方图。
- 未审每包分配密度（另路 PerfWiring）；未审 CPU；Linux 面（TPROXY/tun）不可实测。
- `xray-buf` 红线：本复核只读授权面（`alloc.rs:24-37/84-102/204`），未做任何改动与判定升级。
- **原报告「14 项正面清单」我只抽检 3 项（均真）**，但发现其中相邻面有遗漏：`xray-app-proxyman` 被整段判「正确」，而其 `src/inbound/worker.rs:370/658`、`src/outbound/uot.rs:236/240` 是**每连接** `spawn_tracked`（会话表有清理≠条目有回收）。正面清单结论需按 §1.2 B 类重写。


---

## 6. 裁决表（9 列）

| 编号 | 原断言 | 裁决 | 复现/反证（命令与输出） | 归属 | 校准后严重度 | 最小修法 | 验证门 | 风险 |
|---|---|---|---|---|---|---|---|---|
| MW-1 | 长寿命 scope 无 `try_reap`，每连接滞留条目，OOM 级 | **CONFIRMED（机制/线性）；站点枚举与 vless 归因 ADJUSTED** | `mem_churn_v.py --proto vless`：cli **+2.02 allocs/conn、+396 B/conn**（churn#2 再 +2.01、+287）→ 线性；srv **+0.03 allocs/conn**（字节 +218 为高水位）；`--proto vmess`：srv **+2.06/+2.02**、cli **+4.06/+4.05 allocs/conn**；`fxretain` 复现 **440 B/2 allocs/条目**、`try_reap` 后归零；空闲 5/10/25s live 逐位不动 | **主仓接线缺口**（udf `fx.rs:249/484` 契约明写「调用方收割」，`fx.rs:1009` 自测钉死；非上游缺陷） | **Critical 保留**（A 19 处 + B 25 处 + C）；srv 字节面 **撤销**「条目」定性 | 方案 A：`xray-frame/src/scope.rs` 加 `spawn_reaping` helper，`ArmScope::spawn`(`:72-74`)/`ConnScope::spawn`(`:172-174`) 各 1 行，B 类 25 处机械替换；方案 B：udf 自动回收（提炼回路） | 我的 churn 脚本 `allocs/conn`→≈0；`-p xray-frame/xray-core/tuic/wg/dns/vmess/socks/http/trojan/anytls/hysteria` 测试；workspace + clippy + fmt；32/32；loopback bench <5% 回归；`shutdown_timeout` 报告不空 | 每 spawn 多一次锁（bench 兜底）；只修 A 类会漏 B 类（dns DoH 每查询最陡）；**续 `86i4h` 不新开票** |
| MW-2 | vmess `SessionHistory` 清理任务从未实现；+419 B/conn | **CONFIRMED（任务未实现）；E1 归因 ADJUSTED（≈70~110 B/conn）** | `encoding/server.rs:62-63` `CLEANUP_INTERVAL` dead_code；`:66-71` `new()` 无 spawn；`:88-98` 仅 len≥10k 惰性 retain；`bd search vmess/SessionHistory` = 0 票；vmess srv +631.7 vs vless srv +218~225 | **主仓接线缺口 + 文档谎言**（`server.rs:51-56` 声称 spawn，代码没有） | **High → Medium**（单独一条；与 MW-1 合并看才 Critical） | 装配点（`arm_builders/inbound.rs:886/1068`）用 `ctx.spawn` 起 30s `retain` 任务；删插入路径阈值全表扫描 | `-p xray-proxy-vmess`（新增过期清理断言）；churn 脚本 vmess srv `allocs/conn`≈0；32/32 | 忘记随 inbound 停 ⇒ 泄漏任务；`TtlCache` 不可直接用（单线程 `&mut self`） |
| MW-3 | dokodemo TPROXY `fake_cache` 无 cap/TTL | **CONFIRMED（E2）** | `inbound.rs:1802` 缓存 per-peer 任务内；`inbound.rs:1885-1901` `#[cfg(target_os="linux")]`；本机 Windows 不可实测（需 iptables TPROXY+CAP_NET_ADMIN） | 设计缺口（缺上界；Go 有 conn 兜底） | Medium 保留 | 加 256 上界 + LRU | Linux e2e（TPROXY 环境）+ fd 计数 | 修错会改变 TPROXY 回包路径（wire 语义敏感） |
| MW-4 | ws 池 idle 只惰性 TTL、空 key 不摘，冷 host 驻留到进程结束 | **CONFIRMED / 严重度 Medium→Low** | `pool.rs:219-237` 仅同 key acquire 时扫；`:263` 受 12 约束；`:161-171` 无清扫；`register.rs:340-350` key 的 host = `dest.address()`（outbound 服务器地址，非业务目的） | 设计权衡（预连接池，Go 无此机制） | **Low** | 10s 周期清扫 + 空 key 摘除 | `-p xray-transport-websocket`（补「无 acquire 的 key 被清」用例）+ 冷 host 场景 churn | 清扫任务生命周期需绑 pool 单例，勿随进程泄漏 |
| MW-5 | `ArmScopeRegistry` 只登记不摘除 | **CONFIRMED（E2）** | `scope.rs:252-282` 无条件 push + 仅 `close_all_reverse` 清；gRPC `AddInbound` 路径 `functions.rs:603`/`inbound.rs:3303` | 主仓接线缺口 | Low 保留 | 登记按 tag upsert（覆盖前 close 旧 scope） | `-p xray-core` AddInbound 重复 tag 用例（`registered()` 不增） | upsert 需先 close 旧 arm，否则旧监听仍活 |
| MW-6 | hysteria 池无清理⇒无界增长（派单线索） | **REJECTED（线索）；「`clean_inactive` 死代码」CONFIRMED** | `dialer.rs:351` 定义、全仓 0 调用；键 = server 侧地址（`outbound.rs:104` `resolve_server_dest`）⇒ 恒 1 项 | 死代码（清理对象不存在） | Low 保留（仅死件） | 删 `clean_inactive`（或接 30s 并补键语义注释） | 编译 + `-p xray-transport-hysteria` | 无 |
| MW-7 | 多件实现存在但零生产消费 | **CONFIRMED（E2）** | `with_pool` 仅 `assembly.rs:475` 测试；`XudpManager` 仅自测+integration；`ReverseMonitor`/`PreConnectPool` 仅 re-export+自测；`ErrorCollector` 同上 | 未接线（「看起来有清理」假象） | Info 保留（但 `with_pool` 涉及坑约束④无强制面 → 建议单列 Medium 决策票） | 删或接线二选一；`with_pool` 需 PM 决策（是否要求生产注入 BufferPool） | 编译 + grep 复核 | 直接删 `xray-frame::pool` 会丢「坑约束④」的未来强制面 |
| MW-8 | 稳态常驻预算清单（均显式有界） | **CONFIRMED（抽检 3 项一致）** | 见 §4：UdpDispatcher / mux cleanup / hysteria UDP 三处接线实读为真 | 设计如此 | Info | 无需动作 | — | 清单未逐项复核（14 项只看 3 项） |
| 新增 N1（我方） | vless 服务端（裸 spawn 路径）字节 +218~225 B/conn 但分配笔数 +0.01~0.03/conn | **NEW（原报告误并入 MW-1）** | 见 §0.1 churn#1/#2 表 | 待定（少数大 buffer 高水位/惰性扩容） | **Medium（待定责）** | 用 `live_allocs` + 尺寸分布定位（疑似池化缓冲高水位不缩） | 需新增站点标记/尺寸直方图工具；红线面需授权 | 若在 `xray-buf` 池内属红线，只判不动 |
| 新增 N2（我方） | 原报告把 `xray-app-proxyman` 整段判「正确」、且 B 类（组件自持 `FxScope`）几乎全漏 | **NEW（正面清单需重写）** | `xray-app-proxyman/src/inbound/worker.rs:370`（每 TCP 连接）、`:658`（每 UDP 会话）、`src/outbound/uot.rs:236/240`（每连接）均为 `spawn_tracked` 直投长寿命 scope；同型另有 socks/http/trojan/anytls/freedom/hysteria/wg/tuic/reverse/mux 共 25 处（§1.2 B 类） | 主仓接线缺口（同一 MW-1 根因） | 并入 MW-1（不单列） | 同 MW-1 方案 A（`spawn_reaping` 机械替换） | 同 MW-1 第 2 条（`allocs/conn`→0）**必须覆盖 B 类 crate** | 只按原报告修 A 类会让「修好」的假象留在 12 个 crate 里 |
