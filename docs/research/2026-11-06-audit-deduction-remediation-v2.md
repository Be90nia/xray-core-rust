# 整改 + 性能验收方案 v2（2026-11-06，多维审计扣分项拉分）

> v1 = `docs/research/2026-11-06-audit-deduction-remediation.md`（被本文件取代：v1 的「双主路」「xdns 未接线」等前提被用户口供与 PM 复核推翻）
> 审计底稿：`reports/audit-2026-11-06/{perf-memory,code-quality,architecture}.md` + `FINAL-MULTIDIM-AUDIT.md`
> 用户口供（2026-11-06，本版全部前提）：① **本项目一路就是 framework 架构** ② **新旧代码必须同节点实测对比，性能不优于旧的打回重做** ③ 直连与 CDN 都应能上 60+，CDN/Argo 因 **CF 线路优选**问题未测出真实速度 ⇒ 以历史均值 **50-60+（偶尔 70+）** 为基准

---

## 0. 前提校正（v1 的三处错误，本版已改）

| v1 说法 | 实际（PM 已复核） | 影响 |
|---|---|---|
| 「双主路：生产主路 = `Config::build()` → `start_full`；框架路 = `xray-cli --features framework-assembly`，框架路零 CI 保护」 | **生产路径本身就在 framework 架构上**：`crates/xray-core/src/arm_registry.rs` 用 `xray_frame::PluginRegistry` + `PluginContext` 做 38 个 arm 构造器的唯一生产查表路径（`arm_registry.rs:30-33/173/459`）。`framework-assembly` 只是个 **CLI 侧 feature 门控的备用组合根**（`xray-cli/src/framework.rs` 1752 行），默认不编译 ⇒ **架构 P1 从「生产无 CI 保护」降为「备用组合根无 CI 保护」**（P2）| 架构面评分回调；**不**再把「框架路进 CI」当 P1 |
| 「xdns DoH 生产未接线 ⇒ 波 C 不挂性能预期」 | 保留：PM 复核 `wrap_packet_conn_client` 生产调用点只有测试（`xray-core/src/inbound.rs:12785/12863`）。但**不影响**本轮：波 C 的 DoH 复用是对 `xdns/doh.rs`（finalmask 面）的改动，与 CDN/Argo 测速无关 | 波 C 降为 P2 工程债 |
| 「波 B 桥接字节闸 = 本轮唯一碰热路径的改动」 | **仍然成立且是唯一一处**。但门槛从「劣化 ≤5% 放行」升级为用户口径：**新的性能不优于旧的 ⇒ 打回重做** | 波 B 的验收标准全部重写（见 §3）|

---

## 1. 「拉分不亏性能」的路线图（重排后的最终版）

| 波 | 内容 | 影响的性能面 | 提分 | 风险 | 本轮做不做 |
|---|---|---|---|---|---|
| **A** | 账本归位 + 静默失败显性化（CQ-01/02/03/04/05/06/07、PM-04/05）| **零**（不在数据面热路径；CQ-02 消除忙等 = CPU 正向）| 代码质量 +0.3、性能/内存 +0.2 | 极低 | ✅ 做 |
| **B** | 桥接背压**字节闸**（PM-01：32 MiB/方向 → 2 MiB/方向 + 登记进 96 MB 簿）| **数据面**：mpsc 入队加字节记账 | 性能/内存 +0.2 | **中**（闸值不当=钉窗伤吞吐，r5j96 同族坑）| ✅ 做，但**必须过 §3 新旧实测** |
| **C** | 架构收敛（ARCH-03/04/05/06 + ARCH-02 ADR 位）| DNS 缓存 FIFO→LRU = 命中率↑ = 延迟↓（正向）；其余中性 | 架构 +0.4 | 中（跨 crate 搬移）| ⏳ 波次二 |
| **D** | `framework-assembly` 备用组合根进 CI 编译面（ARCH-01 降级后）| 零 | 架构 +0.1 | 零（只加 CI 一行）| ⏳ 需用户授权（`.github/workflows/` 红线）|

**波次顺序**：A（零风险，先落）→ B（唯一碰热路径，单独 A/B）→ C → D。
**波 B 不与波 A 同批**：性能归因必须单一变量。

---

## 2. 波 A 清单（零性能影响，PM 已写死给执行代理的边界）

| ID | 动作 | 位置 | 性能影响 |
|---|---|---|---|
| CQ-01 | DoH/xdns **失败路径**日志 `DEBUG → WARN`（Go `resolver_doh.go:252` 用 `Severity_Error` 恒可见）| `xdns/{doh,doh3,client}.rs`、`xray-app-dns/src/nameserver/*.rs` | 零（成功路径不写日志）|
| CQ-02 | `xdns/client.rs:266` `Err(_) => continue` → 记日志 + `return`（Go `xdns/client.go:312-313` 同款）| 同上 | **正向**（消除 100% CPU 忙等）|
| CQ-03 | `sockopt/mod.rs:932` `let _ = sock.set_only_v6(..)` → warn + 计数 | `sockopt/mod.rs` | 零 |
| CQ-04/05 | 注释口径改正（UDP 显式缓冲上限 4→64 MiB 实况；「quic:// 未实现」过期注释）| `sockopt/mod.rs`、`finalmask/mod.rs`、`xdns/mod.rs` | 零 |
| CQ-07/PM-04/PM-05 | 登记簿归位：`HANDSHAKE_INFLIGHT_MAX` 128→64 + 交叉断言；hyper idle「字节」改「连接数」；`xray-buf` 8 MiB 登记进簿（改条款不改常量）；h2 `send_buf` 16 MiB/连接入簿；7 个零断言常量补断言 | `xray-core/src/memory_budget.rs` | 零（断言在测试期）|
| CQ-06 | `xray-core/src/register.rs` 30+ `let _ =` → **聚合** warn（不逐条刷屏）；`register_feature` 满表错误类型改对 | `register.rs` | 零 |

**波 A 验收**：code-level（build + clippy `-D warnings` + 新增断言全绿 + **审计探针断言反转**：CQ-01 探针从「DEBUG 在 warn 门下不可见」改为「同事件在 warn 门下可见」；CQ-02 探针从「poll 打满」改为「不再打满」）；end-to-end 不需要 loopback A/B（不触热路径），但**必须**给「改动面不在数据面热路径」的说明（列出改动的函数）。

---

## 3. 波 B 方案 + 用户口径的验收门（重写）

### 3.1 改动（PM 已钉死语义，实现细节由执行代理定）

- `crates/xray-transport/src/bridge.rs:584` `PIPE_BUF_CAP = 64`（**按条目**）⇒ 单方向真上界 **32 MiB**、双向 **64 MiB/连接**，且**未登记进 96 MB 预算簿**（PM 复核：`memory_budget.rs` 全文件无 `bridge`）。
- 改法：**保留条目闸**，其上**加字节闸**：每方向一个 `Arc<tokio::sync::Semaphore>`（许可粒度 1 KiB），条目携带 `OwnedSemaphorePermits`（drop 即归还，零额外记账）；`acquire_many_owned` 必须放在**现有 select 分支内**（与 `abort_rx` 同分支 ⇒ 取消安全，不破坏 rjt2o 中止闸）。
- **闸值 = 2 MiB / 方向** ⇒ 每连接 4 MiB = 登记簿 `MAX_PER_CONN_BUFFER_BYTES`（4 MiB）的每连接份额，**不重复计账**。
- 为什么不照抄 Go 的 512 KiB：r5j96 教训（钉死窗口 = 伤吞吐，WSL netem 150ms 实测 ours 0.80 vs go 7.43 MB/s）⇒ 取 4× 余量，只在下游真读慢时才阻塞（背压该有的行为），**快链路零触发**。

### 3.2 验收门（用户口径：**不优于旧的 ⇒ 打回重做**）

原来的「劣化 ≤5% ⇒ 放行」作废。改为**双门**，两个都过才留：

**门 1（本地 loopback，机器可跑，机械判据）**
```
python tools/loopback_alloc_bench.py --ab <A=改动前二进制> --xray <B=改动后二进制> \
       --ab-runs 3 --ab-tol 0.05 --tag waveB-bridge-bytegate
```
判据：逐对比值中位 **≥ 1.00**（不许低于旧）；离散度 >15% ⇒ CONTAMINATED 重跑；`--floor 120` 不达标 ⇒ 直接 FAIL。
> 注意 `--ab-tol` 是**比值分数**（0.05 = 5%），不是百分数 15（那等于把闸关掉）。

**门 2（真机同节点，用户口径，决定性）**
- 拓扑：**直连**（`us1.begonia92.top` → 176 自有 VPS）+ **CDN**（`cdn_us1.begonia92.top` → CF anycast）+ **Argo**（`us1-argo.begonia92.top`）。
- A/B 二进制：同一台机器、同一客户端配置、同一节点、同一 URL，交替成对跑（`tools/ab_gate.py --scenario remote` 已有脚手架：`a_cfg`/`b_cfg`/两个 SOCKS 端口/同 URL）。
- 基准：**50-60+ MB/s，偶尔 70+**（用户口供）；直连已实测能上 60+ ⇒ 直连是新旧对比的**主战场**。
- 判定：**B 侧中位 ≥ A 侧中位**（不低于旧）⇒ PASS；低于 ⇒ **打回重做**（不是「调闸值凑过」，是重做实现）。
- **CDN/Argo 的可比性前提**（用户指出的「CF 线路优选出问题」）：A/B 每一对必须落在**同一 CF 边缘/同一路径** —— 固定 CF IP + SNI/Host 一致（`--resolve` 或 hosts），并读 `CF-RAY` 头取本轮 colo 留证；colo 不一致 ⇒ 该对作废重跑。方法学正在并行调研（`reports/audit-2026-11-06/research-cf-edge-bench.md`）。

**门 3（内存账，必须与门 1/2 同时成立）**
- 登记簿新增一行：桥接背压闸（每方向 2 MiB，双向 4 MiB/连接）进入 96 MB 预算簿，且**不与** `MAX_PER_CONN_BUFFER_BYTES` 重复计账（同一份额）。
- 新增行为级回归测试：在途字节 ≤ 闸值；改大闸值即红（反向自检锚点）。

**打回重做的触发条件（任一）**：门 1 中位 < 1.00；门 2 任一拓扑中位 < A 侧；门 3 断言不成立；离散度 >15% 且重跑三次仍超。

---

## 4. 波 C（波次二，待波 B 过门后启动）

| 项 | 方案 | 性能 |
|---|---|---|
| ARCH-04 DNS 缓存自造 FIFO | 换 udf `SyncTtlCache`（**已存在**，`crates/udf-frame/std-ext/src/cache.rs:666`，`&self` + Mutex 短临界 + TTL 语义齐）| **正向**：LRU 命中率↑ ⇒ 上游查询↓ ⇒ 延迟↓ |
| ARCH-03 DoH 三份实现 | `xdns/doh.rs` 手写 h2 → hyper-util legacy Client（workspace 既有依赖；`xray-transport-splithttp/src/client.rs` 有同款 client 模式可抄）⇒ 连接池 + HTTP/2 多路复用 | **正向**：每查询省 TCP+TLS+h2 三个握手 |
| ARCH-05 共享池注册表 | 池本体已合规（udf `ObjectPool`），注册表提炼到 `xray-frame` | 中性 |
| ARCH-06 uuid 第二套 | 换 udf `RandomId`（`std_ext::id`，UUIDv4/OS CSPRNG）—— **需开 udf `random` feature**（getrandom 依赖，PM 拍板点）| 中性 |
| ARCH-02 ADR 落盘位 | 建 `docs/adr/` + 本轮公共 API 变更补记 | 中性 |

---

## 5. 波 D（需用户授权）

`.github/workflows/ci.yml` 加一行 `cargo build/test -p xray-cli --features framework-assembly`（备用组合根进 CI 编译面）。**红线，需你一句话**。不授权则 ARCH-01 记 bd 票挂账，不影响其它波次。

---

## 6. 明确不做（防提分注水）

- 不给热路径加常驻缓冲/预分配换分（换分即扣分）。
- 不放宽任何断言；不把「注释已修」当「缺陷已修」计分。
- 不新增外部 crate（`reqwest`/`hyper`/`hyper-util`/`h2`/`quinn`/`tokio` 已在依赖树内）。
- 不在授权前改 `.github/workflows/`。
- **不为了刷分去动 CDN/Argo 链路的传输参数**（ws 帧/窗/h2 窗）—— 那属于性能战役，且必须走新旧 A/B 门，不在审计整改范围内。
- 不改 `crates/udf-frame/**`（父仓独立 PR 回路）；波 C 若需改 udf，走独立 PR + 三平台 CI 绿 + 主仓换依赖复测 32/32。
