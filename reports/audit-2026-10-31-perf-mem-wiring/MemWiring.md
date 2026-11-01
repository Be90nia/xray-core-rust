# R3 内存维度审计（时间维度的驻留/增长 + 释放链路接线）

- 审计人：MemWiring（performance-reviewer 子代理）
- 日期：2026-10-31
- 仓库：`D:/Project/Xray-core-rust`，分支 `feature/fix-inbound-parity`，HEAD `5fe98b90`
- 性质：**只读审计**，未改动任何产品代码（新增仅本报告 + `scripts/mem_wiring_churn.py` 测量脚本）
- 分工边界：只审「时间维度的驻留/增长 + 建/拆是否成对」；每包/每 MB 的空间密度归 PerfWiring。撞上的条目只报一次并标「交叉」。

**首行判据**：`VERDICT: FAIL` —— 存在一条**框架级、生产主路可达、随连接数线性增长且永不回收**的驻留（MW-1，E1 实测 +201 B/连接；vmess 服务端 +620 B/连接），以及 vmess 会话表清理链路断线（MW-2，E1 实测）。

---

## 0. 机器可读回执所需的汇总

| 项 | 数 |
|---|---|
| 发现总数 | 8（Critical 1 / High 1 / Medium 2 / Low 2 / Info 2） |
| E1（一手实测） | 2（MW-1 的连接级驻留、MW-2 的 vmess 增量） |
| E2（源码推导）+ 可跑命令 | 6 |
| 「回收任务未接线」条目 | 7（见 §3） |
| 死件（实现存在、整模块零生产消费） | 5（见 MW-7） |
| 已接线且判定正确（正面清单） | 14（见 §5） |

实测原始数据（同一脚本、同一拓扑、同机同窗，`XRAY_ALLOC_STATS=1` 的 `live_bytes` 分配器级读数）：

| 协议 | 目标连接 | 成功 | 服务端 live 增量 | 客户端 live 增量 | churn 后 60s/30s 空闲 |
|---|---|---|---|---|---|
| vmess+tcp | 6000 | 5154（失败 846，Windows 动态端口） | 1 003 467 → 4 199 795（**+3.20 MB，+620 B/conn**） | 1 270 420 → 5 933 337（**+4.66 MB，+905 B/conn**） | live 恒定 **4 199 795**（12 个采样点全同） |
| vless+tcp（对照） | 6000 | 4842（失败 1158） | 563 748 → 1 537 868（**+0.97 MB，+201 B/conn**） | 445 579 → 2 160 771（**+1.72 MB，+354 B/conn**） | live 恒定 **1 537 868**（6 个采样点全同） |
| vmess−vless 差 | — | — | **+419 B/conn** | +551 B/conn | 两侧均零回落 |

复跑命令：

```bash
cd D:/Project/Xray-core-rust
python reports/audit-2026-10-31-perf-mem-wiring/scripts/mem_wiring_churn.py \
    --proto vmess --conns 6000 --warmup 800 --idle 60 --threads 12
python reports/audit-2026-10-31-perf-mem-wiring/scripts/mem_wiring_churn.py \
    --proto vless --conns 6000 --warmup 800 --idle 30 --threads 12
```

拓扑 = 生产主路（`xray.exe run -c` → `xray_conf::Config::build()` → `xray_core::start_full`）：
`python → socks(socks inbound) → vmess|vless/tcp → server → freedom → echo`，两侧进程均开 `XRAY_ALLOC_STATS=1`（1s 采样）。
「空闲平台不动」是本轮最关键的一手证据：**若清理链路是活的，churn 结束后驻留必须回落**；两侧 60s/30s 窗内 `live_bytes` 一位不差，说明没有任何回收动作发生。

---

## 0.1 发现索引（8 列全文；详情见对应小节）

| 标题 | 严重度 | 位置 file:line | 现状 | 增长/泄漏机制 | 生产可达性证据 | 证据等级 + 命令 | 建议一行 |
|---|---|---|---|---|---|---|---|
| MW-1 `FxScope` 完成条目滞留、长寿命 scope 零收割 | **Critical** | `udf-frame/skeleton-infra/src/fx.rs:252-253,484`；`xray-frame/src/scope.rs:88-93`、`:196-206`；唯一收割 `xray-frame/src/compat.rs:249` | 任务完成后条目留在 JoinSet，只有 shutdown/drop 释放；arm/conn scope 无 `try_reap` 调用 | 每完成一个被托管任务 +1 条目；实测 **+201 B/conn**（vless srv）/ **+354 B/conn**（vless cli）/ **+620 B/conn**（vmess srv）/ **+905 B/conn**（vmess cli）；500 conn/min ⇒ +139~434 MB/天，可达 OOM | 生产主路 `xray.exe run -c` 的 socks/mixed/vmess/vless/ss/tuic/wg 入站全部 `ctx.spawn`（`inbound.rs:557,632,1737,2300…`、`vmess/inbound/server.rs:185`） | **E1** `python reports/audit-2026-10-31-perf-mem-wiring/scripts/mem_wiring_churn.py --proto vmess --conns 6000 --warmup 800 --idle 60`（及 `--proto vless` 对照） | 长寿命 scope 加「spawn 前 reap」或 60s 周期 `try_reap()`（照抄 `compat::ManagedScope::spawn`） |
| MW-2 vmess `SessionHistory` 清理任务从未实现 | **High** | `xray-proxy-vmess/src/encoding/server.rs:57-98`（`CLEANUP_INTERVAL` dead_code、惰性阈值 10k） | TTL 180s 在 <1 万条时不生效（条目驻留到进程结束）；≥1 万条后每次 insert O(n) 扫描 | 每连接 +1 条（48B key+Instant，实测净增 **+419 B/conn**），60s 空闲 `live_bytes` 一位不动 | `arm_builders/inbound.rs:886/1068` + `vmess/inbound/server.rs:162`（tcp/uds 两路都建）；E1 同 MW-1 | **E1** 同 MW-1（vmess − vless 差） | 接线 30s 周期清理（或换 TtlCache），删掉 insert 路径的全表扫描 |
| MW-3 dokodemo TPROXY `fake_cache` 无上限 | Medium | `xray-core/src/inbound.rs:1801-1841` | 每 (响应源 IP,端口) 一个 fakeudp socket，无 cap/TTL/淘汰，随 peer 会话 drop | 单 peer 持续喂包且目的不断变化 ⇒ fd+socket 缓冲线性增长至 fd 上限 | Linux + `followRedirect`（TPROXY）专属分支；本机 Windows 不可实跑 | E2（需 Linux + CAP_NET_ADMIN） | 加上界（如 256）+ LRU |
| MW-4 ws 池 idle 连接无后台清扫、空 key 不摘 | Medium | `xray-transport-websocket/src/pool.rs:161-171,229-237,253-268` | TTL 10s 只在同 key 再 acquire 时惰性检查 | 每个访问过的拨号目标常驻 ≤12 条空闲连接，冷 host 到进程结束 | `global_pool()` 进程级单例，ws 传输默认启用（`max_idle_per_key=12`） | E2（缺「无人访问 key」用例） | 加 10s 周期清扫 + 空 key 摘除 |
| MW-5 `ArmScopeRegistry` 只登记不摘除 | Low | `xray-frame/src/scope.rs:246-282`；`xray-core/src/inbound.rs:3302-3305` | 仅 `close_all_reverse` 出清 | 每次运行期 inbound 重启 +1 永久条目（并钉住该 arm scope） | 仅 AddInbound/RemoveInbound command 面 | E2（文档自认） | 按 tag upsert，覆盖前 close 旧 scope |
| MW-6 hysteria `clean_inactive` 零调用（非增长） | Low | `xray-transport-hysteria/src/dialer.rs:339,350-364` | 清理函数死代码；键=server 侧地址 → 单 outbound 恒 1 项 | 无增长（派单线索「池无清理⇒无界增长」经核实不成立） | 全仓 0 调用点 | E2（键构造链已读全） | 删掉或接 30s 周期任务 |
| MW-7 死件：实现存在、整模块零生产消费 | Info | `xray-xudp/src/extension.rs:122`、`vless/outbound/{reverse.rs:115,preconnect.rs:203}`、`observatory/error_collector.rs:11`、`xray-frame/src/pool.rs`+`assembly.rs:475` | cleanup 函数仅测试调用；`with_pool` 唯一调用点是装配测试 | 无增长（同时也意味着「坑约束 4 缓冲必走 BufferPool」无强制面） | 生产路径零引用（grep 全仓） | E2 | 死件删或接线，二者选一（禁留「看起来有清理」） |
| MW-8 稳态常驻预算清单 | Info | 见 §2 表（xray-buf 池 / 审计环 / status 表 / ws 池 / quinn 窗 / 线程池） | 均显式有界 | 不增长（上限见 §2） | 生产主路 | E2 + 部分 E1（`live_bytes` 基线 0.3–1.0 MB） | 无需动作，仅作预算基线 |

---

## 1. M1：正常流量下无界增长的容器（按增速排序）

### MW-1（Critical）`FxScope` 完成条目滞留 + 主仓长寿命 scope 零收割

**建在哪**：`crates/udf-frame/skeleton-infra/src/fx.rs:252-253`
`FxScope { set: Mutex<JoinSet<Result<(), TaskError>>>, ... }` —— udf 自己的文档写得很清楚：
`crates/udf-frame/skeleton-infra/src/fx.rs:249`「完成条目滞留至 [`Self::try_reap`] 或停机排空显式收割」。
tokio `JoinSet` 不会在被 join 之前丢弃已完成任务的条目（条目持有任务分配块与 join 载荷）。

**应拆在哪**：`FxScope::try_reap()`（`fx.rs:484`，udf issue#13 新增）——能力**已存在**。

**拆的调用点在不在**：**不在**。全仓（除 `udf-frame`）`try_reap|.reap()` 仅 6 处命中，全部在
`crates/xray-frame/src/compat.rs`（`:203/:227/:235/:243/:249/:415`），且只作用于 `ManagedScope`
**自己持有的那份**内嵌 scope —— `ManagedScope::spawn` 每次 spawn 前先 `reap()`（`compat.rs:235`），
所以 dispatcher / dial-bridge 这条线**是对的**（可作范本）。

而**长寿命、按事件高频 spawn 的 scope 全部没有收割**：

| scope | spawn 入口（file:line） | 每次 spawn 对应的事件 | 收割 |
|---|---|---|---|
| `ArmScope`（inbound 级，进程寿命） | `crates/xray-frame/src/scope.rs:88-93` `ArmScope::spawn` → `spawn_tracked`（无 reap） | **每条 TCP 连接 / 每个 UDP 会话** | 无 |
| 同上，生产调用点 | `xray-core/src/inbound.rs:557`（mixed/socks 每连接）、`:632/:645/:698/:744/:800`（mux/UDP associate）、`:1576`、`:1737`（dokodemo 每 peer）、`:2072/:2117/:2300/:2483/:2548`（ss/ss2022 每 client 会话）、`:2695/:2710`（dns 入站） | 同上 | 无 |
| `xray-proxy-vmess` 入站 | `crates/xray-proxy-vmess/src/inbound/server.rs:185` `ctx.spawn(...)`（每连接） | 每连接 | 无 |
| `ConnScope`（连接级） | `scope.rs:196-206` `spawn_tracked`（无 reap） | 每连接内子任务 | 条目随 scope drop 释放 → **非泄漏** |
| DNS nameserver `fx`（实例寿命） | `crates/xray-app-dns/src/nameserver/cached.rs:315`（每次 serveStale 刷新一个任务） / `crates/xray-app-dns/src/nameserver/doh.rs:288`（**每次 DoH 查询**驱一个 h2 连接任务） | 每次刷新 / **每次查询** | 无 |
| `UdpRelay` scope（监听器寿命） | `crates/xray-transport/src/udp/relay.rs:216-217`（每 UDP 会话一个 idle timer） | 每会话 | 无 |
| tuic 入站 scope | `crates/xray-proxy-tuic/src/server.rs:159`（每连接）、`:270`（每 relay）、`:524`（每 UDP assoc） | 每连接/会话 | 无 |
| wireguard 入站 scope | `crates/xray-proxy-wireguard/src/inbound.rs:351`（每 relay）、`:374`（每 dispatch）、`:497`（每 UDP 会话） | 每连接/会话 | 无 |

**泄漏机制（什么输入让什么增长，增速量级）**：
每完成一个被托管任务 → JoinSet 内留存 1 条条目，直到该 scope 的 `shutdown_timeout`/drop。
条目成本 = 该任务分配块大小（头 + 已完成 future 的状态机尺寸），**E1 实测每连接 +201 B（vless 服务端）/ +354 B（vless 客户端，含 socks 入站侧）/ +620 B（vmess 服务端）/ +905 B（vmess 客户端）**。

- 增速换算：500 连接/分钟（≈8.3 conn/s，普通代理节点量级）= 72 万连接/天 → **+139 MB/天（vless）/ +434 MB/天（vmess）**；
  30 conn/s = 260 万连接/天 → **+0.52 GB/天（vless）/ +1.6 GB/天（vmess）**。
- DNS DoH 面更陡：每查询 1 条条目（`doh.rs:288`），100 qps = 864 万条/天。
- 结论「增长到什么程度会出事」：**OOM 级**——不是缓慢长，是线性到进程被 OOM killer 杀掉；且 bar 越高（越忙的节点）越快。

**生产可达性证据**：`xray.exe run -c`（生产主路）的 4 条入站路径（socks/mixed/vmess/vless/ss/tuic/wg）全部走 `PluginContext::spawn`
→ `ArmScope::spawn`（`context.rs:192-197` → `scope.rs:88`）；以上 E1 即用默认 `xray.exe` 实测。

**证据等级**：E1（实测，见 §0 表 + 复跑命令）；机制侧 E2 由 udf 源码与测试
`fx.rs:1009 try_reap_drains_retained_entries_and_is_idempotent` 钉死（「101 条目全部已终局，滞留集合」）。

**归因论证（为何判定是「托管条目滞留」而不是别的 per-conn 状态）**：
1. 残留**与协议无关**：vless 路径（`xray-proxy-vless` 无 per-conn 表——已 grep 全 crate：只有 `validator.email_index/uuid_index`（按用户，配置域）
   与 `inbound/reverse.rs:56 ReverseRegistry`（按配置 tag））也各有 +201/+354 B/conn；唯一「每连接都建且活在长寿命对象里」的东西就是 arm scope 的 JoinSet 条目。
2. 残留**只增不减且不随时间回落**（60s/30s 采样点逐位相同）→ 排除缓存 TTL/惰性收缩类（那些会变）。
3. 增量**与连接数成正比**（+3.20 MB / 5154 conn，+0.97 MB / 4842 conn）→ 排除一次性水位（池预热）类。
4. 库侧语义由 udf 自己的测试钉死：`fx.rs:1009 try_reap_drains_retained_entries_and_is_idempotent`
   （「101 条目全部已终局，滞留集合」）。
> 若要 100% 关闭归因争议，可加一条 5 行 micro-repro（不进产品代码）：同 topology 但把入站处理器换成「accept 即 drop 连接」，
> 若每连接残留仍在 ≈200 B，则唯一变量就是托管条目。

**建议一行**：给 `ArmScope`/DNS/udp-relay/tuic/wg 这些长寿命 scope 加「spawn 前 reap」或 60s 周期 `try_reap()`
（照抄 `compat::ManagedScope::spawn` 的 3 行），把 udf 已有的收割口接上；`ConnScope` 无需改。

---

### MW-2（High）vmess `SessionHistory` 清理任务从未实现（E1：+419 B/连接，且永不回落）

**建在哪**：`crates/xray-proxy-vmess/src/encoding/server.rs:57-58`
`inner: Mutex<HashMap<SessionId, Instant>>`；每连接在 `:237 add_if_not_exists` 插 1 条（TTL 180s）。
装配点：`xray-core/src/arm_builders/inbound.rs:886`（tcp）、`:1068`（uds）、`xray-proxy-vmess/src/inbound/server.rs:162`。

**应拆在哪**：Go 是 `task.Periodic(30s)` 全表 retain。

**拆的实现在不在**：**不在**。`:62-63 const CLEANUP_INTERVAL` 挂着 `#[allow(dead_code)]`，注释自认
「清理接线随 dispatcher 稳定批次跟进」；文件头 `:51-56` 的文档说「改为启动时 spawn 一次性后台任务」，**与代码不符**（代码里没有任何 spawn）。
实际清理只有 `:88-98` 的惰性 retain：`if inner.len() >= RETAIN_THRESHOLD(10_000) { retain(...) }`。

**泄漏机制**：
1. **TTL 在 < 10 000 条时完全不生效** —— 条目驻留到进程结束（E1 实证：60s 空闲窗 `live_bytes` 一位不动）。
2. ≥10 000 条后，**每次 insert 都付一次 O(n) 全表扫描**（首达阈值后 len 不会掉回阈值以下，稳态即每连接 O(10k)）——属 PerfWiring 面的 CPU 灾难，本条只登记交叉。
3. 增速：+419 B/conn（E1，vmess − vless 同拓扑差），叠加 MW-1 后 vmess 服务端合计 **+620 B/conn**。

**生产可达性证据**：E1 用 `xray.exe` vmess 入站实测（§0）；`SessionHistory` 在两条装配路径都建（tcp/uds）。

**证据等级**：E1。
**建议一行**：删掉惰性阈值扫描，接线 30s 周期清理任务（或改用 udf `std_ext::cache::TtlCache`，但那件是单线程 `&mut self`，并发面需自持锁）——两者都不要在 insert 热路径做全表扫描。

---

### MW-3（Medium）dokodemo TPROXY `fake_cache`：每个 (响应源 IP, 端口) 一个 fakeudp socket，无上限

**位置**：`crates/xray-core/src/inbound.rs:1801-1841`（`fake_cache` 声明 + `fake_responder`）。
**现状**：`HashMap<(IpAddr, u16), Arc<UdpSocket>>` 挂在 **per-peer relay 任务**内，键来自**出站响应源**；
命中即复用，未命中就 `fake_udp()` 新建并插入。**无上限、无 TTL、无淘汰**，只有 peer 会话结束（60s 双向空闲）才随任务 drop 释放。
**泄漏机制**：同一 peer 被持续喂包时永不空闲 → 只要它访问的目的 (IP, 端口) 不断变化（扫描/多目的 UDP），
表与 fd 线性增长：每条 +1 fd + socket 缓冲（64KB 级）。单一 peer 可推高到进程 fd 上限。
**生产可达性**：仅 Linux + `followRedirect`（TPROXY）路径；非 TPROXY 与 Windows 不执行该分支（`#[cfg(target_os="linux")]`）。
**证据等级**：E2（源码可达；本机 Windows 无法实跑 TPROXY：需要 `CAP_NET_ADMIN` + iptables 重定向）。
**建议一行**：给 `fake_cache` 加上界（如 256 项）+ LRU 淘汰（Go 侧也是"per 源缓存"，但 Go 有 conn 生命周期兜底）。

### MW-4（Medium）websocket 池：idle 连接只惰性过期、空 key 不摘除 → 冷 host 连接驻留到进程结束

**位置**：`crates/xray-transport-websocket/src/pool.rs:161-171`（`inner: Arc<Mutex<HashMap<PoolKey, VecDeque<PoolEntry>>>>`）、`:219-237`（`try_acquire` 里才扫 TTL）、`:253-268`（release 受 `max_idle_per_key=12` 约束）。
**现状**：TTL 10s 只在**同 key 下一次 acquire** 时检查；没有后台清扫任务，`retain`/空 key 摘除也不存在。
**泄漏机制**：进程访问过的每个拨号目标（`PoolKey = (host, port, path)`，即 ws 服务端）保留 ≤12 条空闲连接（每条约 1 条 TCP + hyper/tungstenite 状态 + socket 缓冲），
访问一次后就再无 acquire 的 host 永远不会被释放。增速：**每新 host +≤12 连接常驻**，与流量无关（key 数受配置/目标数约束 → 增长有界但常数偏大）。
**生产可达性**：`global_pool()`（`:305`）是进程级单例，`register_dialer` 解析 wsSettings 即启用（默认 `max_idle_per_key=12`）；ws 是最常用传输之一。
**证据等级**：E2（`pool_sweeps_expired` 只测「同 key 再取时过期被扫」，无「无人访问的 key」用例 → 缺的正是本条的清扫面）。
**建议一行**：加一条 10s 周期清扫（或复用现有 `reap` 钩子式惰性路径），扫全表并把空 VecDeque 的 key 摘掉。

### MW-5（Low）`ArmScopeRegistry` 只登记不摘除，inbound 运行期重启每次 +1 永久条目

**位置**：`crates/xray-frame/src/scope.rs:246-282`（`entries: Mutex<Vec<(String, Arc<ArmScope>)>>`，只有 `close_all_reverse` 出清）；登记点 `xray-core/src/inbound.rs:3302-3305`。
**机制**：注册一次 `spawn_inbound_serve` 就追加一条，永不 `remove`；`Instance::close` 才 `mem::take`。
运行期 `AddInbound/RemoveInbound`（proxyman command 面存在）rebind 同一 tag → 旧条目仍在表里，
附带把该 arm 的 `FxScope`（含 MW-1 滞留的条目）钉住不释放。增速：每次重启 +1 条（~百字节 + 钉住 scope）。
**生产可达性**：仅运行期动态增删入站（API/command 面），启动-运行-退出的常规主路不触发。
**证据等级**：E2（`scope.rs:244` 文档已自认「条目仅在 close_all_reverse 出清」）。
**建议一行**：登记时按 tag upsert（同 tag 覆盖前先 close 旧 scope），而非无条件 push。

### MW-6（Low）hysteria `ClientManager::clean_inactive` 零调用（但非增长）

**位置**：`crates/xray-transport-hysteria/src/dialer.rs:350-364`（定义）；全仓 0 调用点。
**定性修正（线索复核）**：派单线索称「hysteria client 池无清理 → 无界增长」，**实测源码不成立**：
`get_or_create` 的 key 是 `format!("{}|{}", dest.host, dest.udp_addr)`（`dialer.rs:339`），而 `dest` 来自
`config.server_addr/server_name`（`xray-proxy-hysteria/src/outbound.rs:96` `resolve_server_dest`、
`dispatcher.rs:414-433`），**不是业务目的地址** → 单个 outbound 恒 1 项，非增长。
`clean_inactive` 仍是死代码（且 `Status::Inactive` 只有 `ensure_connected` 会临时产生），删或接上二选一。
**证据等级**：E2（源码；键的构造已读全链）。
**建议一行**：把 `clean_inactive` 删掉（它对应的 Go `clientManager.clean()` 语义在本键模型下无对象），或接成 30s 周期任务并补 key 语义说明。

---

## 2. M3：长跑稳态不可回收驻留（有界，供内存预算）

| # | 常驻面 | 位置 | 上界 / 实测 | 判定 |
|---|---|---|---|---|
| a | `xray-buf` TLS 级缓存 + 分片池（⛔ 红线只审） | `crates/xray-buf/src/alloc.rs:24-37,84-102` | TLS `8/层` × 4 层/线程；全局 `8 分片 × 64 块/层` + 60s 半衰（`:204` `maybe_sweep`）。最坏理论 ~85 MB（全 tier3 满），实测常驻远低（本机 live_bytes 基线 0.3-1.0 MB 量级） | ✅ 有界（TLS 侧按线程数线性：1 MB/线程 上限） |
| b | 插件审计环 | `crates/xray-frame/src/audit.rs:60-83`（`DEFAULT_AUDIT_RING_CAP=1024`，`EvictOldest`） | 每 ctx ≤1024 条 ×（seq+plugin+String+FieldBag）≈ 150 KB/ctx；按 arm ctx 数线性 | ✅ 有界 |
| c | observatory `StatusStore` | `crates/xray-app-observatory/src/status.rs:15-17` | `MAX_STATUSES=1024` + 淘汰最久未探测 | ✅ 有界（有显式上界） |
| d | stats 三张注册表 + online map | `crates/xray-app-stats/src/manager.rs:28-30`、`online_map.rs:41` | 键 = `user>>>{email}>>>…`（配置域）+ 每用户在线 IP 表（refcount 归零即删，`OnlineIpGuard` 兜底，`dispatcher/src/default.rs:851-865`） | ✅ 有界（`close` 清空 online_maps） |
| e | ws 池 idle 驻留 | 见 MW-4 | ≤12/key × key 数 | ⚠ 有界但无主动回收 |
| f | hysteria/quinn 连接窗 | `xray-transport-hysteria/src/dialer.rs`（单 client） | 每 outbound 1 条 QUIC conn，`conn_receive_window` 默认 20 MB **上限**（按需分配） | ✅ 有界 |
| g | geodata/router 构建池 | `xray-app-geodata/src/loader.rs:126`、`xray-app-router/src/condition.rs:1248` | `MemoryPool::new(max,max,Vec::new)`（idle 槽是空 `Vec`，无 payload 驻留）+ `ThreadPool(core,max,queue_cap)` 常驻线程 | ✅ 有界 |
| h | log 密钥掩码表 | `xray-common/src/log/mod.rs:120` `SECRETS: RwLock<Vec<String>>` | 替换语义（`set_secrets`），不追加 | ✅ 有界 |
| i | mux `SessionManager` / `XUDPManager` | `xray-mux/src/session.rs:115-133,672-774` | `sessions` 随 `Session::close → parent.remove` 摘除（`:324`）；`size` 原子镜像供 `is_full`（bd 4uuo 已修）；XUDP 条目 `Expiring` 60s 后由 `start_cleanup` 任务回收（`:694`，`worker.rs:148` 已接线） | ✅ 正确（b d a5pe6 相邻的 `is_full 活跃数` 面无缺陷） |

---

## 3. M2：回收链路接线核对表（「建在哪 / 应拆在哪 / 拆的实现 / 拆的调用点」）

| 项 | 建在哪 | 应拆在哪 | 拆的实现存在？ | 拆的调用点 | 结论 |
|---|---|---|---|---|---|
| vmess 反重放会话表 | `xray-proxy-vmess/src/encoding/server.rs:237` | 30s 周期 retain（Go `task.Periodic`） | ❌ 只有 len≥10k 的惰性 retain（`:88-98`），`CLEANUP_INTERVAL` 是 `dead_code` | 无 | **断线（MW-2）** |
| arm 托管任务集条目 | `xray-core/src/inbound.rs:557` 等（`ctx.spawn`） | `FxScope::try_reap()` | ✅ `udf fx.rs:484` | ❌ 长寿命 scope 零调用（只在 `compat.rs:249` 对 ManagedScope 自己调用） | **断线（MW-1）** |
| dns DoH h2 连接驱动 | `xray-app-dns/src/nameserver/doh.rs:288` | 同上 | ✅ | 无 | **断线（MW-1 子项，每查询）** |
| dns serveStale 刷新任务 | `xray-app-dns/src/nameserver/cached.rs:315` | 同上 | ✅ | 无 | **断线（MW-1 子项）** |
| udp relay 会话 idle timer | `xray-transport/src/udp/relay.rs:216` | 同上 | ✅ | 无 | **断线（MW-1 子项，每会话）** |
| arm scope 登记表条目 | `xray-core/src/inbound.rs:3302` | 同 tag upsert / 摘除 | ⚠ 只有 `close_all_reverse`（`scope.rs:266`） | 仅停机 | **运行期不摘除（MW-5）** |
| ws 池 idle 连接 | `xray-transport-websocket/src/pool.rs:262` | 后台清扫 + 空 key 摘除 | ⚠ 只有 acquire 时惰性 TTL（`:229-237`） | 同 key 再取时 | **半接线（MW-4）** |
| dokodemo TPROXY fake socket | `xray-core/src/inbound.rs:1801` | 上界 + LRU | ❌ 无 | — | **缺（MW-3）** |
| app-proxyman 会话表 | `xray-app-proxyman/src/inbound/worker.rs:534` | 60s idle retain | ✅ `cleanup_inactive`（`:727`） | ✅ interval tick（`:806-808`，60s 对齐 Go） | 正确 |
| mux XUDP 条目 | `xray-mux/src/session.rs:747` | 60s 清 `Expiring` | ✅ `start_cleanup`（`:694`） | ✅ `worker.rs:148`（每日 Drop abort） | 正确 |
| mux worker 列表 | `xray-mux/src/client.rs:143` | 30s retain closed | ✅ `spawn_cleanup_task`（`:218`） | ✅ 首个 worker 创建时启动（`:197-206`，bd me7k 已修） | 正确 |
| UDP NAT 表 | `xray-transport/src/udp/dispatcher.rs:102` | 15s retain + 4096 上界 | ✅ `cleanup_loop`（`:205`）/`register` 满表先清（`:129-140`） | ✅ `new()` 即 spawn（`:108`）+ `Drop` abort | 正确 |
| dns 缓存条目 | `xray-app-dns/src/cache_controller.rs:52` | 300s retain + shrink | ✅ `run_cleanup`（`:288`） | ✅ `start_managed`（`:325-333`）→ `Feature::start`（`server.rs:311-313`） | 正确 |
| ss / ss2022 UDP 会话 | `xray-core/src/inbound.rs:2273/2407/2520` | 每包 retain + 500s 惰性 | ✅ `clients.retain` / `sweep_expired_ss2022_sessions` | ✅ 收包路径内（`:2297`、`:2432`） | 正确（O(n)/包 属 PerfWiring 面） |
| tun UDP 会话 | `xray-proxy-tun/src/inbound.rs:921` | idle sweep | ✅ `sweep_udp_sessions` | ✅ 周期 tick 任务（`:913`） | 正确 |
| wireguard netstack UDP | `xray-proxy-wireguard/src/netstack.rs:414` | idle sweep | ✅ `sweep_udp` | ✅ `inbound.rs:298` 周期任务 | 正确 |
| xhttp 服务端会话表 | `xray-transport-splithttp/src/hub/session.rs:51` | 30s reap / 连接结束 remove | ✅ `remove`（`:122`）+ reap timer（`:100-110`） | ✅ 3 处（`handler.rs:383`、`SessionDropGuard:522`、`session.rs:107`） | 正确（bd s10/s12 已修） |
| 在线 IP 表 | `xray-app-stats/src/online_map.rs:41` | refcount 归零删 | ✅ `remove_ip`（`:103`） | ✅ `OnlineIpGuard::drop`（`dispatcher/src/default.rs:854-865`） | 正确 |
| hysteria UDP 会话 | `xray-transport-hysteria/src/conn.rs:763` | idle 清理 | ✅ 清理任务（`conn.rs:826-860`）+ `close_fn` 摘除 | ✅ `start()` 内 spawn | 正确 |
| xray-xudp 会话 | `xray-xudp/src/extension.rs:85` | TTL 清理 | ✅ `cleanup_expired`（`:122`） | ❌ **零生产消费**（整个 `XudpManager` 只在自身测试/integration 使用） | 死件（MW-7） |
| vless reverse 连接记录 | `xray-proxy-vless/src/outbound/reverse.rs:62` | GC closed | ✅ `gc_closed`（`:115`） | ❌ **零生产消费**（`ReverseMonitor` 仅测试） | 死件（MW-7） |
| vless 预连接池 | `xray-proxy-vless/src/outbound/preconnect.rs:79` | TTL GC | ✅ `gc_expired`（`:203`） | ❌ **零生产消费**（`PreConnectPool` 仅测试 + 一处 e2e 测试） | 死件（MW-7） |

---

## 4. 停机泄漏（停机后仍残留的持有）

| 检查面 | 结论 | 依据 |
|---|---|---|
| 连接级任务 | ✅ 正常：token cancel → `arm_scopes.close_all_reverse()`（逆序）→ 广播父闸 → `ConnScope` 级联取消；arm 内残余由各 arm 监视壳 abort + 超时兜底 | `xray-core/src/instance.rs:363-371`、`xray-frame/src/scope.rs:143-152` |
| 每连接 conn scope | ✅ 正常：`ConnScope::drop` = cancel + close 闸，条目随 scope drop 释放 | `scope.rs:222-230` |
| UDP dispatcher | ✅ `Drop for UdpDispatcher` → `close()` → abort cleanup task | `xray-transport/src/udp/dispatcher.rs:230` |
| mux XUDP 清理任务 | ✅ `Drop for XUDPManager` → `abort` | `xray-mux/src/session.rs:792-798` |
| 全局 dialer 槽 / DialerProxy 钩子 | ✅ 显式摘除（防实例被全局 Arc 钉住） | `instance.rs:352-357` |
| **arm scope 的完成条目** | ⚠ 只在 scope drop 时释放；**运行期永不释放**（= MW-1，不是停机问题而是运行期问题） | 同上 |
| 进程级 compat scope 的 detached 任务 | ⚠ 不随实例关闭而止（`compat::spawn_detached` 语义刻意），生产唯一站点是 shutdown watcher（一次性），可接受 | `xray-core/src/functions.rs:548`（`spawn_scope().spawn_detached`）、`xray-frame/src/compat.rs:185-190`（`compat::spawn` 走 `spawn_tracked`，仅测试使用） |
| 文件句柄 | ✅ E1：6000 连接 churn 后 handles 仅 182→195（+13，Windows TIME_WAIT 量级），无 per-conn fd 泄漏 | §0 实测 |
| `Arc` 环 | 未发现成环：`ArmScope`↔`ConnScope` 用 `watch` + `Weak`（`ConnScope::child_of` 持父 `Arc`，父不持子）；`UdpRelay` timer 用 `Weak<UdpRelay>`（`udp/relay.rs:225`） | 源码 |

---

## 5. 正面清单（已接线且判定正确，供后续不要重开）

`app-proxyman cleanup_inactive`（60s）、`mux XUDPManager::start_cleanup`（60s）+ `IncrementalWorkerPicker` 周期清理（30s）、
`UdpDispatcher`（15s + 4096 上界 + Drop abort）、`dns CacheController`（300s + shrink，`Feature::start` 注单）、
`ss/ss2022` 每包 retain、`tun`/`wireguard` idle sweep、`xhttp SessionMap`（30s reap + 3 处 remove）、
`stats OnlineIpGuard` + `Manager::close` 清 online_maps、`observatory burst cleanup` / `router webhook dedup` / `reverse picker cleanup`、
`xray-buf` TLS + 分片池（有界 + 60s 半衰）、`hysteria UdpSessionManager`（清理 + close_fn 摘除）、
`dispatcher` 的 `ManagedScope`（**reap-before-spawn，正确范本**）。

---

## 6. bd `a5pe6`（h2 下行块池 258 块/流 多流常驻）结论

**结论：不实测成立不了「超预算」，静态上界为「每活跃流 ≤16.5 MB，且随流结束整块归还」；本轮给出 E2 定性与不可实测的明确理由。**

代码事实（`crates/xray-transport-splithttp/src/hub/dl_stream.rs:32-70`）：

- 池是 **per-`DlStream` 私有**（`PoolState { free: Vec<Vec<u8>>, live, peak }`），块大小 `CHUNK=64 KiB`，
  上限 `POOL_MAX = 16 MiB/CHUNK + 2 = 258`（`:33`）；`put` 只在 `free.len() < peak.min(POOL_MAX)` 时留块（`:67`）。
- **容量锚 = 本流观测到的在飞峰值 `peak`**，不是固定 258：`free` 不会超过历史峰值，
  所以「256 条流各自都留满 258 块」只有在**每条流都曾把 258 块同时借给 hyper**（= 16 MB 在下行未消费）时才发生。
- 每流驻留 = `peak × 64 KiB ≤ 16.5 MB`；进程级上界 = **Σ 活跃流**（`DlStream` drop 即整池释放，无跨流共享状态）。

不可实测的理由（非"跳过"）：

1. bd 要求的输入形态是「N 条并发 xhttp 下行流 + 每流深突发（慢读者）」。仓内现有工具
   `tools/loopback_alloc_bench_variants.py`（唯一带 xhttp 拓扑的采集脚本）**只有单 stream 串行下载**，
   没有 N 流并发 + 慢读者注入的旋钮；要造它需要新增一个 xhttp 专用多流 harness（reality/xhttp 配置 +
   N 个限速消费者 + 每流 free 块计数观测——后者是私有字段，只能靠 `XRAY_ALLOC_STATS_SITES` 间接归因），
   超出本轮只读审计范围与预算。
2. 单测能拿到的只有 `frames_carry_all_bytes_in_order_and_blocks_return_to_pool`（`:150`，断言块归还池），
   不覆盖「多流 × 峰值留池」。
3. 本机 `target/release/xray.exe`（2026-10-31 11:00）可用，需再造 harness；给出可执行起点：
   `XRAY_ALLOC_STATS=1 XRAY_ALLOC_STATS_SITES=1 <exe> run -c <xhttp 配置>`，16/64/256 三档并发 + 每流 ≤1 MB/s 限速读者，
   稳态取 `live_bytes` 与 `[xray-alloc-sites]` 中 dl_stream 站点行。

附带定性（可立即用于票面）：**该池不会随"总流数"泄漏**，只会随**同时活跃且曾深突发**的流数放大；
若预算上限是「流数 × 本流 send_buf」，当前实现天然满足（`free ≤ peak ≤ 在飞块数 = send_buf 已占用量`）。

---

## 7. 交叉与边界（避免与 PerfWiring 重复计数）

- **交叉 1**：`ss`/`ss2022` UDP 的 `retain`/`sweep_expired_ss2022_sessions` 是**每包 O(n)** 扫描（`inbound.rs:2297/2432`）——
  内存有界但 CPU 随客户端数线性，属 PerfWiring 面，本报告只登记。
- **交叉 2**：MW-2 的 `len >= 10_000` 惰性全表扫描（`server.rs:88-98`）同属 CPU 灾难，已标注。
- **交叉 3**：`xray-frame/src/pool.rs`（`ManagedBufferPool`/`XrayBufPool`）**生产零消费**——
  `with_pool` 全仓唯一调用点是 `xray-frame/src/assembly.rs:475` 的装配测试；生产 `Instance`/`start_full` 都不注入池。
  含义：①对生产内存**零收益**（本报告按口径如实标注）；②「坑约束 4：缓冲必走 BufferPool」目前**无强制面**（L3 尚未落地）。
  同样 `memgov::{CountingAllocator, LeakGuard}` 零生产消费（仅测试），`MemoryPool`/`BoundedRegistry` 有生产消费。

## 8. 未查/覆盖不足（诚实边界）

- 本机 Windows，**无法实跑**：Linux TPROXY（MW-3）、tun/nftables 面、UDP 大流量场景；这些给 E2。
- `xray-proxy-anytls` / `xray-proxy-socks` / `xray-proxy-http` / `xray-transport-{kcp,grpc,quic,httpupgrade,naive,reality}` 的 per-connection 状态：
  已扫（无长寿命 HashMap 字段），未逐条读状态机内部缓冲（属 PerfWiring 的每包密度面）。
- 未审 CPU 占用、未审每包分配密度（分工明确排除）。
- 未重开已 CLOSED 票（`4y9ns`/`r1693`/`q1r4q`/`9eu4a`/`pv70`）；本报告的 MW-1 与其无重叠（`9eu4a` 是块 churn，`pv70` 是 BBR 账本）。

## 9. 复现资产

- 测量脚本：`reports/audit-2026-10-31-perf-mem-wiring/scripts/mem_wiring_churn.py`（仅测量，无产品代码改动）
- 运行产物：`reports/audit-2026-10-31-perf-mem-wiring/tmp/memwiring/{srv,cli}.{json,log}`
- 脚本判据自检：脚本对每阶段打印 `live_bytes`/RSS/handles，且 `[xray-alloc-stats]` 行解析失败时返回 `None`
  （汇总里显示为缺项而不是 0，避免假绿）。
