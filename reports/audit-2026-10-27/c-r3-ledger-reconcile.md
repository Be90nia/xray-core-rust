# C 面 R3 · 面 5 L3 台账对账（458 → 实测终值）

- 对账对象：per-site / 文件顶 `#[allow(clippy::disallowed_methods | disallowed_macros)]` 台账
- 树态：`073870b5`（HEAD，仅 Cargo.lock 补笔）｜最后一个 `.rs` 提交 = **`23769fa0`**（W7 redline）。本报告全部计数**钉在 23769fa0**；工作树与该 ref 在台账口径上**逐条相同**（568 / 207 / 361），未提交改动（上轮 `vision_conn.rs`）已随 `23769fa0` 入库
- 方法：只读。python 全仓属性扫描（多行属性+Bang 属性+`cfg(test)` 块感知），`git cat-file --batch` 批量取历史文件，`git show`/`git log` 逐波核 diff。**未跑 cargo**（树在动）

VERDICT: PASS

完工状态：DONE_WITH_CONCERNS（对账本身闭合；concerns = 本节 §6 的 4 条台账纯度缺口，均非代码缺陷，落建议）

---

## 0. 一句话结论

**458 不是生产面数，是"全仓 outer per-site 属性数（生产+测试混算）"**；PM 给的 228/29/257 是**单行正则**口径，系统性漏掉 311 条多行属性头。
权威实测（23769fa0）：**568 条 = 生产面 207 + 测试面 361**。
本战役（W3a→W7）在 outer 口径上净清 **-55**（496→441），但同期 L3GapSweep 补登记 **+34**，故相对 ledger-audit 时点净 **-9**（450→441）。
100% 融合度口径下，面 5 的实体（闸规则 + 红线受控入口）已由 xray-frame/工具链承担，剩余 207 条生产面 allow 中 **37 条永久性（热路径+wire）/ 123 条挂 bd 39hko 待迁 / 15 条文件级聚合 / 7 条理由过期 / 6 条未登记 / 19 条其他语义保留**。

---

## 1. 可复跑命令

```bash
# 统计脚本（本票新增，与 ledger-audit §0 同源口径但把口径显式化）
python reports/audit-2026-10-27/tmp/l3-ledger-census.py                      # 工作树
python reports/audit-2026-10-27/tmp/l3-ledger-census.py --ref 23769fa0       # 指定 ref
python reports/audit-2026-10-27/tmp/l3-ledger-census.py --ref 23769fa0 --classify --matrix   # 分类账
python reports/audit-2026-10-27/tmp/l3-ledger-census.py --ref 23769fa0 --list               # 逐站清单

# 逐波归因（对每个 commit 比较其改动文件在 <c>^ 与 <c> 上的属性数）
python reports/audit-2026-10-27/tmp/l3-wave-delta.py b085ff97 7d71a6c6 4ec2f28c b46d6058 bb7b54eb 8a200d7b 554377d7 12a3ff2b 23769fa0
```

落盘取证（本次运行产物）：`reports/audit-2026-10-27/tmp/census-{c0deb2e6,888c6b8f,23769fa0}.txt`。

**口径定义（脚本 docstring 内固化，避免口径再次漂移）**
| 维度 | 规则 |
|---|---|
| 范围 | `crates/**/*.rs`，**排除** `crates/udf-frame`（外部仓工作副本，实测 `allow(clippy::disallowed` 命中 0，排除与否都不影响数字） |
| 单位 | **属性**，不是 lint 名、不是行；一个多行 allow 计 1（同一属性内 methods+macros 也只计 1，全仓实测此类为 0） |
| 多行 | 括号配平解析，`#[allow(\n clippy::disallowed_methods,\n reason=..)]` 计入（这正是 257→568 的差额来源） |
| 形态 | `inner` = `#![...]` 文件顶；`outer` = `#[...]` per-site |
| 面别 | test = ①路径在 `crates/*/{tests,benches,examples}/` ②落在 `#[cfg(test)]` / `#[cfg(any(test,..))]` / `#[cfg(all(test,..))]` 所辖块内（`not(test)` 不算）③`#![cfg_attr(test, ..)]`；其余 = 生产 |

**脚本正确性交叉验证**：用 ledger-audit §1 的 20 条人工抽查样本回打，17 条仍在树上的样本**面别判定 17/17 一致**；另 3 条（`xray-proxy-ss/src/stream.rs`、`xray-common/src/protocol/time.rs`、`xray-transport/src/udp/dispatcher.rs`）在树上**已不存在对应 allow**——正是 W3a/W3b 清掉的站点（与逐波归因表的 -48 互相印证）。

---

## 2. 口径重算（458 到底是什么）

### 2.1 三种口径对照

| 来源 | 数值 | 口径拆解 | 复算 |
|---|---|---|---|
| `docs/architecture/xray-frame-能力收敛方案-2026-10-27.md` §5.2 波次表**第 18 行**、§1 面 5 行、§7.1 面 5 行 | **458**（并外推 "六面迁完可清一批 → ~200"、"458+39≈497"） | 转引 `ledger-audit.md` §0 | — |
| `reports/audit-2026-10-27/ledger-audit.md` §0 | **458**（app 38 / core+common+tls 38 / transport 272 / proxy 49 / other 61） | **outer per-site 属性，多行感知，未分生产/测试**；文件顶 `#![cfg_attr(test,..)]` 明确未计入 | 其扫描窗口内 **450**（见 2.2） |
| PM 手算（本票任务书） | **228 生产 / 29 测试 / 257** | **单行起始正则** `#\[allow\(clippy::disallowed_methods` + **按目录分面**（`src/` 内 test mod 计入生产） | 复现 **231 / 26 / 257**（总和 257 完全一致，面别差 3 = 3 条属性落在 `crates/*/examples|benches` 的归属分歧） |
| **本票实测（口径 Ω）** @23769fa0 | **568 = 生产 207 + 测试 361** | 多行感知 + cfg(test) 感知 + inner/outer 分形态 | 见 §2.3 |

### 2.2 差额解剖（458 侧）

`ledger-audit` 自述"树状态总量"、扫的是工作树，diff 基线 `c31ae9b6..HEAD`。实测其扫描涉及的 5 个提交（`464560d2 / 4330bb1d / 15647696 / ccc4d516 / e301bf86`）**outer 恒为 450**（提交之间无任何 allow 增删），family 分桶中 **`app 38` / `core+common+tls 38` / `proxy 49` 与其报告逐字相同**（`transport` 实测 255 vs 其 272、`other` 实测 70 vs 其 61 —— 两侧和为 450 vs 458，正是同一 8 条差额在家族桶里的体现，说明差的是"少数属性"而非口径本身）→ 口径确认无歧义。

| 项 | 值 | 说明 |
|---|---|---|
| ledger-audit 声称 | 458 | |
| 其窗口提交实测 | **450** | 5 个提交全程恒等 |
| 差额 | **+8** | **不可由任何提交复现** → 来源只能是 ①当时工作树的未提交在飞属性（L3GapSweep 正在落地，最终提交 `888c6b8f` 一次 +34）②同报告 §2 自认的 "app-* 7 单位混用" 汇总口径噪音。**结论：458 是一个脏树读数，方向可用、绝对值不可复算** |

### 2.3 差额解剖（257 侧）

| 项 | 值 | 说明 |
|---|---|---|
| PM 总数 | 257 | 复现一致 |
| 口径 Ω 总数 | **568** | |
| 差额 | **+311** | **全部为多行属性头**：本仓主流写法是 `#[allow(` 换行后接 `clippy::disallowed_methods,` + `reason = "..."`，单行正则的 `#\[allow\(clippy::disallowed_methods` 前缀匹配不到 |
| 面别反转 | PM 228 生产 / 29 测试 → 实测 207 生产 / 361 测试 | PM 按"文件在不在 `tests/` 目录"分面 → `src/` 内 `#[cfg(test)] mod tests` 的 221 条全被算成生产，而真正的生产面只有 207（**含** 15 条文件顶 inner） |

**给后续口径的一句忠告**：用单行正则做 L3 进度 tracker 会**系统性低估测试面 12×**（29 vs 361），且把一个正在下降的生产面读成"228 而且降不动"。口径 Ω 的两条命令已固化在 §1。

### 2.4 形态矩阵（23769fa0）

| 形态 | 生产 | 测试 | 合计 |
|---|---|---|---|
| `#[allow(..)]` per-site（outer） | 192 | 249 | 441 |
| `#![allow(..)]` 文件顶（inner） | 15 | 112 | 127 |
| **合计** | **207** | **361** | **568** |

测试面 361 的构成：`src` 内 `#[cfg(test)] mod tests` 的 per-site **221** + `src` 内文件顶 `#![cfg_attr(test,..)]` **62** + `src` 内 `mod tests` 内 inner **17** + `crates/*/{tests,examples}/` 文件 **61**（其中 24 inner + 28 per-site + 9 其他 inner）。总 inner（生产+测试）= 127。

---

## 3. 逐波清除归因（清除数 = 可复核 diff 证据）

### 3.1 台账时间线（口径 A=outer / 口径 B=全量）

| ref | 事件 | A outer | B 全量 | 生产面 |
|---|---|---|---|---|
| `c0deb2e6` | L3 静态闸落地 + 存量登记 | 108 | 209 | 80 |
| `464560d2`…`4330bb1d`（5 提交） | ledger-audit 扫描窗口 | 450 | 576 | 220 |
| `777b76cc` | 6 proxy crate 补时钟禁令 + 如实登记 | 461 | 587 | 221 |
| `1679a5a7` | W1 框架六件落地 | 462 | 588 | 222 |
| `888c6b8f` | L3GapSweep：dispatcher/kcp/splithttp 补禁令 + 43 站台账化 | **496** | 622 | 252 |
| `b085ff97` | W3a | 488 | 614 | 245 |
| `7d71a6c6` | W3b | 448 | 574 | 215 |
| `bb7b54eb` | W5 | 445 | 571 | 212 |
| `b46d6058` | W4 | 441 | 567 | 207 |
| `554377d7` | R1a | 441 | 568 | 207 |
| `23769fa0` | W7（= HEAD-1） | **441** | **568** | **207** |

两点校正方案稿数字：
- **L3GapSweep 实测 +34**（462→496，outer 与全量都是 +34），方案稿/融合度表写的 **+39 高估 5**（43 站台账化里有一部分折叠进既有属性、一部分进 clippy.toml 禁令而非 allow）。
- `≈497` 外推按 outer 口径成立（496），但**分母口径不同**（496 是 outer，568 是含 inner），文档里两者不可混用。

### 3.2 逐波 Δ（对本波改动文件逐文件比对 `<c>^` vs `<c>`）

| 波 | commit | Δ生产 | Δ测试 | Δ合计 | diff 证据（allow 行）|
|---|---|---|---|---|---|
| W3a | `b085ff97` | −7 | −1 | **−8** | `git show b085ff97`：allow 行 **−8/+0**。`browser.rs −2`、`protocol/time.rs −2（prod −1/test −1）`、`ech_doh.rs −2`、`log/mod.rs −1`、`tls_session_cache.rs −1` |
| W3b | `7d71a6c6` | −30 | −10 | **−40** | allow 行 **−47/+7**，其中 **+7 全是 4 份 `clippy.toml` 的 reason 文本改写**（"一律走 PluginContext::clock" → "ctx 可达走 ctx.clock()，不可达走 xray_frame::compat::clock()"），`.rs` 侧 allow 净 −40。分见 20 个文件（`transport/bridge.rs −4`、`finalmask/xicmp.rs −5`、`proxy-ss 5 文件 −7`、`wireguard 4 文件 −6`…） |
| W2 | `4ec2f28c` | 0 | 0 | **0** | 配置装配面不触台账（diff 内无 allow 行） |
| W4 | `b46d6058` | −5 | +1 | **−4** | allow 行 **−8/+4**：DNS 5 个 nameserver 文件 **−7**；`xray-core/src/inbound.rs` **+3**——`#![allow]` 文件级（73 站聚合）**退役**，改为 3 条逐点（ss2022 墙钟锚 / 监控壳 JoinHandle 外返 / tun serve 公开契约）+ 1 条 `mod tests` inner。**粒度改善但计数上升**，是"台账数 ≠ 违规数"的典型 |
| W5 | `bb7b54eb` | −3 | 0 | **−3** | allow 行 −3/+0：`proxy-vless/inbound/server.rs −2`、`proxy-vmess/inbound/server.rs −1`（tokio 虚拟钟点迁 Budget 后 allow 随之删；其余 12 个"例外"站保留属性） |
| W6 | `8a200d7b` | 0 | 0 | **0** | **无 allow 改动**。原因成立：热路径站点原本就没有 `#[allow]`（`disallowed_macros` 对 proc-macro allow 无效，见 `0791bfb8` 事实），40 站的"清账"体现为**裸宏消失**而不是 allow 减少。**W6 对本台账的贡献 = 0，不要计入减项** |
| R1a | `554377d7` | 0 | +1 | **+1** | 新增 `crates/xray-app-dispatcher/examples/ohm_lookup_ab.rs:1` 的 `#![allow(..)]`（A/B 计时锚点，`examples/` → 测试面） |
| R2 | `12a3ff2b` | 0 | 0 | **0** | kcp `output.rs` 换 udf `std_ext::retry`，无 allow 行 |
| W7 | `23769fa0` | 0 | 0 | **0** | `vision_conn.rs` 裸 `tracing::event!` → `redline::event`，**文件级 allow 未删**（见 §6 finding 4） |
| **合计** | | **−45** | **−9** | **−54** | 与 outer −55 / inner +1 完全吻合 |

**净账**：相对 ledger-audit 时点（450）→ 441 = **−9**；相对 L3GapSweep 峰值（496）→ 441 = **−55**。两个说法都对，但引用时必须带起点，否则会出现"清了 55 条"与"只少 9 条"并存的自相矛盾。

---

## 4. 分类账：生产面 207 条按"禁的是什么"分类

### 4.1 主类别（按属性所辖 item 内首个禁用项命中；39 条 item 同时命中 ≥2 类，标注为多义）

| 类别 | 数量 | 占比 | 代表性站点 |
|---|---|---|---|
| `tokio::spawn`（含 `tokio::task::spawn`） | **128** | 61.8% | `xray-app-dispatcher/src/default.rs:878`、`xray-app-reverse/src/relay.rs:170`、`xray-mux/src/client.rs:315`、`xray-transport-hysteria/src/conn.rs:592` |
| `std::time::Instant::now` | **46** | 22.2% | `xray-app-dispatcher/src/default.rs:651`（IO 实耗测量面）、`xray-cli/src/commands/remote_config.rs:94/147/342`（CLI 冷路径）、`xray-stress/src/{main.rs:242,topology.rs:52}` |
| 文件级聚合（`#![allow]`，整文件多站点） | **15** | 7.2% | `xray-core/src/functions.rs:3`（46 spawn）/`outbound.rs:3`（29 spawn + 2 Instant）/`xray-transport-grpc/src/transport.rs:6`（23 spawn）/`xray-cli` 8 文件（print 宏） |
| `std::time::SystemTime::now` | **6** | 2.9% | `xray-proxy-vmess/src/aead/mod.rs:591`（AEAD 时间戳窗）、`xray-app-metrics/src/debug.rs:27`（进程启动锚点） |
| `tokio::time::Instant::now` | **6** | 2.9% | `xray-proxy-tuic/src/server.rs:561/629`（`Sleep::reset` 只收 tokio Instant）、`xray-transport-kcp/src/connection.rs:656` |
| `to_vec` 扁平化（`slice::to_vec`/`MultiBuffer::to_vec`） | **4** | 1.9% | `xray-app-dispatcher/src/{default.rs:1652,sniffer.rs:770}`、`xray-transport-splithttp/src/h3_client.rs:318`（ALPN 冷路径）、`xray-transport-websocket/src/client.rs:317`（首写触发拨号 joining） |
| `tracing` 宏 | **1** | 0.5% | `xray-core/src/grpc_server.rs:58`（常驻 gRPC server，item 内同时有 spawn+tracing） |
| `std::thread::spawn` | **1** | 0.5% | `xray-transport/src/finalmask/xicmp_sock.rs:384`（raw ICMP 阻塞 recv 循环，确需 OS 线程） |
| **合计** | **207** | 100% | |

> 口径提醒：`disallowed_macros` 对 proc-macro（`tracing::*!`/`println!`）的 `#[allow]` **不生效**（`0791bfb8` 实测），所以"tracing 宏类 allow 只有 1 条"**不代表宏禁令没站点**——宏面的合规靠迁移（批 1/2a/2b + W6 共 ~271 站）保障，不靠 allow。引用时勿把 1 条读成"违规 1 处"。

### 4.2 论证分桶（是否永久性）

按 reason 文本的论证类型分桶（优先级 A>B>C>D>E>F>G；**分桶重叠**：135 条 reason 同时写"不可达"与"bd 39hko"，本表按最强论证归类）：

| 桶 | 数量 | 主类别构成 | 判定 | 代表 |
|---|---|---|---|---|
| **A 文件级聚合** | **15** | 文件级 15 | **12 条为 print/macros 类**（CLI 8 / build.rs 2 / vision_conn 1 / stress 1）→ **永久**（CLI 与构建脚本本就该打印，不需要 log facade）；**3 条 `disallowed_methods`**（core functions.rs / outbound.rs / grpc transport.rs）→ **待迁**（bd 39hko，>20 处/文件分层规则） | `xray-core/src/outbound.rs:3` |
| **B 数据面热路径豁免** | **34** | spawn 29 / std Instant 4 / tokio Instant 1 | **永久**（坑约束⑫：FxScope 记账会落每 chunk 开销；vision/bridge 双 revert 史实）。分布：`transport-splithttp 27`、`transport 4`、`mux 1`、`tuic 1`、`anytls 1` | `xray-mux/src/client.rs:315`（carrier 读循环泵） |
| **C 协议 wire 语义** | **3** | SystemTime 3 | **永久**（Go 兼容：VMess AEAD 时间戳窗 / VLESS ticket 过期换算，纯 codec 无 ctx 注入面） | `xray-proxy-vmess/src/aead/mod.rs:591` |
| **D 待迁（bd 39hko 族）** | **123** | spawn 84 / std Instant 31 / SystemTime 2 / tokio Instant 4 / tracing 1 / to_vec 1 | **可转换，本轮未做**。按 crate：`transport 22`、`hysteria 19`、`stress 14`、`mux 10`、`websocket 8`、`core 7`、`naive 6`、`tun 6`、`quic 5`、`cli 5`、`httpupgrade 4`、`kcp 3`、`vless 3`… | `xray-transport-hysteria/src/conn.rs:592` |
| **E 结构性不可达** | **7** | std Instant 7 | **理由已部分过期**（见 finding 3）：`xray_frame::compat::clock()` 已在 W3b 落地，"ctx 不可达"不再是不可迁理由。位置：`proxy-vless 5`（`encryption/mod.rs:435/636`、`outbound/preconnect.rs:36`…）、`proxy-vmess 1`、`proxy-tuic 1` | `xray-proxy-tuic/src/pool.rs:191` |
| **F 其他语义保留** | **19** | spawn 13 / Instant 3 / SystemTime 1 / tokio Instant 1 / thread 1 | **混合**：进程启动锚点、纯展示格式化、签名锁定于测试调用方、ICMP OS 线程、常驻监控壳 → 逐点已给论证，**多数永久、少数随插件化收口** | `xray-transport/src/finalmask/xicmp_sock.rs:384` |
| **G 未登记（无 `reason=`）** | **6** | to_vec 3 / Instant 1 / spawn 2 | **应修**（台账纯度）：`app-dispatcher/{default.rs:1652,sniffer.rs:770}`、`common/src/antireplay/mod.rs:43`、`common/src/log/general_logger.rs:150`、`common/src/testing/mod.rs:25`、`transport-splithttp/src/h3_client.rs:318`。其中 `testing/mod.rs:25` 是 L3 唯一测试面裸 spawn 出口（bd shexg 决策，有模块文档） | — |
| **合计** | **207** | | **永久性合计 = A(12)+B(34)+C(3)+F(≈14) ≈ 63；待迁 = A(3)+D(123)+E(7) = 133；未登记 6；其余 5 属插件化收口前的签名锁定** | |

reason 覆盖率：**188/207 带 `reason=`**（90.8%）；无 reason 的 19 条里 13 条是文件顶 inner（12 条 print/macros 类 + 1 条 grpc），6 条是 per-site plain allow。

**关键量化**：**135 条 reason 明写 `bd 39hko`**——这是最大的一块可转换池（65%），它把"清不掉"变成一个**有票可查的存量**，而不是免责声明。

---

## 5. 100% 口径终账（方案 §10.1）

### 5.1 口径说明（重申）

100% = **功能面全部由 udf / xray-frame 承担**（§0.1 四态口径 (A+B)/14），**不是** "allow 条数归零"。面 5 的功能 = "静态闸规则 + 豁免台账 + 红线受控入口"，其规则本体在框架侧（xray-frame `redline.rs` + `compat.rs`）与工具链侧（per-crate `clippy.toml`），**分布型配置残余与测试面豁免按 §10.1 计入分子**。

### 5.2 当前状态

| 面 | 前 | 现 | 依据（可 grep） |
|---|---|---|---|
| 1 插件契约/装配门 | B | **B** | `xray-frame/src/{plugin,registry,assembly}.rs`；`core/src/arm_registry.rs` 36 构造器查表 |
| 2 生命周期/停机 | A | **A** | udf `ShutdownCoordinator`；`core/src/instance.rs` 消费 |
| 3 L2 能力供给 | B（D 缺口） | **B（D=0）** | `xray-frame/src/context.rs`；compat 面补 pool/ids/audit 消费点 |
| 4 L4 契约夹具 | B | **B** | `contract_assert.rs` + 16 crate `tests/plugin_contract.rs`（真实实例 3/16 残，另波） |
| **5 L3 闸与台账** | C | **机制面已成 B/A 混合** | 闸规则：56 份 `clippy.toml`（工具链分布）；红线受控入口：`xray-frame/src/redline.rs` 已落（`23769fa0`）；台账：本报告 |
| 6 配置装配 | C | **B** | `4ec2f28c`：`xray-conf/src/serial.rs` 切 `xray-frame::XrayConfigLayers`（影子三路 0 差异） |
| 7 时钟与预算 | C | **B** | `b085ff97`/`7d71a6c6`（compat::clock）+ `bb7b54eb`（Budget，34 站 22 迁 12 例外） |
| 8 任务托管 | C | **B（部分）** | `b46d6058`（inbound/mux/DNS 归 scope）；残 `outbound.rs 29 / functions.rs 46 / transport 29`（另波） |
| 9 日志分发与掩码 | A | **A（质量↑）** | udf `logx` 三通道 + `8a200d7b` HotLog（40 热路径站）；proxy 16 crate 裸 tracing 清零 |
| 10 缓冲池化 | B | **B** | `xray-frame/src/pool.rs` + `17d23baa` |
| 11 观测与审计 | B | **B** | `xray-frame/src/{observe,audit}.rs`（audit 底座 = udf `memgov::BoundedRegistry`） |
| **12 注册表族** | C | **A** | 双生产表都已换 udf 件：`fe8d5481` `InboundRuntime.slots: BoundedRegistry<String, InboundSlot>`（`core/src/inbound.rs:3104`）+ `554377d7` `HandlerRegistry = BoundedRegistry<String, Arc<dyn DispatchHandler>>`（`app-dispatcher/src/default.rs:2043`）；`Eviction::Reject` fail-closed + 升序确定序 iter；A/B 实测 87ns vs 26ns（`c-r1a-registry-bounded.md`） |
| **14 通用散件** | C | **A（含 1 条显式豁免）** | `18ee9656`（fakedns LRU + wireguard `TtlDnsCache` → udf）、`12a3ff2b`（kcp `RetryableWriter` → `std_ext::retry`）、udf `TtlCache/LruCache` 已接；DNS `cache_controller` = **ADR-1 判据③显式豁免**（PM 2026-10-27 裁定：DNS 方向件 + Go 语义逐字对齐 + 热路径并发）；uuid = 勘误留主仓（`uuid` crate 是生态标准件，换 v7 = 可预测凭据回归）；geo weak cache 树内不存在 |
| 13 查表分发 | B | **B** | `xray-frame/src/dispatch.rs` + `arm_registry.rs` |

### 5.3 结论

- **14/14 面均有框架侧承接**：A=3（面 2/9/12）、B=9（1/3/4/6/7/8/10/11/13）、C=2（面 5 的分布型配置残余、面 14 的 1 条显式豁免）→ 按 §10.1 口径 **C 面两项都已给出"机制性/显式豁免"定性并计入分子 → 100%**。
- **R 面三件**：R1a ✅（`554377d7` + `fe8d5481`）、R2 ✅ 唯一真契合件（`12a3ff2b`，其余 3 项按勘误/豁免处置）、**R1b 在飞**（`CR1bRuntime`，不影响本账）、R3 = 本报告 ✅。
- **台账终值**：**568 总（生产 207 / 测试 361）**；相对本战役起点（outer 496）净 −55，相对 ledger-audit 时点（450）净 −9——**两个数都对，引用必须带起点**。

---

## 6. 残余清单（每条：为什么不能 / 不需要清零）

| # | 残余 | 量 | 为什么不清零 | 归属 |
|---|---|---|---|---|
| 1 | per-crate `clippy.toml`（56 份含根） | 56 文件 | clippy 配置**按 crate 生效**，根 `clippy.toml` 不是闸（P0-6 探针实证）；框架件无法代管工具链 | **机制性不可归零**（§10.1 已裁定） |
| 2 | 测试面 allow | **361** | 测试计时/并发夹具**不得改语义**；`tokio::test` 自有 runtime，FxScope 化无生命周期收益。其中 112 条是 inner 白名单（86 条 `#![cfg_attr(test,..)]` + 26 条 `mod tests` 内 inner），249 条是测试模块内 per-site | **不需要清零**（已机制化） |
| 3 | 生产面热路径豁免 | **34** | 坑约束⑫ + vision/bridge 双 revert 史实：per-chunk 记账落数据面开销 | **永久** |
| 4 | 生产面协议 wire 语义 | **3** | Go 兼容时间戳（VMess AEAD / VLESS ticket），纯 codec 无 ctx 注入面 | **永久** |
| 5 | 生产面待迁（bd 39hko） | **123** | FxScope/Clock 接线是独立工程，非本轮面；已 100% 逐点挂票 + reason | **可转换，票面在飞** |
| 6 | 文件级聚合（>20 处/文件分层规则） | **15**（其中 3 条 methods 类） | 12 条 print/macros 类为 CLI/构建脚本固有；3 条 methods 类（core functions/outbound + grpc transport，共 98 站点）逐点登记"属性海不经济"，迁移后应改回逐点 | **待迁（39hko）** |
| 7 | DNS `cache_controller` | 1 件 | ADR-1 判据③显式豁免：方向件 + Go 语义 + 热路径并发（`&mut self` 全局锁 vs LRU 容量界语义冲突） | **显式豁免** |
| 8 | smoltcp 栈时钟 / `transport-tcp/register.rs` / `bridge.rs` P7LM | 28 站 + 2 处 | 第三方契约 / 红线文件 / 性能归因通道（36% 税伪影史实） | **留主仓（已举证）** |

### 6.1 本票新发现（建议级，未修 — 本票只读）

| # | 严重度 | 位置 | 问题 | 修法方向 |
|---|---|---|---|---|
| 1 | 建议 | 方案稿 §5.2 行 18 / §1 面 5 / §7.1 面 5 / `fusion-measure.md` §2 面 5 | 458、≈200、≈497 三个数全部过期且口径混用（outer vs 全量） | 改为「台账终值 568（生产 207 / 测试 361）；见 `reports/audit-2026-10-27/c-r3-ledger-reconcile.md`」 |
| 2 | 建议 | `xray-proxy-tuic/src/pool.rs:191`、`xray-proxy-vless/src/encryption/mod.rs:435/636`、`outbound/preconnect.rs:36`、`xray-proxy-vmess`×1（共 7 条） | reason 仍写「结构性不可达」，但 `xray_frame::compat::clock()` 已于 W3b 落地 → **理由过期**，读者会误判为不可迁 | 改挂 `compat::clock()`，或把 reason 改写为「待 compat 接线（39hko）」 |
| 3 | 建议 | 6 条 per-site plain allow（见 §4.2 G 桶） | 无 `reason=`（ledger-audit 记的是 8 处，现 6 处 + 13 条 inner 无 reason） | 补 reason 或改 `cfg_attr(test,..)` |
| 4 | 建议 | `xray-proxy-vless/src/encryption/vision_conn.rs:1` | 文件级 `#![allow(disallowed_macros, print_stdout, print_stderr)]` 仍在；实测该文件**裸 tracing 宏 0（W7 已换 `redline::event`）、11 处 `eprintln!` 全部落在 `#[cfg(test)]`（737–2673 行）** → 该 allow 已无生产用途，却把整个文件（含生产代码）罩住 | 改 `#![cfg_attr(test, allow(..))]`，与 6 个 proxy crate 惯例一致；W7 面 5「站点不再需要 allow」由此才真正兑现 |
| 5 | 吹毛 | `xray-transport-grpc/src/transport.rs:6` | 文件头注释写「21 处裸 spawn（生产 6 + 测试 15）」，实测 **23 处 `tokio::spawn`** | 注释随码更正（属文件级登记的必要说明，不是 allow 问题） |
| 6 | 吹毛 | `xray-buf/clippy.toml` | 仍只有 `to_vec` 两条，无 spawn/时钟禁令（ledger-audit §2-3 的 4 crate 里剩它） | crate 内当前无 spawn，接入即补 |
| 7 | 吹毛 | 方案稿「L3GapSweep +39」 | 实测 +34（outer 与全量同额） | 并入 finding 1 一并更正 |

---

## 7. 未覆盖范围

- **未跑 cargo**（clippy/test 零执行）："禁令是否真 fire" 仍依赖 CI 门；本报告只给静态写法正确性 + 属性存在性两级证据。
- **面别判定是结构启发式**：`#[cfg(test)]` 块配平 + `tests/` 目录；`#[cfg(not(test))]` 已排除，`cfg(feature="test-utils")` 类不误判（已收紧词界），但 `#[cfg_attr(test, ..)]` 之外的非常规门控（如 `#[cfg(miri)]` 内 allow）按生产计。
- **分类账的"主类别"是单标签近似**：39 条 item 同时命中 ≥2 类（如 `grpc_server.rs:58` 同时有 spawn + tracing），单标签取"首个命中"，跨类求和不可当"站点数"读。
- **`crates/udf-frame`**（外部仓工作副本）按仓外资产处理；实测其 104 个 `.rs` 内 `allow(clippy::disallowed)` 命中 0，不影响结论。
- **R1b 在飞**（`CR1bRuntime` 改 `core/src/inbound.rs`）：本账钉在 `23769fa0`，R1b 落地的当轮需增量复算（跑 §1 第一条命令即可）。
- 历史 ref 的 `.rs` 内容经 `git cat-file --batch` 读取，未做行尾/编码归一（`.rs` 全 UTF-8，`errors="replace"` 兜底；不含 `\r` 干扰属性匹配的实测样例）。

---

## 8. 五轴自评

| 轴 | 分 | 依据 |
|---|---|---|
| 正确性 | 5 | 458 的 8 条差额**如实标为不可复现**而非强行凑平；三口径各自给了复算路径；20 样本交叉验证 17/17 一致、3 条落空各有原因 |
| 完备性 | 4 | 四段必做分析全交付；扣分项：单标签分类对 39 条多义站点是近似（已在未覆盖范围声明） |
| 可复现性 | 5 | 两条命令 + 三个落盘快照；口径写进脚本 docstring；两个口径（outer/全量）在脚本输出里同时打印，避免再次混用 |
| 诚实性 | 5 | 明确否认"清了 55 条"可单独引用；明确 458 是脏树读数；明确 W6 对本台账贡献 = 0（不与方案稿叙事对齐） |
| 边界遵守 | 5 | 零代码/配置/测试改动，零 cargo，零 commit；只写 `reports/audit-2026-10-27/` 下本报告与 `tmp/` 脚本 |
