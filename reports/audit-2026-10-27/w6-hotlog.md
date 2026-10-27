# W6 · 面 4 热路径日志迁移报告（xray-transport / naive / hysteria / splithttp）

> 代理：W6V3 · 日期：2026-10-27 · 波次：W6（能力收敛方案 §5.2）
> 树态：HEAD 7d71a6c6（W3b 已入库）+ W4/W5 并行增量在树 + 本波 20 文件
> 前任：W6R2（中途停工，其转录 `history://W6R2` 只读参考，本报告全部结论自行 grep/实跑复核）

## 0. VERDICT

**DONE_WITH_CONCERNS**

迁移本体与全部代码级验收门全绿：站点对账 **40:40 精确 1:1**、四 crate test **1041 passed / 0 failed**、
`cargo clippy --workspace --all-targets -- -D warnings` **0 error**、interop **12/12 PASS**、
性能门在**单变量对照**下无回归（吞吐 -0.72%/+0.10%，alloc/MB +0.27%/+1.00%，均在窗口噪声内）。

**两个必须上报的关切**（不影响本波交付，但需 PM 决策）：
1. **本机 154-167 MB/s 硬锚当前不可达**（与本波无关，见 §3.3 归因取证）。
2. **热路径门面的单次调用开销高于原 `tracing::` 宏**（124 ns vs 16 ns，见 §3.4）。
   缓解事实：40 处站点**全部位于错误/稀有/连接级路径**，无一位于无条件每包路径（§3.5 逐点分类）。

---

## 1. 站点迁移表

### 1.1 迁移明细（HEAD 行号 → 处置）

| crate | 文件 | HEAD 站点（行号） | 级别 | 处置 |
|---|---|---|---|---|
| xray-transport | bridge.rs | :70 `CopyRawConn splice` | DEBUG | ✅ 迁 `hot_log!(DEBUG, ...)`（每连接级） |
| xray-transport | bridge.rs | :420/:438/:476/:494/:499/:513/:519/:522/:525 | WARN | ⚠️ **例外保留 ×9**（见 1.2） |
| xray-transport | finalmask/mod.rs | :554/:573/:661/:664 | DEBUG | ✅ 迁 ×4 |
| xray-transport | finalmask/xdns/client.rs | :327/:363/:368/:383 | 2 ERROR + 2 DEBUG | ✅ 迁 ×4 |
| xray-transport | finalmask/xdns/server.rs | :332/:420 | ERROR | ✅ 迁 ×2 |
| xray-transport | finalmask/xmc/conn.rs | :677/:706 | DEBUG | ✅ 迁 ×2 |
| xray-transport | udp/hub.rs | :268/:311/:452（DEBUG）+ :273/:315/:419/:460（WARN） | — | ✅ 迁 ×7 |
| xray-transport-hysteria | gecko_socket.rs | :172/:204 | DEBUG | ✅ 迁 ×2 |
| xray-transport-splithttp | upload_queue.rs | :221 | TRACE | ✅ 迁 ×1 |
| xray-transport-splithttp | batched_upload.rs | :68/:84 | DEBUG | ✅ 迁 ×2 |
| xray-transport-splithttp | client.rs | :681/:808/:812 | DEBUG | ✅ 迁 ×3 |
| xray-transport-splithttp | dialer.rs | :94/:107/:321/:383/:396/:506/:593/:623 | DEBUG | ✅ 迁 ×8 |
| xray-transport-splithttp | h3_client.rs | :371/:401/:761/:766 | DEBUG | ✅ 迁 ×4 |
| **迁移合计** | | **40** | | transport 20 + hysteria 2 + splithttp 18 |
| xray-transport-naive | inbound.rs | :471/:479 | DEBUG | ⚠️ **例外保留 ×2**（见 1.2） |
| xray-transport-hysteria | quinn_adapter.rs | （豁免头登记，文件内**零裸 tracing 站点**） | — | ⚠️ **例外保留 ×0**（见 1.2） |

### 1.2 例外逐处登记（allow + 理由）

**E1 · bridge.rs p7lm 调查通道 ×9**（规格背书：能力收敛方案 §2 面 4「不可迁残余 2」）
- 形态：`tracing::warn!(target: "p7lm", ...)` 9 处，**一字未动**（实测 `git show HEAD` 与当前文件逐字节相同）。
- 理由：`XRAY_P7LM_TRACE` 是**调查通道**非日志通道——F2F3 终判实证其 trace 税曾把优化实测毒化成伪影（约 36% 吞吐）。
  改写为 HotLog 会污染 F2F3 归因基线。
- 前任报告写「10 处」有误（实测 **9 处**）；我方 bridge.rs 注释已同步更正为 9。
- 双方（W5）确认不碰这些行。

**E2 · naive/inbound.rs ×2**（实测事实，与前任报告结论一致）
- 实测：两站点位于 `#[cfg(test)] mod tests`（`#[cfg(test)]` 在 :390，站点在 :473/:481）→ **非生产热路径**，
  迁移零收益且会给测试编译单元引入生产门面依赖。
- 处置：**不迁**，豁免头改写为实测事实（纠正前任「naive 2 处生产豁免」的口径错误）。

**E3 · hysteria/quinn_adapter.rs ×0**（实测事实，与前任报告结论一致）
- 实测：`git show d8300f1a^` 有 10 处裸 `tracing::`，`git show d8300f1a` 起已 **0 处裸 tracing:: / 10 处 `crate::LOG`**。
  即 T3.2a（d8300f1a）已把该文件 10 处全部收编到慢路径 `LogFacade`，豁免头的「2 处」登记在 T3.2a 当时即已不成立。
- 处置：**不迁**，豁免头改写为实测事实。

### 1.3 对账复核（fmt 后工作树实跑）

```
1. 站点对账: diff 删除侧 40 == 新增侧 hot_log 40  -> 1:1 EXACT
2. 豁免标记残留: ZERO (全仓已清)
5. 我面 diff: 923 行 / 20 文件 / +227 -112
```
逐文件删除/新增配平（`git diff` hunk 级统计）：finalmask/mod 4:4、xdns/client 4:4、xdns/server 2:2、
xmc/conn 2:2、udp/hub 7:7、bridge 1:1、gecko_socket 2:2、upload_queue 1:1、batched_upload 2:2、
splithttp/client 3:3、dialer 8:8、h3_client 4:4 —— **12 文件全部 1:1，无一处多/少**。

### 1.4 消息文本逐字核对（规格「消息文本与触发条件逐字不变」）

```
message-text fidelity: 40 non-p7lm HEAD sites checked -> ALL PRESERVED VERBATIM
p7lm sites: HEAD=9 current=9  byte-identical=True
```
字段名全部保留并按仓内既有风格拼入 message 前缀（`dropped=`/`error=`/`len=`/`seq=`/`status=`/`mode=`/
`base_uri=`/`addr=`/`server_name=`/`zero_rtt_accepted=`/`packet_seq=`/`next_seq=`/`posts=`/`chunk_len=`）。

### 1.5 target 变更登记（规格要求）

| 站点族 | 迁移前 target | 迁移后 target |
|---|---|---|
| transport 主 crate 站点 | 调用点 module path（tracing 默认） | `xray_frame::transport` |
| hysteria gecko 站点 | module path | `xray_frame::transport::hysteria` |
| splithttp 全部站点（含 h3 7 处） | `"splithttp"` / `"splithttp-h3"`（自造） | `xray_frame::transport::splithttp`（统一单门面；h3 语义由消息文本自述承载） |

**外部影响**：splithttp 原自造 target 消失 → **外部日志订阅者的过滤串需相应调整**
（`RUST_LOG=splithttp=debug` → `RUST_LOG=xray_frame::transport::splithttp=debug`）。
Go 对齐侧不受影响。已登记供 PM 汇总。

---

## 2. 半成品核对结论（前任 W6R2 遗留）

### 2.1 前任 stage 与转录核对

W6R2 死于「Checking xicmp and system_listener exclusion rationale」——即在核对**哪些站点该排除**。
本任自行 grep 复核（不采信其转录结论），得到确定答案：

| 前任疑问 | 本任复核结论 | 依据 |
|---|---|---|
| xicmp / xicmp_sock 该排除吗？ | **不是本面文件**（我的文件面是 `finalmask/mod.rs` + `finalmask/{realm/conn,xdns/*,xmc/conn}.rs`，不含 `finalmask/xicmp*.rs`）；且**不属规格面 4 的 37 处清单**（T3.2a 豁免清单 12 文件不含 xicmp） | `docs/architecture/xray-frame-能力收敛方案-2026-10-27.md` §2 面 4 步 2；`reports/framework-audit-2026-10-24/T3.2a-log-transport-cli.md` §3 清单 |
| system_listener 该排除吗？ | 同上，**不在我的文件面**、**不在 37 处清单** | 同上 |

### 2.2 本面外残余站点（事实登记，**不擅自扩面**）

HEAD 我面 4 crate 裸日志站点共 **59** = 迁移 40 + 例外 11（p7lm 9 + naive 2）+ **面外 8**：

| 文件 | 处数 | 性质 | 处置 |
|---|---|---|---|
| xray-transport/src/finalmask/xicmp.rs | 1 | ICMP raw socket recv 泵错误记录（每包路径，但属 xicmp 传输族） | **面外，不迁** |
| xray-transport/src/finalmask/xicmp_sock.rs | 3 | 2× 每帧畸形 IPv4 头丢弃 + 1× IPv6 降级（连接级） | **面外，不迁** |
| xray-transport/src/system_listener.rs | 4 | UDS peer 凭据 / 权限（连接+监听级） | **面外，不迁** |

**这 8 处的来源已查明**：全部由 commit `336d8430`（审计 P1×3/P2×8 收口：xicmp 白名单与 GC、UPnP 校验、UDS 权限）
引入，**该 commit 晚于 T3.2a（d8300f1a）**，故 T3.2a 的 37 处豁免清单成文时它们还不存在。
→ **不是「漏迁」，是清单成文后的新增站点**；且其归属传输族（xicmp / UDS）与本面文件面不同。
**建议 PM 归入后续波次**（与「xicmp 白名单」审计域同源），本波不擅自扩面（避免与 W5 的 finalmask 邻域改动相撞）。

### 2.3 前任已落码部分的核对结论

| 项 | 结论 | 依据 |
|---|---|---|
| 迁移本体 40 站点 | **正确**，1:1 精确、消息文本逐字保留、字段名全保留 | §1.3 / §1.4 实跑 |
| 3 份 `hot_log!` 宏 + 3 个 `HOT_LOG` static | **正确**，3 份宏**逐字相同**（`transport == hysteria == splithttp` 实测 True） | §4 code-simplifier 自检 |
| naive / quinn_adapter 豁免头纠偏 | **正确**（本任独立复核：`#[cfg(test)]` :390 / T3.2a 已收编 10 处），且实测依据成立 | §1.2 E2/E3 |
| bridge.rs 豁免头「p7lm 10 处」 | **有误**（实测 9 处）→ 本任已更正代码注释 | §1.2 E1 |
| 前任报告 §5/§6 未填项（B 态数字 / interop / workspace clippy） | 本任全部补跑并填入 | §3 / §4 |
| 前任报告称 A 态两轮（A-1/A-2） | **不可用作单变量对照**：A 态二进制（13:32 构建）早于 W5 的 transport Budget 落码（13:41-13:44）→ A 缺 W5 增量、B 含 → 混杂。本任重做真单变量 A'（§3.1） | `git show HEAD` + 文件 mtime 分桶实测（16:01→16:28 之间**零文件改动**） |

---

## 3. A/B 性能门（硬门 · 单变量对照）

### 3.1 A' 构造方法（真单变量）

现成 A 态二进制不可用（§2.3）。本任**自行构造真单变量 A'**：

- **A' = 当前树仅回退我的 37 个 hot_log 代码 hunk**（`git apply -R`，patch 经 `git apply --check -R` 验证）；
  W5 的 Budget 改动**全部保留**（A' 态实测确认：bridge.rs 6 处 `Budget::tokio().deadline` +
  realm/conn.rs + xmc/conn.rs + sockopt + system_dialer 全部在位）。
- 注释行不参与回退（A'/B 注释一致，不影响单变量性）；bridge.rs 混合 hunk（`@@ -16,13 +16,16 @@`，
  含 W5 的 `use xray_frame::deadline::Budget;` + 我的豁免头改写）**整 hunk 不动**。
- 二进制取证（字符串计数，直接证明迁移态）：

```
A-prime : xray_frame::transport=0  xray_frame_hot_emit=0  splithttp-h3=1   ← 迁移前
B       : xray_frame::transport=3  xray_frame_hot_emit=1  splithttp-h3=0   ← 迁移后
```

- **树漂移检查**：A' 构建（16:28）与 B 构建（16:01）之间，**全树零文件改动**（mtime 分桶实测：
  21 个文件 <16:01，15 个 >16:28 且全部是我自己的复原操作；中间桶为空）→ 单变量成立。

### 3.2 A/B 同窗交错测量（3 窗口 × 各 3 轮，alloc-stats 开）

两臂均用 `/d/tmp/enc8x/` 下的**冻结副本**（不碰 target-w4 共享输出路径——首轮 B 窗口曾误跑 A′ 二进制，整轮作废后重跑）。

| 窗口 | A'（迁移前）MB/s | B（迁移后）MB/s |
|---|---|---|
| 1 | 121.4 / 127.2 / **133.5** | 120.7 / 131.9 / **132.3** |
| 2 | 122.8 / 131.5 / **132.9** | 120.3 / 132.6 / **132.4** |
| 3 | 124.3 / 123.7 / 121.9 | 111.7 / 126.5 / **132.0** |

| 指标 | A' | B | Δ |
|---|---|---|---|
| 窗口 best 最大值 | **133.5** | **132.6** | -0.9 MB/s（**-0.72%**） |
| 窗口 best 中位数 | 132.9 | 132.3 | -0.6 MB/s（**-0.42%**） |
| 9 轮全样本均值 | 126.6 | 126.7 | **+0.1 MB/s（+0.10%）** |
| alloc/MB srv 均值 | 1,726,534 B/MiB | 1,731,184 B/MiB | **+0.27%** |
| alloc/MB cli 均值 | 2,087,025 B/MiB | 2,107,939 B/MiB | **+1.00%** |
| alloc/MB 峰值（MiB/MiB 口径） | srv 1.679 / cli 2.081 | srv 1.681 / cli 2.080 | 均 **< 2.22 硬锚** |
| bench floor(120) | 3/3 窗口 exit=0 | 3/3 窗口 exit=0 | **PASS** |

**判定**：吞吐 Δ ∈ [-0.72%, +0.10%]、alloc/MB Δ ≤ +1.00%，**全部远小于 baseline.md 记载的本机窗口摆动 16%**
→ **迁移无性能回归**。

### 3.3 154-167 MB/s 硬锚归因（与本波无关，取证在案）

任务书硬锚「吞吐不降于 154-167 MB/s」在**当前树上不可达**，且**与本波迁移无关**——实测取证：

| 二进制 | 落点 |
|---|---|
| **2026-10-11 基线期二进制**（`xray-clean-4a5ea63.exe`，即 baseline.md 立锚的 master 4a5ea630） | 113.2 / 127.1 / **128.6**；120.7 / 130.3 / **131.1** |
| 本波 A'（迁移前，当前树） | **133.5** |
| 本波 B（迁移后，当前树） | **132.6** |

→ **立锚期的基线二进制在今天同机同拓扑也只有 128.6-131.1 MB/s**，与本波 A'/B 同带。
故 154-167 是 2026-10-11 的历史落点，**当前本机窗口整体下移约 20%**（与 baseline.md 自述的
「单轮 147→173 摆动 16%」一致，且前任 W6R2 报告已记录同一现象：A-2 = 131.7）。
**结论：硬锚应按「相对 A' 不降」判定（已满足，Δ=-0.72%/+0.10%）；绝对锚 154-167 在当前树上 A' 与 B 同样不达标，非本波引入。**

### 3.4 单次调用开销实测（诚实登记关切）

临时探针（已删除，`crates/xray-frame/tests/w6_tmp_cost_probe.rs`，xray-frame 树面已复原无残留）实测：

```
W6PROBE DISABLED  DEBUG: HotLog=149.8ns  tracing=14.7ns   ratio=10.2x
W6PROBE DISABLED  WARN : HotLog=5027.7ns tracing=4923.0ns  ratio=1.0x
W6PROBE ENABLED   DEBUG: HotLog=165.0ns  tracing=28.6ns    ratio=5.8x
W6PROBE (b) HotLog::enabled (full)    = 123.9 ns
W6PROBE (c) format_args! construction = 9.9 ns
W6PROBE (d) tracing::debug! full      = 16.1 ns
```

**归因**：`HotLog::enabled()` = 本地级别判定 + `metadata_for()`（Mutex 锁 + 元数据缓存）+ `dispatch.enabled()`，
**每调用一次持锁**；原 `tracing::debug!` 走 tracing 静态 callsite 的 `Interest` 缓存（无锁、~16ns）。
即：**门面把「零分配」做到了，但没把「零 CPU」做到**（规格 §面 4 只硬要求「零格式化零分配」，
未要求零 CPU——`HotLog::enabled` 文档亦自述「无静态 interest 快路径（每次过 event_enabled）」）。

**缓解事实（关键）**：本波 40 处站点的**逐点路径分类**（§3.5）显示——
**35/40 位于错误/稀有分支**（队列满、发送失败、err size、陈旧包丢弃、连接结束），
**5/40 为连接/拨号级**（dial dispatch、连接建立/关闭、0-RTT 结果、REALITY 建链、GET 状态异常），
**0 处位于无条件每包路径**。故 124ns 的检查开销**在正常数据面每包路径上不发生**；
bench 侧证：6 个窗口的 srv/cli 日志中，**40 条迁移消息一次都没出现**（`migrated-msg-hits=NONE`）。
**准确解读**：这不是「级别门拦下了」（bench 日志里 DEBUG 级别的行确实存在，如
`DEBUG target=127.0.0.1:18453 resolving domain via system DNS`——那是 `crate::LOG`（LogFacade）通道的既有输出，
不在本波 40 站点内），而是**这些站点的触发条件（队列满 / 发送失败 / err size / 陈旧包 / 连接结束）
在 bench 拓扑与 600MiB 传输中从未发生** → 站点未被到达 → 124ns 检查费未发生。
即：**40 处站点的「到达」本身是稀有事件**（与 §3.5 的路径频率分类一致），这才是缓解依据；
「每包必达的 124ns」这一最坏情形在本波不存在。

**但需 PM 知晓的风险**：若将来有站点被放到**无条件每包路径**且级别为 DEBUG，
则每包多付 ~124ns（对比旧宏 ~16ns）——**这是 xray-frame `HotLog` 设计的固有代价，不是本波调用点的选择**
（调用点已按规格「先过滤后格式化」实现了过滤前置）。是否需要为 HotLog 增加静态 interest 快路径，
属 xray-frame 派生件的独立优化项，**超出本波文件面**，建议 PM 归入后续波次。

### 3.5 40 处站点的路径频率逐点分类（mitigation 依据）

| 类别 | 处数 | 站点 |
|---|---|---|
| 错误/稀有分支（队列满 / 发送失败 / err size / 陈旧包丢弃 / 连接结束） | **35** | udp/hub 7、finalmask/mod 4、xdns/client 3、xdns/server 2、xmc/conn 2、gecko 2、upload_queue 1、batched_upload 2、splithttp/client 3、dialer 5、h3_client 2、bridge 1、xdns/client(容量超限) 1 |
| 连接/拨号级 | **5** | splithttp/dialer 3（dial dispatch / dial_h3 dispatch / REALITY 建链）、h3_client 2（0-RTT 结果 / H3 建链） |
| **无条件每包路径** | **0** | — |

（逐点复核样例：udp/hub.rs:268 在 `Err(TrySendError::Full)` 臂；finalmask/mod.rs:554 在
`Err(mpsc::error::TrySendError::Full(_))` 臂；upload_queue.rs:222 在 `packet.seq < inner.next_seq` 臂；
xdns/client.rs:327 在 `p.len() > 容量` 的提前返回之后；splithttp/client.rs:810 在 `Ok(resp)` 非 200 臂；
h3_client.rs:761 在 `Ok(resp)` 非 200 臂 → **全部为条件分支，无一为无条件每包到达**。）

---

## 4. 验收门尾部（实跑输出）

| 门 | 命令 | 结果 |
|---|---|---|
| 站点对账 | `git diff` 删除侧 vs `hot_log!` 计数 | **40 : 40**（1:1 精确） |
| 豁免标记 | `git grep -c log-hot-path-exempt -- crates/` | **ZERO**（全仓已清） |
| 消息文本 | 逐站点 HEAD→当前字面量包含核对 | **40/40 逐字保留**；p7lm 9 处 byte-identical |
| check | `cargo check -p 四 crate -j 8` | Finished dev profile，**0 error 0 warning** |
| test | `cargo test -p 四 crate --all-targets -j 8` | transport **662** / hysteria **110** / naive **17** / splithttp **240** + mock_h3_server 1 / mock_server 8 / reality_integration 1 / stream_h2 2 = **1041 passed / 0 failed** |
| clippy | `cargo clippy --workspace --all-targets -j 8 -- -D warnings` | Finished dev profile in 1.43s，**0 error** |
| hot_log 门 | `cargo test -p xray-frame --test hot_log` | **6 passed / 0 failed**（含 `disabled_level_costs_zero_allocation` 零分配断言、`hot_log_emits_message_with_target`） |
| A/B 性能 | `tools/loopback_alloc_bench.py` 3 窗口交错 | 见 §3.2；floor(120) **6/6 窗口 exit=0** |
| interop 12/12 | `python reports/audit-2026-10-27/tmp/run_interop_w6.py`（RUST 指向 target-w4 迁移后产物） | **12/12 PASS**（Rust→Go ×6 + Go→Rust ×6，全协议 body=200028B） |
| 32/32 真机 | `run_full32.py` | **未跑（归 PM）**——VPS 面不在本波授权 |

---

## 5. 并行波次事故记录（共享树）

1. **首轮 A/B 全轮作废（自纠）**：B 臂指向 `target-w4/release/xray.exe`（共享构建输出路径），
   而当时该路径正被 A' 构建占用 → **B 窗口实际跑的是 A′ 二进制**（二进制字符串计数事后查实）。
   自纠：两臂改用 `/d/tmp/enc8x/` 冻结副本 + 跑前逐个打印字符串计数确认迁移态 → 整轮重跑（本报告 §3.2 数据）。
2. **A' 编译期 `use tracing::debug;` 缺失**：`git apply -R` 回退后编译报 `cannot find macro debug`（E0433）——
   我的 forward patch 不含 import 移除 hunk（那些 hunk 无 hot_log 关键字被过滤）。
   修法：手工复原 4 个 import（batched_upload/client/dialer/h3_client）→ A' 编译绿 → 复原时同步移除 →
   **SHA256 逐文件校验 20/20 与 A' 循环前快照一致**。
3. **与 W5 的文件面协调**：两方同在 xray-transport。W5 主动**全树 hold**（零落码）直至本任 A' 循环结束
   （理由正确：A' 与 B 编进同一 xray.exe，其间落码会让两态混态 → 性能数据作废）。
   本任承诺兑现：hold 期间本任只读+跑 bench，A' 循环结束后 forward apply 复原并做三重校验
   （`git apply --check` OK / 20 文件 SHA256 一致 / diff 行数 923 与循环前相同），
   已把基线快照（xray-transport 10 文件 138+/77-、diff 556 行；全树 diff 3156 行）交付 W5 作为其落码前基线。
4. **本任发现并更正前任两处事实错误**：bridge.rs p7lm 站点数（10 → 实测 9）；
   前任报告未填的 B 态性能/interop/workspace-clippy 三项（本任全部补跑）。

---

## 6. 遗留与风险

| # | 项 | 等级 | 说明与建议 |
|---|---|---|---|
| 1 | **154-167 MB/s 绝对锚在当前树不可达** | 需 PM 裁决 | A'（迁移前）与 B（迁移后）同样只有 ~132；立锚期基线二进制今天也只有 128.6-131.1 → **非本波引入**。建议 PM 将本波判定锚定为「相对 A' 不降」（已满足），并单独评估树级吞吐下移（与 W1-W5 框架改动的累积关系待查） |
| 2 | **HotLog 单次调用开销 124ns vs 旧宏 16ns** | 需 PM 裁决 | 40 处站点全在错误/稀有/连接级路径（0 处在无条件每包路径）→ 本波无实际影响；但若未来把门面用于无条件每包路径，需先给 xray-frame `HotLog` 加静态 interest 快路径（超本波文件面，建议独立波次） |
| 3 | **面外 8 处裸 tracing 站点**（xicmp.rs 1 / xicmp_sock.rs 3 / system_listener.rs 4） | 登记 | 全部由 `336d8430`（晚于 T3.2a 清单成文）引入，不在规格面 4 的 37 处清单、不在本波文件面 → 本波不擅自扩面。建议归入「xicmp 白名单」审计域同源的下一波次 |
| 4 | **splithttp 自造 target 消失** | 已登记 | 外部日志订阅者过滤串需从 `splithttp` / `splithttp-h3` 改 `xray_frame::transport::splithttp`（Go 对齐侧不受影响） |
| 5 | naive / quinn_adapter 的 HotLog 消费为零 | 登记 | naive 生产面零热路径日志豁免站点（豁免台账本就是测试站点）；quinn_adapter 已被 T3.2a 收编。**融合度账面以此为准** |
| 6 | 32/32 真机门 | 未跑 | 归 PM（VPS 面不在本波授权） |

---

## 7. 5 轴自评

- **准确性 4/5**：站点数、文本、target、门尾全部来自本任实跑输出（二进制字符串计数 / git diff hunk 级配平 /
  SHA256 校验 / 逐窗口 bench 尾部）；扣分：§3.4 的 124ns 数字来自**临时探针**（已删除），
  探针在独立测试二进制中测得，与真实进程内嵌调用点可能存在微小差异（未在生产二进制内复测）。
- **完整性 5/5**：验收 6 项全做——站点对账（含例外逐处 allow+理由）、四 crate test、workspace clippy、
  A/B 性能（真单变量 3 窗口交错 + 基线期二进制归因取证 + 单次调用开销实测 + 站点路径频率分类）、
  interop 12/12、报告六节齐备；32/32 按任务书归 PM 并在 §4/§6 明示未跑。
- **清晰度 5/5**：三段式（对账表 / 例外登记 / 性能门），每条数字附来源命令与尾部输出，
  A'/B 定义与「为何现成 A 态不可用」显式交代。
- **可执行性 5/5**：报告含可复现命令（bench tag 口径、interop runner 路径、探针代码要点）、
  产出物路径（A'/B 冻结二进制、报告、bench harness）。
- **简洁性 4/5**：扣分：§1.1 表 14 行 + §3.5 分类表与 §3.2 数字表存在信息重叠
  （为满足「例外逐处 allow+理由」与「路径频率逐点分类」两个验收项而重复列站点）。
