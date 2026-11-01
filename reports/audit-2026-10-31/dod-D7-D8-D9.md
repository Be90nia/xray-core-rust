# DOD 机械复核：D7 / D8 / D9（epic bd 99ifi 收官前对账）

日期 2026-10-31 · 分支 `feature/fix-inbound-parity` · HEAD `65733da7` · 只读复核（零代码改动）
复核脚本：`reports/audit-2026-10-31/tmp/clock-census-20261031.py`（本日新写，口径复用 `reports/audit-2026-10-28/spawn_ledger.py`）；spawn 复算直接跑既有 `spawn_ledger.py` + 本脚本同口径变体。
口径：扫 `crates/*/src/**/*.rs`（顶层 crate，udf-frame 嵌套层级天然排除），剔除注释、`#[cfg(test)]` 块、`/tests/` 目录；xray-stress（独立 bin）单列脚手架类。

---

## D7 — 215 生产裸 spawn 归零（站点数 = 迁移数 + 豁免数）

**VERDICT: PASS**

### 当前 HEAD 重算（2026-10-31，HEAD 65733da7）

| 指标 | 数值 |
|---|---:|
| 生产裸 `tokio::spawn` | **131**（脚手架模块另 11 处单列） |
| 豁免（allow+reason） | **131 / 131**（stmt 117 / item 4 / block 0 / file 10） |
| 违规（无 allow 或缺 reason） | **0** |
| 裸 `std::thread::spawn`（全仓含测试区未剔除） | **0** |

命令：`python reports/audit-2026-10-28/spawn_ledger.py`（→ 131 / 117 / 14 / 0）+ 本日脚本同口径变体复核（→ 131 豁免 / 0 违规，两法一致）。

### 对账等式（like-for-like，同一脚本逻辑跑两个 ref）

- 基线 `73db56f9`（DOD 基线 HEAD）：生产裸 spawn **193**（豁免 82 / 违规 111）
- HEAD：**131**（豁免 131 / 违规 0）
- **193 = 62（迁移/净出）+ 131（显式豁免带 reason）** ✅ 闭合
- crate 集合两 ref 完全一致（`git ls-tree` 差集为空）→ 62 净出即真实迁移/结构化，无删 crate 混入。

### 与票面 215 的口径差

DOD §1 的「215 裸 spawn（登记 66 属性/约 206 站点）」是票面口径（含脚手架模块与 `let _ =`/尾表达式形态）；`reports/audit-2026-10-28/f17zu-hj3jf-spawn-ledger.md` §一已明载两口径差 5~10 处。按票面口径读法：215 → 131+11 脚手架 = 142，净迁 73；按脚本 like-for-like 口径：193 → 131，净迁 62。两读法下「未登记裸 spawn = 0」均成立。

### 票据证据核查

- `bd show f17zu`：CLOSED，但 close reason 字段仅 "Closed"（**薄**）；真实证据在 NOTES 三条进度（0791bfb8 proxy 分片 + 3c0f24d8 transport 分片 + ss 真回归修复）与报告 `reports/audit-2026-10-28/f17zu-hj3jf-spawn-ledger.md`（hj3jf 收尾批次：14 处粗粒度 allow 全部逐点举证、5 处迁 `FxScope::spawn_detached`、无 reason 归零）。
- 关闭时数字 132（HEAD 8754bac6）→ 当前 131（其后 1 处再迁出）：**关闭证据在当前 HEAD 仍成立且无回潮**。

---

## D8 — 187 Instant::now 归零或接 Clock（站点数 = 迁移数 + 豁免数）

**VERDICT: CONDITIONAL**

### 当前 HEAD 重算（2026-10-31，HEAD 65733da7）

| 指标 | HEAD | 基线 73db56f9 |
|---|---:|---:|
| 生产时钟站点（std/tokio 面） | **79** | 153 |
| — Instant（std） | 48 | 88 |
| — tokio::time::Instant | 19 | 35 |
| — SystemTime | 12 | 30 |
| smoltcp 第三方栈面（单列，非 std/tokio） | 31 | 33 |
| 豁免（allow+reason） | **65**（30 stmt / 35 item） | 17 |
| **违规（无 allow 或缺 reason）** | **14** | 136 |
| xray-stress 独立 bin | 另 17 处单列 | 另 17 |

命令：`python reports/audit-2026-10-31/tmp/clock-census-20261031.py [--detail] [73db56f9]`

### 对账等式

- **153 = 74（迁移/净出）+ 65（显式豁免）+ 14（未登记残留）** → **不闭合**：14 处既非迁移也非豁免。
- DOD 的「187」与我口径的差：73db56f9 全口径（含 smoltcp）= 186；187 系 DOD 文档当时另含 1 处统计细节（不影响结论量级）。

### 14 处未登记残留（全部集中在框架自持时钟面）

| 站点 | 数量 | 性质 |
|---|---:|---|
| `xray-frame/src/deadline.rs` :192/219/221/231/236/272/279/297/307 | 9 | `Budget` tokio 计时臂实现体（`BudgetSource::Tokio`）——这就是「tokio 面取时桥」本体，Clock-gate 报告风险②所待的正是此件 |
| `xray-frame/src/deadline.rs` :236 等 std Instant 臂 | （含上） | 同上 std 臂 |
| `xray-frame/src/context.rs:35` | 1 | 进程指纹启动锚点（一次性 `SystemTime`，装配根调用一次） |
| `xray-frame/src/reload.rs:190` | 1 | 热重载临时文件命名纳秒 |
| `xray-frame/src/contract_assert.rs:291/302` | 2 | L4 契约夹具 `assert_deadline_effective_for` 真实耗时测量 |
| `xray-buf/src/alloc.rs:44` | 1 | 池惰性清扫时戳锚（`now_ms`） |

判定要点：
1. **门洞**：`xray-frame/clippy.toml` 与 `xray-buf/clippy.toml` **均无时钟禁令**（只有 spawn/println 条）→ 这 14 处永远不会被 clippy 点名，属 L3 门未覆盖面。`clock-gate-completion.md`（2026-10-29）刻意把它们划为「已裁决 crate 未动」，但**仓内无逐点 allow+reason、无书面台账**——713x6 close 残余段只点名 smoltcp / SessionHistory / SaltReplayFilter，未覆盖这 14 处。
2. smoltcp 31 处：第三方栈契约（`smoltcp::time::Instant::now()` 驱动 `Interface::poll`），713x6 close notes 已登记为结构性残余（「归 P3 ctx 穿透批次」），但同样无逐点 allow（其所在 crate 未列禁令，不构成门洞，构成台账缺口）。
3. 已豁免 65 处质量抽查（`xray-mux/session.rs:404`、`xray-reality/server.rs:534`、`xray-proxy-anytls/server.rs:224` 等）：allow+reason 齐全、reason 含三要素（为何拿不到 ctx.clock / 已就位出口 / 待迁条件）——713x6 + clock-gate 两波的登记纪律在已覆盖 crate 上成立。

### 票据证据核查（713x6）

- `bd show 713x6`：CLOSED，close reason 详实：净迁 28（35368812 app-11crate + wireguard + vless）+ 台账 79 + tokio 面 25 不迁加台账 + 禁令落地 + 5 个 MockClock 行为断言 + workspace 全绿 + 32/32 + interop 12/12。
- 时钟门第二波 `reports/audit-2026-10-28/clock-gate-completion.md`：15 crate 补 tokio/SystemTime 禁令 + 16 生产站点逐点登记 + 10 crate 测试豁免，clippy 15 crate 0 error（含 R1-R3 真实报错反证门生效）。
- **当前 HEAD 仍成立的部分**：65 处豁免登记、15+ crate 禁令、clippy 绿。**不成立/缺口**：close 时未把 xray-frame/xray-buf 的 14 处自持时钟面纳入台账（当时口径「已裁决 crate 未动」，但裁决只存在于报告文字，不在代码或台账）。

### 收口路径（供 PM 裁决，未实施）

二选一：①给 14 处逐点 `#[allow]+reason`（deadline.rs 可按 impl 块 1 条）；②xray-frame/xray-buf clippy.toml 补三变体禁令后同①（顺带把门补齐）。smoltcp 31 处登记进 713x6 残余台账或在 wireguard/tun clippy.toml 列 `smoltcp::time::Instant::now` 豁免条。

---

## D9 — 性能债 4y9ns / r1693 / q1r4q 清偿（alloc 差分 + 真机同窗 A/B）

**VERDICT: CONDITIONAL**（alloc 差分腿：三票全有实测数字；真机同窗 A/B 吞吐腿：三票全部未跑，按用户指示留待用户自测）

| 票 | 状态 | alloc 差分（实测） | 吞吐 A/B | 报告 |
|---|---|---|---|---|
| 4y9ns | CLOSED | cli alloc/MB **9.239→5.085**（−45.0%）；buf_read 绝对量 2,551→46–68 MB（**−98.3%**），站点占比 46.0%→1.5–2.2%；同窗 2×3 交错 A/B 两臂各两批 | loopback 噪声内不降；**真机未跑** | `reports/audit-2026-10-26/w6-4y9ns-fix.md` |
| r1693 | CLOSED | srv alloc/MB **2.159→1.299**（−0.860，达标 ≥0.5）；Phase0 归因 `xhttp_srv_send` +1.052 MB/MB 命中；h2 DATA 载荷抓包逐字节相等（帧数 733→642 系应用层分块） | loopback 38.02→38.27 区间重叠；**真机未跑** | `reports/audit-2026-10-26/r1693-h2-send.md` |
| q1r4q | CLOSED | 每包 alloc **3→2**（计数分配器实测）；dispatcher 138→140 passed；XUDP interop 4/4 | 无吞吐项（小票）；**真机未跑** | `reports/audit-2026-10-26/q1r4q-xudp-copy.md` |

逐票要点与保留意见：

1. **4y9ns 阈值未达原票面即关票**：票面 DESCRIPTION 验收为「cli alloc/MB ≤3 且吞吐不降」，实际 5.085；close reason 改述为「≤4.5 数学不可达（tls_read 单项 4.986 属 vendor/rustls 红线面）→ 另立上游票」。上游票 `bbuh7` 已结（KEEP：vendor rustls 补丁 tls_read −79%、CPU −17~19%、吞吐 +21.7%）——即残余大头已由红线内手段二次清偿，但**两次合并后是否满足「≤3」未复测**（alloc 复测缺失，非本复核范围）。
2. **r1693 互通验收口径**：票面写「Rust↔Go xhttp 互通 12/12 保持」，报告实测为 xhttp 三向（R↔R / R→G / G→R × 2 mode）**6/6** + 抓包逐字节比对；workspace 级 interop 12/12 由每波 D10 门另行覆盖（713x6/f17zu close notes 均载）。口径差异不影响 wire 不变结论。
3. **q1r4q 修复落在测试面**：报告明载全部改动位于 `#[cfg(test)] mod tests`（生产行 1-174 零改动）——两处 `to_vec` 站点在修复时已是测试 handler。「每包 alloc 3→2」为测试/基准语境实测，非生产 UDP 面；票面「UDP 面 alloc/包下降」按此口径视为达成。
4. **真机同窗 A/B（D9 第二腿）三票共同缺失**：所有吞吐 A/B 均为本机 loopback 受控测（4y9ns 375–420 MB/s、r1693 38 MB/s 量级）；直连族/CDN 真机黄金窗测速未跑（黄金窗已过，用户明确表示自己会测）。

---

## 方法论附注（复核中发现的两处工具缺陷，均已绕开，未改他人脚本）

1. **`spawn_ledger.py` 既有隐患**：item 级 allow 作用域的终止判定用裸 `find(';')` vs `find('{')`，签名含 `[u8; 8]` 类数组参数时作用域被分号截断（本日 D8 复核在 `xray-mux/session.rs:404`、`xray-reality/server.rs:534`、`xray-proxy-anytls/server.rs:224` 实测踩中，造成假「无豁免」）。本日脚本已改为括号深度感知扫描；对 spawn 复算的影响 = 0（`无 reason=0` 在修复后逻辑下复核依然成立，131/131 结论两法一致）。
2. **裸 `Instant::now()` 需辨身份**：wireguard/tun 的 31 处 bare/qualified `Instant::now()` 实为 `smoltcp::time::Instant`（第三方栈类型，非 std/tokio），已按 import/qualified 形态分流单列，不计入 D8 的 std/tokio 面。

## 复核结论一览

| DOD | 裁决 | 一句话 |
|---|---|---|
| D7 | **PASS** | 131/131 裸 spawn 全部显式豁免带 reason，未登记=0；193=62+131 闭合；f17zu 关闭证据当前 HEAD 仍成立 |
| D8 | **CONDITIONAL** | 79=74+65+**14**；14 处框架自持时钟面（xray-frame 13 + xray-buf 1）无登记无禁令=台账缺口+门洞；补登记或补禁令后可转 PASS |
| D9 | **CONDITIONAL** | 三票 alloc 差分实测齐全（9.239→5.085 / 2.159→1.299 / 3→2每包）；真机同窗 A/B 三票全缺（用户自测中） |
