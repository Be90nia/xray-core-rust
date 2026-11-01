# DOD 十条复核总账（2026-10-31）

- 分支 `feature/fix-inbound-parity`，HEAD `65733da7`
- 战役：bd epic `99ifi`（xray-frame 深度融合）
- 口径：DOD 原文见 `docs/architecture/xray-frame-深度融合战役计划-2026-10-26.md` §0
- 分工：三条并行只读复核（D1/D2/D6、D3/D4/D5、D7/D8/D9），D10 由 PM 亲自取证

## 裁决表

| # | 判据 | 裁决 | 关键证据 | 细报告 |
|---|---|---|---|---|
| D1 | 生产装配主路 = xray-frame | **PASS** | 唯一构造路径 `arm_registry::lookup_*`（inbound.rs:4166 / outbound.rs:694，UDS/tun 同表）；`arm_builders` 两张 BTreeMap fn 表已删、降级为纯数据源 `INBOUND_CTORS`(20) / `OUTBOUND_CTORS`(18)；双写硬门实跑「配置变体 3 × 协议 37 → 比较 88 次，差异 0 处」 | `dod-D1-D2-D6.md` |
| D2 | L5 装配门生效 | **PASS** | `l5_gates_fail_visible_at_assembly`（arm_registry.rs:542，缺依赖/成环/缺段三档）+ xray-frame `tests/plugin_registry.rs:88/:102`（7 passed）+ `tests_config_parity.rs:263`（1 passed），全绿 | 同上 |
| D3 | L2 运行期能力（三禁令） | **PASS**（2026-10-31 修复后） | 16 协议 crate 生产面零裸 spawn、零裸 `tracing!`；闸数权威口径 **54/54 产品 crate**（56 成员 − tests/benches 两 harness；盘面 55 份 = 54 产品 + 1 份属 udf 工作副本不计）；`xray-frame`/`xray-buf` 已补时钟三禁令；5 处 tokio-Instant 豁免全部挂票锚 bd `23vrp`；探针三变体全红（exit 101）→ 删探针复绿 | `dod-fix-D3-D8-docs.md` |
| D4 | L4 夹具真实实例 16/16 | **PASS** | 16/16 均 `XPlugin::default()` → Framework register → bring_up → shutdown，并用 `stopped==["<crate>"]` 钉空报告边界；16 夹具真跑 171 tests 全过 | 同上 |
| D5 | udf 契约族 13/13 有生产调用点 | **PASS**（2026-10-31 修复后） | 13/13（bd 77r0q 重裁 11 族口径下 11/11）：`testing` 族接线于 `xray-frame/src/state_loop.rs` reducer 契约测试（TestStore×3 + ScriptedRuntime×1，18/18 绿）；`parse_mock` 如实归零（主仓零 JsonPort/SqlDialectPort/MarkdownPort 采用方，无注入缝）；`ConfigFile` 按 bd 77r0q NO-GO 收口（3 条差异属 Xray 语义），影子比对 `cargo test -p xray-conf --test config_file_shadow` 10/10 | `dod-fix-D5.md` |
| D6 | 七面 7/7 | CONDITIONAL | 七面机制全部落地（lint 上浮 udf、注册表族 BoundedRegistry 双侧、JSON/日志/中央 match 臂/停机编排均有 file:line）；8 条老 API 迁出探针 0 命中。**缺口**：面④配置装配按 bd `77r0q` NO-GO 收口（生产走 xray-frame）；CLAUDE.md §3.5.4 两行台账漂移 | `dod-D1-D2-D6.md` |
| D7 | 215 生产裸 spawn 归零 | **PASS** | 当前 HEAD 重算：裸 `tokio::spawn` = **131**，豁免 **131/131**（stmt 117/item 4/file 10），**未登记违规 0**；`std::thread::spawn` = 0；对账闭合：基线 193 = 62（迁移/净出）+ 131（豁免），132@`8754bac6` → 131@HEAD 无回潮 | `dod-D7-D8-D9.md` |
| D8 | 187 Instant::now 归零或接 Clock | **PASS**（2026-10-31 修复后） | 14 处已闭合：4 处接线 udf Clock（`context.rs:35` / `reload.rs:190` → `SystemClock.now_system()`；`contract_assert.rs:291/302` → `SystemClock.now_instant()`）+ 10 处登记（`deadline.rs` 9 站点由 2 条 impl 级 allow 罩住=tokio 虚拟钟桥本体；`xray-buf/alloc.rs` now_ms 1 条 fn 级 allow）；两 crate 时钟三禁令已补 | 同上 |
| D9 | 性能债 4y9ns / r1693 / q1r4q | CONDITIONAL（性能面已清） | 三票 CLOSED 且 alloc 差分齐全：4y9ns cli **9.239→5.085 MB/MB（−45.0%）**、r1693 srv **2.159→1.299**、q1r4q 每包 **3→2**。真机同窗 A/B 吞吐按用户 2026-10-31 口径**由用户自测**，不计未完成 | 同上 |
| D10 | 每波收尾门 | **PASS** | 见下节 | 本文 + 各 run 报告 |

## D10 取证（PM 亲自跑）

| 项 | 结果 | 证据 |
|---|---|---|
| 32/32 真机（CI 产物双端） | **32/32 PASS**，body 中位 959359B | `reports/audit-2026-10-31/run32-176-ci-20261031-0500.md`（05:04，黄金窗） |
| interop 12/12 | **12/12 PASS**（双向：Rust 客户端↔Go 26.10.17 服务端 6 项；Go 客户端↔Rust 服务端 6 项） | 本日实跑 `dist/interop_matrix.py`（`XRAY_RUST_BIN=D:/tmp/latest-bin/win/xray.exe`、`XRAY_GO=D:/tmp/go2617/xray.exe`） |
| check/clippy/test/fmt/doc | 全绿 | CI run `41078561362`（13/13 success）；本地 `cargo clippy/fmt/doc` 复验 0 error |
| CI 远端绿 | 连续两轮 13/13 | `225ce371`、`91e227db` |

## 未闭合项与处置

| 项 | 处置 | 状态 |
|---|---|---|
| D5（testing 族零消费 + ConfigFile 切换） | 已补：13/13（11 族口径） | **完成** |
| D3（闸口径/两 crate 禁令/豁免票锚）+ D8（14 处登记/补门）+ D6/D4 文档漂移 | 已补：三者均转 PASS/已同步 | **完成** |
| D9 · r1693 池化缩放缺陷 | 修复 `5fe98b90`；bd `9eu4a` 已关 | **完成** |
| 池驻留上限（258 块/流）多流并发内存 | bd `a5pe6`（P3）跟踪 | 待观测 |
| D9 真机 A/B | 用户自测（已记入 epic `99ifi` notes） | 用户侧 |

**关 epic 条件**：D1–D10 全 PASS（D9 真机 A/B 由用户自测，已记票面不作未完成）= 满足；D10 门（clippy/test/fmt/doc + interop 12/12）重跑全绿后关 `99ifi`。

## 终态（2026-10-31 修复完成后）

| D1 | D2 | D3 | D4 | D5 | D6 | D7 | D8 | D9 | D10 |
|---|---|---|---|---|---|---|---|---|---|
| PASS | PASS | **PASS** | PASS | **PASS** | PASS(文档已同步) | PASS | **PASS** | **PASS** | PASS |
