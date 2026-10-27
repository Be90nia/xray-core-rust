# spawn 门可见性闭环：26 处「未登记」裸 spawn 逐站点复核（2026-10-28）

VERDICT: PASS（可见性闭环达成；结论 = 26/26 **已在台账内**，0 迁 0 新增 allow，1 处文件头计数刷新；L3 门与红线门实跑全绿）

## 0. 一句话结论

任务前提「26 处未登记裸 spawn 是门盲区」经逐站点核对**不成立**：26 处全部已被合法登记形态覆盖
（fn 级 / 语句级 / 文件级 / 模块级 `#[allow(clippy::disallowed_methods)]` + reason），L3 门
（per-crate clippy.toml `disallowed-methods` + `-D warnings`）对全部 7 crate 实跑 **0 error**——
任何一处真失登记都会当场红。普查表的「未登记」是**扫描方法学假阳性**（见 §3），不是真缺口。
与 bd pdm1q（8 处裸 tracing 真晚于台账）性质不同：本次无一处「晚于台账」。

## 1. 26 站点处置表（逐站点）

登记形态缩写：**逐点** = 属性直接挂 spawn 语句；**fn 级** = 挂所在函数；**语句级** = 挂包络
let 语句（覆盖块内嵌套 spawn，AST 子树生效）；**文件级** = 文件头 `#![allow]`（>20 处/文件
分层规则，clippy.toml 注释自订：须计数+票号）；**模块级** = 门控测试模块 inner allow。

| # | 站点 | 处置 | 覆盖 allow（形态 / 位置 / reason 摘要） | 不迁 FxScope 论证 |
|---|---|---|---|---|
| 1 | xray-core/grpc_server.rs:77 | 已登记 | fn 级 `spawn_grpc`（:62-66）「常驻基础设施任务（metrics gRPC server，句柄返回调用方托管）；迁 FxScope 待 bd 39hko」 | 句柄返还调用方托管（escrow 语义）；无已装配 scope 可挂，迁=改装配面，归 39hko |
| 2 | xray-core/outbound.rs:274 | 已登记 | 文件级（:3-6）「存量 31 处（29 spawn + 2 Instant）>20/文件分层规则，收口 bd 39hko」 | dialerProxy hook 闭包内 fire-and-forget dispatch 泵，寿命=dispatch future 本体；hook 无 scope 注入点 |
| 3 | xray-core/outbound.rs:1823 | 已登记 | 同上（文件级） | DNS outbound 查询任务，同 :274——注册路径无 scope 可达 |
| 4 | xray-frame/redline.rs:106 | 已登记 | fn 级 `spawn_unchecked`「红线受控逃逸口：站点穷举登记于 SITES（CI 门核对调用集合）……」 | **受控入口本体**，任务书明示必须登记不迁移；它就是逃逸口的唯一实现点 |
| 5 | xray-proxy-tun/inbound.rs:903 | 已登记 | fn 级 `spawn_udp_session_sweeper`（:898-901）「存量债：未接 PluginContext 托管句柄（tail 表达式位无法就地登记），接线归 P1 插件装配（B3 T3.1）」 | 存量债已挂 B3 T3.1（P1 装配），收口票在先；本单禁行为迁移 |
| 6-10 | xray-transport/splice.rs:229,232,255,257,264 | 已登记（**非生产面**） | 模块级：`#[cfg(all(test, any(target_os = "linux", target_os = "android")))] mod tests` inner allow（:188-191）「测试：splice 泵/桥测试任务（unix 门控路径，Windows 不编译）」 | **测试任务**（pump/writer/bridge/left/right 全在 unix 门控测试模块内，模块注释自证「生产面 splice 泵本身无 spawn」）；测试面登记已足 |
| 11-18 | xray-transport-grpc/transport.rs:310,372,508,531,705,725,781,862 | 已登记 | 文件级（:8；头注释 :2-7 **本次刷新**）「23 处（生产 8 + 测试 15）>20/文件分层阈值……收口 bd 39hko」 | h2 conn driver / accept 泵 / close_notify 泵 / ping_pong / gun duplex 全为连接寿命任务，传输层无 PluginContext 注入面（坑约束⑫）；FxScope 接线归 39hko 传输切片 |
| 19 | xray-transport-splithttp/dialer.rs:82 | 已登记 | fn 级 `dial_packet_up`（:56-59）「数据面热路径豁免（坑约束⑫）+ ctx 不可达……packet-up 上传泵」 | h2/h3 传输层无 ctx 注入面（reason 已记）；归 39hko |
| 20 | xray-transport-splithttp/dialer.rs:374 | 已登记 | fn 级 `dial_h3_packet_up`（:350-353），同上 | 同上 |
| 21 | xray-transport-splithttp/transport.rs:270 | 已登记 | 语句级 `let accept_task`（:253-256）「本 allow 覆盖 2 处（TCP accept 循环 + 循环内每连接处理任务）」 | accept 循环体嵌套 spawn，寿命=listener；数据面（坑约束⑫） |
| 22 | xray-transport-splithttp/transport.rs:367 | 已登记 | 语句级（:352-355）「覆盖 2 处（unix accept 循环 + 循环内每连接处理任务）」 | 同上（unix 门控生产路径） |
| 23 | xray-transport-splithttp/transport.rs:831 | 已登记 | 语句级 `let _accept_task`（:824-827）「覆盖 2 处（QUIC accept 循环 + 循环内每连接处理任务）」 | 同上（QUIC accept） |
| 24-25 | xray-transport-splithttp/transport.rs:862,870 | 已登记 | 语句级（:854-857）「h3 每请求任务（+ 请求体桥接任务 + 连接终结 abort 任务）」 | h3 每请求/桥接/abort 三任务寿命=h3 连接；数据面（坑约束⑫） |
| 26 | xray-transport-websocket/client.rs:339 | 已登记 | fn 级 `poll_write`（:317-320）「数据面连接任务（首写触发拨号 joining）；迁 FxScope 待 bd 39hko」+ 代码注释「joining 赋值表达式语句位挂属性在本工具链 E0658（无 stmt_expr_attributes），故挂 fn 位」 | Future 挂在 AsyncWrite::poll_write 内，语句位属性工具链不可用（E0658 实证注释在位）；数据面连接任务 |

**处置统计**：登记 26/26（其中 26 处在位、0 处本次新增 allow）／迁移 0。唯一代码改动 =
grpc/transport.rs 文件头**计数注释刷新**（21→23、生产 6→8：mzput close_notify 关停泵 +
per-conn serve 于台账生成后入树；文件级登记形态按分层规则要求「计数+票号」，计数失真即台账
失真，故刷新属本单范围；注释级改动，零行为）。

## 2. 普查表更正

`d-face-spawn-census.md` 已在文首加更正横幅（指向本报告）。原表数字按 2026-10-28 复核修正：

| crate | 原「未登记」 | 复核后真未登记 | 说明 |
|---|---|---|---|
| xray-transport | 5 | **0** | 5 处实为 unix 门控测试 spawn，且生产面统计多计 5 |
| xray-transport-splithttp | 7 | **0** | 7 处全为 fn/语句级在位登记 |
| xray-core | 3 | **0** | 1 fn 级 + 2 文件级在位 |
| xray-transport-grpc | 8 | **0** | 文件级在位（>20/文件规则），头计数 21→23 已刷新 |
| xray-frame | 1 | **0** | 受控入口 fn 级在位 |
| xray-proxy-tun | 1 | **0** | fn 级在位 |
| xray-transport-websocket | 1 | **0** | fn 级在位 |
| **合计** | **26** | **0** | 生产面真未登记裸 spawn = **0** |

## 3. 普查方法学缺口（复跑前必读）

1. **只认逐点 allow**：扫描以「spawn 紧邻的 `#[allow]`」为登记判据，不认 fn 级 / 语句级 /
   文件级 / 模块级——而后三者恰是 clippy.toml 自订分层规则的**合法登记形态**
   （「≤20 处/文件逐点；>20 处/文件文件头 inner allow + 计数与票号」）。fn 级与语句级的
   覆盖是 Rust lint 属性 AST 子树语义（属性所在语句/函数体内的嵌套 spawn 一并覆盖），
   websocket 与 tun 的 fn 级还各有 E0658 / tail-expr 位的硬性理由注释。
2. **测试面判定只匹配 `#[cfg(test)]` 字面量**：splice.rs 的测试模块是
   `#[cfg(all(test, any(target_os = "linux", target_os = "android")))]` → 5 处测试 spawn
   被误计入「生产面」并判未登记。
3. **树漂移**：普查生成后，grpc/outbound 的文件级 allow、h3_client 逐点登记等已陆续入树
   （L3 切片 bd a5r4j/lzzja 滚动中）；今晚 `ledger-audit.md` §2-3 对 splithttp「toml 只禁
   to_vec」的记载同样已过时（现 toml 含 spawn/thread 双条目）。**复跑普查必须先核对 allow
   覆盖形态（含文件头与门控模块），并以当刻 clippy 实跑为最终判据。**

## 4. 门语义澄清（「调用集合 ⊆ 登记集合」如何被机械保证）

- **spawn 面**：台账 = 各 crate `clippy.toml` 的 `disallowed-methods` 禁令 + 逐点/fn/语句/
  文件级 allow 及 reason。`cargo clippy -p <crate> --all-targets -- -D warnings` 下，**任何
  无覆盖 allow 的裸 spawn = 编译期硬错**——「裸 spawn 集合 ⊆ 有 allow 站点集合」由门自动
  强制，无需额外登记表。本次 7 crate 实跑 0 error 即该不变式的实跑证明。
- **红线逃逸口面**（`RedlineSite::SITES` 穷举 + `tests/redline_sites.rs`）：26 处均为裸
  `tokio::spawn`，**不是** `spawn_unchecked`/`event` 逃逸口调用者，不属于 SITES 台账范畴；
  该门测试 4/4 独立全绿（含 `escape_hatch_call_sites_are_registered`）。
- **残余风险（既定取舍，留痕）**：outbound.rs / grpc transport.rs 两文件级 allow 使这两文件
  **未来新增** spawn 对门隐形，直到 bd 39hko 收口改回逐点——这是 >20/文件分层规则的明文
  取舍（「逐点登记属性海不经济」），非本单可越权改判；两文件头均已写明收口票号。

## 5. 验收实跑记录（2026-10-28，CARGO_TARGET_DIR=target-SpawnGate）

1. **红线门测试**（`cargo test -p xray-frame --test redline_sites`）：
   ```text
   running 4 tests
   test ledger_entries_are_complete ... ok
   test redline_spawn_is_observable ... ok
   test bare_tracing_event_only_exists_in_registered_redline_files ... ok
   test escape_hatch_call_sites_are_registered ... ok
   test result: ok. 4 passed; 0 failed; 0 ignored
   ```
2. **7 crate `--lib` 测试**：
   - 6 crate 全绿（0 failed）：
     ```text
     xray-frame               test result: ok.  48 passed; 0 failed; 0 ignored
     xray-proxy-tun           test result: ok. 154 passed; 0 failed; 0 ignored
     xray-transport           test result: ok. 662 passed; 0 failed; 2 ignored
     xray-transport-grpc      test result: ok.  93 passed; 0 failed; 0 ignored
     xray-transport-splithttp test result: ok. 240 passed; 0 failed; 0 ignored
     xray-transport-websocket test result: ok. 109 passed; 0 failed; 1 ignored
     ```
   - xray-core：478 passed / **1 failed**，失败 =
     `functions::tests::shutdown_token_cancel_terminates_inflight_long_connection`，
     panic 原文：`长连接未随停机终止：server shutdown_token cancel 后 2001ms 内仍持续收到
     1417216 bytes (writer 已写 176 块)——停机级联未达在途连接（W4 面 6「connection drain
     留后续」实测）`。**归属实证（非本单引入）**：①该断言文本只存在于 `functions.rs` 的
     **未提交在飞重写**（git diff：+1195/−784，测试本体正在被兄弟代理 W4 面 6 改造，失败
     信息自带「留后续实测」标注——是其在飞工作的已知未实现语义，确定性复现非 flake）；
     ②本单改动仅为 grpc crate 注释 + 两个 markdown，零 xray-core 面。按共享树纪律
     （文件面独占）未代修，归 functions.rs 属主代理。
3. **clippy**（7 crate `--all-targets -- -D warnings`）：exit 0，0 error（首轮全 7 crate
   `CLIPPY_EXIT_0` 实跑；本单注释改动后对 xray-transport-grpc 复跑 `GRPC_CLIPPY_EXIT_0`）。
   vendor/rustls 2 条 warning 为依赖自身 dead_code/unreachable_pub，非 -D 对象、非本范围。
4. **fmt**：`cargo fmt --all -- --check` 的全部差异仅集中在
   `tests/integration/e2e_p2_test.rs`（6 处）与 `tests/integration/transport_interop_test.rs`
   （8 处）——均为 PortToctou-2 在飞文件（本单禁碰）；`crates/` 面（含本次改动文件）零差异。
   按任务书预先授权的回退口径记为「crates 侧 clean、全仓 clean 被兄弟代理 tests/ 在飞编辑阻塞」。

## 6. 变更清单

| 文件 | 改动 | 性质 |
|---|---|---|
| `crates/xray-transport-grpc/src/transport.rs` | 文件头 L3 登记计数刷新 21→23（生产 6→8，+2=mzput close_notify 泵/per-conn serve） | 注释级，零行为 |
| `reports/audit-2026-10-27/d-face-spawn-census.md` | 文首加复核更正横幅 | 文档 |
| `reports/audit-2026-10-27/spawn-gate-visible.md` | 本报告 | 文档 |

生产源码零行为改动：0 处 spawn 迁移、0 处参数/寿命变化、0 处断言语义变化、0 条新 lint 规则。

## 7. 五维自评

| 维度 | 分 | 依据 |
|---|---|---|
| 正确性 | 4.5 | 26 站点逐站点证据（allow 形态+位置+reason 原文）+ 门实跑双证（clippy 0 error、门测试 4/4）；扣 0.5：splice.rs 5 处的覆盖由 CI linux 门背书，Windows 本地无法编译验证该 cfg 门控路径 |
| 完整性 | 5 | 任务书 5 条验收全有实跑证据（含 xray-core 1 失败的归属实证链）；普查表更正+报告+计数刷新三件套落位 |
| 越界控制 | 5 | 零行为改动；未碰 tests/；未代修兄弟在飞的 functions.rs（文件面独占纪律）；唯一生产码改动是台账计数注释（登记形态的组成部分，属「可见性闭环」本义） |
| 可维护性 | 4.5 | 普查方法学缺口成文（复跑前必读），台账计数回归真实；剩余风险（文件级 allow 的未来盲区）已留痕且归 39hko |
| 证据可信 | 5 | 全部结论有当刻命令输出；前提证伪（26 未登记→0）如实上报不注水；共享树三次在飞态干扰（WSL shell flake ×2 / 兄弟编辑窗口 / 缺 env 的误跑）均复跑定案并如实记录 |
