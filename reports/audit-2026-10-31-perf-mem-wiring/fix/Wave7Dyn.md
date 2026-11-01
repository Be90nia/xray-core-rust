VERDICT: MIXED-FIXED —— 票面四项里 **③ DC-6（AddOutbound 查重/插入非原子）是真缺陷，本轮实修**（`SimpleOhm` 变更闸 + 原子 `add_if_absent`，并发同 tag 恰好 1 成功 N-1 明确失败）；**① DC-3 / ② DC-4 / ④ DC-13 在 HEAD 已修**（票面前提过期，附提交与代码位），本轮对其做 Go 对照 + **真互通取证**（② Go 客户端 ↔ Rust 服务端 / Rust 客户端 ↔ Go 服务端 双向 2/2 PASS）并补上 ④ 的确定性并发用例。四项均带「撤回修复 → 用例变红」反证。

- 执行人：MuxUdp（子代理）
- 树：`feature/fix-inbound-parity` @ `afb963f9`（工作区含其他代理未提交改动：`xray-core/src/{inbound,outbound}.rs` 的 DNS 写者队列面、`xray-app-dispatcher/src/udp_session.rs`、`xray-xudp/src/packet.rs`、`xray-frame/src/scope.rs` 等——本票未触碰其语义）
- 构建：`CARGO_TARGET_DIR=D:/Project/Xray-core-rust/target-Wave7Dyn`，`BORING_BSSL_PATH=<预构建 btls>`
- 裁定基准：Go 26.10.17（源码 `D:/Project/Xray-core` @ `92ccc939`，二进制 `D:/tmp/go2617/xray.exe`）
- 改动面（**本票自有**）：
  - `crates/xray-app-dispatcher/src/default.rs`：`SimpleOhm` 变更闸 + `add_if_absent`（+49）
  - `crates/xray-core/src/outbound.rs`：`ApiOutboundRuntime::add_outbound` 走原子插入 + 并发用例（+~140）
  - `crates/xray-core/src/inbound.rs`：④ 确定性/并发用例（+~150）
  - `crates/xray-app-router/src/router.rs`、`crates/xray-cli/src/commands/api_exec.rs`：**零改动**（反证临时回退已完全还原，见 §6）

---

## 0. 票面四项 × HEAD 实况

| 票项 | 票面描述 | HEAD 实况（本轮实测） | 本轮动作 |
|---|---|---|---|
| ① DC-3 | `should_append=false` 被忽略 → 恒追加 | **已修**：`Router::reload_rules`（`xray-app-router/src/router.rs`）按 `should_append` 分「整体替换 / 追加」，balancer 映射同款替换；`command/mod.rs::add_rules` 透传该布尔 | Go 对照 + 真互通取证（替换语义 E1） |
| ② DC-4 | AddRule 载荷形状双错（CLI type_url 不存在 + value 是 JSON；服务端只解单条 RoutingRule） | **已修**：服务端 `grpc.rs::add_rule` 强制 `type == "xray.app.router.Config"` 且解**整份** `xray.app.router.Config`（含 balancers）；CLI `api_exec.rs::build_rule_typed_message` 产同款 proto | **真互通双向**（Go 客户端 ↔ Rust 服务端 / Rust 客户端 ↔ Go 服务端） |
| ③ DC-6 | AddOutbound 查重与插入非原子 → 并发同 tag 双成功 + 静默覆盖 | **仍存在**（本轮实修）：`xray-core/src/outbound.rs::add_outbound` = `get_handler` 查重（一步）+ `ohm.add` 插入（另一步） | **实修**：变更闸 + `add_if_absent`（查重+插入同一临界区）+ 8 线程并发用例 + 反证 |
| ④ DC-13 | `register_user_manager` 用 remove+insert → 复活已删 tag | **已修**（HEAD `xray-core/src/inbound.rs::register_user_manager` 就地 `get_mut` 写 `users`，tag 已摘则丢弃登记） | 补确定性用例（先删后登记 / 先登记后删）+ 并发用例 + 反证 |

---

## 1. ① DC-3：`should_append=false` = 整体替换规则集

### Go 行为（26.10.17 源码）

- `app/router/command/command.go:56` `AddRule` → `bo.AddRule(request.Config, request.ShouldAppend)`。
- `app/router/router.go:84` `Router.AddRule(config *serial.TypedMessage, shouldAppend bool)`：`config.GetInstance()` 必须是 `*Config`（否则 `AddRule: config type error`）→ `ReloadRules(c, shouldAppend)`。
- `app/router/router.go:95` `ReloadRules`：`r.mu` 全程持锁；`shouldAppend=false` ⇒ `newRules` 从空起（旧规则**整体丢弃**、`closeWebhooks(oldRules)`）、`newBalancers` 只留本 config 的；`shouldAppend=true` ⇒ 旧规则 + 旧 balancer 保留，新规则追加，`ruleTag` 重复即 `duplicate ruleTag` 报错（旧规则不动）。任一规则构建失败 ⇒ 旧集合不动。

### Rust 现状（HEAD，已修）

- `xray-app-router/src/router.rs::reload_rules(config, should_append)`：`should_append=false` ⇒ `new_rules` 从空起（旧规则整体替换）、`new_balancers` 只留本 config 的；`true` ⇒ 旧规则/旧 balancer 保留 + 追加，`ruleTag` 重复 ⇒ `DuplicateRuleTag`；**先全部构建成功再落库**（与 Go 同款「构建失败旧规则不动」）。单测 `test_reload_rules_replaces_all` / `test_reload_rules_append_keeps_old_and_rejects_dup_tag` 已在库。
- `xray-app-router/src/command/mod.rs::add_rules(config, should_append)` → `reload_rules`（布尔透传）。
- 「其它路由域」澄清（Go 口径）：Go 的替换粒度是**整份规则列表**——`domain`/`geosite`/`ip` 等只是**单条规则内部的条件字段**，Go/Rust 都**没有**「按条件域分表」的独立注册表，故替换规则集不会遗留任何旧条件域；balancer 是唯一与规则并列的独立表，Go 非 append 分支同样只留本 config（Rust 同款）。

### 修法

无（本项 HEAD 已符合 Go 语义）。本轮只做取证与反证。

### 反证（撤回修复 → 用例变红）

把 `reload_rules` 临时改成恒追加（`let should_append = true;`）后重编 + 跑真互通脚本：

```
[list-after-replace rc=0] { "rules": [ {"ruleTag": "r-initial"}, {"ruleTag": "r-go"} ] }
FAIL: shouldAppend=false 应整体替换（旧 r-initial 仍在），实得 ['r-initial', 'r-go']
==> phase1 Rust server <- Go client (adrules): FAIL
=== 1/2 PASS ===          (interop exit=1)
```

（完整输出：`fix/tmp/api_interop/counterproof_1_append_always.log`；改回后 `router.rs` 与 HEAD **零差异**。）

### 验证（真互通，双向）

见 §2 的互通矩阵（phase1 = Rust 服务端 ← Go 客户端，含替换/追加两段）。

---

## 2. ② DC-4：AddRule 载荷形状（type_url + 整份 Config + balancers）

### Go 行为

- CLI `main/commands/all/api/rules_add.go`：`conf.RouterConfig.Build()` → `serial.ToTypedMessage(config)` ⇒ TypedMessage `{Type: "xray.app.router.Config", Value: proto bytes(rule[] + balancingRule[])}` → `AddRuleRequest{Config: tmsg, ShouldAppend: shouldAppend}`（`-append` 默认 false）。
- 服务端 `app/router/router.go:84`：`config.GetInstance()` 必须得到 `*Config` ⇒ **载荷必须是 `xray.app.router.Config` 整份**（不是单条 `RoutingRule`），否则 `AddRule: config type error`。

### Rust 现状（HEAD，已修）

- 服务端 `xray-app-commander/src/grpc.rs::add_rule`：`tm.r#type != "xray.app.router.Config"` ⇒ `InvalidArgument`；否则 `xray_proto::xray::app::router::Config::decode`（**整份**，含 `balancing_rule`）→ `service.add_rules(&config, req.should_append)`。
- CLI `xray-cli/src/commands/api_exec.rs::build_rule_typed_message`：复用生产装配同一解析器 `xray_core::wiring::parse_routing_json_to_proto`（含 `balancers` → `BalancingRule`、`strategy`/`strategySettings`）⇒ TypedMessage `{Type: "xray.app.router.Config", Value: proto bytes}`。

### 修法

无（本项 HEAD 已符合 Go 形状）。本轮补**真互通**取证。

### 反证（撤回修复 → 用例变红）

把 CLI 临时改回旧形状（`type = "xray.app.router.RoutingConfig"` + JSON 载荷）后重编，真互通打到 **Go 服务端**：

```
[add(replace) rc=1] Error: API request failed: failed to add rule:
  code: 'Unknown error', message: "proto:\u{a0}not found"
FAIL: add 失败
    ruleTags = ['r-initial']
FAIL: 新规则 r-rust 未生效，实得 ['r-initial']
==> phase2 Go server <- Rust client (add-rule): FAIL
=== 1/2 PASS ===          (interop exit=1)
```

（完整输出：`fix/tmp/api_interop/counterproof_2_bad_payload.log`；改回后 `api_exec.rs` 与 HEAD **零差异**。）

### 验证（真互通，脚本 `fix/scripts/wave7dyn_api_addrule_interop.py`）

两侧实例同形（`api.listen=127.0.0.1:10085` 明文 gRPC + `services:["RoutingService"]` + 一条初始规则 `r-initial`）：

```
===== phase1 Rust server <- Go client (adrules) =====
[list-initial rc=0] { "rules": [ {"ruleTag": "r-initial"} ] }
[add(replace) rc=0] {}
[list-after-replace rc=0] { "rules": [ {"ruleTag": "r-go"} ] }        ← 整体替换（旧 r-initial 消失）
[add(append) rc=0] {}
[list-after-append rc=0] { "rules": [ {"ruleTag": "r-go"}, {"ruleTag": "r-go-2"} ] }   ← 追加（旧规则保留）
==> phase1 Rust server <- Go client (adrules): PASS

===== phase2 Go server <- Rust client (add-rule) =====
[list-initial rc=0] ListRuleResponse { rules: [ ListRuleItem { tag: "direct", rule_tag: "r-initial" } ] }
[add(replace) rc=0] added rule
[list-after-replace rc=0] rules: [ ListRuleItem { tag: "direct", rule_tag: "r-rust" } ]     ← Go 服务端接受 Rust 造的载荷
[add(append) rc=0] added rule
[list-after-append rc=0] rules: [ ... "r-rust" ..., ... "r-rust-2" ... ]
==> phase2 Go server <- Rust client (add-rule): PASS

=== 2/2 PASS ===
```

⇒ ② 的三个要点全部 E1 成立：**Go 客户端 → Rust 服务端**（Rust 收 Go 的 `xray.app.router.Config` proto）、**Rust 客户端 → Go 服务端**（Go 收 Rust 同款 proto）、**替换/追加语义两侧一致**。
（完整日志：`fix/tmp/api_interop/after_fix.log`。）

---

## 3. ③ DC-6：AddOutbound 查重与插入必须原子（本轮实修）

### Go 行为（26.10.17）

`app/proxyman/command/handlers.go` `AddHandler`：先 `ohm.GetHandler(tag) != nil` ⇒ `errors.New("existing tag found: ", tag)`；否则 `core.CreateObject` + `ohm.AddHandler(ctx, handler)`（`outbound.Manager.AddHandler` = map 覆盖写）。**Go 同样不是原子操作**（查重与写入分两步），但 Go 的语义是「后写覆盖」；本仓票面要求更严：**并发同 tag 只能成功一个，输家必须拿到明确失败（不许静默覆盖）**。

### Rust 现状（修前）

`crates/xray-core/src/outbound.rs::ApiOutboundRuntime::add_outbound`：

```rust
if self.ohm.get_handler(&cfg.tag).is_some() { return Err(format!("existing tag found: {}", cfg.tag)); }
let handler = build_single_outbound(&ob)...?;
self.ohm.add(&cfg.tag, handler);   // ← upsert（覆盖）
Ok(())
```

`SimpleOhm::add` 是 upsert（`tagged` + 影子表同源覆盖）⇒ **查重与插入分离**：两个并发请求都能通过快路径查重，后者 `add` 静默覆盖前者的 handler，两个调用都返回 `Ok`（gRPC 侧都回 `AddOutboundResponse{}`）。实测（撤回修复后）**8 个并发同 tag 有 4 个返回成功**。

### 修法

1. `crates/xray-app-dispatcher/src/default.rs`：
   - `SimpleOhm` 增 `mutation: parking_lot::Mutex<()>` **变更闸**——`add` / `remove` / `add_if_absent` 三者共用，恒为**第一把锁**（表锁在其内按固定序取）⇒ 查重+插入同临界区，且不与既有表锁构成锁序反转；
   - 新增 `SimpleOhm::add_if_absent(tag, handler) -> Result<(), String>`：闸内同时持 `tagged`/`shadow` 写锁 → 查 `tagged` → 已存在则 `Err("existing tag found: <tag>")`；否则先影子后旧表插入（与 `add` 同序），任一插入失败显式 Err 并回滚影子（不留半注册状态；注册表满 = fail-closed，不静默丢 handler）。
2. `crates/xray-core/src/outbound.rs::add_outbound`：保留 Go 同款**快路径**（tag 已存在 ⇒ `existing tag found`，先于构建），**权威判定**改走 `add_if_absent` ⇒ 并发下唯一赢家，其余拿到同一句明确错误（gRPC 层 `grpc.rs` 已把含 `existing tag found` 的错误映射为 `Status::already_exists`）。

### 反证（撤回修复 → 用例变红）

把 `add_outbound` 临时改回 `self.ohm.add(&cfg.tag, handler); Ok(())`：

```
---- outbound::api_outbound_atomic_add::concurrent_same_tag_add_outbound_exactly_one_wins stdout ----
thread '...' panicked at crates\xray-core\src\outbound.rs:7192:9:
assertion `left == right` failed: 并发同 tag 必须恰好 1 个成功（其余明确失败）
  left: 4
 right: 1
test result: FAILED. 1 passed; 1 failed
```

（8 并发里 **4 个静默成功** = 静默覆盖。串行重复添加用例仍绿——快路径本就拦得住串行重复，缺陷只在并发窗内。）

### 验证

```
$ cargo test -p xray-core --lib -- api_outbound_atomic_add
test outbound::api_outbound_atomic_add::duplicate_tag_add_outbound_is_rejected_without_overwrite ... ok
test outbound::api_outbound_atomic_add::concurrent_same_tag_add_outbound_exactly_one_wins ... ok
test result: ok. 2 passed; 0 failed
```

（用例本体：8 个 `tokio::spawn` 任务过同一 `Barrier` 后并发调 `add_outbound`（同 tag）⇒ 断言恰好 1 个 `Ok`、7 个 `Err` 且错误串含 `existing tag found`，并断言赢家 handler 仍在表内。）

---

## 4. ④ DC-13：`register_user_manager` 不得复活已删 tag

### Go 行为

Go 的用户管理器由各协议 inbound 自己持有（`handler.(proxy.UserManager)`），没有「按 tag 登记/摘除」的独立注册表 ⇒ 不存在「复活已删入站」这一形态。

### Rust 现状（HEAD，已修）

`crates/xray-core/src/inbound.rs::register_user_manager`（HEAD）：

```rust
let mut slots = self.slots.write();
match slots.get_mut(tag) {
    Some(slot) => slot.users = Some(users),
    // tag 已被 RemoveInbound 摘除：丢弃登记，不复活。
    None => tracing::debug!(tag = %tag, "user manager registration skipped: tag removed"),
}
```

即：**查与写同一把写锁内**，tag 已被 `RemoveInbound` 摘除 ⇒ 登记被丢弃（不复活 slot）。

### 修法

无（HEAD 已修）。本轮补**确定性用例**（票面要求的「与 RemoveInbound 并发」此前无覆盖）。

### 反证（撤回修复 → 用例变红）

把 `register_user_manager` 临时改回 remove+insert 形态（摘掉再插回、缺 tag 时插一个新 slot）：

```
---- inbound::user_manager_resurrection::register_user_manager_after_remove_does_not_resurrect_tag stdout ----
thread '...' panicked at crates\xray-core\src\inbound.rs:13229:9:
已删 tag 不得被登记复活
test result: FAILED. 2 passed; 1 failed
```

（并发用例在 64 轮里未必撞上那个窗口——**确定性用例**才是可靠的反证；并发用例的价值在于「终态与交错顺序无关」。）

### 验证

```
$ cargo test -p xray-core --lib -- user_manager_resurrection
test inbound::user_manager_resurrection::register_user_manager_before_remove_is_dropped_with_inbound ... ok
test inbound::user_manager_resurrection::register_user_manager_after_remove_does_not_resurrect_tag ... ok
test inbound::user_manager_resurrection::register_user_manager_parallel_remove_never_resurrects ... ok
test result: ok. 3 passed; 0 failed
```

用例覆盖：①先删后登记 ⇒ tag 不复活（`contains=false`、表空、再删报 `HandlerNotFound`、`user_manager` 报 `HandlerNotFound`）；②先登记后删 ⇒ 随入站一起消失；③`register_user_manager` ∥ `RemoveInbound` 同 tag × 64 轮 ⇒ 终态恒为「已删」。

---

## 5. 全量 test 结果

| 范围 | 命令 | 结果 |
|---|---|---|
| xray-core（含本票新增 5 条：③ 两条 + ④ 三条） | `cargo test -p xray-core --lib` | **518 passed / 0 failed / 2 ignored**（31.78s） |
| xray-app-dispatcher（③ 的 `SimpleOhm` 改动面） | `cargo test -p xray-app-dispatcher --all-targets` | **148 passed / 0 failed** |
| xray-app-router（① 的改动面） | `cargo test -p xray-app-router --all-targets` | **160 passed + 3 passed / 0 failed** |
| workspace lint 门（验收 5） | `cargo clippy --workspace --all-targets -- -D warnings` | **exit 0**——零告警（`clippy_workspace.log` 28 行全部来自 `vendor/rustls` 红线依赖，非本仓代码） |
| fmt 门（验收 5） | `cargo fmt --all -- --check` | **exit 0**——本仓 0 diff（`fmt_all.log` 0 行） |
| ② 真互通 | `python fix/scripts/wave7dyn_api_addrule_interop.py` | **2/2 PASS**（Go 客户端 ↔ Rust 服务端 / Rust 客户端 ↔ Go 服务端） |

未跑 workspace 全量 test（8091 基线那一档）：本次改动只触 `xray-app-dispatcher` / `xray-core` 两个 crate 的生产代码 + 两个 crate 的用例，其余 crate 无代码面；workspace 全量由 PM 收口门统一跑（同箱另有代理在途改动）。

---

## 6. 残余观察（不属本票四项，交 PM 分流）

1. **`ListRule` 回填不全**：Go `ListRuleItem{tag=outboundTag, ruleTag}`（`app/router/command/command.go:70-77`）；Rust `list_rule` 只填 `rule_tag`，`tag` 恒空 ⇒ Go 客户端连 Rust 服务端时 `lsrules` 输出缺 `tag` 字段（互通本身正常）。对照输出见 `after_fix.log` phase1（Go 客户端看到 `{"ruleTag": "r-go"}`，无 `tag`）vs phase2（Rust 客户端连 Go 服务端看到 `tag: "direct"`）。
2. **Go 的 AddHandler 本身非原子**（`app/proxyman/command/handlers.go`：查重与 `AddHandler` 分两步，Go 语义是后写覆盖）；本仓按票面要求做得更严（并发同 tag 只成功一个）。若要与 Go 严格对齐，需 PM 裁定「更严」是否保留（本轮按票面保留）。
3. **Rust 的 UDP relay 不派生 GlobalID**（`AccessContext.from` 恒空）⇒ cone 会话复用未生效；与上一票 sgdkj 报告同源，另票跟进。

## 7. 环境与产物

- 互通脚本：`reports/audit-2026-10-31-perf-mem-wiring/fix/scripts/wave7dyn_api_addrule_interop.py`
  （`XRAY_RUST_BIN` / `XRAY_GO_BIN` 可覆盖二进制路径；默认 Rust=`target-Wave7Dyn/release/xray.exe`、Go=`D:/tmp/go2617/xray.exe`）
- 验证脚本：`reports/audit-2026-10-31-perf-mem-wiring/fix/scripts/wave7dyn_verify.sh`（构建 → 互通 → 三 crate 测试；Git Bash 运行）
- 互通日志：`fix/tmp/api_interop/after_fix.log`（修后 2/2）、`counterproof_1_append_always.log`（① 反证）、`counterproof_2_bad_payload.log`（② 反证）
- 门禁日志：`fix/tmp/api_interop/clippy_workspace.log`（28 行，全为 `vendor/rustls`）、`fix/tmp/api_interop/fmt_all.log`（0 行）
- 二进制：Rust `target-Wave7Dyn/release/xray.exe`（release，`git_rev=afb963f9…`）、Go `D:/tmp/go2617/xray.exe`（26.10.17 `92ccc93`）
- 磁盘：`target-Wave7Dyn`（本代理独占 CARGO_TARGET_DIR）按派单契约收尾删除；复跑请先重编（`BORING_BSSL_PATH=<预构建 btls>` + `cargo build --release -p xray-cli`，约 10-12 分钟）或用 `XRAY_RUST_BIN` 指向其它构建产物
