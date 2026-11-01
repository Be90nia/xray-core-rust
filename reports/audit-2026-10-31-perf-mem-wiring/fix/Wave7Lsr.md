# Wave7 · o1a9p — ListRule 只填 rule_tag，缺 outboundTag（Go 客户端读 Rust 服务端漏 tag 字段）

VERDICT: PASS —— `ListRule` 双字段对齐 Go（`tag`=outboundTag + `ruleTag`）；Go 客户端 ↔ Rust 服务端真互通 4/4 相位逐字段一致（含 balancer 空 tag 语义）；门禁 test / clippy / fmt 全绿。

- [x] §1 Go ListRule 字段真相表（带行号）
- [x] §2 Rust 现状
- [x] §3 实现
- [x] §4 `lsrules` 双向原始输出
- [x] §5 逐字段对比表
- [x] §6 无法对齐项与理由（无——Go 只填两个字段，全回填）
- [x] §7 门禁
- [x] §8 残余风险

---

## §1 Go ListRule 字段真相表（基准 `D:/Project/Xray-core` @ `92ccc939` = v26.10.17）

**结论先行：Go 的 `ListRuleItem` 一共只有两个字段——`tag`（= 规则的 outboundTag）和
`ruleTag`。没有 domain/ip/port/network/protocol/attrs——票面猜测的「等 Go 会填的字段」
实际就是这两个。**

| 字段 | proto 编号 | Go 赋值处 | 数据源 |
|---|---|---|---|
| `tag` | 1 | `app/router/command/command.go:75` `Tag: v.GetOutboundTag()` | `router.go:196` `outboundTag: rule.Tag` ← `RoutingRule.TargetTag.Tag`（**balancer 规则此字段为空**） |
| `ruleTag` | 2 | `app/router/command/command.go:76` `RuleTag: v.GetRuleTag()` | `router.go:197` `ruleTag: rule.RuleTag` |

证据链（逐行）：

- proto 形状 `app/router/command/command.proto:106-116`：
  ```proto
  message ListRuleItem {
    string tag = 1;
    string ruleTag = 2;
  }
  message ListRuleResponse { repeated ListRuleItem rules = 1; }
  ```
- 服务端实现 `app/router/command/command.go:70-79`：
  ```go
  func (s *routingServer) ListRule(...) {
      for _, v := range bo.ListRule() {
          response.Rules = append(response.Rules, &ListRuleItem{
              Tag:     v.GetOutboundTag(),
              RuleTag: v.GetRuleTag(),
          })
      }
  }
  ```
- 数据源 `app/router/router.go:193-201`（`Router.ListRule`）：
  ```go
  ruleList = append(ruleList, &Route{
      outboundTag: rule.Tag,     // ← RoutingRule.GetTag()（config.pb.go:296，TargetTag oneof 之一）
      ruleTag:     rule.RuleTag,
  })
  ```
- `Route` 取值器 `router.go:275-282`：`GetOutboundTag()` / `GetRuleTag()` 原样返回。
- 佐证（写入路径同形）`command.go:132-133`（AddRule）：`rr.Tag = rule.GetTag(); rr.RuleTag = rule.GetRuleTag()`。
- balancer 规则：`RoutingRule.TargetTag` 是 `Tag | BalancingTag` oneof
  （config.pb.go:295-299）——`rule.Tag` 对 balancer 规则 = **空串**（Go 侧 `lsrules`
  对 balancer 规则同样输出空 `tag`，这是 Go 行为的一部分，不是缺陷）。

## §2 Rust 现状

- 缺陷现场：`crates/xray-app-commander/src/grpc.rs:708-718`
  ```rust
  let rules = self.service.list_rule().map_err(router_status)?;
  rules.into_iter().map(|t| prouter::ListRuleItem { tag: String::new(), rule_tag: t })
  ```
  `tag` **恒空**——与 Wave7Dyn 残余观察一致（Go 客户端 `lsrules` 只见 `ruleTag`）。
- 数据源断链：`xray-app-router/src/command/mod.rs:75-78`
  `RoutingService::list_rule() -> Result<Vec<String>>` →
  `xray-app-router/src/router.rs:323-326` `Router::list_rules() -> Vec<String>`
  ——**只吐 rule_tag，把 outbound tag 扔在了半路**。
- 内部结构**不缺字段**：`xray-app-router/src/rule.rs:26-39`
  `Rule { tag: String /* 出站 tag（与 balancer 互斥） */, rule_tag: String, balancer, ... }`；
  构造处 `rule.rs:130` `Rule { tag, rule_tag: proto.rule_tag.clone(), ... }`
  （`tag` ← `TargetTag::Tag`，balancer 规则留空——与 Go `rule.Tag` 语义一字不差）。
  ⇒ **无需动 Rule 结构**，只需让访问器把 `tag` 一起带出来。
- proto 面：Rust `prouter::ListRuleItem` 已有 `tag` + `rule_tag` 两字段（grpc.rs:715
  构造可见），与 Go proto 形状一致，字段编号由 protos/ 镜像保证（只读红线，未动）。

## §3 实现

**裁决：必须动 `crates/xray-app-router`，但不动 Rule 结构。** 必要性：缺陷不在 commander
的填装代码本身——`RoutingService::list_rule()` / `Router::list_rules()` 的返回类型是
`Vec<String>`（只吐 rule_tag），outbound tag 在 `Router::list_rules()` 半路就被扔掉了；
commander 拿不到数据。而 `Rule` 结构**本来就有** `tag` 字段（rule.rs:26-31，构造语义与
Go `rule.Tag` 一字不差），故不需要动 Rule 结构，只需把访问器返回类型改成
`Vec<(outbound_tag, rule_tag)>`——这是访问器签名变更，不是结构变更（超出票面「Rule 结构」
的授权字面，特此报备）。全仓 callers 清点（grep 实证，全部同步）：commander grpc.rs、
router `command/mod.rs`、router.rs 5 处测试、`command/mod.rs` 3 处测试；
`xray-core/src/wiring.rs:72` 仅把返回值喂 `Debug`（tuple Debug 兼容，**未改动该文件**）。

| 文件 | 改动 |
|---|---|
| `crates/xray-app-router/src/router.rs:323-331` | `list_rules() -> Vec<(String, String)>`（出站 tag, 规则 tag）；doc 注明 balancer 规则出站 tag=空串（Go 同款） |
| `crates/xray-app-router/src/command/mod.rs:75-80` | `RoutingService::list_rule()` 返回类型同步 |
| `crates/xray-app-commander/src/grpc.rs:708-719` | `ListRuleItem { tag, rule_tag }` 双字段回填（原 `tag: String::new()` 恒空） |
| `router.rs` 测试 ×4、`command/mod.rs` 测试 ×3 | 断言升级为 pair 形态，`add_rule_then_list_rule_contains_tag` 增加出站 tag 回程断言 |
| `grpc.rs` 测试（rule-1 用例） | 断言 `item.tag == "direct"`（outboundTag 必须经 ListRule 回程） |

不引入新依赖；protos/ 只读未动（Rust `ListRuleItem` 本就有 `tag`+`rule_tag` 两字段，
字段编号由镜像保证）。

## §4 `lsrules` 双向原始输出

脚本：`reports/audit-2026-10-31-perf-mem-wiring/fix/scripts/wave7lsr_lsrules_interop.py`
（`XRAY_RUST_BIN` 可覆盖；原始输出落盘 `fix/tmp/api_interop_lsr/A..D_*.log`）。
配置（两侧同形，`fix/tmp/api_interop_lsr/instance_srv.json`）：`api.listen=127.0.0.1:10085`
+ `services:["RoutingService"]`，两条初始规则——`r-outbound`（`outboundTag: direct`）、
`r-balancer`（`balancerTag: lb1`，用于钉住 balancer 规则的空 tag 语义）。

**A. Rust 服务端 ← Go 客户端**（`xray.exe api lsrules --server=127.0.0.1:10085`，Go 26.10.17）

```json
{
    "rules": [
        { "ruleTag": "r-outbound", "tag": "direct" },
        { "ruleTag": "r-balancer" }
    ]
}
```

**B. Go 服务端 ← Go 客户端**（字段形状基准）

```json
{
    "rules": [
        { "ruleTag": "r-outbound", "tag": "direct" },
        { "ruleTag": "r-balancer" }
    ]
}
```

**C. Rust 服务端 ← Rust 客户端**（`xray.exe api list-rules --server 127.0.0.1:10085`）

```
ListRuleResponse {
    rules: [
        ListRuleItem { tag: "direct", rule_tag: "r-outbound" },
        ListRuleItem { tag: "", rule_tag: "r-balancer" },
    ],
}
```

**D. Go 服务端 ← Rust 客户端**

```
ListRuleResponse {
    rules: [
        ListRuleItem { tag: "direct", rule_tag: "r-outbound" },
        ListRuleItem { tag: "", rule_tag: "r-balancer" },
    ],
}
```

修前对照（Wave7Dyn `after_fix.log` phase1）：Go 客户端连 Rust 服务端只见
`{"ruleTag": "r-go"}`——**无 `tag` 字段**；本轮 A 相位同一客户端已见 `"tag": "direct"`。

## §5 逐字段对比表

| 客户端 | 服务端 | 规则 | `tag`（field 1） | `ruleTag`（field 2） |
|---|---|---|---|---|
| Go | **Rust** | r-outbound | `"direct"` | `"r-outbound"` |
| Go | Go | r-outbound | `"direct"` | `"r-outbound"` |
| Go | **Rust** | r-balancer | 空（wire 省略） | `"r-balancer"` |
| Go | Go | r-balancer | 空（wire 省略） | `"r-balancer"` |
| Rust | **Rust** | r-outbound / r-balancer | `"direct"` / `""` | 一致 |
| Rust | Go | r-outbound / r-balancer | `"direct"` / `""` | 一致 |

- **A == B 且 C == D**（脚本断言，`=== PASS ===`）：同一客户端对两侧服务端抽出的
  `(ruleTag, tag)` 集合逐条一致 ⇒ 字段集一致、值一致。
- proto 字段编号核对：`protos/app/router/command/command.proto:109-116`（`tag=1`、
  `ruleTag=2`、`rules=1`）与 Go `command.proto` 同形。

## §6 无法对齐项与理由

**无。** Go `ListRuleItem` 一共就 `tag` + `ruleTag` 两个字段（§1），本票全部回填。
票面猜测的 `domain`/`ip`/`port`/`network`/`protocol`/`attrs` **Go 不填**（`ListRuleItem`
proto 里根本没有这些字段；Go 客户端 `lsrules` 打印的就是 protojson，多填反而成新差异）。
balancer 规则 `tag` 为空串是 Go 原生语义（`TargetTag` oneof 的 BalancingTag 分支），两侧
一致，不是缺口。

## §7 门禁

环境：`CARGO_TARGET_DIR=D:/Project/Xray-core-rust/target-Wave7Lsr` + `BORING_BSSL_PATH`
（预构建 btls）+ `PROTOC` + `LIBCLANG_PATH`。

| 门 | 命令 | 结果 |
|---|---|---|
| test | `cargo test -p xray-app-router -p xray-app-commander --all-targets` | **router 160 passed + 3 passed**（含 parallel_build 集成）；**commander 93 passed / 0 failed** |
| clippy | `cargo clippy -p xray-app-router -p xray-app-commander --all-targets -- -D warnings` | **Finished，零告警**（`Checking xray-app-router / xray-app-commander`） |
| fmt | `cargo fmt -p xray-app-router -p xray-app-commander -- --check` | **0 diff**（FMT_CLEAN_OK） |
| 真互通 | `python fix/scripts/wave7lsr_lsrules_interop.py` | **4/4 相位，`=== PASS ===`**（A==B 且 C==D，含 balancer 空 tag 语义） |

注：commander 单测新增断言 `item.tag == "direct"`（rule-1 用例，grpc.rs:1807-1812）；
router `command/mod.rs` 新增出站 tag 回程断言（`add_rule_then_list_rule_contains_tag`）。

**改动面确认（`git diff` 范围）**：仅 `crates/xray-app-commander/src/grpc.rs`、
`crates/xray-app-router/src/{router.rs,command/mod.rs}`（+ 新报告/脚本/tmp，不入 crates）。
未触碰 `xray-core`（另一代理在改；`wiring.rs:72` 对 tuple 的 `Debug` 天然兼容，无需改动）、
splithttp、transport-*、mux、xudp、hysteria。未引入新依赖。未 commit。

## §8 残余风险

1. **访问器签名变更外溢一格**：`Router::list_rules()` / `RoutingService::list_rule()`
   返回类型 `Vec<String>` → `Vec<(String, String)>`，全仓 callers 已清点并同步
   （grep 实证仅 commander grpc.rs + 本 crate；`xray-core/wiring.rs:72` 只吃 `Debug`，无需改）。
   超出「只碰 commander」授权字面的部分是**访问器**而非票面点名的「Rule 结构」，已在 §3 报备。
2. **`lsrules` CLI 客户端展示面未改**：Rust CLI（`api_exec.rs:457-468`）原样打印响应
   （Debug/JSON），修复后自动多出 `tag` 字段——客户端零改动即受益；未为 CLI 单独做美化。
3. **balancer 规则的 `tag` 恒空**（Go 同款）：下游若想从 `lsrules` 知道 balancer 规则
   指向谁，Go/Rust 同样给不出（Go `ListRuleItem` 无 balancerTag 字段）——形状对齐即止，
   未私自加字段。
4. **未跑 workspace 全量 test**：改动面 = router 访问器 + commander 填装，两个 crate
   的 `--all-targets` 已全绿；其余 crate 无代码面（xray-core 仅 Debug 兼容确认），
   workspace 全量归 PM 收口门（同箱另有代理在途改动）。
5. **知识图谱**：`index_status` 显示 `indexed_at: 2026-10-31T15:09:00Z`（落后）。未在本轮
   重建——40+ 并行代理持续改树，单独重建立即再过期；建议战役收口统一
   `index_repository`。本票无新符号，滞后不影响本票检索。

## §9 收尾

- 构建目录 `target-Wave7Lsr`（7.3G）**已删除**。复跑互通需重编（`BORING_BSSL_PATH=<预构建
  btls>` + `cargo build --release -p xray-cli`，实测 ~14 分钟）或 `XRAY_RUST_BIN` 指向其它产物。
- 复跑互通：`XRAY_RUST_BIN=<release xray.exe> python
  reports/audit-2026-10-31-perf-mem-wiring/fix/scripts/wave7lsr_lsrules_interop.py`。
- 沉淀：本票无新的语言/工具链级坑（缺陷是「访问器把字段扔在半路」的项目内事实），
  `已沉淀: 无新增经验`。
