# 运行期改配置语义链审计：reload / gRPC 动态配置 / 状态一致性

- 仓 `D:/Project/Xray-core-rust`，分支 `feature/fix-inbound-parity`，HEAD `5fe98b90`
- 口径：**生产主路** = 默认 `xray.exe run -c`（`xray_conf::Config::build()` → `xray_core::start_full`）
- 基准：Go 26.10.17 `D:/tmp/go2617/xray.exe`（源码 `D:/Project/Xray-core` @ `92ccc939`）
- 只读审计，零产品代码改动；E1 夹具在 `reports/audit-2026-10-31-perf-mem-wiring/round6/tmp/`
- **不与 `ym0z8`（同 tag 并发 AddInbound 覆盖/孤儿监听）重复**；**不与 `lu37q`（Routing/Observatory 零注入）重复** —— 涉及两者处只写「门后仍错」的新内容

## 0 结论（一句话）

动态配置面**只有一半能用**：inbound 增删、出站增删、legacy shadowsocks 用户增删实测可用；**vless/vmess/trojan/ss2022/hysteria/masque/wireguard 的用户热更全部不可用**（`proxy is not a UserManager`）；出站动态路径**静默丢弃 `sender_settings` 除 `streamSettings` 外的全部字段**（E1：`sendThrough` 被丢，Go 生效 Rust 不生效）；路由动态面虽因 `lu37q` 不可达，但代码里 3 处语义与 Go 相反，注入修好后立即变成用户可见偏差。**两边都没有配置热重载**（SIGHUP / 文件监听 / `--reload` 全无），这一项是 parity，不是缺口。

## 1 语义矩阵（操作 | Go 行为 | Rust 行为 | 差异 | 用户可见后果）

| # | 操作 | Go 26.10.17 行为 | Rust 行为（HEAD 5fe98b90） | 差异 | 用户可见后果 |
|---|---|---|---|---|---|
| 1 | SIGHUP / 配置文件监听 / `run --reload` | **无**（`main/run.go:106-108` 只 `signal.Notify(os.Interrupt, SIGTERM)`） | **无**（`xray-cli/src/run.rs:301-331` ctrl_c + SIGTERM） | 无 | 改配置必须重启（两边一致）。框架件 `xray_frame::reload::ConfigReloadListener`（`xray-frame/src/reload.rs:376`）**零生产消费方**，不要对外宣称支持热重载 |
| 2 | `AddOutbound` 新 tag + 路由规则已引用该 tag | 立即被路由选中（E1：`B2→B3` PONG） | **立即被路由选中**（E1：`A2→A3` PONG） | 无 | 动态替换节点可行 |
| 3 | `AddOutbound` 携带 `sendThrough` / `proxySettings` / `multiplexSettings` / `targetStrategy` | 全部生效（`app/proxyman/outbound/handler.go:122-168` 由 SenderConfig 构建；E1：`sendThrough` 生效→拨号失败） | **`streamSettings` 之外全丢**（`outbound.rs:449-495` 硬写 `send_through: None`/`proxy_settings_json: None`/`mux_json: None`/`target_strategy: None`）；E1：`sendThrough=192.0.2.123` 被忽略，流量照常直发 | **Rust 静默降级** | 以为经上游代理/绑定了指定源 IP，实际**直连出网（IP 泄漏）**；mux 不生效 |
| 4 | `AddOutbound` 重复 tag | 单锁内 check+insert → `existing tag found`（`app/proxyman/outbound/outbound.go:102-128`） | `get_handler` 与 `add` 两次独立加锁（`outbound.rs:501-513`、`functions.rs:583-597`），且 `add` 是 upsert（`default.rs:2107-2113`） | 检查与写入非原子 | 并发同 tag 双成功、后者静默覆盖（与 `ym0z8` 不同机制：出站无 listener，不会孤儿端口） |
| 5 | `AddOutbound` 注册表超上界（4096） | 无上界 | `insert_handler` 只 `tracing::error!`，`add` 返回 `()` → API 仍 200 | **Rust 假成功** | 畸形配置被"添加成功"，实际未注册 |
| 6 | `RemoveOutbound` 已存在 tag | 立即不可选中；在途连接不切断（`RemoveHandler` 不 `Close`） | 同（drop Arc，在途连接持自有 Arc） | 无 | 一致 |
| 7 | `RemoveOutbound` 不存在 tag | **200 OK**（`outbound.go:131-146`，`delete` 缺键=no-op）；E1 `B10` | **NOT_FOUND**（`functions.rs:738-746`）；E1 `A13` `handler not found: no-such` | **有**（幂等性） | `rmo; ado` 型幂等脚本在 Rust 上第一步即失败 |
| 8 | `AddRule`（`should_append` 语义） | `shouldAppend=false` = **整体替换全部规则**，`true` = 追加（`app/router/router.go:95-160`，CLI 默认 `false`）；E1 `G2→G3` 只剩 `r-new` | `should_append` **被忽略，恒追加**（`grpc.rs:670-690` 注释自认；`router.rs:234-252` 只 `push`） | **有（方向相反）** | 修好 `lu37q` 后：`xray api add-rule cfg.json`（默认非 append）**旧规则残留继续命中**，屏蔽/分流规则越积越多 |
| 9 | `AddRule` 入参类型 | `TypedMessage` 装 `xray.app.router.Config`（`rule[]` + `balancingRule[]`，可顺带新建 balancer） | 只解**单个 `RoutingRule`**（`grpc.rs:670-690`），balancer 无法动态创建 | **有（wire 级）** | Go 形状的请求被当 RoutingRule 解 → 垃圾规则或解码错；链表规则只能预配置 |
| 10 | `AddRule` 的 `ruleTag` | 可空（`ReloadRules` 只对非空 tag 查重） | `rule_tag.is_empty()` → `invalid argument`（`grpc.rs:681-684`；`router.rs:235-237`） | 有 | 匿名规则无法动态添加 |
| 11 | `RemoveRule` 不存在 tag | **200 OK**（`router.go:165-186` 恒 nil）；E1 `G6` | `TagNotFound` → NOT_FOUND（`router.rs:258-268`） | 有 | 同 #7 |
| 12 | `ListRule` 内容 | `{ruleTag, tag(outbound)}`；E1 `G1` | `ListRuleItem{tag:"", rule_tag}`（`grpc.rs:701-710` 恒填空；`command/mod.rs:76` 只返回 rule tag） | **有** | 看不到规则指向哪个出站，无法核对线上规则 |
| 13 | balancer override | override 优先于策略；空串=清除；**不校验** target 存在（`app/router/balancing.go:104-166`） | 同（`balancing.rs:218-250`、`router.rs:302-311`） | 无 | 一致（这一面守得住） |
| 14 | `AddUser`/`RemoveUser` 协议覆盖 | vless/vmess/trojan/shadowsocks/shadowsocks-2022/hysteria/masque/wireguard 全部实现（`proxy/*/…AddUser`：vless `inbound.go:238`、vmess `inbound.go:170`、trojan `server.go:119`、ss `server.go:57`、ss2022 `inbound_multi.go:107`、hysteria `server.go:62`、masque `server.go:224`、wg `server.go:135`） | **只有 legacy shadowsocks**（`inbound.rs:3009` `SsUserManager`，注册点 `inbound.rs:4149` 仅 ss 分支）；其余 `user_manager()` 返回 `NotUserManager`（`inbound.rs:3205-3212`） | **有（大面积）** | vless/vmess/trojan/ss2022/wg 用户**无法热加/热删**，只能改配置重启。E1 见 §4 C/Q 组 |
| 15 | 用户热更即时生效 | E1：`adu` 后**新用户立刻可连**（`P2→P4` PONG），`rmu` 后新连接被拒（`P7`） | legacy ss 有效（E1：count 1→2）；**其余协议根本没有入口**（E1：`Q2` `proxy is not a UserManager`，`Q3` 仍连不上） | 有 | Rust 上"临时加个用户"这件事对主用协议不可用 |
| 16 | 被删用户的已有连接 | 不切断（validator 只影响后续认证） | 同语义（ss validator 只影响后续连接） | 无 | 一致 |
| 17 | 动态改动写回配置文件 | 不写回，重启即丢 | 不写回，重启即丢 | 无 | 一致（运维须知：动态改动是易失的） |
| 18 | `ListOutbounds` / `ListInbounds` 内容 | 回完整 `OutboundHandlerConfig` / `InboundHandlerConfig`（含 settings） | 只回 tag + `type_url`，`value` 恒空（`functions.rs:755-771`、`:674-694`；E1 `A4` `sender_settings: None, proxy_settings: None`） | **有** | 无法用 `lso` 备份/核对线上配置（Go 可以 round-trip） |
| 19 | `RemoveInbound` 后再 `AddInbound` 同 tag/同端口 | 锁内同步 `handler.Close()`（`app/proxyman/inbound/inbound.go:73-100`），端口已释放 | 只 `cancel` token，不等待 listener 退出（`inbound.rs:3176-3192`） | 有（时序） | 理论窗口内端口未释放 → 立即重加可能 EADDRINUSE。**E1 未复现**（`A6→A7→A8` 立即重加成功），留档待压测 |
| 20 | 批量 add 多个 inbound/outbound，第 2 个失败 | 循环内 `Fatalf` 中途退出，**已添加的保留** | 同样中途返回错，已添加的保留（`api_exec.rs` 循环 `?`） | 无 | 批量操作非事务：失败后须人工回滚（两边一致，非缺陷，脚本须自查 `lsi`） |

## 2 半途状态 / 孤儿资源清单（不含 `ym0z8`）

| # | 半途状态 | 机制（file:line） | 后果 | 证据 |
|---|---|---|---|---|
| S1 | `register_user_manager` 用 `remove` + 改 + `insert` 更新槽位 | `inbound.rs:3215-3231` | ①窗口内 `user_manager()`/`list()` 短暂看不到该 tag；②若与 `remove_inbound`（`inbound.rs:3176`）交错，**slot 被重新插回** → 一个已 cancel、无监听器的 tag 常驻 `ListInbounds`，后续 `AddInbound` 同 tag 报 `existing tag found` 且无法清除 | E2（源码推导；窗口极窄） |
| S2 | `AddInbound` 成功路径丢弃 `JoinHandle`（`started` 只判 `is_none`） | `functions.rs:601-632`（`:620`） | 无人 join，只能靠 token 取消；与 S3 叠加时"删除完成"退化为"取消已发出" | E2 |
| S3 | `RemoveInbound` 只 `cancel` 不 join | `inbound.rs:3176-3192`（对照 Go 锁内 `Close()`） | 返回到客户端时端口/任务可能仍在；端口释放是异步的 | E1 未复现；E2 机制明确 |
| S4 | `AddOutbound` 检查-插入非原子 + upsert | `outbound.rs:501-513`、`functions.rs:583-597`、`default.rs:2107-2113` | 并发同 tag 双成功，先注册的 handler 被静默替换（无 listener/资源泄漏，但在途连接与新连接走不同 handler） | E2 |
| S5 | 注册表满时 `add` 只记日志 | `default.rs:2110-2116` | API 200 但未注册（假成功） | E2 |
| S6 | 动态出站不复用装配期能力（dns/policy/inbound_default_rules/mux） | `outbound.rs:427-445` | 同一份配置「静态写能通、动态 add 不通」（`targetStrategy: ForceIP*` 断链；无 policy 超时；mux 不包） | E2（`sendThrough` 侧已 E1，见 §4 D 组） |
| S7 | 路由动态面整块不可达 | `commander.rs:503-507` 静默吞 None（=`lu37q`）+ `xray-cli` API 服务声明门 | 用户按 Go 文档操作恒 `UNIMPLEMENTED`（此项归 `lu37q`，此处仅记录与 §1 #8/#9/#12 的叠加关系） | E1 `R1~R3` |

## 3 Findings（8 列）

| # | 场景 | 类型 | Go 行为 | Rust 行为 | 位置 file:line | 用户可见后果 | 严重度 | 建议 |
|---|---|---|---|---|---|---|---|---|
| DC-1 | vless/vmess/trojan/ss2022/wg/hysteria/masque 的 `AddUser`/`RemoveUser` | 功能缺口（fail-visible） | 8 协议全部实现，E1 实测新用户立刻可连 | 仅 legacy ss；其余 `proxy is not a UserManager`（failed_precondition） | `xray-core/src/inbound.rs:2997-3002`（trait）、`:3009`（唯一实现）、`:4149`（唯一注册点）、`:3205-3212`（返回 NotUserManager） | 主用协议无法热加/删用户，只能改配置重启；E1 `Q2/Q3` | **P1** | 按协议补 `ApiUserManager`：vless/vmess/trojan/ss2022 各把 validator 的 `add/remove/list` 包一层并在 `spawn_one_inbound` 登记（validator 已是 `Arc` 共享，热更对后续连接即时生效） |
| DC-2 | `AddOutbound` 的 `senderSettings` 只取 `streamSettings` | 静默降级 | 全字段生效（含 sendThrough/proxySettings/mux） | 其余字段硬写 None，静默丢 | `xray-core/src/outbound.rs:449-495`（`send_through: None` 在 `:474`；注释自认 targetStrategy 未映射在 `:478`） | 配置了 `sendThrough` 仍从默认源 IP 出（E1 `D` 组：Rust PONG / Go 失败）；配了链式/dialerProxy 变直连（**IP 泄漏**）；mux 静默失效 | **P1** | `built_outbound_from_proto` 补齐 4 字段解析（`sendThrough`、`proxySettings`、`multiplexSettings`、`targetStrategy`），复用静态装配的同一解析函数，禁第二份 |
| DC-3 | `AddRule` 的 `should_append=false` | 语义相反 | 整体替换规则集（E1 `G2→G3`） | 恒追加（代码注释自认） | `xray-app-commander/src/grpc.rs:670-690`（`:676` 注释）；`xray-app-router/src/router.rs:234-252` | 修好 `lu37q` 后：一次 `add-rule` 不清旧规则，**旧屏蔽规则残留继续命中**，规则无限累积 | **P1（latent，随 lu37q 一起暴露）** | `RoutingService::add_rule` 增加 `should_append` 形参；`false` 走已存在的 `Router::reload_rules`（整体替换、失败原子），`true` 走 `add_rule` |
| DC-4 | `AddRule` 入参 wire 形状 | wire 不兼容 | `config` = `xray.app.router.Config`（含 `rule[]`/`balancingRule[]`） | 只解单个 `RoutingRule`（`grpc.rs:670-690`）；CLI 侧更错：type_url 写成 `xray.app.router.RoutingConfig`、payload 是 **JSON 字节**（`api_exec.rs:175-190`） | `xray-app-commander/src/grpc.rs:670-690`；`xray-cli/src/commands/api_exec.rs:175-190`；对照 Go `main/commands/all/api/rules_add.go:78-84` | 注入修好后 Rust CLI 的 `add-rule` 仍会解码失败或解出垃圾规则；Go 客户端→Rust 服务端同样不通 | **P2（latent）** | CLI 改为构造 `xray.app.router.Config` 的 **protobuf** 载荷（复用 `xray-proto` 的 `Config` 类型），服务端按 `Config` 解码并支持 `balancingRule[]` |
| DC-5 | `RemoveOutbound` / `RemoveRule` 对不存在 tag | 失败语义 | 200 OK（幂等） | NOT_FOUND | `xray-core/src/functions.rs:738-746`；`xray-app-router/src/router.rs:258-268`；`xray-app-commander/src/grpc.rs:692-700` | "先删后加"型幂等脚本第一步就报错；E1 `A13` vs `B10` | P2 | 对齐 Go：缺 tag 视为成功（或按 PM 拍板保留严格语义并把 CLI/文档写清，二选一，禁现状模糊） |
| DC-6 | `AddOutbound` 重复 tag 的并发窗口 | 竞态 | 锁内 check+insert | check 与 insert 两次加锁，且 `add` 是 upsert | `xray-core/src/outbound.rs:501-513`；`xray-core/src/functions.rs:583-597`；`xray-app-dispatcher/src/default.rs:2107-2113` | 并发同 tag 双成功、后者静默覆盖（无 listener 泄漏，但在途连接与新连接走不同 handler） | P2 | 把"查重+插入"做成单次写锁内操作（`ohm.add_if_absent`），重复键 fail-closed 返回 `ExistingTag` |
| DC-7 | 动态出站不复用装配期能力（dns/policy/inbound 默认规则/mux） | 静默降级 | `CreateObject(server, config)` 走完整装配（所有 feature 可见） | `build_single_outbound` 传 `dns=None`/`policy=None`/空 `inbound_default_rules`，并丢弃 `mux_bridges` | `xray-core/src/outbound.rs:427-445` | 同一配置「静态写能通、动态 add 不通」：`targetStrategy: ForceIP*` 断链、无 policy 超时兜底、mux 不包、vless 的 BlockPrivate 默认规则缺失 | P2 | 动态构建复用静态装配的同一依赖包（把 dns/policy/mux 收集器作为参数传入），或明确记录并 fail-visible 拒绝这些字段 |
| DC-8 | `ListOutbounds`/`ListInbounds`/`ListRule` 只见壳不见配置 | 可观测缺口 | 回完整 config（Go `handlerServer.ListOutbounds`） | 只回 tag/type_url，`value` 恒空；`ListRule` 的 outboundTag 恒空 | `xray-core/src/functions.rs:674-694`（list_inbounds）、`:755-771`（list_outbounds）；`xray-app-commander/src/grpc.rs:701-710`；`xray-app-router/src/command/mod.rs:76` | 无法 `lso`/`lsi` 备份或核对线上配置；E1 `A4`、`G1` vs `R1` | P3 | 槽位保存原始 proto（`OutboundHandlerConfig`/`InboundHandlerConfig`）原样回吐；`Router` 增加 `list_rules_full() -> Vec<(tag, rule_tag)>` |
| DC-9 | `ruleTag` 必填 | 收紧语义 | 允许匿名规则 | `empty → invalid argument` | `xray-app-commander/src/grpc.rs:681-684`；`xray-app-router/src/router.rs:235-237` | 匿名规则无法动态添加（迁移自 Go 的脚本会失败） | P3 | 允许空 ruleTag（与 Go 一致），仅 `RemoveRule` 因无法定位而保留空串报错 |
| DC-10 | `AddOutbound` 重复 tag 的状态码 | 状态码 | `Code=Unknown(2)` | `AlreadyExists(6)` | `xray-app-commander/src/grpc.rs:170-178`（`existing tag found` → already_exists 映射） | 客户端按 Go 的 `Unknown` 分支做重试/提示时不匹配 | P3 | 与 Go 对齐或（更合理）保留 6 并同步文档/客户端；禁两处并存无说明 |
| DC-11 | 注册表满时 `add` 仅记日志 | 静默失败 | 无上界 | `insert_handler` error! 后 `add` 返回 `()` → API 200 | `xray-app-dispatcher/src/default.rs:2110-2116` | 假成功：handler 未注册但客户端认为已添加 | P3 | `add` 返回 `Result`，`register_outbound`/`add_outbound` 上抛 |
| DC-12 | `RemoveInbound` 只 cancel 不 join | 时序 | 锁内同步 `Close()` | 只发 cancel | `xray-core/src/inbound.rs:3176-3192`（对照 Go `app/proxyman/inbound/inbound.go:73-100`） | 返回成功时端口/任务可能仍在；立即重加同端口可能 EADDRINUSE（**E1 未复现**，`A6→A8` 成功） | P3 | `remove_inbound` 变 async，cancel 后 await 该 inbound 的 join（槽位存 `JoinHandle`，兼修 S2） |
| DC-13 | `register_user_manager` 的 remove+insert | 半途状态 | 无此形态（Go 直接写 manager map） | `slots.remove(tag)` → 改 → `insert` | `xray-core/src/inbound.rs:3215-3231` | 窗口内 tag 短暂消失；与 `remove_inbound` 交错时**复活已删除的 tag**（无监听器、不可再添加同 tag） | P2 | 槽位改 `RwLock` 内字段原位更新（不摘除键）；或改为 `slots.write()` 内直接 `get_mut` |
| DC-14 | 框架热更件零消费 | 死接线 | —— | `ConfigReloadListener` 仅被自身测试使用 | `xray-frame/src/reload.rs:376`（全仓无生产调用方） | 若文档/汇报称"支持配置热更"即为误导；两边实际都只能重启 | P3 | 要么接成 `run` 的一个显式开关（需 PM 拍板，因 Go 无此项属超集），要么件头标注"未接线"并在 CLAUDE.md 台账登记 |
| DC-15 | proxyman 域 `DefaultHandlerService` 是第二份实现 | 双实现漂移 | 只有一份 `handlerServer` | `proxyman` 域的 `add_outbound`/`remove_outbound`（需 registrar/factory；`remove_outbound` 在无 remover 时静默成功）与生产 `ApiHandlerService` 并存，且生产根本不注入它 | `xray-app-proxyman/src/command/mod.rs:502-537`；生产注入点 `xray-core/src/functions.rs:517-521` | 将来若误接该实现：`remove_outbound` 只校验后静默成功（不删 handler）→ 假成功 | P3 | 删掉 `DefaultHandlerService` 的 outbound 面或让它委托同一 `OutboundRuntime`；禁第二份语义 |

## 4 实测证据（E1）

环境：Windows 本机，端口段 28500-28549；每个用例独立进程，按 PID 结束。夹具与脚本：`round6/tmp/`（`srv_*.json`、`ob_*.json`、`user_*.json`、`rule_*.json`、`cli_vless.json`、`run_e1*.py`），原始日志 `round6/tmp/logs*/`。

- **A 组（Rust，`srv_dyn.json`：socks 28500 → 规则指向启动时不存在的 `late-out`；api gRPC 直听 28501）**
  - `A1` 加前：socks 回 success 后空载（与 Go `B1` 同形态）
  - `A2` `xray api add-outbound ob_late.json` → 0
  - `A3` 加后：**`RESULT=ok:PONG`** → 动态出站**立即被路由选中**
  - `A5` 重复添加 → `already exists: existing tag found: late-out`
  - `A6/A7/A8` add-inbound → remove-inbound → 立即重加同 tag/同端口 → **全部成功**（S3 未复现）
  - `A11/A12` `remove-outbound late-out` → 0；随后 socks 连接即回落失败 → 移除即时生效
  - `A13` `remove-outbound no-such` → `NOT_FOUND handler not found: no-such`（Go `B10` = 成功）
  - `A4` `list-outbounds` → `sender_settings: None, proxy_settings: None`（Go 回完整配置）
- **B 组（Go 26.10.17，同一份 `srv_dyn.json`）**：`B1` 空载 → `B2 ado` → `B3 ok:PONG` → `B4` 重复 → `Code=Unknown desc = existing tag found` → `B10` 删不存在 tag = 成功。**行为与 A 组逐条对齐，除 #3/#7/#18 项**
- **C/Q 组（vless 用户热更，Rust 服务端 `srv_vless.json`）**
  - `C1` `inbound-user-count vless-in` → `failed_precondition: proxy is not a UserManager`
  - `C2` `add-user user_vless.json` → `add user error: … proxy is not a UserManager | Added 0 user(s)`
  - `Q1/Q2/Q3`（Rust vless client 用新 uuid 打 Rust 服务端）：加前连不上 → `add-user` 报 NotUserManager → **加后仍连不上**
- **D 组（`sendThrough` 单变量，同一份 `ob_sendthrough.json`，`sendThrough=192.0.2.123` 非本机地址）**
  - Rust：`add-outbound` 成功 → probe **`OK:PONG`** = 仍从默认源 IP 直发（字段被丢）
  - Go：`ado` 成功 → probe **无数据**（连接尝试失败）= `sendThrough` 生效
- **E 组（legacy shadowsocks 用户热更，Rust）**：`inbound-user-count` 1 → `add-user` `ok` → count 2（表已更新；数据面未跑 ss 握手，标 INFERENCE）
- **G 组（Go RoutingService 真语义，`srv_api.json` 声明 `HandlerService` + `RoutingService`）**
  - `G1` `lsrules` → `{ruleTag: r0, tag: direct}`（含出站 tag）
  - `G2` `adrules rule_add.json`（**默认 shouldAppend=false**）→ `G3` 只剩 `r-new` = **整体替换**
  - `G4` `adrules -append` → `G5` `r-new` + `r-new2` 并存
  - `G6` `rmrules no-such` → 成功；`G7/G8` 删 `r-new` → 剩 `r-new2`
- **P 组（Go 服务端 vless 用户热更的"生效"端到端）**：`P1` 未注册 uuid 连不上 → `P2 adu` `Added 1` → `P3` count 2 → **`P4 ok:PONG`（新用户立刻可用）** → `P5 rmu` → `P6` count 1 → `P7` 新连接又被拒（**删用户对现有连接不生效、对新连接立即生效**，与 Go 语义一致）
- **R 组（Rust 声明 `RoutingService` 后仍全不可达）**：`R1 list-rules` / `R2 add-rule` / `R3 remove-rule` 一律 `UNIMPLEMENTED` —— 归 `lu37q`，本节仅作为 §1 #8/#9/#12 的"门"证据

## 5 守得住的（防误报/防回档）

- **AddOutbound 即时选路**：Rust 实测 `A3` PONG，与 Go 逐条一致 —— 不能按"动态出站不生效"报缺陷
- **RemoveOutbound 对在途连接**：Go 不 `Close`、Rust drop Arc，两边都不断已有连接（`B6`/`A11` 的 `A12` 只影响新连接）
- **balancer override**：override 优先、空串清除、不校验 target —— 与 Go `balancing.go:104-166` 完全一致（`balancing.rs:218-250`）
- **改配置是否落盘**：两边都不写回，重启即丢 —— parity
- **`remove_inbound` 后立即重加同 tag/端口**：E1 连续成功，S3 的 EADDRINUSE 窗口未复现（仅留 E2 机制）
- **`api add-user` 在部分用户失败时仍 exit 0**：Go `executeAddInboundUsers` 同样只计数不 `Fatalf` —— 属 parity，不算缺陷

## 6 未覆盖范围

- `SubscribeRoutingStats` / `TestRoute` 的流式与 `PublishResult` 语义（Rust 侧 `routing_stats` 生产恒 None，`grpc.rs:537-547`）—— 随 `lu37q` 一并处理
- wireguard / hysteria / masque 的 `AlterInbound` 用户面（本就随 DC-1 缺失，未单独实测）
- ss2022 / vmess 用户热更的 Go 侧实测（只读源码，未跑 E1）
- 动态 outbound 的统计计数器（`outbound>>>tag>>>traffic`）在 add/remove 后的注册与残留（属 stats 面，另票范畴）
- 多实例并发改同一资源的压测（本轮为单进程单客户端并发，未做线程压力）
- Linux 专属面（UDS listen 的 api、unix socket 的 client 连接）

## 7 自评（5 维，项目惯例）

| 维 | 分 | 依据 |
|---|---|---|
| 正确性 | 4.5/5 | 15 条 finding 全带 `file:line`；DC-1/2/3/5 有 E1 或 Go 源码双证；DC-12/S3 标注 E1 未复现 |
| 完整性 | 4/5 | 必查五面全覆盖（reload / outbound / routing / user / 持久化 + 半途状态）；未覆盖面见 §6 |
| 差异化 | 4.5/5 | 与 `ym0z8` / `lu37q` 显式划界；DC-3/4/9 标为「门后仍错」，非重报 |
| 可执行性 | 4/5 | 修法指向已有件（`reload_rules` / 单锁 `add_if_absent` / 复用静态构建参数） |
| 诚实度 | 5/5 | E1 贴原始命令与返回值；E2 推导与未复现项逐条标注 |
