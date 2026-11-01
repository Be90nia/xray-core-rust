# xray-conf 字段 → 生产消费点 全量台账审计（R1 接线普查）

- 分支/HEAD：`feature/fix-inbound-parity` @ `5fe98b90`
- 审计日期：2026-10-31
- 性质：只读审计（未改任何产品代码）
- 脚本（可复算，全部随报告落盘）：
  - `scripts/conf_field_ledger.py` —— 分母提取 + 三通道消费探测（生成 `fields.json` / `ledger.json`）
  - `scripts/json_key_probe.py` —— 纯 JSON key 字面量探测（交叉校验用）
  - `scripts/schema_drift.py` —— conf 声明键 vs 运行时实际读键的差集
  - `field-ledger.tsv` —— 342 行逐字段台账（struct / field / json_key / file:line / 三路命中数 / status）

复算命令（任一即可）：

```bash
python reports/audit-2026-10-31-perf-mem-wiring/scripts/conf_field_ledger.py
python reports/audit-2026-10-31-perf-mem-wiring/scripts/schema_drift.py
```

---

## 0. 流水线事实（本次审计最重要的前提，先钉住）

配置字段从 JSON 到运行期行为要过三跳，每跳都可能丢字段：

| 跳 | 位置 | 关键事实 |
|---|---|---|
| hop1 | `crates/xray-conf/src/config.rs:151` / `:185` | `inbounds[].settings` 与 `outbounds[].settings` 的类型是 **`Option<Value>`（原始 JSON）**，不是 `InboundSettings`/`OutboundSettings` |
| hop2 | `crates/xray-conf/src/built.rs:193` / `:258` | `build()` 把 `settings` 的原始 Value **原样 `serde_json::to_vec`** 塞进 `BuiltEntry.data` |
| hop3 | `crates/xray-core/src/arm_builders/inbound.rs` / `outbound.rs`、各协议 crate | 运行期用**自己的**结构体 / `v.get("key")` 重新解析 `BuiltEntry.data` |

**推论（贯穿全报告）**：`crates/xray-conf/src/protocols.rs` 里 45 个协议 settings 结构体（约 240 字段）**不在生产数据路径上**，只有 `secrets.rs`（凭据掩码）与测试消费它们。因此：

- 协议 settings 字段「未接线」**不会**导致配置失效（数据走原始 JSON 透传）；
- 但它使 `protocols.rs` 变成一张**无法自证真伪的平行 schema**——键名写错、字段缺失、结构与 Go 脱节，运行期全无感知（见 F5）。

而 `sniffing` / `mux` / 各 app 段（log/policy/dns/…）**是**强类型的（`config.rs:162`、`:197`、`Config` 的 app 字段），`build()` 会把它们重新序列化成 JSON 再交给下游 —— 这些段才有真正的「键名漂移即静默丢值」风险。

---

## 1. 台账规模（分母）

| 项 | 数 | 说明 |
|---|---|---|
| xray-conf 结构体总数 | **78** | `config.rs` / `app_config.rs` / `protocols.rs` / `common.rs` / `built.rs` |
| 字段总数（分母） | **342** | 脚本 `conf_field_ledger.py` 解析，含 `serde rename` / `alias` / `rename_all` 归一 |
| ↳ 配置 JSON schema 字段 | 292 | 参与 hop1 解析 |
| ↳ 内部构建产物字段 | 50 | `BuiltEntry`/`BuiltInbound`/`BuiltOutbound`/`BuiltConfig` 等 hop2 中间态（无 serde，靠 Rust 字段访问消费） |
| 在**非 xray-conf 生产代码**中有消费证据 | **287** | 三通道任一命中：JSON key 字面量 / 运行时 serde 键 / 同 crate 对该 conf 类型的字段访问 |
| 自动判定 NOT-WIRED | **5** | 见 §2，逐条人工复核 |
| 人工复核后「真断线」 | **4** | 其中 1 条与 Go 行为一致（降级 P3 说明） |
| 「结构性有消费但功能上是死值」 | **3** | 见 §3（自动探测抓不到的一类，必须人工判） |

三通道命中分布（脚本输出原文）：

```
json fields consumed at runtime=287 NOT-WIRED=5
  via JSON-key literal : 250
  via runtime serde key: 58
  via typed conf struct: 37
```

> 三通道的必要性：只看 JSON key 字面量会漏掉 37 个「消费方直接用 `xray_conf::app_config::XxxConfig` 反序列化再读字段」的字段（`xray-core/src/register.rs` 就是这种形态）；只看字段名会漏掉 `rename_all = "camelCase"` 生成的键（源码里没有字面量）。

---

## 2. Findings（8 列台账）

**一览表（严格 8 列，明细见下方逐条）**

| 标题 | 严重度 | 位置 file:line | 现状 | 断裂点 | 生产可达性证据 | 建议修法 | 复现/验证 |
|---|---|---|---|---|---|---|---|
| F1 geodata `outbound` 死值：资产下载永不走配置出站 | **P1** 安全/静默失效 | `xray-conf/src/app_config.rs:215` → `xray-core/src/register.rs:965` → `xray-app-geodata/src/config.rs:26` → `register.rs:929` / `downloader.rs:159-176` | 字段被映射进运行时 `GeodataConfig`，但下载器 `RealAssetDownloader` 无 dispatcher；`outbound` 仅出现在 getter/to_proto/测试 | hop3 运行期消费断（警告/错误位也不可达） | `git grep -nE 'outbound' -- crates/xray-app-geodata/src/` 无读取点；`GeodataError::MissingDispatcher`（`error.rs:11`）全仓从未构造；Go `app/geodata/geodata.go:34-40` 走 tagged dispatcher | 给下载器注入 dispatcher（或 tagged dialer 包装），`outbound` 非空无 dispatcher → 硬错（对齐 Go 拒启） | 配 `geodata.outbound:"proxy"` + 夜间 cron → 抓包见下载直连，不经 proxy |
| F2 `metrics.tag` 死值：只配 tag 时 metrics 永不可达且不报错 | **P2** 功能静默缺失 | `xray-conf/src/app_config.rs:239` → `register.rs:457` → `xray-app-metrics/src/config.rs:13,34` | `tag` 只参与 `validate()` 非空检查，从不注册 dispatch handler（对比 commander `commander.rs:642`） | hop3：解析✓ 映射✓ 校验✓ handler 注册✗ | `git grep -nE '\btag\b' -- crates/xray-app-metrics/src/` 仅字段/getter/无关局部变量；`register.rs:454` 注释自认“只保字段不丢” | 接 handler 注册（tag→路由可达）；或 tag 非空且 listen 空时启动硬错 | `{"metrics":{"tag":"metrics"}}` 启动 → 无监听、无告警 |
| F3 `metrics.tags` 完全死字段 | **P3** 债务 | `xray-conf/src/app_config.rs:159` | 解析后无人读；运行时 `MetricsConfig` 无此字段；转 proto 时丢弃 | hop3（且映射缺失） | `git grep -nE '\btags\b' -- crates/xray-app-metrics/src/` 仅 `debug.rs:145-175` 局部变量 | 删字段（配置面少一个骗人旋钮）或落地实现 | `git grep -rn '"tags"' -- crates/`（除 conf 外 0 命中） |
| F4 凭据掩码仅 4 族；8 个生产协议凭据永不进掩码表 | **P2** 安全防线不完整 | `xray-conf/src/secrets.rs:58-94,110-140`；`protocols.rs:1396`/`:1374` | `collect_*` 只 match vmess/vless/trojan/ss，其余 `_ => {}`；hysteria 有 `auth` 结构体却无收集臂 | 装配期：`install_secret_masking`（`functions.rs:152`，默认路径 `:201→:275`）拿到的集合天然缺失 | `arm_builders/mod.rs:213-274` 生产含 anytls/tuic/naive/wireguard；`protocols.rs:1396` 对它们返回 None；无 Go 对照（本仓自定约束 ⑪） | 补 Hysteria/Socks/Http 臂；anytls/tuic/naive/wg 补结构体或从原始 JSON 收集；`_ => None` 加 debug 说明 | `collect_secrets(build(cfg))` 对 anytls `password` / hysteria `auth` 返回空 |
| F5 协议 schema（45 结构体）不在生产路径，漂移无法被发现 | **P3** 债务 | `config.rs:151,185`；`built.rs:193,258`；`protocols.rs` 全量 | `settings` 是 `Option<Value>` 原样透传；`dispatch_*_settings` 仅 `secrets.rs`+测试调用 | hop1 分支路径根本不走 typed schema | `git grep dispatch_inbound_settings` → xray-conf 外零调用；`schema_drift.py`：hysteria 3 vs 16、http 4 vs 14、ss 7 vs 15、vless 6 vs 23 键 | 二选一：让 `build()` 真走 schema（需先补 8 协议）；或把 `protocols.rs` 降级为“凭据抽取器”并删非凭据字段 | `python …/scripts/schema_drift.py` |
| F6 `FreedomOutboundSettings` 键名错 ×2 + `ipsBlocked` 警告从未实现 | **P3** | `protocols.rs:1104`(target_strategy) `:1147`(apply_to) `:1119`(ips_blocked) | conf 声明 `target_strategy`/`apply_to`（Go 为 `targetStrategy`/`applyTo`），`_blocked` 注释承诺 Build 警告但无实现 | 键名：hop1 错源（无行为损失）；警告：hop2 阶段缺失 | `git grep -nE 'ipsBlocked' -- crates/` = 1（仅定义）；运行期读 `targetStrategy`（`outbound.rs:1143`）/`applyTo`（`xray-proxy-freedom/config.rs:440`）；Go `freedom.go:58/20/43` | 补 `rename`；`ValidationStage` 补 ipsBlocked warn | `git grep -c ipsBlocked crates/` |
| F7 `VLessOutboundSettings.seed` 死字段（**与 Go 一致**） | **P3** 说明 | `protocols.rs:355` | 无消费；Go 同样（赋值语句被注释） | 无（有意） | Go `infra/conf/vless.go:300` 为 `//account.Seed = c.Seed` | 无需修；可删 | 同上 |
| F8 `routing.ruleSet` 解析校验后丢弃（Go 完全不懂该键） | **P3** | `wiring.rs:1019-1090` | 构造 `RuleSetRegistry` 后函数结束即 drop；proto 无引用字段 | hop3：解析✓ 校验✓ 路由应用✗ | `git grep -nE 'ruleSet|RuleSet' -- Xray-go/infra/conf Xray-go/app/router` = 0 命中 | 保持；若要逐字对齐 Go 则硬错降级为 warn | 带非法 ruleSet 项 → Rust 拒启、Go 正常启动 |


> 生产可达性列的证据均为本次实跑的命令输出或逐行阅读的结论；`[INFERENCE]` 标注的为推断。

### F1 —— `geodata.outbound` 是死值：地理资产下载永不走配置出站

| 列 | 内容 |
|---|---|
| **标题** | geodata `outbound` 被解析、被映射进运行时配置，但下载器没有任何 dispatcher，配置的出站标签从未被使用 |
| **严重度** | **P1**（静默失效 + 隐私向：绕过用户指定的代理出站） |
| **位置** | 解析 `crates/xray-conf/src/app_config.rs:215` → 映射 `crates/xray-core/src/register.rs:965` → 运行时字段 `crates/xray-app-geodata/src/config.rs:26` → **下载器无 dispatcher**：`crates/xray-core/src/register.rs:929` + `crates/xray-app-geodata/src/downloader.rs:159-176` |
| **现状** | `register.rs:965` 把 `outbound` 写进 `xray_app_geodata::GeodataConfig.outbound`；`GeodataConfig` 对该字段只有 `from_proto`/`to_proto`/测试（`config.rs:34,42,78,91,100,119`），全 crate 无任何读取点；装配处 `Arc::new(RealAssetDownloader::new(default_asset_dir()))`（`register.rs:929`）不传 dispatcher，`RealAssetDownloader` 只有 `asset_dir/timeout/clock` 三个字段（`downloader.rs:167-175`），文档自述“不走 dispatcher dial（Go 走 tagged dialer）”（`downloader.rs:159`） |
| **断裂点** | **hop3（运行期消费）**：`parse ✓ → BuiltConfig ✓ → Instance 装配 ✓ → 下载拨号 ✗`。补强证据：`GeodataError::MissingDispatcher`（`crates/xray-app-geodata/src/error.rs:11`）在**全仓从未被构造**——这个错误变体本身就是“本该有 dispatcher”的化石 |
| **生产可达性证据** | `python -c "subprocess git grep -nE 'outbound' -- crates/xray-app-geodata/src/"` → 仅 `config.rs` 的 getter/to_proto/tests + `error.rs:13` 的错误文案，**无消费者**。Go 对照：`app/geodata/geodata.go:34-40` 拿 `routing.Dispatcher` 后 `newDownloader(ctx, dispatcher, config.Outbound)`；拿不到即 `errors.New("failed to get dispatcher for geodata downloader")` |
| **建议修法** | 给 `RealAssetDownloader` 注入 dispatcher（或上层包装一个走 tagged dialer 的 `AssetDownloader`），并在 `outbound` 非空且无 dispatcher 时返回已存在的 `MissingDispatcher` 硬错（对齐 Go 拒启） |
| **复现/验证** | 配置 `{"geodata":{"cron":"0 3 * * *","outbound":"proxy","assets":[{"url":"https://github.com/x","file":"geoip.dat"}]}}` → 启动 → 观察日志/抓包：下载直连目标域名，不经 `proxy` 出站；`grep -rn "outbound" crates/xray-app-geodata/src/` 无读取点 |

---

### F2 —— `metrics.tag` 是死值：只配 tag（Go 合法且可用）时 metrics 永不可达，且启动不报错

| 列 | 内容 |
|---|---|
| **标题** | metrics 的 `tag` 只参与“非空校验”，从不注册 dispatch handler；`{"metrics":{"tag":"metrics"}}` 静默变成“什么都没起” |
| **严重度** | **P2**（功能静默缺失；配置被接受、无日志、无监听） |
| **位置** | 解析 `crates/xray-conf/src/app_config.rs:239` → 装配 `crates/xray-core/src/register.rs:457` → 运行时 `crates/xray-app-metrics/src/config.rs:13` + 校验 `:34` |
| **现状** | `register.rs:455-470` 把 `tag`/`listen` 灌进 proto → `MetricsConfig`；该 crate 内 `tag` 仅出现在 `from_proto`/`to_proto`/`validate()`；真正起监听的是 `listen`（`MetricsFeature::start` → `TokioHttpServer`） |
| **断裂点** | **hop3**：`parse ✓ → proto ✓ → validate ✓ → handler 注册 ✗`。对比 `api` 的正例：`crates/xray-app-commander/src/commander.rs:642` 有 `reg.add_dispatch_handler(&self.tag, handler)`，metrics 侧没有对应物 |
| **生产可达性证据** | `git grep -nE '\btag\b' -- crates/xray-app-metrics/src/` → `config.rs` 的字段/getter/测试 + `metrics.rs` 里**无关**的 `tag`（counter 名解析、`remove(&self, tag: &str)`）。源码注释自认：`register.rs:454`“hfwq：…handler 供路由暴露属架构接线…此处只保字段不丢” |
| **建议修法** | 二选一：① 接上 handler 注册（tag → 路由可 `outboundTag: "metrics"` 取到 `/metrics`）；② 若短期不做，`tag` 非空而 `listen` 为空时**启动硬错**（否则配置语义与 Go 相反：Go 能通，Rust 全静默） |
| **复现/验证** | 配置 `{"metrics":{"tag":"metrics"},"routing":{"rules":[{"type":"field","domain":["localhost"],"outboundTag":"metrics"}]}}` → 启动后 `curl 127.0.0.1:<port>/metrics` 无服务；日志无任何告警 |

---

### F3 —— `metrics.tags`（Rust 扩展）是完全死字段，文档却暗示有行为

| 列 | 内容 |
|---|---|
| **标题** | `MetricsConfig.tags: Option<Vec<String>>` 解析后无人读；运行时 `MetricsConfig` 根本没这个字段 |
| **严重度** | **P3**（债务：配置项谎报能力） |
| **位置** | `crates/xray-conf/src/app_config.rs:159` |
| **现状** | 文档注释“Rust 扩展：是否在 metrics 中包含 tag 标签。”；`register.rs:455-470` 在转 proto 时直接丢弃（proto `Config` 只有 tag/listen）；`crates/xray-app-metrics/src/config.rs:12-15` 只有 `tag`/`listen` |
| **断裂点** | hop3 且更早：连映射都没写，字段从 hop1 之后即死 |
| **生产可达性证据** | `git grep -nE '\btags\b' -- crates/xray-app-metrics/src/` → 仅 `debug.rs:145-147,173-175` 的**局部变量** `tags`（排序用），与配置无关 |
| **建议修法** | 删除该字段（配置面少一个骗人的旋钮）；或实现后在 proto+metrics 输出里落地 |
| **复现/验证** | `git grep -rn '"tags"' -- crates/`（除 xray-conf 外 0 命中） |

---

### F4 —— 凭据掩码只覆盖 4 族；8 个生产协议的凭据永不进掩码表，且未知协议静默跳过（无告警）

| 列 | 内容 |
|---|---|
| **标题** | 坑约束 ⑪「密钥必掩码」的实现只覆盖 vmess/vless/trojan/shadowsocks；hysteria/socks/http/tuic/anytls/naive/wireguard 的凭据（password/uuid/secretKey/PSK）从不进掩码表，`dispatch_*_settings` 对它们返回 `None` 且**不 warn** |
| **严重度** | **P2**（防线不完整；当前无已知泄露站点，属“下一行日志就漏”的债） |
| **位置** | `crates/xray-conf/src/secrets.rs:58-94`（入站 4 臂 + `_ => {}`）、`:110-140`（出站同样 4 臂）；`crates/xray-conf/src/protocols.rs:1396`（入站 `_ => None`）、`:1374`（出站 `_ => None`） |
| **现状** | `collect_inbound`/`collect_outbound` 只 match Vmess/Vless/Trojan/Shadowsocks，其余 `_ => {}` 静默；`HysteriaInboundSettings` 虽在 `protocols.rs:293` 有 `HysteriaUserConfig.auth`，但 `collect_inbound` **没有 Hysteria 分支**（= 结构体存在、分发存在、收集臂缺失） |
| **断裂点** | hop2 之后（装配期）：`install_secret_masking`（定义 `crates/xray-core/src/functions.rs:152`）拿到的集合天然缺 8 个协议。**两条生产入口都调用它**：默认 CLI 路径 `start_full` → `start_full_dispatched`（`functions.rs:201` → `:275`）；`start_instance` 路径 `start_from_built`（`functions.rs:921` → `:175`）。→ 不是“没接线”，而是“接线了但覆盖不全” |
| **生产可达性证据** | 生产入站表 `crates/xray-core/src/arm_builders/mod.rs:213-274` 含 `anytls/tuic/naive/wireguard/dns/loopback/freedom/tun`；`dispatch_inbound_settings`（`protocols.rs:1382-1398`）对它们一律 `_ => None`。对照 Go：Go 无凭据掩码机制（`maskAddress` 只掩 IP），故此项**无 Go 对照组**，判据是本项目自定约束 ⑪ |
| **建议修法** | 补 Hysteria/Socks/Http 收集臂（结构体已在手）；anytls/tuic/naive/wireguard 补 settings 结构体或直接从原始 JSON 收集（`password`/`uuid`/`secretKey`/`preSharedKey`）；`_ => None` 分支加一次 `debug!` 说明“该协议无掩码覆盖”，避免静默 |
| **复现/验证** | 配 `{"inbounds":[{"protocol":"anytls","port":1,"settings":{"clients":[{"password":"SECRET1"}]}},{"protocol":"hysteria","port":2,"settings":{"clients":[{"auth":"SECRET2"}]}}]}` → `python -c` 调 `xray_conf::collect_secrets(&cfg.build().unwrap())` → 返回集合不含 `SECRET1`/`SECRET2` |

---

### F5 —— `protocols.rs` 整张协议 schema 不在生产路径上：键名/字段与现实脱节且无任何机制能发现

| 列 | 内容 |
|---|---|
| **标题** | 45 个协议 settings 结构体（≈240 字段）只有 `secrets.rs` 与测试消费；`build()` 用原始 `Value` 透传，故该 schema 的错误永远不会表现为行为错误，只会累积漂移 |
| **严重度** | **P3**（债务；但它是 F6 与后续一切“schema 谎报”的根因） |
| **位置** | `config.rs:151`/`:185`（`settings: Option<Value>`）、`built.rs:193`/`:258`（`to_vec`）、消费方 `lib.rs:60`（仅导出给 secrets/测试） |
| **现状** | `git grep -n dispatch_inbound_settings` → 除 `xray-conf` 自身与 `secrets.rs` 外**零调用**；运行期一律自己解析原始 JSON |
| **断裂点** | hop1 的分支路径：`Config::build` 根本不走 `dispatch_*_settings` |
| **生产可达性证据** | 漂移量化（`scripts/schema_drift.py` 输出）：`HysteriaInboundSettings` conf 声明 3 键 / 运行时读 16 键；`HttpInboundSettings` 4 / 14；`ShadowsocksInboundSettings` 7 / 15；`VLessInboundSettings` 6 / 23。反向错键实例见 F6。同一脚本还显示运行期读 `testpre` 而 conf 声明 `testseed`（`protocols.rs:355` 一带）——两者并存说明谁都没在对拍 |
| **建议修法** | 二选一并写进纪律：① 让 `build()` 真走 `dispatch_*_settings → serialize`（schema 变成生产闸，错键立刻暴露，但需先补齐 8 个协议）；② 明确降级 `protocols.rs` 为“仅 secrets 用的抽取器”，把非凭据字段统统删掉，避免它看起来像校验器 |
| **复现/验证** | `python reports/audit-2026-10-31-perf-mem-wiring/scripts/schema_drift.py` |

---

### F6 —— `FreedomOutboundSettings` 三个字段的键名与现实不符；`ipsBlocked` 的“Build 期警告”从未实现

| 列 | 内容 |
|---|---|
| **标题** | `target_strategy`（应为 `targetStrategy`）、`NoiseConfig.apply_to`（应为 `applyTo`）两处键名错；`ips_blocked` 注释承诺“保留字段用于触发 Build 阶段警告”，全仓无任何警告 |
| **严重度** | **P3**（无行为损失——运行期从原始 JSON 读正确键；但注释谎报、Go 的弃用警告在 Rust 侧缺失） |
| **位置** | `crates/xray-conf/src/protocols.rs:1104`（`pub target_strategy`，无 rename）、`:1119`（`ips_blocked`，rename `ipsBlocked`）、`:1147`（`apply_to`，无 rename） |
| **现状** | 三个字段在 conf 侧都“声明好了”；运行期实际读键分别是 `xray-core/src/outbound.rs:1143-1146`（`targetStrategy` 优先、回落 `domainStrategy`，Go freedom.go:62-64 对齐）、`xray-proxy-freedom/src/config.rs:440`（`applyTo`，含 `Invalid applyTo` 硬错）；`ipsBlocked` 在 `crates/` 非 conf 代码里 **0 命中** |
| **断裂点** | `target_strategy`/`apply_to`：hop1（conf 声明键与 Go 配置键不同源，属 schema 错）；`ips_blocked`：hop2/3（应当存在的 Build 警告阶段缺失） |
| **生产可达性证据** | `git grep -nE 'ipsBlocked' -- crates/` → 仅 `protocols.rs:1118`。Go 对照：`infra/conf/freedom.go:58` `errors.LogWarning(...The feature "ipsBlocked" has been removed and migrated to "finalRules"...)`；`:20` `TargetStrategy string \`json:"targetStrategy"\``；`:43` `ApplyTo string \`json:"applyTo"\`` |
| **建议修法** | `target_strategy` 加 `#[serde(rename = "targetStrategy")]`（或直接删，因生产不用）；`apply_to` 加 `rename = "applyTo"`；`ipsBlocked` 在 `ValidationStage` 里补一条 warn（与 Go 同文案级） |
| **复现/验证** | `git grep -c 'ipsBlocked' crates/` = 1（仅定义）；`git grep -n '"targetStrategy"' crates/xray-core/src/outbound.rs` 证明运行期用的是另一套键 |

---

### F7 —— `VLessOutboundSettings.seed` 死字段（**与 Go 一致**，非缺陷，仅备案）

| 列 | 内容 |
|---|---|
| **标题** | `seed` 解析后无人消费；Go 侧同样如此（赋值语句被注释掉） |
| **严重度** | **P3 说明**（不计缺陷） |
| **位置** | `crates/xray-conf/src/protocols.rs:355` |
| **现状** | 全仓非 conf 代码对它无结构化消费（唯一 84 处命中是 `seed` 在 crypto/CLI 的无关同名变量） |
| **断裂点** | 无（有意为之） |
| **生产可达性证据** | Go `infra/conf/vless.go:252` 定义 `Seed string \`json:"seed"\``，`:300` 为 `//account.Seed = c.Seed`（已注释）→ 两侧都是“解析但不使用” |
| **建议修法** | 无需修；若要清爽可删该字段 |
| **复现/验证** | `git grep -n 'Seed' D:/Project/Xray-core/infra/conf/vless.go`（见 `:300` 注释行） |

---

### F8 —— `routing.ruleSet` 解析+校验后被丢弃（与 Go 同为忽略，但 Rust 会硬错拒启）

| 列 | 内容 |
|---|---|
| **标题** | `ruleSet` 数组被完整解析、校验（tag 重复/缺失、类型/格式合法性）后构造的 `RuleSetRegistry` 随即被丢弃——proto 无引用字段，路由永不使用它 |
| **严重度** | **P3**（不改变行为，但与 Go 的“静默忽略”相比是**反向拒绝**差异：Go 里能起来的配置在 Rust 会拒启） |
| **位置** | `crates/xray-core/src/wiring.rs:1019-1090`（`let mut registry = RuleSetRegistry::new()` 局部构造，函数结束即 drop） |
| **现状** | 注释已自认“proto 暂未升级支持 `RoutingRule.rule_set` 引用字段…故 Registry 不会被 Router 使用；但配置错误必须现在就暴露” |
| **断裂点** | hop3：解析 ✓ → 校验 ✓ → 路由应用 ✗ |
| **生产可达性证据** | `git grep -nE 'ruleSet|RuleSet' -- D:/Project/Xray-core/infra/conf/ D:/Project/Xray-core/app/router/` → **0 命中**（Go v26.10.17 完全不支持 ruleSet，连键都不认识，因而静默忽略） |
| **建议修法** | 保持现状即可；若追求与 Go 逐字一致，把硬错降级为 warn（反之若计划实现 ruleSet，则在 proto 补齐前别硬错） |
| **复现/验证** | 配置 `{"routing":{"ruleSet":[{"tag":"rs"}]}}` → Rust 启动、路由无任何 ruleSet 行为；带非法项（如 `"type":"bogus"`）Rust 拒启、Go 正常启动 |

---

## 3. 抽样反向核对（15 个「有消费点」字段，逐条验证落在**生产主路**）

判据：消费点必须在**默认 `xray.exe run -c`** 的调用链上（`Config::build` → `start_full`/`start_from_built` → 各 runtime），不能只在测试或 trait 默认实现里。

| # | 字段 | 消费点（file:line） | 生产链路验证 | 结论 |
|---|---|---|---|---|
| 1 | `Config.log` | `built.rs:168` push_app → `instance.rs:143` 查注册表 → `register.rs:262-301` → `xray-app-log/instance.rs:921` | `register_all_features` 注册 `"log"`（`register.rs:35`） | PASS |
| 2 | `MuxConfig.enabled` | `outbound.rs:607-614`（`if !cfg.enabled → None`） | `try_build_handler` ← `register_outbounds` ← `start_full` | PASS |
| 3 | `MuxConfig.concurrency` | `outbound.rs:581` + `:607-614`（0→8，<0 不包装） | 同上 | PASS |
| 4 | `MuxConfig.xudp_concurrency` | `outbound.rs:628-642` 三态 → `:588-590` | 同上；另有 `proxyman/outbound/handler.rs:216` gRPC 路径 | PASS |
| 5 | `MuxConfig.xudp_proxy_udp_443` | `outbound.rs:544`/`:655` `Udp443Policy::from_mux` → dispatcher UDP443 门 | 同上 | PASS |
| 6 | `SniffingConfig.enabled/metadata_only/route_only/dest_override` | `wiring.rs:282-286`（`sniffing_request_from_json`） | 调用点 `inbound.rs:2979`（`per_inbound_ohm`）← `start_inbound:3154` ← `spawn_inbounds` ← `start_full` | PASS |
| 7 | `PolicyLevel.handshake/conn_idle/uplink/downlink` | `register.rs:475-495`（→proto）→ `xray-app-policy/convert.rs:33-57` → `manager` | `register_all_features` 注册 `"policy"`（`register.rs:38`）；入站握手超时经 `handshake_timeout` 消费（`inbound.rs:664+`） | PASS |
| 8 | `PolicyLevel.buffer_size` | `register.rs:502-510`（KB×1024 / 负值 -1）→ `policy::Buffer` | 同上 | PASS |
| 9 | `PolicySystem.stats_*` | `register.rs:515-530`（→`SystemPolicy.stats`） | 同上 | PASS |
| 10 | `LogConfig.loglevel/access/error/dnsLog/maskAddress/format` | `register.rs:270-301`；`enable_dns_log` → `app-log/instance.rs:780`；`format` → `instance.rs:921`/`:769`/`:795` | `start_from_built` → `Instance::new_from_built` 建 app | PASS |
| 11 | `ApiConfig.tag/listen/services` | `register.rs:738-780`；tag → `commander.rs:642` `add_dispatch_handler` | `register_all_features` 注册 `"api"`（`register.rs:42`） | PASS |
| 12 | `FakeDnsConfig.ipPool/poolSize/pools` | `register.rs:820-843` → `HolderMulti::new` | `register_all_features` 注册 `"fakeDns"`（`register.rs:43`） | PASS |
| 13 | `VersionConfig.min/max` | `register.rs:1001-1002` → `VersionFeature::new`（约束不满足 → 硬错） | 同上（`"version"`） | PASS |
| 14 | `GeodataConfig.cron/assets` | `register.rs:925`+`:945` → `map_geodata_config`（cron 合法性、https、本地文件存在性硬校验） | 同上（`"geodata"`） | **PASS（cron/assets）** / 同结构 `outbound` **FAIL = F1** |
| 15 | `ObservatoryConfig.probeURL/probeInterval/enableConcurrency/subjectSelector` | `register.rs:396-410` → `observer.rs:258`（`effective_probe_url`）、`:117`（并发）、`:282`（间隔） | 同上（`"observatory"`） | PASS（附 P3：`probeInterval` 复合时长 `"1m30s"` 解析失败 → `unwrap_or(0)` → 静默回落默认，`register.rs:396-401` + `config.rs:176`） |

**协议 settings 抽样**（走原始 JSON，不经 conf 类型）：`SocksInboundSettings.auth/accounts` → `inbound.rs:4507-4526`（生产 socks 解析，Go socks.go:54-56 优先级已对齐）——PASS；`ShadowsocksInboundSettings.method` → `inbound.rs:3025`——PASS；`VLessInboundSettings.fallbacks` → `inbound.rs:4662`——PASS；`TrojanInboundSettings.clients` → `arm_builders/inbound.rs:233`——PASS；`DnsOutboundSettings.servers` → `outbound.rs:1034` + `xray-app-dns/jsonconf.rs`——PASS；`LoopbackOutboundSettings.inboundTag` → `outbound.rs:3212`——PASS。

**自动探测的 1 个假阳性（记录在此以免后人重跑）**：`OutboundDetourConfig.proxySettings`（`config.rs:193`）被脚本判为 NOT-WIRED，因为它作为**conf 内部字段**被 `build()` 投影到 `BuiltOutbound.proxy_settings_json`（`built.rs:287`），消费点是 `outbound.rs:476` 的 Rust 字段访问，字面量 `"proxySettings"` 在运行期代码中不出现。→ 实际 **PASS**（`normalize_outbound_proxy` 还额外做了 Go `transportLayer` 注入与 tag 冲突硬错，`built.rs:333-400`）。

**抽样小结**：15 项中 14 PASS、1 FAIL（F1）；协议 settings 6 项全 PASS。生产主路的字段消费质量整体良好——问题集中在**单个 app 的个别字段**（F1/F2/F3）与**schema 层整体**（F5/F6），而不是散点式“写了没接”。

### 3.1 已有的窄域防线（值得推广，别再造新机制）

`crates/xray-core/src/outbound.rs:1994-2027` 已经有一个正确形态的守卫：

```rust
const DNS_OUTBOUND_KNOWN_KEYS: &[&str] = &[ …17 个键… ];
fn warn_unknown_dns_outbound_keys(v: &Value) { … tracing::warn!(keys = ?unknown, "…") }
```

它把“运行期实际认的键”写成显式清单，未知键 warn 留痕（对应 Go 默认静默忽略的差异被显式化）。**目前只有 dns outbound 有这一层**；`xray-conf/src/protocols.rs:1320` 里那份是同一逻辑的 conf 侧副本（两处重复维护同一张表，属可合并项）。

> 由“多行 tracing 宏”扫描确认：全仓 803 个日志站点里，只有 8 个在日志里提到 `settings`，且均为**键名**（`keys = ?unknown`）或 `network/security/users计数`——**没有任何站点打印 settings 值**。这是把 F4 从 P1 降到 P2 的直接依据。

---

## 4. 我查了什么 / 没查什么

**查了**

- `crates/xray-conf/src/` 全部 78 个结构体、342 个字段（脚本可复算），三通道消费探测 + 5 条 NOT-WIRED 人工逐条复核定责。
- 三跳流水线的**真实形态**（`settings: Option<Value>` 透传 vs 强类型 app 段），并据此重排判据（这是本次审计最关键的校正：若按“conf 结构体即 schema”的直觉审，会把 5 个真问题埋进 42 个假阳性里）。
- app 装配枢纽 `xray-core/src/register.rs` 十二个 factory 的逐字段映射（log/dns/routing/policy/api/metrics/stats/fakeDns/observatory/burstObservatory/version/geodata），并追到各 app crate 的读取点。
- `built.rs` 的入/出站投影（tag/port/listen/streamSettings/sniffing/mux/proxySettings/sendThrough/targetStrategy）逐一验证有运行期消费。
- 路由 JSON 方言：`wiring.rs:772-1100` 与 Go `infra/conf/router.go` 逐键对照（domain/domains/domainSuffix/domainKeyword/domainRegex/ip/sourceIP/source/localIP/localPort/port/sourcePort/vlessRoute/network/user/inboundTag/protocol/process/localOS/attrs/webhook/ruleTag/balancers{tag,selector,strategy{type,settings},fallbackTag}）——**未发现 Go v26.10.17 支持而 Rust 缺失的键**（`domainMatcher` 在 Go 侧也不存在）。
- 凭据掩码面：`collect_secrets` → `install_secret_masking`（`functions.rs:152`）在生产 `start_from_built` 首步调用，链路真实；缺口在协议覆盖。
- 803 个日志站点定向扫描，确认**当前**无任何站点打印 settings/凭据（这是判 F4 严重度从 P1 降到 P2 的直接依据）。

**没查 / 超范围**

- **配置语义正确性**（非目标）：键名对得上≠换算对，例如 policy `bufferSize` 的 KB→字节/溢出语义、`PortList` 解析的 Go 兼容性，均未审。
- **streamSettings 内部各传输（ws/grpc/xhttp/reality 等）的字段消费**（R2 另派）——本次只验证了 `stream_settings_json` 这一个投影字段有消费。
- **`xray-cli` 的 `framework-assembly` 目标主路**逐字段（尚未进默认构建）：只抽查了 `sniffing_request_from_json` / mux 相关。
- **gRPC 动态配置路径**（commander `AddInbound/AddOutbound/AlterInbound`）的字段覆盖：只确认 `built_outbound_from_proto` 会把 `target_strategy`/`mux_json` 置 `None`（`outbound.rs:476-481` 已注明 bd bqm 差异项），未逐字段展开。
- **`common.rs` 自定义 Deserialize 类型**（`Address`/`PortList`/`StringList`/`NetworkList`/`Int32Range`）的边界语义（空串、非法 CIDR、极值）。
- **TOML/YAML 装载路径**（`toml_config.rs`/`yaml.rs`）与 `load_file` 的扩展名分派。
- 未编译、未跑测试（只读审计，按派单约束）；所有结论基于源码阅读 + 脚本统计 + Go 侧 grep 对照，无运行期观测。

---

## 5. 一句话结论

字段级台账 342 行里，**只有 4 个真断线 + 3 个死值**，散点质量远好于预期；真正值得登记的系统性问题是 **F1（geodata 出站被静默绕过，P1）**，以及 **F5/F6 揭示的结构性事实：`protocols.rs` 那张 240 字段的协议 schema 不在生产路径上，它的错永远不会变成行为错，也永远不会被测试抓到**。
