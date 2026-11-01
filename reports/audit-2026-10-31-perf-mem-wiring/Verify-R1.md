VERDICT: FAIL
DONE_WITH_CONCERNS

# 审查报告：静默降级/接线缺口 11 条断言 · 第二轮独立对抗复核

> 裁决统计：**CONFIRMED 9 / REJECTED 1 / ADJUSTED 1**
> 三条最重要：**V1（路由降级致屏蔽规则失效，E1 双向实证）**、**V3（freedom finalRules 单条坏 IP → 全阻断，E1 实证）**、**V7（第一轮机制判断错误：不存在 catch-all，但「Rust 降级 vs Go 拒启」属实，须并入 V1）**

## 0. 方法与取证基线

|项|值|
|---|---|
|Rust 二进制|`target/release/xray.exe`（2026-10-31 11:00，`xray 26.10.11`，git `5fe98b90`）——仓库内最新，`dist/xray.exe`（10-13）弃用|
|Go 基线|**本机实编**：`cd D:/Project/Xray-core && go build -o D:/tmp/verify-r1/xray-go.exe ./main` → `Xray 26.10.17 ... 92ccc93-dirty (go1.27.0)`（dirty 来自未跟踪的 graphify-out，源码即 92ccc939）|
|配置/probe|`D:/tmp/verify-r1/*.json` + `probe.py`（socks5 → 127.0.0.1:18500 echo，判据：`echo=b''`=被黑洞拦下 / `echo=b'PING'`=放行到目标）|
|Go 侧只做配置装配|`xray-go.exe -test -c <cfg>`（等价 Go 启动前装载；Go 的 fail-fast 都在这一步）|
|取证等级|E1 = 实跑双向（Rust 进程 + Go 进程）；E2 = 逐行/grep|

**判据校准（本报告采用的「可观测」定义）**：仅有启动期 `WARN` 一行、但**流量后果不可观测**的，仍按「静默失效」计——用户不会因此发现分流被废。这是本轮与第一轮的关键差异点（V1 有 warn，但 E1 证明屏蔽规则整体失效）。

---

## 1. 裁决表

| 编号 | 原断言（一句话） | 位置 | 裁决 | 校准严重度（原→新） | 一句话后果 |
|---|---|---|---|---|---|
| V1 | 路由 JSON/init 失败只 warn 并回退 PatternRouter | `xray-core/src/functions.rs:315-331` | **CONFIRMED** | P0→**P0** | 规则里的 `domain:` 前缀全失效、端口/网络/balancer 条件全丢；E1 实测屏蔽规则消失、流量直连 |
| V2 | outbound 解析失败 warn+skip，默认出站前移 | `xray-core/src/outbound.rs:222-241` | **CONFIRMED** | P0→**P0** | E1 实测：坏 proxy + `blackhole` 两条时默认出站变成 blackhole；换成 freedom 即「以为走代理实际直连」 |
| V3 | freedom finalRules 丢项 → 规则域扩到全量 | `xray-proxy-freedom/src/config.rs:530-560/591-628/821-830/928-945` | **CONFIRMED** | P0→**P0** | E1 实测：`ip:["not-an-ip"]` → `ip=None` → **所有流量被黑洞**（本该启动即报错） |
| V4 | sniffing 排除表逐条 warn+skip，`added==0` 整表失效 | `xray-core/src/wiring.rs:340-445` | **CONFIRMED** | P1→**P1** | 排除域名重新被嗅探并改写目的地；整表失效无任何二次告警 |
| V5 | 协议不支持 warn+skip（inbound 无监听 / masque 缺席） | `xray-core/src/inbound.rs:4168`；`arm_builders` 无 masque 键 | **CONFIRMED** | P1→**P1** | E1：未知 inbound 协议 → 进程活着但**零监听**；masque outbound → 流量直连 |
| V6 | `probeInterval` 只支持单段 duration | `xray-core/src/register.rs:529-549` | **CONFIRMED** | P2→**P2** | `"1m30s"` 静默回落 10s（Go=90s）；垃圾值 Go 拒启、Rust 用默认 |
| V7 | ruleSet/ruleSetTag → 空条件 → 静默 catch-all | `xray-core/src/wiring.rs:1050-1070/809-823`；`xray-app-router/src/rule.rs:72` | **REJECTED**（机制）/ 残值 ADJUSTED | P0→**P3**（残余） | **不存在 catch-all**：全路由对空规则报 `this rule has no effective fields`（与 Go 同），PatternRouter 空规则恒不命中；真问题是「同一错误被降级成 warn+回退」= V1 同根 |
| V8 | gRPC RoutingService/ObservatoryService 零注入 | `xray-app-commander/src/commander.rs:345/350/503-507` | **CONFIRMED** | P1→**P1** | 声明了这两个 service 也不注册，客户端拿 `UNIMPLEMENTED`，启动无告警（除非全空） |
| V9 | api outbound 模式无 registrar → 到不了 API server | `commander.rs:370/1101/645-649` | **ADJUSTED** | P1→**P2** | 机制属实（唯一调用点是测试），但**有明确 WARN**（`:645-649`），用户可发现 → 降一档 |
| V10 | `geodata.outbound` 死值，下载仍直连 | `xray-core/src/register.rs:965`；`xray-app-geodata/src/downloader.rs:167-190` | **CONFIRMED** | P1→**P1**（见 §3.10 升 P0 条件） | 配了 outbound 仍裸 HTTP 拉资产（IP 暴露），`MissingDispatcher`/`MissingOutbound` 全仓零构造 |
| V11 | `metrics.tag` 只做非空校验，不注册 dispatch handler | `xray-app-metrics/src/feature.rs:56,68` | **CONFIRMED** | P2→**P2** | tag 永远注册不进 SimpleOhm（注册器是**具体类型** `Arc<RecordingOutboundRegistrar>`，物理上无法注入真注册器） |

---

## 2. 逐条反证

### V1 路由失败静默降级 → CONFIRMED（P0）

**取证配置**（唯一差异 = 端口串）：
- A `v1-control.json`：`{"type":"field","domain":["domain:localhost"],"port":"18500","outboundTag":"blocked"}`
- B `v1-fallback.json`：同规则，`"port":"18500,bad-port"`

**Rust 实跑（E1）**
```
--- A: port '18500' -> rule must match (full Router)
 socks-probe: rep=0x00 echo=b''                       <-- 被 blackhole 拦下（规则生效）
--- B: port '18500,bad-port' -> PatternRouter fallback
 socks-probe: rep=0x00 echo=b'PING'                   <-- 流量到达目标（规则消失）
 warn-log: WARN full Router init failed, falling back to PatternRouter
           error=routing config JSON parse: routing port list: invalid port start "bad": invalid digit found in string
```
进程照常启动、照常监听 18412。**用户可见后果：配的 `domain:` 屏蔽规则整条失效，流量直连。**

**降级到底丢了什么（逐行）**：回退的 `PatternRouter::from_json`（`xray-core/src/router.rs:261-296`）
- `domain` 数组**一律**装成 `DomainPattern::Exact`（`:274-276`）——Go 的 `domain:xxx`/`full:`/`keyword:`/`regexp:`/`geosite:` 前缀串全变异体字面量，永不命中；
- 只认 `outboundTag`，`balancerTag` 规则直接 `continue`（`:270-273`）；
- 完全不解析 `port` / `network` / `inboundTag` / `source` / `attrs` / `protocol` / `user` —— 这些条件全部丢失（**丢条件=规则变宽**，不仅是变窄）；
- `PatternRule::matches`（`:228-231`）要求 `!domains.is_empty()`，所以空条件规则是死规则（不是 catch-all）。
- `PatternRouter::from_json` 再失败 → `(None, None)`（`functions.rs:329`）→ dispatcher 无路由 → 全部走默认出站。

**Go 对照（E1）**
```
Failed to start: main: failed to load config files: [...v1-badport.json]
 > infra/conf: failed to build routing configuration > infra/conf: invalid field rule
 > infra/conf: invalid port range: not-a-port
```
源码：`infra/conf/common.go:194-211`（`PortRange.UnmarshalJSON` 硬错）＋ `core/xray.go:292-303`（app feature 创建失败即 `New` 失败）。
**结论：Rust 静默降级 × Go 拒启 × 屏蔽规则实效 = P0。**

### V2 outbound warn+skip → CONFIRMED（P0）

**Rust 实跑（E1）**，`v2-default-shift.json` = `[vless(坏 port), blackhole]`，无 routing：
```
listener=True probe=rep=0x00 echo=b''      <-- 默认出站 = 第二条 blackhole（本该是 vless proxy）
WARN failed to parse outbound config, skipping tag=proxy protocol=vless error=missing vnext[0].port
```
判别逻辑：若默认出站仍是 freedom，`echo` 必为 `PING`；实测为空 → **默认出站确被后移**。代码：`outbound.rs:213-217`（首个注册成功者即 default）+ `:222-241`（两个 Err 分支只 warn，不返回错误）。

**Go 对照（E1）**
```
Failed to start: ... > infra/conf: failed to build outbound config with tag proxy
 > infra/conf: failed to load outbound detour config for protocol vless
 > json: cannot unmarshal string into Go struct field VLessOutboundConfig.vnext.0.port of type uint16
```
**后果：真实配置 `[proxy(坏), freedom]` = 全部无路由流量直连（IP 暴露），进程无异常。P0。**

### V3 freedom finalRules 丢项 → CONFIRMED（P0，最强证据）

**Rust 实跑（E1）**，`v3-bad-finalrule-ip.json`：`freedom` + `finalRules:[{action:block, ip:["not-an-ip"]}]`
```
INFO freedom: target blocked by final rule, blackholing connection tag=direct delay=71s
socks-probe: rep=0x00 echo='<TimeoutError>'     <-- 所有流量被黑洞
```
链路：`json_ip_rules` 逐项 `filter_map(..ok()?)` 丢弃（`config.rs:591-628`）→ 全丢后 `cidrs.is_empty() → None`（`:928-945`）→ `FinalRule::match_ip` 的 `(None,_) => true`（`:889-895`）→ 规则匹配所有。

**Go 对照（E1）**
```
Failed to start: ... > infra/conf: failed to build outbound config with tag direct
 > common/geodata: illegal ip rule: not-an-ip
```
源码：`common/geodata/rule_parser.go:16-46`（逐条 parse 失败即 return err）＋ `infra/conf/freedom.go:277-286`（`ParseIPRules` 错误直接上抛）。
**同一代码族还有三处静默丢**（Go 全硬错）：`port` 逐项 `continue`（`config.rs:556-566`）→ 空 = 匹配所有端口；未知 `network` token 丢弃（`:530-548`）→ 空 = `ALL_NETWORKS`（`:821-830`）；`geoip:` 类 IP 项在 matcher 构建期被整体忽略（`:928-937` 注释「geoip 规则被忽略」）。
**后果：一个 IP 拼写错误 = 全阻断（block 规则）或全放行（allow 规则），P0。**
> 附注：`outbound.rs:1127-1181` 的注释声称「finalRules 单条非法 → 硬错（对齐 Go `r.Build()` 失败即拒启）」——**只对 action 字段成立**，逐项字段仍静默丢。这条自我背书正是该缺陷过审的原因（见 §4-E2）。

### V4 sniffing 排除表 → CONFIRMED（P1）

**Rust 实跑（E1）**：`domainsExcluded:["geosite:doesnotexist"]`
```
listener=True probe=rep=0x00 echo=b'PING'   <-- 正常启动、正常转发
WARN sniffing domainsExcluded "geosite:doesnotexist" 解析失败，跳过: 文件校验失败: ...os error 2
```
`wiring.rs:339-345` 逐条 warn `continue`；`:404-406` `added == 0 → None` —— **整表关闭无二次告警**。

**Go 对照（E1）**
```
Failed to start: ... > infra/conf: failed to build sniffing config
 > common/geodata: illegal domain rule: geosite:doesnotexist > ... failed to open geosite.dat
```
源码：`proxyman/config.go:19-23`（`BuildDomainMatcher` 错误上抛）。**后果：被排除域名重新被嗅探并改写目的地 → 分流走错。P1（有 warn）。**

### V5 协议不支持 → CONFIRMED（P1）

**Rust 实跑（E1）**
```
# 未知 inbound 协议
listener=False probe=PORT-NOT-LISTENING (socks inbound absent)
WARN inbound protocol not yet supported, skipping tag= protocol=unknownproto
# masque outbound（Go 已注册）
WARN outbound protocol not yet supported, skipping tag=proxy protocol=masque
socks-probe: rep=0x00 echo=b'PING'   <-- 直连
```
**Go 对照（E1 + 源码）**
```
Failed to start: ... failed to load inbound detour config for protocol unknownproto
 > infra/conf: unknown config id: unknownproto        （infra/conf/xray.go:85-86）
masque 已注册：main/distro/all/all.go:44 (proxy/masque)、:58 (transport/internet/masque)
```
**后果：inbound 写错协议名 = 进程活着但零监听（用户以为在跑）；masque 配置 = 直连。P1（有 warn）。**

### V6 probeInterval → CONFIRMED（P2）

**逐行（E2）**：`register.rs:529-549`
```
/// 不支持复合形式（如 `"1m30s"`）；解析失败返回 `None`。
fn parse_go_duration_ms(s: &str) -> Option<i64> { ... _ => return None }
```
调用点 `:396-400` `.and_then(parse_go_duration_ms).unwrap_or(0)` → `ObservatoryConfig::effective_probe_interval_ms`（`xray-app-observatory/src/config.rs:175-177`）→ 0 即 `DEFAULT_PROBE_INTERVAL_MS`。
**实跑（E1）**：`v6-probe-interval.json`（`"probeInterval":"1m30s"`）→ 进程正常启动、无任何告警（只有 observatory 正常探测日志）→ 静默用默认值。
**Go 对照**：`infra/conf/cfgcommon/duration/duration.go:29` `time.ParseDuration` → `"1m30s"` = 90s（非法串则 Build 硬错）；默认间隔见 `app/observatory/observer.go:76-79`（10s）。
**后果：探测频率 10s vs 90s（9× 探测流量/连接），且非法值不报错。P2。**
> 修法方向（现成件）：`xray-core/src/wiring.rs:1343` 已有支持复合单位的 `parse_go_duration_str`（纳秒），register.rs 另写了一份阉割版——直接复用即可。

### V7 ruleSet/ruleSetTag → REJECTED（机制错），残余 ADJUSTED（P3）

**三条独立反证**

1. **Go 无该键（E1+E2）**：`grep -r "ruleSet|RuleSet|rule_set" D:/Project/Xray-core` → 0 命中；`app/router/config.proto` 的 `RoutingRule` 字段集无 `rule_set`（tag 1/12/19/2/10/14/13/11/16/7/8/9/15/17/18/20/21/22/23）。
2. **Go 不接受空条件规则（E1，推翻 PM 初步反证）**——这条是本轮最重要的纠偏：
```
$ xray-go.exe -test -c v7-rulesetTag-only.json
Failed to start: main: failed to create server > app/router: this rule has no effective fields
```
   源码 `app/router/config.go:117-118`：`if conds.Len() == 0 { return nil, errors.New(...) }`。
   **「Go 空条件同样恒真」不成立**——`ConditionChan.Apply` 对空集合确实返回 true（`app/router/condition.go:36-42`），但空条件规则在 `BuildCondition` 阶段就被拒，永远到不了 `Apply`。
3. **Rust 同样拒绝，但把它降级成 warn（E1）**：
```
WARN full Router init failed, falling back to PatternRouter error=router init: this rule has no effective fields
socks-probe: rep=0x00 echo=b'PING'   <-- 不是 catch-all：空规则在 PatternRouter 里恒不命中
```
   `xray-app-router/src/rule.rs:72` 的 `is_none_or` 是**不可达的防御分支**；`router.rs:228-231` 要求 `!domains.is_empty()`，空规则恒 false。
   于是 `ruleSetTag`-only 规则的真实走向 = **规则静默消失 + 全部规则一并降级**（同 V1），**不是 catch-all**。

**残余（新 finding）**：`ruleSet` 是 Rust 自造扩展——校验并 `registry.load` 文件（`wiring.rs:1030-1082`），随后 registry 被丢弃，且**任何 ruleSet 错误（含 remote / 文件缺失）都会把整条路由推进 PatternRouter 降级路径**：
```
WARN full Router init failed, falling back to PatternRouter
     error=ruleSet 'rs1': failed to read rule_set file "...nonexistent-ruleset.json": os error 2
```
Go 对同一键完全无视（连 warn 都没有）。**即：一个 Go 里根本无效的自造键，能把 Rust 的分流保真度打掉。** 定性 P3（自造扩展未完成），但它是 V1 的**触发器**之一，修 V1 时必须一并处理。

### V8 gRPC 后端零注入 → CONFIRMED（P1）

**逐行/grep（E2）**：全 `crates/` 检索 `set_routing_service|set_observatory_service` → **只有定义处**（`commander.rs:345-355`），无任何生产调用点；对比 `set_handler_service`（`xray-core/src/functions.rs:517`）与 `set_stats_service`（`:506-513`）、`set_outbound_runtime`（`:500`）、`set_logger_service`（`:504`）都已接线。
装配处 `commander.rs:503-507`：
```rust
let routing = declared(api_services::ROUTING).then(|| self.routing_service.read().clone()).flatten();
```
`None` 被 `flatten()` 静默吞掉；唯一告警 `:508-514` 只在**五个服务全空**时触发——声明了 `StatsService` 就一声不响。
**Go 对照**：`infra/conf/api.go:37-44` 把服务名映射为 config，各 app 的 command 包在 feature 创建时注册（`app/router/command/command.go:145-146`、`app/observatory/command/command.go:31-32`）→ 必然暴露。
**后果：`xray api routingrule/list` 类调用恒 `UNIMPLEMENTED`，启动期无告警。P1。**

### V9 api outbound 模式 → ADJUSTED（P1 → P2）

**逐行确认机制**：`set_dispatch_registrar` 全仓唯一调用点是 `commander.rs:1101`，位于 `#[tokio::test] async fn outbound_mode_serves_grpc_via_dispatch()` 内（该函数上文为 duplex/grpc 客户端模拟）→ 生产零注入。
`serve_grpc` 的 `None =>` 分支（`:645-649`）：
```rust
None => { tracing::warn!("commander outbound mode without dispatch registrar — connections routed to tag `{}` will not reach the API server", self.tag); }
```
**校准**：上一轮报 P1（「无告警」前提不成立）——实测该 WARN 明确点名「到不了 API server」，属**有告警可发现**，按口径降 P2。机制本身完全成立（Go commander.go:101-115 会 `ohm.AddHandler`）。

### V10 geodata.outbound 死值 → CONFIRMED（P1，附升 P0 条件）

**逐行（E2）**
- 装配：`register.rs:964-966` 把 `json_cfg.outbound` 放进 `xray_app_geodata::GeodataConfig.outbound`；下载器却是 `RealAssetDownloader::new(default_asset_dir())`（`:928-929`）——**不持有 dispatcher/ohm 任何句柄**。
- 消费面：全 `xray-app-geodata/src` 检索 `outbound` → 仅 `config.rs` 的字段定义/互转/测试，无运行期读取；`download_to` 是裸 HTTP（`downloader.rs:369+`，仅自带 https/redirect 校验）。
- `GeodataError::MissingDispatcher` / `MissingOutbound`（`error.rs:10-14`）**全仓零构造点**（grep 仅命中定义）。
**Go 对照**：`app/geodata/geodata.go:28-35` —— `core.RequireFeatures(ctx, func(d routing.Dispatcher){...})`，取不到即 `errors.New("failed to get dispatcher for geodata downloader")`；`newDownloader(ctx, dispatcher, config.Outbound)` 按 tag 走代理下载。Go 的 `infra/conf/geodata.go:49-57` 亦把 `outbound` 传进 proto。
**后果：用户显式指定 `geodata.outbound` 以隐藏来源 IP，实际仍直连拉资产，且零告警。P1**（若用户威胁模型包含「资产下载也不得暴露出口 IP」，按口径应升 P0——本报告取 P1 因爆炸半径仅限周期性资产下载）。

### V11 metrics.tag → CONFIRMED（P2）

**逐行**：`xray-app-metrics/src/feature.rs:56,68`
```rust
registrar: Arc<RecordingOutboundRegistrar>,   // 具体类型，非 trait object
... registrar: Arc::new(RecordingOutboundRegistrar::new()),
```
`RecordingOutboundRegistrar` 是**测试替身**（`metrics.rs:170-200`，仅记录最后一次 add/remove 的 tag）。字段是具体类型且无 setter → **生产路径物理上无法注入真注册器**；`register.rs:464-473` 的 factory 也只 `MetricsFeature::new(config)`。
**Go 对照**：`app/metrics/metrics.go:82-97` —— `p.ohm.AddHandler(ctx, &Outbound{tag: p.tag, ...})` 真注册；`NewMetricsHandler` 用 `RequireFeatures` 拿 `outbound.Manager`。
**后果：`metrics.tag` 配了也路由不到，`/metrics` 只能靠 `listen` 暴露。P2。**

---

## 3. 五查（针对本轮被复核的**断言本身**）

1. **正确性（断言强度）**：✗ — V1/V2/V3/V5 的断言「只 warn」成立，但都**没写 clean 触发条件与流量后果**，导致第一轮无法区分「有 warn 所以不算静默」。本轮补齐后 P0 才站得住。V7 的断言机制错（catch-all 不存在），属**断言强度不足反而误判方向**。
2. **边界**：✗ — V3 的断言把「丢项」写成单点（`filter_map`），实际有四类丢项（ip/port/network/geoip）；只修一点仍会复发。
3. **错误处理**：✗ — 三条 P0 的共同模式是 `Err → warn → 继续启动`，且**没有任何一处把降级状态做成可查询/可探活信号**（无法从外部判断「我现在的路由是完整的还是降级的」）。
4. **测试质量（原审计的证据等级）**：✗ — 第一轮 V1/V2/V3/V5 均为 E2（源码推导）；本轮 E1 显示「源码推导的严重度」与「实测严重度」可差一档（V7 从 P0 掉到 P3，V9 从 P1 降到 P2）。
5. **接线**：✗ — V8/V9/V10/V11 是同一病：**API/句柄齐全，生产侧无人注入**（4 条全部靠「唯一调用点在测试里」识别）。建议加一条 CI 门：`set_*_service` / `set_*_registrar` 之类注入函数若无 `#[cfg(not(test))]` 调用点 → 报错。

---

## 4. 补充发现（第一轮未列）

| # | 严重度 | 位置 | 问题 | 修法方向 |
|---|---|---|---|---|
| E1 | 建议 | `xray-core/src/functions.rs:315-331` | fail-fast 被收窄到**单一错误类**（仅 `WiringError::Geodata` 拒启），`JsonParse`/`RouterInit`/文件缺失全部降级。这是 V1/V7 的共同根：Go 侧所有 `WiringError` 都对应「配置装载失败 → 拒启」 | 把所有 `WiringError` 统一拒启，PatternRouter 回退整体删除（框架支线无发布包袱，按「不做开关」口径直接做对） |
| E2 | 建议 | `xray-core/src/outbound.rs:1127-1181` | 注释自称「finalRules 单条非法 → 硬错（对齐 Go），不再逐条 warn+丢弃」，但子字段（ip/port/network）仍静默丢 → **自我背书掩盖 V3** | 注释改为「仅 action 硬错；子字段待对齐」，或直接补齐子字段硬错 |
| E3 | 吹毛 | `xray-core/src/register.rs:529` vs `xray-core/src/wiring.rs:1343` | 两份 Go-duration 解析器能力不同（后者支持复合单位） | 删前者，复用后者（返回 ns → /1e6 转 ms） |
| E4 | 建议 | `xray-app-commander/src/commander.rs:508-514` | 「声明了但后端缺失」与「全部为空」共用一条告警 | 逐服务独立告警：`declared && backend.is_none()` → warn（一次性覆盖 V8 的静默） |
| E5 | 建议 | `xray-app-geodata/src/downloader.rs` | `RealAssetDownloader` 无 dispatcher 接口，`MissingDispatcher` 成死变体 | 注入 `DispatchDial`（Go `newDownloader(ctx, dispatcher, tag)` 同构），无 dispatcher 且 outbound 非空 → 硬错 |

---

## 5. 未覆盖范围

1. **V8/V9 未做 gRPC 实调**（未起 `api` + `services` 端到端连 tonic）：结论为 E2（全仓 grep 调用点 + 装配代码逐行）。要升 E1 需起 api 服务并用 `xray api`/grpcurl 探 `RoutingService/ListRule`。
2. **V10 未做「配了 outbound 仍直连」的抓包**：E2（下载器结构体无 dispatcher 字段 + 全仓无消费点 + 错误变体零构造）；要升 E1 需真配一个 cron + 资产 URL 并抓包看是否经代理。
3. **V11 未验证真实 `metrics` outbound 路由**：E2（具体类型注册器，无注入缝）。
4. **V4 的「嗅探改写目的地」未做流量级取证**：只证了「排除表被静默禁用 + 进程正常」，未构造 HTTP 请求观测 `destOverride` 是否真的改写了路由目标。
5. **未审**本轮清单之外的静默失败面（例如 DNS、wireguard、policy 侧），也**未重复审计**性能/内存（属另两路）。
6. 所有 E1 均在 Windows 回环（127.0.0.1）完成，未覆盖 Linux/WSL 差异（本任务无需构建，故未跨平台验证）。

---

## 附：可复现资产

- 配置：`D:/tmp/verify-r1/{v1-control,v1-fallback,v1-badport,v2-bad-outbound,v2-default-shift,v3-bad-finalrule-ip,v4-bad-exclude,v5-unknown-inbound,v5-masque-outbound,v6-probe-interval,v7-ruleset-remote,v7-ruleset-file-missing,v7-rulesetTag-only}.json`
- 探针：`D:/tmp/verify-r1/probe.py <cfg> <socks_port>`（自带 127.0.0.1:18500 echo，判据见 §0）
- Go 基线：`D:/tmp/verify-r1/xray-go.exe`（`go build ./main` @ 92ccc939）
- 均为临时工件，未入库（`reports/` 只落本报告）。
