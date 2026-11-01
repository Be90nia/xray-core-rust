# R1 接线普查 · 静默失败第三路径：错误/缺省被吞导致的静默降级

- 审计者：`WiringDegrade`（reviewer，只读）
- 仓库：`D:/Project/Xray-core-rust` 分支 `feature/fix-inbound-parity`，HEAD `5fe98b90`
- 被测二进制：`target/release/xray.exe`（`xray version` → `git_rev=5fe98b907c7b...`，与 HEAD 一致，2026-10-31 11:00 构建）
- 生产口径：**生产主路** = `xray.exe run -c` → `xray_conf::Config::build()` → `xray_core::start_full`。本报告所有 E1 证据均在此路上取。
- 证据等级：**E1** = 真实二进制实测输出（附命令+日志）；**E2** = 源码 + Go 对照推导（无运行期实测）。

---

## 0. 摘要

共 12 条发现：**P0 × 3**（全是「静默降级导致屏蔽/隐私失效」）、**P1 × 3**、**P2 × 4**、**P3 × 2**。

三条 P0 的共同形态：**配置里有错 → 只打一条 WARN → 进程正常启动 → 安全语义反转**。其中两条已被实测证明会造成「本该被阻断的流量走直连」与「本该只拦部分 IP 却拦了全部」。

另有 7 条「实测/源码证明无问题」项（§6），供 R2/后续审计避免重复劳动——特别提醒：**TLS 指纹回退 rustls 这条路已被硬错封死**，路由器「tag 不存在落默认出站」也已按 Go 的 DO NOT CHANGE 实现正确。

---

## 1. 方法与可复现资产

| 资产 | 路径 |
|---|---|
| E2E 编排脚本 | `reports/audit-2026-10-31-perf-mem-wiring/scripts/run_audit.py` |
| SOCKS5 探针 | `scripts/socks_probe.py`（消费完整 BND.ADDR 后读 payload） |
| 直连目标 sink | `scripts/sink_server.py`（accept 后回 `PONG`） |
| 配置夹具 | `fixtures/cfg_*.json`（每条的触发配置原件） |
| 原始日志 | `scripts/log_*.txt`（每条运行完整输出） |

```bash
# 全量重跑（约 60s，全部 loopback，无外网依赖）
cd reports/audit-2026-10-31-perf-mem-wiring
python scripts/run_audit.py all
```

判读口径：探针 `REPLY b'PONG'` + `sink log: ACCEPT` = 流量**真的连到目标**（= 走了直连）；`REPLY b''` 且无 ACCEPT = 被阻断；`SOCKS_OK` 后 `io: timed out` = 握手成功但链路被静默吞掉（最隐蔽的一种）。

模式扫描脚本：`scripts/`（内联 python；对 807 个 `.rs` 扫 `unwrap_or_default()` / `.ok()` / `if let Ok(` / `Err(_) => continue` / `Err(e) => { warn!.. }`，剔除 `#[cfg(test)]` 之后段落），并对 `xray-conf` 的 **320 个 `pub` 配置字段**做「外部引用计数」普查（0 引用 = 声明但无消费点）。

---

## 2. 发现总表（8 列）

| # | 标题 | 严重度 | 位置 | 现状 | 断裂点 | 生产可达性证据 | 建议修法 | 复现/验证 |
|---|---|---|---|---|---|---|---|---|
| F1 | 路由任一规则解析失败 → 整体降级 PatternRouter，屏蔽规则静默失效 | **P0** | `xray-core/src/functions.rs:298-331`、`wiring.rs:1380-1400`、`router.rs:252-303` | JsonParse/RouterInit 只 warn，回退 PatternRouter（domain 改 Exact、balancerTag 规则丢弃）；PatternRouter 再失败 → `(None,None)` = 无路由 | 解析→装配：**装配把 fail-loud 吃掉** | E1：`a_ok` 阻断 vs `a_fallback` 直连（同一条 `domain:["local"]` 规则）；6 类触发各实测一次 | `JsonParse`/`RouterInit` 与 `Geodata` 同口径拒启 | `python scripts/run_audit.py a` |
| F2 | outbound 配置解析失败/协议不支持 → warn+skip，节点消失且默认出站前移 | **P0** | `xray-core/src/outbound.rs:186-240`、`functions.rs:425-441` | 两臂 warn 后 `continue`；「首个注册成功者即默认」→ 坏节点被跳过后 direct 顶上 | 装配：outbound 表 → 运行期默认出站 | E1：bad uuid + freedom → `REPLY b'PONG'` + ACCEPT（流量直连）；WARN 一行 | 被跳过的 tag 若被任何 routing 规则引用 → 拒启（或直接 fail-visible） | `python scripts/run_audit.py b` |
| F3 | freedom `finalRules` 的 ip/network 项解析失败被丢弃 ⇒ 匹配域扩为「全匹配」 | **P0** | `xray-proxy-freedom/src/config.rs:591-628`、`:530-560`、`:821-830`、`:941` | `filter_map(..ok()?)` 丢项；`ip: None` = 匹配所有 IP；`networks.is_empty()` = ALL_NETWORKS | 解析：规则项 → 运行期 matcher | E1：`ip:["geoip:cn"]` 与笔误 CIDR 都导致**全阻断**（握手后挂死超时、零日志） | 列表项解析返回 Result 并硬错；空列表不得退化为「全匹配」 | `python scripts/run_audit.py f` |
| F4 | sniffing `domainsExcluded`/`ipsExcluded` 单条失败 warn+skip，全失败→排除表消失 | **P1** | `xray-core/src/wiring.rs:340-395`、`:401-445`、`:389` | 逐条 warn 跳过；`added == 0 → return None`（整表失效） | 装配：配置 → SniffingRequest | E1：两条 WARN（regexp 编译失败 / geosite code 不存在），嗅探仍启用 | 提升到 `xray-conf` ValidationStage 硬错 | `python scripts/run_audit.py c` |
| F5 | inbound 协议不支持 → warn+skip，无监听器 | **P1** | `xray-core/src/inbound.rs:4166-4176` | warn + `Ok(None)`，进程照常 | 装配：inbound 表 → listener | E1：`protocol:"masque"` inbound，端口 19002 不监听（连接被拒） | 未知入站协议拒启（Go `common.CreateObject` 失败即 Build 失败） | `python scripts/run_audit.py b` |
| F6 | `masque` 双向协议缺口被 warn 掩盖 | **P1** | `xray-core/src/arm_builders/mod.rs`（`INBOUND_CTORS`/`OUTBOUND_CTORS` 无 masque） | Go `proxy/masque/{client,server}.go` 已注册，Rust 表无键 | 装配：协议表 | E1：`WARN outbound protocol not yet supported, skipping tag=m protocol=masque` | 补 masque 或对 masque 配置显式拒启 | 同 F5 命令 |
| F7 | `observatory.probeInterval` 解析失败 → `0`（默认间隔） | **P2** | `xray-core/src/register.rs:396-400`、`:531-550` | `and_then(parse_go_duration_ms).unwrap_or(0)`；该解析器只支持单段 `30s/1m/1h/500ms` | 解析：duration → 运行期探测周期 | E2：`"1m30s"`/`"1.5h"`/`"2h30m"` 均 None → 0；Go `ProbeInterval` 为 `duration.Duration`（`infra/conf/observatory.go:15`），非法即硬错 | 用 Go duration 全语法（多段）或失败硬错 | `cargo test -p xray-core parse_go_duration_ms` |
| F8 | Rust 独有入站别名无 freedom 默认 block-private 规则 | **P2** | `xray-proxy-freedom/src/config.rs:967-985`、`xray-core/src/outbound.rs:147-160` | `get_default_rule_type` 只匹配 `hysteria`，无 `hysteria2`/`anytls`/`tuic`/`naive` → `None` = 无默认规则 | 装配：入站协议名 → 出站默认 final rule | E2：`hysteria2` 是 Rust 表独立键（`INBOUND_CTORS` 同时有 `inbound:hysteria` 与 `inbound:hysteria2`） | 别名并入同一默认规则类别 | 源码对照 + `get_default_rule_type("hysteria2") == None` |
| F9 | dns app 两处装配降级（matcher 失败 / 本机 client 不可用） | **P2** | `xray-app-dns/src/jsonconf.rs:288-306` | matcher 构建失败 → `None`（per-server `domains` 路由全失效）；本机 client 不可用 → `clients` 空（查询恒 EmptyResponse） | 装配：DNS 配置 → 运行期解析路径 | E2（需构造环境故障） | 至少把 `domains` 失效升级为拒启 | 源码 + 单测注入 |
| F10 | 重复用户 warn+skip，Go 为硬错 | **P2** | `xray-core/src/inbound.rs:4621`（vless）、`:5056`（vmess）、`:3891`（trojan+reality） | warn 后跳过重复项，保留先到者 | 装配：用户表 → 校验器 | E2：Go `proxy/vless/inbound/inbound.go:64-66` `validator.Add` 失败即 `return nil, error` | 重复用户拒启 | 源码对照 |
| F11 | `freedom.ipsBlocked` 无消费点，也无 Go 的弃用告警 | **P3** | `xray-conf/src/protocols.rs:1117-1119` | 注释自称「用于触发 Build 阶段警告」，全仓零引用 | 解析：字段 → 运行期 | 320 字段普查：唯一 0 外部引用项（`fake_dns`/`burst_observatory` 为宏消费误报，已复核 `built.rs` `push_app!`） | 补一条 warn 或删字段 | `scripts/` 字段普查脚本 |
| F12 | 性能开关若有「声明无消费」即列此条：**普查结果为空** | **P3(信息)** | — | 320 字段中与性能/资源相关的均已被消费（uot/uotVersion、mux.concurrency/xudpConcurrency、rewriteNetwork、policy 各档、sockopt） | 无断裂 | E2：逐项定位见 §5 | 无需动作 | 见 §5 表 |

---

## 3. 逐条证据链

### F1 [P0] 路由解析失败 → 降级 PatternRouter → 屏蔽规则静默失效

**现状（代码做了什么）**

`crates/xray-core/src/functions.rs:298-331`：

```rust
match crate::wiring::build_router_adapter_from_json_with_ohm(&a.data, &ohm, observer) {
    Ok(adapter) => { ... },
    Err(e) => {
        // bd il49：仅 Geodata 变体拒启
        if let crate::wiring::WiringError::Geodata(msg) = &e { return Err(...); }
        tracing::warn!(error = %e, "full Router init failed, falling back to PatternRouter");   // :318
        match crate::router::PatternRouter::from_json(&a.data) {
            Ok(r) => { ... },
            Err(_) => (None, None),                                                             // :330
        }
    },
}
```

`WiringError`（`wiring.rs:1380-1400`）有三变体：`JsonParse` / `RouterInit` / `Geodata`。**只有 `Geodata` 拒启**——bd il49 的修复面只覆盖了 geo 资产缺失。其余两类（配置写错、平衡器/ruleSet 不支持）一律降级。

`PatternRouter`（`router.rs:252-303`）是一个**语义缩水版**：
- `domain` 被当作 **Exact**（`DomainPattern::Exact`），而 Go 无前缀 `domain` 是 **Substr**；
- 仅支持 `domain`/`domainSuffix`/`domainKeyword`/`ip`/`outboundTag`；`port`/`network`/`protocol`/`user`/`inboundTag`/`source`/`attributes` 全被忽略 → 这些规则退化为「永不命中」；
- `balancerTag` 规则被 `continue` 丢弃；
- 两者都失败 → `(None, None)` = **完全没有路由**，全流量走默认出站。

**断裂点**：解析→装配 这一环。`parse_routing_json_to_proto`（`wiring.rs`）在文档里明写「不再静默丢规则」，并且对 Lua `script` 刻意 fail-loud（注释：「静默丢 = 路由走向与配置意图完全不同」）——但**调用方把这个 fail-loud 直接吃掉**，回退到一个「丢掉 script 也能解析」的 PatternRouter。这是自相矛盾的一处：底层刻意 fail-loud，上层刻意 fail-open。

**触发条件（六类，逐条实测）**——任一即可，最小片段：

| 触发键 | 实测 WARN 的 error 字段 |
|---|---|
| `"routing": {"script":"function() end"}` | `routing script (Lua) is not supported by this build` |
| `"balancers":[{"tag":"","selector":["x"]}]` | `empty balancer tag` |
| 规则里 `"network":"bogus"` | `routing rule network: unknown network token 'bogus'` |
| 规则里 `"ip":["1.2.3.4/99"]` | `routing rule ip: CIDR 前缀过大: 99, 最大: 32` |
| `"ruleSet":[{... 远程 url ...}]` | `ruleSet 'a': remote rule_set download is not implemented` |
| 规则只有 `domain` 无目标 | `neither outboundTag nor balancerTag is specified in routing rule` |

**用户看到什么**：进程正常启动，`inbounds=1 routed=true` INFO 照打，日志里一条 `WARN full Router init failed, falling back to PatternRouter`。没有任何「屏蔽规则已失效」的提示。

**真实后果（E1，两条对照实验）**

```
CASE a_ok        cfg=cfg_a_ok.json        target=localhost:19099
  SOCKS_OK reply=0
  REPLY b''                                   ← 被屏蔽规则阻断
sink log: LISTENING 19099                     ← sink 从未收到连接

CASE a_fallback  cfg=cfg_a_fallback.json   target=localhost:19099
  SOCKS_OK reply=0
  REPLY b'PONG'                               ← 直连成功（屏蔽失效）
sink log: LISTENING 19099 | ACCEPT ('127.0.0.1', 13777)
WARN full Router init failed, falling back to PatternRouter
     error=routing config JSON parse: routing rule network: unknown network token 'bogus'
```

两配置**唯一差别**是 a_fallback 多了一条与屏蔽无关的坏规则（`network:"bogus"`）。结果：同一条 `{"type":"field","domain":["local"],"outboundTag":"block"}` 从「阻断」变成「放行并直连」。这就是「一条无关的配置笔误 → 全部屏蔽规则失效 → 流量直连」的完整链条。

**日志可观测性**：`WARN` 一条，措辞是「falling back」而非「路由规则已部分/整体失效」，**不足以发现**（用户不会意识到屏蔽没了；且 fallback 成功时的 `routed=true` INFO 反而制造「路由已生效」的错觉）。

**建议修法**：`JsonParse` / `RouterInit` 与 `Geodata` 同口径拒启（Go：`RouterConfig.Build` 失败即启动失败）。若必须保留 PatternRouter 回退，至少要满足「配置中不含任何 block/blackhole 目标规则」才允许降级，并且 WARN 升级为 ERROR 且带「N 条规则已失效」计数。

**复现**：`python scripts/run_audit.py a`（夹具 `fixtures/cfg_a_ok.json` / `cfg_a_fallback.json`，日志 `scripts/log_a_ok.txt` / `log_a_fallback.txt`）。

---

### F2 [P0] outbound 解析失败 warn+skip → 节点消失 → 默认出站前移 → 流量直连

**现状**

`crates/xray-core/src/outbound.rs:186-240`：

```rust
for (i, ob) in built.outbounds.iter().enumerate() {
    match try_build_handler(...) {
        Ok((handler, ..)) => {
            if ohm.get_default_handler().is_none() { ohm.set_default(handler.clone()); }  // :208 首个成功者即默认
            ohm.add(&ob.tag, handler);
        },
        Err(BuildError::Unsupported(p)) => tracing::warn!(tag=.., protocol=%p,
            "outbound protocol not yet supported, skipping"),                          // :226
        Err(BuildError::Parse(e)) => tracing::warn!(tag=.., error=%e,
            "failed to parse outbound config, skipping"),                               // :234
    }
}
```

Go 语义：任一 outbound 的 `Build()` 失败 → `infra/conf` 构建失败 → **拒启**（`BuildError::Parse` 对应 Go 的 `errors.New("invalid outbound config")` 一类硬错）。

**触发条件（用户配置即可触达，全部是「写错一处」）**

1. VLESS `users[].id` 非法（>30 字节且非 32/36 位标准 UUID）：`parse_vless_config` → `UUID::from_str` 失败（`outbound.rs:964`）；
2. `vnext` 成员数 ≠ 1 / `users` 成员数 ≠ 1（Go 同样硬错，但 Rust 是 skip）；
3. 缺 `vnext[0].port` / `address`；
4. 其它协议 settings 形状错误（socks/vmess/trojan/ss 各自 `parse_*_config` 的 Err 分支）；
5. 协议不在 `OUTBOUND_CTORS` 表（见 F6）。

**E1 实测**

```
CASE b2_bad_uuid_expect_direct  cfg=cfg_b2_bad_uuid_outbound.json
  boots ok, socks listening=True
  WARN failed to parse outbound config, skipping tag=proxy protocol=vless error=invalid UUID string: ***
  probe: SOCKS_OK reply=0 / REPLY b'PONG'
sink log: LISTENING 19099 | ACCEPT ('127.0.0.1', 4938)      ← 流量走了 freedom 直连
```

配置原文（`fixtures/cfg_b2_bad_uuid_outbound.json`）：outbounds = `[vless(id 超长) , freedom]`。用户的意图是「全部流量经 vless 代理」；实际是**全部流量明文本机直连**。这条与「用户的代理没生效、但以为生效」完全等价——是隐私面最重的一类静默失败。

**极端情形**：若配置里没有可用的兜底 outbound（例如只有一个坏 outbound），则 `default handler == None`，每条连接走到 `dispatcher/default.rs` 的 `no outbound handler available` → 全站不可用，但进程仍显示正常启动（`outbound.rs:3669` 的单测 `register_empty_outbounds_noop` 正是这个状态）。

**日志可观测性**：`WARN` 一条，措辞「skipping」；用户很容易读成「跳过某个可选节点」。**不足以发现**，因为没有任何一处把「默认出站已变成 freedom」说出来。

**建议修法**（按代价从低到高）：
- 最低成本：注册完成后做一次一致性检查——「任何 routing 规则引用的 tag 若不在 ohm 中 → 拒启」；
- 中等：`register_outbounds` 在「首个成功者设默认」时，如果存在被跳过的 outbound，打 `ERROR` 并列出 tag + 失败原因；
- 彻底：把 `Parse` 分支改为返回错误（`Unsupported` 保留 skip 可以商量，`Parse` 必须硬错——配置语法错误没有理由容错）。

**复现**：`python scripts/run_audit.py b`（`b2_bad_uuid_expect_direct` 用例）。

---

### F3 [P0] freedom `finalRules` 列表项解析失败被丢弃 ⇒ 规则匹配域扩大为「全匹配」

**现状**

`crates/xray-proxy-freedom/src/config.rs`：

- `json_ip_rules`（`:591-628`）：逐项 `filter_map`，`split_once('/')` 的 prefix 解析 `ok()?`、`IpAddr` 解析 `ok()?` —— **失败项静默丢弃**；注释自述「无法解析的项跳过」。
- `json_network_list`（`:530-560`）：`filter_map(|t| match t.to_ascii_lowercase() { "tcp" => .., "udp" => .., "unix" => .., _ => None })` —— 未知 token 静默丢弃。
- `FinalRule::build`（`:821-830`）：`let network = if config.networks.is_empty() { ALL_NETWORKS } else {...}` —— **空 = 匹配所有网络**。
- `build_ip_matcher_from_rules`（`:928-941`）：`if cidrs.is_empty() { None }`；而 `match_ip`（`:865-880`）对 `(None, _)` 返回 **true** = 匹配所有 IP。

**语义反转**：`{"action":"block","ip":["geoip:cn"]}` 的意图是「只拦中国 IP」；因为 `geoip:cn` 不是 CIDR → 被丢弃 → `ip` 列表空 → matcher `None` → **拦所有 IP**。同理 `{"action":"allow","ip":[...]}` 会被放大成「允许所有」。`match_network` 一处同理：`"network":"tpc"` 笔误 → 空 → `ALL_NETWORKS`。

**Go 对照**：`infra/conf/freedom.go` `FreedomFinalRuleConfig.Build()` → `geodata.ParseIPRules(*c.IP)`，**失败即返回 error**（硬错），且 `ParseIPRules` 支持 `geoip:xx` / `ext-ip:` / `!` 反向前缀。`NetworkList.Build()` 对未知 token 同样报错。

**E1 实测（三组对照）**

```
CASE fr_control_other_cidr  ip:["198.18.0.0/15"]      → REPLY b'PONG' + ACCEPT     ← 规则不命中，正常放行
CASE fr_geoip_cn           ip:["geoip:cn"]            → SOCKS_OK 后 io: timed out  ← 全阻断，sink 无 ACCEPT
CASE fr_typo_cidr          ip:["198.18.0.0/15x"]      → SOCKS_OK 后 io: timed out  ← 全阻断
```

三组日志里**零 WARN、零 ERROR**（`scripts/log_fr_geoip_cn.txt` 仅 INFO + DEBUG）。

**真实后果**：
- `block` 侧 → 该出站所有连接被静默吞掉（表现是「握手成功但永远没数据」→ 客户端表现为挂死/超时，最难排查的一种）；Go 下只有 CN IP 被拦，本机/内网/正常站点都能通。
- `allow` 侧 → 反向：规则本意「仅放行 X」，实际「放行一切」。
- 只要配置里出现 `geoip:`/`ext-ip:` 这类 Go 合法但 Rust 不支持的写法（迁移配置时极常见），**必然触发**。

**日志可观测性**：**完全没有**（这是本条比 F1/F2 更严重的地方：连一条 WARN 都没有）。

**建议修法**：`json_ip_rules` / `json_network_list` 返回 `Result`，未知项按 Go 硬错；`FinalRule::build` 增加不变量：调用方声明了 `ip` 但有效项为 0 时必须报错而不是退化为 `None`。

**复现**：`python scripts/run_audit.py f`（夹具 `fixtures/cfg_fr_*.json`）。

---

### F4 [P1] sniffing 排除列表逐条 warn+skip，全失败时整表消失

**现状**：`crates/xray-core/src/wiring.rs:340-445`

```rust
for raw in rules {
    let rule = match parse_domain_rule(...) { Ok(r) => r,
        Err(e) => { tracing::warn!("sniffing domainsExcluded {raw:?} 解析失败，跳过: {e}"); continue; } };
    ...
}
if added == 0 { return None; }        // :389 —— 整条排除表消失
```

函数头注释已自承这是降级：「单条失败 `warn` 跳过（Go 为 Build 期硬错；本函数签名无 Result 且调用方在票外，降级为可见告警，不静默吞）」。

**关键漏洞**：`xray-conf` 的 `ValidationStage`（`init.rs:148-230`）**只校验 `destOverride` 未知协议**（Go 硬错项），**不校验 `domainsExcluded`/`ipsExcluded`**。所以配置层没有兜底，warn 就是最后一道防线。

**E1 实测**

```
CASE c_sniff_exclude   sniffing.domainsExcluded = ["regexp:[bad","geosite:no-such-code"]
WARN sniffing domainsExcluded "regexp:[bad" 编译失败，跳过: 正则表达式编译失败: regex parse error: unclosed character class
WARN sniffing domainsExcluded "geosite:no-such-code" 解析失败，跳过: 文件校验失败: IO 错误: 系统找不到指定的文件。 (os error 2)
probe: REPLY b'PONG'   ← 嗅探照常启用
```

**真实后果**：本应「不嗅探」的域名会被嗅探；在 `destOverride` 含 `fakedns`/`tls` 的场景下，嗅探会**改写目的地**（`session.SniffingRequest.override_destination_for_protocol`），即排除表失效 = 这些域名的流量被改道（可能绕开针对该域名的分流/屏蔽规则）。这是「访问控制面被静默削弱」，因此定 P1。

**日志可观测性**：`WARN` 两条，但埋在启动噪声里；且用户不知道「排除规则＝0 条 = 全量嗅探」。

**建议修法**：把两个排除列表的编译搬进 `ValidationStage`（与 destOverride 同口径硬错），wiring 侧保留防御性 warn。

---

### F5 / F6 [P1] 不支持的协议一律 warn+skip（入站无监听器；出站节点消失）

**现状**：`crates/xray-core/src/inbound.rs:4166-4176`

```rust
let Some(ctor) = crate::arm_registry::lookup_inbound_builder(ib.entry.kind.as_str()) else {
    tracing::warn!(tag = %ib.tag, protocol = %ib.entry.kind,
        "inbound protocol not yet supported, skipping");           // :4168-4172
    return Ok(None);
};
```

Go：`infra/conf` 通过 `common.CreateObject` 构建 proxy，未知协议/不支持协议 → error → 构建失败 → **拒启**。

**E1 实测**

```
CASE b_outbound_skip
WARN outbound protocol not yet supported, skipping tag=m protocol=masque
WARN inbound protocol not yet supported, skipping tag=masque-in protocol=masque
extra port 19002 listening=False        ← 入站根本没监听
```

**协议缺口清单（Go 有、Rust 表无）**：`masque`（inbound + outbound）。对照：Go `proxy/masque/client.go:394` 与 `server.go:551` 都 `common.RegisterConfig`；Rust `INBOUND_CTORS`/`OUTBOUND_CTORS` 20/18 键中无 masque。其余 Go 协议（blackhole/dns/dokodemo/freedom/http/hysteria/loopback/shadowsocks/socks/trojan/tun/vless/vmess/wireguard）均有键。

**真实后果**：
- 入站侧：服务端「假活」——进程在跑、其它端口正常，masque 端口连不上。用户排查成本高（服务端没有客户端那种报错）。
- 出站侧：同时叠加 F2 的默认出站前移 → 该节点的流量走 direct（隐私泄漏）。
- 注意：`"protocol":"shadowsocks_2022"` 这类**非 Go 方言**的协议名在 Rust 也是 warn+skip（实测）；Go 侧 ss2022 走 `"protocol":"shadowsocks"` + `method: 2022-*`，所以这条只作旁证，不计入缺口。

**建议修法**：入站/出站表未命中 → 返回错误（`BuildError::Unsupported` 已经存在，只需让 `register_outbounds`/`spawn_inbounds` 把它当致命）；或者退一步：仅在「该 tag 未被任何路由/链引用」时允许 skip。

---

### F7 [P2] `probeInterval` 解析失败静默归 0

**现状**：`crates/xray-core/src/register.rs:396-400`

```rust
probe_interval: json_cfg.probe_interval.as_deref()
    .and_then(parse_go_duration_ms)
    .unwrap_or(0),                        // :400
```

`parse_go_duration_ms`（`:532-550`）只解析**单段**单位（`500ms/30s/1m/1h`），注释自承「不支持复合形式（如 `1m30s`）；解析失败返回 `None`」。

**断裂点**：解析 → 运行期。`ProbeInterval == 0` 在 Go 侧等于「用默认间隔」（`app/observatory/observer.go:77-78` `if o.config.ProbeInterval != 0 { sleepTime = ... }`）。

**触发条件**：`"probeInterval": "1m30s"` / `"1.5h"` / `"2h30m"` —— **全是 Go 合法写法**（Go 用 `duration.Duration`，`infra/conf/observatory.go:15`，`time.ParseDuration` 语义）。

**用户看到什么**：无任何日志；balancer（leastping/leastload）探测周期与配置不符。

**真实后果**：观测数据刷新率错（性能/可用性判定面）；不涉及安全。

**修法**：实现 Go duration 全语法（多段）或解析失败硬错。

---

### F8 [P2] Rust 独有入站别名缺 freedom 默认 block-private 规则

**现状**：`xray-proxy-freedom/src/config.rs:967-985`

```rust
pub fn get_default_rule_type(inbound_name: &str) -> Option<DefaultRuleType> {
    match inbound_name {
        "vless-reverse" => Some(BlockAll),
        "vless" | "vmess" | "trojan" | "hysteria" | "wireguard" => Some(BlockPrivate),
        other if other.starts_with("shadowsocks") => Some(BlockPrivate),
        _ => None,
    }
}
```

`INBOUND_CTORS` 里 `inbound:hysteria` 与 `inbound:hysteria2` 是两个独立键，`anytls`/`tuic`/`naive` 也是。这些名字走 `_ => None` → **无默认 final rule** → 客户端经这些入站可以访问 127.0.0.1/RFC1918（Go 对等协议 `hysteria` 会 BlockPrivate）。

**断裂点**：装配（`outbound.rs:147-160` 用该函数建表）→ 运行期 freedom final rule 选择。
**后果**：SSRF 面扩展（P2；对 `hysteria2` 这种 hysteria 的同义别名，属明显遗漏）。**修法**：`"hysteria2"` 并入 `"hysteria"` 分支；对 Rust 独有协议明确决定并记录。

---

### F9 [P2] dns app 两处装配降级

`crates/xray-app-dns/src/jsonconf.rs`：
- `:306` matcher 构建失败 → `domain_matcher = None` + `WARN "dns: domain matcher build failed, fallback only"` → 所有 per-nameserver `domains` 限定**整表失效**（查询不再按域名分流，全落 fallback server）。
- `:297` 本机 resolver 不可用 → `clients` 保持空 + `WARN "dns: default localhost client unavailable"` → 之后**每次查询都 EmptyResponse**（等于 DNS 全失效），而进程正常。

这两处触发条件是环境/内部不变量（非用户配置直接写错），故 P2；warn 存在，但后果面很重，建议在 R2 复核运行期影响。

---

### F10 [P2] 重复用户 warn+skip（Go 硬错）

`inbound.rs:4621`（vless）/`:5056`（vmess）/`:3891`（trojan+reality）：`tracing::warn!(error, "skip duplicate ... user during validator build")`。
Go `proxy/vless/inbound/inbound.go:64-66`：

```go
if err := validator.Add(u); err != nil {
    return nil, errors.New("failed to initiate user").Base(err)   // 构建失败 → 拒启
}
```

后果：重复配置（常见于配置生成器拼接）时，被丢的那份用户**静默不可用**。若两份是同一 id 不同 flow/level，实际生效的是先到者，行为与预期可能不同。warn 可发现但极易漏。

---

### F11 [P3] `ipsBlocked` 声明但无消费点、无弃用告警

`xray-conf/src/protocols.rs:1117-1119` 注释写「保留字段用于触发 Build 阶段警告」，但全仓零消费（320 字段普查唯一命中）。Go `infra/conf/freedom.go` 对应分支会 `errors.LogWarning("The feature \"ipsBlocked\" has been removed ...")`。行为（忽略列表）两侧一致，差的是**弃用告警缺失**。P3。

---

## 4. 安全后果单列（访问控制 / 证书校验 / 路由屏蔽 / 隐私）

| 编号 | 严重度 | 失效面 | 一句话后果 | 证据 |
|---|---|---|---|---|
| F1 | **P0** | 路由屏蔽/分流 | 任一路由配置笔误 → 全部屏蔽规则降级为 Exact 语义或整体消失 → 本该拦截的流量**直连** | E1：a_ok 阻断 vs a_fallback 直连 |
| F2 | **P0** | 出站选择（隐私） | 任一 outbound 配置写错 → 该代理消失 → 默认出站（多为 freedom）接管 → **用户以为在代理，实际明文本机直连** | E1：bad uuid → PONG + ACCEPT |
| F3 | **P0** | freedom finalRules | `geoip:`/笔误 CIDR → 规则项被丢弃 → 匹配域扩为「全部」→ block 变**全阻断**、allow 变**全放行**；**零日志** | E1：geoip:cn / typo 均挂死 |
| F4 | **P1** | 嗅探排除（可达访问控制） | 排除列表项写错 → 该域名仍被嗅探 → `destOverride` 场景下目的地被**改写绕过分流规则**；全失败则整表消失 | E1：两条 WARN + 嗅探照常 |
| F5/F6 | **P1** | 服务面/出站面 | 入站协议不支持 → **无监听器**（服务端假活）；出站 unsupported（masque）→ 节点消失并叠加 F2 直连 | E1：端口 19002 不监听 |
| F8 | **P2** | 入站→内网可达性 | `hysteria2`/`anytls`/`tuic`/`naive` 入站无 BlockPrivate 默认规则 → 客户端可打内网/环回 | E2 源码 |
| F10 | **P2** | 用户凭据面 | 重复用户静默丢一份，被丢的那份凭据不可用（非泄漏） | E2 源码 + Go 对照 |

**证书校验面：本轮未发现降级**。已核：
- btls 握手失败 → **返回错误**，不回退 rustls（`xray-tls/src/utls.rs:619-621`，附「配置了指纹却静默回退标准 rustls 等于伪装失效（批3 裁决）」）；
- 指纹清单外 → 硬错（`utls.rs:626-630`）；
- 唯一 warn 型降级是「无指纹 + 配了 ECH」→ rustls 路径不打 ECH（`utls.rs:633-640`），与 Go `crypto/tls`（无 ECH 能力）行为等价，**不是回归**。

**「tag 不存在落默认出站」这一历史担忧不成立**：`xray-app-dispatcher/src/default.rs:1345-1363` 已按 Go 的 `DO NOT CHANGE` 实现（关 writer + return，不落默认出站），强制 tag 分支同（`:1283-1299`）。仅 `pick_route_resolved` 返回 Err（含「no route matched」）时落默认出站，与 Go `routedDispatch` 的 `if route, err := d.router.PickRoute(...); err == nil` 完全同构。

---

## 5. 性能后果单列（供 R2 交叉引用）

| 编号 | 性能/资源后果 | 定位 |
|---|---|---|
| F2 | 出站被跳过时「默认出站前移」改变**流量拓扑**：从代理链路变成直连（吞吐/时延/RTT 全部变化），性能基线对比时若配置有坏节点会得到假数据 | `xray-core/src/outbound.rs:208` |
| F7 | `probeInterval` 解析失败 → 探测周期落到默认值：balancer 选优滞后或过频（过频=CPU/连接数上升，过滞=劣化节点发现慢） | `xray-core/src/register.rs:399-400` |
| F9 | dns matcher 失效 → 全部查询落 fallback server（时延上升，可能绕过并行查询 `enableParallelQuery` 的分流优势）；clients 空 → 每次查询立即空返回（看似"变快"，实为解析失败） | `xray-app-dns/src/jsonconf.rs:297,306` |
| F1 | PatternRouter 回退**不影响热路径性能**（线性扫描规则数与 PatternRouter 实现同量级），但会让「本该被 blackhole 丢弃」的连接真的建立并传输 → 带宽/CPU 上升 | `xray-core/src/router.rs:303-311` |

**性能开关接线普查（本条为 F12 的证据）**：对 `xray-conf` 320 个 `pub` 配置字段做外部引用计数，与性能/资源相关且**已确认有消费点**：

| 配置面 | 消费点 |
|---|---|
| `mux.enabled/concurrency`、`mux.xudpConcurrency`、`mux.xudpProxyUDP443` | `xray-core/src/outbound.rs:607-680`（三态 `XudpMode`）+ `xray-app-dispatcher/src/default.rs:60` |
| ss `uot` / `uotVersion` | `xray-proxy-ss/src/dispatcher.rs:396-425`（`UdpOverTcpConfig`） |
| dns outbound `rewriteNetwork/rewriteAddress/rewritePort` | `xray-proxy-dns/src/plugin.rs:251`、`xray-core/src/outbound.rs:2403` |
| `observatory.probeInterval` / `enableConcurrency` | `xray-core/src/register.rs:396-401`（见 F7 缺陷） |
| `policy.levels[]` 各档 | `xray-core/src/register.rs:490-530` + `with_policy` |
| `sockopt.*` | `xray-transport/src/dialer.rs:213-300`（`validate_sockopt_json` 启动期硬错） |

结论：**没有发现「配置存在、运行期零消费」的性能开关**（唯一零消费字段是 `ipsBlocked`，语义为弃用忽略，见 F11）。限制：本普查只覆盖 `xray-conf` 强类型结构体字段；`streamSettings`/协议 settings 走原始 `serde_json::Value` 的路径不在普查范围内（属 R2 面，已在此声明）。

---

## 6. 验证为「无问题」的项（防误报 / 防 R2 重复）

| 项 | 结论 | 证据 |
|---|---|---|
| TLS 指纹回退 rustls | **硬错，不回退** | `xray-tls/src/utls.rs:619-630` |
| ECH 在 rustls 路径 | warn + 无 ECH 连接（与 Go 无 uTLS 时等价） | `utls.rs:633-641` |
| vision flow 非法值 | **硬错**，无静默降级 | `xray-proxy-vless/src/plugin.rs:397-433`、`outbound/handler.rs:110-120` |
| 路由 tag 不存在 | 关链路，不落默认出站（Go DO NOT CHANGE 同构） | `xray-app-dispatcher/src/default.rs:1345-1363`；强制 tag 分支 `:1283-1299` |
| `PickRoute` 返回 Err | 落默认出站（Go 同构，**非缺陷**） | `default.rs:1364` vs Go `app/dispatcher/default.go:routedDispatch` |
| conf 期硬校验 | `targetStrategy:"bogus"` → 拒启；`mux.xudpProxyUDP443:"bogus"` → ValidationStage 拒启；`dns.servers:["bogus://"]` → 拒启；inbound 缺 port → 拒启 | 实测：`Error: failed to start xray: config build failed: ...`（见 `scripts/log_probe_*.txt`、`scripts/log_b_outbound_skip.txt` 首版） |
| mux 配置 `.ok()` 吞错（`outbound.rs:607/650/675`） | **用户配置不可触发**：`mux` 在 `xray-conf` 已是强类型 `MuxConfig`（`config.rs:246`），`built.rs:288` 由类型序列化而来，round-trip 不会失败；未知键（`"enable":true`）与 Go 一样被忽略 | 实测 `mux_typo_only` 正常启动（Go 亦忽略未知键） |
| `spawn_one_inbound`「inbound has no port, skipping」 | 生产**不可达**（conf 期已硬错 `failed to build inbound.port`）；属防御码 | 实测 `Error: ... inbound 'noport-in' has no port` |
| fakedns 无 destOverride | 仅 warn，**与 Go 一致**（`infra/conf/fakedns.go:131` 同样 `LogWarning`） | E2 对照 |
| `Config.fake_dns` / `burst_observatory` 字段「无外部引用」 | **误报**：`built.rs` 的 `push_app!` 宏消费 | `crates/xray-conf/src/built.rs` |
| ss `uot_version` / dns `rewrite_network` 字段「无外部引用」 | **误报**：经原始 JSON 消费（`first.get("uotVersion")` / `go_json_str(v,"rewriteNetwork")`） | 见 §5 表 |

---

## 7. 未覆盖范围

1. **框架路（`xray-cli` `framework-assembly`）**：本轮全部以生产主路取证。`fill_bridge` / `derive_families` 侧的 skip 语义未逐一核对（已知其 fail-fast 门只在该路生效，`assembly_path_equivalence.rs` 有差异台账）。
2. **`streamSettings` / 各协议 settings 的原始 `Value` 解析面**：这些不走 `xray-conf` 强类型字段，我的「320 字段普查」不覆盖；本报告只在 F3（freedom finalRules）与 F7 上做了点状取证。
3. **运行期非配置消费点**（连接级错误处理、pump 退出、UDP 会话回收）：我只扫了 `Err(e) => {warn}` 形态并抽查了 `inbound.rs`/`default.rs` 的 accept/pump 路径（多为单连接可见失败，未列发现）；系统性覆盖属 R2。
4. **trait 动态分发路径**：`DispatchHandler`/`OutboundHandlerManager`/`Feature` 的实现选择未做「生产装配处是否真构造过该 trait 对象」的穷举核对；本轮只对 `register_outbounds` / `spawn_inbounds` / `new_from_built` 三个装配入口做了逐臂核对。
5. **`masque` 缺口是否为本轮已知规划内**（是否有 bd 票在跟）：未查 bd。
6. 未审 Go 侧除「解释刻意对齐」以外的行为差异（按非目标）。
