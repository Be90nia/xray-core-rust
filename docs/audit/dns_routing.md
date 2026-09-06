# 第三轮审计:DNS 客户端 + 路由引擎 + Dispatcher 决策链

- 审计对象: `xray-app-dns` / `xray-app-router` / `xray-app-dispatcher` vs Go 基准 `D:/Project/Xray-core` (v26.7.28) `app/dns` / `app/router` / `app/dispatcher`
- 方法: 逐点对照源码,只读;每个发现给 file:line + 代码证据 + Go 基准对照 + 负优化自查
- 勿重复项已遵守: cache_controller.rs:240 清理未接线 / dns config.rs domain 匹配 / app_config 键族 / balancer selector 未接线(仅关联提及)
- 统计: **P0x1  P1x6  P2x14  P3x7**(另 3 项文档化偏差备案,不计发现)

---

## 一、DNS 客户端 (xray-app-dns)

### 发现

**[P0] parallel_query 组间推进后 JoinSet 排空导致无限自旋** | crates/xray-app-dns/src/server.rs:437-502
- 证据: 主循环 `while next_group < group_count { let recv = set.join_next().await; match recv { Some(Ok(v)) => v, _ => continue } ... }`。当第 1 组全部失败而第 2 组结果早已收到(存于 `outcomes`)时,`next_group` 推进到 1 后 `join_next()` 返回 None(JoinSet 已排空),走 `_ => continue` → while 条件仍真 → **空转死循环,永不返回,CPU 100%**。Go dns.go:386-438 在收到每个结果后于内层 for(nextGroup < len(groups))立即对已缓存结果做组内 race 检查,后组成功直接返回;Rust 把成功检查绑定在"再来一个新结果"之后,排空后无检查机会。
- 影响: `enableParallelQuery: true` 且 >=2 个 policy 组(不同 domains/tag/expectedIPs 即不同组,geosite:cn 国内外分流是典型形态)时,前组全败 + 后组结果先到 → 该域名的每一次解析任务永久挂死并烧满一个核。
- 修复建议: `join_next()` 返回 None 时跳出循环;并把"组 race 检查"提取为函数,在 `next_group += 1` 后立即对下一组(含已收结果)循环执行,对齐 Go dns.go:414-437 内层 for。
- 负优化自查: 无。仅消除自旋,组内 race 返回最小 RTT 的成功语义不变。

**[P1] singleflight 领导任务中止 → 条目永久泄漏 + 等待者永久挂起** | crates/xray-app-dns/src/nameserver/cached.rs:107-130
- 证据: 领导者 `sf.insert(sf_key, tx)` 后 `send_query(...).await` 期间被 abort(P0 的 `set.abort_all()` 或任意任务取消)时,`sf.remove` 永不执行 → tx 留在 map 中。后续同 key 查询走 `sf.get → rx.recv().await`:因 map 持有 Sender,channel 永不 Closed、领导者永不 send → **recv 永远 Pending,该 (server, fqdn, family) 的所有后续查询挂死**。且 Client.query_ip 无超时包裹(nameserver/mod.rs:233-241),无解挂机制。
- 影响: parallel_query 组成功 abort 他组在飞查询(常见触发)后,同域名后续所有对同一 server 的查询永久挂起。
- 修复建议: 领导者改 guard(Drop 时 `sf.remove`);最小修法:等待者 `rx.recv()` 外加 timeout(query_timeout),超时路径补 `sf.remove(&sf_key)` 清理死条目。
- 负优化自查: 正常命中时零开销;清理仅一处 HashMap 删除,无回退。

**[P1] hosts 域名替换出现环时 lookup_ip 无限递归** | crates/xray-app-dns/src/server.rs:248-253 + crates/xray-app-dns/src/hosts.rs lookup_inner
- 证据: Go hosts.go:90-103 的 unwrap 链由 maxDepth 5 兜底,链耗尽返回 [Domain(尾域)] 后 LookupIP(dns.go:250-253) 直接**落入 nameserver 查询,终止**。Rust server.rs:253 对返回的 Domain 条目调 `recursive_lookup_domain` → 重新执行**完整** lookup_ip(含 hosts,且 max_depth 重置为 5)。配置 `hosts: {"a.com":"b.com","b.com":"a.com"}` 时 lookup(a) 每次都返回 Domain 条目 → lookup_ip(a)→lookup_ip(a) 自引用无限递归(future 永不完成)。
- 影响: 环形 hosts 配置使该域名解析永久挂起;Go 侧优雅回退上游解析。
- 修复建议: 递归改为 Go 语义——hosts unwrap 耗尽后直接以尾域名走 sort_clients + serial/parallel_query(不再进 hosts)。
- 负优化自查: 无。少一次 hosts 重查。

**[P2] 负缓存条目只写不读,NXDOMAIN 域名每次回源** | crates/xray-app-dns/src/nameserver/cached.rs:83-84 + cache_controller.rs upsert_negative
- 证据: 缓存命中路径 `match merge_records(...) { Ok((ips,ttl)) if ttl>0 => return, _ => {} }`——负缓存记录(rcode=3, ips 空)在 `IpRecord::get_ips`(dnscommon.rs:96-110) 产出 Err(RCodeError(3)) → 命中不成立 → 落入 fetch 回源。Go nameserver_cached.go:31-52: 命中 merge 返回 RCodeError 时 `!Is(err,errRecordNotFound) && ttl>0` → **直接从缓存返回该错误**,不回源。
- 影响: NXDOMAIN/NODATA 域名每次查询都打上游,放大上游流量与延迟。
- 修复建议: 命中分支补 `Err(e) if !matches!(e, RecordNotFound) => { if rec 未过期 { return Err(e) } }`。
- 负优化自查: 纯读路径短路,减少上游查询,无回退。

**[P2] UDP 上游 bind 硬编码 0.0.0.0 → IPv6 DNS 服务器必败** | crates/xray-app-dns/src/nameserver/udp.rs:87-91
- 证据: `UdpSocket::bind("0.0.0.0:0")` 后 `send_to(self.addr)`;addr 为 IPv6 SocketAddr 时 family 不匹配,send_to 返回 InvalidInput,每次查询必败。
- 影响: `{"address":"2001:4860:4860::8888"}` 类 IPv6 上游全部失败。
- 修复建议: 按 `self.addr.is_ipv6()` 选择 `"::"` 或 `"0.0.0.0"`。
- 负优化自查: 一处 family 分支,零开销。

**[P2] hosts `domain:` 前缀键静默降级为精确匹配** | crates/xray-app-dns/src/jsonconf.rs parse_hosts + hosts.rs InMemoryMatcher
- 证据: parse_hosts 对 `domain:`/`full:` 一律剥前缀存 HostMapping.domain(无类型字段),InMemoryMatcher 仅 HashMap 精确等值。Go conf dns.go:258 `geodata.ParseDomainRule(rule, Domain_Full)`——`domain:example.com` 是 **Domain(子域)** 规则,匹配所有 `*.example.com`。
- 影响: `hosts:{"domain:corp.example":"10.0.0.1"}` 在 Rust 只命中精确键,子域全部漏配。
- 修复建议: HostMapping 增加 DomainType;`domain:` 类型入 trie(xray-geodata DomainMatcherGroup 现成),`full:`/裸键保持精确。
- 负优化自查: 仅 domain: 前缀条目走 trie,裸键仍 O(1),无回退。

**[P2] DoH 自定义 URL path 被剥除,恒请求 /dns-query** | crates/xray-app-dns/src/nameserver/mod.rs:306-307 + doh.rs:240
- 证据: parse_dns_url "Strip path for DoH" 丢弃 path;请求 `.uri(DEFAULT_DOH_PATH)`(硬编码)。Go nameserver_doh.go 使用完整 u(含 path)。
- 影响: `https://1.1.1.1/query`、AdGuard Home 自定义 path 的 DoH 服务端 404,该 server 永久失败。
- 修复建议: parse_dns_url 保留 path 透传,空则 /dns-query。
- 负优化自查: 无。

**[P2] DoQ 默认端口 854,Go 为 853** | crates/xray-app-dns/src/nameserver/mod.rs:298-302
- 证据: `"quic" => 854`;Go nameserver_quic.go:41 `port := net.Port(853)`(RFC 9250 同 853)。
- 影响: `quic://IP` 不带端口的配置连错端口,该 server 必败。
- 修复建议: 改 853。
- 负优化自查: 无。

**[P2] hosts 命中但族过滤后为空 → 落回上游(Go 短路 EmptyResponse)** | crates/xray-app-dns/src/server.rs:248-256 + hosts.rs lookup_inner
- 证据: Rust lookup 对"记录在案但 filter_ip_entries 后为空"返回 Ok(vec![]),与"未记录"不可区分;server.rs 继续走 nameservers。Go hosts.go:94-99 保留 addrs==nil(未记录)与 len==0(已记录无有效 IP→dns.go:242-244 返回 ErrEmptyResponse)两个状态。
- 影响: hosts 写死 IPv4 + queryStrategy UseIPv6 时,Rust 仍向上游查询并可能返回上游 AAAA;Go 以 hosts 为权威否决。
- 修复建议: lookup 返回 Option<Vec<Address>>,Some(空) 时返回 EmptyResponse。
- 负优化自查: 无。省一次上游查询。

**[P2] TTL=0 应答缓存 60 秒(Go 为 1 秒)** | crates/xray-app-dns/src/dnscommon.rs parsed_to_ip_record
- 证据: `ttl_secs==0 → Duration::from_secs(60)`。Go dnscommon.go:141-143 `ttl := ah.TTL; if ttl == 0 { ttl = 1 }`——逐记录 0 TTL 提为 1 秒,"完全无答案记录"才用 DefaultTTL。
- 影响: 动态解析(ttl=0)域名被 60 秒钉死旧 IP,与 Go 差 60 倍。
- 修复建议: 区分 `min_ttl==Some(0)`(→1s)与 None(无匹配答案→DEFAULT_TTL)。
- 负优化自查: 无。

**[P3] merge 默认 TTL 常量 600,Go DefaultTTL=300** | crates/xray-app-dns/src/dnscommon.rs:151
- 证据: `const DEFAULT_TTL: i32 = 600`;xray-features/src/dns.rs:61 已有 `DEFAULT_TTL=300`(local.rs 正确 re-export)。
- 影响: 双族合并且单族 TTL>300 时返回给调用方的 ttl 是 Go 的两倍。
- 修复建议: 删本地常量,改用 xray_features::dns::DEFAULT_TTL。
- 负优化自查: 无。

**[P3] Client.check_system 死字段,per-server UseSys 失效** | crates/xray-app-dns/src/nameserver/mod.rs:181
- 证据: 构造赋值 `check_system: matches!(ns.query_strategy, Some(UseSys))`,全 crate 无读取点(grep 证实)。Go nameserver.go:171-178 每次 QueryIP 按其钳制。服务级 UseSys 已实现,仅 per-server 覆写失效。
- 影响: `servers:[{queryStrategy:"UseSystem"}]` 全局策略非 UseSys 时不按系统路由钳制(等价 UseIp)。
- 修复建议: Client.query_ip 开头补 check_system 分支(check_routes 有 OnceLock 缓存,零成本)。
- 负优化自查: 进程级缓存,无额外探测。

**[P3] upsert_negative 把超时/无响应标成 NXDOMAIN** | cache_controller.rs upsert_negative + cached.rs:143,154
- 证据: fetch 中 rec 为 None(失败/超时)即写 rcode=3 记录。语义错误:网络失败 ≠ 域名不存在;负缓存读路径(P2 上条)修复后会放大故障。
- 影响: 仅 negativeTtlSecs>0 时生效(当前因读路径失效无实害,修上条后转真缺陷)。
- 修复建议: 仅上游明确 rcode!=0/空应答写负缓存,超时不写。
- 负优化自查: 无。

**[备案·文档化偏差(不计发现)]** 1) 域名地址 nameserver 跳过并告警(jsonconf.rs build),Go 支持经 dispatcher 解析的域名上游——`https://dns.google/dns-query` 类最常见配置静默不生效,注释已声明 bootstrap resolver 升级路径;2) 全部 nameserver 直连 socket(udp.rs 文件头),上游查询不经路由/sockopt/代理出口,tag/IsOwnLink 防环空转;3) read_system_hosts 读不到返回空,Go conf 层 fail-fast。

### DNS 抽查点·确认干净(证据)

1. **merge A/AAAA 双族合并**: RNF 短路、min-TTL、单族直通、双族错误聚合——dnscommon.rs:150-211 与 Go nameserver_cached.go:118-166 merge 逐分支等价。
2. **Client expected/unexpected IP 四分支**: 非 prior 的 expected 过滤空即 Err、非 unprior 的 unexpected 剥离空即 Err、actPrior/actUnprior 命中非空替换——nameserver/mod.rs:233-261 与 nameserver.go:181-249 一致。
3. **sort_clients**: matcher 命中升序、final_query 提前返回(含 log_decision)、fallback 跳过 used/skipFallback、空兜底取第一 client——server.rs:128-198 与 dns.go:268-321 对齐。
4. **serial_query**: FakeDNS 跳过、final_query 失败即终止、merge 聚合——server.rs:408-433 与 dns.go:363-380 等价。
5. **rcode 映射**: from_rcode(0)→EmptyResponse、非 0→RCodeError——error.rs:84-91 与 hosts.go:84-88 一致(有单测)。
6. **localTLDs+dotless**: localhost 注入 `^[^.]+$`+local/lan/home.arpa 等 9 条,空 servers 注入 localhost client——jsonconf.rs:119-176 与 dns.go:94-115,167-170 对齐,含"默认路径不走 updateRules"细节。
7. **policy_id 8 段等价键**(8kha): client|skip|qs|tag|domains|expected|expect|unexpected 规范化拼接、列表排序小写——jsonconf.rs policy_key 与 conf dns.go:288-352 对齐。
8. **expectedIPs→expectIPs 回填**: jsonconf.rs effective_expected_ips 与 dns.go:94-96 一致,policy key 同读回填值。
9. **TCP/DoT/DoQ 2B 长度前缀**: 发送 u16::try_from 防截断、接收 read_exact+上限拒绝——tcp.rs:137-166 / dot.rs:170-201 / quic.rs:153-207(有 mock e2e 单测)。
10. **EDNS0 client subnet**: /24(v4)、/96(v6) 掩码——dnscommon.rs build_dns_query 与 dnscommon.go:88-110 一致(padding 未实现,Go 仅部分路径用,可忽略)。
11. **queryStrategy 别名表**: 全别名与 conf dns.go:381-394 一致,未知回退 UseIp(jsonconf.rs parse_query_strategy)。
12. **useSystemHosts**: 合并系统 hosts、去注释、按域聚合、裸键 Full 精确——jsonconf.rs:216-219 + hosts.rs parse_system_hosts 与 conf dns.go:370-376,414-451 一致。

---

## 二、路由引擎 (xray-app-router)

### 发现

**[P1] leastload: tolerance 被当作 RTT 容差带 + baselines 改为就近匹配,算法整体偏离 Go** | crates/xray-app-router/src/strategy_leastload.rs:229-243,252-283 vs Go strategy_leastload.go:111-152,168-172
- 证据: Rust get_nodes: `let tol_ns = tolerance * rtt; if !baselines.iter().any(|b| (rtt-b).abs() <= tol_ns) { continue }`——baselines 变成"任一基线的容忍带",tolerance 变成 RTT 相对带宽。Go: Tolerance 是**失败率**(HealthPing.Fail/All > Tolerance 则淘汰,strategy_leastload.go:168-172),baselines 是排序后**累计上限走查**(RTTDeviationCost >= baseline 即 break,count 累计到 expected 为止,:127-146),且 Go 在 `Tolerance > 0` 才启用失败率过滤。Rust 还完全缺失失败率(CountFail/CountAll)过滤;选择从"选中集均匀 dice.Roll"(Go :104-108)改为 1/(cost+1) 加权随机;排序键从 5 键(cost/avg/fail/all/tag)减为 3 键。
- 影响: **Go 默认 tolerance=0 的 baseline 配置在 Rust 下 `(rtt-b).abs() <= 0` 要求精确相等——实际全部节点被过滤 → 恒走 fallback 或 EmptyBalancerResult**;有健康检查失败率的节点在 Rust 照样入选。leastload 策略对所有含 baselines 的配置实质不可用。
- 修复建议: 恢复 Go 语义:baselines 走排序后累计上限(count 累计 + `count >= expected` break);tolerance 回归失败率过滤(`fail/all > tolerance → 剔除`,且 tolerance>0 才启用);选择改回选中集均匀随机;排序补 CountFail/CountAll 两键。
- 负优化自查: Go 算法本身 O(n log n)(一次排序+线性走查),无回退;weighted-random 改 uniform 减少一次随机数生成。

**[P1] random 策略杜撰 50/50 fallback 行为,Go 无此语义** | crates/xray-app-router/src/strategy_random.rs:44-49 vs Go strategy_random.go:52-67
- 证据: Rust: fallback_tag 非空时掷硬币,50% 直接返回 fallback。注释"与 Go 一致: fallback 非空时按 50/50 跟 fallback 随机"——**Go RandomStrategy.PickOutbound 无任何 fallback 掷码逻辑**:候选空返回 ""(由 Balancer 层落 fallbackTag),否则在候选中均匀 `dice.Roll`。
- 影响: 配置 `strategy:"random"` + `fallbackTag` 的 balancer,Rust 把约一半流量固定打到 fallback 出站;Go 语义 fallback 仅在候选全灭时兜底。路由分布实质错误。
- 修复建议: 删除掷码分支,pick 直接返回随机候选;空候选返回 Err(EmptyBalancerResult) 由 Balancer fallback(balancing.rs 已如此)。
- 负优化自查: 少一次随机数与分支,无回退。

**[P2] geoip/geosite 资源加载失败静默放宽规则(fail-open)** | crates/xray-app-router/src/rule.rs:parse_proto_domain_rules + convert_proto_ip_rules/load_geoip_to_matcher_rules
- 证据: geosite 条目加载失败/loader 缺失时 `tracing::warn!` 后 continue,**该条件整个从规则中消失**;geoip 同样 warn+skip。全部条件被剥光时才 Err(EmptyRule)。Go BuildCondition(config.go)对 matcher 构建失败直接返回 error——router init fail-fast。
- 影响: geoip.dat/geosite.dat 缺失或损坏时,形如 `domain:["geosite:cn"], outboundTag:"proxy"` 的规则静默变成"全域匹配"或被整条移除,流量改走默认出站——**路由策略静默失效,可能造成本应走代理/被拒的流量直连**。
- 修复建议: geosite/geoip 解析失败改为返回 Err(与 Go 一致 fail-fast);至少提供 `strict` 开关默认 true。
- 负优化自查: 无。启动期一次性校验,零运行时开销。

**[P2] substr/regex 域名规则大小写敏感(Go 输入统一 ToLower)** | crates/xray-app-router/src/condition.rs:107-113 + crates/xray-geodata/src/matcher/matcher_groups.rs:285-288
- 证据: DomainMatcherCondition::apply 把原始 `ctx.get_target_domain()` 传 `match_any`。MphDomainMatcher 内部仅 mph 组(Full/Domain 规则)对输入做 `to_lowercase`(index_mph.rs:816,848);substr 规则走 `simple` 组(SubstrMatcherGroup),`input.contains(&e.pattern)` 用原始输入对已小写 pattern——**大小写敏感**。Go condition.go:80-86 `MatchAny(strings.ToLower(domain))` 对全部类型统一小写。
- 影响: 目标域为混合大小写(sniff/CNAME 链常见)时,keyword/substr 类规则(如拦截 "doubleclick")漏匹配 → 广告拦截/分流规则失效。
- 修复建议: DomainMatcherCondition::apply 传 `d.to_lowercase()`(一行,与 Go 对齐);或 SubstrMatcherGroup::match_any 内部小写。
- 负优化自查: 每次匹配多一次小写分配——Go 同样每次 ToLower,且域名长度短、match_any 本就有哈希/AC 开销,实测无感。

**[P2] roundrobin 观测快照中未出现的候选视为 dead(Go 视为 alive)** | crates/xray-app-router/src/balancing.rs:116-141 vs Go strategy_random.go:56-63 / balancing.go RoundRobinStrategy
- 证据: Rust alive_outbounds: `selected.filter(|t| observation.status.any(|s| s.alive && s.outbound_tag == t))`——无状态条目的候选被过滤。Go 两个策略均: `if found { if Alive { keep } } else { keep }`(**unfound = alive**)。
- 影响: observatory 运行但新加/未被探测的出站永远选不中;首轮探测完成前 balancer 可能全空 → fallback,而 Go 正常分流。
- 修复建议: 改为 `status.iter().find(|s| s.outbound_tag==t).map_or(true, |s| s.alive)`。
- 负优化自查: 无。一次查找语义修正。

**[P2] leastping 策略结构上不持有 selectors,完全无视候选集过滤** | crates/xray-app-router/src/strategy_leastping.rs:23-60
- 证据: `LeastPingStrategy { observer }` 无 selectors/ohm 字段,pick_outbound 遍历**全部**观测状态取最小 delay。Go strategy_leastping.go:48-52 `outboundsList.contains(v.OutboundTag) && v.Alive && Delay < leastPing`——仅在选择器选出的候选中选。
- 影响: `selector: ["proxy-a","proxy-b"]` + leastping 时,Rust 可能选中观测表中任何最小 delay 出站(如 direct),绕开用户指定候选集。(与已知"selector 未接线"同根:此处为策略结构体根本没存 selectors,单列备查)
- 修复建议: 仿 RandomStrategy 持有 selectors+ohm,pick 前 `ohm.select_outbounds(&self.selectors)` 过滤。
- 负优化自查: 一次 O(n) 过滤,与 Go 相同。

**[P3] proto 端口 u32 → u16 静默截断** | crates/xray-app-router/src/rule.rs:to_mem_port_list
- 证据: `Port::new(r.from as u16)`——proto PortRange from/to 为 u32,`as u16` 截断(70000→4464),Go conf 层校验 0-65535 报错。
- 影响: 上游 conf 未校验端口范围时,生成错误的端口区间且无告警(静默路由偏差)。
- 修复建议: `u16::try_from(...)` 失败返回 RouterError。
- 负优化自查: 无。

**[P3] pick_route 命中"空出站 tag"规则时跳过继续,Go 中止并报错** | crates/xray-app-router/src/router.rs:169-181 vs Go router.go:236-241
- 证据: Rust `if let Some(tag) = rule.apply(ctx) { if !tag.is_empty() { return } }`——空 tag 规则被跳过,继续匹配后续规则。Go: 规则命中即返回该 rule,GetTag 为空 → PickRoute 报错 → dispatcher 走默认出站路径(不再匹配后续规则)。
- 影响: 仅影响误配置(规则命中但未配 outboundTag/balancingTag):Rust 可能落到更后面的规则。
- 修复建议: 命中即返回(含空 tag),由上层按 Go 语义处理。
- 负优化自查: 无。

### 路由抽查点·确认干净(证据)

1. **ConditionChan AND 语义**: 空 chan 永真、任一失败即假——condition.rs:58-77 与 condition.go:29-41 一致。
2. **九种 matcher**: IP 三维 asType(Target/Source/Local)+VlessRoute 占位、端口四维、网络 [8]bool 位集、用户等值+`regexp:` 前缀、入站 tag 等值、协议前缀 starts_with、属性 key 双侧小写折叠+value 正则、进程名四类——condition.rs:86-560 与 condition.go:44-263,264-395 语义一致(用户正则编译失败 Rust 报错 vs Go 静默忽略该条,Rust fail-fast 更严,无行为损害)。
3. **pick_route 首中即返 + NoClue**: router.rs:167-181 与 router.go:236-272 一致;规则按配置顺序优先级,无重排。
4. **domainStrategy 解析重跑**: IpOnDemand 先解析再匹配、IpIfNonMatch 首轮不中且有域名时解析后重跑一轮、skipDNSResolve 防环、无 dns/AsIs 退化——router.rs:184-253 与 router.go:243-272 逻辑等价;DNS 客户端已在 xray-core/src/functions.rs:204-210 接线(DnsService 或 localdns 兜底),resolve_into 失败仅去 debug 日志并按域名匹配(Go ResolvableContext 语义同向)。
5. **Balancer 选择链**: override > strategy > 空结果 fallback > 无 fallback 报错——balancing.rs:197-227 与 balancing.go:100-122 一致;override 可由 commander 运行时改写(balancing_override 对应)。
6. **leastload cost 加权**: `value * sqrt(cost)`——strategy_leastload.rs rtt_deviation_cost 与 Go NewLeastLoadStrategy WeightManager 回调一致(weight.rs 对应 Go weight.go)。
7. **geoip reverse_match XOR**: 规则 reverse 与 dat 条目 reverse 异或合并——rule.rs load_geoip_to_matcher_rules,与 Go geodata 层语义一致。
8. **运行时规则管理**: add/remove/reload、重复 ruleTag/balancer tag 校验、webhook 命中触发——router.rs init/add_rule/reload_rules 与 router.go Init/ReloadRules 对齐。

---

## 三、Dispatcher 路由决策链 (xray-app-dispatcher)

### 发现

**[P1] 路由命中但出站 tag 不存在 → 回落默认出站(Go 明令禁止,须关闭链路)** | crates/xray-app-dispatcher/src/default.rs:908-916 vs Go default.go:455-465
- 证据: `Ok(route) => { let picked = ohm.get_handler(&route.outbound_tag); if picked.is_some() {...} else { warn!("routed handler not found, falling back to default"); (ohm.get_default_handler(), false) } }`。Go routedDispatch 同分支: `errors.LogWarning("non existing outTag"); Close(link.Writer); Interrupt(link.Reader); return // DO NOT CHANGE: the traffic shouldn't be processed by default outbound if the specified outbound tag doesn't exist (yet), e.g., VLESS Reverse Proxy`。
- 影响: 规则指向未注册/拼写错误的 tag 时,Rust 把流量静默交给默认出站(通常是 direct)——**流量走错出站(泄露面)**;Go 直接断链。VLESS 反代等"延迟注册 tag"场景下,Rust 会把本应等待/断开的连接交给默认出站。
- 修复建议: else 分支改为 `outbound_writer.shutdown(); return;`(对齐 Go),与 forced_tag 分支(855-867,已正确不回落)同构。
- 负优化自查: 无。断链替代错误转发,无新增开销。

**[P1] routeOnly 丢弃嗅探域名 → 域名规则永不命中** | crates/xray-app-dispatcher/src/default.rs:529-535(override_dest)+ 546-565(build_routing_context)vs Go default.go:196-200,235-240
- 证据: Rust `if req.route_only { debug!("sniffed (route_only, dest unchanged)"); return dest.clone(); }`——嗅探到的域名被丢弃;build_routing_context 仅从 final_dest(原 IP)+ 协议构造,无域名入参。Go: 先 `destination.Address = net.ParseAddress(domain)`,再按 `sniffingRequest.RouteOnly` 分流——`ob.RouteTarget = destination`(域名目标用于**路由**),`ob.Target` 保持原始 IP(用于**实际拨号**)。
- 影响: `routeOnly: true`(sniff+domainStrategy 的主流组合:按域名分流但不按域名回源)时,Rust 路由上下文无域名,`domain:["geosite:cn"]` 等规则永不命中,全部按 IP/默认出站——sniffing+routeOnly 组合的域名分流整体失效。
- 修复建议: DispatcherContext 增加 route_target 字段(或 build_routing_context 增加 sniffed_domain 参数):route_only 时路由用嗅探域名、拨号保持原 dest。
- 负优化自查: 仅上下文多一个字符串,无回退。

**[P2] 路由上下文缺 source/user/源端口 → sourceIp/user 规则静默失效** | crates/xray-app-dispatcher/src/default.rs:546-565 + 901-907 vs Go routing_session.AsRoutingContext
- 证据: build_routing_context 仅填目标地址+嗅探协议;dispatch_link 只回填 inbound_tag(903-907)。DispatcherContext 本有 with_source_ips/with_user 等构造器(167-180)但生产路径无人调用。Go 路由上下文携带 Source 地址、User(level 用户邮箱)、Protocol、Network、Inbound 等。
- 影响: `sourceIp`、`user` 路由规则在生产 dispatch 链路永不命中(静默)。
- 修复建议: AccessContext 扩展 source/user 并在 build_routing_context 回填(inbound_tag 已示范)。
- 负优化自查: 字段复制,无回退。

**[P2] excludedDomainForSniffing 用子串 contains,Go 用域名匹配器** | crates/xray-app-dispatcher/src/default.rs:406-411 vs Go default.go:316-318
- 证据: `if domain_lower.contains(excl.as_str()) { return false }`。Go: `request.ExcludeForDomain.MatchAny(strings.ToLower(domain))`——geodata 域名匹配器(子域/后缀语义,带 label 边界)。
- 影响: 排除表 `["qq.com"]` 会把 `notqq.com.evil.io` 等无关域名也排除嗅探 → 应嗅探的连接未嗅探,路由偏差(过宽排除)。Go 还支持 `domain:`/`regexp:` 前缀条目。
- 修复建议: 复用 xray-geodata DomainMatcher(match_any)替代 contains。
- 负优化自查: 构造期一次建 trie,匹配 O(len(domain)),无回退。

**[P2] excludeIPForSniffing 仅精确 IP 等值,不支持 CIDR** | crates/xray-app-dispatcher/src/default.rs:413-417 vs Go default.go:319-321
- 证据: `request.exclude_for_ip.iter().any(|&ip| ip == addr)`。Go: `request.ExcludeForIP.Match(destination.Address.IP())`——geoip/IPMatcher,CIDR+geoip 全支持。
- 影响: 配置 `["10.0.0.0/8"]` 在 Rust 永不命中(CIDR 存不进单 IP),内网地址嗅探无法排除 → 对内网连接做无谓嗅探/域名覆盖,行为与 Go 相反。
- 修复建议: exclude_for_ip 改存 CIDR 列表 + 前缀匹配(xray-geodata IPMatcher 现成)。
- 负优化自查: 线表扫描量级不变。

**[P3] 嗅探单次读+单次嗅探,无 NeedMoreData 重试预算** | crates/xray-app-dispatcher/src/default.rs:439-460 vs Go default.go:299-345
- 证据: Rust `timeout(handshake_timeout, cr.read_first())` 后单次 `sniffer.sniff(&payload)`;Go: 200ms 递减预算、最多 2 次尝试、`ErrProtoNeedMoreData` 不计次继续读(协议匹配但首包不足)。Rust 超时用 policy handshake 超时(默认 4s)也远长于 Go 200ms。
- 影响: ClientHello 分段到达/慢客户端时嗅探失败率高于 Go → 域名覆盖失败,回退 IP 路由;超时场景嗅探等待最长 4s(Go 200ms)。
- 修复建议: 补 2 次/200ms 预算循环,NeedMoreData 继续读。
- 负优化自查: 预算上限反而低于现状(4s→200ms),更快失败。

**[P3] fakedns "IP 在池但反查失败"与协议子集覆盖分支缺失** | crates/xray-app-dispatcher/src/default.rs:392-421 vs Go default.go:322-343
- 证据: Go shouldOverride 中 `fkr0.IsIPInIPPool(destination.Address) && p=="fakedns" && protocol!="bittorrent"` → 覆盖(fakedns 重启后反查丢失的恢复路径);以及 `SniffIsProtoSubsetOf(p)`(tls ⊂ fakedns+others)。Rust should_override 无这两分支(fakedns 仅在反查命中时进入组合判定)。
- 影响: fakedns 重启后旧 fake-IP 连接:Go 仍能用嗅探域名覆盖,Rust 不覆盖 → 按直连 fake-IP 出站失败。
- 修复建议: should_override 补 is_ip_in_pool 分支(引擎 trait 已有该方法,fakedns.rs:37)。
- 负优化自查: 单次哈希查询,无回退。

### Dispatcher 抽查点·确认干净(证据)

1. **forced_tag 不存在不落默认**: 预检同步 Err(819-843)+ 运行时分支关写端并 return(855-867),忠实 Go default.go:443-454 的 DO NOT CHANGE 语义。
2. **嗅探→覆盖→路由→出站主链**: CachedReader 首包缓存回灌、metadata(fakedns)与 content 结果 Composite 组合判定、override 后域名目标传递——default.rs sniff_connection(437-528)与 Go Dispatch sniffer 分支(184-243)流程同构。
3. **UDP443 mux 拒绝策略**: dest 为 UDP:443 且出站启用 mux 时按 policy Reject/Allow 处理——default.rs:962-975 对应 Go handler.go:220-228。
4. **access log detour 组合**: inTag 空→tag;路由命中→"in -> tag";其余→"in >> tag"——default.rs:929-953 与 Go default.go:488-502 格式一致。
5. **出站流量计数器**: `outbound>>>{tag}>>>traffic>>>{uplink|downlink}` 懒注册包读写——default.rs:955-966 与 Go getStatCounter 一致。
6. **pick_route_resolved 抽象**: trait 默认退化为同步 pick_route(default.rs:263-276),RouterAdapter 委托 router::pick_route_resolved 并桥接两套 RoutingContext(wiring.rs:111-131),dns 注入链完整(functions.rs:204-210)。

---

## TOP3(按影响排序)

1. **[P0] parallel_query JoinSet 排空无限自旋**(server.rs:437-502):enableParallelQuery + 多 policy 组的常见配置下解析任务永久挂死烧 CPU,是 DNS 域唯一必现级缺陷。
2. **[P1] 路由 tag 不存在回落默认出站**(dispatcher default.rs:908-916):违反 Go DO NOT CHANGE,错误 tag 时流量静默走默认出站(通常 direct),是安全面最大的偏差。
3. **[P1] leastload tolerance/baselines 算法偏离**(strategy_leastload.rs:229-283):默认 tolerance=0 的 baseline 配置全灭节点恒 fallback,leastload 实质不可用。

## 确认干净项清单(汇总)

- DNS: merge 双族合并 / expected+unexpected 四分支 / sort_clients 优先级与 finalQuery / serial_query FakeDNS 跳过 / rcode-0 映射 / localTLDs 自动规则 / 空 servers 注入 localhost / policy_id 8 段等价键 / expectIPs 回填 / TCP-DoT-DoQ 2B 前缀 / EDNS0 /24-/96 / queryStrategy 别名表 / useSystemHosts(12 项)
- 路由: ConditionChan AND / 九种 matcher 语义 / pick_route 首中即返 / domainStrategy 解析重跑+DNS 接线 / Balancer override>strategy>fallback / cost*sqrt(cost) 加权 / geoip reverse XOR / 运行时规则管理(8 项)
- Dispatcher: forced_tag 不回落 / 嗅探-覆盖-路由主链 / UDP443 mux 拒绝 / access log detour 格式 / 出站流量计数器 / pick_route_resolved 桥接与 dns 注入(6 项)

## 严重度统计

| 级别 | 数量 | 域分布 |
|---|---|---|
| P0 | 1 | DNS×1 |
| P1 | 6 | DNS×2 路由×2 Dispatcher×2 |
| P2 | 14 | DNS×7 路由×4 Dispatcher×3 |
| P3 | 7 | DNS×3 路由×2 Dispatcher×2 |
| 合计 | 28 | 另文档化偏差备案 3 项(域名 nameserver 跳过/直连 socket/系统 hosts 容错) |
