# 路由 / DNS / 系统拨号链路可用性审计（route-dns）

> 2026-10-19 | 审计范围：xray-app-router / xray-geodata(+platform/filesystem) / xray-transport(system_dialer, happy_eyeballs) / xray-app-dns(+xray-features/dns)
> 对照权威：D:/Project/Xray-core（Go）。只读审计，未改任何代码。
> 「file:line」未注明语言者均为 Rust 仓内路径（crates/ 前缀省略）。

## 结论汇总

**1 P0 + 3 P1 + 8 P2/信息项。** 路由规则匹配核心语义（domain: 前缀族、geoip/geosite code 大写与反向匹配、端口/网络/inboundTag/协议/属性匹配、domainStrategy 枚举编号 2/3、rule 顺序首中即停、IP 字面量命中 IP 规则）与 Go 高保真对齐；两处特殊核查结论：**①IP 字面量目标 ip/geoip 规则必然命中（与 Go 一致）；②sniffing destOverride 改写域名后 IP 规则失效——非 routeOnly 形态 Go 同样失效（一致），但 routeOnly 形态 Go 靠 `Outbound.Target` 保留原 IP 使 IP 规则仍可命中，Rust 桥接清空 target_ips 静默失效（Rust 独有偏差，P1）**。最严重问题：DNS 查询经路由出站缺 `SkipDNSResolve` 循环防护（P0），域名地址 DoH/TCP NS + domainStrategy≠AsIs 配置下递归风暴/挂死，Go 同配置正常。

---

## P0

### P0-1 ｜ DNS 查询经路由出站缺 SkipDNSResolve 防护 → 域名 NS + 非 AsIs 策略 = 递归风暴/挂死

**现象**：DNS 服务器地址为域名（如 `https://dns.cloudflare.com/dns-query`、`tcp://dns.example.com`）且 routing `domainStrategy` 为 IpOnDemand/IpIfNonMatch 时，对任意域名的 DNS 查询经 dispatcher 路由，路由层又向同一 DNS 服务解析 NS 自身域名——无任何防护，递归展开为任务风暴/深度挂起；Go 同配置正常出查询。

**根因**（Rust）：
- 生产 DNS 拨号桥 `xray-core/src/functions.rs:413-432`——dispatch 不携带任何 skip 标记：
```rust
impl xray_app_dns::dial::QueryDialer for DispatcherDnsDialer {
    fn dial_tcp(&self, dest: &Destination) -> ... {
        // Go nameserver_tcp.go:43-47 / dohnameserver.go:68：dispatcher.Dispatch
        // 完整路由链（无 forced tag，无 sniffing——DNS 查询目标即真实目标）。
        Box::pin(async move {
            let link = dispatcher
                .dispatch(&dest, &SniffingRequest::default(), None, None)
```
- 消费点 `xray-app-router/src/router.rs:177-180` 只认 ctx 上的 `skip_dns_resolve`，而 DNS-out 链路构造的 `DispatcherContext`（`xray-app-dispatcher/src/default.rs:762-780 build_routing_context`）恒为 false：
```rust
let can_resolve = !ctx.get_skip_dns_resolve()
    && self.domain_strategy != DomainStrategy::AsIs
    && !ctx.get_target_domain().is_empty()
    && ctx.get_target_ips().is_empty();
```
- 全仓 grep：`with_skip_dns_resolve(true)` 仅存在于测试；生产无一处设置（`xray-app-dispatcher/src/default.rs:1064-1070` 注释也承认 forced 分支外「per-request skip …无 ctx 可传」）。

**Go 对照**：每个经 dispatcher 出站的 DNS 查询都置位跳过标志——`app/dns/nameserver_doh.go:186-188`：
```go
Protocol:       "https",
SkipDNSResolve: true,
```
同见 `nameserver_quic.go:114-116`、`nameserver_tcp.go:146-148`；消费在 `app/router/router.go:203-216`（`skipDNSResolve := ctx.GetSkipDNSResolve()` 门控解析）。另有自解析显式兜底 `nameserver_doh.go:137-145`（"tries to resolve itself! Use IP or set hosts instead"）。

**快速验证**：
```json
{"log":{"loglevel":"debug"},
 "dns":{"servers":["https://cloudflare-dns.com/dns-query"]},
 "routing":{"domainStrategy":"IPIfNonMatch","rules":[{"type":"field","domain":["geosite:cn"],"outboundTag":"direct"}]},
 ...}
```
查询任一非 cn 域名：`RUST_LOG=debug` 下观察 `router dns resolve` 与 dispatch 日志互相触发、任务数暴涨/查询挂起；同配置 Go 内核一次查询即回。规避法（现行可用）：NS 用 IP 字面量、或给 NS 域名配 `hosts`、或 domainStrategy=AsIs。

---

## P1

### P1-1 ｜ routeOnly 桥接清空 target_ips → IP/geoip 目标规则在 routeOnly 下永不命中（Go 保留原 Target IP）

**现象**：`sniffing.routeOnly=true` 时路由只用嗅探域名；此时目标规则里的 IP 类条件（`ip:[...]`、`geoip:xx`、`source` 无涉）在 Rust 上**必然不命中**——原目标 IP 被丢弃。Go 上原 `Outbound.Target` 不动，IP 条件照常按原目标 IP 匹配。用户可见影响：routeOnly + geoip:cn direct 类分流在 Rust 全部落到后续规则/默认出站，Go 正常。

**根因**（Rust）`xray-core/src/wiring.rs:100-111 bridge_context`：
```rust
if let Some(rt) = ctx.get_route_target() {
    match rt.address().ip() {
        Some(ip) => { data.target_ips = vec![ip]; data.target_domain.clear(); },
        None => {
            data.target_domain = rt.address().as_domain().unwrap_or("").to_string();
            data.target_ips.clear();          // ← routeOnly（域名 route_target）时原目标 IP 被清空
        },
    }
    data.target_port = rt.port();
}
```

**Go 对照**：`common/session` 的 Outbound 有三个地址位，`app/dispatcher/default.go:311-315` routeOnly 只写 RouteTarget、不动 Target：
```go
if sniffingRequest.RouteOnly && protocol != "fakedns" && ... && !isFakeIP {
    ob.RouteTarget = destination
} else {
    ob.Target = destination
}
```
而 IP 条件消费的 `GetTargetIPs` **只看 Target**（`features/routing/session/context.go:47-57`）：
```go
func (ctx *Context) GetTargetIPs() []net.IP {
    if ctx.Outbound == nil || !ctx.Outbound.Target.IsValid() { return nil }
    if ctx.Outbound.Target.Address.Family().IsIP() {
        return []net.IP{ctx.Outbound.Target.Address.IP()}
    }
    return nil
}
```
（域名条件用的 `GetTargetDomain` 才优先 RouteTarget，context.go:81-94——Rust 对齐了域名侧、漏了 IP 侧。）

**快速验证**：inbound sniffing `{enabled:true, destOverride:["tls"], routeOnly:true}`；规则 `[{"type":"field","ip":["1.2.3.0/24"],"outboundTag":"direct"}]`，默认出站 proxy。访问 SNI=example.com 的 1.2.3.4:443：Go 命中 direct，Rust 落 proxy。仓库既有测试 `wiring.rs:1882-1901 pick_route_prefers_route_target_over_target` 把这一偏差固化成了断言，修时需连同测试改语义。

### P1-2 ｜ 系统拨号域名目标只取 lookup_host 首个地址，无多地址回退

**现象**：域名解析返回多地址（常见 AAAA 在前）且首选地址不可达（无 IPv6 路由/对端 v6 故障）时，拨号直接失败；Go 会按序尝试全部地址（含 RFC 6555 回退）。用户可见影响：双栈环境偶发「节点连不上」，换 Go 内核即好——且默认配置（无 sockopt.domainStrategy）就中招。

**根因**（Rust）`xray-transport/src/system_dialer.rs:169-186`（DefaultSystemDialer）：
```rust
let mut socket_addrs = tokio::net::lookup_host((host, port)).await?;
socket_addrs.next().ok_or_else(|| {
    io::Error::new(io::ErrorKind::NotFound, format!("DNS resolve failed: {host}"))
})?           // ← 只取第一个解析地址，其余全弃
```
同构问题在 `DnsResolvingDialer`（system_dialer.rs:1335 附近）：
```rust
match tokio::net::lookup_host(&lookup).await {
    Ok(mut addrs) => {
        if let Some(resolved) = addrs.next() {   // ← 同样只取第一个
```
`init_system_dialer`（system_dialer.rs 尾部）生产环境把 effective dialer 换成 DnsResolvingDialer，两条路都是单地址。

**Go 对照**：`transport/internet/system_dialer.go` DefaultSystemDialer 走 stdlib `net.Dialer.DialContext(ctx, network, "host:port")`——stdlib dialer 内建多地址顺序尝试 + Happy Eyeballs。

**快速验证**：hosts 文件（或 DNS）使某域名返回 `[2001:db8::1, 127.0.0.1]`，禁用本机 IPv6 路由，`xray run` 走 freedom 访问该域名 80 端口：Rust connect 超时/失败，Go 成功。

### P1-3 ｜ geodata 资产目录三套并存且未接 platform 多路径探测（Linux 标准安装路径启动失败；DNS 侧 cwd 回退）

**现象**：
- (a) **router**：路由 geosite:/geoip: 规则加载只用「`XRAY_LOCATION_ASSET` → exe 目录」，不探测 Linux 发行版标准路径。geoip.dat 在 `/usr/share/xray`、二进制在别处且未设 env 时，Router init 直接报错（fail-closed）**启动失败**；Go 同环境正常。
- (b) **DNS**：DNS 模块自带的资产目录回退是 **`.`（当前工作目录）** 而非 exe 目录——非 cwd 启动（systemd/scheduled task/双击 exe）+ DNS `geosite:` 规则 → DNS feature 启动失败。
- (c) 三套实现语义不一致（router=exe dir、DNS=cwd、platform 自带=exe dir+3 个共享路径），维护性地雷。

**根因**（Rust）：
- router 侧 `xray-core/src/wiring.rs:1359-1362`：
```rust
/// 找不到 .dat 文件不影响 loader 创建（load 时 warn skip），仅影响 geoip/geosite 规则匹配。
fn resolve_asset_dir() -> std::path::PathBuf {
    xray_common::platform::get_resource_path()   // env → exe 目录，无共享路径探测
}
```
- DNS 侧 `xray-app-dns/src/jsonconf.rs:498-503`：
```rust
/// 资源目录（geosite.dat / geoip.dat 查找路径）。对应 Go `XRAY_LOCATION_ASSET`。
fn resolve_asset_dir() -> std::path::PathBuf {
    std::env::var("XRAY_LOCATION_ASSET")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("."))   // ← cwd，与 router 侧不同
}
```
- 带探测的 `get_asset_location`（`xray-common/src/platform/mod.rs:80-95`，含 `/usr/local/share/xray`、`/usr/share/xray`、`/opt/share/xray`）存在，但 geodata 加载链（GeoDataLoader::new(datadir).join(file)）不经过它；`open_asset` 仅 filesystem 自测使用。
- 失败路径 fail-closed 确认：router `xray-app-router/src/rule.rs:407-414`（load_geoip err → RouterError → init 失败）、DNS `xray-app-dns/src/jsonconf.rs:226-233`（parse_ns_domain_rule err → DnsError → build 失败）。

**Go 对照**：`common/platform/others.go:15-32`：
```go
for _, p := range []string{
    defPath,
    filepath.Join("/usr/local/share/xray/", file),
    filepath.Join("/usr/share/xray/", file),
    filepath.Join("/opt/share/xray/", file),
} {
    if _, err := os.Stat(p); os.IsNotExist(err) { continue }
    return p
}
```
`checkFile`（common/geodata）与 DNS 侧 geosite 解析共用该函数。

**快速验证**（Linux）：`unset XRAY_LOCATION_ASSET`，二进制放 `/opt/xray/xray`，geoip.dat 放 `/usr/share/xray/`：Go 启动正常；Rust 报 `load geoip geoip.dat:CN` 类错误退出。DNS：cd 到空目录启动（配置含 `{"dns":{"servers":[{"address":"1.1.1.1","domains":["geosite:cn"]}]}}`）→ Rust DNS feature 启动失败，Go 正常。

---

## P2

### P2-1 ｜ IpOnDemand eager 全量解析：无 IP 规则的配置也每连接查 DNS（Go 懒解析）

`xray-app-router/src/router.rs:177-185`：IpOnDemand 在进入规则循环前无条件 `resolve_into`（有域名就解析）。Go `app/router/router.go:208-216` 只把 DNS client 注入 ctx（`routing_dns.ContextWithDNSClient`），由 IP 条件触达 `GetTargetIPs` 时才按需解析——纯域名规则（geosite:cn 分流）配置下 Go 零 DNS 查询，Rust 每条连接多一次解析延迟/上游负载。结果等价（解析结果只影响 IP 条件），但行为面（DNS 流量、延迟、NS 可见性）不同。
**验证**：`domainStrategy:"IPOnDemand"` + 仅域名规则 + 计数上游查询（tcpdump/NS 日志）：Rust 每连接一次，Go 零。

### P2-2 ｜ balancer 拾取失败按「未命中」继续扫后续规则（Go 整体报错落默认出站）

`xray-app-router/src/rule.rs:75-78`：
```rust
let tag = match self.get_tag_with_ctx(ctx) {
    Ok(t) => t,
    Err(_) => return None,     // ← 条件已命中，balancer 挂 → 当作不命中滑向下一条规则
};
```
Go `app/router/router.go:69-77`：`pickRouteInternal` 命中后 `tag, err := rule.GetTag()`，err 直接使 PickRoute 失败 → dispatcher（Go default.go:443+）落默认出站。偏差后果：balancer 全挂/无候选时 Rust 可能被**后面的规则**改写出站（语义漂移），Go 稳定走默认。
**验证**：balancer 引用两个不存在的 outboundSelector 候选 + 后置规则 ip 直连：观测出站 tag。

### P2-3 ｜ sendThrough `"origin"`/`"srcip"` 静默不绑定源地址

`xray-transport/src/system_dialer.rs:217-234`：`SendThroughSpec::Origin | SrcIp => None`（代码内 ponytail 注记自认「DialFn 链无 inbound 会话上下文，resolve 恒 None」）；`xray-core/src/outbound.rs:355-358` 仅 `Some(ip)` 才 `DIAL_SRC.scope`。Go `app/proxyman/outbound/handler.go:337-342` 在 inbound 有效时把 inbound.Local.Address 设为 Gateway 并绑定。固定 IP/CIDR 形态已对齐（`dial_system` DIAL_SRC 绑定有 e2e：system_dialer.rs `dial_system_binds_dial_src_as_source_ip`）。
**影响**：这两字面量静默降级为系统默认源 IP，无任何告警。
**验证**：多出口机器配置 `sendThrough:"origin"`，对比 Rust/Go 出口源地址。

### P2-4 ｜ freedom-UDP `GetDynamicStrategy` 动态策略未实现 [INFERENCE]

`xray-core/src/outbound.rs:1656-1659` 注记自认未实现；Go `transport/internet/dialer.go:253-255` 对 freedom+UDP+无源地址场景按原始目标地址族动态收缩策略。影响面：UDP 域名帧在 UseIPv4v6 类策略下可能选错族解析失败/丢帧。freedom UDP relay 主体（crates/xray-proxy-freedom/src/udp.rs）已带 per-帧解析与缓存，真机影响待量化。

### P2-5 ｜ DoH「自解析」显式守卫缺失

Go `app/dns/nameserver_doh.go:137-145`：查询域名 == NS 自身域名时立即报 "tries to resolve itself! Use IP or set hosts instead"。Rust doh.rs 无对应判断（grep 无 "resolve itself"）——该场景直接滑入 P0-1 的递归，而不是一条可诊断的错误。建议随 P0-1 一并补。

### P2-6 ｜ 路由 JSON `script` 字段静默丢弃（Go 为完整 Lua 路由脚本能力）

Go `infra/conf/router.go:75/97-99` 解析 `script`、与 rules/domainStrategy 互斥校验，`app/router/router.go:63-66` `script.pickRoute` 优先执行；`app/router/lua.go` 为完整实现。Rust `xray-core/src/wiring.rs` 与 `xray-core/src/router.rs` 全文无 `script` 处理——配了 script 的配置静默退化为普通规则路由，无告警。属「配置面静默降级」，至少应启动期报错拒绝。

### P2-7 ｜ DefaultSystemDialer 无 UDP 拨号；UDP 目标走 dial_system 会建 TCP 流 [INFERENCE]

`xray-transport/src/system_dialer.rs:22-24`（模块头自认「UDP 拨号留待办」）+ `dial_tcp_raw` 恒 TCP。freedom UDP 已走独立 relay（`xray-proxy-freedom/src/dispatcher.rs:306-309` → udp.rs `UdpSocket` 绑定，含 sendThrough 绑源 e2e），不受影响；风险点在 dokodemo outbound（`xray-proxy-dokodemo/src/outbound.rs:100-102` 无差别 dial_system）遇 UDP 目标时的路径——未实测，标注待验证。Go `system_dialer.go:59-84` UDP ListenPacket 全覆盖。

---

## 信息项（有意/可接受偏离，不计缺陷）

- **quic:// 远端 scheme**：Rust=DoQ 独立实现；Go `app/dns/nameserver.go:54-71` switch 只收 `quic+local`，裸 `quic://` 落 classic UDP（Go 自身怪癖）。Rust 属超集行为。
- **tls://（DoT）**：Rust 有完整 DoT（dot.rs）；Go app/dns 无此 scheme case。超集。
- domainStrategy 枚举编号已核对 Go `app/router/config.proto:98-108`（AsIs=0、**1=reserved**、IpIfNonMatch=2、IpOnDemand=3），Rust `config.rs` 1→AsIs 的「无效回退」与 Go reserved 语义一致，非缺陷。
- 域名匹配大小写链完整对齐：输入侧 to_lowercase（condition.rs:147）＝ Go condition 域名匹配；模式侧 Full/Domain/Substr 小写、**Regex 原样**（geodata/matcher/domain.rs parse_domain ＝ Go common/geodata/domain_matcher.go parseDomain:246-262）。
- geoip 反向匹配折叠 `reverse ^ dat.reverse`（rule.rs:435）＝ Go rule_parser.go:63 `reverse != codeReverse`；pos/neg 分组合并 + 德摩根修正（geodata/matcher/ip.rs build_optimized_ip_matcher，bd 5fc7）与 Go HeuristicIPMatcher XOR 语义一致（ip_matcher.go matchAddr）。
- geosite/geoip code 统一大写（rule.rs:391/425）＝ Go rule_parser.go:60/119 ToUpper；geosite 不支持 code 级 reverse，两边一致。
- dialerProxy 缺 tag 报错（outbound.rs:251-256）＝ Go dialer.go:271-272；sendThrough+dialerProxy 互斥、SRV/TXT addressPortStrategy、happyEyeballs 触发条件（TCP+无 dialerProxy+配置存在+tryDelay/maxConcurrent>0+ips≥2）均逐条对齐 Go dialer.go:246-279。
- DnsService 查询面（hosts 优先/#rcode 上抛、FakeDNS 按 fake_enable 跳过、UseSys 路由可达钳制、服务级×客户端级 queryStrategy AND、尾点只剥一个、singleflight/serveStale）与 Go dns.go/nameserver_cached.go/hosts.go 对齐，测试覆盖充分（server.rs 1500+ 行测试）。

---

## 特殊核查答案（契约点名两项）

1. **目标为 IP 字面量时 ip/geoip 规则是否必然命中**：**是，两边一致**。Rust `default.rs:770-773 build_routing_context` IP dest → `ctx.target_ips=[ip]`；Go `features/routing/session/context.go:47-57` Target 为 IP → GetTargetIPs=[ip]。IP 条件 `IPMatcherCondition::apply`（condition.rs:168-171）any-match 命中。
2. **sniffing destOverride 改写域名后 IP 规则是否静默失效（Go 是否同样）**：分两形态——
   - 非 routeOnly（改写 Target）：**两边同样失效**（Go default.go:313-315 改 Target → GetTargetIPs=nil；Rust final_dest 变域名 → target_ips 空）。失效后需 domainStrategy=IpOnDemand/IpIfNonMatch 解析域名才能命中 IP 规则，两边一致。
   - routeOnly（只设 RouteTarget）：**Go 不失效**（Target 保留原 IP，GetTargetIPs 仍返回原 IP）；**Rust 静默失效**（bridge_context 清空 target_ips）→ P1-1。

## 未覆盖范围

- balancing 策略内部细节（LeastLoad expected/baselines 语义、strategy_settings TypedMessage 当前不解析——router.rs:373-378 注记回退默认值，未逐字段对照 Go StrategyLeastLoadConfig）。
- fakedns 池算法细节（IP 分配/续约）、DoH/DoQ TLS 指纹与 uTLS 选路、cache_controller 逐字段（已抽查主干对齐）。
- rule_set.rs / webhook 触发语义 / observatory 与 balancer 的联动。
- macOS/FreeBSD 进程匹配（condition.rs 已对齐 Go「仅 linux/windows」，平台相关代码未逐一审）。
