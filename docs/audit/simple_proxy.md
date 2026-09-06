# 第四轮审计：简单代理协议栈（freedom / blackhole / loopback / dokodemo / socks / http outbound）

- 审计对象: Xray-core-rust（本轮 HEAD）
- 对照基准: D:/Project/Xray-core（Go Xray-core v26.7.28）逐文件对照
- 范围: freedom、blackhole、loopback、dokodemo、socks（http inbound 认证已审，跳过）、http outbound；每协议 ≥3 抽查点
- 日期: 2026-09-06
- 申报: 只读审计 + 本报告；freedom domainStrategy（已知）、dokodemo followRedirect 非 Linux 降级（已知）不重复申报

## 严重度统计

| 级别 | 数量 |
|---|---|
| P0 | 0 |
| P1 | 5 |
| P2 | 6 |
| P3 | 3 |

**TOP3**
1. **[P1] dokodemo UDP 单 session + last_peer：多客户端响应错发**（inbound.rs:692-720）——DNS/QUIC 转发高并发场景必然数据错乱。
2. **[P1] freedom 默认私网阻断 + UDP per-packet 规则过滤缺失**（udp.rs / dispatcher.rs / handler.rs:129）——远端代理客户端可经 freedom 直访服务器 127.0.0.1/RFC1918，Go 默认阻断。
3. **[P1] socks UDP ASSOC relay 硬编码 bind 127.0.0.1**（server.rs:243-247）——非本机客户端的 UDP 中继整体不可用。

---

## 一、Freedom

### F-1 [P1] destinationOverride 配置解析但生产路径不消费（并纠正第一轮 completeness.md 误判）
- 位置: `crates/xray-proxy-freedom/src/dispatcher.rs:38-53`、`crates/xray-core/src/outbound.rs:510-513`（生产装配）、`crates/xray-proxy-freedom/src/config.rs:246`
- 证据: 生产 freedom 出站 = `FreedomDispatchBridge` + `make_freedom_dial_fn_with_config(config)`（= `make_dial_fn_with_config`，lib.rs:28 别名）。该闭包**只取 `config.fragment`**：
  ```rust
  // dispatcher.rs:38-39
  pub fn make_dial_fn_with_config(config: Config) -> DialFn {
      let fragment = config.fragment;          // destination_override 无任何消费
  ```
  `FreedomHandler::process`（handler.rs:272-380）同样无 `destination_override` 引用；`config.rs:246/259-262` 仅解析与回写序列化。UDP 路径 `udp.rs` 全文无 override。注释自认："domainStrategy 解析已存入 Config，DNS 策略拨号路径未消费"（同类静默）。第一轮 completeness.md 协议表称 freedom "destOverride 完整（freedom/src/{fragment,udp,handler}.rs）"——**该结论有误**，字段存在不等于生产消费。
- Go 基准: `proxy/freedom/freedom.go:287-300`——TCP `destination.Address/Port` 被 override 改写后再拨号；UDP 逐包 `UDPOverride` 改写（freedom.go:638-643）；且 `NoisePacketWriter` 依赖 `UDPOverride.Port == 53` 跳过噪声（freedom.go:676-680）。
- 影响: 透明代理/TPROXY 典型部署（dokodemo + freedom destOverride 改写流量等）静默失效——Rust 拨到**原始目标**而非 override 目标，无任何告警；noises 的 DNS 保护分支也因此无从实现。
- 修复建议: `make_dial_fn_with_config` 内 dial 前按 `isValidAddress` 语义改写 dest（IP/端口均可空缺省）；UDP `parse_and_send` 对帧目标应用同一 override；override 到 :53 时跳过 noises（对齐 Go）。**负优化自查**: 改写为纯值替换，无锁无缓存，无热路径劣化风险。

### F-2 [P1] 默认私网阻断（defaultBlockPrivateRule）口径断裂 + UDP 路径完全无 FinalRule 过滤（completeness F3 未覆盖的增量）
- 位置: `crates/xray-proxy-freedom/src/handler.rs:129-130`；`crates/xray-proxy-freedom/src/udp.rs:196-263`；`crates/xray-proxy-freedom/src/dispatcher.rs:122-160`
- 证据:
  1. handler 路径默认规则按**入站 tag** 推导：`.or_else(|| session.inbound.tag.as_deref().and_then(get_default_rule_type))`。Go 按 **inbound.Name（协议名）** 匹配（freedom.go:126-146，各 proxy Process 首行 `inbound.Name = "vless"` 等）。Rust 全库生产代码无 `session.inbound.name` 赋值（grep 仅测试命中），tag 是用户自配字符串（如 "inbound-8888"）恒不命中。
  2. 生产路径（FreedomDispatchBridge）根本没有 final_rules 字段；UDP relay `parse_and_send`（udp.rs:196-227）对每帧目标、`pump_response`（udp.rs:232-263）对每包来源，**均不查任何 Block 规则**。
- Go 基准: freedom.go:246-250 `matchFinalRule(...) action==Block → blackhole`；freedom.go:527-529 PacketReader 对**每个入包来源** applyFinalRules==Block 则 continue；freedom.go:624-626 PacketWriter 对**每个出包目标** Block 则丢弃。
- 影响: Go 在 vless/vmess/trojan/hysteria/wireguard/shadowsocks* 入站默认阻断对服务器私网/回环的 TCP+UDP 直访（反 SSRF/内网跳板），Rust 生产路径 TCP+UDP 全放行。远程客户端可让服务器对 127.0.0.1、10.0.0.0/8、169.254.169.254 等发起 UDP（以及 TCP）访问。
- 修复建议: ① FreedomDispatchBridge 增加 final_rules（Config.final_rules 构建）+ 默认规则（按**协议名**），TCP dial 前与 UDP per-packet 双侧执行 Block 丢弃；② inbound 侧补 `session.inbound.name = 协议名`（对齐 Go 各 proxy Process 首行），否则 handler 路径 tag 口径一并修正。**负优化自查**: per-packet 匹配用 config 构建期预编译的 IP matcher（xray_geodata 已有），无锁热路径；UDP 只丢包不断链（Go 同款），避免把整条会话打死。

### F-3 [P2] proxyProtocol 配置生产不消费
- 位置: `crates/xray-proxy-freedom/src/dispatcher.rs:38-53`（dial_fn 不写 PROXY header）；`crates/xray-proxy-freedom/src/handler.rs:293-322`（仅非生产接线的 `ProxyOutbound::process` 实现）
- Go 基准: freedom.go:352-362——`ProxyProtocol>0` 时拨号后立即 `HeaderProxyFromAddrs(...).WriteTo(conn)`。
- 影响: 配置 `proxyProtocol` 的部署对端收不到 PROXY 头（源地址信息丢失/对端校验失败），静默。
- 修复建议: 短期 fail-fast——配置解析层对 `proxy_protocol>0` 报错（优于静默）；长期 dial_fn 补 header 写入（需把 session source 传入 dial 上下文）。**负优化自查**: 不为传 src 扩所有协议 DialFn 签名，优先走 session/AccessContext 通道。

### F-4 确认干净
1. **Fragment 语义**（fragment.rs:60-160 vs freedom.go:736-815）: tlshello 判定（`count==1 && len>5 && b[0]==22`、`record_len=5+(b[3]<<8|b[4])`、半截 record 直发）、maxSplit 提前收口、`packets_from/to` 窗口外直发、`interval_max==0` 合并单写、record 后残余直发——逐分支一致。**正优化**: `rand_between(...).max(1)` 修掉 Go `LengthMin==0` 时的死循环（Go `to==from` 永不推进）。已文档化偏差: `interval_min==0` 时 Go 随机 `[0,max)`、Rust 固定 max（测试确定性取舍，不改分片结构）。
2. **blockDelay**: [30,90] 默认 + span 交换逻辑与 Go 一致（handler.rs:139-148 vs freedom.go:222-232）；blackhole drain→timeout→shutdown 与 Go AfterFunc 中断等价。
3. **noises**（udp.rs:216-231 send_noises vs freedom.go:691-724）: applyTo ipv4/ipv6 过滤、用户 packet 或随机长度 `[min,max)`、写后 delay——一致。UDPOverride:53 跳过缺失受 F-1 连带，不另计。
4. **UDP XUDP**: per-frame `udp_target` 路由、响应帧来源=真实 peer、GlobalID 8B 随机（udp.rs:84-86,232-263）与 Go xudp 语义一致；sendThrough 经 DIAL_SRC scope 绑源（bd 7zc）与 Go system_dialer ListenUDP 绑源等价。

---

## 二、Dokodemo

### D-1 [P1] UDP 单 session + last_peer：多客户端响应错发
- 位置: `crates/xray-core/src/inbound.rs:692-720`（serve_dokodemo_udp，注释自认"响应回发给最近一个 peer"）
- 证据: 单 `UdpDispatchSession` + 单循环，`last_peer = Some(peer)` 取**最近一个发包的任意客户端**；出站响应 `(source, payload)` 一律 `udp.send_to(&payload, last_peer)`。
- Go 基准: `app/proxyman/inbound/worker.go:351-356`——UDP 入站按**远端 source** 建独立 session（每 source 独立 conn/timer）；dokodemo.go:160-176 响应 writer 绑定本会话 conn。
- 影响: dokodemo UDP 的典型用途是 DNS/QUIC 透明转发（大量并发客户端）：客户端 A 的 DNS 响应会发给最近发包的 B → 数据错乱 + 目的地信息泄漏。
- 修复建议: per-peer 会话表（`HashMap<SocketAddr, UdpDispatchSession>`，对齐 Go per-source），响应按包来源回发。**负优化自查**: 表项必须带 idle 清理（复用 60s 模式），否则形成缓慢泄漏——清理用循环扫描而非每表项一个 task。

### D-2 [P1] TPROXY UDP 语义缺失：followRedirect UDP 不取 original_dst，fake_udp 为死代码
- 位置: `crates/xray-core/src/inbound.rs:1898-1920`（UDP 注册分支不看 `settings.follow_redirect`）；`crates/xray-proxy-dokodemo/src/fakeudp.rs:18-24`（全库 grep 仅测试调用）；`inbound.rs:692+`（serve_dokodemo_udp 无 fake_udp、无 mark）
- Go 基准: dokodemo.go:158-176——`followRedirect` 且 destinationOverridden 时 UDP writer = `FakeUDP(addr, mark)` + PacketWriter（per-dest conn 表，回包**源地址=原始目标**，TPROXY 核心语义）；未 overridden 时 `SequentialWriter{conn}` 直接回写。
- 影响: Linux TPROXY 部署下 UDP 回包源地址 = dokodemo 监听地址而非客户端原始目标 → 内核 ip rule/tpmark 或按源校验的客户端丢弃响应；且原始目标信息被整体丢弃，所有 UDP 打到预定义 dest。（与"非 Linux 降级"已知项不同：**Linux 上也未实现**。）
- 修复建议: UDP 分支接 `get_original_dst(fd)` + `fake_udp` 回包（Linux 门控）；per-dest FakeUDP 需 conn 表与 Close 回收。**负优化自查**: FakeUDP 每 dest 一个 fd，必须对齐 Go `PacketWriter.Close` 全表关闭，防 fd 泄漏；表查找用 Destination 作 key 的 HashMap（Go conns map 同款）。

### D-3 [P2] settings 强制必填 address+port：Go 合法的 followRedirect 无地址配置启动即拒
- 位置: `crates/xray-core/src/inbound.rs:2314-2319`（`missing address`/`missing port` → InvalidData）
- Go 基准: dokodemo.go:79-109——rewriteAddress/rewritePort 均可空：followRedirect 时由 ob.Target（original dst）回填；非 followRedirect 时由 conn.LocalAddr() 回填（`.`→v4 loopback 否则 v6）。标准 TPROXY 配置形如 `{"port":12345,"network":"tcp,udp","followRedirect":true}`（无 address），Go 合法。
- 影响: 该形态配置在 Rust 直接启动失败（报错清晰非静默，但功能不可用；且 Linux 上同样被拒，不属于已知"非 Linux 降级"）。
- 修复建议: address/port 改可选；followRedirect 时允许缺省（由 original dst 回填），缺 port 时回填 original/本地端口。**负优化自查**: 无。

### D-4 确认干净
1. **TCP followRedirect 优先级**（inbound.rs:575-610 vs dokodemo.go:113-136）: original_dst 覆盖后置 overridden 才跳过 SNI 覆盖——与 Go `destinationOverridden` 门控一致；SNI 取 rustls 握手后 server_name 等价 Go `HandshakeContextServerName`。
2. **port_map**（inbound.rs:593-610 + 2330-2350）: `host:port` 双可空、按监听端口查 map 改写、解析期 SplitHostPort 校验——与 Go dokodemo.go:101-109 及 infra/conf 校验一致。
3. **allowedNetworks 门控**: `tcp,udp` 解析、双 listener 分支、两者皆无报错（inbound.rs:1921-1925）与 Go `Init` "no network specified" 语义等价。
4. 前轮已报: followRedirect 非 Linux 显式 warn 降级（勿重复）。

---

## 三、Socks

### S-1 [P1] UDP ASSOC relay 硬编码 bind 127.0.0.1，config.address 解析后不消费
- 位置: `crates/xray-proxy-socks/src/server.rs:243-247`（`UdpSocket::bind("127.0.0.1:0")`，回复 BND.ADDR=relay_addr 即 127.0.0.1）；`config.rs:88`（`address: Option<IpOrDomain>` 字段无任何消费方，grep 证实）
- Go 基准: protocol.go:198-221——`responseAddress = config.Address`，缺省用 `s.localAddress`（TCP conn LocalAddr IP）；UDP hub **bind 到 responseAddress.IP()**；reply 携带 responseAddress+responsePort。
- 影响: socks 监听非 loopback（LAN/容器网关场景）时，远端客户端拿到的 relay 地址 127.0.0.1 不可达；且 relay socket 只绑 loopback，即使客户端自行改成服务器地址也收不到包——**远程 UDP 中继整体不可用**。
- 修复建议: bind 目标 = `config.address.IP()` 缺省 fallback TCP conn local IP；reply 同地址。**负优化自查**: 纯参数替换，无。

### S-2 [P2] udp_enabled=false 时 UDP ASSOC 无条件放行（开关静默失效）
- 位置: `crates/xray-proxy-socks/src/server.rs:239-271`（CMD_UDP_ASSOCIATE 分支无 `config.udp_enabled` 检查；生产 `inbound.rs:126` 直接消费该函数族）
- Go 基准: protocol.go:172-175——`!s.config.UdpEnabled → writeSocks5Response(statusCmdNotSupport) + 拒绝`。
- 影响: `"udp": false` 的服务器仍提供 UDP 中继；Go 用户用该开关收窄 UDP 面，Rust 静默忽略（默认 false 时行为差异尤其危险：Go 拒绝、Rust 放行）。
- 修复建议: 分支首行检查 `config.udp_enabled`，false 回 `[5,0x07,...]` 并断开。**负优化自查**: 无。

### S-3 [P2] UDP relay 无来源过滤（expectedRemote 缺失）
- 位置: `crates/xray-core/src/inbound.rs:246-253`（recv_from 后直接 `last_client = Some(client)`，不校验与关联 TCP peer 一致）
- Go 基准: temp_udp_listen.go:23-40——`TempUDPConn.Read` 循环丢弃来源不等 expectedRemote 的数据报（IP 相等且 Port 相等；Port==0 时首包学习）。
- 影响: 知道 relay 端口的第三方主机可向会话注入数据报或抢收响应。当前被 S-1 的 127.0.0.1 bind 间接缓解；**S-1 修复后该暴露面随即打开，两项必须同步修**。
- 修复建议: 首包学习来源，后续严格 IP:Port 匹配，不匹配静默丢弃。**负优化自查**: 单会话内两字段比较，零分配零锁。

### S-4 确认干净（及低危观察）
1. 回复码完整性: 未知 CMD → `[5,0x07,0,1,0,0,0,0,0,0]` 与 Go `statusCmdNotSupport` 一致（server.rs:222-225 vs protocol.go:177-182）；auth 失败写 `[0x01,0x01]` 后报错与 Go 写 0xFF 后报错同构（protocol.go:129-137）；SOCKS4 非 CONNECT 回 CD=91——auth 必需时拒 SOCKS4 属已报 P0 范围不重复。
2. 4a 探测（`0.0.0.x, x!=0` → null 结尾域名）、USERID 读至 NULL、CONNECT 成功即回——与 Go handshake4 一致（bugs.md 表 #5 复核通过）。
3. 生命周期: TCP 控制连接 EOF → `relay.abort()`（inbound.rs:128-134）等价 Go `io.Copy(Discard, conn)` 后 `tempUDPConn.Close()`。
4. [P3] 组: relay 无 idle timeout（Go `SetTimeout(ConnectionIdle)` 空闲连 UDP+TCP 一起关，temp_udp_listen.go:42-52）；CONNECT 成功回复 BND=0.0.0.0:0（Go 回 server 地址端口；客户端均忽略，兼容无损）；Tor RESOLVE/PTR（0xF0/0xF1）未实现（Go protocol.go:24-25）。

---

## 四、Blackhole

### B-1 [P3] HTTP 403 伪装响应字节与 Go 不一致 + TCP drain 无界
- 位置: `crates/xray-proxy-blackhole/src/response.rs:14-22`（`
` 行尾 + 结尾两空行，注释称"与 Go 字面量一一对应"——**不实**）；`dispatcher.rs:91-141`（TCP `drain_timeout = Duration::MAX`）
- Go 基准: config.go:9-16——`http403response` 为**纯 LF** 行尾的 backtick 字面量；blackhole.go:33-47——响应写后 sleep 1s 即 `Interrupt` 双端（**TCP 不 drain**），仅 UDP 目标 drain `30+dice.Roll(61)` 秒。
- 影响: 伪装指纹与 Go 基准字节级不同（与该响应"抗探测伪装"的设计目的相悖）；TCP 会话被无限 drain（客户端可长期占住连接，仅靠 inbound 侧 idle 兜底）。
- 修复建议: 字面量逐字节对齐 Go（LF + 两空行）；TCP 分支响应后约 1s 返回，仅保留 UDP drain。**负优化自查**: 无。
- 确认干净: None/HTTPResponse 类型解析（裸类型名 + `type.googleapis.com/` 前缀双兼容，response.rs:37-64）与 Go GetInternalResponse 等价；UDP drain 固定 60s 是已注释化的确定性替代（Go 30-90 随机），可接受偏差。

---

## 五、Loopback

### L-1 [P2] 接线后语义缺口：inbound_tag 被丢弃、SkipDNSResolve 缺失（sink 未注入 stub 本体已由 completeness.md [P2] 报过，不重复）
- 位置: `crates/xray-core/src/outbound.rs:81-95`（DispatcherLoopbackSink::dispatch_loopback 收 `inbound_tag` 参数但**不使用**——`dispatch_link(&destination, link, &sniffing, None, None)` forced_tag=None，也无 inbound-tag 会话语义；无 SkipDNSResolve 通道）
- Go 基准: loopback.go:31-44——`content.SkipDNSResolve = true`；inbound 浅拷贝后 `inbound.Tag = l.inboundTag` 再 DispatchLink（router 的 `inboundTag` 规则以该 tag 匹配）。
- 影响: 即便按前轮建议接好 sink 与 sniffing，loopback 仍不等于 Go：路由规则 `inboundTag` 永不命中；重分发链路会再做 DNS 预解析（Go 明确跳过）。
- 修复建议: dispatcher 增加 loopback 专用入口（或 dispatch_link 增加 `inbound_tag_override + skip_dns_resolve` 参数）。**负优化自查**: 不改既有 dispatch_link 热路径签名，新增方法隔离。
- 确认干净: `parse_loopback_config` 对 inboundTag/sniffing（enabled/destOverride/routeOnly）解析正确（outbound.rs:2226-2240 测试即证）——断点纯在装配层（已报项 + 本条）。

---

## 六、HTTP outbound（socks outbound UDP 同族问题并入本条）

### H-1 [P2] http/socks outbound 对 UDP 目标无早退：XUDP 帧流被灌入 TCP CONNECT 隧道，静默数据损坏
- 位置: `crates/xray-proxy-http/src/client.rs:96-130`（make_http_dial_fn 不看 `dest.network()`）；`crates/xray-proxy-socks/src/client.rs:130-149`（硬编码 CMD_TCP_CONNECT）+ `dispatcher.rs` make_dial_fn（无 UDP 分支）；DialBridge（xray-app-dispatcher/default.rs:1228-1259）对 UDP dest 照常调 dial_fn
- Go 基准: http/client.go:80-82——`target.Network == net.Network_UDP → errors.New("UDP is not supported by HTTP outbound")`（显式早退）；socks/client.go:93-94,146-163——socks outbound **支持** UDP（RequestCommandUDP + UDPReader/UDPWriter associate 流）。
- 影响: 路由把 UDP 目标分到 http/socks 出站时：Rust 对上游发起 CONNECT TCP 隧道并把 XUDP 帧当字节流灌入 → 上游按 TCP 语义连到"目标:端口"，对端收到帧头垃圾；Go 侧 http 干净报错、socks 功能可用。属"早退/错误分类"缺口的最重形态。
- 修复建议: 最小对齐——两者 dial_fn 首行 `Network::UDP` 返回 Err（http 完全对齐 Go；socks UDP 实装可另行排期）。**负优化自查**: 拒绝路径零分配直接 Err。

### H-2 [P3] CONNECT 状态码宽松匹配 + headers 配置丢弃 + h2 未实现
- 位置: `crates/xray-proxy-http/src/client.rs:176-179`（`first_line.contains("200")`）；`parse_http_config:75-97`（settings.headers 不解析）
- Go 基准: client.go:249 `resp.StatusCode != http.StatusOK` 精确比较；client.go:135-166 fillRequestHeader 模板（Source/Target 变量替换）+ client.go:231 `Proxy-Connection: Keep-Alive` + client.go:222 TryDefaultHeadersWith("nav")；client.go:287-313 ALPN h2 → connectHTTP2 + cachedH2Conns 连接缓存。
- 影响: 首行恰含 "200" 的非 200 响应误建隧道（罕见）；伪装 header 配置静默无效；对端强制 h2 时失败。均为低危，但 header 丢弃与 freedom destOverride 同属"配置静默无效"族。
- 修复建议: 状态码取状态行 token 精确比较；headers 解析注入（模板替换可后置）；h2 不支持时对协商出 h2 的连接显式报错。**负优化自查**: 状态码解析复用既有 `
` 扫描边界，零分配。
- 确认干净: ① 200 OK 后残余字节丢弃与 Go 等价（Go `http.ReadResponse` 的 bufio 残余同样不随 rawConn 返回；CONNECT 语义下 200 OK 必先于任何隧道数据到达，无实际丢失面）；② Base64 实现正确（含 padding，RFC 4648）；③ 非 200/写失败/EOF 早退分类与 Go 一致；④ 首包直发缺失仅损失一个写入时机（Go firstPayload），非正确性问题。

---

## 与前三轮报告的关系（防重复申报说明）
- freedom finalRules **生产未消费本体**已由 completeness.md F3 报过 → 本轮 F-2 仅申报增量：默认私网阻断口径（tag vs 协议名）+ UDP per-packet 过滤缺失。
- loopback **sink stub 本体**已由 completeness.md [P2] 报过 → 本轮 L-1 仅申报接线后仍存的 inbound_tag/SkipDNSResolve 缺口。
- socks 认证绕过（select_method NoAuth 回退 + SOCKS4 零校验）已由 security.md P0 报过，不重复；本轮 S-1/S-2/S-3 为 UDP ASSOC 生命周期增量。
- freedom domainStrategy（已知）、followRedirect 非 Linux 降级（已知）未申报。
