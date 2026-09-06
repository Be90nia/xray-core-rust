# Xray-core-rust 深度审计汇总 (AUDIT_SUMMARY)

> 审计日期: 2026-09-05 | 基线: v54 后 HEAD ee7c6c7 | 方法: 6 维度并行只读审计,不改任何代码
> 基准对照: Go Xray-core v26.7.28 (D:/Project/Xray-core) | 报告均含 file:line 证据

## 统计总览

| 维度 | 报告 | P0 | P1 | P2 |
|---|---|---|---|---|
| 性能优化 | [performance.md](performance.md) | 0 | 5 | 7 |
| 内存+泄漏 | [memory.md](memory.md) | 0 | 4 | 6 |
| 高并发 | [concurrency.md](concurrency.md) | 0 | 3 | 4 |
| 功能完善度(对照 Go) | [completeness.md](completeness.md) | 0 | 6 | 15 |
| 功能 bug+静默失败 | [bugs.md](bugs.md) | 1 | 1 | 2 |
| 安全 | [security.md](security.md) | 2 | 3 | 9 |
| **合计** | | **3** | **22** | **43** |

## P0(必须立即修)

| # | 维度 | 发现 | 位置 | 一句话 |
|---|---|---|---|---|
| S1 | 安全 | SOCKS Password 认证完全绕过 | xray-proxy-socks/server.rs:366-377,296-331 | 方法协商 NoAuth 回退 + SOCKS4 零校验双路径,Go 基准均严格拒绝 |
| S2 | 安全 | HTTP 握手无界+无超时 | xray-proxy-http/server.rs:306-328; xray-core/inbound.rs:1866 | 无行长度/行数上限,无 policy 时握手无超时 → 未认证单连接 OOM/slowloris |
| B1 | bug | TUIC H3 帧长无上限 | xray-proxy-tuic/h3.rs:182-190 | 未认证对端 9 字节帧头即触发 `vec![0u8; len]` TB 级分配 → 进程 abort |

## P1 按主题分组(22 条,详见各报告)

**内存泄漏(4)**: reverse BridgeWorker↔ServerWorker 强引用环(worker.rs:355) / DNS 缓存清理任务零调用方(ips 无上限) / ss2022 UDP server_sessions 只插不删(inbound.rs:1102) / reverse monitor 无视 close()(重启双循环)

**并发(3)**: mux XUDP clone 语义破坏状态流转→同 GlobalID New 帧静默丢弃+条目泄漏(worker.rs:276) / VLESS ENC 共享锁跨无超时握手→服务端黑洞时 outbound 永久挂死(dispatcher.rs:178) / burst healthping 锁内同步探测 200s 量级占死 worker(burst_observer.rs:220)

**安全加固(3)**: REALITY hooks 错误路径泄漏+地址复用串号(btls_reality.rs:234) / 无 policy 时 socks/http/mixed 握手零超时(slowloris) / SS-2022 UDP 会话 HashMap 永不清理(与内存组交叉确认)

**性能(5)**: 裸 TCP 腿无 writev 批量(每 64KB 多 7 次 syscall,writer.rs:36) / 加密数据面每 record 2-4 次堆分配(Go 为池化 in-place) / finalmask 每包 spawn+假唤醒(mod.rs:447) / buf 池无上限不收缩(alloc.rs:153) / CommonConn 每 record 双分配+memmove

**功能完善度(6)**: 生产路由装配 NotImplementedSelector→balancer 全失效(wiring.rs:376) / httpupgrade 入站 TLS acceptor 构建后丢弃(register.rs:89) / FakeDNS 引擎从未注入(register.rs:684) 等三处"定义了但没接线"

**bug(1)**: Trojan 客户端 UDP 帧解析错误被吞→rbuf 无界增长 OOM 且零日志(dispatcher.rs:223,入站侧有正确处理可对齐)

## P2 摘要(43 条,详各报告)

nonce 换 key 不对称 / SlidingWindow 淘汰后重放窗口 / from_utf8_unchecked UB-by-contract / legacy SS seen_ivs 无界 / policy level-1 覆盖用户配置 / plain HTTP 静默吞错 / observatory 内联阻塞探测 / mux 空池并发穿透 / tuic 池无 single-flight / buf 双分配池化机会 等

## 审计可信度说明

- 全部发现带 file:line 代码证据;TOP 发现经二次 grep/read 复核
- 防误报: 近期已根治项清单(poll_write 裸 Pending/dirty 状态机/ss2022 sing wire/私钥嗅探/UDP 路由/xor_mode 等)已下发各代理,未出现重复报告
- 负优化预审: 与历史 revert(splice×2/xor 重写)逐一核对无冲突
- unsafe 全仓 37+ 文件逐一评估: 仅 2 处需关注(btls hooks + from_utf8_unchecked),其余必要且正确
- 9 个高风险编解码点(vmess/mux/KCP/socks5/trojan UDP/hysteria varint/DNS)对照 Go 确认无缺陷
- 限制: 静态审计+逻辑推导,未跑 benchmark/模糊测试;P0/P1 修复后建议以现有 e2e 矩阵回归

## 建议修复顺序

1. **P0×3**(安全+远程 abort): SOCKS 认证绕过 / HTTP 握手界限 / TUIC 帧限幅 —— 都是未认证可达,优先级最高
2. **P1 泄漏+挂死组**: ENC 锁跨握手 / XUDP clone 语义 / 三个会话表泄漏 / reverse 引用环
3. **P1 功能组**: balancer NotImplementedSelector / httpupgrade TLS 丢弃 / FakeDNS 未接线(用户可感知的功能缺失)
4. **P1 性能组**: writev / 分配池化(收益最大路径: 加密数据面)
5. P2 按需清偿

---

# 第二轮补漏审计 (2026-09-05,5 切面)

第一轮没覆盖的切面:全平台对称 / 配置→装配 diff / 超时矩阵 / 传输层字节级 / 可观测性。

## 第二轮统计

| 切面 | 报告 | P1 | P2 | P3 |
|---|---|---|---|---|
| 全平台对称 | [platform.md](platform.md) | 0 | 3 | 5 |
| 配置→装配 diff | [config_wiring.md](config_wiring.md) | 4 | 10 | - |
| 超时/资源限制矩阵 | [timeouts.md](timeouts.md) | 3 | 7 | - |
| 传输层深度 | [transport_deep.md](transport_deep.md) | 3 | 16 | 9 |
| 可观测性/统计 | [observability.md](observability.md) | 3 | 3 | 1 |
| **小计** | | **13** | **39** | **15** |

## 两轮合计: P0×3 / P1×35 / P2×82 / P3×16

## 第二轮 P1(13 条)

**配置静默失效组(系统性 camelCase 键名不匹配)**:
- C1 policy 键族静默全丢(connIdle/uplinkOnly/bufferSize/statsUser*/system) app_config.rs:42-87
- C2 observatory/burstObservatory 键族整体 no-op app_config.rs:94-120
- C3 burst executor 生产无注入路径,Rust 方言键致 instance.start() 硬失败 burst_feature.rs:59
- C4 出站级 mux.enabled 静默无复用(concurrency 零消费) outbound.rs:490-507

**超时/资源限制组**:
- T1 vless/trojan/vmess/ss 四协议 inbound 握手读无超时,配 policy 也不生效(slowloris 全覆盖) vless server.rs:643 等
- T2 policy bufferSize 单位错 1024 倍:用户配 512KB 被钳成 512B,吞吐坍缩 register.rs:436-443
- T3 hysteria 认证后 varint 直接分配→单帧进程 abort(TUIC P0 同族,认证后降 P1) protocol.rs:105-116

**传输层组**:
- R1 hysteria UDP 中继 Rust↔Go 断裂:Go 日期门触发 quic-go 不发 DATAGRAM TP,send_datagram 全败(quinn 无 AssumePeer);TCP 路径不受影响故 32 节点未暴露 quinn_adapter.rs:193
- R2 gRPC multiMode 多元素 MultiHunk 帧静默截断→Go→Rust 方向数据丢失 bulk 必现 transport.rs:76-88
- R3 mKCP 服务端 sessions 表永久泄漏(close 空实现)+同 conv 重连锁死 listener.rs:223-228

**可观测性组**:
- O1 用户级流量统计/在线 IP 统计生产零接线(消费端就绪计数端缺失,配置静默无效) default.rs:713-734
- O2 metrics 导出器 StatsCollector 未注入,/metrics 恒空 register.rs:397-410
- O3 anytls 出站 >255 字节域名 expect panic,远端一条 HTTP CONNECT 稳定复现(全仓 317 处 unwrap 审计后唯一网络可达 panic) anytls socks.rs:56-62

## 亮点确认(干净项)

- KCP 状态机/RTT/序号回绕、gRPC 帧编解码/半关闭、WS 帧桥、quicParams 映射、tuic 池生命周期:字节级对照确认干净
- 平台五维(dup/epoll-IOCP/信号/路径/setrlimit)核销无缺口;Linux/Windows 双向无 P1 平台缺陷
- xpadding Huffman 表 19 处错值(P2,脚本对拍 RFC 7541 发现)——tokenish 指纹用户注意

## 修订后修复顺序

1. **P0×3**(不变): SOCKS 认证绕过 / HTTP 握手无界 / TUIC 帧限幅
2. **新增 P1 插队**: 四协议握手无超时(T1,与 P0 同族 slowloris) / bufferSize 1024 倍(T2,一配就坏) / hysteria varint 炸弹(T3)
3. **配置失效组 C1-C4**(用户配置静默不生效,信任损害最大面)
4. **传输层 R1-R3**(hysteria UDP 互通断裂/multiMode 丢数据/mKCP 泄漏)
5. **可观测性 O1-O3 + 第一轮泄漏/挂死/功能组**
6. P2/P3 按需

---

# 第三轮专项审计 (2026-09-05,4 切面)

负优化专项(用户明令)/ DNS+路由引擎 / 加解密字节级 / 依赖健康。方法论强化:**"确认干净"是合法结论,禁止凑数**;每条修复建议附负优化自查。

## 第三轮统计

| 切面 | 报告 | P0 | P1 | P2 | P3 |
|---|---|---|---|---|---|
| 负优化专项 | [negative_optimization.md](negative_optimization.md) | 0 | 0 | 9 | 14 |
| DNS+路由 | [dns_routing.md](dns_routing.md) | **1** | 6 | 14 | 7 |
| 加解密 | [crypto.md](crypto.md) | 0 | 1 | 3 | 5 |
| 依赖健康 | [dependencies.md](dependencies.md) | 0 | 1 | 6 | 11 |
| **小计** | | **1** | **8** | **32** | **37** |

## 三轮合计: P0×4 / P1×43 / P2×114 / P3×53

## 第三轮新 P0

- **DNS parallel_query JoinSet 排空无限自旋**(xray-app-dns/server.rs:437-502):enableParallelQuery+多 policy 组(geosite 国内外分流典型形态)前组全败+后组结果先到 → 解析任务永久挂死烧满一核。修:join_next() 返回 None 跳出+组 race 检查对齐 Go dns.go:414-437

## 第三轮 P1(8 条)

**DNS/路由(6)**:
- singleflight 领导任务中止→条目泄漏+同 key 查询永久挂起(cached.rs:107-130,P0 的放大器)
- hosts 环形配置无限递归(server.rs:248-253,Go maxDepth 耗尽后落 nameserver)
- leastload tolerance/baselines 算法整体偏离 Go(strategy_leastload.rs:229-283,默认 tolerance=0 全灭节点恒 fallback,leastload 实质不可用)
- random 策略杜撰 50/50 fallback(Go 无此语义,一半流量固定走 fallback,strategy_random.rs:44-49)
- 路由命中但 tag 不存在→静默回落默认出站(Go 源码明令 DO NOT CHANGE,流量泄露面,default.rs:908-916)
- routeOnly 丢弃嗅探域名→域名分流整体失效(default.rs:529-535)

**加解密(1)**:
- VLESS ENC 0-RTT 票据失效无恢复:服务端重启后客户端缓存票据有效期内每次重连必败(common_conn.rs:185-188,Go 靠客户端 Read 自愈)

**依赖(1)**:
- h2 0.4.15 命中 RUSTSEC-2026-0258(无界空 DATA 帧→内存耗尽;cargo-deny 实拉 DB 验证非记忆猜测),`cargo update -p h2` 一行修

## 负优化专项结论(用户明令)

- **前两轮 38 项 P0/P1 修复建议逐条预审完成**:5 项标高危前置(ENC 缩锁/writev/CommonConn 池化/finalmask waker/mux wrap——触碰 v49/v50/v51 事故同文件,必须带测试阶梯+benchmark 才可合入);3 项行为激活型(Selector/FakeDNS/httpupgrade/键族)需 changelog+兼容 alias
- **3 项依赖修复明确判定为负优化不做**:强删 fork aws_lc_rs(provider panic 风险)/退回 aead 0.5/换 rsa 实现
- 历史回退模式 6 类,现存同类隐患 4 处已立案;v50/v51/v54 根治点复查无回归;唯一正向性能提交 b069b1a 未被回退
- 代码自认妥协 144 处 ponytail 注释纪律良好,立案其中真正欠账 23 条;P-A 症状抑制模式存量 4 处建议统一改 Build 期硬错
- 生产调试打印残留仅 btls_reality.rs:245 一处 eprintln(一行删)

## 确认干净项(三轮累计,节选)

trojan/hysteria 混淆层字节级全绿;vmess/ENC/ss2022/REALITY 主体一致(44 抽查点);KCP 状态机/gRPC 帧/WS 帧/quicParams 干净;DNS singleflight 算法本体正确;rustls/quinn/tokio/ring RUSTSEC 零命中;无重复 JSON 库;git 依赖 rev 已锁;生产代码无注释掉的功能代码。

## 审计过程事故记录

- timeouts.md 首轮未落盘(reviewer 代理无写盘权限),已由 PM 从 transcript 恢复
- dns_routing.md 首写流超时,已令代理续写成功

---

# 第四轮审计 (2026-09-05,3 切面)

简单协议栈 / mux-reverse 字节级 / **动态验证轮(实跑测试套件,以运行结果为证据)**。

## 第四轮统计

| 切面 | 报告 | P1 | P2 | P3 |
|---|---|---|---|---|
| 简单协议栈 | [simple_proxy.md](simple_proxy.md) | 5 | 6 | 3 |
| mux/XUDP/reverse | [mux_reverse.md](mux_reverse.md) | 4 | 4 | 4 |
| 动态测试 | [dynamic_tests.md](dynamic_tests.md) | 1 | 1 | 3 |
| **小计** | | **10** | **11** | **10** |

## 四轮合计: P0×4 / P1×53 / P2×125 / P3×63

## 第四轮 P1(10 条)

**简单协议(5)**:
- freedom destinationOverride 生产不消费(TPROXY 透明代理静默拨原始目标) dispatcher.rs:38-53
- freedom 默认私网阻断口径断裂+UDP 路径零 FinalRule → 远端客户端可经 freedom 直访 127.0.0.1/169.254.169.254(SSRF 面) udp.rs:196-263
- dokodemo UDP 单 session+last_peer → 多客户端响应错发(DNS/QUIC 透明转发数据错乱) inbound.rs:692-720
- dokodemo TPROXY UDP 语义缺失(回包源=代理地址非原始目标,Linux 上也未实现) inbound.rs:1898-1920
- socks UDP ASSOC 硬编码 127.0.0.1 → 非 loopback 监听时远程 UDP 中继整体不可用 server.rs:243-247

**mux/XUDP(4)**:
- mux 服务端 session 永不移除(Arc::get_mut 恒失败,每子连接泄漏一个) session.rs:541-545
- 客户端缺 writeFirstPayload → SSH/FTP/SMTP 等服务端先说协议经 mux 永不到达 banner client.rs:356-364
- **XUDP 服务端装配断裂:真实 I/O 绑孤儿对象,首包后立即 End —— mux+XUDP 服务端不可用** worker.rs:311-318
- XUDP GlobalID 客户端零接线(生产恒传 None) client.rs:374-380

**动态验证(1)**:
- kcp mask_roundtrip e2e 双用例确定性挂死(finalmask 唯一 e2e 不可用;头号嫌疑=已立案 mKCP sessions 泄漏 R3,关联未证实不重复立案) tests/mask_roundtrip.rs:157

## 动态验证画像(硬证据)

- **workspace 全量 lib 单测:52 目标 5557 passed / 0 failed / 4 ignored,零 panic 零编译错误**——xray-common 历史 flaky 443/0,vless 219/core 246 基线增长无回归
- 集成 45/0 全绿;14 个 Go↔Rust 互操作因旧机残留路径默认跳过(E:\Projcet 残留,P3 一行修)
- kcp tests/ 挂死坐实"必须 --lib"铁律根源;grpc_multimode 4/4 全绿与静态 R2(multiMode 截断)不矛盾——仅 Rust↔Rust 属覆盖盲区
- 零失败用例 → 无 flaky 分诊需求

## SimpleProxyAudit 纠偏

纠正第一轮 completeness.md「freedom destOverride 完整」的误判(实际生产不消费)——已在 simple_proxy.md 标注。


---

# 第五轮:协议级配置全链审计 (2026-09-06,5 协议族,用户点名的最后一块)

方法:以 Go infra/conf 全部 JSON 字段为基准,逐字段比对 Rust serde 解析命名→生产消费点,**inbound/outbound 双侧**。产出 5 份报告、约 **416 个字段级判定**。

## 第五轮统计

| 报告 | 字段判定 | P0 | P1 | P2 | P3 |
|---|---|---|---|---|---|
| [cfg_vless.md](cfg_vless.md) | ≈70 | 0 | 0 | 8 | 9 |
| [cfg_vmess_trojan.md](cfg_vmess_trojan.md) | 38 | 0 | 4 | 4 | 13 |
| [cfg_ss_socks.md](cfg_ss_socks.md) | 68 | 0 | 4 | 8 | 7 |
| [cfg_stream.md](cfg_stream.md) | ≈148 | 0 | 8 | 16 | 6 |
| [cfg_misc.md](cfg_misc.md) | ≈92 | 0 | 2 | 5 | 4 |
| **小计** | **≈416** | **0** | **18** | **41** | **39** |

## 五轮总计: P0×4 / P1×71 / P2×166 / P3×101 ≈ 342 条

## 第五轮 P1(18 条)——配置静默失效实锤(用户直觉正确)

**认证/安全类(最严重)**:
- HTTP inbound `users` 键未解析(只读 accounts)→ Go 风格配置 **Basic 认证静默关闭=开放代理** (inbound.rs:2266)
- anytls 入站零认证(mock 不校验密码,settings 无 password 键) anytls/server.rs:109
- socks `udp:false` 零消费 → ASSOCIATE 恒开 server.rs:247
- grpc 入站不校验 serviceName(任意 POST 放行,反探测失效) grpc/transport.rs:100
- splithttp xPaddingObfsMode 服务端校验桩恒放行(反探测场景裸奔) hub/handler.rs:379

**Go 标准键静默丢(用户配置不生效)**:
- VMess inbound `users` 主键丢弃 → 零用户全拒无日志(仅认 clients)
- SS `users` 主键未解析 + 2022 relay Go 形态(users[].address/port)不认 → 静默落单用户
- VMess/Trojan outbound 平铺形式(顶层 address/port)不支持 → 拒启
- wireguard 六键(preSharedKey/keepAlive/allowedIPs/mtu/reserved/domainStrategy)解析层全丢 → **Cloudflare Warp 类节点直接不可用**
- splithttp `sessionIDPlacement`/`sessionIDKey` 键名错位(读 sessionPlacement/sessionKey)
- splithttp `noSSEHeader` 解析缺键(伪装分支不可用)
- sockopt `tproxy` 类型错位(string 枚举当 bool)→ **透明代理全废**
- acceptProxyProtocol 双入口全断 → PROXY 协议场景拿不到真实源地址

**出站断链**:
- tlsSettings.fingerprint 仅 tcp/REALITY 出站生效,ws/grpc/httpupgrade/splithttp **静默走标准指纹**(抗探测归零)
- grpc 出站 6 字段(authority/user_agent/idle_timeout 等)解析未消费
- Trojan fallbacks dest 数字形式静默落 127.0.0.1:80(错后端)

## 横切结论(第五轮核心发现)

**"Go 主键 vs Rust 别名"模式系统性存在**:vless clients(SS/trojan/vmess/socks/http 同族——vless 做了旧名回退,其余五协议都没做,回退实现本身在仓库里已有可抄)。
**协议层 camelCase 键名错位与 app 层(第二轮)同病**,覆盖:users/sessionIDPlacement/noSSEHeader/tproxy/obfsPassword 等。

## 确认干净(字段级,节选)

VLESS ENC 双侧全链逐字节干净(padding 切片公式同构+interop 4/4 实证);kcpSettings 主干六键双侧生效;finalmask.quicParams 13 项对称;TUIC 出站全键消费;mkcp header 族 6/6 对齐;naive 结构一致。约 416 判定中 ✅ 生效约 230。

## 过程事故(记录)

reviewer 代理无写盘工具+单次输出流超时 → 5 路中 4 路报告初写失败;经"分段落盘"指令自救 3 份 + 誊写员验收 2 份恢复,**零发现丢失**(TranscribeStream 验收修正 cfg_stream 统计错报并恢复漏列发现#8)。
