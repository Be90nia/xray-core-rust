# 负优化专项审计报告（第三轮·负优化切面）

> 审计代理: NegOptAudit | 日期: 2026-09-06 | 基线: HEAD `4e6c1fe`
> Go 基准: D:/Project/Xray-core (v26.7.28) | 方法: 全仓只读,唯一写动作 = 本文件
> 输入: ponytail 注释 144 处全量回收 / 保守·妥协·降级类注释 29 处 / TODO·FIXME 23 文件 / 全仓 641 commit 回退考古 / beads 检索（无失败优化任务记录）/ 与前两轮 38 项 P0/P1 去重交叉
> 用户最高原则已执行: 每条发现 file:line + 代码证据 + Go 基准对照；修复建议逐条做负优化自查；"确认干净"如实记录

---

## 〇、结论速览

| 类别 | 数量 | 说明 |
|---|---|---|
| 新立案 P2 | 9 | 生产 REALITY 调试打印残留、ss2022 轮换无时限等（表一 A/B 类） |
| 新立案 P3 | 14 | 观察级妥协、文档烂账、死代码（表一 A/B/C 类） |
| 交叉索引（前两轮已跟踪，不重复立案） | 38 | 表一 D 类 |
| 表二: 前两轮 P0/P1 修复建议负优化预审 | 38/38 | 全部给出安全修复边界；5 项标"高危前置" |
| 表三: 历史回退事件 | 7 起 → 6 类模式 | 现存同类隐患 4 处（QUIC DATAGRAM 面×3 + 调试打印×1） |

**TOP3**:
1. **[P2] 生产 REALITY 路径残留调试打印 `btls_reality.rs:245`** —— v26 已回退的"探针入库"前科在另一文件复发，一行删除零风险。
2. **[P2] "ponytail 自认语义弱化"组**（ss2022 轮换无 60s 时限 / splithttp obfs 校验短路 / reality 恒定路径）—— 全部有明确 Go 基准且修复面小，属"为绕开实现难度而降级"的 P-A 症状抑制模式存量。
3. **表二高危前置组**（CommonConn 池化 / finalmask waker 重构 / writev / ENC 锁缩窄）—— 修复建议本身携带挂死回归风险，触碰 v50/v51 事故同文件或同模式，必须带测试阶梯合入。

---

## 一、表一: 自认妥协清单

### A 类 — 热路径性能妥协（新立案）

**[P2] 日志文件 handler 每写一行 open/write/close 三个 syscall，Go 为启动时打开一次** | `crates/xray-app-log/src/instance.rs:370,393`
- 证据: `/// ponytail: per-write open — 如果性能不够，改用 RwLock<File> 持有句柄`（:370）；实现 `OpenOptions::new().create(true).append(true).open(&self.path)`（:393）位于 `LogHandler::handle`（每条日志执行）。
- Go 基准: `common/log/logger.go:163-166` `CreateFileLogWriter` 在 handler 创建时**一次性** `os.OpenFile(O_APPEND|O_WRONLY|O_CREATE)` 并复用句柄；`app/log/log_creator.go:49-53` 装配即打开。
- 影响: 配置 access/error 文件日志的部署，每条日志多 2 次 syscall + 路径解析；高 QPS 下写放大显著（access log 每连接 ≥1 行）。
- 升级路径: `RwLock<File>` 持有句柄 + rotate 时 reopen（注释已给出）；或 `OpenOptions` 打开一次存 `Mutex<File>`。
- 负优化自查: 持句柄后 rotate 需显式重开（现 per-write open 天然支持 rotate）——升级时必须保留 rotate 语义，否则引入"日志写满旧 inode"回归。安全可修: **是**（改动封闭在 FileHandler 内）。

**[P2] wireguard TCP relay 轮询桥自认 ~5ms 延迟** | `crates/xray-proxy-wireguard/src/dispatcher.rs:17`
- 证据: `//! # ponytail: 轮询式桥接，延迟 ~5ms 量级。waker 驱动优化留待吞吐量瓶颈时。`
- 影响: wireguard 出站的 TCP 流每次方向切换引入轮询周期级延迟；交互式流量（SSH/RDP over WG）可感知。
- 升级路径: 注释已指明——smoltcp 侧 `SocketSet::will_recv/will_send` 事件驱动 + tokio wake。
- 负优化自查: waker 驱动是 finalmask mod.rs:456 同族重构（见高危前置），需 poll harness 防丢唤醒。安全可修: **有条件**。

**[P2] tun UDP 会话表自认无清理，Arc 永久持有** | `crates/xray-proxy-tun/src/inbound.rs:423-426`
- 证据: `/// # ponytail: 不主动清理 sessions map` —— `Go 端用 CancelAfterInactivity(1min) 回收空闲 udpConn。本切片先用 Arc 永久持有`。
- 影响: Linux 生产 tun 入站下，UDP 会话按源地址只增不减（每会话含 smoltcp socket + duplex 桥），移动端/扫描器场景慢性泄漏。与前两轮 ss2022 UDP 泄漏（inbound.rs:1102）同族。
- 升级路径: 对齐 Go——每 session 记 last_seen，收包路径顺带 retain（inbound.rs:991 既有模式可复用）。
- 负优化自查: retain/包是 O(n)（本表 A4 同款代价），n=会话数可控。安全可修: **是**。

**[P3] legacy ss / ss2022 UDP 每包 O(clients) retain 清扫** | `crates/xray-core/src/inbound.rs:991-993,1111-1113`
- 证据: `// ponytail: 收包时顺带清扫已退出（60s 空闲淘汰）会话的残留 sender；O(clients)/包，海量并发 UDP 客户端时换后台定时清扫` + `clients.retain(|_, tx| !tx.is_closed());`
- 影响: 常规客户端数（<100）下每次 retain 亚微秒级，注释自辩成立；海量 UDP 客户端（DNS 放大/公共出口）时每包锁+全表扫。tuic 侧同款 `server.rs:425-426`。
- 升级路径: 后台定时清扫（300s 周期，对齐 DNS cacheCleanup 模式）。
- 负优化自查: 后台任务自身是新增常驻资源；当前量级**不建议动**（改了反而复杂化），记录在案即可。安全可修: 是但**不建议现在修**。

**[P3] geodata WeakCache 全局 Mutex 串行化** | `crates/xray-geodata/src/weak_cache.rs:16-19`
- 证据: `//! ponytail: 全局 Mutex 串行化所有操作；热点路径单写多读，高并发下 RwLock 更优…升级路径: 用 arc_swap 或 dashmap shards`。
- 影响: 路由热路径每次查表一次全局锁；临界区纯内存极短，注释自辩"开销可忽略"基本成立，高并发路由查表下存在真竞争点。
- 升级路径: `arc_swap` 或分片。
- 负优化自查: 无（读多写少场景换锁只赚不赔），但**无 benchmark 证据前不动**（铁律#1），记录为观察项。安全可修: 是。

**[P3] kcp 拨号域名解析用同步 ToSocketAddrs 占 runtime 线程** | `crates/xray-transport-kcp/src/register.rs:270-273`
- 证据: `/// ponytail: ToSocketAddrs 同步解析会占 runtime 线程；Go runtime 同样线程池 getaddrinfo，DNS 热路径成瓶颈时再换异步 resolver`。
- 影响: 每次 mKCP 出站拨号阻塞一个 tokio worker 至 resolver 返回；解析超时期间占用线程。
- 升级路径: `spawn_blocking` 包裹或异步 resolver。
- 负优化自查: 无；与 Go 同级（Go 亦阻塞 goroutine 线程），按需再修。安全可修: 是。

**[P3] vmess max_padding_hint 恒返回 64** | `crates/xray-proxy-vmess/src/encoding/body_chunk.rs:586-590`
- 证据: `// ponytail: trait object 不能直接调关联常量，统一返回 64…PlainSizeParser 实际为 0，差 64B 不影响正确性，仅 payload_chunk_size 略小`。
- 影响: 缓冲预留偏保守，无正确性问题。
- 负优化自查: 修了无收益。安全可修: 是但不值得。**确认无害**。

### B 类 — 正确性 / 安全语义弱化（新立案）

**[P2] 生产 REALITY 路径残留调试打印（v26 前科复发）** | `crates/xray-tls/src/btls_reality.rs:244-246`
- 证据:
  ```rust
  if let Err(e) = connect_result {
      eprintln!("[REALITY dbg] SslStream::connect failed: {e:?}");
  ```
  位于生产 connect 错误路径（security.md P1-2 所引 :234-243 的紧邻后续行），非 `#[cfg(test)]`。
- Go 基准: REALITY 握手错误经 `log.Record`/AtInfo 管道，受 loglevel 管控。
- 影响: ① 绕过 loglevel/access:"none" 直接写 stderr（与 observability.md P2"直连日志绕过 loglevel"同族）；② `[REALITY dbg]` 标记证明是诊断残留——与 v26 `vless/encryption` eprintln 被回退（commit 335dc80 前科）及 5bdfe05"探针有时序副作用"教训同模式。
- 修复建议: 删除该行（错误已由 `io::Error::new(ConnectionAborted, e.to_string())` 携带上传）。
- 负优化自查: 纯删除，无行为变化。安全可修: **是，一行**。

**[P2] ss2022 UDP server session 轮换缺 Go 的 60s 切换时限** | `crates/xray-proxy-ss/src/ss2022/packet.rs:354-366`
- 证据:
  ```rust
  if !cur && !lst {
      // 新 server session：当前代降级为上一代后轮换
      // ponytail: Go 额外限制 60s 内只允许切换一次 server session
      // （ErrTooManyServerSessions）；这里保留两代轮换不做时限，
      // 防 DoS 语义弱化，正常重绑定场景等价
  ```
- Go 基准: sing-shadowsocks 服务端 60s 内仅允许一次 server session 切换（ErrTooManyServerSessions），防快速轮换抖动。
- 影响: 持合法 PSK 的客户端可无限速轮换 sessionId：连续三次轮换即把上一会话挤出双代窗口，与其并行的合法会话整代失效（对多客户端共用同一 PSK 的部署构成定向干扰面）；正常单客户端重绑定等价（注释判断正确）。
- 修复建议: `remote` 状态加 `last_switch: Instant`，60s 内第二次新 session 直接拒绝（返回 Ss2022PacketIdNotUnique 同类错误）。
- 负优化自查: 多客户端共用 PSK + 频繁重绑定的边缘场景会被 60s 时限误伤——与 Go 行为一致即为目标语义，非回归。安全可修: **是**。

**[P2] splithttp 服务端 obfs_mode=true 时 padding 校验整体短路** | `crates/xray-transport-splithttp/src/hub/handler.rs:376-380` + `payload.rs:86-90`
- 证据: `// ponytail: 非强制 padding 校验。仅在 obfs_mode=false 时检查 Referer。obfs_mode=true 时校验逻辑依赖完整 xpadding 模块，留后续。` → `if ctx.config.x_padding_obfs_mode { return true; }`（无条件放行）。
- Go 基准: Go hub 在 obfs 模式下强制校验 padding（该模式存在意义即严格伪装）。
- 影响: Rust 服务端接受任意不合规 padding 流量——互操作方向安全（多收不拒收），但削弱 obfs 模式的伪装强度保证，且与 Go 服务端行为分叉（Go 拒、Rust 收，流量特征可被探测区分）。
- 修复建议: 对齐 Go 校验（xpadding 模块已在同 crate 实现，`xpadding.rs` 完整）；短期至少打 warn 声明未强制。
- 负优化自查: 补校验会拒收此前放行的流量——属**预期语义修复**（向 Go 收敛），上线需 changelog。安全可修: **是**。

**[P3] dokodemo 出站 Unix→TCP 静默降级** | `crates/xray-proxy-dokodemo/src/outbound.rs:83-85`
- 证据: `// dokodemo 不支持 Unix socket outbound，降级为 TCP` → `Network::Unix => Destination::tcp(...)`。
- 影响: 配置 Unix 网络目标被静默按 TCP 处理（Rust 扩展路径，Go 无对应）。与 platform.md F1/F7"静默降级"同族。
- 修复建议: 返回 Unsupported 硬错或启动期校验拒绝。
- 负优化自查: 无。安全可修: 是。

**[P3] REALITY get_path_locked 确定性取第一个路径** | `crates/xray-reality/src/util.rs:47-50`
- 证据: `// ponytail: deterministic for now; random selection deferred` → `paths.keys().next()`。
- Go 基准: Go reality 从路径集随机选取（fallback 路径多样化是伪装面的一部分）。
- 影响: 服务端 fallback 恒定同一路径，伪装多样性弱化。
- 修复建议: `rand::rng().random_range(0..n)`（注: HashMap 无序，`keys().next()` 本身带偶然性但语义非随机）。
- 负优化自查: 无。安全可修: 是。

**[P3] splithttp roomSize ≥ 2^30 校验跳过** | `crates/xray-transport-splithttp/src/register.rs:315-318`
- 证据: `// ponytail: roomSize >= 2^30 校验跳过——Rust 无 conf 层代理；用户自己保证 table * length 足够大避免熵不足`（Go transport_method.go:420-424 有该校验，ASCII 校验已对齐）。
- 影响: 极端配置下 padding 熵不足，伪装弱化；常规配置无影响。
- 修复建议: 补同款校验硬错。
- 负优化自查: 无。安全可修: 是。

**[P3] UDP relay 空闲 60s 硬编码不受 policy** | `crates/xray-transport/src/udp/relay.rs:34-36`
- 证据: `/// ponytail: hardcode 60s，未暴露 policy 配置化入口（与 issue Non-goals 一致）`。
- Go 基准: UDP 会话空闲受 `policy.Timeouts.ConnectionIdle`（默认 300s）管。
- 影响: 空闲 UDP 会话 Rust 60s 即回收 vs Go 300s——长连接 UDP 应用（游戏/VoIP 空闲期）行为差异；另 dispatcher udp_session.rs:19-22 自认无内置空闲超时（调用方生命周期兜底）。
- 修复建议: 从 policy 注入 idle 值。
- 负优化自查: 放宽超时会延长会话驻留（内存↑），对齐 Go 默认 300s 即可。安全可修: 是。

**[P3] hysteria 出站超长 datagram 无分片直接报错断连** | `crates/xray-proxy-hysteria/src/dispatcher.rs:296-300`
- 证据: `// ponytail: 不做超限分片——Go 依赖 quic.DatagramTooLargeError 携带的 MaxDatagramPayloadSize，Rust io::Error 无此信息；超限包 send_datagram 报错断开`。
- 影响: 超过 QUIC datagram 容量的 UDP 包（视频通话/WireGuard over hysteria）导致会话断开而非分片/丢弃该包。
- 修复建议: 超限时丢包+计数（UDP 语义允许）而非断连；或按 tuic FRAG 方案分片。
- 负优化自查: 断连→丢包是行为放宽（更符合 UDP 语义），无回退面。安全可修: 是。

**[P3] finalmask 超长包剩余字节静默丢弃** | `crates/xray-transport/src/finalmask/mod.rs:449-452`
- 证据: `let n = pkt.len().min(buf.remaining()); buf.put_slice(&pkt[..n]);` + `// ponytail: 超长包丢弃剩余字节——简化不缓存；KCP 段长恒 < 1500 包足够`。
- 影响: 调用方 ReadBuf 小于包长时尾部字节丢失（当前调用方读缓冲 ≥8KB，不触发）；与 mod.rs:447 spawn 问题同文件（后者已跟踪）。
- 修复建议: 剩余字节回填队首（保留 `pkt` 残段）或断言 buf.remaining() 下限。
- 负优化自查: 回填队首引入一次 copy，仅在触发时发生。安全可修: 是。

### C 类 — 文档烂账与死代码（新立案）

**[P3] dns cached.rs 的 ponytail 注释与实现直接矛盾（声称未实现、实际已实现）** | `crates/xray-app-dns/src/nameserver/cached.rs:94-96 vs :103-132`
- 证据: 注释称"省略 singleflight 去重（per-key Mutex）与 pubsub 订阅"；紧随其后的代码正是完整 singleflight（`single_flight` 表 + `broadcast::channel` 广播 + leader 崩溃回退直查，:105-132），concurrency.md 已核查其正确性。
- 影响: 误导后续维护者重复实现或误判缺能力（completeness.md §0 已列同族过期注释 4 处，本条为其漏网第 5 处）。
- 修复建议: 删除/改写该注释。安全可修: 是，零风险。

**[P3] vision.rs splice_copy 恒 Err 桩与生产 raw 通道并存** | `crates/xray-proxy-vless/src/encryption/vision.rs:491-501`
- 证据: `// ponytail: splice 需要底层 raw stream 提取，Rust TLS 不支持，留 TODO` → 恒返回 Err 的死桩。而生产 splice 直通已由 `raw_tcp_clone`/`dup_tcp_stream` 链实装（memory.md §五"接线现状澄清"确认在跑）。
- 影响: 注释与架构现状脱节，读者误以为 Vision 无 splice 能力。
- 修复建议: 删除死桩或改注释指向真实通道（accept 层 dup + VisionConn raw_fallback）。
- 负优化自查: 纯清理。安全可修: 是。

**[P3] xray-buf splice.rs 内核 splice 为死代码且自带两处硬伤** | `crates/xray-buf/src/splice.rs:20-62`（前两轮 memory.md P2 已立案，此处仅归档）
- 两方向串行 + EAGAIN 1ms 忙等；接线即挂死。**修复建议维持原判: 先重构双任务并发 + AsyncFd，否则保留死代码或删除。**

**[P3] docs/audit/timeouts.md 被 AUDIT_SUMMARY.md 引用但文件缺失**
- 证据: AUDIT_SUMMARY.md 第二轮表格引用 `[timeouts.md](timeouts.md)`，`docs/audit/` 实际 11 个文件无该文件；T1-T3 三条 P1 仅存在于汇总摘要中。
- 影响: 审计溯源断链。
- 修复建议: 补文件或修链接。

### D 类 — 已跟踪妥协交叉索引（不重复立案，供本表完整性）

前两轮 38 项 P0/P1 全部自带"自认妥协"属性（注释自认/实现降级），已由 bd 跟踪，速查索引:

| 主题 | 位置 | 轮次 |
|---|---|---|
| SOCKS 认证绕过(NoAuth 回退自认) | socks/server.rs:366 | 1-S1 |
| HTTP 握手无界(逐字节读自认) | http/server.rs:306 | 1-S2 |
| TUIC 帧长无上限 | tuic/h3.rs:182 | 1-B1 |
| 握手无超时(注释自认"简化传 None") | core/inbound.rs:293 | 1-SEC |
| REALITY hooks 手工配对泄漏 | btls_reality.rs:234 | 1-SEC |
| ss2022 UDP 会话只插不删 | core/inbound.rs:1102 | 1-SEC/MEM |
| reverse 强引用环/monitor 无视 close | reverse/worker.rs:355, bridge.rs:268 | 1-MEM |
| DNS 清理任务零调用方("模式已备接线缺失") | dns/cache_controller.rs:240 | 1-MEM |
| mux XUDP clone 语义 | mux/worker.rs:276 | 1-CON |
| ENC 共享锁跨握手 | vless/dispatcher.rs:178 | 1-CON |
| burst 锁内同步探测 | burst_observer.rs:220 | 1-CON |
| Trojan UDP 错误吞掉 | trojan/dispatcher.rs:223 | 1-BUG |
| VMess 每 record 分配链 | crypto/auth_writer.rs+common_conn.rs:192 | 1-PERF |
| 池无上限(注释自认"无上限") | buf/alloc.rs:153 | 1-PERF |
| 裸 TCP 无 writev | buf/writer.rs:36 | 1-PERF |
| finalmask 每包 spawn("ponytail 自认浪费") | finalmask/mod.rs:447 | 1-PERF |
| NotImplementedSelector 装配 | wiring.rs:376 | 1-F1 |
| httpupgrade TLS acceptor 丢弃("ponytail 待接入") | httpupgrade/register.rs:89 | 1-F2 |
| FakeDNS 引擎未注入 | register.rs:684 | 1-F5 |
| freedom domainStrategy 未消费("ponytail 自认") | freedom/dispatcher.rs:33 | 1-F3 |
| dns 出站 domain 匹配缺失("留切片2") | dns/config.rs:159 | 1-F4 |
| policy/observatory 键族静默丢失 | conf/app_config.rs:42-120 | 2-C1/C2 |
| burst executor 无注入路径 | burst_feature.rs:59 | 2-C3 |
| 出站 mux.enabled 无复用 | core/outbound.rs:490 | 2-C4 |
| 四协议握手无超时 | vless/server.rs:643 等 | 2-T1 |
| bufferSize 1024 倍 | register.rs:436 | 2-T2 |
| hysteria varint 分配 | hysteria/protocol.rs:105 | 2-T3 |
| hysteria DATAGRAM 断裂 | quinn_adapter.rs:193 | 2-R1 |
| gRPC multiMode 截断 | grpc/transport.rs:76 | 2-R2 |
| mKCP 会话表泄漏(close 空实现自认) | kcp/listener.rs:223 + dialer.rs:15 | 2-R3 |
| 用户级统计零接线 | dispatcher/default.rs:713 | 2-O1 |
| metrics 恒空 | register.rs:397 | 2-O2 |
| anytls >255 panic | anytls/socks.rs:56 | 2-O3 |
| btls 指纹缺口 | btls_client.rs:19 | 1 |
| policy level-1 强制 600s | policy/manager.rs:57 | 1-BUG P2 |
| vmess/vless 拒绝日志 debug 级 | vmess/inbound/server.rs:151 | 2-OBS P2 |
| socks >255 长度前缀错位 | socks/protocol.rs:166 | 1-SEC P2 |
| splithttp 乱序毒化/padding hint | upload_queue.rs:217+xpadding.rs:49 | 2-R |
| sockopt.interface 静默丢弃 | transport/dialer.rs:163 | 2-PLAT F1 |

另: xor_conn.rs:268-271 每写全量分配（`ponytail: 每写一次一次分配…无零分配写法`）与 ss validator seen_ivs 无界（validator.rs:102-105）已由 memory.md/security.md P2 立案。

---

## 二、表二: 前两轮 P0/P1 修复建议负优化预审（38 项）

图例: 性能回退风险 / 行为破坏风险 / 新 bug 面 → 低·中·高；**边界** = 安全修复边界（必须满足才动手）。

| # | 项目 | 修复动作摘要 | 性能回退 | 行为破坏 | 新 bug 面 | 安全修复边界 |
|---|---|---|---|---|---|---|
| 1 | S1 SOCKS 认证绕过 (server.rs:366,296) | 删 NoAuth 回退 + SOCKS4 按 requires_auth 拒绝 | 低 | 中: 只报 NoAuth 的老客户端从"意外放行"变"拒绝" | 低 | 对齐 Go protocol.go:109-118 即目标语义；拒绝路径回 0xFF 并 warn；`socks4_handshake` 需同步 mixed 入站调用点 |
| 2 | S2 HTTP 握手无界 (server.rs:306) | 行上限 8-16KB + 总量 64KB + 行数上限 + 带缓冲读 | **负优化反转: 修掉每字节一次 read 的 CPU 放大** | 低 | 中: 上限边界(恰好卡线)截断语义 | 上限取值 ≥ Go http 栈等效(1MB 总量级可放宽到 64KB 需验证真实客户端)；socks `read_until_null` 一并加；超限回 4xx/断连并 debug 日志 |
| 3 | B1 TUIC 帧长 (h3.rs:182) | len 硬上限/按帧类型限幅 | 低 | 低 | 中: DATA 类大帧误杀 | 控制帧(SETTINGS 等)小上限；DATA 用流式读或按对端协商上限；上限常量放协议常量区对齐 hysteria 同款(2048/4096 风格) |
| 4 | M1 reverse 引用环 (worker.rs:355) | worker 字段改 Weak 或 close 拆环 | 低 | 低 | 中: upgrade 失败路径 | timer/帧循环收尾处经 weak upgrade 置 None；`is_active`/picker 读到 None 需有既定分支(现 Retain 已兜) |
| 5 | M2 DNS 清理接线 (cache_controller.rs:240) | DnsService start 调 start_cleanup_task + close abort | 低(300s 周期扫描可忽略) | 低 | 低: 重复 start 防重 | JoinHandle 存 service，幂等(已启动不重复 spawn)；close 需 abort 而非 detach |
| 6 | M3 ss2022 UDP 会话泄漏 (inbound.rs:1102) | `server_sessions.retain(\|sid,_\| sessions.contains_key(sid))` 或 last_seen+idle 扫 | 低(与既有 retain 同价) | 低: 60s 后重绑定拿新会话(Go 同) | 低 | 与 relay 60s 空闲退出信号对齐；两张表同键空间已确认 |
| 7 | M4 reverse monitor 无视 close (bridge.rs:268) | 循环内检查 running / CancellationToken | 低 | 低 | 低 | Portal 清理循环同改；close→start 语义保持(单 monitor) |
| 8 | C1 mux XUDP clone (worker.rs:276) | 共享句柄 Arc<Mutex<XUDP>> 或 manager 内 try_begin_init/update_status | 低(UDP 帧路径一次锁) | 低: 启用 Go 本意的流复用 | 中: 状态机转移完整性 | conflict 判定与状态转移必须同一写锁；Session::close→Expiring 同步改；mux/xudp e2e 回归必跑 |
| 9 | C2 ENC 共享锁跨握手 (dispatcher.rs:178) | ①先 timeout 包裹 lock+handshake ②再缩锁到缓存写 | **①不变②提升(消除串行化)** | 低 | **高: ②删外层锁前必须审计 ClientInstance 内部缓存并发** | **高危前置**: 分两步走；②之前核对 pfs_key/ticket/expire 缓存全部 RwLock 化且无 check-then-act；握手 timeout 对齐 policy.handshake；ENC e2e+interop_enc.py 必跑 |
| 10 | C3 burst 锁内探测 (burst_observer.rs:220) | 锁外探测+批量 put；scheduler 挪 spawn_blocking | 低 | 低 | 低 | 与 F-W3(装配断裂)合并修，否则修完锁仍无生产路径 |
| 11 | SEC1 REALITY hooks 泄漏 (btls_reality.rs:234) | RAII guard 或调整注册顺序 | 低 | 低 | 低: 回调触发时序 | 回调只在 connect() 期间触发——注册移到 TokioSslStream::new 后语义不变需注释论证；guard 的 Drop 在 panic unwind 也要注销 |
| 12 | SEC2 握手零超时 (inbound.rs:1866,320) | policy None → 默认 4s；socks/mixed 调用点 timeout 包裹 | 低 | 低: 慢客户端 4s 被断=Go 默认语义 | 低 | 只在 policy 缺失时落默认；mixed 的 SOCKS 分支补同一 timeout；与 T1 统一实现防两套口径 |
| 13 | SEC3=6 同项 | — | — | — | — | 同 #6 |
| 14 | P1 writev (writer.rs:36) | IoSlice 收集 + write_vectored | **高: 实现不当反劣化** | 低 | **高: 部分写推进/TLS 分支误批** | **高危前置**: TLS(rustls 包装)分支必须保持逐 Buffer(违反 v51 语义=挂死前科)；write_vectored 返回字节数需推进 slice 游标；先 benchmark(loopback 8×8KB vs 现路径)证明收益再合 |
| 15 | P2 VMess 分配链 (auth_writer.rs:152) | 池化 Buffer + ring open_in_place | 低 | 低 | 中: 原位解密 tag 处理 | split_bytes 跨块拼接场景保留物化路径；vmess 往返 e2e + alloc 计数(dhat)验证 |
| 16 | P3=15 同源 (common_conn.rs:192) | BytesMut split_to + open_in_place | 低 | 低 | **高: 触碰 v50/v51 挂死前科同文件** | **高危前置**: 只动读侧缓冲管理，poll_write/waker 语义一行不碰；512KB duplex stress + interop_enc.py + 32 节点全跑 |
| 17 | P4 池无上限 (alloc.rs:153) | 每分片每层 cap(如 64) | **中: cap 过小→池抖动** | 低 | 低 | cap 取观测并发峰值上界；burst 单测(池水位)防回归；一行改动先 benchmark 高并发出站场景 |
| 18 | P5 finalmask spawn (mod.rs:447) | Option<Waker> 存储 + try_send_to | 低 | 低 | **高: 丢唤醒=v50 同族事故模式** | **高危前置**: register_waker 语义(不同才替换+wake)需确定性 poll harness 单测；KCP/finalmask e2e |
| 19 | F1 NotImplementedSelector (wiring.rs:376) | 装配点传真实 selector(SimpleOhm 快照) | 低 | **中: balancer 配置开始真实生效，原 fallbackTag 用户流量路径改变** | 低 | 这是"修复即行为变化"项——发布说明必须写明；selector 出错仍走 fallback 的路径保留并 warn |
| 20 | F2 httpupgrade TLS (register.rs:89) | 接 build_tls_acceptor 真实现 | 低 | 低: 修复坏特性 | 中: TLS 握手与 header 读取衔接 | 需真 acceptor 实现(现返回 Unsupported)；httpupgrade+wss e2e |
| 21 | F5 FakeDNS 注入 (register.rs:684) | engine() → set_fdns | 低 | 中: destOverride 开始真实改写 | 低 | 同 #19，配置激活即行为变化；fakedns 池与路由规则联测 |
| 22 | BUG1 Trojan UDP 吞错 (dispatcher.rs:223) | Err → 终止会话 | 低(防 OOM) | 低: 畸形流被杀=Go 语义 | 低 | 与入站侧 server.rs:532 对齐；补"非法 ATYP 流"回归用例 |
| 23 | C-W1 policy 键族 (app_config.rs:42) | rename_all=camelCase + alias | 低 | **高: 若只加 camelCase 会破坏现存 Rust 方言(snake_case)用户配置** | 低 | **必须双 alias**: camelCase(新/Go)+保留 snake_case(旧)serde alias；补 Go 标准 JSON 往返断言单测(现测试只断容器存在) |
| 24 | C-W2 observatory 键族 (app_config.rs:94) | 同上 + subjectSelector 列表化 | 低 | 中: 探测启动后产生出站探测流量 | 低 | 同 #23 双 alias；`probe_timeout` 死字段删除而非实现；单 tag→列表语义迁移需测试 |
| 25 | C-W3 burst 装配 (burst_feature.rs:59) | impl init_dependencies(取 selector+executor) | 低 | 中: 标准配置开始发起真实探测；方言键硬失败需一并消除 | 低 | Go 键落地后 F-W3②(方言键 start 硬失败)自然消解；装配级"config→start 成功"测试必须补 |
| 26 | C-W4 出站 mux (outbound.rs:490) | 分阶段: 先 warn 消静默，再包 mux 客户端 | 低 | 低(warn)/中(wrap) | **高(wrap: 与 vless ENC 链组合)** | **wrap 属高危前置**(组合层=v35/R2 事故面)；第一版只做 warn(注释自认"至少先 warn") |
| 27 | T1 四协议握手超时 (vless/server.rs:643 等) | timeout 包裹首包读 | 低 | 低 | 中: timeout 只能罩握手读不能罩代理寿命 | 与 SEC2 统一；ws/grpc 等 TLS-in-hub 路径确认超时点在 hub 终结后首 payload 读 |
| 28 | T2 bufferSize 单位 (register.rs:436) | 值×1024 修正 | 低(修复后吞吐恢复) | **中: 用户配置内存占用按配置值放大千倍** | 低 | 对齐 Go 单位(KB)语义+钳制范围；启动日志打印生效值(防"修好了但内存涨了"困惑) |
| 29 | T3 hysteria varint (protocol.rs:105) | 复用本 crate 既有 2048/2048/4096 常量限幅 | 低 | 低 | 低 | 照抄同文件既有模式即可 |
| 30 | R1 hysteria DATAGRAM (quinn_adapter.rs:193) | ①send_datagram 探测失败降级 stream ②patch quinn-proto assume-TP | 中(①降级路径性能低于 DATAGRAM) | 低(①是"从全断到可用"严格改善) | 中: ①中途切换丢包/乱序 | 优先②(最小 patch + 上游 issue)；①作为兜底须一次性探测+日志+不可回切；注意 Go 侧 2026-09-01 日期门恒真=所有 Go 对端都缺 TP |
| 31 | R2 gRPC multiMode (transport.rs:76) | multi_mode 时走 decode_multi_hunk_frame 拼接 | 低 | 低(修数据丢失) | 低 | 用 Go 端 MultiHunk wire fixture 做字节级单测；`Hunk::decode` 加 `data_end==len` 快速失败 |
| 32 | R3 mKCP close (listener.rs:223) | Weak<Listener> + remove | 低 | 低(修重连锁死) | 低 | 与 globalConv 随机化(P2)一并上，否则重启后 conv=1 撞死会话概率仍 100% |
| 33 | O1 用户统计接线 (default.rs:713) | policy.statsUser* 门控 + SizeStatWriter 包装 + OnlineMap | **中: 不门控则全量连接白付原子加** | 低 | 中: MAX_REGISTRY_ENTRIES=1024 溢出静默 | **必须按 Go 门控**(policy 开了才挂计数)；超 1024 需 warn(报告已点名)；计数层级(payload vs 连接)差异注释说明(observability P2 项) |
| 34 | O2 metrics 注入 (register.rs:397) | with_stats_collector 适配器 | 低 | 低 | 低 | collector 只在 collect() 时遍历，无热路径代价 |
| 35 | O3 anytls panic (socks.rs:56) | 截断 255(对齐 vless/trojan/vmess)或显式报错 | 低 | 低 | 低 | 建议**报错**而非截断: 与 Go socks 编码语义一致(超长报错)，且避免静默错路由；anytls 无 Go 基准，与兄弟实现一致性次之 |
| 36-38 | (T1/T2/T3 已列; 余下 R1-R3/O1-O3 已列) | — | — | — | — | — |

**预审总结**: 38 项中 33 项为低风险"修了只赚不赔"；**5 项高危前置**（#9 ENC 缩锁、#14 writev、#16 CommonConn、#18 finalmask waker、#26 mux wrap）全部触碰 v50/v51/v35/v49 事故同文件或同模式（详表三），修复时必须带测试阶梯与 benchmark；**3 项行为激活型**（#19/#20/#21/#23-25 组）修复本身即配置语义变化，需 changelog 与双 alias 兼容。

---

## 三、表三: 历史回档模式

### 3.1 回退事件清单（git 考古，641 commits）

| commit | 事件 | 根因 | 模式 |
|---|---|---|---|
| `11bd9db` / `d0cc542` | 双次 Revert "disable splice trigger to avoid btls BAD_DECRYPT"（a8537c5 / 095cfaa） | 症状抑制型 workaround（关触发器躲报错）两次被不同批次重新引入又两次回退；真根因（poll_write 裸 Pending / TLS 包装层 flush 语义）直到 v50/v51 才根治 | **P-A 症状抑制** + **P-C 协调缺口** |
| `5e9b234` (v35) | splithttp 接 btls 尝试回退 | 400 bad status mode 不兼容——传输层组合未先验证服务端模式兼容性 | **P-B 组合层未验证** |
| `0cf53c0` (v29) | revert 子代理补丁 | VPS 中断无法验证——未验证的补丁不入主干 | **P-C 无验证不落地** |
| `5bdfe05` (v49) | server splice 整体回退 | 跨缓冲窗口流式挂死回归；探针有 timing 副作用导致"挂/不挂与时序相关" | **P-D 性能特性无测试阶梯** + **P-E 探针副作用** |
| `335dc80` | 清理 vision/reality 调试 eprintln | 诊断探针流入产品代码 | **P-E 探针入库** |
| `0db20bb` → `f28eba2` | XorConn 全流量 XOR → 按 Go header-only 语义重写 | 首版翻译语义发散（层次/顺序错），互通必败后重写 | **P-F 语义发散重写** |
| `fe24ef5` | 集成测试驱动形态修复（非代码回退） | Windows loopback TCP 病理误判为代码缺陷 | （判定纪律佐证: 挂死≠代码错） |

### 3.2 模式归纳与现存同类隐患

| 模式 | 历史教训 | 现存同类隐患（本轮实测） | 处置建议 |
|---|---|---|---|
| **P-A 症状抑制/降级绕过** | disable-trigger workaround 两次往返，真根因三个月后才修 | ① splithttp obfs 校验短路（handler.rs:377，本轮 P2 新立案）② dokodemo Unix→TCP 降级 ③ Udp443Policy 非法值降级 None 且无日志（F-W12 已证 Go 为启动硬错）④ dns jsonconf 域名 NS 跳过——四处全是"运行期降级绕过而非 fail-fast" | 统一收敛为 **Build 期硬错或显式 warn**（对齐 Go 诊断体验），防"绕过→再踩→再回退"循环 |
| **P-B 组合层未验证** | splithttp×btls 400 回退 | QUIC DATAGRAM 承载面三连: gRPC multiMode 截断（R2）/ hysteria TP 断裂（R1）/ tuic native 无分片——同一承载面反复暴露兼容缺陷 | 新传输组合落地前强制 **Go↔Rust 双向 bulk 用例**；DATAGRAM 面三项修一赔二 |
| **P-C 无验证不落地** | v29 子代理补丁 / 双 agent 重复引入同一 workaround | 流程性风险: 多子代理并行批次无共享"已回退清单"（v31 两次 revert 即两批撞车） | 已回退的 workaround 进 bd/记忆黑名单（现 memory 已有"Debunked"节，保持更新） |
| **P-D 性能特性无测试阶梯** | v49 splice 挂死回退 | 本轮表二 5 项高危前置（ENC 缩锁/writev/CommonConn/finalmask/mux wrap）同模式 | 强制阶梯: 单测→stress(duplex 512KB)→interop→32 节点，逐级通过才合 |
| **P-E 探针入库** | v26 eprintln 回退、335dc80 清理、v49 探针时序副作用 | **btls_reality.rs:245 `[REALITY dbg]` eprintln 残留（本轮 P2 新立案）**；全仓复查: 生产代码仅此一处，其余均在 CLI 输出/build.rs/`#[cfg(test)]`/tests/ | 删除该行；CI 加 `eprintln!(` 生产区扫描（排除 cli/build.rs） |
| **P-F 语义发散重写** | XorConn 两轮回退后按 Go 同构重写 + 逐字节 fixture | 无新增（v54 后无同族）；ENC/xpadding 尚无等价 fixture 机制 | 推广 `xor_conn_go_fixture.txt` 模式: 凡手写协议状态机配 Go 官方库生成真值 fixture |

### 3.3 回退考古与本次建议的一致性核对

- 唯一正向性能提交 `b069b1a`（bridge/inbound 接入分层池）**未被回退**——表二池化类建议与其同向不冲突。
- v50（poll_write 裸 Pending）/v51（TLS dirty 状态机）/v54（xor header-only 重写）三个根治点经 concurrency.md 复查**无回归**——表二 #9/#14/#16 的"高危前置"正是为了避免在这三个文件上制造第四次回退。
- beads 检索（`BD_IGNORE_SCHEMA_SKEW=1`）: 无失败/回退的优化任务记录；"回退"仅命中 S1 与 uTLS 指纹两条在办 issue。
- 前两轮 38 项 P0/P1 修复建议与 7 起回退事件逐条对照: **无一条与历史回退根因同源**（最接近的 #16/#18 已单独标记高危前置）。

---

## 四、确认干净项清单（抽查点证据）

1. **无注释掉的生产代码**: 全仓 `^\s*// (let|if|return|match|self\.|tokio::spawn|for|fn|pub fn)` 扫描唯一命中为 reverse worker.rs:413 的解释性注释（讲 guard 释放原因），非注释代码。
2. **调试打印生产残留仅 1 处**: `eprintln!/println!` 全仓扫描，命中 = xray-cli（CLI 合法输出）、build.rs（cargo 协议输出）、tests//`#[cfg(test)]`（合法），唯 btls_reality.rs:245 越界（已立案 P2）。v26 前科未在 vless/encryption 复发（该处干净）。
3. **DNS singleflight 实现正确**: cached.rs:103-132 与 Go 语义对齐（leader 崩溃自愈、广播窗口无丢失，concurrency.md 复核一致）；仅注释烂账（C 类已立案）。
4. **beads 无负优化前科**: `bd search 优化` 零命中失败任务。
5. **池化底盘健康**: alloc 三级回退、pipe 整体移交零拷贝、merge 走 ManuallyDrop（performance.md 1.1 抽审确认），`b069b1a` 未回退。
6. **v50/v51/v54 根治点无回归**: poll_write continue 语义、TLS dirty 状态机、xor header-only + fixture 单测均在位（concurrency.md §已核查 + 本轮 spot check）。
7. **表二 38 项修复建议无一与历史回退同源**（3.3 节）。
8. **妥协注释整体质量高**: 144 处 ponytail 注释绝大多数同时给出升级路径与适用边界（如 weak_cache.rs 自辩有理、ss server.rs:182 保守方向正确），文档化纪律本身是正向资产——本轮新立案的 23 条是其中真正欠账的部分。

## 五、审计限制

- 静态审计 + git/beads 考古，未运行 benchmark；表二"性能回退风险"为代码路径推导，落地时以测量为准（铁律#1）。
- `docs/audit/timeouts.md` 缺失导致 T1-T3 细节仅能依据 AUDIT_SUMMARY 摘要预审（三条均为低风险加限幅/加超时类，不受影响）。
- ponytail 注释 144 处全部回收，逐条定级基于现场代码 + Go 对照；app 类 crate（proxyman 平行世界等）stub 类妥协未逐条立案（非生产路径，completeness.md §8 已汇总）。
