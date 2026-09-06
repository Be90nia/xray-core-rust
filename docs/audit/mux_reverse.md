# mux/XUDP 帧字节级 + reverse 协议审计 (mux_reverse)

> 审计: 2026-09-06 第四轮剩余切面 | 方法: 帧字节级对照 Go 基准 v26.7.28 (common/mux + app/reverse + proxy/vless reverse)
> 结论: **帧线格式/Control proto 字节级兼容,portal 侧握手与决策参数逐项对齐;发现服务端会话管理 2 处结构性缺陷(泄漏 + XUDP 装配断裂)、客户端缺 writeFirstPayload(服务端先说协议挂死)、XUDP GlobalID 客户端链未接线**
> 严重度统计: P0×0 | P1×4 | P2×4 | P3×4

## Go 基准

- 帧格式: `len(2B BE)+sessionID(2B BE)+status(1B)+option(1B)+[New: network(1B)+port(2B BE)+addr(PortThenAddress)]+[reverse: Source/Local]+[GlobalID 8B]` (common/mux/frame.go:53-108,215-221)
- 状态机: New/Keep/End/KeepAlive=0x01-0x04 (frame.go:19-28);客户端首帧 New 其后 Keep(followup),End 关闭,hasError 置 OptionError (writer.go:46-71,125-136)
- 客户端: writeFirstPayload 100ms 无首包发空 New (client.go:246-249,276);IsFull 并发用 Size() 累计用 Count() (client.go:289-305);SessionManager Allocate/Add/Remove (session.go:55-95)
- 服务端: New→dispatch(XUDP GlobalID 命中→复用旧 mux 管道,server.go:196-277);未知 Keep→回 End+丢弃 (server.go:299-305);60s monitor 空闲关 worker (server.go:152-172)
- XUDP: 全局 Manager+init goroutine 只清 Expiring 过期 (session.go:192-249);GetGlobalID 写入 New 帧 (client.go:271)
- reverse: Control proto `state=1/random=99` (app/reverse/config.proto);bridge 2s monitor 0 worker||avg>16 建 (bridge.go:68-91);portal heartbeat 2s,counter=(c+1)%5,仅 drain(>256)‖counter==1 发送 (portal.go:268-300);picker 两遍最少连接 (portal.go:170-198)
- VLESS reverse(v26 新): bridge 侧 outbound Reverse.monitor 建 mux ServerWorker(IsReverseMux)+经 handler.Process 发 command=Rvs (proxy/vless/outbound/outbound.go:436-478);portal 侧 inbound GetReverse(account)→mux ClientWorker+PortalWorker (inbound/inbound.go:625-668);**reverse 用户禁止 forward proxy** (inbound.go:542-544);New 帧编解码 Inbound.Source/Local 仅 reverse 方向 (frame.go:100-130,155-200)

## P1 发现

### MR1 [P1] mux 服务端 session 永不移除:SessionManager::add 的 Arc::get_mut 在全部生产调用点恒失败 | crates/xray-mux/src/session.rs:531-545

- 证据: `add(&self, mut session: Arc<Session>)` 内 `if let Some(s) = Arc::get_mut(&mut session) { s.set_parent(...) }`(session.rs:542-544)。两个生产调用点均传 `session.clone()` 且调用方仍持有原 Arc(handle_normal_new worker.rs:252、handle_xudp_new worker.rs:314),引用计数 ≥2 → `Arc::get_mut` 恒返回 None → **parent 弱引用从未设置** → `Session::close` 中 `if let Some(shared) = self.parent.upgrade()`(session.rs:311-316)恒 None → sessions map 条目永不删除
- 对照 Go: parent 在构造时即绑定 `Session{parent: w.sessionManager}`(server.go:180,session.go:66-68),Close→parent.Remove(session.go:192-213)必达
- 影响: 服务端 carrier 上每条子连接泄漏一个 Session(Arc+锁+读写端)常驻 map;①内存随连接数无界增长 ②已关 session 仍在 map,后续 Keep 帧写进死 session 的 writer 被静默丢弃(客户端等不到任何反馈) ③`active_sessions()`(session.rs:632-635)每 30s 克隆全量含死 session ④reverse BridgeWorker::connections 统计虚高,monitor 扩缩决策失真
- 修复: add 改为在 caller 持 Arc::get_mut 可变窗口内 set_parent(handle_normal_new 在 `Arc::new` 后、首个 clone 前 set),或 Session 用 `OnceLock<Weak<...>>`/构造传 parent;两条路径同步修
- 负优化自查: 纯修复错误路径,无新增运行时开销;勿为绕过引入每帧全局锁

### MR2 [P1] mux 客户端缺 writeFirstPayload:服务端先说协议(SSH/FTP/SMTP banner)经 mux 永久挂死 | crates/xray-mux/src/client.rs:356-374

- 证据: fetch_input 直接阻塞 `reader.read_multi_buffer()` 等首包,首包到达才由 MuxWriter 首写发出 New 帧;注释(client.rs:358-363)自称「无首包的 session 不提前注册到对端」等价——不等价。Go fetchInput 先 `writeFirstPayload`:`CopyOnceTimeout(100ms)` 超时即 `writer.WriteMultiBuffer(buf.MultiBuffer{})` → writeMetaOnly 发**无数据 New 帧**(client.go:246-249,276)→ 服务端立即 dispatch 目标并开始泵上行数据
- 影响: 凡服务端先发字节的 TCP 协议(SSH banner、FTP 220、SMTP 220、IMAP greeting)经 mux:客户端无首包→New 永不发→服务端永不 dispatch→banner 永不到达→应用层超时挂死。Rust↔Rust 与 Rust 客户端↔Go 服务端同样命中
- 修复: fetch_input 循环前对首读包 `tokio::time::timeout(100ms)`,超时调用 `writer.write(MultiBuffer::new())`(write 空 mb→write_meta_only→New)再进主循环;约 8 行
- 负优化自查: 仅在 100ms 无首包时多发 1 帧 ~6B 元数据;有首包路径零变化;勿改为「New 先行、数据后补」的无条件两帧(会多一帧每连接)

### MR3 [P1] XUDP 服务端会话装配断裂:真实 I/O 绑到孤儿对象,manager 会话立即回 End | crates/xray-mux/src/worker.rs:295-318

- 证据: handle_xudp_new 把 dispatch 返回的 link 绑到 `ms`(worker.rs:295-296 set_input,:310 set_output,:311 xudp.set_mux),而加入 manager 并 spawn `handle_session_output` 的是另一个**空壳** `session`(worker.rs:312-318,从未 set_input/set_output)。handle_session_output 首轮 `let Some(reader) = input.as_mut() else { break }`(worker.rs:342)即 break → `rw.close()` 立即向客户端发 End → session.close。`ms` 无任何泵任务,其 input(上游响应)永不读出
- 对照 Go: 单个 Session 双向绑定 `Session{input: link.Reader, output: link.Writer}`+`go handle()` 泵(server.go:240-277),XUDP 命中也是同管道重挂(server.go:234-238)
- 影响: 任何带 GlobalID 的 XUDP New 帧(Go 客户端 mux+UDP 会带):首包内联数据转发成功(bd 6z8 测试只覆盖这一步)后客户端立刻收到 End,UDP 会话被拆;后续 Keep 数据写入已死会话被丢弃;上游回包滞留 ms 管道直到连接断开。**Rust 服务端 XUDP 端到端完全不可用**
- 修复: 删除 ms,直接 `session.set_input/set_output(dispatch link)`,`xudp.set_mux(&session)`,其余逻辑不变(约 -6 行)
- 负优化自查: 少一个 Session 分配,正向;修复后注意勿动「Packet 直写禁缓冲」语义

### MR4 [P1] XUDP GlobalID 客户端链未接线:生产恒传 None,global_id() 全仓零生产调用 | crates/xray-mux/src/client.rs:374-380

- 证据: fetch_input 构造 `MuxWriter::new(session.id(), dest, ..., None)` 硬编码(client.rs:374-380);`xray_xudp::global_id(&GlobalIdInput)` 全仓仅 xray-xudp 自身测试引用(grep 坐实);vless handler.rs MuxState 有 xudp_concurrency 解析但未接 GlobalID 生成。对照 Go fetchInput `NewWriter(s.ID, ob.Target, output, transferType, xudp.GetGlobalID(ctx), inbound)`(client.go:271)
- 影响: Rust 作为 mux+UDP 客户端永远不发 GlobalID → ①XUDP 跨 carrier 保 NAT 会话(UDP 源端口不变)的核心能力缺失,复用退化为每连接新上游 ②服务端 XUDP 路径(global_id gate,worker.rs:412-415)对 Rust↔Rust 不可达,仅 Go 客户端可触达(并命中 MR3)
- 修复: fetch_input 对 UDP dest 且 xudp 启用/cone 时以入站源计算 GlobalID 传入(需把入站源穿过 dispatch ctx,对齐 Go GlobalIdInput{source,cone})
- 负优化自查: 每 UDP session 一次 hash,可忽略;cone=false 保持 None(对齐 Go 返回全零即跳过)

## P2 发现

### MR5 [P2] XUDP hit 路径不复用旧上游:同 GlobalID 无条件重新 dispatch | crates/xray-mux/src/worker.rs:285-291

- 证据: hit 分支仅改状态后照常 `self.dispatcher.dispatch(target)` 建新链路;ponytail 注释自认「流身份不保留」(worker.rs:299-302)。Go hit 写 `x.Mux.output.WriteMultiBuffer(mb)` 继续用**旧** UDP 管道并以新 SessionID 重挂同管道(server.go:206-240)——这是 XUDP 存在的意义(跨 mux carrier 重连保持上游 NAT 映射)
- 影响: carrier 重连后同 GlobalID 得到新上游 socket,QUIC 连接 ID/源端口漂移,对端会话中断;被替换的旧 link 无 close,泄漏;叠加已知 worker.rs:276 clone 问题(manager entry 恒 Initializing)状态机进一步失真
- 修复: hit 分支改为写旧 xudp.mux 的 output 并以新 id 重绑;避免 dispatch
- 负优化自查: 复用省一次拨号,正向

### MR6 [P2] XUDPManager::start_cleanup 零调用:Expiring 条目永不回收 | crates/xray-mux/src/session.rs:685-719

- 证据: `start_cleanup(&mut self)` 全仓无调用方(grep 坐实);ServerWorker::new 以 `XUDPManager::new()` 构造(worker.rs:88-89)后无启动。清理过滤仅 `status == Expiring && now >= expire`(session.rs:695-703),Initializing 永不过期
- 对照 Go: 全局 XUDPManager init goroutine 每分钟清 Expiring 过期(session.go:231-249)
- 影响: XUDP 条目 map 只增不减(worker 级,量级小但确为泄漏);MR5 的 Initializing 卡死条目连理论清理路径都没有
- 修复: ServerWorker 构造后 spawn 清理(Manager 内部 entries 已 Arc 化,加 `spawn_cleanup(self: &Arc<Self>)` 即可);兜底把 Initializing 超时(如 5 分钟)也清
- 负优化自查: 60s 周期 O(n) 扫,Go 同款;勿改成每帧检查

### MR7 [P2] 客户端 is_full 并发上限误用累计计数 | crates/xray-mux/src/client.rs:267-273

- 证据: `max_conc > 0 && self.session_manager.count() >= max_conc`——count 是**累计分配数**(含已关闭,session.rs:521-527 注释自明);活跃数应为 size()。Go IsFull: MaxConcurrency→`sm.Size()`(活跃),MaxConnection→`sm.Count()`(累计)(client.go:289-305),两口径分明
- 影响: 用户配 `mux.concurrency=N` 时,worker 累计服务 N 条连接后永久 full,IncrementalWorkerPicker 被迫不断新建 carrier;载体 churn+上游连接数放大。默认策略(0,0)无感,故 32/32 不暴露
- 修复: is_full 并发项换 `size()`;is_closing 保持 count(对齐 Go)
- 负优化自查: size() 走 RwLock 读,与 Go 同锁级;可在 SessionManager 挂原子 active 计数消除(非必须)

### MR8 [P2] VLESS reverse bridge 侧未实现 + frame 层 Source/Local 编解码缺失 + forward-proxy 安全规则缺失 | crates/xray-proxy-vless/src/outbound/reverse.rs:73-118

- 证据: ①ReverseMonitor(target-pending 模型)全仓无生产调用方,with_reverse 仅测试引用(grep 坐实)——Go 是 2s monitor 0worker||avg>16 建 BridgeWorker+mux ServerWorker(IsReverseMux)+handler.Process 发 Rvs(outbound.go:436-478),Rust 无对应循环;②frame.rs parse_body/to_bytes 无 Inbound.Source/Local 编解码(frame.go:100-130 写,155-200 读,仅 IsReverseMux 方向),ServerWorker 无 reverse 模式参数;③Rust inbound 缺 Go `account.Reverse != nil && command != Rvs → 拒绝`(inbound.go:542-544)
- 影响: NAT 侧桥接(核心能力)缺失,portal 侧半成品可用;reverse 用户可无限制正向代理,偏离 Go 安全约束(低危:该用户本就通过认证,但与基准行为偏离)
- 修复: 补 bridge monitor 循环(复用 app-reverse should_create_bridge_worker 决策核)+ServerWorker 增加 read_source_and_local 开关+frame.rs 补 Source/Local 编解码(读侧 `network==0 → padding` 容错照抄)+inbound 补安全规则;ReverseMonitor 决策改 Go 算法
- 负优化自查: Source/Local 仅 reverse 开关下编解码,普通 mux 帧零字节增量;勿把 ~24B Source/Local 塞进常规 New 帧

## P3 发现

### MR9 [P3] 服务端 60s KeepAlive 广播为自创行为,Go 全仓无 KeepAlive 发送方 | crates/xray-mux/src/worker.rs:24-25,169-183

- 证据: spawn_keepalive_and_idle_timeout 每 60s 对每活跃 session 发 KeepAlive;grep Go 全仓 SessionStatusKeepAlive 仅两处容错 handler(client.go:399-403/server.go:344-347),无写入点。对 Go 对端无害(无数据即忽略);且 Rust 服务端缺 Go 60s `CloseIfNoSessionAndIdle` 全局空闲关 worker(server.go:152-172),空载 carrier 永不关
- 修复: 删广播,补 worker 级 idle-close(对齐 Go monitor);或保留但注明 Rust 扩展
- 负优化自查: 删除即省带宽;补 idle-close 注意与 MR1(死 session 常驻)叠加的 checkSize 快照语义

### MR10 [P3] 服务端 Keep 未知 session 不回 End(与客户端侧实现不对称) | crates/xray-mux/src/worker.rs:429-442

- 证据: `None => return Ok(())` 静默丢;Go server.go:299-305 未知 session 回 End 帧+丢弃。Rust 客户端侧已实现同款(client.rs:462-468),两侧不一致
- 影响: 对端(尤其 Go 客户端)向已回收 session 发 Keep 后收不到关闭通知,只能靠自身超时;MR1 修复后此路径出现频率上升
- 修复: 对齐客户端:ResponseWriter close 经 SharedWriter 发 End
- 负优化自查: 每未知 Keep 多一帧 End(异常路径),正常路径零影响

### MR11 [P3] mux reader.rs StreamReader/PacketReader 为死代码,且常量与主路径不一致 | crates/xray-mux/src/reader.rs:23-31,64-65

- 证据: 生产读路径=client.rs read_frame/worker.rs process_frame,reader.rs 无生产调用方(grep 坐实);reader.rs:65 允许 meta_len≤1024 而主路径/Go 为 512
- 修复: 删除或收敛为唯一帧读取实现(推荐删)
- 负优化自查: 删死代码无风险;若保留务必统一 512

### MR12 [P3] reverse picker 最少连接用累计数,退化为「最旧优先」 | crates/xray-app-reverse/src/worker.rs:296-300

- 证据: PortalWorker::active_connections 返回 `session_count()`(累计),注释自认近似;Go portal.go:190-206 用 `client.ActiveConnections()`(活跃 Size)
- 影响: 多 worker 负载不均(新 worker 吃到全部新连接直到累计反超);drain 阈值(>256 累计)不受影响(Go 同为 TotalConnections)
- 修复: SessionManager 增原子 active 计数(与 MR7 同一处修复可共用)
- 负优化自查: 原子计数 fetch_sub 于 close,零争用风险

## 注记

- crates/xray-app-reverse/src/relay.rs 是 yamux 平行实现(线格式非 Go reverse 协议),仅被自身测试与 tests/reverse_e2e.rs 消费,未接入生产编排——与 app/reverse 主实现并存易误认,建议后续裁决去留
- 已知勿重报项核对: worker.rs:276 XUDP clone(status 不回写 manager)未重复报告,仅在 MR5/MR6 作为叠加因素引用;client.rs:151 pick 穿透(production ClientManager.dispatch 永不建 worker,仅 handler.rs 测试路径用 pick_internal)未重复报告

## 确认干净项(字节级抽查证据)

- 帧线格式四要素: len/sessionID 大端 2B、status 1B(1-4)、option 位(0x01 Data/0x02 Error)——frame.rs:437-499,529-570 vs Go frame.go:59-108;`test_wire_format_new_tcp_ipv4` 逐字节断言(frame.rs:829-862)✓
- 地址序列化 PortThenAddress: network(1B TCP=0x01/UDP=0x02)+port(2B BE)+addr(1=4B v4/2=len+domain/3=16B v6)双侧一致(frame.rs:205-229 vs frame.go:43-49)✓
- MAX metadata 512 双侧一致(frame.rs:44 vs frame.go:96),超限即拒 ✓
- GlobalID 帧条件逐条一致: 写=New+UDP target(frame.rs:494-499),读=New+Data+UDP+剩余≥8B 才拷贝(frame.rs:600-607 vs frame.go:216-221,含「不足 8B 静默不解析」)✓
- Keep+UDP target「先查第 5 字节标志再解析」(frame.rs:609-615 vs frame.go:156-158 注释 MUST check the flag first)✓
- 数据帧 2B payload 长度前缀+流式 8KB 分块+包式单 buffer 逐帧(writer.rs:180-206,224-240 vs Go writer.go:83-118)✓
- End 帧 hasError→OptionError(writer.rs:207-228 vs Go writer.go:125-136);读错误 set_error→End 带错(worker.rs:358-360)✓
- PacketReader 包长上限 8192=Go buf.Size(reader.rs:19 vs reader.go:71-77,buf/buffer.go:13 Size=8192)——早期疑点「Rust 8192 vs Go 2048」已证伪 ✓
- 客户端 picker swap-to-tail/两遍选择(client.rs:151-206 vs Go client.go:74-112)语义对齐(生产 bootstrap 缺口属已知 151 号)✓
- SessionManager allocate 计数上限/CloseIfNoSessionAndIdle 三条件(session.rs:495-515,590-615 vs Go session.go:55-77,120-140)✓
- DialingWorkerFactory: 64KB×2 pipe、carrier/worker 双向终结 select(client.rs:640-688 vs Go client.go:138-169)✓
- reverse Control proto 字段号 state=1/random=99 与 Go 逐字节兼容(protos/app/reverse/config.proto vs Go app/reverse/config.proto);prost encode/decode 对位;fill_in_random 1..=64 对齐 FillInRandom(config.rs:67-80)✓
- bridge 内部域判定 `reverse`、dispatch domain:0/TCP 建 carrier、控制流逐 Buffer 解析+解析失败终止+EOF 分支 0/24h 存活窗(worker.rs:340-345,438-475 vs Go bridge.go:69-73,165-196)✓
- portal heartbeat 决策核: drain>256、counter=(c+1)%5、should_send=drain||counter==1、drain 后一次性终止(worker.rs:70-97,249-283 vs portal.go:268-300)✓
- bridge monitor 决策核 worker==0||avg>16,边界 17/32 有测试钉住(bridge.rs:66-70,430-445 vs Go bridge.go:88)✓
- portal 侧 per-user reverse.tag 路由且禁 fallback(inbound/server.rs:579-600 vs Go inbound.go:198-216);Rvs command=0x04+固定域 v1.rvs.cool+无地址字段(encoding/mod.rs:44-92 vs Go headers.go:18,encoding.go:117-118)✓
- picker 两遍选择语义(先跳 draining 后允许)与 Go portal.go:170-198 一致,空表/全满错误分支齐全(picker.rs:68-110)✓
