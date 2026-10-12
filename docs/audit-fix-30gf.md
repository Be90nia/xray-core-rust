# audit-fix-30gf：真实 WAN 残留塌缩——发送侧源码审计（2026-10-08）

**结论：TCP 发送侧 SO_SNDBUF 在 rust 全仓零设置（字段存在但 TCP 路径不消费），Go
SocketConfig 全字段亦无任何缓冲设置——两栈同裸跑内核 tcp_wmem autotune。服务端
WAN 面（accept 出的连接）发送缓冲 = 内核缺省 tcp_wmem[1]≈16KB（记账 32KB），
250ms RTT 下 sndbuf 封顶吞吐 ≈ 32KB/0.25s = 128KB/s，与实测塌缩带 30-120KB/s
上缘吻合；autotune 扩展（tcp_sndbuf_expand → cwnd×MSS×2，上限 wmem[2]=4MB）在
持续队列满 + ACK 释放条件下应触发但实测未稳定生效——rust/Go 写模式差异
（阻塞 sendmsg 常驻重灌 vs WouldBlock+就绪事件重灌）是否影响扩展唤醒，待
VisionMac5 的 netem 250ms 20 轮判别实验采样 skmem 轨迹终裁。**

VERDICT: PASS（审计交付；实现按闸门挂起——复现确认后按 §4 预置形态落地）

## 1. 发送侧现状审计（rust 全仓）

- **TCP 路径零 SO_SNDBUF**：`send_buffer_size` 字段存在（sockopt/mod.rs:303-309）
  且 JSON `sendBufferSize` 已解析（dialer.rs:278-282），但字段文档明示「TCP 路径
  不消费；QUIC 系 UDP 端点消费」——唯一消费点 `bind_udp_endpoint` →
  `tune_udp_buffer`（sockopt/mod.rs:641-642，UDP 专用）。
- `apply_outbound_socket_options`（:411+）与 `apply_inbound_socket_options`
  （:511+）只设 RCVBUF（88m0/3e755458 的 4MB 缺省）+ NODELAY/KEEPALIVE/平台项，
  **无任何 SNDBUF 设置**。
- 88m0 修复（3e755458）只覆盖收侧：出站拨号（客户端 WAN 面=下载收侧）4MB；
  **服务端 accept 面（下载发侧）未覆盖——正是本票镜像缺口**。

## 2. 服务端 WAN 面 socket 创建与写路径（file:line）

- 创建：`InboundTcpListener`（system_listener.rs）accept →
  `apply_inbound_socket_options`（sockopt/mod.rs:511）——nodelay/keepalive/
  RCVBUF 4MB/平台项；无 SNDBUF。
- 写路径：bridge `down_writer`（xray-transport/bridge.rs:444+，p7lm 分节）→
  `link.writer` = SequentialWriter（xray-buf/writer.rs:40-77，is_write_vectored
  时 `write_vectored_all` 聚合）→ WriteHalf → VisionConn
  `poll_write_vectored` branch 2（End/Direct commit 后直写）→ rustls
  `poll_write_vectored` → `write_io`（SyncWriteAdapter → tokio TcpStream
  非阻塞 send，WouldBlock 即返回，尾巴滞留 sendable_tls 无界缓冲）。

## 3. Go 基线对照

- Go `SocketConfig` 全字段核对（infra/conf/transport_sockopt.go + config.pb.go）：
  Mark/TFO/TProxy/AcceptProxyProtocol/DomainStrategy/DialerProxy/TCPKeepAlive×2/
  TCPCongestion/TCPWindowClamp/TCPMaxSeg/Penetrate/TCPUserTimeout/V6only/
  Interface/TcpMptcp/CustomSockopt/AddressPortStrategy/HappyEyeballs/
  TrustedXForwardedFor——**无 send/receive buffer 字段**；transport/internet
  sockopt_*.go 全目录无 SO_SNDBUF/SO_RCVBUF 引用（唯一 SendBufferSize 命中在
  proxy/tun gvisor 用户态栈，不适用真实 TCP）。
- 即：**两栈真实 TCP 同为内核 autotune 裸跑**，差异不在配置而在写模式/调度：
  - Go：bufio.BufferedWriter 按 2KB Buffer 满即 flush → tls.Conn.Write(≤2KB
    记录，可 16KB 合并) → conn.Write **阻塞式 sendmsg**——sndbuf 满时 goroutine
    常驻内核写路径，每 ACK 释放即刻重灌。
  - rust：WouldBlock → 尾巴滞留 sendable_tls → WRITABLE 就绪事件 + 任务调度后
    重灌（write_io 每次 poll 贪排到 EAGAIN）。两者对内核 sndbuf 扩展
    （tcp_sndbuf_expand：cwnd×MSS×2，上限 tcp_wmem[2]）的喂压形态等价，
    差异在重灌延迟（阻塞唤醒 vs 就绪事件）。
- 数值吻合：Linux tcp_wmem 缺省 [4KB, 16KB, 4MB] → 初始 sk_sndbuf 记账 32KB；
  250ms RTT 封顶 ≈ 128KB/s——实测塌缩带 30-120KB/s 上缘正落于此；下缘 30KB/s
  ≈ 更小有效窗（+loss 收缩）。**sndbuf 扩展未稳定生效的机理需 skmem 轨迹采样
  确认（expand 的 ACK 驱动条件在 netem 250ms 下是否被饿）**。

## 4. 预置修复形态（闸门=复现确认；未实施）

复刻 862340ff/3e755458 范式三件套（闸门通过后落地）：

1. sockopt/mod.rs 新增 `TCP_SNDBUF_DEFAULT: i32 = 4MiB`（机理文档：WAN 高 RTT
   发送窗 autotune 唤醒不可靠，显式 4MB = 记账上限非预分配；4MB/0.25s =
   16MB/s 远超任何观测速率，无过配风险；SO_SNDBUF 显式设置同样锁定 wmem
   autotune——与 RCVBUF 同代价模型）。
2. `apply_outbound_socket_options` / `apply_inbound_socket_options`：SO_SNDBUF
   缺省 4MB、显式 `sendBufferSize` 优先（JSON 字段已存在，TCP 路径开始消费，
   注释同步）。
3. 测试三件套：缺省 4MB 断言 + 显式优先回归锁 + 旧契约改写（同 88m0 形态）。

副作用评估：显式 SO_SNDBUF 锁定 autotune 后，sndbuf 恒 4MB×2 记账——对低 RTT
路径无影响（缓冲非预分配）；对 >4MB/RTT 的极端 BDP（RTT>30s）才可能不足，
不存在于现实部署。

## 5. 判别实验需求（VisionMac5，netem delay 250ms loss 50ms × 20 轮）

- 塌缩轮传输中 1s 采样两侧 `ss -tinm`：**skmem 的 sk_sndbuf 字段轨迹**（若钉在
  ~32-64KB 不扩张 = sndbuf 饿死实锤 → §4 落地）；cwnd/ssthresh 同采（若 cwnd
  钉低位 = CC 侧，另判）。
- 健康轮同采样对照。
- 若复现：回贴 3 个样本的 sndbuf/cwnd 轨迹，我即落地 §4（三件套+测试+lib 全绿）。

## 6. 写模式差异深挖（Main §3 转向，2026-10-08 第三轮；纯分析未动代码）

### 6.1 「丢一次 WRITABLE 边沿 → 多等一个 RTT」窗口：结构性不存在

tokio/mio 侧三重防护（io/poll.rs Registration/Readiness 语义）：

1. **waker 先注册后检查**：`poll_write_ready` → `Readiness::poll` 先 set_waker
   再读缓存就绪位——缓存乐观返回 Ready 的路径同样持有 waker。
2. **EAGAIN 清位即自唤醒**：`try_io` 撞 WouldBlock 时 ReadyRef drop →
   clear_readiness 清 WRITE 位并唤醒已注册 waker（强制一次立即重 poll）——
   不存在「清位后无人叫醒」的悬空 Pending。
3. **内核 ET 边沿覆盖满→非满跃迁**：EAGAIN 之后 socket 必然处于 not-writable，
   ACK 释放空间的 writable 跃迁是新边沿，EPOLLET 必投递 → mio 置缓存位 + 唤醒。

结论：**就绪事件层无丢边窗口**，重灌滞后不来自 tokio/mio。rustls 侧返回形态
（common/mod.rs:332-364）`(0,true)→Pending / (n,·)→Ok(n) / (0,false)→continue`
中 `(0,false)` 因 rustls Writer 必消费全量（默认 write_vectored=write(bufs[0])
仍整段消费）实际不可达，无自旋或漏报分支。

### 6.2 真正的 rust/Go 写模式不对称：内核压力连续性

- **Go**：bufio 2KB 满即 flush → tls.Conn.Write → conn.Write **阻塞式 sendmsg**
  ——sndbuf 满时 goroutine 停在内核 sendmsg 内部，每 ACK 释放空间即刻原地重灌，
  **应用层零间隙**，内核「队列持续顶满」→ tcp_sndbuf_expand（cwnd×MSS×2，上限
  wmem[2]=4MB）按 ACK 节律稳定触发。
- **rust**：write_io 贪排至 EAGAIN 后尾巴滞留 sendable_tls（无界用户态缓冲），
  重灌 = WRITABLE 事件 → 任务调度 → 再 poll。重灌间隙 = 事件延迟 + 上游泵节律
  （down_reader origin 读 / mpsc / tokio 调度预算）的叠加。**间隙期间内核队列
  排空、writer「安静」**——若 quiet 段横跨 loss 收缩后的恢复期，sndbuf 扩展的
  「持续队列满」前提被稀释，autotune 可能停在 wmem[1]（16KB→记账 32KB）。
- 数值闭环：记账 32KB / 250ms = 128KB/s（塌缩带上缘）；loss 收缩期更小窗 →
  30KB/s 下缘。**death 轮 30-120KB/s 与「sndbuf 钉 wmem[1] 档」全谱吻合。**
- sendable_tls vs Go bufio 的 loss 期对比（子问 2）：loss/乱序期收端窗口收缩
  或零窗时，rustls sendable_tls 无界积压（应用侧永不阻塞），Go 侧 bufio+pipe
  反压到 origin 泵——**恢复喂压时机 rust 不劣于 Go**（积压即蓄洪）；差异不在
  loss 期，而在 §6.2 的稳态重灌连续性。

### 6.3 机理判别式与修复映射

VisionMac5 的 death 轮 sndbuf/cwnd 轨迹二分：
- **sk_sndbuf 钉 ~32-64KB 不扩张** → §6.2 autotune 饿死实锤 → §4 预置三件套
  （TCP_SNDBUF_DEFAULT 4MB，显式锁定免掷签）直接落地——同时把重灌连续性
  依赖归零（缓冲恒满额，间隙无关紧要）。
- **sk_sndbuf 已扩（≥wmem[2] 档）而 cwnd 钉低** → CC/loss 侧，写泵方向出票
  转网络判定路径。
- 混合形态（sndbuf 中位振荡）→ §6.2 重灌间隙参与度量化（trace burst gap vs
  writable 事件延迟）。

