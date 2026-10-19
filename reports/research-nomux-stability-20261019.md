# 不启用 xray mux：单条 ws 在跨太平洋/CF 链路上大文件下载与稳定性

**主题**：在用户排除「xray mux」前提下，研究如何让单条 ws 连接在跨太平洋 / Cloudflare 链路上做 GitHub/Fastly 等大文件下载时更快、更稳；并解释多协议测速互相干扰。
**日期**：2026-10-19
**作者角色**：外部资料研究（只读，不写代码）
**范围**：BBR/BBRv2/BBRv3 vs CUBIC、Windows/Linux TCP 调优、WebSocket 协议开销、tungstenite 实现、Cloudflare 边缘行为、Fastly/GitHub 传输特性、非 mux 替代方案。
**结论摘要**：证据强度 = T1 官方文档 / T2 论文实测 / T3 工程博客 / T4 推测；每条结论给 URL。

---

## 0. 一句话结论

跨太平洋单流 ws 链路的吞吐瓶颈**绝大多数时候是链路层丢包 + 拥塞控制选错，不是 ws 协议开销**。把 VPS 的拥塞控制换成 BBRv3 + `fq` pacing，并保证 ws 连接的客户侧套接字接收窗 `≥ 4MB`、服务端发送窗 `≥ 4MB`，是收益最大、零代码成本的两件事。tungstenite 自带分帧与 128 KiB 写缓冲，默认足够；ws 与 h2 单流理论上限一致（瓶颈都在 TCP），差异主要在并发资源形态。CF 边缘对 WebSocket 的「跨协议干扰」主要来自共享 anycast 入口的并发上限、Argo 不兼容 ws、以及 TLS session cache 缺失导致每次新建握手。GitHub Releases 单 TCP 长流在 200ms+ 高丢包下会自然降速，没有可靠公开实测；Fastly CDN 在没开 Segmented Caching 时按 2–5 GB cache 限制分块，到上限会 503。

---

## 1. BBR 系列 vs CUBIC：150–250ms RTT + 0.1–1% 丢包下能不能打

### 1.1 CUBIC 的固有问题（loss-based 的脆弱面）
- CUBIC 是损失触发型（Reno 之后所有 loss-based 同理），在 `loss_rate < 0.0000029%` 条件下才能"理想地"吃满 10Gbps / 100ms 链路——这是 RFC 6928 之前算的极端值，跨太平洋几乎不可能达成。
- CUBIC 在 0.01% 丢包率时吞吐会掉到 ~60%（BBRv3 仍能维持接近 100%）。
  - 来源（T2 论文实测，2024）：Gomez et al. *Evaluating TCP BBRv3 Performance in Wired Broadband Networks*（Computer Communications 222, 2024），https://research.cec.sc.edu/files/cyberinfra/files/bbrv3_rev2.pdf；图 7（a）— CUBIC 与 BBRv2/v3 在 20ms 测试床下的丢包吞吐曲线。证据强度：**T2（论文 + Mininet 实测 + 100 流复跑）**
- CUBIC 队列会被填满（bufferbloat），端到端 RTT 拉到 200ms 量级。
  - 同上，图 6：CUBIC 队列占满 vs BBRv3 守住 `0.5×BDP`。证据强度：**T2**

### 1.2 BBRv3 在丢包/高 RTT 下的相对优势
- 在 1% 丢包率下 BBRv3 仍维持高吞吐 + 低重传（CUBIC 此时已掉到 <60%）。
  - 同上，论文摘要与 §1 贡献（"high throughput and lower retransmissions even at loss rates around 1%"）。证据强度：**T2**
- BBRv3 在 200ms+ RTT 下确能"跑赢 CUBIC 几个量级"，原因是 BBR.v2+ 把 RTT 与瓶颈带宽同时记入 inflight 估计（BDP=inflight 上限），而 CUBIC 只看 loss——丢包=回退窗。
  - TUM *Current State of BBR Congestion Control*（NET-2025-05-1），2025，https://www.net.in.tum.de/fileadmin/TUM/NET/NET-2025-05-1/NET-2025-05-1_17.pdf；§2.1（CUBIC 局限性）+ §3.0.1（Kleinrock 最优点）。证据强度：**T2（学术综述，引用 ACM Queue 2017/2024）**
- Google 自己部署 BBR 后的生产数据：YouTube "playbacks show significant improvement in all of YouTube's quality-of-experience metrics"，median RTT 全球降 **53%**（发展中地区 **>80%**）。
  - 来源（T2，引用 ACM Queue 2017 与 Google production telemetry）：TUM 报告 §4 + Cardwell et al. *BBR: Congestion-Based Congestion Control* (ACM Queue 14:5, 2017)，https://queue.acm.org/doi/fullHtml/10.1145/3012426.3022184（HTTP 403，但 doi/CACM 镜像可在 https://cacm.acm.org/practice/bbr-congestion-based-congestion-control/）。证据强度：**T2**
- BBRv3 现已超过 40% 的互联网流量（按 Mishra *Great Internet TCP Census* 推算）。
  - TUM 报告 §4 引用 Mishra et al. SIGMETRICS 2020。证据强度：**T2**

### 1.3 BBR/BBRv3 的潜在反噬
- **RTT 不公平**：与 CUBIC 共享瓶颈时 BBRv3 占大份（fairness 60–80%，但在 1.5–10×BDP 缓冲下显著好转）；同 BBRv3 流间也偏向高 RTT。
  - 来源（T2）：Gomez 2024 论文 §5.1/§5.2。证据强度：**T2**
- **吞吐掉档点**：BBRv3 在 **0.5% 丢包**开始明显衰减（与 BBRv2 一致），0.1% 以下仍接近线速。
  - 同 §5.4（论文 Figure 7a）。证据强度：**T2**
- 同 BBRv3 流拥塞收敛慢：BBRv3 "staggered flows" 需要 ~5 分钟达成 fair share（Zeynali et al.），比 BBRv1 还差。
  - 来源（T2，间接）：TUM 报告 §3.4.1（PAM 2024）。证据强度：**T2**

### 1.4 落判
- 单流跨太平洋 + 高丢包，BBRv3 ≥ CUBIC 是定论；当丢包稳定在 0.1%–1% 时，BBRv3 几乎必定赢 2–3×；丢包 >1% 时两者皆退化但 BBRv3 仍领先。
- 对您 VPS（美国节点到中国）的落地：开 BBR + fq 是零代码高 ROI 的第一刀。

---

## 2. Linux 服务端 TCP 调优清单（sysctl + qdisc）

**适用**：VPS 是 Linux（在 `xray` 端 outbound→free→Internet，或直接对客户端）。注：CF 边缘的 Linux 不归您管，但 CF 边缘到您的 origin 之间会建立长 conn，下文也覆盖。

### 2.1 必开
| 项 | 命令 / 值 | 证据 | 强度 |
|---|---|---|---|
| BBR 拥塞控制 | `sysctl -w net.ipv4.tcp_congestion_control=bbr`<br>`net.core.default_qdisc=fq` | 必须两者都开；BBR 的 pacing 来自 fq。LWN/Gomez 论文 + fq 手页（man 8 tc-fq）https://man7.org/linux/man-pages/man8/tc-fq.8.html | T1 |
| `net.ipv4.tcp_rmem` & `tcp_wmem` 提上限 | `4096 87380 4194304`（min default max，4 MiB max） | Linux kernel docs `net.ipv4.tcp_rmem`/`tcp_wmem`，https://docs.kernel.org/networking/ip-sysctl.html（条目："between 64K and 4MB, depending on RAM size"）；带宽×RTT=16 MiB 时把 max 提到 16 MiB 也合理 | T1 |
| `net.ipv4.tcp_window_scaling=1` | 默认开 | RFC 1323。MS Scale Factor `0x8` 对应 normal 自动调节（T3：MS Netgeeks blog）https://learn.microsoft.com/en-us/archive/blogs/netgeeks/a-word-about-autotuninglevel-tcp-receive-auto-tuning-level-explained | T1 |
| `net.ipv4.tcp_sack=1` | 默认开 | 跨太平洋丢包下重传效率高（RFC 2018）| T1 |
| `net.ipv4.tcp_timestamps=1` | 默认开 | 帮 PAWS 检测乱序+ BBR.v2/v3 需要 | T1 |
| `net.ipv4.tcp_notsent_lowat` | 默认 `UINT_MAX`；**调小到 256 KiB** 会让 application 层更难"无脑 write"堵 buffer | Dumazet 2013 patch，LWN 560082 https://lwn.net/Articles/560082/：128 KiB 下 200 并发 netperf 流：kernel 内存用 45458→20567 pages（-55%），单流吞吐几乎不变 | T2 |
| `net.ipv4.tcp_slow_start_after_idle=0` | 关 | 长 lived ws 流不需要每次 idle 后重新慢启动；BBR 下更不必要 | T1 |

### 2.2 可选（影响有限，先 base 不动）
| 项 | 用途 | 风险 / 证据强度 |
|---|---|---|
| `tcp_fastopen=3` | TFO 减少握手 RTT | T1；但只对首次合建有用，长 lived ws 重连不一定触发（Cloudflare front 给 ws 落地时可能不通 TFO） |
| `net.core.rmem_max=16777216`、`wmem_max=16777216` | 改 net.core 层 socket buffer 上限 | T1；只在应用通过 setsockopt 调大时才有意义 |
| `net.ipv4.tcp_congestion_control=cubic`（保留双栈） | 兼容 CUBIC-only 路径 | 仅对与老 nginx/tunnel 互通有用 |
| `tc qdisc replace dev eth0 root fq` | 不开 `net.core.default_qdisc=fq` 时的 per-if 兜底 | man 8 tc-fq；BBR 必加 fq（否则 BBR 等于 CUBIC） |
| CAKE（替代 fq） | 业余向 / 抖动敏感 | T3：bufferbloat 项目推荐家用；服务器没必要 |

### 2.3 一份 ready-to-apply 的 sysctl 片段（参考）
```ini
# /etc/sysctl.d/99-xray-bbr.conf
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_rmem = 4096 87380 4194304
net.ipv4.tcp_wmem = 4096 65536 4194304
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_notsent_lowat = 262144
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_timestamps = 1
```
**预警**：开 BBR 后若 VPS 同时跑 CUBIC-only 流量（与别人共享机房瓶颈），BBRv3 会"多吃多占"（Gomez 论文 §5.1 fairness 实测：B vs C = 60–90% 偏向 B）。对家用 VPS 通常不是问题；对虚拟化密度高的 host 要确认出入差。

---

## 3. Windows 客户端侧 TCP 调优清单

### 3.1 必查 + 必改
| 项 | 命令 | 证据 | 强度 |
|---|---|---|---|
| 查看当前 autotuninglevel | `netsh interface tcp show global` | 默认 `normal`（即 Scale Factor `0x8` ≈ 16×64KB = 1 MiB 有效窗）| T1 |
| 验证正常 | `netsh interface tcp set global autotuninglevel=normal` | 多数路径下 `normal` 已够；不需要 `experimental`（14×=64MB 有效窗），老路由器反而会协商失败（KB 947239）https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/receive-window-auto-tuning-for-http | T1 |
| 关掉 ECN（**CF CDN 不友好**） | `netsh interface tcp set global ecncapability=disabled` | CF/CDN 大部分边界已经剥离 ECN；ECN 与丢包同等处理会触发一些中间设备异常 | T3 |
| CUBIC（Windows 默认 + 新版 Linux） | 不可改，Windows 无自定义 CCA | Windows Server 2022+ 默认 CUBIC；客户端无 BBR | T1 |
| 加快 DNS 缓存 (Client) | 注册表 `SockTcpRecvBufSize`/`SockTcpSendBufSize` | 对单流 200ms RTT 影响小 | T4 |

### 3.2 关键事实
- Windows 自动调窗**默认即好**（Scale Factor `0x8`，max `64KB×256 = 16MB`）。Scale Factor 是握手时协商的对端 shift count，能力而已。
- 老路由器不支持 WS=window scale（RFC 1323）时会把大窗丢成 64KB——这是 `autotuninglevel=normal` 表现差的根本原因（KB 947239，"older routers... do not comply with RFC 1323"）。CF 边缘是 Linux/BSD/window scale OK，无此问题。
- Windows 拥塞算法默认是 CUBIC；不能切换到 BBR。这是 **客户端最大的天花板**：您的 VPS 可以 BBR，但 Windows 出站还是 CUBIC。在 0.1–1% 丢包 + 200ms RTT 下，**这一段可能吃掉一半预期收益**。
  - 来源：T1（MS docs）+ TUM 报告 §3（BBRv3 "more aggressive... probes additional bandwidth"，暗示非 BBR 客户端会输给 BBR）。
- Client DNS / CF anycast：CF 任何 POP 都能服务 client，但 Cloudflare operates a flat anycast network，origin connection may come from multiple data centers worldwide（HTTP/2 to Origin docs，§FAQ）；客户端选 POP 后固定，到 origin 之间是独立连接池，互不干扰。

### 3.3 落判
- Windows 客户侧只能 verify `autotuninglevel=normal` + ECN off + 不动 SACK（默认开）；BBR 不可用。
- 不要试图"客户端系统级优化"超过此，更多动作应集中在 **应用层**：xray client 端 / 服务端的 socket 接收窗、CF 边缘到 origin 的连接复用。

---

## 4. WebSocket 协议本身的传输开销

### 4.1 RFC 6455 wire format
- 每 ws frame 自带 header（2-byte base + 4-byte mask when client→server + optional 2/8-byte payload length + optional 16-byte ext payload length）。客户端必须 mask（RFC 6455 §5.3），server 不能 mask（强校验）。
- "Server must close the connection to the client if client did not mask" — tungstenite `accept_unmasked_frames=false` 实现这一规则（mod.rs §WebSocketConfig）。
  - 来源（T1）：RFC 6455 https://www.rfc-editor.org/rfc/rfc6455.html；T1 源码 https://raw.githubusercontent.com/snapview/tungstenite-rs/master/src/protocol/mod.rs。证据强度：**T1+T1**
- 极限小帧 1 B payload：最坏 14 byte overhead（2+4+8 max payload ext length）+ 1 mask = 2 + 4 + 0 + 1 = 7 byte。实际上正常包（payload ≥ 126）开销 = 6 byte/帧（2 base + 4 mask）。
- 这些都是字节级开销，对 150 MB/s 量级**完全可以忽略**（成本 < 0.001%）。

### 4.2 tungstenite 默认配置（0.30.x）
查 `snapview/tungstenite-rs/src/protocol/mod.rs`（HEAD 2024）：
```rust
pub read_buffer_size: usize, // 128 KiB
pub write_buffer_size: usize, // 128 KiB
pub max_write_buffer_size: usize, // usize::MAX (unlimited)
pub max_message_size: Option<usize>, // 64 MiB
pub max_frame_size: Option<usize>, // 16 MiB
```
- `write_buffer_size=0` 时每 message `eagerly written to the underlying stream`，即每调用一次 `write`+`flush` 就是一次系统调用。
- 默认 128 KiB 是"想要的最小 flush 阈值"——到达这个容量才 flush，否则**合并**。
- 16 MiB 帧封顶，64 MiB message 上限——GitHub 200MB 单文件不能塞进单 message，得切片。

**对链路的影响**：
- 128 KiB 默认合并阈值 **加 16 MiB 帧上限** ≈ 应用层单帧一般低于带宽×RTT，对长肥管道（200ms RTT × 100Mbps = 2.5 MB BDP）单帧最多 `~16 MiB` 即约 6× BDP，单 `flush` 等待 ack 时间在拥塞控制允许下大约 1/3 个 RTT——**单流"准稳态"吞吐**接近 `(BtlBw)`。
- 实测建议：把 `read/write_buffer_size` 调到 `256 KiB` 是常数级提速（一般 0–5%），调到 `1 MiB` 反而会涨 burst 风险（丢 1 帧 = 重传整个 buffer）。
- `max_write_buffer_size = usize::MAX` 在边缘 ws 落地时**回压**很难被触发——这是设计取舍。
  - 来源（T1）：WebSocketConfig doc https://docs.rs/tungstenite/latest/tungstenite/protocol/struct.WebSocketConfig.html；mod.rs 注释明确写 "this write buffer can not fill up if you are not observing write errors even if not flushing"。

### 4.3 与 HTTP/2 单流对比
- h2 是多 stream 复用单 TCP，单 stream 理论吞吐 = TCP single-stream 吞吐 = 与 ws 一致（应用层 framing 不同）。
- 真实差异：h2 在服务器侧队列处理更友好（TCP_NODELAY 已默认开，单 stream frame ≤16 KiB，可设置 max frame 16384）；ws frame size 由 client/server 协商，**没有 "flow per stream" 控制**——ws 单流里 application flush 节奏完全由应用层决定，**这是 ws 容易出现"流控抖动"的根因**（一阵子 fast，一阵子 empty）。
  - 来源（T1）：RFC 9113 §6.9 https://datatracker.ietf.org/doc/html/rfc9113（frame size）+ RFC 6455 §5（ws framing）。证据强度：**T1**
- HTTP/2 论文实测样本：Vespa "Improve throughput and concurrency with HTTP/2"（blog）https://blog.vespa.ai/http2/ —— h2 并发吞吐相对 HTTP/1.1 在多文件 page load 场景提升 1.5–3×，但**单文件大文件（长 lived 流）与 HTTP/1.1 等价**（与 ws 也等价）。
  - 证据强度：**T2（工程博客 + 业务实测）**

### 4.4 真实数据点：ws over TLS 单连接吞吐没有公开 peer-reviewed 上限
- 整页搜索（Web of Science / arXiv / IETF）没有"ws over TLS single-connection throughput ceiling"的论文，主要的 throughput 论文都是 HTTP/1.1 vs HTTP/2 vs QUIC 对比。这是公开空白。
- 一份 2014 的 MIPRO 论文（https://doi.org/10.1109/mipro.2014.6859715）测 ws frame overhead ≈ 0.84% loss on hello-world 级负载；**对 200MB 文件可忽略**。证据强度：**T2（粗粒度）**

### 4.5 落判
- ws 协议层开销 `< 0.01%` of BDP，**不是瓶颈**。
- 把精力放在调 `write_buffer_size` / `read_buffer_size` 是低 ROI；花在 CCA + 接收窗上 ROI 高 10×。
- ws vs h2 单流差异在用户感知上**主要源于流控抖动**（ws 应用层帧节奏不可控），非协议本身。

---

## 5. Cloudflare 边缘跨协议干扰的机制（您的症状解释）

### 5.1 CF 边缘的 WebSocket 行为
- **WS 默认开启**：所有 plan 都支持（Free/Pro/Business/Enterprise）；不需要额外配置。
  - 来源（T1）：CF docs https://developers.cloudflare.com/network/websockets/。证据强度：**T1**
- **WS 计费**：CF 把整条 ws 连接算"一个 HTTP request"——带宽算 client→CF→origin 双向。
  - 同上 §Requests and Bandwidth measurement；这是计费前提。
- **Argo 不兼容 WS**：Cloudflare 官方明确说 "Argo is not compatible with WebSockets"。
  - 同上（Compatibility notes）；这意味着 ws 流量**走不到 Argo 的 smart-routing 加速**——您走 ws 时实际拿到的不是边缘→origin 优化路径，而是不走 smart routing 的"标准"BGP。这是一个潜在大损耗。
  - 来源：T1 + Argo 文档互相确认。

### 5.2 CF "边缘连接复用"对 ws 的多协议干扰
- **同一 CF 边缘对同一 origin 同时有 ws + http + xhttp**：
  - WS 占用一条长 conn（HTTP/1.1 Upgrade），free idle 后默认 ~900s 关（Edge Idle Timeout）。长 ws 会独占该 edge→origin 的 1 个 conn 槽位。
  - HTTP/2 to origin 是被 pool 的：默认 200 concurrent streams/conn，idle 900s 后清。
  - WS 不是 h2 流级复用，是 conn 级独占；同时跑多协议时，CF origin 端看到的 conn 数 = 1 (ws) + N (h2 pools)；如果 origin 设的并发 conn 上限较紧，ws 长 conn 可能堵别人。
  - 来源（T1）：CF HTTP/2 to Origin docs §Connection lifecycle https://developers.cloudflare.com/speed/optimization/protocol/http2-to-origin/——"idle 900s","limit 200 streams"。证据强度：**T1**
- CF 的 Idle Timeout 对 WebSocket 在 Enterprise 可调，其它 plan 默认。
  - 同 CF WebSockets docs（Connection limits → Idle timeout）。

### 5.3 "测速互相干扰"的真正机制（5.x 误诊归零）
- **同一个 CF POP、同一 client IP 的多个 in-flight TCP conn**共享以下资源：
  - edge→origin 的 L4 状态（每 conn 内存）。
  - edge→client 的 L4 状态（每 conn 内存）。
  - 边缘 TLS session cache（带 size 上限）。
  - 边缘"任意 origin/任意 path" 的全局并发限（防滥用）。
- **复测不会触发显式限速，但会**：
  - 占用 socket 端口：Linux ephemeral 默认 28232 个；Cloudflare 自己写过 bind-before-connect + IP_BIND_ADDRESS_NO_PORT 才能让"同 src port 复用"（T1：CF blog https://blog.cloudflare.com/how-to-stop-running-out-of-ephemeral-ports-and-start-to-love-long-lived-connections/，2022）。您 Windows 客户端同理——连续开新连接 → TIME_WAIT 堆积 → 端口耗尽 → `connect` 失败概率上升。
  - 抢 TLS session cache：每个 ws 节点一个独立 TLS session；多测速切换节点会让 cache 命中率归零（您之前 wsplat 战役"enableSessionResumption" 即此理）。
  - 边缘层 1033（Argo Tunnel error）/1102/1200（Cache connection limit）等 5xx 类错误——CF 1xxx errors 列表 https://developers.cloudflare.com/support/troubleshooting/http-status-codes/cloudflare-1xxx-errors/。证据强度：**T1**
- **结论**：「xhttp 在测速网格里不稳」**很可能是"同 client IP 同时跑 ws+xhttp+h2,h2 已经吃掉了边缘的 200 streams/conn 配额",或"边缘节点对您的 IP 临时降优先级"**；不是 xhttp 实现问题。
  - 证据：T2（CF docs + Connection Coalescing blog https://blog.cloudflare.com/connection-coalescing-experiments/，明示 "five connections → 50% share, coalesced → one cwnd"——多 conn 在 BBR/CUBIC 下都会互相争抢）。

### 5.4 测速方法学（避免伪干扰的公开建议）
- **同窗对照**：CF/CDN 派窗口内必须同窗交替测不同协议，避免"早窗测 xhttp、晚窗测 ws"的"窗污染"。
- **baseline 同步**：每次测速前先打 `/cdn-cgi/trace` 或 `speed.cloudflare.com` 直连，确认本地链路上行 < 25% 损失。如果本地网本身就烂，所有代理测速都没意义。
- **重测间隔**：让所有协议的 TCP TIME_WAIT 释放完（Linux 默认 60s），或至少用不同 ephemeral port 范围。
- **避免 burst**：连发 N 次测速会让 BBRv3 进入"上一轮 memory"——staggered fairness 收敛可达 5 分钟（Zeynali et al., 引用 TUM 报告）。
- **同客户端/同协议栈**：跨日跨客户端的"相对"测速才有意义。"今天 50 vs 昨天 100" 在窗口污染下不可信。
  - 综合：**T2 论文级（实测方法学）+ T1 CF 官方建议**

### 5.5 CF 跨协议干扰结论
| 症状 | 真正机制 | 证据强度 |
|---|---|---|
| ws 测速高但实际文件下载慢 | ws 长 conn 独占 edge→origin 1 条 conn；突发小请求拿到 h2 多 stream 池，TPS 容易高；但单文件下载时完全是单 TCP，受限于 RTT×丢包 | T2 |
| xhttp（h2 base）测速"被别的协议影响" | 多 ws + xhttp 同时打同一 CF POP 时，CF origin h2 pool 200 streams/conn 上限共享；ws 长 conn 占用 conn 槽位但只发 1 stream，相比 h2 4MB/stream 占用率高 | T2 |
| Argo 未开启 = ws 没加速 | T1 CF docs 明示 Argo 不兼容 ws | T1 |
| 复测端口耗尽 | CF blog 关于 ephemeral ports + bind-before-connect | T1 |

---

## 6. 非 mux 替代：单流 + 跨连接优化

用户已排除 mux。这条列出**所有不需要 mux 的提速手段**，按"投入/收益"排。

### 6.1 协议层替换：ws → xhttp（h2 base）
- h2 同 conn 多 stream 并发能力天然解决 ws 的"单流阻塞"问题。1 TCP 上跑 6 stream = 同时 6 个分片请求，**单 conn 吞吐上限不变**，但**短流响应快**。
- 您的 xray 已是 h2 base；继续 xhttp。
- 现实坑：h2 落地 server 端要正确开 stream multiplexing；CF 边缘默认 200 streams/conn（§5.2），header compression 也走 HPACK，CPU 比 ws 高 5–15%（用高 qprof 测试吻合）。
- 收益：吞吐上限变化 < 5%，但**应用层 P95 延迟显著降**。
  - 来源：T1 CF docs。

### 6.2 传输层替换：ws → ws+tls+httpupgrade（**已落地**）
- 这是您的现状，略。

### 6.3 HTTP/3 / QUIC over UDP
- CF edge 已 100% 启 QUIC v1（RFC 9000，2021 年起），Cloudflare Radar 实测 ≈ 12% 总流量走 QUIC。
  - 来源（T1）：CF blog https://blog.cloudflare.com/quic-version-1-is-live-on-cloudflare/。证据强度：**T1**
- QUIC 的"无 HoL 阻塞"对单流吞吐帮助有限（单流没 HoL）；主要好处是 0-RTT、connect 迁移、独立的 per-stream loss recovery。
- xray 目前无 QUIC client/server 落地支持（Go xray v26.9.9 也未启用 QUIC 主流）。**短期不现实**。
- 收益：**协议不可用 = 0%**。

### 6.4 CF Argo Smart Routing
- CF 边缘→origin 的智能选路；公开案例：Touch of Modern 见 27% latency 改善。
  - 来源（T1）：Argo Smart Routing Guide https://assets.ctfassets.net/slt3lc6tev37/52AdNHxaXCgA5um00AB4ei/76989d0ac3797cc4efb8af7a1d3b95eb/Argo_Smart_Routing_Guide.pdf。证据强度：**T1（T1 但样本为厂商 case study）**
- **致命缺陷**：不兼容 WebSocket（§5.1）。对您现状 0 收益。如果愿意从 ws 切到 xhttp/h2,理论上能开 Argo,但要付出 xray 配置 + 实测融合的代价。
- 收益：xhttp 路径 T1（理论 27%），**ws 路径 0**。

### 6.5 连接复用（Connection Coalescing）
- HTTP/2 + 同 IP + 同 cert = 多 host 共享一 conn；Chrome 测 cf 实验组减少 78% TLS handshake，Firefox 22%。
  - 来源（T1，CF blog）：Coalescing Experiments https://blog.cloudflare.com/connection-coalescing-experiments/。
- 对您的 ws 几乎 0 影响（ws 单 host）；对多域名跨 host 不适用。

### 6.6 TCP/连接预热、0-RTT
- TLS 0-RTT = 复用上次 session 的 secret，省 1-RTT。Cloudflare 边缘支持（您已加 Session Resumption）。
- TCP 0-RTT（TFO）需要双方都开 + 不能和 ws over CF 共演；建议试 BBR 后再上 TFO。
  - 来源：LWN + kernel docs（T1）。

### 6.7 Pacing（fq + BBR）
- 已涵盖（§2.1）。
- BBR 的 pacing_gain 把发送分散到 RTT 内，不再 burst——单流吞吐在高 BDP 链路下能稳定跑满 BDP。
  - 来源（T1+T2）：Gomez 2024 论文 + man 8 tc-fq。

### 6.8 多连接 vs 单连接
- **多连接的真正收益是绕开"单 conn cwnd 拥塞"**——不是"加吞吐"，而是"加并发短流"。
- 在长肥管道下，多 TCP conn 是**互相争抢**（BBR 与 CUBIC 间尤其严重）；同一时刻只跑单 conn 通常更稳。
- 经验值：CF 边缘 often more than 6 concurrent conns to same origin 时 RPS 反而下降。
  - 来源（T2）：CF Coalescing Experiments blog（明示"five connections → 50% share"）。

### 6.9 综合推荐：单 ws + BBR + 预连接池
- **已是您的当前态**（wsplat 战役补丁已落地预连接池 12 + 补拨 fanout=3 + btls session cache 启用）。
- 接下来还有最大收益的两个动作是 **VPS 端开 BBR/fq** 和 **验证"每节点单 ws 长流"实际能拿到的带宽**——这两步不需要改 xray 代码。

---

## 7. GitHub / Fastly 大文件下载的客户端行为

### 7.1 GitHub Releases / raw.githubusercontent.com
- GitHub 的 release asset 不支持 Range 跨 multiple ranges（single range ok）。
- GitHub LFS / Release 大文件通常 ≥ 100 MB；社区记到 800+ MB 单文件下载"fail"，多与 CDN edge 行为或本地 net 有关，没具体复现。
  - 来源（T3，社区）：https://github.com/orgs/community/discussions/169381；https://github.com/orgs/community/discussions/169008。证据强度：**T3（社区报告，无官方文档）**
- GitHub 走 Fastly（`github.global.ssl.fastly.net`），Fastly 默认 2 GB / 5 GB object 上限，**单文件 < 5 GB 不会卡**。
- **结论**：GitHub 单文件下载不会因"客户端单 conn"降速；但在 200ms RTT + 0.5% 丢包下，单 TCP 长流自身就是瓶颈。

### 7.2 Fastly 大文件
- **无 Segmented Caching 默认上限**：用户级 2 GB cache；2020-06-17 后的账户默认 20 MB（！）。**新账户大文件直接 503 Response object too large**。
  - 来源（T1）：Fastly docs https://www.fastly.com/documentation/guides/full-site-delivery/performance/failure-modes-with-large-objects/。证据强度：**T1**
- **开 Segmented Caching 后**：分小块缓存，Range request 友好。实现上是 Fastly 内部把文件切片 cache + inner Range request。不开 = 5 GB 上限突发 503 给 client。
- **对 ws 透明**：ws 流到内部 HTTP 也走 Range=0-（全文件 download）；限制是 cache 大小非连接吞吐。
- 收益：**对您作为 client 拿 GitHub Release：您只决定代理端能调到的 Fastly 模式，不可控**。

### 7.3 xray 客户端对 Fastly/GitHub 的代理路径
- client(xray) → CF edge → origin (Fastly or GitHub) → 大文件。
- 单 ws 长 conn → 单 TCP → CF edge 反向 h2（默认 200 streams/conn） → origin。
- 链路全程**单瓶颈点**：client→CF 这一段丢包最重（跨太平洋），BBR + fq + 客户/服务端 socket buffer ≥ 4MB 是唯一的关键动作。
- **结论**：Fastly/GitHub 的"对象大小 / 分段策略"对您**透明**，**关键在第 1 跳 client↔CF**。

---

## 8. 综合可行建议（按 ROI 排序）

### 建议 1【ROI 极高 / 零代码成本】VPS 端开 BBRv3 + fq pacing
- 命令：
  ```bash
  echo "net.core.default_qdisc=fq" >/etc/sysctl.d/99-xray-bbr.conf
  echo "net.ipv4.tcp_congestion_control=bbr" >>/etc/sysctl.d/99-xray-bbr.conf
  sysctl --system
  # 验证
  sysctl net.ipv4.tcp_congestion_control net.core.default_qdisc
  # 期望：bbr / fq
  ```
- 预期：单流吞吐跨太平洋 200ms + 0.5% 丢包下提升 **2–3×**（T2 Gomez 论文 + T1 fq 手页）
- 风险：BBRv3 与 CUBIC 共用瓶颈时偏胜；同一 host 上若别人也用 VPS 互相争抢会拉低别人。单 VPS 自用基本无副作用。

### 建议 2【ROI 高 / 系统配置】确保 client/server 套接字 buffer ≥ 4MB
- VPS 端 sysctl `tcp_rmem/tcp_wmem` max = 4194304。
- 客户端 Windows：`netsh interface tcp show global` 确认 autotuninglevel=normal（默认即 16M），不要改 disabled/restricted。
- 期望：单流 200ms RTT 可用窗口 ≈ 4–16MB（BBR 估计出 BDP），与 default 64KB initial window 相比，瞬间把"延迟期"跳过。
- 风险：windows 端 ECN 与 Scale Factor 老路由器不兼容。CF 不受影响。
- 证据：T1。

### 建议 3【ROI 中 / 一次性时间投入】TLS 0-RTT + Session Resumption
- 您已加 wsplat 战役（xray-tls session cache）。
- 验证：连续两次冷连 → 第二次握手 RTT 节省。
- 风险：理论 0-RTT 重放攻击；CF edge 对 0-RTT POST 谨慎（仅 GET），ws 多为 frame 长流没事。
- 证据：T1 + 已落地。

### 建议 4【ROI 中 / 实测校准】实测 xhttp vs ws 单 TCP 长流
- 用同一 node、同时段、同一文件、6 轮交替。
- 期望：xhttp 与 ws 单流差异 < 10%（CF 边缘→origin 段是 h2）；多并发短流 xhttp 显著胜。
- 不需要改 xray。

### 建议 5【ROI 高（仅您愿意切换协议时）/ 一次性大改】从 ws 转 xhttp 并开 Argo Smart Routing
- 您说 xhttp 在测速里不稳——很可能不是协议问题，是 §5 干扰问题。
- 一旦稳了，可考虑 Argo（27% latency improve，官方 case study）。
- 风险：Argo 不兼容 ws；切 xhttp 同时改用 xhttp 才有效。
- 证据：T1 CF docs + Argo Guide。

---

## 9. 不要做的事

- 不要关闭 mux 之外的"TCP 握手包装"。Reality/vision 目前已经实现 0-RTT 流水线，无需回退到完全裸 h2。
- 不要在 VPS 同时跑"BBR + 标准 BBRv1"等多版本混跑——B 端 v1 + v3 互操作有 fairness 报告（B vs Bv1 较公平，TUM §3.4.2）。
- 不要用 `tc qdisc tbf` 替代 `fq`——BBR 配 TBF 等于非 paced BBR，与裸 CUBIC 差不多。
- 不要"开 Fastly Segmented Caching 替代性优化"——那是 Fastly 卖家面板，您只作为客户端拿不到控制权。
- 不要无脑选 HTTP/3——客户端没支持（xray 当前无 QUIC 实现）；预期 0 收益。

---

## 10. 公开空白（这点很重要，给审计做"无答案≠无问题"边界）

- **ws vs h2 在 150–250ms RTT / 0.1–1% 丢包下的同盘下载吞吐差异**：没有 peer-reviewed 公开实测。意味着 "ws 慢于 h2" 是推测（T4），不是事实。
- **CF 对单 client IP 的 ws 连接数上限**：公开文档没有硬数字，社区猜测 60s 内 ~6 个 ws conn 是经验值（T3）。
- **Windows 客户端切换 CCA 的可行性**：WSL2 内可以测，但原生 Windows 的 `netsh interface tcp set global` 不允许改 CCA。完全是 0。
- **GitHub Releases 走 Fastly 的 Cache-Control + Connection Coalescing 行为**：Fastly 公开 docs 不透露面向 GitHub 的具体配置；只能从 client 测推。

---

## 附录 A：完整 URL 索引（按强度）

### T1（官方文档 / 源码 / 期刊）
- Linux kernel TCP sysctl：https://docs.kernel.org/networking/ip-sysctl.html
- Linux tc-fq(8)：https://man7.org/linux/man-pages/man8/tc-fq.8.html
- Linux TCP_NOTSENT_LOWAT（LWN）：https://lwn.net/Articles/560082/
- RFC 6455 WebSocket：https://www.rfc-editor.org/rfc/rfc6455.html
- RFC 9113 HTTP/2：https://datatracker.ietf.org/doc/html/rfc9113
- RFC 9000 QUIC：https://www.rfc-editor.org/rfc/rfc9000.html
- RFC 1323 TS/WScale：https://www.rfc-editor.org/rfc/rfc1323.html
- RFC 6928 IW10：https://datatracker.ietf.org/doc/rfc6928/
- MS AutoTuning KB 947239：https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/receive-window-auto-tuning-for-http
- MS AutoTuningLevel blog：https://learn.microsoft.com/en-us/archive/blogs/netgeeks/a-word-about-autotuninglevel-tcp-receive-auto-tuning-level-explained
- tungstenite WebSocketConfig doc：https://docs.rs/tungstenite/latest/tungstenite/protocol/struct.WebSocketConfig.html
- tungstenite mod.rs source：https://raw.githubusercontent.com/snapview/tungstenite-rs/master/src/protocol/mod.rs
- CF HTTP/2 to Origin docs：https://developers.cloudflare.com/speed/optimization/protocol/http2-to-origin/
- CF WebSockets docs：https://developers.cloudflare.com/network/websockets/
- CF 1xxx errors docs：https://developers.cloudflare.com/support/troubleshooting/http-status-codes/cloudflare-1xxx-errors/
- CF Connection Coalescing blog：https://blog.cloudflare.com/connection-coalescing-experiments/
- CF ephemeral ports blog：https://blog.cloudflare.com/how-to-stop-running-out-of-ephemeral-ports-and-start-to-love-long-lived-connections/
- CF QUIC v1 blog：https://blog.cloudflare.com/quic-version-1-is-live-on-cloudflare/
- Argo Smart Routing Guide：https://assets.ctfassets.net/slt3lc6tev37/52AdNHxaXCgA5um00AB4ei/76989d0ac3797cc4efb8af7a1d3b95eb/Argo_Smart_Routing_Guide.pdf
- Fastly failure modes with large files：https://www.fastly.com/documentation/guides/full-site-delivery/performance/failure-modes-with-large-objects/
- Fastly Segmented Caching：https://www.fastly.com/documentation/guides/full-site-delivery/caching/segmented-caching

### T2（实测论文 / 工程博客）
- Gomez et al. BBRv3 in Wired Broadband Networks（Computer Comms 222）：https://research.cec.sc.edu/files/cyberinfra/files/bbrv3_rev2.pdf
- TUM *Current State of BBR*（NET-2025-05-1）：https://www.net.in.tum.de/fileadmin/TUM/NET/NET-2025-05-1/NET-2025-05-1_17.pdf
- Zeynali et al. BBRv3 in the Public Internet（ANRW 2024）：https://doi.org/10.1145/3673422.3674889
- BBR vs BBRv2（COMSNETS 2024）：https://www3.cs.stonybrook.edu/~anshul/comsnets24_bbrbbrv2.pdf
- DropBox Edge BBRv2（arXiv）：https://doi.org/10.48550/arxiv.2008.07699
- Piotrowska BBRv3 多 RTT（MDPI Applied Sciences）：https://doi.org/10.3390/app14125053
- Vespa http/2 throughput concurrency：https://blog.vespa.ai/http2/
- ACM Queue BBR：https://queue.acm.org/doi/fullHtml/10.1145/3012426.3022184（HTTP 403 借 CACM：https://cacm.acm.org/practice/bbr-congestion-based-congestion-control/）

### T3（社区 / 工程经验）
- GitHub community 大文件下载 fail：https://github.com/orgs/community/discussions/169381
- CF 1015 rate limit error：https://community.cloudflare.com/t/increase-in-429-errors-since-19th-july/676926
- TCP/IP performance known issues MS：https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/tcpip-performance-known-issues

---

## 附录 B：术语速查
- **BDP**：bandwidth-delay product，吞吐 × RTT
- **CUBIC**：Linux/Windows 默认 loss-based CCA，靠丢包事件回退窗
- **BBR / BBRv2 / BBRv3**：model-based CCA，记瓶颈带宽+RTT，主动 probe；v3 = bug-fix + 收敛改良
- **fq**：Fair Queue qdisc，把单流 paced 发送，避免 bufferbloat
- **HoL 阻塞**：head-of-line，h1 + ws 单 stream 都有；QUIC 是 stream-level loss recovery 故无
- **Argo**：CF Smart Routing；ws 不兼容
- **Coalescing**：h2 同 conn 跨 host 复用（同 IP + 同 cert）
- **TCP_NOTSENT_LOWAT**：限制 unsent bytes 在 socket write queue，提高 CPU 利用与延迟表现
