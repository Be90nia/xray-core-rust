# 调研简报 · 高 RTT 路径上 xhttp(h2) 代理推送大文件的吞吐上限

> 2026-11-12 · 供三路调研共用（避免重复劳动与重走死路）。结论落 `docs/research/2026-11-12-high-rtt-*.md`。

## 1. 我们的拓扑与实测事实

- **节点**：单核 VPS（实测 `nproc=1`，528MB RAM，Linux，拥塞控制 `bbrplusv3`），跑我们的 Rust 代理内核；
  `XRAY_MEM_LIMIT_MB=512` ⇒ 内存档 small：预算 96MiB、bridge 背压闸 12MiB/方向。
- **路径**：客户端（中国，~200ms RTT）→ Cloudflare 边缘 → Argo 隧道 → 节点；节点再从源站
  （cachefly，Cloudflare Argo anycast `205.234.175.175`，~6ms）取数据 ⇒ 节点侧源站腿很快（~37MB/s 聚合）。
- **症状**：**同一节点、同一路径**，**ws 44-66MB/s vs xhttp 15-40MB/s**（v2rayN 测速，10 并发下载）。
  Go 官方客户端走 xhttp 同样只有 25-27MB/s ⇒ 不是我们客户端独有。
- **低 RTT 对照**（节点本机当客户端，RTT≈3.6ms）：xhttp 20-36MB/s、ws 25-34MB/s ⇒ **打平**。
  ⇒ 差距只在**高 RTT + 客户端在另一台机**时出现。
- **受控台**（176 loopback + netem 100ms/向，RTT≈200ms，本地 origin 276MB/s）：
  xhttp（缺省 / maxConnections=1/3/10/16）与 ws 聚合**完全相同**（1.5-1.7MB/s）；
  客户端侧 `ss -tin`：`snd_wnd: 65536`（**Linux 接收窗未自动扩窗**）、`rtt 200.1ms`、
  `cwnd 11`、`delivery_rate 1.31Mbps`。

## 2. 已经关死的路（**不要再提这些做推荐**，除非能给出「我们当年测错了」的新证据）

| 路 | 死因与证据 |
|---|---|
| 调 h2 流窗 / 连窗 | `docs/research/2026-11-09-zct77-h2-rtt-stall-plan.md` §12：E1 档 4MiB/32MiB/64MiB 流窗 = 7.84/9.05/9.23 MB/s（调小更差、调大无收益） |
| 调服务端 h2 `send_buf` | 同上 E4：2M/5M/16M = 8.87/9.14/8.91（三档全平，差 <3%） |
| 改退款粒度 / vendor h2 改阈值 | 同上 §7：窗口余量 = 需求的 8.7× ⇒ 收益 0；且 fork h2 是「最贵的错」 |
| RTT 阶梯（按探针 RTT 缩 send_buf） | commit `33bacd22` 引入 → `a750a542`「RTT 阶梯误缩 send_buf 修复」回退。**根因**：预连接探针测的是「本机→host」（CDN 场景 ≈ 边缘 RTT ~30ms），真实数据路径端到端 RTT ≈ 200ms ⇒ 拿它当 BDP 的 RTT 是错的 |
| 显式 `SO_RCVBUF` | bd r5j96 / 7p1m：显式设置是**锁窗**（关 autotune）+ Linux 受 `rmem_max` 静默钳制 ⇒ 反而更差（WSL 实测 0.80 vs 7.43MB/s） |
| `TCP_NOTSENT_LOWAT` | commit `dbdfc83d` 回退：端到端 TTFB 收益经实测证伪 |
| 显式设 socket 缓冲当提速手段 | 同 r5j96 血案，禁 |

## 3. 仍开放的问题（本调研要找答案的）

1. **根在哪一层？** 候选：(a) 节点端**每字节 CPU 成本**（单核）；(b) **唤醒/停-启相位**（h2 退款批粒度 T/3≈11MB ⇒ 11MB 簇 + 簇后等 1 RTT）；(c) **TCP 窗口预算**（内核 `snd_wnd/rmem_max/wmem_max` 未放开）；(d) **连接数/窗口数**（ws 每请求 1 条 TCP，xhttp 复用 ≤3 条）。
2. **有没有已被别人验证的、更优的机制？** 例如：
   - 成熟的**按 BDP 动态定窗/定 cwnd**实现（gRPC-Go 的 `dynamicWindow`/`bdpEstimator`、nghttp2 的窗口策略、quinn 的 auto-tuned window）；
   - **并行多流/多连接以获取更多窗口**的系统做法（MPTCP、HTTP/3 每流独立、代理的 per-conn buffer 预算）；
   - **真实代理**（Envoy / HAProxy / nginx / Caddy）在长路径推大文件时的缓冲与窗口策略（它们的默认值就是行业答案）；
   - 让**内核窗口真的长大**的正统做法（不是显式锁窗）；
   - 降低**每字节 CPU/字节**（TLS record/chunk 尺寸、syscall 批量化、拷贝次数）。
3. **BBR 的 app-limited 语义**：我们内核报 `app_limited`（写队列空）——这与 BBR 的 app-limited 状态机直接相关；
   app-limited 被「相位化灌装」伪造出来时，BBR 的带宽估计会失真吗？外部有无处理办法？

## 4. 输出要求（三路共同）

- 每条结论给**来源 + tier**（tier1 = 论文/RFC/draft/源码；tier2 = 官方文档/issue；tier3 = 博客/论坛）。
- 每条给**适用性裁决**：`直接可用` / `需改造` / `不适用（为什么）`——**允许并鼓励判「不适用」**。
- 若建议落到具体旋钮/常量/代码点，给出**文件与符号线索**（我们仓：`crates/xray-transport-splithttp/`、
  `crates/xray-transport/src/bridge.rs`、`crates/xray-transport-quic/src/congestion_swappable/bbr/`、
  `crates/xray-frame/src/budget/`）。
- **不要**建议 §2 已关死的路；**不要**建议 fork/vendor h2（除非论证「唯一可行」并给出代价）。
- 注明**是否会引入新依赖**（我们要求：新依赖需 PM 拍板；优先用已装依赖能力）。
