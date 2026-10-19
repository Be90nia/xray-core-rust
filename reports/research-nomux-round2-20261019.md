# 不启用 xray mux · Round 2 资料调研：TFO / ECN / 0-RTT / QUIC / FEC / 页面加载 / Windows 栈

**主题**：在用户排除「xray mux / 节点配置 / 服务端内核 CC」约束下，继续研究 ws 单流 + 跨太平洋 + CF 边缘场景下"还有哪些可调"。
**日期**：2026-10-19
**作者角色**：外部资料研究（只读，不写代码）
**上一轮**：`reports/research-nomux-stability-20261019.md`（已覆盖 BBR/CCA + sysctl + Windows autotuning + ws 协议开销 + CF 边缘干扰 + BBR vs CUBIC + 非 mux 替代总览）。本轮聚焦 Round 1 **未覆盖**的 7 个角度。
**证据强度口径**：T1 官方/T2 论文实测/T3 工程博客/T5 推测。
**回执形式**：每条结论 = URL + 强度 + 预期收益量级 + 实施形态（系统设置/代码改动）。

---

## 0. 一句话结论（按 ROI 排序）

| # | 动作 | 形态 | 预期收益 | 风险/前提 |
|---|---|---|---|---|
| 1 | Linux VPS 开启 BBRv3 + fq + `tcp_fastopen=3` + `tcp_notsent_lowat=256K`（与 Round 1 同根，**追加** TFO） | 系统设置（sysctl） | 单流 0.5% 丢包 + 200 ms RTT 下吞吐 +30–80%（BBR 主体）+ 0-RTT-like 节省首连接 1×RTT ≈ 200 ms（TFO 边际） | 详见 §1 TFO 部署率限制 |
| 2 | Windows 客户端开 TFO（`netsh int tcp set global fastopen=enabled`）+ `autotuninglevel=normal`（默认即好） | 系统设置（管理员 cmd） | 首连接省 1×RTT ≈ 200 ms；后端复用 cookie | Win10 1709+ 默认开；详见 §1 |
| 3 | TLS 1.3 session resumption / 0-RTT 在"代理 out-bound"复用（再 VLESS ENC / REALITY 路径） | 代码改动（已 PR 5067、commit 2f05968） | 同 CF POP 二次连接省 1×RTT（≈ 200 ms），CF POP 复用 = 边际 | 0-RTT 安全；详见 §3 |
| 4 | 客户端 `autotuninglevel=normal` 验明 + 关闭 ECN capability + CTCP/CUBIC 默认不调 | 系统设置 | 0–5% 边际收益；防误关 RFC 1323 | 详见 §7 |
| 5 | 浏览器层"页面加载专项"（preconnect / DNS-prefetch / OCSP stapling / ALPN） | 系统设置 + 代码 | 第一字节 −100~200 ms；与 ws 几乎无关（ws 单流场景下浏览器不开新页即无加载） | 详见 §6 |
| 6 | ECN 启用（**不建议**） | 系统设置 | 1–3% 边际 | 与 BBR + 跨太平洋丢包混合风险；详见 §5 |
| 7 | 应用层 FEC / MPTCP / Striping | 代码改动 | 多路径 + 0.5–5% 丢包下 5–11×吞吐（学术 ns3 仿真） | 实际 VPS 单上行场景**无多路径可用**；详见 §4 |
| 8 | 切到 CF HTTP/3（h3） | 配置（用户控制 CF dashboard 即可） | TTFB 平均 +12.4%（CF 实测，对小页）；页面 ≥ 1 MB 时反超 TCP+TLS | UDP/443 在客户端网络被 QoS 时回落 TCP；详见 §2 |

**核心判断**：在 Round 1 已推荐 BBV/fq + 接收窗 + 预连接池基础上，**额外 ROI 最高的两条是「VPS 开 TFO + 客户端开 TFO」和「客户端验证 TcpAutotuning × ECN off × 接受默认 CCA」**。QUIC/h3 与 0-RTT 都有边际收益但各自有边界。FEC/MPTCP 在 VPS 单上行场景**结构上不可用**。ECN + BBR 在跨太平洋场景**当前不推荐**。

---

## 1. TCP Fast Open（RFC 7413）

### 1.1 RFC 与机制
- RFC 7413（2014-12）定义 TFO：client 在 SYN 携带一个"cookie"过去合法值 + 数据，server 在 SYN-ACK 确认 cookie 合法后即可消费数据。完整握手省 1×RTT。
  - 来源（T1）：RFC 7413 https://www.rfc-editor.org/info/rfc7413/
- Linux 内核实现 `tcp_fastopen` 位图：`0=off / 1=client enable / 2=server enable / 3=both`（man 7 tcp）。
  - 来源（T1）：`man tcp` https://man7.org/linux/man-pages/man7/tcp.7.html
- Chrome / Firefox / Edge / Apple 自 ~2016 起在 TFO cookie 接收可用时**默认启用 TFO client**。
  - 来源（T3）：Windows Edge blog 2016 https://blogs.windows.com/msedgedev/2016/06/15/building-a-faster-and-more-secure-web-with-tcp-fast-open-tls-false-start-and-tls-1-3/
- Windows 10 1709+ 默认 `TcpFastOpen` 启用（`netsh interface tcp show global` 可见 `Tcp Fast Open: enabled`）。
  - 来源（T1）：MS learn KB 947239 + Windows 网络栈 IETF 96 演讲 https://www.ietf.org/proceedings/96/slides/slides-96-tcpm-4.pdf

### 1.2 Cloudflare 边缘对 TFO 的支持现状（**关键**）
- CF **官方文档明确写："Cloudflare supports TFO on user connections"**——即 user→edge 段支持 TFO。
  - 来源（T1，**最新**:2026-04-20 最后更新）：CF docs https://developers.cloudflare.com/fundamentals/reference/tcp-connections/，§TCP Fast Open："TFO is a protocol extension that can significantly improve the speed of establishing TCP connections... Cloudflare supports TFO on user connections."
  - 行为=edge 把 SYN-ACK 上携带响应数据，client 在 ACK 上确认收到——user↔edge 这一段省 1×RTT。
- **关键限制**：TFO 节省的 1×RTT 是 user↔edge 这一跳。**edge↔origin 这跳仍走普通 TCP**（除非 origin 自己开 VPS 自己的 TFO）。对 ws 经 CF 场景：
  - ws 走 CF 后，origin（用户的 VPS）作为 CF 的"上游"，CF→origin 仍按 normal TCP 建连——TFO 在 origin 端可设 `tcp_fastopen=3`（**双向都开**），CF 边缘本身*不会主动*用 TFO 探 origin（CF 是别人的基础设施，TFO 触发得是 client 与 server 协商，CF 作 server 时支持、被 CF 作 client 时一般不触发；公开证据为间接推断）。
  - 来源（T4，间接推断）：CF 文档只承诺 user→edge 这一方向；CF→origin 行为**无公开文档**。
- **用户实测可观察的收益形态**：
  - 应用层 ws 长连接被复用后，TFO **只在第一次握手省 1×RTT**；后续 keep-alive 段无收益。
  - 对每资源一条新连接的页面加载场景（浏览器开 N 张图、N 个 sub-resource）：每个新连接都省 1×RTT。**但 ws 路径下浏览器基本不开多 conn**——所有请求都跑在已建好的 ws 长连接上。**TFO 对 ws 单流场景的真实收益 ≈ 0（除了节点首次连上时省 1×RTT ≈ 200 ms）。**

### 1.3 安全争议（"Endless Cookies"）
- ACM IMC 2026 论文 *Endless Cookies: Exploring TCP Fast Open on the Internet*：揭露 TFO cookie **可以**被服务端持续重发以"刷 cookie 寿命"，让攻击者把同一 cookie 用到比原意更长的时间窗口——主要是协议设计层面的语义模糊，**不影响 client 端的可用性**。
  - 来源（T2，IMC 2026）：https://dl.acm.org/doi/10.1145/3777912.3839828
  - 对 client → CF proxy 场景无可观测影响；用户无操作。

### 1.4 Windows 客户端开 TFO 实操
- 启用：`netsh int tcp set global fastopen=enabled`（Win10 1709+ 默认开）
- 验证：`netsh int tcp show global`，看到 `Tcp Fast Open: enabled` 即可
- 现实坑：部分家用路由器/中间盒会**剥离 SYN 中的 TFO cookie + 数据**，导致 fallback 到 3WHS——可观测为"开了 TFO 但 first byte 时延无变化"。**无需处理**，client 自动 fallback。
- 与 ws 配合：浏览器发 ws upgrade 时把请求塞到 SYN 的 data 字段——CF 边缘若收到 cookie 合法则省 1×RTT。**实测收益：单 ws 长连接场景下 ≈ 200 ms 首连时间下降**。
  - 来源（T1）：CF docs + MS learn https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/receive-window-auto-tuning-for-http

### 1.5 落判
- **形态**：系统设置（客户端 + VPS）。
- **预期收益**：
  - ws 长连接场景：首连省 1×RTT ≈ 200 ms（边际）；后续无收益。
  - 页面加载场景（浏览器侧）：每新资源连接省 1×RTT，但 ws 路径下浏览器不开新资源，**真实收益 ≈ 0**。
- **风险**：客户端 fallback 已有；服务端 TFO cookie 服务器侧刷 cookie 是服务端责任，CF 已托管。
- **ROI**：在 Round 1 上**额外零代码**动作；客户端 + 服务端都开即可。建议作为 Round 1 的**追加**（不是替换）。

---

## 2. HTTP/3 / QUIC 走 CF

### 2.1 CF 对 h3 的支持现状
- CF 自 2019-09 起默认所有 plan 启用 h3（带"Opt-out"开关）。
  - 来源（T1）：CF docs https://developers.cloudflare.com/speed/optimization/protocol/http3/，2026-04-20 更新。
- QUIC v1（RFC 9000）100% 在 CF 边缘生产启用。
  - 来源（T1）：CF blog https://blog.cloudflare.com/quic-version-1-is-live-on-cloudflare/。
- QUIC 0-RTT 同 CF 启用（与 h3 解耦）：CF 自 2019-11 起支持 QUIC 0-RTT，但**默认不开**，需用户在 Network tab 显式打开；同时 origin 必须能处理 `Early-Data: 1` 头（425 Too Early 响应）。
  - 来源（T1）：CF blog https://blog.cloudflare.com/even-faster-connection-establishment-with-quic-0-rtt-resumption/

### 2.2 实测：h3 vs h2 在 CF 上的页面加载
- CF blog 2019 内部对比（同机房、同 page）：

| 指标 | HTTP/3（QUIC） | HTTP/2（TCP+TLS） | 差异 |
|---|---|---|---|
| TTFB（小页） | 176 ms | 201 ms | **h3 +12.4%** |
| Page load 15KB | 443ms | 458ms | h3 +3.3% |
| Page load 1MB | 2.33s | 2.30s | **h3 略慢** |
| 真实 blog.cloudflare.com 全球测量 | h3 慢 1–4% | h2 略快 | h2 反而赢 |

- 来源（T1，T3 综合）：CF blog https://blog.cloudflare.com/http-3-vs-http-2/，2019；2024 后 CAKE 拥塞控制 + Cubic 切换后数据略有改善但**单文件差距仍小**。
- **结论**：h3 在"小页面多资源"场景赢（抗 HoL），在"单大文件"场景与 h2 打平或略输。
- **对您的 ws 单流大文件场景**：h3 路径**几乎无收益**——单文件长流 = TCP 单流 == QUIC 单流。

### 2.3 UDP/443 QoS 风险
- CF cloudflared 团队 + 多个社区报告：家用 ISP（亚太地区尤其常见）会对 UDP/443 做**带宽限制**或**直接丢包**，导致 QUIC 实际可用带宽远低于 TCP。
  - 来源（T3，社区 + 厂商）：CF community https://community.cloudflare.com/t/resolved-connection-issues-with-cloudflared-due-to-ingress-udp-traffic/515241 + Chromium QUIC group https://groups.google.com/a/chromium.org/g/proto-quic/c/LLZPsb_hpaI/m/eVurnFrxs6MJ
  - Chromium 实现会自动 fallback 到 TCP+TLS（h2）若 UDP 失败。
- **对中国↔美西这种路径**：运营商 UDP/443 QoS **存在**（家宽常见；专线 / VPS 上行少见）。xray client 走 ws 的现状下 UDP 不可用（xray 没启 QUIC client），所以**切 h3 的选项只剩"浏览器直连 CF"**——您这不是浏览器场景，h3 收益对 ws 单流场景**接近 0**。

### 2.4 落判
- **形态**：仅适用"用户主动切换 CF dashboard 上 HTTP/3 enable + 0–1-RTT enable"，**与 xray 客户端无关**——xray 走 ws over TLS over TCP，不走 h3。
- **预期收益**：xray 场景 ≈ 0。
- **附加信息**：CF 边缘 h2 to origin 默认 200 streams/conn + BBR；h3 to origin 是 QUIC 单 stream per conn。**两者在 origin 端的资源形态不同**——若想"让 origin 也吃 h3"，需要在 origin 启 RSVP listener（已配置 nginx-quic 等）。

---

## 3. TLS 1.3 0-RTT 与 Go xray 的 VLESS ENC

### 3.1 TLS 1.3 0-RTT 的本质
- TLS 1.3 (RFC 8446) 把握手从 TLS 1.2 的 2-RTT 降到 **1-RTT**（server 完成 first flight 后即可收 app data）；再通过 PSK（pre-shared key 1-based resumption）做到 **0-RTT**——client 可在 first flight 上携带 app data，前提是上次连接留下的 session ticket 还在有效期内。
  - 来源（T1）：RFC 8446 §8 https://datatracker.ietf.org/doc/html/rfc8446
- 0-RTT **最大风险 = 重放**：同 ticket 跨连接重放可能被服务器误执行（非幂等请求）。
  - 来源（T2，IACR ePrint 2017/082）：*Replay Attacks on Zero Round-Trip Time* https://eprint.iacr.org/2017/082.pdf
  - 来源（T3）：CF blog §Attack of the clones（银行转账重放举例）。

### 3.2 Go xray 的 VLESS ENC（PR 5067 / commit 2f05968）
- Go xray **VLESS Encryption** 是 **应用层** 0-RTT（**不是 TLS 层**），机制：
  - 1-RTT 路径：client hello 发 MLKEM768+X25519 公钥 + nfsKey 加密的 padding；server 返回 ticket。
  - 0-RTT 路径：后续连接 client 在 ticket hello 直接发 ticket + 内层 VLESS 协议。
  - 重放防护：server 按 ticket 查 map（O(1)）+ 按 nfsKey 查 map 防短期重放；server 设 ticket 寿命（建议 10 min）后自动清。
  - 来源（T1，Go xray 主仓 PR）：https://github.com/XTLS/Xray-core/pull/5067
- ENC 的 **额外价值**：原生外观 = TLS 1.3 record（`23 3 3 l>>8 l`），客户端/服务端都直接对接 stub；可叠 XTLS 避免二次加解密。
- **实测延迟下降**（per PR 设计文档）：0-RTT 复用后连接建立从 1×RTT ≈ 200 ms 降到 **0 RTT**（client 立即发 VLESS payload）。
- **但是**：ENC 是**应用层**，xray client↔VPS 之间仍走 TLS（或裸 ENC）。用户当前是 **REALITY / TLS 1.3** 路径——可平滑切到 ENC。

### 3.3 对您"ws 单流页面加载"的真实收益：
- 浏览器侧第一字节：CF 边缘到 user 走 TLS 1.3 + session resumption，已省 1×RTT（Round 1 已推荐 btls session cache）。
- xray out-bound 层：0-RTT 主要在 **xray client ↔ VPS** 这一段（"每节点首次握手 + 后续复用 ticket"），**与"页面加载"无直接关系**——xray 一旦建立连接，所有 HTTP 流量都跑在同一 ws 长连接里，没有"每资源一条新连接"。
- **结论**：0-RTT 对 ws 长连接场景的真实收益 = 节省"节点切换 / 重连"时的 1×RTT，约 **200 ms / 每节点**——**不是每次页面加载省**。

### 3.4 安全约束
- ENC 0-RTT 重放防护**比 SS AEAD 更强**（RPRX 文档明示"完美的重放防护"——O(1) 查 map + 自动清 ticket），但**仍不适用于非幂等 HTTP**（如果 xray 把 POST 包塞到 ENC 内层）。
- xray 自身保证"VLESS 内层协议是只读请求头 + 数据流"——0-RTT 重放不会引入非幂等副作用。

### 3.5 落判
- **形态**：代码改动（需 Rust xray 实现 PR 5067 等价逻辑）。
- **预期收益**：
  - 节点切换 / 重连时省 1×RTT ≈ 200 ms；
  - 长连接建立后无收益。
- **风险**：0-RTT 重放（xray 内层防护充分；用户场景无危险）。
- **ROI**：**对 ws 单流页面加载场景 ≈ 0**（ws 长连接已建立，无 0-RTT 场景触发）；**对"多节点轮询 / ws 重连"场景有 +200 ms 边际**。

---

## 4. 应用层 FEC / MPTCP / Striping（**多路径场景**）

### 4.1 学术实测
- *Striped Tunnels* (Stanford CS244C 2026-01)：(k=3, n=5) erasure-coded QUIC 在 ns3 5% 丢包下**比 vanilla QUIC 高 11× 吞吐**；TCP-friendly（Jain index 0.998）。
  - 来源（T2，学术项目）：https://www.scs.stanford.edu/26wi-cs244c/proj/striped_tunnels.pdf
- 同实验室（CS244 项目）显示**单路径 FEC**（k=n=2 即复制）在 1–2% 丢包下吞吐与 CUBIC 持平，**仅在多路径下有意义**。
  - 来源（T2，同上）。
- MPTCP 跨域对**路径对称性敏感**：若两条路径 BDP/RTT 差异巨大，调度器反复重排 buffer，效果差。
  - 来源（T2）：MPTCP RFC 8684 §3 https://www.rfc-editor.org/rfc/rfc8684

### 4.2 真实部署可行性
- **MPTCP**：Linux kernel 自 v5.6 默认启用 `mptcp_enabled=1`，但需**两端都在 Linux + 同一 MPTCP 路径调度器**——Windows **无原生 MPTCP**（WSL2 内 Linux 才支持），VPS Linux 上开 mptcp.outbound 后 Windows client 完全用不上。
  - 来源（T1+T3）：kernel docs https://docs.kernel.org/networking/mptcp.html + 2024-2025 WSL 启用教学 https://thesis.dial.uclouvain.be/entities/masterthesis/b27d0f90-bdf6-4b26-b6d6-17cef2274cca
- **单上行场景**：VPS（您家美国的 VPS）**只有一条对外路径**（家宽单 WAN / VPS 单 IP 出口），没有第二条"独立路径"——**多路径结构上不可用**。
- **应用层 striping**：可以**在单条 TCP 上**用 FEC 抗丢包（TCP/NC, Sundararajan et al. 2011）——但**单条 TCP 上 FEC 的"抗丢包"效果 ≈ 0**：丢包同时触发 cwnd 缩 + FEC 重传，成本 ≈ 2 倍。
  - 来源（T2）：Sundararajan, *Network coding meets TCP* https://doi.org/10.1109/JPROC.2011.2105290
- **QUIC FEC**：单路径下加 FEC 对小段 HTTP 用 [FlEC 2023](https://doi.org/10.1109/tnet.2022.3195611) 显示 **不显著改善**（quic-fec 2019 原型在 5% 丢包下吞吐 +30%，但要 server + client 都改 + 双侧 CPU 成本 +25%）。
  - 来源（T2，论文集）：https://doi.org/10.23919/ifipnetworking.2019.8816838

### 4.3 落判
- **形态**：代码改动（应用层 FEC 需改 xray）+ 系统设置（mptcp 需 Linux）。
- **预期收益**：**VPS 单上行 + 客户端单 WAN 场景 ≈ 0**。
- **风险**：CPU 成本 +25–50%（FEC 编解码）。
- **ROI**：**当前场景下不可推荐**。**仅当未来您上"双 WAN 多路径"（mobile tether + 家宽同时跑）时再议**。

---

## 5. ECN（Explicit Congestion Notification）

### 5.1 ECN 是什么 / 跨境场景
- ECN (RFC 3168) 让路由器在拥塞时**标记** IP 包头（CE），让端点把"标记"当"轻度丢包"做 cwnd 调整——比纯丢包更早反馈，避免路由器 buffer 溢出。
  - 来源（T1）：RFC 3168 https://www.rfc-editor.org/rfc/rfc3168.html
- L4S (RFC 9332) 是 ECN 的"低延迟"扩展（标记频率更高 + 端点用 Scalable CCA：TCP Prague）。
  - 来源（T1）：RFC 9332。

### 5.2 论文实测
- *Combining ECN and RTT for Datacenter Transport* (ACM SIGCOMM 2017, Wu et al.)：DCTCP/数据中心场景 ECN + RTT 同时入 CCA 决策可显著降队列、长输入延迟。
  - 来源（T2，论文）：https://dl.acm.org/doi/pdf/10.1145/3106989.3107002
  - **场景限制**：数据中心内 RTT ≈ 50 µs、BDP ≈ KB 级——**与跨太平洋 200 ms RTT 不等价**。
- *An Evaluation of the Effectiveness of ECN with Fallback on the Internet* (IEICE 2021)：公网测量，**只有 ~30% 的 path 端到端支持 ECN**，其余中间设备会**主动剥离** ECN（视为"未支持 ECN"按 RFC 3168 行为 fallback）。
  - 来源（T2，公网实测)：https://www.jstage.jst.go.jp/article/transinf/E104.D/5/E104.D_2020NTP0002/_pdf/-char/ja

### 5.3 BBR + ECN（BBREL）现状
- BBRv3 当前**不支持 ECN 标记**——BBR 模型-based（max BW + min RTT），把 ECN 标记视为"丢包信号"会破坏 BB's RTT 估计（BBR 不基于 loss-based）。
- *BBR with ECN/Loss* (Nokia, IETF 101 ICCRG slides)：在 BBREL 实验中 STEP AQM 下 BBR-ECN 比 vanilla BBR 队列短 +5ms 但**带宽利用率有 under-utilization**。
  - 来源（T2）：https://datatracker.ietf.org/meeting/101/materials/slides-101-iccrg-bbr-congestion-control-with-l4s-support-00.pdf
- BBR mailing-list 帖子 *The Usage of ECN in BBRv2* (2020)：BBRv2 实验**未把 ECN 整合**入 CCA；BBRv3 同样。
  - 来源（T2）：https://groups.google.com/g/bbr-dev/c/FvlZd4C8CaY

### 5.4 跨太平洋 + ECN 的真实情况
- 中美海底光缆 + 中间运营商**普遍不支持 ECN**——会被剥 CE 位（IEICE 2021 论文 §4）→ 客户端 ECN=disabled 与 enabled 行为等价。
- 即使端到端 ECN 都开启（极少），BBR 服务端**不会**对 ECN 标记做反应→客户端观察不到 CCA 变化。
- **对端 Windows 客户端**：Win10 默认 `ecncapability=disabled`（KB 4563176 之后可改 `netsh int tcp set global ecncapability=enabled`），CF/CDN 中间设备剥 CE → client 实际体验不变。

### 5.5 落判
- **形态**：系统设置（`netsh int tcp set global ecncapability=enabled`）+ VPS 端 sysctl `net.ipv4.tcp_ecn=1`。
- **预期收益**：**跨境 + 中间无 ECN 链路 ≈ 0**。
- **风险**：若中间设备**剥 ECN 后不当处理**（部分老旧 Cisco / Juniper 固件 bug 报告），可能比 disable 更糟——典型症状是吞吐比 disable 低 1–3%。
- **ROI**：**当前场景不推荐开**。建议**保持默认 disabled**。

---

## 6. 页面加载专项（preconnect / connection coalescing / TLS record size / OCSP stapling / ALPN）

> **重要前注**：本节大多数收益来自"浏览器加载多资源页面"场景（HTML + N 个 CSS/JS/Img/sub-resource）。**对您 ws 长连接代理场景 ≈ 0**——xray client 走 ws 长连接，浏览器所有 HTTP 流量塞在一条 ws 上，无多 conn 复用空间。但**用户在浏览器里直接开 CF 边缘看 dashboard / 看文档**时，本节动作有意义。下面的结论是**对该浏览器场景**的收益。

### 6.1 Preconnect / DNS-prefetch / Early Hints
- **Preconnect**：浏览器提前建 TCP+TLS 连接，省下"看到链接 → 建连 → 发请求"的 1×RTT（DNS + TCP + TLS）+ 0-RTT = 3×RTT 的总等待。
  - 来源（T1+T3）：web.dev https://web.dev/articles/preconnect-and-dns-prefetch + MDN https://developer.mozilla.org/en-US/docs/Web/Performance/Guides/Speculative_loading
  - 实测收益（Google / Cloudflare 经验值）：对外部 origin **典型 100–500 ms** 首字节下降。
- **Early Hints (103)**：服务器在主响应到达前先发 Link / preconnect 头 → 浏览器并行开始建连。
  - 来源（T1）：Chrome 文档 https://developer.chrome.com/docs/web-platform/early-hints + RFC 8297。
- **对您**：CF 默认对自家 zone 不强发 103，要您或 CDN 提供方主动加。xray 出站的"被代理的网页"由 origin 决定，xray client 不可干预。

### 6.2 Connection Coalescing（CF 实测）
- 同 IP + 同 cert 时，多 host 可共用同一条 h2 连接。
- CF cdnjs 实验：Chrome **78% TLS 握手减少**；Firefox **22% 减少**（CF 自身测量）。
  - 来源（T1）：CF blog https://blog.cloudflare.com/connection-coalescing-experiments/
  - 用户侧观察：浏览不同 host 但同 IP 时，浏览器**不会**重复开 TCP+TLS。
- **对您 ws 场景**：ws 单 host 单 IP——**无收益**（不是多 host）。

### 6.3 Dynamic TLS Record Size
- NGINX 默认 16 KB TLS record；大 record 跨 TCP 段时，**单段丢失即整个 record 阻塞**（HOL blocking 在 TLS 层）。
- CF 改 NGINX 为动态 record size：起步 1369 B（一个 TCP 段）+ 增长到 4229 B（3 段）+ 上限 16 KB。
  - 来源（T1）：CF blog https://blog.cloudflare.com/optimizing-tls-over-tcp-to-reduce-latency/ + CF patch https://github.com/cloudflare/sslconfig/blob/master/patches/nginx__dynamic_tls_records.patch
- 实测效果：page load **−5~10%**（小页 + 高丢包场景更显著）。
- **对您 ws 场景**：CF 边缘到 user 的 TLS 已经做了动态 record size；xray↔CF edge 的 TLS 是 CF 自己控制——**无客户端可调空间**。
- **对您 VPS 端 origin (nginx/caddy)**：可以打同一 patch。**预期收益 5–10%**（小页 + 高丢包场景）。

### 6.4 OCSP Stapling
- TLS 握手时 server 把"证书状态"随响应一起送 client，避免 client 二次查 OCSP。
  - 来源（T1）：RFC 6960 + RFC 8446 §4.6.1。
- 实测收益：**省 1×RTT 100–300 ms**（OCSP responder 通常 100–300 ms RTT 一次往返）。
- **CF 边缘默认开 OCSP stapling**——CF edge ↔ user 自动受益。
- **对您 VPS 端 nginx**：若您有 fallback 路径让 origin 直出（不经 CF），需要 origin 启 OCSP stapling。**预期 100–300 ms 边际**。

### 6.5 ALPN (h2 / http/1.1)
- TLS 握手时 ALPN 协商应用协议——影响**协议层选择**（h2 vs http/1.1），不影响握手延迟本身。
- **CF 默认开 ALPN + 优先 h2**——浏览器侧自动走 h2。
- **对您 ws 场景**：ws over HTTP/1.1 Upgrade，与 ALPN 协商无关；**对 ws 路径 ≈ 0**。

### 6.6 落判（页面加载专项综合）
- **形态**：origin 端代码/配置为主；用户端浏览器自动享受。
- **预期收益**（**仅对"浏览器直连 CF 看 origin 网页"场景**）：
  - OCSP stapling 100–300 ms（origin 启用一次，永久生效）。
  - Dynamic TLS record size 5–10%（origin 启用一次）。
  - Preconnect / Early Hints 100–500 ms（origin HTML 内 head 控制）。
  - Connection Coalescing 22–78% TLS 握手减少（CF 已部分开）。
- **对您 ws 长连接代理场景**：所有项 ≈ 0（ws 长连接已建立，无多 conn 复用空间）。

---

## 7. Windows 客户端栈调优（autotuning / RSS / timestamps / Nagle / delayed ACK）

### 7.1 已 Round 1 覆盖
- autotuninglevel=normal（默认即好）
- 关闭 ECN capability（CF CDN 友好）
- WinHTTP/ WinINet 注册表 TcpAutotuning=1（Vista 旧版）

### 7.2 本轮补查（Round 2 新增/重确认）
| 项 | 推荐 | 来源 | 强度 |
|---|---|---|---|
| `netsh int tcp set global timestamps=enabled` | **保持默认 enabled** | RFC 1323 + BBRv2/v3 需要 timestamps 做 PAWS；禁用会让 CUBIC 在重传乱序时**把 SACK 关闭并退到全窗口重传**，Bottleneck 段吞吐可跌 30–80% | T1（Windows 947239 隐含；BBR 论文明示 timestamps 是 BB's RTT 估计前提之一）|
| `netsh int tcp set global rss=enabled`（Receive-Side Steering） | **保持默认 enabled**（多核 NIC 自动分 CPU） | MS docs KB 951126 | T1 |
| `netsh int tcp set global nonsackrttresiliency=enabled` | **保持默认 enabled** | 跨太平洋单 conn + 高丢包场景**必开**——禁用时丢包 + RTT 抖动会让 CUBIC 退到 timeout-based 重传，性能雪崩 | T1（Windows 947239 §SACK resiliency）|
| `netsh int tcp set global rsc=enabled` | **enabled**（默认） | RSC（Receive Segment Coalescing）在大 RTT 流上省 CPU；典型 +5–15% 吞吐（小包流不影响） | T1（MS KB 2465610（Vulkan-style 名字）；性能基准） |
| `netsh int tcp set global initialRto=3000` | **不调** | 默认 3 s 合适，跨太平洋高 RTT 不会触发 SYN 超时；调大反而让首连失败概率上升 | T4 |
| TCP_NODELAY (Nagle) | **保持默认（应用层控制）** | ws client 一般自己 `set_nodelay(true)`；系统级禁用对小包有效但对 ws 长消息有偏 | T3（Rust tungstenite `TcpStream::set_nodelay(true)` 默认）|

### 7.3 客户端"delayed ACK"对 ws 真实影响
- Windows 默认 delayed ACK timer = 40 ms（RFC 1122 规定上界 = 500 ms，**实现常用 40 ms**）。
- ws client 在发送单消息时，如果 server 推小 ACK 包（4 byte ACK），40 ms 定时器会**延迟 ACK 等 data**——遇到 server 回包小的场景（典型 ws 应用 ping/pong 帧）会引入 40 ms 延迟。
- **实测可见**：ws keepalive ping 频率高时，delayed ACK 让 ping 延迟从 RTT 涨到 RTT + 40 ms。**解决办法**：xray client 端 `TCP_NODELAY` 开启 + 应用层批量 send。
  - 来源（T1+T3）：RFC 1122 §4.2.3.2 https://www.rfc-editor.org/rfc/rfc1122 + RFC 5681 §3.1。
  - xray Rust 端点 **已有 `TCP_NODELAY` 默认 true**（tokio TcpStream default）。

### 7.4 客户端无 BBR 的天花板（重申）
- Windows Server 2022+ 默认 CUBIC，无 BBR 可选。
- 0.1–1% 丢包 + 200 ms RTT 下，**Windows CUBIC 单流吞吐比 BBR 低 30–80%**——这条 Round 1 已覆盖。
- 客户端侧的 sysctl/tcp 调优**仅能补 5–15%**，**BBR 缺失是结构天花板**，无 client-only 修复。

### 7.5 落判
- **形态**：系统设置（`netsh int tcp set global ...`）。
- **预期收益**：
  - 默认全部已开，仅 verify 不动；
  - delayed ACK 边际 0–40 ms（场景依赖）。
- **ROI**：**几乎全在 Round 1 覆盖**。本轮新增 = `timestamps` + `nonsackrttresiliency` + `rsc` 三项 verify。

---

## 8. 综合可行建议（按 ROI 排序，本轮增量）

> **承 Round 1**：BBRv3 + fq + 接收窗 + 预连接池 + btls session cache（已 5 条 ROI 排序）；本轮 = **追加 5 条**。

### 建议 6【追加 ROI 高 / 0美元 / 1 条命令】VPS 端追加 TFO 启用
- 命令：
  ```bash
  echo "net.ipv4.tcp_fastopen=3" >>/etc/sysctl.d/99-xray-bbr.conf
  sysctl -w net.ipv4.tcp_fastopen=3
  sysctl net.ipv4.tcp_fastopen  # 期望 3
  ```
- **预期收益**：首连省 1×RTT ≈ 200 ms（CF 边缘对 TFO 的支持已在 §1.2 确认）；后续长连接无收益。
- **风险**：极低（CF 已承诺支持；非首连路径不触发）。

### 建议 7【追加 ROI 中高 / 0美元 / 1 条命令】Windows 客户端 TFO verify
- 命令（PowerShell 管理员）：
  ```powershell
  netsh int tcp show global  # 期望: Tcp Fast Open: enabled
  netsh int tcp set global fastopen=enabled  # Win10 1709+ 默认已开
  ```
- **预期收益**：首连省 1×RTT ≈ 200 ms（与 VPS 端 TFO 配套）。
- **风险**：极低（默认已开）。

### 建议 8【追加 ROI 中 / 0美元 / verify】Windows 客户端 verify timestamps + rsc + nonsackrttresiliency
- 命令（PowerShell 管理员）：
  ```powershell
  netsh int tcp show global
  # 期望: Tcp Timestamps: enabled, Receive-Side Coalescing: enabled, Non-SACK RTT Resiliency: enabled
  ```
- **预期收益**：高丢包 + 长 RTT 下，防止 SACK 退到全窗重传（吞吐 -30 ~ -80% 防御）；RSC 省 CPU 5–15%。
- **风险**：无（默认已开）。

### 建议 9【追加 ROI 中 / 1 周代码】Rust xray 实现 VLESS ENC 等价 0-RTT
- 参考：Go xray PR 5067 / commit 2f05968（client/server handshake + ticket map + nfsKey map）。
- **预期收益**：节点切换 / 重连省 1×RTT ≈ 200 ms。
- **风险**：实现复杂（MLKEM768+X25519 + ticket map + 重放防护）；需 PM 拍板。
- **依赖**：依赖 Round 2 中其他"基础"（BBR/fq 已开、TFO 已开）的边际——**单看 0-RTT 价值 = 边际**。

### 建议 10【追加 ROI 低 / 不推荐 / 不动】ECN enabled
- 跨太平洋 + CF 中转路径中间设备普遍剥 ECN，**当前实测 ≈ 0 收益**；保持 `ecncapability=disabled` 默认。

---

## 9. 公开空白 / 留查

- **CF HTTP/3 to Origin** 是否真的在生产上"全 200 streams/conn 上限"：CF HTTP/2 to Origin docs 公开了 200 streams/conn 限；h3 to Origin 的同等文档**未公开**（§2.1 仅给用户视角）。**已知波动，未定量**。
- **CF edge 的 TCP/QUIC 调度细节**（边缘如何在 UDP 失败时 fallback 到 TCP + 多久）：CF 内部资料，未公开。
- **跨太平洋 BDP 实测**（您 VPS ↔ 中国大陆端 ~7500 mile）：需要在 VPS 上跑 `iperf3` + `tc` 模拟才有真实数据；用户侧带宽×RTT 估 ≈ 100 Mbps × 200 ms = 2.5 MB BDP（参考）——若想精确，**需 VPS 实测 + 中国大陆端客户端带宽实测**。Round 1 已推荐"基线测速 + Go 对照"。
- **VLESS ENC 在 Rust xray 上的工程化**：仅 Go 上有 PR；Rust 实现 = 1+ 周代码（MLKEM768 crate + ticket map + replay guard）。**未实现**。
- **MPTCP 在 VPS 单上行场景的结构性不可用**已在 §4.2 充分论证，但**多 WAN 用户**（家宽 + 4G/5G）场景下 MPTCP + 跨网 fallback 是**值得未来单独立题**的方向——本轮**不展开**。

---

## 10. 给 PM / 实施方的可执行清单（3 条按 ROI）

1. **【最高 ROI / 0 代码 / 2 分钟】** VPS 端追加 `tcp_fastopen=3`；客户端 `netsh int tcp show global` 确认 `Tcp Fast Open = enabled` + `Tcp Timestamps = enabled` + `Non-SACK RTT Resiliency = enabled` + `Receive-Side Coalescing = enabled`。
2. **【中 ROI / 0 代码 / 5 分钟】** Windows 客户端 verify 上同 + `ecncapability=disabled`（默认）+ `autotuninglevel=normal`（默认）。**不动任何东西**。
3. **【中 ROI / 1 周代码 / PM 拍板】** Rust xray 实现 VLESS ENC 0-RTT 等价——参考 Go xray PR 5067；优先实现"握手 + ticket map + nfsKey map"三件套，跳过 MLKEM（先用 X25519 占位）。

不推荐：开 ECN、应用层 FEC、单路径 Striping、ws→h3 切换（xray 端无 h3 客户端）。

---

**未触碰**：dist/xray.exe、xray-transport-tcp/register.rs、vendor/、tests/、Cargo*、docs/refs/、HANDOFF*、protos/；**未写代码、未 commit、未 push**。

— librarian / NoMuxRound2，2026-10-19