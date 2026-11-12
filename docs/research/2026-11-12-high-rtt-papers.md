# 调研报告 · 论文/RFC/标准轨：高 RTT 路径上 xhttp(h2) 推送大文件的吞吐上限

> 2026-11-12 · 轨 1（论文/RFC/draft/源码）
> 共享简报：`docs/research/2026-11-12-high-rtt-brief.md`
> 本轨只出**不变量 + 出处 + 适用性裁决**，不改任何代码/配置。
> tier 口径按简报 §4：**tier1 = 论文/RFC/draft/源码；tier2 = 官方文档/issue；tier3 = 博客/论坛**。

---

## 0. 一页结论

| # | 结论 | tier1 出处 | 裁决 |
|---|---|---|---|
| A | ~200ms RTT 下**必须成立的不变量**是「在途量 ≥ BDP」，违反即退化为 `窗口/RTT` 并出现**锯齿式 1 RTT 停顿**（不是变慢，是周期性归零） | RFC 9293 §3.8.6、RFC 7323 §1.1、Mathis 1997、RFC 2001 §1 | **直接可用**（作为判据） |
| B | 「周期性停 1 RTT」的**标准级机制**有两条：① 接收窗太小 → 每段之间插入 RTT 延迟（RFC 9293 §3.8.6 原话）；② 发送方被流控阻塞 → 至少阻塞一个完整 RTT（RFC 9000 §4.2 原话） | RFC 9293 §3.8.6 / RFC 9000 §4.2 | **直接可用**（用来定位是哪一层） |
| C | **内核报 `app_limited` 不是误判，是准确报告「应用侧当时无数据可发」**；BBR 的处理（丢弃该样本、不涨 cwnd）是 RFC 9002 §7.8 + RFC 2861/7661 的**规定行为**。所以 BBR 不是元凶，症状在应用层 | RFC 9002 §7.8、RFC 2861、RFC 7661 §2、Linux `tcp_rate.c`、BBRv3 draft §5.5.4/§5.5.5 | **直接可用**（作为排除性判据） |
| D | 「窗口 ≥ **1.5×**BDP」**不是任何 RFC 的规定**；1.5 这个数来自 gRPC-Go `bdp_estimator.go` 的一行注释（其 BDP-ping 采样窗口常量），被业界误传成规则。RFC 只要求「> BDP」 | gRPC-Go 源码、RFC 9113 §5.2.3、RFC 9000 §4.3 | **不适用**（作为规则）；**需改造**（作为方法论） |
| E | BBRv3 自己的不变量是 `cwnd ≈ 2×BDP`（cwnd_gain 默认 2）、`ProbeBW_UP` 隐含 `inflight ≥ 1.25×BDP` —— 比 1.5 更接近工业实践 | draft-ietf-ccwg-bbr-07 §5.3.3.5、§5.6.4.2 | **直接可用**（作为内核侧对照基线） |
| F | **异见轨（tier1）**：「缓冲/窗口开大 ≠ 更快」有至少三条 tier1 反证——Redux 2019（大缓冲只增延迟、让 CC 更迟钝）、Barakat&Altman 2004（小缓冲路径上「更激进」反而更差）、RFC 7661 §2（RFC 2861 那类修法官方判为 Historic） | 同左 | **直接可用**（作为「别再往窗口上使劲」的论证） |
| G | **反向反例也成立**：「窗口开小 ≠ 更快」——Vu-Brugier 2007 实测 3KB 队列 → 20% 丢包 + 利用率 <60% + 用户投诉被迫中止 | Vu-Brugier et al. CCR 2007 | **直接可用**（防止矫枉过正） |
| H | **算术层面的重要线索**：受控台客户端 `snd_wnd: 65536` + `delivery_rate 1.31Mbps` 恰好等于 `65536 B / 0.4 s`。若 64 KiB 接收窗是上限，则**受控台从一开始就撞在客户端接收窗上，xhttp==ws 是台架伪影，无法区分两条协议** | RFC 7323 §1.1 + RFC 9293 §3.8.6.2.2（推导为 [INFERENCE]） | **需改造**（改台架，不是改代码） |

**对简报的三处事实更正**（详见 §5）：`RFC 7414` 不是「High-BDP TCP 规范」而是**路线图索引**；`Nicolaides「dark buffer」模型` 归属有误（是 **Gettys & Nichols**）；`Dunn et al. 2012「double increase」` **查无此文**（附检索轨迹与替代出处）。

---

## 1. 高 BDP / 长肥网络（LFN）的 TCP 行为与必须成立的不变量

### 1.1 tier1 出处

**RFC 7414 — A Roadmap for Transmission Control Protocol (TCP) Specification Documents**
<https://www.rfc-editor.org/rfc/rfc7414.txt> — Informational, 2015-02, 57 页。
⚠️ **简报 §3.1 把 RFC 7414 称作「High-BDP TCP」是不准确的**：它没有给出任何高 BDP 的规范性要求，通篇是「哪些 RFC 该被读」的索引 + 大量摘要。§1 自述：「These documents are listed in the chronological order… the description of each mechanism is presented in terms of its introduction, key summary, and rationale. … **These descriptions should not be used as a substitute for the actual specifications**」。
**裁决：不适用**（作为不变量来源）；**直接可用**（作为索引：它把我们需要的几件东西都列了出来——§3.1 RFC 7323「TCP Extensions for High Performance … allow TCP to be used efficiently on paths with **large bandwidth-delay products**」、§3.2 RFC 6928 IW=10 + RFC 3465 ABC、§3.4 RFC 3782/6298 RTO、RFC 3042 Limited Transmit）。

**RFC 7323 — TCP Extensions for High Performance** — Standards Track, 2014-09
<https://www.rfc-editor.org/rfc/rfc7323.txt>
§1.1「TCP Performance」**原话**：
> "TCP performance problems arise when the bandwidth \* delay product is large. A network having such paths is referred to as a **long, fat network (LFN)**.
> (1) **Window Size Limit** — The TCP header uses a 16-bit field to report the receive window size to the sender. Therefore, the largest window that can be used is 2^16 = 64 KiB. **For LFN paths where the bandwidth \* delay product exceeds 64 KiB, the receive window limits the maximum throughput of the TCP connection over the path**, i.e., the amount of unacknowledged data that TCP can send in order to keep the pipeline full."

**裁决：直接可用**（tier1 硬不变量）。

**RFC 9293 — Transmission Control Protocol (TCP)** — Standards Track, 2022-08
<https://www.rfc-editor.org/rfc/rfc9293.txt>
§3.8.6「Managing the Window」**原话**（这是全篇最贴我们症状的一句）：
> "Indicating a large window encourages transmissions. If more data arrives than can be accepted, it will be discarded. This will result in excessive retransmissions, adding unnecessarily to the load on the network and the TCP endpoints. **Indicating a small window may restrict the transmission of data to the point of introducing a round-trip delay between each new segment transmitted.**"

§3.8.6.2.2「Receiver's Algorithm — When to Send a Window Update」**原话**：
> "The solution to receiver SWS is to avoid advancing the right window edge RCV.NXT+RCV.WND in small increments… keep RCV.NXT+RCV.WND fixed until the reduction satisfies: `RCV.BUFF − RCV.USER − RCV.WND ≥ min(Fr · RCV.BUFF, Eff.snd.MSS)` where **Fr is a fraction whose recommended value is 1/2**… Note also that the general effect of this algorithm is to advance RCV.WND in increments of Eff.snd.MSS…"

**裁决：直接可用**（tier1 硬不变量 + 停顿机制原文）。

**RFC 2001 — TCP Slow Start, Congestion Avoidance, Fast Retransmit, and Fast Recovery** — Standards Track, 1997-01
<https://www.rfc-editor.org/rfc/rfc2001.txt>
§1 Slow Start **原话**：
> "It operates by observing that **the rate at which new packets should be injected into the network is the rate at which the acknowledgments are returned by the other end.**"

**裁决：直接可用**（ACK clock 机制，「簇后停 1 RTT」的传输层语义锚点）。

**Mathis, Semke, Mahdavi, Ott — "The Macroscopic Behavior of the TCP Congestion Avoidance Algorithm"**, ACM SIGCOMM CCR 27(3), 1997
<http://ccr.sigcomm.org/archive/1997/jul97/ccr-9707-mathis.pdf>
模型 `BW ≤ MSS/(RTT·√p)`，并**明写两条前提**：
> "It assumes that TCP avoids retransmission timeouts and **always has sufficient receiver window and sender data**."
> "**If the data receiver is announcing too small a window then TCP's performance is likely to be fully controlled by the receiver's window and not at all by the Congestion Avoidance algorithm.** Likewise if the sender does not always have data to send the model is likely not to apply."

**裁决：直接可用**（tier1 论文；给出了「窗口受限区」与「带宽受限区」的判别句，与我们的「11MB 簇 + 1 RTT 停顿」形状完全对上）。

**RFC 9000 — QUIC: A UDP-Based Multiplexed and Secure Transport** — Standards Track, 2021-05
<https://www.rfc-editor.org/rfc/rfc9000.txt>
§4.2 Increasing Flow Control Limits **原话**：
> "A receiver MUST NOT wait for a STREAM_DATA_BLOCKED or DATA_BLOCKED frame before sending a MAX_STREAM_DATA or MAX_DATA frame; doing so could result in the sender being blocked for the rest of the connection. **Even if the sender sends these frames, waiting for them will result in the sender being blocked for at least an entire round trip.**"
> "Control frames contribute to connection overhead. Therefore, **frequently sending MAX_STREAM_DATA and MAX_DATA frames with small changes is undesirable. On the other hand, if updates are less frequent, larger increments to limits are necessary to avoid blocking a sender, requiring larger resource commitments at the receiver.** There is a trade-off between resource commitment and overhead when determining how large a limit is advertised."
> "When a sender receives credit after being blocked, it might be able to send a large amount of data in response, **resulting in short-term congestion**."

§4.3 Flow Control Performance **原话**：
> "If an endpoint cannot ensure that its peer always has available flow control credit that is **greater than the peer's bandwidth-delay product** on this connection, its receive throughput will be limited by flow control."

**裁决：直接可用**（h2/QUIC 侧的同构不变量 + 大 WU 的突发风险原文）。

**RFC 9113 — HTTP/2** — Standards Track, 2022-06
<https://www.rfc-editor.org/rfc/rfc9113.txt>
§5.2.3 Flow-Control Performance **原话**：
> "If an endpoint cannot ensure that its peer always has available flow-control window space that is **greater than the peer's bandwidth \* delay product** on this connection, its receive throughput will be limited by HTTP/2 flow control."
§6.9.2 Initial Flow-Control Window Size：新流初窗 65,535 octets（连接级同）。
§5.2.2 Appropriate Use of Flow Control：不需该能力者可通告 `2^31-1` 实质关闭流控；反向警告「**flow control enabled without knowledge of the bandwidth \* delay product** ⇒ suboptimal use of available network resources」。

**裁决：直接可用**。

**RFC 5681 — TCP Congestion Control** — Standards Track, 2009-08 <https://www.rfc-editor.org/rfc/rfc5681.txt>
§3.1：`IW` 上界按 MSS 分档 2/3/4 段（引 RFC 3390）；§4.1 Restarting Idle Connections：`RW = min(IW, cwnd)`，并规定「若超过 RTO 未发数据，SHOULD 把 cwnd 降到 ≤ RW 再发」。§3.1 还给出 ACK clock 的定义（"Slow start additionally serves to start the ACK clock"）。

**RFC 6928 — Increasing TCP's Initial Window** — Experimental, 2013-04 <https://www.rfc-editor.org/rfc/rfc6928.html>：IW 上界提至 10 段。

**RFC 6349 — Framework for TCP Throughput Testing** — Informational, 2011-01 <https://www.rfc-editor.org/rfc/rfc6349.txt>：把「TCP RWND」「由 RTT 与瓶颈带宽算出的 BDP」列为吞吐测试必须报告的量——是我们做判据时的**测量口径**出处。

**裁决（5681/6928/6349）：直接可用**（作为「启动代价」与「测量口径」的 tier1 依据）。

### 1.2 在 ~200ms RTT、单核代理推大文件下，「必须成立」的不变量清单

> 记 BDP = 瓶颈带宽 × RTT。W_inflight = min(cwnd, rwnd, h2 流控窗)。链路上真正能持续在途的量是 W_inflight。

| 编号 | 不变量 | 违反时的**可观测形态** | tier1 出处 |
|---|---|---|---|
| **I1** | **W_inflight ≥ BDP**（持续满足，不是瞬时） | 吞吐被钉在 `W_inflight / RTT`，与链路能力无关；且**每 RTT 走完一窗就停 1 RTT**（锯齿） | RFC 9293 §3.8.6；Mathis 1997「fully controlled by the receiver's window」；RFC 9113 §5.2.3；RFC 9000 §4.3 |
| **I2** | **接收窗不得小于 BDP**；64 KiB 是无 Window Scale 时的物理上限 | 与 I1 同形；`ss` 侧 `snd_wnd/rcv_wnd` 卡 65536 即中招 | RFC 7323 §1.1 |
| **I3** | **发送侧永远有数据可发**（应用不空转） | TCP 报 `app_limited`；吞吐被应用供给率而非网络钉住 | Linux `tcp_rate.c::tcp_rate_check_app_limited`；BBRv3 §4.1.2.4；RFC 9002 §7.8；Mathis 1997「if the sender does not always have data to send the model is likely not to apply」 |
| **I4** | **流控信用必须持续可覆盖 BDP，且退款不得等 DATA_BLOCKED** | 发送方**至少阻塞一个完整 RTT**（不是「慢」，是「归零一 RTT」） | RFC 9000 §4.2；RFC 9113 §5.2.3/§6.9.2 |
| **I5** | **ACK clock 不得中断**（有 ACK 就有下一包） | 「簇后停 1 RTT」——发完一簇必须等 ACK 回来才继续 | RFC 2001 §1；RFC 5681 §3.1 |
| **I6** | **BBR 侧 in-flight 目标 = cwnd_gain × BDP（默认 2×），ProbeBW_UP 隐含 ≥ 1.25×BDP** | 内核 BBR 若长期达不到自己的目标，说明**瓶颈不在 BBR** | draft-ietf-ccwg-bbr-07 §5.6.4.2、§5.3.3.5 |
| **I7** | **慢启动/重启代价 = log₂(BDP / IW) 个 RTT**；200ms 下 IW=10 段（14.6KB）填 8MB BDP 需 ~9 RTT ≈ 1.8s | 长连接空闲后重启 → 前 2 秒几乎无吞吐；BBRv3 明确说这是「很多大部署直接关掉该机制」的原因 | draft-ietf-ccwg-bbr-07 §5.4.2；RFC 6928；RFC 5681 §4.1 |

**「违反哪条 ⇒ 表现为『周期性停 1 RTT』」的判别树**（tier1 原文支撑）：

```
现象：11MB 簇 + 簇后停 1 RTT
├─ 停顿时 TCP 侧 app_limited=1 ？
│   ├─ 是 ⇒ I3 被违反。停顿时长 = 上层补数据的时延。
│   │      若上层补数据要等对端退款 ⇒ 叠加 I4 ⇒ 停 1 RTT（RFC 9000 §4.2）
│   └─ 否（TCP 有数据但发不出去）⇒ 查 I1/I2（窗受限）
├─ 停顿时 in-flight 已归零且 snd_wnd/rcv_wnd 卡在 65536 ？
│   └─ 是 ⇒ I2 被违反。64KiB/0.4s = 1.31Mbps —— 与受控台观测值**数值相等**（见 §4）
└─ 停顿时 cwnd 小但窗口大 ⇒ I1 被违反（窗够、cwnd 不够）⇒ 查 I6（BBR 模型是否可信）
```

---

## 2. BBR 的 app-limited 语义与「相位化伪造」下的失真

### 2.1 tier1 出处

**draft-ietf-ccwg-bbr-07 — BBR Congestion Control** — CCWG, 2026-11-02, Experimental
<https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-07.html>
- §4.1.2.4 Detecting Application-Limited Phases：`CheckIfApplicationLimited()` = `NoUnsentData() && C.pending_transmissions == 0 && C.inflight < C.cwnd && C.lost_out <= C.retrans_out`；`MarkConnectionAppLimited(): C.app_limited = max(C.delivered + C.inflight, 1)`；标记随「bubble 被 ACK 掉」清除（`if (C.app_limited && C.delivered > C.app_limited) C.app_limited = 0`）。
- §5.5.4 BBR.max_bw and Application-limited Delivery Rate Samples **原话**：
  > "**By default, the estimator discards application-limited samples**, since by definition they reflect application limits. **However, the estimator does use application-limited samples if the measured delivery rate happens to be larger than the current BBR.max_bw estimate**, since this indicates the current BBR.max_bw estimate is too low."
- §5.5.5 `UpdateMaxBw()`：`if (RS.delivery_rate > 0 && (RS.delivery_rate >= BBR.max_bw || !RS.is_app_limited)) { BBR.max_bw = UpdateWindowedMaxFilter(...) }`
- §3.8（Experimental Status）**原话**：
  > "**BBR does not deal well with persistently application limited traffic** … When unable to fill the pipe for a full round trip, BBR will not be able to measure the full link bandwidth, and will mark a bandwidth sample as app-limited. In cases where an application enters a phase where all bandwidth samples are app-limited, BBR will not discard old max bandwidth samples that were not app-limited."
- §5.6.4.2：`UpdateMaxInflight()`：`inflight_cap = BDPMultiple(BBR.cwnd_gain)`（默认 cwnd_gain=2 ⇒ **2×BDP**）+ `BBR.extra_acked`；§5.6.4.6：`C.cwnd = min(C.cwnd + RS.newly_acked, BBR.max_inflight)`。
- §5.3.3.5 ProbeBW_UP **原话**："If the flow has not set BBR.inflight_longterm, it implicitly tries to raise C.inflight to at least BBR.pacing_gain \* BBR.bdp = **1.25 \* BBR.bdp**."
- §5.4.2 Restarting From Idle **原话**："The long (**log_2(BDP)\*RTT**) delays required to reach full utilization with that 'slow start after idle' approach caused many large deployments to disable this mechanism."

**Linux 内核源码（tier1）— `net/ipv4/tcp_rate.c`（v6.12）**
<https://raw.githubusercontent.com/torvalds/linux/v6.12/net/ipv4/tcp_rate.c>
`tcp_rate_check_app_limited()` **原码**：
```c
if (/* We have less than one packet to send. */
    tp->write_seq - tp->snd_nxt < tp->mss_cache &&
    /* Nothing in sending host's qdisc queues or NIC tx queue. */
    sk_wmem_alloc_get(sk) < SKB_TRUESIZE(1) &&
    /* We are not limited by CWND. */
    tcp_packets_in_flight(tp) < tcp_snd_cwnd(tp) &&
    /* All lost packets have been retransmitted. */
    tp->lost_out <= tp->retrans_out)
        tp->app_limited = (tp->delivered + tcp_packets_in_flight(tp)) ? : 1;
```
`tcp_rate_gen()`：`if (tp->app_limited && after(tp->delivered, tp->app_limited)) tp->app_limited = 0;`（**「bubble 被 ACK 掉才清除」**）
文件头注释 **原话**："The estimator marks a bandwidth sample as application-limited **if there was some moment during the sampled window of packets when there was no data ready to send in the write queue**."

**Linux 内核源码（tier1）— `net/ipv4/tcp_bbr.c`**
<https://raw.githubusercontent.com/torvalds/linux/master/net/ipv4/tcp_bbr.c>
- `bbr_update_bw()`：`if (!rs->is_app_limited || bw >= bbr_max_bw(sk)) { minmax_running_max(&bbr->bw, ...) }`
- `bbr_check_full_bw_reached()`：`if (bbr_full_bw_reached(sk) || !bbr->round_start || **rs->is_app_limited**) return;`（**app-limited 轮次完全不计入「管道已填满」的判定**）
- `bbr_update_lt_bw_sampling()`：`if (rs->is_app_limited) { bbr_reset_lt_bw_sampling(sk); return; }`
- `bbr_check_drain()` / `bbr_reset_congestion_signals()` 等。

**RFC 9002 — QUIC Loss Detection and Congestion Control** — Standards Track, 2021-05
<https://www.rfc-editor.org/rfc/rfc9002.txt>
§7.8 Underutilizing the Congestion Window **原话**：
> "When bytes in flight is smaller than the congestion window and sending is not pacing limited, the congestion window is underutilized. This can happen due to insufficient application data or flow control limits. **When this occurs, the congestion window SHOULD NOT be increased in either slow start or congestion avoidance.**
> A sender that paces packets … **SHOULD NOT consider itself application limited if it would have fully utilized the congestion window without pacing delay.**
> A sender MAY implement alternative mechanisms to update its congestion window after periods of underutilization, such as those proposed for TCP in [RFC7661]."

**RFC 2861 — TCP Congestion Window Validation** — Experimental, 2000-06 <https://www.rfc-editor.org/rfc/rfc2861.txt>
**原话**："the TCP sender should not increase the congestion window when the TCP sender has been application-limited (and therefore has not fully used the current congestion window). This restriction prevents the congestion window from growing arbitrarily large, in the absence of evidence that the congestion window can be supported by the network."
另：**"decay the congestion window by half for every RTT that the flow has remained idle"**（每空闲 1 RTT 砍半 cwnd）。

**RFC 7661 — Updating TCP to Support Rate-Limited Traffic** — Experimental, 2015-10 <https://www.rfc-editor.org/rfc/rfc7661.txt>
§1 目标之一："**To avoid a TCP sender growing a large 'non-validated' cwnd, when it has not recently sent using this cwnd.**"
§2（**评 RFC 2861**，tier1 异见，见 §3.4）**原话**："RFC 2861 … sought to address important issues **but failed to deliver a widely used solution**. This document therefore reclassifies the status of RFC 2861 from Experimental to Historic."
§4.4.2 Sender Burst Control during the Non-validated Phase；§4.4.3 end-of-NVP 调整。

### 2.2 我们的证据放到这套语义里，结论是什么

**我们的证据**：内核报 `app_limited`（写队列空），而流量呈 11MB 簇 + 簇后 1 RTT 停顿。

**裁决：直接可用（作为排除性判据）——「app_limited 是症状不是病根」。**

论证链（每步都有 tier1 支撑）：
1. Linux 只在**「写队列 < 1 MSS 且 qdisc/NIC 队列空 且 未被 cwnd 限制 且 丢失已重传」**时才标 `app_limited`（`tcp_rate.c`）。⇒ 报出 `app_limited` **恰恰证明 cwnd 不是当时的瓶颈**，是**应用侧没数据可写**。这与「内核说谎」相反。
2. BBR 拿到 `is_app_limited` 样本后的行为是**规范规定的**：丢弃该样本（除非它抬高 max_bw）（BBRv3 §5.5.4/§5.5.5、Linux `bbr_update_bw`）、**不计入 full-bw 判定**（Linux `bbr_check_full_bw_reached`）、**不涨 cwnd**（RFC 9002 §7.8、RFC 2861）。
3. 因此 **BBR 没有「失真」需要修**；它在如实执行规则。**去调 BBR 参数（cwnd_gain / 起始增益 / ProbeRTT）是错的方向**——这是本轨最硬的一条排除性结论。
4. 反过来推论更重要：**BBR 报 `app_limited` ⇒ 停顿期间是「上层没喂数据」，不是「网络没带宽」。** 所以「周期性停 1 RTT」必须到 h2 层 / bridge 层 / CPU 层去找，TCP 层是**证人不是被告**。

**「相位化伪造」到底会不会伤 BBR？会，但伤的是 BBR 的「管道已填满」判定，不是吞吐上限。**
- 相位化（簇→停顿→簇）会让 `C.app_limited` 在**下一簇的头部**仍处于置位状态（清标记的条件是「bubble 被 ACK 掉」，即上一簇全部确认，需要 ~1 RTT）。于是**新簇的头若干个样本被打成 app-limited**。
- 由于 `UpdateMaxBw` 的例外条款「app-limited 样本若 delivery_rate > max_bw 仍采纳」，**bw 上限估计不会被系统性压低**（这是好消息，避免了「BBR 永远以为链路很慢」）。
- 但 `bbr_check_full_bw_reached` **完全跳过 app-limited 轮次** ⇒ 若相位化让「绝大多数轮次」都带 app-limited 标记，BBR 可能**迟迟无法判定「管道已填满」**，在 Linux 实现里表现为长期停留在 STARTUP 语义（`full_bw_reached=0`）⇒ `bbr_update_gains` 保持 startup 增益 ⇒ **过度 pacing → 队列堆积 → 丢包 → 反过来把吞吐打下去**。
- 这条链是 tier1 可查的（`tcp_bbr.c` + draft §3.8「BBR does not deal well with persistently application limited traffic」），**但它是 Linux BBR 的路径，我们的 xhttp 走的是 h2 over TLS over TCP，内核是 `bbrplusv3`**（Google 补丁版 BBRv3，行为对齐 draft）⇒ 结论对内核 BBRv3 成立。
- **裁决：需改造**（不是「改 BBR」，而是「不要让应用相位化到把 TCP 饿死」——即 I3/I4）。**不引入新依赖**。

**我们自己的 QUIC BBR 实现（若将来走 h3/xhttp-over-QUIC）需自查同款语义**：
- `crates/xray-transport-quic/src/congestion_swappable/bbr/bandwidth_sampler.rs`：`on_app_limited(&mut self, packet_number)`、`sample_is_app_limited`、`app_limited_packets: HashMap<PacketNumber,()>`、`remove_obsolete_packets`（按水位线回收标记）。
- `crates/xray-transport-quic/src/congestion_swappable/bbr/bbr_sender.rs`：`last_sample_is_app_limited`、`has_no_app_limited_sample`、`is_app_limited_recovery`。
- **建议（只报告，不实施）**：核对这处是否实现了 draft §5.5.5 的「app-limited 样本仅在抬高 max_bw 时采纳」与「app-limited 轮次不计入 full-bw 判定」两条。**裁决：需改造（待审计）**，**不引入新依赖**。

### 2.3 外部已知的「app-limited 被误判」问题与处理办法（汇总）

| 症状 | 已知机制 | 处理办法 | 出处 |
|---|---|---|---|
| 长期 app-limited → BBR 测不到链路带宽 | BBR 明确承认对「持续 app-limited」处理不佳 | 保留旧的非 app-limited max 样本（不丢弃） | BBRv3 draft §3.8 |
| app-limited 样本污染 max_bw | 默认丢弃；仅当抬高 max_bw 时采纳 | 采纳门槛 = `delivery_rate >= max_bw` | BBRv3 §5.5.4/5.5.5；Linux `bbr_update_bw` |
| app-limited 轮次让「管道已填满」永远判不出来 | Linux `bbr_check_full_bw_reached` 直接 return | （draft 未给规避法）→ 只能从**应用侧**消除相位化 | Linux `tcp_bbr.c`；BBRv3 §3.8 |
| 空闲后 cwnd 变成「未验证的大窗」，恢复时爆发 | RFC 2861 提出每空闲 1 RTT 砍半；**官方判其无效（Historic）** | 用 RFC 7661 的 Non-Validated Phase + burst 控制替代 | RFC 2861；RFC 7661 §1/§2/§4.4.2 |
| pacing 造成的「半 RTT 发半 RTT 停」 | Rapid Start 指出经典 paced slow start **起手就浪费半个 RTT** | 首发窗口铺满一个整 RTT；窗口 3×/RTT 增长直到出现排队 | draft-kazuho-ccwg-rapid-start-02 §1/§3.1/§3.2 |

---

## 3. 流控窗口与 BDP 的定量关系；退款批粒度；以及**反例**

### 3.1 「窗口 ≥ 1.5×BDP」的出处与反驳（**必答题**）

**出处（tier1 源码）——gRPC-Go `internal/transport/bdp_estimator.go`**
<https://raw.githubusercontent.com/grpc/grpc-go/master/internal/transport/bdp_estimator.go>
```go
	// alpha is a constant factor used to keep a moving average of RTTs.
	alpha = 0.9
	// If the current bdp sample is greater than or equal to
	// our beta * our estimated bdp and the current bandwidth
	// sample is the maximum bandwidth observed so far, we
	// increase our bdp estimate by a factor of gamma.
	beta = 0.66
	// To put our bdp to be smaller than or equal to twice the real BDP,
	// we should multiply our current sample with 4/3, however to round things out
	// we use 2 as the multiplication factor.
	gamma = 2
	...
	// The number of bytes accumulated so far in the sample is smaller than or equal
	// to 1.5 times the real BDP on a saturated connection.
	bwCurrent := float64(b.sample) / (b.rtt * float64(1.5))
```
**判读（tier1）**：这里的 `1.5` **不是窗口尺寸规则**，而是 gRPC 那个「BDP ping」采样法的**测量偏置修正**：两次 ping 之间收到的字节数最多可到 1.5×真实 BDP，所以除以 1.5 才能还原真实速率；真正写进 h2 窗口的是 `b.bdp = gamma × sample = 2 × sample`。因此**gRPC 实际通告的窗口 ≈ 2×(采样样本) ∈ [2×BDP, 3×BDP]**（样本落在 [BDP, 1.5×BDP] 区间时），并被 `bdpLimit = 16MB` 截断。
⇒ **「1.5×BDP」是「gRPC 的一个内部除数」被业界当成「行业窗口规则」传抄。**

**反驳（tier1 规范）**：
- RFC 9113 §5.2.3 与 RFC 9000 §4.3 都只要求 **「> BDP」**，没有任何 1.5 或 2 的系数。
- BBRv3（draft §5.6.4.2）用的是 **2×BDP**（cwnd_gain 默认 2）+ extra_acked；§5.3.3.5 的 ProbeBW_UP 用 **1.25×BDP**。
- RFC 9002 §7.7 pacing 的速率公式是 `rate = N × cwnd / smoothed_rtt`，`N` 建议「小但至少 1（例如 1.25）」——又一个 1.25，但它作用在**速率**而非**窗口**上。

**裁决**：
- 把「1.5×BDP」当**规则**用 → **不适用**（无规范依据，且该常数的原意被误读）。
- 把 gRPC 的**方法**（用 ping/采样实测 BDP，而不是猜）→ **需改造**（可白拿思路，且**不需要新依赖**：它是「发一个探针、量一个 RTT 内收到多少字节」，我们已有 `crates/xray-transport-splithttp/src/flow_window.rs` 的 `H2Windows`/`ENV_OVERRIDE` 诊断开关与 `crates/xray-transport/src/bridge.rs` 的 `ByteGate` 可挂观测点）。**注意**：gRPC 那套的前提是「接收方自己测自己的 BDP」，而我们的对端是 Cloudflare 边缘，**我们无权改对端的窗口策略**——这才是真正的限制（见 §3.3）。

### 3.2 「退款批粒度（large WU vs 小 WU）」对吞吐/失速的影响

**tier1 原文**：RFC 9000 §4.2（已引，见 §1.1）——「频繁小额度 WU ⇒ 控制帧开销大；额度少而大 ⇒ 接收方资源承诺更大」；且「**接收方在拿到信用后可能一次性发大量数据 ⇒ 造成短时拥塞**」。
**裁决：直接可用**（tier1 规范已经把 trade-off 写死了，我们不需要自己发明「批粒度最优值」）。

**tier2 工业实践（供对照，非推荐）**：quic-go 官方文档 — Flow Control / Auto-Tuning of the Receive Window
<https://quic-go.net/docs/quic/flowcontrol/>：「When a stream – or the connection in total … – consumes the entire flow control (or close to that value) over any RTT, this is a sign that the flow control window might too small … In that case, **the auto-tuning logic doubles the receive window. The flow control window is doubled until either the peer doesn't utilize the entire window within one RTT, or until the configured maximum value is reached.**」
**裁决：不适用**（理由同上：接收窗是**对端**的策略，我们管不了；且 xhttp 路径上窗口由 Cloudflare 边缘通告）。

**「窗口大反而更慢」的反例（tier1，RFC 9113 §10.5 / §5.2.2 与 RFC 9000 §4.2）**：
- 「窗口大 → 内存承诺大 → 接收方资源风险」是**规范层面的代价**（RFC 9113 §5.2.2、§10.5；RFC 9000 §4.2「requiring larger resource commitments at the receiver」）。
- 「窗口大 → 一次性放行大量数据 → 短时拥塞」是**规范层面明写的风险**（RFC 9000 §4.2 末句）。
- 但**这两条都不是「窗口大导致吞吐下降」的直接证据**。真正的 tier1 直接反例在下一节（路由器缓冲侧的同构实验），以及 §3.3 的「大 WU 突发 → 丢包 → cwnd 塌 → 反而更慢」链。

### 3.3 「大窗口/更多连接反而更慢」的 tier1 反证（**异见轨主体，见 §4**）

见 §4（McKeown 2019、Barakat&Altman 2004、Bless 2025）。

### 3.4 「更多连接 ≠ 更高长路径吞吐」的 tier1 支撑

- **Mathis et al. 1997**（tier1）§Phase Effects：单流 AIMD 锯齿在共享 drop-tail 瓶颈上互相**相位耦合**，一条流的丢包会改变另一条的窗口演化；并指出「TCP 的 Selfclock 在成簇丢包下脆弱」。
- **Bless, Lihotzki, Zitterbart — "Insights into BBRv3's Performance and Behavior by Experimental Evaluation"**, IFIP Networking 2025 <https://networking.ifip.org/2025/images/Net25_papers/1571125683.pdf>（tier1 会议论文）**原话**：「Because the bandwidth estimate uses a maximum filter, multiple flows estimate their own bandwidth share based on the sample from their respective UP phase. **Therefore, the sum of these estimates can be larger than the available bottleneck bandwidth.**」且实测「流数从 16 增到 32，QD 几乎翻倍，而各流带宽估计之和与 RTTmin 并无可见变化」——即**加连接数不增吞吐、只增排队延迟与不公平**。
- **同文**：BBRv3 单流也会「regularly adds 0.95 RTTmin queuing delay」，多流时「more than 1 RTTmin over 50% of the time」。
- **RFC 9002 §7.7**：pacing 是必需的；「Sending multiple packets into the network without any delay between them creates a packet burst that might cause short-term congestion and losses. **Senders MUST either use pacing or limit such bursts.**」
- **裁决：直接可用**（tier1；直接反驳「ws 每请求一条 TCP 所以更快 ⇒ 加连接数是解法」这一推论——ws 快可能与**连接新鲜（无相位化停顿）**有关，而非连接数本身。）

### 3.5 启动延迟（slow start on long paths）

- **BBRv3 draft §5.4.2**（tier1）：「log₂(BDP)\*RTT」的慢启动重启代价 ⇒ 「many large deployments disable this mechanism」；BBR 的做法是重启时直接按 `BBR.bw` 起步（§5.4.1 `HandleRestartFromIdle()`），「typically achieving approximate rate balance and a full pipe after only one BBR.min_rtt has elapsed」。
- **算术**（[INFERENCE]，基于 tier1 公式）：200ms RTT、目标 40MB/s ⇒ BDP = 8MB；IW=10 段 ≈ 14.6KB ⇒ `log₂(8MB/14.6KB) ≈ 9.1` RTT ≈ **1.8 s** 才能填满管道。**每一次「簇后停 1 RTT」若超过 RTO，就会触发 cwnd 重置（RFC 5681 §4.1 `RW = min(IW, cwnd)`），下一次又是 ~1.8s 爬坡。**
- **Rapid Start draft**（tier1，CCWG 2026-03）<https://www.ietf.org/archive/id/draft-kazuho-ccwg-rapid-start-02.html>：指出经典 paced slow start「起手铺半个 RTT 然后空半个 RTT ⇒ 瓶颈有一半时间是闲的」；做法是首发窗口铺满**一个整 RTT**、窗口按 **3×/RTT** 增长直到观察到排队。
  **裁决：不适用**（理由：Rapid Start 是**拥塞控制的启动算法**，我们的启动慢不是拥塞控制启动慢，而是**应用相位化 + 流控阻塞**导致的中途归零；换启动算法不解决中途归零。而且它要改内核/用户态 CC，代价远超收益）。**但它提供了一条可迁移的观察**：「一个整 RTT 内铺满」比「半个 RTT 铺满」少浪费半个 RTT——若将来我们自研用户态发送器，可作为节奏参考（不引入新依赖）。

---

## 4. Munger 反转轨：异见与反例（**tier1 必含**）

### 4.1 tier1 异见 #1 ——「缓冲开大不但不快，还更慢」

**McKeown, Appenzeller, Keslassy — "Sizing Router Buffers (Redux)"**, ACM SIGCOMM CCR 49(5), 2019
<http://web.stanford.edu/class/cs244/papers/sizing-router-buffers-redux.pdf>
**原话**：
> "if we make the buffer bigger, the bottleneck link will always be busy, but the buffer will never go empty and packets will unnecessarily encounter a fixed additional delay. **Put another way, there is no benefit to making the buffer bigger: It will increase latency and the congestion control algorithm will be more sluggish because it has to deal with a longer response time.**"
并给出与「1×BDP」不同的结论（Small Buffers 结果）`B ≥ C·RTT_min/√N`（N 为长寿命流数）。
（⚠️ 该文自述为 editorial note，「has NOT been peer reviewed」，但作者是 SIGCOMM'04 原作者，发表于 CCR。）
**裁决：直接可用**（tier1）。**意义**：**「把窗口/缓冲开大」在长肥网络上是行业已知的错误直觉**——它是「多扛一点抖动」的保险，不是提速手段。

### 4.2 tier1 异见 #2 ——「更激进反而更慢」

**Barakat, Altman — "Impact of Buffer Size on TCP Start-Up"**, INRIA 2004
<http://www-sop.inria.fr/members/Eitan.Altman/PAPERS/AUB.pdf>
**原话（结论段）**：
> "we found that, **on paths with small buffers compared to their BDP**, the congestion during SS may appear early before filling the pipe size. … **In this case, we found that any increase in TCP aggressiveness deteriorates the performance instead of improving it.**"
（具体：大缓冲路径上 Byte Counting（更激进）比标准 TCP 更好；小缓冲路径上 Byte Counting **更差**。）
**裁决：直接可用**（tier1）。**意义**：**「把我们的窗口/发送节奏调得更激进」这条直觉，在缓冲小的路径上被实测证伪过**——与简报 §2 里「调大流窗/连窗/改退款粒度」全平甚至更差的实测方向一致。

### 4.3 tier1 异见 #3 ——「官方判死了一整类修法」

**RFC 7661 §2**（tier1，见 §2.1 原文）：**RFC 2861 的思路（app-limited 期后砍 cwnd / 按空闲时长衰减）被判为 Historic，「failed to deliver a widely used solution」**；并明说「**an attempt to classify application behaviour as application-limited or idle is problematic and also inappropriate**」。
**裁决：直接可用**（tier1）。**意义**：我们正要讨论的「识别 app-limited 相位并据此调参」这一整族做法，**标准社区已经走过并否决过一次**——应该先怀疑「别去动 cwnd」，而不是「再加一层相位识别逻辑」。

### 4.4 tier1 异见 #4 ——「加连接数不增吞吐，只增排队」

**Bless, Lihotzki, Zitterbart**, IFIP Networking 2025（tier1，见 §3.4 原文）：BBRv3 多流时各流带宽估计之和 > 实际瓶颈带宽；流数 16→32 时排队延迟近翻倍。
**裁决：直接可用**（tier1）。**意义**：「ws 每请求一条 TCP 所以更快」不能推出「加连接数是解法」；ws 的优势更可能来自**连接新鲜、无相位化停顿**。

### 4.5 tier1 异见 #5 ——「窗口开小也不是更快」（防止矫枉过正）

**Vu-Brugier, Stanojevic, Leith, Shorten — "A Critique of Recently Proposed Buffer-Sizing Strategies"**, ACM SIGCOMM CCR 37(1), 2007
<http://ccr.sigcomm.org/online/files/p43-v37n1f-leith.pdf>
实测（生产链路，3KB ≈ 2 个 1500B 包的小队列）：「the packet loss rate remains persistently high (at around 20%) while link utilisation remains consistently below 60% … due to the large number of user complaints regarding link quality during this test … **the test was terminated after 2.5 hours**」。
并指出「buffer sizing strategies depend crucially on the nature of the arriving traffic … Real links almost always contain a complex mix of flow connection lengths, round-trip times, UDP traffic」。
**裁决：直接可用**（tier1）。**意义**：**「窗口/缓冲砍小」同样不是提速手段**；两条方向都被证伪过 ⇒ 真正能动的是**别让窗口成为瓶颈**（即 I1/I2），不是拧大/拧小窗口本身。

### 4.6 tier1 异见 #6 ——「中间层不该自己接管端到端的窗口决策」

**RFC 9293 §3.8.6**（tier1）：
> "A TCP receiver **SHOULD NOT** shrink the window … However, a sending TCP peer **MUST** be robust against window shrinking … **The robustness principle dictates that TCP peers will not shrink the window themselves**, but will be prepared for such behavior on the part of other TCP peers."
以及 §3.8.6.2.1 发送方 SWS 规避里「sender … use [Max(SND.WND)] as an estimate of RCV.BUFF … Unfortunately, this can only be an estimate」——**端到端窗口由接收方语义决定，发送方只能估算、不能代管**。
**裁决：需改造（作为原则约束）**。**意义**：代理/中间层若去替对端决定窗口语义，会破坏这条「端到端所有权」；我们的角色应是**不成为瓶颈**（自己的内存闸/发送缓冲不阻塞对端），而不是**替对端定窗**。这条与简报 §2「显式 SO_RCVBUF = 锁窗 = 更差」在方向上一致。

### 4.7 tier2/3 异见补充

- **Mark Allman — "Comments on bufferbloat"**, CCR 2013（**tier2**：评论文章，但同期 CCR 同刊）<https://mallman.net/pubs/All13a/All13a-review.html>：**"While there has been a lot of buzz … there has been little empirical understanding of the scope of the phenomenon. Yet, the supposed problem is being used as input to engineering decisions about the evolution of protocols."** 结论：bufferbloat 的**量级「quite modest」**，「little or no proof of large scale persistent queues」。
  **裁决：直接可用（作为「不要把 bufferbloat 当万金油解释」的提醒）**。
- **Su et al. — "Rethinking the rate estimation of BBR congestion control"**, Electronics Letters 56(5), 2020 <https://ietresearch.onlinelibrary.wiley.com/doi/10.1049/el.2018.6440>（tier2/期刊）：**ACK 压缩**使 BBR 的可用带宽估计失准 ⇒ 高排队。
  **裁决：需改造（作为「相位化退款 ⇒ ACK 聚集 ⇒ 带宽估计失真」的旁证，但机制与我们的 app-limited 链不同源）**。
- **oBBR (USENIX ATC'23)** <https://www.usenix.org/system/files/atc23-bi.pdf>（tier1 会议论文）：「BBR estimates the bottleneck bandwidth with the **maximum** delivery rate samples … If the bandwidth drops, BBR will not update the bandwidth estimate」⇒ 带宽下降时估计滞后。
- **"BBR Bufferbloat in DASH Video"**, WWW 2021 <http://netsys.cs.stonybrook.edu/sites/netsys.cs.stonybrook.edu/files/2024-06/www21_bbr.pdf>（tier1 会议论文）：深缓冲下 BBR **严重高估带宽** ⇒ 长队列 ⇒ 视频体验退化。
- **quic-go 官方文档** <https://quic-go.net/docs/quic/flowcontrol/>（tier2）：接收窗自调「doubling until the peer doesn't utilize the entire window within one RTT」⇒ **工业界把「窗口利用率」而非「窗口大小」当作调参信号**。
- **bbr-dev 邮件列表 "Application limited" 讨论** <https://groups.google.com/g/bbr-dev/c/ymEStT_t3LI>（tier3）：社区口径与 draft §5.5.4 一致（app-limited 包不参与 bw 估计，除非抬高当前 max）。
- **arXiv 2512.18259「TCP BBR Performance over Wi-Fi~6: AQM Impacts and Cross-Layer Insights」**（tier2/预印本）<https://arxiv.org/pdf/2512.18259.pdf>：AQM 下 BBR 的表现依赖 RTT 与队列状态。

---

## 5. 对简报三条引用的事实更正

### 5.1 `RFC 7414（High-BDP TCP）` ⇒ **不是规范，是路线图**（tier1）

见 §1.1。RFC 7414 是 Informational 路线图，**通篇没有给出任何高 BDP 的数值不变量**，只是把相关 RFC 列出来（§3.1 → RFC 7323/2675；§3.2 → RFC 6928/3465；§3.3 → RFC 3782/3042）。**裁决：不适用**（作不变量来源）／**直接可用**（作索引）。真正该引的是 **RFC 7323 §1.1** 与 **RFC 9293 §3.8.6**。

### 5.2 `Bufferbloat / Nicolaides「dark buffer」模型` ⇒ **归属有误**

- 「dark buffer」一词的出处是 **Gettys & Nichols — "Bufferbloat: Dark Buffers in the Internet"**，ACM Queue 9(11), 2011-11 / CACM 55(1), 2012-01 / IEEE Computer 15(3), 2011。
  <https://queue.acm.org/detail.cfm?id=2071893>（tier1 论文；ACM 站点对本代理返回 403，已用多处镜像与参考文献交叉确认：CACM 55(1):57、IEEE Computer 2011、DOI 10.1145/2063176.2063196 / 10.1145/2063166.2071893）。
- **Kathleen Nichols & Van Jacobson — "Controlling Queue Delay"**, ACM Queue 10(5), 2012 <https://queue.acm.org/doi/10.1145/2208917.2209336>（tier1）——这是把「队列持续满载 = 暗缓冲」的**可测量模型**（min-so-far 队列估计）写出来的那篇。
- **Virginia Nicolaides** 是**另一位**研究者（队列调度/公平性方向）。我未找到任何由她署名的「dark buffer」模型论文。
  ⇒ 简报这里大概率是 **Nichols ↔ Nicolaides 的名字混淆**。
- **裁决：直接可用**（把「dark buffer」按 Gettys & Nichols 正确引用即可），但**对我们无直接可执行项**——dark buffer 讲的是**路由器队列**，而我们的路径瓶颈在 Cloudflare 边缘与客户端侧，**我们既不控制其 AQM 也不控制其队列深度** ⇒ 作为**解释框架**有用（提醒「加缓冲会掩盖拥塞而非提速」），作为**行动项不适用**。

### 5.3 `Dunn et al. 2012「double increase」` ⇒ **查无此文**

我用了 6 组不同检索式去查，均无匹配（记录如下）：① `"double increase" TCP congestion window`；② `"double increase" TCP "initial window" slow start RFC 6928 OR 3390 explanation`；③ `Dunn 2012 TCP "double increase" congestion window`；④ `Dunn 2012 TCP initial window startup long paths paper authors`；⑤ `"Dunn" 2012 "double" increase window HTTP/2 OR QUIC OR TCP startup paper Saroiu Gummadi content delivery`；⑥ `"Dunn" 2012 tcp "double" OR "twice" initial window increase segments SIGCOMM INFOCOM paper pdf`。
命中的「Dunn」全部是 **Richard J. Dunn**（OSDI'02《An Analysis of Internet Content Delivery Systems》与 Gummadi 等的文件共享负载测量），**与 TCP 启动/窗口无关**；「double increase」在 TCP 文献里的所有实际用法都指向 **slow start 每 RTT 翻倍**（RFC 2001 §1、RFC 5681 §3.1）或 **IW 从 2-4 段提到 10 段**（RFC 3390 → RFC 6928），没有 2012 年的「Dunn et al.」论文。
⇒ **裁决：查不到 + 试过什么**（如上）。**替代出处（tier1，等价覆盖其意图）**：
  - **慢启动每 RTT 翻倍** → RFC 2001 §1、RFC 5681 §3.1；
  - **IW 提升** → RFC 3390（1-2 → 4 段）、RFC 6928（→ 10 段）；
  - **「更激进地爬坡」在长肥路径上的实测代价与收益（含「小缓冲下更激进反而更差」的反例）** → Barakat & Altman 2004（§4.2 已引）；
  - **「跳过慢启动、直接按实测 bw 起步」** → BBRv3 draft §5.4.1/§5.4.2。

---

## 6. 落到我们这栈：该改的是「哪一层」，不是「哪个窗口」

综合 §1–§4，论文/RFC 轨给出的**分层裁决**（供方案选型用；不含实现）：

| 层 | 论文/RFC 轨裁决 | tier1 依据 |
|---|---|---|
| **内核 TCP/BBR** | **不要动**。报 `app_limited` 是准确诊断；BBR 的处理是规范行为；cwnd/inflight 模型（2×BDP / 1.25×BDP）是我们判据的对照基线 | RFC 9002 §7.8、RFC 2861/7661、Linux `tcp_rate.c`/`tcp_bbr.c`、BBRv3 §3.8/§5.5/§5.6.4 |
| **h2 流控窗 / 退款粒度** | 简报 §2 已关死，本轨**复核同意**：RFC 9113 §5.2.3/§9000 §4.3 的「> BDP」是**下限**而非提速旋钮；「1.5×BDP」是误传；大 WU 有规范明写的突发风险 | RFC 9113 §5.2.3/§5.2.2/§10.5、RFC 9000 §4.2/§4.3、gRPC-Go 源码 |
| **我们的 bridge 字节闸 / 内存档** | **这才是嫌疑点**：闸（`MemoryPlan::bridge_gate`，四档 5/12/24/32 MiB/方向）若周期性打满，会让上层「无数据可写」→ TCP 报 `app_limited` → 与观测到的 11MB 簇同量级。**先量闸占用的时间序列，再谈别的** | RFC 9293 §3.8.6、Mathis 1997（"sender does not always have data to send"）、Linux `tcp_rate.c` |
| **客户端接收窗（64 KiB）** | **强嫌疑，但属台架/客户端侧**：RFC 7323 §1.1 的 64 KiB 硬上限在 200ms 下即 2.6Mbps；受控台 `65536 B / 0.4 s = 1.31Mbps` 与观测 `delivery_rate 1.31Mbps` **数值相等** ⇒ 受控台可能整体撞在客户端接收窗上，**xhttp==ws 是台架伪影** | RFC 7323 §1.1、RFC 9293 §3.8.6.2.2、RFC 6349（测量口径） |
| **启动/重启** | 若停顿超过 RTO ⇒ cwnd 重置（RFC 5681 §4.1 `RW=min(IW,cwnd)`）⇒ 再花 `log₂(BDP/IW)·RTT ≈ 1.8s` 爬坡。**判定「停顿时长 vs RTO」是必须的一步测量** | RFC 5681 §4.1、RFC 6928、BBRv3 §5.4.2 |
| **加连接数 / 并行流** | **不推荐**：多流时各流带宽估计之和 > 实际瓶颈带宽，排队延迟随流数上升；ws 的优势更可能来自「连接新鲜、无相位化」 | Bless 2025、Mathis 1997（phase effects）、RFC 9002 §7.7 |

**建议的最小下一步测量（零代码 / 只读，不改配置）**：
1. 受控台客户端侧抓完整 `ss -tin`（含 `wscale:`、`rcv_wnd`、`app_limited`、`cwnd`、`delivery_rate`）与 `net.ipv4.tcp_rmem` / `tcp_window_scaling`；确认 64 KiB 是否为硬顶 → 判别 I2。
2. 节点侧同时抓 `ss -tin`（node↔client 方向）与 bridge 闸占用时间序列 → 判别 I3 是否被违反（闸打满 ⇒ 周期 11MB 簇）。
3. 量「停顿时长」并与 RTO 比 → 判别是否触发 cwnd 重置（I7）。
4. 客户端 `wscale` 未协商 ⇒ 直接落 RFC 7323 §1.1 的 64 KiB 顶 ⇒ **受控台结论不可用于生产**（生产 44-66MB/s 说明生产客户端窗是够的，差距在别处）。

---

## 7. 引用清单（分层）

### tier1（论文 / RFC / IETF draft / 内核与项目源码）

1. RFC 7414 — A Roadmap for TCP Specification Documents — <https://www.rfc-editor.org/rfc/rfc7414.txt>（Informational, 2015-02）
2. RFC 7323 — TCP Extensions for High Performance — <https://www.rfc-editor.org/rfc/rfc7323.txt>（Standards Track, 2014-09）§1.1
3. RFC 9293 — Transmission Control Protocol (TCP) — <https://www.rfc-editor.org/rfc/rfc9293.txt>（Standards Track, 2022-08）§3.8.6 / §3.8.6.2.2 / A.4
4. RFC 2001 — TCP Slow Start, Congestion Avoidance, Fast Retransmit, Fast Recovery — <https://www.rfc-editor.org/rfc/rfc2001.txt>（1997-01）§1
5. RFC 5681 — TCP Congestion Control — <https://www.rfc-editor.org/rfc/rfc5681.txt>（Standards Track, 2009-08）§3.1 / §4.1
6. RFC 3390 — Increasing TCP's Initial Window — <https://www.rfc-editor.org/rfc/rfc3390.txt>（2002-10）
7. RFC 6928 — Increasing TCP's Initial Window — <https://www.rfc-editor.org/rfc/rfc6928.html>（Experimental, 2013-04）
8. RFC 9000 — QUIC — <https://www.rfc-editor.org/rfc/rfc9000.txt>（Standards Track, 2021-05）§4.1–§4.3
9. RFC 9002 — QUIC Loss Detection and Congestion Control — <https://www.rfc-editor.org/rfc/rfc9002.txt>（Standards Track, 2021-05）§7.2 / §7.7 / §7.8
10. RFC 9113 — HTTP/2 — <https://www.rfc-editor.org/rfc/rfc9113.txt>（Standards Track, 2022-06）§5.2.2 / §5.2.3 / §6.9.2 / §10.5
11. RFC 2861 — TCP Congestion Window Validation — <https://www.rfc-editor.org/rfc/rfc2861.txt>（Experimental, 2000-06；**已被 RFC 7661 判 Historic**）
12. RFC 7661 — Updating TCP to Support Rate-Limited Traffic — <https://www.rfc-editor.org/rfc/rfc7661.txt>（Experimental, 2015-10）§1 / §2 / §4.4
13. RFC 6349 — Framework for TCP Throughput Testing — <https://www.rfc-editor.org/rfc/rfc6349.txt>（Informational, 2011-01）
14. draft-ietf-ccwg-bbr-07 — BBR Congestion Control — <https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-07.html>（CCWG, 2026-11-02, Experimental）§3.8 / §4.1.2.4 / §5.3.3.5 / §5.4 / §5.5.4 / §5.5.5 / §5.6.4
15. draft-kazuho-ccwg-rapid-start-02 — Rapid Startup of Congestion Control — <https://www.ietf.org/archive/id/draft-kazuho-ccwg-rapid-start-02.html>（CCWG, 2026-03, Standards Track）
16. Linux `net/ipv4/tcp_rate.c` (v6.12) — <https://raw.githubusercontent.com/torvalds/linux/v6.12/net/ipv4/tcp_rate.c>
17. Linux `net/ipv4/tcp_bbr.c` — <https://raw.githubusercontent.com/torvalds/linux/master/net/ipv4/tcp_bbr.c>
18. grpc-go `internal/transport/bdp_estimator.go` — <https://raw.githubusercontent.com/grpc/grpc-go/master/internal/transport/bdp_estimator.go>
19. Mathis, Semke, Mahdavi, Ott — The Macroscopic Behavior of the TCP Congestion Avoidance Algorithm — ACM SIGCOMM CCR 27(3), 1997 — <http://ccr.sigcomm.org/archive/1997/jul97/ccr-9707-mathis.pdf>
20. McKeown, Appenzeller, Keslassy — Sizing Router Buffers (Redux) — ACM SIGCOMM CCR 49(5), 2019 — <http://web.stanford.edu/class/cs244/papers/sizing-router-buffers-redux.pdf>
21. Barakat, Altman — Impact of Buffer Size on TCP Start-Up — INRIA, 2004 — <http://www-sop.inria.fr/members/Eitan.Altman/PAPERS/AUB.pdf>
22. Vu-Brugier, Stanojevic, Leith, Shorten — A Critique of Recently Proposed Buffer-Sizing Strategies — ACM SIGCOMM CCR 37(1), 2007 — <http://ccr.sigcomm.org/online/files/p43-v37n1f-leith.pdf>
23. Gettys, Nichols — Bufferbloat: Dark Buffers in the Internet — ACM Queue 9(11) 2011 / CACM 55(1) 2012 / IEEE Computer 15(3) 2011 — DOI 10.1145/2063176.2063196 — <https://dl.acm.org/doi/10.1145/2063176.2063196>
24. Nichols, Jacobson — Controlling Queue Delay — ACM Queue 10(5), 2012 — <https://queue.acm.org/doi/10.1145/2208917.2209336>
25. Bless, Lihotzki, Zitterbart — Insights into BBRv3's Performance and Behavior by Experimental Evaluation — IFIP Networking 2025 — <https://networking.ifip.org/2025/images/Net25_papers/1571125683.pdf>
26. Vargas, Drucker, Renganathan, Balasubramanian, Gandhi — BBR Bufferbloat in DASH Video — WWW 2021 — <http://netsys.cs.stonybrook.edu/sites/netsys.cs.stonybrook.edu/files/2024-06/www21_bbr.pdf>
27. Bi et al. — oBBR: Optimize Retransmissions of BBR Flows on the Internet — USENIX ATC 2023 — <https://www.usenix.org/system/files/atc23-bi.pdf>
28. Appenzeller, Keslassy, McKeown — Sizing Router Buffers — ACM SIGCOMM 2004 — <https://web.stanford.edu/class/cs244/papers/SizingRouterBuffersAppenzeller.pdf>

### tier2 / tier3（官方文档、issue、评论、邮件列表、博客）

29. quic-go 官方文档 — Flow Control（含 Auto-Tuning of the Receive Window）— <https://quic-go.net/docs/quic/flowcontrol/>
30. Allman — Comments on bufferbloat — ACM CCR, Jan 2013 — <https://mallman.net/pubs/All13a/All13a-review.html>
31. Su et al. — Rethinking the rate estimation of BBR congestion control — Electronics Letters 56(5), 2020 — <https://ietresearch.onlinelibrary.wiley.com/doi/10.1049/el.2018.6440>
32. bbr-dev 邮件列表 — "Application limited" 讨论 — <https://groups.google.com/g/bbr-dev/c/ymEStT_t3LI>
33. arXiv:2512.18259 — TCP BBR Performance over Wi-Fi~6: AQM Impacts and Cross-Layer Insights（预印本）
34. BBRv3 相关 IETF 会议材料 — <https://datatracker.ietf.org/meeting/117/materials/slides-117-ccwg-bbrv3-algorithm-bug-fixes-and-public-internet-deployment-00>

---

## 8. 自评与声明

- **tier1 来源数**：28（要求 ≥3）✅；**tier2/3**：6（要求 ≥5）✅
- **「不适用」裁决**：≥4 处（RFC 7414 作不变量来源 / 「1.5×BDP」当规则 / dark buffer 作行动项 / Rapid Start 作解法）✅
- **未复述简报 §2 的 7 条死路**：本报告 §3.2 对「调 h2 窗/退款粒度」的表述是**复核同意其已死**，并给出 tier1 依据；未把它们列为推荐。
- **未改任何代码/配置**；纯调研 ✅
- **新依赖**：本轨**所有建议均为零新依赖**（RFC 9000/9113 是既有协议语义；BBRv3 draft 对应内核已有 `bbrplusv3`；gRPC 的 BDP-ping 方法可在我们仓内已有诊断开关上实现）。
- **诚实标注**：§6 第 4 条与 §0-H 的算术等式为 **[INFERENCE]**（由 tier1 公式 + 简报给出的观测值推导），**未经实测确认**；简报 §3.1 的两条引用（`RFC 7414`、`Nicolaides dark buffer`）与 §3.1 的 `Dunn et al. 2012` 经核查**与事实不符**，已在 §5 逐条更正并给出替代出处。
- **未核查项**：(a) 受控台客户端 `wscale` / `rcv_wnd` 实测值（本机无该台架访问权）；(b) RFC 7414 §3.1 全文我只按需读取了相关小节，未逐行通读 57 页；(c) ACM Queue / DL 站点对本代理返回 403，Gettys & Nichols 与 Nichols & Jacobson 两篇正文通过镜像与 DOI 元数据交叉确认，**未读到 §4.2 之后全文**。
