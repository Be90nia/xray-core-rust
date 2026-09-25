# 高 RTT sockopt 调优指南（`sockopt.receiveBufferSize`）

日期：2026-09-17 · 出票：bd adch · 依据：docs/impl-hzcq-collapse-rootcause-2026-09-17.md（一手床数据，HEAD a882432）· 能力出处：bd o93t（inbound per-accept + outbound 已接线、有测试覆盖）

> **文档定位（随发行物分发）**：本文档为面向运维的部署调优指南，随发行物入库分发——读者是在高 RTT/跨洋长肥管链路上部署本项目的运维与自建用户；非内部实现报告。默认值策略维持 opt-in 零改动（见 §6）；内部根因证据链在 `docs/impl-hzcq-collapse-rootcause-2026-09-17.md`（本地工作台文档，不随发行物分发）。

## TL;DR

**RTT > ~50ms 的长肥管路径（跨洋/跨洲中转）**：在服务端 inbound 和客户端 outbound 的 `streamSettings` 显式加 `sockopt.receiveBufferSize: 4194304`（4MB），否则在 Linux 默认 `tcp_rmem` default=128KB 下，接收窗被钳死 → 吞吐锁在 **窗/RTT**（322ms RTT 实测塌速 1.5-2.0Mbps，塌轮概率 25%）。配置后同床 8/8 全快 31.7-40.9Mbps。宿主级备选：`sysctl -w net.ipv4.tcp_rmem="4096 8388608 34603008"`（8/8 全快 48.8-76.5Mbps）。

容量公式：`receiveBufferSize ≥ BDP = 目标带宽 × RTT / 8`。4MB @ 322ms 理论支撑 ~99Mbps，实测 31-40Mbps（瓶颈在腿上其它环节，窗已不设限）。

## 1. 症状与定量（床 199.115.231.188，netem 161ms×2 腿 ≈ 322ms RTT，REALITY+vless vision 上行 16MB）

| 配置 | 轮次 | 结果 |
|---|---|---|
| 不配（基线） | 12 轮 | **3/12 塌**（1.535 / 1.845 / 1.902 Mbps）+ 5 中速（3.3-8.2）+ 4 快（17-26），塌轮率 25% |
| per-socket 4MB | 8 轮 | **8/8 全快 31.7-40.9Mbps，塌 0/8** |
| 宿主 tcp_rmem default 8MB | 8 轮 | **8/8 全快 48.8-76.5Mbps**（3 倍历史快峰） |
| Go 26.9.9 同床对照 | 4 轮 | 4/4 快 13.8-20.4Mbps（与历史 12.5-19.0 一致）——Go 不配也不塌 |

塌轮恒速定律：**塌速 = 服务端广告窗 ÷ RTT**。实测 r9：snd_wnd 69632B ÷ 0.322s ≈ 1.73Mbps ≈ 实测 1.535；r3：79872÷0.322 ≈ 1.98 ≈ 1.845。发送端 cwnd 充足、零重传、应用有货——纯粹被对端窗钳死。

## 2. 机制：为什么 Rust 需要显式大窗，而 Go 不用

同一段 128KB 默认 rcvbuf，两个实现命运不同：

- **Go（免疫）**：服务端握手后**延迟消费**，内核接收队列积压 99-122KB 持续 ~5s；开始消费瞬间一次性吸干积压，内核 DRS（tcp_moderate_rcvbuf）的速率采样 = 积压量/耗时 → **天然爆表，必然解锁**，窗自动爬到 MB 级。Go 是被自己的"慢"意外救了。
- **Rust（自锁）**：解耦泵（master 6b53cd5 起）**即时转发**，服务端接收队列 rq 恒 0，每 RTT 到货一批立刻被吸走 → DRS 速率采样恒等于"当前窗/RTT"，采样值自我一致永远不触发扩容判据 → **确定性锁死**在 64-128KB 窗。快轮（25%）只是初始 1-2 秒 DRS 采样碰巧爆表的幸运分支。

关键差异一句话：**Go 的消费节律制造积压、积压制造解锁信号；Rust 即时消费消灭了积压，也就消灭了内核自动扩窗的依据——必须显式给窗。**

为什么"以前没事"：09-15 之前的 Rust 旧串行泵有读锁步（服务端不读→窗也开不了），那个根因在 6b53cd5 修复；但解耦泵同时消灭了"读间隙内核积压"这个意外解锁器，暴露出即时消费流在 128KB 默认 rcvbuf 下的 DRS 自锁。塌轮是修复的副产品，不是回归。

## 3. 配方（配置级，产品码 0 行）

### 3.1 服务端 inbound（关键项——上行方向接收端）

```json
{
  "inbounds": [{
    "port": 20001,
    "protocol": "vless",
    "settings": { "...": "..." },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": { "...": "..." },
      "sockopt": { "receiveBufferSize": 4194304 }
    }
  }]
}
```

### 3.2 客户端 outbound（对端代理链路）

```json
{
  "outbounds": [{
    "protocol": "vless",
    "settings": { "...": "..." },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": { "...": "..." },
      "sockopt": { "receiveBufferSize": 4194304 }
    }
  }]
}
```

### 3.3 客户端本地 inbound（socks/http，下行方向接收端）

```json
{
  "inbounds": [{
    "port": 10808,
    "protocol": "socks",
    "settings": { "auth": "noauth", "udp": false },
    "streamSettings": {
      "sockopt": { "receiveBufferSize": 4194304 }
    }
  }]
}
```

上述三处即床验证配置 `/tmp/repro8sum/r2/{srv_fix.json,cli_fix.json}` 的实际内容（8/8 全快的原样）。**方向速记**：`receiveBufferSize` 管的是"这条 socket 收"的方向——数据往哪流，哪一端的接收侧就该配。长肥管全双工场景三处都配最省心。

### 3.4 注意事项

- 值超过 `net.core.rmem_max`（床值 34603008≈33MB）会被内核**静默截断**——设大值前先查 rmem_max。
- 显式 SO_RCVBUF 会**锁定该 socket 的内核自动调节**（失去 DRS 自适应），换来确定大窗；只影响显式配置的 socket，其它连接零变化。wire-format 零变化。

## 4. 内存账

- SO_RCVBUF=4MB → 内核按 **2× 记账**（sk_rcvbuf=8MB 计入 tcp_mem 压力账），**实际物理内存只在积压到高水位时才真实占用**，空闲连接几 KB。
- 预算公式：`账面 = 并发连接数 × 8MB`。1000 并发 = 8GB 账面；**万级并发 = 80GB 账面**——会顶进 tcp_mem pressure 区触发全局回收抖动。
- 大并发部署的降档路径：receiveBufferSize 降到 1-2MB（2MB @ 322ms 仍支撑 ~50Mbps），或改走 §5 宿主级方案（无 per-socket 记账翻倍）。

## 5. 宿主级备选：tcp_rmem

```bash
# default 从 128KB 抬到 8MB（min/max 不动；需 root；影响宿主全部新 socket）
sysctl -w net.ipv4.tcp_rmem="4096 8388608 34603008"
# 持久化: 写入 /etc/sysctl.d/99-highrtt.conf
```

| 维度 | per-socket sockopt（§3） | 宿主 tcp_rmem（本节） |
|---|---|---|
| 生效面 | 仅显式配置的 socket，精确 | 全部新 socket，面广 |
| 实测 | 8/8 全快 31.7-40.9Mbps | **8/8 全快 48.8-76.5Mbps（更快）** |
| DRS 自适应 | 锁死（失去自动调节） | **保留**（起点抬高，仍可自动长到 max） |
| 记账 | 每连接 ×2 固定记账 | 默认值仅是起点，按需增长 |
| 权限 | 应用配置即可 | 需宿主 root（容器/共享宿主未必给） |
| 适用 | 无宿主权限、只想调代理链路 | 自有 VPS/独享宿主（**首选**） |

自有整机首选 sysctl（更快且保留自适应）；无宿主权限或面广顾虑时用 per-socket。两者不互斥。

## 6. §策略 默认值评估（供 PM/用户拍板，未改码）

| | A：维持 opt-in（现状） | B：outbound+inbound 默认 4MB | C：高 RTT 探测后自动 |
|---|---|---|---|
| 改码量 | 0 | 中（默认值 + 全量回归） | 大（RTT 探测 + 动态决策 + 状态） |
| 高 RTT 用户 | 需读文档自行配置 | 开箱即快 | 开箱即快（探测可信时） |
| 内存税 | 无 | **所有用户征收**：每连接 8MB 账面，千并发 8GB/万并发 80GB 账面 | 按需征收，但探测窗口内不确定 |
| 低 RTT 链路 | 零影响 | 显式 SO_RCVBUF 锁死 DRS 自适应（4MB 封顶），Lan/同城大传输被无谓限幅 | 无影响（不触发） |
| 与 Go 行为 | 一致（Go 同样 opt-in 且默认不设） | **分叉**（Go 默认不设） | Go 无对应物，完全分叉 |
| 失败模式 | 不配→塌（有本文档兜底） | 大并发部署 tcp_mem 压力，难排查到"默认值"头上 | 探测噪声误判→时快时慢，最难诊断 |
| 先例 | bd o93t 终裁：**"默认 0 零行为变化，opt-in 字段保留为高 BDP 运维工具"** | 违背该终裁 | 违背该终裁 |

**推荐：A（维持 opt-in）+ 本文档运维配方 + VPS 固化配方（§8）**。理由：

1. 塌轮是"Linux 默认 rmem 128KB × 即时消费泵 × 高 RTT"三条件联合产物；命中条件的目标用户（自建跨洋中转）恰恰是会读文档、有 root、能一行 sysctl 或一段 JSON 的人群——运维解法够得着。
2. B 对不需要的用户收全局内存税，且大并发部署的 tcp_mem 压力是最难排查的故障形态（表现为莫名全局抖动，根因藏在"默认值"里）。
3. C 是过度工程：RTT 探测引入新的失败模式，换来的只是"省一段 JSON"——B 的内存税它躲开了，但复杂度和 Go 分叉都留着。
4. 项目先例（o93t 终裁）已把该字段定位为高 BDP 运维工具，A 是对既有决策的延续，B/C 需要推翻先例的新论据。

若未来拍板要动默认值，**B 的温和变体是仅 outbound 默认**（面向远端高 RTT 的那一条，内存税减半），仍需先解决大并发记账预算再上。

## 7. 数据出处（防注水声明）

- 全部数字来自 docs/impl-hzcq-collapse-rootcause-2026-09-17.md 的一手床实验（12 基线轮 + 8 per-socket 轮 + 8 sysctl 轮 + 4 Go 对照轮，含 ss -tin 全腿采样与 strace 读节律），本文档未新增任何测量。
- 机制结论（DRS 自锁/Go 积压解锁）为该报告 §3 证据链（观察→推断闭环，删改实验双向验证），内核内部细节按可观测行为定案。
- 未验证面：生产真实跨洋链路（无床外数据）；非 Linux 平台行为（床仅 Linux）。

## 8. VPS 床复现（固化配方）

床：`ssh -p 26617 root@199.115.231.188`，配方目录 `/tmp/repro8sum/r2/`。

```bash
# 默认即修复态（CFG=fix → srv_fix.json/cli_fix.json，sockopt 4MB）
TAG=adch ./r2run_adapt.sh ./xray_new /tmp/repro8sum/r2/out_adch 16
# 复现塌轮（研究用）：CFG=base 切回原始 128KB 配置
CFG=base TAG=base ./r2run_adapt.sh ./xray_new /tmp/repro8sum/r2/out_base 16
```

详见目录内 README.md。netem（161ms/1% on lo）由脚本自动确保，勿手工拆除。
