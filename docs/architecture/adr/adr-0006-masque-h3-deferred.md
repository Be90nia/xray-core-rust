# ADR-0006 · MASQUE h3 承载押后（等上游），连接数拓扑修复与本票收口

- 日期：2026-11-12
- 状态：**Accepted**（PM 拍板 2026-11-12）
- 关联：bd anygg（MASQUE 收口，G6）、bd m2mmm（xhttp 缺省连接拓扑）、bd yc54c（XDRIVE 收口）、`reports/2026-11-12-masque-g2-listener.md`、`reports/2026-11-12-masque-gap-closure.md`
- 前序：`docs/architecture/xray-frame-masque-契约级任务书-2026-10-30.md` §附录 A 建议（ADR-M4 Proposed）、`docs/architecture/xray-frame-masque-实施计划-2026-11-11.md` §7 R11（高，决定 M3 生死）与「未决 2」

---

## 背景

MASQUE 的 h3 承载（UDP/443，QUIC DATAGRAM 载荷 IP 包，Go `hub.go:91 listenHTTP3` + `conn.go:673-683` 二分支）在 **h2 路径之外**多一条传输形态。实现它有一个硬前置：

**`h3` crate 0.0.8（crates.io 最新）表达不了 `:protocol=connect-ip`** —— `src/ext.rs` 的 `ProtocolInner` 是闭集（仅 `WebTransport`/`ConnectUdp`），且无 `from_static` 类入口（bd anygg G6 / 计划 R11，等级「高（决定 M3 生死）」）。

三个选项（契约级任务书 §附录 A 与实施计划 §7 R11 列过）：
1. **`vendor/h3` patch**：增 `ConnectIp` 变体 + `Protocol::from_static`（与 `vendor/quinn-proto` 同类先例）；代价 ≈2 人日 + 长期上游追赶债。
2. **自写 QUIC DATAGRAM 承载**（绕开 h3 的 connect-ip 框架，自己在 quinn 上写 IP 包分发）：成本最高，违「禁造轮子」纪律（计划已否决）。
3. **押后等上游**：h3 上游支持 connect-ip 后零补丁升级；时间未知。

## 决策（PM 2026-11-12）

1. **选 ③ 押后等上游**。理由：
   - **UDP/443 在目标用户网络（中国大陆）普遍被运营商限制/降速**（QUIC/UDP 干扰策略与 TCP 不同，劣化期往往更差）⇒ h3 路径对实际使用场景的**增益存疑**；
   - **vendor patch 的维护债是长期的**：h3 是 pre-1.0 crate，破坏性变更频繁，每月级 rebase 负担（`vendor/quinn-proto` 同类先例的成本已知）；
   - **本票的价值主张已由 h2 路径全部承载**：h2（TCP/443）已真连打通（L1）+ 1MiB 真实字节代理线往返（L2）+ 8 缺口收口 7 条 + G3 在飞 ⇒ h3 不新增当前可用能力。
2. **隧道路由通告范围对齐 Go**（masque 计划「未决 2」一并裁决）：**恒通告全路由（`0.0.0.0/0` + `::/0`）**，不做「默认只通告内网段」的语义偏离；安全面依赖 freedom 默认规则（BlockPrivate）——与本仓生产接线一致（`xray-proxy-freedom/src/config.rs:1200` masque→BlockPrivate + `xray-core/src/outbound.rs:206-209` tag→规则）。
3. **触发重开条件**（满足其一即重立票）：
   - 出现「**UDP/443 比 TCP/443 更通**」的网络环境（实测判据：同节点同路径，h3 探针连通且吞吐 ≥ h2 的 70%）；
   - **上游 h3 支持 connect-ip**（crates.io 发布含 `ConnectIp` 变体或 `from_static` 入口的版本）⇒ 零 patch 升级；
   - 有明确用户需求需要 QUIC 承载特性（如 0-RTT、QUIC DATAGRAM 的原生 UDP 性能）。

## 后果

- **能力差显性登记**：Go（v26.11.9）有 h3 监听面（`hub.go:91`），本仓 h2-only ⇒ **与 Go 存在已知能力差**（非缺陷；masque 的互通对拍不受影响——对拍走 h2）。`crates/xray-transport-masque/src/warp.rs:49,52` 的两个 h3 专属常量（CID=20、`0x276`）保留（golden 断言锚点），件头注释「本仓 h3 未接」继续有效。
- **不做 vendor/h3 patch** ⇒ 不引入该长期维护债；`vendor/quinn-proto` 先例不受影响。
- **本仓 masque 的 h2 路径不受影响**：`Cargo.toml` 无 h3 依赖（审计确认），`MASQUE-H2-ONLY` 装配门（`outbound.rs:627-638` ALPN 必须显式含 h2）继续 fail-visible。
- **masque G2（transport 级真 listener）已在本票落地**（与 h3 决策正交）：`register.rs` 真 listener + 共享 users 闸 + L2 e2e（64KiB 逐字节往返 + 401 委托 + canary==0）⇒ `network:"masque"` 承载 VLESS 可用。

## 修订历史中的错误结论（本 ADR 一并更正）

- 实施计划 §7 R1 曾记「网络阻断」（WARP anycast 443 被墙）⇒ **2026-11-12 证伪**：真因是**端点选错**（engage anycast 对 WARP 免费版一律 400）+ **pin 取错证书族**；换 usque 的 `DefaultEndpointH2V4 = 162.159.198.2` + 对应 SPKI ⇒ 即通（证据：`reports/2026-11-12-masque-warp-nonmainland.md`，端点×证书族矩阵 200×10 / 400×10，Go 参考探针同端点同样 400）。
- 本票 bd ujimu 已关闭（目标达成）；`warp_cloudflare.rs` 默认端点已改为 `162.159.198.2`（+10/−6，含 clippy 存量红修复）。

## 何时重审

按「触发重开条件」三条；另：masque 实施计划 §7 R16（上游基准再动 masque）⇒ 重跑该计划 §2.1/§2.3 取证。
