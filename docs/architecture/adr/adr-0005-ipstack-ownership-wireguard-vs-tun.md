# ADR-0005：用户态 IP 栈归属——wireguard 版进 `xray-frame`，tun 版保留为 TUN 专属扩展（不合并）

- 状态：**Accepted**（PM 拍板 2026-11-11，用户选择方案 A：带处置结论关票，不做夜间合并）
- 日期：2026-11-11
- 关联：bd `gjiu7`（本 ADR 的落地票 · 收编债）· bd `55yh7`（MASQUE B3 触发源）· 提交 `409b12c3`（wireguard 版净移动已落）· `reports/2026-11-11-fixes/masque-b3.md`

> 本 ADR 落**归属与裁断**，不落实现。MASQUE B3 的净移动已落库并验证（wireguard 104/0 · 红线 dataplane 4/0 · 机器判据构造性 sha 恒等）。

## 背景

### 问题

MASQUE 需要「用户态 IP 栈桥」机制。库内当时已有两份实现：

| 实现 | 位置 | 体量 |
|---|---|---|
| wireguard 版 | `crates/xray-proxy-wireguard/src/netstack.rs` | 542 非注释行 |
| tun 版 | `crates/xray-proxy-tun/src/netstack.rs` | 649 非注释行 |

MASQUE 若再写一份即命中用户硬约束「**必须基于现有 udf/xray-frame 派生，决不允许造轮子**」，也违反 CLAUDE.md §3.5.4（归一化面禁副本）。但两份实现**早已分叉**，不是同一份代码的拷贝——实测（2026-11-11）：

- 共有非注释行 **191**；仅 wireguard 侧独有 **351**；**仅 tun 侧独有 458**。
- tun 独有语义（节选）：IPv6 组播下界、IPv4 头校验和验证、IPv6 UDP 校验和强制（零校验和非法）、lazy TCP listen cache、mDNS 组播处理——来自 2026-11-10 TUN Windows 四项批次（bd `172ew`）。

即：收编不是「同一份搬两次」，而是**两份不同实现的合并**。

## 决策

1. **wireguard 版 → `xray_frame::ipstack`**（已落，`409b12c3`）：净移动 + re-export，wireguard 侧签名零变化；MASQUE **消费它**，禁自写栈（第三份风险消除）。
2. **tun 版保留在 `xray-proxy-tun`，不与 wireguard 版合并**：它是 TUN 专属增强（mDNS / 组播 / 校验和策略），合并需同时动两条红线数据面（wireguard + tun），收益不抵夜间风险。
3. **「三份并存债」降级为「两份，且差异有据」**：新协议一律进 `xray-frame::ipstack`；tun 侧差异是**入站面差异**（TUN 设备需要组播/mDNS 语义），不是重复。
4. **未来若需共享**：落点是「抽取共同基座（smoltcp 封装 + 帧收发）+ tun 保留扩展层」，**不是**整体收编——后者需先解两组行为差异的语义归属。

## 后果

**正面**
- 新增 IP 栈消费者（MASQUE 等）有唯一落点（`xray-frame::ipstack`），第三份风险消除。
- tun 侧独有语义零改动保留，bd `172ew` 成果不回退。
- 债票 `gjiu7` 从「悬案」变为「已裁定的架构事实」，不再挂 open。

**负面 / 已知代价**
- 库内仍有两份 IP 栈实现，重复代码债**从三份降为两份**（非归零）——这是明确接受的代价，不是遗漏。
- tun 与 wireguard 的 IP 栈行为**不完全一致**（校验和 / 组播策略差异）；两者入站面不同，差异可接受，但**跨协议复用时必须显式核对**。
- 未来若 tun 版能力被其他协议需要，共享基座的提炼成本会被推迟到需求出现时才付。

**维护义务**
- 改动 `xray-frame::ipstack` 时必须同步核对 wireguard 侧（红线 dataplane 回归 + `integration_wireguard_dataplane`）。
- 改动 tun 侧 `netstack.rs` 时不得反向要求 wireguard 版对齐（除非走 ADR 修订本条）。

## 备选否决

| 备选 | 否决理由 |
|---|---|
| 用 tun 版覆盖 wireguard 版 | tun 版缺 wireguard 侧 351 行独有逻辑 → wireguard 21 项测试与红线 dataplane 回归必红 |
| 立即合并两份（今晚做） | 动两条红线数据面 + 语义归属未定；收益（消除 1 份重复）不抵夜间高风险回归成本 |
| 抽第三份「公共基座」再各自派生 | 新造一层抽象，且在需求出现前无第三个消费者——违反「不造轮子/不提前抽象」 |
| tun 版也上浮 udf-frame | IP 栈是网络方向件，CLAUDE.md §3.5.3 明令不进 udf |

## 验证方式

1. 归属证明：`crates/xray-frame/src/ipstack/mod.rs` 存在且由 wireguard 版净移动而来（机器判据：逆向适配后与移动前 `HEAD:netstack.rs` sha256 逐字节恒等，见 `masque-b3.md` 门 B3-M）。
2. 行为证明：`cargo test -p xray-proxy-wireguard --all-targets` 全绿 + `cargo test -p xray-integration-tests --test integration_wireguard_dataplane` 4/4 PASS。
3. tun 侧未被触碰的证明：`git log --oneline -- crates/xray-proxy-tun/src/netstack.rs` 在本 ADR 落库后无新增提交（tun 副本保持原样）。
4. 反向自检锚：若将来出现「第三个 IP 栈消费者」或「tun 版能力被非 TUN 协议要求」，本 ADR 的第 4 条触发重估——重估结论必须仍回答「消费者是否走 `xray-frame::ipstack`」。
