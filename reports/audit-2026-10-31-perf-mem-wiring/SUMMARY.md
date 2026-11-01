# 2026-10-31 多维审计总账：性能 / 内存 / 功能接线

- 仓库 `D:/Project/Xray-core-rust`，分支 `feature/fix-inbound-parity`，HEAD `5fe98b90`
- 口径：**生产主路** = 默认 `xray.exe run -c`（`xray_conf::Config::build()` → `xray_core::start_full`）；目标主路 = `xray-cli` framework-assembly（未进默认构建）
- 全部产出为只读审计，零产品代码改动

## 0 一句话结论

「写完了但没接通」在本仓有三个层次，且**第三层最危险**：配置解析了没人用（30+ 处）、装配期静默降级（warn+skip / fail-open，可直接造成屏蔽规则失效与流量明文直连）、运行期装配了却无效果（reverse / policy / log / observatory）。内存侧有一条 **OOM 级的线性泄漏**（FxScope 完成条目滞留，+2 分配/连接，永不回落）。

## 1 轮次与产物

| 轮 | 主题 | 代理 | 报告 |
|---|---|---|---|
| R1-A | 配置字段 → 生产消费点（342 字段 / 78 结构体） | reviewer | `xray-conf-field-wiring.md` + `field-ledger.tsv` |
| R1-B | pub 符号 / 死代码 / stub 生产可达性（118 allow + 16 stub + 68 候选全定性） | reviewer | `WiringApi.md` |
| R1-C | 静默降级与吞错（807 个 .rs 扫描 + 13 配置夹具 E1） | reviewer | `WiringDegrade.md` |
| R2 | 性能机制接线 + 热路径浪费（31 项机制三态表） | performance-reviewer | `PerfWiring.md` |
| R3 | 内存生命周期（8 发现，E1 实测 2） | performance-reviewer | `MemWiring.md` |
| R1-D | 协议 settings 原始解析面（329 键 × 25 crate） | reviewer | `SettingsWiring.md` + `settings-ledger.tsv` |
| R1-E | app 域运行期效果（8 域 × 4-5 功能点矩阵） | reviewer | `AppWiring.md` |
| R4-1 | 对抗复核：静默降级族（11 条断言） | reviewer | `Verify-R1.md`（9C/1R/1A） |
| R4-2 | 对抗复核：性能断言（5 条） | performance-reviewer | `Verify-Perf.md`（3C/3A） |
| R4-3 | 对抗复核：内存断言（7 条 + 2 新增） | reviewer | `Verify-Mem.md` |
| R4-4 | 对抗复核：安全断言（5 条 + 2 新增，E1 可利用性） | security-reviewer | `Verify-Security.md` |

## 2 核心结论

1. **静默失效 ≠ 没实现**。最严重的问题都通过了「配置解析 → 装配 → 启动」三道关，只在运行期无声失效；用户自检发现不了，只有抓包/对照 Go 才能看出。
2. **失败语义不统一**：底层对 Lua script 等刻意 fail-loud，但装配调用方把 fail-loud 吃掉换成 warn + 回退（路由/出站/sniffing/freedom finalRules 同一根因）。**这是 P0 群的主因**。
3. **凭据面存在 fail-open**：ss 空口令 = 公开可算常量（E1 已用公开 KDF 打通数据，任何人可代理上网）；anytls 无口令 = 完全不校验认证帧；ss 多用户只认首用户。
4. **内存有 OOM 级线性泄漏**：udf `FxScope` 完成条目需调用方显式 `try_reap` 收割，主仓唯一收割点只覆盖 `ManagedScope` 自身；A 类 19 处 `ctx.spawn` + B 类 25 处组件自持 scope + C 类 `ConnScope` 全部未收割。
5. **性能最大单项是 rustls 每 record 全量明文拷贝**（E1：1.00025 MB/MB，占 cli 分配 89.9%），但删它的收益未在 CPU 上兑现（分配降 46% 吞吐零变化），排期前必须先量 CPU。

## 3 票面索引（第一轮 18 张 + 更新 1 张；第二轮 12 张见 §7）

| 票 | 级别 | 主题 |
|---|---|---|
| `vaye2` | P0 | 路由解析失败静默降级 PatternRouter（屏蔽规则失效，E1） |
| `o91s4` | P0 | 出站 warn+skip → 默认出站前移（以为在代理实际直连，E1） |
| `5w5z0` | P0 | freedom finalRules 丢项 → 匹配域扩为全量（E1） |
| `u4efe` | P0 | ss 空口令 open proxy + 多用户只认首用户（E1 打通） |
| `bz800` | P1 | anytls 无口令即零认证（开放代理） |
| `vdl95` | P1 | sniffing 排除表整表失效 + 未知协议 inbound 零监听（含 masque 缺口） |
| `lu37q` | P1 | gRPC Routing/Observatory 后端零注入 + api outbound registrar 仅测试 |
| `3nt18` | P1 | geodata.outbound 死值（资产下载直连暴露 IP） |
| `nip4p` | P1 | reverse 全域失效（set_deps 零调用 + vless portal 零赋值） |
| `86i4h` | P2 | **更新**：FxScope 条目滞留（udf 已提供 try_reap，改判主仓接线缺口，解除 BLOCKED） |
| `txtpo` | P2 | vmess SessionHistory 清理任务从未实现（文档谎称有） |
| `s6h2j` | P2 | policy bufferSize 全链路失效 + per-user level timeout 丢弃 |
| `1fm1l` | P2 | 性能批次一：xhttp 上行 ReaderStream + UDP 每包 4 分配 |
| `x0f0r` | P2 | 协议 settings 静默失效批次（downloadSettings/udpHop/masquerade/probeInterval 等） |
| `sex3y` | P2 | 日志与指标面：dnsLog 零生产者 / 写失败静默 / observatory 恒 null |
| `slv4n` | P2 | rustls 逐 record 全量明文拷贝（先测 CPU 再定） |
| `a0m9d` | P3 | BufferPool 接缝零生产消费 + 文档漂移 |
| `7kp03` | P3 | 死代码清理批次 + 过期 allow 注释 + ruleSet 自造半成品 |
| `il9lh` | P3 | 小内存项：TPROXY fake_cache / ws 池 / ArmScopeRegistry |
| `a5pe6` | — | **既有**，MemWiring 定性：per-DlStream 私有、drop 整池释放，天然满足票面判据 |

## 4 被复核推翻 / 降级的断言（诚实记录）

| 原断言 | 复核结论 |
|---|---|
| `ruleSetTag` 导致静默 catch-all（P0） | **REJECTED**：空条件规则在 `BuildCondition` 就拒启（与 Go `app/router/config.go:117` 同措辞），到不了 `ConditionChan::Apply`。真问题是同一根 fail-open（已并入 `vaye2`），自造 `ruleSet` 扩展另立 `7kp03` |
| rustls 拷贝「纯多余」+ 需 vendor 红线授权（P1） | **ADJUSTED**：buffered API 内拷贝必需；真改动在调用侧重写 TLS 适配层，**不涉 vendor 红线**；严重度 P1→P2 |
| BufferPool 未接线 = 缺陷 | **ADJUSTED**：属「已规划未落地」（bd `nn8os` 已降格关票），非缺陷；但文档自相矛盾 + CLAUDE.md 缺台账行 |
| F12 trojan 空口令「Go 拒启」 | **ADJUSTED**：Go 26.10.17 trojan **入站**同样放行（`trojan.go:70-71` 是出站），照原断言修会撞 32/32 对拍；改为只加 warn，拒启交 PM 拍板 |
| MW-2 vmess +419 B/conn | **ADJUSTED**：其中 419 B 主要是 FxScope 条目，`SessionHistory` 仅 ~70-110 B/conn；严重度 High→Medium，「任务从未实现」成立 |
| W3 装箱 future | **ADJUSTED**：量级仅 ~0.01 MB/MB，`76feeba3` 两次回退史 → 不重做，仅登记 |
| hysteria client 池无界增长 | **REJECTED**：键 = `server_addr`，单 outbound 恒 1 项；死代码另计 |
| ws 池 / ArmScopeRegistry 严重度 | Medium→Low（key 受配置约束） |

## 5 建议修复顺序

1. **先止血 4 张 P0**：`vaye2`/`o91s4`/`5w5z0`/`u4efe` —— 共同修法是一条「装配期 fail-visible 门」，一次改可覆盖多条（与框架路 `fail-fast` 门对齐）。
2. **P1 凭据面**：`bz800` / `u4efe` 的 anytls 与 ss 多用户（同根：认证校验缺失即放行）。
3. **P1 内存**：`86i4h` —— 3 行 + 25 处替换，但触及 spawn 热路径，验证门必须含 workspace + 32/32 + loopback <5%。
4. **P1 功能面**：`nip4p`（reverse）、`lu37q`（gRPC 后端）、`3nt18`（geodata）、`vdl95`（sniffing/masque）。
5. **P2**：`s6h2j`/`sex3y`/`txtpo`/`1fm1l`/`x0f0r`，其中 `1fm1l` 成本最低收益明确。
6. **P2/P3**：`slv4n`（先量 CPU）、`a0m9d`（文档一行或建票）、`7kp03`/`il9lh`（清理）。

## 6 未覆盖面（本轮没做，需另派）

- hyper/h2 帧层内部（full cli 90.4% untagged 分配的主体）、BoringSSL C 侧 malloc（不经 Rust 分配器 → 站点恒 0 是**不可见**不是零分配）
- KCP/QUIC/gRPC/ws/wg/tun 各自帧层的分配密度
- app 域 per-user 计数与 online map 的 E1（需 vless 认证互通环境）
- Linux 专属面（TPROXY / tun / iptables）不可本机实测
- anytls 无口令的端到端抓包（需手写 TLS+padding 客户端）、ss 多用户的 UDP 面
- 未定位线索：ss 入站实测不打 `shadowsocks inbound listening` 日志（两次复现，原因未查）
- vless srv 每连接 +218 B 但分配笔数不涨（buffer 高水位，无站点标记无法定责）

## 7 第二轮：换角度（攻击者 / 慢对端 / 并发）

第一轮是「从代码往里看」（接线、效果、分配计数）。第二轮改为「从外部往里打」：畸形字节、慢速对端、故障时序。三路并行 + 一路专项复核，产物在 `reports/audit-2026-10-31-perf-mem-wiring/round2/`，新建 12 张票。

| 票 | 级别 | 主题 | 关键 E1 |
|---|---|---|---|
| `dct2d` | P0 | splithttp packet-up 请求体无上限整读 | 1 请求 7.7s 推 2000MB → RSS 16.3MB→2592MB，**零凭据** |
| `zmpxy` | P0 | dokodemo UDP 无会话容量门 | 800 源 → +118.9MB（152KB/源，线性），UDP 源可伪造 |
| `itd0p` | P0 | xdns finalmask 长度门 off-by-two | **53 字节单包**打崩 recv 任务，隧道永久失聪不自动恢复 |
| `dp2dm` | P1 | SOCKS4 USERID 无上限逐字节读 | 10s 吃 12.44 CPU 秒 + 82MB 堆 |
| `y5cy9` | P1 | HTTP 请求头逐字节无缓冲读 | ≈1 CPU 秒/MiB；20 并发 21.5 CPU 秒 |
| `tini5` | P1 | socks UDP associate 每会话 55.8KB 无上限 | 1200 会话 → +65.3MB |
| `3zbwx` | P1 | splithttp SessionMap 无容量门、id 客户端自选 | 100 唯一 session × 900KB → +93MB |
| `2xgln` | P2 | h2/gRPC/splithttp 服务端并发流无上限 | 500 流/1 TCP → +20.4MB |
| `rjt2o` | P1 | 数据面写臂无 deadline：policy 三超时失效 | 对端不读时 6/6 socket 在 3×connIdle 后仍 ESTABLISHED，句柄不回落（无界） |
| `uwq9n` | P1 | DNS-over-TCP 出站 writer 锁跨 await | 停读客户端 → DNS 会话永不结束（无 policy 兜底） |
| `cinni` | P1 | wireguard UDP send 持锁跨拨号与写 | 死连接静默黑洞、永不重拨 |
| `ym0z8` | P1 | 同 tag 并发 AddInbound 静默覆盖 → 孤儿监听 | API 假成功；同 tag 并发出现两种状态码 |

（共 12 张：P0×3 / P1×8 / P2×1。）

### 第二轮被修正的判定

| 原判 | 复核修正 |
|---|---|
| C4 重复 tag 报 `registry full` | **REJECTED**：`BoundedRegistry::insert` 对重复键静默覆盖并返回 Ok，registry-full 文案只在 ≥1024 时出现。真实缺陷更严重：覆盖丢 cancel 令牌 → **孤儿监听器（端口永久占用不可摘除）** |
| C1「写臂无 deadline」 | **机制修正**：读侧 deadline 其实是好的（对照组 2.01s 准时断连）。真根因是「**判定存在但无法执行**」——被堵在 `send/write` 的腿不再被 poll，而 `join!` 要求四腿全归 |
| C1 修法会撞「数据面热路径零改动」红线 | **不撞**：`bridge.rs:396` watch 中止闸 + 4 个 await 点改 `select!`，泵结构/mpsc 容量/vectored/readv 一个字不改。探针实测 9.2µs 直通、能打断永不完成的 future、空闲 CPU 0.000s（已编译验证，非纸面） |
| C2 位置在 app-dns | **路径纠正**：`crates/xray-core/src/outbound.rs:1836/1933`(+`:1920`) |

### 第二轮反向对照（守得住的，防误报/防回档）

TCP 上行对端不读 +4.6MB 停滞、下行 +1.3MB、VLESS 裸 TCP +0.9MB、gRPC 大 body 只 1.3MB、握手蹲坑 300 连接 46KB/连接 60s 内全回收、半关闭 2s 内全断、UDP 4000 目标风暴 +0.6MB、socks 握手超时 60-65s 正常关闭（原「无握手超时」被证伪）。

### 第二轮方法学备注

多代理并行实测会互抢 loopback/CPU 与误杀同名进程；本轮已定纪律：独立端口段 + 按 PID 清理 + 报告注明并发环境（一次 `-Name xray` 广杀已留档）。

## 8 第三轮：Go↔Rust 真跑差分 + 测试有效性 + 真 Linux

前两轮的 Go 对照全是**源码推导（E2）**。第三轮第一次用两个真实二进制（`D:/tmp/go2617/xray.exe` = Go 26.10.17 裁定基准 vs `target/release/xray.exe`）做同输入双跑，并首次在**真 Linux**（WSL `ubuntu-xray`，root + `/dev/net/tun`，kernel 6.6.87.2）落地验证。

| 票 | 级别 | 主题 | 关键证据 |
|---|---|---|---|
| `f2ap9` | **P0** | SOCKS5/VLESS 入站不归一化「域名字段形态的 IP 字面量」→ `routing.rules[].ip` 永不命中 → **屏蔽规则被绕过、流量直连泄漏** | Go 在 `common/protocol/address.go:213-217` 归一化，Rust `xray-proxy-socks/src/protocol.rs:248` 与 `xray-proxy-vless/src/encoding/mod.rs:174` 无。排除干扰变量后单变量实测 |
| `amynv` | P1 | L4 契约夹具验的是框架不是插件（55/56）+ 条款 3 `conn_id` 生产调用数 = 0 | 契约宏 `plugin.build()` 从未被调用、`deps()` 返回值被丢弃、16/16 lifecycle 三相全 `Ok(())` |
| `7k7mj` | P1 | 测试把失败路径固化为期望（4 条） | anytls 无口令放行 / vless 非法 uuid skip / 路由规则丢弃 / sniffing 排除降级 —— 正是前两轮 P0/P1 一路绿灯的根因 |
| `05ac1` | P1 | 56 个生产错误变体零测试覆盖（全在凭据面） | ss2022 重放防护、vmess auth id、socks/trojan 密码校验、VMESS-U16 u16 溢出 |
| `t3wtj` | P1 | CI 协议差分门仍比 Go **v26.9.9**，而裁定基准是 v26.10.17 | `ci.yml:214-251`、`interop.yml:82-97` 均下载 26.9.9 release。⚠ 改 workflow 属红线，需授权 |
| `0bzcd` | P1 | Go↔Rust 配置面 fail-open 差异 13 例（Go 全拒启而 Rust 放行） | 162 用例双跑全成，26 差异（去重 21） |
| `1gkcf` | P1 | dokodemo fakeudp 测试在 root 下**必 panic** | 裸 `#[test]` + `UdpSocket::from_std` 需 reactor；root=FAILED / nobody=ok → CI 绿是假绿，生产 VPS(root) 必红 |
| `jf1wv` | P1 | UDP TPROXY 整条链零测试 + CI 无 root/CAP_NET_ADMIN job | `xray-transport/src/udp/hub.rs:344-526` 零断言；`ci.yml:148-176` 无特权 job → 恒走权限错误分支 |
| `3t30l` | P1 | Linux 发布产物零验证门 | 32/32 唯一调用方跑 Windows 二进制；`release.yml` build job 零测试 |
| `0m0f6` | P2 | interop 门无 PR 触发 + 11 脚本只接 1 个 + `run_full32.py` 未接 | — |
| `0snlt` | P2 | HTTP 入站错误响应方向与 Go 相反 | 缺 Host：Go 400 / Rust 静默关；坏 Content-Length：Go 静默关 / Rust 400 |

### 第三轮的方法学突破

前三轮都是「Rust 单侧视角」，因此只能证明「Rust 有问题」，不能证明「Rust 与基准不同」。第三轮改用**同输入双跑**，首次能量化「Rust 更宽松」这类真正危险的差异：`f2ap9` 的屏蔽绕过、`0bzcd` 的 13 条 fail-open、`0snlt` 的响应方向相反，全部是真跑出来的，不是读代码推的。

判别技巧（可复用）：测「路由是否命中」时不能用 `127.0.0.1`（freedom 对 loopback 有独立 block，会完全掩盖命中与否），且 Rust VLESS 入站默认注入 `BlockPrivate`，须显式 `finalRules:[{action:allow}]`——排除这两个干扰变量后才是单变量实测。

### 真 Linux 首轮落地结果（关闭前两轮盲区）

WSL `ubuntu-xray`：TUN 13/13 绿（真建设备）、splice 6/6 + core e2e 绿、UDS 9 形态绿、dokodemo 31/31 绿、QUIC GSO 6/6 绿、背压 3/3 绿；**dokodemo fakeudp 在 root 下 FAILED**（即 `1gkcf`）。sockopt 2 项失败经对照确认为环境项（stock `rmem_max=212992`，抬到 8MB 后 23/23 绿）。

## 9 第四轮：配置全集 + UDP/DNS + 真 Linux 端到端

| 路 | 结果 | 关键发现 |
|---|---|---|
| ConfigParity | Go 配置键 **425** / Rust 有解析点 **415（97.6%）**；157 例双跑 → 60 差异 | Go 已移除的 feature 在 Rust 复活（`proxySettings`/`noise`/`flow`，`jwg8y`）；`useSystemCA` 语义缺口（`1avs1`）；splithttp H3 三窗口键零消费、`disablePathMtuDiscovery` 拼写同仓两说（并入 `x0f0r`） |
| UdpDnsDiff | 64 例双跑 → 23 差异（归并 7 条） | DNS 语义层**逐字节一致**；但 `ownLink` 失效致本地 DNS 零应答（`7qxjj`）、帧格式按上游网络选（`64nmm`）、freedom 域名目标只取首址（`1ksxu`） |
| LinuxE2E | 真 Linux 构建 Rust 产物（git_rev=5fe98b90），TCP **50/50 PASS**、UDP **6/16** | **`t0ls1` P0：UDP over 隧道全废**。TCP 面可替代 Go，UDP 面不可 |
| Verify-XUDP | X1 成立（归因更细）/ X2 成立且更广 / X3 成立 / X4 成立 | 帧格式两侧逐字节相同，差别在「哪层剥帧」；需 4 处改动同时做；不碰 vision/splice/TCP 锚 |

## 10 第五轮：传输层 wire + 第三方协议

| 路 | 结果 | 关键发现 |
|---|---|---|
| WireParity | 40/40 双向全跑，跨实现数据面 **36/36 PASS**，无裹帧类缺陷 | ws 默认预连接池（服务端连接数 ×4）、gRPC 16MB/流窗口预算（`vkirx`）；splithttp stream-one 多 1 条零字节 TCP、mux carrier 头不同、`wsSettings.ed` 独有（`vkirx`/`3zbwx` 族） |
| ThirdPartyInterop | sing-box 1.14.3 对端，13 用例 + 9 控制组 | 通用 socks5 UDP **7600B 起无回包**（Go 8000B 正常，`zu7tk`）；hysteria2 入站 obfs 静默失效（`a3tos`）；anytls UDP 全链缺失（`yfcnr`）；tuic UDP 双缺陷（`j7de2`） |

## 11 第六轮：TLS/REALITY + reload/动态配置

| 路 | 结果 | 关键发现 |
|---|---|---|
| TlsReality | 62 组对跑；安全属性成立（证书链/主机名/有效期/REALITY 门/fallback 偷自己 均 E1 与 Go 一致） | 只配 `verifyPeerCertByName` 时 Rust 两条路径全拒（`idtl1`）；未配 fingerprint 时发 rustls 原生 hello → DPI 可判定（`qscjv`）；缺 cert 静默自签等（`mwvwd`） |
| ReloadDynConfig | 58 调用点 + 4 数据面探测双跑，20 项矩阵 13 有差异 | 用户热更只支持 legacy ss（`hl8q6`）；API AddOutbound 丢 `senderSettings` → `sendThrough` 不生效、直连泄漏（`ucjcl`）；`should_append` 忽略等 latent（`9c8k6`） |

## 12 覆盖矩阵与剩余

**已覆盖（14 个方向）**：接线（配置/协议 settings/app 域运行期效果）· 装配期静默降级 · 性能（热路径分配/池化接缝）· 内存（生命周期/增长/驻留）· 攻击面（畸形输入/CPU 放大/远程 panic）· 背压与慢对端 · 并发/取消/超时 · Go↔Rust 差分（配置面/TCP/UDP-DNS/配置全集）· 传输层 wire 差分 · 第三方协议对照 · mux · TLS/REALITY/Vision · reload/动态配置 · 测试有效性/CI 门 · Linux-only 路径与端到端。

**明确未覆盖（低优先或不可达）**：
- 供应链（依赖 CVE、`vendor/` 补丁漂移）
- 移动端（`mobile.yml`）
- 长期运行数值正确性（计数器溢出、时钟回拨）
- 真实公网多跳拓扑（NAT / CDN / 域名前置 / 链路 MTU）
- 性能真机吞吐 A/B（按用户口径由用户自测）
- BoringSSL C 侧分配（不经 Rust 分配器，站点恒 0 是**不可见**不是零分配）
- QUIC 传输（Go 26.10.17 已移除，无对照物）；hysteria2/tuic 的 >8KB UDP（sing-box 侧接收缓冲限制）



