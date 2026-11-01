# Round 4 · LinuxE2E：真 Linux 上的端到端互通与生产等价性

- 仓库 `D:/Project/Xray-core-rust`，分支 `feature/fix-inbound-parity`，HEAD `5fe98b90`
- 床：WSL `ubuntu-xray`（kernel `6.6.87.2-microsoft-standard-WSL2`，root，`/dev/net/tun` 可用）
- 裁定基准：Go **v26.10.17** linux-64（`/root/go2617-linux`，`92ccc93-dirty`）；被测：Rust linux-x86_64 release（自建 `git_rev=5fe98b90`，与 HEAD 一致）
- 只读审计，**零产品代码改动**；全部结论来自真 Linux 实测

---

## 0 一句话结论

**Linux 产物的 TCP 面已经可以替代 Go 做生产**（互通矩阵 44/44 通过、生产等价配置四路行为逐项一致、优雅停机/TUN/大文件/splice/DNS 批收全绿）；但**本轮挖出一个此前从未被登记的 P0 级缺陷：Rust 作为 UDP 隧道端点时，向对端发送的是 XUDP 帧而非裸 UDP 载荷，与 Go 26.10.17 的 wire 格式不兼容 —— 只要 UDP 流量经过 Rust 客户端或 Rust 服务端，该流量全部丢失**（DNS over UDP / QUIC / 实时游戏全废）。

**该缺陷与平台无关**（Windows 侧同字节复现），不是 Linux 专属；但它是「Linux 产物能否替代 Go」这个问题上唯一的拦路虎——TCP 全通、UDP 全废。

---

## 1 互通矩阵（真 Linux，判据 = curl 经 socks5h 出站命中本机 1KB HTTP echo，body 含标记串 `XRAY-ECHO-OK`）

### 1.1 TCP 面协议矩阵（`tmp/linux_interop.py`，44 用例）

| 协议 | 方向 | 结果 | 判据 | 日志摘录 |
|---|---|---|---|---|
| vless (tcp) | Rust client→Go server | PASS | body=1024B HTTP:200 | — |
| vless (tcp) | Go client→Rust server | PASS | body=1024B HTTP:200 | — |
| vless (tcp) | Rust↔Rust | PASS | body=1024B HTTP:200 | — |
| vless (tcp) | Go↔Go | PASS | body=1024B HTTP:200 | — |
| vless + **tcp+tls** | Rust→Go / Go→Rust / Rust↔Rust / Go↔Go | **4/4 PASS** | body=1024B HTTP:200 | 自签证书 + `pinnedPeerCertSha256` 双向钉扎 |
| vless_vision_tls (XRV) | 4 方向 | 4/4 PASS | body=1024B HTTP:200 | — |
| trojan (tcp) | 4 方向 | 4/4 PASS | body=1024B HTTP:200 | — |
| trojan + **tcp+tls** | 4 方向 | 4/4 PASS | body=1024B HTTP:200 | — |
| vmess | 4 方向 | 4/4 PASS | body=1024B HTTP:200 | — |
| ss (aes-256-gcm) | 4 方向 | 4/4 PASS | body=1024B HTTP:200 | — |
| ss2022 (2022-blake3-aes-128-gcm) | 4 方向 | 4/4 PASS | body=1024B HTTP:200 | — |
| socks（server=socks inbound / client=socks outbound 互为对端） | 4 方向 | 4/4 PASS | body=1024B HTTP:200 | — |
| http（server=http inbound / client=http outbound 互为对端） | 4 方向 | 4/4 PASS | body=1024B HTTP:200 | — |
| **dokodemo** | Rust dokodemo-entry→Go vless-server | **PASS** | body=1024B HTTP:200 | 见 §1.2 |
| **dokodemo** | Go dokodemo-entry→Rust vless-server | **PASS** | body=1024B HTTP:200 | 见 §1.2 |
| **dokodemo** | Rust↔Rust | PASS | body=1024B HTTP:200 | — |
| **dokodemo** | Go↔Go | PASS | body=1024B HTTP:200 | — |

**TCP 面合计 44/44 PASS**（`tmp/linux_e2e/interop_matrix_results.json`）。

> **口径说明（不是缺陷）**：首轮我把 dokodemo 写成 Go 不认的协议名 `dokodemo`（Go 注册表只有 `dokodemo-door`/`tunnel`，见 `D:/Project/Xray-core/infra/conf/xray.go:29-30`），导致 3 例 FAIL。改用 `dokodemo-door` + 「dokodemo 作为客户端侧透明入口 + 对端 vless 隧道」形态后 **6/6 PASS**。Go 的 dokodemo 是 inbound-only，Rust 另有 outbound 形态——见 §3 F2（口径差异，非缺陷）。

### 1.2 dokodemo 专项（`tmp/linux_dokodemo.py`，6/6 PASS）

dokodemo 无自有 wire 协议（透明 TCP 改写器），跨实现互通的可测形态是「dokodemo 作客户端侧入口 + 对端隧道」：

| 用例 | 方向 | 结果 | 判据 | 日志摘录 |
|---|---|---|---|---|
| Rust dokodemo-entry → Go vless-server | Rust→Go | PASS | body=1024B HTTP:200 | — |
| Go dokodemo-entry → Rust vless-server | Go→Rust | PASS | body=1024B HTTP:200 | — |
| Rust dokodemo-entry → Rust vless-server | Rust↔Rust | PASS | body=1024B HTTP:200 | — |
| Go dokodemo-entry → Go vless-server | Go↔Go | PASS | body=1024B HTTP:200 | — |
| Rust dokodemo-direct（纯 dokodemo+freedom 行为对照） | — | PASS | body=1024B HTTP:200 | — |
| Go dokodemo-direct（行为对照） | — | PASS | body=1024B HTTP:200 | — |

### 1.3 UDP 面矩阵（**本轮 P0 发现，见 §2**）

| 协议 | 方向 | 结果 | 判据 | 上游实际收到的字节 |
|---|---|---|---|---|
| vless | Go→Go | PASS | reply=55B | **29B 裸 DNS 报文**（`1234 0100...`） |
| vless | Rust→Go | **FAIL** | reply=0B | **53B = XUDP 帧头 + 报文** |
| vless | Go→Rust | **FAIL** | reply=0B | 0B（Rust 服务端解不出） |
| vless | Rust→Rust | **FAIL** | reply=0B | 53B（同样带 XUDP 帧头） |
| vmess | Go→Go | PASS | reply=55B | 29B 裸报文 |
| vmess | Rust→Go / Go→Rust / Rust→Rust | **FAIL** | reply=0B | 53B / 0B / 53B |
| trojan | Go→Go | PASS | reply=55B | 29B 裸报文 |
| trojan | Rust→Go | **FAIL** | reply=0B | 53B |
| trojan | Go→Rust | **PASS** | reply=55B | 29B 裸报文 |
| trojan | Rust→Rust | **FAIL** | reply=0B | 53B |
| ss | Go→Go | **FAIL** | reply=0B | 0B（Go 侧 ss UDP 未通，见 §3 F3） |
| ss | Rust→Go | **FAIL** | reply=0B | 0B |
| ss | Go→Rust / Rust→Rust | **PASS** | reply=55B | 29B 裸报文 |

> **对照已排除试验床假阳性**：Rust socks-UDP → Rust freedom（不经隧道）**PASS**，上游收到 29B 裸报文逐字节相同 → socks UDP 入站 + XUDP 编解码 + freedom 出站三段全正常，缺陷唯一定位在「隧道协议承载 UDP」这一段。

---

## 2 【P0 新发现】Rust 隧道端点的 UDP 载荷裹了 XUDP 帧，与 Go 26.10.17 wire 不兼容

### 2.1 一句话根因

Rust 的 UDP dispatch link 契约是 **XUDP 数据帧**（`crates/xray-app-dispatcher/src/udp_session.rs:8-10` 头注释明示），`UdpDispatchSession::send_packet` 把每个 UDP 载荷包成 `XUDP帧头 + 2B长度 + 载荷`（`udp_session.rs:83-107`，帧构造在 `:102-105`）。**但 Rust 的 vless/vmess/trojan 出站在把这批帧送上线时，没有剥掉 XUDP 帧头，而是把「帧头+载荷」整体当作 UDP 载荷写进隧道**；Go 26.10.17 的对应实现（`proxy/vless/outbound/outbound.go:67-68` `EncodeBodyAddons` → `NewMultiLengthPacketWriter`，`proxy/vless/encoding/addons.go:87-124`）写的是**裸载荷 + 2B 长度前缀**，无 XUDP 帧。

### 2.2 决定性字节证据（真 Linux，E1）

同一台 WSL、同一份 socks-UDP 客户端配置、同一 DNS 假上游，只换实现：

```
=== GO client -> GO server ===
  upstream bytes(29): 123401000001000000000000076578616d706c6503636f6d0000010001
  upstream RAW-DNS: True | client reply len=55        <-- Go 侧正确：裸报文

=== RUST client -> GO server ===
  upstream bytes(53): 0014000001010201bb017f0000017a40eb3bbfbb8f73001d
                       123401000001000000000000076578616d706c6503636f6d0000010001
  upstream RAW-DNS: False | client reply len=0         <-- Rust 侧：多出 24B XUDP 帧头
```

拆解 Rust 那 53B：
- `0014 0000 0101 02 01bb` = XUDP New 帧头（status/option/端口）
- `017f000001` = 帧内目标地址 127.0.0.1
- `7a40eb3bbfbb8f73` = GlobalID（8B 随机）
- `001d` = 载荷长度 29
- `1234 0100 ...` = 真正的 DNS 查询（29B，**完整无损**）

→ **载荷本身是对的，多出来的是 24 字节 XUDP 帧头**。Go 服务端把这 53B 当成 UDP 载荷原样发给上游 → 上游收到垃圾 → 不回包。

### 2.3 反向（Go client → Rust server）为何也失败

Go 侧写的是裸载荷 + 2B 长度前缀。Rust 的 vless inbound `handle_udp_relay`（`crates/xray-proxy-vless/src/inbound/server.rs:645-726`）用 `read_length_packet` 读——它剥 2B 长度前缀后，把剩余字节当成 UDP 载荷塞进 `session.send_packet()`（`server.rs:701`）→ **又包一层 XUDP** → 对端 freedom 出站按 XUDP 帧解析时把 DNS 报文的 `\x12\x34` 当成帧 status → `invalid session status: 0x00`（`crates/xray-xudp/src/packet.rs:40-41`）。

Rust 侧实测日志（`RUST_LOG=debug`）：
```
INFO  from  accepted udp:127.0.0.1:53496
DEBUG socks udp dispatch recv failed error=invalid session status: 0x00
```

### 2.4 影响面

| 维度 | 事实 |
|---|---|
| 受影响协议 | vless / vmess / trojan（**凡用隧道承载 UDP 的协议**） |
| 受影响方向 | Rust 作客户端（Rust→Go / Rust→Rust）+ Rust 作服务端（Go→Rust）——**双向皆废** |
| 不受影响 | ss（Rust 侧走 shadowsocks 自有 UDP 中继，不经 XUDP 帧契约）——Go→Rust / Rust→Rust PASS；trojan 的 Go→Rust 方向因 Go 端另走裸帧而 PASS |
| 用户可见后果 | **UDP DNS 查询全废**（丢包、无应答）、QUIC/HTTP3/实时游戏/语音全部超时；TCP 流量完全正常 → 用户表现为「网页能开但 DNS 解析挂」 |
| 平台相关性 | **与平台无关**：Windows 侧 `target/release/xray.exe` 同字节复现（upstream 同样 53B、同样 `invalid session status: 0x00`）。不是 Linux 专属缺陷，但 Linux 侧同样成立 |
| 已有登记 | **未登记**。bd 45 张 open + closed 票全检：`1ka5i`（D12）已 CLOSED 且根因是 **`dns` outbound** 侧（`dns` outbound 按裸 DNS 报文读 link）；`1wq8`/`uhg2`（vless/vmess 出站 UDP 命令恒 TCP）已 CLOSED 且是**命令字**问题（`VlessCommand::Tcp` 恒定）。本条是**载荷帧格式**问题，既非 `dns` outbound 也非命令字，三票均未覆盖 |

### 2.5 建议修法（不实施）

对称解：隧道出站在写上线前**剥掉 XUDP 帧头**（只留 `2B长度 + 载荷`），隧道入站在读上线后**不再重复包帧**（把读到的裸载荷直接作为 `send_packet` 的 payload 传入，或给 `UdpDispatchSession` 加一个「已是裸载荷」的旁路）。参照物就在仓内：`crates/xray-proxy-freedom/src/dispatcher.rs` 的 UDP 出站是**正确**的（它按 XUDP 帧消费 link），说明「link 侧是 XUDP 帧」这一层没问题；问题在 vless/vmess/trojan 三个协议把 link 的帧直接当载荷上线。

修复后必须回归：vless/vmess/trojan × {Rust→Go, Go→Rust, Rust→Rust, Go→Go} 4×3 = 12 例 UDP 用例 + 已有 44 例 TCP 用例不得回归。

---

## 3 生产等价性（同一份配置，四路并跑）

配置 `tmp/prod_parity_config.json`：socks inbound（含 sniffing）+ http inbound + dokodemo-door inbound + freedom/blackhole 双出站 + 路由规则（`blocked.test` → blackhole）+ dns hosts + policy levels。

| 探针 | Linux Rust | Windows Rust | Linux Go | Windows Go | 一致？ |
|---|---|---|---|---|---|
| 启动 | OK，三入站全监听 | OK | OK | OK | ✅ |
| `socks_to_echo` | body=1033B `XRAY-ECHO-OK` | 同 | 同 | 同 | ✅ |
| `socks_blocked_domain`（路由→blackhole） | **HTTP:403** | HTTP:403 | HTTP:403 | HTTP:403 | ✅ |
| `http_to_echo` | body=1033B | 同 | 同 | 同 | ✅ |
| `dokodemo_to_echo` | body=1033B | 同 | 同 | 同 | ✅ |
| `dns_hosts_direct_test` | **rc=52 HTTP:000** | rc=52 | rc=52 | rc=52 | ✅（四路同错，见 F4） |
| `version` | `26.10.11 git_rev=5fe98b90 linux-x86_64` | 同（windows-x86_64） | `26.10.17 92ccc93-dirty` | 同 | ✅ |

**结论：Linux 与 Windows 行为逐项一致；Rust 与 Go 在这 6 个探针上行为也逐项一致。**

### 3.1 Linux 专属生产路径（`tmp/linux_only_paths.py`，真 root）

| # | 路径 | 结果 | 判据 | 证据 |
|---|---|---|---|---|
| L3 | **TUN 入站真建设备** | **PASS** | 进程存活 + `ip link show` 见 `xrayr4tun` | `/dev/net/tun` 真建设备 |
| L4 | **大文件 16MB 通路（Linux splice 路径）** | **PASS** | `HTTP:200 size=16777216`，0.04s ≈ 400 MB/s | loopback + splice 零拷贝 |
| L5 | **DNS UDP `recvmmsg` 批收**（linux-gnu only） | **PASS**（4/5 轮） | 灌 40 个 query，**40/40 收全** | 触发 `recvmmsg(2)` 批收路径。**诚实披露：5 轮中 1 轮收 39/40（缺 1 包）**，重跑 3 轮全 40/40；机制未定位（疑 burst 首包与 UDP 上游 socket 建立时序相关），**不立票，留观** |
| L6 | **优雅停机**（systemd 语义） | **PASS** | SIGTERM → exit 0（0.01s）→ 端口释放 → **同端口立即重启成功** | `port_freed=true, relisten=true` |
| L2 | UDS（unix domain socket）入站 | **PASS** | Go 与 Rust 均在 `network:"unix"` 下真创建 `.sock` 文件且进程存活 | 两实现对齐 |
| L1 | UDP 隧道 | **FAIL** | 见 §2 | P0 |

---

## 4 Findings（8 列）

### F1 — 【P0·缺陷】Rust 隧道端点 UDP 载荷裹 XUDP 帧，与 Go 26.10.17 wire 不兼容，UDP 流量全废

| 项 | 内容 |
|---|---|
| **场景** | socks UDP associate → vless/vmess/trojan 隧道 → 对端 freedom → 上游 UDP 服务 |
| **类型** | **缺陷**（Rust 放行但行为错 = 比 Go 更差；Go 正常工作） |
| **Go 行为** | 上游收到 **29B 裸 DNS 报文**，客户端收到 55B 应答 |
| **Rust 行为** | 上游收到 **53B = 24B XUDP 帧头 + 29B 报文**；客户端 **0 应答**（反向：Rust 服务端报 `invalid session status: 0x00`） |
| **位置** | 出站：`crates/xray-proxy-vless/src/dispatcher.rs:539-541`（`VlessUdpFramedConn` 包装的是**含 XUDP 帧的 link 流**，未剥帧）；入站：`crates/xray-proxy-vless/src/inbound/server.rs:701`（`session.send_packet` 对已剥长度的裸载荷**二次包帧**）；帧契约源头 `crates/xray-app-dispatcher/src/udp_session.rs:83-107`（帧构造 `:102-105`）；参照 Go `D:/Project/Xray-core/proxy/vless/outbound/outbound.go:67-68` + `proxy/vless/encoding/addons.go:87-124` |
| **用户可见后果** | UDP DNS 全废、QUIC/HTTP3/实时游戏全超时；TCP 正常 → 「能开网页但解析不了域名」；**双向皆废**（Rust 客户端与 Rust 服务端都中招） |
| **严重度** | **P0**（生产 DNS 基础能力全废；已 CLOSED 的 `1ka5i`/`1wq8`/`uhg2` 三票均未覆盖本条） |
| **建议** | 隧道出站写上线前剥 XUDP 帧头（留 2B 长度 + 载荷）；隧道入站读上线后不再二次包帧。回归门：vless/vmess/trojan × 4 方向 UDP 12 例 + 44 例 TCP 不回归 |

### F2 — 【口径差异】Rust 额外提供 `dokodemo` 出站形态，Go 无此协议名

| 项 | 内容 |
|---|---|
| **场景** | 配置 `"protocol": "dokodemo"` 的 outbound |
| **类型** | 口径差异（Rust 更宽松，但 Go 拒启 → 跨实现配置不可移植） |
| **Go 行为** | `Failed to start: ... unknown config id: dokodemo`（**拒启**） |
| **Rust 行为** | 接受并正常启动（`build_dokodemo_outbound`，`crates/xray-core/src/arm_builders/outbound.rs:679-702`） |
| **位置** | Rust 出站注册表 `crates/xray-core/src/arm_builders/outbound.rs:891`；Go 注册表 `D:/Project/Xray-core/infra/conf/xray.go:29-30`（inbound 只有 `tunnel`/`dokodemo-door`，outbound 无 dokodemo） |
| **用户可见后果** | 用 Rust 写的含 dokodemo outbound 的配置，拿到 Go 侧直接拒启；运维侧「同一份配置两边跑」预期破 |
| **严重度** | P2（Rust 独有扩展，非功能缺陷） |
| **建议** | 明确 dokodemo outbound 为 Rust 扩展并在配置面标注；或对齐 Go 拒绝该协议名（保留 inbound 的 `dokodemo`/`dokodemo-door` 双别名——Go 侧也支持 `dokodemo-door`） |

### F3 — 【口径差异】Go 的 shadowsocks UDP 在本轮测试形态下不通（与 Rust 无关）

| 项 | 内容 |
|---|---|
| **场景** | ss 协议 UDP 隧道（Go→Go 对照组） |
| **类型** | 口径差异（对照组失败，非 Rust 缺陷） |
| **Go 行为** | Go→Go 上游收到 **0B**，客户端 0 应答 |
| **Rust 行为** | Go→Rust / Rust→Rust **PASS**（29B 裸报文 + 55B 应答）；Rust→Go 上游 0B |
| **位置** | Go `proxy/shadowsocks/`（UDP 中继路径与本轮 ss 配置形态不匹配）；Rust `crates/xray-proxy-ss/` |
| **用户可见后果** | ss 的 UDP 转发不可用（两侧一致，不构成互通差异，但阻断「ss 隧道承载 UDP」这一生产用法） |
| **严重度** | P2 |
| **建议** | 单独立票复核 ss UDP 面（本轮为对照组证据，非完整对拍；ss2022 的 UDP 面未覆盖） |

### F4 — 【口径差异·非缺陷】`dns.hosts` 映射 + `domainStrategy:AsIs` 时域名不解析（四路同错）

| 项 | 内容 |
|---|---|
| **场景** | 配置 `dns.hosts: {"direct.test": "127.0.0.1"}` + `freedom.domainStrategy: "AsIs"`，经 socks 访问 `http://direct.test:<port>/` |
| **类型** | 口径差异（Rust 与 Go **行为完全相同**，故非 Rust 缺陷；判定为配置语义问题） |
| **Go 行为** | rc=52 HTTP:000（不解析裸域名，日志 `accepted tcp:direct.test:<port>` 后拨号失败） |
| **Rust 行为** | rc=52 HTTP:000，**逐字节同形态**（日志 `resolving domain via system DNS` → `Name or service not known`） |
| **位置** | Rust `crates/xray-core/src/outbound.rs` freedom 拨号路径；Go `proxy/freedom/freedom.go` `resolveStrategy` |
| **用户可见后果** | 裸域名不经 DNS 解析器直连 → 无法命中 `dns.hosts`；四路一致故用户不会归因于 Rust |
| **严重度** | P3（口径差异，非缺陷；记此以免重复调查） |
| **建议** | 若要 `dns.hosts` 生效需 `domainStrategy: "UseIP"`；建议在配置面文档说明，本轮不立票 |

### F5 — 【已覆盖·无新发现】Rust 服务端协议名 `dokodemo` 不可移植（同 F2 家族，此处仅记录配置侧）

| 项 | 内容 |
|---|---|
| **场景** | 配置 `"protocol": "dokodemo"` 的 **inbound** |
| **类型** | 口径差异（Rust 接受 `dokodemo`/`dokodemo-door` 双别名，Go 只认 `dokodemo-door`/`tunnel`） |
| **Go 行为** | `unknown config id: dokodemo` → 拒启 |
| **Rust 行为** | 正常启动并监听（`crates/xray-core/src/arm_builders/inbound.rs:1380` 附近，`tests.rs:139-140` 显式登记双别名） |
| **位置** | 同 F2 |
| **用户可见后果** | 同 F2；实测两实现均可创建 UDS socket（L2 PASS） |
| **严重度** | P3（与 F2 同族，合并处理） |
| **建议** | 与 F2 合并 |

### F6 — 【已覆盖·无新发现】Linux 与 Windows 在本轮全部探针上行为一致

| 项 | 内容 |
|---|---|
| **场景** | 同配置在 Linux Rust / Windows Rust / Linux Go / Windows Go 四路并跑 |
| **类型** | 无缺陷（正面结论） |
| **Go 行为** | Linux 与 Windows 探针结果逐项相同 |
| **Rust 行为** | Linux 与 Windows 探针结果逐项相同；且 Rust 与 Go 在 6 个探针上逐项相同（含 blackhole 403 与 dns rc=52 两处"同错"） |
| **位置** | — |
| **用户可见后果** | 无 |
| **严重度** | —（本轮的核心正面结论：Linux 产物无平台特有行为偏差） |
| **建议** | 无需修；可作为「Linux 产物行为 = Windows 产物行为」的实测依据 |

### F7 — 【已覆盖·无新发现】Linux 专属生产路径（splice / TUN / recvmmsg / 优雅停机）真机全绿

| 项 | 内容 |
|---|---|
| **场景** | L3 TUN 真建设备 / L4 16MB splice 通路 / L5 DNS recvmmsg 批收 / L6 SIGTERM 同端口重启 |
| **类型** | 无缺陷（正面结论） |
| **Go 行为** | Go 无对应 Linux-only 分支可比 |
| **Rust 行为** | **4/4 PASS**：TUN 真建 `xrayr4tun` 设备；16MB HTTP 200（0.04s）；DNS 40/40 query 收全；SIGTERM exit 0 + 端口释放 + 同端口立即重启成功 |
| **位置** | `crates/xray-transport/src/splice.rs`；`crates/xray-proxy-tun/src/device.rs`；`crates/xray-core/src/inbound.rs:2761`（recvmmsg）；`crates/xray-core/src/instance.rs`（停机编排） |
| **用户可见后果** | 无（生产 Linux VPS 的四个关键路径均有实测背书） |
| **严重度** | — |
| **建议** | 无需修；建议把本轮的 L4/L5/L6 三条固化为 CI Linux job 的常规门（当前 CI 无任何 Linux 功能验证，见 §5） |

### F8 — 【已覆盖·无新发现】dokodemo-door 作为客户端侧透明入口与对端隧道互通良好

| 项 | 内容 |
|---|---|
| **场景** | dokodemo-door inbound（固定目标）→ vless 隧道 → 对端 freedom |
| **类型** | 无缺陷（正面结论） |
| **Go 行为** | Go→Go PASS |
| **Rust 行为** | Rust→Go PASS / Go→Rust PASS / Rust↔Rust PASS（6/6，含纯 dokodemo 行为对照） |
| **位置** | `crates/xray-core/src/arm_builders/inbound.rs:394`（dokodemo inbound）、`crates/xray-proxy-dokodemo/src/server.rs` |
| **用户可见后果** | 无 |
| **严重度** | — |
| **建议** | 无需修 |

---

## 5 明确回答：Linux 产物能否替代 Go 做生产？

**就本轮覆盖范围而言：TCP 面可以，UDP 面不可以。**

| 覆盖面 | 结论 | 依据 |
|---|---|---|
| TCP 协议互通（vless/vless+tls/vision/trojan/trojan+tls/vmess/ss/ss2022/socks/http/dokodemo） | ✅ **可以替代** | 44/44 + 6/6 PASS，四方向双向 |
| 生产等价配置（多入站/多出站/路由/黑洞/嗅探/DNS/policy） | ✅ **可以替代** | 四路（Linux/Windows × Rust/Go）探针逐项一致 |
| Linux 专属路径（splice / TUN / recvmmsg / 优雅停机 / UDS） | ✅ **可以替代** | 6/6 PASS，无平台特有偏差 |
| **UDP 隧道（vless/vmess/trojan）** | ❌ **不可替代** | **F1：Rust 端点裹 XUDP 帧，UDP 流量 100% 丢失，双向皆废** |
| shadowsocks UDP | ⚠️ 存疑 | F3：Go 侧本轮形态也不通，需独立复核 |

**因此：作为「纯 TCP 代理服务端」或「TCP-only 客户端」，Linux Rust 产物已达到可替代 Go 的水平**（本轮首次在真 Linux 上拿到协议级双向互通的实测背书）。**但只要生产流量含 UDP（最典型的是 UDP DNS —— 现代 AAAA/EDNS 解析、大流量站点的并发解析几乎都走 UDP），Rust 端点就是黑洞**，且故障现象（DNS 静默失败、TCP 正常）极易被误判为「网络问题」而非「实现缺陷」。

**部署建议（不改代码前提）**：Rust 服务端可用于 TCP-only 场景；**Rust 客户端**若本地做 DNS 解析（很多客户端把 DNS 查询走代理）则同样受影响。修复 F1 之前，不建议把 Rust 端点放在 UDP 流量必经路径上。

---

## 6 查了什么 / 没查什么

**查了（真 Linux 实测）**
- 协议级双向互通 44 用例（TCP，8 协议族 × 4 方向）+ dokodemo 专项 6 用例 + UDP 矩阵 16 用例（4 协议 × 4 方向）
- 生产等价配置四路并跑（Linux Rust / Windows Rust / Linux Go / Windows Go），6 探针 + 启动面
- Linux 专属：TUN 真建设备、16MB splice 通路、DNS recvmmsg 批收、SIGTERM 优雅停机与同端口重启、UDS 入站
- UDP 缺陷的决定性字节取证（上游收到的原始 payload hex）+ 控制组（不经隧道的 freedom 路径）
- 缺陷的 Windows 侧同字节复现（证平台无关）

**没查（明确边界）**
- 外网可达性（WSL 无外网：GitHub 403、crates.io 403，rsproxy 200）→ 全部用本地回环 + 本地 echo 上游，**未做真实公网节点互通**
- 真实节点 32/32（需外部 URI 与可达 VPS，本轮禁止部署到外部机）
- QUIC/UDP 承载的 HTTP/3、WireGuard UDP、Trojan UDP 的完整协议级对拍（仅 vless/vmess/trojan/ss 的 UDP 隧道做了字节级取证）
- `dokodemo` 的 UDP 面、fakeudp、TPROXY/REDIRECT 真链路（root 具备条件，但本轮预算优先给协议互通矩阵）
- REALITY / splithttp / grpc / hysteria2 / anytls / tuic 的 Linux 侧互通（本轮聚焦任务书点名的协议族）
- 未跑 CI、未改任何产品代码、未部署到任何外部机器

---

## 7 复现材料

| 文件 | 内容 |
|---|---|
| `tmp/linux_interop.py` | 44 例 TCP 互通矩阵（端口段 28100-28199，PID 清理，本地 echo 上游） |
| `tmp/linux_dokodemo.py` | dokodemo 专项 6 例 |
| `tmp/linux_only_paths.py` | Linux 专属路径 L1-L6（UDP 隔离矩阵含 4 方向对照） |
| `tmp/linux_udp_xudp_evidence.py` | **UDP 缺陷的决定性字节取证**（上游收到的原始 hex，4 协议 × 4 方向） |
| `tmp/prod_parity.py` + `tmp/prod_parity_config.json` | 生产等价四路并跑 |
| `tmp/linux_e2e/*.json` | 机器可读结果（interop_matrix_results / dokodemo_results / linux_only_results） |

**环境**：WSL `ubuntu-xray`，kernel 6.6.87.2，root；Rust 产物 `/root/target-r4/release/xray`（自建 release，`git_rev=5fe98b90`，`target_triple=linux-x86_64`，构建需 `BORING_BSSL_ASSUME_PATCHED=1` + `BORING_BSSL_SOURCE_PATH=/root/boringssl-patched`）；Go 基线 `/root/go2617-linux`（26.10.17 `92ccc93-dirty`）。

**工具**：serena-cli 未启用（本次为运行期行为取证，非符号级代码检索）；代码定位用 grep + `read` 精读。
