# Verify-XUDP — X1..X4 独立复核（Windows 本地实跑，字节级自证）

- 复核人：VerifyXudp（独立复核，非重复审计）
- 基准：Rust `D:/Project/Xray-core-rust/target/release/xray.exe`（git_rev `5fe98b90`）/ Go `D:/tmp/go2617/xray.exe`（26.10.17）
- 环境：Windows 11 / 本机 loopback，端口段 28200-28249，UDP 上游记录器（Python，录字节）
- harness：`reports/audit-2026-10-31-perf-mem-wiring/round4/scripts/verify_xudp/`（`vxudp_probe.py` / `final_evidence.py` / `cone_disabled.py` / `dokodemo.py` / `mux_mitigation.py` / `tap_capture.py`）
- 原始产物：`reports/audit-2026-10-31-perf-mem-wiring/round4/tmp/verify_xudp/*.json` + `tap_*.txt`
- 约定：**所有字节均为本轮我自己跑出来的**，未引用上一轮结论（上一轮结论只作为待验命题）。

---

## 0. 一句话结论

**X1 成立但需修正归因；X2 成立（且比原断言更广）；X3 成立；X4 成立。**

**精确机理（本轮字节级定位，比「裹了 XUDP 帧」更细一层）**：
Rust 与 Go 的 **XUDP/mux 帧格式其实逐字节相同**（`[2B len=20][2B session][1B status=1][1B opt=1][1B net=2][2B port][atyp+addr][8B GlobalID][2B data_len][data]`，24B 头）——Go 客户端 cone 模式的 wire 字节 `0014 0000 0101 026e32 017f000001 <gid8> 001d <29B>` 与 Rust 客户端送出的 53B **完全同构**。
**差别不在编码，在「哪一层负责剥帧」与「隧道出站送的是什么」**：

- **Go 的隧道 wire 上跑的是裸载荷**：plain UDP（command=UDP）= `[2B len][裸载荷]`，目标在 VLESS/VMess 请求头；cone 模式（command=Mux，v1.mux.cool:666）= mux 帧，**data 段是裸载荷**、目标在帧 meta。剥帧的是 **Go mux 服务端**（`common/mux/server.go:196` → `common/mux/reader.go` 的 `NewPacketReader` 只取 data 段的裸载荷）→ Go freedom 拿到 29B 裸报文 → 上游 29B ✅。
- **Rust 的隧道入站要的就是裸载荷**（`crates/xray-proxy-vless/src/inbound/server.rs:678-700`：`read_length_packet` → `session.send_packet` 自己裹 XUDP 帧）→ 所以 **Go→Rust（cone 关）能通**（实测 29B + 57B 应答 ✅，这是 Rust 入站一侧正确的直接证据）。
- **Rust 的隧道出站送的是 XUDP 帧**：`udp_session.rs:96-108` 往 dispatch link 写帧，隧道出站（vless `dispatcher.rs:539-541`/`570-620`、vmess `dispatcher.rs:355-357`、trojan `dispatcher.rs:143-145,195`）只加一层 `[2B len]`（trojan 是 addr+len+CRLF）后**原样搬运**，帧头一起上线 → 对端把整帧当载荷 → **上游 53B** ❌。
- **Rust mux 服务端把 data 段裸载荷直接交给 freedom**（`crates/xray-mux/src/worker.rs:380-390`），而 Rust freedom 只认 XUDP 帧（`crates/xray-proxy-freedom/src/udp.rs:344-352`）→ Go 默认 cone（走 mux）时**解帧失败静默丢包 → 上游 0 字节** ❌。
- **Rust↔Rust 直连隧道（mux 关）也废**：Rust 客户端上线的是 XUDP 帧，Rust 服务端按「裸载荷」再裹一层 → 上游 53B（双层裹帧）❌。
- **Rust↔Rust 开 mux 反而好**：Rust mux 客户端把 link 上的 XUDP 帧整段塞进 mux 帧 data 段，Rust mux 服务端原样透传 → freedom 解帧成功 → 29B ✅（**歪打正着**，跨实现立刻露馅）。

| 边界 | Rust 送出的 | 对端期待的 | 结果 |
|---|---|---|---|
| Rust 隧道出站 → Go 服务端 | XUDP 帧（24B 头 + 载荷） | 裸载荷 | 上游收到 53B 垃圾 → 废 |
| Rust 服务端 → Rust 服务端（无 mux） | XUDP 帧（客户端已裹） | 服务端再裹一层 | 上游 53B（双层）→ 废 |
| Go mux 服务端 → Rust mux 服务端 → Rust freedom | 裸载荷（mux data 段） | Rust freedom 要 XUDP 帧 | 静默丢弃 → 上游 0 字节 → 废 |
| Go 客户端(cone 关) → Rust 服务端 | 裸载荷 | 裸载荷（Rust 入站自己裹帧） | 29B ✅ 好 |

---

## 1. 独立字节级证据（本轮实跑）

### 1.1 载荷定义
29B 裸 DNS 查询（与上一轮同形态，便于对照）：

```
123401000001000000000000076578616d706c6503636f6d0000010001
```
（`12 34`=txnid，`0100`=flags，`0001`=qdcount，`00`*6，`07example03com00`=QNAME，`0001 0001`=QTYPE/QCLASS）

### 1.2 四向矩阵（vless，`final_evidence.py` 本轮 17:29-17:31 复跑 + 两次独立 ad-hoc 复跑，结果一致）

| 用例 | 上游收到 | 上游收到 hex（前 24B） | 客户端收到回包 |
|---|---|---|---|
| **rust → go** | **53B** | `0014 0000 0101 026e32 017f000001 0993929610ab4c20 001d` | **0B** |
| **go → rust（cone 默认开）** | **0B** | — | 0B |
| **go → rust（cone 关 / dest 端口 53、443）** | **29B** | `123401000001000000000000076578616d706c6503636f6d0000010001` | **57B（合法 DNS 应答）** |
| **go → go（对照组）** | **29B** | 同上裸报文 | 57B（合法 DNS 应答） |

rust→go 的 53B 完整字节（两次独立复跑，gid 每次随机）：

```
001400000101026e32017f000001733e71378efa962f001d123401000001000000000000076578616d706c6503636f6d0000010001
001400000101026e32017f0000010a6314103b03a00f001d123401000001000000000000076578616d706c6503636f6d0000010001
```

逐字段解码（24B 帧头）：

| 偏移 | 字节 | 含义 |
|---|---|---|
| 0-1 | `0014` | meta 长度 = 20 |
| 2-3 | `0000` | mux session id = 0 |
| 4 | `01` | status = New |
| 5 | `01` | opt = Data |
| 6 | `02` | network = UDP |
| 7-8 | `6e32` | port = 28210（上游端口 ✓） |
| 9 | `01` | atyp = IPv4 |
| 10-13 | `7f000001` | 127.0.0.1 ✓ |
| 14-21 | 8B | GlobalID（每次随机） |
| 22-23 | `001d` | data 长度 = 29 |
| 24-52 | 29B | **真正的 DNS 查询** |

⇒ 上游 DNS 服务器收到的是「帧头 + 查询」，真实 DNS 解析器直接判废 → 零回包。**这就是「53B = 24B XUDP 帧头 + 29B」的成因，且方向为 Rust→Go。**

### 1.3 wire 抓包（TCP tap，`tap_capture.py`）

- Go 客户端（cone **开**，默认）→ 服务端，72B C2S：
  `00 <uuid16> 00 03`（version + uuid + addonLen=0 + **command=Mux**）+ `0014 0000 0101 026e32 017f000001 63c9b3892156b174 001d` + 29B 载荷
  ⇒ Go cone 模式把 UDP 转成 **Mux command（v1.mux.cool:666）**，载荷是 **mux/XUDP 帧**（meta 带 GlobalID，data 段 2B 长度 + 裸载荷）。
- Go 客户端 → **Rust** 服务端（cone 开）：C2S 72B 同上，**S2C 仅 2B `0000`**（VLESS 响应头后无下文）→ Rust 服务端收了帧但没把 UDP 会话派发出去。
- Go 客户端（cone **关**）→ 服务端：57B C2S = `00 <uuid16> 00 02 6e32 01 7f000001`（**command=UDP**，目标写进请求头）+ `001d` + 29B 裸载荷。

### 1.4 其它协议（同一 harness，`final_evidence.py`）

| 用例 | 上游收到 | 判定 |
|---|---|---|
| vmess rust → go | **53B** | 废（同因） |
| vmess go → rust（cone 开） | **0B** | 废（同因） |
| **trojan go → rust** | **29B 裸 + 回包 57B** | **好**（Go trojan 不走 cone/mux） |
| trojan rust → go | **53B** | 废（同因） |

### 1.5 dokodemo-door（`dokodemo.py`）

| 用例 | 上游收到 | 判定 |
|---|---|---|
| dokodemo rust → go | 53B | 废 |
| dokodemo go → rust | 超时（0 字节） | 废 |
| dokodemo rust → rust | 53B | 废（Rust↔Rust 直连隧道同样废，见 §3） |
| dokodemo go → go | 29B | 好（对照） |

### 1.6 mux 开关对照（`mux_mitigation.json`，Rust 客户端开 mux）

| 用例 | 上游收到 | 判定 |
|---|---|---|
| rust → go（mux 关） | 53B | 废 |
| rust → go（mux 开） | 53B | 废（Rust mux 客户端把 **XUDP 帧**整段塞进 mux 帧 data 段 → Go mux 服务端只剥 mux 层，剩给 freedom 的仍是 53B XUDP 帧） |
| go → rust（mux 开） | 0B | 废 |
| **rust → rust（mux 开）** | **29B 裸** | **好**（Rust↔Rust 双层抵消，歪打正着） |
| rust → rust（mux 关） | 53B | 废 |

---

## 2. X1..X4 裁决表

| 编号 | 原断言 | 裁决 | 复现命令与字节证据 | 影响面 | 根因 file:line | 最小修法 | 触碰红线? | 验证门 |
|---|---|---|---|---|---|---|---|---|
| **X1** | Rust 隧道端点 UDP 载荷裹 XUDP 帧；Go→Go 上游收 29B 裸 DNS 报文；Rust→Go 上游收 53B = 24B XUDP 帧头 + 29B；反向（Rust 服务端）对二次包帧报 `invalid session status: 0x00` → 双向皆废 | **成立（53B 帧头+29B 与「双向皆废」实测复现；归因两处需修正）** | `python scripts/verify_xudp/final_evidence.py`（本轮 17:29-17:31 复跑）+ 2 次 ad-hoc 复跑：rust→go 上游 53B（`0014 0000 0101 026e32 017f000001 <gid8> 001d` + 29B）；go→go 29B 裸 + 57B 应答；go→rust(cone 开) **0B**（不是 53B）；go→rust(cone 关) 29B + 57B 应答 | vless/vmess/trojan 的 UDP-over-TCP 全废；dokodemo 全废；**Rust↔Rust 直连隧道（mux 关）亦废**；**trojan Go→Rust 是好的** | Rust 写帧：`crates/xray-app-dispatcher/src/udp_session.rs:96-108`；Rust 隧道出站原样搬运：`crates/xray-proxy-vless/src/dispatcher.rs:539-541,570-620`、`crates/xray-proxy-vmess/src/dispatcher.rs:355-357`、`crates/xray-proxy-trojan/src/dispatcher.rs:143-145,195`；通用桥 `crates/xray-app-dispatcher/src/default.rs:1932`；Rust 内部消费方按帧解：`crates/xray-proxy-freedom/src/udp.rs:344-352`；Rust mux 服务端透传裸载荷：`crates/xray-mux/src/worker.rs:380-390`；Go 侧裸报文消费：`proxy/freedom/freedom.go:419`、`transport/internet/udp/dispatcher.go:117-119`、`common/mux/reader.go` | **四处边界转换**：隧道出站解帧（上行）+ 隧道出站回程裹帧 + mux client 解帧 + mux server 裹帧；不动内部 link 契约 | **是**（数据面，见 §5.4） | 见 §6 |
| **X2** | 影响 vless/vmess/trojan 的 UDP over 隧道；控制组（不经隧道 freedom）PASS → 缺陷唯一定位在隧道段 | **成立且更广** | `dokodemo.py`：rust→go 53B / go→rust 超时 / go→go 29B；`final_evidence.py` vmess/trojan 同型；控制组 go→go 29B + 57B 应答 | 见 §3 影响面表 | 同上 | 同上 | 是 | 见 §6 |
| **X3** | 平台无关，Windows 侧同字节复现 | **成立** | 本轮全部证据均在 Windows 复现：53B 帧头逐字段与格式完全一致（meta len=20、gid 随机、data len=29） | 与平台无关（纯 wire 格式问题） | — | — | 否 | 加一条 Linux 复跑即可闭环 |
| **X4** | 32/32 真机矩阵与 interop 12/12 都没抓到（推测纯 TCP / 无 UDP 用例） | **成立** | `dist/run_full32.py:47` = `curl -x socks5h://...`（TCP）；`dist/interop_matrix.py:124-125` = 同款（TCP）；`dist/interop_hysteria.py` 有 UDP 但走 hysteria2 原生 UDP（不受影响路径） | CI 对 UDP-over-隧道 **零覆盖** | — | — | 否 | 见 §6（矩阵必须加 UDP 用例） |

---

## 3. 影响面判定表（逐项「废 / 好 / 未测」+ 补测代价）

| 路径 | 判定 | 依据 | 补测代价 |
|---|---|---|---|
| vless UDP over TCP 隧道（Rust client → Go server） | **废** | 上游 53B，零回包 | — |
| vless UDP over TCP 隧道（Go client → Rust server，Go 默认 cone 开） | **废** | 上游 0B | — |
| vless UDP over TCP 隧道（Go client → Rust server，cone 关 或 dest 端口 53/443） | **好** | 29B 裸 + 57B 应答 | — |
| vmess UDP over TCP 隧道 | **废**（双向同 vless） | 53B / 0B | — |
| trojan UDP over TCP 隧道（Go client → Rust server） | **好** | 29B + 57B | — |
| trojan UDP over TCP 隧道（Rust client → Go server） | **废** | 53B | — |
| socks5 UDP ASSOCIATE 经隧道 | **废**（同隧道段） | 与 vless 同一链路，仅入口不同 | — |
| socks5 UDP ASSOCIATE 不经隧道（直连 freedom） | **好** | 控制组 29B / 57B | — |
| dokodemo-door UDP 经隧道 | **废**（双向） | 53B / 超时 | — |
| **Rust ↔ Rust** UDP over 隧道（mux 关） | **废** | 53B（双层裹帧） | — |
| **Rust ↔ Rust** UDP over 隧道（mux 开） | **好** | 29B（歪打正着） | — |
| hysteria2 原生 UDP（Rust↔Rust / interop 脚本） | **未测（大概率好）** | Rust hysteria 出站自己解 XUDP 帧再转原生 `UdpMessage`（`crates/xray-proxy-hysteria/src/dispatcher.rs:28,176-179,290-293`），**跨不到隧道边界**；`dist/interop_hysteria.py` 已有 UDP 往返用例 | 跑一遍现成脚本即可（低成本） |
| tuic 原生 UDP | **未测（大概率好）** | 同上，`crates/xray-core/src/outbound.rs:2675-2679` 有 tuic UDP dispatch 测试；原生 UDP 不走隧道 framing | 低成本 |
| anytls | **未测** | 仓内未见 anytls UDP 路径 | 需先确认 anytls 是否支持 UDP |
| DNS over UDP 经隧道（vless/vmess/trojan） | **废**（继承隧道段） | 隧道段断了，DNS 必废；另注意 Go 客户端 dest 端口 = 53 时走 plain UDP 模式，此时 go→rust 反而是好的（§1.2） | 中等：需专用 mock DNS + 端到端解析断言 |
| QUIC / HTTP3（UDP over 隧道） | **废**（继承隧道段） | 同上 | 中等 |
| TUN 模式 UDP | **未测（推定废）** | TUN 入站走同一 dispatch link；未实测 | 中等：需 TUN + UDP 探针 |

**「废」的机理统一**：隧道出站把 link 上的 XUDP 帧原样搬到 wire（Rust→Go），或对端把裸报文塞进 Rust 期待 XUDP 帧的 link（Go→Rust 回程 / Go cone→Rust）。

---

## 4. 为什么一直没被发现

1. **32/32 真机矩阵只有 TCP**：`dist/run_full32.py:47` 用 `curl -x socks5h://127.0.0.1:<port> <url>`。`socks5h` 的 DNS 在**客户端本地**解析，隧道里一个 UDP 数据报都不走 → UDP-over-隧道路径在 32 个节点里是**零执行**。
2. **interop 12/12 也只有 TCP**：`dist/interop_matrix.py:124-125` 同款 curl。6 协议 × 2 方向全部 TCP。
3. **唯一带 UDP 的 interop 是 hysteria2**（`dist/interop_hysteria.py`，SOCKS5 UDP ASSOCIATE → UDP echo）。但 hysteria2 走**原生 UDP 消息**（`UdpMessage`），Rust hysteria 出站在**隧道内**就把 XUDP 帧转成原生格式，**根本碰不到隧道 framing 边界** → 恰好绕开了缺陷面。
4. **协议 census（12 例）同样是 TCP**：`reports/audit-2026-10-30/tmp/ProtocolCensus/bidir.py:438-441` curl over socks5h（POST /echo）。
5. **仓内单测覆盖的是「同实现内部自洽」**：`crates/xray-proxy-vless/src/inbound/server.rs:1249-1332` 的 `vless_outbound_udp_roundtrip_e2e` 直接 `make_dial_fn` + 手写 payload，走不到 dispatcher link；`crates/xray-app-dispatcher/src/udp_session.rs` 的测试用 EchoHandler 回写 XUDP 帧（自洽闭环）。**Rust 内部自洽 ≠ 与 Go 互通**。
6. **生产用户多久踩到**：不是「立刻全网爆炸」，而是**静默劣化**——
   - 隧道内 DNS over UDP：Rust 客户端 → Go 服务端时上游收到 53B 垃圾，真实解析器丢弃 → 表现为 DNS 解析超时/SERVFAIL，而不是报错；
   - 回程 `invalid session status: 0x00`（`crates/xray-xudp/src/packet.rs:40` + `crates/xray-core/src/inbound.rs:479` 的 socks 入站日志）只打在 **Rust 客户端**侧，不是服务端（修正上一轮归因）；
   - QUIC/HTTP3、游戏、VoIP、TUN 模式 UDP 全部哑掉；
   - 系统 DNS 走隧道外的用户**完全无感**（这也是它能潜伏的原因）；
   - Go 客户端 + Rust 服务端更糟：**默认 cone 开 → 上游 0 字节，完全黑洞**（只有 dest 端口 53/443 或显式 `xray.cone.disabled=true` 才通）。

---

## 5. 根因与最小修法方向

### 5.1 两个互不兼容的内部契约

| | 内部 UDP dispatch-link 上跑的是什么 | 证据 |
|---|---|---|
| **Go** | **裸报文**；目标地址放在 `buf.Buffer.UDP` 元数据里 | `proxy/freedom/freedom.go:419` `buf.Copy(input, writer, ...)`（input=link.Reader，writer=UDP PacketWriter）——freedom **完全不解析 XUDP**；`common/mux/server.go:196-240` mux 服务端 `NewPacketReader` 取出 data 段裸报文直接写给被派发的 outbound |
| **Rust** | **XUDP 帧**（自带 per-packet 目标 + GlobalID） | `crates/xray-app-dispatcher/src/udp_session.rs:83-108` 生产；`crates/xray-proxy-freedom/src/udp.rs:229-360`、`crates/xray-core/src/outbound.rs:1684-1692`（dns）、hysteria/tuic/ss/wg 全部按 XUDP 帧消费 |

Go 侧 XUDP 只出现在**两个地方**：① mux/XUDP 帧（`common/xudp/xudp.go:95-135`，即 cone 模式 VLESS 的 wire 格式）；② mux 服务端按 GlobalID 复用会话（`common/mux/server.go:195-240`）。Go 的 **dispatch link 从来不是 XUDP 帧**。

### 5.2 偏差点（file:line）

Rust 侧（把内部 XUDP 帧当 wire 载荷原样搬运）：
- `crates/xray-app-dispatcher/src/udp_session.rs:96-108` —— 首帧 New(+GlobalID)、后续 Keep，`meta.write_to` + 2B 长度 + 载荷，**写进 dispatch link**。
- `crates/xray-proxy-vless/src/dispatcher.rs:539-541` + `crates/xray-proxy-vless/src/dispatcher.rs:570-620`（`VlessUdpFramedConn::poll_write`：只加 `[2B len]` 前缀，chunk 原样）—— 隧道出站把 link 字节原样写 wire，**帧头一起上了线**。
- `crates/xray-app-dispatcher/src/default.rs:1932`（`bridge_link_with_stream_full(link, remote, ...)`）—— link ↔ wire 的通用桥，**逐字节搬运，不解帧**；这是「link 上是什么，wire 上就是什么」的执行点。
- `crates/xray-proxy-vmess/src/dispatcher.rs:355-357`（`VmessUdpConn`）、`crates/xray-proxy-trojan/src/dispatcher.rs:143-145,195`（`write_udp_packet(addr,port,chunk)`，chunk = link 字节 = XUDP 帧）——同型。
- `crates/xray-mux/src/worker.rs:380-390`（`handle_xudp_new` 把 mux 帧 data 段**裸报文**直接写给被派发 outbound）——Rust freedom 期待 XUDP 帧 → 解析失败静默丢包。
- `crates/xray-mux/src/client.rs:447-449` + `crates/xray-mux/src/writer.rs:236-264`（Rust mux 客户端把 link 的 XUDP 帧整段当 mux 帧 data 段写出）→ Go mux 服务端再剥一层长度 → 错位。
- `crates/xray-core/src/inbound.rs:479` + `crates/xray-xudp/src/packet.rs:40` —— 回程裸报文被当 XUDP 帧解 → `invalid session status: 0x00`（**在客户端侧**）。

Go 侧对照（正确形态）：
- `proxy/freedom/freedom.go:419`（`buf.Copy(input, writer, ...)`，input=link.Reader，writer=UDP PacketWriter）—— **裸报文直发 socket**，freedom 不解 XUDP。
- `transport/internet/udp/dispatcher.go:117-119`（`conn.link.Writer.WriteMultiBuffer(buf.MultiBuffer{payload})`）—— Go 的 dispatcher 往 link 上写的是**裸载荷**（目标放在 `b.UDP` 元数据，`dispatcher.go:153-158` 读回）。
- `common/mux/server.go:196` + `common/mux/reader.go`（`NewPacketReader`）—— mux 服务端从帧 data 段只取**裸载荷**（目标在帧 meta），写给被派发 outbound → Go 侧 freedom 拿到裸报文。
- `common/xudp/xudp.go:95-135`（`PacketWriter.WriteMultiBuffer`）—— Go 的 XUDP 帧写法：`[2B len][2B session][New][Opt][UDP][addr+port][GlobalID 8B][2B data len][data]`，**与 Rust `crates/xray-xudp/src/packet.rs` 的帧格式逐字节同构**（这就是为什么 Rust 送的 53B 与 Go 送的 53B 完全一样）。
- `proxy/vless/outbound/outbound.go:303-306` —— cone 开启且 dest 端口 ∉ {53,443} 时，UDP → `RequestCommandMux` + `v1.mux.cool:666`。
- `proxy/vless/outbound/outbound.go:319-321` + `common/xudp/xudp.go:95-135` —— cone 模式载荷 = mux/XUDP 帧（meta + GlobalID + 2B 长度 + 裸载荷）。
- `proxy/vless/encoding/encoding.go:80-82`（MultiLengthPacketWriter/Reader）—— plain UDP 模式载荷 = 2B 长度 + **裸报文**。

### 5.3 改哪一层？——建议 **隧道/mux 边界做转换**（不动内部 link 契约）

**主修（P0，最小面）**：内部 dispatch link 继续跑 XUDP 帧（Rust 内部 6+ 消费方 freedom/dns/hysteria/tuic/ss/wg 全不动），在**跨实现的三个边界**上做表示转换：

1. **隧道出站（client 侧，vless / vmess / trojan）**：
   - **上行**：link 的 XUDP 帧 → **解帧取裸载荷**，按各协议 wire 格式写（VLESS/VMess = `[2B len][裸载荷]`；Trojan = `[addr+port][2B len][CRLF][裸载荷]`）。目标地址：VLESS/VMess plain 模式的目标在请求头（取首帧目标，一隧道一目标，与 Go plain 一致）；后续帧目标不同 → 只能走 cone/mux 模式。
   - **下行**：wire 上的裸载荷（Go 服务端回的是裸载荷）→ **裹成 XUDP 帧**再写回内部 link。**这一步同样缺失**：Rust 客户端 socks 入站（`crates/xray-core/src/inbound.rs:479` 的 `UdpDispatchSession::recv_packet`）按 XUDP 帧解，收到裸载荷就解不出 → 客户端零回包（实测 client_reply_len=0）。上一轮引用的 `invalid session status: 0x00` 字符串就在 `crates/xray-xudp/src/packet.rs:40`（`PacketError::InvalidStatus`），由 `crates/xray-core/src/inbound.rs:479` 打点——**该报错属 Rust 客户端侧（回程解帧），不是 Rust 服务端**（本轮 Rust 服务端日志只有探针噪声 `vless decode: io error: early eof`，无该错误）。
2. **Rust mux client（`crates/xray-mux/src/client.rs:530-560` 的 `fetch_input` → `writer.rs:236-264` 的 `write_meta_with_frame`）**：mux 帧 data 段现在写的是 link 里的 **XUDP 帧**。应改为**裸载荷**（与 Go mux 客户端一致：Go 的 mux data 段是裸载荷，目标在帧 meta 里）。
3. **Rust mux server（`crates/xray-mux/src/worker.rs:380-390` 的 `handle_xudp_new`）**：data 段现在**裸报文直接写给被派发 outbound**（Rust freedom 期待 XUDP 帧 → 解帧失败静默丢包）。应改为**裹成 XUDP 帧**再写（帧的目标 = 帧 meta 的 target，GlobalID = meta 的 global_id）——与 (2) 对称。这一处正是「Rust↔Rust 开 mux 时 29B 裸（好）」与「Go→Rust 开 mux 时 0B（废）」的分水岭：Rust 自家两端刚好互相抵消，跨实现就露馅。
4. **Rust 服务端隧道入站（`crates/xray-proxy-vless/src/inbound/server.rs:645-724` 等）**：plain UDP 模式当前是「收到裸报文 → 裹 XUDP → 派发」，**已正确**，保持。

> 四处改动**互相独立且必须同时做**：只改出站 → 回程仍零应答；只改 mux → plain 模式仍 53B。

**备选（结构性，范围大）**：把内部 dispatch-link 契约整体改成 Go 形态（裸报文 + per-packet 目标元数据）。这会牵动 freedom/dns/hysteria/tuic/ss/wg/mux-server 全部消费方 + 所有断言 XUDP 帧的测试；**语义上更「正统」，但工程面大一到两个数量级**，不建议作为 P0 急救。

**明确不建议**：改 `udp_session.rs` 让它写裸报文（那样 freedom/dns/hysteria/tuic/ss/wg 六个消费方一起炸），或只在某一个协议上打补丁（vless/vmess/trojan 三者必须同改，否则又造一个半修不修的特例）。

### 5.4 是否触碰坑约束 12（数据面热路径零改动）

**触碰，但范围可控、且不是 vision/splice 战场**：
- 受影响面 = **UDP 隧道段**（每包多一次「解 XUDP 帧 → 取载荷」或「裹帧」），TCP 面（154-167 MB/s 锚）不受影响。
- 不碰 vision gate、不碰 `bridge_link_with_stream` 的 splice 语义、不碰 `xray-transport-tcp/register.rs`。
- 但按 CLAUDE.md 的纪律，**任何数据面改动都要走 review 门 + 需要一个 UDP 面性能锚**（现有 baseline 只有 TCP 锚，UDP 段没有）。⇒ 修法必须写成「零额外拷贝」形态（沿用 `Buffer` 池化 + 原地剥头，参考 `crates/xray-app-dispatcher/src/udp_session.rs` 里 `ChainCursor` 免摊平的既有做法），否则会引入每包一次分配。

---

## 6. 验证门（修完必须跑才算真修好）

**A. 字节级互通（新增脚本，建议落 `dist/interop_udp_tunnel.py`）**
1. vless / vmess / trojan × {Rust→Go, Go→Rust, Rust→Rust, Go→Go} × {cone 开, cone 关} × {dest 端口 53/443/其它} 四象限；
2. 断言 **上游收到的第一包必须恰好等于 29B 裸 DNS 查询**（逐字节 hex 相等，**不是**「长度相近」）；
3. 断言 **客户端收到 57B 合法 DNS 应答**（含 txid 回显 + answer 段），不得为 0；
4. 断言 Rust 客户端日志**不得出现** `invalid session status` / `socks udp dispatch recv failed`；
5. mux 开/关两态都要跑（Rust mux client/server 的 data 段表示改动必须被覆盖）。

**B. 既有矩阵补 UDP 用例（堵 X4 盲区）**
6. `dist/run_full32.py` 每个节点加一条 **UDP 探针**（socks5h UDP ASSOCIATE → 本地 UDP echo / DNS mock → 字节比对），不是只加一条 TCP curl；
7. `dist/interop_matrix.py` 12 例同样补 UDP 腿（当前 6 协议 × 2 方向全 TCP）；
8. `dist/interop_hysteria.py` 保持（原生 UDP，作为「不该被隧道缺陷波及」的对照组）。

**C. 回归**
9. `cargo test --workspace --all-targets`（含 `crates/xray-app-dispatcher/src/udp_session.rs`、`crates/xray-mux/tests/integration.rs`、`crates/xray-proxy-vless` / `vmess` / `trojan` 的 UDP 用例）；
10. `cargo clippy --workspace --all-targets -- -D warnings` + `cargo fmt --all -- --check`；
11. 32/32 全绿 + interop 12/12 全绿 + 新增 UDP 腿全绿；
12. 抓包留证（wire 上**不得**出现 `0014 0000 0101 ...` 这类 XUDP 帧头，UDP 载荷前应是协议自身的 2B 长度或 addr+CRLF）。

**D. 性能**
13. UDP 面新增 alloc/MB 基线（隧道段每包零额外分配），防修法引入回归。

---

## 7. 未覆盖范围（本轮没查的）

1. **hysteria2 / tuic / anytls 的 Go↔Rust 原生 UDP 互通**：只做了代码路径判读（不跨隧道边界 → 推定不受影响），**未实跑** interop；anytls 的 UDP 能力本身未确认。
2. **TUN 模式 UDP**：未实测（推定继承隧道段缺陷）。
3. **DNS over UDP 经隧道的端到端解析断言**：本轮 `dns_over_tunnel.py` 的 mock 记录口径自身有问题（go→go 对照组 `upstream_seen` 也为空），**该脚本结论作废**，DNS 判定是从 UDP 隧道段字节证据外推的，未拿到干净的 DNS 端到端证据。
4. **Linux 侧字节复现**：X3 只在 Windows 完成（结论为格式问题，与平台无关，但没跑 Linux）。
5. **多目标（cone 真语义）场景**：XUDP 帧的 per-packet 目标在隧道出站如何映射到「一隧道一目标」的 wire 格式，方案未定稿（Go plain 模式本身就丢多目标）。
6. **非隧道出站（socks outbound / dns outbound / wireguard / ss）的表示一致性**：只按代码路径判读，未逐个实跑。
7. **性能/内存计量**：按非目标未做。

---

## 8. 产物清单

| 文件 | 内容 |
|---|---|
| `scripts/verify_xudp/vxudp_probe.py` | 核心 harness（实例管理 / socks5 UDP associate / 配置模板） |
| `scripts/verify_xudp/final_evidence.py` | 四向 × (上游字节 + 回包字节 + 双方日志) |
| `scripts/verify_xudp/cone_disabled.py` | cone 开/关对照 + Rust 服务端 debug 日志 |
| `scripts/verify_xudp/dokodemo.py` | dokodemo-door 路径 |
| `scripts/verify_xudp/mux_mitigation.py` | mux 开/关 × 三协议对照 |
| `scripts/verify_xudp/tap_capture.py` + `tap.py` | TCP wire 抓包（C2S/S2C hex） |
| `tmp/verify_xudp/final_evidence.json` | 四向字节矩阵（本轮 17:29-17:31 复跑） |
| `tmp/verify_xudp/mux_mitigation.json` | mux 对照 |
| `tmp/verify_xudp/dokodemo.json` | dokodemo 对照 |
| `tmp/verify_xudp/tap_vless_*.txt` | wire 抓包原文 |
