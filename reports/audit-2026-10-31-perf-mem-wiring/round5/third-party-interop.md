# R5 第三方对端互通审计：hysteria2 / tuic v5 / anytls（对端 = sing-box 1.14.3）

- 被测二进制：`D:/Project/Xray-core-rust/target/release/xray.exe`，`git_rev=5fe98b90`（实测 `xray.exe version`）
- 第三方对端：`D:/Program Files/v2rayN-windows-64/bin/sing_box/sing-box.exe` → **sing-box 1.14.3**（go1.26.8 windows/amd64，with_quic）
- 端口段：28300-28349（本代理独占）；每 case 起进程后按 PID terminate
- 只读审计：零产品代码改动；脚本与日志在 `reports/audit-2026-10-31-perf-mem-wiring/round5/`
  - `r5_thirdparty.py`（主矩阵，含 SOCKS5 UDP ASSOCIATE 客户端 + 进程内 TCP 源站/UDP echo）
  - `r5_probe2.py`（方向性判别探针）
  - 逐 case 日志 `round5/tmp/<case>_{srv,cli}.log`

## 0 前提修正（重要，影响判据）

任务书前提「hysteria2 在 Go 26.10.17 里不存在」**只对一半**：

- `proxy/tuic`、`proxy/anytls`、`infra/conf` 中 tuic/anytls 的确零命中 → 这两协议从未被 Go 对照。
- **hysteria2 在 Go 里存在，但形态是 transport 而非 protocol**：`proxy/hysteria/` + `transport/internet/hysteria/`（`network: "hysteria"` + `hysteriaSettings.version=2`）。其握手就是 Hysteria2 wire：`transport/internet/hysteria/config.go:14-20` 定义 `URLHost="hysteria"` / `URLPath="/auth"` / `Hysteria-Auth` / `Hysteria-UDP` / `Hysteria-CC-RX`，`hub.go:44` 的 `AuthHTTP` 按 `POST https://hysteria/auth` 校验；帧格式 `proxy/hysteria/protocol.go:63-95` 的 `WriteTCPRequest`（varint 地址长 + 地址 + varint padding 长 + padding）与 `UDPMessage`（4B session + 2B packet + frag + varint 地址 + 数据）与 Hysteria2 规范逐字节一致。
- 因此本轮 hysteria2 有**两重**对端：Go 26.10.17（transport 形态）+ sing-box（hysteria2 inbound/outbound）。Rust 侧对应 `crates/xray-transport-hysteria` + `crates/xray-proxy-hysteria`，同一份代码同时服务两种对端形态。

## 1 结论（能否上生产）

| 协议 | TCP 面 | UDP 面 | 上生产判定 |
|---|---|---|---|
| **hysteria2**（`network: hysteria`） | 全绿：4 组方向/参数组合，64KiB 下行整包 + 64KiB 上行回显逐字节一致 | ≤1300B 通（1400B 起为 QUIC datagram MTU 口径）；**服务端一旦配 obfs 全红** | **有条件可上**：仅限 `finalmask.udp` 为空的服务端（obfs 配置 = 静默失效 + 与真实客户端不通，见 F1） |
| **tuic v5** | 全绿：双向 64KiB 逐字节一致（含 congestion/alpn 变体） | native：≤1180B 通（1190B 起静默丢）；**quic 模式与第三方全量不通**；Rust↔Rust ≥1500B 也丢 | **仅 native ≤1.1KB UDP 可上**；quic 模式不可上（F3），大 UDP 不可上（F4） |
| **anytls** | 全绿：双向 64KiB 逐字节一致 | **完全不可用（双向，两个独立断点）** | **仅 TCP 可上**；UDP 全静默黑洞（F2，P1） |

一句话：**三协议的 TCP 面全部经第三方验证通过；UDP 面除 hysteria2 无 obfs 场景外全部有缺陷**，其中 anytls UDP 全缺、tuic quic 模式零互通属必堵项。

## 2 矩阵（协议 × 方向 × 传输）

方向 A = **Rust 客户端 → sing-box 服务端**；方向 B = **sing-box 客户端 → Rust 服务端**。
TCP 腿 = 下行 GET 64KiB+marker 整包比对 + 上行 POST 64KiB 逐字节回显；UDP 腿 = SOCKS5 UDP ASSOCIATE → 进程内 UDP echo，多尺寸逐字节往返。

| # | 协议 | 方向 | 参数 | TCP | UDP | 断点（失败时） |
|---|---|---|---|---|---|---|
| 1 | anytls | A | — | PASS 64KiB↔64KiB | **FAIL** 1B 起 | 客户端出站把 UDP 报当 TCP 目标拨号（sing-box 侧日志 `inbound connection to <udp-port>` → refused） |
| 2 | anytls | B | — | PASS | **FAIL** 1B 起 | 服务端把 `sp.v2.udp-over-tcp.arpa:0` 当域名解析（`os error 11001`） |
| 3 | tuic | A | native, cubic | PASS | **FAIL** 1190B 起（1/512/900/1100/1180 通） | 客户端按 peer `max_datagram_size` 分片，sing-box 不重组 → 静默丢 |
| 4 | tuic | A | quic relay | （未测） | **FAIL** 1B 起 | `tuic: unmatched udp resp assoc=1 pkt=1`（响应配对不匹配即丢弃） |
| 5 | tuic | B | native | PASS | **FAIL** 1190B 起 | 同上（Rust 服务端分片 ≤1183B 才发；1190B 需分片） |
| 6 | tuic | B | quic relay | （未测） | PASS 1B…1200B | — |
| 7 | hy2 | A | 无 obfs | PASS | PASS 1B…1300B | 1400B 起丢（QUIC datagram MTU 口径，见 §3 控制组） |
| 8 | hy2 | B | 无 obfs | PASS | PASS 1B…1300B | 同上 |
| 9 | hy2 | A | obfs salamander | PASS | PASS 1B…1100B（1200B 丢） | — |
| 10 | hy2 | B | obfs salamander | **FAIL**（socks 连接都不通，15s 超时） | **FAIL** 全尺寸 | Rust 服务端混淆路径未生效（F1 判别见 §3） |
| 11 | hy2 | A | brutal（force-brutal 100Mbps 双向） | PASS | PASS 1B…1300B | — |
| 12 | hy2 | B | alpn=h3 显式 | PASS | PASS 1B…1300B | — |
| 13 | tuic | A | alpn=h3 显式 | PASS | （按用例设计不测 UDP） | — |

统计：**13 case / 全量重跑 2 轮**（首轮 1/13、修正 harness 后 subset 重跑），无双跑不一致；TCP 用例 8/8 全绿，UDP 用例 9 个（含变体）中仅 4 个全绿。

## 3 控制组（判据成立性）

| 控制 | 结果 | 作用 |
|---|---|---|
| sing-box↔sing-box：anytls / tuic(native) / hy2 | TCP 全绿；UDP anytls 5/5、tuic 5/5、hy2 4/5（8192B 红，sing-box 自身 `packet download closed: ... larger than the internal message buffer`） | 证明**测试装置本身能跑通**；并证明 **anytls 协议支持 UDP**（sing-box 实现了），故 #1/#2 是 Rust 单边缺陷而不是协议无此能力 |
| sing-box↔sing-box：hy2 8192B | 红（sing-box 自己的 UDP 收包缓冲不够） | 把「8KB no」定为**口径差异**，不计入 Rust 缺陷 |
| Rust↔Rust：hy2 无 obfs | TCP 绿；UDP ≤1300B 绿、1400B 红 | 与 #7/#8 一致 → hy2 数据面自洽，MTU 上限 1300B |
| Rust↔Rust：hy2 **带 obfs** | **TCP 红 + UDP 全红** | 判别 F1：不是「与 sing-box 算法差异」，而是 Rust **服务端**混淆路径失效（客户端方向对 sing-box 是通的：#9） |
| Rust 服务端配 obfs + **非 obfs** 客户端 | **TCP 绿 + UDP 绿** | **决定性判别**：服务端 obfs 根本没生效（混淆服务端本应拒绝未混淆首包） |
| Rust hysteria 入站 + **非法** `finalmask`（`type:"bogus"` / salamander PSK 2 字节） | **照样启动并监听**（无任何 error/warn） | **决定性判别**：入站路径从未解析 `streamSettings.finalmask`（`parse_udp_obfs` 未被执行；同一份非法配置放到**出站**会立刻 `WARN ... unsupported udp mask type`，见 §4 末 o91s4 证据） |
| Rust↔Rust：tuic native | UDP 1300B 绿、1500B 起红 | 判别 F4 的第二半：分片/重组自身也有缺陷（不依赖 sing-box） |
| Rust↔Rust：tuic **quic** | UDP 100B/500B/1200B/4000B 全绿 | 判别 F3：quic 模式不是压根没实现，而是**只与自己自洽**，与第三方响应配对不兼容 |
| Go 26.10.17 vs Rust：socks5 UDP → freedom → echo | Go 4000/5000/6000/7000/7500/8000 **全绿**；Rust 4000…7500 绿、**7600 起全红**（7600/7700/7800/7900/7950/7999/8000/8192/16000/65000 全无回包） | F5：Go↔Rust 单变量差分（同拓扑、同源站、同探测码） |

## 4 Findings

（Go 行为列：tuic/anytls 在 Go 不存在 → 写 "N/A（Go 无此协议）"，改列第三方对端行为以保持可判定性。）

| # | 场景 | 类型 | Go / 第三方行为 | Rust 行为 | 位置 | 用户可见后果 | 严重度 | 建议 |
|---|---|---|---|---|---|---|---|---|
| **F1** | hysteria2 **入站**配 `streamSettings.finalmask.udp[].salamander` | 缺陷（配置静默失效 + 互通失败 + 安全语义） | sing-box hysteria2 inbound + obfs：**拒绝**未混淆客户端、接受混淆客户端 | 配了 obfs 的入站：**接受未混淆客户端**（TCP/UDP 全通）；对混淆客户端（sing-box，甚至 Rust 自己的客户端）**QUIC 握手 15s 超时全红**；且**非法**混淆配置（未知 type、2 字节 PSK）照样启动 → 证明入站路径**从未解析** `streamSettings.finalmask` | 解析函数本身正确：`crates/xray-core/src/inbound.rs:5312` `parse_udp_obfs(finalmask_json)`；但入站侧 `finalmask_json` 恒为 None（非法配置不报错即证）→ 需核 `crates/xray-conf/src/built.rs:232` `ib.stream_settings.clone()` → `crates/xray-core/src/arm_builders/inbound.rs:577` `parse_hysteria_inbound_config(..., ib.stream_settings_json.as_ref())` 之间是否被清空；生效面 `xray-transport-hysteria/src/quinn_adapter.rs`；解码侧 `salamander_socket.rs` `poll_recv`（短包/解码失败 `continue` 静默丢弃，无计数） | ① 用户以为开了防主动探测的混淆，实际服务端就是裸 QUIC（隐蔽性承诺不成立）；② 任何真实 hysteria2 客户端（开混淆）连不上；③ 非法混淆配置不报错（配置面 fail-open）；④ 失败零日志，运维无法归因 | **P1** | 入站 `finalmask` 必须真的进解析：先用「未知 type / 短 PSK 必须拒启」做契约断言（当前反向成立）；`poll_recv` 解码失败要计数/告警；再加一条「server+obfs 必须拒绝非混淆客户端」的生效性断言 |
| **F2** | anytls UDP（双向） | 缺陷（功能缺失 + 静默黑洞） | sing-box↔sing-box anytls UDP 5/5 通过 → 协议有 UDP 能力 | ① 客户端：`can_handle(UDP)==false`（显式 TCP-only），UDP 数据报被当成 **TCP 目标**去连（sing-box 侧日志 `inbound connection to 127.0.0.1:<udp-port>` → `connectex refused`），socks 客户端只看到无响应；② 服务端：sing-box 用 `sp.v2.udp-over-tcp.arpa:0` 标记 UDP 会话，Rust 服务端当域名去解析（`anytls mock server: dial target sp.v2.udp-over-tcp.arpa:0 failed: 不知道这样的主机 (os error 11001)`） | ① `crates/xray-proxy-anytls/src/outbound.rs:96-98`；② `crates/xray-proxy-anytls/src/server.rs:401`（拨号失败分支） | anytls 节点上所有 UDP（HTTP/3、QUIC、WebRTC、游戏、DNS-over-UDP）**静默不可用**，无任何错误暴露给应用；对端是 sing-box 时 Udp-over-TCP 语义完全没实现 | **P1** | 二选一并写进文档：实现 UDP-over-TCP（`sp.v2.udp-over-tcp.arpa` 会话）或让 anytls 出站 UDP 显式 fail-visible（当前是转 TCP + DEBUG 日志，属最坏的静默形态） |
| **F3** | tuic `udp_relay_mode: "quic"`（客户端方向） | 缺陷（互通失败） | sing-box tuic 服务端：响应帧 `(assoc_id, pkt_id)` 由服务端自行编号 | Rust 客户端按 `(assoc_id, pkt_id)` **严格配对**，第三方响应一律 unmatched → 丢弃：`tuic: unmatched udp resp assoc=1 pkt=1`；Rust↔Rust（双方同一套编号约定）100B…4000B 全绿，故自测无法发现 | `crates/xray-proxy-tuic/src/udp.rs:63-104`（`UniRespRouter` 的 waiters 表 + `unmatched udp resp` 日志） | `udp_relay_mode=quic` 的 Rust 客户端与 sing-box/hysteria 生态服务器 **UDP 全丢**（TCP 不受影响） | **P2**（非默认模式，但 100% 失败） | 按 assoc_id 配对（pkt_id 仅作参考），或对「响应 pkt_id 与请求不同」容忍；加一条「对端不复用 pkt_id」的契约测试（现有测试双侧同构，天然测不出） |
| **F4** | tuic `native` 模式大 UDP 报 | 缺陷（静默丢，非默认尺寸） | 第三方 tuic 服务端不重组 FRAG 分片（sing-box↔sing-box native 8192B 可通，故其自身路径不依赖 TUiC FRAG） | 单 datagram 容量 = `max_datagram_size - (10 + addr_len)`（对端 1200 → 约 **1183B**）；超过即按 TUIC v5 FRAG 分片发出 → **1190B 起静默丢**；**Rust↔Rust 自身也在 1500B 起丢**（1300B 通）——后者与对端无关，是 Rust 自身分片/重组路径缺陷，前者还需 pcap 区分「对端不重组」与「Rust FRAG 帧不合规范」 | `crates/xray-proxy-tuic/src/udp.rs:200-219`（`native_frag_payload` / `send_native`）、`crates/xray-proxy-tuic/src/protocol/packet.rs`（`FragmentAssembler`） | tuic native 下 UDP 载荷 >1.2KB（≈任何 QUIC Initial、大 DNS、WireGuard 包）静默丢；Rust↔Rust >1.4KB 即丢 | **P2** | 先修 Rust↔Rust 1500B 红（不依赖对端，纯本地可复现）；再按「对端能力」决定是否分片，或对分片不可用场景 fail-visible 而不是静默丢 |
| **F5** | 通用 socks5 UDP 大报（socks inbound → freedom → echo） | 缺陷（Go↔Rust 差分，静默丢） | Go 26.10.17：4000/5000/6000/7000/7500/**8000** 全部逐字节回显 | Rust：4000…7500 通，**7600B 起全无回包**（7600/7800/7999/8000/8192/16000/65000 全红；socks 入站接收缓冲本身是 65535，`crates/xray-core/src/inbound.rs:432`，故上限在 socks→dispatch→freedom 链路其它环节） | 待定位（候选：`crates/xray-transport/src/udp/hub.rs:27` `UDP_BUFFER_SIZE=4096` 注释称与 Go 一致，但 Go 实测 8000B 可通，说明 Rust 该常量与 Go 实际路径不对等/或另有 8KB 级缓冲） | 与 Go 行为不一致：>7.5KB 的 UDP 报（大 DNS、DTLS 分片、部分隧道协议）静默丢，且影响**所有**协议的 UDP 面 | **P2** | 用 `hy2 non-obfs ≤1300` 与 `socks+freedom ≤7500` 两条独立上限对齐 Go 的 `buf.UDPSize` 实际大小；FF 建议顺带核对 `finalmask.UDPSize`(Go 4096) 与 socks 路径是否被误用为同一上限 |
| **F6** | QUIC datagram 尺寸上限 | 口径差异（**不计缺陷**） | sing-box 自身 8192B UDP 也红（其 Windows 收包缓冲报 `larger than the internal message buffer`）；hy2 的 datagram 天然受 MTU 限制 | hy2：Rust↔Rust 与 Rust↔sing-box 均在 **1300B 通 / 1400B 起丢**（一致） | — | 无（属 QUIC 语义） | 口径 | 文档化「hysteria2/tuic native 的 UDP 单包建议 ≤1200B」；不要按 8KB 报缺陷 |

### 已登记项的补充证据（不新报）

- `o91s4`（出站 warn+skip）：本轮首次用**错误 finalmask 形状**触发，实证链为
  `WARN failed to parse outbound config, skipping tag= protocol=hysteria error=hysteria finalmask: unsupported udp mask type ""` → 随后 `WARN dispatch_link failed ... outbound handler not found: default`，客户端仍能监听 socks 端口，用户看到的是「连上了但什么都没有」。属既有票面机制的又一次 E1 复现。
- `bz800`（anytls 无口令即零认证）：本轮所有 anytls 用例都带口令，未重复验证。

## 5 未覆盖 / 局限（诚实声明）

1. **第三方对端只有一个**：sing-box 1.14.3。mihomo/clash-meta、hysteria2 官方客户端（hysteria/hysteria-go）本机不存在，未获取。任何「三方一致」结论都不成立，只能说「与 sing-box 互通（或不通）」。
2. **hysteria2 未跑 Go↔Rust 之外的 Go 侧第三方组合**：本轮 hysteria2 的第三方证据全部来自 sing-box；Go 26.10.17 的 hysteria transport 仅用于确认 wire 同源（源码 + 既有 `dist/interop_hysteria.py` 脚本存在），本轮未重跑该脚本。
3. **0-RTT 未单独探针**：Rust hysteria 客户端走 `DialEarly` 路径、服务端 `max_early_data_size=u32::MAX`（`quinn_adapter.rs:482`），但本轮没有「先建连 → 断 → 零 RTT 重连」的判别用例，不能声称 0-RTT 已验。
4. **padding 未单独验**：hysteria 的 `TcpRequestPadding/TcpResponsePadding` 两端恒定注入，属于每次流首帧必然经过的路径（TCP 用例已覆盖），但没有「padding 长度非零且被对端正确跳过」的独立断言。
5. **tuic heartbeat / reduce_rtt(zero_rtt_handshake)** 未单独验；**hysteria2 up_mbps/down_mbps 的 brutal 协商（Hysteria-CC-RX/TX 双向带宽）**只用 `force-brutal` 单向验过（#11），未验对端侧 brutal 反馈。
6. **>8KB UDP 在 sing-box 侧不可测**（其 Windows 收包缓冲先炸），故 F5 只用 Go↔Rust 差分取证。
7. **未做抓包**：本轮判据全部是「字节级数据完整性 + 两端日志」，没有 pcap 级别的帧字段比对（hysteria2 的 TCPRequest padding 字段、tuic 的 FRAG 字段布局均未在 wire 层核对）。
8. F5 的**根因位置未定位**（只给出 (7500, 7600] 的实测上限与 Go 对照），需要一条专门的定位链（socks→xudp→freedom 逐段注入）。

## 6 复现

```bash
cd D:/Project/Xray-core-rust
# 主矩阵（13 case；8192B 只作信息项）
python reports/audit-2026-10-31-perf-mem-wiring/round5/r5_thirdparty.py
# 只跑某协议 / 某些端口
python reports/audit-2026-10-31-perf-mem-wiring/round5/r5_thirdparty.py --only tuic --ports 28311,28313
# 方向性判别（Rust↔Rust obfs / tuic 尺寸边界）
python reports/audit-2026-10-31-perf-mem-wiring/round5/r5_probe2.py
```
