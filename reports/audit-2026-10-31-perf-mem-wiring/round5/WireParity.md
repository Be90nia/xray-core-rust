# 第五轮：传输层帧级 wire 差分（Go 26.10.17 ↔ Rust HEAD）

- 仓库 `D:/Project/Xray-core-rust`，分支 `feature/fix-inbound-parity`，HEAD `5fe98b90`
- 基准二进制 Go `D:/tmp/go2617/xray.exe`（Xray 26.10.17，`92ccc93-dirty`）；被测 Rust `target/release/xray.exe`（`git_rev=5fe98b90…` = HEAD）
- 端口段 28300–28349 / 28400–28449；清理只按 PID（`Popen.kill()`），全程无 `-Name`/taskkill 通配
- **方法（t0ls1 套路的通用化）**：客户端 socks 入站 → 传输出站 → **录制中继**（明文落盘，双向分连接记账）→ 服务端传输入站 → freedom(`finalRules:[{action:"allow"}]`) → 本地 echo。载荷 = 确定性伪随机，**上行 64KB + 下行 64KB 逐字节回验**；多流用例每子流用不同 seed（串流必然被抓）。
- 判据是**帧级/字节级**：不仅比「连通」，还比段头、POST body 重组字节、WS 帧头、HTTP/2 帧头与 SETTINGS、mux carrier 帧。
- 全部用例 `security:"none"`：这样中继抓到的是**明文 wire**（用 TLS 会比到密文，毫无判别力）。TLS/REALITY 面不在本轮范围。

---

## 0 一句话结论

**七个传输在 36 个跨实现组合里没有一条「能连但数据错/丢」**——KCP 段字节、splithttp POST body 重组字节、mux 帧字节都与 Go **逐字节一致**（仅目标端口不同）。

差异全部落在**行为口径层**而非数据层，最值得处理的是三条与「连接/窗口」有关的：Rust xhttp 每会话多 1 条零字节 TCP、Rust ws 默认开预连接池（Go 无此机制）、Rust gRPC 流控窗口比 Go 大 2 个数量级（16MB vs 98KB/128KB）。

---

## 1 传输 × 方向矩阵

方向定义：**R2G = Rust 客户端 → Go 服务端**；**G2R = Go 客户端 → Rust 服务端**；R2R / G2G 为同实现对照（用于把「实现差异」与「配置本身不可行」分开）。

| 传输 / 用例 | R2G | G2R | 判据（除双向连通外） |
|---|---|---|---|
| tcp-control（对照） | PASS | PASS | 上行重组 131098B / 下行 131074B 两侧同值；echo sha 一致 |
| tcp-multi4（4 并发） | PASS | PASS | 4 条子流各自 sha 互异且各回本路（无串流） |
| **KCP**（mtu1350/tti20/none） | PASS | PASS | 段头 `conv u16BE/cmd/opt=0`、`ts/sn/una/len` 布局一致；`leftover_bytes=0`；data 段上限 1332=1350-18；ack 段 `win/una/ts/count/numlist` 一致 |
| KCP + `seed` | PASS | PASS | 抓包两侧均明文（见 §2.4：`seed` 在 Go 26.10.17 已是死键） |
| **ws** | PASS | PASS | upgrade 头集合、WS 帧头（mask/opcode/len）、帧边界 |
| ws + `wsSettings.ed` | PASS | PASS | Rust 发 `Sec-WebSocket-Protocol`，Go 忽略该键（见 §2.5） |
| ws + `path:"…?ed=N"` | PASS | PASS | 两侧都从 path 剥 `ed`（请求行为 `/ws`），ED 触发条件见 §2.6 |
| ws`?ed=N&x=1`（其余 query 残留） | FAIL | FAIL | **两侧一致失败**（G2G/R2R 同样失败）→ 口径一致，非 Rust 缺陷 |
| ws-multi4 | PASS | PASS | 4 子流 |
| **httpupgrade** | PASS | PASS | 请求/响应头集合逐项相同 |
| **gRPC（h2c）** | PASS | PASS | h2 preface / SETTINGS / HEADERS / 5 字节 gRPC 帧 `00+len32` 一致；窗口见 §2.3 |
| **splithttp** packet-up | PASS | PASS | POST body 重组字节一致；`/path/{sid}/{seq}` 序号方案一致 |
| **splithttp** stream-up | PASS | PASS | `Transfer-Encoding: chunked` 上行；chunk 边界不同但重组字节一致 |
| **splithttp** stream-one | PASS | PASS | `POST /xh/`（无 sid）；重组字节一致 |
| **splithttp** auto | PASS | PASS | 落 packet-up 语义，双侧一致 |
| **mux** concurrency=8 | PASS | PASS | carrier 数 =1；mux 帧 `len u16 + sid/status/option/network/port/atyp/addr` 一致 |
| **mux** + xudp 参数 | PASS | PASS | 同上 |
| **mux** multi4（4 子流） | PASS | PASS | 两侧均 1 carrier 承载 4 子流 |
| **mux** concurrency=1（2 会话） | PASS | PASS | 两侧均 2 carrier（1 会话 1 carrier） |
| **QUIC**（network:"quic"） | 未测 | 未测 | **Go 26.10.17 已移除 quic 传输**（`D:/Project/Xray-core/transport/internet/` 无 `quic/`），无对照物 |
| **hysteria** | 未测 | 未测 | Go 有 `transport/internet/hysteria/`，但全程 QUIC 加密、本轮无法明文比对；且优先级低于上述七项 |

合计：R2G 19/20、G2R 19/20（唯一失败项是两侧一致失败的同一用例）。**跨实现数据完整性 36/36 全 PASS。**

同实现对照（R2R）补测：`ws-ed-path` 4/4、`mux` 全 5 例 PASS（即 Rust 的 `cmd=1 + v1.mux.cool` carrier 也被 Rust 自己的入站接受）；`xh-stream-one` 在 R2R 下同样出现 1 条零字节连接 → 证实 §2.1 是**客户端侧**行为，与服务端实现无关。

---

## 2 差异表（按用户可见后果排序）

| # | 场景 | 类型 | Go 行为 | Rust 行为 | 位置 file:line | 用户可见后果 | 严重度 | 建议 |
|---|---|---|---|---|---|---|---|---|
| 1 | splithttp **stream-one**，单会话 | 缺陷（连接面） | 1 条 TCP 承载双向上行下行 | **2 条 TCP**：1 条承载数据，另 1 条 connect 后零字节即 EOF（3/3 复现） | `crates/xray-transport-splithttp/src/client.rs`（stream-one 拨号路径） | 每会话连接数翻倍；CDN/服务端每 IP 连接数限额、连接数计费、TLS 面多一次握手 RTT 都会中招；对端 access log 出现无流量连接 | 建议 | 定位 stream-one 的二次拨号来源（疑似 hyper 连接池预连接/重试路径），复用同一条连接或延后拨号 |
| 2 | **ws 出站**，任意单会话（未写任何池参数） | 缺陷（静默默认行为） | Go `WebSocketConfig` **无池概念**（无 poolSize 字段），每会话现拨 1 条 | 默认 `poolSize=12` 开启全局预连接池 + 首波 `BURST_REPLENISH_FANOUT=3`；实测单会话期间后台多出 **0~3 条只握手不传数据的连接**（各 `581~582B` 上行 / `129B` 下行） | `crates/xray-transport-websocket/src/config.rs:60`（`pool_size: 12`）、`register.rs:353,384`、`pool.rs:130` | 服务端看到 4~13 条连接而非 1 条；空闲 10s 后丢弃再补拨 → 持续静默握手流量；对端连接数限额/CDN 并发计数会被放大 | 建议 | 待 PM 拍板：是否把默认改为 `0`（与 Go 同口径），或至少把「默认开池」写进配置文档并在装配期打一条 info。**注**：`il9lh` 记的是「ws 池内存」口径；本条是「默认开池 → 对端可见连接数」口径，勿重复计量 |
| 3 | **gRPC**，任一会话 | 口径差异（刻意性能修复） | 客户端 `SETTINGS_INITIAL_WINDOW_SIZE=98340`、连接窗 `WINDOW_UPDATE=+65535` 级别分多次；服务端 `131070` | 客户端 `INITIAL_WINDOW_SIZE=16777216`、连接窗一次 `+33488897`（≈32MB）；服务端同样 `16777216` | 客户端/服务端 h2 栈配置（`crates/xray-transport-grpc`） | Rust 作为接收方时**允许对端每流一次发 16MB**：峰值内存 ≈ 16MB × 并发流，需要在内存预算里显式计入；与 Go 对拍时窗口行为不同 | 建议 | 保留（同源 bd `enc8x` 的 h2 窗钉是为解 8.8Mbps 线程瓶颈），但把「16MB/流」写进内存预算与压测基线；建议给 `grpcSettings` 暴露窗口旋钮 |
| 4 | **mux carrier 的 VLESS 请求头** | 口径差异（互通仍通过） | `cmd=3 (Mux)`，**不写地址/端口** → 19 字节头，随后直接是 mux 帧（`000c` + 12 字节 metadata） | `cmd=1 (TCP)` + `atyp=2 addr="v1.mux.cool" port=9527` → 34 字节头，随后同一套 mux 帧 | 出站 command 决策：`crates/xray-proxy-vless/src/dispatcher.rs:495`；入站 cmd=3：`crates/xray-proxy-vless/src/inbound/server.rs:574,733` | 双向互通实测通过（Go 服务端按域名判、Rust 服务端按 cmd=3 判都认）。风险在**第三方严格 VLESS 服务端**：Rust 的 carrier 依赖 `v1.mux.cool` 域名启发式才被识别为 mux；若对端只认 cmd=3，Rust 的 carrier 会被当普通 TCP 拨 `v1.mux.cool` | 口径差异 | 不改（两度证伪的改动面）。建议在协议契约文本里记一句「carrier 命令字两侧不同但互认」，避免下一轮再当缺陷报 |
| 5 | `wsSettings.ed = N` | 配置面差异（Rust 独有键） | 该键**不存在**：`WebSocketConfig` 只有 host/path/headers/acceptProxyProtocol/heartbeatPeriod，早期数据只从 `path` 的 `?ed=` 提取（`infra/conf/transport_method.go:618-629`） | 同时支持 `wsSettings.ed` 与 `path` 的 `?ed=`，且 **path 的 `?ed=` 覆盖 `wsSettings.ed`**（`register.rs:641` 读 `ed`，`register.rs:654-657` 用路径值覆写）；实测 `ed=2048` 时 Rust 发 `Sec-WebSocket-Protocol: <base64(26B)>`，Go 完全忽略该键 | `crates/xray-transport-websocket/src/register.rs:641` | 同一份配置在 Go 侧是空操作、在 Rust 侧改变 wire：VLESS 头 26 字节（version+UUID+cmd+目标地址）进**明文 HTTP 头**，且 ws 子协议指纹与 Go 不一致 | 建议 | 要么删掉 `wsSettings.ed`（只留 Go 的 `?ed=`），要么在装配期打 warn：「此键 Go 不支持，跨实现不可移植」 |
| 6 | ws 早期数据**触发条件** | 口径差异 | ED 只在「首次写入 ≤ ed」时生效，而 Go 首次写入含 VLESS 头 + 首个数据缓冲（本例 ≈8KB）→ `ed=2048` 时**不发** | Rust 首次写入仅 26 字节 → `ed=2048` 时**发**（`ed=65536` 两者都发，但 Go 的 ED 携带 ~8KB、Rust 只携带 26B） | 同上 | 0-RTT 收益与 ws 指纹面两侧不同；**不影响正确性**（四个组合双向实测通过） | 口径差异 | 不改；若要严格对齐，可让 Rust 的首个写缓冲与 Go 同粒度（属性能面，非正确性） |
| 7 | splithttp 上行 **POST 尺寸** | 口径差异 | 按写缓冲切：本例 8218 / 57344 / 24576 / 40960，多连接并行 POST | 每 POST ≤64KB：本例 65562 / 65536，单连接顺序 POST | `crates/xray-transport-splithttp`（`scMaxEachPostBytes` 消费点） | 无功能后果：服务端按 `/{sid}/{seq}` 重组，实测重组字节完全一致。差异只在「对 CDN 的请求体大小/并发形态」 | 吹毛 | 不改 |
| 8 | `kcpSettings.seed` / `header` | 配置死键（**两侧一致**） | Go 26.10.17 `transport/internet/kcp/config.proto` 只有 mtu/tti/uplink/downlink/cwndMultiplier/maxSendingWindow，**无 seed、无 header** | Rust 同样未实现（抓包实证见 §3.1：两侧都是明文 KCP 段） | — | 配置里写 seed/header 两侧都被静默忽略；用户以为「加了混淆」其实没有 | 口径一致 | 非 Rust 缺陷。建议在配置文档标注这两键在 26.10.x 已失效（属文档面） |

---

## 3 字节级证据

### 3.1 KCP：段头与载荷逐字节

`analyze.py kcp` 对四份抓包（R2G/G2R × up/down）解析：

```
packets=117  segments=117  data=113  ack=4  other=0
convs=[42272]  opt_vals=[0]  cmds=[0,1]  leftover_bytes=0
payload_total=131098  uniq_sn=113  sn_range=0..112
first_data: conv=42272 cmd=1 opt=0 ts=0 sn=0 una=0 len=26
first_ack : conv=42272 cmd=0 opt=0 win=1585 una=32 ts=20 cnt=32 nums=[0,1,2,3,4,5]
```

- 四个方向 `leftover_bytes=0` —— **没有任何尾随/未知字节**，段边界干净。
- data 段最大载荷 1332 = mtu 1350 − 18，两侧同值。
- ack 段 `count` 上限 57（Go `ackNumberLimit=128` 语义未触顶），字段序一致。
- cmd 集合只有 `{0 ACK, 1 DATA}`（一次抓包出现 `3 PING`），**未见 `2 TERMINATE`** —— 收尾靠连接关闭而非 terminate 段，两侧一致。

重组后逐字节比对（Rust 客户端 vs Go 客户端，上行）：

```
a(Rust) len=131098  b(Go) len=131098
a[:48]=00b831381d63244d53ad4f8cda48b308110001 18 82 01 7f000001 31b3f391166a426e…
b[:48]=00b831381d63244d53ad4f8cda48b308110001 25 9a 01 7f000001 31b3f391166a426e…
first_diff_off=19 identical_prefix=19
```

第 19–20 字节 = VLESS 的目标端口（每轮 echo 端口不同）→ **除此之外上行字节流完全相同**。下行（服务端 → 客户端）131074 字节 **完全一致**（`first_diff_off=-1`）。

`seed` 用例抓包首包 `c2ab01000000…` / `eef30100000000…` 均能按明文 KCP 段解析（conv/cmd/len 合法、leftover=0）→ 两侧都没有加密，与 §2.8「seed 已是死键」互相印证。

### 3.2 splithttp：POST body 重组逐字节

把各 mode 的 POST body 按 seq 排序拼接后比对：

```
R2G-xh-packet-up: posts=2 total=131098 head=00b831381d63244d53ad4f8cda48b30811000118 8c 017f000001…
G2R-xh-packet-up: posts=4 total=131098 head=00b831381d63244d53ad4f8cda48b30811000125 9a 017f000001…
DIFF: len 131098/131098  first_diff=19  prefix_identical=19
...（stream-one / stream-up 同结论）
```

长度精确相等（26 字节 VLESS 头 + 2×65536 载荷 = 131098），唯一差异仍是目标端口两字节。**三种 mode 的 body 语义完全一致。**

下行（服务端 → 客户端）两侧都是 SSE 风格：`Content-Type: text/event-stream` + `X-Accel-Buffering: no` + `X-Padding`（默认 100–1000 随机，两侧范围相同），body 用 `Transfer-Encoding: chunked` 分块，首块 2 字节 = VLESS 响应头 `0000`。

### 3.3 WS / HTTPUpgrade：握手与帧

```
Go   客户端 GET /ws HTTP/1.1  Host/User-Agent/Accept/…/Sec-WebSocket-Key/Version/Upgrade   （17 个标准头）
Rust 客户端 GET /ws HTTP/1.1  Host/Connection/Upgrade/Sec-WebSocket-Version/Key + Chrome 伪装头组（sec-ch-ua 等）
```
- 两侧 `Sec-WebSocket-Key` 均 16 字节 base64、`Version: 13`、`Upgrade: websocket`、101 响应 `Sec-WebSocket-Accept` 计算正确。
- 帧：客户端恒 masked、服务端恒 unmasked，opcode 只用 `0x2 (binary)` + `0x8 (close)`；Rust 单帧上限 8192，Go 4096/8192 —— 帧边界不同但流字节一致。
- httpupgrade 两侧请求头集合**逐项相同**、响应同为 `HTTP/1.1 101` + `connection/upgrade`。

### 3.4 gRPC（h2c）

```
R2G(Rust 客户端) c2s: SETTINGS[4=16777216], WINDOW_UPDATE +33488897, PING×4, HEADERS×1, DATA×14
G2R(Go 客户端)   c2s: SETTINGS[4=98340],     WINDOW_UPDATE 多次小额,   PING×6, HEADERS×1, DATA×17
G2R(Rust 服务端) s2c: SETTINGS[4=16777216],  WINDOW_UPDATE +33488897
R2G(Go 服务端)   s2c: SETTINGS[5=16384, 4=131070], WINDOW_UPDATE×12
```
- h2 preface `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` 两侧一致；HEADERS 均 HPACK 编码（不可直读，但 path 能被对端接受即证明 `/{serviceName}/Tun` 一致）。
- DATA 均带 gRPC 5 字节前缀 `[compressed=0][len:u32be]`；Rust 消息 32KB 拆 2×16KB DATA，Go 消息 8KB 一帧 → 重组后一致。
- 两侧都只发 1 个 HEADERS、无 trailing HEADERS（不依赖 gRPC trailers）→ 语义一致。
- **窗口差见 §2.3**。

### 3.5 mux

carrier 头（Rust）：`ver=0 cmd=1(TCP) port=9527 atyp=2 addr="v1.mux.cool"` → 34 字节，随后
`00 0c | 00 01 01 01 01 18 d0 | 01 7f 00 00 01`
= `[frame_len=12][sid=1][status=1 New][option=1 data][network=1 TCP][port=0x18d0][atyp=1 IPv4][127.0.0.1]`

carrier 头（Go）：`ver=0 cmd=3(Mux)` → 19 字节（无地址/端口），随后
`00 0c | 00 01 01 01 01 26 2c | 01 7f 00 00 01`
= **完全相同的 mux 帧布局**（仅内部端口不同，因为 echo 端口每轮不同）。

并发语义完全对齐：`concurrency=8` → 1 carrier；4 并发会话 → 仍 1 carrier；`concurrency=1` + 2 会话 → 2 carrier（两方向一致）。

---

## 4 可以放心上生产吗

**可以上生产（跨实现数据面已验证）**：tcp、kcp、ws、httpupgrade、splithttp（4 模式）、grpc、mux — 全部 64KB 双向 + 多子流字节级通过，无一条「连上但数据错/丢」。

**上生产前建议先处理的三条**（都不阻断正确性，但会影响生产观感与容量）：

1. **§2.1 splithttp stream-one 每会话多 1 条零字节 TCP** —— 这是唯一“纯浪费”的项，且每会话必现。CDN 场景（连接数限额/计费）下会被看见。
2. **§2.2 ws 默认开池（Go 没有）** —— 需要 PM 决定「与 Go 同口径（默认 0）」还是「保留但记录」。它在服务端侧是可观测行为差异。
3. **§2.3 grpc 16MB/流窗口** —— 不是缺陷（同源性能修复），但必须计入内存预算；若有一批高并发 grpc 会话，16MB × 并发流是真实上限。

**不建议依赖的能力**：`wsSettings.ed`（§2.5，Rust 独有键，跨实现不可移植）、`kcpSettings.seed`/`header`（§2.8，现代 Go 已是死键，两侧都静默忽略）。

---

## 5 未覆盖范围（明确声明）

- **QUIC 传输**：Go 26.10.17 已无 `quic` 传输，无对照物 → 未测。
- **hysteria / hysteria2 传输**：Go 有实现，但全程 QUIC 加密，本轮无解密手段（未接 SSLKEYLOGFILE/qlog），未做字节比对。
- **TLS / REALITY / XTLS-Vision 面**：本轮全部用例 `security:"none"` 以取明文；TLS 记录层、ALPN、指纹属 32/32 与既有审计覆盖范围，本轮未重测。
- **mux 的 XUDP（`xudpConcurrency`/UDP 子流）**：属已登记票 `t0ls1`，按派单要求不重报、未重测。
- **h2/h3 承载的 splithttp**（`alpn:["h2"]`/`["h3"]`）：本轮只测 h1 明文；h2 承载的 xhttp 需 TLS，未测。
- **xhttp `downloadSettings`**：配置解析被丢弃的问题已登记（`x273` 行 settings-ledger → bd `x0f0r` 族），本轮不重复。

---

## 6 复现

```
python reports/audit-2026-10-31-perf-mem-wiring/round5/scripts/matrix.py only-R2G   # Rust 客户端 → Go 服务端
python reports/audit-2026-10-31-perf-mem-wiring/round5/scripts/matrix.py only-G2R   # Go 客户端 → Rust 服务端
python reports/audit-2026-10-31-perf-mem-wiring/round5/scripts/matrix.py only-R2R / only-G2G   # 同实现对照

# 抓包结构解析（脚本 analyze.py）
python analyze.py kcp  D:/tmp/wire-r5/R2G-kcp.up.bin D:/tmp/wire-r5/R2G-kcp.down.bin
python analyze.py kcpdiff D:/tmp/wire-r5/R2G-kcp.up.bin D:/tmp/wire-r5/G2R-kcp.up.bin
python analyze.py ws   D:/tmp/wire-r5/R2G-ws.conn0.c2s.bin …s2c.bin
python analyze.py h2   D:/tmp/wire-r5/R2G-grpc.conn0.c2s.bin …s2c.bin
python analyze.py http D:/tmp/wire-r5/R2G-xh-stream-one.conn3.c2s.bin …
```
落盘位置：`D:/tmp/wire-r5/`（配置、进程日志、逐连接 `connN.c2s/s2c.bin`、UDP 每包 `up/down.bin`）。

---

## 附：本轮顺带确认的两个“不是缺陷”

- **G2R 侧 KCP 出现 42 次重传而 R2G 为 0**：同一轮内的偶发（UDP 中继在单线程 `recvfrom` 下会丢包，真机同样会重传），重传后重组字节仍完全一致；不按缺陷计。
- **`ws?ed=N&x=1` 双侧一致失败**：剥掉 `ed` 后 path 变成 `/ws?x=1`，两侧服务端都不认（G2G/R2R 同样失败）→ 是 Go 的 path 匹配口径，Rust 与之**一致**，非差异。
