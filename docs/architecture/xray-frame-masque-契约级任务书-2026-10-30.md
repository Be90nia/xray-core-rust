# xray-frame · MASQUE 契约级任务书（bd `Xray-core-rust-55yh7`，2026-10-30）

> **状态**：架构方案 + ADR 草案（architect 产出）。**M1 需主代理拍板后才派单**；本文件不含任何实现代码，签名/伪代码仅作契约。
> **裁定基准**：Go `D:/Project/Xray-core` @ `92ccc939` = tag **v26.10.17**（一手材料只读）。
> **规范源**：`docs/architecture/xray-frame-强约束插件模型-2026-10-23.md`（L1–L5 + 坑约束 12 条）；`CLAUDE.md` §3.5（三层定位 / §3.5.2 禁重复造轮子 / §3.5.5 归属判定）；`docs/architecture/xray-frame-PM排期-2026-10-30.md` §1 W5 行。
> **一句话结论**：**做，但只做分层里的"薄协议层 + 复用 hyper H2 栈"**——先做 transport 层（M1，可独立验收），proxy 层（M2，需先落 IP 栈桥框架件）次之，H3/WARP 变体（M3）最后；总计 **30–45 人日**。

---

## 0. 边界与既有资产（开工前必须核对的 5 条现状）

| # | 现状（file:line） | 对本任务的含义 |
|---|---|---|
| 0.1 | 枚举已在：`crates/xray-common/src/net/transport.rs:54-55`（`TransportProtocol::Masque`，注释「Rust 未实现，配置层显式拒绝」）、`:76`（`"masque"`）、`:100`（`"masque" → Some(Masque)`） | 名字已冻结，**不新增枚举**；只需解除拒绝 + 接线 |
| 0.2 | 配置层硬拒：`crates/xray-conf/src/init.rs:340-352`（`masqueSettings`/`xdriveSettings`/`address`/`port` 四键出现即 `LintError`；`network=masque|xdrive` 同样硬错）；测试锚 `init.rs:826-856` | M2 起要**只放开 masque 两条**（保留 xdrive 拒绝），并改该测试 |
| 0.3 | proto 已生成：`crates/xray-proto/src/lib.rs:176-178`（`xray.proxy.masque`）、`:306-308`（`xray.transport.internet.masque`，含 `Config{host,path,headers,warp,xmux}` 与 `Warp{private_key,public_key,address}`） | **无需新增 proto**；`Config` 字段与 Go `transport/internet/masque/config.proto:15-27` 逐字段一致 |
| 0.4 | transport 侧已留位：`crates/xray-transport/src/dialer.rs:555`（`Masque => "masqueSettings"`）；`listener_registry.rs:51-62`（`TransportListenFn`）、`:80`（注册）、`:118`（`listen_tcp` 入口） | 接线点已存在，无框架改造 |
| 0.5 | H2 栈现状：splithttp 客户端用 **hyper** `http2::Builder`（`crates/xray-transport-splithttp/src/dialer.rs:657`），服务端用 **hyper-util auto**（`hub.rs:224-241`）；workspace 依赖 `hyper = "1"` / `h2 = "0.4"` / `hyper-util = "0.1"`（根 `Cargo.toml:135-142`） | 见 §2.3 复用结论 |

---

## 1. Go 语义摘要（逐条带 file:line）

### 1.1 MASQUE 是什么（在 Xray 里）

MASQUE = **一个 IP 隧道传输**（不是 CONNECT-UDP 的"每 UDP 会话一条流"）：客户端与服务器建立一条 HTTP `CONNECT` 流，流的载荷是**胶囊（capsule）序列**，里面装的是**完整 IP 包**。承载流量 = 该隧道内所有 IP 协议的流量（TCP/UDP/ICMP 都在里面），由两端的用户态 IP 栈各自处理。

- 传输层（`transport/internet/masque`）：只负责「HTTP 隧道 + 胶囊读写 + 地址分配」，对上层暴露 `stat.Connection`（`dialer.go:35`），读 = 取 IP 包，写 = 送 IP 包。
- 代理层（`proxy/masque`）：客户端把隧道当网卡（`wireguard.CreateNetTUN`，`client.go:330`），出站目标在**隧道内的虚拟栈**上 Dial（`client.go:139-180`）；服务端把隧道当网卡（`server.go:186`，同样 `wireguard.CreateNetTUN`），包进栈 → 栈上 TCP/UDP 流交给 dispatcher（`server.go:503-553`）。

> **关键事实（消除"UDP 会话→stream 映射"这条误设）**：Go 实现里**没有** UDP-session-per-stream。多路复用发生在 **IP 层**：一条 CONNECT-IP 流承载全部 5 元组；UDP "会话"只是虚拟栈上一个 socket（客户端侧 `t.tnet.Dial("udp", ...)`，`client.go:160-176`；服务端侧 smoltcp/UDP forwarder，见 `server.go:413-446` → `HandleConnection`）。

### 1.2 HTTP/2 CONNECT-IP 用法（RFC 9298 家族，实现即 RFC 9484 connect-ip）

| 环节 | Go 实现 | 证据 |
|---|---|---|
| 请求方法 | `CONNECT`，`:protocol: connect-ip`，绝对 URL `https://<authority><path>`，附加 `Capsule-Protocol: ?1` | `connectip/request.go:20,22,28-42` |
| 默认路径 | `/.well-known/masque/ip/*/*/`（**字面 `*` 也要原样发**；percent-encode `%2A` 亦接受） | `config.go:12`；匹配规则与反例见 `hub.go:307-312` + `hub_test.go:42-46` |
| 服务端 SETTINGS | `ENABLE_CONNECT_PROTOCOL=1`（RFC 8441）+ `MAX_CONCURRENT_STREAMS=100` + `MAX_HEADER_LIST_SIZE`；握手超时 **10s** | `http2_server.go:27-29,127-128`；握手超时用点 `hub.go:205-208` |
| 响应 | `200` + `Capsule-Protocol: ?1`；此后该 stream 全双工承载胶囊 | `connectip/proxy.go:22-36` |
| 拒绝语义 | 非 CONNECT → `405`；`:protocol≠connect-ip` → `501`；缺 `Capsule-Protocol` → `400`；认证失败 → `401 + WWW-Authenticate: Basic realm="masque"`；无地址可分配 → `503` | `request.go:61-96`；`hub_test.go:110-120`；`server.go:35-38,271-282,293-296` |
| 认证 | HTTP Basic（用户名 = user email，密码 = `Account.Password`），常数时间比较 | `server.go:271-282`；`account.go`（`subtle`） |
| UA | 缺省 `User-Agent: chrome`（可被配置 headers 覆盖；`"golang"` = 删除 UA） | `dialer.go:323-337` |

### 1.3 胶囊编码（h2 与 h3 共用的唯一协议内核）

| 胶囊 | 类型值 | 载荷 | 证据 |
|---|---|---|---|
| DATAGRAM | **0** | `QUIC-varint(0)`（contextID 恒 0）+ 一个完整 IP 包 | `capsule.go:22`；`conn.go:673-677`（h2 分支） |
| ADDRESS_ASSIGN | 1 | 重复 `{varint requestID, varint prefixLen, addr…}` | `capsule.go:40-63` |
| ADDRESS_REQUEST | 2 | 同上（服务端 `serveAddressRequests` 应答） | `capsule.go:92-96`；`server.go:359-390` |
| ROUTE_ADVERTISEMENT | 3 | 重复 `{ipVersion, startIP, endIP, ipProto}`，须按序且不重叠 | `capsule.go:191-224,244-250` |
| 上限 | 单胶囊 payload ≤ `1<<16-1`；单胶囊内条目 ≤ 8192；`maxQueuedCapsules/Datagrams = 128` | `conn.go:62-63`；`capsule.go:27-30` |
| 帧格式 | `varint(type) varint(length) payload`（RFC 9297）；未知类型跳过 | `conn.go:410-420`；`conn_test.go:385` |

写入侧还有两处**必须翻译**的语义：
1. IPv4 头校验和重算（发送前）、IPv6 头不做。
2. **MTU 与 ICMP**：包超 MTU 时**不丢**，`WritePacket` 返回一个 ICMP「packet too big」包由上层回灌隧道（`conn.go:592-…`、`server.go:484-490`、`client.go:367-371`）；上限默认 `maxCapsulePacketSize = 65535`（h2）/ QUIC datagram 探测（h3，`conn.go:695-700`），隧道最小可用 `MinPacketSize = 1280`（`dialer.go:31`，客户端校验 `dialer.go:233-236`）。

### 1.4 地址分配与 `pool.go` 的作用

- 服务端按配置 `address[]`（每族仅一个前缀，`server.go:145-175`、`infra/conf/masque.go` 校验 v4/v6 各一 + `mtu∈[1280,65535]`）建 `addressPool`（`pool.go:10-45`）：剔除网络地址/广播地址/服务器自身地址，环形游标 `next` 分配，`used` 集合去重，`release` 归还（`pool.go:47-80`）。
- 每条隧道分配每族一个地址（`server.go:286-292`），然后 `AssignAddresses` + `AdvertiseRoute`（全 0.0.0.0/0、::/0，`server.go:313-325` + `fullRoutes` `server.go:343-356`），再起 `serveAddressRequests` 响应客户端显式请求（`server.go:359-390`）。（`server.go:185-189` 用同一份 `local` 建虚拟网卡。）
- 客户端反之：`RequestAddresses(0.0.0.0/32, ::/128)` → 等 `ADDRESS_ASSIGN`（`dialer.go:277-296`），取每族第一个地址进本地 TUN（`dialer.go:295-307`）。

### 1.5 包路由（服务端）

`readFromTunnel`（`server.go:413-446`）：读隧道 IP 包 → 解析目的地址（`packetDestination`，`server.go:497-510`）→ ① 目的地址属于**另一条隧道** → 转发到那条隧道的发送队列（隧道间转发）② 属于地址池但非本机 → 丢弃 ③ 否则喂给本机虚拟栈。`readFromStack`（`server.go:447-468`）做反向：栈发出的包按目的地址找回隧道并投递。两者之间是 `tunnelQueueSize = 512` 的有界队列（`server.go:20`）。

### 1.6 超时 / 心跳 / 拥塞

| 项 | Go 值 | 证据 |
|---|---|---|
| TLS/H2 握手 | 10s（server 侧） | `http2_server.go:28`；`hub.go:205-208` |
| 隧道建立 | 10s（client） | `client.go:33-36`（`establishTimeout=10s` / `retryInterval=1s`） |
| H2 keep-alive（PING） | `Xmux.HKeepAlivePeriod`，缺省用 `net.ChromeH2KeepAlivePeriod` | `config.go:14-19`；`dialer.go:191-195` |
| 会话空闲 | 走 Xray policy `ConnectionIdle`（`signal.CancelAfterInactivity`） | `client.go:105-192`（Process 内的握手/空闲计时接线） |
| 拥塞（仅 H3） | `quicParams.Congestion ∈ {"",reno,bbr,brutal,force-brutal}` + BBR/Brutal 桥 | `hub.go:97-103,122-140`；`dialer.go:130-145` |
| 流控 | 自实现 H2 流控（`awaitSendWindow`/`applySettings`）——**这条我们改用 hyper 自带** | `http2.go:...(awaitSendWindow)` |

### 1.7 规模账（**修正 PM 排期里的「Go ≈1670 行」**）

| 区 | 文件 | 行 |
|---|---|---|
| proxy/masque（不含测试/pb） | server.go 554 · client.go 397 · pool.go 80 · account.go 108 | **1139** |
| transport/internet/masque | dialer.go 347 · hub.go 422 · conn.go 129 · config.go 27 · warp.go 78 · **http2.go 614 · http2_server.go 680** | **2297**（其中 **1294 = 手写 H2 客户端+服务端**） |
| connectip（协议内核） | conn.go 721 · capsule.go 308 · http2.go 218 · client.go 115 · request.go 101 · icmp.go 94 · address.go 86 · iprange.go 73 · proxy.go 43 · checksum.go 23 | **1782** |
| 合计 | | **≈ 5218** |

**必须移植 ≈ 3924 行**（5218 − 1294 手写 H2；`warp.go 78` 延到 M3）。手写 H2 那 1294 行是 Go 因为 x/net/http2 不带 CONNECT-IP 语义才自己写的——**我们不复刻**（§2.3）。

---

## 2. 分层拆分 + 落点

### 2.1 层与内容（与 Go 同构，禁止改形）

| 层 | crate（新/改） | 内容 | 明确不做 |
|---|---|---|---|
| **协议线** | `xray-transport-masque`（新） | 胶囊编解码、CONNECT-IP 会话状态机、H2/H3 绑定、TLS/ALPN 拨号与服务端 accept、地址池 | 不碰 netstack、不碰 dispatcher、不碰配置 JSON |
| **代理层** | `xray-proxy-masque`（新） | 客户端：隧道池 + netstack + 目标 Dial；服务端：隧道表 + 包路由 + dispatcher 桥 + 认证 | 不复刻 Go 的 h2/warp 手写栈 |
| **接线** | `xray-core`（arm_builders 两处）+ `xray-conf`（lint 放开 + `masqueSettings` 解析） | 构造表加 `inbound:masque` / `outbound:masque`；解析 `settings.users/address/mtu` 与 `masqueSettings.host/path/headers/xmux` | 配置语义解析不得散落到 transport crate |
| **框架层** | `xray-frame`（**新增一件**，见 §2.4） | IP 包 ↔ TCP/UDP 事件 ↔ dispatcher 的桥（第三个消费者） | 不放 xray 无关的净室 smoltcp 细节到 udf（§3.5.3 方向件纪律） |
| **udf-frame** | 不动 | 胶囊/RFC 编解码属"协议方向件"，按 §3.5.3 不进 udf | — |

### 2.2 服务端 / 客户端各自的角色矩阵

| | transport 层 | proxy 层 |
|---|---|---|
| **出站（client）** | `Dial`：TCP+TLS(ALPN h2) → `CONNECT-IP` → 拿到 `ConnectIpSession`（读/写 IP 包） | 隧道池（xmux 语义）→ 隧道内 netstack → 目标 `Dial(tcp|udp)` → 双向 copy |
| **入站（server）** | `Listen`：TCP accept → TLS → hyper h2（`ENABLE_CONNECT_PROTOCOL`）→ `ServeHTTP` 建 `ServerConn` → 交给 conn handler | 认证 → 分配地址 → `Accept` 得会话 → 包路由（隧道间 + 本机栈） |

### 2.3 【关键结论】transport 能否复用现有 splithttp 的 H2 栈？

**结论：复用「hyper/h2 帧层」，不复用「splithttp 的请求模式与模块」。新 crate 自成一层，依赖集与 splithttp 相同。**

**判据（全部为 v26.10.17 现状实测/读码，不是推测）**：

1. **extended CONNECT 在我们这代 hyper 上是可用的**——这是本方案成立的前提，逐点核过：
   - 服务端：`hyper::server::conn::http2::Builder::enable_connect_protocol()`（`hyper-1.12.0/src/server/conn/http2.rs:258`）；hyper-util auto 透传 `Builder::http2().enable_connect_protocol()`（`hyper-util-0.1.21/src/server/conn/auto/mod.rs:1068`）。
   - 客户端：`hyper::ext::Protocol`（`hyper-1.12.0/src/ext/mod.rs:76-83`）插入 request extensions 即发 `:protocol`（`proto/h2/client.rs:731-733`）；CONNECT 请求体必须为空、响应成功后走 upgrade 拿全双工 IO（`client.rs:716-735` + `server.rs:275-296`，服务端在 `server.rs:488-511` 把 `connect_parts.recv_stream` 与响应流配成 `Upgraded`）。
   - 底层 h2 crate 也支持（`h2-0.4.19/src/server.rs:1043,500`、`ext.rs:8-13`、`proto/streams/streams.rs:271`），是 hyper 之上的兜底路径。
2. **splithttp 的模块不可直接复用**（不是"不想用"，是类型与语义都不对口）：
   - 它的传输语义是「多请求拼一条流」（packet-up / stream-up / stream-one，`crates/xray-transport-splithttp/src/hub.rs:1-33`），而 MASQUE 是**单 CONNECT 流 + 胶囊**；`ServerConn`/`UploadQueue` 的生命周期与帧格式零交集。
   - 它的连接外壳类型是 crate 私有（`SplitStream`/`DestTcpStream`，`dialer.rs:136-236`），跨 crate 复用必须依赖 `xray-transport-splithttp`（同级 transport 互依赖＝分层污染）。
   - 它**从未启用过** `enable_connect_protocol`（全仓 0 命中），所以"能编译"不等于"这条路被跑过"——这正是 M1 spike 要验的（§8 未知点 1）。
3. **能复用的是依赖与参数**（照抄配置，不照抄代码）：
   - TLS 拨号带指纹：走 `xray-tls`（`btls_client::connect_with_alpn`，`crates/xray-tls/src/btls_client.rs:1224,1255`；rustls 路径 `utls::client`，`utls.rs:495`），与 Go `dialer.go:173-185` 的 `tls.UClient`/`tls.Client` 分支 + ALPN=h2 硬校验对应。
   - H2 流控窗口按 RTT 阶梯：`crates/xray-transport-splithttp/src/flow_window.rs`（被 `dialer.rs:659`、`transport.rs:543` 消费）——MASQUE 单流载全部流量，窗口更敏感，**M1 就以 16MB 连接窗/16MB 流窗起步**（仓库既有 h2 窗钉战役结论，见 CLAUDE.md §5「h2 窗钉（enc8x）」）。
   - 隧道池语义：`crates/xray-transport-splithttp/src/mux.rs`（`XmuxManager`/`XmuxClient<C: XmuxConn>`）**是泛型的、与 splithttp 协议无关**，可直接作为 masque 隧道池（对应 Go `client.go:57-102,195-226` 复用 `splithttp.XmuxManager`）。这是唯一真正跨协议复用的现成件。

> **为什么这一节是本方案的"最大一笔赌注"**：如果选"新建第二套 H2 栈"（照 Go 逐行复刻 `http2.go` + `http2_server.go`），代价 = +1294 行 + 自管流控/优先级/GOAWAY，且与 splithttp/hysteria 三处并存 —— 直接违反 §3.5.2。选错损失 ≈ 一个 M2 的人力且留下长期双栈债。

### 2.4 IP 栈桥：为什么必须落 `xray-frame`（框架件），不能塞进 masque crate

- 现状是**已经有两份**同类实现：`crates/xray-proxy-tun/src/netstack.rs`（1284 行 smoltcp 栈）+ `crates/xray-proxy-tun/src/inbound.rs`（2733 行桥）；`crates/xray-proxy-wireguard/src/netstack.rs`（1056 行）+ `inbound.rs`（1499 行桥）。且 `crates/xray-proxy-wireguard/src/inbound.rs:596` 已写明「**第三个消费者已出现——后续提取共享 trait**」。
- MASQUE 若再写一份，就是第三个副本 —— 命中「新功能一律长在框架上」的禁止项（机制留在单个自用 crate，别的协议再来抄）。
- 归属判定（§3.5.5 三判据）：桥里带有 `dispatcher` 语义（Xray 语义）→ **不得进 udf**；零 xray 语义部分（smoltcp 封装）是**网络方向件**（§3.5.3）→ 也不进 udf → **归 xray-frame（派生层）**。
- **形态建议（M2 前置条件，需 PM 授权）**：`xray-frame/src/ipstack/` 提供 `PacketStack`（`ingest_rx / drain_tx / poll / drain_accepted / drain_udp / udp_send_reply`）+ `PacketBridge`（socket ↔ `DispatchHandler`）。首次落地用**移动**（把 wireguard 的 `netstack.rs` 语义键搬进框架，wireguard 侧改为 `pub use` 保持内部路径不变）——见 §7 风险 R6（`WG-TUN-FROZEN` 红线，**这是需要主代理裁的决策，不是本文件能定的**）。

---

## 3. 产出文件清单

### 3.1 M1（transport 层，客户端方向，可独立验收）

| 文件 | 类型 | 内容 |
|---|---|---|
| `Cargo.toml`（根） | 改 | workspace `members` 加 `crates/xray-transport-masque` |
| `crates/xray-transport-masque/Cargo.toml` | 新 | 依赖：`hyper`(http2,client) / `hyper-util`(tokio,rt) / `http` / `http-body-util` / `tokio` / `bytes` / `h3`(varint) / `xray-buf` / `xray-common` / `xray-transport` / `xray-tls` / `xray-proto` / `xray-frame`；`clippy.toml` 同 splithttp 纪律 |
| `.../src/lib.rs` | 新 | 模块挂载 + `LOG`/`HOT_LOG` 面（target `xray_frame::transport::masque`，抄 `xray-transport-splithttp/src/lib.rs:56-67` 形态） |
| `.../src/config.rs` | 新 | `Config{host,path,headers,xmux}` ← proto `Config`（`xray-proto/src/lib.rs:306-308`）+ JSON `masqueSettings` 解析（`path` 缺省 `/.well-known/masque/ip/*/*/`） |
| `.../src/capsule.rs` | 新 | 四类胶囊编解码 + 校验上限（§1.3 表） |
| `.../src/connect.rs` | 新 | `ConnectIpSession`：地址请求/分配、包收发、MTU/ICMP 回灌 |
| `.../src/h2.rs` | 新 | hyper h2 客户端：CONNECT + `:protocol` + `Capsule-Protocol` + 200 校验 + `Upgraded` → 会话 |
| `.../src/error.rs` | 新 | `MasqueError`（`Auth/Protocol/Io/Mtu/Rejected(status)` 分类，对齐 `ClauseId::ErrorClassifiedNoPanicEscape`） |
| `.../src/register.rs` | 新 | `register_dialer()`（M1 只注册 dialer；`register_listener` 留 M2 空壳不注册） |
| `.../tests/capsule_golden.rs` | 新 | 胶囊字节 golden（用 Go `capsule_test.go` 的构造形态做对拍基准） |
| `.../tests/connectip_go_interop.rs` | 新 | `#[ignore]` + env 门控（`XRAY_GO_MASQUE_ADDR`），M1 验收 ⇒ **手工构造 IP/UDP DNS 查询往返**（§5） |

### 3.2 M2（server + proxy 层 + 接线）

| 文件 | 类型 | 内容 |
|---|---|---|
| `xray-frame/src/ipstack/mod.rs` | 新（框架件） | `PacketStack` / `PacketBridge`（§2.4） |
| `crates/xray-transport-masque/src/hub.rs` | 新 | `Listener`：TCP accept → TLS → hyper auto h2（**必须** `.http2().enable_connect_protocol()`）→ `ServeHTTP` → `ServerConn{request_meta, session, reject(status)}` |
| `crates/xray-transport-masque/src/pool.rs` | 新 | 地址池（对齐 `proxy/masque/pool.go:10-80`，含 v4 末地址剔除 + 环形游标） |
| `crates/xray-proxy-masque/**` | 新 crate | `plugin.rs`（L1 `Plugin` + `PluginContract` 12 条逐条声明）/ `client.rs`（隧道池 + netstack 目标 Dial）/ `server.rs`（认证 + 地址分配 + 包路由 + dispatcher 桥）/ `config.rs`（`settings.users/address/mtu`） |
| `crates/xray-conf/src/init.rs` | 改 | `:340-352` 只放开 `masqueSettings` 与 `network=masque`（**xdrive 保持拒绝**）+ `:826-856` 测试改对应断言 |
| `crates/xray-core/src/arm_builders/{mod,inbound,outbound}.rs` | 改 | 两张表各加一行 `("inbound:masque", …)` / `("outbound:masque", …)` |
| `crates/xray-proxy-masque/tests/plugin_contract.rs` | 新 | `assert_plugin_contract!(MasquePlugin)` + 装配负向（缺 address / 非 TLS / 无 users） |
| `crates/xray-cli` 或 `xray-core` 的 transport 注册入口 | 改 | 调 `xray_transport_masque::register_dialer()/register_listener()`（对齐其余 transport 的注册位置） |

### 3.3 不产出（红线/非目标）

`tests/**`、`dist/interop_*`、`.github/workflows/**`、`docs/refs/**`、`vendor/**`、`protos/**`、`crates/xray-transport-tcp/register.rs` **一律不改**；`crates/udf-frame` 只读。

---

## 4. 关键 API 签名草案（只签名，不写实现）

### 4.1 胶囊层（`xray-transport-masque/src/capsule.rs`）

```rust
// 类型值对齐 Go capsule.go:22-25；varint 用 h3::proto::varint（已在工作区依赖内）
pub const CAPSULE_DATAGRAM: u64 = 0;
pub const CAPSULE_ADDRESS_ASSIGN: u64 = 1;
pub const CAPSULE_ADDRESS_REQUEST: u64 = 2;
pub const CAPSULE_ROUTE_ADVERTISEMENT: u64 = 3;

/// 单胶囊 payload 上限（Go conn.go:63）与单胶囊条目上限（Go capsule.go:27-30）。
pub const MAX_CAPSULE_PAYLOAD: usize = (1 << 16) - 1;
pub const MAX_ENTRIES_PER_CAPSULE: usize = 8192;

pub enum Capsule {
    Datagram(Vec<u8>),                              // contextID(0) 已剥除，裸 IP 包
    AddressAssign(Vec<AssignedAddress>),
    AddressRequest(Vec<AddressRequest>),
    RouteAdvertisement(Vec<IpRoute>),
    Unknown { ty: u64, payload: Vec<u8> },          // 未知类型跳过不报错（conn_test.go:385）
}

pub struct CapsuleReader<R> { /* 流式：一次只驻留一个胶囊 payload（有界） */ }
impl<R: tokio::io::AsyncRead + Unpin> CapsuleReader<R> {
    pub fn new(inner: R) -> Self;
    pub async fn next(&mut self) -> Result<Option<Capsule>, MasqueError>;  // None = 对端 EOF
}

pub struct CapsuleWriter<W> { /* 合并写：Datagram 走小缓冲直写 */ }
impl<W: tokio::io::AsyncWrite + Unpin> CapsuleWriter<W> {
    pub async fn write(&mut self, c: &Capsule) -> Result<(), MasqueError>;
    pub async fn flush(&mut self) -> Result<(), MasqueError>;
}
```

参照：Go `connectip/capsule.go:21-26,40-63,92-96,191-250` 与 `conn.go:467-477,673-677`。

### 4.2 CONNECT-IP 会话（`connect.rs`）——对 Go `connectip.Conn` 的等价面

```rust
pub struct ConnectIpSession { /* capsule 读写 + 地址状态 + 关闸 */ }

impl ConnectIpSession {
    /// `stream` 可以是 h2 Upgraded（M1）或 h3 RequestStream（M3）。
    pub fn new<S>(stream: S) -> Self where S: AsyncRead + AsyncWrite + Send + Unpin + 'static;

    /// 送一个 IP 包；Ok(Some(icmp)) = 超 MTU，调用方须把 icmp 包回灌隧道
    /// （Go conn.go:592 + client.go:367-371 / server.go:484-490）。
    pub async fn send_packet(&mut self, ip: &[u8]) -> Result<Option<Vec<u8>>, MasqueError>;

    /// 取一个 IP 包（内部对非 Datagram 胶囊自动分流到对应事件队列）。
    pub async fn recv_packet(&mut self) -> Result<Vec<u8>, MasqueError>;

    /// 地址面（客户端用）：Go dialer.go:277-296。
    pub async fn request_addresses(&mut self, want: &[IpPrefix]) -> Result<(), MasqueError>;
    pub async fn recv_assignment(&mut self) -> Result<Vec<AssignedAddress>, MasqueError>;
    pub fn local_addrs(&self) -> &[IpAddr];

    /// 地址面（服务端用）：Go server.go:355-371。
    pub async fn assign_addresses(&mut self, addrs: &[IpPrefix]) -> Result<(), MasqueError>;
    pub async fn advertise_route(&mut self, routes: &[IpRoute]) -> Result<(), MasqueError>;
    pub async fn serve_address_requests(&mut self, ...) -> Result<(), MasqueError>;

    pub fn max_packet_size(&self) -> usize;      // Go conn.go:695-700
    pub async fn close(self) -> Result<(), MasqueError>;
}
```

**对齐锚点**：`ReadPacket`/`WritePacket` 的 `io::ErrShortBuffer` 语义（`conn.go:495-520`；`server.go:417-421`、`client.go:345-351` 都靠它续读）在 Rust 侧改为「返回整包 `Vec<u8>`」，**不要**照抄短缓冲续读约定（Rust 无此惯例，照抄只会制造第二个约定）。

### 4.3 H2 绑定（`h2.rs`）

```rust
/// 客户端：CONNECT-IP over h2（字节序语义对齐 Go dialer.go:154-208 + connectip/http2.go）。
pub async fn connect_h2<S>(io: S, cfg: &Config, authority: &str)
    -> Result<ConnectIpSession, MasqueError>
where S: AsyncRead + AsyncWrite + Send + Unpin + 'static;

/// 服务端（M2）：一条已 TLS 的连接 → hyper auto h2，请求交给 `ServeHttp`.
pub struct H2ListenerConfig {
    pub path: PathMatcher,           // Go hub.go:307-312（path + query 全等）
    pub max_concurrent_streams: u32, // Go http2_server.go:27 = 100
    pub handshake_timeout: Duration, // Go http2_server.go:28 = 10s
}

/// 握手完成的连接面（对应 Go hub.go:327-420 ServerConn）。
pub struct ServerConn { /* request; session; answered: OnceFlag */ }
impl ServerConn {
    pub fn request_meta(&self) -> &RequestMeta;   // method/:protocol/:path/headers（认证取 Basic）
    pub async fn accept(self) -> Result<ConnectIpSession, MasqueError>;  // 写 200 + Capsule-Protocol: ?1
    pub fn reject(self, status: StatusCode);      // Go hub.go:357-365
    pub fn local_addr(&self) -> SocketAddr;
    pub fn remote_addr(&self) -> SocketAddr;
}
```

**必须照抄的 hyper 细节**（否则 Go 端不认）：CONNECT 请求体为空、响应**不带 `Content-Length`**（`hyper-1.12.0/src/proto/h2/server.rs:489-499` 对二者均有硬行为）；服务端必须 `.http2().enable_connect_protocol()`。

### 4.4 框架件（`xray-frame/src/ipstack/mod.rs`，M2）

```rust
/// 虚拟 IP 栈的最小面（对应 Go `wireguard.Net` 的 Dial 面 + gVisor 栈的 Input 面）。
pub trait PacketStack: Send {
    fn ingest_rx(&mut self, pkt: Vec<u8>);
    fn drain_tx(&mut self) -> Vec<Vec<u8>>;
    fn poll(&mut self, now: Instant);
}

/// 栈上 TCP/UDP 事件 ↔ `DispatchHandler`（对应 Go `server.go:503-553 HandleConnection`
/// 与 `proxy/wireguard/netstack.go:49 CreateNetTUN` 的 handler 面）。
pub trait PacketBridge: Send + Sync {
    fn on_tcp_accept(&self, ev: TcpAcceptEvent, link: DuplexLink);
    fn on_udp_datagram(&self, src: IpEndpoint, dst: IpEndpoint, payload: Vec<u8>);
}
```

参照实现（**移动来源，不是新写**）：`crates/xray-proxy-wireguard/src/netstack.rs:56,94,147,165,170,301,367,391`（`ingest_rx/drain_tx/poll/drain_accepted/drain_udp/udp_send_reply`）；`inbound.rs:597`（`WgTcpRelay`）+ `dispatcher.rs:472`（`make_wireguard_dial_fn` 的 DialBridge 形态）。

### 4.5 插件声明（`xray-proxy-masque/src/plugin.rs`，M2）

```rust
static MASQUE_CONTRACT: PluginContract = PluginContract {
    clauses: &[ /* 12 条全适用，参照 wireguard plugin.rs:44-57 的写法 */ ],
    extra: &[
        ("MASQUE-TLS-REQUIRED", "masque transport 必须 security=tls 且 ALPN 含 h2（Go server.go:129-134）"),
        ("MASQUE-ADDR-POOL",    "每族仅一个前缀；服务器自身地址与网络/广播地址不得分配（Go pool.go:31-45）"),
        ("MASQUE-HTTP2-ONLY",   "M1/M2 只支持 ALPN=h2；h3 需显式 alpn=h3 且不在本里程碑（Go hub.go:47-50）"),
    ],
    not_applicable: &[ /* M1/M2 起：HotPathFreeze 视热路径定义，M3 复核 */ ],
};
```

---

## 5. 互通取证方案（Go 26.10.17 双端 + 抓包）

### 5.1 对端资产（已核实在位）

| 用途 | 路径 | 状态 |
|---|---|---|
| Go 服务端（Windows） | `D:/tmp/go2617/xray.exe` | ✓ 45,184,000 B（2026-10-28） |
| Go 客户端/服务端（Linux/WSL） | `/root/go2617-linux` | ✓ 46,463,432 B（2026-10-30） |
| 抓包 | `D:/Project/tools/Wireshark/tshark.exe`（4.6.8）；scapy 2.7 兜底（`conf.use_pcap=True`，接口名 `Loopback Pseudo-Interface 1`） | ✓ |
| Go 源码裁定 | `D:/Project/Xray-core` @ `92ccc939` | ✓ |

### 5.2 方向矩阵（每方向都要，缺一不算过）

| # | 方向 | 组网 | 判据 |
|---|---|---|---|
| A | Rust client → **Go server** | Go inbound `masque`（`network:"masque", security:"tls", alpn:["h2"]`, `settings.address:["10.0.0.1/24"]`, `users:[{email,pass}]`） | ① 拿到 `ADDRESS_ASSIGN`（非 0.0.0.0）② **手工构造 IPv4/UDP DNS 查询 → 隧道 → 收到同 id 的 DNS 应答** ③ Go 日志出现 `MASQUE: tunnel from ... assigned [...]`（`server.go:355-357` 的日志锚） |
| B | **Go client** → Rust server | Rust inbound `masque`，Go outbound `masque`+`network:"masque"` 指向它 | 同 ②③，判据换成 Rust 侧日志 + 抓包 |
| C | Rust client ↔ Rust server（自环） | 两端都是新 crate | 同 ②；另加 64KB 连续 IP 包往返不丢（有界队列 512 的语义，`server.go:20`） |

> **M1 只做 A**（且只用 transport crate 的测试二进制，不接 CLI）。B/C 属 M2。

### 5.3 抓包取证（协议改动验收硬要求）

1. **密钥**：rustls 侧开 keylog（等价 `tlsSettings.masterKeyLog`），`SSLKEYLOGFILE=D:/tmp/masque-keys.log`；Go 侧同变量。
2. **抓 H2 帧**：
   ```bash
   D:/Project/tools/Wireshark/tshark.exe -r D:/tmp/masque.pcapng -d tcp.port==443,http2 \
     -Y "http2" -T fields -e http2.type -e http2.header.name -e http2.header.value
   ```
   逐项断言（**硬指标**）：`SETTINGS` 含 `ENABLE_CONNECT_PROTOCOL(0x8)=1`；`HEADERS` 含 `:method=CONNECT` / `:protocol=connect-ip` / `:path=/.well-known/masque/ip/*/*/`（原样 `*`）/ `capsule-protocol: ?1`；响应 `:status=200` + `capsule-protocol: ?1`。
3. **抓胶囊**：从解密后的 TCP 流按 `varint(type) varint(len)` 逐帧解析，报表输出「解析残留非零帧数 = 0」（沿用 KCP/vision 的取证口径，见 CLAUDE.md §5 与 memory 中的协议取证实务）。
4. **H3（M3）**：`tshark -d udp.port==443,quic` + 解密，断言语义同上（h3 分支下 IP 包走 QUIC DATAGRAM 而非 DATAGRAM 胶囊，Go `conn.go:673-683` 二分支）。

### 5.4 可执行验收命令（M1）

```bash
# 1) Go 服务端（Windows）
D:/tmp/go2617/xray.exe run -c D:/tmp/masque-go-server.json   # inbound masque, alpn=["h2"], address ["10.0.0.1/24"]

# 2) Rust 侧互通（env 门控 + ignore，形态照 vless_mux_go_server_interop）
cargo test -p xray-transport-masque --test connectip_go_interop -- --ignored --nocapture

# 3) 双向第二落点（WSL，Linux Go）
wsl -d ubuntu-xray -e bash -lc '/root/go2617-linux run -c /root/masque-server.json'

# 4) 本 crate 常规门
cargo test -p xray-transport-masque --all-targets
cargo clippy -p xray-transport-masque --all-targets -- -D warnings
cargo fmt -p xray-transport-masque -- --check
```

---

## 6. 里程碑与工作量

### M1 —— transport 客户端 + 胶囊内核（**可独立验收，先做这一层**）

产出：§3.1 全部文件；可 `Dial` 到 Go 26.10.17 server，完成地址分配 + DNS 查询往返。
验收：§5.4 命令 1+2 全绿；抓包断言 §5.3 全过；`capsule_golden` 与 Go 构造逐字节对齐；本 crate 三件套（test/clippy/fmt）干净。
**估算：8–10 人日**（Rust ≈1500 行 + 测试；其中 0.5 人日为 §8-U1 的 hyper CONNECT spike，**spike 不过则整个方案改走 raw `h2` crate**）。

### M2 —— 服务端 + proxy 双侧 + 接线 + 框架件

产出：`xray-frame::ipstack`、`xray-transport-masque::{hub,pool}`、`xray-proxy-masque`（plugin/client/server）、conf 放开、arm_builders 两行、transport 注册。
验收：
1. §5.2 的 A/B/C 三方向全绿；
2. `cargo test -p xray-proxy-masque --all-targets` + `assert_plugin_contract!` 通过 + 装配负向（缺 address / 非 TLS / 空 users → build `Err`）；
3. `cargo test -p xray-conf` 里 `init.rs:826-856` 的改后断言（masque 放行、xdrive 仍拒）；
4. `dist/interop_matrix.py` 12/12 不回归（masque 尚未进矩阵，此条只证"没打坏别人"）；
5. 抓包：seed 隧道间转发（`server.go:428-437`）与 ISP：两隧道互 ping 通。
**估算：16–20 人日**（含框架件提炼 3–4 人日、服务端 5、proxy 双侧 6、接线 2、取证 2–3）。

### M3 —— H3 模式 + WARP 变体 + 收口

产出：h3 绑定（`h3`/`quinn`，复用 `xray-transport-quic` 的拥塞桥）、`warp`（client cert + 公钥 pin + 20 字节 CID + `0x276` draft setting，Go `warp.go:14-78` + `dialer.go:110-115,147-152`）、xmux 隧道池调参、插件热路径复核。
验收：H3 方向 A/C 全绿（含 QUIC DATAGRAM 分支抓包）；WARP 对 Cloudflare 端点实测一例（若不可得，记 CONDITIONAL）；`cargo test --workspace --lib` 0 failed。
**估算：6–12 人日**（h3 4–6、warp 2–3、收口 1–2）。

| 里程碑 | 人日 | 累计 |
|---|---|---|
| M1 | 8–10 | 8–10 |
| M2 | 16–20 | 24–30 |
| M3 | 6–12 | **30–42** |

> 口径：单人、熟悉本仓、不含中途返工。**风险 R1（hyper CONNECT 实测不过）成立时 M1 +2 人日**（改 raw `h2` crate，仍是复用而非新栈）。

---

## 7. 风险清单

| # | 风险 | 触发后果 | 处置（本方案的应对） | 等级 |
|---|---|---|---|---|
| **R1** | **extended CONNECT 在我们 H2 栈的支持度**：hyper 1.12 代码层面支持（§2.3 已逐点核过），但 `enable_connect_protocol` + `:protocol` **在本仓从未被启用/跑过**（全仓 0 命中）；hyper 的 CONNECT 分支对"请求体为空 + 响应无 content-length"有硬约束 | M1 走不通则方案整体延后 | **M1 首件事 = 0.5 人日 spike**（自建 hyper server 开 `enable_connect_protocol` + hyper client 发 `:protocol`，断言两端都看到）；spike 失败 → 降级 raw `h2` crate（`h2-0.4.19/src/server.rs:1043` 已实证支持），**不是**手写帧 | **高** |
| **R2** | **UDP↔stream 映射与多路复用**：前提本身就错（Go 无 per-UDP-session stream，见 §1.1）；真实风险是**单流载全部流量 → 单条 h2 流的流控窗口成为全局瓶颈** | 吞吐塌（历史同型：h2 窗钉 enc8x，CLAUDE.md §5） | M1 起就用 16MB 连接窗/16MB 流窗起步（`flow_window.rs` 已有 RTT 阶梯），M2 加"隧道数 × 每隧道带宽"观测；**禁**自造流控 | 中 |
| **R3** | `warp.go` 是什么变体 | 误以为 MASQUE 必带 WARP，把 client cert/pin 塞进 M1 | 定性：**Cloudflare WARP 专用变体**（`WarpHost="cloudflareaccess.com"`/`WarpPath="/"`，`warp.go:14-16`；ECDSA 私钥签临时证书 `:18-45`；`InsecureSkipVerify` + 公钥 pin `:52-77`；20 字节 CID `dialer.go:147-149`；draft datagram setting `0x276` `connectip/client.go:24-26`）。**M1/M2 不实现**，配置里 `warp` 出现即 fail-visible（L5 装配门） | 低（已隔离） |
| **R4** | 与 splithttp/xhttp 的命名边界 | 有人把 masque 当成 splithttp 的 mode 塞进 `xhttpSettings` | 边界锁死：传输名 = `masque`、JSON 键 = `masqueSettings`（Go `transport_internet.go:68-69`，我们 `dialer.rs:555` 已对齐）；masque 与 splithttp **零共享模块**（只共享依赖与 `xmux` 泛型池） | 低 |
| **R5** | **零 xray 语义部分是否该提炼 udf** | 把胶囊编解码塞进 udf，污染地基（§3.5.3 明确"协议方向件不进 udf"） | 判定：胶囊/connect-ip = **协议 wire 语义** → 留 `xray-transport-masque`（§3.5.2 例外条款 + 件头写 `udf 不适用` 理由）；只有"IP 栈桥"上框架（§2.4）。**两者都不进 udf** | 中（纪律性） |
| **R6** | 框架件提炼触 `WG-TUN-FROZEN` / `xray-proxy-tun` 红线 | 提炼动作被解读为"改数据面"，触发红线重审 | §2.4 的**移动式**提炼需主代理显式授权；未授权时 M2 的退路 = masque 侧只写**薄适配**、复用 wireguard 的 `netstack` 模块（跨 crate 依赖记债），并在票面注明"待授权后收编" | **中高（决策项）** |
| **R7** | 服务端包路由的隧道间转发（`server.go:428-437`）易漏 | 多客户端互相 ping 不通 | M2 显式做成验收项（§6 M2-5）；队列有界 512 + 溢出丢弃计数（对齐 `server.go:37` 的 `tunnelQueueSize=512` 与 `:428-437` 的非阻塞 send→Release） | 中 |
| **R8** | 认证与凭据落日志 | 安全问题（喷 401 时把 password 打进日志） | 强制 `ClauseId::SecretMasking`；`PluginContext::log()` 的 `LogFacade` secrets 表登记 password；401 分支只记 email（对齐 Go `server.go:271-282` 只记 name） | 中 |
| **R9** | H3 默认值陷阱 | 配置只写 `security:"tls"` 不写 alpn 时，Go 服务端**默认起 h3**（`hub.go:47-50`：`h3 = contains(h3) \|\| !h2`） | M1/M2 的所有互通配置**必须显式 `alpn:["h2"]`**；Rust 服务端 M2 若未实现 h3，则在 `security=tls` 且 alpn 缺省时硬错提示（不静默） | **高（易踩）** |
| **R10** | 地址池边界（v4 广播/网络/服务器自身地址） | 分配出不可用地址 → 静默黑洞 | 照抄 `pool.go:31-45` 三条校验 + `infra/conf/masque.go` 的 `mtu∈[1280,65535]` 与"每族仅一前缀"；M2 写表驱动单测 | 中 |

---

## 8. 非目标 / 未知点

### 8.1 非目标（本任务书明确不做）

1. **CONNECT-UDP（RFC 9298）本体**与 `connect-udp` :protocol——Xray 用的是 connect-ip，二者不共存。
2. **Cloudflare WARP 变体**（client cert / 公钥 pin / 20 字节 CID / `0x276` draft datagram）→ M3。
3. **URI 模板形式的 IP flow forwarding**（Go 明确报错 `request.go:29-31`）+ 多跳 forwarding 链。
4. **xmux 全参数调优**（复用泛型池即可，不新造参数面板）。
5. **ICMP 全语义**：只做 packet-too-big 回灌（Go 也只有这条 + 转发普通 ICMP 包）。
6. **重构 `xray-proxy-tun` / `xray-proxy-wireguard`**（红线 R6，未授权不动）。
7. **把 masque 加进 `dist/interop_matrix.py`**（`dist/` 是验证资产红线）。
8. 提升 Go 基准到 26.10.21（闸门未开，见 PM 排期 §0.2）。

### 8.2 未知点（**必须先原型验证**，验证不过即回改方案）

| # | 未知 | 验证方式 | 何时 |
|---|---|---|---|
| **U1** | hyper 1.12 的 `enable_connect_protocol` + `:protocol` + `Upgraded` 全链路是否真通 | 0.5 人日 spike：自建 hyper auto server（开开关）+ hyper h2 client（`Protocol::from_static("connect-ip")`），断言服务端收到 `:protocol`、客户端拿到 `Upgraded` 并能双向传字节 | **M1 第 1 步** |
| **U2** | Go 26.10.17 server 是否接受 hyper 发的 HEADERS 语义（`:path` 字面 `*` 的编码、`:authority` 带/不带端口、`te`/`accept` 等头） | M1 互通第一跑；失败逐项按 `hub.go:307-312` + `hub_test.go:42-46` 消歧 | M1 中段 |
| **U3** | Go server 的 `MaxPacketSize` 在 h2 下是否恒 65535（`conn.go:695-696`），且 hyper 单 DATA 帧上限（16KB 默认）对胶囊边界无影响 | 抓包 + 大包（>16KB IP 包）往返 | M1 末 |
| **U4** | Go server 缺省路径 `/.well-known/masque/ip/*/*/` 是真要求还是可配；我们的缺省 path 该写什么才能两边都通 | 分别试 `/`、`/.well-known/masque/ip/*/*/`、自定义 path | M1 末 |
| **U5** | 单流流控闸：hyper 的 h2 连接窗/流窗参数对我们（单流载全流量）是否够（16MB 起步够不够） | 回环 + 单隧道 100MB 传输测吞吐；对拍 Go 同拓扑 | M1 末 / M2 初 |
| **U6** | 框架件移动（R6）是否会动到 WG 数据面字节行为 | 移动后 `integration_wireguard_dataplane` 红线回归 + diff 复核 | M2 前（需授权） |

---

## 9. ADR 草案（Proposed；状态由主代理拍板）

### ADR-M1：MASQUE 的 H2 栈复用形态（**Y-statement 一段式** + 五问）

> **In the context of** 需要 MASQUE 的 CONNECT-IP 隧道且本仓已有 hyper/h2 栈（splithttp），**facing** Go 的手写 H2 客户端/服务端共 1294 行与"禁重复造轮子"的硬约束，**we decided** 新建 `xray-transport-masque` 只用 hyper/h2 的 **extended CONNECT 能力**做绑定层、不移植 Go 的手写 H2（流控/优先级/GOAWAY 交给 hyper），**to achieve** 协议面 ≈1500 行而非 ≈2800 行、且与 splithttp/hysteria 共享同一份帧层，**accepting** hyper 的 CONNECT 分支约束（空请求体 + 无 content-length 响应）与"hyper 从不支持时必须降级 raw `h2` crate"的耦合风险，**because** 手写帧层的维护成本远高于一次 0.5 人日 spike。

五问：
- **牺牲了什么**：放弃 Go 那种"完全掌控 H2 帧"的能力（自定义 SETTINGS 粒度、`awaitSendWindow` 级别的调优自由度）。
- **被否决备选**：① 逐行复刻 `http2.go`+`http2_server.go`（+1294 行 + 三处双栈，违 §3.5.2）② 直接依赖 `xray-transport-splithttp` 的私有连接外壳（跨 transport 互依赖 + 语义错配：多请求拼流 vs 单流胶囊）。
- **驱动场景**：QAS-1（吞吐）、QAS-3（互通）。
- **验证方式**：U1 spike + §5 三方向互通 + 抓包断言。
- **何时重审**：出现"必须自定义 SETTINGS/优先级"的需求（例如 H3 模式下需要 datagram 级调度），或 hyper 上游移除 `ext::Protocol`。

### ADR-M2：IP 栈桥归属 xray-frame（轻量五节）

- **Context**：MASQUE 是第三个需要「IP 包 ↔ TCP/UDP ↔ dispatcher」的消费者（前两个：`xray-proxy-tun`、`xray-proxy-wireguard`，后者已在 `inbound.rs:596` 留"提取共享 trait"记认）。
- **Decision**：把该桥作为 `xray-frame::ipstack`（派生层），协议 crate 只做薄适配；smoltcp 细节随件上移，wireguard/tun 后续收编。
- **Alternatives**：① 塞进 masque crate（第三次复制 → 打回项）② 上浮 udf（含 dispatcher 语义 + 网络方向件 → 双重违 §3.5.3）③ 依赖 `xray-proxy-wireguard`（proxy crate 当库 → 分层污染）。
- **Consequences**：短期需一次移动式提炼（触 `WG-TUN-FROZEN` 须授权，R6）；长期三处归一。
- **Status**：Proposed（待主代理 + 用户授权）。

### ADR-M3：里程碑切分（M1 transport 客户端优先）

- **Rationale**：M1 不需要 IP 栈桥、不需要配置接线、不需要服务端地址池——它是**纯协议正确性问题**，可独立验收且风险前置（U1–U4 全在 M1 暴露）。先做服务端会同时压上 R6 决策与地址池/路由，问题不可分离。

---

## 10. 质量需求场景（QAS，禁形容词）

| ID | 场景（源→刺激→制品→响应→度量） |
|---|---|
| **QAS-1** | 开发期·Rust client→Go server·单隧道·经隧道传 100MB TCP·吞吐 ≥ **50 MB/s**（本机回环）；失败线 < 20 MB/s ⇒ 视为流控/窗口缺陷，回查 U5 |
| **QAS-2** | 运行期·服务端·512 并发隧道·地址池 1×/24 前缀·分配/释放 10^4 次·**零地址重复、零泄漏**（释放后复用率 100%），超配时返回 503 而非挂起（对齐 `server.go:307-309`） |
| **QAS-3** | 互通期·任意一端为 Go 26.10.17·握手（TLS+CONNECT-IP+地址分配）·**≤ 1.5×Go↔Go 同拓扑耗时**；失败即视为 `:path`/headers 语义偏差（U2） |
| **QAS-4** | 故障期·对端进程被 kill·持活隧道·**≤ 5s** 内感知并向 dispatcher 注入 EOF，无 task 泄漏（托管在 `PluginContext::spawn`，`ctx.audit()` 可查） |
| **QAS-5** | 配置期·`network:"masque"` 但缺 `security:"tls"`·inbound 启动·**启动前**即 `Err`（不进入监听），错误文案点名缺项（对齐 Go `server.go:129-134`） |
| **QAS-6** | 取证期·一次 M1 互通会话·tshark H2 解析·**残留非零帧数 = 0**；SETTINGS/HEADERS 断言清单 §5.3 全过 |

---

## 11. 附录：一手材料索引（本文件所有结论的出处）

**Go（`D:/Project/Xray-core` @ `92ccc939`）**
`proxy/masque/server.go:35-38,126-191,263-341,343-356,359-390,373-411,413-446,447-468,470-495,497-501,503-553` ·
`proxy/masque/client.go:33-36,57-102,105-192,195-273,276-397` ·
`proxy/masque/pool.go:10-80` · `proxy/masque/account.go` · `proxy/masque/config.proto:11-26` ·
`transport/internet/masque/config.go:12,14-19` · `config.proto:15-27` ·
`transport/internet/masque/dialer.go:31,35,154-208,211-307,309-320,323-337` ·
`transport/internet/masque/hub.go:47-50,91-163,165-180,182-220,269-303,307-312,327-420` ·
`transport/internet/masque/http2.go:479-483` · `http2_server.go:27-29,111-131` ·
`transport/internet/masque/conn.go:58-62` · `warp.go:14-78` ·
`transport/internet/masque/connectip/{capsule.go:21-26,27-30,55-63,92-96,191-250,244-250}` ·
`connectip/conn.go:62-63,410-420,467-477,495-520,592-700` · `connectip/request.go:20,22,28-42,61-96` ·
`connectip/proxy.go:22-36` · `connectip/client.go:24-26,39-88` ·
`proxy/wireguard/netstack.go:49,103-107,159-173` · `infra/conf/masque.go`（client/server 两侧 JSON 面）·
`hub_test.go:42-46,110-120`（path/状态码判据）

**本仓**
`crates/xray-common/src/net/transport.rs:54-55,76,100` · `crates/xray-conf/src/init.rs:340-352,826-856` ·
`crates/xray-proto/src/lib.rs:176-178,306-308` ·
`crates/xray-transport/src/dialer.rs:93-110,555` · `crates/xray-transport/src/listener_registry.rs:51-62,80,102,118` ·
`crates/xray-core/src/arm_builders/mod.rs:129-155,157-180` ·
`crates/xray-frame/src/plugin.rs:13-93` · `context.rs:189-193,241-243,263-265,268-278,285-290,327-330` ·
`crates/xray-transport-splithttp/src/lib.rs:56-67` · `hub.rs:1-33,147-241` · `dialer.rs:136-236,646-680` · `mux.rs:75-123` · `flow_window.rs` ·
`crates/xray-proxy-wireguard/src/netstack.rs:56,93-94,147,165,170,184,193,207,214,224,239,301,331,367,391,414` · `inbound.rs:109,163,596-600` · `dispatcher.rs:472` · `plugin.rs:1-123` ·
`crates/xray-tls/src/btls_client.rs:1224,1255` · `utls.rs:495` ·
**第三方能力锚**：`hyper-1.12.0/src/server/conn/http2.rs:258` · `hyper-util-0.1.21/src/server/conn/auto/mod.rs:1068` · `hyper-1.12.0/src/ext/mod.rs:76-83` · `hyper-1.12.0/src/proto/h2/client.rs:716-735` · `hyper-1.12.0/src/proto/h2/server.rs:275-296,489-511` · `h2-0.4.19/src/server.rs:500,1043` · `h2-0.4.19/src/ext.rs:8-13` · `h2-0.4.19/src/proto/streams/streams.rs:271`

---

**维护**：里程碑结论与 §7/§8 的任何变化须回写 bd `Xray-core-rust-55yh7`（`--append-notes`），本文件不回改历史结论。
