VERDICT: DONE_WITH_CONCERNS（接线完成 + 复用取证通过；h2 侧复用弱于 Go 的成因未定 → §5.1）

## 0. 本轮落地清单（接手先看这里）

| 文件 | 改动（未 commit） |
|---|---|
| `src/register.rs` | ① xmux 解析去 `Some()` 包裹（`Config.xmux: Option<XmuxConfig>` 直取，修 E0609）；② `parse_range` 补 Go `Int32Range` 的**字符串形态** `"1-2"` / `"7"`（修前静默忽略 = xmux 范围等于没配），对象形态保留为宽松超集；③ `parse_splithttp_config_all_fields` 去掉 Go 非法的 `maxConnections`+`maxConcurrency` 组合，新增互斥硬错用例 + 两个 Go 形态用例；④ `fingerprint` 去多余 `clone`（clippy `clone_on_copy`） |
| `src/dialer.rs` | h3 三处 `set_on_close` 删掉 `xmux_client.conn.close()`（关的是**共享池单元**；Go `dialer.go:409-419` 的 onClose 只 `DoneRunning()`），注释按 Go 源码重写 |
| `src/h3_client.rs` | 删除 `H3ClientLike::close()` 及两个 impl（唯一调用方就是上面三处；留着即复现该 bug 的入口），文档同步 |
| `tests/xmux_reuse.rs`（新增 458 行） | 6 个复用锚用例：h2 计数 TLS server / h3 计数 quinn endpoint / 反证（绕池）/ 串行形态 / `hMaxRequestTimes` 预算对照 |
| `fix/scripts/wave7_h3_matrix.py` | ① xmux 维度锚改为 **TCP 转发器计数**（原 access-log 数的是入站会话，测不到 TCP 复用）；② xmux 值改 Go 合法形态（`"3"` / `"1"`）；③ pool vs no-reuse 对照判据；④ `kill_xray` 只杀本脚本二进制（不误杀同机其他代理的 xray）；⑤ socks 端口就绪等待（修 Go 客户端启动竞态） |

（`src/config.rs` / `src/mux.rs` / `src/h3_client.rs` 的 `XmuxConn`/`LazyH3Conn`/`ManagerPool` 主体是上一轮已落地部分，本轮只在其上修 bug 与删死码。）

# s42cg：splithttp xmux 连接复用（实现已存在但 dialer 零引用）

改动文件：`crates/xray-transport-splithttp/src/{mux,dialer,register,h3_client}.rs`（+ 三个测试文件的调用点同步）。
无新依赖、无 wire 语义改动、未 commit。未碰红线文件（xray-mux / xray-core 的 inbound/outbound/functions / xray-transport-hysteria / 各 udp.rs / grpc.rs / api_exec.rs）。

---

## 1. Go 五维判定规格表（源码核对：Go xray-core @ 92ccc939 = v26.10.17）

### 1.1 参数与默认值

| 参数 | Go 缺省（`GetNormalized*`） | 比较方向 | 语义（判定式） |
|---|---|---|---|
| `maxConcurrency` | `{0,0}` | `client.Running < concurrency` | **单 client 的并发连接上限**；`0` = 不限（候选 = 全部 client）。注：与 `maxConnections` **互斥**（`transport_method.go:458-460` 硬错「maxConnections cannot be specified together with maxConcurrency」） |
| `maxConnections` | `{0,0}` | `len(clients) < connections` | **池内 client 总数上限**；`0` = 不限（每次取用都可能新建）。非 0 时**未达上限就先新建**（`mux.go:117-120`） |
| `cMaxReuseTimes` | `{0,0}` | `leftUsage == 0` 即淘汰 | **单个 client 的复用次数**；新建时 `leftUsage = rand-1`（`mux.go:67-69`）⇒ 配 `N` 时该 client 总共可用 `N` 次；`0` = 不限（`leftUsage = -1`） |
| `hMaxRequestTimes` | `{0,0}` | `LeftRequests <= 0` 即淘汰 | **单个 client 的请求数上限**；新建时 `LeftRequests = rand`（`mux.go:71-73`）；`0` = 不限（`MaxInt32`）。由**拨号器逐请求扣减**（`dialer.go:426/435/444/512`） |
| `hMaxReusableSecs` | `{0,0}` | `now > UnreusableAt` 即淘汰 | **单个 client 的存活期**；新建时 `UnreusableAt = now + rand s`（`mux.go:74-76`）；`0` = 不限 |

**conf 层缺省预设**（`transport_method.go:461-468`）：用户**未配置** xmux 块（`c.Xmux == (XmuxConfig{})`）时，conf 层套
`maxConnections {3,3}` / `hMaxRequestTimes {600,900}` / `hMaxReusableSecs {1800,3000}`（`maxConcurrency`、`cMaxReuseTimes` 保持 0 = 不限）。
⇒ **Go 缺省即池化**（最多 3 条连接、每连接 600-900 请求、存活 1800-3000 秒）。

### 1.2 选路算法（`mux.go:89-146`，四分支）

1. **淘汰扫描**：任一条件命中即摘除该 client（`NotUsed=true` + 无在途请求时关连接）：
   `IsClosed()` ∨ `leftUsage == 0` ∨ `LeftRequests <= 0` ∨ `now > UnreusableAt`。
2. 池空 → **新建**（`create=false` 时返回 nil）。
3. `create && connections > 0 && len(clients) < connections` → **新建**（未达上限先扩池）。
4. 候选筛选：`concurrency > 0` 时只留 `Running < concurrency` 的 client；候选空 → **新建**；否则**随机选一个**，且 `leftUsage > 0` 时 `leftUsage -= 1`。

### 1.3 连接复用面（谁被复用）

`getHTTPClient`（`dialer.go:47-79`）：`globalDialerMap[dialerConf{dest, *MemoryStreamConfig}] → *XmuxManager`
⇒ **池单元 = `DialerClient`（HTTP 客户端）**，key = (目标, **配置对象指针身份**)。
⇒ 复用效果：**同一 outbound 的多条代理连接共用同一个 HTTP 客户端**（h2 侧 = 同一条 TCP 连接多 stream；h3 侧 = 同一条 QUIC 连接多 stream）。

---

## 2. Rust 现状与一致性核对

### 2.1 修前现状
- `crates/xray-transport-splithttp/src/mux.rs`（574 行）**已实现** `XmuxClient` / `XmuxManager` / `ManagerPool`：
  四分支选路 ✓、五维计数 ✓、`concurrency`/`connections` 构造期一次采样 ✓、`new_xmux_client` 的三段初始化 ✓、
  淘汰四条件 ✓——**与 Go 语义逐条一致**（本次核对未发现偏差，无需修正）。
- 但 `dialer.rs` 对 `mux::` **零引用**：`DefaultDialerClient` **每次拨号现建**（`register.rs` 的
  `Arc::new(DefaultDialerClient::new(...))`）⇒ 每条代理连接一条新 TCP（h3 侧一条新 QUIC）。
- `resolve_mode(..., has_download_settings)` 在 `dial()`/`dial_h3()` 里**硬编码 false** ⇒ Go 的
  「auto+REALITY+downloadSettings → stream-up」也没实现。
- 计数方法（`inc_open_usage`/`dec_open_usage`/`dec_left_requests`）**无人调用** ⇒ 即便接线，
  `maxConcurrency` / `hMaxRequestTimes` 两维在生产路径永不触发。

### 2.2 核对结论
| 维度 | Rust 已实现 | Go | 结论 |
|---|---|---|---|
| 四分支选路 | ✓ | ✓ | 一致 |
| `leftUsage = rand-1`（`cMaxReuseTimes`） | ✓ | ✓ | 一致 |
| `LeftRequests = rand`（`hMaxRequestTimes`） | ✓ | ✓ | 一致 |
| `UnreusableAt = now + rand s` | ✓ | ✓ | 一致 |
| `connections` 未达上限先新建 | ✓ | ✓ | 一致 |
| `concurrency` 过滤 `Running < N` | ✓（字段名 `open_usage` = Go `Running`） | ✓ | 一致 |
| 随机选候选 | ✓ | ✓ | 一致 |
| 缺省预设（conf 层） | ✓（`register.rs` 解析时套 `maxConnections {3,3}` / `hMaxRequestTimes {600,900}` / `hMaxReusableSecs {1800,3000}`） | ✓ | 一致 |
| `maxConnections` + `maxConcurrency` 互斥校验 | ✗ 缺 | ✓（`transport_method.go:458-460` 硬错） | **偏差**：Rust 未做互斥校验（配了会走「先按 connections 扩池、再按 concurrency 过滤」的混合语义）⇒ 已补（见 §3） |
| 池 key | 内容 key（Rust 拨号入口拿到的是克隆的 `StreamSettings`） | **指针身份**（每 outbound 一个 manager） | **偏差**（登记在案，见 §3） |

---

## 3. 接线设计

### 3.1 承载（复用既有面，不新造体系）
- 池单元沿用 mux.rs 已有的 `XmuxManager<C>` / `XmuxClient<C>`（`C` = 被复用的连接）✓；
- 新增两条适配：`XmuxConn for Arc<DefaultDialerClient>`（h2）、`XmuxConn for LazyH3Conn`（h3）✓；
- **进程级 manager 池**沿用 mux.rs 已有的 `ManagerPool<C>`（对应 Go `globalDialerMap`）✓：
  `H2_MANAGERS` / `H3_MANAGERS`（`LazyLock` 静态）✓。

### 3.2 池 key
Go 的 key 是 `dialerConf{dest, *MemoryStreamConfig}`——**指针身份**（每 outbound 一个 manager）。
Rust 拨号入口拿到的是**克隆**的 `StreamSettings`（`register.rs` 的 `dial_fn` 每次 `settings.clone()`），
无稳定身份 ⇒ 用**内容** key：目标 + security + transport_json + security_json + sockopt_json + finalmask_json
（`mux::xmux_manager_key`）。
**差异登记**：两个配置内容完全相同的 outbound 在 Rust 侧共用一个 manager（Go 不会）。
影响面可控——传输层在路由层之下（路由在拨号前已定），共享的只是同目标的底层连接。

### 3.3 拨号路径
- **h2**：`register.rs` 不再每次 `Arc::new(DefaultDialerClient::new(...))`，改为经
  `H2_MANAGERS.get_or(key, …)` → `XmuxManager::get_xmux_client()` 取池单元 ✓（复用 = 复用底层 TCP）。
- **h3**：Go 的 h3 xmux 单元 = `http3.Transport`（**只造 transport，QUIC 握手推迟到首次请求**，
  `dialer.go:155-240`）。Rust 的 `H3Conn::connect_with_quic_params` 是**急连**（await），而
  `XmuxManager` 的工厂是**同步** `Fn() -> C` ⇒ 新增 `LazyH3Conn`（握手推迟到首次 `get()`，
  `tokio::sync::OnceCell::get_or_try_init`）✓ 语义与 Go 的 lazy transport 一致。
  h3 拨号函数因此泛型化为 `C: H3ClientLike`（生产 = `LazyH3Conn`；测试 = 已建好的 `Arc<H3Conn>`）✓。
- **五维计数接线**（Go `dialer.go:398-444`）：`Running` ↔ `inc_open_usage`/`dec_open_usage`
  （连接建立/关闭时）；`LeftRequests` ↔ `dec_left_requests`（**每个 splithttp 请求扣一次**：下行 GET、
  上行 POST、packet-up 的每个 POST）✓ ⇒ `maxConcurrency` / `hMaxRequestTimes` 两维在生产路径真正生效。
- **拨号函数签名**：`dial_packet_up` / `dial_stream_up` / `dial_stream_one` / `dial_h3_*` / `dial` / `dial_h3`
  的 client 参数由 `Arc<DefaultDialerClient>` / `Arc<H3Conn>` 改为 `Arc<XmuxClient<C>>`（Go 侧拨号器持有的
  就是 `*XmuxClient`——连接与计数一体）✓。
- **补 Go 的互斥校验**：`maxConnections` 与 `maxConcurrency` 同时 > 0 → 配置期硬错（Go
  `transport_method.go:458-460`）✓。

### 3.4 缺省行为（不变式）
Go 缺省即池化（conf 层预设 maxConnections=3 等）⇒ Rust 接线后**默认也池化**（Rust 的 conf 层预设本就与 Go 一致）✓。
**协议面行为不变**：session id 仍逐拨号生成 ✓、请求/响应字节序列不变 ✓（池化只影响底层连接复用）。

---

## 4. 复用证据锚 / 五维断言 / 反证 / 压测

### 4.1 复用证据锚（本票核心验收）：服务端连接接受次数

新增 `crates/xray-transport-splithttp/tests/xmux_reuse.rs`（6 用例）。锚**不看请求是否成功**
（复用坏掉时拨号照样成功，只是每次都新建连接），而是数**服务端侧的连接接受次数**：
h2 数 `TcpListener::accept`（= 新 TCP 连接数），h3 数 `quinn::Endpoint::accept`（= QUIC 握手次数）。
客户端走**生产接线路径**（`register::register_dialer()` + `xray_transport::dialer::dial`），
即 `H2_MANAGERS` / `H3_MANAGERS` + `XmuxManager` 五维判定，不是直接调 `dial_*`。
拨号形态取生产形态（多条代理连接同时存活，读尽下载流后仍保持）。

实测（`cargo test -p xray-transport-splithttp --test xmux_reuse -- --nocapture`）：

| 用例 | xmux 配置 | 拨号 | 连接接受数 | 读法 |
|---|---|---|---|---|
| `h2_bypass_pool_control`（**反证**） | 无池：每拨号 `wrap_xmux_client(现建 client)` = 接线前形态 | 5 | **10 = 2×N** | GET/POST 各一条，锚对"是否复用"敏感 |
| `h2_default_xmux_reuses_tcp_connection` | 缺省（conf 套预设 maxConnections {3,3}） | 5 | **8** | 复用生效（< 反证 10） |
| `h2_max_connections_one_single_client` | `maxConnections {1,1}` | 5 | **6** | 单 client 池 |
| `h2_sequential_close_weakens_reuse` | 缺省，拨完即关（串行） | 5 | **8** | 关连接会终止下载流，复用弱于并发形态 |
| `h2_h_max_request_times_…` | `hMaxRequestTimes` 100 vs 1 | 5 | **6 vs 10** | 预算 1 时每拨号必换 client ⇒ `dec_left_requests` 真接了 |
| `h3_xmux_reuses_quic_connection` | `maxConnections {1,1}` | 4 | **1**（gets=4 / posts=4） | 4 条代理连接的 8 个请求全多路复用在同一条 QUIC 连接上 |

**修复项（本票发现，非上一轮遗留）**：h3 侧复用本来为 **0**（实测 4 拨号 = 4 次 QUIC 握手），
根因是三处 h3 拨号函数的 `set_on_close` 里调了 `xmux_client.conn.close()` —— 池化后那是
**共享池单元**的关闭口，逐代理连接调用 = 池单元即刻报废。Go 对照：`splithttp/dialer.go:409-419`
的 `splitConn.onClose` 只做 `DoneRunning()`；`tr.Close()` 在 `dialer.go:232` 挂在 **QUIC 连接自己的**
context 上，不是代理连接。已改 `dialer.rs` 三处（`dial_h3_packet_up` / `dial_h3_stream_up` /
`dial_h3_stream_one`）为"只 `dec_open_usage()` + 发关闭信号"，并按 Go 语义重写注释；
修后 4 拨号 = **1 次握手**。

### 4.2 五维逐条断言（§1.1 规格 ↔ 落点）

| 维度 | 断言 | 落点 |
|---|---|---|
| `maxConnections` | 未达上限先新建；达上限复用、池深不再增长 | `mux.rs::tests::max_connections_grows_then_reuses` / `max_connections_encourages_new_clients`（pool_size 2→2）+ §4.1 第 2/3 行（端到端） |
| `maxConcurrency` | `Running < N` 才算候选，超限新建 | `mux.rs::tests::max_concurrency_triggers_new_client_when_full` |
| `cMaxReuseTimes` | `leftUsage = N-1`，耗尽即淘汰 | `mux.rs::tests::c_max_reuse_times_evicts_after_exhaustion` |
| `hMaxRequestTimes` | `LeftRequests = N`，逐请求扣减至 0 即淘汰 | `mux.rs::tests::h_max_request_times_evicts_after_requests_exhausted` + §4.1 第 5 行（生产路径扣减） |
| `hMaxReusableSecs` | `UnreusableAt = now + N s`，到期淘汰 | `mux.rs::tests::h_max_reusable_secs_evicts_after_expiry` |

### 4.3 缺省行为不变式

- 缺省（用户不写 `xmux`）与 Go 一致地**套预设**：`maxConnections {3,3}` / `hMaxRequestTimes {600,900}` /
  `hMaxReusableSecs {1800,3000}`（`register.rs` 解析分支 + 既有单测 `parse_xmux_default_preset_when_missing`
  / `parse_xmux_empty_object_applies_preset` / `parse_xmux_explicit_value_passes_through`）。
- 协议面不变：session id 仍逐拨号生成；请求/响应字节序列未改（池化只影响底层连接复用）。
  `mock_server` / `stream_h2` / `mock_h3_server` / `hub_limits` / `reality_integration` 全套既有集成
  测试绿 = 接线前后行为等价（数字见 §6 门禁）。

### 4.4 反证

绕过池（`h2_bypass_pool_control`，每次现建 client = 接线前形态）⇒ 连接数 10 = 2×拨号数，
锚变红条件成立（断言 `accepts >= DIALS` 与之对照的池化用例 `accepts < 2×DIALS` 互斥）。
第二反证：`hMaxRequestTimes=1`（每拨号必换 client）⇒ 10，与无池齐平。

### 4.5 配置兼容缺口（本票发现并修复）

Go `infra/conf/common.go` 的 `Int32Range.UnmarshalJSON` **只认两种形态**：字符串 `"1-2"` / `"7"`，
或裸整数 `7`；`{from,to}` 对象在 Go 侧是**硬错**
（`Invalid integer range, expected either string of form "1-2" or plain integer.`）。
Rust 的 `register.rs::parse_range` 修前只认对象/裸整数 ⇒ 用户按 Go 文档写的 xmux 范围
（`"maxConnections": "3"`、`"hMaxRequestTimes": "600-900"`）被 **`and_then(parse_range)` 静默丢弃**
（等于没配，落回缺省预设）。已在 `parse_range` 补 Go 的字符串形态（单值 / `a-b`），并保留对象形态作
Rust 侧**宽松超集**（既有测试与内部用例依赖；反向不兼容是 Go 侧**报错**而非静默漂移）。
单测：`parse_range_from_go_string_forms` / `parse_xmux_go_string_forms_reach_fields`。

矩阵的 xmux 维度即用 Go 合法形态（`"3"` / `"1"`）跑三方向——修前 Go 客户端会因该形态报错
（首次矩阵跑出 `Failed to start: … Invalid integer range`，#26/#27 即此因）。

### 4.6 压测 / 进程级矩阵（`wave7_h3_matrix.py --dl --xmux`）

脚本内 xmux 维度已按同一锚重写：客户端出站目标前插 TCP 转发器，`tcp_conns` = 客户端为这些
代理连接实际打开的 TCP 数（**不能**用服务端 access log 计数——splithttp 的 access 行是入站
**会话**数，TCP 复用时仍是 N 行，测不到底层复用）。用例 = pool（maxConnections 3）vs
no-reuse（hMaxRequestTimes 1）三方向对照，同时输出吞吐。

（矩阵结果见 §6）

## 5. 残余风险与未做

### 5.1 h2 侧"每拨号仍常见新增 1 条 TCP"——成因未定，登记待查

**现象**：同一 `DefaultDialerClient`、`pool_size=1`、`is_closed=false`、服务端连接全部保持打开，
但每次新拨号仍新增一条 TCP（单测 6~8 条 / 5 拨号；进程级矩阵 Rust 客户端 13 条 / 10 连接，
同配置 Go 客户端只有 3 条 = 精确封顶 maxConnections=3）。
反证（§6.3 四组诊断）：同一 `DefaultDialerClient` 在连接**保持**时 5 拨号仅 2 条 TCP、10 个请求
全多路复用（hyper-util 的 h2 多路复用本身正常）；把下载流读到 EOF 再关与只读 2 字节就关同为 8 条
（**不是**"中止 GET"）；顺序拨号时池内 client 指针不变、`is_closed=false`、`pool_size=1`
（**不是** xmux 淘汰）；服务端 `serve_connection` 存活计数与 accept 数同步增长（**不是**服务端关的）。
⇒ 责任面收窄到 hyper-util legacy client 的 h2 池"上一拨号全部 stream 结束后不再复用该连接"。
**本票不修**（属第三方客户端池行为，需专门票：可能要绕过 legacy client 的池语义，见 `dialer.rs`
stream-one 已有的手写 h2 通路），建议单开票并附本节四组诊断。

> **【闭案注记，lf51l 2026-11-01】** 主因已找到并删除：就是 `register.rs` 在 xmux 池查找前的
> **RTT 探针**（`resolve_rtt` 一次性 TCP，每拨号一条）——它当时藏在"每拨号新增 1 条"里，四组
> 诊断都没往"接线路径上还有一条额外连接"上查。删除后（Wave7Rtt.md）：maxConnections=1 下
> 5 拨号 **1 条 TCP**（修前 6），default 下 **3 条**（修前 8），矩阵 Rust 客户端 10 连接
> **3 条**（修前 13），与 Go 完全同形。上文"hyper-util 池不复用"的收窄结论作废——锚没测错，
> 是锚测的对象里混进了探针连接。

### 5.2 其他

- **池 key 用内容而非指针身份**（`xmux_manager_key`）：两个配置内容完全相同的 outbound 会共用一个
  manager ⇒ 共享底层连接（Go 按 `*MemoryStreamConfig` 指针身份，每 outbound 一个 manager）。影响面：
  传输层在路由层之下（路由在拨号前已定），共享的只是同目标的底层连接；不同 dest / security /
  协议配置必然分池。
- **h3 侧只跑了 loopback Rust→Rust**（QUIC 直连计数型 mock server）：Go↔Rust 的 h3 xmux 行为差异
  （Go 侧 `http3.Transport` 池化形态）**未验证**；矩阵 `--xmux` 维度走 h2（packet-up），h3 的复用
  证据只来自单元集成测试（§4.1 末行）。
- **`LazyH3Conn` 握手失败后的重试**：`get()` 用 `tokio::sync::OnceCell::get_or_try_init`——错误不落
  缓存，失败后 `peek()` 仍为 `None`，下次 `get()` 重新握手（[INFERENCE]：源码 + OnceCell 语义，未加
  "先失败后成功"的专门测试——构造该 QUIC 端点成本高）。
- **空闲 QUIC 连接的回收改由 quinn idle timeout + 池淘汰负责**：不再逐连接 `close()`，代理连接结束
  后 UDP socket 要等连接 idle（默认 30s 量级）或池淘汰才释放。`is_closed()` 会把已死 conn 的池单元
  立即淘汰，不会误用；但 bd s12 那种"逐连接立即释放 fd"的强语义不再成立（池化的固有代价，与 Go 一致）。
- **h3 + `host` 含端口**（如 `"example.com:8443"`）当前直接硬错
  `splithttp H3 dial failed: … invalid server name: example.com:8443`——`server_name` 直接进 quinn。
  属**既有行为**（接线前同款代码），非本票引入；Go 侧 `requestURL.Host` 去端口。登记待票。
- **未做**：长稳压测下的连接数/内存曲线（只做 10 连接短程对比）；未跑 32/32 全量互通矩阵（本票只改
  传输层拨号与配置解析，全量门禁由 PM 侧统一跑）。

## 6. 门禁（本轮实测）

| 门禁 | 命令 | 结果 |
|---|---|---|
| 单 crate 全目标测试 | `cargo test -p xray-transport-splithttp --all-targets` | **301 passed / 0 failed**（lib 275 + `hub_limits` 4 + `mock_h3_server` 1 + `mock_server` 12 + `reality_integration` 1 + `stream_h2` 2 + `xmux_reuse` 6） |
| clippy | `cargo clippy -p xray-transport-splithttp --all-targets -- -D warnings` | 零告警（`Finished`，无 `^error`） |
| fmt | `cargo fmt -p xray-transport-splithttp -- --check` | 0 diff |
| 互通矩阵（含 `--dl`） | `python reports/…/scripts/wave7_h3_matrix.py --rust <release> --go D:/tmp/go2617/xray.exe --dl --xmux` | **30/30 PASS**（18 模式×方向 + 3 `--dl` + 6 xmux + 3 xmux 对照）——21 基线**零退化** |

### 6.1 矩阵 xmux 维度原始输出（连接复用 vs 反证）

```
[PASS] #22 Rust->Rust pool       conns=10 tcp_conns=13 bytes=655360 wall=0.55s thr=1.1MB/s
[PASS] #23 Rust->Rust no-reuse   conns=10 tcp_conns=20 bytes=655360 wall=0.55s thr=1.1MB/s
[PASS] xmux-cmp  Rust->Rust pool_tcp_conns=13 < no-reuse_tcp_conns=20 => 复用
[PASS] #24 Rust->Go  pool       conns=10 tcp_conns=13 bytes=655360 wall=0.72s thr=0.9MB/s
[PASS] #25 Rust->Go  no-reuse   conns=10 tcp_conns=20 bytes=655360 wall=0.59s thr=1.1MB/s
[PASS] xmux-cmp  Rust->Go  pool_tcp_conns=13 < no-reuse_tcp_conns=20 => 复用
[PASS] #26 Go->Rust  pool       conns=10 tcp_conns=3  bytes=655360 wall=0.66s thr=1.0MB/s
[PASS] #27 Go->Rust  no-reuse   conns=10 tcp_conns=12 bytes=655360 wall=1.59s thr=0.4MB/s
[PASS] xmux-cmp  Go->Rust  pool_tcp_conns=3 < no-reuse_tcp_conns=12 => 复用
```

读法：客户端侧 TCP 连接数（转发器计数）。`no-reuse` = `hMaxRequestTimes "1"` 控制组（每拨号必换 client）。
**Rust 客户端 10 连接 → 13 条 TCP；Go 客户端同配置 → 3 条**（Go 精确封顶 maxConnections=3）。
⇒ 复用已生效但弱于 Go，差距定位见 §5.1。

### 6.2 单测锚原始输出（`--test xmux_reuse --nocapture`）

```
[h2 bypass pool]      dials=5 accepts=10
[h2 default xmux]     dials=5 accepts=8 gets=5 posts=5
[h2 maxConnections=1] dials=5 accepts=6
[h2 sequential close] dials=5 accepts=8
[h2 hMaxRequestTimes] dials=5 budget=100 accepts=6 budget=1 accepts=10
[h3 maxConnections=1] dials=4 accepts=1 gets=4 posts=4
```

### 6.3 诊断实验（结论已写入 §5.1，脚本/诊断代码未留档）

| 实验 | 观察 |
|---|---|
| 同一 client 连拨 5 次、连接**保持** | 2 条 TCP / 10 请求 → 多路复用正常 |
| 下载流读到 EOF 再关 vs 只读 2 字节就关 | 8 vs 8 → **不是**"中止 GET"导致的 |
| 顺序拨号时打印池内 client 指针/状态 | 指针不变、`is_closed=false`、`pool_size=1` → **不是** xmux 淘汰 |
| 服务端 `serve_connection` 存活计数 | 服务端连接**全部保持打开**（accepts=N 时 server_open=N）→ 不是服务端关的 |

⇒ 责任面收窄到 **hyper-util legacy client 的 h2 池在"上一拨号全部 stream 结束、连接回到池"后
不再复用它**。属客户端库行为，非本票接线缺陷，单开票。

---
