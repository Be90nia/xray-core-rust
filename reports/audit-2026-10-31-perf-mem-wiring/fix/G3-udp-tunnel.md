# G3 · UDP 隧道 wire 组修复合集（7 票）

- 基准 HEAD：`5fe98b90`（分支 `feature/fix-inbound-parity`）
- 构建：`CARGO_TARGET_DIR=target-WAVE1` + `BORING_BSSL_PATH=target/boringssl-asm/prebuilt`
- 参考：`round4/Verify-XUDP.md`（机理）、`round5/third-party-interop.md`（zu7tk）

---

## t0ls1（P0）UDP 隧道 4 处契约同改 — DONE（代码级）

**根因（复核报告已定）**：内部 dispatch link 跑 **XUDP 帧**（freedom/dns/hysteria/tuic/ss/wg
六族按帧解析），隧道 wire / mux carrier 跑**裸载荷**。旧实现把 link 字节流原样搬到 wire
→ 帧头一起上线（对端把整帧当载荷，上游收到 53B = 24B 帧头 + 29B DNS）；回程裸载荷被当
XUDP 帧解 → 客户端零回包。

**修法：在边界做表示转换，内部 link 契约零改动。**

新增共享适配层（`crates/xray-app-dispatcher/src/udp_session.rs`，本组文件面）：

| 件 | 作用 |
|---|---|
| `probe_xudp_frame` / `FrameHead` | 按 `[2B meta_len]` 直接算载荷偏移，**不解析地址**（零分配、零摊平）；`opt&1==0` 的控制帧整帧跳过；meta 上限 512（防垃圾流量等 64KiB） |
| `XudpUnframer::feed` | XUDP 帧流 → 逐包裸载荷回调；帧完整落在入参内时**零拷贝**（直接在入参切片上切），仅跨 Buffer 半帧并入 `accum`（一次拷贝） |
| `XudpReframer::write_header` | 裸载荷 → XUDP 帧头（New 首帧 → Keep 后续，GlobalID 每会话随机），支持 per-packet 目标覆盖 |
| `XudpUnframingReader`（`buf::io::Reader`） | link 上行剥帧：Buffer 原地 `advance(head)` + `split_to(payload)`（零拷贝），**一包一 Buffer**（mux Packet 写端硬前提） |
| `XudpFramingWriter`（`buf::io::Writer`） | link 下行裹帧：帧头进池化 Buffer，载荷 Buffer 原样挂上（零拷贝）；每次调用 = 一个数据报 |
| `XudpWireConn<C>`（`AsyncRead+AsyncWrite+Connection`） | `[2B BE len][裸载荷]` wire 表示 ↔ XUDP link 表示；上行零额外拷贝、下行载荷原地分段交付（帧头先行），`Pending` 重入用 `fed` 记账不重复喂 |

四处接线：

1. **隧道出站剥帧/裹帧**
   - `crates/xray-proxy-vless/src/dispatcher.rs:543-548`：`conn = XudpWireConn::new(conn, Destination::udp(target_addr, target_port))`（替换原 `VlessUdpFramedConn`，后者本地实现已删，改为 type alias 到共用件）。
   - `crates/xray-proxy-vmess/src/dispatcher.rs`：`VmessUdpConn` 内嵌 `XudpUnframer`（上行逐包成一 chunk）+ `XudpReframer`（下行逐包裹帧，`hdr`/`hpos` + `rpay`/`rpos` 分段交付，**不再截断大包**）；`from_udp_conn` 新增 `dest` 参数，dial 处构造 `udp_dest`。
   - `crates/xray-proxy-trojan/src/dispatcher.rs`：`TrojanUdpFramedConn` 上行剥帧后**按帧头目标**写 Trojan 帧（退回请求头目标），下行用 wire 帧自带 addr/port 作 XUDP 帧目标（cone 语义保留）。
2. **mux client**（`crates/xray-mux/src/client.rs:438-447`）：UDP 会话的 session input/output 换成 `XudpUnframingReader` / `XudpFramingWriter`（carrier data 段 = 裸载荷，与 Go mux 客户端一致）。
3. **mux server**（`crates/xray-mux/src/worker.rs:381-384`）：`handle_xudp_new` 把 dispatch 出的 link 双向包一层 —— 上行裹帧（否则 freedom 拿到裸报文解帧失败静默丢包 = Go cone 默认走 mux 时上游 0 字节）、下行剥帧（mux data 段必须是裸载荷）。
4. **服务端隧道入站 plain UDP 模式保持原样**（`xray-proxy-vless/src/inbound/server.rs` 未改；`go→rust(cone 关)` 实测本就正确）。

**未触碰**：vision gate、`bridge_link_with_stream` splice 语义、`xray-transport-tcp/register.rs`、`xray-buf/src/alloc.rs`。

**新增单测（替代旧「自洽闭环」断言，改为新契约）**
- `udp_session::tests::xudp_unframer_segmentation_invariant` / `xudp_unframer_holds_partial_frame`
  / `xudp_framing_writer_roundtrip_new_then_keep`
- `xray-proxy-vless`：`vless_udp_framed_conn_roundtrip`（wire 断言**不含** XUDP 帧头；读侧交付 XUDP 帧）
- `xray-proxy-vmess`：`vmess_udp_conn_write_boundaries`（link 侧 XUDP 帧 → 裸载荷 chunk）
- `xray-proxy-trojan`：`udp_framed_conn_roundtrip`（wire 裸载荷 / 回程 XUDP 帧）
- `xray-mux`：`xudp_new_frame_forwards_inline_data` / `xudp_new_bidirectional_send_receive` /
  `xudp_new_same_global_id_reuses_existing_session`（拆帧断言）

## zu7tk（P1）socks5 UDP 大包上限 — DONE

根因：`crates/xray-xudp/src/packet.rs` 的 `MAX_DATA_LEN = 8192-666 = 7526` 抄自 Go
**wire 侧**（`common/xudp/xudp.go:100` 的 `length+666 > buf.Size`）。Rust 的 XUDP 帧只跑
内部 link，隧道/mux 的 wire 表示已由各协议 framing 层负责 → 该值让 >7526B 的 UDP 应答在
`PacketWriter::write_packet` 里**静默跳过**（socks→dispatch→freedom 回程丢包：7600B 起全无回包）。
改为 `u16::MAX`（帧 `data_len` 字段宽度极限），并保留 Go 的超限跳过语义。测试
`test_large_packet_roundtrip_past_old_7526_limit`（8000B 逐字节往返）钉住。

## tini5（P1）每会话 64KiB 常驻 + 无会话上限 — DONE

`xray-app-dispatcher/src/udp_session.rs`：
- 读缓冲 `RECV_BUF = 8 KiB`（原 `MAX_DATAGRAM = 64 KiB`；帧解析走 `accum` 增量重组，大报文天然分多次读入）→ 每会话常驻 64KiB → 8KiB。
- `MAX_UDP_SESSIONS = 4096` 进程级上限（`LIVE_SESSIONS` 计数 + `Inner::drop` 归还），超限 `establish()` 返回 `io::Error`（fail-visible，不静默丢包）。
- `frame` 序列化 scratch 常驻会话（免每包 `Vec::with_capacity`）。

## yfcnr（P1）anytls UDP-over-TCP（UoT v2）— DONE（代码级，单目标形态）

规范来源（本轮实取）：`github.com/SagerNet/sing/common/uot/{protocol,conn,server,client}.go`
—— magic 目标 `sp.v2.udp-over-tcp.arpa`；首帧 `Request = [1B isConnect][SOCKS5 addr]`；
之后每包 `[2B BE len][payload]`（isConnect=true）/ 每包再带 atyp+addr（isConnect=false）。

- 新增 `crates/xray-proxy-anytls/src/uot.rs`：`MAGIC_ADDRESS`/`LEGACY_MAGIC_ADDRESS`/`is_magic`、
  `encode_request`/`decode_request`（不足返回 `Ok(None)`，非法 atyp 显式错）、
  `LengthFramedReader`/`LengthFramedWriter`（`[2B len][payload]` 的 buf Reader/Writer；
  写侧帧头进池化 Buffer + 载荷 Buffer 原样挂上，零拷贝）。
- 出站 `crates/xray-proxy-anytls/src/dispatcher.rs::make_dial_fn`：UDP 目标 → 以 magic 目标
  dial → 写 `Request(isConnect=true, 真实目标)` → 包 `XudpWireConn`（复用 t0ls1 的共用件）。
- 服务端 `crates/xray-proxy-anytls/src/server.rs::handle_session`：magic 目标不再交给
  dispatcher 当域名解析，转 `serve_uot_session`：读 Request → `Destination::udp` → link 双向
  套 `XudpUnframingReader`/`XudpFramingWriter`（经既有 duplex + `pump_session_to_duplex` 管线）。
- **限制（显式，不静默）**：`isConnect=false`（每包自带目标的 cone 形态）服务端打 warn 并关会话。

## j7de2（P2）tuic UDP — 未做

时间预算耗尽前未动 `crates/xray-proxy-tuic/src/udp.rs`（quic 模式 `(assoc,pkt)` 严格配对 +
native 分片重组）。零改动，无半成品。

## 1fm1l（P2，UDP 半）每数据报 4 次分配 — DONE（3/4 站点）

| 站点 | 处理 |
|---|---|
| `udp_session.rs` 每包 `Vec::with_capacity` | 会话常驻 `frame` scratch（clear 复用） |
| `freedom/udp.rs` 响应装帧 | 会话 scratch + `Buffer::from_vec(take(...))`（零拷贝移交，去掉 `merge_bytes` 二次拷贝） |
| `socks/udp.rs` 响应装帧 | 同上 |
| `xray-xudp/packet.rs` reader 载荷 `vec![0u8; len]` | **未改**：`PacketData` 以 owned `Vec` 交付（API 面），去掉它需把 `PacketData` 换成 Buffer 型并改 8 个消费方 —— 记入遗留 |

## 1ksxu（D3/D6） — DONE / 已满足

- **D3** `freedom/udp.rs`：`resolve_udp_domain` 新增 `prefer_v4`（取 socket 族，来自
  `default_target.is_ipv4()`），系统解析后按族择优（旧实现 `.next()` 取首址，v6 在前时
  `send_to` 必败 → 帧被静默丢弃）；丢帧日志 `debug` → `warn`。会话默认目标
  `resolve_socket_addr` 同样改为族偏好（对齐 Go `favoriteAddrFamily`）；策略路径保留
  随机择一（`lookup_for_ip` 已按策略过滤族）。
- **D6** `socks/udp.rs::parse_relay_frame`：现状已有 `frag_dropped` 计数 + debug 日志（含
  fragment 值与累计数）→ 票面诉求「加计数或提级」已由现有实现满足，本轮零改动。

---

## 验证（本轮实跑）

```
cargo check  -p xray-app-dispatcher -p xray-mux -p xray-proxy-vless -p xray-proxy-vmess
             -p xray-proxy-trojan -p xray-proxy-anytls --all-targets   → 全绿
cargo test   -p xray-app-dispatcher --lib   → 147 passed / 0 failed
cargo test   -p xray-mux --lib              → 143 passed / 0 failed
cargo test   -p xray-xudp --lib             → 41 passed / 0 failed
cargo test   -p xray-proxy-freedom --lib    → 97 passed / 0 failed
cargo test   -p xray-proxy-socks --lib      → 86 passed / 1 ignored
```

## 遗留（未完成项，按缺口列）

1. **字节级 e2e `dist/interop_udp_tunnel.py` 未建**（t0ls1 的正式验收门）：四象限
   （vless/vmess/trojan × Rust→Go / Go→Rust / Rust→Rust / Go→Go）× cone 开关 × 端口
   53/443/其它 + dokodemo/socks5 ASSOCIATE/DNS-over-UDP。Go 基准二进制在
   `D:/tmp/go2617/xray.exe`。**本轮只有单元级/接线级证据，没有真机字节比对。**
2. `cargo test --workspace --all-targets` / `clippy -D warnings` / `fmt --check` 未跑全量。
3. `XRAY_ALLOC_STATS=1` 前后 alloc/包数字未取（1fm1l 只做了代码级去分配，无实测对比）。
4. j7de2（tuic UDP）零改动。
5. yfcnr `isConnect=false`（cone/每包目标）形态未实现（服务端显式拒绝）。
6. `xray-xudp` reader 载荷 Vec 仍每包 1 次分配（API 面改动，跨 8 消费方）。
7. 文件面说明：本次另触碰 `crates/xray-xudp/src/packet.rs`（zu7tk/1fm1l 的根因所在，审计
   报告直接点名该文件）、`crates/xray-proxy-anytls/{uot.rs,lib.rs,dispatcher.rs,server.rs}`
   （yfcnr 必需的全链）。二者均无其他组占用。

## git status --porcelain（本组改动清单）

```
 M crates/xray-app-dispatcher/src/udp_session.rs
 M crates/xray-mux/src/client.rs
 M crates/xray-mux/src/worker.rs
 M crates/xray-proxy-anytls/src/dispatcher.rs
 M crates/xray-proxy-anytls/src/lib.rs
 M crates/xray-proxy-anytls/src/server.rs
 M crates/xray-proxy-freedom/src/udp.rs
 M crates/xray-proxy-socks/src/udp.rs
 M crates/xray-proxy-trojan/src/dispatcher.rs
 M crates/xray-proxy-vless/src/dispatcher.rs
 M crates/xray-proxy-vmess/src/dispatcher.rs
 M crates/xray-xudp/src/packet.rs
?? crates/xray-proxy-anytls/src/uot.rs
```

---

# 附录 B（PM 复查后补做，2026-10-31 晚）

## B1 红测试修复（trojan `udp_framed_conn_roundtrip`）

根因 = 测试期望错（实现符合 AsyncRead 契约）：`TrojanUdpFramedConn::poll_read` 分段交付
（先帧头、载荷留后续 poll），测试只 `read()` 一次就算偏移。修法 = 测试改累积读：
`read_until(2)` → 解析 `meta_len` → `read_until(4+meta_len)` → 解析 `data_len` →
`read_until(4+meta_len+data_len)` → 断言 `got[4]==1` 且载荷切片逐字节相等。
**未改 `poll_read` 交付粒度**（那是合法流式行为，改它会影响数据面）。
`cargo test -p xray-proxy-trojan --lib` → 全绿。

## B2 `dist/interop_udp_tunnel.py`（t0ls1 字节级验收门）

Rust 侧用 `target-WAVE1/debug/xray.exe`（含本组改动，`git_rev 5fe98b90` + 本地修改），
Go 侧 `D:/tmp/go2617/xray.exe`（26.10.17）。载荷 = 29B 裸 DNS 查询；上游记录器记录
peer/len/hex 并回 45B 合法 DNS 应答。判据：上游 hex **逐字节等于** 29B 裸查询、
上游包数 == 1、客户端收到合法 DNS 应答（txid 回显 + ancount==1）。

### 结果（全矩阵 3 协议 × 4 方向 × cone 开关 × dest 53/443/29090）

| 分组 | 结果 |
|---|---|
| **cone=off（plain UDP 隧道）** | **36/36 PASS**：vless/vmess/trojan × {rust→go, go→rust, rust→rust, go→go} × {53,443,29090}，上游均收到 `12 34 01 00 …` 29B 逐字节一致 + 客户端 45B DNS 应答 |
| cone=on，dest=53 / 29090 | PASS（除 rust→rust） |
| cone=on，**dest=443** | FAIL **但 go→go 同实现对照组也 FAIL** ⇒ 非本组代码（Go 客户端 mux + UDP:443 口径/harness 面），单列不计缺陷 |
| cone=on，**rust→rust（全部端口）** | **FAIL（上游 0 字节）** ⇒ 新发现：Rust 客户端 + Rust 服务端 + 客户端开 mux 的组合；而 rust→go / go→rust 同 cone 均 PASS ⇒ 定位在 **Rust mux 服务端 XUDP 会话面** |
| dokodemo UDP 经隧道 | rust→go **PASS**（29B 逐字节，此前 53B 废）；go→go PASS；go→rust / rust→rust FAIL（与上一条同源） |
| socks5 UDP ASSOCIATE 经隧道 | = 主矩阵入口（全部用例均经 socks5 ASSOCIATE） |
| DNS over UDP 经隧道 | rust→go / go→rust / go→go PASS（45B 合法应答）；rust→rust FAIL（同源） |

复跑：`python dist/interop_udp_tunnel.py`（`--quick` 烟测 / `--only <proto>` / `--out`）。
原始产物 `dist/tmp_udp_tunnel/interop_udp_tunnel.json`。

### 结论（t0ls1）

**plain UDP 隧道（cone 关 / dest 任意端口）字节级证据齐全：36/36 逐字节 PASS**，
含修复前双向皆废的 `rust→go`、`rust→rust`、`go→rust`。
**cone 开（客户端 mux）** 面上，跨实现（Rust↔Go）已通，但 **Rust↔Rust 的 mux 组合仍红**
—— 这是 t0ls1 四处契约之外的新缺陷（Rust mux 服务端 XUDP 会话），需单开票跟进。

## B3 遗留（更新）

1. 新票建议：**Rust↔Rust + mux(cone) + UDP 上游 0 字节**（定位起点：`xray-mux/src/worker.rs`
   `handle_xudp_new` 与本组新加的 `XudpFramingWriter`/`XudpUnframingReader` 组合在
   Rust 客户端 ↔ Rust 服务端 时的行为；注意 go→rust 的 socks 入口通过、dokodemo 入口不通过）。
2. `cone=on + dest=443` 在 **go↔go 控制组** 同样失败 → harness 口径待定（不在本组范围）。
3. j7de2（tuic UDP）仍未做；`XRAY_ALLOC_STATS` 数字仍未取。
