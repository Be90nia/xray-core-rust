VERDICT: PASS（F3 第三方互通修复：quic 模式配对键由 (assoc,pkt) 改为 assoc（spec：PKT_ID 是分片重组 ID）；
F4 修两处：server 响应侧按 spec 分片 + `Address::None` 线契约修正为 1 字节（第三方解析错位根因）；
Rust↔Rust 1200/1500/4000/20000B 逐字节全绿；与真第三方 sing-box 1.14.4 四组合全 PASS）

# j7de2 — TUIC UDP：quic 模式配对键错 + native 大报静默丢

分支 feature/fix-inbound-parity｜改动仅 `crates/xray-proxy-tuic/**`（udp.rs / server.rs /
client.rs / protocol/packet.rs / protocol/address.rs + 新增 `tests/third_party_udp.rs`）

## 0. 第三方对端获取方式（本票要求的明确项）

**方式 = 票面第 2 条「只读 scp 拷贝」**（GitHub 下载在 WSL 内极不稳定，改走 scp）：

```text
$ scp -P 26617 root@176.122.139.45:/root/agsbx/sing-box 'D:\tmp\sing-box-tp'
Transferred: received 81502332 bytes, in 84.7 seconds
$ wsl -d ubuntu-xray -- cp /mnt/d/tmp/sing-box-tp /root/tp/sing-box
$ /root/tp/sing-box version
sing-box version 1.14.4        (Environment: go1.26.10 linux/amd64)
```

生产机（176.122.139.45）**只做只读拷贝**，未在其上运行任何测试、未改任何文件 ✔。
对端在 WSL 内起：`sing-box`（TUIC v5 入站 + UDP echo）——编排脚本入库：
`reports/audit-2026-10-31-perf-mem-wiring/fix/tuic_third_party.sh`。

踩坑两则（已写进脚本注释）：
- 该 sing-box 构建的 TUIC 入站**必须显式配 `tls.alpn`**（缺省无 ALPN → 客户端握手报
  `no_application_protocol`）；配 `["tuic","h3"]` 后通。
- `sing-box generate tls-keypair` 把 key+cert 一起打到 stdout，需按 PEM 块拆分。

---

# F3 — quic 模式与第三方零互通（`unmatched udp resp`）

## F3.1 复现

修前客户端把响应按 **`(assoc_id, pkt_id)` 严格配对**（`UniRespRouter` 的 waiters 表 key）。
第三方（sing-box）回包时用**自己的** PKT_ID 编号（不回显请求的）→ 配对全部落空：

```text
# 修前（本仓 router 临时还原 (assoc,pkt) 配对）+ 真第三方 sing-box：
thread 'tuic_udp_third_party_roundtrip' panicked at third_party_udp.rs:139:18:
third-party quic-mode send_recv failed: UdpTimeout(10s)
test result: FAILED. 0 passed; 1 failed
```

## F3.2 规范依据

TUIC v5 `SPEC.md`（tuic-protocol/tuic，权威）：

> `PKT_ID` - UDP packet ID. See [UDP relaying]
> A UDP packet can be fragmented into multiple `Packet` commands. Field `PKT_ID`,
> `FRAG_TOTAL` and `FRAG_ID` are used to **identify and reassemble the fragmented
> UDP packets**.

即 **PKT_ID 是「UDP 包 ID」，用途是分片重组，不是请求-响应配对键**；spec 全文没有
「server 必须回显请求 PKT_ID」的约束（server 回包自带编号即可）。第三方 sing-box
（`sing-quic/tuic`，`udpPacketConn.WritePacket` 用 `packetId.Add(1)` 自增）正是如此。

## F3.3 修法

`UniRespRouter` 的等待表由 `HashMap<(u16,u16), Sender>` 改为
`HashMap<u16 /*assoc_id*/, VecDeque<Slot>>`：

- 响应按 **assoc_id（UDP 会话）** 归属，按**到达顺序 FIFO** 交付给该会话当前等待者；
- 槽位用 `Arc<Mutex<Option<Sender>>>`：超时后把本槽清空（sender drop → rx 断），
  后续响应跳过该槽，**不会错投**给已超时的请求；
- 交付时 `tx.send()` 失败（rx 已 drop）→ 继续取下一个槽。

## F3.4 反证

修后（assoc 级 FIFO）+ 真第三方 sing-box 1.14.4：

```text
$ TUIC_TP_MODE=quic TUIC_TP_SIZE=32   cargo test -p xray-proxy-tuic --test third_party_udp -- --ignored
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

$ TUIC_TP_MODE=quic TUIC_TP_SIZE=20000 ... → test result: ok. 1 passed
```

第三方侧日志（同一连接，证明 UDP 真的中继到 echo）：

```text
INFO inbound/tuic[tuic-in]: inbound packet connection from 192.168.224.1:53160
INFO inbound/tuic[tuic-in]: inbound packet connection to 127.0.0.1:24999
INFO outbound/direct[0]: outbound packet connection
```

把 router 临时还原成修前 `(assoc,pkt)` 严格配对后，同一第三方对端 → `UdpTimeout(10s)`（上文 F3.1）。

## F3.5 验证

见文末「验证」节（71 lib + 19 集成用例全绿、clippy 零告警、fmt 干净）。

---

# F4 — native 大报静默丢

修前实际有**两个**独立缺陷，Rust↔Rust 与 vs 第三方各暴露一个：

## F4.1 复现 A（Rust↔Rust，server 响应侧不切分）

```text
# 修前（本仓 mock server + 本仓客户端，native 模式）：
thread 'native_datagram_large_payload_roundtrips' panicked:
native 1500B send_recv failed: UdpTimeout(10s)
test result: FAILED. 0 passed; 1 failed
```

（1200B 过、1500B 起超时——单 QUIC DATAGRAM 容量约 1183B。）

根因：`ReplySink::write_packet` 把**整个响应包塞进一个 DATAGRAM** → 超过单 datagram
容量 → quinn `send_datagram` 直接报错 → 响应被丢（客户端只等到超时）。

## F4.2 复现 B（vs 第三方，None 地址线契约错位）

修前 20000B 分片发给 sing-box → 第三方侧：

```text
ERROR inbound/tuic[tuic-in]: connection failed: handle message: decode UDP message: unexpected EOF
```

根因：**`Address::None` 的线格式多写了 2 字节端口**。本仓旧写法 `0xff` + 2B 端口占位
（3 字节），而：

- TUIC v5 SPEC：*「The port number is encoded in 2 bytes **after the Domain name / IP
  address**」*——None 既无域名也无 IP → **无端口**（1 字节）；
- 参考实现 tuic 5.0.0-pre-alpha6（crates.io `tuic` crate）：`Address::len()` →
  `None => 1`；
- 第三方 sing-box（`sing-quic/tuic` 的 `AddressSerializer`）：None 分支**只写类型字节**。

后果：第三方读分片**后续片**时，地址段多出 2 字节 → 载荷起点错位 →
`reader.Len() != dataLength` → `unexpected EOF` → **整包被丢**（即审计里
「≥1190B 起丢、对端不重组」的现象）。

## F4.3 规范依据（同上）+ 第三方实现

sing-quic/tuic 的分片与重组（`fragUDPMessage` / `udpDefragger`）：

- 片内载荷 = `maxPacketSize - headerSize`（header = 10B + 地址段）；
- 后续片地址置空（`M.Socksaddr{}` → 0xff，**1 字节**）；
- `SIZE` 字段 = **本片**载荷长度（`uint16(m.data.Len())`）；
- 接收端 `udpDefragger` 按 **packetID** 分组、`fragmentID` 归位 → 重组 ✔（sing-box
  **有**重组能力）。

## F4.4 修法

1. **server 响应侧按 spec 分片**（`ReplySink::write_packet` 的 Dgram 分支）：
   `frag_payload = max_datagram_size - (10 + addr.encoded_len())`；超限则
   `build_native_fragments`（同 pkt_id、FRAG_TOTAL、FRAG_ID 0-based、仅首片带地址）
   逐片发 DATAGRAM；帧编码走共用函数 `encode_packet_frame`（线格式单一来源）。
2. **`Address::None` 编码改为 1 字节**（`0xff`），解码同步只读类型字节
   （`protocol/address.rs` + `udp.rs::read_packet_payload` 的 0xff 分支）——两侧同改，
   Rust↔Rust 仍自洽，第三方对齐 ✔。
3. **DATAGRAM 接收缓冲 8KB → 256KB**（client/server 同值，`TUIC_DATAGRAM_RECV_BUFFER`）：
   一个 64KB UDP 载荷的分片组 ≈ 55 片 × 1200B ≈ 64KB，8KB 缓冲在突发到达时会被
   quinn **静默丢 datagram** → 对端重组永不完成 → 大包超时。
4. **分片总负载上界**改用 `MAX_UDP_PAYLOAD`（65507，UDP 数据报物理上限）；单片仍受
   `MAX_PACKET_PAYLOAD`（16KB）约束——**未放宽既有校验**（新增的是分片「总量」维度
   的界，per-frame 的 16KB 闸门原样保留）。

## F4.5 反证

```text
# 修前（本仓 mock server，native 模式）：
native 1500B send_recv failed: UdpTimeout(10s)        ← 修前红
# 修后：
native_datagram_large_payload_roundtrips ... ok        ← 1200/1500/4000/20000B 逐字节相等
```

vs 真第三方（修前 None 地址 3 字节 → `unexpected EOF` 整包丢；修后）：

```text
$ TUIC_TP_MODE=native TUIC_TP_SIZE=32    → test result: ok. 1 passed
$ TUIC_TP_MODE=native TUIC_TP_SIZE=20000 → test result: ok. 1 passed
```

第三方日志（20000B 分片被 sing-box **成功重组**并中继到 echo；回包 16384B 是 sing-box
自身 16KB buf 池上限截断，非本仓问题）：

```text
INFO inbound/tuic[tuic-in]: inbound packet connection to 127.0.0.1:24999
INFO outbound/direct[0]: outbound packet connection
```

## F4.6 验证

```text
$ cargo test -p xray-proxy-tuic --all-targets
  lib 71 passed（含新增：native 大报往返 / 分片阈值±1 / None 地址线契约）
  dispatcher_loopback 1 · domain_dial 1 · inbound_dispatch 1 · loopback 5
  plugin_contract 9 · third_party_udp 1 ignored（需外部对端）· udp_loopback 2
  → 全绿，0 failed

$ cargo clippy -p xray-proxy-tuic --all-targets -- -D warnings → Finished（零告警）
$ cargo fmt -p xray-proxy-tuic -- --check → 0
```

新增用例：
- `server::udp_assoc_tests::native_datagram_large_payload_roundtrips`：Rust↔Rust
  native 模式 1200 / 1500 / 4000 / 20000B **逐字节相等**（修前 ≥1500B 红）。
- `udp::tests::native_fragment_threshold_boundary`：分片阈值 ±1 形态（≤阈值 1 片、
  阈值+1 两片）+ 后续片地址为 None（1 字节）+ 对端重组器还原为原载荷。
- `protocol::address::tests::none_address_is_single_type_byte`：None 地址线契约
  （`[0xff]`，1 字节）。
- `tests/third_party_udp.rs`（`#[ignore]`，需外部对端）：quic/native × 32B/20000B 四组合。

## 5. 残余 / 边界

- **quic 模式单包上限仍是 16KB**（`MAX_PACKET_PAYLOAD`，per-frame 闸门未放宽）：
  >16KB 的 quic 模式请求被**显式报错**（`PacketTooLarge`，fail-visible），非静默丢；
  若要支持需给 quic 模式的读端加重组器（`FragmentAssembler` 现只在 native 路径接线）。
- **native 模式重组器是单 pkt_id 窗口**（`FragmentAssembler` 简化策略，同 hysteria
  Defragger）：同 assoc 并发多 pkt_id 的分片组会互相重置——串行请求-响应无碍。
- **第三方 sing-box 的回程按 16KB buf 池截断**：20000B 载荷对端回包只有 16384B
  （第三方侧限制）；第三方用例断言因此为「前缀一致 + 不超长」，≤16KB 时要求完整相等。
- 未动 `crates/xray-app-dispatcher/src/udp_session.rs`、`xray-proxy-freedom/src/udp.rs`、
  `xray-proxy-socks/src/udp.rs`、`xray-xudp/src/packet.rs`（上一票的零分配优化）、
  `xray-transport-splithttp/**`、`xray-app-commander/src/grpc.rs`、
  `xray-app-router/src/router.rs`、`xray-core/src/inbound.rs` ✔。
- 未 commit。

## 6. 收尾

- 构建目录 `D:/Project/Xray-core-rust/target-Wave7Tuic`（本任务独占）任务结束删除。
- 第三方对端仍在 WSL 内运行（`/root/tp/sing-box`，:24443 + echo :24999）；收工可
  `pkill -f /root/tp/sing-box`。`D:\tmp\sing-box-tp`（81MB scp 副本）可删，脚本会
  按需重新拷贝/下载。
