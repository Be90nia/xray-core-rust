VERDICT: PASS（UDP **请求方向**解析不再落中间 Vec：framing 级 2.00 → 0.00 分配/包，
freedom pump 级（真 UdpSocket）2.00 → 0.00/包；dispatcher 收包内层 2 → 1（余 1 为
`recv_packet` 返回拥有型 `Vec` 的 API 契约成本，登记在案）。四 crate 423 用例全绿
（1 ignored）+ clippy 零告警 + fmt 0 diff；wire 互通 32/32 PASS（本机干净单跑，无端口竞态））

# lppdz W7 — UDP 请求方向 slice-parse（每帧 2 分配 + 2 拷贝 → 0/0）

分支 feature/fix-inbound-parity｜改动面：`crates/xray-xudp/src/packet.rs`（借用式解析
API + 语义对照测试）、`crates/xray-app-dispatcher/src/udp_session.rs`（`recv_packet`）、
`crates/xray-proxy-freedom/src/udp.rs`（`parse_and_send`）、
`crates/xray-proxy-socks/src/udp.rs`（`pump_request`）。
前序：1fm1l W5 的响应方向写入已归零（`fix/Wave7Udp.md` §6 把请求方向留给了本票）。

## 1. 现状与根因

请求方向三个调用面原来都用 `PacketReader`（泛型 `R: Read`）过 `Cursor::new(&accum[..])`：

| 站点 | 旧形态 | 每帧分配 |
|---|---|---|
| `udp_session.rs::recv_packet` | `Cursor` + `PacketReader::read_packet` → `PacketData` | 2（reader scratch `Vec` + 载荷 `vec![0u8; len]`）+ 2 拷贝 |
| `freedom udp.rs::parse_and_send` | 同上 → `into_parts()`（owned `(Vec<u8>, target)`） | 2 + 2 拷贝 |
| `socks udp.rs::pump_request` | 同上 | 2 + 2 拷贝 |

根因不是「算法慢」而是**所有权**：`accum` 已经是连续的，`PacketReader` 却仍按「流」
处理——先 `read_exact` 进 scratch `Vec` 再 `from_bytes`，载荷再 `vec![0u8; len]` 拷一遍。

## 2. 新 API 契约（借用语义 + 与写侧对称）

`crates/xray-xudp/src/packet.rs`：

```rust
pub struct SlicePacket<'a> { pub target: Option<Destination>, pub data: &'a [u8], pub consumed: usize }
pub fn parse_packet_slice(buf: &[u8]) -> Result<Option<SlicePacket<'_>>, PacketError>;
pub fn parse_packet_slice_at(buf: &[u8]) -> (Result<Option<SlicePacket<'_>>, PacketError>, usize);
```

- **借用**：`data` 直接切片入参缓冲 → 0 分配 0 拷贝；调用方在 `data` 存活期不得改缓冲
  （三个调用面都把 `accum.drain(..consumed)` 放到载荷最后一次使用之后）。
- **对称**：写侧 `FrameMetadata::write_into_buffer`（直写调用方 `Buffer`）↔ 读侧本 API
  （直读调用方切片）。两侧都是「调用方缓冲即工作区」，无中间件。
- **错误路径也返回 consumed**：调用方按它清理坏帧（否则同一字节上反复 Err = qyn8 忙旋）。
- `_at` 版本是**唯一实现**，`parse_packet_slice` 只是 `.0`——不存在两份解析逻辑。

## 3. 三调用面改造

1. `udp_session.rs::recv_packet`（:156-200）：`Cursor + PacketReader` →
   `parse_packet_slice_at`。半帧（`Io/UnexpectedEof`）→ 等更多字节；其它 Err →
   `drain(consumed.min(len))` 后返回 `InvalidData`（qyn8 语义原样保留）；
   `Ok(None)` → 继续等（与旧代码 `Ok(None) => {}` 注释「帧不完整，等更多数据」同义）。
2. `freedom udp.rs::parse_and_send`（:367-460）：载荷改成借用切片，`sock.send_to(data, …)`
   直接发；override / 域名解析 / finalRule / noises 逐包语义一行未动；
   四条提前返回分支各自 drain（借用在该路径上已死，NLL 允许）。
3. `socks udp.rs::pump_request`（:325-352）：载荷借用 → `encode_udp_packet(&dest, data)`
   → `relay.send` → 最后一次使用后 drain。

三处都保留了「清理已消费字节必须在最后一次使用载荷之后」的注释——这是借用改法唯一
的坑，写下来防后人挪错行。

## 4. 错误语义对照（未放宽校验）

`slice_parse_error_semantics_match_stream_reader` 在同一段字节上**同时**跑新旧两条
路径，逐条比较「分类 + consumed」（不只是断言新路径长相）：

| 用例 | 旧（PacketReader） | 新（slice_at） | consumed 一致？ |
|---|---|---|---|
| 完整数据帧 | `Data` | `Data` | 是（= 帧长） |
| 长度头声明 32B meta、实到 0B | `Io(UnexpectedEof)` | `Io(UnexpectedEof)` | 是（2） |
| 长度字段 < `MIN_META_LEN` | `MetadataTooShort(1)` | `MetadataTooShort(1)` | 是（2） |
| status 字节非法 | `InvalidStatus(0x99)` | `InvalidStatus(0x99)` | 是（6） |
| New 帧 net=UDP 但无 port/addr（字段缺失） | `AddressParseFailed` | `AddressParseFailed` | 是（7） |
| 数据长度字段截断（2B 只到 1B） | `Io(UnexpectedEof)` | `Io(UnexpectedEof)` | **否**：旧 15（吃掉半截 1B）/ 新 14（只到完整边界） |
| 数据体截断（声明 16B 实到 4B） | `Io(UnexpectedEof)` | `Io(UnexpectedEof)` | **否**：旧吃满 / 新停在字段边界 |
| 零长数据非 KeepAlive（协议层终止帧） | `NoFrame` | `NoFrame` | 是（= 帧长） |

两处**刻意**差异（都写进 `parse_packet_slice` 文档，测试逐条断言，不是放宽）：

1. **缓冲耗尽**：流式读端把「没有更多字节」当流结束（`Ok(None)`）；缓冲解析端无从判断
   流是否结束 → 报 `Io(UnexpectedEof)`。EOF 判定职责上移到传输层——三个调用面本来就
   先判 `accum` 空 / `read` 返回 0 再退出，故**无悬空等待**（`[]`、`[0x00]`、
   「KeepAlive 后无字节」三例在测试里显式钉住 旧=`NoFrame` / 新=`IoEof`）。
   顺带修掉一处旧语义的隐患：freedom/socks 旧路径对**半截长度头**判 `Ok(None)` →
   `Terminated`（误终止整条流），新路径判「需要更多字节」→ 继续读。
2. **半截字段的 consumed**：新路径只前进到最后一个**完整字段边界**，`consumed ≤
   cursor.position()`，绝不吞后续帧的字节（旧路径已把半截字节从流里读走，属于流语义的
   必然损失）。错误分类完全不变，所有既有 `MetadataTooShort`/`InvalidStatus`/
   `AddressParseFailed` 分支的判定条件一行未动（同一 `FrameMetadata::from_bytes`）。

## 5. 两级分配数字（256 / 64 包实测）

**framing 级**（`xudp packet::tests::parse_allocs_per_packet_ab`，计数分配器 + 单线程
窗口，预热 64 包后计 256 包）：

```text
parse allocs/packet over 256 pkts: old(PacketReader scratch + payload Vec) = 512 (2.00/pkt),
new(slice borrow) = 0 (0.00/pkt)
test result: ok. 1 passed
```

**pump 级**（freedom `udp::tests::request_parse_allocs_per_datagram_bounded`，真
`UdpSocket` 目标 + 计数分配器，帧副本窗口外构造）：

```text
freedom request parse allocs/packet: 0/64 = 0.00/pkt
test result: ok
```

**dispatcher 收包内层**（`udp_session::tests::recv_parse_allocs_per_packet_ab`，新增：

```text
lppdz recv per-packet allocs: old(PacketReader)=2 new(slice+to_vec)=1
test udp_session::tests::recv_parse_allocs_per_packet_ab ... ok
```

## 6. 反证（回退调用面 → 数字变差 + 断言红）

把 freedom `parse_and_send` 临时换回 `Cursor + PacketReader`（同一 harness，同一份
256/64 包帧），实测：

```text
freedom request parse allocs/packet: 128/64 = 2.00/pkt

thread 'udp::tests::request_parse_allocs_per_datagram_bounded' panicked at udp.rs:670:
请求方向每数据报堆分配 128/64 = 2.00 > 上界 1（bd lppdz：旧路径 2/包）
test result: FAILED. 0 passed; 1 failed
```

随后按备份还原（`md5sum` 前后一致：`9372fc89fd6796e3ef03a8b4de53c9f1`），同测试 PASS
（0.00/包）。→ 断言确实由本次改动变绿，不是恒真。

## 7. wire 与门禁

```text
$ cargo test -p xray-xudp -p xray-app-dispatcher -p xray-proxy-freedom -p xray-proxy-socks --all-targets
xray-app-dispatcher lib 149 passed（含 q1r4q + 本票 recv A/B）
xray-proxy-freedom  lib 102 + plugin_contract 12
xray-proxy-socks    lib 89(1 ignored) + e2e_proxy 2 + error_variants 4 + plugin_contract 10
xray-xudp           lib 45（含 parse A/B、slice 语义对照）+ env_basekey 1 + env_legacy 1 + integration 8
全部 0 failed（TEST_EXIT=0）

$ cargo clippy -p xray-xudp -p xray-app-dispatcher -p xray-proxy-freedom -p xray-proxy-socks --all-targets -- -D warnings
Finished `dev` profile … （CLIPPY_EXIT=0，仅 vendor/rustls 既有告警）

$ cargo fmt -p 同上四 crate -- --check  → FMT_EXIT=0（0 diff）
```

wire 回归（release 构建 `target/release/xray.exe`，本次源码）：

```text
python dist/interop_udp_tunnel.py --rust target/release/xray.exe \
        --go D:/tmp/go2617/xray.exe --dest-ports 29090
...
=== 32/32 PASS  (raw -> dist/tmp_udp_tunnel/interop_udp_tunnel.json) ===
```

32/32 含 vless/vmess/trojan × rust→go/go→rust/rust→rust/go→go × cone on-off、dokodemo、
dns-udp；每例 `upstream_hex_exact=true`（29B DNS 查询逐字节）+ `client_reply_dns_ok=true`
+ `upstream_count=1`（不放大）。本次单跑干净，无端口竞态（1fm1l 报告里的 10061 拒连未复现）。

## 8. 未归零处理由

| 残留 | 位置 | 为什么留 | 归零前置 |
|---|---|---|---|
| **1 分配 + 1 拷贝**（载荷 `to_vec`） | `udp_session.rs:196` | `recv_packet` 契约是 `(Destination, Vec<u8>)`，载荷必须脱开 `accum` 独立存活（借用与 `accum.drain` 互斥）→ 拥有型 Vec 无法零拷贝。改签名波及 10+ 调用方（含 `xray-core/src/{inbound,outbound}.rs` 红线文件） | 改 API 为借用/回调形态（如 `recv_packet_into(&mut Vec<u8>)` 复用调用方缓冲），需单独立票 |
| SOCKS5 帧编码 `Vec` | `socks protocol.rs::encode_udp_packet` | 属 **wire 编码**（RSV+FRAG+addr+payload），不是 XUDP 解析；每包 1 次分配为既有形态，不在本票「解析不落中间 Vec」范围 | 与 1fm1l 写侧同法：`encode_udp_packet_into(&mut Buffer)` |
| 其它 crate 的请求方向站点 | `vless inbound server.rs`、`ss dispatcher.rs`、`hysteria dispatcher.rs`、`dispatcher/default.rs` 仍有 `PacketReader` | 属其它 crate 面（部分是本波其他票/他代理面），本票派单只授权三个调用面 | 单独立票，逐面换 `parse_packet_slice_at` |

`crates/xray-proxy-freedom/src/udp.rs` 的 `pump_response` 与 `xray-xudp` 写侧为 1fm1l
已落地内容，本票未改（只在其同文件内新增请求方向测试与一处 needless-borrow 修正）。

## 9. 收尾

- 构建目录沿用本票上一轮代理的 `target-Wave7Slice`（其 owner 已挂，无并发写者；未另建
  `target-Wave7Slice2` 以免 12 分钟冷编），**任务结束删除**（9.2G）。release 构建走共享
  `target/`（复用既有 release 产物，12m15s）。
- 未 commit。未碰红线面（splithttp / hysteria / commander / cli / core inbound-outbound-functions）。
- 反证实验的文件改动已按 md5 校验还原，工作树中本票净改动只有四个文件。
- 代码图谱未重索引：本波并行多代理同时改树，`index_repository` 期间重索引会 abort
  （同 `fix/Wave7Udp.md` §7 现象）——本票符号定位均 read/grep 一手取证，建议整波落地后
  由 PM 统一重索引一次。
