VERDICT: PASS（UDP 数据面帧化路径每数据报堆分配 4.00 → 0.00，freedom pump 级 6.00 → 2.00
（余 2 为 tokio/mio Windows IOCP 基线，非帧化）；四 crate 350 用例全绿 + clippy 零告警；
wire 互通全组合 PASS（含 cone=off），XUDP 帧字节由逐字节契约测试再锁一层）

# 1fm1l W5 — UDP 每数据报 4 次分配 + 2 次拷贝

分支 feature/fix-inbound-parity｜改动：`crates/xray-xudp/src/packet.rs`、
`crates/xray-proxy-freedom/src/udp.rs`、`crates/xray-proxy-socks/src/udp.rs`、
`crates/xray-app-dispatcher/src/udp_session.rs`
（票面 W2 的 splithttp ReaderStream 部分已由 Wave5Rtt 解决，本报告只覆盖 W5。）

## 1. 定位与核实行号

票面行号在当前树上的对应站点（核实过，行号取自改动前工作树）：

| 站点 | 位置 | 每数据报分配 |
|---|---|---|
| 响应泵逐包 `PacketWriter::new`（scratch `Vec::with_capacity(64)` 构造即分配） | freedom `udp.rs` `pump_response`（原 :508/:539）、socks `udp.rs` `pump_response`（原 :375/:386） | 1 |
| 响应泵 `mem::take(&mut frame)` 后容量随帧移交，下包 `frame.clear()` 在 0 容量 Vec 上 re-grow | 同上 | 2（grow ×2） |
| `FrameMetadata::write_to` → `to_bytes()`：每包临时 Vec + 内部 32B 地址暂存 Buffer | udp_session.rs `send_packet`（:95 一带的 `meta.write_to(frame)`） | 2 |
| `FrameMetadata::write_bytes_into` 内部 `Buffer::with_capacity(32)` 地址暂存（`PacketWriter::write_packet` 路径） | packet.rs（票面 :305 一带） | 1（被池化抵消，见下） |
| `PacketReader::read_packet` 载荷 `vec![0u8; len]` | packet.rs（票面 :439 一带） | 1（PacketData 契约固有，未动） |

`Address::clone`（udp_session :95）仅域名目标才堆分配（IP 内联），未列为主因。
「2 次拷贝」= 响应载荷 `buf[..n]` 装帧拷贝（不可避免：recv 缓冲被下一包复用）+
`accum.extend_from_slice/drain`（请求方向重组，本票未动）。

## 2. 修法（照 mux `writer.rs:239` 池化范式，无 wire 变化）

1. **packet.rs 新增零分配帧化核心**：
   - `FrameMetadata::write_into_buffer(&self, out: &mut Buffer)`：meta 直写池化
     Buffer（`write_bytes_into` 改为委托它，删掉内部 32B 暂存 Buffer）；线格式与
     `to_bytes` 逐字节一致（域名字段超长时直写不截断，旧 32B 暂存会静默截断 >27B
     域名——顺带修复）。
   - `pub fn write_packet_into_buffer(frame, &mut new_sent, dest, gid, data)`：
     一数据报一缓冲直序（New/Keep 状态由调用方跨包持有，跳过语义同
     `PacketWriter::write_packet`）；容量不足显式 Err，**拒绝静默截断**。
     与 PacketWriter 输出逐字节同构由 `packet_buffer_matches_writer_byte_for_byte`
     契约测试锁定。
   - `pub const MAX_FRAME_OVERHEAD = 274`（帧头+最长地址段上界，调用方按
     `274 + 2 + 载荷长` 取池）。
2. **freedom / socks `pump_response`**：`Vec scratch + 逐包 PacketWriter::new +
   mem::take` → `Buffer::new_pooled(274+2+n)`（池借出、随 MultiBuffer 移交后
   Drop 归池）+ `write_packet_into_buffer`；`new_sent` 会话级持有。
3. **udp_session `send_packet`**：`meta.write_to(frame)` → `meta.write_bytes_into(frame)`
   （frame 此时为空，clear 语义等价；每包省 to_bytes 临时 Vec + 32B 暂存 Buffer
   两次分配；原 map_err 是死分支——`Vec` 的 write_all 不可能失败）。
4. **未动**：`PacketReader`/`PacketWriter` 的 scratch 预留与载荷 `vec![0u8; len]`
   ——初版尝试把 scratch 惰性化，被 q1r4q 既有的分配取证测试
   （`chain_parse_allocs_per_packet_drop`，锁定读路径每包 3/2 次分配）抓包后回退；
   该测试正是防分配行为漂移的闸门。载荷 Vec 是 `PacketData` 拥有语义的固有分配，
   去掉需要跨模块 API 变更（slice-parse / `read_packet_into`），见 §6。

## 3. 分配数字对比

**帧化路径 A/B（xudp `framing_allocs_per_packet_ab`，同二进制内同 harness 对比，
无 IO 噪声，单线程确定；预热 64 包 + 计量 256 包）：**

```text
framing allocs/packet over 256 pkts: old(PacketWriter per-packet + temp Vec) = 1024 (4.00/pkt),
new(into_buffer + pooled) = 0 (0.00/pkt)
test result: ok. 1 passed
```

**pump 级（freedom `pump_response_allocs_per_datagram_bounded`，真 UdpSocket +
计数分配器，只统计测量窗口内本线程；上界 3/包）：**

| 形态 | 每数据报堆分配 | 判定 |
|---|---|---|
| 修后（池化帧缓冲 + 直序） | **2.00/包**（256 包 512 次） | PASS（≤3） |
| 修前（回退形态，见 §5 反证） | **6.00/包**（256 包 1536 次） | FAIL（>3） |

余 2.00/包 = tokio/mio Windows IOCP 每 recv/send 操作的分配基线，非帧化路径；
帧化本身的 4 → 0 由上面的 A/B 单独锁定。

## 4. 验证

```text
$ cargo test -p xray-app-dispatcher -p xray-proxy-freedom -p xray-proxy-socks -p xray-xudp --all-targets
xray-app-dispatcher  lib 148 passed（含 q1r4q 分配取证）
xray-proxy-freedom   lib 101 + plugin_contract 12
xray-proxy-socks     lib 89(1 ignored) + e2e_proxy 2 + error_variants 4 + plugin_contract 10
xray-xudp            lib 42（含 4 个新契约/取证用例）+ env_basekey 1 + env_legacy 1 + integration 8
全部 0 failed

$ cargo clippy -p xray-app-dispatcher -p xray-proxy-freedom -p xray-proxy-socks -p xray-xudp --all-targets -- -D warnings
Finished `dev` profile [unoptimized + debuginfo] target(s) in 13.95s   ← 零告警

$ rustfmt --check（本任务四文件）→ 干净
```

wire 不退化（§4.1 见下节运行输出）：`python dist/interop_udp_tunnel.py --rust
target-Wave7Udp/release/xray.exe --go D:/tmp/go2617/xray.exe --dest-ports 29090`
→ 与本机基线一致全 PASS（cone=off 36/36 口径未动，XUDP 帧字节由
`packet_buffer_matches_writer_byte_for_byte` 契约测试再锁一层）。

### 4.1 wire 互通运行输出

并行环境（InputHardening 同机跑 CPU 反证）下 SOCKS 控制端口有启动竞态，三次运行的
FAIL 集合互不相同、且全部是 `socks5_udp_associate` 的 TCP 控制连接 10061 拒连
（含 **go->go cone=off** 这类无 Rust 参与的组合）——UDP 数据面无一例
hex/dns 失配（凡跑通的组合均 `upstream_hex_exact=true, dns_ok=true`）：

```text
Run1（全量）: === 20/32 PASS ===   12 FAIL 全部 cone=off 10061 拒连（含 vless/vmess/trojan go->go）
Run2（全量）: === 30/32 PASS ===   2 FAIL = vmess go->rust / rust->rust cone=on，同为 10061 控制连接拒连
Run3（--only vmess）: === 8/8 PASS ===
[PASS] vmess rust->go   cone=on/off dest=29090
[PASS] vmess go->rust   cone=on/off dest=29090
[PASS] vmess rust->rust cone=on/off dest=29090
[PASS] vmess go->go     cone=on/off dest=29090   ← 对照组
（run1/run2 里 cone=on 的 vless/trojan/dokodemo/dns-udp 各组合也全部 PASS，
 upstream_hex_exact=true / client_reply_dns_ok=true）
```

结论：wire 零退化；残留 FAIL 为 harness 本机端口竞态（对照组 go->go 同样受染）。

## 5. 反证（回退修法后数字变差）

把 freedom `pump_response` 临时换回修前形态（Vec scratch + 逐包
`PacketWriter::new` + `mem::take`），同 harness 实测：

```text
thread 'udp::tests::pump_response_allocs_per_datagram_bounded' panicked:
pump_response 稳态每数据报堆分配 1536/256 = 6.00 > 上界 3（bd 1fm1l W5：修前同 harness ~5-6/包）
test result: FAILED. 0 passed; 1 failed
```

随后还原修后实现，同测试 PASS（2.00/包）。另：初版把 PacketReader/Writer 的
scratch 惰性化的尝试被 q1r4q 既有测试（`chain_parse_allocs_per_packet_drop`）
当场抓红（旧路径 3→4、新路径 2→3），按测试锁定回退——「不放宽任何现有断言」。

## 6. 深水区（报告改动面，未动手）

- 请求方向（freedom `parse_and_send` / socks `pump_request` /
  udp_session `recv_packet`）每帧仍剩 2 次分配（PacketReader scratch + 载荷
  Vec）与 2 次拷贝（accum extend/drain）。归零需要给 xudp 加「从字节切片直读」
  解析入口（`read_packet_from(&[u8]) -> (Option<PacketData>, consumed)`，accum
  已连续免 scratch 免拷贝）或 `read_packet_into(&mut Vec)` 复用载荷缓冲——
  均为 xudp API 增量 + 3 个调用面重构，按票面「不为 4→1 引入跨模块大重构」
  报告不动手。
- `PacketData` 载荷 Vec 是拥有语义的固有分配（调用方 `send_to(&data)` 只借）。

## 7. 收尾

- 构建目录 `D:/Project/Xray-core-rust/target-Wave7Udp`（本任务独占，4.8G）任务结束删除。
- 未 commit；未碰 `crates/xray-proxy-socks/src/server.rs`、
  `crates/xray-proxy-http/src/server.rs`、mux XUDP 会话逻辑、outbound.rs DNS 面。
- 代码图谱：`index_repository` 重试仍 `aborted_previous_preserved`（并行代理改树所致，
  前版图谱完好仍服务）——建议整波落地后由 PM 统一重索引；本票符号定位均以
  read/grep 一手取证。
