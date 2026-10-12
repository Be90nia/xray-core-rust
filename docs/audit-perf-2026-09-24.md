# Xray-core-rust 性能与协议算法优化空间审计（2026-09-24）

- 基线：master `352ecc92`（对照 Go Xray-core v26.9.9，D:/Project/Xray-core）
- 性质：只读审计；产出可执行优化票清单（位置+证据+Go 对照+预期收益+成本+置信度）
- 已排除：已落地项（splice/readv/PGO/mimalloc/GeoIP 二分/TUN 锁拆/QUIC UDP 8MB/hy2 0-RTT/TUIC CC/REALITY probe+mirror/PQ/tokio 1.53/mKCP ACK MTU/sockopt 全表）；已裁决不做项（io_uring/thread-per-core/MSG_ZEROCOPY/quinn-udp 0.6/XHTTP obfuscation）；2026-09-18 已修项（QUIC 泵 32KB memcpy、HysteriaConn to_vec、datagram 链 2 拷 3 alloc、跨 await 持锁）
- WS 写侧 `buf.to_vec()` 已有票据裁决（lwwz，tungstenite 0.26 Sink 结构性成本），本报告不重复立项

VERDICT: CONDITIONAL

## 负优化审查（动手前必做，已执行）

- `git log --grep="perf|优化|cache|pool|revert" -i`：唯一实质信号 = bridge 泵历史（`378ab889` Revert "上行18x劣化根因修复——bridge泵按Go getLink语义pipe解耦(8sum)" → `f34d5ad6` perf: 8sum 方案A 重新落地：4-block reader/writer + 512KiB mpsc + tokio::io::split）。结论：该区域已按方案 A 满血，本报告**无任何触碰 bridge 泵拓扑的提案**；如未来有人在泵内做"串行简化"即重蹈 `378ab889` 覆辙（up 3.1 vs Go 19.8 Mbps 锁步签名）。
- beads 库已重置（`bd list` 空，`.beads` 不存在），无失败/回退优化票可考。
- `93fa5f52`（splice08 诊断埋点 revert）、`5ddd1cb5`（trojan v2 政策回退后恢复）非性能回退信号。

## Finding 清单

### P1-1 mux 帧读路径每帧 ~4 分配 3 拷贝（对照 Go 池化单读原地解析）

- 位置：
  - `crates/xray-mux/src/reader.rs:97-109`（`StreamReader::read_exact_buffered`：每次调用 `Vec::with_capacity(n)` 结果缓冲 + `vec![0u8; remaining]` 临时缓冲 + `extend_from_slice` 二次拷贝；每帧对 len 前缀/meta/payload 各调一次，payload 一次即 2 alloc + 2 copy）
  - `crates/xray-mux/src/reader.rs:124-131`（`[&len_data[..], &body[..]].concat()` 每帧为 parse 拼 1 个新 Vec）
  - `crates/xray-mux/src/reader.rs:148-160`（`StreamReader::read` 出口用 `Buffer::with_capacity(remaining.len())` ——**绕过池**的 `BytesMut::with_capacity`——再 `write_from` 拷一次）
  - `crates/xray-mux/src/reader.rs:36-48,62-75`（`PacketReader`（UDP mux）同构）
  - `crates/xray-mux/src/worker.rs:521-527,614-621`（服务端 `process_frame` 每帧 meta concat Vec + 逐段 alloc 读）
- 证据（reader.rs:97-109）：
  ```rust
  async fn read_exact_buffered(&mut self, n: usize) -> Result<Vec<u8>, MuxError> {
      let mut result = Vec::with_capacity(n);
      let mut remaining = n;
      while remaining > 0 {
          let mut tmp = vec![0u8; remaining];      // 分配 1
          let read_n = self.reader.read(&mut tmp).await;
          result.extend_from_slice(&tmp[..read_n]); // 拷贝 2
  ```
- Go 对照：`common/mux/frame.go:126` meta 读进池化 `buf.New()` 后 `UnmarshalFromBuffer` **原地解析**；`common/mux/reader.go:44-45` payload `b.ReadFullFrom(reader, size)` 直读进池化 buffer。Go = 1 次内核拷贝 + 原地解析；Rust = wire→cache→tmp→result→Buffer 4 拷 3-4 alloc/帧。
- 预期收益：mux 开启用户下行（client demux，`reader.rs StreamReader` 路径）与服务端上行每帧省 ~2-3 次堆分配 + ~2 次全量 memcpy（8KB 帧量级）；按 1Gbps×8KB 帧 ≈ 每方向每秒 1.5 万帧，CPU 与 alloc 压力可降一个可测台阶。生产已接线（`xray-core/src/outbound.rs:1100` worker.dispatch、`inbound.rs:293` ServerWorker）。
- 成本：~40 行（payload 直读进池化 Buffer 的 `writable_bytes`；meta 用复用小缓冲 parse，去掉 concat；`Buffer::with_capacity`→`Buffer::new()` 池化）。
- 置信度：高（机制层面代码实锤；收益幅度需 bench 验证——见回归保护）。

### P2-2 vmess 入站 UDP 泵每数据报一次全量 `to_vec`

- 位置：`crates/xray-proxy-vmess/src/inbound/server.rs:587`（`pump_udp_session` up 腿）
- 证据：
  ```rust
  match req_cipher.open_in_place(nonce, &[], &mut ciphertext[..ciphertext_size]) {
      Ok(packet) if packet.is_empty() => break,
      Ok(packet) => {
          if up_tx.send(packet.to_vec()).await.is_err() {  // ← 每包一次分配+全量拷贝
  ```
  `ciphertext` 本就是可 take 的 owned `Vec`，`open_in_place` 原地解密——拷贝纯冗余。
- Go 对照：Go `proxy/vmess/inbound` UDP 路径 `payload` 为池化 buffer 直传（`buf.New()` 语义），无每包 owned 拷贝。
- 预期收益：vmess UDP 流量（XUDP/proxy-UDP）每数据报省 1 次分配 + 1 次全量 memcpy（≤2KB/包）。
- 成本：3 行——`ciphertext.truncate(ciphertext_size); let _ = up_tx.send(std::mem::take(&mut ciphertext)).await;`（下一轮 `ciphertext.resize(total_size, 0)` 自愈缓冲复用）。
- 置信度：高。

### P2-3 SSStream 每 chunk 3-4 次堆分配（读+写双向）

- 位置：`crates/xray-proxy-ss/src/stream.rs`
  - 读：`362-398`（`read_chunk`：`size_buf = vec![0u8; 2+tag]`、`open→Vec`、`payload_buf = vec![0u8; wire_len]`、`open→Vec`——每 chunk 4 alloc + 2 拷贝；`627-636` `read_raw_chunk` 同构）
  - 写：`286-290`（`write_chunk`：`seal→Vec` 每 chunk 1 alloc + 1 拷贝）
- 证据（stream.rs:362-396 节选）：
  ```rust
  let mut size_buf = vec![0u8; size_wire_len];       // alloc/chunk
  ... .open(&self.read_nonce, &[], &size_buf)         // Vec alloc/chunk
  let mut payload_buf = vec![0u8; wire_len];          // alloc/chunk
  ... .open(&self.read_nonce, &[], &payload_buf)      // Vec alloc/chunk → 之后还拷进调用方
  ```
- 库内现成原语未用：`AeadCipher::open_in_place` / `seal_into`（vmess 生产泵已在用，见 `xray-proxy-vmess/src/dispatcher.rs:604-621`）。
- Go 对照：Go `proxy/shadowsocks` 读循环为 `sizeBuf`/payload 各一次 alloc（`cipher.Open(dst[:0], …)` dst 复用容量），稳态零新分配；Rust 每 chunk 4 新分配。
- 预期收益：ss（classic+2022 TCP 流）每 chunk（≤1.4KB payload）省 3-4 次分配 + 1-2 次拷贝；高 PPS 小包场景收益放大。
- 成本：~30 行（复用 size_buf/payload_buf 成员字段 + `open_in_place` + 写侧 `seal_into` 复用 out Vec）。
- 置信度：高（机制）；收益幅度中低（AES-GCM 主导，alloc 占比小）。

### P2-4 WebSocket 读半部每 poll_read 一次 Vec 分配（drain-collect）

- 位置：`crates/xray-transport-websocket/src/ws_bridge.rs:120-126`
- 证据：
  ```rust
  // VecDeque::drain 收集到 Vec 太重，直接逐字节拷贝（n 通常很小）。
  let chunk: Vec<u8> = self.read_buf.drain(..n).collect();  // ← 注释说逐字节，实际 collect 新 Vec
  buf.put_slice(&chunk);
  ```
  大帧跨多次 poll_read 时（消息 > 调用方读缓冲），每次读 1 alloc + 1 多余拷贝。
- Go 对照：gorilla/websocket `NextReader`→`Read` 直拷调用方缓冲，无中间 per-read 分配。
- 预期收益：WS 链路下行跨帧读场景每读省 1 alloc + 1 copy；小包为主时接近零频。
- 成本：6 行——`let (a, b) = self.read_buf.as_slices();` 两段 `put_slice`（或 `make_contiguous` 一次）。
- 置信度：高（机制）。同族结构成本（`Message::Binary(Bytes)→Vec<u8>` 转换）属 tungstenite 层，与已裁决写侧 `to_vec`（lwwz）同族，不另立项。

### P3-5 freedom UDP request 泵 `mb.to_vec()` 逐读累积

- 位置：`crates/xray-proxy-freedom/src/udp.rs:242`
- 证据：`accum.extend_from_slice(&mb.to_vec());` ——每个 8KB MultiBuffer 先堆外拷一次再并入 accum（XUDP 帧解析前奏）。
- Go 对照：Go freedom UDP 直接在 MultiBuffer 上 `SplitFirstBytes` 逐包解析，无整段 flatten。
- 预期收益：freedom UDP 中继请求方向每读省 1 alloc + 1 copy（`read_to`/`split_first_bytes` 直解）。
- 成本：~15 行（accum 换 `MultiBuffer` + `read_to` 进定长 buf 解析）。
- 置信度：高（机制）、收益低（仅请求方向 + UDP 面）。

### P3-6 CachedReader::cached_bytes 每次 sniff 尝试整包 to_vec

- 位置：`crates/xray-app-dispatcher/src/default.rs:643`（`sniff_connection` 内）+ `1558-1560`（实现）
- 证据：`pub fn cached_bytes(&self) -> Vec<u8> { self.cache...to_vec() }`——每次嗅探尝试（首读 + `read_more` 最多 2 次）整包（≤8KB）复制一次。
- 预期收益：每连接 ≤3 次 8KB 拷贝；改 `read_to(&mut [u8])`/借阅形态可消。
- 成本：~10 行（签名改借阅或 caller 提供缓冲）。
- 置信度：高（机制）、收益低（每连接一次，非每字节）。

### P3-7 dyn Reader/Writer trait 每 op `Box::pin` 堆分配（架构票）

- 位置：`crates/xray-buf/src/io.rs:53-56`（trait 签名 `Pin<Box<dyn Future>>`）+ `reader.rs:31-34`（`SingleReader` 每调用 Box::pin async block）
- 证据：桥泵双腿（`bridge_link_with_stream_full`）每 8KB 读/写经 `Box<dyn Reader/Writer>` 各 1 次boxed-future 堆分配；同循环内 `timeout(conn_idle, …)` 每读新建 Sleep 并注册定时器轮。
- 量化诚实评估：1Gbps/8KB ≈ 每方向每秒 ~1.6 万次分配；mimalloc 小 bin ~20-30ns，占热循环 <5%，**非当前主瓶颈**。
- Go 对照：goroutine/channel 零此类分配。
- 成本：大——trait 改 RPITIT/枚举态机 + 热路径泛型化（dyn 仅留边界），属跨 crate 接口改造；`Sleep` 复用有 Pin/set 方法解析陷阱（V-Batch7 vy0 教训，当前 sleep_until-per-loop 模式已被裁决可接受）。
- 置信度：中。建议仅在未来大版本接口重构时顺带做，不单独立即改。

### P3-8 MultiBuffer::split_first / split_first_bytes `remove(0)` O(n)

- 位置：`crates/xray-buf/src/multi.rs:157-172`（split_first_bytes）、`199-206`（split_first）
- 证据：`self.buffers.remove(0)` 每次触发 Vec 前缀整体 memmove；Go `mb = mb[1:]` 是 O(1) reslice。
- 量化：Vec ≤64 指针，单次 ≤512B memmove，仅在 UDP/xudp 逐包 split 高频路径有可测意义。
- 成本：`VecDeque` 或 `drain(..1)`+swap 思路，~10 行 + 调用面核对。
- 置信度：高（机制）、收益低。

## 调研遗留项核实（只核实不深挖）

| # | 项 | 结论 | 证据 |
|---|---|---|---|
| ① | splithttp H3 dialer 是否消费 finalmask.quicParams CC 配置 | **已具备**（全链活） | `crates/xray-transport-splithttp/src/register.rs:160-164` 解析 finalmask.quicParams → `h3_client.rs:184-217 connect_with_quic_params`（窗口映射 quinn TransportConfig + `apply_splithttp_cc`：nil 兜底 BBR(standard) 对齐 Go dialer.go:161-164 + PR #5711；reno 不应用/"" 与 "bbr"→BBR/force-brutal→Brutal(up≠0 硬错)/未知→Err） |
| ② | ECH echConfigList="https://…" 获取路径（对照 Go PR #3813） | **已具备**（两个登记缺口：`udp://` 经典 DNS 显式未实现（Go 可用）；缓存无 Go 4h 旧值+后台刷新分支，TTL 过期同步重查） | `crates/xray-tls/src/ech_doh.rs:62-146`（`parse_ech_dns_server` SplitN("+",2) 语义 + DoH https://h2c:// RFC8484 POST + 进程级 TTL 缓存）、`utls.rs:548` 生产接线回灌 base64；缓存键 `ech.rs:191 ech_cache_key` 对齐 Go ECHCacheKey |
| ③ | DNS 乐观缓存（optimistic/TTL 前台刷新） | **已具备** | `crates/xray-app-dns/src/nameserver/cached.rs:129-146`：serveStale 且过 serveExpiredTTL 闸门 → 秒回旧 IP + `pull` 后台刷新（Go nameserver_cached.go:31-41 等价）+ singleflight 并发去重；测试锚定 `cached.rs:393` |
| ④ | REALITY probe.rs dest 记录长度序列探测解锁 mirror | **缺失**（生产 gate 恒 false；解锁条件未实现） | `crates/xray-reality/src/server.rs:654-657`：`POST_HANDSHAKE_MIRROR_PROBE_READY = false`（非 test）；probe.rs 仅 CCS tier 探测（`probe.rs:459-463`），无 Go record_detect.go:124-139 的 dest 主动发 type23 记录长度列表探测。解锁 = probe.rs 扩展列表探测 + gate 改查表结果；在此之前 mirror 恒不发（Go 在列表空时同样不发，行为安全但能力缺失） |

## 已查无恙（本次未发现优化空间的领域）

- **bridge 泵**（`xray-transport/bridge.rs` 8sum 方案 A：4-block 解耦 + vectored 聚合写 + 池化缓冲）——满血，勿再动。
- **xray-buf 基础层**：TLS+8 分片双层池（alloc.rs）、pipe 单锁热路径 1 lock（与 Go pipe mutex 对等）、copy.rs 零拷贝循环、readv 零分配栈数组（fwhh 已修）、multi.rs drain 型切分。
- **vmess TCP 双向泵**（生产路径 `dispatcher.rs` pump_up/pump_down + `inbound/server.rs` pump_request/response）：`seal_into`/`open_in_place`/`next_ref`/chunk_buf 复用/单次 write_all——Go 对齐良好；逐 chunk 分配的 `body_chunk.rs::write_one_chunk` 仅在 per-connection header 路径与测试面，非热点。
- **VLESS**：头后透传，热路径即桥/TLS 层；testpre 预连接池 Go 对齐。
- **QUIC transport**：泵已 BytesMut 直写免 32KB memcpy（2026-09-18 修复保持）。
- **路由**：域名 MPH 匹配器（`MphDomainMatcher`）+ GeoIP CIDR 二分（6nxp 已修）+ leastload 排序选择，复杂度不劣于 Go。
- **DNS**：serveStale/乐观缓存已具备（见调研项③）。
- **锁面**：本轮未发现新跨 await 持锁/锁序反转/全局串行点（与 2026-09-18 三轮审计结论一致）。
- **task spawn**：每连接 1 次（spawn_tracked JoinSet 收口），非每字节成本，Go goroutine 对等可接受。

## 回归保护（各票落地时建议）

- P1-1：`cargo bench`/criterion 对 mux StreamReader `read()` 单帧 8KB 基准（前/后 alloc 计数 + ns/op）；mux e2e 双向 echo 已有 wire 测试保护正确性（client.rs 测试群）。
- P2-2/P3-5：vmess UDP / freedom UDP 既有集成测试回归 + 逐包内容断言（防 truncate/take 引入半帧）。
- P2-3：ss classic+2022 round-trip 测试群（stream.rs tests 已有 nonce/chunk 断言）+ wire 对拍（禁止改 wire）。
- P2-4：ws_bridge 现有跨帧读测试 + 新增大帧（>8KB）跨 poll_read 分段断言。
- 通用：改后 `cargo test --lib -p <crate>` + 终验走 workspace `--lib`（项目惯例）；收益声称须附真实 bench 输出（先测量后优化铁律）。
