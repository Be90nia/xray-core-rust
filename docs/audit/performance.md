# 性能优化维度审计报告（PerfAudit）

- 仓库：D:/Project/Xray-core-rust（HEAD `ee7c6c7`，v54 后）
- Go 基准：D:/Project/Xray-core（v26.7.28）
- 方法：负优化审查（git 历史 + 既有结论回溯）→ 六维度热路径抽审（每维度 ≥3 个函数，贴代码证据）→ 与 Go 基准逐点对照。
- 本审计为只读静态审计：**未运行 benchmark**，以下"影响"均基于代码路径的分配/拷贝/syscall 计数推导，并给出 Go 基准的对应行为作参照锚点。

## 0. 负优化审查结论（动手前必做，通过）

- `git log --grep="perf|优化|cache|pool|revert|回退"`：唯一正向性能提交 `b069b1a perf: bridge/inbound 缓冲接入 xray-buf 分层池（dcy）` **未被回退**，本报告的池化相关建议与其不冲突。
- `5bdfe05`（v49 server splice 回退）、`5e9b234`（splithttp 接 btls 回退）均为**正确性**回退（挂死 / 400 兼容），非性能回退；本报告不重提 splice 相关优化方案。
- v51（TLS 包装层 dirty 状态机）、v50（poll_write 裸 Pending→continue）为近期根治项，本报告**不再报**其缺陷本身；仅在 syscall 效率维度引用其"每次 poll_write 内联 flush"的既定行为作为背景。
- beads：未查（`.beads/` schema skew 只读前缀在本会话不可用），git 侧证据已覆盖回档信号。

---

## 1. 维度① 热路径不必要拷贝/分配

抽审函数：`xray_buf::alloc::alloc/release`、`xray_buf::writer::SequentialWriter::write_multi_buffer`、`xray_buf::reader::SingleReader::read_multi_buffer`、`bridge::bridge_link_with_stream_full` 下行读循环、`xray_crypto::AuthenticationWriter::seal/write_stream`、`xray_crypto::aead`（ring）`seal/open`、`vless::encryption::CommonConn::poll_read/poll_write`、`vless::encryption::aead::Aead::seal/open`、`VisionConn::poll_read`。

### 1.1 正面确认（池化底盘已到位）

- `alloc.rs:90-129`：TLS 缓存 → 8 分片全局池 → 新分配，三级回退，`alloc` 返回 `len=0`；`bridge.rs:113-115` 严格遵循 `alloc` + `resize(DEFAULT_SIZE, 0)` 惯例（铁律③无违例样本）。
- `pipe.rs:178-233`：pipe 读写以 `std::mem::take(&mut inner.data)` 整体移交 `MultiBuffer`，管内零拷贝。
- `multi.rs:179-184`：`merge` 走 `ManuallyDrop::take + forget`，MultiBuffer 合并不复制 payload。

### 1.2 发现

**[P1] VMess 认证块每块 2 次堆分配 + 3 次拷贝，非池化（Go 为池化 + in-place Open）| crates/xray-crypto/src/auth_writer.rs:152-160,104; crates/xray-crypto/src/aead.rs:181-226,289-334**
- 证据（写侧，每 ~2.7KB 块）：
  ```rust
  // auth_writer.rs:152-155
  while !mb.is_empty() {
      let chunk = mb.split_bytes(payload_size);
      let chunk_data = chunk.to_vec();          // 拷贝1：整块复制进新 Vec
      match self.seal(&chunk_data) { ... }
  }
  // auth_writer.rs:104,115-121
  let mut eb = Buffer::with_capacity(total_size);  // 非池化（绕过分层池）
  let sealed = self.auth.seal(&mut [], data)?;      // 分配1：ring seal 内部
  ...writable[..seal_len].copy_from_slice(&sealed[..seal_len]);  // 拷贝2：seal 结果再抄入 Buffer
  ```
- 证据（读侧 + 密码库，每块）：
  ```rust
  // aead.rs:196 / 220,225（ring GCM 与 ChaCha 同构）
  let mut in_out = plaintext.to_vec();              // 拷贝/分配
  self.key.seal_in_place_append_tag(...)
  // open:
  let mut in_out = ciphertext.to_vec();             // 分配1+拷贝1
  let plaintext = self.key.open_in_place(...)?;
  Ok(plaintext.to_vec())                            // 分配2+拷贝2（open 双 to_vec）
  // auth_reader.rs:91,115,149
  let mut data = Vec::with_capacity(size); ...
  let chunk_data = chunk_mb.to_vec();
  ```
- Go 基准（`common/crypto/auth.go:137-151`）：`b := buf.New()`（池化）→ `ReadFullFrom` 直读进池化 Buffer → `auth.Open(b.BytesTo(0), b.BytesTo(size))` **原位解密回同一池化 Buffer**，全流程 0 额外分配 0 额外拷贝。
- 影响：VMess 上/下行每块（≤8KB）多 2-4 次堆分配与 2-3 次 memcpy，属 GCM 数据面恒定税；高吞吐时段放大 allocator 压力与 cache miss。
- 修复建议：`AuthenticationWriter::seal` 改用 `Buffer::new()`（池化）；`split_bytes` 后对 MultiBuffer 逐 Buffer `bytes()` 引用加密（跨块拼接场景才物化）；ring `open` 增加 `open_in_place` 变体（返回 `&mut [u8]` 截断 tag），`auth_reader::read_buffer` 池化读入后原位 Open——对齐 Go readBuffer 形态。

**[P1] VLESS ENC 数据面每 record 双堆分配 + drain memmove（Go 池化 in-place）| crates/xray-proxy-vless/src/encryption/common_conn.rs:192-207,211-226,303-313; crates/xray-proxy-vless/src/encryption/aead.rs:107-114,138-145**
- 证据：
  ```rust
  // common_conn.rs:192-205（每收满一个 TLS record）
  let data: Vec<u8> = this.raw_buf[TLS_RECORD_HEADER_LEN..total].to_vec(); // 分配1+拷贝
  let mut plaintext = Vec::with_capacity(...);                            // 分配2
  peer_aead.open(&mut plaintext, None, &data, &header)?;
  this.raw_buf.drain(..total);                                            // memmove 残余
  // common_conn.rs:211（每次 poll_read）
  let mut tmp = [0u8; 16_384];                                            // 16KB 栈帧
  this.raw_buf.extend_from_slice(&tmp[..n]);
  // common_conn.rs:303-310（每个发 record）
  let mut ct = Vec::with_capacity(TLS_RECORD_HEADER_LEN + n + TAG_LEN + 16);
  // vless aead.rs:107-112：aes_gcm encrypt() 返回新 Vec，dst.extend_from_slice(&ct) 再整体拷贝
  ```
- 影响：`encryption != none` 的 VLESS 连接每 record（读+写两方向）共 ~4 次堆分配 + 3 次拷贝 + 一次 memmove；16KB 栈临时缓冲随 poll 频率反复进出 cache。
- 修复建议：`raw_buf` 改池化 `BytesMut` 并用 `split_to(total)`（O(1) 指针前移替代 `drain` memmove）；解密用 `open_in_place`（对 `raw_buf` 中密文段原位）；发送侧 `ct` 复用 member buffer（`pre_write` 只影响首块，可单独处理）。

**[P1] 全局缓冲池分片无上限，高水位内存永久滞留 | crates/xray-buf/src/alloc.rs:131-160**
- 证据：
  ```rust
  // alloc.rs:153-157（注释自认）
  // 2. 尝试全局分片（无上限，但 Mutex 保护）
  let shard_idx = next_shard();
  let mut shard = SHARDS[shard_idx].lock();
  shard.tiers[tier].push(buf);
  ```
  TLS 层有 `TLS_MAX_PER_TIER=8` 上限（alloc.rs:24），全局 8 分片层**无任何容量检查**，`clear()` 仅测试调用。
- 影响：池保留量 = 历史并发峰值水位，永不收缩。128KB 层尤甚：一次 1 万并发出站突发后，`131072B × N` 常驻 RSS（Go `sync.Pool` 在 GC 时丢弃旧代缓冲，等价自动收缩）。
- 修复建议：给每分片每层加 cap（如 64），超限直接丢弃归还的 buffer；或加惰性收缩（release 时按 1/k 概率丢弃）。属一行级改动。

**[P2] bridge 下行 read→merge_bytes 双拷贝 | crates/xray-transport/src/bridge.rs:234-270**
- 证据：
  ```rust
  let mut buf = xray_buf::alloc::alloc(DEFAULT_SIZE);
  buf.resize(DEFAULT_SIZE, 0);
  let n = ... s_read.read(&mut buf).await ...;
  let mut mb = MultiBuffer::new();
  mb.merge_bytes(&buf[..n]);        // socket buf → 新池化 Buffer 再拷贝一次
  ```
- 影响：下行每 8KB 多一次 memcpy。Go `buf.NewReader` 直读进池化 Buffer（`readv_reader` 更是 readv 直聚散）。
- 修复建议：`merge_bytes` 前空 MultiBuffer 场景直接 `Buffer::from_bytes(buf 分离)` 或提供 `read_into_buffer` 形态；`buf` 不再每次归还池而以 `Buffer` 轮转。

**[P2] VisionConn padding 阶段每 poll_read 16KB 栈临时 + unpadding Vec 分配 | crates/xray-proxy-vless/src/encryption/vision_conn.rs:196-237,324-332**
- 证据：
  ```rust
  let mut tmp = [0u8; 16_384];                    // 每次栈分配
  let content = xtls_unpadding(&tmp[..n], ...);   // 返回新 Vec（分配）
  ...
  let padded = xtls_padding(Some(&buf[..n]), ...); // 每次写一个新 Vec（分配）
  ```
- 影响：仅 padding 阶段（握手+首请求，DIRECT/END 后走 raw 旁路）受影响，量小；但 Vision 每连接握手期高频触发。
- 修复建议：`tmp` 提为 struct 字段（`[u8; 16384]` 复用）；`downlink_pending` 改 `BytesMut` 复用容量。

---

## 2. 维度② 锁竞争

抽审函数：`pipe::Reader::read_multi_buffer / Writer::write_multi_buffer`（std Mutex 作用域）、`cnc::ContentNetworkConnection::poll_read/poll_write/close`（parking_lot Mutex）、`udp::NatTable::register/touch`（tokio Mutex）、`proxyman Inbound/OutboundManager::get_handler`（RwLock）、`xray-app-dispatcher::stats` Counter、`CachedReader`。

**结论：未发现持锁跨 await 或热路径粗粒度锁热点（P 级证据均不成立，列为核查通过）。** 已核对样本：

- `pipe.rs:181-189,327-347`：锁在块作用域内取数据/判定动作，`drop` 后才进入 `select!` 等待——临界区不含 await。
- `cnc.rs:168-243`：`Mutex<Inner>` 在 poll 函数内锁定，poll 语义下无 await 点；读/写两方向共享单锁使同连接双向 poll 串行化，但临界区均为纯内存操作（读缓冲回放/状态机推进），持有时长亚微秒级——不构成竞争热点，不计入发现。
- `udp/dispatcher.rs:119-151,156-162`：NAT 表 tokio Mutex，`register/touch` 锁内仅 HashMap 增改查，无 IO 无 await；与 Go `sync.Mutex` 保守护 NAT map 同构。tokio Mutex 此处为过度选择（std 即可），非缺陷。
- `default.rs:1038-1043`：Go `cachedReader{sync.Mutex}` 被 Rust 所有权模型消锁（单任务持有），消除一处 Go 侧真实锁。
- `xray-app-stats/counter.rs:57-60` + `stats.rs:126-133`：流量计数为 `AtomicI64::fetch_add`，每 MultiBuffer 一次原子加，无锁竞争。
- `proxyman inbound/outbound mod.rs`：`RwLock<ManagerState>` 只在 handler 查找（每连接一次）短读锁定，注册/启停在控制面。

---

## 3. 维度③ async 开销

抽审函数：`DefaultDispatcher::dispatch_link`（spawn 粒度）、`bridge_link_with_stream_full`（任务/超时结构）、`finalmask::PacketIoConn::poll_read/poll_write`、`xray_buf::io::Reader/Writer` trait（`Pin<Box<dyn Future>>` 返回签名）、ss UDP relay `mpsc::channel(16)`。

**[P1] finalmask PacketIoConn：每次 Pending 读 spawn 一个任务、每包写 spawn 一个任务 + 整包拷贝 | crates/xray-transport/src/finalmask/mod.rs:447-487**
- 证据：
  ```rust
  // poll_read（每次返回 Pending 都执行）
  // ponytail: 每次 Pending 都 spawn 唤醒——频繁唤醒浪费，但简化为可运行。
  let waker = cx.waker().clone();
  tokio::spawn(async move {
      notify.notified().await;
      waker.wake();
  });
  Poll::Pending
  // poll_write（每包）
  let data = buf.to_vec();
  tokio::spawn(async move {
      if let Err(e) = inner.send_to(&data, remote).await { ... }
      waker.wake();
  });
  Poll::Ready(Ok(n))
  ```
- 影响：KCP/finalmask 数据面按包驱动：读侧每次空 poll 泄漏一个 spawn 任务（N 次 poll 积 N 个 waiter，`Notify::notify_one` 只唤醒其一，其余滞留至后续包逐个假唤醒）；写侧每包 1 次 spawn + 1 次整包 memcpy + 1 次 无效 `wake()`（调用方已 Ready 不会重新 poll）。包速率高时任务调度开销可比协议处理本身贵。
- 修复建议：读侧存 `Option<Waker>` 于结构体（`notify` 改配对 `Notify::notified()` 存续 `Notified` future 或直接 `register_waker` 模式），杜绝每 Pending spawn；写侧优先 `try_send_to`（UdpIo 已有冷调用语义），仅 WouldBlock 才落 spawn，且去掉 `waker.wake()`。

**[P2] Reader/Writer trait 每调用 `Pin<Box<dyn Future>>` 堆分配 | crates/xray-buf/src/io.rs:78-102; crates/xray-buf/src/pipe.rs:293-299,413-419; crates/xray-buf/src/writer.rs:37-41; crates/xray-buf/src/reader.rs:34-37**
- 证据：
  ```rust
  pub trait Reader: Send {
      fn read_multi_buffer(&mut self)
          -> Pin<Box<dyn Future<Output = Result<MultiBuffer>> + Send + '_>>;   // io.rs
  }
  // pipe.rs:296-298
  Box::pin(async move { Reader::read_multi_buffer(self).await })
  ```
- 影响：读/写链每跳一 MultiBuffer 一盒（dispatcher 链典型 4-6 层包装：pipe → stats → endpoint_override → 协议层 → bridge），每 8KB 一次额外 allocator 往返 + vtable 间接。Go interface 调用无此分配。
- 修复建议：trait 改 `async fn`（Rust 1.75+ / trait_variant 生成 Send 版），或最少把热路径两跳（pipe Reader/Writer → 调用方）改泛型具体类型。此项收益需 benchmark 确认后再动（每次分配 ~48B，占比低于维度①的 memcpy，优先级靠后）。

**正面确认（非发现，抽审记录）**
- `default.rs:1022-1026` / `inbound.rs:97,317,404`：spawn 粒度 = 每连接，与 Go goroutine-per-conn 同构；无每消息 spawn。
- ss UDP relay `mpsc::channel(16)`（`xray-core/src/inbound.rs:1004,1153`）：有界通道 + await 背压，无丢包式溢出。
- `bridge_link_with_stream_full` 每方向循环内重建 `tokio::time::timeout` future：cancel-safe（bridge.rs:193-194 注释已论证），无任务泄漏。

---

## 4. 维度④ 算法复杂度

抽审函数：`MultiBuffer::split_bytes/split_size/split_first_bytes`、`proxyman::UdpWorker::process`（active_sessions 查找）、`xray-app-router::ConditionChan::apply`、`alloc::select_tier`、`Buffer` 游标读写。

**[P2] MultiBuffer::split_bytes / split_size 用 `Vec::remove(0)`，逐块切分 O(n²) memmove | crates/xray-buf/src/multi.rs:99-113,148-172**
- 证据：
  ```rust
  while remaining > 0 && !self.buffers.is_empty() {
      ...
      if front.len() <= remaining {
          remaining -= front.len();
          let buf = self.buffers.remove(0);   // O(n) 前移全 Vec
          result.push(buf);
      }
  ```
- 影响：vmess `write_stream`（auth_writer.rs:152-163）/ mux `writer.rs:138` 按 ~2.7KB 循环切分一个 MultiBuffer；pipe 积压突发时 mb 可含数十个 Buffer，每次 `remove(0)` 整体前移。512KB 积压 + 2.7KB 块 = ~190 次 memmove，量级仍小但纯浪费。
- 修复建议：`split_bytes/split_size` 记录消费游标，循环尾部 `self.buffers.drain(0..i)` 一次性前移；或内部改 `VecDeque<Buffer>`。

**[P2] proxyman UdpWorker active_sessions 线性扫描 per 包 | crates/xray-app-proxyman/src/inbound/worker.rs:449-472**
- 证据：
  ```rust
  let sessions = self.active_sessions.read();          // RwLock<Vec<Arc<UdpSession>>>
  let existing = sessions.iter().find(|s| s.source() == source);
  ```
- 影响：每 UDP 包 O(n) 扫描 + 读锁；DNS/QUIC 大流量下单 inbound 会话数可达数百，每包线性扫。Go 基准对应结构为 map（`hub` 按 addr 索引）。
- 修复建议：改 `RwLock<HashMap<SocketAddr, Arc<UdpSession>>>`（清理侧 retain 改 retain 式遍历即可）。

**[P2] MultiBuffer::len/is_empty 每调用 O(n) 求和 | crates/xray-buf/src/multi.rs:59-67**
- 证据：`pub fn len(&self) -> usize { self.buffers.iter().map(|b| b.len()).sum() }`；`is_empty()` 每次调用 `len()==0`。
- 影响：`copy_with_options`（copy.rs:95）、pipe 满判定（pipe.rs:331）等热循环每轮求和；buffer 数通常 ≤8，常数极小——记录为可忽略级，若做 `VecDeque` 改造可顺带维护 `total_len` 缓存。
- 修复建议：随上一条改造顺带缓存总长，不单独立项。

**正面确认**
- `condition.rs:47-86`：路由规则线性 AND 求值与 Go `ConditionChan` 同构（Go 亦线性），非劣化。
- `alloc.rs:71-78`：`select_tier` 4 元素线性，`#[inline]`，无问题。
- vless/vmess validator 查找为 HashMap（v47 轮已对齐口径），无线性热点。

---

## 5. 维度⑤ TLS record 处理效率

抽审函数：`utls::Conn::poll_write/poll_flush/poll_read`、`utls::ServerConn::poll_write`、全库 `poll_write_vectored` 存在性、Go 基准 `buf.NewWriter`（io.go:171-192）。

**[P1] 裸 TCP 腿无 writev 批量：MultiBuffer 逐 Buffer write_all，Go 同位为 net.Buffers 单次 writev | crates/xray-buf/src/writer.rs:36-62; crates/xray-transport/src/bridge.rs:149-161;（全库 grep `poll_write_vectored|write_vectored` 零命中）**
- 证据（Rust 唯一的 MultiBuffer→AsyncWrite 出口，两个均逐 Buffer）：
  ```rust
  // writer.rs:41-59 SequentialWriter::write_multi_buffer
  let buffers = mb.into_buffers();
  for mut buf in buffers {
      match self.inner.write_all(data).await { ... }   // 每 Buffer 一次 write 系统调用
  }
  // bridge.rs:154-159 write_all_mb
  for b in mb.iter() { w.write_all(bytes).await?; }
  ```
- Go 基准（`common/buf/io.go:171-192` + `writer.go:22-66`）：`NewWriter` 对非 TLS conn 返回 `BufferToBytesWriter`，多 Buffer 组装 `net.Buffers(bs)` 后 `nb.WriteTo(w.Writer)`——**一次 writev 写完整个 MultiBuffer**（writer.go:49-57）；仅 TLS conn 走逐块 SequentialWriter（io_test.go:45 明示）。
- 影响：8×8KB 的 MultiBuffer 在 Rust = 8 次 write syscall；Go = 1 次 writev。生产链上 freedom 直连出站、dokodemo、socks 入站等**裸 TCP 腿**每 64KB 多 7 次系统调用+TCP 头部小包化（配合 Nagle 关闭直接小段出网）。TLS 腿为 Go 同构（每 record 一写，且 v51 后内联 flush），不在此条范围。
- 修复建议：`SequentialWriter` 内实现批量：收集 `Vec<IoSlice>` 调 `inner.write_vectored`（tokio AsyncWrite 已提供默认实现，TcpStream 原生映射 writev）；桥层 `write_all_mb` 同改。TLS 分支（`S: Connection` rustls 包装）保持逐 Buffer，避免违反 v51 语义。

**正面确认（v51 修复回归核查，不报缺陷）**
- `utls.rs:140-160`（Conn）与 `utls.rs:273-287`（ServerConn）：poll_write 成功后内联 poll_flush、Pending 记 `dirty` 不上传、poll_read 借机推进滞留——与 v51 根治语义一致，无回归。
- 握手批量：rustls session/ticket 复用已由 config 层管理（client_config/server_config），未见每连接重建密码套件的浪费。

---

## 6. 维度⑥ syscall 效率（小包频繁 write）

抽审函数：`SequentialWriter::write_multi_buffer`（同维度⑤）、`SSStream::write_single_chunk`、`PacketIoConn::poll_write`（同维度③）、`sockopt::apply_outbound/inbound_socket_options`（NODELAY）、`bridge_connections`（tokio::io::copy 8KB 栈缓冲）。

**[P2] SS2022 每 chunk 两次独立 write（size 块 ~18B 单独成包）+ 每 seal 两个中间 Vec | crates/xray-proxy-ss/src/stream.rs:255-274**
- 证据：
  ```rust
  let sealed_size = self.write_aead.seal(&self.write_nonce, &[], &plain_size.to_be_bytes())?;
  let sealed_payload = self.write_aead.seal(&self.write_nonce, &[], plaintext)?;
  self.inner.write_all(&sealed_size).await?;     // syscall1: 2+tag 字节
  self.inner.write_all(&sealed_payload).await?;  // syscall2: ≤8KB
  ```
- 影响：每 ~8KB 数据 2 次 write，且 size 段单独成 TCP 段（NOVEL：与 Go shadowaead 同构，属基准同款；真正可省的是两次 seal 的中间 Vec 与 size/payload 拼写一次的 syscall）。
- 修复建议：`sealed_size`+`sealed_payload` 拼进同一池化 Buffer 后单次 `write_all`；`Aead::seal` 提供 `seal_into(&mut Vec<u8>)`（append 语义，免返回值 Vec）。

**[P2] bridge_connections 用 tokio::io::copy（每方向 8KB 非池化堆缓冲 + 每 8KB 两跳 memcpy）| crates/xray-transport/src/bridge.rs:40-60**
- 证据：`let a_to_b = tokio::io::copy(&mut a_read, &mut b_write);` —— tokio 内部 `CopyBuffer` 为堆分配 8KB，socket→copy buf→socket 两拷贝；同 crate 的 `bridge_link_with_stream_full` 已示范 `xray_buf::alloc` 池化读缓冲。
- 影响：`Box<dyn Connection>` 级桥接（fallback/部分测试/旧路径）每连接 2 次额外堆分配；相对池化无 cache 复用。仅低频路径受影响。
- 修复建议：统一切 `bridge_link_with_stream_full` 或抽共享池化双向循环；保留 `bridge_connections` 仅作语义兼容（select! 单向取消语义与 full 的 join! 不同，合并时需保留两种模式）。

**正面确认**
- TCP_NODELAY：`SocketOptions::default()` `tcp_nodelay: true`（sockopt/mod.rs:349），出站 `apply_outbound_socket_options`（:391）与入站 accept 路径（system_listener.rs:265-290 → apply_inbound_socket_options:475）均应用，测试 `default_listener_applies_sockopt_on_accept` 覆盖——无 Nagle 40ms 陷阱（Go 默认 TCP_NODELAY=true 已对齐）。
- 单连接 read 面每次一个 8KB read syscall（SingleReader），与 Go SingleReader 同构。

---

## 汇总

| 严重度 | 数量 | 条目 |
|---|---|---|
| P0 | 0 | —（未发现可致崩溃/挂死/安全漏洞级性能缺陷） |
| P1 | 5 | ①VMess 认证块分配拷贝链（auth_writer/aead/auth_reader）②VLESS ENC 每 record 双分配+drain memmove ③缓冲池全局分片无上限高水位滞留 ④finalmask 每包/每 Pending spawn（维度③）⑤裸 TCP 腿逐 Buffer write 缺 writev 批量（维度⑤） |
| P2 | 7 | bridge 下行双拷贝、Vision padding 阶段临时缓冲、trait Box::pin 每调用分配、MultiBuffer remove(0) O(n²)、UDP worker 线性扫、SS2022 双 write/双 Vec、bridge_connections 非池化 copy |

TOP3：

## 回归保护建议（供 PM 采纳后立项）

- 增加 cargo bench（criterion）三条基线：①`SequentialWriter` vs 实验性 writev 路径（8×8KB MultiBuffer→TcpStream，环回）②VMess AuthenticationWriter 往返（1MB payload，计 alloc 次数用 dhat 或 counting allocator）③pipe→bridge 泵吞吐（512KB×N）。
- `xray-buf` 加池水位单测：burst N 连接后 `SHARDS` 总量 ≤ cap（防回归到无上限）。

## 架构建议（locality / deletion test）

- 维度①的池化/in-place 改造全部收敛在 `xray-buf`、`xray-crypto`、`vless/encryption` 三个模块内部，调用方签名不变（deletion test 通过：删除任一中间拷贝不产生新 pass-through 层）。
- 维度⑤若引入 writev，建议只在 `xray-buf::writer` 增一个 `writev` 能力探测方法，不在各协议 crate 重复判定——避免为性能新增浅层适配模块。
