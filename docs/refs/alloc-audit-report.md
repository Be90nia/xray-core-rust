# 全仓数据面热路径内存分配模式审计报告

**结论（最严重 3 项）**：
1. **splithttp/xhttp 字节路径多拷贝族**——上行每 chunk `read_buf[..n].to_vec()`（dialer.rs:92/374）、h3 模式每 chunk `Bytes::copy_from_slice`（h3_client.rs:386）、服务端收流每 chunk `chunk.to_vec()`（hub/handler.rs:328）。xhttp 是当前主力 CDN 传输，字节路径每 chunk 多 1-2 次全量拷贝，均可改 ownership 转移（`Bytes::from(Vec)`/pooled `split_to().freeze()`）零拷贝化。
2. **grpc hunk 帧路径双拷贝 + O(n) 摘除**——`encode_hunk_frame` 每帧 `data.to_vec()` + `encode_to_vec` 两次全量拷贝 3 次分配（encoding.rs:248-252/306-310）；下行 `acc.extend_from_slice` + `Hunk::decode to_vec` + `acc.drain(..used)` 逐帧 memmove + `vec![data]` 包装（transport.rs:269-296）。
3. **KCP 每 segment / 每 poll 堆分配**——`SimpleSegmentWriter::write_segment` 每段 `vec![0u8; byte_size]`（output.rs:57，listener.rs:219 同型），Go 基线 output.go:32-35 用持久 `buf.Buffer`（Clear/Extend）零分配——Rust 侧为对基线的真实偏差；`KcpConn::poll_read` 每次 poll `vec![0u8; remaining]`（connection.rs:684，含虚假唤醒）。

**VERDICT: PASS**

- 审计完成全范围扫描，未发现 vision 级「每帧钉死」残留；vision 本体的池化修复已提交（7681f7cc）+ 工作树后续迭代，不在 finding 范围（仅作建议写法引用）。
- 全部 finding 均有行号 + 热度证据；读不准的一律未报（各 crate「已查无发现」节列明扫描证据）。

---

## 0. 方法（扫了什么 / 怎么判定热路径）

**范围**：crates/ 全部 56 crate 中数据面相关的 33 个——9 个 xray-transport-*（含 xray-transport 本体的 bridge/record_framer/finalmask/mkcp）+ xray-tls/xray-reality + 17 个 xray-proxy-*（含 xudp）+ xray-buf/xray-core/xray-mux/xray-app-dispatcher。控制面 crate（conf/cli/proto/features/app-commander/app-proxyman/app-log/app-stats/app-policy/app-version/app-metrics/app-observatory/app-router/app-reverse/app-geodata/geodata/common/stress）不在数据面定义内，仅 xray-app-dns 因带数据面 nameserver 做了扫查（命中全为控制面/测试）。

**扫查模式**：A 类 `Vec::new(`、`vec![`、`BytesMut::(new|with_capacity|zeroed)`、`Box::new`；B 类 `.to_vec()`、`copy_from_slice`、`.clone()`、`to_owned()`、`extend_from_slice`；C 类 `remove(0)`、`drain(..`、逐字节 read、循环内 write_all。对每 crate 的 src 全量 grep，命中点逐一回读上下文分类。

**热路径判定标准（去伪存真）**：
- 每 chunk/每帧/每包执行 = 热路径（报告）；
- 每 task/pump 循环外一次性分配、循环内复用 = 不报（如 tuic/anytls/ss dispatcher 的 `vec![0u8; 8*1024]` 每 pump 一次）；
- 握手/拨号/config/测试代码 = 不报；
- `#[cfg(test)]` 模块内命中一律剔除。

**负优化审查（动手前查史，产出为路线图故以「风险注记」形式并入）**：
- `git log --grep=perf/池化/alloc/revert`：vision 池化已提交 7681f7cc（padding out-param + padding_scratch 容量流转 + downlink 直写复用）；波 A 28bce568（mux 帧读池化/vmess·SS·WS 零拷贝小修）；readv 零分配栈数组 092edf18；mimalloc 默认开 c9e11fc2。
- 回档信号 2 处：①`378ab889 Revert "bridge泵按Go getLink语义pipe解耦(8sum)"`→改道 f34d5ad6 方案A——**bridge 泵再动必须同窗配对 A/B**；②`d8562b56`+`a427613b` vision splice 触发条件两次 revert——**vision 的 gate/DIRECT 切换语义是雷区，池化改造不得触碰**。
- bd 交叉验证：xi40 四条中两条已修（见 §2.1/§2.2），vscd（vision）、lwwz（ws tungstenite 结构性）合并入清单。

**工具**：serena-cli warm rust 1 次（本审计为批量正则模式扫查 + grep 定位 + read 区间读，非符号级单点查询，未走 serena 符号寻址）；codebase-memory-mcp 不适用（分配模式不在图谱能力内）。

---

## 1. Findings 总表（按优先级）

> 分类：A=频繁分配-销毁/池化候选；B=可共享却深拷贝/共享化候选；C=数据结构性低效。

### P1（字节路径多拷贝/基线偏差，显著吞吐影响、低风险）

| # | 位置 | 分类 | 模式 | 热度证据 | 建议 | 风险 |
|---|---|---|---|---|---|---|
| F1 | xray-transport-splithttp/src/dialer.rs:92, dialer.rs:374 | B | 上行 POST 每 chunk `read_buf[..n].to_vec()`，随后进 request body | 每读满一次 `sc_max_each_post_bytes` 即执行，上传字节路径逐 chunk | `payload = Bytes::from(read_buf)` 所有权转移（Vec→Bytes 零拷贝）或 pooled BytesMut `split_to(n).freeze()` | 无 wire 变化；注意 `read_buf` 复用语义改为 split 后需 `resize` 回来 |
| F2 | xray-transport-splithttp/src/h3_client.rs:386 | B | h3 上传每 chunk `Bytes::copy_from_slice(b)` | h3 send_data 每 chunk 调用（stream-one 上行路径） | 上游持有 `Bytes` 时直传（`impl Into<Bytes>` 免拷）；`&[u8]` 路径为 h3 API 所限，仅能减不能免 | h3 crate API 约束，需核对 bytes 所有权链 |
| F3 | xray-transport-splithttp/src/hub/handler.rs:328 | B | 服务端收流每 chunk `Packet::new(chunk.to_vec(), seq)` | 入站每 h2/h3 body DATA 帧执行 | h2 body chunk 常为 `Bytes`（hyper）→ 直接存 `Bytes` 免拷 | Packet 字段类型从 Vec<u8>→Bytes，波及 upload_queue.rs 读取端 |
| F4 | xray-transport-grpc/src/encoding.rs:248-252, 306-310 | B+A | `encode_hunk_frame`：`Hunk::new(data.to_vec())` 拷贝① + `encode_to_vec` 拷贝②，3 次分配 | grpc up 泵每 32KB chunk 调用（transport.rs:240-243） | 一次 `Vec::with_capacity(FRAME_HEADER_LEN+1+varint_len+n)` 内直接序列化（tag+varint+copy 一次） | 纯本地重写，wire 不变；有 roundtrip 测试护栏（encoding.rs tests） |
| F5 | xray-transport-grpc/src/transport.rs:269-296 + encoding.rs:137-155, 204-229 | B+C | 下行 `acc.extend_from_slice(&d)` 拷贝① → `Hunk::decode` 内 `data.to_vec()` 拷贝② → `(used, vec![data])` 分配③ → `acc.drain(..used)` 每帧 O(n) memmove → `wr.write_all` 拷贝④ | grpc down 每帧执行；acc 在慢读快收时滞留多帧放大 drain 成本 | decode 改借用切片（返回 range），`wr.write_all(&acc[start..end])` 直写后单次 drain；消掉 to_vec 与 vec![] 包装 | 多帧粘包边界逻辑需测（decode_multi_hunk_frame 同改） |
| F6 | xray-transport-kcp/src/output.rs:57-58; listener.rs:218-221 | A | 每 segment `vec![0u8; seg.byte_size()]` + serialize + write_all | KCP flush 每个待发 segment 一次（sending.rs:334-336 循环）；小包高频 | writer 内持久 scratch buffer（对齐 Go output.go:32-35 `buffer.Clear()+Extend`） | 低；RetryableWriter 语义不变 |
| F7 | xray-transport-kcp/src/connection.rs:684 | A | `poll_read` 每次调用 `vec![0u8; buf.remaining()]`（含 spurious wakeup） | KCP 数据面每次 poll 读执行，虚假唤醒也分配 | persistent scratch（参照 vision_conn.rs `read_tmp: Vec::with_capacity(16*1024)` 字段化模式） | 需 `&mut self` 借用重构（KcpConn 已有 Mutex 状态字段模式可循） |

### P2（每帧/每读小分配族，累积放大）

| # | 位置 | 分类 | 模式 | 热度证据 | 建议 | 风险 |
|---|---|---|---|---|---|---|
| F8 | xray-buf/src/io.rs:76-78（trait 定义）+ 全链路包装层（stats.rs:87、default.rs:1528 CachedReader、endpoint_override.rs:89、timeout.rs 等） | A | `Reader::read_multi_buffer` 返回 `Pin<Box<dyn Future>>`——**每次读调用 1 次堆分配**，每层包装再叠一层 Box | 数据面每次 read_multi_buffer 都执行；bridge/vless/vmess/全 transport 读循环全走此 trait（bd xi40 第 4 条dyn Reader Box::pin，现码未修） | trait 改 RPITIT（`async fn`/`impl Future`）或 poll 化；分层包装合并 | 大面积签名变更，波及所有 Reader 实现；建议先在 bridge 泵热点路径做 poll 化试点——**注意 bridge 泵有 8sum 回档史，须同窗配对 A/B** |
| F9 | xray-mux/src/writer.rs:128-130（write_meta_only 每帧 `Vec::new`）、frame.rs:544-547（`write_to`→`to_bytes()` 每帧分配）、frame.rs:602-604（read_from 每帧 `vec![0u8; meta_len]`）、client.rs:693-700（read_frame 每帧 body 分配） | A | mux 每帧元数据编解码各 1-2 次小分配 | mux 会话每帧（含数据帧+End/KeepAlive 帧）执行；mux 开启时按帧放大 | meta 编码写入调用方 scratch（u16 len + ≤274B 常见体积可栈上/SmallVec）；读侧 body 帧走 buf 池（28bce568 已做帧读池化一部分，此为剩余 meta 路径） | wire 不变；注意 bd txhn 帧原子性语义（整帧单次落盘）不得破坏 |
| F10 | xray-xudp/src/packet.rs:228, 414 + xray-app-dispatcher/src/udp_session.rs:93-100（每包 `FrameMetadata::write_to`→`to_bytes` 分配 + frame Vec） | A | XUDP 每帧/每 UDP 包 2-3 次分配 | UdpDispatchSession 每 UDP 包执行（vless/vmess inbound UDP 路径） | 同 F9：meta 写入复用 scratch；packet body 走池 | 低 |
| F11 | xray-proxy-ss/src/config.rs:215-249（encode_packet/decode_packet 每包 iv to_vec + plaintext to_vec + zero_nonce + sealed）；protocol.rs:216-224, 233-234（UDP 解码兜底 3 次拷贝）；ss2022/packet.rs:238, 270, 392, 758（每 UDP 包 `plain[used..].to_vec()`/`enc_hdr.to_vec()`/`body.to_vec()`） | B | SS UDP 每 datapacket 全量拷贝 1-3 次 | SS UDP（含 2022）每包执行；DNS 查询等小包高频场景 | decode 借用切片返回 range；encode 复用 frame scratch（注意 chacha_plain 字段所有权） | wire 不变；SS2022 重放窗口逻辑勿动 |
| F12 | xray-transport/src/finalmask/udp.rs:71,152（每 recv_from `vec![0u8; UDP_SIZE]`）；finalmask/tcp.rs:145-146（循环内每 item `vec![0u8;2048]`+hello Vec）；finalmask/custom/evaluator.rs:258（每 UDP 包构建 out Vec） | A | finalmask 伪装层每包分配 | finalmask 启用时每包/每 item 执行（niche 场景） | recv scratch 字段化；evaluator 输出走调用方 scratch | finalmask 为小众特性，P2 末位 |

### P3（搭车批：低频/小对象/niche）

| # | 位置 | 分类 | 模式 | 热度证据 | 建议 | 风险 |
|---|---|---|---|---|---|---|
| F13 | xray-app-dispatcher/src/default.rs:1620-1623 `cached_bytes()` → `mb.to_vec()` | B | 嗅探时整包 flatten 拷贝（**bd xi40 第 2 条，现码仍在**） | 每连接嗅探 1-2 次（非每帧），低收益 | sniff 各 sniffer 直接迭代 `mb.iter()` 切片免 flatten | 低 |
| F14 | xray-proxy-vmess/src/encoding/body_chunk.rs 全套 `encode_chunk_stream*`/`decode_chunk_stream*`（每 chunk size_field/pad 分配 + `nonce_gen.next()` to_vec + cipher.seal 新 Vec；decode 返回**整流拼接单 Vec**） | A+B | 整 body 缓冲式 API | **生产 pump 已绕开**（dispatcher.rs:346/357 pump_up/pump_down、inbound/server.rs:381-385 pump_request_body/pump_response_body 均用 next_ref()+持久 chunk_buf+seal_into/open_in_place 零分配形态）；whole-body API 仅 client.rs/server.rs 包装 + 测试（inbound/server.rs:830-970 tests） | 生产无热路径成本；建议给 whole-body API 加 `#[doc(hidden)]`/注释「勿接入生产流」防未来误接线（整流缓冲=延迟+内存陷阱） | 无 |
| F15 | xray-transport-splithttp/src/upload_queue.rs:165 | B | 部分消费时 `rest.payload = rest.payload[n..].to_vec()` | 每次跨 read 边界的部分消费执行 | `Bytes` 存储后 `split_to(n)` 零拷贝 | 低（依赖 F3 的 Packet→Bytes 改造） |
| F16 | xray-mux/src/frame.rs:216-281 + xudp PacketWriter 每帧 `write_target_to_vec` | A | 见 F9/F10（合并搭车） | 同 F9 | 同 F9 | 低 |
| F17 | xray-transport-hysteria/src/gecko_socket.rs:156,189（每包 `Bytes::copy_from_slice`）；conn.rs:411（read future 内 `vec![0u8; remaining]`） | A+B | gecko 混淆每包拷贝进 channel | hysteria+gecko 每包执行 | channel 传 Bytes 沿用现有模式；conn read scratch 字段化 | gecko 分片重组语义勿动 |
| F18 | xray-transport/src/finalmask/custom/evaluator.rs:96-110, 150-155, 357, 406, 426-441 | A | 表达式求值每包多次中间 Vec（concat/slice/pack） | custom mask 每包执行（niche） | out 复用 + EvalValue 借用化 | 表达式语义勿动 |
| F19 | xray-transport/src/finalmask/salamander_gecko.rs:315-324, 341-344（重组每包 chunks Vec + flatten extend） | A+C | 分片重组每包建 chunks 表 | gecko 大包分片时执行 | chunks 池化/预分配 `vec![None; total]` 已是现状，assembly 输出复用 | 低 |
| F20 | xray-app-dispatcher/src/endpoint_override.rs:25-56（rewrite_complete_frames 每读 `Vec::new` out + `meta.clone()`） | A+B | endpoint override 每读重建输出 | 仅配置了 destinationOverride 的 UDP 流每读执行 | meta 写回原 buffer 就地改写 | 低 |

### 已修复/已登记（勿重复立项）

| 来源 | 条目 | 现状 |
|---|---|---|
| bd xi40 第 1 条 | freedom udp.rs 逐读 to_vec | **已修**：现码 udp.rs:250-253「池化 Buffer 直写：逐 buffer 单拷贝进 accum，免 to_vec 的中间分配+二次拷贝」 |
| bd xi40 第 3 条 | MultiBuffer remove(0) O(n) | **已修**：multi.rs:133-134 `drain(..1)` 单次 memmove（注释明示替代 remove(0)）；writer.rs:95 保留一处 ≤8 块 remove(0)（ponytail 注记：块数≤8 无关紧要） |
| bd xi40 第 2 条 | CachedReader sniff 整包 to_vec | 仍在（→F13，P3） |
| bd xi40 第 4 条 | dyn Reader Box::pin(+Sleep) | Box::pin 部分仍在（→F8，P2）；Sleep 注册部分已按 vy0 结论改为每轮 sleep_until 重建（cancel-safe 标准形态，非缺陷） |
| bd vscd (P1) | vision xtls_padding/xtls_unpadding 每帧 Vec + poll_write_vectored 多拷贝 | **主体已落地**：提交 7681f7cc（padding 改 out-param、padding_scratch 容量流转、downlink 直写复用、read_tmp 字段化）+ 工作树迭代（vision_conn.rs:252-256 pop_frame_recycle swap、vision.rs:149/198 scratch 参数化）；xor_conn.rs:34-37 4ucv 持久 write_buf。本票不重复立项，**仅作 A 类修复的建议写法范本** |
| bd lwwz | ws 每帧 `buf.to_vec()`（ws_bridge.rs:214） | 已定案不修：tungstenite 0.26 Sink API 结构性成本，fork 才能消除（注释 205-213 已留档）；维持登记 |
| bd z32z | REALITY mirror 载荷逐条重放 | 非 alloc 语义票，不在本审计范围 |

---

## 2. 分 crate 章节（全覆盖）

### xray-transport（本体）
- **bridge.rs**：池化泵（copy_pooled 池化 buf、merge_bytes 已消、write_all_mb 零拷贝 vectored、read future 每轮重建为 cancel-safe 文档化形态）——已优化到位（bd etks/VISIONMAC/y1yx）。测试代码命中全部剔除。**无新 finding**。
- **record_framer.rs / splice.rs / dialer.rs / system_dialer.rs / memory_settings.rs / cnc.rs / browser_dialer.rs**：命中均为握手/注册/测试级。cnc.rs:388 `to_vec` 在测试。**已查无发现**。
- **finalmask/**：F12、F18、F19。

### xray-transport-tcp
register.rs:24-27 闭包 per-dial clone（每连接 1 次，注册闭包所有权语义所迫）；dial 路径直透。**已查无数据面热路径发现**。

### xray-transport-websocket
- client.rs:288 `buf.to_vec()` 仅首写 early data（每连接 1 次）——不报。
- ws_bridge.rs:214 每帧 `buf.to_vec()`——**bd lwwz 已定案不修**（tungstenite 结构性），维持登记。

### xray-transport-httpupgrade
握手 leftover `to_vec`（server.rs:117、client.rs:103、deferred.rs:128,150）均为每连接握手级。升级后数据面为直透。**已查无热路径发现**。

### xray-transport-splithttp
F1（dialer.rs:92/374）、F2（h3_client.rs:386）、F3（hub/handler.rs:328）、F15（upload_queue.rs:165）。另 dialer.rs:81/363 `read_buf` 已池化（每 task 一次）。xpadding.rs:114 per-request（每 POST 一次，非每帧）→ P3 级以下不立项。

### xray-transport-grpc
F4、F5（encoding.rs + transport.rs dial_h2 down 泵）。服务端 gun 路径共用 HunkReader/MultiHunkReader（encoding.rs:430-545）同享 F4/F5 修复。

### xray-transport-kcp
F6（output.rs:57、listener.rs:219）、F7（connection.rs:684）。receiving.rs:319 每段 copy_from_slice 为拷入调用方 buf 的必要单拷贝；AckList 已带 capacity 128 预分配注释（对齐 Go NewAckList）。Go 基线 output.go:28-37 用持久 buf.Buffer 零分配（已核对 D:/Project/Xray-core）——F6 为对基线的真实偏差；每 segment 一次 writer.Write 的 syscall 形态与 Go 一致，非 Rust 特有回归。

### xray-transport-quic
transport.rs 命中均为 listen/probe/config 级；数据面走 quinn/h3 内部（包级 IO 在第三方栈）。**已查无 Rust 侧数据面热路径发现**。

### xray-transport-hysteria
已高度优化（现码注释为证）：conn.rs:472 poll_write 直通零 to_vec、:612-620 BytesMut::freeze owned 组包、quinn_adapter.rs:203-207 owned Bytes 直入 quinn 免 copy_from_slice、udphop.rs:66-68 BufPool 对齐 Go pool.Get/Put、salamander_socket.rs:140-141 收发 scratch 持久化。残留 F17（gecko）。conn.rs:105-108 逐字节 read 为 auth 帧解析（每连接级，注释已论证 quinn read 语义所迫）——不报。

### xray-transport-naive
PaddingDecoder 的 rdbuf 16KB 持久化（dial.rs:236）、decode 输出走调用方 out。命中余为握手/测试。**已查无热路径发现**。

### xray-tls / xray-reality
client_config.rs/btls_* /certificate.rs/ech* 命中全为 config/握手级；record 级加密在 rustls/btls 内部。reality probe 为后台探测任务。**已查无数据面热路径发现**。

### xray-proxy-vless
数据面 = vision_conn（工作树池化中，不在范围）+ 透传。inbound/server.rs 命中为每连接预读（first buf）/测试；dispatcher.rs:406 uuid to_vec 每连接 1 次。**vision 外无新 finding**。

### xray-proxy-vmess
生产 pump 全部零分配形态（pump_up/pump_down/pump_request_body/pump_response_body/pump_udp_session：`next_ref()` 零分配 nonce + 持久 chunk_buf + seal_into/open_in_place）。whole-body API = F14（P3 防误接）。aead/mod.rs:289-292 KDF 每长度块 2 个小 to_vec（协议规定的 per-chunk nonce 派生，Go 同型 KDF 调用；仅 path_segments 容器分配可省）→ P3 以下，搭车可顺手改数组借用。

### xray-proxy-ss
F11（config.rs UDP per-packet 族、protocol.rs 解码兜底、ss2022/packet.rs 每包拷贝）。TCP 流路径：dispatcher.rs:145-147 泵缓冲每 task 一次复用；stream.rs 单写合并已落地（014fcdb1 G2Perf）。inbound/ss2022 握手命中为每连接级。

### xray-proxy-trojan
sweep 命中仅测试与 config（协议头 sha224 每连接 1 次），数据面 auth 后直透。**已查无数据面热路径发现**。

### xray-proxy-tuic
dispatcher.rs:230/252 泵 `vec![0u8; 8*1024]` 每 task 一次循环复用；client.rs 控制帧 BytesMut::with_capacity 每命令（连接级/心跳级）。**已查无每帧级发现**。

### xray-proxy-hysteria
inbound.rs/protocol.rs 命中为握手/测试级（数据面走 xray-transport-hysteria 的 quinn 通道）。**已查无数据面热路径发现**。

### xray-proxy-anytls
server.rs/outbound.rs 泵缓冲每 task 一次复用（8KB）；首帧 `buf[consumed..n].to_vec()` 每连接 1 次。**已查无每帧级发现**。

### xray-proxy-wireguard / xray-proxy-tun
sweep 命中以 config/proto 转换与测试为主；数据面在 netstack（smoltcp 栈）。模式级扫查未见每包全量拷贝命中；**未做 netstack 内部逐行审读**（诚实声明：置信度低于其他章节）。

### xray-proxy-socks / xray-proxy-http / xray-proxy-dokodemo / xray-proxy-blackhole / xray-proxy-loopback / xray-proxy-dns
socks（readv 接线已落地 ee2ef3db）/http 为每请求解析级；dokodemo fakeudp 每包小分配（UDP 低频，P3 以下）；blackhole/loopback 无数据面缓冲。**已查无显著发现**。

### xray-proxy-freedom
udp.rs 逐读 to_vec **已修**（xi40 闭环，udp.rs:250-253）；fragment.rs:100-121 分片仅 TLSHello 首写触发（每连接 1 次）。**无新 finding**。

### xray-xudp
F10（packet.rs 每帧 body 分配）。见 P2。

### xray-buf
核心读写已池化：alloc.rs 分层 TLS_CACHE + Buffer::new 走池（buffer.rs:377/393 release 回池）；multi.rs drain 单次 memmove；readv 单缓冲快速路径（56977640）+ 零分配栈数组（092edf18）。pipe.rs 环形管道零拷贝。残留 F8（Reader trait boxed future，trait 层面问题，buf 层自身无错）。tests/readv_perf.rs 已有性能测试基建。

### xray-core
inbound.rs/outbound.rs/router.rs 命中全为装配/每连接级（handle_plain_http:644 已用池化 buf；mux inbound 帧循环复用 xray-mux worker——帧级成本归 F9）。**已查无新发现**。

### xray-mux
F9（writer.rs:128、frame.rs:544/602、client.rs:693）。28bce568 已做帧读池化一部分，本条为 meta 编解码路径残留。

### xray-app-dispatcher
F8（默认包装链）、F10（udp_session.rs）、F13（CachedReader sniff）、F20（endpoint_override）。default.rs pump/bridge 装配层无每帧分配。

### xray-app-dns（附带）
nameserver 命中全为每查询控制级；recvmmsg 批收已落地（508c3b26）。**已查无数据面热路径发现**。

---

## 3. 优化路线图（按 收益×风险 排序）

**批次 P1（字节路径去拷贝，预计净收益最大）**
1. F1+F3+F15（splithttp 族）：Packet payload 与 request body 统一 `Bytes` 化，`Bytes::from(Vec)`/`split_to().freeze()` 所有权转移。wire 零变化，回归护栏 = splithttp 既有 interop + e2e。
2. F4+F5（grpc 族）：hunk 序列化单次成型 + down 泵借用化解码直写、消 drain。护栏 = grpc interop 双向 + 多帧粘包单测。
3. F6+F7（kcp 族）：writer 持久 scratch + poll_read scratch 字段化。护栏 = kcp tests（--test-threads=1）+ e2e。

**批次 P2（每帧/每读小分配）**
4. F8（Reader boxed future）：先做 bridge 泵 poll 化试点——**8sum 回档史约束：同 binary 同窗交替 A/B，禁跨窗对比**；全 trait RPITIT 化单列一票评估波及面。
5. F9+F10（mux/xudp meta scratch）+ F16 合并搭车。
6. F11（SS UDP 拷贝族）。
7. F12+18+19（finalmask，搭车批）。

**批次 P3**
8. F13、F14（文档化防误接）、F17、F20 及其余搭车项。

**回归保护（建议随批次落地）**
- 每批次跑 `tests/readv_perf.rs` 级 micro-bench + stress.yml 压测场景（s5-s12）前后对比（同 binary 同窗交替，禁跨窗对比——30gf 方法论）。
- loopback 单流吞吐基线（现 ~1200Mbps）作为冒烟闸：批次落地后不低于基线 95%。
- 功能回归：全套 integration + interop 双平台（本地门须镜像 CI 宽门：clippy --workspace --all-targets、cargo doc、stable fmt）。

## 4. 架构建议
- **locality**：本审计所有修复点都在各 transport/proxy crate 内部（scratch 字段化、序列化单次成型），无跨 crate 接口变更（F8 除外）——F8 单列正因它是唯一需要动 trait 契约的项。
- **deletion test**：F14 的 whole-body API 若确认无生产调用方， deletion（删除或 hidden）优于维护两套语义；建议在 F14 落地票中先 grep 全仓 caller 定夺。
