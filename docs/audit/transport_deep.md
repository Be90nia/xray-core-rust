# 传输层协议深度审计（第二轮：字节级 / 状态机级）

- 日期：2026-09-06；基线：D:/Project/Xray-core（v26.7.28）；目标：D:/Project/Xray-core-rust
- 范围：mKCP / gRPC(含 h2 面) / WebSocket / splithttp+xhttp / QUIC(hysteria+tuic 共用面) / TUIC / xray-transport-quic
- 切面：①状态机（重传/退避/窗口/流控）②帧编解码边界（长度/序号回绕/粘包）③关闭语义 ④重连/恢复（mtu 探测/路径验证）⑤错误分类
- 方法：逐文件与 Go 基线对照 + 关键算法外部真值对拍（RFC 7541 Huffman 表、h2 0.4.15 / quinn-proto 0.11.17 / quic-go v0.59.1 源码）。所有行号为当日 HEAD 实测。
- 与第一轮不重复：第一轮位置清单（socks/http/tuic h3.rs:182 帧长/reverse/dns/ss/mux/vless ENC/burst/trojan/btls/buf/common_conn/finalmask/wiring/httpupgrade/freedom/dns config/register FakeDNS/btls_client 指纹/policy/xcicmp）均未重复收录；splithttp mode 语义已回退、finalmask spawn 已报，均未收录。

## 严重度统计

| 级别 | 数量 |
|---|---|
| P1 | 3 |
| P2 | 16 |
| P3 | 9 |

TOP3：
1. **[P1] hysteria UDP 中继与 Go 基准互通断裂**（Go 侧 2026-09-01 日期门触发 OmitMaxDatagramFrameSize，quinn 判 peer 不支持 DATAGRAM，send_datagram 全部失败）
2. **[P1] gRPC multiMode 多元素 MultiHunk 帧静默截断**（生产解码恒取首元素并丢弃整帧余量 → bulk 流量静默数据丢失）
3. **[P1] mKCP 服务端会话表永久泄漏**（Writer::close 空实现，Go 对照为 delete(sessions, id)）

---

## 1. mKCP（crates/xray-transport-kcp）

### [P1] ListenerWriter::close 空实现 → 服务端 sessions 表永久泄漏
- 位置：`crates/xray-transport-kcp/src/listener.rs:223-228`；Go 对照 `transport/internet/kcp/listener.go:167-170`
- 证据（Rust，注释自认简化）：
```rust
impl ConnectionCloser for ListenerWriter {
    fn close(&self) {
        // 实际 remove 需要访问 Listener（Go 中 writer 持有 listener 引用）。
        // 简化：close 时仅 hub.close 由 Listener.close 统一处理。
```
  Go：`func (w *Writer) Close() error { w.listener.Remove(w.id); return nil }`，而 `Connection.Terminate()`（connection.go:531-543）必经 `closer.Close()` 触发 remove。全 crate 检索：`Listener::remove` 仅一处测试调用，无生产路径。
- 影响：服务端每条连接到达 Terminated（或 30s stale）后，`HashMap<ConnectionId, Arc<Connection>>` 条目不删除，内存无界增长（DoS 面）；且同 (src,conv) 的新连接包会继续投喂给死会话（`on_receive` 命中旧条目），重连被锁死到旧条目 30s stale 为止。
- 修复：`ListenerWriter` 持 `Weak<Listener>`（或 id + Weak），`close()` 里 `remove(&id)`，与 Go 完全对齐。

### [P2] globalConv 从不随机初始化 → 进程重启后 conv 确定性回归
- 位置：`crates/xray-transport-kcp/src/dialer.rs:15-28`（`GLOBAL_CONV: AtomicU32 = AtomicU32::new(0)`；`init_global_conv` 仅测试调用，生产 `register_dialer` 未调用）
- Go 对照：`globalConv = dice.RollUint16()`（包初始化随机种子）。
- 影响：每次进程重启首个连接 conv=1、第二个 conv=2……结合上条泄漏，服务端残留 (src,conv=1) 会话时新连接 100% 撞上死会话；Go 概率 1/65536。
- 修复：`static GLOBAL_CONV: AtomicU32 = AtomicU32::new(...)` 无法直接随机；用 `LazyLock`/首次 `next_conv` 时以随机数播种。

### [P2] AckList::flush_candidates 容量恒 0 → Go 的延迟 ACK 补发机制成死代码
- 位置：`crates/xray-transport-kcp/src/receiving.rs:87`（`flush_candidates: Vec::new()`，容量 0）、`:145`（`len < capacity` 恒假，永不入列）、`:166-172`（补段循环恒空集）
- Go 对照：`receiving.go:79` `flushCandidates: make([]uint32, 0, 128)` + `:127-134` 未到 flush 时间的 number 进 candidates，收尾时补进当前未满段立即发出（不更新 nextFlush）。
- 影响：Rust 每个已 ACK 但处于 rto/2(≥20ms) 节流窗内的 number 不会被捎带补发，丢包路径下对端 fast-retransmit 触发变慢（依赖 HandleFastAck 的冗余 ACK 减少）；同时留下永不执行的分支。
- 修复：`Vec::with_capacity(128)` 即可恢复 Go 语义。

### [P2] kcpSettings 零校验（mtu≥21 / tti∈[10,1000] / cwndMultiplier≥1，负数回绕）
- 位置：`crates/xray-transport-kcp/src/register.rs:221-253`（`parse_kcp_config` 逐字段 `as_i64 → as u32` 直接赋值）
- Go 对照：`infra/conf/transport_method.go:564-577`：`Mtu<21` / `tti<10||tti>1000` / `CwndMultiplier<1` / `GetSendingBufferSize()==0` 四条硬校验，违者启动报错；且 JSON number 解析阶段负数进不了 `*uint32`。
- 影响：`mtu=0/-1`（回绕成 4294967295）等非法配置静默接受：`mss=mtu-18` 饱和为 0 → `Connection::write` 全部产出 0 长度段；`tti=1` 时 updater 每 1ms 空转 flush。行为与 Go 完全相反（Go fail-fast）。
- 修复：parse 末尾补 Go 同款四条校验；`as u32` 前检查非负。

### [P2] UDP 收包缓冲 1500B 硬截断（Go 为 buf.Size=2048）
- 位置：`crates/xray-transport-kcp/src/udp_hub.rs:97`（服务端 `recv_from` 缓冲）、`:162`（客户端 `StdPacketInput::read_packet` 同为 1500）
- Go 对照：`transport/internet/udp/hub.go:107-118`：`buffer.Extend(buf.Size)`（xray buf.Size=2048）。
- 影响：UDP 数据报超长时 `std` 静默截断（无错误返回）→ 段解析失败整包丢弃。双方一致配置 `mtu>~1480`（或 mask 链开销叠加）时 Go↔Go 互通而 Rust 单边坏。属配置相关但触发条件完全由用户可控。
- 修复：缓冲提升至 ≥2048 对齐 Go，或按 `config.mtu + DataSegmentOverhead + mask 开销` 动态分配。

### [P3] 两处低风险偏差（记录在案，不建议当缺陷修）
- `segment.rs` DataSegment::parse 最短 14B（Go segment.go:61 为 15B）：Rust 更宽松，仅影响 Go 端发 0 载荷 DataSegment 的假想场景，互通方向安全。
- 生产接线用 `SimpleSegmentWriter`（register.rs:334），未包 Go 的 `RetryableWriter`（5×100ms 重试，output.go:44-50）：数据段有 RTO 重传、ACK 有 acklist nextFlush 重发兜底，仅瞬时 UDP 写错误下少一次即时机会。

### 确认干净（抽查点）
1. 重传/退避：`prepare_flush` 与 Go `SendingWindow.Flush` 逐行等价——timeout 判定 `current.wrapping_sub(seg.timeout)>=0x7FFF_FFFF`、首传计数、`max_in_flight` 停止条件、loss rate `lost*100/totalInFlight`（含 Go 的 rto==0 早退路径差异仅在 adjust_control_window 无早退，初始 rto=100 非零故不可达）。
2. RTT/RTO：`round_trip.rs` 与 Go RFC6298 公式逐分支一致（srtt==0 初始化、delta 绝对值、min_rtt 钳制=tti、10000ms 上限、×5/4；有单测钉住 750/337/12500）。
3. 序号回绕：`process_ack`/`clear_before`/`handle_fast_ack` 全部 `wrapping_sub` + 0x7FFF_FFFF 判定，与 Go 位运算一致；`next_conv` u16 回绕有测试。
4. 状态机：6 态转移（Active/ReadyToClose/PeerClosed/Terminating/PeerTerminating/Terminated）在 `close()/on_peer_closed()/input(Terminate)/flush_inner` 四个入口与 Go connection.go 逐分支对照一致；flush 内联转移省略的 `pingUpdater.SetInterval(1s)` 实为 Go 死代码（Go ticker 构造后不随 SetInterval 变化），Rust 的 TokioUpdater 反而实时生效，语义等效偏优。
5. 参数映射：`config.rs` 三个派生公式与 Go config.go 逐字符一致（含 /mtu/(1000/tti) 整除序、8 下限），默认值 1350/50/5/20/1/2MiB 与 Go init() 一致（有对拍测试）。
6. 输入分发：`Input` 对 conv 不匹配 break、Terminate 的 5 态转移、CmdOnly 三元组转发（sending/receiving next、peer RTO 3s 节流）与 Go 逐行一致。

## 2. gRPC（crates/xray-transport-grpc）

生产路径 = `transport.rs` 直写 h2（hyper 不在 wire 路径）；`encoding.rs` 的 HunkStream/`client.rs` GrpcClient 为测试层死代码（不影响下述结论）。

### [P1] multiMode 下多元素 MultiHunk 消息被静默截断 → 数据丢失
- 位置：`crates/xray-transport-grpc/src/transport.rs:85` 与 `:151`（生产解码恒走 `decode_hunk_frame` 并 `acc.drain(..frame_end)`）；`encoding.rs:296-302`（返回 `(frame_end, hunk.data)`，`hunk.data` 仅首个元素；`Hunk::decode` :134-162 无 `data_end == payload.len()` 校验）
- Go 对照：`grpc/encoding/multiconn.go` `WriteMultiBuffer` 把**全部非空 buffer 合并进一条** `MultiHunk{Data: hunks}` 消息（`repeated bytes`）；单元素时 Hunk 与 MultiHunk wire 字节相同（皆 `0x0a len data`），多元素时 Rust 只取 `0x0a len1 data1` 并把**整帧余量连同 `0x0a len2 data2...` 一并 drain 丢弃**。
- 触发+影响：`multiMode=true` 对真 Go 对端，bulk 流量一次写必然产生多 buffer 合帧 → 每帧只保留第一段，中间段静默丢失（TLS record/HTTP 流错位，无任何报错）。Rust 上行恒单元素帧，对 Go TunMulti 侥幸兼容，故仅 Go→Rust 方向丢数据。
- 修复：`cfg.multi_mode` 时改用已有 `decode_multi_hunk_frame`（encoding.rs:322，现生产不可达）并顺序拼接 `data_vec`；或至少在 `Hunk::decode` 加 `data_end == buf.len()` 断言让错配快速失败。

### [P2] 客户端永不发送 :authority，config.authority 为死字段
- 位置：`transport.rs:53-56`：`Request::builder().method("POST").uri(path)`（path-only URI，未设 `version(HTTP_2)`）→ h2 0.4.15 `client.rs:1638-1648`：scheme/authority 均缺且 version=HTTP_11 时仅补 `:scheme: http`，`:authority` 恒缺；`config.rs` 解析的 `authority` 全 crate 无消费点。
- Go 对照：`grpc/dial.go:157-164` authority 三级回退（settings → tls ServerName → dest）+ `grpc.WithAuthority`。
- 影响：依赖 :authority 路由/校验的 CDN/中间件行为分歧；带 authority 的用户配置静默无效；与 Go 的 h2 指纹可区分（gRPC 主要使用场景恰是 CDN 前置）。
- 修复：builder 显式 `.version(Version::HTTP_2)` 并按 Go 回退链补 authority（完整 URI 或 header 注入）。

### [P2] 响应不校验 :status / content-type → 非法响应静默截断而非快速失败
- 位置：`transport.rs:76-88`：`resp_fut.await` 后直接 `into_body()`，status/content-type 全程未读。
- Go 对照：grpc-go 对 `:status != 200` 与缺 `application/grpc` content-type 立即返回类型化错误（hunkconn.go:52-58 forceFetch 将其分类为 stream 失败 → xray 立即重建连接）。
- 影响：CF challenge/404/502 的 HTML body 前 5B 被当帧头：payload_len≤4MiB 时 `Ok(None)` 挂起到流结束（误判半关闭），否则报与真实原因无关的 IO 错——正是 B 类（CF 严格指纹）节点的排障黑洞。
- 修复：`resp.status()==200` + content-type 前缀校验，失败即带状态码报错。

### [P2] GrpcListener::close 为 no-op；accept 循环对 Err 无条件 continue
- 位置：`transport.rs:183-185`（`fn close(&self) -> io::Result<()> { Ok(()) }`，listener 句柄未保存无法关闭）、`:109-113`（`Err(_)=>continue` 无退避无停机）
- Go 对照：`grpc/hub.go:62-64` `Close → l.s.Stop()`，Serve 退出有日志。
- 影响：inbound 重载/关闭后 TCP 端口仍被占用、新连接仍被接受（资源泄漏+行为分歧）；EMFILE 等永久错误时 accept 烧 CPU。
- 修复：保存 `TcpListener` 句柄或 `Notify` shutdown；对 accept 错误区分 `ErrorKind::ConnectionAborted` 等瞬时类与永久类。

### [P2] send_data 不等流控窗口 → h2 库内无界缓冲，失去端到端背压
- 位置：`transport.rs:71`（client 上行）、`:150`（server 下行）：`send_stream.send_data(Bytes::from(frame), false)` 直发，未走 `poll_capacity`/`reserve_capacity`；h2 0.4.15 `share.rs:48-56` 文档明示无库内上限。
- Go 对照：`hunkconn.go:108-118` 经 grpc `SendMsg`，grpc-go transport 等待 flow-control quota 才写。
- 影响：对端停读（慢消费者）时 Rust 侧内存无界增长、上游 relay 不被反压；Go 同场景稳态内存受限。
- 修复：发送循环改为 `poll_capacity` → 按授权量切片组帧。

### [P2] 6 个配置字段解析但不生效（keepalive/初始窗口/UA/拨号超时）
- 位置：`config.rs` 解析 `authority/idle_timeout/health_check_timeout/permit_without_stream/initial_windows_size/user_agent`；`transport.rs:46` 用默认 `client::handshake`（h2 无自动 keepalive，`ping_pong()` 全库未用）、`:24` `TcpStream::connect` 无超时无退避。
- Go 对照：`dial.go:101` MinConnectTimeout 5s + `:93-100` 指数退避、`:166-170` keepalive 参数、`:174-175` 初始窗口、`:190-204` 浏览器 UA 注入。
- 影响：配置 idle_timeout 的节点无 PING 保活 → 长闲连接被 NAT/CDN 掐死且无探测；无 UA 指纹分歧；对被墙 IP 挂 OS 级 TCP 超时（数十秒）无 5s 上限。
- 修复：至少接 `idle_timeout → h2 ping_pong 周期任务` 与连接超时；UA 注入属指纹面，与 btls/u_client 政策统筹。

### [P3] server 不校验 :path 与 content-type
- `transport.rs:133-141` 仅查 method=POST，任意路径任意头一律 200 application/grpc 并交给 inbound。Go 经 grpc-go 路由精确匹配 `/{service}/{tun}`、未知路径 Unimplemented、非 gRPC content-type 415。主动探测面与 Go 可区分。

### 确认干净（抽查点）
1. 5B 帧编解码：`FRAME_HEADER_LEN=5`、`MAX_FRAME_PAYLOAD=4MiB`=grpc-go 默认收包上限、encode 侧 32KB 读块不可能溢出 u32（encoding.rs:247-282 有单测）。
2. varint 上下限 10 字节，无无限移位（encoding.rs:~420-445）。
3. 粘包/跨 DATA 帧截断：client 下行与 server 上行均 `acc` 累积池 + `loop { decode, None=>break }`（transport.rs:79-88/:151），合并帧/拆帧均正确。
4. 半关闭：上游 EOF → `send_data(Bytes::new(), true)` END_STREAM（transport.rs:68/:150），等价 Go Close=cancel+CloseSend（hunkconn.go:120-128）；错误上抛 → duplex 关闭，与 Go forceFetch io.EOF 分类一致。
5. HEADERS 后立即泵 DATA 不等响应头（transport.rs:57-60，含 interop 注释）——Go gun 语义，此前挂死已修，本轮复核无回退。
6. 服务名/路径转义 `normalize_grpc_path` 与 Go getServiceName/getTunStreamName 逐分支等价（含 "/foo" 退化分支，4 个边界单测）。
7. 压缩帧：compressed=1 无 grpc-encoding → 显式错误（encoding.rs:287-294）；Go 双向未注册 compressor，失败路径等价。

## 3. WebSocket（crates/xray-transport-websocket）

### [P2] 客户端 early data 恒不发送（Ed>0 配置无效）
- 位置：`crates/xray-transport-websocket/src/register.rs:199`：`early_data: None` 硬编码；`client.rs:186-199` 的 Sec-WebSocket-Protocol 注入实现完整但永不触发。
- Go 对照：`dialer.go:39-49 + 100-104`：`Ed>0` 时 delayDialConn 缓存首写并 `header.Set("Sec-WebSocket-Protocol", base64url(ed))` 随握手发出。
- 影响：Ed>0 配置下 Rust 客户端无 0-RTT（首字节 +1 RTT），且握手头与 Go 客户端指纹不同（ed 头缺失）——WS/CDN 指纹敏感场景的分歧点。
- 修复：dial_ws 解析 `cfg.ed>0` 后用现有 delay/缓冲机制喂 `early_data`（server 端 server.rs:225-226 已支持接收）。

### [P3] 客户端 heartbeatPeriod 解析但不启动心跳
- `register.rs` `dial_ws` 得到 `WsConnection` 后未调 `start_heartbeat`（server.rs:222-224 服务端有调用）；Go `connection.go:24-33` 在 NewConnection 里双端统一启动 ping goroutine。影响：仅客户端配置心跳时无 NAT 保活（若服务端配了心跳，客户端 tungstenite 自动 pong 可部分兜底）。

### [P3] Host 头回退链缺 ServerName 级
- `client.rs:118-133`：`cfg.host` 非空才覆盖 Host，否则保留 URI authority（=拨号地址）；Go `dialer.go:86-92`：Host → tlsConfig.ServerName → dest 地址三级。影响：`wss + IP 拨号 + SNI 域名`组合下 Host 与 Go 不同，按 Host 路由的 CDN 错位。

### [P3] Text 帧按协议错误断链
- `ws_bridge.rs:131-137`：收到 Text 帧 → `InvalidData` 硬错误。Go gorilla `NextReader` 同样接受 Text 数据帧并把载荷交给上层。中间件/异常对端改写帧类型时 Go 连接存活、Rust 断链。

### 确认干净（抽查点）
1. 帧编解码（掩码、分片、控制帧 ≤125B、close 握手）全部由 tokio-tungstenite 0.26 承担，Rust 侧无手写帧路径（handshake.rs 仅常量/AcceptKey，与 RFC 对拍有测试）。
2. 读路径：一条 Binary 消息跨多次 poll_read 的余量保存在 `read_buf: VecDeque`，消息间不串流（ws_bridge.rs:96-128）；空 Binary 跳过与 Go 的 0 字节 EOF 语义一致。
3. 写路径：poll_write 每消息 `poll_flush` 内联（ws_bridge.rs:203-217）——符合 v51 铁律（写后必 flush、Pending 不丢唤醒），无 BufWriter 滞留同族缺陷；poll_shutdown 发 Close 帧（poll_close）。
4. 心跳任务共享写锁 `Arc<Mutex<SplitSink>>`，Drop abort 无泄漏（有运行时测试钉 ping 帧发射）。
5. ALPN 钉 `http/1.1`（register.rs:179-184，防 CDN 协商 h2 后 upgrade 失败）——与 Go `tls.WithNextProto("http/1.1")` 一致。
6. `?ed=N` 提取/删除/键排序/QueryEscape/Atoi 边界（负数回绕、溢出钳制、空值门）与 Go `WebSocketConfig.Build` 逐条对齐（20+ 单测）。
7. accept 循环有 close_notify 停机路径，TcpListener 随句柄 drop 关闭（无 gRPC 式 no-op close 问题）。

## 4. splithttp / xhttp（crates/xray-transport-splithttp）

### [P2] HUFFMAN_BITS 表 19 处错值（15 个 base62 字符）→ tokenish padding 长度系统性偏差
- 位置：`crates/xray-transport-splithttp/src/xpadding.rs:49-70`（表）、`:72-75`（`huffman_encode_length`）、`:201-218`（`is_padding_valid`）
- 证据：以 RFC 7541 Appendix B 原文脚本化对拍 256 项，19 处不一致，其中 base62 字符 15 个：`'e' 6≠5, 'g' 5≠6, 'h' 7≠6, 'i' 7≠5, 'j' 6≠7, 'k' 6≠7, 'm' 5≠6, 'o' 7≠5, 'q' 5≠7, 'r' 5≠6, 's' 6≠5, 't' 7≠5, 'u' 7≠6, 'y' 15≠7, 'z' 11≠7`（另有 `{|}~` 4 处非 base62 也错；'X'/'Z'=8 恰好正确，repeat-x 不受影响）。96-127 行区间呈错位/抄写特征。
- Go 对照：`xpadding.go:96` 用真 `hpack.HuffmanEncodeLength`；IsPaddingValid 容差仅 ±2。
- 影响：`xPaddingMethod:"tokenish"`（新一代 xhttp 抗探测配置，恰是 B 类节点常用）时，Rust 客户端按错表把 padding 调到目标长度，真实 HPACK 长度偏离约 15%（百字节级 padding 偏差数十字节，远超 ±2）→ Go 服务端 IsPaddingValid 拒收 → 连接被弃；反向 Go 客户端 → Rust 服务端经 `validate_padding`（hub/handler.rs:388-400）当前是简化非强制路径，影响有限。
- 修复：脚本从 RFC/Go hpack 生成表替换，并加"256 值逐项对拍 + 随机 base62 串与 Go 一致"的单测。

### [P2] 乱序/重复 seq 永久毒化 reorder 堆（Go 静默丢弃）
- 位置：`crates/xray-transport-splithttp/src/upload_queue.rs:217-226`（channel 分支 `seq != next_seq` 一律入堆，无 `seq < next_seq` 丢弃分支）；Go 对照 `upload_queue.go:88-107`：pop 后 `Seq==nextSeq` 交付、`Seq>nextSeq` 回堆等待、**两者皆否（Seq<nextSeq）静默丢弃**。
- 影响：迟到的重复 POST（HTTP 层重试/代理重放）使堆头永远不是 next_seq，新包持续堆积直到 `PacketQueueTooLarge` 拆会话；Go 同输入自愈继续服务。
- 修复：出堆/入堆前 `if packet.seq < inner.next_seq { skip }`。

### [P3] close() 语义：drain 后继续交付 vs Go 立即 EOF
- `upload_queue.rs:120-147` close 时排空 channel 入堆供 read 继续消费；Go `Close()` 仅 `closed.Close()`，Read 立即 EOF 丢弃全部在途数据。调用方（hub/handler.rs:284-285）以 `Ok(0)=EOF` 收尾，无卡死风险；仅与 Go 的"关闭即中止"语义不一致（Rust 更优雅）。

### [P3] Packet 无 Reader 流式路径（整 POST 缓冲后入队）
- `upload_queue.rs:18-19` 注明简化；Go `upload_queue.go:30-46` 首个 POST body 以 `Packet.Reader` 流式直读。内存上限变为"并发 POST body 总量"，无正确性问题；大上传（默认 maxUploadSize 分片下界可控）可接受。

### 确认干净（抽查点）
1. tokenish 迭代算法（初始 n=ceil(target/0.8)、±2 收敛、X/Z 交替、len≤1 保护、150 iter 上限、空串回退 "X"*n）与 Go xpadding.go:89-125 逐行一致。
2. `randStringFromCharset` 拒绝采样（limit=256-256%m）一致；`GeneratePadding` 各 method 分支一致。
3. reorder 主干：顺序交付/partial read（nextSeq 仅在整包消费后推进，与 Go 相同）/`maxPackets` 超限拆除/0 字节 payload 回归（有 Go Test_regression_readzero 对应单测）。
4. placement 注入（query/cookie/header/queryInHeader → RequestMeta）与 Go ApplyXPaddingToRequest 四分支对齐；`get_normalized_x_padding_bytes` 默认 100-1000 一致。
5. 服务端 30s noDownload reap（session.rs）+ GET 到达 mark_fully_connected 关 reap，与 Go hub 会话生命周期对齐。
6. 本轮未复检项（第一轮已报或已有结论）：mode 语义（已回退）、finalmask spawn（已报）。

## 5. QUIC 共用面：hysteria + tuic（crates/xray-transport-hysteria / xray-proxy-tuic）

### [P1] Go 侧 OmitMaxDatagramFrameSize 日期门已触发 → quinn 判 peer 不支持 DATAGRAM，hysteria UDP 中继 Rust↔Go 断裂
- 证据链：
  - Go `transport/internet/hysteria/dialer.go:95-96`：`OmitMaxDatagramFrameSize: time.Now().After(time.Date(2026, 9, 1, ...))` ——今天（2026-09-06）恒真；hub.go:274 同时设 `AssumePeerMaxDatagramFrameSize: MaxDatagramFrameSize`（非标豁免）。
  - quic-go v0.59.1（go.mod apernet/quic-go@v0.59.1-0.20260425）`connection.go:351/480`：`if EnableDatagrams && !OmitMaxDatagramFrameSize { params.MaxDatagramFrameSize = ... }` —— 置位后**不发送 max_datagram_frame_size TP**（interface.go:174-179 文档原文"omits ... even when QUIC datagram support is enabled"）。
  - quinn-proto 0.11.17：peer TP 缺省为 `None`（transport_parameters.rs:125），发送侧 `datagrams.rs:79-83` 对 `None` 返回 `SendDatagramError::UnsupportedByPeer`（:229-231）；quinn 无 AssumePeer 等价配置。
  - Rust 消费点：`quinn_adapter.rs:193-201` `send_datagram` → `conn.rs:758-765` hysteria UDP 会话 write_fn 全部经此路径。
- 影响：Rust↔Go hysteria 的 UDP 代理（QUIC DATAGRAM 承载）双向不可用（客户端/服务端发送方向都命中 UnsupportedByPeer）；Go↔Go 因 AssumePeer 互相豁免照常工作。TCP-over-hysteria 走 QUIC STREAM 不受影响——所以 32 节点 TCP 验收未暴露。tuic native 模式（udp.rs:117）对 quic-go 系对端存在同族风险（EAimTY/tuic 的 quic-go 配置未核，列为风险注记）。
- 修复方向：quinn 0.11 无 peer-TP 假设开关——①握手后首次 send_datagram 探测失败即降级为 stream 承载（hysteria 协议允许 UDP over stream 的 v5 兼容形态需查）；②patch quinn-proto 增加可配置 assume-peer TP（最小侵入：peer TP None 时按常量 1200 处理），并向上游报 issue；③跟踪 quic-go/RFC9221bis 将 TP 改为可选的正式语义。

### [P2] 接收窗口映射丢失 initial→max 两级
- `quinn_adapter.rs:309-315`：`stream_receive_window = max(initial, max)` 单值注入；Go `dialer.go:86-109` 传 quic-go 双级窗口（initial 起步、auto-tune 到 max）。影响：quinn 从一开始即按峰值（默认 8MiB/流、20MiB/连接）授权，多连接/低带宽场景接收内存放大 ~2.5×；功能正确仅资源语义偏差。修复：quinn 无两级，建议取 initial 值并注释差异。

### [P3] datagram_receive_buffer_size 硬编码 8192
- `quinn_adapter.rs:287`：≈6 个 MTU 级 datagram 的接收缓冲，满即丢（DATAGRAM 无重传）。Go quic-go 的 datagram 队列行为不同。建议随配置暴露。

### 确认干净（抽查点）
1. quicParams JSON→校验→默认值三段与 Go infra/conf:2153-2240 + dialer.go:98-115 逐条对齐（65536/16384/45/5/8 等边界有 20+ 校验单测）；带宽字符串 `uint64(val*mul)/8` 先截断再整除的 Go 语义有对拍测试。
2. idle 默认 30s、keepalive 默认关、MaxIncomingStreams 默认 1024（hub.go:292-294）、窗口默认 8388608 与 8388608*5/2——quinn_adapter 单测逐一钉住。
3. keepalive：quic-go KeepAlivePeriod（周期 PING）→ quinn `keep_alive_interval`（:283-285）语义等价；maxIdleTimeout 秒→毫秒 VarInt 映射正确。
4. MTU/路径验证：`disablePathMTUDiscovery → mtu_discovery_config(None)`（:300-303），默认开（DPLPMTUD）与 quic-go 默认一致；Go 的非 linux/windows/darwin 强制关闭条款在 Rust 无对应（quinn 全平台软件实现，无影响）。
5. CC 热切换架构（quinn_bridge 可热插拔槽位 + auth 后 apply_negotiated）正确弥合 quic-go `SetCongestionControl` 与 quinn 工厂预装的差异；brutal 窗口 `2*bps*rtt`、pacer 预算、ack-rate 槽位与 Go congestion/common 对照一致（本轮抽核心公式，逐行审计留专项）。
6. xray-transport-quic（独立 quic:// 隧道）：Go v26.7.28 已移除 QUIC transport，无基准可比（Rust 扩展属性）；拨号/accept_bi 循环/duplex 桥直白，未发现状态机缺陷；其 quicParams 配置面与 hysteria 共用（上同）。

## 6. TUIC（crates/xray-proxy-tuic）

（Rust 扩展协议，Go 基线无 TUIC；对照 tuic v5 spec/EAimTY 实现。第一轮已报 h3.rs:182 帧长，勿重复。）

### [P2] native DATAGRAM 模式无分片，>~1.1KB UDP 包报错丢弃
- 位置：`crates/xray-proxy-tuic/src/udp.rs:117-135`（`Packet::new(..., data.to_vec())` 整包序列化进单个 datagram，`send_datagram` TooLarge → Err 直接上抛）；模块注释自认"不实现分片"。
- tuic v5 规范要求 UDP 载荷超过承载容量时以 FRAG_TOTAL/FRAG_ID 分片。影响：native 模式下任何超过 quinn 对端容量（≈1200B 减 TUIC 头/地址）的 UDP 报文（视频通话、大 DNS 响应、WireGuard 等）必丢。
- 修复：按 `conn.max_datagram_size()` 上界做 FRAG 分片，或该尺寸段自动回退 quic-stream 模式。

### [P2] UDP 响应单次 read 即解析（QUIC 流允许部分返回）
- 位置：`udp.rs:169-177`：`recv.read(&mut buf)` 一次调用后立刻按帧解析；`if n==0` 才报 EOF。quinn `read()` 在任意数据可达时即返回 n<len，响应跨 QUIC 包/流控边界时被截断 → 解析错/丢包。另有 `RECV_BUF_CAP=64KiB` 单次读上限（大响应同样截断）。
- 修复：循环 `read` 至 `Ok(0)`（服务端 finish 后）或按帧头长度 read_exact。

### [P2] 连接池 get_or_connect 并发窗口：双拨号 + 覆盖丢连接
- 位置：`crates/xray-proxy-tuic/src/pool.rs:139-180`：快路径（持锁查）与慢路径（无锁 connector + insert）之间无二次检查；并发首拨时两个新 quinn 连接竞争 insert，败者被覆盖且未 close（quinn 连接句柄全弃后仅靠 idle timeout 收场）。
- 影响：突发并发下重复握手 + 一条连接资源滞留两端直至 idle timeout；无正确性破坏。
- 修复：insert 前 re-check，覆盖时对旧条目 `conn.close(...)`。

### 确认干净（抽查点）
1. `PoolKey`（addr+name+ALPN 排序拼接）键语义正确（排序无关性有测试）。
2. `is_alive` 用显式 close 标记 + `close_reason().is_none()` 双条件，死连接（Reset/Timeout）能被 `get_or_reconnect` 的 remove+重试路径清理（1s→30s 指数退避 ×5）。
3. `clear()` 对每条连接 `close(0, "pool cleared")` 正确传播应用层关闭；quic 模式（每 UDP 包一条 bi-stream，finish 半关闭 + 超时读回）与 tuic v5 单包单流形态一致。
4. 服务端（server.rs）认证失败按请求级回错误码、UDP session 表带超时清理（本轮抽查级通过；第一轮已覆盖的 h3 帧长除外）。

## 7. 方法附注与遗留
- 对拍所用第三方版本：h2 0.4.15 / quinn-proto 0.11.17 / quic-go v0.59.1-0.20260425（D:/Project/Xray-core go.mod 锁定）/ tokio-tungstenite 0.26；RFC 7541 表为 rfc-editor.org 原文脚本对拍。
- grpc-go 库本机不在模块缓存，gRPC 两条涉及 grpc-go 内部行为（响应校验错误分类、路由 415）的表述基于 grpc-go 惯常行为，已在正文以对照代码间接锚定；其余全部为逐字核实。
- 未覆盖/留专项：hysteria salamander 混淆与 udphop 切换状态机的逐字节审计、congestion/brutal、bbr 全行对照、tuic h3 服务端全帧状态机（第一轮已涉帧长）、splithttp h3_client 与 browser 面。
