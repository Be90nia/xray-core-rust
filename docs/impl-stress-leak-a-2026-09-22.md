# 票A：s10/s12 splithttp 族泄漏根因定位与修复

日期：2026-09-22　|　范围：crates/xray-transport-splithttp（生产 crate）　|　状态：修复完成待终验

## 结论

**泄漏在生产 crate `xray-transport-splithttp`，双侧（客户端断连不传播 + 服务端会话链不解体），h2/h3 两条路径同型。** 非 harness 拓扑问题（s7/s8/s11 同 bridge 零泄漏佐证；harness 仅装配 start_full 生产路径）。

## 复现数据（本机 Windows，修复前）

`xray-stress --duration 180 --scenarios s10 --sample-interval 15`（concurrency=8，~41 roundtrip/s）：

| 采样 | conn_ok | fd_count | alive_tasks | RSS |
|---|---|---|---|---|
| t=0 | 0 | 266 | 132 | 28MB |
| t=105s | 4328 | 19028 | 39438 | 1000MB |
| 斜率 | — | **≈+1800 fd/min** | **≈+22500 task/min** | **≈+555MB/min** |

每 roundtrip 泄漏 ≈4.3 fd + ≈9 个 tokio 任务 + ≈224KB 堆。表型与 docker 基线一致（s10 fd+5701/min / s12 RSS+1131MB/min，速率差异来自容器并发与 h3 路径对象大小）。

## 根因

每次短连接 roundtrip = 一次完整 `dial_splithttp`（每连接新建 `DefaultDialerClient`/`H3Conn`，对应 Go `createHTTPClient`）+ 一条 session 链。连接关闭时终止信号断裂，服务端整条链永挂：

### 断点 1（客户端）：SplitConn drop 不传播断连

Go（`dialer.go` + `connection.go`）：`splitConn.onClose → reader.Close()` → GET 下载流被 close（h2 RST_STREAM / h1 关 TCP）→ 服务端 `request.Context().Done()` 触发（hub.go:394-398）→ GET handler 返回 → `defer h.sessions.Delete` + `conn.Close()` → 服务端整条 dispatch 链解体。

Rust：`dial_packet_up` spawn 的 GET lazy reader（`spawn_h2_lazy_reader`/`spawn_h3_lazy_reader`）**持有 hyper body / h3 RequestStream，阻塞在 `recv_data()`**。SplitConn drop 只 drop mpsc rx——**不会唤醒阻塞中的任务**，请求不取消、连接不关闭。`SplitConn.on_close` 钩子存在但**从未接线**。

### 断点 2（服务端）：session 删除不关 UploadQueue

Go reap 路径（hub.go:84-91）：`sessions.Delete` + **`s.uploadQueue.Close()`**。Rust `SessionMap::remove` 只删 map 条目，**不 close queue** → `forward_queue_to_writer` 的 `queue.read()` 永挂 → upload duplex 写端不 drop → dispatcher 桥上行 EOF 永不到达 → 桥接/freedom/echo 连接全挂。

### 挂死链（每次 roundtrip 一套，永不回收）

客户端：GET lazy reader 任务 + POST 上传任务（持有 `Arc<DefaultDialerClient>`→hyper 池 TCP 不关）+ h3 的 quinn Endpoint/Connection（**无 Go `AfterFunc { tr.Close(); pktConn.Close() }` 等价物**，UDP fd 等 30s idle timeout，期间连接缓冲 ~MB 级驻留）。
服务端：hyper serve_connection + GET handler + session + UploadQueue + forward task + duplex×2(64KB) + dispatcher 桥 + freedom/echo TCP。

s12 的 RSS 爆炸主体是服务端每-roundtrip 挂链的堆对象 + 客户端 quinn 连接缓冲（`stream_receive_window` 默认 1.22MB）；s10 的 fd 主体是永挂的 h1 TCP（客户端池连接 checkout 中 + 服务端 accept 侧）。

## 修复（最小 diff，4 文件）

1. **client.rs**：`CloseSignal = oneshot::Receiver<()>` 新类型；`open_stream` 加 `close` 参数；`spawn_h2_lazy_reader` 用 `select!` 监听信号，信号到达即放弃请求（hyper 连接按不可复用处理：h1 关 TCP / h2 RST_STREAM）。
2. **h3_client.rs**：`H3Conn::close()`（`quinn_conn.close(0, b"client conn dropped")`，对齐 Go AfterFunc）；`open_stream`/`spawn_h3_lazy_reader` 同样接信号。
3. **dialer.rs**：`dial_packet_up`/`dial_stream_up`/`dial_h3_packet_up`/`dial_h3_stream_up` 创建 oneshot，`SplitConn::set_on_close` 发信号；h3 版 on_close 同时调 `H3Conn::close()`（连接级 fd 立即释放 + 服务端 QUIC 连接立即终结）。
4. **hub/session.rs**：`SessionMap::remove` 删除后 `upload_queue.close()`（对齐 Go hub.go:88 reap 语义；幂等，30s reap 路径复用同函数）。

stream-one/stream-up 的 POST 任务本就随 pipe EOF 退出，未改（最小修复原则）；dial_reality_stream_one 无 lazy reader，不受影响。

## Go 基线对照

| 语义 | Go | 修复前 Rust | 修复后 Rust |
|---|---|---|---|
| 断连传播 | `splitConn.onClose → reader.Close()` | 无（on_close 钩子空置） | oneshot 信号 → 终止 lazy reader |
| QUIC 连接生命周期 | `AfterFunc(conn.Context) { tr.Close(); pktConn.Close() }` | 无（等 30s idle timeout） | `H3Conn::close()` on_drop |
| session 删除 | reap: `Delete + uploadQueue.Close()` | `Delete` only | `remove` 内 `close()` |
| h1 keep-alive | `DisableKeepAlives: true` | hyper 池 keep-alive | 修复后 Client 随连接关闭即刻 drop，池关闭 |

## 验证

（终验数据待回填：lib 测试 + 本地复现斜率 + docker 10min 判定）

## 影响面

`xray-transport-splithttp` 生产 crate；harness 与其他 crate 零改动。签名变化仅 `open_stream`（crate 内 + 1 处测试调用点）。
