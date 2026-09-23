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

## 第二轮（2026-09-23）：s12 残留死锁环的定位与修复

第一轮修复后 s10 达标（300s 平台、尾段 fd -36/min、RSS +18.3MB/min）；s12 fd 归零（833→1600 稳态，无斜率）但 alive_tasks 仍无限涨（600s 7688→100290，+3.2 任务/conn，RSS +259MB/min 尾段）——残留无独立内存泄漏，全部是滞留任务的工作集。

### 定位方法

临时插桩（`leak_probe.rs`，guard 计数 + 5s stderr 报告，验证后移除）：对 splithttp 服务端 8 个 spawn 点 + vmess inbound 4 个 spawn 点计数 live/total。本地 420s s12（concurrency=8，~9300 conn）：

| 插桩点 | live/total | 判定 |
|---|---|---|
| vm_conn / vm_pump_a / vm_pump_b（vmess inbound） | **0-5 / N** | 立即退，健康 |
| **hub_copy**（add_conn 的 duplex copy task） | **N / N = 100%** | 死锁，零回收 |
| **hub_forward**（UploadQueue→writer） | **N / N = 100%** | 死锁，零回收 |
| **h3_req**（serve_h3_request，GET 分支每 conn 1 个） | **N live（POST 分支全退）** | GET 全部滞留 |
| h3_lazy / h3_driver（客户端） | ~35-55%（quinn 30s idle 兜底收敛） | 窗口型稳态 |

### 根因：h3 GET response body 的「等下行 duplex EOF」无解体锚点

服务端 GET 链 `serve_h3_request` 的 response body 循环（`body.frame().await` ← `ReaderStream(dl_rx)`）在响应数据发完后挂在等 `dl_tx` drop；`dl_tx` 在 hub copy task 里，copy task 的 `join!(copy(up→wr), copy(rd→down))` 又挂在上行 `up`（ServerConn.reader = UploadQueue，永不 EOF）。**三条任务互相等，且整条链没有任何超时/终结信号**（dispatcher 桥的 connIdle 兜不到——vmess 层先退，桥在 duplex 对端 drop 后即解体，剩下的滞留全在 hub/h3 层）。客户端 CONNECTION_CLOSE 到达时 quinn 流读写会 Err，但 GET 循环挂的是「没数据可发」的 Pending，Err 传不到它。

Go 语义锚点（hub.go:394-398）：`request.Context().Done()`（客户端断开）中断 handler → `defer conn.Close()` → splitConn 整体终结（reader=UploadQueue close + writer close）→ 全链解体。Rust 缺「连接终结 → 强制终结该连接全部请求」这一环。

### 修复（transport.rs serve_h3_conn，~10 行）

每个 h3 请求 spawn 后，配套 spawn 一个连接终结 watcher：`conn.closed().await → task.abort()`。abort 即 drop response body（含 `SessionDropGuard`）→ 既有第一轮机制接手：guard drop 触发 `sig.close()`（ServerConn 上行注入 EOF → copy task 上行半退 → join 完成 → dl_tx drop）+ `sessions.remove` → `upload_queue.close()`（hub_forward 退）。三条滞留族同一信号统杀，语义对齐 Go request-context-cancel + conn.Close()。

s10 的 TCP/h2 路径无此环（第一轮修复后 300s connIdle 收割即达标），不改动（最小修复原则）。

### 第二轮修复验证（Windows 本机 debug build，420s s12，与 docker build 并行期）

| 指标（t=360-420s 尾段） | 修复前（同窗口） | 修复后 |
|---|---|---|
| alive_tasks | +2300/15s 无限涨 | **9775（-90/15s，负增长收敛）** |
| RSS | +259MB/min | **≈+5MB/min（噪声级）** |
| fd | 1592 稳态 | 996-1056 稳态 |
| 峰值 RSS（420s） | 1086MB | 356MB |

插桩交叉验证：hub_copy / hub_forward / h3_req-GET 三族 live 从 100%/conn 滞留降至 ~35% 的时间窗口型稳态（quinn idle 30s 窗口量），死锁解除。

本地实验期 conn_fail 17%（os error 10048）为 Windows ephemeral 端口耗尽 + 与 docker 全量构建抢 CPU 的环境噪声（debug 日志实锤，非协议失败）；修复后连接终结更快、UDP ephemeral bind 频率升高，Windows 本机端口预算下 10048 概率上升，属环境资源噪声；干净判定以下方 docker 数据为准。

### Docker 验收（Linux 容器，xray-stress:fixed，600s s12，concurrency=8 实测 65 conn/s）

数据：`stress-tmp-debug/leak-a-docker-final/`（summary.md + metrics.csv）

| 指标 | 修复前基线 | 修复后验收 | 判定 |
|---|---|---|---|
| alive_tasks | +2200/15s 无限涨（600s 7688→100290） | **20132→20155 全程平台（20k±60 波动）** | ✅ 死锁解除 |
| RSS 尾段斜率（t=270→570s） | +259MB/min（持续） | **+15.4MB/min（收敛中）** | ✅ <20 达标 |
| fd_count | 稳态 1600 | 稳态 1599-1626 | ✅ 无 fd 泄漏 |
| conn_ok / conn_fail | — | 30723 / 3（0.01%） | ✅ 健康 |
| p50 / p95 / p99 | 3.8ms | 3.4 / 34.1 / 35.2ms | ✅ 正常 |

RSS 绝对值（峰值 5.4GB）为 65 conn/s 高速率下滞留 300s connIdle 窗口的在途任务缓冲（约 1 任务/conn × glibc arena 不归还）的高位平衡，斜率持续收敛，无界泄漏已消除。sampler 的线性拟合 verdict SUSPECT 由前 90s 瞬态堆积主导（20→4.7GB 后趋平），以尾段斜率口径判定达标。

s10（vless+xhttp h2/TCP）不经 serve_h3_conn 路径，本轮零改动；第一轮修复 docker 600s 已达标（尾段 fd -36/min、RSS +18.3MB/min，见第一轮记录）。

### 第三轮（2026-09-23）：6 场景并行打回后的两个补修

fdtest 逐场景快扫（120s 尾段斜率口径）发现 b 批并行 +330MB/min 的大头除 s12 窗口堆积外还有 **s6（trojan+grpc）独立泄漏**（修复前 578MB、+218MB/min、fd 13532 线性涨——s6 此前从未被单场景测过）：

1. **s6 grpc**：`dial_h2` 的连接驱动/保活泵 task 恒保活持有 `h2_conn`，roundtrip 结束 DuplexConn drop 后连接永不关闭（对齐 Go grpc.ClientConn 随调用 GC）。修复：DuplexConn 加 `_conn_kill: Option<JoinHandle>` guard，Drop 时 abort 泵 → h2 驱动 future drop → 连接关闭、fd 释放（transport.rs +22 行）。
2. **s12 客户端显式 close**：quinn Endpoint 句柄在 `connect_with_quic_params` 返回前已 drop，Endpoint drop 不终结连接；H3Conn 的 close 只挂在 SplitConn on_close（可能被泵任务拖延）。修复：`impl Drop for H3Conn`，最后 Arc 引用 drop 且未 closed 时发 CONNECTION_CLOSE（h3_client.rs +15 行）。

lib 测试：grpc 89 + splithttp 219 + vmess 145 全绿。本地 s6 复验：RSS 578→27MB、尾段 +218→+0.0MB/min、fd 13532→224、任务收敛。

### 6 场景并行验收（xray-stress:fixed2，600s，s7-s12 并行 65conn/s/场景）

数据：`stress-tmp-debug/batch-b-fixed2/`（含 ss 分状态对账：TCP TIME_WAIT 正常回收、CLOSE_WAIT 仅 83）

| 指标 | 修复前（Main b 批基线） | 修复后 | 判定 |
|---|---|---|---|
| alive_tasks | 线性涨 | **51-60k 平台（t=300s 后波动，尾段 -4240/min）** | ✅ 无界消除 |
| RSS | +330MB/min 不收敛 | **t=300s 后 5.7-5.8GB 平台，尾段 -333MB/min（负收敛）** | ✅ 斜率达标 |
| fd | 线性涨 | **~29k 平台（尾段 -3424/min）** | ✅ |
| conn_fail | — | 30/16 万（0.02%） | ✅ |

平台高度 5.8GB 超「<4GB」预期：构成 = connIdle 300s 窗口的在途任务（约 0.5-1 任务/conn × 512KiB pipe 容量上限 + 连接缓冲）+ CPU 饱和（worker busy 35/36s）下的收割延迟，属窗口固有堆积而非泄漏；压平台需改 dispatcher 桥 connIdle 语义/窗口，超出本票范围，留 PM 决策。注：该 csv 含 PM 并行实验交错行（t=468s 起锯齿），以 conn_ok 连续段区分。

### 构建注记

`s9/s10/s12` 复现镜像 `xray-stress:fixed`（860e0a57）与三修复终版 `xray-stress:fixed2`（b0b124ab，含 grpc conn-kill + H3Conn Drop）均由 exec 式构建产出（`docker run` 基础镜像 + `docker cp` 覆盖修复版源码 + 容器内增量 `cargo build --release -p xray-stress` + `docker commit`）——Docker Desktop 下 `docker build` 因 builder prune 后 fetch 层网络断流与 context 陈旧问题无法产出新版（详见规则 common-windows buildkit 条目），exec 路径产物与 Dockerfile 语义等价。


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
