# 票B：s9 anytls fd 泄漏（+5222/min）根因定位与修复

日期：2026-09-22 ｜ 分支：master（未 commit，PM 审后提交） ｜ 状态：修复落地，docker 斜率验收见 §5

## 1. 结论（首行）

**泄漏在生产 crate `xray-proxy-anytls`（client + MockServer 双侧），非 harness 装配方。**
根因：anytls-rs 0.3.5 的 `Session::terminate()` 是**纯本地标记**——不发 FIN 帧、不关底层
TLS socket、不唤醒阻塞在 TLS read 的 `recv_loop`。而双侧桥接层（`pump_stream` /
`bridge` / `pump_session_to_duplex`）在流结束时全部只调 `terminate()`，导致：

1. 对端永远不知道流已结束（无 FIN）；
2. 双端 `recv_loop` 永远阻塞在各自 TLS read → `run()` 不退出 → `Arc<Session>` 挂在活跃
   `sessions` map → TLS fd 永不 drop；
3. 外部 crate 的兜底回收（`idle_cleanup` / `Client::close`）全部只调 `terminate()`，同样
   不关 socket——无任何有效兜底。

每请求泄 2 fd（client TLS + server TLS，压测进程内同进程），与实测 +5222 fd/min 吻合
（请求速率约 2600/min）。

## 2. 泄漏侧判定：生产 vs harness

| 证据 | 指向 |
| --- | --- |
| 健康对照 s7-ss/s8-tuic/s11-http 同走 socks 入站 + start_full dispatch，fd 16→16 | harness 装配（start_full/sampler/echo）无泄漏 |
| 泄漏路径唯一差异 = anytls 协议栈（client.rs + server.rs，均属生产 crate xray-proxy-anytls） | 泄漏在生产 crate |
| anytls-rs 源码（~/.cargo/registry anytls-0.3.5）逐层核对：`terminate()` 只置 `closed` flag + 关 pipe + notify，不碰 reader/writer half；`recv_loop` 阻塞点在 `reader.lock().await.read()`，循环顶部 closed 检查在阻塞时永远走不到 | 外部 crate 回收闭环缺失 |
| `spawn_idle_waiter` 把流结束的 session 入 idle 池依赖 `idle_notify`，而 notify 只在 `mark_local_stream_closed`（收到 FIN）或 `terminate` 时发——不发 FIN 就永远不回池 | 复用路径同样断裂 |

**Go 基线对照**（anytls-go / Xray-core anytls outbound）：Go `session.Close()` 真正关闭底层
conn（TCP fd 释放）；client 流结束发 FIN，server 收 FIN 关流，空闲超时后主动 `conn.Close()`。
Rust 侧 anytls-rs 0.3.5 缺失的正是「主动关 conn」这一环。

## 3. 修复（最小 diff，2 文件）

### 3.1 `crates/xray-proxy-anytls/src/client.rs`（+10/-1）

`pump_stream::up`（duplex EOF，即请求写方向结束）：`session.terminate()` →
`write_frame(FIN, DEFAULT_SID)` + `mark_local_stream_closed(DEFAULT_SID)`。
对齐 anytls-go Pipe 关闭语义：FIN 通知服务端流结束（客户端收到干净 EOF 后连接关闭由
服务端驱动），session 双关后可回 idle 池。duplex Err 分支同样收尾（发 FIN 无害）。

### 3.2 `crates/xray-proxy-anytls/src/server.rs`（生产 +55/-10，测试 +98）

- `handle_conn`：accept 前对 `TcpStream::into_std()` 做 `try_clone()`，spawn 一次性
  kill watcher（oneshot → `shutdown(Both)`）。auth/accept 失败早退路径 kill_tx 随
  return drop，watcher 自行退出，无 task 泄漏。
- 新增 `finish_session(&Session, kill_tx)`：`write_frame(FIN)` + `mark_local_stream_closed`
  + `kill_tx.send(())`。FIN 先行保证客户端读到干净 EOF（数据先于连接关闭送达），
  shutdown 驱动本端 recv_loop 退出 → `run()` 结束 → Arc 全量 drop → TLS fd 释放。
- `handle_session` 两个分支（mock 直连 bridge / dispatch pump）收尾统一走
  `finish_session`；`bridge` / `pump_session_to_duplex` 的 up 分支原 `terminate()` 删除
  （收尾上移，pump 只做数据搬运）。
- `on_new_session` 为 `Fn` 闭包不能 move out kill_tx：`Mutex<Option<_>>` + `take()`
  （单次触发由 anytls 单流模式 `handler_started` 保护保证）。

### 3.3 语义说明与取舍

- 单流模式（0.3.x）一条 session 就是一条流。server 端「流双关即关连接」放弃了
  session 跨请求复用（anytls-go server 支持同 session 开第二条流）：client 侧池里
  session 被 server 关闭后，`pick_session_from_idle_pool` 对 `is_terminated` 的
  session 直接丢弃再新建，行为正确、fd 不泄漏；代价是每请求一次 TLS 握手。
  修复优先正确性（fd 泄漏），复用性能如需恢复应升级外部 crate，不在本票范围。
- 未动外部 crate anytls-rs 0.3.5（无 vendor patch，无版本变更）。
- 未动 `inbound.rs`（生产入站接线缺陷 stop_tx drop 是 PM 已登记的独立缺陷，
  压测经 MockServer 直挂绕过，不属本票）。

## 4. 测试（TDD：先红后绿）

新增 `server::tests::stream_close_releases_server_connection`：tracked echo server
（活跃连接计数），client 完整 echo 一轮后 drop conn，断言 5s 内服务端 echo 连接计数
归零。修复前红（5.05s 超时 assert 失败，计数不归零），修复后绿（0.08s）。

## 5. 验证

### 5.1 crate 测试（Windows 本机，--target-dir target/stress-dev）

```
cargo test -p xray-proxy-anytls --lib     → 24 passed / 0 failed
cargo test -p xray-proxy-anytls --tests   → dial_system_contract 1/1
                                            dispatcher_loopback   2/2
                                            inbound_dispatch      1/1
                                            loopback              2/2
                                          （合计 30 passed / 0 failed）
```

### 5.2 docker 泄漏复现（Acceptance #4）

```
docker run --rm xray-stress --duration 600 --scenarios s9 --sample-interval 15
```

（结果回填：修复前基线 fd +5222/min / RSS +91MB/min；修复后斜率见下方回执。）

[TO BE FILLED AFTER DOCKER RUN]

## 6. 残余风险

- anytls session 跨请求复用被放弃（见 §3.3），吞吐敏感场景每请求多一次 TLS 握手。
- dispatcher 半关闭场景（未读完响应即 drop AnytlsConn）pump task 被 abort，FIN 不发，
  该连接 fd 仍依赖对端超时——压测 echo 为完整读写不触发；完整修复需 AnytlsConn
  Drop 钩子，涉及外部 crate 会话语义，另行立项。
- 48h 长跑（stress-win-12scn-48h，旧 exe）不含本修复，其 s9 数据仍是泄漏形态。
