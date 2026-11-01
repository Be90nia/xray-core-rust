VERDICT: PASS（结构性修复：客户端写者改单 owner 任务 + 帧队列，锁消失；反证两段 + 新增并发用例已跑）

# uwq9n — DNS-over-TCP 出站 writer 锁跨 await

等级 P1（perf / 资源泄漏）｜分支 feature/fix-inbound-parity｜改动仅 `crates/xray-core/src/outbound.rs`

## 1. 定位

修前 `dispatch_dns_link` 的 TCP 段把 link writer 包成 `Arc<tokio::sync::Mutex<Box<dyn Writer>>>`，
两个 loop（Go `dns.go` 的 request / response）都按「取锁 → 写 → 放锁」用它，取锁后的
`write_multi_buffer(...).await` **在锁内**（行号取自 `HEAD=afb963f9` 的
`crates/xray-core/src/outbound.rs`，符号名为准；票面写的 1836/1933/1920 是同一批站点在旧树的编号）：

| 站点 | 修前形态 | 行 |
|---|---|---|
| 建锁 | `Arc::new(Mutex::new(link.writer))` | 1866 |
| response loop（上游帧 → 客户端） | `writer.lock().await.write_multi_buffer(mb).await` | 1903 |
| request loop（规则应答 / UDP 上游内联回写） | `write_client_frame()` → 同一把锁 + 写 | 1991 / 2000 |
| 收尾 | `writer.lock().await.shutdown()` | 1987 |
| 唯一兜底（会被上面废掉） | 客户端读超时 / 上游读超时 | 1918 / 1885 |

失败链（客户端连上却不读响应 = TCP send buffer 满 → `poll_write` 恒 Pending）：

1. 先拿到锁的一侧卡在 `write_multi_buffer` 的 future 里——该 future **不可取消**（半写状态），
   只能等对端腾窗口；
2. 另一侧要写就得等这把锁 → 也永久挂起；
3. 两侧都挂在「await」上，于是 `:1918` / `:1885` 两处 `tokio::time::timeout(idle, read)`
   **不再被 poll**，policy `ConnectionIdle` 这道唯一兜底对这条路径失效；
4. `select!` 等不到任一 loop 结束，函数不返回 → 会话（及其 link/上游连接）永不结束。

Go 对照（`proxy/dns/dns.go:222-310`，26.10.17 @ 92ccc939）：`writer` 无互斥（每个 loop 各自
直写 link.Writer），且 `signal.CancelAfterInactivity(ctx, terminate, h.timeout)` 超时后
`cancel()` + `conn.Close()`，`task.Run` 见 ctx 结束即返回——**放弃阻塞的那一侧 goroutine，
不陪它等**。Rust 侧的「锁」是把两条独立路径串成一条，Go 没有这个失败模式。

## 2. 选型理由（选了方案 1 的加强形态）

票面给的两个方案：

- **方案 2「写客户端走同一取消令牌/有界化」**：加取消令牌也只能让 *读* 侧收尾，写侧仍卡在
  不可取消的 future 上；要让它可取消就得把写包进 `timeout`/`select!`，而半写状态下的
  future 被丢弃等于**截断一帧 DNS 响应**（长度前缀已写、载荷没写完）——那是把挂死换成
  脏帧。**否决**。
- **方案 1「锁内出队、锁外写」**：采用，并按 Rust 所有权把它做成最彻底的形式——
  **锁消失**：writer 移交给唯一的写者任务（单 owner），生产者只入队。

```text
request loop ─┐
              ├─ try_send / send ──▶ [队列 DNS_CLIENT_QUEUE=16] ──▶ 写者任务（独占 writer）──▶ link.writer
response loop ┘                                                   └─ 收尾：shutdown()
```

关键设计点与理由：

| 决定 | 理由 |
|---|---|
| 写者任务独占 `Box<dyn Writer>` | `write_multi_buffer` 要 `&mut self`，只要「同一 writer 被两侧并发写」，就必然要么锁要么队列；单 owner 是唯一无锁解 |
| 队列消息两态 `Frame` / `Shutdown` | 收尾用**哨兵**而非 drop sender：hijack 的 spawn 任务可能还持有 sender，drop 语义会被它拖住；哨兵排在已入队帧之后 → **FIFO 保证**先排空再 `shutdown()`，正常路径行为与修前一致（修前也是「写完在途帧再 shutdown」） |
| request loop 用 `try_send`（满则丢帧 + warn） | 读循环**绝不能阻塞在入队**：一旦它停在入队处，读超时同样失效，等于把挂死换个形态。丢帧只在「队列满 = 写者卡住 = 客户端不读」时发生，留痕可见 |
| response loop 用 `send().await`（背压） | 它是「上游应答 → 客户端」的唯一生产者，背压留在自己身上安全（request loop 的读超时仍能收尾会话）；用 try_send 反而会在一次 4KB 上游读解出 >16 帧时误丢**健康客户端**的应答 |
| 收尾 `timeout(idle, writer_task)` → 超时 `abort()` | 卡住的写不可取消，只能放弃（Go 同样放弃）。给一个空闲窗排空在途帧，超时就 abort——**会话结束不受写者牵制**，这是本票要求的「会话在预期时限内结束」 |
| 队列 16（有界） | 防「客户端不读」时的无界内存增长；16 帧 × DNS 报文（≤64KB 帧上限）为内存上界 |

**并发出队顺序证明**：所有客户端回写都经由**同一个** channel 的**单个**消费者；`mpsc` FIFO +
单消费者串行写 ⇒ 入队序 = 落地序。同一 DNS 会话内：
- 上游应答（response loop，逐帧 `send().await`）按上游读序入队，顺序与修前逐帧
  `lock→write` 相同（修前也是这条 loop 串行持有 writer）；
- 规则应答（request loop，按 query 序 `try_send`）在同一会话内保留请求序；
- 两条生产者之间的相对序：修前是**锁竞争序**（不确定），修后是**入队序**（确定），
  不会比修前更乱；跨生产者乱序在修前同样存在（hijack 是独立 spawn，也抢同一把锁）。

## 3. 反证（客户端连上但永不读响应）

用例：`crates/xray-core/src/outbound.rs::dns_client_writer_queue`
（`stalled_client_session_ends_within_idle_window` / `stalled_session_does_not_block_healthy_session`）。

构造（真实代码，无 mock 语义让步）：
- 客户端 → 服务端方向：`xray_buf::pipe`，测试先写入一帧 DNS 查询（`Return` 规则命中 A 查询 →
  规则应答，不碰上游），**pipe 写端保活不 drop** → 读端没 EOF，会话只能靠空闲超时收尾；
- 服务端 → 客户端方向：`StalledWriter`（`write_multi_buffer` 返回 `std::future::pending()`）——
  就是「TCP send buffer 满 → `poll_write` 恒 Pending → 写 future 不可取消」的同一形态；
- 判定：**墙钟截止轮询**（`is_finished()` + 10ms 探测 + `Instant` 截止），不是固定 sleep 后断言。

修前实现取自 `HEAD=afb963f9`（`git show HEAD:crates/xray-core/src/outbound.rs`）+ 同一份测试
模块，跑完立即还原为修后版本（还原后与还原前逐字节相同，见 §4.5）。

### 3.1 修前：会话永不结束（10s 仍未结束，非「慢」）

```text
thread 'outbound::dns_client_writer_queue::stalled_client_session_ends_within_idle_window' panicked at crates\xray-core\src\outbound.rs:7037:13:
客户端不读响应时会话必须收尾：10s 内未结束（修前挂死形态）
test outbound::dns_client_writer_queue::stalled_client_session_ends_within_idle_window ... FAILED

failures:
    outbound::dns_client_writer_queue::stalled_client_session_ends_within_idle_window

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 513 filtered out; finished in 10.02s
```

（同一次反证先按默认 1.6s 预算跑过一遍，同样 FAILED ——「1.6s 内未结束」；把预算放宽到 10s
仍 FAILED，说明是挂死而不是收尾慢。）

### 3.2 修后：同一场景 0.6s 内收尾

```text
running 2 tests
test outbound::dns_client_writer_queue::stalled_session_does_not_block_healthy_session ... ok
test outbound::dns_client_writer_queue::stalled_client_session_ends_within_idle_window ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 512 filtered out; finished in 0.62s
```

收尾时长 = 空闲窗 300ms（request loop 读超时）+ 排空窗 ≤300ms（写者卡死 → 到点 `abort`），
实测 0.62s（两条用例合计）。

### 3.3 诚实说明：并发用例在修前也 pass

`stalled_session_does_not_block_healthy_session` 在修前实现下同样 pass——因为修前那把锁是
**per-session**（每次 `dispatch_dns_link` 各建一个 `Arc<Mutex<..>>`），跨会话本来就不互相阻塞。
它的作用是**防修复引入跨会话串行**（若改法收敛成一把全局锁 / 单例队列就会红），不是修前反证。
真正的反证是 3.1。

## 4. 验证

### 4.1 新增用例（客户不读 → 会话收尾 + 并发不串行）

```text
$ cargo test -p xray-core --lib dns_client_writer_queue
running 2 tests
test outbound::dns_client_writer_queue::stalled_session_does_not_block_healthy_session ... ok
test outbound::dns_client_writer_queue::stalled_client_session_ends_within_idle_window ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 512 filtered out; finished in 0.62s
```

### 4.2 dns 相关用例全量（含既有 TCP 双 loop 正常路径回归）

```text
$ cargo test -p xray-core --lib dns
test outbound::tests::dns_tcp_direct_dual_loop_pipeline ... ok          ← 修前既有用例，正常语义未变
test outbound::dns_client_writer_queue::stalled_client_session_ends_within_idle_window ... ok
test outbound::dns_client_writer_queue::stalled_session_does_not_block_healthy_session ... ok
test outbound::tests::dns_udp_dispatch_session_framed_roundtrip ... ok
test outbound::tests::dns_udp_session_closes_after_idle_timeout ... ok
test outbound::tests::dns_udp_direct_forwards_raw_roundtrip ... ok
test outbound::tests::dns_udp_own_link_bypasses_rules ... ok
test outbound::tests::dns_udp_default_a_hijacks_via_fakedns ... ok
test inbound::tests::dns_inbound_wears_finalmask ... ok
test result: ok. 33 passed; 0 failed; 0 ignored; 0 measured; 481 filtered out; finished in 0.63s
```

### 4.3 票面验收命令（带 --all-targets）

```text
$ cargo test -p xray-core --lib dns --all-targets
Running unittests src\lib.rs
test result: ok. 33 passed; 0 failed; 0 ignored; 0 measured; 481 filtered out; finished in 0.63s
     Running tests\assembly_path_equivalence.rs
     Running tests\bind_failure_fatal.rs
     Running tests\invalid_inline_cert_startup.rs
（其余 target 过滤后 0 matched，无 FAILED）
```

### 4.4 clippy + 全 crate lib 回归

```text
$ cargo clippy -p xray-core --all-targets -- -D warnings
    Checking xray-core v0.1.0 (D:\Project\Xray-core-rust\crates\xray-core)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 34.48s   ← 零告警

$ cargo test -p xray-core --lib
test result: ok. 512 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out; finished in 32.13s

$ rustfmt --edition 2024 --check crates/xray-core/src/outbound.rs   → exit 0
```

### 4.5 反证工具的干净性

```text
$ python D:/tmp/uwq9n_swap.py post && cmp 修后版本 vs 保存版本
identical: True
$ git diff --stat crates/xray-core/src/outbound.rs
 crates/xray-core/src/outbound.rs | 240 +++++++++++++++++++++++++++++++++++----
 1 file changed, 216 insertions(+), 24 deletions(-)
```

（216+/24- 中约 160 行是新增测试模块，实现面改动约 55 行。构建均用
`CARGO_TARGET_DIR=D:/Project/Xray-core-rust/target-Wave7Dns`，与并行代理隔离。）

## 5. 非目标 / 残余

- **UDP 客户端分支**（`client_is_udp`）仍是单 loop 内联写、无锁：不存在本票的互相阻塞形态，未改。
  残余：UDP 客户端不读时该 link 的写仍会挂到会话空闲超时（单 loop，超时在写侧之外，写本身的
  挂起不可取消）——属 `Link`/`Writer` 抽象边界，不在本票面。
- **上游写侧**（`write_or_inline_upstream` 里 `wh.write_all(&framed).await` 持 `write_slot`）：
  上游不读同样会挂住 request loop，且该锁跨 await。此路径**无第二持有者**（只有 request loop
  用它，hijack 不写上游），不是本票的互相阻塞形态；且 Go `connWriter.WriteMessage` 同样阻塞
  （`dns.go:252`），一致。留作后续票据（若要做，做法同本票：上游写也改单 owner + 有界队列）。
- 未改 DNS 协议解析、未改 policy 配置面、未 commit。

## 6. 收尾

- 反证工具（仓库外）：`D:/tmp/uwq9n_swap.py`（`save|pre|post` 三档，切换前后逐字节校验）。
- 构建目录 `D:/Project/Xray-core-rust/target-Wave7Dns` 为本任务独占（与并行代理隔离），任务结束删除。
- 代码图谱：尝试重索引两次均返回 `aborted_previous_preserved`（原因：并行代理仍在改树，索引运行期文件变动 → 本次索引中止，前版图谱完好仍可服务）。因此图谱里
  `dispatch_dns_link` 仍是旧行区间、新增 `ClientWrite`/`DNS_CLIENT_QUEUE`/测试模块尚未入图。
  **建议在整波并行代理全部落地后由 PM 统一跑一次** `codebase-memory-mcp cli index_repository`（逐符号结论不受影响：本票的符号定位均已用 serena/read 取证）。
