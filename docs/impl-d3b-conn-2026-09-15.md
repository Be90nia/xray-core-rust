# impl-d3b — Batch D-3 Lane B 执行回执（2026-09-15）

**结论：三票全部修复，红→绿证据齐备。crate 级测试全绿：xray-common 459 / xray-transport 520 / xray-proxy-tuic 50 / xray-tls 163 / xray-reality 110 / xray-transport-splithttp 201 / xray-app-geodata 71 / xray-app-router 157 / xray-core 325（均 0 failed）。**

VERDICT: 3/3 fixed — 09c4 Windows 真半关闭 / 4zjf 池锁临界区零 await / jrh7 单一安装入口；Lane B 全部 crate 级验证绿

**补跑终态（proxyman 解除阻塞后）**：`cargo test -p xray-proxy-tuic --lib` = **50 passed / 0 failed**、`cargo test -p xray-core --lib` = **325 passed / 0 failed**。事故记录：修 4zjf 时误删 tuic [dependencies] 的 rcgen（把 duplicate-key 误判为多余行）+ 漏改 `QuinnConnectionPool::new()` 的构造，两者已修复并全量复验；属既有教训「Cargo/批量 edit 后必须 re-read 核对」的再确认，无新增沉淀。

## 票 1 — 09c4 (P0): Windows TcpConnection close_read/close_write 静默 Ok

**裁决依据（先查基准与契约）**：
- Go 基准：`net.TCPConn.CloseRead/CloseWrite` 在 Windows 走 `syscall.Shutdown(SD_RECEIVE/SD_SEND)`——Go 平台支持真半关闭，不是 "Windows 不支持"。
- trait 契约：`Connection::close_read` doc（connection.rs:40-42）自陈 "Windows 上 TcpConnection 用 shutdown(SHUT_RD/SHUT_WR) 实现"——**文档声称已实现，实现却在撒谎**（静默 Ok）。
- 修复方向选择：**真实现**（而非 Err(Unsupported)）。理由：审计建议的 Err(Unsupported) 会迫使调用方走 `shutdown(Both)` 兜底，杀掉响应方向——对 VMess 请求方向提前 EOF + 响应续传类协议是行为回归。真实现 = Go 对齐 + trait 文档对齐 + 零调用方退化。

**实现**（crates/xray-transport/src/connection.rs）：
- 新增私有 `TcpConnection::winsock_shutdown(how)`：借 `as_raw_socket()` 的 `ManuallyDrop<std::net::TcpStream>` 视图调 `std shutdown`（std 在 Windows 映射 `Shutdown::Read/Write → SD_RECEIVE/SD_SEND`）。tokio 句柄只有 `Shutdown::Both` 方向语义，故不经 tokio。SAFETY 注释齐备（不接管所有权，dup_tcp_stream 同款惯例）。
- `close_read`/`close_write` 的 `#[cfg(windows)]` 臂从 tracing::debug 静默 no-op 改为 `self.winsock_shutdown(...)?`；unix 臂原样保留。

**红→绿**：
- 红（Windows 本机，修复前）：
  `thread 'tcp_half_close_directional_semantics' panicked at connection.rs:604: close_write: peer must observe EOF within 5s (Windows no-op stalls here): Elapsed(())`
- 绿（修复后 Windows 本机）：
  `test connection::tests::tcp_half_close_directional_semantics ... ok`（`cargo test -p xray-transport --lib`：**520 passed / 0 failed**）
- 测试断言可观察行为：close_write 后对端 read 必须 Ok(0)（FIN）；本端读方向仍能收数据；close_read 后对端新写入的数据不得再被读出（unix=EOF / windows=WSAESHUTDOWN error）。

## 票 2 — 4zjf (P0): TUIC pool lock-across-await（pool-wide stall）

**实现**（crates/xray-proxy-tuic/src/pool.rs，对齐审计建议 1+2）：
- `inner: Arc<tokio Mutex<HashMap>>` → `Arc<parking_lot::RwLock<HashMap>>`（pooling_lot 从 [dev-dependencies] 移入 [dependencies]）。
- 快速路径 + double-check：读锁内只 `get(&key).cloned()`，`is_alive().await` 在锁外（锁临界区零 await）。
- `remove/clear/len/is_empty` 四个 pub 方法 async → sync（原实现锁内本无 await，async 是噪音）；调用方同步更新（ReconnectingConnection:285、pool tests）。
- `dial_locks`（per-key single-flight，跨 connector().await 持有）保留 tokio Mutex——那是设计语义（票 5poj），非 bug。

**红→绿**（决定性停顿测试 `concurrent_get_or_connect_does_not_stall_on_alive_check`）：
- 测试设计：W 持池内连接 `is_closed` 写锁冻结 `is_alive()` → A 走快速路径阻塞在 alive 检查 → B 调 `pool.len()` 必须 1s 内返回。
- 红（修复前）：`panicked at pool.rs:519: pool.len must not stall while an alive-check is in flight (bd 4zjf): Elapsed(())`——pool-wide stall 实锤复现。
- 绿（修复后）：`test result: ok. 4 passed`（该测试 + 既有 3 个 pool 测试；A 在 W 释放后返回活跃连接，B 期间不受阻）。
- 注：tuic 全量 --lib 因 proxyman 中间态暂跑不了，pool::tests 4 个已在本机全绿（红前 3 passed 1 failed → 绿 4 passed）。

## 票 3 — jrh7 (P1): rustls dual CryptoProvider 集中安装

**位置偏差声明（有意，客观约束）**：审计建议入口放 `xray-tls`，实际落在 **`xray-common`**（`crates/xray-common/src/crypto_provider.rs`，lib.rs 根 re-export `xray_common::ensure_default_crypto_provider`）。理由：xray-tls 依赖 btls/btls-sys/tokio-btls（4min 冷构建 + buildenv 专属），把 xray-tls 塞给 xray-proxy-tuic 会破坏 PM 明示的 "tuic 纯 Rust 直接 cargo test" 环境契约；xray-common 是纯 Rust 叶子 crate，且**全部 15 个生产调用点所在 crate 都已依赖 xray-common**（含 tuic），零新增传递负担。票面契约（Once 单一入口、幂等、生产禁散装、测试惯例保留）全部满足。

**替换清单（15 处生产调用点 → `xray_common::ensure_default_crypto_provider()`）**：
- xray-tls：client_config.rs:78、client_config.rs:258、server_config.rs:191、ocsp_stapling.rs:128、utls.rs:621
- xray-reality：client.rs:400、mitm.rs:62
- xray-proxy-tuic：inbound.rs:117、server.rs:70
- xray-core：outbound.rs:810/2193/2638、inbound.rs:3675/3778（后两处为复核新发现的生产点：hysteria/anytls inbound 解析器）
- xray-transport-splithttp：register.rs:111
- xray-app-geodata：downloader.rs:467；xray-app-router：webhook.rs:377
- Cargo 变更：xray-common +`rustls = { workspace = true }`（rustls 全仓树上本就存在）；xray-reality 原本已依赖 xray-common，无变更。

**红→绿**：
- 红：测试引用缺失入口 → `error[E0433]: cannot find module or crate xray_common`（crypto_provider.rs 测试，编译失败即红）。
- 绿：`cargo test -p xray-common --lib`：**459 passed / 0 failed**（含新测试：双调用幂等 + `CryptoProvider::get_default().is_some()` + 裸 `ClientConfig::builder()` 不 panic）。

**验收 grep（生产路径 install_default 零散点 = 集中入口唯一）**：全仓 src `install_default` 残留全部逐一核对为 `#[cfg(test)] mod tests` / tests/ 目录内（并行测试惯例，票面明示保留），生产代码仅剩 xray-common crypto_provider.rs:16 一处。

---

## 4zjf 同族扫描（全 crate lock-across-await）

方法：grep 全部 crates `\.lock\(\)\.await|\.read\(\)\.await|\.write\(\)\.await`（42+ 文件），逐个核对 guard 作用域内是否有 await。结论：**我 lane 内无残留；lane 外按审计既定分类登记如下，未修**：

| 位置 | 形态 | 分类 |
|---|---|---|
| xray-app-dns/dot.rs:202-204、tcp.rs:176-178 | conn_guard 持锁跨 connect_tls/connect().await | 良性：lazy-connect single-flight（并发共享一次连接），per-实例非池级 |
| xray-transport-wireguard/driver.rs:139-141 | writer guard 跨 connect().await | 同上 lazy-dial single-flight |
| xray-core/outbound.rs:2058+ | write_slot lazy dial | 同上 |
| xray-app-proxyman/inbound/worker.rs:199 | `lock().await.recv().await` | 单消费者 channel（审计 F8 同族判定：锁无用但无害）；proxyman 为 d3a 活跃文件，不碰 |
| xray-core/inbound.rs:4213/4220、outbound.rs:1931/2015/2029 | stream 读写锁跨 IO await | 单读者/单写者固有串行；登记 P3 |
| xray-mux client.rs/session.rs/writer.rs（多处） | workers/xudp/inner 锁跨 flush 等 | **d3a lane**，已属其 F2 修复范围，登记转交 |
| xray-transport-splithttp/h3_client.rs:268+ | send_req 锁跨 send_request().await | 共享单控制流固有（H3 单 writer），队头阻塞已是该设计语义；登记 P2 |
| xray-transport-websocket/ws_bridge.rs:279-282 | write 锁跨 ping send | 单写者固有；P3 |
| xray-transport/finalmask（xicmp/realm/xdns） | rx.recv().await 在锁内 | 单消费者 channel 同族（F8 判定复用）；P3 |
| hysteria quinn_adapter.rs:65/83、udp.rs:760 | recv/send 锁跨 IO、close_all 跨 await | 审计 F8 已登记同族；P2 |
| xray-transport/src/udp/dispatcher.rs、relay.rs | 临界区全 sync | 干净 |

修复判定：pool-wide 类（不同 key/不同连接互相饿死）仅 tuic pool 一处，已修；其余均为 per-实例 single-flight（正确模式）或单消费者固有串行（无锁竞争对象），不构成同形态 bug。

---

## 验证命令 + 关键输出汇总

```
cargo test -p xray-common --lib            → 459 passed / 0 failed        (jrh7 绿)
cargo test -p xray-transport --lib         → 520 passed / 0 failed        (09c4 绿, 全 crate)
cargo test -p xray-tls --lib               → 163 passed / 0 failed        (jrh7 无回归)
cargo test -p xray-reality --lib           → 110 passed / 0 failed        (jrh7 无回归)
cargo test -p xray-transport-splithttp --lib → 201 passed / 0 failed      (jrh7 无回归)
cargo test -p xray-app-geodata --lib       → 71 passed / 0 failed         (jrh7 无回归)
cargo test -p xray-app-router --lib        → 157 passed / 0 failed        (jrh7 无回归)
cmd /c buildenv cargo test -p xray-proxy-tuic --lib pool::tests → 4 passed (4zjf 绿)
# 红证据（修复前）：
#   09c4: panicked 'close_write: peer must observe EOF within 5s ... Elapsed(())'
#   4zjf: panicked 'pool.len must not stall while an alive-check is in flight ... Elapsed(())'
#   jrh7: error[E0433] cannot find ensure_default_crypto_provider
```
补跑（proxyman 解除阻塞后）：`cargo test -p xray-proxy-tuic --lib` → 50 passed / 0 failed；`cargo test -p xray-core --lib` → 325 passed / 0 failed。

## read 调用审计
- rule://rust ⇒ 自检纪律（Rust 改动），已遵循（unwrap 禁用/SAFETY 注释/parking_lot/测试置底）
- bd show 09c4/4zjf/jrh7 ⇒ 票面定位；bd memories cryptoprovider ⇒ 命中 rknm 教训（双 provider panic 前科）
- docs/audit-{concurrency,platform}-2026-09-15.md F1/F3 ⇒ 修复方向依据
- skill://code-simplifier、silent-failure-hunter、agent-self-evaluation ⇒ 收尾自检已按清单执行（无 lint suppress、无吞错、ensure 的 Err 吞掉为幂等语义且有文档）
- task-closing-ritual ⇒ 沉淀见下

## side-effects 三态
- 预期：15 个生产调用点行为等价替换（Once 幂等 ≙ `let _ = install_default`）；Windows close 语义从静默 no-op → 真半关闭（这正是票面要求的行为变更）；pool 元操作 async→sync（crate 内调用方已全部迁移，crate 外无调用方——grep 证实 xray-core 仅用 `QuinnConnectionPool::new`）。
- 意外：无。
- 未验证：workspace 全量与 run_full32（PM 统一收口）；xray-core/tuic 全量 --lib（sibling 阻塞）。

## 残余风险
- Windows close_read（SD_RECEIVE）后对端继续发数据会触发 RST——与 Go 完全一致的平台语义，但与 unix（静默丢弃）有差异；未来若 bridge 起用 close_read 需知晓。
- jrh7 入口位置与票面文字（xray-tls）不同（xray-common），理由如上；若 PM 坚持票面位置需先解除 btls 对 tuic 的构建污染。

## 沉淀
- `~/.omp/agent/rules/rust-ffi-cross-target.md` ← tokio TcpStream 无方向 shutdown；Windows 真半关闭借 as_raw_socket 的 ManuallyDrop std 视图调 std shutdown（std 映射 SD_RECEIVE/SD_SEND，Go CloseRead/CloseWrite 同款）。
