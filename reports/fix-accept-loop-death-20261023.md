# fix-accept-loop-death-20261023 交付报告

PASS
VERDICT: PASS | loops_fixed=6+1 | files_changed=7M+1A | tests=1150 passed/0 failed | clippy_workspace_deny_warnings=exit0 | fmt_my_crates=clean | commit=none

- 日期：2026-10-23
- 范围：inbound accept 循环「错误文本/无条件 break 决定生死」缺陷（生产实证：8 号机 443 在 26.10.10/26.10.11 被「TLS 握手成功→断开」两步客户端 ≤11 秒打死，监听消失、进程存活、日志零线索）
- 契约：原合同 3 处 + PM 追加 #2（hysteria）+ 追加 #3（httpupgrade/splithttp/stress 形态对齐 + 共享助手 `xray_transport::accept_policy` 替代 per-crate 方案）

## 0. 共享助手（新文件）

**`crates/xray-transport/src/accept_policy.rs`（新增，244 行含测试）**
- `pub enum AcceptErrorKind { Resource, Connection, Unknown }` —— 无「退出」变体：退出在类型表示域上不存在，结构性保证任何错误分类都不产生退出
- `pub fn classify(e: &io::Error) -> AcceptErrorKind` —— kind 优先（Connection: Aborted/Reset/BrokenPipe/UnexpectedEof/TimedOut；Resource: OutOfMemory/ResourceBusy/WouldBlock/Interrupted），其余大小写不敏感 "too many" 文本兜底 → Resource，再否则 Unknown
- `pub async fn backoff_if_resource(e: &io::Error)` —— 仅资源类 sleep 500ms（对齐 xray-core accept_fd_backoff）
- `pub async fn supervise_accept_loop(tag: &str, local: String, handle: JoinHandle<()>)` —— 循环句柄 panic（非显式 close 的唯一意外退出途径）时 `tracing::error!` 留痕，文案含 tag/local/panic 摘要；显式 close（close_notify/abort→cancelled）静默
- `fn panic_brief(Box<dyn Any + Send>) -> String`（私有）
- 接线：`crates/xray-transport/src/lib.rs:31` +`pub mod accept_policy;`

## 0.5 立论：Go 原版为什么安全，我们为什么中招（一手来源对照，PM 追加 #4）

**Go `transport/internet/tcp/hub.go` `keepAccepting`（D:/Project/Xray-core）**：accept 循环里同样有 `strings.Contains(errStr, "closed") { break }`——写法与我们一字不差，但 Go 安全，因为它的错误分类前提不同：**TLS/REALITY/header 包装全部发生在每连接 goroutine 内**（`go func(){ conn = tls.Server(conn,...); ...; v.addConn(...) }()`），accept 循环只可能拿到 **listener 级**错误（Accept 系统调用失败），"closed" 文本在它的前提下只可能来自真正的监听器关闭。**Go `transport/internet/websocket/hub.go`** 走 `http.Server.Serve`，每连接错误由 net/http 内部消化，同样不会因单连接错误而死。

**Rust 复刻为何中招**：`xray-transport-websocket/src/server.rs` 的 `accept_tls` 把 TCP accept → PROXY protocol → TLS accept → WS handshake **全部内联在 accept 循环里 await**——单连接级错误（rustls "peer closed ... close_notify" / tungstenite `ConnectionClosed`）与 listener 级错误共用同一个 Err 分支，照抄 Go 的文本匹配就成了一颗子弹打死整个监听（生产 P1 票 wsiq，8 号机 443 实锤）。**这是复刻引入的缺陷，不是 Go 的设计。**

**对修复形态的影响（已照此实现）**：
1. 不修文本匹配，改为**显式分类**：判定依据是错误类型/kind；文本只允许作为资源类兜底且大小写不敏感（`accept_policy::classify`）。
2. 「真监听器已关闭 → 退出」在 Rust 侧由**显式 close 信号**表达（ws/tcp/unix = close_notify 分支；hysteria/httpupgrade/splithttp = close() 的 abort 句柄）——裁决理由：没有任何 io `ErrorKind` 能可靠区分「监听器真关闭」（EBADF 也可能是瞬时 fd 错误），而 PM 追加 #3 铁律（验收标准不变）规定错误永不作为退出条件；Go 的文本匹配恰恰证明了「用错误特征推断关闭」在错误分类前提变化时会误杀。
3. hysteria：`QuinnQuicListener::accept` 返回 `io::Result<Arc<dyn QuicConn>>`（quinn endpoint accept 包装，quinn_adapter.rs:360-364）——错误即 `io::Error`，直接交共享 `classify`；endpoint 关闭场景由 close() 的 abort 句柄先落地（close() 先 abort 本循环再 ep.close，见该处既有注释），错误路径永不退出。

**WsError 逐变体归类（`register.rs::accept_kind`，映射即修复核心）**：

| WsError 变体 | 归类 | 依据 |
|---|---|---|
| `HandshakeFailed(String)` | **Connection** | 服务端仅在三处产生：tcpmask wrap 失败 / TLS accept 失败（rustls 错误串，含 "tls accept: ..."）/ 4s 超时——全部发生在已 accept 的连接上 |
| `InvalidUpgradeRequest { .. }` | **Connection** | WS 升级请求非法，单连接 |
| `InvalidOpcode(u8)` | **Connection** | 帧解析，单连接 |
| `FrameTooLarge(u64)` | **Connection** | 帧解析，单连接 |
| `Tungstenite(..)` | **Connection** | 握手/帧/协议违规；**含生产杀手链**（rustls UnexpectedEof "peer closed ..." 经 tungstenite `Error::Io` 包装） |
| `Io(io::Error)` | **共享 classify 细分** | 唯一可能含 listener 级的变体（`listener.accept()` 系统调用失败 / tcpmask IO）：连接类 kind → Connection；OOM/Busy/WouldBlock/Interrupted/"too many"（大小写不敏感）→ Resource；其余 → Unknown（warn+继续，永不退出） |

## 1. 六处循环修复（改前 → 改后）

### ① ws accept 循环 —— 生产杀手（`crates/xray-transport-websocket/src/register.rs`）
- 循环体 121-165（Err 分支 139-154）；映射助手 `accept_kind` 591-600；supervise 接线 163；测试 1234 起
- 改前：
  ```rust
  Err(e) => {
      let msg = e.to_string();
      if msg.contains("closed") { break; }          // ← 杀手：rustls "peer closed ... close_notify" 命中即整个 443 监听消失
      // ponytail: too many open files 时 sleep 重试，其他错误继续
      if msg.contains("too many") { sleep(500ms) }
      continue;
  }
  ```
- 改后：`match accept_kind(&e)` → Connection=`debug!`(tag+error 原文)、Resource=`warn!`(tag+local+error)+`backoff_if_resource`、Unknown=`warn!`；**循环无任何错误退出路径**，唯一 `break` 在 close_notify 分支；spawn 后接 `supervise_accept_loop("ws", ...)`
- 注：原 `// ponytail:` 标记随分支重写移入 Backoff 语义（退避 500ms 防忙旋），原文案"too many 时 sleep 重试，其他错误继续"的事实由 accept_policy rustdoc 承接；「ws 监听级错误原 warn+continue 不退避」→ 现统一退避（时序变化仅错误路径，无 wire 影响）

### ② tcp accept 循环（`crates/xray-transport/src/tcp/hub.rs`）
- keep_accepting doc 84-93 + Err 分支 127-141；spawn_accept_loop 75-87
- 改前：`err_str.contains("closed") => break` + 大小写敏感 `contains("too many")` 退避 + warn+continue
- 改后：`match classify(&e)` 三级日志 + `backoff_if_resource`；无错误退出；`spawn_accept_loop` 改「监控包裹」结构（JoinHandle 不可 Clone：外层 task spawn 内层循环并 supervise，返回外层句柄，await/drop-detach 语义不变）

### ③ unix accept 循环（同文件）
- struct 246-253（新增私有字段 `path: String` —— 意外退出日志标识 inbound 用，unix `local_addr()` 是全零占位）；listen() 构造 271；Err 分支 298-311；spawn_accept_loop 275-285
- 改前：与 ② 相同的 `contains("closed") => break` 写法
- 改后：同 ②（tag=`tcp-unix`，日志带 `path` 字段）

### ④ hysteria accept 循环（`crates/xray-transport-hysteria/src/register.rs:122-161`）
- 改前：`Err(_) => break` —— 任何 accept 错误（含单连接级）直接杀监听，无退避无日志
- 改后：`match classify(&e)` 三级日志 + 资源类退避 + `continue`；退出唯一来源是 close() 的 abort 句柄（先 `abort_handle()` 再把句柄 move 进 `supervise_accept_loop("hysteria", ...)`）
- 注：同文件 `accept_hysteria_conn` 内 `accept_bi` 的 `Err(_) => break`（~166）是**连接级**循环（只结束该连接的 task）——核实安全，未动

### ⑤ httpupgrade accept 循环（`crates/xray-transport-httpupgrade/src/register.rs:104-186`）
- 改前：`Err(e) => { debug!("HTTPUpgrade accept error: {e}"); continue; }` —— 无退避（EMFILE 忙旋烧 CPU）、无分级
- 改后：`match classify(&e)` 三级日志 + 资源类退避；接 `supervise_accept_loop("httpupgrade", ...)`

### ⑥ splithttp(XHTTP) accept 循环（`crates/xray-transport-splithttp/src/transport.rs:156-218`）
- 改前：`Err(_) => continue` —— 无退避无日志
- 改后：同 ⑤（tag=`splithttp`）；接 `supervise_accept_loop("splithttp", ...)`

### ⑦ xray-stress echo 循环形态对齐（`crates/xray-stress/src/topology.rs:82-87`）
- 改前：`Err(e) => { warn!("echo accept fatal, stopping echo: {e}"); break; }`
- 改后：`warn!` + 100ms 退避 + continue（该 crate 无 xray-transport 依赖，**不改 Cargo.toml** 故内联对齐形态，不调共享助手）

## 2. 验收命令实际输出

```
$ cargo test --lib -p xray-transport -p xray-transport-websocket -p xray-transport-hysteria \
             -p xray-transport-httpupgrade -p xray-transport-splithttp   # 最终代码（fmt 写回后）
test result: ok. 610 passed; 0 failed; 0 ignored; ... finished in 6.25s    # xray-transport
test result: ok.  90 passed; 0 failed; ...       finished in 2.09s         # hysteria
test result: ok. 110 passed; 0 failed; 1 ignored; ... finished in 0.11s    # splithttp
test result: ok. 232 passed; 0 failed; ...       finished in 2.10s         # httpupgrade
test result: ok. 108 passed; 0 failed; 1 ignored; ... finished in 2.12s    # websocket
cargo-test-exit:0                                                          # 合计 1150 passed / 0 failed

$ cargo clippy --workspace --all-targets -- -D warnings
clippy-exit:0                      # 全仓（含 6 个改动 crate）零告警

$ cargo fmt --all -- --check       # CI 口径（rust-toolchain.toml 钉 nightly-2026-05-28）
# 改动的 6 个 crate：0 diff（全量 diff 仅剩 crates/udf-frame/** 既有项，见 §4）
```

## 3. 新增测试（16 个）

**accept_policy.rs（xray-transport）—— 8 个**
| 测试 | 断言要点 |
|---|---|
| `single_connection_errors_are_connection_class` | Aborted/Reset/BrokenPipe/UnexpectedEof/TimedOut → Connection（继续） |
| `resource_errors_are_resource_class` | OutOfMemory/ResourceBusy/WouldBlock/Interrupted → Resource（退避+继续） |
| `emfile_enfile_detected_regardless_of_text_case` | "Too many open files"（大写 T）与小写同判 Resource —— 旧 `contains("too many")` 大小写敏感静默失效的回归锁 |
| `closed_text_never_maps_to_exit_because_exit_is_not_representable` | "Connection closed normally" / "peer closed connection without sending TLS alert" → Unknown（warn+继续）；**退出不在 AcceptErrorKind 表示域** |
| `backoff_skips_non_resource_errors_immediately` | 非资源类零 sleep 直达（时序断言只证路径，不睡 500ms 拖 CI） |
| `supervise_logs_error_with_tag_local_and_last_error_on_panic` | 【测试③】循环 task panic → ERROR 级日志含 tag/local/panic 摘要/WITHOUT close signal（手写 mini Subscriber + `set_default` 捕获，不引 tracing-subscriber dev-dep） |
| `supervise_is_silent_on_clean_close` | 显式 close（正常结束）零日志 |

**hub.rs（tcp/unix 共用助手的 accept 场景锁）—— 3 个**
`accept_queue_abort_is_connection_class`（ECONNABORTED/WSAECONNRESET→Connection）、`emfile_enfile_backs_off_regardless_of_text_case`、`closed_text_still_never_maps_to_exit`

**websocket register.rs（accept_kind 映射）—— 5 个**
| 测试 | 断言要点 |
|---|---|
| `tungstenite_connection_closed_maps_to_connection` | 【测试①】tungstenite ConnectionClosed（Display "Connection closed normally"，含小写 closed）→ Connection；前置断言证明文本命中旧触发条件 |
| `rustls_peer_closed_via_tungstenite_io_maps_to_connection` | 【测试①】生产触发链按**本仓 vendored rustls 实际形态**建模：握手后对端断开 → conn.rs `UNEXPECTED_EOF_MESSAGE`（"peer closed connection without sending TLS close_notify..."，`ErrorKind::UnexpectedEof`；上游 rustls 同义错误为 `Error::PeerClosed` "...TLS alert"）→ tungstenite `Error::Io` → `WsError::Tungstenite` → Connection |
| `tls_accept_handshake_failed_path_maps_to_connection` | rustls 错误另一落地路径 `HandshakeFailed("tls accept: ...")` → Connection |
| `listener_level_io_errors_classify_resource_with_any_case` | EMFILE 大小写两态 → Resource |
| `connection_dropped_mid_handshake_maps_to_connection` | PROXY/握手读取中途断开（UnexpectedEof/Reset/Aborted）→ Connection |

## 4. 同族问题核实结论（只报告，未改的均为 PM「已核实安全」清单项）

- **已修 6+1 处**：见 §1。PM 清单「已核实安全、不要动」的 9 处（quic transport、splithttp h3、hysteria quinn_adapter h3、grpc h2、httpupgrade 无、tuic/utls `?` 传播、xray-transport listener/system_listener 辅助方法）全部未动 ✓
- **hub.rs `unreachable!("tcpmask wrap failed but conn was moved by auth wrap")`（keep_accepting 内 ~119）**：真实的 panic 杀监听路径（tcpmask wrap 失败即炸掉整个 accept task）——本次未改逻辑（Tidy First），但 supervise 已把它从「静默死亡」变为「error! 留痕」；建议后续任务单独分诊
- **xray-core 的 `accept_fd_backoff` 委托共享助手**：PM 追加 #3 标注为「可选但推荐」；原合同非目标明确不动 xray-core，**显式跳过**（xray-core 7 处循环本就符合样板）
- **`cargo fmt --all -- --check` 全仓视角有既有 diff**：全部位于 `crates/udf-frame/**`（skeleton/std-ext/skeleton-infra，约 1.6 万行 diff 输出），非本次引入（该目录不在本次改动集，git 未跟踪其修改），属 udf-frame 工作流资产；PM 收口时需确认其是否在 CI fmt 门内
- **可选行为级验证（本地 ws+tls inbound 两步客户端）**：按 PM 追加 #2 指示以决策助手单测覆盖（避免 CI flaky），真机复现归 PM 灰度 8 号机执行
- rustls 事实勘误（供 PM 对表）：本仓 vendored rustls 的 `Error` 枚举**无 `PeerClosed` 变体**；"peer closed" 文本实际出自 `conn.rs:302 UNEXPECTED_EOF_MESSAGE`（`ErrorKind::UnexpectedEof` + "…without sending TLS close_notify…"），机制与 PM 核对的链路一致（文本含小写 closed → tungstenite Io → `WsError::Tungstenite`），测试已按本仓真实形态建模

## 5. 行为面边界声明

- wire/握手顺序/超时值/协议语义：零改动（全部改动在错误分支与 spawn 结构；`#[cfg(unix)]` 代码本机不可编译验证，CI linux 兜底）
- 时序变化仅错误路径：监听器级错误从「warn+立即 continue」变「warn+500ms 退避」（对齐样板）；tcp/unix `spawn_accept_loop` 返回句柄语义不变（await=循环结束，drop=detach）
- 未 commit / 未 push（归 PM 审计）

— FixAcceptLoopDeath 2026-10-23
