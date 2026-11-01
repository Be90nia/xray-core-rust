# Wave7 · 0z7zt — metrics 的 tag 形态暴露端点未实现（Go 经 OutboundListener + ohm 注册）

VERDICT: PASS —— metrics tag 形态已接线（OutboundListener + SimpleOhm 注册，Go metrics.go:63-94 逐行对应）；真实二进制经 socks+路由访问 `GET /metrics` 得 200 + Prometheus；listen 回归绿；反证（短路注入）curl rc=52 红；Go 对照实测（Go tag 形态 = /debug/vars JSON，无 /metrics）。

- [x] §1 Go 机制真相（带行号）
- [x] §2 Rust 现状（含半成品盘点）
- [x] §3 挂载点取舍（含与 Go 的差异及理由）
- [x] §4 实现
- [x] §5 端到端证据（tag 形态 + listen 回归）
- [x] §6 反证
- [x] §7 Go 对照
- [x] §8 门禁
- [x] §9 残余风险

---

## §1 Go 机制真相（基准 `D:/Project/Xray-core` @ `92ccc939` = v26.10.17）

### 1.1 `MetricsHandler.Start`（`app/metrics/metrics.go:51-95`）——listen 与 tag **可并存**

```go
// metrics.go:53-61  listen 分支
if p.listen != "" {
    TCPlistener, err := xnet.Listen("tcp", p.listen)
    ...
    go p.serve(TCPlistener, handler)
}
// metrics.go:63-70  tag 分支前置
if p.tag == "" {
    if p.tcpListener == nil { return errors.New("metrics must have a tag or listen address") }
    return nil
}
listener := &OutboundListener{ buffer: make(chan xnet.Conn, 4), done: done.New() }
p.listener = listener
go p.serve(listener, handler)                      // metrics.go:78 同一个 http handler
if err := p.ohm.RemoveHandler(ctx, p.tag); err != nil { /* 仅 LogInfo（:82-84）*/ }
if err := p.ohm.AddHandler(ctx, &Outbound{tag: p.tag, listener: listener}); err != nil {
    // 失败 → Close() 并返回 err（:86-94）
}
```

- 同一个 `http.Handler`（`httpHandler()`，metrics.go:125-137）同时喂两个 listener：
  **`/debug/vars`（expvar JSON + stats + observatory）与 `/debug/pprof/*`**。
  **Go 26.10.17 的 metrics 没有 `/metrics` Prometheus 路径**（全仓 grep `prometheus`
  仅命中 docs 的开发计划文档）——票面「Prometheus 格式输出」在 Go 侧不成立，Go 的
  tag 形态暴露的是 expvar JSON（详见 §7 对照）。
- `Close()`（metrics.go:105-119）：关 tcpListener + 关 OutboundListener +
  `ohm.RemoveHandler(tag)`（容忍失败）。

### 1.2 `OutboundListener`（`app/metrics/outbound.go:16-56`）——chan(4) 缓冲的假 net.Listener

- `add(conn)`（:21-28）：`select { buffer <- conn | <-done | default: conn.Close() }`
  ——**关闭或缓冲满即丢连接**；缓冲容量 4。
- `Accept()`（:31-38）：阻塞；关闭后返回 "listen closed"。
- `Addr()`（:51-56）：`0.0.0.0:0` 假地址（仅满足接口，无寻址语义）。

### 1.3 `Outbound`（`app/metrics/outbound.go:59-103`）——`outbound.Handler`，Link 伪装成 net.Conn

```go
// outbound.go:66-84
func (co *Outbound) Dispatch(ctx context.Context, link *transport.Link) {
    if co.closed { Interrupt(reader/writer); return }
    closeSignal := done.New()
    c := cnc.NewConnection(ConnectionInputMulti(link.Writer), ConnectionOutputMulti(link.Reader),
        ConnectionOnClose(closeSignal))
    co.listener.add(c)
    <-closeSignal.Wait()          // Dispatch 阻塞到连接关闭
}
```

### 1.4 外部如何"经出站"访问（决定 Rust 挂载点的事实）

`Outbound` 实现的是 `outbound.Handler`（`Tag()`/`Dispatch()`），注册进
`outbound.Manager`（= 本仓 `SimpleOhm` 对应物）。**访问路径 = 路由**：配置一条
`routing.rules: [{outboundTag: <metrics-tag>}]`，dispatcher 按出站 tag 把 `Link` 交给
`Outbound.Dispatch`——不是 DNS/端口可达，而是**任何命中该规则的入站连接都被灌进
metrics 的 HTTP server**。即 metrics 的 tag 形态 = 「一个挂在出站表上的内部 HTTP 端点」。

## §2 Rust 现状

### 2.1 半成品盘点（`crates/xray-app-metrics`——**机制件大半已在，差接线**）

| 件 | 状态 |
|---|---|
| `outbound.rs::OutboundListener` | ✅ 已实现：`VecDeque<BoxedConn>` 容量 4 + 关闭丢弃（`try_add`/`accept`/`close`），Go 语义对齐 |
| `outbound.rs::Outbound` | ✅ 已实现：`tag` + listener + closed；`dispatch(BoxedConn)` 投递；另实现 `xray_features::outbound::OutboundHandler`（dial 型 trait，**非 dispatcher 的 DispatchHandler**） |
| `metrics.rs::TokioHttpServer::serve_outbound` | ✅ **实际已实现**（结构体 doc 说「当前 stub」是**过期注释**）：spawn_blocking accept 循环 → `serve_boxed_conn` |
| `metrics.rs::serve_boxed_conn` | ⚠️ **只 downcast `tokio::net::TcpStream`**，类型不匹配 warn 后丢弃——dispatcher 路径的 Link/cnc 连接进不来（**静默失败缝**） |
| `metrics.rs::OutboundRegistrar` trait + `RecordingOutboundRegistrar` | ⚠️ trait 有 `add(Arc<Outbound>)/remove(tag)`，但生产实现缺失：`MetricsFeature` 默认只用 Recording（**只记 tag 不注册**，`feature.rs:59`） |
| `feature.rs::MetricsFeature` | ⚠️ 无 `set_outbound_registrar` 注入口；`close()` 不做 ohm 反注册 |
| 装配（`xray-core/functions.rs:364-374`） | ⚠️ 只注入 stats/obs collector（bd 3xmjx/sex3y）；**无人注入 registrar**。`register.rs:454-455`（bd hfwq）明说「tag 字段只保不丢，inbound handler 供路由暴露属架构接线」 |

### 2.2 结论

缺陷 = **三处断点**：①`serve_boxed_conn` 只认 TcpStream（dispatcher 给的是 cnc 连接）；
②生产 `OutboundRegistrar` 缺失（Recording 只记账）；③装配面无人把 SimpleOhm 注入 metrics。
不是从零写：dispatcher 侧模式在本仓已有**已验证先例**——commander 的
`OutboundHandlerImpl`（`xray-app-commander/src/server.rs:186-232`，Link →
`xray_transport::cnc::ContentNetworkConnection` → listener.add → await close）+
`SimpleOhmDispatchRegistrar`（server.rs:258-275，`ohm.add(tag, handler)` / `ohm.remove(tag)`）。
`xray-app-metrics` 缺 `xray-transport` / `xray-app-dispatcher` 两个 workspace 内依赖。

## §3 挂载点取舍（含与 Go 的差异及理由）

**挂载点 = commander 已验证模式在 metrics 内的复刻**，装配注入点 = `xray-core/functions.rs`
（metrics 既有注入块旁，非 `inbound.rs`/`outbound.rs`）：

| 决策 | 选择 | 理由 |
|---|---|---|
| DispatchHandler 适配器 | `MetricsDispatchHandler`（metrics crate 内，包 `Arc<Outbound>`） | 与 `xray-app-commander/src/server.rs:186-232` 同款（Link → cnc → listener.add → await close）；放 metrics 内可 crate 级 e2e 测试，不必每轮动 xray-core |
| 出站注册面 | `SimpleOhmOutboundRegistrar(Arc<SimpleOhm>)` 实现 metrics 既有 `OutboundRegistrar` trait | 对应 Go `ohm.AddHandler/RemoveHandler`（metrics.go:82-94）；`SimpleOhm::add` 覆盖同 tag 旧 handler（commander 同款） |
| 注入形态 | `MetricsFeature::set_outbound_registrar(&self, Arc<dyn OutboundRegistrar>)`，默认仍 `RecordingOutboundRegistrar` | 与既有 stats/obs 注入（bd 3xmjx/sex3y）同形：Instance 只持 `Arc<MetricsFeature>`，装配点只有 `&self`；默认 Recording 保证「未注入 = 行为不变」（测试兼容） |
| 连接类型 | `BoxedConn`（`Box<dyn Any + Send>`）保持不变，`serve_boxed_conn` 增加 cnc downcast 分支 | listener 保持类型擦除（crate 原设计）；支持 `TcpStream`（listen 形态/测试）与 `ContentNetworkConnection`（tag 形态）两种生产形态，未命中 warn 后丢弃（消除静默失败缝） |
| Cargo.toml | metrics 新增 `xray-transport` + `xray-app-dispatcher`（workspace path）+ dev-dep `xray-buf` | `MetricsDispatchHandler` 需要 `Link`/`ContentNetworkConnection`/`DispatchHandler`/`SimpleOhm`；均为仓内 crate（非外部依赖），commander 同款依赖面，无循环（dispatcher 不依赖 metrics） |

**与 Go 的差异（不许假装一致的部分）**：
1. **HTTP 面不同**：Go tag 形态暴露 `/debug/vars`（expvar JSON）+ `/debug/pprof/*`，
   **没有 `/metrics` Prometheus 路径**；Rust 的 `/metrics`（Prometheus text）+ `/debug/vars`
   + `/debug/pprof` 是本仓 listen 形态既有面，tag 形态复用同一 handler。Go 对照实测证实
   （§7：Go `/debug/vars` 200，`/metrics` 404）。票面要求的「Prometheus 格式输出」按本仓
   既有验收面执行。
2. **`http.Serve` vs 手写 HTTP/1.1**：Go 用 net/http；Rust 用 tokio 手写最小请求行解析
   （crate 既有设计，不引 hyper/axum）。语义覆盖本仓验收所需（GET + 路径路由）。

## §4 实现

| 文件 | 改动 |
|---|---|
| `crates/xray-app-metrics/src/outbound.rs` | 新增 `MetricsDispatchHandler`（`xray_app_dispatcher::DispatchHandler`）：`dispatch` = Link → `ContentNetworkConnection::new(reader, writer).with_on_close(...)` → `outbound.dispatch(Box::new(conn))` → `close_rx.await`（Go outbound.go:66-84 逐行对应；closed 分支 drop link = Go Interrupt） |
| `crates/xray-app-metrics/src/metrics.rs` | ① 新增 `SimpleOhmOutboundRegistrar`（`ohm.add(tag, MetricsDispatchHandler)` / `ohm.remove(tag)`）；② `serve_one` 对流类型泛型化（TcpStream 与 cnc 共用处理逻辑）；③ `serve_boxed_conn` 增加 cnc downcast 分支 + 未命中 warn；④ 修正过期注释（「serve_outbound 当前 stub」→ 实际行为） |
| `crates/xray-app-metrics/src/feature.rs` | `registrar` 改 `RwLock<Arc<dyn OutboundRegistrar>>`（默认 Recording）；新增 `set_outbound_registrar`；`close()` 增加 ohm 反注册（Go metrics.go:113-118 Close 语义，容忍失败） |
| `crates/xray-app-metrics/src/lib.rs` | 导出 `SimpleOhmOutboundRegistrar` / `MetricsDispatchHandler` |
| `crates/xray-app-metrics/Cargo.toml` | 新增 workspace 内 `xray-transport` / `xray-app-dispatcher`（dep）+ `xray-buf`（dev-dep）——**报备**：属仓内 path 依赖，非外部 crate |
| `crates/xray-core/src/functions.rs:374-379` | metrics 注入块追加 `metrics.set_outbound_registrar(Arc::new(SimpleOhmOutboundRegistrar(Arc::clone(&ohm))))` —— **装配面最小改动（+6 行），报备**；`ohm` 在 functions.rs:287 创建、位于本块之前，时序成立 |
| `crates/xray-app-metrics/tests/tag_mode_e2e.rs`（新） | 正向：SimpleOhm 注册 → `ohm.get_handler` → dispatch duplex Link → `GET /metrics` 200 + Prometheus 断言；**反证内嵌**：Recording registrar 下 ohm 表无该 tag |

Rule 结构未动；`crates/xray-app-dispatcher/**` 零改动（只用其公开 API）。

## §5 端到端证据

脚本：`reports/audit-2026-10-31-perf-mem-wiring/fix/scripts/wave7met_metrics_tag_e2e.py`
（真实二进制；原始响应落盘 `fix/tmp/metrics_tag/`）。

### 5.1 tag 形态（Rust，metrics 只有 `tag`，无 listen）

配置：`metrics: {"tag": "metrics-out"}` + socks 入站（:10908）+
`routing.rules: [{inboundTag: [socks-in], outboundTag: metrics-out}]`。
访问路径：`curl --socks5-hostname 127.0.0.1:10908 http://metrics.internal/metrics`
（流量经 socks 入站 → 路由规则命中 → dispatcher 按出站 tag 灌进 metrics HTTP server）。

原始响应（`curl -i`，rc=0）：

```
HTTP/1.1 200 OK
Content-Type: text/plain; version=0.0.4; charset=utf-8
Content-Length: 96
Connection: close

# HELP xray_traffic_bytes Total traffic in bytes by direction
# TYPE xray_traffic_bytes counter
```

（无流量时 body 仅 HELP/TYPE 头——EmptyStats 装配形态，与 listen 形态同源；stats 注入
后计数值随连接出现，bd 3xmjx 已在 functions.rs 集成测试覆盖。）

### 5.2 listen 形态回归

配置：`metrics: {"listen": "127.0.0.1:10909"}`（无 tag）→ `curl http://127.0.0.1:10909/metrics`：

```
HTTP/1.1 200 OK
Content-Type: text/plain; version=0.0.4; charset=utf-8
...
# HELP xray_traffic_bytes Total traffic in bytes by direction
# TYPE xray_traffic_bytes counter
```

### 5.3 crate 级全链路（`tests/tag_mode_e2e.rs`，2/2 PASS）

- `tag_mode_dispatch_serves_prometheus_over_link`：SimpleOhm 注册 → `ohm.get_handler`
  → dispatch duplex Link → 客户端半边 `GET /metrics` → 断言 200 + exposition + 计数值
  回程（`xray_traffic_bytes{type="inbound",tag="e2e_in",direction="uplink"} 1234`）；
  并断言 dispatch 任务在连接被消费关闭后才返回（Go `<-closeSignal.Wait()` 语义）。
- `tag_mode_without_registrar_is_dead`（内嵌反证）：默认 Recording registrar ⇒
  `ohm.get_handler("metrics-out")` 为 None（tag 路径死），注册面仅记账。

## §6 反证

把装配注入短路（`functions.rs` 的 `set_outbound_registrar` 临时注释，即「回到只校验
不接线」形态）→ 重编 release → 同一脚本 tag 相位：

```
===== REVERSE tag 形态（短路 set_outbound_registrar） =====
[curl rc=52]
FAIL: curl 非零退出（tag 形态不可达）
==> REVERSE tag 形态（短路 set_outbound_registrar）: FAIL
```

`curl rc=52`（Empty reply from server）：socks 入站照常、路由规则命中 `metrics-out`，
但出站表无该 tag ⇒ dispatcher 拨号失败 ⇒ 连接被关、零字节响应——与正向（§5.1，rc=0
200）两段输出互为对照。恢复注入后复测（RESTORE 相位）：**rc=0，200 + Prometheus 头**。
crate 级同型反证：`tag_mode_without_registrar_is_dead`（§5.3）。

## §7 Go 对照

Go 26.10.17（`D:/tmp/go2617/xray.exe`）同款 tag 配置（`metrics: {"tag": "metrics-out"}` +
socks + 路由）：

- `GET /debug/vars`（经 socks→路由→metrics-out）→ **HTTP 200**，
  `Content-Type: application/json`，body 为 expvar JSON
  （`{"cmdline":[...],"memstats":{...},"stats":...}`）——Go 的 tag 形态真实可达；
- `GET /metrics` → **404**（Go 无该路径，全仓 grep `prometheus` 仅 docs 命中）。

⇒ Go 的 tag 形态行为基准 = 「路由可达 + expvar JSON」；Rust 侧 `/metrics`（Prometheus）
是本仓 listen 形态既有面在 tag 形态下的自然延伸，字段面为 Go 超集（`/debug/vars` 同样
可访问）。本票接线语义（OutboundListener + ohm 注册 + Dispatch）与 Go 逐行对应，
HTTP 面差异已在 §3 声明。

## §8 门禁

环境：`CARGO_TARGET_DIR=D:/Project/Xray-core-rust/target-Wave7Met` + `BORING_BSSL_PATH`
（预构建 btls）+ `PROTOC` + `LIBCLANG_PATH`。

| 门 | 命令 | 结果 |
|---|---|---|
| test | `cargo test -p xray-app-metrics --all-targets` | **93 tests 全绿**：lib 77 + debug_endpoints 5 + feature_start 6 + prometheus_e2e 3 + **tag_mode_e2e 2**，0 failed |
| clippy | `cargo clippy -p xray-app-metrics --all-targets -- -D warnings` | **Finished，零告警** |
| fmt | `cargo fmt -p xray-app-metrics -- --check` | **0 diff**（FMT_CLEAN_OK） |
| 真互通 | `python fix/scripts/wave7met_metrics_tag_e2e.py` | **3/3 PASS**（tag 形态 / listen 回归 / Go 对照） |
| 反证 | 短路 `set_outbound_registrar` → 重编 → tag 相位 | **curl rc=52 FAIL**；恢复后 RESTORE 相位 **rc=0 200 PASS** |

**改动面确认（`git diff --stat`）**

```
 crates/xray-app-metrics/Cargo.toml      |   8 ++
 crates/xray-app-metrics/src/feature.rs  |  34 +++++-
 crates/xray-app-metrics/src/lib.rs      |   7 +-
 crates/xray-app-metrics/src/metrics.rs  |  60 +++++++---
 crates/xray-app-metrics/src/outbound.rs |  65 +++++++++++
 crates/xray-core/src/functions.rs       | 196 +++++++++++++++++++++++++++++++-
 6 files changed, 346 insertions(+), 24 deletions(-)
 ?? crates/xray-app-metrics/tests/tag_mode_e2e.rs
```

⚠️ `functions.rs` 的 196 行 diff 里**本票只有 `@@ -371,6 +371,12 @@` 一个 hunk（+6 行注入）**；
其余两个 hunk（@@681 / @@6004，+180 行）是**并行代理在 xray-core 的在途改动**，本票未触碰。
未触碰：`xray-core/src/{inbound,outbound}.rs`、`xray-app-dispatcher/**`（只用公开 API）、
splithttp、mux、xudp、transport-*、hysteria。未引入外部依赖（workspace 内 path 依赖已在
§3 报备）。未 commit。

## §9 残余风险

1. **HTTP 面与 Go 不同**（§3 已声明）：Go tag 形态只有 `/debug/vars` + pprof；Rust 额外有
   `/metrics`（Prometheus）。这是本仓 listen 形态既有面的延伸，未为对齐而删功能；若 PM
   要求字节级对齐（去掉 /metrics），另票裁决。
2. **`serve_boxed_conn` 未命中类型走 warn+丢弃**：未来若有第三种 conn 形态进 listener，
   会被丢（有 warn 日志，非静默）。
3. **`OutboundListener::accept` 是阻塞 condvar**（Go chan 语义的同步翻译），跑在
   `spawn_blocking` 上；**Feature::close → handler.close() → listener.close() 是其唯一
   唤醒路径**——装配方若不 close 直接 drop feature，runtime drop 会等这个阻塞任务
   （实测：测试漏 close 即挂死）。生产 Instance.close 走 Feature::close，路径闭合；
   新增测试均已显式 close。
4. **Close 语义补全**：`MetricsFeature::close` 现在会 `registrar.remove(tag)`（对齐 Go
   metrics.go:113-118）；默认 Recording registrar 下 remove 只是记账，行为不变。
5. **未跑 workspace 全量**：改动面 = metrics crate + functions.rs 一个 hunk（xray-core
   release 构建三轮均通过，含我的 hunk 与兄弟代理在途改动共存编译绿）；workspace 全量归
   PM 收口门。
6. **知识图谱**：`index_status` 落后于本票改动，未重建（40+ 并行代理在改树，收口统一重建）。

## §10 收尾

- 构建目录 `target-Wave7Met`（~7G）**已删除**。复跑 e2e 需重编
  （`cargo build --release -p xray-cli`，实测 ~10-14 分钟）后
  `XRAY_RUST_BIN=<release> python reports/audit-2026-10-31-perf-mem-wiring/fix/scripts/wave7met_metrics_tag_e2e.py`。
- 沉淀：本票「tokio runtime drop 会等已开跑的 spawn_blocking 任务——阻塞 condvar 型
  accept 必须 close 唤醒」属语言级可复用坑，见 `~/.omp/agent/rules/rust-testing.md`。
