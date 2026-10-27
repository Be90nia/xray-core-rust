# D 面清单：生产面裸 spawn 普查（2026-10-27 夜，可复跑）

> **⚠️ 2026-10-28 复核更正（详见 `spawn-gate-visible.md`）**：下方「未登记 26」经逐站点核对
> **全部已在台账内**（fn 级/语句级/文件级/模块级 allow + reason，均为 clippy.toml 自订分层
> 规则的合法登记形态）——普查扫描的两个方法学缺口造成假阳性：①只认 spawn 紧邻的逐点
> allow，不认 fn/语句/文件级登记；②测试面判定只匹配 `#[cfg(test)]` 字面量，漏掉
> `#[cfg(all(test, any(target_os = ...)))]` 门控模块（splice.rs 5 处实为 unix 门控测试
> spawn，非生产面）。当前 L3 门实跑证据：7 crate `clippy -D warnings` 0 error +
> `redline_sites` 门测试 4/4 绿。复跑时请先核对 allow 覆盖形态再判「未登记」。

普查口径：`crates/**/*.rs`，排除 `crates/udf-frame/`（外部工作副本）、`tests/`、`examples/`、`benches/`、`#[cfg(test)]` 块与注释行。
结果：生产面 **157** 处 = 已逐点 `#[allow(clippy::disallowed_methods)]` 登记 **131** + 未登记 **26**。

| crate | 生产站点 | 已登记 | 未登记 |
|---|---|---|---|
| xray-transport | 43 | 38 | **5** |
| xray-transport-splithttp | 28 | 21 | **7** |
| xray-transport-hysteria | 16 | 16 | **0** |
| xray-core | 10 | 7 | **3** |
| xray-transport-grpc | 8 | 0 | **8** |
| xray-mux | 7 | 7 | **0** |
| xray-proxy-tun | 6 | 5 | **1** |
| xray-stress | 6 | 6 | **0** |
| xray-transport-naive | 6 | 6 | **0** |
| xray-transport-websocket | 6 | 5 | **1** |
| xray-transport-httpupgrade | 4 | 4 | **0** |
| xray-transport-quic | 3 | 3 | **0** |
| xray-app-dispatcher | 2 | 2 | **0** |
| xray-app-reverse | 2 | 2 | **0** |
| xray-proxy-vless | 2 | 2 | **0** |
| xray-reality | 2 | 2 | **0** |
| xray-cli | 1 | 1 | **0** |
| xray-common | 1 | 1 | **0** |
| xray-frame | 1 | 0 | **1** |
| xray-proxy-tuic | 1 | 1 | **0** |
| xray-tls | 1 | 1 | **0** |
| xray-transport-kcp | 1 | 1 | **0** |

## 未登记站点明细（红线门看不见的真缺口）

| 文件:行 | 说明 |
|---|---|
| `crates/xray-core/src/grpc_server.rs:77` | `Ok(tokio::spawn(async move {` |
| `crates/xray-core/src/outbound.rs:274` | `tokio::spawn(async move {` |
| `crates/xray-core/src/outbound.rs:1823` | `tokio::spawn(async move {` |
| `crates/xray-frame/src/redline.rs:106` | `tokio::spawn(fut)` |
| `crates/xray-proxy-tun/src/inbound.rs:903` | `tokio::spawn(async move {` |
| `crates/xray-transport/src/splice.rs:229` | `tokio::spawn(async move { splice_copy(&sa_for_pump, &sb_for_` |
| `crates/xray-transport/src/splice.rs:232` | `let writer = tokio::spawn(async move {` |
| `crates/xray-transport/src/splice.rs:255` | `let bridge = tokio::spawn(async move { bridge_with(s1, s2).a` |
| `crates/xray-transport/src/splice.rs:257` | `let left = tokio::spawn(async move {` |
| `crates/xray-transport/src/splice.rs:264` | `let right = tokio::spawn(async move {` |
| `crates/xray-transport-grpc/src/transport.rs:310` | `let conn_driver_task = tokio::spawn(async move {` |
| `crates/xray-transport-grpc/src/transport.rs:372` | `tokio::spawn(async move {` |
| `crates/xray-transport-grpc/src/transport.rs:508` | `tokio::spawn(async move {` |
| `crates/xray-transport-grpc/src/transport.rs:531` | `tokio::spawn(async move {` |
| `crates/xray-transport-grpc/src/transport.rs:705` | `tokio::spawn(async move {` |
| `crates/xray-transport-grpc/src/transport.rs:725` | `tokio::spawn(async move {` |
| `crates/xray-transport-grpc/src/transport.rs:781` | `tokio::spawn(async move {` |
| `crates/xray-transport-grpc/src/transport.rs:862` | `tokio::spawn(async move {` |
| `crates/xray-transport-splithttp/src/dialer.rs:82` | `tokio::spawn(async move {` |
| `crates/xray-transport-splithttp/src/dialer.rs:374` | `tokio::spawn(async move {` |
| `crates/xray-transport-splithttp/src/transport.rs:270` | `tokio::spawn(async move {` |
| `crates/xray-transport-splithttp/src/transport.rs:367` | `tokio::spawn(async move {` |
| `crates/xray-transport-splithttp/src/transport.rs:831` | `tokio::spawn(async move {` |
| `crates/xray-transport-splithttp/src/transport.rs:862` | `let task = tokio::spawn(serve_h3_request(req, stream, peer, ` |
| `crates/xray-transport-splithttp/src/transport.rs:870` | `tokio::spawn(async move {` |
| `crates/xray-transport-websocket/src/client.rs:339` | `this.joining = Some(tokio::spawn(async move { factory(ed).aw` |
