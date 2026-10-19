# fix-early-data-20261019 — TLS 1.3 0-RTT (early data) 全量落地

> VERDICT: DONE — 客户端 early data（含拒绝重发回退）+ 本地 rustls 服务端接受 + 真实 CF 实测结论。

## 目标

客户端 btls (BoringSSL) 路径提供 0-RTT（含服务端拒绝时的 reset+重发回退）；
本地 rustls 服务端接受 0-RTT；真实 CF (argo ws) 节点实测 CF 是否接受 0-RTT。

## 语义调研结论（实现依据，全部源码实读）

| 事实 | 出处 |
|---|---|
| 0-RTT-capable session 下 `SSL_connect` 停在 ClientHello 后即返回 1（`SSL_in_early_data=1`） | BoringSSL handshake.cc:642（`*out_early_return = true; return 1`）|
| 写窗内 `SSL_write` 发 early data；写超上限/读会先完成握手 | ssl.h:4160-4166 |
| 服务端拒绝 → `SSL_get_error = SSL_ERROR_EARLY_DATA_REJECTED (15)`；`SSL_reset_early_data_reject` 丢弃未完成写、连接可续用，重握手后须重发数据 | ssl.h:4172-4182 + handshake.cc:631-634 |
| session 是否 0-RTT-capable 由服务端 NST 的 `max_early_data_size` 宣告决定；无宣告 = 不提供 0-RTT（自动 fallback，零风险） | ssl.h `SSL_SESSION_early_data_capable` + tls13_client.cc |
| rustls 只接受 stateful resumption 的 0-RTT：`max_early_data_size > 0 && !ticketer.enabled()` | vendor rustls server/tls13.rs:671 |
| rustls stateful NST：ticketer 关时发随机 32B id 存 `ServerSessionMemoryCache(256)`（builder 默认，std feature），并在 NST 宣告 `max_early_data_size` | server/tls13.rs:1322-1343 |
| vendored tokio-rustls `TlsAcceptor::accept` 直连 `ServerConnection`，不经 `Accepting::early_data()`——early data 缓冲无人排空，**必须显式读出并前缀到流**，否则随 0-RTT 发来的 ws upgrade GET 永久滞留 | tokio-rustls server.rs:42-52 + rustls `ServerConnection::early_data()` (server_conn.rs:729) |
| btls-sys bindings 未生成 early-data 符号 → 手动 `extern "C"` 声明（符号在静态 ssl.lib 内，btls_reality.rs REALITY patch 同款先例） | btls-sys grep 0 命中 + ssl.h:4194-4230 |

## 改动清单

### 客户端（crates/xray-tls/src/btls_client.rs）
- FFI：`SSL_set_early_data_enabled` / `SSL_in_early_data` / `SSL_early_data_accepted` /
  `SSL_reset_early_data_reject`（`SSL_get_error` 用 btls_sys 既有绑定）。
- `connect_with_alpn` 增 `early_data: bool` 闸门（`connect` 委托传 false）；
  仅 `SSL_set_session` 命中时启用（无缓存不提供 0-RTT）。
- `EarlyData` per-connection 状态机（无全局锁、无跨连接共享）：
  `Off → Offering{written 缓存} →（读/写驱动握手完成）ACCEPTED`
  或 `Offering →（EARLY_DATA_REJECTED）→ Replay{pending, sent} → 补握手（SSL_do_handshake）→ 普通 SSL_write 重发 → Off`。
- flush/shutdown 在 Replay 期先清重发义务（关闭不丢数据）。
- 拒绝路径握手重跑后对真实证书链**重跑回接验证**（connect 时验证的是 session 预测链）。
- 终态查询 `early_data_accepted(): Option<bool>`（None=未提供，供测试/验收）。
- 配置闸门：`tlsSettings.allowEarlyData`（缺省 false，Go 忽略未知字段），
  解析器 `tls_session_cache::parse_allow_early_data`；仅 ws/httpupgrade 路径
  （`u_client_with_alpn`）透传——其他协议（grpc/splithttp/naive 非幂等首写）天然不启用。

### 服务端（crates/xray-tls/src/server_config.rs + xray-transport-websocket/src/server.rs）
- `allowEarlyData=true` → `max_early_data_size=64KB` 且**不装** ticketer
  （保持 builder 默认 `NeverProducesTickets` + `ServerSessionMemoryCache(256)`，
  NST 走 stateful 并宣告 0-RTT 上限）；缺省行为零变化（bd0kqj ticketer 契约不动，
  既有测试 `bd0kqj_default_server_installs_real_ticketer` 原样通过）。
- `WsListener::accept_tls`：`max_early_data_size>0` 时 accept 完成后显式排空
  `ServerConnection::early_data()` → `EarlyDataPrefixed` 前缀流先吐 0-RTT 字节再接
  TLS 流（修复 early data 被 rustls 缓冲吞掉导致 ws upgrade 悬挂）；缺省配置零包装零变化。
- 接受时 `info` 日志 `TLS 0-RTT early data accepted bytes=N`。

### 接线（零改动受益方）
- ws/httpupgrade 客户端出站经 `u_client_with_alpn(security_json)` 自动获得闸门——
  websocket client.rs 无需改动。
- `xray-reality/probe.rs` 两处 `connect_with_alpn` 调用补 `false`（显式关闭）。

## 验收证据

### 1) 单元/集成测试（真实回环，非 mock）
- `cargo test -p xray-tls --all-targets`：**199 passed / 0 failed**
  - 关键新测 `btls_client::tests::early_data_accept_reject_replay_roundtrip ... ok`：
    真实 TCP loopback 三相——①首连 full handshake 无 0-RTT（终态 None）②warm cache
    重连 → 停窗 → 首写 `PING2` 以 early data 发出 → `Some(true)` ACCEPTED，服务端
    排空缓冲收到的字节与客户端写出逐字节一致 ③同 SNI 拨无 0-RTT 服务端（PSK 解不开）
    → REJECTED → reset+补握手+重发 → `Some(false)`，服务端 post-handshake 完整收到
    `PING3`（无丢失、无重复）。
  - 新配置测试：`allow_early_data_enables_max_early_data_and_disables_ticketer` /
    `allow_early_data_absent_keeps_default_behavior` / parse 边界（非 bool 值安全）。
- `cargo test -p xray-transport --all-targets`：**530 passed / 0 failed**。

### 2) clippy + fmt（stable）
- `cargo +stable clippy -p xray-tls -p xray-transport-websocket -p xray-reality
  --all-targets -- -D warnings`：**exit 0**（仅 vendor rustls 存量告警）。
- `cargo +stable fmt … -- --check`：`Diff in` 计数 **0**（CRLF 检出行尾噪音为本地
  checkout 既有现象，非违规）。

### 3) 本地 harness 三相（D:/tmp/plat-b-verify/harness_ed.py，产物 xray_r4.exe）
- 相 A 冷+暖 burst：10/10 数据通；1 次 full handshake（reused=false）+ 9 次
  0-RTT offer 全 ACCEPTED。
- 相 B 稳态 burst：**新增 10/10 全 ACCEPTED**；`session_reused=true` 9→19
  （**不回退**）；client 写出 early bytes = server 收到 early bytes
  （双方 586/587 字节集合逐连接一致 → 数据完整性）。
- 相 C **重启 server**（session store 清空）：首个 dial 命中真实拒绝路径——
  client `early_data_status=REJECTED` + `early_data replay complete`，重发后数据
  完整送达（10/10 socks 全通）；后续 9 dial 重新暖化后再 ACCEPTED（+9）。
- 汇总行：`offers=29 ACCEPTED=28 REJECTED=1 replays=1 reused=true=29 false=1`，
  `VERDICT: PASS (A warmup / B ACCEPTED+reused / C REJECTED+replay, data intact)`。

### 4) 真实 CF 探针（D:/tmp/wsplat/probe_ed.py，argo ws 节点 us1-argo.begonia92.top）
- 3 轮 × 6 并发（poolSize=0 每请求真拨号，allowEarlyData=true，RUST_LOG debug）：
  18/18 HTTP 响应全通。
- `offers=0`（BoringSSL 从未进入 0-RTT 写窗）+ `reused=true=12`：**CF 边缘对本
  zone 未下发 0-RTT-capable 票据**（NST 无 `max_early_data_size` 宣告）→ 客户端
  自动退 1-RTT 会话复用，零回归、零数据风险。CF 侧无 REJECTED 场景可触发
  （无 capable session 即无 offer）。结论：**CF 当前不提供 0-RTT；复用链路正常**。

### 5) non-native 产物
- `D:/tmp/wsplat/xray_r4.exe`，md5 `cb0de1107c602af8fb7b5eb6ad9c477e`
  （`CARGO_BUILD_RUSTFLAGS="-C target-cpu=x86-64"` release 构建，未触碰 .cargo/config.toml）。

## 非目标/红线遵守

- 未动：用户配置、mux、服务端内核 CC、tests/、.github/、.gitignore、docs/refs/、
  protos/、dist/、vendor/、xray-transport-tcp/register.rs、指纹逻辑、.cargo/config.toml；
  未 commit。工作树中其余 22 个文件为其他代理在飞改动，本次未触碰。
- 0-RTT 仅在缓存 session 命中时提供（无缓存不启用）；非幂等首写协议
  （grpc/splithttp/naive/reality probe 路径）不启用——闸门只在 ws/httpupgrade
  的 `u_client_with_alpn` 读取，且默认关闭。

## 已知边界（非缺陷，如实声明）

- 服务端 early-data 排空接线在 ws listener（`accept_tls`）——grpc/splithttp 等
  transport hub 的 TLS 终结点若未来要接受 0-RTT，需要同款排空+前缀接线
  （本次验收范围=ws/CF，未外扩）。
- rustls stateful 0-RTT 无内建防重放（`ServerSessionMemoryCache::get` 不取走
  session）——单连接级重放由调用方语义防（本仓场景=ws upgrade GET 幂等 +
  VLESS 认证层）；启用 `allowEarlyData` 的服务端配置应有此认知。
- CF 探针结论是时点实测（2026-10-19）；CF 开启 zone 级 0-RTT 后重跑探针即可复测。
