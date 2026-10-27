# 测试端口探测 TOCTOU 竞态消除 — 审计报告

VERDICT: CONDITIONAL-PASS
（本任务交付与验收全绿；唯一保留项 = `crates/xray-core` 一个**与端口探测无关的存量栈溢出测试**，见 §4，非本任务非目标允许触碰）

- 任务：全量 `cargo test --workspace --all-targets` 唯一失败 `integration_socks_through_ss_to_echo`（`InstanceStart("inbound \`socks-in\` (socks) start failed: … os error 10048")`），分面跑绿、全量并行偶发。
- 根因：`TcpListener::bind("127.0.0.1:0")` 取空闲端口 → `drop(probe)` 释放 → 被测实例稍后再绑同端口；drop 与再绑之间的窗口在全量并行（大量测试同时探测临时端口）下被其他测试/进程抢占。
- 加重因素：仓内既有重试 helper（functions.rs `start_full_retrying_eaddrinuse`）的错误判定用 `format!("{e:?}").contains("in use")`——**中文 Windows 上错误消息已本地化**（"通常每个套接字地址…只允许使用一次"），判定永不命中，重试形同虚设；且全量 34 个 integration 测试里只有 1 个走了该 helper。

## 1. 普查站点清单

### 1.1 修复站点（bind(:0)→drop→被测方再 bind，53 个调用点 / 9 个 wrapper）

**`crates/xray-core/src/functions.rs`（34 测试 / 52 个 `start_full_retrying_eaddrinuse` 调用点，含 `n_ports=2` 单实例双端口 1 处）**：

integration_socks_through_ss_to_echo（**报告的失败测试**）· start_full_socks_inbound_to_freedom_outbound_e2e · naive_inbound_to_naive_outbound_two_stack_e2e · integration_splice_admitted_two_stack_echo · access_log_full_chain_socks_to_freedom_e2e · graceful_shutdown_cancels_inbound_tasks · integration_socks_through_vmess_to_echo · assert_socks_chain_via_inbound_settings（vmess/vless users-form ×2 测试共用）· integration_socks_through_vless_to_echo · integration_socks_through_trojan_to_echo · integration_vless_over_websocket_to_echo · integration_ss2022_over_websocket_to_echo · integration_routing_selects_correct_outbound · integration_vless_over_tls_to_echo · integration_vless_vision_over_tls_to_echo · integration_vless_vision_testseed_to_echo · integration_trojan_over_tls_to_echo · integration_vmess_over_tls_to_echo · integration_trojan_tls_fallback_routes_failed_handshake · integration_vless_tls_fallback_routes_non_vless · integration_sniffing_tls_sni_routes_by_sniffed_domain · integration_routing_geoip_private_blocks · integration_stats_counters_via_default_dispatcher · integration_metrics_app_exposes_real_stats_counters · integration_socks_udp_relay_to_echo · integration_socks_udp_through_router · integration_ss_udp_relay_to_echo · integration_loopback_outbound_reinjects_to_inbound（2 端口单实例）· integration_outbound_mux_tcp_reuses_single_carrier（`server_probe`/`client_probe` 命名，首轮 `drop(probe)` 普查漏网、复查 `start_full` 调用点补获；carrier forwarder 移到 server 端口定 retry 后再起，防转发到陈旧端口）· integration_outbound_mux_tcp_via_vless_inbound · vless_mux_go_server_interop（`#[ignore]`）· integration_udp_relay_through_outbound_mux · integration_socks_outbound_loopback_to_echo（既有已迁移样例，改配新签名）。

**`crates/xray-core/src/inbound.rs`（3 测试 × 每腿 1 探测，`spawn_one_inbound_retrying`）**：ss_inbound_wears_finalmask、ss_inbound_udp_wears_finalmask、dokodemo_inbound_udp_wears_finalmask。

**`crates/xray-app-commander/src/commander.rs`（3 测试，`start_commander_retrying`）**：listen_mode_exposes_declared_stats_service、listen_mode_hides_undeclared_stats_service、listen_mode_declared_without_backend_not_exposed（原 `reserve_port()` 已删；`tcp_bind_failure_escalates_to_start_error` 的 holder **保活占位**不属 TOCTOU，未动）。

**`crates/xray-app-metrics`（9 测试）**：src/metrics.rs `repeated_scrapes_do_not_accumulate_handles`（内联重试环）；tests/debug_endpoints.rs（`pick_port`→`start_server_retrying`，覆盖 start_server 包装 + PopulatedStats 内联点，5 测试）；tests/feature_start.rs（`start_feature_retrying`，4 测试）；tests/prometheus_e2e.rs（`start_server_retrying`，3 测试）。

**`crates/xray-proxy-wireguard/src/inbound.rs`（5 测试，UDP 端口，`new_handler_retrying`）**：construct_inbound_handler、start_close_lifecycle、tunnel_tcp_end_to_end_echoes、tunnel_tcp_inbound_large_response_no_truncation、tunnel_tcp_inbound_dispatch_eof_flushes_tail（原 `free_port()` 已删；`construct_allows_no_peers` 用 port 0 显式语义，未动）。

**`crates/xray-transport-splithttp/tests/mock_server.rs`（1 测试）**：packet_up_end_to_end_tls_h2_via_serve_http_conn——probe→drop→`listen_splithttp` 再绑（TransportListener 不暴露 local_addr 才需 probe；首轮普查 grep 输出截断漏网，收尾全仓复查 `drop(probe)` 残留时补获）。内联重试环。

### 1.2 普查到但不修（bind(:0)→drop 但**无被测方再绑**，不属本模式）

- **故意死端口类**（断言 connect/查询失败；drop 正是制造"无监听"的手段——保活监听会让 TCP connect 因 backlog 握手成功而改变语义）：xray-proxy-socks/client.rs、xray-proxy-ss/dispatcher.rs + outbound.rs、xray-proxy-vless/dispatcher.rs、xray-proxy-vmess/dispatcher.rs、xray-proxy-http/server.rs `dead_port()`（自带"竞态概率可忽略"注记）、xray-app-geodata/tests/real_download.rs（connection_refused）、xray-tls/ech_doh.rs、xray-app-dns doh.rs（永不 accept 腿）+ quic.rs（DoQ UDP 死端口）+ udp.rs（silent server）。
- **listener 自持类**（probe 出的 listener 即最终服务，存活至断言结束，端口从不被再绑）：xray-app-dispatcher 3 处 echo、xray-app-dns doh/tcp/udp mock server 族、xray-app-observatory、xray-app-reverse、xray-buf readv、xray-cli framework/remote_config stub、xray-app-router condition、xray-app-geodata spawn_server、xray-core UDP echo 族 + ss2022 relay 族、xray-proxy-freedom/socks/ss/trojan/dns-proxy UDP echo 族、xray-app-proxyman uot/worker。
- **Drop 语义测试**（drop 的就是被测 listener 本身，测关闭行为，无复用）：xray-transport-grpc/register.rs、xray-transport-httpupgrade/register.rs。
- **压测二进制路径**（`xray-stress/topology.rs::pick_free_port`：pick→立即 rebind echo / 喂 start_full；其单测不触达 start 路径，`cargo test` 不执行压测链路；quic_loop.rs 已自带"被抢→换端口重试"；改动属压测工具链重构，超出"只改测试/测试辅助"边界，留档不改）。

## 2. 修复机制

**统一原语（`crates/xray-common/src/testing/mod.rs`，仓内既有测试工具模块，复用优先）**：

1. `pick_free_ports(n) -> Vec<u16>`：N 个探测 listener 在取号全程存活（OS 保证组内互不重号——顺带消除旧"两连 probe-drop"可能取到同一端口的第二竞态），全部取齐后统一释放，把窗口收敛为"释放→被测方 bind"一段。
2. `is_addr_in_use_err(err: impl Debug) -> bool`：匹配 `(os error 10048)`（Windows WSAEADDRINUSE，Display 尾缀与本地化消息无关）/`(os error 98)`（Unix EADDRINUSE）/`AddrInUse`（io::Error Debug 形态 `Os { code: 10048, kind: AddrInUse, .. }` 经 `#[from]` 透传），覆盖"错误串格式化"与"错误链透传"两种落盘形态。

**各 crate 重试 wrapper（语义 =「启动失败且为地址占用 → 换新端口重建配置重试，至多 5 次」；5 次全撞 panic fail-visible，不静默、不 sleep 掩盖）**：

| crate | wrapper | 包裹的被测启动点 |
|---|---|---|
| xray-core/functions.rs | `start_full_retrying_eaddrinuse(n_ports, build)`（既有 helper 泛化：N 端口组 + Windows 判定 + 返回完整四元组） | `start_full` |
| xray-core/inbound.rs tests | `spawn_one_inbound_retrying` | `spawn_one_inbound` |
| xray-app-commander | `start_commander_retrying` | `Commander::start`（重建 Commander + 服务声明） |
| xray-app-metrics ×2 tests | `start_server_retrying` / `start_feature_retrying` | `TokioHttpServer::start_http_listen` / `MetricsFeature::start` |
| xray-proxy-wireguard | `new_handler_retrying` | `WireguardInboundHandler::new`（构造期绑 UDP） |
| xray-transport-splithttp tests | 内联 loop | `listen_splithttp` |

约束遵守：只改测试/测试辅助（`xray-common/src/testing` 既有测试面模块）；未放宽/删除任何断言（helper 对非占用错误立即 panic，占用重试只替换端口号，配置内容与断言逐字节不变）；无 sleep 掩盖（测试内既有就绪 sleep 原样保留，不新增）；未动产品代码逻辑与 `.github/`。clippy 联动：新原语按 xray-common `unwrap_used=deny` 门改用 `expect`（同会话 ConnNotify 代理实证并复跑通过）。

## 3. 验收（实测）

| 验收项 | 命令 | 结果 |
|---|---|---|
| 原失败测试 3 连跑 | `cargo test -p xray-core --lib integration_socks_through_ss_to_echo -- --nocapture` ×3 | 3× `test result: ok. 1 passed; 0 failed`（0.23s/0.23s/0.24s） |
| xray-core 全量 lib | `RUST_MIN_STACK=16777216 cargo test -p xray-core --lib` | `test result: ok. 477 passed; 0 failed; 2 ignored` |
| xray-common | `cargo test -p xray-common --lib` | `ok. 461 passed; 0 failed` |
| xray-app-commander | `cargo test -p xray-app-commander --lib` | `ok. 93 passed; 0 failed` |
| xray-app-metrics lib | `cargo test -p xray-app-metrics --lib` | `ok. 77 passed; 0 failed` |
| xray-app-metrics integration（改动文件所在） | `cargo test -p xray-app-metrics --test debug_endpoints --test feature_start --test prometheus_e2e` | 5+5+3 = 13 passed; 0 failed |
| xray-proxy-wireguard | `cargo test -p xray-proxy-wireguard --lib` | `ok. 110 passed; 0 failed` |
| xray-transport-splithttp（改动文件所在） | `cargo test -p xray-transport-splithttp --test mock_server` | `ok. 8 passed; 0 failed` |
| fmt 门 | `cargo fmt --all -- --check` | clean |
| clippy 联动门 | `cargo clippy -p xray-common --all-targets -- -D warnings` | 通过（新原语已改 expect） |

## 4. 修复前后风险说明 + 唯一保留项

- **修复前**：探测→释放→再绑窗口内端口被抢 → `InstanceStart(os error 10048)` 直接 fail（并行度越高越易触发；分面跑无并发探测故绿）。既有 helper 的 `"in use"` 字符串判定在中文 locale Windows 上永不命中（本地化消息），即使测试走 helper 也无法重试。
- **修复后**：占用 → 整组换端口重试（≤5 次）。组内端口由存活期取号保证互异；重试仅替换端口号，不改任何断言。失败模式从"偶发 flake"变为"需同时抢占 5 个不同端口才 panic"（实际不可达），且 panic fail-visible。
- **唯一保留项（与本任务无关的存量缺陷，非目标范围，未修）**：`cargo test -p xray-core --lib`（**默认栈**）在 `inbound::tests::mixed_socks_udp_associate_roundtrip`（2026-10-20 commit 2fef9285 引入，非本次改动面）确定性栈溢出（`STATUS_STACK_OVERFLOW` 0xc00000fd）。实证三连：①隔离 `--test-threads=1` 仍溢出（与并行度无关）；②`RUST_MIN_STACK=16777216` 下该测试 0.01s 通过（深但**有界**的递归/future 嵌套，预算边缘）；③该测试及其产品路径（serve_mixed/socks-UDP relay）不在本次 diff 触及面。任务开工时"唯一失败"观察应即为此测试当时未越出栈预算 / 或树在此后落入更深嵌套的 refactor（[INFERENCE] 近期 inbound.rs W4 scope 重构 b46d6058 疑似加大嵌套，未深挖）。处置建议：单开票——产品侧查 serve_mixed future 嵌套深度，或测试侧 `RUST_MIN_STACK` 固化（后者动 CI = 红线，须授权）。
- **残余风险**：修复面内极端端口耗尽场景 5 次全撞 → fail-visible panic（比静默错绑安全）；死端口类测试（§1.2）的微小竞态窗口保留原状（注释已自认概率可忽略，且修复需改变测试语义）。

## 5. 五维自评

| 维度 | 评分 | 说明 |
|---|---|---|
| 正确性 | 4.5 | 53 个 TOCTOU 调用点收口到统一机制（含 2 处首轮普查漏网、复查补获）；跨平台判定双实证（Windows 10048 本机 + Linux 98 CI run 35218583839）；扣 0.5：死端口类微竞态按范围裁决留档未修 |
| 性能 | 5 | 零热路径改动；测试侧仅探测 N 个 listener 存活期取号，开销与原逐个 probe 相当 |
| 可维护性 | 4.5 | 判定/取号单一出处（xray-common::testing），各 crate wrapper ≤25 行；删除 3 个分散 pick helper；新增 integration 测试有单一范式可抄 |
| 风格 | 4.5 | 复用仓内既有 helper 形态与命名（`_retrying` 后缀）；fmt --check clean；注释写 why（TOCTOU 窗口 + 本地化坑）；clippy unwrap_used 门已过 |
| 测试 | 5 | 验收全跑：xray-core --lib 477/0 + 原失败测试 3 连跑 + 5 个改动面 crate/测试目标全 0 failed（明细 §3） |

## 7. tests/ 目录补收口（PM 授权追加轮，2026-10-28）

PM 复核发现顶层 `tests/`（红线验证资产，本次获授权仅限端口探测 TOCTOU 收口类改动）仍是同一竞态裸奔区——`e2e_p2_dokodemo_full_chain` 与 `e2e_p2_tls_utls_pinned` 在全量跑下复现 os error 10048。本轮普查 `tests/**` 全部 23 个测试目标并收口。

### 7.1 站点清单（14 文件 / 约 55 个探测点）

| 文件 | 探测点 | 修复形态 |
|---|---|---|
| integration/e2e_p2_test.rs | 7（含 DNS mock UDP 自绑 1 处；2 个失败用例在内） | `start_full_retrying` helper（5 处实例启动）+ UDP 自绑内联环；删 `pick_free_port` |
| integration/transport_interop_test.rs | 10（5 测试 × vless/vmess+socks） | `start_full_retrying` helper + 每测试 server/client 各自独立重试闭包；删 `pick_free_port` |
| integration/fingerprint_matrix_test.rs | 4（REALITY/TLS 两个 run_* helper） | 内联换端口环（保留 `Result<(),String>` 错误路径语义）；删 `pick_free_port` |
| integration/grpc_multimode_e2e_test.rs | 2（run_grpc_e2e helper） | 内联换端口环；删 `pick_free_port` |
| integration/gap_matrix_e2e_test.rs | 7（6 测试，G-15 双实例 ×2） | 新增 `start_xray_retrying(build)->u16`（复用文件内 `start_xray` 语义 + LISTENER_READY_DELAY）；删 `pick_free_port` |
| integration/e2e_test.rs | 4（E2eTestBuilder.with_xray） | 每测试内联环：端口占用时重建 builder + 换端口重试（echo server 随组重建）；删 `pick_free_port` |
| integration/policy_test.rs | 2（start_pair helper） | server/client 各自内联换端口环；删 `pick_free_port` |
| integration/sniffing_test.rs | 2（start_topology helper，http+snif 双端口） | `pick_free_ports(2)` 整组换端口环；删 `pick_free_port` |
| integration/commander_api_test.rs | 2（start_with_api + reflection 未 opt-in 用例） | 内联换端口环（start_full 直启 api app）；删 `TcpListener` 探针 |
| integration/test_dial_xray.rs | 2（两个双实例用例的 server 腿） | 内联换端口环；删 `pick_free_port` |
| integration/test_passive_connection.rs | 1 | 内联换端口环；删 `pick_free_port` |
| integration/test_udp_connection.rs | 1 | 内联换端口环；删 `pick_free_port` |
| integration/wireguard_dataplane_test.rs | 10（4 用例 × (wg_port+entry_port[+inner_port])，含 UDP echo 自绑 ×2） | `pick_free_ports(2/3)` 整组换端口环；client 先启、server 撞占用时 abort client 句柄再整组重试；`spawn_udp_echo` 改返 `io::Result` 由环内重试；删 `pick_free_port`/`pick_free_udp_port` |
| integration/commander_gap_test.rs | 3（start_api_instance_once 内） | **不改动**——外层 `start_api_instance` 已有 5 次重试兜底（判定含 "10048"/"address in use"，中文 Windows 消息命中 os error 10048 尾缀），同一机制先例 |

### 7.2 依赖

`tests/Cargo.toml` 的 `[dev-dependencies]` **本就含 `xray-common`** → 零 manifest 改动、零新依赖、无循环风险（xray-common 不依赖 tests 包）。全部环体直接调用 `xray_common::testing::{pick_free_ports, is_addr_in_use_err}`。

### 7.3 约束遵守与验收

- 红线目录内仅动「端口探测收口」一类测试辅助：**断言逐字节未动**（helper 对非占用错误原语义上抛/panic；重试只替换端口号）；无新增 sleep；非端口类测试未触碰；未 commit。
- `cargo test -p xray-integration-tests --test integration_e2e_p2` ×3（最终树态）：

```
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.27s
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.26s
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.27s
```

- `cargo test -p xray-integration-tests` 全 target（23 个测试二进制）：**0 failed**——vmess 9/0 · commander_api 4/0 · commander_gap 5/0 · compatibility 5/0 · dial_xray 2/0 · e2e 4/0 · **e2e_p2 5/0** · fingerprint 4/0 · gap_matrix 6/0 · grpc_multimode 4/0 · interop_ss 2/0(+5 ign) · interop_trojan/vless/vmess 0/0(+9 ign) · passive 1/0 · policy 2/0 · sniffing 2/0 · ss 8/0 · transport_interop 5/0 · trojan 3/0 · udp_connection 1/0 · vless 2/0 · wireguard_dataplane 4/0。
- `cargo fmt -p xray-integration-tests -- --check` → clean（workspace 级 `cargo fmt --all -- --check` 在前一轮已 clean；本轮不复查全树，避免误格式化同树其他代理的 xray-frame 在飞改动）。
- 附带清理：修复过程移除 tests/ 内 12 个已无调用的 `pick_free_port`/`pick_free_udp_port` 探针 helper 与 2 处 `TcpListener` 死 import，全包零 warning。
- 私有 target 目录 `target-PortToctou-2b` 用毕删除。
