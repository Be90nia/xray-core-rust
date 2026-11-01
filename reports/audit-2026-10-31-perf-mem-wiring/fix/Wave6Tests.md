VERDICT: PASS

# Wave6Tests — 三条「产品契约已收紧、测试未跟上」修复

- 基线：`feature/fix-inbound-parity` @ `a750a542`（CI 在 5fe98b90 全绿 → 三条失败是本轮引入的测试滞后）
- 改动面：**只有 3 个文件的 `#[cfg(test)]` 区** + 各文件内自建小 helper；产品代码零改动，无新依赖，未 commit。
- 工具：三处均用 read/grep 定位（`cargo` 命令取证），未调用 serena-cli（纯 `#[cfg(test)]` 代码段，符号级检索无增量）。

---

## 1. `xray-proxy-vless --lib inbound::server::tests::vless_outbound_udp_roundtrip_e2e`

### 根因

波1（98c8a360 / bd t0ls1）把 `crates/xray-proxy-vless/src/dispatcher.rs` 的 UDP link 表示从「裸载荷」重写为 XUDP 帧：

```rust
// crates/xray-proxy-vless/src/dispatcher.rs:551-552
/// `[2B BE len][裸载荷]`，见 `xray-app-dispatcher::udp_session`。
type VlessUdpFramedConn = XudpWireConn<Box<dyn Connection>>;
```

`XudpWireConn`（`crates/xray-app-dispatcher/src/udp_session.rs:549+`）的契约：上行把 link 的 XUDP 帧 `[meta][2B BE len][payload]` 剥成裸载荷写 wire；下行把 wire 的 `[2B len][payload]` 裹回 XUDP 帧交付 link。

测试仍按旧契约写裸 `b"ping"` 并 `read_exact(payload.len())`。裸字节被 `XudpUnframer::feed` 当帧解析（`probe_xudp_frame` 把 payload 头两字节当 `meta_len`），服务端因此收不到有效 UDP 载荷 → 无下行 → 客户端 `read_exact` 得 `early eof`（即 PM 观察到的失败点 `server.rs` 内 `expect("read")`）。

产品侧自洽：同提交的 dispatcher 单测（`vless_udp_framed_conn_roundtrip`）已用 XUDP 帧，绿。

### 改法

`crates/xray-proxy-vless/src/inbound/server.rs`（测试模块内新增两个 helper + 改 4 步往返体）：

- `fn xudp_frame(dest: &Destination, payload: &[u8]) -> Vec<u8>` — 用 `xray_xudp::packet::FrameMetadata::new_udp(dest.address().clone(), dest.port(), gid)` + `[2B BE len][payload]` 构造 link 帧（`xray-xudp` 已是该 crate 的 dev-dependency，未加依赖）。
- `async fn read_xudp_payload(conn) -> (FrameStatus, Vec<u8>)` — 按帧内长度逐段 `read_exact`（先 `meta_len`、再 `meta`、再 `data_len`、再 payload），**不越读**；`meta[2]` 解析 `FrameStatus`。
- 往返体：写 XUDP 帧 → 读回一帧 → 断言 `status == [New, Keep][idx]`（帧序 + 会话复用）且 `payload` 逐字节一致；包数仍是两包（`ping` / 600B），断言未放宽。

### 反证（临时改回裸 payload → 重新失败）

```
test inbound::server::tests::vless_outbound_udp_roundtrip_e2e ... FAILED
thread 'inbound::server::tests::vless_outbound_udp_roundtrip_e2e' (20324) panicked at crates\xray-proxy-vless\src\inbound\server.rs:1357:18:
read: Custom { kind: UnexpectedEof, error: "early eof" }
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 277 filtered out; finished in 0.51s
```

### 最终测试输出

```
running 1 test
test inbound::server::tests::vless_outbound_udp_roundtrip_e2e ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 277 filtered out; finished in 0.01s
```

---

## 2. `xray-proxy-vmess --lib inbound::server::tests::vmess_outbound_udp_roundtrip_e2e`

### 根因

同一波（bd t0ls1）把 vmess UDP link 表示也切成 XUDP 帧：`VmessUdpConn`（`crates/xray-proxy-vmess/src/dispatcher.rs:512+`）内部持有 `XudpUnframer`（上行剥帧）+ `XudpReframer`（下行裹帧），doc 原文「内部 dispatch link 跑 XUDP 帧，VMess wire 跑裸载荷 chunk（目标在请求头）」。测试仍写/读裸载荷 → 首包被 `XudpUnframer` 按帧格式解析（payload 头两字节当 `meta_len`，帧永远攒不齐 → 整包滞留 `accum`），服务端零 chunk → 无回包 → 客户端 `read_exact` 超时（PM 记为 `early eof`，本机复现为 `roundtrip timeout`，同一根因的时序差异）。

### 改法

`crates/xray-proxy-vmess/src/inbound/server.rs`（测试模块内）：

- `fn xudp_frame(payload: &[u8], first: bool) -> Vec<u8>` — **手拼**线格式（vmess crate 不依赖 `xray-xudp`，加 dev-dependency 属「引入新依赖」，故不用它），格式与同 crate `dispatcher::tests::xudp_frame` 完全一致；帧内目标只是格式占位（vmess 服务端转发目标取自请求头）。
- `async fn read_xudp_payload(conn) -> (u8, Vec<u8>)` — 同上的逐段精确读，`meta[2]` 返回状态字节。
- 往返体：写帧（首包 New / 次包 Keep）→ 读回 → 断言 `status == [1, 2][idx]` 且 payload 逐字节一致；两包（`ping` / 600B）不变。

### 反证（临时改回裸 payload → 重新失败）

```
test inbound::server::tests::vmess_outbound_udp_roundtrip_e2e ... FAILED
thread 'inbound::server::tests::vmess_outbound_udp_roundtrip_e2e' (35512) panicked at crates\xray-proxy-vmess\src\inbound\server.rs:1167:18:
roundtrip timeout: Elapsed(())
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 172 filtered out; finished in 10.01s
```

### 最终测试输出

```
running 1 test
test inbound::server::tests::vmess_outbound_udp_roundtrip_e2e ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 172 filtered out; finished in 0.02s
```

---

## 3. `xray-transport-splithttp --lib transport::tests::h3_server_receives_stream_one`

### 根因（与任务书的假设不同，证据在下面）

原测试把 `security_json` 只设成 `{"alpn": ["h3"]}`——**服务端一个证书都没有**。而 bd mwvwd F2 已取消「缺证书自签兜底」（`crates/xray-tls/src/server_config.rs:200-212`：缺证书只 warn，握手逐连接失败）→ rustls 服务端 `resolve` 返回 `None` → 客户端收到 `crypto(31) "unexpected error: no server certificate chain resolved"`。

**这个错误是服务端侧产生的**，不是客户端 `allowInsecure` 的问题：`client_config.rs:103-113` 显示 `allowInsecure=true` 至今仍是「warn + 跳过验链」（`warn_removed_feature`），并未变成硬错。实测反证见下一节：**服务端配上证书后，客户端继续用 allowInsecure 反而能通过**。

### 改法

`crates/xray-transport-splithttp/src/transport.rs`：

- 服务端：`generate_self_signed_cert(&["localhost"])` 生成证书，写入 `settings.security_json` 的 `certificates: [{ "certificate": cert_pem, "key": key_pem }]`（Go `certificates[]` 语义，`build_named_cert_keys` 只在有 key 的 encipherment 条目上采纳）。
- 客户端：去掉 `allowInsecure`，改用现成信任入口 `pinnedPeerCertSha256`（`crates/xray-tls/src/client_config.rs:365+` 的 pin 段；命中叶子即放行，等价 Go `foundLeaf`）。pin 由 `xray_tls::pin::generate_cert_hash_hex(certs[0].as_ref())` 算出（与 `xray-transport-naive` 测试同一写法）。SNI/连接主机名取证书 SAN `localhost`（`endpoint.connect(addr, "localhost")`），HTTP `host` 头保持 `127.0.0.1:port` 不变。
- 产品侧无改动：`certificates[]` 与 pin 都是既有产品路径。

### 反证

**反证 A（任务书假设的形态）：客户端改回 `allowInsecure`、服务端保留证书 → 仍通过**（说明 allowInsecure 不是失败原因）

```
test transport::tests::h3_server_receives_stream_one ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 266 filtered out; finished in 0.02s
```

**反证 B（真正的必要条件）：客户端保持 pin、服务端去掉证书（`"certificates": []`）→ 失败**，与修复前同一错误：

```
test transport::tests::h3_server_receives_stream_one ... FAILED
thread 'transport::tests::h3_server_receives_stream_one' (21904) panicked at crates\xray-transport-splithttp\src\transport.rs:1371:71:
quic connect: ConnectionClosed(ConnectionClose { error_code: Code::crypto(31), frame_type: None, reason: b"unexpected error: no server certificate chain resolved" })
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 266 filtered out; finished in 0.01s
```

### 最终测试输出

```
running 1 test
test transport::tests::h3_server_receives_stream_one ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 266 filtered out; finished in 0.02s
```

---

## 4. 门禁命令汇总

|命令|结果|
|---|---|
|`cargo test --workspace --all-targets --no-fail-fast`|**EXIT=0**，196 个 test binary，**8091 passed / 0 failed / 35 ignored**，日志内 `failures:` 0 次、`error` 行 0 次（`D:/tmp/wave6-full-test.log`）|
|`cargo clippy --workspace --all-targets -- -D warnings`|EXIT=0，仅 vendored `rustls` 自带的 2 条既有告警（本仓代码零告警）；格式化后再跑 `-p vless -p vmess -p splithttp --all-targets` 重编三 crate，同样 EXIT=0|
|`cargo fmt --all -- --check`|本仓 0 diff（仅 `crates/udf-frame/**` 外部工作副本有既有 diff，按任务书忽略）|

### 全量 test 汇总行（196 条，`binary → test result`）

- `xray_app_commander-63035ac1cc2864aa` → test result: ok. 93 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.12s
- `xray_app_dispatcher-23ee9f4d442252d9` → test result: ok. 148 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.19s
- `dual_write_longrun-75ec3a086a68047e` → test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
- `dual_write_parity-2d6fc83ed222bbe8` → test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
- `ohm_lookup_ab-6df7c2e63c782988` → test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
- `xray_app_dns-4331d1720fb290d0` → test result: ok. 244 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 7.38s
- `dns_e2e-8e50849d4bda7d4b` → test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.08s
- `xray_app_geodata-0ccf51a3c200e4c6` → test result: ok. 88 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.03s
- `cron_schedule-562b8afdc8b9db94` → test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.10s
- `geodata_parallel_load-0a0721c7d233e348` → test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.12s
- `load_and_query_e2e-1ca3ae3f2c1c27fe` → test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
- `real_download-a55a7f0b404d61bc` → test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.06s
- `xray_app_log-d8669fc6295a7443` → test result: ok. 87 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
- `dns_log_and_write_failure-62ee4d5ed3131832` → test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
- `general_quiet-04907775eb6248ed` → test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
- `general_visibility-58adf1413432c53f` → test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
- `xray_app_metrics-ecf5568289059e2f` → test result: ok. 77 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.50s
- `debug_endpoints-1ae12fae1f362fc7` → test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.27s
- `feature_start-a9ed5f87eaa4fe4d` → test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.42s
- `prometheus_e2e-81898850d4a5d469` → test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.08s
- `xray_app_observatory-55abceed8ea24723` → test result: ok. 158 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.52s
- `observe_stream-35d9a2064b726763` → test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
- `xray_app_policy-ff26b21f26a28bfc` → test result: ok. 27 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
- `xray_app_proxyman-18a7c25dff0d2f64` → test result: ok. 124 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.24s
- `xray_app_reverse-3035c984a493885c` → test result: ok. 93 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 4.02s
- `reverse_e2e-fc323138afbcd717` → test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.08s
- `xray_app_router-01d6972d59d01916` → test result: ok. 160 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.05s
- `router_parallel_build-7449b12b0fb1156c` → test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 7.33s
- `xray_app_stats-ca448ce551f49cb2` → test result: ok. 119 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.11s
- `xray_app_version-108e364073234390` → test result: ok. 21 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
- `xray_buf-89af7876df154623` → test result: ok. 207 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.12s
- `xray_cli-f69f6ab97233ad23` → test result: ok. 100 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.05s
- `xray-4a097b90f02bc8a9` → test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
- `cli-005e68acbab56b04` → test result: ok. 18 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.74s
- `xray_common-deb58093eeb4d714` → test result: ok. 470 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.17s
- `alloc_site_zero_alloc-82ff5a2a41738ee5` → test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
- `log_single_entry-23b862c9f4c8a8ed` → test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.05s
- `unregistered_channel_warn-d57f7e16459f0cac` → test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
- `xray_conf-9e5c8dbae88b32a6` → test result: ok. 222 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.03s
- `config_file_shadow-881e540b9239d06b` → test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
- `udf_rev_anchor-8917476652ca574c` → test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.05s
- `xray_core-76c1dfe6a1360803` → test result: ok. 510 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out; finished in 31.77s
- `assembly_path_equivalence-24f404489122a137` → test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
- `bind_failure_fatal-0f130521115ade33` → test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
- `invalid_inline_cert_startup-056d862f94176266` → test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
- `xray_crypto-392be212f0f65b66` → test result: ok. 128 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.24s
- `xray_features-267ab27ca1fd83d4` → test result: ok. 73 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
- `xray_frame-fad705107490ce46` → test result: ok. 99 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.31s
- `assembly_e2e-8b78a64f23e3ab54` → test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
- `compat_caps-4ea605d89886b4cd` → test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
- `compat_fallback-92b0d7ce33b8677b` → test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
- `config_merge-974723257f3242ca` → test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
- `config_routing-3b85b2f358b4c494` → test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
- `conn_scope-a4c8405df0ff86c8` → test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.03s
- `contract_assert-c5befc0f698293db` → test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
- `deadline_budget-8878cf98482b9b83` → test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.15s
- `deadline_contract-c3b688f2b9638c1e` → test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.03s
- `fx_managed_spawn-8793a6421913de6e` → test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
- `hot_log-4e025081cc5a1308` → test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
- `l4_fixtures-96b0ecfba9250c23` → test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.22s
- `lifecycle_order-bd5d51a7849dd75e` → test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
- `log_discipline-b621456f0f294aa6` → test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
- `observe_fields-1ce3d29b7e01cac5` → test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
- `observe_wire-aea37f34b7264080` → test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
- `plugin_context-0517b9b261b3da4a` → test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
- `plugin_registry-a21320bc3a609af6` → test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
- `pool_isolation-b05a84f855feb633` → test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
- `redline_sites-ad2745ee58565795` → test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.58s
- `reload_rollback-eed7a76e20ae1314` → test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.07s
- `shutdown_wiring-4ab870bc5797df1f` → test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.01s
- `xray_geodata-5b1c0db42ea20987` → test result: ok. 261 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.04s
- `registry_reload-726389e6f9ead136` → test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
- `strmatcher_go_parity-51f602e5f44c1675` → test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
- `integration-7abb0c6c4098e9db` → test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 30.01s
- `integration_commander_api-3cc2dd2b2a7e430a` → test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.05s
- `integration_commander_gap-8116fbe36efa6bb3` → test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.33s
- `integration_compatibility-b1ee84d9e0480da3` → test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
- `integration_dial_xray-5564b63028a38deb` → test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
- `integration_e2e-1da38fdf468458c8` → test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.11s
- `integration_e2e_p2-cd732bf8c0c4d399` → test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.29s
- `integration_fingerprint_matrix-176b4554fde50138` → test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.06s
- `integration_gap_matrix-58e00bac5576ca22` → test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.24s
- `integration_grpc_multimode-764c26ec7e506c62` → test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.06s
- `integration_interop_ss-372b8160fbd67eac` → test result: ok. 2 passed; 0 failed; 5 ignored; 0 measured; 0 filtered out; finished in 0.55s
- `integration_interop_trojan-1c65ed80b1d831ef` → test result: ok. 0 passed; 0 failed; 3 ignored; 0 measured; 0 filtered out; finished in 0.00s
- `integration_interop_vless-a54f6938971151d7` → test result: ok. 0 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out; finished in 0.00s
- `integration_interop_vmess-e3e68cdba6398b70` → test result: ok. 0 passed; 0 failed; 4 ignored; 0 measured; 0 filtered out; finished in 0.00s
- `integration_passive_connection-4a40e44a8535c5e9` → test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
- `integration_policy-5c7fd88119cb60d1` → test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.18s
- `integration_sniffing-b2f72c633433cdfa` → test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.13s
- `integration_ss-efbb439496db124b` → test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
- `integration_transport_interop-07a14cb37d96826e` → test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.31s
- `integration_trojan-c072e39cba29158d` → test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
- `integration_udp_connection-bcac161be6785e9e` → test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
- `integration_vless-f8e31974708ea9ab` → test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
- `integration_wireguard_dataplane-2f7136122d11f550` → test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.85s
- `xray_mux-83351a68e2fd8a8a` → test result: ok. 145 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.12s
- `integration-6b60dfd188560e85` → test result: ok. 23 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
- `xray_proto-18401a13e739acdd` → test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
- `xray_proxy_anytls-bafb56684b69a6d1` → test result: ok. 39 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.33s
- `dial_system_contract-d46f8ac6058639ee` → test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.06s
- `dispatcher_loopback-cc446e822ecce1cc` → test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.07s
- `inbound_dispatch-55d1e3eece6cd7b5` → test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.07s
- `loopback-1b42913362676794` → test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.06s
- `plugin_contract-0c31d59a3e46f419` → test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
- `xray_proxy_blackhole-bd47d1978310e7d1` → test result: ok. 37 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.02s
- `dispatch_bridge-a4ea08678ad549e5` → test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
- `plugin_assembly-8ee16b28419a6feb` → test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
- `plugin_contract-bcee1122ab052927` → test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.01s
- `xray_proxy_dns-8fdbeac4ab0b8e1f` → test result: ok. 85 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.94s
- `dispatch_bridge-dd17040382531d83` → test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
- `plugin_contract-c8c61d21387a7896` → test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
- `xray_proxy_dokodemo-97f33e4ee423c275` → test result: ok. 46 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
- `plugin_contract-6f389c8879f09f6d` → test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
- `xray_proxy_freedom-7d144a8274eb2062` → test result: ok. 100 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 5.04s
- `plugin_contract-3da20c51a9032d3f` → test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
- `xray_proxy_http-29e000a43d489e0f` → test result: ok. 85 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.12s
- `http_proxy_e2e-7ed23a6ca830a214` → test result: ok. 22 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.05s
- `plugin_contract-58f8da5350d7cb1a` → test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
- `xray_proxy_hysteria-0925c19562c407bf` → test result: ok. 73 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.04s
- `e2e-430d0a1449fb1e42` → test result: ok. 2 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.07s
- `plugin_contract-7c94f58d4b26639b` → test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.23s
- `xray_proxy_loopback-7d300f91216213fc` → test result: ok. 28 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
- `dispatch_bridge-cc926e0298879d48` → test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.10s
- `plugin_contract-d5d02279d43b1f88` → test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.22s
- `xray_proxy_socks-402c86fc5f279502` → test result: ok. 88 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 10.78s
- `e2e_proxy-95eb60cd49c27cdf` → test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
- `error_variants-7f2f2a286d8fa373` → test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
- `plugin_contract-e46b488cd51fb481` → test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.21s
- `xray_proxy_ss-bf395bae65761fb1` → test result: ok. 185 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 5.74s
- `error_variants-6327a3a0cbecbc1b` → test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
- `plugin_contract-224fbfb9dabe1736` → test result: ok. 17 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.23s
- `ss2022_uot_multi_e2e-5a7c94ba7294d842` → test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.03s
- `ss_dispatcher_e2e-1d7fcefc1198972c` → test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
- `ss_proxy_e2e-987dbfb434f6c405` → test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
- `vps_interop-c27ad42b2e25c641` → test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s
- `xray_proxy_trojan-f211294b7d3f6c53` → test result: ok. 88 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.08s
- `error_variants-b0163c51459c241d` → test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
- `plugin_contract-8a2c881949c6b703` → test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.22s
- `trojan_proxy_e2e-df40b13a368ed25e` → test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.03s
- `vps_interop-0916510260ba34fb` → test result: ok. 0 passed; 0 failed; 3 ignored; 0 measured; 0 filtered out; finished in 0.00s
- `xray_proxy_tuic-b6971ce7a6eae556` → test result: ok. 68 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 31.10s
- `dispatcher_loopback-692ff998aeb02fb4` → test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.17s
- `domain_dial-525268a5b9fd1799` → test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.18s
- `inbound_dispatch-a4a9fcabb1bf95e1` → test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.08s
- `loopback-6d5723236b9c0496` → test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.36s
- `plugin_contract-cb5018a2386c20ea` → test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.22s
- `udp_loopback-11d012f7b850639b` → test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.06s
- `xray_proxy_tun-d59a611920950fa0` → test result: ok. 154 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.25s
- `plugin_contract-df6cf04c0b5754d7` → test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.22s
- `wfp_live-cf17bd124254c9c1` → test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
- `xray_proxy_vless-8fb70074bd0ca48a` → test result: ok. 277 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 48.84s
- `plugin_contract-98e7d63dbd4d502f` → test result: ok. 14 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.22s
- `vless_proxy_e2e-2a31d6ad0e1098f4` → test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
- `vps_interop-c43d29687fe3f468` → test result: ok. 0 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out; finished in 0.00s
- `xray_proxy_vmess-3825406d20ed8650` → test result: ok. 173 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.24s
- `body_roundtrip-e37ff9536d378aa1` → test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
- `error_variants-6e93d18f4e8aa403` → test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
- `plugin_contract-c057959524cdddcc` → test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.22s
- `vmess_proxy_e2e-71024f84b7ec1677` → test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.04s
- `vps_interop-923a7e9394c65477` → test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s
- `xray_proxy_wireguard-b89b5842ae6a00e7` → test result: ok. 112 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 5.02s
- `plugin_contract-a1b337ed831208ed` → test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.22s
- `xray_reality-0a6d80ecf2dc5aac` → test result: ok. 165 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 15.03s
- `reality_tls_smoke-26637ca616c25457` → test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.05s
- `vps_interop-1765534cedd69017` → test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s
- `xray_stress-0783abd6fa4e8b3b` → test result: ok. 21 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
- `xray_stress-6d62dfa26f77e804` → test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
- `xray_tls-5a548b26b6ad1f79` → test result: ok. 215 passed; 0 failed; 3 ignored; 0 measured; 0 filtered out; finished in 2.08s
- `xray_transport-e8abe1924e4d9865` → test result: ok. 675 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out; finished in 12.09s
- `udp_tproxy_chain-e320a1143086528a` → test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
- `xray_transport_grpc-61d3c0902aac7dd8` → test result: ok. 94 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 5.05s
- `xray_transport_httpupgrade-dcf7bd2cadb0c801` → test result: ok. 91 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.14s
- `xray_transport_hysteria-8f728d4d21f2ca2b` → test result: ok. 115 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.53s
- `xray_transport_kcp-62db9cb92a938d14` → test result: ok. 179 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.09s
- `mask_roundtrip-41f4b56ad043b4d7` → test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.23s
- `xray_transport_naive-daa8857dd5eca73b` → test result: ok. 17 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.06s
- `xray_transport_quic-86cd8935d8b9a226` → test result: ok. 147 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.28s
- `xray_transport_splithttp-d2626d58bc5b2b73` → test result: ok. 267 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.11s
- `hub_limits-acb9cd6c4e3c9b54` → test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.10s
- `mock_h3_server-1622ac6d33775c56` → test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.57s
- `mock_server-9f0b8523c0ab9baa` → test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.55s
- `reality_integration-d77f5ec44218d178` → test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.06s
- `stream_h2-467c28c9cbc5338e` → test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.38s
- `xray_transport_tcp-c0a854b2df7c39c5` → test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
- `tcp_finalmask_dial-35a31f39bafa5421` → test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 8.18s
- `tcp_header_dial-eb4a6486469f60b9` → test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.04s
- `tcp_reality_dial-cb44b115878f6ce2` → test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.08s
- `tcp_tls_dial-0e6468826bac29ce` → test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.06s
- `xray_transport_websocket-211edeab2100a50f` → test result: ok. 109 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 2.09s
- `register_dialer-b6cfe0418801ce54` → test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.04s
- `ws_e2e-a1dc931660e35ac6` → test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 3.05s
- `xray_xudp-8aeb2b21ae1213f8` → test result: ok. 38 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
- `env_basekey-502330b4d954a6a0` → test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
- `env_legacy_name-37c5518b0881b995` → test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
- `integration-ad41a1c476c2070f` → test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
