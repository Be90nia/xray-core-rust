# audit-fix-xf6z — SS legacy inbound 响应方向 AEAD 认证失败修复

日期：2026-10-09 · 票：bd xf6z (P2) · 基线：master 0be50d9a · 状态：**已修复，待 PM CI 仲裁**

## 结论

VERDICT: FIXED — full chain roundtrip 实测全绿（dispatcher e2e 2/2 + proxy e2e 1/1 + lib 162/162）。

## 根因（最终版，修正票面 NOTES 的 d017662a 描述）

d017662a 的调查结论（「read_request 用 new_client 构造服务端流，响应写不带新 IV」）只对了一半——
那是 75765b4f（2026-09-05）**之前**的旧状态。75765b4f 已给生产 server 路径补上
`begin_server_response`（新随机 IV 先行明文写出 + 写侧 AEAD 重派生 + write_nonce [0xFF;n] 重置，
stream.rs:730-744），`read_request`（server.rs:236）与 `SsInbound::handle_conn`（inbound.rs:94）均已接线。

剩下的另一半在**客户端适配器**：`SsOutbound::process`（outbound.rs:51）走 `dial_target`——
不设 `mark_response_rekey`，客户端读响应仍用请求方向 AEAD。而 server 恒写响应 IV header →
客户端在错误字节偏移（16B IV）+ 错误 AEAD 下解密 → AeadOpen 认证失败。

即：**协议两端分批修复后装配假设错位**——server 升级到 Go 语义（恒写新 IV），客户端适配器还停在
「Rust inbound server 不写 IV header」的过期前提上（该注释原文在 client.rs dial_target_for_proxy 文档）。

## Go 基线对照

- `WriteTCPResponse`（proxy/shadowsocks/protocol.go:191-204）：响应方向生成新随机 IV → 先行明文写出
  → `NewEncryptionWriter(key, iv)` 重派生写侧。Rust `begin_server_response` 逐条对齐。
- client.go:140：客户端读响应恒走 `ReadTCPResponse`（读新 IV + `NewDecryptionReader`）。
  Rust 对称物 = `dial_target_for_proxy`（lazy `mark_response_rekey` → 首次 read_chunk 读 IV 重派生）。

## 改动清单

| 位置 | 改动 |
|---|---|
| `crates/xray-proxy-ss/src/outbound.rs:50-58` | `SsOutbound::process` 改走 `dial_target_for_proxy`（读响应必经响应 rekey），附 why 注释 |
| `crates/xray-proxy-ss/src/client.rs:130-132` | `dial_target_for_proxy` 文档修正：`dial_target` 仅适用不读响应的调用方；生产 server 恒写响应 IV |
| `crates/xray-proxy-ss/tests/ss_dispatcher_e2e.rs:78` | 拆除 ac2ae1d6 的 `#[ignore]`（xf6z 本体） |
| `crates/xray-proxy-ss/tests/ss_proxy_e2e.rs:43,106-109` | 拆除 d017662a 的 `#[ignore]`（同根因）；客户端装配 `dial_target` → `dial_target_for_proxy` |

未动：`dial_target`/`dial_target_on` 本体（剩余调用方 ss_test.rs、interop_ss_test.rs:142 均为只写不读响应场景，
不受影响）；ss2022 族（另一套 salt 语义，测试全绿）；测试断言原文零改动。

## 验证

```
$ cargo test -p xray-proxy-ss --test ss_dispatcher_e2e --test ss_proxy_e2e
running 2 tests
test outbound_inbound_handshake_metadata_matches ... ok
test outbound_inbound_full_chain_to_echo_roundtrip ... ok        ← xf6z 本体，原 known-fail
test result: ok. 2 passed; 0 failed; 0 ignored
running 1 test
test ss_proxy_to_echo_target_e2e ... ok                          ← d017662a 同根因，原 known-fail
test result: ok. 1 passed; 0 failed; 0 ignored

$ cargo test --lib -p xray-proxy-ss
test result: ok. 162 passed; 0 failed; 0 ignored; finished in 5.47s
```

修复前同命令基线（-- --ignored）：`read response chunk: AeadOpen("authentication failed: ...")`，
本地 0.01s 确定性复现，与 CI run 36210988842 表型一致。

## 备注

- 本机验证遇 AV 拦截测试 exe（os error 5），重跑即过（已知环境坑，非本次改动引入）。
- bd xf6z 票面已 append 修复 notes；关票留 PM CI 仲裁后。
