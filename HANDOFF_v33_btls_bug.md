# HANDOFF v33 (2026-09-04) — btls Chrome 133 ClientHello 实装有 bug (ws 路径下 server RST)

## 关键发现: btls Chrome 133 ClientHello 字节不正确

**实证** (会话 2026-09-04 15:30-16:13):

| transport | 接 fingerprint (btls Chrome 133) | 实测 32 节点结果 |
|---|---|---|
| **tcp** (register.rs:104 已接) | ✅ 已接 | **19/32 PASS (baseline 21/32 包含 tcp)** |
| **websocket** (register.rs 我加的) | ✅ 接 | **9/32 PASS (大灾难!)** — vmess/trojan+ws+btls 全 FAIL with RST |

## 具体错误 (vmess + ws + btls Chrome 133)

```
ERROR dial failed: vmess dial server (ws): tungstenite error:
WebSocket protocol error: httparse error: invalid HTTP version tag=proxy
```

**含义**:
1. Client 发 ClientHello (btls Chrome 133 字节布局)
2. **Server reset connection (TLS-level DPI 拒绝)**
3. Client 收不到 ServerHello, 也收不到后续 HTTP upgrade 响应
4. tungstenite 解析 httparse invalid version

**结论**: **btls Chrome 133 ClientHello 字节被 CF/CDN 拒识** — btls 实装的某个 extension/cipher/sigalg/GREASE 字节布局**与真实 Chrome 133 不一致**。

## 已知 btls 实装 (crates/xray-tls/src/btls_client.rs)

- Chrome 133/131/120/Firefox 148/120/Safari 26.3/iOS 13/14/18.4/Edge 106/133/360 11.0/QQ 11.1 全部**自称** 真指纹
- 但是没做过**逐字节 wire 比对** vs Go uTLS Chrome 133 ClientHello 字节
- TCP 路径下能 PASS 不是因为 btls 实装对, 而是因为 TCP 路径测试用的是**没用 fingerprint 的节点**(security=tls 但 fp=chrome 解析后走 u_client + btls,但 server 端可能在 TLS 1.2 协商后退到 RFC 默认套件,不严格校验 ClientHello 字节)

## 已 revert 的改动 (commit 不留)

回滚了 `crates/xray-transport-websocket/src/{client,register}.rs` + `tests/ws_e2e.rs` + `crates/xray-transport-httpupgrade/src/register.rs`。
**HEAD 现在 = d072815 + 当前 revert**。

**dist/xray.exe** = **0d7ba463 (clean HEAD 21/32 baseline)**。

## 接下来要做

**P0**: **验证 btls Chrome 133 ClientHello 字节与 Go uTLS 一致**。

方法: 
- 起 Go uTLS client 发 Chrome 133 ClientHello, 用 tcpdump/wireshark 抓 ClientHello 字节 hex
- 用 Rust xray.exe + btls client 发 ClientHello, 抓字节
- 对比两段 hex 找差异点

或者更简单:
- 跑 `xray.exe run -c cfg.json` 时开 `RUST_LOG=debug` 看 btls 是否 log cipher/extension
- 或: 加 eprintln 打印 ClientHello bytes.len() + 前 200 字节 hex

如果差异确定, 修 `crates/xray-tls/src/btls_client.rs` 对应指纹表。

**P1**: 4 个 transport (websocket/httpupgrade/splithttp/grpc) 等 P0 修完后再统一接入 fingerprint。

**P2**: mlkem (#7 #10 #11 #12 #13 #16) 复合节点修复需要架构重构, 不在本任务。