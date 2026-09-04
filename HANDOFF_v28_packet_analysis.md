# Xray-core-rust HANDOFF v28 (2026-09-04) — Wireshark 抓包根因分析

> **当前 baseline: 21/32 PASS**
> **本次会话**: 用 Wireshark+tshark 抓包定位 11 个 FAIL 节点根因
> **关键发现**: 8 个节点 Rust bug, 2 个服务端不可控, 1 个边角 case

## 1. 抓包环境

- Wireshark 4.6.8 装在 `D:\Project\tools\Wireshark\`
- tshark CLI: `D:\Project\tools\Wireshark\tshark.exe`
- npcap 1.84 内核驱动已装（用户手动管理员装 + 重启）
- 抓包脚本: `D:\tmp\cap_all.py` (批量) + `D:\tmp\cap_rust.py` / `D:\tmp\cap_go.py` (单节点)
- 抓包结果: `D:\tmp\cap_rust_<idx>.pcapng` + `D:\tmp\cap_go_<idx>.pcapng` (idx = 节点行号)
- 摘要: `D:\tmp\cap_summary.json`

## 2. 抓包方法

1. 同时抓 loopback (i=4) + ethernet (i=3) 两网卡
2. tshark duration 15s + curl https://www.youtube.com/ 触发 xray
3. Rust/Go 各抓一次对比

## 3. 11 节点分类

| 节点 | Rust | Go | 分类 | 真根因 |
|------|------|-----|------|--------|
| #1 vmess+xhttp+argo | FAIL | PASS 876KB | Rust bug | xhttp transport 用 hyper-rustls, ClientHello 257B 不像 Chrome |
| #7 vless+xhttp | FAIL | PASS 880KB | Rust bug | 同 #1 |
| #10 vless+httpupgrade | FAIL | PASS 875KB | Rust bug | httpupgrade 同样问题, 254B ClientHello |
| #11 vless+reality+xhttp+mlkem | FAIL | PASS 877KB | Rust bug | ClientHello 508B 缺 mlkem key_share 1216B |
| #12 vless+xhttp | FAIL | PASS 874KB | Rust bug | 同 #1 |
| #13 vless+ws | FAIL | PASS 877KB | Rust bug | ws transport 用 hyper-rustls, 253B ClientHello |
| #16 vless+httpupgrade | FAIL | PASS 871KB | Rust bug | 同 #10 |
| #18 trojan+xhttp+argo | FAIL | PASS 877KB | Rust bug | splithttp 走 btls 但用旧 Chrome 120 fingerprint 1495B vs Go 1786B |
| #29 naive | FAIL | **FAIL** | 服务端 | Go 也 FAIL — 远端节点不可用 |
| #31 anytls | FAIL | **FAIL** | 服务端 | Go 也 FAIL — 远端节点不可用 |
| #32 vless+reality+vision | 200/0B | PASS 874KB | Rust bug | REALITY 走 btls 但缺 mlkem / vision 数据 framing 缺失 |

## 4. 字节级证据

**对比 ClientHello 长度（rust vs go）**:

```
node                                 rust_CH    go_CH   diff
#1 vmess+xhttp+argo                      257     1818  +1561
#7 vless+xhttp                           257     2036  +1779
#10 vless+httpupgrade                    254     1815  +1561
#11 vless+reality+xhttp+mlkem            508     1748  +1240
#12 vless+xhttp                          599     1785  +1186
#13 vless+ws                             253     1782  +1529
#16 vless+httpupgrade                    253     1782  +1529
#18 trojan+xhttp+argo                   1495     1786   +291
#32 vless+reality+tcp+vision             508     1780  +1272
```

**所有 9 个 Rust bug 节点的 ClientHello 都比 Go 小**。差异来源:

### 4.1 6 transport 不读 fingerprint 字段 (diff ~1500B)
- xhttp, websocket, httpupgrade, grpc, splithttp (部分), kcp 全部用 `hyper-rustls` 标准 rustls
- 标准 rustls ClientHello 只 6 个扩展 (server_name, supported_versions, ec_point_formats, supported_groups, key_share, status_request)
- 真实 Chrome ClientHello 有 20+ 扩展 (signature_algorithms, psk_key_exchange_modes, application_settings/ALPS, application_layer_protocol_negotiation, signed_certificate_timestamp, padding, ...)
- **CF Argo tunnel / 部分 CDN 用 ClientHello 指纹识别浏览器**, 不接受裸 rustls → 12s timeout

### 4.2 mlkem 缺失 (diff 1240B)
- Go 26.3.27+ 把 ML-KEM-768 公钥 (1088B) + X25519 公钥 (32B) = 1216B 作为 key_share entry 塞到 TLS ClientHello
- **关键**: Go 在 **TLS 握手阶段** 就完成 vless+mlkem 协商, 不再独立 vless enc 协议
- Rust vless 加密层 (`crates/xray-proxy-vless/src/encryption/mod.rs`) 还在 TLS 之后用 Application Data 发 mlkem 1216B
- 服务端 vps 26.7.28 期望 key_share 拿到 mlkem pub, 看到裸 key_share → RST

### 4.3 btls fingerprint 不全 (diff 291B)
- splithttp + REALITY 走 `xray_tls::utls::u_client` + `BtlsConn` 走真实 Chrome fingerprint
- 但用 Chrome 120 fingerprint, 缺 ALPN 多协议 / signed_certificate_timestamp 等
- 服务端 26.7.28 用最新 Chrome 133 fingerprint 校验 → diff 291B → 拒绝

## 5. 修复路径 (统一)

### 5.1 6 transport 接 fingerprint (4-6h)
- `crates/xray-transport-websocket/src/register.rs`
- `crates/xray-transport-httpupgrade/src/register.rs`
- `crates/xray-transport-grpc/src/register.rs`
- `crates/xray-transport-splithttp/src/register.rs` (uTLS 分支已写, 但被 mode 不匹配问题挡住)
- `crates/xray-transport-kcp/src/register.rs` (KCP 不走 TLS, 跳过)
- 统一改: 当 `tlsSettings.fingerprint` 不为空时, 走 `xray_tls::utls::u_client` + BtlsConn + 自实现 HTTP/1.1 upgrade framing (不依赖 hyper-rustls)
- splithttp 复杂, 需要自实现 HTTP/2 CONNECT 或 packet-up/stream-up/stream-one 模式

### 5.2 mlkem key_share 注入 (4-8h)
- `xray_tls::utls::u_client` 加参数 `extra_key_share: Option<(MlKem768EncapsulationKey, X25519PublicKey)>`
- `BtlsConn::connect` 把这 1216B 作为 key_share entry 加到 ClientHello
- 在 vless outbound dispatch 阶段 (`crates/xray-proxy-vless/src/dispatcher.rs:169`) 先调 `ClientInstance::new()` 拿 mlkem+x25519 pub, 把 1216B 传到 u_client
- **不再用 vless enc Application Data 协议**

### 5.3 btls fingerprint 更新到 Chrome 133 (1h)
- `crates/xray-tls/src/btls_client.rs` 加 Chrome 133 / 134 fingerprint
- ALPN, padding, signature_algorithms 完整化

## 6. 不可控节点

- #29 naive: Go 也 FAIL (CONNECT 200 OK 后服务器立即 EOF)
- #31 anytls: Go 也 FAIL (未深入)
- 这两个节点 vps 端可能禁用了 / 协议层缺失, 不在 Rust 可修范围

## 7. 立即 commit

- `dist/capture_node.cmd`: 手动抓包脚本 (Windows 管理员)
- `HANDOFF_v28_packet_analysis.md`: 本文档
- 抓包 pcapng 留在 `D:\tmp\cap_*.pcapng` (不入仓, 太大)
- 抓包脚本 `D:\tmp\cap_*.py` (不入仓)

## 8. 下一步优先级 (PM 决策)

1. **(最高 ROI, 4-6h)** 6 transport 接 fingerprint — 修 6 个节点 (#1 #7 #10 #12 #13 #16)
2. **(中等 ROI, 4-8h)** mlkem key_share 注入 — 修 #11
3. **(低 ROI, 1h)** btls fingerprint 更新 — 修 #18 部分差距
4. **(边角)** #32 vision flow splice waker chain bug
5. **(不可控)** #29 #31 跳过