VERDICT: DONE（结论 = 半接线：出站能用、入站装配白名单缺 quic；传输层自洽互通 PASS，内核级 FAIL 定位到入站；零生产代码改动，处置建议待拍板）

# 0270p：QUIC 传输 Rust↔Rust 自洽互通 + 生产接线审计

> 用户拍板口径：**只做**①Rust↔Rust 自洽互通（`network=quic` 双端）②生产接线审计（arm_builders 键 /
> quicSettings 解析→消费链）。**不追**历史 Go wire 对照、不声明与任何 Go 版本一致（Go 26.10.17 已把
> `transport/internet/quic` 整体移除，无基准可对）。

## 待办清单
- [x] §1 接线审计表：arm_builders quic 键与构造器 / quicSettings 解析与消费方 / xray-transport-quic 完整度
- [x] §2 自洽互通证据
- [x] §4 建议处置
- [x] §5 门禁（test / clippy / fmt）
- [x] §6 残余风险
- [x] §3 与 Go 26.10.17 已移除的关系（一句）（≥64KB 真实往返，原始输出）
- [ ] §3 与 Go 26.10.17 已移除的关系（一句）
- [ ] §4 建议处置
- [ ] §5 门禁（test / clippy / fmt）
- [ ] §6 残余风险

---

## 1. 接线审计表

### 1.1 注册与装配链（生产路径核实）

| 环节 | 状态 | 证据 |
|---|---|---|
| 传输注册 | ✅ 生产主路已注册 | `crates/xray-core/src/register.rs:112-114`：`register_all_transports()` 内 `xray_transport_quic::register::{register_dialer,register_listener}()`；该函数在 `functions.rs:183/283/1001`（`start_full` / `start_full_with_outbound_handlers` / `start_from_built` 三条启动路径）被调用，且文档注明「必须在 register_outbounds / spawn_inbounds 之前」 |
| 出站拨号 | ✅ 已接线 | `dialer::dial` 按 `settings.protocol` 查注册表（`xray-transport/src/dialer.rs`）→ `"quic"` 命中 → `transport.rs::dial`；`protocol_settings_key("quic") = "quicSettings"`（dialer.rs:552）⇒ `quicSettings` 进 `transport_json` |
| 入站监听 | ❌ **半接线** | `inbound.rs:4424-4434` `is_transport_listener_protocol` 白名单 = `ws/websocket/grpc/h2/http/kcp/mkcp/httpupgrade/splithttp/xhttp`——**缺 `"quic"`**。vless 入站配 `network=quic` 时走不到 transport 分支（arm_builders/inbound.rs:215-235），落到**裸 TCP 分支**：`InboundTcpListener::bind`（TCP socket）+ TLS acceptor——对 UDP 传输完全错误（quic 客户端拨 UDP 永远到不了它）。对照：同为 UDP 传输的 `kcp/mkcp` 在白名单里，说明该路径本就支持 UDP 传输，漏的只是 quic 这一个词 |

### 1.2 quicSettings 解析与消费方

| 项 | 状态 | 证据 |
|---|---|---|
| 解析 | ✅ | `xray-transport-quic/src/config.rs:69` `QuicConfig::from_json`（keepAlive / congestion / disableGSO / initialMtu / disableSendFairness / 流控窗族；非法拥塞值硬错）；`xray-conf` **不**单独解析 quicSettings——原始 JSON 经 `streamSettings` 原样进 `transport_json`，由 quic crate 在 dial/listen 时消费（属「透传 + 端点消费」形态，无悬空结构） |
| 消费方 | ✅ 两端都在用 | dial：`transport.rs:74` `QuicConfig::from_json(settings.transport_json)` → `build_transport_config()`；listen：同文件 listen 路径同样消费（disableGSO 有端到端接线测试，transport.rs:416-419 注释 + `echo_roundtrip_gso_*` 用例） |

### 1.3 `crates/xray-transport-quic` 实现完整度

| 项 | 状态 | 证据 |
|---|---|---|
| 客户端 dial | ✅ | `transport.rs:38-120`：TLS 强制校验、DNS+握手外层 16s timeout、quicSettings→quinn TransportConfig、GSO 开关（`udp_gso.rs` NoGsoSocket）、endpoint 存活入桥接任务 |
| 服务端 listen | ✅ | `transport.rs:125` `listen()`：quinn Endpoint::server + accept loop，每 QUIC 连接内 `accept_bi` loop → 每流一个 handler（多流复用，对齐 Go hub.go）；`close()` 真关 endpoint（`close_rejects_new_connections` 回归锚） |
| TODO/占位 | ✅ 无 | grep `TODO/todo!/unimplemented!/placeholder` 零命中 |
| 测试 | ✅ 较全 | 传输级 128KiB 字节级回环 ×2（GSO 开/关）、close 语义、0-RTT 恢复/回退、GSO 包装、BBR/brutal 拥塞全套单测（147 个 lib tests 全绿） |
| 已知文档漂移 | ⚠️ 微 | `lib.rs:17-18`「quicSettings 的 KeepAlive / 拥塞控制等参数留 follow-up」已过期——config.rs 实际已解析消费（本票不改，留文档票） |
| 特性警告 | ⚠️ 设计如此 | 每次生产 dial 会发 `removed_feature_warnings`：「QUIC transport (without web service, etc.) → XHTTP stream-one H3」（`xray-transport/src/dialer.rs:581-585`，Rust 对 Go 26.10.17 移除该传输的对齐标记，warn 不阻断） |

### 1.4 结论（逐项）

- **出站（quic outbound）：能用**——注册在生产主路、dial 全链路（含 quicSettings）通。
- **入站（quic inbound）：半接线**——listener 已注册且实现完整，但装配白名单缺 `"quic"`，
  入站会错误地 TCP 监听（§4 给一行修复建议；文件在本票红线内，不动）。
- **非死代码**：实现、测试、注册齐备，缺的只是装配层一个词。

---

## 2. 自洽互通证据

### 2.1 传输层（生产注册表路径）—— **PASS，256KiB 字节级**

新增 `crates/xray-transport-quic/tests/registry_self_interop.rs`：两端都走**生产入口**——
服务端 `register_listener()` 注册后经 `listener_registry::listen_tcp`（装配层实际查找入口），
客户端 `register_dialer()` 注册后经 `dialer::dial`（removed-feature 警告与
`protocol_settings_key("quic")→quicSettings` 解析都在这条路径上）。`streamSettings.network=quic`
双端 + 非缺省 `quicSettings`（`congestion:"bbr"` / `keepAlive:10`——解析失败 dial 即报错，
成功即证明 quicSettings 消费链完整）。

```
running 1 test
test registry_path_quic_self_interop_roundtrip ... ok
test result: ok. 1 passed; 0 failed; ... finished in 0.06s
```

256KiB 确定性载荷（`i*7%251`）写 → 回显 → 字节级 `assert_eq!` 通过。

补充：crate 自带 `echo_roundtrip_gso_{disabled,default}` 两用例（128KiB 字节级、GSO 开/关双路）
同日重跑通过——传输层自洽互通在**两条证据链**（生产注册表 + 直连）下均成立。

### 2.2 生产内核路径（vless over quic 双端 xray.exe）—— **FAIL，定位 = 入站装配白名单**

`fix/scripts/wave7_quic_e2e.py`（vless inbound/outbound + `network=quic`，pinned 证书，
64KiB socks 链路）实测：

```
tcp_probe: TCP connect 成功（入站绑了 TCP —— 走了裸 TCP 分支）
[FAIL] quic Rust->Rust UP:0 DOWN:0 TimeoutError('timed out')
--- s0.log tail ---
    INFO  vless inbound listening addr=127.0.0.1:18700 reverse=false      ← 裸 TCP 分支的日志
    WARN  vless TLS accept failed error=tls handshake eof                 ← 在 TCP 上做 TLS accept
--- c0.log tail ---
    INFO  version=26.10.11 ... profile=release
    WARN  general log channel has no sink registered; ...
```

失败定位链：客户端出站正常发起 QUIC（UDP）→ 服务端入站因 §1.1 白名单缺 `"quic"` 走了裸 TCP
分支（`InboundTcpListener::bind`，tcp_probe 实证绑了 TCP）→ UDP 包无人应答 → socks 8s 超时。
**不是** QUIC 传输本身的问题（§2.1 同一双端函数经注册表直连即通）。

客户端配置注：`allowInsecure` 被 5x41 裁决在配置后处理期拒收（`Error: ... The feature
"allowInsecure" has been`），改用 `pinnedPeerCertSha256`。

---

## 3. 与 Go 26.10.17 已移除的关系（一句）

Go 26.10.17 已把 `transport/internet/quic` 整体移除（引导用户走 XHTTP stream-one H3），Rust 侧
保留该传输并在生产拨号路径上以 `removed_feature_warnings` 对齐这一事实（warn 不阻断）——本票按
拍板只验自洽，不做任何 Go 对照。

---

## 4. 建议处置（待 PM 拍板，本票未动代码）

| 项 | 建议 |
|---|---|
| 入站白名单 | `crates/xray-core/src/inbound.rs:4424` `is_transport_listener_protocol` 加 `"quic"`（一个词）。加完即全链路打通：listener 已注册（register.rs:113-114）、listen/dial 实现完整、quicSettings 消费链已验证。**该文件在本票红线内（并行代理在改），未动**。补一条 `arm_lookup_inbound_table_is_complete` 同族的守卫断言可选 |
| removed-feature 警告 | 与"自洽可用"的产品定位矛盾（每个 QUIC 拨号都告警一次）；若拍板保留 QUIC 传输，应把 `"quic"` 从 `removed_feature_warnings` 摘除或降级——同属 PM 裁决（Go 已删但 Rust 保留属产品决策） |
| lib.rs 文档漂移 | `lib.rs:17-18`「quicSettings … 留 follow-up」已过期（config.rs 实际已解析），随下次触碰该 crate 顺手更正 |

---

## 5. 门禁

| 门禁 | 结果 |
|---|---|
| `cargo test -p xray-transport-quic --all-targets` | **148 passed / 0 failed**（lib 147 + 新增 registry_self_interop 1） |
| `cargo clippy -p xray-transport-quic --all-targets -- -D warnings` | 零告警 |
| `cargo fmt -p xray-transport-quic -- --check` | 0 diff |

本票**零生产代码改动**（只新增 1 个集成测试 + 1 个 e2e 脚本 + 报告）。

---

## 6. 残余风险

- 入站白名单未修（红线文件）⇒ 生产内核的 `network=quic` 入站仍是坏的（绑 TCP + TLS accept）。
  在 PM 拍板补线前，**用户配置 quic 入站会得到一个假监听**（TCP 端口活、QUIC 永远不通）——
  建议拍板时二选一：补白名单，或入站配置期对 `network=quic` 显式报错（fail-visible，与 Go
  移除语义对齐）。
- 内核级互通证据在入站补线后需重跑 `wave7_quic_e2e.py`（脚本已留 `fix/scripts/`）。
- QUIC 无 Go 26.10.17 wire 基准（上游已删）：自洽互通不等于与任何历史 Go 版本互通；若未来需要
  与旧 Go 节点互通 QUIC，须另行立项做历史版本对照。

（本节完 → 落盘）
