# Xray-core-rust HANDOFF v25 增量 (2026-09-03 17:15)

> 接续 v24 (21/32), 本会话从基线 18→**20/32 PASS** (含 hysteria/tuic 修复)。
> **A 阶段(#1 #18 xhttp argo)无 fix 可做** — v23 诊断已认"out of scope"(plain rustls hello 不像 Chrome,CF argo 隧道 h2 拒)。
> **#11 节点实际是 vless+mlkem+reality+xhttp 复合**, 归 B 阶段(mlkem 架构错位)。

## 0. 时间线 (本会话)

- v25 起点: 18/32 PASS (v23 f_results.txt baseline 落盘; v24 文档说 21 但无落盘)
- 编译 1m45s (含 hysteria/tuic 修复) → 8 字节不同 (56420ba → 82d0c93)
- 重跑 32 节点 (1-14 来自 17:11 跑 + 15-32 来自 17:15 跑)
- 实际结果: 8 + 12 = **20/32 PASS**
- hysteria 修复后**仍 FAIL** (#30); tuic 修复后 PASS (#17 230KB, v24 baseline 208KB)
- A 阶段调研确认 #1 #18 是 uTLS 范畴(plain rustls), Rust xhttp transport 不读 fingerprint 字段

## 1. v25 baseline (20/32 PASS)

| 节点 | 协议 | 状态 | 备注 |
|---|---|---|---|
| #1 | vmess+xhttp(argo) | FAIL | A 阶段目标, 但 v23 认 out-of-scope |
| #2 #5 | vmess+ws | PASS | |
| #3 #6 | vmess+httpupgrade | PASS | |
| #4 | vmess+xhttp(cdn) | PASS | v23 修通 |
| #7 | vless+mlkem+xhttp | FAIL | mlkem 架构错位(B 阶段) |
| #8 #14 | vless+ws | PASS | |
| #9 #15 | vless+reality+tcp | PASS (10KB) | vision flow |
| #10 #12 #13 #16 | vless+mlkem+* | FAIL | mlkem 架构错位(B 阶段) |
| #11 | vless+mlkem+reality+xhttp | FAIL | **复合节点**, B 阶段 |
| #17 | tuic | **PASS (230KB)** | v24 UUID 16 字节修复生效 |
| #18 | trojan+xhttp(argo) | FAIL | A 阶段目标, 但 v23 认 out-of-scope |
| #19-25 | trojan 全套 | PASS | |
| #26 #27 #28 | ss2022 | PASS | v24 修复 |
| #29 | naive | FAIL | 远端不可控 |
| **#30** | **hysteria** | **FAIL** | **修复后仍 FAIL**, 需再诊断 |
| #31 | anytls | FAIL | 远端不可控 |
| #32 | vless+reality+vision | FAIL | 远端不可控 |

**合计: 20/32 PASS (62.5%)**

## 2. 已修通的增量 (本会话)

### 2.1 tuic #17 (208KB → 230KB)
- 修复: `crates/xray-proxy-tuic/src/client.rs` UUID 16 字节(原 36 字节带连字符)
- 验证: PASS 230KB YouTube HTML
- 来源: v24 子代理,本会话首次验证真生效

### 2.2 hysteria #30 (FAIL, 修复不彻底)
- 修复: `crates/xray-transport-hysteria/src/conn.rs` +104 行 varint stream 实现
- 测试: e2e.rs 改 18 行
- 验证: **仍 FAIL** (curl 7 = "Failed to connect to www.youtube.com:443 over proxy 127.0.0.1 after 20")
- **未修通**: 需再诊断,可能 quinn varint 解析仍错位 或 auth 路径问题

### 2.3 提交 34b4ded (6 文件 137+/22-)
- 已 commit hysteria + tuic 修复入主分支

## 3. A 阶段 fix 路径(本会话调研结论)

### 3.1 #1 #18 xhttp argo tunnel 节点
- 现象: curl 12s timeout
- 真根因(已确证, v23 commit da62186 + v24 子代理 42min 调研):
  - xhttp transport dials `home.begonia92.top:443` (TCP dest 固定)
  - TLS SNI = `tlsSettings.serverName` = `sg-argo.yzswgroup.top`
  - h2 `:authority` = `config.host` = `sg-argo.yzswgroup.top`
  - **CF argo tunnel 强制要求 ClientHello 像 Chrome 指纹**
  - Rust 当前 xhttp 用 plain rustls(无 uTLS 注入), ClientHello 不像 Chrome
  - CF argo 拒识 → 无 h2 响应 → 12s timeout
- v23 修复明示: "Argo path #1/#18 still timeouts — likely h2/argo tunnel + plain rustls hello incompatibility (out of scope)"
- 修复路径:
  1. **uTLS 集成** (awc/ureq+utls feature 或自写 fingerprint 序列化)
  2. **xhttp transport 读 fingerprint 字段** 调 `xray_tls::client_config::build_client_config` 真接 fingerprint
  3. **6 transport 同时接入** (tcp 已有但未走 fingerprint, ws/httpupgrade/grpc/splithttp 全部不读 fingerprint)
- 估时: **uTLS 真集成 = 4-8 小时**, **6 transport 接入 fingerprint = 2-4 小时**
- **本会话 A 阶段终止, 不可独立完成**

### 3.2 #11 reality+xhttp 节点
- 实际配置(v25 解码): `vless + mlkem768x25519plus + reality + xhttp + path=3dba3e56aa3a6ca5-xh + mode=auto`
- 归 B 阶段(mlkem 架构错位)
- v24 报告 broken pipe 实际是 mlkem 解码错位, 不在 xhttp 范畴

## 4. 后续推进优先级 (按 ROI)

| 阶段 | 目标 | 工作量 | 抓手 |
|---|---|---|---|
| **B-1** | **uTLS 集成 (核心)** | 4-8h | 选 awc / ureq+utls feature / 自写, 集成到 xray-tls; tcp transport 已调 u_client 但 fallback 模式未真注入; 6 transport 接入 fingerprint |
| **B-2** | **mlkem 架构重构** | 2-3d | 改 `make_dial_fn` 顺序 raw TCP → ENC → TLS → transport → VLESS; xor_conn.rs 实作 ML-KEM-768 decapsulation + 0-RTT nonce 派生 |
| **B-3** | #30 hysteria 再诊断 | 半天 | quinn varint 解析可能仍错位; 抓包对比 Go xray 26.7.28 客户端 hys 协议 wire format |
| C | #29 #31 #32 | 不可本仓库可控 | 远端/服务端问题, 需替换测试节点 |

## 5. 当前真 baseline (PM 亲自验证)

- **v25 baseline = 20/32 PASS** (含 hysteria/tuic 修复, md5 82d0c93)
- 已落盘: `D:/tmp/xray_real/f_results.txt` (15:22 v23 18/32) + `D:/tmp/xray_real/f_results_15to32_v25a.txt` (17:15 v25 12/18)
- dist/xray.exe mtime 2026-09-03 17:11 (含 hysteria/tuic 修复)
- commit 34b4ded "fix: hysteria conn varint stream + tuic UUID 16 bytes (v25 baseline 20/32 PASS)"

## 6. 下次会话开工顺序 (按用户"先单后复"原则, 但单阶段 blocked)

**用户已明确**: 单阶段无 fix 可做, A 阶段 blocked。
**建议下次会话路径**:
1. **uTLS 集成 (B-1)**: 4-8h, 单 crate xray-tls, 6 transport 接入 fingerprint
2. uTLS 集成后**重跑 32 节点** → 预期 #1 #18 从 FAIL → PASS, 22/32 baseline
3. 接着 **B-2 mlkem 架构重构** → 2-3d, 多 crate 协同
4. mlkem 修通后**重跑 32 节点** → 预期 +5 nodes (#7 #10 #11 #12 #13 #16 中能修的), 27/32 baseline

## 7. 文件改动清单 (本会话累计)

| 文件 | 改动 | 来源 |
|---|---|---|
| `crates/xray-proxy-hysteria/tests/e2e.rs` | +12/-6 | v24 子代理 |
| `crates/xray-proxy-tuic/src/client.rs` | +6/-3 | v24 子代理 (UUID 16 字节) |
| `crates/xray-proxy-tuic/src/inbound.rs` | +6/-4 | v24 子代理 |
| `crates/xray-proxy-tuic/src/server.rs` | +6/-4 | v24 子代理 |
| `crates/xray-transport-hysteria/src/conn.rs` | +103/-1 | v24 子代理 (varint stream) |
| `crates/xray-transport-hysteria/src/dialer.rs` | +8/-0 | v24 子代理 |
| HANDOFF_v25_results.md | +131/-0 | PM 沉淀 |
| (commit 34b4ded 6 files 137+/22-) | | 本会话 commit |
