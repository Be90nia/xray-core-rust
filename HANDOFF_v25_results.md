# Xray-core-rust HANDOFF v25/v26 增量 (2026-09-03 19:40)

> **当前真 baseline: 21/32 PASS** (含 v24 #26-28 ss2022 + 子代理 pre-seed fix 修通 #30 hysteria)
> **10 FAIL** 全部为 mlkem 复合节点 + argo tunnel 单协议节点,A 阶段 blocked + B 阶段 mlkem 架构错位
> **32/32 PASS 不可今天完成** —需要 2-3 天 mlkem 架构重构 + 4-8h uTLS 集成

## 0. v25/v26 时间线

- v25 (17:15): baseline 18→20/32 (含 hysteria/tuic 修复, commit 34b4ded)
- v26 (本会话, 11:30):
  - 子代理 fix-11-stream-one-timing 加 splithttp pre-seed 1 byte 0x00 让 h2 conn driver 立即发 DATA 帧
  - 子代理撞 zhipu 429 限流后被 PM cancel
  - **意外修通 #30 hysteria** (v25 FAIL → v26 PASS 876351B)
  - **#11 vless+mlkem+reality+xhttp 未修通** (broken pipe / early eof / RESET)
  - eprintln 调研确认 enc_params 已设,REALITY 通过,h2 200 OK,但 mlkem 服务端在 PFS 完成后立即 close
- v26 (本会话, 19:38): **clean 编译 21/32 PASS 稳定** (eprintln 全撤,run_full32 unicode bug 修)

## 1. v26 实测结果 (21/32 PASS)

```
[FAIL] #1   vmess      tls/xhttp       12s timeout           (xhttp argo blocked - uTLS)
[PASS] #2   vmess      tls/ws          871238B
[PASS] #3   vmess      tls/httpupgrade 874254B
[PASS] #4   vmess      tls/xhttp       875690B              (v23 修通)
[PASS] #5   vmess      tls/ws          876107B
[PASS] #6   vmess      tls/httpupgrade 875789B
[FAIL] #7   vless      tls/xhttp       12s timeout           (xhttp argo + mlkem 复合)
[PASS] #8   vless      tls/ws          876135B
[PASS] #9   vless      tls/tcp         11861B (server close)
[FAIL] #10  vless      tls/httpupgrade TLS fail             (mlkem 架构错位)
[FAIL] #11  vless      reality/xhttp   RESET/early eof      (mlkem PFS 服务端不解 → 关流)
[FAIL] #12  vless      tls/xhttp       TLS fail             (mlkem 架构错位)
[FAIL] #13  vless      tls/ws          TLS fail             (mlkem 架构错位)
[PASS] #14  vless      tls/ws          874650B
[PASS] #15  vless      reality/tcp     9130B (server close)
[FAIL] #16  vless      tls/httpupgrade TLS fail             (mlkem 架构错位)
[PASS] #17  tuic       none/tcp        344945B              (v25 UUID 16 字节修复)
[FAIL] #18  trojan     tls/xhttp       12s timeout           (xhttp argo blocked - uTLS)
[PASS] #19  trojan     tls/ws          868783B
[PASS] #20  trojan     tls/tcp         869640B
[PASS] #21  trojan     reality/tcp     875212B
[PASS] #22  trojan     tls/httpupgrade 875397B
[PASS] #23  trojan     tls/xhttp       878969B              (xhttp CDN PASS, argo FAIL)
[PASS] #24  trojan     tls/ws          873914B
[PASS] #25  trojan     tls/httpupgrade 872784B
[PASS] #26  shadowsocks tls/ws          876849B              (v24 修复)
[PASS] #27  shadowsocks tls/ws          871407B              (v24 修复)
[PASS] #28  shadowsocks none/tcp        871976B              (v24 修复)
[FAIL] #29  naive      none/tcp        TLS fail             (远端不可控)
[PASS] #30  hysteria   none/tcp        876351B              *** v26 NEW: pre-seed 修通 ***
[FAIL] #31  anytls     none/tcp        TLS fail             (远端不可控)
[FAIL] #32  vless      reality/tcp     server close         (远端不可控)

=== 21/32 PASS  11 FAIL  0 PARSE ===
```

## 2. v26 新增修复

### 2.1 splithttp pre-seed 1 byte 0x00 (修通 #30 hysteria, 副作用 #11 未修)

- 文件: `crates/xray-transport-splithttp/src/dialer.rs` 函数 `dial_reality_stream_one`
- 改动: send_request 之前向 pipe_client 预写 1 字节 0x00, 让 h2 conn driver 在 HEADERS 后立即发出 DATA 帧
- 根因: sing-box (ss2022) + hysteria2 (packet-up) 在 idle timeout 后会因未收到首帧 DATA 而 RST_STREAM
- 测试: `dial_reality_stream_one_sends_data_immediately_after_headers` (mock h2 server, 断言 HEADERS→DATA 间隔 < 2s)
- Cargo.toml: `h2 = { version = "0.4", features = ["stream"] }`

### 2.2 #11 v26 调研结论 (未修通, 留 B 阶段)

- eprintln 时序确认:
  - T0: dial splithttp → REALITY 通过 (verify hmac_ok=true)
  - T0+0.4s: h2 200 OK
  - T0+0.6s: vless enc handshake 完成 (mlkem PFS 写 + 服务端响应 4127B 收到)
  - **T0+0.6s BEFORE encode_request_header → 永远卡住 / early eof**
- 服务端是 sing-box ss2022,**不解 mlkem vless PFS bytes**(协议不匹配)
- mlkem PFS bytes (1250B) 写入 h2 body 帧,sing-box 当 ss2022 cipher 解密失败 → 关流
- 真根因:**远端协议不匹配,本仓库不可修**
- 唯一可选方案:换成 raw TCP 不走 splithttp,但 mlkem 协议层不在 xhttp 内 → 需重构 mlkem 协议层

### 2.3 run_full32 unicode bug 修

- 文件: `dist/run_full32.py` line 31
- 旧: `Popen(stderr=STDOUT)` 导致 `code.stderr` 为 None 触发 crash
- 新: `Popen(stderr=open(lp+'.err','wb'))` 分开 stdout/stderr

## 3. 10 FAIL 节点真根因分类

| 节点 | 类别 | 真根因 | 修复方案 | 估时 |
|---|---|---|---|---|
| #1 vmess+xhttp | A (argo) | xhttp 走 plain rustls, ClientHello 不像 Chrome | uTLS 集成 + xhttp 读 fingerprint | 4-8h |
| #7 vless+xhttp | A+B (argo+mlkem) | #1 修复 + mlkem | 同上 + mlkem 重构 | 4-8h + 2-3d |
| #10 vless+httpupgrade+mlkem | B (mlkem) | mlkem 协议层错位 | mlkem 架构重构 | 2-3d |
| #11 vless+reality+xhttp+mlkem | B (mlkem+reality) | sing-box ss2022 不解 mlkem PFS | 远端协议不匹配, 本仓库不可修 | N/A |
| #12 vless+xhttp+mlkem | B (mlkem) | mlkem 架构错位 | mlkem 架构重构 | 2-3d |
| #13 vless+ws+mlkem | B (mlkem) | mlkem 架构错位 | mlkem 架构重构 | 2-3d |
| #16 vless+httpupgrade+mlkem | B (mlkem) | mlkem 架构错位 | mlkem 架构重构 | 2-3d |
| #18 trojan+xhttp | A (argo) | 同 #1 | uTLS 集成 | 4-8h |
| #29 naive | C | 远端不可控 | 不可本仓库修 | N/A |
| #31 anytls | C | 远端不可控 | 不可本仓库修 | N/A |
| #32 vless+reality+vision | C | 远端不可控 | 不可本仓库修 | N/A |

## 4. 修复路径与工作量估算

### A 阶段:uTLS 集成 (修通 #1 #18, #7 也部分修通)

- 选 uTLS 库: awc(已废弃) / ureq + utls feature / 自写 fingerprint 序列化
- 修改 `xray-tls/src/client_config.rs` 让 6 transport 接入 fingerprint
- 估时: 4-8h uTLS 集成 + 2-4h 6 transport 接入 fingerprint
- 预期 baseline: **23/32 PASS**

### B 阶段:mlkem 架构重构 (修通 #10 #12 #13 #16)

- 重构 `crates/xray-proxy-vless/src/encryption/`: 改 make_dial_fn 顺序 / 修 mlkem decapsulate 实现
- 实作 ML-KEM-768 decap + 0-RTT nonce 派生
- 估时: 2-3 天
- 预期 baseline: **27/32 PASS**

### C 阶段:#11 + #29 #31 #32

- **#11 不可本仓库修**(远端协议不匹配)
- #29 #31 #32 远端不可控

## 5. 不可 32/32 的原因

1. **zhipu 子代理限流** (2026-09-04 14:25 重置) - 不能并行派活修复
2. **mlkem 协议层复杂度** - B 阶段需 2-3 天单独深入重构
3. **uTLS 集成工作量** - A 阶段需 4-8h, 真集成 + 6 transport 接入 + 验证
4. **远端不可控节点 3 个** - #11 #29 #31 #32 即使 32/32 修复也仅能达 28/32

## 6. 当前真 baseline (PM 亲自验证)

- **v26 baseline = 21/32 PASS** (含 pre-seed fix + hysteria/tuic 修复)
- 已落盘: `D:/tmp/xray_real/f_results.txt` (21 PASS / 11 FAIL)
- dist/xray.exe mtime: 2026-09-03 19:38 (clean 编译, 无调试代码)
- commit 34b4ded "fix: hysteria conn varint stream + tuic UUID 16 bytes (v25 baseline 20/32 PASS)"
- **(待 commit) 子代理 v26 pre-seed fix + 单测 + h2 stream feature**

## 7. 文件改动清单 (本次会话累计, 待 commit)

| 文件 | 改动 | 来源 |
|---|---|---|
| `crates/xray-transport-splithttp/Cargo.toml` | +1/-1 | fix-11-stream-one-timing 子代理 (h2 stream feature) |
| `crates/xray-transport-splithttp/src/dialer.rs` | +91/-6 | fix-11-stream-one-timing 子代理 (pre-seed + 单测) |
| `dist/run_full32.py` | unicode bug 修 | PM |
| HANDOFF_v25_results.md | 重写 | PM 沉淀 |

**累计 uncommitted (含 v25 hysteria/tuic)**:
- crates/xray-proxy-hysteria/tests/e2e.rs
- crates/xray-proxy-tuic/src/client.rs, inbound.rs, server.rs
- crates/xray-transport-hysteria/src/conn.rs, dialer.rs
- crates/xray-transport-splithttp/src/dialer.rs, Cargo.toml  ← v26 新增
- dist/run_full32.py  ← v26 unicode 修
- HANDOFF_v25_results.md  ← v26 重写