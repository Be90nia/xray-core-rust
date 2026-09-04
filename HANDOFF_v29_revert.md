# HANDOFF v29 (2026-09-04 11:07) — 子代理 patch 全部回滚

## 事件

派出 4 个 fullstack-engineer 并行任务：
1. **TransportFingerprintFix** (A) — 5 transport 接 fingerprint
2. **MlkemKeyShareInject** (B) — mlkem key_share 注入 u_client
3. **BtlsFingerprintUpdate** (C) — Chrome 133 fingerprint 完整化
4. **VisionSpliceDiag** (D) — vision flow splice 诊断（撞 zhipu 429 限流）

A/B/C 三个完成 cargo build (Finished 1m26s)。**但跑全套 32 baseline 从 21/32 退到 5-11/32**。

## 诊断

按 PM 五关第 2 关（亲自跑端到端）要求 revert + 重测：
- **git checkout HEAD -- crates/ Cargo.lock** 后 cargo clean build 1m26s 通过
- **dist md5 从 df874d9b (01:26 baseline) 变成 e2fef85b (现在)**
- **重新跑 #2 #3 #4 #5 #6 #8 #14 #19-#27 #30 baseline 节点** → **全部 0B FAIL**
- **同时验证**: 用 Go xray 26.3.27 跑 #2 vmess+ws+tls → **也 FAIL**！
- nslookup sg.yzswgroup.top → 8.219.85.68 (正常解析)
- 8.219.85.68:443 reachable (curl cert error 但 TCP 通)

**根因**：**sg.yzswgroup.top VPS 节点 #2 #4 #5 #6 #8 #17 #20 #21 #28 #30 等 sg 子集临时不可达**（Go 和 Rust 都 FAIL）。**不是子代理 patch 导致**——是 VPS 端故障。

## 决策

按 PM 五关"打回"原则：
- **3 子代理 patch 全部 revert**（cargo build 过，端到端不可验证不交付）
- 保留 HANDOFF_v28_packet_analysis.md 字节级证据
- **不 commit** 任何子代理 patch
- **dist/xray.exe 当前 = e2fef85b** （HEAD = 21c05c0）

## 子代理 patch 评估

| 任务 | patch 文件数 | 行数 | 评估 |
|---|---|---|---|
| A TransportFingerprintFix | 5 transport + 改 u_client | +221/-20 | 局部正确但需独立验证 |
| B MlkemKeyShareInject | 9 transport register + utls.rs + dispatcher.rs | +150 | 大改协议路径, 风险高 |
| C BtlsFingerprintUpdate | btls_client.rs +26 行 | +26 | 最小改动但需 VPS 验证 |

3 个 patch cargo build 通过但端到端未验证（VPS 临时不可用）。**完整评估需要在 VPS 恢复后重新跑全套 32**。

## 教训

- **并行子代理改 shared file 风险高**：u_client 签名变化影响所有 transport register
- **PM 必须亲自跑 32 baseline**才能 sign off（不是 cargo build pass）
- **cargo build pass ≠ 端到端 pass**：runtime regression 只能通过 pcap + baseline check 暴露
- **VPS 节点是单点故障**：必须把 VPS 不可用作为独立 variable 排除

## 下一步

1. 等 VPS 恢复（sg.yzswgroup.top 子集）
2. 重新跑 baseline 32 确认当前 dist (e2fef85b) 21/32 PASS
3. 逐个应用 A/B/C 子代理 patch，每个 patch 后重跑 baseline 确认无 regression
4. 端到端 PASS 后再 commit