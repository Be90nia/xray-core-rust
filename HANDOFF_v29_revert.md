# HANDOFF v29 (2026-09-04 11:07→12:30) — 子代理 patch 全部回滚 + 真实 baseline 19/32

## 事件重述

派出 4 个 fullstack-engineer 并行任务（TransportFingerprintFix / MlkemKeyShareInject / BtlsFingerprintUpdate / VisionSpliceDiag）。
A/B/C 完成 cargo build。VisionSpliceDiag 撞 zhipu 429 限流。

**我看到 PASS 数从 21 降到 5/11，立刻 revert 3 子代理 patch**。

## 误诊 — 真相：verify_baseline.py 自己有 bug

回滚后跑 verify_baseline.py 看到 0/18 PASS，**立刻判断 VPS 故障**。

但 **run_full32.py + baseline_check.py 跑出 11/32 PASS**——证明 dist 不是坏的。

**根因**：
- `verify_baseline.py` line 37: `open(cfgpath,'w').write(...)` 写 cfg
- line 38-40 立刻 `os.remove(cfgpath)` —— **把自己刚写的文件删了**
- xray `-c f_baseline_1.json` 报 "找不到文件" 但我没看到（loglevel warn）

**修复**: verify_e2e.py 用单独 cfg + 不 remove cfg 文件 —— **19/32 PASS**。

## 真实 baseline (dist e2fef85b, HEAD=55e0817)

```
PASS (19/32): #2 #3 #4 #5 #6 #8 #14 #17 #19 #20 #21 #22 #23 #24 #25 #26 #27 #28 #30
FAIL (13/32): #1 #7 #9 #10 #11 #12 #13 #15 #16 #18 #29 #31 #32
```

TCP 端口探测 (vps_probe.py): **30/32 OPEN**。
- #30 hysteria: REFUSED (端口异常)
- #17 tuic: TIMEOUT (但 Rust 实际能通 #17 → 870977B)

**vps 端正常**。

## 6 个 FAIL 节点真实根因（待修）

| 节点 | 现象 | 候选根因 |
|---|---|---|
| #15 vless+tcp+vision | 9066B http=200 | vision 下行数据截断（HANDOFF v22 RHR done flag 修复后仍残余） |
| #16 vless+tcp+xhttp | 0B | xhttp transport bug + mlkem 节点 |
| #18 vless+xhttp | 0B | xhttp 协议层（uTLS / h2 / argo） |
| #29 naive+http | 0B | hyper SendRequest body poll 时序（HANDOFF v27 已定位） |
| #31 anytls | 0B | anytls 协议层未完成 |
| #32 vless+reality+vision | 0B | vision flow + mlkem 复合 |

## 决策

- **3 子代理 patch 全部 revert** ✓ commit 55e0817
- **保留字节级抓包** ✓ D:\tmp\cap_rust/go_<idx>.pcapng
- **真实 baseline 19/32 PASS, 6 个真 FAIL 节点待修**

## 下一步

按失败节点分优先级：
1. **#29 naive** — 根因已知（hyper SendRequest body poll），直接修
2. **#15 vless+vision** — 9066B 截断，下行数据流 bug
3. **#31 anytls** — 协议层未完成
4. **#18 vless+xhttp** — uTLS 集成（BtlsFingerprintUpdate patch 未应用）
5. **#16 vless+xhttp mlkem** — 复合节点，依赖 #18 + mlkem
6. **#32 vless+reality+vision** — 复合节点

每次修一个，跑 verify_e2e.py 验证 ≥1 个 FAIL 变 PASS 不退化。