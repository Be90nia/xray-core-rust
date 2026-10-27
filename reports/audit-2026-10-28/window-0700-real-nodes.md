# 2026-10-28 早 07:00 黄金窗：真机 93 节点 Rust vs Go 同窗配对

**二进制**：`target/release/xray.exe`(48MB, 02:16, HEAD `6bac23e6` 含今夜全部修复) vs `xray-go.exe`(9-02, 26.x)
**节点表**：`D:/tmp/vps_nodes.txt` 93 节点（含今晨补 pbk/sid/fp/sni 的 3 个 reality）
**口径**：`run_full32.py`，每节点 12s 下载 `speed.cloudflare.com/__down?bytes=8000000`，marker 校验通过才 PASS

## 1. 总账

| | PASS | FAIL | 完整拿到 8MB |
|---|---|---|---|
| **Rust** | **75/93** | 18 | **71** |
| **Go** | 69/93 | 24 | 69 |

## 2. 判定：18 个 FAIL 全在节点侧，**零 Rust 独有失败**

Rust 失败的 18 个节点：`[4,8,13,16,21,24,41,49,50,53,73,74,81,83,84,85,90,92]`
→ **Go 在同一窗口对这 18 个也全部失败**（逐节点 diff，18/18 两边同败）。

失败族：
- **ss 9 个**（#4/#13/#21/#50/#81/#84/#85/#90/#92，none/ws 与 none/tcp）——与历史口径一致：节点表里 ss 的密码/加密与节点不符
- **vless reality/raw 6 个**（#8/#24/#53/#73/#74/#83）——同批 reality 的 trojan reality/raw(#6/#26/#27) 与 reality/xhttp(#17/#18/#69) 双端全通，说明是这 6 个节点的 pbk/sid 未补
- **vless tls/raw 3 个**（#16/#41/#49）

## 3. 差异 6 个节点，**全部 Rust 胜**

| 节点 | 协议 | Rust | Go |
|---|---|---|---|
| #22 | tuic/none/tcp | PASS 8MB | FAIL |
| #23 | anytls/none/tcp | PASS 8MB | FAIL |
| #34 | tuic/none/tcp | PASS 8MB | FAIL |
| #40 | anytls/none/tcp | PASS 8MB | FAIL |
| #68 | anytls/none/tcp | PASS 8MB | FAIL |
| #71 | tuic/none/tcp | PASS 8MB | FAIL |

tuic×3 + anytls×3：Go 客户端在这 6 个节点上不通（其 tuic/anytls 实现为实验性），Rust 全通。

## 4. 速度（仅 4 个被 12s 截断的慢节点可比）

| 节点 | Rust | Go |
|---|---|---|
| #6 | 648.3 KB/s | 651.0 KB/s |
| #15 | 650.1 KB/s | 651.0 KB/s |
| #25 | 646.7 KB/s | 651.0 KB/s |
| #27 | 649.4 KB/s | 651.0 KB/s |

差 ≤0.7%，且这 4 个节点自身限速 ≈650 KB/s(5.2 Mbps)——client 侧无差别。
（更快节点 8MB 在 12s 内跑完，脚本不记耗时，故不进速度榜；受控速度判定见 `tools/ab_gate.py`）

## 5. 同窗互通门（最终二进制）

- `dist/interop_reality.py` → **2/2 PASS**（Rust↔Go 双向）
- 6 协议 × 双向矩阵 → **12/12 PASS**（`win_interop.log`）
- 全量测试 → **7791 passed / 0 failed**（185 二进制，`6bac23e6`）

## 6. 结论

**无回归。Rust ≥ Go**：同窗口 PASS 数 +6，失败集合是 Go 失败集合的子集，慢节点速度打平。
剩余 18 个坏节点需回源头修节点表（ss 密码/加密、6 个 reality 的 pbk/sid），非代码问题。

原始日志：本目录 `win_rust.log` / `win_go.log` / `win_interop.log`
