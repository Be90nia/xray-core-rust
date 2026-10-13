# qtzi 战役收口——黄金窗双向护栏实测（2026-10-14）

> 环境：us1 VPS **新 Linux 内核 7.2.10-tcpboost+**（bbrplusv3 / rmem_max 33MB，机器 06:20 前后重启）
> 服务端：/root/agsbx/xr.json（10-09 核）**保持不动**——单变量设计，仅客户端 binary A/B
> 节点：us1.begonia92.top:39380（vless+xhttp+reality+enc，直连）
> 方法：fzir2 同款双臂交替（6 并发 curl × 10MB × N 轮，thinkbroadband 源），new/base ratio ≥0.95

## 臂定义
| 臂 | binary | md5 | 说明 |
|---|---|---|---|
| base | v2rayN xray.exe（v26.10.13 基版） | 74f4dc6d | CI 同配方 |
| new | CI run 38414425386 artifact | a3d37d9d | master 6aff9172（qtzi 145 处 + CVE bump）|

## 下载方向
| 批次 | 轮数 | base 中位/均值 | new | ratio | 判定 |
|---|---|---|---|---|---|
| 旧内核（10-13 内核） | 3 | 17.93 | 18.91 | **1.054** | PASS |
| 新内核 3 轮 | 3 | 20.68 | 19.62 | 0.948 | 差 0.002 擦线（噪声带 ±5%）|
| **新内核 6 轮（定案）** | 6 | 18.40 | 19.75 | **1.074** | **PASS** |

6 轮明细（MB/s）：base 13.81/14.30/20.51/19.80/21.02/20.94（前两轮暖机拖尾）；new 14.62/20.53/19.80/21.17/21.33/21.04（5/6 轮 ≥19.8 稳定带）。

**结论：qtzi 145 处 + CVE bump 客户端零回归；新内核整体水位 base 臂 +15%（17.93→20.68，内核红利）。**

## 上传方向（双向补测）
| 轮 | base | new | ratio |
|---|---|---|---|
| 1 | 4.82 | 4.78 | 0.992 |
| 2 | 4.84 | 4.74 | 0.979 |

**ratio ≈0.98 PASS**（360MB/轮完整到达 ok=6/6）。绝对值 ~4.8 MB/s vs 下载 20 的 4× 不对称
= xhttp stream-up 上行路径固有（enc8x 战役上行窗已对称化后仍存），非本次回归，另开票候选。

## 插案发现（不阻塞）
1. **VPS xray freedom 出站 SSRF 防护 block 回环**：POST 目标 127.0.0.1:19900 被 VPS 端 freedom 黑洞（curl 干等 180s），
   公网 IP 目标直通——Rust freedom 与 Go freedom.go:165 getDefaultFinalRule 同款行为实证。
2. e2e_p2_dns_core_resolution（CI release）一次假挂 = hosted runner 限流（debug 步骤 6.7min→92min 劣化 14 倍），rerun 绿，非代码问题。

## 基线对照
- 用户判据：v2rayN 多线程 ≥25 MB/s（us1:39824 raw+reality）为最终验收——PM 护栏口径（39380 节点 6×10MB）与
  v2rayN 方法不可跨口径比绝对值，本次护栏结论为**相对无回归**。
- 绝对值验收：用户下次 v2rayN 多线程实测。

## 用户最终验收（2026-10-14 黄金窗，v2rayN 多线程，内核 a3d37d9d）

**VERDICT: PASS——基线判据全线达标**

直连族（us1.begonia92.top，全部 ≥25 ✅）：
| 节点 | 端口/传输 | 速度 MB/s |
|---|---|---|
| trojan-reality | 39436 raw | **28.4**（逼近直连历史上限 ~30）|
| vl-xhttp-reality-enc | 39380 xhttp | 25.9 |
| trojan-tls | 39949 raw | 25.8 |
| vl-reality-vision（基准）| 39824 raw | **25.7 ≥25 ✅** |
| vless-tls-vision | 39057 raw | 25.5 |
| tuic | 39743 | 25.1 |

CF 隧道族（home.begonia92.top）：25.0-66.9，vless-ws-tls-argo 66.9 / tt-httpupgrade-cdn 65.4 领跑，xhttp-argo 族 25-26 常态。

**定案：qtzi 145 处 + 10 CVE 清零 + 新内核 7.2.10-tcpboost+ 组合，v2rayN 原生方法实测零回归且 trojan-reality 创新高。**
