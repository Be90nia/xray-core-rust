# HANDOFF v35 (2026-09-04) — splithttp 接 btls 尝试失败回退

## 尝试: splithttp H1/H2 路径走 btls + stream-one 模式

**目标**: 修 #1 #7 argo tunnel + #18 trojan+xhttp 节点 (CF 严格反指纹要求真 Chrome ClientHello)

**方案**: 把 splithttp register.rs H1/H2 路径改为:
1. 自己 dial_system TCP
2. 用 `xray_tls::utls::u_client` 握 TLS (走 btls 真 Chrome 指纹)
3. 直接 `dialer::dial_reality_stream_one(tls_stream, ...)` 走 stream-one 模式 (单连接 http2 多路复用)

**实施**: commit 改动 `crates/xray-transport-splithttp/src/register.rs`

**结果**: ❌ **回退**

## 实测问题

| 节点 | 旧 (baseline) | 新 (splithttp btls) |
|---|---|---|
| #1 vmess tls/xhttp argo | timeout | timeout |
| #7 vless tls/xhttp argo | timeout | timeout |
| #18 trojan tls/xhttp argo | timeout | timeout |
| **#4 vmess tls/xhttp cdn** | **PASS 877KB** | ❌ **400 bad status** |

## 根因

错误日志:
```
ERROR dial failed: vmess dial server (xhttp): splithttp stream-one: splithttp bad status: 400 tag=proxy
```

**#4 (cdn, baseline PASS) 现在 400** —— **server 端期望 packet-up mode** (默认 mode) 但 **stream-one 的 request meta 含 mode=stream-one 标志**,server 拒绝。

具体:
- splithttp config 字段 `mode` 没设 → 默认 `auto` → `resolve_mode("auto", has_reality=false, has_download=false)` = `"packet-up"` (register.rs:230 resolve_mode)
- 但我让 H1/H2 路径强制走 `dial_reality_stream_one` (内部用 stream-one 风格 request meta)
- Server 收到 stream-one flag 但 base_uri 路径 `/path` = packet-up 期望路径
- Server 返回 400

**修复失败**: 没法让 stream-one 既符合 packet-up mode server 又能 verify。

## 真正修法 (工作量评估)

**需要让 splithttp H1/H2 路径既走 btls 指纹又支持三种 mode (packet-up / stream-up / stream-one)** —— **必须重写 packet-up 和 stream-up** 让它们也用 http2::handshake 而不是 hyper-rustls。

**工作量 ~3-4h** (重写 packet-up/stream-up 用 http2 多路复用),**风险高** (因为这些路径是 32 节点中通过的基础设施,改坏就 regression 18/32 → 12/32)。

**决策**: **回退 + 不动 splithttp**。接受现状 21/32。

## 当前状态

- HEAD: 7fed2ff (v34 HANDOFF)
- dist: ac585acf (干净 HEAD)
- **21/32 PASS** (baseline 恢复)

## 剩余 11 FAIL

| 节点 | 类别 | 工作量 |
|---|---|---|
| #1 #7 argo | splithttp 接 btls (mode-兼容) | 3-4h 高风险 |
| #10 #11 #12 #13 #16 mlkem | vless protocol 架构重构 | 2-3 天 |
| #18 trojan+xhttp | splithttp 接 btls | 同 #1 #7 |
| #29 naive | 协议层 (sing-box) | 1-2 天 |
| #31 anytls | 协议层 | 1-2 天 |
| #9 #15 #32 vision splice partial | raw TCP unwrap | 2-4h |

**ROI 排序**: mlkem (#10-#13 #16 = 5 节点) > vision splice (#9 #15 #32 = 3 节点) > splithttp btls (#1 #7 #18 = 3 节点) > naive/anytls (#29 #31 = 2 节点)。

**当前状态: 21/32 PASS 已稳定**, **用户已接受当前进度**,**剩余工作量 > 3天**。