VERDICT: DONE（方案 A PASS：Rust 客户端 → CF(AMS) → argo 隧道 → Go 26.10.11 trojan+xhttp:39014，64KiB+3×1MiB 真实往返全 200；出口 IP 实证 = VPS；服务端零改动；NAT/方案 B 按门槛跳过并说明）

# zlezx：真实公网多跳 —— CDN / 域名前置（方案 A 零风险路径）

> 用户授权：**只读使用**现有 argo 隧道与 Go 26.10.11 服务端（「可以用但是测试完了要还原回去」）。
> 禁改 CF 控制台 / argo.service / token 文件 / xr.json（只读）。

## 待办清单
- [x] §1 环境事实表
- [x] §2 DNS 与证书确认（39007-39016 各端口真实协议，来自 xr.json，不猜）
- [ ] §2 DNS 与证书确认（us1-argo.begonia92.top）
- [x] §3 方案 A：Rust 客户端 → CF → Go 26.10.11（≥64KB 真实往返 + 经 CF 证据）
- [x] §4 NAT 模拟（跳过，见 §4）（可选）
- [x] §5 方案 B（跳过，见 §5）（可选；若做含还原证据）
- [x] §6 发现的问题 / §7 残余风险

---

## 1. 环境事实表（来源：`/root/agsbx/xr.json` 只读拉取，D:/tmp/xr_ro.json 留档；**不猜**）

39007-39016（CF ingress `^/3dba3e56aa3a6ca5-a-*` 指向的这组）全部为 **security=none 的 CF 源站形态**
（TLS 终结在 CF 边缘，cloudflared → 127.0.0.1 明文），且全部 `mode=packet-up`（xhttp）：

| 端口 | tag | protocol | network | path | 认证 |
|---|---|---|---|---|---|
| 39007 | d-vl-ws | vless | ws | /3dba3e56aa3a6ca5-a-vw | id（dec=none） |
| 39008 | d-vl-xhttp | vless | **xhttp** | /3dba3e56aa3a6ca5-a-vx | **decryption=mlkem768x25519plus…**（VLESS 加密） |
| 39009 | d-vm-ws | vmess | ws | /3dba3e56aa3a6ca5-a-vm | uuid |
| 39010 | d-vl-hu | vless | httpupgrade | /3dba3e56aa3a6ca5-a-vu | **decryption=mlkem768…** |
| 39011 | d-tr-ws | trojan | ws | /3dba3e56aa3a6ca5-a-tw | password |
| 39012 | d-tr-hu | trojan | httpupgrade | /3dba3e56aa3a6ca5-a-tu | password |
| 39013 | d-vm-hu | vmess | httpupgrade | /3dba3e56aa3a6ca5-a-mu | uuid |
| **39014** | **d-tr-xhttp** | **trojan** | **xhttp** | **/3dba3e56aa3a6ca5-a-tx** | **password = 8822cf1e-dd8a-4af3-b1c6-dab0eab00c6a** |
| 39015 | d-vm-xhttp | vmess | xhttp | /3dba3e56aa3a6ca5-a-mx | uuid |
| 39016 | d-ss-ws | shadowsocks | ws | /3dba3e56aa3a6ca5-a-sw | ss method/password |

票面前置侦察说的「-vx = vless+xhttp」**错了一半**：`-a-vx`（39008）确实是 vless+xhttp，但其
`decryption=mlkem768x25519plus…`（VLESS 加密，Go 26.x 特性）——Rust 客户端不支持该解密，选它会
卡在认证层污染本票结论。**方案 A 选定 39014 = trojan + xhttp（packet-up）**：认证是 trojan
password（Rust trojan 客户端标准面），xhttp 形态 ✔。

（同域其他形态非 39007-16 组：2053 vless+xhttp `/3dba3e56aa3a6ca5-vx` sec=tls 等，本票不涉及。）
服务端出站：`direct(freedom)` / `x-warp-out(wireguard)` / `warp-out(freedom)`。

## 2. DNS 与证书确认（本机实测）

- DNS：`us1-argo.begonia92.top` → **104.21.14.64 / 172.67.158.34**（Cloudflare anycast 段）✔
- `curl -sI https://us1-argo.begonia92.top/3dba3e56aa3a6ca5-a-tx`：

  ```
  HTTP/1.1 404 Not Found        ← ingress 转发进隧道后由源站 xray 返回（裸 GET 无会话）
  cf-cache-status: DYNAMIC
  Server: cloudflare
  CF-RAY: a53b9fce5ea22f36-AMS  ← CF 边缘（AMS）终结并回源
  alt-svc: h3=":443"
  ```

  证书链由 CF 终结（本机 curl 无告警）✔。

---

## 3. 方案 A：Rust 客户端 → CF → Go 26.10.11（**PASS**）

### 3.1 配置（客户端，未 commit；服务端零改动）

```json
outbound: protocol=trojan, servers[0]={us1-argo.begonia92.top:443,
           password=8822cf1e-dd8a-4af3-b1c6-dab0eab00c6a}
streamSettings: network=xhttp, security=tls,
  xhttpSettings={host=us1-argo.begonia92.top, path=/3dba3e56aa3a6ca5-a-tx, mode=packet-up},
  tlsSettings={serverName=us1-argo.begonia92.top, alpn=[h2,http/1.1]}
inbound: socks 127.0.0.1:18765
```

客户端二进制 = 本仓 release 构建（`xray 26.10.11 profile=release windows-x86_64`，target-Wave7Cdn）。
服务端零改动（只读用了 xr.json 的 39014 trojan+xhttp 入站与 argo 隧道）。

### 3.2 真实数据往返（原始输出）

```
=== run0 冷启动（含 xhttp 会话建立 + CF TLS 握手） ===
run0: http=200 bytes=65536  start=3.722s total=3.723s          ← ≥64KB ✔（冷启动 TTFB 3.7s）
=== 3 × 1MiB ===
run1: http=200 bytes=1048576 start=1.993s total=5.134s speed=204235B/s
run2: http=200 bytes=1048576 start=3.748s total=5.641s speed=185887B/s
run3: http=200 bytes=1048576 start=1.417s total=2.717s speed=386001B/s
=== 第二轮复测 ===
run4: http=200 bytes=1048576 total=17.802s
```

下载文件落盘字节精确（65536 / 1048576×3）。TLS 握手/会话建立计入冷启动 TTFB（3.7s 含 CF 握手 +
xhttp packet-up 会话 + trojan 认证 + 源站 freedom 拨号）；热请求 TTFB 1.4-3.7s（本地 CN→CF 晚高峰
链路质量主导，见 §6 观察 2）。

### 3.3 「流量确实经 CF 而非直连 VPS」的证据闭环

1. **DNS**：`us1-argo.begonia92.top` → 104.21.14.64 / 172.67.158.34（Cloudflare anycast 段）——
   客户端 TCP 对端是 CF 边缘，不是 VPS（VPS IP 176.122.139.45 完全不出现在拨号目标里）。
2. **CF 响应头**：直连隧道域名 `curl -sI` → `Server: cloudflare` + `CF-RAY: a53b9fce5ea22f36-AMS`
   （AMS 边缘；404 响应体本身来自隧道源站 = ingress 转发生效）。
3. **出口位置（决定性）**：`https://cloudflare.com/cdn-cgi/trace` 经隧道 vs 本机直连：

   ```
   本机直连:  ip=61.144.188.80    colo=LAX  loc=CN   ← 本机出口
   经隧道:    ip=176.122.139.45   colo=LAX  loc=US   ← = VPS IP
   ```

   出口 IP = VPS ⇒ 数据确实走了 本机 → CF 边缘 → argo 隧道(cloudflared) → 源站 xray(39014
   trojan+xhttp) → freedom 出公网 的完整多跳链。

---

## 4. NAT 模拟（可选）——跳过

WSL iptables 方案需改动本机网络栈（NAT 重定向规则），风险/收益比不划算：方案 A 已证明 Rust 客户端
在「无公网入站端口、仅出站访问 CF anycast」的 CDN 前置形态下正常工作——这正是 NAT 后部署的语义
（客户端本来就只需要出站能力）。如后续要专项验证 NAT/防火墙行为，建议单开票（含 UDP 出站被禁等
更细的分档）。

---

## 5. 方案 B（Rust 服务端经 CDN）——跳过

判断：**风险高、增量价值低，跳过**（符合票面「仅在阶段 1 通过且确有价值时」的门槛）。
- 价值面：Rust xhttp 服务端 `transport::listen_splithttp` 已有 loopback 端到端测试覆盖
  （hub_limits / mock_server / stream_h2 套件），CDN 场景对服务端的额外输入 = cloudflared 转发的
  明文 HTTP（h2/h1.1）——与 loopback 测试同一输入族，预期无新信息。
- 风险面：需要停 `xr` 生产服务、换二进制、改后还原——生产链路上任何半途失败影响真实节点。
- 若 PM 要做：流程 = 记录 `xr.service` 状态 + `/root/agsbx/xray` sha256 → 停服换 Rust 二进制 →
  测 → 还原 → sha256 校验 + `systemctl status xr` 对比，全程 journalctl 留档。

---

## 6. 发现的问题

1. **观察（非缺陷）**：吞吐波动大（200-386KB/s，第二轮 1MiB 17.8s）——本地 CN→CF 晚高峰链路主导
   （直连对照同样波动）；本票判据是连通性与路径，吞吐基准归 `loopback_alloc_bench`/专项票。
2. **观察**：`speed.cloudflare.com/meta` 经隧道返回空 `{}`（直连同 URL 返回正常 JSON）——该端点对
   经代理流量的响应差异未深究（trace 端点已给出更结论性的证据）；若复现感兴趣再开小票。
3. **工程注意**：Windows 下 OMP bash 的后台子进程随命令结束被回收——客户端进程需与压测命令放在
   **同一命令内**先后台再测（本次采用）；PowerShell Start-Process 方案在本环境会挂起，弃用。

---

## 7. 残余风险

- 只用了 trojan+xhttp 一个形态做了端到端；39008（vless+xhttp）因服务端启用 VLESS 加密
  （decryption=mlkem768x25519plus，Rust 客户端不支持）不可用——若 PM 要 Rust 支持该形态，属
  新特性票（VLESS encryption），非本票范围。
- 云flare 免费边缘的吞吐波动会干扰任何「性能」类结论；后续性能类验证建议换 `loopback_alloc_bench`
  或多轮取中位数。
- 测试账号/路径为生产在用节点（只读使用，无任何改动）；`D:/tmp/wave7_cdn/` 留有客户端配置
  （含 trojan password）与下载样本——敏感信息与 VPS 同源，本机留档风险可接受，如需可删除。

（本节完 → 落盘）
