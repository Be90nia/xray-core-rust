# HANDOFF v36 (2026-09-04) — vision splice deep dive 调研结论

## 任务背景

用户指令 "全改" - 修通所有11 FAIL 节点。先攻 vision splice partial (#9 #15 #32 = 3 节点)。

## 已调研真相: Rust client splice trigger 不工作

### Wire level dbg 数据 (Rust vs Go)

**Rust client (dist/xray.exe + dbg eprintln)** 测试 #9:
```
[VISION dbg] down n=126  cmd=0 content_len=105   dl_pad=true
[VISION dbg] down n=1058 cmd=0 content_len=1058  dl_pad=true
[VISION dbg] down n=2372 cmd=0 content_len=2372  dl_pad=true
[VISION dbg] down n=1825 cmd=0 content_len=1608  dl_pad=true
[VISION dbg] down n=4744 cmd=0 content_len=4739  dl_pad=true
[VISION dbg] down n=495  cmd=0 content_len=437   dl_pad=true
[VISION dbg] down n=3190 cmd=0 content_len=3016  dl_pad=true
[VISION dbg] down n=6387 cmd=0 content_len=6140  dl_pad=true
[VISION dbg] down n=1500 cmd=2 content_len=1395  dl_pad=false
```

**Go client (v26.7.28) 同样 #9**:878KB PASS

### Go xray vision splice 真模型

`Go vless outbound.go + proxy.go VisionReader/VisionWriter`:
- **`XtlsRead`** (serverReader → clientWriter) 检查 DIRECT frame (cmd=2)
- **收到 DIRECT frame 后**:`switchToDirectCopy = true` → 下次 ReadMultiBuffer 返回 buffer (no unpadding)
- **`readerConn = UnwrapRawConn(conn)`** = raw TCP socket underneath TLS/REALITY conn
- **关键**: **reader 读 raw TLS records from VPS server** (encrypted), forward 给 caller (browser via socks5)
- **TLS termination**:Go xray **TLS终止于 VPS server 和 origin 之间**, Go client 端只 forward raw TLS records
- **splice set 后** = TLS termination **移到 caller (curl) 和 VPS server** 之间
- **curl 通过 socks5 直接 TLS handshake with VPS server**:走 raw bytes pipe

### Rust xray vision splice 局限

**Rust btls SslStream**:
- 有 `get_pin_mut() -> Pin<&mut S>` 借 raw stream
- **没有 `take_inner()` / `into_inner()` 拿走 raw stream**
- **不能像 Go UnwrapRawConn 那样从 TLS conn 中拆 raw TCP socket**

**Rust VisionConn 设计**:`inner: C` (TLS conn), 无法把 inner 拆成 raw TCP 给 caller。

### Ponytail 分析

**client splice trigger 失效**:
- Go client splice trigger 检查 `IsCompleteRecord(buf)`: 检测 caller buffer 是否 TLS record format
- **Rust caller** = bridge io::copy from socks5 (browser sends plaintext HTTP) = **plaintext bytes**
- **`is_complete_record`** 检查 `[0x17, 0x03, 0x03]` 前缀 → **plaintext HTTP 不通过** → splice trigger 永远 false
- **所以 Rust client splice trigger 永远不触发**

**server splice set 单方面触发** (VPS Go server):
- VPS server splice set 后, server 发 DIRECT frame + raw bytes (no frame wrap)
- **Rust client**:
  - **disable DIRECT response (v34 baseline)**:继续解 unpadding → raw bytes 当 frame 解 → 错位 → 10KB partial 后 EOF
  - **enable DIRECT response (v36 尝试)**:设 `downlink_padding=false` → next `inner.poll_read` 走 `btls SSL_read` 返回 decrypted plaintext → curl 拿到 HTTPS response plaintext 部分 + 没 close_notify → curl timeout 0KB

### 实际 root cause

**VPS server splice set 时机**:
- VPS server 检测 caller (origin HTTPS server) 发完整 TLS record → server splice set
- splice set 后 server 发 DIRECT frame + 切 raw copy
- 但 VPS server splice set 是 **server-side unilateral toggle** (来自 caller write 行为)
- Rust client **无法同步 server splice set**:
  - server splice set 时: client 解 DIRECT frame 切 raw copy (Go 可以, Rust 不行 raw read)
  - **server raw copy 模式**: server 发的 raw bytes 经 VPS TLS encrypt → wire → Rust TLS decrypt → plaintext
  - **client caller** 拿这些 plaintext = HTTPS response body
  - **但 server raw copy 关闭连接时 close_notify 行为**: server 主动 close → VPS TLS client-side close_notify → Rust TLS decrypt → EOF
  - **理论应OK但实测**:
    - 9 vision chunks 解 OK (~20KB HTTPS response 头+ body partial)
    - DIRECT frame 切 raw, content 1395 bytes = more HTTPS body
    - EOF 后续没更多数据 → curl 收到 ~10KB plaintext

**为什么 Go client PASS 878KB**:
- Go client splice set 后 raw read = raw TLS records from VPS server
- raw TLS records contain full HTTPS response (878KB) + close_notify
- Go client forward raw bytes to curl
- **curl does TLS handshake with VPS server** (via socks5 raw pipe):完整 TLS exchange → 878KB HTML + close_notify

**为什么 Rust client partial 10KB**:
- Rust client splice set 后 read decrypted plaintext (从 VPS server 来的 raw bytes 经 Rust TLS 解密)
- VPS server splice raw copy 写得 raw HTTPS response data → Rust TLS 解密 → plaintext
- **但 raw HTTPS response 是 plaintext** 不是 TLS records (VPS server 和 origin HTTPS server 之间是 VPS 在 TLS):caller = bridge → socks5 → curl. **Curl 没做 TLS handshake**(curl 用 socks5h 仅做 SOCKS5代理, 不做TLS)
- Curl 把这些 bytes 当 **HTTP response plaintext**:HTTP/200 + body. **但 close_notify 缺失** (raw bytes 没 TLS 包裹,所以没 close_notify alert)
- curl schannel 期望 close_notify → 报错 `server closed abruptly (missing close_notify)`

## 结论

**#9 #15 #32 partial 10KB 的真根因**:**Rust vision splice implementation 不等价于 Go**:
- Go splice = raw TCP forwarder (TLS termination移到 caller)
- Rust splice = TLS layer 解密 plaintext forwarder (TLS termination 留在 Rust btls)
- **VPS server splice set** 后,**Rust 收到 raw bytes**, **btls 试图 decrypt 这些 bytes 当作 VPS-TLS-client-to-server 协议**:但这些 bytes 不是 TLS records (是 VPS-to-origin TLS 解密后的 HTTPS response plaintext)
- **btls 解密错乱** → curl 拿到 10KB 部分错位 plaintext → timeout

**修通路径 (工作量评估)**:
1. **实现 vision_conn splice set 后 raw TCP 读**:
   - 把 `inner: C` 拆成 `(raw_tcp, tls_conn)`:存 raw TcpStream 副本
   - btls 用 SSL_BIO_new 设 BIO 到 raw stream → splice set 后 caller poll_read 直读 raw stream (TLS 在 VPS 终止)
   - **btls 库 0.5.6 不暴露 SSL_BIO manipulation API**, **需要 patch btls 或换库**
   - **工作量**:4-8h 高风险

2. **接受 baseline 21/32 PASS**:partial 10KB 不动

## 当前状态

- HEAD: 73467d0 (v35 HANDOFF) + clean vision_conn.rs
- dist md5: 321fec760f9f6fb394735f55dbe46939
- **21/32 PASS baseline 恢复**
- **本次会话无效改动全部 revert**

## 剩余 11 FAIL (按 ROI)

| 节点 | 类别 | 工作量 |
|---|---|---|
| #1 #7 #18 argo + xhttp | splithttp 接 btls (mode 兼容) | 3-4h 高风险 |
| #10 #11 #12 #13 #16 mlkem | vless protocol 架构重构 | 2-3 天 |
| #9 #15 #32 vision splice | btls UnwrapRawConn 或重写 vision_conn | 4-8h |
| #29 #31 naive/anytls | 协议层 (sing-box) | 1-2 天 |

**已尝试 splice enable DIRECT response + dl_pad=false**:实测 #9 #15 #32 body=0 (比 baseline 10KB 还差)。**回退到 v34 baseline 21/32**。

**用户 "全改" 指令**:已就 vision splice 部分尽最大努力调研 + 多次实验,确认根本限制 (Rust btls 没 raw-TCP unwrap API),**接受 21/32 baseline**。**剩余工作需要专门 session 集中精力**。