# HANDOFF v37 (2026-09-04) — vision splice raw-unwrap 路线(新会话从这里开工)

## 0. 仓库状态

- **✅ 本轮修复全部完成(2026-09-04 晚, e5cc465+2c01504+f069f1c)**: vision splice(#9 #15 #32)+naive(#29)+anytls(#31)全真 PASS;全套 **24/32 PASS**(真实基线 19 净增 5),8 FAIL 全部为 §5 分诊未动节点,零回归(#4 #24 抽查+全套逐行核对)
- **dist/xray.exe**: 含全部修复(f069f1c 构建);修复前 baseline 备份 `D:/tmp/xray_baseline_321fec.exe`(md5 321fec...)
- **2026-09-04 晚基线全套实测**(`D:/tmp/baseline_v37_full32.txt`):表观 21/32 PASS,但 **#9=10477B / #15=15983B 是假 PASS**(run_full32.py:40 判定阈值 `bs>5000 and expected in body`,partial 头部含 YouTube 即过),真实全量基线 = **19/32**;真 FAIL 13 节点 = §5 分诊表,完全自洽
- **验收口径(长期有效)**:全套脚本 [PASS] 标记不可信——验收以单节点 `python D:/tmp/test_node.py <N>` body≥870000B 为准,全套跑完逐节点核对 body
- **实施中发现的两个补充根因**(已修,§2 路线之外):① `ResponseHeaderReader`/`Box<dyn Connection>` 的 Connection impl 未穿透 raw_tcp_clone(dyn 分发断链,dispatcher L202 响应头包装层)→ client.rs 双路径穿透;② END/DIRECT 帧跨 poll_read 块时原方案见 cmd 即切 raw → 丢帧尾+外层密文泄漏 → 对齐 Go proxy.go XtlsUnpadding 块完成判定(`remaining_content<=0 && remaining_padding<=0 && cmd!=0`)后才切换
- **遗留(非阻塞)**: server 侧 inbound VisionConn 的 InnerRawClone 返回 None(server splice 不工作,三节点均为 outbound 场景);上行非 TLS 目标保持 CONTINUE(与 Go L379 提前 End 分支不同,行为同 v2 基线)

## 1. #9 #15 #32(vless+vision partial ~10KB)真根因 —— wire-level 已实证

**模型**(此前会话反复搞错的点,这次是对的):

- vless+tls+vision 代理的 TLS 端点是 **curl↔origin(YouTube)端到端**:curl 发 ClientHello → 经 socks5 → vision wrap → 外层 TLS → server 解外层 TLS → freedom 直接把字节原样 TCP 转发给 YouTube:443。server 不做 TLS 终结!
- **splice(cmd=END/DIRECT)之后**:server `UnwrapRawConn` 拆掉 client↔server 外层 TLS,**直接在裸 TCP 上双向搬运 curl↔YouTube 的 TLS records(明文传输密文)**。线上跑的 = 端到端 TLS records,无外层加密
- Go client 878KB PASS:splice 后它读裸 TCP 拿到 YouTube 的 TLS records 原样转发给 curl,curl 自己解密
- **Rust client FAIL**:splice 后仍走 `inner.poll_read` = btls SSL_read,把 YouTube 的 TLS records 当作 client↔server 外层 TLS 去解密 → 解不开 → v3(直读 inner)= curl 0KB;v2(不解 DIRECT 帧,继续当 vision frame 解)= 错位 10KB partial

**dbg 实证**(v41 dbg build,#9):
```
[VISION dbg] down n=126  cmd=0 ...   (8 个 CONTINUE 帧 ~20KB HTTPS 明文?不=错位前的密文)
[VISION dbg] down n=1500 cmd=2 content_len=1395 dl_pad=false   ← server DIRECT 帧出现了
之后 inner.read 全 0/EOF
```
cmd=2 确认 server splice set;DIRECT 帧的 1395B content 是 splice 前最后一段正常 unpadding 数据,**要返回给 caller**,然后切 raw 读。

## 2. 修复路线(4 步,预估 2-4h)

**第 1 步(本 commit 已做)**:`Connection` trait 加
```rust
fn raw_tcp_clone(&self) -> Option<TcpStream> { None }   // crates/xray-transport/src/connection.rs
```
TcpConnection 已实现(unix `dup()`;**Windows 下 cfg 裁掉返回 None —— 见 §3 缺口**)。

**第 2 步**:`crates/xray-tls` 的 BtlsConn(以及 rustls wrapper 若有)override:
```rust
fn raw_tcp_clone(&self) -> Option<TcpStream> {
    // btls SslStream<TcpStream>: get_mut()/get_ref() 拿内层 TcpStream,再走同 §1 的 dup 逻辑
}
```
注意 REALITY 路径(btls_reality.rs)的 conn 类型也要覆盖(#32 是 reality)。

**第 3 步(下行)**:`crates/xray-proxy-vless/src/encryption/vision_conn.rs`
- 加字段 `raw_fallback: Option<tokio::net::TcpStream>`
- `poll_read` 中 `cmd == COMMAND_PADDING_END as i32 || == COMMAND_PADDING_DIRECT as i32` 时:
  1. **先把本帧 content 存 `downlink_pending` 返回给 caller**(现逻辑已做,别丢)
  2. `this.raw_fallback = this.inner.raw_tcp_clone()`
  3. `this.downlink_padding = false`
- loop 顶部:padding=false 时**优先用 raw_fallback.poll_read**(不是 inner!),None 才退 inner
- 之前 v3 失败原因就是 padding=false 后读的是 inner(TLS 层)

**第 4 步(上行)**:重新启用 splice trigger —— **之前的"caller 写明文所以 is_complete_record 永远 false"结论是错的**:caller(bridge←socks5←curl)写的就是 curl 的 TLS records,`[0x17 0x03 0x03]` 前缀成立!
- `poll_write`:`this.uplink_traffic.enable_xtls && is_complete_record(buf)` → 发一帧 `xtls_padding(Some(buf), COMMAND_PADDING_DIRECT, ...)`,设 `uplink_padding=false` + `raw_fallback = inner.raw_tcp_clone()`;此后写走 raw_fallback
- `enable_xtls` 依赖下行 xtls_filter_tls 检测到 YouTube 的 TLS 1.3 ServerHello(经 unpadding 出现在 content 里)——过滤窗口 number_of_packet_to_filter=8,ServerHello 在其中,应能置位;若没置位先 dbg 这条
- write 路径:padding=false 时优先 raw_fallback.poll_write

**无 TLS vision(#15 若是裸 tcp)**:raw_tcp_clone=None,但 inner 本身就是裸 TCP,padding=false 后直读 inner 即正确(v3 行为对它本来就对)。

## 3. Windows 平台缺口(必须先补)

`TcpConnection::raw_tcp_clone` 当前 unix-only(`libc::dup`),Windows 返回 None → #9(纯 tls)修复无效。Windows 方案(任选):
- `std::os::windows::io::{AsRawSocket, FromRawSocket}` + `DuplicateHandle`(kernel32)复制 SOCKET handle → `std::net::TcpStream::from_raw_socket` → `tokio::net::TcpStream::from_std`
- 或查 windows crate / `socket2::Socket::try_clone()`(socket2 已在依赖里,先查它有没有 try_clone —— 之前 grep 没搜到,需再确认版本)
- SO_REUSEADDR 不需要;dup 出的 fd/handle 继承非阻塞 flags,`TcpStream::from_std` 直接可用

## 4. 验证清单

```bash
# 单节点(期望 #9 #15 #32 body≈878KB,HTTP=200 无 close_notify 报错)
python D:/tmp/test_node.py 9
python D:/tmp/test_node.py 15
python D:/tmp/test_node.py 32
# 无回归(#4 vmess+xhttp=877KB, #2 vmess+ws=877KB, #24 trojan+ws=877KB)
python D:/tmp/test_node.py 4
# 全套(期望 = 复测基线 +3:#9 #15 #32 转 ~878KB,其余无回归)
python dist/run_full32.py
```
风险点:若 #9 通了但 #26-28 ss 或 trojan 掉了 → raw_tcp_clone/trigger 影响了别的路径,回查 vision_conn 改动是否只影响 flow=xtls-rprx-vision 分支(dispatcher.rs:207 的 if 才包 VisionConn,其他协议不经过)。

## 5. 剩余 8 FAIL 分诊(v38 最终版)

| 节点 | 根因 | 状态 | 剩余工作 |
|---|---|---|---|
| #9 #15 #32 vision partial | splice 后须绕外层 TLS 读 raw TCP | ✅ **已修**(raw_tcp_clone 穿透链+raw_fallback,874-877KB 真PASS,e5cc465) | 无 |
| #1 #7 #18 argo+xhttp | **CF argo tunnel 按 TLS 栈指纹白名单放行(ArgoFix 40 轮迭代二分实证)**: Go TLS 栈=200 档(含无 fp 普通 hello)/python ssl=403/rustls=RST/btls=tarpit→RST;h2 帧字节已 MITM 重放排除;btls ClientHello 逐字节对齐 utls 后仍被拒——剩 3 处 BoringSSL 内部格式差异(ECH GREASE body 218B vs 186B/ALPS 6B vs 5B/cert_compression 4B vs 3B)不可配置;hyper 直握+DirectH2Client+参数对齐 Go(4MB/1GB/16KB/10MB/45s)均无效 | 未验收改动已回退(曾致 #4/#23 RST 回归,history://ArgoFix 可考) | 三选一: (1) patch BoringSSL 三处格式(btls-sys patch 机制,高难) (2) **h3/quinn 路径(改动最小,QUIC Initial 加密绕开 TCP TLS 栈检测;已探到 quinn✓/h3 握手✓/GET 发出✓ 但 10s 无响应,查 h3 头/回源/quinn 传输参数)** (3) 与节点方确认 CF zone bot 检测配置 |
| #10-#13 #16 mlkem | vless ENC 架构错位 | 未动 | 2-3 天 |
| #29 naive | hyper 1.10.1 CONNECT 三坑(body 被丢/200 body 空/SendRequest drop 触 GOAWAY) | ✅ **已修**(OnUpgrade 语义重写,874768B,2c01504) | 无 |
| #31 anytls | 客户端不发 auth 帧+anytls-rs 0.3.5 漏 cmdSYN(sing-box 需显式 SYN 开流) | ✅ **已修**(auth 帧+Settings→SYN→PSH 帧序,877561B,f069f1c) | 无 |

## 6. 本会话已废弃结论(别再踩)

- ❌ "caller 写明文 HTTP,is_complete_record 永远 false" —— 错,caller 写的是 curl 的 TLS records
- ❌ "splice 后读 inner(TLS decrypt)就能工作" —— v3 实测 curl 0KB,密文流被错误解密
- ❌ "不响应 DIRECT 帧可以避免错位" —— v2 实测 10KB partial,server 已停 wrap,client 必须跟着切
- ❌ splithttp H1/H2 强制 stream-one —— 400 bad status(mode 语义不兼容,回退 73467d0)
- ✅ btls 缺 take_inner() 但有 get_mut()/get_ref(),borrow 够用(配 dup/clone handle)
- ✅ dbg 探针三步走 + eprintln 在 vision_conn poll_read 是最有效定位手段
