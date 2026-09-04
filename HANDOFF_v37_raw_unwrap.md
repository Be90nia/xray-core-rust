# HANDOFF v37 (2026-09-04) — vision splice raw-unwrap 路线(新会话从这里开工)

## 0. 仓库状态

- **HEAD**: 02b83a3(docs: HANDOFF v36)+ 本 commit(connection.rs raw_tcp_clone 雏形)
- **dist/xray.exe**: md5 `321fec760f9f6fb394735f55dbe46939` = 干净 v34 baseline 编译,未含 raw_tcp_clone(该改动 Windows 下惰性,无需急拷)
- **2026-09-04 晚实测单节点**:#9=10477B / #15=10477B / #32=4560B,全 partial FAIL(curl 56 missing close_notify)——§1 模型与 §5 分诊实证成立;**全套 PASS 数以复测为准**(记忆记载"21/32"与分诊表 13 节点 FAIL 矛盾,不可信)
- **开工第一件事**:`python dist/run_full32.py` 复测钉死基线(单节点验证命令 `python D:/tmp/test_node.py <N>`)
- 工作树应只剩 dist/ 下 untracked 测试脚本;`git status` 有 M crates/xray-transport/src/connection.rs = 本 commit 之前状态

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

## 5. 剩余 11 FAIL 分诊(更新版)

| 节点 | 根因 | 本会话动作 | 剩余工作 |
|---|---|---|---|
| #9 #15 #32 vision partial | splice 后须绕外层 TLS 读 raw TCP | 根因实证 + trait 雏形 | §2 第 2-4 步 + §3 Windows,2-4h |
| #1 #7 #18 argo+xhttp | CF 严格反指纹;强制 stream-one 会 400(splithttp bad status:400,server 要 packet-up) | 尝试+回退(73467d0) | 重写 packet-up/stream-up dialer 用 http2::handshake+btls(保持 mode 语义),3-4h 高回归风险 |
| #10-#13 #16 mlkem | vless ENC 架构错位 | 未动 | 2-3 天 |
| #29 #31 naive/anytls | 协议层缺口 | 未动 | 1-2 天 |

## 6. 本会话已废弃结论(别再踩)

- ❌ "caller 写明文 HTTP,is_complete_record 永远 false" —— 错,caller 写的是 curl 的 TLS records
- ❌ "splice 后读 inner(TLS decrypt)就能工作" —— v3 实测 curl 0KB,密文流被错误解密
- ❌ "不响应 DIRECT 帧可以避免错位" —— v2 实测 10KB partial,server 已停 wrap,client 必须跟着切
- ❌ splithttp H1/H2 强制 stream-one —— 400 bad status(mode 语义不兼容,回退 73467d0)
- ✅ btls 缺 take_inner() 但有 get_mut()/get_ref(),borrow 够用(配 dup/clone handle)
- ✅ dbg 探针三步走 + eprintln 在 vision_conn poll_read 是最有效定位手段
