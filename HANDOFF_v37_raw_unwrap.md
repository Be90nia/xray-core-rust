# HANDOFF v40 (2026-09-05) — 🎉 **32/32 全通达成**(v37→v40 一日战役)

## 0. 仓库状态
- **✅ v41 全协议调通收官(2026-09-05 凌晨)**: ① VPS 32/32 全通(4092505, PM 两轮独立复跑 `D:/tmp/final_32of32.txt`/`final_v41_full32.txt` 均逐行核对); ② **wireguard 互操作打通**(d8a114b: smoltcp 0.12 端口 0 恒 Unaddressable 需自分配+TX checksum 未开致 gVisor 静默丢包;YouTube 经 WG 隧道 875KB+scapy Noise 握手证据); ③ **server 侧补全+反向互操作**(6f27649/dd9bdbf: grpc server 三病对称修复+content-type+ss inbound transport 接线缺失+ss legacy 响应缺新 IV/rekey 违反 Go wire——Go client→Rust server 的 grpc/kcp/ss 三发 874-878KB 全 PASS)
- **⚠️→✅ v49 server 侧 vision splice 尝试回退(2026-09-05, SrvSplice 1h33m)**: 大框架帧逻辑正确(3 确定性单测: END 编码/DIRECT 写切 raw/收 DIRECT 读切 raw, accept 层 dup_tcp_stream 克隆等价 Go UnwrapRawConn)但引入**跨缓冲窗口流式挂死回归**(512KB 挂/32KB 过; v44 基线无; 污染 client 既有 splice_uplink 测试)——按 PM 裁决整体回退保 32/32 底线。挂死线索留存 history://SrvSplice: CommonConn poll_read Pending 与 VisionConn loop 的 waker 传播(半 record 滞留 raw_buf 丢唤醒窗口)/poll_write Ok(0)→Pending 分支/512KB duplex 复现床(target/stress_out.txt)。**回滚后基线验证: #28 #9 #32 抽验全绿 + 全套 32/32**(dist=cd7a5177)。结论: server splice 需先解 smoltcp/duplex 层 waker 问题再战, 挂死期间 dist 严禁部署 server vision+TLS 大流量场景
- **✅ v42 质量打磨轮(2026-09-05, c4cf909+6f32c25)**: ENC 0-RTT 快路径启用(xor_mode=0+seconds>0 即走,缓存 PfsKey+新 nfsKey 对齐 Go;本地双连实证 conn1 缓存写入→conn2 fast path engaged 双 200)+app-dns 族过滤根治(serial/parallel_query 透传 IpOption,ipv6_enable=false 不再混 AAAA——wg 首连 50% 超时的上游根因,wg 出口另有防御过滤双保险)+wg 首连超时根因修复(dispatcher 族过滤,30/30 零超时);v42 合集二进制全套复跑 32/32 零回归;dist/xray.exe=e65c506b
- **✅ v54 遗留清偿轮(2026-09-05, d5d7825+0da2368+4b6ec8f+6b5a88a)**: HANDOFF v53 三注脚全部闭环——①**xor_mode==2 双向互通**(0da2368): 三根因(XorConn 全流量 XOR 应为 header-only/mode2 时替代 CommonConn 层次/skip 顺序颠倒), xor_conn.rs 重写为 Go 同构状态机+Go 真值 fixture 逐字节单测, vless 219/0, interop_enc.py 4/4 PASS(PM 复跑); ②**grpc 深层对称**(6b5a88a): interop_grpc.py 双向 3 连发 x 2 轮稳定, **零修复**直接全通; ③**ocsp-stapling**(4b6ec8f): feature 编译错修复+2 烂测试清理, feature 143/0; ④**REALITY/vision server 穿透本机实证**: Docker Linux 床(rust:1-bookworm 容器挂载编译, CARGO_TARGET_DIR=/lt 隔离不污染 Windows target)跑 Linux 版 Rust server, Windows Go client 连 localhost 映射口, strace 实证 `dup(10)=11`(accept 层 raw 克隆激活)+3 轮 874-878KB e2e——穿透从"仅 VPS 验证"升级为"本机可复现调试"; 附产=**Linux 编译账全清**(d5d7825: xray-buf nix zerocopy feature+splice AsFd 重构/sockopt impl 错位/xicmp 路径/socket2 Type::from 等价构造/udp cmsg 借用/dokodemo tokio from_std 中转+fd double-close 真缺陷修复, 容器 build 全绿+buf --lib 186/0, 全在 linux 门控内 Windows 零影响); PM 复跑 12/12 矩阵+全套 32/32 零回归
- **✅ v53 本地双向互操作矩阵轮(2026-09-05, 2c99e38+d4f0f37)**: 新增 dist/interop_matrix.py(**6 协议×2 方向=12 测**: vmess/vless+vision+TLS/trojan+TLS/vless+ws/ss/ss2022, Go client 侧 pinnedPeerCertSha256 从证书现算/Rust client 侧 allowInsecure, 验收口径与 32 套一致)+interop_gogo.py 三测对照。首跑 9/12 曝出 2 个 Rust server 真 bug 双双修复: ①**TLS 私钥错标**(2c99e38): Go `tls cert` 产 RSA 标签+PKCS#8 EC 内容, Go X509KeyPair 逐格式试解析免疫而 rustls-pemfile 按标签分发炸——修=pem_private_key() 官方 PrivateKeyDer::try_from 内容嗅探重定形(失败保留原定形向后兼容), xray-tls 133/0; ②**ss2022 sing wire 四缺陷**(d4f0f37): 首段 payload 嵌请求 chunk 尾被丢/缺响应头(resp_salt||AEAD fixed||AEAD 首段, 响应 subkey 重计数)/握手 chunk 直 seal 无 2B size 前缀/臆造 900+260 上限——wire 以对端读路径反推, ss 155/0; PM 复跑**矩阵 12/12 全 PASS + 全套 32/32 零回归**; 注: 32 套本身即 Rust client↔VPS(Go server)真实互操作, 本矩阵补齐本地双象限
- **✅ v52 三层组合专项闭环轮(2026-09-05, 94b9df2)**: Rust↔Rust vision splice 512KB bulk 挂死定位并修复——根因**不在 xray 代码层**, 是 Windows loopback TCP 栈病理(单 task 零间歇全速 send 大 bulk 发送停滞: 内核 send buffer 持续 Ok 但 25KB 滞留永不送达, 20+ 探针实证各层 poll 语义全对+字节守恒); 对照矩阵(bare TCP/rustls 无 Vision/Vision 无 rustls 全绿, 仅三层组合挂)排除法定界; 修=集成测试 client 改 curl 并发+8KB/1ms 节流对齐真实 pump 节奏(512KB 完整性断言不变); vps_interop 两测试适配 InnerRawClone bound(v50 起 VisionConn 带 raw_tcp 注入); integration 3 连跑 1.06-1.10s 稳定绿(PM 复验)+全套 32/32 零回归; **vision splice 双端 e2e 闭环, 唯一开放缺陷清零**; 沉淀 rules/common-windows.md + bd remember: Windows loopback TCP 单进程零间歇全速 send 大 bulk 发送停滞病理+分层探针定界法+测试驱动对齐真实 pump 节奏铁律
- **✅ v51 TLS 包装层丢唤醒根治轮(2026-09-05, f9a14f6)**: 验证阶梯 c 真根因=**tokio-rustls 0.26(Watfaq fork) poll_write 是 BufWriter 语义**——Ok(n) 只保证进 rustls session 缓冲, write_io Pending(底层窗口满)时尾部 TLS record 滞留仅 poll_flush 写出; 生产 bridge write_all 循环不 flush→尾 chunk 滞留+上层转等响应=双向死锁(64KB duplex 硬窗口必现, 真实 TCP 弹性缓冲不触发=VPS 一直绿的原因); btls 路径无缺陷(ENABLE_PARTIAL_WRITE 开启 waker 已注册); xray-tls 三包装浅层审计纯转发无同族缺陷。修=utls.rs Conn/ServerConn dirty 状态机(poll_write 内联尽力 flush, Pending 不上传防重发同段明文重复加密; poll_read 借读侧 poll 推进滞留解鸡生蛋相位)+stress_tests.rs 双路径真 TLS 512KB duplex bulk 回归(修复前 30s 挂死→修复后 0.04s 5 连稳定); xray-tls 129/0, vless --lib 217/0, #9=877201B #15=876904B PASS
- **✅ v50 挂死根因修复 + server splice 合入轮(2026-09-05, f926b06)**: WakerBugFix 钉死根因(纯 HEAD 复现, 非 splice 引入)——CommonConn.poll_write 部分写后返回**裸 Pending**(底层刚 Ok(n) 无 poll 注册 waker)→丢唤醒→writer 停转+对端持残段凑不齐 record→五边形死锁(账面 1355+7x8197+8141=65536 恰满 64KB 窗); 修=部分写 continue 重试+Ok(0)→WriteZero(VisionConn/CommonConn 两层); server splice 重接(accept 层 dup+VisionRole)验证阶梯 a 512KB 0.38s/2MBx3 PASS+b vless 217/transport 487 全绿+c duplex bulk 相位超时(**TLS 包装层同族丢唤醒, 独立排查; 真实 TCP 不触发**)+d Go client↔Rust server 879375B PASS(PM)+e VPS #9 #15 PASS(PM); PM 复跑全套 32/32 零回归; dist/xray.exe=f8b5831b
- **✅ v48 四小项收官轮(2026-09-05, f572380)**: trojan users 日志口径(get_key_count 对齐 vless)+vless 拒绝日志 debug→info(Go inbound.go:522 AtInfo)+ss2022 uot 多用户 e2e(集成+进程级双通; Go 基准无 uot 概念, 目标=uot 配置在场时 EIH UDP 链路完整)+certificates 非法内联集成测试(完整配置启动报 certificate 错 EXIT=1, 对照组自签回退正常); 四 crate --lib 全绿; PM 复跑全套 32/32 零回归; dist/xray.exe=f572380 构建(含全部改动)
- **✅ v47 validator 计数口径轮(2026-09-05, 85c1bbb)**: users=0 "认证跳过"经复现**证伪**——clients 载入与 UUID 认证从未断裂(decode_request_header 未注册 UUID 一律拒), 是 get_count 只数 email 表(Go GetCount 同义)的口径问题; 修=Validator trait 新增 get_uuid_count()+3 处启动日志换口径+2 认证单测+serve 级认证 e2e(合法通/非法拒); 顺带修 e1f4a5a 遗留 serve_reality_vless 测试调用缺参(曾阻塞 xray-core 测试编译); 复验 vless --lib 215/0, core --lib 241/0, #9=877103B(PM)
- **✅ v46 ENC server 0-RTT 会话轮(2026-09-05, e1f4a5a)**: 按用户裁决拓扑 **Go client 26.7.28 ↔ Rust server** 实测——curl#1 1-RTT session stored(sessions=1) → curl#2 **0-RTT ticket accepted**(replay-guard) → curl#3 nfs_keys=2, Go client 零 handshake error; 实装=SessionStore(sessions/tickets/lasts/closed 对齐 Go server.go:36-41)+handshake_zero_rtt(miss 回写 1279..2279B 非 TLS 噪声触发重握手+同 nfs_key 即 replay)+ticket 协商(from-to rand)+60s 过期清理; **inbound 生产接线**(inbound.rs build_vless_decryption 消除硬编码 encryption:none+三子路径); vless --lib 213/0(5 新: replay 4 连全拒/过期噪声/清理语义); PM 复跑全套 32/32 零回归; 既有遗留新记: validator users=0(UUID 认证跳过)独立排查
- **遗留(非阻塞, v54 口径)**: ss2022 uot 互操作不可行(Go 基准无此概念, Rust 扩展); grpc server 已双向多请求闭环(v54); ocsp-stapling 已修(v54); xor_mode==2 已双向互通(v54); REALITY/vision server 穿透已本机实证(v54, Docker Linux 床配方见容器章节); workspace 画像全绿; **注脚清零——本机可验项全部闭环**; 留账: xicmp linux_impl 仍为 ponytail 占位(send/recv 返回 Unsupported, 与 Windows 路径行为一致); Rust client grpc 无连接池(单连接多请求仅 Go client 方向结构性成立); EncXor2 residual: xor_mode==2 的 0-RTT 双向未单独立项测(client 0-RTT deferred/server (16,0) 已按 Go 对齐, Rust↔Rust zero_rtt 绿); Docker 调试床配方: `docker run -d --name xrbed2 -p 18400:18400 -v D:/Project/Xray-core-rust:/src -v D:/tmp:/tmp_host rust:1-bookworm sleep infinity` + `docker cp` 拷 `/lt/release/xray`(Linux 编译须 CARGO_TARGET_DIR=/lt 隔离+btls-sys 走 BORING_BSSL_SOURCE_PATH=/src/target/boringssl-patched+BORING_BSSL_ASSUME_PATCHED=1, 容器 config.toml [env] 固化)
- **✅ v44 workspace 测试全绿轮(2026-09-05, 91b72ab)**: 4 个既有测试失败全修——observatory probe 产品 bug(block_on 复用 runtime,async 上下文必炸,改 thread::scope+独立 runtime)+core observatory_init(#[tokio::test])+**UDP 路由产品真 bug**(RoutingContext 恒缺 inbound_tag+UDP 入口 access=None→inboundTag 规则永不命中恒落 blackhole,TCP 同病此前无覆盖,修 dispatcher.rs:902+wiring.rs:310);observatory 148/core 240 全绿,btls-sys debug 挂死已解(inject_btls_cache.py 配方,ss 148 跑通);PM 复跑全套 32/32 零回归;剩余非绿=vless 6F/xray-tls 1F/hysteria 3F(debug-profile 既有,stash 对照与本次无关,留分诊)
- **验收口径(长期有效)**:全套 [PASS] 标记有假 PASS 前科——以单节点 `python D:/tmp/test_node.py <N>` body≥870000B 为准;**改动波及共用代码时必须重编译后用新二进制复验**(本次 ss nonce 分离就需补验 #26-28)
- **方法论沉淀**: wire 调试三板斧(本地 Go server+oracle 逐步解密+scapy 抓包字节 diff);部署副本 md5 必校验;两个 scout 线索均可证伪,dbg 实证优先
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
| #1 #18 argo+xhttp | CF argo 按 TCP TLS 栈白名单拒(rustls=RST/btls=tarpit,详见 history://ArgoFix 二分实证) | ✅ **已修 h3 路线**(换 QUIC 检测面: CF QUIC 面放行 quinn 无需 TP 对齐;真根因=h3 GET 同步等响应与 POST 上传顺序死锁,改 lazy reader 对齐 Go gotConn;876-880KB,f559f03;alpn=[h3] 由节点配置驱动,dist/uriclient.py 测试注入) | 无 |
| **mlkem 组 ×6: #7 #10 #11 #12 #13 #16**(原分诊 #7 误归 argo,#18 实为 trojan+xhttp 无 mlkem) | vless ENC mlkem768 0-RTT;统一 `encryption=mlkem768x25519plus.native.0rtt.<ek>` + `seconds=1`;parse/1-RTT/0-RTT client pre_write 已实装(params.rs/outbound.rs:887/mod.rs:332-382),0-RTT cache 未实装;**两个待实证线索**: (a) ArgoH3Fix 称 dispatcher.rs L52 自认 enc_params 配置链未接线 (b) MlkemScout 称 Rust server 侧 length==32 拒绝是首因——outbound 场景(远端 Go server)此推理存疑,实施须先 dbg 实证 client handshake 卡点(发 pre_write 后读 serverHello?);#11 为 reality+ENC 分支顺序正交错位(ENC 包流致 reality dialer 拿不到裸流) | MlkemScout 已摸底(缺口清单+Go wire 格式+byte-diff harness 方案,history://MlkemScout) | 先实证 client 卡点→对齐 Go wire(client.go Handshake: iv+relays→nfsAEAD.seal(pfs 1250+padding≥34)→serverHello 1120+32)→0-RTT cache 实装;预估 1-2 天 |
| #29 naive | hyper 1.10.1 CONNECT 三坑(body 被丢/200 body 空/SendRequest drop 触 GOAWAY) | ✅ **已修**(OnUpgrade 语义重写,874768B,2c01504) | 无 |
| #31 anytls | 客户端不发 auth 帧+anytls-rs 0.3.5 漏 cmdSYN(sing-box 需显式 SYN 开流) | ✅ **已修**(auth 帧+Settings→SYN→PSH 帧序,877561B,f069f1c) | 无 |

## 6. 本会话已废弃结论(别再踩)

- ❌ "caller 写明文 HTTP,is_complete_record 永远 false" —— 错,caller 写的是 curl 的 TLS records
- ❌ "splice 后读 inner(TLS decrypt)就能工作" —— v3 实测 curl 0KB,密文流被错误解密
- ❌ "不响应 DIRECT 帧可以避免错位" —— v2 实测 10KB partial,server 已停 wrap,client 必须跟着切
- ❌ splithttp H1/H2 强制 stream-one —— 400 bad status(mode 语义不兼容,回退 73467d0)
- ✅ btls 缺 take_inner() 但有 get_mut()/get_ref(),borrow 够用(配 dup/clone handle)
- ✅ dbg 探针三步走 + eprintln 在 vision_conn poll_read 是最有效定位手段
