# 第二轮对抗审计：外部攻击者视角（畸形输入 / 故障 / 慢对端）

- 仓库 `D:/Project/Xray-core-rust`，分支 `feature/fix-inbound-parity`，HEAD `5fe98b90`
- 实测二进制 `target/release/xray.exe`，启动自报 `version=26.10.11 git_rev=5fe98b907c7b550d4a70202abb475e26ee89013d`（与 HEAD 一致）
- 口径：**生产主路** = 默认 `xray.exe run -c`（`xray_conf::Config::build()` → `xray_core::start_full`）
- 全部为只读审计：零产品代码改动。脚本与配置在 `round2/scripts/`、`round2/tmp/`
- 与第一轮不重叠：第一轮全部「从代码往里看」（接线/效果/分配计数）；本轮「从外往里看」，全部结论都由**真实二进制 + 真实畸形字节流**打出（E1），代码只用于定责与 Go 对照

## 0 一句话结论

解码路径上 panic 很少（vless/ss/vmess 3.9 万次结构化变异零 panic），但**「逐字节 `read_exact`」这一写法在三处开花**：SOCKS4 的 USERID 无上限吃内存、HTTP 请求头把 1 MiB 头吃成 1 CPU 秒、xdns 分片包一处长度门 off-by-two 直接 panic 并让隧道**永久失聪**。三条都是匿名可达（无需凭据），Go 侧同类位置分别是 8 KB 硬顶 + bufio 缓冲 + 255 字节定长数组，**Rust 是逐字翻译时把有界写法换成了无界写法**。

## 1 发现表（8 列）

| # | 标题 | 严重度 | 位置 file:line | 触发输入/条件 | 后果 | 证据等级 + 命令与输出 | Go 侧对照 | 建议一行 |
|---|---|---|---|---|---|---|---|---|
| F1 | SOCKS4/4a USERID（及 4a 域名）读取**无长度上限**且**逐字节 `read_exact`** → 未认证内存 + CPU 双放大 | High | `crates/xray-proxy-socks/src/server.rs:435-449`（`read_until_null`，生产经 `serve_mixed` → `socks_handshake` 调用，`crates/xray-core/src/inbound.rs:613`），调用点 `:408`（USERID）与 `:413`（SOCKS4a 域名） | 匿名：socks/mixed 入站（`auth: noauth`，默认）发 `VER=0x04` + 7 字节头后，无 NUL 地灌数据。无需任何凭据 | **内存无界**：单连接在 60s 握手窗内可推入 ~82 MB 常驻堆（Vec 倍增后可达 128 MB 容量）；**CPU**：逐字节 1 次 `read → read_exact` 系统调用，10s 实测吃掉 **12.44 CPU 秒**（≈1.2 核/连接），吞吐仅 2 MB/s | **E1**：`round2/scripts/probe_amplify.py` 思路直跑。①10s 窗口单连接：`sent=21.0 MB rate=2.01 MB/s cpu_delta=12.44s rss 65->89 MB`；②持续到 60s 被握手 deadline 掐断时已灌 82 MB：`t=45.94s sent=64MB rss=231MB`；`send fail at 82 MB ... t=60.01s`（服务端关闭）。③4 连接 `\x05` 半包 65s 被关（证明 mixed 路径确实有 60s deadline，问题不在时限而在**上限缺失**）。日志：`round2/tmp/run_multi.log` | Go `proxy/socks/protocol.go:288-306 ReadUntilNull`：`buf.StackNew()`（`common/buf/buffer.go:13 Size=8192`）+ `if b.IsFull() { return "", errors.New("buffer overrun") }` → **8 KB 硬顶**；且上游读全部经 `bufio`（Go `handshake4` 拿到的 reader 是 8 KB 缓冲）。Rust 两处都退化 | 给 `read_until_null` 加 `MAX_SOCKS4_FIELD = 8*1024`（对齐 Go 的 `buffer overrun`，超限即 `HandshakeFailed`），并把 1 字节 `read_exact` 换成自建 4 KB 缓冲读；4a 域名复用同一函数即同时修复 |
| F2 | xdns finalmask 服务端分片分支**长度门 off-by-two** → 远程 panic，且 panic 后**整个隧道永久失聪**（不自动恢复） | High（配置门控：需配 `streamSettings.finalmask.udp=[xdns]`） | `crates/xray-transport/src/finalmask/xdns/server.rs:244-248`（长度门 `flag8 == 3 && n < 9+3+1`，即 n<13）＋ panic 点 `:269`（`decoded[13]`/`decoded[14]`/`decoded[15..n]`） | 匿名：对配了 xdns udp mask 的入站（dokodemo/ss/kcp 等）发 1 个 **53 字节 DNS 查询**。QNAME = base32(13B payload)+`.a.example.com`，payload 里 `[8]=0xC3`（分片标记 + flag3）即触发；**零凭据、单包** | **panic**（`task panicked ... index out of bounds: the len is 13 but the index is 13`）→ recv 任务死亡 → 该 xdns 隧道此后**不再转发任何包**（实测两次重试全超时），只能重启进程恢复 = 永久 DoS | **E1**：`round2/tmp/cfg_xdns.json` + 现成二进制。①panic：`ERROR task panicked ... location=crates\xray-transport\src\finalmask\xdns\server.rs:269 panic=index out of bounds: the len is 13 but the index is 13`（`round2/tmp/run_xdns2.log`）；②A/B 存活：`BEFORE panic (valid packet): forwarded 8 bytes -> 127.0.0.1:55069` → 打畸形包 → `AFTER panic (valid packet): NOT forwarded (TimeoutError)` ×2。13/14 字节两种 payload 均可（n=14 时 `decoded[14]` 越界） | Go `transport/internet/finalmask/xdns/server.go:169-220`：`var decoded [255]byte` 定长数组 + 同一条 `n < 9+3+1` 检查 → `decoded[13]/[14]` 读得到 0 不 panic；但 `decoded[15:n]` 在 n∈{13,14} 时 **low>high 同样会 panic** —— **上游同缺陷**，两侧需一起修 | 把长度门改成 `flag8 == 3 && n < 9 + 3 + 3`（分片固定头 3 字节，最小 n=15），Rust 侧先 fail-closed（回 `ok_header` 空响应，不与 Go 的 panic 对齐）；同条上游缺陷另外报给 Xray-core |
| F3 | HTTP 请求头解析**逐字节无缓冲读**（`reader.read(&mut byte)`）→ 未认证 CPU 放大 ≈ 1 CPU 秒 / MiB | Medium | `crates/xray-proxy-http/src/server.rs:1133-1157`（`read_http_line`），调用点 `:990 read_request_head`、`:438`（`REQUEST_HEADER_TIMEOUT` 只限时**不限 CPU**） | 匿名：任何 http / socks / mixed 入站的 HTTP 分支，一条连接写满 `MAX_HTTP_HEAD_BYTES = 1 MiB` 的单行头（`CONNECT AAAA…:443`）即可 | **CPU**：每字节 1 次 `read` 系统调用；1 MiB 头 ≈ **0.89–1.07 CPU 秒**，20 并发 ≈ 21.5 CPU 秒 + 31 MB 常驻 RSS（回收不回）；攻击者 10 MB/s（80 Mbps）即可钉死 ~10 核。**注意**：60s deadline 只限流速率，不限制总量 CPU | **E1**：线性标定 `round2/scripts/probe_amplify.py http-head`：`64K→0.09s, 128K→0.16s, 256K→0.28s, 512K→0.67s, 1M→0.89s`（≈0.85 µs/byte）；并发 `n=1/5/20` → `cpu 6.52→11.17→32.70s`，`rss 49→55→86 MB`（关连接后不回落）。日志 `round2/tmp/run_multi.log` | Go `proxy/http/server.go:102-110`：`bufio.NewReaderSize(conn, buf.Size=8192)` + `http.ReadRequest` → 每 8 KB 一次系统调用（1 MiB ≈ 128 次），CPU 量级 ~1 ms，**约 1000× 便宜**；且 Go 侧对本仓 1 MiB 预算不做上限（只贵不炸） | `read_request_head` 外面套一层 `BufReader`（或把 `read_http_line` 改成 4 KB 块读 + 行切分），保持 1 MiB 预算与错误语义不变；同源 1 字节读的清单一并核对（见 F4） |
| F4 | 其余「逐字节读」站点大盘点（同类但有界 → 仅登记，非漏洞） | Info | `crates/xray-core/src/inbound.rs:1236-1250`（chunked 请求体行读，`MAX_LINE_BYTES=16K`）、`crates/xray-app-geodata/src/downloader.rs:403-412`（拉取 geodata 响应头，远端可拖）、`crates/xray-transport/src/proxy_protocol.rs:88-106`（v1 行，`MAX_V1_HEADER_SIZE=107`）、`crates/xray-proxy-socks/src/server.rs:441`（同 F1） | —— | 有界 → CPU 上限可算（16K/107 字节），不构成独立放大；但 F3 修完之后这些点仍是白送的 CPU 成本 | **E2**（源码定位）+ F1/F3 的实测曲线可外推 | Go 侧全部经 `bufio`/`Reader.ReadString` | 与 F3 一起改成块读；`proxy_protocol` 可保持（107 字节微不足道） |

## 2 复核/证伪记录（诚实留档，防止后续重报）

| 观察 | 结论 |
|---|---|
| 「vless 入站被打到不再 accept（`connect → WinError 10048`）」 | **证伪，非服务端缺陷**：`10048` 出现在**测试脚本侧** `connect()`，且 4/6 次重试立即恢复；根因是脚本 1.2 万条短连接堆在客户端 TIME_WAIT。服务端进程全程存活（RSS 96 MB / 26 线程），其它 6 个入站同时刻正常 |
| 「socks 入站无握手超时」 | **证伪**：`serve_mixed`/`build_socks_inbound` 传 `Some(handshake_timeout)`，实测 `\x05` 半包在 60–65s 被服务端关闭（4/4 连接）。`crates/xray-proxy-socks/src/server.rs` 里那份 `socks_handshake` 裸调用不在生产主路 |
| vless / vmess / ss(legacy, 真 AES-128-GCM 线格式) 变异模糊：**12k + 4k + 12k** 次，含合法 UUID/合法口令派生 key、随机 atyp/domain 长度/命令字/截断 | **零 panic**，入站全程存活。vless 的 `vec![0u8; len_buf[0] as usize]`（≤255）、vmess `ciphertext.resize(total_size)`（u16 ≤64 KB）、trojan `read_addr_port`（域长 ≤255，且**先验 hash 再解地址**）全部有界 → 不重报 |
| REALITY ClientHello 解析（`crates/xray-reality/src/server.rs:100-330`）、PROXY protocol、KCP segment、QUIC/UTP/HTTP/TLS 嗅探器（`xray-app-dispatcher/src/sniffer.rs` 全文） | 逐行核过边界：`off` 越界均有 `body.len() < off + x` 回退、`cipher_suites_len` 越界被下一条 `off+1` 检查接住、`crypto_data[write_start..write_end]` 有 32767 上限门、`read_quic_varint` 只返回 ≤buf.len() 的步长 → **未找到可达 panic 路径**（E2，未构造 E1 证据） |
| anytls 入站（padding0 上限 16 KB-34、认证常数时间比较、TLS/首包双 deadline） | 未找到越界/放大；`bz800`（无口令即零认证）属第一轮已登记，不重报 |

## 3 未覆盖面

- **未实测**：tuic / hysteria / wireguard / tun / kcp 真机（需 TLS/QUIC/虚拟网卡环境）；ws / grpc / httpupgrade / splithttp 传输层帧解析；DNS 入站与 DNS outbound；mux carrier 会话数上限（需先完成 vless 认证再打 65k 个 New 帧）；UDP 侧放大（ss/socks UDP 每个目的地址新建会话，Go 同构，未定级）。
- **未做**：ReDoS（`domainsExcluded` 的 `regexp:` 规则来自本地配置，非远端可控）；HashMap hash 洪泛（未找到远端可控 key 的 `HashMap` 直接暴露面）；路径穿越（资产/geodata 路径来自配置）；同进程权限类攻击（按任务约定排除）。
- **证据等级说明**：F1/F2/F3 = E1（真实二进制 + 真实字节流 + 进程侧 CPU/RSS/panic 观测）；F4 = E2。F2 的 Go 侧「同缺陷」判断为 E2（源码切片语义推导，未跑 Go 二进制复现）。
- **置信度**：F2 最高（确定性 panic，日志直接给出 file:line）；F1/F3 高（数字可复现，但绝对 CPU 数与机器/核数相关）。
- **环境说明（并发审计）**：本轮实测期间 PM 侧另有两路代理在同机跑 xray 实例（Backpressure 跑 splithttp/grpc，ConcurrencyCancel 跑取消面）。F1/F3 的数据是**单实例串行**测的（每次测量前确认只有我的 19101-19107/19201 端口段在跑，`Get-Process xray` 计数与 CPU 差值按进程聚合），因此不受并发干扰；F2 的 panic/失聪判定不依赖 CPU 或吞吐，与并发无关。**清理事故**：收尾时我执行过一次 `Stop-Process -Name xray -Force`（按名广杀），已向 PM 与两路代理广播；确认受影响代理的探针均已结束、无人丢结果。此后清理一律按显式 PID。
- **交叉引用**：splithttp 传输层 `handle_packet_up` 的「先 `body.collect()` 后查 `sc_max_each_post_bytes`」导致单 h2 连接 2000 MB body → RSS 2592 MB 由 **Backpressure** 实测登记，不在本报告重复计票（本轮我未测 splithttp/grpc 传输层）。

## 4 建议修复顺序

1. **F2**（一行门槛 + 一条 fail-closed 断言测试）：唯一的远程 panic + 永久失聪，且是分片包一条 53 字节可达。
2. **F1**（一个 `MAX_SOCKS4_FIELD` + 缓冲读）：匿名内存 DoS，风险面最大（默认 `socks`/`mixed` 入站就吃）。
3. **F3**（套 `BufReader`）：匿名 CPU DoS，改法机械、风险低；顺带把 F4 的清单一起收。
4. F4 剩余站点随 F3 顺手，`proxy_protocol` 可不动。
