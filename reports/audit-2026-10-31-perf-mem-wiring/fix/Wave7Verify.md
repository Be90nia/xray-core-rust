VERDICT: DONE（5/5 判定 FIXED：dp2dm/y5cy9/uwq9n/0snlt/il9lh——其中 il9lh 的 TPROXY 子项为 CODE-ONLY（需 Linux root），其余均有实跑证据；601+5 测试全绿，e2e 含 CPU/内存实测与 Go 字节级对照）

# 复测 5 张「代码已在树但票未关」的票 —— 独立证据（不信任票面/报告，只看代码与实跑）

## 待办清单
- [x] T1 `dp2dm`（代码+回归测试已核，e2e 待二进制）（P1）SOCKS4 USERID 上限与拒绝
- [x] T2 `y5cy9`（代码+测试已核）（P1）HTTP read_http_line fill_buf 块读
- [x] T3 `uwq9n`（代码+既有超时测试已核）（P1）DNS-over-TCP writer 锁跨 await
- [x] T4 `0snlt`（P2）HTTP 入站错误响应方向 vs Go 26.10.17
- [x] T5 `il9lh`（P3）TPROXY fake_cache / ws 池惰性 TTL / ArmScopeRegistry
- [x] 汇总表

---

## T3 `bd uwq9n`（P1）DNS-over-TCP 出站 writer 锁跨 await

**票面原述**：停读客户端可让 DNS 会话永不结束。

**实现定位**（迁移后形态）：
- `crates/xray-app-dns/src/dnscommon.rs:468-563` `tcp_frame::{write,read}`：**每个**写/读段都包
  `deadline.timeout(...)`（`BudgetDeadline`，来自 `Budget::tokio().deadline(query_timeout)`）——
  写 len / 写 payload / flush / 读 len / 读 payload 五段各有独立超时，超时即 `DnsError::WireFormat`
  （"tcp write len timeout" / "tcp read payload timeout" 等）。
- `crates/xray-app-dns/src/nameserver/tcp.rs:186-229` `query_once`：`conn_guard`（tokio Mutex）
  确实跨 try_query 的 await 持有——这是连接池串行化的**刻意形态**；关键变化是等待全程被
  `query_timeout` 预算封顶：对端停读/停写 → 段超时 → Err → 池内连接被置 `None` 丢弃（或重试一次，
  重试同样受同一 `deadline` 封顶，:229 注释 bd 2iauj）→ 锁随 fn 返回释放，**会话必然收场**。
- `udp/tcp_fallback.rs:49-50` 同款 deadline 包裹。

**实测方法与原始输出**（既有 in-tree 测试，均为真实 TCP 对端场景）：
- `tcp_query_timeout_records_error`（tcp.rs:422）：listener 只 accept **永不读/回** → 连接成功但
  read 段等到 timeout → `outcome.rec_v4.is_none()` + `errors.len()==1` ✔（本轮套件内通过）。
- `tcp_total_deadline_covers_slow_response`（tcp.rs:503）：慢响应服务端（头部立回、payload 延迟
  `payload_delay`）→ 断言整条查询在**绝对 deadline** 上以 `"tcp read payload timeout"` 收场，不因
  分段预算重置而延长 ✔（本轮套件内通过）。
- `tcp_deadline_shared_by_both_families`（A/AAAA 共享同一 deadline）✔。

**判定：FIXED**（代码在 + 两个真实 TCP 停读/慢响应场景的 in-tree 测试通过；锁跨 await 仍在但已被
绝对 deadline 封顶，会话必然结束——原票害点消除）。

---

## T1 `bd dp2dm`（P1）SOCKS4 USERID 无上限逐字节读

**实现定位**：`crates/xray-proxy-socks/src/server.rs:441`（`SOCKS4_MAX_FIELD_BYTES: usize = 8192`，
注释引 Go `ReadUntilNull` 的 `buffer overrun` 与 bd dp2dm 实测数字）；`:448-465` `read_until_null`
超限即 `Err("SOCKS4 field exceeds 8192 bytes (buffer overrun)")`——**拒握手，非截断继续**；
USERID 与 SOCKS4a 域名共用同一上限（:409/:414）。

**实测方法与原始输出**：真实 xray 进程（target-Wave7Verify debug，socks 入站 127.0.0.1:16003）
+ python 洪灌（0x04 握手后持续灌非 NUL 字节共 8MiB、无 NUL）：

```
before: CPU=0.109s WS=20.9MB
flood sent=8MiB
recv after flood: closed ConnectionResetError(10054, 远程主机强迫关闭...)   ← 服务端在 8192 上限处主动断链
after:  CPU=0.125s WS=21.7MB
CPU delta = 0.016s  WS delta = +0.7MB      xray still alive: True
```

对照票面修前形态（10s 灌 12.44 CPU 秒、82MB 堆）：8MiB 洪灌只耗 **0.016 CPU 秒**、内存 +0.7MB、
连接被断、进程存活。crate 回归测试 `socks4_userid_without_terminator_rejected_at_cap`
（server.rs:1213，断言错误含 `buffer overrun`）本轮套件内通过。

**判定：FIXED**

---

## T2 `bd y5cy9`（P1）HTTP 请求头逐字节无缓冲读

**实现定位**：`crates/xray-proxy-http/src/server.rs:1188` `read_http_line<R: AsyncBufRead>`——
`fill_buf()` 一次取满 8KB 内部缓冲、块内切行、只 `consume` 到行尾（:1193-1196 + `LineStep`
:1239）；文档明记 bd y5cy9（1MiB 头 = 100 万次 syscall → 块读后 ~128 次）。行后多读字节留在
reader（`consume` 只到行尾）。头总上限 `MAX_HTTP_HEAD_BYTES = 1MiB`（:1178）。

**实测方法与原始输出**（真实 xray http 代理 127.0.0.1:16004，目标指向本地死端口以剥离网络 RTT，
纯服务端头处理计时）：

```
header=128KiB send=0.000s total=0.630s   resp=HTTP/1.1 503 Service Unavailable
header=1024KiB send=0.001s total=0.704s  resp=HTTP/1.1 503 Service Unavailable
header=1024KiB send=0.001s total=0.710s
header=1024KiB send=0.001s total=0.716s
```

8× 数据（128KiB→1MiB）只 +0.08s——斜率符合 8KB 块读（1MiB ≈ 128 次 `fill_buf`），**无**
票面「~1 CPU 秒/MiB」的逐字节放大（0.6s 基座 = freedom 对死端口的拨号收场，与头大小无关）。
crate 内回归测试 `read_http_line_leaves_bytes_after_newline_in_reader`（:1812，断言行后字节留在
reader、body/下一请求/隧道数据不丢）与 `read_http_line_keeps_non_utf8_bytes` 本轮套件内通过。

**判定：FIXED**

---

## T4 `bd 0snlt`（P2）HTTP 入站错误响应与 Go 不一致

**实现定位**：`crates/xray-proxy-http/src/server.rs:111-114`
`RESPONSE_BAD_REQUEST = "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nProxy-Connection: close\r\nContent-Length: 0\r\n\r\n"`
（注释：Go 实测锚点=同一构造路径的 503 头块）；两处使用：解析失败（:568）、
origin-form 无 allowTransparent（:1071，bd 0snlt——**先于 dest 解析**）。

**实测方法与原始输出**（字节级对照：Go 26.10.17 `D:/tmp/go2617/xray.exe` http 入站 :16001 vs
Rust 同配置 :16002，同一组畸形请求原样发送）：

```
[GO]   origin-form-no-transparent: 91B | HTTP/1.1 400 Bad Request |
       HTTP/1.1 400 Bad Request\r\nConnection: close\r\nProxy-Connection: close\r\nContent-Length: 0\r\n\r\n
[RUST] origin-form-no-transparent: 91B | 同上——逐字节一致
[GO]   garbage-line:            0B（无响应，连接关闭）      [RUST] 同
[GO]   bad-version:             91B 同上 400 块            [RUST] 同
[GO]   missing-host-absolute:   200（freedom 真实代到 example.com，928B）[RUST] 同（928B）
```

四种输入两端的响应（状态行、头集合、字节数）完全一致——含 bd 0snlt 点名的
origin-form-无-transparent → 400 场景。

**判定：FIXED**（字节级对照实测）

---

## T5 `bd il9lh`（P3）小内存项批次（三子项）

### 5.1 TPROXY `fake_cache` 无上限

**实现定位**：`crates/xray-core/src/inbound.rs:1967-2049`（bd il9lh MW-3）：`FakeResponderCache`
= `HashMap` + LRU `VecDeque`，**上限 `FAKE_RESPONDER_CACHE_CAP = 256`**；满则逐出最旧条目
（`pop_front` + `map.remove`，socket 随 Arc drop 关闭）；命中搬队尾（LRU touch）。

**实测**：CODE-ONLY——TPROXY 回发路径需要 Linux root + iptables REDIRECT/TPROXY，Windows 无法
构造。逻辑为纯同步 LRU（map+order 双结构一致性肉眼可核），且逐出即关 fd 的行为由 Arc 语义保证。

### 5.2 ws 池惰性 TTL

**实现定位**：`crates/xray-transport-websocket/src/pool.rs`：
- 后台扫除任务（`ensure_sweeper`，:262-297）：周期 = TTL/4 钳 [100ms, 30s]，**扫全部 key**、
  摘过期条目并连带摘空 key（修前唯一回收路径是 `try_acquire(同一 key)`——bd il9lh MW-4）；
- `try_acquire` 惰性扫除 + `probe_conn_alive`（对端已关的连接当场丢弃，:348-350）；
- 默认关池（`max_idle_per_key=0`，对齐 Go 26.10.17 无池，bd s8eio），显式 pool_size>0 才启用。

**实测**：crate 套件内回归测试通过——`idle_entries_reclaimed_without_any_access`（:565，bd il9lh
MW-4 回归锚：全程不访问任何 key，TTL 后条目/键归零 **且对端读到 EOF**（socket 级关闭证据））、
`sweeper_keeps_entries_within_ttl`（不误伤 TTL 内条目）、`reuse_within_ttl_keeps_hit_rate`（TTL 内
命中率 100%）。

**判定：FIXED**

### 5.3 ArmScopeRegistry 只登记不摘

**实现定位**：`crates/xray-frame/src/scope.rs:269-336`：`entries: Mutex<Vec<(String, Arc<ArmScope>)>>`；
同 tag **upsert 单条**（不重复登记）；宿主 `close` 走 `close_all_reverse` **逆序显式 close** 全部
arm scope（幂等）。关键边界：登记集 = **入站 arm 数**（配置有界、实例生命周期），每连接的
`ConnScope` 是 arm scope 的子作用域（watch 级联取消），**不进登记表** ⇒ 不存在随连接数增长的
无界集合。

**实测**：crate 单测 5 项通过（本轮实跑）：`register_same_tag_upserts_single_entry` /
`register_same_scope_twice_keeps_it_open` / `register_distinct_tags_keep_all_entries` /
`concurrent_register_same_tag_keeps_single_entry` / `concurrent_register_and_close_all_no_deadlock`。

**判定：FIXED（按设计有界）**——「只登记不摘」属实但**不是泄漏**：集合大小被入站配置数上界约束、
生命周期 = 实例生命周期、停机有显式逆序 close。原担忧（无界增长）不成立。

---

## 汇总表

| 票号 | 判定 | 关键证据 | 建议 |
|---|---|---|---|
| `dp2dm`（P1） | **FIXED** | server.rs:441/460-465 上限 8192 + `buffer overrun` 拒握手；e2e 实测 8MiB 灌入 CPU +0.016s、WS +0.7MB、RST 断链；回归测试在套件内通过 | **可关** |
| `y5cy9`（P1） | **FIXED** | server.rs:1188 `fill_buf` 块读 + `consume` 到行尾（行后字节留在 reader，:1812 测试）；e2e 实测 1MiB 头处理 0.70-0.72s 且 128KiB→1MiB 斜率 +0.08s（无逐字节放大） | **可关** |
| `uwq9n`（P1） | **FIXED** | dnscommon.rs:517-552 五段读写全部 `deadline.timeout` 包裹；in-tree 测试实证「对端不应答」与「慢响应」均在绝对 deadline 收场并记录错误 | **可关** |
| `0snlt`（P2） | **FIXED** | server.rs:111-114 响应块与 Go 逐字节一致；四场景双端实测对照全一致（91B 400 块/garbage 关连接/200 透传） | **可关** |
| `il9lh`（P3） | **FIXED**（5.1 为 CODE-ONLY） | fake_cache 256+LRU（CODE-ONLY：需 Linux root 实测）；ws 池后台全 key 扫除 + socket 级回收测试；ArmScopeRegistry 有界 + 逆序 close，5 单测过 | **可关**（5.1 可选补一条 Linux e2e） |

---

## 复测环境与口径备注

- 二进制：`target-Wave7Verify/debug/xray.exe`（本轮树构建，git_rev=afb963f94f58 版本串 26.10.11）。
- 套件：`cargo test -p xray-proxy-socks -p xray-proxy-http -p xray-app-dns -p xray-transport-websocket
  --all-targets` = **601 passed / 0 failed / 2 ignored**；另实跑 `cargo test -p xray-frame --lib scope::` =
  5 passed。
- T4 的 Go 对照端 = `D:/tmp/go2617/xray.exe`（26.10.17）；网络型对照（missing-host-absolute 会真实
  出网到 example.com）已标注。
- 测试工件：`D:/tmp/wave7_verify/`（配置/探针脚本/日志）。

（本节完 → 落盘）
