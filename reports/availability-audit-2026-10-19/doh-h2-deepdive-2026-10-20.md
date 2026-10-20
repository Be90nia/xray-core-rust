# DoH h2 深挖报告：4s 无响应根因（2026-10-20）

> 调查：DoHDig（debugger 子代理）。结论一句话：**服务器从未忽略我们——alidns 在 10ms 内正常应答；是 xray 共享拨号器（dispatcher 管线）的下行方向把每个响应批次压到调用方自己的 `query_timeout`（缺省 4000ms）到期才交付，DoH 各阶段 4s 超时先到，把已到手的应答当超时丢弃。**

## VERDICT

根因定位完成（行为级铁证 + 组件级二分）。修复 = 消除 dispatcher 内部拨号管线下行的唤醒丢失（精确到行的 micro-race 定位见 §5 建议开 bd 专项）；短期可令 DoH/DoT/TCP-DNS 绕过共享拨号器（`+local` 语义直连）立即恢复。

## 1. 症状与口供复核

- 复现：`target/debug/xray.exe run -c <config>`（socks 10991 → 触发 DoH 查询），日志形态：`tls established(alpn=h2) → h2 handshake done → h2 ready → request built → send_request ok → body sent → response TIMEOUT (4000ms)`。100% 复现（alidns；cloudflare 在本机网络路径本身被 RST，事实不可靠，见 §3.4）。
- 口供修正两条：
  1. 「服务器完全不回」不成立——包级中继实测服务器 **10ms** 应答（§3.2）。
  2. 「DoT 真机正常（缓存命中 0.39s）」未测新鲜上游查询——TCP-DNS/DoT/DoH 全部中招同一停顿（§3.5/§3.6），DoT 新鲜查询同样会被 4s 阶段超时杀死。

## 2. 排除清单（全部实测）

| 假设 | 实验 | 结果 |
|---|---|---|
| DNS wire payload 非法 | python 手工 wire 复刻 | 服务器 200 + 正常应答，排除 |
| 头集合/伪头问题（无 content-length 等） | python h2 逐头复刻 | alidns 200 应答，排除 |
| 服务器严格度（mock 过真实不过） | python 同语义请求 | 真实服务器正常应答，排除 |
| 陈旧二进制（authority 修复未生效） | exe 内嵌字符串 + 埋点日志 | 二进制含全部新埋点，排除 |
| TLS/拨号层 | DoT/同源 rustls 路径 | 症状与 TLS 无关（TCP-DNS 同病），排除 |
| 服务器/网络慢 | wire 级中继计时（§3.2） | 服务器全程 10ms 应答，排除 |
| 上行方向 | 中继计时 | 上行每批瞬时，排除 |
| 独立 bug：h2c 路径 URI 构造 | E2 | 另案（§6.3） |

## 3. 证据链（全部真实运行）

### 3.1 E1：python h2 复刻（基线）
同伪头（:method POST / :scheme https / :authority / :path / content-type，**无 content-length、无 accept**）直连 dns.alidns.com:443 → **200 + 72B DNS 应答**。头集合与 payload 无罪。
（附带：cloudflare-dns.com TLS 握手即被 RST——本机到 1.1.1.1 路径劣化，CF 侧"静默"事实不可靠。）

### 3.2 E7：socks 出站中继（wire 级实锤，逐字节双向计时）
把 direct 出站换成本机 python socks5 中继（10992），xray DoH 的 TLS 在隧道内端到端，中继逐批打时间戳：

```
+0.000  trigger
+1.146  C>S 250B    ClientHello 出 xray（上行瞬时）
+1.156  S>C 2742B   服务器 10ms 应答 ServerHello+cert，中继推回
+5.143  C>S 110B    ← xray 才写出第二飞（恰好 +3.997s）
+5.143  C>S 120B    h2 preface+SETTINGS+HEADERS+DATA（上行瞬时）
+5.153  S>C 96/31/349B  DNS 应答 10ms 返回、推回
+9.156  C>S 44B     resp 超时后的收尾批
```

→ **下行每批被压 4s 才被 DoH 任务处理；上行永不卡；服务器 10ms 应答。**

### 3.3 E5：RUST_LOG=trace（进程内佐证）
`timeout(4s, resp_future)` 到期后 1ms，h2 driver 才 `read.bytes=39`（响应字节首次被读）——应答早已躺在 pipe 里，读端死等。同 run：`ClientHello 发出 → ServerHello 读到 = +4.012s`；`body sent → resp TIMEOUT = +4.006s`，且 timeout 后 1ms 响应即涌出（39B/224B/81B）。

### 3.4 停顿时长 = 调用方自身超时（机制判决）
TCP-DNS（无 TLS、无 h2）走同一管线：

| 配置 | 应答到达→被处理延迟 | 全程 |
|---|---|---|
| timeoutMs=4000（缺省） | **4.006s** | HTTP 8.44s |
| timeoutMs=15000 | **15.010s** | HTTP 30.42s |
| `tcp+local://`（直连，绕管线） | 亚秒 | HTTP 0.44s |

→ 停顿时长**精确等于调用方 per-stage 超时**：pipe 数据到达的唤醒完全丢失，**唯一推进读端的定时器就是调用方自己的 `timeout(query_timeout, …)`**。tokio `Timeout::poll` 先 poll inner 再查 deadline，故握手阶段在 deadline 轮询中"意外成功"（表现为 handshake 恰迟 4s 但无错误），而 resp 阶段 inner 依赖独立 spawn 的 h2 driver（同样死等）→ 超时错误照常抛出。

### 3.5 E6/E8：管线组件二分
- TCP-DNS 查询经 dispatcher→DialBridge→freedom→bridge：**查询上行 0.9ms 到达**（管线转发机器完好）。
- `https+local://223.6.6.6`（同一套 DoH 代码，仅流来源换直连 TcpStream）：**TLS 18ms、整查询 48ms、零停顿**。
→ 病灶唯一收敛于：**共享拨号器管线的下行（raw→pipe→调用方读端）唤醒丢失**。涉案组件：`xray-buf` pipe（`CountingNotify`/`Reader::read_multi_buffer` 的 select 唤醒）+ `LinkStream::poll_read`（每 poll 新建 future）+ 各出站泵的 raw 读包装。逐组件静态审查未定位到确切竞态行（§5 建议）。

### 3.6 影响面
共享拨号器（`xray-app-dns::dial::shared_dialer`）由装配层注入（functions.rs DispatcherDnsDialer）——**所有经它拨号的 DNS 出站形态全部中招**：DoH(h2c/https)、DoT、TCP-DNS。UDP-DNS/DoQ 不走该链（待确认）。普通代理流量（socks/http 入站 → 出站）的 Link 与此不同源（E2 中 socks 直发 HTTP 仍慢但可用），受影响程度待专项评估。

### 3.7 插桩反常（bd 专项首要线索）
在 `xray-buf/src/pipe.rs` 的 `Writer::write_multi_buffer`（Done 分支）与 `Reader::read_multi_buffer`（park/woke/EOF）插入 `pipeprobe` 临时埋点并重编后，复现 15s 停顿全程 **pipeprobe 零输出**（同 log 内其它 DEBUG 行正常）——而数据确实流经 dispatch_with_access 创建的 pipe（E8/E9 应答处理延迟精确跟随 timeoutMs）。两个互斥事实：
1. 源码层面：`dispatch_with_access`（default.rs:1017-1018）创建 `xray_buf::pipe` 两对，LinkStream 直接包其 reader/writer，trait impl 委托固有方法（probe 在委托目标上）；
2. 运行层面：probe 路径零执行 + 数据照常流动。
⟹ 运行时 DNS 拨号链路的实际 reader/writer **不是** dispatch_with_access 源码所示的 pipe 端点（装配/类型换绑或分支分歧），或存在第二条建链路径。**这是定位精确竞态行的最短线索**：micro-harness 前先追 `DispatcherDnsDialer` 实际拿到的 `Box<dyn MbReader/MbWriter>` 具体类型（可 `Box::as_any`-式打点或 temporarily log `std::ptr::from_ref`）。插桩已回滚（git checkout pipe.rs），干净二进制已重编。

## 4. 根因陈述（帧级）

**服务器端**：收到我们的 h2 请求（HEADERS[END_HEADERS] + DATA[END_STREAM]，:method POST、:authority 齐全、content-type: application/dns-message、29B 合法 DNS wire）后 **10ms 内 200 + DNS 应答**——服务端无任何问题。

**xray 端**：`xray-app-dns` 经共享拨号器（dispatcher pipes）拨出的流，其**下行数据到达唤醒丢失**：响应批次写入 downlink pipe 后读端不被唤醒，唯有调用方各阶段的 `timeout(query_timeout, …)` 定时器（tokio Timeout 先 poll inner）在到期轮询时才顺带消费数据。DoH 时序被强行拉成：

```
TLS 握手第二飞：+4.0s（tls 阶段 deadline 轮询顺带完成，侥幸无错）
h2 请求发出：   握手完成后瞬时
DNS 应答处理：  body_sent + 4.006s = resp deadline → 先判 Elapsed，应答被弃
```

## 5. 修复建议

**P0（立即止血，最小 diff）**：DoH/DoT/TCP-DNS 的 `connect_stream` 绕过共享拨号器（等价 `force_local` 语义：直连 + 每查询现解析）。代价：DNS 查询暂不可经代理路由（域名 NS + 非 AsIs 策略退化为直连）；换来全部 DNS 形态立即可用。改动点：`crates/xray-app-dns/src/dial.rs connect_stream`（一行分支反转或配置开关）。

**P1（根因修复，需 bd 专项）**：定位并修复 dispatcher 内部拨号管线下行唤醒丢失。建议 micro-harness：两 tokio task + `xray_buf::pipe::new_with_option(idle_timeout=300s)` + 一写一读，压测唤醒延迟即可复现（无需整仓）；嫌疑排序：
1. `Reader::read_multi_buffer` 的 `select!` 每轮重建 + `CountingNotify::wait()` 的 `swap` 副作用被 select 取消分支吞掉（count 已清、notify permit 已耗、数据未取的经典丢失窗口）；
2. `LinkStream::poll_read` 每 poll 丢弃重建 future 导致的 waker 换绑窗口；
3. dispatch 下行 writer 侧包装（stats/CachedReader 链）的 pass-through poll 语义。
修好后 P0 止血开关回滚。

**P2（顺带修复，本调查发现的独立 bug）**：
1. `from_config_h2c`（doh.rs:163）传 `String::new()` 当 server_name → query_once 构造 `https:///dns-query` 非法 URI → `body(())` Err → **无日志 `?` 静默早退** → 上层吞成 `record not found`。h2c 形态完全不可用且报错误导排查。修：server_name 用 dest address；顺手给 build 失败路径补日志。
2. cached.rs 将上游任何错误统一吞成 `RecordNotFound`（`fetch` → server.rs 串行查询日志只见 "record not found"）——本次排查的最大噪声源。建议保留原始错误透传到 serial 日志。

## 6. 验证方法（修复后）

1. `python D:/tmp/dohdig/e7_socks_relay.py` —— DoH 全程 < 1s、无 `response TIMEOUT`；
2. E8 同款 TCP-DNS 计时 —— 应答处理 < 100ms；
3. `https+local` 直连基线（已证明健康）：48ms 不回归；
4. DoT 新鲜查询（非缓存）首次可用。

## 7. 临时产物清单（D:/tmp/dohdig/，可全删）

e1_h2_replica.py / e2_h2c_dump_server.py / e2_run.py / e3_run.py / e5_run.py / e6_pipeline_probe.py / e7_socks_relay.py / *.json / *.log。**pipe.rs 临时插桩已回滚（git checkout），干净 debug 二进制已重编（本会话内完成），无残留。**
