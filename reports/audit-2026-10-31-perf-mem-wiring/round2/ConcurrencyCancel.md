# 并发 / 故障时序审计（第二轮 · 从外往里看：攻击者、故障、慢对端）

- 仓库 `D:/Project/Xray-core-rust`，分支 `feature/fix-inbound-parity`，HEAD `5fe98b90`
- 被测二进制 `target/release/xray.exe`（`version` 输出 `git_rev=5fe98b907c7b550d4a70202abb475e26ee89013d` = HEAD，`26.10.11`）
- 口径：生产主路 = 默认 `xray.exe run -c`（`xray_conf::Config::build()` → `xray_core::start_full`）
- 只读审计，零产品代码改动；脚本保存在 `round2/scripts/`
- 不与第一轮 18 条重叠（本条系列全部是「阻塞/取消/超时/账本」面，不是接线/分配面）

## 0 一句话结论

**入站握手和 DNS 全链都有 deadline，但数据面的「写」这一半完全没有 deadline，而且没有任何取消闸能打断一个卡在写里的 future**：
Go 用 `signal.CancelAfterInactivity → ctx cancel → task.Run 早退 → common.Interrupt(link)` 把阻塞的写打断；
Rust 侧超时只包住 `read_*`，写臂裸 `write_all`/`write_multi_buffer`，收尾用的是 `tokio::join!`（等全部四腿）——
于是「对端不读」这一个故障态就让 `connIdle` / `uplinkOnly` / `downlinkOnly` 三个 policy 全部静默失效，
连接、outbound socket、4 个任务被钉死（E1：客户端断开 3s 后 xray 仍持有该 socket `ESTABLISHED`）。

## 1 发现总表（8 列）

| # | 标题 | 严重度 | 位置 file:line | 触发输入/条件 | 后果 | 证据 | Go 侧对照 | 建议 |
|---|---|---|---|---|---|---|---|---|
| C1 | 桥接写臂无 deadline + `join!` 等四腿 → 全部连接级超时在对端停读时失效 | blocker | `crates/xray-transport/src/bridge.rs:415`（up 读 timeout）、`:452`（up_writer `write_all_mb` 无 timeout）、`:471`（down 读 timeout）、`:509`（down_writer `write_multi_buffer` 无 timeout）、`:547`（`tokio::join!` 四腿） | 客户端零窗口不读（下载塞满）；或对端不读（上传塞满） | 连接与 outbound socket 永不释放；客户端断开后 xray 仍钉住 socket + 4 任务 + 最多 512KiB 通道缓冲 | **E1**（两个独立 harness，见 §2.1/§2.2） | Go `task.Run`（`common/task/task.go:51` `case <-ctx.Done(): return ctx.Err()`）+ `common.Interrupt(link.Reader/Writer)`（`proxy/freedom/freedom.go:233-234`、`proxy/shadowsocks/server.go:287-288`）打断阻塞写 | 写臂包 `select!{ w = write; _ = cancel.cancelled() => break }`（或 `timeout(conn_idle)`），收尾改成「任一臂超时/结束即广播 cancel」，不要 `join!` 全等 |
| C2 | DNS-over-TCP 出站：`writer` 锁跨 `write_multi_buffer().await`，两 loop 互等同锁 | 建议(高) | `crates/xray-core/src/outbound.rs:1836`（response_loop 持锁写客户端）、`:1933`（request_loop 写客户端）、`:1920`（收尾 `writer.lock().await.shutdown()`） | DNS over TCP 客户端停止读取响应（应用挂起/零窗口） | response_loop 卡在写并持锁 → request_loop 下一次写先卡在锁 → 两 loop 的 `timeout(idle, read)` 都不再被 poll → DNS 会话永不结束（2 socket + 2 task + 上游 write_slot） | E2（静态；未构造 DNS-over-TCP 挂起客户端） | 同 C1：Go `proxy/dns/dns.go:226` `CancelAfterInactivity` → cancel → `task.Run` 早退 → conn 关闭 | 写客户端也用同一取消令牌包 `select!`，或把 `writer` 锁换成「锁内只做 poll 出队、锁外写」 |
| C3 | wireguard outbound UDP：`send` 持 `writer` 锁跨拨号 + 跨 `write_all`，堵死 read_loop 的重拨判据 | 建议 | `crates/xray-proxy-wireguard/src/driver.rs:144`（`let mut guard = self.writer.lock().await`）、`:146`（持锁 `connect().await`）、`:152`（持锁 `write_all(&frame).await`）、`:201-202`/`:208`（read_loop 收尾 `*self.writer.lock().await = None`） | 对端停止读取（隧道写塞满） | 该目的地址后续全部 UDP 报文排在锁后；read_loop 的「读错 → 清 writer → 下次 send 重拨」被同一把锁挡住 → 往死连接继续写、重拨永不触发；双份账本（reader 判死 vs sender 判死）互相阻塞 | E2 | Go `proxy/wireguard/client.go:230` `CancelAfterInactivity`；`bind.go` 的 readQueue 与写并发无共享可变槽 | 不要在锁内 await：`Option<WriteHalf>` 取出→锁外写→写错再回锁置 None；写加 deadline |
| C4 | `start_inbound` / `remove_inbound` 竞态：可返回成功而实际不监听；重复 tag 错误文案误报容量 | 建议 | `crates/xray-core/src/inbound.rs:3136`（`start_inbound`）、`:3140`（`contains`）、`:3153`（`insert` 失败即报 `inbound registry full`，重复 tag 亦命中）、`:3176`（`remove_inbound` 只 `cancel` 不等待） | gRPC `AddInbound` 与 `RemoveInbound` 并发（同一 tag） | start 在 insert 后 await 期间被 remove 取消 → 仍返回 `Ok(Some(handle))`（API 报成功、实际已停）；`contains()`→`insert()` 之间被抢占 → 重复 tag 报成 "inbound registry full"（误导排障） | E2 | Go `app/proxyman/inbound/inbound.go:39`/`:73` Add/Remove 全程持 `m.access.Lock()`，重复 tag 报 `existing tag found`，Remove 在锁内 `handler.Close()` 同步关监听 | 同一把锁内完成 insert+spawn 登记，或 insert 时带状态位（Starting/Listening）并让 start 在取消时返回 `Err` |
| C5 | `XUDP::interrupt()` 只 `flush()` 不 `shutdown()`，与自身文档和 `Session::close` 不一致（**需确认是否有意**） | 吹毛（待确认） | `crates/xray-mux/src/session.rs:422-436`（`reader.interrupt()` + `writer.flush()`）对照 `:304`/`:308`（`Session::close` 用 `writer.shutdown()`） | XUDP 会话 Expiring 60s 回收（无人重发该 GlobalID） | 上游写半部收不到 EOF；若上游 pump 只靠 `link.writer` 的关闭传播退出，则依赖 drop 传播——而 `xray-app-dispatcher/src/default.rs:1940-1941` 注释明说「pipe Writer 的 drop 不传播 close，对端 reader 会永远挂在 wait_close」 | E2（静态对照；未做上游 pump 依赖分析，故不定级为缺陷） | Go `XUDP.Interrupt()` = `common.Interrupt(x.Mux.input)` + `common.Close(x.Mux.output)`（`common/mux/session.go:227-230`） | 请作者确认：Expiring 回收是否只需中断读；若需要关输出，改用 `writer.shutdown()` 与 `Session::close` 同款 |

## 2 E1 证据（一手实测，release 二进制 + Python 客户端）

公共环境：`policy.levels["0"].connIdle = 2`（配置键 `connIdle`，`xray-conf/app_config.rs` `PolicyLevel` camelCase），
`inbounds=[socks 127.0.0.1:2108x]`、`outbounds=[freedom]`；`connIdle` 经
`xray-core/src/outbound.rs:413`（`wrap_bridge` → `bridge.with_policy(policy_for_level(pm,0).timeout)`）注入桥。

### 2.1 下载方向停读（`round2/scripts/e1_bridge_stall.py`）

```
[control] resume bytes=67108864 eof=True in 1.47s flood_sent=67108864 err=None done=True
------------------------------------------------------------
[stall] client tcp 12505 state at t=+6s (connIdle=2s): [('127.0.0.1:12505', '127.0.0.1:21080', 'ESTABLISHED')]
[stall] flood sent=9043968 err=None done=False
[stall] resume bytes=67108864 eof=True in 1.38s flood_sent=67108864 err=None done=True
[stall] upstream advanced 58064896 bytes after resume
VERDICT: LEAK — connIdle 未关闭连接（写侧阻塞，桥 join! 等四腿）
```

读法：control 组（持续读）64MB 全程跑通 = harness 本身没问题；stall 组客户端静默 6s（connIdle=2s），
① t=+6s 连接仍 `ESTABLISHED`（xray 没关）；② 上游 flood 卡在 9,043,968 B（窗口塞满、无错误）；
③ 客户端恢复读取后又收到 58MB —— 整条连接**从未**被 connIdle 拆掉。

### 2.2 上传方向停读（`round2/scripts/e1_upload_stall.py`，按 xray PID 查 socket）

```
uploaded=9977856 bytes (budget=8388608) accepted=True
xray pid=19828 sockets->21083 at t=+4s: [('127.0.0.1:4642', '127.0.0.1:21083', 'ESTABLISHED')]
recv -> 0 bytes, closed=True
xray sockets->21083 after client close (+3s): [('127.0.0.1:4642', '127.0.0.1:21083', 'ESTABLISHED')]
VERDICT: LEAK — 客户端可见 EOF 但 xray 仍钉着 outbound socket（up_writer 阻塞在写、join! 不返回）
```

读法：对端 `accept` 后永不 `read`（黑洞），客户端持续上传把窗口写死。
此时 **down_reader 的 `timeout(conn_idle,…)` 确实按期触发**（客户端能看到 EOF —— down_writer 已 shutdown 客户端写半部），
但 `up_writer` 仍阻塞在 `write_all` 上，`join!` 不返回 → **outbound socket 在客户端彻底断开 3s 后仍是 `ESTABLISHED`**。
这一条把「超时没触发」和「超时触发了却拆不掉」区分开，直接指向 `join!` + 无写 deadline 的组合根因。

## 3 五面覆盖说明（查了什么 / 没查出什么）

1. **持锁跨 await**：全仓 221 处 tokio 锁位点、61 处「guard 后仍 await」候选逐个手核（大量为测试与伪阳性）。
   实害 3 处 = C2（writer 锁跨写客户端）、C3（writer 锁跨拨号+写）、以及 `xray-transport-hysteria/src/conn.rs:892`
   （`run_inner.lock().await.close_all().await`，管理锁跨 session 收尾 await —— 收尾期 feed 停摆，无死锁面，**未单独立项**）。
   **锁序颠倒**：唯一双向候选是 mux `xudp → inner`（`session.rs:293` → `:324`）；未找到 `inner → xudp` 的反向路径
   （`SessionManager::close` 的 `inner.write` 块先 drop 再调 `session.close()`），**无可同时到达的环**。
2. **取消安全**：C1（写臂不可取消）；`select!` 丢 future 的两处已核为安全——
   `xray-mux/src/worker.rs:541`（`read_exact_slice` 非 cancel-safe，但另一臂是「整条 carrier 终止」，丢弃即终止）、
   `xray-transport-splithttp/src/upload_queue.rs:228-260`（`try_recv`+`Notify`，无丢唤醒；`close()` 先 drain 再置 `pushed=None`）。
   C5 是「回收路径是否少了一次 shutdown」的待确认项。
3. **超时覆盖**：入站握手 deadline 齐全（抽查 vless `server.rs:75` / vmess `server.rs:154` / trojan `server.rs:163` /
   http `server.rs:94` / mixed `inbound.rs:592` / anytls `server.rs:54` / ws `server.rs:256`(4s) /
   httpupgrade `server.rs:67`(4s)；`handshake_timeout_for` 兜底 60s）；DNS 全链（udp/dot/doh/tcp fallback + cached 双保险）逐段有 deadline。
   **缺口集中在数据面写臂**：C1/C2/C3。
4. **原子/可见性**：mux `size`/`count`/`closed_flag` 全 `Acquire`/`Release`/`AcqRel`（`session.rs:505-620`），
   未发现用 `Relaxed` 看守内存因果的站点；`INBOUND_SPLICE`（`default.rs:1758`）是 **`tokio::task_local!`** 而非
   `thread_local!`（跨线程迁移安全，符合 CLAUDE.md §3.5.5 ADR-2），**无问题**。
5. **双份账本**：C3（reader/sender 双判死）、C4（slots 表 vs listener 生命周期）；
   mux `size: AtomicUsize` + `inner.sessions` + `count: AtomicU16` 三处口径逐路径核过（allocate/add/remove/close/
   close_if_no_session_and_idle），未发现漂移。

## 4 未覆盖范围

- 未做 Linux 专属面（splice 快路径 `bridge_link_with_stream_downlink_splice` 的取消语义、TPROXY、tun/wg 数据面）——
  Windows 上平台闸门恒 false，不可达。
- 未构造 mux carrier（vless+ws+mux）的并发压测，故 `xray-mux` 的会话输出泵/SharedWriter 只做了静态核。
- gRPC / naive / tuic / hysteria 入站的握手与写超时未逐文件核（C2/C3 之外的协议未取样）。
- C2/C3/C4/C5 为 E2（源码推导），未升级 E1；C1 的两条 E1 只覆盖 freedom 出站的 socks 入站主路。

## 5 修复优先级

1. **C1**（blocker）：一条修法覆盖 connIdle/uplinkOnly/downlinkOnly 三个 policy + DNS/ wireguard 同族站点——
   给桥的每个臂加取消闸（写臂 `select!` + 广播 cancel），收尾从 `join!` 改为「任一臂结束即取消其余」。
   验证门必须含：两个 E1 脚本复跑（期望 stall 组在 connIdle 后 `CLOSE_WAIT`/无 ESTABLISHED）、workspace 全量 + 32/32 + loopback 吞吐 <5% 波动。
2. **C2 / C3**：同族（写臂 deadline + 锁内不 await），各自 crate 内可独立修。
3. **C4**：API 面假成功，随 gRPC 面一起修（需用户裁决是否值得动 InboundRuntime 结构）。
4. **C5**：先找作者确认意图，再决定改不改。
