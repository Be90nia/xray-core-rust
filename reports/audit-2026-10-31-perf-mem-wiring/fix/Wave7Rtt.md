VERDICT: DONE（探针删除 + 因果取证闭环；矩阵 30/30 零退化；附带闭案 s42cg §5.1）

# lf51l：删掉 splithttp 的 RTT 探针（阶梯已随 Wave5Rtt 删除，探针零消费且每会话多一条可指纹化 TCP）

## 待办清单
- [x] 探针调用链取证（grep 全链 + 读侧消费者核查）
- [ ] Go 26.10.17 侧对应行为核对（源码引用）
- [ ] 删除清单落地（flow_window / client / dialer / register / transport + 测试调用点）
- [ ] accept 数前后对比（TCP 转发器/计数锚）+ 反证（加回探针 → accept 变多）
- [x] 矩阵 30/30 + 三门禁（test / clippy / fmt）
- [ ] 残余风险 + VERDICT 定稿

## 1. 探针调用链取证

调用链（grep `resolve_rtt|rtt_hint|probe_rtt|client_windows_from_rtt` 全 crate）：

```
register.rs dial_splithttp（h2/明文分支，:321-322）
  └─ flow_window::resolve_rtt(host, port)          ← 每次拨号都执行（在 xmux 池查找之前）
       └─ rtt_hint_env() 未设置 → probe_rtt(host, port)
            └─ tokio TcpStream::connect + 1s 超时计时，然后**立即丢弃**这条连接
  rtt_hint → DefaultDialerClient::new(..., rtt_hint)   (client.rs:452)
  └─ flow_window::client_windows_from_rtt(rtt)
       └─ windows_for("client", CLIENT_FALLBACK, rtt)
            └─ rtt **只进 hot_log! 定窗日志**；窗组恒 = CLIENT_FALLBACK（32MB/32MB/16MB）
```

**读侧为空的证据**：
- `flow_window.rs:75-77`：`client_windows_from_rtt` 文档原话「恒 = `CLIENT_FALLBACK`；`rtt` 只进日志，不参与定窗」。
- `flow_window.rs:89-93`：`windows_for` 实现体 `let mut w = fallback; apply_env_overrides(&mut w);`——`rtt` 从未参与窗值计算，只进 `hot_log!` 一行。
- `client.rs:398-401` / `register.rs:312-314` / `dialer.rs:774-775` 注释均自认「**只进定窗日志**，不参与定窗；RTT 阶梯已撤」。
- 全 crate 无第二消费者（grep 无其他读取点）。

结论：探针结果的唯一去向是**一行 DEBUG 日志**；而 `resolve_rtt` 在 `register.rs` 的调用点位于
xmux 池查找**之前**——即使 HTTP 客户端被池化复用，**每条代理连接仍会新拨一条一次性 TCP**（bd
vkirx① 抓包实证：stream-one 每会话多 1 条零字节 TCP，Rust 2 条 vs Go 1 条）。零收益 + 可指纹化，符合删除条件。

**非目标的两个"rtt"**（不产生额外 TCP，一并处理但性质不同）：
- REALITY 路径 `register.rs:249-262`：`rtt_hint = Some(dial_started.elapsed())` 是对**真实** TCP
  connect 的计时（无额外连接），同样只喂日志；
- 服务端 `transport.rs:426`：`rtt_hint` = 真实连接的 TLS accept 耗时（无额外连接），同样只喂日志。

---

## 2. Go 26.10.17 侧对应行为（源码核对 @ 92ccc939）

`transport/internet/splithttp/dialer.go`：

1. **无 RTT 探针**。全文件 grep `rtt|probe|WindowSize` 零命中（仅有的 "window" 是 h3 的 QUIC
   `quicConfig.{Initial,Max}Stream/ConnectionReceiveWindow`，来自用户 `QuicParams`）；`Dial()` 直接
   `getHTTPClient` + `dialContext` 建真实连接，**没有任何"先拨一条测 RTT 再丢弃"的动作**。
2. **h2 分支不配置任何窗**（`dialer.go` `httpVersion == "2"` 分支）：

   ```go
   transport = &http2.Transport{
       DialTLSContext: ..., IdleConnTimeout: net.ConnIdleTimeout, ReadIdleTimeout: keepAlivePeriod,
   }
   ```

   即 Go 的 splithttp h2 流控窗 = **x/net/http2 库默认值**（库默认，非按 RTT 定制）。

**删除是否造成"退化"？** 不会：Rust 侧窗组**恒为** `CLIENT_FALLBACK`（32MB/32MB/16MB，bd wz2b C2 /
bd c9oc F-A 静态保底），探针结果从未参与过任何窗值——删除前后窗值逐字节一致，只是少一条一次性 TCP
与一行 DEBUG 日志。Rust 的静态窗与 Go 的库默认不同——那是 bd wz2b/c9oc 的既有拍板（本票不动）；
本票删的是"代码里还留着、但已无人消费"的探测动作，让代码与 Wave5Rtt 已拍板的行为对齐，且与 Go
的"无探针"行为一致。

---

## 3. 删除清单

| 文件 | 删除/修改 |
|---|---|
| `src/flow_window.rs` | 删 `probe_rtt`（一次性 TCP 探针本体）、`resolve_rtt`、`pick_rtt`、`parse_rtt_hint`、`rtt_hint_env`、`ENV_RTT_HINT_MS`；`windows_for(role, fallback, rtt)` → `windows_for(role, fallback)`（日志行去掉 `rtt_ms=` 字段）；`client_windows_from_rtt`/`server_windows_from_rtt` 更名 `client_windows()`/`server_windows()`；测试删 4 个 RTT 相关用例（hint 解析、hint 优先级、`send_buf_is_rtt_independent`、`flow_windows_do_not_follow_rtt`——其防回档职责由「签名上已无 rtt 参数」+ 两个 fallback 相等断言接管）；删 `probe_rtt_*` 两个 tokio 测试。331 行 → 187 行 |
| `src/register.rs` | 删 h2 路径的 `resolve_rtt(...)` 调用（xmux 池查找前，每拨号一条额外 TCP 的来源）及其 bd rjzw2/vkirx① 注释（改为已清说明）；REALITY 路径删 `dial_started`/`rtt_hint` 计时（它只为喂日志）；两处 `DefaultDialerClient::new` / `dial_reality_stream_one` 调用点同步 |
| `src/client.rs` | `DefaultDialerClient::new` 去 `rtt_hint` 参数；定窗改 `flow_window::client_windows()`；`h2_windows_do_not_follow_rtt` → `h2_windows_are_static_fallback`（阶梯若借尸还魂，签名编译不过）；测试调用点同步 |
| `src/dialer.rs` | `dial_reality_stream_one` 去 `rtt_hint` 参数；定窗改 `client_windows()`；测试调用点同步 |
| `src/transport.rs` | `serve_http_conn` 去 `rtt_hint` 参数；服务端 TLS accept 计时（只喂日志）随之删除；REALITY 分支调用点同步；定窗改 `server_windows()` |
| `src/hub.rs` | `server_windows_from_rtt(None)` → `server_windows()`（明文 h2 路径），注释去 `XRAY_H2_RTT_HINT_MS` |
| `tests/mock_server.rs`（10 处）/ `tests/stream_h2.rs`（2 处）/ `tests/xmux_reuse.rs`（1 处）/ `tests/reality_integration.rs`（1 处） | 调用点去尾部 `None` 实参 |

不删：`XRAY_H2_FLOW_WINDOW_OVERRIDE_BYTES` / `XRAY_H2_SEND_BUF_OVERRIDE_BYTES`（bench 扫曲线用，
与探针无关）；`CLIENT_FALLBACK` / `SERVER_FALLBACK` 及其窗值（bd wz2b/c9oc 拍板的静态保底）。

---

## 4. accept 数前后对比（计数锚）+ 反证

锚 = 上一票（s42cg）落地的**服务端连接接受计数**：`tests/xmux_reuse.rs` 的计数型 h2 server 数
`TcpListener::accept`（每条新 TCP +1，含探针那条一次性连接），h3 数 quinn 握手。客户端走生产接线
（`register_dialer()` + `dial`），探针恰在接线路径上。

"删除前"数字取自同一批用例在探针仍在时的实测（s42cg 轮终态，h2 路径与本票删除点之外零差异）：

| 用例（5 拨号） | 删除前 accepts | 删除后 accepts | 差值读法 |
|---|---|---|---|
| `h2_default_xmux_reuses_tcp_connection` | 8 | **3** | 每拨号 1 条探针 TCP 消失（5 条） |
| `h2_max_connections_one_single_client` | 6 | **1** | maxConnections=1 现在精确封顶 1 条（= Go 语义） |
| `h2_sequential_close_weakens_reuse` | 8 | **3** | |
| `h2_h_max_request_times_…`（预算 100 / 1） | 6 / 10 | **1 / 5** | 预算 100 = 单连接零额外；预算 1 = 每拨号恰 1 条新连接 |
| `h2_bypass_pool_control`（**不经接线路径**，无探针） | 10 | **10** | **不变** ✓（探针只在接线路径上，对照成立） |
| `h3_xmux_reuses_quic_connection`（h3 路径无探针） | 1 | **1** | **不变** ✓ |

删除后原始输出（`cargo test … --test xmux_reuse -- --nocapture --test-threads=1`）：

```
[h2 bypass pool]      dials=5 accepts=10
[h2 default xmux]     dials=5 accepts=3 gets=5 posts=5
[h2 hMaxRequestTimes] dials=5 budget=100 accepts=1 budget=1 accepts=5
[h2 maxConnections=1] dials=5 accepts=1
[h2 sequential close] dials=5 accepts=3
[h3 maxConnections=1] dials=4 accepts=1 gets=4 posts=4
```

### 4.1 反证（把探针加回 → accept 数回升）

临时在 `register.rs` h2 路径塞回等价探针行为（一次性 `TcpStream::connect` + 计时后丢弃），
同用例原样重跑：

```
[h2 bypass pool]      dials=5 accepts=10
[h2 default xmux]     dials=5 accepts=8 gets=5 posts=5   ← 回到删除前
[h2 hMaxRequestTimes] dials=5 budget=100 accepts=6 budget=1 accepts=10
[h2 maxConnections=1] dials=5 accepts=6                  ← 回到删除前
[h2 sequential close] dials=5 accepts=8                  ← 回到删除前
[h3 maxConnections=1] dials=4 accepts=1 gets=4 posts=4   ← 不变（h3 无探针）
```

逐值回到删除前 ⇒ accept 数差异**因果归因于探针**（而非其他并发因素）。反证补丁已还原，
`git diff` 确认无残留（`grep probe_rtt src/` 仅命中注释）。

### 4.2 附带收益：s42cg §5.1 的"h2 每拨号新增 1 条 TCP"悬案闭案

上一票（Wave7Xmux §5.1）登记的「h2 侧池化后仍常见每拨号新增 1 条 TCP、成因未定」——
本票证实**主因就是探针**：删除后 maxConnections=1 下 5 拨号仅 **1 条 TCP**（修前 6 条），
default 下 3 条（修前 8 条），已与 Go 的"封顶 maxConnections"形态一致（矩阵对照见 §5）。

---

## 5. 矩阵（不得退化）

命令：`python reports/audit-2026-10-31-perf-mem-wiring/fix/scripts/wave7_h3_matrix.py
--rust D:/tmp/wave7_h3_matrix/xray-rs-lf51l.exe --go D:/tmp/wave7_h3_matrix/xray-go-xmux2.exe --dl --xmux`
（二进制 = 本票删除探针后的 release 重建；Go 侧与 s42cg 同一二进制）。

**30/30 PASS**（18 模式×方向 + 3 `--dl` + 6 xmux + 3 xmux 对照）——对 s42cg 基线零退化。
xmux 维度同时给出本票的进程级收益（客户端侧 TCP 数，转发器锚）：

```
[PASS] #22 Rust->Rust pool       conns=10 tcp_conns=3   ← 删除前 13，与 Go 持平
[PASS] #23 Rust->Rust no-reuse   conns=10 tcp_conns=10  ← 删除前 20（每拨号恰 1 条）
[PASS] xmux-cmp  Rust->Rust pool_tcp_conns=3 < no-reuse_tcp_conns=10 => 复用
[PASS] #24 Rust->Go  pool       conns=10 tcp_conns=3    ← 删除前 13
[PASS] #25 Rust->Go  no-reuse   conns=10 tcp_conns=10   ← 删除前 20
[PASS] xmux-cmp  Rust->Go  pool_tcp_conns=3 < no-reuse_tcp_conns=10 => 复用
[PASS] #26 Go->Rust  pool       conns=10 tcp_conns=3    ← 删除前后均 3（Go 无探针，不受影响）
[PASS] #27 Go->Rust  no-reuse   conns=10 tcp_conns=21   ← 删除前 21
[PASS] xmux-cmp  Go->Rust  pool_tcp_conns=3 < no-reuse_tcp_conns=21 => 复用
```

**结论**：删除探针后 Rust 客户端在 xmux 池化下的 TCP 连接数 = 3（10 条代理连接），与 Go 同配置
**完全持平**（删除前 Rust 13 vs Go 3）。s42cg §5.1 登记的"Rust 复用弱于 Go"缺口**就此闭案**，
不存在 hyper-util 池语义问题。

---

## 6. 门禁

| 门禁 | 结果 |
|---|---|
| `cargo test -p xray-transport-splithttp --all-targets` | **295 passed / 0 failed**（lib 269 + 4 + 1 + 12 + 1 + 2 + 6；较 s42cg 的 301 净 -6 = 删除的 4 个 RTT 相关 flow_window 测试 + 2 个 probe_rtt tokio 测试） |
| `cargo clippy -p xray-transport-splithttp --all-targets -- -D warnings` | 零告警 |
| `cargo fmt -p xray-transport-splithttp -- --check` | 0 diff |

**顺带修复（非本票目标但必须交代）**：`transport::tests::h3_accept_loop_panic_is_reported`
（x2ywg 判别器）在本轮由"侥幸绿"转"恒红"——根因是该测试见到**任何首条日志**就 break，而 crate
内 LogFacade 懒初始化 banner（INFO）可能先于监督 ERROR 落进捕获（s42cg 轮调度序侥幸先见到 ERROR）。
修法 = 内容断言移进轮询循环（等到含 ERROR/splithttp-h3/local/panic 摘要的行，5s 墙钟兜底），
未放宽断言实质。与 udf CI 教训②（callsite interest 缓存 / 捕获时序）同族。

---

## 7. 残余风险

- 探针删除后，定窗日志不再带 `rtt_ms` 标签；排查「探针 RTT vs 端到端 RTT 差多少」的诊断手段
  随之消失——但该诊断在阶梯删除后本已无消费场景（Wave5Rtt 已拍板静态窗）。
- `XRAY_H2_RTT_HINT_MS` env 一并删除：如有 bench 脚本仍在设它，现为无害未知 env（不再读取）。
  `XRAY_H2_FLOW_WINDOW_OVERRIDE_BYTES` / `XRAY_H2_SEND_BUF_OVERRIDE_BYTES` 保留未动。
- REALITY 路径的服务端 accept 计时（transport.rs）与真实 TCP connect 计时（register.rs）一并删除
  ——它们不产生额外连接、也只喂日志；若未来需要「连接建立耗时」观测，应走观测性票（bd 39hko
  Clock 注入面）而非会话内探针。

（本节完 → 落盘）
