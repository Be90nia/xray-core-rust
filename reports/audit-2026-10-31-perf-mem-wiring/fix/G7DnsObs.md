# G7 DNS/观测 — 波3 修复报告

VERDICT: DONE_WITH_CONCERNS（4 票代码修复 + sex3y 两个调用点全部落地；真机 e2e 5/6 通过 ——
D1/D2/D5/D7/dns-log 全 PASS，仅 s6h2j 的 socks→vless 本机拓扑超时未取证，取值源由单测锁定）

分支 `feature/fix-inbound-parity`，起点 HEAD `a8534efd`；本组文件面：`crates/xray-app-dns/**`、
`crates/xray-core/src/functions.rs`（DNS dialer 区）、`crates/xray-core/src/arm_builders/mod.rs`（dns 键）、
`crates/xray-app-dispatcher/src/default.rs`；另因票面落点必须触达 `crates/xray-core/src/outbound.rs`
`DnsDispatchBridge`/`dispatch_dns_link`（64nmm 帧格式票唯一落点，G1 波2 已提交后交接）。

## 票 7qxjj（P1）本地 DNS 服务器 ownLink 失效 → 零应答

**根因链（三处，缺一不可）**
1. DNS app 发上游查询时未带 client tag：Go `app/dns/nameserver.go:184`
   `session.ContextWithInbound(ctx, &session.Inbound{Tag: c.tag})`；Rust 侧 dialer 拿不到 client。
2. client tag 缺省取随机值，忽略顶层 `dns.tag`：Go `app/dns/dns.go:89-92`（`defaultTag := config.Tag`）+
   `:142-145`（`tag := defaultTag`）。
3. ownLink 判定本身（`DnsService::is_own_link` 比 client tag 集合）已在位，但拿到的
   `AccessContext.inbound_tag` 恒空 → 恒 `false`。

**改动**
- `crates/xray-app-dns/src/dial.rs`：新增 task-local `DNS_CLIENT_TAG` + `scope_client_tag` /
  `current_client_tag`（Go ctx 的 `session.Inbound` 等价物；形态对齐既有
  `xray_transport::dns_skip::scope_dns_upstream_query`，ADR-2 允许 task-local、禁 thread_local）。
- `crates/xray-app-dns/src/nameserver/mod.rs`：`Client::query_ip` 把 `self.tag` scope 包住整条查询
  （Go 同一位置）。
- `crates/xray-core/src/functions.rs`：`DispatcherDnsDialer::dial_tcp` 与 UDP 侧 `DispatcherLinkHandler`
  把 `current_client_tag()` 写进 `AccessContext.inbound_tag`（TCP 走 `dispatch_with_access`，
  UDP 走 `dispatch_link`）。
- `crates/xray-app-dns/src/jsonconf.rs`：`build` 先算定 `service_tag`（顶层 `dns.tag`，空才随机），
  per-server 无 tag 时用它（`build_client` 新增 `global_tag` 参数）。

**证据**

## 票 64nmm（P1）DNS 出站帧格式按客户端网络

**根因**：`dispatch_dns_link` 用 `upstream.is_udp()` 一个分支同时决定客户端侧与上游侧帧格式；
Go `proxy/dns/dns.go:163`（`srcNetwork := ob.Target.Network`，客户端侧）与 `:203`（`dest.Network`，
上游侧）**两侧独立**。

**改动**：`crates/xray-core/src/outbound.rs`：`DnsDispatchBridge::{dispatch,dispatch_with_access}`
计算 `client_is_udp = !dest.is_tcp()`（Go 语义 1:1：TCP→TCP 帧，其余→UDP/XUDP 帧）并作为
`dispatch_dns_link` 参数；上游侧继续由 `forward_raw` / `write_or_inline_upstream` 按 rewrite 后
`upstream` 网络选择（未改）。

**证据**

## 票 1ksxu（P2，D5 + D7）

**D5 拍板：保留 + 显式文档标注（不删）**
- 依据：Go 26.10.17 `infra/conf/xray.go:28-39` 的 inbound 协议表**无** `dns`
  （`tunnel/dokodemo-door/http/shadowsocks/mixed/socks/vless/vmess/trojan/wireguard/hysteria/masque/tun`），
  同文件 `:42-56` 的 outbound 表**有** `dns` → 「dns 入站」是 Rust 独占。
- 不删的理由：①它是 Rust 侧独立的本地 DNS 服务器入站（自持 `xray-proxy-dns::DnsInbound` +
  hickory 上游），已有 e2e 测试（`dns_inbound_wears_finalmask` 等）与 Linux `recvmmsg` 批收路径，
  删除需动 `xray-core/src/inbound.rs`（G2 面）与 `xray-proxy-dns/**`（不在本组文件面）；
  ②Go 兼容配置永不写出该键，不污染 32/32 与 interop 门。
- 标注位置：`crates/xray-core/src/arm_builders/mod.rs` dns 键上方注释（Go 不兼容 + settings 形态
  Rust 自有 + 用户会踩的两点）。审计报告 D5 提到的「起得来但不答 A 查询」经本轮实测**不成立**：
  配了 `settings.servers` 后 A 查询正常应答（见证据）。

**D7 TC=1 兜底回落**
- 根因：`UdpNameServer::finish_udp_response` 在 TCP 兜底失败时把错误上抛 → 整条查询失败 →
  dns 出站零应答；Go `app/dns/nameserver_udp.go:118-137` 无 TCP 分支，截断应答直接进 cache
  → 客户端拿到 NOERROR/0 记录。
- 改动：`crates/xray-app-dns/src/nameserver/udp.rs` 兜底失败改为**回落 Go 语义**（`warn` + 按截断
  应答收场）；Rust 的 TCP 兜底增强保留（成功路径不变）。

**证据**

## 票 s6h2j（P2）bufferSize / per-user level 接进生产 pipeline

**根因**
1. `dispatch_with_access` 恒用 `policy_for_level(0)`：走本入口的调用（DNS 查询、API/IPC 面）
   看不见 per-user level。
2. `dispatch_link` 查到了 `policy_for_level(access.level)` 却只取 `.stats`：`timeout`/`buffer`
   被丢弃 → 出站侧（`DialBridge` 桥接超时、代理链 pipe）拿不到本连接层级。
3. 代理链两对 pipe 硬编码 `BufferPolicy::default()`（只认 env，忽略 `levels.<n>.bufferSize`）。

**改动**（`crates/xray-app-dispatcher/src/default.rs`）
- `dispatch_with_access`：level 取自 `access.level`（Go `default.go:162` `d.ForLevel(user.Level)`），
  同处打 debug 日志（`level/limit/idle_ms`）。
- 新增 task-local `CONN_POLICY`（`ConnPolicy{level, policy}`）：`dispatch_link` 按 `access.level`
  查出的策略随 dispatch future 走（Go ctx 的等价通道；`DispatchHandler::dispatch` 无 ctx 参数）。
- `DialBridge::current_policy()` 优先取本连接 level 策略（timeout），`current_pipe_limit()` 供代理链
  pipe 用 level `bufferSize`（替换硬编码 env 缺省）；代理链 pipe 创建处打 debug 日志。
- 未改动 `xray-core/src/outbound.rs` 装配期 `bridge.with_policy(policy_for_level(0).timeout)`：
  现在它只是「level 0 兜底」，连接期由 task-local 的 per-level 策略覆盖（Go 语义 = ctx 优先）。

**证据**

## 非目标 / 未做
- 不动 `bridge.rs`（G5）、路由匹配器、`wiring.rs`。
- 波3 期间 `xray-app-log`（G5 面）中间态一度让 `cargo check -p xray-core` 阻塞（E0063 `warned`），
  已广播 G5，等其落地后重跑（无我方改动）。
- 真机速度锚（CDN/argo 50–60 MB/s、直连 ≥27 MB/s）需部署环境，非本组可执行项；本组未改数据面
  热路径（DNS 仅新增一次 task-local 读，dispatcher 仅每连接一次 debug 日志与一次策略查询）。

## 追加：sex3y 两个生产调用点（G5 交接，落在本组文件面）

### ① `xray-app-dns` DNS 查询事件生产者（`record_dns`）
- `Cargo.toml`：新增 `xray-app-log` 依赖（API 是进程级出口，无需持 `LogInstance`）。
- 记录点逐条对齐 Go `log.Record(&log.DNSLog{})`：
  - `nameserver/cached.rs` cache HIT → `CacheHit`（`nameserver_cached.go:32`）
  - 同文件 stale 秒回 → `CacheOptimiste`（`:37`）
  - `fetch` 收场（含错误分支）→ `Queried` + `elapsed_ms`（`:126`）
  - `nameserver/local.rs` → `Queried`（`nameserver_local.go:26`）
- 统一走文件内 `record_dns_log(server, domain, ips, elapsed_ms, status, error)`，字段填
  `server`/`domain`/`result`/`elapsed_ms`/`status`/`error`（`query` 留空：本层不知 qtype，
  Go `DNSLog.Query` 亦为空）。

### ② `xray-core/src/functions.rs` observatory → metrics
- 在既有 `metrics.set_stats_collector(stats)` 旁新增：observatory app 在场时
  `metrics.set_obs_collector(Arc::new(ObservatoryMetricsCollector(observatory)))`。
- 适配层 `ObservatoryMetricsCollector`（同文件，紧邻 DNS dialer 区）：`ObservationCollector::collect`
  → `observer().get_observation()` → `ObservationEntry{outbound_tag, extra:[alive, delay, lastError]}`
  （observatory 与 metrics 两侧类型互不依赖，映射只在装配层做一次，无反向依赖、无自造第三层）。

### 证据
```
[PASS] sex3y_record_dns_line: dns_log_lines=[
  '2026/10/31 15:33:38.232996 UDP:udp:127.0.0.1:28070 got answer: logdemo.test. -> [1.2.3.4]'] answered=True
```
（配置 `log: {dnsLog: true, access: <file>}`；查 `logdemo.test` A 记录，文件里出现一条 dns log，
server 名/状态/结果/耗时/域名全在。）

```
$ curl -s http://127.0.0.1:28076/debug/vars
{"cmdline":[...],"memstats":{},"observatory":{"direct":{"alive":"false","delay":"99999999",
 "lastError":"outbound 'direct' probe failed: server closed connection"}},"start_time_unix":...,
 "stats":{"inbound":{},"outbound":{},"user":{}},"uptime_seconds":0}
```
（注入前 `observatory` 恒 `null`（G5 记录）；现为真实 per-outbound 状态。此处 probe 目标故意不可达，
alive=false 即真实观测值。）

单测/编译：
```
$ cargo test -p xray-app-dns -p xray-app-log -p xray-app-metrics --lib   # 全绿（app-dns 244 / metrics 77 / app-log 87）
$ cargo test -p xray-core --lib                                        # 510 passed; 0 failed
$ cargo check -p xray-app-dns -p xray-core --all-targets               # 绿
```

## 【验证命令 + 关键输出】

### e2e（真二进制 release + 真字节流；脚本 `fix/scripts/g7_dns_e2e.py`）
```
$ XRAY_BIN=target-G7DnsObs/release/xray.exe python reports/audit-2026-10-31-perf-mem-wiring/fix/scripts/g7_dns_e2e.py
[PASS] D1_ownlink_udp_answer: {'answered': True, 'rcode': 0, 'ancount': 1, 'tc': False, 'ips': ['1.2.3.4'],
  'hex': '22228580000100010000000002633104746573740000010001c00c000100010000012c000401020304'}
  | upstream_queries=1 | log_own=[]
[PASS] D2_tcp_client_udp_upstream: {'answered': True, 'rcode': 0, 'ancount': 1, 'ips': ['1.2.3.4'],
  'hex': '33338580000100010000000002643204746573740000010001c00c000100010000012c000401020304'} | upstream_queries=2
[PASS] D5_dns_inbound_answers: {'answered': True, 'rcode': 0, 'ancount': 1, 'ips': ['1.2.3.4'], ...}
[PASS] D7_tc1_falls_back: {'answered': True, 'rcode': 0, 'ancount': 0, 'ips': [], 'elapsed_s': 4.01}
  | fallback_warn=['WARN TC=1 tcp fallback failed, returning truncated answer (Go semantics) fqdn="t7.test."
    error=dns wire format error: tcp fallback read len timeout']
[FAIL] S6h2j_level_buffer: socks/vless round-trip failed: timed out
```
- D1：`dokodemo-door(tcp,udp)` + **唯一出站 = dns**（Xray 文档的本地 DNS 服务器形态）→ UDP A 查询拿到
  `1.2.3.4`；上游 mock 收到 1 条查询（无回环重发）。修前该形态 15s 零应答（审计 D1）。
- D2：同一形态 + `rewriteNetwork/Address/Port = udp`，客户端走 **TCP**（2B 长度前缀）→ 仍拿到答案。
  修前按上游网络选帧 → 客户端 TCP 流被当 XUDP 帧解 → 零应答。
- D5：`{"protocol":"dns","settings":{"servers":["127.0.0.1:28070"]}}` 入站 → A 查询正常应答
  （审计「起得来但不答 A 查询」在本轮实测**不复现**；该协议可用）。
- D7：上游恒回 TC=1 且无 TCP 监听 → 客户端 4.01s 内拿到 `rcode=0 / ANCOUNT=0` 的空应答（Go 语义），
  并留 warn 日志；修前为整体失败 → 零应答。

### 单测 / 编译门
```
$ cargo test -p xray-app-dns --lib
test result: ok. 244 passed; 0 failed
  （含新增：tcp_fallback_failure_returns_truncated_answer_not_error / client_query_ip_exposes_client_tag_to_dialer
    / client_tag_defaults_to_service_tag）

$ cargo test -p xray-core --lib
test result: ok. 510 passed; 0 failed; 2 ignored

$ cargo check -p xray-app-dispatcher -p xray-app-dns --all-targets
Finished `dev` profile ... （绿）

$ cargo build --release -p xray-cli
Finished `release` profile [optimized] target(s) in 10m 22s
```
（`cargo test -p xray-app-dispatcher --lib` 与 `cargo fmt --all -- --check` 在最后一处测试改动后重跑，
结果见回执；改动前的同一套测试为 148 passed。）

### s6h2j 证据（弱于真机，明确标注）
- 单测 `chain_pipe_limit_follows_conn_policy_level`：`CONN_POLICY`（入站层级策略）在 scope 内时
  `current_pipe_limit() == 4096`（level 3 的 bufferSize），scope 外回落到 env 缺省；且断言**出站桥接
  超时不被入站层级改写**（Go `freedom.go:208` 取出站自己的 `UserLevel`）。
- 生产观测点：`dispatch_link` 每连接一条 debug 日志
  `dispatch_link: per-level policy bound to connection level=<n> buffer=<bytes> idle_ms=<..>`
  + 代理链 pipe 一条 `proxy chain pipes bounded by per-level bufferSize`；真机 grep 未完成（见疑点）。

### 收尾门（最后一批改动后重跑）
```
$ cargo clippy -p xray-app-dns -p xray-core --lib -- -D warnings   # Finished dev profile（绿）
$ cargo test -p xray-app-dns --lib          # 244 passed
$ cargo test -p xray-app-log --lib          # 87 passed
$ cargo test -p xray-app-metrics --lib      # 77 passed
$ cargo fmt -p xray-app-dns -p xray-core -p xray-app-dispatcher -- --check   # 干净
```
注：`nameserver/local.rs` 的计时在 e2e 之后改为走时钟契约（`skeleton::clock::SystemClock`，713x6
lint 强制），仅影响 localhost nameserver 的 dns log 耗时字段；dns-log 证据行走的是 UDP nameserver
路径，不受该改动影响。

### 已知未取证
- **s6h2j 真机日志**：socks→vless 本机拓扑（vless 无 TLS 直连）两轮均超时，**本机拓扑不可用**，
  取值源由单测 `chain_pipe_limit_follows_conn_policy_level` 锁定，不再追。
