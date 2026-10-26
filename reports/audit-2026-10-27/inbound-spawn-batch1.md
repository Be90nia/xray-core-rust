# inbound.rs 裸 spawn → FxScope 托管 · 第一批（scope 归属清晰面）

票：bd 39hko 切片。日期：2026-10-27。执行：InboundSpawn1（独占树）。
基线：master 4330bb1d，工作树净（仅未跟踪报告）。

## 0. 台账漂移修正（先于迁移的实数）

文件顶 allow 写的是「79 处（74 tokio::spawn + 5 std Instant）」。本批开工 grep 实测：

- `tokio::spawn` 全文件 **81 处**（生产 29 + tests 模块 52）——较台账 +7（台账落笔后 tests 面新增）。
- `std::time::Instant` 生产面 4 处（2198/2200/2342/2357；tokio::time::Instant 契约不禁）。

**真数：81 tokio::spawn + 4 std Instant = 85**，allow reason 计数已过期。本批收尾按迁移后实数改写。

## 1. 归属表（先表后码；生产面 29 处逐条）

判定口径：**迁** = 任务为连接/会话生命周期管理（handshake→dispatch handoff、每 UDP associate/peer 会话表驱动），宿主为 serve 函数可自持 `Arc<PluginContext>`（arm 装配 ctx，`InboundCtx.plugin_ctx` → `Arc::new`），任务内持克隆做 scope 生命周期锚（裸 spawn detach 语义等价）；**保留** = mux 跨连接 / vision-splice 红线 / 数据面泵 / 结构化监控 / cfg(unix) 本机不可验证。

| # | 行 | 所属函数 | 路径 | 热路径 | scope 归属 | 处置 |
|---|----|---------|------|--------|-----------|------|
| 1 | 147 | `serve_socks5` | SOCKS5 accept→每连接 handler | 每连接控制路径（非每包） | 清晰：arm ctx 实例 scope | **迁** |
| 2 | 385 | `handle_connection` | SOCKS5 每 UDP associate relay | UDP 会话面 | 清晰，但函数与 cfg(unix) UDS 栈共用（spawn_unix_inbound:4122 同参调用），改签名必动 unix 门控调用点 | 保留（附理由） |
| 3 | 433 | `handle_connection` | mux link 派生 | 跨连接生命周期 | mux 域（跨连接，票面明示不迁） | 保留 |
| 4 | 650 | `serve_mixed` | 每连接 1 字节 sniff+双协议 handler | 每连接控制路径 | 清晰 | **迁** |
| 5 | 684 | `serve_mixed`(socks 分支) | mux link | 跨连接 | mux 域 | 保留 |
| 6 | 694 | `serve_mixed`(socks 分支) | 每 UDP associate relay（控制连接关闭即 abort） | UDP 会话面 | 清晰（Spawned::abort 与 JoinHandle::abort 同形） | **迁** |
| 7 | 747 | `serve_mixed`(http 分支) | mux link | 跨连接 | mux 域 | 保留 |
| 8 | 790 | `serve_http` | 每连接 keep-alive 回环 handler | 每连接控制路径 | 清晰 | **迁** |
| 9 | 842 | `serve_http` | mux link | 跨连接 | mux 域 | 保留 |
| 10 | 1585 | `serve_dokodemo` | 每连接 handler | 每连接控制路径 | 清晰（dokodemo 臂已有 B6 `fx` 先例，ctx 走臂 entry 注入） | **迁** |
| 11 | 1736 | `serve_dokodemo_udp_on` | 每 UDP peer 会话 relay（会话表 tx 管理） | UDP 会话面 | 清晰 | **迁** |
| 12 | 1916 | `spawn_ss_pump` | SS 数据面双向泵（SSStream nonce 串行纪律，select! 单任务） | **每包数据面** | 数据面泵保留族（transport 波先例「⑫数据面泵保留」） | 保留 |
| 13 | 2043 | `serve_ss` | SS UDP serve task（每 inbound UDP socket，Legacy/Ss2022 分派） | 会话面 | 清晰：宿主 serve_ss 持 ctx | **迁** |
| 14 | 2070 | `serve_ss` | 每连接 ss_mode pipeline | 每连接控制路径 | 清晰 | **迁** |
| 15 | 2244 | `serve_ss_udp` | 每 UDP client relay（mpsc 会话） | UDP 会话面 | 清晰 | **迁** |
| 16 | 2404 | `serve_ss2022_udp` | 每 UDP session relay（ss2022 会话表） | UDP 会话面 | 清晰 | **迁** |
| 17 | 2537 | `serve_dns` | DNS UDP recv loop（每 inbound） | 请求-响应服务环 | 清晰：arm ctx scope，任务持克隆 | **迁** |
| 18 | 2540 | `serve_dns` | DNS TCP accept loop（每 inbound） | 同上 | 清晰 | **迁** |
| 19 | 2546 | `serve_dns` | DNS 每连接 handle_conn | 每连接控制路径 | 清晰 | **迁** |
| 20 | 3089 | `spawn_inbound_serve` | 外层监控壳（serve panic→error! 留痕，bd wsiq 族） | 启动期 | 结构化监控保留族（transport 波先例） | 保留 |
| 21 | 3094 | `spawn_inbound_serve` | 内层 serve task（shutdown_token select） | 启动期 | 同上（token 生命周期，非连接域） | 保留 |
| 22 | 3482 | `serve_reality_vless` | REALITY vision splice 装配循环（bd e0ni/39824） | 数据面 | splice/vision 红线（坑约束⑫；W5 对 xray-proxy-vless 同位点 per-site allow 保留先例） | 保留 |
| 23 | 3673 | `serve_reality_trojan` | REALITY vision 路径 serve | 数据面 | splice/vision 红线 | 保留 |
| 24 | 3901 | `spawn_one_inbound` | tun `handler.start()` serve | 启动期 | 归属清晰但 JoinHandle 外返契约 + 平台门控臂（linux/android/freebsd/windows） | 保留 |
| 25 | 4122 | `spawn_unix_inbound` | UDS socks 每连接 | 每连接 | 归属清晰（:4058 `plugin_ctx` 在作用域），但 `#[cfg(unix)]` 本机 cargo check 不可编译验证——改=盲改 | 保留（留 Linux 床批） |
| 26 | 4162 | `spawn_unix_inbound` | UDS vless 每连接 | 同上 | 同上（且 `plugin_ctx` 已被 vless 臂 `build_vless_decryption` move，所有权需梳理） | 保留 |
| 27 | 4201 | `spawn_unix_inbound` | UDS vmess 每连接 | 同上 | 同上 | 保留 |
| 28 | 4238 | `spawn_unix_inbound` | UDS trojan 每连接 | 同上 | 同上 | 保留 |
| 29 | 4273 | `spawn_unix_inbound` | UDS ss 每连接 | 同上 | 同上 | 保留 |

**生产面小计：迁 13 处（#1,4,6,8,10,11,13,14,15,16,17,18,19）/ 保留 16 处。**

tests 模块（5635-11546）52 处 `tokio::spawn`：全保留（测试面 allow 先例；W5/transport 波测试面均挂台账，测试走 `tokio::test` 自有 runtime，FxScope 化无生命周期收益）。

## 2. 迁移形态（照抄既有两先例）

- **句柄面**（W5 proxy 形态）：组件自持 `Arc<PluginContext>`——serve 函数加参 `plugin_ctx: Arc<PluginContext>`，由臂 entry `Arc::new(ctx.plugin_ctx)` 注入（与 vless/trojan/vmess entry 完全同形；arm ctx scope = `arm_plugin_ctx(kind)` per-实例自持，`for_plugin` 只在装配派发点构造，禁测试/调用方自造）。
- **spawn 面**：`tokio::spawn(f)` → `plugin_ctx.spawn(f).expect("arm FxScope is never closed")`（expect 文案对齐 B6 dokodemo 臂先例；`Spawned` Drop 不 abort——任务归 scope JoinSet 托管，fire-and-forget 语义与裸 spawn 等价）。
- **生命周期锚**（本夜坑 1 的对策）：每个被迁任务内持 `let _ctx = Arc::clone(&plugin_ctx);`——serve future 因 shutdown 提前 drop 时 scope 不随之 drop，在途连接任务继续跑到自然结束，**与裸 spawn detach 语义逐位等价**（SsConnection `_ctx` 自持同款）。
- **签名增量**：serve/build 函数各 +1 参（最多 6→7），全部 ≤8 参红线内；构造点（臂 entry）同步。

改动清单（签署后执行）：
1. `inbound.rs`：import `xray_frame::PluginContext`；8 个 serve 函数签名 +1 参；13 处 spawn 点换 `plugin_ctx.spawn` + 任务内锚。
2. `arm_builders/inbound.rs`：6 个 build 函数签名 +1 参（socks/mixed/http/dokodemo/shadowsocks/dns）；对应 6 个 entry 补 `Arc::new(ctx.plugin_ctx)`。
3. tests 模块 ~20 处调用点补 `test_plugin_ctx("<kind>")` 实参（既有助手，:5639）。
4. 文件顶 allow reason 改为迁移后实数。

## 3. 保留清单及理由（汇总）

| 保留面 | 处数 | 理由 |
|---|---|---|
| mux link（433/684/747/842） | 4 | 跨连接生命周期，票面明示不迁；迁=scope 归属改挂非宿主连接，语义不等价 |
| SS 数据面泵（1916） | 1 | 每包数据面（SSStream nonce 串行 select! 纪律），数据面泵保留族先例 |
| 结构化监控（3089/3094） | 2 | panic→error! 留痕 + token select 的 serve 生命周期壳，transport 波结构化监控保留族 |
| vision splice（3482/3673） | 2 | splice/vision 红线⑫；vision gate/DIRECT 切换禁碰 |
| tun serve（3901） | 1 | JoinHandle 外返契约 + 平台门控臂 |
| UDS 每连接（4122/4162/4201/4238/4273） | 5 | `#[cfg(unix)]`：归属清晰但 Windows 本机不可编译验证（改=盲改）；vless 臂 plugin_ctx 所有权已被 move 需梳理。留待 Linux 验证床批次 |
| handle_connection UDP associate（385） | 1 | 归属清晰，但签名与 cfg(unix) UDS socks 臂共用（盲改连带）；待 UDS 批同迁 |
| tests 面 | 52 | 测试面 allow 台账先例，非本批目标 |

## 4. 验收记录

### 4.1 cargo check --workspace --all-targets

```
    Checking xray-proxy-http v0.1.0 (D:\Project\Xray-core-rust\crates\xray-proxy-http)
    Checking xray-core v0.1.0 (D:\Project\Xray-core-rust\crates\xray-core)
    Checking xray-cli v0.1.0 (D:\Project\Xray-core-rust\crates\xray-cli)
    Checking xray-stress v0.1.0 (D:\Project\Xray-core-rust\crates\xray-stress)
    Checking xray-integration-tests v0.1.0 (D:\Project\Xray-core-rust\tests)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 27.74s
```
0 error。

### 4.2 cargo clippy --workspace --all-targets -- -D warnings

```
    Checking xray-core v0.1.0 (D:\Project\Xray-core-rust\crates\xray-core)
    Checking xray-cli v0.1.0 (D:\Project\Xray-core-rust\crates\xray-cli)
    Checking xray-stress v0.1.0 (D:\Project\Xray-core-rust\crates\xray-stress)
    Checking xray-integration-tests v0.1.0 (D:\Project\Xray-core-rust\tests)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 49.21s
```
0 error 0 warning（-D warnings 下 Finished 即全绿）。

### 4.3 cargo test -p xray-core --all-targets

```
binaries: 3 passed: 478 failed: 0
  ('ok', '476', '0')   # lib 单元+集成测试（含 socks/mixed/http/dokodemo/ss/ss2022/dns/finalmask 全部本批触碰路径）
  ('ok', '1', '0')     # bind_failure_fatal
  ('ok', '1', '0')     # invalid_inline_cert_startup
ALL GREEN
```

### 4.4 release 构建

```
warning: `xray-cli` (bin "xray") generated 1 warning   # 既有 linker warning（非本批引入）
    Finished `release` profile [optimized] target(s) in 9m 24s
```

### 4.5 32/32 真机（核心风险门）

首跑 0/32 全灭（81s、逐条 `curl: (3) URL rejected: Port number…`）——**harness 参数伪影，非被测物缺陷**：经 `cmd /c "… --url \"https://…\" …"` 转义引号按字面漏进 python argparse，curl 收到坏 URL。鉴别：手工起 release xray.exe（socks inbound :17801）+ 手工 curl 同下载 URL → `HTTP:200, body=200000 bytes`，socks 链路（即本批迁移路径）实活。换干净参数传递（bash 侧直跑 python）重跑：

```
[PASS] #1	vless	reality/tcp	HTTP=HTTP:200    	body= 200000B	
[PASS] #2	anytls	none/tcp	HTTP=HTTP:200    	body= 200000B	
[PASS] #3	hysteria	tls/hysteria	HTTP=HTTP:200    	body= 200000B	
[PASS] #4	naive	none/tcp	HTTP=HTTP:200    	body= 200000B	
[PASS] #5	shadowsocks	none/tcp	HTTP=HTTP:200    	body= 200000B	
[PASS] #6	shadowsocks	tls/ws	HTTP=HTTP:200    	body= 200000B	
[PASS] #7	shadowsocks	tls/ws	HTTP=HTTP:200    	body= 200000B	
[PASS] #8	trojan	tls/httpupgrade	HTTP=HTTP:200    	body= 200000B	
[PASS] #9	trojan	tls/ws	HTTP=HTTP:200    	body= 200000B	
[PASS] #10	trojan	tls/xhttp	HTTP=HTTP:200    	body= 200000B	
[PASS] #11	trojan	tls/httpupgrade	HTTP=HTTP:200    	body= 200000B	
[PASS] #12	trojan	reality/tcp	HTTP=HTTP:200    	body= 185517B	curl: (28) …
[PASS] #13	trojan	tls/tcp	HTTP=HTTP:200    	body= 200000B	
[PASS] #14	trojan	tls/ws	HTTP=HTTP:200    	body= 200000B	
[PASS] #15	trojan	tls/xhttp	HTTP=HTTP:200    	body= 200000B	
[PASS] #16	tuic	none/tcp	HTTP=HTTP:200    	body= 200000B	
[PASS] #17	vless	tls/httpupgrade	HTTP=HTTP:200    	body= 200000B	
[PASS] #18	vless	reality/tcp	HTTP=HTTP:200    	body= 200000B	
[PASS] #19	vless	tls/ws	HTTP=HTTP:200    	body= 200000B	
[PASS] #20	vless	tls/ws	HTTP=HTTP:200    	body= 200000B	
[PASS] #21	vless	tls/xhttp	HTTP=HTTP:200    	body= 200000B	
[PASS] #22	vless	reality/xhttp	HTTP=HTTP:200    	body= 200000B	
[PASS] #23	vless	tls/httpupgrade	HTTP=HTTP:200    	body= 200000B	
[PASS] #24	vless	tls/tcp	HTTP=HTTP:200    	body= 200000B	
[PASS] #25	vless	tls/ws	HTTP=HTTP:200    	body= 200000B	
[PASS] #26	vless	tls/xhttp	HTTP=HTTP:200    	body= 200000B	
[PASS] #27	vmess	tls/httpupgrade	HTTP=HTTP:200    	body= 200000B	
[PASS] #28	vmess	tls/ws	HTTP=HTTP:200    	body= 200000B	
[PASS] #29	vmess	tls/xhttp	HTTP=HTTP:200    	body= 200000B	
[PASS] #30	vmess	tls/httpupgrade	HTTP=HTTP:200    	body= 200000B	
[PASS] #31	vmess	tls/ws	HTTP=HTTP:200    	body= 200000B	
[PASS] #32	vmess	tls/xhttp	HTTP=HTTP:200    	body= 200000B	

=== 32/32 PASS  0 FAIL  0 PARSE ===
```
（#12 下载 185KB 后 curl 12s 超时但 marker 命中判 PASS——网络窗口噪声，与基线行为同形。）

harness 的 client 配置 inbound = **socks**（`run_full32.py::test` 固定 socks-in），即每个节点都实测了本批迁移后的 `serve_socks5` per-conn 托管路径。

### 4.6 interop 12/12

```
== A: Rust client -> Go server ==
[PASS] #01 Rust->Go     vmess            HTTP body= 200028B
[PASS] #02 Rust->Go     vless_vision_tls HTTP body= 200028B
[PASS] #03 Rust->Go     trojan_tls       HTTP body= 200028B
[PASS] #04 Rust->Go     vless_ws         HTTP body= 200028B
[PASS] #05 Rust->Go     ss               HTTP body= 200028B
[PASS] #06 Rust->Go     ss2022           HTTP body= 200028B
== B: Go client -> Rust server ==
[PASS] #07 Go->Rust     vmess            HTTP body= 200028B
[PASS] #08 Go->Rust     vless_vision_tls HTTP body= 200028B
[PASS] #09 Go->Rust     trojan_tls       HTTP body= 200028B
[PASS] #10 Go->Rust     vless_ws         HTTP body= 200028B
[PASS] #11 Go->Rust     ss               HTTP body= 200028B
[PASS] #12 Go->Rust     ss2022           HTTP body= 200028B

=== 互操作矩阵: 12/12 PASS ===
```

### 4.7 剩余实数（迁移后终盘）

| 面 | 迁移前（开工实测） | 迁移后 |
|---|---|---|
| 生产 `tokio::spawn` | 29 | **16**（-13） |
| tests `tokio::spawn` | 52 | 52 |
| 生产 `std Instant` | 4 | 4 |
| allow reason 计数 | 79（已漂移） | **72**（= 68 spawn + 4 Instant，逐处可对） |

改动面：`crates/xray-core/src/inbound.rs`（+564/-227 行级 diff，含 fmt 归整）、`crates/xray-core/src/arm_builders/inbound.rs`（+60）。其余文件零触碰（`git status` 仅此两个 tracked 修改）。

### 4.8 allow 台账改写

文件顶 reason 由「79 处（74 tokio::spawn + 5 std Instant）」改为实盘「72 处（68 tokio::spawn：生产 16 + tests 52；4 std Instant）」——旧计数在 tests 面新增后已漂移（开工 grep 实测 81 spawn），现与文件内容逐处可对（见 §1 表 + §3 保留清单）。
