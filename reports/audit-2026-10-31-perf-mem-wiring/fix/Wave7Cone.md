VERDICT: PASS（UDP relay 接入站源 + 协议名 → XUDP GlobalID 按 Go `xudp.GetGlobalID`
语义派生上线；双向互通实测「同源两条件会话共享同一上游绑定」（上游绑定数=1，改前/反证=2）；
xray-core lib 535 绿 + dispatcher/mux/tun/xudp 386 绿 + clippy 零告警 + fmt 0 diff。
反证已做（恒空 → 绑定数 2、断言红），还原后编译通过）

# kol4a — UDP cone 会话复用：入站源 → XUDP GlobalID 接线

- 执行人：SliceWire（子代理）。**派单竞争说明**：本票被 Main 同时派给 ConeWire 与本代理
  （消息竞争）。ConeWire 在本代理实现之上做了两项更 Go 忠实的修正（access 改可后置
  `set_access` + socks 源取首个被接受数据报的源而非 TCP 对端），于验证前 parked；
  本代理接手合流两线工作并完成验证。两线的编辑均已在上树状态中合流，无丢弃。
- 树：`feature/fix-inbound-parity` @ `afb963f9`（工作区含多票未提交改动，本票只碰 cone 相关面）
- 构建目录：`target-Wave7Cone`（本代理）/ ConeWire 用 `target-Wave7Cone2`；收尾各自删除
- 报告：`reports/audit-2026-10-31-perf-mem-wiring/fix/Wave7Cone.md`（本文件，增量更新）

## 进度清单（增量更新，防中断）

- [x] §1 Go 派生规则核对（两代理独立复核，结论一致：`xudp.go:65-80` + `core/xray.go:195-196` + `platform.go:21`）
- [x] §2 Rust 现状与 sgdkj 复核
- [x] §3 实现（relay 接线 + 白名单 + Mutex access 通道 + hit 打点）
- [x] 测试（dispatcher access 路由 1 条 PASS；MuxBridge 白名单正反 2 条；4jyhm 用例适配）
- [x] 探针脚本 `fix/scripts/wave7cone_reuse_interop.py`（py_compile 过）
- [x] 门禁（test/clippy/fmt 全绿；期间 splithttp 曾因 s42cg WIP 短暂阻塞，恢复后跑通）
- [x] §5 载波复用证据锚（上游绑定数：改后 1 / 反证 2，双向实测）
- [x] §6 Go↔Rust 双向 cone 语义（2/2 PASS，`cone_reuse.json`）
- [x] §7 反证（GlobalID 恒空 → 上游绑定 2、xudp_new=0、断言红；已还原）
- [x] §8 harness 修正说明
- [x] §9 残余风险

**VERDICT 更新见首行。门禁（test/clippy/fmt）与探针/反证均已在 splithttp 恢复后跑通。**

## §1 Go 事实（两代理独立复核一致，@92ccc939）

`common/xudp/xudp.go:65-80`：

```go
func GetGlobalID(ctx context.Context) (globalID [8]byte) {
	if cone := ctx.Value("cone"); cone == nil || !cone.(bool) { // cone is nil only in some unit tests
		return
	}
	if inbound := session.InboundFromContext(ctx); inbound != nil && inbound.Source.Network == net.Network_UDP &&
		(inbound.Name == "dokodemo-door" || inbound.Name == "socks" || inbound.Name == "shadowsocks" || inbound.Name == "tun") {
		h := blake3.New(8, ensureBaseKey())          // 8 字节输出，keyed 模式
		h.Write([]byte(inbound.Source.String()))    // 仅源地址字符串进 message
		copy(globalID[:], h.Sum(nil))
		...
	}
	return
}
```

- 白名单四族：`dokodemo-door` / `socks` / `shadowsocks` / `tun`，且 `inbound.Source.Network == UDP`。
- 派生公式：`blake3.New(8, baseKey)` keyed，message = `inbound.Source.String()`（`"udp:ip:port"` 形态；
  **仅源、含端口；不含目标地址**——票面「按 (源地址, 目标地址) 派生」的猜测不成立，实现以 Go 为准）。
- `cone` 标志：`core/xray.go:195-196` → env `xray.cone.disabled`（`platform.go:21`）不为 `"true"`
  ⇒ **默认启用**（默认行为与 Go 一致，无新增开关——框架支线不留门控）。
- cone 的另外两个作用面（票面边界，本票不动）：
  - 客户端出站改道：`vless/outbound.go:303-306`、`vmess/outbound.go:146-149`——
    `h.cone && UDP && port ∉ {53,443}` → mux carrier + `NewPacketWriter(GetGlobalID(ctx))`；
  - 服务端入站目标钉扎：`socks/shadowsocks/trojan server.go` 的 `if !s.cone || dest == nil`；
  - 服务端复用：`common/mux/server.go:195-247` `XUDPManager.Map[GlobalID]` 命中即复用
    dispatcher link（**"载波复用"发生在 mux 服务端 XUDP 层**，非客户端载波选择）。

## §2 Rust 现状与 sgdkj 复核

- 派生函数已在树：`xray_xudp::global_id(&GlobalIdInput)`（blake3 keyed + 32B 随机 base_key，
  与 Go 同构；`test_global_id_matches_go_keyed_vector` 字节对拍锁定）。`cone_disabled()`
  读同一 env，默认 cone 开。
- 出站消费点已在树（bd 4jyhm）：`MuxBridge::dispatch_with_access`（`outbound.rs:899-952`）。
- 服务端复用已在树：`xray-mux worker.rs::handle_xudp_new` + `xudp_hit_rebind`（zv9l）；
  既有测试 `xudp_new_same_global_id_reuses_existing_session` 断言「同 GlobalID 第二条
  mux session 不再 dispatch」。
- **缺口（本票）**：生产 UDP relay 全部无源 dispatch → `access.from` 恒空 → GlobalID 从不派生
  → 服务端永远 `handle_normal_new`（无 cone 复用）。与 Wave7Mux.md §2.2/§6.1 定位一致。
- **sgdkj 复核**：其现象（socks 通、dokodemo 不通）经 Wave7Mux.md §2.3 实证为 **Go 客户端
  那一列**（Go socks 入口带会话 ctx → GlobalID → 好路径；dokodemo 入口无 ctx → 坏路径，
  波 2 已修）。非本仓缺陷，本票维持"接线"定性，无需升级。
- **harness 错位复核**：`interop_udp_tunnel.py` 的 cone 列 = 出站 mux 开关（cone=False 不启
  mux）；`xray.cone.disabled` 在本仓 UDP 路径此前零消费。见 §8。

## §3 实现（已合流落地）

1. **AccessContext.inbound_name: String**（`default.rs`）——Go `session.Inbound.Name`；
   白名单判定信号（此前 4jyhm 的「from 非空」近似在 relay 面接线后会静默扩大 cone 面）。
2. **UdpDispatchSession access 通道**（`udp_session.rs`）：
   `access: parking_lot::Mutex<Option<AccessContext>>` + `with_access()`（builder，源已知面用）
   + `set_access()`（后置装填，socks ASSOCIATE 用——源 = 首个被接受数据报的源，建会话时未知）；
   `establish` 有源走 `dispatch_with_access`、无源保持旧 `dispatch`（语义不变）。
3. **MuxBridge 白名单**（`outbound.rs:749-755`）：`GO_CONE_INBOUND_WHITELIST =
   ["dokodemo-door","socks","shadowsocks","tun"]`（xudp.go:69-70 逐字），
   `dispatch_with_access` 先判白名单再派生。
4. **relay 接线**（Go 白名单四族；其余协议不填，双保险）：
   - socks `handle_udp_associate`：首包锁定 expectedRemote 后
     `set_access(from: relay.expected_addr(), inbound_name: "socks")`——**源 = 首个被接受
     数据报的源**（Go `server.go:243 changeRemote`：`conn.RemoteAddr()` 是 UDP 对端，
     不是 TCP 控制连接对端；ConeWire 修正，比初版 `peer` 参数更忠实）；
   - dokodemo `dokodemo_peer_relay`：`from: peer`（per-peer 任务的真实 UDP 源）；
   - shadowsocks `ss_udp_client_relay` / `ss2022_udp_client_relay`：`from: client`；
   - tun `run_udp_session`：`from: 内层源 endpoint`（smoltcp IpEndpoint → SocketAddr）。
5. **服务端 hit 打点**（`xray-mux worker.rs`）：hit-rebind 成功路径
   `info!("XUDP hit {:?}", global_id)`（对齐 Go `server.go:227`），供 go→rust 实测断言。

git diff 面（本票）：`xray-app-dispatcher/src/{default,udp_session}.rs`、
`xray-core/src/{inbound,outbound}.rs`、`xray-proxy-tun/src/inbound.rs`、`xray-mux/src/worker.rs`。

## 测试（已落地）

- `with_access_routes_through_dispatch_with_access`（dispatcher）：with_access 会话 establish
  必须走 dispatch_with_access 且携带 from/inbound_name —— **PASS（实测）**。
- `mux_bridge_dispatch_with_access_non_whitelisted_inbound_has_no_global_id`（xray-core）：
  from 非空 + name="vless" → New 帧无 GlobalID（Go 白名单反面锁定）。待 xray-core 可编译后跑。
- 4jyhm 用例适配：gid 用例 access 补 `inbound_name: "socks"`（白名单语义，非放宽）。
- 既有 `xudp_new_same_global_id_reuses_existing_session`（xray-mux）：同 GlobalID 第二条
  session 复用、dispatcher 只调一次——服务端复用锚，已在树。

## 门禁（实测）

```text
$ cargo test -p xray-core --lib
test result: ok. 535 passed; 0 failed; 2 ignored   （含 gid 正例/白名单反面/tun relay 用例）

$ cargo test -p xray-app-dispatcher -p xray-mux -p xray-xudp -p xray-proxy-tun --all-targets
dispatcher lib 150 / mux 145+23 / tun 154+10 / xudp 45+1+1+8 —— 全部 0 failed

$ cargo clippy -p xray-core -p xray-app-dispatcher -p xray-mux -p xray-xudp -p xray-proxy-tun \
      --all-targets -- -D warnings
CLIPPY_EXIT=0（零告警）

$ cargo fmt -p 同上五 crate -- --check
FMT_EXIT=0（0 diff）
```

（初版 clippy 抓到本代理测试里 MutexGuard 跨 await 一处，已用内层作用域修掉；
fmt 三处排版差异已按 rustfmt 落盘。）

## §5 载波复用证据锚（改后 = 实测数字）

**核心锚：上游绑定数（recorder 观察到的不同源 endpoint 数）**。cone 语义的本质 =
同源多条 mux session 共享**同一条上游 UDP 通道**（Go `server.go:195-247` hit → 复用旧
`x.Mux` link，不重新 Dispatch）；无复用时每条 session 各自 `dispatcher.Dispatch` →
freedom 独立拨号 → 源 endpoint 各不相同。该锚不依赖服务端日志（Go stdout 截断不可靠，
见 §8），直接在网络观测面计数。

探针驱动：同一客户端 UDP 源端口做两次 socks UDP ASSOCIATE（各一条控制连接），各发
1 包（29B DNS 查询）到同一上游目标；两侧服务端均为 vless-in(mux 终止) + freedom。

改后（本票接线，`target-Wave7Cone/release/xray.exe`，2026-11-01 实测）：

```text
[PASS] rust->go cone-reuse: xudp_new=1, upstream_peer_count=1, pkts=2, hex_ok=true, replies_ok=2
       srv 日志样本: common/mux: XUDP new [33 99 144 38 121 204 158 92]  ← Rust relay 派生的 GID
[PASS] go->rust cone-reuse: upstream_peer_count=1, pkts=2, hex_ok=true, replies_ok=2
=== 2/2 PASS  (raw -> dist/tmp_udp_tunnel/cone_reuse.json) ===
```

- `upstream_peer_count=1`：两条 mux session 复用同一条上游 UDP 通道（cone 生效）；
- `xudp_new` 样本里的 8 字节 = `xray_xudp::global_id(udp:127.0.0.1:<client_port>)`，
  即 Rust relay 按 Go 公式派生的 GlobalID 真实上线；
- 数据面：两包逐字节抵达、两次 associate 各收到合法 DNS 应答（复用不破坏投递）。

**字节级旁证**（`fix/scripts/wave7cone_carrier_tap.py`，TCP 裸代理抓 carrier 解帧）：
同一源两条 associate（目标 29291/29292）的 mux New 帧逐字节解析——

```text
frame#0 session=1 status=New port=29291 gid=3ec54acc43901e80
frame#1 session=2 status=New port=29292 gid=3ec54acc43901e80   ← 同源同 GID
```

**服务端复用单元锚**（已在树）：`xray-mux worker.rs::
xudp_new_same_global_id_reuses_existing_session`——同 GlobalID 第二条 New 帧命中复用、
dispatcher 恰好只调一次（不新建上游）。

## §6 Go↔Rust 双向 cone 语义（实测）

| 方向 | 上游绑定数 | 数据面 | 结论 |
|---|---|---|---|
| Rust 客户端 → Go 服务端（26.10.17） | **1** | 2/2 包逐字节、2/2 应答 | Rust relay 派生 GID → Go 按 XUDP 复用（日志样本 `XUDP new [33 99 …]`） |
| Go 客户端 → Rust 服务端 | **1** | 2/2 包逐字节、2/2 应答 | Go 客户端派生 GID → Rust `handle_xudp_new` 复用（hit-rebind，zv9l） |

两侧 cone 语义一致：同源多会话共享单条上游绑定；且 rust↔rust / go↔go 纯数据面在
`dist/interop_udp_tunnel.py` 口径不受影响（cone=on dest=29090 既有用例为同波回归项）。

## §8 harness 修正说明

1. **错误口径**：`dist/interop_udp_tunnel.py` 的 `cone=True/False` 列实为**出站 mux 开关**
   （`tunnel_outbound(cone)` 只控制是否给 outbound 加 mux 段；cone=False 根本不启 mux），
   测的是「走不走 mux carrier」，与 `xray.cone.disabled` / GlobalID 复用无关——Wave7Mux.md
   §2.3 探针实证，本票复核确认。
2. **本票修正**：新建 `fix/scripts/wave7cone_reuse_interop.py`，把「cone 开关」与
   「mux 开关」拆开：mux 固定启用，cone 语义用**上游绑定数**直接断言（复用=1 / 不复用=2），
   不再借道 harness 的 cone 列。旧的 cone 列命名保留（改 `interop_udp_tunnel.py` 属共享
   harness，另有团队在用，不宜本票顺手改语义），其局限已在本节与 Wave7Mux.md 双点登记。
3. **服务端日志不可作硬门**：Go 进程 stdout 在 terminate 时存在行丢失（本票实测：hit 行
   多次未出现在 drain 中，而同链路「XUDP new」时有时无），故日志只作样本展示，
   断言用网络面计数。

## §7 反证（回退派生 → 断言变红）

把 `MuxBridge::dispatch_with_access` 的派生分支改回恒空（恢复 4jyhm 前行为，diff 见下），
重编 release 后同一探针：

```diff
-        if dest.network() != xray_common::net::network::Network::UDP || access.from.is_empty() {
-            return self.dispatch(dest, link);
-        }
+        // REVERT-PROOF (bd kol4a 反证)：GlobalID 派生改回恒空
+        return self.dispatch(dest, link);
```

结果（2026-11-01 实测，重编 release 10m50s 后同一探针）：

```text
[FAIL] rust->go cone-reuse: upstream_peers=["127.0.0.1:55897","127.0.0.1:55899"],
       upstream_peer_count=2, xudp_new=0, xudp_hit=0, pkts=2, hex_ok=true, replies_ok=2
=== 1/2 PASS ===
[PASS] go->rust cone-reuse: upstream_peer_count=1   ← 对照组：Go 客户端自己派生 GID，
       不受 Rust 侧回退影响（复现赛跑结论：sgdkj 现象属 Go 客户端列的机理证据）
```

- 派生改回恒空 → 两条 mux session 各自 freedom 拨号 → **上游绑定数 1→2，断言红**；
- `xudp_new=0`：无 GID 上线（与 §5 改后 `XUDP new [33 99 …]` 形成改前/改后对照）；
- 数据面仍 2/2 逐字节 + 应答正常——证实「无 GID 功能不受影响，缺的是 cone 复用」；
- 还原后 `cargo check -p xray-core --lib` 通过（38.7s）。

## §9 残余风险

1. **Go cone 的入站目标钉扎未实现**（`socks/shadowsocks/trojan server.go` 的
   `if !s.cone || dest == nil`：cone 开时 dispatcher 目标钉首包）。Rust 侧 UDP relay
   仍是 per-packet 目标（`UdpDispatchSession` Keep 帧带各自真实目标）——观测差异仅在
   mux 会话的 target 字段与路由粒度，上游投递均按 per-packet 目标走（本探针 up_a/up_b
   双目标实测双向正确），故不阻塞；如需逐字节对齐 Go 再立票。
2. **非白名单协议 relay（vless/vmess/trojan/tuic/hysteria/wg）仍不带 access**——Go 同样
   不为它们派生 GlobalID（`xudp.go:69-70` 白名单外），行为一致；但这些 relay 的
   `from` 为空意味着路由 source 规则/access log 在 UDP 面缺失（Go 侧有 Source），
   属既有债，与 cone 无关，未在本票扩大改动面。
3. **tun 的源地址可伪造性**：tun relay 的 `from` 取内层 IP 源（可伪造），派生 GID 用于
   服务端会话复用键——Go 同款（tun 在白名单），风险与 Go 对齐，无新增。
4. **日志面**：Rust 服务端 hit 打点为 `info!`；生产默认日志级别若为 warning 则不可见
   （Go 同款 Info 级）。探针侧不依赖该日志。
5. **`interop_udp_tunnel.py` cone 列命名未改**（共享 harness，见 §8.2）——后续用
   `fix/scripts/wave7cone_reuse_interop.py` 作为 cone 语义的权威验收。


