VERDICT: ALREADY-FIXED（票面前提在 HEAD 不成立）——sgdkj 描述的失败在 HEAD 复现不出来（`rust→rust cone=on` 32/32 全 PASS）；缺陷本体早在波 2 `a8534efd` 已修（`handle_normal_new` 缺 XUDP 边界转换 + meta-only New 的 GlobalID 写读不对称），波 4 `707cd30e` 收敛为 `xudp_boundary_link`。本轮**未改产品代码**，只补上票面缺失的回归测试（两种入口一条用例），并取证了「撤掉修复 → 用例必红 + harness 复现上游 0 字节」。

- 执行人：MuxUdp（子代理）
- 树：`feature/fix-inbound-parity` @ `afb963f9`（工作区含其他代理未提交改动：`xray-core/src/{inbound,outbound}.rs`、`xray-proxy-http/**`、`xray-proxy-socks/src/server.rs`、`xray-xudp/src/packet.rs` — 本票未触碰）
- 构建：`CARGO_TARGET_DIR=D:/Project/Xray-core-rust/target-Wave7Mux`，`BORING_BSSL_PATH=<预构建 btls>`（release 冷编 14m51s；产物与清理见 §7）
- 改动面：`crates/xray-core/src/functions.rs`（+180 行，一条新测试；产品代码 0 行）

---

## 1. 复现

### 1.1 HEAD 实测：复现不出来

```
$ python dist/interop_udp_tunnel.py --rust target-Wave7Mux/release/xray.exe \
      --go D:/tmp/go2617/xray.exe --dest-ports 29090
[PASS] vless rust->rust cone=on dest=29090: {"proto":"vless","cone":true,"dest_port":29090,
  "upstream_count":1,"upstream_len":29,
  "upstream_hex":"123401000001000000000000076578616d706c6503636f6d0000010001",
  "upstream_hex_exact":true,"client_reply_len":45,"client_reply_dns_ok":true,"pass":true}
[PASS] dokodemo rust->rust cone=on dest=29090: {... "upstream_hex_exact":true, "pass":true}
[PASS] dns-udp   rust->rust cone=on dest=29056: {... "upstream_hex_exact":true, "pass":true}
=== 32/32 PASS  (raw -> dist/tmp_udp_tunnel/before_29090.json) ===
```

全端口跑（默认 `--dest-ports 53,443,29090`，80 例）：

```
=== 68/80 PASS  (raw -> dist/tmp_udp_tunnel/before_full.json) ===
  FAIL vless/vmess/trojan rust->go|go->rust|rust->rust|go->go cone=on dest=443  （12 条）
```

12 条失败**全部**是 `cone=on dest=443`，其中 4 条是 **Go↔Go（无 Rust 进程）** ⇒ 属票面已声明的非本仓缺陷（Go 客户端 mux + UDP:443 口径），不在本次范围。**没有任何 `rust→rust` 专属失败**。

原始 JSON 已归档：`fix/Wave7Mux-head-29090.json`、`fix/Wave7Mux-head-full.json`。

### 1.2 用「撤掉修复」重建票面失败（要因确认）

把波 2/波 4 落在 `ServerWorker::handle_normal_new` 里的边界转换临时撤掉（仅该一行，`handle_xudp_new` 不动），重编 release 得 `target-Wave7Mux/release/xray-prefix.exe`，同一 harness：

```
$ python dist/interop_udp_tunnel.py --rust target-Wave7Mux/release/xray-prefix.exe \
      --go D:/tmp/go2617/xray.exe --dest-ports 29090
[FAIL] vless rust->rust cone=on dest=29090: {"proto":"vless","cone":true,"dest_port":29090,
  "upstream_count":0,"upstream_len":0,"upstream_hex":null,"upstream_hex_exact":false,
  "client_reply_len":0,"client_reply_dns_ok":false,"pass":false, ...}
[FAIL] vmess   rust->rust cone=on dest=29090: {... "upstream_count":0,"upstream_len":0 ...}
[FAIL] trojan  rust->rust cone=on dest=29090: {... "upstream_count":0,"upstream_len":0 ...}
[FAIL] dokodemo rust->rust cone=on dest=29090: {... "upstream_count":0,"upstream_len":0 ...}
[FAIL] dokodemo go->rust cone=on dest=29090: {... "upstream_count":0,"upstream_len":0 ...}
[FAIL] dns-udp  rust->rust cone=on dest=29056: {... "upstream_count":0,"upstream_len":0 ...}
=== 26/32 PASS  (raw -> dist/tmp_udp_tunnel/prefix_29090.json) ===
```

（其余 26 例全 PASS：任意方向的 `cone=off`、`rust→go` / `go→go` 的 cone=on、以及 `go→rust` 的 socks-入口 cone=on。）

这就是票面现象：**上游 0 字节**，且严格落在「mux 客户端那侧没有 GlobalID」的组合上（§2.2）。原始 JSON：`fix/Wave7Mux-prefix-29090.json`。

---

## 2. 根因

### 2.1 缺陷本体（波 1 遗留，波 2 已修）

两套**互不兼容的内部表示**在 mux 边界相撞：

| 段 | 表示 |
|---|---|
| 内部 dispatch link（app 侧，freedom/dns/hysteria/tuic/ss/wg 消费） | **XUDP 帧**（`[2B meta_len][meta][?2B data_len][payload]`，自带 per-packet 目标） |
| mux carrier data 段（wire） | **裸载荷**（一帧 = 一个 datagram，目标在 mux 帧元数据里） |

波 1（`98c8a360`）在客户端对**所有** UDP 会话做了表示转换（`client.rs::xudp_boundary_link` 前身），但服务端只给**带 GlobalID** 的 `handle_xudp_new` 加转换，`handle_normal_new`（无 GlobalID 的 UDP 会话）把 mux 的裸载荷**原样**写进 dispatch link：

- 下行侧：freedom 拿到裸报文按 XUDP 帧解析 → `meta_len` 越界/垃圾 → 解帧失败 → **静默丢包**；
- 观测到的就是**上游 0 字节**（数据连目标都没到），客户端 5s 超时。

⇒ 只要 UDP 会话**没有 GlobalID**，这条路径必废；与入口协议、目标端口无关。修复即 `handle_normal_new` 同样过一道 `xudp_boundary_link`（波 2 `a8534efd`；波 4 `707cd30e` 把两处内联转换收敛成共享函数，并排除「域名+端口 0」的内部通道）。

同票第二处（写读不对称）也在波 2 修掉：客户端首包探测 100ms 超时会发 **meta-only New**（无 `OPTION_DATA`），写侧只要 New+UDP 就写 8B GlobalID，读侧却只在 `OPTION_DATA` 时读回 → 服务端 `global_id=None` → 又落回上面那条坏路径。`frame.rs::parse_body` 现按「无内联数据时剩余**恰 8 字节**才读 gid」补齐。

### 2.2 为什么只有 rust↔rust 红

Rust 的 UDP relay（`UdpDispatchSession`，`crates/xray-app-dispatcher/src/udp_session.rs:241`）走的是 `Dispatcher::dispatch(&udp_dest, link)`——**不带** `AccessContext`，因此：

- mux 出站拿到 `access.from` 为空 → `MuxBridge::dispatch_with_access` 早退到无源 `dispatch()` → `global_id = None`（`crates/xray-mux/src/client.rs:482`）；
- 服务端于是走 `handle_normal_new`（= 波 1 的坏路径），**不是** XUDP 路径。

实测探针（临时 `eprintln!`，已撤；`xray-mux/src/worker.rs` process_frame）：

```
[PROBE] NORMAL path udp=true gid=None target=Some(Destination { address: IPv4(127.0.0.1), port: Port(29090), network: UDP })
```

Go 客户端在 mux 下按入站会话 ctx 派生 GlobalID（`xudp.GetGlobalID`）→ 服务端走 `handle_xudp_new`（有转换）⇒ 只要 **Go 客户端那一侧的入口带会话 ctx**，就一直是通的。这直接由撤修复后的失败集合印证（§1.2）：`go→rust` 只有 **dokodemo 入口**红，socks 入口的 `go→rust` 绿。

### 2.3 「socks 通、dokodemo 不通」的真实来源：不在 Rust 侧，而由「客户端入口是否带会话 ctx」决定

判据是**客户端**那条 UDP relay 有没有 inbound 会话 ctx（→ 有没有 GlobalID），而不是 mux 服务端按入口分叉：

| 客户端 | socks 入口 | dokodemo 入口 |
|---|---|---|
| **Go** | 带 ctx → GlobalID → `handle_xudp_new`（有转换）→ 通 | 无 ctx → 无 GlobalID → `handle_normal_new` → 波 1 坏路径 → **上游 0 字节** |
| **Rust** | 无 `AccessContext`（`UdpDispatchSession`）→ 无 GlobalID → 坏路径 → **红** | 同左（同一条 relay）→ 坏路径 → **红** |

实证（§1.2 的 6 条失败）：

- `rust→rust`：vless/vmess/trojan + dokodemo + dns-udp **全红**；
- `go→rust`：socks 入口**绿**，dokodemo 入口**红**（`dokodemo go->rust cone=on ... upstream_count=0`）。

⇒ 票面「socks 通过、dokodemo 不通过」是**Go 客户端**那一列的真实现象（W1 表同格也写着 `dokodemo go→rust FAIL`），但对 **Rust 客户端**两个入口一律红：两者共用同一条 relay，没有入口特判可言：

- socks：`inbound.rs:424 handle_udp_associate` → `UdpDispatchSession::new(handler)`（`inbound.rs:429`）
- dokodemo：`inbound.rs:1820 dokodemo_peer_relay` → `UdpDispatchSession::new(handler)`（`inbound.rs:1828`）

修复（= 服务端对所有 UDP 会话做边界转换）恰好把**两侧**都覆盖：Rust 客户端两入口、Go 客户端 dokodemo 入口，一并转绿（§1.1）。

另：harness 的 `cone` 与真实 cone 语义**不等价**——`dist/interop_udp_tunnel.py::tunnel_outbound` 只在 `cone=True` 时给出站加 `mux` 段，`cone=False` 根本不启 mux（探针实测：cone=off 时 Rust mux 服务端一条 New 帧都没收到，服务端日志 4 行 vs cone=on 的 5 行）。`xray.cone.disabled` 目前唯一消费点是 `MuxBridge::dispatch_with_access` 的 `cone: !cone_disabled()`（`crates/xray-core/src/outbound.rs:925`），而 UDP relay 链路 `access.from` 为空、到不了那里 ⇒ 该 env 在本仓 UDP 路径上实际无效果。这解释了「cone=off 36/36 一直绿」：它跑的是**不经 mux** 的 plain UDP 隧道。

---

## 3. 修法

**产品代码：无改动（缺陷已在树内修好）。**

本轮新增的是一条**回归测试**，把「mux 服务端上行投递与入口无关」钉死：

`crates/xray-core/src/functions.rs::tests::integration_udp_mux_uplink_delivery_both_entry_points`

- 拓扑：客户端同时开 `socks-in(udp:true)` + `dokodemo-in(network=udp → 上游)`，共用一个 **mux 打开**的 socks 出站 → 服务端 `socks-in`（mux 终止）→ `freedom` → 上游 UDP 记录器；
- 判据：①两个入口各自的数据报**逐字节**抵达上游（记录器账本比对，= 票面的「上行送到目标」）；②各自收到回程（往返成立）；载荷用两条不同字符串，证明不是同一条被复用蒙对；
- 无入口特判：两入口走同一 `UdpDispatchSession`，用例只是把两条真实入口都驱动一遍。

（socks 侧另有既有 `integration_udp_relay_through_outbound_mux` 覆盖；本次用例额外把 dokodemo 入口纳入同一断言面，且**必须**用同一 mux 载体，避免「两个入口各开一条 carrier」把复用面测丢。）

---

## 4. 修后 harness 输出

见 §1.1（HEAD 32/32，全端口 68/80 且余下 12 条全为已声明的 `cone=on dest=443`，含 Go↔Go 对照）。

收尾用**最终源码**（探针 eprintln 已撤）重编 release 后复跑确认（`dist/tmp_udp_tunnel/after_29090.json`）：

```
$ python dist/interop_udp_tunnel.py --rust target-Wave7Mux/release/xray.exe \
      --go D:/tmp/go2617/xray.exe --dest-ports 29090
[PASS] vless    rust->rust cone=on  dest=29090: upstream_count=1, upstream_len=29, upstream_hex_exact=true, client_reply_dns_ok=true
[PASS] vless    rust->rust cone=off dest=29090: 同上
[PASS] vmess    rust->rust cone=on/off dest=29090: 同上
[PASS] trojan   rust->rust cone=on/off dest=29090: 同上
[PASS] dokodemo rust->rust cone=on  dest=29090: 同上
[PASS] dns-udp  rust->rust cone=on  dest=29056: 同上
=== 32/32 PASS ===
```

`cargo test -p xray-mux --all-targets`：

```
running 145 tests
test result: ok. 145 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
running 23 tests
test result: ok. 23 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

`cargo clippy -p xray-mux --all-targets -- -D warnings`：

```
    Checking xray-mux v0.1.0 (D:\Project\Xray-core-rust\crates\xray-mux)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 42.51s
```

（零告警；`rustls` 的 2 条 warning 来自 `vendor/` 红线依赖，非本票面。）

新测试所在 crate 的宽门同样通过（含同箱代理在途改动）：

```
$ cargo clippy -p xray-core --all-targets -- -D warnings
    Checking xray-core v0.1.0 (D:\Project\Xray-core-rust\crates\xray-core)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 1m 36s
```

fmt：`rustfmt --check crates/xray-core/src/functions.rs` → 干净（新增块已按仓内 `rustfmt.toml` 格式化；同箱代理 InputHardening 报的 4 处 fmt diff 即此块，已消）。

### 验收项 ↔ 证据对照

| 票面验收 | 证据 |
|---|---|
| ① 修前 FAIL 原始 JSON（含 upstream 0 字节） | §1.2 `fix/Wave7Mux-prefix-29090.json`（26/32，5 条 rust→rust `upstream_count=0/len=0`） |
| ② 修后 harness PASS | §1.1 / §4：`--dest-ports 29090` → 32/32 |
| ③ `cargo test -p xray-mux --all-targets` | §4：145 + 23 passed，0 failed |
| ④ `cargo clippy -p xray-mux --all-targets -- -D warnings` | §4：零告警 |
| ⑤ 新增回归测试（修前必红） | §5：撤修复 → `timeout waiting for socks udp echo` 红；HEAD → 1 passed |


---

## 5. 回归测试与反证

| 状态 | 命令 | 结果 |
|---|---|---|
| 修前（撤掉 `handle_normal_new` 的边界转换） | `cargo test -p xray-core --lib integration_udp_mux_uplink_delivery_both_entry_points` | **FAILED**：`panicked at crates\xray-core\src\functions.rs:6153: timeout waiting for socks udp echo`（撤修复时行号，fmt 后为 6150）；`test result: FAILED. 0 passed; 1 failed` |
| 修后（HEAD） | 同上 | `test result: ok. 1 passed; 0 failed`（finished in 0.27s） |

反证说明：撤掉一行产品代码 → 用例 5s 超时变红（上行没到目标，两个入口都断在同一条路径上：socks 分支先跑先超时）；恢复该行 → 绿。同一撤除状态下 harness 也复现票面的上游 0 字节（§1.2），两侧证据互相印证。

---

## 6. 残余观察（不属本票范围，交 PM 分流）

1. **Rust UDP relay 不派生 GlobalID**：`UdpDispatchSession` 不带 `AccessContext`，`MuxBridge` 只能走无源 `dispatch()` ⇒ cone/GlobalID 会话复用（同源多目标共享一条 UDP 通道）在 Rust 客户端**从未生效**；功能不受影响（无 gid 也正确投递），但缺一次 Go `xudp.GetGlobalID(ctx)` 等价语义。定位面 = inbound/dispatcher 的 access 填充（socks `handle_udp_associate` / dokodemo `dokodemo_peer_relay` 把 peer 传进 relay），不属 mux crate。
2. **harness 的 cone 命名与真实 cone 语义错位**：`cone=False` 实际是「不启 mux」，`xray.cone.disabled` 在本仓 UDP 路径上无消费点（见 §2.3）。若后续要真测 cone，需要把「mux 开关」与「cone 开关」拆成两个维度。
3. `cone=on dest=443` 12 条红（含 Go↔Go）为既有面，票面已声明非本仓缺陷。

---

## 7. 环境与产物

- Rust：`target-Wave7Mux/release/xray.exe`（HEAD 源码，release，`git_rev=afb963f94f58f0a75bbc753f76c45ba9b42a5f8f`）
- 修前对照二进制：`target-Wave7Mux/release/xray-prefix.exe`（§1.2 用，收尾已删除）
- Go 裁定基准：`D:/tmp/go2617/xray.exe`（26.10.17 `92ccc93`）
- 证据 JSON：`fix/Wave7Mux-head-29090.json`（HEAD 32/32）、`fix/Wave7Mux-head-full.json`（HEAD 68/80）、`fix/Wave7Mux-prefix-29090.json`（撤修复后 26/32，含上游 0 字节）
- harness：`dist/interop_udp_tunnel.py` 未改动（临时探针脚本在 `D:/tmp/`，未入库）
- codebase-memory 图谱：本轮只新增一条测试函数，未单独重索引（同箱多代理在途改动会一起被吸进索引，留战役收尾统一 `index_repository`）
- 磁盘：`target-Wave7Mux`（11G，本代理独占 CARGO_TARGET_DIR）与 `target-Wave7MuxLint`（clippy 独立目录）按派单契约**收尾已删除**；重跑验证请按仓内构建配方重编（`BORING_BSSL_PATH=<预构建 btls>` + `cargo build --release -p xray-cli`，约 12-15 分钟）
