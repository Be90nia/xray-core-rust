VERDICT: FIXED — 波1（`98c8a360`）两处 mux 边界缺口已最小修复，t0ls1 四处帧转换契约**未回退**；`cargo test -p xray-core --lib mux` 21 passed / 0 failed，两条目标测试单跑亦绿，`xray-mux`+`xray-xudp`+`xray-app-dispatcher` 334 passed / 0 failed，UDP 隧道互通 68/80（12 条失败全为 cone=on dest=443，且 **Go↔Go 同样失败** = 既有行为，与本改动无关），fmt/clippy 绿。

- 修复人：MuxRegress（子代理）
- 树：`feature/fix-inbound-parity` @ `98c8a360`（工作区含其他代理未提交改动：`xray-tls/**`、`xray-proxy-socks/src/protocol.rs`、`xray-proxy-vless/src/encoding/mod.rs`、`xray-transport/src/finalmask/**`、`xray-core/src/{outbound,register}.rs` — 本票未触碰）
- 改动面：`crates/xray-mux/src/frame.rs`、`crates/xray-mux/src/worker.rs`（+59 / −3，共 2 文件）

---

## 1. 根因（两处，均源自波1 的 t0ls1 边界转换只做了一半）

波1 在 `xray-mux/src/client.rs` 把 **UDP 会话的 app 侧 link 无条件**裹成
「内部 XUDP 帧 ↔ wire 裸载荷」(`XudpUnframingReader` / `XudpFramingWriter`)，
但在服务端只给 `handle_xudp_new`（带 GlobalID 的会话）加了同款转换，
并留下了一处**写读不对称**。两个失败测试各命中一处。

### 1.1 失败测试 A：`mux_bridge_dispatch_with_access_carries_global_id_for_udp`（`left=None`）

**定位链（不是猜，实跑取证）**：临时在 `ClientWorker::dispatch_with_source` 与
`MuxWriter::get_next_frame_meta` 插 `eprintln!` 重跑该测试，得到

```
[DBG client] dest=Destination { address: IPv4(8.8.8.8), port: Port(53), network: UDP } input_src=Some("udp:10.0.0.9:5555") gid=Some([139, 185, 245, 10, 165, 119, 178, 0])
[DBG writer] id=1 status=New gid=Some([139, 185, 245, 10, 165, 119, 178, 0]) dest=Some(Destination { ... network: UDP })
assertion `left == right` failed: UDP New frame must carry source-derived GlobalID
  left: None
 right: Some([139, 185, 245, 10, 165, 119, 178, 0])
```

⇒ **GlobalID 在写侧是 `Some`，是「写进去了读不回来」**，不是没算出来。

机制：
1. 波1 之后客户端 app 侧 link 是 `XudpUnframingReader`。测试写入的 `b"probe"`
   （5B）不是完整 XUDP 帧 → 拆帧器留在 `accum`，首读阻塞。
2. `fetch_input` 的首包探测（Go `writeFirstPayload` 100ms）超时 → 走
   `write_meta_only()`，发出**无 `OPTION_DATA` 的 meta-only New 帧**。
3. `FrameMetadata::write_bytes_into`（Go `common/mux/frame.go:100`
   `else if b.UDP != nil`）只要 New + UDP 就写 8B GlobalID — **与 option 无关**；
   而 `parse_body` 照 Go `frame.go:215` 只在 `OptionData` 置位时才读回。
   波1 之前这条路径不可达：首帧恒有内联数据（`b"probe"` 直接进 data 段），
   `has_data()==true` 掩盖了不对称。

### 1.2 失败测试 B：`integration_udp_relay_through_outbound_mux`（`timeout waiting for udp via outbound mux echo`）

同款 `eprintln!` 取证：

```
[DBG client] dest=Destination { address: IPv4(127.0.0.1), port: Port(51088), network: UDP } input_src=None gid=None
[DBG writer] id=1 status=New gid=None dest=Some(... network: UDP })
```

⇒ 这一条**根本没有 GlobalID**（该链路 `AccessContext.from` 为空 → 走无源
`dispatch()`，`input=None`），即服务端落 `handle_normal_new`；
而波1 只在 `handle_xudp_new` 里做了「裸载荷 → XUDP 帧」转换。客户端已经把
wire 换成裸载荷（对 UDP 无条件裹/剥），服务端普通路径却把裸报文直接交给
freedom（`xray-proxy-freedom/src/udp.rs` 按 XUDP 帧解析）→ 解帧失败静默丢包
→ 上行到达、无回程 → 超时。这正是 Verify-XUDP 报告里
「Rust mux 服务端把 data 段裸载荷直接交给 freedom → 上游 0 字节」的残留面。

---

## 2. 修复（两处，均为增量，不动 t0ls1 契约）

### 2.1 `crates/xray-mux/src/frame.rs`（`parse_body`，659-679）

GlobalID 读侧与**本仓写侧**对齐：

```rust
let remaining = body.len().saturating_sub(offset);
let gid_present = if meta.has_data() { remaining >= 8 } else { remaining == 8 };
if meta.is_udp_target() && gid_present { ... }
```

- 有内联数据：保持 Go 语义（`remaining >= 8`）不变。
- 无内联数据（meta-only New）：只在剩余**恰好 8 字节**时读 —— New 帧 meta 在
  目标地址后除 GlobalID 外无其它字段，长度精确为 8 即该帧必是 gid 帧
  （写侧永远只写 8 或不写）。这样既不误读 Keep/End 帧，也不误读带
  reverse-mux source/local 的帧（那类在 `read_source_and_local=true` 路径
  先行返回）。
- 新增回归测试 `frame::tests::test_new_udp_frame_with_global_id_and_no_data_roundtrip`
  （meta-only New 读回 gid + 无 gid 时不得凭空拼出 gid）。

### 2.2 `crates/xray-mux/src/worker.rs`（`handle_normal_new`，278-290）

对所有 UDP 目标会话做与 `handle_xudp_new` 相同的边界转换：

```rust
let link = if target.network() == Network::UDP {
    Link {
        reader: Box::new(XudpUnframingReader::new(link.reader)),
        writer: Box::new(XudpFramingWriter::new(link.writer, target.clone())),
    }
} else { link };
```

理由：波1 的 wire 侧表示（裸载荷）对**所有** UDP 会话成立（客户端侧转换
不看 GlobalID），GlobalID 只是「cone 会话复用」的优化键，不是「要不要转换」
的判据。既有测试 `worker::tests::udp_new_small_first_frame_immediate`
（无 gid 的普通 UDP 路径）同步改为断言「上行 = XUDP 帧、载荷逐字节还原」。

**未回退项**：`client.rs` 的客户端裹/剥帧、`handle_xudp_new` 的服务端转换、
`udp_session.rs` 的四个适配件（`XudpUnframingReader`/`XudpFramingWriter`/
`XudpUnframer`/`XudpWireConn`）全部原样保留。

---

## 3. 验证（真实命令 + 原始输出）

### 3.1 `cargo test -p xray-core --lib mux`
```
running 22 tests
test outbound::tests::mux_bridge_dispatch_with_access_carries_global_id_for_udp ... ok
test functions::tests::integration_udp_relay_through_outbound_mux ... ok
test result: ok. 21 passed; 0 failed; 1 ignored; 0 measured; 490 filtered out; finished in 0.24s
```
（ignored 为 `vless_mux_go_server_interop`，需 Go xray + echo 编排，波1 起即 ignored）

### 3.2 两条目标测试单跑
```
test outbound::tests::mux_bridge_dispatch_with_access_carries_global_id_for_udp ... ok
test result: ok. 1 passed; 0 failed; ... finished in 0.13s

test functions::tests::integration_udp_relay_through_outbound_mux ... ok
test result: ok. 1 passed; 0 failed; ... finished in 0.23s
```

### 3.3 `cargo test -p xray-mux -p xray-xudp -p xray-app-dispatcher --lib`
```
test result: ok. 147 passed; 0 failed; 0 ignored   (xray-mux)
test result: ok. 144 passed; 0 failed; 0 ignored   (xray-xudp)
test result: ok.  43 passed; 0 failed; 0 ignored   (xray-app-dispatcher)
```

### 3.4 反向证明不破 t0ls1：`python dist/interop_udp_tunnel.py --rust target-muxfix/debug/xray.exe --go D:/tmp/go2617/xray.exe`
（本次改动的 debug 二进制 `cargo build -p xray-cli` 产出；Go = `26.10.17 92ccc93`）
```
=== 68/80 PASS ===
  FAIL vless  rust->go cone=on dest=443 [retry]
  FAIL vless  go->rust cone=on dest=443 [retry]
  FAIL vless  rust->rust cone=on dest=443 [retry]
  FAIL vless  go->go   cone=on dest=443 [retry]
  FAIL vmess  rust->go cone=on dest=443 [retry]
  FAIL vmess  go->rust cone=on dest=443 [retry]
  FAIL vmess  rust->rust cone=on dest=443 [retry]
  FAIL vmess  go->go   cone=on dest=443 [retry]
  FAIL trojan rust->go cone=on dest=443 [retry]
  FAIL trojan go->rust cone=on dest=443 [retry]
  FAIL trojan rust->rust cone=on dest=443 [retry]
  FAIL trojan go->go   cone=on dest=443 [retry]
```
- **cone 关 36/36 全 PASS**（3 协议 × 4 向 × dest{53,443,29090}），逐字节判据
  `upstream_hex_exact=true`（29B 裸 DNS 查询）+ `upstream_count=1`（不放大）
  + 客户端 `client_reply_dns_ok=true`。
- 附加面全 PASS：`dokodemo` 4/4、`dns-udp` 4/4、cone=on 的 dest=53/29090 全部
  Rust 参与用例 PASS（含 Rust→Go、Go→Rust 双向 cone/mux 路径）。
- 12 条失败**全部**是 `cone=on dest=443`，其中 4 条是 **Go↔Go**（无 Rust 进程），
  ⇒ 属既有 cone/mux 边界的 443 语义问题（波1 的正式验收门也只声明
  「cone 关 36/36」），与本改动无关，本票未扩大范围处理。

### 3.5 静态门（本票触碰的三个 crate）
```
cargo fmt -p xray-mux -p xray-xudp -p xray-app-dispatcher -- --check   → exit=0
cargo clippy -p xray-mux -p xray-xudp -p xray-app-dispatcher --all-targets -- -D warnings
  → Finished `dev` profile ... （`rustls` 2 条 warning 来自 vendor/rustls 红线依赖，非本票代码）
```

---

## 4. 残余观察（未在本票范围，交给 PM 分流）

1. `AccessContext.from` 在「socks 入站 UDP relay → mux 出站」链路上为空
   （3.2 的 `input_src=None` 取证），因此该入口不会派生 GlobalID、cone 会话
   复用不生效；功能上不影响（2.2 已让无 gid 的 UDP 会话也能正确走
   XUDP 边界转换），但与 Go `xudp.GetGlobalID(ctx)` 的「有入站 ctx 即派生」
   语义仍有差距。定位面在 inbound/dispatcher 的 access 填充，不属本票文件面。
2. `cone=on dest=443` 的 12 条互通失败见 3.4，含 Go↔Go 对照，属既有面。

## 5. 环境
构建/测试环境变量（btls 预构建跳过 cmake）：
`BORING_BSSL_PATH=target/boringssl-asm/prebuilt`、`BORING_BSSL_ASSUME_PATCHED=1`、
`PROTOC=D:/Project/tools/bin/protoc.exe`、`LIBCLANG_PATH="D:/Program Files/llvm/bin"`、
`CARGO_TARGET_DIR=target-muxfix`（收尾已删除）。
互通产物：`dist/tmp_udp_tunnel/interop_udp_tunnel.json`（harness 自写）。

---

# 附录 A — 追加修复：`xray-app-reverse::portal_worker` 两条测试（§2.2 的过度转换）

**结论：父提交 `5fe98b90` 绿（2 passed）→ 红由本票引入（不是 `30c03adf` 既有债），已在附录修好。**

## A.1 归因（worktree 实测，非推断）

```
git worktree add D:/tmp/wt-prev 5fe98b90
mklink /J D:\tmp\wt-prev\crates\udf-frame D:\Project\Xray-core-rust\crates\udf-frame
CARGO_TARGET_DIR=D:/Project/Xray-core-rust/target-wtprev cargo test -p xray-app-reverse --lib portal_worker
→ running 2 tests
  test worker::entity_tests::portal_worker_heartbeat_sends_control_on_internal_dest ... ok
  test worker::entity_tests::portal_worker_drains_over_threshold_and_disposes ... ok
  test result: ok. 2 passed; 0 failed        (5fe98b90)
```

**机理**：reverse 的**内部控制流**是一条 UDP 会话，目标 `reverse:0`
（Go `app/reverse/portal.go:241` `net.UDPDestination(net.DomainAddress("reverse"), 0)`），
载荷是**裸 `ProtoControl` protobuf**。波1 的转换只看 `dest.network()==UDP` 就裹/剥帧，
§2.2 又把服务端 `handle_normal_new` 扩成「所有 UDP 都转换」⇒ 控制流 protobuf 被当
XUDP 帧处理：客户端上行 `XudpUnframingReader` 把 protobuf 前两字节当 `meta_len` 解失败
（`Eof`），服务端下行侧多套一层帧头（`control payload within timeout`）。

## A.2 修法：按「是否内部目标」判定，而非按「是否 UDP」

判据：

- Xray 内部通道用 **域名地址 + 端口 0** 标记（`portal.go:241` UDP `reverse:0`；
  `bridge.go:116` TCP `DomainAddress(domain):0`）。端口 0 不是可投递的网络目标
  ⇒ 这类会话**永不进入 outbound**，载荷契约由控制面自己定义。
- 故 t0ls1 的「裸载荷 ↔ XUDP 帧」只对**会进 outbound 的真实 UDP 目标**成立；内部目标
  两侧都保持裸载荷。**这是硬要求**：Go 侧 reverse 控制流同样是裸 protobuf，Rust 单方面
  裹帧会直接破 reverse portal↔bridge 与 Go 的互通。

实现（`crates/xray-mux` 内自洽，无开关、无 feature 门）：

- `client.rs:74-82` 新增 `pub(crate) fn is_internal_target(&Destination)`（域名 + 端口 0）；
- `client.rs:84-102` 新增 `pub(crate) fn xudp_boundary_link(Link, &Destination) -> Link`
  ——**唯一**转换入口（非 UDP 或内部目标 → 原样返回），三处调用点统一走它：
  `client.rs:470`（客户端）、`worker.rs:284`（`handle_normal_new`）、
  `worker.rs:390`（`handle_xudp_new`）；顺带消掉波1 与 §2.2 重复的 6 行裹/剥帧块；
- 新增回归测试 `worker::tests::udp_internal_target_new_frame_stays_raw`
  （内部目标 + GlobalID 的 New 帧 → 派发出的载荷逐字节等于裸 protobuf）。

## A.3 验证

```
cargo test -p xray-mux -p xray-xudp -p xray-app-dispatcher -p xray-app-reverse --lib
  test result: ok. 148 passed; 0 failed
  test result: ok.  93 passed; 0 failed      (xray-app-reverse，含两条 portal_worker)
  test result: ok. 145 passed; 0 failed
  test result: ok.  38 passed; 0 failed
  （与逐包跑相比计数有 ±：本命令 feature unification 不同，非用例增减）

cargo test -p xray-app-reverse --lib portal_worker
  portal_worker_heartbeat_sends_control_on_internal_dest ... ok
  portal_worker_drains_over_threshold_and_disposes ... ok
  test result: ok. 2 passed; 0 failed

cargo test -p xray-core --lib mux
  test result: ok. 21 passed; 0 failed; 1 ignored      ← §1 的两条修复未回退

cargo fmt -p xray-mux -p xray-app-reverse -p xray-xudp -p xray-app-dispatcher -- --check → exit 0
cargo clippy -p xray-mux -p xray-app-reverse -p xray-xudp -p xray-app-dispatcher \
  --all-targets -- -D warnings → Finished，零告警

python dist/interop_udp_tunnel.py --rust target-revfix/debug/xray.exe --go D:/tmp/go2617/xray.exe
  === 68/80 PASS ===   （与 §3.4 逐条同结果：cone 关 36/36 全 PASS；12 条失败仍是
   cone=on dest=443 且含 Go↔Go 4 条 = 既有面）
```

## A.4 环境/并发声明

- 验证期间 `crates/xray-mux/{Cargo.toml,session.rs,client.rs}` 出现**其他代理**的未提交
  改动（bd 86i4h 阶段2：`compat::spawn_reaping` 替换 `spawn_tracked`）。本附录未触碰这些行；
  上述绿灯均在该混合树上跑出（clippy 亦通过）。
- worktree `D:/tmp/wt-prev`、`target-wtprev`、`target-revfix` 用完已删除。
