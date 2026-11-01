VERDICT: PASS — f2ap9 与 itd0p 均已修复并 E1 实测（修复前红/修复后绿，单变量对照齐全）；三 crate lib 测试绿（唯一红为基线已红的环境性用例，非本单引入，见 §4）。

# 环境与工作树

- 工作树 `D:/Project/Xray-core-rust`，分支 `feature/fix-inbound-parity`，HEAD `98c8a360`。
- 本单文件面：`crates/xray-proxy-socks/src/protocol.rs`、`crates/xray-proxy-vless/src/encoding/mod.rs`、
  `crates/xray-transport/src/finalmask/xdns/{server.rs,mod.rs}`、**新增共用 helper 落**
  `crates/xray-common/src/net/address.rs`（`ip_literal`，Go `common/net` 同源位；无新文件）。
- 未触碰 G1 面（`xray-core/src/{functions,outbound,register}.rs`、`xray-app-router/router.rs`、`xray-app-commander/**`）与 G6 面（`xray-tls/**`、TLS 组装点）。
- 构建环境 `CARGO_TARGET_DIR=target-P0wire`（结束时删除），
  `BORING_BSSL_PATH=target/boringssl-asm/prebuilt`（btls 走预构建，跳过 cmake）。

---

# 票 f2ap9 — SOCKS5/VLESS 入站不归一化 IP 字面量

## 根因核对

`Address::ip()` 只在 IP 变体返回 `Some`；dispatcher 建 routing 上下文时
`crates/xray-app-dispatcher/src/default.rs:803-806`：

```rust
match dest.address().ip() {
    Some(ip) => ctx.target_ips = vec![ip],
    None => ctx = ctx.with_target_domain(...),
}
```

→ 目标以 `Address::Domain("192.168.89.180")` 形态到达时 `target_ips` 恒空 →
`IPMatcherCondition::apply`（`crates/xray-app-router/src/condition.rs:222-227`）
对空切片恒 false → `ip` 规则永不命中。Go 在 `common/protocol/address.go:213-217`
（`addressParser.readAddress` 的 Domain 分支）用 `maybeIPPrefix` + `ParseAddress` 归一化，
Rust 两个入站解析器都缺这一步。

## 改动

1. `crates/xray-common/src/net/address.rs:141-162` — 新增 `pub fn ip_literal(s: &str) -> Option<IpAddr>`，
   逐条对齐 Go：`maybeIPPrefix`（首字节 `[` 或数字才尝试）→ `[v6]` 去括号 → 首/尾非字母数字时
   `TrimSpace` → `parse::<IpAddr>()`。共用 helper 放 `xray-common`（Go 同层 `common/net/address.go`），
   socks/vless 已有该依赖，**未改任何 Cargo.toml**。
2. `crates/xray-proxy-socks/src/protocol.rs:236-256` — `parse_address_port` 的 `ATYP_DOMAIN` 分支
   先归一化（**先于** `is_valid_domain_bytes` 字符集校验，与 Go 同序），命中 IP 走 `Host::Ipv4/Ipv6`，
   否则保留 `Host::Domain`。`parse_address_port_from_stream`（TCP 握手）与
   `decode_udp_packet`（UDP relay）都复用同一函数 → 两条路径一并修好。
3. `crates/xray-proxy-vless/src/encoding/mod.rs:168-181` — `read_address_port` 的
   `addr_type::DOMAIN` 分支同一归一化：命中 IP 走 `Address::IPv4/IPv6`，否则 `Address::Domain`。
4. 回归测试：`protocol.rs:465-495`（socks，IPv4 字面量 / `[::1]` / `1.2.3.4.example.com` 三态）、
   `encoding/mod.rs:366-399`（vless 同三态，`read_address_port` 直测）。

## E1 端到端（真实二进制 + 真实路由 + 真实客户端）

构建：`cargo build --release -p xray-cli` → `target-P0wire/release/xray.exe`（13m35s）。
「修复前」用树内既有二进制 `target/release/xray.exe`（2026-10-31 11:00 build，rev 98c8a360，
早于全部改动文件 mtime，即无修复版本），**同一份配置、同一份客户端逐字重跑**。

服务端配置（`D:/tmp/p0wire/f2ap9_server.json`，两侧完全一致，单变量）：

```json
"routing": {"domainStrategy":"AsIs",
  "rules":[{"type":"field","ip":["192.168.89.180/32"],"outboundTag":"blocked"}]},
"inbounds":[
  {"protocol":"socks","listen":"127.0.0.1","port":18301,"settings":{"auth":"noauth"}},
  {"protocol":"vless","listen":"127.0.0.1","port":18302,"settings":{"clients":[{"id":"5c1e9d17-ee1e-4b1a-a1c8-7d0fca0a44ee"}],"decryption":"none"}}],
"outbounds":[
  {"protocol":"freedom","tag":"direct","settings":{"finalRules":[{"action":"allow"}]}},
  {"protocol":"blackhole","tag":"blocked"}]
```

干扰变量按要求排除：目标**不用** `127.0.0.1`（用本机 LAN `192.168.89.180:18400`，echo 服务实时在线）；
freedom **显式** `finalRules:[{action:"allow"}]`（Rust VLESS 入站默认注入 BlockPrivate 的逃生门）。
客户端用 `ATYP=DOMAIN` 承载 `"192.168.89.180"`（`socks5_domain_client.py` / `vless_domain_client.py`，
脚本自带请求字节构造，见 `D:/tmp/p0wire/`）。

修复前（`target/release/xray.exe`）：

```
--- SOCKS5 (domain-form IP 192.168.89.180) ---
connect_reply=050000017f000001477d rep=0
echo=b'ECHO:PING-P0WIRE'
RESULT=ECHO_OK(leak)
--- VLESS (domain-form IP 192.168.89.180) ---
raw=b'\x00\x00ECHO:PING-P0WIRE'
RESULT=ECHO_OK(leak)
```
服务端日志同步佐证目标被当**域名**处理（走系统 DNS 解析后才拨号）：
```
DEBUG target=192.168.89.180:18400 resolving domain via system DNS
DEBUG target=192.168.89.180:18400 addrs=[192.168.89.180:18400] domain resolved
```

修复后（`target-P0wire/release/xray.exe`）：

```
--- f2ap9 AFTER ip-rule: SOCKS5 ---
connect_reply=050000017f000001477d rep=0
echo=b''
RESULT=NO_ECHO(blocked)
--- f2ap9 AFTER ip-rule: VLESS ---
raw=b'\x00\x00'
RESULT=NO_ECHO(blocked) head=0000 len=2
```
修复后日志**无**任何 `resolving domain via system DNS` 行 → 流量在 freedom 之前已被 blackhole 吃掉。

### 对照证明（票面要求的「只有 ip 条件失效」）

| 运行 | 二进制 | 规则 | SOCKS5 | VLESS |
|---|---|---|---|---|
| A | 修复前 | `ip:["192.168.89.180/32"]` | ECHO_OK（leak） | ECHO_OK（leak） |
| B | 修复前 | `port:"18400"` | NO_ECHO（blocked） | NO_ECHO（blocked） |
| C | 修复后 | `ip:["192.168.89.180/32"]` | NO_ECHO（blocked） | NO_ECHO（blocked） |
| D | 修复后 | `ip:["10.9.9.9/32"]`（不匹配） | ECHO_OK（leak） | ECHO_OK（leak） |

- B：`port` 条件修复前后都正常拦截 → 路由链路本身没问题，失效的只有 `ip`。
- D：同一二进制把不匹配的 ip 换成匹配值即从 leak 翻成 block → **block 由 ip 条件命中产生**，
  排除「服务端坏了/黑名单误伤」等替代解释。
- 修复后 ip 命中面变宽（原先靠漏匹配放行的部署行为会变），按票面要求 PM 需知悉。

---

# 票 itd0p — xdns finalmask 分片长度门 off-by-two

## 根因核对

`server_read`（`crates/xray-transport/src/finalmask/xdns/server.rs`）的长度门只要求
`flag8==3 → n >= 9+3+1 = 13`，但分片路径随后取 `decoded[12]`/`decoded[13]`/`decoded[14]` 与
`&decoded[15..n]`，实际需要 `n >= 15`。n∈[13,14] 时 `decoded[13]` 直接 panic，panic 发生在
`recv_loop` 的 `server_read` 内 → 整个 recv 任务死亡 → `recv_from` 永久挂起（隧道永久失聪，
后续重传全部超时且不自动恢复）。Go 用 `[255]byte` 定长数组规避 `[13]`/`[14]`，但其
`decoded[15:n]` 同样越界（上游同缺陷，Rust 侧按票面要求修对不复刻）。

## 改动

`crates/xray-transport/src/finalmask/xdns/server.rs`：

1. `:40-44` 新增 `const FRAG_MIN_DECODED_LEN: usize = 15;`（含"Go 上游同点越界"注释）。
2. `:243-256` 长度门按实际切片边界重算：新增 `let fragmented = decoded[8] & 0xC0 == 0xC0;` 与
   `|| (flag8 == 3 && fragmented && n < FRAG_MIN_DECODED_LEN)`，越界包走既有
   `decref(state, ok_header(msg), addr)` 分支 → **回空成功响应且不 panic**。
3. `:268-287` 分支体改为 `fragmented` 标志 + `decoded.get(12..15)` 解出 `(frag_id, frag_idx, frag_n)`，
   数据段用 `decoded.get(15..).unwrap_or_default()` —— **该分支内不再出现任何 `decoded[i]` 直接索引**
   （`decoded[13]` 消失），即使长度门将来被改动也不会 panic。
4. 回归测试 `crates/xray-transport/src/finalmask/xdns/mod.rs:437-484`：
   `short_fragment_query()` 现构造票面同款 **53 字节** DNS 查询（解码 13 字节、`[8]=0xC3`），
   `short_fragment_query_keeps_recv_task_alive` 连续发 3 次，每次都必须收到响应（QR 置位）。

## E1 端到端（真实二进制 + 真实 UDP + 生产 finalmask 装配）

配置 `D:/tmp/p0wire/xdns_server.json`：`shadowsocks` 入站 + `streamSettings.finalmask.udp=[{type:"xdns",
settings:{domains:[{name:"abcdefghijklm",types:[16]}]}}]`（这条是 `inbound.rs:2105`
`wrap_packet_conn_server` 的生产接线路径），探针 `D:/tmp/p0wire/xdns_probe.py` 直接从本机 UDP
发那 53 字节查询。

修复前（`target/release/xray.exe`）：

```
query_len=53 decoded_len=13
round1: RESPONSE 65B in 1012.0ms id=1234 flags=8400 rcode=0   ← panic 前已入队的 Rec，1s 攒包超时后的空应答
round2: TIMEOUT (no reply in 2.0s)
round3: TIMEOUT (no reply in 2.0s)
answered=1/3
```
服务端 stderr（panic 原文）：
```
ERROR task panicked thread="tokio-rt-worker" location=crates\xray-transport\src\finalmask\xdns\server.rs:269 panic=index out of bounds: the len is 13 but the index is 13

thread 'tokio-rt-worker' (13404) panicked at crates\xray-transport\src\finalmask\xdns\server.rs:269:47:
index out of bounds: the len is 13 but the index is 13
```
`round2/3` 全超时 = panic 后永久失聪（复现票面「隧道永久失聪」）。

修复后（`target-P0wire/release/xray.exe`）：

```
query_len=53 decoded_len=13
round1: RESPONSE 53B in 0.5ms id=1234 flags=8400 rcode=0
round2: RESPONSE 53B in 0.4ms id=1234 flags=8400 rcode=0
round3: RESPONSE 53B in 0.4ms id=1234 flags=8400 rcode=0
answered=3/3
```
服务端 stderr 全程无 panic（`PANIC_IN_LOG= False`，仅 2 行启动 INFO）。3/3 即时应答 = recv 任务存活。

---

# 验证命令与关键输出

```bash
export BORING_BSSL_PATH=D:/Project/Xray-core-rust/target/boringssl-asm/prebuilt
export BORING_BSSL_ASSUME_PATCHED=1
export PROTOC=D:/Project/tools/bin/protoc.exe
export LIBCLANG_PATH="D:/Program Files/llvm/bin"
export CARGO_TARGET_DIR=D:/Project/Xray-core-rust/target-P0wire
```

1) 票面原命令：`cargo test -p xray-proxy-socks -p xray-proxy-vless -p xray-transport --lib`
```
test result: ok.     87 passed;  0 failed; 1 ignored   (xray-proxy-socks)
test inbound::server::tests::vless_outbound_udp_roundtrip_e2e ... FAILED
test result: FAILED. 294 passed; 1 failed; 1 ignored   (xray-proxy-vless)
error: test failed, to rerun pass `-p xray-proxy-vless --lib`   ← cargo 在首个失败 crate 后停止，transport 未跑
```
2) 同一命令跳过该失败用例：`... -- --skip vless_outbound_udp_roundtrip_e2e`
```
test result: ok. 87  passed; 0 failed; 1 ignored; 1 filtered out   (socks)
test result: ok. 294 passed; 0 failed; 1 ignored; 1 filtered out   (vless)
test result: ok. 675 passed; 0 failed; 2 ignored                    (xray-transport)
```
3) 新增用例点名：`cargo test -p xray-transport --lib xdns` →
   `test finalmask::xdns::tests::short_fragment_query_keeps_recv_task_alive ... ok`（38 passed）；
   `cargo test -p xray-proxy-vless --lib test_read_address_normalizes` →
   `test encoding::tests::test_read_address_normalizes_domain_form_ip_literal ... ok`；
   socks `parse_normalizes_domain_form_ip_literal` 随 87 passed 一并绿。
4) clippy：`cargo clippy -p xray-common -p xray-proxy-socks -p xray-proxy-vless -p xray-transport --all-targets -- -D warnings`
   → `Finished dev profile in 48.88s`，本仓 crate 零告警（仅 vendored `vendor/rustls` 既有 2 条）。
5) fmt：`cargo fmt --all -- --check` → 本单 5 个文件零 diff。

# §4 关于那条红用例（非本单引入，已实证）

`crates/xray-proxy-vless/src/inbound/server.rs::vless_outbound_udp_roundtrip_e2e`
（`:1322` `read: Custom { kind: UnexpectedEof, error: "early eof" }`，稳定 0.5s 内可复现）：
把本单 5 个文件的改动 `git stash push -- <这 5 个文件>` 后在**同一 target 目录**重跑该用例，结果逐字相同
（`test result: FAILED. 0 passed; 1 failed`），随后 `git stash pop` 原样恢复。
该用例目标是 `Address::from_ipv4_bytes`（ATYP=IPv4），不经过本单改动的 DOMAIN 分支，
故判为**基线既红的环境性失败**，不由本单引入，也未在本单修复（非目标：不越界）。

# 非目标 / 未做

- 未改 routing 匹配器（`xray-app-router/router.rs`）、未改 freedom 策略、未改 Go 上游缺陷。
- 未把同一归一化推广到 vmess/trojan/ss/http 等其它入站的 domain 分支，也未改
  `xray-common::protocol::AddressParser::read_address`（该函数是 Go `addressParser` 的通用镜像，
  同样缺归一化；本次按票面只修 socks/vless 两个入站，其余留作后续票，
  避免一次性放宽全部协议的既有行为面）。
- 未修复 `vless_outbound_udp_roundtrip_e2e`（基线已红，见 §4）。
- 未 commit（按契约留给上级）。

# 证据脚本位置（未入库，按项目惯例留 tmp）

`D:/tmp/p0wire/`：`xdns_probe.py`、`xdns_server.json`、`f2ap9_server.json`、
`f2ap9_ctrl_port.json`、`f2ap9_ctrl_otherip.json`、`socks5_domain_client.py`、
`vless_domain_client.py`、`echo_server.py`、`start_xray.ps1`，以及 `*-before*.err` / `*-after*.err` 原始日志。
