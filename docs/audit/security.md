# 安全审计报告 — security 维度

- 审计对象: Xray-core-rust (crates/ 全部 50+ crate，重点: 密码学/认证/replay/输入校验/DoS/unsafe/敏感信息)
- 对照基准: D:/Project/Xray-core (Go Xray-core v26.7.28)；ss2022 语义参考 sing-shadowsocks
- 方法: 全量 grep 关键模式（unsafe/nonce/rand/constant-time/log 泄漏/长度字段）+ 逐点精读生产路径 + Go 逐行对照
- 日期: 2026-09-06

## 发现统计

| 严重度 | 数量 |
|---|---|
| P0 | 2 |
| P1 | 3 |
| P2 | 9 |

---

## 漏洞发现

### P0-1 SOCKS inbound 配置 Password 认证时可被完全绕过（双路径）

**位置**: `crates/xray-proxy-socks/src/server.rs:366-377`（方法协商回退）、`crates/xray-proxy-socks/src/server.rs:296-331`（SOCKS4 完全不校验）；生产入口 `crates/xray-core/src/inbound.rs:116`、`crates/xray-core/src/inbound.rs:328`

**证据**（select_method，Password 配置时客户端只报 NoAuth 即放行，注释自认）:
```rust
// crates/xray-proxy-socks/src/server.rs:366-377
AuthType::Password => {
    // 优先密码认证
    if client_methods.contains(&AUTH_PASSWORD) {
        (AUTH_PASSWORD, true)
    } else if client_methods.contains(&AUTH_NOT_REQUIRED) {
        // 回退到无认证（与 Go 一致：如果客户端不支持密码但服务端配置 Password，
        // 仍允许 NoAuth 连接——实际生产应严格拒绝）   ← 注释承认是错的
        (AUTH_NOT_REQUIRED, false)
    } else {
        (AUTH_NO_MATCHING_METHOD, false)
    }
}
```
第二条路径——SOCKS4 握手对配置完全不设防（`_config` 未使用）:
```rust
// crates/xray-proxy-socks/src/server.rs:296
pub async fn socks4_handshake<RW>(stream: &mut RW, _config: &ServerConfig) -> Result<SocksRequest>
// ... 内部零认证检查，直接回 SOCKS4_REQUEST_GRANTED 并返回 TcpConnect
```
生产接线: `xray-core/src/inbound.rs:115-118` `socks_handshake(&mut stream, config)` 直接消费该函数族，mixed inbound（`inbound.rs:328`）同样。

**Go 基准**（两处都严格拒绝）:
```go
// D:/Project/Xray-core/proxy/socks/protocol.go:109-118
var expectedAuth byte = authNotRequired
if s.config.AuthType == AuthType_PASSWORD { expectedAuth = authPassword }
if !hasAuthMethod(expectedAuth, buffer.BytesRange(0, int32(nMethod))) {
    writeSocks5AuthenticationResponse(writer, socks5Version, authNoMatchingMethod) // 0xFF 拒绝
    return nil, errAuthenticationFailed
}
// protocol.go:52-56  SOCKS4 + AuthType_PASSWORD → 直接 reject
```
（注: "与 Go 一致" 的注释是错的——Go 正是拒绝。）

**影响**: 配置了用户名/密码的 SOCKS 入站对任意攻击者完全开放: 攻击者发 `[VER=5, NMETHODS=1, 0x00]`（只报 NoAuth）或直接走 SOCKS4 版本字节即可零凭据获得开放代理出口（开放 relay / 滥用出口 IP / 内网穿透跳板）。

**修复建议**: `select_method` 删除 NoAuth 回退分支，Password 配置下客户端不报 0x02 一律回 `AUTH_NO_MATCHING_METHOD`；`socks4_handshake` 开头对 `config.requires_auth()` 返回 rejected（对齐 Go handshake4:52-56）。

---

### P0-2 HTTP 握手读行无长度/行数上限 + 字节级循环，无认证单连接可 OOM

**位置**: `crates/xray-proxy-http/src/server.rs:306-328`（read_http_line）、`crates/xray-proxy-http/src/server.rs:233-243`（header 循环无行数上限）；生产入口 `crates/xray-core/src/inbound.rs:383-415`（serve_http）

**证据**:
```rust
// crates/xray-proxy-http/src/server.rs:306-328
async fn read_http_line<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<String> {
    let mut buf = Vec::with_capacity(128);
    ...
    loop {
        let n = reader.read(&mut byte).await ...   // 每次读 1 字节
        ...
        buf.push(byte[0]);                          // 无任何长度上限
    }
}
// server.rs:233-243  header 循环:
loop {
    let line = read_http_line(stream).await?;       // 无行数/总大小上限
    if line.is_empty() { break; }
    ...
}
```
一个未认证连接发送一条不带 `\r\n` 的无限字节流即可让 `buf` 无界增长直至进程 OOM；同时每字节一次 `read` syscall 放大 CPU 开销。header 条数同样无上限（HashMap 无界增长）。

**对照 Go**: Go 侧 http inbound 基于 `common/http` server + `SetReadDeadline(policy().Timeouts.Handshake)`（proxy/http/server.go:112，默认 policy 4s），请求头处理有 Go http 栈的 1MB 级上限语义；Rust 两者皆无（超时缺失见 P1-1）。

**影响**: 无认证远程 DoS，可致进程崩溃（OOM）——符合 P0（可致崩溃）。

**修复建议**: `read_http_line` 加单行上限（如 8-16KB，超限即断），握手 header 循环加总字节上限（如 64KB）与行数上限；顺手把逐字节 read 换成带缓冲读。socks 侧同类 `read_until_null`（server.rs:335-345，USERID/4a 域名）一并加上限。

---

### P1-1 无 policy 配置时 socks/http/mixed 握手完全无超时（慢速连接挂死）

**位置**: `crates/xray-core/src/inbound.rs:1866-1868`（http: 无 policy → None → 不限时）、`crates/xray-core/src/inbound.rs:72-118`（serve_socks5 全链路无超时参数）、`crates/xray-core/src/inbound.rs:293,320-328`（mixed: 注释自认"握手超时简化(传 None)"，且即便 Some，SOCKS 分支也只用它限 1 字节 peek）

**证据**:
```rust
// inbound.rs:1866-1868
let handshake_timeout = policy
    .as_ref()
    .map(|pm| pm.policy_for_level(config.user_level).timeout.handshake);
// 无 policy manager → None → serve_http 的 match None 分支 = 无限等待
```
```rust
// inbound.rs:320-328  mixed: sniff 限时，但 socks_handshake 无限
let read_res = match handshake_timeout {
    Some(d) => tokio::time::timeout(d, stream.peek(&mut sniff)).await,
    None => Ok(stream.peek(&mut sniff).await),
};
...
match socks_handshake(&mut stream, &socks_cfg).await {   // 无 timeout 包裹
```

**Go 基准**: `proxy/socks/server.go:98-101` `conn.SetReadDeadline(time.Now().Add(plcy.Timeouts.Handshake))`；默认 policy（app/policy）handshake=4s 兜底，**不存在无超时形态**。Rust 把"无 policy 配置"翻译成"无限时"，注释自己也承认与 Go DefaultPolicyFeature 的差异是假的（"此处直接不设超时"）。

**影响**: 未认证攻击者每个 TCP 连接成本极低（连上不发数据），可长期占住 task/FD/内存（slowloris）→ FD 耗尽拒绝服务。

**修复建议**: `handshake_timeout` 为 None 时落默认 4s（对齐 Go DefaultPolicy），而非 None=无限时；`socks_handshake`/`socks5_server_handshake` 调用点统一 `tokio::time::timeout` 包裹；mixed 的 SOCKS 分支补 timeout。

---

### P1-2 REALITY hooks 全局注册表：错误路径泄漏条目，SSL 裸指针地址复用可串号

**位置**: `crates/xray-tls/src/btls_reality.rs:234-243`

**证据**:
```rust
// crates/xray-tls/src/btls_reality.rs
234:  let ssl_key = ssl.as_ptr() as usize;
235:  register_reality_hooks(ssl_key, Arc::clone(&hooks));      // 注册
236:  let rewrite_stream = HelloRewriteStream { inner: stream };
238:  let tls_stream = TokioSslStream::new(ssl, rewrite_stream)
239:      .map_err(|e| io::Error::other(e.to_string()))?;       // ← `?` 提前返回，跳过 unregister
241:  let mut pinned = Box::pin(tls_stream);
242:  let connect_result = pinned.as_mut().connect().await;
243:  unregister_reality_hooks(ssl_key);                        // 只有正常走到这里才注销
```
注册表以 `ssl.as_ptr() as usize` 为 key（`REALITY_HOOKS: Mutex<Option<HashMap<usize, ...>>>`，btls_reality.rs:99-100），`TokioSslStream::new` 失败（或 235-243 之间 panic unwind）时该地址的条目永久残留。分配器复用该地址给后续 SSL 时，`reality_rewrite_trampoline`（:103-119）按地址命中**陈旧 hooks**，把新连接的 ClientHello 用上一会话的 auth_key/参数改写——跨连接凭据串扰 + 握手必然失败或认证到错误上下文。

**影响**: REALITY 客户端路径上的低概率、高危害缺陷：静默的跨连接凭据污染，难以排查的握手失败；注册表同时构成无界泄漏。

**修复建议**: 用 RAII guard（Drop 中 unregister）替代手工配对；或把 `TokioSslStream::new` 移到 `register_reality_hooks` 之前（回调只在 connect() 期间触发，注册顺序后移不影响语义）；进一步可在 trampoline 命中后校验 ssl 指针仍存活。

---

### P1-3 SS-2022 UDP 服务端会话表永不清理（内存泄漏，认证后无界增长）

**位置**: `crates/xray-core/src/inbound.rs:1101-1102,1124-1133,1152-1166`

**证据**:
```rust
// crates/xray-core/src/inbound.rs serve_ss2022_udp
1101:  let mut sessions: HashMap<u64, tokio::sync::mpsc::Sender<Item>> = HashMap::new();
1102:  let mut server_sessions: HashMap<u64, Arc<ServerUdpSession2022>> = HashMap::new();
...
1124:  if !server_sessions.contains_key(&sid) {
1127:      server_sessions.insert(sid, Arc::new(s));     // 只插入
...
1152:  let tx = sessions.entry(sid).or_insert_with(|| { ... spawn relay ... });
1163:  if tx.send(...).await.is_err() {
1165:      sessions.remove(&sid);                        // 只清 sessions，不清 server_sessions
```
relay task 60s 空闲退出后，`server_sessions[sid]`（含 PSK clone、AEAD cipher、滑动窗口）永不删除；`sessions[sid]` 里已断开的 Sender 也只在"该 sid 再来一包"时才被清除，之后再次滞留。持有合法 PSK 的客户端以唯一 sessionId 持续发包即可无界堆积条目与（60 秒生命期的）relay task/channel/UdpDispatchSession。

**对照 Go**: Go `udpNat`/`TempUDPConn` 有 `CancelAfterInactivity` + 会话表清理（server.go:172 SetTimeout(ConnectionIdle)，UDP nat entry 随 TCP 断开/空闲关闭整体回收）。

**影响**: 长期运行服务器的慢性内存泄漏；合法凭据持有者可放大为确定性 OOM。

**修复建议**: relay 退出时同时移除两张表的条目（或定期扫描：entries 无 activity > idle timeout 即回收，对齐 Go）。

---

### P2-1 ENC CommonConn 读侧缺 MaxNonce 换 key（与 Go 不对称），且 nonce 自增到顶后静默停摆

**位置**: `crates/xray-proxy-vless/src/encryption/common_conn.rs:194-198`（读侧无检查）vs `:298-301`（写侧有）；`crates/xray-proxy-vless/src/encryption/aead.rs:89-114`（seal/open 忽略 `increase_nonce` 返回值）

**证据**:
```rust
// common_conn.rs 读侧: 直接 open，无 is_max 检查
194:  let peer_aead = this.peer_aead.as_mut().expect("peer_aead established at loop top");
198:  if let Err(e) = peer_aead.open(&mut plaintext, None, &data, &header) {
// 写侧有（对齐 Go）:
299:  if this.aead.is_max() { this.aead = Aead::new(&header, &this.united_key, this.use_aes); }
// aead.rs seal(nonce=None):
99:   self.increase_nonce();   // 返回值 false(已达 MAX)被忽略 → 之后恒以 MAX_NONCE seal = nonce 重用
```
**Go 基准**（proxy/vless/encryption/common.go:134-141）: 读侧 Open 前检查 `PeerAEAD.Nonce == MaxNonce`，预派生 newAEAD 并在 Open 后切换。Rust 缺该分支；且 Go 的 `IncreaseNonce` 到顶回绕、Rust 停在 MAX（seal/open 忽略 false 返回值 = 每 record 重用同一 nonce）。

**影响**: 达到 2^96 条 record 才触发——现实不可达，故 P2。但属于与 Go 的结构性不对称 + 防线失效模式（一旦有人改小 nonce/复用此类型即变成真 nonce 重用），建议补齐。

**修复建议**: 读侧镜像 Go（`is_max()` → 以当前 header+data 派生新 AEAD，open 后替换）；`seal/open` 在 `increase_nonce()==false` 时返回错误，把"调用方必须 rekey"从约定升级为强制。

---

### P2-2 SS-2022 TCP SaltReplayFilter TTL 内无界增长（"128KB 上限"注释不成立）

**位置**: `crates/xray-proxy-ss/src/ss2022/replay.rs:36-48`

**证据**:
```rust
// crates/xray-proxy-ss/src/ss2022/replay.rs
39:  // ponytail: 阈值惰性清理（4096×32B ≈ 128KB 上限），sing 按时间轮询等价
40:  if pool.len() >= 4096 {
41:      pool.retain(|_, t| now.duration_since(*t) < self.ttl);  // 只清过期项
42:  }
...
45:  pool.insert(salt.into(), now);   // check 即注册，攻击者可灌任意 32B salt
```
4096 是**清理触发阈值而非容量上限**：持续洪泛新鲜 salt 时 TTL（60s）内条目全部存活，`retain` 无物可清，池随连接数无界增长（~100B/条）。salt 检查发生在任何认证之前（inbound.rs:425/522），未认证攻击者以 1 次 TCP 连接 + 32 字节的成本换取 ~100B 常驻内存，60 秒窗口内 10k conn/s ≈ 60MB 常驻。

**影响**: 未认证内存弹药（有界放大 ~3 倍流量，需持续攻击维持），且注释声称的硬上限会误导后续维护者。

**修复建议**: 触发 retain 后若仍 ≥ 阈值则按插入时间强制淘汰最旧一半（真上限）；或改为定容环形注册表；修正注释。

---

### P2-3 SS-2022 UDP 滑动窗口淘汰语义弱于 Go bitmap（淘汰后旧 packetId 重新可接受）

**位置**: `crates/xray-proxy-ss/src/ss2022/packet.rs:95-117`

**证据**:
```rust
// crates/xray-proxy-ss/src/ss2022/packet.rs
93:  // ponytail: Go 用 64 槽 bitmap；这里用 BTreeSet 近似（重复 id 拒绝 + 容量
94:  // 淘汰最小 id）。窗口边界外的极旧 id 重放可能重新接受，与 bitmap 语义相同。 ← 结论错误
108: pub fn add(&mut self, id: u64) {
109:     if self.seen.insert(id) && self.seen.len() > WINDOW_CAPACITY {
111:         if let Some(&first) = self.seen.iter().next() { self.seen.remove(&first); }  // 无 base 指针
```
Go 的 64 槽 bitmap 有 base 指针：低于 base 的 id **一律拒绝**；本实现无 base，最小 id 被容量淘汰后 `check()` 重新返回 true——被淘汰的旧包重放将被当作新包接受（双向：client 收 server 回包侧 + server per-session decode_body）。利用需在 64 个合法包之后重放捕获包，UDP 重复投递危害有限，但与注释声称的"bitmap 语义相同"不符。

**影响**: replay 防护窗口实际只有"最近 64 个未淘汰 id"，弱于 Go；协议加固缺口。

**修复建议**: 加 `base: u64`，`check(id)` 对 `id < base` 直接拒绝，`add` 推进 base（对齐 bitmap），或将注释改回真实语义。

---

### P2-4 blake3 derive_key 用 `from_utf8_unchecked` 构造非法 `&str`（语言层 UB-by-contract）

**位置**: `crates/xray-proxy-vless/src/encryption/aead.rs:44`

**证据**:
```rust
// crates/xray-proxy-vless/src/encryption/aead.rs:44
let ctx_str = unsafe { std::str::from_utf8_unchecked(context) };
let derived = blake3::derive_key(ctx_str, key);
```
协议 context（iv/密钥哈希/密文切片）是任意字节。当前 blake3 实现只 `as_bytes()`，但 `&str` 的有效性是全语言契约：`from_utf8_unchecked` 构造非法 UTF-8 即为 instant UB，任何依赖 `&str` 合法性的优化/未来版本变更都可能触发未定义行为。密钥派生是全协议最敏感路径，不应以 UB 换 wire 兼容。

**影响**: 潜在 UB（当前版本实际无害）；安全关键路径上的健壮性债务。

**修复建议**: blake3 提供字节 context 的途径是 `blake3::Hasher::new_derive_key` 不接受字节——可用 `derive_key(context_hex_or_len_prefixed_bytes)` 的等价构造，或自实现 `derive_key(context_bytes, key) = blake3 keyed/extendable 等价公式`；至少把 unsafe 收敛为有注释的 `Hasher` 字节路径。

---

### P2-5 legacy SS `iv_check` 的 seen-IV 表无 TTL、无界增长

**位置**: `crates/xray-proxy-ss/src/validator.rs:258-267`

**证据**:
```rust
// crates/xray-proxy-ss/src/validator.rs
262:  let seen = inner.seen_ivs.entry(user.email.clone()).or_default();
263:  if !seen.insert(iv) {           // HashSet<Vec<u8>>，只进不出，无过期
264:      return Err(SsError::IvNotUnique);
```
启用 `iv_check` 的账户每请求累积 16B IV 永不释放（仅认证成功后到达，属认证后慢性泄漏）。且 `get()` 全程持有 Mutex 做 HKDF+AEAD 试匹配，多用户下放大锁竞争。

**影响**: 慢性内存泄漏 + 锁竞争；建议对齐常规 replay 表语义（TTL/容量淘汰）。

**修复建议**: seen_ivs 改为带 TTL（如 12h）的惰性清理结构或容量淘汰；匹配循环移出锁外（clone 用户列表后再试）。

---

### P2-6 SOCKS 客户端写地址时 domain>255 字节写错长度前缀（帧错位）

**位置**: `crates/xray-proxy-socks/src/protocol.rs:162-167`

**证据**:
```rust
// crates/xray-proxy-socks/src/protocol.rs write_address_port
166:  buf.push(bytes.len().min(255) as u8);   // 长度前缀截到 255
167:  buf.extend_from_slice(bytes);           // 却把全量字节写出去
```
长度前缀与实际写入字节数不一致，对端按 255 消费后剩余字节被当作后续帧解析 → 协议错位。Go `WriteAddressPort` 对超长域名返回错误。

**影响**: 配置了超长域名（客户端侧配置输入）时产生静默协议损坏；边界输入未校验。

**修复建议**: >255 返回错误（对齐 Go），或写前 `truncate(255)` 保证一致。

---

### P2-7 SS-2022 多用户 EIH 识别为 O(n) blake3 + 非常数时间比较

**位置**: `crates/xray-proxy-ss/src/ss2022/inbound.rs:544-546`

**证据**:
```rust
// crates/xray-proxy-ss/src/ss2022/inbound.rs
544:  let matched = users
545:      .iter()
546:      .find(|u| psk_identity(&u.psk) == plaintext);   // 每连接对每用户做一次 blake3::hash + 16B ==
```
每个连接对全量用户各算一次 `blake3::hash(psk)`（无预计算缓存）；`==` 非常数时间。可利用性评估：plaintext 须先通过 iPSK 的 AES-ECB 解密（攻击者无 iPSK 则无法控制明文），时序侧信道实际不可利用——但每连接 O(n) 哈希在多用户大表下是放大点，且 identity 可在用户装载时预计算。

**影响**: 性能放大（认证前每连接 × 用户数）+ 理论时序噪音；无实际越权路径。

**修复建议**: 用户装载时预计算 `psk_identity` 存表，匹配改查 HashMap<identity, user>。

---

### P2-8 btls REALITY 残留 `eprintln!` 直写 stderr（绕过日志框架）

**位置**: `crates/xray-tls/src/btls_reality.rs:245`

**证据**:
```rust
// crates/xray-tls/src/btls_reality.rs:245
eprintln!("[REALITY dbg] SslStream::connect failed: {e:?}");
```
调试残留：无条件向 stderr 输出握手错误内部细节（Debug 格式含 BoringSSL 错误队列），绕过日志级别与脱敏管道。同类输出在本仓库其他 crate 已被清理（v26 教训）。

**影响**: 信息泄露面 + 日志管道失控。

**修复建议**: 换 `tracing::debug!` 或删除。

---

### P2-9 vmess SessionHistory 每次新增全表 retain（O(n) 清理）

**位置**: `crates/xray-proxy-vmess/src/encoding/server.rs:69-79`

**证据**:
```rust
// crates/xray-proxy-vmess/src/encoding/server.rs
74:  inner.retain(|_, expire| *expire > now);   // 每个新连接全表扫描
```
3 分钟 TTL 内每连接（认证后）一条，高峰 100k 连接时每条新连接付 O(100k) 扫描。Go 用 `task.Periodic` 每 30s 周期清理，摊销 O(1)/连接。

**影响**: 纯性能（认证后）；高并发下全局 Mutex 持有时间被拉长。

**修复建议**: 改周期清理（tokio interval）或分代环形桶。

---

## unsafe 块专项审计（grep unsafe 全仓 37+ 文件逐一评估）

| 类别 | 位置 | 评估 |
|---|---|---|
| FFI setsockopt/getsockopt/socket/bind（linux/darwin/freebsd/windows sockopt、udp hub、dokodemo fakeudp） | xray-transport/src/sockopt/*、xray-proxy-dokodemo/src/fakeudp.rs:34-71 | **必要且正确**。指针均指向栈上标量/结构，同步调用不保留指针；fakeudp 的 fd 生命周期处理规范（错误路径统一 close、`from_raw_fd` 失败置 -1 防双关闭）。 |
| fd 复制（splice 用 raw 克隆） | xray-transport/src/connection.rs:74-92 | **必要且正确**。`libc::dup` 后立即 `from_raw_fd` 转移所有权；Windows 路径 `ManuallyDrop` + `try_clone` 不夺取原句柄所有权。v50/v54 已实战验证。 |
| shutdown(SHUT_RD/WR) | xray-transport/src/connection.rs:167,180,248,257 | 正确，已验证 fd 有效性。 |
| ManuallyDrop 字段移动 | xray-buf/src/multi.rs:80,181,254,371、xray-transport-splithttp/src/connection.rs:92-93 | **正确**。take/extend/drain 全程配对 forget/drop 注释明确；splithttp 的 `ptr::read` 逐字段搬移在 ManuallyDrop 保护下无双重 drop。 |
| Pin 投影 | xray-transport/src/finalmask/mod.rs:197-360 | 正确（newtype 对 Unpin 内字段的 `map_unchecked_mut` 标准用法）。 |
| Waker::from_raw（no-op VTABLE） | xray-transport-kcp/src/connection.rs:1097 | 正确（测试专用 no-op waker，VTABLE 静态存储）。 |
| Send/Sync 手工 impl | xray-core/src/outbound.rs:114-115、xray-proxy-tun/netstack.rs:495-517、xray-proxy-wireguard/netstack.rs:280-302 | 合理：裸指针生命周期均限定在单 task 驱动循环内，注释说明了契约。 |
| Windows API（GetExtendedTcpTable/OpenProcess、FreeBSD procstat、`env::set_var` 测试代码） | xray-app-router/src/condition.rs:610-947、xray-common/xray-conf 测试 | 正确；env::set_var 局限于测试/启动期（built.rs:127 为配置注入，属配置信任边界内）。 |
| blake3 `from_utf8_unchecked` | xray-proxy-vless/src/encryption/aead.rs:44 | **唯一不健全点**，见 P2-4。 |
| BoringSSL FFI（REALITY trampoline/私钥导出/i2d_X509） | xray-tls/src/btls_reality.rs:26-31,94,114,258-265 | FFI 本体正确（SAFETY 注释齐全、生命周期在握手窗口内），但**外围 hooks 注册表存在泄漏/串号缺陷**，见 P1-2。 |

结论: unsafe 总量克制、绝大多数必要且有 SAFETY 注释；需修的是 P2-4 与 P1-2，无需扩大化重写。

## 敏感信息泄漏专项

- 全仓 log/tracing 语句扫描 `password|secret|psk|private|cmd_key|united_key|nfs_key|pfs_key|uuid`：**未发现密钥/密码/UUID 明文进日志**。ENC 相关日志仅输出计数与长度（mod.rs:1011 `sessions.len()`、mod.rs:1140 `nfs_keys.len()`、mod.rs:384 `pre_write.len()`）。
- vless 拒绝类日志 info 级对齐 Go inbound.go AtInfo（v47 已核）；SS 失败路径经 drainer 排空后仅返回统一错误（server.rs:165-176），无认证结果侧信道。
- 唯一例外: btls_reality.rs:245 的 `eprintln!`（P2-8）。
- 密钥缓存（ClientInstance pfs_key_cache/ticket_cache、xray-crypto KeyCache）均仅内存驻留，无落盘序列化路径——未发现泄漏通道。

## 对照 Go 基准缺失的加固点汇总

1. **默认 policy 兜底缺失**: Go 无 policy 配置时 DefaultPolicy 提供 handshake=4s/connIdle=5min 等兜底；Rust `policy: None` 直接翻译为"无超时"（P1-1）。
2. **SOCKS4 + Password 拒绝**（Go protocol.go:52-56）与**方法协商严格匹配**（:109-118）均缺失（P0-1）。
3. **UDP nat 会话回收**（Go server.go:172 `SetTimeout(ConnectionIdle)` + nat 清理）仅部分移植：relay task 有 60s 空闲退出，但会话表不回收（P1-3）。
4. **ENC CommonConn 读侧 MaxNonce 换 key**（Go common.go:134-141）缺失（P2-1）。
5. **UDP packetId bitmap 的 base 语义**（Go 64 槽窗口拒绝越界 id）弱化（P2-3）。
6. **超长 domain 写入报错**（Go WriteAddressPort 返回 error）缺失（P2-6）。

## 已核查无需报告的项（防重复审计）

- AEAD nonce 管理主干: ss2022 TCP/UDP 的 LE 自增序列、SSStream 双向独立 nonce/响应 rekey（含 begin_server_response 新随机 IV，stream.rs:734-740）、vmess ChunkNonceGenerator u16 回绕（与 Go GenerateChunkNonce 逐位一致）、ENC nfsAEAD 固定 nonce 序列（0000-0004/MaxNonce 特例）均与 Go/sing 对齐；握手分配全部有界（u16/固定长度），未发现超大分配原语。
- ENC 0-RTT replay（nfs_keys HashSet insert 冲突即拒 + lasts/tickets FIFO + 60s 周期清理 + miss 噪声回写）与 Go server.go:198-235 逐条对齐；SessionStore 无落盘。
- 随机源: 全仓密钥/IV/salt/sessionId 生成统一走 `rand::rng()`/`rand::random()`（ThreadRng，OS 种子的 CSPRNG），未发现 SmallRng/seed_from_u64 用于安全用途（dice.rs 的 StdRng 仅统计采样）。
- vmess SessionHistory/Validator、vless/trojan/SS validator 的 map 匹配模式与 Go 一致（Go 本身也非常数时间 map 查找，非回归）；vmess AuthID 时间窗 + Replay 错误路径存在。
- 报文长度字段: mux（512B meta/8192 packet 双上限）、ss2022（salt 定长 + u16 variable）、ENC 握手（解密前仅固定/配置定长分配）、socks/http 解析均为有界读取，除 read_http_line/read_until_null 外未见无界分配。
