VERDICT: PASS

# G8Lifecycle — cinni / nip4p / a3tos / txtpo / 37jw1

工作树：`D:/Project/Xray-core-rust`（分支 `feature/fix-inbound-parity`，基线 HEAD `98c8a360` + 本波未提交改动）
构建目录：`target-G8Lifecycle`（本组独占，回执末尾注明占用）

---

## cinni（P1）wireguard UDP send 持 writer 锁跨拨号与写 → 死连接静默黑洞

### 根因
`DialedUdp::send` 用一把 `tokio::sync::Mutex<Option<WriteHalf>>` 同时守护「连接槽」与
「写」：`connect().await`（拨号）与 `write_all().await`（写）都在锁内；`read_loop` 判死
清槽要同一把锁 → 互锁。半死连接（对端不收包但未关）上第一笔写永久挂住 ⇒ 读侧无法清槽
⇒ 其余 send 全部排队 ⇒ 永不重拨、无日志（静默黑洞）。

### 改了什么（`crates/xray-proxy-wireguard/src/driver.rs`）
1. **槽锁与写锁分离**：槽改成 `parking_lot::Mutex<Option<Arc<ConnWriter>>>`（sync 锁，只在
   取槽/置槽瞬间持有，**绝不跨 await**）；每条连接自带 `ConnWriter { write: AsyncMutex<..> }`，
   写只锁本连接，读侧判死不必等写。
2. **拨号移出临界区 + 单飞**（`dialing: AsyncMutex<()>`）：N 个 worker 并发 send 只拨一条。
3. **写入有界**：`DIALED_WRITE_TIMEOUT = 5s`，超时作废连接让下次 send 重拨。
4. **按身份作废**：`drop_conn`/`is_current` 以 `Arc::ptr_eq` 判定，避免误清重拨后的新连接；
   迟到的等待者在拿到写锁后发现连接已被判死，立即返回 `already retired`（不再各付一次超时）。
5. **先置槽再 spawn 读 task**：保证读侧判死（`drop_conn`）必然发生在置槽之后，死连接不会
   残留槽里。

### 证据（代码级「无锁内 await」+ 并发压测）
- 代码级：`send` 中唯一的 await 序列 = `self.conn.lock().clone()`（语句级，guard 立刻 drop）
  → `connect().await`（锁外）→ `conn.write.lock().await` → `timeout(write_all)`；槽锁
  guard 从不存活到任何 await 点（`dialing` 是拨号单飞锁，tokio Mutex，不涉及槽）。
- `cargo test -p xray-proxy-wireguard --lib` → **112 passed; 0 failed**，含两个新用例：
  - `dialed_send_not_stalled_by_dead_connection_write`：第一笔写仍挂住时，第二笔 send 在 2s
    内完成重拨并把 payload 送到新连接对端（旧实现此处置永久挂死）；断言 `dials == 2`。
  - `dialed_send_concurrent_stalled_writes_bounded_and_single_flight`（**并发压测**）：8 路并发
    send 打在同一条半死连接上 → 全部在 `5s+5s` 有界窗内返回错误（`errs == 8`），且
    `dials == 1`（单飞，无重复连接泄漏），整套 lib 测试 5.01s 跑完（无挂死）。

---

## nip4p（P1）reverse 全域失效（set_deps 零生产调用 + vless portal 零赋值）

### 根因（三处断点，逐条实证）
1. `ReverseFeature::set_deps` 全仓零生产调用 → `Feature::start` 走「warn + Ok」空转。
2. 生产 vless 入站从不设 `enable_reverse/reverse_registry/reverse_ohm` → 收到 `command=Rvs`
   只 warn+close。
3. `build_vless_validator` 把 client JSON 的 `reverse` 字段**整块丢弃**（`ProtoAccount.reverse`
   恒 None）→ 即便前两项接好，`handle_reverse_relay` 也拿不到 `user.account.reverse`。
4. （构建期发现）派生配置误用 `xray_app_reverse::INTERNAL_DOMAIN`（`"reverse"`，是 mux 内部
   控制流目的地）当 carrier 域 → carrier 拨号去 DNS 解析 `reverse`；正确值是
   `xray_proxy_vless::RVS_DOMAIN`（`v1.rvs.cool`）。E2E 首跑即抓到（见下）。

### 改了什么
|文件|改动|
|---|---|
|`crates/xray-core/src/reverse.rs`（**新增**）|从 `BuiltConfig` 派生 `ReverseConfig`（出站 user `reverse.tag` → bridge；入站 user `reverse.tag` → portal，域 = `v1.rvs.cool`），`install_vless_reverse` = 建 `ReverseFeature` + `set_deps(DefaultDispatcherAdapter, SimpleOhmRegistrar)` + `add_feature`；`add_feature` 失败即启动失败。4 个单测覆盖 tag 解析/去重/`clients` 覆盖 `users`/派生域。|
|`crates/xray-core/src/functions.rs`（**1 行调用**，G1 已同意保留）|`instance.start()?` 之前 `crate::reverse::install_vless_reverse(&mut instance, built, &ohm, &dispatcher)?;`——portal handler 必须在入站收 Rvs 之前登记进 ohm（`instance.start` 先于 `spawn_inbounds`）。|
|`crates/xray-core/src/arm_builders/inbound.rs`|新增 `apply_vless_reverse()`：settings 里有 user `reverse.tag` → 建 registry（tag → `v1.rvs.cool`）+ `enable_reverse` + `reverse_ohm`；**portal handler 不在 ohm 即 Err 拒启**。TCP/UDS 两条 vless 臂都调用。|
|`crates/xray-core/src/inbound.rs::build_vless_validator`（**最小跨面**，非 G1 的 serve/spawn 面）|把 client 的 `reverse.tag` 透传进 `ProtoAccount.reverse`；`reverse` 在场但 tag 空 → 配置硬错（对齐 Go `infra/conf/vless.go:88-91`）。|
|`crates/xray-app-reverse/src/reverse.rs`|`Feature::start` 缺 deps 由「warn + Ok(())」改为 `StartFailed`（Go `core.RequireFeatures` 失败即硬错）；单测 `feature_start_without_deps_fails_visible`。|
|`crates/xray-core/src/lib.rs`|`pub(crate) mod reverse;`|

### 端到端（真实回连 + 数据往返）
`reports/audit-2026-10-31-perf-mem-wiring/fix/e2e-G8Lifecycle/reverse_roundtrip.py`
（单进程 loopback 但**全链路真实**：socks → 路由 rvs1 → PortalOutbound → `command=Rvs`
carrier → portal vless 入站 → BridgeWorker（2s monitor）→ 路由 rvs1 → freedom → 目标 HTTP）：

```
python reports/.../e2e-G8Lifecycle/reverse_roundtrip.py target-G8Lifecycle/debug/xray.exe
RESULT=PASS detail=REVERSE-TUNNEL-OK
```
日志证据（`reverse-roundtrip.log`）：
```
INFO  vless inbound listening addr=127.0.0.1:28443 reverse=true
DEBUG vless Reverse: dispatch to PortalOutbound via ohm user= portal_tag=rvs1
DEBUG target=127.0.0.1:28081 resolving domain via system DNS     ← bridge 侧把隧道流交给 freedom
```
（首跑 FAIL 的日志正是第 4 条断点的实证：`ERROR dial failed: ... DNS lookup failed for reverse
... tag=freedom-out dest=tcp:reverse:0` —— 修 `RVS_DOMAIN` 后转绿。）

---

## a3tos（P1）hysteria2 入站从不解析 finalmask（裸 QUIC 暴露）

### 根因
`build_hysteria_inbound` 把**整个 `streamSettings`** 当 finalmask 传给
`parse_hysteria_inbound_config`；而 `parse_udp_obfs`/`parse_quic_params` 读的是
`finalmask` 子对象的顶层 `udp` / `quicParams` 键 → 永远 None：
- 配了 `finalmask.udp.salamander` 的服务端仍收未混淆客户端（裸 QUIC 可识别）；
- 非法混淆配置（未知 type / 短 PSK）也照常启动。

### 改了什么
`crates/xray-core/src/arm_builders/inbound.rs::build_hysteria_inbound`：改为
`StreamSettings::from_json(...).finalmask_json`（与出站侧 `arm_builders/outbound.rs` 同源），
解析错误经 `?` 上抛 ⇒ 入站构造失败 ⇒ 启动失败。

### 端到端
`reports/.../e2e-G8Lifecycle/hysteria_obfs_checks.py`：
```
CASE=bad-type   EXIT=1 RESULT=PASS finalmask_err=True
CASE=short-psk  EXIT=1 RESULT=PASS finalmask_err=True
CASE=salamander-ok ALIVE_WHEN_CHECKED=True RESULT=PASS listening_log=True
OVERALL=PASS
```
错误原文（实跑）：
```
ERROR inbound bind failed, aborting startup tag=hy-in protocol=hysteria \
  error=hysteria finalmask: unsupported udp mask type "bogus" (supported: salamander)
exit=1
ERROR inbound bind failed ... error=hysteria finalmask salamander: PSK must be at least 4 bytes
exit=1
```
合法 salamander 配置正常启动（`hysteria inbound listener started tag=hy-in`）。

---

## txtpo（P2）vmess SessionHistory 清理任务从未实现（文档谎称有）

### 改了什么（`crates/xray-proxy-vmess/src/encoding/server.rs`）
1. `SessionHistory::start_cleanup(&Arc<Self>, &PluginContext)`：用 `ctx.spawn` 起 30s
   `interval`（`MissedTickBehavior::Skip`，对齐 Go `time.Ticker` 丢 tick）周期 `retain_expired`；
   持 `Weak`，history 释放后循环自然退出；任务随 inbound 停机被 scope 取消。
2. **删阈值惰性扫描**（`RETAIN_THRESHOLD = 10_000` 的 `retain`）：`add_if_not_exists` 现在只做
   一次哈希查找，不再有 1 万条后的每连接 O(n)。
3. 文档改写（原注释谎称「启动时 spawn 一次性后台任务」）；`CLEANUP_INTERVAL` 去掉
   `#[allow(dead_code)]`。
4. 装配点接线（3 处生产构造点全接）：`serve_vmess`（`inbound/server.rs`）、
   `vmess_transport_on_conn`（transport 臂，就地构造 arm ctx 并由 ConnHandler 闭包保活）、
   `unix_vmess_serve`（UDS 臂）。

### 证据
`cargo test -p xray-proxy-vmess --lib`：全绿（见 §验证命令），含新增
`session_history_retain_expired_drops_only_expired`（过期条目丢弃、未过期保留）与
`session_history_start_cleanup_spawns_on_plugin_ctx`（装配点起任务不 panic）。

---

## 37jw1（P2）BBR apply_profile_locked 零调用 + remove_obsolete_packets 空体

> 位置更正：BBR 实体在 `crates/xray-transport-quic/src/congestion_swappable/bbr/`
> （`xray-transport-hysteria` 经 `pub use xray_transport_quic::congestion_swappable as congestion`
> 复用）。

### 改了什么
1. `bbr_sender.rs::new`：构造期调用 `apply_profile_locked(&mut inner, profile)`（此前
   `_profile` 被忽略、`profile: Profile::Standard` 硬编码 ⇒ 配置的 `bbrProfile`
   conservative/aggressive **永远无效**）；去掉该函数的 `#[allow(dead_code)]`。
2. `bandwidth_sampler.rs::remove_obsolete_packets`：补实现——按发包水位线回收
   `app_limited_packets`（原先只写不读、随 app-limited 发包**无界增长**）；
   在 `on_packet_sent` 里调用。`sent_packets` 仍由 ack/loss 路径（`on_congestion_event`）
   逐包退役，不被水位线清理（避免影响 ack 记账）。
3. 新增两个单测：`new_sender_applies_configured_profile`（三档 gain 逐一断言）、
   `remove_obsolete_packets_prunes_app_limited_marks_only`。

---

## 验证命令 + 关键输出

```bash
export BORING_BSSL_PATH=D:/Project/Xray-core-rust/target/boringssl-asm/prebuilt
export BORING_BSSL_ASSUME_PATCHED=1
export PROTOC=D:/Project/tools/bin/protoc.exe
export LIBCLANG_PATH="D:/Program Files/llvm/bin"
export CARGO_TARGET_DIR=D:/Project/Xray-core-rust/target-G8Lifecycle
```

|命令|结果|
|---|---|
|`cargo test -p xray-proxy-wireguard --lib`|`112 passed; 0 failed`（含 2 个新用例，含并发压测）|
|`cargo test -p xray-proxy-hysteria --lib`|`73 passed; 0 failed`|
|`cargo test -p xray-transport-quic --lib -- congestion_swappable`|`121 passed; 0 failed`（BBR 面全绿，含 2 个新用例）|
|`cargo test -p xray-core --lib -- reverse`|`6 passed; 0 failed`|
|`cargo test -p xray-core --lib -- build_vless_validator`|`8 passed; 0 failed`|
|`cargo test -p xray-app-reverse --lib`|`91 passed; 2 failed`（见下「非本组红」）|
|`cargo test -p xray-proxy-vmess --lib`|`172 passed; 1 failed`（见下「非本组红」）|
|`cargo test -p xray-proxy-vless --lib`|`293 passed; 1 failed`（见下「非本组红」）|
|`cargo check -p xray-core --all-targets`|`Finished dev profile`（0 error）|
|`cargo clippy -p xray-app-reverse -p xray-proxy-vmess -p xray-proxy-wireguard -p xray-transport-quic -p xray-core --all-targets -- -D warnings`|**绿**：`Finished dev profile`（仅 vendor `rustls` 既有 warning，属依赖非本仓）|
|`cargo fmt -p xray-proxy-wireguard -p xray-transport-quic`|已格式化（仅本组 3 个文件变化；`cargo fmt -p` 只覆盖本组文件）|
|`python .../reverse_roundtrip.py target-G8Lifecycle/debug/xray.exe`|`RESULT=PASS detail=REVERSE-TUNNEL-OK`|
|`python .../hysteria_obfs_checks.py target-G8Lifecycle/debug/xray.exe`|`OVERALL=PASS`（3/3 case）|

### 非本组红（错误位于他人文件面，未代改）

|测试|报错|归属判断|
|---|---|---|
|`xray-transport-quic::transport::tests::{echo_roundtrip_gso_default, echo_roundtrip_gso_disabled, close_rejects_new_connections}`、`zero_rtt::tests::{resumed_session_hits_zero_rtt, rejected_zero_rtt_falls_back_to_1rtt}`|`ConnectionClosed(crypto(31), "unexpected error: no server certificate chain resolved")`（`transport.rs:422`）|**G6Tls 的 bd mwvwd**（删除 TLS 自签证书回退：缺证书 = 每条握手失败）；文件面 `crates/xray-tls/**`，非本组|
|`xray-app-reverse::worker::entity_tests::{portal_worker_drains_over_threshold_and_disposes, portal_worker_heartbeat_sends_control_on_internal_dest}`|`worker.rs:891 read ok: Eof`|本组在 app-reverse 只改 `reverse.rs::Feature::start` 的缺 deps 分支（其新测试 `feature_start_without_deps_fails_visible` 通过），未触碰 `worker.rs`/`relay.rs` → 非本组（建议 owner 复核 W1 波对 worker entity 的改动）|
|`xray-proxy-vmess::inbound::server::tests::vmess_outbound_udp_roundtrip_e2e`、`xray-proxy-vless::inbound::server::tests::vless_outbound_udp_roundtrip_e2e`|`roundtrip timeout: Elapsed(())`（vmess `inbound/server.rs:1122`）——两 crate 的**同族 UDP 往返 e2e** 同时超时|本组改动均与该路径无关（vmess 只增 30s 定时清理 + 删阈值扫描；vless 只在 settings 含 `reverse.tag` 时改 options，两测试均无 reverse 用户）→ 判定为共享 UDP 面（W1/W3 UDP 票面）状态，非本组|

---

## 非目标 / 未做
- 未改 `xray-frame` scope API（G5/86i4h 面）、未改 `xray-core/src/inbound.rs` 的 serve/spawn
  机制（只在该文件 `build_vless_validator` 内透传 `reverse` 字段，8 行）。
- `functions.rs` 只保留 1 行调用（G1 已同意），本组不再改该文件。
- hysteria obfs 的**握手层**互通（混淆客户端能通 / 未混淆客户端被拒）未在本组跑：
  需要 hysteria 客户端↔服务端互联矩阵，属 a3tos 的相邻验证面（配置层拒启已实证）。
- `ReverseMonitor`（`xray-proxy-vless/src/outbound/reverse.rs`）仍无生产消费点：
  反向 carrier 保活由 `app/reverse::RuntimeBridge` 的 2s monitor 承担（本波已接线），
  该结构与桥重复——PM 裁决不删，已建 P3 票 **`Xray-core-rust-78ysn`**（接线或删除，二选一）。

## 磁盘
`target-G8Lifecycle` 构建目录在本组回执中注明，任务收尾由 PM 统一清理。
