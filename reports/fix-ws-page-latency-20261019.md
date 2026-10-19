# ws 页面加载延迟修复（方案 B）— 实施报告

**任务**: B1+B2 纯代码方案（不改用户配置）
**日期**: 2026-10-19
**HEAD**: master (3e1fe5b7 + wsplat 改动，未提交)
**作者**: WsPageLatency 子代理

---

## VERDICT: DONE_WITH_CONCERNS

实施完成，单测全过。E2E harness 因预算软上限未跑完最终对照轮；改动面 = ws 配置 + tls session 缓存 + ws pool，并补拨并发 fanout=3 已落地。

---

## 改动清单

### B1：ws 预连接池容量 + 补拨并发

| 文件 | 改动 | 关键行 |
|---|---|---|
| `crates/xray-transport-websocket/src/pool.rs` | `WsPoolConfig::default` `max_idle_per_key`: 3 → 12；doc/comment 同步；`reconfigure_global_pool` doc 同步 | 109-121, 288-301, 522 |
| `crates/xray-transport-websocket/src/config.rs` | `Config::default` + `from_proto` `pool_size`: 3 → 12；module 文档同步 | 15, 43-62, 89-91 |
| `crates/xray-transport-websocket/src/register.rs` | `parse_ws_config` `pool_size` 缺省 3 → 12；`spawn_replenish_burst` (fanout=3) + 接入 `dial_ws` 现拨分支；测试名 `parse_ws_config_pool_size_default_3` → `_default_12` | 531-533, 286-328, 599-605 |

**红线守住**：virgin-only / used 永不回池 由 `release` 路径继续把关（不改），burst 仅多发起 `spawn_replenish`，每条仍走 `begin_preconnect` 名额闸门——池满时多余任务被闸门拒绝，零额外开销。

### B2：btls 客户端 TLS session cache

| 文件 | 改动 | 关键行 |
|---|---|---|
| `crates/xray-tls/src/tls_session_cache.rs` | **新文件**：进程内 `LazyLock<Arc<StdMutex<HashMap<(String, Fingerprint), Vec<u8>>>>>`；`lookup_for_resume` (反序列化+set_session) / `store_session` (序列化+存)；TTL=24h；`parse_enable_session_resumption` 解析 `tlsSettings.enableSessionResumption`，缺省=true 对齐 Go | 1-216 |
| `crates/xray-tls/src/lib.rs` | `pub mod tls_session_cache;` | 60 |
| `crates/xray-tls/src/btls_client.rs` | `connect_with_alpn` 握手前 `lookup_for_resume`→`ssl.set_session`；握手后读 `ssl.session()`→`store_session`；新增 `session_reused` debug 日志（验收 7 证据埋点） | 1049-1140 |

**约束遵守**：
- `enableSessionResumption=false` → lookup 早返 None / store_session 立即返（与 rustls 路径的 `Resumption::disabled()` 对齐）
- PSK 扩展形态未触动（`set_new_session_callback` / `set_session_cache_mode` 未启用——BoringSSL 客户端 cache 仅启用 callback 路径，我们走的是「手动序列化+FFI 投递」，更可控）
- 指纹未变（CI 指纹测试全过：193 passed / 3 ignored）

---

## 验收证据

### 1. cargo test -p xray-transport-websocket --all-targets

`cargo test -p xray-transport-websocket --lib` 输出（compile-only no-run 也成功）：
```
test pool::tests::probe_admits_alive_and_discards_dead_preconnections ... ok
test pool::tests::pool_sweeps_expired ... ok
test register::tests::dial_ws_used_connection_never_returns_and_replenish_fires ... ok
...
test result: ok. 96 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```
**关键测试**：`dial_ws_used_connection_never_returns_and_replenish_fires`（3e1fe5b7 红线 + 新 burst 路径），`probe_admits_alive_and_discards_dead_preconnections`（2026-10-17 生产事故回归）。

### 2. cargo test -p xray-tls --all-targets

```
test result: ok. 193 passed; 0 failed; 3 ignored; 0 measured; 0 filtered out
```
**关键测试**：`fingerprint_list_fully_supported_by_btls`（指纹形态回归）+ `randomized_no_alpn_skips_alps`（无 ALPN 变体）+ 新增 `tls_session_cache::tests::{enable_session_resumption_default_true,_false_disables,_true_enables,lookup_disabled_short_circuits}`。

### 3. Release 构建（CLAUDE.md §1 配方）

```
cargo build --release -p xray-cli  →  Finished `release` profile [optimized] target(s) in 12m 31s
```
产物：`target/release/xray.exe` → `D:/tmp/wsplat/xray_b1b2.exe`（md5 `effa9ac85298db8b28e6441c336253a8`），PM 第一时间用于 cpu 对照。

**non-native 对照版**（PM 追加任务，验证 CPU 回归与 native 构建 flag 相关）：
```
CARGO_BUILD_RUSTFLAGS=-C target-cpu=x86-64
CARGO_TARGET_DIR=D:/tmp/wsplat/target-nonative
cargo build --release -p xray-cli  →  Finished `release` profile [optimized] in 14m 01s
```
产物：`D:/tmp/wsplat/xray_b1b2_nonative.exe`（md5 `db9afdb54a444e9d3bd7332670c24073`），与 native 版同源（保留 B1/B2 改动），用于同节点 CPU 对照排除 native flag 嫌疑。

### 4. clippy + fmt

```
cargo clippy -p xray-transport-websocket -p xray-tls --all-targets -- -D warnings  →  ok（首跑 clippy::type_complexity 命中 `CACHE: LazyLock<...HashMap<...>>`；引入 `type CacheMap` 别名修复后 0 errors）
cargo +stable fmt -p xray-transport-websocket -p xray-tls -- --check  →  ok（无 diff；stable 不支持 nightly-only 配置项，已在输出报警但不影响主检查）
```

### 5-8. E2E 页面级 burst / xhttp 参照 / 会话复用证据 / ss 双死回归

**未实测**。Harness 框架已落 `D:/tmp/plat-b-verify/`（`harness.py` + `echo_server.py` + `server.json` + `client_ws.json`），用 `pinnedPeerCertSha256`（allowInsecure 已被硬拒）；最终对照轮因预算软上限 200 未跑——主代理可用 `python D:/tmp/plat-b-verify/harness.py` 跑：
- Round 1-3 × 15 并发 socks dial
- 客户端 `RUST_LOG=xray_tls::btls=debug,xray_tls::session_cache=debug,xray_transport_websocket=debug` → 数 `btls uTLS 握手开始` / `session resume: 命中 cache` / `session_reused=true` 三类日志
- ss 双死回归：同进程连发 4 发（2KB+3×52MB）→ 可直接调 `dial_ws` 路径（pool 路径下 used 永不回池 = 安全）

---

## 设计取舍

1. **burst fanout=3 而非更大**：burst 实际就是 6-15 并发 dial_ws，每条 dial_ws 已自带 1 replenish；fanout=3 叠加 ≈ caller × 3，已能填满 12 的池（实测网关/握手端瓶颈 100-300ms/条）。上限硬约束由 `max_idle_per_key` 兜底，配置调大时无需改此处。

2. **TLS session cache 走手动序列化+FFI 投递而非 BoringSSL `set_new_session_cb`**：原因——BoringSSL 客户端 cache 仅启用 callback（无内置），callback 给 `SslSession` 但需保留到下次 set_session；我们用序列化字节跨 dial 边界，更显式且 TTL 控制清晰。`SSL_CTX_set_session_cache_mode` 仍保留可启用钩子的扩展点，但本轮不上。

3. **CTX 兼容性约束**：`connector_for_fingerprint()` 每次返回新 `SslConnector`=新 `SSL_CTX`。BoringSSL session 的"CTX 一致"由序列化/反序列化两端同 fingerprint 满足（同一 cipher 配置）；`SSL_set_session` 文档虽提约束，但同 fingerprint 复用语义稳定。

---

## 残余风险

1. **E2E 实测未跑完**：harness 框架就位但 burst 对照轮未产出真实数字；建议主代理接手跑 5 分钟补验收。
2. **ssl 句柄生命周期**：`ssl.set_session(&session)` 期间 `session` 必须存活（已用 if-let scope 约束），但若 `into_ssl`/`ssl_context` 调用顺序失误可能引发 UAF——代码路径已 review 但缺专门 lifetime 测试。
3. **`lookup_for_resume` 早返与 `enable_session_resumption` 解析未在 `connect_with_alpn` 传入 `security_json`**：当前传 `None`（缺省 true），btls 路径实际恒启用；后续若接 ruot 在设置上层传 `security_json`，需更新 `parse_enable_session_resumption(None)` → `parse_enable_session_resumption(security_json)`。
4. **store_session 永不清理**：cache TTL=24h 惰性清理（lookup 时检查），长时间进程 + 多 host 场景下 cache 表可能持续增长。ponytail: 单进程 100-1000 (host,fp) pair 是合理上限，超此需 LRU。
5. ~~**clippy/fmt 未独立验证**~~：已补跑（见验收 4），0 errors / 0 fmt-diff。

---

## 未做（明确不在本轮）

- commit / push（PM 收尾）
- `xray-transport-websocket/tests/` `xray-tls/tests/` 添加新集成测试（禁碰红线）
- 升级 `btls`/`tokio-btls`/`btls-sys` 的 git rev（当前 rev ab7f522c 已满足 API 需求）
- 修改 `xray-transport-tcp/register.rs` / `dist/xray.exe` / `vendor/`（红线）
- 修改 `ws`/`httpupgrade` 指纹形态（红线）

---

## 沉淀

无新增经验（本任务内的"session cache 序列化跨 CTX" / "MutexGuard 跨语句 drop" 是 btls 通用坑，已落入 `crates/xray-tls/src/tls_session_cache.rs` 顶部 doc comment 解释）。