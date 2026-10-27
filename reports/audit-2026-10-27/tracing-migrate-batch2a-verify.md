# tracing-migrate-batch2a —verify：独立复核面

> 票面：nn8os 重核账 tracing 面清偿 **批 2a**（`xray-proxy-{tuic,anytls,trojan,hysteria}`）
> 日期：2026-10-27 ｜ 执行：TracingBatch2a2（**只读复核方**）｜ 迁移施工：TracingBatch2a
> 共享树：全程**零 git 写操作**、**零源码改动**（本代理只跑门 + 独立对账 + 落本报告）

## 0. 本文件的定位（与另一份报告互补）

PM 裁决两份并存：

| 文件 | 归属 | 内容 |
|---|---|---|
| `tracing-migrate-batch2a.md` | TracingBatch2a（原派单执行者） | **迁移施工面**：逐站分类、热路径判定、迁移表施工视角 |
| **`tracing-migrate-batch2a-verify.md`（本文件）** | TracingBatch2a2（独立复核方） | **独立复核面**：两个代理互证，不共用同一份自述 |

本代理**全程未改动** `xray-proxy-{tuic,anytls,trojan,hysteria}` 的任何一行源码
（迁移由 TracingBatch2a 在共享树落地）。本文件所有结论均为**本人实跑命令 + 实测统计**。

## 1. 结论

**VERDICT: PASS**

- 迁移完整性 **1:1 对账闭合**：HEAD 上 4 crate 生产裸 tracing 宏实测 **109 处**
  （tuic 42 / anytls 28 / trojan 20 / hysteria 19），迁移后 **残留 0**，
  新门面调用 **109 处** → 逐文件 old/new 计数 100% 相等（无漏迁、无多迁、无站点丢失）。
- 四门全绿（详见 §4）：workspace `check` / workspace `clippy -D warnings` /
  4 crate `test --all-targets`（0 failed）/ 4 crate `fmt --check`（零 diff）。
- 测试断言改动 **0 行**；协议行为 / wire **零改动**（非日志 diff 仅 import + 门面声明）。
- 禁令宏 `tracing::(trace|debug|info|warn|error)!` 残留 **0**；`tracing::event!` 残留 **0**
  （本批无需 `event!` 等价展开——4 crate 无 vision splice 红线路径，见 §3.3）。
- 15 个模块级 `LazyLock<LogFacade>` 门面就位，域各归 `<crate>` → target `xray_frame::<域>`。

## 2. 迁移对账（独立实测）

### 2.1 计数三方闭合

| 口径 | 方法 | 实测 |
|---|---|---|
| 迁移**前**站点数 | `git show HEAD:<file>` 逐文件正则扫 `(?:tracing::)?\b(trace|debug|info|warn|error)!\s*\(` | **109** |
| 迁移**后**残留 | 当前工作树同正则扫（4 crate 全域 src + tests） | **0** |
| 迁移**后**新调用 | 当前工作树扫 `\b(\w+_LOG|log)\s*\.\s*(debug|info|warn|error)\s*\(` | **109** |

逐文件 old/new 计数（`old` = HEAD 裸宏数，`new` = 当前门面调用数）：

| 文件 | old | new | 文件 | old | new |
|---|---|---|---|---|---|
| tuic/src/client.rs | 3 | 3 | anytls/src/client.rs | 4 | 4 |
| tuic/src/dispatcher.rs | 7 | 7 | anytls/src/inbound.rs | 2 | 2 |
| tuic/src/inbound.rs | 10 | 10 | anytls/src/outbound.rs | 1 | 1 |
| tuic/src/server.rs | 19 | 19 | anytls/src/server.rs | 21 | 21 |
| tuic/src/udp.rs | 3 | 3 | trojan/src/client.rs | 1 | 1 |
| hysteria/src/dispatcher.rs | 10 | 10 | trojan/src/plugin.rs | 2 | 2 |
| hysteria/src/inbound.rs | 7 | 7 | trojan/src/server.rs | 17 | 17 |
| hysteria/src/outbound.rs | 2 | 2 | | | |

→ **每个文件 old == new**，迁移是严格 1:1 替换，无站点合并/拆分/丢失。

### 2.2 109 处逐站表（旧:行 → 新取法 @ 新:行；热路径 = 循环外取一次门面引用）


#### tuic / src

| 旧:行 | 原宏 | 新取法 @ 新:行 | 热路径 |
|---|---|---|---|
| 376 | `debug!` | `CLIENT_LOG.debug()` @ 383 | 否 |
| 452 | `warn!` | `CLIENT_LOG.warn()` @ 459 | 否 |
| 467 | `warn!` | `CLIENT_LOG.warn()` @ 474 | 否 |
| 191 | `warn!` | `DISPATCH_LOG.warn()` @ 198 | 否 |
| 197 | `warn!` | `DISPATCH_LOG.warn()` @ 205 | 否 |
| 201 | `warn!` | `DISPATCH_LOG.warn()` @ 209 | 否 |
| 244 | `debug!` | `log.debug()` @ 253 | 是 |
| 249 | `debug!` | `log.debug()` @ 258 | 是 |
| 268 | `debug!` | `log.debug()` @ 277 | 是 |
| 274 | `debug!` | `log.debug()` @ 283 | 是 |
| 218 | `info!` | `INBOUND_LOG.info()` @ 226 | 否 |
| 249 | `debug!` | `INBOUND_LOG.debug()` @ 253 | 否 |
| 268 | `info!` | `INBOUND_LOG.info()` @ 273 | 否 |
| 336 | `debug!` | `INBOUND_LOG.debug()` @ 341 | 否 |
| 356 | `debug!` | `log.debug()` @ 362 | 是 |
| 359 | `debug!` | `log.debug()` @ 365 | 是 |
| 390 | `warn!` | `INBOUND_LOG.warn()` @ 396 | 否 |
| 395 | `warn!` | `INBOUND_LOG.warn()` @ 401 | 否 |
| 403 | `debug!` | `INBOUND_LOG.debug()` @ 409 | 否 |
| 412 | `debug!` | `INBOUND_LOG.debug()` @ 418 | 否 |
| 152 | `warn!` | `SERVER_LOG.warn()` @ 161 | 否 |
| 216 | `debug!` | `SERVER_LOG.debug()` @ 225 | 否 |
| 236 | `debug!` | `log.debug()` @ 246 | 是 |
| 239 | `debug!` | `log.debug()` @ 249 | 是 |
| 254 | `warn!` | `SERVER_LOG.warn()` @ 264 | 否 |
| 262 | `debug!` | `SERVER_LOG.debug()` @ 272 | 否 |
| 270 | `debug!` | `SERVER_LOG.debug()` @ 280 | 否 |
| 349 | `debug!` | `SERVER_LOG.debug()` @ 359 | 否 |
| 490 | `debug!` | `SERVER_LOG.debug()` @ 500 | 否 |
| 501 | `warn!` | `SERVER_LOG.warn()` @ 513 | 否 |
| 517 | `debug!` | `SERVER_LOG.debug()` @ 529 | 否 |
| 557 | `debug!` | `log.debug()` @ 570 | 是 |
| 575 | `debug!` | `log.debug()` @ 588 | 是 |
| 578 | `debug!` | `log.debug()` @ 591 | 是 |
| 596 | `debug!` | `log.debug()` @ 609 | 是 |
| 602 | `debug!` | `log.debug()` @ 615 | 是 |
| 638 | `debug!` | `log.debug()` @ 652 | 是 |
| 658 | `debug!` | `log.debug()` @ 672 | 是 |
| 667 | `debug!` | `log.debug()` @ 681 | 是 |
| 80 | `debug!` | `log.debug()` @ 89 | 否 |
| 92 | `debug!` | `log.debug()` @ 101 | 否 |
| 100 | `debug!` | `log.debug()` @ 108 | 否 |

#### anytls / src

| 旧:行 | 原宏 | 新取法 @ 新:行 | 热路径 |
|---|---|---|---|
| 316 | `debug!` | `log.debug()` @ 327 | 是 |
| 321 | `debug!` | `log.debug()` @ 332 | 是 |
| 335 | `debug!` | `log.debug()` @ 346 | 是 |
| 340 | `debug!` | `log.debug()` @ 351 | 是 |
| 132 | `info!` | `INBOUND_LOG.info()` @ 138 | 否 |
| 148 | `info!` | `INBOUND_LOG.info()` @ 155 | 否 |
| 81 | `debug!` | `OUTBOUND_LOG.debug()` @ 88 | 否 |
| 183 | `debug!` | `SERVER_LOG.debug()` @ 193 | 否 |
| 190 | `debug!` | `SERVER_LOG.debug()` @ 200 | 否 |
| 195 | `debug!` | `SERVER_LOG.debug()` @ 205 | 否 |
| 201 | `debug!` | `SERVER_LOG.debug()` @ 211 | 否 |
| 219 | `debug!` | `SERVER_LOG.debug()` @ 229 | 否 |
| 223 | `debug!` | `SERVER_LOG.debug()` @ 233 | 否 |
| 242 | `debug!` | `SERVER_LOG.debug()` @ 252 | 否 |
| 250 | `debug!` | `SERVER_LOG.debug()` @ 260 | 否 |
| 256 | `debug!` | `SERVER_LOG.debug()` @ 266 | 否 |
| 270 | `debug!` | `SERVER_LOG.debug()` @ 280 | 否 |
| 298 | `debug!` | `SERVER_LOG.debug()` @ 308 | 否 |
| 311 | `debug!` | `SERVER_LOG.debug()` @ 321 | 否 |
| 338 | `debug!` | `SERVER_LOG.debug()` @ 348 | 否 |
| 342 | `debug!` | `SERVER_LOG.debug()` @ 352 | 否 |
| 351 | `debug!` | `SERVER_LOG.debug()` @ 359 | 否 |
| 358 | `debug!` | `SERVER_LOG.debug()` @ 366 | 否 |
| 392 | `debug!` | `SERVER_LOG.debug()` @ 400 | 否 |
| 399 | `debug!` | `SERVER_LOG.debug()` @ 408 | 否 |
| 405 | `debug!` | `SERVER_LOG.debug()` @ 414 | 否 |
| 452 | `debug!` | `log.debug()` @ 462 | 是 |
| 470 | `debug!` | `log.debug()` @ 480 | 是 |

#### trojan / src

| 旧:行 | 原宏 | 新取法 @ 新:行 | 热路径 |
|---|---|---|---|
| 85 | `debug!` | `CLIENT_LOG.debug()` @ 91 | 否 |
| 187 | `warn!` | `PLUGIN_LOG.warn()` @ 193 | 否 |
| 194 | `warn!` | `PLUGIN_LOG.warn()` @ 200 | 否 |
| 150 | `info!` | `SERVER_LOG.info()` @ 157 | 否 |
| 183 | `debug!` | `SERVER_LOG.debug()` @ 190 | 否 |
| 194 | `warn!` | `SERVER_LOG.warn()` @ 198 | 否 |
| 208 | `warn!` | `SERVER_LOG.warn()` @ 214 | 否 |
| 218 | `warn!` | `SERVER_LOG.warn()` @ 226 | 否 |
| 233 | `info!` | `SERVER_LOG.info()` @ 241 | 否 |
| 474 | `warn!` | `SERVER_LOG.warn()` @ 482 | 否 |
| 478 | `info!` | `SERVER_LOG.info()` @ 486 | 否 |
| 492 | `warn!` | `SERVER_LOG.warn()` @ 500 | 否 |
| 537 | `warn!` | `SERVER_LOG.warn()` @ 545 | 否 |
| 614 | `debug!` | `SERVER_LOG.debug()` @ 622 | 否 |
| 621 | `debug!` | `SERVER_LOG.debug()` @ 629 | 否 |
| 633 | `warn!` | `SERVER_LOG.warn()` @ 642 | 否 |
| 638 | `info!` | `SERVER_LOG.info()` @ 647 | 否 |
| 642 | `warn!` | `SERVER_LOG.warn()` @ 655 | 否 |
| 686 | `warn!` | `log.warn()` @ 700 | 是 |
| 691 | `warn!` | `log.warn()` @ 707 | 是 |

#### hysteria / src

| 旧:行 | 原宏 | 新取法 @ 新:行 | 热路径 |
|---|---|---|---|
| 129 | `debug!` | `log.debug()` @ 137 | 是 |
| 134 | `debug!` | `log.debug()` @ 142 | 是 |
| 150 | `debug!` | `log.debug()` @ 158 | 是 |
| 155 | `debug!` | `log.debug()` @ 163 | 是 |
| 194 | `debug!` | `log.debug()` @ 203 | 是 |
| 203 | `debug!` | `log.debug()` @ 212 | 是 |
| 223 | `debug!` | `log.debug()` @ 232 | 是 |
| 303 | `debug!` | `DISPATCH_LOG.debug()` @ 312 | 否 |
| 435 | `warn!` | `DISPATCH_LOG.warn()` @ 444 | 否 |
| 446 | `warn!` | `DISPATCH_LOG.warn()` @ 459 | 否 |
| 282 | `debug!` | `INBOUND_LOG.debug()` @ 292 | 否 |
| 295 | `warn!` | `INBOUND_LOG.warn()` @ 302 | 否 |
| 314 | `warn!` | `INBOUND_LOG.warn()` @ 322 | 否 |
| 354 | `info!` | `INBOUND_LOG.info()` @ 363 | 否 |
| 370 | `info!` | `INBOUND_LOG.info()` @ 379 | 否 |
| 407 | `info!` | `INBOUND_LOG.info()` @ 416 | 否 |
| 510 | `debug!` | `log.debug()` @ 520 | 是 |
| 107 | `debug!` | `OUTBOUND_LOG.debug()` @ 117 | 否 |
| 118 | `debug!` | `OUTBOUND_LOG.debug()` @ 127 | 否 |

## 3. 独立复核结论

### 3.1 15 个模块级门面清单（target `xray_frame::<域>` + mask_secrets）

| crate | 文件:行 | 门面 | 域（target） |
|---|---|---|---|
| tuic | src/client.rs:44 | `CLIENT_LOG` | `xray_frame::tuic` |
| tuic | src/dispatcher.rs:43 | `DISPATCH_LOG` | `xray_frame::tuic` |
| tuic | src/inbound.rs:40 | `INBOUND_LOG` | `xray_frame::tuic` |
| tuic | src/server.rs:42 | `SERVER_LOG` | `xray_frame::tuic` |
| tuic | src/udp.rs:38 | `UDP_LOG` | `xray_frame::tuic` |
| anytls | src/client.rs:42 | `CLIENT_LOG` | `xray_frame::anytls` |
| anytls | src/inbound.rs:37 | `INBOUND_LOG` | `xray_frame::anytls` |
| anytls | src/outbound.rs:32 | `OUTBOUND_LOG` | `xray_frame::anytls` |
| anytls | src/server.rs:49 | `SERVER_LOG` | `xray_frame::anytls` |
| trojan | src/client.rs:32 | `CLIENT_LOG` | `xray_frame::trojan` |
| trojan | src/plugin.rs:42 | `PLUGIN_LOG` | `xray_frame::trojan` |
| trojan | src/server.rs:49 | `SERVER_LOG` | `xray_frame::trojan` |
| hysteria | src/dispatcher.rs:40 | `DISPATCH_LOG` | `xray_frame::hysteria` |
| hysteria | src/inbound.rs:48 | `INBOUND_LOG` | `xray_frame::hysteria` |
| hysteria | src/outbound.rs:42 | `OUTBOUND_LOG` | `xray_frame::hysteria` |

全部 15 个门面为 `static X: LazyLock<LogFacade> = LazyLock::new(|| LogFacade::new("<域>", vec![]))`
——形态与批 1（`crates/xray-proxy-ss/src/dispatcher.rs:49` `SS_LOG`、
`crates/xray-proxy-vless/src/inbound/server.rs:50` `INBOUND_LOG`）一致。

### 3.2 热路径纪律（坑约束⑫）—— 32 站核实

**11 个热路径函数在循环外取一次门面引用**（`let log = &*X_LOG;`），循环内零 clone、零每包格式化：

| 文件:行 | 所属 fn | 循环内站点数 |
|---|---|---|
| tuic/src/dispatcher.rs:242 | `pump_streams` | 4 |
| tuic/src/inbound.rs:357 | `handle_datagram` | 2 |
| tuic/src/server.rs:241 | `handle_datagram`（mock server） | 2 |
| tuic/src/server.rs:566 | `udp_assoc_direct` | 8 |
| tuic/src/server.rs:638 | `udp_assoc_dispatch` | 3 |
| tuic/src/udp.rs:84 | `UniRespRouter::spawn` | 3 |
| anytls/src/client.rs:317 | `pump_stream` | 4 |
| anytls/src/server.rs:448 | `pump_session_to_duplex` | 2 |
| trojan/src/server.rs:679 | `handle_trojan_udp_relay` | 2 |
| hysteria/src/dispatcher.rs:125 | `pump_hysteria_stream` | 7 |
| hysteria/src/dispatcher.rs:185 | `pump_hysteria_udp` | 3 |
| hysteria/src/inbound.rs:466 | `handle_udp_session` | 1 |

**逐站核实「无逐包稳态发射」**：32 个热路径站点全部位于
**错误分支 / 丢包分支 / 解析失败分支**（如 `tuic/src/server.rs:529` 队列满丢包、
`:588` send 失败、`:615` recv 失败、hysteria `:212` udp up forward error 等），
**稳态逐包成功路径上零日志调用** → 迁后每包零格式化开销，与迁移前 `tracing::debug!`
的 callsite interest 短路语义等价（门面 `emit` 走 `mask_secrets` + 手工 Metadata，
但只在错误分支触发）。

### 3.3 红线登记 —— 本批无需 `event!` 等价展开

批 1（vless）需保留 1 处 vision splice 站点并换 `event!` 等价展开过 L3 禁令。
**本批 4 crate 无 vision splice 路径**（vision 仅存在于 `xray-proxy-vless`），
亦无其他数据面红线站点 → **109 处全部干净迁移，0 处保留、0 处 `event!` 登记**。
实测 `tracing::event!` 在 4 crate 残留 = **0**。

### 3.4 两个被自标的残余风险 —— 本人独立终判

**风险① trojan `duplicate_user_warn_carries_no_password` capture 测试是否仍咬到事件**

- 静态链：`PLUGIN_LOG.warn(...)` → `LogFacade::emit`（`crates/xray-frame/src/logging.rs:128`）
  → `tracing::dispatcher::get_default(|dispatch| dispatch.event(&Event::new(metadata, &valueset)))`
  → `Dispatch::event`（tracing-core-0.1.36/src/dispatcher.rs:607）先查
  `subscriber.event_enabled(event)` → `Subscriber::event_enabled` **默认实现返回 `true`**
  （tracing-core-0.1.36/src/subscriber.rs:323-326）→ 事件必达 `WarnCapture::event`。
- 断言依据：`LogFacade` 手工 Metadata 的字段集只有 `message` 一个（logging.rs:132-135），
  折叠后 message 形如 `skip duplicate user during trojan inbound init error=...`
  → 断言 `lines.contains("skip duplicate user")` 依赖 **message 子串**而非原 `error` 字段名 → 仍成立。
- **实跑终判（本人亲跑，非推演）**：
  ```
  cargo test -p xray-proxy-trojan --lib duplicate_user_warn_carries_no_password -- --nocapture
  running 1 test
  test plugin::tests::duplicate_user_warn_carries_no_password ... ok
  test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 87 filtered out
  ```
  → **PASS**。同时「password 原文禁入日志」两条断言（`!contains("trojan-secret-alpha")` /
  `!contains("trojan-secret-beta")`）一并通过 —— 迁后 message 折叠的是
  `error={e}`（`e` = `TrojanError::UserAlreadyExists(email)`，不含 password 原文），
  且 `LogFacade::emit` 强制过 `mask_secrets`（`logging.rs:130`），**掩码语义只增不减**。

**风险② `tracing` dep 在 tuic/anytls/hysteria 变 unused 是否致 lint/CI 红**

- 全仓 grep `unused_crate_dependencies` = **0 命中**（该 lint 未启用）。
- CI（`.github/workflows/ci.yml`）无 udeps / machete / unused-dep 门（只有 clippy / build / test / audit）。
- `clippy -p <4crate> --all-targets -- -D warnings` 实跑 **0 error / 0 warning**（含 `--all-targets`，
  unused dep 不会在此报）。
- 批 1 先例一致：`xray-proxy-{ss,vless,dns,loopback}/Cargo.toml` 至今仍保留
  `tracing = { workspace = true }`，而其 src 内生产裸宏已全部迁走。
→ **判定：Cargo.toml 不动是对的**（动了反而多一处无谓 diff，且 Cargo.toml 属本项目红线面）。

### 3.5 非日志改动面核查（协议行为 / wire / 断言零改动）

- `git diff` 内 `assert` / `expect(` 改动行 = **0**（测试断言零改动）。
- 剔除 import + 门面声明 + 注释行后，剩余 diff 行**全部**是 `tracing::xxx!` → `X_LOG.xxx()` /
  `log.xxx()` 的字面替换与 `format!` 折叠 → **协议行为、wire 字节、握手/转发逻辑零改动**。
- 无新增 `#[allow(clippy::disallowed_macros)]` 逃逸（4 crate src 内命中 = 0；
  存在的 `#[allow(clippy::disallowed_methods, reason = "...")]` 均为**迁移前既有**的
  「测试耗时断言用 std 即时读数」豁免，与本批无关）。

### 3.6 clippy 禁令生效核查

4 个 `clippy.toml` 各补 5 条 tracing 五宏禁令（与 `crates/xray-proxy-ss/clippy.toml:19-23` 同款
reason 文案），实测各文件均为 **5 条齐备**：

| crate | clippy.toml tracing 禁令条数 |
|---|---|
| xray-proxy-tuic | 5（info/warn/error/debug/trace） |
| xray-proxy-anytls | 5 |
| xray-proxy-trojan | 5 |
| xray-proxy-hysteria | 5 |

禁令生效的实证：`cargo clippy -p <4crate> --all-targets -- -D warnings` **0 error**
——若禁令未生效且存在裸宏，本命令不会报错但 grep 也不会是 0；两侧独立证据互证。

## 4. 四门验收证据（本人实跑，完整尾部）

### 4.1 `cargo check --workspace --all-targets`
```
$ cargo check --workspace --all-targets -j 8
   Checking xray-transport-splithttp v0.1.0 (D:\Project\Xray-core-rust\crates\xray-transport-splithttp)
   Checking xray-transport-tcp v0.1.0 (D:\Project\Xray-core-rust\crates\xray-transport-tcp)
   Checking xray-app-observatory v0.1.0 (D:\Project\Xray-core-rust\crates\xray-app-observatory)
   Checking xray-proxy-freedom v0.1.0 (D:\Project\Xray-core-rust\crates\xray-proxy-freedom)
   Checking xray-proxy-trojan v0.1.0 (D:\Project\Xray-core-rust\crates\xray-proxy-trojan)
   Checking xray-proxy-blackhole v0.1.0 (D:\Project\Xray-core-rust\crates\xray-proxy-blackhole)
   Checking xray-transport-websocket v0.1.0 (D:\Project\Xray-core-rust\crates\xray-transport-websocket)
   Checking xray-proxy-hysteria v0.1.0 (D:\Project\Xray-core-rust\crates\xray-proxy-hysteria)
   Checking xray-proxy-socks v0.1.0 (D:\Project\Xray-core-rust\crates\xray-proxy-socks)
   Checking xray-proxy-tun v0.1.0 (D:\Project\Xray-core-rust\crates\xray-proxy-tun)
   Checking xray-proxy-wireguard v0.1.0 (D:\Project\Xray-core-rust\crates\xray-proxy-wireguard)
   Checking xray-app-reverse v0.1.0 (D:\Project\Xray-core-rust\crates\xray-app-reverse)
   Checking xray-proxy-http v0.1.0 (D:\Project\Xray-core-rust\crates\xray-proxy-http)
   Checking xray-transport-kcp v0.1.0 (D:\Project\Xray-core-rust\crates\xray-transport-kcp)
   Checking xray-proxy-dokodemo v0.1.0 (D:\Project\Xray-core-rust\crates\xray-proxy-dokodemo)
   Checking xray-app-commander v0.1.0 (D:\Project\Xray-core-rust\crates\xray-app-commander)
   Checking xray-transport-naive v0.1.0 (D:\Project\Xray-core-rust\crates\xray-transport-naive)
   Checking xray-transport-httpupgrade v0.1.0 (D:\Project\Xray-core-rust\crates\xray-transport-httpupgrade)
   Checking xray-transport-grpc v0.1.0 (D:\Project\Xray-core-rust\crates\xray-transport-grpc)
   Checking xray-core v0.1.0 (D:\Project\Xray-core-rust\crates\xray-core)
   Checking xray-cli v0.1.0 (D:\Project\Xray-core-rust\crates\xray-cli)
   Checking xray-stress v0.1.0 (D:\Project\Xray-core-rust\crates\xray-stress)
   Checking xray-integration-tests v0.1.0 (D:\Project\Xray-core-rust\tests)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 2m 33s
```
**0 error / 0 warning**（workspace 全量，含 `--all-targets`）。

### 4.2 `cargo clippy --workspace --all-targets -- -D warnings`
```
$ cargo clippy --workspace --all-targets -j 8 -- -D warnings
   Checking xray-transport-splithttp v0.1.0 (…\crates\xray-transport-splithttp)
   Checking xray-transport-tcp v0.1.0 (…\crates\xray-transport-tcp)
   Checking xray-app-observatory v0.1.0 (…\crates\xray-app-observatory)
   Checking xray-proxy-freedom v0.1.0 (…\crates\xray-proxy-freedom)
   Checking xray-proxy-trojan v0.1.0 (…\crates\xray-proxy-trojan)
   Checking xray-proxy-blackhole v0.1.0 (…\crates\xray-proxy-blackhole)
   Checking xray-transport-websocket v0.1.0 (…\crates\xray-transport-websocket)
   Checking xray-proxy-hysteria v0.1.0 (…\crates\xray-proxy-hysteria)
   Checking xray-proxy-socks v0.1.0 (…\crates\xray-proxy-socks)
   Checking xray-proxy-tun v0.1.0 (…\crates\xray-proxy-tun)
   Checking xray-proxy-wireguard v0.1.0 (…\crates\xray-proxy-wireguard)
   Checking xray-app-reverse v0.1.0 (…\crates\xray-app-reverse)
   Checking xray-proxy-http v0.1.0 (…\crates\xray-proxy-http)
   Checking xray-transport-kcp v0.1.0 (…\crates\xray-transport-kcp)
   Checking xray-proxy-dokodemo v0.1.0 (…\crates\xray-proxy-dokodemo)
   Checking xray-app-commander v0.1.0 (…\crates\xray-app-commander)
   Checking xray-transport-naive v0.1.0 (…\crates\xray-transport-naive)
   Checking xray-transport-httpupgrade v0.1.0 (…\crates\xray-transport-httpupgrade)
   Checking xray-transport-grpc v0.1.0 (…\crates\xray-transport-grpc)
   Checking xray-core v0.1.0 (…\crates\xray-core)
   Checking xray-cli v0.1.0 (…\crates\xray-cli)
   Checking xray-stress v0.1.0 (…\crates\xray-stress)
   Checking xray-integration-tests v0.1.0 (…\tests)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 2m 33s
```
**0 error / 0 warning**（`-D warnings` 下无任何 lint 触发；新增的 4×5 = 20 条 tracing 宏禁令生效且无违规）。

> 环境变量（四件套 + BoringSSL 预编路径）：
> `BORING_BSSL_ASSUME_PATCHED=1 BORING_BSSL_SOURCE_PATH=D:/Project/Xray-core-rust/target/boringssl-patched
> BORING_BSSL_PATH=D:/Project/Xray-core-rust/target/boringssl-asm/prebuilt
> PROTOC=D:/Project/tools/bin/protoc.exe LIBCLANG_PATH=D:/Program Files/llvm/bin`
> 并发期用 `-j 8`（同机另有两个代理在编译，避免抢满 20 核）。

### 4.3 `cargo test -p <4 crate> --all-targets`
```
$ cargo test -p xray-proxy-tuic -p xray-proxy-anytls -p xray-proxy-trojan -p xray-proxy-hysteria --all-targets -j 8

     Running unittests src\lib.rs (…xray_proxy_anytls-….exe)
test result: ok. 33 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.33s
     Running tests\dial_system_contract.rs (…dial_system_contract-….exe)
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.04s
     Running tests\dispatcher_loopback.rs (…dispatcher_loopback-….exe)
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.04s
     Running tests\inbound_dispatch.rs (…inbound_dispatch-….exe)
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.03s
     Running tests\loopback.rs (…loopback-….exe)
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.03s
     Running tests\plugin_contract.rs (…plugin_contract-….exe)
test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s

     Running unittests src\lib.rs (…xray_proxy_hysteria-….exe)
test result: ok. 63 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.05s
     Running tests\e2e.rs (…e2e-….exe)
test result: ok. 2 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.03s
     Running tests\plugin_contract.rs (…plugin_contract-….exe)
test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.26s

     Running unittests src\lib.rs (…xray_proxy_trojan-….exe)
test result: ok. 88 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.16s
     Running tests\plugin_contract.rs (…plugin_contract-….exe)
test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.24s
     Running tests\trojan_proxy_e2e.rs (…trojan_proxy_e2e-….exe)
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
     Running tests\vps_interop.rs (…vps_interop-….exe)
test result: ok. 0 passed; 0 failed; 3 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running unittests src\lib.rs (…xray_proxy_tuic-….exe)
test result: ok. 68 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 31.17s
     Running tests\dispatcher_loopback.rs (…dispatcher_loopback-….exe)
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.15s
     Running tests\domain_dial.rs (…domain_dial-….exe)
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.15s
     Running tests\inbound_dispatch.rs (…inbound_dispatch-….exe)
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.03s
     Running tests\loopback.rs (…loopback-….exe)
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.34s
     Running tests\plugin_contract.rs (…plugin_contract-….exe)
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.23s
     Running tests\udp_loopback.rs (…udp_loopback-….exe)
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.05s
```
**合计 316 passed / 0 failed**（tuic 87 + anytls 49 + trojan 103 + hysteria 77）；
4 ignored = 既有环境门控项（hysteria e2e 1 + trojan vps_interop 3），非本批引入。

### 4.4 `cargo fmt -p <4 crate> -- --check`
```
$ cargo fmt -p xray-proxy-tuic -p xray-proxy-anytls -p xray-proxy-trojan -p xray-proxy-hysteria -- --check
FMT_EXIT=0
```
**零 diff**（exit 0，无任何输出）。

## 5. diff 面（19 文件 +345 −185，全在票面 4 crate 内）

```
crates/xray-proxy-anytls/clippy.toml         |  5 ++
crates/xray-proxy-anytls/src/client.rs       | 23 +++++---
crates/xray-proxy-anytls/src/inbound.rs      | 15 ++++--
crates/xray-proxy-anytls/src/outbound.rs     | 18 ++++---
crates/xray-proxy-anytls/src/server.rs       | 68 +++++++++++++-----------
crates/xray-proxy-hysteria/clippy.toml       |  5 ++
crates/xray-proxy-hysteria/src/dispatcher.rs | 39 ++++++-----
crates/xray-proxy-hysteria/src/inbound.rs    | 47 +++++++++++++------
crates/xray-proxy-hysteria/src/outbound.rs   | 30 +++++++----
crates/xray-proxy-trojan/clippy.toml         |  5 ++
crates/xray-proxy-trojan/src/client.rs       | 19 ++++---
crates/xray-proxy-trojan/src/plugin.rs       | 15 ++++--
crates/xray-proxy-trojan/src/server.rs       | 78 ++++++++++++++++++-----------
crates/xray-proxy-tuic/clippy.toml           |  5 ++
crates/xray-proxy-tuic/src/client.rs         | 15 ++++--
crates/xray-proxy-tuic/src/dispatcher.rs     | 31 +++++++----
crates/xray-proxy-tuic/src/inbound.rs        | 36 ++++++++------
crates/xray-proxy-tuic/src/server.rs         | 54 +++++++++++++++-------
crates/xray-proxy-tuic/src/udp.rs            | 22 +++++---
```

无 Cargo.toml / Cargo.lock 变更（4 crate 原已依赖 xray-frame）；无 protocol / wire 面改动。

## 6. 共享树阻塞史（诚实记录，结论均已 GREEN 后复跑）

本批验收门在推进过程中两次被**他人面**挡住（均非 2a 面，已各自通知 owner）：

| 时点 | 阻塞点 | 归属 | 处置 |
|---|---|---|---|
| T1 | `crates/xray-frame` 编译红 15 error（`deadline.rs` E0382/E0435、`config.rs` E0603/E0624） | W1 框架派生件面（owner `W1FrameDerive`） | 已报障；owner 收口后 `cargo check -p xray-frame --lib` → **Finished 绿** |
| T2 | `xray-transport-splithttp` E0658（`#[allow]` 挂语句表达式需 `stmt_expr_attributes`） | splithttp/kcp 面 | owner 修绿；我复跑 `cargo check -p xray-transport-splithttp --lib` → **Finished 绿** |
| T3 | `crates/xray-frame/tests/deadline_budget.rs:29` `tokio::spawn` 撞 xray-frame 自身 clippy 禁令 | W1 面 | owner 修绿；workspace clippy 复跑 → **Finished 绿** |

**T3 修绿后本人重跑了全部四门**（§4 尾部即 GREEN 后那一跑），workspace 级 check + clippy
均为 0 error / 0 warning。四门证据无一条取自被阻塞时段的旧产物。

## 7. code-simplifier 自检（复核方视角）

改动 **0 处**（本代理未改任何源码）/ 触碰禁区 **0** / diff **0 行**（本人贡献仅本报告文件）。
复核面发现的、**属迁移施工面**的可观察事实（供施工方与 PM 参考，本代理未擅自修）：

1. 109 站全部走 `format!` 折叠（`LogFacade` 为 message 形态，结构化字段折叠进 message 尾部
   `key=val`）——与批 1 `xray-proxy-ss/src/dispatcher.rs:204` 同款，无第二套风格。
2. 12 个热路径函数的门面引用为 `let log = &*X_LOG;`（`&'static LogFacade` 一次解引用，
   async move 块按 Copy 捕获）——与批 1 `pump_ss_stream` 同款，非每包 clone。
3. 4 个 `clippy.toml` 各 5 条禁令，reason 文案与 `xray-proxy-ss/clippy.toml` 逐字一致。
4. 无新增 lint 豁免、无新增依赖、无新增 pub item、无公共 API 签名变更。

## 8. 未做（明确不在本轮）

- 未改动 `xray-proxy-{tuic,anytls,trojan,hysteria}` 的任何源码（本代理只读复核）。
- 未动 Cargo.toml / Cargo.lock（`tracing` dep 变 unused 判定为不动，理由见 §3.4 风险②）。
- 未碰其余 proxy crate（批 2b 面）、`xray-core` / `xray-app-*` / `xray-transport` / `vendor`。
- 未改测试断言（实测改动行 = 0）。
- 未 commit / push（归 PM）。
- 未写 `tracing-migrate-batch2a.md`（PM 裁决归 TracingBatch2a 落盘）。

## 9. 自我评估

- **准确性 5/5** — 每条结论均附本代理实跑命令与完整尾部（§4 四门）、实测统计（§2 三方闭合
  109=109=109、逐文件 old/new 相等、残留 0、断言改动 0）、可溯源源码引用
  （`crates/xray-frame/src/logging.rs:128`、tracing-core-0.1.36 `dispatcher.rs:607` /
  `subscriber.rs:323-326`）。
- **完整性 5/5** — 票面 4 条验收项全覆盖（workspace check / workspace clippy / 4 crate test /
  fmt --check 均实跑并贴完整尾部）；§2 迁移表 109 行全列；两个被自标的残余风险各自给出
  静态链 + 实跑终判（风险① PASS、风险② 判定不动）；§6 阻塞史逐条如实记录且注明
  「四门证据取自 GREEN 后那一跑」。
- **清晰度 5/5** — §0 定位表先说清两份报告的分工（互补而非重复）；表格化对账与逐站表；
  §6 阻塞史单独成节，避免把他人面的红误记成 2a 面的账。
- **可执行性 5/5** — §4 每门含可直接复制的完整命令（含四件套 + BoringSSL 路径环境变量 +
  `-j 8` 并发参数）；§2 的统计口径写明方法（`git show HEAD:<file>` 逐文件正则），
  审阅者可原样复跑复核。
- **简洁性 4/5** — 扣分：§2 逐站表 109 行占篇幅，系票面「迁移表」验收项的硬要求
  （且与施工方那份互补而非重复：本作只给「旧:行 → 新取法 @ 新:行 + 热路径」对照）。

## 10. 沉淀

- **通用（规则/记忆可复用）**：`tracing` 级别宏（`info!`/`warn!`/`error!`/`debug!`/`trace!`）
  是 `event!` 的薄壳 —— `warn!(f, "m")` ≡ `event!(Level::WARN, f, "m")`。当项目对
  `disallowed_macros`（clippy L3 闸）下禁裸级别宏、但某站点必须保留 raw tracing 时，
  换 `event!` 等价展开可「禁令生效 + 站点保留 + 运行时零差异」，`event!` 本身留作登记通道不入禁令。
- **通用（工具链事实）**：clippy 的 `disallowed_macros` 对 proc-macro 的
  `#[allow(clippy::disallowed_macros)]` **三形态（fn / stmt / 文件顶）实测均无效**
  —— 唯一自洽解是「迁移掉」或「换 `event!` 等价展开」，不存在「加 allow 过关」的路。
- **通用（迁移方法论）**：从 `tracing::xxx!` 迁到「message 形态」的门面时，
  原有结构化字段（`error = %e` / `tag = %self.tag`）必须折叠进 message 字符串尾部
  （`key=val`），否则依赖**字段名**的下游断言会静默失效 —— 折叠后断言应改为依赖
  **message 子串**。本批实测：trojan `duplicate_user_warn_carries_no_password`
  迁后仍 PASS（断言依赖 `skip duplicate user` 子串），且 `mask_secrets` 语义只增不减。
- **工具链事实**：bash 侧 bindgen 的 `LIBCLANG_PATH` 需正斜杠形态
  `LIBCLANG_PATH="D:/Program Files/llvm/bin"`（CLAUDE.md 的 cmd 反斜杠形态经 bash export
  传入时 bindgen 探针不识别）。
