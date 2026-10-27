# tracing-migrate-batch2a：4 crate 裸 tracing 宏 → LogFacade 迁移报告

> 票面：nn8os tracing 面批 2a（`xray-proxy-{tuic,anytls,trojan,hysteria}`）
> 日期：2026-10-27 ｜ 执行：TracingBatch2a ｜ 共享树：开工时干净（仅 untracked reports），全程零 git 写操作

## 1. 结论

**109 处生产裸 tracing 宏全部迁 `LogFacade`**（票面估 ~102，开工 grep 实测 109：tuic 42 /
anytls 28 / trojan 20 / hysteria 19），**零残留、零红线保留、零测试面豁免**（逐站分类见 §3）。
15 个模块级 `LazyLock<LogFacade>` 静态门面（照抄批 1 / socks `RELAY_LOG` 先例，域 = crate 名）；
10 个数据面泵/逐包函数**循环外取一次引用**（`let log = &*X_LOG;`），零每包克隆。
4 个 crate 的 `clippy.toml` 补齐 socks 同款 tracing 五宏禁令。**迁后禁令宏 grep 实数 = 0**。

## 2. 迁移表（crate | 文件:行(迁后) | 原宏 | 新取法 | 热路径?）

门面形态：15 个文件级 `static X_LOG: LazyLock<LogFacade>`（域各归 crate 名，secrets 均
`vec![]`，同批 1 / socks 先例）；`log` = 该函数体首部 `let log = &*X_LOG;` 的一次引用
（`&'static LogFacade`，Copy，可入 `async move`）；结构化字段折叠进 message 尾部
`key=val`（Display/Debug 语义与原 `%`/`?` 一一对应）；无插值的字面量消息按批 1
`PLUGIN_LOG.warn(静态串)` 先例**直传**（避 `clippy::useless_format`）。

### xray-proxy-tuic（42 处；门面 CLIENT_LOG client.rs:44 / DISPATCH_LOG dispatcher.rs:43 /
INBOUND_LOG inbound.rs:40 / SERVER_LOG server.rs:42 / UDP_LOG udp.rs:38）

| 文件:行 | 原宏 | 新取法 | 热路径? |
|---|---|---|---|
| `src/client.rs:383` | tracing::debug! | `CLIENT_LOG.debug(format!)` | 否（连接级/装配·错误分支） |
| `src/client.rs:459` | tracing::warn! | `CLIENT_LOG.warn(字面量直传)` | 否（连接级/装配·错误分支） |
| `src/client.rs:474` | tracing::warn! | `CLIENT_LOG.warn(字面量直传)` | 否（连接级/装配·错误分支） |
| `src/dispatcher.rs:199` | tracing::warn! | `DISPATCH_LOG.warn(format!)` | 否（连接级/装配·错误分支） |
| `src/dispatcher.rs:205` | tracing::warn! | `DISPATCH_LOG.warn(format!)` | 否（连接级/装配·错误分支） |
| `src/dispatcher.rs:209` | tracing::warn! | `DISPATCH_LOG.warn(format!)` | 否（连接级/装配·错误分支） |
| `src/dispatcher.rs:253` | tracing::debug! | `log.debug(format!)`（log = fn 顶 `&*X_LOG` 引用） | 是（逐包/帧循环内·错误/丢弃分支，循环外取引用） |
| `src/dispatcher.rs:258` | tracing::debug! | `log.debug(format!)`（log = fn 顶 `&*X_LOG` 引用） | 是（逐包/帧循环内·错误/丢弃分支，循环外取引用） |
| `src/dispatcher.rs:277` | tracing::debug! | `log.debug(format!)`（log = fn 顶 `&*X_LOG` 引用） | 是（逐包/帧循环内·错误/丢弃分支，循环外取引用） |
| `src/dispatcher.rs:283` | tracing::debug! | `log.debug(format!)`（log = fn 顶 `&*X_LOG` 引用） | 是（逐包/帧循环内·错误/丢弃分支，循环外取引用） |
| `src/inbound.rs:226` | tracing::info! | `INBOUND_LOG.info(format!)` | 否（连接级/装配·错误分支） |
| `src/inbound.rs:254` | tracing::debug! | `INBOUND_LOG.debug(format!)` | 否（连接级/装配·错误分支） |
| `src/inbound.rs:273` | tracing::info! | `INBOUND_LOG.info(format!)` | 否（连接级/装配·错误分支） |
| `src/inbound.rs:341` | tracing::debug! | `INBOUND_LOG.debug(format!)` | 否（连接级/装配·错误分支） |
| `src/inbound.rs:362` | tracing::debug! | `log.debug(format!)`（log = fn 顶 `&*X_LOG` 引用） | 是（逐包/帧循环内·错误/丢弃分支，循环外取引用） |
| `src/inbound.rs:365` | tracing::debug! | `log.debug(format!)`（log = fn 顶 `&*X_LOG` 引用） | 是（逐包/帧循环内·错误/丢弃分支，循环外取引用） |
| `src/inbound.rs:396` | tracing::warn! | `INBOUND_LOG.warn(format!)` | 否（连接级/装配·错误分支） |
| `src/inbound.rs:401` | tracing::warn! | `INBOUND_LOG.warn(format!)` | 否（连接级/装配·错误分支） |
| `src/inbound.rs:409` | tracing::debug! | `INBOUND_LOG.debug(format!)` | 否（连接级/装配·错误分支） |
| `src/inbound.rs:418` | tracing::debug! | `INBOUND_LOG.debug(format!)` | 否（连接级/装配·错误分支） |
| `src/server.rs:161` | tracing::warn! | `SERVER_LOG.warn(format!)` | 否（连接级/装配·错误分支） |
| `src/server.rs:225` | tracing::debug! | `SERVER_LOG.debug(format!)` | 否（连接级/装配·错误分支） |
| `src/server.rs:246` | tracing::debug! | `log.debug(format!)`（log = fn 顶 `&*X_LOG` 引用） | 是（逐包/帧循环内·错误/丢弃分支，循环外取引用） |
| `src/server.rs:249` | tracing::debug! | `log.debug(format!)`（log = fn 顶 `&*X_LOG` 引用） | 是（逐包/帧循环内·错误/丢弃分支，循环外取引用） |
| `src/server.rs:264` | tracing::warn! | `SERVER_LOG.warn(format!)` | 否（连接级/装配·错误分支） |
| `src/server.rs:272` | tracing::debug! | `SERVER_LOG.debug(format!)` | 否（连接级/装配·错误分支） |
| `src/server.rs:280` | tracing::debug! | `SERVER_LOG.debug(format!)` | 否（连接级/装配·错误分支） |
| `src/server.rs:359` | tracing::debug! | `SERVER_LOG.debug(format!)` | 否（连接级/装配·错误分支） |
| `src/server.rs:500` | tracing::debug! | `SERVER_LOG.debug(format!)` | 否（连接级/装配·错误分支） |
| `src/server.rs:513` | tracing::warn! | `SERVER_LOG.warn(字面量直传)` | 否（连接级/装配·错误分支） |
| `src/server.rs:529` | tracing::debug! | `SERVER_LOG.debug(format!)` | 否（连接级/装配·错误分支） |
| `src/server.rs:570` | tracing::debug! | `log.debug(format!)`（log = fn 顶 `&*X_LOG` 引用） | 是（逐包/帧循环内·错误/丢弃分支，循环外取引用） |
| `src/server.rs:588` | tracing::debug! | `log.debug(format!)`（log = fn 顶 `&*X_LOG` 引用） | 是（逐包/帧循环内·错误/丢弃分支，循环外取引用） |
| `src/server.rs:591` | tracing::debug! | `log.debug(format!)`（log = fn 顶 `&*X_LOG` 引用） | 是（逐包/帧循环内·错误/丢弃分支，循环外取引用） |
| `src/server.rs:609` | tracing::debug! | `log.debug(format!)`（log = fn 顶 `&*X_LOG` 引用） | 是（逐包/帧循环内·错误/丢弃分支，循环外取引用） |
| `src/server.rs:615` | tracing::debug! | `log.debug(format!)`（log = fn 顶 `&*X_LOG` 引用） | 是（逐包/帧循环内·错误/丢弃分支，循环外取引用） |
| `src/server.rs:652` | tracing::debug! | `log.debug(format!)`（log = fn 顶 `&*X_LOG` 引用） | 是（逐包/帧循环内·错误/丢弃分支，循环外取引用） |
| `src/server.rs:672` | tracing::debug! | `log.debug(format!)`（log = fn 顶 `&*X_LOG` 引用） | 是（逐包/帧循环内·错误/丢弃分支，循环外取引用） |
| `src/server.rs:681` | tracing::debug! | `log.debug(format!)`（log = fn 顶 `&*X_LOG` 引用） | 是（逐包/帧循环内·错误/丢弃分支，循环外取引用） |
| `src/udp.rs:89` | tracing::debug! | `log.debug(format!)`（log = fn 顶 `&*X_LOG` 引用） | 是（逐包/帧循环内·错误/丢弃分支，循环外取引用） |
| `src/udp.rs:101` | tracing::debug! | `log.debug(format!)`（log = fn 顶 `&*X_LOG` 引用） | 是（逐包/帧循环内·错误/丢弃分支，循环外取引用） |
| `src/udp.rs:108` | tracing::debug! | `log.debug(format!)`（log = fn 顶 `&*X_LOG` 引用） | 是（逐包/帧循环内·错误/丢弃分支，循环外取引用） |

### xray-proxy-anytls（28 处；门面 CLIENT_LOG client.rs:42 / INBOUND_LOG inbound.rs:37 /
OUTBOUND_LOG outbound.rs:32 / SERVER_LOG server.rs:49）

| 文件:行 | 原宏 | 新取法 | 热路径? |
|---|---|---|---|
| `src/client.rs:327` | tracing::debug! | `log.debug(format!)`（log = fn 顶 `&*X_LOG` 引用） | 是（逐包/帧循环内·错误/丢弃分支，循环外取引用） |
| `src/client.rs:332` | tracing::debug! | `log.debug(format!)`（log = fn 顶 `&*X_LOG` 引用） | 是（逐包/帧循环内·错误/丢弃分支，循环外取引用） |
| `src/client.rs:346` | tracing::debug! | `log.debug(format!)`（log = fn 顶 `&*X_LOG` 引用） | 是（逐包/帧循环内·错误/丢弃分支，循环外取引用） |
| `src/client.rs:351` | tracing::debug! | `log.debug(format!)`（log = fn 顶 `&*X_LOG` 引用） | 是（逐包/帧循环内·错误/丢弃分支，循环外取引用） |
| `src/inbound.rs:139` | tracing::info! | `INBOUND_LOG.info(format!)` | 否（连接级/装配·错误分支） |
| `src/inbound.rs:155` | tracing::info! | `INBOUND_LOG.info(format!)` | 否（连接级/装配·错误分支） |
| `src/outbound.rs:88` | tracing::debug! | `OUTBOUND_LOG.debug(format!)` | 否（连接级/装配·错误分支） |
| `src/server.rs:193` | tracing::debug! | `SERVER_LOG.debug(format!)` | 否（连接级/装配·错误分支） |
| `src/server.rs:200` | tracing::debug! | `SERVER_LOG.debug(format!)` | 否（连接级/装配·错误分支） |
| `src/server.rs:205` | tracing::debug! | `SERVER_LOG.debug(format!)` | 否（连接级/装配·错误分支） |
| `src/server.rs:211` | tracing::debug! | `SERVER_LOG.debug(format!)` | 否（连接级/装配·错误分支） |
| `src/server.rs:229` | tracing::debug! | `SERVER_LOG.debug(format!)` | 否（连接级/装配·错误分支） |
| `src/server.rs:233` | tracing::debug! | `SERVER_LOG.debug(format!)` | 否（连接级/装配·错误分支） |
| `src/server.rs:252` | tracing::debug! | `SERVER_LOG.debug(format!)` | 否（连接级/装配·错误分支） |
| `src/server.rs:260` | tracing::debug! | `SERVER_LOG.debug(字面量直传)` | 否（连接级/装配·错误分支） |
| `src/server.rs:266` | tracing::debug! | `SERVER_LOG.debug(format!)` | 否（连接级/装配·错误分支） |
| `src/server.rs:280` | tracing::debug! | `SERVER_LOG.debug(format!)` | 否（连接级/装配·错误分支） |
| `src/server.rs:308` | tracing::debug! | `SERVER_LOG.debug(format!)` | 否（连接级/装配·错误分支） |
| `src/server.rs:321` | tracing::debug! | `SERVER_LOG.debug(format!)` | 否（连接级/装配·错误分支） |
| `src/server.rs:348` | tracing::debug! | `SERVER_LOG.debug(format!)` | 否（连接级/装配·错误分支） |
| `src/server.rs:353` | tracing::debug! | `SERVER_LOG.debug(字面量直传)` | 否（连接级/装配·错误分支） |
| `src/server.rs:359` | tracing::debug! | `SERVER_LOG.debug(字面量直传)` | 否（连接级/装配·错误分支） |
| `src/server.rs:366` | tracing::debug! | `SERVER_LOG.debug(format!)` | 否（连接级/装配·错误分支） |
| `src/server.rs:401` | tracing::debug! | `SERVER_LOG.debug(format!)` | 否（连接级/装配·错误分支） |
| `src/server.rs:408` | tracing::debug! | `SERVER_LOG.debug(format!)` | 否（连接级/装配·错误分支） |
| `src/server.rs:414` | tracing::debug! | `SERVER_LOG.debug(format!)` | 否（连接级/装配·错误分支） |
| `src/server.rs:462` | tracing::debug! | `log.debug(format!)`（log = fn 顶 `&*X_LOG` 引用） | 是（逐包/帧循环内·错误/丢弃分支，循环外取引用） |
| `src/server.rs:480` | tracing::debug! | `log.debug(format!)`（log = fn 顶 `&*X_LOG` 引用） | 是（逐包/帧循环内·错误/丢弃分支，循环外取引用） |

### xray-proxy-trojan（20 处；门面 CLIENT_LOG client.rs:32 / PLUGIN_LOG plugin.rs:42 /
SERVER_LOG server.rs:49）

| 文件:行 | 原宏 | 新取法 | 热路径? |
|---|---|---|---|
| `src/client.rs:91` | tracing::debug! | `CLIENT_LOG.debug(format!)` | 否（连接级/装配·错误分支） |
| `src/plugin.rs:193` | tracing::warn! | `PLUGIN_LOG.warn(字面量直传)` | 否（连接级/装配·错误分支） |
| `src/plugin.rs:201` | tracing::warn! | `PLUGIN_LOG.warn(format!)` | 否（连接级/装配·错误分支） |
| `src/server.rs:157` | tracing::info! | `SERVER_LOG.info(format!)` | 否（连接级/装配·错误分支） |
| `src/server.rs:190` | tracing::debug! | `SERVER_LOG.debug(format!)` | 否（连接级/装配·错误分支） |
| `src/server.rs:198` | tracing::warn! | `SERVER_LOG.warn(format!)` | 否（连接级/装配·错误分支） |
| `src/server.rs:214` | tracing::warn! | `SERVER_LOG.warn(format!)` | 否（连接级/装配·错误分支） |
| `src/server.rs:226` | tracing::warn! | `SERVER_LOG.warn(format!)` | 否（连接级/装配·错误分支） |
| `src/server.rs:241` | tracing::info! | `SERVER_LOG.info(format!)` | 否（连接级/装配·错误分支） |
| `src/server.rs:482` | tracing::warn! | `SERVER_LOG.warn(format!)` | 否（连接级/装配·错误分支） |
| `src/server.rs:486` | tracing::info! | `SERVER_LOG.info(format!)` | 否（连接级/装配·错误分支） |
| `src/server.rs:500` | tracing::warn! | `SERVER_LOG.warn(format!)` | 否（连接级/装配·错误分支） |
| `src/server.rs:545` | tracing::warn! | `SERVER_LOG.warn(format!)` | 否（连接级/装配·错误分支） |
| `src/server.rs:622` | tracing::debug! | `SERVER_LOG.debug(format!)` | 否（连接级/装配·错误分支） |
| `src/server.rs:630` | tracing::debug! | `SERVER_LOG.debug(format!)` | 否（连接级/装配·错误分支） |
| `src/server.rs:642` | tracing::warn! | `SERVER_LOG.warn(format!)` | 否（连接级/装配·错误分支） |
| `src/server.rs:647` | tracing::info! | `SERVER_LOG.info(format!)` | 否（连接级/装配·错误分支） |
| `src/server.rs:655` | tracing::warn! | `SERVER_LOG.warn(format!)` | 否（连接级/装配·错误分支） |
| `src/server.rs:700` | tracing::warn! | `log.warn(format!)`（log = fn 顶 `&*X_LOG` 引用） | 是（逐包/帧循环内·错误/丢弃分支，循环外取引用） |
| `src/server.rs:707` | tracing::warn! | `log.warn(format!)`（log = fn 顶 `&*X_LOG` 引用） | 是（逐包/帧循环内·错误/丢弃分支，循环外取引用） |

### xray-proxy-hysteria（19 处；门面 DISPATCH_LOG dispatcher.rs:40 / INBOUND_LOG inbound.rs:48 /
OUTBOUND_LOG outbound.rs:42）

| 文件:行 | 原宏 | 新取法 | 热路径? |
|---|---|---|---|
| `src/dispatcher.rs:137` | tracing::debug! | `log.debug(format!)`（log = fn 顶 `&*X_LOG` 引用） | 是（逐包/帧循环内·错误/丢弃分支，循环外取引用） |
| `src/dispatcher.rs:142` | tracing::debug! | `log.debug(format!)`（log = fn 顶 `&*X_LOG` 引用） | 是（逐包/帧循环内·错误/丢弃分支，循环外取引用） |
| `src/dispatcher.rs:158` | tracing::debug! | `log.debug(format!)`（log = fn 顶 `&*X_LOG` 引用） | 是（逐包/帧循环内·错误/丢弃分支，循环外取引用） |
| `src/dispatcher.rs:163` | tracing::debug! | `log.debug(format!)`（log = fn 顶 `&*X_LOG` 引用） | 是（逐包/帧循环内·错误/丢弃分支，循环外取引用） |
| `src/dispatcher.rs:203` | tracing::debug! | `log.debug(format!)`（log = fn 顶 `&*X_LOG` 引用） | 是（逐包/帧循环内·错误/丢弃分支，循环外取引用） |
| `src/dispatcher.rs:212` | tracing::debug! | `log.debug(format!)`（log = fn 顶 `&*X_LOG` 引用） | 是（逐包/帧循环内·错误/丢弃分支，循环外取引用） |
| `src/dispatcher.rs:232` | tracing::debug! | `log.debug(format!)`（log = fn 顶 `&*X_LOG` 引用） | 是（逐包/帧循环内·错误/丢弃分支，循环外取引用） |
| `src/dispatcher.rs:312` | tracing::debug! | `DISPATCH_LOG.debug(format!)` | 否（连接级/装配·错误分支） |
| `src/dispatcher.rs:444` | tracing::warn! | `DISPATCH_LOG.warn(format!)` | 否（连接级/装配·错误分支） |
| `src/dispatcher.rs:459` | tracing::warn! | `DISPATCH_LOG.warn(format!)` | 否（连接级/装配·错误分支） |
| `src/inbound.rs:293` | tracing::debug! | `INBOUND_LOG.debug(format!)` | 否（连接级/装配·错误分支） |
| `src/inbound.rs:303` | tracing::warn! | `INBOUND_LOG.warn(format!)` | 否（连接级/装配·错误分支） |
| `src/inbound.rs:323` | tracing::warn! | `INBOUND_LOG.warn(format!)` | 否（连接级/装配·错误分支） |
| `src/inbound.rs:363` | tracing::info! | `INBOUND_LOG.info(format!)` | 否（连接级/装配·错误分支） |
| `src/inbound.rs:379` | tracing::info! | `INBOUND_LOG.info(format!)` | 否（连接级/装配·错误分支） |
| `src/inbound.rs:416` | tracing::info! | `INBOUND_LOG.info(format!)` | 否（连接级/装配·错误分支） |
| `src/inbound.rs:520` | tracing::debug! | `log.debug(format!)`（log = fn 顶 `&*X_LOG` 引用） | 是（逐包/帧循环内·错误/丢弃分支，循环外取引用） |
| `src/outbound.rs:117` | tracing::debug! | `OUTBOUND_LOG.debug(format!)` | 否（连接级/装配·错误分支） |
| `src/outbound.rs:127` | tracing::debug! | `OUTBOUND_LOG.debug(format!)` | 否（连接级/装配·错误分支） |

## 3. 逐站分类账（生产 / 测试 / 红线）

| 分类 | 站点数 | 说明 |
|---|---|---|
| **生产（迁）** | **109** | 全部在非 `cfg(test)` 编译区。含 tuic `server.rs`（TuicMockServer）与 anytls `server.rs`（AnytlsMockServer）——两者模块头自述「不是生产 server」，但均为 `pub mod` 生产编译区 + 对外导出（xray-core tests / xray-stress 消费），clippy 禁令按 crate 生效，故随批迁移并在门面注释标注 mock 面 |
| **测试面（豁免）** | **0** | 开工逐文件定位 `#[cfg(test)]` mod 边界 + `tests/` 目录逐行扫描：4 crate 的 test 区**零** tracing 级宏站点（批 1 的 capture 自发射形态本批不存在） |
| **红线（保留 + event! 登记）** | **0** | vision splice 为 vless 专属（批 1 已登记）；本批 4 crate 无 splice/DIRECT 面。数据面热路径处置：35 处站点位于逐包/帧循环内，**全部为错误/丢弃分支**（稳态逐包路径零日志站点），循环外取引用后稳态零开销——处置同批 1 ss pump 先例（坑约束⑫） |

## 4. 数据面热路径处置（坑约束⑫）

10 个函数含循环内站点，按批 1 ss pump 形态在 **fn 体首部取一次引用**：
tuic `dispatcher::pump_streams`、`udp::UniRespRouter::spawn`（泵闭包内首行）、
`server::handle_datagram`、`udp_assoc_direct`、`udp_assoc_dispatch`；
anytls `client::pump_stream`、`server::pump_session_to_duplex`；
trojan `server::handle_trojan_udp_relay`；
hysteria `dispatcher::pump_hysteria_stream`、`pump_hysteria_udp`、`inbound::handle_udp_session`。

语义保真说明：`tracing::debug!` 原为 lazy（level 关闭时零成本）；迁后 `format!` 在**调用点
即时求值**——但所有循环内站点都在 `Err`/丢弃分支（break/return/continue-丢弃），非稳态
逐包路径，故 format+mask 只在错误发生时付一次（批 1 ss 同款论证，报告 §4）。

## 5. clippy.toml（4 crate 补 tracing 五宏禁令，照 socks/http 模板）

`crates/xray-proxy-{tuic,anytls,trojan,hysteria}/clippy.toml` 的 `disallowed-macros` 各补
`tracing::{info,warn,error,debug,trace}` 5 条（reason 与 socks 逐字同款）。`tracing::event!`
未入禁令（保留为红线/测试登记通道——本批未用到）。原有 spawn 族/时钟族/println 条目零改动。

## 6. 验收证据（实跑）

工具链：仓内 `rust-toolchain.toml` 钉 nightly；`cargo fmt --check` 判定用 plain
`cargo fmt -p <crate> -- --check`。

1. **check（workspace 全量）**：
   ```
   $ cargo check --workspace --all-targets
       Checking xray-cli v0.1.0 (…\crates\xray-cli)
       Checking xray-stress v0.1.0 (…\crates\xray-stress)
       Checking xray-integration-tests v0.1.0 (…\tests)
       Finished `dev` profile [unoptimized + debuginfo] target(s) in 2m 53s
   CHECK_EXIT=0
   ```
2. **clippy（workspace 全量，-D warnings，含 4 crate 新禁令）**：
   ```
   $ cargo clippy --workspace --all-targets -- -D warnings
       Checking xray-core v0.1.0 (…\crates\xray-core)
       Checking xray-cli v0.1.0 (…\crates\xray-cli)
       Checking xray-stress v0.1.0 (…\crates\xray-stress)
       Checking xray-integration-tests v0.1.0 (…\tests)
       Finished `dev` profile [unoptimized + debuginfo] target(s) in 4m 40s
   CLIPPY_EXIT=0
   ```
   另跑我面收窄口径（等价更严：只 lint 本批 4 crate）：`cargo clippy -p xray-proxy-tuic -p
   xray-proxy-anytls -p xray-proxy-trojan -p xray-proxy-hysteria --all-targets -- -D warnings`
   → `MY_CLIPPY_EXIT=0`（8.20s）。
3. **测试（4 crate --all-targets）**：20 个测试二进制全绿：
   ```
   33+1+2+1+2+10+63+12+88+12+3+68+1+1+1+5+9+2 passed → 314 passed; 0 failed; 4 ignored
   TEST_EXIT=0
   ```
   （4 ignored = tuic vps_interop 既有环境门控 + hysteria 1 项既有 ignore，与本批无关。）
   行为敏感点单独复跑：trojan capture 测试（迁移后消息形态变化唯一的断言依赖面）：
   ```
   $ cargo test -p xray-proxy-trojan --lib duplicate_user_warn_carries_no_password
   test plugin::tests::duplicate_user_warn_carries_no_password ... ok
   test result: ok. 1 passed; 0 failed; … 87 filtered out
   CAPTURE_EXIT=0
   ```
4. **fmt（4 crate，迁后两轮复验）**：
   ```
   xray-proxy-tuic FMT_CLEAN / xray-proxy-anytls FMT_CLEAN /
   xray-proxy-trojan FMT_CLEAN / xray-proxy-hysteria FMT_CLEAN
   ```
5. **grep 实数（迁后）**：
   - 禁令宏 `tracing::(trace|debug|info|warn|error)!` + 裸导入宏 `{debug,info,warn}!(`
     → 4 crate 全域（含 tests/）**0** 残留
   - `use tracing::` 裸导入 → 4 crate src **0**（anytls inbound/server、trojan client/server、
     hysteria inbound 的 5 处导入全删）
   - 门面 `static *_LOG: LazyLock<LogFacade>` → **15** 个（清单见 §2）
   - `tracing` dep 在 tuic/anytls/hysteria 变 unused（trojan tests 仍用 `tracing::Subscriber`）——
     **Cargo.toml/Cargo.lock 零改动**（红线；批 1 同款保留先例，`unused_crate_dependencies`
     未启用、CI 无 udeps/machete 门，不报红）

diff 面：19 文件 +345/−185（4 clippy.toml + 15 src），全在票面 4 crate 内。

### 验收环境说明（如实）

workspace 三关实跑于**私有 `CARGO_TARGET_DIR`（target-2a-verify，验收后已删）**：共享
target 目录的 build 锁被并行协作代理的长构建持续持有（实测 >240s 排队不释放），按共享树
纪律切私有目录；工具链（rust-toolchain.toml）、workspace Cargo.toml、boringssl
预构建路径与共享目录完全一致，结果等价。期间工作树两次被邻居在飞编辑打红（xray-frame
15 error / splithttp E0658，均非本批面），已按 10-15 分钟法则通知各 owner 修绿后复跑，
最终三关全绿。

## 7. 交叉复核（TracingBatch2a2 只读复核 + 本文终判）

重复派单的复核代理（TracingBatch2a2）对两处残余风险做了独立静态判定，本文以实跑终判：
1. **trojan capture 测试**（`duplicate_user_warn_carries_no_password`）：其静态分析
   （`Dispatch::event` 先 `event_enabled` 默认 true → 事件必达；LogFacade 折叠后 message
   含 `skip duplicate user` 子串 → 断言成立）与本文一致；**test 实跑 ok**（§6.3）终判。
2. **`tracing` dep unused**：其全仓核查（`unused_crate_dependencies` 0 命中、CI 无
   udeps/machete 门、批 1 同款保留）与本文一致 → Cargo.toml 不动，双方结论闭合。

## 8. code-simplifier 自检

自检改动 3 处 / 触碰禁区 0 / diff +345 / −185：①anytls server.rs 首包超时站点误用
`format!`（纯续行字面量）→ 改字面量直传（clippy `useless_format` 实测抓到后修）；
②tuic server.rs 门面 doc 注释行首 `+` 触发 `doc_lazy_continuation` → 措辞改写；
③anytls server.rs 导入块被我误并入未用的 `AsyncWrite` trait → 删（`deny(warnings)`
unused_imports 实测抓到后修）。无 lint suppress、无新抽象、测试断言零改动、公共 API 零变更
（15 个门面均为文件私有 `static`）。

## 9. 剩余（非本批）

proxy 层剩余 8 crate 归批 2b 面：vmess / socks / http / dokodemo / blackhole / freedom /
tun / wireguard（批 1 已清 loopback/dns/ss/vless，本批已清 tuic/anytls/trojan/hysteria）；
transport / app / cli 面另行排队（批 1 报告口径：12 crate / 217 站点总量）。

## 10. 自我评估

- 准确性 5/5 — 站点数开工 grep 实测 109（票面估 102，tuic 35→实测 42 系票面口径未计裸导入宏），
  迁后 grep 0 残留 + 109 行迁移表逐行与最终文件行号对账；三关证据均为实跑完整尾部。
- 完整性 4/5 — 票面 4 项验收全数完成 + 行为敏感点（capture 测试）单独复跑；扣 1 分：
  workspace 三关在共享树被邻居在飞编辑两次打断，最终绿依赖邻居收敛（已如实记录时间线），
  非本批可控。
- 清晰度 5/5 — 表格逐行 + 分类账 + 热路径处置单独成节；门面/取法约定（`log` = fn 顶引用、
  字面量直传）在 §2 开头显式定义。
- 可执行性 5/5 — §6 命令与完整尾部可直接复跑；grep 残留复查命令口径（含裸导入宏）在 §6.5
  给全。
- 简洁性 4/5 — 109 行迁移表系票面验收项要求全文保留；其余段落压缩。

## 11. 沉淀

无新增经验：本次踩坑（doc 注释行首 `+` → `doc_lazy_continuation`；共享树并行验证用私有
CARGO_TARGET_DIR）均已存在于 `~/.omp/agent/rules/rust-pitfalls.md`（L57/L222）与项目记忆
（多代理共享树纪律），本轮为既有条目的再次实证，不重复记录。
