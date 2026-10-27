# tracing-migrate-batch1：4 crate 裸 tracing 宏 → LogFacade 迁移报告

> 票面：nn8os 重核账 tracing 面清偿 batch1（`xray-proxy-{loopback,dns,ss,vless}`）
> 日期：2026-10-27 ｜ 执行：TracingBatch1 ｜ 共享树：开工时干净（仅 untracked reports），全程零 git 写操作

## 1. 结论

33 处生产裸 tracing 宏（票面估 ~30，实数 33）全部迁 `LogFacade`（32 迁移 + 1 红线保留登记）；
另 2 处测试面自发射事件保留 raw tracing（等价 `event!` 形态，登记）。4 个 crate 的
`clippy.toml` 均补齐 socks/http 同款 tracing 五宏禁令。**迁移后禁令宏 grep 实数 = 0**。

## 2. 迁移表（crate | 文件:行(迁后) | 原宏 | 新取法 | 热路径）

门面形态：9 个模块级 `static X: LazyLock<LogFacade>`（域各归 domain：loopback/dns/ss/vless，
secrets 均 `vec![]`，同 socks/http 先例）；站点全为 message 形态 `format!`，结构化字段折叠进
message 尾部 `key=val`（socks udp.rs / http server.rs 同款）。

### xray-proxy-loopback（2 处，static `LOOPBACK_LOG` lib.rs:51）

| 文件:行 | 原宏 | 新取法 | 热路径 |
|---|---|---|---|
| lib.rs:251 | tracing::warn! | LOOPBACK_LOG.warn(format!) | 否（dispatch 错误分支） |
| lib.rs:259 | tracing::error! | LOOPBACK_LOG.error(format!) | 否（装配缺失丢弃分支） |

### xray-proxy-dns（5 处，static `CONFIG_LOG` config.rs:28 / `HANDLER_LOG` handler.rs:34 / `PLUGIN_LOG` plugin.rs:40）

| 文件:行 | 原宏 | 新取法 | 热路径 |
|---|---|---|---|
| config.rs:217 | tracing::warn!(target: xray_proxy_dns::config) | CONFIG_LOG.warn(format!) | 否（geosite 解析冷路径） |
| config.rs:227 | tracing::warn!(target: 同上) | CONFIG_LOG.warn(format!) | 否 |
| handler.rs:107 | tracing::error!(target: xray_proxy_dns::handler) | HANDLER_LOG.error(format!) | 否（规则编译失败 fail-closed） |
| plugin.rs:230 | tracing::warn!(target: xray_proxy_dns::plugin) | PLUGIN_LOG.warn(静态串) | 否（弃用特性告警） |
| plugin.rs:339 | tracing::warn!(target: 同上) | PLUGIN_LOG.warn(format!) | 否（未知键告警） |

### xray-proxy-ss（10 处，static `SS_LOG` dispatcher.rs:49，pump 函数循环外 `let log = &*SS_LOG;` 取一次引用）

| 文件:行 | 原宏 | 新取法 | 热路径 |
|---|---|---|---|
| dispatcher.rs:204 | tracing::debug! | log.debug(format!)（pump_ss_stream:177 提升） | pump 循环内·错误分支（坑约束⑫处置见 §4） |
| dispatcher.rs:229 | tracing::debug! | 同上 | 同上 |
| dispatcher.rs:263 | tracing::debug! | 同上 | 同上 |
| dispatcher.rs:639 | tracing::debug! | log.debug(format!)（pump_ss_udp:619 提升） | UDP pump 循环内·错误分支 |
| dispatcher.rs:648 | tracing::debug! | 同上 | 同上 |
| dispatcher.rs:666 | tracing::debug! | 同上 | 同上 |
| dispatcher.rs:727 | tracing::debug! | log.debug(format!)（pump_ss2022_udp:715 提升） | 会话初始化失败分支 |
| dispatcher.rs:758 | tracing::debug! | 同上 | UDP pump 循环内·错误分支 |
| dispatcher.rs:767 | tracing::debug! | 同上 | 同上 |
| dispatcher.rs:785 | tracing::debug! | 同上 | 同上 |

### xray-proxy-vless（15 迁移 + 1 保留，static `PRECONN_LOG` dispatcher.rs:48 / `PLUGIN_LOG` plugin.rs:64 / `ENC_LOG` encryption/mod.rs:43 / `INBOUND_LOG` inbound/server.rs:50）

| 文件:行 | 原宏 | 新取法 | 热路径 |
|---|---|---|---|
| dispatcher.rs:274 | tracing::debug! | PRECONN_LOG.debug(format!) | 否（预拨号 200ms 重试错误分支） |
| plugin.rs:451 | tracing::warn! | PLUGIN_LOG.warn(format!) | 否（validator 构建冷路径） |
| plugin.rs:500 | tracing::info! | PLUGIN_LOG.info(format!) | 否（decryption 装配一次性） |
| encryption/mod.rs:468 | tracing::debug! | ENC_LOG.debug(format!) | 否（0-RTT 快路径·每连接一次） |
| encryption/mod.rs:647 | tracing::debug! | ENC_LOG.debug(format!) | 否（凭据缓存·每连接一次） |
| encryption/mod.rs:1136 | tracing::info! | ENC_LOG.info(format!) | 否（1-RTT 发票·每连接一次） |
| encryption/mod.rs:1284 | tracing::info! | ENC_LOG.info(format!) | 否（0-RTT 收票·每连接一次） |
| inbound/server.rs:118 | tracing::info! | INBOUND_LOG.info(format!) | 否（listen 一次性） |
| inbound/server.rs:132 | tracing::warn! | INBOUND_LOG.warn(format!) | accept 循环·错误分支 |
| inbound/server.rs:189 | tracing::warn! | INBOUND_LOG.warn(format!) | 否（TLS accept 失败即退出） |
| inbound/server.rs:213 | tracing::info! | INBOUND_LOG.info(format!) | 否（连接终局） |
| inbound/server.rs:317 | tracing::info! | INBOUND_LOG.info(format!) | 否（ENC 握手失败） |
| inbound/server.rs:436 | tracing::debug! | INBOUND_LOG.debug(format!) | 否（fallback 决策一次） |
| inbound/server.rs:772 | tracing::warn! | INBOUND_LOG.warn(format!) | 否（Rvs 拒绝） |
| inbound/server.rs:820 | tracing::debug! | INBOUND_LOG.debug(format!) | 否（Reverse 派发一次） |
| **encryption/vision_conn.rs:390** | tracing::warn! | **保留 raw tracing**（见 §3） | **vision 数据面·红线** |

## 3. 登记项（grep 非零残留，共 3 处）

| 位置 | 形态 | 理由 |
|---|---|---|
| vless encryption/vision_conn.rs:390 | `tracing::event!(tracing::Level::WARN, error = %e, "vision inner read error")` | 票面判定规则：vision splice 路径 tracing 保留（红线 d8562b56+a427613b 双 revert 史实），不硬攻。`warn!` → `event!` 为**等价展开**（warn! 即 `event!(Level::WARN, ..)` 薄壳），运行时零差异，仅为过 L3 宏禁令；站点在 poll_read 错误分支（非成功路径），DIRECT 切换逻辑零触碰。 |
| ss ss2022/key.rs:372 | `tracing::event!(tracing::Level::DEBUG, …)` | 测试面自发射事件（验证 capture subscriber 形态 + PSK 不入日志断言），非生产路径；`debug!` 同理换等价展开过禁令。断言原文零改动。 |
| vless error.rs:193 | `tracing::event!(tracing::Level::WARN, …)` | 同上（UUID 掩码断言测试）。 |

> 工具链事实：`disallowed_macros` 对 tracing 宏的 `#[allow]` 三形态（fn/stmt/文件顶）实测无效
> （nn8os 已证，本轮未再试豁免）——上表三处是「禁令生效 + 站点保留」的唯一自洽解。
> `tracing::event!` 未入禁令清单 = 红线/测试登记通道（与 socks 模板一致，未扩禁令）。

## 4. 热路径处置说明（坑约束⑫）

ss 三个 pump（stream/udp/ss2022-udp）是唯一循环内站点。取法：pump 函数体首部
`let log = &*SS_LOG;`（`&'static LogFacade` 一次解引用，async move 块按 Copy 捕获），
循环内仅 `log.debug(...)`——零每包克隆、零每包原子检查；format! 只在错误分支构造
（错误分支本身即终止路径，非逐包稳态）。loopback/dns/vless 站点全为连接级/装配级一次性
事件，直引静态门面。**vision gate / DIRECT 切换 / 数据面成功路径零改动。**

## 5. 验收证据（实跑）

1. **check + clippy（workspace 全量，-D warnings）**：
   ```
   cargo check --workspace --all-targets
     Finished `dev` profile [unoptimized + debuginfo] target(s) in 30.52s
   cargo clippy --workspace --all-targets -- -D warnings
     Checking xray-integration-tests v0.1.0 (…\tests)
     Finished `dev` profile [unoptimized + debuginfo] target(s) in 38.04s
   ```
   0 error（含新增禁令下 4 crate + 全 workspace）。
2. **测试（4 crate --all-targets）**：16 个测试二进制全绿：
   ```
   83+2+11+28+1+11+176+15+1+2+1+0+287+14+2+0 passed → 634 passed; 0 failed; 3 ignored
   ```
   （3 ignored = vps_interop 环境门控既有项；key.rs / error.rs 两处 capture 测试在绿。）
3. **clippy.toml**：4 文件各补 5 条（tracing::info/warn/error/debug/trace，socks 同款
   reason 文案），与既有 spawn 族/println 条目并列表内。
4. **grep 实数（迁后）**：
   - 禁令宏 `tracing::(trace|debug|info|warn|error)!\(` → **0**（4 crate 全域）
   - 登记项 `tracing::event!` → **3**（§3 三处，逐条有 reason 注释）
   - 门面 `LazyLock<LogFacade>` → **9** 静态
5. **fmt**：`cargo fmt -p <4 crate> -- --check` → 零 diff（FMT_CLEAN）。

diff 面：16 文件 +201/−88（4 clippy.toml + 12 src），全在票面 4 crate 内；无 Cargo.toml/
Cargo.lock 变更（xray-frame 四 crate 原已依赖）。

## 6. code-simplifier 自检

改动 0 处 / 触碰禁区 0 / diff +201 / −88。迁移即既有 socks/http 形态复制（无新风格、无新
抽象、无 pub API 变更、测试断言零改动）；一处编辑变形（encryption/mod.rs 1-RTT 站连行）
已当场修正并经 workspace 全量编译/测试/clippy 复验。

## 7. 沉淀

- 通用（建议入规则/记忆）：**tracing 级别宏是 `event!` 薄壳**——`warn!(f, "m")` ≡
  `event!(Level::WARN, f, "m")`。宏禁令（disallowed_macros 对 proc-macro allow 无效）下
  需保留 raw tracing 的登记站，换 `event!` 等价展开形态即可「禁令生效 + 站点保留 + 运行时
  零差异」，`event!` 本身留作登记通道不入禁令。
- 环境：bash 侧 bindgen 的 `LIBCLANG_PATH` 需正斜杠形态
  `LIBCLANG_PATH="D:/Program Files/llvm/bin"`（CLAUDE.md 的 cmd 反斜杠形态经 bash export
  传入时 bindgen 探针不识别）。

自我评估：准确性 5/5 — 每站有 文件:行 + 原宏对照，33=32+1 与 2+5+10+16 对账闭合；完整性
4/5 — 票面 5 项验收全数完成，唯一自主裁量是 vision 站 event! 等价形态（§3 显式登记，可一行
回滚但回滚即 clippy 红）；清晰度 5/5 — 表格 + 登记通道说明；可执行性 5/5 — §5 命令可复跑；
简洁性 4/5 — 迁移表占篇幅系票面验收项要求。
