VERDICT: PASS — 15 个 crate 的三变体时钟禁令已全部齐全（含 D8 补齐的 tokio::time::Instant::now 与缺失的 std::time::SystemTime::now），被点名的 16 个生产站点全部逐点登记、11 个测试站点经 crate 级测试豁免收口，`cargo clippy --all-targets -- -D warnings` 全绿、`cargo fmt -- --check` exit 0、`cargo test -p xray-transport --lib` 671 passed / 0 failed。

# 战役 99ifi D8：时钟静态门在 15 crate 上生效

日期 2026-10-29 · 分支 `feature/fix-inbound-parity` · 独立 target `target-clockgate`（收尾已删）· 未 commit / 未 push。

## 1. 改了什么

### 1.1 clippy.toml（15 个 crate，仅补缺失项，不重复、不删既有）

补齐文本（`tokio` 面）：

```
{ path = "tokio::time::Instant::now", reason = "时钟唯一源 = skeleton::clock::{Clock}：ctx 可达走 ctx.clock()，不可达走 xray_frame::compat::clock()；tokio 虚拟钟预算面与 std 面禁混换，确需保留时逐点 #[allow(clippy::disallowed_methods)] + 理由注释登记（D8 补齐）" }
```

补齐文本（`SystemTime` 面）：同上前缀 + `裸挂钟不可注入，取时走 clock.now_system()`。

| crate | 补 tokio Instant | 补 SystemTime | 备注 |
|---|---|---|---|
| xray-cli | ✅ | ✅ | 原仅 std 面 |
| xray-common | ✅ | — | 原 std + SystemTime |
| xray-conf | ✅ | ✅ | 原仅 std 面 |
| xray-core | ✅ | — | 原 std + SystemTime |
| xray-mux | ✅ | ✅ | 原仅 std 面 |
| xray-reality | ✅ | ✅ | 原仅 std 面 |
| xray-stress | ✅ | ✅ | 原仅 std 面 |
| xray-tls | ✅ | — | 原 std + SystemTime |
| xray-transport | ✅ | ✅ | 原仅 std 面 |
| xray-transport-grpc | ✅ | ✅ | 原仅 std 面 |
| xray-transport-httpupgrade | ✅ | ✅ | 原仅 std 面 |
| xray-transport-hysteria | ✅ | ✅ | 原仅 std 面 |
| xray-transport-naive | ✅ | ✅ | 原仅 std 面 |
| xray-transport-quic | ✅ | ✅ | 原仅 std 面 |
| xray-transport-websocket | ✅ | ✅ | 原仅 std 面 |

小计：**+15 tokio 条 · +11 SystemTime 条**（均随 `disallowed-methods` 数组内追加，未新建 key）。

### 1.2 生产站点登记（item 级 `#[allow(clippy::disallowed_methods, reason = "…")]`，共 16 处 / 13 个 allow 块）

| # | 站点（file:line） | 挂点 | 条数 | 面 |
|---|---|---|---|---|
| 1 | `crates/xray-common/src/signal/mod.rs:144` | `ActivityTimer::run`（allow :139） | 1 | tokio |
| 2 | `crates/xray-transport/src/happy_eyeballs.rs:126,165` | `race_dial`（allow :76） | 2 | tokio |
| 3 | `crates/xray-transport/src/system_dialer.rs:206` | `dial_first_reachable`（allow :200） | 1 | tokio |
| 4 | `crates/xray-transport/src/system_dialer.rs:255,265` | `dial_serial`（allow :248） | 2 | tokio |
| 5 | `crates/xray-reality/src/client.rs:245` | `rewrite_client_hello`（allow :207） | 1 | SystemTime |
| 6 | `crates/xray-reality/src/client.rs:298` | `rewrite_client_hello_msg`（allow :276） | 1 | SystemTime |
| 7 | `crates/xray-reality/src/server.rs:530` | `verify_and_probe`（allow :507） | 1 | SystemTime |
| 8 | `crates/xray-reality/src/probe.rs:382` | `detect_one_record_lens_inner`（allow :363） | 1 | tokio |
| 9 | `crates/xray-stress/src/main.rs:75` | `main`（allow :63） | 1 | SystemTime |
| 10 | `crates/xray-stress/src/report.rs:238` | `unix_now`（allow :237） | 1 | SystemTime |
| 11 | `crates/xray-stress/src/sampler.rs:93` | `sample_once`（allow :87） | 1 | SystemTime |
| 12 | `crates/xray-transport-grpc/src/transport.rs:273` | `grpc_backoff_delay`（allow :264） | 1 | SystemTime |
| 13 | `crates/xray-mux/src/client.rs:682` | `monitor`（allow :670） | 1 | tokio |
| 14 | `crates/xray-mux/src/worker.rs:224` | `spawn_monitor` 内唯一 `tokio::spawn` 语句（复用既有 allow :212，仅扩 reason） | 1 | tokio |

生产面合计：**tokio 8 处 · SystemTime 8 处 = 16 处**。

reason 统一包含三要素：为什么此处拿不到 `ctx.clock()`（BoringSSL 回调内 / 独立 bin / tokio 虚拟钟面不接受 std Instant / 探测窗口不应被 mock 冻结）+ 已就位出口（`xray_frame::compat::clock` 不覆盖该面则明说）+ 待迁条件。

### 1.3 测试站点处理（crate 级测试豁免，10 个 `lib.rs`）

`#![cfg_attr(test, allow(clippy::disallowed_macros, …))]` → 加入 `clippy::disallowed_methods`：

`xray-cli` · `xray-common` · `xray-core` · `xray-mux` · `xray-reality` · `xray-transport` · `xray-transport-grpc` · `xray-transport-httpupgrade` · `xray-transport-hysteria` · `xray-transport-websocket`

`xray-transport` 的 11 处测试站点是 clippy 实报的（豁免补上之前）：

```
crates\xray-transport\src\retry.rs:135:25
crates\xray-transport\src\system_dialer.rs:1062:23 / 1065:13 / 1092:23 / 1094:48 / 1136:19
crates\xray-transport\src\finalmask\realm\portmap\natpmp.rs:324:24 / 325:15
crates\xray-transport\src\finalmask\xmc\conn.rs:833:23
crates\xray-transport\src\tcp\hub.rs:683:24 / 689:17
```

其余 9 个 crate 的测试站点在豁免落地后未被 clippy 逐个点名（不重复枚举，见 §4 风险）。

## 2. 验证（真实命令 + 真实输出）

`CARGO_TARGET_DIR=D:/Project/Xray-core-rust/target-clockgate` + 四项 env（BORING_BSSL_ASSUME_PATCHED / BORING_BSSL_SOURCE_PATH / PROTOC / LIBCLANG_PATH）。

### 2.1 clippy 15 crate 全量（0 error）

```
$ cargo clippy -p xray-cli -p xray-common -p xray-conf -p xray-core -p xray-mux -p xray-reality \
    -p xray-stress -p xray-tls -p xray-transport -p xray-transport-grpc -p xray-transport-httpupgrade \
    -p xray-transport-hysteria -p xray-transport-naive -p xray-transport-quic -p xray-transport-websocket \
    --all-targets -- -D warnings
    Checking xray-conf v0.1.0 …
    Checking xray-tls v0.1.0 …
    Checking xray-mux v0.1.0 …
    Checking xray-transport-quic v0.1.0 …
    Checking xray-reality v0.1.0 …
    Checking xray-transport-websocket v0.1.0 …
    Checking xray-transport-naive v0.1.0 …
    Checking xray-transport-grpc v0.1.0 …
    Checking xray-transport-httpupgrade v0.1.0 …
    Checking xray-transport-hysteria v0.1.0 …
    Checking xray-core v0.1.0 …
    Checking xray-cli v0.1.0 …
    Checking xray-stress v0.1.0 …
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 25.08s
error 计数 = 0
```

同一次运行还连带复查了这些 crate 的依赖面（`xray-app-*` / `xray-proxy-*` / `xray-transport-tcp` / `xray-transport-kcp` / `xray-transport-splithttp` 等，全部 `Checking` 通过、零 warning），即新禁令未对已登记兄弟 crate 产生回归。

**门确实生效的反证（D8 前后对照，非 0-site 静态推断）**：禁令落地后真实报错并被逐点收口 ——

| 轮次 | 报错 |
|---|---|
| R1 | `crates\xray-common\src\signal\mod.rs:144:28: error: use of a disallowed method tokio::time::Instant::now` → `could not compile xray-common (lib) / (lib test)` |
| R2 | xray-transport lib 5 处 + lib test 11 处同类 error（共 16） |
| R3 | `crates\xray-reality\src\probe.rs:382:18: error … tokio::time::Instant::now` |
| R4 | `Finished` |

### 2.2 fmt（exit 0）

```
$ cargo fmt -p <15 crate> -- --check
FMT_CHECK_EXIT=0
```

（首跑 FMT_EXIT=1：rustfmt 要求 4 项 allow 列表换多行；已按 rustfmt 输出 auto-format 后复检通过。）

### 2.3 测试（被改动最多的 crate）

```
$ cargo test -p xray-transport --lib
test result: ok. 671 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out; finished in 12.08s
```

（含被点名的 `system_dialer` / `happy_eyeballs` 相关用例：`dial_first_reachable_falls_back_to_second_address` ok、`blackholed_addr_does_not_eat_whole_budget` ok、`tcp_race_dial_connects_v4_when_v6_refused` ok、`close_rejects_new_connections` ok。）

### 2.4 改动面（`git diff --stat`，37 文件 / +182 −14，零越界）

15 × `clippy.toml` + 22 × 源码文件（1.2 的 13 个 allow 块 + 1 个 reason 扩容 + 10 个 lib.rs 测试豁免行 + 2 处注释改写）。无业务逻辑、无 Cargo 依赖、无 CI/红线文件。

## 3. 风险 / 非目标确认

- **非目标**：未改任何业务逻辑（只 attribute + 配置）；未迁移到 Clock（迁移属另一波次）；未动 7 个已裁决 crate（`xray-frame`/`xray-buf`/`xray-crypto`/`xray-features`/`xray-geodata`/`xray-proto`/`udf-frame`）；未动 CI / 工作流 / 红线文件；**未**去掉 `-D warnings`。
- **生产面仍被硬门把住**：`--all-targets` 会分别编译 `(lib)` 与 `(lib test)`，crate 级 `cfg_attr(test, allow(...))` 只影响后者的 lint 结果；每次 R1–R3 的 `(lib)` 报错即证据。
- **风险①（行为面宽松）**：10 个 crate 的测试目标现在整体豁免 `disallowed_methods`，其中也包含 `tokio::spawn`——测试侧原本逐点登记的 spawn 豁免从此可有可无（不再被点）。此形态与仓内既有约定一致（`xray-xudp`、`xray-transport` 早已对 `disallowed_macros` 这么挂），但不是"逐点最严"。若战役要求测试面也逐点，需回退为 mod 级 allow。
- **风险②（tokio 面无法用现有 Clock 收口）**：`sleep_until`/`interval_at`/`timeout_at` 只收 `tokio::time::Instant`，`skeleton::clock::Clock` 只出 `std::time::Instant`，`xray_frame::compat::clock()` 同。因此本批 8 处 tokio 站点不是"偷懒不迁"，而是**缺 tokio 面取时桥**（deadline::Budget 的 timer-arm 面）。8 处 reason 已统一写明 `待 Budget 补 timer-arm 面后迁`，可直接 grep 出待办。
- **风险③**：`xray-stress` 是独立 bin，既无 `ctx` 也无 `compat::clock` 接线，3 处登记按"待压测工具接 Clock 端口后迁"挂账。
- **vendor 噪声（非本次引入）**：`vendor/rustls` 2 条 warning（`needs_key_share` 未用 / `unreachable_pub`）在 clippy 输出里出现但不算 error（path 依赖不被 `-D warnings` 升级）。红线目录，未动。

## 4. 未决点 / 交回 PM

1. **测试面豁免粒度**：现为 crate 级（10 crate）。若要做成"生产 0 处 + 测试逐点"的最严形态，需把 crate 级豁免下沉到各 `mod tests` 的 inner allow，工作量 = 各 crate 测试站点数（未知，需先临时移除豁免跑一遍 clippy 才知）。建议留给下一次静态门收紧波次。
2. **tokio 面取时桥**：`deadline::Budget` 补 timer-arm 面（或 `Clock` 增 `now_tokio()`）后，8 处 tokio 登记可一次性回收。这是 15 crate 之外的新增能力，不属本单。
3. **知识图谱**：本仓图谱 `indexed_at=2026-10-28T12:46:46Z`，本次改动为纯 attribute/注释（零新增符号、零签名变化），已发起一次 `index_repository` 刷新（若超时/失败，图谱对本次改动无符号级影响，可下轮随代码改动一并刷新）。
4. **未跑**：除 `xray-transport` 外的 14 crate 未跑 `cargo test`（按任务书"其余 crate 只跑 clippy"）；未跑 workspace 全量 clippy（任务书禁）。
