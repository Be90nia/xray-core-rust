# W7 · 面 5 红线受控接口收口（vision 数据面错误事件）

**VERDICT: PASS**

## 1. 目标与结论

把 `xray-proxy-vless` vision 数据面错误事件从**裸 `tracing::event!`** 接到 **`xray-frame::redline` 受控入口**，使
`redline_sites::escape_hatch_call_sites_are_registered` 由红转绿。

- 门状态：`3 passed / 1 failed` → **`4 passed / 0 failed`**
- 数据面：**零改动**（diff 只有 import 一行 + 日志调用四行，`poll_read` 的 splice/DIRECT 判定逐字未动）
- `redline.rs` API：**未扩**（按 PM 拍板，结构化字段折叠进 message）

## 2. 改动（唯一文件）

`crates/xray-proxy-vless/src/encryption/vision_conn.rs` → `git diff --stat`：`14 +++--`（+8 / -6）

```diff
@@ -20,6 +20,7 @@ use tokio::{
     io::{AsyncRead, AsyncWrite, ReadBuf},
     net::TcpStream,
 };
+use xray_frame::redline::{self, RedlineSite};
 use xray_transport::connection::Connection;
@@ -383,11 +384,14 @@ where
                 Poll::Ready(Err(e)) => {
                     // 结构化观测：TLS 层 fatal（如对端安全层误解 raw 流的
                     // BadRecordMac）是 splice 边界问题的第一现场。
-                    // 红线登记（nn8os 2b）：vision splice 数据面 raw tracing 保留
-                    // （迁移票判定规则：红线不硬攻）；`warn!` → `event!` 为等价
-                    // 展开（warn! 即 event!(Level::WARN, ..) 薄壳），仅过 L3 宏
-                    // 禁令，运行时零差异。
-                    tracing::event!(tracing::Level::WARN, error = %e, "vision inner read error");
+                    // 面 5 红线受控入口（nn8os 2b → 台账 RedlineSite::VisionSpliceEvent）：
+                    // target/level 由站点钉死（= 原裸 event! 的模块 target → 订阅者过滤串不变）；
+                    // redline::event 只承载单条 message，原结构化字段 error 折叠进 message 尾部。
+                    redline::event(
+                        RedlineSite::VisionSpliceEvent,
+                        tracing::Level::WARN,
+                        format_args!("vision inner read error: error={e}"),
+                    );
                     return Poll::Ready(Err(e));
                 },
```

**数据面零改动的证明**：diff 两个 hunk 均不在判定路径上——hunk 1 是 `use` 组，hunk 2 的**唯一实质变更**是
`Poll::Ready(Err(e)) =>` 分支里的日志语句；该分支 `return Poll::Ready(Err(e));`、`Poll::Pending` 分支、
DIRECT 帧处理（`COMMAND_PADDING_DIRECT` / `seal inner read`）、`downlink_pending` / `xtls_filter_tls` 调用
**逐字未动**。`git diff --stat` 中另有 `crates/xray-app-dispatcher/**`（CR1aC 面）与 `docs/benchmarks/baseline.md`
（他人面），非本代理改动。

## 3. 折叠后的消息文本（PM 拍板口径）

|项|改动前|改动后|
|---|---|---|
|level|`WARN`|`WARN`（字面量，未变）|
|target|模块路径 `xray_proxy_vless::encryption::vision_conn`|`redline::event` 内为 `VisionSpliceEvent` 钉死 `"xray_proxy_vless::encryption::vision_conn"` → **同一字符串**|
|message|`"vision inner read error"`|`"vision inner read error: error=<e>"`（`format_args!` 发射点格式化）|
|结构化字段|`error = %e`（独立字段）|**折叠进 message 尾部** `error=<e>`（`redline::event` 只承载单条 `fmt::Arguments`，API 未扩）|

target 等价性证据：`crates/xray-proxy-vless/src/lib.rs:31 pub mod encryption;` +
`crates/xray-proxy-vless/src/encryption/mod.rs:56 pub mod vision_conn;` → 模块路径就是
`xray_proxy_vless::encryption::vision_conn`，与 `redline.rs` 为 `VisionSpliceEvent` 钉死的 target 字面量
一字不差 → 外部日志订阅者的过滤串不变。

## 4. 断言依赖记录（逐处列举，按任务要求）

全仓 grep `vision inner read error` 命中 2 处（`crates;dist;tests` 全扫）：

|位置|性质|结论|
|---|---|---|
|`crates/xray-proxy-vless/src/encryption/vision_conn.rs:390`（改前）|被迁移的发射点本身|已改为 `redline::event`|
|`crates/xray-frame/tests/hot_log.rs:134`|`hb.write_fmt(format_args!("vision inner read error"))` —— HotBuf 测试**自带字面量样本消息**，不消费 vless 事件|**不受影响**，断言原文零改动|

- 全仓**无**任何测试断言本事件的 `error` 结构化字段名，也无需改任何断言为 message 子串。
- `crates/xray-proxy-vless/src/error.rs:193` 的 `tracing::event!`（测试面 UUID 掩码断言）**未动**；门
  `bare_tracing_event_only_exists_in_registered_redline_files` 通过 → 测试面豁免生效（未出现需上报的情形）。

## 5. 验收（四条 P0，全实跑）

### 5.1 红线四门（`cargo test -p xray-frame --test redline_sites -j 8`）

```
running 4 tests
test ledger_entries_are_complete ... ok
test redline_spawn_is_observable ... ok
test escape_hatch_call_sites_are_registered ... ok
test bare_tracing_event_only_exists_in_registered_redline_files ... ok

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.30s
```

（改前该文件报红原文：`站点 vision.splice.event 已登记但其期望文件 crates/xray-proxy-vless/src/encryption/vision_conn.rs 无逃逸口调用`；
现 `found` 集合含该文件，`registered ⊆ found` 双向满足。）

### 5.2 vless 全 target（`cargo test -p xray-proxy-vless --all-targets -j 8`）

```
Running unittests src\lib.rs   test result: ok. 287 passed; 0 failed; 1 ignored
Running tests\plugin_contract.rs   test result: ok. 14 passed; 0 failed; 0 ignored
Running tests\vless_proxy_e2e.rs   test result: ok. 2 passed; 0 failed; 0 ignored
Running tests\vps_interop.rs       test result: ok. 0 passed; 0 failed; 2 ignored
```

合计 303 passed / 0 failed / 3 ignored（VPS 组按口径 ignored，不涉及）。

### 5.3 clippy + fmt

```
cargo clippy --workspace --all-targets -j 8 -- -D warnings
    Checking xray-proxy-vless v0.1.0 ...
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 2m 07s    # 0 error / 0 warning

cargo fmt --all -- --check      # 空输出（clean）
```

### 5.4 interop 矩阵（`python` 壳复用 `dist/interop_matrix.py`，RUST = 本代理 release 构建）

```
== A: Rust client -> Go server ==
[PASS] #01 Rust->Go vmess            HTTP body= 200028B
[PASS] #02 Rust->Go vless_vision_tls HTTP body= 200028B
[PASS] #03 Rust->Go trojan_tls       HTTP body= 200028B
[PASS] #04 Rust->Go vless_ws         HTTP body= 200028B
[PASS] #05 Rust->Go ss               HTTP body= 200028B
[PASS] #06 Rust->Go ss2022           HTTP body= 200028B
== B: Go client -> Rust server ==
[PASS] #07 Go->Rust vmess            HTTP body= 200028B
[PASS] #08 Go->Rust vless_vision_tls HTTP body= 200028B
[PASS] #09 Go->Rust trojan_tls       HTTP body= 200028B
[PASS] #10 Go->Rust vless_ws         HTTP body= 200028B
[PASS] #11 Go->Rust ss               HTTP body= 200028B
[PASS] #12 Go->Rust ss2022           HTTP body= 200028B

=== 互操作矩阵: 12/12 PASS ===
```

- 跑批壳：`D:/tmp/w7_interop_run.py`（`runpy` 复用原脚本，仅换 `RUST` 指向 `target-w7/release/xray.exe`、
  `WORK` 独占、`kill()` 改 no-op 以免 `taskkill /IM xray.exe` 误杀同机其他代理进程）。断言/协议用例原文零改动。
- 每行 `curl: (28) … 15022 ms` 是 `--max-time 15` 截断 YouTube 大页的正常现象（body 已 200KB 且含 marker），
  A 组（Rust 客户端）与 B 组（Go 客户端）**同形同尺寸** → 非本改动引入。
- 抓包：按任务口径**不需要**（本次是日志调用形态迁移，数据面字节未变；wire 不变性由 diff 证明）。
- 32/32 VPS：不跑（归 PM）。

## 6. 环境与产物

- `CARGO_TARGET_DIR=D:/Project/Xray-core-rust/target-w7`（独占；当前 9.8G，含 release CLI，保留供 PM 复验，可随时删）
- 构建开关：`BORING_BSSL_PATH=target/boringssl-asm/prebuilt`（汇编版，非 NO_ASM 路径）+ `PROTOC` / `LIBCLANG_PATH`
- 未 commit / 未 push（归 PM）

## 7. 5 轴自评

- **准确性 5/5** — 四条验收均为本机实跑输出原文（门 4 tests、vless 4 二进制 303 passed、clippy Finished 0 error、interop 12/12）；target 等价性由 `lib.rs:31` + `encryption/mod.rs:56` + `redline.rs` 字面量三方对照给出，非推断。
- **完整性 5/5** — 任务书 6 条要求全覆盖：门转绿、vless 不劣化、clippy/fmt clean、interop 12/12、数据面零改动 diff 证明、断言依赖逐处列举（含"无断言依赖结构化字段"的否定证据）。
- **清晰度 5/5** — 按「结论 / diff / 折叠口径 / 断言记录 / 四组验收 / 环境」分节，每条数字带命令。
- **可执行性 5/5** — 报告含可直接复跑的命令、跑批壳路径、目标目录与构建开关，PM 可原样复验。
- **简洁性 4/5** — 扣分：§3 与 §2 的注释片段有轻微重复（保留是为让「折叠口径」独立可读）。

## 8. 未做 / 残余风险

- 未做：32/32 VPS 实网、抓包、`redline.rs` API 扩展（PM 已拍板不做）、commit/push。
- 残余风险（低）：本事件**改前改后均无单元测试断言其发射**（全仓无 capture-subscriber 断言），故 message 文本
  `error=<e>` 的运行时形态由编译期字面量 + `redline::event` 的 level 分派宏保证，未被测试捕获验证；
  若需硬证据，可后续在 vless 侧补一条 capture 断言（本次按「不动测试面、不新增文件」口径不做）。
- 文档失真提示（不改他人报告原文）：`reports/audit-2026-10-27/tracing-migrate-batch1.md:69,75` 仍写
  "vision_conn.rs:390 保留 raw tracing"，该站现已迁至 `redline` 受控入口——以本报告为准。
