# vendor/h2 — 本仓 patch 说明（SOP）

## 基线

- 上游：crates.io **h2 0.4.20**（`.crate` 解包原样入库，`Cargo.toml.orig` 保留可核对基线与 patch 差异）。
- 引入方式：`Cargo.toml` 的 `[patch.crates-io]` 段 `h2 = { path = "vendor/h2" }`；
  `[workspace] exclude` 同时排除 `vendor/h2`（path 依赖落在 workspace 目录内会被 cargo 自动纳入 member）。

## patch 面（2026-11-16 起共两处）

### 1. `src/proto/streams/flow_control.rs`（WINDOW_UPDATE 回填阈值）

| 项 | 上游行为 | 本仓行为 |
|---|---|---|
| WINDOW_UPDATE 回填阈值 | 窗口的一半（`window_size / 2`）⇒ 稳态在飞只有半窗 | `min(window_size / 2, INFLOW_MIN_REFRESH = 4 KiB)`，与 **Go `x/net/http2` 的 `inflowMinRefresh`（`http2/flow.go:12-14`，`4 << 10`）** 同粒度 |
| 测试 | — | 新增 `window_update_threshold_is_min_of_half_window_and_4kib`（32 MiB 窗 → 4096） |
| 可见性 | `fn window_update_threshold` 私有 | `pub(crate)`（connection.rs 的 flush_gate 捆绑断言跨模块引用）；`streams/mod.rs` 的 `mod flow_control` 同步 `pub(crate)` |

**为什么**：半窗回填把稳态在飞数据砍半 ⇒ 高 RTT 路径吞吐被腰斩（实测 RTT 170 ms 69.8–70.1 MB/s、RTT 400 ms 35.6–35.8 MB/s，恰好一半）。Go 侧因 4 KiB 粒度回填而在同样 RTT 下满窗在飞，这是 xhttp 过 CDN 慢于 Go 的一半根因。

> 注意：另一半是 CF 侧 `BUF/RTT` 信用门（我们窗管不到 CF↔origin 腿），见
> `reports/2026-11-13-cf-buffering-verification.md`。本 patch 只负责「我们自己这半窗」。

### 2. `src/proto/connection.rs`（poll2 循环内非门控 flush，campaign C2，bd hktfy/9wktc）

| 项 | 上游行为 | 本仓行为 |
|---|---|---|
| poll2 逐帧处理后的出站帧 | 只在 poll() 的 Pending 臂（排空拖尾）`poll_complete` ⇒ 读侧持续 Ready 时，生产者 DATA 与消费回填 WINDOW_UPDATE 全部滞留 | poll2 **逐帧处理后**尽力 `poll_complete`：`if let Poll::Ready(res) = ... { res?; }`——**Pending 只吞不传播**（codec 已注册写就绪 waker，滞留帧由既有 Pending 臂收尾），错误仍传播 |
| 测试 | — | 同文件 `#[cfg(test)] mod flush_gate`：三钉桩（①单向大流量 WU 中途上线 ②写堵不停读 ③生产者灌 DATA 时控制帧不上界滞留，全部以 poll_read 快照断言「中途上线」）+ 捆绑断言 `flush_gate_bundles_flow_control_threshold_patch`（引用 patch 面 1 的 `window_update_threshold`，两侧任一被覆盖即红） |

**为什么**：xhttp 下行 = 同连接 GET 持续读 + 回填 WU；读侧热时 WU/出站帧滞留到拖尾 ⇒ 服务端看不到信用回填、在飞掉到半窗（bd 9wktc 实测窗利用率 ~62%）。形态取 Go `transport.go` 同临界区回填+Flush 的同构；**禁改回 `ready!` 透传**——写堵 ⇒ 停读是 h2#975 镜像面。

**测试为什么长这样**： vendored crate 无 fixtures/（`Cargo.toml` exclude）——上游 `hpack::test` 全量 fixture 测试在本树必然红（382 个，与本 patch 无关的环境性失败）；钉桩必须自含 mock io（`SharedIo`：单帧/次 poll_read + written 快照），断言「WU 在排空中途（非拖尾）上线」。

## 升级流程（上游发新版时）

1. 下载新版 `.crate` 并解包，**整目录替换** `vendor/h2`（保留本 `REBASE.md`）。
2. 重叠两个 hunk：
   - `src/proto/streams/flow_control.rs`：新增 `INFLOW_MIN_REFRESH` 常量 + 阈值函数改 `min(window/2, INFLOW_MIN_REFRESH)` 并升 `pub(crate)`（`streams/mod.rs` 同步 `pub(crate) mod flow_control`），带上同文件钉桩单测；
   - `src/proto/connection.rs`：poll2 循环内逐帧尽力 `poll_complete`（`if let Poll::Ready(res)`，**禁 `ready!` 透传**）+ 整块带回 `mod flush_gate` 测试。
3. 验证三条，缺一不许提交：
   - `cd vendor/h2 && cargo test`——以 `flush_gate` 4 测试 + `proto::/codec::/frame::` 全绿为准（`hpack::test` 因本树无 fixtures/ 必红，属环境性失败，升级前后一致即视为无回归）；
   - `cargo test -p xray-transport-splithttp` 与 `cargo check --workspace --all-targets`；
   - rig A/B（campaign-plan §3 步 1 判据）确认下行窗利用率与吞吐无回归。
4. 更新本文件「基线」与 `Cargo.toml` 注释里的版本号。

## 禁止事项

- **不要**改 `vendor/h2` 里上述两处之外的任何文件（patch 面保持最小，便于升级时 diff）。
- **不要**把 `vendor/h2` 纳入 workspace member（会重复编译 + feature 解析错乱）。
- **不要**在此目录跑 `cargo fmt`（上游排版不改，避免升级 diff 爆炸）。
- **不要**在 connection.rs 的 flush hunk 上加 `ready!`/门控语义（写堵 ⇒ 停读 = h2#975 镜像，钉桩会红）。
