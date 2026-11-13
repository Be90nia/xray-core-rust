# vendor/h2 — 本仓 patch 说明（SOP）

## 基线

- 上游：crates.io **h2 0.4.20**（`.crate` 解包原样入库，`Cargo.toml.orig` 保留可核对基线与 patch 差异）。
- 引入方式：`Cargo.toml` 的 `[patch.crates-io]` 段 `h2 = { path = "vendor/h2" }`；
  `[workspace] exclude` 同时排除 `vendor/h2`（path 依赖落在 workspace 目录内会被 cargo 自动纳入 member）。

## 唯一 patch 面

`src/proto/streams/flow_control.rs`：

| 项 | 上游行为 | 本仓行为 |
|---|---|---|
| WINDOW_UPDATE 回填阈值 | 窗口的一半（`window_size / 2`）⇒ 稳态在飞只有半窗 | `min(window_size / 2, INFLOW_MIN_REFRESH = 4 KiB)`，与 **Go `x/net/http2` 的 `inflowMinRefresh`（`http2/flow.go:12-14`，`4 << 10`）** 同粒度 |
| 测试 | — | 新增 `window_update_threshold_is_min_of_half_window_and_4kib`（32 MiB 窗 → 4096） |

**为什么**：半窗回填把稳态在飞数据砍半 ⇒ 高 RTT 路径吞吐被腰斩（实测 RTT 170 ms 69.8–70.1 MB/s、RTT 400 ms 35.6–35.8 MB/s，恰好一半）。Go 侧因 4 KiB 粒度回填而在同样 RTT 下满窗在飞，这是 xhttp 过 CDN 慢于 Go 的一半根因。

> 注意：另一半是 CF 侧 `BUF/RTT` 信用门（我们窗管不到 CF↔origin 腿），见
> `reports/2026-11-13-cf-buffering-verification.md`。本 patch 只负责「我们自己这半窗」。

## 升级流程（上游发新版时）

1. 下载新版 `.crate` 并解包，**整目录替换** `vendor/h2`（保留本 `REBASE.md`）。
2. 在新 `src/proto/streams/flow_control.rs` 上**重新叠这一个 hunk**：新增 `INFLOW_MIN_REFRESH`
   常量 + 把阈值函数的返回值改成 `min(window/2, INFLOW_MIN_REFRESH)`，并把上游自带单测
   一起带上（若上游改了函数名，按新名重写，语义不变）。
3. 验证三条，缺一不许提交：
   - `cargo test -p h2`（vendor 自己的测试，若有）与 `cargo test -p xray-transport-splithttp`；
   - `cargo check --workspace --all-targets`；
   - loopback A/B（`tools/loopback_alloc_bench.py --ab`）确认高 RTT 下吞吐仍为满窗，无回归。
4. 更新本文件「基线」与 `Cargo.toml` 注释里的版本号。

## 禁止事项

- **不要**改 `vendor/h2` 里 `flow_control.rs` 之外的任何文件（patch 面保持最小，便于升级时 diff）。
- **不要**把 `vendor/h2` 纳入 workspace member（会重复编译 + feature 解析错乱）。
- **不要**在此目录跑 `cargo fmt`（上游排版不改，避免升级 diff 爆炸）。
