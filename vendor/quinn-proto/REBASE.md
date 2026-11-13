# vendor/quinn-proto — 本仓 patch 说明（SOP）

## 基线

- 上游：crates.io **quinn-proto 0.11.19**（`.crate` 解包原样入库；`Cargo.toml.orig` 保留，
  可与 `Cargo.toml`（cargo 规范化后的那份）对照核对基线与 patch 差异）。
- 来源指纹：`.crate` sha256 `0e750cca55fe4f0439a15d0bb529da9651e79993e8e72c61a899a36d462befbe`；
  `.cargo_vcs_info.json` = `quinn-rs/quinn@8192ed399a26a6e8f0aba43d10ec8badaa5b905e`。
- 引入方式：根 `Cargo.toml` 的 `[patch.crates-io]` 段 `quinn-proto = { path = "vendor/quinn-proto" }`。
  它是 patch 源而非 workspace member ⇒ 自带的 `src/tests/` 不进 `cargo test --workspace`，
  `Cargo.lock` 里该包条目也不含 dev-deps（h2 额外登记了 `exclude`，本 crate 无需）。
- 版本演进：0.11.18 → **0.11.19 为安全版**，消解
  - `RUSTSEC-2026-0523` / GHSA-53rm-773f-4q8c：`MAX_STREAM_DATA` 指名未开的高号 bidi 流时，
    `received_max_stream_data` 不做流号上限校验就把该流及所有更小号流当已开 ⇒ 对端一帧小包
    即可让 `accept_bi` 循环吐出 >2^40 条流（OOM / 空转）。修在
    `src/connection/streams/state.rs`（`validate_receive_id` + 隐式开流处防御检查）。
  - `RUSTSEC-2026-0524` / GHSA-wppq-2f6r-wfvm：Retry token 无长度上限且进每个 Initial 头，
    1200B 的 Initial 装不下最小载荷时 `PacketBuilder::new` 的 `min_size > max_size` 只被
    debug 断言兜住 ⇒ debug 构建 panic / release 构建单次尝试分配 >10GiB 并 abort。修在
    `src/connection/packet_builder.rs`（Initial token 挤掉帧空间即 `PROTOCOL_VIOLATION` 关连）
    + `src/connection/mod.rs`（ACK 之后给 CONNECTION_CLOSE 留位）。

## 唯一 patch 面

`src/connection/datagrams.rs` 的 `Datagrams::max_size()`：

| 项 | 上游行为 | 本仓行为 |
|---|---|---|
| 对端未广告 `max_datagram_frame_size` TP | `peer_params.max_datagram_frame_size?` ⇒ 返回 `None`（= 无法发 datagram，`send()` 报 `UnsupportedByPeer`） | 按本地 `path.current_mtu()` 推上限假定对端支持 ⇒ 返回 `Some(min(本地MTU, mtu−1RTT头−帧界))` |
| 对齐对象 | — | apernet/quic-go fork 的 `AssumePeerMaxDatagramFrameSize`（Go 侧 `transport/internet/hysteria/hub.go` + `dialer.go`，自 2026-09-01 起 client `OmitMaxDatagramFrameSize=true` 不再广告） |
| 继承面 | — | 0.11.18 起的 `Datagrams::drop_oversized()` 走 `max_size()`，自动继承本假定（不会把假定上限排掉的包误丢） |
| 守卫测试 | — | `crates/xray-transport-hysteria/src/quinn_adapter.rs::send_side_max_datagram_when_peer_omits_tp`（对端 `datagram_receive_buffer_size(None)` ⇒ 本侧 `max_datagram_size()` 必须 `Some` 且 `send_datagram` 成功） |

**为什么**：quic-go 的 hysteria2 客户端只省略广告、仍照 `AssumePeerMaxDatagramFrameSize`
收包；Rust 侧服务端若照上游返回 `None`，回包（UDP 下行中继）全部 `UnsupportedByPeer` 丢掉
⇒ 下行静默断流。背景数据见 `reports/audit-2026-10-29/hysteria-datagram-fix.md`。

**0.11.19 判定**：上游**仍未**提供等价 assume-peer API（`max_size()` 原文仍是
`peer_params.max_datagram_frame_size?`，`?` 展开即「对端未广告 ⇒ `None`」），故本 patch 保留。

**已知冲突（不影响 CI）**：上游单测 `src/tests/mod.rs::datagram_unsupported` 断言「对端未广告
⇒ `max_size() == None`」，与本 patch 语义相反 —— 0.11.18 起即如此，vendor 单测不进本仓测试面。

## 升级流程（上游发新版时）

1. 下载并校验：
   ```bash
   curl -sSL -o quinn-proto-<VER>.crate https://static.crates.io/crates/quinn-proto/quinn-proto-<VER>.crate
   sha256sum quinn-proto-<VER>.crate   # 记进本文件「基线」
   tar -xzf quinn-proto-<VER>.crate
   ```
2. **整目录替换** `vendor/quinn-proto`（替换掉除本 `REBASE.md` 外的全部文件；`Cargo.toml.orig`
   要留着，它是基线对照物）。
3. 在新版 `src/connection/datagrams.rs` 的 `max_size()` 上**重新叠这一个 hunk**：把上游的
   `let limit = self.conn.peer_params.max_datagram_frame_size?...;` 换成 `match` + `None` 分支
   按本地 MTU 推上限，注释里的 `REBASE(quinn>=<新版本>)` 同步改，并写清「上游是否已有等价 API」
   的判定依据（引用新版源码那一行）。
4. 同步根 `Cargo.lock` 里 `name = "quinn-proto"` 的 `version`（path 依赖无 checksum，只需改版本号；
   `cargo check` 也会自己重写，但先改可避免锁文件与 vendor 树不一致）。
5. 验证四条，缺一不许提交：
   - `cargo tree -i quinn-proto` ⇒ 显示 `quinn-proto v<新版本> (…/vendor/quinn-proto)`；
   - `cargo check --workspace --all-targets` ⇒ 0 error；
   - `cargo test -p xray-transport-hysteria` ⇒ 全绿（含 `send_side_max_datagram_when_peer_omits_tp`
     与 `datagram_1200_and_1414_payload_survive_default_window`）；
   - hysteria2 真机 UDP 互通（Rust 服务端 ↔ Go 客户端）：下行中继不 `UnsupportedByPeer`。
6. 更新根 `Cargo.toml` 里 `quinn-proto` 上方注释的基线版本与安全票结论，并更新本文件。

## 禁止事项

- **不要**改 `vendor/quinn-proto` 里 `src/connection/datagrams.rs` 之外的任何文件（patch 面保持最小，
  升级时 diff 才能一眼看完）。
- **不要**在 vendor 目录跑 `cargo fmt`（上游排版不改，避免升级 diff 爆炸）。
- **不要**把 vendor 单测接进本仓测试面（会撞上面「已知冲突」，且拉进一堆 dev-deps）。
- **不要**为了「看起来更接近上游」删本 patch —— 删了 hysteria2 UDP 下行对 Go 客户端直接断流。

## 本次升级（0.11.18 → 0.11.19）验证记录

命令与输出见 bd nza5s 回执；判定要点：

- 上游 0.11.18→0.11.19 源码变更共 8 文件（`config/transport.rs` 文档、`connection/{mod,packet_builder}.rs`
  token 修复、`connection/streams/state.rs` 流上限、`endpoint.rs` 失败时回收 cid、`tests/*` 新测试），
  **无一触碰 `max_size()` / `drop_oversized()`** ⇒ 与本地 patch 正交。
- datagram 发送上限的全部判定都汇于 `max_size()`（`send()` 取上限、`drop_oversized()` 判可留、
  上游 `can_send_1rtt` 由 `Connection` 传同一值），故 patch 一处即覆盖三条路径。
