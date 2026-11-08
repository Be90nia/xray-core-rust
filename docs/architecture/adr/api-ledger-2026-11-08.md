# API 记账表——批次 B `2b2407da..HEAD`（整改波补录 8 项）

> 2026-11-08 审计整改波 P3 交付物。口径同
> [批次 A](api-ledger-2026-11-06.md)：`git diff -U0 2b2407da..HEAD -- crates` 中
> `^\+\s*pub (async fn|fn|struct|enum|trait|const|static|type|mod|use)` 声明行。
>
> **本表只补录 `rescore-architecture.md` §3 N-01 点名的整改波新增公共 API（8 项）**。
> 同区间（`2b2407da..HEAD`）本表口径实测 **151 条**声明行——在 `aa0252a3` 快照上重算同样
> 得 151 条，与审计记的 136 条差异属**统计口径不同**（非期间新增），故以本条命令的
> 可复现数字为准。其余约 143 条仍欠账（A-05），按 bd 8snor/2myvx/w9ttk 逐项入下一批表
> ——本表**不冒充**那批的账。
>
> 每项给：位置（`aa0252a3`/`a5871ebb` 快照行号，随树漂移）+ 归属结论 + 核实方式。

## A. 常量入 ADR-0002 既定地址（`xray-frame::budget`）——3 项

| 项 | 位置 | 归属理由 |
|---|---|---|
| `QUIC_CONN_RECEIVE_WINDOW_BOOKED_BYTES` | `crates/xray-frame/src/budget.rs:113`（= 32 MiB） | 纯常量簿，[ADR-0002](adr-0002-memory-budget-ownership-split.md) 裁决后的既定地址（判据 1 不成立：QUIC 缓冲口径属 Xray 语义 ⇒ 判据 2 归派生层）。值 = 实现缺省 `xray_transport_quic::config::DEFAULT_CONNECTION_RECEIVE_WINDOW`，**交叉断言钉住**（`xray-core::memory_budget::tests::quic_receive_window_ledger_enters_hard_account`:652）|
| `QUIC_STREAM_RECEIVE_WINDOW_BYTES` | `crates/xray-frame/src/budget.rs:119`（= 16 MiB） | 同上（同址；流窗是**连接窗信用内**的子份额，doc 明记「不单独入账」，防重复记账）|
| `XDNS_FRAG_WORST_CASE_BYTES` | `crates/xray-frame/src/budget.rs:196`（= 43,155,456） | 同上（同址；账面算式从实现常量计算，`xdns::frag::WORST_CASE_BYTES` 交叉断言——`memory_budget::tests::xdns_frag_ledger_matches_impl`:1368，改任一上限即红）|

## B. 派生层迁移中件的读数/写入口——2 项（`xray-common::mem_probe`）

| 项 | 位置 | 归属理由 |
|---|---|---|
| `MemoryPlan::effective_max_conns` | `crates/xray-common/src/mem_probe.rs:266` | 归属已由件头 §3.5.5 三判据 + 3 步迁移清单举证（`mem_probe.rs:27-57`，A-03）：档位策略归 `xray-frame::budget::plan`，本项是**读数 API**（`EFFECTIVE_MAX_CONNS` AtomicUsize，0 = 未覆写、回落到派生值），随迁移清单第 2 步平移，**无新归属决策** |
| `set_effective_max_conns` | `crates/xray-common/src/mem_probe.rs:282` | 同上：进程级生效连接数写入口（`limit.max(1)`，返回落库值）；迁移清单第 2 步点名迁 `xray_frame::budget::plan`。消费点 `xray-core::memory_budget`（降档后写生效值，D-02 执行点）|

## C. 无新归属裁决（既有 crate 内的停机接线 / 交叉断言所需可见性）——3 项

| 项 | 位置 | 归属理由 |
|---|---|---|
| `close_shared_client_endpoints` | `crates/xray-transport-quic/src/transport.rs:145` | 停机接线：`Instance::close()`（`xray-core/src/instance.rs:411`）收尾调它 drain 进程级 `SHARED_CLIENT_ENDPOINTS`（旧端点每个 8 MiB 内核缓冲 ×2 不再钉住进程）。**不引入机制**，故无需 ADR；多实例共享池语义已登记为观察项（rescore-security N-2）|
| `DEFAULT_STREAM_RECEIVE_WINDOW` | `crates/xray-transport-quic/src/config.rs:13`（= 16 MiB） | **private → pub**（行为面不变，doc 自陈「pub 是为了登记簿交叉断言」，同 `handshake_gate::MAX_INFLIGHT_HANDSHAKES` 先例）；QUIC 传输语义留协议 crate（§3.5.3 方向件），只开可见性 |
| `DEFAULT_CONNECTION_RECEIVE_WINDOW` | `crates/xray-transport-quic/src/config.rs:18`（= 32 MiB） | 同上；doc 区分「应用层真缓冲 vs socket `SO_RCVBUF`」不同账（bd 2026-11-08 D-03）|

## 补录项（本轮 P3 波新增：核实后入账）

| 项 | 现状 | 结论 |
|---|---|---|
| `bridge::PIPE_BUF_CAP` | `crates/xray-transport/src/bridge.rs:33`（= 64，模块级 `pub const`） | **入账（第 9 项，本轮 P3 波）**：原为函数内私有，提 pub 的唯一理由是簿交叉断言的事实源（D-05：禁簿值自证）。`xray-core::memory_budget::bridge_backpressure_ledger_matches_impl` 已改为 `(PIPE_BUF_CAP + 2) * 512KiB * 2` 推导（PM 亲跑该测试 1 passed）。行为面由 `crates/xray-transport/tests/bridge_backpressure_entry_cap.rs` 钉住，值未变 |

## 记账口径备注

- 「无需 ADR」≠「无需遵守纪律」：B/C 类仍受 §3.5.2 查重与 §3.5.5 三判据约束，只是
  不产生**新的**归属裁决。
- 逐项核实方法：`git diff -U0 2b2407da..HEAD -- crates` 过滤 `+\s*pub …` 声明行，
  再对每条落地文件 `git show HEAD:` 取行号与 doc；**未引用工作树**（工作树有他代理
  未提交改动）。
- 本表为批次快照（`2b2407da..HEAD` 的整改波子集）；后续批次另起批次表。
