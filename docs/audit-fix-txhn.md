# bd txhn 审计与修复：mux carrier 高丢包链路 ~2s 静默死亡

- 票：bd txhn（P2，loss-resilience/mux）· 2026-10-09 · FixTxhn
- 结论行：**根因 = 共享写端帧写入非原子（帧头/载荷分两次共享锁临界区落盘），并发会话载荷插隔致帧流错位，读端 `meta_len too large` 拆整条 carrier；非窗口钉死族、非 carrier EOF 语义缺失**。VERDICT: FIXED（本地 e2e 复现→修复→回归 + 单元回归测试；VPS 复验协议见 §6）

## 1. 根因证据链（文件:行号）

1. **VPS 表型**（VISIONMAC5.md 补遗 3）：loss 0.5%+RTT150ms 下 carrier 存活 ~2s（client `bytes_retrans 1213` 后 socket 消失），8 流首轮突发 13KB-327KB 后零字节，9/9 复现；冒烟期即带病（c8 单流 1.56 vs perflow 6.58MB/s）。载体接收侧 rcv_space autotune 3.9MB 健康 → 排除 88m0 收窗族。
2. **本地复现（无 netem，loopback 8×12MB 流）**：`target/txhn-repro/out/cli.log` 抓获 4 条
   `mux client fetch_output stopped: meta_len too large: 11396/46734/21529/21960`
   —— 客户端 carrier 读循环（`crates/xray-mux/src/client.rs` `read_frame`）把**载荷字节当前帧头长度**解析 → 帧流错位实锤；对应 4 次 worker 死亡、8 流 0-2.9MB 饿死。单流冒烟不触发（无并发写者）、≥2 会话并发 ≥4KB 载荷即触发——与 VPS「~2s 死亡、9/9 一致」完全吻合。
3. **错位机理**：`MuxWriter` 每帧 = `[帧头(2B len+meta), 载荷(≤8KB)]`（`crates/xray-mux/src/writer.rs` `write_meta_with_frame`），但旧实现经 `BufferedWriter::write_multi_buffer_impl`（`crates/xray-buf/src/writer.rs`）**逐 Buffer** 走 `write_buffer`：
   - 帧头 ~30B ≤ 容量半量 → 滞留内部缓冲；
   - 载荷 8192B > 容量半量 → 先 `flush()`（帧头单独一次 `SharedWriter` 锁临界区落盘）、再直写（载荷第二次锁临界区）；
   - **两个临界区之间，另一会话的完整帧可整帧插入** → 流内出现「会话 A 帧头 … 会话 B 完整帧 … 会话 A 孤立载荷」→ 读端在 B 帧消费完后把 A 的载荷当帧头 → `meta_len too large`。
4. **为什么 carrier 死了不重建/无 ERROR**：
   - carrier 死亡 → `fetch_output` break → `close()` → monitor 关全部 session → app 流终止；EOF 路径**零日志**、错误路径仅 debug 级（`client.rs` fetch_output 旧代码）→ 「无 ERROR」。
   - 重建是按需的（下一 `Dispatch` 经 picker 跳过 closed worker 新建 carrier，Go 同语义）；VPS 场景 8 流全挂后无新 dispatch → 「无重建」。死亡竞窗期间新 dispatch 命中 `is_full`（closed→full）→ 旧 `MuxBridge::dispatch` 直接 **warn + 丢 link**（`outbound.rs`），流被静默丢弃 → 加重「冻结」观感。
5. **Go 基线（D:/Project/Xray-core）**：`common/mux/writer.go:71-87` `writeMetaWithFrame` 把 frame+data append 进**同一 mb 一次 `WriteMultiBuffer`**；共享载体写端是 `*pipe.Writer`，`transport/pipe/impl.go:128-131` `writeMultiBufferInternal` 持 `pipe.sync.Mutex` 整批写 → **Go 天然帧原子**。Rust 偏离点即 `BufferedWriter` 的逐 Buffer 拆分写。

## 2. 修复（diff 摘要）

| 文件 | 改动 |
|---|---|
| `crates/xray-buf/src/writer.rs` | 新增 `BufferedWriter::write_multi_buffer_direct`：先 flush 既有内部缓冲（保序），再把整 mb **单次**交付底层 Writer——共享写端下的帧原子性边界 |
| `crates/xray-mux/src/writer.rs` | `write_meta_only` / `write_data` / `write_meta_with_frame` / `close` 全部改走 direct（对齐 Go writer.go:71-87 单 WriteMultiBuffer 形态），删除冗余尾 flush；锁获取次数：≥4KB 帧 2→1，其余持平 |
| `crates/xray-mux/src/client.rs` | `fetch_output` 终止可观测：EOF/错误/写失败原因 + 掉线会话数，有活跃会话时 **error!** 级（旧 EOF 零日志/错误 debug 级） |
| `crates/xray-core/src/inbound.rs` | 服务端 mux 帧循环 `Err` 分支 warn → **error!**（carrier 连同全部子会话拆除处） |
| `crates/xray-core/src/outbound.rs` | `MuxBridge` 抽 `dispatch_via_picker`：对齐 Go `ClientManager.Dispatch` 16 次重试环（`is_full` 预检后死亡竞窗换 worker 重 pick，无可用由 picker 经 factory **新建 carrier = 补位重建**）；全部 link 丢弃路径 warn → **error!** |
| `CHANGELOG.md` | Unreleased/Fixed 加 txhn 条目 |

红线核对：未触碰 xray-transport-tcp/register.rs、vendor patch、dist/、ws/httpupgrade 指纹；未 commit；公共 API 签名未变（仅新增 crate 内 pub 方法 `write_multi_buffer_direct`）。

## 3. 回归测试

- `crates/xray-mux/src/writer.rs::tests::shared_writer_interleaved_frame_writes_stay_atomic`：2 个 `MuxWriter` 经同一 `SharedWriter` 并发各写 24×8KB（384KB 流量灌 64KB 管道制造背压交错），并发逐帧解析断言：meta_len 合法、session_id 已知、载荷长度恰 8192、载荷不跨会话污染、每会话帧数 24。旧实现在该调度形态下帧被插隔即击穿断言；修复后通过。
- 补位重建语义既有覆盖：`test_incremental_picker_pick_internal` / `test_incremental_picker_concurrent_pick_does_not_penetrate`（closed worker 被跳过、并发只建 ≤2）。

## 4. 本地验证（命令 + 关键输出）

```
cargo test -p xray-buf --lib      → 186 passed; 0 failed
cargo test -p xray-mux --lib      → 142 passed; 0 failed（含新回归测试）
```

本地 e2e（`target/txhn-repro/`，8 流并发经 socks→vless+mux c8→vless→freedom→http sink）：
- 修复前：cli.log 4× `meta_len too large`，8 流终态 0/8192/40960/1949696/2678784/2899968/0/0 B（12MB 流大面积饿死）。
- 修复后：见 §5（全量送达 + 日志零异常）。

## 5. 修复后 e2e（同装置 rerun，release 重建产物）

```
smoke single-flow: 242319255B/s
== finals ==   （8×12MB 流，40s 窗）
flow1..flow8 = 12582912 × 8   ← 全量送达（修复前 0/8192/40960/1949696/2678784/2899968/0/0）
```

- cli.log 零 `meta_len too large`、零 `fetch_output stopped`；唯一 carrier 终止记录为全部流完成后 16s 空闲退役的 debug 级正常记录（`carrier terminated (no active sessions) reason=worker closed`）。
- 命令：`bash target/txhn-repro/run_repro.sh`（脚本含拓扑/采样/复原段）。

## 6. VPS 验证协议（交 PM / VisionMac5）

1. 取修复 commit 构建产物（CI run 或本地 `cargo build --release`），推 VPS `/root/bin/xray-txhn-fix`。
2. 复跑 `gam0_matrix.sh`（原脚本零改动：拓扑/采样/netem 0.5%+75ms 双腿、3 臂 ×3 轮）。
   - **通过判据**：c8 臂 carrier socket 存活整个 90s 窗（无 ~2s 消失）、cli/inb 日志零 `meta_len too large`、8×50MB 全量送达、per-flow rate_p50 ≥ perflow 臂 ×0.8；客户端日志零 `mux carrier terminated, active sessions dropped`（error 级新埋点）。
   - 复现手段（若需定位残差）：`RUST_LOG=xray_mux=error,xray_core=error` 收紧日志面，error 埋点即 carrier 死亡探针。
3. 现场纪律：跑完 `tc_restore.sh` + 杀实例 + rmem_max 还原 212992（脚本已含复原段）。

## 7. 残余风险

- `is_full` 预检与 `session_manager.allocate` 之间仍有 µs 级竞窗（allocate 失败即断流，error 可观测）；彻底消除需 `ClientWorker::dispatch` 返回被消费的 link（公共 API 变更），按 Go 16 次耗尽语义已对齐，不再做。
- 单元回归测试的「旧实现必挂」依赖调度时序（384KB→64KB 管道背压），理论存在侥幸通过可能；本地修复前 e2e 已提供确定性旧实现失败证据。
- 冒烟期 mux 单流偏慢（VPS 1.56 vs perflow 6.58MB/s）为独立吞吐议题（帧处理 + 64KB pipe 结构），不在本票修。
