# Batch D-6a 实施报告：gjfs re-triage + 6odi splice handoff race

日期：2026-09-16 · agent：impl-d6a · HEAD 基线：ae2e1a6

## 结论（VERDICT）

```
VERDICT: gjfs = (a) 完全覆盖 → 建议关票（票面病灶已被 8sum 方案 A 消除，无残余落地项）
VERDICT: 6odi = 已落地（VisionConn 写侧 splice 激活延迟到 write 完成，对齐 Go f926ee4a）
```

- 失败分级：非 fatal；gjfs 票面与代码现实的偏差为 **recoverable 票面过时**（票面写于 49262b6 revert 态，未跟进 6b53cd5 方案 A 合入）。
- 无领域外副作用；未触碰禁区（bd 票只读 / 无 ws-httpupgrade / 无 register.rs / 未动 stash）。

## 任务 1：gjfs re-triage

### 1.1 票面主张（audit-performance-2026-09-15-r2.md §5，写于 revert 态）

> bridge 内部 join! 并发但 dispatch_link 直通流式 link，50074b2 的 512KiB pipe 解耦未保留；
> dispatch_link 直通串行泵（读 TLS 8KB → 写对端腿 → 循环）使两腿锁步；8sum 上行 18x 劣化原始病灶仍在。

### 1.2 现状核实（6b53cd5 方案 A 合入后）

**病灶 1「bridge_link_with_stream_full 串行泵」——已消除。**

`crates/xray-transport/src/bridge.rs:288-433` 现为方案 A 四块解耦泵：

| 证据 | 行号 | 内容 |
|---|---|---|
| split 无锁拆半 | bridge.rs:310 | `tokio::io::split(stream)`（BiLock 已删，50074b2 锁步塌陷实证） |
| 512KiB×2 mpsc | bridge.rs:313-319 | `mpsc::channel::<MultiBuffer>(64)` 两条（≈512KiB，对齐 Go defaultBufferSize） |
| 上行 reader 只读 | bridge.rs:331-367 | `up_tx.send(mb).await` 背压阻塞在发送端，**不阻塞下行读** |
| 上行 writer 只写 | bridge.rs:369-380 | `up_rx.recv() → write_all_mb`（vectored 批写 y1yx） |
| 下行 reader/writer | bridge.rs:383-427 | 同构独立块 |
| 四块并发 | bridge.rs:429-432 | `tokio::join!(up_reader, up_writer, down_reader, down_writer)` |

串行泵签名（「读→写→循环」单腿锁步）在此结构下不存在：写背压只回压本向 reader 的 mpsc send，另一腿完全独立推进。

**病灶 2「dispatch_link 直通、pipe 解耦未保留」——非缺陷，与 Go v26.9.9 同构。**

- Go 基准（D:/Project/Xray-core，v26.9.9）：`app/dispatcher/default.go:140-143 getLink`（两对 `pipe.New`，OptionsFromContext → buffer.PerConnection 512KiB）**只在 `Dispatch`（default.go:286）里调用**；`DispatchLink`（default.go:324-327）不建 pipe，直接 `routedDispatch` 消费调用方传入的 link。vless inbound `Process` 调的正是 DispatchLink 传直通 conn link（Go inbound.go:552-598）——**Go 的 vless 链路 inbound 侧本来就直通**，解耦点在 outbound 侧泵（freedom buf.Copy / CopyRawConnIfExist）。
- Rust 现状同位对齐：`DefaultDispatcher::dispatch`（xray-app-dispatcher/src/default.rs:987-993）恒建两对 `pipe::new_with_option(limit = policy.buffer.connection)`（512KiB，同 Go getLink）；`dispatch_tagged`（default.rs:1095-1101）同构；`dispatch_link`（default.rs:1131+）不建 pipe、spawn handler——**与 Go DispatchLink 语义逐行对应**。vless server（xray-proxy-vless/src/inbound/server.rs:345-347）走 dispatch_link 直通 split link = Go vless Process 同构。
- research-cpu §1.2:119「dispatch_link 直通根因 = 同形态」是方案 A 之前的推断性解读，其成立前提（bridge 泵串行）已被 6b53cd5 移除。

**残留串行段：0。** Go 同床新基准实测 up 1.27-1.58 vs Go 1.19-2.77 同层（6b53cd5 commit 记录，v5fw 裁决），无劣化证据。

### 1.3 判定

**a) 完全覆盖 → 建议关票。** 票面两病灶分别被方案 A（bridge 泵）与 Go 语义对齐核实（dispatch_link 直通）覆盖，无残余落地项。建议附注：`gjfs-b`（research 表中的 txno 入口 splice 激活）不随本票关闭，其等价工单为 6odi 防护修复 + 后续激活接线票。

## 任务 2：6odi splice handoff race（Go f926ee4a 移植）

### 2.1 Go 原始修复（f926ee4a，2026-03-22，issue #4878）

`proxy/proxy.go WriteMultiBuffer`：
- 修复前：`inbound.CanSpliceCopy = 1`（session 共享指针）在 write **前**置位 → CopyRawConnIfExist splice 泵立即开写同一 TCP fd，与 VisionWriter in-flight 写并发 → SSL out-of-order。
- 修复后：只记 `spliceReadyInbound`，`w.Writer.WriteMultiBuffer(mb)` 完成**后**才置 1；并删除 CopyRawConnIfExist 的 1ms Sleep workaround。

### 2.2 Rust 现状盘点（改动前）

| 层 | 状态 |
|---|---|
| splice 状态载体 | `AccessContext.can_splice_copy: i32` 值快照 → freedom dial 时拷进 `InboundSpliceMeta`（xray-proxy-freedom/src/dispatcher.rs:386-391）→ task-local `INBOUND_SPLICE` → DialBridge 一次性准入（xray-app-dispatcher/src/default.rs:1796-1806）。**无共享可变状态，Go 形态的跨 goroutine race 前提不存在** |
| vless 激活路径 | **未接通**：vless server AccessContext 走 `..Default::default()`（server.rs:338-344）→ `can_splice_copy = 0` → 准入恒 false（nevn/激活接线未做）——context 预判成立，6odi 按防护性修复落地 |
| VisionConn 写侧 DIRECT 切换 | **同形反模式**：判定点（vision_conn.rs 改动前 :369-374）在 pending 帧写入前即 `raw_fallback = Some(...)`——与 Go 修复前「先设标志后完成 write」同形。生产当前无并发写者（txno 泵单写者 + 泵写序隔离），故无活体 bug，但 poll_flush/poll_shutdown（改动前 :380-396）在 in-flight 窗口内会走 raw 腿——未来重构（如把 raw 检查挪到 pending 写之前）或 nevn 接线后即成真 race |

### 2.3 修复（约 25 行 + 测试 2 个）

`crates/xray-proxy-vless/src/encryption/vision_conn.rs`：

1. struct 新增 `splice_armed: bool` 挂起标志（:89-94）。
2. poll_write DIRECT 判定点：`raw_fallback` 赋值 → `splice_armed = true`（:371-378，激活不再提前）。
3. pending 帧两个写完返回点（:298-301、:313-317）返回前调 `arm_splice_raw()`——真正激活延迟到 write 完成。
4. 新增私有 `arm_splice_raw()`（:173-185）：消费 armed 标志 take raw_tcp / clone inner（`is_none()` 防与读侧激活重复）。

读侧 poll_read 不动（其 DIRECT 切换在帧完成后才切，改动前即对齐 Go XtlsRead 顺序语义）。

### 2.4 测试（红绿 + 写序契约）

| 测试 | 断言 | 红绿 |
|---|---|---|
| `splice_activation_deferred_until_write_completes` | DIRECT 帧 in-flight（duplex(1) 背压 Pending）时：`splice_armed=true` 且 `raw_fallback=None`；poll_shutdown 探针走 inner；raw 对端零字节零 EOF | 改前：判定点即激活 → shutdown 走 raw → 对端 EOF → **红**；改后绿 |
| `splice_raw_write_only_after_direct_completes` | 判定前零激活 → write 完成即激活（armed 消费干净）→ 后续写全走 raw 明文直传 | 写序契约（验收 3），锚定切换时点 |

红绿复现：物理回滚验证记录见 §4。

## 3. 验证

```
# 修复态：crate 全量 lib 测试
$ cargo test -p xray-proxy-vless --lib    # cmd /c buildenv
test result: ok. 233 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

# 模块级（vision_conn 旧 9 + 新 2）
$ cargo test -p xray-proxy-vless --lib encryption::vision_conn
test result: ok. 11 passed; 0 failed
```

验收 2（改的 crate 范围全绿）✓；验收 1 之 6odi 红绿 ✓（§4）。
验收 3（splice 激活路径写序契约）：`splice_activation_deferred_until_write_completes`
把激活时序做成可断言契约（判定→armed 置位、raw 通道未激活、in-flight 期间
poll_shutdown 探针不得走 raw、对端零字节零 EOF）；`splice_raw_write_only_after_direct_completes`
锚定写序（写完成点激活 + 后续写全走 raw 明文）。vless→splice 泵的端到端激活
路径仍未接通（nevn 未做，server AccessContext can=0），本契约守在激活真正
发生点（VisionConn 层），nevn 接线时直接受保护。

## 4. 红绿复现记录

1. 修复态：两测试绿（233/0）。
2. 物理回滚：`git diff > patch && git checkout -- vision_conn.rs`（仅本文件，不动他人改动）。
3. 红票复现：patch 恢复后判定点临时还原旧激活逻辑（`raw_fallback = raw_tcp.take()...`
   直接置位，等价改动前代码）→ `cargo test ...splice_activation_deferred`：
   ```
   panicked at vision_conn.rs:788: assert!(server.splice_armed,
       "DIRECT judged but not armed")   ← 契约断言在旧逻辑下立即抓到
   test result: FAILED. 0 passed; 1 failed
   ```
4. 恢复新逻辑 → 复跑：233 passed / 0 failed（红→绿闭环）。
5. 临时 patch 已清理。

## 5. Side-effects

- 触碰文件：`crates/xray-proxy-vless/src/encryption/vision_conn.rs`（唯一）。
- 公共 API：无变更（`splice_armed`/`arm_splice_raw` 均私有）。
- 行为变化面：仅「DIRECT 判定后、pending 帧写完前」窗口内的 poll_flush/poll_shutdown 改走 inner（语义更正确）；生产桥泵路径 write_all 不触发 flush，桥尾 shutdown 时 pending 已排空——行为不可见。
- 禁区核对：未动 bd 票（只读）/ws-httpupgrade/xray-transport-tcp/register.rs/stash。

## 6. commit 粒度建议

1. `fix(vless): splice 激活延迟到 write 完成（Go f926ee4a 移植，bd 6odi）` — vision_conn.rs 全部改动。
2. `docs: D-6a 链式报告（gjfs 判定 a + 6odi 落地）` — 本文件。
3. gjfs 建议关票（附 §1.2 行号证据），由上级执行 bd close。
