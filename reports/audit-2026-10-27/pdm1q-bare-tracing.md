# pdm1q — xicmp / system_listener 8 处裸 tracing 收敛统一入口

VERDICT: PASS

- bd 票：`Xray-core-rust-pdm1q`（xicmp.rs 1 + xicmp_sock.rs 3 + system_listener.rs 4 = 8 处，336d8430 引入，晚于 T3.2a 37 站点清单）
- 全部 8 处走**统一入口迁移**（首选路线），零处走 allow+登记豁免 → 无需动红线台账，调用集合 ⊆ 登记集合不变
- 事件形参零改动：字段名以 `key=value` 前缀保留、消息文本逐字保留、level 逐字保留；仅调用入口变更
- target：门面（`LOG`/`HOT_LOG`）构造期钉死为域规范 `xray_frame::transport`（T3.2a 契约）——裸 `tracing::` 的模块路径 target 随统一入口消失，与 W6 已登记的 target 规范化后果（w6-hotlog.md §6 风险 #4 splithttp 同款）一致

## 1. 8 站点 before/after 对照

| # | 站点（file:line 改后） | 面 | before | after |
|---|---|---|---|---|
| 1 | `finalmask/xicmp.rs:393`（`spawn_recv_task` recv Err 臂） | 错误面（读错即退出，一次性） | `tracing::warn!(error = %e, is_client, "xicmp: raw socket recv failed, closing")` | `crate::hot_log!(tracing::Level::WARN, "error={e} is_client={is_client} xicmp: raw socket recv failed, closing")` |
| 2 | `finalmask/xicmp_sock.rs:184`（`degrade_v6`，bind 期至多一次） | 系统面 | `tracing::warn!(error = %err, role, "xicmp: IPv6 socket unavailable, degrading to IPv4-only; …")` | `crate::LOG.warn(format!("error={err} role={role} xicmp: IPv6 socket unavailable, degrading to IPv4-only; IPv6 destinations will fail"))` |
| 3 | `finalmask/xicmp_sock.rs:294`（unix `IcmpSock::recv` 畸形 IPv4 头丢帧臂） | 每帧**条件**分支（畸形才触发） | `tracing::debug!(bytes = n, "xicmp: dropped frame with malformed IPv4 header")` | `crate::hot_log!(DEBUG, "bytes={n} xicmp: dropped frame with malformed IPv4 header")` |
| 4 | `finalmask/xicmp_sock.rs:420`（OS 线程 `recv_loop` 畸形帧丢帧臂） | 每帧**条件**分支 | 同 #3 before | 同 #3 after（hot_log 同步安全：栈缓冲、无 async 依赖，裸线程内可用） |
| 5 | `system_listener.rs:796`（SO_PEERCRED 成功，每 UDS 连接一次） | 连接级 | `tracing::debug!(pid = cred.pid, uid = cred.uid, gid = cred.gid, "uds peer credentials (SO_PEERCRED)")` | `crate::LOG.debug(format!("pid={} uid={} gid={} uds peer credentials (SO_PEERCRED)", cred.pid, cred.uid, cred.gid))` |
| 6 | `system_listener.rs:801`（getsockopt 失败） | 连接级错误面 | `tracing::debug!(error = %io::Error::last_os_error(), "uds peer credentials unavailable: SO_PEERCRED getsockopt failed")` | `crate::LOG.debug(format!("error={} uds peer credentials unavailable: SO_PEERCRED getsockopt failed", io::Error::last_os_error()))` |
| 7 | `system_listener.rs:810`（非 Linux/Android 平台无 SO_PEERCRED） | 连接级 | `tracing::debug!("uds peer credentials unavailable: SO_PEERCRED not supported on this platform")` | `crate::LOG.debug("uds peer credentials unavailable: SO_PEERCRED not supported on this platform")` |
| 8 | `system_listener.rs:873`（UDS 权限缺省 0700 提示，bind 期一次） | 系统面 | `tracing::info!(path = %socket_path.display(), mode = %mode_str, "uds socket permission defaulted to owner-only (…)")` | `crate::LOG.info(format!("path={} mode={} uds socket permission defaulted to owner-only (Go default 0777&~umask is too permissive); append ',mode' (e.g. /path,0755) to allow other local users, at your own risk", socket_path.display(), mode_str))` |

## 2. 入口选择理由（bd 票要求的逐面判定）

**判定结论：8 处无一位于无条件每包路径** → bd 票预警的「HotLog 124ns 每包开销」情形不发生，全部可迁统一入口，无需受控豁免：

| 面 | 站点 | 依据 |
|---|---|---|
| 系统面（bind 期至多一次） | #2 #8 | `degrade_v6` 仅 socket 建立时调用；权限提示在 `perm.is_none()` 分支、每次 `bind` 至多一次 |
| 连接级（每 UDS 连接一次） | #5 #6 #7 | `log_peer_credentials` 每条 accepted UDS 连接调用一次 |
| 错误/条件面（稀有触发） | #1 #3 #4 | #1 在 `Err` 臂且随即 `return`（socket 终结，一次性）；#3/#4 仅畸形帧触发（正常流零到达） |

- **#1/#3/#4 → `hot_log!`**：与 W6 迁移口径同款（udp/hub.rs recv 错误臂、finalmask/mod.rs 条件分支均走 hot_log）；`xray-frame/src/logging.rs` 模块文档明文将 finalmask「裸 `debug!` 点」列为 HotLog 设计消费面；`debug_fmt`/`enabled` 先判级别，禁用时零格式化零分配（logging.rs:317-337 亲读核实）
- **#2/#5-#8 → `crate::LOG` 慢路径**：系统/连接级站点与同文件既有 `crate::LOG.debug/warn` 先例（system_listener.rs:321/385/397/408/414）一致，走 `mask_secrets` 慢路径（安全 > 微优化，logging.rs 设计明文）
- **豁免路线不用**：`xray-transport/clippy.toml` 未禁 tracing 宏（只禁 spawn/Instant::now），8 处不构成 clippy 违规；统一入口已使「日志唯一入口」纪律闭合，登记豁免（选项二）无必要

## 3. 验收输出（实跑）

| 门 | 命令 | 结果 |
|---|---|---|
| 1. 测试 | `cargo test -p xray-transport --all-targets` | **662 passed; 0 failed; 2 ignored**（12.08s） |
| 2. clippy | `cargo clippy -p xray-transport --all-targets -- -D warnings` | **Finished，0 error**（30.07s） |
| 3. 红线门 | `cargo test -p xray-frame --test redline_sites` | **4 passed; 0 failed**（4 门全绿：ledger / escape_hatch / bare_tracing_event / spawn_observable） |
| 4. fmt | `cargo fmt -p xray-transport -- --check` | **clean**（见下方注记） |

**fmt 全仓注记**：`cargo fmt --all -- --check` 在 `crates/xray-frame/tests/zz_bench_tmp.rs` 有 diff——该文件为 **untracked（`??`）外来一次性微基准**（文件头自注「bd 9doy9，测完删除」），非本任文件面（疑似并行代理 HotLogNoLock-2 的工作文件），按文件面独占纪律未触碰。本任 3 个文件经 `cargo fmt -p xray-transport -- --check` 实证 clean；全仓门绿需该文件归属方删除/格式化后达成。

**隔离与清理**：构建/测试全程用独立 `CARGO_TARGET_DIR=target-BareTracing-2`，验收后已整体删除（实测 `TARGET_DIR_DELETED`）。

**diff 足迹**：`git diff --stat` 本任仅 3 文件（xicmp.rs 5 行 / xicmp_sock.rs 20 行 / system_listener.rs 35 行）；同树 `crates/xray-frame/src/logging.rs` 86 行改动属并行兄弟代理，未触碰。

## 4. 非目标确认

- 未改日志语义/事件字段/target 字符串/level（仅字段以 `key=value` 前缀并入消息文本，门面既有风格）
- 未动 xicmp/system_listener 业务逻辑（diff 全部为日志调用行）
- 未新增红线门规则、未动 `tests/redline_sites.rs` 与台账

## 5. 五维自评

| 维度 | 分 | 说明 |
|---|---|---|
| 正确性 | 5/5 | 8/8 站点迁移，消息文本/字段名/level 逐字保留（before/after 表逐条对照）；测试 662/0 + clippy 0 error + 红线 4/4 |
| 性能 | 5/5 | 零无条件每包站点（逐面判定表）；hot_log 禁用态零格式化零分配（源码亲读）；LOG 慢路径仅系统/连接级 |
| 可维护性 | 5/5 | 唯一入口纪律闭合，零新静态/零 alias/零豁免登记负担 |
| 风格 | 4/5 | 本任文件 fmt clean；扣 1 分：全仓 fmt 门被外来 untracked 文件 zz_bench_tmp.rs 阻塞（非本任所改，已登记） |
| 测试 | 4/5 | 全量受影响 target 测试 + 红线门实跑；纯日志调用迁移无行为变化，未加新测试（无新契约可断言） |
