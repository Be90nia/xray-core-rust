# impl-8sum-planA — bd 9al2 方案 A 实施报告（bridge 泵解耦）

> 2026-09-15 / HEAD 49262b6 基线 / 实施代理 impl-8sum-a
> VERDICT: FAIL（VPS 双向 Mbps 验收线未达标——**床退化实锤：Go 官方实现同塌**；
> 本地验收全绿；桥内解耦机制实证生效；移交建议见 §5）

## 1. 改动范围（最终态）

唯一代码改动点：`crates/xray-transport/src/bridge.rs`（未 commit，等 PM 审计）。

1. **`bridge_link_with_stream_full` 串行泵 → 4-block 解耦泵（方案 A）**
   - 4 个 async block（join! 并发轮询）：up reader / up writer / down reader / down writer。
   - 2 × `tokio::sync::mpsc::channel::<MultiBuffer>(64)` ≈ 512KiB（对齐 Go `defaultBufferSize`）。
   - reader 阻塞 `send().await` 不抢对向时间片；writer 仅 `recv()` 消费。
   - 超时语义逐行等价原串行版：`conn_idle` + done watch 半关闭限窗（activity 重置）。
   - 级联退出：writer 死 → mpsc rx drop → 对向 reader send Err → done watch 传播 half_window。
   - 瞬时写错只关本向（绝不 shutdown 对向，50074b2 教训）。

2. **stream 拆分两轮迭代（均 VPS 实测仲裁）**
   - v1 保留自研 BiLock（为 vectored 窥探）→ 1.58Mbps 塌；strace 锁步签名。根因=join!
     固定轮询顺序下 up 大流量系统性抢锁饿死 down_reader（与 50074b2「BiLock 竞争塌陷」同源）。
   - v2（最终态）：`tokio::io::split`（out_f1 33Mbps 实证拓扑，无锁）。BiLock 全家删除
   （dead code 清零）。splice 桥（cfg(linux)）同步换 split + up_done_tx 声明修复
   （Windows 编不到该分支，容器 Linux 侧暴露——cfg 门控代码必须容器复验的老账第 N+1 例）。

3. **y1yx 保留**：`write_all_mb` vectored 批写（IoSlice 栈数组批 ≤8 对齐 Go readv 上界，
   `write_vectored`+`advance_slices` 推进循环处理部分写）。生产经 tokio WriteHalf 透传
   `poll_write_vectored`/`is_write_vectored` 到 TCP writev。

4. **禁做项核查**：无编译级优化混入；readv 基建未动（down 走 SingleReader 顺序读=
   out_f1 实证拓扑，readv 重接属 bd 2o9l 专项）；未用 crossbeam；未动 wire-format/
   dispatcher/splice 激活/register.rs/ws 指纹。`+ 'static` bound 加入
   `bridge_link_with_stream_full{,_default}`（new_reader 要求；全部调用点传 'static
   类型，workspace 编译证明无破坏）。

## 2. 本地验收（全绿）

| 契约项 | 命令 | 结果 |
|---|---|---|
| 1 | `cargo test -p xray-transport --lib` | **518 passed / 0 failed**（基线 514 + 新增 4） |
| 2 | `cmd /c buildenv.bat cargo test --workspace --lib` | 45 crate 全 ok 0 failed（hysteria 首轮 1 failed 为 flaky，复测 217/0；首轮 btls LNK1120 是自卷 PATH 缺 BORING_BSSL env，换 `D:\tmp\buildenv.bat` 消除——非代码问题） |
| 4 | `python dist/run_full32.py`（新构建 dist/xray.exe） | **32/32 PASS 0 FAIL 0 PARSE** |
| 5 | 桥语义单元测试 | `up_write_err_keeps_downlink` / `down_write_err_keeps_uplink`：写错只断本向，对向 2s 内照常送达，全桥 5s 收敛 |

新增 4 测试：上述 2 条 + `bridge_stream_full_uplink_survives_slow_remote`（解耦回归门）
+ `write_all_mb_vectored_batch_write`（3 buffer 聚合单次 poll_write_vectored）。
既有超时语义测试 3 条不改一行全过 = 行为等价证据。

## 3. VPS 实测记录（全部真实输出）

床：199.115.231.188 / netem `delay 161ms loss 1%` on lo（RTT 322ms）/ 单核 512MB。
床脚本重部署 /tmp/r2/（原目录丢失）；二进制 md5 三端一致。

**32MB 稳态长轮（最终仲裁矩阵）**：

| 配置 | up 实测 | 备注 |
|---|---|---|
| **Go 26.9.9 官方构建**（xray-go-build 容器 GOTOOLCHAIN=auto，version 已验） | **1.19 Mbps** | dur=226.3s；历史参考 19.8 |
| **Go 26.9.9 换端口**（29901/22001/11003） | **2.77 Mbps** | dur=97.0s；仍差 19.8 达 7 倍 |
| Rust 方案 A（split 版） | 1.27 Mbps | dur=211.7s |
| Rust 方案 A 换端口 | 1.58 Mbps | dur=169.5s |
| Rust 旧 base 文件（来源存疑） | 1.18 Mbps | dur=227.3s；历史记录 3.1-3.3 |
| **裸 TCP 对照**（同 netem） | **70.87 Mbps** | dur=3.8s；床物理层健康 |
| Go 8MB 短轮 / Rust 8MB 短轮 | 5.65 / 1.48-2.16 | 慢启动相位，非稳态 |
| loss 0% 对照（Rust） | 1.65 Mbps | 排除重传因素 |

**判定：down≥15/up≥16 未达标，双向验收 FAIL——Go 官方实现同塌（1.19-2.77 vs 历史
19.8，差 7-17 倍），床退化实锤，当前床上该验收线对任何实现客观不可达。**

## 4. 根因分析（实测证据链）

1. **v1 塌陷**（BiLock）：join! 固定轮询顺序 + up 高频 poll 抢锁 → down_reader 系统性
   饥饿。strace GAP 全部 0.3217s。已修（换 split）。
2. **v2 仍塌但已与 Go 同层**：ss 连拍显示 client→server Send-Q 卡 106KB 饱和、
   server 20001 Recv-Q=0、传输期全进程 0% CPU（环形睡眠非计算瓶颈）。
   **Go 链 ss 铁证：`rwnd_limited:97.7%`、`snd_wnd:85KB`、`rcv_ssthresh:96KB`**——
   Go 与 Rust 同受 **TCP 接收窗死锁**（窗 64-85KB/RTT = 1.2-2.6Mbps，与实测精确吻合）。
   机制：rcvbuf default 128KB + 转发应用消费过快（rustls 64KB fill_buf limit / Go
   读即空）→ rcvbuf 从不积压 → DRC 无扩窗信号 → 窗恒定。裸 TCP 70Mbps（收发模式给足
   DRC 信号）反证床物理层无碍。
3. **桥内解耦机制已生效**：读侧不再被写背压锁步（v1 修复后 strace 从「avg 9.5ms 突发
   +1RTT 停」变规整步进=纯 TCP 窗行为）；级联退出/写错不断向有单测背书。
4. **历史数字不可复现**：Go 19.8 / base 3.1 / out_f1 33 当前床全部不可达。历史横向
   差距（18x/6x）在当前床不可比，8sum 原始定罪数据需床修复后重取。

## 5. 移交建议（需 PM 裁决）

1. **床仲裁已闭环**（Main 裁决 A 执行完毕）：Go 官方同塌 → 分叉 B 成立——床退化。
   修复方向：VPS 供应商层排查（宿主迁移/内核升级史/sysctl 隐藏差异）或换床。
2. **8sum 票**：桥内解耦代码（本地全绿+机制实证）可保留为 9al2 部分成果；双向 Mbps
   验收线在床修复前挂起；**禁在当前床上做任何实现间吞吐对比结论**。
3. **窗死锁开独立票**：候选修复=server inbound listener 显式 SO_RCVBUF（≥BDP 1.3MB）
   或应用层预读蓄水。rustls 64KB fill_buf limit 是放大器非根因（Go 无此 limit 同样死锁）。

## 6. 环境副作用

- 已执行：xrbuild /src 同步+3 次 release 构建；xray-go-build /xs 构建 Go 26.9.9；
  VPS /tmp/r2 床脚本与三份二进制部署；netem 重建+端口移位配置；dist/xray.exe 刷新。
- 未动：master 分支（未 commit）；VPS netem 已恢复 `delay 161ms loss 1%` 标准态。
- VPS 测试产物：/tmp/r2/out_*（各轮日志/trace/ss 采样）。

## 7. 沉淀

- bd remember [rust-tokio-bilock-guard-poll-join-task-poll]：BiLock 轮转锁在 join!
  固定轮询顺序下的系统性饥饿机制与修复。
- bd remember [tcp-min-rtt-ss-send-q-recv-q]：转发代理窗死锁诊断法（双腿 ss 连拍 +
  CPU 0% + 裸 TCP 对照 + loss 0% 对照四步）。
- run_full32 必须先刷新 dist/xray.exe（老坑再次验证）。
