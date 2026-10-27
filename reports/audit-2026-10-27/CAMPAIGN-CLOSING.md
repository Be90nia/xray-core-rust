# 能力收敛战役 · 收口与复盘（2026-10-27）

> 范围：`feature/framework` 分支，能力收敛方案（六面 + C 面）全波落地。
> 本文件是**收口账**：交付、验收、遗留、以及本次在流程上踩的坑（供下次复用）。

---

## 1. 交付（19 个 commit，全部已 push）

| # | commit | 内容 |
|---|---|---|
| 1 | `377c712d` | CLAUDE.md §3.5.5 ADR-1/ADR-2 入宪（能力归属三判据）|
| 2 | `1679a5a7` | W1 xray-frame 六件派生件（compat/redline/scope/Budget/HotLog/XrayConfigLayers）+ 7 测试 |
| 3 | `d3c43a61` | tracing 批 2a（tuic/anytls/trojan/hysteria 109 处）|
| 4 | `96483e8f` | tracing 批 2b（wireguard/tun/freedom/vmess 90 处）|
| 5 | `888c6b8f` | L3 台账（dispatcher/kcp/splithttp 禁令 + 43 站点）|
| 6 | `b085ff97` | W3a 底层时钟 → udf `SystemClock`（9 站）|
| 7 | `4ec2f28c` | W2 配置装配 → `XrayConfigLayers`（影子三路 0 差异 + Go 12/12 全等）|
| 8 | `7d71a6c6` | W3b 上层时钟 → `compat::clock`（64 站，删 allow 40）|
| 9 | `8a200d7b` | W6 热路径日志 → `HotLog`（40 站，40/40 消息逐字保留）|
| 10 | `0e6b4a4b` | 基准校准（性能门判定纪律）|
| 11 | `5baf33cd` | W6 漏跑 fmt 补修 |
| 12 | `99a0eb16` | 基准校准更正（锚可达 vs 污染读数）|
| 13 | `bb7b54eb` | W5 tokio 预算（34 站 = 迁 22 + 例外 12）+ **栈足迹回归修复** |
| 14 | `b46d6058` | W4 任务归 scope（inbound/mux/DNS；含 4 处栈修正、redline 全路径）|
| 15 | `554377d7` | C-R1a `SimpleOhm` → udf `BoundedRegistry` |
| 16 | `d3a756a0` | 基准校准定稿（同二进制跨窗 20% 漂移）|
| 17 | `12a3ff2b` | C-R2 kcp retry → udf `std_ext::retry`（4 面中唯一契合件）|
| 18 | `23769fa0` | W7 红线受控入口接线（`redline_sites` 门 3/1 → 4/4）|
| 19 | `073870b5` / `af221b91` | Cargo.lock 漏带补齐 / CHANGELOG |

## 2. 融合度终账：**14/14**（口径见方案 §10.1）

- 框架六面 W1-W7 全落；C 面 R1a/R1b（`InboundRuntime` 早已在 `fe8d5481` 迁完）/R2/R3 收口
- **显式豁免 1 项**：DNS `cache_controller` 留主仓（ADR-1 判据③逐条举证：DNS 方向件 + Go 语义逐字对齐 + 热路径并发面）
- **分布型残余（机制性，不可归零）**：per-crate `clippy.toml` 55 份 + 测试面 361 条豁免
- 台账权威口径：**568 = 生产 207 + 测试 361**（旧记 "458" 是 outer 且生产/测试混算）；本战役清 **−55**（496→441）

## 3. 验收证据（全部可复跑）

| 门 | 结果 | 位置 |
|---|---|---|
| workspace clippy `-D warnings` | 0 error（多次）| — |
| 各面测试 | 全 0 failed（合计 4000+ 用例跨面）| 各波报告 |
| fmt 全仓 | clean | — |
| `redline_sites` 四门 | 4/4 | — |
| 本地互操作矩阵 | **12/12**（6 协议 × 双向，最终二进制）| `tmp/interop_final.py` |
| **真机 93 节点 + Go 对照** | Rust **72/93** vs Go **64/93**，**仅 Rust 失败 0** | `32-32-acceptance.md` · `32-32-control-diff.md` |
| 性能 | 各波同窗交错 A/B Δ 在噪声内 | 各波报告 |

## 4. 遗留（bd 票，均不阻塞发布）

| 票 | 内容 |
|---|---|
| `9doy9` | `HotLog::enabled` 每调用持锁 124ns（vs 旧宏 16ns）→ level 快照改无锁原子读 |
| `pdm1q` | xicmp/system_listener 8 处裸 tracing（336d8430 引入，晚于清单）|
| `mzput` | `ConnScope::child_of` 每连接 20ms 父闸轮询（≈50 唤醒/s/连接）→ 改 close-notify |
| （本日新开）| R3 台账纯度 5 项（过期 reason / 缺 reason= / 文件级 allow 该收窄 / 注释数字）|
| （本日新开）| **REALITY 零本地覆盖**：本地矩阵 6 协议不含 reality，真机 12 个 reality 节点两边全失败 → 补 reality 双向用例 |
| `n539c` | udf 缺口汇总：`BoundedRegistry` 缺 `Borrow<Q>`/`Clone`/`get_mut`；`retry` 是同步域（async 面 3 处不可收敛）；`cache` 单线程 `&mut self`；`IdGen` 是 v7 确定性（凭据面不可换）|
| `39hko` | FxScope 收口残余（生产 spawn 待迁 **123 处**，含 dispatcher/kcp/splithttp 直连 udf 的路径） |

## 5. 复盘：本次踩的坑（按代价排序）

### 5.1 代理存活：**6 任代理因 provider 429 死亡 + 3 次误杀/重启**
- 代价：累计约 **3 小时**代理工时；每次丢的是**内存上下文**（磁盘半成品都在）
- 有效对冲：**磁盘半成品 + 转录指针**（`history://<agent>`）。新代理契约里带"前任转录指针 + 半成品 mtime 分桶"后，续跑恢复得很快（W4/W5 各 1.5 小时的审计/盘点成果没浪费）
- 教训：**代理的"过程产物"（审计结论、census 清单）必须落到报告或可读转录**，否则一死即失

### 5.2 PM 误判三次
1. **误杀**（用户说"等会 kill"我当成"立刻"）→ 教训：**时间窗口类指令必须复述确认**（"到点我自动执行，现在不动"）
2. **W6 验收漏跑 fmt 门** → 只跑了 check/clippy/test，漏了 fmt，导致已入库文件带 3 处 rustfmt 差异（CI 会红）。发现者是下一个代理，不是我
3. **台账口径错**（我用单行正则得 228，实际 568）→ 正则口径类统计必须用**多行感知**脚本，且要交叉验证

### 5.3 契约漏洞（已修，写进新纪律）
1. **`CARGO_TARGET_DIR` 撞名**：共享 context 块写死 `target-w2` 给三个代理 → 必须**全局唯一**（`target-<AgentName>`）
2. **框架层波次未隔离自验**：W1 的 15 error 中间态挡住两个无关波次的门 → **框架层（xray-frame/udf）必须先隔离自验绿再合共享树**
3. **性能测量窗口污染**：并发编译压低 loopback 约 20%；且**同一二进制跨窗也能差 20%** → 定稿纪律：当场交错 A/B + 窗口内禁编译 + 进程快照取证 + A/B 混杂即作废
4. **`Cargo.toml` 改依赖未同 commit 带 `Cargo.lock`**：两次发生（W3a、C-R2）→ 已沉淀 `rules/rust-dependencies.md`

### 5.4 技术上有价值的发现（都已沉淀进 `rules/rust-pitfalls.md`）
1. **async-fn 超时会撑爆栈**：`BudgetDeadline::timeout`（async-fn）在巨型 future 内加厚栈帧 → 2MiB 栈 `STATUS_STACK_OVERFLOW`；**构造式 `deadline::timeout(fut, remaining())`（具名 `Timeout<F>`）是默认正确形态**。这是"单测全绿、e2e 必炸"的类型
2. **字面量扫描型 CI 门对 `use ... as` 别名隐形**：受控入口必须**全路径调用**，否则整文件对门不可见（空集合直接放过）
3. **clippy `disallowed-methods` 的 def-id 规则**：`tokio::spawn` 与 `tokio::task::spawn` 同 def-id（双登记去重、每站点只报一次）；`std::time::Instant::now` 与 `tokio::time::Instant::now` 是不同 def-id（必须分列）；`spawn` 不命中 `spawn_blocking`；**路径写错 = 静默 no-op**（必须探针验证真拦截）
4. **bindgen `LIBCLANG_PATH` 在 bash 下要反斜杠形态**（`D:\Program Files\llvm\bin`）；且"编暖后 build script 不重跑"会造成**假绿**
5. **验收门用了外部站点做 marker 时**：外部不可达会导致"全红"，先做控制实验（直连探活 + 服务端是否已 dispatching），再换可达判据——否则会把环境问题误判成代码回归

## 6. 一句话总结

**六面 + C 面全落（14/14），19 commit，零代码回归**（真机 93 节点：Rust 72 vs Go 64，仅 Rust 失败 0）；**今天的真成本不在写代码，而在"代理反复死亡 + 验收口径不断自我更正"**——后者反而是最有价值的产出（4 条纪律、5 条技术沉淀、2 次基准文档自我更正）。

— PM · 2026-10-27
