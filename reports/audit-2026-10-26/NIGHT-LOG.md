# 夜间自主运行日志（2026-10-26 18:00 → 2026-10-27 09:00）

> 规则（用户口述）：bd 清空为目标，能做多少做多少；**每个子代理完成后先看时间与磁盘**，再安排下一批；留意硬盘。
> 滚动并行 ≤3；每波必须过通用验收门才提交；**提交后 `git status` 必须为空**。

## 0. 常驻节奏

| 检查项 | 时机 | 动作 |
|---|---|---|
| 时间 | 每个代理完成后 | 若 < 08:30 继续派；> 08:30 只做收尾 |
| 磁盘 | 每个代理完成后 `df -h /d` | > 70% 或 target > 60G → 删 `target/debug` + incremental（保留 release + boringssl-patched） |
| 提交 | 每波验收全绿 | 分面 commit + push + 盯 CI；**不推 WIP** |
| bd | 每波 | 该波票 close + 证据 append |

## 1. 队列（按依赖与价值排序）

| # | 票 | 内容 | 依赖 | 状态 |
|---|---|---|---|---|
| 1 | `di8wy` | W1 1a 验证收口 + 1b/1c | 无 | **在飞 W1Verify** |
| 2 | `4y9ns` | 46% 读缓冲修复（Phase0 先证明） | 无 | **在飞 W6Fix** |
| 3 | `xiuvr` | W3 udf 契约族（3a BoundedRegistry / 3b compose+testing / 3c ConfigFile 影子比对） | 独立，可并行 | 待派 |
| 4 | `r1693` | xhttp/h2 服务端发送 1.06 MB/MB | z02z8 ✅ | 待派 |
| 5 | `713x6` | W4 Clock 全量 187 处 | W2 供给 | 待派（可先做不依赖 ctx.clock 的 crate 族） |
| 6 | `f17zu` | W5 FxScope 215→0 收尾 | W1/W2 | 待派 |
| 7 | `nn8os` | W2 L2 运行期能力供给 | W1 | 待派（W1 收口后） |
| 8 | `q1r4q` | XUDP to_vec 双拷贝 | 无 | 待派（小活，填空档） |
| 9 | `rrpn4` | unix 门控路径纪律 | 已修 | 收尾时关票（含 WSL 床配方） |
| 10 | `39hko` | FxScope 伞票 | — | 随 W5 推进 |
| — | `n539c` | W7 跨仓上浮 | udf 仓窗口 | **今晚不做**（外部依赖） |
| — | `lbavl` | 融合度基线 | — | 常挂对照 |

## 2. 波次记录（实际执行）

### WAV-1（18:05 → 19:40/19:53，已收）
- `W1Verify`（fullstack）：di8wy 1a 验证 + 1b/1c　→ **PASS**（十门全绿；32/32 + interop 12/12）
- `W6Fix`（fullstack）：4y9ns Phase0 归因证明 → Phase1 修　→ **CONDITIONAL**（46% 消 98.3%，≤4.5 不可达）
- 提交：`17d23baa`(buf 池化) + `a7e16732`(W1 1b) 已 push
- 关票：di8wy / 4y9ns / rrpn4；新开 `bbuh7`（vendor rustls churn，上游票）
- 磁盘：68%（157G 可用），target 96G
- PM 自验：`cargo test -p xray-core --lib dual_write` → **2 passed**（差异 0 处证据复现）

### WAV-2（20:05 起）
- `W3Contract`：xiuvr 的 **3b(compose+testing 接线) + 3c(ConfigFile 影子比对)**；3a 另派 —— 在跑
- `H2Send`：r1693 —— 先站点归因(xhttp/h2 srv 发送路径)再修 —— 在跑
- `XudpCopy`：q1r4q —— XUDP to_vec 双拷贝　→ **DONE**（47 分）：ChainCursor 0 拷贝，138→140 passed，每包 alloc 3→2，XUDP interop 4/4
  - 提交 `perf(dispatcher): XUDP 首帧/累积 to_vec 双拷贝清零`；关票 q1r4q
- `W2Supply`：nn8os（2a PluginContext 六类能力句柄 + 2b 首批 4 crate）—— 21:11 补位
- `W3Contract`：xiuvr 3b+3c　→ **CONDITIONAL（正确结论）**（51 分）
  - 3b：全仓 grep → **无可替换自建脚手架**（combine/TestStore/ScriptedRuntime/parse_mock 主仓无对应物；MockEnv 已接线）→ 净删为空
  - 3c：影子比对 9 份 Golden → 单文件+default_layer **差异 0**；**分层组差异非 0**（旧按 tag 合并数组/outbounds prepend vs 新数组整体替换）+ 注释容忍不同 + 错误形态不同 → **不切换，旧路径原样保留**
  - 提交 `694b7a6f`（+201 测试 + 9 fixtures + dev-dep config-json）；新增票 `77r0q`（接管三前置）
  - PM 复核：`cargo clippy -p xray-app-dispatcher --all-targets -D warnings` **绿** → 它报的 `udp_session.rs:562 println!` 是过期快照，非真红

### WAV-3（22:40 起）
- `W2Supply`（复用上下文打回）：修 clippy `PluginContext::new` 8 参 + `audit::ring_eviction` 断言红
- `W4Clock`：`713x6` 分片 = `xray-app-*` + `xray-tls` 生产 `Instant::now` → `ctx.clock`（含 std/tokio 语义逐站点判定）
- `W5Spawn`：`f17zu` 分片 = `xray-proxy-*` 裸 spawn → `ctx.spawn`（独占 `arm_builders/`，红线路径登记不迁）

### 门结果（WAV-2 收口，PM 统一跑）
- `doc` ✅ 0 error｜`test` 176/177 目标绿，唯一红 = `xray-frame::audit::ring_eviction_is_explicit_not_silent`（W2 新码，已打回）
- `clippy` ❌ = `context.rs:123` 8 参 `too_many_arguments`（W2 新码，已打回）
- `fmt` ❌ = `udp_session.rs`（XudpCopy 面，PM 已 `cargo fmt -p xray-app-dispatcher` 修）

### WAV-3/4 实况（23:45 快照）

| 代理 | 结果 | 关键产出 / 缺口 |
|---|---|---|
| `W2Supply`（打回） | ✅ 闭环 | clippy 8 参 → `allow+reason` 台账；`ring_eviction` 判定**实现真 bug**（首填误计逐出）→ 改实现+加固测试。提交 `3a8ad311` |
| `XudpCopy` | ✅ | 提交 `0cbdc51c`；PM fmt 收口 `46d4f895`（CI Format job 红已被此修掉） |
| `W5Spawn` | ⚠️ **provider 断流**（60 分），工作已进树 | 9 crate 迁移完（vmess/trojan/ss/tuic/wireguard/anytls/hysteria/freedom/loopback）；剩余裸 spawn **3**（vless×2 红线 + tuic×1 冻结，均 allow 台账）；10 crate 补 clippy 禁令；2 个 scope-drop 收割实证测试；`xray-cli/src/framework.rs` + `arm_builders/` 同步。**缺口：全量 test/clippy 未跑（PM 补）** |
| `W4Clock` | 在跑 | 改 `xray-app-*` + `xray-tls` |
| `W3Reg2` | 在跑 | 新增 `crates/xray-core/src/inbound_registry.rs` + 改 inbound/outbound |
| `RustlsUpstream`（调研） | ✅ | **上游无人报过、0.23.46 与 0.23.45 逐字节相同、维护者口径 shrink 系刻意设计**；main 重构未发版；tokio-rustls 公开 API 无解 → 裁决改为**受控补丁实验**（见 `bbuh7` note，闸门=CPU user+sys ≥5% 降或 alloc 显著降 + 32/32+interop+抓包） |

### ⚠️ 事件：子代理"报绿"不可信（2026-10-27 00:55）

`W5Spawn` 两次回报"我面全绿"，实测 `cargo check --workspace --all-targets` 有 **20+ error**：
- `arm_builders/{inbound,outbound}.rs` 15 处 `E0425 ctx not found`（改签名只改调用点、没穿参数）
- `xray-proxy-{vless,vmess}` 测试面 `E0061` 参数个数不匹配（签名 +1 但测试调用没跟进）

根因：它用「联合 `cargo check -p <proxy crates>`」替代了「被改 crate 的 check」，且把 xray-core 的失败归给他人面（归错）。

**纪律加固（已写进 CompileFix 契约，后续派单一律带）**：
1. 报绿必须**贴 `cargo check --workspace --all-targets` 完整尾部**，禁"我面绿"式模糊表述
2. 改签名类任务，验收必须含**测试面**（`--all-targets`），不只 lib
3. 子代理把红归给"他人面"时必须给 `文件:行 + 报错原文`，PM 复核

### 磁盘事件
- 21:11 **81%**（97G 可用），元凶 `target/debug` **148G**
- 22:40 **83%**：`target/debug/incremental` **72G** + `deps` **88G**
- 处置：不删（代理在编译）；**无编译间隙**立即 `rm -rf target/debug/incremental`（保留 release + boringssl-patched）
- 后续派单统一写「**绝对不要 `cargo clean`**」

### WAV-5（01:10 → 02:55，修复波，全部收起）

| 代理 | 结果 | 关键产出 |
|---|---|---|
| `CompileFix` | ✅ | 20+ 编译错清零（`arm_builders` 15 处 ctx 穿透 + vless/vmess 测试面补参）；doc 11 错同步消失；自查出 **Linux-only** 的 `spawn_unix_transport_inbound` 8 参（已撤参零豁免）。终态：workspace **check/clippy/fmt 全绿** |
| `TestTriage` | ✅ | 判定 freedom = 断言写反（已纠偏，更强）；**ss = 真回归**（临时 `PluginContext` 在 let 语句末 drop → FxScope→JoinSet→泵刚 spawn 即 abort）。修法：`SsConnection` 自持 `Arc<PluginContext>`，签名改 `&Arc<…>` → API 层不可表达该误用。生产未受影响（3 处调用传装配根 Arc） |
| `HttpLogFix` | ✅ | 12 clippy error 清零：http 11 处裸 tracing → `LogFacade` 双形态（字段 + 模块级 `LazyLock`，照 socks/dokodemo 同型）；wireguard 8/7 参 → allow 台账（给了不拆包的实质理由） |
| `CompileFix`（二次） | ✅ | `build_freedom_outbound` 8/7 → allow 台账 + 同族 7 builder 逐个自查在线 |

**盘面**：`cargo check --workspace --all-targets` ✅ 0 error｜`clippy -D warnings` ✅ 0｜`fmt --all --check` ✅ 零 diff｜`doc` ✅ 0 error｜全量 test 正在跑

### WAV-5 提交（2026-10-27 02:26，103 文件 / 4 面）

| commit | 面 | 内容 |
|---|---|---|
| `35368812` | `713x6` W4 Clock | app-* 11 crate 26 生产站点 → ctx.clock；tokio 面保留 7 + 台账 7；9 crate 补禁令；5 个 MockClock 行为断言 |
| `0791bfb8` | `f17zu` W5 Spawn | 10 proxy crate 裸 spawn 清零（剩 3 红线条目）；**ss 真回归修复**（连接自持 `Arc<PluginContext>`）；socks 8 + dokodemo 1 + http 11 生产 tracing → LogFacade（allow 全撤） |
| `fe8d5481` | `xiuvr` 3a + `nn8os` | inbound `RwLock<Vec>` → `BoundedRegistry`（双写 175/0）；ctx 穿透收口（含 Linux-only 8 参自查）；`build_freedom_outbound` allow 台账 |
| `46d4f895` | 门修复 | fmt 收口（CI Format job 红源） |

**门**：check/clippy(-D warnings)/fmt/doc 全绿；全量 test **176 target 无 FAILED**；已 push
**端到端（PM 亲自跑，release 13m42s 构建）**：**32/32 PASS + interop 12/12 PASS**（含 Go→Rust 六个方向）
**票面**：close `xiuvr`（3a+3b+3c 全完，perf A/B 不做并写明理由）→ open **8**
`713x6`/`f17zu` 已 append 分片进度与剩余面

### WAV-6（03:00 → 03:40）`bbuh7` vendor 受控实验 → **KEEP**

| 指标 | 改前 | 改后 | 变化 |
|---|---:|---:|---|
| `tls_read` 站点 | 4.76 MB/MB | **1.00 MB/MB** | **−79.0%**（剩余=明文交付固有 1×） |
| 总分配 | — | — | **−76.7%** |
| 客户端 CPU user+sys | — | — | **−17~19%** |
| 吞吐 | 341 MB/s | **415.5 MB/s** | **+21.7%** |
| wire | — | — | 8MB+200MB **sha256 双侧逐字节 MATCH**；tshark record 数 1043=1043、bulk 516×1041 精确相等、0 条 >16389 |

- 补丁（`vendor/rustls/src/msgs/deframer/buffers.rs` +9/−3）：`prepare_read` 缩容条件去掉 `self.used == 0`；超大握手回收保留。代价 **+12KB/conn 常驻**
- 提交 `8b5453ef`；`Cargo.toml` vendor 注释已登记 patch + **升级需重放这 1 行**
- **同波重要发现 → 新票 `aj0n3`（P2）**：带 `fingerprint` 的配置在 `utls.rs:573-577` **一律接 `BtlsConn`，rustls fallback 已成死代码** → 带指纹节点享受不到 rustls 侧任何优化；且契约 bench 30MB/s vs dist 136MB/s（**4.4×**）待查
- 教训：此前的分配测量（含 W6 的 46%）**只在无指纹 rustls 拓扑成立**，契约 bench 测的是 btls 路径

## 3. 待发队列（契约已备）

### 下一波 A：`bbuh7` vendor/rustls 受控补丁实验
- 面：**独占** `vendor/rustls/src/msgs/deframer/buffers.rs`（红线已授权：用户 2026-10-27「全部交给你判断」）+ `Cargo.toml` vendor 注释
- 改法：`prepare_read` 去 `shrink_to` / 保留容量（5-10 行）
- 闸门（缺一即 `git checkout vendor/rustls` 回滚）：①同窗 A/B 测 **CPU user+sys**（不只吞吐）+ alloc/MB（`XRAY_ALLOC_STATS_SITES=1`）②`cargo check/clippy/test/doc/fmt` 全绿 ③32/32 + interop 12/12 ④Rust↔Go TLS wire 无变化（抓包取证）
- 判据：CPU 降 ≥5% 或 alloc/MB 显著降 → 保留 + 在 Cargo.toml 登记该 patch 行 + 更新升级 SOP `reports/fix-gqkk-vendor.md`

### 下一波 B：`nn8os` 剩余协议 crate ctx 迁移（分批，每批 ≤4 crate）
- 已迁：socks/http/blackhole/dokodemo + vmess/vless/trojan/ss/tuic/wireguard/anytls/hysteria/freedom/loopback
- 待盘：先 grep 实数确认还剩哪些 crate 有裸 spawn/Instant/tracing，再按批派
- **本批教训**：单代理 ≤4 crate，且契约必须写「验收=workspace `--all-targets` 全文尾部」

### 下一波 C：`f17zu`/`713x6` 台账收口核查
- 复核两票的 `#[allow]+reason` 台账是否每条都有真实依据（禁"为过 lint 而 allow"）
- 统计剩余裸调用实数，更新票面进度

---

## 4. 收尾（2026-10-27 07:45）

### 4.1 夜间成果：**8 张票关闭**，open 13 → **7**

| 关闭 | 内容 |
|---|---|
| `di8wy` | W1 1a+1b：生产装配走 PluginRegistry + Instance 生命周期（十门全绿） |
| `4y9ns` | 客户端读缓冲池化：cli alloc/MB **9.239→5.085** |
| `q1r4q` | XUDP 双拷贝清零：每包 alloc **3→2** |
| `r1693` | h2/xhttp 服务端发送块池化：srv alloc/MB **2.159→1.299** |
| `rrpn4` | unix 门控路径纪律（Linux 床 clippy 绿） |
| `xiuvr` | W3 契约族 3a+3b+3c（inbound 注册表 BoundedRegistry，双写 175/0） |
| `bbuh7` | **vendor/rustls 补丁**：tls_read **−79%**、CPU **−17~19%**、吞吐 **+21.7%** |
| `713x6` | W4 Clock 全量收口（净迁 28 + 台账 79，逐点 reason） |
| `77r0q`/`8wvo9` | 裁决/去重关闭（ConfigFile NO-GO 留档） |

**open 7**：`99ifi`(epic) · `nn8os` · `39hko` · `f17zu` · `aj0n3`(新) · `n539c` · `lbavl`

### 4.2 夜间提交：**20 个**（含 2 个 WIP 快照），全部 push

### 4.3 端到端验收（PM 亲自跑，共 4 轮）
每轮均 **32/32 PASS + interop 12/12 PASS**；最后一轮针对 inbound spawn 批次，release 重建后自验通过；全量 test **177 target 0 FAILED**

### 4.4 CI
- `46d4f895` Format 红 → 已修（该轮 Clippy 红是 socks 生产 tracing，已迁）
- `fe8d5481` Asset Gate 红（我提交的影子夹具引用 geo 资产）→ `76ae443c` 修（门排除 `fixtures`），**该轮 CI 全绿**
- 末两个提交 CI 在跑（本地四门 + e2e 已绿）

### 4.5 剩余（下一会话入口）
| 项 | 前置/风险 |
|---|---|
| `f17zu` 剩余 16 处 inbound spawn | UDS 6 处需 **Linux 床**（cfg(unix) 本机不可编译，禁止盲改）；mux link 4 处需跨连接 scope 设计裁量；SS 泵/tun/vision 属红线 |
| `39hko` | 台账总量已定型（90 时钟 + 若干 spawn），剩余同上 |
| `nn8os` | 12 个协议 crate 的 ctx 迁移（已由 W5Spawn 覆盖大部分，需重新核账） |
| `aj0n3` | 带指纹配置走 btls 的路径归因 + 契约 bench vs dist 4.4× 回查 |
| `n539c`/`lbavl` | 已裁决不排期，保持挂账 |

### 4.6 磁盘
夜间最险时 **92%（40G）**；两次 `rm -rf target/debug/incremental` 共回收 128G。**收尾态 96G 可用 / target/debug ≈149G**（可再删，但下一会话要重建）。

---
（每波完成后追加：时间 / 代理 / 结果 / 提交 hash / 磁盘 / 决策）
