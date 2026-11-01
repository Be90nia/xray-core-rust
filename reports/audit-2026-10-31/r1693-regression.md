# bd 9eu4a — r1693 xhttp/h2 服务端发送池化「回退」定位与修复

日期：2026-10-31 ｜ 分支 `feature/fix-inbound-parity` ｜ 执行：R1693Regression（OMP 子代理）
复测环境：`tools/loopback_alloc_bench_variants.py --variant plain-xhttp`（reality+xhttp，vless 加解密 none），`XRAY_ALLOC_STATS=1` + `XRAY_ALLOC_STATS_SITES=1`，BoringSSL 带汇编预构建（`BORING_BSSL_PATH=target/boringssl-asm/prebuilt`）。

## 0. 结论（TL;DR）

- **不是某笔提交改坏了池化代码**：`dl_stream.rs` 池化实现与 `alloc_site` 字节归因口径在 `c31ae9b6..HEAD` 间均无行为变更（diff 取证见 §2.1/§2.2）；hyper/h2/bytes/tokio 版本零变化；服务端窗值 16/32/16 MB 被测试钉死未动。
- **真实机制 = 池容量按突发深度定死，客户端提速把突发加深后池被打成逐帧 churn**。`xhttp_srv_send` 站点字节全部由「池未命中时的 64 KiB 块分配」构成（HEAD 实测 200 MiB 窗：4,352 次站点分配 ≈ 1,147 次 64 KiB 未命中 × 65,536 B + owner 头），未命中率 0.195 档 ≈19% → 现档 36–62%。
- **回退比较本身跨了吞吐档位**：r1693 记录的 1.299/0.195 基线在 **38.27 MB/s**（commit message 原文）档位测得——当时 btls 无汇编、客户端排空慢 7 倍；`65fc6dcd`（10-27，Windows btls 恢复汇编，指纹客户端 31.6→241.2 MB/s）之后同款 bench 跑 **269–281 MB/s**。客户端排空节奏加快 → 服务端 hyper send_buf（16 MB）「填充满→排空」循环加深（在飞块数 >POOL_MAX=8）→ 每循环逐帧重分配。
- **修复（`dl_stream.rs`）**：池容量从固定 8 块改为**本流观测在飞峰值自适应**（封顶 258 块 = send_buf 16MB/64KiB + 2）。驻留 ≤ 本流 send_buf 本就要占的量；突发间隙块整批留池，下一突发整批复用，churn 归零。wire 语义零改动（块大小/帧粒度/窗值全部不动）。
- **结果**：`xhttp_srv_send` 392,041,792 B（0.62/share 37.2%）→ **26,217,264 B（0.044/share 3.8%）**（plain 600MiB）；srv alloc/MB **1.758 → 1.144 ≤ 1.30**（plain，还优于 r1693 自己的 1.299），full 变体 1.172；同窗 A/B 吞吐中位 345.4 vs 344.5 MB/s（不降）；floor 120 两变体 PASS（298/136）。

## 1. 判据与复现

判据 = plain-xhttp 变体 `xhttp_srv_send` 站点窗口差分字节（比 full 变体干净：该变体 vless 明文，站点仍可观测）。

| 树 | xhttp_srv_send | srv alloc/MB | 吞吐档 | 裁定 |
|---|---|---|---|---|
| c31ae9b6（r1693 记录，2026-10-26） | 116,821,216 B / 600 MiB = 0.195 | 1.299 | 38.27 MB/s（无汇编客户端） | good |
| HEAD `cd15e549`（本机复测，1 轮 200 MiB） | 75,192,704 B = 0.359（share 25.2%，4,352 次分配） | 1.491 | 269.4 MB/s | bad |
| HEAD `cd15e549`（PM 2026-10-31，3 轮 600 MiB） | 392,041,792 B = 0.62（share 37.2%） | 1.758 | — | bad |
| `d68a1f66` + udf-API 垫片（1 轮 200 MiB） | 81,353,040 B = 0.388（4,445 次分配） | 1.523 | 281.2 MB/s | bad |

## 2. Bisect 过程与死区

### 2.1 池化代码与归因口径未变（排除「代码被改坏」）

- `git diff c31ae9b6..HEAD -- crates/xray-transport-splithttp/src/hub{,/dl_stream,/handler}.rs`：`dl_stream.rs` 唯一差异是 udf-promotion 注释改口（cb2bd6ec）；`handler.rs` 差异全是 spawn 托管豁免标注（hj3jf）；`hub.rs` 差异是取窗改走 `flow_window::server_windows_from_rtt(None)`，且有测试 `plaintext_serve_windows_equal_pre_fix_static` 钉死逐值 = 修前静态 16/32/16 MB。
- `git diff c31ae9b6..HEAD -- crates/xray-common/src/alloc_site.rs`：字节维度 `SITE_BYTES`、线程局部 `enter`/`current()`、分配器钩子记账路径逐字保留；58823d1e 只换计数机制（udf AllocSite），dd03ac0c 只新增 `scope`（唯一消费方 bridge.rs `BUF_READ`，非本站点）。
- `Cargo.lock`：hyper/h2/bytes/tokio 在区间内零变化。

### 2.2 checkout bisect 的可达边界

| 提交 | 结果 |
|---|---|
| `d68a1f66`（10-29 12:31，客户端 readv x8 批读） | **bad**（上表）→ 病灶在 ≤ d68a1f66 |
| `d68a1f66` 以下（< `88b55aa1` 10-28 18:53） | **构建不可达**：udf 工作副本（禁碰）HEAD=`51c2428b`，其 `FxScope::shutdown_timeout → ShutdownReport` 破坏老树编译（xray-frame/scope.rs E0308）；`88b55aa1` 之前的树还缺 `spawn→spawn_tracked` 85 处适配，垫片不可行 |
| `92f11077` / `33bacd22` / `dbdfc83d` / `2e43d5c1` / `cb2bd6ec` / `02a00cca` | 静态逐笔核对：无一触及服务端发送腿的块粒度/池/窗值（详见 §3 元素表） |

（d68a1f66 树仅打一处编译垫片：`xray-frame/src/scope.rs` 的 `shutdown_timeout` 适配 ShutdownReport 签名——xray-frame 胶水，非数据面；垫片未提交，测后已还原。）

### 2.3 病灶即 `65fc6dcd` 的吞吐档位迁移（代码因果链）

池化代码不变 + 判据变坏 ⇒ 变量在**运行时节律**。c31ae9b6..HEAD 区间内改变客户端排空节奏的提交：

| 提交 | 面向 | 对服务端发送突发的作用 |
|---|---|---|
| `65fc6dcd`（10-27） | Windows btls 恢复汇编（构建级） | **客户端 TLS 吞吐 31.6→241.2 MB/s（7.6×）**——r1693 基线（10-26，38 MB/s 档）在此之后测出，故它不在 1.299 的度量条件下，却是 1.758 的度量条件。本 bisect 全程带 asm env，故所有新测数字都在快档 |
| `92f11077`（10-28） | 客户端 h2 下行零拷贝读腿 | 排空延迟再降（去 8KB 池化拷贝路径） |
| `d68a1f66`（10-29） | 客户端下行 readv 批粒度 8191→65536 B（x8） | 单轮 syscall 数 ÷8，排空批间空隙加大、批深加大 |

三者同向：客户端消费 h2 响应越快、批越大 → 服务端 hyper send_buf（16 MB 上限）的「填充深度×排空周期」越深 → 在飞块峰值越超过 POOL_MAX=8 → `take()` 未命中（64 KiB 重分配）+ 归还溢出丢弃的 churn 越烈。**缺陷本体是 r1693 的固定容量设计对突发深度不鲁棒**；`65fc6dcd` 是暴露点（缺直接构建对照，依据 = 吞吐档位差 + d68a1f66 bad + §4 容量实验闭环）。

## 3. 修复：池容量自适应峰值化（`crates/xray-transport-splithttp/src/hub/dl_stream.rs`）

（数字与验收见 §4/§5；此节补实现要点）

- `PoolState { free, live, peak }`：`take()` 记 `live+1`、升 `peak`；`put()` 记 `live-1`，`free.len() < min(peak, POOL_MAX)` 才收块。
- `POOL_MAX` 8 → `16MB/CHUNK+2 = 258`（= 本流在飞块理论上界）。容量按**实测峰值**收紧：驻留 ≈ 本流 send_buf 本就要占的量，且只发生在真突发过的流上——对 r1693「加大 POOL_MAX 线性抬常驻内存」顾虑的正面回应。
- wire 面零改动：块 64 KiB、一 poll 一帧、窗值/帧尺寸分布不动。

## 4. 验证（code-level，修复树上实测）

| 门 | 命令 | 结果 |
|---|---|---|
| clippy | `cargo clippy --workspace --all-targets -- -D warnings` | **0 error**（1m49s，btls 预构建路线） |
| fmt | `cargo fmt -p xray-transport-splithttp -- --check` | **干净**（首跑揪出测试断言折行，已 `cargo fmt -p` 收口复检过；`cargo fmt --all` 的 Diff 全部位于 `crates/udf-frame/` 工作副本=派单声明的恒脏，非本次改动） |
| 测试 | `cargo test -p xray-transport-splithttp -p xray-core` | **0 failed**：xray-core 505 lib + 5 integration；splithttp 256 lib + 16 integration（mock_h3 1 / mock_server 12 / reality 1 / stream_h2 2） |

## 5. 验证（end-to-end）

二进制：`xray-fix.exe`（修复树 release）/ `xray-head.exe`（同一棵树 stash 修复后重建 = `cd15e549` 原样），同 env（btls 汇编预构建）、同机同窗。

### 5.1 同窗交错 A/B（plain-xhttp，3×200 MiB 交错跑，中位数）

| | head | fix | 判定 |
|---|---|---|---|
| 吞吐 MB/s（3 轮中位） | 344.5（336.8/344.5/367.7） | 345.4（331.3/345.4/348.4） | **+0.3%，吞吐不降**（窗口内噪声 ±5% 口径） |
| srv alloc/MB | 1.479（1.462/1.479/1.494） | **1.159**（三轮恒定 1.159） | −0.32 |
| xhttp_srv_send | 中位 72.9 MB/200MiB（69.4/72.9/75.8，share 23.7–25.4%） | **8.80 MB/200MiB**（8.74/8.80/8.80，share 3.8%） | **−8.3×** |

### 5.2 600 MiB 窗双变体（fix 二进制，各 3 轮，`--floor 120`）

| 变体 | xhttp_srv_send | srv alloc/MB | 吞吐（best） | floor |
|---|---|---|---|---|
| plain-xhttp | **26,217,264 B = 0.044 MB/MB（share 3.8%）**（HEAD 同款窗 = 392,041,792 B = 0.62 / 37.2%） | **1.144** ≤ 1.30（且优于 r1693 自己的 1.299） | 265.4 / 297.0 / **298.1** MB/s | PASS（298.1 ≥ 120） |
| full | **40,459,392 B = 0.064 MB/MB（share 5.8%）** | **1.172** ≤ 1.30 | 120.8 / 135.6 / **136.0** MB/s | PASS（136.0 ≥ 120） |

残余站点字节 = 每流冷启动坡道（每连接前几个突发周期 ~130–400 次块分配）+ `Bytes::from_owner` owner 头（每帧 ~40 B，API 固有），前者随流数线性、后者随帧数线性，均不可归零亦无害（旧「好态」0.195 里同样是这两项 + 当时低档位下的小额未命中）。

注：A/B 窗（330–370 MB/s）与 5.2 窗（265–298 MB/s）绝对值不同属跨窗漂移（本仓既有校准结论 d3a756a0：性能门判同窗相对差）；5.1 的 A/B 是交错同窗，为有效对照。

## 6. 残余与移交

1. **修复未提交**（派单铁律）：改动 = `crates/xray-transport-splithttp/src/hub/dl_stream.rs` 单文件（工作树唯一 M 条目），主代理验收后自行 commit；建议票注引用本报告。
2. **4y9ns 未触碰**：A/B 中 cli alloc/MB plain=1.600 与 HEAD 逐位一致（cli 面零改动旁证）；full 变体 cli 2.192 属 vless-enc/mlkem 面（`buf_read` 21%），非本票。
3. **下一站（非本票）**：srv 侧 `(untagged)` 桶 plain=216 MB/200MiB（修复后 share 93.3%，hyper/tokio 内部件分配）——站点机制覆盖外，后续若压 srv 总量从它下手，需另立票。
4. 工件：bisect 数据=本报告 §1/§5 表；bench 日志与两枚二进制在 `D:/tmp/enc8x/`（`srv-*.log`/`*.out`/`xray-{head,fix}.exe`）；一次性 bisect 脚手架 `tools/bisect_r1693.py` 已删；**`target-r1693/` 已整目录删除**。
5. 给后续 bench 的口径提醒：r1693 时代的 srv alloc/MB 绝对值（1.299）绑定 38 MB/s 吞吐档，与 asm 后的 270–370 MB/s 档**不可直比**；srv alloc 门建议按「≤1.30 + site share」双判据。
