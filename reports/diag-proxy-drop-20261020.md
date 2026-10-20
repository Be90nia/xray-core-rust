# 代理"用一会儿全挂"排查 + 最近改动审计（2026-10-20 12:20–13:45）

用户口供：YouTube 能打开，过一会立刻"未连接到互联网 / 代理服务器出现问题"；**所有协议**同样症状；怀疑缓冲池。
时间闸：14:00，实际收工 13:45。

## 结论先行

1. **未复现**：Rust HEAD、用户现场二进制、Go 对照三份内核同窗压测全绿，Windows 事件日志 8h 无 xray 崩溃记录 → 不是"客户端一压就死"。
2. **池确实有真 bug**（用户直觉对）：`alloc::release` 按 `capacity` 选层、`alloc` 不校验层内容量，多入口制造"小容量真池块"污染大层。当前代码下表现为吞吐退化/分层错配，**不是**必然 panic；证据不足以判定它就是本次全挂根因。
3. **最近改动里最可疑的是 DoH P0 直连旁路**（52a659ab）：`connect_stream` 把 `force_local` 架空，**所有 DNS 出站改为直连**，境内直连 `cloudflare-dns.com:443` 常态失败 → 依赖 DNS 模块的目标全灭。形态与"浏览器报代理错误"吻合。
4. 现场还有一条硬证据：v2rayN 日志 2026-10-19 09:09 `CoreHandler,ErrorStartingProcess ... 另一个程序正在使用此文件，进程无法访问。` = 内核根本没起来（残留 xray 进程占用）。当前机器上确实有残留 xray 进程跑 `target/interop_ci/c30.json`。

## 1. 同窗对照（本机，2026-10-20 12:20–13:30）

配置：用户真实节点 `vless-httpupgrade-tls + enc 0rtt`（home.begonia92.top:2087，SNI cdn_us1.begonia92.top），仅改端口；工作目录 `v2rayN\bin`（geo 数据），`XRAY_LOCATION_ASSET` 指 bin。

| 内核 | 顺序请求 | 并发（6×N） | 结果 |
|---|---|---|---|
| HEAD `target/release/xray.exe` (90f2d9…) | 25 | 6×5 | 55/55 = 200 |
| 用户现场 `bin\xray\xray.exe` (d518cf…) | 15 | 6×3 | 33/33 = 200 |
| Go 对照 `xray_backup.exe` | 8 | — | 8/8 = 200 |

- 三份二进制 MD5 互不相同（v2rayN 用的那份 ≠ 仓库任何现有构建），未做身份推断。
- Windows Application 日志近 8h 过滤 `xray|v2rayN`：**零事件**（无崩溃、无 .NET 异常）。
- Rust 侧 debug 日志全程无 ERROR；每条连接均 `btls 握手完成 session_reused=true` + `vless enc: 0-RTT fast path engaged`。
- 结论：30–60s 量级、≤6 并发的压测不能复现"过一会全挂"。要抓现场必须长时间 + 浏览器长连接形态 + 内核日志落盘。

## 2. 池缺陷（静态实锤）

`crates/xray-buf/src/alloc.rs`
- `release()`：`select_tier(capacity)` 选层后直接 `push` —— 只要求 `capacity <= TIER_SIZES[tier]`。
- `alloc(size)`：从层里 `pop` 后不做容量校验，调用方按"该层 = 固定容量"使用。
- 后果：容量 3000 的块可进 8KB 层；下次 `Buffer::new()` 拿到的"8KB 块"只有 3000。

制造小容量真池块的入口（都在 `crates/xray-buf/src/buffer.rs`）：
- `with_capacity(size)`（:54）：注释自称"直接分配，不经过池"，但变体是 `Inner::Pooled` → Drop 回池。
- `from_bytes(BytesMut)`（:63）：外部 `BytesMut` 容量任意，标 Pooled。
- `pooled_mut` 的 Frozen→COW 转正（:100-116）：`from_vec` 修好了（08852d7b），但一旦发生写，转正后的 `BytesMut` 容量 = 原 Vec 任意容量，仍标 Pooled 回池。
- 生产命中：`xray-crypto/src/auth_writer.rs:102 Buffer::with_capacity(total_size)`、`xray-mux/src/{client,reader,worker}.rs` 的 `Buffer::with_capacity(0)`。

放大效应：`maybe_sweep` 只清全局分片，**TLS_CACHE 永不清**（alloc.rs），污染块长期粘在 worker 线程上（与 2026-10-17 us1 cdn 钉死节点同族）。

严重度判断：现有消费方（`writable_bytes`/`advance_write`/`read_to`）都是自适应长度，不会越界 → **性能/池分层正确性 bug（P1）**，暂未找到由此直接 panic 或挂死的路径。

最小修复（未实施，待授权，diff ~5 行）：`release` 只在 `capacity == TIER_SIZES[tier]` 时入池，否则丢弃；`alloc` 侧加 `debug_assert_eq!(buf.capacity(), tier_size)`。

## 3. 最近改动审计（新发现）

| 提交 | 发现 | 严重度 |
|---|---|---|
| `52a659ab` DoH quad-fix | `dial.rs:305` `_force_local` 形参被架空，**所有 DNS 出站一律直连**（走共享拨号器的分支整段注释掉）。境内直连 CF 的 DoH 常态不可用 → DNS 模块可用性完全赌在网络窗口上 | **P0（形态吻合用户症状）** |
| bd `34nk`（open） | 共享拨号器下行唤醒丢失：经路由的 DoH/DoT/TCP-DNS 应答延迟精确 = 调用方 `timeoutMs`（4s/15s）。根因未修，仅被上面直连旁路绕过 | P0 open |
| `3e5da226` ws 预连接池 | 默认 `pool_size=12`、每节点常驻 12 条闲置 TLS+WS；`begin_preconnect` 名额闸 + virgin-only + probe 探活都在，未找到破绽，但常开 12 条到 CF 边缘与"用一会儿全挂"形态相容，列待观测 | 观测项 |
| `2b8469f6` 0-RTT early data | 缺省 `allowEarlyData=false`，用户配置未开 → 无影响 | 无 |
| `dc0c18ca` TFO | 仅 Linux 分支，Windows 不生效 | 无 |
| `323fab57` httpupgrade pending | 修得对：先吐 `pending` 再透传 inner，`poll_read` 返回 `Ready(Ok(()))` 语义正确 | 无 |
| `140772a9` / `89958b15` | 大批 inbound/dispatcher 改动，未逐 hunk 审（时间闸），未发现全局性缺陷 | 未覆盖 |

## 4. 下一步（按代价升序）

1. **让现场可观测**（5 min）：给 v2rayN 的 `binConfigs/config.json` 加 `"log": {"loglevel":"debug","error":"<path>","access":"<path>"}`；本次 diag 配置已验证该写法可落盘。
2. **清残留 + 换 HEAD 二进制**：机器上曾有 xray 进程跑 `target/interop_ci/c30.json`（占用/锁文件 → v2rayN `ErrorStartingProcess`）；换完再观察。
3. **池修复**（需授权，~5 行 + 一条回归测试）：见 §2。
4. **DoH 旁路收口**：把 P0 直连改成配置开关，或在共享拨号器修复后恢复分支；否则境内 DNS 可用性不成立。
5. 若仍复现：用 §1 的三内核同窗法（含 Go 对照）做 ≥30 分钟长时压测 + 浏览器真实流量，只在失败瞬间抓内核日志。

---

# 深挖第二轮（13:50–15:00）

## 6. 现场进程定位（关键）

- v2rayN **PID 18496**（13:26:06 启动）+ 子进程 `bin\xray\xray.exe` **PID 20880**（13:26:09，`run -c config.json`，cwd=binConfigs），监听 `127.0.0.1:10808`。
- 系统代理 `ProxyEnable=1 / ProxyServer=127.0.0.1:10808`，TUN 关闭（`EnableTun=False`）→ **Chrome 走 10808 的 HTTP 代理**（mixed inbound 同时收 HTTP）。
- v2rayN 日志时间线：`12:17:09 启动 → 12:18:05 退出`——用户截图里的报错正落在**内核重启窗口**内。

## 7. 对用户真实进程的压测（非我起的进程）

| 压测 | 结果 |
|---|---|
| HEAD 构建 @11808，SOCKS，768 请求（12 并发） | 768/768 = 200；RSS 97.8→101.2MB、线程 29→24、句柄 225（**无泄漏**） |
| HEAD 构建 @11808，HTTP 代理 CONNECT（Chrome 路径） | 25/25 = 200 |
| 用户二进制 @11810 | 33/33 = 200 |
| **用户线上进程 @10808（HTTP 代理，8 并发 × 10 轮）** | **80/80 = 200；句柄 325→307、RSS 92→102MB 稳定** |
| Go 对照 | 8/8 = 200 |

## 8. 第二轮排除的假设（都做了实验）

| 假设 | 实验 | 结论 |
|---|---|---|
| 嗅探 200ms 超时会掐断连接 | 延迟 0/50/150/250/400/800ms 再发首字节 | **不掐**；`SniffingTimeout` 在 dispatch 层优雅降级回原 dest（default.rs:1224） |
| 内核长期持有配置文件 → v2rayN 报“文件被占用” | 进程运行时以 r+b 打开 + truncate 重写配置 | **无锁**，可重写 |
| 端口占用导致新内核起不来 | 10808 被占时再启动一份 | **明确报错并退出**：`inbound bind failed ... os error 10048`（行为正确） |
| 句柄/线程/内存泄漏 | 768 请求采样 | 无增长趋势（句柄 225 恒定） |
| 池分层污染导致读路径见 EOF | 代码追链 + alloc 调用点穷举 | 生产热路径 `bridge.rs:88` / `inbound.rs:693` 直接 `alloc` 后 **BytesMut 直接 drop（根本不回池）**，池污染只影响走 `Buffer::new()` 的次级路径 → **性能级**，非断连 |
| 会话缓存/0-RTT 拒绝后无回落 | 读 2b8469f6/faf0eef2 状态机 | `EarlyData::Replay` 有完整重发 + 证书重验，且缺省 `allowEarlyData=false` 不启用 |

## 9. 第二轮新发现（审计）

1. **HEAD 的 DoH 直连旁路是延迟回归**：同节点同时刻，HEAD(11808) 首个域名请求 4.4s，用户旧二进制(11810) 1.5s。原因是 52a659ab 把 DNS 出站改成直连（境内直连 CF 更慢）。属可量化回归，建议改配置开关。
2. **启动日志顺序误导**：`Xray instance started version=...` 在内核绑定 inbound **之前**打印（本次 bind 冲突实验可见：先 "started"，后 "bind failed, aborting"）。若上层监管以 stdout 判活，会把“绑定失败”误判为“已启动”——与 v2rayN 报“文件被占用后没起来但界面正常”形态相容。
3. 池 bug 的生产影响被高估：热路径并没经过池（见 §8），修它优先解决的是**分层正确性**而非本次故障。

## 10. 第二轮结论

**用户看到的“代理服务器出现问题”= 系统代理指向 10808 而该端口无人服务**（内核重启窗口 / 内核启动失败），不是协议或数据面 bug；因为系统代理与出站协议无关，所以“换任何协议都一样”。

内核在 HEAD 与用户二进制上均未复现服务端化失败；两轮共 **889+80 请求零失败、零泄漏、零崩溃、零锁**。

---

# 深挖第三轮（空闲连接的判定）

## 11. 空闲 60 秒：四内核同窗对照

方法：HTTP CONNECT 建隧道 → 空闲 60s → 再发首字节；每内核 4 条并发。

| 内核 | 端口 | idle=0s | idle=60s（各 4 条） |
|---|---|---|---|
| Rust HEAD | 11808 | 全活 | **4/4 中止（WinError 10053）** |
| **Go 对照** | 11809 | — | **4/4 中止（10053）** |
| 用户二进制 | 11810 | — | **4/4 中止（10053）** |
| 用户线上进程 | 10808 | — | **4/4 中止（10053）** |

**结论：60s 空闲回收是上游（CF 边缘 / 服务端）行为，Go 同样中招 → 不是 Rust 客户端回归。**
但它解释了"页面放着不动、稍后再点就报错"的观感：隧道被上游回收，浏览器复用失败。这条对**任何内核都成立**，属节点/边缘特性（可考虑让服务端/CF 侧调 keepalive，或客户端加下行 keepalive 探测）。

## 12. 第三轮结论更新

故障解释排序（证据强度降序）：

1. **系统代理开着但 10808 无服务**（内核重启窗口 / 启动失败）——与 Chrome 报错字面完全对应，且与出站协议无关，解释"所有协议都一样"。日志时间线（12:17:09 起 / 12:18:05 退）正好覆盖截图时刻；昨日 `ErrorStartingProcess: 另一个程序正在使用此文件` 同类。
2. **上游 60s 空闲回收**——四内核一致，非本仓 bug；影响"放一会再点"的体感。
3. 池分层污染 / DoH 直连旁路——真实缺陷但为性能级，不是断连原因。

## 13. 修复（2026-10-20 15:00 落地）

| 修复 | 文件 | 内容 | 验证 |
|---|---|---|---|
| 池分层污染 | `crates/xray-buf/src/alloc.rs` | `release` 只在 `capacity == TIER_SIZES[tier]` 时入池，否则丢弃 | 新增 `release_discards_off_size_blocks`；`cargo test -p xray-buf --lib` **201 passed / 0 failed** |
| 启动日志误导 | `crates/xray-core/src/instance.rs` | `Xray instance started` → `Xray instance initialized (features started; inbounds bound by caller)`；权威 started 仍由 `start_full_dispatched` 在 bind 成功后打印 | 冒烟日志实测顺序：initialized → `mixed inbound listening` → `inbound bind summary` → `started via DefaultDispatcher` |

部署：`bin\xray\xray_new.exe`（新构建，44,974,592B）；原 10:37 版本备份为 `bin\xray\xray_before_1020fix.exe`。**未改动任何 v2rayN / 节点配置**。

日志采集开关（不碰 config）：用户环境变量 `RUST_LOG=warn,xray_core=debug,xray_transport=debug,xray_app_dispatcher=debug,xray_tls=debug`（`run.rs` 的 `EnvFilter::try_from_default_env()` 优先于配置 loglevel）。

未修（有据的取舍）：
- **DoH 直连旁路**（bd 34nk 的 P0 止血）：恢复共享拨号器会重启 4s 停顿，需先修管线下行唤醒丢失；
- **60s 空闲回收**：四内核（含 Go）一致，上游行为。

## 14. 构建口径（target-cpu）核查 + A/B 实测（2026-10-20 15:00-16:00）

用户问「编译用的是 `-C target-cpu=x86-64` 还是 `native`」。权威判据 = **cargo fingerprint**（`target/release/.fingerprint/xray-cli-*/lib-xray_cli.json` 的 `rustflags` 字段）：

| 构建时刻 | rustflags | 对应产物 |
|---|---|---|
| 10-18 18:17 | `['-C','target-cpu=x86-64']` | F2F3 矩阵 B_g |
| 10-20 01:04 | `['-C','native','-C','x86-64']` | 环境变量 + config 双份 |
| 10-20 11:42 | `['-C','target-cpu=native']` | **v2rayN 现役 10:37 部署件 = native** |
| 10-20 13:41 / 13:49 | `[]`（无 flag） | **本次修复构建 = rustc 默认 baseline x86-64（等价 `-C target-cpu=x86-64`）** |

**二进制里出现 ymm/zmm 指令 ≠ native**：本产物 19,256 条 AVX2/AVX-512 指令全部来自 aws-lc 加密库的 C/汇编目标文件（`aws_lc_0_46_0_jent_entropy` + .text 内 crypto 实现），rustc 的 target-cpu 不作用于 .S/.c 目标文件；判据只能看 fingerprint。

**`.cargo/config.toml` 写法坑**：用户 15:02 版本把 `CARGO_BUILD_RUSTFLAGS="-C target-cpu=x86-64"` 写在 TOML 顶层 = cargo 忽略的未知键（不报错、不生效）。已改为真正生效的 `[build] rustflags = ["-C","target-cpu=x86-64"]`。

### A/B 同窗交替（节点 home.begonia92.top:2087，CF CDN 族，20MB/50MB 单发）

3 轮 × 20MB：native [4.0, 8.3, 0.0] / generic [3.6, 3.8, 9.5] / go [9.5, 2.4, 4.0] —— 三者中位均 ~4MB/s，Go 对照同窗摆 2.4→9.5，**窗口内路径噪声主导，分不出构建差异**。

6 轮 × 50MB：native [8.3, 0.5, 0.1, 4.4, 14.0, **0.0**] 中位 4.4 / generic [1.6, 1.6, 1.2, 19.2, 9.1, 12.8] 中位 9.1 / go [18.6, 0.9, 8.1, 9.1, 9.8, 9.1] 中位 9.1。
native 9 次采样里 2 次塌到 ≈0（0.1 / 0.0），generic 与 Go 均未塌（最低 1.2 / 0.9）。
**归因未分离**：native 与 generic 之间还差「池分层污染修复 + 启动日志」，两变量混用；需同源码 native 重建（flag 单变量）才能定论。

## 15. 「native 会让 CPU 空转」实证核验（2026-10-20 16:40）

复用 10-18 原版 harness（`D:/tmp/dig-pause-mech/repro_cpu.py`，本地回环：socks5 消费者 → xray cli → :12088 xray srv(vless+tls) → freedom → httpd big.bin），**服务端固定**（generic_fixed），只换客户端二进制，`DIGP7LM=0`（关 P7LM 测量税）：

| 客户端二进制 | 吞吐 | >5ms 停顿 | 停顿总时长 | 顶层线程 CPU avg / max |
|---|---|---|---|---|
| old_native（10:37 现役生产版） | **12.6 MB/s** | **99** | **4839 ms** | **15.5% / 15.3%**（max 57% / 73%） |
| native_fixed（今日源码 + native flag） | **54.8 MB/s** | 7 | 818 ms | 8.5% / 5.6%（max 39.7% / 33.3%） |
| generic_fixed（今日源码 + x86-64） | 41.9 MB/s | 11 | 1146 ms | 6.5% / 5.6%（max 29.7% / 36.3%） |

**裁决**：
1. **「native 导致 CPU 空转」不成立**。同一份源码下 native 与通用版的顶层线程 CPU 同量级（8.5% vs 6.5%），native 吞吐反而更高（54.8 vs 41.9 MB/s）。与 10-18 报告 §5 结论一致（native 重建 91.6 MB/s 零停顿零烧核，flag 无罪）。
2. **烧核 + 巨停绑定的是「现役 10:37 生产版」**：两个线程各 ~15% avg、99 次停顿、4.8 秒停顿总量，比今日构建慢 3-4 倍。与 10-18 §4/§5 的因果收敛一致：现象绑定「主树非 HEAD 源内容构建」，与 codegen flag 无关；10-18 的 RIP 直方图已把热点定位到 AEAD 反复重加密的 poll-retry 循环（CRYPTO_chacha_20 / poly1305_finish）。
3. 因此「整体速度慢」的处置 = 换今日构建（generic x86-64 + 池分层修复 + 准确启动日志），**与 target-cpu 无关**。

口径限制：本地回环（剥公网噪声）；今日本机→CF 直连仅 0.45-0.70 MB/s（窗口劣化，见 §14），公网测速数据今日不可用。native vs 通用 CPU 差为单轮数据，量级相同，不足以支撑「native 空转」结论。

## 5. 边界与风险

- 未改任何业务代码、未动 `tests/`/`.github/`/`dist/`/`vendor/`；诊断配置与日志留在 `target/tmp-diag/`（构建产物目录）。
- 未验证服务端与 CF 边缘：本次全绿同样可能是"当前窗口好"；用户故障时刻的窗口未知，不能据此宣布代码无罪。
- 池缺陷是真 bug 但未证明是本次根因；DoH 旁路是"形态吻合"而非实锤，需第 1 步的现场日志确认。
