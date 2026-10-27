# btls 指纹路径审计：接线事实 + 三组 A/B + 契约 bench 4.4× 归因

票 `aj0n3` · 2026-10-27 · 执行：BtlsPathAudit · **只读审计（未改任何源码/配置/vendor）**

VERDICT: **CONDITIONAL-PASS — ①指纹分支面已钉死：`connector_for_fingerprint` 全清单返回 `Some`，带指纹（及 ws/httpupgrade 缺省 chrome、naive、REALITY）一律走 btls，rustls fallback 是死代码；②4.4× 是真回退（同脚本同拓扑同窗交替 ×3 轮复现 4.16-4.25×，HEAD 仍在）；③罪责钉死 = client 方向 btls conn 每 read 事件 ~137µs CPU（dist 同位 18µs，交叉配对裁决），REALITY/xhttp/enc/帧化/分配/加密/C 源全数排除；④可修（dist 同机 233 MB/s = 存在性证明），精确 commit 留 bisect 战役（判据脚本与锚点已备，见 §4）。**

---

## 1. 接线事实：带 fingerprint 一律走 btls，rustls fallback 是死代码

### 1.1 中央接线点（票面指认处，逐行核实）

`crates/xray-tls/src/utls.rs:573-577`（`u_client_with_alpn`）：

```rust
// 尝试 btls（真实指纹）
if let Some(result) = crate::btls_client::connector_for_fingerprint(&fingerprint) {
    match result {
        Ok(_) => {
            debug!(target: "xray_tls::utls", ?fingerprint, server_name, "u_client: 尝试 btls 指纹伪装");
```

死代码判定链（三证）：

1. **`connector_for_fingerprint` 不再返回 `None`**：`crates/xray-tls/src/btls_client.rs:944-970`——文档注释自证「rustls）；**函数不再返回 `None`**」；清单外指纹返回 `Some(Err(InvalidData))` 硬错（:964-966 错误文案原文 `"fingerprint {fp:?} not supported by btls; pick a supported fingerprint (silent rustls fallback removed)"`），清单内返回 `Some(Ok(config))`。
2. **fallback 分支不可达**：`utls.rs:641-643` `debug!("u_client: rustls fallback")` + `client(...)` 只在 `connector_for_fingerprint` 返回 `None` 时到达——永不。`utls.rs:619-623` 握手失败分支注释自证「fallback: 重新建立 TCP 连接已不可能（stream 被 consume），返回错误」。
3. **测试注释自证**：`utls.rs:763-766`「pz6c 修正：Random 指纹实际映射 Chrome 133 走 btls（connector_for_fingerprint 对全清单返回 Some，rustls fallback 分支已随"清单外指纹硬错"裁决成为死代码）」。

结论：**任何进入 `u_client`/`u_client_with_alpn` 的连接 100% 走 btls（BoringSSL）**；rustls 侧优化（含 bbuh7 的 vendor deframer churn 修复）对带指纹节点零收益。

### 1.2 传输出站分支点全表（文件:行）

| 传输 | 分支点 | 有指纹（或缺省）→ | 无指纹 → | 备注 |
|---|---|---|---|---|
| TCP | `crates/xray-transport-tcp/src/register.rs:110-145` | `u_client` → **btls** | `utls::client` → rustls | 分支判据 = `fp_name.is_empty()`（:110）；ECH 无指纹 → 强制 Chrome 指纹走 btls（:127-137 warn） |
| WebSocket | `crates/xray-transport-websocket/src/client.rs:136-152` | `get_fingerprint` Ok → `u_client_with_alpn` → **btls** | 仅**非法指纹名** Err → rustls | ⚠️ `unwrap_or("")` + `get_fingerprint("")=Chrome`（fingerprint.rs:149-151）→ **ws TLS 出站缺省也走 btls**，rustls 分支仅非法名可达 |
| HTTPUpgrade | `crates/xray-transport-httpupgrade/src/register.rs:504-533` | Ok → `u_client_with_alpn` → **btls** | 仅非法名 → rustls | 同 ws：`fingerprint_name()`（:624-626）缺省 `""` → Chrome → 恒 btls |
| SplitHTTP h1/h2 | `crates/xray-transport-splithttp/src/register.rs:121-126` + `client.rs:277-284` | `Some(fp)` → `SplitConnector::Btls` → `u_client` → **btls** | `None` → rustls connector | 判据 `has_tls && !has_reality && !fp_name.is_empty()` |
| SplitHTTP h3 (quinn) | `crates/xray-transport-splithttp/src/register.rs:166-168` | **恒 rustls ClientHello**（指纹不支持，warn 降级） | 同左 | 唯一指纹不生效的 TLS 出站 |
| gRPC | `crates/xray-transport-grpc/src/transport.rs:230-243` | `Some(fp)` → `u_client` → **btls** | `None` → rustls | |
| naive | `crates/xray-transport-naive/src/dial.rs:69-83` | **恒 btls**（`BtlsConn::connect` 直连，无 rustls 分支） | 同左 | 指纹缺省 `HelloChrome133`（uri.rs:34） |
| REALITY | `crates/xray-reality/src/client.rs:461-463`（空指纹配置期硬错）+ `crates/xray-tls/src/btls_reality.rs:368-372` | **恒 btls**（HelloRewrite 握手） | — | REALITY 无 rustls 路径 |

### 1.3 受影响配置面（谁在 btls 数据面上）

- **带 `tlsSettings.fingerprint` 的全部 TLS 出站**（tcp/ws/httpupgrade/xhttp/grpc）：指进去 btls，享受不到 rustls 侧任何后续优化（含 bbuh7 vendor patch——其对 btls 路径本就零影响）。
- **ws/httpupgrade 无指纹 TLS 出站**：`get_fingerprint("")=Chrome` 缺省语义 → **同样恒 btls**（与 Go dialer.go GetFingerprint 缺省 chrome 对齐，非 bug，但意味着「无指纹=rustls」仅 tcp/grpc/xhttp/splithttp 成立）。
- **全部 REALITY 出站**：恒 btls。
- **naive 全部**：恒 btls。
- **生产节点面**：三台生产 VPS 的 26 监听里带指纹/reality 的节点全部落在 btls 数据面（契约 bench 的 xhttp+reality+chrome 亦然）。

---

## 2. 三组 A/B 实测（同机同拓扑 vless+tcp+enc=none，仅切 security/fingerprint）

日期 2026-10-27，脚本 `D:/tmp/aj0n3_ab.py`（每组 = 独立进程对 + 3 轮 × 200MB curl，XRAY_ALLOC_STATS+SITES 开，psutil 记 xray 双进程 CPU）。同窗内 R→B→BR 交替 ×3 轮。

### 2.1 主表（二进制 = `D:/tmp/xray-bbuh7-base.exe`，fe8d5481 干净树，exe_fingerprint=12987ae2，即 bbuh7 报出 30MB/s 的原二进制）

| 组 | 拓扑 | TLS 实现 | 3 轮均值（MB/s） | best | CPU cli（s） | CPU srv（s） | cli alloc MB/MB（主站点） |
|---|---|---|---|---|---|---|---|
| **R** | vless+tcp+tls，无指纹 | **rustls** | 142.8 / 259.3 / 319.9（轮1含冷启动） | **339.5** | 2.0-2.6 | 1.3-1.6 | 4.83-4.84（tls_read 4.76，vendor deframer churn 未 patch 态） |
| **B** | 同上 + `fingerprint: chrome` | **btls** | 26.3 / 27.7 / 29.2 | 31.6 | **20.2-22.4** | 1.2-1.5 | **0.06** |
| **BR** | vless+tcp+**reality**+chrome | **btls+REALITY** | 28.1 / 30.1 / 26.9 | 33.4 | 19.9-21.3 | 1.3-1.5 | 0.06 |

（机器背景负载：Trae IDE 恒占 ~10 核，全程同在——三组同窗交替，相对比较不受影响；R 组轮 1 偏低为 E2 尾部负载余波。）

### 2.2 交叉核对（B 组单点）

| 二进制 | B 组 3 轮（MB/s） | 均值 | CPU cli / srv（s） |
|---|---|---|---|
| dist/xray.exe（10-13 master 时代） | 206.9 / 223.9 / 233.8 | **221.5** | 2.8 / 1.2 |
| base（fe8d5481） | 26.0-31.6（§2.1） | 28.4 | 21.2 / 1.4 |
| cur（target/release，今日 06:53 构建树态） | 20.4 / 19.9 / 18.7 | 19.7 | 23.6 / 1.6 |

### 2.3 判读

1. **同一二进制内 11× 悬崖**：R=339.5 vs B=31.6——唯一变量是指纹有无（rustls↔btls 数据面）。
2. **REALITY 层零贡献**：B≈BR（28.4 vs 28.4 均值级）。
3. **cli 进程独担 CPU**：B 组 cli 20-22s（单核打满整个传输窗）vs rustls 2.0-2.6s；srv 两同 1.2-1.6s。
4. **非分配问题**：B 组 cli 分配仅 0.06 MB/MB（36MB/600MiB），却烧 20s CPU——btls 读路径每 record 纯 CPU 为 dist 同位 7.5×（绝对值 ~137µs/record 按 4KB record 估，[INFERENCE-算术]；比值与 record 尺寸假设无关）。
5. cur（今日 HEAD 态）同样回退 → **回退仍在树上**。

---

## 3. 契约 bench 30 vs dist 136（4.4×）归因

### 3.1 可比性判定：**可比**（同脚本同拓扑，回退真实）

铁证 = dist 判别组原始输出 `D:/tmp/enc8x/cpu-bbuh7-dist.txt`（bbuh7 留证）：`tag=bbuh7-dist`，`[via-enc-chain]`×3 × 200MB = 600MiB——与契约 bench（`tools/loopback_alloc_bench.py`，vless(mlkem-enc)+xhttp+reality+chrome）完全同一脚本同一配置生成器。本次审计以三二进制**同窗交替 ×3 轮**复测（bbuh7 原判别组只有 dist 单点，本次补齐交替性）：

| 二进制 | 9 轮分布（MB/s） | 均值 | best | 差距 |
|---|---|---|---|---|
| dist/xray.exe | 103.7-129.2 | **118.5** | 129.2 | 1× |
| base（fe8d5481） | 26.1-30.4 | **28.5** | 30.4 | **4.16×（均值）/ 4.25×（best）** |
| cur（HEAD 态） | 18.0-30.1（轮3 负载劣化 18-23） | 27.2（净窗 28.8） | 30.1 | 4.1× |

对照（免 alloc-stats）：20.1/21.7/26.1——**不快反慢**（负载漂移尾），计数器开销无罪。原报数字 136/30.9=4.4× 与今日 4.16-4.25× 同带（±7% 日内漂移）。**结论：真回退，非拓扑伪影。**

### 3.2 排除清单（每个候选都有直接证据）

| 候选 | 裁决 | 证据 |
|---|---|---|
| rustls↔btls 拓扑差（dist 走 rustls？） | **排除** | dist 契约 bench = xhttp+**reality**（恒 btls：`btls_reality.rs:368`）；btls 后端 07-23 落地、REALITY btls 08-29、pz6c 09-12、daqq 10-20——dist（10-13 构建）全在 btls 时代 |
| REALITY 层 | 排除 | §2.1 B≈BR |
| xhttp/h2 + mlkem-enc | 排除 | §2.2 B（无 xhttp 无 enc）与契约 bench 同为 28-30 |
| record 帧化/加密批处理 | **排除** | wire 取证：dist srv→cli 主力 **4122B×1724 条/8MB**（跑 118-233 MB/s）vs base 双峰 1041/15386（均值更大，跑 30）——**record 更碎的二进制反而最快**，帧化与吞吐反相关 |
| 分配量 | 排除 | B 组 cli 0.06 MB/MB；且回退二进制与不回退二进制 alloc 画像同源 |
| 加密本体（BoringSSL） | 排除 | 同一二进制 srv 侧加密 600MiB 仅 1.4s CPU（AES-NI 速率）；BoringSSL 源+补丁树 8-27 定形早于 dist（`tools/setup_boringssl_reality.py` 末改 10-09，patched tree mtime 8-27） |
| btls 依赖版本漂移 | 排除 | Cargo.lock 新旧同 rev `ab7f522`（仅 git URL 0x676e67→Be90nia mirror，381c651b 同 hash=同内容） |
| alloc-stats 计数器 | 排除 | §3.1 对照组不快反慢 |
| `target-cpu=native` 3.2× 税（bd hxy3） | 排除 | 10-20 已撤销；且 E1 R/B 悬崖在同一二进制内，flag 恒定 |
| 0-RTT EarlyData 状态机 | 排除 | 普通连接 `early=Off` 直通（`btls_client.rs:1358-1367,1479-1481`）；poll_read/write 薄委托无自旋（:1466-1500 逐行核） |
| vendor/rustls patch（bbuh7） | 无关 | btls 路径不经 rustls deframer（tls_read 站点 566B/600MiB） |

### 3.3 定位结论（证据链）

**罪责在 cli 进程的 btls TLS 数据面读路径**：唯二变量（§2.1）只剩 conn 实现；cli CPU 7.5×/record 于 dist 同拓扑。**回退窗口 = merge-base(≈10-13) → 10-25**（perf-framework-cost 已见 34-36 MB/s）的 framework 支线 commit 空间。

⚠️ **`ab-master-vs-framework.md` 的 framework=157 MB/s 不可采信**：与其引用的 d72c195f 同日验收数字（a819ca9f 代码态 = 34.4-36.4 MB/s，10-26 10:48）直接矛盾，且与 perf-framework-cost(10-25)、c31ae9b6、bbuh7(10-27)、本次 E2 共 5 个独立会话的 28-36 一致带对立；其 master 列（146-165）与 dist 今日 103-129 相符，故该实验的 framework 侧数字疑为二进制/参数串扰。**据此，本审计不采信「回退仅在 a819ca9f..fe8d5481 的 20 commit」的窄窗口**——该报告不能作为 bisect 锚点。

另：bbuh7 移交要点 2 的「btls SSL_read 单 record 语义不吃 F3 64KB readbuf」假说与本审计的帧化反相关证据冲突，一并修正；dig-direct-pump 的「~30MB/s 长驻非回归」系 harness 拓扑（Windows loopback 病理族，v52）结论，不适用于真 TCP 管线（dist 今日 233 MB/s 实证）。

### 3.4 交叉配对（cli↔srv 二进制互换，B 组，XRAY_ALLOC_STATS 关）

| 配对 | 3 轮（MB/s） | cli CPU（s） | srv CPU（s） | 判读 |
|---|---|---|---|---|
| **cli=base + srv=dist** | 30.7 / 34.3 / 35.2 | **18.77** | 1.50 | 换上快服务端**照样慢** |
| **cli=dist + srv=base** | 137.3 / 154.2 / 140.2 | 2.22 | **0.81** | 慢二进制当服务端**毫无问题** |

**罪责 100% 钉死在客户端方向的 btls conn**：同一 base 二进制，client 方向烧 18.8s CPU，server 方向 0.81s 跑满 140+ MB/s——btls server 路径（`btls_server.rs`/accept 侧）健康，回退面 = **client 专有代码路径**（u_client→BtlsConn::connect 及其 client-only 附件：session cache、rcvbuf 拨号、0-RTT offer、daqq connector 改造）。

### 3.5 定位证据链小结

1. 同拓扑（§3.1）→ 真回退（4.16-4.25×，HEAD 仍在）。
2. 同二进制切指纹（§2.1）→ 悬崖在 TLS 实现层（rustls 339 vs btls 32）。
3. 切 REALITY / xhttp / mlkem-enc（§2.1、§2.2）→ 全部无罪，悬崖在 btls conn 本体。
4. **交叉配对（§3.4）→ 罪责 = client 方向 btls conn**（server 方向 0.81s CPU 健康）。
5. wire + alloc + C 源 + 依赖 rev + 状态机（§3.2）→ 机制画像：**client btls conn 每 read 事件 ~137µs 固定 CPU 成本**（dist 同位 18µs），非加密、非分配、非帧化、非 C 侧。
6. 候选 commit 空间 = merge-base(≈10-13)→10-25 的 **client-side btls 路径**改动：`2b8469f6`（0-RTT client offer）、`fb789348`/`faf0eef2`（client session cache + rcvbuf 16MB→4MB 翻转）、`3e5da226`（session cache + ws pool）、`75d8d862`（daqq client connector）、`2a488df3`（aoms keyshare）——**静态排查已清白**：EarlyData 状态机、poll_read/write 委托、record 帧化；洞可能在更深的 conn 构造/运行时交互（如 session cache 回调注册、SSL 对象选项、socket 选项与读循环的互动），静态不可达，须 bisect+采样。

---

## 4. 修法方案

**判定：可修的回退**（非 BoringSSL 语义代价——dist 同机同 record 形态 200+ MB/s = 存在性证明）。但**精确到 commit 的根因未钉死**，本轮只读审计不产出代码补丁；给 PM 的最小定位+修法路径：

1. **bisect 战役（预算 ~2h）**：在 framework 支线 merge-base(10-13)→10-25 区间，用 `D:/tmp/aj0n3_ab.py` **B 组**做判据（单组 3 轮仅 ~25s，比契约 bench 快 6×；悬崖 11× 远超噪声；交叉配对配方见 §3.4 可二分 cli/srv 侧）。隔离 worktree + 独立 `CARGO_TARGET_DIR`，锚点（全部 client-side btls 改动，见 §3.5.6）：10-19 簇前 / `3e5da226` 后 / `faf0eef2` 后 / `75d8d862` 后 → 悬崖出现区间再二分到单 commit。
2. **并行采样**：慢锚上对 cli 跑 `wpr -start CPU`（ETW 采样栈）或 tokio-console feature 构建，直视 137µs/record 花在哪个栈帧（SSL_read BIO 轮询 vs 任务唤醒链 vs bridge pump）。
3. **验收线**：修后 B 组 best ≥ 150 MB/s（dist 存在性证明 233，修到 ≥60% 即 140+），契约 bench 回到 ≥100 MB/s；三组 A/B + 32/32 + wire 帧序不变（wire 本就与吞吐无关，取证照 bbuh7 流程）。

---

## 5. 五维自评

- **定位准确性 4.5**：悬崖钉到「cli btls conn 每 read 事件固定 CPU 成本」——同二进制切指纹 11×、切 REALITY/xhttp 零变化、cli/srv 不对称、13 项排除清单全带证据；扣 0.5：精确 commit 未钉（bisect 留给修法战役，窗口已用 5 会话交叉收窄到 10-13→10-25）。
- **证据质量 4.5**：全部今日实测（E2 三二进制 27 轮 + E1 9 组 27 轮 + 交叉 2 组 + wire 2 份 + 对照 3 轮），同窗交替、脚本/原始输出留盘可复跑；扣 0.5：E1 R 组轮 1 与 E2 尾轮受 Trae 负载漂移（已标注、不影响相对结论）。
- **完备性 4**：验收 4 项全交（A/B 表 / 4.4× 归因 / 分支面清单 file:line / 零代码改动）；扣 1：base 的 B 组 wire 帧分布未抓（bash 设备名转义失败一次，结论已由 dist 侧反相关证据闭环）。
- **可执行性 5**：§4 给出判据脚本（aj0n3_ab.py B 组 25s/轮）、锚点 commit、预算与验收线；复跑命令全在文内。
- **简洁性 4**：主链三段式（接线事实/实测/归因）；站点画像与历史矛盾仲裁各一段必要保留。
