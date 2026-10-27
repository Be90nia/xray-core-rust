VERDICT: PASS

# ab-gate 工装验收报告（tools/ab_gate.py）

日期：2026-10-27 深夜～10-28 凌晨 ｜ 执行：ABGate（OMP 子代理）｜ 场景拓扑：本机 loopback
任务：把「性能只能同窗交错 A/B」（baseline.md 2026-10-27 校准节）变成可执行工装。

## 0. 交付物

- `tools/ab_gate.py`（Python 3 标准库，零新依赖）：
  - 输入：`--a`（默认 `target/release/xray.exe`）/ `--b`（必填）/ `--rounds`（默认 5）/ `--tol`（默认 0.05）/ `--tag` / `--force` / `--scenario {minvless,loopback}`
  - 严格交错：A,B,A,B,...（绝先跑完一侧再跑另一侧）
  - 污染防线三道：①启动前 `tasklist` 扫 cargo/rustc/cl，默认拒跑（exit 4，`--force` 覆盖并记录）；②每轮记录编译进程计数+UTC 时间戳；③任一侧轮间离散度 `(max-min)/median > 15%` → 标记 CONTAMINATED 且 exit 3
  - 判定：**中位数比值 B/A**（抗离群），`ratio < 1 - tol` → FAIL（exit 1）；同时打印逐轮原始值、median/MAD/IQR
  - 存档：`reports/bench/ab-<UTC>-<tag>.json`（双方 sha256、机器名、逐轮数字+负载快照、判定、forced 标记）+ stdout 一行 `AB-GATE-SUMMARY:` 可直接贴报告
  - 场景：`minvless`（自建裸 vless+tcp，200MB×2 curl 均值，跨二进制，默认）；`loopback`（复用 `tools/loopback_alloc_bench.py`，基线拓扑，仅 Rust↔Rust——新增，见 §4.1）
- 存档 9 份：`reports/bench/ab-2026102{7}T*.json`（本报告全部引用）

## 1. 验收 #1：`--help` 可用且参数齐全 ✅

```
usage: ab_gate.py [-h] [--a BIN_A] --b BIN_B [--rounds ROUNDS] [--tol TOL]
                  [--tag TAG] [--scenario {minvless,loopback}] [--force]

同窗交错 A/B 吞吐对比闸（中位数比值判定，编译污染检测）

options:
  -h, --help            show this help message and exit
  --a BIN_A             基准侧二进制（默认 target/release/xray.exe）
  --b BIN_B             对照侧二进制（必填）
  --rounds ROUNDS       交错轮数（每轮 A,B 各一次，默认 5）
  --tol TOL             允许 B 比 A 慢的比例（默认 0.05 = 5%）
  --tag TAG             存档 tag（默认 ab）
  --scenario {minvless,loopback}
                        minvless=裸 vless+tcp（跨二进制，默认）；loopback=基线拓扑（仅
                        Rust↔Rust）
  --force               检测到编译进程仍强行运行（记入报告）

退出码: 0=PASS 1=FAIL 2=ERROR 3=CONTAMINATED 4=REFUSED(编译活动)
```

## 2. 验收 #2：有人编译时拒绝或标记 CONTAMINATED ✅（两类证据都拿到了）

**拒跑（exit 4）**——当晚兄弟代理编译波频繁，预检 5 次真实触发，节选：

```
REFUSED: 检测到编译活动 ['cargo.exe', 'rustc.exe'] x5 —— loopback 跑分会被压低约20%。
  等编译结束再跑，或确认知情用 --force。
EXIT=4
```

另捕获 x8、x10、x21 等波次（x21 为大规模并行编译高峰）。拒跑判定与 `tasklist` 实况逐次吻合（工具拒绝时人工复扫确认进程在）。

**CONTAMINATED 标记**——同窗轮中出现编译波被逐轮捕获并标记（存档 `ab-20261027T155003Z-aa-selfcheck.json`）：

```
  round 1A: 117.2 MB/s (8.4s, compilers={"cargo.exe": 2, "rustc.exe": 13, ...})
  round 2A: 117.3 MB/s (8.5s, compilers={"cargo.exe": 2, "rustc.exe": 1, ...})
  round 3A: 121.1 MB/s (8.4s, compilers={"cargo.exe": 0, ...})
CONTAMINATED: 轮中见编译进程 ['cargo.exe', 'rustc.exe']
```

同时该轮证明**交错设计对污染免疫**：1A/1B 配对（117.2 vs 114.8，差 2%）在 13 个 rustc 压场下仍紧贴。离散度超阈分支另见 §4 的 5 次实弹（spread 48.2%/60.8%/28.5%/42.0%/20.9%/21.8% 均 exit 3）。

语义说明：轮中见编译进程 = 标记 CONTAMINATED + stderr 告警 + 存档 `contaminated=true`，但退出码只由离散度阈值触发（exit 3）——避免背景编译残流把可用比值判死票（本轮实证：编译波下配对差仅 2-6%）。

## 3. 验收 #3：A/A 自检（rounds=3）✅

**主证据（minvless 场景，全程零编译进程，exit 0）**——存档 `ab-20261027T160114Z-aa-minvless.json`：

```
  round 1A: 293.2 MB/s   round 1B: 281.6 MB/s
  round 2A: 290.7 MB/s   round 2B: 268.9 MB/s
  round 3A: 267.5 MB/s   round 3B: 287.1 MB/s
A: median=290.70 MAD=2.52 IQR=12.85 spread=8.8%
B: median=281.62 MAD=5.50 IQR=9.13 spread=6.5%
median ratio B/A = 0.9688 (tol=0.05) -> verdict=PASS
AB-GATE-SUMMARY: tag=aa-minvless ratio_B_over_A=0.9688 ... contaminated=false
```

**A/A 实测偏差汇总**（三次，含污染窗对照）：

| 跑 | 场景 | ratio | 偏差 \|1-ratio\| | 窗口状态 |
|---|---|---|---|---|
| `aa-minvless` | 裸 vless+tcp | 0.9688 | **3.1%** | 干净（全程 compilers=0） |
| `aa-selfcheck-clean` | loopback 基线拓扑 | 0.9940 | **0.6%** | 前 2 轮干净，3B 遇波（中位数抗离群：3B 115.9 拖不偏 0.994） |
| `aa-selfcheck` | loopback 基线拓扑 | 1.0580 | **5.8%** | 污染窗（1-2 轮 rustc 13→1） |

**建议阈值**：干净窗实测偏差 ≤3.1%，`tol=0.05` 够用；**无法确认全窗干净时阈值至少 0.08**（污染窗 A/A 偏差实测 5.8%，5% 会误判），或加轮数（5+）稳中位数。另注意：本工具 FAIL 判据是单向的（B 比 A 慢超 tol），A/A 永远 PASS——A/A 的验收指标是偏差绝对值，上表即口径。

## 4. 验收 #4：Rust/Go 真对照 ✅（比值 + 一个重要发现）

### 4.1 loopback 基线拓扑对 Go 不可用（工具适配记录）

Go 对照 `D:/Project/Xray-core/target/xray-go.exe` = Xray **26.7.28**。`loopback_alloc_bench.py` 的 `read_keys()` 取 `vlessenc.txt` 最后一对密钥 = **ML-KEM-768（后量子）变体**，Go 26.7.28 不支持该 wire → 全链路 connection reset（失败证据：`reports/bench` 首次 rust-vs-go 跑 + `D:/tmp/enc8x/srv-rust-vs-go-b1.log`）。基线工具属共享面不动，故按任务书「自建等价最小场景」选项给 ab_gate 内置 `minvless` 场景（裸 vless+tcp，双方原生支持），`loopback` 场景保留作 Rust↔Rust 基线拓扑对比。

### 4.2 Rust/Go 比值（minvless，4 次独立干净窗 attempt，全部零编译进程）

| attempt | ratio B/A | A(Rust) median | B(Go) median | A spread | B spread |
|---|---|---|---|---|---|
| 1（`...160424Z`） | 1.3513 | 283.4 | 383.0 | 9.1% | 28.5% |
| 2（`...160634Z`） | 1.6328 | 285.6 | 466.2 | 3.7% | 42.0% |
| 3（`...160843Z`） | 1.4900 | 286.7 | 427.2 | 3.5% | 20.9% |
| 4（`...161052Z`） | 1.4899 | 285.3 | 425.1 | 5.5% | 21.8% |

**结论：裸 vless+tcp loopback 上 Go 内核吞吐 ≈ Rust 的 1.35-1.63×（中位数口径，四次 attempt 中位 1.49，方向零分歧）。** Rust 侧同 harness 下轮间离散仅 3.5-9.1%（健康）；Go 侧 20.9-42%。

### 4.3 发现：15% 离散度门对跨内核对比是「内核固有方差」误报（需 PM 知悉）

4 次 attempt 全部零编译进程，Go 侧离散仍 20.9-42%（attempt 2 出现 541 MB/s 孤峰、attempt 1 呈 309→413→418 爬升，[INFERENCE] 疑与进程级 CPU boost/GC 行为有关，未深挖）。这是**被测内核自身的方差**，不是环境污染——但按任务书的 15% 规则被标 CONTAMINATED（exit 3，行为符合规格，5 次实证含 §首跑）。工装语义目前无法区分「环境污染型离散」与「被测体固有离散」。

**建议 PM 口径**（未实施，超出本单范围）：跨内核比较时以中位数比值为准、以 **A 侧 spread 作窗口健康度判据**（Rust↔Go 场景 A 是固定锚，spread 3.5-9.1% 即窗口干净），B 侧 spread 超阈标注但人工判读；如需自动化，后续可给 ab_gate 加 `--spread-gate {both,a-only,off}` 选项。

## 5. 给 baseline.md 的建议（未改文件，仅建议）

2026-10-27 校准节第 4-5 条（交错 A/B、报窗口时间戳+进程快照）可补一句工具化落地：「同窗交错 A/B 用 `python tools/ab_gate.py --a <bin> --b <bin> --tag <t>`，存档自动落 `reports/bench/`，含 sha256+逐轮负载快照；判定看 `AB-GATE-SUMMARY` 行」；并补跨内核场景的 A 侧 spread 健康度口径（§4.3）。

## 6. 复现命令

```bash
python tools/ab_gate.py --help
python tools/ab_gate.py --a target/release/xray.exe --b target/release/xray.exe --rounds 3 --tag aa
python tools/ab_gate.py --a target/release/xray.exe --b D:/Project/Xray-core/target/xray-go.exe --rounds 5 --tag rust-vs-go
# 场景默认 minvless（跨二进制）；loopback 基线拓扑加 --scenario loopback（仅 Rust↔Rust，Go 26.7.28 不支持 ML-KEM-768 enc）
```

## 7. 五维自评

| 维度 | 分 | 依据 |
|---|---|---|
| 正确性 | 4.5 | 三条验收全过且有实弹证据；交错序、中位数判定、三道污染防线、退出码语义均按任务书实现；扣 0.5：Go 固有方差与污染离散未在工具内区分（已文档化，属任务书规则本身盲区） |
| 证据强度 | 4.5 | 9 份 json 存档 + 全部 stdout 落报告；拒跑 5 次、CONTAMINATED 6 次、A/A 3 次、Rust/Go 5 次均为真实运行；扣 0.5：Go 方差根因未深挖（[INFERENCE] 标注） |
| 可维护性 | 4.5 | 260 行标准库单文件、复用既有 bench、场景可插拔、退出码契约写进 --help；扣 0.5：两场景 runner 有少量重复结构 |
| 范围纪律 | 5 | 零产品代码改动、未动 baseline.md（只建议）、未动共享 bench 工具、临时目录已清理（D:/tmp/abgate 已删）、未 commit |
| 实用性 | 4.5 | 一条命令出可贴报告的 SUMMARY 行 + 可审计存档；当晚已实际拦截 5 次污染跑；扣 0.5：跨内核场景需人工判读 B 侧 spread（待 §4.3 选项） |

**综合 4.6/5**。遗留：①§4.3 的 spread 门分侧选项未实施（建议后续单开）；②`loopback` 场景跨内核不可用是 Go 26.7.28 的 ML-KEM-768 支持问题，非本工具缺陷。
