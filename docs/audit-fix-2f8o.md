# bd 2f8o 修复报告：stress harness RSS 泄漏判定被启动爬坡段污染

日期：2026-10-09 · 修复轮（未 commit，归 PM）· master 09944b40 工作树

## 结论（VERDICT: FIXED & REPLAY-VERIFIED）

`judge_leak` 斜率拟合由全段改为**尾半段**（`samples[n/2..]`，RSS 稳态段），
基线（前 10% 样本均值）与阈值（5 %/h）不变。run 36237760680 五目录回放：
macOS a/b SUSPECT→OK，linux a/b 与 windows all 结论不翻转；旧口径复刻与
summary.md 逐位一致（45.24/5.00、48.41/6.27），复刻保真已自校验。

## 1. 定位（票面预设勘误）

票面预设判定代码在 "stress-analysis/ 或 dist/ 下 metrics 分析脚本"——两处均无
（dist/ 仅 interop 工具，stress-analysis/ 目录不存在）。全仓 grep `SUSPECT` 唯一
判定生产点：`crates/xray-stress/src/report.rs judge_leak`（%/h 口径，写入
summary.md 与 checkpoint）。该 crate 为压测 harness 工具面（非产品数据面），
与票面 "建议 harness 泄漏判定改为尾半段" 一致；产品代码零改动。
CI 独立门禁 `tools/check_stress_leak.py`（MB/min 口径 + 600s warmup 剥离）本票未动。

## 2. 修复内容（crates/xray-stress/src/report.rs）

- `judge_leak`：拟合输入 `samples` → `samples[n/2..]`；尾段不足 2 样本（n≤2）退化回全段
- doc 注释记录动机与票号；summary 渲染标签 `linear slope` → `tail-half slope (steady-state fit)`
- 新增回归测试 `leak_startup_ramp_then_plateau_is_ok`（前 20% 爬坡 + 平台 → 必须 OK）
- 其余口径（baseline/first/last/peak、阈值比较、drain 不入判定、`rss_slope_mb_per_h`）不动

## 3. 回放对比（run 36237760680 × 5 目录，`stress-analysis-tmp/replay_2f8o.py`）

| 目录 | n | 旧 slope | 旧 %/h | 旧判定 | 新 slope | 新 %/h | 新判定 | q1..q5 RSS 均值 (MB) |
|---|---|---|---|---|---|---|---|---|
| stress-macos-a | 601 | 45.24 MB/h | 5.00% | **SUSPECT** | 1.30 MB/h | 0.14% | **OK** | 945 1039 1121 1123 1133 |
| stress-macos-b | 601 | 48.41 MB/h | 6.27% | **SUSPECT** | 11.62 MB/h | 1.50% | **OK** | 803 923 982 992 1013 |
| stress-linux-a | 601 | 38.62 MB/h | 1.70% | OK | 20.82 MB/h | 0.92% | OK | 2385 2529 2522 2531 2579 |
| stress-linux-b | 601 | 60.01 MB/h | 0.94% | OK | 5.78 MB/h | 0.09% | OK | 6591 6822 6814 6855 6896 |
| stress-windows-all | 601 | -14.24 MB/h | -1.07% | OK | 8.24 MB/h | 0.62% | OK | 1279 1248 1226 1220 1238 |

- 无假阳复现：macOS 两批尾段平台化后 %/h 落到 0.14/1.50，远低于 5 阈值；
  真泄漏形态仍被捕获（全段线性增长的合成用例尾半段斜率不变，`leak_suspect_above_threshold` 原样通过）。
- CI 门禁旁证（只读）：`check_stress_leak.py` 对 5 目录全部 PASS
  （rss 负载斜率 +0.61/+0.70/+0.20/+0.19/-0.25 MB/min，max 20）——假阳仅存在于 %/h 判定面。

## 4. 验证

- `cargo test -p xray-stress --lib`：**21 passed / 0 failed**（旧泄漏判定双向测试原样通过 + 新增回归测试）
- `cargo test -p xray-stress --lib leak_startup_ramp`：**1 passed**（单跑确认）
- 复刻自校验：回放旧口径 = summary.md 逐位（macos-a 45.24 MB/h / 5.00 %/h，macos-b 48.41 / 6.27）
- 本地构建用 bd 4jrt 绕开配方（`BORING_BSSL_ASSUME_PATCHED=1` + 已 patch out 目录），未改任何构建配置

## 5. 票面数字勘误（不影响结论）

票面 "q4→q5 RSS 平台化(macos-a 161MB 恒定/macos-b 144 走平)" 与 `__proc__` RSS
五分位均值不符（实测 macos-a q4/q5 = 1123/1133 MB，macos-b = 992/1013 MB；161/144
疑为其他列口径）。形态结论本身成立：头 60s 陡爬坡（15.5→529.7MB）+ 尾段平台，
全段拟合假阳机制与票面一致。

## 6. 文档同步

- `docs/impl-stress-harness-2026-09-20.md:86` 判定描述勘正为尾半段口径
- `CHANGELOG.md` Unreleased/Changed 追加一行

## 7. 残留/移交

- 未 commit（归 PM）。本票改动：`crates/xray-stress/src/report.rs`、`CHANGELOG.md`、
  `docs/impl-stress-harness-2026-09-20.md`、本报告；回放工作区 `stress-analysis-tmp/`（gitignore 内）。
- 工作树预存改动 `tools/setup_boringssl_reality.py`（非本票所改）未触碰。
- 六小时以上真机回归由下次 stress CI run 自然验证（summary 标签已带 tail-half 口径）。
