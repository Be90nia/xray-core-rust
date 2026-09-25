#!/usr/bin/env python3
"""xray-stress 泄漏门禁：对 metrics.csv 的 fd/RSS 序列拟合线性斜率并判定。

默认阈值锚定 docs/impl-stress-leak-{a,b}-2026-09-22.md 实测口径：
- 干净：fd 约 0-224 fd/min、RSS 尾段 <20 MB/min；泄漏：fd ≥+1800/min、RSS ≥+218 MB/min。
判定规则（阈值均可 CLI 覆盖）：
1. fd 负载期斜率 > --fd-slope-max → FAIL（fd 泄漏不豁免：连接泄漏在 drain 观察窗不会回收）
2. RSS 负载期斜率 > --rss-slope-max：
   - 存在 __drain__ 段且 drain 段 RSS 斜率 <= --rss-drain-slope-max → PASS
     （connIdle 300s 固有堆积：停负载后回落/企稳，非泄漏）
   - 否则 → FAIL（无 drain 数据无法排除真泄漏，保守判负）
3. fd_count 全缺失（macOS 无 /proc）→ fd 判定 SKIPPED，不影响退出码。
退出码：0=PASS，1=FAIL，2=样本不足/解析错误。
"""

import argparse
import csv
import sys


def slope_per_min(points):
    """最小二乘斜率；points = [(x_sec, y), ...]，x 为 unix 秒。"""
    n = len(points)
    xs = [x / 60.0 for x, _ in points]
    ys = [y for _, y in points]
    x_mean = sum(xs) / n
    y_mean = sum(ys) / n
    var = sum((x - x_mean) ** 2 for x in xs)
    if var == 0.0:
        return 0.0
    cov = sum((x - x_mean) * (y - y_mean) for x, y in zip(xs, ys))
    return cov / var


def load_series(path):
    """读 CSV，返回 (proc, drain)：[(ts, rss_mb, fd_or_None)]。

    追加文件中重复 header 视为新 run 开头，只保留最后一个 run 的样本。
    """
    proc, drain = [], []
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            if row["scenario"] == "scenario":
                proc, drain = [], []
                continue
            sc = row["scenario"]
            if sc not in ("__proc__", "__drain__"):
                continue
            ts = int(row["ts"])
            rss = float(row["rss_mb"])
            fd = None if row["fd_count"] == "-" else int(row["fd_count"])
            (drain if sc == "__drain__" else proc).append((ts, rss, fd))
    return proc, drain


def strip_warmup(rows, warmup_secs):
    if not rows:
        return rows
    t0 = rows[0][0]
    return [r for r in rows if r[0] - t0 >= warmup_secs]


def main():
    ap = argparse.ArgumentParser(description="leak gate over xray-stress metrics.csv")
    ap.add_argument("--csv", required=True, help="metrics.csv 路径")
    ap.add_argument("--warmup-secs", type=int, default=600,
                    help="负载期前段（运行时热身 + connIdle 窗口堆积）不入拟合，默认 600")
    ap.add_argument("--fd-slope-max", type=float, default=500.0,
                    help="fd 斜率阈值 fd/min（默认 500：干净实测 ≤224，泄漏 ≥1800）")
    ap.add_argument("--rss-slope-max", type=float, default=20.0,
                    help="负载期 RSS 斜率阈值 MB/min（默认 20：修复验收口径）")
    ap.add_argument("--rss-drain-slope-max", type=float, default=10.0,
                    help="drain 段 RSS 斜率阈值 MB/min（仍上升超过它 = 真泄漏）")
    args = ap.parse_args()

    try:
        proc, drain = load_series(args.csv)
    except (OSError, KeyError, ValueError) as e:
        print("[leak-gate] FAIL: cannot parse %s: %s" % (args.csv, e))
        return 2

    proc = strip_warmup(proc, args.warmup_secs)
    if len(proc) < 2:
        print("[leak-gate] FAIL: need >=2 load samples after %ds warmup, got %d"
              % (args.warmup_secs, len(proc)))
        return 2

    failures = []
    print("[leak-gate] samples: load=%d drain=%d (warmup skipped %ds)"
          % (len(proc), len(drain), args.warmup_secs))

    fd_pts = [(t, fd) for t, _, fd in proc if fd is not None]
    if len(fd_pts) >= 2:
        fd_slope = slope_per_min(fd_pts)
        ok = fd_slope <= args.fd_slope_max
        print("[leak-gate] fd slope: %+.2f fd/min (max %.0f) — %s"
              % (fd_slope, args.fd_slope_max, "PASS" if ok else "FAIL"))
        if not ok:
            failures.append("fd slope %+.2f fd/min > %.0f" % (fd_slope, args.fd_slope_max))
    else:
        print("[leak-gate] fd slope: SKIPPED (fd_count unavailable on this platform)")

    rss_slope = slope_per_min([(t, rss) for t, rss, _ in proc])
    rss_ok = rss_slope <= args.rss_slope_max
    print("[leak-gate] rss slope (load): %+.2f MB/min (max %.1f) — %s"
          % (rss_slope, args.rss_slope_max, "PASS" if rss_ok else "FAIL"))

    if rss_ok:
        pass
    elif len(drain) >= 2:
        drain_slope = slope_per_min([(t, rss) for t, rss, _ in drain])
        if drain_slope <= args.rss_drain_slope_max:
            print("[leak-gate] rss slope (drain): %+.2f MB/min (max %.1f) — "
                  "idle accumulation reclaimed after load stop, not a leak"
                  % (drain_slope, args.rss_drain_slope_max))
        else:
            print("[leak-gate] rss slope (drain): %+.2f MB/min (max %.1f) — "
                  "still rising after load stop, real leak"
                  % (drain_slope, args.rss_drain_slope_max))
            failures.append("rss drain slope %+.2f MB/min > %.1f"
                            % (drain_slope, args.rss_drain_slope_max))
    else:
        print("[leak-gate] rss slope (drain): NO DRAIN DATA — cannot exempt load-phase growth")
        failures.append("rss slope %+.2f MB/min > %.1f and no drain window"
                        % (rss_slope, args.rss_slope_max))

    if failures:
        print("[leak-gate] VERDICT: FAIL (%s)" % "; ".join(failures))
        return 1
    print("[leak-gate] VERDICT: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
