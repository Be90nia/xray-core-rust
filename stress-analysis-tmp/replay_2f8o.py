#!/usr/bin/env python3
"""bd 2f8o 回放：复刻 xray-stress judge_leak 旧/新判定，对 5 个 metrics.csv 目录对比。

旧判定（report.rs 现状）：全段最小二乘斜率，baseline = 前 10% 样本均值，
slope/baseline %/h > 阈值(5.0) → SUSPECT。
新判定（2f8o 修复）：仅尾半段（samples[n/2:]）参与斜率拟合，baseline/阈值不变。

本脚本数字必须与 summary.md 逐位对上（自校验），否则复刻失真。
"""

import csv
import sys

THRESHOLD_PCT = 5.0


def load_proc(path):
    rows = []
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            if row["scenario"] == "scenario":  # 追加文件的重复 header：只留最后一个 run
                rows = []
                continue
            if row["scenario"] == "__proc__":
                rows.append((int(row["ts"]), float(row["rss_mb"])))
    return rows


def ols_slope_mb_per_h(samples):
    n = len(samples)
    st = sum(t for t, _ in samples)
    sr = sum(r for _, r in samples)
    stt = sum(t * t for t, _ in samples)
    str_ = sum(t * r for t, r in samples)
    denom = n * stt - st * st
    if denom == 0:
        return None
    return (n * str_ - st * sr) / denom * 3600.0


def judge(samples, tail_half):
    """复刻 judge_leak；tail_half=True 时斜率只取后半段（2f8o 新口径）。"""
    n = len(samples)
    if n < 2:
        return None
    fit = samples[n // 2:] if tail_half else samples
    if len(fit) < 2:
        fit = samples  # 退化短序列保底：样本不足以劈半时退回全段
    slope = ols_slope_mb_per_h(fit)
    if slope is None:
        return None
    baseline_n = max(n // 10, 1)
    baseline = sum(r for _, r in samples[:baseline_n]) / baseline_n
    pct = slope / baseline * 100.0 if baseline > 0 else float("inf")
    return {
        "slope": slope, "pct": pct, "baseline": baseline,
        "last": samples[-1][1],
        "verdict": "SUSPECT" if pct > THRESHOLD_PCT else "OK",
    }


def quintiles(samples):
    n = len(samples)
    return [sum(r for _, r in samples[i * n // 5:(i + 1) * n // 5]) / (n // 5)
            for i in range(5)]


def main():
    dirs = sys.argv[1:]
    print(f"{'dir':<20} {'n':>4} | {'OLD slope':>10} {'OLD %/h':>8} {'OLD':>8} | "
          f"{'NEW slope':>10} {'NEW %/h':>8} {'NEW':>8} | q1..q5 RSS 均值")
    for d in dirs:
        s = load_proc(f"{d}/metrics.csv")
        old = judge(s, tail_half=False)
        new = judge(s, tail_half=True)
        qs = " ".join(f"{q:.0f}" for q in quintiles(s))
        print(f"{d:<20} {len(s):>4} | {old['slope']:>8.2f}h {old['pct']:>6.2f}% {old['verdict']:>8} | "
              f"{new['slope']:>8.2f}h {new['pct']:>6.2f}% {new['verdict']:>8} | {qs}")


if __name__ == "__main__":
    main()
