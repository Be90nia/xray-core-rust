"""逐波台账增减归因：对指定 commit，比较其改动 .rs 文件在 <c>^ 与 <c> 上的 allow 属性数。

口径与 l3-ledger-census.py 完全一致（同一解析函数，import 复用）。
用法: python reports/audit-2026-10-27/tmp/l3-wave-delta.py <commit> [<commit> ...]
"""
from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("census", HERE / "l3-ledger-census.py")
census = importlib.util.module_from_spec(spec)
spec.loader.exec_module(census)

REPO = census.REPO


def changed_rs(commit: str) -> list[str]:
    out = subprocess.run(
        ["git", "show", "--name-only", "--pretty=format:", commit, "--", "crates"],
        cwd=REPO, capture_output=True, text=True, check=True,
    ).stdout.split()
    return [p for p in out if p.endswith(".rs") and not p.startswith("crates/udf-frame/")]


def blob(ref: str, path: str) -> str:
    return subprocess.run(
        ["git", "show", f"{ref}:{path}"], cwd=REPO, capture_output=True, text=True,
    ).stdout


def count(src: str, path: str) -> tuple[int, int]:
    spans = census.test_spans(src)
    prod = test = 0
    for start, _end, inner in census.find_allows(src):
        face = census.classify_face(path, src, start, inner, spans)
        if face == "prod":
            prod += 1
        else:
            test += 1
    return prod, test


def main() -> None:
    commits = sys.argv[1:]
    print(f"{'commit':10} {'Δ生产':>6} {'Δ测试':>6} {'Δ合计':>6}  subject")
    tp = tt = 0
    for c in commits:
        files = changed_rs(c)
        dp = dt = 0
        detail = []
        for f in files:
            before = blob(f"{c}^", f)
            after = blob(c, f)
            bp, bt = count(before, f)
            ap, at = count(after, f)
            if (ap - bp) or (at - bt):
                detail.append((f, ap - bp, at - bt))
                dp += ap - bp
                dt += at - bt
        subj = subprocess.run(
            ["git", "log", "-1", "--pretty=%s", c], cwd=REPO,
            capture_output=True, text=True, check=True,
        ).stdout.strip()[:60]
        print(f"{c:10} {dp:+6d} {dt:+6d} {dp + dt:+6d}  {subj}")
        for f, a, b in detail:
            print(f"           {a:+4d} prod {b:+4d} test  {f}")
        tp += dp
        tt += dt
    print(f"{'TOTAL':10} {tp:+6d} {tt:+6d} {tp + tt:+6d}")


if __name__ == "__main__":
    main()
