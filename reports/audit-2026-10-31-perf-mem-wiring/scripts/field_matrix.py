"""批量输出 (crate, field) 的读/写站点摘要（排除测试模块），用于台账证据列。

用法: python field_matrix.py  < spec.txt
spec 每行 `crate field [field ...]`（crate=ALL 表示全仓）。
"""
import os
import re
import sys

try:  # Windows 控制台默认 cp1252/cp936，字段名含非 ASCII 时 print 会 OSError(22)
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

ROOT = r"D:/Project/Xray-core-rust/crates"


def iter_files(scope):
    base = ROOT if scope == "ALL" else os.path.join(ROOT, scope)
    for dp, _, fs in os.walk(base):
        if "udf-frame" in dp.replace("\\", "/"):
            continue
        for f in sorted(fs):
            if f.endswith(".rs"):
                yield os.path.join(dp, f)


def code_only(txt):
    last = None
    for m in re.finditer(r"#\[cfg\(test\)\]\s*\n\s*mod [a-z_0-9]+", txt):
        last = m
    return txt if last is None else txt[: last.start()]


def scan(scope, field):
    reads, writes = [], []
    rx = re.compile(r"\." + re.escape(field) + r"\b")
    for p in iter_files(scope):
        txt = code_only(open(p, encoding="utf-8", errors="replace").read())
        for i, ln in enumerate(txt.split("\n"), 1):
            for m in rx.finditer(ln):
                rel = os.path.relpath(p, ROOT).replace("\\", "/")
                if re.match(r"\s*=(?!=)", ln[m.end():]):
                    writes.append(f"{rel}:{i}")
                else:
                    reads.append(f"{rel}:{i}")
    return reads, writes


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        scope, fields = parts[0], parts[1:]
        for f in fields:
            r, w = scan(scope, f)
            sites = r[:6]
            extra = "" if len(r) <= 6 else f" (+{len(r) - 6} more)"
            print(f"{scope}\t{f}\t reads={len(r)} writes={len(w)}\t {', '.join(sites)}{extra}")


if __name__ == "__main__":
    main()
