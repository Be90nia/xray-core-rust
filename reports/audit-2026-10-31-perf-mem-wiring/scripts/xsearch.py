"""跨 crate（含 xray-core / xray-cli / xray-conf）统计若干符号的出现次数与位置，
用于确认「字段只在本 crate 内写入、全仓无人读」。

用法: python xsearch.py symbol1 symbol2 ...
"""
import os
import re
import sys

ROOT = r"D:/Project/Xray-core-rust/crates"
SKIP_DIRS = {"udf-frame"}


def main():
    pats = sys.argv[1:]
    rx = re.compile(r"\b(" + "|".join(re.escape(p) for p in pats) + r")\b")
    hits = {p: [] for p in pats}
    for crate in sorted(os.listdir(ROOT)):
        if crate in SKIP_DIRS:
            continue
        srcdir = os.path.join(ROOT, crate)
        if not os.path.isdir(srcdir):
            continue
        for dp, _, fs in os.walk(srcdir):
            for f in fs:
                if not f.endswith(".rs"):
                    continue
                p = os.path.join(dp, f)
                txt = open(p, encoding="utf-8", errors="replace").read()
                if not rx.search(txt):
                    continue
                _m = [m for m in re.finditer(r"#\[cfg\(test\)\]\s*\n\s*mod [a-z_0-9]+", txt)]
                intest = _m[-1].start() if _m else -1
                for i, ln in enumerate(txt.split("\n"), 1):
                    for m in rx.finditer(ln):
                        pos = sum(len(x) + 1 for x in txt.split("\n")[: i - 1]) + m.start()
                        in_test = intest >= 0 and pos > intest
                        hits[m.group(1)].append(
                            (
                                "test" if in_test else "code",
                                os.path.relpath(p, ROOT).replace("\\", "/"),
                                i,
                                ln.strip()[:120],
                            )
                        )
    for p in pats:
        print(f"=== {p}: {len(hits[p])} hits")
        for k, f, i, s in hits[p][:40]:
            print(f"  [{k}] {f}:{i}  {s}")


if __name__ == "__main__":
    main()
