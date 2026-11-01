"""列出某 crate（或全仓）内 ``.field`` 的读/写站点（排除 #[cfg(test)] 之后的代码），
给台账提供「实际消费点 file:line」证据。

用法: python field_reads.py <crate|ALL> field1 [field2 ...]
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
    if scope == "ALL":
        bases = [ROOT]
    else:
        bases = [os.path.join(ROOT, scope)]
    for base in bases:
        for dp, _, fs in os.walk(base):
            if "udf-frame" in dp.replace("\\", "/"):
                continue
            for f in sorted(fs):
                if f.endswith(".rs"):
                    yield os.path.join(dp, f)


def main():
    scope = sys.argv[1]
    fields = sys.argv[2:]
    for field in fields:
        print(f"=== .{field}")
        n_read = n_write = 0
        for p in iter_files(scope):
            txt = open(p, encoding="utf-8", errors="replace").read()
            last = None
            for m in re.finditer(r"#\[cfg\(test\)\]\s*\n\s*mod [a-z_0-9]+", txt):
                last = m
            code = txt if last is None else txt[: last.start()]
            for i, ln in enumerate(code.split("\n"), 1):
                for m in re.finditer(r"\." + re.escape(field) + r"\b", ln):
                    is_write = re.match(r"\s*=(?!=)", ln[m.end():]) is not None
                    if is_write:
                        n_write += 1
                    else:
                        n_read += 1
                    tag = "W" if is_write else "R"
                    print(f"  [{tag}] {os.path.relpath(p, ROOT).replace(chr(92), '/')}:{i}  {ln.strip()[:120]}")
        print(f"  -> reads={n_read} writes={n_write}")


if __name__ == "__main__":
    main()
