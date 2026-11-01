"""统计各协议/传输 crate 中配置结构体字段的「写入/读取」计数，输出 tsv 供台账复算。

用法: python field_usage.py [crate ...]   # 输出写到脚本同目录 field_usage.tsv
"""
import re
import os
import sys

try:  # Windows 控制台默认 cp1252/cp936，字段名含非 ASCII 时 print 会 OSError(22)
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

ROOT = r"D:/Project/Xray-core-rust/crates"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "field_usage.tsv")


def strip_tests(text):
    """只砍掉文件末尾的测试模块（`#[cfg(test)]\nmod tests`），保留中段的 cfg(test) 辅助函数。"""
    last = None
    for m in re.finditer(r"#\[cfg\(test\)\]\s*\n\s*mod [a-z_0-9]+", text):
        last = m
    return text[: last.start()] if last else text


def main():
    crates = sys.argv[1:] or sorted(
        d for d in os.listdir(ROOT) if d.startswith(("xray-proxy-", "xray-transport-"))
    )
    rows = []
    for crate in crates:
        srcdir = os.path.join(ROOT, crate, "src")
        if not os.path.isdir(srcdir):
            continue
        files = {}
        for dp, _, fs in os.walk(srcdir):
            for f in fs:
                if f.endswith(".rs"):
                    p = os.path.join(dp, f)
                    rel = os.path.relpath(p, os.path.join(ROOT, crate)).replace("\\", "/")
                    files[rel] = strip_tests(open(p, encoding="utf-8", errors="replace").read())
        structs = []
        for rel, txt in files.items():
            for m in re.finditer(r"pub struct (\w+)\s*(?:<[^>]*>)?\s*\{", txt):
                name = m.group(1)
                i = m.end() - 1
                depth = 0
                j = i
                for j in range(i, len(txt)):
                    if txt[j] == "{":
                        depth += 1
                    elif txt[j] == "}":
                        depth -= 1
                        if depth == 0:
                            break
                body = txt[i:j]
                line = txt[: m.start()].count("\n") + 1
                fields = []
                for fm in re.finditer(r"^\s*(?:pub )?(\w+)\s*:\s*", body, re.M):
                    fname = fm.group(1)
                    if fname in ("pub", "crate"):
                        continue
                    fields.append(fname)
                if fields:
                    structs.append((rel, line, name, fields))
        for rel, line, name, fields in structs:
            for f in fields:
                tot = reads = writes = 0
                where = []
                for rel2, txt2 in files.items():
                    # .field  (read or write)
                    dots = list(re.finditer(r"\." + re.escape(f) + r"\b", txt2))
                    w = sum(1 for m in dots if re.match(r"\s*=(?!=)", txt2[m.end():]))
                    r_ = len(dots) - w
                    c2 = len(re.findall(r"[\{,]\s*" + re.escape(f) + r"\s*:", txt2))
                    if dots or c2:
                        tot += len(dots) + c2
                        reads += r_
                        writes += w + c2
                        where.append(f"{rel2}:r{r_}/w{w + c2}")
                rows.append((crate, name, f, f"{rel}:{line}", tot, reads, writes, ",".join(where)))
    with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("crate\tstruct\tfield\tdef_site\tcount\treads\twrites\twhere(r/w)\n")
        for r in rows:
            fh.write("\t".join(map(str, r)) + "\n")
    zero = [r for r in rows if r[4] == 0]
    no_read = [r for r in rows if r[5] == 0 and r[6] > 0]
    print(f"rows={len(rows)} zero_any={len(zero)} written_never_read={len(no_read)} -> {OUT}")
    for r in no_read:
        print(f"NO_READ\t{r[0]}\t{r[1]}\t{r[2]}\t{r[3]}\tw={r[6]}")


if __name__ == "__main__":
    main()
