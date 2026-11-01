import re, os, json, sys
ROOT = r"D:/Project/Xray-core-rust/crates"
out = []
for crate in sorted(os.listdir(ROOT)):
    if not (crate.startswith("xray-proxy-") or crate.startswith("xray-transport-")):
        continue
    srcdir = os.path.join(ROOT, crate, "src")
    if not os.path.isdir(srcdir):
        continue
    for dirpath, _, files in os.walk(srcdir):
        for f in files:
            if not f.endswith(".rs"):
                continue
            p = os.path.join(dirpath, f)
            rel = os.path.relpath(p, os.path.join(ROOT, crate)).replace("\\", "/")
            lines = open(p, encoding="utf-8", errors="replace").read().split("\n")
            for i, ln in enumerate(lines, 1):
                for m in re.finditer(r'\.get\(\s*"([A-Za-z0-9_\-\.]+)"\s*\)', ln):
                    out.append((crate, rel, i, "get", m.group(1), ln.strip()[:160]))
                for m in re.finditer(r'\.get\(\s*"([A-Za-z0-9_\-\.]+)"\s*\)', ln):
                    pass
                for m in re.finditer(r'\[\s*"([A-Za-z0-9_\-\.]+)"\s*\]', ln):
                    # only when likely JSON indexing
                    if "json" in ln.lower() or "settings" in ln.lower() or "val" in ln.lower() or "raw" in ln.lower():
                        out.append((crate, rel, i, "index", m.group(1), ln.strip()[:160]))
print("crate\tfile\tline\tkind\tkey\tsrc")
for r in out:
    print("\t".join(map(str, r)))
