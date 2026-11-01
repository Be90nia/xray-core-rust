#!/usr/bin/env python3
"""Prong A: JSON-key consumption probe.

xray-conf parses every field, then `Config::build()` re-serializes each section back to
JSON (`BuiltEntry.data`) which downstream crates re-parse into their own structs. So the
only way a parsed key can reach runtime behaviour is that some production crate either
  (a) declares it (`#[serde(rename = "<key>")]` / a same-named struct field), or
  (b) looks it up in a raw Value (`get("<key>")` / `contains_key("<key>")`).

This script counts, per conf field, the number of quoted-literal occurrences of the JSON
key name in non-xray-conf, non-test code. 0 => parsed-but-never-read.

Usage: python json_key_probe.py [--all]
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))


def rust_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in (".git", "target", "vendor", "docs")
                       and not d.startswith("target-") and not d.startswith("udf-frame")]
        for f in filenames:
            if f.endswith(".rs"):
                yield os.path.join(dirpath, f)


def is_test_path(rel):
    return "/tests/" in rel or rel.endswith("_test.rs") or "/benches/" in rel


def main(show_all=False):
    with open(os.path.join(HERE, "fields.json"), encoding="utf-8") as fh:
        data = json.load(fh)

    keys = {}   # json key -> list of (rel, line, kind)
    for p in rust_files(os.path.join(ROOT, "crates")):
        rel = os.path.relpath(p, ROOT).replace(os.sep, "/")
        base = "test" if is_test_path(rel) else ("conf" if rel.startswith("crates/xray-conf/") else "prod")
        with open(p, encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
        test_start = None
        for i, ln in enumerate(lines):
            if re.match(r"^\s*#\[cfg\(test\)\]", ln):
                test_start = i + 1
                break
        for i, text in enumerate(lines, 1):
            if not text or text.lstrip().startswith("//"):
                continue
            kind = base
            if kind != "test" and test_start and i >= test_start:
                kind = "test"
            for lit in re.findall(r'"([^"\\]{1,40})"', text):
                keys.setdefault(lit, []).append((rel, i, kind, text.strip()))

    rows = []
    for st in data["conf"]:
        for f in st["fields"]:
            cand = [f["json"]] + list(f["aliases"])
            prod, conf, test = [], [], []
            for k in cand:
                for rel, line, kind, text in keys.get(k, []):
                    (prod if kind == "prod" else conf if kind == "conf" else test).append((rel, line, k, text))
            rows.append({
                "struct": st["struct"],
                "struct_file": os.path.relpath(st["file"], ROOT).replace(os.sep, "/"),
                "struct_line": st["line"],
                "field": f["rust"],
                "json": f["json"],
                "field_line": f["line"],
                "prod_count": len(prod),
                "conf_count": len(conf),
                "test_count": len(test),
                "prod_hits": [f"{r}:{l} {k}" for r, l, k, _ in prod[:8]],
            })

    with open(os.path.join(HERE, "json_key_ledger.json"), "w", encoding="utf-8") as fh:
        json.dump(rows, fh, indent=1, ensure_ascii=False)

    zero = [r for r in rows if r["prod_count"] == 0]
    print(f"conf fields={len(rows)}  json-key consumed in prod={len(rows) - len(zero)}  ZERO={len(zero)}")
    print("\n=== ZERO prod JSON-key consumption ===")
    for r in zero:
        print(f"{r['struct']}.{r['field']:26s} key={r['json']:24s} "
              f"{r['struct_file'].split('/src/')[-1]}:{r['field_line']:<5d} "
              f"conf={r['conf_count']} test={r['test_count']}")
    if show_all:
        print("\n=== all fields ===")
        for r in rows:
            print(f"{r['prod_count']:3d} {r['struct']}.{r['field']:26s} key={r['json']:24s} "
                  f"{' ; '.join(r['prod_hits'][:3])}")


if __name__ == "__main__":
    main("--all" in sys.argv)
