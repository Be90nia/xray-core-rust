#!/usr/bin/env python3
"""Round4 ConfigParity: Go 配置键全集 vs Rust 解析点覆盖（425 / 415 / 10）.

口径（见 ConfigParity.md §1.1 / §1.2）:
  Go 侧 : D:/Project/Xray-core/infra/conf/**/*.go 的全部 `json:"..."` tag 去重
          （排除 _test.go）。**不含 app/** —— 那里是 protobuf 生成的 json tag，
          不是用户配置面。
  Rust 侧: crates/**/*.rs（排除 _test.rs 与 tests/）中
          (a) serde 字段名（含 rename / alias / rename_all=camelCase 展开）
          (b) 引号字面量（`.get("key")` / `get_bool("key")` / helper 传参）
          两者的并集。

输出:
  Go_KEYS_TOTAL / RUST_HAS_PARSE_SITE / RUST_NO_PARSE_SITE + 无解析点键清单
"""
import os
import re
import sys

GO_ROOT = "D:/Project/Xray-core"
RUST_ROOT = "D:/Project/Xray-core-rust"


def go_keys():
    tag = re.compile(r'json:"([^",]*)')
    keys = set()
    structs = 0
    rows = 0
    for dp, _, fs in os.walk(os.path.join(GO_ROOT, "infra/conf")):
        for f in fs:
            if not f.endswith(".go") or f.endswith("_test.go"):
                continue
            src = open(os.path.join(dp, f), encoding="utf-8", errors="replace").read()
            structs += len(re.findall(r'^type\s+\w+\s+struct\s*\{', src, re.M))
            for ln in src.split("\n"):
                m = tag.search(ln)
                if m and m.group(1):
                    keys.add(m.group(1))
                    rows += 1
    return keys, structs, rows


def rust_corpus():
    corpus = {}
    for dp, dn, fn in os.walk(os.path.join(RUST_ROOT, "crates")):
        if "udf-frame" in dp:
            continue
        for f in fn:
            if not f.endswith(".rs") or f.endswith("_test.rs"):
                continue
            p = os.path.join(dp, f)
            if "/tests/" in p.replace("\\", "/"):
                continue
            corpus[os.path.relpath(p, RUST_ROOT).replace("\\", "/")] = open(
                p, encoding="utf-8", errors="replace"
            ).read()
    return corpus


STRUCT_RE = re.compile(r'(?:pub(?:\([^)]*\))?\s+)?struct\s+(\w+)\s*\{')
FIELD_RE = re.compile(r'^\s*(?:pub(?:\([^)]*\))?\s+)?([A-Za-z_]\w*)\s*:\s*[^,]+,\s*$')
SERDE_ATTR_RE = re.compile(r'#\[serde\(([^)]*)\)\]')


def camel(s):
    parts = s.split("_")
    out = parts[0]
    for p in parts[1:]:
        out += p[:1].upper() + p[1:]
    return out


def snake(s):
    return re.sub(r'(?<!^)(?=[A-Z])', '_', s).lower()


def rust_serde_keys(corpus):
    keys = set()
    for src in corpus.values():
        cur = None
        rename_all = None
        pending = []
        for ln in src.split("\n"):
            ms = STRUCT_RE.match(ln)
            if ms:
                cur, rename_all, pending = ms.group(1), None, []
                continue
            ma = SERDE_ATTR_RE.search(ln)
            if ma:
                pending.append(ma.group(1))
                rm = re.search(r'rename_all\s*=\s*"([^"]+)"', ma.group(1))
                if rm:
                    rename_all = rm.group(1)
                continue
            mf = FIELD_RE.match(ln)
            if mf and cur:
                fname = mf.group(1)
                attrs = " ".join(pending)
                pending = []
                if "skip_serializing" not in attrs and "skip_deserializing" not in attrs:
                    if re.search(r'\bskip\b', attrs):
                        continue
                r = re.search(r'rename\s*=\s*"([^"]+)"', attrs)
                a = re.search(r'alias\s*=\s*"([^"]+)"', attrs)
                if r:
                    keys.add(r.group(1))
                elif rename_all == 'camelCase':
                    keys.add(camel(fname))
                elif rename_all == 'snake_case':
                    keys.add(snake(fname))
                else:
                    keys.add(fname)
                if a:
                    keys.add(a.group(1))
    return keys


def rust_literals(corpus):
    keys = set()
    for src in corpus.values():
        for m in re.finditer(r'"([A-Za-z_][A-Za-z0-9_\-]{1,45})"', src):
            keys.add(m.group(1))
    return keys


def main():
    gk, structs, rows = go_keys()
    corpus = rust_corpus()
    surface = rust_serde_keys(corpus) | rust_literals(corpus)

    no_parse = []
    for k in sorted(gk):
        if not ({k, snake(k), k.lower()} & surface):
            no_parse.append(k)

    print(f"GO_KEYS_TOTAL       = {len(gk)}   (structs={structs}, tag_rows={rows})")
    print(f"RUST_HAS_PARSE_SITE = {len(gk) - len(no_parse)}")
    print(f"RUST_NO_PARSE_SITE  = {len(no_parse)}")
    for k in no_parse:
        print("   -", k)
    return 0


if __name__ == "__main__":
    sys.exit(main())
