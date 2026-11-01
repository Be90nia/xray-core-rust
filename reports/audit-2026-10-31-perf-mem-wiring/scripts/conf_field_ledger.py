#!/usr/bin/env python3
"""Denominator + ledger for the xray-conf field wiring audit.

Pipeline under audit (three hops, any of which can drop a field):
  hop1  JSON -> xray-conf typed struct      (`Config`, `app_config`, `protocols`, `common`)
  hop2  typed struct -> BuiltEntry.data JSON (`Config::build` re-serializes)
  hop3  JSON -> runtime crate struct -> runtime behaviour

Effective JSON key per field accounts for `#[serde(rename_all = "...")]` (camelCase /
snake_case / lowercase), explicit `rename`, and aliases.

Classification of each field:
  JSON field   : struct derives Deserialize -> key is what a config file must use.
  INTERNAL     : built.rs artifacts / build products -> consumed by Rust field access only.

Consumption probe:
  prod_json   quoted literal of the effective key (or alias) anywhere outside xray-conf,
              outside test regions  -> proves some runtime struct/`get()` reads that key
  prod_ident  rust identifier outside xray-conf / tests -> weak signal, evidence only

Writes fields.json (denominator) + ledger.json (full per-field record).
Usage: python conf_field_ledger.py
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))

STRUCT_RE = re.compile(r"^\s*pub struct\s+(\w+)")
FIELD_RE = re.compile(r"^\s*pub (r#)?(\w+)\s*:")
RENAME_RE = re.compile(r'rename\s*=\s*"([^"]+)"')
ALIAS_RE = re.compile(r'alias\s*=\s*"([^"]+)"')
RENAME_ALL_RE = re.compile(r'rename_all\s*=\s*"([^"]+)"')
WORD = re.compile(r"[A-Za-z0-9_]+")

INTERNAL_STRUCTS = {"BuiltEntry", "BuiltInbound", "BuiltOutbound", "BuiltConfig"}


def camel(name):
    parts = name.split("_")
    return parts[0] + "".join(p[:1].upper() + p[1:] for p in parts[1:])


def apply_rename_all(name, mode):
    if mode is None:
        return name
    if mode == "camelCase":
        return camel(name)
    if mode == "snake_case":
        return name
    if mode == "lowercase":
        return name.lower()
    return name


def split_structs(path):
    with open(path, encoding="utf-8") as fh:
        lines = fh.readlines()
    cur = None
    depth = 0
    pending = ""      # attribute lines buffered for the next struct/field
    for idx, raw in enumerate(lines, 1):
        line = "" if raw.strip().startswith("//") else raw.split("//")[0]
        m = STRUCT_RE.match(line)
        if m:
            # `pending` holds the derive/attr lines that preceded `pub struct`
            cur = {"struct": m.group(1), "file": path, "line": idx, "fields": [],
                   "rename_all": None, "serde": False, "has_flatten": False,
                   "has_deny_unknown": False}
            blob = pending + line
            ra = RENAME_ALL_RE.search(blob)
            if ra:
                cur["rename_all"] = ra.group(1)
            for dm in re.finditer(r"derive\s*\(([^)]*)\)", blob):
                if "Deserialize" in dm.group(1):
                    cur["serde"] = True
            pending = ""
            depth = 0
        if cur is None:
            if re.match(r"^\s*#\[", line):
                pending += line
            elif line.strip():
                pending = ""
            continue
        if "flatten" in line:
            cur["has_flatten"] = True
        if "deny_unknown_fields" in line:
            cur["has_deny_unknown"] = True
        fm = FIELD_RE.match(line)
        if fm:
            blob = pending + line
            rm = RENAME_RE.search(blob)
            cur["fields"].append({"rust": fm.group(2), "rename": rm.group(1) if rm else None,
                                  "aliases": re.findall(r'alias\s*=\s*"([^"]+)"', blob),
                                  "line": idx})
            pending = ""
        elif re.match(r"^\s*#\[", line):
            pending += line
        elif line.strip():
            pending = ""
        opens = line.count("{") - line.count("}")
        if depth == 0 and "{" in line:
            depth = opens
        elif depth > 0:
            depth += opens
            if depth <= 0:
                yield cur
                cur = None
                depth = 0
                pending = ""
    if cur is not None:
        yield cur


def rust_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in (".git", "target", "vendor", "docs")
                       and not d.startswith("target-")]
        for f in filenames:
            if f.endswith(".rs"):
                yield os.path.join(dirpath, f)


def is_test_path(rel):
    return "/tests/" in rel or rel.endswith("_test.rs") or "/benches/" in rel


def crate_of(rel):
    parts = rel.split("/")
    return parts[1] if len(parts) > 2 and parts[0] == "crates" else rel


def main():
    conf_structs = []
    for p in sorted(rust_files(os.path.join(ROOT, "crates", "xray-conf", "src"))):
        conf_structs.extend(split_structs(p))

    # index prod code: quoted literals + identifiers + runtime serde struct keys
    lit_index, ident_index, rt_key_index, access_index = {}, {}, {}, {}
    struct_ref_crates = {}
    conf_names = {st["struct"] for st in conf_structs}
    for p in rust_files(os.path.join(ROOT, "crates")):
        rel = os.path.relpath(p, ROOT).replace(os.sep, "/")
        if rel.startswith("crates/xray-conf/") or rel.startswith("crates/udf-frame/"):
            continue
        base = "test" if is_test_path(rel) else "prod"
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
            kind = "test" if (base == "test" or (test_start and i >= test_start)) else "prod"
            if kind != "prod":
                continue
            for lit in re.findall(r'"([^"\\]{1,40})"', text):
                lit_index.setdefault(lit, []).append((rel, i, text.strip()))
            toks = set(WORD.findall(text))
            for tok in toks:
                ident_index.setdefault(tok, []).append((rel, i, text.strip()))
            for m2 in re.finditer(r"\.(\w+)", text):
                access_index.setdefault(m2.group(1), []).append((rel, i, text.strip()))
            for tok in toks & conf_names:
                struct_ref_crates.setdefault(tok, set()).add(crate_of(rel))
        if base == "prod":
            # runtime structs that serde-decode the passthrough JSON: their effective
            # key names are consumption even when no string literal exists (rename_all)
            for st in split_structs(p):
                if not st["serde"]:
                    continue
                for f in st["fields"]:
                    k = f["rename"] or apply_rename_all(f["rust"], st["rename_all"])
                    rt_key_index.setdefault(k, []).append((rel, st["struct"], f["line"]))

    rows = []
    for st in conf_structs:
        internal = not st["serde"] or st["struct"] in INTERNAL_STRUCTS
        ref_crates = struct_ref_crates.get(st["struct"], set())
        for f in st["fields"]:
            eff = f["rename"] or apply_rename_all(f["rust"], st["rename_all"])
            keys = [eff] + list(f["aliases"])
            json_hits = []
            for k in keys:
                json_hits.extend(lit_index.get(k, []))
            rt_hits = []
            for k in keys:
                rt_hits.extend(rt_key_index.get(k, []))
            ident_hits = ident_index.get(f["rust"], [])
            access_hits = access_index.get(f["rust"], [])
            typed_hits = [h for h in ident_hits if crate_of(h[0]) in ref_crates]
            rows.append({
                "struct": st["struct"],
                "struct_file": os.path.relpath(st["file"], ROOT).replace(os.sep, "/"),
                "struct_line": st["line"],
                "field": f["rust"],
                "json_key": eff,
                "aliases": f["aliases"],
                "field_line": f["line"],
                "internal": internal,
                "ref_crates": sorted(ref_crates),
                "prod_json_hits": len(json_hits),
                "prod_rt_key_hits": len(rt_hits),
                "prod_typed_hits": len(typed_hits),
                "prod_ident_hits": len(ident_hits),
                "prod_access_hits": len(access_hits),
                "access_hit_detail": [f"{r}:{i}" for r, i, _ in access_hits[:6]],
                "json_hit_detail": [f"{r}:{i}" for r, i, _ in json_hits[:6]],
                "rt_key_hit_detail": [f"{r}::{s}:{i}" for r, s, i in rt_hits[:6]],
                "typed_hit_detail": [f"{r}:{i}" for r, i, _ in typed_hits[:6]],
                "ident_hit_detail": [f"{r}:{i}" for r, i, _ in ident_hits[:6]],
            })

    with open(os.path.join(HERE, "fields.json"), "w", encoding="utf-8") as fh:
        json.dump({"conf": conf_structs}, fh, indent=1, ensure_ascii=False)
    with open(os.path.join(HERE, "ledger.json"), "w", encoding="utf-8") as fh:
        json.dump(rows, fh, indent=1, ensure_ascii=False)

    json_fields = [r for r in rows if not r["internal"]]
    internal = [r for r in rows if r["internal"]]

    def wired(r):
        return r["prod_json_hits"] or r["prod_rt_key_hits"] or r["prod_typed_hits"]

    zero_json = [r for r in json_fields if not wired(r)]
    print(f"structs={len(conf_structs)} fields={len(rows)} "
          f"json_fields={len(json_fields)} internal_fields={len(internal)}")
    print(f"json fields consumed at runtime={len(json_fields) - len(zero_json)} "
          f"NOT-WIRED={len(zero_json)}")
    json_only = [r for r in json_fields if r["prod_json_hits"]]
    typed_only = [r for r in json_fields if not r["prod_json_hits"] and not r["prod_rt_key_hits"]
                  and r["prod_typed_hits"]]
    print(f"  via JSON-key literal : {len(json_only)}")
    print(f"  via runtime serde key: {len([r for r in json_fields if r['prod_rt_key_hits']])}")
    print(f"  via typed conf struct: {len(typed_only)}")
    print("\n=== NOT-WIRED: no key read, no typed field access ===")
    for r in sorted(zero_json, key=lambda r: (r["struct"], r["field_line"])):
        print(f"{r['struct']}.{r['field']:24s} key={r['json_key']:22s} "
              f"{r['struct_file'].split('/src/')[-1]}:{r['field_line']:<5d} "
              f"ref_crates={','.join(r['ref_crates']) or 'NONE'} ident_hits={r['prod_ident_hits']}")
    print("\n=== INTERNAL (built.rs artifacts) ===")
    for r in sorted(internal, key=lambda r: (r["struct"], r["field_line"])):
        print(f"{r['struct']}.{r['field']:24s} "
              f"{r['struct_file'].split('/src/')[-1]}:{r['field_line']:<5d} "
              f"access_hits={r['prod_access_hits']} {'; '.join(r['access_hit_detail'][:4])}")


if __name__ == "__main__":
    main()
