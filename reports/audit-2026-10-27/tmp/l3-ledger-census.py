"""L3 台账普查：per-site / 文件级 `#[allow(clippy::disallowed_methods|disallowed_macros)]` 计数。

口径（与 ledger-audit §0 同源，本脚本把口径显式化以便复跑）：
  - 范围：crates/**/*.rs，排除 crates/udf-frame（外部仓工作副本）
  - 单位：**属性**，不是 lint 名也不是行。一个多行 allow 属性计 1（内含 disallowed_methods
    与 disallowed_macros 也计 1——与 ledger-audit「per-site #[allow(clippy::disallowed_methods,…)]
    共 458 处」一致）
  - 面别：test 面 = ①路径在 crates/<c>/tests|benches|examples/ 下 ②位置落在 `#[cfg(test)]`
    或 `#[cfg(any(test,…))]` 所辖大括号块内 ③文件顶 `#![cfg_attr(test, allow(...))]`
    其余 = 生产面

用法：
  python reports/audit-2026-10-27/tmp/l3-ledger-census.py                  # 工作树（含未提交改动）
  python reports/audit-2026-10-27/tmp/l3-ledger-census.py --ref HEAD       # 指定 git ref
  python reports/audit-2026-10-27/tmp/l3-ledger-census.py --ref HEAD --classify   # 生产面按禁用项分类
  python reports/audit-2026-10-27/tmp/l3-ledger-census.py --ref HEAD --list       # 逐站清单
"""
from __future__ import annotations

import re
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
ATTR_START = re.compile(r"#!?\s*\[")
LINT_KEYS = ("clippy::disallowed_methods", "clippy::disallowed_macros")
CFG_ATTR = re.compile(r"#\s*\[\s*cfg(?!_attr)\s*\(")


# ---------------------------------------------------------------- 源码装载
def load_sources(ref: str | None) -> dict[str, str]:
    """返回 {相对路径: 文本}。ref=None 读工作树。"""
    if ref is None:
        files = {}
        for p in sorted((REPO / "crates").rglob("*.rs")):
            rel = p.relative_to(REPO).as_posix()
            if rel.startswith("crates/udf-frame/"):
                continue
            files[rel] = p.read_text(encoding="utf-8", errors="replace")
        return files

    listing = subprocess.run(
        ["git", "ls-tree", "-r", "--name-only", ref, "--", "crates"],
        cwd=REPO, capture_output=True, text=True, check=True,
    ).stdout.splitlines()
    wanted = [
        p for p in listing
        if p.endswith(".rs") and not p.startswith("crates/udf-frame/")
    ]
    proc = subprocess.run(
        ["git", "cat-file", "--batch"],
        cwd=REPO, input=("\n".join(f"{ref}:{p}" for p in wanted) + "\n").encode(),
        capture_output=True, check=True,
    )
    out = proc.stdout
    files, pos, i = {}, 0, 0
    while i < len(wanted):
        nl = out.index(b"\n", pos)
        header = out[pos:nl].decode("utf-8", "replace").split()
        pos = nl + 1
        if len(header) < 3 or header[1] != "blob":
            i += 1
            continue
        size = int(header[2])
        files[wanted[i]] = out[pos:pos + size].decode("utf-8", "replace")
        pos += size + 1
        i += 1
    return files


# ---------------------------------------------------------------- 结构解析
def find_allows(src: str) -> list[tuple[int, int, str]]:
    """返回 [(start, end, 属性内文)]，start 为 '#' 的偏移。跳过注释行中的伪属性。

    属性内文含前导 '!'（inner attribute）时保留，调用方据此分"文件顶 inner"与"per-site outer"。
    """
    hits = []
    for m in ATTR_START.finditer(src):
        start = m.start()
        line_start = src.rfind("\n", 0, start) + 1
        if "//" in src[line_start:start]:
            continue  # 行注释里举的例子
        # 括号配平：ATTR_START 已吃掉 '['，从其后开始
        depth, j = 1, m.end()
        while j < len(src) and depth:
            c = src[j]
            if c == "[":
                depth += 1
            elif c == "]":
                depth -= 1
            j += 1
        inner = src[m.end():j - 1]
        if any(k in inner for k in LINT_KEYS):
            bang = "!" if src[m.start():m.end()].strip().replace("#", "").startswith("!") else ""
            hits.append((start, j, bang + inner.lstrip()))
    return hits


def test_spans(src: str) -> list[tuple[int, int]]:
    """`#[cfg(test)]`/`#[cfg(any(test,…))]` 所辖项的字符区间（属性起点 → 块尾）。

    跨行安全：属性后可能跟 `\nmod tests {`、`\nfn x() {`、`\nuse …;`。
    """
    spans = []
    for m in CFG_ATTR.finditer(src):
        # 取 cfg(...) 的括号内文，判定是否 test 门（`not(test)` 不算）
        popen = m.end() - 1
        depth, k0 = 0, popen
        while k0 < len(src):
            if src[k0] == "(":
                depth += 1
            elif src[k0] == ")":
                depth -= 1
                if depth == 0:
                    break
            k0 += 1
        cond = src[popen + 1:k0]
        if not re.search(r"(?:^|[\s(,])test(?:\s*[,)]|$)", cond) or re.fullmatch(r"\s*not\s*\(\s*test\s*\)\s*", cond):
            continue
        # 再跨过属性自身的 ']'
        depth, j = 1, src.find("[", m.start()) + 1
        while j < len(src) and depth:
            if src[j] == "[":
                depth += 1
            elif src[j] == "]":
                depth -= 1
            j += 1
        paren = bracket = 0
        while j < len(src):
            ch = src[j]
            if ch == "(":
                paren += 1
            elif ch == ")":
                paren -= 1
            elif ch == "[":
                bracket += 1
            elif ch == "]":
                bracket -= 1
            elif paren == 0 and bracket == 0:
                if ch == "{":
                    break
                if ch == ";":
                    j = len(src)  # 无块体（use/const 等），无 span
                    break
            j += 1
        if j >= len(src) or src[j] != "{":
            continue
        depth, k = 0, j
        while k < len(src):
            if src[k] == "{":
                depth += 1
            elif src[k] == "}":
                depth -= 1
                if depth == 0:
                    break
            k += 1
        spans.append((m.start(), k + 1))
    return spans


def classify_face(path: str, src: str, start: int, inner: str, spans) -> str:
    body = inner.lstrip("!")
    if re.search(r"/tests?/", path) or "/benches/" in path or "/examples/" in path:
        return "test"
    if any(a <= start < b for a, b in spans):
        return "test"
    # 文件顶 #![cfg_attr(test, allow(clippy::disallowed_methods))]：机制性测试面豁免
    if "cfg_attr(test" in body:
        return "test"
    return "prod"


# ---------------------------------------------------------------- 站点分类
ITEM_PATTERNS = [
    ("tokio::spawn", re.compile(r"\btokio::spawn\s*\(")),
    ("tokio::task::spawn", re.compile(r"\btokio::task::spawn\s*\(")),
    ("std::thread::spawn", re.compile(r"\bthread::spawn\s*\(|\bstd::thread::spawn")),
    # Instant 两种走同一匹配、再按前缀回看区分（全限定写法很多）
    ("__instant__", re.compile(r"\bInstant::now\s*\(")),
    ("std::time::SystemTime::now", re.compile(r"\bSystemTime::now\s*\(")),
    ("to_vec 扁平化", re.compile(r"\.to_vec\s*\(|\bto_vec\s*\(")),
    ("println/eprintln", re.compile(r"\b(?:println|eprintln)!\s*\(")),
    ("tracing 宏", re.compile(r"\btracing::(?:trace|debug|info|warn|error|event)!\s*\(")),
]


def classify_item(src: str, attr_end: int, inner_attr: bool = False):
    """看属性所辖代码，按禁用项首个命中归类。

    优先取属性所辖 item 的块体（属性后第一个 '{' 起的配平块）全文扫描；无块体
    （语句位属性/let）则回退到属性后 4000 字符、且不越过下一个 allow 属性。
    """
    if inner_attr:
        # 文件级 inner：整文件聚合，无法单项归因
        return "文件级聚合（#![allow]）", -1
    tail_full = src[attr_end:attr_end + 4000].split("#[allow(clippy::")[0]
    body = tail_full
    brace = tail_full.find("{")
    semi = tail_full.find(";")
    if brace >= 0 and (semi < 0 or brace < semi):
        depth, k = 0, brace
        while k < len(tail_full):
            if tail_full[k] == "{":
                depth += 1
            elif tail_full[k] == "}":
                depth -= 1
                if depth == 0:
                    break
            k += 1
        body = tail_full[:k + 1]  # 含块前的表达式（tokio::spawn(...{..}) 形态）
    hits: list[tuple[int, str]] = []
    for name, pat in ITEM_PATTERNS:
        m = pat.search(body)
        if not m:
            continue
        if name == "__instant__":
            ctx = body[max(0, m.start() - 24):m.start()]
            name = "tokio::time::Instant::now" if "tokio::time::" in ctx else "std::time::Instant::now"
        hits.append((m.start(), name))
    if not hits:
        return "未识别", 0
    hits.sort()
    return hits[0][1], len({n for _, n in hits})


def crate_of(path: str) -> str:
    parts = path.split("/")
    return parts[1] if len(parts) > 1 else "?"


# ---------------------------------------------------------------- 主流程
def main() -> None:
    args = sys.argv[1:]
    ref = None
    if "--ref" in args:
        ref = args[args.index("--ref") + 1]
    do_class = "--classify" in args
    do_list = "--list" in args
    do_matrix = "--matrix" in args
    show_all = "--all" in args

    files = load_sources(ref)
    stat = Counter()
    matrix = Counter()  # (form, face)
    per_crate_prod: Counter = Counter()
    per_crate_test: Counter = Counter()
    per_file = Counter()
    sites = []  # (path, lineno, face, kind)

    for path, src in files.items():
        spans = test_spans(src)
        for start, end, inner in find_allows(src):
            face = classify_face(path, src, start, inner, spans)
            form = "inner(文件顶 #![..])" if inner.startswith("!") else "outer(per-site #[..])"
            kind = ("methods" if "clippy::disallowed_methods" in inner else "") + \
                   ("+macros" if "clippy::disallowed_macros" in inner else "")
            lineno = src.count("\n", 0, start) + 1
            stat[face] += 1
            matrix[(form, face)] += 1
            per_file[f"{path}:{lineno}"] = 1
            if face == "prod":
                per_crate_prod[crate_of(path)] += 1
                sites.append((path, lineno, *classify_item(src, end, inner.startswith("!")), inner))
            else:
                per_crate_test[crate_of(path)] += 1
                if show_all:
                    sites.append((path, lineno, "TEST", inner))

    label = ref or "WORKTREE"
    print(f"# L3 台账普查  ref={label}  crates/*.rs={len(files)}（排除 udf-frame）")
    print(f"TOTAL 属性数 = {stat['prod'] + stat['test']}   "
          f"生产面 = {stat['prod']}   测试面 = {stat['test']}\n")
    print("## 形态 × 面别矩阵")
    for form in ("outer(per-site #[..])", "inner(文件顶 #![..])"):
        print(f"  {form:26} prod={matrix[(form,'prod')]:4d}  test={matrix[(form,'test')]:4d}")
    print("  # 口径A（ledger-audit 458 同源）= 仅 outer per-site = "
          f"{matrix[('outer(per-site #[..])','prod')] + matrix[('outer(per-site #[..])','test')]}")
    print("  # 口径B（含文件顶 inner）= 全量 = " f"{stat['prod'] + stat['test']}\n")
    print("## 生产面 top crate")
    for c, n in per_crate_prod.most_common():
        print(f"  {n:4d}  {c}")
    print("\n## 测试面 crate（非零）")
    for c, n in per_crate_test.most_common():
        print(f"  {n:4d}  {c}")

    if do_class:
        print("\n## 生产面按禁用项分类")
        cat = Counter(s[2] for s in sites if s[2] != "TEST")
        for k, v in cat.most_common():
            print(f"  {v:4d}  {k}")

    if do_class:
        multi = sum(1 for s_ in sites if s_[3] and s_[3] > 1)
        print(f"  # 其中「所属 item 同时命中 >=2 类」的站点 = {multi}")

    if do_matrix:
        print("\n## 生产面 crate × 禁用项矩阵")
        mat: dict[str, Counter] = defaultdict(Counter)
        for path, lineno, kind, ncat, inner in sites:
            if kind == "TEST":
                continue
            mat[crate_of(path)][kind] += 1
        cats = [k for k, _ in Counter(s[2] for s in sites if s[2] != "TEST").most_common()]
        print("  crate".ljust(30) + "".join(x[:12].rjust(14) for x in cats) + "  合计")
        for cr, row in sorted(mat.items(), key=lambda kv: -sum(kv[1].values())):
            print("  " + cr.ljust(28) + "".join(str(row[x]).rjust(14) for x in cats)
                  + str(sum(row.values())).rjust(6))

    if do_list:
        print("\n## 逐站清单（生产面）")
        for path, lineno, kind, ncat, inner in sorted(sites):
            if kind == "TEST":
                continue
            one = " ".join(inner.split())[:90]
            suffix = f" (+{ncat - 1}类)" if ncat and ncat > 1 else ""
            print(f"  {path}:{lineno}  [{kind}{suffix}]  {one}")


if __name__ == "__main__":
    main()
