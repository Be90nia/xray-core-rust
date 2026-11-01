"""生成的站点清单（bd 86i4h 阶段2 报告附录）：只读枚举，不改源码。

分类口径（CLAUDE.md §3.5.6）：
  bare    = `tokio::spawn` / `tokio::task::spawn` / `std::thread::spawn`
  managed = `spawn_tracked` / `spawn_reaping` / `spawn_detached`

登记判定（② 豁免类）：站点行**之前**出现过 `clippy::disallowed_methods` 的 allow 属性
（fn 级属性覆盖其体内全部调用，故按「之前出现过」而非「紧邻」判定）。
权威闸仍是 `cargo clippy --workspace --all-targets -- -D warnings`（本清单只是台账）。

测试面判定：文件内最后一个 `#[cfg(test)]` 之后、或位于 `tests/` 目录 = 测试面
（不在坑约束 5 的 CI 闸范围）。

用法：python 86i4h_site_inventory.py > inventory.txt
"""
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
CRATES = os.path.join(ROOT, "crates")
SKIP = {os.path.normpath(os.path.join(CRATES, "udf-frame"))}

BARE = re.compile(r"(?<!/)(tokio::spawn|tokio::task::spawn|std::thread::spawn)\s*\(")
MANAGED = re.compile(r"(spawn_tracked|spawn_reaping|spawn_detached)\s*\(")
ALLOW = "clippy::disallowed_methods"


def rust_files():
    for crate in sorted(os.listdir(CRATES)):
        cdir = os.path.join(CRATES, crate)
        if os.path.normpath(cdir) in SKIP or not os.path.isdir(cdir):
            continue
        for sub in ("src", "tests", "benches"):
            base = os.path.join(cdir, sub)
            if not os.path.isdir(base):
                continue
            for dirpath, _d, filenames in os.walk(base):
                for fn in sorted(filenames):
                    if fn.endswith(".rs"):
                        yield os.path.relpath(os.path.join(dirpath, fn), ROOT)


def scan(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8", errors="replace") as f:
        lines = f.read().splitlines()
    cfg_test = [i for i, l in enumerate(lines) if l.strip().startswith("#[cfg(test)]")]
    last_cfg = cfg_test[-1] if cfg_test else None
    is_test_dir = os.sep + "tests" + os.sep in rel or os.sep + "benches" + os.sep in rel

    # allow 登记点：位置 -> reason 摘录
    allow_at = []
    for i, l in enumerate(lines):
        if ALLOW in l:
            block = "\n".join(lines[i:i + 4])
            m = re.search(r'reason\s*=\s*"([^"]{0,110})', block)
            allow_at.append((i, m.group(1) if m else "（无 reason）"))

    bare, managed = [], []
    for i, line in enumerate(lines):
        stripped = line.lstrip()
        if stripped.startswith("//") or stripped.startswith("*"):
            continue
        code = line.split("//", 1)[0]
        for rx, bucket in ((BARE, bare), (MANAGED, managed)):
            if not rx.search(code):
                continue
            prior = [r for (ln, r) in allow_at if ln < i]
            bucket.append(
                {
                    "line": i + 1,
                    "code": stripped[:88],
                    "test": is_test_dir or (last_cfg is not None and i > last_cfg),
                    "registered": bool(prior),
                    "reason": prior[-1] if prior else "",
                }
            )
    return bare, managed


def main():
    bare_prod, bare_test, managed_all = [], [], []
    for rel in rust_files():
        bare, managed = scan(rel)
        for row in bare:
            (bare_test if row["test"] else bare_prod).append(dict(row, file=rel))
        for row in managed:
            managed_all.append(dict(row, file=rel))

    print("== A. 生产面裸 spawn（坑约束 5 台账）==")
    for r in sorted(bare_prod, key=lambda x: (x["file"], x["line"])):
        status = "② 已登记" if r["registered"] else "③ 违规（无 allow）"
        print(f"{r['file']}:{r['line']}\t{status}\t{r['reason'] or '-'}\t{r['code']}")
    reg = sum(1 for r in bare_prod if r["registered"])
    print(f"-- 生产面裸 spawn {len(bare_prod)} 处（已登记 {reg} / 未登记 {len(bare_prod) - reg}）")

    print("\n== B. 测试面裸 spawn（cfg(test)/tests，不在坑约束 5 CI 闸范围）==")
    for r in sorted(bare_test, key=lambda x: (x["file"], x["line"])):
        print(f"{r['file']}:{r['line']}\t{r['code']}")
    print(f"-- 测试面裸 spawn {len(bare_test)} 处")

    print("\n== C. 托管面站点（spawn_tracked / spawn_reaping / spawn_detached）==")
    for r in sorted(managed_all, key=lambda x: (x["file"], x["line"])):
        print(f"{r['file']}:{r['line']}\t{r['code']}")
    print(f"-- 托管面 {len(managed_all)} 处")


if __name__ == "__main__":
    main()
