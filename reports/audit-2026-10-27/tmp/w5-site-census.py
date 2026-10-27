"""W5 面3步3：tokio 预算站点 HEAD 普查（剥离 #[cfg(test)] 模块后计数）。

用法: python w5-site-census.py <git-ref>
输出: 每 crate 每文件的生产 tokio 预算站点清单。
"""
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
CRATES = [
    "xray-proxy-tuic",
    "xray-proxy-vless",
    "xray-proxy-vmess",
    "xray-transport",
]

# tokio 预算面站点：取时点 + 超时包装 + 绝对截止点消费
SITE_RE = re.compile(
    r"tokio::time::Instant::now\(\)"
    r"|tokio::time::timeout(_at)?\s*\("
    r"|tokio::time::sleep_until\s*\("
    r"|(?<![:\w])Instant::now\(\)"
    r"|(?<![:\w])timeout_at\s*\("
    r"|(?<![:\w])timeout\s*\("
    r"|(?<![:\w])sleep_until\s*\("
)


def strip_test_modules(src: str) -> str:
    """把 #[cfg(test)] mod {...} 整块删掉（按大括号配平）。"""
    out = []
    i = 0
    while True:
        m = re.search(r"#\[cfg\(test\)\]", src[i:])
        if not m:
            out.append(src[i:])
            break
        start = i + m.start()
        out.append(src[i:start])
        j = src.find("{", m.end())
        if j < 0:
            break
        depth = 0
        k = j
        while k < len(src):
            if src[k] == "{":
                depth += 1
            elif src[k] == "}":
                depth -= 1
                if depth == 0:
                    break
            k += 1
        i = k + 1
    return "".join(out)


def main() -> None:
    ref = sys.argv[1] if len(sys.argv) > 1 else "HEAD"
    # 一次性取整棵树（一次 git 调用，避开逐文件 git show 的开销）
    listing = subprocess.run(
        ["git", "ls-tree", "-r", "--name-only", ref],
        cwd=REPO, capture_output=True, text=True, check=True,
    ).stdout.splitlines()
    wanted = {}
    for path in listing:
        for crate in CRATES:
            prefix = f"crates/{crate}/src/"
            if path.startswith(prefix) and path.endswith(".rs"):
                wanted.setdefault(crate, []).append(path)

    total = 0
    for crate in CRATES:
        print(f"\n=== {crate} ===")
        crate_total = 0
        for path in sorted(wanted.get(crate, [])):
            src = subprocess.run(
                ["git", "show", f"{ref}:{path}"],
                cwd=REPO, capture_output=True, text=True, check=True,
            ).stdout
            prod = strip_test_modules(src)
            hits = []
            for i, line in enumerate(prod.splitlines(), 1):
                if SITE_RE.search(line):
                    hits.append((i, line.strip()))
            if hits:
                crate_total += len(hits)
                print(f"  {path}  ({len(hits)})")
                for i, line in hits:
                    print(f"    :{i}  {line[:120]}")
        print(f"  -- {crate} 生产 tokio 预算站点 = {crate_total}")
        total += crate_total
    print(f"\nTOTAL(生产 tokio 预算站点, {ref}) = {total}")


if __name__ == "__main__":
    main()
