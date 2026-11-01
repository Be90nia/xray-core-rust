"""数值正确性静态扫描（bd Xray-core-rust-3q3h0）。

三族：
  A. 整数截断/回绕 —— 窄化 cast（`as u8/u16/u32/i8/i16/i32`）与无 saturating 的 `-=`
  B. 速率/时间除数 —— 时长或计数的除法分母未做零/负守卫
  C. 挂钟敏感点 —— 生产代码 SystemTime::now() 出现位置（回拨语义风险面）

扫描前剥离字符串/字符字面量与 `//` 注释（否则路径与 URL 里的 `/` 全是假阳性）。
`#[cfg(test)]` 之后与 tests/ 目录不扫。

用法: python <this> [--verbose]
"""
import os
import re
import sys

ROOT = "crates"
VERBOSE = "--verbose" in sys.argv

TEST_FILE = re.compile(r"(^|/)(tests?)/|(^|/)tests?\.rs$|_tests?\.rs$")

# 窄化 cast：只报「网络/数据面长度或计数」窄化，不报枚举判别 `as u8`
NARROW = re.compile(r"\bas\s+(u8|u16|i8|i16)\b")
# 窄化源：len()/count()/宽度量 —— 这些一旦超过目标宽度就被静默截断
NARROW_SRC = re.compile(
    r"(len\(\)|count\(\)|_len\b|_size\b|_bytes\b|remaining|payload|body|frame)\s*(\.min\([^)]*\))?\s*as\s+(u8|u16|i8|i16)\b"
)
# 已显式钳制的写法（min / try_from / clamp）不算缺陷
CLAMPED = re.compile(r"\.min\(|try_from|clamp\(|& 0xFF|& 0xFFFF")
DECREMENT = re.compile(r"\b[a-z_][a-z0-9_.]*\s*-=\s*")
# 除数上下文关键词：出现这些才认为该行在做速率/时长运算
RATE_CTX = re.compile(
    r"(as_secs|as_millis|as_nanos|as_secs_f64|elapsed|bps|_rate|rate_|throughput|duration|interval|delta|_window|avg|per_sec)"
)
DIV = re.compile(r"([A-Za-z_0-9).\]]+)\s*/\s*([a-z_][a-z0-9_.]*)\b")
GUARDED_DIV = re.compile(r"\.max\(|!= *0|== *0|checked_div|unwrap_or\(1|is_zero\(\)|\.max\(1")
WALLCLOCK = re.compile(r"SystemTime::now\(\)")
STRING_OR_CHAR = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')


def strip_code(text):
    """去字符串/字符字面量 + 行注释，保留行内其余结构。"""
    out = STRING_OR_CHAR.sub('""', text)
    return out.split("//")[0]


def rust_files():
    for dirpath, dirnames, files in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in {"target", "target-G10Plan", "udf-frame"}]
        for f in files:
            if f.endswith(".rs"):
                p = os.path.join(dirpath, f).replace(os.sep, "/")
                if not TEST_FILE.search(p):
                    yield p


def prod_lines(path):
    lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
    cut = next((i for i, l in enumerate(lines) if re.match(r"\s*#\[cfg\(test\)\]", l)), len(lines))
    for i in range(cut):
        yield i + 1, lines[i]


hits = {"A_narrow_len": {}, "A_decrement": {}, "B_unguarded_div": {}, "C_wallclock": {}}


def add(kind, path, ln, text):
    hits[kind].setdefault((path, ln, text), 0)


for path in rust_files():
    for ln, raw in prod_lines(path):
        code = strip_code(raw)
        if WALLCLOCK.search(code):
            add("C_wallclock", path, ln, raw.strip())
        if NARROW_SRC.search(code) and not CLAMPED.search(code):
            add("A_narrow_len", path, ln, raw.strip())
        if DECREMENT.search(code) and "saturating" not in code and "wrapping" not in code:
            add("A_decrement", path, ln, raw.strip())
        if RATE_CTX.search(code) and not GUARDED_DIV.search(code):
            for dm in DIV.finditer(code):
                divisor = dm.group(2)
                if divisor in {"as", "let", "self"}:
                    continue
                add("B_unguarded_div", path, ln, "%s   [分母=%s]" % (raw.strip(), divisor))

total = sum(len(v) for v in hits.values())
print("=" * 78)
print("数值正确性静态扫描（生产代码；已剥字符串/注释/测试段）  命中合计 %d" % total)
print("=" * 78)
for kind in ("A_narrow_len", "A_decrement", "B_unguarded_div", "C_wallclock"):
    rows = sorted(hits[kind].keys())
    print("\n### %s : %d 处" % (kind, len(rows)))
    shown = rows if VERBOSE else rows[:25]
    for path, ln, text in shown:
        print("  %s:%d  %s" % (path, ln, text[:150]))
    if len(rows) > len(shown):
        print("  … 余 %d 处（--verbose 全列）" % (len(rows) - len(shown)))
