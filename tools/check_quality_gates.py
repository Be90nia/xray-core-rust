#!/usr/bin/env python3
"""je3u3 质量门四件套 —— MASTER-BACKLOG「防复发机制」表的脚本化落盘。

四道门（对应 MASTER-BACKLOG.md 门表 1-4 + CQ-04 / PM-04 / u0pe2 / er2q5 防复发）：
  (a) 失败留痕门    生产代码禁 `hot_log!(DEBUG, "error=…")` 形态——失败在默认
                    warn 门下必须可见（bd u0pe2 ① 缺陷指纹：26 处失败留痕在
                    loglevel=warn 下零痕迹）。白名单只登记有 Go 源码依据的
                    瞬断重放噪声站（splithttp packet-up replay-once，
                    Go `canRetryError` 同不打日志，重放失败由 dialer WARN 兜底）。
  (b) 抑制登记门    每个 `allow(dead_code)`（含 cfg_attr 变体）必须带理由——
                    同行尾注 / 下 2 行 / 紧邻前向注释块（er2q5 交工口径：
                    「邻接注释」双向计，前向注释不漏判）；
                    `allow(unused_imports)` 恒为 0（er2q5 14→0，零豁免）。
  (c) 登记簿漂移门  跑既有 Rust 交叉断言（登记簿常量 vs 实现值，bd sgdwm 面向
                    `xray-core::memory_budget` mod tests + `xray-frame::budget`
                    tests）——脚本只负责「CI 必跑这些断言」，断言本体不在此维护。
  (d) 注释漂移抽查  登记簿/上限类整数常量的邻接注释：注释带绑定语数字但常量值
                    的任何等价表示（十进制 / N KiB/MiB 分级 / 浮点 MiB）都不在
                    注释中 ⇒ 报漂移嫌疑。保守放行三口：值已复述 / 注释自述
                    「交叉断言」（(c) 已钉住，数字漂移有测试兜底）/ 登记簿在飞债。
                    抽查语义：启发式，误放由人审兜，误红登记后收紧。

用法（房规 check_udp_binds.py / check_proto_drift.py）：
  python tools/check_quality_gates.py             # 四道门全跑（(c) 含 cargo）
  python tools/check_quality_gates.py --no-cargo  # 只跑静态门 (a)(b)(d)（快路径）
  python tools/check_quality_gates.py --list      # 枚举 (a)(b)(d) 全部命中与分类
  python tools/check_quality_gates.py --self-test # 四道门各一条故意违反→必须报错

扫描语义（与 check_udp_binds.py 同源，直接复用其基础设施）：
- 只扫 crates/*/src/**（排除 crates/udf-frame——独立仓工作副本，纪律归 udf CI；
  排除 tests 目录与 `#[cfg(test)]` 块——测试面不属生产纪律面）。
- 命中判定在注释/字符串剥离后的文本上做（位置保持，行号不变）；理由判定
  （(b)）与注释窗口（(d)）回原文本取——剥离函数逐字符掏空、不位移。
- 已知盲区（登记，不静默）：(a) 只匹配消息字面量以 `error=` 开头的形态
  （u0pe2 判定表同口径）；`tracing::debug!`/`log::debug!` 面不在本门
  （生产留痕走 hot_log 单口，见 xray-common logx 纪律）。
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path

# 复用 d597w 门的基础设施（候选文件 / 注释与字符串剥离 / cfg(test) 剥离 /
# 行号与括号配对）——同一套扫描语义，禁在两个门脚本里各养一份 lexer。
sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_udp_binds import (  # noqa: E402  (房规工具导入)
    candidate_files,
    line_of,
    strip_cfg_test_blocks,
    strip_comments_and_strings,
)

INT_TYPES = {
    "i8", "i16", "i32", "i64", "isize",
    "u8", "u16", "u32", "u64", "usize",
}

# ---------------------------------------------------------------------------
# (a) 失败留痕门
# ---------------------------------------------------------------------------

# DEBUG 变体：`DEBUG` / `tracing::Level::DEBUG` / `Level::DEBUG`（宁误红不漏放）。
HOT_LOG_DEBUG_ERROR = re.compile(
    r"\bhot_log!\s*\(\s*(?:tracing::)?(?:Level::)?DEBUG\s*,\s*\"error"
)

# 白名单（文件级，房规同 check_udp_binds）。**只准登记「有 Go 源码依据的瞬断
# 重放噪声」**，新增白名单条目必须在报告/票面点名 Go 对位依据。
FAILURE_TRACE_WHITELIST: dict[str, str] = {
    "crates/xray-transport-splithttp/src/client.rs": (
        "u0pe2 判定表 #20：packet-up 连接级瞬断重放一次（GetBody）。Go "
        "canRetryError 路径同样不打日志；重放失败 → dialer.rs WARN 兜底 + "
        "错误上抛；提级 = 正常网络抖动刷屏"
    ),
}

# ---------------------------------------------------------------------------
# (b) 抑制登记门
# ---------------------------------------------------------------------------

ALLOW_DEAD_CODE = re.compile(r"allow\s*\(\s*dead_code\s*\)")
ALLOW_UNUSED_IMPORTS = re.compile(r"allow\s*\(\s*unused_imports\s*\)")

# 理由形态（机械代理，er2q5「邻接注释」口径）：
#   同行：属性收口 `]` 后同一行出现 `//` 且有非空文字；
#   下 2 行：属性行之后两行内，以 `//` 开头的非空注释行；
#   前向块：属性行向上紧邻的连续注释行（`//` `///` `//!`）。
COMMENT_LINE = re.compile(r"^\s*//")
TRAILING_COMMENT = re.compile(r"//")

# 临时登记：实测裸 allow（待清债，不属本票面——er2q5 已交工，发现即登记放行并
# 在报告列 file:line）。键 = f"{文件}#{宿主符号}"（宿主符号提取失败时用行号键）。
ALLOW_DEBT_REGISTRY: dict[str, str] = {}

# ---------------------------------------------------------------------------
# (d) 注释漂移抽查门
# ---------------------------------------------------------------------------

CONST_ITEM = re.compile(
    r"(?:^|\n)[ \t]*(?:pub(?:\([^)]*\))?[ \t]+)?const\s+"
    r"([A-Z_][A-Z0-9_]*)[ \t]*:[ \t]*([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*([^;\n]+);"
)
SIMPLE_INT_EXPR = re.compile(r"^\s*\d[\d_]*\s*(?:(?:<<|\*|\+|-)\s*\d[\d_]*\s*)*$")

# 绑定语关键词：注释里数字与「上限/缺省/预算」类断言词相邻才算对常量值的声明
# （抽查降噪：纯历史叙事/估算旁注/引用编号不算绑定）。
BINDING_KEYWORD_WORDS = (
    "上限|上界|硬顶|至多|最多|不超过|缺省|默认|容量|预算|账面|合计|配额|并发|条数|条目"
)
BINDING_KEYWORD = re.compile(BINDING_KEYWORD_WORDS)
# 数字 + 可选单位（含浮点 MiB 形态，如「≈ 2.5MiB」）；单位组含时间拼写
# （s/秒/ms——按常量名后缀选时间制或字节制换算）。
UNIT_GROUP = r"KiB|MiB|GiB|KB|MB|GB|B|sec|ms|s|秒"
NUM_WITH_UNIT = re.compile(rf"(\d[\d,_.]*)[ \t]*({UNIT_GROUP})?")
FLOAT_WITH_UNIT = re.compile(rf"(\d+\.\d+)[ \t]*({UNIT_GROUP})")
# 绑定语数字：关键词后 0-6 个非数字字符内的数字（含单位）。关键词在数字**后**
# （如「8 条」）不构成对值的声明，不取。
BINDING_NUM = re.compile(
    r"(?:" + BINDING_KEYWORD_WORDS + r")[^\d]{0,6}(\d[\d,_.]*)[ \t]*(" + UNIT_GROUP + r")?"
)
# 引用/日期/票号剥离：RFC 编号 / bd·票号 / commit / 日期 / 版本号 / 字母开头的
# 混合 token（IPv4、x25519、sha256、wz2b、b2og、uwq9n）不是常量值声明（抽查降噪）。
CITATION = re.compile(
    r"(?:RFC|rfc|bd|CVE|§|票|commit|version|rev)[#: ]*[A-Za-z]*\d[\w]*"
    r"|\d{4}-\d{2}-\d{2}"
    r"|v\d+(?:\.\d+)*"
    r"|\b[A-Za-z]{1,6}\d[\da-zA-Z]*\b"
)

UNIT_BYTES: dict[str, int] = {
    "": 1, "B": 1,
    "KiB": 1024, "KB": 1024,
    "MiB": 1024**2, "MB": 1024**2,
    "GiB": 1024**3, "GB": 1024**3,
}
# 时间制：常量名后缀 _MS / _SECS 选定基准单位，注释里的 s/秒/ms 按同一制换算。
TIME_NAME = re.compile(r"_(MS|SECS|SECONDS|SECS)$")
TIME_UNITS_MS: dict[str, int] = {
    "": 1, "ms": 1, "s": 1000, "sec": 1000, "秒": 1000,
    "m": 60_000, "min": 60_000, "分": 60_000,
}
TIME_UNITS_S: dict[str, int] = {
    "": 1, "s": 1, "sec": 1, "秒": 1,
    "m": 60, "min": 60, "分": 60,
}

CROSS_ASSERT_MARK = "交叉断言"


def units_for(name: str) -> dict[str, int]:
    """按常量名后缀选单位制：字节制（缺省）或时间制（_MS / _SECS 族）。"""
    m = TIME_NAME.search(name)
    if m is None:
        return UNIT_BYTES
    return TIME_UNITS_MS if m.group(1) == "MS" else TIME_UNITS_S

# 临时登记：实测注释漂移嫌疑（⚠️ CommentDrift 代理正在同批修注释漂移——本票
# 只建门 + 登记，不改任何 rust 文件；其交工后清空本登记簿收紧）。
# 键 = f"{文件}#{常量名}"；值 = 裁定理由。分两类：
#   【已裁定·注释正确】启发式假阳（值是注释数字的算术合成/叙事口径，逐一人工核证），
#     收紧时逐条复议；
#   【在飞债】CommentDrift 待修站点（本轮无）。
COMMENT_DRIFT_REGISTRY: dict[str, str] = {
    "crates/xray-app-dispatcher/src/udp_session.rs#DUPLEX_BUF": (
        "已裁定·注释正确：256KiB = 单包 65535 + 帧头 + 多包裕量（「留多包裕量」"
        "明示非 1:1 对应；4× 头寸）。值非注释单数直达，属容量推导注释"
    ),
    "crates/xray-app-dns/src/dnscommon.rs#RECV_MAX": (
        "已裁定·注释正确：65535 = 2B 长度前缀的表示上界（2^16−1）；「2B」指"
        "前缀宽度不是值本身"
    ),
    "crates/xray-proxy-tuic/src/client.rs#DEFAULT_STREAM_RECEIVE_WINDOW": (
        "已裁定·注释正确：1.25MB 是 quinn 缺省流收窗（被本常量覆盖的旧值，"
        "bd wp9o 高 BDP 窗钉叙事），本常量 16MiB 为覆盖值；历史叙事非本值声明"
    ),
    "crates/xray-proxy-vmess/src/inbound/chunk_stream.rs#PAYLOAD_MAX": (
        "已裁定·注释正确：8176 = 8KiB 池块 − AEAD tag 16B（tag 长度在邻接"
        "常量面，窗口内未复述数字）"
    ),
    "crates/xray-transport-hysteria/src/salamander_socket.rs#MAX_WIRE_DATAGRAM": (
        "已裁定·注释正确：65544 = QUIC max_udp_payload_size 64KiB + salt 8B"
        "（salt 长度在下一常量 smSaltLen 注释面，窗口内未复述数字）"
    ),
}

# ---------------------------------------------------------------------------
# (c) 登记簿漂移门——跑既有 Rust 交叉断言（断言本体住 xray-core::memory_budget
# mod tests 与 xray-frame::budget tests；改任一实现值即红，脚本只负责必跑）。
# ---------------------------------------------------------------------------

LEDGER_CROSS_ASSERT_TARGETS: list[list[str]] = [
    ["cargo", "test", "-p", "xray-core", "memory_budget"],
    ["cargo", "test", "-p", "xray-frame", "--lib", "budget"],
]


# ---------------------------------------------------------------------------
# 扫描基础设施
# ---------------------------------------------------------------------------

def strip_comments_keep_strings(src: str) -> str:
    """逐字符掏空注释（// 与 /* */），字符串/字符字面量**原样保留**、位置不变。

    (a) 门专用：指纹 `hot_log!(DEBUG, "error=…")` 的 `error=` 在字符串字面量里，
    字符串不能掏空；注释必须掏空（doc 注释里提到该形态不算命中）。
    字符串里的 `//`（如 "https://…"）不误判为注释——状态机跳过字符串体。
    """
    out = list(src)
    i, n = 0, len(src)
    NORMAL, LINE_C, BLOCK_C = range(3)
    state = NORMAL
    while i < n:
        c = src[i]
        if state == NORMAL:
            if src.startswith("//", i):
                state = LINE_C
                out[i] = out[i + 1] = " "
                i += 2
                continue
            if src.startswith("/*", i):
                state = BLOCK_C
                out[i] = out[i + 1] = " "
                i += 2
                continue
            if c == '"':  # 字符串体原样跳过（含转义）
                i += 1
                while i < n and src[i] != '"':
                    i += 2 if src[i] == "\\" else 1
                i += 1
                continue
            if c == "'":  # char 字面量整体跳过（生命周期 'a 只跳引号）
                m = re.match(r"'(\\.|[^\\'])'", src[i:])
                if m:
                    i += len(m.group(0))
                    continue
                i += 1
                continue
            i += 1
        elif state == LINE_C:
            if c == "\n":
                state = NORMAL
            else:
                out[i] = " "
            i += 1
        else:  # BLOCK_C
            if src.startswith("*/", i):
                out[i] = out[i + 1] = " "
                state = NORMAL
                i += 2
            else:
                if c != "\n":
                    out[i] = " "
                i += 1
    return "".join(out)


def load_production(root: Path) -> dict[Path, str]:
    """candidate_files 全量读入；返回 {路径: 原文}。

    ⚠️ candidate_files 的 `parts[1] == "udf-frame"` 排除假设**相对路径**（rglob
    在 root 为绝对路径时产出绝对路径，parts[1] 恒为盘符后第一级）——此处按
    相对 posix 路径补一道硬排除（udf-frame 独立仓，纪律归 udf CI）。
    """
    out: dict[Path, str] = {}
    for rs in candidate_files(root):
        r = rs.relative_to(root).as_posix()
        if r.startswith("crates/udf-frame/") or r.startswith("udf-frame/"):
            continue
        try:
            out[rs] = rs.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
    return out


def production_clean(root: Path, raw: dict[Path, str]) -> dict[Path, str]:
    """注释+字符串掏空、cfg(test) 块剥离后的生产面文本（(b)/(d) 命中面）。"""
    out: dict[Path, str] = {}
    for rs, src in raw.items():
        out[rs] = strip_cfg_test_blocks(strip_comments_and_strings(src))[0]
    return out


def rel(root: Path, p: Path) -> str:
    return p.relative_to(root).as_posix()


# ---------------------------------------------------------------------------
# (a) 扫描
# ---------------------------------------------------------------------------

def scan_failure_traces(root: Path, whitelist: dict[str, str] | None = None) -> list[dict]:
    """生产代码 `hot_log!(DEBUG, "error=…")` 命中（白名单文件按登记分类）。

    --self-test 复用本函数（whitelist 注入临时夹具白名单，房规同 check_udp_binds）。
    """
    whitelist = FAILURE_TRACE_WHITELIST if whitelist is None else whitelist
    hits: list[dict] = []
    for rs, src in load_production(root).items():
        cleaned = strip_cfg_test_blocks(strip_comments_keep_strings(src))[0]
        for m in HOT_LOG_DEBUG_ERROR.finditer(cleaned):
            r = rel(root, rs)
            hits.append({
                "file": r,
                "line": line_of(cleaned, m.start()),
                "kind": "WHITELISTED" if r in whitelist else "PRODUCTION",
                "reason": whitelist.get(r, ""),
            })
    return hits


# ---------------------------------------------------------------------------
# (b) 扫描
# ---------------------------------------------------------------------------

def attr_span(cleaned: str, hit_start: int) -> tuple[int, int] | None:
    """命中点所属属性的 [ ] 跨度（`allow(...)` 所在的那一层方括号）。"""
    open_idx = cleaned.rfind("[", 0, hit_start)
    if open_idx == -1:
        return None
    depth = 0
    for j in range(open_idx, len(cleaned)):
        if cleaned[j] == "[":
            depth += 1
        elif cleaned[j] == "]":
            depth -= 1
            if depth == 0:
                return open_idx, j + 1
    return None


def has_reason(src: str, span: tuple[int, int]) -> bool:
    """er2q5「邻接注释」三形态：同行尾注 / 下 2 行注释行 / 紧邻前向注释块。"""
    start, end = span
    first_line = line_of(src, start)
    last_line = line_of(src, end - 1)
    # 1) 同行尾注：属性收口后同一行出现 `//` 且有文字
    line_end = src.find("\n", end)
    if line_end == -1:
        line_end = len(src)
    tail = src[end:line_end]
    tpos = tail.find("//")
    if tpos != -1 and tail[tpos + 2:].strip():
        return True
    lines = src.split("\n")
    # 2) 下 2 行：以 // 开头的非空注释行
    for k in range(last_line, min(last_line + 2, len(lines))):
        if COMMENT_LINE.match(lines[k]) and lines[k].strip().removeprefix("//").strip():
            return True
    # 3) 前向块：属性行向上紧邻的连续注释行（≥1 行非空）
    k = first_line - 2  # 0-based 上一行
    while k >= 0 and COMMENT_LINE.match(lines[k]):
        if lines[k].strip().removeprefix("//").strip():
            return True
        k -= 1
    return False


def subject_ident(src: str, span: tuple[int, int]) -> str:
    """allow 宿主符号名（登记簿键用；解析失败退化为行号键）。"""
    _, end = span
    tail = src[end:]
    tail = re.sub(r"\s*#\[[^\]]*\]", "", tail)  # 跳过属性链上后续属性
    m = re.match(
        r"\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?"
        r"(?:fn|struct|enum|union|const|static|mod|trait|type|let)?\s*"
        r"([A-Za-z_][A-Za-z0-9_]*)",
        tail,
    )
    return m.group(1) if m else f"@line{line_of(src, end)}"


def scan_suppressions(root: Path) -> dict[str, list[dict]]:
    """生产面 allow(dead_code) 全量 + 裸 allow（无邻接理由）+ unused_imports。"""
    raw = load_production(root)
    all_hits: list[dict] = []
    bare: list[dict] = []
    unused: list[dict] = []
    for rs, src in raw.items():
        cleaned = strip_cfg_test_blocks(strip_comments_and_strings(src))[0]
        r = rel(root, rs)
        for m in ALLOW_DEAD_CODE.finditer(cleaned):
            span = attr_span(cleaned, m.start())
            if span is None:
                continue
            reasonless = not has_reason(src, span)
            entry = {
                "file": r,
                "line": line_of(cleaned, m.start()),
                "ident": subject_ident(src, span),
                "bare": reasonless,
            }
            all_hits.append(entry)
            if reasonless:
                bare.append(entry)
        for m in ALLOW_UNUSED_IMPORTS.finditer(cleaned):
            unused.append({"file": r, "line": line_of(cleaned, m.start())})
    return {"all": all_hits, "bare": bare, "unused": unused}


# ---------------------------------------------------------------------------
# (d) 扫描
# ---------------------------------------------------------------------------

def eval_int_expr(expr: str) -> int | None:
    """纯整数字面量四则/移位（const 求值的安全子集）；其余形态拒判。"""
    if not SIMPLE_INT_EXPR.match(expr):
        return None
    try:
        node = ast_literal(expr)
    except (ValueError, SyntaxError):
        return None
    return node


def ast_literal(expr: str) -> int:
    """安全的整数字面量算术求值（只允许已由 SIMPLE_INT_EXPR 过滤的形态）。"""
    tokens = re.findall(r"\d[\d_]*|<<|\*|\+|-", expr)
    # Python eval 对 1 << 20 / 2 * 1024 * 1024 与 Rust 同义（此形态无除法/浮点）
    text = " ".join(t.replace("_", "") for t in tokens)
    for tok in text.split():
        if tok not in {"<<", "*", "+", "-"} and not tok.isdigit():
            raise ValueError(tok)
    return int(eval(text))  # noqa: S307  (形态已被 SIMPLE_INT_EXPR + 白名单算符钉死)


def comment_numbers(comment: str, units: dict[str, int]) -> set[int]:
    """注释里的数字（含浮点+单位按单位制换算成基准值；纯数字去分隔符）。

    浮点形态（`≈ 2.5MiB`）优先吞掉其覆盖区间，避免把 `2.5` 拆成 `2` 和 `5MiB`
    两个假数字；单位制由常量名后缀决定（字节制/时间制）。
    """
    vals: set[int] = set()
    covered: list[tuple[int, int]] = []
    for m in FLOAT_WITH_UNIT.finditer(comment):
        v = parse_count(m.group(1), m.group(2), units)
        if v is not None:
            vals.add(v)
        covered.append(m.span())
    for m in NUM_WITH_UNIT.finditer(comment):
        if any(m.start() < e and m.end() > s for s, e in covered):
            continue  # 已被浮点形态覆盖
        v = parse_count(m.group(1), m.group(2), units)
        if v is not None:
            vals.add(v)
    return vals


def compositions(numbers: set[int], target: int) -> bool:
    """值 = 注释数字的算术合成（两/三数的和差积商）——覆盖本仓惯用的
    「取整留余量 / 头+载荷 / 16×4KiB / 65535−28」式取值注释。"""
    nums = sorted(numbers)
    if target in nums:
        return True
    for a in nums:
        for b in nums:
            if a == b:
                continue
            if target in (a + b, a - b, a * b) or (b and target == a // b and a % b == 0):
                return True
    for i, a in enumerate(nums):
        for j, b in enumerate(nums):
            if i == j:
                continue
            for c in nums[i + 1:]:
                if c in (a, b):
                    continue
                if target in (a + b + c, a * b * c, a + b - c, a * b + c):
                    return True
    return False


def comment_window(src: str, item_start: int, item_end: int) -> str:
    """常量的邻接注释窗口：紧邻上方的连续注释行 + 同行 `;` 后尾注。"""
    lines = src.split("\n")
    first_line = line_of(src, item_start)
    block: list[str] = []
    k = first_line - 2  # 0-based 上一行
    while k >= 0 and COMMENT_LINE.match(lines[k]):
        block.append(lines[k])
        k -= 1
    line_end = src.find("\n", item_end)
    if line_end == -1:
        line_end = len(src)
    tail = src[item_end:line_end]
    tpos = tail.find("//")
    if tpos != -1:
        block.append(tail[tpos:])
    return "\n".join(reversed(block))


def parse_count(token: str, unit: str | None, units: dict[str, int]) -> int | None:
    """数字 token（整数或小数）× 单位 → 基准单位值。

    单位不在本常量的单位制里（如字节制常量注释里出现 `300s`）按无单位裸数
    处理；非整结果（秒制下的 500ms）不可能等于整数常量值，返回 None 跳过。
    """
    t = token.replace("_", "").strip(".,")
    mult = units.get(unit or "")
    if mult is None:
        mult = units[""]
    try:
        val = float(t) * mult
    except ValueError:  # 多重点等非数字形态（如 1.2.3）
        return None
    return int(val) if val == int(val) else None


def binding_numbers(comment: str, units: dict[str, int]) -> set[int]:
    """绑定语数字：上限/缺省/预算类关键词紧邻（≤6 非数字字符）的数字×单位。"""
    vals: set[int] = set()
    for m in BINDING_NUM.finditer(comment):
        v = parse_count(m.group(1), m.group(2), units)
        if v is not None:
            vals.add(v)
    return vals


def scan_comment_drift(root: Path, raw: dict[Path, str], cleaned_map: dict[Path, str]) -> list[dict]:
    """登记簿/上限类整数常量：绑定语声明的数字与常量值不一致 ⇒ 嫌疑。

    判定顺序（抽查精度优先）：
      ① 引用剥离（RFC/bd 票号/日期）后注释无数字 → 不判；
      ② 值的任何等价表示（十进制/分级单位/浮点 MiB）在注释任一处复述 → 放行；
      ③ 注释自述「交叉断言」→ 放行（(c) 门测试兜住值漂移，注释数字不担保真）；
      ④ 无绑定语声明（关键词紧邻的数字）→ 不判（纯叙事/旁注属人审面）；
      ⑤ 绑定语数字与值一致 → 放行；否则 → 嫌疑。
    """
    suspects: list[dict] = []
    for rs in cleaned_map:
        cleaned = cleaned_map[rs]
        src = raw[rs]
        r = rel(root, rs)
        for m in CONST_ITEM.finditer(cleaned):
            name, ty, expr = m.group(1), m.group(2), m.group(3)
            if ty not in INT_TYPES:
                continue
            v = eval_int_expr(expr)
            if v is None or v < 0:
                continue
            # CONST_ITEM 以 (?:^|\n) 起配：起点可能是常量行上一行的换行符本身，
            # 行号与注释窗口都要跳过它，否则差一行（前向注释块会取空）。
            lead = 1 if cleaned[m.start()] == "\n" else 0
            item_start, item_end = m.start() + lead, m.end()
            # 原文取窗口：cleaned 与 src 位置一致，但 cleaned 里注释已掏空——
            # 用命中行的行号回原文取块。
            window = comment_window(src, item_start, item_end)
            if not re.search(r"\d", window):
                continue
            plain = CITATION.sub(" ", window)
            units = units_for(name)
            all_nums = comment_numbers(plain, units)
            if not all_nums:
                continue
            if v in all_nums or compositions(all_nums, v):
                continue  # ② 值已复述（含算术合成：头+载荷 / 16×4KiB / 65535−28）
            if CROSS_ASSERT_MARK in window:
                continue  # ③ (c) 门已钉住
            binding = binding_numbers(plain, units)
            if not binding:
                continue  # ④ 无绑定语声明，人审面
            if v in binding or compositions(binding, v):
                continue  # ⑤ 绑定一致
            key = f"{r}#{name}"
            entry = {
                "file": r,
                "line": line_of(cleaned, item_start),
                "const": name,
                "value": v,
                "comment_numbers": sorted(all_nums),
                "binding_numbers": sorted(binding),
                "registered": key in COMMENT_DRIFT_REGISTRY,
                "reason": COMMENT_DRIFT_REGISTRY.get(key, ""),
            }
            suspects.append(entry)
    return suspects


# ---------------------------------------------------------------------------
# 门执行
# ---------------------------------------------------------------------------

def gate_a(root: Path) -> tuple[bool, str]:
    hits = scan_failure_traces(root)
    prod = [h for h in hits if h["kind"] == "PRODUCTION"]
    lines = []
    if prod:
        lines.append(f"FAIL (a) 失败留痕门：生产代码 `hot_log!(DEBUG, \"error=…\")` {len(prod)} 处：")
        for h in prod:
            lines.append(f"  {h['file']}:{h['line']}")
            lines.append("    → 失败必须默认 warn 门可见：提级 WARN（逐包加限频）或给出 Go 对位依据进白名单")
        wl = [h for h in hits if h["kind"] == "WHITELISTED"]
        lines.append(f"  （白名单放行 {len(wl)} 处：{'; '.join(sorted({h['file'] for h in wl}))}）")
        return False, "\n".join(lines)
    wl = [h for h in hits if h["kind"] == "WHITELISTED"]
    return True, (
        f"OK (a) 失败留痕门：生产代码零 DEBUG error= 留痕"
        f"（白名单 {len(wl)} 处：{'; '.join(sorted({h['file'] for h in wl})) or '无'}）"
    )


def gate_b(root: Path) -> tuple[bool, str]:
    res = scan_suppressions(root)
    lines = []
    registered = []
    for b in res["bare"]:
        key = f"{b['file']}#{b['ident']}"
        if key in ALLOW_DEBT_REGISTRY:
            registered.append(b)
        else:
            lines.append(f"  {b['file']}:{b['line']}  ({b['ident']})")
    unregistered = len(res["bare"]) - len(registered)
    if res["unused"] or unregistered:
        if res["unused"]:
            lines.insert(0, f"FAIL (b) 抑制登记门：allow(unused_imports) {len(res['unused'])} 处（恒 0）：")
            for u in res["unused"]:
                lines.insert(1, f"  {u['file']}:{u['line']}")
        if unregistered:
            lines.append(
                f"FAIL (b) 抑制登记门：裸 allow(dead_code)（无邻接理由）{unregistered} 处："
            )
        return False, "\n".join(lines)
    debt = ", ".join(f"{b['file']}:{b['line']}({b['ident']})" for b in registered) or "无"
    return True, (
        f"OK (b) 抑制登记门：allow(dead_code) {len(res['all'])} 处全部带邻接理由"
        f"（裸 0；临时登记放行 {len(registered)}：{debt}）；allow(unused_imports)=0"
    )


def gate_d(root: Path) -> tuple[bool, str]:
    raw = load_production(root)
    cleaned_map = production_clean(root, raw)
    suspects = scan_comment_drift(root, raw, cleaned_map)
    unreg = [s for s in suspects if not s["registered"]]
    reg_keys = {f"{s['file']}#{s['const']}" for s in suspects}
    stale = [k for k in COMMENT_DRIFT_REGISTRY if k not in reg_keys]
    lines = []
    if stale:
        lines.append(
            f"WARN (d)：登记簿陈旧条目（嫌疑已消失，可删除）：{'; '.join(stale)}"
        )
    if unreg:
        lines.append(f"FAIL (d) 注释漂移抽查门：绑定语声明的数字与常量值不一致（未登记）{len(unreg)} 处：")
        for s in unreg:
            lines.append(
                f"  {s['file']}:{s['line']}  {s['const']} = {s['value']}"
                f"  绑定数字={s['binding_numbers']}  注释数字={s['comment_numbers']}"
            )
    reg = [s for s in suspects if s["registered"]]
    if unreg:
        if reg:
            lines.append(f"  （登记簿放行 {len(reg)} 处）")
        return False, "\n".join(lines)
    debt = "; ".join(f"{s['file']}:{s['line']} {s['const']}" for s in reg) or "无"
    ok_msg = (
        f"OK (d) 注释漂移抽查门：整数常量注释数字与值一致（嫌疑 0；"
        f"登记簿放行 {len(reg)}：{debt}）"
    )
    if stale:
        return True, ok_msg + "\n" + "\n".join(lines)
    return True, ok_msg


def gate_c(run_cargo: bool) -> tuple[bool, str]:
    if not run_cargo:
        return True, "SKIP (c) 登记簿漂移门：--no-cargo（静态快路径不含 cargo 面）"
    lines = []
    for cmd in LEDGER_CROSS_ASSERT_TARGETS:
        print(f"  → {' '.join(cmd)}")
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        except subprocess.TimeoutExpired:
            lines.append(f"FAIL (c): {' '.join(cmd)} 超时 1800s")
            return False, "\n".join(lines)
        tail = "\n".join((proc.stdout + proc.stderr).strip().splitlines()[-12:])
        if proc.returncode != 0:
            lines.append(f"FAIL (c): {' '.join(cmd)} exit {proc.returncode}")
            lines.append(tail)
            return False, "\n".join(lines)
        lines.append(f"  exit 0: {tail.splitlines()[-1] if tail.strip() else ''}")
    return True, "OK (c) 登记簿漂移门：交叉断言全绿\n" + "\n".join(lines)


# ---------------------------------------------------------------------------
# --self-test：四道门各一条「故意违反 → 脚本报错」用例（AC#3，形态照
# check_udp_binds.py --self-test 的临时树 + 断言式）。
# ---------------------------------------------------------------------------

def cmd_self_test() -> int:
    ok = True
    with tempfile.TemporaryDirectory(prefix="qgates-") as td:
        troot = Path(td)
        src = troot / "crates" / "fx" / "src"
        src.mkdir(parents=True)

        # (a) 故意违反：DEBUG error= 留痕必须命中；非 error 的 DEBUG 与白名单文件必须放行
        (src / "bad_trace.rs").write_text(
            'fn f(e: String) {\n'
            '    crate::hot_log!(DEBUG, "error={e} doh post failed");\n'
            '}\n',
            encoding="utf-8",
        )
        (src / "ok_trace.rs").write_text(
            'fn g(e: String) {\n'
            '    crate::hot_log!(DEBUG, "tick processed");\n'
            '    crate::hot_log!(tracing::Level::WARN, "error={e} visible at warn");\n'
            '}\n',
            encoding="utf-8",
        )
        (src / "wl.rs").write_text(
            'fn h(e: String) {\n'
            '    crate::hot_log!(\n'
            '        DEBUG,\n'
            '        "error={e} packet-up request failed on connection level, replaying once"\n'
            '    );\n'
            '}\n',
            encoding="utf-8",
        )
        test_wl = {"crates/fx/src/wl.rs": "self-test whitelist"}

        def check(label: str, cond: bool) -> None:
            nonlocal ok
            nonlocal_ok = cond
            print(f"  [{'OK' if nonlocal_ok else 'FAIL'}] {label}")
            ok &= nonlocal_ok

        hits = scan_failure_traces(troot, whitelist=test_wl)
        by = {h["file"]: h["kind"] for h in hits}
        check("(a) DEBUG error= 故意违规必须报", by.get("crates/fx/src/bad_trace.rs") == "PRODUCTION")
        check("(a) 非 error DEBUG 留痕不误报", "crates/fx/src/ok_trace.rs" not in by)
        check("(a) 多行形态 + 白名单必须放行", by.get("crates/fx/src/wl.rs") == "WHITELISTED")

        # (b) 裸 allow 必须报；同行/下2行/前向注释理由必须放行；unused_imports 恒报
        (src / "bare.rs").write_text(
            "#[allow(dead_code)]\n"
            "pub fn orphan() {}\n",
            encoding="utf-8",
        )
        (src / "reasoned.rs").write_text(
            "// 前向注释：drop-glue 契约（er2q5 口径）\n"
            "#[allow(dead_code)]\n"
            "pub struct Anchor;\n"
            "#[allow(dead_code)] // 同行尾注理由\n"
            "pub fn kept() {}\n"
            "#[allow(dead_code)]\n"
            "// 下 1 行理由\n"
            "pub fn kept2() {}\n"
            "// 平台面：非 unix 无消费点\n"
            "#[cfg_attr(not(unix), allow(dead_code))]\n"
            "pub struct Platform;\n",
            encoding="utf-8",
        )
        (src / "unused.rs").write_text(
            "#[allow(unused_imports)]\n"
            "use std::collections::HashMap;\n",
            encoding="utf-8",
        )
        res = scan_suppressions(troot)
        bare_files = {b["file"] for b in res["bare"]}
        check("(b) 裸 allow 故意违规必须报", "crates/fx/src/bare.rs" in bare_files)
        check("(b) 三形态理由（前向/同行/下2行）+ cfg_attr 前向不误报",
              bare_files.isdisjoint({"crates/fx/src/reasoned.rs"}))
        check("(b) allow(unused_imports) 恒报", len(res["unused"]) == 1)

        # (d) 绑定语数字 ≠ 值必须报；值复述/无数字必须放行；浮点 MiB 表示必须认
        (src / "drift.rs").write_text(
            "/// 握手在途并发上限（128 条）。\n"
            "pub const HANDSHAKE_CAP: usize = 64;\n",
            encoding="utf-8",
        )
        (src / "match.rs").write_text(
            "/// 保守预算（96MB；留 24MB 给抖动）。\n"
            "pub const BUDGET: usize = 96 * 1024 * 1024;\n"
            "/// 条目上界（估算档 ≈ 2.5MiB，单条 2~20KiB 取上沿）。\n"
            "pub const EST: usize = 128 * 20 * 1024;\n"
            "/// 平台语义（无数字，无从判漂移）。\n"
            "pub const NO_NUM: usize = 4096;\n",
            encoding="utf-8",
        )
        raw = load_production(troot)
        cleaned_map = production_clean(troot, raw)
        drift = scan_comment_drift(troot, raw, cleaned_map)
        drift_files = {d["file"] for d in drift}
        check("(d) 绑定语数字漂移（128 vs 64）故意违规必须报", "crates/fx/src/drift.rs" in drift_files)
        check("(d) 值复述（96MB）/浮点 MiB（2.5MiB）/无数字注释不误报",
              drift_files.isdisjoint({"crates/fx/src/match.rs"}))

        # (c) 交叉断言由 cargo 测试本体执行，脚本只负责命令接线——自测钉命令面
        check("(c) 交叉断言命令接线",
              LEDGER_CROSS_ASSERT_TARGETS == [
                  ["cargo", "test", "-p", "xray-core", "memory_budget"],
                  ["cargo", "test", "-p", "xray-frame", "--lib", "budget"],
              ])

    print("SELF-TEST:", "PASS" if ok else "FAIL")
    return 0 if ok else 2


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------

def cmd_list(root: Path) -> int:
    a_ok, a_msg = gate_a(root)
    print(a_msg)
    b_ok, b_msg = gate_b(root)
    print(b_msg)
    raw = load_production(root)
    cleaned_map = production_clean(root, raw)
    print(f"allow(dead_code) 全量 {len(scan_suppressions(root)['all'])} 处（含 cfg_attr 变体；测试面已剥离）")
    d = scan_comment_drift(root, raw, cleaned_map)
    print(f"(d) 整数常量注释嫌疑 {len(d)} 处（含登记簿放行）：")
    for s in d:
        mark = "REGISTERED" if s["registered"] else "SUSPECT"
        print(f"  {mark}  {s['file']}:{s['line']}  {s['const']} = {s['value']}  注释数字={s['comment_numbers']}")
    return 0 if (a_ok and b_ok) else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="je3u3 质量门四件套（失败留痕/抑制登记/登记簿漂移/注释漂移）")
    ap.add_argument("--no-cargo", action="store_true", help="跳过 (c) cargo 面（纯静态快路径）")
    ap.add_argument("--list", action="store_true", help="枚举 (a)(b)(d) 全部命中与分类")
    ap.add_argument("--self-test", action="store_true", help="注入违规自测（四道门各一条）")
    ap.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    args = ap.parse_args()
    if args.self_test:
        return cmd_self_test()
    if args.list:
        return cmd_list(args.root)

    results: list[tuple[str, bool, str]] = []
    results.append(("a", *gate_a(args.root)))
    print(results[-1][2])
    results.append(("b", *gate_b(args.root)))
    print(results[-1][2])
    d_gate = gate_d(args.root)
    results.append(("d", *d_gate))
    print(d_gate[1])
    c_gate = gate_c(run_cargo=not args.no_cargo)
    results.append(("c", *c_gate))
    print(c_gate[1])

    failed = [name for name, ok, _ in results if not ok]
    if failed:
        print(f"\n质量门 FAIL：{'/'.join(failed)}")
        return 1
    print("\n质量门 PASS：(a) 失败留痕 / (b) 抑制登记 / (c) 登记簿漂移 / (d) 注释漂移抽查")
    return 0


if __name__ == "__main__":
    sys.exit(main())
