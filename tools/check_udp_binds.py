#!/usr/bin/env python3
"""bd d597w 静态门：生产代码禁裸 `UdpSocket::bind`。

Go 在 `netFD.init`（D:/Go/src/net/fd_windows.go:60-78，只读裁定基准）对**全部**
UDP socket 打 `SIO_UDP_CONNRESET`/`SIO_UDP_NETRESET`，任何 UDP socket 都收不到
伪造 ICMP 假错误（WSAECONNRESET 10054）。Rust 侧同口径：所有生产 UDP bind 必须
经 `xray_transport::udp::bind_udp_no_connreset` 族（std 版 / socket2 ioctl 直调 /
xray-proxy-dns crate 内薄转调）。本门把守：**生产代码出现裸 `UdpSocket::bind`
即红**（测试代码与两个 bind 机制本体白名单除外）。

用法：
    python tools/check_udp_binds.py             # 门：违规 exit 1
    python tools/check_udp_binds.py --list      # 枚举证据：全部命中 + 分类
    python tools/check_udp_binds.py --self-test # 自测：注入违规必须报错（AC#3）

扫描语义：
- 只扫 crates/*/src/**（排除 crates/udf-frame——独立仓工作副本，其纪律归 udf CI）。
- 词法剥离注释与字符串字面量内容（doc 注释里提到 `UdpSocket::bind` 不算命中），
  行号与列位置保持不变。
- 剥离 `#[cfg(test)] mod X { ... }` 整块；`#[cfg(test)] mod X;` 挂载的
  X.rs / X/mod.rs 视为测试文件（不扫）。
- 白名单（bind 机制本体，禁在此之外新增）：
    crates/xray-transport/src/udp/mod.rs      —— helper 正本
    crates/xray-proxy-dns/src/udp_connreset.rs —— proxy-dns 薄转调本体
- 已知盲区（登记，不静默）：socket2 `Socket::bind` 路径（QUIC endpoint /
  system dialer / TPROXY Linux 分支）不匹配文本门；QUIC endpoint 与 system
  dialer 已手工接 ioctl（见 bd 票报告），TPROXY 分支 Linux-only 不适用。
"""

from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path

PATTERN = re.compile(r"UdpSocket::bind")

WHITELIST: dict[str, str] = {
    "crates/xray-transport/src/udp/mod.rs": "bind 机制本体（helper 正本，d597w）",
    "crates/xray-proxy-dns/src/udp_connreset.rs": "proxy-dns 薄转调本体（依赖图不含 xray-transport，d597w）",
}

ATTR_OPEN = re.compile(r"\s*#\s*\[")
CFG_TEST_HEAD = re.compile(r"#\s*\[\s*cfg\s*\(")


def bracket_end(src: str, open_idx: int) -> int | None:
    """open_idx 指向 '['，返回配对 ']' 之后的位置；不配对返回 None。"""
    depth = 0
    for j in range(open_idx, len(src)):
        if src[j] == "[":
            depth += 1
        elif src[j] == "]":
            depth -= 1
            if depth == 0:
                return j + 1
    return None


def cfg_test_attr_spans(src: str) -> list[tuple[int, int]]:
    """所有 `#[cfg(...test...)]` 的 (start, end)——含嵌套括号与
    `#[cfg(all(test, windows))]` 形态；test 词出现在 cfg 参数里即算。"""
    spans = []
    for m in CFG_TEST_HEAD.finditer(src):
        # m.end()-1 指向 cfg( 的 '('；先配对圆括号拿到参数串
        paren_end = None
        depth = 0
        for j in range(m.end() - 1, len(src)):
            if src[j] == "(":
                depth += 1
            elif src[j] == ")":
                depth -= 1
                if depth == 0:
                    paren_end = j
                    break
        if paren_end is None:
            continue
        if not re.search(r"\btest\b", src[m.end():paren_end]):
            continue
        outer_open = src.find("[", m.start(), m.end())
        close = bracket_end(src, outer_open)
        if close is None:
            continue
        spans.append((m.start(), close))
    return spans


def strip_comments_and_strings(src: str) -> str:
    out = list(src)
    i, n = 0, len(src)
    NORMAL, LINE_C, BLOCK_C, STR, RAW_STR = range(5)
    state = NORMAL
    raw_hashes = 0
    while i < n:
        c = src[i]
        if state == NORMAL:
            if src.startswith("//", i):
                state = LINE_C
                out[i] = " "
                i += 1
                continue
            if src.startswith("/*", i):
                state = BLOCK_C
                out[i] = out[i + 1] = " "
                i += 2
                continue
            if src.startswith('"', i):
                state = STR
                out[i] = " "
                i += 1
                continue
            if c == "'":
                # char 字面量（含转义）：整体掏空；不匹配（生命周期 'a 等）只跳过引号。
                m = re.match(r"'(\\.|[^\\'])'", src[i:])
                if m:
                    for k in range(i, i + len(m.group(0))):
                        if out[k] != "\n":
                            out[k] = " "
                    i += len(m.group(0))
                    continue
                i += 1
                continue
            if c == "r" and i + 1 < n and src[i + 1] == '"':
                state = STR
                out[i] = out[i + 1] = " "
                i += 2
                continue
            if c == "r" and i + 1 < n and src[i + 1] == "#":
                m = re.match(r'r#+"', src[i:])
                if m:
                    raw_hashes = len(m.group(0)) - 2  # r 与 " 之间的 # 数
                    state = RAW_STR
                    for k in range(i, i + len(m.group(0))):
                        out[k] = " "
                    i += len(m.group(0))
                    continue
            i += 1
        elif state == LINE_C:
            if c == "\n":
                state = NORMAL
            else:
                out[i] = " "
            i += 1
        elif state == BLOCK_C:
            if src.startswith("*/", i):
                out[i] = out[i + 1] = " "
                state = NORMAL
                i += 2
            else:
                if c != "\n":
                    out[i] = " "
                i += 1
        elif state == STR:
            if c == "\\":
                out[i] = " "
                if i + 1 < n:
                    out[i + 1] = " "
                i += 2
            elif c == '"':
                out[i] = " "
                state = NORMAL
                i += 1
            else:
                if c != "\n":
                    out[i] = " "
                i += 1
        else:  # RAW_STR
            end = '"' + "#" * raw_hashes
            if src.startswith(end, i):
                for k in range(i, i + len(end)):
                    out[k] = " "
                i += len(end)
                state = NORMAL
            else:
                if c != "\n":
                    out[i] = " "
                i += 1
    return "".join(out)


def strip_cfg_test_blocks(src: str) -> tuple[str, list[str]]:
    """剥离 `#[cfg(...test...)] mod X { ... }` 整块（允许属性链中间隔其它
    `#[...]`）；`mod X;` 返回挂载模块名（供跨文件测试面判定）。

    只对 well-formed 的 mod 项动刀（保守：其它 cfg(test) 项保留 → 宁误红不漏放）。
    """
    mounted_mods: list[str] = []
    spans: list[tuple[int, int]] = []
    for a_start, a_end in cfg_test_attr_spans(src):
        # 跳过紧随其后的其它属性（#[allow(...)] 等）
        j = a_end
        while True:
            m_next = ATTR_OPEN.match(src, j)
            if not m_next:
                break
            nxt_end = bracket_end(src, src.index("[", j))
            if nxt_end is None:
                break
            j = nxt_end
        tail = src[j:]
        mod_m = re.match(r"\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)", tail)
        if not mod_m:
            continue  # 非 mod 项（fn/static/use 等）保守保留
        body_off = j + mod_m.end()
        rest = src[body_off:]
        if rest.lstrip().startswith(";"):
            semi = body_off + rest.index(";")
            mounted_mods.append(mod_m.group(1))
            spans.append((a_start, semi + 1))
            continue
        brace = rest.find("{")
        if brace == -1:
            continue
        depth = 0
        k = body_off + brace
        while k < len(src):
            if src[k] == "{":
                depth += 1
            elif src[k] == "}":
                depth -= 1
                if depth == 0:
                    break
            k += 1
        if depth == 0:
            spans.append((a_start, k + 1))
    result = list(src)
    for start, end in spans:
        for idx in range(start, end):
            if result[idx] != "\n":
                result[idx] = " "
    return "".join(result), mounted_mods


def line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def candidate_files(root: Path) -> list[Path]:
    crates = root / "crates"
    if not crates.is_dir():
        return []
    out = []
    for rs in sorted(crates.rglob("*.rs")):
        parts = rs.parts
        if len(parts) < 3 or parts[1] == "udf-frame" or "src" not in parts:
            continue  # 只扫 crates/*/src/**；udf-frame 独立仓不扫
        if "tests" in parts[parts.index("src") + 1:]:
            continue
        out.append(rs)
    return out


def scan(root: Path, whitelist: dict[str, str] | None = None) -> list[dict]:
    """返回生产代码裸 bind 命中列表（含文件/行/分类）。

    --list 复用本函数（whitelist={} 时白名单文件按 HELPER 分类而非豁免）。
    """
    whitelist = WHITELIST if whitelist is None else whitelist
    files = candidate_files(root)
    # Pass 1：收集 `#[cfg(test)] mod X;` 挂载的测试支撑文件（跨文件判定）。
    mounted: set[str] = set()
    raw: dict[Path, str] = {}
    for rs in files:
        try:
            src = rs.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        raw[rs] = src
        stripped_src = strip_comments_and_strings(src)
        _, mods = strip_cfg_test_blocks(stripped_src)
        for name in mods:
            mounted.add((rs.parent / f"{name}.rs").relative_to(root).as_posix())
            mounted.add((rs.parent / name / "mod.rs").relative_to(root).as_posix())
    # Pass 2：命中扫描。
    hits: list[dict] = []
    for rs, src in raw.items():
        rel = rs.relative_to(root).as_posix()
        if rel in mounted:
            continue  # #[cfg(test)] mod X; 挂载的测试支撑文件 = 测试面
        cleaned, _ = strip_cfg_test_blocks(strip_comments_and_strings(src))
        for m in PATTERN.finditer(cleaned):
            kind = "HELPER-WHITELIST" if rel in whitelist else "PRODUCTION"
            hits.append({
                "file": rel,
                "line": line_of(cleaned, m.start()),
                "kind": kind,
                "reason": whitelist.get(rel, ""),
            })
    return hits


def cmd_list(root: Path) -> int:
    hits = scan(root, whitelist={})
    prod = [h for h in hits if h["kind"] == "PRODUCTION"]
    helper = [h for h in hits if h["kind"] != "PRODUCTION"]
    # 测试面计数：不做 cfg(test) 剥离再扫一遍（注释/字符串仍剥离）。
    test_face = 0
    for rs in candidate_files(root):
        try:
            src = rs.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        cleaned = strip_comments_and_strings(src)
        test_face += sum(1 for _ in PATTERN.finditer(cleaned))
    print(f"== 全仓 crates/*/src/** `UdpSocket::bind` 文本出现（注释/字符串已剥，cfg(test) 未剥）==")
    print(f"   文本总计 {test_face} 处（生产 + 测试面 + 机制本体）")
    print(f"== 其中生产代码（cfg(test) 剥离后存活）==")
    for h in prod:
        print(f"  PRODUCTION  {h['file']}:{h['line']}")
    for h in helper:
        print(f"  HELPER      {h['file']}:{h['line']}  ({h['reason']})")
    print(f"生产代码裸 bind = {len(prod)} 处（门要求 0）")
    return 0


def cmd_gate(root: Path) -> int:
    hits = [h for h in scan(root) if h["kind"] == "PRODUCTION"]
    if hits:
        print(f"FAIL: 生产代码裸 `UdpSocket::bind` {len(hits)} 处（bd d597w 门）：")
        for h in hits:
            print(f"  {h['file']}:{h['line']}")
            print(f"    → 改走 xray_transport::udp::bind_udp_no_connreset 族")
        return 1
    print("OK: 生产代码零裸 UdpSocket::bind（白名单=bind 机制本体 2 文件）")
    return 0


def cmd_self_test() -> int:
    """AC#3：故意造违规 → 必须报错；测试面/注释/白名单 → 必须放行。"""
    ok = True
    with tempfile.TemporaryDirectory(prefix="udpbind-gate-") as td:
        troot = Path(td)
        crate = troot / "crates" / "fx"
        (crate / "src").mkdir(parents=True)
        files = {
            "prod.rs": 'fn f() { let s = tokio::net::UdpSocket::bind("127.0.0.1:0").await; }\n',
            "in_test.rs": (
                "mod x {\n"
                "#[cfg(test)]\nmod tests {\n"
                "    fn t() { let _ = UdpSocket::bind(\"127.0.0.1:0\"); }\n"
                "}\n}\n"
            ),
            "in_doc.rs": '/// 文档提到 UdpSocket::bind 不算命中\nfn g() {}\n',
            "in_string.rs": 'const S: &str = "UdpSocket::bind is just a string";\n',
            "in_charlit.rs": (
                "fn esc(c: char) -> char {\n"
                "    match c {\n"
                "        '\\\"' => 'x',\n"
                "        _ => c,\n"
                "    }\n"
                "}\n"
                "fn h() { let _ = UdpSocket::bind(\"127.0.0.1:0\"); }\n"
            ),
            "helper.rs": 'pub async fn bind_udp_no_connreset() { let s = UdpSocket::bind("x").await; }\n',
        }
        for name, content in files.items():
            (crate / "src" / name).write_text(content, encoding="utf-8")
        wl = {
            "crates/fx/src/helper.rs": "self-test whitelist",
        }
        hits = scan(troot, whitelist=wl)
        by_file = {}
        for h in hits:
            if h["kind"] == "PRODUCTION":  # 白名单命中按放行计（kind 非 PRODUCTION）
                by_file.setdefault(h["file"], []).append(h["kind"])

        def expect(file: str, should_flag: bool, label: str) -> bool:
            flagged = file in by_file
            status = "OK" if flagged == should_flag else "FAIL"
            if flagged != should_flag:
                return False
            print(f"  [{status}] {label}: {file} → flagged={flagged}")
            return True

        ok &= expect("crates/fx/src/prod.rs", True, "故意违规必须报")
        ok &= expect("crates/fx/src/in_test.rs", False, "cfg(test) 块内必须放行")
        ok &= expect("crates/fx/src/in_doc.rs", False, "注释内必须放行")
        ok &= expect("crates/fx/src/in_string.rs", False, "字符串内必须放行")
        ok &= expect("crates/fx/src/helper.rs", False, "白名单必须放行")
    print("SELF-TEST:", "PASS" if ok else "FAIL")
    return 0 if ok else 2


def main() -> int:
    ap = argparse.ArgumentParser(description="bd d597w UDP bind 静态门")
    ap.add_argument("--list", action="store_true", help="枚举全部命中（含分类）")
    ap.add_argument("--self-test", action="store_true", help="注入违规自测")
    ap.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    args = ap.parse_args()
    if args.self_test:
        return cmd_self_test()
    if args.list:
        return cmd_list(args.root)
    return cmd_gate(args.root)


if __name__ == "__main__":
    sys.exit(main())
