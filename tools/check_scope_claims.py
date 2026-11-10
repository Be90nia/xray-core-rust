#!/usr/bin/env python3
"""ADR-0004 B3 静态门 —— 组件 scope 持有件契约的文案与残留检查。

三查（对应 ADR-0004 §2.6 A5 / B1' / A6）：
  (1) A5 伪 Drop-abort 断言：`.rs` 注释/doc 与 `docs/**/*.md` 中「drop/丢弃/归零 …
      即/=/⇒ … abort」类表述 ⇒ 红。这类文案把「Drop 兜底」当在途中止保证写——
      而环 / 多持有者 / abort 时点不确定使其恒不可达或 best-effort（§2.2 Q3）。
      白名单三道（PM 裁定 2026-11-09）：① `docs/architecture/adr/` 目录整体豁免
      （ADR 是裁决历史引文，A5 门不管历史，只管现行代码与现行文档）；② 行内正确
      口吻（不作中止保证 / 为实现事实，非契约保证 / 不得声称 abort 等）或禁令
      引文——静默放行；③ 机制事实句（含 JoinSet/FxScope/udf 等机制词）与否定
      语境句（不可/防/避免等）——放行但以 `note:` 行列出（非静默洗绿）。
      门只抓「组件持有件的 Drop 契约声称」，不抓 udf FxScope/JoinSet 机制描述。
  (2) B1' 旧件残留：`crates/**` 出现 `compat::ManagedScope` ⇒ 红（B1' 删旧类型后
      `grep -rn "compat::ManagedScope" crates` 归零，ADR-0004 §2.5 B1'）。
      B1' 落地前本项在本树为红属预期——红点即 B1' 待收口清单。
  (3) A6 单账本：同一 `.rs` 同时**以类型用法**持有 `JoinSet` 与
      `ComponentScope` ⇒ 红（真双账本 = ADR-0004 §2.7 打回项）。
      判据（bd n06e1）：只认**类型位置**上的用法（构造 `T::new(` / 泛型 `T<` `T>`
      / 类型标注 `: T`、`: path::T`），且判定面是**代码面**——注释与字符串字面量
      剔除，`use` 导入不算持有（导入 ≠ 账本）。旧判据按纯文本搜 `JoinSet`，
      把文档注释里解释 udf「JoinSet drop ⇒ abort」机制的散文提及当成持有账本
      ⇒ 6 个文件 6/6 全误报、长期带 6 条噪音。

用法（房规 check_lock_across_await.py）：
  python tools/check_scope_claims.py             # 全树跑，退出码非零 = 红
  python tools/check_scope_claims.py --list      # 枚举全部命中与分类
  python tools/check_scope_claims.py --self-test # 临时树注入违规自测

扫描语义（与 check_quality_gates.py 同源纪律）：
- (1) 的 .rs 面只扫**注释/doc**（字符串字面量与代码不在 A5 判定面——断言只长在
  注释里）；.md 面全行扫（正文皆「文案」）。
- 排除 crates/udf-frame/**（独立仓工作副本，纪律归 udf CI）。
"""

from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path

# ADR 目录整体豁免（PM 裁定 2026-11-09）：ADR 是裁决历史引文（引文形态本身就是
# 旧语义），改它们等于篡改历史——A5 门不管历史，只管现行代码与现行文档。
ADR_DIR_PREFIX = "docs/architecture/adr/"

# 遍历防护（PM 提示 2026-11-09）：任何自实现遍历必须跳过 SKIP_PARTS——
# `target/` 全树巨大（CI 上不跳过会超时），`vendor/` 与 `crates/udf-frame/`
# 是外部仓工作副本（不归本仓纪律管），`.git` 是元数据，`reports/` 是
# gitignored 证据目录（含大量历史文案，扫了必误报）。
SKIP_PARTS = {".git", "target", "vendor", "udf-frame", "reports"}


def _walkable(root: Path, p: Path) -> bool:
    return not (set(p.relative_to(root).parts) & SKIP_PARTS)


# ---------------------------------------------------------------------------
# (1) A5 伪 Drop-abort 断言
# ---------------------------------------------------------------------------

DROP_ABORT_CLAIM = re.compile(
    r"(?:drop|丢弃|归零)[^\n]{0,24}(?:即|=>|=|⇒)[^\n]{0,16}abort",
    re.IGNORECASE,
)

# 正确口吻 / 禁令引文标记：命中行含任一 ⇒ 该行不算违规（白名单②）。
TONE_OK = (
    "不作中止保证",
    "为实现事实，非契约保证",
    "不得声称 abort",
    # Q3 认可口吻的免责/条件式变体（B1 迁移写进站点的实际措辞）。
    "实现事实",
    "而非保证",
    "非契约",
    "最后一份强引用",
    "最后一份引用",
    "若已无他引",
    "udf 语义",
    # 禁令引文：描述禁令本身的行（含这些标记）是治理文案，不是断言。
    "伪断言",
    "打回",
)
BAN_MARK = re.compile(r"(?:禁|不得|禁止)")

# PM 裁定 2026-11-09：A5 禁令的对象是「组件持有件的 Drop 契约声称」（把 Drop 当
# 停机保证的说法），不是描述 udf FxScope/JoinSet 机制本身的事实句，也不该惩罚
# 否定/防御语境的行。门只抓契约声称，不抓机制描述：
#   mechanism —— 行含机制词 ⇒ 机制事实句，放行 + note（非静默）。
#   negation  —— 行含否定/防御词 ⇒ 否定语境，放行 + note（非静默）。
MECHANISM_FACT = (
    "JoinSet",
    "FxScope",
    "udf",
    "实现事实",
    "不作中止保证",
    "实现事实而非保证",
)
NEGATION_MARK = re.compile(r"不可|不得|禁止|防|避免|无任何|旧形态|历史上")


def classify_claim(line: str, block: str | None = None) -> str | None:
    """命中行放行分类：tone（正确口吻，静默）/ mechanism / negation（均 note）/ None（违规）。

    口吻/否定判定在**命中行**；机制词判定在**命中所属注释块**（doc 句跨行，
    JoinSet/FxScope 字样常在相邻注释行）——.md 面无块概念，传 None 即行级。
    """
    if any(t in line for t in TONE_OK):
        return "tone"
    hay = line if block is None else block
    if any(t in hay for t in MECHANISM_FACT):
        return "mechanism"
    if NEGATION_MARK.search(line):
        return "negation"
    if BAN_MARK.search(line):
        return "tone"
    return None


def _comment_block(lines: list[str], idx: int) -> str:
    """注释文本中的连续注释块（空行=代码/字符串被剥离后的空白，即块边界）。"""
    top = idx
    while top > 0 and lines[top - 1].strip():
        top -= 1
    bot = idx
    while bot + 1 < len(lines) and lines[bot + 1].strip():
        bot += 1
    return "\n".join(lines[top:bot + 1])


def _blank(text: str) -> str:
    """非换行字符全置换为空格，换行保留（保持行号对齐）。"""
    return "".join(ch if ch == "\n" else " " for ch in text)


def _scan_rust(src: str, *, keep_comments: bool) -> str:
    """逐字符扫描 Rust 源，产出两个等长视图之一。

    `keep_comments=True` → **注释面**：只保留注释（`//` 与 `/* */`），其余
    （代码/字符串）置换为空格——A5 伪断言判定面（断言只长在注释里）。
    `keep_comments=False` → **代码面**：只保留代码，注释与字符串字面量置换为
    空格——A6 类型用法判定面（代码面里出现的类型名才是真用法）。

    位置与换行不变 ⇒ 命中行号与原文对齐（房规：剥离函数不位移）。
    覆盖普通字符串、字符字面量与原始字符串 r"…" / r#"…"#（其中的 // 不是注释）。
    """
    out: list[str] = []
    i, n = 0, len(src)
    state = "code"  # code | str | byte_char | raw
    raw_hashes = 0
    while i < n:
        c = src[i]
        if state == "code":
            if c == "/" and src.startswith("//", i):
                j = src.find("\n", i)
                j = n if j < 0 else j
                out.append(src[i:j] if keep_comments else _blank(src[i:j]))
                i = j
                continue
            if c == "/" and src.startswith("/*", i):
                j = src.find("*/", i + 2)
                j = n if j < 0 else j + 2
                out.append(src[i:j] if keep_comments else _blank(src[i:j]))
                i = j
                continue
            if c == '"':
                state = "str"
            elif c == "'":
                state = "byte_char"
            elif c == "r":
                # r"…" / r#"…"# 原始字符串
                k = i + 1
                while k < n and src[k] == "#":
                    k += 1
                if k < n and src[k] == '"' and k > i + 1 or (k == i + 1 and k < n and src[k] == '"'):
                    state = "raw"
                    raw_hashes = k - (i + 1)
            out.append(c if c == "\n" or not keep_comments else " ")
            i += 1
        elif state == "str":
            if c == "\\":
                out.append("  " if src[i + 1 : i + 2] != "\n" else " \n")
                i += 2
                continue
            if c == '"':
                state = "code"
            out.append(c if c == "\n" else " ")
            i += 1
        elif state == "byte_char":
            if c == "\\":
                out.append("  " if src[i + 1 : i + 2] != "\n" else " \n")
                i += 2
                continue
            if c == "'":
                state = "code"
            out.append(c if c == "\n" else " ")
            i += 1
        else:  # raw
            if c == '"' and src.startswith('"' + "#" * raw_hashes, i):
                out.append(" " * (1 + raw_hashes))
                i += 1 + raw_hashes
                state = "code"
                continue
            out.append(c if c == "\n" else " ")
            i += 1
    return "".join(out)


def extract_rust_comments(src: str) -> str:
    """注释面：逐字符保留注释（`//` 与 `/* */`），其余（代码/字符串）置换为空格。

    位置与换行不变 ⇒ 命中行号与原文对齐（房规：剥离函数不位移）。
    """
    return _scan_rust(src, keep_comments=True)


def extract_rust_code(src: str) -> str:
    """代码面：保留代码，**注释与字符串字面量内容**置换为空格。

    位置与换行不变 ⇒ 命中行号与原文对齐。A6 双账本判据的判定面——散文提及
    （注释里解释 udf 机制）与日志文案里的类型名都不算「持有该类型」。
    """
    return _scan_rust(src, keep_comments=False)


# `use` 导入语句：导入 ≠ 持有账本（`use tokio::task::JoinSet;` 只是把类型名拉进
# 作用域）。判据要在类型位置上找用法，故先把 use 语句整条从判定面剔除。
# `[^;]*` 跨行（Rust 的 use 语句可多行），`;` 终止 ⇒ 不会吃掉后续语句。
_USE_STMT = re.compile(r"(?m)^[ \t]*(?:pub(?:\([^)]*\))?[ \t]+)?use\b[^;]*;")


def strip_use_statements(code: str) -> str:
    """从代码面剔除 `use` 语句（内容置空格，换行保留）。"""
    return _USE_STMT.sub(lambda m: _blank(m.group(0)), code)


# ---------------------------------------------------------------------------
# (2) B1' 旧件残留 + (3) A6 双账本
# ---------------------------------------------------------------------------

MANAGED_SCOPE_RESIDUE = "compat::ManagedScope"
LEDGER_TOKENS = ("JoinSet", "ComponentScope")


def type_use_pattern(token: str) -> re.Pattern[str]:
    """类型用法判据：token 出现在**类型位置**才算持有该类型。

    四种形态（bd n06e1 定案）：
      ① 构造：`T::new(`；
      ② 泛型实例：`T<`（如 `JoinSet<(usize, ...)>`）；
      ③ 泛型实参：`T>`（如 `Vec<JoinSet>`）；
      ④ 类型标注：`: T` / `: path::T`（字段、局部变量、参数、返回值绑定）。
    散文提及（注释）与字符串文案不算（判定面是代码面）；`use` 导入也不算
    （导入 ≠ 持有账本，见 strip_use_statements）。
    """
    t = re.escape(token)
    return re.compile(
        rf"(?<![\w]){t}\s*::\s*new\s*\("
        rf"|(?<![\w]){t}\s*<"
        rf"|(?<![\w]){t}\s*>"
        rf"|:\s*(?:&\s*)?(?:mut\s+)?(?:[\w:]+::)*{t}\b"
    )


# ---------------------------------------------------------------------------
# 扫描
# ---------------------------------------------------------------------------

def rel(root: Path, p: Path) -> str:
    return p.relative_to(root).as_posix()


def rust_files(root: Path) -> list[Path]:
    crates = root / "crates"
    if not crates.is_dir():
        return []
    return sorted(
        p for p in crates.rglob("*.rs")
        if _walkable(root, p)
    )


def crate_text_files(root: Path) -> list[Path]:
    """(2) 面：crates/** 全部文本文件（grep 语义；二进制/解码失败跳过）。"""
    crates = root / "crates"
    if not crates.is_dir():
        return []
    out: list[Path] = []
    for p in sorted(crates.rglob("*")):
        if not p.is_file() or not _walkable(root, p):
            continue
        try:
            p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        out.append(p)
    return out


def doc_files(root: Path) -> list[Path]:
    docs = root / "docs"
    if not docs.is_dir():
        return []
    return sorted(p for p in docs.rglob("*.md") if _walkable(root, p))


def _scan_claims(root: Path) -> tuple[list[dict], list[dict]]:
    """A5 扫描：返回 (违规 hits, 放行 notes)。

    notes = 正则命中但被判机制事实/否定语境的行（非静默洗绿，gate 以 note 行列出）。
    tone（正确口吻/禁令引文）静默放行；ADR 目录前缀整体 skip（连 note 都不出）。
    """
    hits: list[dict] = []
    notes: list[dict] = []
    for p in rust_files(root):
        comments = extract_rust_comments(p.read_text(encoding="utf-8"))
        comment_lines = comments.splitlines()
        for m in DROP_ABORT_CLAIM.finditer(comments):
            line_no = comments.count("\n", 0, m.start()) + 1
            line = comment_lines[line_no - 1]
            entry = {
                "file": rel(root, p), "line": line_no,
                "kind": "rs-comment", "snippet": line.strip()[:120],
            }
            verdict = classify_claim(line, _comment_block(comment_lines, line_no - 1))
            if verdict is None:
                hits.append(entry)
            elif verdict != "tone":
                entry["pass"] = verdict
                notes.append(entry)
    for p in doc_files(root):
        r = rel(root, p)
        if r.startswith(ADR_DIR_PREFIX):
            continue
        for line_no, line in enumerate(
            p.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if not DROP_ABORT_CLAIM.search(line):
                continue
            entry = {"file": r, "line": line_no, "kind": "doc", "snippet": line.strip()[:120]}
            verdict = classify_claim(line)
            if verdict is None:
                hits.append(entry)
            elif verdict != "tone":
                entry["pass"] = verdict
                notes.append(entry)
    return hits, notes


def scan_drop_abort_claims(root: Path) -> list[dict]:
    """A5 违规命中（房规接口：gates 脚本 self-test 消费；放行面见 scan_claim_notes）。"""
    return _scan_claims(root)[0]


def scan_claim_notes(root: Path) -> list[dict]:
    """A5 放行面（机制事实/否定语境）：非静默，gate/cmd_list 以 note 行列出。"""
    return _scan_claims(root)[1]


def scan_managed_scope_residue(root: Path) -> list[dict]:
    """B1' 残留命中：crates/** 内 `compat::ManagedScope` 全文匹配（含注释）。"""
    hits: list[dict] = []
    for p in crate_text_files(root):
        text = p.read_text(encoding="utf-8")
        if MANAGED_SCOPE_RESIDUE not in text:
            continue
        for line_no, line in enumerate(text.splitlines(), start=1):
            if MANAGED_SCOPE_RESIDUE in line:
                hits.append({
                    "file": rel(root, p), "line": line_no,
                    "snippet": line.strip()[:120],
                })
    return hits


def scan_dual_ledger(root: Path) -> list[dict]:
    """A6 报告级：同一 .rs 同时**以类型用法**持有 JoinSet 与 ComponentScope ⇒ WARN。

    判据（bd n06e1）：只认类型位置上的用法，且判定面是**代码面**（注释与字符串
    字面量剔除）——文档注释里解释 udf「JoinSet drop ⇒ abort」机制的散文提及不是
    持有账本（那 6 个文件命中 8 行全此类 ⇒ 6/6 全误报）。
    """
    warns: list[dict] = []
    for p in rust_files(root):
        code = strip_use_statements(extract_rust_code(p.read_text(encoding="utf-8")))
        present = [t for t in LEDGER_TOKENS if type_use_pattern(t).search(code)]
        if len(present) == len(LEDGER_TOKENS):
            warns.append({"file": rel(root, p)})
    return warns


def gate(root: Path) -> tuple[bool, str]:
    """红 = A5 伪断言 / B1' 残留 / A6 双账本任一命中。

    A6（bd n06e1）：判据 = 同一 `.rs` **以类型用法**同时持有 `JoinSet` 与
    `ComponentScope`（注释与字符串剔除、`use` 导入不算）——旧判据按纯文本匹配，
    把文档注释里解释 udf 机制的散文提及当成持有账本 ⇒ 6/6 全误报。判据收紧后
    命中即真双账本（ADR-0004 §2.7 打回项），故可红。
    """
    claims, claim_notes = _scan_claims(root)
    residue = scan_managed_scope_residue(root)
    dual = scan_dual_ledger(root)
    lines: list[str] = []
    ok = not claims and not residue and not dual
    if claims:
        lines.append(f"(g1) A5 伪 Drop-abort 断言 {len(claims)} 处（注释/doc 不得声称 Drop 兜底中止，ADR-0004 §2.2 Q3）：")
        lines += [f"  RED  {h['file']}:{h['line']}  {h['snippet']}" for h in claims]
    else:
        lines.append(f"OK (g1) A5 伪 Drop-abort 断言：0 处（另有 {len(claim_notes)} 处正则命中被放行，见 note）")
    if claim_notes:
        lines.append(f"(g1) note 正则命中放行 {len(claim_notes)} 处（机制事实/否定语境，非静默洗绿）：")
        lines += [
            f"  note  {n['file']}:{n['line']}  [{n['pass']}]  {n['snippet'][:80]}"
            for n in claim_notes
        ]
    if residue:
        lines.append(f"(g2) B1' 旧件残留 {len(residue)} 处（`compat::ManagedScope` 应已删净，ADR-0004 §2.5 B1'）：")
        lines += [f"  RED  {h['file']}:{h['line']}  {h['snippet']}" for h in residue]
    else:
        lines.append("OK (g2) B1' 旧件残留：`compat::ManagedScope` 0 命中")
    if dual:
        lines.append(f"(g3) A6 双账本 {len(dual)} 处（同一 .rs 同时以类型用法持有 JoinSet 与 ComponentScope = ADR-0004 §2.7 打回项）：")
        lines += [f"  RED  {w['file']}  JoinSet 与 ComponentScope 同文件并存" for w in dual]
    else:
        lines.append("OK (g3) A6 双账本：0 处")
    return ok, "\n".join(lines)


# ---------------------------------------------------------------------------
# --self-test：临时树注入「故意违反 → 必须红；正确口吻/白名单 → 必须绿」
# ---------------------------------------------------------------------------

def cmd_self_test() -> int:
    ok = True

    def check(label: str, cond: bool) -> None:
        nonlocal ok
        print(f"  [{'OK' if cond else 'FAIL'}] {label}")
        ok &= cond

    with tempfile.TemporaryDirectory(prefix="scopeclaims-") as td:
        root = Path(td)
        rs_dir = root / "crates" / "demo" / "src"
        rs_dir.mkdir(parents=True)
        docs_dir = root / "docs" / "architecture"
        docs_dir.mkdir(parents=True)
        adr_dir = docs_dir / "adr"
        adr_dir.mkdir()

        (rs_dir / "bad_claim.rs").write_text(
            "/// 句柄丢弃即 abort 在途连接任务。\n"
            "pub struct A;\n"
            "impl Drop for A {\n"
            "    fn drop(&mut self) {}\n"
            "}\n",
            encoding="utf-8",
        )
        (rs_dir / "ok_tone.rs").write_text(
            "/// Drop 语义：引用归零 ⇒ abort（为实现事实，非契约保证）。\n"
            "pub struct B;\n"
            "let s = \"Drop 即 abort 在途\";  // 字符串字面量不在 A5 判定面\n"
            "pub fn f() { let _ = s; }\n",
            encoding="utf-8",
        )
        (rs_dir / "mechanism.rs").write_text(
            "/// scope drop = JoinSet abort 全组（FxScope 托管机制事实）。\n"
            "pub struct M;\n",
            encoding="utf-8",
        )
        (rs_dir / "negation.rs").write_text(
            "// 该句柄不可丢弃，丢弃即 abort 在途泵任务。\n"
            "pub struct N;\n",
            encoding="utf-8",
        )
        (rs_dir / "residue.rs").write_text(
            "// 迁移完成前的注释：与旧 compat::ManagedScope 口径一致。\n"
            "pub struct C;\n",
            encoding="utf-8",
        )
        (rs_dir / "dual_ledger.rs").write_text(
            "use tokio::task::JoinSet;\n"
            "use xray_frame::scope::ComponentScope;\n"
            "pub struct D { js: JoinSet, sc: ComponentScope }\n",
            encoding="utf-8",
        )
        # bd n06e1 反例：JoinSet 只在文档注释里被提及（解释 udf 机制），代码面无
        # 类型用法 ⇒ 不得判为双账本（旧判据按纯文本匹配 ⇒ 这类文件 6/6 全误报）。
        (rs_dir / "prose_only.rs").write_text(
            "/// 旧件口径：JoinSet drop ⇒ abort 全组（udf 语义，实现事实）。\n"
            "pub struct P { sc: ComponentScope }\n",
            encoding="utf-8",
        )
        # bd n06e1 反例：只有 use 导入（导入 ≠ 持有账本）⇒ 不得判为双账本。
        (rs_dir / "import_only.rs").write_text(
            "use tokio::task::JoinSet;\n"
            "use xray_frame::scope::ComponentScope;\n",
            encoding="utf-8",
        )
        (docs_dir / "bad.md").write_text(
            "# 旧文档\n\nscope 句柄丢弃即 abort 在途任务，停机无忧。\n",
            encoding="utf-8",
        )
        (docs_dir / "ban_quote.md").write_text(
            "治理：禁「Drop 即 abort 在途」伪断言（A5 门）。\n",
            encoding="utf-8",
        )
        (adr_dir / "adr-0004-component-scope-holder-contract.md").write_text(
            "禁令描述：句柄丢弃 ⇒ 在途任务 abort 这类文案不得再写。\n",
            encoding="utf-8",
        )

        claims = scan_drop_abort_claims(root)
        claim_keys = {(h["file"], h["line"]) for h in claims}
        check("(g1) .rs 注释伪断言必须报", ("crates/demo/src/bad_claim.rs", 1) in claim_keys)
        check("(g1) docs 伪断言必须报", ("docs/architecture/bad.md", 3) in claim_keys)
        check("(g1) 正确口吻行不报", not any(h["file"].endswith("ok_tone.rs") for h in claims))
        check("(g1) 字符串字面量不报（只扫注释/doc）", not any(
            h["file"].endswith("ok_tone.rs") and h["line"] == 3 for h in claims))
        check("(g1) 禁令引文行不报", not any(h["file"].endswith("ban_quote.md") for h in claims))
        check("(g1) ADR-0004 自身豁免", not any(h["file"].endswith("adr-0004-component-scope-holder-contract.md") for h in claims))

        notes = scan_claim_notes(root)
        note_keys = {(n["file"], n["line"]) for n in notes}
        check("(g1) 机制事实句（含 JoinSet）不报且出 note",
              ("crates/demo/src/mechanism.rs", 1) in note_keys
              and ("crates/demo/src/mechanism.rs", 1) not in claim_keys)
        check("(g1) 否定语境句（含「不可丢弃」）不报且出 note",
              ("crates/demo/src/negation.rs", 1) in note_keys
              and ("crates/demo/src/negation.rs", 1) not in claim_keys)
        check("(g1) 真契约声称（无机制词/否定词）仍必红",
              ("crates/demo/src/bad_claim.rs", 1) in claim_keys)
        check("(g1) tone 正确口吻静默放行（不出 note）",
              not any(n["file"].endswith("ok_tone.rs") for n in notes))

        residue = scan_managed_scope_residue(root)
        check("(g2) crates 注释里的 compat::ManagedScope 残留必须报",
              any(h["file"] == "crates/demo/src/residue.rs" for h in residue))

        dual = scan_dual_ledger(root)
        check("(g3) 同文件以类型用法持有 JoinSet+ComponentScope 必须报",
              any(w["file"] == "crates/demo/src/dual_ledger.rs" for w in dual))
        check("(g3) JoinSet 仅见于文档注释 ⇒ 不得报（bd n06e1 反例）",
              not any(w["file"] == "crates/demo/src/prose_only.rs" for w in dual))
        check("(g3) 仅有 use 导入 ⇒ 不得报（导入 ≠ 持有账本）",
              not any(w["file"] == "crates/demo/src/import_only.rs" for w in dual))

        ok_gate, _ = gate(root)
        check("(g) 有 A5/B1'/A6 命中 ⇒ 门必须红", not ok_gate)

        # 删掉违规 ⇒ 绿
        (rs_dir / "bad_claim.rs").write_text("pub struct A;\n", encoding="utf-8")
        (rs_dir / "residue.rs").write_text("pub struct C;\n", encoding="utf-8")
        (rs_dir / "dual_ledger.rs").write_text("pub struct D;\n", encoding="utf-8")
        (docs_dir / "bad.md").write_text("# 旧文档\n", encoding="utf-8")
        ok_gate2, msg2 = gate(root)
        check("(g) 违规清零 ⇒ 门必须绿", ok_gate2)
        check("(g) 绿态 (g3) 零命中", "(g3) A6 双账本：0 处" in msg2)
        # 绿态 note 确定数：mechanism.rs + negation.rs 各 1（ok_tone/ban_quote 走
        # tone 静默，adr 目录 skip，bad.md/bad_claim/residue/dual_ledger 已清零）。
        check("(g) 绿态 note 非静默（恰 2 处放行可见）", msg2.count("note  ") == 2)

    print("SELF-TEST:", "PASS" if ok else "FAIL")
    return 0 if ok else 2


def cmd_list(root: Path) -> int:
    for h in scan_drop_abort_claims(root):
        print(f"RED   {h['file']}:{h['line']}  [{h['kind']}]  {h['snippet']}")
    for n in scan_claim_notes(root):
        print(f"note  {n['file']}:{n['line']}  [{n['pass']}]  {n['snippet'][:80]}")
    for h in scan_managed_scope_residue(root):
        print(f"RED   {h['file']}:{h['line']}  [residue]  {h['snippet']}")
    for w in scan_dual_ledger(root):
        print(f"RED   {w['file']}  JoinSet 与 ComponentScope 同文件并存（A6 双账本）")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="ADR-0004 B3 静态门：A5 伪 Drop-abort 断言 / B1' 旧件残留 / A6 双账本嫌疑"
    )
    ap.add_argument("--list", action="store_true", help="枚举全部命中与分类")
    ap.add_argument("--self-test", action="store_true", help="临时树注入违规自测")
    ap.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    args = ap.parse_args()
    if args.self_test:
        return cmd_self_test()
    if args.list:
        return cmd_list(args.root)
    ok, msg = gate(args.root)
    print(msg)
    if not ok:
        print("\nscope-claims 门 FAIL：A5 伪断言 / B1' 残留 / A6 双账本未清零")
        return 1
    print("\nscope-claims 门 PASS：(g1) 伪 Drop-abort 断言 / (g2) compat::ManagedScope 残留 / (g3) A6 双账本")
    return 0


if __name__ == "__main__":
    sys.exit(main())
