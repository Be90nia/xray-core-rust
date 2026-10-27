#!/usr/bin/env python3
"""W2 影子第三路实测：真 Go 内核 `-dump` vs Rust 折叠路径 `-dump`。

Go  = D:/Project/Xray-core/target/xray-go.exe（Xray 26.7.28，dumpConfig 不启动实例）
Rust= target-w2/debug/xray.exe（W2 切换后：merge_configs → XrayConfigLayers 折叠）

对照口径：两侧 dump 递归解析后结构对比（dict 无序）。已知序列化差异类（serial.rs
模块文档记载）：Go isNullValue 额外跳过空字符串字段（如 tag:""/spiderX:""），
Rust 保留——对比前对两侧统一剥离「值为空串」的键，剩余差异逐条列出。
"""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(r"D:/Project/Xray-core-rust")
# infra/conf 层 dump（serial.MergeConfigFromFiles → creflect.MarshalToJson，临时工具
# tmp_w2_dumpconf，用后删）。xray-go.exe 26.7.28 的 -dump 走 proto 域 marshal
# （Duration ns/零值物化），与本对照域不同层，故自建工具取同层输出。
GO = Path(r"D:/tmp/w2_dumpconf.exe")
RUST = ROOT / "target-w2/debug/xray.exe"
FX = ROOT / "crates/xray-conf/tests/fixtures/shadow"

GROUPS = [
    ("01-minimal", [FX / "01-minimal.json"]),
    ("02-full-apps", [FX / "02-full-apps.json"]),
    ("03-multi-inbounds", [FX / "03-multi-inbounds.json"]),
    ("04-outbound-chain", [FX / "04-outbound-chain.json"]),
    ("05-with-comments(jsonc)", [FX / "05-with-comments.jsonc"]),
    ("07-missing-sections", [FX / "07-missing-sections.json"]),
    ("w2/base-a", [FX / "w2/base-a.json"]),
    ("base+override", [FX / "base-layer.json", FX / "override-layer.json"]),
    ("base-a+override-b", [FX / "w2/base-a.json", FX / "w2/override-b.json"]),
    ("base-a+tail(追加)", [FX / "w2/base-a.json", FX / "w2/zz-tail-append.json"]),
    ("mt-base+mt-override(缺tag)", [FX / "w2/mt-base.json", FX / "w2/mt-override.json"]),
    ("三层链", [FX / "w2/base-a.json", FX / "w2/override-b.json", FX / "w2/third-layer.json"]),
]


def dump(binpath: Path, files: list[Path], cli=False):
    # dumpconf 工具吃裸文件路径；真 xray CLI 吃 `run -dump -c f`。
    cmd = [str(binpath)]
    if cli:
        cmd += ["run", "--dump"]
        for f in files:
            cmd += ["-c", str(f)]
    else:
        cmd += [str(f) for f in files]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    return p.returncode, p.stdout, p.stderr


def parse_json_loose(out: str):
    """跳过 Go info 日志行（时间戳开头；首行含 '{' 会污染 index('{')），取首个 '{' 行起的 JSON。"""
    lines = out.splitlines()
    start = next(i for i, l in enumerate(lines) if l.startswith("{"))
    return json.loads("\n".join(lines[start:]))

ZEROISH = (False, 0, 0.0, "", [], {})


def is_zeroish(v) -> bool:
    return v is False or v == 0 or v == "" or v == [] or v == {}


def strip_empty_strings(v):
    """Go isNullValue 类：空字符串字段两侧对齐（Go 跳过，Rust 保留 → 剥离）。"""
    if isinstance(v, dict):
        return {k: strip_empty_strings(x) for k, x in v.items() if x != ""}
    if isinstance(v, list):
        return [strip_empty_strings(x) for x in v]
    return v


def diff(path: str, a, b, out: list):
    if isinstance(a, dict) and isinstance(b, dict):
        for k in a:
            if k in b:
                diff(f"{path}.{k}", a[k], b[k], out)
            else:
                out.append(f"{path}.{k}: Go缺失(仅Rust)={json.dumps(a[k], ensure_ascii=False)[:80]}")
        for k in b:
            if k not in a:
                out.append(f"{path}.{k}: Rust缺失(仅Go)={json.dumps(b[k], ensure_ascii=False)[:80]}")
    elif isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            out.append(f"{path}: 数组长度 Go={len(a)} Rust={len(b)}")
        for i, (x, y) in enumerate(zip(a, b)):
            diff(f"{path}[{i}]", x, y, out)
    elif a != b:
        out.append(f"{path}: Go={json.dumps(a, ensure_ascii=False)[:60]} Rust={json.dumps(b, ensure_ascii=False)[:60]}")


def _val_after(d: str, marker: str):
    if marker not in d:
        return None
    raw = d.split(marker, 1)[1]
    try:
        return json.loads(raw)
    except Exception:
        return raw


def entries_sig(block):
    """in/outbounds 条目的 (tag, protocol, listen, port) 决策序（合并语义域）。"""
    sig = []
    for e in block or []:
        if not isinstance(e, dict):
            sig.append(e)
            continue
        sig.append((e.get("tag", ""), e.get("protocol", ""), e.get("listen"), e.get("port")))
    return sig


def merge_signature(v: dict) -> dict:
    """合并决策域签名：数组序 + 块存在集 + env 键值 + log 级别。

    恰好覆盖 tag 命中替换/追加/前插/tail/块整体替换/env 键级合并——
    typed 物化形态（零值/ns/Value 直传展开）全部落在签名之外。
    """
    blocks = ["log", "routing", "dns", "transport", "policy", "api", "metrics",
              "stats", "reverse", "fakeDns", "observatory", "burstObservatory",
              "version", "geodata"]
    return {
        "inbounds": entries_sig(v.get("inbounds")),
        "outbounds": entries_sig(v.get("outbounds")),
        "blocks_present": sorted(b for b in blocks if v.get(b) not in (None, {}, [])),
        "loglevel": (v.get("log") or {}).get("loglevel"),
        "env": dict(v.get("env") or {}),
    }


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "compare"
    out_dir = ROOT / "reports/audit-2026-10-27/tmp/go_dumps"
    if mode == "fetch-go":
        out_dir.mkdir(parents=True, exist_ok=True)
        for name, files in GROUPS:
            grc, gout, gerr = dump(GO, files)
            slug = name.replace("/", "_").replace("(", "_").replace(")", "")
            (out_dir / f"{slug}.json").write_text(
                json.dumps({"rc": grc, "stdout": gout, "stderr": gerr}, ensure_ascii=False),
                encoding="utf-8",
            )
            print(f"{name}: rc={grc} bytes={len(gout)}")
        return 0

    print(f"Go  = {GO}")
    print(f"Rust= {RUST}")
    print()
    total_bad = 0
    for name, files in GROUPS:
        slug = name.replace("/", "_").replace("(", "_").replace(")", "")
        saved = json.loads((out_dir / f"{slug}.json").read_text(encoding="utf-8"))
        grc, gout = saved["rc"], saved["stdout"]
        rrc, rout, rerr = dump(RUST, files, cli=True)
        if grc != 0 or rrc != 0:
            print(f"| {name} | Go rc={grc} Rust rc={rrc} |")
            if grc != 0:
                print(f"    Go err: {(gout + saved['stderr']).strip()[:160]}")
            if rrc != 0:
                print(f"    Rust err: {(rout + rerr).strip()[:160]}")
            total_bad += 1
            continue
        g = strip_empty_strings(parse_json_loose(gout))
        r = strip_empty_strings(parse_json_loose(rout))
        diffs: list[str] = []
        diff("$", g, r, diffs)
        # 语义归属分类：仅 Go 侧多出的零值/空值键 = Go typed marshal 非指针零值
        # 物化（duration ns 归一同类），非合并语义差异。
        go_art = [d for d in diffs if "仅Go=" in d and is_zeroish(_val_after(d, "仅Go="))]
        rust_art = [d for d in diffs if "仅Rust=" in d and is_zeroish(_val_after(d, "仅Rust="))]
        reals = [d for d in diffs if d not in go_art and d not in rust_art]
        status = "0 差异" if not reals else f"{len(reals)} 实差异"
        print(f"| {name} | {status}（Go 零值物化 {len(go_art)} / Rust 零值物化 {len(rust_art)}） |")
        for d in reals:
            print(f"    [REAL] {d}")
        for d in rust_art:
            print(f"    [rust-artifact·typed物化·影子0差异证旧有] {d}")
        for d in go_art[:6]:
            print(f"    [go-artifact·typed物化] {d}")
        if len(go_art) > 6:
            print(f"    ...go-artifact 共 {len(go_art)}")
        total_bad += len(reals)
    print()
    print(f"TOTAL residual diffs = {total_bad}")
    return 0 if total_bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
