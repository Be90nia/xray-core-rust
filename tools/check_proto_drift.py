#!/usr/bin/env python3
"""protos/ 镜像漂移门 —— 纪律见 protos/README.md（镜像只准从 Go 基线 rsync 同步，禁手改）。

三模式（互斥）：
  --manifest          校验 protos/**/*.proto 与 protos/.checksums.json 一致（CI 门）
  --upstream <go-repo> 逐文件比对 protos/ 与 Go 仓同相对路径，列真实漂移清单
  --write             重生成 protos/.checksums.json
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROTOS = ROOT / "protos"
MANIFEST = PROTOS / ".checksums.json"


def sha256_of(path: Path) -> str:
    # 行尾归一化：index 存 LF，Windows 工作树是 CRLF（autocrlf）。
    # 不归一的话 manifest 在 Windows 生成、在 CI（LF 检出）必 mismatch。
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def scan_protos() -> dict:
    """protos/ 下全部 *.proto → {posix 相对路径: sha256}，键序确定。"""
    return {
        p.relative_to(PROTOS).as_posix(): sha256_of(p)
        for p in sorted(PROTOS.rglob("*.proto"))
    }


def cmd_manifest() -> int:
    if not MANIFEST.is_file():
        print(f"FAIL: {MANIFEST.name} 不存在，先跑 --write 生成", file=sys.stderr)
        return 1
    recorded = json.loads(MANIFEST.read_text(encoding="utf-8"))
    current = scan_protos()
    changed = sorted(k for k in current if k in recorded and current[k] != recorded[k])
    added = sorted(k for k in current if k not in recorded)
    removed = sorted(k for k in recorded if k not in current)
    if not (changed or added or removed):
        print(f"OK: {len(current)} 个 proto 与 .checksums.json 一致")
        return 0
    print("FAIL: protos/ 与 .checksums.json 不一致——有人手改镜像？")
    print("纪律：protos/ 修改必须从 Go 基线 rsync 同步（protos/README.md），禁直接编辑")
    for label, items in (
        ("内容被改", changed),
        ("新增未登记", added),
        ("已删但仍登记", removed),
    ):
        for rel in items:
            print(f"  [{label}] {rel}")
    return 1


def cmd_upstream(go_repo: str) -> int:
    upstream = Path(go_repo).resolve()
    if not upstream.is_dir():
        print(f"FAIL: 上游 Go 仓不存在: {upstream}", file=sys.stderr)
        return 1
    current = scan_protos()
    # 镜像范围 = protos/ 的子目录（与 Go 仓顶层前缀一一对应）+ 根级散文件
    scope_dirs = sorted(d.name for d in PROTOS.iterdir() if d.is_dir())

    missing, differs, extra = [], [], []
    for rel in current:
        src = upstream / rel
        if not src.is_file():
            extra.append(rel)
        elif sha256_of(src) != current[rel]:
            differs.append(rel)
    for d in scope_dirs:
        for p in sorted((upstream / d).rglob("*.proto")):
            rel = p.relative_to(upstream).as_posix()
            if rel not in current:
                missing.append(rel)
    for p in sorted(upstream.glob("*.proto")):
        if p.name not in current:
            missing.append(p.name)

    if not (missing or differs or extra):
        print(f"OK: {len(current)} 个 proto 与上游 {upstream} 完全一致")
        return 0
    print(f"FAIL: protos/ 镜像与上游 {upstream} 存在漂移（对照票 bd 5std G-01/02/03 类）")
    for label, items in (
        ("镜像缺失", missing),
        ("内容不同", differs),
        ("镜像多余", extra),
    ):
        for rel in items:
            print(f"  [{label}] {rel}")
    print(f"合计: 缺失 {len(missing)} / 不同 {len(differs)} / 多余 {len(extra)}"
          f"（镜像现有 {len(current)} 个）")
    return 1


def cmd_write() -> int:
    current = scan_protos()
    if not current:
        print(f"FAIL: {PROTOS} 下没有任何 *.proto", file=sys.stderr)
        return 1
    MANIFEST.write_text(
        json.dumps(current, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"OK: 已写 {MANIFEST.relative_to(ROOT).as_posix()}（{len(current)} 个 proto）")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--manifest", action="store_true", help="校验 .checksums.json（CI 默认）")
    g.add_argument("--upstream", metavar="GO_REPO", help="比对 Go 仓同相对路径，列漂移清单")
    g.add_argument("--write", action="store_true", help="重生成 .checksums.json")
    args = ap.parse_args()
    if args.manifest:
        return cmd_manifest()
    if args.upstream:
        return cmd_upstream(args.upstream)
    return cmd_write()


if __name__ == "__main__":
    sys.exit(main())
