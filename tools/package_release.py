#!/usr/bin/env python3
"""release 产物打包（G-21）：二进制 + README/LICENSE → zip + 四算法 dgst。

对齐 Go `.github/workflows/release.yml:270-291`：
- 产物内含 README.md 与 LICENSE（许可证随包分发）；
- zip 打包（zip -9 等价：ZIP_DEFLATED level 9，mtime 归一到当年 1 月 1 日，
  与 Go `touch -mt $(date +%Y01010000)` 同思路，保证同内容同包）；
- 每个上传文件生成 `<file>.dgst`，四行 `MD5= / SHA1= / SHA256= / SHA512=`，
  格式等同 Go 的 `openssl dgst -$M $FILE | sed 's/([^)]*)//g'`（用户脚本可直接解析）。

用 hashlib 而非 openssl：Linux/macOS/Windows 一致，便于本机跑同一份逻辑。

用法：python tools/package_release.py dist [--docs .]
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import zipfile
from pathlib import Path

ALGOS = ("md5", "sha1", "sha256", "sha512")
DOC_FILES = ("README.md", "LICENSE")
# Go 侧 touch -mt $(date +%Y01010000)：固定到当年 1 月 1 日，同内容同包
FIXED_TIME = (2026, 1, 1, 0, 0, 0)


def digest_lines(path: Path) -> str:
    digests = {algo: hashlib.new(algo) for algo in ALGOS}
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            for d in digests.values():
                d.update(chunk)
    return "".join(f"{algo.upper()}= {digests[algo].hexdigest()}\n" for algo in ALGOS)


def write_dgst(path: Path) -> Path:
    out = path.with_name(path.name + ".dgst")
    out.write_text(digest_lines(path), encoding="utf-8")
    return out


def make_zip(binary: Path, docs: list[Path]) -> Path:
    stem = binary.name[:-4] if binary.name.lower().endswith(".exe") else binary.name
    zip_path = binary.with_name(f"{stem}.zip")
    # 压缩级别必须在 writestr 上给：ZipInfo 入参时 ZipFile 构造的 compresslevel 不生效
    with zipfile.ZipFile(zip_path, "w") as zf:
        for src in [binary, *docs]:
            info = zipfile.ZipInfo(src.name, date_time=FIXED_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o755 << 16  # zip 内保留可执行位（Go `zip -v` 同效）
            zf.writestr(info, src.read_bytes(), compresslevel=9)
        assert set(zf.namelist()) == {p.name for p in (binary, *docs)}, zf.namelist()
    return zip_path


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("dist", help="已拍平的二进制目录（原地追加 .zip / .dgst）")
    ap.add_argument("--docs", default=str(Path(__file__).resolve().parent.parent),
                    help="README.md / LICENSE 所在目录（缺省仓根）")
    args = ap.parse_args()

    dist = Path(args.dist)
    docs_dir = Path(args.docs)
    docs = [docs_dir / name for name in DOC_FILES]
    absent = [str(d) for d in docs if not d.is_file()]
    if absent:
        print(f"FAIL：缺随包文档 {', '.join(absent)}", file=sys.stderr)
        return 1

    binaries = [
        p for p in sorted(dist.iterdir())
        if p.is_file() and not p.name.endswith((".zip", ".dgst")) and p.name not in DOC_FILES
    ]
    if not binaries:
        print(f"FAIL：{dist} 内无可打包二进制", file=sys.stderr)
        return 1

    for binary in binaries:
        zip_path = make_zip(binary, docs)
        for produced in (zip_path, write_dgst(zip_path), write_dgst(binary)):
            print(f"{produced.name}\t{produced.stat().st_size} bytes")
    print(f"PASS：{len(binaries)} 个二进制 → zip + dgst（随包文档：{', '.join(d.name for d in docs)}）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
