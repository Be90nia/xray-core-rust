#!/usr/bin/env python3
r"""构建**带汇编**的 BoringSSL 预构建库（Windows 专用），供 btls-sys 走
`BORING_BSSL_PATH` 预构建路线链接。

## 为什么需要这个（票 jyipl，P1）

`btls-sys` 的 build.rs 在 Windows 上**无条件**设 `OPENSSL_NO_ASM=YES`
（原文注释：*"BoringSSL's CMakeLists.txt isn't set up for cross-compiling using
Visual Studio. Disable assembly support so that it at least builds."*）。后果：

1. `crypto/cpu_intel.cc` 被整文件排除 → **AES-NI / AVX2 探测恒为 false**
2. 密码协商因此落到 **CHACHA20**，而 chacha20-poly1305 的汇编也被排除 →
   **纯 C 回退**
3. 每 record CPU ~7-11× → 客户端单核打满

实测（vless+tcp+tls，指纹 chrome，`D:/tmp/aj0n3_ab.py` B 组）：

| 构�� | 吞吐 | cli CPU |
|---|---|---|
| NO_ASM（cargo 默认路径） | 31.6 MB/s | 18.8 s |
| 本脚本产出的 ASM 库 | **241.2 MB/s**（best 253.0） | **2.48 s** |

而且开汇编后 BoringSSL 能正确探测 AES-NI → 协商 **TLS_AES_128_GCM_SHA256**，
与 Go `crypto/tls` 的偏好一致（Go 也是 AES-NI 硬件支持则优先 AES-GCM）。

**注意**：Linux/macOS 不需要本脚本——btls-sys 只在 Windows 分支设 NO_ASM。

## 用法

```bat
python tools\build_boringssl_asm.py            :: 编 + 组装 + 打印 env
python tools\build_boringssl_asm.py --check    :: 只体检（不编）
```

产出布局（btls-sys 的 `BORING_BSSL_PATH` 约定：`{crypto.lib, ssl.lib, include/openssl}`）：

```
target/boringssl-asm/prebuilt/{crypto.lib, ssl.lib, include/openssl/**}
```

随后用该路径构建 xray：

```bat
set BORING_BSSL_ASSUME_PATCHED=1
set BORING_BSSL_PATH=D:/Project/Xray-core-rust/target/boringssl-asm/prebuilt
set PROTOC=D:/Project/tools/bin/protoc.exe
set LIBCLANG_PATH=D:\Program Files\llvm\bin
cargo build --release -p xray-cli
```

## 前置

- **NASM**（x86_64 Windows 汇编器）：本仓已有 `D:/Project/tools/nasm.exe`；
  也可用 `C:/Users/<user>/AppData/Local/bin/NASM/nasm.exe`（CMake 会自动找到）
- **cmake**（本仓 `D:/Program Files/Python 3.14/Scripts/cmake.exe` 或 PATH 里的）
- **MSVC**（Visual Studio 2022 Build Tools）
- **已打补丁的 BoringSSL 源树**：`target/boringssl-patched`（含 REALITY 补丁；
  由 `tools/setup_boringssl_reality.py` 产出，**禁手改**）

## 校验（编完必查，缺一即视为没开汇编）

1. `CMakeCache.txt` 里**没有** `OPENSSL_NO_ASM`
2. `CMakeCache.txt` 里 `CMAKE_ASM_NASM_COMPILER_WORKS:INTERNAL=1`
3. 产出的 `crypto.lib` **比无汇编版大**（无汇编 ≈ 7,006,776 B；带汇编 ≈ 7,050,528 B）
4. `dumpbin /symbols` 能看到 chacha20-poly1305 / AES-NI 符号
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "target" / "boringssl-patched"
BUILD = REPO / "target" / "boringssl-asm" / "build"
STAGE = REPO / "target" / "boringssl-asm" / "prebuilt"
NASM_CANDIDATES = [
    Path(r"D:\Project\tools\nasm.exe"),
    Path.home() / "AppData" / "Local" / "bin" / "NASM" / "nasm.exe",
    Path(r"C:\Program Files\NASM\nasm.exe"),
    Path(r"C:\ProgramData\chocolatey\bin\nasm.exe"),
]


def find_nasm() -> Path | None:
    for cand in NASM_CANDIDATES:
        if cand.is_file():
            return cand
    found = shutil.which("nasm")
    return Path(found) if found else None


def run(cmd: list[str], **kw) -> None:
    print(f"$ {' '.join(cmd)}", flush=True)
    subprocess.run(cmd, check=True, **kw)


# VS 生成器随 runner 镜像变：windows-2025-vs2026 只装 VS 2026（cmake 生成器
# "Visual Studio 18 2026"，cmake ≥4.2 才有），钉死 17 2022 会报
# "could not find any instance of Visual Studio"。逐个试，配通即止。
VS_GENERATORS = ("Visual Studio 18 2026", "Visual Studio 17 2022")


def configure(src: Path, build: Path, nasm: Path) -> None:
    """cmake 配置 BoringSSL：VS 生成器候选逐个试（最后一个 = cmake 默认生成器）。"""
    candidates = [["-G", gen, "-A", "x64"] for gen in VS_GENERATORS] + [["-A", "x64"]]
    for gen_args in candidates:
        shutil.rmtree(build, ignore_errors=True)
        try:
            run([
                "cmake", "-S", str(src), "-B", str(build),
                *gen_args,
                f"-DCMAKE_ASM_NASM_COMPILER={nasm}",
            ])
            return
        except subprocess.CalledProcessError:
            print(f"[warn] 生成器 {gen_args or '默认'} 不可用，换下一个", file=sys.stderr)
    raise SystemExit("[FAIL] 所有 VS 生成器候选都配不通（见上方 cmake 报错）")


def health(src: Path | None = None, dest: Path | None = None) -> int:
    """体检：源树 / NASM / 缓存里的 NO_ASM 标志。返回退出码。"""
    src = src or SRC
    dest = dest or STAGE
    build = dest.parent / "build"
    problems: list[str] = []
    if not (src / "ssl" / "ssl_lib.cc").is_file():
        problems.append(f"缺补丁源树 {src}（跑 tools/setup_boringssl_reality.py 产出）")
    nasm = find_nasm()
    if nasm is None:
        problems.append("找不到 NASM（D:\\Project\\tools\\nasm.exe 或 %LOCALAPPDATA%\\bin\\NASM\\nasm.exe）")
    else:
        print(f"[ok] NASM: {nasm}")
    cache = build / "CMakeCache.txt"
    if cache.is_file():
        text = cache.read_text(encoding="utf-8", errors="replace")
        if "OPENSSL_NO_ASM" in text:
            problems.append("CMakeCache.txt 里出现 OPENSSL_NO_ASM → 汇编没开")
        else:
            print("[ok] CMakeCache 无 OPENSSL_NO_ASM")
        if "CMAKE_ASM_NASM_COMPILER_WORKS:INTERNAL=1" in text:
            print("[ok] CMAKE_ASM_NASM_COMPILER_WORKS=1")
        else:
            problems.append("CMAKE_ASM_NASM_COMPILER_WORKS != 1")
    stage = dest / "crypto.lib"
    if stage.is_file():
        size = stage.stat().st_size
        print(f"[info] 已组装 crypto.lib: {size} B（无汇编约 7,006,776 B）")
        if size < 7_020_000:
            problems.append("crypto.lib 大小像无汇编构建 → 汇编没进去")
    else:
        problems.append(f"未组装 {stage}")
    for p in problems:
        print(f"[FAIL] {p}", file=sys.stderr)
    return 1 if problems else 0


def main() -> int:
    # Windows 控制台默认 ANSI 代码页（cp1252/cp437）：脚本里带中文的 print 会
    # UnicodeEncodeError 直接崩掉整个构建（CI 里 stdout 编码 = 代码页）。强制
    # UTF-8 输出 + 替换兜底，保证日志可读且不因编码中断构建。
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):  # 非 TextIOWrapper（被重定向到别处）
            pass
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", help="只体检，不编译")
    ap.add_argument("--jobs", type=int, default=14, help="并行编译作业数")
    ap.add_argument(
        "--src",
        default=None,
        help="已打补丁的 BoringSSL 源树（默认 target/boringssl-patched；"
        "CI 上由 setup-boringssl action 产出，走 $BORING_BSSL_SOURCE_PATH）",
    )
    ap.add_argument(
        "--dest",
        default=None,
        help="预构建库输出目录（默认 target/boringssl-asm/prebuilt）",
    )
    args = ap.parse_args()

    src = Path(args.src) if args.src else SRC
    dest = Path(args.dest) if args.dest else STAGE
    if args.check:
        return health(src, dest)

    nasm = find_nasm()
    if nasm is None:
        print("[FAIL] 找不到 NASM，见文档前置", file=sys.stderr)
        return 2
    if not (src / "ssl" / "ssl_lib.cc").is_file():
        print(f"[FAIL] 缺补丁源树 {src}", file=sys.stderr)
        return 2

    build = dest.parent / "build"
    build.parent.mkdir(parents=True, exist_ok=True)
    configure(src, build, nasm)
    run(["cmake", "--build", str(build), "--config", "Release", "--parallel", str(args.jobs)])

    dest.mkdir(parents=True, exist_ok=True)
    for lib in ("crypto.lib", "ssl.lib"):
        src_lib = build / "Release" / lib
        if not src_lib.is_file():
            print(f"[FAIL] 缺 {src_lib}", file=sys.stderr)
            return 2
        shutil.copy2(src_lib, dest / lib)
    inc_dst = dest / "include"
    if inc_dst.exists():
        shutil.rmtree(inc_dst)
    shutil.copytree(src / "include", inc_dst)

    print("\n[ok] 预构建库已组装：", dest)
    print("构建 xray 时带上：")
    print(f"  set BORING_BSSL_ASSUME_PATCHED=1")
    print(f"  set BORING_BSSL_PATH={dest.as_posix()}")
    return health(src, dest)


if __name__ == "__main__":
    raise SystemExit(main())
