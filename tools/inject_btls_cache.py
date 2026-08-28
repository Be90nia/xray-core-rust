"""btls-sys CMakeCache 幂等注入器。

上游 bug：build/main.rs host==target 早退跳过 windows OPENSSL_NO_ASM 分支，
新 fingerprint 的 build 目录从零 configure 时要 NASM（本机无）。对每个已存在的
CMakeCache.txt 追加注入（幂等），未生成 cache 的目录由首次失败生成后再注入。

用法：python tools/inject_btls_cache.py
"""
import os
import glob

INJECT = "\nOPENSSL_NO_ASM:INTERNAL=YES\nCMAKE_VS_GLOBALS:INTERNAL=TrackFileAccess=false\n"

for p in glob.glob(r"target/debug/build/btls-sys-*/out/build/CMakeCache.txt"):
    body = open(p, encoding="utf-8", errors="replace").read()
    if "OPENSSL_NO_ASM:INTERNAL=YES" in body:
        print(f"skip (injected): {os.path.dirname(os.path.dirname(p))}")
        continue
    with open(p, "a", newline="\n") as f:
        f.write(INJECT)
    print(f"injected: {os.path.dirname(os.path.dirname(p))}")
