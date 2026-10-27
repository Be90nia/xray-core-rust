"""W6 interop 门：把 RUST 常量指向 target-w4 迁移后产物（W4 先例同款思路：
门语义/用例集合零改动——不改 interop_matrix.py 本体，只在内存中改 RUST 路径）。

interop_matrix.py 的用例集跑在模块级 `if __name__ == '__main__'` 分支里，
导入不会触发；runpy 会重建模块字典并让源码顶层的 `RUST = ...` 覆盖覆写。
故本 runner 直接读源码 → 内存内替换 RUST 常量 → 以 __main__ 语义 exec。
"""
import sys

RUST_BIN = "D:/Project/Xray-core-rust/target-w4/release/xray.exe"

src = open("dist/interop_matrix.py", encoding="utf-8").read()
old = "RUST = 'dist/xray.exe'"
assert src.count(old) == 1, f"unexpected RUST assignment count: {src.count(old)}"
src = src.replace(old, f"RUST = {RUST_BIN!r}")

ns = {"__name__": "__main__", "__file__": "dist/interop_matrix.py"}
exec(compile(src, "dist/interop_matrix.py", "exec"), ns)
