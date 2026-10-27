# W4 interop 门：模块导入覆写 RUST 变量指向 target-w4 迁移后产物（W3a 先例同款，
# 门语义/用例集合零改动——不改 interop_matrix.py 本体）。
import sys

sys.path.insert(0, "dist")
import interop_matrix

interop_matrix.RUST = "D:/Project/Xray-core-rust/target-w4/release/xray.exe"

rc = interop_matrix.main() if hasattr(interop_matrix, "main") else None
if rc is None:
    # 脚本若以模块级代码跑 main，重跑其 __main__ 等价路径
    import contextlib
    import io

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        pass
if rc is not None:
    sys.exit(rc)
