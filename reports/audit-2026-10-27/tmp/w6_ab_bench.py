"""W6 面 4 性能门：A/B 同窗交错对照。

口径：
- A' = 当前树仅回退 hot_log 代码 hunk 的构建（单变量：迁移本体）
- B  = 当前树含迁移的构建
- 3 个窗口交错（A' B A' B A' B），每窗口 --runs 3，与 baseline.md「块级交替」口径一致
- alloc-stats 开（alloc/MB 硬锚 2.22）
- floor 用 120（baseline.md 记本机窗口摆动 16%，154-167 带在当前树上历史落点见报告披露）
"""
import subprocess
import sys

BENCH = "tools/loopback_alloc_bench.py"
# 两臂都用 /d/tmp/enc8x 下的**冻结副本**，绝不用 target-w4 共享路径：
# target-w4/release/xray.exe 是共享构建输出，A' 构建与 B 重建都会写它
# （首轮 B 窗口曾误跑 A' 二进制 → 整轮作废）。
A = "D:/tmp/enc8x/xray-w6-Aprime.exe"   # A' = 迁移前（仅回退 hot_log 代码 hunk）
B = "D:/tmp/enc8x/xray-w6-B.exe"        # B  = 迁移后（冻结副本，md5 f4327146...）

results = []
for i in range(3):
    for tag, binary in (("ap", A), ("b", B)):
        tagname = f"w6-hotlog-{tag}{i+1}"
        print(f"\n===== window {i+1} [{tagname}] binary={binary} =====", flush=True)
        r = subprocess.run(
            [sys.executable, BENCH, "--tag", tagname, "--xray", binary,
             "--runs", "3", "--alloc-stats", "--floor", "120"],
            capture_output=True, text=True, encoding="utf-8", errors="replace")
        out = r.stdout + ("\nSTDERR:" + r.stderr if r.stderr else "")
        for line in out.splitlines():
            if any(k in line for k in ("[via-enc-chain]", "alloc/MB", "floor check",
                                       "FLOOR", "window_start", "window_end", "site=",
                                       "transferred")):
                print(line, flush=True)
        print(f"--- exit={r.returncode} ---", flush=True)
        results.append((tagname, binary, r.returncode, out))

print("\n\n===== SUMMARY (speed lines per window) =====")
for tagname, binary, rc, out in results:
    speeds = [l for l in out.splitlines() if "[via-enc-chain]" in l]
    alloc = [l for l in out.splitlines() if "alloc/MB" in l and "=" in l and "N/A" not in l]
    print(f"{tagname:22s} rc={rc}  {' | '.join(s.split('speed=')[1].split(' B/s')[0] for s in speeds)}")
    for a in alloc:
        print(f"    {a.strip()}")
