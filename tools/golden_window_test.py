"""黄金窗口自动测速（schtasks 明早 05:00 触发）
5 轮 10MB 下载（走 us1:39824 raw+reality），中位数判据：
  >=25 PASS / >=20 CONDITIONAL / <20 FAIL（fail 自动带 FRDBG 现场日志）
结果落 D:/Project/Xray-core-rust/reports/golden-window-2026-10-13.log
"""
import subprocess, time, os, datetime

XRAY = r"D:\Program Files\v2rayN-windows-64\bin\xray\xray.exe"
CFG = r"D:\Project\Xray-core-rust\target\tmp-perftest\perf-a-btls.json"
D = r"D:\Project\Xray-core-rust\target\tmp-perftest"
URL = "https://speed.cloudflare.com/__down?bytes=10485760"
OUT = r"D:\Project\Xray-core-rust\reports\golden-window-2026-10-13.log"

env = dict(os.environ)
env["XRAY_FRDBG"] = "1"

lines = [f"# golden window test @ {datetime.datetime.now():%Y-%m-%d %H:%M:%S}"]
results = []
for i in (1, 2, 3, 4, 5):
    logf = open(os.path.join(D, f"gw-{i}.log"), "wb")
    p = subprocess.Popen([XRAY, "run", "-c", CFG], stdout=logf, stderr=subprocess.STDOUT, cwd=D, env=env)
    time.sleep(2)
    try:
        r = subprocess.run(
            ["curl", "-s", "--max-time", "20", "--socks5-hostname", "127.0.0.1:15901",
             "-o", os.devnull, "-w", "%{speed_download}", URL],
            capture_output=True, text=True, cwd=D)
        try:
            mbps = float(r.stdout.strip()) / 1048576
        except ValueError:
            mbps = -1.0
        results.append(mbps)
        lines.append(f"round{i}: {mbps:.2f} MB/s")
    finally:
        p.terminate()
        try:
            p.wait(timeout=5)
        except Exception:
            p.kill()
        logf.close()
    time.sleep(1)

ok = sorted(x for x in results if x > 0)
med = ok[len(ok) // 2] if ok else -1.0
verdict = "PASS>=25" if med >= 25 else ("CONDITIONAL>=20" if med >= 20 else "FAIL<20")
lines.append(f"MEDIAN: {med:.2f} MB/s")
lines.append(f"VERDICT: {verdict}")

os.makedirs(os.path.dirname(OUT), exist_ok=True)
with open(OUT, "w", encoding="utf-8") as f:
    f.write("\n".join(lines) + "\n")
print("\n".join(lines))
