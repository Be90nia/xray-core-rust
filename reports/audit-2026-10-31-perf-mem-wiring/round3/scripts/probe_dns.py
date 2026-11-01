import socket, subprocess, sys, os, json, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import GO, RUST, TMP

# 1) 25032 是否真无人监听
s = socket.socket(); s.settimeout(0.5)
try:
    s.connect(("127.0.0.1", 25032)); print("25032 LISTENING (unexpected)")
except OSError as e:
    print("25032 dead:", e)
finally:
    s.close()

# 2) Go exit 23 的完整输出
cfg = {
  "log": {"loglevel": "warning"},
  "inbounds": [{"tag":"in-socks","listen":"127.0.0.1","port":25030,
                "protocol":"socks","settings":{"auth":"noauth","udp":False}}],
  "outbounds": [{"tag":"out-free","protocol":"freedom","settings":{"domainStrategy":"UseIP"}}],
  "dns": {"servers": ["127.0.0.1:1"], "queryStrategy": "UseIP"},
}
p = os.path.join(TMP, "probe_dns_dead.json")
open(p,"w").write(json.dumps(cfg, indent=2))
for name, exe in (("GO", GO), ("RUST", RUST)):
    r = subprocess.run([exe, "run", "-c", p], capture_output=True, text=True, timeout=30)
    print("---", name, "exit=", r.returncode)
    print("STDOUT:", r.stdout[:1500])
    print("STDERR:", r.stderr[:800])
