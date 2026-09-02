#!/usr/bin/env python3
"""对每个 URI 起一个 dist/xray.exe + socks12080+端口,curl 一次 PASS/FAIL。"""
import subprocess, time, os, sys, urllib.parse as up
sys.path.insert(0, os.path.dirname(__file__))
from uriclient import cfg

URI_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "vps测试连接.txt"))
BIN = os.path.abspath("dist/xray.exe")
WORK = "D:/tmp/xray_runs"
TEST_URL = "https://www.youtube.com/"

os.makedirs(WORK, exist_ok=True)

def run_one(idx, uri):
    sp = 13000 + idx
    cfg_path = f"{WORK}/r{idx}.json"
    log_path = f"{WORK}/r{idx}.log"
    try:
        ob = cfg(uri.strip(), sp)
    except Exception as e:
        return f"#{idx}\tPARSE_ERR\t{type(e).__name__}: {e}"
    cfgobj = {
        "log":{"loglevel":"warning"},
        "inbounds":[{"tag":"socks-in","listen":"127.0.0.1","port":sp,"protocol":"socks","settings":{"udp":True},"sniffing":{"enabled":True,"destOverride":["http","tls","quic"]}}],
        "outbounds":[ob, {"tag":"direct","protocol":"freedom","settings":{}}]
    }
    import json
    open(cfg_path,"w",encoding="utf-8").write(json.dumps(cfgobj, ensure_ascii=False))
    try:
        # kill any stale
        subprocess.run(["cmd","/c","taskkill /F /IM xray.exe"], capture_output=True, timeout=5)
        time.sleep(0.3)
        p = subprocess.Popen([BIN, "run", "-c", cfg_path], stdout=open(log_path,"wb"), stderr=subprocess.STDOUT)
        time.sleep(4)
        code = subprocess.run(["curl","-sS","--max-time","20","-x",f"socks5h://127.0.0.1:{sp}", TEST_URL, "-o","NUL","-w","%{http_code} %{size_download}"], capture_output=True, text=True, timeout=25)
        parts = (code.stdout.strip() or "NONE 0").split()
        rc = parts[0] if parts else "NONE"
        try: blen = int(parts[1])
        except: blen = 0
        verdict = "PASS" if rc in ("200","301","302") and blen > 10000 else ("HALF" if rc in ("200","301","302") else "FAIL")
        p.terminate()
        try: p.wait(timeout=5)
        except: p.kill()
        subprocess.run(["cmd","/c","taskkill /F /IM xray.exe"], capture_output=True, timeout=5)
        label = ob.get("protocol","?") + ("+reality" if ob.get("streamSettings",{}).get("security")=="reality" else "+tls" if ob.get("streamSettings",{}).get("security")=="tls" else "")
        net = ob.get("streamSettings",{}).get("network","tcp")
        return f"#{idx}\t{verdict}\t{label}\tnet={net}\tHTTP={rc}\tbody={blen}B\t{up.urlparse(uri).fragment or uri[:40]}"
    except Exception as e:
        return f"#{idx}\tRUN_ERR\t{type(e).__name__}: {e}"

def main():
    uris = [u.strip() for u in open(URI_FILE, encoding="utf-8") if u.strip() and not u.startswith("#")]
    out = ["#\tverdict\tprotocol\tnet\tHTTP\tbody\tname"]
    for i, uri in enumerate(uris, 1):
        line = run_one(i, uri)
        out.append(line)
        print(line, flush=True)
    open(f"{WORK}/results.txt","w",encoding="utf-8").write("\n".join(out))
    print(f"\n=== saved to {WORK}/results.txt ===")

if __name__=="__main__":
    main()
