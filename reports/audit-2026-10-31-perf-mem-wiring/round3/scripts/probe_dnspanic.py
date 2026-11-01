"""专探：Go 26.10.17 在 dns.servers 缺 address 时 panic（rc=2）。"""
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import GO, RUST, TMP  # noqa: E402

CASES = [
    ("obj_no_address", {"port": 53}),
    ("obj_only_port", {"port": 5353}),
    ("obj_empty", {}),
    ("obj_null_address", {"address": None}),
    ("obj_address_empty_str", {"address": ""}),
    ("str_empty", ""),
    ("str_colon", "127.0.0.1:1"),
    ("str_colon_port", "8.8.8.8:53"),
]


def mkcfg(server):
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{"tag": "in-socks", "listen": "127.0.0.1", "port": 25040,
                      "protocol": "socks", "settings": {"auth": "noauth", "udp": False}}],
        "outbounds": [{"tag": "out-free", "protocol": "freedom", "settings": {}}],
        "dns": {"servers": [server]},
    }


def probe(exe, cfg_path, timeout=6):
    try:
        r = subprocess.run([exe, "run", "-c", cfg_path], capture_output=True, text=True,
                           timeout=timeout)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired as e:
        def _d(x):
            if x is None:
                return ""
            return x.decode("utf-8", "replace") if isinstance(x, bytes) else x
        return "RUNNING", _d(e.stdout) + _d(e.stderr)


def main():
    for name, server in CASES:
        path = os.path.join(TMP, "probe_dnspanic_%s.json" % name)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(mkcfg(server), f, indent=2)
        g_rc, g_out = probe(GO, path)
        r_rc, r_out = probe(RUST, path)
        g_panic = "panic:" in g_out or "goroutine" in g_out
        print("[%s] server=%r" % (name, server))
        print("   GO   rc=%s panic=%s" % (g_rc, g_panic))
        for l in g_out.splitlines():
            if g_panic or "Failed to start" in l:
                print("        G:", l[:170])
                if g_panic and "main.go" in l:
                    break
        print("   RUST rc=%s" % r_rc)
        for l in r_out.splitlines():
            if "ERROR" in l or "error" in l.lower() or "Failed" in l:
                print("        R:", l[:170])


if __name__ == "__main__":
    main()
