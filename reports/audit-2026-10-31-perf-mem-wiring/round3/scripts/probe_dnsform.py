"""专探：DNS server 地址形态的接受度差异（Go 拒启 vs Rust 放行）。"""
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import GO, RUST, TMP  # noqa: E402

CASES = [
    ("plain_ip", "8.8.8.8"),
    ("ip_port", "127.0.0.1:1"),
    ("ip_port_dns", "127.0.0.1:5353"),
    ("https_url", "https://dns.google/dns-query"),
    ("tcp_local", "tcp+local://8.8.8.8"),
    ("quic", "quic://8.8.8.8"),
    ("localhost", "localhost"),
    ("ipv6", "2001:4860:4860::8888"),
    ("ipv6_brackets", "[2001:4860:4860::8888]"),
    ("garbage", "not-an-ip-at-all"),
    ("empty", ""),
    ("with_port_field", {"address": "8.8.8.8", "port": 5353}),
    ("with_port_only", {"address": "127.0.0.1", "port": 1}),
    ("obj_no_address", {"port": 53}),
]


def mkcfg(server):
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{"tag": "in-socks", "listen": "127.0.0.1", "port": 25039,
                      "protocol": "socks", "settings": {"auth": "noauth", "udp": False}}],
        "outbounds": [{"tag": "out-free", "protocol": "freedom", "settings": {}}],
        "dns": {"servers": [server]},
    }


def probe(exe, cfg_path, timeout=8):
    try:
        r = subprocess.run([exe, "run", "-c", cfg_path], capture_output=True, text=True,
                           timeout=timeout)
        out = (r.stdout or "") + (r.stderr or "")
        return r.returncode, out
    except subprocess.TimeoutExpired as e:
        def _dec(x):
            if x is None:
                return ""
            if isinstance(x, bytes):
                return x.decode("utf-8", "replace")
            return x
        return "RUNNING", _dec(e.stdout) + _dec(e.stderr)


def main():
    for name, server in CASES:
        cfg = mkcfg(server)
        path = os.path.join(TMP, "probe_dnsform_%s.json" % name)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        g_rc, g_out = probe(GO, path)
        r_rc, r_out = probe(RUST, path)
        g_first = next((l for l in g_out.splitlines() if "Failed to start" in l
                        or "failed" in l.lower()), g_out.strip().splitlines()[-1] if g_out.strip() else "")
        r_first = next((l for l in r_out.splitlines() if "error" in l.lower() or "ERROR" in l),
                       r_out.strip().splitlines()[-1] if r_out.strip() else "")
        print("[%s] server=%r" % (name, server))
        print("   GO   rc=%s :: %s" % (g_rc, g_first[:180]))
        print("   RUST rc=%s :: %s" % (r_rc, r_first[:180]))


if __name__ == "__main__":
    main()
