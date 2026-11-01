"""E1: log domain — access log really written? dnsLog really produces DNS lines?

Config: socks-in -> freedom, routing domainStrategy=IPOnDemand (so a domain target is
resolved through the dns app), log.access -> file, log.dnsLog=true.

Signals:
  access.log line count and sample lines;
  presence/absence of any DNS-query line ("got answer" / query ip) in the same file.
"""

import json
import os
import socket
import subprocess
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
XRAY = os.path.join(ROOT, "target", "release", "xray.exe")
TMP = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tmp"))
os.makedirs(TMP, exist_ok=True)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def socks_connect(socks_port, host, port, timeout=5.0):
    s = socket.create_connection(("127.0.0.1", socks_port), timeout=timeout)
    s.sendall(b"\x05\x01\x00")
    s.recv(2)
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host.encode() + port.to_bytes(2, "big"))
    s.recv(10)
    return s


def main():
    socks_port = free_port()
    access_log = os.path.join(TMP, "e1_log_access.log")
    if os.path.exists(access_log):
        os.remove(access_log)
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    target_port = srv.getsockname()[1]

    def drain():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=lambda s: (s.recv(64), s.close()), args=(c,), daemon=True).start()

    threading.Thread(target=drain, daemon=True).start()

    cfg = {
        "log": {"loglevel": "warning", "access": access_log.replace("\\", "/"), "dnsLog": True},
        "dns": {"servers": ["localhost"], "queryStrategy": "UseIP"},
        "routing": {"domainStrategy": "IPOnDemand",
                    "rules": [{"type": "field", "ip": ["127.0.0.0/8"], "outboundTag": "direct"}]},
        "inbounds": [{"tag": "socks-in", "listen": "127.0.0.1", "port": socks_port,
                      "protocol": "socks", "settings": {"udp": False}}],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
    }
    path = os.path.join(TMP, "e1_log.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)

    proc = subprocess.Popen([XRAY, "run", "-c", path],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out = {"config": path, "access_log": access_log}
    try:
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                socket.create_connection(("127.0.0.1", socks_port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.2)
        for _ in range(2):
            # domain target forces a DNS resolve (routing IPOnDemand + dialer)
            c = socks_connect(socks_port, "localhost", target_port)
            c.sendall(b"hi")
            time.sleep(0.2)
            c.close()
            time.sleep(0.3)
        time.sleep(0.5)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        srv.close()
    lines = []
    if os.path.exists(access_log):
        with open(access_log, encoding="utf-8", errors="replace") as f:
            lines = [l.rstrip("\n") for l in f if l.strip()]
    out["access_log_exists"] = os.path.exists(access_log)
    out["access_log_lines"] = len(lines)
    out["access_log_sample"] = lines[:6]
    out["dns_lines"] = [l for l in lines if "got answer" in l or "->" in l or "dns" in l.lower()]
    print(json.dumps(out, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
