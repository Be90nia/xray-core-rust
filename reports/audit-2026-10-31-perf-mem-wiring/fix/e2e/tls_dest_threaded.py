#!/usr/bin/env python3
"""并发版 TLS dest（每连接一线程）：避免单线程 accept 排队把后到的真实探针饿死。

用法：python tls_dest_threaded.py --port P --cert C --key K --out f.jsonl --seconds 25
每连接一行：{"t":ts,"ok":bool,"version":..,"alpn":..,"sni":..,"app_bytes":..,"error":..}
"""
import argparse
import json
import socket
import ssl
import sys
import threading
import time

LOCK = threading.Lock()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--seconds", type=float, default=25.0)
    a = ap.parse_args()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(a.cert, a.key)
    made = [0]

    def log(rec):
        with LOCK:
            with open(a.out, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec) + "\n")

    def sni_cb(sslobj, name, c):
        sslobj.sni_seen = name
        return None

    ctx.sni_callback = sni_cb

    def handle(raw, n):
        rec = {"conn": n, "ok": False}
        raw.settimeout(6.0)
        try:
            tls = ctx.wrap_socket(raw, server_side=True)
            rec["ok"] = True
            rec["version"] = tls.version()
            rec["cipher"] = tls.cipher()[0] if tls.cipher() else None
            rec["alpn"] = tls.selected_alpn_protocol()
            rec["sni"] = getattr(tls, "sni_seen", None)
            tls.settimeout(2.0)
            try:
                data = tls.recv(256)
            except socket.timeout:
                data = b""
            rec["app_bytes"] = len(data)
            try:
                tls.close()
            except Exception:
                pass
        except Exception as e:
            rec["error"] = f"{type(e).__name__}: {e}"
            try:
                raw.close()
            except Exception:
                pass
        log(rec)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", a.port))
    srv.listen(16)
    end = time.time() + a.seconds
    srv.settimeout(0.5)
    while time.time() < end:
        try:
            raw, _ = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        made[0] += 1
        threading.Thread(target=handle, args=(raw, made[0]), daemon=True).start()
    srv.close()
    time.sleep(0.3)


if __name__ == "__main__":
    sys.exit(main())
