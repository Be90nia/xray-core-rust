#!/usr/bin/env python3
"""TLS 观测服务器：记录每个连接的协商结果（version/cipher/ALPN/SNI）与首段应用层字节。

用法：
  python tls_srv.py --port 28510 --cert fixtures/leaf.pem --key fixtures/leaf.key \
      --alpn h2,http/1.1 --conns 1 --out tmp/srv.log.jsonl

输出 JSONL，每连接一行：
  {"conn":1,"ok":true,"version":"TLSv1.3","cipher":"...","alpn":"h2","sni":"...",
   "app_bytes":123,"app_head":"1603..."} 或 {"ok":false,"error":"..."}
"""
import argparse
import json
import socket
import ssl
import sys
import time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--alpn", default="")
    ap.add_argument("--conns", type=int, default=1)
    ap.add_argument("--out", required=True)
    ap.add_argument("--min-ver", default="TLSv1.2")
    ap.add_argument("--max-ver", default="")
    a = ap.parse_args()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(a.cert, a.key)
    ctx.minimum_version = getattr(ssl.TLSVersion, a.min_ver.replace("TLSv1.2", "TLSv1_2").replace("TLSv1.3", "TLSv1_3"))
    if a.max_ver:
        ctx.maximum_version = getattr(ssl.TLSVersion, a.max_ver.replace("TLSv1.2", "TLSv1_2").replace("TLSv1.3", "TLSv1_3"))
    if a.alpn:
        ctx.set_alpn_protocols([x for x in a.alpn.split(",") if x])

    sni_seen = {"name": None}

    def _sni_cb(sslobj, server_name, ctx2):
        sni_seen["name"] = server_name
        return None

    ctx.sni_callback = _sni_cb

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", a.port))
    srv.listen(8)
    srv.settimeout(30)

    out = open(a.out, "w", encoding="utf-8")
    for i in range(a.conns):
        try:
            raw, _ = srv.accept()
        except socket.timeout:
            out.write(json.dumps({"conn": i + 1, "ok": False, "error": "accept timeout"}) + "\n")
            out.flush()
            break
        rec = {"conn": i + 1, "ok": False}
        raw.settimeout(5)
        try:
            tls = ctx.wrap_socket(raw, server_side=True)
            rec["ok"] = True
            rec["version"] = tls.version()
            rec["cipher"] = tls.cipher()[0] if tls.cipher() else None
            rec["alpn"] = tls.selected_alpn_protocol()
            rec["sni"] = sni_seen["name"]
            # 读首段应用层数据（vless/trojan 头或任意 payload）
            tls.settimeout(2.0)
            try:
                data = tls.recv(256)
            except socket.timeout:
                data = b""
            rec["app_bytes"] = len(data)
            rec["app_head"] = data[:16].hex()
            try:
                tls.close()
            except Exception:
                pass
        except Exception as e:  # handshake rejected by client / cert problems
            rec["error"] = f"{type(e).__name__}: {e}"
            try:
                raw.close()
            except Exception:
                pass
        out.write(json.dumps(rec) + "\n")
        out.flush()
        time.sleep(0.05)
    out.close()
    srv.close()


if __name__ == "__main__":
    sys.exit(main())
