#!/usr/bin/env python3
"""REALITY fallback 目标服务器（"被偷站"）：记录收到的字节并回 banner。

用法：python dest_srv.py --port 28521 --conns 2 --out tmp/dest.jsonl

每连接一行：
  {"conn":1,"first_len":517,"first_head":"1603010201...","second_len":0,
   "second_head":"", "sent_banner":true}
"""
import argparse
import json
import socket
import sys
import time

BANNER = b"DEST-BANNER-OK\r\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--conns", type=int, default=1)
    ap.add_argument("--out", required=True)
    ap.add_argument("--timeout", type=float, default=2.0)
    a = ap.parse_args()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", a.port))
    srv.listen(8)
    srv.settimeout(30)
    out = open(a.out, "w", encoding="utf-8")
    for i in range(a.conns):
        try:
            c, _ = srv.accept()
        except socket.timeout:
            out.write(json.dumps({"conn": i + 1, "ok": False, "error": "accept timeout"}) + "\n")
            out.flush()
            break
        rec = {"conn": i + 1, "ok": True}
        c.settimeout(a.timeout)
        deadline = time.time() + a.timeout
        first = b""
        try:
            while time.time() < deadline and len(first) < 4096:
                chunk = c.recv(4096)
                if not chunk:
                    break
                first += chunk
        except socket.timeout:
            pass
        except OSError as e:
            rec["recv_error"] = str(e)
        rec["first_len"] = len(first)
        rec["first_head"] = first[:24].hex()
        try:
            c.sendall(BANNER)
            rec["sent_banner"] = True
        except OSError as e:
            rec["sent_banner"] = False
            rec["send_error"] = str(e)
        # 再读一小段，观察客户端后续
        second = b""
        c.settimeout(1.0)
        try:
            second = c.recv(4096)
        except socket.timeout:
            pass
        except OSError as e:
            rec["recv2_error"] = str(e)
        rec["second_len"] = len(second)
        rec["second_head"] = second[:24].hex()
        try:
            c.close()
        except Exception:
            pass
        out.write(json.dumps(rec) + "\n")
        out.flush()
    out.close()
    srv.close()


if __name__ == "__main__":
    sys.exit(main())
