#!/usr/bin/env python3
"""ClientHello 抓取/解析：接收 1 个连接，读取并解析首个 TLS record 的 ClientHello。

输出 JSON：ciphers / supported_versions / alpn / groups / sigalgs / ext_types / hello_len

用法：python hello_dump.py --port 28526 --out tmp/hello.json
"""
import argparse
import json
import socket
import struct
import sys


def parse_hello(rec):
    # rec: TLS record body（handshake message）
    out = {"record_len": None, "hello_len": None}
    if len(rec) < 4 or rec[0] != 0x01:
        out["error"] = f"not a ClientHello: {rec[:4].hex()}"
        return out
    hs_len = int.from_bytes(rec[1:4], "big")
    out["hello_len"] = hs_len
    body = rec[4:4 + hs_len]
    i = 0
    out["legacy_version"] = body[i:i + 2].hex()
    i += 2
    i += 32  # random
    sid_len = body[i]
    i += 1 + sid_len
    cs_len = int.from_bytes(body[i:i + 2], "big")
    i += 2
    ciphers = [body[i + k:i + k + 2].hex() for k in range(0, cs_len, 2)]
    out["ciphers"] = ciphers
    i += cs_len
    comp_len = body[i]
    i += 1 + comp_len
    if i + 2 > len(body):
        return out
    ext_total = int.from_bytes(body[i:i + 2], "big")
    i += 2
    end = min(len(body), i + ext_total)
    exts = []
    sup_ver = []
    alpn = []
    groups = []
    sigalgs = []
    keyshare_groups = []
    while i + 4 <= end:
        etype = int.from_bytes(body[i:i + 2], "big")
        elen = int.from_bytes(body[i + 2:i + 4], "big")
        i += 4
        data = body[i:i + elen]
        i += elen
        exts.append(etype)
        if etype == 0x002B:  # supported_versions
            n = data[0]
            sup_ver = [data[1 + k:1 + k + 2].hex() for k in range(0, n, 2)]
        elif etype == 0x0010:  # ALPN
            n = 0
            j = 2
            while j < len(data):
                ln = data[j]
                alpn.append(data[j + 1:j + 1 + ln].decode("latin1"))
                j += 1 + ln
                n += 1
        elif etype == 0x000A:  # supported_groups
            n = int.from_bytes(data[0:2], "big")
            groups = [int.from_bytes(data[2 + k:4 + k], "big") for k in range(0, n, 2)]
        elif etype == 0x000D:  # signature_algorithms
            n = int.from_bytes(data[0:2], "big")
            sigalgs = [int.from_bytes(data[2 + k:4 + k], "big") for k in range(0, n, 2)]
        elif etype == 0x0033:  # key_share
            n = int.from_bytes(data[0:2], "big")
            j = 2
            for _ in range(n):
                if j + 4 > len(data):
                    break
                grp = int.from_bytes(data[j:j + 2], "big")
                klen = int.from_bytes(data[j + 2:j + 4], "big")
                keyshare_groups.append({"group": grp, "len": klen})
                j += 4 + klen
    out["ext_types"] = [f"{e:04x}" for e in exts]
    out["supported_versions"] = sup_ver
    out["alpn"] = alpn
    out["groups"] = [f"{g:04x}" for g in groups]
    out["keyshare"] = keyshare_groups
    out["sigalgs_count"] = len(sigalgs)
    out["has_grease"] = any((c[0:2] == c[2:4]) and (int(c[0:2], 16) % 16 == 0x0A) for c in ciphers if len(c) == 4)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", a.port))
    srv.listen(4)
    srv.settimeout(20)
    res = {"ok": False}
    try:
        c, _ = srv.accept()
        c.settimeout(5)
        hdr = b""
        while len(hdr) < 5:
            chunk = c.recv(5 - len(hdr))
            if not chunk:
                break
            hdr += chunk
        if len(hdr) == 5:
            rlen = int.from_bytes(hdr[3:5], "big")
            body = b""
            while len(body) < rlen:
                chunk = c.recv(rlen - len(body))
                if not chunk:
                    break
                body += chunk
            res = parse_hello(body)
            res["ok"] = True
            res["record_len"] = rlen
        else:
            res["error"] = f"short header: {hdr.hex()}"
        c.close()
    except Exception as e:
        res["error"] = f"{type(e).__name__}: {e}"
    srv.close()
    with open(a.out, "w", encoding="utf-8") as fh:
        json.dump(res, fh, indent=2)
    print(json.dumps(res)[:600])


if __name__ == "__main__":
    sys.exit(main())
