"""Round-2 audit probe: half-close occupancy (client shutdown(WR), peer never writes).

N socks connections -> target that accepts and never writes -> client sends 1 byte
then shutdown(SHUT_WR). Measures whether the server tears the session down
(fd/RSS back to baseline) or keeps it until ConnectionIdle (300s).

Usage: python halfclose_probe.py --n 300
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import struct
import subprocess
import threading
import time

import psutil

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
EXE = os.path.join(ROOT, "target", "release", "xray.exe")
TMP = os.path.join(ROOT, "reports", "audit-2026-10-31-perf-mem-wiring", "round2", "tmp")


def cfg(port):
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "socks",
                      "settings": {"auth": "noauth"}}],
        "outbounds": [{"protocol": "freedom"}],
    }


def start_xray(c, tag):
    os.makedirs(TMP, exist_ok=True)
    p_cfg = os.path.join(TMP, f"cfg-{tag}.json")
    with open(p_cfg, "w", encoding="utf-8") as f:
        json.dump(c, f, indent=2)
    log_path = os.path.join(TMP, f"xray-{tag}.log")
    logf = open(log_path, "wb")
    p = subprocess.Popen([EXE, "run", "-c", p_cfg], stdout=logf,
                         stderr=subprocess.STDOUT, cwd=ROOT)
    time.sleep(2.5)
    if p.poll() is not None:
        raise SystemExit(f"xray died: {log_path}")
    return p, log_path


def silent_target(port, stop):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(256)
    srv.settimeout(0.3)
    held = []
    while not stop.is_set():
        try:
            c, _ = srv.accept()
            held.append(c)  # accept, never write, keep open
        except socket.timeout:
            continue
    stop.wait(1)


def socks_connect(port, dest_port):
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    s.sendall(b"\x05\x01\x00")
    assert s.recv(2) == b"\x05\x00"
    host = b"127.0.0.1"
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + struct.pack(">H", dest_port))
    rep = s.recv(10)
    assert rep[1] == 0, rep
    return s


def snap(ps):
    return ps.memory_info().rss / 1048576, ps.num_handles()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=300)
    ap.add_argument("--port", type=int, default=18101)
    ap.add_argument("--target-port", type=int, default=19094)
    args = ap.parse_args()
    stop = threading.Event()
    threading.Thread(target=silent_target, args=(args.target_port, stop), daemon=True).start()
    proc, log = start_xray(cfg(args.port), "halfclose")
    ps = psutil.Process(proc.pid)
    time.sleep(1.5)
    base = snap(ps)
    conns = []
    for _ in range(args.n):
        try:
            c = socks_connect(args.port, args.target_port)
            c.sendall(b"x")
            c.shutdown(socket.SHUT_WR)
            conns.append(c)
        except (OSError, AssertionError) as e:
            print("conn fail:", e)
            break
    time.sleep(1.0)
    after = snap(ps)
    print(f"[halfclose] conns={len(conns)} base={base[0]:.1f}MB/{base[1]}h "
          f"after_open={after[0]:.1f}MB/{after[1]}h delta={after[0]-base[0]:+.1f}MB")
    for wait in (2, 5, 10, 20):
        time.sleep(wait - (0 if wait == 2 else 0))
        cur = snap(ps)
        print(f"[halfclose] t≈{wait}s rss={cur[0]:.1f}MB handles={cur[1]}")
    # are the client sockets still usable (did the server close)?
    alive = 0
    for c in conns:
        try:
            c.settimeout(0.2)
            if c.recv(1) == b"":
                alive += 1  # clean EOF from server
        except socket.timeout:
            pass
        except OSError:
            alive += 1
    print(f"[halfclose] server-closed-or-EOF on {alive}/{len(conns)} conns after hold")
    stop.set()
    proc.terminate()
    proc.wait(10)
    print("log:", log)


if __name__ == "__main__":
    main()
