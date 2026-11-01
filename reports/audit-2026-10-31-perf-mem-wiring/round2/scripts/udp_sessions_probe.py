"""Round-2 audit probe: socks UDP ASSOCIATE session memory cost.

Each `UdpDispatchSession` lazily establishes two `tokio::io::duplex(256KiB)`
buffers (512KiB committed) on the first datagram, and the session lives until
the idle timeout. This probe opens N associates, sends one datagram each, and
measures RSS growth per session. No authentication needed (socks noauth).

Usage: python udp_sessions_probe.py --n 400
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


def config(port):
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": "127.0.0.1", "port": port, "protocol": "socks",
            "settings": {"udp": True, "auth": "noauth"},
        }],
        "outbounds": [{"protocol": "freedom"}],
    }


def start_xray(cfg, tag):
    os.makedirs(TMP, exist_ok=True)
    p_cfg = os.path.join(TMP, f"cfg-{tag}.json")
    with open(p_cfg, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    log_path = os.path.join(TMP, f"xray-{tag}.log")
    logf = open(log_path, "wb")
    p = subprocess.Popen([EXE, "run", "-c", p_cfg], stdout=logf,
                         stderr=subprocess.STDOUT, cwd=ROOT)
    time.sleep(2.5)
    if p.poll() is not None:
        raise SystemExit(f"xray died: {log_path}")
    return p, log_path


def assoc(port):
    """Returns (tcp_control, udp_sock, relay_port)."""
    c = socket.create_connection(("127.0.0.1", port), timeout=10)
    c.sendall(b"\x05\x01\x00")
    assert c.recv(2) == b"\x05\x00"
    c.sendall(b"\x05\x03\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack(">H", 0))
    rep = c.recv(10)
    assert rep[1] == 0, f"associate failed {rep!r}"
    relay_port = struct.unpack(">H", rep[8:10])[0]
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.settimeout(1)
    return c, u, relay_port


def sampler(proc, stop, samples, interval=0.25):
    ps = psutil.Process(proc.pid)
    while not stop.is_set():
        try:
            samples.append((time.time(), ps.memory_info().rss / 1048576, ps.num_handles()))
        except psutil.Error:
            break
        time.sleep(interval)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=400)
    ap.add_argument("--port", type=int, default=18095)
    ap.add_argument("--hold", type=int, default=8)
    args = ap.parse_args()
    proc, log = start_xray(config(args.port), "udpsess")
    stop = threading.Event()
    samples = []
    threading.Thread(target=sampler, args=(proc, stop, samples), daemon=True).start()
    time.sleep(1.5)
    base = samples[-1]
    conns = []
    sent = 0
    t0 = time.time()
    for i in range(args.n):
        try:
            c, u, rp = assoc(args.port)
        except (OSError, AssertionError) as e:
            print(f"associate #{i} failed: {e}")
            break
        # one datagram to a distinct destination (no listener -> ICMP unreachable)
        pkt = (b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1")
               + struct.pack(">H", 20000 + (i % 40000)) + b"probe")
        try:
            u.sendto(pkt, ("127.0.0.1", rp))
            sent += 1
        except OSError:
            pass
        conns.append((c, u))
        if i % 50 == 0:
            time.sleep(0.2)
    time.sleep(2)
    mid = samples[-1]
    print(f"associates={len(conns)} datagrams={sent} in {time.time()-t0:.0f}s")
    print(f"[udpsess] base_rss={base[1]:.1f}MB after_rss={mid[1]:.1f}MB "
          f"delta={mid[1]-base[1]:+.1f}MB => {(mid[1]-base[1])*1024/max(len(conns),1):.1f}KB/session "
          f"handles {base[2]}->{mid[2]}")
    time.sleep(args.hold)
    end = samples[-1]
    print(f"[udpsess] hold+{args.hold}s rss={end[1]:.1f}MB handles={end[2]} "
          f"(idle timeout is 300s by policy default; nothing reaped yet expected)")
    path = os.path.join(TMP, "samples-udpsess.tsv")
    with open(path, "w", encoding="utf-8") as f:
        f.write("t\trss_mb\thandles\n")
        for t, r, h in samples:
            f.write(f"{t-samples[0][0]:.2f}\t{r:.2f}\t{h}\n")
    print("samples:", path)
    stop.set()
    for c, u in conns:
        try:
            c.close()
        except OSError:
            pass
    proc.terminate()
    proc.wait(10)
    print("log:", log)


if __name__ == "__main__":
    main()
