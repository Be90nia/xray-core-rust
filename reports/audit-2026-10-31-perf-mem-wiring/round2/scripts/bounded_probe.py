"""Round-2 audit probe: slow-peer / resource-exhaustion bounds of the release binary.

Modes
-----
upslow   target accepts and NEVER reads; client hose-pipes bytes at it through socks5.
downtrick target accepts and never writes; client connects and never reads (idle hold).
downflood target writes forever; client never reads (downlink backpressure).
squat     N socks connections opened, no bytes sent (handshake squat).
udpstorm  socks UDP ASSOCIATE, packets to many distinct destinations.

Every mode samples xray RSS + handle count via psutil.

Usage: python bounded_probe.py --mode upslow --mb 600
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time

import psutil

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
EXE = os.path.join(ROOT, "target", "release", "xray.exe")
TMP = os.path.join(ROOT, "reports", "audit-2026-10-31-perf-mem-wiring", "round2", "tmp")


def socks_config(port, udp=False):
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": port,
                "protocol": "socks",
                "settings": {"udp": udp, "auth": "noauth"},
            }
        ],
        "outbounds": [{"protocol": "freedom"}],
    }


def start_xray(cfg, tag):
    os.makedirs(TMP, exist_ok=True)
    cfg_path = os.path.join(TMP, f"cfg-{tag}.json")
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    log_path = os.path.join(TMP, f"xray-{tag}.log")
    logf = open(log_path, "wb")
    p = subprocess.Popen(
        [EXE, "run", "-c", cfg_path],
        stdout=logf,
        stderr=subprocess.STDOUT,
        cwd=ROOT,
    )
    time.sleep(2.5)
    if p.poll() is not None:
        raise SystemExit(f"xray died: see {log_path}")
    return p, log_path


def socks5_connect(proxy_port, dest_host="127.0.0.1", dest_port=9999, timeout=10):
    s = socket.create_connection(("127.0.0.1", proxy_port), timeout=timeout)
    s.settimeout(timeout)
    s.sendall(b"\x05\x01\x00")
    assert s.recv(2) == b"\x05\x00", "socks greeting failed"
    host = dest_host.encode()
    req = b"\x05\x01\x00\x03" + bytes([len(host)]) + host + struct.pack(">H", dest_port)
    s.sendall(req)
    rep = s.recv(10)
    assert len(rep) >= 2 and rep[1] == 0, f"socks connect failed {rep!r}"
    return s


def sampler(proc, stop_evt, samples, interval=0.25):
    ps = psutil.Process(proc.pid)
    while not stop_evt.is_set():
        try:
            rss = ps.memory_info().rss / (1024 * 1024)
            handles = ps.num_handles() if hasattr(ps, "num_handles") else ps.num_fds()
        except psutil.Error:
            break
        samples.append((time.time(), rss, handles))
        time.sleep(interval)


def report(samples, label, extra=""):
    if not samples:
        print(f"[{label}] no samples")
        return
    base = min(s[1] for s in samples[:4]) if len(samples) >= 4 else samples[0][1]
    h0 = samples[0][2]
    peak_i = max(range(len(samples)), key=lambda i: samples[i][1])
    peak = samples[peak_i]
    print(f"[{label}] base_rss={base:.1f}MB peak_rss={peak[1]:.1f}MB "
          f"delta={peak[1]-base:+.1f}MB  handles {h0}->{peak[2]} {extra}")
    # coarse curve
    n = len(samples)
    idxs = [0, n // 4, n // 2, (3 * n) // 4, n - 1]
    curve = " ".join(f"{samples[i][1]:.0f}MB@{samples[i][0]-samples[0][0]:.0f}s"
                     for i in idxs if i < n)
    print(f"   curve: {curve}")
    return base, peak[1]


# ---------------------------------------------------------------- target servers
def never_read_server(port, stop_evt, accepted):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(64)
    srv.settimeout(0.5)
    conns = []
    while not stop_evt.is_set():
        try:
            c, _ = srv.accept()
        except socket.timeout:
            continue
        c.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)  # tiny window: max backpressure
        accepted.append(c)
        conns.append(c)
    # hold conns open until the end (do not read, do not close)
    stop_evt.wait(1)
    for c in conns:
        c.close()


def flood_write_server(port, stop_evt, chunk=b"x" * 65536):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(64)
    srv.settimeout(0.5)
    while not stop_evt.is_set():
        try:
            c, _ = srv.accept()
        except socket.timeout:
            continue
        threading.Thread(target=_pump_out, args=(c, stop_evt, chunk), daemon=True).start()


def _pump_out(c, stop_evt, chunk):
    c.settimeout(0.5)
    while not stop_evt.is_set():
        try:
            c.sendall(chunk)
        except (socket.timeout, OSError):
            # socket blocked or busted: keep the conn alive, retry slowly
            time.sleep(0.05)
            try:
                c.send(b"\x00")
            except OSError:
                return
    c.close()


# ---------------------------------------------------------------- modes
def mode_upslow(args):
    stop = threading.Event()
    accepted = []
    threading.Thread(target=never_read_server, args=(args.target_port, stop, accepted),
                     daemon=True).start()
    proc, log = start_xray(socks_config(args.proxy_port), "upslow")
    samples = []
    threading.Thread(target=sampler, args=(proc, stop, samples), daemon=True).start()
    time.sleep(2.0)
    sent = 0
    chunk = b"A" * 65536
    total = args.mb * 1024 * 1024
    c = socks5_connect(args.proxy_port, dest_port=args.target_port)
    c.settimeout(5)
    t0 = time.time()
    stalled_at = None
    try:
        while sent < total:
            if time.time() - t0 > args.seconds:
                break
            try:
                n = c.send(chunk if sent + len(chunk) <= total else chunk[: total - sent])
            except socket.timeout:
                stalled_at = sent
                break
            if n == 0:
                break
            sent += n
    except OSError as e:
        print("client send error:", e)
    # after stall keep sampling: memory must not keep growing with no reader
    time.sleep(3)
    stop.set()
    time.sleep(0.5)
    report(samples, "upslow", f"sent={sent/1048576:.1f}MB stalled_at={stalled_at and round(stalled_at/1048576,1)} "
                             f"dur={time.time()-t0:.0f}s")
    yield_samples(samples, "upslow")
    proc.terminate(); proc.wait(10)
    print("log:", log)


def mode_downflood(args):
    stop = threading.Event()
    threading.Thread(target=flood_write_server, args=(args.target_port, stop), daemon=True).start()
    proc, log = start_xray(socks_config(args.proxy_port), "downflood")
    samples = []
    threading.Thread(target=sampler, args=(proc, stop, samples), daemon=True).start()
    time.sleep(2.0)
    socks5_connect(args.proxy_port, dest_port=args.target_port)  # never read
    time.sleep(args.seconds)
    stop.set()
    time.sleep(0.5)
    report(samples, "downflood", f"dur={args.seconds}s client-never-reads")
    yield_samples(samples, "downflood")
    proc.terminate(); proc.wait(10)
    print("log:", log)


def mode_downtrick(args):
    stop = threading.Event()
    threading.Thread(target=never_read_server, args=(args.target_port, stop, []), daemon=True).start()
    proc, log = start_xray(socks_config(args.proxy_port), "downtrick")
    samples = []
    threading.Thread(target=sampler, args=(proc, stop, samples), daemon=True).start()
    time.sleep(2.0)
    socks5_connect(args.proxy_port, dest_port=args.target_port)
    time.sleep(args.seconds)
    stop.set(); time.sleep(0.5)
    report(samples, "downtrick", f"dur={args.seconds}s idle-but-connected")
    yield_samples(samples, "downtrick")
    proc.terminate(); proc.wait(10)
    print("log:", log)


def mode_squat(args):
    stop = threading.Event()
    proc, log = start_xray(socks_config(args.proxy_port), "squat")
    samples = []
    threading.Thread(target=sampler, args=(proc, stop, samples), daemon=True).start()
    time.sleep(2.0)
    base_rss = samples[-1][1]
    base_h = samples[-1][2]
    conns = []
    for _ in range(args.n):
        try:
            conns.append(socket.create_connection(("127.0.0.1", args.proxy_port), timeout=5))
        except OSError as e:
            print("connect fail:", e)
            break
    print(f"opened={len(conns)}")
    time.sleep(1.5)
    mid = samples[-1]
    print(f"after open: rss={mid[1]:.1f}MB (+{mid[1]-base_rss:.1f}MB for {len(conns)} conns "
          f"= {(mid[1]-base_rss)*1024/max(len(conns),1):.1f}KB/conn) handles={mid[2]}")
    # wait past handshake timeout (60s default)
    time.sleep(args.wait)
    end = samples[-1]
    print(f"after {args.wait}s wait: rss={end[1]:.1f}MB handles={end[2]} "
          f"(peak during window {max(s[1] for s in samples):.1f}MB)")
    for c in conns:
        try:
            c.settimeout(1); alive = c.recv(1)
        except (socket.timeout, OSError):
            alive = None
    stop.set(); time.sleep(0.5)
    yield_samples(samples, "squat")
    proc.terminate(); proc.wait(10)
    print("log:", log)


def mode_udpstorm(args):
    stop = threading.Event()
    proc, log = start_xray(socks_config(args.proxy_port, udp=True), "udpstorm")
    samples = []
    threading.Thread(target=sampler, args=(proc, stop, samples), daemon=True).start()
    time.sleep(2.0)
    base = samples[-1]
    # SOCKS5 UDP ASSOCIATE over TCP control conn
    c = socket.create_connection(("127.0.0.1", args.proxy_port), timeout=10)
    c.sendall(b"\x05\x01\x00")
    assert c.recv(2) == b"\x05\x00"
    c.sendall(b"\x05\x03\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack(">H", 0))
    rep = c.recv(10)
    assert rep[1] == 0, f"associate failed {rep!r}"
    relay_port = struct.unpack(">H", rep[8:10])[0]
    if relay_port == 0:
        # empty bind addr: parse actual port from a normal socks request instead
        relay_port = struct.unpack(">H", rep[len(rep) - 2:])[0]
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.settimeout(1)
    payload = b"P" * 16
    sent = 0
    t0 = time.time()
    for i in range(args.n):
        if time.time() - t0 > args.seconds:
            break
        # distinct destination per packet: target_port+i, 127.0.0.x sweep for source diversity
        dp = 20000 + (i % 40000)
        ip = bytes([127, 0, (i // 250) % 255, 1])
        pkt = b"\x00\x00\x00\x01" + ip + struct.pack(">H", dp) + payload
        try:
            u.sendto(pkt, ("127.0.0.1", relay_port))
            sent += 1
        except OSError:
            time.sleep(0.001)
    time.sleep(3)
    end = samples[-1]
    print(f"[udpstorm] sent={sent} distinct_dests={args.n} base_rss={base[1]:.1f}MB "
          f"end_rss={end[1]:.1f}MB peak={max(s[1] for s in samples):.1f}MB "
          f"handles {base[2]}->{end[2]} dur={time.time()-t0:.0f}s")
    stop.set(); time.sleep(0.5)
    yield_samples(samples, "udpstorm")
    try:
        c.close()
    except OSError:
        pass
    proc.terminate(); proc.wait(10)
    print("log:", log)


def yield_samples(samples, tag):
    path = os.path.join(TMP, f"samples-{tag}.tsv")
    with open(path, "w", encoding="utf-8") as f:
        f.write("t\trss_mb\thandles\n")
        t0 = samples[0][0] if samples else 0
        for t, rss, h in samples:
            f.write(f"{t-t0:.2f}\t{rss:.2f}\t{h}\n")
    print("samples:", path)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", required=True)
    ap.add_argument("--proxy-port", type=int, default=18080)
    ap.add_argument("--target-port", type=int, default=19099)
    ap.add_argument("--mb", type=int, default=600)
    ap.add_argument("--seconds", type=int, default=20)
    ap.add_argument("--n", type=int, default=2000)
    ap.add_argument("--wait", type=int, default=65)
    args = ap.parse_args()
    globals()[f"mode_{args.mode}"](args)


if __name__ == "__main__":
    main()
