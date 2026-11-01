"""Round-2 audit probe: gRPC/h2 stream-count amplification and dokodemo UDP
per-source session table.

Modes
-----
h2streams  one TCP connection, N h2 streams opened with headers only (no body).
           Each accepted stream spawns a task and parks in the VLESS 60s
           handshake read -> measures per-stream RSS cost (1 fd -> N x cost).
dokodemo   dokodemo-door UDP inbound, packets from N distinct source ports.
           Each source creates a per-peer session (mpsc(64) + task + 64KiB buf).

Usage: python stream_sessions_probe.py --mode h2streams --n 500
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
import uuid as uuidlib

import psutil
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import StreamReset, ResponseReceived

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
EXE = os.path.join(ROOT, "target", "release", "xray.exe")
TMP = os.path.join(ROOT, "reports", "audit-2026-10-31-perf-mem-wiring", "round2", "tmp")
UUID = "a3482e88-686a-4a58-8126-99c9df64b7bf"


def grpc_cfg(port):
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": "127.0.0.1", "port": port, "protocol": "vless",
            "settings": {"clients": [{"id": UUID}], "decryption": "none"},
            "streamSettings": {"network": "grpc", "security": "none",
                               "grpcSettings": {"serviceName": "svc"}},
        }],
        "outbounds": [{"protocol": "freedom",
                       "settings": {"finalRules": [{"action": "allow"}]}}],
    }


def dokodemo_cfg(port, target_port):
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": "127.0.0.1", "port": port, "protocol": "dokodemo-door",
            "settings": {"address": "127.0.0.1", "port": target_port,
                         "network": "udp", "timeout": 0},
        }],
        "outbounds": [{"protocol": "freedom",
                       "settings": {"finalRules": [{"action": "allow"}]}}],
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


def sampler(proc, stop, samples, interval=0.2):
    ps = psutil.Process(proc.pid)
    while not stop.is_set():
        try:
            samples.append((time.time(), ps.memory_info().rss / 1048576, ps.num_handles()))
        except psutil.Error:
            break
        time.sleep(interval)


def silent_udp_sink(port, stop):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", port))
    s.settimeout(0.3)
    n = 0
    while not stop.is_set():
        try:
            s.recv(65535)
            n += 1
        except socket.timeout:
            continue
        except OSError:
            break
    print(f"[sink] received {n} datagrams")


def mode_h2streams(args):
    proc, log = start_xray(grpc_cfg(args.port), "h2streams")
    stop = threading.Event()
    samples = []
    threading.Thread(target=sampler, args=(proc, stop, samples), daemon=True).start()
    time.sleep(1.5)
    base = samples[-1]
    sock = socket.create_connection(("127.0.0.1", args.port), timeout=10)
    sock.settimeout(0.2)
    conn = H2Connection(config=H2Configuration(client_side=True, header_encoding="utf-8"))
    conn.initiate_connection()
    sock.sendall(conn.data_to_send())
    opened = 0
    resets = 0
    for i in range(args.n):
        sid = conn.get_next_available_stream_id()
        conn.send_headers(sid, [
            (":method", "POST"), (":path", "/svc/Tun"), (":scheme", "http"),
            (":authority", f"127.0.0.1:{args.port}"), ("content-type", "application/grpc"),
        ], end_stream=False)
        try:
            sock.sendall(conn.data_to_send())
        except OSError as e:
            print("send err", e)
            break
        opened += 1
        # drain responses/resets periodically so the socket does not fill up
        if i % 20 == 0:
            try:
                data = sock.recv(65536)
                for ev in conn.receive_data(data) if data else []:
                    if isinstance(ev, StreamReset):
                        resets += 1
                out = conn.data_to_send()
                if out:
                    sock.sendall(out)
            except (socket.timeout, OSError):
                pass
    time.sleep(0.5)
    # drain any resets
    try:
        while True:
            data = sock.recv(65536)
            if not data:
                break
            for ev in conn.receive_data(data):
                if isinstance(ev, StreamReset):
                    resets += 1
            out = conn.data_to_send()
            if out:
                sock.sendall(out)
    except (socket.timeout, OSError):
        pass
    time.sleep(args.hold)
    mid = samples[-1]
    print(f"[h2streams] opened={opened} resets={resets} base_rss={base[1]:.1f}MB "
          f"after_rss={mid[1]:.1f}MB delta={mid[1]-base[1]:+.1f}MB "
          f"=> {(mid[1]-base[1])*1024/max(opened,1):.1f}KB/stream handles {base[2]}->{mid[2]}")
    # let the 60s handshake timeout reap them
    time.sleep(args.wait)
    end = samples[-1]
    print(f"[h2streams] +{args.wait}s rss={end[1]:.1f}MB handles={end[2]} "
          f"peak={max(s[1] for s in samples):.1f}MB")
    stop.set()
    _dump(samples, "h2streams")
    proc.terminate()
    proc.wait(10)
    print("log:", log)


def mode_dokodemo(args):
    stop = threading.Event()
    threading.Thread(target=silent_udp_sink, args=(args.target_port, stop), daemon=True).start()
    proc, log = start_xray(dokodemo_cfg(args.port, args.target_port), "dokodemo")
    samples = []
    threading.Thread(target=sampler, args=(proc, stop, samples), daemon=True).start()
    time.sleep(1.5)
    base = samples[-1]
    socks = []
    t0 = time.time()
    for i in range(args.n):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        try:
            s.sendto(b"q" * 16, ("127.0.0.1", args.port))
        except OSError:
            pass
        socks.append(s)
    time.sleep(1.0)
    mid = samples[-1]
    print(f"[dokodemo] sources={len(socks)} in {time.time()-t0:.0f}s base_rss={base[1]:.1f}MB "
          f"after_rss={mid[1]:.1f}MB delta={mid[1]-base[1]:+.1f}MB "
          f"=> {(mid[1]-base[1])*1024/max(len(socks),1):.1f}KB/source handles {base[2]}->{mid[2]}")
    time.sleep(args.hold)
    print(f"[dokodemo] +{args.hold}s rss={samples[-1][1]:.1f}MB handles={samples[-1][2]}")
    stop.set()
    _dump(samples, "dokodemo")
    proc.terminate()
    proc.wait(10)
    print("log:", log)


def _dump(samples, tag):
    path = os.path.join(TMP, f"samples-{tag}.tsv")
    with open(path, "w", encoding="utf-8") as f:
        f.write("t\trss_mb\thandles\n")
        t0 = samples[0][0]
        for t, r, h in samples:
            f.write(f"{t-t0:.2f}\t{r:.2f}\t{h}\n")
    print("samples:", path)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", required=True, choices=["h2streams", "dokodemo"])
    ap.add_argument("--n", type=int, default=500)
    ap.add_argument("--port", type=int, default=18097)
    ap.add_argument("--target-port", type=int, default=19095)
    ap.add_argument("--hold", type=int, default=3)
    ap.add_argument("--wait", type=int, default=65)
    args = ap.parse_args()
    globals()[f"mode_{args.mode}"](args)


if __name__ == "__main__":
    main()
