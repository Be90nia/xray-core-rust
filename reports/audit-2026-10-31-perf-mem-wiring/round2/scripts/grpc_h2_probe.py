"""Round-2 audit probe: h2 (gRPC transport) server-side receive-window buffering.

Scenario: authenticated-looking VLESS request over the gRPC transport whose
destination never reads. Measures xray RSS while the client keeps pushing.

Compares transport tcp (baseline, bounded pipe) vs grpc (h2 window).
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
from h2.events import DataReceived, WindowUpdated, StreamReset, ResponseReceived

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
EXE = os.path.join(ROOT, "target", "release", "xray.exe")
TMP = os.path.join(ROOT, "reports", "audit-2026-10-31-perf-mem-wiring", "round2", "tmp")
UUID = "a3482e88-686a-4a58-8126-99c9df64b7bf"


def make_config(port, network, target_port):
    inbound = {
        "listen": "127.0.0.1",
        "port": port,
        "protocol": "vless",
        "settings": {"clients": [{"id": UUID}], "decryption": "none"},
    }
    if network == "grpc":
        inbound["streamSettings"] = {
            "network": "grpc",
            "security": "none",
            "grpcSettings": {"serviceName": "svc"},
        }
    else:
        inbound["streamSettings"] = {"network": "tcp", "security": "none"}
    return {
        "log": {"loglevel": "info"},
        "inbounds": [inbound],
        # vless inbound 默认注入 BlockPrivate → 显式 allow 才能拨 127.0.0.1
        "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow"}]}}],
    }


def start_xray(cfg, tag):
    os.makedirs(TMP, exist_ok=True)
    cfg_path = os.path.join(TMP, f"cfg-{tag}.json")
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    log_path = os.path.join(TMP, f"xray-{tag}.log")
    logf = open(log_path, "wb")
    p = subprocess.Popen([EXE, "run", "-c", cfg_path], stdout=logf,
                         stderr=subprocess.STDOUT, cwd=ROOT)
    time.sleep(2.5)
    if p.poll() is not None:
        raise SystemExit(f"xray died: {log_path}")
    return p, log_path


def never_read_server(port, stop_evt, accepted):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(16)
    srv.settimeout(0.5)
    while not stop_evt.is_set():
        try:
            c, _ = srv.accept()
        except socket.timeout:
            continue
        c.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        accepted.append(c)
        print(f"[target] accepted #{len(accepted)} (never reads)")
    stop_evt.wait(1)


def vless_header(target_port, payload=b""):
    u = uuidlib.UUID(UUID).bytes
    hdr = bytes([0]) + u + bytes([0]) + bytes([1])  # ver, uuid, addons len=0, cmd TCP
    hdr += struct.pack(">H", target_port) + bytes([1]) + socket.inet_aton("127.0.0.1")
    return hdr + payload


def grpc_frame(data: bytes) -> bytes:
    """gRPC length-prefixed frame carrying Hunk{data} (field 1, wire 2)."""
    inner = bytes([0x0A]) + varint(len(data)) + data
    return bytes([0]) + struct.pack(">I", len(inner)) + inner


def varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def sampler(proc, stop_evt, samples, interval=0.25):
    ps = psutil.Process(proc.pid)
    while not stop_evt.is_set():
        try:
            samples.append((time.time(), ps.memory_info().rss / 1048576, ps.num_handles()))
        except psutil.Error:
            break
        time.sleep(interval)


def run_h2_client(port, target_port, seconds, chunk=32768, stop_evt=None):
    sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    sock.settimeout(0.2)
    conn = H2Connection(config=H2Configuration(client_side=True, header_encoding="utf-8"))
    conn.initiate_connection()
    sock.sendall(conn.data_to_send())
    sid = conn.get_next_available_stream_id()
    conn.send_headers(sid, [
        (":method", "POST"), (":path", "/svc/Tun"), (":scheme", "http"),
        (":authority", f"127.0.0.1:{port}"), ("content-type", "application/grpc"),
    ], end_stream=False)
    sock.sendall(conn.data_to_send())

    first = grpc_frame(vless_header(target_port))
    sent = 0
    pending = first
    junk = grpc_frame(b"J" * chunk)
    t0 = time.time()
    reset = False
    stall_start = None
    while time.time() - t0 < seconds:
        # drain inbound (WINDOW_UPDATE / RESET / GOAWAY)
        try:
            data = sock.recv(65536)
            if data:
                for ev in conn.receive_data(data):
                    if isinstance(ev, WindowUpdated):
                        pass
                    elif isinstance(ev, StreamReset) and ev.stream_id == sid:
                        print(f"[client] server RESET stream at sent={sent/1048576:.1f}MB")
                        reset = True
                    elif isinstance(ev, ResponseReceived):
                        print("[client] response", ev.headers)
                out = conn.data_to_send()
                if out:
                    sock.sendall(out)
            else:
                print("[client] eof from server")
                break
        except socket.timeout:
            pass
        except OSError as e:
            print("[client] recv err", e)
            break
        if reset:
            break
        # window-limited send
        try:
            win = conn.local_flow_control_window(sid)
        except Exception:
            break
        if win <= len(pending) if pending else True:
            try:
                win = conn.local_flow_control_window(sid)
            except Exception:
                break
        body = pending if pending else junk
        if win <= 0:
            if stall_start is None:
                stall_start = time.time()
            time.sleep(0.05)
            continue
        stall_start = None
        take = body[: min(win, 16384)]
        conn.send_data(sid, take, end_stream=False)
        sent += len(take)
        if take == body:
            pending = b""
        else:
            pending = body[len(take):]
        try:
            sock.sendall(conn.data_to_send())
        except OSError as e:
            print("[client] send err", e)
            break
    print(f"[client] sent={sent/1048576:.1f}MB in {time.time()-t0:.0f}s"
          + (f" stalled_since={stall_start}" if stall_start else ""))
    return sock, conn, sid


def run_tcp_client(port, target_port, seconds, chunk=65536):
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    s.settimeout(5)
    s.sendall(vless_header(target_port))
    sent = 0
    t0 = time.time()
    try:
        while time.time() - t0 < seconds:
            n = s.send(b"J" * chunk)
            sent += n
    except (socket.timeout, OSError) as e:
        print(f"[client] stalled at {sent/1048576:.1f}MB ({e})")
    print(f"[client] sent={sent/1048576:.1f}MB in {time.time()-t0:.0f}s")
    return s


def report(samples, label, extra):
    base = min(s[1] for s in samples[:6])
    peak = max(s[1] for s in samples)
    print(f"[{label}] base_rss={base:.1f}MB peak_rss={peak:.1f}MB delta={peak-base:+.1f}MB {extra}")
    n = len(samples)
    idxs = sorted({0, n // 4, n // 2, (3 * n) // 4, n - 1})
    print("   curve: " + " ".join(f"{samples[i][1]:.0f}MB@{samples[i][0]-samples[0][0]:.0f}s"
                                  for i in idxs if i < n))
    path = os.path.join(TMP, f"samples-{label}.tsv")
    with open(path, "w", encoding="utf-8") as f:
        f.write("t\trss_mb\thandles\n")
        t0 = samples[0][0]
        for t, r, h in samples:
            f.write(f"{t-t0:.2f}\t{r:.2f}\t{h}\n")
    print("   samples:", path)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--network", default="grpc", choices=["grpc", "tcp"])
    ap.add_argument("--port", type=int, default=18090)
    ap.add_argument("--target-port", type=int, default=19097)
    ap.add_argument("--seconds", type=int, default=20)
    args = ap.parse_args()
    stop = threading.Event()
    accepted = []
    threading.Thread(target=never_read_server, args=(args.target_port, stop, accepted),
                     daemon=True).start()
    tag = f"{args.network}-h2probe"
    proc, log = start_xray(make_config(args.port, args.network, args.target_port), tag)
    samples = []
    threading.Thread(target=sampler, args=(proc, stop, samples), daemon=True).start()
    time.sleep(1.5)
    if args.network == "grpc":
        cli = run_h2_client(args.port, args.target_port, args.seconds)
    else:
        cli = run_tcp_client(args.port, args.target_port, args.seconds)
    time.sleep(2)
    stop.set()
    time.sleep(0.3)
    report(samples, tag, f"target_conns={len(accepted)}")
    proc.terminate()
    proc.wait(10)
    print("log:", log)


if __name__ == "__main__":
    main()
