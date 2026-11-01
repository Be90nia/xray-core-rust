"""Adversarial fuzz harness for xray.exe inbounds (round2 security audit).

Drives malformed payloads at live inbounds, watches for:
  - process death
  - new "panicked" lines in the server log
  - inbound port staying open after a fuzz round (accept-loop liveness)
  - RSS growth (memory amplification)

Usage: python fuzz_inbounds.py <logfile> [round]
"""
import os
import socket
import struct
import subprocess
import sys
import threading
import time
import random

LOG = sys.argv[1]
ROUND = sys.argv[2] if len(sys.argv) > 2 else "all"
HOST = "127.0.0.1"

PORTS = {
    "socks": 19101,
    "http": 19102,
    "vless": 19103,
    "vmess": 19104,
    "trojan": 19105,
    "ss": 19106,
    "ss2022": 19107,
}

UUID = bytes.fromhex("11111111222233334444555555555555")


def rss_kb():
    """RSS of xray.exe processes via wmic (KB)."""
    try:
        out = subprocess.run(
            ["wmic", "process", "where", "name='xray.exe'", "get", "WorkingSetSize", "/value"],
            capture_output=True, text=True, timeout=20,
        ).stdout
        vals = [int(l.split("=")[1]) for l in out.splitlines() if l.startswith("WorkingSetSize=") and l.split("=")[1].strip()]
        return sum(vals) // 1024 if vals else -1
    except Exception:
        return -1


def log_len():
    try:
        return os.path.getsize(LOG)
    except OSError:
        return 0


def new_panics(prev_size):
    try:
        with open(LOG, "rb") as f:
            f.seek(prev_size)
            return f.read().decode("utf-8", "replace")
    except OSError:
        return ""


def send(port, payload, read_ms=400, half=False):
    """Open conn, send payload, optionally half-close, read up to read_ms."""
    s = None
    try:
        s = socket.create_connection((HOST, port), timeout=2)
        if payload:
            s.sendall(payload)
        if half:
            s.shutdown(socket.SHUT_WR)
        s.settimeout(read_ms / 1000.0)
        got = b""
        try:
            got = s.recv(4096)
        except socket.timeout:
            got = b"<timeout>"
        except OSError as e:
            got = f"<err {e}>".encode()
        return got
    except OSError as e:
        return f"<connect/io {e}>".encode()
    finally:
        if s:
            s.close()


def port_open(port):
    try:
        s = socket.create_connection((HOST, port), timeout=1)
        s.close()
        return True
    except OSError:
        return False


# ---------------- payload builders ----------------

def socks_payloads():
    p = []
    p.append(b"\x05\x01\x00")                                  # greeting only
    p.append(b"\x05\x04\x00\x01\x02\xff")                      # bad nmethods
    p.append(b"\x05\x01\x00\x05\x01\x00\x01" + b"\x7f\x00\x00\x01" + b"\x00\x50")   # bad cmd 0x05
    p.append(b"\x05\x01\x00\x05\x01\x00\x03\xff")              # domain len 255 truncated
    p.append(b"\x05\x01\x00\x05\x01\x00\x03\x08" + b"a.com" + b"\x00\x50")
    p.append(b"\x05\x01\x00\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")  # UDP with 0 payload
    p.append(b"\x05\x01\x00\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x50")  # valid CONNECT
    p.append(b"\x04\x01\x00\x50\x7f\x00\x00\x01\x00")          # socks4
    p.append(b"\x05\x01\x00\x05\x01\x00\x00" + b"\x00" * 8)    # atyp 0
    return p


def http_payloads():
    return [
        b"CONNECT " + b"a" * 4000 + b":443 HTTP/1.1\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: " + b"b" * 4000 + b"\r\n\r\n",
        b"CONNECT a.com:notaport HTTP/1.1\r\n\r\n",
        b"CONNECT :443 HTTP/1.1\r\n\r\n",
        b"GET / HTTP/1.0\r\n\r\n",
        b"\r\n\r\n",
        b"PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n",
        b"GET " + b"/" * 3000 + b" HTTP/1.1\r\nHost: a\r\n\r\n",
        b"CONNECT a.com:99999999 HTTP/1.1\r\n\r\n",
    ]


def vless_payloads():
    def hdr(cmd=1, port=b"\x00\x50", atyp=1, addr=b"\x7f\x00\x00\x01", addon=b"", ver=0, uuid=UUID):
        return bytes([ver]) + uuid + bytes([len(addon)]) + addon + bytes([cmd]) + port + bytes([atyp]) + addr

    return [
        b"\x00",                                     # 1 byte only
        bytes([0]) + UUID + b"\x00" + b"\x01" + b"\x00\x50" + b"\x01" + b"\x7f\x00\x00\x01",  # valid-ish
        hdr(cmd=0xFF),                               # bad command
        hdr(cmd=3),                                  # MUX
        hdr(cmd=4),                                  # RVS
        hdr(atyp=0xFF),                              # bad atyp
        hdr(atyp=3, addr=b"\xff"),                   # domain len 255 truncated
        hdr(atyp=3, addr=b"\x05a.com"),              # valid domain
        hdr(port=b"\xff\xff"),
        bytes([1]) + UUID + b"\x00\x01\x00\x50\x01\x7f\x00\x00\x01",   # bad version
        bytes([0]) + b"\x00" * 16 + b"\x00\x01\x00\x50\x01\x7f\x00\x00\x01",  # unknown uuid
        b"\x00" + UUID + b"\xff" + b"\x00" * 255 + b"\x01\x00\x50\x01\x7f\x00\x00\x01",  # addon len 255
    ]


def vmess_payloads():
    return [
        b"\x00",
        b"\x01\x00\x00\x00",
        b"\x01" + b"\x00" * 20,
        b"\x01" + b"\xff" * 20,
        bytes(range(1, 33)),
        b"\x01" + b"\x00" * 16 + b"\xff\xff\xff\xff",   # declared body len huge
        b"\x01" + b"\x00" * 16 + b"\x00\x00\x00\x00",
        b"\x00" * 64,
        b"\xff" * 64,
    ]


def trojan_payloads():
    import hashlib
    key = hashlib.sha224(b"fuzzpass").hexdigest().encode()
    def h(cmd=0x01, atyp=1, rest=b"\x7f\x00\x00\x01\x00\x50"):
        return key + b"\r\n" + bytes([cmd]) + bytes([atyp]) + rest + b"\r\n" + b"PING"
    return [
        key + b"\r\n" + b"\x01" + b"\x01" + b"\x7f\x00\x00\x01\x00\x50\r\nPING",  # valid
        key + b"\r\n",                                   # truncated after CRLF
        key,                                             # no CRLF
        key + b"\r\n" + b"\x01" + b"\xff\x00\x50\r\n",   # bad atyp
        key + b"\r\n" + b"\x09\x01\x7f\x00\x00\x01\x00\x50\r\n",  # bad cmd 9
        key + b"\r\n" + b"\x03" + b"\x01\xff",           # UDP + domain len 255 truncated
        b"\x00" * 56 + b"\r\n",
        key + b"\r\n" + b"\x01" + b"\x01" + b"\x7f\x00\x00\x01\x00\x50",  # missing second CRLF
    ]


def ss_payloads():
    # legacy AEAD: 16B salt then AEAD chunks; wrong key material on purpose + structural probes
    return [
        b"\x00" * 16,
        b"\x00" * 32,
        b"\xff" * 16 + b"\xff\xff",
        b"\x00" * 16 + b"\x3f\xff" + b"\x00" * 4,      # declared 16383 payload len
        b"\x00" * 16 + b"\x7f\xff" + b"\x00" * 4,      # declared 32767 (over 0x3FFF cap)
        b"\x00" * 16 + b"\x00\x05" + b"\x00" * 21,     # short but plausible frame
        b"",
    ]


def ss2022_payloads():
    # 2022: 16B salt + encrypted fixed header (0x00 client) etc. All invalid on purpose.
    return [
        b"\x00" * 16,
        b"\x00" * 16 + b"\x00" * 11 + b"\x00" * 16,
        b"\xff" * 16 + b"\xff\xff\xff\xff" + b"\x00" * 32,
        b"\x00" * 16 + b"\xff\xff" + b"\x00" * 30,     # variable_len 65535
        b"\x00" * 40,
    ]


TARGETS = {
    "socks": socks_payloads,
    "http": http_payloads,
    "vless": vless_payloads,
    "vmess": vmess_payloads,
    "trojan": trojan_payloads,
    "ss": ss_payloads,
    "ss2022": ss2022_payloads,
}


def run_target(name, payloads, concurrency=24, repeats=1):
    port = PORTS[name]
    before_rss = rss_kb()
    before_log = log_len()
    results = []
    lock = threading.Lock()

    def worker(payload, idx):
        got = send(port, payload, read_ms=300, half=(idx % 2 == 0))
        with lock:
            results.append((payload, got))

    for _ in range(repeats):
        threads = []
        for i, pl in enumerate(payloads):
            # a few parallel copies of each payload, one half-closed variant
            for j in range(concurrency // max(1, len(payloads)) + 1):
                t = threading.Thread(target=worker, args=(pl, i * 7 + j))
                threads.append(t)
                t.start()
        for t in threads:
            t.join(timeout=6)
    time.sleep(0.6)
    after_rss = rss_kb()
    log = new_panics(before_log)
    panicked = "panicked" in log.lower()
    alive = port_open(port)
    return {
        "port": port,
        "alive": alive,
        "panicked": panicked,
        "rss_before": before_rss,
        "rss_after": after_rss,
        "log": log[-2000:] if panicked else "",
        "probes": len(results),
    }


def main():
    names = list(TARGETS) if ROUND == "all" else ROUND.split(",")
    print(f"# baseline RSS {rss_kb()} KB")
    for n in names:
        r = run_target(n, TARGETS[n]())
        print(
            f"{n:8s} port={r['port']} probes={r['probes']:4d} alive={r['alive']} "
            f"panic={r['panicked']} rss {r['rss_before']}->{r['rss_after']} KB"
        )
        if r["panicked"]:
            print("---- log tail ----")
            print(r["log"])
    print(f"# final RSS {rss_kb()} KB")


if __name__ == "__main__":
    main()
