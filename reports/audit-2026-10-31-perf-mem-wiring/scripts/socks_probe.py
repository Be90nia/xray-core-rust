"""Minimal SOCKS5 (no-auth) CONNECT probe.

Usage: python socks_probe.py <proxy_host> <proxy_port> <target_host> <target_port> [timeout]
Prints "SOCKS_OK <reply>" and then "REPLY <bytes>" / fails with "SOCKS_FAIL <reason>".
Exit code 0 on success, 1 on failure.
"""
import socket
import struct
import sys

proxy_host = sys.argv[1]
proxy_port = int(sys.argv[2])
target_host = sys.argv[3]
target_port = int(sys.argv[4])
timeout = float(sys.argv[5]) if len(sys.argv) > 5 else 4.0


def fail(msg):
    print(f"SOCKS_FAIL {msg}", flush=True)
    raise SystemExit(1)


try:
    s = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
except OSError as e:
    fail(f"connect proxy: {e}")

s.settimeout(timeout)
try:
    s.sendall(b"\x05\x01\x00")
    reply = s.recv(2)
    if len(reply) != 2 or reply[0] != 5:
        fail(f"greeting reply {reply!r}")
    # CONNECT, domain or IP target
    try:
        ip = socket.inet_aton(target_host)
        atyp, addr = 1, ip
    except OSError:
        atyp, addr = 3, bytes([len(target_host)]) + target_host.encode()
    s.sendall(b"\x05\x01\x00" + bytes([atyp]) + addr + struct.pack(">H", target_port))
    head = s.recv(4)
    if len(head) < 4:
        fail(f"short connect reply {head!r}")
    rc = head[1]
    atyp = head[3]
    # consume BND.ADDR + BND.PORT so later reads only see payload
    need = {1: 4 + 2, 4: 16 + 2}.get(atyp)
    if need is None:  # domain
        ln = s.recv(1)[0]
        need = ln + 2
    got = b""
    while len(got) < need:
        chunk = s.recv(need - len(got))
        if not chunk:
            break
        got += chunk
    if rc != 0:
        fail(f"connect reply code {rc} (0x{rc:02x})")
    print(f"SOCKS_OK reply={rc}", flush=True)
    s.sendall(b"PING")
    data = s.recv(16)
    print(f"REPLY {data!r}", flush=True)
except OSError as e:
    fail(f"io: {e}")
finally:
    s.close()
