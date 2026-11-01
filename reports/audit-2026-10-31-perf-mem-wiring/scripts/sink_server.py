"""TCP sink/echo server: replies with b'PONG' then closes. Used as the
direct-connection target for audit E2E probes.

Usage: python sink_server.py <port> [seconds]
Prints "LISTENING <port>" once bound; appends "ACCEPT <n>" per accepted conn.
"""
import socket
import sys
import threading
import time

port = int(sys.argv[1])
lifetime = float(sys.argv[2]) if len(sys.argv) > 2 else 25.0
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(16)
srv.settimeout(0.5)
print(f"LISTENING {port}", flush=True)

deadline = time.time() + lifetime
hits = 0
while time.time() < deadline:
    try:
        conn, peer = srv.accept()
    except socket.timeout:
        continue
    except OSError:
        break
    hits += 1
    print(f"ACCEPT {peer}", flush=True)
    try:
        conn.settimeout(2.0)
        conn.recv(4096)
        conn.sendall(b"PONG")
    except OSError:
        pass
    finally:
        conn.close()
print(f"DONE hits={hits}", flush=True)
