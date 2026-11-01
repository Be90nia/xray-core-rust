"""E1 harness: does policy.connIdle / policy.system.stats actually change runtime behaviour?

Runs target/release/xray.exe twice with a minimal socks-in -> freedom-out config:
  A: no policy block at all           (control)
  B: policy.levels["0"].connIdle = 2s + policy.system.stats* = true

Signals:
  1) after 6 s idle on a proxied TCP connection, is the connection still usable?
     (connIdle=2s should kill it if the policy reaches the data path)
  2) GET /debug/vars + /metrics: is `inbound>>>socks-in>>>traffic>>>uplink` present
     and non-zero (stats gated by policy.system)?

Usage: python e1_stats_policy.py
Outputs a compact JSON verdict on stdout; raw bodies kept under tmp/.
"""

import json
import os
import socket
import subprocess
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
XRAY = os.path.join(ROOT, "target", "release", "xray.exe")
TMP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tmp")
TMP = os.path.normpath(TMP)
os.makedirs(TMP, exist_ok=True)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def sink_server():
    """Accept, read a greeting, then stay silent forever (idle connection)."""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]
    held = []

    def run():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            held.append(c)

    threading.Thread(target=run, daemon=True).start()
    return srv, port, held


def socks5_connect(socks_port, host, port, timeout=5.0):
    s = socket.create_connection(("127.0.0.1", socks_port), timeout=timeout)
    s.sendall(b"\x05\x01\x00")
    if s.recv(2) != b"\x05\x00":
        raise RuntimeError("socks greeting failed")
    req = b"\x05\x01\x00\x01" + socket.inet_aton(host) + port.to_bytes(2, "big")
    s.sendall(req)
    rep = s.recv(10)
    if len(rep) < 2 or rep[1] != 0:
        raise RuntimeError(f"socks connect failed: {rep!r}")
    return s


def http_get(port, path, timeout=3.0):
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    s.sendall(f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n".encode())
    data = b""
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    s.close()
    if b"\r\n\r\n" not in data:
        return ""
    head, body = data.split(b"\r\n\r\n", 1)
    if b"chunked" in head.lower():
        out = b""
        rest = body
        while True:
            i = rest.find(b"\r\n")
            if i < 0:
                break
            n = int(rest[:i] or b"0", 16)
            if n == 0:
                break
            out += rest[i + 2:i + 2 + n]
            rest = rest[i + 2 + n + 2:]
        body = out
    return body.decode("utf-8", "replace")


def run_case(name, policy, idle_seconds):
    socks_port, metrics_port = free_port(), free_port()
    srv, sink_port, held = sink_server()
    cfg = {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {"tag": "socks-in", "listen": "127.0.0.1", "port": socks_port,
             "protocol": "socks", "settings": {"udp": False}}
        ],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
        "metrics": {"listen": f"127.0.0.1:{metrics_port}"},
    }
    if policy is not None:
        cfg["policy"] = policy
    path = os.path.join(TMP, f"e1_{name}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)

    proc = subprocess.Popen([XRAY, "run", "-c", path],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    res = {"case": name, "config": path}
    try:
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                socket.create_connection(("127.0.0.1", socks_port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.2)
        conn = socks5_connect(socks_port, "127.0.0.1", sink_port)
        conn.sendall(b"hello")
        time.sleep(0.3)
        res["sink_received"] = len(held) == 1
        # keep the proxied connection idle, then probe whether it is still usable
        time.sleep(idle_seconds)
        alive = None
        try:
            conn.sendall(b"ping")
            conn.settimeout(2.0)
            # sink never replies; only an error means the tunnel was torn down
            conn.recv(16)
            alive = True
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            alive = False
        except socket.timeout:
            alive = True
        except OSError as e:
            alive = False if getattr(e, "errno", None) else True
        res["conn_alive_after_idle"] = alive
        conn.close()

        vars_body = http_get(metrics_port, "/debug/vars")
        metrics_body = http_get(metrics_port, "/metrics")
        with open(os.path.join(TMP, f"e1_{name}_debug_vars.json"), "w", encoding="utf-8") as f:
            f.write(vars_body)
        with open(os.path.join(TMP, f"e1_{name}_metrics.txt"), "w", encoding="utf-8") as f:
            f.write(metrics_body)
        stats = {}
        try:
            stats = json.loads(vars_body).get("stats", {})
        except Exception:
            pass
        res["stats_keys"] = sorted(stats.keys())
        res["debug_vars_len"] = len(vars_body)
        res["metrics_has_inbound_uplink"] = "inbound" in metrics_body and "uplink" in metrics_body
        res["metrics_head"] = metrics_body.splitlines()[:6]
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        srv.close()
    return res


def main():
    out = []
    out.append(run_case("A_no_policy", None, 6))
    out.append(run_case(
        "B_policy_connidle2_stats_on",
        {"levels": {"0": {"connIdle": 2, "handshake": 4, "uplinkOnly": 1, "downlinkOnly": 1}},
         "system": {"statsInboundUplink": True, "statsInboundDownlink": True,
                    "statsOutboundUplink": True, "statsOutboundDownlink": True}},
        6,
    ))
    print(json.dumps(out, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    sys.exit(main())
