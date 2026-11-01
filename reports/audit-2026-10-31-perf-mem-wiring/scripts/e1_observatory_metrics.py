"""E1: does `metrics` expose observatory status (Go /debug/vars "observatory" key)?

Configures a real observatory app (subjectSelector + 1s probeInterval) plus metrics,
sends one proxied request so the outbound is live, waits >2 probe intervals, then reads
GET /debug/vars and /metrics.

Go reference: app/metrics/metrics.go:157 `vars["observatory"] = marshalJSON(p.observatoryStatus())`
(Rust: expvars_json 'observatory' key / format_prometheus xray_observation_extra).
"""

import json
import os
import socket
import subprocess
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
XRAY = os.path.join(ROOT, "target", "release", "xray.exe")
TMP = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tmp"))
os.makedirs(TMP, exist_ok=True)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def http_get(port, path, timeout=4.0):
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
    return data.split(b"\r\n\r\n", 1)[-1].decode("utf-8", "replace")


def socks_connect(socks_port, host, port, timeout=5.0):
    s = socket.create_connection(("127.0.0.1", socks_port), timeout=timeout)
    s.sendall(b"\x05\x01\x00")
    s.recv(2)
    s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(host) + port.to_bytes(2, "big"))
    s.recv(10)
    return s


def main():
    socks_port, metrics_port = free_port(), free_port()
    # local target so one proxied connection succeeds (makes the outbound "used")
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    target_port = srv.getsockname()[1]

    cfg = {
        "log": {"loglevel": "warning"},
        "inbounds": [{"tag": "socks-in", "listen": "127.0.0.1", "port": socks_port,
                      "protocol": "socks", "settings": {"udp": False}}],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
        "policy": {"system": {"statsInboundUplink": True, "statsOutboundUplink": True}},
        "observatory": {
            "subjectSelector": ["direct"],
            "probeUrl": "https://www.gstatic.com/generate_204",
            "probeInterval": "1s",
        },
        "metrics": {"listen": f"127.0.0.1:{metrics_port}"},
    }
    path = os.path.join(TMP, "e1_observatory.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)

    proc = subprocess.Popen([XRAY, "run", "-c", path],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out = {"config": path}
    try:
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                socket.create_connection(("127.0.0.1", socks_port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.2)
        c = socks_connect(socks_port, "127.0.0.1", target_port)
        c.sendall(b"x")
        time.sleep(0.3)
        c.close()
        time.sleep(3.5)  # let >=3 probe rounds run
        vars_body = http_get(metrics_port, "/debug/vars")
        metrics_body = http_get(metrics_port, "/metrics")
        with open(os.path.join(TMP, "e1_observatory_debug_vars.json"), "w", encoding="utf-8") as f:
            f.write(vars_body)
        with open(os.path.join(TMP, "e1_observatory_metrics.txt"), "w", encoding="utf-8") as f:
            f.write(metrics_body)
        try:
            parsed = json.loads(vars_body)
        except Exception:
            parsed = {}
        out["debug_vars_observatory"] = parsed.get("observatory")
        out["stats"] = parsed.get("stats")
        out["metrics_has_observation_section"] = "xray_observation_extra" in metrics_body
        out["metrics_traffic_lines"] = [l for l in metrics_body.splitlines() if l.startswith("xray_traffic")]
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        srv.close()
    print(json.dumps(out, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
