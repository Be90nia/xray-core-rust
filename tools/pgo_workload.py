#!/usr/bin/env python3
"""PGO profile-collection workload (bd 4m1u).

Runs an xray socks->freedom loopback pump for --duration seconds so the
instrumented build (cargo pgo build) gathers representative profile data over
the dispatcher/bridge hot path. Exits non-zero if the proxy never comes up or
all pumps error.

Usage: python3 tools/pgo_workload.py --xray <path> [--duration 30] [--conns 4]
"""
import argparse, json, os, socket, struct, subprocess, sys, tempfile, threading, time

PAYLOAD = os.urandom(65536)
STOP = threading.Event()


def echo_server(ready, port_holder):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    port_holder.append(srv.getsockname()[1])
    srv.listen(64)
    ready.set()
    srv.settimeout(1.0)
    while not STOP.is_set():
        try:
            c, _ = srv.accept()
        except (socket.timeout, OSError):
            continue
        def serve(c=c):
            try:
                while not STOP.is_set():
                    d = c.recv(262144)
                    if not d:
                        break
                    c.sendall(d)
            except OSError:
                pass
            finally:
                c.close()

        threading.Thread(target=serve, daemon=True).start()
    srv.close()


def socks5_connect(proxy_port, dst_port):
    s = socket.create_connection(("127.0.0.1", proxy_port), timeout=10)
    s.sendall(b"\x05\x01\x00")
    if s.recv(2) != b"\x05\x00":
        raise RuntimeError("socks5 greeting failed")
    s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack(">H", dst_port))
    resp = b""
    while len(resp) < 10:
        resp += s.recv(10 - len(resp))
    if resp[1] != 0:
        raise RuntimeError(f"socks5 connect failed: {resp!r}")
    return s


def pump(proxy_port, echo_port, errors):
    try:
        s = socks5_connect(proxy_port, echo_port)
        s.settimeout(30)

        def rx():
            while not STOP.is_set():
                try:
                    # socket timeout 为收发两线程共享：rx 醒着时压回 1s，以便
                    # 及时响应 STOP；sendall 侧由 settimeout(30) 兜底
                    s.settimeout(1.0)
                    if not s.recv(262144):
                        return
                except socket.timeout:
                    continue
                except OSError:
                    return

        t = threading.Thread(target=rx)
        t.start()
        while not STOP.is_set():
            s.sendall(PAYLOAD)
        s.close()
        t.join(10)
    except Exception as e:
        if not STOP.is_set():
            errors.append(e)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--xray", required=True)
    ap.add_argument("--duration", type=int, default=30)
    ap.add_argument("--conns", type=int, default=4)
    args = ap.parse_args()

    with tempfile.TemporaryDirectory() as td:
        ready, port_holder = threading.Event(), []
        eth = threading.Thread(target=echo_server, args=(ready, port_holder), daemon=True)
        eth.start()
        ready.wait(5)
        echo_port = port_holder[0]

        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        sport = s.getsockname()[1]
        s.close()

        cfg = {
            "log": {"loglevel": "warning"},
            "inbounds": [{"listen": "127.0.0.1", "port": sport, "protocol": "socks",
                          "settings": {"auth": "noauth", "udp": False}}],
            "outbounds": [{"protocol": "freedom", "settings": {}}],
        }
        cfg_path = os.path.join(td, "pgo.json")
        with open(cfg_path, "w") as f:
            json.dump(cfg, f)

        xray = subprocess.Popen([args.xray, "run", "-c", cfg_path],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.5)
        if xray.poll() is not None:
            print(f"pgo_workload: xray exited rc={xray.returncode}", file=sys.stderr)
            return 2

        errors = []
        threads = [threading.Thread(target=pump, args=(sport, echo_port, errors))
                   for _ in range(args.conns)]
        for t in threads:
            t.start()
        time.sleep(args.duration)
        STOP.set()
        for t in threads:
            t.join(35)
        eth.join(5)
        xray.terminate()
        try:
            xray.wait(10)
        except subprocess.TimeoutExpired:
            xray.kill()
        if len(errors) == args.conns:
            print(f"pgo_workload: all {len(errors)} pumps failed: {errors[0]}", file=sys.stderr)
            return 3
        print(f"pgo_workload: OK ({args.duration}s, {args.conns} conns, {len(errors)} conn errors)")
        return 0


if __name__ == "__main__":
    sys.exit(main())
