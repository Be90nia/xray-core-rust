"""专探：Rust 生产路的路由规则到底生效没有。

同一份 client 字节（socks5 CONNECT 127.0.0.1:ECHO），两侧服务端只差端口。
每条规则变体各跑一次 Go 与 Rust，看「谁被选中」+ 数据是否被丢弃。
"""
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import GO, RUST, TMP, kill_proc  # noqa: E402

GO_PORT = 25033
RUST_PORT = 25073
ECHO_PORT = 25031


class EchoServer:
    def __init__(self, port):
        self.s = socket.socket()
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind(("127.0.0.1", port))
        self.s.listen(64)
        self.stop_flag = False
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        self.s.settimeout(0.5)
        while not self.stop_flag:
            try:
                c, _ = self.s.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()

    def _serve(self, c):
        try:
            c.settimeout(8)
            while True:
                b = c.recv(65536)
                if not b:
                    break
                c.sendall(b)
        except OSError:
            pass
        finally:
            c.close()

    def stop(self):
        self.stop_flag = True
        try:
            self.s.close()
        except OSError:
            pass


class Server:
    def __init__(self, side, cfg, port, name):
        self.side = side
        self.port = port
        self.path = os.path.join(TMP, name + ".json")
        open(self.path, "w", encoding="utf-8").write(json.dumps(cfg, indent=2))
        exe = GO if side == "go" else RUST
        self.p = subprocess.Popen([exe, "run", "-c", self.path], stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, cwd=os.path.dirname(self.path))
        self.lines = []
        threading.Thread(target=self._reader, daemon=True).start()
        self.ready = self._wait_ready()

    def _reader(self):
        for raw in self.p.stdout:
            self.lines.append(raw.decode("utf-8", "replace").rstrip())

    def _wait_ready(self, timeout=10.0):
        end = time.time() + timeout
        while time.time() < end:
            if self.p.poll() is not None:
                return False
            s = socket.socket()
            s.settimeout(0.4)
            try:
                s.connect(("127.0.0.1", self.port))
                return True
            except OSError:
                time.sleep(0.15)
            finally:
                s.close()
        return False

    def stop(self):
        kill_proc(self.p)


def socks5(proxy_port, host, port, payload=b"ping\n", timeout=5.0):
    out = {"stage": "?", "code": None, "data": b"", "err": None}
    try:
        s = socket.create_connection(("127.0.0.1", proxy_port), timeout=timeout)
    except OSError as e:
        out["stage"] = "tcp_fail"
        out["err"] = str(e)
        return out
    try:
        s.settimeout(timeout)
        s.sendall(bytes([5, 1, 0]))
        r = s.recv(2)
        if len(r) < 2 or r[1] != 0:
            out["stage"] = "auth_fail"
            out["code"] = r[1] if len(r) > 1 else None
            return out
        hb = host.encode() if isinstance(host, str) else host
        req = bytes([5, 1, 0, 3, len(hb)]) + hb + struct.pack(">H", port)
        s.sendall(req)
        rep = b""
        while len(rep) < 4:
            b = s.recv(4 - len(rep))
            if not b:
                break
            rep += b
        if len(rep) < 4:
            out["stage"] = "reply_truncated"
            return out
        atyp = rep[3]
        alen = {1: 4, 4: 16}.get(atyp, 0)
        if atyp == 3:
            x = s.recv(1)
            alen = x[0] if x else 0
        need = 4 + alen + 2
        while len(rep) < need:
            b = s.recv(need - len(rep))
            if not b:
                break
            rep += b
        out["code"] = rep[1]
        if rep[1] != 0:
            out["stage"] = "connect_refused"
            return out
        out["stage"] = "connected"
        try:
            s.sendall(payload)
            out["data"] = s.recv(4096)
        except OSError as e:
            out["err"] = str(e)
        return out
    finally:
        s.close()


def cfg(port, rules):
    return {
        "log": {"loglevel": "debug"},
        "inbounds": [{"tag": "in-socks", "listen": "127.0.0.1", "port": port,
                      "protocol": "socks", "settings": {"auth": "noauth", "udp": False}}],
        "outbounds": [
            {"tag": "out-free", "protocol": "freedom", "settings": {}},
            {"tag": "out-black", "protocol": "blackhole", "settings": {}},
        ],
        "routing": {"domainStrategy": "AsIs", "rules": rules},
    }


VARIANTS = [
    ("rule_ip_match_blackhole", [{"type": "field", "ip": ["127.0.0.1"], "outboundTag": "out-black"}]),
    ("rule_port_match_blackhole", [{"type": "field", "port": str(ECHO_PORT), "outboundTag": "out-black"}]),
    ("rule_network_tcp_blackhole", [{"type": "field", "network": "tcp", "outboundTag": "out-black"}]),
    ("rule_protocol_blackhole", [{"type": "field", "protocol": ["socks"], "outboundTag": "out-black"}]),
    ("rule_inboundtag_blackhole", [{"type": "field", "inboundTag": ["in-socks"], "outboundTag": "out-black"}]),
    ("rule_domain_match_blackhole", [{"type": "field", "domain": ["example.com"], "outboundTag": "out-black"}]),
    ("rule_all_blackhole", [{"type": "field", "network": "tcp", "outboundTag": "out-black"}]),
]


def main():
    echo = EchoServer(ECHO_PORT)
    try:
        for name, rules in VARIANTS:
            row = {"case": name}
            for side, port in (("go", GO_PORT), ("rust", RUST_PORT)):
                srv = Server(side, cfg(port, rules), port, "probe_rt_%s_%s" % (side, name))
                if not srv.ready:
                    row[side] = {"stage": "server_not_ready", "alive": srv.p.poll()}
                    srv.stop()
                    continue
                r = socks5(port, "127.0.0.1", ECHO_PORT)
                time.sleep(0.3)
                row[side] = {"stage": r["stage"], "code": r["code"],
                             "data": r["data"][:32].hex(), "err": r["err"],
                             "alive": srv.p.poll() is None,
                             "log": "\n".join(srv.lines[-6:])[:900]}
                srv.stop()
            row["same"] = (row["go"].get("stage") == row["rust"].get("stage")
                           and row["go"].get("data") == row["rust"].get("data"))
            print("%-32s GO(%s data=%s) RUST(%s data=%s) %s" % (
                name, row["go"].get("stage"), row["go"].get("data"),
                row["rust"].get("stage"), row["rust"].get("data"),
                "SAME" if row["same"] else "**DIFF**"), flush=True)
            if not row["same"]:
                print("   GO  log:", repr(row["go"].get("log", "")[:500]))
                print("   RUST log:", repr(row["rust"].get("log", "")[:500]))
    finally:
        echo.stop()


if __name__ == "__main__":
    main()
