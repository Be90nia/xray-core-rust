"""专探（决定性）：用非 loopback 的本机 LAN IP 做目标，
避开 freedom 对 loopback 的 block，让「路由 ip 条件是否命中」直接可见。

同一份 SOCKS5 字节 → Go 与 Rust 各自入站 → 观察 payload 是否回显。
回显 = 未被 blackhole 拦截 = 路由 ip 条件未命中。
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

GO_PORT = 25051
RUST_PORT = 25052
ECHO_PORT = 25053
LAN_IP = "192.168.89.180"


class EchoServer:
    def __init__(self, port, bind_ip):
        self.s = socket.socket()
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind((bind_ip, port))
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


def socks5(proxy_port, atyp, host, port, payload=b"ping\n", timeout=5.0):
    out = {"stage": "?", "data": b"", "err": None}
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
            return out
        if atyp == 1:
            addr = socket.inet_aton(host)
        else:
            hb = host.encode()
            addr = bytes([len(hb)]) + hb
        s.sendall(bytes([5, 1, 0, atyp]) + addr + struct.pack(">H", port))
        rep = b""
        while len(rep) < 4:
            b = s.recv(4 - len(rep))
            if not b:
                break
            rep += b
        if len(rep) < 4:
            out["stage"] = "reply_truncated"
            return out
        a = rep[3]
        alen = {1: 4, 4: 16}.get(a, 0)
        if a == 3:
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
        out["echoed"] = payload in out["data"]
        return out
    finally:
        s.close()


def mkcfg(port):
    return {
        "log": {"loglevel": "debug"},
        "inbounds": [{"tag": "in-socks", "listen": "127.0.0.1", "port": port,
                      "protocol": "socks", "settings": {"auth": "noauth", "udp": False}}],
        "outbounds": [
            {"tag": "out-free", "protocol": "freedom",
             "settings": {"finalRules": [{"action": "allow"}]}},
            {"tag": "out-black", "protocol": "blackhole", "settings": {}},
        ],
        "routing": {"domainStrategy": "AsIs", "rules": [
            {"type": "field", "ip": [LAN_IP], "outboundTag": "out-black"}]},
    }


VARIANTS = [
    ("socks_atyp1_ipv4_literal", 1, LAN_IP),
    ("socks_atyp3_domain_ip_literal", 3, LAN_IP),
]


def main():
    echo = EchoServer(ECHO_PORT, LAN_IP)
    try:
        for name, atyp, host in VARIANTS:
            row = {"case": name}
            for side, port in (("go", GO_PORT), ("rust", RUST_PORT)):
                srv = Server(side, mkcfg(port), port, "probe_lan_%s_%s" % (side, name))
                if not srv.ready:
                    row[side] = {"stage": "not_ready"}
                    srv.stop()
                    continue
                r = socks5(port, atyp, host, ECHO_PORT)
                time.sleep(0.3)
                row[side] = {"stage": r["stage"], "code": r.get("code"),
                             "echoed": r.get("echoed"), "data": r["data"][:32].hex(),
                             "log": "\n".join(srv.lines[-5:])[:700]}
                srv.stop()
            row["same"] = row["go"].get("echoed") == row["rust"].get("echoed")
            print("%-36s GO(echo=%s) RUST(echo=%s) %s" % (
                name, row["go"].get("echoed"), row["rust"].get("echoed"),
                "SAME" if row["same"] else "**DIFF**"), flush=True)
            if not row["same"]:
                print("   GO  :", repr(row["go"].get("log", "")[:450]))
                print("   RUST:", repr(row["rust"].get("log", "")[:450]))
    finally:
        echo.stop()


if __name__ == "__main__":
    main()
