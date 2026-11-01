"""专探：路由规则引用不存在的 outboundTag 时两侧行为。

用 inboundTag（两侧都生效的条件）隔离出「tag 查找失败」这一维。
另测：省略 domainStrategy 时的默认行为。
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

GO_PORT = 25037
RUST_PORT = 25077
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
            return out
        hb = host.encode()
        s.sendall(bytes([5, 1, 0, 3, len(hb)]) + hb + struct.pack(">H", port))
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
        return out
    finally:
        s.close()


def mkcfg(port, rules, strategy="AsIs", omit_strategy=False):
    routing = {"rules": rules}
    if not omit_strategy:
        routing["domainStrategy"] = strategy
    return {
        "log": {"loglevel": "debug"},
        "inbounds": [{"tag": "in-socks", "listen": "127.0.0.1", "port": port,
                      "protocol": "socks", "settings": {"auth": "noauth", "udp": False}}],
        "outbounds": [
            {"tag": "out-free", "protocol": "freedom", "settings": {}},
            {"tag": "out-black", "protocol": "blackhole", "settings": {}},
        ],
        "routing": routing,
    }


VARIANTS = [
    ("inboundTag_to_nonexistent_tag",
     lambda p: mkcfg(p, [{"type": "field", "inboundTag": ["in-socks"], "outboundTag": "out-nope"}]),
     "127.0.0.1"),
    ("inboundTag_to_existing_black",
     lambda p: mkcfg(p, [{"type": "field", "inboundTag": ["in-socks"], "outboundTag": "out-black"}]),
     "127.0.0.1"),
    ("ip_rule_default_strategy_omitted",
     lambda p: mkcfg(p, [{"type": "field", "ip": ["127.0.0.1"], "outboundTag": "out-black"}],
                     omit_strategy=True),
     "127.0.0.1"),
    ("ip_rule_default_strategy_as_is",
     lambda p: mkcfg(p, [{"type": "field", "ip": ["127.0.0.1"], "outboundTag": "out-black"}]),
     "127.0.0.1"),
]


def main():
    echo = EchoServer(ECHO_PORT)
    try:
        for name, mk, host in VARIANTS:
            row = {"case": name}
            for side, port in (("go", GO_PORT), ("rust", RUST_PORT)):
                srv = Server(side, mk(port), port, "probe_tag_%s_%s" % (side, name))
                if not srv.ready:
                    row[side] = {"stage": "not_ready", "log": "\n".join(srv.lines[-4:])[:500]}
                    srv.stop()
                    continue
                r = socks5(port, host, ECHO_PORT)
                time.sleep(0.25)
                row[side] = {"stage": r["stage"], "code": r["code"],
                             "data": r["data"][:32].hex(), "err": r["err"],
                             "log": "\n".join(srv.lines[-5:])[:700]}
                srv.stop()
            row["same"] = (row["go"].get("stage") == row["rust"].get("stage")
                           and row["go"].get("data") == row["rust"].get("data"))
            print("%-38s GO(%s data=%-12s) RUST(%s data=%-12s) %s" % (
                name, row["go"].get("stage"), row["go"].get("data"),
                row["rust"].get("stage"), row["rust"].get("data"),
                "SAME" if row["same"] else "**DIFF**"), flush=True)
            if not row["same"]:
                print("   GO  :", repr(row["go"].get("log", "")[:400]))
                print("   RUST:", repr(row["rust"].get("log", "")[:400]))
    finally:
        echo.stop()


if __name__ == "__main__":
    main()
