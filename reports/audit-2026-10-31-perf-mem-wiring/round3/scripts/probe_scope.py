"""专探：Rust 路由 ip 条件失效的影响面。

变体：
1. domainStrategy = IPIfNonMatch / IPOnDemand（能否靠解析救回）
2. HTTP inbound 的 Host 头填 IP 字面量（同一根因是否跨入站）
3. srcPort / user 等其他条件是否受影响
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

GO_PORT = 25036
RUST_PORT = 25076
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


def http_get(proxy_port, host_header, timeout=5.0):
    """HTTP 入站：CONNECT 语义（http proxy 用 CONNECT 到 host:port）。"""
    out = {"stage": "?", "data": b"", "err": None}
    try:
        s = socket.create_connection(("127.0.0.1", proxy_port), timeout=timeout)
    except OSError as e:
        out["stage"] = "tcp_fail"
        out["err"] = str(e)
        return out
    try:
        s.settimeout(timeout)
        s.sendall(("CONNECT %s:%d HTTP/1.1\r\nHost: %s\r\n\r\n"
                   % (host_header, ECHO_PORT, host_header)).encode())
        buf = b""
        end = time.time() + timeout
        while time.time() < end and b"\r\n\r\n" not in buf:
            b = s.recv(4096)
            if not b:
                break
            buf += b
        out["stage"] = "resp"
        out["data"] = buf[:64].hex()
        out["text"] = buf[:64].decode("utf-8", "replace")
        return out
    finally:
        s.close()


def cfg_socks(port, strategy):
    return {
        "log": {"loglevel": "debug"},
        "inbounds": [{"tag": "in-socks", "listen": "127.0.0.1", "port": port,
                      "protocol": "socks", "settings": {"auth": "noauth", "udp": False}}],
        "outbounds": [
            {"tag": "out-free", "protocol": "freedom", "settings": {}},
            {"tag": "out-black", "protocol": "blackhole", "settings": {}},
        ],
        "routing": {"domainStrategy": strategy, "rules": [
            {"type": "field", "ip": ["127.0.0.1"], "outboundTag": "out-black"}]},
    }


def cfg_http(port):
    return {
        "log": {"loglevel": "debug"},
        "inbounds": [{"tag": "in-http", "listen": "127.0.0.1", "port": port,
                      "protocol": "http", "settings": {}}],
        "outbounds": [
            {"tag": "out-free", "protocol": "freedom", "settings": {}},
            {"tag": "out-black", "protocol": "blackhole", "settings": {}},
        ],
        "routing": {"domainStrategy": "AsIs", "rules": [
            {"type": "field", "ip": ["127.0.0.1"], "outboundTag": "out-black"}]},
    }


def run_pair(name, mkcfg, action):
    row = {"case": name}
    for side, port in (("go", GO_PORT), ("rust", RUST_PORT)):
        srv = Server(side, mkcfg(port), port, "probe_scope_%s_%s" % (side, name))
        if not srv.ready:
            row[side] = {"stage": "not_ready"}
            srv.stop()
            continue
        r = action(port)
        time.sleep(0.25)
        row[side] = {"stage": r.get("stage"), "data": r.get("data", "")[:64].hex()
                     if isinstance(r.get("data"), bytes) else r.get("data"),
                     "text": r.get("text", ""), "err": r.get("err"),
                     "log": "\n".join(srv.lines[-4:])[:600]}
        srv.stop()
    row["same"] = (row["go"].get("stage") == row["rust"].get("stage")
                   and row["go"].get("data") == row["rust"].get("data"))
    print("%-34s GO(%s %s) RUST(%s %s) %s" % (
        name, row["go"].get("stage"), row["go"].get("data"),
        row["rust"].get("stage"), row["rust"].get("data"),
        "SAME" if row["same"] else "**DIFF**"), flush=True)
    if not row["same"]:
        print("   GO  :", repr(row["go"].get("log", "")[:350]))
        print("   RUST:", repr(row["rust"].get("log", "")[:350]))
    return row


def main():
    echo = EchoServer(ECHO_PORT)
    try:
        run_pair("socks_ds_AsIs", lambda p: cfg_socks(p, "AsIs"),
                 lambda p: socks5(p, "127.0.0.1", ECHO_PORT))
        run_pair("socks_ds_IPIfNonMatch", lambda p: cfg_socks(p, "IPIfNonMatch"),
                 lambda p: socks5(p, "127.0.0.1", ECHO_PORT))
        run_pair("socks_ds_IPOnDemand", lambda p: cfg_socks(p, "IPOnDemand"),
                 lambda p: socks5(p, "127.0.0.1", ECHO_PORT))
        run_pair("http_inbound_host_ip_literal", cfg_http,
                 lambda p: http_get(p, "127.0.0.1"))
    finally:
        echo.stop()


if __name__ == "__main__":
    main()
