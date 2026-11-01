"""专探（决定性）：VLESS 入站 + LAN IP 目标 + ip 路由规则。

对比点：
  - Go 是否走 detour [out-black]（命中 ip 规则）
  - Rust 是否走 freedom（未命中 ip 规则）
  - payload 是否回显（回显 = 未被拦截）
目标用 192.168.89.180（本机 LAN IP），避开 freedom 对 loopback 的独立 block。
"""
import json
import os
import socket
import subprocess
import sys
import threading
import time
import uuid as _uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import GO, RUST, TMP, kill_proc  # noqa: E402

GO_PORT = 25048
RUST_PORT = 25088
ECHO_PORT = 25049
LAN_IP = "192.168.89.180"
UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
UB = _uuid.UUID(UUID).bytes

KEY = ("detour", "freedom", "accepted", "routing", "domain", "resolved",
       "blocked", "out-black", "out-free")


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


def vless_connect(port, atyp, host, target_port, payload=b"ping\n", timeout=5.0):
    out = {"stage": "?", "data": b"", "err": None}
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    except OSError as e:
        out["stage"] = "tcp_fail"
        out["err"] = str(e)
        return out
    try:
        s.settimeout(timeout)
        if atyp == 1:
            addr = socket.inet_aton(host)
        else:
            hb = host.encode()
            addr = bytes([len(hb)]) + hb
        # VLESS: version(1) uuid(16) addons_len(1)=0 command(1)=TCP
        #        port(2 BE) atyp(1) addr  → PortThenAddress
        hdr = (bytes([0]) + UB + bytes([0]) + bytes([1])
               + target_port.to_bytes(2, "big") + bytes([atyp]) + addr)
        s.sendall(hdr + payload)
        buf = b""
        end = time.time() + timeout
        while time.time() < end:
            try:
                b = s.recv(4096)
            except socket.timeout:
                break
            except OSError as e:
                out["err"] = str(e)
                break
            if not b:
                out["stage"] = "closed"
                break
            buf += b
            if len(buf) >= 3:
                break
        out["data"] = buf
        out["stage"] = "done"
        out["echoed"] = payload in buf[2:] if len(buf) > 2 else False
        return out
    finally:
        s.close()


def mkcfg(port):
    return {
        "log": {"loglevel": "debug"},
        "inbounds": [{"tag": "in-vless", "listen": "127.0.0.1", "port": port,
                      "protocol": "vless", "settings": {"clients": [{"id": UUID}],
                                                       "decryption": "none"}}],
        "outbounds": [
            {"tag": "out-free", "protocol": "freedom",
             "settings": {"finalRules": [{"action": "allow"}]}},
            {"tag": "out-black", "protocol": "blackhole", "settings": {}},
        ],
        "routing": {"domainStrategy": "AsIs", "rules": [
            {"type": "field", "ip": [LAN_IP], "outboundTag": "out-black"}]},
    }


VARIANTS = [
    ("vless_atyp1_ipv4_literal", 1, LAN_IP),
    ("vless_atyp2_domain_ip_literal", 2, LAN_IP),
]


def main():
    echo = EchoServer(ECHO_PORT, LAN_IP)
    try:
        for name, atyp, host in VARIANTS:
            row = {"case": name}
            for side, port in (("go", GO_PORT), ("rust", RUST_PORT)):
                srv = Server(side, mkcfg(port), port, "probe_vl_%s_%s" % (side, name))
                if not srv.ready:
                    row[side] = {"stage": "not_ready"}
                    srv.stop()
                    continue
                r = vless_connect(port, atyp, host, ECHO_PORT, timeout=4.0)
                time.sleep(0.4)
                keys = [l for l in srv.lines
                        if any(k in l.lower() for k in KEY) and "listening" not in l.lower()]
                row[side] = {"stage": r["stage"], "data": r["data"][:40].hex(),
                             "echoed": r.get("echoed"), "err": r["err"],
                             "log": "\n".join(keys[-4:])[:800]}
                srv.stop()
            row["same"] = row["go"].get("echoed") == row["rust"].get("echoed")
            print("%-34s GO(echo=%s) RUST(echo=%s) %s" % (
                name, row["go"].get("echoed"), row["rust"].get("echoed"),
                "SAME" if row["same"] else "**DIFF**"), flush=True)
            print("   GO  :", row["go"].get("log", "")[:600])
            print("   RUST:", row["rust"].get("log", "")[:600])
    finally:
        echo.stop()


if __name__ == "__main__":
    main()
