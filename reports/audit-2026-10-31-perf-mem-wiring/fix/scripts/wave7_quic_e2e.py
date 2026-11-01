"""QUIC 传输 Rust↔Rust 内核级互通探针（0270p）。

用法：python wave7_quic_e2e.py --rust <xray.exe>

两端都 Rust：vless inbound/outbound，streamSettings.network = "quic"（security=tls，
自签证书 + allowInsecure）。判据：64KiB 确定性载荷 socks 链路字节级往返。

本脚本同时采集**装配行为证据**：
- 服务端启动后对 inbound 端口做 TCP connect 探测——若成功，说明入站 quic 走了裸 TCP
  分支（is_transport_listener_protocol 白名单缺 "quic"，audit 报告 §1.1）；
- 客户端 socks 连接的异常类型与两端日志尾部。
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import socket
import subprocess
import time

WORK = os.path.join("D:/tmp", "wave7_quic")
CERT = os.path.join(WORK, "cert.pem")
KEY = os.path.join(WORK, "key.pem")
UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
PAYLOAD = bytes(range(256)) * 256  # 65536 B
OPENSSL_CNF = """[req]
distinguished_name = dn
x509_extensions = v3_req
prompt = no
[dn]
CN = localhost
[v3_req]
subjectAltName = DNS:localhost,IP:127.0.0.1
"""


PIN = ""


def gen_cert():
    os.makedirs(WORK, exist_ok=True)
    cnf = CERT + ".cnf"
    with open(cnf, "w") as f:
        f.write(OPENSSL_CNF)
    r = subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", KEY, "-out", CERT, "-days", "2", "-config", cnf],
        capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError("openssl 证书生成失败: " + r.stderr.strip()[:300])
    with open(CERT) as f:
        der = base64.b64decode("".join(l for l in f.read().splitlines() if "-----" not in l))
    global PIN
    PIN = hashlib.sha256(der).hexdigest()
    return PIN


def kill_mine(names):
    for name in names:
        subprocess.run(["cmd", "/c", "taskkill /F /IM " + name],
                       capture_output=True, timeout=10)


def socks_connect(port, dest_port, timeout=8):
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    s.settimeout(timeout)
    s.sendall(b"\x05\x01\x00")
    assert s.recv(2) == b"\x05\x00", "socks greeting failed"
    req = b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + dest_port.to_bytes(2, "big")
    s.sendall(req)
    rep = s.recv(10)
    assert len(rep) >= 2 and rep[1] == 0, f"socks connect failed {rep!r}"
    return s


class Echo:
    def __init__(self):
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(8)
        self.port = self.srv.getsockname()[1]
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        self.srv.settimeout(0.5)
        while not getattr(self, "stop", False):
            try:
                conn, _ = self.srv.accept()
            except socket.timeout:
                continue  # 空闲继续等（原实现 break → 0.5s 后无人 accept，echo 恒超时）
            except OSError:
                break
            threading.Thread(target=self._echo, args=(conn,), daemon=True).start()

    @staticmethod
    def _echo(conn):
        try:
            conn.settimeout(20)
            while True:
                data = conn.recv(65536)
                if not data:
                    break
                conn.sendall(data)
        except OSError:
            pass
        finally:
            conn.close()


import threading  # noqa: E402  (Echo 之上使用，置于文件级 import 后)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rust", required=True)
    a = ap.parse_args()
    os.makedirs(WORK, exist_ok=True)
    gen_cert()
    echo = Echo()

    p, s = 18700, 18701
    si = {"port": p, "listen": "127.0.0.1", "protocol": "vless",
          "settings": {"clients": [{"id": UUID}], "decryption": "none"},
          "streamSettings": {"network": "quic", "security": "tls",
                             "tlsSettings": {"certificates": [
                                 {"certificateFile": CERT, "keyFile": KEY}]},
                             "quicSettings": {}}}
    co = {"protocol": "vless", "settings": {"vnext": [
        {"address": "127.0.0.1", "port": p,
         "users": [{"id": UUID, "encryption": "none"}]}]},
        "streamSettings": {"network": "quic", "security": "tls",
                           "tlsSettings": {"serverName": "localhost",
                                           "pinnedPeerCertSha256": PIN},
                           "quicSettings": {}}}
    scfg = {"log": {"loglevel": "info"}, "inbounds": [si],
            "outbounds": [{"protocol": "freedom",
                           "settings": {"finalRules": [{"action": "allow"}]}}]}
    ccfg = {"log": {"loglevel": "info"},
            "inbounds": [{"listen": "127.0.0.1", "port": s, "protocol": "socks",
                          "settings": {"udp": False}}],
            "outbounds": [co]}
    scp, ccp = os.path.join(WORK, "s0.json"), os.path.join(WORK, "c0.json")
    with open(scp, "w") as f:
        json.dump(scfg, f)
    with open(ccp, "w") as f:
        json.dump(ccfg, f)

    server_bin = os.path.join(WORK, "xray-quic-srv.exe")
    client_bin = os.path.join(WORK, "xray-quic-cli.exe")
    import shutil
    shutil.copyfile(a.rust, server_bin)
    shutil.copyfile(a.rust, client_bin)
    kill_mine([os.path.basename(server_bin), os.path.basename(client_bin)])
    time.sleep(0.3)

    ps = subprocess.Popen([server_bin, "run", "-c", scp],
                          stdout=open(os.path.join(WORK, "s0.log"), "wb"),
                          stderr=subprocess.STDOUT)
    time.sleep(2.5)

    # 装配行为证据：inbound 端口上是 TCP 还是 UDP？
    tcp_probe = None
    try:
        c = socket.create_connection(("127.0.0.1", p), timeout=2)
        tcp_probe = "TCP connect 成功（入站绑了 TCP —— 走了裸 TCP 分支）"
        c.close()
    except OSError as e:
        tcp_probe = f"TCP connect 失败（{e!r}）——入站未绑 TCP"

    pc = subprocess.Popen([client_bin, "run", "-c", ccp],
                          stdout=open(os.path.join(WORK, "c0.log"), "wb"),
                          stderr=subprocess.STDOUT)
    time.sleep(2.5)

    err = ""
    up = down = 0
    try:
        sock = socks_connect(s, echo.port)
        sock.sendall(PAYLOAD)
        buf = b""
        while len(buf) < len(PAYLOAD):
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf += chunk
        up, down = len(PAYLOAD), len(buf)
        err = "bytes-identical" if buf == PAYLOAD else "BYTES-MISMATCH"
        sock.close()
    except Exception as e:  # noqa: BLE001
        err = repr(e)[:120]

    ps.terminate()
    pc.terminate()
    kill_mine([os.path.basename(server_bin), os.path.basename(client_bin)])
    time.sleep(0.3)

    ok = down == len(PAYLOAD) and buf == PAYLOAD
    print(f"tcp_probe: {tcp_probe}")
    print(f"[{'PASS' if ok else 'FAIL'}] quic Rust->Rust UP:{up} DOWN:{down} {err}")

    for tag in ("s0.log", "c0.log"):
        f = os.path.join(WORK, tag)
        if os.path.exists(f):
            with open(f, "rb") as fh:
                tail = fh.read().decode("utf-8", errors="replace").splitlines()[-6:]
            print(f"--- {tag} tail ---")
            for line in tail:
                print("   ", line[:160])
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
