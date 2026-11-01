#!/usr/bin/env python3
"""横向：凭据字段缺省/空串时的启动行为（Rust 5fe98b90 vs Go 26.10.17）。

只判「是否启动 + 是否监听」——启动即监听 = 该凭据面在运行期生效（E1 级证据）；
拒启 = fail-closed。数据面打通只对 ss/trojan 做（见 verify_empty_password_e1.py）。
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import time

RUST_XRAY = r"D:\Project\Xray-core-rust\target\release\xray.exe"
GO_XRAY = r"D:\tmp\go2617\xray.exe"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tmp")
OUT = os.path.abspath(OUT)
os.makedirs(OUT, exist_ok=True)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


# name -> (settings dict, 额外 inbound 字段)
def cases(port):
    return [
        ("vless: clients[0] 无 id",
         {"protocol": "vless", "port": port,
          "settings": {"decryption": "none", "clients": [{"email": "a"}]}}),
        ("vmess: clients[0] 无 id",
         {"protocol": "vmess", "port": port,
          "settings": {"clients": [{"email": "a"}]}}),
        ("ss legacy: users[0] 无 password",
         {"protocol": "shadowsocks", "port": port,
          "settings": {"method": "aes-128-gcm", "users": [{"method": "aes-128-gcm"}]}}),
        ("ss legacy: 单用户 password=\"\"",
         {"protocol": "shadowsocks", "port": port,
          "settings": {"method": "aes-128-gcm", "password": ""}}),
        ("ss2022: password=\"\"",
         {"protocol": "shadowsocks", "port": port,
          "settings": {"method": "2022-blake3-aes-128-gcm", "password": ""}}),
        ("trojan: clients[0] 无 password",
         {"protocol": "trojan", "port": port, "settings": {"clients": [{"email": "a"}]}}),
        ("socks: accounts[0] 空 user/pass + auth=password",
         {"protocol": "socks", "port": port,
          "settings": {"auth": "password", "accounts": [{"user": "", "pass": ""}]}}),
        ("http: accounts[0] 空 user/pass",
         {"protocol": "http", "port": port,
          "settings": {"accounts": [{"user": "", "pass": ""}]}}),
        ("hysteria: 无 auth 字段",
         {"protocol": "hysteria", "port": port, "settings": {"version": 2}}),
        ("wireguard: 无 secretKey",
         {"protocol": "wireguard", "port": port, "settings": {}}),
        ("anytls: 无 password 字段",
         {"protocol": "anytls", "port": port, "settings": {}}),
        ("tuic: password=\"\" (uuid 合法)",
         {"protocol": "tuic", "port": port,
          "settings": {"uuid": "00000000-0000-0000-0000-000000000001", "password": ""}}),
    ]


def run_one(exe, inbound, tag):
    port = inbound["port"]
    cfg = {"log": {"loglevel": "warning"},
           "inbounds": [dict(inbound, tag="probe")],
           "outbounds": [{"protocol": "freedom"}]}
    fd, path = tempfile.mkstemp(suffix=".json", prefix="cred_")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(cfg, f)
    logpath = os.path.join(OUT, f"cred_{tag}.log")
    fh = open(logpath, "wb")
    p = subprocess.Popen([exe, "run", "-c", path], stdout=fh, stderr=fh,
                         stdin=subprocess.DEVNULL)
    up = False
    deadline = time.time() + 10
    while time.time() < deadline:
        if p.poll() is not None:
            break
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=0.3)
            s.close()
            up = True
            break
        except OSError:
            time.sleep(0.12)
    alive = p.poll() is None
    try:
        p.terminate()
        p.wait(timeout=6)
    except Exception:
        p.kill()
    fh.close()
    try:
        os.unlink(path)
    except OSError:
        pass
    log = ""
    try:
        with open(logpath, encoding="utf-8", errors="replace") as f:
            log = f.read()
    except OSError:
        pass
    return alive, up, log


def why(log):
    keys = ("not specified", "not set", "invalid", "missing", "Failed to start",
            "failed to build", "unsupported", "cannot", "requires", "must")
    lines = [ln.strip() for ln in log.splitlines() if any(k in ln for k in keys)]
    if not lines:
        lines = [ln.strip() for ln in log.splitlines() if ln.strip()][-2:]
    return " | ".join(lines[-2:])[:300]


def main():
    only = sys.argv[1] if len(sys.argv) > 1 else None
    for name, tmpl in cases(free_port()):
        if only and only not in name:
            continue
        row = [name]
        for label, exe in (("rust", RUST_XRAY), ("go", GO_XRAY)):
            ib = json.loads(json.dumps(tmpl))
            ib["port"] = free_port()
            alive, up, log = run_one(exe, ib, f"{label}_{name.split(':')[0]}")
            verdict = ("STARTED+LISTEN" if (alive and up) else
                       "STARTED-NO-LISTEN" if alive else "REFUSED")
            row.append(f"{label}={verdict}" + ("" if alive and up else f" [{why(log)}]"))
        print(" | ".join(row), flush=True)


if __name__ == "__main__":
    main()
