#!/usr/bin/env python
"""bd hl8q6：用户热更（AddUser/RemoveUser）端到端验证——新用户立刻能连，移除后立刻被拒。

拓扑（每个协议一轮）：
    客户端实例 B：socks inbound + <proto> outbound（用**新用户**凭据）
        → 服务端实例 A：<proto> inbound（api 可控）+ freedom
        → 目标 sink（回 b"PONG"）

流程：
  1. 起服务端 A（seed 用户 1 个）+ sink；
  2. `api adu` 加入新用户（Rust CLI 或 Go CLI）→ 用户数 1→2；
  3. 起客户端 B（用新用户凭据）→ 探针 CONNECT 到 sink ⇒ 必须 ok:PONG
     （= 新用户**立刻**可用，不是「下次重载才生效」）；
  4. `api rmu` 移除新用户 → 用户数 2→1；
  5. 同一客户端 B 再探 ⇒ 必须失败（= 移除对新连接立即生效）。

用法：
  python reports/audit-2026-10-31-perf-mem-wiring/fix/scripts/wave7um_user_hotupdate_e2e.py
  # 可用 XRAY_RUST_BIN / XRAY_GO_BIN 覆盖二进制路径
"""
from __future__ import annotations

import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time

REPO = r"D:/Project/Xray-core-rust"
RUST = os.environ.get(
    "XRAY_RUST_BIN", os.path.join(REPO, "target-Wave7Um", "release", "xray.exe")
)
GO = os.environ.get("XRAY_GO_BIN", r"D:/tmp/go2617/xray.exe")
TMP = os.path.join(REPO, "reports", "audit-2026-10-31-perf-mem-wiring", "fix", "tmp", "um_e2e")
os.makedirs(TMP, exist_ok=True)

API_PORT = 10088
SOCKS_PORT = 19090
SINK_PORT = 19091
API_ADDR = f"127.0.0.1:{API_PORT}"
TAG = "user-in"
SEED_UUID = "27848739-7e62-4138-9fd3-098a63964b6b"
ADDED_UUID = "e641f5ad-9397-41e3-bf1a-e8740dfed019"
SEED_EMAIL = "seed@um.test"
ADDED_EMAIL = "added@um.test"
SEED_PW = "seed-pass-1"
ADDED_PW = "added-pass-1"


# ─────────────────────────── sink（PONG 目标） ───────────────────────────
class Sink(threading.Thread):
    def __init__(self, port: int):
        super().__init__(daemon=True)
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(8)
        self.sock.settimeout(0.3)
        self.accepted = 0
        self._stop = False

    def run(self) -> None:
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                continue
            self.accepted += 1
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(3)
            conn.recv(4096)
            conn.sendall(b"PONG")
        except OSError:
            pass
        finally:
            conn.close()

    def stop(self) -> None:
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass


def wait_port(port: int, timeout: float = 20.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=0.5)
            s.close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def run(cmd: list[str]) -> tuple[int, str]:
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    return p.returncode, (p.stdout + p.stderr).strip()


def probe(socks_port: int, timeout: float = 6.0) -> str:
    """socks5 CONNECT → sink；返回 'ok:PONG' 或失败原因串。"""
    try:
        s = socket.create_connection(("127.0.0.1", socks_port), timeout=timeout)
    except OSError as e:
        return f"FAIL:connect:{e.__class__.__name__}"
    try:
        s.settimeout(timeout)
        s.sendall(b"\x05\x01\x00")
        if s.recv(2) != b"\x05\x00":
            return "FAIL:socks-greet"
        s.sendall(
            b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", SINK_PORT)
        )
        reply = s.recv(10)
        if len(reply) < 2 or reply[1] != 0:
            return f"FAIL:socks-reply:{reply!r}"
        s.sendall(b"PING\n")
        data = s.recv(64)
        return "ok:PONG" if data.startswith(b"PONG") else f"FAIL:payload={data!r}"
    except OSError as e:
        return f"FAIL:io:{e.__class__.__name__}"
    finally:
        s.close()


# ─────────────────────────── 协议配置 ───────────────────────────
def inbound_settings(proto: str, user: dict) -> dict:
    if proto == "vless":
        return {"decryption": "none", "clients": [user]}
    if proto == "vmess":
        return {"clients": [user]}
    if proto == "trojan":
        return {"clients": [user]}
    raise ValueError(proto)


def outbound_settings(proto: str, user: dict, port: int) -> dict:
    if proto == "vless":
        return {"vnext": [{"address": "127.0.0.1", "port": port, "users": [user]}]}
    if proto == "vmess":
        # Rust vmess 出站走 `vnext`（Go `infra/conf/vmess.go:115-124` 同款）。
        return {"vnext": [{"address": "127.0.0.1", "port": port, "users": [user]}]}
    if proto == "trojan":
        return {"servers": [{"address": "127.0.0.1", "port": port, "password": user["password"]}]}
    raise ValueError(proto)


def seed_user(proto: str) -> dict:
    if proto == "vless":
        return {"id": SEED_UUID, "email": SEED_EMAIL, "level": 0}
    if proto == "vmess":
        return {"id": SEED_UUID, "email": SEED_EMAIL, "level": 0, "alterId": 0}
    if proto == "trojan":
        return {"password": SEED_PW, "email": SEED_EMAIL, "level": 0}
    raise ValueError(proto)


def added_user(proto: str) -> dict:
    # 注意：vless **入站**用户禁带 "encryption"（Go `infra/conf/vless.go:84-86`：
    # "VLESS users: \"encryption\" should not be in inbound settings" ⇒ Go 客户端
    # `api adu` 会拒启）。出站侧凭据另见 `client_user`。
    if proto == "vless":
        return {"id": ADDED_UUID, "email": ADDED_EMAIL, "level": 0}
    if proto == "vmess":
        return {"id": ADDED_UUID, "email": ADDED_EMAIL, "level": 0, "alterId": 0}
    if proto == "trojan":
        return {"password": ADDED_PW, "email": ADDED_EMAIL, "level": 0}
    raise ValueError(proto)


def client_user(proto: str, which: str = "added") -> dict:
    """客户端出站用的凭据（which="seed" 用配置里的种子用户；"added" 用热更新用户）。"""
    if proto == "vless":
        return {
            "id": SEED_UUID if which == "seed" else ADDED_UUID,
            "encryption": "none",
        }
    if proto == "vmess":
        return {
            "id": SEED_UUID if which == "seed" else ADDED_UUID,
            "alterId": 0,
            "security": "auto",
        }
    if proto == "trojan":
        return {"password": SEED_PW if which == "seed" else ADDED_PW}
    raise ValueError(proto)


def server_cfg(proto: str) -> dict:
    return {
        "log": {"loglevel": "warning"},
        "api": {
            "tag": "api",
            "listen": f"127.0.0.1:{API_PORT}",
            "services": ["HandlerService"],
        },
        "inbounds": [
            {
                "tag": TAG,
                "listen": "127.0.0.1",
                "port": 19092,
                "protocol": proto,
                "settings": inbound_settings(proto, seed_user(proto)),
            }
        ],
        "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {"finalRules": [{"action": "allow"}]}}],
    }


def client_cfg(proto: str, which: str = "added") -> dict:
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": SOCKS_PORT,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True},
            }
        ],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": proto,
                "settings": outbound_settings(proto, client_user(proto, which), 19092),
            }
        ],
    }


def adu_cfg(proto: str) -> dict:
    """`api adu` 输入：同 tag 的 inbound + 待新增用户（Go 侧要求 inbound 可构建）。"""
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": TAG,
                "listen": "127.0.0.1",
                "port": 19092,
                "protocol": proto,
                "settings": inbound_settings(proto, added_user(proto)),
            }
        ],
    }


class Instance:
    def __init__(self, exe: str, cfg: dict, name: str):
        self.exe = exe
        self.cfg_path = os.path.join(TMP, f"{name}.json")
        with open(self.cfg_path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        self.proc: subprocess.Popen | None = None

    def start(self) -> None:
        self.proc = subprocess.Popen(
            [self.exe, "run", "-c", self.cfg_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=6)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=6)


def api_cmds(client: str, adu_path: str) -> dict[str, list[str]]:
    if client == "go":
        return {
            "adu": [GO, "api", "adu", f"--server={API_ADDR}", adu_path],
            "rmu": [GO, "api", "rmu", f"--server={API_ADDR}", "-tag", TAG, ADDED_EMAIL],
            "count": [GO, "api", "inboundusercount", f"--server={API_ADDR}", "-tag", TAG],
        }
    return {
        "adu": [RUST, "api", "add-user", "--server", API_ADDR, adu_path],
        "rmu": [RUST, "api", "remove-user", "--server", API_ADDR, "--tag", TAG, ADDED_EMAIL],
        "count": [RUST, "api", "inbound-user-count", "--server", API_ADDR, "--tag", TAG],
    }


def count_from(out: str) -> int | None:
    import re

    m = re.search(r'"count"\s*:\s*(\d+)', out) or re.search(r"count:\s*(\d+)", out)
    return int(m.group(1)) if m else None


def case(proto: str, client: str) -> bool:
    label = f"{proto} / {client} client"
    print(f"\n===== {label} =====", flush=True)
    ok = True
    sink = Sink(SINK_PORT)
    sink.start()
    adu_path = os.path.join(TMP, f"adu_{proto}.json")
    with open(adu_path, "w", encoding="utf-8") as f:
        json.dump(adu_cfg(proto), f, indent=2)
    cmds = api_cmds(client, adu_path)
    server = Instance(RUST, server_cfg(proto), f"srv_{proto}")
    server.start()
    cli = Instance(RUST, client_cfg(proto, "added"), f"cli_{proto}")
    try:
        if not wait_port(API_PORT) or not wait_port(19092):
            print("FAIL: 端口未监听")
            return False
        time.sleep(0.5)

        # 基线自检：**种子用户**（配置里就有）必须能连——否则说明是拓扑/协议
        # 问题，不能归到「热更新不生效」头上。
        base_cli = Instance(RUST, client_cfg(proto, "seed"), f"cli_seed_{proto}")
        base_cli.start()
        if wait_port(SOCKS_PORT):
            r = probe(SOCKS_PORT)
            print(f"[probe-baseline-seed] {r}", flush=True)
            if not r.startswith("ok:PONG"):
                print("FAIL: 基线（种子用户）都连不通 ⇒ 拓扑/协议问题，不是热更新缺陷")
                ok = False
        else:
            print("FAIL: 基线客户端 socks 端口未监听")
            ok = False
        base_cli.stop()
        time.sleep(0.3)

        rc, out = run(cmds["count"])
        n0 = count_from(out)
        print(f"[count-initial rc={rc}] {out[:200]}  => {n0}", flush=True)

        rc, out = run(cmds["adu"])
        print(f"[adu rc={rc}] {out[:300]}", flush=True)
        if rc != 0:
            print("FAIL: adu 失败")
            ok = False
        rc, out = run(cmds["count"])
        n1 = count_from(out)
        print(f"[count-after-adu rc={rc}] {out[:200]}  => {n1}", flush=True)
        if n0 is not None and n1 != n0 + 1:
            print(f"FAIL: adu 后用户数应为 {n0 + 1}，实得 {n1}")
            ok = False

        # 客户端用**新用户**凭据起（模拟新用户立刻拿凭据连接）
        cli.start()
        if not wait_port(SOCKS_PORT):
            print("FAIL: 客户端 socks 端口未监听")
            return False
        time.sleep(0.4)
        r = probe(SOCKS_PORT)
        print(f"[probe-after-adu] {r}", flush=True)
        if not r.startswith("ok:PONG"):
            print("FAIL: 新用户加完后仍连不上（未立即生效？）")
            ok = False

        rc, out = run(cmds["rmu"])
        print(f"[rmu rc={rc}] {out[:300]}", flush=True)
        if rc != 0:
            print("FAIL: rmu 失败")
            ok = False
        rc, out = run(cmds["count"])
        n2 = count_from(out)
        print(f"[count-after-rmu rc={rc}] {out[:200]}  => {n2}", flush=True)
        if n0 is not None and n2 != n0:
            print(f"FAIL: rmu 后用户数应回到 {n0}，实得 {n2}")
            ok = False

        r = probe(SOCKS_PORT)
        print(f"[probe-after-rmu] {r}", flush=True)
        if r.startswith("ok:PONG"):
            print("FAIL: 用户移除后新连接仍被放行（未立即生效？）")
            ok = False
    finally:
        cli.stop()
        server.stop()
        sink.stop()
        time.sleep(0.3)
    print(f"==> {label}: {'PASS' if ok else 'FAIL'}", flush=True)
    return ok


def main() -> int:
    for exe in (RUST, GO):
        if not os.path.isfile(exe):
            print(f"FATAL: missing binary {exe}", file=sys.stderr)
            return 2
    protos = [
        p for p in (sys.argv[1].split(",") if len(sys.argv) > 1 else ["vless", "vmess", "trojan"])
    ]
    results = []
    for proto in protos:
        results.append(case(proto, "rust"))
    for proto in protos:
        results.append(case(proto, "go"))
    passed = sum(1 for r in results if r)
    print(f"\n=== {passed}/{len(results)} PASS ===")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
