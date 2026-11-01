#!/usr/bin/env python
"""bd c89uy：API adu/rmu 用户载荷真互通（Go 客户端 ↔ Rust 服务端 / Rust 客户端 ↔ Go 服务端）。

矩阵（两侧各一轮）：
  phase1  Rust 服务端 ← Go 客户端 `api adu` / `api rmu`
  phase2  Go   服务端 ← Rust 客户端 `api adu` / `api rmu`

判据（每轮）：
  1. 初始用户数 = 1（服务端配置里 seed 的那个用户）；
  2. `adu` 后用户数 = 2（新增用户在两端都被接受 ⇒ 载荷形状可被对端解析）；
  3. `rmu` 后用户数 = 1（移除语义一致）。

用法：
  python reports/audit-2026-10-31-perf-mem-wiring/fix/scripts/wave7user_api_user_interop.py
  # 可用 XRAY_RUST_BIN / XRAY_GO_BIN 覆盖二进制路径
"""
from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
import time

REPO = r"D:/Project/Xray-core-rust"
RUST = os.environ.get(
    "XRAY_RUST_BIN", os.path.join(REPO, "target-Wave7User", "release", "xray.exe")
)
GO = os.environ.get("XRAY_GO_BIN", r"D:/tmp/go2617/xray.exe")
TMP = os.path.join(REPO, "reports", "audit-2026-10-31-perf-mem-wiring", "fix", "tmp", "api_user_interop")
os.makedirs(TMP, exist_ok=True)

API_PORT = 10086
VLESS_PORT = 10802
API_ADDR = f"127.0.0.1:{API_PORT}"
TAG = "vless-in"
SEED_UUID = "27848739-7e62-4138-9fd3-098a63964b6b"
ADDED_UUID = "e641f5ad-9397-41e3-bf1a-e8740dfed019"
SEED_EMAIL = "seed@interop.test"
ADDED_EMAIL = "added@interop.test"


def server_cfg() -> dict:
    """两侧同形的服务端配置（api listen 模式 = 明文 gRPC）。"""
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
                "port": VLESS_PORT,
                "protocol": "vless",
                "settings": {
                    "decryption": "none",
                    "clients": [{"id": SEED_UUID, "email": SEED_EMAIL, "level": 0}],
                },
            }
        ],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
    }


def adu_cfg() -> dict:
    """`api adu` 的输入配置：同 tag 的 inbound + 一个待新增用户。

    Go 的 `adu` 走 `inbound.Build()` 取用户，故 inbound 必须是**可构建**的完整配置
    （缺 listen/port 时 Go 报 "Listen on AnyIP but no Port(s) set in InboundDetour"）。
    """
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": TAG,
                "listen": "127.0.0.1",
                "port": VLESS_PORT,
                "protocol": "vless",
                "settings": {
                    "decryption": "none",
                    "clients": [{"id": ADDED_UUID, "email": ADDED_EMAIL, "level": 1}],
                },
            }
        ],
    }


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


def user_count(out: str) -> int | None:
    """从 `inboundusercount` 输出里抽用户数（Go protojson / Rust Debug 两种形态）。"""
    m = re.search(r'"count"\s*:\s*(\d+)', out)
    if m:
        return int(m.group(1))
    m = re.search(r"count:\s*(\d+)", out)
    if m:
        return int(m.group(1))
    return None


class Instance:
    def __init__(self, exe: str):
        self.exe = exe
        self.cfg_path = os.path.join(TMP, "server.json")
        with open(self.cfg_path, "w", encoding="utf-8") as f:
            json.dump(server_cfg(), f, indent=2)
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


def phase(label: str, server_exe: str, client: str) -> bool:
    """一轮互通：Go 客户端或 Rust 客户端对同形服务端做 adu/rmu + 计数核对。"""
    print(f"\n===== {label} =====", flush=True)
    adu_path = os.path.join(TMP, "adu.json")
    with open(adu_path, "w", encoding="utf-8") as f:
        json.dump(adu_cfg(), f, indent=2)

    if client == "go":
        count_cmd = [GO, "api", "inboundusercount", f"--server={API_ADDR}", "-tag", TAG]
        adu_cmd = [GO, "api", "adu", f"--server={API_ADDR}", adu_path]
        rmu_cmd = [GO, "api", "rmu", f"--server={API_ADDR}", "-tag", TAG, ADDED_EMAIL]
    else:
        count_cmd = [RUST, "api", "inbound-user-count", "--server", API_ADDR, "--tag", TAG]
        adu_cmd = [RUST, "api", "add-user", "--server", API_ADDR, adu_path]
        rmu_cmd = [RUST, "api", "remove-user", "--server", API_ADDR, "--tag", TAG, ADDED_EMAIL]

    inst = Instance(server_exe)
    inst.start()
    ok = True
    try:
        if not wait_port(API_PORT):
            print("FAIL: api 端口未监听")
            return False
        time.sleep(0.5)

        rc, out = run(count_cmd)
        print(f"[count-initial rc={rc}] {out[:300]}", flush=True)
        n0 = user_count(out)
        print(f"    count = {n0}", flush=True)
        if n0 is None:
            print("FAIL: 初始用户数读不出")
            ok = False

        rc, out = run(adu_cmd)
        print(f"[adu rc={rc}] {out[:400]}", flush=True)
        if rc != 0:
            print("FAIL: adu 失败")
            ok = False

        rc, out = run(count_cmd)
        print(f"[count-after-adu rc={rc}] {out[:300]}", flush=True)
        n1 = user_count(out)
        print(f"    count = {n1}", flush=True)
        if n0 is not None and n1 != n0 + 1:
            print(f"FAIL: adu 后用户数应为 {n0 + 1}，实得 {n1}")
            ok = False

        rc, out = run(rmu_cmd)
        print(f"[rmu rc={rc}] {out[:400]}", flush=True)
        if rc != 0:
            print("FAIL: rmu 失败")
            ok = False

        rc, out = run(count_cmd)
        print(f"[count-after-rmu rc={rc}] {out[:300]}", flush=True)
        n2 = user_count(out)
        print(f"    count = {n2}", flush=True)
        if n0 is not None and n2 != n0:
            print(f"FAIL: rmu 后用户数应回到 {n0}，实得 {n2}")
            ok = False
    finally:
        inst.stop()
        time.sleep(0.4)
    print(f"==> {label}: {'PASS' if ok else 'FAIL'}", flush=True)
    return ok


def main() -> int:
    for exe in (RUST, GO):
        if not os.path.isfile(exe):
            print(f"FATAL: missing binary {exe}", file=sys.stderr)
            return 2

    results = [
        phase("phase1 Rust server <- Go client (adu/rmu)", RUST, "go"),
        phase("phase2 Go server <- Rust client (adu/rmu)", GO, "rust"),
    ]
    passed = sum(1 for r in results if r)
    print(f"\n=== {passed}/{len(results)} PASS ===")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
