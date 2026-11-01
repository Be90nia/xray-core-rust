#!/usr/bin/env python
"""bd 0z7zt：metrics tag 形态端到端（真实二进制）。

相位：
  1. tag 形态：metrics 只有 `tag`（无 listen）→ 起 Rust xray → 经 socks 入站 +
     路由规则 `outboundTag: <metrics-tag>` 访问 `http://metrics.internal/metrics`
     → 200 + Prometheus exposition。
  2. listen 回归：metrics 只有 `listen` → 直接 `GET /metrics` → 200。
  3. Go 对照：Go 26.10.17 同款 tag 配置 → `/debug/vars`（expvar JSON）；
     `/metrics` 404（Go 无该路径）。

环境：XRAY_RUST_BIN / XRAY_GO_BIN 可覆盖二进制路径；curl.exe 取自 PATH。
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time

REPO = r"D:/Project/Xray-core-rust"
RUST = os.environ.get("XRAY_RUST_BIN", os.path.join(REPO, "target-Wave7Met", "release", "xray.exe"))
GO = os.environ.get("XRAY_GO_BIN", r"D:/tmp/go2617/xray.exe")
TMP = os.path.join(REPO, "reports", "audit-2026-10-31-perf-mem-wiring", "fix", "tmp", "metrics_tag")
os.makedirs(TMP, exist_ok=True)

SOCKS_PORT = 10908
LISTEN_PORT = 10909
METRICS_TAG = "metrics-out"


def tag_cfg() -> dict:
    return {
        "log": {"loglevel": "warning"},
        "metrics": {"tag": METRICS_TAG},
        "inbounds": [
            {
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": SOCKS_PORT,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": False},
            }
        ],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
        "routing": {
            "rules": [{"type": "field", "inboundTag": ["socks-in"], "outboundTag": METRICS_TAG}]
        },
    }


def listen_cfg() -> dict:
    return {
        "log": {"loglevel": "warning"},
        "metrics": {"listen": f"127.0.0.1:{LISTEN_PORT}"},
        "inbounds": [],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
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


def run(cmd: list[str], timeout: int = 30) -> tuple[int, str]:
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return p.returncode, (p.stdout + p.stderr).strip()


def start_instance(name: str, exe: str, cfg: dict) -> subprocess.Popen:
    cfg_path = os.path.join(TMP, f"{name}.json")
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    proc = subprocess.Popen(
        [exe, "run", "-c", cfg_path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    return proc


def stop(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=6)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=6)


def phase_tag_via_socks(exe: str, label: str) -> bool:
    print(f"\n===== {label} =====", flush=True)
    proc = start_instance("tag_mode", exe, tag_cfg())
    ok = True
    try:
        if not wait_port(SOCKS_PORT):
            print("FAIL: socks 入站端口未监听")
            return False
        time.sleep(0.5)
        rc, out = run(
            [
                "curl",
                "-s",
                "-i",
                "--max-time",
                "10",
                "--socks5-hostname",
                f"127.0.0.1:{SOCKS_PORT}",
                "http://metrics.internal/metrics",
            ]
        )
        with open(os.path.join(TMP, "tag_mode_resp.txt"), "w", encoding="utf-8") as f:
            f.write(out)
        print(f"[curl rc={rc}]\n{out[:800]}", flush=True)
        if rc != 0:
            print("FAIL: curl 非零退出（tag 形态不可达）")
            ok = False
        else:
            head = out.split("\r\n")[0] if "\r\n" in out else out.split("\n")[0]
            if "200" not in head:
                print(f"FAIL: 期望 200，实得 {head!r}")
                ok = False
            if "# HELP xray_traffic_bytes" not in out:
                print("FAIL: body 缺 Prometheus exposition 头")
                ok = False
    finally:
        stop(proc)
        time.sleep(0.3)
    print(f"==> {label}: {'PASS' if ok else 'FAIL'}", flush=True)
    return ok


def phase_listen(exe: str, label: str) -> bool:
    print(f"\n===== {label} =====", flush=True)
    proc = start_instance("listen_mode", exe, listen_cfg())
    ok = True
    try:
        if not wait_port(LISTEN_PORT):
            print("FAIL: metrics listen 端口未监听")
            return False
        time.sleep(0.3)
        rc, out = run(["curl", "-s", "-i", "--max-time", "10", f"http://127.0.0.1:{LISTEN_PORT}/metrics"])
        print(f"[curl rc={rc}]\n{out[:500]}", flush=True)
        if rc != 0 or "200" not in (out.split("\n")[0] + out.split("\r\n")[0]):
            print("FAIL: listen 形态回归失败")
            ok = False
    finally:
        stop(proc)
        time.sleep(0.3)
    print(f"==> {label}: {'PASS' if ok else 'FAIL'}", flush=True)
    return ok


def phase_go_reference(exe: str) -> bool:
    print("\n===== Go 对照（tag 形态，Go 26.10.17 行为基准）=====", flush=True)
    proc = start_instance("go_tag", exe, tag_cfg())
    ok = True
    try:
        if not wait_port(SOCKS_PORT):
            print("FAIL: socks 入站端口未监听")
            return False
        time.sleep(0.5)
        rc_vars, out_vars = run(
            [
                "curl",
                "-s",
                "-i",
                "--max-time",
                "10",
                "--socks5-hostname",
                f"127.0.0.1:{SOCKS_PORT}",
                "http://metrics.internal/debug/vars",
            ]
        )
        print(f"[debug/vars rc={rc_vars}] {out_vars[:300]}", flush=True)
        rc_met, out_met = run(
            [
                "curl",
                "-s",
                "-o",
                os.devnull,
                "-w",
                "%{http_code}",
                "--max-time",
                "10",
                "--socks5-hostname",
                f"127.0.0.1:{SOCKS_PORT}",
                "http://metrics.internal/metrics",
            ]
        )
        print(f"[/metrics http_code={rc_met}:{out_met}]", flush=True)
        if rc_vars != 0 or "200" not in (out_vars.split("\n")[0] + out_vars.split("\r\n")[0]):
            print("FAIL: Go tag 形态 /debug/vars 不可达（对照基线本身失效）")
            ok = False
    finally:
        stop(proc)
        time.sleep(0.3)
    print(f"==> Go 对照: {'PASS' if ok else 'FAIL'}", flush=True)
    return ok


def main() -> int:
    for exe in (RUST, GO):
        if not os.path.isfile(exe):
            print(f"FATAL: missing binary {exe}", file=sys.stderr)
            return 2

    results = []
    results.append(phase_tag_via_socks(RUST, "1 tag 形态（Rust，经 socks+路由出站）"))
    results.append(phase_listen(RUST, "2 listen 形态回归（Rust）"))
    results.append(phase_go_reference(GO))

    passed = sum(1 for r in results if r)
    print(f"\n=== {passed}/{len(results)} PASS ===")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
