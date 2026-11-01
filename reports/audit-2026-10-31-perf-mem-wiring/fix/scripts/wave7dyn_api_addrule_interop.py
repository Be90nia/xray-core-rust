#!/usr/bin/env python
"""bd 9c8k6 ②：AddRule 真互通（Go 客户端 ↔ Rust 服务端 / Rust 客户端 ↔ Go 服务端）。

同时验证 ①：AddRule 的 `shouldAppend=false` = **整体替换**规则集（新增规则后旧
ruleTag 必须消失），`shouldAppend=true` = 追加（旧 ruleTag 保留）。

矩阵：
  phase 1  Rust 服务端  ← Go 客户端 `api adrules`（Go 造的 xray.app.router.Config 载荷）
  phase 2  Go   服务端  ← Rust 客户端 `api add-rule`（Rust 造的 xray.app.router.Config 载荷）
  phase 3  两端各跑一次 append（追加语义）

用法：
  python reports/audit-2026-10-31-perf-mem-wiring/fix/scripts/wave7dyn_api_addrule_interop.py
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
    "XRAY_RUST_BIN", os.path.join(REPO, "target-Wave7Dyn", "release", "xray.exe")
)
GO = os.environ.get("XRAY_GO_BIN", r"D:/tmp/go2617/xray.exe")
TMP = os.path.join(REPO, "reports", "audit-2026-10-31-perf-mem-wiring", "fix", "tmp", "api_interop")
os.makedirs(TMP, exist_ok=True)

API_PORT = 10085
SOCKS_PORT = 10801
API_ADDR = f"127.0.0.1:{API_PORT}"


def instance_cfg() -> dict:
    """两侧共用的实例配置（api listen 模式 = 明文 gRPC，Go/Rust 同形）。"""
    return {
        "log": {"loglevel": "warning"},
        "api": {
            "tag": "api",
            "listen": f"127.0.0.1:{API_PORT}",
            "services": ["RoutingService"],
        },
        "inbounds": [
            {
                "tag": "in-1",
                "listen": "127.0.0.1",
                "port": SOCKS_PORT,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True},
            }
        ],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
        "routing": {
            "rules": [
                {
                    "type": "field",
                    "ruleTag": "r-initial",
                    "inboundTag": ["in-1"],
                    "outboundTag": "direct",
                }
            ]
        },
    }


def rule_cfg(rule_tag: str) -> dict:
    """`api adrules` 用的配置片段（必须含 "routing" 字段）。"""
    return {
        "routing": {
            "rules": [
                {
                    "type": "field",
                    "ruleTag": rule_tag,
                    "inboundTag": ["in-1"],
                    "outboundTag": "direct",
                }
            ]
        }
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


def rule_tags_from_output(text: str) -> list[str]:
    """从 lsrules 输出（Go protojson / Rust Debug 形态）里抽 ruleTag。"""
    tags = re.findall(r'"ruleTag"\s*:\s*"([^"]+)"', text)
    if tags:
        return tags
    # Rust CLI 打印 proto Debug：`rule_tag: "r-x"`。
    return re.findall(r'rule_tag:\s*"([^"]+)"', text)


class Instance:
    def __init__(self, side: str, exe: str):
        self.side = side
        self.exe = exe
        self.cfg_path = os.path.join(TMP, f"instance_{side}.json")
        with open(self.cfg_path, "w", encoding="utf-8") as f:
            json.dump(instance_cfg(), f, indent=2)
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


def phase(label: str, server_exe: str, client_cmds: dict[str, list[str]], expect_replace: bool) -> bool:
    """起一个实例，用 client_cmds 里的两种客户端各跑一遍 add + list。"""
    print(f"\n===== {label} =====", flush=True)
    inst = Instance("srv", server_exe)
    inst.start()
    ok = True
    try:
        if not wait_port(API_PORT):
            print("FAIL: api 端口未监听")
            return False
        # 初始规则集（配置期带 r-initial）
        rc, out = run(client_cmds["list"])
        print(f"[list-initial rc={rc}] {out[:400]}", flush=True)
        initial = rule_tags_from_output(out)
        if "r-initial" not in initial:
            print(f"FAIL: 初始规则集应含 r-initial，实得 {initial}")
            ok = False

        # 客户端下发新规则（默认 shouldAppend=false → 整体替换）
        rc, out = run(client_cmds["add_replace"])
        print(f"[add(replace) rc={rc}] {out[:400]}", flush=True)
        if rc != 0:
            print("FAIL: add 失败")
            ok = False

        rc, out = run(client_cmds["list"])
        print(f"[list-after-replace rc={rc}] {out[:400]}", flush=True)
        tags = rule_tags_from_output(out)
        print(f"    ruleTags = {tags}", flush=True)
        if client_cmds["added_tag"] not in tags:
            print(f"FAIL: 新规则 {client_cmds['added_tag']} 未生效，实得 {tags}")
            ok = False
        if expect_replace and "r-initial" in tags:
            print(f"FAIL: shouldAppend=false 应整体替换（旧 r-initial 仍在），实得 {tags}")
            ok = False

        # 追加语义（shouldAppend=true → 旧规则保留）
        rc, out = run(client_cmds["add_append"])
        print(f"[add(append) rc={rc}] {out[:400]}", flush=True)
        rc, out = run(client_cmds["list"])
        print(f"[list-after-append rc={rc}] {out[:400]}", flush=True)
        tags = rule_tags_from_output(out)
        print(f"    ruleTags = {tags}", flush=True)
        if client_cmds["appended_tag"] not in tags:
            print(f"FAIL: 追加规则 {client_cmds['appended_tag']} 未生效，实得 {tags}")
            ok = False
        if client_cmds["added_tag"] not in tags:
            print(f"FAIL: 追加语义下旧规则 {client_cmds['added_tag']} 应保留，实得 {tags}")
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

    go_replace = os.path.join(TMP, "go_replace.json")
    go_append = os.path.join(TMP, "go_append.json")
    rust_replace = os.path.join(TMP, "rust_replace.json")
    rust_append = os.path.join(TMP, "rust_append.json")
    for path, tag in (
        (go_replace, "r-go"),
        (go_append, "r-go-2"),
        (rust_replace, "r-rust"),
        (rust_append, "r-rust-2"),
    ):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(rule_cfg(tag), f, indent=2)

    results = []

    # phase 1：Rust 服务端 ← Go 客户端
    results.append(
        phase(
            "phase1 Rust server <- Go client (adrules)",
            RUST,
            {
                "list": [GO, "api", "lsrules", f"--server={API_ADDR}"],
                "add_replace": [GO, "api", "adrules", f"--server={API_ADDR}", go_replace],
                "add_append": [GO, "api", "adrules", f"--server={API_ADDR}", "-append", go_append],
                "added_tag": "r-go",
                "appended_tag": "r-go-2",
            },
            expect_replace=True,
        )
    )

    # phase 2：Go 服务端 ← Rust 客户端
    results.append(
        phase(
            "phase2 Go server <- Rust client (add-rule)",
            GO,
            {
                "list": [RUST, "api", "list-rules", "--server", API_ADDR],
                "add_replace": [RUST, "api", "add-rule", "--server", API_ADDR, rust_replace],
                "add_append": [
                    RUST, "api", "add-rule", "--server", API_ADDR, "--append", rust_append,
                ],
                "added_tag": "r-rust",
                "appended_tag": "r-rust-2",
            },
            expect_replace=True,
        )
    )

    passed = sum(1 for r in results if r)
    print(f"\n=== {passed}/{len(results)} PASS ===")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
