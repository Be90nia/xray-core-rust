#!/usr/bin/env python
"""bd o1a9p：ListRule 字段形状真互通（Go `ListRuleItem{tag, ruleTag}`）。

四个相位（同一份配置，api listen = 明文 gRPC 127.0.0.1:10085）：
  A. Rust 服务端 ← Go 客户端   `xray api lsrules --server=…`
  B. Go   服务端 ← Go 客户端   （字段形状基准）
  C. Rust 服务端 ← Rust 客户端 `xray api list-rules --server …`
  D. Go   服务端 ← Rust 客户端

断言：同一客户端对两侧服务端抽出的 `(ruleTag, tag)` 集合逐条一致
（A==B 且 C==D），且集合里至少一条规则带非空 tag（证明不是"两边都空"的假对齐）。

配置含两类规则：outboundTag 规则（tag 非空）+ balancerTag 规则（Go 侧 tag 恒空，
验证空串语义也一致）。

环境：XRAY_RUST_BIN / XRAY_GO_BIN 可覆盖二进制路径。
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
RUST = os.environ.get("XRAY_RUST_BIN", os.path.join(REPO, "target-Wave7Lsr", "release", "xray.exe"))
GO = os.environ.get("XRAY_GO_BIN", r"D:/tmp/go2617/xray.exe")
TMP = os.path.join(REPO, "reports", "audit-2026-10-31-perf-mem-wiring", "fix", "tmp", "api_interop_lsr")
os.makedirs(TMP, exist_ok=True)

API_PORT = 10085
SOCKS_PORT = 10801
API_ADDR = f"127.0.0.1:{API_PORT}"


def instance_cfg() -> dict:
    """两侧共用的实例配置（api listen 模式 = 明文 gRPC，Go/Rust 同形）。"""
    return {
        "log": {"loglevel": "warning"},
        "api": {"tag": "api", "listen": API_ADDR, "services": ["RoutingService"]},
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
                    "ruleTag": "r-outbound",
                    "inboundTag": ["in-1"],
                    "outboundTag": "direct",
                },
                {
                    "type": "field",
                    "ruleTag": "r-balancer",
                    "network": "tcp,udp",
                    "balancerTag": "lb1",
                },
            ],
            "balancers": [{"tag": "lb1", "selector": ["direct"]}],
        },
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


def pairs_from_output(text: str) -> list[tuple[str, str]]:
    """从 lsrules 输出抽 (ruleTag, tag)，保持服务端返回顺序。

    Go 客户端输出 protojson（空字段省略）；Rust 客户端输出 prost Debug。
    两侧都按「规则对象」切块后逐对象取字段；tag 缺失 = 空串（Go protojson
    对空串省略字段，等价空值）。
    """
    pairs: list[tuple[str, str]] = []

    def take(obj: str) -> None:
        m_rt = re.search(r'(?:ruleTag|rule_tag)"?\s*[:=]\s*"([^"]*)"', obj)
        m_t = re.search(r'(?<![a-zA-Z_"])(?:"tag"|tag)"?\s*[:=]\s*"([^"]*)"', obj)
        if m_rt:
            pairs.append((m_rt.group(1), m_t.group(1) if m_t else ""))

    for obj in re.findall(r"ListRuleItem\s*\{[^}]*\}", text):
        take(obj)
    if not pairs:
        for obj in re.findall(r"\{[^{}]*ruleTag[^{}]*\}", text):
            take(obj)
    return pairs


class Instance:
    def __init__(self, side: str, exe: str):
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


def phase(label: str, server_exe: str, client_cmd: list[str], log_name: str) -> list[tuple[str, str]]:
    """起一个实例跑一次 lsrules，返回 (ruleTag, tag) 列表；原始输出落盘。"""
    print(f"\n===== {label} =====", flush=True)
    inst = Instance("srv", server_exe)
    inst.start()
    try:
        if not wait_port(API_PORT):
            print("FAIL: api 端口未监听")
            return []
        rc, out = run(client_cmd)
        with open(os.path.join(TMP, log_name), "w", encoding="utf-8") as f:
            f.write(out)
        print(f"[rc={rc}] {out}", flush=True)
        if rc != 0:
            print("FAIL: lsrules 非零退出")
            return []
        return pairs_from_output(out)
    finally:
        inst.stop()
        time.sleep(0.4)


def norm(pairs: list[tuple[str, str]]) -> dict[str, str]:
    return {rt: t for rt, t in pairs}


def main() -> int:
    for exe in (RUST, GO):
        if not os.path.isfile(exe):
            print(f"FATAL: missing binary {exe}", file=sys.stderr)
            return 2

    go_ls = [GO, "api", "lsrules", f"--server={API_ADDR}"]
    rust_ls = [RUST, "api", "list-rules", "--server", API_ADDR]

    a = phase("A Rust server <- Go client", RUST, go_ls, "A_rust_srv_go_client.log")
    b = phase("B Go server <- Go client (shape baseline)", GO, go_ls, "B_go_srv_go_client.log")
    c = phase("C Rust server <- Rust client", RUST, rust_ls, "C_rust_srv_rust_client.log")
    d = phase("D Go server <- Rust client", GO, rust_ls, "D_go_srv_rust_client.log")

    ok = True
    print("\n===== 对比 =====", flush=True)
    print(f"A (rust srv, go client)   = {a}", flush=True)
    print(f"B (go srv,   go client)   = {b}", flush=True)
    print(f"C (rust srv, rust client) = {c}", flush=True)
    print(f"D (go srv,   rust client) = {d}", flush=True)

    if not all([a, b, c, d]):
        print("FAIL: 有相位拿不到规则列表")
        ok = False
    else:
        if norm(a) != norm(b):
            print(f"FAIL: Go 客户端视角字段集不一致\n  rust={norm(a)}\n  go  ={norm(b)}")
            ok = False
        if norm(c) != norm(d):
            print(f"FAIL: Rust 客户端视角字段集不一致\n  rust={norm(c)}\n  go  ={norm(d)}")
            ok = False
        if not any(t for _, t in a):
            print("FAIL: 无任何规则带非空 tag——对齐可能是「两边都空」的假对齐")
            ok = False
        for rt, t in a:
            print(f"    rule {rt!r}: tag={t!r}", flush=True)

    print(f"\n=== {'PASS' if ok else 'FAIL'} ===")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
