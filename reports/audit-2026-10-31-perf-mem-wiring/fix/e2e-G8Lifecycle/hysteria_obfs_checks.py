#!/usr/bin/env python3
"""bd a3tos 端到端：hysteria2 入站 finalmask 解析与非法配置拒启。

判据：
 1. 非法混淆（未知 type / 2 字节 PSK）→ `xray run` 退出码非 0，且错误点名 finalmask；
 2. 合法 salamander → 启动成功（进程存活 + 监听日志 "hysteria inbound liste..."）。

用法: python hysteria_obfs_checks.py <xray.exe>
"""
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PORT = 28543
BASE = {
    "log": {"loglevel": "debug"},
    "inbounds": [
        {
            "tag": "hy-in",
            "listen": "127.0.0.1",
            "port": PORT,
            "protocol": "hysteria",
            "settings": {"version": 2, "auth": "test-pass"},
        }
    ],
    "outbounds": [{"tag": "freedom-out", "protocol": "freedom", "settings": {}}],
}


def write_cfg(name, finalmask):
    cfg = json.loads(json.dumps(BASE))
    cfg["inbounds"][0]["streamSettings"] = {"network": "hysteria", "finalmask": finalmask}
    path = os.path.join(HERE, f"hysteria-{name}.generated.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    return path


def case_reject(xray, name, finalmask):
    path = write_cfg(name, finalmask)
    cp = subprocess.run(
        [xray, "run", "-c", path], capture_output=True, text=True, timeout=90
    )
    out = (cp.stdout or "") + (cp.stderr or "")
    with open(os.path.join(HERE, f"hysteria-{name}.log"), "w", encoding="utf-8") as f:
        f.write(out)
    ok = cp.returncode != 0 and "finalmask" in out.lower()
    print(
        f"CASE={name} EXIT={cp.returncode} RESULT={'PASS' if ok else 'FAIL'} "
        f"finalmask_err={'finalmask' in out.lower()}"
    )
    if not ok:
        print("---- output ----\n" + "\n".join(out.splitlines()[-15:]))
    return ok


def case_accept(xray, name, finalmask):
    path = write_cfg(name, finalmask)
    log_path = os.path.join(HERE, f"hysteria-{name}.log")
    with open(log_path, "wb") as log:
        proc = subprocess.Popen([xray, "run", "-c", path], stdout=log, stderr=log)
        started = False
        end = time.time() + 25
        while time.time() < end:
            if proc.poll() is not None:
                break
            time.sleep(0.5)
            try:
                with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                    text = f.read()
            except OSError:
                continue
            if "hysteria inbound listener" in text or "hysteria inbound listening" in text:
                started = True
                break
        alive = proc.poll() is None
        if alive:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()
    ok = started and "%" not in text.lower().replace("%", "%")
    ok = started
    print(
        f"CASE={name} ALIVE_WHEN_CHECKED={alive} RESULT={'PASS' if ok else 'FAIL'} "
        f"listening_log={'hysteria inbound liste' in text}"
    )
    if not ok:
        print("---- log tail ----\n" + "\n".join(text.splitlines()[-15:]))
    return ok


def main():
    xray = sys.argv[1]
    results = [
        case_reject(xray, "bad-type", {"udp": [{"type": "bogus", "settings": {}}]}),
        case_reject(
            xray, "short-psk", {"udp": [{"type": "salamander", "settings": {"password": "ab"}}]}
        ),
        case_accept(
            xray,
            "salamander-ok",
            {"udp": [{"type": "salamander", "settings": {"password": "0123456789abcdef"}}]},
        ),
    ]
    print(f"OVERALL={'PASS' if all(results) else 'FAIL'}")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
