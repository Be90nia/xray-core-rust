#!/usr/bin/env python3
"""Round4 ConfigParity v4: Go 26.10.17 vs Rust HEAD 配置接受度差分（正确口径）.

方法学修正（v2/v3 的坑，本文件修掉）:
  1. Rust `--test` 只跑 `xray_conf::Config::build()`（conf 层），**不含**协议层解析
     （`xray-core/src/outbound.rs` 的 `parse_*_config` 在 `start_full` 里跑）。
     Go `-test` 跑 `core.New` = conf + 协议 Build 全链。
     → 两侧口径不等价，必须都用**完整启动**比。
  2. 完整启动的输出采集用**临时文件**重定向（不用 PIPE）：
     v2 用 `proc.stdout.read1()` 在子进程存活期间读 PIPE → 阻塞挂死（900s 超时）。
  3. 存活判定：日志出现 `started|listening|listener started` 即视为「配置被接受且
     服务起来了」；UDP 传输（kcp/quic）不绑 TCP，故**端口探测仅作辅助**、不作判据。

判据（两侧都是「配置被接受」）：
  OK      = 配置被接受（进程存活 + 日志确认 started，或退出码 0）
  REJECT  = 进程非零退出（配置被拒）
"""
import json, os, subprocess, sys, tempfile, time, re

GO = "D:/tmp/go2617/xray.exe"
RUST = "D:/Project/Xray-core-rust/target/release/xray.exe"
TMP = "D:/Project/Xray-core-rust/reports/audit-2026-10-31-perf-mem-wiring/round4/tmp"
os.makedirs(TMP, exist_ok=True)

BASE = {
    "log": {"loglevel": "warning"},
    "inbounds": [
        {"tag": "in-1", "listen": "127.0.0.1", "port": 28000,
         "protocol": "socks", "settings": {"auth": "noauth", "udp": True}}
    ],
    "outbounds": [{"tag": "out-1", "protocol": "freedom", "settings": {}}],
}

ALIVE = re.compile(r"started|listening|listener started|Xray 26\.10\.17 started", re.I)


def deep_set(cfg, path, value):
    cur = cfg
    for i, k in enumerate(path):
        if i == len(path) - 1:
            cur[k] = value
        else:
            cur = cur[k]


def run_full(binary, cfg, tag):
    p = os.path.join(TMP, f"v4_{tag}.json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump(cfg, f)
    logp = os.path.join(TMP, f"v4_{tag}.log")
    with open(logp, "wb") as lf:
        proc = subprocess.Popen([binary, "run", "-c", p], stdout=lf, stderr=subprocess.STDOUT)
        deadline = time.time() + 3.5
        exited = None
        try:
            while time.time() < deadline:
                rc = proc.poll()
                if rc is not None:
                    exited = rc
                    break
                time.sleep(0.12)
        finally:
            try:
                proc.terminate()
                try:
                    proc.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=3)
            except OSError:
                pass
    txt = open(logp, "rb").read().decode("utf-8", "replace")
    # 判据：进程在窗口内非零退出 = 配置被拒（REJECT）；窗口结束仍存活 = 配置被接受。
    # 不依赖日志关键字——Rust 的 "listening" 是 INFO 级，loglevel=warning 时被抑制。
    if exited is not None and exited != 0:
        return "REJECT", txt
    return "OK", txt


def probe(name, path, value):
    cfg = json.loads(json.dumps(BASE))
    deep_set(cfg, path, value)
    gs, go_out = run_full(GO, cfg, f"{name}_go")
    rs, rust_out = run_full(RUST, cfg, f"{name}_rust")
    return {"name": name, "path": path, "value": value,
            "go": gs, "rust": rs, "go_out": go_out[-1500:], "rust_out": rust_out[-1500:]}


def keyline(txt):
    lines = [l.strip() for l in (txt or "").splitlines() if l.strip()]
    for l in reversed(lines):
        low = l.lower()
        if any(k in low for k in ("error", "failed", "rejected", "not supported", "not implemented",
                                  "removed", "unknown", "invalid", "unsupported", "must", "warn")):
            return l[:300]
    return lines[-1][:300] if lines else ""


if __name__ == "__main__":
    cases = json.load(open(sys.argv[1], encoding="utf-8"))
    results = []
    for c in cases:
        r = probe(c["name"], c["path"], c["value"])
        results.append(r)
        mark = ""
        if r["go"] == "OK" and r["rust"] != "OK":
            mark = "  <<< GO_OK / RUST_" + r["rust"]
        elif r["go"] != "OK" and r["rust"] == "OK":
            mark = "  <<< GO_" + r["go"] + " / RUST_OK"
        print(f"[{r['name']:38s}] GO={r['go']:8s} RUST={r['rust']:8s}{mark}")
        if r["go"] != "OK":
            print("    GO  :", keyline(r["go_out"]))
        if r["rust"] != "OK":
            print("    RUST:", keyline(r["rust_out"]))
    outp = os.path.join(TMP, f"results_v4_{os.path.basename(sys.argv[1]).replace('.json','')}.json")
    with open(outp, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=1, ensure_ascii=False)
    d1 = [r for r in results if r["go"] == "OK" and r["rust"] != "OK"]
    d2 = [r for r in results if r["go"] != "OK" and r["rust"] == "OK"]
    print(f"\n== {len(results)} cases ==")
    print(f"A. GO_OK & RUST!=OK  (Rust 更严 -> 兼容性缺口): {len(d1)}")
    for r in d1:
        print(f"   - {r['name']:36s} {r['rust']:8s} {keyline(r['rust_out'])[:170]}")
    print(f"B. GO!=OK & RUST_OK  (Rust 更宽 -> fail-open): {len(d2)}")
    for r in d2:
        print(f"   - {r['name']:36s} {r['go']:8s} {keyline(r['go_out'])[:170]}")
