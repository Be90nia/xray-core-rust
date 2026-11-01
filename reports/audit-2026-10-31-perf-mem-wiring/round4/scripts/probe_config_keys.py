#!/usr/bin/env python3
"""Round4 ConfigParity: Go 26.10.17 vs Rust HEAD 双跑配置键接受度探针.

纪律:
- 端口段 ConfigParity 28000-28049
- 清理只按 PID (Stop-Process -Id), 禁 -Name / taskkill /IM / 通配
- 起实例用 python subprocess.Popen 持句柄, finally terminate
- 同输入字节 -> 两侧各起 -> 比可观测行为

判据:
  GO_ACCEPT / RUST_ACCEPT   两侧都起来 -> 看是否行为一致
  GO_ACCEPT / RUST_REJECT   Rust 拒启 -> 兼容性缺口
  GO_REJECT                 Go 拒启 -> 样本无效 (不算差异)
"""
import json, os, subprocess, sys, time, socket, tempfile

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


def deep_set(cfg, path, value):
    """path: list of keys (dict) or ints (list index)."""
    cur = cfg
    for i, k in enumerate(path):
        last = i == len(path) - 1
        if last:
            cur[k] = value
        else:
            cur = cur[k]


def run_one(binary, cfg, port, tag):
    """起实例 -> 返回 (status, stderr/stdout tail)."""
    cfg = json.loads(json.dumps(cfg))
    for ib in cfg.get("inbounds", []):
        ib["port"] = port
    p = os.path.join(TMP, f"cfg_{tag}.json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump(cfg, f)
    proc = subprocess.Popen(
        [binary, "run", "-c", p],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    out = b""
    deadline = time.time() + 6.0
    started = False
    try:
        while time.time() < deadline:
            rc = proc.poll()
            if rc is not None:
                out = proc.stdout.read()
                return ("REJECT" if rc != 0 else "EXIT0", out.decode("utf-8", "replace"))
            # 探端口是否在听
            try:
                s = socket.create_connection(("127.0.0.1", port), timeout=0.3)
                s.close()
                started = True
                break
            except OSError:
                time.sleep(0.15)
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
        try:
            out = proc.stdout.read()
        except Exception:
            pass
    txt = out.decode("utf-8", "replace")
    if started:
        return ("ACCEPT", txt)
    return ("NO_LISTEN", txt)


def probe(name, mutate, go_port=28000, rust_port=28001):
    cfg = json.loads(json.dumps(BASE))
    mutate(cfg)
    gs, go_out = run_one(GO, cfg, go_port, f"{name}_go")
    rs, rust_out = run_one(RUST, cfg, rust_port, f"{name}_rust")
    return {
        "name": name,
        "go": gs, "rust": rs,
        "go_out": go_out[-1500:],
        "rust_out": rust_out[-1500:],
    }


def tail(txt, n=6):
    lines = [l for l in (txt or "").splitlines() if l.strip()]
    return " || ".join(lines[-n:])


if __name__ == "__main__":
    results = []
    cases = json.load(open(sys.argv[1], encoding="utf-8"))
    for c in cases:
        path = c["path"]
        val = c["value"]

        def mut(cfg, path=path, val=val):
            deep_set(cfg, path, val)

        r = probe(c["name"], mut, go_port=c.get("go_port", 28000), rust_port=c.get("rust_port", 28001))
        r["path"] = path
        r["value"] = val
        results.append(r)
        print(f"[{r['name']}] GO={r['go']} RUST={r['rust']}")
        if r["go"] != "ACCEPT":
            print("   GO_OUT:", tail(r["go_out"]))
        if r["rust"] != "ACCEPT":
            print("   RUST_OUT:", tail(r["rust_out"]))
    with open(os.path.join(TMP, "results.json"), "w", encoding="utf-8") as f:
        json.dump(results, f, indent=1, ensure_ascii=False)
    print(f"\n== {len(results)} cases done ==")
    diff = [r for r in results if r["go"] == "ACCEPT" and r["rust"] != "ACCEPT"]
    print(f"GO_ACCEPT & RUST!=ACCEPT: {len(diff)}")
    for r in diff:
        print("  -", r["name"], r["rust"], tail(r["rust_out"], 3))
