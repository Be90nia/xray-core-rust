"""能力探针：确认两侧对各协议/配置面的支持情况（启动即退出，只看输出）。

读输出用独立线程 + 队列，避免 readline 阻塞。
"""
import json, os, queue, subprocess, sys, threading, time

GO = r"D:\tmp\go2617\xray.exe"
RUST = r"D:\Project\Xray-core-rust\target\release\xray.exe"
TMP = r"D:\Project\Xray-core-rust\reports\audit-2026-10-31-perf-mem-wiring\round4\tmp"
os.makedirs(TMP, exist_ok=True)

CASES = {
    "dns_inbound": {
        "inbounds": [{"protocol": "dns", "tag": "d", "port": 28100,
                      "settings": {"servers": ["127.0.0.1:5399"]}}],
        "outbounds": [{"protocol": "freedom", "tag": "out"}],
    },
    "dokodemo_udp": {
        "inbounds": [{"protocol": "dokodemo-door", "tag": "d", "port": 28101,
                      "settings": {"address": "127.0.0.1", "port": 5399, "network": "udp"}}],
        "outbounds": [{"protocol": "freedom", "tag": "out"}],
    },
    "socks_udp": {
        "inbounds": [{"protocol": "socks", "tag": "s", "port": 28102,
                      "settings": {"udp": True, "auth": "noauth"}}],
        "outbounds": [{"protocol": "freedom", "tag": "out"}],
    },
    "dns_outbound": {
        "inbounds": [{"protocol": "dokodemo-door", "tag": "d", "port": 28103,
                      "settings": {"address": "127.0.0.1", "port": 53, "network": "tcp,udp"}}],
        "outbounds": [{"protocol": "dns", "tag": "dns-out", "settings": {"address": "127.0.0.1", "port": 5399}}],
        "routing": {"rules": [{"type": "field", "inboundTag": ["d"], "outboundTag": "dns-out"}]},
    },
    "dns_app": {
        "dns": {"servers": ["127.0.0.1:5399"], "hosts": {"a.test": "1.2.3.4"}},
        "inbounds": [{"protocol": "socks", "tag": "s", "port": 28104, "settings": {"auth": "noauth"}}],
        "outbounds": [{"protocol": "freedom", "tag": "out"}],
    },
    "socks_out_udp": {
        "inbounds": [{"protocol": "socks", "tag": "s", "port": 28105, "settings": {"auth": "noauth"}}],
        "outbounds": [{"protocol": "socks", "tag": "o", "settings": {"servers": [{"address": "127.0.0.1", "port": 28102}]}}],
    },
    "vmess_udp": {
        "inbounds": [{"protocol": "vmess", "tag": "v", "port": 28106,
                      "settings": {"clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811"}]}}],
        "outbounds": [{"protocol": "vmess", "tag": "o", "settings": {"vnext": [{"address": "127.0.0.1", "port": 28106, "users": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811"}]}]}}],
    },
}


def run(side, name, cfg, wait=2.0):
    exe = GO if side == "go" else RUST
    path = os.path.join(TMP, f"probe_{name}_{side}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg, f)
    p = subprocess.Popen([exe, "run", "-c", path], stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    q = queue.Queue()

    def reader():
        for raw in iter(p.stdout.readline, b""):
            q.put(raw.decode("utf-8", "replace").rstrip())
        q.put(None)

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    lines = []
    deadline = time.time() + wait
    while time.time() < deadline:
        try:
            line = q.get(timeout=0.2)
        except queue.Empty:
            if p.poll() is not None:
                break
            continue
        if line is None:
            break
        lines.append(line)
    alive = p.poll() is None
    if alive:
        p.terminate()
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait(timeout=5)
    try:
        p.stdout.close()
    except Exception:
        pass
    return alive, lines


def main():
    only = sys.argv[1] if len(sys.argv) > 1 else None
    for name, cfg in CASES.items():
        if only and only != name:
            continue
        for side in ("go", "rust"):
            alive, lines = run(side, name, cfg)
            print(f"=== {name} [{side}] alive={alive}", flush=True)
            for l in lines[:14]:
                print("   ", l[:200], flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
