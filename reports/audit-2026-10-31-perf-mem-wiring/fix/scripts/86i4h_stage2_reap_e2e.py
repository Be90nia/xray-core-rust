"""bd 86i4h 阶段2 e2e：每连接 spawn 收割（spawn_reaping）+ 停机零残留。

真实 release 二进制 + 真实 socks5 → freedom 转发。三类量：

  R1 真实转发   1KB 往返字节一致（收割装配点没碰数据面）
  R2 条目累积   `XRAY_ALLOC_STATS` 的 live_bytes 在 N 条连接前后的增量 / N
                （判别器：修前每次 spawn 留 1 条 JoinSet 条目 ≈ 百字节级/连接；
                 修后条目随下次 spawn 出集 → 增量落回噪声）
  R3 句柄/线程  相对暖机基线不随轮次增长
  R4 停机       terminate → 期限内退出 + 端口释放

用法：
  python 86i4h_stage2_reap_e2e.py --xray <release/xray.exe> --conns 300
  python 86i4h_stage2_reap_e2e.py --xray <xray.exe> --conns 300 --expect leaky   # 反向对照
"""
import argparse
import json
import os
import re
import socket
import struct
import subprocess
import sys
import threading
import time

import psutil

HERE = os.path.dirname(os.path.abspath(__file__))
TMP = os.path.abspath(os.path.join(HERE, "..", "tmp"))
os.makedirs(TMP, exist_ok=True)

SOCKS_PORT = 21381
ECHO_PORT = 22090
STATS = re.compile(r"\[xray-alloc-stats\].*?live_bytes=(\d+)")
PAYLOAD = bytes(range(256)) * 4  # 1KB


class EchoServer(threading.Thread):
    def __init__(self, port):
        super().__init__(daemon=True)
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", port))
        self.srv.listen(64)

    def run(self):
        while True:
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self.serve, args=(c,), daemon=True).start()

    @staticmethod
    def serve(c):
        try:
            while True:
                data = c.recv(65536)
                if not data:
                    return
                c.sendall(data)
        except OSError:
            pass
        finally:
            c.close()


def socks_roundtrip(dest_port, payload):
    s = socket.create_connection(("127.0.0.1", SOCKS_PORT), timeout=10)
    try:
        s.sendall(b"\x05\x01\x00")
        if s.recv(2) != b"\x05\x00":
            raise RuntimeError("socks method negotiation failed")
        s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack(">H", dest_port))
        if s.recv(10)[1] != 0:
            raise RuntimeError("socks connect failed")
        s.sendall(payload)
        got = b""
        while len(got) < len(payload):
            chunk = s.recv(65536)
            if not chunk:
                break
            got += chunk
        return got
    finally:
        s.close()


def sample(proc):
    p = psutil.Process(proc.pid)
    try:
        handles = p.num_handles() if hasattr(p, "num_handles") else p.num_fds()
    except AttributeError:
        handles = -1
    return {"handles": handles, "threads": p.num_threads(),
            "rss_mb": round(p.memory_info().rss / 1048576, 2)}


def last_live_bytes(log_path):
    last = None
    with open(log_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = STATS.search(line)
            if m:
                last = int(m.group(1))
    return last


def wait_live_bytes(log_path, min_after_seconds=1.0):
    """等 dump 线程出新行（interval 300ms）：取最近一条 live_bytes。"""
    t0 = time.time()
    prev = last_live_bytes(log_path)
    while time.time() - t0 < min_after_seconds + 5:
        time.sleep(0.4)
        cur = last_live_bytes(log_path)
        if cur is not None and cur != prev:
            return cur
    return last_live_bytes(log_path)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--xray", required=True)
    ap.add_argument("--conns", type=int, default=300)
    ap.add_argument("--expect", choices=("fixed", "leaky"), default="fixed")
    args = ap.parse_args()

    echo = EchoServer(ECHO_PORT)
    echo.start()

    cfg = {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "socks-in", "port": SOCKS_PORT, "listen": "127.0.0.1",
            "protocol": "socks", "settings": {"auth": "noauth", "udp": False},
        }],
        "outbounds": [{"tag": "out", "protocol": "freedom", "settings": {}}],
    }
    cfg_path = os.path.join(TMP, "86i4h_reap_cfg.json")
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)

    log_path = os.path.join(TMP, "86i4h_reap_xray.log")
    if os.path.exists(log_path):
        os.remove(log_path)
    log_f = open(log_path, "w", encoding="utf-8")
    env = dict(os.environ, XRAY_ALLOC_STATS="1", XRAY_ALLOC_STATS_INTERVAL_MS="300")
    proc = subprocess.Popen([args.xray, "run", "-c", cfg_path],
                            stdout=log_f, stderr=subprocess.STDOUT, env=env)

    verdict = {"R1": "FAIL", "R2": "FAIL", "R3": "FAIL", "R4": "FAIL"}
    try:
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                socket.create_connection(("127.0.0.1", SOCKS_PORT), timeout=0.5).close()
                break
            except OSError:
                time.sleep(0.1)
        else:
            raise RuntimeError("xray socks inbound never came up")

        got = socks_roundtrip(ECHO_PORT, PAYLOAD)
        verdict["R1"] = "PASS" if got == PAYLOAD else "FAIL"
        print(f"[R1 真实转发] 1024B 往返一致={got == PAYLOAD} got={len(got)}B", flush=True)

        # 暖机：连接数固定为 40（池/线程池/JIT 到位后再取基线）
        for _ in range(40):
            socks_roundtrip(ECHO_PORT, PAYLOAD)
        base = sample(proc)
        live0 = wait_live_bytes(log_path)
        print(f"[基线] {base} live_bytes={live0}", flush=True)

        samples = []
        batch = max(args.conns // 3, 1)
        for r in range(3):
            for _ in range(batch):
                socks_roundtrip(ECHO_PORT, PAYLOAD)
            samples.append(sample(proc))
            print(f"[churn 轮 {r + 1}] +{batch} 连接 → {samples[-1]}", flush=True)
        live1 = wait_live_bytes(log_path)

        per_conn = (live1 - live0) / float(args.conns)
        dh = [s["handles"] - base["handles"] for s in samples]
        dt = [s["threads"] - base["threads"] for s in samples]
        if args.expect == "fixed":
            ok = per_conn <= 100.0 and dh[-1] <= 16 and dt[-1] <= 2
        else:
            ok = per_conn >= 100.0
        verdict["R2"] = "PASS" if ok else "FAIL"
        verdict["R3"] = "PASS" if dh[-1] <= 16 and dt[-1] <= 2 else "FAIL"
        print(f"[R2 条目累积] live_bytes {live0} → {live1}（Δ={live1 - live0}B，"
              f"{per_conn:.1f} B/连接，判据 expect={args.expect}）→ {verdict['R2']}", flush=True)
        print(f"[R3 句柄/线程] 句柄Δ={dh} 线程Δ={dt} → {verdict['R3']}", flush=True)

        t0 = time.time()
        proc.terminate()
        try:
            rc = proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            rc = proc.wait(timeout=10)
            print("[R4 停机] terminate 15s 未退，已 kill", flush=True)
        elapsed = round(time.time() - t0, 2)
        time.sleep(0.3)
        try:
            socket.create_connection(("127.0.0.1", SOCKS_PORT), timeout=0.5).close()
            freed = False
        except OSError:
            freed = True
        alive = proc.poll() is None
        verdict["R4"] = "PASS" if (not alive and freed) else "FAIL"
        print(f"[R4 停机] exit={rc} elapsed={elapsed}s 端口已释放={freed} 进程存活={alive}"
              f" → {verdict['R4']}", flush=True)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=10)
        log_f.close()
        echo.srv.close()

    print("VERDICT: " + " | ".join(f"{k} {v}" for k, v in verdict.items()), flush=True)
    print(f"log: {log_path}", flush=True)
    return 0 if all(v == "PASS" for v in verdict.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
