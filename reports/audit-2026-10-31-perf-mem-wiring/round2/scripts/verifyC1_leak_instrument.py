"""Verify-C1 独立复现：用「进程句柄数 + 按 PID 的连接数」而非上轮的 socket 枚举。

三个场景共用一份 release 二进制与一份配置（connIdle/uplinkOnly/downlinkOnly = 2s）：

  S2  CONTROL-IDLE  目标 accept 后既不读也不写，客户端什么都不发
                     → 期望 ≈2s 内客户端见 EOF（证明 connIdle 计时器本身工作）
  S1  UP-BLOCKED    目标 accept 后永不 read（黑洞），客户端狂写到窗口堵死
                     → 观察 xray 是否被 connIdle 拆掉（写臂阻塞时是否失效）
  S3  DOWN-BLOCKED  目标狂写，客户端只读 1MB 后停读（零窗口）
                     → 观察下行写臂阻塞时是否失效

S1/S3 结束后关闭全部客户端，等 3×connIdle，再量一次 xray 的句柄数与
「xray PID 拥有的到目标端口的 ESTABLISHED 连接数」——两者不回落 = 泄漏。

用法：python verifyC1_leak_instrument.py [--n 8]
"""
import argparse
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time

import psutil

REPO = r"D:/Project/Xray-core-rust"
XRAY = os.path.join(REPO, "target/release/xray.exe")
HERE = os.path.dirname(os.path.abspath(__file__))
TMP = os.path.abspath(os.path.join(HERE, "..", "tmp"))
os.makedirs(TMP, exist_ok=True)

SOCKS_PORT = 21280
PORT_BLACKHOLE = 22080
PORT_FLOOD = 22081
CONN_IDLE = 2.0


# ---------------------------------------------------------------- target servers
class HoleServer(threading.Thread):
    """accept 后永不 read（下行仍可写，供 S3 用 write_mode=True）。"""

    def __init__(self, port, write_mode=False):
        super().__init__(daemon=True)
        self.port = port
        self.write_mode = write_mode
        self.conns = []
        self.lock = threading.Lock()
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", port))
        self.srv.listen(64)
        self.stop = False

    def run(self):
        while not self.stop:
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            with self.lock:
                self.conns.append(c)
            if self.write_mode:
                threading.Thread(target=self._flood, args=(c,), daemon=True).start()

    @staticmethod
    def _flood(c):
        buf = b"x" * (256 * 1024)
        try:
            c.settimeout(30)
            while True:
                c.sendall(buf)
        except OSError:
            pass

    def close(self):
        self.stop = True
        try:
            self.srv.close()
        except OSError:
            pass
        with self.lock:
            for c in self.conns:
                try:
                    c.close()
                except OSError:
                    pass


# ---------------------------------------------------------------- socks5 client
def socks_connect(dest_port, timeout=10):
    s = socket.create_connection(("127.0.0.1", SOCKS_PORT), timeout=timeout)
    s.sendall(b"\x05\x01\x00")
    if s.recv(2) != b"\x05\x00":
        raise RuntimeError("socks greeting rejected")
    s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack(">H", dest_port))
    rep = s.recv(10)
    if len(rep) < 2 or rep[1] != 0:
        raise RuntimeError(f"socks connect failed: {rep!r}")
    return s


def wait_eof(s, budget):
    """返回 (saw_eof, elapsed)。"""
    t0 = time.time()
    s.settimeout(budget)
    try:
        while True:
            d = s.recv(65536)
            if not d:
                return True, time.time() - t0
    except (socket.timeout, OSError):
        return False, time.time() - t0


def fill_until_blocked(s, budget_bytes, per_try_timeout=1.0):
    """持续写直到 send 超时（窗口堵死），返回已写字节数。"""
    s.settimeout(per_try_timeout)
    chunk = b"y" * 65536
    sent = 0
    while sent < budget_bytes:
        try:
            s.sendall(chunk)
            sent += len(chunk)
        except (socket.timeout, OSError):
            return sent, "blocked"
    return sent, "budget"


def drain_read(s, nbytes, budget=10.0):
    s.settimeout(budget)
    got = 0
    while got < nbytes:
        d = s.recv(65536)
        if not d:
            return got, "eof"
        got += len(d)
    return got, "budget"


# ---------------------------------------------------------------- measurement
def handles(pid):
    try:
        return psutil.Process(pid).num_handles()
    except Exception as e:  # noqa: BLE001
        return f"ERR {e}"


def established_to(pid, port):
    try:
        conns = psutil.Process(pid).net_connections(kind="tcp")
    except Exception:  # noqa: BLE001
        return "ERR"
    out = []
    for c in conns:
        if c.status != psutil.CONN_ESTABLISHED:
            continue
        for a in (c.laddr, c.raddr):
            if a and a.port == port:
                out.append(c)
                break
    return out


DUMP = False


def report(tag, pid):
    e1 = established_to(pid, PORT_BLACKHOLE)
    e3 = established_to(pid, PORT_FLOOD)
    n1 = len(e1) if isinstance(e1, list) else e1
    n3 = len(e3) if isinstance(e3, list) else e3
    print(f"  [{tag}] handles={handles(pid)} est_to_blackhole={n1} est_to_flood={n3}")
    if DUMP:
        try:
            allc = psutil.Process(pid).net_connections(kind="tcp")
        except Exception:  # noqa: BLE001
            allc = []
        buckets = {}
        for c in allc:
            if c.status != psutil.CONN_ESTABLISHED:
                continue
            key = c.raddr.port if c.raddr else 0
            buckets[key] = buckets.get(key, 0) + 1
            print(f"      {c.laddr} -> {c.raddr} {c.status}")
        print(f"      established by remote port: {buckets}")
    return handles(pid), n1, n3


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=8)
    ap.add_argument("--dump", action="store_true")
    args = ap.parse_args()
    n = args.n
    global DUMP
    DUMP = args.dump

    cfg = {
        "log": {"loglevel": "warning"},
        "policy": {
            "levels": {
                "0": {
                    "connIdle": int(CONN_IDLE),
                    "uplinkOnly": int(CONN_IDLE),
                    "downlinkOnly": int(CONN_IDLE),
                }
            }
        },
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": SOCKS_PORT,
                "protocol": "socks",
                "settings": {"udp": False, "auth": "noauth"},
            }
        ],
        "outbounds": [{"protocol": "freedom"}],
    }
    cfg_path = os.path.join(TMP, "cfg-verifyc1-instrument.json")
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)

    blackhole = HoleServer(PORT_BLACKHOLE)
    flood = HoleServer(PORT_FLOOD, write_mode=True)
    blackhole.start()
    flood.start()

    log = open(os.path.join(TMP, "log-verifyc1-instrument.txt"), "w", encoding="utf-8")
    proc = subprocess.Popen(
        [XRAY, "run", "-c", cfg_path],
        stdout=log,
        stderr=subprocess.STDOUT,
        cwd=REPO,
    )
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", SOCKS_PORT), timeout=0.5).close()
                break
            except OSError:
                time.sleep(0.1)
        pid = proc.pid
        print(f"xray pid={pid} (connIdle=uplinkOnly=downlinkOnly={CONN_IDLE}s)")
        time.sleep(1.0)
        print("== 基线（冷启动后）")
        base = report("baseline", pid)

        print("\n== S2 CONTROL-IDLE：目标 accept 后既不读也不写，客户端静默")
        c = socks_connect(PORT_BLACKHOLE)
        t0 = time.time()
        eof, el = wait_eof(c, budget=CONN_IDLE * 4)
        print(f"  client saw_eof={eof} after {el:.2f}s (expect ~{CONN_IDLE}s)")
        c.close()
        time.sleep(CONN_IDLE * 1.5)

        print(f"\n== S3 DOWN-BLOCKED：目标狂写，{n} 个客户端只读 1MB 后停读")
        down_clients = []
        for i in range(n):
            try:
                s = socks_connect(PORT_FLOOD)
                got, why = drain_read(s, 1024 * 1024, budget=15)
                down_clients.append(s)
                print(f"  [{i}] pre-read={got}B ({why})")
            except Exception as e:  # noqa: BLE001
                print(f"  [{i}] setup failed: {e}")
        print(f"  holding {len(down_clients)} stalled readers for {CONN_IDLE * 4:.0f}s")
        time.sleep(CONN_IDLE * 4)
        report("S3-during-stall", pid)
        for s in down_clients:
            try:
                s.close()
            except OSError:
                pass
        time.sleep(CONN_IDLE * 3)
        print("  after closing all stalled readers (+3x connIdle):")
        s3 = report("S3-after-close", pid)

        print(f"\n== S1 UP-BLOCKED：目标永不 read，{n} 个客户端写满窗口后静默")
        up_clients = []
        for i in range(n):
            try:
                s = socks_connect(PORT_BLACKHOLE)
                got, why = fill_until_blocked(s, 32 * 1024 * 1024)
                up_clients.append(s)
                print(f"  [{i}] filled={got}B ({why})")
            except Exception as e:  # noqa: BLE001
                print(f"  [{i}] setup failed: {e}")
        print(f"  holding {len(up_clients)} stalled senders for {CONN_IDLE * 4:.0f}s")
        time.sleep(CONN_IDLE * 4)
        report("S1-during-stall", pid)
        # 观测：客户端是否已被 xray 关闭（读侧）
        eof_cnt = 0
        for s in up_clients:
            eof, el = wait_eof(s, budget=0.2)
            eof_cnt += bool(eof)
        print(f"  clients seeing EOF while stalled: {eof_cnt}/{len(up_clients)}")
        for s in up_clients:
            try:
                s.close()
            except OSError:
                pass
        time.sleep(CONN_IDLE * 3)
        print("  after closing all stalled senders (+3x connIdle):")
        s1 = report("S1-after-close", pid)

        print("\n== 判读")
        hb, nb1, nb3 = base
        for name, m in (("S3", s3), ("S1", s1)):
            h, n1, n3 = m
            if isinstance(h, int) and isinstance(hb, int):
                print(
                    f"  {name}: handles {hb} -> {h} (Δ{h - hb}), "
                    f"blackhole est {nb1} -> {n1}, flood est {nb3} -> {n3}"
                )
        leak = False
        for name, m in (("S3", s3), ("S1", s1)):
            h, n1, n3 = m
            if isinstance(h, int) and isinstance(hb, int) and h - hb > 6:
                leak = True
            if (isinstance(n1, int) and n1 > 0) or (isinstance(n3, int) and n3 > 0):
                leak = True
        print(
            "VERDICT: LEAK — 全部客户端关闭 + 3x connIdle 后仍有 xray 侧 ESTABLISHED/句柄未回落"
            if leak
            else "VERDICT: CLEAN — 句柄与连接数均回落到基线附近"
        )
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        blackhole.close()
        flood.close()
        log.close()


if __name__ == "__main__":
    sys.exit(main())
