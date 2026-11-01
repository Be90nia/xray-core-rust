"""bd rjt2o e2e：写臂被堵（对端活着但不读）时桥必须按时拆（中止闸）。

真实二进制 + 真实转发。三类量：

  R1 真实转发   socks5 → echo 目标 64KB 往返字节一致（数据面未被闸破坏）
  R2 S1 形态    N 条到「accept 后永不 read」黑洞的 socks 连接狂写 → connIdle 到点后
                xray→黑洞的 ESTABLISHED 必须归零、客户端全部见 EOF/重置
                （修前 6/6 永久钉死：句柄 Δ 不回落、连接恢复后还能续传）
  R3 无残留     多轮重复 R2：每轮结束后无 ESTABLISHED/CLOSE_WAIT、句柄按轮持平
                （单轮 +N 是进程暖机；**逐轮增长**才是每连接泄漏）

用法：python rjt2o_abort_e2e.py --xray <xray.exe> [--n 6] [--idle 2] [--rounds 3]
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

HERE = os.path.dirname(os.path.abspath(__file__))
TMP = os.path.abspath(os.path.join(HERE, "..", "tmp"))
os.makedirs(TMP, exist_ok=True)

SOCKS_PORT = 21280
PORT_HOLE = 22080
PORT_ECHO = 22082


class HoleServer(threading.Thread):
    """accept 后永不 read（接收窗被写满 = 客户端侧写阻塞）。"""

    def __init__(self, port):
        super().__init__(daemon=True)
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", port))
        self.srv.listen(64)
        self.conns = []
        self.lock = threading.Lock()

    def run(self):
        while True:
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            with self.lock:
                self.conns.append(c)  # 持有引用但永不 recv → 接收窗写满

    def close_all(self):
        with self.lock:
            for c in self.conns:
                try:
                    c.close()
                except OSError:
                    pass
            self.conns.clear()


class EchoServer(threading.Thread):
    def __init__(self, port):
        super().__init__(daemon=True)
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", port))
        self.srv.listen(16)

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


def socks5_connect(port, target_port):
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.sendall(b"\x05\x01\x00")
    if s.recv(2) != b"\x05\x00":
        raise RuntimeError("socks greeting failed")
    s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack(">H", target_port))
    rep = s.recv(10)
    if len(rep) < 2 or rep[1] != 0:
        raise RuntimeError(f"socks connect failed: {rep!r}")
    return s


def conns_of(pid, ports):
    return [
        c
        for c in psutil.Process(pid).net_connections(kind="tcp")
        if (c.raddr and c.raddr.port in ports) or (c.laddr and c.laddr.port in ports)
    ]


def est_to(pid, ports):
    return sum(1 for c in conns_of(pid, ports) if c.status == psutil.CONN_ESTABLISHED)


def states_of(pid, ports):
    out = {}
    for c in conns_of(pid, ports):
        out[c.status] = out.get(c.status, 0) + 1
    return out


def stuck_of(pid, ports):
    st = states_of(pid, ports)
    return sum(st.get(s, 0) for s in (psutil.CONN_ESTABLISHED, "CLOSE_WAIT"))


def wait_port(port, timeout=15.0):
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            return True
        except OSError:
            time.sleep(0.05)
    return False


def fill_window(socks, mb_cap=64 * 1024 * 1024):
    """狂写到所有 socket 都阻塞（非阻塞 send 全 EWOULDBLOCK）。"""
    filled = 0
    for s in socks:
        s.setblocking(False)
    deadline = time.time() + 10.0
    while time.time() < deadline and filled < mb_cap:
        progress = 0
        for s in socks:
            try:
                progress += s.send(b"\x00" * 262144)
            except (BlockingIOError, OSError):
                pass
        if progress == 0:
            break
        filled += progress
        time.sleep(0.01)
    return filled


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--xray", required=True)
    ap.add_argument("--n", type=int, default=6)
    ap.add_argument("--idle", type=float, default=2.0)
    ap.add_argument("--rounds", type=int, default=3)
    args = ap.parse_args()

    hole = HoleServer(PORT_HOLE)
    hole.start()
    EchoServer(PORT_ECHO).start()

    cfg = {
        "log": {"loglevel": "warning"},
        "inbounds": [{"tag": "socks-in", "protocol": "socks", "listen": "127.0.0.1",
                      "port": SOCKS_PORT, "settings": {"udp": False}}],
        "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {}}],
        "policy": {"levels": {"0": {"connIdle": int(args.idle),
                                    "uplinkOnly": int(args.idle),
                                    "downlinkOnly": int(args.idle)}}},
    }
    cfg_path = os.path.join(TMP, "rjt2o-e2e-config.json")
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f)

    log_path = os.path.join(TMP, "rjt2o-e2e-xray.log")
    log_f = open(log_path, "w", encoding="utf-8", errors="replace")
    proc = subprocess.Popen([args.xray, "run", "-c", cfg_path], stdout=log_f, stderr=log_f)
    verdict = []
    try:
        if not wait_port(SOCKS_PORT):
            raise SystemExit("FAIL: socks inbound 未起来（见 %s）" % log_path)
        time.sleep(0.5)
        p = psutil.Process(proc.pid)
        base_handles, base_threads = p.num_handles(), p.num_threads()
        print(f"[baseline] pid={proc.pid} handles={base_handles} threads={base_threads}")

        # ---- R1 真实转发（数据面未被闸破坏）----
        payload = bytes((i * 37) % 256 for i in range(65536))
        c = socks5_connect(SOCKS_PORT, PORT_ECHO)
        c.sendall(payload)
        c.settimeout(10)
        got = b""
        while len(got) < len(payload):
            chunk = c.recv(65536)
            if not chunk:
                break
            got += chunk
        c.close()
        print(f"[R1 真实转发] 65536B 往返一致={got == payload} got={len(got)}B")
        if got != payload:
            raise SystemExit("FAIL: 真实转发被破坏")

        # ---- R2/R3：多轮 S1 形态 ----
        per_round = []
        for rnd in range(1, args.rounds + 1):
            stalled = [socks5_connect(SOCKS_PORT, PORT_HOLE) for _ in range(args.n)]
            filled = fill_window(stalled)
            during = est_to(proc.pid, {PORT_HOLE})
            time.sleep(args.idle + 1.5)
            after = est_to(proc.pid, {PORT_HOLE})
            closed = 0
            for s in stalled:
                try:
                    s.setblocking(True)
                    s.settimeout(1.0)
                    if s.recv(4096) == b"":
                        closed += 1
                except OSError:
                    closed += 1
                finally:
                    try:
                        s.close()
                    except OSError:
                        pass
            hole.close_all()
            time.sleep(2.0)
            handles, threads = p.num_handles(), p.num_threads()
            residual = {k: v for k, v in states_of(proc.pid, {PORT_HOLE}).items()}
            print(f"[round {rnd}] filled={filled / 1e6:.1f}MB during_est={during}/{args.n} "
                  f"after_idle_est={after} client_eof={closed}/{args.n} "
                  f"residual={residual or '{}'} handles={handles} threads={threads}")
            per_round.append(
                dict(during=during, after=after, closed=closed, residual=residual,
                     handles=handles, threads=threads)
            )
            if during != args.n or after != 0 or closed != args.n or stuck_of(
                proc.pid, {PORT_HOLE}
            ) != 0:
                verdict.append(f"round{rnd} FAIL（during={during} after={after} closed={closed} "
                               f"residual={residual}）")
            else:
                verdict.append(f"round{rnd} PASS（{args.n}→0 拆净、客户端 {closed}/{args.n} 收尾）")

        if verdict and all("PASS" in v for v in verdict):
            verdict.insert(0, "R2/R2b PASS（connIdle 到点即拆，无钉死）")
        # 泄漏判据：逐轮句柄不得持续增长（单轮 +N 是暖机）。
        hs = [r["handles"] for r in per_round]
        growth = hs[-1] - hs[0] if len(hs) > 1 else 0
        if len(hs) > 1 and growth <= 3:
            verdict.append(f"R3 PASS（逐轮句柄持平 {hs}，Δ={growth}；无 ESTABLISHED/CLOSE_WAIT）")
        elif len(hs) > 1:
            verdict.append(f"R3 FAIL（逐轮句柄增长 {hs}，Δ={growth}）")
        final_socks = states_of(proc.pid, {SOCKS_PORT})
        print(f"[R3 states] hole={states_of(proc.pid, {PORT_HOLE})} "
              f"echo={states_of(proc.pid, {PORT_ECHO})} socks={final_socks}")
        if all(k in (psutil.CONN_LISTEN, "LISTEN") for k in final_socks):
            verdict.append("R3b PASS（入站侧只剩 LISTEN，无遗留连接）")
        else:
            verdict.append(f"R3b FAIL（入站侧遗留 {final_socks}）")

        print("VERDICT: " + " | ".join(verdict))
        if any("FAIL" in v for v in verdict):
            sys.exit(1)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        log_f.close()
        print(f"xray log: {log_path}")


if __name__ == "__main__":
    main()
