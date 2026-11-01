"""帧级 wire 差分 harness 核心件（只读审计用，零产品代码改动）。

件：
  Echo        本地 TCP echo（记每连接收到/回写的字节数与 sha256，可选落盘原文）
  UdpEcho     本地 UDP echo（同样记账，按 datagram 记录）
  TcpRec      TCP 录制中继：listen -> 转发到 server，双向字节流按 chunk 边界落盘
  UdpRec      UDP 录制中继：每个 datagram 落盘（带方向与时间）
  Proc        xray 进程（Popen 持句柄，finally terminate -> 按 PID）

约定：
  - 端口只从 POOL 里取（28300-28349 / 28400-28449）
  - 禁 taskkill /IM；一律 Popen.kill()
"""
from __future__ import annotations

import hashlib
import json
import os
import socket
import struct
import subprocess
import threading
import time
from typing import Optional

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))))
RUST = os.path.join(ROOT, "target", "release", "xray.exe")
GO = r"D:/tmp/go2617/xray.exe"
WORK = r"D:/tmp/wire-r5"
SRV_BIN = RUST
CLI_BIN = GO


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()[:16]


def payload(n: int, seed: int = 0) -> bytes:
    """确定性伪随机（可复算，双向可独立验）。"""
    out = bytearray()
    x = (seed * 2654435761 + 1) & 0xFFFFFFFF
    while len(out) < n:
        x = (1103515245 * x + 12345) & 0xFFFFFFFF
        out += struct.pack("<I", x)
    return bytes(out[:n])


# ---------------------------------------------------------------- 端口


class Ports:
    """按块分配：每块 5 个（listen, relay, socks, spare, spare）。

    端口段受限（28300-28349 / 28400-28449），用例数超过块数时按 FIFO 回收最旧的块
    ——每个用例结束都会 kill 进程，回收后重绑是安全的。
    """

    CHUNK = 3   # listen / relay / socks（echo 用系统临时口）
    SPAN = 50

    def __init__(self) -> None:
        self._held: list[list[int]] = []

    def block(self, base: int) -> list[int]:
        candidates = [list(range(s, s + self.CHUNK))
                      for s in range(base, base + self.SPAN, self.CHUNK)]
        ordered = [c for c in candidates if c not in self._held] + \
                  [c for c in self._held if c in candidates]
        for c in ordered:
            if self._bindable(c):
                if c in self._held:
                    self._held.remove(c)
                self._held.append(c)
                return c
        raise RuntimeError(f"端口段 {base}-{base + self.SPAN} 全被占用")

    @staticmethod
    def _bindable(c: list[int]) -> bool:
        """真绑一遍再放掉：上一个用例的同端口套接字可能还在 linger。"""
        socks = []
        try:
            for p in c:
                for udp in (False, True):
                    s = listen_socket(udp=udp)
                    s.bind(("127.0.0.1", p))
                    socks.append(s)
            return True
        except OSError:
            return False
        finally:
            for s in socks:
                try:
                    s.close()
                except OSError:
                    pass


def listen_socket(udp: bool = False) -> socket.socket:
    """监听口绑定。

    Windows 上 SO_REUSEADDR 允许两个套接字绑同一端口（后绑者不一定赢），
    端口回收时会静默把流量送到上一个用例的残留套接字——故一律用
    SO_EXCLUSIVEADDRUSE，冲突就报错而非静默共享。
    """
    if udp:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        return s
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
        s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    else:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    return s


PORTS = Ports()


def wait_port(port: int, host: str = "127.0.0.1", timeout: float = 20.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.05)
    return False


# ---------------------------------------------------------------- TCP echo


class Echo:
    def __init__(self, tag: str = "echo", dump: bool = False) -> None:
        self.tag = tag
        self.dump = dump
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(64)
        self.port = self.srv.getsockname()[1]
        self.conns: list[dict] = []
        self.lock = threading.Lock()
        self.stop = False
        self.t = threading.Thread(target=self._accept, daemon=True)
        self.t.start()

    def _accept(self) -> None:
        while not self.stop:
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()

    def _serve(self, c: socket.socket) -> None:
        # 记账件在 accept 时就登记：连接被服务端一直持有时（gRPC/XHTTP 长连）
        # 的字节数也能读到，不依赖 close。
        rec = {"rx": 0, "tx": 0, "rx_sha": "", "rx_hex_head": "", "closed": False, "buf": bytearray()}
        with self.lock:
            self.conns.append(rec)
        try:
            while True:
                d = c.recv(65536)
                if not d:
                    break
                with self.lock:
                    rec["buf"] += d
                    rec["rx"] += len(d)
                    rec["rx_sha"] = sha(bytes(rec["buf"]))
                    rec["rx_hex_head"] = bytes(rec["buf"][:64]).hex()
                c.sendall(d)
                with self.lock:
                    rec["tx"] += len(d)
        except OSError:
            pass
        finally:
            try:
                c.close()
            except OSError:
                pass
            with self.lock:
                rec["closed"] = True
            if self.dump:
                with open(os.path.join(WORK, f"{self.tag}.conn.bin"), "wb") as f:
                    f.write(bytes(rec["buf"]))

    def close(self) -> None:
        self.stop = True
        try:
            self.srv.close()
        except OSError:
            pass


class UdpEcho:
    def __init__(self, tag: str = "udpecho") -> None:
        self.tag = tag
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind(("127.0.0.1", 0))
        self.port = self.s.getsockname()[1]
        self.pkts: list[dict] = []
        self.stop = False
        self.t = threading.Thread(target=self._loop, daemon=True)
        self.t.start()

    def _loop(self) -> None:
        while not self.stop:
            try:
                d, a = self.s.recvfrom(70000)
            except OSError:
                return
            self.pkts.append({"len": len(d), "sha": sha(d), "hex_head": d[:48].hex()})
            try:
                self.s.sendto(d, a)
            except OSError:
                pass

    def close(self) -> None:
        self.stop = True
        try:
            self.s.close()
        except OSError:
            pass


# ---------------------------------------------------------------- 录制中继


class TcpRec:
    """listen(127.0.0.1:bind) -> connect(127.0.0.1:target)；逐连接分别记账。

    必须**按连接**分开存：同一条链路会开多条 TCP（ws 池 / XHTTP 的多 stream），
    拼进一个 buffer 会让帧解析在连接边界处失步。
    """

    def __init__(self, target_port: int, tag: str, bind: int = 0) -> None:
        self.target_port = target_port
        self.tag = tag
        self.srv = listen_socket()
        self.srv.bind(("127.0.0.1", bind))
        self.srv.listen(64)
        self.port = self.srv.getsockname()[1]
        self.transcripts: list[dict] = []
        self.conns = 0
        self.stop = False
        self.lock = threading.Lock()
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self) -> None:
        while not self.stop:
            try:
                a, _ = self.srv.accept()
            except OSError:
                return
            try:
                b = socket.create_connection(("127.0.0.1", self.target_port), timeout=10)
            except OSError:
                a.close()
                continue
            t = {"c2s": bytearray(), "s2c": bytearray(), "up": [], "down": []}
            with self.lock:
                self.conns += 1
                self.transcripts.append(t)
            threading.Thread(target=self._pump, args=(a, b, t, True), daemon=True).start()
            threading.Thread(target=self._pump, args=(b, a, t, False), daemon=True).start()

    def _pump(self, src: socket.socket, dst: socket.socket, t: dict, up: bool) -> None:
        key = "c2s" if up else "s2c"
        ck = "up" if up else "down"
        try:
            while True:
                d = src.recv(65536)
                if not d:
                    break
                with self.lock:
                    t[key] += d
                    t[ck].append(len(d))
                dst.sendall(d)
        except OSError:
            pass
        finally:
            for s in (src, dst):
                try:
                    s.close()
                except OSError:
                    pass

    @property
    def c2s(self) -> bytearray:
        b = bytearray()
        for t in self.transcripts:
            b += t["c2s"]
        return b

    @property
    def s2c(self) -> bytearray:
        b = bytearray()
        for t in self.transcripts:
            b += t["s2c"]
        return b

    def dump(self) -> list[str]:
        paths = []
        for i, t in enumerate(list(self.transcripts)):
            for key in ("c2s", "s2c"):
                p = os.path.join(WORK, f"{self.tag}.conn{i}.{key}.bin")
                with open(p, "wb") as f:
                    f.write(bytes(t[key]))
                paths.append(p)
        return paths

    def main_stream(self, key: str = "c2s") -> tuple[int, bytes]:
        """返回 (连接序号, 该方向字节最多的那条流)。"""
        best = (-1, b"")
        for i, t in enumerate(list(self.transcripts)):
            if len(t[key]) > len(best[1]):
                best = (i, bytes(t[key]))
        return best

    def close(self) -> None:
        self.stop = True
        try:
            self.srv.close()
        except OSError:
            pass


class UdpRec:
    """UDP 录制中继：按源地址区分方向，每个 datagram 落盘（长度 + 原文）。"""

    def __init__(self, target_port: int, tag: str, bind: int = 0) -> None:
        self.target_port = target_port
        self.tag = tag
        self.s = listen_socket(udp=True)
        self.s.bind(("127.0.0.1", bind))
        self.port = self.s.getsockname()[1]
        self.up: list[bytes] = []
        self.down: list[bytes] = []
        self.client: Optional[tuple] = None
        self.stop = False
        self.lock = threading.Lock()
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self) -> None:
        while not self.stop:
            try:
                d, a = self.s.recvfrom(70000)
            except OSError:
                return
            if a[1] == self.target_port:
                with self.lock:
                    self.down.append(d)
                    c = self.client
                if c:
                    try:
                        self.s.sendto(d, c)
                    except OSError:
                        pass
            else:
                with self.lock:
                    self.up.append(d)
                    self.client = a
                try:
                    self.s.sendto(d, ("127.0.0.1", self.target_port))
                except OSError:
                    pass

    def dump(self) -> tuple[str, str]:
        p1 = os.path.join(WORK, f"{self.tag}.up.bin")
        p2 = os.path.join(WORK, f"{self.tag}.down.bin")
        with open(p1, "wb") as f:
            for d in self.up:
                f.write(struct.pack(">H", len(d)))
                f.write(d)
        with open(p2, "wb") as f:
            for d in self.down:
                f.write(struct.pack(">H", len(d)))
                f.write(d)
        return p1, p2

    def close(self) -> None:
        self.stop = True
        try:
            self.s.close()
        except OSError:
            pass


# ---------------------------------------------------------------- 进程


class Proc:
    def __init__(self, binary: str, cfg: dict, tag: str) -> None:
        os.makedirs(WORK, exist_ok=True)
        self.tag = tag
        self.cfg_path = os.path.join(WORK, f"{tag}.json")
        with open(self.cfg_path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=1)
        self.log_path = os.path.join(WORK, f"{tag}.log")
        self.logf = open(self.log_path, "wb")
        env = dict(os.environ)
        env["XRAY_LOCATION_ASSET"] = os.path.join(ROOT, "dist")
        self.p = subprocess.Popen(
            [binary, "run", "-c", self.cfg_path],
            stdout=self.logf, stderr=subprocess.STDOUT, env=env,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )

    def read_log(self) -> str:
        try:
            self.logf.flush()
            with open(self.log_path, "rb") as f:
                return f.read().decode("utf-8", "replace")
        except OSError:
            return ""

    def close(self) -> None:
        try:
            if self.p.poll() is None:
                self.p.kill()
                self.p.wait(timeout=10)
        except Exception:
            pass
        try:
            self.logf.close()
        except Exception:
            pass


# ---------------------------------------------------------------- SOCKS5 客户端


def socks5_connect(port: int, host: str, dport: int, timeout: float = 25.0,
                   raw_ip: bool = True) -> socket.socket:
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    s.settimeout(timeout)
    s.sendall(b"\x05\x01\x00")
    if s.recv(2) != b"\x05\x00":
        raise RuntimeError("socks5 方法协商失败")
    if raw_ip:
        # ATYP=1 裸 IPv4：避免撞已登记票 f2ap9（域名形态 IP 未归一化）的混淆变量
        s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(host) + struct.pack(">H", dport))
    else:
        hb = host.encode()
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + struct.pack(">H", dport))
    rep = s.recv(4)
    if len(rep) < 4 or rep[1] != 0:
        raise RuntimeError(f"socks5 CONNECT 被拒 rep={rep[1] if len(rep) > 1 else '?'}")
    atyp = rep[3]
    if atyp == 1:
        s.recv(4 + 2)
    elif atyp == 3:
        n = s.recv(1)[0]
        s.recv(n + 2)
    elif atyp == 4:
        s.recv(16 + 2)
    return s


def send_all(s: socket.socket, data: bytes) -> None:
    mv = memoryview(data)
    off = 0
    while off < len(data):
        n = s.send(mv[off:])
        if n <= 0:
            raise RuntimeError("send 返回 0")
        off += n


def recv_exact(s: socket.socket, n: int, timeout: float = 30.0) -> bytes:
    end = time.time() + timeout
    buf = bytearray()
    while len(buf) < n:
        if time.time() > end:
            raise RuntimeError(f"recv 超时：{len(buf)}/{n}")
        try:
            d = s.recv(min(65536, n - len(buf)))
        except socket.timeout:
            raise RuntimeError(f"recv 超时（socket）：{len(buf)}/{n}") from None
        if not d:
            raise RuntimeError(f"对端提前关闭：{len(buf)}/{n}")
        buf += d
    return bytes(buf)


# ---------------------------------------------------------------- 配置模板

UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

FREEDOM_ALLOW = {"finalRules": [{"action": "allow"}]}


def server_cfg(listen_port: int, stream: dict) -> dict:
    return {
        "log": {"loglevel": "debug"},
        "inbounds": [{
            "listen": "127.0.0.1", "port": listen_port, "protocol": "vless",
            "settings": {"clients": [{"id": UUID}], "decryption": "none"},
            "streamSettings": stream,
        }],
        "outbounds": [{"protocol": "freedom", "settings": FREEDOM_ALLOW}],
    }


def client_cfg(socks_port: int, server_port: int, stream: dict, mux: Optional[dict] = None) -> dict:
    ob = {
        "protocol": "vless",
        "settings": {"vnext": [{
            "address": "127.0.0.1", "port": server_port,
            "users": [{"id": UUID, "encryption": "none"}],
        }]},
        "streamSettings": stream,
    }
    if mux:
        ob["mux"] = mux
    return {
        "log": {"loglevel": "debug"},
        "inbounds": [{
            "listen": "127.0.0.1", "port": socks_port, "protocol": "socks",
            "settings": {"udp": True, "auth": "noauth"},
        }],
        "outbounds": [ob],
    }
