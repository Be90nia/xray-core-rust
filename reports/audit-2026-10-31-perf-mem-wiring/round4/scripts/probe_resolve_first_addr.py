"""确认 Rust UDP 域名目标「只取解析结果第一个地址」。

H1: echo 只监听 IPv4 127.0.0.1（localhost 解析首项 = ::1）→ Rust 失败 / Go 成功
H2: echo 只监听 IPv6 [::1]（解析首项 = ::1）→ Rust 成功 / Go 成功
"""
import socket
import sys
import time

from mocksrv import Instance, socks5_udp_associate, wait_port

PORT = {"go": 28086, "rust": 28087}


class Echo6:
    """只监听 IPv6 的 echo。"""

    def __init__(self, port):
        self.sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        self.sock.bind(("::1", port))
        self.sock.settimeout(0.2)
        self.port = port
        self.seen = []
        self._stop = False
        import threading
        self._thr = threading.Thread(target=self._run, daemon=True)
        self._thr.start()

    def _run(self):
        while not self._stop:
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            self.seen.append((addr[0], addr[1], data.hex()))
            try:
                self.sock.sendto(data, addr)
            except OSError:
                pass

    def stop(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass


class Echo4:
    """只监听 IPv4 的 echo。"""

    def __init__(self, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", port))
        self.sock.settimeout(0.2)
        self.port = port
        self.seen = []
        self._stop = False
        import threading
        self._thr = threading.Thread(target=self._run, daemon=True)
        self._thr.start()

    def _run(self):
        while not self._stop:
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            self.seen.append((addr[0], addr[1], data.hex()))
            try:
                self.sock.sendto(data, addr)
            except OSError:
                pass

    def stop(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass


def frame_domain(dom, port, payload):
    d = dom.encode()
    return (b"\x00\x00\x00" + bytes([3, len(d)]) + d
            + port.to_bytes(2, "big") + payload)


def run(side, echo, echo_port):
    port = PORT[side]
    cfg = {
        "log": {"loglevel": "debug"},
        "inbounds": [{"tag": "socks-in", "listen": "127.0.0.1", "port": port,
                      "protocol": "socks", "settings": {"auth": "noauth", "udp": True}}],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
    }
    inst = Instance(side, "h_res", cfg).start()
    try:
        if not wait_port(port, tcp=True):
            return "no listen"
        time.sleep(1.0)
        bnd, bport, ctrl, _ = socks5_udp_associate("127.0.0.1", port)
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(4.0)
        u.sendto(frame_domain("localhost", echo_port, b"probe"), (bnd, bport))
        try:
            d, _ = u.recvfrom(65535)
            res = f"reply={d[-4:].decode('latin-1', 'replace')!r}"
        except Exception as e:  # noqa: BLE001
            res = f"ERR:{type(e).__name__}"
        time.sleep(0.4)
        u.close()
        ctrl.close()
        return f"{res} echo_seen={len(echo.seen)} peer={echo.seen[0][0] if echo.seen else None}"
    finally:
        inst.stop()
        time.sleep(0.3)


def main():
    e4 = Echo4(28088)
    e6 = Echo6(28089)
    try:
        for side in ("go", "rust"):
            print(f"[{side}] H1 echo-IPv4-only : {run(side, e4, 28088)}", flush=True)
            print(f"[{side}] H2 echo-IPv6-only : {run(side, e6, 28089)}", flush=True)
    finally:
        e4.stop()
        e6.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
