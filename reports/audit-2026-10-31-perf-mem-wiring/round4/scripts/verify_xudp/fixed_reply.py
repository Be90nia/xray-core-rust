"""反向路径取证：上游回**固定**应答（不回显），检验 Rust 客户端能否解出。

背景：上一版 recorder 回显输入 → Rust→Go 方向回包“看起来正常”（因为回显字节
恰好仍是合法 XUDP 帧）。真实上游（如 DNS 服务器）回的是**新构造**的应答，
不含 XUDP 帧头 → Rust 客户端的 session.recv_packet 会把应答首字节当 status
解析 → 报 `invalid session status: 0x00` → 客户端零应答。

本脚本用 fixed-reply recorder 复现该差异。
"""
import json
import os
import socket
import struct
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vxudp_probe import (Instance, PORT_UPSTREAM, PORT_SOCKS, PORT_TUNNEL,  # noqa: E402
                          PAYLOAD, client_cfg, server_cfg, socks5_udp_associate,
                          socks5_udp_frame, socks5_udp_recv, tunnel_inbound,
                          tunnel_outbound, wait_port)

# 固定应答：55B 合法 DNS 应答（不含 XUDP 帧头）
FIXED_REPLY = (b"\x12\x34\x81\x80" + b"\x00\x01\x00\x00\x00\x00\x00\x00"
               + b"\x07example\x03com\x00" + b"\x00\x01\x00\x01"
               + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x4c\x00\x04"
               + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x4c\x00\x04"
               + b"\x01\x02\x03\x04")


class FixedReplyRecorder(threading.Thread):
    """UDP 上游：记录收到的字节，**回固定应答**（不回显）。"""

    def __init__(self, port):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", port))
        self.sock.settimeout(0.2)
        self.seen = []
        self._stop = False

    def run(self):
        while not self._stop:
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            self.seen.append({"peer": f"{addr[0]}:{addr[1]}", "len": len(data),
                              "hex": data.hex()})
            try:
                self.sock.sendto(FIXED_REPLY, addr)
            except OSError:
                pass

    def stop(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass


def one(proto, client_side, server_side, label):
    up = FixedReplyRecorder(PORT_UPSTREAM)
    up.start()
    tun_port = PORT_TUNNEL[server_side]
    socks_port = PORT_SOCKS[client_side]
    inbound = tunnel_inbound(proto)
    inbound["port"] = tun_port
    srv = Instance(server_side, f"{label}_srv", server_cfg(tun_port, inbound)).start()
    cli = Instance(client_side, f"{label}_cli",
                   client_cfg(socks_port, tunnel_outbound(proto, tun_port))).start()
    obs = {"case": label}
    try:
        wait_port(tun_port)
        wait_port(socks_port)
        time.sleep(1.0)
        bnd, bport, ctrl = socks5_udp_associate("127.0.0.1", socks_port)
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(6.0)
        u.sendto(socks5_udp_frame("127.0.0.1", PORT_UPSTREAM, PAYLOAD), (bnd, bport))
        got = socks5_udp_recv(u, 5.0)
        time.sleep(1.0)
        obs["upstream"] = up.seen[0] if up.seen else None
        obs["reply_len"] = len(got["payload"]) if got else 0
        obs["reply_hex"] = got["payload"].hex() if got else None
        obs["reply_is_fixed"] = bool(got and got["payload"] == FIXED_REPLY)
        logs = cli.drain(1.0) + srv.drain(1.0)
        obs["errors"] = [l[:180] for l in logs
                         if "invalid" in l.lower() or "error" in l.lower()
                         or "fail" in l.lower()][:4]
        u.close()
        ctrl.close()
    finally:
        cli.stop()
        srv.stop()
        up.stop()
    print(f"[{label}] {json.dumps(obs, ensure_ascii=False)[:600]}", flush=True)
    return obs


if __name__ == "__main__":
    results = []
    for proto in ("vless", "vmess", "trojan"):
        for cs, ss in (("rust", "go"), ("go", "rust"), ("rust", "rust"), ("go", "go")):
            try:
                results.append(one(proto, cs, ss, f"FIX_{proto}_{cs}_{ss}"))
            except Exception as e:  # noqa: BLE001
                print(f"[{proto} {cs}->{ss}] harness_error {type(e).__name__}: {e}")
            time.sleep(0.3)
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "..", "..", "tmp", "verify_xudp", "fixed_reply_results.json")
    out = os.path.abspath(out)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print("results ->", out)
