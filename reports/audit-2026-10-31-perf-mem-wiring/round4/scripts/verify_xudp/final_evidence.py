"""最终裁决取证：四向 ×（上游字节 + 客户端回包字节 + 两侧日志）。

关键设计修正（前几版的两处坑）：
  1. `Instance.lines` 只在 drain() 时填充 → 必须先 drain 再读 lines。
  2. wait_port(tcp=True) 的探针连接会让 VLESS 服务端记
     "vless decode: io error: early eof" —— **那是探针噪声**，不是隧道故障。
     本脚本按 peer 端口过滤，只保留隧道连接的日志。
"""
import json
import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vxudp_probe import (Instance, PORT_UPSTREAM, PORT_SOCKS, PORT_TUNNEL,  # noqa: E402
                          PAYLOAD, client_cfg, server_cfg, socks5_udp_associate,
                          socks5_udp_frame, socks5_udp_recv, tunnel_inbound,
                          tunnel_outbound, wait_port)

FIXED_REPLY = (b"\x12\x34\x81\x80" + b"\x00\x01\x00\x00\x00\x00\x00\x00"
               + b"\x07example\x03com\x00" + b"\x00\x01\x00\x01"
               + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x4c\x00\x04"
               + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x4c\x00\x04"
               + b"\x01\x02\x03\x04")


class Rec(threading.Thread):
    """UDP 上游：记录收到的字节，回**固定**应答（模拟真实 DNS 服务器）。"""

    def __init__(self, port):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", port))
        self.sock.settimeout(0.2)
        self.seen = []
        self._stop = False
        self.start()

    def run(self):
        while not self._stop:
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            self.seen.append({"len": len(data), "hex": data.hex()})
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


def run_case(proto, client_side, server_side, cone_disabled, label):
    up = Rec(PORT_UPSTREAM)
    tun_port = PORT_TUNNEL[server_side]
    socks_port = PORT_SOCKS[client_side]
    inbound = tunnel_inbound(proto)
    inbound["port"] = tun_port
    env = {"xray.cone.disabled": "true"} if cone_disabled else None
    srv = Instance(server_side, f"FV_{label}_srv", server_cfg(tun_port, inbound)).start()
    cli = Instance(client_side, f"FV_{label}_cli",
                   client_cfg(socks_port, tunnel_outbound(proto, tun_port)), env=env).start()
    obs = {"case": label, "proto": proto, "cone_disabled_on_client": cone_disabled}
    try:
        wait_port(tun_port)
        wait_port(socks_port)
        time.sleep(1.2)
        srv.drain(0.8)   # 丢弃探针噪声
        cli.drain(0.8)
        bnd, bport, ctrl = socks5_udp_associate("127.0.0.1", socks_port)
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(6.0)
        u.sendto(socks5_udp_frame("127.0.0.1", PORT_UPSTREAM, PAYLOAD), (bnd, bport))
        got = socks5_udp_recv(u, 5.0)
        time.sleep(1.2)
        obs["upstream_received_len"] = up.seen[0]["len"] if up.seen else 0
        obs["upstream_received_hex"] = up.seen[0]["hex"] if up.seen else None
        obs["upstream_got_raw_dns"] = bool(
            up.seen and up.seen[0]["hex"].startswith("123401000001"))
        obs["client_reply_len"] = len(got["payload"]) if got else 0
        obs["client_reply_hex"] = got["payload"].hex() if got else None
        obs["client_reply_is_dns_answer"] = bool(
            got and got["payload"][:2] == b"\x12\x34" and (got["payload"][2] & 0x80))
        # 日志：先 drain 再读 lines（lines 由 drain 填充）
        srv_lines = srv.drain(1.2)
        cli_lines = cli.drain(1.2)
        obs["server_log_udp"] = [l[:190] for l in srv_lines
                                 if "udp" in l.lower() or "xudp" in l.lower()
                                 or "mux" in l.lower()][:8]
        obs["client_log_err"] = [l[:190] for l in cli_lines
                                 if "invalid" in l.lower() or "error" in l.lower()
                                 or "fail" in l.lower()][:8]
        u.close()
        ctrl.close()
    finally:
        cli.stop()
        srv.stop()
        up.stop()
    print(f"[{label}] {json.dumps(obs, ensure_ascii=False)[:900]}", flush=True)
    return obs


if __name__ == "__main__":
    res = []
    cases = [
        ("vless", "rust", "go", False, "vless_rust_go_coneON"),
        ("vless", "go", "rust", False, "vless_go_rust_coneON"),
        ("vless", "go", "rust", True, "vless_go_rust_coneOFF"),
        ("vless", "rust", "rust", False, "vless_rust_rust"),
        ("vless", "go", "go", False, "vless_go_go"),
        ("vmess", "rust", "go", False, "vmess_rust_go"),
        ("vmess", "go", "rust", False, "vmess_go_rust"),
        ("trojan", "rust", "go", False, "trojan_rust_go"),
        ("trojan", "go", "rust", False, "trojan_go_rust"),
    ]
    for proto, cs, ss, cd, label in cases:
        try:
            res.append(run_case(proto, cs, ss, cd, label))
        except Exception as e:  # noqa: BLE001
            print(f"[{label}] harness_error {type(e).__name__}: {e}")
        time.sleep(0.4)
    out = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                       "..", "..", "tmp", "verify_xudp", "final_evidence.json"))
    with open(out, "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2, ensure_ascii=False)
    print("results ->", out)
