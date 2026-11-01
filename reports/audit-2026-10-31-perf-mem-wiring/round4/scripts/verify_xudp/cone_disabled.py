"""Go→Rust（cone 关闭）固定应答实验 + Rust 服务端 debug 日志取证。

用途：
  1. 判定 Go→Rust 在 cone 关闭时是否端到端可用（对照 cone 默认时失败）。
  2. 抓 Rust 服务端 debug 日志，定位 cone 默认（cmd=Mux + XUDP 帧）失败的确切层。
"""
import json
import os
import socket
import subprocess
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


class Recorder(threading.Thread):
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


def one(proto, client_side, server_side, cone_disabled):
    up = Recorder(PORT_UPSTREAM)
    tun_port = PORT_TUNNEL[server_side]
    socks_port = PORT_SOCKS[client_side]
    inbound = tunnel_inbound(proto)
    inbound["port"] = tun_port
    env = {"xray.cone.disabled": "true"} if cone_disabled else None
    # 服务端 debug 日志（定位 mux 层失败点）
    srv_cfg = server_cfg(tun_port, inbound)
    srv_cfg["log"]["loglevel"] = "debug"
    srv = Instance(server_side, f"CD_{proto}_{server_side}_srv", srv_cfg).start()
    cli = Instance(client_side, f"CD_{proto}_{client_side}_cli",
                   client_cfg(socks_port, tunnel_outbound(proto, tun_port)), env=env).start()
    obs = {"case": f"{proto} {client_side}->{server_side}", "cone_disabled": cone_disabled}
    try:
        wait_port(tun_port)
        wait_port(socks_port)
        time.sleep(1.0)
        bnd, bport, ctrl = socks5_udp_associate("127.0.0.1", socks_port)
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(6.0)
        u.sendto(socks5_udp_frame("127.0.0.1", PORT_UPSTREAM, PAYLOAD), (bnd, bport))
        got = socks5_udp_recv(u, 5.0)
        time.sleep(1.2)
        obs["upstream"] = up.seen[0] if up.seen else None
        obs["reply_len"] = len(got["payload"]) if got else 0
        obs["reply_is_fixed"] = bool(got and got["payload"] == FIXED_REPLY)
        obs["server_log"] = [l[:190] for l in srv.drain(1.2)][-14:]
        u.close()
        ctrl.close()
    finally:
        cli.stop()
        srv.stop()
        up.stop()
    print(f"[{obs['case']}] cone_disabled={cone_disabled} "
          f"{json.dumps(obs, ensure_ascii=False)[:700]}", flush=True)
    return obs


if __name__ == "__main__":
    res = []
    for proto in ("vless", "trojan"):
        for cd in (True, False):
            for cs, ss in (("go", "rust"),):
                try:
                    res.append(one(proto, cs, ss, cd))
                except Exception as e:  # noqa: BLE001
                    print(f"[{proto} {cs}->{ss}] harness_error {type(e).__name__}: {e}")
                time.sleep(0.4)
    out = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                       "..", "..", "tmp", "verify_xudp",
                                       "cone_disabled_results.json"))
    with open(out, "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2, ensure_ascii=False)
    print("results ->", out)
