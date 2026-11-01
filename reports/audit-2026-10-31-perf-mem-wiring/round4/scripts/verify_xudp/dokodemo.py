"""dokodemo UDP 走隧道 + 原生 UDP 协议（hysteria2/tuic/anytls）影响面判定。

dokodemo：dokodemo-door inbound(network=udp) → dispatcher → 隧道出站。
原生 UDP 协议：Rust↔Rust hysteria2 / tuic（QUIC datagram），看是否也裹 XUDP 帧。
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


class Rec(threading.Thread):
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
                self.sock.sendto(data, addr)
            except OSError:
                pass

    def stop(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass


def dokodemo_case(client_side, server_side, label):
    """dokodemo-door（UDP）→ 隧道 → 服务端 freedom → 上游。"""
    up = Rec(PORT_UPSTREAM)
    tun_port = PORT_TUNNEL[server_side]
    dok_port = PORT_SOCKS[client_side]
    inbound = tunnel_inbound("vless")
    inbound["port"] = tun_port
    srv = Instance(server_side, f"DK_{label}_srv", server_cfg(tun_port, inbound)).start()
    # 客户端侧：dokodemo-door（network=udp，目标=上游）→ vless 出站
    ccfg = {
        "log": {"loglevel": "debug"},
        "inbounds": [{"tag": "dok-in", "listen": "127.0.0.1", "port": dok_port,
                      "protocol": "dokodemo-door",
                      "settings": {"address": "127.0.0.1", "port": PORT_UPSTREAM,
                                   "network": "udp"}}],
        "outbounds": [tunnel_outbound("vless", tun_port)],
    }
    cli = Instance(client_side, f"DK_{label}_cli", ccfg).start()
    obs = {"case": label}
    try:
        wait_port(tun_port)
        wait_port(dok_port)
        time.sleep(1.0)
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(6.0)
        u.sendto(PAYLOAD, ("127.0.0.1", dok_port))
        got = u.recvfrom(65535)[0] if True else None
        time.sleep(1.0)
        obs["upstream"] = up.seen[0] if up.seen else None
        obs["reply_len"] = len(got)
        obs["reply_matches"] = got == PAYLOAD
        u.close()
    except Exception as e:  # noqa: BLE001
        obs["error"] = f"{type(e).__name__}: {e}"
    finally:
        cli.stop()
        srv.stop()
        up.stop()
    print(f"[{label}] {json.dumps(obs, ensure_ascii=False)[:300]}", flush=True)
    return obs


if __name__ == "__main__":
    res = []
    for cs, ss in (("rust", "go"), ("go", "rust"), ("rust", "rust"), ("go", "go")):
        try:
            res.append(dokodemo_case(cs, ss, f"dokodemo_{cs}_{ss}"))
        except Exception as e:  # noqa: BLE001
            print(f"[dokodemo {cs}->{ss}] harness_error {type(e).__name__}: {e}")
        time.sleep(0.4)
    out = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                       "..", "..", "tmp", "verify_xudp", "dokodemo.json"))
    with open(out, "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2, ensure_ascii=False)
    print("results ->", out)
