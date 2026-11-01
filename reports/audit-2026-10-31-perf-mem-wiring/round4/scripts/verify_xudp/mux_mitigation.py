"""缓解措施取证：Rust 客户端开 mux（Go cone 的等价物）→ Go 服务端。

Go 默认 cone=true 时把 UDP-over-VLESS 转成 v1.mux.cool:666 carrier + mux 帧
（带 GlobalID），Go 服务端 mux ServerWorker 能解 → 上游收裸载荷。
Rust 客户端若开 "mux": {"enabled": true}，应走同一路径 → 观察上游字节是否变裸 29B。

同时对照 Rust 客户端不开 mux（已知 53B 帧泄漏）。
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


def one(proto, client_side, server_side, mux_on, label):
    up = Rec(PORT_UPSTREAM)
    tun_port = PORT_TUNNEL[server_side]
    socks_port = PORT_SOCKS[client_side]
    inbound = tunnel_inbound(proto)
    inbound["port"] = tun_port
    srv = Instance(server_side, f"MX_{label}_srv", server_cfg(tun_port, inbound)).start()
    ob = tunnel_outbound(proto, tun_port)
    if mux_on:
        ob["mux"] = {"enabled": True, "concurrency": 8}
    cli = Instance(client_side, f"MX_{label}_cli", client_cfg(socks_port, ob)).start()
    obs = {"case": label, "mux_on": mux_on}
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
        obs["upstream_len"] = up.seen[0]["len"] if up.seen else 0
        obs["upstream_raw"] = bool(up.seen and up.seen[0]["hex"].startswith("12340100"))
        obs["upstream_hex"] = up.seen[0]["hex"][:80] if up.seen else None
        obs["reply_len"] = len(got["payload"]) if got else 0
        u.close()
        ctrl.close()
    finally:
        cli.stop()
        srv.stop()
        up.stop()
    print(f"[{label}] {json.dumps(obs, ensure_ascii=False)[:340]}", flush=True)
    return obs


if __name__ == "__main__":
    res = []
    for proto in ("vless", "vmess"):
        for mux_on in (False, True):
            for cs, ss in (("rust", "go"), ("go", "rust"), ("rust", "rust")):
                label = f"{proto}_{cs}_{ss}_mux{int(mux_on)}"
                try:
                    res.append(one(proto, cs, ss, mux_on, label))
                except Exception as e:  # noqa: BLE001
                    print(f"[{label}] harness_error {type(e).__name__}: {e}")
                time.sleep(0.4)
    out = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                       "..", "..", "tmp", "verify_xudp", "mux_mitigation.json"))
    with open(out, "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2, ensure_ascii=False)
    print("results ->", out)
