"""Go cone 转换的端口例外实测（真实端口 53 / 443 / 其他）。

Go proxy/vless/outbound/outbound.go:303
    if request.Command == RequestCommandUDP && (flow==XRV || (h.cone && request.Port != 53 && request.Port != 443)) {
        request.Command = RequestCommandMux; request.Address = "v1.mux.cool"; request.Port = 666 }

→ cone 开启时，目标端口 **53 / 443** 保持 RequestCommandUDP（裸载荷 + 2B 长度前缀），
  其余端口转 Mux（v1.mux.cool:666，mux 帧）。

本脚本用真实端口 53 / 443 / 28011 三档，测：
  A. Go 客户端 → Go 服务端（对照组）
  B. Go 客户端 → Rust 服务端（cone 默认开）
  C. Rust 客户端 → Go 服务端
"""
import json
import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vxudp_probe import (Instance, PORT_SOCKS, PORT_TUNNEL, PAYLOAD,  # noqa: E402
                          client_cfg, server_cfg, socks5_udp_associate,
                          socks5_udp_frame, socks5_udp_recv, tunnel_inbound,
                          tunnel_outbound, wait_port)

PORT_53 = 53
PORT_443 = 443
PORT_OTHER = 28011


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


def one(client_side, server_side, up_port, label):
    up = Rec(up_port)
    tun_port = PORT_TUNNEL[server_side]
    socks_port = PORT_SOCKS[client_side]
    inbound = tunnel_inbound("vless")
    inbound["port"] = tun_port
    srv = Instance(server_side, f"PX_{label}_srv", server_cfg(tun_port, inbound)).start()
    cli = Instance(client_side, f"PX_{label}_cli",
                   client_cfg(socks_port, tunnel_outbound("vless", tun_port))).start()
    obs = {"case": label, "target_port": up_port}
    try:
        wait_port(tun_port)
        wait_port(socks_port)
        time.sleep(1.0)
        bnd, bport, ctrl = socks5_udp_associate("127.0.0.1", socks_port)
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(6.0)
        u.sendto(socks5_udp_frame("127.0.0.1", up_port, PAYLOAD), (bnd, bport))
        got = socks5_udp_recv(u, 5.0)
        time.sleep(1.0)
        obs["upstream_len"] = up.seen[0]["len"] if up.seen else 0
        obs["upstream_raw"] = bool(up.seen and up.seen[0]["hex"].startswith("12340100"))
        obs["reply_len"] = len(got["payload"]) if got else 0
        u.close()
        ctrl.close()
    finally:
        cli.stop()
        srv.stop()
        up.stop()
    print(f"[{label}] {json.dumps(obs, ensure_ascii=False)[:260]}", flush=True)
    return obs


if __name__ == "__main__":
    res = []
    for tag, p in (("p53", PORT_53), ("p443", PORT_443), ("pother", PORT_OTHER)):
        for cs, ss in (("go", "go"), ("go", "rust"), ("rust", "go"), ("rust", "rust")):
            label = f"{tag}_{cs}_{ss}"
            try:
                res.append(one(cs, ss, p, label))
            except Exception as e:  # noqa: BLE001
                print(f"[{label}] harness_error {type(e).__name__}: {e}")
            time.sleep(0.35)
    out = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                       "..", "..", "tmp", "verify_xudp", "port53_443.json"))
    with open(out, "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2, ensure_ascii=False)
    print("results ->", out)
