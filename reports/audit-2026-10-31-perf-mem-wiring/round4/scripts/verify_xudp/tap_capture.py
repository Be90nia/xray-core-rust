"""抓 Go 客户端 → (Rust|Go) 服务端 的 wire 字节（cone 默认 + cone 关闭两态）。

判读要点：
  - Go 默认 cone=true：UDP-over-VLESS 走 `RequestCommandMux` + v1.mux.cool:666
    （Go proxy/vless/outbound/outbound.go:303-306），payload 裹 XUDP 帧
    （xudp.NewPacketWriter，:319-321）。
  - Go cone 关闭：走 `RequestCommandUDP`，payload = 裸载荷 + 2B 长度前缀
    （encoding/addons.go:66-69 MultiLengthPacketWriter）。
  - Rust 客户端：command=Udp + VlessUdpFramedConn（2B 长度前缀），但 link
    侧本身是 XUDP 帧流 → 帧头被当载荷送出。
"""
import json
import os
import socket
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vxudp_probe import (Instance, PORT_UPSTREAM, PORT_SOCKS, PORT_TUNNEL,  # noqa: E402
                          PAYLOAD, client_cfg, server_cfg, socks5_udp_associate,
                          socks5_udp_frame, socks5_udp_recv, tunnel_inbound,
                          tunnel_outbound, wait_port)

TAP_PORT = 28220
TMP = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   "..", "..", "tmp", "verify_xudp"))
os.makedirs(TMP, exist_ok=True)


class Recorder:
    def __init__(self, port):
        import threading
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", port))
        self.sock.settimeout(0.2)
        self.seen = []
        self._stop = False
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        while not self._stop:
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            self.seen.append({"len": len(data), "hex": data.hex()})

    def stop(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass


def run(proto, client_side, server_side, cone_disabled, tap):
    up = Recorder(PORT_UPSTREAM)
    real_tun = PORT_TUNNEL[server_side]
    socks_port = PORT_SOCKS[client_side]
    inbound = tunnel_inbound(proto)
    inbound["port"] = real_tun
    env = {"xray.cone.disabled": "true"} if cone_disabled else None
    srv = Instance(server_side, f"TAP_{proto}_{server_side}_srv",
                   server_cfg(real_tun, inbound)).start()
    cli = Instance(client_side, f"TAP_{proto}_{client_side}_cli",
                   client_cfg(socks_port, tunnel_outbound(proto, TAP_PORT)), env=env).start()
    obs = {"case": f"{proto} {client_side}->{server_side}", "cone_disabled": cone_disabled}
    try:
        wait_port(real_tun)
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
        u.close()
        ctrl.close()
    finally:
        cli.stop()
        srv.stop()
        up.stop()
    print(f"[{obs['case']}] cone_disabled={cone_disabled} "
          f"{json.dumps(obs, ensure_ascii=False)[:300]}", flush=True)
    return obs


def main():
    proto = sys.argv[1] if len(sys.argv) > 1 else "vless"
    results = []
    for cone_disabled in (False, True):
        for cs, ss in (("go", "rust"), ("go", "go")):
            cap = os.path.join(TMP, f"tap_{proto}_{cs}_{ss}_cone{int(cone_disabled)}.txt")
            tap = subprocess.Popen(
                [sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "tap.py"),
                 str(TAP_PORT), str(PORT_TUNNEL[ss]), cap])
            time.sleep(0.8)
            try:
                results.append(run(proto, cs, ss, cone_disabled, tap))
            except Exception as e:  # noqa: BLE001
                print(f"[{cs}->{ss}] harness_error {type(e).__name__}: {e}")
            finally:
                tap.terminate()
                try:
                    tap.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    tap.kill()
            time.sleep(0.5)
    out = os.path.join(TMP, "tap_results.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print("results ->", out)


if __name__ == "__main__":
    main()
