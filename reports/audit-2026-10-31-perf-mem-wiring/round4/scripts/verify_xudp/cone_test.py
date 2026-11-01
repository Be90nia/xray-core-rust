"""Go cone 模式对照实验：Go 客户端 `xray.cone.disabled=true` → 强制走
RequestCommandUDP（裸载荷 + 2B 长度前缀）而非 Mux/v1.mux.cool + XUDP。

用途：判定「Go→Rust 失败」到底是 XUDP 帧问题，还是 Go 默认 cone(Mux) 路径
与 Rust 服务端不兼容的问题。

env: xray.cone.disabled=true（Go 26.10.17 core/xray.go:195-196
    `platform.NewEnvFlag(platform.UseCone).GetValue("") != "true"` → 默认 cone=true）
"""
import json
import os
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vxudp_probe import (Instance, PORT_UPSTREAM, PORT_SOCKS, PORT_TUNNEL,  # noqa: E402
                          PAYLOAD, client_cfg, server_cfg, socks5_udp_associate,
                          socks5_udp_frame, socks5_udp_recv, tunnel_inbound,
                          tunnel_outbound, wait_port)


class Recorder:
    """UDP 上游：记录字节，回固定应答。"""

    def __init__(self, port):
        import threading
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", port))
        self.sock.settimeout(0.2)
        self.seen = []
        self._stop = False
        self.t = threading.Thread(target=self._run, daemon=True)
        self.t.start()

    def _run(self):
        reply = bytes.fromhex("123481800001000000000000076578616d706c6503636f6d0000010001")
        while not self._stop:
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            self.seen.append({"len": len(data), "hex": data.hex()})
            try:
                self.sock.sendto(reply, addr)
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
    srv = Instance(server_side, f"CONE_{proto}_{server_side}_srv",
                   server_cfg(tun_port, inbound)).start()
    cli = Instance(client_side, f"CONE_{proto}_{client_side}_cli",
                   client_cfg(socks_port, tunnel_outbound(proto, tun_port)),
                   env=env).start()
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
        time.sleep(1.0)
        obs["upstream"] = up.seen[0] if up.seen else None
        obs["reply_len"] = len(got["payload"]) if got else 0
        obs["reply_ok"] = bool(got and got["payload"] == PAYLOAD)
        logs = cli.drain(1.0) + srv.drain(1.0)
        obs["errors"] = [l[:170] for l in logs
                         if "invalid" in l.lower() or "error" in l.lower()
                         or "fail" in l.lower()][:3]
        u.close()
        ctrl.close()
    finally:
        cli.stop()
        srv.stop()
        up.stop()
    print(f"[{obs['case']}] cone_disabled={cone_disabled} "
          f"{json.dumps(obs, ensure_ascii=False)[:400]}", flush=True)
    return obs


if __name__ == "__main__":
    res = []
    for proto in ("vless", "vmess", "trojan"):
        for cd in (True,):
            for cs, ss in (("go", "rust"), ("go", "go"), ("rust", "go")):
                try:
                    res.append(one(proto, cs, ss, cd))
                except Exception as e:  # noqa: BLE001
                    print(f"[{proto} {cs}->{ss}] harness_error {type(e).__name__}: {e}")
                time.sleep(0.3)
    out = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                       "..", "..", "tmp", "verify_xudp", "cone_results.json"))
    with open(out, "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2, ensure_ascii=False)
    print("results ->", out)
