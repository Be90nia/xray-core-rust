"""G 组：XUDP（VMess UDP）跨侧对打 + dokodemo UDP 修正版（等待就绪）+ socks UDP 域名型目标。

端口：客户端侧 socks 28080（rust/go 各一）；服务端侧 vmess 28081（两侧共用端口号不同实例）；
echo 28082。
"""
import json
import socket
import sys
import time

from mocksrv import (Instance, UdpEcho, socks5_udp_associate, socks5_udp_frame,
                     socks5_udp_recv, wait_port)

RESULTS = []
ECHO_PORT = 28082
VMESS_PORT = 28081
CLIENT_SOCKS = {"rust": 28080, "go": 28083}
VMESS_ID = "b831381d-6324-4d53-ad4f-8cda48b30811"


def record(case, side, obs):
    RESULTS.append({"case": case, "side": side, "obs": obs})


def vmess_server_cfg(port):
    return {
        "log": {"loglevel": "debug"},
        "inbounds": [{"tag": "vmess-in", "listen": "127.0.0.1", "port": port,
                      "protocol": "vmess",
                      "settings": {"clients": [{"id": VMESS_ID}]}}],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
    }


def client_cfg(socks_port, vmess_port):
    return {
        "log": {"loglevel": "debug"},
        "inbounds": [{"tag": "socks-in", "listen": "127.0.0.1", "port": socks_port,
                      "protocol": "socks", "settings": {"auth": "noauth", "udp": True}}],
        "outbounds": [{"tag": "proxy", "protocol": "vmess",
                       "settings": {"vnext": [{"address": "127.0.0.1", "port": vmess_port,
                                               "users": [{"id": VMESS_ID}]}]}}],
    }


def wait_udp_ready(inst, seconds=3.0):
    """UDP 入站无法用 connect 证明监听 → 睡固定时长并查存活。"""
    time.sleep(seconds)
    inst.drain(0.4)
    return inst.alive()


def run_xudp(client_side, case_name, payload):
    server_side = "go" if client_side == "rust" else "rust"
    echo = UdpEcho(ECHO_PORT)
    echo.start()
    srv = Instance(server_side, f"g_{server_side}_vmess", vmess_server_cfg(VMESS_PORT)).start()
    cli = Instance(client_side, f"g_{client_side}_cli",
                   client_cfg(CLIENT_SOCKS[client_side], VMESS_PORT)).start()
    try:
        if not wait_port(VMESS_PORT, tcp=True):
            record(case_name, client_side, {"error": "vmess server no listen"})
            return
        if not wait_port(CLIENT_SOCKS[client_side], tcp=True):
            record(case_name, client_side, {"error": "client no listen"})
            return
        time.sleep(0.8)
        bnd, bport, ctrl, rep = socks5_udp_associate("127.0.0.1", CLIENT_SOCKS[client_side])
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(8.0)
        u.sendto(socks5_udp_frame("127.0.0.1", ECHO_PORT, payload), (bnd, bport))
        got = socks5_udp_recv(u, 8.0)
        time.sleep(0.8)
        obs = {
            "associate_rep": rep,
            "reply": (got or {}).get("payload", b"").decode("latin-1", "replace"),
            "reply_matches": (got["payload"] == payload) if got else False,
            "echo_seen_count": len(echo.seen),
            "echo_payload": echo.seen[0][2] if echo.seen else None,
        }
        srv_logs = srv.drain(0.6)
        cli_logs = cli.drain(0.6)
        obs["server_err"] = [l[:170] for l in srv_logs
                             if "error" in l.lower() or "fail" in l.lower()][:3]
        obs["client_err"] = [l[:170] for l in cli_logs
                             if "error" in l.lower() or "fail" in l.lower()][:3]
        record(case_name, client_side, obs)
        u.close()
        ctrl.close()
    finally:
        cli.stop()
        srv.stop()
        echo.stop()


def case_g1_xudp_cross(client_side):
    """G1 VMess(XUDP) UDP 跨侧链路：payload 往返。"""
    run_xudp(client_side, "G1_xudp_vmess_cross", b"xudp-payload-0123456789")


def case_g2_xudp_cross_large(client_side):
    """G2 VMess(XUDP) UDP 跨侧链路：2000 字节。"""
    run_xudp(client_side, "G2_xudp_vmess_cross_large", bytes(range(256)) * 8)


def case_g3_xudp_cross_multi(client_side):
    """G3 VMess(XUDP) UDP 跨侧链路：3 包。"""
    server_side = "go" if client_side == "rust" else "rust"
    echo = UdpEcho(ECHO_PORT)
    echo.start()
    srv = Instance(server_side, f"g3_{server_side}_vmess", vmess_server_cfg(VMESS_PORT)).start()
    cli = Instance(client_side, f"g3_{client_side}_cli",
                   client_cfg(CLIENT_SOCKS[client_side], VMESS_PORT)).start()
    try:
        if not wait_port(VMESS_PORT, tcp=True) or not wait_port(
                CLIENT_SOCKS[client_side], tcp=True):
            record("G3_xudp_vmess_cross_multi", client_side, {"error": "no listen"})
            return
        time.sleep(0.8)
        bnd, bport, ctrl, _ = socks5_udp_associate("127.0.0.1", CLIENT_SOCKS[client_side])
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(8.0)
        replies = []
        for i in range(3):
            u.sendto(socks5_udp_frame("127.0.0.1", ECHO_PORT, f"g{i}".encode()),
                     (bnd, bport))
            g = socks5_udp_recv(u, 6.0)
            replies.append(g["payload"].decode() if g else None)
        time.sleep(0.6)
        record("G3_xudp_vmess_cross_multi", client_side,
               {"replies": replies, "echo_seen_count": len(echo.seen)})
        u.close()
        ctrl.close()
    finally:
        cli.stop()
        srv.stop()
        echo.stop()


def case_g4_dokodemo_udp_fixed(side):
    """G4 dokodemo-door UDP（修正版：等就绪后再发）→ payload 往返 + 源地址。"""
    echo = UdpEcho(ECHO_PORT)
    echo.start()
    port = 28084 if side == "go" else 28085
    cfg = {
        "log": {"loglevel": "debug"},
        "inbounds": [{"tag": "dok-in", "listen": "127.0.0.1", "port": port,
                      "protocol": "dokodemo-door",
                      "settings": {"address": "127.0.0.1", "port": ECHO_PORT,
                                   "network": "udp"}}],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
    }
    inst = Instance(side, "g4_dok", cfg).start()
    try:
        if not wait_udp_ready(inst):
            record("G4_dokodemo_udp_fixed", side, {"error": "not alive"})
            return
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(5.0)
        u.sendto(b"dok-udp-fixed", ("127.0.0.1", port))
        try:
            data, _ = u.recvfrom(65535)
        except (socket.timeout, ConnectionResetError):
            data = None
        time.sleep(0.5)
        record("G4_dokodemo_udp_fixed", side, {
            "reply": data.decode("latin-1", "replace") if data else None,
            "echo_seen_count": len(echo.seen),
            "echo_peer_ip": echo.seen[0][0] if echo.seen else None,
        })
        u.close()
    finally:
        inst.stop()
        echo.stop()


def case_g5_socks_udp_domain_target(side):
    """G5 socks5 UDP 帧目标为域名（ATYP=3）→ 两侧行为。"""
    echo = UdpEcho(ECHO_PORT)
    echo.start()
    port = 28086 if side == "go" else 28087
    cfg = {
        "log": {"loglevel": "debug"},
        "inbounds": [{"tag": "socks-in", "listen": "127.0.0.1", "port": port,
                      "protocol": "socks", "settings": {"auth": "noauth", "udp": True}}],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
    }
    inst = Instance(side, "g5_domain", cfg).start()
    try:
        if not wait_port(port, tcp=True):
            record("G5_socks_udp_domain_target", side, {"error": "no listen"})
            return
        time.sleep(0.5)
        bnd, bport, ctrl, rep = socks5_udp_associate("127.0.0.1", port)
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(5.0)
        # 手工构造 ATYP=3（域名）帧：RSV(2)+FRAG(1)+ATYP(1)+len(1)+domain+port(2)+payload
        dom = b"localhost"
        frame = (b"\x00\x00\x00" + bytes([3, len(dom)]) + dom
                 + ECHO_PORT.to_bytes(2, "big") + b"domain-target")
        u.sendto(frame, (bnd, bport))
        got = socks5_udp_recv(u, 4.0)
        time.sleep(0.5)
        record("G5_socks_udp_domain_target", side, {
            "reply": (got or {}).get("payload", b"").decode("latin-1", "replace"),
            "echo_seen_count": len(echo.seen),
        })
        u.close()
        ctrl.close()
    finally:
        inst.stop()
        echo.stop()


CASES = [
    ("G1_xudp_vmess_cross", case_g1_xudp_cross),
    ("G2_xudp_vmess_cross_large", case_g2_xudp_cross_large),
    ("G3_xudp_vmess_cross_multi", case_g3_xudp_cross_multi),
    ("G4_dokodemo_udp_fixed", case_g4_dokodemo_udp_fixed),
    ("G5_socks_udp_domain_target", case_g5_socks_udp_domain_target),
]


def main():
    only = sys.argv[1] if len(sys.argv) > 1 else None
    for name, fn in CASES:
        if only and only != name:
            continue
        sides = ("rust", "go") if "cross" in name else ("go", "rust")
        for side in sides:
            try:
                fn(side)
            except Exception as e:  # noqa: BLE001
                record(name, side, {"harness_error": f"{type(e).__name__}: {e}"})
            print(f"[done] {name} side={side}", flush=True)
    out = "xudp_results.json" if not only else f"xudp_{only}.json"
    path = f"D:/Project/Xray-core-rust/reports/audit-2026-10-31-perf-mem-wiring/round4/tmp/{out}"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(list(RESULTS), f, indent=2, ensure_ascii=False)
    print("results ->", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
