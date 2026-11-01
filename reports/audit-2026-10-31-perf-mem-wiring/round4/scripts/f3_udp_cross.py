"""跨侧 UDP 对打：Rust 客户端 ↔ Go 服务端 / Go 客户端 ↔ Rust 服务端。

拓扑（每侧一实例）：
  客户端侧：socks 入站(udp) → socks 出站(udp) → 服务端侧:28080
  服务端侧：socks 入站(udp) → freedom → UDP echo
python 客户端对客户端侧的 socks 入站做 UDP ASSOCIATE，数据走完整链路。

端口：客户端侧 socks 28075（rust 客户端）/ 28076（go 客户端）；服务端侧 socks 28077。
"""
import json
import socket
import sys
import time

from mocksrv import (PORTS, Instance, UdpEcho, socks5_udp_associate, socks5_udp_frame,
                     socks5_udp_recv, wait_port)

RESULTS = []
ECHO_PORT = 28078
SOCKS_SERVER = 28077          # 服务端侧 socks 入站（两侧共用同一端口号但不同实例）
SOCKS_CLIENT = {"rust": 28075, "go": 28076}


def record(case, side, obs):
    RESULTS.append({"case": case, "side": side, "obs": obs})


def server_cfg(port):
    return {
        "log": {"loglevel": "debug"},
        "inbounds": [{"tag": "socks-in", "listen": "127.0.0.1", "port": port,
                      "protocol": "socks", "settings": {"auth": "noauth", "udp": True}}],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
    }


def client_cfg(port, server_port):
    return {
        "log": {"loglevel": "debug"},
        "inbounds": [{"tag": "socks-in", "listen": "127.0.0.1", "port": port,
                      "protocol": "socks", "settings": {"auth": "noauth", "udp": True}}],
        "outbounds": [{"tag": "proxy", "protocol": "socks",
                       "settings": {"servers": [{"address": "127.0.0.1",
                                                 "port": server_port}]}}],
    }


def run_case(client_side, label):
    """client_side 的实例做客户端；服务端侧固定为另一侧。"""
    server_side = "go" if client_side == "rust" else "rust"
    echo = UdpEcho(ECHO_PORT)
    echo.start()
    srv = Instance(server_side, f"x_{server_side}_server",
                   server_cfg(SOCKS_SERVER)).start()
    cli = Instance(client_side, f"x_{client_side}_client",
                   client_cfg(SOCKS_CLIENT[client_side], SOCKS_SERVER)).start()
    try:
        if not wait_port(SOCKS_SERVER, tcp=True):
            record(label, client_side, {"error": "server no listen"})
            return
        if not wait_port(SOCKS_CLIENT[client_side], tcp=True):
            record(label, client_side, {"error": "client no listen"})
            return
        time.sleep(0.6)
        bnd, bport, ctrl, rep = socks5_udp_associate("127.0.0.1", SOCKS_CLIENT[client_side])
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(6.0)
        payload = b"cross-udp-payload-0123456789"
        u.sendto(socks5_udp_frame("127.0.0.1", ECHO_PORT, payload), (bnd, bport))
        got = socks5_udp_recv(u, 6.0)
        time.sleep(0.6)
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
        record(label, client_side, obs)
        u.close()
        ctrl.close()
    finally:
        cli.stop()
        srv.stop()
        echo.stop()


def case_x1_socks_udp_cross(client_side):
    """X1 socks5 UDP ASSOCIATE 跨侧链路（payload 往返 + 目标观测）。"""
    run_case(client_side, "X1_socks_udp_cross")


def case_x2_socks_udp_cross_multi(client_side):
    """X2 跨侧链路连续 3 包。"""
    server_side = "go" if client_side == "rust" else "rust"
    echo = UdpEcho(ECHO_PORT)
    echo.start()
    srv = Instance(server_side, f"x2_{server_side}_server", server_cfg(SOCKS_SERVER)).start()
    cli = Instance(client_side, f"x2_{client_side}_client",
                   client_cfg(SOCKS_CLIENT[client_side], SOCKS_SERVER)).start()
    try:
        if not wait_port(SOCKS_SERVER, tcp=True) or not wait_port(
                SOCKS_CLIENT[client_side], tcp=True):
            record("X2_socks_udp_cross_multi", client_side, {"error": "no listen"})
            return
        time.sleep(0.6)
        bnd, bport, ctrl, _ = socks5_udp_associate("127.0.0.1", SOCKS_CLIENT[client_side])
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(6.0)
        replies = []
        for i in range(3):
            u.sendto(socks5_udp_frame("127.0.0.1", ECHO_PORT, f"x{i}".encode()),
                     (bnd, bport))
            g = socks5_udp_recv(u, 4.0)
            replies.append(g["payload"].decode() if g else None)
        time.sleep(0.5)
        record("X2_socks_udp_cross_multi", client_side,
               {"replies": replies, "echo_seen_count": len(echo.seen)})
        u.close()
        ctrl.close()
    finally:
        cli.stop()
        srv.stop()
        echo.stop()


def case_x3_socks_udp_cross_large(client_side):
    """X3 跨侧链路 2000 字节大包。"""
    run_case(client_side, "X3_socks_udp_cross_large")


def case_x4_socks_udp_cross_source(client_side):
    """X4 跨侧链路：目标看到的源地址（是否透传原始客户端地址）。"""
    server_side = "go" if client_side == "rust" else "rust"
    echo = UdpEcho(ECHO_PORT)
    echo.start()
    srv = Instance(server_side, f"x4_{server_side}_server", server_cfg(SOCKS_SERVER)).start()
    cli = Instance(client_side, f"x4_{client_side}_client",
                   client_cfg(SOCKS_CLIENT[client_side], SOCKS_SERVER)).start()
    try:
        if not wait_port(SOCKS_SERVER, tcp=True) or not wait_port(
                SOCKS_CLIENT[client_side], tcp=True):
            record("X4_socks_udp_cross_source", client_side, {"error": "no listen"})
            return
        time.sleep(0.6)
        bnd, bport, ctrl, _ = socks5_udp_associate("127.0.0.1", SOCKS_CLIENT[client_side])
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(6.0)
        u.sendto(socks5_udp_frame("127.0.0.1", ECHO_PORT, b"src-check"), (bnd, bport))
        got = socks5_udp_recv(u, 5.0)
        time.sleep(0.5)
        record("X4_socks_udp_cross_source", client_side, {
            "reply_ok": bool(got),
            "echo_peer_ip": echo.seen[0][0] if echo.seen else None,
            "echo_peer_is_loopback": (echo.seen[0][0] == "127.0.0.1") if echo.seen else None,
        })
        u.close()
        ctrl.close()
    finally:
        cli.stop()
        srv.stop()
        echo.stop()


CASES = [
    ("X1_socks_udp_cross", case_x1_socks_udp_cross),
    ("X2_socks_udp_cross_multi", case_x2_socks_udp_cross_multi),
    ("X3_socks_udp_cross_large", case_x3_socks_udp_cross_large),
    ("X4_socks_udp_cross_source", case_x4_socks_udp_cross_source),
]


def main():
    only = sys.argv[1] if len(sys.argv) > 1 else None
    for name, fn in CASES:
        if only and only != name:
            continue
        for client_side in ("rust", "go"):
            try:
                fn(client_side)
            except Exception as e:  # noqa: BLE001
                record(name, client_side, {"harness_error": f"{type(e).__name__}: {e}"})
            print(f"[done] {name} client={client_side}", flush=True)
    out = "udp_cross_results.json" if not only else f"udp_cross_{only}.json"
    path = f"D:/Project/Xray-core-rust/reports/audit-2026-10-31-perf-mem-wiring/round4/tmp/{out}"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(list(RESULTS), f, indent=2, ensure_ascii=False)
    print("results ->", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
